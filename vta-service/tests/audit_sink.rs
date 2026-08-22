//! The audit sink is a real seam, not a decorative trait (#1031).
//!
//! A pluggable extension point earns nothing if the thing it is supposed to
//! divert still goes where it always went. These tests install a sink that is
//! *not* the keyspace and assert two things about every path that audits:
//! the sink receives the entry, and the keyspace does not. The second half is
//! what makes the first non-vacuous — a sink that merely observes alongside an
//! unchanged keyspace write would pass an "did the sink see it" assertion while
//! delivering none of the property the issue asks for.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use vta_sdk::protocols::audit_management::list::AuditLogEntry;
use vta_service::server::{AppStateParts, build_app_state};
use vta_service::store::Store;
use vta_service::test_support::{TestSeedStore, init_jwt_provider, test_app_config};
use vti_common::error::AppError;

/// A sink that keeps what it is given, and nothing else — deliberately not
/// backed by any keyspace, so "the row reached storage" cannot be confused with
/// "the row reached the sink".
#[derive(Default)]
struct Recording {
    seen: Mutex<Vec<AuditLogEntry>>,
}

impl Recording {
    fn actions(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.action.clone())
            .collect()
    }
}

#[async_trait]
impl vta_audit::AuditSink for Recording {
    async fn record(&self, entry: &AuditLogEntry) -> Result<(), AppError> {
        self.seen.lock().unwrap().push(entry.clone());
        Ok(())
    }
}

/// Build an `AppState` with `sink` installed, plus the temp dir keeping the
/// store alive.
async fn state_with_sink(
    sink: Option<vta_audit::SharedAuditSink>,
) -> (vta_service::server::AppState, tempfile::TempDir) {
    init_jwt_provider();
    let dir = tempfile::tempdir().expect("temp dir");
    let config = test_app_config(dir.path().to_path_buf());
    let store = Store::open(&config.store).expect("open store");
    let seed_store: Arc<dyn vta_service::keys::seed_store::SeedStore> =
        Arc::new(TestSeedStore(vec![0xABu8; 32]));
    let (restart_tx, _rx) = tokio::sync::watch::channel(false);
    let state = build_app_state(
        config,
        &store,
        seed_store,
        None,
        None,
        restart_tx,
        AppStateParts {
            audit_sink: sink,
            ..AppStateParts::default()
        },
    )
    .await
    .expect("build app state");
    (state, dir)
}

/// How many rows are in the audit keyspace.
async fn keyspace_rows(state: &vta_service::server::AppState) -> usize {
    state
        .audit_ks
        .prefix_iter_raw("log:")
        .await
        .expect("audit prefix scan")
        .len()
}

#[tokio::test]
async fn an_installed_sink_receives_the_row_and_the_keyspace_does_not() {
    let recording = Arc::new(Recording::default());
    let (state, _dir) =
        state_with_sink(Some(Arc::clone(&recording) as vta_audit::SharedAuditSink)).await;

    vta_audit::record(
        &state.audit_sink,
        "keys.create",
        "did:key:zTestAdmin",
        Some("key-1"),
        "success",
        Some("test"),
        None,
    )
    .await
    .expect("record");

    assert_eq!(
        recording.actions(),
        ["keys.create"],
        "the installed sink must receive the entry"
    );
    assert_eq!(
        keyspace_rows(&state).await,
        0,
        "the keyspace must NOT also have been written — otherwise the sink is \
         an observer, not a destination, and 'install an append-only backend' \
         would silently keep the mutable copy as the real log"
    );
}

#[tokio::test]
async fn the_default_sink_is_still_the_keyspace() {
    // The other half of the contract: a deployment that installs nothing gets
    // exactly the behaviour it had before this seam existed.
    let (state, _dir) = state_with_sink(None).await;

    vta_audit::record(
        &state.audit_sink,
        "acl.grant",
        "did:key:zTestAdmin",
        None,
        "success",
        None,
        None,
    )
    .await
    .expect("record");

    assert_eq!(
        keyspace_rows(&state).await,
        1,
        "with no sink installed the row must land in the audit keyspace, which \
         is what the retrieval and retention APIs read"
    );
}

#[tokio::test]
async fn the_sweepers_write_through_the_installed_sink_too() {
    // Sweeper removals are unattended: nobody was watching when the ACL entry
    // vanished, which makes them exactly the rows an operator installs a
    // tamper-evident backend to capture. They run on the storage thread, far
    // from the request path, so it is entirely possible to wire the sink into
    // one and not the other — and the failure would be invisible until someone
    // went looking for a deletion that was never recorded.
    let recording = Arc::new(Recording::default());
    let (state, _dir) =
        state_with_sink(Some(Arc::clone(&recording) as vta_audit::SharedAuditSink)).await;

    let expired =
        vti_common::acl::AclEntry::new("did:key:zExpired", vti_common::acl::Role::Admin, "test")
            .with_expires_at(Some(1));
    vti_common::acl::store_acl_entry(&state.acl_ks, &expired)
        .await
        .expect("store acl entry");

    vta_service::acl_sweeper::sweep_expired(&state.acl_ks, &state.audit_sink)
        .await
        .expect("sweep");

    assert_eq!(
        recording.actions(),
        ["acl.expire"],
        "the sweeper's audit row must go through the installed sink"
    );
}

#[tokio::test]
async fn both_transports_share_one_sink() {
    // `VtaState` is the DIDComm-transport view of `AppState`. If it rebuilt its
    // own sink instead of sharing the Arc, an operator-installed backend would
    // cover REST and quietly miss every task that arrived over DIDComm or TSP.
    // Same class of split the P1.1 config `RwLock` fix closed.
    let recording = Arc::new(Recording::default());
    let (state, _dir) =
        state_with_sink(Some(Arc::clone(&recording) as vta_audit::SharedAuditSink)).await;
    let vta_state = vta_service::messaging::router::VtaState::from(&state);

    assert!(
        Arc::ptr_eq(&state.audit_sink, &vta_state.audit_sink),
        "both transports must hold the same sink object, not two that happen to \
         agree today"
    );
}

#[tokio::test]
async fn a_fan_out_keeps_the_query_api_working_beside_a_new_backend() {
    // The composition the issue's motivating case actually needs. Replacing the
    // keyspace sink outright would take `GET /audit/logs` and the retention
    // sweep with it, because both read the keyspace directly and neither can be
    // served by a write-only remote backend.
    let (state, _dir) = state_with_sink(None).await;
    let recording = Arc::new(Recording::default());
    let fan: vta_audit::SharedAuditSink = Arc::new(vta_audit::FanOutAuditSink::new(vec![
        Arc::new(vta_audit::KeyspaceAuditSink::new(state.audit_ks.clone()))
            as vta_audit::SharedAuditSink,
        Arc::clone(&recording) as vta_audit::SharedAuditSink,
    ]));

    vta_audit::record(
        &fan,
        "audit.retention_update",
        "did:key:zAdmin",
        None,
        "success",
        None,
        None,
    )
    .await
    .expect("record");

    assert_eq!(recording.actions(), ["audit.retention_update"]);
    assert_eq!(
        keyspace_rows(&state).await,
        1,
        "the keyspace half of the fan-out must still be written, or the audit \
         query API goes dark the moment an operator adds a second backend"
    );
}
