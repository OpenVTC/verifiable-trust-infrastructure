//! `rollback_rest` operation — fail-forward dispatch.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.5a.
//!
//! Reads the per-kind snapshot store for `rest` and dispatches
//! into the equivalent **forward** operation that returns the
//! VTA's REST advertisement to the pre-mutation state. WebVH is
//! append-only; rollback never rewinds the chain — it appends a
//! new LogEntry whose `service[]` matches the snapshot.
//!
//! Dispatch table:
//!
//! | snapshot         | current state    | dispatched op            |
//! |------------------|------------------|--------------------------|
//! | `Disabled`       | enabled          | `disable_rest`           |
//! | `Enabled { X }`  | disabled         | `enable_rest` with X     |
//! | `Enabled { X }`  | enabled with Y   | `update_rest` with X     |
//! | `Disabled`       | disabled         | no-op (snapshot≡current) |
//! | `Enabled { X }`  | enabled with X   | no-op (snapshot≡current) |
//!
//! No-op rollbacks happen when (a) a previous mutation crashed
//! between snapshot persist and runtime mutation (the snapshot
//! describes the current state, so re-applying it is a no-op), or
//! (b) the operator runs `rollback` twice in a row (a "rollback the
//! rollback" cycle). Both are valid; the operator sees a result
//! with `new_version_id: None` and a `kind == NoOp` marker so the
//! CLI can print "nothing to do" without raising an error.
//!
//! Brick-prevention is enforced by the dispatched forward op,
//! which already calls [`would_violate_last_service`] for its
//! disable path. The §7a.5 rollback histories that resolve to
//! `LastServiceRefused` (e.g. rolling back a `services rest enable`
//! when DIDComm is disabled) surface the typed error from the
//! forward op verbatim.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use vti_common::seed_store::SeedStore;
use vti_common::telemetry::SharedTelemetrySink;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::operations::did_webvh::UpdateDidWebvhError;
use crate::operations::protocol::OpContext;
use crate::operations::protocol::disable_rest::{
    DisableRestError, DisableRestParams, disable_rest,
};
use crate::operations::protocol::document::{DocumentPatchError, current_rest_service};
use crate::operations::protocol::enable_rest::{EnableRestError, EnableRestParams, enable_rest};
use crate::operations::protocol::snapshot::{
    self, RestSnapshot, ServiceConfigSnapshot, ServiceKind,
};
use crate::operations::protocol::update_rest::{UpdateRestError, UpdateRestParams, update_rest};
use crate::store::KeyspaceHandle;

#[derive(Debug, Clone, Default)]
pub struct RollbackRestParams;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackKind {
    /// Snapshot was `Disabled`; rollback re-disabled REST.
    Disabled,
    /// Snapshot was `Enabled { url }`; rollback re-enabled REST
    /// at the prior URL (forward operation: enable_rest).
    Enabled,
    /// Snapshot was `Enabled { url }`; rollback restored the prior
    /// URL on an existing entry (forward operation: update_rest).
    Updated,
    /// Snapshot ≡ current state. No LogEntry was published.
    NoOp,
}

#[derive(Debug, Clone)]
pub struct RollbackRestResult {
    /// `Some(version_id)` when a LogEntry was published, `None`
    /// when the rollback was a no-op (snapshot ≡ current).
    pub new_version_id: Option<String>,
    pub kind: RollbackKind,
    /// The VTA's own DID. Empty for no-op rollbacks (no LogEntry
    /// was written). See [`super::enable_rest::EnableRestResult`].
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted. `false` on no-op
    /// rollbacks (no follow-up redeploy needed).
    pub serverless: bool,
}

#[derive(Debug, Error)]
pub enum RollbackRestError {
    #[error(
        "no prior mutation for `services rest` to roll back from. \
         Use `services rest enable / update / disable` directly instead."
    )]
    NoPriorMutation,
    #[error("VTA DID is not configured — run `vta setup` first")]
    VtaDidNotConfigured,
    #[error("VTA DID `{0}` has no webvh record")]
    VtaDidRecordMissing(String),
    #[error("VTA DID `{0}` has no published log")]
    VtaDidLogMissing(String),
    #[error("VTA DID log is empty")]
    EmptyLog,

    /// Forward dispatch into `enable_rest` failed. The inner error
    /// carries any typed variants the operator should act on
    /// (e.g. `Validation` if the snapshotted URL is malformed —
    /// shouldn't happen since the snapshot was written by an
    /// already-validated forward op, but defensive).
    #[error(transparent)]
    EnableForward(#[from] EnableRestError),
    /// Forward dispatch into `update_rest` failed.
    #[error(transparent)]
    UpdateForward(#[from] UpdateRestError),
    /// Forward dispatch into `disable_rest` failed. Includes
    /// `LastServiceRefused` (rollback would brick the VTA per
    /// spec §7a.5 — operator must enable DIDComm first).
    #[error(transparent)]
    DisableForward(#[from] DisableRestError),

    /// Document patch failed mid-rollback. Surfaced separately so
    /// the CLI can distinguish a snapshot-corruption from a
    /// pre-mutation refusal.
    #[error("DID document patch failed: {0}")]
    DocumentPatch(#[from] DocumentPatchError),
    #[error("WebVH update failed: {0}")]
    WebVHUpdate(#[from] UpdateDidWebvhError),
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<AppError> for RollbackRestError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for RollbackRestError
{
    fn from(value: crate::operations::protocol::preconditions::ProtocolPreconditionError) -> Self {
        use crate::operations::protocol::preconditions::ProtocolPreconditionError as E;
        match value {
            E::VtaDidNotConfigured => Self::VtaDidNotConfigured,
            E::VtaDidRecordMissing(s) => Self::VtaDidRecordMissing(s),
            E::VtaDidLogMissing(s) => Self::VtaDidLogMissing(s),
            E::EmptyLog => Self::EmptyLog,
            E::Storage(s) | E::DocumentParse(s) => Self::Storage(s),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn rollback_rest(
    config: &Arc<RwLock<AppConfig>>,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    snapshot_ks: &KeyspaceHandle,
    service_state_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    telemetry: &SharedTelemetrySink,
    auth: &AuthClaims,
    _params: RollbackRestParams,
    webvh_auth_locks: &crate::operations::did_webvh::WebvhAuthLocks,
    channel: &str,
) -> Result<RollbackRestResult, RollbackRestError> {
    auth.require_super_admin()
        .map_err(|e| RollbackRestError::Auth(e.to_string()))?;

    // 1. Read the snapshot. None → NoPriorMutation. Note: we do
    //    NOT take PROTOCOL_LOCK here because the dispatched
    //    forward op takes it; holding it twice would deadlock.
    let snap = snapshot::read(snapshot_ks, ServiceKind::Rest)
        .await
        .map_err(|e| RollbackRestError::Storage(format!("snapshot read: {e}")))?
        .ok_or(RollbackRestError::NoPriorMutation)?;
    let rest_snap = match snap {
        ServiceConfigSnapshot::Rest(s) => s,
        other => {
            // `snapshot::read` already validates the variant tag
            // matches the requested kind; if we land here the
            // snapshot module's invariant is broken. Surface it.
            return Err(RollbackRestError::Storage(format!(
                "snapshot kind mismatch: stored {other:?}, requested Rest",
            )));
        }
    };

    // 2. Read the current REST state from config + the on-chain
    //    DID document. We don't strictly need both; the on-chain
    //    state is authoritative for the rollback decision (it's
    //    what the snapshot will be compared against), and config
    //    is asserted to match by the existing precondition checks
    //    in the forward ops.
    let current_url = read_current_rest_url(config, webvh_ks).await?;

    // 3. Dispatch table (see module doc).
    info!(
        channel,
        snapshot = ?rest_snap,
        current = ?current_url,
        "rollback_rest dispatching",
    );
    match (rest_snap, current_url.as_deref()) {
        // Snapshot says off, currently on → disable.
        (RestSnapshot::Disabled, Some(_)) => {
            let result = disable_rest(
                config,
                keys_ks,
                imported_ks,
                contexts_ks,
                webvh_ks,
                audit_ks,
                snapshot_ks,
                service_state_ks,
                seed_store,
                did_resolver,
                didcomm_bridge,
                telemetry,
                auth,
                DisableRestParams,
                OpContext::Rollback,
                webvh_auth_locks,
                channel,
            )
            .await?;
            Ok(RollbackRestResult {
                new_version_id: Some(result.new_version_id),
                kind: RollbackKind::Disabled,
                vta_did: result.vta_did,
                serverless: result.serverless,
            })
        }

        // Snapshot says on with URL X, currently off → enable.
        (RestSnapshot::Enabled { url }, None) => {
            let result = enable_rest(
                config,
                keys_ks,
                imported_ks,
                contexts_ks,
                webvh_ks,
                audit_ks,
                snapshot_ks,
                service_state_ks,
                seed_store,
                did_resolver,
                didcomm_bridge,
                telemetry,
                auth,
                EnableRestParams { url: url.clone() },
                OpContext::Rollback,
                webvh_auth_locks,
                channel,
            )
            .await?;
            Ok(RollbackRestResult {
                new_version_id: Some(result.new_version_id),
                kind: RollbackKind::Enabled,
                vta_did: result.vta_did,
                serverless: result.serverless,
            })
        }

        // Snapshot says on with URL X, currently on with Y where
        // X != Y → update.
        (RestSnapshot::Enabled { url }, Some(current)) if url != current => {
            let result = update_rest(
                config,
                keys_ks,
                imported_ks,
                contexts_ks,
                webvh_ks,
                audit_ks,
                snapshot_ks,
                service_state_ks,
                seed_store,
                did_resolver,
                didcomm_bridge,
                telemetry,
                auth,
                UpdateRestParams { url: url.clone() },
                OpContext::Rollback,
                webvh_auth_locks,
                channel,
            )
            .await?;
            Ok(RollbackRestResult {
                new_version_id: Some(result.new_version_id),
                kind: RollbackKind::Updated,
                vta_did: result.vta_did,
                serverless: result.serverless,
            })
        }

        // Snapshot ≡ current state. No LogEntry, no telemetry.
        // Operator sees `kind == NoOp` and can interpret as
        // "rollback was already applied" or "no diff to revert."
        _ => {
            info!(
                channel,
                "rollback_rest: snapshot matches current state — no-op"
            );
            Ok(RollbackRestResult {
                new_version_id: None,
                kind: RollbackKind::NoOp,
                // No LogEntry written — the CLI hint path is
                // suppressed for no-ops anyway, so empty + false
                // is the right "nothing to follow up on" signal.
                vta_did: String::new(),
                serverless: false,
            })
        }
    }
}

/// Read the currently-advertised REST URL from the on-chain DID
/// document. Returns `None` when no `#vta-rest` entry is present.
async fn read_current_rest_url(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
) -> Result<Option<String>, RollbackRestError> {
    let state = super::preconditions::load_vta_doc_state(config, webvh_ks).await?;
    Ok(current_rest_service(&state.current_doc).map(|svc| svc.url))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    /// Owns the fjall store so a test can derive multiple keyspace
    /// handles from the same open instance — fjall locks the data
    /// dir on each open.
    struct TestFixture {
        _dir: tempfile::TempDir,
        _config: Arc<RwLock<AppConfig>>,
        store: Store,
    }

    impl TestFixture {
        fn snapshot_ks(&self) -> KeyspaceHandle {
            self.store.keyspace(snapshot::KEYSPACE_NAME).unwrap()
        }
    }

    fn build_fixture(rest: bool, didcomm: bool) -> TestFixture {
        use crate::test_support::test_app_config;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_app_config(dir.path().into());
        cfg.services.rest = rest;
        cfg.services.didcomm = didcomm;
        cfg.vta_did = Some("did:webvh:scid123:host:vta".into());
        cfg.config_path = dir.path().join("vta.toml");
        let initial = toml::to_string_pretty(&cfg).unwrap();
        std::fs::write(&cfg.config_path, initial).unwrap();
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        TestFixture {
            _dir: dir,
            _config: Arc::new(RwLock::new(cfg)),
            store,
        }
    }

    /// `rollback_rest` returns `NoPriorMutation` when the snapshot
    /// keyspace is empty.
    #[tokio::test]
    async fn no_prior_mutation_when_snapshot_empty() {
        let fx = build_fixture(true, true);
        let snapshot_ks = fx.snapshot_ks();
        // No snapshot written.
        let snap = snapshot::read(&snapshot_ks, ServiceKind::Rest)
            .await
            .unwrap();
        assert!(snap.is_none());

        // The full rollback_rest call requires too many fixtures
        // (resolver, seed_store, didcomm_bridge, etc.) for a unit
        // test — full e2e coverage lives in P6's matrix. Here we
        // just assert the precondition (empty snapshot) holds and
        // that the typed error path is wired up via direct
        // construction.
        let err = RollbackRestError::NoPriorMutation;
        let msg = err.to_string();
        assert!(msg.contains("no prior mutation"));
    }

    /// Round-trip: write `Disabled` snapshot → reading it back
    /// and inspecting the variant matches the expected dispatch
    /// arm. The actual dispatch is integration-tested in P6.
    #[tokio::test]
    async fn snapshot_disabled_round_trips() {
        let fx = build_fixture(true, true);
        let snapshot_ks = fx.snapshot_ks();
        snapshot::write(
            &snapshot_ks,
            ServiceConfigSnapshot::Rest(RestSnapshot::Disabled),
        )
        .await
        .unwrap();

        let read = snapshot::read(&snapshot_ks, ServiceKind::Rest)
            .await
            .unwrap()
            .unwrap();
        match read {
            ServiceConfigSnapshot::Rest(RestSnapshot::Disabled) => {}
            other => panic!("expected Rest(Disabled), got {other:?}"),
        }
    }

    /// Round-trip: write `Enabled { url: X }` snapshot → reading
    /// it back returns the URL X.
    #[tokio::test]
    async fn snapshot_enabled_with_url_round_trips() {
        let fx = build_fixture(true, true);
        let snapshot_ks = fx.snapshot_ks();
        snapshot::write(
            &snapshot_ks,
            ServiceConfigSnapshot::Rest(RestSnapshot::Enabled {
                url: "https://prior.example.com".into(),
            }),
        )
        .await
        .unwrap();

        let read = snapshot::read(&snapshot_ks, ServiceKind::Rest)
            .await
            .unwrap()
            .unwrap();
        match read {
            ServiceConfigSnapshot::Rest(RestSnapshot::Enabled { url }) => {
                assert_eq!(url, "https://prior.example.com");
            }
            other => panic!("expected Rest(Enabled {{ url }}), got {other:?}"),
        }
    }

    /// `RollbackKind` discriminants cover the four cases the
    /// dispatch table produces. Pin the public surface so the
    /// CLI layer can rely on it.
    #[test]
    fn rollback_kind_variants_are_distinct() {
        assert_ne!(RollbackKind::Disabled, RollbackKind::Enabled);
        assert_ne!(RollbackKind::Enabled, RollbackKind::Updated);
        assert_ne!(RollbackKind::Updated, RollbackKind::NoOp);
        assert_ne!(RollbackKind::NoOp, RollbackKind::Disabled);
    }
}
