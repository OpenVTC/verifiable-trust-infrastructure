//! `register_did_with_server` — promote a serverless WebVH DID to a
//! server-managed one without re-issuing the DID identifier.
//!
//! Use case: an operator brings up a VTA in serverless mode (so the
//! DID exists locally and they publish `did.jsonl` manually or not
//! at all), then later stands up a webvh hosting server and wants
//! the VTA to publish there. Re-running setup would mint a new DID
//! with a different SCID, breaking every integration that already
//! references the existing DID. This op flips the DID's
//! `server_id` from `"serverless"` to a registered server in place,
//! pushes the existing log to the new host, and leaves the DID
//! identifier untouched.
//!
//! Invariants:
//! - DID must currently be serverless. Re-pointing a server-managed
//!   DID at a different host is a separate operation (would require
//!   coordinating teardown on the old host).
//! - Target server must already be registered via `add_webvh_server`.
//! - Local `did.jsonl` is the source of truth and is pushed
//!   verbatim; the host's prior content (if any) is overwritten.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use chrono::Utc;
use didwebvh_rs::url::WebVHURL;
use thiserror::Error;
use tracing::info;

use crate::audit;
use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::keys::seed_store::SeedStore;
use crate::store::KeyspaceHandle;
use crate::webvh_store;

use super::{RaceDetected, RecordSnapshot, WebvhRestAuthContext, WebvhTransport};

/// `server_id` value stored on a DID record that has not yet been
/// associated with a webvh hosting server. Mirrors the literal used
/// in `create_did_webvh` and `update_did_webvh`.
const SERVERLESS_MARKER: &str = "serverless";

#[derive(Debug, Clone)]
pub struct RegisterDidWithServerParams {
    pub did: String,
    pub server_id: String,
    /// When true, asks the host to take this slot even if it is owned
    /// by a different DID. Honoured only when the caller authenticates
    /// to the host as an admin; an owner re-registering their own slot
    /// is always allowed without force (the operation is idempotent in
    /// that case). Maps to the `force` field on the host's
    /// `did/register` request.
    pub force: bool,
}

#[derive(Debug, Clone)]
pub struct RegisterDidWithServerResult {
    pub did: String,
    pub server_id: String,
    /// Number of log entries pushed to the host (informational —
    /// equals the local log's entry count).
    pub log_entry_count: u32,
}

#[derive(Debug, Error)]
pub enum RegisterDidWithServerError {
    #[error("auth: {0}")]
    Auth(String),
    #[error("DID not found: {0}")]
    DidNotFound(String),
    #[error(
        "DID `{did}` is already managed by webvh server `{server_id}`. \
         Re-pointing a server-managed DID at a different host is not supported \
         — only serverless DIDs can be registered."
    )]
    AlreadyServerManaged { did: String, server_id: String },
    #[error(
        "webvh server `{0}` is not registered. \
         Add it first with `pnm webvh add-server --id {0} --did <server-did>` (online) \
         or `vta webvh add-server --id {0} --did <server-did>` (offline, daemon stopped)."
    )]
    ServerNotFound(String),
    #[error("DID `{0}` has no published log on disk (cannot push to server)")]
    LogMissing(String),
    #[error("transport setup failed: {0}")]
    Transport(String),
    #[error("publish to server failed: {0}")]
    Publish(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("could not derive URL from DID `{did}`: {reason}")]
    DidUrlParse { did: String, reason: String },
    /// Optimistic-concurrency race: the local DID record changed
    /// between the initial read (where we asserted serverless +
    /// looked up server + fetched log) and the final store (where
    /// we flip server_id + persist mnemonic). Wraps the structured
    /// `RaceDetected` reason from the shared snapshot helper.
    #[error(
        "DID was modified concurrently between read and write — re-run \
         `pnm webvh register-did` after confirming no other operator \
         is registering the same DID. Reason: {0}"
    )]
    Conflict(RaceDetected),
}

impl From<AppError> for RegisterDidWithServerError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

/// Push an existing serverless DID's log to a registered webvh
/// server and flip the local record's `server_id` so future
/// `update_did_webvh` calls (and therefore future `services`
/// mutations) auto-publish there.
pub async fn register_did_with_server(
    webvh_ks: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    config: &AppConfig,
    auth: &AuthClaims,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    params: RegisterDidWithServerParams,
    channel: &str,
) -> Result<RegisterDidWithServerResult, RegisterDidWithServerError> {
    auth.require_super_admin()
        .map_err(|e| RegisterDidWithServerError::Auth(e.to_string()))?;

    // 1. Look up the DID record. Refuse if not found, or if already
    //    server-managed. Snapshot the version-vector fields so we can
    //    detect any concurrent mutation before the final store —
    //    without this, two concurrent calls (e.g. operator + a bot
    //    that just set `server_id`, or a rollback racing the original
    //    register) both pass the serverless check then both write,
    //    and the second `store_did` clobbers the first. The local
    //    record then points at one of two upstream hosts that each
    //    think they own the DID.
    let mut record = webvh_store::get_did(webvh_ks, &params.did)
        .await?
        .ok_or_else(|| RegisterDidWithServerError::DidNotFound(params.did.clone()))?;
    let snapshot = RecordSnapshot::capture(&record);

    if record.server_id != SERVERLESS_MARKER {
        return Err(RegisterDidWithServerError::AlreadyServerManaged {
            did: params.did.clone(),
            server_id: record.server_id.clone(),
        });
    }

    // 2. Look up the target server.
    let server = webvh_store::get_server(webvh_ks, &params.server_id)
        .await?
        .ok_or_else(|| RegisterDidWithServerError::ServerNotFound(params.server_id.clone()))?;

    // 3. Read the local did.jsonl. Source of truth for the push.
    let did_log = webvh_store::get_did_log(webvh_ks, &params.did)
        .await?
        .ok_or_else(|| RegisterDidWithServerError::LogMissing(params.did.clone()))?;

    // 4. Build the transport for the target server (REST or DIDComm
    //    depending on the server DID's advertised endpoints).
    let rest_auth = WebvhRestAuthContext {
        webvh_ks,
        keys_ks,
        seed_store,
        config,
        channel,
    };
    let transport = WebvhTransport::from_server(&server, did_resolver, didcomm_bridge, &rest_auth)
        .await
        .map_err(|e| RegisterDidWithServerError::Transport(e.to_string()))?;

    // 5. Atomic claim-and-publish on the host. One round-trip writes
    //    slot allocation + log content + owner index in a single batch,
    //    so any in-flight resolver hits either the prior content or the
    //    new content — never the empty 404 window the older two-step
    //    `request_uri` + `publish_did` flow had.
    //
    //    `WebVHURL::parse_did_url` returns `path` with leading and
    //    trailing slashes (`/glenn-vta/`). The host expects the path
    //    without surrounding slashes. Empty or `.well-known` paths
    //    aren't supported here — atomic-register requires an explicit
    //    path on the host side; root-DID registration is a separate
    //    admin-only flow.
    let parsed = WebVHURL::parse_did_url(&params.did).map_err(|e| {
        RegisterDidWithServerError::DidUrlParse {
            did: params.did.clone(),
            reason: e.to_string(),
        }
    })?;
    let request_path = parsed.path.trim_matches('/').to_string();

    let response = transport
        .register_did_atomic(&request_path, &did_log, params.force)
        .await
        .map_err(|e| RegisterDidWithServerError::Publish(e.to_string()))?;

    // 6. Optimistic-concurrency check. Re-load the record and assert
    //    nothing changed between the initial read and now (where we're
    //    about to flip server_id + persist mnemonic). This catches a
    //    second register call (or any concurrent record-mutating op)
    //    that ran while we were doing the host round-trip — without
    //    this, the loser's `store_did` silently overwrites the
    //    winner's, and the local record points at the wrong upstream
    //    while the host actually owning the slot is left orphaned.
    let current = webvh_store::get_did(webvh_ks, &params.did)
        .await?
        .ok_or_else(|| RegisterDidWithServerError::DidNotFound(params.did.clone()))?;
    snapshot
        .assert_unchanged(&current)
        .map_err(RegisterDidWithServerError::Conflict)?;

    // 7. Flip `server_id` on the local record AND persist the
    //    server-issued mnemonic (equals the path for custom-path slots).
    //    From here on, `update_did_webvh` will treat this as a
    //    server-managed DID and auto-publish on every subsequent change
    //    (including the `services` runtime mutations) using this mnemonic.
    record.server_id = params.server_id.clone();
    record.mnemonic = response.mnemonic;
    record.updated_at = Utc::now();
    let log_entry_count = record.log_entry_count;
    webvh_store::store_did(webvh_ks, &record).await?;

    // 6. Audit. Best-effort; log+swallow on error.
    let resource = format!("did:webvh:{}", record.scid);
    if let Err(e) = audit::record(
        audit_ks,
        "did.register_server",
        &auth.did,
        Some(&resource),
        "success",
        Some(channel),
        Some(&record.context_id),
    )
    .await
    {
        tracing::warn!(error = %e, "audit emission failed for did.register_server");
    }

    info!(
        channel,
        did = %record.did,
        server_id = %record.server_id,
        log_entry_count,
        "did:webvh registered with server"
    );

    Ok(RegisterDidWithServerResult {
        did: record.did,
        server_id: record.server_id,
        log_entry_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::seed_store::PlaintextSeedStore;
    use crate::store::Store;
    use crate::test_support::test_app_config;
    use vta_sdk::webvh::{WebvhDidRecord, WebvhServerRecord};
    use vti_common::config::StoreConfig as VtiStoreConfig;

    async fn setup() -> (
        tempfile::TempDir,
        KeyspaceHandle,
        KeyspaceHandle,
        KeyspaceHandle,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let keys_ks = store.keyspace("keys").unwrap();
        let webvh_ks = store.keyspace("webvh").unwrap();
        let audit_ks = store.keyspace("audit").unwrap();
        // Force the test_app_config helper to be exercised so any
        // future field addition surfaces as a test failure.
        let _ = test_app_config(dir.path().into());
        (dir, keys_ks, webvh_ks, audit_ks)
    }

    fn seed_store(dir: &tempfile::TempDir) -> PlaintextSeedStore {
        PlaintextSeedStore::new(dir.path())
    }

    fn serverless_record(did: &str) -> WebvhDidRecord {
        let now = chrono::Utc::now();
        WebvhDidRecord {
            did: did.into(),
            server_id: "serverless".into(),
            mnemonic: "test-mnemonic".into(),
            scid: "scid".into(),
            context_id: "vta".into(),
            portable: true,
            log_entry_count: 1,
            pre_rotation_count: 0,
            next_fragment_id: 1,
            created_at: now,
            updated_at: now,
        }
    }

    fn server_record(id: &str) -> WebvhServerRecord {
        let now = chrono::Utc::now();
        WebvhServerRecord {
            id: id.into(),
            did: format!("did:web:{id}.example"),
            label: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn super_admin() -> AuthClaims {
        AuthClaims::unsafe_local_cli_super_admin("test")
    }

    fn other_user() -> AuthClaims {
        use vti_common::acl::Role;
        AuthClaims {
            did: "did:key:z6Mk-test".into(),
            role: Role::Admin,
            allowed_contexts: vec!["vta".into()],
        }
    }

    /// Concrete instances aren't used in unit tests because building
    /// a real `DIDCacheClient` requires network/cache state. The
    /// preflight checks (auth, DID lookup, server lookup, log
    /// presence, already-server-managed) all fire before transport
    /// is constructed, so we exercise them here. The transport
    /// happy path is covered by the integration test in
    /// tests/api_integration.rs.
    async fn resolver() -> DIDCacheClient {
        DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap()
    }

    fn bridge() -> Arc<DIDCommBridge> {
        Arc::new(DIDCommBridge::placeholder())
    }

    #[tokio::test]
    async fn rejects_non_super_admin() {
        let (dir, keys_ks, webvh_ks, audit_ks) = setup().await;
        let resolver = resolver().await;
        let bridge = bridge();
        let config = test_app_config(dir.path().into());
        let seed_store = seed_store(&dir);
        let err = register_did_with_server(
            &webvh_ks,
            &keys_ks,
            &audit_ks,
            &seed_store,
            &config,
            &other_user(),
            &resolver,
            &bridge,
            RegisterDidWithServerParams {
                did: "did:webvh:scid:host:vta".into(),
                server_id: "primary".into(),
                force: false,
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RegisterDidWithServerError::Auth(_)));
    }

    #[tokio::test]
    async fn rejects_when_did_not_found() {
        let (dir, keys_ks, webvh_ks, audit_ks) = setup().await;
        let resolver = resolver().await;
        let bridge = bridge();
        let config = test_app_config(dir.path().into());
        let seed_store = seed_store(&dir);
        let err = register_did_with_server(
            &webvh_ks,
            &keys_ks,
            &audit_ks,
            &seed_store,
            &config,
            &super_admin(),
            &resolver,
            &bridge,
            RegisterDidWithServerParams {
                did: "did:webvh:nonexistent:host:vta".into(),
                server_id: "primary".into(),
                force: false,
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RegisterDidWithServerError::DidNotFound(_)));
    }

    #[tokio::test]
    async fn rejects_when_already_server_managed() {
        let (dir, keys_ks, webvh_ks, audit_ks) = setup().await;
        let did = "did:webvh:scid:host:vta";
        let mut rec = serverless_record(did);
        rec.server_id = "existing-host".into();
        webvh_store::store_did(&webvh_ks, &rec).await.unwrap();

        let resolver = resolver().await;
        let bridge = bridge();
        let config = test_app_config(dir.path().into());
        let seed_store = seed_store(&dir);
        let err = register_did_with_server(
            &webvh_ks,
            &keys_ks,
            &audit_ks,
            &seed_store,
            &config,
            &super_admin(),
            &resolver,
            &bridge,
            RegisterDidWithServerParams {
                did: did.into(),
                server_id: "primary".into(),
                force: false,
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            RegisterDidWithServerError::AlreadyServerManaged { .. }
        ));
    }

    #[tokio::test]
    async fn rejects_when_server_not_registered() {
        let (dir, keys_ks, webvh_ks, audit_ks) = setup().await;
        let did = "did:webvh:scid:host:vta";
        webvh_store::store_did(&webvh_ks, &serverless_record(did))
            .await
            .unwrap();
        webvh_store::store_did_log(&webvh_ks, did, "{}\n")
            .await
            .unwrap();

        let resolver = resolver().await;
        let bridge = bridge();
        let config = test_app_config(dir.path().into());
        let seed_store = seed_store(&dir);
        let err = register_did_with_server(
            &webvh_ks,
            &keys_ks,
            &audit_ks,
            &seed_store,
            &config,
            &super_admin(),
            &resolver,
            &bridge,
            RegisterDidWithServerParams {
                did: did.into(),
                server_id: "missing-host".into(),
                force: false,
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RegisterDidWithServerError::ServerNotFound(_)));
    }

    #[tokio::test]
    async fn rejects_when_log_missing() {
        let (dir, keys_ks, webvh_ks, audit_ks) = setup().await;
        let did = "did:webvh:scid:host:vta";
        webvh_store::store_did(&webvh_ks, &serverless_record(did))
            .await
            .unwrap();
        webvh_store::store_server(&webvh_ks, &server_record("primary"))
            .await
            .unwrap();
        // Note: no `store_did_log` call.

        let resolver = resolver().await;
        let bridge = bridge();
        let config = test_app_config(dir.path().into());
        let seed_store = seed_store(&dir);
        let err = register_did_with_server(
            &webvh_ks,
            &keys_ks,
            &audit_ks,
            &seed_store,
            &config,
            &super_admin(),
            &resolver,
            &bridge,
            RegisterDidWithServerParams {
                did: did.into(),
                server_id: "primary".into(),
                force: false,
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RegisterDidWithServerError::LogMissing(_)));
    }

    /// The `Conflict` error variant must map cleanly through to the
    /// HTTP 409 / DIDComm `e.p.msg.conflict` boundary. Pin the
    /// constructor wiring so the route + DIDComm error mappers (which
    /// match exhaustively on this enum) stay in sync if a future
    /// edit changes the variant shape.
    ///
    /// Real end-to-end concurrent-call coverage lives at the
    /// integration layer (would need two WebvhTransports racing the
    /// same DID); the within-op snapshot mechanism itself is unit-
    /// tested in `super::concurrency::tests`.
    #[test]
    fn conflict_variant_carries_race_reason() {
        use super::super::RaceDetected;
        let err = RegisterDidWithServerError::Conflict(RaceDetected::ServerIdChanged {
            did: "did:webvh:foo".into(),
            expected: "serverless".into(),
            current: "webvh-prod".into(),
        });
        let msg = err.to_string();
        assert!(
            msg.contains("modified concurrently"),
            "user-facing wrapper text missing: {msg}"
        );
        assert!(msg.contains("serverless"), "race reason inlined: {msg}");
        assert!(msg.contains("webvh-prod"), "race reason inlined: {msg}");
        assert!(matches!(err, RegisterDidWithServerError::Conflict(_)));
    }
}
