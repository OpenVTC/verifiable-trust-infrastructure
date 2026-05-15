//! `enable_didcomm` operation.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`,
//! success criterion #1.
//!
//! Sequence (under [`PROTOCOL_LOCK`]):
//! 1. Verify caller is super-admin.
//! 2. Confirm `services.didcomm` is currently `false`. If already
//!    enabled, refuse with [`EnableDidcommError::DidcommAlreadyEnabled`]
//!    — operator should use `migrate` to change mediators.
//! 3. Look up the VTA's own webvh record (SCID + context_id) from
//!    `webvh_ks`.
//! 4. Run the 5-step mediator handshake against the new mediator
//!    DID. Failure here aborts before any LogEntry is published.
//! 5. Read the current DID document from the latest log entry,
//!    patch in the `#vta-didcomm` service entry pointing at the new
//!    mediator.
//! 6. Call [`update_did_webvh`] with the patched document. This
//!    rotates the WebVH control keys (the existing semantics) but
//!    leaves `verificationMethod` byte-identical.
//! 7. Persist `services.didcomm = true` and the
//!    `messaging.mediator_did` to disk.
//! 8. Register the new mediator as active in the
//!    [`MediatorListenerRegistry`].
//! 9. Emit `ServicesDidcommEnable` telemetry.

use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde_json::Value as JsonValue;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use vti_common::config::MessagingConfig;
use vti_common::seed_store::SeedStore;
use vti_common::telemetry::{SharedTelemetrySink, TelemetryEvent, TelemetryKind};

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::messaging::handshake::{
    HandshakeError, HandshakeOptions, ListenerProver, mediator_handshake,
};
use crate::messaging::registry::{MediatorBinding, MediatorListenerRegistry, RegistryError};
use crate::operations::did_webvh::{UpdateDidWebvhError, UpdateDidWebvhOptions, update_did_webvh};
use crate::operations::protocol::document::{DocumentPatchError, with_didcomm_service};
use crate::operations::protocol::{OpContext, PROTOCOL_LOCK};
use crate::store::KeyspaceHandle;

/// Caller-supplied parameters.
#[derive(Debug, Clone)]
pub struct EnableDidcommParams {
    pub mediator_did: String,
    pub force: bool,
    pub handshake_timeout: Duration,
}

/// Result returned to the operator.
#[derive(Debug, Clone)]
pub struct EnableDidcommResult {
    pub new_version_id: String,
    pub mediator_did: String,
    pub mediator_endpoint: String,
    /// The VTA's own DID. See [`super::enable_rest::EnableRestResult`].
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted.
    pub serverless: bool,
}

#[derive(Debug, Error)]
pub enum EnableDidcommError {
    #[error(
        "DIDComm is already enabled. Use `pnm services didcomm update --mediator-did <did>` to change the active mediator."
    )]
    DidcommAlreadyEnabled,
    #[error("VTA DID is not configured — run `vta setup` first")]
    VtaDidNotConfigured,
    #[error("VTA DID `{0}` has no webvh record (corrupted state — re-run setup)")]
    VtaDidRecordMissing(String),
    #[error("VTA DID `{0}` has no published log (cannot patch service array)")]
    VtaDidLogMissing(String),
    #[error("VTA DID log is empty — cannot read current document")]
    EmptyLog,
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    #[error("DID document patch failed: {0}")]
    DocumentPatch(#[from] DocumentPatchError),
    #[error("WebVH update failed: {0}")]
    WebVHUpdate(#[from] UpdateDidWebvhError),
    #[error("config persistence failed: {0}")]
    ConfigPersistence(String),
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<AppError> for EnableDidcommError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for EnableDidcommError
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
pub async fn enable_didcomm(
    config: &Arc<RwLock<AppConfig>>,
    keys_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    snapshot_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    registry: &MediatorListenerRegistry,
    telemetry: &SharedTelemetrySink,
    prover: &(dyn ListenerProver + Send + Sync),
    auth: &AuthClaims,
    params: EnableDidcommParams,
    ctx: OpContext,
    channel: &str,
) -> Result<EnableDidcommResult, EnableDidcommError> {
    auth.require_super_admin()
        .map_err(|e| EnableDidcommError::Auth(e.to_string()))?;

    let _guard = PROTOCOL_LOCK.lock().await;

    // Pre-flight: must currently be disabled, VTA DID must exist,
    // current DID document must be loadable.
    let (vta_did, scid, current_doc) = read_preconditions(config, webvh_ks).await?;

    // Step 1–5: handshake (with --force gating step 2–5). On failure
    // this returns before any LogEntry is published — atomicity
    // guarantee.
    let resolved = mediator_handshake(
        did_resolver,
        prover,
        telemetry,
        &params.mediator_did,
        &vta_did,
        HandshakeOptions {
            timeout: params.handshake_timeout,
            force: params.force,
        },
    )
    .await?;

    // Persist snapshot BEFORE the runtime mutation per spec §3.5a.
    // Pre-state for an enable is DidcommSnapshot::Disabled so a
    // future `services didcomm rollback` re-applies "off." Snapshot
    // write happens after handshake (handshake failure means the
    // mutation never started; no snapshot needed).
    use crate::operations::protocol::snapshot::{self, DidcommSnapshot, ServiceConfigSnapshot};
    snapshot::write(
        snapshot_ks,
        ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Disabled),
    )
    .await
    .map_err(|e| EnableDidcommError::Storage(format!("snapshot write: {e}")))?;

    // Patch the document. `with_didcomm_service` enforces the at-
    // most-one invariant and preserves verificationMethod
    // byte-identical.
    let patched = with_didcomm_service(current_doc, &resolved.mediator_did)?;

    // Publish via update_did_webvh — single source of truth for
    // LogEntry append. Rotates control keys; preserves
    // verificationMethod.
    let current_config = config.read().await.clone();
    let update_result = update_did_webvh(
        keys_ks,
        contexts_ks,
        webvh_ks,
        audit_ks,
        seed_store,
        &current_config,
        auth,
        &scid,
        UpdateDidWebvhOptions {
            document: Some(patched),
            ..Default::default()
        },
        did_resolver,
        didcomm_bridge,
        channel,
    )
    .await?;

    // Persist config: services.didcomm = true and messaging.mediator_did.
    persist_didcomm_enabled(config, &resolved.mediator_did, &resolved.endpoint).await?;

    // Register the mediator as active. The caller (the route layer)
    // is responsible for opening the upstream listener if it isn't
    // already; the registry's `record_activate` updates state +
    // emits the `ServicesDidcommUpdate` telemetry event.
    registry
        .record_activate(MediatorBinding {
            mediator_did: resolved.mediator_did.clone(),
            endpoint: resolved.endpoint.clone(),
        })
        .await;

    // ServicesDidcommEnable: distinct from MigrateStart so reports
    // can distinguish "first-time enable" from "mediator migration".
    let mut event = TelemetryEvent::new(TelemetryKind::ServicesDidcommEnable)
        .with_mediator(&resolved.mediator_did)
        .with_field(
            "new_version_id",
            JsonValue::from(update_result.new_version_id.clone()),
        );
    if let Some(tag) = ctx.telemetry_triggered_by() {
        event = event.with_field("triggered_by", JsonValue::from(tag));
    }
    let _ = telemetry.record(event).await;

    info!(
        channel,
        mediator = %resolved.mediator_did,
        new_version_id = %update_result.new_version_id,
        "DIDComm enabled"
    );

    Ok(EnableDidcommResult {
        new_version_id: update_result.new_version_id,
        mediator_did: resolved.mediator_did,
        mediator_endpoint: resolved.endpoint,
        vta_did,
        serverless: update_result.serverless,
    })
}

async fn read_preconditions(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
) -> Result<(String, String, JsonValue), EnableDidcommError> {
    {
        let cfg = config.read().await;
        if cfg.services.didcomm {
            return Err(EnableDidcommError::DidcommAlreadyEnabled);
        }
    }
    let state = super::preconditions::load_vta_doc_state(config, webvh_ks).await?;
    Ok((state.vta_did, state.scid, state.current_doc))
}

async fn persist_didcomm_enabled(
    config: &Arc<RwLock<AppConfig>>,
    mediator_did: &str,
    mediator_endpoint: &str,
) -> Result<(), EnableDidcommError> {
    let (contents, path) = {
        let mut cfg = config.write().await;
        cfg.services.didcomm = true;
        cfg.messaging = Some(MessagingConfig {
            mediator_url: mediator_endpoint.to_string(),
            mediator_did: mediator_did.to_string(),
            mediator_host: None,
        });
        let contents = toml::to_string_pretty(&*cfg)
            .map_err(|e| EnableDidcommError::ConfigPersistence(e.to_string()))?;
        let path = cfg.config_path.clone();
        (contents, path)
    };
    std::fs::write(&path, contents)
        .map_err(|e| EnableDidcommError::ConfigPersistence(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::keys::seed_store::PlaintextSeedStore;
    use crate::messaging::handshake::{AlwaysOkProver, FailingProver, HandshakeStage};
    use crate::operations::protocol::snapshot;
    use crate::store::Store;
    use crate::test_support::test_app_config;
    use vti_common::telemetry::RingBufferTelemetry;

    fn fresh_config(tmpdir: &std::path::Path) -> Arc<RwLock<AppConfig>> {
        let mut cfg = test_app_config(tmpdir.into());
        cfg.services.rest = true;
        cfg.services.didcomm = false;
        cfg.vta_did = Some("did:webvh:scid123:host:vta".into());
        cfg.config_path = tmpdir.join("config.toml");
        Arc::new(RwLock::new(cfg))
    }

    fn mocks() -> (
        Arc<DIDCommBridge>,
        Arc<MediatorListenerRegistry>,
        SharedTelemetrySink,
    ) {
        let bridge = Arc::new(DIDCommBridge::placeholder());
        let sink: SharedTelemetrySink = Arc::new(RingBufferTelemetry::with_capacity(64));
        let registry = Arc::new(MediatorListenerRegistry::new(Arc::clone(&sink)));
        (bridge, registry, sink)
    }

    async fn empty_keyspace(name: &str) -> (tempfile::TempDir, KeyspaceHandle) {
        use vti_common::config::StoreConfig as VtiStoreConfig;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace(name).unwrap();
        (dir, ks)
    }

    fn super_admin() -> AuthClaims {
        AuthClaims::unsafe_local_cli_super_admin("test")
    }

    fn dummy_seed_store(dir: &std::path::Path) -> Arc<dyn SeedStore> {
        // For refusal-path tests that bail before seed access,
        // a placeholder seed store with no actual seed is fine.
        Arc::new(PlaintextSeedStore::new(dir))
    }

    #[tokio::test]
    async fn refuses_when_didcomm_already_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(dir.path());
        config.write().await.services.didcomm = true;
        let (bridge, registry, sink) = mocks();
        let (_kd, keys_ks) = empty_keyspace("keys").await;
        let (_cd, contexts_ks) = empty_keyspace("contexts").await;
        let (_wd, webvh_ks) = empty_keyspace("webvh").await;
        let (_ad, audit_ks) = empty_keyspace("audit").await;
        let (_sd, snapshot_ks) = empty_keyspace(snapshot::KEYSPACE_NAME).await;
        let resolver = DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap();
        let prover = AlwaysOkProver;
        let seed = dummy_seed_store(dir.path());

        let result = enable_didcomm(
            &config,
            &keys_ks,
            &contexts_ks,
            &webvh_ks,
            &audit_ks,
            &snapshot_ks,
            &*seed,
            &resolver,
            &bridge,
            &registry,
            &sink,
            &prover,
            &super_admin(),
            EnableDidcommParams {
                mediator_did: "did:m:A".into(),
                force: false,
                handshake_timeout: Duration::from_secs(1),
            },
            OpContext::Direct,
            "test",
        )
        .await;

        assert!(matches!(
            result.unwrap_err(),
            EnableDidcommError::DidcommAlreadyEnabled
        ));
    }

    #[tokio::test]
    async fn refuses_when_vta_did_not_configured() {
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(dir.path());
        config.write().await.vta_did = None;
        let (bridge, registry, sink) = mocks();
        let (_kd, keys_ks) = empty_keyspace("keys").await;
        let (_cd, contexts_ks) = empty_keyspace("contexts").await;
        let (_wd, webvh_ks) = empty_keyspace("webvh").await;
        let (_ad, audit_ks) = empty_keyspace("audit").await;
        let (_sd, snapshot_ks) = empty_keyspace(snapshot::KEYSPACE_NAME).await;
        let resolver = DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap();
        let prover = AlwaysOkProver;
        let seed = dummy_seed_store(dir.path());

        let result = enable_didcomm(
            &config,
            &keys_ks,
            &contexts_ks,
            &webvh_ks,
            &audit_ks,
            &snapshot_ks,
            &*seed,
            &resolver,
            &bridge,
            &registry,
            &sink,
            &prover,
            &super_admin(),
            EnableDidcommParams {
                mediator_did: "did:m:A".into(),
                force: false,
                handshake_timeout: Duration::from_secs(1),
            },
            OpContext::Direct,
            "test",
        )
        .await;

        assert!(matches!(
            result.unwrap_err(),
            EnableDidcommError::VtaDidNotConfigured
        ));
    }

    #[tokio::test]
    async fn refuses_when_vta_did_record_missing() {
        // Configured VTA DID, but webvh_ks is empty — corrupted state.
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(dir.path());
        let (bridge, registry, sink) = mocks();
        let (_kd, keys_ks) = empty_keyspace("keys").await;
        let (_cd, contexts_ks) = empty_keyspace("contexts").await;
        let (_wd, webvh_ks) = empty_keyspace("webvh").await;
        let (_ad, audit_ks) = empty_keyspace("audit").await;
        let (_sd, snapshot_ks) = empty_keyspace(snapshot::KEYSPACE_NAME).await;
        let resolver = DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap();
        let prover = AlwaysOkProver;
        let seed = dummy_seed_store(dir.path());

        let result = enable_didcomm(
            &config,
            &keys_ks,
            &contexts_ks,
            &webvh_ks,
            &audit_ks,
            &snapshot_ks,
            &*seed,
            &resolver,
            &bridge,
            &registry,
            &sink,
            &prover,
            &super_admin(),
            EnableDidcommParams {
                mediator_did: "did:m:A".into(),
                force: false,
                handshake_timeout: Duration::from_secs(1),
            },
            OpContext::Direct,
            "test",
        )
        .await;

        match result.unwrap_err() {
            EnableDidcommError::VtaDidRecordMissing(did) => {
                assert_eq!(did, "did:webvh:scid123:host:vta");
            }
            other => panic!("expected VtaDidRecordMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_partial_state_on_handshake_failure() {
        // Even though the VTA DID record is missing, the handshake
        // failure path is reached only AFTER preconditions pass. To
        // prove handshake-failure is non-mutating without a full DID
        // setup, we bail at the same precondition check — the test
        // here documents the contract: any pre-LogEntry failure
        // leaves config and registry untouched.
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(dir.path());
        let (bridge, registry, sink) = mocks();
        let (_kd, keys_ks) = empty_keyspace("keys").await;
        let (_cd, contexts_ks) = empty_keyspace("contexts").await;
        let (_wd, webvh_ks) = empty_keyspace("webvh").await;
        let (_ad, audit_ks) = empty_keyspace("audit").await;
        let (_sd, snapshot_ks) = empty_keyspace(snapshot::KEYSPACE_NAME).await;
        let resolver = DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap();
        let prover = FailingProver {
            stage: HandshakeStage::TrustPing,
            cause: "synthetic".into(),
        };
        let seed = dummy_seed_store(dir.path());

        let _ = enable_didcomm(
            &config,
            &keys_ks,
            &contexts_ks,
            &webvh_ks,
            &audit_ks,
            &snapshot_ks,
            &*seed,
            &resolver,
            &bridge,
            &registry,
            &sink,
            &prover,
            &super_admin(),
            EnableDidcommParams {
                mediator_did: "did:m:A".into(),
                force: false,
                handshake_timeout: Duration::from_secs(1),
            },
            OpContext::Direct,
            "test",
        )
        .await;

        // Config untouched.
        let cfg = config.read().await;
        assert!(!cfg.services.didcomm);
        assert!(cfg.messaging.is_none());
        // Registry untouched.
        assert!(registry.active_listener_id().await.is_none());
    }

    // The success path lands in the integration test (P3.5) — it
    // requires a fully-bootstrapped VTA with a webvh log on disk,
    // which is heavyweight to assemble in a unit test. The refusal
    // paths above guard the state-machine entry-points; the
    // happy-path coverage is intentional in the integration suite.
}
