//! `disable_didcomm` operation.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`
//! success criteria #2, #3, #12.
//!
//! Sequence (under [`PROTOCOL_LOCK`]):
//! 1. Verify caller is super-admin.
//! 2. Confirm `services.didcomm` is currently `true` (refuse with
//!    [`DisableDidcommError::DidcommNotEnabled`] otherwise).
//! 3. Confirm `services.rest` is also currently `true` — otherwise
//!    disabling DIDComm leaves the VTA with no protocol surface.
//! 4. If transport is DIDComm, refuse `--drain-ttl 0s` (would drop
//!    the response on the inbound listener mid-flight). Spec
//!    minimum: 1h over DIDComm transport, any value over REST.
//! 5. Look up the VTA's webvh record + current document, patch out
//!    the `#vta-didcomm` service entry, publish via
//!    [`update_did_webvh`].
//! 6. Persist `services.didcomm = false` (the `messaging` block is
//!    LEFT IN PLACE so the drained listener can still reach the
//!    mediator until its TTL expires).
//! 7. If TTL > 0, register the prior mediator as draining via
//!    `record_drain_persisted`. If TTL == 0 (REST-only), tear down
//!    the listener immediately by deactivating the registry.
//! 8. Emit `ServicesDidcommDisable` telemetry.

use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use chrono::Utc;
use serde_json::Value as JsonValue;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use vti_common::telemetry::{TelemetryEvent, TelemetryKind};

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::messaging::registry::RegistryError;
use crate::operations::did_webvh::{UpdateDidWebvhError, UpdateDidWebvhOptions, update_did_webvh};
use crate::operations::protocol::document::{DocumentPatchError, without_didcomm_service};
use crate::operations::protocol::{OpContext, PROTOCOL_LOCK, ServiceOpDeps};
use crate::store::KeyspaceHandle;

/// Spec minimum drain TTL when called over DIDComm transport: 1
/// hour. Avoids the race where the inbound listener's response
/// drops while the listener is being torn down.
pub const MIN_DRAIN_TTL_OVER_DIDCOMM: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisableTransport {
    Rest,
    Didcomm,
}

#[derive(Debug, Clone)]
pub struct DisableDidcommParams {
    /// How long to keep the listener on the prior mediator
    /// connected while in-flight messages drain. Zero means
    /// immediate teardown (REST transport only).
    pub drain_ttl: Duration,
    /// Transport over which the operator dispatched this request.
    /// Drives the 1h-min-TTL guard.
    pub transport: DisableTransport,
}

#[derive(Debug, Clone)]
pub struct DisableDidcommResult {
    pub new_version_id: String,
    pub prior_mediator_did: String,
    /// `Some(deadline)` if the prior listener entered drain state;
    /// `None` if the listener was torn down immediately (TTL = 0).
    pub drains_until: Option<chrono::DateTime<chrono::Utc>>,
    /// The VTA's own DID. See [`super::enable_rest::EnableRestResult`].
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted.
    pub serverless: bool,
}

#[derive(Debug, Error)]
pub enum DisableDidcommError {
    #[error(
        "DIDComm is not currently enabled. Enable it first: \
         `pnm services didcomm enable --mediator-did <did>` (online) \
         or `vta services didcomm enable --mediator-did <did>` (offline, daemon stopped)."
    )]
    DidcommNotEnabled,
    #[error(
        "cannot disable DIDComm — REST is also disabled. The VTA would have no protocol surface left. \
         Enable REST first: `pnm services rest enable --url <url>` (online) \
         or `vta services rest enable --url <url>` (offline, daemon stopped). \
         Then retry the disable."
    )]
    NoProtocolRemaining,
    #[error("drain ttl {requested}s outside allowed range [{min}s, {max}s]")]
    DrainTtlOutOfBounds { min: u64, max: u64, requested: u64 },
    #[error("VTA DID is not configured — run `vta setup` first")]
    VtaDidNotConfigured,
    #[error("VTA DID `{0}` has no webvh record")]
    VtaDidRecordMissing(String),
    #[error("VTA DID `{0}` has no published log")]
    VtaDidLogMissing(String),
    #[error("VTA DID log is empty")]
    EmptyLog,
    #[error(
        "DIDComm is enabled but the VTA's DID document has no `#vta-didcomm` service entry — \
         on-disk state is inconsistent (re-run setup)"
    )]
    NoActiveMediator,
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

impl From<AppError> for DisableDidcommError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for DisableDidcommError
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

pub async fn disable_didcomm(
    deps: &ServiceOpDeps<'_>,
    auth: &AuthClaims,
    params: DisableDidcommParams,
    ctx: OpContext,
    channel: &str,
) -> Result<DisableDidcommResult, DisableDidcommError> {
    auth.require_super_admin()
        .map_err(|e| DisableDidcommError::Auth(e.to_string()))?;

    let _guard = PROTOCOL_LOCK.lock().await;

    // Pre-flight checks (atomic; nothing mutated until past here).
    let (vta_did, scid, current_doc, prior_mediator) =
        read_preconditions(deps.config, deps.webvh_ks, &params).await?;

    // Persist snapshot BEFORE the runtime mutation per spec §3.5a.
    // Pre-state is DidcommSnapshot::Enabled with the prior mediator
    // so a future `services didcomm rollback` re-enables that
    // mediator. routing_keys is empty — the existing #vta-didcomm
    // service entry doesn't carry routing-keys today.
    use crate::operations::protocol::snapshot::{self, DidcommSnapshot, ServiceConfigSnapshot};
    snapshot::write(
        deps.snapshot_ks,
        ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Enabled {
            mediator_did: prior_mediator.clone(),
            routing_keys: vec![],
        }),
    )
    .await
    .map_err(|e| DisableDidcommError::Storage(format!("snapshot write: {e}")))?;

    // Patch out the `#vta-didcomm` service entry.
    let patched = without_didcomm_service(current_doc);

    // Publish via update_did_webvh.
    let update_result = update_did_webvh(
        deps.keys_ks,
        deps.imported_ks,
        deps.contexts_ks,
        deps.webvh_ks,
        deps.audit_ks,
        deps.seed_store,
        auth,
        &scid,
        UpdateDidWebvhOptions {
            document: Some(patched),
            ..Default::default()
        },
        deps.did_resolver,
        deps.didcomm_bridge,
        Some(vta_did.as_str()),
        deps.webvh_auth_locks,
        channel,
    )
    .await?;

    // Persist: `services.didcomm = false` to fjall (authoritative runtime
    // state) + mirror into the in-memory config. `messaging` stays intact so
    // the drained listener can still reach the mediator until its TTL expires.
    crate::operations::protocol::runtime_state::set_didcomm_enabled(deps.service_state_ks, false)
        .await
        .map_err(|e| DisableDidcommError::ConfigPersistence(format!("runtime state: {e}")))?;
    {
        let mut cfg = deps.config.write().await;
        cfg.services.didcomm = false;
    }

    // Schedule the drain or immediate teardown.
    let drains_until = if params.drain_ttl.is_zero() {
        // Immediate: deactivate the registry so the listener stops
        // receiving. The teardown channel consumer in server.rs
        // calls `DIDCommService::remove_listener` when the
        // sweeper fires; with TTL=0 we don't go through the
        // sweeper, so deactivate is the only signal — the
        // listener is removed on next service restart.
        deps.registry.record_deactivate().await;
        None
    } else {
        // First, dethrone the active mediator in registry state so
        // the subsequent drain insert isn't refused with
        // `ActiveMediatorMustBeReplaced`.
        deps.registry.record_deactivate().await;
        let deadline = Utc::now()
            + chrono::Duration::from_std(params.drain_ttl).map_err(|e| {
                DisableDidcommError::ConfigPersistence(format!("drain TTL out of range: {e}"))
            })?;
        // Resolve a best-effort endpoint string for the drain
        // entry. Re-resolving the prior mediator here is bounded
        // and avoids carrying the endpoint through several layers
        // of state.
        let endpoint = best_effort_endpoint(deps.did_resolver, &prior_mediator).await;
        deps.registry
            .record_drain_persisted(deps.drains_ks, &prior_mediator, endpoint, deadline)
            .await?;
        // Arm the sweeper so the TTL actually fires. Without this
        // call the drain entry sits in fjall + registry forever
        // (it would be replayed on next boot but never expire).
        deps.sweeper.arm(&prior_mediator, deadline).await;
        Some(deadline)
    };

    let mut event = TelemetryEvent::new(TelemetryKind::ServicesDidcommDisable)
        .with_mediator(&prior_mediator)
        .with_field(
            "drain_ttl_secs",
            JsonValue::from(params.drain_ttl.as_secs()),
        )
        .with_field(
            "new_version_id",
            JsonValue::from(update_result.new_version_id.clone()),
        )
        .with_field(
            "transport",
            JsonValue::from(match params.transport {
                DisableTransport::Rest => "rest",
                DisableTransport::Didcomm => "didcomm",
            }),
        );
    if let Some(tag) = ctx.telemetry_triggered_by() {
        event = event.with_field("triggered_by", JsonValue::from(tag));
    }
    let _ = deps.telemetry.record(event).await;

    info!(
        channel,
        prior_mediator = %prior_mediator,
        new_version_id = %update_result.new_version_id,
        drain_ttl_secs = params.drain_ttl.as_secs(),
        "DIDComm disabled"
    );

    Ok(DisableDidcommResult {
        new_version_id: update_result.new_version_id,
        prior_mediator_did: prior_mediator,
        drains_until,
        vta_did,
        serverless: update_result.serverless,
    })
}

async fn read_preconditions(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
    params: &DisableDidcommParams,
) -> Result<(String, String, JsonValue, String), DisableDidcommError> {
    use crate::operations::protocol::invariant::{
        CurrentServices, ProposedOp, would_violate_last_service,
    };
    use crate::operations::protocol::snapshot::ServiceKind;
    use vta_sdk::error::VtaError;

    // Op-specific config gating (services.didcomm enabled, brick-
    // prevention, drain-TTL bounds) runs first under the read lock.
    {
        let cfg = config.read().await;
        if !cfg.services.didcomm {
            return Err(DisableDidcommError::DidcommNotEnabled);
        }
        // Brick-prevention via the shared §3.2 helper (T0.4) —
        // single source of truth across all disable / rollback paths.
        // VtaError::LastServiceRefused maps to the existing
        // NoProtocolRemaining wire variant.
        if let Err(VtaError::LastServiceRefused) = would_violate_last_service(
            &CurrentServices::new(
                cfg.services.rest,
                cfg.services.didcomm,
                cfg.services.webauthn,
            ),
            ProposedOp::disable(ServiceKind::Didcomm),
        ) {
            return Err(DisableDidcommError::NoProtocolRemaining);
        }
        crate::operations::protocol::validate_drain_ttl(params.transport, params.drain_ttl)
            .map_err(|e| DisableDidcommError::DrainTtlOutOfBounds {
                min: e.min,
                max: e.max,
                requested: e.requested,
            })?;
    }

    // Common load: `vta_did`, `scid`, `did_log`, `current_doc`.
    let state = super::preconditions::load_vta_doc_state(config, webvh_ks).await?;

    let prior_mediator =
        crate::operations::protocol::document::current_didcomm_service(&state.current_doc)
            .map(|s| s.mediator_did)
            .ok_or(DisableDidcommError::NoActiveMediator)?;

    Ok((state.vta_did, state.scid, state.current_doc, prior_mediator))
}

async fn best_effort_endpoint(resolver: &DIDCacheClient, mediator_did: &str) -> String {
    match crate::messaging::handshake::resolve_mediator(resolver, mediator_did).await {
        Ok(r) => r.endpoint,
        // Endpoint string is operational metadata only — losing it
        // doesn't break drain. The mediator DID itself is the
        // identifier the listener uses.
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use vti_common::seed_store::SeedStore;
    use vti_common::telemetry::SharedTelemetrySink;

    use super::*;
    use crate::config::AppConfig;
    use crate::didcomm_bridge::DIDCommBridge;
    use crate::keys::seed_store::PlaintextSeedStore;
    use crate::messaging::drain_sweeper::DrainSweeper;
    use crate::messaging::registry::MediatorListenerRegistry;
    use crate::operations::protocol::snapshot;
    use crate::store::Store;
    use crate::test_support::test_app_config;
    use vti_common::telemetry::RingBufferTelemetry;

    fn fresh_config(tmpdir: &std::path::Path, didcomm: bool, rest: bool) -> Arc<RwLock<AppConfig>> {
        let mut cfg = test_app_config(tmpdir.into());
        cfg.services.rest = rest;
        cfg.services.didcomm = didcomm;
        cfg.vta_did = Some("did:webvh:scid123:host:vta".into());
        cfg.config_path = tmpdir.join("config.toml");
        Arc::new(RwLock::new(cfg))
    }

    fn registry() -> (
        Arc<DIDCommBridge>,
        Arc<MediatorListenerRegistry>,
        SharedTelemetrySink,
    ) {
        let bridge = Arc::new(DIDCommBridge::placeholder());
        let sink: SharedTelemetrySink = Arc::new(RingBufferTelemetry::with_capacity(64));
        let registry = Arc::new(MediatorListenerRegistry::new(Arc::clone(&sink)));
        (bridge, registry, sink)
    }

    fn sweeper_for(
        registry: Arc<MediatorListenerRegistry>,
        drains_ks: KeyspaceHandle,
    ) -> Arc<DrainSweeper> {
        let (tx, _rx) = crate::messaging::drain_sweeper::teardown_channel(8);
        Arc::new(DrainSweeper::new(registry, drains_ks, tx))
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

    fn dummy_seed(dir: &std::path::Path) -> Arc<dyn SeedStore> {
        Arc::new(PlaintextSeedStore::new(dir))
    }

    async fn resolver() -> DIDCacheClient {
        DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap()
    }

    fn rest_params(ttl: Duration) -> DisableDidcommParams {
        DisableDidcommParams {
            drain_ttl: ttl,
            transport: DisableTransport::Rest,
        }
    }

    fn didcomm_params(ttl: Duration) -> DisableDidcommParams {
        DisableDidcommParams {
            drain_ttl: ttl,
            transport: DisableTransport::Didcomm,
        }
    }

    /// Owns every keyspace + shared infra and hands out a borrowed
    /// [`ServiceOpDeps`] (P2.5). All the refusal-path tests below bail before
    /// touching the registry/sweeper, so a fresh bundle per test is enough.
    struct TestEnv {
        _dirs: Vec<tempfile::TempDir>,
        keys_ks: KeyspaceHandle,
        imported_ks: KeyspaceHandle,
        contexts_ks: KeyspaceHandle,
        webvh_ks: KeyspaceHandle,
        audit_ks: KeyspaceHandle,
        snapshot_ks: KeyspaceHandle,
        service_state_ks: KeyspaceHandle,
        drains_ks: KeyspaceHandle,
        config: Arc<RwLock<AppConfig>>,
        seed: Arc<dyn SeedStore>,
        resolver: DIDCacheClient,
        bridge: Arc<DIDCommBridge>,
        sink: SharedTelemetrySink,
        registry: Arc<MediatorListenerRegistry>,
        sweeper: Arc<DrainSweeper>,
        locks: crate::operations::did_webvh::WebvhAuthLocks,
    }

    impl TestEnv {
        async fn new(seed_dir: &std::path::Path, config: Arc<RwLock<AppConfig>>) -> Self {
            let (bridge, registry, sink) = registry();
            let (d1, keys_ks) = empty_keyspace("keys").await;
            let (d2, imported_ks) = empty_keyspace("imported_secrets").await;
            let (d3, contexts_ks) = empty_keyspace("contexts").await;
            let (d4, webvh_ks) = empty_keyspace("webvh").await;
            let (d5, audit_ks) = empty_keyspace("audit").await;
            let (d6, snapshot_ks) = empty_keyspace(snapshot::KEYSPACE_NAME).await;
            let (d7, service_state_ks) = empty_keyspace("service_state").await;
            let (d8, drains_ks) = empty_keyspace("drains").await;
            let sweeper = sweeper_for(Arc::clone(&registry), drains_ks.clone());
            Self {
                _dirs: vec![d1, d2, d3, d4, d5, d6, d7, d8],
                keys_ks,
                imported_ks,
                contexts_ks,
                webvh_ks,
                audit_ks,
                snapshot_ks,
                service_state_ks,
                drains_ks,
                config,
                seed: dummy_seed(seed_dir),
                resolver: resolver().await,
                bridge,
                sink,
                registry,
                sweeper,
                locks: crate::operations::did_webvh::WebvhAuthLocks::new(),
            }
        }

        fn deps(&self) -> ServiceOpDeps<'_> {
            ServiceOpDeps {
                config: &self.config,
                keys_ks: &self.keys_ks,
                imported_ks: &self.imported_ks,
                contexts_ks: &self.contexts_ks,
                webvh_ks: &self.webvh_ks,
                audit_ks: &self.audit_ks,
                snapshot_ks: &self.snapshot_ks,
                service_state_ks: &self.service_state_ks,
                drains_ks: &self.drains_ks,
                seed_store: &*self.seed,
                did_resolver: &self.resolver,
                didcomm_bridge: &self.bridge,
                telemetry: &self.sink,
                webvh_auth_locks: &self.locks,
                registry: &self.registry,
                sweeper: &self.sweeper,
            }
        }
    }

    #[tokio::test]
    async fn refuses_when_not_currently_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(
            dir.path(),
            /* didcomm = */ false,
            /* rest = */ true,
        );
        let env = TestEnv::new(dir.path(), config).await;

        let err = disable_didcomm(
            &env.deps(),
            &super_admin(),
            rest_params(Duration::from_secs(3600)),
            OpContext::Direct,
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DisableDidcommError::DidcommNotEnabled));
    }

    #[tokio::test]
    async fn refuses_when_rest_also_disabled() {
        // Spec criterion #3: VTA must not end up with no protocol
        // surface.
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(
            dir.path(),
            /* didcomm = */ true,
            /* rest = */ false,
        );
        let env = TestEnv::new(dir.path(), config).await;

        let err = disable_didcomm(
            &env.deps(),
            &super_admin(),
            rest_params(Duration::from_secs(3600)),
            OpContext::Direct,
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DisableDidcommError::NoProtocolRemaining));
    }

    #[tokio::test]
    async fn refuses_short_drain_over_didcomm() {
        // Spec criterion #12: 1h minimum drain when called over
        // DIDComm transport.
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(dir.path(), true, true);
        let env = TestEnv::new(dir.path(), config).await;

        // 30 minutes < 1h minimum.
        let err = disable_didcomm(
            &env.deps(),
            &super_admin(),
            didcomm_params(Duration::from_secs(1800)),
            OpContext::Direct,
            "test",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                DisableDidcommError::DrainTtlOutOfBounds { min: 3600, .. }
            ),
            "expected DrainTtlOutOfBounds with 1h min, got {err:?}"
        );
    }

    /// Spec §7a.4 row: `--drain-ttl 31d` is rejected with
    /// `DrainTtlOutOfBounds`. Pins the upper bound at the op layer
    /// so the check no longer relies on the registry-layer guard
    /// firing late in the publication path.
    #[tokio::test]
    async fn refuses_drain_ttl_above_max() {
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(dir.path(), true, true);
        let env = TestEnv::new(dir.path(), config).await;

        // 31 days > 30-day MAX_DRAIN_TTL.
        let err = disable_didcomm(
            &env.deps(),
            &super_admin(),
            rest_params(Duration::from_secs(31 * 86_400)),
            OpContext::Direct,
            "test",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                DisableDidcommError::DrainTtlOutOfBounds { max: 2_592_000, .. }
            ),
            "expected DrainTtlOutOfBounds with 30d max, got {err:?}"
        );
    }

    #[tokio::test]
    async fn allows_zero_drain_over_rest() {
        // 0s is permitted over REST transport.
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(dir.path(), true, true);
        let env = TestEnv::new(dir.path(), config).await;

        // 0s over REST passes the TTL guard; the next refusal
        // will be VtaDidRecordMissing (because no webvh setup in
        // the fixture). That confirms TTL=0 is not the blocker.
        let err = disable_didcomm(
            &env.deps(),
            &super_admin(),
            rest_params(Duration::from_secs(0)),
            OpContext::Direct,
            "test",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, DisableDidcommError::VtaDidRecordMissing(_)),
            "TTL=0 over REST must pass the TTL guard; saw {err:?}"
        );
    }

    #[tokio::test]
    async fn allows_1h_drain_over_didcomm() {
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(dir.path(), true, true);
        let env = TestEnv::new(dir.path(), config).await;

        let err = disable_didcomm(
            &env.deps(),
            &super_admin(),
            didcomm_params(Duration::from_secs(3600)),
            OpContext::Direct,
            "test",
        )
        .await
        .unwrap_err();
        // 1h passes the TTL guard; VtaDidRecordMissing is the next
        // refusal (no webvh setup in the fixture).
        assert!(matches!(err, DisableDidcommError::VtaDidRecordMissing(_)));
    }
}
