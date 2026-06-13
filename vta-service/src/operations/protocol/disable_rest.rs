//! `disable_rest` operation.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.2, §3.4.
//! Shares the disable skeleton (brick-prevention → preconditions → snapshot →
//! patch-remove → publish) with [`super::disable_webauthn`] via the
//! [`service_lifecycle`](super::service_lifecycle) helpers; the REST-specific
//! persist (runtime-state + in-memory flag) and telemetry stay here.
//!
//! Sequence (under [`PROTOCOL_LOCK`]):
//! 1. super-admin → 2. brick-prevention (refuse if it would leave no advertised
//!    transport) → 3. snapshot `RestSnapshot::Enabled { prior_url }` (rollback
//!    target) → 4. remove `#vta-rest` + publish → 5. persist `services.rest =
//!    false` → 6. telemetry.
//!
//! REST has no drain semantics — the Axum process stays running (it's a
//! process-level binding), so the local CLI can still reach the VTA; only the
//! *advertisement* is removed.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde_json::Value as JsonValue;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use vta_sdk::error::VtaError;

use vti_common::seed_store::SeedStore;
use vti_common::telemetry::{SharedTelemetrySink, TelemetryEvent, TelemetryKind};

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::operations::did_webvh::UpdateDidWebvhError;
use crate::operations::protocol::OpContext;
use crate::operations::protocol::document::DocumentPatchError;
use crate::operations::protocol::service_lifecycle::{
    DisableMutationError, RestService, ServiceLifecycle, ServiceLifecycleDeps,
    check_disable_preconditions, publish_patch,
};
use crate::operations::protocol::{PROTOCOL_LOCK, snapshot};
use crate::store::KeyspaceHandle;

#[derive(Debug, Clone, Default)]
pub struct DisableRestParams;

#[derive(Debug, Clone)]
pub struct DisableRestResult {
    pub new_version_id: String,
    /// Pre-disable URL — recorded so callers / telemetry / audit can graph
    /// what was just unadvertised.
    pub prior_url: String,
    /// The VTA's own DID. See [`super::enable_rest::EnableRestResult`].
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted.
    pub serverless: bool,
}

#[derive(Debug, Error)]
pub enum DisableRestError {
    #[error("REST is not currently enabled — nothing to disable.")]
    ServiceNotPresent,
    #[error(
        "refusing operation: would leave the VTA with no advertised services. \
         Enable DIDComm first via `services didcomm enable --mediator-did <did>`, \
         then retry."
    )]
    LastServiceRefused,
    #[error("VTA DID is not configured — run `vta setup` first")]
    VtaDidNotConfigured,
    #[error("VTA DID `{0}` has no webvh record")]
    VtaDidRecordMissing(String),
    #[error("VTA DID `{0}` has no published log")]
    VtaDidLogMissing(String),
    #[error("VTA DID log is empty")]
    EmptyLog,
    #[error("DID document patch failed: {0}")]
    DocumentPatch(#[from] DocumentPatchError),
    #[error("WebVH update failed: {0}")]
    WebVHUpdate(#[from] UpdateDidWebvhError),
    #[error("config persistence failed: {0}")]
    ConfigPersistence(String),
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<AppError> for DisableRestError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for DisableRestError
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

/// Map [`VtaError::LastServiceRefused`] (from the invariant helper) onto our
/// typed variant. Other [`VtaError`] shapes shouldn't surface here — the helper
/// is total over its inputs — but if one ever does we route it through
/// `Storage` so it isn't silently swallowed.
impl From<VtaError> for DisableRestError {
    fn from(value: VtaError) -> Self {
        match value {
            VtaError::LastServiceRefused => Self::LastServiceRefused,
            other => Self::Storage(other.to_string()),
        }
    }
}

impl DisableMutationError for DisableRestError {
    fn not_present() -> Self {
        Self::ServiceNotPresent
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn disable_rest(
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
    _params: DisableRestParams,
    ctx: OpContext,
    webvh_auth_locks: &crate::operations::did_webvh::WebvhAuthLocks,
    channel: &str,
) -> Result<DisableRestResult, DisableRestError> {
    auth.require_super_admin()
        .map_err(|e| DisableRestError::Auth(e.to_string()))?;

    let _guard = PROTOCOL_LOCK.lock().await;

    let deps = ServiceLifecycleDeps {
        config,
        keys_ks,
        imported_ks,
        contexts_ks,
        webvh_ks,
        audit_ks,
        snapshot_ks,
        seed_store,
        did_resolver,
        didcomm_bridge,
        telemetry,
        webvh_auth_locks,
    };

    // Brick-prevention (§3.2) + preconditions, capturing the prior URL.
    let (state, prior_url) =
        check_disable_preconditions::<RestService, DisableRestError>(config, webvh_ks).await?;

    // Snapshot BEFORE the mutation (spec §3.5a): pre-state is the prior URL.
    snapshot::write(
        snapshot_ks,
        RestService::snapshot_enabled(prior_url.clone()),
    )
    .await
    .map_err(|e| DisableRestError::Storage(format!("snapshot write: {e}")))?;

    let patched = RestService::without_service(state.current_doc);
    let update_result = publish_patch::<DisableRestError>(
        &deps,
        auth,
        &state.scid,
        &state.vta_did,
        patched,
        channel,
    )
    .await?;

    // Persist services.rest = false to fjall (authoritative runtime state) +
    // mirror into the in-memory config. Same post-publish risk window as the
    // other ops if this fails — operator retries.
    crate::operations::protocol::runtime_state::set_rest_enabled(service_state_ks, false)
        .await
        .map_err(|e| DisableRestError::Storage(format!("runtime state: {e}")))?;
    {
        let mut cfg = config.write().await;
        cfg.services.rest = false;
    }

    let mut event = TelemetryEvent::new(TelemetryKind::ServicesRestDisable)
        .with_field("channel", JsonValue::from(channel))
        .with_field(
            "new_version_id",
            JsonValue::from(update_result.new_version_id.clone()),
        )
        .with_field("prior_url", JsonValue::from(prior_url.clone()));
    if let Some(tag) = ctx.telemetry_triggered_by() {
        event = event.with_field("triggered_by", JsonValue::from(tag));
    }
    let _ = telemetry.record(event).await;

    info!(
        channel,
        prior_url = %prior_url,
        new_version_id = %update_result.new_version_id,
        vta_did = %state.vta_did,
        "REST disabled"
    );

    Ok(DisableRestResult {
        new_version_id: update_result.new_version_id,
        prior_url,
        vta_did: state.vta_did,
        serverless: update_result.serverless,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::protocol::invariant::{
        CurrentServices, ProposedOp, would_violate_last_service,
    };
    use crate::operations::protocol::snapshot::ServiceKind;
    use crate::store::Store;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    /// Mirrors the test fixture in enable_rest / update_rest — owns the fjall
    /// store so a single test can derive multiple keyspaces from one handle.
    struct TestFixture {
        _dir: tempfile::TempDir,
        config: Arc<RwLock<AppConfig>>,
        store: Store,
    }

    impl TestFixture {
        fn webvh_ks(&self) -> KeyspaceHandle {
            self.store.keyspace(crate::keyspaces::WEBVH).unwrap()
        }
    }

    fn build_fixture(rest_initially: bool, didcomm_initially: bool) -> TestFixture {
        use crate::test_support::test_app_config;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_app_config(dir.path().into());
        cfg.services.rest = rest_initially;
        cfg.services.didcomm = didcomm_initially;
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
            config: Arc::new(RwLock::new(cfg)),
            store,
        }
    }

    #[tokio::test]
    async fn preconditions_reject_when_rest_disabled() {
        let fx = build_fixture(false, true);
        let err = check_disable_preconditions::<RestService, DisableRestError>(
            &fx.config,
            &fx.webvh_ks(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DisableRestError::ServiceNotPresent));
    }

    /// Brick-prevention runs before the doc load: "REST on, DIDComm off"
    /// surfaces as `LastServiceRefused` (not a missing-vta_did storage error).
    #[tokio::test]
    async fn preconditions_reject_when_would_brick() {
        let fx = build_fixture(true, false);
        let err = check_disable_preconditions::<RestService, DisableRestError>(
            &fx.config,
            &fx.webvh_ks(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DisableRestError::LastServiceRefused));
    }

    #[tokio::test]
    async fn preconditions_reject_without_vta_did() {
        let fx = build_fixture(true, true);
        fx.config.write().await.vta_did = None;
        let err = check_disable_preconditions::<RestService, DisableRestError>(
            &fx.config,
            &fx.webvh_ks(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DisableRestError::VtaDidNotConfigured));
    }

    /// The brick-prevention helper is wired correctly: invoking it from a
    /// "REST on, DIDComm off" state with a disable-rest op must surface as
    /// `LastServiceRefused`.
    #[test]
    fn brick_prevention_rejects_disable_rest_when_didcomm_off() {
        let result = would_violate_last_service(
            &CurrentServices::new(true, false, false),
            ProposedOp::disable(ServiceKind::Rest),
        );
        let err = DisableRestError::from(result.unwrap_err());
        assert!(matches!(err, DisableRestError::LastServiceRefused));
    }

    /// Conversely, brick-prevention accepts disabling REST when DIDComm is on.
    #[test]
    fn brick_prevention_allows_disable_rest_when_didcomm_on() {
        let result = would_violate_last_service(
            &CurrentServices::new(true, true, false),
            ProposedOp::disable(ServiceKind::Rest),
        );
        assert!(result.is_ok());
    }

    /// Disabling REST is also allowed when WebAuthn alone is on — WebAuthn
    /// counts as a transport for invariant purposes.
    #[test]
    fn brick_prevention_allows_disable_rest_when_webauthn_on() {
        let result = would_violate_last_service(
            &CurrentServices::new(true, false, true),
            ProposedOp::disable(ServiceKind::Rest),
        );
        assert!(result.is_ok());
    }

    /// Confirms the typed `From<VtaError>` path: the helper's
    /// `LastServiceRefused` round-trips into our error variant, and any other
    /// VtaError shape lands in `Storage` (defensive).
    #[test]
    fn vta_error_to_disable_rest_error_mapping_is_typed() {
        let mapped = DisableRestError::from(VtaError::LastServiceRefused);
        assert!(matches!(mapped, DisableRestError::LastServiceRefused));

        let mapped = DisableRestError::from(VtaError::ServiceNotPresent);
        assert!(matches!(mapped, DisableRestError::Storage(_)));
    }
}
