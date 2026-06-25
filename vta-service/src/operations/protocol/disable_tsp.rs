//! `disable_tsp` operation.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.2, §3.4 +
//! `docs/05-design-notes/tsp-enablement.md`. Shares the disable skeleton
//! (brick-prevention → preconditions → snapshot → patch-remove → publish) with
//! [`super::disable_rest`] / [`super::disable_webauthn`] via the
//! [`service_lifecycle`](super::service_lifecycle) helpers; the TSP-specific
//! persist (runtime-state + in-memory flag) and telemetry stay here.
//!
//! Sequence (under [`PROTOCOL_LOCK`]):
//! 1. super-admin → 2. brick-prevention (refuse if it would leave no advertised
//!    transport) → 3. snapshot `TspSnapshot::Enabled { prior_mediator_did }`
//!    (rollback target) → 4. remove `#tsp` + publish → 5. persist
//!    `services.tsp = false` → 6. telemetry.
//!
//! TSP has no drain semantics — like REST, only the *advertisement* is
//! removed; there is no in-flight-message window to wind down.

use serde_json::Value as JsonValue;
use thiserror::Error;
use tracing::info;

use vta_sdk::error::VtaError;

use vti_common::telemetry::{TelemetryEvent, TelemetryKind};

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations::did_webvh::UpdateDidWebvhError;
use crate::operations::protocol::document::DocumentPatchError;
use crate::operations::protocol::service_lifecycle::{
    DisableMutationError, ServiceLifecycle, TspService, check_disable_preconditions, publish_patch,
};
use crate::operations::protocol::{OpContext, ServiceOpDeps};
use crate::operations::protocol::{PROTOCOL_LOCK, snapshot};

#[derive(Debug, Clone, Default)]
pub struct DisableTspParams;

#[derive(Debug, Clone)]
pub struct DisableTspResult {
    pub new_version_id: String,
    /// Pre-disable mediator DID — recorded so callers / telemetry / audit
    /// can graph what was just unadvertised.
    pub prior_mediator_did: String,
    /// The VTA's own DID. See [`super::enable_tsp::EnableTspResult`].
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted.
    pub serverless: bool,
}

#[derive(Debug, Error)]
pub enum DisableTspError {
    #[error("TSP is not currently enabled — nothing to disable.")]
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

impl From<AppError> for DisableTspError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for DisableTspError
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
impl From<VtaError> for DisableTspError {
    fn from(value: VtaError) -> Self {
        match value {
            VtaError::LastServiceRefused => Self::LastServiceRefused,
            other => Self::Storage(other.to_string()),
        }
    }
}

impl DisableMutationError for DisableTspError {
    fn not_present() -> Self {
        Self::ServiceNotPresent
    }
}

pub async fn disable_tsp(
    deps: &ServiceOpDeps<'_>,
    auth: &AuthClaims,
    _params: DisableTspParams,
    ctx: OpContext,
    channel: &str,
) -> Result<DisableTspResult, DisableTspError> {
    auth.require_super_admin()
        .map_err(|e| DisableTspError::Auth(e.to_string()))?;

    let _guard = PROTOCOL_LOCK.lock().await;

    // Brick-prevention (§3.2) + preconditions, capturing the prior mediator.
    let (state, prior_mediator_did) =
        check_disable_preconditions::<TspService, DisableTspError>(deps.config, deps.webvh_ks)
            .await?;

    // Snapshot BEFORE the mutation (spec §3.5a): pre-state is the prior mediator.
    snapshot::write(
        deps.snapshot_ks,
        TspService::snapshot_enabled(prior_mediator_did.clone()),
    )
    .await
    .map_err(|e| DisableTspError::Storage(format!("snapshot write: {e}")))?;

    let patched = TspService::without_service(state.current_doc);
    let update_result =
        publish_patch::<DisableTspError>(deps, auth, &state.scid, &state.vta_did, patched, channel)
            .await?;

    // Persist services.tsp = false to fjall (authoritative runtime state) +
    // mirror into the in-memory config. Same post-publish risk window as the
    // other ops if this fails — operator retries.
    crate::operations::protocol::runtime_state::set_tsp_enabled(deps.service_state_ks, false)
        .await
        .map_err(|e| DisableTspError::Storage(format!("runtime state: {e}")))?;
    {
        let mut cfg = deps.config.write().await;
        cfg.services.tsp = false;
    }

    let mut event = TelemetryEvent::new(TelemetryKind::ServicesTspDisable)
        .with_field("channel", JsonValue::from(channel))
        .with_field(
            "new_version_id",
            JsonValue::from(update_result.new_version_id.clone()),
        )
        .with_field("prior_url", JsonValue::from(prior_mediator_did.clone()));
    if let Some(tag) = ctx.telemetry_triggered_by() {
        event = event.with_field("triggered_by", JsonValue::from(tag));
    }
    let _ = deps.telemetry.record(event).await;

    info!(
        channel,
        prior_mediator_did = %prior_mediator_did,
        new_version_id = %update_result.new_version_id,
        vta_did = %state.vta_did,
        "TSP disabled"
    );

    Ok(DisableTspResult {
        new_version_id: update_result.new_version_id,
        prior_mediator_did,
        vta_did: state.vta_did,
        serverless: update_result.serverless,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use super::*;
    use crate::config::AppConfig;
    use crate::operations::protocol::invariant::{
        CurrentServices, ProposedOp, would_violate_last_service,
    };
    use crate::operations::protocol::snapshot::ServiceKind;
    use crate::store::{KeyspaceHandle, Store};
    use vti_common::config::StoreConfig as VtiStoreConfig;

    /// Mirrors the test fixture in disable_rest — owns the fjall store so a
    /// single test can derive multiple keyspaces from one handle.
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

    fn build_fixture(tsp_initially: bool, didcomm_initially: bool) -> TestFixture {
        use crate::test_support::test_app_config;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_app_config(dir.path().into());
        cfg.services.tsp = tsp_initially;
        cfg.services.didcomm = didcomm_initially;
        // REST defaults on in `test_app_config`; turn it off so DIDComm is
        // the only *other* transport — that makes the "TSP on, DIDComm off"
        // case a genuine brick (mirrors the disable_rest fixture, where REST
        // and DIDComm are the only two transports under test).
        cfg.services.rest = false;
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
    async fn preconditions_reject_when_tsp_disabled() {
        let fx = build_fixture(false, true);
        let err =
            check_disable_preconditions::<TspService, DisableTspError>(&fx.config, &fx.webvh_ks())
                .await
                .unwrap_err();
        assert!(matches!(err, DisableTspError::ServiceNotPresent));
    }

    /// Brick-prevention runs before the doc load: "TSP on, DIDComm off"
    /// surfaces as `LastServiceRefused` (not a missing-vta_did storage error).
    #[tokio::test]
    async fn preconditions_reject_when_would_brick() {
        let fx = build_fixture(true, false);
        let err =
            check_disable_preconditions::<TspService, DisableTspError>(&fx.config, &fx.webvh_ks())
                .await
                .unwrap_err();
        assert!(matches!(err, DisableTspError::LastServiceRefused));
    }

    #[tokio::test]
    async fn preconditions_reject_without_vta_did() {
        let fx = build_fixture(true, true);
        fx.config.write().await.vta_did = None;
        let err =
            check_disable_preconditions::<TspService, DisableTspError>(&fx.config, &fx.webvh_ks())
                .await
                .unwrap_err();
        assert!(matches!(err, DisableTspError::VtaDidNotConfigured));
    }

    /// The brick-prevention helper is wired correctly: invoking it from a
    /// "TSP on, everything else off" state with a disable-tsp op must surface
    /// as `LastServiceRefused`.
    #[test]
    fn brick_prevention_rejects_disable_tsp_when_others_off() {
        let result = would_violate_last_service(
            &CurrentServices::new(false, false, false, true),
            ProposedOp::disable(ServiceKind::Tsp),
        );
        let err = DisableTspError::from(result.unwrap_err());
        assert!(matches!(err, DisableTspError::LastServiceRefused));
    }

    /// Conversely, brick-prevention accepts disabling TSP when DIDComm is on.
    #[test]
    fn brick_prevention_allows_disable_tsp_when_didcomm_on() {
        let result = would_violate_last_service(
            &CurrentServices::new(false, true, false, true),
            ProposedOp::disable(ServiceKind::Tsp),
        );
        assert!(result.is_ok());
    }

    /// Confirms the typed `From<VtaError>` path: the helper's
    /// `LastServiceRefused` round-trips into our error variant, and any other
    /// VtaError shape lands in `Storage` (defensive).
    #[test]
    fn vta_error_to_disable_tsp_error_mapping_is_typed() {
        let mapped = DisableTspError::from(VtaError::LastServiceRefused);
        assert!(matches!(mapped, DisableTspError::LastServiceRefused));

        let mapped = DisableTspError::from(VtaError::ServiceNotPresent);
        assert!(matches!(mapped, DisableTspError::Storage(_)));
    }
}
