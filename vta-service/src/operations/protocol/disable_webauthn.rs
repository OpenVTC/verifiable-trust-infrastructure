//! `disable_webauthn` operation.
//!
//! Mirrors [`super::disable_rest`] for the WebAuthn-RP transport — sharing the
//! disable skeleton (brick-prevention → preconditions → snapshot → patch-remove
//! → publish) via the [`service_lifecycle`](super::service_lifecycle) helpers —
//! plus one WebAuthn-only concern: per the operator's chosen hard-disable
//! semantics, this op also strips passkey VMs from every DID the VTA controls
//! (a passkey VM is useless when its RP is no longer advertised).
//!
//! Sequence (under [`PROTOCOL_LOCK`]):
//! 1. super-admin → 2. brick-prevention + preconditions (capture prior URL) →
//!    3. snapshot `WebauthnSnapshot::Enabled { prior_url }` → 4. **strip passkey
//!    VMs** (per-DID failures non-fatal, surfaced in the result) → 5. remove
//!    `#vta-webauthn` + publish → 6. persist `services.webauthn = false` →
//!    7. telemetry.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde_json::Value as JsonValue;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{info, warn};

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
use crate::operations::protocol::passkey_vm_cleanup::{self, CleanupSummary};
use crate::operations::protocol::service_lifecycle::{
    DisableMutationError, ServiceLifecycle, ServiceLifecycleDeps, WebauthnService,
    check_disable_preconditions, publish_patch,
};
use crate::operations::protocol::{PROTOCOL_LOCK, snapshot};
use crate::store::KeyspaceHandle;

#[derive(Debug, Clone, Default)]
pub struct DisableWebauthnParams {}

#[derive(Debug, Clone)]
pub struct DisableWebauthnResult {
    pub new_version_id: String,
    pub vta_did: String,
    pub serverless: bool,
    /// Summary of the passkey-VM cleanup sweep. `succeeded` / `failed` counts
    /// plus per-DID outcomes so the CLI can show the operator which DIDs (if
    /// any) still need attention.
    pub cleanup: CleanupSummary,
}

#[derive(Debug, Error)]
pub enum DisableWebauthnError {
    #[error("WebAuthn is not currently enabled. Use `services webauthn enable --url <url>` first.")]
    ServiceNotPresent,
    #[error(
        "refusing to disable — at least one transport (REST, DIDComm, or WebAuthn) must remain advertised"
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

impl From<VtaError> for DisableWebauthnError {
    fn from(value: VtaError) -> Self {
        match value {
            VtaError::LastServiceRefused => Self::LastServiceRefused,
            other => Self::Storage(other.to_string()),
        }
    }
}

impl From<AppError> for DisableWebauthnError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for DisableWebauthnError
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

impl DisableMutationError for DisableWebauthnError {
    fn not_present() -> Self {
        Self::ServiceNotPresent
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn disable_webauthn(
    config: &Arc<RwLock<AppConfig>>,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    snapshot_ks: &KeyspaceHandle,
    _service_state_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    telemetry: &SharedTelemetrySink,
    auth: &AuthClaims,
    _params: DisableWebauthnParams,
    ctx: OpContext,
    webvh_auth_locks: &crate::operations::did_webvh::WebvhAuthLocks,
    channel: &str,
) -> Result<DisableWebauthnResult, DisableWebauthnError> {
    auth.require_super_admin()
        .map_err(|e| DisableWebauthnError::Auth(e.to_string()))?;

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
        check_disable_preconditions::<WebauthnService, DisableWebauthnError>(config, webvh_ks)
            .await?;

    // Snapshot BEFORE the mutation (spec §3.5a): re-enables WebAuthn at the
    // prior URL on rollback.
    snapshot::write(
        snapshot_ks,
        WebauthnService::snapshot_enabled(prior_url.clone()),
    )
    .await
    .map_err(|e| DisableWebauthnError::Storage(format!("snapshot write: {e}")))?;

    // Hard-disable: strip passkey VMs from every DID. Per-DID failures are
    // non-fatal — collected in the summary (operator's intent on disable is
    // "remove this surface AND its dependent state"; partial success beats
    // abort-and-leave-the-service-on).
    let cleanup = passkey_vm_cleanup::strip_all_passkey_vms(
        config,
        keys_ks,
        imported_ks,
        contexts_ks,
        webvh_ks,
        audit_ks,
        seed_store,
        did_resolver,
        didcomm_bridge,
        auth,
        webvh_auth_locks,
        channel,
    )
    .await?;
    if cleanup.failed > 0 {
        warn!(
            channel,
            failed = cleanup.failed,
            succeeded = cleanup.succeeded,
            "passkey-VM cleanup had per-DID failures; surface to operator",
        );
    }

    let patched = WebauthnService::without_service(state.current_doc);
    let update_result = publish_patch::<DisableWebauthnError>(
        &deps,
        auth,
        &state.scid,
        &state.vta_did,
        patched,
        channel,
    )
    .await?;

    persist_webauthn_disabled(config).await?;

    let mut event = TelemetryEvent::new(TelemetryKind::ServicesWebauthnDisable)
        .with_field("channel", JsonValue::from(channel))
        .with_field(
            "new_version_id",
            JsonValue::from(update_result.new_version_id.clone()),
        )
        .with_field("prior_url", JsonValue::from(prior_url))
        .with_field(
            "passkey_vm_cleanup_succeeded",
            JsonValue::from(cleanup.succeeded),
        )
        .with_field("passkey_vm_cleanup_failed", JsonValue::from(cleanup.failed));
    if let Some(tag) = ctx.telemetry_triggered_by() {
        event = event.with_field("triggered_by", JsonValue::from(tag));
    }
    let _ = telemetry.record(event).await;

    info!(
        channel,
        new_version_id = %update_result.new_version_id,
        vta_did = %state.vta_did,
        passkey_vm_cleanup_succeeded = cleanup.succeeded,
        passkey_vm_cleanup_failed = cleanup.failed,
        "WebAuthn disabled"
    );

    Ok(DisableWebauthnResult {
        new_version_id: update_result.new_version_id,
        vta_did: state.vta_did,
        serverless: update_result.serverless,
        cleanup,
    })
}

async fn persist_webauthn_disabled(
    config: &Arc<RwLock<AppConfig>>,
) -> Result<(), DisableWebauthnError> {
    let (contents, path) = {
        let mut cfg = config.write().await;
        cfg.services.webauthn = false;
        let contents = toml::to_string_pretty(&*cfg)
            .map_err(|e| DisableWebauthnError::ConfigPersistence(e.to_string()))?;
        let path = cfg.config_path.clone();
        (contents, path)
    };
    std::fs::write(&path, contents)
        .map_err(|e| DisableWebauthnError::ConfigPersistence(e.to_string()))?;
    Ok(())
}
