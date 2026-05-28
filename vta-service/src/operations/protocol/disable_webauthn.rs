//! `disable_webauthn` operation.
//!
//! Mirrors [`super::disable_rest`] for the WebAuthn-RP transport, plus
//! one additional concern: per the operator's chosen hard-disable
//! semantics, this op also strips passkey VMs from every DID the VTA
//! controls (a passkey VM is useless when its RP is no longer
//! advertised).
//!
//! Sequence (under [`PROTOCOL_LOCK`]):
//! 1. Verify caller is super-admin.
//! 2. Brick-prevention check (REST or DIDComm or no-other-on-WebAuthn).
//! 3. Confirm `services.webauthn = true` and `#vta-webauthn` is
//!    advertised; load the prior URL for the snapshot.
//! 4. Persist a [`WebauthnSnapshot::Enabled { url: prior_url }`]
//!    snapshot before the mutation, per spec §3.5a.
//! 5. **Strip passkey VMs** from every DID via
//!    [`super::passkey_vm_cleanup::strip_all_passkey_vms`]. Per-DID
//!    failures are non-fatal — they're returned in the result so
//!    the operator can investigate, and the disable still proceeds
//!    (an operator who disables but leaves orphan VMs can fix
//!    individual DIDs later).
//! 6. Patch the VTA's DID document removing `#vta-webauthn` and
//!    publish via [`update_did_webvh`].
//! 7. Persist `services.webauthn = false`.
//! 8. Emit [`TelemetryKind::ServicesWebauthnDisable`].

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde_json::Value as JsonValue;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{info, warn};

use vti_common::seed_store::SeedStore;
use vti_common::telemetry::{SharedTelemetrySink, TelemetryEvent, TelemetryKind};

use vta_sdk::error::VtaError;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::operations::did_webvh::{UpdateDidWebvhError, UpdateDidWebvhOptions, update_did_webvh};
use crate::operations::protocol::document::{
    DocumentPatchError, current_webauthn_service, without_webauthn_service,
};
use crate::operations::protocol::invariant::{
    CurrentServices, ProposedOp, would_violate_last_service,
};
use crate::operations::protocol::passkey_vm_cleanup::{self, CleanupSummary};
use crate::operations::protocol::snapshot::{
    self, ServiceConfigSnapshot, ServiceKind, WebauthnSnapshot,
};
use crate::operations::protocol::{OpContext, PROTOCOL_LOCK};
use crate::store::KeyspaceHandle;

#[derive(Debug, Clone, Default)]
pub struct DisableWebauthnParams {}

#[derive(Debug, Clone)]
pub struct DisableWebauthnResult {
    pub new_version_id: String,
    pub vta_did: String,
    pub serverless: bool,
    /// Summary of the passkey-VM cleanup sweep. `succeeded` /
    /// `failed` counts plus per-DID outcomes so the CLI can show
    /// the operator which DIDs (if any) still need attention.
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

    // 1. Brick-prevention check up front — cheap, no I/O.
    let (rest_enabled, didcomm_enabled) = {
        let cfg = config.read().await;
        if !cfg.services.webauthn {
            return Err(DisableWebauthnError::ServiceNotPresent);
        }
        (cfg.services.rest, cfg.services.didcomm)
    };
    would_violate_last_service(
        &CurrentServices::new(rest_enabled, didcomm_enabled, true),
        ProposedOp::disable(ServiceKind::Webauthn),
    )?;

    // 2. Read preconditions: capture the prior URL for the snapshot.
    let (vta_did, scid, current_doc, prior_url) = read_preconditions(config, webvh_ks).await?;

    // 3. Persist snapshot BEFORE the runtime mutation per spec §3.5a.
    //    Pre-state is WebauthnSnapshot::Enabled with the prior URL so
    //    a rollback re-enables WebAuthn at that URL.
    snapshot::write(
        snapshot_ks,
        ServiceConfigSnapshot::Webauthn(WebauthnSnapshot::Enabled {
            url: prior_url.clone(),
        }),
    )
    .await
    .map_err(|e| DisableWebauthnError::Storage(format!("snapshot write: {e}")))?;

    // 4. Hard-disable: strip passkey VMs from every DID. Per-DID
    //    failures are non-fatal — we collect them in the summary.
    //    Best-effort by design (operator's intent on disable is
    //    "remove this surface AND its dependent state"; partial
    //    success is better than abort-and-leave-the-service-on).
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

    // 5. Remove the WebAuthn service entry and publish.
    let patched = without_webauthn_service(current_doc);

    let update_result = update_did_webvh(
        keys_ks,
        imported_ks,
        contexts_ks,
        webvh_ks,
        audit_ks,
        seed_store,
        auth,
        &scid,
        UpdateDidWebvhOptions {
            document: Some(patched),
            ..Default::default()
        },
        did_resolver,
        didcomm_bridge,
        Some(vta_did.as_str()),
        webvh_auth_locks,
        channel,
    )
    .await?;

    // 6. Persist services.webauthn = false.
    persist_webauthn_disabled(config).await?;

    // 7. Telemetry.
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
        vta_did = %vta_did,
        passkey_vm_cleanup_succeeded = cleanup.succeeded,
        passkey_vm_cleanup_failed = cleanup.failed,
        "WebAuthn disabled"
    );

    Ok(DisableWebauthnResult {
        new_version_id: update_result.new_version_id,
        vta_did,
        serverless: update_result.serverless,
        cleanup,
    })
}

async fn read_preconditions(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
) -> Result<(String, String, JsonValue, String), DisableWebauthnError> {
    let state = super::preconditions::load_vta_doc_state(config, webvh_ks).await?;
    let svc = current_webauthn_service(&state.current_doc)
        .ok_or(DisableWebauthnError::ServiceNotPresent)?;
    Ok((state.vta_did, state.scid, state.current_doc, svc.url))
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
