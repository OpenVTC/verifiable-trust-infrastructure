//! `update_webauthn` operation.
//!
//! Mirrors [`super::update_rest`]: replaces the URL on an existing
//! `#vta-webauthn` entry. Refuses with
//! [`UpdateWebauthnError::ServiceNotPresent`] when WebAuthn is not
//! currently advertised.
//!
//! Snapshots the prior URL so rollback can restore it.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde_json::Value as JsonValue;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use vti_common::seed_store::SeedStore;
use vti_common::telemetry::{SharedTelemetrySink, TelemetryEvent, TelemetryKind};

use vta_sdk::protocol::services::validate_service_url;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::operations::did_webvh::{UpdateDidWebvhError, UpdateDidWebvhOptions, update_did_webvh};
use crate::operations::protocol::document::{
    DocumentPatchError, current_webauthn_service, with_webauthn_service,
};
use crate::operations::protocol::snapshot::{self, ServiceConfigSnapshot, WebauthnSnapshot};
use crate::operations::protocol::{OpContext, PROTOCOL_LOCK};
use crate::store::KeyspaceHandle;

#[derive(Debug, Clone)]
pub struct UpdateWebauthnParams {
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct UpdateWebauthnResult {
    pub new_version_id: String,
    pub url: String,
    pub vta_did: String,
    pub serverless: bool,
}

#[derive(Debug, Error)]
pub enum UpdateWebauthnError {
    #[error("WebAuthn is not currently enabled. Use `services webauthn enable --url <url>` first.")]
    ServiceNotPresent,
    #[error("invalid URL: {0}")]
    Validation(String),
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
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<AppError> for UpdateWebauthnError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for UpdateWebauthnError
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
pub async fn update_webauthn(
    config: &Arc<RwLock<AppConfig>>,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    snapshot_ks: &KeyspaceHandle,
    // Threaded by every caller for signature parity with the other
    // protocol-mutation operations. Not consumed inside this function;
    // see `enable_webauthn` for the rationale.
    _service_state_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    telemetry: &SharedTelemetrySink,
    auth: &AuthClaims,
    params: UpdateWebauthnParams,
    ctx: OpContext,
    webvh_auth_locks: &crate::operations::did_webvh::WebvhAuthLocks,
    channel: &str,
) -> Result<UpdateWebauthnResult, UpdateWebauthnError> {
    auth.require_super_admin()
        .map_err(|e| UpdateWebauthnError::Auth(e.to_string()))?;

    let _guard = PROTOCOL_LOCK.lock().await;

    let validated = validate_service_url(&params.url)
        .map_err(|e| UpdateWebauthnError::Validation(e.to_string()))?;
    let canonical_url = validated.to_string();

    let (vta_did, scid, current_doc, prior_url) = read_preconditions(config, webvh_ks).await?;

    snapshot::write(
        snapshot_ks,
        ServiceConfigSnapshot::Webauthn(WebauthnSnapshot::Enabled { url: prior_url }),
    )
    .await
    .map_err(|e| UpdateWebauthnError::Storage(format!("snapshot write: {e}")))?;

    let patched = with_webauthn_service(current_doc, &canonical_url)?;

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

    let mut event = TelemetryEvent::new(TelemetryKind::ServicesWebauthnUpdate)
        .with_field("channel", JsonValue::from(channel))
        .with_field(
            "new_version_id",
            JsonValue::from(update_result.new_version_id.clone()),
        )
        .with_field("url", JsonValue::from(canonical_url.clone()));
    if let Some(tag) = ctx.telemetry_triggered_by() {
        event = event.with_field("triggered_by", JsonValue::from(tag));
    }
    let _ = telemetry.record(event).await;

    info!(
        channel,
        url = %canonical_url,
        new_version_id = %update_result.new_version_id,
        vta_did = %vta_did,
        "WebAuthn updated"
    );

    Ok(UpdateWebauthnResult {
        new_version_id: update_result.new_version_id,
        url: canonical_url,
        vta_did,
        serverless: update_result.serverless,
    })
}

async fn read_preconditions(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
) -> Result<(String, String, JsonValue, String), UpdateWebauthnError> {
    {
        let cfg = config.read().await;
        if !cfg.services.webauthn {
            return Err(UpdateWebauthnError::ServiceNotPresent);
        }
    }

    let state = super::preconditions::load_vta_doc_state(config, webvh_ks).await?;

    let prior = current_webauthn_service(&state.current_doc)
        .ok_or(UpdateWebauthnError::ServiceNotPresent)?;

    Ok((state.vta_did, state.scid, state.current_doc, prior.url))
}
