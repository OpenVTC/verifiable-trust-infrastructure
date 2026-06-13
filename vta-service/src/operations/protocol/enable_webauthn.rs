//! `enable_webauthn` operation.
//!
//! Mirrors [`super::enable_rest`] for the WebAuthn-RP transport — a thin
//! wrapper over the shared [`service_lifecycle`](super::service_lifecycle)
//! engine. See [`run_enable`] for the sequence. The only transport-specific
//! difference is how "enabled" is persisted: WebAuthn writes the config file
//! (no runtime-state keyspace), so `_service_state_ks` is unused here.
//!
//! Brick-prevention is not consulted — enabling can only add a transport
//! service.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use thiserror::Error;
use tokio::sync::RwLock;

use vti_common::seed_store::SeedStore;
use vti_common::telemetry::SharedTelemetrySink;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::operations::did_webvh::UpdateDidWebvhError;
use crate::operations::protocol::OpContext;
use crate::operations::protocol::document::DocumentPatchError;
use crate::operations::protocol::service_lifecycle::{
    EnableMutationError, ServiceLifecycleDeps, ServiceMutationError, WebauthnService, run_enable,
};
use crate::store::KeyspaceHandle;

#[derive(Debug, Clone)]
pub struct EnableWebauthnParams {
    /// Public URL the VTA will advertise on its `#vta-webauthn` service
    /// entry. Typically the auth-portal URL (e.g.
    /// `https://vta.example.com/auth/portal`).
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct EnableWebauthnResult {
    pub new_version_id: String,
    pub url: String,
    pub vta_did: String,
    pub serverless: bool,
}

#[derive(Debug, Error)]
pub enum EnableWebauthnError {
    #[error(
        "WebAuthn is already enabled. Use `services webauthn update --url <url>` to change the URL."
    )]
    ServiceAlreadyEnabled,
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
    #[error("config persistence failed: {0}")]
    ConfigPersistence(String),
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<AppError> for EnableWebauthnError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for EnableWebauthnError
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

impl ServiceMutationError for EnableWebauthnError {
    fn validation(msg: String) -> Self {
        Self::Validation(msg)
    }
    fn auth(msg: String) -> Self {
        Self::Auth(msg)
    }
    fn storage(msg: String) -> Self {
        Self::Storage(msg)
    }
}

impl EnableMutationError for EnableWebauthnError {
    fn already_enabled() -> Self {
        Self::ServiceAlreadyEnabled
    }
    fn config_persistence(msg: String) -> Self {
        Self::ConfigPersistence(msg)
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn enable_webauthn(
    config: &Arc<RwLock<AppConfig>>,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    snapshot_ks: &KeyspaceHandle,
    // Threaded by every caller for signature parity with the other protocol-
    // mutation operations; WebAuthn persists to the config file, not the
    // per-kind service-state keyspace, so it is unused here.
    _service_state_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    telemetry: &SharedTelemetrySink,
    auth: &AuthClaims,
    params: EnableWebauthnParams,
    ctx: OpContext,
    webvh_auth_locks: &crate::operations::did_webvh::WebvhAuthLocks,
    channel: &str,
) -> Result<EnableWebauthnResult, EnableWebauthnError> {
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
    // WebAuthn persists "enabled" by writing the config file.
    let ok = run_enable::<WebauthnService, EnableWebauthnError>(
        &deps,
        auth,
        &params.url,
        ctx,
        channel,
        || async {
            let (contents, path) = {
                let mut cfg = config.write().await;
                cfg.services.webauthn = true;
                let contents = toml::to_string_pretty(&*cfg).map_err(|e| e.to_string())?;
                let path = cfg.config_path.clone();
                (contents, path)
            };
            std::fs::write(&path, contents).map_err(|e| e.to_string())?;
            Ok(())
        },
    )
    .await?;

    Ok(EnableWebauthnResult {
        new_version_id: ok.new_version_id,
        url: ok.canonical_url,
        vta_did: ok.vta_did,
        serverless: ok.serverless,
    })
}
