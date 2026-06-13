//! `rollback_webauthn` operation — fail-forward dispatch.
//!
//! Mirrors [`super::rollback_rest`] for the WebAuthn-RP transport.
//! Reads the snapshot for `webauthn` and dispatches into the
//! equivalent forward op (enable / update / disable) to return the
//! VTA's WebAuthn advertisement to the pre-mutation state.
//!
//! See [`super::rollback_rest`] for the full design rationale —
//! WebVH is append-only, rollback appends a new LogEntry, no-op when
//! snapshot ≡ current.

use std::sync::Arc;

use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::operations::did_webvh::UpdateDidWebvhError;
use crate::operations::protocol::disable_webauthn::{
    DisableWebauthnError, DisableWebauthnParams, disable_webauthn,
};
use crate::operations::protocol::document::{DocumentPatchError, current_webauthn_service};
use crate::operations::protocol::enable_webauthn::{
    EnableWebauthnError, EnableWebauthnParams, enable_webauthn,
};
use crate::operations::protocol::snapshot::{
    self, ServiceConfigSnapshot, ServiceKind, WebauthnSnapshot,
};
use crate::operations::protocol::update_webauthn::{
    UpdateWebauthnError, UpdateWebauthnParams, update_webauthn,
};
use crate::operations::protocol::{OpContext, ServiceOpDeps};
use crate::store::KeyspaceHandle;

#[derive(Debug, Clone, Default)]
pub struct RollbackWebauthnParams;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackKind {
    Disabled,
    Enabled,
    Updated,
    NoOp,
}

#[derive(Debug, Clone)]
pub struct RollbackWebauthnResult {
    pub new_version_id: Option<String>,
    pub kind: RollbackKind,
    pub vta_did: String,
    pub serverless: bool,
}

#[derive(Debug, Error)]
pub enum RollbackWebauthnError {
    #[error(
        "no prior mutation for `services webauthn` to roll back from. \
         Use `services webauthn enable / update / disable` directly instead."
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

    #[error(transparent)]
    EnableForward(#[from] EnableWebauthnError),
    #[error(transparent)]
    UpdateForward(#[from] UpdateWebauthnError),
    #[error(transparent)]
    DisableForward(#[from] DisableWebauthnError),

    #[error("DID document patch failed: {0}")]
    DocumentPatch(#[from] DocumentPatchError),
    #[error("WebVH update failed: {0}")]
    WebVHUpdate(#[from] UpdateDidWebvhError),
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<AppError> for RollbackWebauthnError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for RollbackWebauthnError
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

pub async fn rollback_webauthn(
    deps: &ServiceOpDeps<'_>,
    auth: &AuthClaims,
    _params: RollbackWebauthnParams,
    channel: &str,
) -> Result<RollbackWebauthnResult, RollbackWebauthnError> {
    auth.require_super_admin()
        .map_err(|e| RollbackWebauthnError::Auth(e.to_string()))?;

    let snap = snapshot::read(deps.snapshot_ks, ServiceKind::Webauthn)
        .await
        .map_err(|e| RollbackWebauthnError::Storage(format!("snapshot read: {e}")))?
        .ok_or(RollbackWebauthnError::NoPriorMutation)?;
    let webauthn_snap = match snap {
        ServiceConfigSnapshot::Webauthn(s) => s,
        other => {
            return Err(RollbackWebauthnError::Storage(format!(
                "snapshot kind mismatch: stored {other:?}, requested Webauthn",
            )));
        }
    };

    let current_url = read_current_webauthn_url(deps.config, deps.webvh_ks).await?;

    info!(
        channel,
        snapshot = ?webauthn_snap,
        current = ?current_url,
        "rollback_webauthn dispatching",
    );

    match (webauthn_snap, current_url.as_deref()) {
        (WebauthnSnapshot::Disabled, Some(_)) => {
            let result = disable_webauthn(
                deps,
                auth,
                DisableWebauthnParams::default(),
                OpContext::Rollback,
                channel,
            )
            .await?;
            Ok(RollbackWebauthnResult {
                new_version_id: Some(result.new_version_id),
                kind: RollbackKind::Disabled,
                vta_did: result.vta_did,
                serverless: result.serverless,
            })
        }
        (WebauthnSnapshot::Enabled { url }, None) => {
            let result = enable_webauthn(
                deps,
                auth,
                EnableWebauthnParams { url: url.clone() },
                OpContext::Rollback,
                channel,
            )
            .await?;
            Ok(RollbackWebauthnResult {
                new_version_id: Some(result.new_version_id),
                kind: RollbackKind::Enabled,
                vta_did: result.vta_did,
                serverless: result.serverless,
            })
        }
        (WebauthnSnapshot::Enabled { url }, Some(current)) if url != current => {
            let result = update_webauthn(
                deps,
                auth,
                UpdateWebauthnParams { url: url.clone() },
                OpContext::Rollback,
                channel,
            )
            .await?;
            Ok(RollbackWebauthnResult {
                new_version_id: Some(result.new_version_id),
                kind: RollbackKind::Updated,
                vta_did: result.vta_did,
                serverless: result.serverless,
            })
        }
        _ => {
            info!(
                channel,
                "rollback_webauthn: snapshot matches current state — no-op"
            );
            Ok(RollbackWebauthnResult {
                new_version_id: None,
                kind: RollbackKind::NoOp,
                vta_did: String::new(),
                serverless: false,
            })
        }
    }
}

async fn read_current_webauthn_url(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
) -> Result<Option<String>, RollbackWebauthnError> {
    let state = super::preconditions::load_vta_doc_state(config, webvh_ks).await?;
    Ok(current_webauthn_service(&state.current_doc).map(|svc| svc.url))
}
