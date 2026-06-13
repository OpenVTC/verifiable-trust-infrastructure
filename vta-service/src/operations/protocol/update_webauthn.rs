//! `update_webauthn` operation.
//!
//! Mirrors [`super::update_rest`] for the WebAuthn-RP transport — a thin
//! wrapper over the shared [`service_lifecycle`](super::service_lifecycle)
//! engine. See [`run_update`] for the sequence. Replaces the URL on an existing
//! `#vta-webauthn` entry; refuses with [`UpdateWebauthnError::ServiceNotPresent`]
//! when WebAuthn is not currently advertised. Snapshots the prior URL so
//! rollback can restore it.

use thiserror::Error;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations::did_webvh::UpdateDidWebvhError;
use crate::operations::protocol::document::DocumentPatchError;
use crate::operations::protocol::service_lifecycle::{
    ServiceMutationError, UpdateMutationError, WebauthnService, run_update,
};
use crate::operations::protocol::{OpContext, ServiceOpDeps};

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

impl ServiceMutationError for UpdateWebauthnError {
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

impl UpdateMutationError for UpdateWebauthnError {
    fn not_present() -> Self {
        Self::ServiceNotPresent
    }
}

pub async fn update_webauthn(
    deps: &ServiceOpDeps<'_>,
    auth: &AuthClaims,
    params: UpdateWebauthnParams,
    ctx: OpContext,
    channel: &str,
) -> Result<UpdateWebauthnResult, UpdateWebauthnError> {
    let ok =
        run_update::<WebauthnService, UpdateWebauthnError>(deps, auth, &params.url, ctx, channel)
            .await?;

    Ok(UpdateWebauthnResult {
        new_version_id: ok.new_version_id,
        url: ok.canonical_url,
        vta_did: ok.vta_did,
        serverless: ok.serverless,
    })
}
