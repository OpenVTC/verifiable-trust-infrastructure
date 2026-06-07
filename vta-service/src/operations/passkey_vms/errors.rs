use thiserror::Error;

use crate::error::AppError;
use crate::operations::did_webvh::UpdateDidWebvhError;

use super::multikey::MultikeyError;

#[derive(Debug, Error)]
pub enum PasskeyVmError {
    /// `passkey` feature not configured (no `public_url`, etc.).
    #[error("passkey enrolment not available: {0}")]
    NotAvailable(String),
    /// Ceremony id unknown, expired, or already consumed.
    #[error("unknown or expired ceremony id")]
    UnknownCeremony,
    /// The submitted DID doesn't match the DID associated with the
    /// ceremony — replay against a different DID.
    #[error("ceremony/DID mismatch")]
    CeremonyDidMismatch,
    /// WebAuthn `attestationObject` couldn't be parsed.
    #[error("invalid attestation: {0}")]
    InvalidAttestation(String),
    /// WebAuthn-rs rejected the assertion.
    #[error("webauthn ceremony failed: {0}")]
    WebauthnFinishFailed(String),
    /// Browser-claimed multikey doesn't match the one re-derived from
    /// `attestationObject.authData`. This is the anti-tamper gate.
    #[error("public-key mismatch — browser tampered with the multikey")]
    PublicKeyMismatch,
    /// COSE → Multikey conversion failed.
    #[error("multikey conversion failed: {0}")]
    Multikey(#[from] MultikeyError),
    /// DID `id` field in the request body doesn't match the DID
    /// associated with the ceremony.
    #[error("DID not found or not VTA-managed")]
    DidNotFound,
    /// Caller is authenticated but lacks the admin role required to
    /// mutate this DID's passkey VMs. Distinct from the internal-error
    /// bucket so it renders as a 403 `permissionDenied`, not a 500.
    #[error("admin role required")]
    PermissionDenied(String),
    /// Revoke target fragment is not present on the DID document. The
    /// spec distinguishes this from `didNotFound` so a client can tell
    /// "wrong DID" from "already gone".
    #[error("passkey verification-method fragment not found")]
    FragmentNotFound,
    /// Two passkeys with the same WebAuthn credential id can't share
    /// the same DID — fragment collision.
    #[error("passkey already enrolled on this DID")]
    AlreadyEnrolled,
    /// The DID document already references the fragment we'd produce
    /// (race or replay).
    #[error("verification-method fragment collision: {0}")]
    FragmentCollision(String),
    /// Bubbled up from the underlying WebVH update.
    #[error(transparent)]
    Update(#[from] UpdateDidWebvhError),
    /// Persistence-layer error.
    #[error("persistence: {0}")]
    Persistence(String),
    /// Other / generic.
    #[error("{0}")]
    Internal(String),
}

impl From<PasskeyVmError> for AppError {
    fn from(e: PasskeyVmError) -> Self {
        match e {
            PasskeyVmError::NotAvailable(msg) => AppError::ServiceError {
                status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
                message: msg,
            },
            PasskeyVmError::UnknownCeremony => AppError::NotFound("unknown ceremony".into()),
            PasskeyVmError::CeremonyDidMismatch => {
                AppError::Authentication("ceremony/DID mismatch".into())
            }
            PasskeyVmError::InvalidAttestation(msg) => AppError::Validation(msg),
            PasskeyVmError::WebauthnFinishFailed(msg) => AppError::Authentication(msg),
            PasskeyVmError::PublicKeyMismatch => {
                AppError::Validation("publicKeyMultibase mismatch".into())
            }
            PasskeyVmError::Multikey(e) => AppError::Validation(format!("multikey: {e}")),
            PasskeyVmError::DidNotFound => AppError::NotFound("DID not managed by this VTA".into()),
            PasskeyVmError::PermissionDenied(msg) => AppError::Forbidden(msg),
            PasskeyVmError::FragmentNotFound => {
                AppError::NotFound("passkey verification-method fragment not found".into())
            }
            PasskeyVmError::AlreadyEnrolled => {
                AppError::Conflict("passkey already enrolled".into())
            }
            PasskeyVmError::FragmentCollision(msg) => AppError::Conflict(msg),
            PasskeyVmError::Update(e) => AppError::from(e),
            PasskeyVmError::Persistence(msg) => AppError::Internal(msg),
            PasskeyVmError::Internal(msg) => AppError::Internal(msg),
        }
    }
}
