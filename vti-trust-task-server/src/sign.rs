//! Signing every answer, refusals included.
//!
//! SPEC §7.3 item 7: where a specification declares no separate requirement
//! for the *response*, the request's applies to it. Every response document —
//! success **and** `trust-task-error` — is signed with `proofPurpose:
//! authentication` (VTI-KEY-106), so a client that refuses unsigned replies can
//! attribute a refusal as well as a result. Signing once, in the spine, is
//! what keeps a handler from forgetting to.

use serde_json::Value;
use vti_common::error::AppError;

use crate::TrustTaskOutcome;

/// Attaches the service's Data-Integrity proof to a response document.
#[async_trait::async_trait]
pub trait ResponseSigner: Send + Sync {
    /// Add a `proof` member to `doc`, made for `authentication`.
    async fn sign_response_document(&self, doc: &mut Value) -> Result<(), AppError>;
}

/// Sign `outcome`'s document with `signer`.
///
/// Left alone: an empty body, a document that already carries a proof, and
/// every document when there is no signer (a service before provisioning has
/// nothing to sign with, and refusing to answer would make it unusable rather
/// than merely unattributable). A signing failure answers unsigned and logs.
pub async fn sign_response(
    signer: Option<&dyn ResponseSigner>,
    outcome: TrustTaskOutcome,
) -> TrustTaskOutcome {
    if outcome.body.is_empty() {
        return outcome;
    }
    let Some(signer) = signer else {
        return outcome;
    };

    let mut doc: Value = match serde_json::from_slice(&outcome.body) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "success response is not JSON; returning it unsigned");
            return outcome;
        }
    };
    if doc.get("proof").is_some() {
        return outcome;
    }
    if let Err(e) = signer.sign_response_document(&mut doc).await {
        tracing::error!(error = %e, "could not sign the response; returning it unsigned");
        return outcome;
    }
    match serde_json::to_vec(&doc) {
        Ok(body) => TrustTaskOutcome {
            status: outcome.status,
            body,
        },
        Err(e) => {
            tracing::error!(error = %e, "could not serialise the signed response");
            outcome
        }
    }
}
