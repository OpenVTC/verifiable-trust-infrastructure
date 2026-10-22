//! Server-built Data-Integrity proofs (operations layer).
//!
//! Backs the `vta/proofs/attach/0.1` Trust Task. The VTA frames the signed
//! bytes itself — canonicalize, build the proof configuration, hash — so this
//! is a **proof producer**, not a signing oracle over caller-supplied bytes. A
//! caller obtains a proof it is authorized to obtain and cannot obtain a
//! signature over anything else.
//!
//! That is what lets a holder proof be produced without anyone but the VTA
//! holding the key: the key is persisted in a context (so its verification
//! method resolves, rotates and revokes), and the authority needed is over that
//! context rather than over the instance.

use serde_json::Value;
use tracing::info;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations::context_signing;
use crate::operations::contexts::ALLOWED_PROOF_PURPOSES;
use crate::server::AppState;

/// The audit action [`attach_proof`] records refusals under.
const ATTACH_ACTION: &str = "proofs.attach";

/// Parameters for [`attach_proof`].
pub struct AttachProofParams<'a> {
    pub context_id: &'a str,
    pub document: &'a Value,
    pub proof_purpose: &'a str,
    pub challenge: Option<&'a str>,
    pub domain: Option<&'a str>,
    /// The verification method the caller asserts will sign. Never selects a
    /// key — a disagreement is refused.
    pub expected_verification_method: Option<&'a str>,
}

/// What [`attach_proof`] produced.
pub struct ProvenDocument {
    pub document: Value,
    pub verification_method: String,
}

/// Attach an `eddsa-jcs-2022` Data-Integrity proof to `document`, signed as
/// `context_id`'s DID with the key that context designates for
/// `proof_purpose`.
pub async fn attach_proof(
    state: &AppState,
    auth: &AuthClaims,
    params: AttachProofParams<'_>,
    channel: &str,
) -> Result<ProvenDocument, AppError> {
    if !params.document.is_object() {
        return Err(AppError::Validation(
            "document must be a JSON object".to_string(),
        ));
    }

    if !ALLOWED_PROOF_PURPOSES.contains(&params.proof_purpose) {
        return Err(context_signing::refuse(
            state,
            auth,
            channel,
            ATTACH_ACTION,
            params.context_id,
            format!(
                "proof purpose `{}` is not one of {ALLOWED_PROOF_PURPOSES:?}",
                params.proof_purpose
            ),
        )
        .await);
    }

    // Refused rather than ignored. The `eddsa-jcs-2022` implementation in use
    // carries no `challenge`/`domain` member, so a proof claiming to be bound
    // to one could not be — and returning a proof the caller believes is
    // replay-bound when it is not is worse than refusing the request.
    if params.challenge.is_some() || params.domain.is_some() {
        return Err(AppError::Validation(
            "challenge and domain are not supported by the eddsa-jcs-2022 proofs this task \
             produces: a proof carrying neither member cannot be bound to them, and a proof \
             that silently dropped them would not be replay-bound"
                .to_string(),
        ));
    }

    let signer = context_signing::resolve_signer(
        state,
        auth,
        channel,
        context_signing::SignerRequest {
            context_id: params.context_id,
            proof_purpose: Some(params.proof_purpose),
            expected_verification_method: params.expected_verification_method,
            action: ATTACH_ACTION,
        },
    )
    .await?;

    // JCS canonicalization is presence-sensitive, so an inbound `proof` would
    // be hashed into the signing input and the result would verify against
    // nothing. Dropped before signing, not after.
    let mut document = params.document.clone();
    document
        .as_object_mut()
        .expect("document is an object")
        .remove("proof");

    let proof = context_signing::sign_data_integrity_proof(
        state,
        auth,
        channel,
        &document,
        &signer,
        params.proof_purpose,
    )
    .await?;
    context_signing::attach_proof(&mut document, &proof)?;

    info!(
        channel,
        context_id = params.context_id,
        proof_purpose = params.proof_purpose,
        verification_method = %signer.verification_method,
        "data-integrity proof attached"
    );

    Ok(ProvenDocument {
        document,
        verification_method: signer.verification_method,
    })
}
