//! Signing **as a context's own DID**, with that context's own key.
//!
//! Shared by `credentials/issue-in-context` and `proofs/attach`: both resolve a
//! key they were never told, for a caller whose authority is over a context
//! rather than over the instance, and both then produce an `eddsa-jcs-2022`
//! Data-Integrity proof with it.
//!
//! ## Why the key is resolved rather than named
//!
//! A proof's `verificationMethod` must be a method of the DID the artifact
//! claims — a verifier checks exactly that. So for a given (context, purpose)
//! there is exactly one valid key: the caller would have no choice to make, and
//! offering one would let it name a key the context does not own. Resolving it
//! instead is also what makes key rotation invisible to callers.
//!
//! ## Why no private key material appears here
//!
//! [`DataIntegrityProof::sign`] wants a `Secret`, which an **internal**
//! (non-exportable) key will never hand over — and non-exportable is the right
//! custody for a signing key. So the signing input is built with
//! [`prepare_sign_input`] and handed to the existing signing oracle, which
//! loads, signs and zeroizes inside the keystore.

use affinidi_data_integrity::{DataIntegrityProof, crypto_suites::CryptoSuite, prepare_sign_input};
use base64::Engine;
use chrono::Utc;
use serde::Serialize;
use serde_json::Value;

use crate::auth::AuthClaims;
use crate::contexts::get_context;
use crate::error::AppError;
use crate::server::AppState;
use vta_sdk::keys::KeyRecord;
use vta_sdk::protocols::key_management::sign::{SignAlgorithm, SigningDomain};

/// The identity a context signs with: its DID, the key id to sign through, and
/// the verification method those two produce.
pub struct ContextSigner {
    pub issuer_did: String,
    pub key_id: String,
    pub verification_method: String,
}

/// What a context is being asked to sign as.
pub struct SignerRequest<'a> {
    pub context_id: &'a str,
    /// `None` resolves the context's **credential issuer** key; `Some(purpose)`
    /// resolves its Data-Integrity proof key for that purpose.
    pub proof_purpose: Option<&'a str>,
    /// The verification method the caller asserts will sign. Never selects a
    /// key — a disagreement is refused.
    pub expected_verification_method: Option<&'a str>,
    /// The audit action refusals are recorded under.
    pub action: &'a str,
}

/// Resolve the key `request.context_id` signs with, enforcing every gate that
/// makes following its designation safe.
///
/// In order, because each refusal must not leak what the next one would check:
/// the caller must be authorized in the context; the context must exist and
/// have a DID; it must designate a key for this purpose (**fail closed** — a
/// fallback to the VTA's own key would attribute the artifact to the VTA while
/// the caller asked for the context); that key must exist; and it must *live in
/// the context*. The last is what puts the VTA's own `#key-0` out of reach: it
/// has no context, so it can never match.
pub async fn resolve_signer(
    state: &AppState,
    auth: &AuthClaims,
    channel: &str,
    request: SignerRequest<'_>,
) -> Result<ContextSigner, AppError> {
    let context_id = request.context_id;

    // Reachability first, so a caller outside the context is told that — and is
    // told it before the context's existence, its DID, or its key designation
    // leak through a more specific error.
    if auth.require_context(context_id).is_err() {
        return Err(refuse(
            state,
            auth,
            channel,
            request.action,
            context_id,
            format!("caller is not authorized in context `{context_id}`"),
        )
        .await);
    }

    let context = get_context(&state.contexts_ks, context_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context `{context_id}` not found")))?;

    let issuer_did = context.did.clone().ok_or_else(|| {
        AppError::Validation(format!(
            "context `{context_id}` has no DID, so it cannot sign as itself"
        ))
    })?;

    let key_id = match request.proof_purpose {
        Some(purpose) => crate::operations::contexts::resolve_proof_key(&context, purpose)
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "context `{context_id}` has no designated key for proof purpose \
                     `{purpose}`: designate one before signing"
                ))
            })?,
        None => context.issuer_key_id.as_deref().ok_or_else(|| {
            AppError::Validation(format!(
                "context `{context_id}` has no designated issuer key: designate one before \
                 issuing"
            ))
        })?,
    }
    .to_string();

    // Read the record directly rather than through `operations::keys::get_key`,
    // which refuses internal keys outright because it is an export surface.
    // Nothing is exported here.
    let key: KeyRecord = state
        .keys_ks
        .get(crate::keys::store_key(&key_id))
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "context `{context_id}` designates key `{key_id}`, which does not exist"
            ))
        })?;

    if key.context_id.as_deref() != Some(context_id) {
        return Err(refuse(
            state,
            auth,
            channel,
            request.action,
            context_id,
            format!("key `{key_id}` does not belong to context `{context_id}`; refusing to sign"),
        )
        .await);
    }

    let verification_method = format!("{issuer_did}#{}", key.public_key);

    if let Some(expected) = request.expected_verification_method
        && expected != verification_method
    {
        return Err(refuse(
            state,
            auth,
            channel,
            request.action,
            context_id,
            format!(
                "expectedVerificationMethod `{expected}` does not match the verification \
                 method this context resolves to; refusing to sign with a different key"
            ),
        )
        .await);
    }

    Ok(ContextSigner {
        issuer_did,
        key_id,
        verification_method,
    })
}

/// Produce an `eddsa-jcs-2022` Data-Integrity proof over `document`, signed
/// through the keystore by `signer`.
///
/// `document` must not already carry a `proof` member: JCS canonicalization is
/// presence-sensitive, so hashing a document with one produces a signature no
/// verifier can reconstruct.
pub async fn sign_data_integrity_proof<S: Serialize>(
    state: &AppState,
    auth: &AuthClaims,
    channel: &str,
    document: &S,
    signer: &ContextSigner,
    proof_purpose: &str,
) -> Result<DataIntegrityProof, AppError> {
    // Seconds precision, because that is the form hashed into the proof
    // configuration — re-rendering it differently would break verification.
    let created = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let proof_config = DataIntegrityProof::new(
        CryptoSuite::EddsaJcs2022,
        signer.verification_method.clone(),
        proof_purpose.to_string(),
        None,
        Some(created),
        None,
    );

    let signing_input = prepare_sign_input(document, &proof_config, CryptoSuite::EddsaJcs2022)
        .map_err(|e| AppError::Internal(format!("prepare data-integrity signing input: {e}")))?;

    let signed = crate::operations::keys::sign_payload(
        &state.keys_ks,
        &state.imported_ks,
        &state.internal_ks,
        &state.contexts_ks,
        &state.acl_ks,
        &state.seed_store,
        &state.audit_sink,
        auth,
        &signer.key_id,
        &signing_input,
        &SignAlgorithm::EdDSA,
        // These bytes are a data-integrity proof input the VTA built itself.
        // Framing them again under the opaque domain would produce a signature
        // no Data Integrity verifier accepts.
        SigningDomain::ProtocolDefined,
        channel,
    )
    .await?;

    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&signed.signature)
        .map_err(|e| AppError::Internal(format!("decode data-integrity signature: {e}")))?;

    let mut proof = proof_config;
    proof.proof_value = Some(multibase::encode(multibase::Base::Base58Btc, &signature));
    Ok(proof)
}

/// Attach `proof` to `document` under its `proof` member.
pub fn attach_proof(document: &mut Value, proof: &DataIntegrityProof) -> Result<(), AppError> {
    document
        .as_object_mut()
        .ok_or_else(|| AppError::Validation("document must be a JSON object".to_string()))?
        .insert(
            "proof".to_string(),
            serde_json::to_value(proof)
                .map_err(|e| AppError::Internal(format!("serialize data-integrity proof: {e}")))?,
        );
    Ok(())
}

/// Audit a refusal on a context-signing path and render it as the error to
/// return.
///
/// Every refusal goes through here: a refusal that is not recorded is
/// indistinguishable from a request that was never made, and these tasks are
/// reachable *without* instance authority, so the attempts are exactly the ones
/// worth seeing.
pub async fn refuse(
    state: &AppState,
    auth: &AuthClaims,
    channel: &str,
    action: &str,
    context_id: &str,
    reason: String,
) -> AppError {
    tracing::warn!(
        audit = true,
        security_alert = true,
        did = %auth.did,
        role = %auth.role,
        channel,
        action,
        context_id,
        reason = %reason,
        "context-scoped signing refused",
    );
    crate::audit::record_with_detail_best_effort(
        &state.audit_sink,
        action,
        &auth.did,
        Some(&reason),
        "denied",
        Some(channel),
        Some(context_id),
        None,
    )
    .await;
    AppError::Forbidden(reason)
}
