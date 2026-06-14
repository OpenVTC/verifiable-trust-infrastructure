//! OID4VCI issuer gate: holder key-binding proof verification +
//! credential issuance + offer construction (split out of `exchange.rs`, P2.3).

use super::jwt::{aud_matches, decode_segment};
use affinidi_openid4vci::issuer::{
    create_credential_offer, create_credential_response, validate_credential_request,
};
use affinidi_openid4vci::{CredentialOffer, CredentialRequest, CredentialResponse};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use vti_common::error::AppError;

/// OID4VCI proof-JWT `typ` header (OID4VCI §7.2.1).
pub(super) const OID4VCI_PROOF_TYP: &str = "openid4vci-proof+jwt";

/// Freshness window for a key-binding proof — a proof whose `iat` is older than
/// this (or implausibly in the future) is rejected. Mirrors the 60s DIDComm
/// envelope window's intent with a little more slack for wallet clock drift.
pub(super) const PROOF_MAX_AGE_SECS: i64 = 300;
/// Tolerance for a proof `iat` slightly ahead of the issuer's clock.
const PROOF_FUTURE_SKEW_SECS: i64 = 60;

/// A holder key-binding proof that [`verify_oid4vci_proof`] has cryptographically
/// verified: the signature checked out under the key named by the proof's `kid`.
#[derive(Debug, Clone)]
pub struct ProvenHolderProof {
    /// The `did:key` whose key signed the proof (the `kid` with any fragment
    /// stripped). The requester demonstrably controls this DID's key.
    pub holder_did: String,
    /// The issuer-supplied freshness nonce the proof committed to, if any
    /// (the OID4VCI `c_nonce`). A later wiring slice uses this to correlate the
    /// request back to a single-use pending offer.
    pub nonce: Option<String>,
}

/// Verify an OID4VCI key-binding proof JWT.
///
/// Checks, in order: the compact JWT is well-formed; `typ` is
/// `openid4vci-proof+jwt` and `alg` is `EdDSA`; the `kid` names a `did:key`;
/// the Ed25519 signature verifies under that key; the `aud` names this issuer;
/// and the `iat` is fresh. On success the proven `did:key` (and nonce) are
/// returned — only then may a credential bound to that DID be released.
///
/// `did:webvh` / `did:web` `kid`s need resolver-based key resolution and are a
/// follow-up slice; here a non-`did:key` `kid` is rejected.
pub fn verify_oid4vci_proof(
    proof_jwt: &str,
    expected_aud: &str,
    now: DateTime<Utc>,
) -> Result<ProvenHolderProof, AppError> {
    let mut parts = proof_jwt.split('.');
    let (h_b64, p_b64, s_b64) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => {
            return Err(AppError::Validation(
                "key-binding proof is not a compact JWS (header.payload.signature)".into(),
            ));
        }
    };

    let header = decode_segment(h_b64, "proof header")?;
    if header.get("typ").and_then(Value::as_str) != Some(OID4VCI_PROOF_TYP) {
        return Err(AppError::Validation(format!(
            "key-binding proof `typ` must be `{OID4VCI_PROOF_TYP}`"
        )));
    }
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return Err(AppError::Validation(
            "key-binding proof `alg` must be `EdDSA` (Ed25519)".into(),
        ));
    }

    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation("key-binding proof header has no `kid`".into()))?;
    // The holder DID is the `kid` with any VM fragment stripped.
    let holder_did = kid.split('#').next().unwrap_or(kid).to_string();
    if !holder_did.starts_with("did:key:") {
        return Err(AppError::Validation(format!(
            "key-binding proof `kid` ({holder_did}) is not a `did:key` — resolving a \
             did:webvh / did:web holder needs the DID resolver, a follow-up slice"
        )));
    }

    // Resolve the holder's Ed25519 verifying key and check the signature over
    // the JWS signing input.
    let pub_bytes = affinidi_crypto::did_key::did_key_to_ed25519_pub(&holder_did).map_err(|e| {
        AppError::Validation(format!("holder `{holder_did}` is not a did:key: {e}"))
    })?;
    let verifying_key = VerifyingKey::from_bytes(&pub_bytes)
        .map_err(|e| AppError::Validation(format!("holder key is not a valid Ed25519 key: {e}")))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(s_b64)
        .map_err(|e| AppError::Validation(format!("proof signature is not base64url: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| AppError::Validation(format!("proof signature is malformed: {e}")))?;
    let signing_input = format!("{h_b64}.{p_b64}");
    verifying_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| AppError::Validation("key-binding proof signature did not verify".into()))?;

    // Signature is good — now the bound claims.
    let payload = decode_segment(p_b64, "proof payload")?;
    if !aud_matches(payload.get("aud"), expected_aud) {
        return Err(AppError::Validation(format!(
            "key-binding proof `aud` does not name this issuer ({expected_aud})"
        )));
    }
    let iat = payload
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| AppError::Validation("key-binding proof has no numeric `iat`".into()))?;
    let now_secs = now.timestamp();
    if iat > now_secs + PROOF_FUTURE_SKEW_SECS {
        return Err(AppError::Validation(
            "key-binding proof `iat` is in the future".into(),
        ));
    }
    if now_secs - iat > PROOF_MAX_AGE_SECS {
        return Err(AppError::Validation(format!(
            "key-binding proof is stale (older than {PROOF_MAX_AGE_SECS}s)"
        )));
    }

    let nonce = payload
        .get("nonce")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(ProvenHolderProof { holder_did, nonce })
}

/// Issue a credential in response to an OID4VCI credential request.
///
/// `credential` is the credential the VTC has already decided to issue (a
/// minted VMC / VEC, opaque here); `expected_holder_did` is the subject it is
/// bound to. The request's key-binding proof must verify *and* prove control of
/// exactly `expected_holder_did` — so only the rightful subject, demonstrating
/// key possession, can redeem the credential. Returns the OID4VCI
/// [`CredentialResponse`] to wrap in a `credential-exchange/issue` body.
pub fn issue_on_request(
    request: &CredentialRequest,
    credential: Value,
    expected_holder_did: &str,
    issuer_id: &str,
    now: DateTime<Utc>,
) -> Result<CredentialResponse, AppError> {
    // Structural validation (format present, vct/doctype for the format,
    // proof envelope well-formed) from the OID4VCI crate.
    validate_credential_request(request)
        .map_err(|e| AppError::Validation(format!("invalid credential request: {e}")))?;

    let proof = request.proof.as_ref().ok_or_else(|| {
        AppError::Validation(
            "credential request carries no key-binding proof — issuance requires \
             proof of holder key possession"
                .into(),
        )
    })?;
    if proof.proof_type != "jwt" {
        return Err(AppError::Validation(format!(
            "unsupported key-binding proof type `{}` (expected `jwt`)",
            proof.proof_type
        )));
    }

    let proven = verify_oid4vci_proof(&proof.jwt, issuer_id, now)?;
    if proven.holder_did != expected_holder_did {
        // Forbidden, not Validation: the proof is valid, but it binds a
        // different DID than the credential's subject — a redemption-by-the-
        // wrong-party attempt, not a malformed request.
        return Err(AppError::Forbidden(format!(
            "key-binding proof proves control of {} but the credential is bound to {}",
            proven.holder_did, expected_holder_did
        )));
    }

    Ok(create_credential_response(credential, None, None))
}

/// Build an OID4VCI pre-authorized-code credential offer for `config_ids`.
///
/// Thin wrapper over [`create_credential_offer`] that documents the VTC's
/// stance: issuance is always pre-authorized (the community has already decided
/// to issue — via a ceremony / approval — before the offer goes out), never the
/// interactive OAuth authorization-code flow. `pre_authorized_code` is the
/// single-use redemption token (a later slice persists the pending offer keyed
/// by it).
pub fn credential_offer(
    issuer_id: &str,
    config_ids: Vec<String>,
    pre_authorized_code: String,
) -> CredentialOffer {
    create_credential_offer(issuer_id, config_ids, Some(pre_authorized_code))
}
