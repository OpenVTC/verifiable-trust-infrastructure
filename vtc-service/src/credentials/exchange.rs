//! Issuer-side credential-exchange (Phase 3, spec §6) — the VTC answering an
//! OID4VCI `credential-exchange/request` by issuing the credential.
//!
//! The [`vta_sdk::protocols::credential_exchange`] Trust Tasks carry OID4VCI on
//! the wire; the `affinidi-openid4vci` crate gives us the offer/response
//! builders and *structural* request validation. What it does **not** give us
//! — and what gates issuance — is the **cryptographic verification of the
//! holder's key-binding proof**. That gate lives here:
//! [`verify_oid4vci_proof`] proves the requester controls a key, and
//! [`issue_on_request`] only releases the credential when that proven key is
//! the credential's intended subject.
//!
//! This is the issuer mirror of the VTA holder-receive
//! (`vta-service/src/operations/credential_exchange.rs`, task 3.3): a pure
//! operation, unit-tested in isolation; a later slice wires it to the VTC
//! DIDComm router with a pending-offer store.
//!
//! ## Scope of this slice
//! - **`did:key` holders** — fully wired (the proof `kid` is a `did:key`,
//!   resolved locally, and must equal the credential's bound subject).
//! - A **`did:webvh` / `did:web`** holder proof needs resolver-based key
//!   resolution — a follow-up slice (symmetric with the receive side, which
//!   defers the same resolver path).
//! - **Sealed** issuance to an *unknown* holder (the invite / air-gap case) is
//!   the `sealed_transfer` slice (3.6); this operation is the cleartext,
//!   known-holder path.

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
const OID4VCI_PROOF_TYP: &str = "openid4vci-proof+jwt";

/// Freshness window for a key-binding proof — a proof whose `iat` is older than
/// this (or implausibly in the future) is rejected. Mirrors the 60s DIDComm
/// envelope window's intent with a little more slack for wallet clock drift.
const PROOF_MAX_AGE_SECS: i64 = 300;
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

/// Decode a base64url JWT segment into JSON.
fn decode_segment(segment: &str, what: &str) -> Result<Value, AppError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| AppError::Validation(format!("{what} is not base64url: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Validation(format!("{what} is not JSON: {e}")))
}

/// OID4VCI `aud` may be a single string or an array of strings; match either.
fn aud_matches(aud: Option<&Value>, expected: &str) -> bool {
    match aud {
        Some(Value::String(s)) => s == expected,
        Some(Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_openid4vci::{CredentialRequestProof, FORMAT_SD_JWT_VC};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const ISSUER: &str = "did:web:vtc.example";

    /// A holder identity: an Ed25519 key + its `did:key`.
    struct Holder {
        key: SigningKey,
        did: String,
    }
    impl Holder {
        fn new(seed: u8) -> Self {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let did =
                affinidi_crypto::did_key::ed25519_pub_to_did_key(key.verifying_key().as_bytes());
            Self { key, did }
        }

        /// Build an OID4VCI proof JWT (`openid4vci-proof+jwt`) signed by this
        /// holder, with the given `aud` / `iat` / `nonce`.
        fn proof_jwt(&self, aud: &str, iat: i64, nonce: Option<&str>) -> String {
            let header = json!({
                "typ": OID4VCI_PROOF_TYP,
                "alg": "EdDSA",
                "kid": format!("{}#key-0", self.did),
            });
            let mut payload = json!({ "iss": self.did, "aud": aud, "iat": iat });
            if let Some(n) = nonce {
                payload["nonce"] = json!(n);
            }
            let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
            let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
            let signing_input = format!("{h}.{p}");
            let sig: Signature = self.key.sign(signing_input.as_bytes());
            format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
        }
    }

    fn request_with(proof_jwt: String) -> CredentialRequest {
        CredentialRequest {
            format: FORMAT_SD_JWT_VC.to_string(),
            vct: Some("https://openvtc.org/credentials/MembershipCredential".into()),
            doctype: None,
            proof: Some(CredentialRequestProof {
                proof_type: "jwt".into(),
                jwt: proof_jwt,
            }),
            credential_identifier: None,
        }
    }

    fn a_credential() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": ISSUER,
            "credentialSubject": { "id": "did:example:member" }
        })
    }

    #[test]
    fn verifies_a_fresh_holder_proof() {
        let holder = Holder::new(7);
        let now = Utc::now();
        let jwt = holder.proof_jwt(ISSUER, now.timestamp(), Some("n-1"));
        let proven = verify_oid4vci_proof(&jwt, ISSUER, now).expect("verify proof");
        assert_eq!(proven.holder_did, holder.did);
        assert_eq!(proven.nonce.as_deref(), Some("n-1"));
    }

    #[test]
    fn issues_to_the_bound_holder() {
        let holder = Holder::new(11);
        let now = Utc::now();
        let req = request_with(holder.proof_jwt(ISSUER, now.timestamp(), None));
        let resp = issue_on_request(&req, a_credential(), &holder.did, ISSUER, now)
            .expect("issue to bound holder");
        assert_eq!(resp.credential, Some(a_credential()));
    }

    #[test]
    fn refuses_when_the_proof_binds_a_different_holder() {
        let bound = Holder::new(1);
        let attacker = Holder::new(2);
        let now = Utc::now();
        // The attacker signs a perfectly valid proof — for *their own* DID.
        let req = request_with(attacker.proof_jwt(ISSUER, now.timestamp(), None));
        let err = issue_on_request(&req, a_credential(), &bound.did, ISSUER, now).unwrap_err();
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "wrong-holder redemption must be Forbidden, got {err:?}"
        );
    }

    #[test]
    fn refuses_a_proof_for_another_audience() {
        let holder = Holder::new(3);
        let now = Utc::now();
        let jwt = holder.proof_jwt("did:web:other.example", now.timestamp(), None);
        let err = verify_oid4vci_proof(&jwt, ISSUER, now).unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("aud")),
            "{err:?}"
        );
    }

    #[test]
    fn refuses_a_stale_proof() {
        let holder = Holder::new(4);
        let now = Utc::now();
        let stale = now.timestamp() - (PROOF_MAX_AGE_SECS + 60);
        let err =
            verify_oid4vci_proof(&holder.proof_jwt(ISSUER, stale, None), ISSUER, now).unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("stale")),
            "{err:?}"
        );
    }

    #[test]
    fn refuses_a_tampered_signature() {
        let holder = Holder::new(5);
        let now = Utc::now();
        let mut jwt = holder.proof_jwt(ISSUER, now.timestamp(), None);
        // Flip the last signature character.
        let last = jwt.pop().unwrap();
        jwt.push(if last == 'A' { 'B' } else { 'A' });
        let err = verify_oid4vci_proof(&jwt, ISSUER, now).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }

    #[test]
    fn refuses_a_request_with_no_proof() {
        let now = Utc::now();
        let req = CredentialRequest {
            format: FORMAT_SD_JWT_VC.to_string(),
            vct: Some("https://openvtc.org/credentials/MembershipCredential".into()),
            doctype: None,
            proof: None,
            credential_identifier: None,
        };
        let err =
            issue_on_request(&req, a_credential(), "did:key:zHolder", ISSUER, now).unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("no key-binding proof")),
            "{err:?}"
        );
    }

    #[test]
    fn refuses_a_non_did_key_holder_proof_for_now() {
        // A structurally-valid proof whose kid is a did:web — resolver deferred.
        let now = Utc::now();
        let header =
            json!({ "typ": OID4VCI_PROOF_TYP, "alg": "EdDSA", "kid": "did:web:holder.example#k" });
        let payload = json!({ "aud": ISSUER, "iat": now.timestamp() });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        // Signature is irrelevant — the kid is rejected before verification.
        let jwt = format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode([0u8; 64]));
        let err = verify_oid4vci_proof(&jwt, ISSUER, now).unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("did:key")),
            "{err:?}"
        );
    }

    #[test]
    fn offer_is_pre_authorized() {
        let offer = credential_offer(
            ISSUER,
            vec!["MembershipCredential".into()],
            "code-xyz".into(),
        );
        assert_eq!(offer.credential_issuer, ISSUER);
        assert_eq!(
            offer.credential_configuration_ids,
            vec!["MembershipCredential"]
        );
        let grant = offer.grants.unwrap().pre_authorized_code.unwrap();
        assert_eq!(grant.pre_authorized_code, "code-xyz");
    }
}
