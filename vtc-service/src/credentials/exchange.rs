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
//! (`vta-service/src/operations/credential_exchange.rs`, task 3.3). The core
//! [`issue_on_request`] gate is a pure operation; [`make_offer`] + [`redeem`]
//! add the persisted single-use pending-offer store, and the VTC DIDComm
//! `credential-exchange/request` handler (`messaging.rs`) drives `redeem` to
//! complete the `offer → request → issue` loop with the VTA holder side.
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
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

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

// ── Pending-issuance store + the offer→request→issue wire flow ──
//
// When the community decides to issue a credential (e.g. ceremony admit mints a
// VMC), the VTC emits a pre-authorized-code offer and persists a *pending
// issuance* keyed by that code. The holder later redeems it with a
// `credential-exchange/request` carrying a key-binding proof; the issuer looks
// the pending record up, verifies the proof binds the intended subject, and
// returns the credential. The **pre-authorized code doubles as the proof
// `nonce`** (the issuer-generated freshness value the holder commits to) — no
// separate token-endpoint round-trip in the DIDComm collapse.

/// Key prefix for pending issuances. Stored in the `join_requests` keyspace
/// (credential issuance is the terminal step of the join/admit lifecycle that
/// keyspace already tracks); the join retention sweeper walks `join_requests:`,
/// a disjoint prefix, so the two never collide. A dedicated keyspace is a clean
/// future migration — the prefix is the single source of truth for the shape.
const PENDING_PREFIX: &str = "credx-pending:";

/// Default lifetime of a pending offer before it expires unredeemed.
pub const DEFAULT_OFFER_TTL: Duration = Duration::minutes(30);

fn pending_key(code: &str) -> String {
    format!("{PENDING_PREFIX}{code}")
}

/// A credential the VTC has decided to issue, awaiting redemption by the holder.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingIssuance {
    /// The credential to deliver (already minted; opaque here).
    credential: Value,
    /// The subject the credential is bound to — only this DID, proving key
    /// possession, may redeem.
    expected_holder_did: String,
    /// The Credential Issuer Identifier the holder's proof `aud` must name.
    issuer_id: String,
    /// Expiry, seconds since the Unix epoch.
    expires_at: i64,
}

/// Emit a pre-authorized-code credential offer and persist the pending issuance.
///
/// Returns the [`CredentialOffer`] to send to the holder and the single-use
/// `pre_authorized_code` (which the holder echoes as the proof `nonce`). The
/// credential is bound to `expected_holder_did`; only that subject can redeem.
#[allow(clippy::too_many_arguments)]
pub async fn make_offer(
    ks: &KeyspaceHandle,
    issuer_id: &str,
    config_ids: Vec<String>,
    credential: Value,
    expected_holder_did: &str,
    ttl: Duration,
    now: DateTime<Utc>,
) -> Result<(CredentialOffer, String), AppError> {
    let code = format!("pac_{}", Uuid::new_v4().simple());
    let pending = PendingIssuance {
        credential,
        expected_holder_did: expected_holder_did.to_string(),
        issuer_id: issuer_id.to_string(),
        expires_at: (now + ttl).timestamp(),
    };
    ks.insert(pending_key(&code), &pending).await?;
    Ok((credential_offer(issuer_id, config_ids, code.clone()), code))
}

/// Redeem a credential request against a persisted pending offer.
///
/// Looks the pending issuance up by the request's proof `nonce` (the
/// pre-authorized code), checks it hasn't expired, then [`issue_on_request`]
/// verifies the key-binding proof and binds the holder. The pending record is
/// consumed (single-use) **only on success** — a forged or wrong-party request
/// returns an error without burning the legitimate holder's offer.
pub async fn redeem(
    ks: &KeyspaceHandle,
    request: &CredentialRequest,
    now: DateTime<Utc>,
) -> Result<CredentialResponse, AppError> {
    let code = proof_nonce(request)?.ok_or_else(|| {
        AppError::Validation(
            "credential request proof carries no nonce (the pre-authorized code)".into(),
        )
    })?;

    let pending = get_pending(ks, &code).await?.ok_or_else(|| {
        AppError::NotFound(
            "no pending issuance for this code (unknown, already redeemed, or expired)".into(),
        )
    })?;

    if now.timestamp() > pending.expires_at {
        // Best-effort cleanup of the expired record; ignore the result.
        let _ = ks.remove(pending_key(&code)).await;
        return Err(AppError::Validation("pending issuance has expired".into()));
    }

    // Verifies the proof signature, audience, freshness, and that the proven
    // holder DID equals the credential's bound subject (else `Forbidden`).
    let response = issue_on_request(
        request,
        pending.credential.clone(),
        &pending.expected_holder_did,
        &pending.issuer_id,
        now,
    )?;

    // Single-use: consume the offer now that issuance succeeded.
    ks.remove(pending_key(&code)).await?;
    Ok(response)
}

async fn get_pending(ks: &KeyspaceHandle, code: &str) -> Result<Option<PendingIssuance>, AppError> {
    match ks.get_raw(pending_key(code)).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| AppError::Internal(format!("PendingIssuance decode: {e}"))),
        None => Ok(None),
    }
}

/// Structurally read the `nonce` claim from a credential request's proof JWT —
/// the lookup key for the pending offer. This is an **unverified** peek; the
/// real cryptographic verification happens in [`issue_on_request`], and the
/// credential is only released after the holder-binding check there.
fn proof_nonce(request: &CredentialRequest) -> Result<Option<String>, AppError> {
    let Some(proof) = request.proof.as_ref() else {
        return Ok(None);
    };
    let payload_b64 = proof.jwt.split('.').nth(1).ok_or_else(|| {
        AppError::Validation("credential request proof is not a compact JWT".into())
    })?;
    let payload = decode_segment(payload_b64, "proof payload")?;
    Ok(payload
        .get("nonce")
        .and_then(Value::as_str)
        .map(str::to_string))
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

    // ── pending-offer store + redeem flow ──

    fn fresh_ks() -> (tempfile::TempDir, vti_common::store::Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("join_requests").unwrap();
        (dir, store, ks)
    }

    #[tokio::test]
    async fn make_offer_then_redeem_delivers_and_consumes() {
        let (_d, _s, ks) = fresh_ks();
        let holder = Holder::new(30);
        let now = Utc::now();

        let (offer, code) = make_offer(
            &ks,
            ISSUER,
            vec!["MembershipCredential".into()],
            a_credential(),
            &holder.did,
            DEFAULT_OFFER_TTL,
            now,
        )
        .await
        .expect("make offer");
        // The offer advertises the same pre-authorized code we persisted.
        assert_eq!(
            offer
                .grants
                .unwrap()
                .pre_authorized_code
                .unwrap()
                .pre_authorized_code,
            code
        );

        // Holder redeems: proof nonce == the pre-authorized code.
        let req = request_with(holder.proof_jwt(ISSUER, now.timestamp(), Some(&code)));
        let resp = redeem(&ks, &req, now).await.expect("redeem");
        assert_eq!(resp.credential, Some(a_credential()));

        // Single-use: the offer is consumed.
        let again = redeem(&ks, &req, now).await.unwrap_err();
        assert!(matches!(again, AppError::NotFound(_)), "{again:?}");
    }

    #[tokio::test]
    async fn redeem_rejects_unknown_code() {
        let (_d, _s, ks) = fresh_ks();
        let holder = Holder::new(31);
        let now = Utc::now();
        let req = request_with(holder.proof_jwt(ISSUER, now.timestamp(), Some("pac_missing")));
        let err = redeem(&ks, &req, now).await.unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "{err:?}");
    }

    #[tokio::test]
    async fn redeem_rejects_an_expired_offer() {
        let (_d, _s, ks) = fresh_ks();
        let holder = Holder::new(32);
        let issued = Utc::now();
        let (_offer, code) = make_offer(
            &ks,
            ISSUER,
            vec!["m".into()],
            a_credential(),
            &holder.did,
            Duration::seconds(1),
            issued,
        )
        .await
        .unwrap();

        let later = issued + Duration::seconds(30);
        let req = request_with(holder.proof_jwt(ISSUER, later.timestamp(), Some(&code)));
        let err = redeem(&ks, &req, later).await.unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("expired")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn redeem_refuses_wrong_holder_without_burning_the_offer() {
        let (_d, _s, ks) = fresh_ks();
        let bound = Holder::new(33);
        let attacker = Holder::new(34);
        let now = Utc::now();
        let (_offer, code) = make_offer(
            &ks,
            ISSUER,
            vec!["m".into()],
            a_credential(),
            &bound.did,
            DEFAULT_OFFER_TTL,
            now,
        )
        .await
        .unwrap();

        // Attacker signs a valid proof for *their own* DID, echoing the code.
        let bad = request_with(attacker.proof_jwt(ISSUER, now.timestamp(), Some(&code)));
        let err = redeem(&ks, &bad, now).await.unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");

        // The legitimate offer was NOT consumed — the real holder still redeems.
        let good = request_with(bound.proof_jwt(ISSUER, now.timestamp(), Some(&code)));
        assert!(redeem(&ks, &good, now).await.is_ok());
    }
}
