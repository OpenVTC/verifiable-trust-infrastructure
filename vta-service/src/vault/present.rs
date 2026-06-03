//! Present a stored SD-JWT-VC, **gated by a consent record** (task 1.4,
//! `docs/05-design-notes/vti-credential-architecture.md` §7 "Present", §7a
//! consent records, §14 invariants).
//!
//! This is the credential vault's **disclosure path**: the VTA, acting as the
//! holder's agent, builds a selectively-disclosed SD-JWT-VC *presentation* of a
//! credential it already holds — disclosing **exactly** the claims a signed,
//! unexpired, recipient-matching consent record authorizes, and binding the
//! presentation to the verifier with a mandatory holder key-binding JWT
//! (`kb-jwt`). The output is the compact SD-JWT-VC presentation
//! (`<jws>~<disclosure>…~<kb-jwt>`), ready to hand to the verifier.
//!
//! ## Scope (SD-JWT-VC only, library op)
//!
//! Like [`receive`](super::receive) and [`mint`](super::mint), this is a
//! **library operation** with **no route / DIDComm handler** (the wire surface
//! is Phase 3) and pulls in **no BBS** (`affinidi-bbs` is audit-gated —
//! `vti-credential-architecture.md` §4, open question #1).
//!
//! ## Security / privacy invariants (spec §14 — do not relax)
//!
//! - **Consent before disclosure (§14.2).** Disclosure is gated on a consent
//!   record loaded via [`consent::get`] (which re-verifies the holder's
//!   non-repudiable DI proof) and judged by [`consent::authorizes`]. A
//!   missing, withdrawn, expired, or recipient-mismatched record yields
//!   **nothing** — [`present_sd_jwt_vc`] returns `Err` and emits no
//!   presentation.
//! - **Claim minimisation (§14.3).** The reveal set is derived **only** from
//!   the consent record's `dpv:hasPersonalData`. The presentation discloses
//!   *exactly* that set — no more. The disclosed disclosures are filtered to
//!   the consented names by [`affinidi_sd_jwt::holder::select_disclosures`],
//!   and then re-checked to be a subset of the consented set as belt-and-
//!   braces: the disclosed set can never exceed `hasPersonalData`.
//! - **Holder binding mandatory (§14.4).** Every presentation carries a
//!   `kb-jwt` signed by the VTA-held `holder_signer` over `(sd_hash, aud,
//!   nonce)`. There is no path through this function that produces a
//!   presentation without one — the `kb_input` is always `Some`.
//! - **Never present a revoked or temporally-invalid credential (§14.5).**
//!   The stored credential's resolved `status` must be
//!   [`CredentialStatus::Valid`] and its `valid_from`/`valid_until` window
//!   must contain `now`; otherwise disclosure is refused.
//!
//! ## Keys are VTA-managed
//!
//! The holder's key-binding key is VTA-managed (spec open question #5): the
//! caller injects it as an [`affinidi_sd_jwt::signer::JwtSigner`]
//! (`holder_signer`). This module never sees or exports raw key bytes — it
//! sees a sign-only capability, mirroring the issuer-side signer in
//! [`mint`](super::mint). The signer's public key MUST be the one the
//! credential committed to in its `cnf.jwk` at issuance, or a verifier's
//! key-binding check will (correctly) fail.

use affinidi_sd_jwt::SdJwt;
use affinidi_sd_jwt::hasher::Sha256Hasher;
use affinidi_sd_jwt::holder::{KbJwtInput, present, select_disclosures};
use affinidi_sd_jwt::signer::JwtSigner;
use chrono::{DateTime, Utc};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::consent;
use super::model::{CredentialFormat, CredentialStatus};
use super::storage;

/// Build a consent-gated, selectively-disclosed SD-JWT-VC presentation of a
/// stored credential, bound to the verifier with a mandatory holder `kb-jwt`.
///
/// `credential_id` names the [`StoredCredential`](super::model::StoredCredential)
/// to present; `consent_record_id` names the [`ConsentRecord`](consent::ConsentRecord)
/// that authorizes the disclosure. `holder_signer` is the VTA-held holder
/// key-binding signer (sign-only). `nonce` and `aud` are the verifier-supplied
/// freshness nonce and the verifier identity (= the consent record's
/// `dpv:hasRecipient`); they are bound into the `kb-jwt`. `iat_unix` is the
/// `kb-jwt` issued-at (Unix seconds). `now` anchors the consent-authority and
/// credential-temporal checks.
///
/// On success returns the compact SD-JWT-VC presentation — the issuer JWS, the
/// **consented** disclosures only, and a holder `kb-jwt` over `(sd_hash, aud,
/// nonce)`.
///
/// ## Refuses (discloses nothing) when
/// - the credential or the consent record does not exist
///   ([`AppError::NotFound`]);
/// - the consent record's holder proof does not verify (surfaced by
///   [`consent::get`]);
/// - the credential's `subject_did` is absent or does not equal the consent
///   record's `dpv:hasDataSubject` — the credential and the consent must be
///   about the **same** holder (§13, [`AppError::Forbidden`]);
/// - [`consent::authorizes`] is `false` — i.e. the record is not bound to this
///   `credential_id` (`dct:source`, §13), is withdrawn or expired, its
///   `dpv:hasRecipient` is not `aud`, or the reveal set is out of scope
///   ([`AppError::Forbidden`]);
/// - the stored credential is not [`CredentialStatus::Valid`], or `now` is
///   outside its `valid_from`/`valid_until` window ([`AppError::Forbidden`]);
/// - the credential is not an SD-JWT-VC, or its stored body is malformed
///   ([`AppError::Validation`]).
pub async fn present_sd_jwt_vc(
    vault: &KeyspaceHandle,
    credential_id: &str,
    consent_record_id: &str,
    holder_signer: &dyn JwtSigner,
    nonce: &str,
    aud: &str,
    iat_unix: u64,
    now: DateTime<Utc>,
) -> Result<String, AppError> {
    // (1) Load the stored credential — its body is the SD-JWT-VC compact form.
    let cred = storage::get(vault, credential_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("credential `{credential_id}` not found")))?;

    if cred.format != CredentialFormat::SdJwtVc {
        return Err(AppError::Validation(format!(
            "credential `{credential_id}` is not an SD-JWT-VC (format {:?}); cannot present",
            cred.format
        )));
    }

    // (2) Load the consent record. `consent::get` re-verifies the holder DI
    // proof (the non-repudiation anchor) before returning it — a record whose
    // proof no longer verifies is surfaced as an error, never presented.
    let record = consent::get(vault, consent_record_id)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("consent record `{consent_record_id}` not found"))
        })?;

    // (2a) Subject binding (§13, §14.2). The consent record's `dpv:hasDataSubject`
    // (the holder who signed it) MUST be the credential's subject. Without this
    // a record authored by holder B could be used to present holder A's
    // credential whenever the claim names line up — the credential and the
    // consent must be about the *same* subject. `authorizes` separately binds
    // the record to *this credential id* (`dct:source`); this check binds it to
    // the credential's *subject*, so both the credential identity and its
    // subject must agree with the consent.
    match cred.subject_did.as_deref() {
        Some(subject) if subject == record.data_subject => {}
        _ => {
            return Err(AppError::Forbidden(format!(
                "credential `{credential_id}` subject does not match consent record \
                 `{consent_record_id}` data subject `{}`; refusing to present",
                record.data_subject
            )));
        }
    }

    // The reveal set IS the consent record's `dpv:hasPersonalData`: present
    // discloses EXACTLY the consented set, no more. (5) derive-reveal-set.
    let reveal_set = &record.process.personal_data;

    // (3) Gate. `authorizes` binds the record to *this credential*
    // (`dct:source == credential_id`, §13) and is judged against the same set
    // we intend to disclose (requested_claims = the reveal set), so the request
    // can never exceed what the holder consented to. Refuse on any of:
    // wrong-credential/withdrawn/expired/recipient-mismatch.
    if !consent::authorizes(&record, credential_id, aud, reveal_set, now) {
        return Err(AppError::Forbidden(format!(
            "consent record `{consent_record_id}` does not authorize disclosure of \
             `{credential_id}` to `{aud}` (wrong credential, withdrawn, expired, \
             recipient-mismatch, or claim out of scope)"
        )));
    }

    // (4) Never present a revoked or temporally-invalid credential (§14.5).
    // The stored status must be `Valid` (task 1.6 resolves real revocation
    // state into this tag) and `now` must be inside the credential's own
    // validity window.
    if cred.status != CredentialStatus::Valid {
        return Err(AppError::Forbidden(format!(
            "credential `{credential_id}` is not valid (status {:?}); cannot present",
            cred.status
        )));
    }
    if !credential_temporally_valid(cred.valid_from.as_deref(), cred.valid_until.as_deref(), now)? {
        return Err(AppError::Forbidden(format!(
            "credential `{credential_id}` is outside its temporal validity window; cannot present"
        )));
    }

    // (6) Build the presentation. Parse the stored compact form, select ONLY
    // the consented disclosures, and produce a presentation with a mandatory
    // holder kb-jwt over (sd_hash, aud, nonce).
    let hasher = Sha256Hasher;
    let compact = std::str::from_utf8(&cred.body).map_err(|e| {
        AppError::Validation(format!(
            "credential `{credential_id}` body is not valid UTF-8 SD-JWT-VC: {e}"
        ))
    })?;
    let sd_jwt = SdJwt::parse(compact, &hasher).map_err(|e| {
        AppError::Validation(format!(
            "credential `{credential_id}` body is not a parseable SD-JWT-VC: {e}"
        ))
    })?;

    // Select exactly the consented disclosures by claim name. `select_disclosures`
    // filters to disclosures whose `claim_name` is in the consented set, so the
    // resulting set is a subset of `reveal_set` by construction.
    let reveal_names: Vec<&str> = reveal_set.iter().map(String::as_str).collect();
    let selected = select_disclosures(&sd_jwt, &reveal_names);

    // Belt-and-braces (§14.3): the disclosed set MUST NOT exceed the consented
    // set. `select_disclosures` already guarantees this, but we re-assert it so
    // a future change to the selection logic cannot silently over-disclose.
    for d in &selected {
        let name = d.claim_name.as_deref().unwrap_or("");
        if !reveal_set.iter().any(|c| c == name) {
            return Err(AppError::Internal(format!(
                "refusing to disclose `{name}`: not in the consent record's reveal set"
            )));
        }
    }

    // Holder binding is mandatory (§14.4): always build a kb-jwt.
    let kb_input = KbJwtInput {
        audience: aud,
        nonce,
        signer: holder_signer,
        iat: iat_unix,
    };

    let presentation = present(&sd_jwt, &selected, Some(&kb_input), &hasher)
        .map_err(|e| AppError::Internal(format!("build SD-JWT-VC presentation: {e}")))?;

    Ok(presentation.serialize())
}

/// True iff `now` lies within `[valid_from, valid_until]`.
///
/// Either bound may be absent (the stored credential omits it). A malformed
/// RFC-3339 bound is a hard error (default-deny: we never present a credential
/// whose window we cannot evaluate). An absent bound imposes no constraint on
/// that side.
fn credential_temporally_valid(
    valid_from: Option<&str>,
    valid_until: Option<&str>,
    now: DateTime<Utc>,
) -> Result<bool, AppError> {
    if let Some(from) = valid_from {
        let from = from.parse::<DateTime<Utc>>().map_err(|e| {
            AppError::Validation(format!(
                "credential valid_from `{from}` is not RFC-3339: {e}"
            ))
        })?;
        if now < from {
            return Ok(false);
        }
    }
    if let Some(until) = valid_until {
        let until = until.parse::<DateTime<Utc>>().map_err(|e| {
            AppError::Validation(format!(
                "credential valid_until `{until}` is not RFC-3339: {e}"
            ))
        })?;
        if now >= until {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::consent::{ConsentGrant, create as create_consent, withdraw};
    use crate::vault::mint::{MintRequest, mint_sd_jwt_vc};
    use crate::vault::model::StoredCredential;
    use affinidi_sd_jwt::error::SdJwtError;
    use affinidi_sd_jwt::hasher::Sha256Hasher;
    use affinidi_sd_jwt::signer::{JwtSigner, JwtVerifier};
    use affinidi_sd_jwt::verifier::{VerificationOptions, verify};
    use affinidi_secrets_resolver::secrets::Secret;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono::Duration;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
    use serde_json::{Value, json};
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn fresh_vault() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store.keyspace("vault").expect("vault keyspace");
        (dir, store, ks)
    }

    /// A production-shape EdDSA (Ed25519) JWT signer. Used for both the issuer
    /// (minting) and the holder (kb-jwt). The raw key is reachable only via the
    /// sign-only `JwtSigner` trait.
    struct EddsaSigner {
        key: SigningKey,
        kid: String,
    }

    impl JwtSigner for EddsaSigner {
        fn algorithm(&self) -> &str {
            "EdDSA"
        }
        fn key_id(&self) -> Option<&str> {
            Some(&self.kid)
        }
        fn sign_jwt(&self, header: &Value, payload: &Value) -> Result<String, SdJwtError> {
            let header_b64 = URL_SAFE_NO_PAD.encode(
                serde_json::to_string(header)
                    .map_err(SdJwtError::from)?
                    .as_bytes(),
            );
            let payload_b64 = URL_SAFE_NO_PAD.encode(
                serde_json::to_string(payload)
                    .map_err(SdJwtError::from)?
                    .as_bytes(),
            );
            let signing_input = format!("{header_b64}.{payload_b64}");
            let sig: Signature = self.key.sign(signing_input.as_bytes());
            let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
            Ok(format!("{signing_input}.{sig_b64}"))
        }
    }

    /// An EdDSA `JwtVerifier` over a single Ed25519 key — used in tests to
    /// verify both the issuer JWS and the holder kb-jwt end to end.
    struct EddsaVerifier {
        key: VerifyingKey,
    }
    impl JwtVerifier for EddsaVerifier {
        fn verify_jwt(&self, jws: &str) -> Result<Value, SdJwtError> {
            let parts: Vec<&str> = jws.split('.').collect();
            if parts.len() != 3 {
                return Err(SdJwtError::Verification("malformed JWS".into()));
            }
            let signing_input = format!("{}.{}", parts[0], parts[1]);
            let sig_bytes = URL_SAFE_NO_PAD
                .decode(parts[2])
                .map_err(|e| SdJwtError::Verification(e.to_string()))?;
            let sig = Signature::from_slice(&sig_bytes)
                .map_err(|e| SdJwtError::Verification(e.to_string()))?;
            self.key
                .verify(signing_input.as_bytes(), &sig)
                .map_err(|_| SdJwtError::Verification("bad sig".into()))?;
            let payload = URL_SAFE_NO_PAD
                .decode(parts[1])
                .map_err(|e| SdJwtError::Verification(e.to_string()))?;
            serde_json::from_slice(&payload).map_err(|e| SdJwtError::Verification(e.to_string()))
        }
    }

    /// An issuer whose DID is the `did:key` for its Ed25519 key.
    fn issuer(seed: u8) -> (EddsaSigner, String, VerifyingKey) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let vk = signing.verifying_key();
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(vk.as_bytes());
        let kid = format!("{did}#key-0");
        (EddsaSigner { key: signing, kid }, did, vk)
    }

    /// A holder identity: the `did:key`, a kb-jwt `JwtSigner` whose verification
    /// method is under that DID, the consent-receipt `Secret`, and the verifying
    /// key. The same Ed25519 key signs the kb-jwt AND the consent receipt — both
    /// are the holder's VTA-managed key.
    fn holder(seed: u8) -> (String, EddsaSigner, Secret, VerifyingKey) {
        let seed = [seed; 32];
        let signing = SigningKey::from_bytes(&seed);
        let vk = signing.verifying_key();
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(vk.as_bytes());
        let vm = format!(
            "{did}#{}",
            did.strip_prefix("did:key:").expect("did:key prefix")
        );
        let kb_signer = EddsaSigner {
            key: signing,
            kid: vm.clone(),
        };
        let mut secret = Secret::generate_ed25519(Some(&vm), Some(&seed));
        secret.id = vm;
        (did, kb_signer, secret, vk)
    }

    /// Mint a membership SD-JWT-VC with the named disclosable claims and store
    /// it directly via `storage::put` (status forced to `Valid` and the window
    /// set), returning the stored id.
    #[allow(clippy::too_many_arguments)]
    async fn mint_and_put(
        vault: &KeyspaceHandle,
        id: &str,
        issuer_signer: &EddsaSigner,
        issuer_did: &str,
        subject_did: &str,
        claims: &Value,
        disclosable: &[&str],
        status: CredentialStatus,
        valid_from: Option<&str>,
        valid_until: Option<&str>,
    ) {
        let req = MintRequest {
            vct: "https://openvtc.org/credentials/MembershipCredential",
            issuer_did,
            subject_did,
            claims,
            disclosable,
            iat: 1_700_000_000,
            exp: Some(1_900_000_000),
        };
        let compact = mint_sd_jwt_vc(&req, issuer_signer).expect("mint");
        let cred = StoredCredential {
            id: id.to_string(),
            format: CredentialFormat::SdJwtVc,
            types: vec!["MembershipCredential".into()],
            schema_id: None,
            community_did: Some("did:web:acme.example".into()),
            subject_did: Some(subject_did.to_string()),
            issuer_did: Some(issuer_did.to_string()),
            purpose: None,
            status,
            valid_from: valid_from.map(str::to_string),
            valid_until: valid_until.map(str::to_string),
            received_at: "2026-01-01T00:00:00Z".into(),
            source: None,
            tags: Default::default(),
            body: compact.into_bytes(),
        };
        storage::put(vault, &cred).await.expect("put");
    }

    fn grant<'a>(
        holder_did: &'a str,
        credential_id: &'a str,
        verifier_did: &'a str,
        claims: Vec<String>,
        valid_until: DateTime<Utc>,
    ) -> ConsentGrant<'a> {
        ConsentGrant {
            holder_did,
            credential_id,
            verifier_did,
            purpose: "join the Acme community",
            claims,
            valid_until,
        }
    }

    /// Parse + verify a presentation produced by `present_sd_jwt_vc`: the issuer
    /// JWS, the disclosures, and the mandatory kb-jwt (aud + nonce bound).
    /// Returns the resolved claims.
    fn verify_presentation(
        compact: &str,
        issuer_vk: VerifyingKey,
        holder_vk: VerifyingKey,
        aud: &str,
        nonce: &str,
    ) -> Value {
        let hasher = Sha256Hasher;
        let sd_jwt = SdJwt::parse(compact, &hasher).expect("parse presentation");
        assert!(sd_jwt.kb_jwt.is_some(), "presentation MUST carry a kb-jwt");
        let issuer_v = EddsaVerifier { key: issuer_vk };
        let holder_v = EddsaVerifier { key: holder_vk };
        let opts = VerificationOptions {
            verify_kb: true,
            expected_audience: Some(aud),
            expected_nonce: Some(nonce),
        };
        let result = verify(&sd_jwt, &issuer_v, &hasher, &opts, Some(&holder_v))
            .expect("presentation verifies");
        assert!(result.is_verified(), "kb-jwt must verify");
        assert_eq!(result.kb_verified, Some(true));
        result.claims
    }

    // ---- ACCEPTANCE: happy path -----------------------------------------

    #[tokio::test]
    async fn presents_only_consented_claims_with_valid_kb_jwt() {
        let (_dir, _store, vault) = fresh_vault();
        let (issuer_signer, issuer_did, issuer_vk) = issuer(9);
        let (holder_did, kb_signer, consent_key, holder_vk) = holder(7);
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        let claims = json!({
            "givenName": "Alice",
            "memberSince": "2020",
            "dateOfBirth": "1990-01-01",
        });
        mint_and_put(
            &vault,
            "cred-1",
            &issuer_signer,
            &issuer_did,
            &holder_did,
            &claims,
            &["givenName", "memberSince", "dateOfBirth"],
            CredentialStatus::Valid,
            Some("2020-01-01T00:00:00Z"),
            Some("2100-01-01T00:00:00Z"),
        )
        .await;

        // Consent to disclose ONLY givenName + memberSince (NOT dateOfBirth).
        let rec = create_consent(
            &vault,
            &grant(
                &holder_did,
                "cred-1",
                verifier,
                vec!["givenName".into(), "memberSince".into()],
                now + Duration::hours(1),
            ),
            &consent_key,
        )
        .await
        .unwrap();

        let nonce = "verifier-nonce-abc";
        let pres = present_sd_jwt_vc(
            &vault,
            "cred-1",
            &rec.identifier,
            &kb_signer,
            nonce,
            verifier,
            now.timestamp() as u64,
            now,
        )
        .await
        .expect("present");

        // Verifiable end to end (issuer JWS + kb-jwt bound to aud/nonce).
        let resolved = verify_presentation(&pres, issuer_vk, holder_vk, verifier, nonce);

        // Discloses EXACTLY the consented claims — and NOT dateOfBirth.
        assert_eq!(resolved["givenName"], "Alice");
        assert_eq!(resolved["memberSince"], "2020");
        assert!(
            resolved.get("dateOfBirth").is_none(),
            "dateOfBirth was not consented and MUST NOT be disclosed"
        );

        // The wire form carries exactly two disclosures.
        let hasher = Sha256Hasher;
        let parsed = SdJwt::parse(&pres, &hasher).unwrap();
        assert_eq!(parsed.disclosures.len(), 2);
        let mut names: Vec<String> = parsed
            .disclosures
            .iter()
            .map(|d| d.claim_name.clone().unwrap_or_default())
            .collect();
        names.sort();
        assert_eq!(names, vec!["givenName".to_string(), "memberSince".into()]);
    }

    // ---- ACCEPTANCE: NEGATIVE — disclosed set never exceeds consent ------

    #[tokio::test]
    async fn never_discloses_beyond_the_consent_reveal_set() {
        // The credential makes THREE claims disclosable, but the consent record
        // names only ONE. The presentation must disclose exactly that one — the
        // disclosed set must never exceed `hasPersonalData`.
        let (_dir, _store, vault) = fresh_vault();
        let (issuer_signer, issuer_did, issuer_vk) = issuer(11);
        let (holder_did, kb_signer, consent_key, holder_vk) = holder(13);
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        let claims = json!({
            "givenName": "Bob",
            "memberSince": "2019",
            "dateOfBirth": "1988-05-05",
        });
        mint_and_put(
            &vault,
            "cred-2",
            &issuer_signer,
            &issuer_did,
            &holder_did,
            &claims,
            &["givenName", "memberSince", "dateOfBirth"],
            CredentialStatus::Valid,
            None,
            None,
        )
        .await;

        let rec = create_consent(
            &vault,
            &grant(
                &holder_did,
                "cred-2",
                verifier,
                vec!["memberSince".into()], // ONLY memberSince
                now + Duration::hours(1),
            ),
            &consent_key,
        )
        .await
        .unwrap();

        let nonce = "n1";
        let pres = present_sd_jwt_vc(
            &vault,
            "cred-2",
            &rec.identifier,
            &kb_signer,
            nonce,
            verifier,
            now.timestamp() as u64,
            now,
        )
        .await
        .expect("present");

        let resolved = verify_presentation(&pres, issuer_vk, holder_vk, verifier, nonce);
        assert_eq!(resolved["memberSince"], "2019");
        assert!(
            resolved.get("givenName").is_none(),
            "givenName not consented"
        );
        assert!(
            resolved.get("dateOfBirth").is_none(),
            "dateOfBirth not consented"
        );

        let hasher = Sha256Hasher;
        let parsed = SdJwt::parse(&pres, &hasher).unwrap();
        assert_eq!(
            parsed.disclosures.len(),
            1,
            "exactly one disclosure — the consented claim, nothing more"
        );
        assert_eq!(
            parsed.disclosures[0].claim_name.as_deref(),
            Some("memberSince")
        );
    }

    // ---- SECURITY: cross-subject consent must not present another's cred --

    #[tokio::test]
    async fn consent_by_a_different_holder_cannot_present_anothers_credential() {
        // The attack the subject-binding gate closes: holder B authors a
        // consent record (recipient V) naming claims that also exist on holder
        // A's credential. Without the `subject_did == data_subject` check, B's
        // consent would authorize disclosing A's credential to V. It must be
        // refused — the credential and the consent must be about the SAME
        // subject (§13, §14.2).
        let (_dir, _store, vault) = fresh_vault();
        let (issuer_signer, issuer_did, _ivk) = issuer(21);
        let (holder_a_did, holder_a_kb, _a_key, _a_vk) = holder(22); // credential subject
        let (holder_b_did, _b_kb, holder_b_key, _b_vk) = holder(23); // consent author
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        // A's credential, disclosable givenName.
        let claims = json!({ "givenName": "Alice" });
        mint_and_put(
            &vault,
            "cred-1",
            &issuer_signer,
            &issuer_did,
            &holder_a_did, // subject = A
            &claims,
            &["givenName"],
            CredentialStatus::Valid,
            None,
            None,
        )
        .await;

        // B authors consent for cred-1 (claims overlap), signed by B's key —
        // so data_subject == B, not A.
        let rec = create_consent(
            &vault,
            &grant(
                &holder_b_did,
                "cred-1",
                verifier,
                vec!["givenName".into()],
                now + Duration::hours(1),
            ),
            &holder_b_key,
        )
        .await
        .unwrap();
        assert_eq!(rec.data_subject, holder_b_did, "consent author is B");

        // Presenting A's credential under B's consent must be refused before any
        // disclosure — even though A's holder key signs the kb-jwt.
        let err = present_sd_jwt_vc(
            &vault,
            "cred-1",
            &rec.identifier,
            &holder_a_kb,
            "n",
            verifier,
            now.timestamp() as u64,
            now,
        )
        .await
        .expect_err("must refuse cross-subject presentation");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "a consent record by a different subject must never present another's \
             credential, got {err:?}"
        );
    }

    // ---- SECURITY: consent for a different credential is refused ----------

    #[tokio::test]
    async fn consent_bound_to_another_credential_is_refused() {
        // The consent record names a different credential (`dct:source`), so it
        // must not authorize presenting THIS one even though subject, verifier,
        // and claim names all match (§13: consent is per-credential).
        let (_dir, _store, vault) = fresh_vault();
        let (issuer_signer, issuer_did, _ivk) = issuer(31);
        let (holder_did, kb_signer, consent_key, _hvk) = holder(32);
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        let claims = json!({ "givenName": "Alice" });
        mint_and_put(
            &vault,
            "cred-1",
            &issuer_signer,
            &issuer_did,
            &holder_did,
            &claims,
            &["givenName"],
            CredentialStatus::Valid,
            None,
            None,
        )
        .await;

        // Consent is for "cred-OTHER", not "cred-1".
        let rec = create_consent(
            &vault,
            &grant(
                &holder_did,
                "cred-OTHER",
                verifier,
                vec!["givenName".into()],
                now + Duration::hours(1),
            ),
            &consent_key,
        )
        .await
        .unwrap();

        let err = present_sd_jwt_vc(
            &vault,
            "cred-1",
            &rec.identifier,
            &kb_signer,
            "n",
            verifier,
            now.timestamp() as u64,
            now,
        )
        .await
        .expect_err("must refuse: consent is for a different credential");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "a consent record bound to a different credential must not authorize \
             this one, got {err:?}"
        );
    }

    // ---- ACCEPTANCE: missing consent record refused ----------------------

    #[tokio::test]
    async fn missing_consent_record_is_refused() {
        let (_dir, _store, vault) = fresh_vault();
        let (issuer_signer, issuer_did, _ivk) = issuer(9);
        let (holder_did, kb_signer, _ck, _hvk) = holder(7);
        let claims = json!({ "givenName": "Alice" });
        mint_and_put(
            &vault,
            "cred-1",
            &issuer_signer,
            &issuer_did,
            &holder_did,
            &claims,
            &["givenName"],
            CredentialStatus::Valid,
            None,
            None,
        )
        .await;

        let now = Utc::now();
        let err = present_sd_jwt_vc(
            &vault,
            "cred-1",
            "urn:uuid:does-not-exist",
            &kb_signer,
            "n",
            "did:web:acme-verifier.example",
            now.timestamp() as u64,
            now,
        )
        .await
        .expect_err("must refuse");
        assert!(
            matches!(err, AppError::NotFound(_)),
            "a missing consent record must refuse disclosure, got {err:?}"
        );
    }

    // ---- ACCEPTANCE: withdrawn consent refused ---------------------------

    #[tokio::test]
    async fn withdrawn_consent_record_is_refused() {
        let (_dir, _store, vault) = fresh_vault();
        let (issuer_signer, issuer_did, _ivk) = issuer(9);
        let (holder_did, kb_signer, consent_key, _hvk) = holder(7);
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        let claims = json!({ "givenName": "Alice" });
        mint_and_put(
            &vault,
            "cred-1",
            &issuer_signer,
            &issuer_did,
            &holder_did,
            &claims,
            &["givenName"],
            CredentialStatus::Valid,
            None,
            None,
        )
        .await;

        let rec = create_consent(
            &vault,
            &grant(
                &holder_did,
                "cred-1",
                verifier,
                vec!["givenName".into()],
                now + Duration::hours(1),
            ),
            &consent_key,
        )
        .await
        .unwrap();
        withdraw(&vault, &rec.identifier, &consent_key)
            .await
            .unwrap()
            .expect("withdrawn");

        let err = present_sd_jwt_vc(
            &vault,
            "cred-1",
            &rec.identifier,
            &kb_signer,
            "n",
            verifier,
            now.timestamp() as u64,
            now,
        )
        .await
        .expect_err("must refuse");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "a withdrawn consent record must refuse disclosure, got {err:?}"
        );
    }

    // ---- ACCEPTANCE: expired consent refused -----------------------------

    #[tokio::test]
    async fn expired_consent_record_is_refused() {
        let (_dir, _store, vault) = fresh_vault();
        let (issuer_signer, issuer_did, _ivk) = issuer(9);
        let (holder_did, kb_signer, consent_key, _hvk) = holder(7);
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        let claims = json!({ "givenName": "Alice" });
        mint_and_put(
            &vault,
            "cred-1",
            &issuer_signer,
            &issuer_did,
            &holder_did,
            &claims,
            &["givenName"],
            CredentialStatus::Valid,
            None,
            None,
        )
        .await;

        // Consent already expired.
        let rec = create_consent(
            &vault,
            &grant(
                &holder_did,
                "cred-1",
                verifier,
                vec!["givenName".into()],
                now - Duration::minutes(1),
            ),
            &consent_key,
        )
        .await
        .unwrap();

        let err = present_sd_jwt_vc(
            &vault,
            "cred-1",
            &rec.identifier,
            &kb_signer,
            "n",
            verifier,
            now.timestamp() as u64,
            now,
        )
        .await
        .expect_err("must refuse");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "an expired consent record must refuse disclosure, got {err:?}"
        );
    }

    // ---- ACCEPTANCE: recipient mismatch refused --------------------------

    #[tokio::test]
    async fn recipient_mismatch_is_refused() {
        let (_dir, _store, vault) = fresh_vault();
        let (issuer_signer, issuer_did, _ivk) = issuer(9);
        let (holder_did, kb_signer, consent_key, _hvk) = holder(7);
        let now = Utc::now();

        let claims = json!({ "givenName": "Alice" });
        mint_and_put(
            &vault,
            "cred-1",
            &issuer_signer,
            &issuer_did,
            &holder_did,
            &claims,
            &["givenName"],
            CredentialStatus::Valid,
            None,
            None,
        )
        .await;

        // Consent is to verifier A; we present to verifier B.
        let rec = create_consent(
            &vault,
            &grant(
                &holder_did,
                "cred-1",
                "did:web:acme-verifier.example",
                vec!["givenName".into()],
                now + Duration::hours(1),
            ),
            &consent_key,
        )
        .await
        .unwrap();

        let err = present_sd_jwt_vc(
            &vault,
            "cred-1",
            &rec.identifier,
            &kb_signer,
            "n",
            "did:web:evil-verifier.example", // mismatched aud
            now.timestamp() as u64,
            now,
        )
        .await
        .expect_err("must refuse");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "a recipient mismatch must refuse disclosure, got {err:?}"
        );
    }

    // ---- ACCEPTANCE: revoked credential refused --------------------------

    #[tokio::test]
    async fn revoked_credential_is_refused() {
        let (_dir, _store, vault) = fresh_vault();
        let (issuer_signer, issuer_did, _ivk) = issuer(9);
        let (holder_did, kb_signer, consent_key, _hvk) = holder(7);
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        let claims = json!({ "givenName": "Alice" });
        mint_and_put(
            &vault,
            "cred-1",
            &issuer_signer,
            &issuer_did,
            &holder_did,
            &claims,
            &["givenName"],
            CredentialStatus::Revoked, // <-- revoked
            None,
            None,
        )
        .await;

        let rec = create_consent(
            &vault,
            &grant(
                &holder_did,
                "cred-1",
                verifier,
                vec!["givenName".into()],
                now + Duration::hours(1),
            ),
            &consent_key,
        )
        .await
        .unwrap();

        let err = present_sd_jwt_vc(
            &vault,
            "cred-1",
            &rec.identifier,
            &kb_signer,
            "n",
            verifier,
            now.timestamp() as u64,
            now,
        )
        .await
        .expect_err("must refuse");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "a revoked credential must never be presented, got {err:?}"
        );
    }

    // ---- ACCEPTANCE: temporally-invalid credential refused ---------------

    #[tokio::test]
    async fn temporally_invalid_credential_is_refused() {
        let (_dir, _store, vault) = fresh_vault();
        let (issuer_signer, issuer_did, _ivk) = issuer(9);
        let (holder_did, kb_signer, consent_key, _hvk) = holder(7);
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        let claims = json!({ "givenName": "Alice" });
        // valid_until already in the past.
        mint_and_put(
            &vault,
            "cred-1",
            &issuer_signer,
            &issuer_did,
            &holder_did,
            &claims,
            &["givenName"],
            CredentialStatus::Valid,
            Some("2000-01-01T00:00:00Z"),
            Some("2001-01-01T00:00:00Z"),
        )
        .await;

        let rec = create_consent(
            &vault,
            &grant(
                &holder_did,
                "cred-1",
                verifier,
                vec!["givenName".into()],
                now + Duration::hours(1),
            ),
            &consent_key,
        )
        .await
        .unwrap();

        let err = present_sd_jwt_vc(
            &vault,
            "cred-1",
            &rec.identifier,
            &kb_signer,
            "n",
            verifier,
            now.timestamp() as u64,
            now,
        )
        .await
        .expect_err("must refuse");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "a temporally-invalid credential must never be presented, got {err:?}"
        );
    }

    // ---- the kb-jwt is bound to the nonce (replay resistance) ------------

    #[tokio::test]
    async fn kb_jwt_is_bound_to_the_verifier_nonce() {
        let (_dir, _store, vault) = fresh_vault();
        let (issuer_signer, issuer_did, issuer_vk) = issuer(9);
        let (holder_did, kb_signer, consent_key, holder_vk) = holder(7);
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        let claims = json!({ "givenName": "Alice" });
        mint_and_put(
            &vault,
            "cred-1",
            &issuer_signer,
            &issuer_did,
            &holder_did,
            &claims,
            &["givenName"],
            CredentialStatus::Valid,
            None,
            None,
        )
        .await;

        let rec = create_consent(
            &vault,
            &grant(
                &holder_did,
                "cred-1",
                verifier,
                vec!["givenName".into()],
                now + Duration::hours(1),
            ),
            &consent_key,
        )
        .await
        .unwrap();

        let pres = present_sd_jwt_vc(
            &vault,
            "cred-1",
            &rec.identifier,
            &kb_signer,
            "the-right-nonce",
            verifier,
            now.timestamp() as u64,
            now,
        )
        .await
        .expect("present");

        // Verifying with the WRONG expected nonce must fail.
        let hasher = Sha256Hasher;
        let sd_jwt = SdJwt::parse(&pres, &hasher).unwrap();
        let issuer_v = EddsaVerifier { key: issuer_vk };
        let holder_v = EddsaVerifier { key: holder_vk };
        let opts = VerificationOptions {
            verify_kb: true,
            expected_audience: Some(verifier),
            expected_nonce: Some("a-different-nonce"),
        };
        assert!(
            verify(&sd_jwt, &issuer_v, &hasher, &opts, Some(&holder_v)).is_err(),
            "kb-jwt bound to one nonce must not verify against another"
        );

        // And the RIGHT nonce verifies — sanity.
        let _ = verify_presentation(&pres, issuer_vk, holder_vk, verifier, "the-right-nonce");
    }

    // ---- missing credential refused --------------------------------------

    #[tokio::test]
    async fn missing_credential_is_refused() {
        let (_dir, _store, vault) = fresh_vault();
        let (_is, _id, _ivk) = issuer(9);
        let (_hd, kb_signer, consent_key, _hvk) = holder(7);
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();
        let (holder_did, _ks2, _cs2, _vk2) = holder(7);

        let rec = create_consent(
            &vault,
            &grant(
                &holder_did,
                "cred-1",
                verifier,
                vec!["givenName".into()],
                now + Duration::hours(1),
            ),
            &consent_key,
        )
        .await
        .unwrap();

        let err = present_sd_jwt_vc(
            &vault,
            "no-such-cred",
            &rec.identifier,
            &kb_signer,
            "n",
            verifier,
            now.timestamp() as u64,
            now,
        )
        .await
        .expect_err("must refuse");
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }
}
