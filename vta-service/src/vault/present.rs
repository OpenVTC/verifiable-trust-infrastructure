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

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
use affinidi_sd_jwt::SdJwt;
use affinidi_sd_jwt::hasher::Sha256Hasher;
use affinidi_sd_jwt::holder::{KbJwtInput, present, select_disclosures};
use affinidi_sd_jwt::signer::JwtSigner;
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use serde_json::Value;
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
#[allow(clippy::too_many_arguments)]
pub async fn present_sd_jwt_vc(
    vault: &KeyspaceHandle,
    credential_id: &str,
    consent_record_id: &str,
    holder_signer: &dyn JwtSigner,
    nonce: &str,
    aud: &str,
    iat_unix: u64,
    status_resolver: Option<&dyn super::status::StatusListResolver>,
    now: DateTime<Utc>,
) -> Result<String, AppError> {
    // Consent + subject-binding + authorization + status + temporal gate. Shared
    // with the Data-Integrity path ([`present_di_vc`]) — the single source of
    // truth for the security-critical disclosure gate.
    let (cred, record) = gate_present(
        vault,
        credential_id,
        consent_record_id,
        aud,
        status_resolver,
        now,
    )
    .await?;

    if cred.format != CredentialFormat::SdJwtVc {
        return Err(AppError::Validation(format!(
            "credential `{credential_id}` is not an SD-JWT-VC (format {:?}); cannot present",
            cred.format
        )));
    }

    // The reveal set IS the consent record's `dpv:hasPersonalData`: present
    // discloses EXACTLY the consented set, no more.
    let reveal_set = &record.process.personal_data;

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

/// The shared disclosure gate for both present paths (the single source of truth
/// for the security-critical gate): load the credential + the proof-re-verified
/// consent record, enforce **subject binding** (§13/§14.2), the per-credential
/// **`authorizes`** decision (`dct:source` + recipient + claims-subset + given +
/// unexpired, §13), the **`Valid`** status (§14.5), and **temporal** validity.
/// Returns the credential + record; the caller builds the format-specific,
/// consent-scoped presentation.
pub(super) async fn gate_present(
    vault: &KeyspaceHandle,
    credential_id: &str,
    consent_record_id: &str,
    aud: &str,
    status_resolver: Option<&dyn super::status::StatusListResolver>,
    now: DateTime<Utc>,
) -> Result<(super::model::StoredCredential, consent::ConsentRecord), AppError> {
    let cred = storage::get(vault, credential_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("credential `{credential_id}` not found")))?;

    // `consent::get` re-verifies the holder DI proof (the non-repudiation
    // anchor); a record whose proof no longer verifies is an error, never used.
    let record = consent::get(vault, consent_record_id)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("consent record `{consent_record_id}` not found"))
        })?;

    // Subject binding (§13/§14.2): the consent's `dpv:hasDataSubject` must be the
    // credential's subject — so holder B's consent can't present holder A's
    // credential.
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

    // Per-credential authorization (§13): bound to this credential (`dct:source`),
    // recipient = `aud`, claims ⊆ reveal set, given + unexpired.
    if !consent::authorizes(
        &record,
        credential_id,
        aud,
        &record.process.personal_data,
        now,
    ) {
        return Err(AppError::Forbidden(format!(
            "consent record `{consent_record_id}` does not authorize disclosure of \
             `{credential_id}` to `{aud}` (wrong credential, withdrawn, expired, \
             recipient-mismatch, or claim out of scope)"
        )));
    }

    // Live status re-check (§14.5): when a resolver is configured, re-resolve the
    // credential's status list **now** rather than trusting the stored tag — so a
    // credential revoked since receive is refused at present time. `refresh_status`
    // persists any change; re-read to gate on the live status.
    //
    // Resilient: a transient fetch failure (status-list host unreachable) falls
    // back to the stored tag rather than blocking every presentation — fail-open
    // on a fetch error, but fail-closed on a successfully-fetched `revoked` bit.
    let cred = if let Some(resolver) = status_resolver {
        match super::status::refresh_status(vault, credential_id, resolver).await {
            Ok(_) => storage::get(vault, credential_id).await?.ok_or_else(|| {
                AppError::NotFound(format!("credential `{credential_id}` not found"))
            })?,
            Err(e) => {
                tracing::warn!(
                    credential_id,
                    error = %e,
                    "live status re-check failed; falling back to the stored status"
                );
                cred
            }
        }
    } else {
        cred
    };

    // Archived / soft-deleted credentials are not presentable — archival
    // lifecycle is orthogonal to validity but equally disqualifying.
    if !cred.is_active() {
        return Err(AppError::Forbidden(format!(
            "credential `{credential_id}` is archived or deleted; cannot present"
        )));
    }

    // Never present a revoked / temporally-invalid credential (§14.5).
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

    Ok((cred, record))
}

/// Build a consent-gated, holder-bound **W3C Data-Integrity Verifiable
/// Presentation** of a stored DI VC — the format-agnostic sibling of
/// [`present_sd_jwt_vc`] (spec D4).
///
/// Plain `eddsa-jcs-2022` has **no claim-level selective disclosure** (only BBS+
/// does), so a DI presentation is **whole-credential**: every claim is
/// disclosed. The gate therefore additionally requires the credential's claims
/// to be a **subset of the consented reveal set** — refusing rather than
/// over-disclosing. Holder binding (§14.4) is mandatory: the holder signs the VP
/// (which carries the verifier `nonce` + `domain`/`aud`) with an
/// `eddsa-jcs-2022` DI proof, so freshness + audience are covered by the
/// signature.
///
/// `holder_secret` is the holder's VTA-managed DI signing key. Returns the VP as
/// a JSON string.
#[allow(clippy::too_many_arguments)]
pub async fn present_di_vc(
    vault: &KeyspaceHandle,
    credential_id: &str,
    consent_record_id: &str,
    holder_secret: &Secret,
    nonce: &str,
    aud: &str,
    status_resolver: Option<&dyn super::status::StatusListResolver>,
    now: DateTime<Utc>,
) -> Result<String, AppError> {
    let (cred, record) = gate_present(
        vault,
        credential_id,
        consent_record_id,
        aud,
        status_resolver,
        now,
    )
    .await?;

    if cred.format != CredentialFormat::EddsaJcs2022 {
        return Err(AppError::Validation(format!(
            "credential `{credential_id}` is not an eddsa-jcs-2022 Data-Integrity VC \
             (format {:?}); cannot present via present_di_vc",
            cred.format
        )));
    }

    let vc: Value = serde_json::from_slice(&cred.body)
        .map_err(|e| AppError::Validation(format!("stored DI VC body is not JSON: {e}")))?;

    // Whole-credential disclosure guard: every `credentialSubject` claim (besides
    // `id`) MUST be in the consented reveal set, else presenting the whole VC
    // would over-disclose (plain DI cannot redact).
    let reveal_set = &record.process.personal_data;
    if let Some(subject) = vc.get("credentialSubject").and_then(Value::as_object) {
        for name in subject.keys() {
            if name == "id" {
                continue;
            }
            if !reveal_set.iter().any(|c| c == name) {
                return Err(AppError::Forbidden(format!(
                    "a Data-Integrity presentation discloses the whole credential, but claim \
                     `{name}` is not in the consent reveal set; refusing to over-disclose \
                     (use SD-JWT-VC or BBS+ for partial disclosure)"
                )));
            }
        }
    }

    // Build the VP wrapping the VC, carrying the verifier nonce + domain so the
    // holder proof binds freshness + audience.
    let holder_did = holder_secret
        .id
        .split_once('#')
        .map(|(d, _)| d)
        .unwrap_or(holder_secret.id.as_str());
    let mut vp = serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": holder_did,
        "verifiableCredential": [vc],
        "nonce": nonce,
        "domain": aud,
    });

    // Holder binding (§14.4): sign the VP (covering nonce + domain).
    let proof = DataIntegrityProof::sign(
        &vp,
        holder_secret,
        SignOptions::new()
            .with_proof_purpose("authentication")
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .map_err(|e| AppError::Internal(format!("sign VP: {e}")))?;
    vp.as_object_mut().expect("vp is an object").insert(
        "proof".into(),
        serde_json::to_value(proof)
            .map_err(|e| AppError::Internal(format!("serialize VP proof: {e}")))?,
    );

    serde_json::to_string(&vp).map_err(|e| AppError::Internal(format!("serialize VP: {e}")))
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
        let ks = store
            .keyspace(crate::keyspaces::VAULT)
            .expect("vault keyspace");
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
            lifecycle: vti_common::vault::VaultStatus::Active,
            archived_at: None,
            deleted_at: None,
            grace_until: None,
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

    // ---- BBS+ selective disclosure (feature `bbs`) ----------------------

    #[cfg(feature = "bbs")]
    #[tokio::test]
    async fn present_bbs_discloses_only_consented_claims() {
        use crate::vault::bbs::{present_bbs, receive_bbs};
        use affinidi_bbs as bbs;
        use affinidi_data_integrity::bbs_2023_transform::{
            sign_base_document, verify_derived_proof,
        };

        let (_dir, _store, vault) = fresh_vault();
        let (holder_did, _kb, consent_key, _vk) = holder(7);
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        // Issuer signs a BBS base-proof VC bound to the holder as subject.
        let sk = bbs::keygen(b"present-bbs-issuer-key-material!!", b"").unwrap();
        let pk = bbs::sk_to_pk(&sk);
        let issuer_did = affinidi_crypto::bls12381::g2_pub_to_did_key(&pk.to_bytes());
        let vc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": issuer_did,
            "validFrom": "2020-01-01T00:00:00Z",
            "credentialSubject": {
                "id": holder_did,
                "givenName": "Alice",
                "memberSince": "2020",
                "dateOfBirth": "1990-01-01"
            }
        });
        let mandatory = ["/@context", "/type", "/issuer", "/credentialSubject/id"];
        let signed = sign_base_document(
            &vc,
            &mandatory,
            &format!("{issuer_did}#bbs-key-0"),
            "2020-01-01T00:00:00Z",
            &sk,
            &pk,
            b"present-bbs-test-hmac-key-32byte",
        )
        .unwrap();
        let body = serde_json::to_vec(&signed).unwrap();
        receive_bbs(&vault, "bbs-cred", &body, &pk.to_bytes(), None, now)
            .await
            .expect("receive BBS base proof");

        // Consent to disclose ONLY givenName + memberSince (NOT dateOfBirth).
        let rec = create_consent(
            &vault,
            &grant(
                &holder_did,
                "bbs-cred",
                verifier,
                vec!["givenName".into(), "memberSince".into()],
                now + Duration::hours(1),
            ),
            &consent_key,
        )
        .await
        .unwrap();

        let nonce = "verifier-nonce-bbs";
        let pres = present_bbs(
            &vault,
            "bbs-cred",
            &rec.identifier,
            &pk.to_bytes(),
            nonce,
            verifier,
            None,
            now,
        )
        .await
        .expect("present BBS");

        let derived: Value = serde_json::from_str(&pres).unwrap();
        let cs = &derived["credentialSubject"];
        assert_eq!(cs["givenName"], "Alice");
        assert_eq!(cs["memberSince"], "2020");
        assert!(
            cs.get("dateOfBirth").is_none(),
            "dateOfBirth was not consented and MUST be redacted by BBS"
        );
        assert_eq!(
            cs["id"],
            holder_did.as_str(),
            "mandatory subject id disclosed"
        );

        // The derived proof verifies against the issuer key. (The standards-track
        // verify authenticates the presentation header embedded in the proof; the
        // verifier binds that header to its own challenge — covered in the VTC
        // join verifier tests, not here.)
        assert!(
            verify_derived_proof(&derived, &pk).unwrap(),
            "BBS derived presentation must verify"
        );
    }

    #[cfg(feature = "bbs")]
    #[tokio::test]
    async fn present_bbs_holder_bound_is_per_verifier_pseudonymous() {
        use crate::vault::bbs::{issue_bbs_pseudonym_for_test, present_bbs, receive_bbs_pseudonym};
        use affinidi_bbs as bbs;
        use affinidi_data_integrity::bbs_2023_transform::verify_pseudonym_derived_proof;

        let (_dir, _store, vault) = fresh_vault();
        let (holder_did, _kb, consent_key, _vk) = holder(9);
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        // Issue a pseudonym (holder-binding) base-proof VC bound to the holder.
        let sk = bbs::keygen(b"present-nym-issuer-key-material!!", b"").unwrap();
        let pk = bbs::sk_to_pk(&sk);
        let issuer_did = affinidi_crypto::bls12381::g2_pub_to_did_key(&pk.to_bytes());
        let vc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": issuer_did,
            "validFrom": "2020-01-01T00:00:00Z",
            "credentialSubject": { "id": holder_did, "givenName": "Alice", "dateOfBirth": "1990-01-01" }
        });
        let mandatory = ["/@context", "/type", "/issuer", "/credentialSubject/id"];
        let vm = format!("{issuer_did}#bbs-key-0");
        let (base, nym, blind) = issue_bbs_pseudonym_for_test(
            &vc,
            &mandatory,
            &vm,
            "2020-01-01T00:00:00Z",
            &sk,
            &pk,
            b"present-nym-test-hmac-key-32byte",
            &[0x11u8; 32],
            &[0x22u8; 32],
        );
        let body = serde_json::to_vec(&base).unwrap();
        receive_bbs_pseudonym(
            &vault,
            "nym-cred",
            &body,
            &pk.to_bytes(),
            &nym,
            &blind,
            None,
            now,
        )
        .await
        .expect("receive pseudonym base proof");

        // Consent to disclose only givenName.
        let rec = create_consent(
            &vault,
            &grant(
                &holder_did,
                "nym-cred",
                verifier,
                vec!["givenName".into()],
                now + Duration::hours(1),
            ),
            &consent_key,
        )
        .await
        .unwrap();

        let pres = present_bbs(
            &vault,
            "nym-cred",
            &rec.identifier,
            &pk.to_bytes(),
            "verifier-nonce-nym",
            verifier,
            None,
            now,
        )
        .await
        .expect("present holder-bound BBS");
        let derived: Value = serde_json::from_str(&pres).unwrap();

        // It is a *pseudonym* derived proof (`0xd95d09`), not a basic one.
        let pv = derived["proof"]["proofValue"].as_str().unwrap();
        let (_b, bytes) = multibase::decode(pv).unwrap();
        assert_eq!(
            &bytes[..3],
            &[0xd9, 0x5d, 0x09],
            "holder-binding must emit a pseudonym derived proof"
        );

        // Verifies under the verifier it was bound to ...
        assert!(
            verify_pseudonym_derived_proof(&derived, &pk, verifier).unwrap(),
            "pseudonym proof must verify for its bound verifier"
        );
        // ... and NOT under a different verifier id (per-verifier binding).
        assert!(
            !verify_pseudonym_derived_proof(&derived, &pk, "did:web:someone-else.example")
                .unwrap_or(false),
            "a pseudonym proof must not verify under a different verifier id"
        );

        // Disclosure is still minimised.
        assert_eq!(derived["credentialSubject"]["givenName"], "Alice");
        assert!(
            derived["credentialSubject"].get("dateOfBirth").is_none(),
            "an unconsented claim must be redacted"
        );
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
            now,
        )
        .await
        .expect_err("must refuse");
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }

    // ---- Data-Integrity present (present_di_vc) -------------------------

    use affinidi_data_integrity::VerifyOptions;

    /// Store a plain W3C-DI VC (format `EddsaJcs2022`) with `subject_did` + the
    /// given `subject_claims` merged into `credentialSubject`. (present_di_vc
    /// wraps the stored body into the VP; it does not re-verify the issuer proof
    /// — that happened at receive — so a plain VC body suffices here.)
    async fn di_put(vault: &KeyspaceHandle, id: &str, subject_did: &str, subject_claims: Value) {
        let mut cs = serde_json::Map::new();
        cs.insert("id".into(), serde_json::json!(subject_did));
        if let Some(obj) = subject_claims.as_object() {
            for (k, v) in obj {
                cs.insert(k.clone(), v.clone());
            }
        }
        let vc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": "did:web:issuer.example",
            "credentialSubject": cs,
        });
        let cred = StoredCredential {
            id: id.to_string(),
            format: CredentialFormat::EddsaJcs2022,
            types: vec!["MembershipCredential".into()],
            schema_id: None,
            community_did: None,
            subject_did: Some(subject_did.to_string()),
            issuer_did: Some("did:web:issuer.example".into()),
            purpose: None,
            status: CredentialStatus::Valid,
            valid_from: None,
            valid_until: None,
            received_at: "2026-01-01T00:00:00Z".into(),
            source: None,
            tags: Default::default(),
            body: serde_json::to_vec(&vc).unwrap(),
            lifecycle: vti_common::vault::VaultStatus::Active,
            archived_at: None,
            deleted_at: None,
            grace_until: None,
        };
        storage::put(vault, &cred).await.expect("put DI VC");
    }

    /// A held DI VC carrying a W3C `BitstringStatusListEntry` at `index`,
    /// stored with the `Valid` tag (as if status hadn't been re-checked since
    /// receive).
    async fn di_put_with_status(vault: &KeyspaceHandle, id: &str, subject_did: &str, index: usize) {
        let vc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": "did:web:issuer.example",
            "credentialSubject": { "id": subject_did, "givenName": "Alice" },
            "credentialStatus": {
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": index.to_string(),
                "statusListCredential": "https://issuer.example/status/1",
            },
        });
        let cred = StoredCredential {
            id: id.to_string(),
            format: CredentialFormat::EddsaJcs2022,
            types: vec!["MembershipCredential".into()],
            schema_id: None,
            community_did: None,
            subject_did: Some(subject_did.to_string()),
            issuer_did: Some("did:web:issuer.example".into()),
            purpose: None,
            status: CredentialStatus::Valid,
            valid_from: None,
            valid_until: None,
            received_at: "2026-01-01T00:00:00Z".into(),
            source: None,
            tags: Default::default(),
            body: serde_json::to_vec(&vc).unwrap(),
            lifecycle: vti_common::vault::VaultStatus::Active,
            archived_at: None,
            deleted_at: None,
            grace_until: None,
        };
        storage::put(vault, &cred).await.expect("put DI VC");
    }

    /// A live status resolver whose list marks `revoked` index as revoked.
    struct RevokedAt(usize);

    #[async_trait::async_trait]
    impl super::super::status::StatusListResolver for RevokedAt {
        async fn resolve(
            &self,
            _url: &str,
            _expected_issuer: Option<&str>,
        ) -> Result<super::super::status::ResolvedStatusList, AppError> {
            use affinidi_status_list::{BitstringStatusList, StatusPurpose};
            let mut list = BitstringStatusList::new(1024, StatusPurpose::Revocation);
            list.set(self.0, true).unwrap();
            Ok(super::super::status::ResolvedStatusList {
                encoded_list: list.encode().unwrap(),
                size: 1024,
                status_purpose: StatusPurpose::Revocation,
            })
        }
    }

    #[tokio::test]
    async fn gate_present_live_status_refuses_a_since_revoked_credential() {
        let (_dir, _store, vault) = fresh_vault();
        let (holder_did, _kb, holder_secret, _vk) = holder(7);
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        // Stored with the Valid tag, status index 5.
        di_put_with_status(&vault, "di-rev", &holder_did, 5).await;
        let rec = create_consent(
            &vault,
            &grant(
                &holder_did,
                "di-rev",
                verifier,
                vec!["givenName".into()],
                now + chrono::Duration::hours(1),
            ),
            &holder_secret,
        )
        .await
        .unwrap();

        // No resolver → the stored tag (Valid) is trusted → the gate passes.
        gate_present(&vault, "di-rev", &rec.identifier, verifier, None, now)
            .await
            .expect("stored-tag gate passes");

        // Live resolver whose list does NOT revoke index 5 → the gate re-resolves
        // and still passes.
        gate_present(
            &vault,
            "di-rev",
            &rec.identifier,
            verifier,
            Some(&RevokedAt(999)),
            now,
        )
        .await
        .expect("live gate passes when the list says valid");

        // Live resolver whose list **revokes** index 5 → the gate re-resolves and
        // refuses, even though the stored tag still said Valid.
        let err = gate_present(
            &vault,
            "di-rev",
            &rec.identifier,
            verifier,
            Some(&RevokedAt(5)),
            now,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("not valid")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn present_di_vc_produces_a_verifiable_holder_bound_vp() {
        let (_dir, _store, vault) = fresh_vault();
        let (holder_did, _kb, holder_secret, _vk) = holder(7);
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        di_put(
            &vault,
            "di-1",
            &holder_did,
            serde_json::json!({ "givenName": "Alice" }),
        )
        .await;
        let rec = create_consent(
            &vault,
            &grant(
                &holder_did,
                "di-1",
                verifier,
                vec!["givenName".into()],
                now + Duration::hours(1),
            ),
            &holder_secret,
        )
        .await
        .unwrap();

        let vp_json = present_di_vc(
            &vault,
            "di-1",
            &rec.identifier,
            &holder_secret,
            "nonce-1",
            verifier,
            None,
            now,
        )
        .await
        .expect("present DI VC");
        let vp: Value = serde_json::from_str(&vp_json).unwrap();

        assert_eq!(vp["type"][0], "VerifiablePresentation");
        assert_eq!(vp["holder"], holder_did);
        assert_eq!(vp["nonce"], "nonce-1"); // freshness, covered by the holder proof
        assert_eq!(vp["domain"], verifier); // audience binding
        assert_eq!(
            vp["verifiableCredential"][0]["credentialSubject"]["givenName"],
            "Alice"
        );

        // The holder proof verifies over the VP with `proof` stripped — so the
        // nonce + domain binding is cryptographically attested.
        let proof: DataIntegrityProof = serde_json::from_value(vp["proof"].clone()).unwrap();
        let mut unsigned = vp.clone();
        unsigned.as_object_mut().unwrap().remove("proof");
        proof
            .verify_with_public_key(
                &unsigned,
                holder_secret.get_public_bytes(),
                VerifyOptions::new(),
            )
            .expect("holder VP proof must verify");
    }

    #[tokio::test]
    async fn present_di_vc_refuses_to_over_disclose() {
        // The credential carries givenName + dateOfBirth, but consent covers only
        // givenName. Plain DI can't redact, so presenting would over-disclose →
        // refuse.
        let (_dir, _store, vault) = fresh_vault();
        let (holder_did, _kb, holder_secret, _vk) = holder(8);
        let verifier = "did:web:v.example";
        let now = Utc::now();

        di_put(
            &vault,
            "di-2",
            &holder_did,
            serde_json::json!({ "givenName": "Alice", "dateOfBirth": "1990-01-01" }),
        )
        .await;
        let rec = create_consent(
            &vault,
            &grant(
                &holder_did,
                "di-2",
                verifier,
                vec!["givenName".into()], // NOT dateOfBirth
                now + Duration::hours(1),
            ),
            &holder_secret,
        )
        .await
        .unwrap();

        let err = present_di_vc(
            &vault,
            "di-2",
            &rec.identifier,
            &holder_secret,
            "n",
            verifier,
            None,
            now,
        )
        .await
        .expect_err("over-disclosure must be refused");
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
    }

    #[tokio::test]
    async fn present_di_vc_refuses_a_non_di_credential() {
        // An SD-JWT-VC can't be presented via the DI path.
        let (_dir, _store, vault) = fresh_vault();
        let (issuer_signer, issuer_did, _ivk) = issuer(9);
        let (holder_did, _kb, holder_secret, _vk) = holder(7);
        let verifier = "did:web:v.example";
        let now = Utc::now();

        mint_and_put(
            &vault,
            "sd-1",
            &issuer_signer,
            &issuer_did,
            &holder_did,
            &serde_json::json!({ "givenName": "Alice" }),
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
                "sd-1",
                verifier,
                vec!["givenName".into()],
                now + Duration::hours(1),
            ),
            &holder_secret,
        )
        .await
        .unwrap();

        let err = present_di_vc(
            &vault,
            "sd-1",
            &rec.identifier,
            &holder_secret,
            "n",
            verifier,
            None,
            now,
        )
        .await
        .expect_err("SD-JWT-VC must not present via the DI path");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }
}
