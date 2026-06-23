//! Receive a credential into the VTA vault (task 1.2,
//! `docs/05-design-notes/vti-credential-architecture.md` §5 "Receive").
//!
//! This is the **write path** of the credential vault: it takes an incoming
//! SD-JWT-VC, verifies it **minimally** (issuer signature + temporal
//! validity), maps the verified claims into a [`StoredCredential`] envelope,
//! and stores + indexes it via the storage layer ([`super::storage`]).
//!
//! ## Scope (deliberately minimal — spec §5 "verify minimally")
//!
//! Receive verifies exactly two things, and **rejects-without-storing** on
//! either failure:
//! 1. **Issuer signature.** The SD-JWT's issuer JWS is verified against the
//!    Ed25519 key resolved from the credential's own `iss` DID (`did:key`).
//!    A tampered signature never produces verified claims, so a forged
//!    credential cannot reach the store.
//! 2. **Temporal validity.** `affinidi_sd_jwt_vc::verify_temporal` over the
//!    *verified* claims — `iat` not in the future, `exp` not in the past,
//!    `nbf` not in the future. An expired credential is rejected.
//!
//! Everything else the broader architecture eventually checks — schema
//! validation (§8), issuer-trust policy (§14.6), status-list revocation
//! (§14.5), holder binding (§14.4, a *presentation*-time concern) — is **out
//! of scope for receive** and lands in later tasks. `status` is therefore set
//! to [`CredentialStatus::Valid`] only in the narrow "passed signature +
//! temporal" sense; task 1.6 resolves real revocation state.
//!
//! ## Security invariants upheld here (spec §14)
//! - **Reject-before-store.** The verification result is the *only* path to a
//!   [`StoredCredential`]: claims are read from the verified result, never
//!   from the unverified payload. A tampered or expired credential returns an
//!   `Err` and **nothing is written** — there is no partial-store window
//!   (`storage::put` is the single, final side effect, reached only after
//!   both checks pass).
//! - **No enumeration.** This module only *writes*; it adds no list/scan
//!   surface (spec §14.1). Discovery stays the targeted index scan from task
//!   1.1.
//! - **Input validation.** The compact serialization is parsed and the issuer
//!   DID is resolved before any trust is placed in the bytes; a malformed
//!   credential, an `iss` that is not a resolvable `did:key`, or a missing
//!   `iss` all fail closed.
//!
//! ## What this module does NOT do
//! It pulls in **no BBS** (`affinidi-bbs` is audit-gated; BBS receive is a
//! later task) and adds **no route / DIDComm handler** — the credential vault
//! exposes no wire surface yet, so receive is a library operation only.

use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions, crypto_suites::CryptoSuite};
use affinidi_sd_jwt::SdJwt;
use affinidi_sd_jwt::hasher::Sha256Hasher;
use affinidi_sd_jwt::signer::JwtVerifier;
use affinidi_sd_jwt::verifier::{VerificationOptions, verify};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::model::{CredentialFormat, CredentialPurpose, CredentialStatus, StoredCredential};
use super::storage;

/// An EdDSA (Ed25519) `JwtVerifier` bound to a single issuer key.
///
/// The key is resolved from the credential's own `iss` DID before this
/// verifier is built, so verification proves the JWS was signed by the key
/// the credential names as its issuer. It validates the `alg` header is
/// `EdDSA` *before* touching the signature and checks the Ed25519 signature
/// over the compact signing input (`header_b64.payload_b64`). A wrong `alg`,
/// a malformed JWS, or a bad signature all return an error — which means
/// `verify` returns `Err` and no claims are produced.
struct IssuerEddsaVerifier {
    key: VerifyingKey,
}

impl JwtVerifier for IssuerEddsaVerifier {
    fn verify_jwt(&self, jws: &str) -> Result<Value, affinidi_sd_jwt::error::SdJwtError> {
        use affinidi_sd_jwt::error::SdJwtError;

        let parts: Vec<&str> = jws.split('.').collect();
        if parts.len() != 3 {
            return Err(SdJwtError::Verification("malformed compact JWS".into()));
        }
        let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

        // Validate the algorithm header before doing any signature work.
        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| SdJwtError::Verification(e.to_string()))?;
        let header: Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| SdJwtError::Verification(e.to_string()))?;
        if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
            return Err(SdJwtError::Verification(
                "unexpected alg (want EdDSA)".into(),
            ));
        }

        // Verify the Ed25519 signature over `header_b64.payload_b64`.
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| SdJwtError::Verification(e.to_string()))?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|e| SdJwtError::Verification(e.to_string()))?;
        self.key
            .verify(signing_input.as_bytes(), &sig)
            .map_err(|_| SdJwtError::Verification("Ed25519 signature invalid".into()))?;

        // Signature good — decode and return the payload.
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| SdJwtError::Verification(e.to_string()))?;
        serde_json::from_slice(&payload_bytes).map_err(|e| SdJwtError::Verification(e.to_string()))
    }
}

/// Provenance hint recorded on the stored envelope's `source` field.
///
/// Free-form; carried through verbatim. Callers pass the exchange thread id /
/// delivering DID so an operator can later trace where a credential came
/// from. `None` leaves `source` unset.
pub type Provenance = Option<String>;

/// Receive an incoming SD-JWT-VC into the vault: verify minimally, map, and
/// store.
///
/// `compact` is the SD-JWT-VC compact serialization (the JWS plus tilde-
/// separated disclosures). `id` is the holder-agent-assigned local handle
/// (the vault primary key — a ULID is recommended). `source` is optional
/// provenance. `now_unix` is the current time in Unix seconds, injected for
/// testability (production callers pass `chrono::Utc::now().timestamp()`).
///
/// On success the credential is stored under `id` and indexed by
/// `{type, community_did, issuer_did, purpose, status}` so it is findable via
/// [`super::find_by_index`]. Returns the [`StoredCredential`] that was
/// persisted.
///
/// ## Failure modes (all reject **without** storing)
/// - `id` is empty → [`AppError::Validation`].
/// - `compact` does not parse as an SD-JWT → [`AppError::Validation`].
/// - the payload has no `iss`, or `iss` is not a resolvable `did:key`
///   → [`AppError::Validation`].
/// - the issuer signature does not verify → [`AppError::Validation`].
/// - the credential is expired / not-yet-valid / has no `iat`
///   → [`AppError::Validation`].
///
/// No write to the store happens on any of these paths.
pub async fn receive_sd_jwt_vc(
    vault: &KeyspaceHandle,
    id: &str,
    compact: &str,
    source: Provenance,
    now_unix: u64,
) -> Result<StoredCredential, AppError> {
    if id.trim().is_empty() {
        return Err(AppError::Validation(
            "credential id must be non-empty".to_string(),
        ));
    }

    let hasher = Sha256Hasher;

    // Parse the compact serialization. Malformed input fails closed here,
    // before any trust is placed in the bytes.
    let sd_jwt = SdJwt::parse(compact, &hasher)
        .map_err(|e| AppError::Validation(format!("malformed SD-JWT-VC: {e}")))?;

    // Read the *unverified* payload only to learn which issuer DID to resolve.
    // No claim is trusted from this view — every value mapped onto the stored
    // envelope below comes from the *verified* result.
    let unverified_payload = sd_jwt
        .payload()
        .map_err(|e| AppError::Validation(format!("unreadable SD-JWT-VC payload: {e}")))?;

    let issuer_did = unverified_payload
        .get("iss")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("SD-JWT-VC is missing the `iss` claim".to_string()))?;

    // Resolve the issuer DID to its Ed25519 public key. The credential names
    // its own issuer; resolution failing (not a did:key, bad multicodec)
    // rejects the credential rather than trusting an unresolvable issuer.
    let issuer_pub = affinidi_crypto::did_key::did_key_to_ed25519_pub(issuer_did).map_err(|e| {
        AppError::Validation(format!(
            "issuer `iss` ({issuer_did}) is not a resolvable did:key: {e}"
        ))
    })?;
    let verifying_key = VerifyingKey::from_bytes(&issuer_pub)
        .map_err(|e| AppError::Validation(format!("issuer key is not a valid Ed25519 key: {e}")))?;
    let verifier = IssuerEddsaVerifier { key: verifying_key };

    // Verify the issuer signature. A tampered JWS produces `Err` here, so
    // forged credentials never reach the store. We pass no holder-binding
    // verifier: holder binding is a *presentation*-time concern (spec §14.4),
    // not a receive-time one. The returned `claims` are the only trusted view.
    let opts = VerificationOptions::default();
    let result = verify(&sd_jwt, &verifier, &hasher, &opts, None)
        .map_err(|e| AppError::Validation(format!("issuer signature verification failed: {e}")))?;
    if !result.is_verified() {
        return Err(AppError::Validation(
            "SD-JWT-VC verification did not succeed".to_string(),
        ));
    }
    let claims = &result.claims;

    // Temporal validity over the *verified* claims. Expired / not-yet-valid /
    // missing-iat all reject without storing.
    affinidi_sd_jwt_vc::verify_temporal(claims, now_unix)
        .map_err(|e| AppError::Validation(format!("temporal validity check failed: {e}")))?;

    // --- map verified claims → StoredCredential envelope (spec §5) ---

    let types = extract_types(claims);
    let subject_did = claims
        .get("sub")
        .and_then(Value::as_str)
        .map(str::to_string);
    let purpose = infer_purpose(&types);
    let valid_from =
        unix_claim_to_rfc3339(claims, "nbf").or_else(|| unix_claim_to_rfc3339(claims, "iat"));
    let valid_until = unix_claim_to_rfc3339(claims, "exp");

    let cred = StoredCredential {
        id: id.to_string(),
        format: CredentialFormat::SdJwtVc,
        types,
        // schema_id resolution against the VTC schema store is task 1.2's
        // sibling-phase work (§8); not derived here.
        schema_id: None,
        // The credential's community/context binding is a higher-layer
        // concept (a claim convention); not part of the minimal SD-JWT-VC
        // profile, so left unset at receive time.
        community_did: None,
        context_id: None,
        subject_did,
        issuer_did: Some(issuer_did.to_string()),
        purpose,
        // "Valid" here means *passed signature + temporal* only. Real
        // revocation state is resolved by the status task (1.6).
        status: CredentialStatus::Valid,
        valid_from,
        valid_until,
        received_at: chrono::Utc::now().to_rfc3339(),
        source,
        tags: std::collections::BTreeMap::new(),
        // Store the credential verbatim as the holder received it, so a later
        // present/refresh re-parses the exact bytes. Opaque to the store.
        body: compact.as_bytes().to_vec(),
        lifecycle: vti_common::vault::VaultStatus::Active,
        archived_at: None,
        deleted_at: None,
        grace_until: None,
    };

    // Single, final side effect. Reached only after both checks passed, so
    // there is no path that stores an unverified or expired credential.
    storage::put(vault, &cred).await?;

    Ok(cred)
}

/// Receive a **W3C Data-Integrity VC** (`eddsa-jcs-2022`) into the vault: verify
/// the issuer proof + temporal validity, map, and store (spec D4 — the
/// format-agnostic bridge; the W3C-DI sibling of [`receive_sd_jwt_vc`]).
///
/// `vc_json` is the credential as the holder received it (a W3C VC 2.0 JSON
/// document with a `proof`). `issuer_pub` is the issuer's Ed25519 public key —
/// **the caller resolves the issuer DID** (the vault stays network-free,
/// mirroring the injected-signer pattern in [`super::present`]; the wire layer
/// resolves a `did:webvh` / `did:web` issuer, a test passes the known key).
/// `now` anchors the temporal check.
///
/// ## Failure modes (all reject **without** storing)
/// - `id` empty, or `vc_json` not a JSON object → [`AppError::Validation`];
/// - no `proof`, or a non-`eddsa-jcs-2022` cryptosuite (BBS+ is audit-gated and
///   routed elsewhere) → [`AppError::Validation`];
/// - the issuer proof does not verify against `issuer_pub` → [`AppError::Validation`];
/// - `now` is outside `validFrom`/`validUntil` → [`AppError::Validation`].
pub async fn receive_di_vc(
    vault: &KeyspaceHandle,
    id: &str,
    vc_json: &[u8],
    issuer_pub: &[u8],
    source: Provenance,
    now: DateTime<Utc>,
) -> Result<StoredCredential, AppError> {
    if id.trim().is_empty() {
        return Err(AppError::Validation(
            "credential id must be non-empty".to_string(),
        ));
    }

    let vc: Value = serde_json::from_slice(vc_json)
        .map_err(|e| AppError::Validation(format!("malformed Data-Integrity VC JSON: {e}")))?;

    // Pull the proof and require eddsa-jcs-2022 (BBS+ is audit-gated, routed by
    // [`receive`] to an explicit error).
    let proof_val = vc
        .get("proof")
        .cloned()
        .ok_or_else(|| AppError::Validation("Data-Integrity VC has no `proof`".to_string()))?;
    let proof: DataIntegrityProof = serde_json::from_value(proof_val)
        .map_err(|e| AppError::Validation(format!("unparseable Data-Integrity proof: {e}")))?;
    if !matches!(proof.cryptosuite, CryptoSuite::EddsaJcs2022) {
        return Err(AppError::Validation(format!(
            "unsupported cryptosuite {:?} (expected eddsa-jcs-2022; BBS+ is audit-gated)",
            proof.cryptosuite
        )));
    }

    // Verify over the document with `proof` removed — JCS is presence-sensitive,
    // so sign-time and verify-time both strip it. A tampered credential fails
    // here, before any trust is placed in the bytes.
    let mut signing_doc = vc.clone();
    signing_doc
        .as_object_mut()
        .ok_or_else(|| AppError::Validation("Data-Integrity VC is not a JSON object".to_string()))?
        .remove("proof");
    proof
        .verify_with_public_key(&signing_doc, issuer_pub, VerifyOptions::new())
        .map_err(|e| {
            AppError::Validation(format!(
                "issuer Data-Integrity proof verification failed: {e}"
            ))
        })?;

    // Temporal validity over W3C VC 2.0 `validFrom` / `validUntil`.
    di_temporal_valid(&vc, now)?;

    // --- map verified VC → StoredCredential envelope ---
    let types = extract_types(&vc);
    let subject_did = vc
        .get("credentialSubject")
        .and_then(|s| s.get("id"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let issuer_did = vc.get("issuer").and_then(|i| {
        i.as_str()
            .map(str::to_string)
            .or_else(|| i.get("id").and_then(Value::as_str).map(str::to_string))
    });
    let purpose = infer_purpose(&types);
    let valid_from = vc
        .get("validFrom")
        .and_then(Value::as_str)
        .map(str::to_string);
    let valid_until = vc
        .get("validUntil")
        .and_then(Value::as_str)
        .map(str::to_string);

    let cred = StoredCredential {
        id: id.to_string(),
        format: CredentialFormat::EddsaJcs2022,
        types,
        schema_id: None,
        community_did: None,
        context_id: None,
        subject_did,
        issuer_did,
        purpose,
        status: CredentialStatus::Valid,
        valid_from,
        valid_until,
        received_at: now.to_rfc3339(),
        source,
        tags: std::collections::BTreeMap::new(),
        body: vc_json.to_vec(),
        lifecycle: vti_common::vault::VaultStatus::Active,
        archived_at: None,
        deleted_at: None,
        grace_until: None,
    };

    storage::put(vault, &cred).await?;
    Ok(cred)
}

/// Format-dispatching receive — the vault's single entry point for storing an
/// incoming credential of any format (spec D4).
///
/// `SdJwtVc` resolves its issuer `did:key` internally; the Data-Integrity
/// formats take a caller-resolved `issuer_pub` (the wire layer resolves the
/// issuer DID). `Bbs2023` is audit-gated and `Zkp` is Phase-0-gated; `Other`
/// is rejected.
pub async fn receive(
    vault: &KeyspaceHandle,
    id: &str,
    format: &CredentialFormat,
    body: &[u8],
    issuer_pub: Option<&[u8]>,
    source: Provenance,
    now: DateTime<Utc>,
) -> Result<StoredCredential, AppError> {
    match format {
        CredentialFormat::SdJwtVc => {
            let compact = std::str::from_utf8(body).map_err(|e| {
                AppError::Validation(format!("SD-JWT-VC body is not valid UTF-8: {e}"))
            })?;
            receive_sd_jwt_vc(vault, id, compact, source, now.timestamp().max(0) as u64).await
        }
        CredentialFormat::EddsaJcs2022 => {
            let pubkey = issuer_pub.ok_or_else(|| {
                AppError::Validation(
                    "a Data-Integrity credential needs a caller-resolved issuer key".to_string(),
                )
            })?;
            receive_di_vc(vault, id, body, pubkey, source, now).await
        }
        CredentialFormat::Bbs2023 => {
            #[cfg(feature = "bbs")]
            {
                let pubkey = issuer_pub.ok_or_else(|| {
                    AppError::Validation(
                        "a BBS (bbs-2023) credential needs a caller-resolved 96-byte G2 issuer key"
                            .to_string(),
                    )
                })?;
                super::bbs::receive_bbs(vault, id, body, pubkey, source, now).await
            }
            #[cfg(not(feature = "bbs"))]
            Err(AppError::Validation(
                "BBS+ receive requires the `bbs` feature (audit-gated, Phase 0b)".to_string(),
            ))
        }
        CredentialFormat::Zkp => Err(AppError::Validation(
            "ZKP receive is Phase-0-gated and not yet supported (commitment primitives \
             + Circom/Groth16 verifier not yet wired)"
                .to_string(),
        )),
        CredentialFormat::Other(tag) => Err(AppError::Validation(format!(
            "unsupported credential format `{tag}`"
        ))),
    }
}

/// True iff `now` lies within a W3C VC 2.0 `validFrom`/`validUntil` window.
/// Either bound may be absent; a malformed RFC-3339 bound is a hard error
/// (default-deny — never store a credential whose window can't be evaluated).
pub(super) fn di_temporal_valid(vc: &Value, now: DateTime<Utc>) -> Result<(), AppError> {
    if let Some(from) = vc.get("validFrom").and_then(Value::as_str) {
        let from = from.parse::<DateTime<Utc>>().map_err(|e| {
            AppError::Validation(format!("`validFrom` ({from}) is not RFC-3339: {e}"))
        })?;
        if now < from {
            return Err(AppError::Validation(
                "credential is not yet valid (`validFrom` is in the future)".to_string(),
            ));
        }
    }
    if let Some(until) = vc.get("validUntil").and_then(Value::as_str) {
        let until = until.parse::<DateTime<Utc>>().map_err(|e| {
            AppError::Validation(format!("`validUntil` ({until}) is not RFC-3339: {e}"))
        })?;
        if now >= until {
            return Err(AppError::Validation(
                "credential has expired (`validUntil` is in the past)".to_string(),
            ));
        }
    }
    Ok(())
}

/// Extract VC `type` tags from the verified claims.
///
/// SD-JWT-VC's primary type identifier is the `vct` claim (always present in
/// the protected payload). We index that, and additionally fold in any
/// JSON-LD-style `type` / `vc.type` arrays a richer credential carries, so a
/// match on either the SD-JWT-VC `vct` or a classic VC `type` tag finds the
/// credential. Duplicates are de-duplicated; order is preserved.
pub(super) fn extract_types(claims: &Value) -> Vec<String> {
    let mut types: Vec<String> = Vec::new();
    let mut push_unique = |s: String| {
        if !s.is_empty() && !types.contains(&s) {
            types.push(s);
        }
    };

    if let Some(vct) = claims.get("vct").and_then(Value::as_str) {
        push_unique(vct.to_string());
    }
    collect_type_field(claims.get("type"), &mut push_unique);
    if let Some(vc) = claims.get("vc") {
        collect_type_field(vc.get("type"), &mut push_unique);
    }

    types
}

/// Fold a `type` field — which may be a string or an array of strings — into
/// the type set via `push`.
fn collect_type_field(field: Option<&Value>, push: &mut impl FnMut(String)) {
    match field {
        Some(Value::String(s)) => push(s.clone()),
        Some(Value::Array(arr)) => {
            for v in arr {
                if let Some(s) = v.as_str() {
                    push(s.to_string());
                }
            }
        }
        _ => {}
    }
}

/// Infer the credential [`CredentialPurpose`] from its type tags.
///
/// A best-effort mapping from the catalog type names (spec §3) onto the
/// indexed purpose taxonomy, so a received credential is findable by purpose
/// without the caller having to classify it. Matching is case-insensitive and
/// substring-based against the known catalog families; an unrecognised type
/// leaves `purpose` unset (rather than guessing wrong).
pub(super) fn infer_purpose(types: &[String]) -> Option<CredentialPurpose> {
    for t in types {
        let lower = t.to_ascii_lowercase();
        if lower.contains("invitation") || lower.contains("invite") {
            return Some(CredentialPurpose::Invite);
        }
        if lower.contains("membership") {
            return Some(CredentialPurpose::Membership);
        }
        if lower.contains("role") {
            return Some(CredentialPurpose::Role);
        }
        if lower.contains("endorsement") {
            return Some(CredentialPurpose::Endorsement);
        }
        if lower.contains("personhood") {
            return Some(CredentialPurpose::Personhood);
        }
    }
    None
}

/// Convert a Unix-seconds numeric claim into an RFC-3339 timestamp string for
/// the envelope's `valid_from` / `valid_until` fields. Returns `None` if the
/// claim is absent or not a representable timestamp.
fn unix_claim_to_rfc3339(claims: &Value, key: &str) -> Option<String> {
    let secs = claims.get(key).and_then(Value::as_i64)?;
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0).map(|dt| dt.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_sd_jwt::hasher::Sha256Hasher;
    use affinidi_sd_jwt::signer::JwtSigner;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    /// A production-shape EdDSA (Ed25519) JWT signer for the tests. Mirrors
    /// the SDK smoke test's issuer: signs the compact signing input and emits
    /// the full compact JWS.
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
        fn sign_jwt(
            &self,
            header: &Value,
            payload: &Value,
        ) -> Result<String, affinidi_sd_jwt::error::SdJwtError> {
            use affinidi_sd_jwt::error::SdJwtError;
            let header_b64 = URL_SAFE_NO_PAD.encode(
                serde_json::to_string(header)
                    .map_err(|e| SdJwtError::Verification(e.to_string()))?
                    .as_bytes(),
            );
            let payload_b64 = URL_SAFE_NO_PAD.encode(
                serde_json::to_string(payload)
                    .map_err(|e| SdJwtError::Verification(e.to_string()))?
                    .as_bytes(),
            );
            let signing_input = format!("{header_b64}.{payload_b64}");
            let sig: Signature = self.key.sign(signing_input.as_bytes());
            let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
            Ok(format!("{signing_input}.{sig_b64}"))
        }
    }

    /// A fresh tempdir-backed `vault` keyspace handle.
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

    /// An issuer whose DID is the *real* `did:key` for its Ed25519 key, so the
    /// receive path's `iss` → key resolution resolves to the verifying key.
    fn issuer() -> (EddsaSigner, String) {
        let secret = [9u8; 32];
        let signing = SigningKey::from_bytes(&secret);
        let did =
            affinidi_crypto::did_key::ed25519_pub_to_did_key(signing.verifying_key().as_bytes());
        let kid = format!("{did}#key-0");
        (EddsaSigner { key: signing, kid }, did)
    }

    /// Issue a membership-shaped SD-JWT-VC from `issuer_did` whose `iat`/`exp`
    /// bracket `iat..exp`. Returns the compact serialization.
    fn issue_membership(
        signer: &EddsaSigner,
        issuer_did: &str,
        iat: u64,
        exp: Option<u64>,
    ) -> String {
        let hasher = Sha256Hasher;
        let claims = json!({
            "community": "did:web:community.example",
            "tier": "founding",
        });
        let frame = json!({ "_sd": ["community", "tier"] });
        let vc = affinidi_sd_jwt_vc::issue(
            "https://openvtc.org/credentials/MembershipCredential",
            issuer_did,
            Some("did:example:alice"),
            &claims,
            &frame,
            signer,
            &hasher,
            None,
            iat,
            exp,
        )
        .expect("issue SD-JWT-VC");
        vc.serialize()
    }

    #[tokio::test]
    async fn valid_sd_jwt_vc_is_stored_and_indexed() {
        let (_dir, _store, vault) = fresh_vault();
        let (signer, did) = issuer();
        // valid_from = 1_700_000_000, valid_until = 1_900_000_000.
        let compact = issue_membership(&signer, &did, 1_700_000_000, Some(1_900_000_000));

        let stored = receive_sd_jwt_vc(
            &vault,
            "cred-1",
            &compact,
            Some("exchange:thread-7".into()),
            1_800_000_000,
        )
        .await
        .expect("valid credential is received");

        // Envelope mapping.
        assert_eq!(stored.id, "cred-1");
        assert_eq!(stored.format, CredentialFormat::SdJwtVc);
        assert!(
            stored
                .types
                .contains(&"https://openvtc.org/credentials/MembershipCredential".to_string())
        );
        assert_eq!(stored.issuer_did.as_deref(), Some(did.as_str()));
        assert_eq!(stored.subject_did.as_deref(), Some("did:example:alice"));
        assert_eq!(stored.purpose, Some(CredentialPurpose::Membership));
        assert_eq!(stored.status, CredentialStatus::Valid);
        assert_eq!(stored.source.as_deref(), Some("exchange:thread-7"));
        assert!(stored.valid_until.is_some());
        // Body is the verbatim compact serialization.
        assert_eq!(stored.body, compact.as_bytes());

        // Findable by type via the 1.1 index.
        let by_type = storage::find_by_index(
            &vault,
            crate::vault::IndexField::Type,
            "https://openvtc.org/credentials/MembershipCredential",
        )
        .await
        .unwrap();
        assert_eq!(by_type.len(), 1);
        assert_eq!(by_type[0].id, "cred-1");

        // Findable by issuer via the 1.1 index.
        let by_issuer = storage::find_by_index(&vault, crate::vault::IndexField::IssuerDid, &did)
            .await
            .unwrap();
        assert_eq!(by_issuer.len(), 1);
        assert_eq!(by_issuer[0].id, "cred-1");
    }

    #[tokio::test]
    async fn tampered_signature_is_rejected_and_not_stored() {
        let (_dir, _store, vault) = fresh_vault();
        let (signer, did) = issuer();
        let compact = issue_membership(&signer, &did, 1_700_000_000, Some(1_900_000_000));

        // Flip a byte inside the issuer JWS signature segment. The compact
        // form is `<jws>~<disclosure>~...`; mutate a char in the first
        // (JWS) segment's signature so the Ed25519 check fails.
        let mut chars: Vec<char> = compact.chars().collect();
        // Find the end of the JWS (first '~') and a position just before it.
        let tilde = compact.find('~').expect("has disclosures");
        let pos = tilde - 1;
        chars[pos] = if chars[pos] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();

        let err = receive_sd_jwt_vc(&vault, "cred-bad", &tampered, None, 1_800_000_000)
            .await
            .expect_err("tampered credential must be rejected");
        assert!(matches!(err, AppError::Validation(_)));

        // Nothing was stored.
        assert!(storage::get(&vault, "cred-bad").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expired_credential_is_rejected_and_not_stored() {
        let (_dir, _store, vault) = fresh_vault();
        let (signer, did) = issuer();
        // exp is in the past relative to the `now` we pass below.
        let compact = issue_membership(&signer, &did, 1_700_000_000, Some(1_701_000_000));

        let err = receive_sd_jwt_vc(&vault, "cred-exp", &compact, None, 1_900_000_000)
            .await
            .expect_err("expired credential must be rejected");
        assert!(matches!(err, AppError::Validation(_)));

        // Nothing was stored, and no stray index row points at it.
        assert!(storage::get(&vault, "cred-exp").await.unwrap().is_none());
        assert!(
            storage::find_by_index(&vault, crate::vault::IndexField::IssuerDid, &did)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn credential_signed_by_a_different_key_than_iss_is_rejected() {
        // An attacker signs with their own key but sets `iss` to a victim's
        // did:key. Resolution picks the victim's key, the signature fails to
        // verify, and the credential is rejected — proving the signature is
        // checked against the *named* issuer, not whoever actually signed.
        let (_dir, _store, vault) = fresh_vault();
        let attacker_secret = [1u8; 32];
        let attacker = SigningKey::from_bytes(&attacker_secret);
        let attacker_signer = EddsaSigner {
            key: attacker,
            kid: "did:key:attacker#key-0".to_string(),
        };
        // The victim's did:key (a different key than the attacker's).
        let victim_secret = [2u8; 32];
        let victim_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(
            SigningKey::from_bytes(&victim_secret)
                .verifying_key()
                .as_bytes(),
        );

        let compact = issue_membership(
            &attacker_signer,
            &victim_did,
            1_700_000_000,
            Some(1_900_000_000),
        );

        let err = receive_sd_jwt_vc(&vault, "cred-forged", &compact, None, 1_800_000_000)
            .await
            .expect_err("issuer-impersonation must be rejected");
        assert!(matches!(err, AppError::Validation(_)));
        assert!(storage::get(&vault, "cred-forged").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn missing_iss_is_rejected() {
        // An SD-JWT (not VC-profiled) with no `iss` must fail closed: the
        // receive path can't resolve an issuer key, so it can't verify.
        let (_dir, _store, vault) = fresh_vault();
        let hasher = Sha256Hasher;
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        let signer = EddsaSigner {
            key: signing,
            kid: "k".into(),
        };
        // Issue a raw SD-JWT with no `iss` claim.
        let claims = json!({ "iat": 1_700_000_000, "foo": "bar" });
        let frame = json!({ "_sd": ["foo"] });
        let sd_jwt =
            affinidi_sd_jwt::issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let compact = sd_jwt.serialize();

        let err = receive_sd_jwt_vc(&vault, "cred-noiss", &compact, None, 1_800_000_000)
            .await
            .expect_err("missing iss must be rejected");
        assert!(matches!(err, AppError::Validation(_)));
        assert!(storage::get(&vault, "cred-noiss").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn empty_id_is_rejected() {
        let (_dir, _store, vault) = fresh_vault();
        let (signer, did) = issuer();
        let compact = issue_membership(&signer, &did, 1_700_000_000, Some(1_900_000_000));
        let err = receive_sd_jwt_vc(&vault, "  ", &compact, None, 1_800_000_000)
            .await
            .expect_err("empty id must be rejected");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn infer_purpose_maps_catalog_types() {
        assert_eq!(
            infer_purpose(&["InvitationCredential".into()]),
            Some(CredentialPurpose::Invite)
        );
        assert_eq!(
            infer_purpose(&["https://x/MembershipCredential".into()]),
            Some(CredentialPurpose::Membership)
        );
        assert_eq!(
            infer_purpose(&["RoleCredential".into()]),
            Some(CredentialPurpose::Role)
        );
        assert_eq!(infer_purpose(&["UnknownThing".into()]), None);
    }

    #[test]
    fn extract_types_folds_vct_and_type_arrays() {
        let claims = json!({
            "vct": "https://x/MembershipCredential",
            "type": ["VerifiableCredential", "MembershipCredential"],
        });
        let types = extract_types(&claims);
        assert!(types.contains(&"https://x/MembershipCredential".to_string()));
        assert!(types.contains(&"VerifiableCredential".to_string()));
        assert!(types.contains(&"MembershipCredential".to_string()));
        // No duplicates.
        let mut sorted = types.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), types.len());
    }

    // ---- Data-Integrity (eddsa-jcs-2022) receive ------------------------

    use affinidi_data_integrity::{
        DataIntegrityProof as DiProof, SignOptions, crypto_suites::CryptoSuite as Suite,
    };
    use affinidi_secrets_resolver::secrets::Secret;

    /// Build + sign a W3C-DI VC (eddsa-jcs-2022); returns `(vc_bytes,
    /// issuer_public_key_bytes)`.
    async fn signed_di_vc(seed: u8, valid_until: Option<&str>) -> (Vec<u8>, Vec<u8>) {
        let secret =
            Secret::generate_ed25519(Some("did:web:issuer.example#key-0"), Some(&[seed; 32]));
        let mut vc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": "did:web:issuer.example",
            "validFrom": "2020-01-01T00:00:00Z",
            "credentialSubject": { "id": "did:key:zMember", "givenName": "Alice" }
        });
        if let Some(u) = valid_until {
            vc["validUntil"] = json!(u);
        }
        let proof = DiProof::sign(
            &vc,
            &secret,
            SignOptions::new()
                .with_proof_purpose("assertionMethod")
                .with_cryptosuite(Suite::EddsaJcs2022),
        )
        .await
        .expect("sign DI VC");
        vc["proof"] = serde_json::to_value(&proof).unwrap();
        (
            serde_json::to_vec(&vc).unwrap(),
            secret.get_public_bytes().to_vec(),
        )
    }

    #[tokio::test]
    async fn di_vc_verifies_and_stores() {
        let (_dir, _store, vault) = fresh_vault();
        let (vc, issuer_pub) = signed_di_vc(9, Some("2100-01-01T00:00:00Z")).await;
        let cred = receive_di_vc(&vault, "c1", &vc, &issuer_pub, None, Utc::now())
            .await
            .expect("receive DI VC");
        assert_eq!(cred.format, CredentialFormat::EddsaJcs2022);
        assert_eq!(cred.subject_did.as_deref(), Some("did:key:zMember"));
        assert_eq!(cred.issuer_did.as_deref(), Some("did:web:issuer.example"));
        assert!(cred.types.contains(&"MembershipCredential".to_string()));
        assert!(
            crate::vault::storage::get(&vault, "c1")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn di_vc_tampered_is_rejected_and_not_stored() {
        let (_dir, _store, vault) = fresh_vault();
        let (vc, issuer_pub) = signed_di_vc(9, None).await;
        let mut v: Value = serde_json::from_slice(&vc).unwrap();
        v["credentialSubject"]["givenName"] = json!("Mallory"); // tamper after signing
        let tampered = serde_json::to_vec(&v).unwrap();
        let err = receive_di_vc(&vault, "c1", &tampered, &issuer_pub, None, Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        assert!(
            crate::vault::storage::get(&vault, "c1")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn di_vc_expired_is_rejected() {
        let (_dir, _store, vault) = fresh_vault();
        let (vc, issuer_pub) = signed_di_vc(9, Some("2001-01-01T00:00:00Z")).await;
        let err = receive_di_vc(&vault, "c1", &vc, &issuer_pub, None, Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }

    #[tokio::test]
    async fn dispatch_routes_di_requires_key_and_gates_bbs() {
        let (_dir, _store, vault) = fresh_vault();
        let (vc, issuer_pub) = signed_di_vc(9, None).await;
        // DI without a resolved issuer key → rejected.
        assert!(
            receive(
                &vault,
                "c1",
                &CredentialFormat::EddsaJcs2022,
                &vc,
                None,
                None,
                Utc::now()
            )
            .await
            .is_err()
        );
        // With the key → routed to receive_di_vc + stored.
        let cred = receive(
            &vault,
            "c1",
            &CredentialFormat::EddsaJcs2022,
            &vc,
            Some(&issuer_pub),
            None,
            Utc::now(),
        )
        .await
        .expect("dispatch DI");
        assert_eq!(cred.format, CredentialFormat::EddsaJcs2022);
        // BBS+ is audit-gated.
        assert!(
            receive(
                &vault,
                "c2",
                &CredentialFormat::Bbs2023,
                &vc,
                Some(&issuer_pub),
                None,
                Utc::now()
            )
            .await
            .is_err()
        );
        // ZKP is Phase-0-gated.
        let zkp_err = receive(
            &vault,
            "c3",
            &CredentialFormat::Zkp,
            &vc,
            Some(&issuer_pub),
            None,
            Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&zkp_err, AppError::Validation(m) if m.contains("ZKP")),
            "{zkp_err:?}"
        );
    }

    #[test]
    fn zkp_format_tag_round_trips_as_kebab_case() {
        // The additive variant must serialise to a stable wire tag so stored
        // credentials and DCQL `format` selectors agree on it.
        let json = serde_json::to_string(&CredentialFormat::Zkp).unwrap();
        assert_eq!(json, "\"zkp\"");
        let back: CredentialFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(back, CredentialFormat::Zkp);
    }
}
