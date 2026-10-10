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
//!    key the credential's own `iss` names — a `did:key`, or the `kid`
//!    verification method of a `did:web` / `did:webvh` issuer, resolved for
//!    `assertionMethod` by the caller's resolver. EdDSA, ES256 (P-256) and
//!    ES256K (secp256k1) are accepted, the algorithm fixed by the resolved key
//!    (`vta_sdk::jws`, #1988). A tampered signature never produces verified
//!    claims, so a forged credential cannot reach the store.
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
//!   credential, an `iss` whose key does not resolve, a `kid` that is not a
//!   method of `iss`, or a missing `iss` all fail closed.
//!
//! ## What this module does NOT do
//! It pulls in **no BBS** (`affinidi-bbs` is audit-gated; BBS receive is a
//! later task) and adds **no route / DIDComm handler** — the credential vault
//! exposes no wire surface yet, so receive is a library operation only.

use affinidi_sd_jwt::SdJwt;
use affinidi_sd_jwt::hasher::Sha256Hasher;
use affinidi_sd_jwt::signer::JwtVerifier;
use affinidi_sd_jwt::verifier::{VerificationOptions, verify};
use chrono::{DateTime, Utc};
use serde_json::Value;
use vta_sdk::jws::{JwsKey, sd_jwt_issuer_method};
use vta_sdk::trust_task_proof::{ProofPurpose, PurposeVmResolver, TrustTaskVmResolver};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::model::{CredentialFormat, CredentialPurpose, CredentialStatus, StoredCredential};
use super::storage;

/// A `JwtVerifier` bound to a single resolved issuer key — Ed25519, P-256 or
/// secp256k1.
///
/// The key is resolved from the credential's own `iss` before this verifier is
/// built, so verification proves the JWS was signed by a key the credential's
/// issuer controls. The header's `alg` must be the one that key signs with
/// ([`JwsKey::verify_compact`]); a wrong `alg`, a malformed JWS or a bad
/// signature all return an error, so `verify` produces no claims.
struct IssuerJwsVerifier {
    key: JwsKey,
}

impl JwtVerifier for IssuerJwsVerifier {
    fn verify_jwt(&self, jws: &str) -> Result<Value, affinidi_sd_jwt::error::SdJwtError> {
        self.key
            .verify_compact(jws)
            .map_err(|e| affinidi_sd_jwt::error::SdJwtError::Verification(e.to_string()))
    }
}

/// Verify an SD-JWT-VC's issuer signature against the key its `iss` names, and
/// return `(iss, claims)` — the claims reconstructed with every disclosure the
/// token carries, read only from the verified result.
///
/// The verification method is the `kid` under `iss` (or a `did:key`'s own key;
/// [`sd_jwt_issuer_method`]), resolved through `resolver` for
/// `assertionMethod`: a key the issuer has not authorised to issue does not
/// verify its credentials. The unverified payload is read only to learn which
/// issuer to resolve.
async fn verify_sd_jwt_issuer(
    sd_jwt: &SdJwt,
    resolver: &(dyn PurposeVmResolver + '_),
) -> Result<(String, Value), AppError> {
    let payload = sd_jwt
        .payload()
        .map_err(|e| AppError::Validation(format!("unreadable SD-JWT-VC payload: {e}")))?;
    let issuer_did = payload
        .get("iss")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("SD-JWT-VC is missing the `iss` claim".to_string()))?
        .to_string();
    let header = sd_jwt
        .header()
        .map_err(|e| AppError::Validation(format!("unreadable SD-JWT-VC header: {e}")))?;
    let method = sd_jwt_issuer_method(&header, &issuer_did)
        .map_err(|e| AppError::Validation(format!("SD-JWT-VC issuer: {e}")))?;

    let resolved = resolver
        .resolve_vm_for_purpose(&method, ProofPurpose::AssertionMethod)
        .await
        .map_err(|e| {
            AppError::Validation(format!(
                "issuer `iss` ({issuer_did}) key did not resolve: {e}"
            ))
        })?;
    let key = JwsKey::from_resolved(&resolved)
        .map_err(|e| AppError::Validation(format!("issuer key cannot verify a JWS: {e}")))?;

    // No holder-binding verifier: holder binding is a *presentation*-time
    // concern (spec §14.4), not a receive-time one.
    let hasher = Sha256Hasher;
    let result = verify(
        sd_jwt,
        &IssuerJwsVerifier { key },
        &hasher,
        &VerificationOptions::default(),
        None,
    )
    .map_err(|e| AppError::Validation(format!("issuer signature verification failed: {e}")))?;
    if !result.is_verified() {
        return Err(AppError::Validation(
            "SD-JWT-VC verification did not succeed".to_string(),
        ));
    }
    Ok((issuer_did, result.claims))
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
/// (the vault primary key — a ULID is recommended). `resolver` resolves the
/// issuer's key — the caller supplies it, so the vault stays network-free: a
/// `TrustTaskVmResolver` over the agent's DID cache reaches `did:web` /
/// `did:webvh` issuers, `TrustTaskVmResolver::did_key_only()` reaches
/// `did:key` alone. `source` is optional provenance. `now_unix` is the current time in Unix seconds, injected for
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
/// - the payload has no `iss`, its `kid` is not a method of `iss`, or the
///   issuer key does not resolve for `assertionMethod` → [`AppError::Validation`].
/// - the issuer signature does not verify → [`AppError::Validation`].
/// - the credential is expired / not-yet-valid / has no `iat`
///   → [`AppError::Validation`].
///
/// No write to the store happens on any of these paths.
pub async fn receive_sd_jwt_vc(
    vault: &KeyspaceHandle,
    id: &str,
    compact: &str,
    resolver: &(dyn PurposeVmResolver + '_),
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

    // Verify the issuer signature. A tampered JWS produces `Err` here, so
    // forged credentials never reach the store. The returned `claims` are the
    // only trusted view.
    let (issuer_did, claims) = verify_sd_jwt_issuer(&sd_jwt, resolver).await?;
    let claims = &claims;

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

    // "Valid" means *passed signature + temporal* only; revocation state is
    // resolved by the status task (1.6). The exception is an IETF Token Status
    // List reference (`status.status_list`): nothing here reads a
    // `statuslist+jwt` yet (#1988 follow-up), so a refresh can never settle it,
    // and its state is Unknown rather than an assumed Valid (VTI-CRD-012).
    let status = if claims
        .get("status")
        .and_then(|s| s.get("status_list"))
        .is_some()
    {
        CredentialStatus::Unknown
    } else {
        CredentialStatus::Valid
    };

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
        issuer_did: Some(issuer_did),
        purpose,
        status,
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

/// The claims a stored credential carries, as one JSON document — what a
/// `claimPath` (RFC 6901) is read against.
///
/// - **SD-JWT-VC**: re-verified against its issuer and reconstructed with
///   every disclosure the holder holds, exactly as [`receive_sd_jwt_vc`] reads
///   it on arrival. The stored body is what was verified then; re-verifying is
///   what makes this the only way the claims are read.
/// - **Data-Integrity VC**: the document itself, verified on arrival.
/// - **mdoc**: not readable by path here, and refused rather than guessed.
///
/// `resolver` resolves an SD-JWT-VC's issuer key, as on receive.
///
/// Fails closed: a body that does not parse, or a signature that no longer
/// verifies, is an error, never an empty document.
pub async fn stored_claims(
    cred: &StoredCredential,
    resolver: &(dyn PurposeVmResolver + '_),
) -> Result<Value, AppError> {
    match &cred.format {
        CredentialFormat::SdJwtVc => {
            let hasher = Sha256Hasher;
            let compact = std::str::from_utf8(&cred.body)
                .map_err(|e| AppError::Validation(format!("SD-JWT-VC body is not UTF-8: {e}")))?;
            let sd_jwt = SdJwt::parse(compact, &hasher)
                .map_err(|e| AppError::Validation(format!("malformed SD-JWT-VC: {e}")))?;
            let (_, claims) = verify_sd_jwt_issuer(&sd_jwt, resolver).await.map_err(|e| {
                AppError::Validation(format!("issuer signature no longer verifies: {e}"))
            })?;
            Ok(claims)
        }
        CredentialFormat::EddsaJcs2022 | CredentialFormat::Bbs2023 => {
            serde_json::from_slice(&cred.body).map_err(|e| {
                AppError::Validation(format!("Data-Integrity VC body is not JSON: {e}"))
            })
        }
        other => Err(AppError::Validation(format!(
            "claims of a {other:?} credential cannot be read by path"
        ))),
    }
}

/// Receive a **W3C Data-Integrity VC** (`eddsa-jcs-2022`, optionally beside
/// further proofs such as `mldsa44-jcs-2024`) into the vault: verify the issuer
/// proof set + temporal validity, map, and store (spec D4 — the format-agnostic
/// bridge; the W3C-DI sibling of [`receive_sd_jwt_vc`]).
///
/// `vc_json` is the credential as the holder received it (a W3C VC 2.0 JSON
/// document with a `proof` — one proof object, or the proof set a multi-key
/// issuer emits, VTI-44). `resolver` resolves each proof's
/// `verificationMethod` for `assertionMethod` — **the caller supplies it** (the
/// vault stays network-free, mirroring the injected-signer pattern in
/// [`super::present`]; the wire layer passes a `TrustTaskVmResolver` over its
/// DID cache, a test a fixed key). `now` anchors the temporal check. See
/// [`super::di_verify::verify_di_issuer_proofs`] for the proof-set rule.
///
/// ## Failure modes (all reject **without** storing)
/// - `id` empty, or `vc_json` not a JSON object → [`AppError::Validation`];
/// - no `issuer` or `proof`, a malformed proof, a `bbs-2023` proof (BBS+ is
///   audit-gated and routed elsewhere), or no proof in a suite this build
///   implements → [`AppError::Validation`];
/// - a proof's key is not under the credential `issuer` → [`AppError::Validation`];
/// - any checkable proof does not verify → [`AppError::Validation`];
/// - `now` is outside `validFrom`/`validUntil` → [`AppError::Validation`].
pub async fn receive_di_vc(
    vault: &KeyspaceHandle,
    id: &str,
    vc_json: &[u8],
    resolver: &(dyn PurposeVmResolver + '_),
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

    if !vc.is_object() {
        return Err(AppError::Validation(
            "Data-Integrity VC is not a JSON object".to_string(),
        ));
    }

    // Verify the issuer proof — or proof set (VTI-44) — bound to the credential
    // `issuer`, over the received document with `proof` removed. A tampered
    // credential fails here, before any trust is placed in the bytes.
    super::di_verify::verify_di_issuer_proofs(resolver, &vc).await?;

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

/// Receive an ISO/IEC 18013-5 **mdoc** into the vault: verify, map, and store.
///
/// `body` is the CBOR `IssuerSigned` wire form. `issuer_pub` is the **caller-
/// resolved** Document Signer public key (SEC1, P-256) — caller-supplied like
/// [`receive_di_vc`]'s issuer resolver, and for the same reason: resolving
/// *which* key to trust is a policy decision that belongs to the wire layer,
/// not to the verifier.
///
/// That seam matters more here than for DI. **mdoc anchors issuer trust in an
/// X.509 chain** (`x5chain`, COSE header label 33, rooted in an IACA), while
/// this stack is DID-rooted end to end. Taking a resolved key here keeps that
/// unresolved question — configured trust-anchor set, trust-registry mapping,
/// or `did:x509` — out of the storage layer instead of quietly settling it.
///
/// Verifies three things, rejecting-without-storing on any failure, per
/// ISO 18013-5 §9.3.1:
/// 1. **`issuerAuth`** — the COSE_Sign1 over the MSO, against `issuer_pub`.
/// 2. **Digests** — every disclosed item against the MSO's `valueDigests`. A
///    valid signature over an MSO whose digests do not match the items is a
///    tampered credential.
/// 3. **`validityInfo`** — `now` inside `[validFrom, validUntil]`.
///
/// `device_key_id` names the VTA key whose public half is the MSO's
/// `deviceKey` — the caller resolves it, because matching a COSE_Key against
/// the VTA's own keyspace is above this layer. It is recorded on the stored
/// envelope so presentation can find the key that must sign `DeviceAuth`.
/// Refusing an mdoc whose device key the VTA does not hold is the point: such a
/// credential could be stored but never presented with holder binding, and the
/// failure would otherwise surface much later, at presentation, with nothing
/// pointing at the cause.
///
/// ES256 only. ISO 18013-5 and the EUDI profiles mandate it, and it is what the
/// VTA already has via [`vta_sdk::keys::KeyType::P256`], so no new curve enters
/// the graph. A credential signed with any other algorithm is refused by name
/// rather than silently mis-verified.
pub async fn receive_mdoc(
    vault: &KeyspaceHandle,
    id: &str,
    body: &[u8],
    issuer_pub: &[u8],
    device_key_id: &str,
    source: Provenance,
    now: DateTime<Utc>,
) -> Result<StoredCredential, AppError> {
    if id.trim().is_empty() {
        return Err(AppError::Validation(
            "credential id must be non-empty".to_string(),
        ));
    }

    // Parse. This is structure only — nothing is trusted yet.
    let issued = affinidi_mdoc::IssuerSigned::from_cbor_bytes(body)
        .map_err(|e| AppError::Validation(format!("mdoc body is not a valid IssuerSigned: {e}")))?;

    // Refuse an unexpected algorithm before touching the signature, mirroring
    // the SD-JWT path's `alg` check.
    let alg = issued.issuer_auth.protected.header.alg.clone();
    let expected = coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::ES256);
    if alg.as_ref() != Some(&expected) {
        return Err(AppError::Validation(format!(
            "mdoc issuerAuth must be ES256 (ISO 18013-5 / EUDI); got {alg:?}"
        )));
    }

    // 1. issuerAuth signature, against the caller-resolved Document Signer key.
    let verifier = affinidi_mdoc::es256_cose::Es256CoseVerifier::from_bytes(issuer_pub)
        .map_err(|e| AppError::Validation(format!("invalid mdoc issuer key: {e}")))?;
    let mso = issued
        .verify_issuer_auth(&verifier)
        .map_err(|e| AppError::Validation(format!("mdoc issuerAuth did not verify: {e}")))?;

    // 2. Digests. A good signature over an MSO whose digests do not match the
    //    items means the items were swapped after signing.
    if !issued
        .verify_digests()
        .map_err(|e| AppError::Validation(format!("mdoc digest check failed: {e}")))?
    {
        return Err(AppError::Validation(
            "mdoc item digests do not match the signed MSO".to_string(),
        ));
    }

    // 3. Temporal validity.
    let now_odt = time::OffsetDateTime::from_unix_timestamp(now.timestamp())
        .map_err(|e| AppError::Internal(format!("clock conversion: {e}")))?;
    mso.validity_info
        .check(now_odt)
        .map_err(|e| AppError::Validation(format!("mdoc is not currently valid: {e}")))?;

    // Map. `docType` is the credential's type — taken from the *signed* MSO,
    // never from the outer map (the codec guarantees this).
    let cred = StoredCredential {
        id: id.to_string(),
        format: CredentialFormat::MsoMdoc,
        types: vec![mso.doc_type.clone()],
        schema_id: None,
        community_did: None,
        context_id: None,
        // An mdoc binds to the holder through the MSO's `deviceKey`, not a
        // subject DID, and carries no issuer DID — its issuer identity is the
        // X.509 chain. Leaving both `None` is truthful; inventing a DID here
        // would put an unverifiable identifier into a secondary index.
        subject_did: None,
        issuer_did: None,
        purpose: Some(CredentialPurpose::Other(mso.doc_type.clone())),
        status: CredentialStatus::Valid,
        valid_from: Some(mso.validity_info.valid_from.clone()),
        valid_until: Some(mso.validity_info.valid_until.clone()),
        received_at: now.to_rfc3339(),
        source,
        // The holder-binding key, recorded now because nothing else in the
        // stored envelope says which VTA key can speak for this credential.
        tags: std::collections::BTreeMap::from([(
            super::model::MDOC_DEVICE_KEY_TAG.to_string(),
            device_key_id.to_string(),
        )]),
        body: body.to_vec(),
        lifecycle: vti_common::vault::VaultStatus::Active,
        archived_at: None,
        deleted_at: None,
        grace_until: None,
    };

    storage::put(vault, &cred).await?;
    Ok(cred)
}

/// How [`receive`] verifies the issuer of an incoming credential — the one
/// input that differs by format.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum IssuerKey<'a> {
    /// No caller-supplied key: the format resolves its own issuer locally (an
    /// SD-JWT-VC's `did:key` or `did:peer` `iss`, with no I/O), or none
    /// applies.
    None,
    /// Resolves each Data-Integrity proof's `verificationMethod` — one proof
    /// or a proof set (VTI-44) — for the `EddsaJcs2022` format, and an
    /// SD-JWT-VC issuer's key — a `did:web` / `did:webvh` issuer needs one.
    Resolver(&'a (dyn PurposeVmResolver + 'a)),
    /// A caller-resolved raw public key — the 96-byte G2 key for `Bbs2023`.
    PublicKey(&'a [u8]),
}

impl std::fmt::Debug for IssuerKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Resolver(_) => f.write_str("Resolver(..)"),
            Self::PublicKey(k) => write!(f, "PublicKey({} bytes)", k.len()),
        }
    }
}

/// Format-dispatching receive — the vault's single entry point for storing an
/// incoming credential of any format (spec D4).
///
/// `SdJwtVc` resolves its issuer through a caller-supplied
/// [`IssuerKey::Resolver`], or locally (`did:key` / `did:peer` only) under
/// [`IssuerKey::None`]; `EddsaJcs2022` takes a
/// caller-supplied [`IssuerKey::Resolver`] (the wire layer resolves the issuer
/// DID); `Bbs2023` takes a caller-resolved [`IssuerKey::PublicKey`] and is
/// audit-gated; `Zkp` is Phase-0-gated; `Other` is rejected.
pub async fn receive(
    vault: &KeyspaceHandle,
    id: &str,
    format: &CredentialFormat,
    body: &[u8],
    issuer: IssuerKey<'_>,
    source: Provenance,
    now: DateTime<Utc>,
) -> Result<StoredCredential, AppError> {
    match format {
        CredentialFormat::SdJwtVc => {
            let compact = std::str::from_utf8(body).map_err(|e| {
                AppError::Validation(format!("SD-JWT-VC body is not valid UTF-8: {e}"))
            })?;
            let now_unix = now.timestamp().max(0) as u64;
            match issuer {
                IssuerKey::Resolver(resolver) => {
                    receive_sd_jwt_vc(vault, id, compact, resolver, source, now_unix).await
                }
                IssuerKey::None => {
                    let local = TrustTaskVmResolver::did_key_only();
                    receive_sd_jwt_vc(vault, id, compact, &local, source, now_unix).await
                }
                IssuerKey::PublicKey(_) => Err(AppError::Validation(
                    "an SD-JWT-VC issuer is resolved from its `iss`, not supplied as a raw key"
                        .to_string(),
                )),
            }
        }
        CredentialFormat::EddsaJcs2022 => {
            let IssuerKey::Resolver(resolver) = issuer else {
                return Err(AppError::Validation(
                    "a Data-Integrity credential needs a caller-supplied issuer resolver"
                        .to_string(),
                ));
            };
            receive_di_vc(vault, id, body, resolver, source, now).await
        }
        CredentialFormat::Bbs2023 => {
            #[cfg(feature = "bbs")]
            {
                let IssuerKey::PublicKey(pubkey) = issuer else {
                    return Err(AppError::Validation(
                        "a BBS (bbs-2023) credential needs a caller-resolved 96-byte G2 issuer key"
                            .to_string(),
                    ));
                };
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
        // Not reachable through this entry point: an mdoc needs a
        // caller-resolved Document Signer key *and* the VTA key id holding its
        // MSO deviceKey. This signature can carry the first but not the second,
        // and guessing the binding is exactly what must not happen.
        CredentialFormat::MsoMdoc => Err(AppError::Validation(
            "receive an mdoc through `receive_mdoc`, which takes the device-key binding \
             this format-agnostic entry point cannot supply"
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
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    /// The no-I/O resolver: every issuer in these tests is a `did:key`.
    fn local() -> TrustTaskVmResolver {
        TrustTaskVmResolver::did_key_only()
    }

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
            .keyspace(vta_keyspaces::VAULT)
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
            &local(),
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
            crate::IndexField::Type,
            "https://openvtc.org/credentials/MembershipCredential",
        )
        .await
        .unwrap();
        assert_eq!(by_type.len(), 1);
        assert_eq!(by_type[0].id, "cred-1");

        // Findable by issuer via the 1.1 index.
        let by_issuer = storage::find_by_index(&vault, crate::IndexField::IssuerDid, &did)
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

        let err = receive_sd_jwt_vc(&vault, "cred-bad", &tampered, &local(), None, 1_800_000_000)
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

        let err = receive_sd_jwt_vc(&vault, "cred-exp", &compact, &local(), None, 1_900_000_000)
            .await
            .expect_err("expired credential must be rejected");
        assert!(matches!(err, AppError::Validation(_)));

        // Nothing was stored, and no stray index row points at it.
        assert!(storage::get(&vault, "cred-exp").await.unwrap().is_none());
        assert!(
            storage::find_by_index(&vault, crate::IndexField::IssuerDid, &did)
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

        let err = receive_sd_jwt_vc(
            &vault,
            "cred-forged",
            &compact,
            &local(),
            None,
            1_800_000_000,
        )
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

        let err = receive_sd_jwt_vc(
            &vault,
            "cred-noiss",
            &compact,
            &local(),
            None,
            1_800_000_000,
        )
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
        let err = receive_sd_jwt_vc(&vault, "  ", &compact, &local(), None, 1_800_000_000)
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

    use affinidi_data_integrity::{DataIntegrityError, ResolvedKey};
    use affinidi_data_integrity::{
        DataIntegrityProof as DiProof, SignOptions, crypto_suites::CryptoSuite as Suite,
    };
    use affinidi_secrets_resolver::secrets::Secret;
    use vta_sdk::trust_task_proof::ProofPurpose;

    const DI_ISSUER: &str = "did:web:issuer.example";

    /// The issuer's DID document, without the network: resolves the listed
    /// verification methods, and only for `assertionMethod`.
    struct FixedKeys(Vec<(String, ResolvedKey)>);

    impl FixedKeys {
        fn of(secrets: &[&Secret]) -> Self {
            Self(
                secrets
                    .iter()
                    .map(|s| {
                        (
                            s.id.clone(),
                            ResolvedKey::new(s.get_key_type(), s.get_public_bytes().to_vec()),
                        )
                    })
                    .collect(),
            )
        }
    }

    #[async_trait::async_trait]
    impl PurposeVmResolver for FixedKeys {
        async fn resolve_vm_for_purpose(
            &self,
            vm: &str,
            purpose: ProofPurpose,
        ) -> Result<ResolvedKey, DataIntegrityError> {
            if purpose != ProofPurpose::AssertionMethod {
                return Err(DataIntegrityError::Resolver(format!(
                    "{vm} is not authorised for {purpose}"
                )));
            }
            self.0
                .iter()
                .find(|(id, _)| id == vm)
                .map(|(_, k)| k.clone())
                .ok_or_else(|| DataIntegrityError::Resolver(format!("unknown method {vm}")))
        }
    }

    fn di_vc_doc(valid_until: Option<&str>) -> Value {
        let mut vc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": DI_ISSUER,
            "validFrom": "2020-01-01T00:00:00Z",
            "credentialSubject": { "id": "did:key:zMember", "givenName": "Alice" }
        });
        if let Some(u) = valid_until {
            vc["validUntil"] = json!(u);
        }
        vc
    }

    /// Build + sign a W3C-DI VC (eddsa-jcs-2022, one proof object); returns
    /// `(vc_bytes, issuer_resolver)`.
    async fn signed_di_vc(seed: u8, valid_until: Option<&str>) -> (Vec<u8>, FixedKeys) {
        let secret =
            Secret::generate_ed25519(Some(&format!("{DI_ISSUER}#key-0")), Some(&[seed; 32]));
        let mut vc = di_vc_doc(valid_until);
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
        (serde_json::to_vec(&vc).unwrap(), FixedKeys::of(&[&secret]))
    }

    /// The field shape (VTI-44): a VTC with `#key-0` Ed25519 and `#key-2`
    /// ML-DSA-44 signs once per key, so `proof` is an array.
    fn hybrid_issuer_keys() -> (Secret, Secret) {
        (
            Secret::generate_ed25519(Some(&format!("{DI_ISSUER}#key-0")), Some(&[0x61; 32])),
            Secret::generate_ml_dsa_44(Some(&format!("{DI_ISSUER}#key-2")), Some(&[0x62; 32])),
        )
    }

    async fn proof_set_over(doc: &Value, secrets: &[&Secret]) -> Value {
        let signers: Vec<&dyn affinidi_data_integrity::signer::Signer> = secrets
            .iter()
            .map(|s| *s as &dyn affinidi_data_integrity::signer::Signer)
            .collect();
        let proofs = DiProof::sign_multi(
            doc,
            &signers,
            SignOptions::new().with_proof_purpose("assertionMethod"),
        )
        .await
        .expect("sign_multi");
        serde_json::to_value(&proofs).unwrap()
    }

    /// VTI-44: a two-proof (Ed25519 + ML-DSA-44) membership card is received
    /// and stored — the single-object reader refused every one in the field.
    #[tokio::test]
    async fn vti_44_a_hybrid_proof_set_credential_is_received() {
        let (_dir, _store, vault) = fresh_vault();
        let (ed, pq) = hybrid_issuer_keys();
        let mut vc = di_vc_doc(Some("2100-01-01T00:00:00Z"));
        vc["proof"] = proof_set_over(&vc, &[&ed, &pq]).await;
        assert_eq!(vc["proof"].as_array().map(Vec::len), Some(2));
        let body = serde_json::to_vec(&vc).unwrap();

        let cred = receive_di_vc(
            &vault,
            "c1",
            &body,
            &FixedKeys::of(&[&ed, &pq]),
            None,
            Utc::now(),
        )
        .await
        .expect("a hybrid proof set is received");
        assert_eq!(cred.issuer_did.as_deref(), Some(DI_ISSUER));
        assert_eq!(cred.body, body, "stored as received");
        assert!(crate::storage::get(&vault, "c1").await.unwrap().is_some());

        // The format-dispatching entry point takes the same path.
        receive(
            &vault,
            "c2",
            &CredentialFormat::EddsaJcs2022,
            &body,
            IssuerKey::Resolver(&FixedKeys::of(&[&ed, &pq])),
            None,
            Utc::now(),
        )
        .await
        .expect("dispatch a hybrid proof set");
    }

    /// VTI-44: the ML-DSA proof is verified, not ignored — tampering with it
    /// alone refuses the credential, even though the Ed25519 proof is good.
    #[tokio::test]
    async fn vti_44_one_tampered_proof_in_the_set_is_refused() {
        let (_dir, _store, vault) = fresh_vault();
        let (ed, pq) = hybrid_issuer_keys();
        let mut vc = di_vc_doc(None);
        vc["proof"] = proof_set_over(&vc, &[&ed, &pq]).await;
        let other = proof_set_over(&json!({"other": 1}), &[&ed, &pq]).await;
        vc["proof"][1]["proofValue"] = other[1]["proofValue"].clone();

        let err = receive_di_vc(
            &vault,
            "c1",
            &serde_json::to_vec(&vc).unwrap(),
            &FixedKeys::of(&[&ed, &pq]),
            None,
            Utc::now(),
        )
        .await
        .expect_err("one bad proof refuses the set");
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("1 of 2 proofs")),
            "{err:?}"
        );
        assert!(crate::storage::get(&vault, "c1").await.unwrap().is_none());
    }

    /// VTI-44 issuer binding: a genuine proof by a key under another DID,
    /// appended to the issuer's proof, is refused before anything resolves it.
    #[tokio::test]
    async fn vti_44_a_proof_by_a_key_not_under_the_issuer_is_refused() {
        let (_dir, _store, vault) = fresh_vault();
        let (ed, _) = hybrid_issuer_keys();
        let stranger =
            Secret::generate_ed25519(Some("did:web:stranger.example#key-0"), Some(&[0x63; 32]));
        let mut vc = di_vc_doc(None);
        vc["proof"] = proof_set_over(&vc, &[&ed, &stranger]).await;

        let err = receive_di_vc(
            &vault,
            "c1",
            &serde_json::to_vec(&vc).unwrap(),
            &FixedKeys::of(&[&ed, &stranger]),
            None,
            Utc::now(),
        )
        .await
        .expect_err("a key outside the issuer DID");
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("not under the credential issuer")),
            "{err:?}"
        );

        // A single proof by the stranger alone is refused the same way.
        let mut vc = di_vc_doc(None);
        vc["proof"] = proof_set_over(&vc, &[&stranger]).await[0].clone();
        let err = receive_di_vc(
            &vault,
            "c2",
            &serde_json::to_vec(&vc).unwrap(),
            &FixedKeys::of(&[&stranger]),
            None,
            Utc::now(),
        )
        .await
        .expect_err("issuer spoofing");
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("not under the credential issuer")),
            "{err:?}"
        );
    }

    /// A proof for another purpose is refused: a credential is relied on as an
    /// attestation (VTI-KEY-022).
    #[tokio::test]
    async fn di_vc_with_an_authentication_proof_is_refused() {
        let (_dir, _store, vault) = fresh_vault();
        let (ed, _) = hybrid_issuer_keys();
        let mut vc = di_vc_doc(None);
        let proof = DiProof::sign(
            &vc,
            &ed,
            SignOptions::new().with_proof_purpose("authentication"),
        )
        .await
        .unwrap();
        vc["proof"] = serde_json::to_value(&proof).unwrap();
        assert!(
            receive_di_vc(
                &vault,
                "c1",
                &serde_json::to_vec(&vc).unwrap(),
                &FixedKeys::of(&[&ed]),
                None,
                Utc::now(),
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn di_vc_verifies_and_stores() {
        let (_dir, _store, vault) = fresh_vault();
        let (vc, keys) = signed_di_vc(9, Some("2100-01-01T00:00:00Z")).await;
        let cred = receive_di_vc(&vault, "c1", &vc, &keys, None, Utc::now())
            .await
            .expect("receive DI VC");
        assert_eq!(cred.format, CredentialFormat::EddsaJcs2022);
        assert_eq!(cred.subject_did.as_deref(), Some("did:key:zMember"));
        assert_eq!(cred.issuer_did.as_deref(), Some("did:web:issuer.example"));
        assert!(cred.types.contains(&"MembershipCredential".to_string()));
        assert!(crate::storage::get(&vault, "c1").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn di_vc_tampered_is_rejected_and_not_stored() {
        let (_dir, _store, vault) = fresh_vault();
        let (vc, keys) = signed_di_vc(9, None).await;
        let mut v: Value = serde_json::from_slice(&vc).unwrap();
        v["credentialSubject"]["givenName"] = json!("Mallory"); // tamper after signing
        let tampered = serde_json::to_vec(&v).unwrap();
        let err = receive_di_vc(&vault, "c1", &tampered, &keys, None, Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        assert!(crate::storage::get(&vault, "c1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn di_vc_expired_is_rejected() {
        let (_dir, _store, vault) = fresh_vault();
        let (vc, keys) = signed_di_vc(9, Some("2001-01-01T00:00:00Z")).await;
        let err = receive_di_vc(&vault, "c1", &vc, &keys, None, Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }

    #[tokio::test]
    async fn dispatch_routes_di_requires_key_and_gates_bbs() {
        let (_dir, _store, vault) = fresh_vault();
        let (vc, keys) = signed_di_vc(9, None).await;
        // DI without a resolved issuer key → rejected.
        assert!(
            receive(
                &vault,
                "c1",
                &CredentialFormat::EddsaJcs2022,
                &vc,
                IssuerKey::None,
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
            IssuerKey::Resolver(&keys),
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
                IssuerKey::None,
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
            IssuerKey::None,
            None,
            Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&zkp_err, AppError::Validation(m) if m.contains("ZKP")),
            "{zkp_err:?}"
        );
        // mdoc is deliberately unreachable through the format-dispatching entry
        // point: it needs the device-key binding, which this signature cannot
        // carry. Guessing that binding is exactly what must not happen.
        let mdoc_err = receive(
            &vault,
            "c4",
            &CredentialFormat::MsoMdoc,
            &vc,
            IssuerKey::None,
            None,
            Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&mdoc_err, AppError::Validation(m) if m.contains("receive_mdoc")),
            "error should point at the right entry point, got {mdoc_err:?}"
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

    /// The mdoc tag is `mso_mdoc` — underscore, matching OpenID4VP's
    /// `CredentialQuery.format` — and NOT the `rename_all` kebab-case
    /// `mso-mdoc` the enum would otherwise produce. Storage and protocol must
    /// spell it identically or a DCQL selector silently matches nothing, so
    /// pin the exact bytes rather than only the round-trip.
    #[test]
    fn mso_mdoc_format_tag_is_the_openid4vp_spelling() {
        let json = serde_json::to_string(&CredentialFormat::MsoMdoc).unwrap();
        assert_eq!(json, "\"mso_mdoc\"", "must match the OID4VP format token");
        let back: CredentialFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(back, CredentialFormat::MsoMdoc);
    }

    /// Before this variant existed an mdoc deserialised into the
    /// `Other("mso_mdoc")` escape hatch. It must now land on the real variant,
    /// or every downstream `match` treats a known format as unknown.
    #[test]
    fn mso_mdoc_no_longer_falls_into_the_other_escape_hatch() {
        let parsed: CredentialFormat = serde_json::from_str("\"mso_mdoc\"").unwrap();
        assert_eq!(parsed, CredentialFormat::MsoMdoc);
        assert_ne!(parsed, CredentialFormat::Other("mso_mdoc".to_string()));
    }
    // ── mdoc receive ──────────────────────────────────────────────────

    /// Build a signed mdoc plus its Document Signer public key. The MSO carries
    /// a generated P-256 device key, returned so a test can assert the binding.
    fn test_mdoc() -> (Vec<u8>, Vec<u8>) {
        use affinidi_mdoc::es256_cose::Es256CoseSigner;
        use affinidi_mdoc::mso::ValidityInfo;

        let signer = Es256CoseSigner::generate();
        let issued = affinidi_mdoc::MdocBuilder::new("eu.europa.ec.eudi.pid.1")
            .validity(ValidityInfo {
                signed: "2026-01-01T00:00:00Z".into(),
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: "2036-01-01T00:00:00Z".into(),
            })
            .add_json_attribute(
                affinidi_mdoc::EIDAS_PID_NAMESPACE,
                "family_name",
                &serde_json::json!("Gore"),
            )
            .build(&signer)
            .unwrap();
        (issued.to_cbor_bytes().unwrap(), signer.public_key_bytes())
    }

    #[tokio::test]
    async fn mdoc_receive_verifies_and_stores() {
        let (_tmp, _store, vault) = fresh_vault();
        let (body, issuer_pub) = test_mdoc();

        let cred = receive_mdoc(
            &vault,
            "m1",
            &body,
            &issuer_pub,
            "key-device-1",
            None,
            Utc::now(),
        )
        .await
        .expect("a well-formed mdoc should store");

        assert_eq!(cred.format, CredentialFormat::MsoMdoc);
        // docType comes from the signed MSO, and becomes the credential type.
        assert_eq!(cred.types, vec!["eu.europa.ec.eudi.pid.1"]);
        // No subject/issuer DID: an mdoc binds via the MSO deviceKey and its
        // issuer identity is an X.509 chain. Inventing either would put an
        // unverifiable identifier into a secondary index.
        assert!(cred.subject_did.is_none());
        assert!(cred.issuer_did.is_none());
        assert_eq!(cred.body, body, "the body is stored verbatim");
    }

    #[tokio::test]
    async fn mdoc_receive_rejects_a_wrong_issuer_key() {
        use affinidi_mdoc::es256_cose::Es256CoseSigner;
        let (_tmp, _store, vault) = fresh_vault();
        let (body, _) = test_mdoc();
        let attacker = Es256CoseSigner::generate().public_key_bytes();

        let err = receive_mdoc(
            &vault,
            "m2",
            &body,
            &attacker,
            "key-device-1",
            None,
            Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("issuerAuth")),
            "{err:?}"
        );
    }

    /// Reject-before-store: a failed verification must leave nothing behind.
    #[tokio::test]
    async fn mdoc_receive_stores_nothing_when_verification_fails() {
        use affinidi_mdoc::es256_cose::Es256CoseSigner;
        let (_tmp, _store, vault) = fresh_vault();
        let (body, _) = test_mdoc();
        let attacker = Es256CoseSigner::generate().public_key_bytes();

        let _ = receive_mdoc(
            &vault,
            "m3",
            &body,
            &attacker,
            "key-device-1",
            None,
            Utc::now(),
        )
        .await;

        assert!(
            storage::get(&vault, "m3").await.unwrap().is_none(),
            "a rejected mdoc must not be stored"
        );
    }

    /// An expired credential is refused even though its signature is perfectly
    /// good — ISO 18013-5 §9.3.1 requires the validityInfo check separately.
    #[tokio::test]
    async fn mdoc_receive_rejects_an_expired_credential() {
        let (_tmp, _store, vault) = fresh_vault();
        let (body, issuer_pub) = test_mdoc();
        let long_after = "2040-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();

        let err = receive_mdoc(
            &vault,
            "m4",
            &body,
            &issuer_pub,
            "key-device",
            None,
            long_after,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("not currently valid")),
            "{err:?}"
        );
    }

    /// The device-key binding is recorded on the stored envelope. Without it
    /// nothing downstream could know which VTA key may sign `DeviceAuth`, and
    /// the credential would be unpresentable with no trace of why.
    #[tokio::test]
    async fn mdoc_receive_records_the_device_key_binding() {
        let (_tmp, _store, vault) = fresh_vault();
        let (body, issuer_pub) = test_mdoc();

        let cred = receive_mdoc(
            &vault,
            "m5",
            &body,
            &issuer_pub,
            "key-device-42",
            None,
            Utc::now(),
        )
        .await
        .expect("stores");

        assert_eq!(
            cred.tags.get(super::super::model::MDOC_DEVICE_KEY_TAG),
            Some(&"key-device-42".to_string()),
            "the binding must survive onto the stored envelope"
        );
    }

    #[tokio::test]
    async fn mdoc_receive_rejects_a_body_that_is_not_an_mdoc() {
        let (_tmp, _store, vault) = fresh_vault();
        let err = receive_mdoc(
            &vault,
            "m6",
            b"not cbor at all",
            &[0u8; 65],
            "key-device-1",
            None,
            Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("IssuerSigned")),
            "{err:?}"
        );
    }

    // ---- ES256 / did:web SD-JWT-VC issuers (#1988) -----------------------

    /// An ES256 (P-256) issuer, the swiyu / EUDI shape.
    struct Es256Signer {
        private: Vec<u8>,
        kid: Option<String>,
    }

    impl JwtSigner for Es256Signer {
        fn algorithm(&self) -> &str {
            "ES256"
        }
        fn key_id(&self) -> Option<&str> {
            self.kid.as_deref()
        }
        fn sign_jwt(
            &self,
            header: &Value,
            payload: &Value,
        ) -> Result<String, affinidi_sd_jwt::error::SdJwtError> {
            let enc = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
            let input = format!("{}.{}", enc(header), enc(payload));
            let sig = affinidi_crypto::p256::sign(&self.private, input.as_bytes())
                .map_err(|e| affinidi_sd_jwt::error::SdJwtError::Verification(e.to_string()))?;
            Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig)))
        }
    }

    fn p256_issuer(kid: Option<&str>) -> (Es256Signer, ResolvedKey) {
        let kp = affinidi_crypto::p256::generate(Some(&[0x71; 32])).unwrap();
        let key = ResolvedKey::new(
            affinidi_secrets_resolver::secrets::KeyType::P256,
            kp.public_bytes,
        );
        (
            Es256Signer {
                private: kp.private_bytes,
                kid: kid.map(str::to_string),
            },
            key,
        )
    }

    fn issue_with(signer: &dyn JwtSigner, issuer_did: &str) -> String {
        affinidi_sd_jwt_vc::issue(
            "https://validant.ai/credentials/IterationSeal",
            issuer_did,
            None,
            &json!({ "verdict": "pass", "band": "adequate" }),
            &json!({ "_sd": ["band"] }),
            signer,
            &Sha256Hasher,
            None,
            1_700_000_000,
            Some(1_900_000_000),
        )
        .expect("issue SD-JWT-VC")
        .serialize()
    }

    /// #1988: an ES256 credential from a `did:web` issuer whose `kid` names a
    /// P-256 assertion key is received, with its disclosed claims.
    #[tokio::test]
    async fn an_es256_did_web_credential_is_received() {
        let (_dir, _store, vault) = fresh_vault();
        let vm = format!("{DI_ISSUER}#assert-key-01");
        let (signer, key) = p256_issuer(Some(&vm));
        let compact = issue_with(&signer, DI_ISSUER);
        let resolver = FixedKeys(vec![(vm, key)]);

        let stored = receive_sd_jwt_vc(&vault, "es256", &compact, &resolver, None, 1_800_000_000)
            .await
            .expect("an ES256 did:web credential is received");
        assert_eq!(stored.issuer_did.as_deref(), Some(DI_ISSUER));

        let claims = stored_claims(&stored, &resolver)
            .await
            .expect("re-verifies");
        assert_eq!(claims["band"], "adequate", "the disclosure is read back");

        // Through the format-dispatching entry point too.
        let id = "es256-dispatch";
        receive(
            &vault,
            id,
            &CredentialFormat::SdJwtVc,
            compact.as_bytes(),
            IssuerKey::Resolver(&resolver),
            None,
            chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        )
        .await
        .expect("dispatch with a resolver");
    }

    /// A Token Status List reference cannot be read yet, so the credential is
    /// held as Unknown, never an assumed Valid (VTI-CRD-012).
    #[tokio::test]
    async fn a_token_status_list_reference_is_stored_unknown() {
        let (_dir, _store, vault) = fresh_vault();
        let vm = format!("{DI_ISSUER}#assert-key-01");
        let (signer, key) = p256_issuer(Some(&vm));
        let compact = affinidi_sd_jwt_vc::issue(
            "https://validant.ai/credentials/IterationSeal",
            DI_ISSUER,
            None,
            &json!({
                "verdict": "pass",
                "status": { "status_list": { "idx": 7, "uri": "https://issuer.example/sl/1" } },
            }),
            &json!({}),
            &signer,
            &Sha256Hasher,
            None,
            1_700_000_000,
            Some(1_900_000_000),
        )
        .expect("issue")
        .serialize();
        let stored = receive_sd_jwt_vc(
            &vault,
            "tsl",
            &compact,
            &FixedKeys(vec![(vm, key)]),
            None,
            1_800_000_000,
        )
        .await
        .expect("received");
        assert_eq!(stored.status, CredentialStatus::Unknown);
    }

    /// Without a resolver, `receive` resolves locally only, so a `did:web`
    /// issuer is refused for that reason and nothing is stored.
    #[tokio::test]
    async fn a_did_web_credential_needs_a_resolver() {
        let (_dir, _store, vault) = fresh_vault();
        let vm = format!("{DI_ISSUER}#assert-key-01");
        let (signer, _) = p256_issuer(Some(&vm));
        let compact = issue_with(&signer, DI_ISSUER);
        let err = receive(
            &vault,
            "no-resolver",
            &CredentialFormat::SdJwtVc,
            compact.as_bytes(),
            IssuerKey::None,
            None,
            chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        )
        .await
        .expect_err("did:web needs a resolver");
        assert!(err.to_string().contains("did:key only"), "{err}");
        assert!(storage::get(&vault, "no-resolver").await.unwrap().is_none());
    }

    /// A P-256 `did:key` issuer needs no resolver at all.
    #[tokio::test]
    async fn a_p256_did_key_issuer_resolves_locally() {
        let (_dir, _store, vault) = fresh_vault();
        let (mut signer, key) = p256_issuer(None);
        let did = vta_sdk::jws::JwsKey::from_resolved(&key).unwrap().did_key();
        signer.kid = Some(format!("{did}#key-0"));
        let compact = issue_with(&signer, &did);
        receive_sd_jwt_vc(&vault, "p256-key", &compact, &local(), None, 1_800_000_000)
            .await
            .expect("a P-256 did:key issuer verifies with no I/O");
    }

    /// A `kid` naming another DID's key is refused, even when that key did
    /// sign: the issuer is who `iss` says, and only its keys count.
    #[tokio::test]
    async fn a_kid_outside_iss_is_refused() {
        let (_dir, _store, vault) = fresh_vault();
        let foreign = "did:web:attacker.example#k1".to_string();
        let (signer, key) = p256_issuer(Some(&foreign));
        let compact = issue_with(&signer, DI_ISSUER);
        let err = receive_sd_jwt_vc(
            &vault,
            "foreign-kid",
            &compact,
            &FixedKeys(vec![(foreign, key)]),
            None,
            1_800_000_000,
        )
        .await
        .expect_err("a key of another DID must not sign for this issuer");
        assert!(
            err.to_string().contains("not a verification method of"),
            "{err}"
        );
        assert!(storage::get(&vault, "foreign-kid").await.unwrap().is_none());
    }

    /// The IterationSeal vector attached to #1988, verbatim. Its signature is
    /// genuine ES256 (`vta_sdk::jws` verifies it against the published JWK),
    /// but its header names no `kid` on a `did:web` issuer, so the signing
    /// key cannot be selected and the credential is refused for that reason —
    /// not as a bad signature.
    #[tokio::test]
    async fn the_issue_1988_vector_is_refused_for_its_missing_kid() {
        const VECTOR: &str = concat!(
            "eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.",
            "eyJpc3MiOiJkaWQ6d2ViOnZhbGlkYW50LmFpIiwidmN0IjoiaHR0cHM6Ly92YWxpZGFudC5haS9jcmVkZW50aWFscy9JdGVyYXRpb25TZWFsIiwiYXNzZXNzbWVudF9pZCI6IjNmMmE5YzFlLThiNDctNGQyYS05ZTZmLTFjNWI3YTBkNGUyMSIsIml0ZXJhdGlvbl9udW1iZXIiOjIsImNvbnRyYWN0dWFsX21ldHJpYyI6ImRlbW9ncmFwaGljX3Bhcml0eSIsInZlcmRpY3QiOiJwYXNzIiwiYmFuZCI6ImFkZXF1YXRlIiwibGVpIjoiOTg0NTAwOUI2OERONzZJNUY1MTAiLCJwb2ludGluZyI6eyJib2R5IjoiTW9kZWwiLCJwYXRod2F5IjoiaGlyaW5nL0NWLXNjcmVlbmluZyIsImF1ZGllbmNlIjpbInN1YmplY3QiXX0sImFzc3VyYW5jZV9wcm9maWxlIjp7ImFjY2VzcyI6IkEzIiwiZXZpZGVuY2UiOiJFMiIsInZhbGlkaXR5IjoiVjIiLCJhc3N1cmFuY2VfY2xhc3MiOiJyZWFzb25hYmxlIiwiY2VpbGluZyI6InJlYXNvbmFibGUiLCJsaW1pdGluZyI6WyJhY2Nlc3MiLCJldmlkZW5jZSIsInZhbGlkaXR5Il0sIm1pbl9kZXRlY3RhYmxlX2VmZmVjdCI6MC4wNDMsImZyb250aWVyIjp7ImludGVydmVudGlvbmFsIjoibm90X29mZmVyZWQiLCJmdWxsX2xpbmVhZ2UiOiJub3Rfb2ZmZXJlZCIsImNvbnRpbnVvdXMiOiJub3Rfb2ZmZXJlZCJ9LCJjYWxpYnJhdGlvbiI6IjIwMjYtMDgifSwiY29udGVudF9oYXNoIjoiMzEwNTYzNzE4ZTA2ZjdjNzI0ODE2OGUyYjRiZTk1MjZlZDQ2MWExOWU3YjhhYmFjYWJiMWY5ZWYwZTkwYzE4ZCIsImlhdCI6MTc4NTk3NDQwMCwiZXhwIjoxODE3NTEwNDAwLCJfc2QiOlsiU2xfR0ZSRXFuMU9nSEd2Y1lLekNxSVM5SFBiZW01ZzhVaWphWDF3RExZSSJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9.",
            "02oW1G8gG29v0lp4vGG3nweHVJ5mjq6guWhQjFmy_lmC69Zup4iYMJNQeOOU21pfq86qqBWjTqjnqCvGi7mL9g",
            "~WyItT3dsZHFfU25YWEFuSkVZRG5DM3N3IiwiZGV0YWlscyIseyJtYXhfZGlzcGFyaXR5IjowLjA0MSwiY29udHJhY3R1YWxfdGhyZXNob2xkIjowLjEsInRocmVzaG9sZF9zb3VyY2UiOiJzaWduZWRfbWV0cmljIiwidmVyZGljdF9wcm92aXNpb25hbCI6ZmFsc2UsImZyYW1lc19zaGEyNTYiOiI5ZjFjMGIzYTJkNGU1ZjYwNzE4MjkzYTRiNWM2ZDdlOGY5MDExMjIzMzQ0NTU2Njc3ODg5OWFhYmJjY2RkZWVmZiIsInByb3ZlbmFuY2VfdmVyaWZpZWQiOnRydWV9XQ~"
        );
        let (_dir, _store, vault) = fresh_vault();
        let err = receive_sd_jwt_vc(
            &vault,
            "seal",
            VECTOR,
            &FixedKeys(vec![]),
            None,
            1_785_974_401,
        )
        .await
        .expect_err("no kid on a did:web issuer");
        assert!(err.to_string().contains("DID-URL kid"), "{err}");
    }
}
