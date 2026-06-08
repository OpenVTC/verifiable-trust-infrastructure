//! BBS+ (`bbs-2023`) credential support for the vault — feature-gated `bbs`.
//!
//! The vault's SD-JWT-VC / eddsa-jcs-2022 paths are always built; BBS pulls in
//! the BLS12-381 curve (`affinidi-bbs`) + the `bbs-2023` Data-Integrity
//! cryptosuite, so it lives behind the `bbs` feature. The document-level
//! derive/verify is delegated to the standards-track
//! [`affinidi_data_integrity::bbs_2023_transform`] (W3C vc-di-bbs, RDF-canonical)
//! — per the workspace principle, proof handling is the library's job, not
//! hand-rolled here. (The earlier `bbs_2023` module is an affinidi-internal,
//! non-interoperable encoding and is now deprecated upstream.)
//!
//! A vc-di-bbs soundness bug in the document layer (a holder could present
//! forged disclosed values) was found during this work and fixed upstream in
//! `affinidi-data-integrity` 0.7.5 / `affinidi-rdf-encoding` 0.1.5
//! (affinidi-tdk-rs#381) — the fix adds JSON-LD **safe mode**, so every claim
//! term MUST be defined by the credential's `@context` (no silent `@vocab`
//! drop). The regression is pinned by `tampered_disclosure_is_rejected_upstream_381`.
//! Note: BBS issuer *signing* remains separately **audit-gated** (#294).
//!
//! ## Scope (audit gate)
//!
//! The VTA is a credential **holder/verifier**, not an issuer, so issuer
//! *signing* (`sign_base_document`) is deliberately **not** exposed from this
//! module — BBS issuance stays audit-gated. This module covers the holder side:
//! **receive** ([`receive_bbs`] — verify the issuer base proof, then store),
//! **present** ([`present_bbs`] — consent-gated selective disclosure), and the
//! G2 issuer-key resolution ([`resolve_bbs_issuer_key`]) the wire layer uses.

use affinidi_bbs::PublicKey;
use affinidi_data_integrity::bbs_2023_transform as bbs_tx;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde_json::Value;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::model::{
    BBS_PROVER_NYM_TAG, BBS_SECRET_PROVER_BLIND_TAG, CredentialFormat, CredentialStatus,
    StoredCredential,
};
use super::receive::{Provenance, di_temporal_valid, extract_types, infer_purpose};
use super::storage;

/// Compressed BLS12-381 G2 public key length.
const BLS12381_G2_LEN: usize = 96;

/// Parse a 96-byte compressed BLS12-381 G2 key into a BBS [`PublicKey`]
/// (validates the point is on-curve, in-subgroup, non-identity).
pub fn g2_public_key(bytes: &[u8]) -> Result<PublicKey, AppError> {
    let arr: [u8; BLS12381_G2_LEN] = bytes.try_into().map_err(|_| {
        AppError::Validation(format!(
            "BBS issuer key must be {BLS12381_G2_LEN} bytes (compressed G2), got {}",
            bytes.len()
        ))
    })?;
    PublicKey::from_bytes(&arr)
        .map_err(|e| AppError::Validation(format!("invalid BBS issuer key: {e}")))
}

/// Resolve a BBS issuer's G2 public key from a `did:key` issuer (the whole DID
/// *is* the key, multicodec `0xeb`). `did:webvh` / `did:web` issuers are
/// resolved from a DID-document verification method by the wire layer, which
/// passes the 96 bytes to [`receive_bbs`] — keeping this module network-free,
/// like the eddsa-jcs path.
pub fn g2_issuer_key_from_did_key(issuer_did: &str) -> Result<PublicKey, AppError> {
    let bytes = affinidi_crypto::bls12381::did_key_to_g2_pub(issuer_did).map_err(|e| {
        AppError::Validation(format!("issuer `{issuer_did}` is not a BBS did:key: {e}"))
    })?;
    g2_public_key(&bytes)
}

/// Resolve a BBS issuer's 96-byte compressed G2 public key from a credential,
/// **binding the proof's `verificationMethod` to the credential `issuer`** (so a
/// key under some other DID can't sign a credential claiming a different issuer).
///
/// `did:key` issuers resolve locally; `did:webvh` / `did:web` issuers resolve
/// through `did_resolver` (the verification method's `publicKeyMultibase`, a
/// `0xeb` Multikey). The G2 analog of
/// [`crate::vault::di_verify::resolve_di_issuer_key`] — used by the wire layer
/// (`store_issued_credential`) to receive a BBS credential delivered over
/// DIDComm.
pub async fn resolve_bbs_issuer_key(
    did_resolver: Option<&DIDCacheClient>,
    credential: &Value,
) -> Result<[u8; BLS12381_G2_LEN], AppError> {
    let issuer_did = crate::vault::di_verify::credential_issuer(credential)
        .ok_or_else(|| AppError::Validation("bbs-2023 credential has no `issuer`".into()))?;
    let vm = credential
        .get("proof")
        .and_then(|p| p.get("verificationMethod"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation("bbs-2023 proof has no `verificationMethod`".into()))?;
    if vm.split('#').next().unwrap_or_default() != issuer_did {
        return Err(AppError::Validation(format!(
            "bbs-2023 proof verificationMethod `{vm}` is not under the credential issuer \
             `{issuer_did}`"
        )));
    }

    if issuer_did.starts_with("did:key:") {
        return affinidi_crypto::bls12381::did_key_to_g2_pub(&issuer_did).map_err(|e| {
            AppError::Validation(format!("issuer `{issuer_did}` is not a BBS did:key: {e}"))
        });
    }
    let resolver = did_resolver.ok_or_else(|| {
        AppError::Validation(format!(
            "resolving issuer `{issuer_did}` needs a DID resolver for did:webvh / did:web BBS \
             issuers"
        ))
    })?;
    let resolved = resolver.resolve(&issuer_did).await.map_err(|e| {
        AppError::Validation(format!("issuer DID `{issuer_did}` did not resolve: {e}"))
    })?;
    let doc: Value = serde_json::to_value(&resolved.doc)
        .map_err(|e| AppError::Internal(format!("issuer DID document serialise failed: {e}")))?;
    let vms = doc
        .get("verificationMethod")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            AppError::Validation(format!(
                "issuer DID `{issuer_did}` has no verificationMethod array"
            ))
        })?;
    let relative = vm
        .split_once('#')
        .map(|(_, f)| format!("#{f}"))
        .unwrap_or_default();
    let entry = vms
        .iter()
        .find(|e| {
            let id = e.get("id").and_then(Value::as_str).unwrap_or("");
            id == vm || id == relative
        })
        .ok_or_else(|| {
            AppError::Validation(format!(
                "verificationMethod `{vm}` not found in issuer DID `{issuer_did}`"
            ))
        })?;
    let multibase = entry
        .get("publicKeyMultibase")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::Validation(format!(
                "verificationMethod `{vm}` has no publicKeyMultibase (BLS12-381 G2 Multikey)"
            ))
        })?;
    affinidi_crypto::bls12381::did_key_to_g2_pub(&format!("did:key:{multibase}")).map_err(|e| {
        AppError::Validation(format!(
            "verificationMethod `{vm}` is not a BLS12-381 G2 Multikey: {e}"
        ))
    })
}

/// Receive a BBS (`bbs-2023`) **base-proof** credential into the vault.
///
/// Verifies the issuer's base proof, checks temporal validity, then stores the
/// base-proof VC verbatim (the holder keeps it to derive selective-disclosure
/// presentations later). `issuer_pub` is the caller-resolved 96-byte compressed
/// G2 key — the vault stays network-free, mirroring `receive_di_vc`.
///
/// **Base-proof verification:** the cryptosuite exposes no standalone
/// "verify base", so we confirm the issuer signature by deriving a
/// full-disclosure proof and verifying it — a full-disclosure derived proof
/// verifies iff the base BBS signature is valid over every message.
pub async fn receive_bbs(
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
    let pk = g2_public_key(issuer_pub)?;
    let vc: Value = serde_json::from_slice(vc_json)
        .map_err(|e| AppError::Validation(format!("malformed BBS VC JSON: {e}")))?;

    // Verify the issuer base proof before trusting any bytes. The cryptosuite
    // exposes no standalone "verify base", so we derive a **full-disclosure**
    // proof and verify it: a full-disclosure derived proof verifies iff the base
    // BBS signature is valid over every message, so a tampered claim — mandatory
    // or not — is rejected. The `""` root JSON pointer selects every statement
    // (`select_json_ld` returns the whole document for an empty path).
    const BASE_CHECK_NONCE: &[u8] = b"vta-vault-base-check";
    let full = bbs_tx::create_derived_proof(&vc, &[""], BASE_CHECK_NONCE, &pk)
        .map_err(|e| AppError::Validation(format!("BBS base proof is malformed: {e}")))?;
    if !bbs_tx::verify_derived_proof(&full, &pk)
        .map_err(|e| AppError::Validation(format!("BBS base proof verification failed: {e}")))?
    {
        return Err(AppError::Validation(
            "BBS issuer base proof did not verify".to_string(),
        ));
    }

    // Temporal validity over W3C VC 2.0 `validFrom` / `validUntil`.
    di_temporal_valid(&vc, now)?;

    let cred = build_stored_bbs(&vc, id, vc_json, source, now);
    storage::put(vault, &cred).await?;
    Ok(cred)
}

/// Map a verified BBS VC into a [`StoredCredential`] envelope (mirrors
/// `receive_di_vc`). Pure metadata extraction — the caller has already verified
/// the issuer proof and temporal validity.
fn build_stored_bbs(
    vc: &Value,
    id: &str,
    vc_json: &[u8],
    source: Provenance,
    now: DateTime<Utc>,
) -> StoredCredential {
    let types = extract_types(vc);
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

    StoredCredential {
        id: id.to_string(),
        format: CredentialFormat::Bbs2023,
        types,
        schema_id: None,
        community_did: None,
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
    }
}

/// Receive a BBS (`bbs-2023`) **pseudonym** base-proof credential — one issued in
/// **holder-binding** mode, where the issuer blind-signed the holder's link-secret
/// commitment ([`affinidi_bbs::nym_commit`]).
///
/// Same envelope mapping as [`receive_bbs`], but additionally persists the
/// holder's pseudonym secrets (`prover_nym`, `secret_prover_blind`, generated by
/// the holder at the commitment step) under the reserved
/// [`BBS_PROVER_NYM_TAG`] / [`BBS_SECRET_PROVER_BLIND_TAG`] tags, so the holder
/// can later derive a per-verifier pseudonym presentation ([`present_bbs`]).
///
/// **Base-proof verification:** the cryptosuite exposes no standalone "verify
/// base", so we derive a *full-disclosure pseudonym* proof with the holder's
/// secrets under a fixed check context and verify it — which succeeds iff the
/// issuer's blind signature over the committed messages is valid.
#[allow(clippy::too_many_arguments)]
pub async fn receive_bbs_pseudonym(
    vault: &KeyspaceHandle,
    id: &str,
    vc_json: &[u8],
    issuer_pub: &[u8],
    prover_nym: &[u8],
    secret_prover_blind: &[u8],
    source: Provenance,
    now: DateTime<Utc>,
) -> Result<StoredCredential, AppError> {
    if id.trim().is_empty() {
        return Err(AppError::Validation(
            "credential id must be non-empty".to_string(),
        ));
    }
    let pk = g2_public_key(issuer_pub)?;
    let vc: Value = serde_json::from_slice(vc_json)
        .map_err(|e| AppError::Validation(format!("malformed BBS VC JSON: {e}")))?;

    // Verify the issuer pseudonym base proof under a fixed check context (any
    // stable verifier id works — we only care that the signature is valid).
    const BASE_CHECK_NONCE: &[u8] = b"vta-vault-base-check";
    const BASE_CHECK_VERIFIER: &str = "vta-vault-base-check";
    let full = bbs_tx::create_pseudonym_derived_proof(
        &vc,
        &[""],
        BASE_CHECK_NONCE,
        &pk,
        prover_nym,
        secret_prover_blind,
        BASE_CHECK_VERIFIER,
    )
    .map_err(|e| AppError::Validation(format!("BBS pseudonym base proof is malformed: {e}")))?;
    if !bbs_tx::verify_pseudonym_derived_proof(&full, &pk, BASE_CHECK_VERIFIER).map_err(|e| {
        AppError::Validation(format!("BBS pseudonym base proof verification failed: {e}"))
    })? {
        return Err(AppError::Validation(
            "BBS issuer pseudonym base proof did not verify".to_string(),
        ));
    }
    di_temporal_valid(&vc, now)?;

    let mut cred = build_stored_bbs(&vc, id, vc_json, source, now);
    cred.tags.insert(
        BBS_PROVER_NYM_TAG.to_string(),
        URL_SAFE_NO_PAD.encode(prover_nym),
    );
    cred.tags.insert(
        BBS_SECRET_PROVER_BLIND_TAG.to_string(),
        URL_SAFE_NO_PAD.encode(secret_prover_blind),
    );
    storage::put(vault, &cred).await?;
    Ok(cred)
}

/// Build a consent-gated, **selectively-disclosed** BBS (`bbs-2023`)
/// presentation of a stored credential — the holder's side of selective
/// disclosure.
///
/// Gating is the shared [`super::present::gate_present`] (subject binding,
/// per-credential consent, live status, temporal — same as the SD-JWT / DI
/// paths). Unlike the eddsa-jcs path (which is whole-credential), BBS discloses
/// **exactly** the consent record's reveal set (`dpv:hasPersonalData`) as
/// `credentialSubject` claims, plus the issuer's mandatory claims — it redacts
/// everything else, so there's no over-disclosure.
///
/// `issuer_pub` is the caller-resolved 96-byte G2 key (deriving a proof needs
/// the issuer key); `nonce` is the verifier's presentation challenge (bound into
/// the proof for freshness). Returns the derived VC as a JSON string.
#[allow(clippy::too_many_arguments)]
pub async fn present_bbs(
    vault: &KeyspaceHandle,
    credential_id: &str,
    consent_record_id: &str,
    issuer_pub: &[u8],
    nonce: &str,
    aud: &str,
    status_resolver: Option<&dyn super::status::StatusListResolver>,
    now: DateTime<Utc>,
) -> Result<String, AppError> {
    let (cred, record) = super::present::gate_present(
        vault,
        credential_id,
        consent_record_id,
        aud,
        status_resolver,
        now,
    )
    .await?;

    if cred.format != CredentialFormat::Bbs2023 {
        return Err(AppError::Validation(format!(
            "credential `{credential_id}` is not a bbs-2023 credential (format {:?}); \
             cannot present via present_bbs",
            cred.format
        )));
    }
    let pk = g2_public_key(issuer_pub)?;
    let vc: Value = serde_json::from_slice(&cred.body)
        .map_err(|e| AppError::Validation(format!("stored BBS VC body is not JSON: {e}")))?;

    // Disclose EXACTLY the consented claims (the reveal set) as `credentialSubject`
    // pointers; BBS redacts the rest, so the gate's claim-scope check is enforced
    // cryptographically rather than by a whole-credential guard.
    let selective: Vec<String> = record
        .process
        .personal_data
        .iter()
        .map(|name| format!("/credentialSubject/{}", rfc6901_escape(name)))
        .collect();
    let selective_refs: Vec<&str> = selective.iter().map(String::as_str).collect();

    // Holder-binding (pseudonym) mode iff the stored credential carries the
    // holder's pseudonym secrets (set at blind issuance by
    // [`receive_bbs_pseudonym`]). Then we derive a *per-verifier pseudonym* proof
    // bound to `aud` (the verifier context), so the verifier learns the presenter
    // **is** the subject — without sacrificing cross-verifier unlinkability.
    // Otherwise the basic, possession-based derived proof (anyone holding the
    // credential can present as the disclosed subject).
    let derived = match holder_pseudonym_secrets(&cred)? {
        Some((prover_nym, secret_prover_blind)) => bbs_tx::create_pseudonym_derived_proof(
            &vc,
            &selective_refs,
            nonce.as_bytes(),
            &pk,
            &prover_nym,
            &secret_prover_blind,
            aud,
        )
        .map_err(|e| AppError::Validation(format!("BBS holder-bound disclosure failed: {e}")))?,
        None => bbs_tx::create_derived_proof(&vc, &selective_refs, nonce.as_bytes(), &pk)
            .map_err(|e| AppError::Validation(format!("BBS selective disclosure failed: {e}")))?,
    };
    serde_json::to_string(&derived)
        .map_err(|e| AppError::Internal(format!("serialise BBS presentation: {e}")))
}

/// Read the holder's BBS pseudonym secrets from a stored credential's reserved
/// tags, returning `(prover_nym, secret_prover_blind)` as raw bytes when the
/// credential was issued in holder-binding mode, or `None` for a
/// possession-based bbs-2023 credential.
///
/// Errors if exactly one secret is present (a corrupt half-pair — both are
/// required to derive a pseudonym) or a value is not valid base64url.
fn holder_pseudonym_secrets(
    cred: &StoredCredential,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, AppError> {
    let decode = |k: &str, v: &str| {
        URL_SAFE_NO_PAD
            .decode(v)
            .map_err(|e| AppError::Validation(format!("bbs `{k}` tag is not base64url: {e}")))
    };
    match (
        cred.tags.get(BBS_PROVER_NYM_TAG),
        cred.tags.get(BBS_SECRET_PROVER_BLIND_TAG),
    ) {
        (None, None) => Ok(None),
        (Some(nym), Some(blind)) => Ok(Some((
            decode(BBS_PROVER_NYM_TAG, nym)?,
            decode(BBS_SECRET_PROVER_BLIND_TAG, blind)?,
        ))),
        _ => Err(AppError::Validation(
            "bbs-2023 credential has only one of the two pseudonym holder secrets — both \
             `bbs:prover_nym` and `bbs:secret_prover_blind` are required for holder binding"
                .into(),
        )),
    }
}

/// RFC 6901 token escaping (`~` -> `~0`, `/` -> `~1`) for a claim name embedded
/// in a JSON pointer.
fn rfc6901_escape(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Test-only: issue a `bbs-2023` **pseudonym** base-proof credential — the
/// audit-gated *issuer* side, exercised only in tests (production issuer signing
/// stays out of this crate per the module's "audit gate" scope).
///
/// Runs the blind-issuance handshake: the holder commits a `prover_nym` link
/// secret ([`affinidi_bbs::nym_commit`]) and the issuer blind-signs it
/// ([`bbs_tx::create_pseudonym_base_proof_value`]) with `signer_nym_entropy`
/// mixed in. Returns `(base_document, prover_nym, secret_prover_blind)` — the
/// latter two are the holder secrets to pass to [`receive_bbs_pseudonym`].
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn issue_bbs_pseudonym_for_test(
    vc: &Value,
    mandatory: &[&str],
    verification_method: &str,
    created: &str,
    sk: &affinidi_bbs::SecretKey,
    pk: &PublicKey,
    hmac_key: &[u8],
    prover_nym_bytes: &[u8; 32],
    signer_nym_entropy_bytes: &[u8; 32],
) -> (Value, Vec<u8>, Vec<u8>) {
    use affinidi_bbs as bbs;
    // Holder side: commit the link secret.
    let prover_nym =
        bbs::hash::scalar_from_bytes(prover_nym_bytes).expect("prover_nym is a valid scalar");
    let (commitment_with_proof, secret_prover_blind) =
        bbs::nym_commit(prover_nym, &[], bbs::Ciphersuite::default()).expect("nym_commit");
    let secret_prover_blind_bytes = bbs::hash::scalar_to_bytes(&secret_prover_blind);

    // Issuer side: blind-sign the commitment into a pseudonym base proof. Build
    // the proof object exactly as `sign_base_document` does for the basic suite.
    let context = vc.get("@context").cloned().expect("vc has @context");
    let proof_config = serde_json::json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "bbs-2023",
        "created": created,
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
        "@context": context,
    });
    let proof_value = bbs_tx::create_pseudonym_base_proof_value(
        vc,
        &proof_config,
        mandatory,
        sk,
        pk,
        hmac_key,
        &commitment_with_proof,
        signer_nym_entropy_bytes,
    )
    .expect("create pseudonym base proof");
    let mut proof = proof_config;
    let obj = proof.as_object_mut().unwrap();
    obj.remove("@context");
    obj.insert("proofValue".to_string(), Value::String(proof_value));
    let mut base = vc.clone();
    base.as_object_mut()
        .unwrap()
        .insert("proof".to_string(), proof);

    (
        base,
        prover_nym_bytes.to_vec(),
        secret_prover_blind_bytes.to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_bbs as bbs;
    use affinidi_data_integrity::bbs_2023_transform::sign_base_document;
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    const MANDATORY: &[&str] = &["/@context", "/type", "/issuer", "/credentialSubject/id"];
    /// Per-credential HMAC key (32 bytes) — carried inside the base proofValue so
    /// the holder can derive presentations. Fixed here for deterministic tests.
    const TEST_HMAC: &[u8; 32] = b"vta-bbs-test-hmac-key-32-bytes!!";
    const TEST_CREATED: &str = "2020-01-01T00:00:00Z";

    fn fresh_vault() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store.keyspace("vault").expect("vault keyspace");
        (dir, store, ks)
    }

    fn issuer_keys() -> (bbs::SecretKey, bbs::PublicKey) {
        let sk = bbs::keygen(b"vta-bbs-test-key-material-32byte", b"").unwrap();
        let pk = bbs::sk_to_pk(&sk);
        (sk, pk)
    }

    fn issuer_did(pk: &bbs::PublicKey) -> String {
        affinidi_crypto::bls12381::g2_pub_to_did_key(&pk.to_bytes())
    }

    fn signed_bbs_vc(valid_until: Option<&str>) -> (Vec<u8>, bbs::PublicKey) {
        let (sk, pk) = issuer_keys();
        let did = issuer_did(&pk);
        let mut vc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": did,
            "validFrom": "2020-01-01T00:00:00Z",
            "credentialSubject": { "id": "did:key:zMember", "givenName": "Alice", "memberLevel": "gold" }
        });
        if let Some(u) = valid_until {
            vc["validUntil"] = json!(u);
        }
        let vm = format!("{did}#bbs-key-0");
        let signed =
            sign_base_document(&vc, MANDATORY, &vm, TEST_CREATED, &sk, &pk, TEST_HMAC).unwrap();
        (serde_json::to_vec(&signed).unwrap(), pk)
    }

    #[tokio::test]
    async fn receives_and_stores_a_valid_bbs_credential() {
        let (_dir, _store, vault) = fresh_vault();
        let (vc, pk) = signed_bbs_vc(Some("2100-01-01T00:00:00Z"));
        let cred = receive_bbs(&vault, "bbs-1", &vc, &pk.to_bytes(), None, Utc::now())
            .await
            .expect("receive valid BBS VC");
        assert_eq!(cred.format, CredentialFormat::Bbs2023);
        assert_eq!(cred.subject_did.as_deref(), Some("did:key:zMember"));
        assert!(cred.types.contains(&"MembershipCredential".to_string()));
        assert!(
            storage::get(&vault, "bbs-1").await.unwrap().is_some(),
            "credential must be stored"
        );
    }

    #[tokio::test]
    async fn rejects_a_tampered_bbs_credential() {
        let (_dir, _store, vault) = fresh_vault();
        let (vc, pk) = signed_bbs_vc(None);
        let mut v: Value = serde_json::from_slice(&vc).unwrap();
        v["credentialSubject"]["memberLevel"] = json!("platinum"); // tamper post-sign
        let tampered = serde_json::to_vec(&v).unwrap();
        let err = receive_bbs(&vault, "bbs-x", &tampered, &pk.to_bytes(), None, Utc::now())
            .await
            .expect_err("a tampered BBS VC must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        assert!(
            storage::get(&vault, "bbs-x").await.unwrap().is_none(),
            "a rejected credential must not be stored"
        );
    }

    /// Soundness regression for **affinidi-tdk-rs#381** (fixed in
    /// `affinidi-data-integrity` 0.7.5 / `affinidi-rdf-encoding` 0.1.5).
    ///
    /// A holder must not be able to change a signed attribute and have the
    /// derived proof verify. The fix added JSON-LD **safe mode**, so the document
    /// layer now enforces the disclosed-value ↔ proof binding two ways, both
    /// covered here:
    /// 1. **defined terms** (examples `@vocab`): the value is in the signed RDF
    ///    dataset, so tampering it makes `verify_derived_proof` return `false`;
    /// 2. **undefined terms** (bare `credentials/v2`): expansion is refused
    ///    outright, so a forged value can't even be derived.
    ///
    /// The raw `affinidi-bbs` primitive was always sound (asserted here too).
    #[test]
    fn tampered_disclosure_is_rejected_upstream_381() {
        let (sk, pk) = issuer_keys();
        let did = issuer_did(&pk);

        // Raw primitive: tampered disclosure is correctly REJECTED.
        let sig = bbs::sign(&sk, &pk, b"hdr", &[b"m0".as_ref(), b"gold"]).unwrap();
        let proof = bbs::proof_gen(
            &pk,
            &sig,
            b"hdr",
            b"ph",
            &[b"m0".as_ref(), b"platinum"],
            &[1],
        )
        .unwrap();
        assert!(
            !bbs::proof_verify(&pk, &proof, b"hdr", b"ph", &[b"platinum".as_ref()], &[1]).unwrap(),
            "raw affinidi-bbs must reject a tampered disclosure"
        );

        // (1) Defined terms (examples @vocab) → value is in the signed dataset.
        let vc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "type": ["VerifiableCredential", "ExampleMembershipCredential"],
            "issuer": did,
            "credentialSubject": { "id": "did:key:zMember", "memberLevel": "gold" }
        });
        let base = sign_base_document(
            &vc,
            MANDATORY,
            &format!("{did}#bbs-key-0"),
            TEST_CREATED,
            &sk,
            &pk,
            TEST_HMAC,
        )
        .unwrap();
        // Honest derive verifies.
        let honest =
            bbs_tx::create_derived_proof(&base, &["/credentialSubject/memberLevel"], b"n", &pk)
                .unwrap();
        assert!(bbs_tx::verify_derived_proof(&honest, &pk).unwrap());
        // Tamper the base, re-derive disclosing the forged value → verify REJECTS.
        let mut tampered = base.clone();
        tampered["credentialSubject"]["memberLevel"] = json!("platinum");
        let forged =
            bbs_tx::create_derived_proof(&tampered, &["/credentialSubject/memberLevel"], b"n", &pk)
                .expect("derive (defined terms)");
        assert!(
            !bbs_tx::verify_derived_proof(&forged, &pk).unwrap_or(false),
            "REGRESSION (affinidi-tdk-rs#381): bbs_2023_transform accepted a forged disclosed value"
        );

        // (2) Undefined terms (bare credentials/v2) → safe mode refuses expansion,
        // so a credential whose claims aren't in its @context can't be signed at all.
        let undefined = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": did,
            "credentialSubject": { "id": "did:key:zMember", "memberLevel": "gold" }
        });
        assert!(
            sign_base_document(
                &undefined,
                MANDATORY,
                &format!("{did}#bbs-key-0"),
                TEST_CREATED,
                &sk,
                &pk,
                TEST_HMAC,
            )
            .is_err(),
            "safe mode must refuse a credential with @context-undefined claim terms"
        );
    }

    #[tokio::test]
    async fn rejects_an_expired_bbs_credential() {
        let (_dir, _store, vault) = fresh_vault();
        let (vc, pk) = signed_bbs_vc(Some("2001-01-01T00:00:00Z"));
        let err = receive_bbs(&vault, "bbs-exp", &vc, &pk.to_bytes(), None, Utc::now())
            .await
            .expect_err("an expired BBS VC must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }

    #[tokio::test]
    async fn rejects_a_wrong_issuer_key() {
        let (_dir, _store, vault) = fresh_vault();
        let (vc, _pk) = signed_bbs_vc(None);
        let other = bbs::sk_to_pk(&bbs::keygen(b"another-bbs-key-material-32bytes", b"").unwrap());
        let err = receive_bbs(&vault, "bbs-w", &vc, &other.to_bytes(), None, Utc::now())
            .await
            .expect_err("verification under the wrong issuer key must fail");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }

    #[test]
    fn resolves_g2_issuer_key_from_did_key() {
        let (_sk, pk) = issuer_keys();
        let did = issuer_did(&pk);
        let resolved = g2_issuer_key_from_did_key(&did).expect("resolve G2 did:key");
        assert_eq!(resolved.to_bytes(), pk.to_bytes());
    }

    // ---- holder-binding (pseudonym) ------------------------------------------

    /// A bbs-2023 **pseudonym** base-proof VC + the holder's `(prover_nym,
    /// secret_prover_blind)` raw-byte secrets.
    fn pseudonym_bbs_vc() -> (Vec<u8>, bbs::PublicKey, [u8; 32], Vec<u8>) {
        let (sk, pk) = issuer_keys();
        let did = issuer_did(&pk);
        let vc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": did,
            "validFrom": "2020-01-01T00:00:00Z",
            "credentialSubject": { "id": "did:key:zMember", "givenName": "Alice", "memberLevel": "gold" }
        });
        let vm = format!("{did}#bbs-key-0");
        let prover_nym = [0x11u8; 32];
        let entropy = [0x22u8; 32];
        let (base, nym, blind) = issue_bbs_pseudonym_for_test(
            &vc,
            MANDATORY,
            &vm,
            TEST_CREATED,
            &sk,
            &pk,
            TEST_HMAC,
            &prover_nym,
            &entropy,
        );
        assert_eq!(nym, prover_nym.to_vec());
        (serde_json::to_vec(&base).unwrap(), pk, prover_nym, blind)
    }

    #[tokio::test]
    async fn receives_and_stores_a_pseudonym_bbs_credential() {
        let (_dir, _store, vault) = fresh_vault();
        let (vc, pk, nym, blind) = pseudonym_bbs_vc();
        let cred = receive_bbs_pseudonym(
            &vault,
            "bbs-nym",
            &vc,
            &pk.to_bytes(),
            &nym,
            &blind,
            None,
            Utc::now(),
        )
        .await
        .expect("receive pseudonym BBS VC");
        assert_eq!(cred.format, CredentialFormat::Bbs2023);
        assert!(
            cred.tags.contains_key(BBS_PROVER_NYM_TAG)
                && cred.tags.contains_key(BBS_SECRET_PROVER_BLIND_TAG),
            "holder pseudonym secrets must be persisted"
        );
        let stored = storage::get(&vault, "bbs-nym")
            .await
            .unwrap()
            .expect("stored");
        assert_eq!(
            stored.tags.get(BBS_PROVER_NYM_TAG),
            cred.tags.get(BBS_PROVER_NYM_TAG),
            "secrets round-trip through the store"
        );
        // The decoded secrets must be the holder's originals.
        assert_eq!(
            holder_pseudonym_secrets(&stored).unwrap(),
            Some((nym.to_vec(), blind))
        );
    }

    #[tokio::test]
    async fn rejects_pseudonym_base_with_wrong_holder_secret() {
        let (_dir, _store, vault) = fresh_vault();
        let (vc, pk, _nym, blind) = pseudonym_bbs_vc();
        let wrong_nym = [0x33u8; 32];
        let err = receive_bbs_pseudonym(
            &vault,
            "bbs-bad",
            &vc,
            &pk.to_bytes(),
            &wrong_nym,
            &blind,
            None,
            Utc::now(),
        )
        .await
        .expect_err("a wrong holder link secret must fail the base check");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        assert!(
            storage::get(&vault, "bbs-bad").await.unwrap().is_none(),
            "a rejected credential must not be stored"
        );
    }

    #[test]
    fn half_a_pseudonym_secret_pair_is_an_error() {
        // A credential carrying only one of the two reserved secret tags must not
        // be silently treated as possession-based.
        let mut cred = StoredCredential {
            id: "x".into(),
            format: CredentialFormat::Bbs2023,
            types: vec![],
            schema_id: None,
            community_did: None,
            subject_did: None,
            issuer_did: None,
            purpose: None,
            status: CredentialStatus::Valid,
            valid_from: None,
            valid_until: None,
            received_at: Utc::now().to_rfc3339(),
            source: None,
            tags: std::collections::BTreeMap::new(),
            body: vec![],
        };
        assert_eq!(holder_pseudonym_secrets(&cred).unwrap(), None);
        cred.tags.insert(
            BBS_PROVER_NYM_TAG.to_string(),
            URL_SAFE_NO_PAD.encode([1u8; 32]),
        );
        assert!(holder_pseudonym_secrets(&cred).is_err());
    }
}
