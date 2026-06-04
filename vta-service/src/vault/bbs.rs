//! BBS+ (`bbs-2023`) credential support for the vault — feature-gated `bbs`.
//!
//! The vault's SD-JWT-VC / eddsa-jcs-2022 paths are always built; BBS pulls in
//! the BLS12-381 curve (`affinidi-bbs`) + the `bbs-2023` Data-Integrity
//! cryptosuite, so it lives behind the `bbs` feature. The document-level
//! sign/derive/verify is delegated to
//! [`affinidi_data_integrity::bbs_2023`] — per the workspace principle, proof
//! handling is the library's job, not hand-rolled here.
//!
//! ## Scope (audit gate)
//!
//! The VTA is a credential **holder/verifier**, not an issuer, so issuer
//! *signing* (`sign_vc_base`) is deliberately **not** exposed from this module
//! — BBS issuance stays audit-gated. This module covers **receive** (verify the
//! issuer's base proof, then store) plus issuer-key resolution. The holder
//! **present** (selective-disclosure derive) lands in a follow-up.

use affinidi_bbs::PublicKey;
use affinidi_data_integrity::bbs_2023;
use chrono::{DateTime, Utc};
use serde_json::Value;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::model::{CredentialFormat, CredentialStatus, StoredCredential};
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

    // Verify the issuer base proof before trusting any bytes. The empty pointer
    // `""` is a prefix of every claim pointer, so this discloses everything; a
    // full-disclosure derived proof verifies iff the base signature is valid.
    const BASE_CHECK_NONCE: &[u8] = b"vta-vault-base-check";
    let full = bbs_2023::derive_vc(&vc, &[""], BASE_CHECK_NONCE, &pk)
        .map_err(|e| AppError::Validation(format!("BBS base proof is malformed: {e}")))?;
    if !bbs_2023::verify_vc_derived(&full, BASE_CHECK_NONCE, &pk)
        .map_err(|e| AppError::Validation(format!("BBS base proof verification failed: {e}")))?
    {
        return Err(AppError::Validation(
            "BBS issuer base proof did not verify".to_string(),
        ));
    }

    // Temporal validity over W3C VC 2.0 `validFrom` / `validUntil`.
    di_temporal_valid(&vc, now)?;

    // --- map verified VC → StoredCredential envelope (mirrors receive_di_vc) ---
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
    };
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

    let derived = bbs_2023::derive_vc(&vc, &selective_refs, nonce.as_bytes(), &pk)
        .map_err(|e| AppError::Validation(format!("BBS selective disclosure failed: {e}")))?;
    serde_json::to_string(&derived)
        .map_err(|e| AppError::Internal(format!("serialise BBS presentation: {e}")))
}

/// RFC 6901 token escaping (`~` -> `~0`, `/` -> `~1`) for a claim name embedded
/// in a JSON pointer.
fn rfc6901_escape(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_bbs as bbs;
    use affinidi_data_integrity::bbs_2023::sign_vc_base;
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    const MANDATORY: &[&str] = &["/@context", "/type", "/issuer", "/credentialSubject/id"];

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
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": did,
            "validFrom": "2020-01-01T00:00:00Z",
            "credentialSubject": { "id": "did:key:zMember", "givenName": "Alice", "memberLevel": "gold" }
        });
        if let Some(u) = valid_until {
            vc["validUntil"] = json!(u);
        }
        let vm = format!("{did}#bbs-key-0");
        let signed = sign_vc_base(&vc, MANDATORY, &vm, &sk, &pk).unwrap();
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
}
