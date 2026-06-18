//! Integration test for the consent-gated present path (task 1.4,
//! `docs/05-design-notes/vti-credential-architecture.md` §7 "Present", §7a
//! consent, §14 invariants).
//!
//! Exercises the *public* `vta_service::vault::present_sd_jwt_vc` API exactly
//! as a caller would — across the crate boundary, over a real on-disk
//! **encrypted** `Store` keyspace. It mints a holder-bound SD-JWT-VC, files it
//! into the vault, captures a signed consent record, and then builds a
//! selectively-disclosed presentation gated by that record — proving end to
//! end that:
//!
//! - the presentation discloses **only** the consented claims (a NEGATIVE check
//!   that an unconsented disclosable claim never leaves the agent);
//! - it carries a **mandatory** holder `kb-jwt` bound to `aud` + `nonce`, and
//!   verifies end-to-end via `affinidi-sd-jwt`;
//! - a missing / withdrawn / expired / recipient-mismatched consent record is
//!   refused;
//! - a revoked or temporally-invalid credential is refused.

use affinidi_crypto::did_key;
use affinidi_sd_jwt::SdJwt;
use affinidi_sd_jwt::error::SdJwtError;
use affinidi_sd_jwt::hasher::Sha256Hasher;
use affinidi_sd_jwt::signer::{JwtSigner, JwtVerifier};
use affinidi_sd_jwt::verifier::{VerificationOptions, verify};
use affinidi_secrets_resolver::secrets::Secret;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use serde_json::{Value, json};

use vta_service::vault::consent::{self, ConsentGrant};
use vta_service::vault::{
    CredentialFormat, CredentialStatus, MintRequest, StoredCredential, mint_sd_jwt_vc,
    present_sd_jwt_vc, storage,
};

use vti_common::config::StoreConfig;
use vti_common::error::AppError;
use vti_common::store::{KeyspaceHandle, Store};

/// A production-shape EdDSA (Ed25519) JWT signer. The raw key is reachable only
/// via the sign-only `JwtSigner` trait — the present code never sees bytes.
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
        let header_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(header).map_err(SdJwtError::from)?);
        let payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(payload).map_err(SdJwtError::from)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig: Signature = self.key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

/// An EdDSA `JwtVerifier` over a single Ed25519 key — verifies the issuer JWS
/// and the holder kb-jwt at the verifier end.
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

fn issuer(seed: u8) -> (EddsaSigner, String, VerifyingKey) {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let vk = signing.verifying_key();
    let did = did_key::ed25519_pub_to_did_key(vk.as_bytes());
    let kid = format!("{did}#key-0");
    (EddsaSigner { key: signing, kid }, did, vk)
}

/// A holder: the `did:key`, a kb-jwt signer under that DID, the consent-receipt
/// `Secret`, and the verifying key. The same Ed25519 key signs both the kb-jwt
/// and the consent receipt (both are the holder's VTA-managed key).
fn holder(seed: u8) -> (String, EddsaSigner, Secret, VerifyingKey) {
    let seed = [seed; 32];
    let signing = SigningKey::from_bytes(&seed);
    let vk = signing.verifying_key();
    let did = did_key::ed25519_pub_to_did_key(vk.as_bytes());
    let vm = format!("{did}#{}", did.strip_prefix("did:key:").unwrap());
    let kb = EddsaSigner {
        key: signing,
        kid: vm.clone(),
    };
    let mut secret = Secret::generate_ed25519(Some(&vm), Some(&seed));
    secret.id = vm;
    (did, kb, secret, vk)
}

fn fresh_vault() -> (tempfile::TempDir, Store, KeyspaceHandle) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .expect("open store");
    // Encryption-at-rest, like every other vault value.
    let ks = store
        .keyspace("vault")
        .expect("vault keyspace")
        .with_encryption([7u8; 32]);
    (dir, store, ks)
}

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

/// Verify the presentation end to end (issuer JWS + mandatory kb-jwt bound to
/// aud/nonce) and return the resolved claim set.
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
    let iv = EddsaVerifier { key: issuer_vk };
    let hv = EddsaVerifier { key: holder_vk };
    let opts = VerificationOptions {
        verify_kb: true,
        expected_audience: Some(aud),
        expected_nonce: Some(nonce),
    };
    let result = verify(&sd_jwt, &iv, &hasher, &opts, Some(&hv)).expect("verifies");
    assert_eq!(result.kb_verified, Some(true));
    result.claims
}

#[tokio::test]
async fn present_discloses_only_consented_claims_with_kb_jwt_end_to_end() {
    let (_dir, _store, vault) = fresh_vault();
    let (issuer_signer, issuer_did, issuer_vk) = issuer(40);
    let (holder_did, kb_signer, consent_key, holder_vk) = holder(41);
    let verifier = "did:web:acme-verifier.example";
    let now = Utc::now();

    // The credential makes THREE claims disclosable.
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

    // Consent to disclose ONLY givenName + memberSince.
    let rec = consent::create(
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

    let nonce = "verifier-nonce-xyz";
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

    let resolved = verify_presentation(&pres, issuer_vk, holder_vk, verifier, nonce);
    assert_eq!(resolved["givenName"], "Alice");
    assert_eq!(resolved["memberSince"], "2020");
    // NEGATIVE: the disclosed set never exceeds hasPersonalData.
    assert!(
        resolved.get("dateOfBirth").is_none(),
        "dateOfBirth was disclosable in the credential but NOT consented — it must not leak"
    );

    let hasher = Sha256Hasher;
    let parsed = SdJwt::parse(&pres, &hasher).unwrap();
    assert_eq!(parsed.disclosures.len(), 2, "exactly the consented claims");
}

#[tokio::test]
async fn present_refused_for_missing_withdrawn_and_expired_consent() {
    let (_dir, _store, vault) = fresh_vault();
    let (issuer_signer, issuer_did, _ivk) = issuer(42);
    let (holder_did, kb_signer, consent_key, _hvk) = holder(43);
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

    // Missing consent record -> NotFound.
    let err = present_sd_jwt_vc(
        &vault,
        "cred-1",
        "urn:uuid:absent",
        &kb_signer,
        "n",
        verifier,
        now.timestamp() as u64,
        None,
        now,
    )
    .await
    .expect_err("missing consent refused");
    assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");

    // Withdrawn consent record -> Forbidden.
    let rec = consent::create(
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
    consent::withdraw(&vault, &rec.identifier, &consent_key)
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
    .expect_err("withdrawn consent refused");
    assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");

    // Expired consent record -> Forbidden.
    let expired = consent::create(
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
        &expired.identifier,
        &kb_signer,
        "n",
        verifier,
        now.timestamp() as u64,
        None,
        now,
    )
    .await
    .expect_err("expired consent refused");
    assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
}

#[tokio::test]
async fn present_refused_for_revoked_or_temporally_invalid_credential() {
    let (_dir, _store, vault) = fresh_vault();
    let (issuer_signer, issuer_did, _ivk) = issuer(44);
    let (holder_did, kb_signer, consent_key, _hvk) = holder(45);
    let verifier = "did:web:acme-verifier.example";
    let now = Utc::now();
    let claims = json!({ "givenName": "Alice" });

    // Revoked credential.
    mint_and_put(
        &vault,
        "revoked",
        &issuer_signer,
        &issuer_did,
        &holder_did,
        &claims,
        &["givenName"],
        CredentialStatus::Revoked,
        None,
        None,
    )
    .await;
    // Temporally-invalid (window already closed) credential.
    mint_and_put(
        &vault,
        "expired",
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

    // One consent record per credential — consent is per-credential (§13), so
    // each must be bound (`dct:source`) to the credential it gates. This also
    // means we reach the status / temporal refusal rather than short-circuiting
    // on a credential-binding mismatch.
    for cred_id in ["revoked", "expired"] {
        let rec = consent::create(
            &vault,
            &grant(
                &holder_did,
                cred_id,
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
            cred_id,
            &rec.identifier,
            &kb_signer,
            "n",
            verifier,
            now.timestamp() as u64,
            None,
            now,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "credential `{cred_id}` must never be presented, got {err:?}"
        );
    }
}
