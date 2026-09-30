//! Integration test for the credential-vault receive path (task 1.2,
//! `docs/05-design-notes/vti-credential-architecture.md` §5).
//!
//! Exercises the *public* `vta_service::vault::receive_sd_jwt_vc` API exactly
//! as a caller would: issue a real Ed25519-signed SD-JWT-VC, receive it into a
//! fresh on-disk vault, and assert it is stored + findable via the task-1.1
//! index — then assert the two security-critical rejection paths (tampered
//! signature, expired credential) reject *and store nothing*.
//!
//! This complements the in-module unit tests by going through the crate
//! boundary (`vault::receive_sd_jwt_vc`, `vault::find_by_index`,
//! `vault::IndexField`) and a real `Store`, proving the write path is wired
//! end-to-end.

use affinidi_sd_jwt::hasher::Sha256Hasher;
use affinidi_sd_jwt::signer::JwtSigner;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde_json::{Value, json};
use vta_service::vault::{self, CredentialFormat, CredentialPurpose, CredentialStatus, IndexField};

use vti_common::config::StoreConfig;
use vti_common::store::{KeyspaceHandle, Store};

/// A production-shape EdDSA (Ed25519) JWT signer for issuing test credentials.
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

fn fresh_vault() -> (tempfile::TempDir, Store, KeyspaceHandle) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .expect("open store");
    let ks = store.keyspace("vault").expect("vault keyspace");
    (dir, store, ks)
}

/// An issuer whose DID is the real `did:key` for its Ed25519 key.
fn issuer() -> (EddsaSigner, String) {
    let signing = SigningKey::from_bytes(&[42u8; 32]);
    let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(signing.verifying_key().as_bytes());
    let kid = format!("{did}#key-0");
    (EddsaSigner { key: signing, kid }, did)
}

fn issue_invitation(signer: &EddsaSigner, issuer_did: &str, iat: u64, exp: Option<u64>) -> String {
    let hasher = Sha256Hasher;
    let claims = json!({ "community": "did:web:acme.example", "seat": "founding" });
    let frame = json!({ "_sd": ["community", "seat"] });
    affinidi_sd_jwt_vc::issue(
        "https://openvtc.org/credentials/InvitationCredential",
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
    .expect("issue SD-JWT-VC")
    .serialize()
}

#[tokio::test]
async fn valid_credential_is_stored_and_findable_by_type_and_issuer() {
    let (_dir, _store, vault) = fresh_vault();
    let (signer, did) = issuer();
    let compact = issue_invitation(&signer, &did, 1_700_000_000, Some(1_900_000_000));

    let stored = vault::receive_sd_jwt_vc(
        &vault,
        "inv-1",
        &compact,
        Some("link:qr-onboarding".into()),
        1_800_000_000,
    )
    .await
    .expect("valid credential received");

    assert_eq!(stored.format, CredentialFormat::SdJwtVc);
    assert_eq!(stored.purpose, Some(CredentialPurpose::Invite));
    assert_eq!(stored.status, CredentialStatus::Valid);
    assert_eq!(stored.issuer_did.as_deref(), Some(did.as_str()));

    // Findable by type (task-1.1 index).
    let by_type = vault::find_by_index(
        &vault,
        IndexField::Type,
        "https://openvtc.org/credentials/InvitationCredential",
    )
    .await
    .unwrap();
    assert_eq!(by_type.len(), 1);
    assert_eq!(by_type[0].id, "inv-1");

    // Findable by issuer DID.
    let by_issuer = vault::find_by_index(&vault, IndexField::IssuerDid, &did)
        .await
        .unwrap();
    assert_eq!(by_issuer.len(), 1);
    assert_eq!(by_issuer[0].id, "inv-1");

    // Findable by purpose.
    let by_purpose = vault::find_by_index(&vault, IndexField::Purpose, "invite")
        .await
        .unwrap();
    assert_eq!(by_purpose.len(), 1);
}

#[tokio::test]
async fn tampered_credential_is_rejected_and_not_stored() {
    let (_dir, _store, vault) = fresh_vault();
    let (signer, did) = issuer();
    let compact = issue_invitation(&signer, &did, 1_700_000_000, Some(1_900_000_000));

    // Corrupt a byte inside the issuer JWS (the segment before the first `~`).
    let mut chars: Vec<char> = compact.chars().collect();
    let tilde = compact.find('~').expect("disclosures present");
    let pos = tilde - 1;
    chars[pos] = if chars[pos] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();

    let err = vault::receive_sd_jwt_vc(&vault, "inv-bad", &tampered, None, 1_800_000_000)
        .await
        .expect_err("tampered credential rejected");
    assert!(matches!(err, vti_common::error::AppError::Validation(_)));

    // Nothing stored, no index rows.
    assert!(vault::get(&vault, "inv-bad").await.unwrap().is_none());
    assert!(
        vault::find_by_index(&vault, IndexField::IssuerDid, &did)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn expired_credential_is_rejected_and_not_stored() {
    let (_dir, _store, vault) = fresh_vault();
    let (signer, did) = issuer();
    let compact = issue_invitation(&signer, &did, 1_700_000_000, Some(1_701_000_000));

    let err = vault::receive_sd_jwt_vc(&vault, "inv-exp", &compact, None, 1_900_000_000)
        .await
        .expect_err("expired credential rejected");
    assert!(matches!(err, vti_common::error::AppError::Validation(_)));

    assert!(vault::get(&vault, "inv-exp").await.unwrap().is_none());
    assert!(
        vault::find_by_index(
            &vault,
            IndexField::Type,
            "https://openvtc.org/credentials/InvitationCredential"
        )
        .await
        .unwrap()
        .is_empty()
    );
}
