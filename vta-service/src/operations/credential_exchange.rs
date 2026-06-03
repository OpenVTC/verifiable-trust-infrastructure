//! Holder-side credential-exchange operations (Phase 3, spec §6) — the VTA
//! receiving an issued credential and storing it in its credential vault.
//!
//! This is the **credential vault's first wire exposure**: a
//! `credential-exchange/issue` message ([`vta_sdk::protocols::credential_exchange`])
//! carries an OID4VCI credential response, and [`receive_issued_credential`]
//! infers the format and stores it through the format-agnostic
//! [`crate::vault::receive`] (SD-JWT-VC + W3C Data-Integrity, from tasks 3.1a/3.1b).
//!
//! ## Scope of this slice
//! - **SD-JWT-VC** — fully wired (the issuer `did:key` is resolved inside
//!   `receive`).
//! - **W3C Data-Integrity** from a **`did:key`** issuer — fully wired.
//! - A DI VC from a **`did:webvh` / `did:web`** issuer needs resolver-based
//!   issuer-key resolution — a follow-up slice (the VTC issues under
//!   `did:webvh`, so this lands next).
//! - A **`sealed`** bundle (the unknown-holder / invite case) is deferred to the
//!   sealed-issuance slice (3.6).

use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;
use vta_sdk::protocols::credential_exchange::IssueBody;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::vault::model::{CredentialFormat, StoredCredential};
use crate::vault::{self};

/// Receive a credential delivered in a credential-exchange `issue` message into
/// the holder's `vault`. Infers the credential format from the body, resolves
/// the issuer DID for the Data-Integrity path, and stores via the
/// format-agnostic [`vault::receive`]. Returns the persisted credential.
///
/// `source` is recorded as the stored credential's provenance (e.g. the exchange
/// thread id or the authenticated issuer DID). `now` anchors the temporal check.
pub async fn receive_issued_credential(
    vault_ks: &KeyspaceHandle,
    issue: &IssueBody,
    source: Option<String>,
    now: DateTime<Utc>,
) -> Result<StoredCredential, AppError> {
    if issue.sealed.is_some() {
        return Err(AppError::Validation(
            "sealed credential issuance (unknown-holder / invite) is not yet wired \
             (sealed-issuance slice 3.6)"
                .into(),
        ));
    }

    let credential = issue
        .credential_response
        .as_ref()
        .and_then(|r| r.credential.as_ref())
        .ok_or_else(|| AppError::Validation("issue message carries no credential".to_string()))?;

    let id = format!("urn:uuid:{}", Uuid::new_v4());

    match credential {
        // A JSON string → SD-JWT-VC compact serialization; `receive` resolves the
        // issuer `did:key` internally.
        Value::String(compact) => {
            vault::receive(
                vault_ks,
                &id,
                &CredentialFormat::SdJwtVc,
                compact.as_bytes(),
                None,
                source,
                now,
            )
            .await
        }
        // A JSON object carrying a `proof` → a W3C Data-Integrity VC. Resolve the
        // issuer DID to its key and store via the DI path.
        Value::Object(_) if credential.get("proof").is_some() => {
            let issuer_did = credential
                .get("issuer")
                .and_then(issuer_str)
                .ok_or_else(|| {
                    AppError::Validation("Data-Integrity credential has no `issuer`".to_string())
                })?;
            let issuer_pub = resolve_issuer_ed25519(&issuer_did)?;
            let body = serde_json::to_vec(credential)
                .map_err(|e| AppError::Internal(format!("credential -> bytes: {e}")))?;
            vault::receive(
                vault_ks,
                &id,
                &CredentialFormat::EddsaJcs2022,
                &body,
                Some(&issuer_pub),
                source,
                now,
            )
            .await
        }
        _ => Err(AppError::Validation(
            "unrecognised credential in issue message (expected an SD-JWT-VC string or a \
             W3C Data-Integrity VC object with a `proof`)"
                .to_string(),
        )),
    }
}

/// The issuer DID from a VC `issuer` field — a string, or an object with `id`.
fn issuer_str(issuer: &Value) -> Option<String> {
    issuer
        .as_str()
        .map(str::to_string)
        .or_else(|| issuer.get("id").and_then(Value::as_str).map(str::to_string))
}

/// Resolve an issuer DID to its Ed25519 public key bytes.
///
/// `did:key` is resolved locally. Resolver-based resolution of `did:webvh` /
/// `did:web` issuers (via the app-state DID resolver) is a follow-up slice.
fn resolve_issuer_ed25519(did: &str) -> Result<Vec<u8>, AppError> {
    if did.starts_with("did:key:") {
        affinidi_crypto::did_key::did_key_to_ed25519_pub(did)
            .map(|k| k.to_vec())
            .map_err(|e| {
                AppError::Validation(format!("issuer `{did}` is not a resolvable did:key: {e}"))
            })
    } else {
        Err(AppError::Validation(format!(
            "resolving a non-did:key issuer (`{did}`) needs the DID resolver — a follow-up \
             slice; SD-JWT-VC and did:key Data-Integrity issuers are wired"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_sd_jwt::error::SdJwtError;
    use affinidi_sd_jwt::signer::JwtSigner;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn fresh_vault() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("vault").unwrap();
        (dir, store, ks)
    }

    /// A minimal Ed25519 issuer whose DID is the `did:key` for its key.
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
            let h = URL_SAFE_NO_PAD.encode(serde_json::to_string(header)?.as_bytes());
            let p = URL_SAFE_NO_PAD.encode(serde_json::to_string(payload)?.as_bytes());
            let input = format!("{h}.{p}");
            let sig: Signature = self.key.sign(input.as_bytes());
            Ok(format!(
                "{input}.{}",
                URL_SAFE_NO_PAD.encode(sig.to_bytes())
            ))
        }
    }

    /// Build an `IssueBody` from JSON (avoids depending on the openid4vci crate
    /// in the test — the handler-side serde is what production exercises anyway).
    fn issue_body(credential: Value, sealed: Option<String>) -> IssueBody {
        let mut obj = serde_json::Map::new();
        match sealed {
            Some(s) => {
                obj.insert("sealed".into(), json!(s));
            }
            None => {
                obj.insert(
                    "credential_response".into(),
                    json!({ "credential": credential }),
                );
            }
        }
        serde_json::from_value(Value::Object(obj)).expect("build IssueBody")
    }

    #[tokio::test]
    async fn stores_an_issued_sd_jwt_vc() {
        let (_dir, _store, vault) = fresh_vault();

        // Mint a real SD-JWT-VC from a did:key issuer.
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let did =
            affinidi_crypto::did_key::ed25519_pub_to_did_key(signing.verifying_key().as_bytes());
        let signer = EddsaSigner {
            key: signing,
            kid: format!("{did}#key-0"),
        };
        // The subject is a real did:key (the mint binds it as `cnf`).
        let subject = affinidi_crypto::did_key::ed25519_pub_to_did_key(
            SigningKey::from_bytes(&[5u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let compact = crate::vault::mint::mint_sd_jwt_vc(
            &crate::vault::mint::MintRequest {
                vct: "https://openvtc.org/credentials/MembershipCredential",
                issuer_did: &did,
                subject_did: &subject,
                claims: &json!({ "givenName": "Alice" }),
                disclosable: &["givenName"],
                iat: 1_700_000_000,
                exp: Some(1_900_000_000),
            },
            &signer,
        )
        .expect("mint SD-JWT-VC");

        let body = issue_body(Value::String(compact), None);
        let cred = receive_issued_credential(&vault, &body, Some("thread-1".into()), Utc::now())
            .await
            .expect("receive issued SD-JWT-VC");
        assert_eq!(cred.format, CredentialFormat::SdJwtVc);
        assert_eq!(cred.subject_did.as_deref(), Some(subject.as_str()));
        assert!(
            crate::vault::storage::get(&vault, &cred.id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn refuses_a_sealed_bundle_for_now() {
        let (_dir, _store, vault) = fresh_vault();
        let body = issue_body(Value::Null, Some("-----BEGIN VTA SEALED-----…".into()));
        let err = receive_issued_credential(&vault, &body, None, Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }

    #[tokio::test]
    async fn refuses_a_di_vc_from_a_non_did_key_issuer_for_now() {
        let (_dir, _store, vault) = fresh_vault();
        // A DI VC (object + proof) from a did:web issuer → resolver path deferred.
        let vc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": "did:web:issuer.example",
            "credentialSubject": { "id": "did:key:zMember" },
            "proof": { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022" }
        });
        let err = receive_issued_credential(&vault, &issue_body(vc, None), None, Utc::now())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("did:key")),
            "expected a did:key follow-up error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn refuses_an_empty_issue() {
        let (_dir, _store, vault) = fresh_vault();
        let empty = IssueBody {
            credential_response: None,
            sealed: None,
        };
        let err = receive_issued_credential(&vault, &empty, None, Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }
}
