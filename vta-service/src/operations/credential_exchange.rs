//! Holder-side credential-exchange operations (Phase 3, spec §6) — the VTA's
//! side of `credential-exchange/*`: receiving issued credentials and answering
//! a verifier's DCQL query against the held vault.
//!
//! - [`receive_issued_credential`] (task 3.3) — the **credential vault's first
//!   wire exposure**: a `credential-exchange/issue` message
//!   ([`vta_sdk::protocols::credential_exchange`]) carries an OID4VCI credential
//!   response, and this infers the format and stores it through the
//!   format-agnostic [`crate::vault::receive`] (SD-JWT-VC + W3C Data-Integrity,
//!   tasks 3.1a/3.1b).
//! - [`match_held`] (task 3.5, query→match half) — runs a verifier's DCQL query
//!   locally over the held credentials, returning which satisfy it and the claim
//!   paths to disclose. The consent gate + selectively-disclosed `present` that
//!   turns a match into a `vp_token` is the next slice.
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

use affinidi_openid4vp::{CandidateCredential, ClaimPathSegment, DcqlQuery, Oid4vpError};
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

// ── Holder-side DCQL match (Phase 3, task 3.5: query → match) ──
//
// A verifier's `credential-exchange/query` carries a DCQL query; the holder
// runs it **locally** over its own vault and learns which held credentials
// satisfy it (and which claim paths the query asks to disclose). This is the
// read/match half — the consent gate + selectively-disclosed `present` that
// turns a match into a `vp_token` is the next slice.

/// One held credential that satisfied a credential query, with the claim paths
/// the query asked to disclose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldMatch {
    /// The DCQL `CredentialQuery.id` that matched.
    pub credential_query_id: String,
    /// The local vault id of the [`StoredCredential`] that satisfied it.
    pub credential_id: String,
    /// The claim paths to disclose, each rendered segment-by-segment
    /// (`Name` → the name, `Index` → `[i]`, `Wildcard` → `[*]`). **Empty** when
    /// the query named no `claims` (disclose per the holder's own policy).
    pub disclosed_paths: Vec<Vec<String>>,
}

/// Run a verifier's DCQL `query` over the holder's `held` credentials, returning
/// the matches (which credential satisfied which query, and the claim paths to
/// disclose). The query is validated first (it came off the wire). Credentials
/// in a format not yet presentable via DCQL are skipped, not errored.
///
/// An **empty** result means the holder has nothing that satisfies the query —
/// a legitimate outcome (the verifier gets a "no presentation" answer), distinct
/// from an `Err` (a malformed query or an unparseable stored body).
pub fn match_held(
    query: &DcqlQuery,
    held: &[StoredCredential],
) -> Result<Vec<HeldMatch>, AppError> {
    query
        .validate()
        .map_err(|e| AppError::Validation(format!("invalid DCQL query: {e}")))?;

    let mut candidates = Vec::with_capacity(held.len());
    for stored in held {
        if let Some(candidate) = candidate_from_stored(stored)? {
            candidates.push(candidate);
        }
    }

    let matched = match query.match_credentials(&candidates) {
        Ok(matched) => matched,
        // "Nothing the holder holds satisfies the request" — not an error here.
        Err(Oid4vpError::NoMatchingCredentials(_)) => return Ok(Vec::new()),
        Err(e) => return Err(AppError::Validation(format!("DCQL match failed: {e}"))),
    };

    Ok(matched
        .matches
        .into_iter()
        .map(|m| HeldMatch {
            credential_query_id: m.credential_query_id,
            credential_id: m.candidate_id,
            disclosed_paths: m.disclosed_paths.into_iter().map(render_path).collect(),
        })
        .collect())
}

/// Build a DCQL [`CandidateCredential`] from a stored credential by parsing its
/// body for the claims tree. Returns `None` for formats not yet presentable via
/// DCQL (`Zkp` / `Other`).
fn candidate_from_stored(
    stored: &StoredCredential,
) -> Result<Option<CandidateCredential>, AppError> {
    let Some(format) = dcql_format(&stored.format) else {
        return Ok(None);
    };

    let (claims, vct, supports_holder_binding) = match stored.format {
        CredentialFormat::SdJwtVc => {
            let compact = std::str::from_utf8(&stored.body).map_err(|e| {
                AppError::Validation(format!("credential `{}` is not UTF-8: {e}", stored.id))
            })?;
            let hasher = affinidi_sd_jwt::hasher::Sha256Hasher;
            let sd = affinidi_sd_jwt::SdJwt::parse(compact, &hasher).map_err(|e| {
                AppError::Validation(format!("credential `{}` is not SD-JWT-VC: {e}", stored.id))
            })?;
            let payload = sd.payload().map_err(|e| {
                AppError::Validation(format!("credential `{}` payload: {e}", stored.id))
            })?;
            let claims = affinidi_sd_jwt::holder::resolve_claims(&payload, &sd.disclosures)
                .map_err(|e| {
                    AppError::Validation(format!("credential `{}` claims: {e}", stored.id))
                })?;
            let vct = payload
                .get("vct")
                .and_then(Value::as_str)
                .map(str::to_string);
            // SD-JWT-VC carries holder binding via the `cnf` confirmation claim.
            let holder_binding = payload.get("cnf").is_some();
            (claims, vct, holder_binding)
        }
        CredentialFormat::EddsaJcs2022 | CredentialFormat::Bbs2023 => {
            // The claims tree is the whole VC object — a verifier path walks it
            // (e.g. `["credentialSubject","givenName"]`). Our DI present builds a
            // holder-bound VP, so holder binding is supported.
            let vc: Value = serde_json::from_slice(&stored.body).map_err(|e| {
                AppError::Validation(format!("credential `{}` is not JSON: {e}", stored.id))
            })?;
            (vc, None, true)
        }
        // Unreachable: `dcql_format` returned `Some` only for the arms above.
        CredentialFormat::Zkp | CredentialFormat::Other(_) => return Ok(None),
    };

    Ok(Some(CandidateCredential {
        id: stored.id.clone(),
        format: format.to_string(),
        claims,
        vct,
        doctype: None,
        supports_holder_binding,
    }))
}

/// Map a stored credential format to its DCQL `format` selector, or `None` if
/// the format is not yet presentable via DCQL.
fn dcql_format(format: &CredentialFormat) -> Option<&'static str> {
    match format {
        CredentialFormat::SdJwtVc => Some("dc+sd-jwt"),
        CredentialFormat::EddsaJcs2022 | CredentialFormat::Bbs2023 => Some("ldp_vc"),
        CredentialFormat::Zkp | CredentialFormat::Other(_) => None,
    }
}

/// Render a DCQL claim path's segments as strings for [`HeldMatch`].
fn render_path(path: Vec<ClaimPathSegment>) -> Vec<String> {
    path.into_iter()
        .map(|seg| match seg {
            ClaimPathSegment::Name(name) => name,
            ClaimPathSegment::Index(i) => format!("[{i}]"),
            ClaimPathSegment::Wildcard => "[*]".to_string(),
        })
        .collect()
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

    // ── DCQL match (task 3.5) ──

    const MEMBERSHIP_VCT: &str = "https://openvtc.org/credentials/MembershipCredential";

    /// Mint a real SD-JWT-VC and store it in `vault`, returning the
    /// `StoredCredential` (the holder's vault entry).
    async fn mint_and_store(vault: &KeyspaceHandle) -> StoredCredential {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let did =
            affinidi_crypto::did_key::ed25519_pub_to_did_key(signing.verifying_key().as_bytes());
        let signer = EddsaSigner {
            key: signing,
            kid: format!("{did}#key-0"),
        };
        let subject = affinidi_crypto::did_key::ed25519_pub_to_did_key(
            SigningKey::from_bytes(&[5u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let compact = crate::vault::mint::mint_sd_jwt_vc(
            &crate::vault::mint::MintRequest {
                vct: MEMBERSHIP_VCT,
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
        let cred = receive_issued_credential(vault, &body, None, Utc::now())
            .await
            .expect("receive");
        crate::vault::storage::get(vault, &cred.id)
            .await
            .unwrap()
            .expect("stored")
    }

    #[tokio::test]
    async fn matches_a_held_sd_jwt_vc_by_vct_and_discloses_the_named_claim() {
        let (_dir, _store, vault) = fresh_vault();
        let stored = mint_and_store(&vault).await;

        let query = DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "membership",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": [MEMBERSHIP_VCT] },
                "claims": [{ "path": ["givenName"] }]
            }]
        }))
        .unwrap();

        let matches = match_held(&query, std::slice::from_ref(&stored)).expect("match");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].credential_query_id, "membership");
        assert_eq!(matches[0].credential_id, stored.id);
        assert_eq!(
            matches[0].disclosed_paths,
            vec![vec!["givenName".to_string()]]
        );
    }

    #[tokio::test]
    async fn does_not_match_a_different_vct() {
        let (_dir, _store, vault) = fresh_vault();
        let stored = mint_and_store(&vault).await;

        let query = DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "x",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.org/Other"] }
            }]
        }))
        .unwrap();

        assert!(match_held(&query, &[stored]).unwrap().is_empty());
    }

    #[tokio::test]
    async fn skips_not_yet_presentable_formats_without_erroring() {
        let (_dir, _store, vault) = fresh_vault();
        let mut zkp = mint_and_store(&vault).await;
        // A ZKP credential isn't presentable via DCQL yet — it must be skipped,
        // not error the whole match.
        zkp.format = CredentialFormat::Zkp;

        let query = DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "membership",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": [MEMBERSHIP_VCT] }
            }]
        }))
        .unwrap();

        // Skipped → no candidates → no match, but Ok (not Err).
        assert!(match_held(&query, &[zkp]).unwrap().is_empty());
    }
}
