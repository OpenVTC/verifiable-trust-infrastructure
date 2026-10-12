//! The VTC's OpenID4VP **verifier identities** — the identities it presents to
//! swiyu and EUDI wallets when they present credentials to it (#1988).
//!
//! A verifier identity is not the community's own DID. swiyu wallets accept a
//! request object signed by a P-256 key of a DID registered in the swiyu Base
//! Registry and shaped by the Swiss Profile Anchor (the `swiyu-verifier` DID
//! template); EUDI wallets accept one signed by the key of an X.509 access
//! certificate. Neither is the Ed25519 identity the VTC signs credentials
//! with, so neither key may reach [`crate::credentials::LocalSigner`] — every
//! key there puts a proof on every credential this community issues.
//!
//! # Custody
//!
//! The VTA mints and custodies the key, as it does every key this VTC holds;
//! the VTC caches it and signs locally, so a wallet's request never waits on
//! the VTA. It arrives as a sealed transfer bundle the operator relays
//! (`vtc oid4vp request` → `pnm keys bundle` → `vtc oid4vp install`), and lives
//! here in the `oid4vp_keys` keyspace, encrypted at rest under the same storage
//! key as `install` and `passkey`. A deployment that wants the key never to
//! leave the VTA will use `keys/sign-jws` instead, behind the same
//! [`VerifierSigner`] trait — see `docs/05-design-notes/oid4vp-wallet-verifier.md`.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vti_common::error::AppError;

use crate::store::KeyspaceHandle;

pub mod session;
pub mod wallet;
pub mod x509;

/// How a verifier identity is known to wallets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerifierKind {
    /// A swiyu verifier: `client_id = decentralized_identifier:<did>`, the
    /// request object's `kid` a DID URL under that DID.
    Swiyu,
    /// An EUDI verifier: `client_id = x509_hash:<SHA-256 of the access
    /// certificate>`, the request object carrying that certificate's chain as
    /// `x5c`. It has no DID.
    Eudi,
}

/// One verifier identity, as stored. The private key is held as the
/// multibase string the VTA sealed it in; everything else is public.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifierIdentityRecord {
    /// The operator's name for the identity, e.g. `swiyu`.
    pub id: String,
    pub kind: VerifierKind,
    /// The identity's DID — a swiyu identity's only. An EUDI identity is
    /// known by its certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    /// The verification method that signs request objects — a swiyu
    /// identity's JAR `kid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// The signing key's public half (as a swiyu DID publishes it,
    /// `publicKeyJwk`).
    pub public_jwk: Value,
    /// The signing key's private half: multibase, `p256-priv` multicodec.
    pub private_key_multibase: String,
    /// An EUDI identity's access certificate and the chain above it, leaf
    /// first, each standard base64 DER — the JAR's `x5c`. Absent until
    /// `vtc oid4vp certificate` installs what the registrar issued, and until
    /// then the identity opens no session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    /// Attestations about the verifier carried in every request's
    /// `verifier_info` — an EUDI registration certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_info: Option<Vec<Value>>,
    /// When it was installed, seconds since the epoch.
    pub installed_at: u64,
}

impl std::fmt::Debug for VerifierIdentityRecord {
    /// Written by hand so the private key never reaches a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifierIdentityRecord")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("did", &self.did)
            .field("kid", &self.kid)
            .field("x5c", &self.x5c.as_ref().map(Vec::len))
            .field("private_key_multibase", &"<redacted>")
            .finish()
    }
}

impl VerifierIdentityRecord {
    /// The OpenID4VP client identifier, prefix included — `None` while an
    /// EUDI identity has no certificate.
    pub fn client_id(&self) -> Option<String> {
        match self.kind {
            VerifierKind::Swiyu => self
                .did
                .as_ref()
                .map(|did| format!("decentralized_identifier:{did}")),
            VerifierKind::Eudi => {
                let leaf = self.x5c.as_ref()?.first()?;
                let der = base64::engine::general_purpose::STANDARD
                    .decode(leaf)
                    .ok()?;
                Some(affinidi_openid4vp::ClientId::x509_hash(&der).to_string())
            }
        }
    }
}

const KEY_PREFIX: &str = "identity:";

fn storage_key(id: &str) -> String {
    format!("{KEY_PREFIX}{id}")
}

/// Store (or replace) a verifier identity.
pub async fn put_identity(
    ks: &KeyspaceHandle,
    record: &VerifierIdentityRecord,
) -> Result<(), AppError> {
    ks.insert(storage_key(&record.id), record).await
}

/// Read one verifier identity.
pub async fn get_identity(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<VerifierIdentityRecord>, AppError> {
    ks.get(storage_key(id)).await
}

/// Remove a verifier identity. Returns whether one was there.
pub async fn delete_identity(ks: &KeyspaceHandle, id: &str) -> Result<bool, AppError> {
    let existed = get_identity(ks, id).await?.is_some();
    if existed {
        ks.remove(storage_key(id)).await?;
    }
    Ok(existed)
}

/// Every verifier identity, by id.
pub async fn list_identities(ks: &KeyspaceHandle) -> Result<Vec<VerifierIdentityRecord>, AppError> {
    let rows = ks.prefix_iter_raw(KEY_PREFIX).await?;
    let mut out = Vec::with_capacity(rows.len());
    for (_, value) in rows {
        out.push(serde_json::from_slice(&value).map_err(|e| {
            AppError::Internal(format!("an oid4vp_keys record does not parse: {e}"))
        })?);
    }
    Ok(out)
}

/// Signs a verifier identity's protocol messages — its OpenID4VP request
/// objects.
///
/// A trait because custody differs by deployment: [`LocalP256Signer`] holds
/// the key here; a VTA-held key will sign through `keys/sign-jws`. Callers
/// build the signing input (`BASE64URL(header) || '.' || BASE64URL(payload)`)
/// and receive the JWS signature, so the JAR builder is the same for both.
#[async_trait::async_trait]
pub trait VerifierSigner: Send + Sync {
    /// The JWS `alg` this signer produces.
    fn alg(&self) -> &'static str;
    /// The verification method the signature verifies under.
    fn kid(&self) -> &str;
    /// Sign a JWS signing input; returns the JWS signature bytes (ECDSA as
    /// `r || s`, RFC 7518 §3.4).
    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, AppError>;
}

/// A P-256 key held by this VTC, signing ES256.
pub struct LocalP256Signer {
    kid: String,
    private_key: zeroize::Zeroizing<Vec<u8>>,
}

impl LocalP256Signer {
    /// Build from a record, checking that its private key is a P-256 key whose
    /// public half is the one it says it publishes. A mismatch means the
    /// stored key would sign request objects no wallet could verify against
    /// the published DID — refused here rather than discovered by a wallet.
    pub fn from_record(record: &VerifierIdentityRecord) -> Result<Self, AppError> {
        let secret = affinidi_tdk::secrets_resolver::secrets::Secret::from_multibase(
            &record.private_key_multibase,
            Some(record.kid.as_deref().unwrap_or(&record.id)),
        )
        .map_err(|e| {
            AppError::Config(format!(
                "verifier identity '{}': the stored key does not decode: {e}",
                record.id
            ))
        })?;
        let private = secret.get_private_bytes().to_vec();
        let kp = affinidi_crypto::p256::generate(Some(&private)).map_err(|e| {
            AppError::Config(format!(
                "verifier identity '{}' must hold a P-256 key: {e}",
                record.id
            ))
        })?;
        let derived = serde_json::to_value(&kp.jwk)
            .map_err(|e| AppError::Internal(format!("JWK serialisation: {e}")))?;
        for member in ["kty", "crv", "x", "y"] {
            if derived.get(member) != record.public_jwk.get(member) {
                return Err(AppError::Config(format!(
                    "verifier identity '{}': the stored private key is not the key its \
                     published JWK names ({member} differs)",
                    record.id
                )));
            }
        }
        Ok(Self {
            kid: record.kid.clone().unwrap_or_else(|| record.id.clone()),
            private_key: zeroize::Zeroizing::new(private),
        })
    }
}

#[async_trait::async_trait]
impl VerifierSigner for LocalP256Signer {
    fn alg(&self) -> &'static str {
        "ES256"
    }

    fn kid(&self) -> &str {
        &self.kid
    }

    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, AppError> {
        affinidi_crypto::p256::sign(&self.private_key, signing_input)
            .map_err(|e| AppError::Internal(format!("ES256 signing failed: {e}")))
    }
}

/// The verifier identities this VTC can sign as, by id.
pub type VerifierSigners = BTreeMap<String, Arc<dyn VerifierSigner>>;

/// Load every installed verifier identity's signer, refusing the boot on any
/// that does not load — a configured verifier that cannot sign would answer
/// every wallet with a request it cannot verify.
pub async fn load_signers(ks: &KeyspaceHandle) -> Result<VerifierSigners, AppError> {
    let mut signers = VerifierSigners::new();
    for record in list_identities(ks).await? {
        let signer: Arc<dyn VerifierSigner> = Arc::new(LocalP256Signer::from_record(&record)?);
        signers.insert(record.id.clone(), signer);
    }
    Ok(signers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    pub(crate) fn p256_record(id: &str, seed: u8) -> VerifierIdentityRecord {
        let kp = affinidi_crypto::p256::generate(Some(&[seed; 32])).unwrap();
        let secret = affinidi_tdk::secrets_resolver::secrets::Secret::generate_p256(
            None,
            Some(&kp.private_bytes),
        )
        .unwrap();
        let mut jwk = serde_json::to_value(&kp.jwk).unwrap();
        jwk.as_object_mut().unwrap().remove("d");
        VerifierIdentityRecord {
            id: id.into(),
            kind: VerifierKind::Swiyu,
            did: Some("did:webvh:Qm1:identifier-reg.example:api:v1:did:abc".into()),
            kid: Some("did:webvh:Qm1:identifier-reg.example:api:v1:did:abc#verifier-key-1".into()),
            public_jwk: jwk,
            private_key_multibase: secret.get_private_keymultibase().unwrap(),
            x5c: None,
            verifier_info: None,
            installed_at: 0,
        }
    }

    /// The signer produces an ES256 signature its own published JWK verifies.
    #[tokio::test]
    async fn a_stored_identity_signs_es256_under_its_published_key() {
        let record = p256_record("swiyu", 0x21);
        let signer = LocalP256Signer::from_record(&record).unwrap();
        assert_eq!(signer.alg(), "ES256");
        let input = b"eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ";
        let sig = signer.sign(input).await.unwrap();
        assert_eq!(sig.len(), 64, "JWS ECDSA is r || s");

        let x = URL_SAFE_NO_PAD
            .decode(record.public_jwk["x"].as_str().unwrap())
            .unwrap();
        let y = URL_SAFE_NO_PAD
            .decode(record.public_jwk["y"].as_str().unwrap())
            .unwrap();
        let mut point = vec![0x04];
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        assert!(affinidi_crypto::p256::verify(&point, input, &sig).unwrap());
        assert_eq!(
            record.client_id().as_deref(),
            Some("decentralized_identifier:did:webvh:Qm1:identifier-reg.example:api:v1:did:abc")
        );
    }

    /// A record whose private key is not the published key is refused.
    #[test]
    fn a_key_that_is_not_the_published_one_is_refused() {
        let mut record = p256_record("swiyu", 0x21);
        record.public_jwk = p256_record("other", 0x22).public_jwk;
        let err = LocalP256Signer::from_record(&record)
            .err()
            .expect("refused");
        assert!(err.to_string().contains("not the key"), "{err}");
    }

    #[test]
    fn debug_never_prints_the_private_key() {
        let record = p256_record("swiyu", 0x21);
        let printed = format!("{record:?}");
        assert!(!printed.contains(&record.private_key_multibase));
    }

    #[tokio::test]
    async fn identities_round_trip_through_the_keyspace() {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store
            .keyspace(crate::store::keyspaces::OID4VP_KEYS)
            .unwrap()
            .with_encryption([7u8; 32]);
        put_identity(&ks, &p256_record("swiyu", 0x21))
            .await
            .unwrap();
        assert_eq!(list_identities(&ks).await.unwrap().len(), 1);
        assert_eq!(load_signers(&ks).await.unwrap().len(), 1);
        assert!(delete_identity(&ks, "swiyu").await.unwrap());
        assert!(list_identities(&ks).await.unwrap().is_empty());
    }
}
