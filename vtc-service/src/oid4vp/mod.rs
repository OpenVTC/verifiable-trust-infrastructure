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
//! The VTA mints and custodies the key, as it does every key this VTC holds.
//! Two ways to use it, behind the one [`VerifierSigner`] trait:
//!
//! - **Cached here** ([`LocalP256Signer`]): the VTC signs locally, so a
//!   wallet's request never waits on the VTA. The key arrives as a sealed
//!   transfer bundle the operator relays (`vtc oid4vp request` →
//!   `pnm keys bundle` → `vtc oid4vp install`), and lives in the `oid4vp_keys`
//!   keyspace, encrypted at rest under the same storage key as `install` and
//!   `passkey`.
//! - **Kept in the VTA** ([`VtaHeldSigner`]): the record names the VTA's key
//!   (`vtc oid4vp attach`) and every request object is signed by the VTA
//!   through `keys/sign-jws`, over the community's link to it
//!   ([`crate::vta_link`]). The VTC holds no private key, and needs an ACL entry
//!   at the VTA carrying `sign-jws`. Each JWS the VTA returns is verified under
//!   the identity's recorded public key before it reaches a wallet.
//!
//! See `docs/05-design-notes/oid4vp-wallet-verifier.md`.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use vti_common::error::AppError;

use crate::store::KeyspaceHandle;

pub mod session;
pub mod swiyu_issuer;
pub mod trust_statement;
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

/// One verifier identity, as stored. Its key is either cached here — the
/// multibase string the VTA sealed it in — or named in the VTA that keeps it;
/// exactly one of the two. Everything else is public.
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
    /// The signing key's private half, when this VTC caches it: multibase,
    /// `p256-priv` multicodec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_multibase: Option<String>,
    /// The id of the key in the community's VTA, when the VTA keeps it and
    /// signs every request object through `keys/sign-jws`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_key_id: Option<String>,
    /// An EUDI identity's access certificate and the chain above it, leaf
    /// first, each standard base64 DER — the JAR's `x5c`. Absent until
    /// `vtc oid4vp certificate` installs what the registrar issued, and until
    /// then the identity opens no session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    /// Attestations about the verifier carried in every request's
    /// `verifier_info` — an EUDI registration certificate, or a swiyu
    /// identity's trust statements ([`trust_statement`]).
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
            .field(
                "private_key_multibase",
                &self.private_key_multibase.as_ref().map(|_| "<redacted>"),
            )
            .field("vta_key_id", &self.vta_key_id)
            .finish()
    }
}

/// Where an identity's key is, as its record says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCustody<'a> {
    /// Cached here: the private key's multibase.
    Local(&'a str),
    /// Kept in the VTA: the key's id there.
    Vta(&'a str),
}

impl VerifierIdentityRecord {
    /// Where the key is — exactly one of the two, or the record is refused.
    pub fn custody(&self) -> Result<KeyCustody<'_>, AppError> {
        match (&self.private_key_multibase, &self.vta_key_id) {
            (Some(key), None) => Ok(KeyCustody::Local(key)),
            (None, Some(id)) => Ok(KeyCustody::Vta(id)),
            (Some(_), Some(_)) => Err(AppError::Config(format!(
                "verifier identity '{}' names both a cached key and a VTA key",
                self.id
            ))),
            (None, None) => Err(AppError::Config(format!(
                "verifier identity '{}' has no key: neither cached nor in the VTA",
                self.id
            ))),
        }
    }

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
/// the key here; [`VtaHeldSigner`] asks the VTA. Callers hand over the header
/// members and the claims and receive a compact JWS, because a VTA-held key
/// signs only a signing input the VTA builds itself (`keys/sign-jws`).
#[async_trait::async_trait]
pub trait VerifierSigner: Send + Sync {
    /// The JWS `alg` this signer produces.
    fn alg(&self) -> &'static str;
    /// The verification method the signature verifies under.
    fn kid(&self) -> &str;
    /// A compact JWS over `claims`, with the protected `header` members given
    /// and `alg` set by the signer — never by the caller.
    async fn sign_jws(
        &self,
        header: Map<String, Value>,
        claims: Map<String, Value>,
    ) -> Result<String, AppError>;
}

/// A refused `alg` in a caller's header: the signer sets it from the key.
fn refuse_caller_alg(header: &Map<String, Value>) -> Result<(), AppError> {
    if header.contains_key("alg") {
        return Err(AppError::Internal(
            "a verifier signer sets the JWS alg itself".into(),
        ));
    }
    Ok(())
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
        let KeyCustody::Local(private_key_multibase) = record.custody()? else {
            return Err(AppError::Config(format!(
                "verifier identity '{}' keeps its key in the VTA; it has none here to sign with",
                record.id
            )));
        };
        let secret = affinidi_tdk::secrets_resolver::secrets::Secret::from_multibase(
            private_key_multibase,
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

    async fn sign_jws(
        &self,
        mut header: Map<String, Value>,
        claims: Map<String, Value>,
    ) -> Result<String, AppError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        refuse_caller_alg(&header)?;
        header.insert("alg".into(), Value::String(self.alg().into()));
        let encode = |v: Map<String, Value>| {
            serde_json::to_vec(&Value::Object(v))
                .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
                .map_err(|e| AppError::Internal(format!("JWS serialisation: {e}")))
        };
        let signing_input = format!("{}.{}", encode(header)?, encode(claims)?);
        let signature = affinidi_crypto::p256::sign(&self.private_key, signing_input.as_bytes())
            .map_err(|e| AppError::Internal(format!("ES256 signing failed: {e}")))?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }
}

/// A VTA that signs JWSs with keys it keeps — `keys/sign-jws/0.1`, over the
/// community's link to it ([`crate::vta_link::VtaLink`]). A trait so a test
/// can stand a VTA in.
#[async_trait::async_trait]
pub trait VtaJwsSigner: Send + Sync {
    /// The compact JWS the VTA returns for key `key_id`.
    async fn sign_jws(
        &self,
        key_id: &str,
        header: Map<String, Value>,
        claims: Map<String, Value>,
    ) -> Result<String, AppError>;
}

/// The community's link to its VTA, set once messaging can reach it — after
/// the signers are loaded, which is why it is a cell rather than an argument.
pub type VtaLinkCell = Arc<std::sync::OnceLock<Arc<dyn VtaJwsSigner>>>;

/// A key the VTA keeps, signing every request object through `keys/sign-jws`.
pub struct VtaHeldSigner {
    id: String,
    kid: String,
    key_id: String,
    public: vta_sdk::jws::JwsKey,
    link: VtaLinkCell,
}

impl VtaHeldSigner {
    /// Build from a record that names a VTA key, and the link it will sign
    /// over. The recorded public key is what every JWS the VTA returns must
    /// verify under.
    pub fn from_record(
        record: &VerifierIdentityRecord,
        link: VtaLinkCell,
    ) -> Result<Self, AppError> {
        let KeyCustody::Vta(key_id) = record.custody()? else {
            return Err(AppError::Config(format!(
                "verifier identity '{}' caches its key here; it is not one the VTA signs with",
                record.id
            )));
        };
        let public = vta_sdk::jws::JwsKey::from_jwk(&record.public_jwk).map_err(|e| {
            AppError::Config(format!(
                "verifier identity '{}': its public key is not usable: {e}",
                record.id
            ))
        })?;
        if !matches!(public, vta_sdk::jws::JwsKey::P256(_)) {
            return Err(AppError::Config(format!(
                "verifier identity '{}' must name a P-256 key; swiyu and EUDI wallets accept \
                 ES256 only",
                record.id
            )));
        }
        Ok(Self {
            id: record.id.clone(),
            kid: record.kid.clone().unwrap_or_else(|| record.id.clone()),
            key_id: key_id.to_string(),
            public,
            link,
        })
    }
}

#[async_trait::async_trait]
impl VerifierSigner for VtaHeldSigner {
    fn alg(&self) -> &'static str {
        self.public.alg()
    }

    fn kid(&self) -> &str {
        &self.kid
    }

    async fn sign_jws(
        &self,
        header: Map<String, Value>,
        claims: Map<String, Value>,
    ) -> Result<String, AppError> {
        refuse_caller_alg(&header)?;
        let link = self.link.get().ok_or_else(|| {
            AppError::Internal(format!(
                "verifier identity '{}' signs through the VTA, and the link to it is not up",
                self.id
            ))
        })?;
        let jws = link.sign_jws(&self.key_id, header, claims).await?;
        // The VTA builds what it signs; check it is a JWS by this identity's
        // key before a wallet sees it (keys/sign-jws: a producer SHOULD verify).
        self.public.verify_compact(&jws).map_err(|e| {
            AppError::Internal(format!(
                "the VTA's JWS for verifier identity '{}' does not verify under its key: {e}",
                self.id
            ))
        })?;
        Ok(jws)
    }
}

/// The verifier identities this VTC can sign as, by id.
pub type VerifierSigners = BTreeMap<String, Arc<dyn VerifierSigner>>;

/// Load every installed verifier identity's signer, refusing the boot on any
/// that does not load — a configured verifier that cannot sign would answer
/// every wallet with a request it cannot verify. An identity whose key the VTA
/// keeps signs over `link`; whether there is one is checked once messaging is
/// configured ([`needs_vta_link`]).
pub async fn load_signers(
    ks: &KeyspaceHandle,
    link: &VtaLinkCell,
) -> Result<VerifierSigners, AppError> {
    let mut signers = VerifierSigners::new();
    for record in list_identities(ks).await? {
        let signer: Arc<dyn VerifierSigner> = match record.custody()? {
            KeyCustody::Local(_) => Arc::new(LocalP256Signer::from_record(&record)?),
            KeyCustody::Vta(_) => Arc::new(VtaHeldSigner::from_record(&record, link.clone())?),
        };
        signers.insert(record.id.clone(), signer);
    }
    Ok(signers)
}

/// The identities whose key the VTA keeps — each needs the link to the VTA.
pub async fn needs_vta_link(ks: &KeyspaceHandle) -> Result<Vec<String>, AppError> {
    Ok(list_identities(ks)
        .await?
        .into_iter()
        .filter(|r| r.vta_key_id.is_some())
        .map(|r| r.id)
        .collect())
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
            private_key_multibase: Some(secret.get_private_keymultibase().unwrap()),
            vta_key_id: None,
            x5c: None,
            verifier_info: None,
            installed_at: 0,
        }
    }

    fn object(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    /// The signer produces an ES256 JWS its own published JWK verifies.
    #[tokio::test]
    async fn a_stored_identity_signs_es256_under_its_published_key() {
        let record = p256_record("swiyu", 0x21);
        let signer = LocalP256Signer::from_record(&record).unwrap();
        assert_eq!(signer.alg(), "ES256");
        let jws = signer
            .sign_jws(
                object(serde_json::json!({ "typ": "jwt" })),
                object(serde_json::json!({ "a": 1 })),
            )
            .await
            .unwrap();
        let sig = URL_SAFE_NO_PAD
            .decode(jws.rsplit('.').next().unwrap())
            .unwrap();
        assert_eq!(sig.len(), 64, "JWS ECDSA is r || s");
        let claims = vta_sdk::jws::JwsKey::from_jwk(&record.public_jwk)
            .unwrap()
            .verify_compact(&jws)
            .expect("verifies under the published key");
        assert_eq!(claims["a"], 1);
        assert!(
            signer
                .sign_jws(object(serde_json::json!({ "alg": "none" })), Map::new())
                .await
                .is_err(),
            "the caller never sets alg"
        );
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
        assert!(!printed.contains(record.private_key_multibase.as_deref().unwrap()));
    }

    /// A VTA standing in with one key: it signs as `keys/sign-jws` would, or —
    /// for the test of a VTA that answers with another key — with `wrong`.
    struct FakeVta {
        key_id: String,
        signer: LocalP256Signer,
    }

    #[async_trait::async_trait]
    impl VtaJwsSigner for FakeVta {
        async fn sign_jws(
            &self,
            key_id: &str,
            header: Map<String, Value>,
            claims: Map<String, Value>,
        ) -> Result<String, AppError> {
            assert_eq!(key_id, self.key_id);
            self.signer.sign_jws(header, claims).await
        }
    }

    fn vta_record(id: &str, seed: u8) -> VerifierIdentityRecord {
        let mut record = p256_record(id, seed);
        record.private_key_multibase = None;
        record.vta_key_id = Some("verifier-p256".into());
        record
    }

    fn link_to(signing_seed: u8) -> VtaLinkCell {
        let cell = VtaLinkCell::default();
        let vta: Arc<dyn VtaJwsSigner> = Arc::new(FakeVta {
            key_id: "verifier-p256".into(),
            signer: LocalP256Signer::from_record(&p256_record("vta", signing_seed)).unwrap(),
        });
        assert!(cell.set(vta).is_ok());
        cell
    }

    /// A VTA-held identity signs through the link, and only a JWS by its own
    /// recorded key comes back out.
    #[tokio::test]
    async fn a_vta_held_identity_signs_through_the_vta_and_checks_the_answer() {
        let record = vta_record("swiyu", 0x21);
        let header = || object(serde_json::json!({ "typ": "oauth-authz-req+jwt" }));

        let signer = VtaHeldSigner::from_record(&record, link_to(0x21)).unwrap();
        assert_eq!(signer.alg(), "ES256");
        let jws = signer.sign_jws(header(), Map::new()).await.unwrap();
        vta_sdk::jws::JwsKey::from_jwk(&record.public_jwk)
            .unwrap()
            .verify_compact(&jws)
            .unwrap();

        let wrong = VtaHeldSigner::from_record(&record, link_to(0x22)).unwrap();
        let err = wrong.sign_jws(header(), Map::new()).await.unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");

        let unlinked = VtaHeldSigner::from_record(&record, VtaLinkCell::default()).unwrap();
        let err = unlinked.sign_jws(header(), Map::new()).await.unwrap_err();
        assert!(err.to_string().contains("not up"), "{err}");
    }

    /// A record names its key exactly once, and each signer takes only its own
    /// custody.
    #[test]
    fn a_record_names_one_key_and_each_signer_its_own_custody() {
        let local = p256_record("a", 0x21);
        let vta = vta_record("b", 0x21);
        assert!(matches!(local.custody(), Ok(KeyCustody::Local(_))));
        assert!(matches!(
            vta.custody(),
            Ok(KeyCustody::Vta("verifier-p256"))
        ));
        assert!(LocalP256Signer::from_record(&vta).is_err());
        assert!(VtaHeldSigner::from_record(&local, VtaLinkCell::default()).is_err());

        let mut both = local.clone();
        both.vta_key_id = Some("k".into());
        assert!(both.custody().is_err());
        let mut neither = vta.clone();
        neither.vta_key_id = None;
        assert!(neither.custody().is_err());

        // A record written before `vtaKeyId` existed still reads.
        let mut stored = serde_json::to_value(&local).unwrap();
        stored.as_object_mut().unwrap().remove("vtaKeyId");
        let read: VerifierIdentityRecord = serde_json::from_value(stored).unwrap();
        assert!(matches!(read.custody(), Ok(KeyCustody::Local(_))));
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
        put_identity(&ks, &vta_record("eudi", 0x22)).await.unwrap();
        assert_eq!(list_identities(&ks).await.unwrap().len(), 2);
        assert_eq!(
            load_signers(&ks, &VtaLinkCell::default())
                .await
                .unwrap()
                .len(),
            2
        );
        assert_eq!(needs_vta_link(&ks).await.unwrap(), vec!["eudi".to_string()]);
        assert!(delete_identity(&ks, "eudi").await.unwrap());
        assert!(delete_identity(&ks, "swiyu").await.unwrap());
        assert!(list_identities(&ks).await.unwrap().is_empty());
    }
}
