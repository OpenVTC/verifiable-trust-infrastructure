//! Sealed storage credentials (`vtc/storage/credentials/set/0.2`): the discouraged
//! fallback for a community with no VTA account.
//!
//! An administrator's client seals a `SealedStorageCredential` to this community's
//! DID with `sealed_transfer` ([`vta_sdk::sealed_transfer::SealedPayloadV1::StorageCredential`]);
//! the community opens it here with the X25519 derivation of its Ed25519 key, checks
//! the cleartext **as received** against the specification's schema, its `kind`
//! against the config's and its `configId` against the request's (item 2), and keeps
//! it in the `storage_credentials` keyspace:
//!
//! - **encrypted at rest** under the storage key derived from the community's own
//!   secret, and refused outright when there is none to encrypt under (item 3);
//! - **excluded from every backup**, and cleared when a backup is imported, so a
//!   restored config reports its credential `required` until it is set again
//!   (item 7);
//! - **never returned**: what leaves is a fingerprint, HMAC-SHA-256 under a key
//!   derived from the community's secret, never a bare hash of the secret (item 4);
//! - **replaced whole** — the earlier one destroyed — by a later set, and removed when
//!   the config's `auth` leaves `sealed` (item 5, `configs/update` item 5).
//!
//! What it protects against, and what not: every administrator, through every surface
//! this community offers; never whoever operates this machine, which must be able to
//! use the key. Whether the mode is offered at all is that operator's choice
//! (`[rooms.files.auth] sealed`).

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use vta_sdk::sealed_transfer::{SealedPayloadV1, armor, multibase_digest_to_hex, open_bundle};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use zeroize::Zeroizing;

/// Why a sealed block was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedRefusal {
    /// `cannotOpen`: not sealed to this community, malformed, or not the digest given.
    CannotOpen(String),
    /// `invalidCredential`: it opened, but is not a `SealedStorageCredential` for
    /// this config. The reason never quotes the cleartext.
    Invalid(String),
}

/// A stored credential: the cleartext as received, with when it was set and its
/// fingerprint. Never serialised anywhere but the encrypted keyspace.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredCredential {
    pub cleartext: Value,
    pub fingerprint: String,
    pub set_at: String,
}

impl std::fmt::Debug for StoredCredential {
    // The cleartext is the secret: never in a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredCredential")
            .field("fingerprint", &self.fingerprint)
            .field("set_at", &self.set_at)
            .finish_non_exhaustive()
    }
}

/// An opened, checked credential, not yet stored.
pub struct OpenedCredential {
    cleartext: Value,
}

impl OpenedCredential {
    pub fn kind(&self) -> &str {
        self.cleartext["kind"].as_str().unwrap_or_default()
    }
}

fn key_of(config_id: &str) -> String {
    format!("cred:{config_id}")
}

/// The community's sealed storage credentials.
pub struct SealedCredentials {
    /// Encrypted under the storage key.
    ks: KeyspaceHandle,
    /// The X25519 secret the community opens sealed blocks with.
    open_key: Zeroizing<[u8; 32]>,
    /// The fingerprint's HMAC key.
    fingerprint_key: Zeroizing<[u8; 32]>,
}

impl SealedCredentials {
    /// Over `ks` (encrypted here under `storage_key`), for the community whose Ed25519
    /// signing key has `ed25519_seed`.
    pub fn new(ks: KeyspaceHandle, storage_key: [u8; 32], ed25519_seed: &[u8; 32]) -> Self {
        let open_key = vta_sdk::sealed_transfer::ed25519_seed_to_x25519_secret(ed25519_seed);
        let mut fingerprint_key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, ed25519_seed)
            .expand(
                b"vtc-storage-credential-fingerprint/v1",
                &mut fingerprint_key[..],
            )
            .expect("32 bytes of HKDF-SHA256 output");
        Self {
            ks: ks.with_encryption(storage_key),
            open_key,
            fingerprint_key,
        }
    }

    /// Open `armored` (whose digest is `digest_multibase`) as the credential for
    /// `config_id` of kind `kind` (item 2). Nothing is stored.
    pub fn open(
        &self,
        config_id: &str,
        kind: &str,
        armored: &str,
        digest_multibase: &str,
    ) -> Result<OpenedCredential, SealedRefusal> {
        let cannot = |why: &str| SealedRefusal::CannotOpen(why.to_string());
        let bundles = armor::decode(armored).map_err(|_| cannot("the block is not armored"))?;
        let [bundle] = bundles.as_slice() else {
            return Err(cannot("the block holds other than one sealed bundle"));
        };
        let digest = multibase_digest_to_hex(digest_multibase)
            .map_err(|_| cannot("digestMultibase is not a sha2-256 digest"))?;
        // The request's own proof covers the block and its digest: the digest is the
        // integrity anchor a `PinnedOnly` producer relies on.
        let opened = open_bundle(&self.open_key, bundle, Some(&digest)).map_err(|e| {
            cannot(match e {
                vta_sdk::sealed_transfer::SealedTransferError::DigestMismatch { .. } => {
                    "the block's digest is not digestMultibase"
                }
                _ => "the block is not sealed to this community",
            })
        })?;
        let cleartext = match opened.payload {
            SealedPayloadV1::StorageCredential(p) => p.0,
            _ => {
                return Err(SealedRefusal::Invalid(
                    "the block holds something other than a storage credential".into(),
                ));
            }
        };
        check_cleartext(&cleartext, config_id, kind)?;
        Ok(OpenedCredential { cleartext })
    }

    /// The fingerprint of a cleartext: HMAC-SHA-256 under the community's key over its
    /// RFC 8785 form, as a multibase multihash.
    fn fingerprint(&self, cleartext: &Value) -> String {
        let canonical = serde_json_canonicalizer::to_vec(cleartext).unwrap_or_default();
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.fingerprint_key[..])
            .expect("HMAC takes any key");
        mac.update(&canonical);
        let mut mh = vec![0x12, 0x20];
        mh.extend_from_slice(&mac.finalize().into_bytes());
        multibase::encode(multibase::Base::Base58Btc, mh)
    }

    /// Store `opened` as `config_id`'s credential, replacing — destroying — any before
    /// it (item 5). Returns what is stored.
    pub async fn put(
        &self,
        config_id: &str,
        opened: OpenedCredential,
    ) -> Result<StoredCredential, AppError> {
        let stored = StoredCredential {
            fingerprint: self.fingerprint(&opened.cleartext),
            set_at: chrono::Utc::now().to_rfc3339(),
            cleartext: opened.cleartext,
        };
        self.ks.remove(key_of(config_id)).await?;
        self.ks.insert(key_of(config_id), &stored).await?;
        Ok(stored)
    }

    pub async fn get(&self, config_id: &str) -> Result<Option<StoredCredential>, AppError> {
        self.ks.get(key_of(config_id)).await
    }

    /// Destroy `config_id`'s credential (its `auth` left `sealed`).
    pub async fn remove(&self, config_id: &str) -> Result<(), AppError> {
        self.ks.remove(key_of(config_id)).await
    }

    /// Destroy every credential: a restore never carries one (item 7).
    pub async fn clear(&self) -> Result<usize, AppError> {
        let keys = self.ks.prefix_keys(b"cred:".to_vec()).await?;
        for k in &keys {
            self.ks.remove(k.clone()).await?;
        }
        Ok(keys.len())
    }
}

/// The `SealedStorageCredential` schema, out of `vtc/storage/credentials/set/0.2`'s own
/// payload schema, which declares it for exactly this.
fn cleartext_schema() -> Option<String> {
    use trust_tasks_rs::Payload;
    use trust_tasks_rs::specs::vtc::storage::credentials::set::v0_2 as set;
    let mut schema: Value = serde_json::from_str(set::Payload::PAYLOAD_SCHEMA?).ok()?;
    let defs = schema.get("$defs")?.as_object()?;
    let name = ["SealedCredentialCleartext", "SealedStorageCredential"]
        .into_iter()
        .find(|n| defs.contains_key(*n))?;
    let obj = schema.as_object_mut()?;
    for member in [
        "properties",
        "required",
        "additionalProperties",
        "type",
        "title",
        "description",
    ] {
        obj.remove(member);
    }
    obj.insert("$ref".into(), Value::String(format!("#/$defs/{name}")));
    serde_json::to_string(&schema).ok()
}

/// Item 2: the cleartext, as received, is a `SealedStorageCredential` of the config's
/// kind naming the request's config. The reason never quotes a value: a validator's
/// message would.
pub fn check_cleartext(
    cleartext: &Value,
    config_id: &str,
    kind: &str,
) -> Result<(), SealedRefusal> {
    let invalid = |why: &str| SealedRefusal::Invalid(why.to_string());
    let schema = cleartext_schema()
        .ok_or_else(|| invalid("this build cannot read the SealedStorageCredential schema"))?;
    if trust_tasks_rs::validate::against_schema(&schema, cleartext).is_err() {
        return Err(invalid(
            "the cleartext does not validate as a SealedStorageCredential",
        ));
    }
    if cleartext["kind"].as_str() != Some(kind) {
        return Err(invalid("the credential's kind is not the config's"));
    }
    if cleartext["configId"].as_str() != Some(config_id) {
        return Err(invalid("the credential names another config"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vta_sdk::sealed_transfer::{
        AssertionProof, InMemoryNonceStore, ProducerAssertion, StorageCredentialPayload,
        bundle_digest_multibase, seal_payload,
    };

    const SEED: [u8; 32] = [7; 32];

    fn community_x25519_pub() -> [u8; 32] {
        let secret = vta_sdk::sealed_transfer::ed25519_seed_to_x25519_secret(&SEED);
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).to_bytes()
    }

    async fn seal_to(
        recipient: &[u8; 32],
        cleartext: Value,
    ) -> vta_sdk::sealed_transfer::SealedBundle {
        let mut id = [0u8; 16];
        rand::fill(&mut id);
        seal_payload(
            recipient,
            id,
            ProducerAssertion {
                producer_did: "did:key:zAdmin".into(),
                proof: AssertionProof::PinnedOnly,
            },
            &SealedPayloadV1::StorageCredential(Box::new(StorageCredentialPayload(cleartext))),
            &InMemoryNonceStore::default(),
        )
        .await
        .unwrap()
    }

    async fn seal(cleartext: Value) -> (String, String) {
        let bundle = seal_to(&community_x25519_pub(), cleartext).await;
        (armor::encode(&bundle), bundle_digest_multibase(&bundle))
    }

    async fn store(dir: &std::path::Path) -> SealedCredentials {
        let s = vti_common::store::test_fixture::open_with_keyspaces(
            &dir.join("db"),
            &["storage_credentials"],
        )
        .unwrap();
        SealedCredentials::new(s.keyspace("storage_credentials").unwrap(), [3; 32], &SEED)
    }

    fn s3(config: &str) -> Value {
        json!({
            "kind": "s3",
            "configId": config,
            "accessKeyId": "EXAMPLEKEYID0001",
            "secretAccessKey": "example-secret-not-a-real-one",
        })
    }

    /// Sealed in a client, opened here, stored encrypted, reported by fingerprint.
    #[tokio::test]
    async fn a_sealed_credential_round_trips_and_is_kept_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let creds = store(dir.path()).await;
        let (armored, digest) = seal(s3("r2-archive")).await;
        let opened = creds.open("r2-archive", "s3", &armored, &digest).unwrap();
        let stored = creds.put("r2-archive", opened).await.unwrap();
        assert!(stored.fingerprint.starts_with('z'));
        assert!(!format!("{stored:?}").contains("example-secret"));
        let back = creds.get("r2-archive").await.unwrap().unwrap();
        assert_eq!(back.cleartext, s3("r2-archive"));

        // On disk: the secret appears nowhere in the clear.
        let raw = vti_common::store::test_fixture::open_with_keyspaces(
            &dir.path().join("db"),
            &["storage_credentials"],
        );
        drop(raw);
        for entry in walk(&dir.path().join("db")) {
            let bytes = std::fs::read(&entry).unwrap_or_default();
            assert!(
                !bytes
                    .windows(b"example-secret".len())
                    .any(|w| w == b"example-secret"),
                "{} holds the secret in the clear",
                entry.display()
            );
        }

        // Replaced whole; and the fingerprint is keyed, not a hash anyone can compute.
        let mut other = s3("r2-archive");
        other["secretAccessKey"] = json!("another-secret");
        let (armored, digest) = seal(other).await;
        let second = creds
            .put(
                "r2-archive",
                creds.open("r2-archive", "s3", &armored, &digest).unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(second.fingerprint, stored.fingerprint);
        assert_eq!(creds.clear().await.unwrap(), 1);
        assert!(creds.get("r2-archive").await.unwrap().is_none());
    }

    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    out.extend(walk(&p));
                } else {
                    out.push(p);
                }
            }
        }
        out
    }

    #[tokio::test]
    async fn a_block_for_another_config_kind_or_digest_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let creds = store(dir.path()).await;
        let (armored, digest) = seal(s3("r2-archive")).await;
        assert!(matches!(
            creds.open("elsewhere", "s3", &armored, &digest),
            Err(SealedRefusal::Invalid(_))
        ));
        assert!(matches!(
            creds.open("r2-archive", "gcs", &armored, &digest),
            Err(SealedRefusal::Invalid(_))
        ));
        let (_, other_digest) = seal(s3("x")).await;
        assert!(matches!(
            creds.open("r2-archive", "s3", &armored, &other_digest),
            Err(SealedRefusal::CannotOpen(_))
        ));
        assert!(matches!(
            creds.open("r2-archive", "s3", "not armor", &digest),
            Err(SealedRefusal::CannotOpen(_))
        ));
        // Not repaired into validity: an extra member is refused, not dropped.
        let mut extra = s3("r2-archive");
        extra["note"] = json!("x");
        let (armored, digest) = seal(extra).await;
        let refused = creds.open("r2-archive", "s3", &armored, &digest);
        match refused {
            Err(SealedRefusal::Invalid(why)) => assert!(!why.contains("example-secret")),
            other => panic!("{:?}", other.err()),
        }
        // Sealed to someone else.
        let other_pub =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([1u8; 32])).to_bytes();
        let bundle = seal_to(&other_pub, s3("r2-archive")).await;
        assert!(matches!(
            creds.open(
                "r2-archive",
                "s3",
                &armor::encode(&bundle),
                &bundle_digest_multibase(&bundle)
            ),
            Err(SealedRefusal::CannotOpen(_))
        ));
    }

    #[test]
    fn a_gcs_key_file_and_a_walrus_key_validate() {
        let gcs = json!({
            "kind": "gcs",
            "configId": "g",
            "serviceAccountKey": {
                "type": "service_account",
                "client_email": "rooms@p.iam.gserviceaccount.com",
                "private_key_id": "abc123",
                "private_key": format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", "A".repeat(64)),
                "project_id": "p",
                "token_uri": "https://evil.example/token",
            },
        });
        check_cleartext(&gcs, "g", "gcs").unwrap();
        let walrus = json!({ "kind": "walrus", "configId": "w", "suiPrivateKey": "suiprivkey1qqqqqqqqqqqqqqqqqqqqqqqq" });
        check_cleartext(&walrus, "w", "walrus").unwrap();
    }
}
