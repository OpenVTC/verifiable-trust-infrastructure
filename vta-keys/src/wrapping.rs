//! Ephemeral X25519 wrapping key for REST key import.
//!
//! Each wrapping key is single-use with a 60-second TTL. The VTA generates
//! an ephemeral X25519 keypair and returns the public key as a JWK. Clients
//! may then import a private key via one of two paths:
//!
//! - **Sealed transfer (preferred)** — client seals a
//!   [`SealedPayloadV1::RawPrivateKey`](vta_sdk::sealed_transfer::SealedPayloadV1)
//!   to the wrapping pubkey using HPKE via `vta_sdk::sealed_transfer`, sends
//!   the armored bundle. Server opens it with
//!   [`WrappingKeyCache::unwrap_sealed`].
//! - **Legacy JWE** — historical compact ECDH-ES + AES-GCM format. Retained
//!   only so in-flight clients keep working; new code should use the
//!   sealed-transfer path.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::sync::Mutex;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use vti_common::error::AppError;

const TTL: Duration = Duration::from_secs(60);
const NONCE_LEN: usize = 12;

struct WrappingEntry {
    private_key: StaticSecret,
    #[allow(dead_code)]
    public_key: PublicKey,
    created_at: Instant,
    used: bool,
}

/// In-memory cache of ephemeral wrapping keys.
#[derive(Clone)]
pub struct WrappingKeyCache {
    entries: Arc<Mutex<HashMap<String, WrappingEntry>>>,
}

impl Default for WrappingKeyCache {
    fn default() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl WrappingKeyCache {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Generate a new ephemeral wrapping keypair and return (kid, public_key_base64url).
    pub async fn generate(&self) -> (String, String) {
        let kid = Uuid::new_v4().to_string();
        // Use StaticSecret so we can store it (EphemeralSecret is consumed on DH)
        let secret = StaticSecret::random_from_rng(&mut rand::rng());
        let public = PublicKey::from(&secret);

        let public_b64 = BASE64.encode(public.as_bytes());

        let entry = WrappingEntry {
            private_key: secret,
            public_key: public,
            created_at: Instant::now(),
            used: false,
        };

        self.entries.lock().await.insert(kid.clone(), entry);

        (kid, public_b64)
    }

    /// Consume a wrapping key and decrypt a JWE-like payload.
    ///
    /// Expected format: `{kid}.{ephemeral_pub_b64}.{nonce_b64}.{ciphertext_b64}`
    /// where ciphertext was encrypted with AES-256-GCM using a key derived from
    /// ECDH(ephemeral_client_secret, vta_wrapping_pub) via HKDF.
    pub async fn unwrap_jwe(&self, jwe: &str) -> Result<Vec<u8>, AppError> {
        let parts: Vec<&str> = jwe.split('.').collect();
        if parts.len() != 4 {
            return Err(AppError::Validation(
                "invalid JWE format: expected kid.ephemeral_pub.nonce.ciphertext".into(),
            ));
        }

        let kid = parts[0];
        let ephemeral_pub_bytes = BASE64
            .decode(parts[1])
            .map_err(|e| AppError::Validation(format!("invalid ephemeral public key: {e}")))?;
        let nonce_bytes = BASE64
            .decode(parts[2])
            .map_err(|e| AppError::Validation(format!("invalid nonce: {e}")))?;
        let ciphertext = BASE64
            .decode(parts[3])
            .map_err(|e| AppError::Validation(format!("invalid ciphertext: {e}")))?;

        if ephemeral_pub_bytes.len() != 32 {
            return Err(AppError::Validation(
                "ephemeral public key must be 32 bytes".into(),
            ));
        }
        if nonce_bytes.len() != NONCE_LEN {
            return Err(AppError::Validation(format!(
                "nonce must be {NONCE_LEN} bytes"
            )));
        }

        // Look up and consume the wrapping key
        let mut entries = self.entries.lock().await;
        let entry = entries
            .get_mut(kid)
            .ok_or_else(|| AppError::NotFound("wrapping key not found or expired".into()))?;

        if entry.used {
            entries.remove(kid);
            return Err(AppError::Validation("wrapping key already used".into()));
        }
        if entry.created_at.elapsed() > TTL {
            entries.remove(kid);
            return Err(AppError::Validation("wrapping key expired".into()));
        }

        // Perform ECDH
        let ephemeral_pub: [u8; 32] = ephemeral_pub_bytes
            .try_into()
            .map_err(|_| AppError::Internal("public key conversion failed".into()))?;
        let ephemeral_pub = PublicKey::from(ephemeral_pub);
        let shared_secret = entry.private_key.diffie_hellman(&ephemeral_pub);

        // Mark as used and remove
        entry.used = true;
        entries.remove(kid);
        drop(entries);

        // Derive AES key from shared secret via HKDF
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut aes_key = [0u8; 32];
        hkdf.expand(b"vta-key-import-wrapping", &mut aes_key)
            .map_err(|e| AppError::Internal(format!("hkdf expand: {e}")))?;

        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| AppError::Internal(format!("aes key: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
            AppError::Authentication("failed to unwrap key (ECDH mismatch or tampering)".into())
        })?;

        aes_key.zeroize();

        Ok(std::mem::take(&mut plaintext))
    }

    /// Consume a wrapping key and open a sealed-transfer armored bundle,
    /// returning the raw private key bytes and its declared `key_type` tag.
    /// The caller must cross-check the tag against the outer request's
    /// declared `key_type` to reject mismatches.
    pub async fn unwrap_sealed(&self, armored: &str) -> Result<(String, Vec<u8>), AppError> {
        use vta_sdk::sealed_transfer::{
            PinnedOnlyPolicy, SealedPayloadV1, armor, open_bundle_with_policy,
        };

        let bundles = armor::decode(armored)
            .map_err(|e| AppError::Validation(format!("sealed bundle armor: {e}")))?;
        if bundles.len() != 1 {
            return Err(AppError::Validation(format!(
                "expected exactly one sealed bundle, got {}",
                bundles.len()
            )));
        }
        let bundle = &bundles[0];

        // Chunk 0's producer_assertion carries the wrapping-key kid via the
        // producer_pubkey_b64 field by convention — the sealed envelope
        // already constrains who could have produced this bundle because it
        // had to be sealed to this cache's X25519 pubkey.
        //
        // Operationally we need to identify which cached wrapping secret to
        // try. Sealed-transfer doesn't expose the recipient pubkey in the
        // ciphertext (that would defeat sender-anonymity), so we attempt
        // open against each unexpired, unused entry.
        let mut entries = self.entries.lock().await;
        let now = Instant::now();
        entries.retain(|_, e| now.duration_since(e.created_at) < TTL && !e.used);

        let mut last_err: Option<AppError> = None;
        let mut matched_kid: Option<String> = None;
        let mut matched_payload: Option<SealedPayloadV1> = None;

        for (kid, entry) in entries.iter() {
            let secret_bytes = entry.private_key.to_bytes();
            // Trust anchor: this is the POST /keys/import handshake; the
            // caller has already authenticated to the VTA and the
            // wrapping key is one-shot + ephemeral. PinnedOnly without
            // an OOB digest is expected here — the HTTP session is the
            // integrity anchor.
            match open_bundle_with_policy(
                &secret_bytes,
                bundle,
                None,
                PinnedOnlyPolicy::CallerHasIndependentTrustAnchor,
            ) {
                Ok(opened) => {
                    matched_kid = Some(kid.clone());
                    matched_payload = Some(opened.payload);
                    break;
                }
                Err(e) => {
                    last_err = Some(AppError::Authentication(format!(
                        "sealed bundle open failed: {e}"
                    )));
                }
            }
        }

        if let (Some(kid), Some(payload)) = (matched_kid, matched_payload) {
            entries.remove(&kid);
            return match payload {
                SealedPayloadV1::RawPrivateKey(raw) => {
                    let key_bytes = BASE64
                        .decode(raw.key_bytes_b64.as_bytes())
                        .map_err(|e| AppError::Validation(format!("key bytes base64: {e}")))?;
                    Ok((raw.key_type, key_bytes))
                }
                other => Err(AppError::Validation(format!(
                    "sealed payload is not RawPrivateKey (got {:?})",
                    std::mem::discriminant(&other)
                ))),
            };
        }

        Err(last_err.unwrap_or_else(|| {
            AppError::NotFound(
                "no wrapping key could open this sealed bundle (expired or mismatched)".into(),
            )
        }))
    }

    /// Remove expired entries. Call periodically.
    pub async fn reap_expired(&self) {
        let mut entries = self.entries.lock().await;
        entries.retain(|_, entry| entry.created_at.elapsed() < TTL && !entry.used);
    }

    /// Spawn a background task that reaps expired wrapping keys every 30 seconds.
    pub fn spawn_reaper(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                self.reap_expired().await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Client-side wrapping helper for tests.
    fn wrap_for_test(vta_pub_bytes: &[u8; 32], kid: &str, plaintext: &[u8]) -> String {
        let vta_pub = PublicKey::from(*vta_pub_bytes);
        let client_secret = StaticSecret::random_from_rng(&mut rand::rng());
        let client_pub = PublicKey::from(&client_secret);

        let shared = client_secret.diffie_hellman(&vta_pub);
        let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut aes_key = [0u8; 32];
        hkdf.expand(b"vta-key-import-wrapping", &mut aes_key)
            .unwrap();

        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        use aes_gcm::aead::rand_core::RngCore;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        aes_gcm::aead::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext).unwrap();

        format!(
            "{}.{}.{}.{}",
            kid,
            BASE64.encode(client_pub.as_bytes()),
            BASE64.encode(nonce_bytes),
            BASE64.encode(ciphertext),
        )
    }

    #[tokio::test]
    async fn test_generate_and_unwrap() {
        let cache = WrappingKeyCache::new();
        let (kid, pub_b64) = cache.generate().await;

        let pub_bytes: [u8; 32] = BASE64.decode(&pub_b64).unwrap().try_into().unwrap();

        let secret = b"test-private-key-32-bytes!!!!!!";
        let jwe = wrap_for_test(&pub_bytes, &kid, secret);

        let unwrapped = cache.unwrap_jwe(&jwe).await.unwrap();
        assert_eq!(unwrapped, secret);
    }

    #[tokio::test]
    async fn test_single_use() {
        let cache = WrappingKeyCache::new();
        let (kid, pub_b64) = cache.generate().await;
        let pub_bytes: [u8; 32] = BASE64.decode(&pub_b64).unwrap().try_into().unwrap();

        let jwe = wrap_for_test(&pub_bytes, &kid, b"secret");
        cache.unwrap_jwe(&jwe).await.unwrap();

        // Second use should fail
        let jwe2 = wrap_for_test(&pub_bytes, &kid, b"secret2");
        assert!(cache.unwrap_jwe(&jwe2).await.is_err());
    }

    #[tokio::test]
    async fn test_unwrap_sealed_round_trip() {
        use vta_sdk::sealed_transfer::{
            AssertionProof, InMemoryNonceStore, ProducerAssertion, RawPrivateKey, SealedPayloadV1,
            armor, generate_ed25519_keypair, seal_payload,
        };

        let cache = WrappingKeyCache::new();
        let (_kid, pub_b64) = cache.generate().await;
        let pub_bytes: [u8; 32] = BASE64.decode(&pub_b64).unwrap().try_into().unwrap();

        let secret_key = b"deadbeef-private-key-material-32";
        let payload = SealedPayloadV1::RawPrivateKey(RawPrivateKey {
            key_type: "ed25519".into(),
            key_bytes_b64: BASE64.encode(secret_key),
        });
        let (_prod_seed, prod_ed_pub) = generate_ed25519_keypair();
        let producer = ProducerAssertion {
            producer_did: affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod_ed_pub),
            proof: AssertionProof::PinnedOnly,
        };
        let store = InMemoryNonceStore::new();
        let bundle = seal_payload(&pub_bytes, [7u8; 16], producer, &payload, &store)
            .await
            .unwrap();
        let armored = armor::encode(&bundle);

        let (key_type, bytes) = cache.unwrap_sealed(&armored).await.unwrap();
        assert_eq!(key_type, "ed25519");
        assert_eq!(bytes, secret_key);

        // Second attempt must fail — the wrapping key is consumed.
        assert!(cache.unwrap_sealed(&armored).await.is_err());
    }
}
