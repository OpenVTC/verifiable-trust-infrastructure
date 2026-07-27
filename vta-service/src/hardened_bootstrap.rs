//! Non-TEE hardened configuration: derive the storage-encryption key from the master
//! seed, and manage the JWT signing key as an AES-GCM ciphertext stored in
//! the `bootstrap` keyspace — mirroring how TEE mode handles both.
//!
//! # Purpose
//!
//! Standard `vta-service` (non-TEE) boots with:
//!   - The JWT signing key stored in plaintext in `config.toml` — the
//!     highest-value secret on the filesystem; a root user can forge any token.
//!   - The fjall keyspaces unencrypted at rest — sessions, ACL entries, audit
//!     logs, etc. readable by anyone with disk access.
//!
//! This module closes both gaps **without a Nitro enclave or KMS**:
//!
//! 1. At boot, load the master seed from the configured secret-store backend.
//! 2. Derive the **storage-encryption key** via `HKDF-SHA256(seed, salt, info
//!    = "vta-storage-key/v1")` and pass it to `server::run()` as
//!    `storage_encryption_key: Some(_)` — the `VAE1` AES-256-GCM
//!    per-value encryption layer activates.
//! 3. **JWT signing key** — mirrors TEE exactly, replacing KMS with the
//!    HKDF-derived storage key as the KEK:
//!    - **First boot**: generate a random 32-byte JWT key, AES-GCM encrypt it
//!      under the storage key, write `hardened:jwt_ciphertext` +
//!      `hardened:jwt_fingerprint` to the `bootstrap` keyspace (stored
//!      unencrypted at the keyspace level, application-layer encrypted).
//!    - **Subsequent boots**: read the ciphertext, decrypt with the storage
//!      key, verify the SHA-256 fingerprint.
//!    - The JWT key is **never written to `config.toml`**.
//!    - **Independent rotation**: delete `hardened:jwt_ciphertext` and
//!      `hardened:jwt_fingerprint` from the `bootstrap` keyspace, then
//!      restart — a new random key is generated. This does **not** require
//!      rotating the master seed (unlike the previous derived-key approach).
//!
//! Both features require the seed to be in a **real** secret-store backend
//! (OS keyring, AWS/GCP/Azure/Vault/K8s). The plaintext file fallback
//! defeats the protection and triggers a startup warning.
//!
//! Analogous to `tee::kms_bootstrap` — that module does the same job for TEE
//! deployments using KMS as the trust anchor; this one uses the external
//! secret store instead.
//!
//! # Migration from derived-key approach
//!
//! If you previously ran with the now-removed `derive_jwt_signing_key`
//! function, the VTA will generate a new random JWT key on next boot and
//! store it in `bootstrap:hardened:jwt_ciphertext`. All existing sessions
//! will be invalidated (access tokens signed under the old key will be
//! rejected). This is expected behaviour for a JWT key rotation.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256 as Sha256Hasher;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::store::KeyspaceHandle;

/// fjall key for the AES-GCM ciphertext of the JWT signing key.
/// Stored in the `bootstrap` keyspace (unencrypted at rest — application-layer
/// encrypted under the storage key, matching TEE's `bootstrap:jwt_ciphertext`).
pub const HARDENED_JWT_CT_KEY: &str = "hardened:jwt_ciphertext";

/// fjall key for the SHA-256 fingerprint of the JWT signing key.
/// Tamper-detection: mismatch on boot → fatal, same as TEE's fingerprint check.
pub const HARDENED_JWT_FINGERPRINT_KEY: &str = "hardened:jwt_fingerprint";

/// HKDF `info` for the storage-encryption key.
///
/// Domain-separated from the VTC counterpart (`vtc-storage-key/v1`) so the
/// same seed never yields the same material for two different services.
const STORAGE_KEY_INFO: &[u8] = b"vta-storage-key/v1";

/// Derive the 32-byte AES-256-GCM storage-encryption key from `seed`.
///
/// `salt` must match `config.hardened.storage_key_salt`. **Changing the salt
/// invalidates all encrypted data** — treat it as a permanent per-VTA constant
/// set once at initial setup.
///
/// Deterministic: same seed + same salt → same key on every boot.
pub fn derive_storage_key(seed: &[u8], salt: &str) -> Zeroizing<[u8; 32]> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt.as_bytes()), seed)
        .expand(STORAGE_KEY_INFO, &mut key)
        .expect("32-byte output is within HKDF-SHA256 limits");
    Zeroizing::new(key)
}

/// AES-256-GCM encrypt `plaintext` under `key`.
/// Returns `[12-byte nonce || ciphertext+tag]` — same wire format as the
/// TEE `aes_gcm_encrypt` helper in `kms_bootstrap.rs`.
pub fn aes_gcm_seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    use aes_gcm::aead::rand_core::RngCore;
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let mut nonce_bytes = [0u8; 12];
    aes_gcm::aead::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let mut ct = cipher.encrypt(nonce, plaintext).expect("AES-GCM encrypt");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.append(&mut ct);
    out
}

/// AES-256-GCM decrypt a `[12-byte nonce || ciphertext+tag]` blob.
/// Returns `None` on authentication failure (tampered or wrong key).
pub fn aes_gcm_open(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 13 {
        return None;
    }
    let nonce = aes_gcm::Nonce::from_slice(&blob[..12]);
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher.decrypt(nonce, &blob[12..]).ok()
}

/// Compute a SHA-256 fingerprint of a JWT signing key for tamper detection.
/// Returns the first 16 bytes as 32 hex characters — same as TEE's `jwt_fingerprint`.
pub fn jwt_key_fingerprint(key: &[u8; 32]) -> String {
    let hash = Sha256Hasher::digest(key);
    hex::encode(&hash[..16])
}

/// Error variants for [`load_or_generate_jwt_key`].
#[derive(Debug)]
pub enum JwtKeyError {
    /// AES-GCM decryption failed — wrong storage key or tampered ciphertext.
    DecryptFailed,
    /// Decrypted bytes are not exactly 32 bytes long.
    BadKeyLength,
    /// The stored fingerprint row is absent — possible tampering.
    FingerprintMissing,
    /// The stored fingerprint does not match the computed one — possible tampering.
    FingerprintMismatch { stored: String, computed: String },
    /// A store I/O error occurred.
    Store(vti_common::error::AppError),
}

impl std::fmt::Display for JwtKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtKeyError::DecryptFailed => write!(
                f,
                "hardened: AES-GCM decryption of JWT signing key failed — \
                 storage_key_salt mismatch or tampered ciphertext. \
                 Clear 'hardened:jwt_ciphertext' from the bootstrap keyspace to \
                 generate a new key (existing sessions will be invalidated)."
            ),
            JwtKeyError::BadKeyLength => write!(
                f,
                "hardened: decrypted JWT key is not 32 bytes — store may be corrupt."
            ),
            JwtKeyError::FingerprintMissing => write!(
                f,
                "hardened: JWT key fingerprint missing — possible tampering. \
                 Clear 'hardened:jwt_ciphertext' and 'hardened:jwt_fingerprint' \
                 from the bootstrap keyspace to regenerate."
            ),
            JwtKeyError::FingerprintMismatch { stored, computed } => write!(
                f,
                "hardened: JWT key fingerprint MISMATCH (stored={stored}, \
                 computed={computed}) — possible tampering with the ciphertext or \
                 salt change. Clear both bootstrap entries to regenerate."
            ),
            JwtKeyError::Store(e) => write!(f, "hardened: store error: {e}"),
        }
    }
}

impl From<vti_common::error::AppError> for JwtKeyError {
    fn from(e: vti_common::error::AppError) -> Self {
        JwtKeyError::Store(e)
    }
}

/// Load the JWT signing key from the bootstrap keyspace, or generate and seal
/// a new one on first boot (or after a `vta hardened rotate-jwt`).
///
/// This is the testable core of the hardened-mode boot logic, extracted from
/// `main.rs`. The caller maps `Err` to a `tracing::error!` + `process::exit(1)`.
///
/// # Boot paths
///
/// - **First boot / rotate**: `HARDENED_JWT_CT_KEY` absent → generate random
///   32-byte key → AES-GCM seal under `storage_key` → write ciphertext +
///   fingerprint to `bootstrap_ks` → return key.
/// - **Subsequent boot**: `HARDENED_JWT_CT_KEY` present → decrypt → verify
///   fingerprint → return key. Any verification failure returns `Err`.
pub async fn load_or_generate_jwt_key(
    bootstrap_ks: &KeyspaceHandle,
    storage_key: &[u8; 32],
) -> Result<[u8; 32], JwtKeyError> {
    match bootstrap_ks
        .get_raw(HARDENED_JWT_CT_KEY)
        .await
        .map_err(JwtKeyError::Store)?
    {
        Some(ciphertext) => {
            // Subsequent boot: decrypt and verify fingerprint.
            let plaintext =
                aes_gcm_open(storage_key, &ciphertext).ok_or(JwtKeyError::DecryptFailed)?;

            let key: [u8; 32] = plaintext
                .try_into()
                .map_err(|_| JwtKeyError::BadKeyLength)?;

            // Fingerprint check — tamper detection, same as TEE.
            let stored_fp = bootstrap_ks
                .get_raw(HARDENED_JWT_FINGERPRINT_KEY)
                .await
                .map_err(JwtKeyError::Store)?
                .ok_or(JwtKeyError::FingerprintMissing)?;

            let stored = String::from_utf8_lossy(&stored_fp).trim().to_string();
            let computed = jwt_key_fingerprint(&key);
            if stored != computed {
                return Err(JwtKeyError::FingerprintMismatch { stored, computed });
            }

            Ok(key)
        }
        None => {
            // First boot or after rotate-jwt: generate a random key and seal it.
            let mut key_bytes = [0u8; 32];
            rand::fill(&mut key_bytes);
            let ciphertext = aes_gcm_seal(storage_key, &key_bytes);
            let fingerprint = jwt_key_fingerprint(&key_bytes);

            bootstrap_ks
                .insert_raw(HARDENED_JWT_CT_KEY, ciphertext)
                .await
                .map_err(JwtKeyError::Store)?;
            bootstrap_ks
                .insert_raw(
                    HARDENED_JWT_FINGERPRINT_KEY,
                    fingerprint.as_bytes().to_vec(),
                )
                .await
                .map_err(JwtKeyError::Store)?;

            Ok(key_bytes)
        }
    }
}

/// Transient secrets derived from the master seed during hardened-mode daemon
/// boot. Mirrors `tee::kms_bootstrap::BootstrappedSecrets`: all fields are
/// explicitly zeroized when the struct drops.
///
/// Create via [`load_boot_secrets`]. Callers extract the values they need
/// (by copy or encode) before the struct goes out of scope.
pub struct HardenedBootSecrets {
    /// AES-256-GCM storage-encryption key — pass to `server::run` as
    /// `storage_encryption_key`.
    pub storage_key: [u8; 32],
    /// Random JWT signing key — encode to base64 and inject into
    /// `config.auth.jwt_signing_key` in memory.
    pub jwt_key: [u8; 32],
}

impl Drop for HardenedBootSecrets {
    fn drop(&mut self) {
        self.storage_key.zeroize();
        self.jwt_key.zeroize();
    }
}

/// Load and derive all hardened-mode boot secrets from the master seed.
///
/// - Loads the seed from the configured external secret store, wrapping it in
///   `Zeroizing<Vec<u8>>` so it is zeroed when this function returns.
/// - Derives `storage_key` via HKDF.
/// - Loads (or generates on first boot) the JWT signing key from
///   `bootstrap_ks` via [`load_or_generate_jwt_key`], and emits the
///   appropriate `tracing::info!` log line.
///
/// Returns [`HardenedBootSecrets`] whose `Drop` impl zeroizes both keys.
pub async fn load_boot_secrets(
    config: &crate::config::AppConfig,
    seed_store: &dyn crate::keys::seed_store::SeedStore,
    bootstrap_ks: &KeyspaceHandle,
) -> Result<HardenedBootSecrets, Box<dyn std::error::Error>> {
    // Load the seed and immediately wrap it so it is zeroized on drop.
    let seed = zeroize::Zeroizing::new(
        seed_store
            .get()
            .await
            .map_err(|e| format!("hardened: seed load failed: {e}"))?
            .ok_or("hardened: no seed in secret store — run `vta setup` first")?,
    );

    let storage_key = *derive_storage_key(&seed, &config.hardened.storage_key_salt);
    // seed is zeroized here when Zeroizing<Vec<u8>> drops at end of this block.
    drop(seed);

    // Peek before calling so we can emit the right log line.
    let had_ciphertext = bootstrap_ks
        .get_raw(HARDENED_JWT_CT_KEY)
        .await
        .ok()
        .flatten()
        .is_some();

    let jwt_key = load_or_generate_jwt_key(bootstrap_ks, &storage_key)
        .await
        .map_err(|e| format!("{e}"))?;

    if had_ciphertext {
        tracing::info!("hardened: JWT signing key decrypted from bootstrap keyspace");
    } else {
        tracing::info!(
            "hardened: new random JWT signing key generated and \
             sealed in bootstrap keyspace"
        );
    }

    Ok(HardenedBootSecrets {
        storage_key,
        jwt_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Derivation is deterministic: same inputs → same output.
    #[test]
    fn derive_storage_key_is_deterministic() {
        let seed = [0x42u8; 32];
        let k1 = derive_storage_key(&seed, "test-salt");
        let k2 = derive_storage_key(&seed, "test-salt");
        assert_eq!(*k1, *k2);
    }

    /// Different salts produce different storage keys (domain separation).
    #[test]
    fn derive_storage_key_differs_by_salt() {
        let seed = [0x42u8; 32];
        let k1 = derive_storage_key(&seed, "salt-a");
        let k2 = derive_storage_key(&seed, "salt-b");
        assert_ne!(*k1, *k2);
    }

    /// Different seeds produce different storage keys.
    #[test]
    fn derive_storage_key_differs_by_seed() {
        let k1 = derive_storage_key(&[0x01u8; 32], "same-salt");
        let k2 = derive_storage_key(&[0x02u8; 32], "same-salt");
        assert_ne!(*k1, *k2);
    }

    /// Stability / test-vector: pins the exact HKDF-SHA256 output for a known
    /// seed + salt + info. If this test fails, the derivation algorithm or the
    /// `info` string (`b"vta-storage-key/v1"`) has silently changed — which
    /// would invalidate all encrypted data in every existing hardened-mode VTA.
    ///
    /// Vector computed from:
    ///   HKDF-SHA256(ikm=[0x42;32], salt=b"test-salt", info=b"vta-storage-key/v1")
    #[test]
    fn derive_storage_key_matches_known_test_vector() {
        let seed = [0x42u8; 32];
        let key = derive_storage_key(&seed, "test-salt");
        assert_eq!(
            hex::encode(*key),
            "4d2652108d380a68af082f04e031d6c0dd67d3f86692fa79783aff92a0e9df4e",
            "HKDF output changed — this would silently invalidate all encrypted fjall data"
        );
    }

    /// AES-GCM seal/open round-trips correctly.
    #[test]
    fn aes_gcm_seal_open_roundtrip() {
        let key = [0xABu8; 32];
        let plaintext = b"a 32-byte jwt signing key value!";
        let ct = aes_gcm_seal(&key, plaintext);
        let pt = aes_gcm_open(&key, &ct).expect("open should succeed");
        assert_eq!(pt, plaintext);
    }

    /// AES-GCM open fails with a different key (authentication failure).
    #[test]
    fn aes_gcm_open_fails_with_wrong_key() {
        let key = [0xABu8; 32];
        let wrong_key = [0xCDu8; 32];
        let ct = aes_gcm_seal(&key, b"secret jwt key bytes go here!!!");
        assert!(aes_gcm_open(&wrong_key, &ct).is_none());
    }

    /// AES-GCM open fails on a tampered ciphertext.
    #[test]
    fn aes_gcm_open_fails_on_tampered_ciphertext() {
        let key = [0x11u8; 32];
        let mut ct = aes_gcm_seal(&key, b"secret jwt key bytes go here!!!");
        let mid = ct.len() / 2;
        ct[mid] ^= 0xFF;
        assert!(aes_gcm_open(&key, &ct).is_none());
    }

    /// JWT fingerprint is deterministic and 32 hex chars.
    #[test]
    fn jwt_key_fingerprint_is_deterministic() {
        let key = [0xABu8; 32];
        let fp1 = jwt_key_fingerprint(&key);
        let fp2 = jwt_key_fingerprint(&key);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 32);
    }

    /// Different keys produce different fingerprints.
    #[test]
    fn jwt_key_fingerprint_differs_by_key() {
        let fp1 = jwt_key_fingerprint(&[0x01u8; 32]);
        let fp2 = jwt_key_fingerprint(&[0x02u8; 32]);
        assert_ne!(fp1, fp2);
    }

    // -----------------------------------------------------------------------
    // load_or_generate_jwt_key — integration scenarios against a real fjall store.
    // -----------------------------------------------------------------------

    fn temp_bootstrap_ks() -> (crate::store::Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = crate::store::Store::open(&config).expect("open store");
        (store, dir)
    }

    /// First-boot path: no ciphertext in the bootstrap keyspace.
    #[tokio::test]
    async fn first_boot_generates_and_seals_key() {
        let (store, _dir) = temp_bootstrap_ks();
        let bs_ks = store
            .keyspace(crate::keyspaces::BOOTSTRAP)
            .expect("bootstrap keyspace");
        let storage_key = [0x42u8; 32];

        let jwt_key = load_or_generate_jwt_key(&bs_ks, &storage_key)
            .await
            .expect("first boot should succeed");

        assert_eq!(jwt_key.len(), 32, "key must be 32 bytes");
        assert!(
            bs_ks.get_raw(HARDENED_JWT_CT_KEY).await.unwrap().is_some(),
            "ciphertext row must be written"
        );
        assert!(
            bs_ks
                .get_raw(HARDENED_JWT_FINGERPRINT_KEY)
                .await
                .unwrap()
                .is_some(),
            "fingerprint row must be written"
        );

        let ct = bs_ks.get_raw(HARDENED_JWT_CT_KEY).await.unwrap().unwrap();
        let decrypted: [u8; 32] = aes_gcm_open(&storage_key, &ct)
            .expect("decrypt")
            .try_into()
            .expect("32 bytes");
        assert_eq!(decrypted, jwt_key);
    }

    /// Subsequent-boot path: same key returned on second call.
    #[tokio::test]
    async fn subsequent_boot_returns_same_key() {
        let (store, _dir) = temp_bootstrap_ks();
        let bs_ks = store
            .keyspace(crate::keyspaces::BOOTSTRAP)
            .expect("bootstrap keyspace");
        let storage_key = [0x77u8; 32];

        let key_first = load_or_generate_jwt_key(&bs_ks, &storage_key)
            .await
            .expect("first boot");
        let key_second = load_or_generate_jwt_key(&bs_ks, &storage_key)
            .await
            .expect("subsequent boot");
        assert_eq!(
            key_first, key_second,
            "same key must be returned on restart"
        );
    }

    /// Wrong storage key → `JwtKeyError::DecryptFailed`.
    #[tokio::test]
    async fn wrong_storage_key_returns_decrypt_failed() {
        let (store, _dir) = temp_bootstrap_ks();
        let bs_ks = store
            .keyspace(crate::keyspaces::BOOTSTRAP)
            .expect("bootstrap keyspace");
        load_or_generate_jwt_key(&bs_ks, &[0x11u8; 32])
            .await
            .expect("first boot with key_a");
        let err = load_or_generate_jwt_key(&bs_ks, &[0x22u8; 32])
            .await
            .expect_err("must fail with wrong key");
        assert!(
            matches!(err, JwtKeyError::DecryptFailed),
            "expected DecryptFailed, got: {err}"
        );
    }

    /// Fingerprint missing → `JwtKeyError::FingerprintMissing`.
    #[tokio::test]
    async fn missing_fingerprint_returns_fingerprint_missing() {
        let (store, _dir) = temp_bootstrap_ks();
        let bs_ks = store
            .keyspace(crate::keyspaces::BOOTSTRAP)
            .expect("bootstrap keyspace");
        let storage_key = [0x33u8; 32];
        load_or_generate_jwt_key(&bs_ks, &storage_key)
            .await
            .expect("first boot");
        bs_ks
            .remove(HARDENED_JWT_FINGERPRINT_KEY)
            .await
            .expect("remove fingerprint");
        let err = load_or_generate_jwt_key(&bs_ks, &storage_key)
            .await
            .expect_err("must fail without fingerprint");
        assert!(
            matches!(err, JwtKeyError::FingerprintMissing),
            "expected FingerprintMissing, got: {err}"
        );
    }

    /// Tampered fingerprint → `JwtKeyError::FingerprintMismatch`.
    #[tokio::test]
    async fn tampered_fingerprint_returns_fingerprint_mismatch() {
        let (store, _dir) = temp_bootstrap_ks();
        let bs_ks = store
            .keyspace(crate::keyspaces::BOOTSTRAP)
            .expect("bootstrap keyspace");
        let storage_key = [0x44u8; 32];
        load_or_generate_jwt_key(&bs_ks, &storage_key)
            .await
            .expect("first boot");
        bs_ks
            .insert_raw(
                HARDENED_JWT_FINGERPRINT_KEY,
                b"deadbeefdeadbeefdeadbeefdeadbeef".to_vec(),
            )
            .await
            .expect("overwrite fingerprint");
        let err = load_or_generate_jwt_key(&bs_ks, &storage_key)
            .await
            .expect_err("must fail on fingerprint mismatch");
        assert!(
            matches!(err, JwtKeyError::FingerprintMismatch { .. }),
            "expected FingerprintMismatch, got: {err}"
        );
    }

    /// Rotate path: new random key generated after both entries deleted.
    #[tokio::test]
    async fn rotate_generates_new_key() {
        let (store, _dir) = temp_bootstrap_ks();
        let bs_ks = store
            .keyspace(crate::keyspaces::BOOTSTRAP)
            .expect("bootstrap keyspace");
        let storage_key = [0x55u8; 32];

        let original_key = load_or_generate_jwt_key(&bs_ks, &storage_key)
            .await
            .expect("first boot");
        bs_ks
            .remove(HARDENED_JWT_CT_KEY)
            .await
            .expect("remove ciphertext");
        bs_ks
            .remove(HARDENED_JWT_FINGERPRINT_KEY)
            .await
            .expect("remove fingerprint");

        let new_key = load_or_generate_jwt_key(&bs_ks, &storage_key)
            .await
            .expect("boot after rotate");
        assert_eq!(new_key.len(), 32);
        assert_ne!(original_key, new_key, "rotate must produce a different key");

        let key_third = load_or_generate_jwt_key(&bs_ks, &storage_key)
            .await
            .expect("subsequent boot after rotate");
        assert_eq!(new_key, key_third);
    }
}
