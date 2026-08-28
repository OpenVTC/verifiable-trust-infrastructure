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
//! 3. **JWT signing key** — a random 32-byte key, stored in the **encrypted**
//!    `KEYS` keyspace at `hardened:jwt_key`:
//!    - **First boot**: generate it and write it through the encrypted handle.
//!      The `VAE1` layer that protects every other secret protects this one; the
//!      value is not separately sealed.
//!    - **Subsequent boots**: read it back. A wrong `storage_key_salt` or seed
//!      fails the `VAE1` decrypt, which is the tamper/mismatch signal — the
//!      separate SHA-256 fingerprint row it used to carry is gone, because the
//!      AEAD tag authenticates the value and the AAD binds it to its
//!      `(keyspace, key)` location. The retired bespoke seal had no associated
//!      data at all, so a relocated ciphertext would still have opened.
//!    - The JWT key is **never written to `config.toml`**.
//!    - **Independent rotation**: `vta hardened rotate-jwt` clears the row; the
//!      next boot generates a fresh key. This does **not** require rotating the
//!      master seed.
//!
//! Both features require the seed to be in a **real** secret-store backend
//! (OS keyring, AWS/GCP/Azure/Vault/K8s). The plaintext file fallback
//! defeats the protection and triggers a startup warning.
//!
//! Analogous to `tee::kms_bootstrap` — that module does the same job for TEE
//! deployments using KMS as the trust anchor; this one uses the external
//! secret store instead.
//!
//! # Migration
//!
//! Two one-time conversions run automatically at boot, in this order:
//!
//! 1. **Store**: rows written before `[hardened] enabled = true` are converted
//!    to `VAE1` ([`migrate_store_to_encrypted`]). Without this the flag makes
//!    every pre-existing row unreadable, including the ACL keyspace.
//! 2. **JWT key**: a key held under the retired `bootstrap:hardened:jwt_ciphertext`
//!    seal is opened, rewritten into the encrypted `KEYS` keyspace, and the two
//!    legacy rows deleted. The key itself is carried across unchanged, so live
//!    sessions survive the move.
//!
//! Both are idempotent, so they cost one scan and no writes on every later boot.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::store::{KeyspaceHandle, Store};

/// Keyspaces deliberately left **unencrypted** by the storage layer, and so
/// excluded from [`migrate_store_to_encrypted`].
///
/// `bootstrap` is the only one. `server::run` opens it bare (see the
/// "unencrypted, KMS-protected" call site in `server.rs`) because its contents
/// are already application-layer sealed and, in TEE deployments, must stay
/// readable by the parent-side proxy that has no storage key.
///
/// Migrating it would be actively harmful, not merely redundant: the
/// hardened JWT ciphertext at [`HARDENED_JWT_CT_KEY`] is written and read
/// through a *bare* handle, so wrapping it in a `VAE1` envelope would make the
/// next boot's [`aes_gcm_open`] fail on what looks like a tampered ciphertext —
/// i.e. an unbootable VTA whose error message points at the wrong cause.
pub const MIGRATION_EXCLUDED_KEYSPACES: &[&str] = &[vta_keyspaces::BOOTSTRAP];

/// `KEYS`-keyspace row holding the JWT signing key.
///
/// Written and read through the **encrypted** handle, so the value on disk is a
/// standard `VAE1` envelope like every other secret this VTA stores. There is
/// no second, hand-rolled encryption layer inside it.
pub const HARDENED_JWT_KEY: &str = "hardened:jwt_key";

/// Legacy `BOOTSTRAP`-keyspace row: the JWT key under a bespoke application-layer
/// AES-GCM seal, from before the key moved into the encrypted `KEYS` keyspace.
///
/// Read once by [`load_or_generate_jwt_key`] to carry an existing key across the
/// move, then deleted. Removable once no deployment can still be on the old
/// layout.
pub const LEGACY_JWT_CT_KEY: &str = "hardened:jwt_ciphertext";

/// Legacy `BOOTSTRAP`-keyspace row: SHA-256 fingerprint of the JWT key.
///
/// Obsolete. It guarded a ciphertext that carried no AAD; `VAE1` binds every
/// value to its `(keyspace, key)` location, which is strictly stronger. Deleted
/// alongside [`LEGACY_JWT_CT_KEY`] during the one-time move.
pub const LEGACY_JWT_FINGERPRINT_KEY: &str = "hardened:jwt_fingerprint";

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

/// Mint a fresh random salt for a new hardened-mode VTA.
///
/// 32 hex characters (128 bits) from the OS CSPRNG. `vta setup` calls this once
/// and writes the result into `config.toml`; from then on it must never change,
/// because the storage key is derived from it.
///
/// To be precise about what this buys and what it does not: an HKDF salt is not
/// required to be secret, and the IKM here is already a per-VTA high-entropy
/// master seed, so a shared salt would *not* let one VTA derive another's
/// storage key. This is defence in depth, plus honesty — `storage_key_salt` is
/// documented as a per-VTA constant, so it should actually vary per VTA. It is
/// not a fix for a break.
///
/// Existing configs that omit the field keep the legacy compatibility constant,
/// so this changes nothing for a VTA that has already written data.
pub fn generate_storage_key_salt() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    hex::encode(bytes)
}

/// Decrypt a legacy `[12-byte nonce || ciphertext+tag]` blob.
///
/// Only used to read [`LEGACY_JWT_CT_KEY`] once during the move to `VAE1`.
/// Nothing writes this format any more.
///
/// Returns `None` on authentication failure (tampered or wrong key).
pub fn legacy_aes_gcm_open(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 13 {
        return None;
    }
    // `try_from` rather than the deprecated `from_slice`, which panics on a
    // wrong length. The bounds check above makes the slice exactly 12, so this
    // cannot fail — but a panicking conversion on a decrypt path is one
    // refactor away from being reachable.
    let nonce = aes_gcm::Nonce::try_from(&blob[..12]).ok()?;
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher.decrypt(&nonce, &blob[12..]).ok()
}

/// Error variants for [`load_or_generate_jwt_key`].
#[derive(Debug)]
pub enum JwtKeyError {
    /// The stored key is not exactly 32 bytes — the row is corrupt.
    BadKeyLength,
    /// A legacy sealed row exists but would not open under the storage key.
    LegacyDecryptFailed,
    /// A store I/O error, which for an encrypted handle includes a failed
    /// `VAE1` decrypt (wrong `storage_key_salt`, wrong seed, or tampering).
    Store(vti_common::error::AppError),
}

impl std::fmt::Display for JwtKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtKeyError::BadKeyLength => write!(
                f,
                "hardened: stored JWT signing key is not 32 bytes — the row is corrupt. \
                 Run `vta hardened rotate-jwt` to generate a new one (existing sessions \
                 will be invalidated)."
            ),
            JwtKeyError::LegacyDecryptFailed => write!(
                f,
                "hardened: the legacy sealed JWT signing key would not decrypt — \
                 storage_key_salt mismatch or tampering. Run `vta hardened rotate-jwt` \
                 to discard it and generate a new key (existing sessions will be \
                 invalidated)."
            ),
            JwtKeyError::Store(e) => write!(
                f,
                "hardened: could not read the JWT signing key: {e}. If this is a decrypt \
                 failure, the storage_key_salt or the master seed does not match the one \
                 this store was written with."
            ),
        }
    }
}

impl From<vti_common::error::AppError> for JwtKeyError {
    fn from(e: vti_common::error::AppError) -> Self {
        JwtKeyError::Store(e)
    }
}

/// Load the JWT signing key, or generate one on first boot.
///
/// The key lives in the **encrypted** `KEYS` keyspace at [`HARDENED_JWT_KEY`],
/// stored as raw bytes through an encrypted handle. The `VAE1` layer that
/// protects every other secret protects this one too — there is no second,
/// hand-rolled AEAD inside the value.
///
/// That is a simplification and a small strengthening at once. The previous
/// layout sealed the key with a bespoke AES-GCM blob in the *unencrypted*
/// `bootstrap` keyspace, carrying **no associated data**: the ciphertext was not
/// bound to where it was stored, so it could be copied to another row and would
/// still open. `VAE1` binds every value to its `(keyspace, key)` location. The
/// separate SHA-256 fingerprint row existed to cover part of that gap and is now
/// redundant — the AEAD tag authenticates the value and the AAD pins its
/// location.
///
/// # Boot paths
///
/// - **Existing key**: read it back through `keys_ks`. A `VAE1` decrypt failure
///   surfaces as [`JwtKeyError::Store`] — the salt or seed does not match.
/// - **Legacy layout**: a [`LEGACY_JWT_CT_KEY`] row in `bootstrap_ks` is opened
///   with the old scheme, rewritten into `keys_ks`, and both legacy rows are
///   deleted. One-time, and it preserves live sessions across the move.
/// - **First boot / after rotate**: generate a random 32-byte key and store it.
pub async fn load_or_generate_jwt_key(
    keys_ks: &KeyspaceHandle,
    bootstrap_ks: &KeyspaceHandle,
    storage_key: &[u8; 32],
) -> Result<[u8; 32], JwtKeyError> {
    // 1. Current layout.
    if let Some(bytes) = keys_ks.get_raw(HARDENED_JWT_KEY).await? {
        return bytes.try_into().map_err(|_| JwtKeyError::BadKeyLength);
    }

    // 2. Legacy layout: carry the key across rather than rotating it, so the
    //    move does not silently invalidate every live session.
    if let Some(blob) = bootstrap_ks.get_raw(LEGACY_JWT_CT_KEY).await? {
        let plaintext =
            legacy_aes_gcm_open(storage_key, &blob).ok_or(JwtKeyError::LegacyDecryptFailed)?;
        let key: [u8; 32] = plaintext
            .try_into()
            .map_err(|_| JwtKeyError::BadKeyLength)?;

        keys_ks.insert_raw(HARDENED_JWT_KEY, key.to_vec()).await?;
        bootstrap_ks.remove(LEGACY_JWT_CT_KEY).await?;
        bootstrap_ks.remove(LEGACY_JWT_FINGERPRINT_KEY).await?;

        tracing::info!(
            "hardened: moved the JWT signing key into the encrypted KEYS keyspace; \
             the bespoke seal and its fingerprint row are gone. The key is unchanged, \
             so existing sessions remain valid"
        );
        return Ok(key);
    }

    // 3. First boot, or the row was cleared by `vta hardened rotate-jwt`.
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    keys_ks.insert_raw(HARDENED_JWT_KEY, key.to_vec()).await?;
    Ok(key)
}

/// Convert any still-plaintext rows in the encrypted keyspaces to the `VAE1`
/// format, so a VTA that ran before `[hardened] enabled = true` stays readable.
///
/// # Why this has to exist
///
/// The store is deliberately **fail-closed**: `KeyspaceHandle`'s decrypt path
/// has no lenient "maybe it's plaintext" fallback, because that would reopen
/// the cut-and-paste downgrade hole the `VAE1` AAD binding closes. The
/// consequence is that flipping `hardened.enabled` on a VTA that already has
/// data makes *every* pre-existing row fail to read — including the ACL
/// keyspace, which locks the operator out of their own VTA. The data is intact
/// but unreachable through the only handle the daemon will open.
///
/// So the flag cannot be a pure config change; something has to convert the
/// existing rows. This runs that conversion at boot, before `server::run` opens
/// anything, mirroring what `vtc-service` already does for its own at-rest
/// encryption.
///
/// # Properties
///
/// - **Idempotent.** `migrate_to_encrypted` skips rows already in `VAE1`
///   format, so the steady-state cost on every subsequent boot is one prefix
///   scan per keyspace and zero writes.
/// - **Crash-safe.** An interrupted run leaves a mix of encrypted and plaintext
///   rows, which the next boot completes. There is no half-converted state that
///   needs manual repair.
/// - **Bare handles only.** Each keyspace is opened without encryption, which
///   is what `migrate_to_encrypted` requires — it reads raw bytes, decides per
///   row, and writes back through an encrypted handle.
/// - **Skips `bootstrap`**, for the reason on [`MIGRATION_EXCLUDED_KEYSPACES`].
///
/// Returns the total number of rows converted (0 on a fresh install, and on
/// every boot after the first migrating one).
pub async fn migrate_store_to_encrypted(
    store: &Store,
    key: [u8; 32],
) -> Result<usize, vti_common::error::AppError> {
    let mut total = 0usize;

    for name in vta_keyspaces::ALL {
        if MIGRATION_EXCLUDED_KEYSPACES.contains(name) {
            continue;
        }
        // Bare handle: migrate_to_encrypted refuses an already-encrypted one,
        // and needs raw reads to tell converted rows from legacy ones.
        let bare = store.keyspace(name)?;
        let migrated = bare.migrate_to_encrypted(key).await?;
        if migrated > 0 {
            tracing::info!(
                keyspace = %name,
                rows = migrated,
                "hardened: converted plaintext rows to encrypted storage"
            );
            total += migrated;
        }
    }

    if total > 0 {
        // The conversion is the only thing standing between this boot and an
        // unreadable store; make it durable before anything else runs.
        store.persist().await?;
        tracing::warn!(
            rows = total,
            "hardened: migrated a pre-existing plaintext store to encrypted at rest — \
             this is a one-time conversion; take a backup if you have not already"
        );
    }

    Ok(total)
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
/// Order matters and is enforced here rather than left to the caller:
///
/// 1. Load the seed (in `Zeroizing`, so it is wiped when this returns) and
///    derive the storage key.
/// 2. **Migrate the store**, converting any rows written before hardened mode
///    was enabled. This has to precede step 3, because step 3 reads and writes
///    through an *encrypted* handle on the `KEYS` keyspace — against an
///    unmigrated store that read would fail on the first legacy row.
/// 3. Load (or generate, or carry over from the legacy layout) the JWT signing
///    key.
///
/// Returns [`HardenedBootSecrets`], whose `Drop` zeroizes both keys.
pub async fn load_boot_secrets(
    config: &crate::config::AppConfig,
    seed_store: &dyn crate::keys::seed_store::SeedStore,
    store: &Store,
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
    // seed is zeroized here when Zeroizing<Vec<u8>> drops.
    drop(seed);

    // Step 2 — before any encrypted read.
    migrate_store_to_encrypted(store, storage_key)
        .await
        .map_err(|e| format!("hardened: store migration failed: {e}"))?;

    let keys_ks = store
        .keyspace(vta_keyspaces::KEYS)
        .map_err(|e| format!("hardened: open KEYS keyspace: {e}"))?
        .with_encryption(storage_key);
    // Bare on purpose: the legacy row predates VAE1 and the keyspace is never
    // migrated. See MIGRATION_EXCLUDED_KEYSPACES.
    let bootstrap_ks = store
        .keyspace(vta_keyspaces::BOOTSTRAP)
        .map_err(|e| format!("hardened: open BOOTSTRAP keyspace: {e}"))?;

    let existed = keys_ks
        .get_raw(HARDENED_JWT_KEY)
        .await
        .ok()
        .flatten()
        .is_some();

    let jwt_key = load_or_generate_jwt_key(&keys_ks, &bootstrap_ks, &storage_key)
        .await
        .map_err(|e| format!("{e}"))?;

    if existed {
        tracing::info!("hardened: JWT signing key loaded from the encrypted KEYS keyspace");
    } else {
        tracing::info!(
            "hardened: JWT signing key established in the encrypted KEYS keyspace \
             (generated, or carried over from the legacy sealed row)"
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

    // -----------------------------------------------------------------------
    // load_or_generate_jwt_key — integration scenarios against a real fjall store.
    // -----------------------------------------------------------------------

    /// AES-GCM seal in the retired format, so the legacy-import test can build
    /// a fixture. Nothing in the crate writes this any more.
    fn legacy_aes_gcm_seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        use rand::Rng;
        let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce: &aes_gcm::Nonce<_> = (&nonce_bytes).into();
        let mut ct = cipher.encrypt(nonce, plaintext).expect("AES-GCM encrypt");
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.append(&mut ct);
        out
    }

    /// `(encrypted KEYS handle, bare BOOTSTRAP handle)` — the exact pair
    /// `load_boot_secrets` builds.
    fn jwt_handles(
        store: &crate::store::Store,
        storage_key: [u8; 32],
    ) -> (KeyspaceHandle, KeyspaceHandle) {
        let keys = store
            .keyspace(crate::keyspaces::KEYS)
            .expect("keys keyspace")
            .with_encryption(storage_key);
        let bootstrap = store
            .keyspace(crate::keyspaces::BOOTSTRAP)
            .expect("bootstrap keyspace");
        (keys, bootstrap)
    }

    fn temp_bootstrap_ks() -> (crate::store::Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = crate::store::Store::open(&config).expect("open store");
        (store, dir)
    }

    /// First boot: the key lands in the encrypted KEYS keyspace, and the value
    /// on disk is a VAE1 envelope — not a bespoke sealed blob, and not plaintext.
    #[tokio::test]
    async fn first_boot_stores_key_in_the_encrypted_keyspace() {
        let (store, _dir) = temp_bootstrap_ks();
        let storage_key = [0x42u8; 32];
        let (keys_ks, bs_ks) = jwt_handles(&store, storage_key);

        let jwt_key = load_or_generate_jwt_key(&keys_ks, &bs_ks, &storage_key)
            .await
            .expect("first boot should succeed");
        assert_eq!(jwt_key.len(), 32);

        // Read back through the encrypted handle.
        let stored = keys_ks
            .get_raw(HARDENED_JWT_KEY)
            .await
            .unwrap()
            .expect("row written");
        assert_eq!(stored, jwt_key.to_vec());

        // And confirm the on-disk form really is VAE1, i.e. the storage layer is
        // doing the encrypting rather than a second layer inside the value.
        let raw = store
            .keyspace(crate::keyspaces::KEYS)
            .unwrap()
            .get_raw(HARDENED_JWT_KEY)
            .await
            .unwrap()
            .expect("row present on disk");
        assert!(
            raw.starts_with(b"VAE1"),
            "expected a VAE1 envelope on disk, got {:?}",
            &raw[..raw.len().min(8)]
        );
        assert_ne!(raw, jwt_key.to_vec(), "key must not be stored in the clear");

        // Nothing is left in the bootstrap keyspace any more.
        assert!(bs_ks.get_raw(LEGACY_JWT_CT_KEY).await.unwrap().is_none());
        assert!(
            bs_ks
                .get_raw(LEGACY_JWT_FINGERPRINT_KEY)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Subsequent boot returns the same key.
    #[tokio::test]
    async fn subsequent_boot_returns_same_key() {
        let (store, _dir) = temp_bootstrap_ks();
        let storage_key = [0x77u8; 32];
        let (keys_ks, bs_ks) = jwt_handles(&store, storage_key);

        let first = load_or_generate_jwt_key(&keys_ks, &bs_ks, &storage_key)
            .await
            .expect("first boot");
        let second = load_or_generate_jwt_key(&keys_ks, &bs_ks, &storage_key)
            .await
            .expect("subsequent boot");
        assert_eq!(first, second);
    }

    /// A wrong storage key cannot read the row: the VAE1 layer fails the decrypt,
    /// which is what replaced the hand-rolled AES-GCM open.
    #[tokio::test]
    async fn wrong_storage_key_cannot_read_the_jwt_key() {
        let (store, _dir) = temp_bootstrap_ks();
        let (keys_a, bs_a) = jwt_handles(&store, [0x11u8; 32]);
        load_or_generate_jwt_key(&keys_a, &bs_a, &[0x11u8; 32])
            .await
            .expect("first boot with key_a");

        let (keys_b, bs_b) = jwt_handles(&store, [0x22u8; 32]);
        let err = load_or_generate_jwt_key(&keys_b, &bs_b, &[0x22u8; 32])
            .await
            .expect_err("must not open under a different storage key");
        assert!(
            matches!(err, JwtKeyError::Store(_)),
            "expected a decrypt failure from the store layer, got: {err}"
        );
    }

    /// The value is bound to its `(keyspace, key)` location by VAE1's AAD, so a
    /// row copied elsewhere does not open. The retired bespoke seal carried no
    /// associated data and *would* have opened — this is the strengthening the
    /// move buys.
    #[tokio::test]
    async fn jwt_key_row_is_bound_to_its_location() {
        let (store, _dir) = temp_bootstrap_ks();
        let storage_key = [0x64u8; 32];
        let (keys_ks, bs_ks) = jwt_handles(&store, storage_key);
        load_or_generate_jwt_key(&keys_ks, &bs_ks, &storage_key)
            .await
            .expect("first boot");

        let bare = store.keyspace(crate::keyspaces::KEYS).unwrap();
        let envelope = bare.get_raw(HARDENED_JWT_KEY).await.unwrap().unwrap();
        bare.insert_raw("hardened:jwt_key_copy", envelope)
            .await
            .expect("cut-and-paste the envelope to another row");

        assert!(
            keys_ks.get_raw("hardened:jwt_key_copy").await.is_err(),
            "a relocated envelope must not decrypt — that is the AAD binding"
        );
    }

    /// The one-time move: an existing legacy sealed row is carried over rather
    /// than rotated, so live sessions survive, and both legacy rows are cleaned up.
    #[tokio::test]
    async fn legacy_sealed_key_is_migrated_not_rotated() {
        let (store, _dir) = temp_bootstrap_ks();
        let storage_key = [0x5Au8; 32];
        let (keys_ks, bs_ks) = jwt_handles(&store, storage_key);

        let original = [0xC3u8; 32];
        bs_ks
            .insert_raw(
                LEGACY_JWT_CT_KEY,
                legacy_aes_gcm_seal(&storage_key, &original),
            )
            .await
            .expect("write legacy ciphertext");
        bs_ks
            .insert_raw(
                LEGACY_JWT_FINGERPRINT_KEY,
                b"deadbeefdeadbeefdeadbeefdeadbeef".to_vec(),
            )
            .await
            .expect("write legacy fingerprint");

        let loaded = load_or_generate_jwt_key(&keys_ks, &bs_ks, &storage_key)
            .await
            .expect("legacy import");
        assert_eq!(
            loaded, original,
            "the key must be carried across, not regenerated — otherwise the move \
             silently invalidates every session"
        );

        assert_eq!(
            keys_ks.get_raw(HARDENED_JWT_KEY).await.unwrap().unwrap(),
            original.to_vec()
        );
        assert!(
            bs_ks.get_raw(LEGACY_JWT_CT_KEY).await.unwrap().is_none(),
            "legacy ciphertext must be removed"
        );
        assert!(
            bs_ks
                .get_raw(LEGACY_JWT_FINGERPRINT_KEY)
                .await
                .unwrap()
                .is_none(),
            "legacy fingerprint must be removed"
        );

        // Idempotent: the next boot takes the current-layout path.
        let again = load_or_generate_jwt_key(&keys_ks, &bs_ks, &storage_key)
            .await
            .expect("boot after import");
        assert_eq!(loaded, again);
    }

    /// A legacy row that will not open is an error, not a silent regeneration —
    /// regenerating would invalidate every session without saying so.
    #[tokio::test]
    async fn undecryptable_legacy_row_errors() {
        let (store, _dir) = temp_bootstrap_ks();
        let storage_key = [0x6Bu8; 32];
        let (keys_ks, bs_ks) = jwt_handles(&store, storage_key);

        bs_ks
            .insert_raw(
                LEGACY_JWT_CT_KEY,
                legacy_aes_gcm_seal(&[0xFFu8; 32], &[0x01u8; 32]),
            )
            .await
            .expect("write a legacy row sealed under a different key");

        let err = load_or_generate_jwt_key(&keys_ks, &bs_ks, &storage_key)
            .await
            .expect_err("must not silently regenerate");
        assert!(
            matches!(err, JwtKeyError::LegacyDecryptFailed),
            "expected LegacyDecryptFailed, got: {err}"
        );
    }

    /// Rotate path: clearing the row yields a fresh key on the next boot.
    #[tokio::test]
    async fn rotate_generates_new_key() {
        let (store, _dir) = temp_bootstrap_ks();
        let storage_key = [0x55u8; 32];
        let (keys_ks, bs_ks) = jwt_handles(&store, storage_key);

        let original = load_or_generate_jwt_key(&keys_ks, &bs_ks, &storage_key)
            .await
            .expect("first boot");
        keys_ks.remove(HARDENED_JWT_KEY).await.expect("rotate");

        let rotated = load_or_generate_jwt_key(&keys_ks, &bs_ks, &storage_key)
            .await
            .expect("boot after rotate");
        assert_ne!(original, rotated, "rotate must produce a different key");

        let third = load_or_generate_jwt_key(&keys_ks, &bs_ks, &storage_key)
            .await
            .expect("stable afterwards");
        assert_eq!(rotated, third);
    }

    // -----------------------------------------------------------------------
    // migrate_store_to_encrypted — the flip-the-flag-on-an-existing-VTA path.
    // -----------------------------------------------------------------------

    /// The core guarantee: rows written before hardened mode was enabled stay
    /// readable through an encrypted handle afterwards. Without the migration
    /// this read fails and the operator is locked out of their own ACL.
    #[tokio::test]
    async fn migration_makes_preexisting_plaintext_rows_readable() {
        let (store, _dir) = temp_bootstrap_ks();
        let key = [0x91u8; 32];

        // Pre-hardened VTA: plaintext row via a bare handle.
        let bare_acl = store.keyspace(crate::keyspaces::ACL).expect("acl");
        bare_acl
            .insert_raw("did:key:zLegacy", b"legacy-plaintext".to_vec())
            .await
            .expect("write legacy row");

        // Flipping the flag without migrating: the encrypted handle cannot read it.
        let enc_acl = store
            .keyspace(crate::keyspaces::ACL)
            .expect("acl")
            .with_encryption(key);
        assert!(
            enc_acl.get_raw("did:key:zLegacy").await.is_err(),
            "a legacy plaintext row must NOT be silently readable through an \
             encrypted handle — that would be the downgrade hole"
        );

        let migrated = migrate_store_to_encrypted(&store, key)
            .await
            .expect("migration");
        assert!(
            migrated >= 1,
            "expected at least the ACL row, got {migrated}"
        );

        let value = enc_acl
            .get_raw("did:key:zLegacy")
            .await
            .expect("read after migration")
            .expect("row present");
        assert_eq!(value, b"legacy-plaintext");
    }

    /// Idempotent: a second pass converts nothing and leaves values intact, so
    /// the steady-state cost on every later boot is zero writes.
    #[tokio::test]
    async fn migration_is_idempotent() {
        let (store, _dir) = temp_bootstrap_ks();
        let key = [0x92u8; 32];

        store
            .keyspace(crate::keyspaces::ACL)
            .expect("acl")
            .insert_raw("k", b"v".to_vec())
            .await
            .expect("seed row");

        let first = migrate_store_to_encrypted(&store, key)
            .await
            .expect("first");
        assert!(first >= 1);
        let second = migrate_store_to_encrypted(&store, key)
            .await
            .expect("second");
        assert_eq!(second, 0, "already-encrypted rows must be skipped");

        let value = store
            .keyspace(crate::keyspaces::ACL)
            .expect("acl")
            .with_encryption(key)
            .get_raw("k")
            .await
            .expect("read")
            .expect("present");
        assert_eq!(value, b"v", "value must survive a repeated migration");
    }

    /// The bootstrap keyspace must stay bare. It holds rows that are read
    /// through unencrypted handles — TEE's `tee:did_log`, which the parent-side
    /// proxy reads without any storage key, and the legacy sealed JWT row that
    /// the one-time import still has to open. Wrapping either in VAE1 would make
    /// the reader fail as though the value had been tampered with.
    #[tokio::test]
    async fn migration_leaves_bootstrap_keyspace_bare() {
        let (store, _dir) = temp_bootstrap_ks();
        let storage_key = [0x93u8; 32];
        let (keys_ks, bs_ks) = jwt_handles(&store, storage_key);

        // A parent-readable row, and a legacy sealed JWT row.
        bs_ks
            .insert_raw("tee:did_log", b"{\"versionId\":\"1-abc\"}".to_vec())
            .await
            .expect("write parent-readable row");
        let original = [0xD4u8; 32];
        bs_ks
            .insert_raw(
                LEGACY_JWT_CT_KEY,
                legacy_aes_gcm_seal(&storage_key, &original),
            )
            .await
            .expect("write legacy ciphertext");

        migrate_store_to_encrypted(&store, storage_key)
            .await
            .expect("migration");

        // Still plaintext for a reader with no storage key.
        assert_eq!(
            bs_ks.get_raw("tee:did_log").await.unwrap().unwrap(),
            b"{\"versionId\":\"1-abc\"}".to_vec(),
            "migrating bootstrap would break the parent-side proxy"
        );

        // And the legacy import still works, which it would not if the blob had
        // been wrapped in VAE1 underneath it.
        let imported = load_or_generate_jwt_key(&keys_ks, &bs_ks, &storage_key)
            .await
            .expect("legacy import after migration");
        assert_eq!(imported, original);
    }
}
