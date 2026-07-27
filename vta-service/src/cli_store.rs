//! `CliStore` — thin store wrapper for offline CLI commands under hardened configuration.
//!
//! Offline CLI commands (ACL, keys, vault, webvh, …) need to open fjall
//! keyspaces with the same per-value AES-256-GCM encryption that the running
//! daemon uses. `CliStore` abstracts that: it derives the storage-encryption
//! key from the master seed (when `hardened.enabled = true`) and wraps every
//! `keyspace()` call with `with_encryption(key)` transparently.
//!
//! When `hardened.enabled = false` the wrapper is a zero-cost pass-through —
//! callers never need to branch on the hardened flag.

use crate::hardened_bootstrap::derive_storage_key;
use crate::store::KeyspaceHandle;

/// Derive the storage-encryption key for an offline CLI command.
///
/// Loads the master seed from the configured secret-store backend, derives the
/// storage key via HKDF, and returns it. Returns `None` when
/// `hardened.enabled = false` (no encryption in use).
///
/// This is the single shared helper for all offline CLI commands that need to
/// open fjall keyspaces with the correct encryption state. If the seed load
/// fails the error is returned and the caller should surface it to the operator.
pub async fn load_storage_key_for_cli(
    config: &crate::config::AppConfig,
) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
    if !config.hardened.enabled {
        return Ok(None);
    }
    let seed_store = crate::keys::seed_store::create_seed_store(config)
        .map_err(|e| format!("hardened: failed to create seed store: {e}"))?;
    let seed = zeroize::Zeroizing::new(
        seed_store
            .get()
            .await
            .map_err(|e| format!("hardened: seed load failed: {e}"))?
            .ok_or("hardened: no seed in secret store — run `vta setup` first")?,
    );
    let key = *derive_storage_key(&seed, &config.hardened.storage_key_salt);
    // seed is zeroized here when Zeroizing<Vec<u8>> drops.
    Ok(Some(key))
}

/// A thin store wrapper for offline CLI commands.
///
/// Holds an open `Store` and an optional storage-encryption key derived from
/// the master seed. Every call to `keyspace()` transparently wraps the handle
/// with `with_encryption(key)` when hardened configuration is active, or returns a bare
/// handle when it is not — callers never branch on `hardened.enabled`.
///
/// Implements `Deref<Target=Store>` so `cs.persist()`, `cs.keyspace_raw()`,
/// etc. work directly without going through `.store`.
///
/// # Usage
///
/// ```rust
/// let cs = CliStore::open(&config).await?;
/// let acl_ks  = cs.keyspace(crate::keyspaces::ACL)?;
/// let keys_ks = cs.keyspace(crate::keyspaces::KEYS)?;
/// cs.persist().await?;
/// ```
pub struct CliStore {
    /// The underlying fjall store.  Exposed as a field so callers can pass
    /// `&cs.store` to functions that explicitly require `&Store`; prefer
    /// the `Deref` impl (`&*cs` or just `&cs`) in new code.
    pub store: crate::store::Store,
    enc_key: Option<[u8; 32]>,
}

impl std::ops::Deref for CliStore {
    type Target = crate::store::Store;
    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

impl Drop for CliStore {
    fn drop(&mut self) {
        // Zeroize the storage-encryption key when the CLI command finishes so
        // it does not linger in heap memory. Mirrors `HardenedBootSecrets::drop`.
        if let Some(ref mut key) = self.enc_key {
            zeroize::Zeroize::zeroize(key);
        }
    }
}

impl CliStore {
    /// Open the store and, if `hardened.enabled`, load the master seed from
    /// the configured backend and derive the storage-encryption key.
    pub async fn open(
        config: &crate::config::AppConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let enc_key = load_storage_key_for_cli(config).await?;
        let store = crate::store::Store::open(&config.store)
            .map_err(|e| format!("failed to open store: {e}"))?;
        Ok(Self { store, enc_key })
    }

    /// Construct a `CliStore` from an already-open `Store` and an optional
    /// encryption key.  Use this when the store open needs a custom error
    /// handler (e.g. `status.rs` which returns early if the daemon is
    /// running) and the enc_key has been pre-loaded with
    /// [`load_storage_key_for_cli`].
    pub fn from_store(store: crate::store::Store, enc_key: Option<[u8; 32]>) -> Self {
        Self { store, enc_key }
    }

    /// The storage-encryption key, if hardened configuration is active.
    /// Pass this to `build_app_state(…, enc_key, …)` for code paths that
    /// use the full app-state builder instead of opening keyspaces directly.
    pub fn enc_key(&self) -> Option<[u8; 32]> {
        self.enc_key
    }

    /// Open a keyspace, wrapping it with AES-256-GCM encryption when
    /// hardened configuration is active. Equivalent to:
    /// ```rust
    /// let ks = store.keyspace(name)?;
    /// let ks = if let Some(key) = enc_key { ks.with_encryption(key) } else { ks };
    /// ```
    pub fn keyspace(&self, name: &str) -> Result<KeyspaceHandle, vti_common::error::AppError> {
        let ks = self.store.keyspace(name)?;
        Ok(match self.enc_key {
            Some(key) => ks.with_encryption(key),
            None => ks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only keyspace names — not real production keyspaces; defined as
    // constants so the `no_bare_keyspace_literals` guard stays happy.
    const KS_TEST: &str = "test";
    const KS_SECRETS: &str = "secrets";
    const KS_DATA: &str = "data";

    fn temp_cli_store(enc_key: Option<[u8; 32]>) -> (CliStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = crate::store::Store::open(&config).expect("open store");
        (CliStore::from_store(store, enc_key), dir)
    }

    /// `from_store` with `None` enc_key → `keyspace()` returns a bare handle.
    #[tokio::test]
    async fn cli_store_no_key_returns_bare_handle() {
        let (cs, _dir) = temp_cli_store(None);
        let ks = cs.keyspace(KS_TEST).expect("keyspace");
        assert!(
            !ks.is_encrypted(),
            "handle must be bare when enc_key is None"
        );
        ks.insert_raw("row", b"value".to_vec()).await.unwrap();
        let raw = cs
            .store
            .keyspace(KS_TEST)
            .unwrap()
            .get_raw("row")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(raw, b"value", "bare write must be plaintext on disk");
    }

    /// `from_store` with `Some(key)` → `keyspace()` returns an encrypted handle.
    #[tokio::test]
    async fn cli_store_with_key_returns_encrypted_handle() {
        let enc_key = [0xABu8; 32];
        let (cs, _dir) = temp_cli_store(Some(enc_key));
        let ks = cs.keyspace(KS_SECRETS).expect("keyspace");
        assert!(
            ks.is_encrypted(),
            "handle must be encrypted when enc_key is Some"
        );
        ks.insert_raw("row", b"sensitive".to_vec()).await.unwrap();
        let on_disk = cs
            .store
            .keyspace(KS_SECRETS)
            .unwrap()
            .get_raw("row")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(on_disk, b"sensitive", "value must be encrypted on disk");
        assert!(on_disk.starts_with(b"VAE1"), "must carry VAE1 magic");
    }

    /// Same key round-trips across two `CliStore` instances.
    #[tokio::test]
    async fn cli_store_round_trips_with_same_key() {
        let enc_key = [0x77u8; 32];
        let dir = tempfile::tempdir().expect("tempdir");
        let config = vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };

        {
            let store = crate::store::Store::open(&config).expect("open");
            let cs = CliStore::from_store(store, Some(enc_key));
            cs.keyspace(KS_DATA)
                .unwrap()
                .insert_raw("key", b"secret".to_vec())
                .await
                .unwrap();
            cs.persist().await.unwrap();
        }
        {
            let store = crate::store::Store::open(&config).expect("reopen");
            let cs = CliStore::from_store(store, Some(enc_key));
            let val = cs
                .keyspace(KS_DATA)
                .unwrap()
                .get_raw("key")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(val, b"secret");
        }
    }

    /// A different key fails to decrypt rows written by another key.
    #[tokio::test]
    async fn cli_store_wrong_key_fails_to_decrypt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };

        {
            let store = crate::store::Store::open(&config).expect("open");
            let cs = CliStore::from_store(store, Some([0x11u8; 32]));
            cs.keyspace(KS_DATA)
                .unwrap()
                .insert_raw("row", b"secret".to_vec())
                .await
                .unwrap();
            cs.persist().await.unwrap();
        }
        {
            let store = crate::store::Store::open(&config).expect("reopen");
            let cs = CliStore::from_store(store, Some([0x22u8; 32]));
            let result = cs.keyspace(KS_DATA).unwrap().get_raw("row").await;
            assert!(result.is_err(), "wrong key must fail AAD authentication");
        }
    }

    /// `enc_key()` returns the key passed to `from_store`.
    #[test]
    fn cli_store_enc_key_accessor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = crate::store::Store::open(&config).expect("open");

        let cs_none = CliStore::from_store(store.clone(), None);
        assert!(cs_none.enc_key().is_none());

        let key = [0x55u8; 32];
        let cs_some = CliStore::from_store(store, Some(key));
        assert_eq!(cs_some.enc_key(), Some(key));
    }

    /// `Deref` to `Store` — `cs.persist()` works without going through `.store`.
    #[tokio::test]
    async fn cli_store_deref_persist() {
        let (cs, _dir) = temp_cli_store(None);
        cs.persist().await.expect("persist via Deref must work");
    }
}
