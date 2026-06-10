use std::collections::HashMap;
use std::time::Duration;

use crate::config::StoreConfig;
use crate::error::AppError;
use fjall::{KeyspaceCreateOptions, PersistMode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::info;

pub mod counter;

#[cfg(feature = "encryption")]
pub(crate) mod encryption;

#[cfg(feature = "vsock-store")]
pub mod vsock;

/// Timeout for blocking fjall operations. Prevents indefinite hangs if the
/// store deadlocks or I/O stalls.
const STORE_OP_TIMEOUT: Duration = Duration::from_secs(30);

/// Run a blocking operation with timeout.
async fn blocking_with_timeout<F, T>(f: F) -> Result<T, AppError>
where
    F: FnOnce() -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::time::timeout(STORE_OP_TIMEOUT, tokio::task::spawn_blocking(f)).await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => Err(AppError::Internal(format!("blocking task panicked: {e}"))),
        Err(_) => Err(AppError::Internal(format!(
            "store operation timed out after {}s",
            STORE_OP_TIMEOUT.as_secs()
        ))),
    }
}

/// A key-value pair of raw bytes from a prefix scan.
pub type RawKvPair = (Vec<u8>, Vec<u8>);

// ===========================================================================
// Store — dispatches to local (fjall) or vsock backend
// ===========================================================================

/// Persistent key-value store.
///
/// Wraps either a local fjall database or a vsock-proxied store on the parent
/// EC2 instance. All consumers use this type uniformly.
#[derive(Clone)]
pub enum Store {
    /// Local fjall database (standard mode).
    Local(LocalStore),
    /// Vsock-proxied store on the parent (Nitro Enclave mode).
    #[cfg(feature = "vsock-store")]
    Vsock(vsock::VsockStore),
}

impl Store {
    /// Open a local fjall-backed store.
    pub fn open(config: &StoreConfig) -> Result<Self, AppError> {
        Ok(Store::Local(LocalStore::open(config)?))
    }

    /// Connect to the parent's vsock storage proxy.
    #[cfg(feature = "vsock-store")]
    pub async fn connect_vsock(port: Option<u32>) -> Result<Self, AppError> {
        Ok(Store::Vsock(vsock::VsockStore::connect(port).await?))
    }

    pub fn keyspace(&self, name: &str) -> Result<KeyspaceHandle, AppError> {
        match self {
            Store::Local(s) => Ok(KeyspaceHandle::Local(s.keyspace(name)?)),
            #[cfg(feature = "vsock-store")]
            Store::Vsock(s) => Ok(KeyspaceHandle::Vsock(s.keyspace(name)?)),
        }
    }

    pub async fn persist(&self) -> Result<(), AppError> {
        match self {
            Store::Local(s) => s.persist().await,
            #[cfg(feature = "vsock-store")]
            Store::Vsock(s) => s.persist().await,
        }
    }
}

// ===========================================================================
// KeyspaceHandle — dispatches to local (fjall) or vsock backend
// ===========================================================================

/// Handle to a keyspace with optional transparent encryption.
///
/// Wraps either a local fjall keyspace or a vsock-proxied keyspace.
/// Encryption is always applied locally (before data leaves the enclave).
#[derive(Clone)]
pub enum KeyspaceHandle {
    Local(LocalKeyspaceHandle),
    #[cfg(feature = "vsock-store")]
    Vsock(vsock::VsockKeyspaceHandle),
}

impl KeyspaceHandle {
    #[cfg(feature = "encryption")]
    pub fn with_encryption(self, key: [u8; 32]) -> Self {
        match self {
            KeyspaceHandle::Local(h) => KeyspaceHandle::Local(h.with_encryption(key)),
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => KeyspaceHandle::Vsock(h.with_encryption(key)),
        }
    }

    pub fn is_encrypted(&self) -> bool {
        match self {
            KeyspaceHandle::Local(h) => h.is_encrypted(),
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.is_encrypted(),
        }
    }

    /// Durably flush the store to disk (a write barrier).
    ///
    /// Persistence is store-wide, not per-keyspace: the local backend
    /// fsyncs the shared fjall journal, the vsock backend asks the
    /// parent proxy to flush. Call after security-critical writes whose
    /// loss on crash would violate an invariant (carve-out close,
    /// counter allocation) — once this returns, the writes survive
    /// power loss.
    pub async fn persist(&self) -> Result<(), AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.persist().await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.persist().await,
        }
    }

    pub async fn insert<V: Serialize>(
        &self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<(), AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.insert(key, value).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.insert(key, value).await,
        }
    }

    /// Insert `value` at `key` only if `key` is currently absent.
    /// Returns `true` when the insert happened, `false` when the key
    /// already existed (the stored value is left untouched).
    ///
    /// On the [`KeyspaceHandle::Local`] variant the check and insert
    /// run inside one blocking closure, so exactly one of two racing
    /// callers observes `true`. On the [`KeyspaceHandle::Vsock`]
    /// variant the vsock RPC does not yet carry a native
    /// insert-if-absent opcode; the fallback is `get_raw` + `insert`,
    /// which has a TOCTOU window across two vsock round-trips — the
    /// same documented gap as [`KeyspaceHandle::take_raw`] (TEE
    /// enclaves are single-replica, so the window is per-connection
    /// rather than cross-replica).
    pub async fn insert_if_absent<V: Serialize>(
        &self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<bool, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.insert_if_absent(key, value).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => {
                tracing::warn!(
                    "KeyspaceHandle::Vsock::insert_if_absent using non-atomic get+insert \
                     fallback; vsock proto lacks a native insert-if-absent opcode. \
                     Single-replica TEE deployments are unaffected in practice."
                );
                let key = key.into();
                if h.get_raw(key.clone()).await?.is_some() {
                    return Ok(false);
                }
                h.insert(key, value).await?;
                Ok(true)
            }
        }
    }

    /// Raw-bytes variant of [`KeyspaceHandle::insert_if_absent`] — same
    /// semantics and the same vsock TOCTOU caveat, for values that are
    /// stored via `insert_raw`/`get_raw` rather than as serde JSON.
    pub async fn insert_raw_if_absent(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<bool, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.insert_raw_if_absent(key, value).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => {
                tracing::warn!(
                    "KeyspaceHandle::Vsock::insert_raw_if_absent using non-atomic get+insert \
                     fallback; vsock proto lacks a native insert-if-absent opcode. \
                     Single-replica TEE deployments are unaffected in practice."
                );
                let key = key.into();
                if h.get_raw(key.clone()).await?.is_some() {
                    return Ok(false);
                }
                h.insert_raw(key, value).await?;
                Ok(true)
            }
        }
    }

    pub async fn get<V: DeserializeOwned + Send + 'static>(
        &self,
        key: impl Into<Vec<u8>>,
    ) -> Result<Option<V>, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.get(key).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.get(key).await,
        }
    }

    pub async fn remove(&self, key: impl Into<Vec<u8>>) -> Result<(), AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.remove(key).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.remove(key).await,
        }
    }

    /// Atomic `GET` + `DELETE` — see
    /// [`LocalKeyspaceHandle::take_raw`].
    ///
    /// On the [`KeyspaceHandle::Vsock`] variant the vsock RPC does
    /// not yet carry a native `take` opcode. The fallback is
    /// `get_raw` + `remove`, which has a TOCTOU window across two
    /// vsock round-trips — two concurrent presenters could both
    /// observe `Some`. The canonical refresh-token claim treats
    /// this as a documented gap (TEE enclaves are single-replica,
    /// so the window is per-connection rather than cross-replica)
    /// and emits a `warn!` on every call so it stays visible
    /// until the vsock proto gains a `take` opcode.
    pub async fn take_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        let key = key.into();
        match self {
            KeyspaceHandle::Local(h) => h.take_raw(key).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => {
                tracing::warn!(
                    "KeyspaceHandle::Vsock::take_raw using non-atomic get+remove fallback; \
                     vsock proto lacks a native take opcode. Single-replica TEE deployments \
                     are unaffected in practice."
                );
                let val = h.get_raw(key.clone()).await?;
                if val.is_some() {
                    h.remove(key).await?;
                }
                Ok(val)
            }
        }
    }

    pub async fn insert_raw(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<(), AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.insert_raw(key, value).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.insert_raw(key, value).await,
        }
    }

    pub async fn get_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.get_raw(key).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.get_raw(key).await,
        }
    }

    pub async fn prefix_iter_raw(
        &self,
        prefix: impl Into<Vec<u8>>,
    ) -> Result<Vec<RawKvPair>, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.prefix_iter_raw(prefix).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.prefix_iter_raw(prefix).await,
        }
    }

    pub async fn prefix_keys(&self, prefix: impl Into<Vec<u8>>) -> Result<Vec<Vec<u8>>, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.prefix_keys(prefix).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.prefix_keys(prefix).await,
        }
    }

    pub async fn approximate_len(&self) -> Result<usize, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.approximate_len().await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.approximate_len().await,
        }
    }

    pub async fn swap<V: Serialize>(
        &self,
        old_key: impl Into<Vec<u8>>,
        new_key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<bool, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.swap(old_key, new_key, value).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.swap(old_key, new_key, value).await,
        }
    }
}

// ===========================================================================
// LocalStore — fjall-backed implementation (original code)
// ===========================================================================

/// Per-keyspace write locks shared by every handle the store hands out.
///
/// fjall serialises *individual* operations, not sequences of them: two
/// check-then-write closures running on separate `spawn_blocking`
/// threads interleave freely. The multi-op methods that promise
/// atomicity ([`LocalKeyspaceHandle::take_raw`],
/// [`LocalKeyspaceHandle::swap`],
/// [`LocalKeyspaceHandle::insert_if_absent`]) therefore serialise
/// through this lock. It is keyed by keyspace *name* and owned by the
/// store, so handles obtained from separate `keyspace(name)` calls
/// still exclude each other.
type WriteLocks =
    std::sync::Arc<std::sync::Mutex<HashMap<String, std::sync::Arc<std::sync::Mutex<()>>>>>;

#[derive(Clone)]
pub struct LocalStore {
    db: fjall::Database,
    write_locks: WriteLocks,
}

#[derive(Clone)]
pub struct LocalKeyspaceHandle {
    keyspace: fjall::Keyspace,
    /// The owning database, kept so the handle can fsync the shared
    /// journal ([`LocalKeyspaceHandle::persist`]) — fjall only exposes
    /// persistence at the database level.
    db: fjall::Database,
    /// Shared with every other handle for the same keyspace name — see
    /// [`WriteLocks`].
    write_lock: std::sync::Arc<std::sync::Mutex<()>>,
    #[cfg(feature = "encryption")]
    encryption_key: Option<std::sync::Arc<zeroize::Zeroizing<[u8; 32]>>>,
}

/// Acquire a write lock inside a blocking closure, recovering from
/// poisoning: the lock only guards check-then-write sequencing, and
/// every critical section re-reads store state, so a panicked holder
/// leaves nothing logically inconsistent to inherit.
fn lock_writes(lock: &std::sync::Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
    lock.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl LocalStore {
    pub fn open(config: &StoreConfig) -> Result<Self, AppError> {
        std::fs::create_dir_all(&config.data_dir).map_err(AppError::Io)?;
        info!(path = %config.data_dir.display(), "opening store");
        let db = fjall::Database::builder(&config.data_dir).open()?;
        Ok(Self {
            db,
            write_locks: WriteLocks::default(),
        })
    }

    pub fn keyspace(&self, name: &str) -> Result<LocalKeyspaceHandle, AppError> {
        let keyspace = self.db.keyspace(name, KeyspaceCreateOptions::default)?;
        let write_lock = self
            .write_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(name.to_string())
            .or_default()
            .clone();
        Ok(LocalKeyspaceHandle {
            keyspace,
            db: self.db.clone(),
            write_lock,
            #[cfg(feature = "encryption")]
            encryption_key: None,
        })
    }

    pub async fn persist(&self) -> Result<(), AppError> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || db.persist(PersistMode::SyncAll))
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))??;
        Ok(())
    }
}

impl LocalKeyspaceHandle {
    #[cfg(feature = "encryption")]
    pub fn with_encryption(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(std::sync::Arc::new(zeroize::Zeroizing::new(key)));
        self
    }

    pub fn is_encrypted(&self) -> bool {
        #[cfg(feature = "encryption")]
        {
            self.encryption_key.is_some()
        }
        #[cfg(not(feature = "encryption"))]
        {
            false
        }
    }

    /// Fsync the owning database's journal — see
    /// [`KeyspaceHandle::persist`].
    pub async fn persist(&self) -> Result<(), AppError> {
        let db = self.db.clone();
        blocking_with_timeout(move || Ok(db.persist(PersistMode::SyncAll)?)).await
    }

    pub async fn insert<V: Serialize>(
        &self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<(), AppError> {
        let key = key.into();
        let bytes = serde_json::to_vec(value)?;
        let bytes = self.maybe_encrypt(bytes)?;
        let ks = self.keyspace.clone();
        blocking_with_timeout(move || Ok(ks.insert(key, bytes)?)).await
    }

    pub async fn get<V: DeserializeOwned + Send + 'static>(
        &self,
        key: impl Into<Vec<u8>>,
    ) -> Result<Option<V>, AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        #[cfg(feature = "encryption")]
        let enc_key = self.encryption_key.clone();
        blocking_with_timeout(move || match ks.get(key)? {
            Some(bytes) => {
                #[cfg(feature = "encryption")]
                let bytes = {
                    let k = enc_key.as_ref().map(|arc| &***arc);
                    encryption::maybe_decrypt_bytes(k, &bytes)?
                };
                #[cfg(not(feature = "encryption"))]
                let bytes = bytes.to_vec();
                Ok(Some(serde_json::from_slice(&bytes)?))
            }
            None => Ok(None),
        })
        .await
    }

    pub async fn remove(&self, key: impl Into<Vec<u8>>) -> Result<(), AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        blocking_with_timeout(move || Ok(ks.remove(key)?)).await
    }

    /// Atomically `GET` + `DELETE` (the classic Redis `GETDEL`).
    ///
    /// The `get` and `remove` run under the per-keyspace write lock
    /// (see [`WriteLocks`]) so they are atomic with respect to any
    /// other `take_raw`/`swap`/`insert_if_absent` racing on the same
    /// keyspace — exactly one caller observes `Some`. (fjall alone
    /// does NOT provide this: it serialises individual operations,
    /// not check-then-write sequences across blocking threads.)
    ///
    /// Used by the canonical refresh-token claim
    /// ([`crate::auth::session::take_session_id_by_refresh`]) to
    /// close the rotation TOCTOU: a leaked refresh token can be
    /// presented exactly once even under concurrent retries.
    pub async fn take_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        let lock = self.write_lock.clone();
        #[cfg(feature = "encryption")]
        let enc_key = self.encryption_key.clone();
        blocking_with_timeout(move || {
            let _guard = lock_writes(&lock);
            match ks.get(&key)? {
                Some(bytes) => {
                    ks.remove(&key)?;
                    #[cfg(feature = "encryption")]
                    let bytes = {
                        let k = enc_key.as_ref().map(|arc| &***arc);
                        encryption::maybe_decrypt_bytes(k, &bytes)?
                    };
                    #[cfg(not(feature = "encryption"))]
                    let bytes = bytes.to_vec();
                    Ok(Some(bytes))
                }
                None => Ok(None),
            }
        })
        .await
    }

    pub async fn insert_raw(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<(), AppError> {
        let key = key.into();
        let value = self.maybe_encrypt(value.into())?;
        let ks = self.keyspace.clone();
        blocking_with_timeout(move || Ok(ks.insert(key, value)?)).await
    }

    pub async fn get_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        #[cfg(feature = "encryption")]
        let enc_key = self.encryption_key.clone();
        blocking_with_timeout(move || match ks.get(key)? {
            Some(bytes) => {
                #[cfg(feature = "encryption")]
                let bytes = {
                    let k = enc_key.as_ref().map(|arc| &***arc);
                    encryption::maybe_decrypt_bytes(k, &bytes)?
                };
                #[cfg(not(feature = "encryption"))]
                let bytes = bytes.to_vec();
                Ok(Some(bytes))
            }
            None => Ok(None),
        })
        .await
    }

    pub async fn prefix_iter_raw(
        &self,
        prefix: impl Into<Vec<u8>>,
    ) -> Result<Vec<RawKvPair>, AppError> {
        let prefix = prefix.into();
        let ks = self.keyspace.clone();
        #[cfg(feature = "encryption")]
        let enc_key = self.encryption_key.clone();
        blocking_with_timeout(move || {
            let mut results = Vec::new();
            for guard in ks.prefix(&prefix) {
                let (key, value) = guard.into_inner()?;
                #[cfg(feature = "encryption")]
                let value = {
                    let k = enc_key.as_ref().map(|arc| &***arc);
                    encryption::maybe_decrypt_bytes(k, &value)?
                };
                #[cfg(not(feature = "encryption"))]
                let value = value.to_vec();
                results.push((key.to_vec(), value));
            }
            Ok(results)
        })
        .await
    }

    pub async fn prefix_keys(&self, prefix: impl Into<Vec<u8>>) -> Result<Vec<Vec<u8>>, AppError> {
        let prefix = prefix.into();
        let ks = self.keyspace.clone();
        blocking_with_timeout(move || {
            let mut results = Vec::new();
            for guard in ks.prefix(&prefix) {
                let (key, _value) = guard.into_inner()?;
                results.push(key.to_vec());
            }
            Ok(results)
        })
        .await
    }

    pub async fn approximate_len(&self) -> Result<usize, AppError> {
        let ks = self.keyspace.clone();
        blocking_with_timeout(move || Ok(ks.approximate_len())).await
    }

    pub async fn swap<V: Serialize>(
        &self,
        old_key: impl Into<Vec<u8>>,
        new_key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<bool, AppError> {
        let old_key = old_key.into();
        let new_key = new_key.into();
        let bytes = serde_json::to_vec(value)?;
        let bytes = self.maybe_encrypt(bytes)?;
        let ks = self.keyspace.clone();
        let lock = self.write_lock.clone();
        blocking_with_timeout(move || {
            let _guard = lock_writes(&lock);
            if ks.contains_key(&new_key)? {
                return Ok(false);
            }
            ks.insert(&new_key, bytes)?;
            ks.remove(&old_key)?;
            Ok(true)
        })
        .await
    }

    /// Insert only if `key` is absent. The check and insert run under
    /// the per-keyspace write lock (see [`WriteLocks`]), so exactly one
    /// of two racing callers observes `true`.
    pub async fn insert_if_absent<V: Serialize>(
        &self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<bool, AppError> {
        let key = key.into();
        let bytes = serde_json::to_vec(value)?;
        self.insert_bytes_if_absent(key, bytes).await
    }

    /// Raw-bytes variant of [`LocalKeyspaceHandle::insert_if_absent`] —
    /// same lock, same exactly-one-winner guarantee.
    pub async fn insert_raw_if_absent(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<bool, AppError> {
        self.insert_bytes_if_absent(key.into(), value.into()).await
    }

    /// Shared body: check and insert run under the per-keyspace write
    /// lock (see [`WriteLocks`]), so exactly one of two racing callers
    /// observes `true`.
    async fn insert_bytes_if_absent(&self, key: Vec<u8>, bytes: Vec<u8>) -> Result<bool, AppError> {
        let bytes = self.maybe_encrypt(bytes)?;
        let ks = self.keyspace.clone();
        let lock = self.write_lock.clone();
        blocking_with_timeout(move || {
            let _guard = lock_writes(&lock);
            if ks.contains_key(&key)? {
                return Ok(false);
            }
            ks.insert(&key, bytes)?;
            Ok(true)
        })
        .await
    }

    fn maybe_encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, AppError> {
        #[cfg(feature = "encryption")]
        {
            match self.encryption_key.as_ref().map(|arc| &***arc) {
                Some(key) => encryption::encrypt_value(key, &plaintext),
                None => Ok(plaintext),
            }
        }
        #[cfg(not(feature = "encryption"))]
        {
            Ok(plaintext)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&config).expect("failed to open store");
        (store, dir)
    }

    #[tokio::test]
    async fn persist_survives_store_reopen() {
        // persist() is the durability barrier mint_mode_b relies on
        // before returning the admin bundle. Prove a persisted write
        // survives dropping and reopening the store from the same dir
        // (the closest a unit test gets to a power-loss boundary).
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().to_path_buf();
        {
            let store = Store::open(&StoreConfig {
                data_dir: path.clone(),
            })
            .expect("open store");
            let ks = store.keyspace("keys").unwrap();
            ks.insert_raw("carveout:closed", b"admin-did".to_vec())
                .await
                .unwrap();
            ks.persist().await.unwrap();
            // store dropped here without an explicit graceful shutdown
        }
        let store = Store::open(&StoreConfig { data_dir: path }).expect("reopen store");
        let ks = store.keyspace("keys").unwrap();
        assert_eq!(
            ks.get_raw("carveout:closed").await.unwrap().as_deref(),
            Some(b"admin-did".as_slice()),
            "a persisted write must survive a store reopen"
        );
    }

    #[tokio::test]
    async fn insert_if_absent_claims_only_once() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();

        assert!(
            ks.insert_if_absent("k", &"first".to_string())
                .await
                .unwrap(),
            "first claim must succeed"
        );
        assert!(
            !ks.insert_if_absent("k", &"second".to_string())
                .await
                .unwrap(),
            "second claim must be refused"
        );
        let got: String = ks.get("k").await.unwrap().unwrap();
        assert_eq!(got, "first", "loser must not overwrite the stored value");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn insert_if_absent_under_concurrency_admits_exactly_one() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();

        let mut handles = Vec::new();
        for i in 0..16u32 {
            let ks = ks.clone();
            handles.push(tokio::spawn(async move {
                ks.insert_if_absent("contested", &format!("writer-{i}"))
                    .await
                    .unwrap()
            }));
        }
        let mut winners = 0;
        for h in handles {
            if h.await.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "exactly one racing claim may win");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn take_raw_under_concurrency_admits_exactly_one() {
        // Pins the refresh-token single-use guarantee: N concurrent
        // take_raw calls on one key — exactly one observes Some.
        // Handles are obtained via separate keyspace() calls to prove
        // the write lock is shared per keyspace name, not per handle.
        let (store, _dir) = temp_store();
        store
            .keyspace("test")
            .unwrap()
            .insert("token", &"refresh".to_string())
            .await
            .unwrap();

        let mut handles = Vec::new();
        for _ in 0..16 {
            let ks = store.keyspace("test").unwrap();
            handles.push(tokio::spawn(
                async move { ks.take_raw("token").await.unwrap() },
            ));
        }
        let mut claimed = 0;
        for h in handles {
            if h.await.unwrap().is_some() {
                claimed += 1;
            }
        }
        assert_eq!(claimed, 1, "exactly one concurrent take_raw may claim");
    }

    #[tokio::test]
    async fn test_basic_roundtrip() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();

        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct TestRecord {
            id: String,
            value: u64,
        }

        let record = TestRecord {
            id: "test-1".into(),
            value: 42,
        };

        ks.insert("key:test-1", &record).await.unwrap();
        let got: TestRecord = ks.get("key:test-1").await.unwrap().unwrap();
        assert_eq!(got, record);
    }

    #[tokio::test]
    async fn test_prefix_iter() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();

        for i in 0..5 {
            ks.insert_raw(format!("prefix:{i}"), format!("value-{i}").into_bytes())
                .await
                .unwrap();
        }

        let raw = ks.prefix_iter_raw("prefix:").await.unwrap();
        assert_eq!(raw.len(), 5);
    }

    #[tokio::test]
    async fn test_remove() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();

        ks.insert_raw("key", b"value".to_vec()).await.unwrap();
        assert!(ks.get_raw("key").await.unwrap().is_some());

        ks.remove("key").await.unwrap();
        assert!(ks.get_raw("key").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_swap() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();

        ks.insert("old", &"value").await.unwrap();
        let swapped = ks.swap("old", "new", &"value").await.unwrap();
        assert!(swapped);
        assert!(ks.get::<String>("old").await.unwrap().is_none());
        assert!(ks.get::<String>("new").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_passthrough_mode_no_encryption() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("plain").unwrap();
        assert!(!ks.is_encrypted());

        ks.insert_raw("test", b"visible".to_vec()).await.unwrap();
        let raw = ks.get_raw("test").await.unwrap().unwrap();
        assert_eq!(raw, b"visible");
    }

    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn test_encrypted_roundtrip() {
        let (store, _dir) = temp_store();
        let ks = store
            .keyspace("encrypted")
            .unwrap()
            .with_encryption([0xAB; 32]);

        assert!(ks.is_encrypted());

        // Raw bytes roundtrip
        ks.insert_raw("raw:test", b"hello world".to_vec())
            .await
            .unwrap();
        let raw = ks.get_raw("raw:test").await.unwrap().unwrap();
        assert_eq!(raw, b"hello world");

        // JSON roundtrip
        ks.insert("json:test", &"encrypted value").await.unwrap();
        let got: String = ks.get("json:test").await.unwrap().unwrap();
        assert_eq!(got, "encrypted value");
    }

    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn test_encrypted_data_is_actually_encrypted_on_disk() {
        let (store, _dir) = temp_store();
        let enc_key = [0x42; 32];

        // Write with encryption
        let ks_enc = store.keyspace("secrets").unwrap().with_encryption(enc_key);
        ks_enc
            .insert_raw("test", b"plaintext secret".to_vec())
            .await
            .unwrap();

        // Read the same keyspace WITHOUT encryption — should get raw ciphertext
        let ks_raw = store.keyspace("secrets").unwrap();
        let on_disk = ks_raw.get_raw("test").await.unwrap().unwrap();

        // The on-disk value should NOT be the plaintext
        assert_ne!(on_disk, b"plaintext secret");
        // It should be nonce (12) + ciphertext + tag (16) = at least 28 + plaintext len
        assert!(on_disk.len() >= 12 + 16 + 16);

        // But reading with the correct encryption key should work
        let decrypted = ks_enc.get_raw("test").await.unwrap().unwrap();
        assert_eq!(decrypted, b"plaintext secret");
    }
}
