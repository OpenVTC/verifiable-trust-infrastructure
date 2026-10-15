use std::collections::HashMap;
use std::time::Duration;

use crate::config::{FjallTuning, StoreConfig};
use crate::error::AppError;
use fjall::{KeyspaceCreateOptions, PersistMode, Readable};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::info;

pub mod counter;

#[cfg(feature = "encryption")]
pub(crate) mod encryption;

pub(crate) mod generation;
#[cfg(any(feature = "vsock-store", test))]
mod key_locks;
#[cfg(feature = "vsock-store")]
pub mod vsock;
#[cfg(any(feature = "vsock-store", test))]
mod vsock_pool;

#[cfg(any(test, feature = "test-support"))]
pub mod test_fixture;

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

/// fjall's on-disk "this directory is a database root" marker
/// (`fjall::file::VERSION_MARKER`, which the crate does not re-export).
const FJALL_VERSION_MARKER: &str = "version";

/// Does `data_dir` already hold a local (fjall) database?
///
/// Probes for fjall's own version marker — the same file
/// [`fjall::Database`] consults to decide "recover" versus "create new" —
/// so this cannot drift from what actually opening the store would do.
///
/// Deliberately **not** `data_dir.exists()`. A Docker bind mount, a
/// Kubernetes PVC, and an operator's `mkdir` all produce an
/// existing-but-storeless directory, which is a perfectly good target for
/// a fresh store. Only the marker means "there is state here".
pub fn local_store_exists(data_dir: &std::path::Path) -> bool {
    data_dir.join(FJALL_VERSION_MARKER).is_file()
}

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
    /// Open a local fjall-backed store, with fjall's own memory tuning
    /// (block cache / write buffer / journal size — see [`FjallTuning`])
    /// left at its defaults. Every pre-existing call site uses this.
    pub fn open(config: &StoreConfig) -> Result<Self, AppError> {
        Self::open_with(config, &FjallTuning::default())
    }

    /// [`Self::open`], applying `tuning`'s fjall memory settings. Only the
    /// VTA's and VTC's real startup paths build a non-default
    /// [`FjallTuning`] (their loaded config file, then an env var
    /// override) and call this directly — everywhere else keeps calling
    /// [`Self::open`], which is this with [`FjallTuning::default()`] (every
    /// field unset), so nothing that already opened a store needed to
    /// change.
    pub fn open_with(config: &StoreConfig, tuning: &FjallTuning) -> Result<Self, AppError> {
        Ok(Store::Local(LocalStore::open_with(config, tuning)?))
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

    /// A cache ticket for this keyspace: `Some(generation)` while no write
    /// through any handle for this keyspace is in flight or has an unknown
    /// outcome, `None` otherwise ("read through, cache nothing").
    ///
    /// The protocol for caching a value derived from this keyspace: take a
    /// ticket *before* reading; serve a cached value only if it was cached
    /// under the current ticket; cache a fresh read only if the ticket taken
    /// before it is still the current one ([`Self::ticket_is_current`]). The
    /// `store::generation` module docs give the argument, including why a
    /// write the parent applies after its future was cancelled cannot leave
    /// a stale value cached. State is process-local only.
    pub fn cache_ticket(&self) -> Option<u64> {
        self.writes().ticket()
    }

    /// Whether `ticket` is still current: nothing has been written, begun,
    /// or abandoned in this keyspace since it was taken.
    pub fn ticket_is_current(&self, ticket: u64) -> bool {
        self.writes().ticket() == Some(ticket)
    }

    fn writes(&self) -> &generation::KeyspaceWrites {
        match self {
            KeyspaceHandle::Local(h) => &h.writes,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.writes(),
        }
    }

    /// Test-only: hold a local write open, as a running write would.
    #[cfg(test)]
    pub(crate) fn begin_local_write_for_test(&self) -> generation::WriteGuard {
        match self {
            KeyspaceHandle::Local(h) => h.writes.begin().known_on_drop(),
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(_) => unimplemented!("local-store tests only"),
        }
    }

    /// Test-only: delete `key` *without* recording a write — the one way to
    /// change a row behind a cache's back, used to prove a cache hit reads
    /// nothing. Never compiled into a build.
    #[cfg(test)]
    pub(crate) async fn remove_untracked(&self, key: impl Into<Vec<u8>>) -> Result<(), AppError> {
        match self {
            KeyspaceHandle::Local(h) => {
                let key = key.into();
                let ks = h.keyspace.clone();
                blocking_with_timeout(move || Ok(ks.remove(key)?)).await
            }
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(_) => unimplemented!("local-store tests only"),
        }
    }

    /// Re-encrypt every legacy plaintext row in this keyspace under `key`,
    /// in place, so a store first written before encryption-at-rest was
    /// enabled can be read by an encrypted handle.
    ///
    /// Must be called on a **bare** handle (no encryption configured): it
    /// reads raw bytes *without* decrypting, then writes each plaintext
    /// row back through an encrypted handle. Returns the number of rows
    /// newly encrypted.
    ///
    /// **Idempotent and crash-safe.** Rows already in the v1 encrypted
    /// format ([`encryption::is_v1_encrypted`]) are skipped, so an
    /// interrupted run leaves a mix of encrypted + plaintext rows that a
    /// re-run completes. The format magic (`VAE1`) is what distinguishes
    /// the two; no value this is used for (serde-JSON state, raw key
    /// bytes) begins with those four bytes, so detection is unambiguous.
    ///
    /// This deliberately does **not** add a lenient read-fallback to the
    /// decrypt path — that would reintroduce the cut-and-paste downgrade
    /// hole [`encryption`] documents. The store stays strictly
    /// fail-closed; migration is a one-shot forward conversion.
    #[cfg(feature = "encryption")]
    pub async fn migrate_to_encrypted(&self, key: [u8; 32]) -> Result<usize, AppError> {
        if self.is_encrypted() {
            return Err(AppError::Internal(
                "migrate_to_encrypted must be called on a bare (unencrypted) keyspace handle"
                    .into(),
            ));
        }
        // Bare read: returns raw on-disk bytes with no decryption, so
        // both legacy plaintext rows and any already-encrypted rows from
        // a prior partial run come back verbatim.
        let rows = self.prefix_iter_raw(Vec::<u8>::new()).await?;
        let encrypted = self.clone().with_encryption(key);
        let mut migrated = 0usize;
        for (k, v) in rows {
            if encryption::is_v1_encrypted(&v) {
                continue;
            }
            // insert_raw on the encrypted handle re-encrypts the value
            // bound to its (keyspace, key) AAD location.
            encrypted.insert_raw(k, v).await?;
            migrated += 1;
        }
        Ok(migrated)
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
    /// Atomic on both variants: exactly one of two racing callers observes
    /// `true`. The local store runs the check and insert under its keyspace
    /// write lock; the vsock store holds the key's lock across its two round
    /// trips (see `key_locks`).
    pub async fn insert_if_absent<V: Serialize>(
        &self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<bool, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.insert_if_absent(key, value).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.insert_if_absent(key, value).await,
        }
    }

    /// Raw-bytes variant of [`KeyspaceHandle::insert_if_absent`] — same
    /// semantics, for values that are stored via `insert_raw`/`get_raw`
    /// rather than as serde JSON.
    pub async fn insert_raw_if_absent(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<bool, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.insert_raw_if_absent(key, value).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.insert_raw_if_absent(key, value).await,
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
    /// [`LocalKeyspaceHandle::take_raw`]. Exactly one of two racing callers
    /// receives the value: this is what makes a refresh token single-use
    /// (RFC 9700 §4.14.2). The vsock store holds the key's lock across the
    /// read and the delete (see `key_locks`).
    pub async fn take_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.take_raw(key).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.take_raw(key).await,
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

    /// Iterate key/value pairs whose key is `>= from` (inclusive lower
    /// bound, unbounded above), in ascending key order. Unlike
    /// [`Self::prefix_iter_raw`] this **seeks** to `from` rather than
    /// scanning from the start of the keyspace — used by the registry
    /// syncer's audit-tail walk to skip already-processed history
    /// (audit keys are `<rfc3339-ts>:<event_id>`, which sort
    /// chronologically), so per-tick cost is proportional to new rows
    /// rather than the whole audit log.
    pub async fn range_from_raw(
        &self,
        from: impl Into<Vec<u8>>,
    ) -> Result<Vec<RawKvPair>, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.range_from_raw(from).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.range_from_raw(from).await,
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

    /// Move a row to a new key, only while it still holds exactly `expected`
    /// (its plaintext as read earlier), writing `value` at `new_key`. See
    /// [`LocalKeyspaceHandle::move_if_unchanged`].
    ///
    /// Atomic on both variants; the vsock store holds both keys' locks.
    pub async fn move_if_unchanged<V: Serialize>(
        &self,
        old_key: impl Into<Vec<u8>>,
        expected: Vec<u8>,
        new_key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<MoveOutcome, AppError> {
        match self {
            KeyspaceHandle::Local(h) => {
                h.move_if_unchanged(old_key, expected, new_key, value).await
            }
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => {
                h.move_if_unchanged(old_key, expected, new_key, value).await
            }
        }
    }

    /// Apply `batch`'s writes only if every one of its preconditions holds,
    /// as one operation.
    ///
    /// Atomic with respect to every other multi-step operation on this
    /// keyspace (exactly one of two racing batches requiring the same key
    /// absent is applied) and, on the local store and on a proxy that serves
    /// OP_APPLY_BATCH, with respect to a crash: the writes are one journal
    /// record, so recovery replays all of them or none. A proxy without it
    /// gets the batch as single operations under the enclave's key locks —
    /// still exclusive, but a crash can land between them, as with every
    /// other atomic operation's fallback.
    ///
    /// A refused batch writes nothing. A batch with no writes only checks.
    pub async fn apply_batch(&self, batch: Batch) -> Result<BatchOutcome, AppError> {
        batch.validate()?;
        match self {
            KeyspaceHandle::Local(h) => h.apply_batch(batch).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.apply_batch(batch).await,
        }
    }
}

// ===========================================================================
// Batch — several writes to one keyspace and their preconditions, as one
// ===========================================================================

/// One precondition of a [`Batch`], checked against the keyspace as it is
/// before any of the batch's writes.
#[derive(Clone, Debug)]
pub(crate) enum Check {
    /// No row at the key.
    Absent(Vec<u8>),
    /// A row at the key, whatever it holds.
    Present(Vec<u8>),
    /// A row at the key holding exactly these plaintext bytes.
    Unchanged(Vec<u8>, Vec<u8>),
}

impl Check {
    #[cfg(feature = "vsock-store")]
    pub(crate) fn key(&self) -> &[u8] {
        match self {
            Check::Absent(k) | Check::Present(k) | Check::Unchanged(k, _) => k,
        }
    }
}

/// One write of a [`Batch`]. A `Put` value is plaintext until the batch is
/// applied, when it is encrypted for its own key like any other insert.
#[derive(Clone, Debug)]
pub(crate) enum Write {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

impl Write {
    pub(crate) fn key(&self) -> &[u8] {
        match self {
            Write::Put(k, _) | Write::Delete(k) => k,
        }
    }
}

/// Writes to one keyspace, applied together only if every precondition
/// holds — see [`KeyspaceHandle::apply_batch`].
///
/// Preconditions are checked against the keyspace before any of the writes;
/// a key may be written at most once per batch.
#[derive(Clone, Debug, Default)]
pub struct Batch {
    pub(crate) checks: Vec<Check>,
    pub(crate) writes: Vec<Write>,
}

impl Batch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply only if no row is stored at `key`.
    pub fn require_absent(&mut self, key: impl Into<Vec<u8>>) -> &mut Self {
        self.checks.push(Check::Absent(key.into()));
        self
    }

    /// Apply only if a row is stored at `key`.
    pub fn require_present(&mut self, key: impl Into<Vec<u8>>) -> &mut Self {
        self.checks.push(Check::Present(key.into()));
        self
    }

    /// Apply only if the row at `key` still holds exactly `expected` — its
    /// plaintext as [`KeyspaceHandle::get_raw`] returned it. A missing row
    /// fails this check.
    pub fn require_unchanged(
        &mut self,
        key: impl Into<Vec<u8>>,
        expected: impl Into<Vec<u8>>,
    ) -> &mut Self {
        self.checks
            .push(Check::Unchanged(key.into(), expected.into()));
        self
    }

    /// Store `value` (serde JSON, as [`KeyspaceHandle::insert`]) at `key`.
    pub fn insert<V: Serialize>(
        &mut self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<&mut Self, AppError> {
        self.writes
            .push(Write::Put(key.into(), serde_json::to_vec(value)?));
        Ok(self)
    }

    /// Store raw bytes at `key`, as [`KeyspaceHandle::insert_raw`].
    pub fn insert_raw(&mut self, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> &mut Self {
        self.writes.push(Write::Put(key.into(), value.into()));
        self
    }

    /// Delete the row at `key`, if any.
    pub fn remove(&mut self, key: impl Into<Vec<u8>>) -> &mut Self {
        self.writes.push(Write::Delete(key.into()));
        self
    }

    pub fn is_empty(&self) -> bool {
        self.checks.is_empty() && self.writes.is_empty()
    }

    /// Refuse a batch that writes one key twice. Within one fjall write
    /// batch every item shares a sequence number, so which of two writes to a
    /// key survives would be decided by the memtable, not by the caller.
    pub(crate) fn validate(&self) -> Result<(), AppError> {
        let mut seen = std::collections::HashSet::new();
        for w in &self.writes {
            if !seen.insert(w.key()) {
                return Err(AppError::Internal(
                    "store batch writes the same key twice".into(),
                ));
            }
        }
        Ok(())
    }

    /// Every key the batch checks or writes, for locking.
    #[cfg(feature = "vsock-store")]
    pub(crate) fn keys(&self) -> Vec<&[u8]> {
        self.checks
            .iter()
            .map(Check::key)
            .chain(self.writes.iter().map(Write::key))
            .collect()
    }
}

/// What [`KeyspaceHandle::apply_batch`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchOutcome {
    /// Every precondition held and every write was applied.
    Applied,
    /// The precondition at this index (in the order they were added) did not
    /// hold. Nothing was written.
    Refused { check: usize },
}

impl BatchOutcome {
    pub fn is_applied(self) -> bool {
        self == BatchOutcome::Applied
    }
}

/// What [`KeyspaceHandle::move_if_unchanged`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveOutcome {
    /// The row was moved: `new_key` holds the value and `old_key` is gone.
    Moved,
    /// `old_key` held nothing, so another caller moved or removed it first.
    SourceMissing,
    /// `old_key` held something other than the expected bytes.
    SourceChanged,
    /// `new_key` was already occupied. Nothing was written.
    TargetExists,
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
/// [`LocalKeyspaceHandle::insert_if_absent`],
/// [`LocalKeyspaceHandle::apply_batch`]) therefore serialise through this
/// lock. Plain inserts and removes take it too, so none can land between a
/// multi-step operation's check and its write (see
/// [`LocalKeyspaceHandle::locked_write`]). It is keyed by keyspace *name*
/// and owned by the store, so handles obtained from separate
/// `keyspace(name)` calls still exclude each other.
type WriteLocks =
    std::sync::Arc<std::sync::Mutex<HashMap<String, std::sync::Arc<std::sync::Mutex<()>>>>>;

#[derive(Clone)]
pub struct LocalStore {
    db: fjall::Database,
    write_locks: WriteLocks,
    writes: generation::Generations,
}

#[derive(Clone)]
pub struct LocalKeyspaceHandle {
    keyspace: fjall::Keyspace,
    /// Keyspace name, bound into the AES-GCM associated data so a value
    /// cannot be relocated to another keyspace (which shares the storage
    /// key) and still authenticate. See [`encryption`].
    ///
    /// Gated with the feature it serves, like `encryption_key` below: every
    /// read of it is an AAD construction, so a build without `encryption` has
    /// nothing to read it and the compiler says so (`field is never read`,
    /// which is what `pnm-cli` and every other default-feature consumer sees).
    /// Carrying it regardless would leave a security-relevant field looking
    /// like it might be doing something in builds where it cannot.
    #[cfg(feature = "encryption")]
    name: String,
    /// The owning database, kept so the handle can fsync the shared
    /// journal ([`LocalKeyspaceHandle::persist`]) — fjall only exposes
    /// persistence at the database level.
    db: fjall::Database,
    /// Shared with every other handle for the same keyspace name — see
    /// [`WriteLocks`].
    write_lock: std::sync::Arc<std::sync::Mutex<()>>,
    /// Shared with every other handle for the same keyspace name. Each write
    /// begins one before its blocking closure and ends it inside, after the
    /// write — see [`generation`].
    writes: std::sync::Arc<generation::KeyspaceWrites>,
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

/// A consistent point-in-time view for a read that does not hold the
/// keyspace write lock.
///
/// fjall's plain reads (`Keyspace::get`, `prefix`, `range`) read at the
/// newest sequence number, and a write batch is applied to the memtables one
/// item at a time before its sequence number is published. A lock-free plain
/// read can therefore see part of a batch: both rows of a move, an index
/// entry without its record. A snapshot reads at the last *published*
/// sequence number, so it sees every batch whole or not at all, and every
/// write that has returned. Reads under the write lock need none of this: no
/// batch on that keyspace can be in flight while it is held.
fn read_snapshot(db: &fjall::Database) -> fjall::Snapshot {
    db.snapshot()
}

/// Write `value` at `new` and delete `old` as one fjall write batch.
///
/// One batch is one journal record under one sequence number, so recovery
/// after a crash replays both or neither. As two writes, a crash between
/// them would leave both rows — the moved-from row still live beside its
/// replacement (an old ACL DID keeping its authority, `routes::members::
/// rotate`). The enclave proxy's `move_locked` commits the same way, so the
/// local and vsock backends make the same crash guarantee.
fn commit_move(
    db: &fjall::Database,
    ks: &fjall::Keyspace,
    old: &[u8],
    new: &[u8],
    value: Vec<u8>,
) -> Result<(), AppError> {
    let mut batch = db.batch();
    batch.insert(ks, new, value);
    batch.remove(ks, old);
    batch.commit()?;
    Ok(())
}

impl LocalStore {
    /// [`Store::open`] for the local backend directly — fjall's own
    /// memory tuning left at its defaults.
    pub fn open(config: &StoreConfig) -> Result<Self, AppError> {
        Self::open_with(config, &FjallTuning::default())
    }

    /// [`Store::open_with`] for the local backend directly. See there for
    /// who calls this — everywhere else keeps calling [`Self::open`].
    pub fn open_with(config: &StoreConfig, tuning: &FjallTuning) -> Result<Self, AppError> {
        // Defense in depth: re-checked here regardless of how `tuning` was
        // built (the config-file deserializer and `apply_fjall_env_overrides`
        // both validate already, but a directly-constructed `FjallTuning` —
        // a test fixture, a future caller — must never reach the asserting
        // `Builder` calls below with a value fjall itself would panic on.
        tuning.validate().map_err(AppError::Config)?;

        std::fs::create_dir_all(&config.data_dir).map_err(AppError::Io)?;

        let mut builder = fjall::Database::builder(&config.data_dir);
        if let Some(bytes) = tuning.block_cache {
            builder = builder.cache_size(bytes);
        }
        if let Some(bytes) = tuning.max_journal {
            builder = builder.max_journaling_size(bytes);
        }
        if let Some(bytes) = tuning.write_buffer {
            // `Builder::max_write_buffer_size` is `#[doc(hidden)]` and
            // `#[deprecated = "todo"]` upstream (fjall 3.1) — it is still
            // the only way to cap the total memtable budget across every
            // keyspace a process opens (see `KeyspaceCreateOptions::
            // max_memtable_size`'s own doc, which points back at it), and
            // it remains fully wired (`WriteBufferManager`, checked on
            // every insert/remove). Re-check this note against fjall's
            // changelog when bumping past 3.1 in case a replacement lands.
            #[allow(deprecated)]
            {
                builder = builder.max_write_buffer_size(Some(bytes));
            }
        }

        info!(
            path = %config.data_dir.display(),
            block_cache = %tuning.block_cache.map(crate::config::human_bytes).unwrap_or_else(|| "default".to_string()),
            write_buffer = %tuning.write_buffer.map(crate::config::human_bytes).unwrap_or_else(|| "default".to_string()),
            max_journal = %tuning.max_journal.map(crate::config::human_bytes).unwrap_or_else(|| "default".to_string()),
            "opening store"
        );

        let db = builder.open()?;
        Ok(Self {
            db,
            write_locks: WriteLocks::default(),
            writes: generation::Generations::default(),
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
            #[cfg(feature = "encryption")]
            name: name.to_string(),
            db: self.db.clone(),
            write_lock,
            writes: self.writes.for_keyspace(name),
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
        let bytes = self.maybe_encrypt(&key, bytes)?;
        self.locked_write(move |ks| Ok(ks.insert(key, bytes)?))
            .await
    }

    pub async fn get<V: DeserializeOwned + Send + 'static>(
        &self,
        key: impl Into<Vec<u8>>,
    ) -> Result<Option<V>, AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        #[cfg(feature = "encryption")]
        let enc_key = self.encryption_key.clone();
        #[cfg(feature = "encryption")]
        let name = self.name.clone();
        let db = self.db.clone();
        // A snapshot read, never a half-applied batch — see `read_snapshot`.
        blocking_with_timeout(move || match read_snapshot(&db).get(&ks, &key)? {
            Some(bytes) => {
                #[cfg(feature = "encryption")]
                let bytes = {
                    let k = enc_key.as_ref().map(|arc| &***arc);
                    encryption::maybe_decrypt_bytes(k, &name, &key, &bytes)?
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
        self.locked_write(move |ks| Ok(ks.remove(key)?)).await
    }

    /// A single write under the per-keyspace write lock (see [`WriteLocks`]).
    ///
    /// fjall makes the write itself atomic, so the lock is not for the write:
    /// it orders the write against every multi-step operation on the
    /// keyspace. Without it a plain insert or remove could land between an
    /// [`Self::apply_batch`] precondition check and its commit — a sign-out
    /// slipping in after a `require_unchanged` passed — and the batch would
    /// commit over a row that no longer matched its precondition.
    async fn locked_write<F>(&self, f: F) -> Result<(), AppError>
    where
        F: FnOnce(&fjall::Keyspace) -> Result<(), AppError> + Send + 'static,
    {
        let ks = self.keyspace.clone();
        let lock = self.write_lock.clone();
        let write = self.writes.begin().known_on_drop();
        blocking_with_timeout(move || {
            let _guard = lock_writes(&lock);
            let _write = write;
            f(&ks)
        })
        .await
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
        let write = self.writes.begin().known_on_drop();
        #[cfg(feature = "encryption")]
        let enc_key = self.encryption_key.clone();
        #[cfg(feature = "encryption")]
        let name = self.name.clone();
        blocking_with_timeout(move || {
            let _guard = lock_writes(&lock);
            // Ends the write on every exit path, after anything written here.
            let _write = write;
            match ks.get(&key)? {
                Some(bytes) => {
                    ks.remove(&key)?;
                    #[cfg(feature = "encryption")]
                    let bytes = {
                        let k = enc_key.as_ref().map(|arc| &***arc);
                        encryption::maybe_decrypt_bytes(k, &name, &key, &bytes)?
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
        let value = self.maybe_encrypt(&key, value.into())?;
        self.locked_write(move |ks| Ok(ks.insert(key, value)?))
            .await
    }

    pub async fn get_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        #[cfg(feature = "encryption")]
        let enc_key = self.encryption_key.clone();
        #[cfg(feature = "encryption")]
        let name = self.name.clone();
        let db = self.db.clone();
        // A snapshot read, never a half-applied batch — see `read_snapshot`.
        blocking_with_timeout(move || match read_snapshot(&db).get(&ks, &key)? {
            Some(bytes) => {
                #[cfg(feature = "encryption")]
                let bytes = {
                    let k = enc_key.as_ref().map(|arc| &***arc);
                    encryption::maybe_decrypt_bytes(k, &name, &key, &bytes)?
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
        let db = self.db.clone();
        #[cfg(feature = "encryption")]
        let enc_key = self.encryption_key.clone();
        #[cfg(feature = "encryption")]
        let name = self.name.clone();
        blocking_with_timeout(move || {
            let mut results = Vec::new();
            for guard in read_snapshot(&db).prefix(&ks, &prefix) {
                let (key, value) = guard.into_inner()?;
                #[cfg(feature = "encryption")]
                let value = {
                    let k = enc_key.as_ref().map(|arc| &***arc);
                    encryption::maybe_decrypt_bytes(k, &name, &key, &value)?
                };
                #[cfg(not(feature = "encryption"))]
                let value = value.to_vec();
                results.push((key.to_vec(), value));
            }
            Ok(results)
        })
        .await
    }

    /// See [`KeyspaceHandle::range_from_raw`]. fjall's `range` seeks to
    /// the lower bound, so this reads only keys `>= from`.
    pub async fn range_from_raw(
        &self,
        from: impl Into<Vec<u8>>,
    ) -> Result<Vec<RawKvPair>, AppError> {
        let from = from.into();
        let ks = self.keyspace.clone();
        let db = self.db.clone();
        #[cfg(feature = "encryption")]
        let enc_key = self.encryption_key.clone();
        #[cfg(feature = "encryption")]
        let name = self.name.clone();
        blocking_with_timeout(move || {
            let mut results = Vec::new();
            for guard in read_snapshot(&db).range(&ks, from..) {
                let (key, value) = guard.into_inner()?;
                #[cfg(feature = "encryption")]
                let value = {
                    let k = enc_key.as_ref().map(|arc| &***arc);
                    encryption::maybe_decrypt_bytes(k, &name, &key, &value)?
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
        let db = self.db.clone();
        blocking_with_timeout(move || {
            let mut results = Vec::new();
            for guard in read_snapshot(&db).prefix(&ks, &prefix) {
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
        // The value lands at `new_key`, so bind the AAD to `new_key`.
        let bytes = self.maybe_encrypt(&new_key, bytes)?;
        let db = self.db.clone();
        let ks = self.keyspace.clone();
        let lock = self.write_lock.clone();
        let write = self.writes.begin().known_on_drop();
        blocking_with_timeout(move || {
            let _guard = lock_writes(&lock);
            // Ends the write on every exit path, after anything written here.
            let _write = write;
            if ks.contains_key(&new_key)? {
                return Ok(false);
            }
            commit_move(&db, &ks, &old_key, &new_key, bytes)?;
            Ok(true)
        })
        .await
    }

    /// Compare-and-move under the per-keyspace write lock (see [`WriteLocks`]).
    ///
    /// Moves the row at `old_key` to `new_key`, storing `value` there, only if
    /// `old_key` still holds exactly `expected` (compared as plaintext) and
    /// `new_key` is empty. Exactly one of two racing callers observes
    /// [`MoveOutcome::Moved`]; every other outcome writes nothing.
    pub async fn move_if_unchanged<V: Serialize>(
        &self,
        old_key: impl Into<Vec<u8>>,
        expected: Vec<u8>,
        new_key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<MoveOutcome, AppError> {
        let old_key = old_key.into();
        let new_key = new_key.into();
        let bytes = serde_json::to_vec(value)?;
        let bytes = self.maybe_encrypt(&new_key, bytes)?;
        let db = self.db.clone();
        let ks = self.keyspace.clone();
        let lock = self.write_lock.clone();
        let write = self.writes.begin().known_on_drop();
        #[cfg(feature = "encryption")]
        let enc_key = self.encryption_key.clone();
        #[cfg(feature = "encryption")]
        let name = self.name.clone();
        blocking_with_timeout(move || {
            let _guard = lock_writes(&lock);
            // Ends the write on every exit path, after anything written here.
            let _write = write;
            let Some(current) = ks.get(&old_key)? else {
                return Ok(MoveOutcome::SourceMissing);
            };
            #[cfg(feature = "encryption")]
            let current = {
                let k = enc_key.as_ref().map(|arc| &***arc);
                encryption::maybe_decrypt_bytes(k, &name, &old_key, &current)?
            };
            #[cfg(not(feature = "encryption"))]
            let current = current.to_vec();
            if current != expected {
                return Ok(MoveOutcome::SourceChanged);
            }
            if ks.contains_key(&new_key)? {
                return Ok(MoveOutcome::TargetExists);
            }
            commit_move(&db, &ks, &old_key, &new_key, bytes)?;
            Ok(MoveOutcome::Moved)
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
        let bytes = self.maybe_encrypt(&key, bytes)?;
        let ks = self.keyspace.clone();
        let lock = self.write_lock.clone();
        let write = self.writes.begin().known_on_drop();
        blocking_with_timeout(move || {
            let _guard = lock_writes(&lock);
            // Ends the write on every exit path, after anything written here.
            let _write = write;
            if ks.contains_key(&key)? {
                return Ok(false);
            }
            ks.insert(&key, bytes)?;
            Ok(true)
        })
        .await
    }

    /// See [`KeyspaceHandle::apply_batch`]. The checks and the commit run
    /// under the per-keyspace write lock (see [`WriteLocks`]), and the writes
    /// are one fjall write batch — one journal record.
    pub async fn apply_batch(&self, batch: Batch) -> Result<BatchOutcome, AppError> {
        let Batch { checks, writes } = batch;
        let writes = writes
            .into_iter()
            .map(|w| match w {
                Write::Put(k, v) => {
                    let v = self.maybe_encrypt(&k, v)?;
                    Ok(Write::Put(k, v))
                }
                d => Ok(d),
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        let db = self.db.clone();
        let ks = self.keyspace.clone();
        let lock = self.write_lock.clone();
        let write = self.writes.begin().known_on_drop();
        #[cfg(feature = "encryption")]
        let enc_key = self.encryption_key.clone();
        #[cfg(feature = "encryption")]
        let name = self.name.clone();
        blocking_with_timeout(move || {
            let _guard = lock_writes(&lock);
            // Ends the write on every exit path, after anything written here.
            let _write = write;
            for (i, check) in checks.iter().enumerate() {
                let holds = match check {
                    Check::Absent(k) => !ks.contains_key(k)?,
                    Check::Present(k) => ks.contains_key(k)?,
                    Check::Unchanged(k, expected) => match ks.get(k)? {
                        None => false,
                        Some(stored) => {
                            #[cfg(feature = "encryption")]
                            let current = {
                                let key = enc_key.as_ref().map(|arc| &***arc);
                                encryption::maybe_decrypt_bytes(key, &name, k, &stored)?
                            };
                            #[cfg(not(feature = "encryption"))]
                            let current = stored.to_vec();
                            current == *expected
                        }
                    },
                };
                if !holds {
                    return Ok(BatchOutcome::Refused { check: i });
                }
            }
            if writes.is_empty() {
                return Ok(BatchOutcome::Applied);
            }
            let mut batch = db.batch();
            for w in writes {
                match w {
                    Write::Put(k, v) => batch.insert(&ks, k, v),
                    Write::Delete(k) => batch.remove(&ks, k),
                }
            }
            batch.commit()?;
            Ok(BatchOutcome::Applied)
        })
        .await
    }

    fn maybe_encrypt(&self, store_key: &[u8], plaintext: Vec<u8>) -> Result<Vec<u8>, AppError> {
        #[cfg(feature = "encryption")]
        {
            match self.encryption_key.as_ref().map(|arc| &***arc) {
                Some(key) => encryption::encrypt_value(key, &self.name, store_key, &plaintext),
                None => Ok(plaintext),
            }
        }
        #[cfg(not(feature = "encryption"))]
        {
            let _ = store_key;
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

    #[test]
    fn local_store_exists_ignores_a_bare_directory() {
        // The case that motivated this probe: a Docker volume / PVC /
        // hand-created directory exists before setup ever runs. That is
        // not "there is a store here", and setup must not treat it as a
        // conflict.
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(
            !local_store_exists(dir.path()),
            "an empty directory holds no store"
        );

        std::fs::write(dir.path().join("did.jsonl"), b"{}").expect("write stray file");
        assert!(
            !local_store_exists(dir.path()),
            "a non-empty directory without fjall's marker still holds no store"
        );

        assert!(
            !local_store_exists(&dir.path().join("does-not-exist")),
            "an absent directory holds no store"
        );
    }

    #[test]
    fn local_store_exists_sees_an_opened_store() {
        let (_store, dir) = temp_store();
        assert!(
            local_store_exists(dir.path()),
            "opening a store must make the probe report it"
        );
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

    /// The hand-off's commit (VTI-ACL-056): N concurrent moves of one row to N
    /// different keys — exactly one lands, and the row is gone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn move_if_unchanged_under_concurrency_admits_exactly_one() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();
        ks.insert("src", &"row".to_string()).await.unwrap();
        let expected = ks.get_raw("src").await.unwrap().unwrap();

        let mut handles = Vec::new();
        for n in 0..16 {
            let ks = store.keyspace("test").unwrap();
            let expected = expected.clone();
            handles.push(tokio::spawn(async move {
                ks.move_if_unchanged("src", expected, format!("dst{n}"), &"row".to_string())
                    .await
                    .unwrap()
            }));
        }
        let mut moved = 0;
        for h in handles {
            if h.await.unwrap() == MoveOutcome::Moved {
                moved += 1;
            }
        }
        assert_eq!(moved, 1, "exactly one concurrent move may land");
        assert!(ks.get_raw("src").await.unwrap().is_none());
    }

    /// The local store's journal sequence number — one per journal record.
    fn journal_seqno(store: &Store) -> fjall::SeqNo {
        match store {
            Store::Local(s) => s.db.seqno(),
            #[cfg(feature = "vsock-store")]
            Store::Vsock(_) => unreachable!("local-store tests only"),
        }
    }

    /// A move is one journal record: the insert and the delete share one
    /// sequence number, so crash recovery replays both or neither. Two
    /// separate writes would take two, and a crash between them would leave
    /// both rows live — the old row keeping its authority beside the new one.
    #[tokio::test]
    async fn moves_commit_as_one_journal_record() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();
        ks.insert("a", &"row".to_string()).await.unwrap();

        let before = journal_seqno(&store);
        assert!(ks.swap("a", "b", &"row".to_string()).await.unwrap());
        assert_eq!(journal_seqno(&store) - before, 1, "swap is one record");

        let expected = ks.get_raw("b").await.unwrap().unwrap();
        let before = journal_seqno(&store);
        assert_eq!(
            ks.move_if_unchanged("b", expected, "c", &"row".to_string())
                .await
                .unwrap(),
            MoveOutcome::Moved
        );
        assert_eq!(journal_seqno(&store) - before, 1, "move is one record");
        assert!(ks.get_raw("b").await.unwrap().is_none());
        assert!(ks.get_raw("c").await.unwrap().is_some());

        // A refused move writes nothing at all.
        ks.insert("d", &"taken".to_string()).await.unwrap();
        let before = journal_seqno(&store);
        assert!(!ks.swap("c", "d", &"row".to_string()).await.unwrap());
        assert_eq!(journal_seqno(&store), before, "refusal writes nothing");
    }

    /// An applied batch is one journal record — every write lands under one
    /// sequence number, so recovery replays all of them or none — and a
    /// refused one writes nothing.
    #[tokio::test]
    async fn apply_batch_commits_one_journal_record_or_nothing() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();
        ks.insert("old", &"v1".to_string()).await.unwrap();
        let v1 = ks.get_raw("old").await.unwrap().unwrap();

        let mut b = Batch::new();
        b.require_absent("new").require_unchanged("old", v1.clone());
        b.insert("new", &"v2".to_string()).unwrap();
        b.insert_raw("idx:a", "1")
            .insert_raw("idx:b", "1")
            .remove("old");
        let before = journal_seqno(&store);
        assert_eq!(ks.apply_batch(b).await.unwrap(), BatchOutcome::Applied);
        assert_eq!(journal_seqno(&store) - before, 1, "one journal record");
        assert_eq!(
            ks.get::<String>("new").await.unwrap().as_deref(),
            Some("v2")
        );
        assert!(ks.get_raw("idx:a").await.unwrap().is_some());
        assert!(ks.get_raw("idx:b").await.unwrap().is_some());
        assert!(ks.get_raw("old").await.unwrap().is_none());

        // Refused: the stale `old` comparison. Nothing written.
        let mut b = Batch::new();
        b.require_absent("other").require_unchanged("new", v1);
        b.insert_raw("x", "y");
        let before = journal_seqno(&store);
        assert_eq!(
            ks.apply_batch(b).await.unwrap(),
            BatchOutcome::Refused { check: 1 }
        );
        assert_eq!(journal_seqno(&store), before, "refusal writes nothing");
        assert!(ks.get_raw("x").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn apply_batch_reports_the_first_failing_precondition() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();
        ks.insert("a", &"v".to_string()).await.unwrap();
        let v = ks.get_raw("a").await.unwrap().unwrap();
        let outcome = |b: Batch| {
            let ks = ks.clone();
            async move { ks.apply_batch(b).await.unwrap() }
        };

        let mut b = Batch::new();
        b.require_present("a")
            .require_absent("a")
            .require_present("missing");
        assert_eq!(outcome(b).await, BatchOutcome::Refused { check: 1 });

        let mut b = Batch::new();
        b.require_unchanged("missing", v.clone());
        assert_eq!(outcome(b).await, BatchOutcome::Refused { check: 0 });

        // Preconditions only: checked, nothing written.
        let mut b = Batch::new();
        b.require_present("a").require_unchanged("a", v);
        let before = journal_seqno(&store);
        assert_eq!(outcome(b).await, BatchOutcome::Applied);
        assert_eq!(journal_seqno(&store), before);
    }

    #[tokio::test]
    async fn apply_batch_refuses_a_key_written_twice() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();
        let mut b = Batch::new();
        b.insert_raw("k", "1").remove("k");
        assert!(ks.apply_batch(b).await.is_err());
        assert!(ks.get_raw("k").await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn apply_batch_under_concurrency_admits_exactly_one() {
        let (store, _dir) = temp_store();
        let mut handles = Vec::new();
        for n in 0..16 {
            let ks = store.keyspace("test").unwrap();
            handles.push(tokio::spawn(async move {
                let mut b = Batch::new();
                b.require_absent("claim")
                    .insert_raw("claim", format!("{n}"))
                    .insert_raw(format!("by:{n}"), "1");
                ks.apply_batch(b).await.unwrap().is_applied()
            }));
        }
        let mut applied = 0;
        for h in handles {
            if h.await.unwrap() {
                applied += 1;
            }
        }
        assert_eq!(applied, 1, "exactly one batch may claim the key");
        let ks = store.keyspace("test").unwrap();
        assert_eq!(ks.prefix_keys("by:").await.unwrap().len(), 1);
    }

    /// `require_unchanged` compares plaintext, whatever ciphertext a fresh
    /// nonce gave the stored row.
    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn apply_batch_compares_plaintext_on_an_encrypted_keyspace() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap().with_encryption([9u8; 32]);
        ks.insert("a", &"secret".to_string()).await.unwrap();
        let plain = ks.get_raw("a").await.unwrap().unwrap();
        let mut b = Batch::new();
        b.require_unchanged("a", plain);
        b.insert("a", &"secret-2".to_string()).unwrap();
        assert!(ks.apply_batch(b).await.unwrap().is_applied());
        assert_eq!(
            ks.get::<String>("a").await.unwrap().as_deref(),
            Some("secret-2")
        );
    }

    /// A plain write waits for the keyspace write lock, so it cannot land
    /// inside a multi-step operation holding it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plain_writes_wait_for_the_keyspace_write_lock() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();
        let lock = match &ks {
            KeyspaceHandle::Local(h) => h.write_lock.clone(),
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(_) => unreachable!("local store"),
        };
        // Held on its own thread (a std guard must not cross an await) until
        // `release` is sent.
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let _guard = lock_writes(&lock);
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        held_rx.recv().unwrap();

        let writer = ks.clone();
        let insert = tokio::spawn(async move { writer.insert_raw("k", "v").await });
        let remover = ks.clone();
        let remove = tokio::spawn(async move { remover.remove("other").await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!insert.is_finished(), "insert ran under a held write lock");
        assert!(!remove.is_finished(), "remove ran under a held write lock");

        release_tx.send(()).unwrap();
        holder.join().unwrap();
        insert.await.unwrap().unwrap();
        remove.await.unwrap().unwrap();
        assert!(ks.get_raw("k").await.unwrap().is_some());
    }

    /// A conditional rewrite racing a plain remove of the same row: in every
    /// serial order the row ends up gone (removed after the rewrite, or the
    /// rewrite refused because the row it required had been removed). It can
    /// only survive if the remove landed between the rewrite's check and its
    /// commit — a signed-out session written back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_plain_remove_never_lands_inside_a_conditional_batch() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();
        for i in 0..500 {
            ks.insert_raw("row", "v1").await.unwrap();
            let writer = ks.clone();
            let rewrite = tokio::spawn(async move {
                let mut b = Batch::new();
                b.require_unchanged("row", "v1").insert_raw("row", "v2");
                writer.apply_batch(b).await.unwrap()
            });
            let remover = ks.clone();
            let remove = tokio::spawn(async move { remover.remove("row").await.unwrap() });
            rewrite.await.unwrap();
            remove.await.unwrap();
            assert!(
                ks.get_raw("row").await.unwrap().is_none(),
                "iteration {i}: a removed row was written back"
            );
        }
    }

    /// A lock-free read never sees half of a batch. One writer moves a row
    /// between two keys with batches; a reader scanning both keys in one call
    /// while it does must always find exactly one of them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_reader_never_sees_a_batch_half_applied() {
        const MOVES: usize = 2_000;
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();
        ks.insert_raw("mv:a", "row").await.unwrap();

        let writer = {
            let ks = ks.clone();
            tokio::spawn(async move {
                for n in 0..MOVES {
                    let (from, to) = if n % 2 == 0 {
                        ("mv:a", "mv:b")
                    } else {
                        ("mv:b", "mv:a")
                    };
                    let mut b = Batch::new();
                    b.require_present(from).remove(from).insert_raw(to, "row");
                    assert!(ks.apply_batch(b).await.unwrap().is_applied());
                }
            })
        };
        let mut reads = 0usize;
        while !writer.is_finished() {
            let rows = ks.prefix_iter_raw("mv:").await.unwrap();
            assert_eq!(
                rows.len(),
                1,
                "read {reads} saw a half-applied move: {rows:?}"
            );
            reads += 1;
        }
        writer.await.unwrap();
        assert!(reads > 0, "the reader never overlapped the writer");
    }

    #[tokio::test]
    async fn move_if_unchanged_refuses_a_changed_source_and_an_occupied_target() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();
        ks.insert("src", &"v1".to_string()).await.unwrap();
        let stale = ks.get_raw("src").await.unwrap().unwrap();
        ks.insert("src", &"v2".to_string()).await.unwrap();
        assert_eq!(
            ks.move_if_unchanged("src", stale, "dst", &"x".to_string())
                .await
                .unwrap(),
            MoveOutcome::SourceChanged
        );
        let current = ks.get_raw("src").await.unwrap().unwrap();
        ks.insert("dst", &"taken".to_string()).await.unwrap();
        assert_eq!(
            ks.move_if_unchanged("src", current, "dst", &"x".to_string())
                .await
                .unwrap(),
            MoveOutcome::TargetExists
        );
        assert!(ks.get_raw("src").await.unwrap().is_some(), "nothing moved");
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
    async fn test_range_from_raw_seeks_to_lower_bound() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();

        // Timestamp-like keys (the audit-tail use case): lexical order
        // == chronological order.
        for k in ["2026-01:a", "2026-02:b", "2026-03:c", "2026-04:d"] {
            ks.insert_raw(k.as_bytes().to_vec(), b"v".to_vec())
                .await
                .unwrap();
        }

        // Seek from "2026-03:" → only the rows at-or-after it.
        let rows = ks.range_from_raw(b"2026-03:".to_vec()).await.unwrap();
        let keys: Vec<String> = rows
            .iter()
            .map(|(k, _)| String::from_utf8(k.clone()).unwrap())
            .collect();
        assert_eq!(keys, vec!["2026-03:c", "2026-04:d"]);

        // An empty lower bound returns everything (ascending).
        assert_eq!(ks.range_from_raw(Vec::new()).await.unwrap().len(), 4);
        // A bound past the end returns nothing.
        assert!(
            ks.range_from_raw(b"2026-99:".to_vec())
                .await
                .unwrap()
                .is_empty()
        );
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

    /// End-to-end AAD enforcement through the real handle (P0.1): a
    /// ciphertext written at one key must not decrypt when an attacker
    /// who controls the store relocates it to another key — even within
    /// the same keyspace and storage key. Without AAD this paste
    /// succeeds and resurrects e.g. a revoked ACL row.
    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn encrypted_value_cannot_be_pasted_to_another_key() {
        let (store, _dir) = temp_store();
        let key = [0x55; 32];
        let ks = store.keyspace("acl").unwrap().with_encryption(key);

        ks.insert_raw("acl:victim", b"admin-row".to_vec())
            .await
            .unwrap();

        // Simulate a hostile store operator copying the raw ciphertext
        // from one key to another (writing it back via an unencrypted
        // handle so no re-encryption happens).
        let raw = store.keyspace("acl").unwrap();
        let stolen = raw.get_raw("acl:victim").await.unwrap().unwrap();
        raw.insert_raw("acl:attacker", stolen).await.unwrap();

        // Reading the relocated ciphertext through the encrypted handle
        // must fail AAD authentication, not silently return the value.
        let err = ks.get_raw("acl:attacker").await;
        assert!(
            err.is_err(),
            "a ciphertext pasted to a different key must fail AAD authentication"
        );
        // The original location still decrypts fine.
        assert_eq!(
            ks.get_raw("acl:victim").await.unwrap().unwrap(),
            b"admin-row"
        );
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

    /// P0.7: a keyspace first written in plaintext (pre-encryption-at-rest)
    /// can be migrated in place so an encrypted handle reads it, and the
    /// migrated rows are genuinely ciphertext on disk.
    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn migrate_to_encrypted_converts_legacy_plaintext() {
        let (store, _dir) = temp_store();
        let key = [0x33; 32];

        // Seed legacy plaintext rows via a bare handle.
        let bare = store.keyspace("install").unwrap();
        bare.insert_raw("token:a", b"ephemeral-key-bytes".to_vec())
            .await
            .unwrap();
        bare.insert("token:b", &"json-state".to_string())
            .await
            .unwrap();

        // Migrate.
        let migrated = bare.migrate_to_encrypted(key).await.unwrap();
        assert_eq!(migrated, 2, "both legacy rows must be encrypted");

        // On disk (bare read) the rows are now ciphertext, not the
        // original plaintext.
        let on_disk = bare.get_raw("token:a").await.unwrap().unwrap();
        assert_ne!(on_disk, b"ephemeral-key-bytes");
        assert!(
            on_disk.starts_with(b"VAE1"),
            "migrated row must carry the v1 encryption magic"
        );

        // An encrypted handle reads the original values back.
        let enc = store.keyspace("install").unwrap().with_encryption(key);
        assert_eq!(
            enc.get_raw("token:a").await.unwrap().unwrap(),
            b"ephemeral-key-bytes"
        );
        let b: String = enc.get("token:b").await.unwrap().unwrap();
        assert_eq!(b, "json-state");
    }

    /// Re-running the migration is a no-op: already-encrypted rows are
    /// detected by their format magic and skipped, so an interrupted run
    /// is completed (not double-encrypted) by a re-run.
    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn migrate_to_encrypted_is_idempotent_and_crash_safe() {
        let (store, _dir) = temp_store();
        let key = [0x44; 32];

        let bare = store.keyspace("passkey").unwrap();
        bare.insert_raw("row:1", b"plaintext-one".to_vec())
            .await
            .unwrap();

        // First pass encrypts the one legacy row.
        assert_eq!(bare.migrate_to_encrypted(key).await.unwrap(), 1);

        // A new legacy row lands (simulating a crash mid-migration that
        // left one row plaintext) alongside the already-encrypted one.
        bare.insert_raw("row:2", b"plaintext-two".to_vec())
            .await
            .unwrap();

        // Second pass skips the encrypted row and only converts the new
        // one — never double-encrypting.
        assert_eq!(bare.migrate_to_encrypted(key).await.unwrap(), 1);

        // Third pass is a pure no-op.
        assert_eq!(bare.migrate_to_encrypted(key).await.unwrap(), 0);

        let enc = store.keyspace("passkey").unwrap().with_encryption(key);
        assert_eq!(
            enc.get_raw("row:1").await.unwrap().unwrap(),
            b"plaintext-one"
        );
        assert_eq!(
            enc.get_raw("row:2").await.unwrap().unwrap(),
            b"plaintext-two"
        );
    }

    /// Calling the migration on an already-encrypted handle is a usage
    /// error — it would try to decrypt legacy plaintext and fail. Guard
    /// against it explicitly rather than corrupting data.
    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn migrate_to_encrypted_rejects_encrypted_handle() {
        let (store, _dir) = temp_store();
        let enc = store
            .keyspace("install")
            .unwrap()
            .with_encryption([0x55; 32]);
        assert!(enc.migrate_to_encrypted([0x55; 32]).await.is_err());
    }

    // =======================================================================
    // Fjall memory settings (`FjallTuning` / STORAGE_FJALL_*)
    // =======================================================================

    /// `Store::open` — every pre-existing call site — must behave exactly
    /// as it did before `open_with` existed: fjall's own default cache
    /// capacity, no builder method called for write buffer or journal.
    #[test]
    fn open_leaves_fjalls_own_default_cache_capacity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = LocalStore::open(&config).expect("open");
        // fjall's own built-in default (see `fjall::db_config::Config::new`).
        assert_eq!(store.db.cache_capacity(), 32 * 1024 * 1024);
    }

    /// `open_with` given `FjallTuning::default()` is identical to `open` —
    /// the shape `Store::open` is defined in terms of.
    #[test]
    fn open_with_default_tuning_matches_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = LocalStore::open_with(&config, &FjallTuning::default())
            .expect("open_with default tuning");
        assert_eq!(store.db.cache_capacity(), 32 * 1024 * 1024);
    }

    /// A configured block cache reaches fjall's `Database` unchanged —
    /// the one setting fjall exposes a public getter for, so this is a
    /// concrete, not just "it didn't panic", check that the value actually
    /// took effect. `write_buffer` and `max_journal` are wired through the
    /// identical `if let Some(bytes) = ... { builder = builder.method(bytes) }`
    /// shape in `open_with`, and are exercised below by the
    /// success/refusal boundary tests instead, since fjall does not expose
    /// a getter for either configured maximum.
    #[test]
    fn configured_tuning_opens_and_the_block_cache_takes_effect() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let tuning = FjallTuning {
            block_cache: Some(8 * 1024 * 1024),
            write_buffer: Some(crate::config::MIN_WRITE_BUFFER_BYTES),
            max_journal: Some(crate::config::MIN_MAX_JOURNAL_BYTES),
        };
        let store = LocalStore::open_with(&config, &tuning).expect("open_with configured tuning");
        assert_eq!(store.db.cache_capacity(), 8 * 1024 * 1024);
    }

    /// A `FjallTuning` built by hand (bypassing the deserializer and
    /// `apply_fjall_env_overrides`, both of which already validate) with a
    /// below-floor value is still refused at `open_with` — the
    /// `tuning.validate()` defense-in-depth check — naming the setting,
    /// not a fjall panic.
    #[test]
    fn open_with_refuses_a_below_floor_setting_naming_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let tuning = FjallTuning {
            block_cache: None,
            write_buffer: None,
            max_journal: Some(1024), // far under the 64 MiB floor
        };
        let Err(err) = LocalStore::open_with(&config, &tuning) else {
            panic!("a below-floor max_journal must be refused");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("fjall.max_journal"),
            "error must name the setting, got: {msg}"
        );
    }

    /// Zero is refused with the same clear naming, not silently ignored.
    #[test]
    fn open_with_refuses_a_zero_setting_naming_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let tuning = FjallTuning {
            block_cache: Some(0),
            write_buffer: None,
            max_journal: None,
        };
        let Err(err) = LocalStore::open_with(&config, &tuning) else {
            panic!("a zero block_cache must be refused");
        };
        let msg = err.to_string();
        assert!(msg.contains("fjall.block_cache"), "got: {msg}");
        assert!(msg.contains("zero"), "got: {msg}");
    }
}
