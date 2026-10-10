//! Vsock-backed key-value store for Nitro Enclaves.
//!
//! Sends all storage operations over vsock to the parent EC2 instance,
//! which persists them to fjall on its EBS volume. Data is encrypted
//! enclave-side before crossing vsock — the parent only sees opaque blobs.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::{info, warn};

use super::key_locks::KeyLocks;
#[cfg(test)]
use super::vsock_pool::MAX_MESSAGE_SIZE;
use super::vsock_pool::{BoxStream, ConnectionPool, Connector};
use crate::error::AppError;

// ---------------------------------------------------------------------------
// Wire protocol (duplicated from enclave-proxy/src/protocol.rs to avoid
// a shared crate dependency — the proxy is a standalone non-workspace crate)
// ---------------------------------------------------------------------------

const OP_GET: u8 = 0x01;
const OP_INSERT: u8 = 0x02;
const OP_DELETE: u8 = 0x03;
const OP_PREFIX_ITER: u8 = 0x04;
const OP_PREFIX_KEYS: u8 = 0x05;
const OP_PERSIST: u8 = 0x06;

// Atomic multi-step operations, served by proxies that advertise them in
// OP_HELLO (see `enclave-proxy/src/protocol.rs` for the request layouts).
// Each runs under the keyspace's lock in the parent; the enclave still holds
// its own per-key lock around every one, so a proxy without them — or one
// downgraded while the enclave runs — falls back to single operations with
// the same exactly-one guarantee. None needs plaintext: values are ciphertext
// bound to (keyspace, key), and compare-and-move compares ciphertext the
// enclave has just read and checked itself.
const OP_HELLO: u8 = 0x07;
const OP_TAKE: u8 = 0x08;
const OP_INSERT_IF_ABSENT: u8 = 0x09;
const OP_SWAP_IF_ABSENT: u8 = 0x0A;
const OP_MOVE_IF_EQUAL: u8 = 0x0B;

/// Requests that cannot modify a keyspace. Everything else is tracked as a
/// write (`VsockKeyspaceHandle::send`).
fn is_read_only(payload: &[u8]) -> bool {
    matches!(
        payload.first(),
        Some(&(OP_GET | OP_PREFIX_ITER | OP_PREFIX_KEYS | OP_HELLO | OP_PERSIST))
    )
}

const CAP_TAKE: u32 = 1 << 0;
const CAP_INSERT_IF_ABSENT: u32 = 1 << 1;
const CAP_SWAP_IF_ABSENT: u32 = 1 << 2;
const CAP_MOVE_IF_EQUAL: u32 = 1 << 3;

const MOVE_MOVED: u8 = 0;
const MOVE_SOURCE_MISSING: u8 = 1;
const MOVE_SOURCE_CHANGED: u8 = 2;
const MOVE_TARGET_EXISTS: u8 = 3;

const STATUS_OK: u8 = 0x00;
const STATUS_NOT_FOUND: u8 = 0x01;
const STATUS_ERROR: u8 = 0x02;

fn encode_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn decode_bytes(data: &[u8], offset: usize) -> Result<(&[u8], usize), String> {
    if offset + 4 > data.len() {
        return Err("truncated length".into());
    }
    let len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    let start = offset + 4;
    let end = start + len;
    if end > data.len() {
        return Err(format!("truncated data at offset {start}"));
    }
    Ok((&data[start..end], end))
}

fn encode_keyspace(buf: &mut Vec<u8>, name: &str) {
    buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
    buf.extend_from_slice(name.as_bytes());
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// Open a vsock connection to the parent's storage proxy.
async fn connect_vsock(cid: u32, port: u32) -> Result<BoxStream, AppError> {
    let addr = tokio_vsock::VsockAddr::new(cid, port);
    let stream = tokio_vsock::VsockStream::connect(addr)
        .await
        .map_err(AppError::vsock("vsock connect"))?;
    tracing::trace!(cid, port, "vsock connected");
    Ok(Box::new(stream))
}

/// Ask the proxy which atomic operations it serves.
///
/// A proxy that predates OP_HELLO answers "unknown opcode"; that, and only
/// that, means "none". Any other error, or a malformed answer, is an error,
/// and at connect it fails the boot: HELLO reads no storage and takes no
/// input, so a working proxy has no reason to refuse it, and one that does is
/// broken or not the proxy we expect. Treating that as "none" would silently
/// run on the slower path and hide the fault; retrying would not change the
/// answer of a proxy that cannot answer HELLO.
async fn probe_capabilities(pool: &ConnectionPool) -> Result<u32, AppError> {
    let resp = pool.request(&[OP_HELLO]).await?;
    match resp.first() {
        Some(&STATUS_OK) if resp.len() >= 5 => {
            Ok(u32::from_be_bytes([resp[1], resp[2], resp[3], resp[4]]))
        }
        _ if is_unknown_opcode(&resp) => Ok(0),
        Some(&STATUS_ERROR) => {
            decode_ok(&resp)?;
            Err(AppError::Internal("storage proxy refused HELLO".into()))
        }
        _ => Err(AppError::Internal(format!(
            "malformed HELLO response from storage proxy ({} bytes)",
            resp.len()
        ))),
    }
}

/// How long after finding no atomic operations to ask the proxy again.
const REPROBE_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

/// The atomic operations the proxy serves, shared by every handle.
///
/// A proxy found without them — an older build at boot, or one swapped for an
/// older build while the enclave runs ("unknown opcode" on an atomic op) — may
/// be upgraded later, so with none known the next operation after
/// `REPROBE_AFTER` asks again (one caller does; the rest keep the single-op
/// path meanwhile). Without this, a brief downgrade would cost two to four
/// round trips per claim until the enclave restarted.
struct Capabilities {
    bits: AtomicU32,
    /// While `bits` is 0: when to ask again.
    next_probe: std::sync::Mutex<Option<std::time::Instant>>,
    reprobe_after: std::time::Duration,
}

impl Capabilities {
    fn new(bits: u32, reprobe_after: std::time::Duration) -> Self {
        let next_probe = (bits == 0).then(|| std::time::Instant::now() + reprobe_after);
        Self {
            bits: AtomicU32::new(bits),
            next_probe: std::sync::Mutex::new(next_probe),
            reprobe_after,
        }
    }

    fn has(&self, cap: u32) -> bool {
        self.bits.load(Ordering::Relaxed) & cap != 0
    }

    fn next_probe(&self) -> std::sync::MutexGuard<'_, Option<std::time::Instant>> {
        self.next_probe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The proxy answered "unknown opcode": stop sending atomic opcodes and
    /// schedule a re-probe. `true` if it had any before.
    fn downgrade(&self) -> bool {
        *self.next_probe() = Some(std::time::Instant::now() + self.reprobe_after);
        self.bits.swap(0, Ordering::Relaxed) != 0
    }

    /// Whether this caller should re-probe now. Pushes the next probe out, so
    /// concurrent callers do not all probe at once.
    fn claim_probe(&self) -> bool {
        let mut next = self.next_probe();
        match *next {
            Some(at) if std::time::Instant::now() >= at => {
                *next = Some(std::time::Instant::now() + self.reprobe_after);
                true
            }
            _ => false,
        }
    }

    fn set(&self, bits: u32) {
        self.bits.store(bits, Ordering::Relaxed);
        if bits != 0 {
            *self.next_probe() = None;
        }
    }
}

/// True when a response says the proxy does not know the opcode it was sent.
fn is_unknown_opcode(resp: &[u8]) -> bool {
    resp.first() == Some(&STATUS_ERROR)
        && decode_bytes(resp, 1).is_ok_and(|(msg, _)| msg.starts_with(b"unknown opcode"))
}

// ---------------------------------------------------------------------------
// VsockStore
// ---------------------------------------------------------------------------

/// The vsock CID of a Nitro Enclave's parent instance, as seen from inside
/// the enclave. The parent is the only peer an enclave can reach or be
/// reached by: the storage proxy, the log sink and the REST ingress
/// (`vta-service`'s vsock listener accepts this CID only) all sit there.
pub const PARENT_CID: u32 = 3;
/// Default vsock port for the storage proxy.
const DEFAULT_STORAGE_PORT: u32 = 5500;
/// Upper bound on simultaneous storage connections to the parent.
///
/// High enough that storage round trips stop being the bottleneck on the
/// enclave sizes we run (1 to 6 vCPUs), low enough that a burst cannot open
/// an unbounded number of sockets on the parent.
const DEFAULT_MAX_CONNECTIONS: usize = 8;

/// A key-value store backed by the parent's storage proxy over vsock.
///
/// Drop-in replacement for `Store` when running inside a Nitro Enclave.
///
/// Storage operations run concurrently over a bounded pool of connections
/// (see [`super::vsock_pool`]); each operation is still one request and
/// response.
#[derive(Clone)]
pub struct VsockStore {
    pool: Arc<ConnectionPool>,
    /// Shared by every keyspace handle, so multi-step operations on one key
    /// exclude each other however the handles were obtained.
    locks: Arc<KeyLocks>,
    /// Atomic operations the proxy serves (OP_HELLO), shared by every handle;
    /// see [`Capabilities`].
    caps: Arc<Capabilities>,
    /// Per-keyspace write tracking, shared by every handle for a name, so a
    /// cache over one handle sees writes through any other — see
    /// `super::generation`.
    writes: super::generation::Generations,
}

impl VsockStore {
    /// Connect to the parent's storage proxy.
    pub async fn connect(port: Option<u32>) -> Result<Self, AppError> {
        let port = port.unwrap_or(DEFAULT_STORAGE_PORT);
        // Connect once up front so a missing proxy fails the boot here.
        let first = connect_vsock(PARENT_CID, port).await?;
        info!(
            port,
            max_connections = DEFAULT_MAX_CONNECTIONS,
            "connected to parent storage proxy via vsock"
        );
        let connector: Connector = Arc::new(move || Box::pin(connect_vsock(PARENT_CID, port)));
        let pool = Arc::new(ConnectionPool::new(
            connector,
            DEFAULT_MAX_CONNECTIONS,
            first,
        ));
        let caps = probe_capabilities(&pool).await?;
        info!(
            capabilities = format_args!("{caps:#x}"),
            "storage proxy atomic operations"
        );
        Ok(Self {
            pool,
            locks: Arc::new(KeyLocks::default()),
            caps: Arc::new(Capabilities::new(caps, REPROBE_AFTER)),
            writes: Default::default(),
        })
    }

    /// Get a keyspace handle. No RPC needed — the keyspace name is sent
    /// with each operation.
    pub fn keyspace(&self, name: &str) -> Result<VsockKeyspaceHandle, AppError> {
        Ok(VsockKeyspaceHandle {
            pool: Arc::clone(&self.pool),
            locks: Arc::clone(&self.locks),
            caps: Arc::clone(&self.caps),
            writes: self.writes.for_keyspace(name),
            keyspace: name.to_string(),
            #[cfg(feature = "encryption")]
            encryption_key: None,
        })
    }

    /// Flush the parent's store to disk.
    pub async fn persist(&self) -> Result<(), AppError> {
        let payload = vec![OP_PERSIST];
        let resp = self.pool.request(&payload).await?;
        decode_ok(&resp)
    }
}

// ---------------------------------------------------------------------------
// VsockKeyspaceHandle
// ---------------------------------------------------------------------------

/// Handle to a keyspace on the parent's storage proxy.
///
/// Same API as `KeyspaceHandle` — get, insert, remove, prefix_iter, etc.
/// Encryption is applied enclave-side before sending over vsock.
#[derive(Clone)]
pub struct VsockKeyspaceHandle {
    pool: Arc<ConnectionPool>,
    locks: Arc<KeyLocks>,
    caps: Arc<Capabilities>,
    /// This keyspace's write tracking, shared with every handle for the name.
    /// [`Self::send`] begins a write before any request that can modify the
    /// keyspace leaves the enclave, and ends it when the response arrives —
    /// or marks its outcome unknown if the request fails or is cancelled.
    writes: Arc<super::generation::KeyspaceWrites>,
    keyspace: String,
    #[cfg(feature = "encryption")]
    encryption_key: Option<Arc<zeroize::Zeroizing<[u8; 32]>>>,
}

/// Raw key-value pair type (same as in the local store).
pub type RawKvPair = (Vec<u8>, Vec<u8>);

impl VsockKeyspaceHandle {
    /// Return a clone with AES-256-GCM encryption enabled.
    #[cfg(feature = "encryption")]
    pub fn with_encryption(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(Arc::new(zeroize::Zeroizing::new(key)));
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

    /// Ask the parent proxy to flush the store to disk — see
    /// [`crate::store::KeyspaceHandle::persist`]. Store-wide, not
    /// per-keyspace.
    pub async fn persist(&self) -> Result<(), AppError> {
        let payload = vec![OP_PERSIST];
        let resp = self.send(&payload).await?;
        decode_ok(&resp)
    }

    pub async fn insert<V: Serialize>(
        &self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<(), AppError> {
        let key = key.into();
        let bytes = serde_json::to_vec(value)?;
        let bytes = self.maybe_encrypt(&key, bytes)?;
        let mut payload = vec![OP_INSERT];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, &key);
        encode_bytes(&mut payload, &bytes);
        let resp = self.send(&payload).await?;
        decode_ok(&resp)
    }

    pub async fn get<V: DeserializeOwned + Send + 'static>(
        &self,
        key: impl Into<Vec<u8>>,
    ) -> Result<Option<V>, AppError> {
        let key = key.into();
        let mut payload = vec![OP_GET];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, &key);
        let resp = self.send(&payload).await?;
        match decode_value(&resp)? {
            Some(bytes) => {
                let bytes = self.maybe_decrypt(&key, &bytes)?;
                Ok(Some(serde_json::from_slice(&bytes)?))
            }
            None => Ok(None),
        }
    }

    pub async fn remove(&self, key: impl Into<Vec<u8>>) -> Result<(), AppError> {
        let key = key.into();
        let mut payload = vec![OP_DELETE];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, &key);
        let resp = self.send(&payload).await?;
        decode_ok(&resp)
    }

    pub async fn insert_raw(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<(), AppError> {
        let key = key.into();
        let value = self.maybe_encrypt(&key, value.into())?;
        let mut payload = vec![OP_INSERT];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, &key);
        encode_bytes(&mut payload, &value);
        let resp = self.send(&payload).await?;
        decode_ok(&resp)
    }

    pub async fn get_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        let key = key.into();
        match self.get_stored(&key).await? {
            Some(bytes) => Ok(Some(self.maybe_decrypt(&key, &bytes)?)),
            None => Ok(None),
        }
    }

    /// The stored bytes at `key` (ciphertext when encrypted), undecrypted.
    async fn get_stored(&self, key: &[u8]) -> Result<Option<Vec<u8>>, AppError> {
        let mut payload = vec![OP_GET];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, key);
        let resp = self.send(&payload).await?;
        decode_value(&resp)
    }

    pub async fn prefix_iter_raw(
        &self,
        prefix: impl Into<Vec<u8>>,
    ) -> Result<Vec<RawKvPair>, AppError> {
        let prefix = prefix.into();
        let mut payload = vec![OP_PREFIX_ITER];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, &prefix);
        let resp = self.send(&payload).await?;
        let pairs = decode_kv_list(&resp)?;
        // Decrypt values
        pairs
            .into_iter()
            .map(|(k, v)| {
                let v = self.maybe_decrypt(&k, &v)?;
                Ok((k, v))
            })
            .collect()
    }

    /// See [`crate::store::KeyspaceHandle::range_from_raw`]. The vsock
    /// proxy protocol has no native range op, and this backend is only
    /// used by the enclave VTA (the registry syncer that calls
    /// `range_from_raw` is VTC-only, never on vsock), so this falls back
    /// to a full scan filtered to `key >= from` — correct, just not
    /// seek-optimised.
    pub async fn range_from_raw(
        &self,
        from: impl Into<Vec<u8>>,
    ) -> Result<Vec<RawKvPair>, AppError> {
        let from = from.into();
        let all = self.prefix_iter_raw(Vec::<u8>::new()).await?;
        Ok(all
            .into_iter()
            .filter(|(k, _)| k.as_slice() >= from.as_slice())
            .collect())
    }

    pub async fn prefix_keys(&self, prefix: impl Into<Vec<u8>>) -> Result<Vec<Vec<u8>>, AppError> {
        let prefix = prefix.into();
        let mut payload = vec![OP_PREFIX_KEYS];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, &prefix);
        let resp = self.send(&payload).await?;
        decode_key_list(&resp)
    }

    pub async fn approximate_len(&self) -> Result<usize, AppError> {
        // Approximate by counting keys with empty prefix
        let keys = self.prefix_keys("").await?;
        Ok(keys.len())
    }

    /// Insert `value` at `key` only if absent; `true` when it was inserted.
    /// Atomic: the key's lock is held across the operation, and a proxy that
    /// serves OP_INSERT_IF_ABSENT does it in one round trip.
    pub async fn insert_if_absent<V: Serialize>(
        &self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<bool, AppError> {
        let key = key.into();
        let stored = self.maybe_encrypt(&key, serde_json::to_vec(value)?)?;
        self.insert_stored_if_absent(key, stored).await
    }

    /// Raw-bytes [`Self::insert_if_absent`].
    pub async fn insert_raw_if_absent(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<bool, AppError> {
        let key = key.into();
        let stored = self.maybe_encrypt(&key, value.into())?;
        self.insert_stored_if_absent(key, stored).await
    }

    /// `stored` is already encrypted for `key`.
    async fn insert_stored_if_absent(
        &self,
        key: Vec<u8>,
        stored: Vec<u8>,
    ) -> Result<bool, AppError> {
        let _guard = self.locks.lock(&self.keyspace, &[&key]).await;
        if self.has(CAP_INSERT_IF_ABSENT).await {
            let mut p = vec![OP_INSERT_IF_ABSENT];
            encode_keyspace(&mut p, &self.keyspace);
            encode_bytes(&mut p, &key);
            encode_bytes(&mut p, &stored);
            if let Some(resp) = self.send_atomic(&p).await? {
                return decode_bool(&resp);
            }
        }
        if self.get_raw(key.clone()).await?.is_some() {
            return Ok(false);
        }
        self.put_stored(&key, &stored).await?;
        Ok(true)
    }

    /// Read and delete `key`; exactly one of two racing callers gets the
    /// value. The key's lock is held across the operation, and a proxy that
    /// serves OP_TAKE does it in one round trip.
    ///
    /// On the two-step path, a caller cancelled between the steps leaves the
    /// row and receives nothing, and a failed delete returns the error, not
    /// the value. Neither path hands the value out twice.
    pub async fn take_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        let key = key.into();
        let _guard = self.locks.lock(&self.keyspace, &[&key]).await;
        if self.has(CAP_TAKE).await {
            let mut p = vec![OP_TAKE];
            encode_keyspace(&mut p, &self.keyspace);
            encode_bytes(&mut p, &key);
            if let Some(resp) = self.send_atomic(&p).await? {
                return match decode_value(&resp)? {
                    Some(stored) => match self.maybe_decrypt(&key, &stored) {
                        Ok(value) => Ok(Some(value)),
                        Err(e) => {
                            // The parent has already deleted the row. Put the
                            // exact bytes back before reporting: a storage-key
                            // misconfiguration must fail the claim, not wipe
                            // every row a claim touches. Still under the key's
                            // lock, so no other enclave claim sees the gap.
                            self.restore_after_failed_take(&key, &stored).await;
                            Err(e)
                        }
                    },
                    None => Ok(None),
                };
            }
        }
        let val = self.get_raw(key.clone()).await?;
        if val.is_some() {
            self.remove(key).await?;
        }
        Ok(val)
    }

    /// Move to `new_key` unless it is occupied; `false` when it was. Atomic
    /// with respect to every other multi-step operation on either key.
    pub async fn swap<V: Serialize>(
        &self,
        old_key: impl Into<Vec<u8>>,
        new_key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<bool, AppError> {
        let old_key = old_key.into();
        let new_key = new_key.into();
        let _guard = self.locks.lock(&self.keyspace, &[&old_key, &new_key]).await;
        // The value lands at `new_key`, so bind the AAD to it.
        let stored = self.maybe_encrypt(&new_key, serde_json::to_vec(value)?)?;
        self.swap_locked(&old_key, &new_key, &stored).await
    }

    /// The steps of [`Self::swap`]; the caller holds both keys' locks and
    /// `stored` is already encrypted for `new_key`.
    async fn swap_locked(
        &self,
        old_key: &[u8],
        new_key: &[u8],
        stored: &[u8],
    ) -> Result<bool, AppError> {
        if self.has(CAP_SWAP_IF_ABSENT).await {
            let mut p = vec![OP_SWAP_IF_ABSENT];
            encode_keyspace(&mut p, &self.keyspace);
            encode_bytes(&mut p, old_key);
            encode_bytes(&mut p, new_key);
            encode_bytes(&mut p, stored);
            if let Some(resp) = self.send_atomic(&p).await? {
                return decode_bool(&resp);
            }
        }
        if self.get_raw(new_key.to_vec()).await?.is_some() {
            return Ok(false);
        }
        self.put_stored(new_key, stored).await?;
        self.remove(old_key.to_vec()).await?;
        Ok(true)
    }

    /// Compare-and-move: only while `old_key` still holds exactly `expected`
    /// (plaintext). Both keys' locks are held throughout, so two callers
    /// holding the same `expected` cannot both move.
    ///
    /// The plaintext comparison happens here, in the enclave. A proxy that
    /// serves OP_MOVE_IF_EQUAL is then asked to move only if the row still
    /// holds the ciphertext just read: two round trips instead of four, and
    /// the parent never sees what it compares.
    pub async fn move_if_unchanged<V: Serialize>(
        &self,
        old_key: impl Into<Vec<u8>>,
        expected: Vec<u8>,
        new_key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<super::MoveOutcome, AppError> {
        use super::MoveOutcome;
        let old_key = old_key.into();
        let new_key = new_key.into();
        let _guard = self.locks.lock(&self.keyspace, &[&old_key, &new_key]).await;
        let Some(current_stored) = self.get_stored(&old_key).await? else {
            return Ok(MoveOutcome::SourceMissing);
        };
        if self.maybe_decrypt(&old_key, &current_stored)? != expected {
            return Ok(MoveOutcome::SourceChanged);
        }
        let stored = self.maybe_encrypt(&new_key, serde_json::to_vec(value)?)?;
        if self.has(CAP_MOVE_IF_EQUAL).await {
            let mut p = vec![OP_MOVE_IF_EQUAL];
            encode_keyspace(&mut p, &self.keyspace);
            encode_bytes(&mut p, &old_key);
            encode_bytes(&mut p, &current_stored);
            encode_bytes(&mut p, &new_key);
            encode_bytes(&mut p, &stored);
            if let Some(resp) = self.send_atomic(&p).await? {
                return match decode_byte(&resp)? {
                    MOVE_MOVED => Ok(MoveOutcome::Moved),
                    MOVE_SOURCE_MISSING => Ok(MoveOutcome::SourceMissing),
                    MOVE_SOURCE_CHANGED => Ok(MoveOutcome::SourceChanged),
                    MOVE_TARGET_EXISTS => Ok(MoveOutcome::TargetExists),
                    other => Err(AppError::Internal(format!(
                        "storage proxy: unknown move outcome {other}"
                    ))),
                };
            }
        }
        if self.swap_locked(&old_key, &new_key, &stored).await? {
            Ok(MoveOutcome::Moved)
        } else {
            Ok(MoveOutcome::TargetExists)
        }
    }

    /// Re-insert the exact bytes an OP_TAKE returned and the enclave could not
    /// decrypt or authenticate. The caller holds the key's lock.
    ///
    /// Insert-if-absent where the proxy serves it, so a legitimate value
    /// written meanwhile is never overwritten (the lock makes that moot, but
    /// a restore must never be the thing that destroys data); plain insert
    /// otherwise. Best effort: the caller returns the decrypt error either
    /// way, and a failed restore is logged as a security alert.
    async fn restore_after_failed_take(&self, key: &[u8], stored: &[u8]) {
        let restored: Result<(), AppError> = async {
            if self.has(CAP_INSERT_IF_ABSENT).await {
                let mut p = vec![OP_INSERT_IF_ABSENT];
                encode_keyspace(&mut p, &self.keyspace);
                encode_bytes(&mut p, key);
                encode_bytes(&mut p, stored);
                if let Some(resp) = self.send_atomic(&p).await? {
                    if !decode_bool(&resp)? {
                        warn!(
                            keyspace = %self.keyspace,
                            "a value was written while an undecryptable take was being restored; kept it"
                        );
                    }
                    return Ok(());
                }
            }
            self.put_stored(key, stored).await
        }
        .await;
        if let Err(e) = restored {
            tracing::error!(
                security_alert = true,
                keyspace = %self.keyspace,
                error = %e,
                "could not restore a row whose taken value failed to decrypt; the row is lost"
            );
        }
    }

    /// Whether the proxy serves an atomic operation, re-probing first if none
    /// is known and a re-probe is due (see [`Capabilities`]).
    async fn has(&self, cap: u32) -> bool {
        if self.caps.has(cap) {
            return true;
        }
        if self.caps.claim_probe() {
            match probe_capabilities(&self.pool).await {
                Ok(bits) => {
                    self.caps.set(bits);
                    if bits != 0 {
                        info!(
                            capabilities = format_args!("{bits:#x}"),
                            "storage proxy serves atomic operations again"
                        );
                    }
                }
                Err(e) => warn!(error = %e, "storage proxy re-probe failed"),
            }
            return self.caps.has(cap);
        }
        false
    }

    /// Send an atomic-operation request, never resent once it may have been
    /// applied (see [`ConnectionPool::request_once`]).
    ///
    /// `Ok(None)` when the proxy does not know the opcode after all (replaced
    /// by an older build since HELLO): nothing was applied, so the caller
    /// falls back to single operations, and every handle stops sending atomic
    /// opcodes until a re-probe finds them again. An error — including
    /// "outcome unknown" — is returned as is: falling back after a request
    /// that may have been applied could apply it twice.
    async fn send_atomic(&self, payload: &[u8]) -> Result<Option<Vec<u8>>, AppError> {
        // Every atomic opcode is a write; tracked as `send` tracks one.
        let write = self.writes.begin();
        let resp = self
            .pool
            .request_once_tracked(payload, write.sent())
            .await?;
        write.completed();
        if is_unknown_opcode(&resp) {
            if self.caps.downgrade() {
                warn!("storage proxy no longer serves atomic operations; using single operations");
            }
            return Ok(None);
        }
        Ok(Some(resp))
    }

    /// Write already-encrypted bytes at `key`.
    async fn put_stored(&self, key: &[u8], stored: &[u8]) -> Result<(), AppError> {
        let mut payload = vec![OP_INSERT];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, key);
        encode_bytes(&mut payload, stored);
        let resp = self.send(&payload).await?;
        decode_ok(&resp)
    }

    /// This keyspace's write tracking — see
    /// [`crate::store::KeyspaceHandle::cache_ticket`].
    pub(crate) fn writes(&self) -> &super::generation::KeyspaceWrites {
        &self.writes
    }

    /// Send one idempotent request over a pooled connection (resent once on
    /// failure) and return the response.
    ///
    /// The store's requests leave the enclave through here or
    /// [`Self::send_atomic`] — single operations, the atomic opcodes, their
    /// single-operation fallbacks, the restore after a failed take — and both
    /// track writes. Here anything that is not a known read counts as a
    /// write, so an opcode added later is tracked until someone decides
    /// otherwise.
    async fn send(&self, payload: &[u8]) -> Result<Vec<u8>, AppError> {
        if is_read_only(payload) {
            return self.pool.request(payload).await;
        }
        // Begun before the frame leaves. Dropped without `completed` — an
        // error, or this future cancelled — it marks the outcome unknown only
        // if the frame had completely left (`sent`); before that, the parent
        // cannot have applied it.
        let write = self.writes.begin();
        let resp = self.pool.request_tracked(payload, write.sent()).await?;
        write.completed();
        Ok(resp)
    }

    fn maybe_encrypt(&self, store_key: &[u8], plaintext: Vec<u8>) -> Result<Vec<u8>, AppError> {
        #[cfg(feature = "encryption")]
        {
            match self.encryption_key.as_ref().map(|arc| &***arc) {
                Some(key) => {
                    super::encryption::encrypt_value(key, &self.keyspace, store_key, &plaintext)
                }
                None => Ok(plaintext),
            }
        }
        #[cfg(not(feature = "encryption"))]
        {
            let _ = store_key;
            Ok(plaintext)
        }
    }

    fn maybe_decrypt(&self, store_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AppError> {
        #[cfg(feature = "encryption")]
        {
            match self.encryption_key.as_ref().map(|arc| &***arc) {
                Some(key) => super::encryption::maybe_decrypt_bytes(
                    Some(key),
                    &self.keyspace,
                    store_key,
                    ciphertext,
                ),
                None => Ok(ciphertext.to_vec()),
            }
        }
        #[cfg(not(feature = "encryption"))]
        {
            let _ = store_key;
            Ok(ciphertext.to_vec())
        }
    }
}

// ---------------------------------------------------------------------------
// Response decoders
// ---------------------------------------------------------------------------

fn decode_ok(data: &[u8]) -> Result<(), AppError> {
    if data.is_empty() {
        return Err(AppError::Internal(
            "empty response from storage proxy".into(),
        ));
    }
    match data[0] {
        STATUS_OK => Ok(()),
        STATUS_ERROR => {
            let (msg, _) = decode_bytes(data, 1)
                .map_err(|e| AppError::Internal(format!("decode error: {e}")))?;
            Err(AppError::Internal(format!(
                "storage proxy error: {}",
                String::from_utf8_lossy(msg)
            )))
        }
        s => Err(AppError::Internal(format!("unexpected status: {s:#04x}"))),
    }
}

fn decode_value(data: &[u8]) -> Result<Option<Vec<u8>>, AppError> {
    if data.is_empty() {
        return Err(AppError::Internal(
            "empty response from storage proxy".into(),
        ));
    }
    match data[0] {
        STATUS_OK => {
            let (value, _) = decode_bytes(data, 1)
                .map_err(|e| AppError::Internal(format!("decode error: {e}")))?;
            Ok(Some(value.to_vec()))
        }
        STATUS_NOT_FOUND => Ok(None),
        STATUS_ERROR => {
            let (msg, _) = decode_bytes(data, 1)
                .map_err(|e| AppError::Internal(format!("decode error: {e}")))?;
            Err(AppError::Internal(format!(
                "storage proxy error: {}",
                String::from_utf8_lossy(msg)
            )))
        }
        s => Err(AppError::Internal(format!("unexpected status: {s:#04x}"))),
    }
}

/// `[OK][byte]` → byte; an error status carries its message.
fn decode_byte(data: &[u8]) -> Result<u8, AppError> {
    match data.first() {
        Some(&STATUS_OK) if data.len() >= 2 => Ok(data[1]),
        Some(&STATUS_ERROR) => {
            // Surfaces the proxy's message as the error.
            decode_ok(data)?;
            Err(AppError::Internal("storage proxy error".into()))
        }
        _ => Err(AppError::Internal(format!(
            "malformed response from storage proxy ({} bytes)",
            data.len()
        ))),
    }
}

fn decode_bool(data: &[u8]) -> Result<bool, AppError> {
    Ok(decode_byte(data)? != 0)
}

fn decode_kv_list(data: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, AppError> {
    if data.is_empty() {
        return Err(AppError::Internal("empty response".into()));
    }
    match data[0] {
        STATUS_OK => {
            if data.len() < 5 {
                return Err(AppError::Internal("truncated kv list".into()));
            }
            let count = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            let mut offset = 5;
            let mut pairs = Vec::with_capacity(count);
            for _ in 0..count {
                let (key, new_offset) = decode_bytes(data, offset)
                    .map_err(|e| AppError::Internal(format!("decode kv: {e}")))?;
                let (value, new_offset) = decode_bytes(data, new_offset)
                    .map_err(|e| AppError::Internal(format!("decode kv: {e}")))?;
                pairs.push((key.to_vec(), value.to_vec()));
                offset = new_offset;
            }
            Ok(pairs)
        }
        STATUS_ERROR => {
            let (msg, _) = decode_bytes(data, 1)
                .map_err(|e| AppError::Internal(format!("decode error: {e}")))?;
            Err(AppError::Internal(format!(
                "storage proxy error: {}",
                String::from_utf8_lossy(msg)
            )))
        }
        s => Err(AppError::Internal(format!("unexpected status: {s:#04x}"))),
    }
}

fn decode_key_list(data: &[u8]) -> Result<Vec<Vec<u8>>, AppError> {
    if data.is_empty() {
        return Err(AppError::Internal("empty response".into()));
    }
    match data[0] {
        STATUS_OK => {
            if data.len() < 5 {
                return Err(AppError::Internal("truncated key list".into()));
            }
            let count = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            let mut offset = 5;
            let mut keys = Vec::with_capacity(count);
            for _ in 0..count {
                let (key, new_offset) = decode_bytes(data, offset)
                    .map_err(|e| AppError::Internal(format!("decode key: {e}")))?;
                keys.push(key.to_vec());
                offset = new_offset;
            }
            Ok(keys)
        }
        STATUS_ERROR => {
            let (msg, _) = decode_bytes(data, 1)
                .map_err(|e| AppError::Internal(format!("decode error: {e}")))?;
            Err(AppError::Internal(format!(
                "storage proxy error: {}",
                String::from_utf8_lossy(msg)
            )))
        }
        s => Err(AppError::Internal(format!("unexpected status: {s:#04x}"))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// The full VsockStore round-trip is exercised at integration level against the
// enclave-proxy binary (see `deploy/nitro/enclave-proxy`). These tests cover
// the pure wire-format layer in isolation — the encoders/decoders that both
// ends must agree on. A bug here silently breaks every enclave boot.

#[cfg(test)]
mod tests {
    use super::*;

    // ── encode/decode_bytes round-trip ─────────────────────────────

    #[test]
    fn encode_bytes_prepends_big_endian_length() {
        let mut buf = Vec::new();
        encode_bytes(&mut buf, b"hello");
        assert_eq!(
            buf,
            vec![
                0, 0, 0, 5, // length as u32 big-endian
                b'h', b'e', b'l', b'l', b'o',
            ],
            "wire format must be BE-u32 length prefix + bytes"
        );
    }

    #[test]
    fn decode_bytes_recovers_encoded_payload() {
        let mut buf = Vec::new();
        encode_bytes(&mut buf, b"payload-one");
        encode_bytes(&mut buf, b"payload-two");
        let (first, next_offset) = decode_bytes(&buf, 0).unwrap();
        assert_eq!(first, b"payload-one");
        let (second, final_offset) = decode_bytes(&buf, next_offset).unwrap();
        assert_eq!(second, b"payload-two");
        assert_eq!(final_offset, buf.len());
    }

    #[test]
    fn decode_bytes_rejects_truncated_length_prefix() {
        // 3 bytes — not enough for a u32 length prefix.
        let err = decode_bytes(&[0, 0, 5], 0).expect_err("truncated length must error");
        assert!(err.contains("truncated length"), "got {err}");
    }

    #[test]
    fn decode_bytes_rejects_truncated_data() {
        // Length prefix claims 10 bytes but only 3 follow.
        let mut buf = vec![0, 0, 0, 10];
        buf.extend_from_slice(b"abc");
        let err = decode_bytes(&buf, 0).expect_err("truncated data must error");
        assert!(err.contains("truncated data"), "got {err}");
    }

    #[test]
    fn decode_bytes_rejects_offset_past_end() {
        let err = decode_bytes(&[0u8; 2], 10).expect_err("offset past end must error");
        assert!(err.contains("truncated length"), "got {err}");
    }

    #[test]
    fn encode_bytes_handles_empty_payload() {
        let mut buf = Vec::new();
        encode_bytes(&mut buf, b"");
        assert_eq!(buf, vec![0, 0, 0, 0]);
        let (decoded, _) = decode_bytes(&buf, 0).unwrap();
        assert_eq!(decoded, b"");
    }

    // ── encode_keyspace ─────────────────────────────────────────────

    #[test]
    fn encode_keyspace_uses_be_u16_prefix() {
        let mut buf = Vec::new();
        encode_keyspace(&mut buf, "sessions");
        assert_eq!(
            buf,
            vec![
                0, 8, // length as u16 big-endian
                b's', b'e', b's', b's', b'i', b'o', b'n', b's',
            ],
            "keyspace names use a u16 length prefix, not u32"
        );
    }

    // ── decode_ok ───────────────────────────────────────────────────

    #[test]
    fn decode_ok_accepts_status_ok() {
        decode_ok(&[STATUS_OK]).expect("STATUS_OK must decode");
    }

    #[test]
    fn decode_ok_propagates_error_message() {
        let mut resp = vec![STATUS_ERROR];
        encode_bytes(&mut resp, b"disk full");
        let err = decode_ok(&resp).expect_err("STATUS_ERROR must be an error");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("storage proxy error") && msg.contains("disk full"),
            "must surface the proxy message — got {msg}"
        );
    }

    #[test]
    fn decode_ok_rejects_empty_response() {
        let err = decode_ok(&[]).expect_err("empty response must error");
        assert!(format!("{err:?}").contains("empty response"), "got {err:?}");
    }

    #[test]
    fn decode_ok_rejects_unknown_status() {
        let err = decode_ok(&[0xFF]).expect_err("unknown status must error");
        assert!(
            format!("{err:?}").contains("unexpected status"),
            "got {err:?}"
        );
    }

    // ── decode_value ────────────────────────────────────────────────

    #[test]
    fn decode_value_returns_ok_payload() {
        let mut resp = vec![STATUS_OK];
        encode_bytes(&mut resp, b"the value");
        let result = decode_value(&resp).unwrap();
        assert_eq!(result, Some(b"the value".to_vec()));
    }

    #[test]
    fn decode_value_returns_none_for_not_found() {
        let result = decode_value(&[STATUS_NOT_FOUND]).unwrap();
        assert_eq!(result, None, "STATUS_NOT_FOUND must map to Option::None");
    }

    #[test]
    fn decode_value_propagates_error() {
        let mut resp = vec![STATUS_ERROR];
        encode_bytes(&mut resp, b"io error");
        let err = decode_value(&resp).expect_err("STATUS_ERROR must be an error");
        assert!(format!("{err:?}").contains("io error"), "got {err:?}");
    }

    // ── decode_kv_list / decode_key_list ────────────────────────────

    #[test]
    fn decode_kv_list_empty_result() {
        // STATUS_OK + count=0 + no pairs
        let resp = vec![STATUS_OK, 0, 0, 0, 0];
        let pairs = decode_kv_list(&resp).unwrap();
        assert!(pairs.is_empty());
    }

    #[test]
    fn decode_kv_list_decodes_multiple_pairs() {
        let mut resp = vec![STATUS_OK];
        resp.extend_from_slice(&2u32.to_be_bytes()); // count
        encode_bytes(&mut resp, b"k1");
        encode_bytes(&mut resp, b"v1");
        encode_bytes(&mut resp, b"k2");
        encode_bytes(&mut resp, b"v2");
        let pairs = decode_kv_list(&resp).unwrap();
        assert_eq!(
            pairs,
            vec![
                (b"k1".to_vec(), b"v1".to_vec()),
                (b"k2".to_vec(), b"v2".to_vec()),
            ]
        );
    }

    #[test]
    fn decode_kv_list_rejects_truncated_count_header() {
        // STATUS_OK but only 3 bytes of count (needs 4).
        let resp = vec![STATUS_OK, 0, 0, 0];
        let err = decode_kv_list(&resp).expect_err("truncated count must error");
        assert!(
            format!("{err:?}").contains("truncated kv list"),
            "got {err:?}"
        );
    }

    #[test]
    fn decode_kv_list_rejects_count_larger_than_payload() {
        // Claims 5 pairs but no pair data follows — inner decode_bytes
        // must error rather than silently returning an empty vec.
        let mut resp = vec![STATUS_OK];
        resp.extend_from_slice(&5u32.to_be_bytes());
        let err = decode_kv_list(&resp).expect_err("count > actual pairs must error");
        assert!(format!("{err:?}").contains("decode kv"), "got {err:?}");
    }

    #[test]
    fn decode_key_list_decodes_multiple_keys() {
        let mut resp = vec![STATUS_OK];
        resp.extend_from_slice(&3u32.to_be_bytes());
        encode_bytes(&mut resp, b"alpha");
        encode_bytes(&mut resp, b"beta");
        encode_bytes(&mut resp, b"gamma");
        let keys = decode_key_list(&resp).unwrap();
        assert_eq!(
            keys,
            vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()]
        );
    }

    #[test]
    fn decode_key_list_propagates_error() {
        let mut resp = vec![STATUS_ERROR];
        encode_bytes(&mut resp, b"denied");
        let err = decode_key_list(&resp).expect_err("STATUS_ERROR must propagate");
        assert!(format!("{err:?}").contains("denied"), "got {err:?}");
    }

    // ── Request payload shape ───────────────────────────────────────
    //
    // The enclave-proxy expects:
    //   [OP_CODE: u8] [keyspace_len: u16 BE] [keyspace bytes] [..op-specific..]
    // Both sides duplicate these constants; a change here without the
    // corresponding proxy update silently breaks every enclave boot.

    #[test]
    fn op_code_constants_match_proxy_wire_contract() {
        // Stability assertion: these values are persisted by the
        // enclave-proxy and must not change without a protocol bump.
        assert_eq!(OP_GET, 0x01);
        assert_eq!(OP_INSERT, 0x02);
        assert_eq!(OP_DELETE, 0x03);
        assert_eq!(OP_PREFIX_ITER, 0x04);
        assert_eq!(OP_PREFIX_KEYS, 0x05);
        assert_eq!(OP_PERSIST, 0x06);
    }

    #[test]
    fn status_code_constants_match_proxy_wire_contract() {
        assert_eq!(STATUS_OK, 0x00);
        assert_eq!(STATUS_NOT_FOUND, 0x01);
        assert_eq!(STATUS_ERROR, 0x02);
    }

    #[test]
    fn max_message_size_is_bounded() {
        // Bounded-parser invariant: a malicious parent can't induce
        // OOM by claiming a large response size. 16 MiB is generous
        // for legitimate backup payloads while still bounding attack
        // surface.
        assert_eq!(MAX_MESSAGE_SIZE, 16 * 1024 * 1024);
    }

    #[test]
    fn get_request_payload_matches_wire_contract() {
        // Manually construct what VsockKeyspaceHandle::get_raw sends.
        let mut payload = vec![OP_GET];
        encode_keyspace(&mut payload, "sessions");
        encode_bytes(&mut payload, b"session:abc");

        // Expected: op + u16(8) + "sessions" + u32(11) + "session:abc"
        let mut expected = vec![OP_GET];
        expected.extend_from_slice(&8u16.to_be_bytes());
        expected.extend_from_slice(b"sessions");
        expected.extend_from_slice(&11u32.to_be_bytes());
        expected.extend_from_slice(b"session:abc");
        assert_eq!(payload, expected);
    }

    #[test]
    fn insert_request_payload_matches_wire_contract() {
        let mut payload = vec![OP_INSERT];
        encode_keyspace(&mut payload, "acl");
        encode_bytes(&mut payload, b"acl:did:key:zABC");
        encode_bytes(&mut payload, b"{\"role\":\"Admin\"}");

        // Op byte + u16 keyspace len + keyspace + u32 key len + key + u32 val len + val
        assert_eq!(payload[0], OP_INSERT);
        let (ks_len, rest) = payload[1..].split_at(2);
        assert_eq!(u16::from_be_bytes([ks_len[0], ks_len[1]]), 3);
        assert_eq!(&rest[..3], b"acl");
    }
}

/// Multi-step operations against a fake parent that serves the real wire
/// protocol over in-memory pipes and holds every request for a few
/// milliseconds, so concurrent round trips overlap the way they do on a busy
/// enclave. Run on a multi-thread runtime: the REST server is one.
///
/// The fake plays both proxy generations: one that serves the atomic opcodes
/// (OP_HELLO advertises them) and one that predates them (answers "unknown
/// opcode", as the real proxy's dispatcher does). Every exactly-one test runs
/// against both.
#[cfg(test)]
mod atomicity_tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    type Rows = Arc<StdMutex<HashMap<(String, Vec<u8>), Vec<u8>>>>;

    const BOTH: [bool; 2] = [false, true];
    const ALL_CAPS: u32 = CAP_TAKE | CAP_INSERT_IF_ABSENT | CAP_SWAP_IF_ABSENT | CAP_MOVE_IF_EQUAL;

    #[derive(Clone)]
    struct FakeParent {
        rows: Rows,
        /// Serves the atomic opcodes (a current proxy) or not (an old one).
        atomic: Arc<AtomicBool>,
        /// Requests served, HELLO included.
        requests: Arc<AtomicUsize>,
        /// Apply the next request with this opcode, then hang up without
        /// replying: the enclave cannot know whether it was applied.
        hang_up_after: Arc<StdMutex<Option<u8>>>,
        /// Refuse HELLO with an ordinary error (not "unknown opcode").
        refuse_hello: Arc<AtomicBool>,
        /// Write tracking shared by every handle this parent hands out, as
        /// `VsockStore` shares it across its handles.
        writes: crate::store::generation::Generations,
        /// While set, a write is received and then held, unapplied, until
        /// [`Self::release_writes`] — a parent that has the frame but has not
        /// acted on it yet.
        hold: Arc<AtomicBool>,
        gate: Arc<tokio::sync::Notify>,
        /// Writes received and currently held.
        held: Arc<AtomicUsize>,
    }

    impl FakeParent {
        fn new(atomic: bool) -> Self {
            Self {
                rows: Rows::default(),
                atomic: Arc::new(AtomicBool::new(atomic)),
                requests: Arc::new(AtomicUsize::new(0)),
                hang_up_after: Arc::default(),
                refuse_hello: Arc::default(),
                writes: Default::default(),
                hold: Arc::new(AtomicBool::new(false)),
                gate: Arc::new(tokio::sync::Notify::new()),
                held: Arc::new(AtomicUsize::new(0)),
            }
        }

        /// As [`Self::new`], with a short unknown-settle period.
        fn with_settle(atomic: bool, settle: Duration) -> Self {
            Self {
                writes: crate::store::generation::Generations::with_settle(settle),
                ..Self::new(atomic)
            }
        }

        /// A handle that can never get a frame out: its only connection is
        /// already closed and reconnecting fails — a connect error before
        /// anything is written. Shares this parent's write tracking.
        fn unreachable_handle(&self) -> VsockKeyspaceHandle {
            let (dead, peer) = tokio::io::duplex(64);
            drop(peer);
            let connect: Connector =
                Arc::new(|| Box::pin(async { Err(AppError::Internal("connect refused".into())) }));
            VsockKeyspaceHandle {
                pool: Arc::new(ConnectionPool::new(connect, 8, Box::new(dead))),
                locks: Arc::new(KeyLocks::default()),
                caps: Arc::new(Capabilities::new(ALL_CAPS, REPROBE_AFTER)),
                writes: self.writes.for_keyspace("ks"),
                keyspace: "ks".into(),
                #[cfg(feature = "encryption")]
                encryption_key: None,
            }
        }

        /// A handle on this parent whose round trips time out after
        /// `timeout` — for a write the parent holds past its deadline.
        async fn handle_timing_out_after(&self, timeout: Duration) -> VsockKeyspaceHandle {
            let parent = self.clone();
            let connect: Connector = Arc::new(move || {
                let parent = parent.clone();
                Box::pin(async move { Ok(parent.open()) })
            });
            let pool = Arc::new(ConnectionPool::new(connect, 8, self.open()).with_timeout(timeout));
            VsockKeyspaceHandle {
                pool,
                locks: Arc::new(KeyLocks::default()),
                caps: Arc::new(Capabilities::new(ALL_CAPS, REPROBE_AFTER)),
                writes: self.writes.for_keyspace("ks"),
                keyspace: "ks".into(),
                #[cfg(feature = "encryption")]
                encryption_key: None,
            }
        }

        /// A handle whose every connection accepts one byte and is then never
        /// read: a request frame can never be completely written, so each
        /// round trip times out *before* sending. Shares this parent's write
        /// tracking.
        fn unwritable_handle(&self, timeout: Duration) -> VsockKeyspaceHandle {
            fn stuck() -> BoxStream {
                let (client, peer) = tokio::io::duplex(1);
                // Kept open and never read, so writes stall instead of failing.
                std::mem::forget(peer);
                Box::new(client)
            }
            let connect: Connector = Arc::new(|| Box::pin(async { Ok(stuck()) }));
            VsockKeyspaceHandle {
                pool: Arc::new(ConnectionPool::new(connect, 8, stuck()).with_timeout(timeout)),
                locks: Arc::new(KeyLocks::default()),
                caps: Arc::new(Capabilities::new(ALL_CAPS, REPROBE_AFTER)),
                writes: self.writes.for_keyspace("ks"),
                keyspace: "ks".into(),
                #[cfg(feature = "encryption")]
                encryption_key: None,
            }
        }

        fn hold_writes(&self) {
            self.hold.store(true, Ordering::SeqCst);
        }

        fn release_writes(&self) {
            self.hold.store(false, Ordering::SeqCst);
            self.gate.notify_waiters();
        }

        /// Wait until `n` writes are being held.
        async fn until_held(&self, n: usize) {
            for _ in 0..400 {
                if self.held.load(Ordering::SeqCst) >= n {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            panic!("fake parent: {n} held write(s) never arrived");
        }

        /// The raw bytes at `key` in keyspace "ks", for waiting on a held
        /// write to land.
        fn raw(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.rows
                .lock()
                .unwrap()
                .get(&("ks".to_string(), key.to_vec()))
                .cloned()
        }

        /// A handle wired the way `VsockStore::connect` wires one, HELLO
        /// probe included.
        async fn handle(&self) -> VsockKeyspaceHandle {
            self.handle_reprobing_after(REPROBE_AFTER).await
        }

        async fn handle_reprobing_after(&self, reprobe_after: Duration) -> VsockKeyspaceHandle {
            let parent = self.clone();
            let connect: Connector = Arc::new(move || {
                let parent = parent.clone();
                Box::pin(async move { Ok(parent.open()) })
            });
            let pool = Arc::new(ConnectionPool::new(connect, 8, self.open()));
            let caps = probe_capabilities(&pool).await.expect("probe");
            VsockKeyspaceHandle {
                pool,
                locks: Arc::new(KeyLocks::default()),
                caps: Arc::new(Capabilities::new(caps, reprobe_after)),
                writes: self.writes.for_keyspace("ks"),
                keyspace: "ks".into(),
                #[cfg(feature = "encryption")]
                encryption_key: None,
            }
        }

        /// Replace the proxy with one that predates the atomic opcodes.
        fn downgrade(&self) {
            self.atomic.store(false, Ordering::SeqCst);
        }

        /// Replace it again with a proxy that serves them.
        fn upgrade(&self) {
            self.atomic.store(true, Ordering::SeqCst);
        }

        fn hang_up_after(&self, op: u8) {
            *self.hang_up_after.lock().unwrap() = Some(op);
        }

        fn requests(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }

        /// The bytes the parent holds at `key` in keyspace "ks".
        #[cfg(feature = "encryption")]
        fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.rows
                .lock()
                .unwrap()
                .get(&("ks".to_string(), key.to_vec()))
                .cloned()
        }

        #[cfg(feature = "encryption")]
        fn stored(&self) -> Vec<Vec<u8>> {
            self.rows.lock().unwrap().values().cloned().collect()
        }

        fn open(&self) -> BoxStream {
            let (client, server) = tokio::io::duplex(64 * 1024);
            tokio::spawn(self.clone().serve(server));
            Box::new(client)
        }

        async fn serve(self, mut s: DuplexStream) {
            loop {
                let Ok(len) = s.read_u32().await else { return };
                let mut req = vec![0u8; len as usize];
                if s.read_exact(&mut req).await.is_err() {
                    return;
                }
                self.requests.fetch_add(1, Ordering::SeqCst);
                if !is_read_only(&req) && self.hold.load(Ordering::SeqCst) {
                    self.held.fetch_add(1, Ordering::SeqCst);
                    loop {
                        let released = self.gate.notified();
                        tokio::pin!(released);
                        released.as_mut().enable();
                        if !self.hold.load(Ordering::SeqCst) {
                            break;
                        }
                        released.await;
                    }
                    self.held.fetch_sub(1, Ordering::SeqCst);
                }
                tokio::time::sleep(Duration::from_millis(3)).await;
                let resp = self.apply(&req);
                {
                    let mut hang_up = self.hang_up_after.lock().unwrap();
                    if *hang_up == Some(req[0]) {
                        *hang_up = None;
                        return; // applied, never answered
                    }
                }
                let mut frame = (resp.len() as u32).to_be_bytes().to_vec();
                frame.extend_from_slice(&resp);
                if s.write_all(&frame).await.is_err() {
                    return;
                }
            }
        }

        fn apply(&self, req: &[u8]) -> Vec<u8> {
            let op = req[0];
            let atomic_op = matches!(
                op,
                OP_HELLO | OP_TAKE | OP_INSERT_IF_ABSENT | OP_SWAP_IF_ABSENT | OP_MOVE_IF_EQUAL
            );
            if atomic_op && !self.atomic.load(Ordering::SeqCst) {
                // The real proxy's dispatcher, before these opcodes existed.
                let mut out = vec![STATUS_ERROR];
                encode_bytes(&mut out, format!("unknown opcode: {op:#04x}").as_bytes());
                return out;
            }
            if op == OP_HELLO && self.refuse_hello.load(Ordering::SeqCst) {
                let mut out = vec![STATUS_ERROR];
                encode_bytes(&mut out, b"internal: something broke");
                return out;
            }
            if op == OP_HELLO {
                let mut out = vec![STATUS_OK];
                out.extend_from_slice(&ALL_CAPS.to_be_bytes());
                return out;
            }

            let ks_len = u16::from_be_bytes([req[1], req[2]]) as usize;
            let ks = String::from_utf8(req[3..3 + ks_len].to_vec()).unwrap();
            let mut fields = Vec::new();
            let mut at = 3 + ks_len;
            while at < req.len() {
                let (f, next) = decode_bytes(req, at).unwrap();
                fields.push(f.to_vec());
                at = next;
            }
            let id = |k: &[u8]| (ks.clone(), k.to_vec());
            let value = |v: &[u8]| {
                let mut out = vec![STATUS_OK];
                encode_bytes(&mut out, v);
                out
            };

            // Every operation runs under the one rows lock, so the atomic
            // opcodes are atomic here as they are in the real proxy.
            let mut rows = self.rows.lock().unwrap();
            match op {
                OP_GET => match rows.get(&id(&fields[0])) {
                    Some(v) => value(v),
                    None => vec![STATUS_NOT_FOUND],
                },
                OP_INSERT => {
                    rows.insert(id(&fields[0]), fields[1].clone());
                    vec![STATUS_OK]
                }
                OP_DELETE => {
                    rows.remove(&id(&fields[0]));
                    vec![STATUS_OK]
                }
                OP_TAKE => match rows.remove(&id(&fields[0])) {
                    Some(v) => value(&v),
                    None => vec![STATUS_NOT_FOUND],
                },
                OP_INSERT_IF_ABSENT => {
                    let k = id(&fields[0]);
                    let inserted = !rows.contains_key(&k);
                    if inserted {
                        rows.insert(k, fields[1].clone());
                    }
                    vec![STATUS_OK, inserted as u8]
                }
                OP_SWAP_IF_ABSENT => {
                    let (old, new) = (id(&fields[0]), id(&fields[1]));
                    let moved = !rows.contains_key(&new);
                    if moved {
                        rows.insert(new, fields[2].clone());
                        rows.remove(&old);
                    }
                    vec![STATUS_OK, moved as u8]
                }
                OP_MOVE_IF_EQUAL => {
                    let (old, new) = (id(&fields[0]), id(&fields[2]));
                    let outcome = match rows.get(&old) {
                        None => MOVE_SOURCE_MISSING,
                        Some(current) if *current != fields[1] => MOVE_SOURCE_CHANGED,
                        Some(_) if rows.contains_key(&new) => MOVE_TARGET_EXISTS,
                        Some(_) => {
                            rows.insert(new, fields[3].clone());
                            rows.remove(&old);
                            MOVE_MOVED
                        }
                    };
                    vec![STATUS_OK, outcome]
                }
                other => panic!("fake parent: unexpected opcode {other:#04x}"),
            }
        }
    }

    const CALLERS: usize = 32;

    /// Run `CALLERS` copies of `op` at once and count how many report success.
    async fn race<F, Fut>(op: F) -> usize
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = bool> + Send + 'static,
    {
        let wins = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = (0..CALLERS)
            .map(|_| {
                let fut = op();
                let wins = wins.clone();
                tokio::spawn(async move {
                    if fut.await {
                        wins.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for t in tasks {
            t.await.unwrap();
        }
        wins.load(Ordering::SeqCst)
    }

    fn mode(atomic: bool) -> &'static str {
        if atomic {
            "atomic-opcode proxy"
        } else {
            "older proxy"
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn take_raw_under_concurrency_admits_exactly_one() {
        for atomic in BOTH {
            // A refresh token presented by many callers at once: one rotation.
            let h = FakeParent::new(atomic).handle().await;
            h.insert_raw(b"refresh:t".to_vec(), b"session".to_vec())
                .await
                .unwrap();
            let wins = race(|| {
                let h = h.clone();
                async move { h.take_raw(b"refresh:t".to_vec()).await.unwrap().is_some() }
            })
            .await;
            assert_eq!(wins, 1, "{}", mode(atomic));
            assert_eq!(h.get_raw(b"refresh:t".to_vec()).await.unwrap(), None);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn insert_if_absent_under_concurrency_admits_exactly_one() {
        for atomic in BOTH {
            let h = FakeParent::new(atomic).handle().await;
            let wins = race(|| {
                let h = h.clone();
                async move { h.insert_if_absent(b"claim".to_vec(), &1u32).await.unwrap() }
            })
            .await;
            assert_eq!(wins, 1, "{}", mode(atomic));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn insert_raw_if_absent_under_concurrency_admits_exactly_one() {
        for atomic in BOTH {
            let h = FakeParent::new(atomic).handle().await;
            let wins = race(|| {
                let h = h.clone();
                async move {
                    h.insert_raw_if_absent(b"claim".to_vec(), b"x".to_vec())
                        .await
                        .unwrap()
                }
            })
            .await;
            assert_eq!(wins, 1, "{}", mode(atomic));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn move_if_unchanged_under_concurrency_admits_exactly_one() {
        for atomic in BOTH {
            let h = FakeParent::new(atomic).handle().await;
            let current = serde_json::to_vec(&"v1").unwrap();
            h.insert(b"old".to_vec(), &"v1").await.unwrap();
            let wins = race(|| {
                let h = h.clone();
                let expected = current.clone();
                async move {
                    h.move_if_unchanged(b"old".to_vec(), expected, b"new".to_vec(), &"v2")
                        .await
                        .unwrap()
                        == super::super::MoveOutcome::Moved
                }
            })
            .await;
            assert_eq!(wins, 1, "{}", mode(atomic));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn swap_under_concurrency_admits_exactly_one() {
        for atomic in BOTH {
            let h = FakeParent::new(atomic).handle().await;
            h.insert(b"old".to_vec(), &"v").await.unwrap();
            let wins = race(|| {
                let h = h.clone();
                async move {
                    h.swap(b"old".to_vec(), b"new".to_vec(), &"v")
                        .await
                        .unwrap()
                }
            })
            .await;
            assert_eq!(wins, 1, "{}", mode(atomic));
        }
    }

    #[tokio::test]
    async fn move_if_unchanged_reports_every_outcome_in_both_modes() {
        use super::super::MoveOutcome::*;
        for atomic in BOTH {
            let parent = FakeParent::new(atomic);
            let h = parent.handle().await;
            let v1 = serde_json::to_vec(&"v1").unwrap();
            let mv = |expected: Vec<u8>| {
                let h = h.clone();
                async move {
                    h.move_if_unchanged(b"old".to_vec(), expected, b"new".to_vec(), &"v2")
                        .await
                        .unwrap()
                }
            };
            assert_eq!(mv(v1.clone()).await, SourceMissing, "{}", mode(atomic));
            h.insert(b"old".to_vec(), &"v1").await.unwrap();
            assert_eq!(
                mv(serde_json::to_vec(&"other").unwrap()).await,
                SourceChanged,
                "{}",
                mode(atomic)
            );
            h.insert(b"new".to_vec(), &"taken").await.unwrap();
            assert_eq!(mv(v1.clone()).await, TargetExists, "{}", mode(atomic));
            h.remove(b"new".to_vec()).await.unwrap();
            assert_eq!(mv(v1).await, Moved, "{}", mode(atomic));
            assert_eq!(
                h.get::<String>(b"new".to_vec()).await.unwrap().as_deref(),
                Some("v2")
            );
            assert_eq!(h.get_raw(b"old".to_vec()).await.unwrap(), None);
        }
    }

    /// Round trips each multi-step operation costs, older proxy vs current.
    #[tokio::test]
    async fn atomic_opcodes_cut_round_trips() {
        async fn counts(atomic: bool) -> [usize; 4] {
            let parent = FakeParent::new(atomic);
            let h = parent.handle().await;
            h.insert_raw(b"t".to_vec(), b"x".to_vec()).await.unwrap();
            h.insert(b"old".to_vec(), &"v1").await.unwrap();
            h.insert(b"a".to_vec(), &"v").await.unwrap();

            let mut n = parent.requests();
            let mut step = || {
                let now = parent.requests();
                let d = now - n;
                n = now;
                d
            };
            h.take_raw(b"t".to_vec()).await.unwrap();
            let take = step();
            h.insert_if_absent(b"claim".to_vec(), &1u32).await.unwrap();
            let insert = step();
            h.swap(b"a".to_vec(), b"b".to_vec(), &"v").await.unwrap();
            let swap = step();
            let expected = serde_json::to_vec(&"v1").unwrap();
            h.move_if_unchanged(b"old".to_vec(), expected, b"new".to_vec(), &"v2")
                .await
                .unwrap();
            let mv = step();
            [take, insert, swap, mv]
        }
        // take, insert-if-absent, swap, compare-and-move
        assert_eq!(counts(false).await, [2, 2, 3, 4]);
        assert_eq!(counts(true).await, [1, 1, 1, 2]);
    }

    #[tokio::test]
    async fn an_older_proxy_is_probed_as_having_no_atomic_opcodes() {
        let h = FakeParent::new(false).handle().await;
        assert_eq!(h.caps.bits.load(Ordering::SeqCst), 0);
        let h = FakeParent::new(true).handle().await;
        assert_eq!(h.caps.bits.load(Ordering::SeqCst), ALL_CAPS);
    }

    /// The proxy replaced by an older build while the enclave runs: the
    /// operation that meets "unknown opcode" falls back and still succeeds,
    /// and later ones go straight to single operations.
    #[tokio::test]
    async fn a_downgraded_proxy_falls_back_without_failing() {
        let parent = FakeParent::new(true);
        let h = parent.handle().await;
        h.insert_raw(b"t".to_vec(), b"session".to_vec())
            .await
            .unwrap();
        parent.downgrade();

        assert_eq!(
            h.take_raw(b"t".to_vec()).await.unwrap(),
            Some(b"session".to_vec())
        );
        assert_eq!(
            h.caps.bits.load(Ordering::SeqCst),
            0,
            "capabilities cleared"
        );
        assert_eq!(h.get_raw(b"t".to_vec()).await.unwrap(), None);

        let before = parent.requests();
        assert!(h.insert_if_absent(b"claim".to_vec(), &1u32).await.unwrap());
        assert_eq!(parent.requests() - before, 2, "no atomic opcode attempted");
    }

    /// The parent stores, compares and moves ciphertext only.
    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn the_parent_never_sees_plaintext() {
        for atomic in BOTH {
            let parent = FakeParent::new(atomic);
            let h = parent.handle().await.with_encryption([7u8; 32]);
            h.insert(b"old".to_vec(), &"secret-v1").await.unwrap();
            let expected = serde_json::to_vec(&"secret-v1").unwrap();
            assert_eq!(
                h.move_if_unchanged(b"old".to_vec(), expected, b"new".to_vec(), &"secret-v2")
                    .await
                    .unwrap(),
                super::super::MoveOutcome::Moved,
                "{}",
                mode(atomic)
            );
            h.insert_raw(b"t".to_vec(), b"secret-token".to_vec())
                .await
                .unwrap();
            assert!(
                h.insert_raw_if_absent(b"c".to_vec(), b"secret-claim".to_vec())
                    .await
                    .unwrap()
            );
            for row in parent.stored() {
                assert!(
                    !row.windows(6).any(|w| w == b"secret"),
                    "{}: plaintext reached the parent",
                    mode(atomic)
                );
            }
            assert_eq!(
                h.get::<String>(b"new".to_vec()).await.unwrap().as_deref(),
                Some("secret-v2")
            );
            assert_eq!(
                h.take_raw(b"t".to_vec()).await.unwrap(),
                Some(b"secret-token".to_vec())
            );
        }
    }

    /// A take whose value the enclave cannot decrypt (here: the wrong storage
    /// key) fails without destroying the row, in both modes: the row the
    /// parent deleted is put back byte for byte.
    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn an_undecryptable_take_leaves_the_row_byte_identical() {
        for atomic in BOTH {
            let parent = FakeParent::new(atomic);
            let writer = parent.handle().await.with_encryption([1u8; 32]);
            writer
                .insert_raw(b"refresh:t".to_vec(), b"session".to_vec())
                .await
                .unwrap();
            let before = parent.row(b"refresh:t").expect("written");

            let misconfigured = parent.handle().await.with_encryption([2u8; 32]);
            assert!(
                misconfigured.take_raw(b"refresh:t".to_vec()).await.is_err(),
                "{}: the decrypt error is returned",
                mode(atomic)
            );
            assert_eq!(
                parent.row(b"refresh:t"),
                Some(before),
                "{}: the row survives, byte-identical",
                mode(atomic)
            );
            // And the right key still claims it, once.
            assert_eq!(
                writer.take_raw(b"refresh:t".to_vec()).await.unwrap(),
                Some(b"session".to_vec())
            );
        }
    }

    /// Round trips with encryption on: a successful take is still one; a take
    /// that fails to decrypt costs one more, the restore.
    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn take_round_trips_on_success_and_on_restore() {
        let parent = FakeParent::new(true);
        let h = parent.handle().await.with_encryption([1u8; 32]);
        h.insert_raw(b"a".to_vec(), b"x".to_vec()).await.unwrap();
        h.insert_raw(b"b".to_vec(), b"x".to_vec()).await.unwrap();

        let n = parent.requests();
        assert_eq!(
            h.take_raw(b"a".to_vec()).await.unwrap(),
            Some(b"x".to_vec())
        );
        assert_eq!(parent.requests() - n, 1, "happy path: OP_TAKE only");

        let wrong = parent.handle().await.with_encryption([2u8; 32]);
        let n = parent.requests();
        assert!(wrong.take_raw(b"b".to_vec()).await.is_err());
        assert_eq!(
            parent.requests() - n,
            2,
            "restore path: OP_TAKE, then OP_INSERT_IF_ABSENT"
        );
    }

    /// OP_TAKE applied, then the connection drops before the reply: the
    /// enclave gets an error, the request is not resent and no single-op
    /// fallback runs (either would make a legitimate claim find nothing), and
    /// the take happened exactly once.
    #[tokio::test]
    async fn an_atomic_take_with_an_unknown_outcome_is_not_resent() {
        let parent = FakeParent::new(true);
        let h = parent.handle().await;
        h.insert_raw(b"refresh:t".to_vec(), b"session".to_vec())
            .await
            .unwrap();
        parent.hang_up_after(OP_TAKE);

        let n = parent.requests();
        let err = h.take_raw(b"refresh:t".to_vec()).await.unwrap_err();
        assert!(err.to_string().contains("outcome unknown"), "{err}");
        assert_eq!(
            parent.requests() - n,
            1,
            "one frame: no resend, no fallback"
        );
        assert_eq!(
            h.get_raw(b"refresh:t".to_vec()).await.unwrap(),
            None,
            "applied once"
        );
    }

    #[tokio::test]
    async fn an_atomic_swap_with_an_unknown_outcome_is_not_resent() {
        let parent = FakeParent::new(true);
        let h = parent.handle().await;
        h.insert(b"old".to_vec(), &"v").await.unwrap();
        parent.hang_up_after(OP_SWAP_IF_ABSENT);

        let n = parent.requests();
        let err = h
            .swap(b"old".to_vec(), b"new".to_vec(), &"v")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("outcome unknown"), "{err}");
        assert_eq!(
            parent.requests() - n,
            1,
            "one frame: no resend, no fallback"
        );
        // A resend would have found `new` occupied and reported a refusal for
        // a move that happened. It happened once.
        assert_eq!(h.get_raw(b"old".to_vec()).await.unwrap(), None);
        assert!(h.get_raw(b"new".to_vec()).await.unwrap().is_some());
    }

    /// HELLO refused for any reason but "unknown opcode" fails the probe,
    /// and so the connect: a proxy that cannot answer it is not one to guess
    /// about.
    #[tokio::test]
    async fn hello_refused_otherwise_fails_the_probe() {
        let parent = FakeParent::new(true);
        parent.refuse_hello.store(true, Ordering::SeqCst);
        let connect: Connector = {
            let parent = parent.clone();
            Arc::new(move || {
                let parent = parent.clone();
                Box::pin(async move { Ok(parent.open()) })
            })
        };
        let pool = ConnectionPool::new(connect, 2, parent.open());
        let err = probe_capabilities(&pool).await.unwrap_err();
        assert!(err.to_string().contains("something broke"), "{err}");
    }

    /// A proxy downgraded and then upgraded again is used atomically again
    /// once the re-probe is due — not only after an enclave restart.
    #[tokio::test]
    async fn a_downgraded_proxy_is_re_probed_and_used_again() {
        let parent = FakeParent::new(true);
        let h = parent.handle_reprobing_after(Duration::ZERO).await;
        parent.downgrade();
        assert!(h.insert_if_absent(b"a".to_vec(), &1u32).await.unwrap());
        assert_eq!(h.caps.bits.load(Ordering::SeqCst), 0);

        parent.upgrade();
        let n = parent.requests();
        assert!(h.insert_if_absent(b"b".to_vec(), &1u32).await.unwrap());
        assert_eq!(parent.requests() - n, 2, "HELLO, then the atomic op");
        assert_eq!(h.caps.bits.load(Ordering::SeqCst), ALL_CAPS);

        let n = parent.requests();
        assert!(h.insert_if_absent(b"c".to_vec(), &1u32).await.unwrap());
        assert_eq!(parent.requests() - n, 1, "atomic again, no re-probe");
    }

    #[tokio::test]
    async fn no_re_probe_before_it_is_due() {
        let parent = FakeParent::new(true);
        let h = parent.handle().await; // REPROBE_AFTER: a minute
        parent.downgrade();
        assert!(h.insert_if_absent(b"a".to_vec(), &1u32).await.unwrap());
        parent.upgrade();
        let n = parent.requests();
        assert!(h.insert_if_absent(b"b".to_vec(), &1u32).await.unwrap());
        assert_eq!(parent.requests() - n, 2, "single ops, no HELLO yet");
        assert_eq!(h.caps.bits.load(Ordering::SeqCst), 0);
    }

    /// Control: the same harness catches the race the locks close. Without
    /// a lock, a read-then-delete claim is won by more than one caller.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn harness_detects_an_unlocked_claim() {
        let h = FakeParent::new(false).handle().await;
        h.insert_raw(b"refresh:t".to_vec(), b"session".to_vec())
            .await
            .unwrap();
        let wins = race(|| {
            let h = h.clone();
            async move {
                let v = h.get_raw(b"refresh:t".to_vec()).await.unwrap();
                if v.is_some() {
                    h.remove(b"refresh:t".to_vec()).await.unwrap();
                }
                v.is_some()
            }
        })
        .await;
        assert!(
            wins > 1,
            "unlocked read-then-delete should double-claim here, got {wins}"
        );
    }

    // ── The audit-key cache over vsock ──────────────────────────────────
    //
    // `AuditKeyStore` caches the active key under the keyspace's write
    // tracking. Over vsock every request goes through `send`; these prove
    // each write path — single operations, every atomic opcode, each one's
    // fallback, and the restore after an undecryptable take — retires a
    // cached key, and that a write the parent applies after its writer gave
    // up can never leave the old key cached.

    use crate::audit::{AuditKey, AuditKeyStore, KeyId, RotationReason};
    use crate::store::{KeyspaceHandle, MoveOutcome};

    const MARKER: &[u8] = b"audit_key:active";

    /// An `AuditKeyStore` over its own handle on `parent`, with the key
    /// established and cached: a second `active` reads nothing.
    async fn cached_keys(parent: &FakeParent) -> AuditKeyStore {
        let keys = AuditKeyStore::new(KeyspaceHandle::Vsock(parent.handle().await));
        keys.ensure_initial(&[9u8; 32]).await.unwrap();
        keys.active().await.unwrap();
        let n = parent.requests();
        keys.active().await.unwrap();
        assert_eq!(parent.requests(), n, "warm: a hit reads nothing");
        keys
    }

    /// The next `active` went to the parent: the cache was retired.
    async fn assert_retired(parent: &FakeParent, keys: &AuditKeyStore, path: &str, atomic: bool) {
        let n = parent.requests();
        keys.active().await.unwrap();
        assert!(
            parent.requests() > n,
            "{path} ({}) left the cached key in place",
            mode(atomic)
        );
    }

    /// Every write path the store can send, through a *different* handle than
    /// the cache's, on both proxy generations (atomic opcodes and the
    /// single-operation fallbacks).
    #[tokio::test]
    async fn every_vsock_write_path_retires_the_cached_key() {
        type Op = for<'a> fn(
            &'a VsockKeyspaceHandle,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = ()> + Send + 'a>,
        >;
        let paths: [(&str, Op); 8] = [
            ("insert", |w| {
                Box::pin(async { w.insert(b"p:ins".to_vec(), &"v").await.unwrap() })
            }),
            ("insert_raw", |w| {
                Box::pin(async {
                    w.insert_raw(b"p:raw".to_vec(), b"v".to_vec())
                        .await
                        .unwrap()
                })
            }),
            ("remove", |w| {
                Box::pin(async { w.remove(b"p:seed".to_vec()).await.unwrap() })
            }),
            ("insert_if_absent", |w| {
                Box::pin(async {
                    assert!(w.insert_if_absent(b"p:iia".to_vec(), &"v").await.unwrap());
                })
            }),
            ("insert_raw_if_absent", |w| {
                Box::pin(async {
                    assert!(
                        w.insert_raw_if_absent(b"p:iria".to_vec(), b"v".to_vec())
                            .await
                            .unwrap()
                    );
                })
            }),
            ("take_raw", |w| {
                Box::pin(async {
                    assert!(w.take_raw(b"p:seed".to_vec()).await.unwrap().is_some());
                })
            }),
            ("swap", |w| {
                Box::pin(async {
                    assert!(
                        w.swap(b"p:seed".to_vec(), b"p:swapped".to_vec(), &"v")
                            .await
                            .unwrap()
                    );
                })
            }),
            ("move_if_unchanged", |w| {
                Box::pin(async {
                    let outcome = w
                        .move_if_unchanged(
                            b"p:seed".to_vec(),
                            b"seed".to_vec(),
                            b"p:moved".to_vec(),
                            &"v",
                        )
                        .await
                        .unwrap();
                    assert!(matches!(outcome, MoveOutcome::Moved), "{outcome:?}");
                })
            }),
        ];
        for atomic in BOTH {
            for (path, op) in paths {
                let parent = FakeParent::new(atomic);
                let writer = parent.handle().await;
                writer
                    .insert_raw(b"p:seed".to_vec(), b"seed".to_vec())
                    .await
                    .unwrap();
                let keys = cached_keys(&parent).await;
                op(&writer).await;
                assert_retired(&parent, &keys, path, atomic).await;
            }
        }
    }

    /// Only what is sent counts. Taking an absent key on an older proxy is a
    /// lone GET — nothing written, so the cached key stays (correctly). On a
    /// current proxy it is an OP_TAKE request, tracked as a write whatever it
    /// found.
    #[tokio::test]
    async fn an_absent_take_retires_the_cache_only_when_it_sends_a_write() {
        for atomic in BOTH {
            let parent = FakeParent::new(atomic);
            let writer = parent.handle().await;
            let keys = cached_keys(&parent).await;
            assert!(writer.take_raw(b"p:none".to_vec()).await.unwrap().is_none());
            let n = parent.requests();
            keys.active().await.unwrap();
            assert_eq!(
                parent.requests() > n,
                atomic,
                "{}: an absent take retires the cache iff it sent OP_TAKE",
                mode(atomic)
            );
        }
    }

    /// The restore after an undecryptable OP_TAKE is a write of its own
    /// (OP_INSERT_IF_ABSENT): two tracked writes, each moving the generation
    /// twice (begin and end), and the cached key retired.
    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn the_restore_after_an_undecryptable_take_is_tracked() {
        let parent = FakeParent::new(true);
        let writer = parent.handle().await.with_encryption([1u8; 32]);
        writer
            .insert_raw(b"victim".to_vec(), b"x".to_vec())
            .await
            .unwrap();
        let keys = cached_keys(&parent).await;
        let probe = KeyspaceHandle::Vsock(parent.handle().await);
        let before = probe.cache_ticket().expect("idle");

        let wrong = parent.handle().await.with_encryption([2u8; 32]);
        let n = parent.requests();
        assert!(wrong.take_raw(b"victim".to_vec()).await.is_err());
        assert_eq!(parent.requests() - n, 2, "OP_TAKE, then the restore");

        let after = probe.cache_ticket().expect("idle");
        assert_eq!(after - before, 4, "both requests tracked as writes");
        assert_retired(&parent, &keys, "restore", true).await;
    }

    /// The gap the tracking closes: a rotation's marker write reaches the
    /// parent, its writer gives up (the future is dropped), and the parent
    /// applies it afterwards. Nothing read in between is cached, so the read
    /// after the parent applies it sees the new key — not the old one, cached
    /// under a generation that has already moved.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_rotation_applied_after_its_writer_gave_up_is_never_cached_stale() {
        for atomic in BOTH {
            let parent = FakeParent::new(atomic);
            let keys = cached_keys(&parent).await;
            let old = keys.active().await.unwrap();

            // The successor key row lands normally; only the marker flip is
            // abandoned.
            let new = AuditKey {
                key_id: KeyId::new(),
                key: [2u8; 32],
                valid_from: chrono::Utc::now(),
                valid_until: None,
                rotation_reason: RotationReason::Manual,
            };
            let writer = parent.handle().await;
            writer
                .insert(format!("audit_key:{}", new.key_id.0).into_bytes(), &new)
                .await
                .unwrap();
            assert_eq!(keys.active().await.unwrap().key_id, old.key_id);

            parent.hold_writes();
            let flip = writer.insert_raw(MARKER.to_vec(), new.key_id.0.to_string().into_bytes());
            let gave_up = tokio::time::timeout(Duration::from_millis(100), async {
                tokio::join!(flip, parent.until_held(1)).0
            })
            .await;
            assert!(gave_up.is_err(), "the writer gave up with the write held");

            // In the gap the old key is still what the parent holds; it may
            // be read, but must not be cached.
            assert_eq!(keys.active().await.unwrap().key_id, old.key_id);

            // The parent applies the abandoned write.
            parent.release_writes();
            for _ in 0..400 {
                if parent.raw(MARKER) == Some(new.key_id.0.to_string().into_bytes()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(
                keys.active().await.unwrap().key_id,
                new.key_id,
                "{}: the old key was served after the parent applied the rotation",
                mode(atomic)
            );

            // Caching resumes once a later write completes.
            writer
                .insert_raw(b"later".to_vec(), b"x".to_vec())
                .await
                .unwrap();
            keys.active().await.unwrap();
            let n = parent.requests();
            keys.active().await.unwrap();
            assert_eq!(parent.requests(), n, "cached again after a known write");
        }
    }

    /// While a write is in flight every read goes through and nothing is
    /// cached; once it completes, caching resumes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_write_in_flight_suppresses_caching() {
        let parent = FakeParent::new(true);
        let keys = cached_keys(&parent).await;
        let writer = parent.handle().await;

        parent.hold_writes();
        let pending = tokio::spawn(async move {
            writer
                .insert_raw(b"slow".to_vec(), b"x".to_vec())
                .await
                .unwrap();
        });
        parent.until_held(1).await;

        for _ in 0..2 {
            let n = parent.requests();
            keys.active().await.unwrap();
            assert!(
                parent.requests() > n,
                "read through while a write is in flight"
            );
        }

        parent.release_writes();
        pending.await.unwrap();
        keys.active().await.unwrap();
        let n = parent.requests();
        keys.active().await.unwrap();
        assert_eq!(parent.requests(), n, "cached again once it completed");
    }

    /// Whether `keys` caches again: a re-read, then a hit that reads nothing.
    async fn caches_again(parent: &FakeParent, keys: &AuditKeyStore) -> bool {
        keys.active().await.unwrap();
        let n = parent.requests();
        keys.active().await.unwrap();
        parent.requests() == n
    }

    /// A write that fails before its frame leaves — no connection to be had —
    /// cannot have been applied: a known outcome, not an unknown one. On a
    /// keyspace written once in weeks (`audit_key`), treating it as unknown
    /// would switch the cache off until the next write. Both pool paths: a
    /// plain insert and an atomic opcode.
    #[tokio::test]
    async fn a_write_that_never_left_does_not_disable_caching() {
        let parent = FakeParent::new(true);
        let keys = cached_keys(&parent).await;
        let dead = parent.unreachable_handle();

        assert!(dead.insert_raw(b"x".to_vec(), b"v".to_vec()).await.is_err());
        assert!(caches_again(&parent, &keys).await, "plain insert");

        assert!(
            dead.insert_raw_if_absent(b"y".to_vec(), b"v".to_vec())
                .await
                .is_err()
        );
        assert!(caches_again(&parent, &keys).await, "atomic opcode");
    }

    /// A write whose frame left and got no reply is unknown: caching stays
    /// off — until a later write completes, or the mark settles on its own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_after_send_unknown_disables_caching_until_it_settles() {
        let settle = Duration::from_millis(300);
        let parent = FakeParent::with_settle(true, settle);
        let keys = cached_keys(&parent).await;
        let writer = parent.handle().await;

        // The parent applies the atomic insert, then hangs up: the enclave
        // gets "outcome unknown".
        parent.hang_up_after(OP_INSERT_IF_ABSENT);
        assert!(
            writer
                .insert_raw_if_absent(b"z".to_vec(), b"v".to_vec())
                .await
                .is_err()
        );
        assert!(!caches_again(&parent, &keys).await, "unknown: read through");
        assert!(!caches_again(&parent, &keys).await, "still unknown");

        tokio::time::sleep(settle + Duration::from_millis(100)).await;
        assert!(caches_again(&parent, &keys).await, "settled: caching again");
    }

    /// The pool's per-round-trip deadline, expiring *after* the frame left:
    /// the parent holds the write, the enclave gives up. The parent may still
    /// apply it, so caching is off — both pool paths.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_timeout_after_the_frame_was_sent_disables_caching() {
        for (path, atomic_op) in [("plain insert", false), ("atomic opcode", true)] {
            let parent = FakeParent::new(true);
            let keys = cached_keys(&parent).await;
            let writer = parent
                .handle_timing_out_after(Duration::from_millis(100))
                .await;

            parent.hold_writes();
            let failed = if atomic_op {
                writer
                    .insert_raw_if_absent(b"late".to_vec(), b"v".to_vec())
                    .await
                    .is_err()
            } else {
                writer
                    .insert_raw(b"late".to_vec(), b"v".to_vec())
                    .await
                    .is_err()
            };
            assert!(failed, "{path}: the deadline expired");
            assert!(
                !caches_again(&parent, &keys).await,
                "{path}: a timeout after sending is an unknown outcome"
            );
            parent.release_writes();
        }
    }

    /// The deadline expiring *before* the frame was completely written: the
    /// parent cannot act on a partial frame, so the outcome is known (not
    /// applied) and caching stays on — both pool paths.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_timeout_before_the_frame_was_sent_does_not_disable_caching() {
        let parent = FakeParent::new(true);
        let keys = cached_keys(&parent).await;
        let stuck = parent.unwritable_handle(Duration::from_millis(100));

        assert!(
            stuck
                .insert_raw(b"x".to_vec(), b"v".to_vec())
                .await
                .is_err()
        );
        assert!(caches_again(&parent, &keys).await, "plain insert");

        assert!(
            stuck
                .insert_raw_if_absent(b"y".to_vec(), b"v".to_vec())
                .await
                .is_err()
        );
        assert!(caches_again(&parent, &keys).await, "atomic opcode");
    }
}
