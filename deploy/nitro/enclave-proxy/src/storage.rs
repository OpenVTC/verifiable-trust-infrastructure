//! Parent-side persistent key-value storage server.
//!
//! Listens on a vsock port and serves K/V operations backed by fjall on the
//! parent EC2 instance's EBS volume.
//!
//! All data from the enclave is already encrypted (AES-256-GCM) before it
//! reaches this server — the parent only stores opaque blobs.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode, Readable};
use tokio::sync::RwLock;
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};
use tracing::{debug, error, info, warn};

use crate::protocol::*;

/// Run the parent-side storage server.
///
/// Opens a fjall database at `data_dir` and listens for K/V operations on
/// the given vsock port.
pub async fn run_storage(vsock_port: u32, data_dir: PathBuf) {
    // Open the fjall database on the parent's EBS volume
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        error!(
            "[storage] failed to create data directory {}: {e}",
            data_dir.display()
        );
        return;
    }

    let db = match Database::builder(&data_dir).open() {
        Ok(db) => db,
        Err(e) => {
            error!(
                "[storage] failed to open fjall database at {}: {e}",
                data_dir.display()
            );
            return;
        }
    };

    info!("[storage] opened database at {}", data_dir.display());

    // On startup, check if a DID log was previously stored and write it to disk.
    // This ensures the file is always available even after proxy restarts.
    //
    // The key is spelled out rather than imported: this proxy runs on the
    // *parent* and deliberately does not link enclave code. Canonical
    // definition is `vta_tee::did_autogen::DID_LOG_STORE_KEY` — keep in sync.
    if let Ok(ks) = db.keyspace("bootstrap", KeyspaceCreateOptions::default)
        && let Ok(Some(value)) = ks.get("tee:did_log")
    {
        write_did_log_file(&data_dir, &value);
    }

    let state = Arc::new(StorageState {
        db,
        keyspaces: RwLock::new(HashMap::new()),
        data_dir: data_dir.clone(),
        #[cfg(test)]
        batch_commits: Default::default(),
        #[cfg(test)]
        critical_delay_ms: Default::default(),
        #[cfg(test)]
        reached_lock: Default::default(),
    });

    let listener = match VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port)) {
        Ok(l) => l,
        Err(e) => {
            error!("[storage] failed to bind vsock:{vsock_port}: {e}");
            return;
        }
    };

    info!("[storage] listening on vsock:{vsock_port}");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("[storage] accept error: {e}");
                continue;
            }
        };
        info!("[storage] connection from vsock peer {peer:?}");

        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &state).await {
                debug!("[storage] connection ended: {e}");
            }
        });
    }
}

struct StorageState {
    db: Database,
    keyspaces: RwLock<HashMap<String, KeyspaceEntry>>,
    data_dir: PathBuf,
    /// Moves committed as one write batch (tests assert the batch path).
    #[cfg(test)]
    batch_commits: std::sync::atomic::AtomicUsize,
    /// Extra time each atomic operation holds its keyspace lock, so a test
    /// can make contention real.
    #[cfg(test)]
    critical_delay_ms: std::sync::atomic::AtomicU64,
    /// Atomic operations that have reached their keyspace lock (holding it
    /// or waiting for it).
    #[cfg(test)]
    reached_lock: std::sync::atomic::AtomicUsize,
}

/// A keyspace and the lock its atomic operations hold.
///
/// fjall makes each operation atomic, not a sequence of them, and every
/// connection is served on its own task, so OP_TAKE, OP_INSERT_IF_ABSENT,
/// OP_SWAP_IF_ABSENT and OP_MOVE_IF_EQUAL hold this across their steps, on
/// the blocking pool (see [`critical_section`]). A plain mutex rather than
/// fjall's transactional database: the critical sections are a few fjall
/// calls with no await inside, and switching the database type would touch
/// every operation for no gain. Plain get/insert/delete do not take it: the
/// enclave is the only writer, and it holds its own lock on a key across
/// every operation that touches it, plain or atomic, so a plain write to a
/// key never arrives while an atomic operation on that key is in flight.
#[derive(Clone)]
struct KeyspaceEntry {
    ks: Keyspace,
    lock: Arc<Mutex<()>>,
}

impl KeyspaceEntry {
    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        // Poisoning carries no meaning here: every critical section re-reads
        // the rows it decides on.
        self.lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl StorageState {
    #[cfg(test)]
    fn hold_critical_section(&self) {
        let ms = self
            .critical_delay_ms
            .load(std::sync::atomic::Ordering::SeqCst);
        if ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }

    /// Get or create a keyspace by name.
    async fn get_keyspace(&self, name: &str) -> Result<Keyspace, String> {
        Ok(self.entry(name).await?.ks)
    }

    /// Get or create a keyspace by name, with its lock.
    async fn entry(&self, name: &str) -> Result<KeyspaceEntry, String> {
        // Fast path: read lock
        {
            let ks_map = self.keyspaces.read().await;
            if let Some(entry) = ks_map.get(name) {
                return Ok(entry.clone());
            }
        }

        // Slow path: write lock + create
        let mut ks_map = self.keyspaces.write().await;
        if let Some(entry) = ks_map.get(name) {
            return Ok(entry.clone());
        }

        let ks = self
            .db
            .keyspace(name, KeyspaceCreateOptions::default)
            .map_err(|e| format!("failed to create keyspace '{name}': {e}"))?;
        let entry = KeyspaceEntry {
            ks,
            lock: Arc::new(Mutex::new(())),
        };
        ks_map.insert(name.to_string(), entry.clone());
        debug!("[storage] created keyspace: {name}");
        Ok(entry)
    }
}

/// Handle a single client connection (long-lived, multiple requests).
async fn handle_connection(
    mut stream: tokio_vsock::VsockStream,
    state: &Arc<StorageState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        // Read request frame
        let request = match read_frame(&mut stream).await {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(()); // Clean disconnect
            }
            Err(e) => return Err(e.into()),
        };

        if request.is_empty() {
            write_frame(&mut stream, &build_error("empty request")).await?;
            continue;
        }

        let opcode = request[0];
        let response = match opcode {
            OP_GET => handle_get(state, &request[1..]).await,
            OP_INSERT => handle_insert(state, &request[1..]).await,
            OP_DELETE => handle_delete(state, &request[1..]).await,
            OP_PREFIX_ITER => handle_prefix_iter(state, &request[1..]).await,
            OP_PREFIX_KEYS => handle_prefix_keys(state, &request[1..]).await,
            OP_SCAN => handle_scan(state, &request[1..]).await,
            OP_PERSIST => handle_persist(state).await,
            OP_HELLO => build_ok_u32(CAPABILITIES),
            OP_TAKE => handle_take(state, &request[1..]).await,
            OP_INSERT_IF_ABSENT => handle_insert_if_absent(state, &request[1..]).await,
            OP_SWAP_IF_ABSENT => handle_swap_if_absent(state, &request[1..]).await,
            OP_MOVE_IF_EQUAL => handle_move_if_equal(state, &request[1..]).await,
            OP_APPLY_BATCH => handle_apply_batch(state, &request[1..]).await,
            _ => build_error(&format!("unknown opcode: {opcode:#04x}")),
        };

        write_frame(&mut stream, &response).await?;
    }
}

// ---------------------------------------------------------------------------
// Operation handlers
// ---------------------------------------------------------------------------

async fn handle_get(state: &StorageState, data: &[u8]) -> Vec<u8> {
    let result: Result<_, String> = (|| {
        let (ks_name, offset) = decode_keyspace(data, 0)?;
        let (key, _) = decode_bytes(data, offset)?;
        Ok((ks_name.to_string(), key.to_vec()))
    })();

    let (ks_name, key) = match result {
        Ok(v) => v,
        Err(e) => return build_error(&format!("invalid get request: {e}")),
    };

    let ks = match state.get_keyspace(&ks_name).await {
        Ok(ks) => ks,
        Err(e) => return build_error(&e),
    };

    match ks.get(&key) {
        Ok(Some(value)) => build_ok_value(&value),
        Ok(None) => build_not_found(),
        Err(e) => build_error(&format!("get failed: {e}")),
    }
}

/// Write the DID log to a file alongside the database for easy operator access.
fn write_did_log_file(data_dir: &Path, value: &[u8]) {
    // Write to the parent directory of the store (e.g., /mnt/vta-data/did.jsonl)
    let output_path = data_dir.parent().unwrap_or(data_dir).join("did.jsonl");
    match std::fs::write(&output_path, value) {
        Ok(()) => info!("[storage] wrote DID log to {}", output_path.display()),
        Err(e) => warn!(
            "[storage] failed to write DID log to {}: {e}",
            output_path.display()
        ),
    }
}

/// Side effects of a value landing at a key, for every operation that
/// writes one.
///
/// When the VTA writes its auto-generated DID log to the bootstrap keyspace,
/// also write it to disk so the operator can retrieve it without needing REST
/// enabled. Key mirrors `vta_tee::did_autogen::DID_LOG_STORE_KEY` (see the
/// startup read above for why it is not imported).
fn after_insert(state: &StorageState, ks_name: &str, key: &[u8], value: &[u8]) {
    if ks_name == "bootstrap" && key == b"tee:did_log" {
        write_did_log_file(&state.data_dir, value);
    }
}

async fn handle_insert(state: &StorageState, data: &[u8]) -> Vec<u8> {
    let result: Result<_, String> = (|| {
        let (ks_name, offset) = decode_keyspace(data, 0)?;
        let (key, offset) = decode_bytes(data, offset)?;
        let (value, _) = decode_bytes(data, offset)?;
        Ok((ks_name.to_string(), key.to_vec(), value.to_vec()))
    })();

    let (ks_name, key, value) = match result {
        Ok(v) => v,
        Err(e) => return build_error(&format!("invalid insert request: {e}")),
    };

    let ks = match state.get_keyspace(&ks_name).await {
        Ok(ks) => ks,
        Err(e) => return build_error(&e),
    };

    match ks.insert(&key, &value) {
        Ok(()) => {
            after_insert(state, &ks_name, &key, &value);
            build_ok_empty()
        }
        Err(e) => build_error(&format!("insert failed: {e}")),
    }
}

async fn handle_delete(state: &StorageState, data: &[u8]) -> Vec<u8> {
    let result: Result<_, String> = (|| {
        let (ks_name, offset) = decode_keyspace(data, 0)?;
        let (key, _) = decode_bytes(data, offset)?;
        Ok((ks_name.to_string(), key.to_vec()))
    })();

    let (ks_name, key) = match result {
        Ok(v) => v,
        Err(e) => return build_error(&format!("invalid delete request: {e}")),
    };

    let ks = match state.get_keyspace(&ks_name).await {
        Ok(ks) => ks,
        Err(e) => return build_error(&e),
    };

    match ks.remove(&key) {
        Ok(()) => build_ok_empty(),
        Err(e) => build_error(&format!("delete failed: {e}")),
    }
}

async fn handle_prefix_iter(state: &StorageState, data: &[u8]) -> Vec<u8> {
    let result: Result<_, String> = (|| {
        let (ks_name, offset) = decode_keyspace(data, 0)?;
        let (prefix, _) = decode_bytes(data, offset)?;
        Ok((ks_name.to_string(), prefix.to_vec()))
    })();

    let (ks_name, prefix) = match result {
        Ok(v) => v,
        Err(e) => return build_error(&format!("invalid prefix_iter request: {e}")),
    };

    let ks = match state.get_keyspace(&ks_name).await {
        Ok(ks) => ks,
        Err(e) => return build_error(&e),
    };

    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for guard in ks.prefix(&prefix) {
        match guard.into_inner() {
            Ok((key, value)) => pairs.push((key.to_vec(), value.to_vec())),
            Err(e) => return build_error(&format!("prefix_iter error: {e}")),
        }
    }

    let refs: Vec<(&[u8], &[u8])> = pairs
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();
    build_ok_kv_list(&refs)
}

async fn handle_prefix_keys(state: &StorageState, data: &[u8]) -> Vec<u8> {
    let result: Result<_, String> = (|| {
        let (ks_name, offset) = decode_keyspace(data, 0)?;
        let (prefix, _) = decode_bytes(data, offset)?;
        Ok((ks_name.to_string(), prefix.to_vec()))
    })();

    let (ks_name, prefix) = match result {
        Ok(v) => v,
        Err(e) => return build_error(&format!("invalid prefix_keys request: {e}")),
    };

    let ks = match state.get_keyspace(&ks_name).await {
        Ok(ks) => ks,
        Err(e) => return build_error(&e),
    };

    let mut keys: Vec<Vec<u8>> = Vec::new();
    for guard in ks.prefix(&prefix) {
        match guard.into_inner() {
            Ok((key, _)) => keys.push(key.to_vec()),
            Err(e) => return build_error(&format!("prefix_keys error: {e}")),
        }
    }

    let refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
    build_ok_key_list(&refs)
}

async fn handle_scan(state: &StorageState, data: &[u8]) -> Vec<u8> {
    let result: Result<_, String> = (|| {
        let (ks_name, offset) = decode_keyspace(data, 0)?;
        let (prefix, offset) = decode_bytes(data, offset)?;
        let (after, offset) = decode_bytes(data, offset)?;
        if offset + 5 > data.len() {
            return Err("truncated scan options".into());
        }
        let limit = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        let flags = data[offset + 4];
        if flags & !0x01 != 0 {
            return Err(format!("unknown scan flags: {flags:#04x}"));
        }
        Ok((
            ks_name.to_string(),
            prefix.to_vec(),
            (!after.is_empty()).then(|| after.to_vec()),
            limit,
            flags & 0x01 != 0,
        ))
    })();

    let (ks_name, prefix, after, limit, reverse) = match result {
        Ok(v) => v,
        Err(e) => return build_error(&format!("invalid scan request: {e}")),
    };
    if limit == 0 {
        return build_ok_kv_list(&[]);
    }

    let ks = match state.get_keyspace(&ks_name).await {
        Ok(ks) => ks,
        Err(e) => return build_error(&e),
    };
    let (lower, upper) = scan_bounds(&prefix, after.as_deref(), reverse);
    let mut pairs = Vec::with_capacity(limit.min(1024));
    let mut response_size = 5usize;
    // Read at the last published sequence number, as the enclave's local
    // backend does (`vti_common::store::read_snapshot`): a plain `range` can
    // see a write batch half-applied, and a page torn across a batch is what a
    // chain verifier reports as tampering.
    let snapshot = state.db.snapshot();
    let iter = snapshot.range(&ks, (lower, upper));
    let guards: Box<dyn Iterator<Item = _>> = if reverse {
        Box::new(iter.rev())
    } else {
        Box::new(iter)
    };
    for guard in guards.take(limit) {
        let (key, value) = match guard.into_inner() {
            Ok(pair) => pair,
            Err(e) => return build_error(&format!("scan error: {e}")),
        };
        let pair_size = 8usize.saturating_add(key.len()).saturating_add(value.len());
        if response_size.saturating_add(pair_size) > MAX_MESSAGE_SIZE as usize {
            // Fails the request rather than returning the rows that do fit,
            // and **must keep doing so**: the enclave reads a page shorter
            // than the limit it asked for as "the range ended", so a
            // size-capped page would stop a walk early and, in chain-head
            // recovery, anchor the next audit write at genesis — forking a
            // chain that was never broken. The wire cannot currently tell
            // "short because the range ended" from "short because it did not
            // fit"; serving partial pages needs that distinction added first.
            return build_error("scan response exceeds maximum message size");
        }
        response_size += pair_size;
        pairs.push((key.to_vec(), value.to_vec()));
    }
    let refs: Vec<(&[u8], &[u8])> = pairs
        .iter()
        .map(|(key, value)| (key.as_slice(), value.as_slice()))
        .collect();
    build_ok_kv_list(&refs)
}

/// The key range an `OP_SCAN` request covers, as `(lower, upper)` bounds.
///
/// **Mirrors `vti_common::store::scan_bounds`**, which computes the same
/// range inside the enclave — for a scan this proxy cannot serve, the
/// enclave reads the whole prefix and applies these bounds itself, and a
/// caller must get the same rows either way. The two live in separate cargo
/// workspaces and cannot share code without coupling them, so they are
/// pinned to the shared vectors in
/// `vti-common/src/store/scan_range_vectors.json` instead — a change here
/// needs the same change there, and a new edge case needs a new vector.
fn scan_bounds(
    prefix: &[u8],
    after: Option<&[u8]>,
    reverse: bool,
) -> (std::ops::Bound<Vec<u8>>, std::ops::Bound<Vec<u8>>) {
    let lower = if prefix.is_empty() {
        std::ops::Bound::Unbounded
    } else {
        std::ops::Bound::Included(prefix.to_vec())
    };
    let mut upper = prefix_upper_bound(prefix);
    if let Some(after) = after {
        if reverse {
            let within = match &upper {
                std::ops::Bound::Excluded(end) => after < end.as_slice(),
                _ => true,
            };
            if within {
                upper = std::ops::Bound::Excluded(after.to_vec());
            }
        } else if after >= prefix {
            return (std::ops::Bound::Excluded(after.to_vec()), upper);
        }
    }
    (lower, upper)
}

fn prefix_upper_bound(prefix: &[u8]) -> std::ops::Bound<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < u8::MAX {
            end.push(last + 1);
            return std::ops::Bound::Excluded(end);
        }
    }
    std::ops::Bound::Unbounded
}

async fn handle_persist(state: &StorageState) -> Vec<u8> {
    match state.db.persist(PersistMode::SyncAll) {
        Ok(()) => {
            debug!("[storage] persist completed");
            build_ok_empty()
        }
        Err(e) => build_error(&format!("persist failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Atomic multi-step operations (see the opcode docs in `protocol`)
// ---------------------------------------------------------------------------

/// Run an atomic operation's critical section — the keyspace lock and the
/// fjall calls under it — on tokio's blocking pool, and return its response.
///
/// The work under the lock is blocking I/O, and contended operations on one
/// keyspace (every refresh-token claim lands on the same one) queue for the
/// lock. On a worker thread both would stall that worker and every connection
/// task scheduled on it — plain reads on other keyspaces included. On the
/// blocking pool only the operation's own task waits. A std mutex rather than
/// tokio's: nothing under it awaits, and blocking work under a blocking lock
/// is what the blocking pool is for.
///
/// If the connection is dropped meanwhile, the section still runs to the end:
/// an operation is applied whole or not at all, never half.
async fn critical_section<F>(state: &Arc<StorageState>, entry: KeyspaceEntry, f: F) -> Vec<u8>
where
    F: FnOnce(&StorageState, &Keyspace) -> Vec<u8> + Send + 'static,
{
    let state = Arc::clone(state);
    let section = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        state
            .reached_lock
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _guard = entry.lock();
        #[cfg(test)]
        state.hold_critical_section();
        f(&state, &entry.ks)
    });
    match section.await {
        Ok(resp) => resp,
        Err(e) => build_error(&format!("storage operation failed: {e}")),
    }
}

async fn handle_take(state: &Arc<StorageState>, data: &[u8]) -> Vec<u8> {
    let parsed: Result<_, String> = (|| {
        let (ks_name, offset) = decode_keyspace(data, 0)?;
        let (key, _) = decode_bytes(data, offset)?;
        Ok((ks_name.to_string(), key.to_vec()))
    })();
    let (ks_name, key) = match parsed {
        Ok(v) => v,
        Err(e) => return build_error(&format!("invalid take request: {e}")),
    };
    let entry = match state.entry(&ks_name).await {
        Ok(e) => e,
        Err(e) => return build_error(&e),
    };
    critical_section(state, entry, move |_, ks| match ks.get(&key) {
        Ok(Some(value)) => match ks.remove(&key) {
            Ok(()) => build_ok_value(&value),
            Err(e) => build_error(&format!("take failed: {e}")),
        },
        Ok(None) => build_not_found(),
        Err(e) => build_error(&format!("take failed: {e}")),
    })
    .await
}

async fn handle_insert_if_absent(state: &Arc<StorageState>, data: &[u8]) -> Vec<u8> {
    let parsed: Result<_, String> = (|| {
        let (ks_name, offset) = decode_keyspace(data, 0)?;
        let (key, offset) = decode_bytes(data, offset)?;
        let (value, _) = decode_bytes(data, offset)?;
        Ok((ks_name.to_string(), key.to_vec(), value.to_vec()))
    })();
    let (ks_name, key, value) = match parsed {
        Ok(v) => v,
        Err(e) => return build_error(&format!("invalid insert_if_absent request: {e}")),
    };
    let entry = match state.entry(&ks_name).await {
        Ok(e) => e,
        Err(e) => return build_error(&e),
    };
    critical_section(state, entry, move |state, ks| match ks.contains_key(&key) {
        Ok(true) => build_ok_bool(false),
        Ok(false) => match ks.insert(&key, &value) {
            Ok(()) => {
                after_insert(state, &ks_name, &key, &value);
                build_ok_bool(true)
            }
            Err(e) => build_error(&format!("insert_if_absent failed: {e}")),
        },
        Err(e) => build_error(&format!("insert_if_absent failed: {e}")),
    })
    .await
}

async fn handle_swap_if_absent(state: &Arc<StorageState>, data: &[u8]) -> Vec<u8> {
    let parsed: Result<_, String> = (|| {
        let (ks_name, offset) = decode_keyspace(data, 0)?;
        let (old, offset) = decode_bytes(data, offset)?;
        let (new, offset) = decode_bytes(data, offset)?;
        let (value, _) = decode_bytes(data, offset)?;
        Ok((
            ks_name.to_string(),
            old.to_vec(),
            new.to_vec(),
            value.to_vec(),
        ))
    })();
    let (ks_name, old, new, value) = match parsed {
        Ok(v) => v,
        Err(e) => return build_error(&format!("invalid swap_if_absent request: {e}")),
    };
    let entry = match state.entry(&ks_name).await {
        Ok(e) => e,
        Err(e) => return build_error(&e),
    };
    critical_section(state, entry, move |state, ks| {
        match move_locked(state, &ks_name, ks, &old, &new, &value) {
            Ok(moved) => build_ok_bool(moved),
            Err(e) => build_error(&format!("swap_if_absent failed: {e}")),
        }
    })
    .await
}

async fn handle_move_if_equal(state: &Arc<StorageState>, data: &[u8]) -> Vec<u8> {
    let parsed: Result<_, String> = (|| {
        let (ks_name, offset) = decode_keyspace(data, 0)?;
        let (old, offset) = decode_bytes(data, offset)?;
        let (expected, offset) = decode_bytes(data, offset)?;
        let (new, offset) = decode_bytes(data, offset)?;
        let (value, _) = decode_bytes(data, offset)?;
        Ok((
            ks_name.to_string(),
            old.to_vec(),
            expected.to_vec(),
            new.to_vec(),
            value.to_vec(),
        ))
    })();
    let (ks_name, old, expected, new, value) = match parsed {
        Ok(v) => v,
        Err(e) => return build_error(&format!("invalid move_if_equal request: {e}")),
    };
    let entry = match state.entry(&ks_name).await {
        Ok(e) => e,
        Err(e) => return build_error(&e),
    };
    critical_section(state, entry, move |state, ks| {
        // Same order of checks as the enclave's compare-and-move.
        match ks.get(&old) {
            Ok(None) => return build_ok_byte(MOVE_SOURCE_MISSING),
            Ok(Some(current)) if *current != *expected => {
                return build_ok_byte(MOVE_SOURCE_CHANGED);
            }
            Ok(Some(_)) => {}
            Err(e) => return build_error(&format!("move_if_equal failed: {e}")),
        }
        match move_locked(state, &ks_name, ks, &old, &new, &value) {
            Ok(true) => build_ok_byte(MOVE_MOVED),
            Ok(false) => build_ok_byte(MOVE_TARGET_EXISTS),
            Err(e) => build_error(&format!("move_if_equal failed: {e}")),
        }
    })
    .await
}

/// One OP_APPLY_BATCH precondition.
enum BatchCheck {
    Absent(Vec<u8>),
    Present(Vec<u8>),
    Equals(Vec<u8>, Vec<u8>),
}

/// One OP_APPLY_BATCH write; `None` deletes.
type BatchWrite = (Vec<u8>, Option<Vec<u8>>);

fn parse_batch(data: &[u8]) -> Result<(String, Vec<BatchCheck>, Vec<BatchWrite>), String> {
    let (ks_name, mut offset) = decode_keyspace(data, 0)?;
    let mut checks = Vec::new();
    let mut writes: Vec<BatchWrite> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    while offset < data.len() {
        let (tag, next) = decode_bytes(data, offset)?;
        let (key, next) = decode_bytes(data, next)?;
        offset = next;
        let [tag] = tag else {
            return Err(format!("batch tag of {} bytes", tag.len()));
        };
        let is_check = matches!(*tag, BATCH_ABSENT | BATCH_PRESENT | BATCH_EQUALS);
        if is_check && !writes.is_empty() {
            return Err("batch precondition after a write".into());
        }
        if !is_check && !seen.insert(key.to_vec()) {
            // One sequence number per batch: two writes to a key would leave
            // which one survives to the memtable.
            return Err("batch writes the same key twice".into());
        }
        let mut field = || -> Result<Vec<u8>, String> {
            let (v, next) = decode_bytes(data, offset)?;
            offset = next;
            Ok(v.to_vec())
        };
        match *tag {
            BATCH_ABSENT => checks.push(BatchCheck::Absent(key.to_vec())),
            BATCH_PRESENT => checks.push(BatchCheck::Present(key.to_vec())),
            BATCH_EQUALS => checks.push(BatchCheck::Equals(key.to_vec(), field()?)),
            BATCH_PUT => writes.push((key.to_vec(), Some(field()?))),
            BATCH_DELETE => writes.push((key.to_vec(), None)),
            other => return Err(format!("unknown batch tag {other:#04x}")),
        }
    }
    if checks.is_empty() && writes.is_empty() {
        return Err("empty batch".into());
    }
    if checks.len() >= u32::MAX as usize {
        return Err("too many batch preconditions".into());
    }
    Ok((ks_name.to_string(), checks, writes))
}

async fn handle_apply_batch(state: &Arc<StorageState>, data: &[u8]) -> Vec<u8> {
    let (ks_name, checks, writes) = match parse_batch(data) {
        Ok(v) => v,
        Err(e) => return build_error(&format!("invalid apply_batch request: {e}")),
    };
    let entry = match state.entry(&ks_name).await {
        Ok(e) => e,
        Err(e) => return build_error(&e),
    };
    critical_section(state, entry, move |state, ks| {
        for (i, check) in checks.iter().enumerate() {
            let holds = match check {
                BatchCheck::Absent(k) => ks.contains_key(k).map(|present| !present),
                BatchCheck::Present(k) => ks.contains_key(k),
                BatchCheck::Equals(k, expected) => ks
                    .get(k)
                    .map(|current| current.is_some_and(|c| *c == **expected)),
            };
            match holds {
                Ok(true) => {}
                Ok(false) => return build_ok_u32(i as u32 + 1),
                Err(e) => return build_error(&format!("apply_batch failed: {e}")),
            }
        }
        if writes.is_empty() {
            return build_ok_u32(0);
        }
        // One write batch: one journal record, so recovery after a crash
        // replays every write or none.
        let mut batch = state.db.batch();
        for (k, v) in &writes {
            match v {
                Some(v) => batch.insert(ks, k.as_slice(), v.as_slice()),
                None => batch.remove(ks, k.as_slice()),
            }
        }
        if let Err(e) = batch.commit() {
            return build_error(&format!("apply_batch failed: {e}"));
        }
        #[cfg(test)]
        state
            .batch_commits
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        for (k, v) in &writes {
            if let Some(v) = v {
                after_insert(state, &ks_name, k, v);
            }
        }
        build_ok_u32(0)
    })
    .await
}

/// Write `value` at `new` and delete `old`, unless `new` is occupied
/// (`Ok(false)`, nothing written). The caller holds the keyspace's lock.
///
/// The insert and the delete are one fjall write batch: one journal record
/// under one sequence number, so recovery after a crash replays both or
/// neither. As two writes, a crash between them would leave both rows — the
/// moved-from row still live beside its replacement (an old ACL DID keeping
/// its authority).
fn move_locked(
    state: &StorageState,
    ks_name: &str,
    ks: &Keyspace,
    old: &[u8],
    new: &[u8],
    value: &[u8],
) -> Result<bool, fjall::Error> {
    if ks.contains_key(new)? {
        return Ok(false);
    }
    let mut batch = state.db.batch();
    batch.insert(ks, new, value);
    batch.remove(ks, old);
    batch.commit()?;
    #[cfg(test)]
    state
        .batch_commits
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    after_insert(state, ks_name, new, value);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fresh database in its own temporary directory.
    fn state() -> Arc<StorageState> {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "enclave-proxy-storage-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Database::builder(&dir).open().unwrap();
        Arc::new(StorageState {
            db,
            keyspaces: RwLock::new(HashMap::new()),
            data_dir: dir,
            batch_commits: Default::default(),
            critical_delay_ms: Default::default(),
            reached_lock: Default::default(),
        })
    }

    fn req(op: u8, fields: &[&[u8]]) -> Vec<u8> {
        let mut buf = vec![op];
        encode_keyspace(&mut buf, "ks");
        for f in fields {
            encode_bytes(&mut buf, f);
        }
        buf
    }

    async fn dispatch(state: &Arc<StorageState>, request: &[u8]) -> Vec<u8> {
        let body = &request[1..];
        match request[0] {
            OP_GET => handle_get(state, body).await,
            OP_INSERT => handle_insert(state, body).await,
            OP_TAKE => handle_take(state, body).await,
            OP_INSERT_IF_ABSENT => handle_insert_if_absent(state, body).await,
            OP_SWAP_IF_ABSENT => handle_swap_if_absent(state, body).await,
            OP_MOVE_IF_EQUAL => handle_move_if_equal(state, body).await,
            OP_APPLY_BATCH => handle_apply_batch(state, body).await,
            OP_SCAN => handle_scan(state, body).await,
            op => panic!("unexpected op {op}"),
        }
    }

    /// Build an `OP_SCAN` request: `[op][ks][prefix][after][limit:u32][flags:u8]`.
    fn scan_req(prefix: &[u8], after: &[u8], limit: u32, reverse: bool) -> Vec<u8> {
        let mut buf = vec![OP_SCAN];
        encode_keyspace(&mut buf, "ks");
        encode_bytes(&mut buf, prefix);
        encode_bytes(&mut buf, after);
        buf.extend_from_slice(&limit.to_be_bytes());
        buf.push(if reverse { 0x01 } else { 0x00 });
        buf
    }

    async fn get(state: &Arc<StorageState>, key: &[u8]) -> Option<Vec<u8>> {
        decode_value_response(&dispatch(state, &req(OP_GET, &[key])).await).unwrap()
    }

    async fn put(state: &Arc<StorageState>, key: &[u8], value: &[u8]) {
        decode_ok_response(&dispatch(state, &req(OP_INSERT, &[key, value])).await).unwrap();
    }

    /// Run `n` copies of a request at once on the multi-thread runtime and
    /// count the ones `won` accepts.
    async fn race(
        state: &Arc<StorageState>,
        request: Vec<u8>,
        n: usize,
        won: fn(&[u8]) -> bool,
    ) -> usize {
        let tasks: Vec<_> = (0..n)
            .map(|_| {
                let state = state.clone();
                let request = request.clone();
                tokio::spawn(async move { won(&dispatch(&state, &request).await) })
            })
            .collect();
        let mut wins = 0;
        for t in tasks {
            if t.await.unwrap() {
                wins += 1;
            }
        }
        wins
    }

    #[test]
    fn hello_advertises_every_atomic_op() {
        let resp = build_ok_u32(CAPABILITIES);
        assert_eq!(resp[0], STATUS_OK);
        let caps = u32::from_be_bytes([resp[1], resp[2], resp[3], resp[4]]);
        assert_eq!(
            caps,
            CAP_TAKE
                | CAP_INSERT_IF_ABSENT
                | CAP_SWAP_IF_ABSENT
                | CAP_MOVE_IF_EQUAL
                | CAP_APPLY_BATCH
                | CAP_SCAN
        );
    }

    /// An OP_APPLY_BATCH request: each entry is a tag and its fields.
    fn batch(entries: &[(u8, &[&[u8]])]) -> Vec<u8> {
        let mut fields: Vec<&[u8]> = Vec::new();
        let tags: Vec<[u8; 1]> = entries.iter().map(|(t, _)| [*t]).collect();
        for ((_, rest), tag) in entries.iter().zip(&tags) {
            fields.push(tag);
            fields.extend_from_slice(rest);
        }
        req(OP_APPLY_BATCH, &fields)
    }

    fn batch_outcome(resp: &[u8]) -> u32 {
        assert_eq!(resp[0], STATUS_OK, "{resp:?}");
        u32::from_be_bytes([resp[1], resp[2], resp[3], resp[4]])
    }

    /// An applied batch is one write batch (one journal record); a refused
    /// one names the first precondition that failed and writes nothing.
    #[tokio::test]
    async fn apply_batch_commits_one_write_batch_or_nothing() {
        let s = state();
        let batches = || s.batch_commits.load(Ordering::SeqCst);
        put(&s, b"old", b"v").await;

        let r = dispatch(
            &s,
            &batch(&[
                (BATCH_ABSENT, &[b"new"]),
                (BATCH_EQUALS, &[b"old", b"v"]),
                (BATCH_PUT, &[b"new", b"w"]),
                (BATCH_PUT, &[b"idx", b"1"]),
                (BATCH_DELETE, &[b"old"]),
            ]),
        )
        .await;
        assert_eq!(batch_outcome(&r), 0);
        assert_eq!(batches(), 1);
        assert_eq!(get(&s, b"old").await, None);
        assert_eq!(get(&s, b"new").await, Some(b"w".to_vec()));
        assert_eq!(get(&s, b"idx").await, Some(b"1".to_vec()));

        // Each kind of precondition refusing, reported by its 1-based index.
        let put_xy: &[&[u8]] = &[b"x", b"y"];
        for (entries, refused) in [
            (vec![(BATCH_ABSENT, &[&b"new"[..]][..])], 1),
            (
                vec![
                    (BATCH_PRESENT, &[&b"new"[..]][..]),
                    (BATCH_PRESENT, &[&b"old"[..]][..]),
                ],
                2,
            ),
            (vec![(BATCH_EQUALS, &[&b"new"[..], &b"other"[..]][..])], 1),
            (vec![(BATCH_EQUALS, &[&b"old"[..], &b"v"[..]][..])], 1),
        ] {
            let mut entries = entries;
            entries.push((BATCH_PUT, put_xy));
            let r = dispatch(&s, &batch(&entries)).await;
            assert_eq!(batch_outcome(&r), refused);
        }
        assert_eq!(get(&s, b"x").await, None, "refusals write nothing");
        assert_eq!(batches(), 1);

        // Preconditions only: checked, nothing committed.
        let r = dispatch(&s, &batch(&[(BATCH_PRESENT, &[b"new"])])).await;
        assert_eq!(batch_outcome(&r), 0);
        assert_eq!(batches(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn apply_batch_under_concurrency_admits_exactly_one() {
        let s = state();
        let request = batch(&[
            (BATCH_ABSENT, &[b"claim"]),
            (BATCH_PUT, &[b"claim", b"v"]),
            (BATCH_PUT, &[b"index", b"v"]),
        ]);
        let wins = race(&s, request, 64, |r| batch_outcome(r) == 0).await;
        assert_eq!(wins, 1);
    }

    #[tokio::test]
    async fn malformed_batches_are_refused_before_any_write() {
        let s = state();
        for bad in [
            // A precondition after a write.
            batch(&[(BATCH_PUT, &[b"a", b"1"]), (BATCH_ABSENT, &[b"b"])]),
            // One key written twice.
            batch(&[(BATCH_PUT, &[b"a", b"1"]), (BATCH_DELETE, &[b"a"])]),
            // An unknown tag.
            batch(&[(b'z', &[b"a"])]),
            // A put without its value.
            batch(&[(BATCH_PUT, &[b"a"])]),
        ] {
            let resp = dispatch(&s, &bad).await;
            assert_eq!(resp[0], STATUS_ERROR, "{resp:?}");
        }
        assert_eq!(get(&s, b"a").await, None);
        assert_eq!(s.batch_commits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn take_returns_and_removes() {
        let s = state();
        put(&s, b"k", b"v").await;
        let resp = dispatch(&s, &req(OP_TAKE, &[b"k"])).await;
        assert_eq!(decode_value_response(&resp).unwrap(), Some(b"v".to_vec()));
        assert_eq!(get(&s, b"k").await, None);
        let resp = dispatch(&s, &req(OP_TAKE, &[b"k"])).await;
        assert_eq!(decode_value_response(&resp).unwrap(), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn take_under_concurrency_admits_exactly_one() {
        let s = state();
        put(&s, b"k", b"v").await;
        let wins = race(&s, req(OP_TAKE, &[b"k"]), 64, |r| {
            decode_value_response(r).unwrap().is_some()
        })
        .await;
        assert_eq!(wins, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn insert_if_absent_under_concurrency_admits_exactly_one() {
        let s = state();
        let wins = race(&s, req(OP_INSERT_IF_ABSENT, &[b"k", b"v"]), 64, |r| {
            decode_bool_response(r).unwrap()
        })
        .await;
        assert_eq!(wins, 1);
        assert_eq!(get(&s, b"k").await, Some(b"v".to_vec()));
    }

    #[tokio::test]
    async fn insert_if_absent_leaves_an_existing_value() {
        let s = state();
        put(&s, b"k", b"first").await;
        let r = dispatch(&s, &req(OP_INSERT_IF_ABSENT, &[b"k", b"second"])).await;
        assert!(!decode_bool_response(&r).unwrap());
        assert_eq!(get(&s, b"k").await, Some(b"first".to_vec()));
    }

    #[tokio::test]
    async fn swap_if_absent_moves_or_writes_nothing() {
        let s = state();
        put(&s, b"old", b"v").await;
        let r = dispatch(&s, &req(OP_SWAP_IF_ABSENT, &[b"old", b"new", b"w"])).await;
        assert!(decode_bool_response(&r).unwrap());
        assert_eq!(get(&s, b"old").await, None);
        assert_eq!(get(&s, b"new").await, Some(b"w".to_vec()));

        put(&s, b"old", b"v").await;
        let r = dispatch(&s, &req(OP_SWAP_IF_ABSENT, &[b"old", b"new", b"x"])).await;
        assert!(!decode_bool_response(&r).unwrap());
        assert_eq!(get(&s, b"old").await, Some(b"v".to_vec()), "old kept");
        assert_eq!(get(&s, b"new").await, Some(b"w".to_vec()), "new untouched");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn swap_if_absent_under_concurrency_admits_exactly_one() {
        let s = state();
        put(&s, b"old", b"v").await;
        let wins = race(
            &s,
            req(OP_SWAP_IF_ABSENT, &[b"old", b"new", b"w"]),
            64,
            |r| decode_bool_response(r).unwrap(),
        )
        .await;
        assert_eq!(wins, 1);
    }

    #[tokio::test]
    async fn move_if_equal_reports_every_outcome() {
        let s = state();
        let outcome = |r: Vec<u8>| {
            assert_eq!(r[0], STATUS_OK, "{r:?}");
            r[1]
        };
        let m = |exp: &'static [u8]| req(OP_MOVE_IF_EQUAL, &[b"old", exp, b"new", b"w"]);

        assert_eq!(outcome(dispatch(&s, &m(b"v")).await), MOVE_SOURCE_MISSING);
        put(&s, b"old", b"v").await;
        assert_eq!(
            outcome(dispatch(&s, &m(b"other")).await),
            MOVE_SOURCE_CHANGED
        );
        put(&s, b"new", b"taken").await;
        assert_eq!(outcome(dispatch(&s, &m(b"v")).await), MOVE_TARGET_EXISTS);
        assert_eq!(get(&s, b"old").await, Some(b"v".to_vec()));
        assert_eq!(get(&s, b"new").await, Some(b"taken".to_vec()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn move_if_equal_under_concurrency_admits_exactly_one() {
        let s = state();
        put(&s, b"old", b"v").await;
        let wins = race(
            &s,
            req(OP_MOVE_IF_EQUAL, &[b"old", b"v", b"new", b"w"]),
            64,
            |r| r == build_ok_byte(MOVE_MOVED).as_slice(),
        )
        .await;
        assert_eq!(wins, 1);
        assert_eq!(get(&s, b"new").await, Some(b"w".to_vec()));
        assert_eq!(get(&s, b"old").await, None);
    }

    /// Every move commits its insert and delete as one write batch, and only
    /// a move that happens commits one. Outcomes are unchanged.
    #[tokio::test]
    async fn moves_commit_one_write_batch() {
        let s = state();
        let batches = || s.batch_commits.load(Ordering::SeqCst);
        put(&s, b"old", b"v").await;

        let r = dispatch(&s, &req(OP_SWAP_IF_ABSENT, &[b"old", b"mid", b"w"])).await;
        assert!(decode_bool_response(&r).unwrap());
        assert_eq!(batches(), 1);

        let r = dispatch(&s, &req(OP_MOVE_IF_EQUAL, &[b"mid", b"w", b"new", b"x"])).await;
        assert_eq!(r, build_ok_byte(MOVE_MOVED));
        assert_eq!(batches(), 2);
        assert_eq!(get(&s, b"old").await, None);
        assert_eq!(get(&s, b"mid").await, None);
        assert_eq!(get(&s, b"new").await, Some(b"x".to_vec()));

        // Refused moves write nothing at all.
        put(&s, b"a", b"1").await;
        let r = dispatch(&s, &req(OP_SWAP_IF_ABSENT, &[b"a", b"new", b"y"])).await;
        assert!(!decode_bool_response(&r).unwrap());
        let r = dispatch(&s, &req(OP_MOVE_IF_EQUAL, &[b"a", b"2", b"z", b"y"])).await;
        assert_eq!(r, build_ok_byte(MOVE_SOURCE_CHANGED));
        assert_eq!(batches(), 2);
    }

    /// Contended atomic operations on one keyspace queue for its lock on the
    /// blocking pool, not on the runtime's workers: a plain read on another
    /// keyspace completes promptly while they wait.
    ///
    /// Two workers, two operations on one keyspace: one holds the lock for
    /// `HOLD_MS`, the other waits for it. Taken on worker threads, that is both
    /// workers, and a read arriving meanwhile cannot run until the holder
    /// finishes. On the blocking pool the workers are free.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn contended_atomic_ops_do_not_starve_other_reads() {
        const HOLD_MS: u64 = 300;
        let s = state();
        let mut other = vec![OP_GET];
        encode_keyspace(&mut other, "other");
        encode_bytes(&mut other, b"x");
        // Create both keyspaces first: creation is durable (an fsync, slow on
        // macOS) and would be measured instead of the wait for a worker.
        dispatch(&s, &other).await;
        put(&s, b"warm", b"v").await;
        s.critical_delay_ms.store(HOLD_MS, Ordering::SeqCst);

        let contended: Vec<_> = (0..2)
            .map(|_| {
                let s = s.clone();
                tokio::spawn(async move {
                    dispatch(&s, &req(OP_INSERT_IF_ABSENT, &[b"claim", b"v"])).await
                })
            })
            .collect();
        // Until both have reached the lock: one holds it, one waits. A
        // blocking wait on the test thread, which is not a worker, so it does
        // not depend on the workers being free.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while s.reached_lock.load(Ordering::SeqCst) < 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "operations never reached the lock"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        // On a worker, like every connection task: that is what would starve.
        let started = std::time::Instant::now();
        let reader = s.clone();
        let read = tokio::spawn(async move { dispatch(&reader, &other).await });
        let resp = read.await.unwrap();
        let took = started.elapsed();
        assert_eq!(resp, build_not_found());
        assert!(
            took < std::time::Duration::from_millis(HOLD_MS / 3),
            "a read on another keyspace waited {took:?} behind a {HOLD_MS} ms critical section"
        );

        let mut inserted = 0;
        for t in contended {
            if decode_bool_response(&t.await.unwrap()).unwrap() {
                inserted += 1;
            }
        }
        assert_eq!(inserted, 1, "still exactly one winner");
    }

    /// The shared bounded-scan vectors, against this proxy's real
    /// `handle_scan`.
    ///
    /// The file is the contract between this implementation and
    /// `vti_common::store::scan_bounds` inside the enclave: for a scan an
    /// older proxy cannot serve, the enclave reads the whole prefix and
    /// applies its own bounds, and a caller must get the same rows either
    /// way. The two cannot share code — separate cargo workspaces, and this
    /// binary's dependency surface is deliberately small — so they share this
    /// table instead. `include_str!` reaches across the workspace boundary at
    /// compile time, which costs no dependency.
    #[tokio::test]
    async fn scan_matches_the_shared_range_vectors() {
        #[derive(serde::Deserialize)]
        struct Case {
            name: String,
            #[serde(default)]
            encoding: Option<String>,
            keys: Vec<String>,
            prefix: String,
            after: Option<String>,
            reverse: bool,
            expect: Vec<String>,
        }
        #[derive(serde::Deserialize)]
        struct Vectors {
            cases: Vec<Case>,
        }

        /// Render a key the way its case wrote it, so a failure reads as
        /// keys rather than as byte arrays.
        fn render(keys: &[Vec<u8>], hex_encoded: bool) -> Vec<String> {
            keys.iter()
                .map(|key| {
                    if hex_encoded {
                        key.iter().map(|b| format!("{b:02x}")).collect()
                    } else {
                        String::from_utf8_lossy(key).into_owned()
                    }
                })
                .collect()
        }

        fn bytes(value: &str, hex_encoded: bool) -> Vec<u8> {
            if hex_encoded {
                assert!(value.len().is_multiple_of(2), "hex field has odd length");
                (0..value.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex byte"))
                    .collect()
            } else {
                value.as_bytes().to_vec()
            }
        }

        let vectors: Vectors = serde_json::from_str(include_str!(
            "../../../../vti-common/src/store/scan_range_vectors.json"
        ))
        .expect("scan range vectors parse");

        for case in vectors.cases {
            let hex_encoded = case.encoding.as_deref() == Some("hex");
            let s = state();
            for key in &case.keys {
                put(&s, &bytes(key, hex_encoded), b"v").await;
            }

            // The vectors describe the range, not a page, so the limit is
            // only there to stop a bounds error hiding behind a truncation.
            let request = scan_req(
                &bytes(&case.prefix, hex_encoded),
                &case
                    .after
                    .as_deref()
                    .map(|a| bytes(a, hex_encoded))
                    .unwrap_or_default(),
                u32::MAX,
                case.reverse,
            );
            let scanned: Vec<Vec<u8>> = decode_kv_list_response(&dispatch(&s, &request).await)
                .expect("scan response")
                .into_iter()
                .map(|(key, _)| key)
                .collect();

            let expect: Vec<Vec<u8>> = case
                .expect
                .iter()
                .map(|key| bytes(key, hex_encoded))
                .collect();
            assert_eq!(
                render(&scanned, hex_encoded),
                render(&expect, hex_encoded),
                "proxy scan disagrees with the shared vectors: {}",
                case.name
            );
        }
    }

    #[tokio::test]
    async fn scan_returns_ascending_range_respecting_limit() {
        let s = state();
        for i in 0..5u8 {
            put(&s, &[b'k', i], &[b'v', i]).await;
        }
        let resp = dispatch(&s, &scan_req(b"k", b"", 3, false)).await;
        let pairs = decode_kv_list_response(&resp).unwrap();
        assert_eq!(
            pairs,
            vec![
                (vec![b'k', 0], vec![b'v', 0]),
                (vec![b'k', 1], vec![b'v', 1]),
                (vec![b'k', 2], vec![b'v', 2]),
            ]
        );
    }

    #[tokio::test]
    async fn scan_reverse_flag_returns_newest_first() {
        let s = state();
        for i in 0..5u8 {
            put(&s, &[b'k', i], &[b'v', i]).await;
        }
        let resp = dispatch(&s, &scan_req(b"k", b"", 3, true)).await;
        let pairs = decode_kv_list_response(&resp).unwrap();
        assert_eq!(
            pairs,
            vec![
                (vec![b'k', 4], vec![b'v', 4]),
                (vec![b'k', 3], vec![b'v', 3]),
                (vec![b'k', 2], vec![b'v', 2]),
            ]
        );
    }

    #[tokio::test]
    async fn scan_after_cursor_is_exclusive_in_both_directions() {
        let s = state();
        for i in 0..5u8 {
            put(&s, &[b'k', i], &[b'v', i]).await;
        }

        // Ascending: resume strictly after k2 -> k3, k4.
        let resp = dispatch(&s, &scan_req(b"k", &[b'k', 2], 10, false)).await;
        let pairs = decode_kv_list_response(&resp).unwrap();
        assert_eq!(
            pairs,
            vec![
                (vec![b'k', 3], vec![b'v', 3]),
                (vec![b'k', 4], vec![b'v', 4])
            ]
        );

        // Reverse: resume strictly before (older than) k2 -> k1, k0.
        let resp = dispatch(&s, &scan_req(b"k", &[b'k', 2], 10, true)).await;
        let pairs = decode_kv_list_response(&resp).unwrap();
        assert_eq!(
            pairs,
            vec![
                (vec![b'k', 1], vec![b'v', 1]),
                (vec![b'k', 0], vec![b'v', 0])
            ]
        );
    }

    #[tokio::test]
    async fn scan_zero_limit_returns_an_empty_list() {
        let s = state();
        put(&s, b"k", b"v").await;
        let resp = dispatch(&s, &scan_req(b"k", b"", 0, false)).await;
        assert_eq!(decode_kv_list_response(&resp).unwrap(), vec![]);
    }

    #[tokio::test]
    async fn scan_rejects_unknown_flag_bits() {
        let s = state();
        let mut request = scan_req(b"k", b"", 10, false);
        // Flip a bit outside the single defined `reverse` flag.
        *request.last_mut().unwrap() = 0x02;
        let resp = dispatch(&s, &request).await;
        assert_eq!(resp[0], STATUS_ERROR);
    }

    #[tokio::test]
    async fn scan_rejects_responses_over_the_frame_size_cap() {
        let s = state();
        // Large enough values that a handful of pairs already exceed
        // MAX_MESSAGE_SIZE (16 MiB), proving the cap is enforced while the
        // scan is being assembled rather than only at the transport layer.
        let value = vec![0u8; 1_048_576];
        for i in 0..20u8 {
            put(&s, &[b'k', i], &value).await;
        }
        let resp = dispatch(&s, &scan_req(b"k", b"", 20, false)).await;
        assert_eq!(resp[0], STATUS_ERROR);
    }

    #[tokio::test]
    async fn malformed_requests_are_errors_not_panics() {
        let s = state();
        for op in [
            OP_TAKE,
            OP_INSERT_IF_ABSENT,
            OP_SWAP_IF_ABSENT,
            OP_MOVE_IF_EQUAL,
            OP_APPLY_BATCH,
            OP_SCAN,
        ] {
            // Keyspace only; every key/value field missing.
            let mut truncated = vec![op];
            encode_keyspace(&mut truncated, "ks");
            // A length prefix claiming more bytes than the frame holds.
            let mut lying = truncated.clone();
            lying.extend_from_slice(&u32::MAX.to_be_bytes());
            for request in [vec![op], truncated, lying] {
                let resp = dispatch(&s, &request).await;
                assert_eq!(resp[0], STATUS_ERROR, "op {op:#04x}: {resp:?}");
            }
        }
    }
}
