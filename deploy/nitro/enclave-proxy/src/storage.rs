//! Parent-side persistent key-value storage server.
//!
//! Listens on a vsock port and serves K/V operations backed by fjall on the
//! parent EC2 instance's EBS volume.
//!
//! All data from the enclave is already encrypted (AES-256-GCM) before it
//! reaches this server — the parent only stores opaque blobs.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use fjall::{Database, KeyspaceCreateOptions, Keyspace, PersistMode};
use tokio::sync::RwLock;
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
use tracing::{debug, error, info, warn};

use crate::protocol::*;

/// Run the parent-side storage server.
///
/// Opens a fjall database at `data_dir` and listens for K/V operations on
/// the given vsock port.
pub async fn run_storage(vsock_port: u32, data_dir: PathBuf) {
    // Open the fjall database on the parent's EBS volume
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        error!("[storage] failed to create data directory {}: {e}", data_dir.display());
        return;
    }

    let db = match Database::builder(&data_dir).open() {
        Ok(db) => db,
        Err(e) => {
            error!("[storage] failed to open fjall database at {}: {e}", data_dir.display());
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
    if let Ok(ks) = db.keyspace("bootstrap", KeyspaceCreateOptions::default) {
        if let Ok(Some(value)) = ks.get("tee:did_log") {
            write_did_log_file(&data_dir, &value);
        }
    }

    let state = Arc::new(StorageState {
        db,
        keyspaces: RwLock::new(HashMap::new()),
        data_dir: data_dir.clone(),
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
    keyspaces: RwLock<HashMap<String, Keyspace>>,
    data_dir: PathBuf,
}

impl StorageState {
    /// Get or create a keyspace by name.
    async fn get_keyspace(&self, name: &str) -> Result<Keyspace, String> {
        // Fast path: read lock
        {
            let ks_map = self.keyspaces.read().await;
            if let Some(ks) = ks_map.get(name) {
                return Ok(ks.clone());
            }
        }

        // Slow path: write lock + create
        let mut ks_map = self.keyspaces.write().await;
        if let Some(ks) = ks_map.get(name) {
            return Ok(ks.clone());
        }

        let ks = self
            .db
            .keyspace(name, KeyspaceCreateOptions::default)
            .map_err(|e| format!("failed to create keyspace '{name}': {e}"))?;
        ks_map.insert(name.to_string(), ks.clone());
        debug!("[storage] created keyspace: {name}");
        Ok(ks)
    }
}

/// Handle a single client connection (long-lived, multiple requests).
async fn handle_connection(
    mut stream: tokio_vsock::VsockStream,
    state: &StorageState,
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
            OP_PERSIST => handle_persist(state).await,
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
fn write_did_log_file(data_dir: &PathBuf, value: &[u8]) {
    // Write to the parent directory of the store (e.g., /mnt/vta-data/did.jsonl)
    let output_path = data_dir
        .parent()
        .unwrap_or(data_dir.as_path())
        .join("did.jsonl");
    match std::fs::write(&output_path, value) {
        Ok(()) => info!("[storage] wrote DID log to {}", output_path.display()),
        Err(e) => warn!("[storage] failed to write DID log to {}: {e}", output_path.display()),
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
            // When the VTA writes its auto-generated DID log to the bootstrap
            // keyspace, also write it to disk so the operator can retrieve it
            // without needing REST enabled. Key mirrors
            // `vta_tee::did_autogen::DID_LOG_STORE_KEY` (see the startup read
            // above for why it is not imported).
            if ks_name == "bootstrap" && key == b"tee:did_log" {
                write_did_log_file(&state.data_dir, &value);
            }
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

    let refs: Vec<(&[u8], &[u8])> = pairs.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect();
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

async fn handle_persist(state: &StorageState) -> Vec<u8> {
    match state.db.persist(PersistMode::SyncAll) {
        Ok(()) => {
            debug!("[storage] persist completed");
            build_ok_empty()
        }
        Err(e) => build_error(&format!("persist failed: {e}")),
    }
}
