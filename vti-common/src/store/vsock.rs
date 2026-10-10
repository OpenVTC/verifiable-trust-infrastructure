//! Vsock-backed key-value store for Nitro Enclaves.
//!
//! Sends all storage operations over vsock to the parent EC2 instance,
//! which persists them to fjall on its EBS volume. Data is encrypted
//! enclave-side before crossing vsock — the parent only sees opaque blobs.

use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::info;

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

// ---------------------------------------------------------------------------
// VsockStore
// ---------------------------------------------------------------------------

/// CID 3 = parent/host in Nitro Enclaves.
const PARENT_CID: u32 = 3;
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
        Ok(Self {
            pool: Arc::new(ConnectionPool::new(
                connector,
                DEFAULT_MAX_CONNECTIONS,
                first,
            )),
            locks: Arc::new(KeyLocks::default()),
        })
    }

    /// Get a keyspace handle. No RPC needed — the keyspace name is sent
    /// with each operation.
    pub fn keyspace(&self, name: &str) -> Result<VsockKeyspaceHandle, AppError> {
        Ok(VsockKeyspaceHandle {
            pool: Arc::clone(&self.pool),
            locks: Arc::clone(&self.locks),
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
        let mut payload = vec![OP_GET];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, &key);
        let resp = self.send(&payload).await?;
        match decode_value(&resp)? {
            Some(bytes) => Ok(Some(self.maybe_decrypt(&key, &bytes)?)),
            None => Ok(None),
        }
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
    /// Atomic: the key's lock is held across the read and the write.
    pub async fn insert_if_absent<V: Serialize>(
        &self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<bool, AppError> {
        let key = key.into();
        let _guard = self.locks.lock(&self.keyspace, &[&key]).await;
        if self.get_raw(key.clone()).await?.is_some() {
            return Ok(false);
        }
        self.insert(key, value).await?;
        Ok(true)
    }

    /// Raw-bytes [`Self::insert_if_absent`].
    pub async fn insert_raw_if_absent(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<bool, AppError> {
        let key = key.into();
        let _guard = self.locks.lock(&self.keyspace, &[&key]).await;
        if self.get_raw(key.clone()).await?.is_some() {
            return Ok(false);
        }
        self.insert_raw(key, value).await?;
        Ok(true)
    }

    /// Read and delete `key`; exactly one of two racing callers gets the
    /// value. The key's lock is held across both round trips.
    ///
    /// If the caller is cancelled between them the row stays and nobody
    /// received it; if the delete fails the caller gets the error, not the
    /// value. Neither path hands the value out twice.
    pub async fn take_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        let key = key.into();
        let _guard = self.locks.lock(&self.keyspace, &[&key]).await;
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
        self.swap_locked(old_key, new_key, value).await
    }

    /// The steps of [`Self::swap`]; the caller holds both keys' locks.
    async fn swap_locked<V: Serialize>(
        &self,
        old_key: Vec<u8>,
        new_key: Vec<u8>,
        value: &V,
    ) -> Result<bool, AppError> {
        if self.get_raw(new_key.clone()).await?.is_some() {
            return Ok(false);
        }

        // Insert new, delete old. The value lands at `new_key`, so bind
        // the AAD to it.
        let bytes = serde_json::to_vec(value)?;
        let bytes = self.maybe_encrypt(&new_key, bytes)?;

        let mut insert_payload = vec![OP_INSERT];
        encode_keyspace(&mut insert_payload, &self.keyspace);
        encode_bytes(&mut insert_payload, &new_key);
        encode_bytes(&mut insert_payload, &bytes);
        let resp = self.send(&insert_payload).await?;
        decode_ok(&resp)?;

        let mut delete_payload = vec![OP_DELETE];
        encode_keyspace(&mut delete_payload, &self.keyspace);
        encode_bytes(&mut delete_payload, &old_key);
        let resp = self.send(&delete_payload).await?;
        decode_ok(&resp)?;

        Ok(true)
    }

    /// Compare-and-move: only while `old_key` still holds exactly `expected`
    /// (plaintext). Both keys' locks are held from the comparison to the
    /// delete, so two callers holding the same `expected` cannot both move.
    pub async fn move_if_unchanged<V: Serialize>(
        &self,
        old_key: impl Into<Vec<u8>>,
        expected: Vec<u8>,
        new_key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<super::MoveOutcome, AppError> {
        let old_key = old_key.into();
        let new_key = new_key.into();
        let _guard = self.locks.lock(&self.keyspace, &[&old_key, &new_key]).await;
        match self.get_raw(old_key.clone()).await? {
            None => return Ok(super::MoveOutcome::SourceMissing),
            Some(current) if current != expected => return Ok(super::MoveOutcome::SourceChanged),
            Some(_) => {}
        }
        if self.swap_locked(old_key, new_key, value).await? {
            Ok(super::MoveOutcome::Moved)
        } else {
            Ok(super::MoveOutcome::TargetExists)
        }
    }

    /// Send one request over a pooled connection (reconnecting once on
    /// failure) and return the response.
    async fn send(&self, payload: &[u8]) -> Result<Vec<u8>, AppError> {
        self.pool.request(payload).await
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
#[cfg(test)]
mod atomicity_tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    type Rows = Arc<StdMutex<HashMap<(String, Vec<u8>), Vec<u8>>>>;

    #[derive(Clone, Default)]
    struct FakeParent {
        rows: Rows,
    }

    impl FakeParent {
        fn handle(&self) -> VsockKeyspaceHandle {
            let parent = self.clone();
            let connect: Connector = Arc::new(move || {
                let parent = parent.clone();
                Box::pin(async move { Ok(parent.open()) })
            });
            VsockKeyspaceHandle {
                pool: Arc::new(ConnectionPool::new(connect, 8, self.open())),
                locks: Arc::new(KeyLocks::default()),
                keyspace: "ks".into(),
                #[cfg(feature = "encryption")]
                encryption_key: None,
            }
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
                tokio::time::sleep(Duration::from_millis(3)).await;
                let resp = self.apply(&req);
                let mut frame = (resp.len() as u32).to_be_bytes().to_vec();
                frame.extend_from_slice(&resp);
                if s.write_all(&frame).await.is_err() {
                    return;
                }
            }
        }

        fn apply(&self, req: &[u8]) -> Vec<u8> {
            let op = req[0];
            let ks_len = u16::from_be_bytes([req[1], req[2]]) as usize;
            let ks = String::from_utf8(req[3..3 + ks_len].to_vec()).unwrap();
            let (key, next) = decode_bytes(req, 3 + ks_len).unwrap();
            let id = (ks, key.to_vec());
            let mut rows = self.rows.lock().unwrap();
            match op {
                OP_GET => match rows.get(&id) {
                    Some(v) => {
                        let mut out = vec![STATUS_OK];
                        encode_bytes(&mut out, v);
                        out
                    }
                    None => vec![STATUS_NOT_FOUND],
                },
                OP_INSERT => {
                    let (value, _) = decode_bytes(req, next).unwrap();
                    rows.insert(id, value.to_vec());
                    vec![STATUS_OK]
                }
                OP_DELETE => {
                    rows.remove(&id);
                    vec![STATUS_OK]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn take_raw_under_concurrency_admits_exactly_one() {
        // A refresh token presented by many callers at once: one rotation.
        let h = FakeParent::default().handle();
        h.insert_raw(b"refresh:t".to_vec(), b"session".to_vec())
            .await
            .unwrap();
        let wins = race(|| {
            let h = h.clone();
            async move { h.take_raw(b"refresh:t".to_vec()).await.unwrap().is_some() }
        })
        .await;
        assert_eq!(wins, 1);
        assert_eq!(h.get_raw(b"refresh:t".to_vec()).await.unwrap(), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn insert_if_absent_under_concurrency_admits_exactly_one() {
        let h = FakeParent::default().handle();
        let wins = race(|| {
            let h = h.clone();
            async move { h.insert_if_absent(b"claim".to_vec(), &1u32).await.unwrap() }
        })
        .await;
        assert_eq!(wins, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn insert_raw_if_absent_under_concurrency_admits_exactly_one() {
        let h = FakeParent::default().handle();
        let wins = race(|| {
            let h = h.clone();
            async move {
                h.insert_raw_if_absent(b"claim".to_vec(), b"x".to_vec())
                    .await
                    .unwrap()
            }
        })
        .await;
        assert_eq!(wins, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn move_if_unchanged_under_concurrency_admits_exactly_one() {
        let h = FakeParent::default().handle();
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
        assert_eq!(wins, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn swap_under_concurrency_admits_exactly_one() {
        let h = FakeParent::default().handle();
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
        assert_eq!(wins, 1);
    }

    /// Control: the same harness catches the race the locks close. Without
    /// a lock, a read-then-delete claim is won by more than one caller.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn harness_detects_an_unlocked_claim() {
        let h = FakeParent::default().handle();
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
}
