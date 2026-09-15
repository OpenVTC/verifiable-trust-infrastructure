//! Wire protocol for the vsock key-value storage proxy.
//!
//! Some functions (request builders, response decoders) are defined here
//! for protocol completeness but only used by the vsock client in vti-common.
//!
//! Simple length-prefixed binary messages. Each message:
//!   [4 bytes: payload length (u32 big-endian)][payload bytes]
//!
//! Request payload: [1 byte: opcode][operation-specific fields]
//! Response payload: [1 byte: status][operation-specific fields]
//!
//! All multi-byte lengths in fields are u32 big-endian.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Opcodes
// ---------------------------------------------------------------------------

pub const OP_GET: u8 = 0x01;
pub const OP_INSERT: u8 = 0x02;
pub const OP_DELETE: u8 = 0x03;
pub const OP_PREFIX_ITER: u8 = 0x04;
pub const OP_PREFIX_KEYS: u8 = 0x05;
pub const OP_PERSIST: u8 = 0x06;

// ---------------------------------------------------------------------------
// Response status
// ---------------------------------------------------------------------------

pub const STATUS_OK: u8 = 0x00;
pub const STATUS_NOT_FOUND: u8 = 0x01;
pub const STATUS_ERROR: u8 = 0x02;

// ---------------------------------------------------------------------------
// Frame I/O
// ---------------------------------------------------------------------------

/// Maximum message size (16 MB — generous for prefix scans with many results).
const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// Read a length-prefixed frame from the stream.
pub async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let len = reader.read_u32().await?;
    if len > MAX_MESSAGE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes (max {MAX_MESSAGE_SIZE})"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write a length-prefixed frame to the stream.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> std::io::Result<()> {
    writer.write_u32(data.len() as u32).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Encode a byte slice as [4B length][bytes].
pub fn encode_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Decode a byte slice from [4B length][bytes] at the given offset.
/// Returns (bytes, new_offset).
pub fn decode_bytes(data: &[u8], offset: usize) -> Result<(&[u8], usize), String> {
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
        return Err(format!(
            "truncated data: need {len} bytes at offset {start}, have {}",
            data.len() - start
        ));
    }
    Ok((&data[start..end], end))
}

/// Encode a keyspace name as [2B length][name_bytes].
pub fn encode_keyspace(buf: &mut Vec<u8>, name: &str) {
    buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
    buf.extend_from_slice(name.as_bytes());
}

/// Decode a keyspace name from [2B length][name_bytes] at the given offset.
pub fn decode_keyspace(data: &[u8], offset: usize) -> Result<(&str, usize), String> {
    if offset + 2 > data.len() {
        return Err("truncated keyspace length".into());
    }
    let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    let start = offset + 2;
    let end = start + len;
    if end > data.len() {
        return Err("truncated keyspace name".into());
    }
    let name = std::str::from_utf8(&data[start..end])
        .map_err(|e| format!("invalid keyspace name: {e}"))?;
    Ok((name, end))
}

// ---------------------------------------------------------------------------
// Request builders (used by the enclave client)
// ---------------------------------------------------------------------------

pub fn build_get_request(keyspace: &str, key: &[u8]) -> Vec<u8> {
    let mut buf = vec![OP_GET];
    encode_keyspace(&mut buf, keyspace);
    encode_bytes(&mut buf, key);
    buf
}

pub fn build_insert_request(keyspace: &str, key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut buf = vec![OP_INSERT];
    encode_keyspace(&mut buf, keyspace);
    encode_bytes(&mut buf, key);
    encode_bytes(&mut buf, value);
    buf
}

pub fn build_delete_request(keyspace: &str, key: &[u8]) -> Vec<u8> {
    let mut buf = vec![OP_DELETE];
    encode_keyspace(&mut buf, keyspace);
    encode_bytes(&mut buf, key);
    buf
}

pub fn build_prefix_iter_request(keyspace: &str, prefix: &[u8]) -> Vec<u8> {
    let mut buf = vec![OP_PREFIX_ITER];
    encode_keyspace(&mut buf, keyspace);
    encode_bytes(&mut buf, prefix);
    buf
}

pub fn build_prefix_keys_request(keyspace: &str, prefix: &[u8]) -> Vec<u8> {
    let mut buf = vec![OP_PREFIX_KEYS];
    encode_keyspace(&mut buf, keyspace);
    encode_bytes(&mut buf, prefix);
    buf
}

pub fn build_persist_request() -> Vec<u8> {
    vec![OP_PERSIST]
}

// ---------------------------------------------------------------------------
// Response builders (used by the parent server)
// ---------------------------------------------------------------------------

pub fn build_ok_empty() -> Vec<u8> {
    vec![STATUS_OK]
}

pub fn build_ok_value(value: &[u8]) -> Vec<u8> {
    let mut buf = vec![STATUS_OK];
    encode_bytes(&mut buf, value);
    buf
}

pub fn build_ok_bool(value: bool) -> Vec<u8> {
    vec![STATUS_OK, if value { 0x01 } else { 0x00 }]
}

pub fn build_ok_kv_list(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut buf = vec![STATUS_OK];
    buf.extend_from_slice(&(pairs.len() as u32).to_be_bytes());
    for (key, value) in pairs {
        encode_bytes(&mut buf, key);
        encode_bytes(&mut buf, value);
    }
    buf
}

pub fn build_ok_key_list(keys: &[&[u8]]) -> Vec<u8> {
    let mut buf = vec![STATUS_OK];
    buf.extend_from_slice(&(keys.len() as u32).to_be_bytes());
    for key in keys {
        encode_bytes(&mut buf, key);
    }
    buf
}

pub fn build_not_found() -> Vec<u8> {
    vec![STATUS_NOT_FOUND]
}

pub fn build_error(msg: &str) -> Vec<u8> {
    let mut buf = vec![STATUS_ERROR];
    encode_bytes(&mut buf, msg.as_bytes());
    buf
}

// ---------------------------------------------------------------------------
// Response decoders (used by the enclave client)
// ---------------------------------------------------------------------------

/// Decode a response that returns an optional value (Get, FileRead).
/// Returns Ok(Some(bytes)) for STATUS_OK, Ok(None) for STATUS_NOT_FOUND,
/// Err for STATUS_ERROR.
pub fn decode_value_response(data: &[u8]) -> Result<Option<Vec<u8>>, String> {
    if data.is_empty() {
        return Err("empty response".into());
    }
    match data[0] {
        STATUS_OK => {
            let (value, _) = decode_bytes(data, 1)?;
            Ok(Some(value.to_vec()))
        }
        STATUS_NOT_FOUND => Ok(None),
        STATUS_ERROR => {
            let (msg, _) = decode_bytes(data, 1)?;
            Err(String::from_utf8_lossy(msg).into_owned())
        }
        s => Err(format!("unknown status: {s:#04x}")),
    }
}

/// Decode a response that returns success/failure (Insert, Delete, FileWrite, Persist).
pub fn decode_ok_response(data: &[u8]) -> Result<(), String> {
    if data.is_empty() {
        return Err("empty response".into());
    }
    match data[0] {
        STATUS_OK => Ok(()),
        STATUS_ERROR => {
            let (msg, _) = decode_bytes(data, 1)?;
            Err(String::from_utf8_lossy(msg).into_owned())
        }
        s => Err(format!("unexpected status: {s:#04x}")),
    }
}

/// Decode a response that returns a boolean (FileExists).
pub fn decode_bool_response(data: &[u8]) -> Result<bool, String> {
    if data.len() < 2 {
        return Err("truncated bool response".into());
    }
    match data[0] {
        STATUS_OK => Ok(data[1] != 0),
        STATUS_ERROR => {
            let (msg, _) = decode_bytes(data, 1)?;
            Err(String::from_utf8_lossy(msg).into_owned())
        }
        s => Err(format!("unexpected status: {s:#04x}")),
    }
}

/// One key-value pair as it comes off the wire, owned.
pub type KvPair = (Vec<u8>, Vec<u8>);

/// Decode a response that returns a list of key-value pairs (PrefixIter).
pub fn decode_kv_list_response(data: &[u8]) -> Result<Vec<KvPair>, String> {
    if data.is_empty() {
        return Err("empty response".into());
    }
    match data[0] {
        STATUS_OK => {
            if data.len() < 5 {
                return Err("truncated kv list response".into());
            }
            let count = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            let mut offset = 5;
            let mut pairs = Vec::with_capacity(count);
            for _ in 0..count {
                let (key, new_offset) = decode_bytes(data, offset)?;
                let (value, new_offset) = decode_bytes(data, new_offset)?;
                pairs.push((key.to_vec(), value.to_vec()));
                offset = new_offset;
            }
            Ok(pairs)
        }
        STATUS_ERROR => {
            let (msg, _) = decode_bytes(data, 1)?;
            Err(String::from_utf8_lossy(msg).into_owned())
        }
        s => Err(format!("unexpected status: {s:#04x}")),
    }
}

/// Decode a response that returns a list of keys (PrefixKeys).
pub fn decode_key_list_response(data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if data.is_empty() {
        return Err("empty response".into());
    }
    match data[0] {
        STATUS_OK => {
            if data.len() < 5 {
                return Err("truncated key list response".into());
            }
            let count = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            let mut offset = 5;
            let mut keys = Vec::with_capacity(count);
            for _ in 0..count {
                let (key, new_offset) = decode_bytes(data, offset)?;
                keys.push(key.to_vec());
                offset = new_offset;
            }
            Ok(keys)
        }
        STATUS_ERROR => {
            let (msg, _) = decode_bytes(data, 1)?;
            Err(String::from_utf8_lossy(msg).into_owned())
        }
        s => Err(format!("unexpected status: {s:#04x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_bytes() {
        let mut buf = Vec::new();
        encode_bytes(&mut buf, b"hello");
        let (decoded, offset) = decode_bytes(&buf, 0).unwrap();
        assert_eq!(decoded, b"hello");
        assert_eq!(offset, 9); // 4 + 5
    }

    #[test]
    fn test_encode_decode_keyspace() {
        let mut buf = Vec::new();
        encode_keyspace(&mut buf, "keys");
        let (decoded, offset) = decode_keyspace(&buf, 0).unwrap();
        assert_eq!(decoded, "keys");
        assert_eq!(offset, 6); // 2 + 4
    }

    #[test]
    fn test_get_request_roundtrip() {
        let req = build_get_request("myks", b"mykey");
        assert_eq!(req[0], OP_GET);
        let (ks, offset) = decode_keyspace(&req, 1).unwrap();
        assert_eq!(ks, "myks");
        let (key, _) = decode_bytes(&req, offset).unwrap();
        assert_eq!(key, b"mykey");
    }

    #[test]
    fn test_insert_request_roundtrip() {
        let req = build_insert_request("ks", b"k", b"v");
        assert_eq!(req[0], OP_INSERT);
        let (ks, offset) = decode_keyspace(&req, 1).unwrap();
        assert_eq!(ks, "ks");
        let (key, offset) = decode_bytes(&req, offset).unwrap();
        assert_eq!(key, b"k");
        let (value, _) = decode_bytes(&req, offset).unwrap();
        assert_eq!(value, b"v");
    }

    #[test]
    fn test_value_response_ok() {
        let resp = build_ok_value(b"data");
        let result = decode_value_response(&resp).unwrap();
        assert_eq!(result, Some(b"data".to_vec()));
    }

    #[test]
    fn test_value_response_not_found() {
        let resp = build_not_found();
        let result = decode_value_response(&resp).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_error_response() {
        let resp = build_error("something broke");
        let result = decode_value_response(&resp);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("something broke"));
    }

    #[test]
    fn test_kv_list_response() {
        let resp = build_ok_kv_list(&[(b"key1", b"val1"), (b"key2", b"val2")]);
        let pairs = decode_kv_list_response(&resp).unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], (b"key1".to_vec(), b"val1".to_vec()));
        assert_eq!(pairs[1], (b"key2".to_vec(), b"val2".to_vec()));
    }

    #[test]
    fn test_key_list_response() {
        let resp = build_ok_key_list(&[b"a", b"b", b"c"]);
        let keys = decode_key_list_response(&resp).unwrap();
        assert_eq!(keys, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    }

    #[test]
    fn test_bool_response() {
        assert!(decode_bool_response(&build_ok_bool(true)).unwrap());
        assert!(!decode_bool_response(&build_ok_bool(false)).unwrap());
    }
}
