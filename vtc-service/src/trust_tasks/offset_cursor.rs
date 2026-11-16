//! Offset cursors for list tasks that recompute their ordered result on
//! every call (badges, boards, elections).
//!
//! A cursor is `"{offset}.{tag}"`: the offset into the caller's ordered
//! result and an HMAC-SHA256 tag (128 bits) over the task family, the
//! binding (the caller and the question) and the offset, under a key only
//! this community holds. A cursor whose tag does not verify (edited,
//! minted for another caller or other filters, or made without the key) is
//! refused. The tag is compared in constant time.
//!
//! The key is the audit writer's active key, as the directory and group
//! cursors use (`vti_common::pagination::Cursor::encode_bound`). A
//! community with no audit writer uses a random key made once per process,
//! so its cursors stop verifying at a restart: a client then starts the
//! list again.
//!
//! A verified offset can still be past the end of the result, which may
//! have shrunk since the cursor was made. Callers clamp it ([`window`]).

use std::sync::OnceLock;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use vti_common::error::AppError;

use crate::server::AppState;

/// Bytes of the HMAC kept in a cursor.
const TAG_LEN: usize = 16;

/// The key this community's offset cursors are tagged under.
pub(crate) async fn key(state: &AppState) -> Result<[u8; 32], AppError> {
    if let Some(writer) = state.audit_writer.as_ref() {
        return Ok(writer.active_key().await?.key);
    }
    static PROCESS_KEY: OnceLock<[u8; 32]> = OnceLock::new();
    Ok(*PROCESS_KEY.get_or_init(|| {
        use rand::RngExt;
        let mut k = [0u8; 32];
        rand::rng().fill(&mut k);
        k
    }))
}

fn tag(key: &[u8; 32], family: &str, binding: &str, offset: usize) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(b"vtc/list-cursor/v2\0");
    for part in [family, binding, &offset.to_string()] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
    mac
}

/// The cursor naming `offset` in `family`'s list for `binding`.
pub(crate) fn mint(key: &[u8; 32], family: &str, binding: &str, offset: usize) -> String {
    let full = tag(key, family, binding, offset).finalize().into_bytes();
    format!("{offset}.{}", hex::encode(&full[..TAG_LEN]))
}

/// The offset `wire` names, if it is a cursor this community minted for
/// `family` and `binding`; `None` otherwise.
pub(crate) fn read(key: &[u8; 32], family: &str, binding: &str, wire: &str) -> Option<usize> {
    let (n, hex_tag) = wire.split_once('.')?;
    // Only the form `mint` writes: canonical decimal digits.
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let offset: usize = n.parse().ok()?;
    if offset.to_string() != n {
        return None;
    }
    let presented = hex::decode(hex_tag).ok()?;
    if presented.len() != TAG_LEN {
        return None;
    }
    tag(key, family, binding, offset)
        .verify_truncated_left(&presented)
        .ok()
        .map(|()| offset)
}

/// The `[start, end)` window of a page of at most `limit` items from
/// `offset`, within a result of `len` items. Never out of bounds, whatever
/// `offset` and `limit` are.
pub(crate) fn window(offset: usize, limit: usize, len: usize) -> (usize, usize) {
    let start = offset.min(len);
    (start, start.saturating_add(limit).min(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: [u8; 32] = [3u8; 32];

    #[test]
    fn a_minted_cursor_reads_back_for_its_binding_only() {
        let c = mint(&K, "badges", "list|did:key:zA", 50);
        assert_eq!(read(&K, "badges", "list|did:key:zA", &c), Some(50));
        assert_eq!(
            read(&K, "badges", "list|did:key:zB", &c),
            None,
            "another caller"
        );
        assert_eq!(
            read(&K, "boards", "list|did:key:zA", &c),
            None,
            "another family"
        );
        assert_eq!(
            read(&[4u8; 32], "badges", "list|did:key:zA", &c),
            None,
            "another key"
        );
    }

    #[test]
    fn an_edited_cursor_is_refused() {
        let c = mint(&K, "badges", "b", 50);
        let (_, t) = c.split_once('.').unwrap();
        for wire in [
            format!("51.{t}"),
            format!("{}.{t}", usize::MAX),
            format!("+50.{t}"),
            format!("050.{t}"),
            "50".to_string(),
            "50.".to_string(),
            format!("50.{}", &t[..t.len() - 2]),
            format!("50.{t}00"),
            "50.zz".to_string(),
        ] {
            assert_eq!(read(&K, "badges", "b", &wire), None, "{wire}");
        }
    }

    #[test]
    fn a_cursor_without_the_key_cannot_be_made() {
        // The old construction: an unkeyed digest anyone could compute.
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(b"vtc/badges/cursor/v1\0");
        for part in ["b", "1000000"] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part.as_bytes());
        }
        let unkeyed = format!("1000000.{}", hex::encode(&h.finalize()[..12]));
        assert_eq!(read(&K, "badges", "b", &unkeyed), None);
    }

    #[test]
    fn the_window_never_leaves_the_result() {
        assert_eq!(window(0, 50, 10), (0, 10));
        assert_eq!(window(5, 3, 10), (5, 8));
        assert_eq!(window(usize::MAX, 50, 10), (10, 10));
        assert_eq!(window(9, usize::MAX, 10), (9, 10));
        assert_eq!(window(usize::MAX, usize::MAX, 0), (0, 0));
    }
}
