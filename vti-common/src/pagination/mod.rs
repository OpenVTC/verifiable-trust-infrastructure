//! Cursor pagination — workspace-wide standard for every list
//! endpoint.
//!
//! Implements **M0.1.4** of the VTC MVP Phase 0 plan. The cursor
//! contract from spec §9.1:
//!
//! ```text
//! GET /v1/<collection>?cursor=<opaque>&limit=<1..200>
//!
//! → 200 OK
//! {
//!   "items":          [...],
//!   "nextCursor":     "<opaque>" | null,
//!   "total_estimate": <u64 | null>
//! }
//! ```
//!
//! ## Design properties
//!
//! - **Opaque to consumers.** The cursor is a base64url-encoded
//!   binary blob; clients pass it back verbatim. No public structure.
//! - **Tamper-evident.** The cursor's payload is HMAC-SHA256-signed
//!   under a per-maintainer 32-byte key. A cursor minted by one
//!   maintainer can't be replayed against another; a guessed cursor
//!   can't iterate past the protocol boundary. See [`Cursor::decode`]
//!   for the verification flow.
//!
//!   Where that key comes from depends on what the maintainer already
//!   has. The VTC signs under the active `audit_key` from its
//!   [`crate::audit::AuditKeyStore`]. A maintainer with no such store
//!   — the VTA keeps a flat audit log with no hash chain — uses
//!   [`CursorKey`], which persists a random key in a keyspace of the
//!   caller's choosing and is used for nothing but cursor MACs.
//! - **No structural feedback on failure.** A tampered, forged, or
//!   malformed cursor returns [`AppError::InvalidCursor`] (400) with
//!   no detail. The HMAC verification + payload deserialisation share
//!   a single error so the caller can't learn whether the tag check
//!   or the structure check rejected them.
//! - **`(last_key, snapshot_id)` payload.** `last_key` is the raw
//!   storage key of the last item the previous page returned;
//!   `snapshot_id` is the wall-clock timestamp at mint. The
//!   snapshot is carried through opaquely (no consistency check
//!   today — newly-inserted rows may or may not appear in the next
//!   page). Plumbing for it is in place so a future tightening can
//!   land without a wire-shape change.
//!
//! ## Limit bounds
//!
//! - **min**: 1 (a zero-limit request would never make progress).
//! - **max**: 200 — pinned in code per spec §9.1.
//! - **default**: 50 — the most common operator-facing list size.
//!
//! Larger reads should iterate via repeated `next_cursor` calls;
//! the maximum is non-negotiable to keep response sizes bounded.
//!
//! ## Storage iteration model
//!
//! For Phase 0, [`paginate`] takes the already-materialised list of
//! raw key/value pairs from [`crate::store::KeyspaceHandle::prefix_iter_raw`]
//! and walks them in-memory. That's O(N) per page but bounded by the
//! community's keyspace size — adequate for the small lists (members,
//! join requests, policies, audit) that Phase 0 ships. A cursor-aware
//! `prefix_iter_after` method on `KeyspaceHandle` is the natural
//! follow-up if community sizes outgrow this; the wire shape doesn't
//! change.

use std::io::{Cursor as IoCursor, Read};

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::AppError;
use crate::store::RawKvPair;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// HMAC tag length in bytes. 32 (full SHA-256 output) — overhead is
/// trivial relative to base64-encoded cursors and removes any
/// concern about short-tag birthday-style attacks.
const HMAC_TAG_LEN: usize = 32;

/// Maximum cursor `last_key` length to accept on decode. Prevents an
/// adversary from supplying a multi-megabyte cursor that allocates
/// inflated buffers. Keyspace keys in the workspace are well under
/// this in practice.
const MAX_LAST_KEY_LEN: u32 = 1024;

/// Minimum list-page size accepted from query params. See module docs.
pub const MIN_LIMIT: usize = 1;
/// Maximum list-page size accepted from query params. See module docs.
pub const MAX_LIMIT: usize = 200;
/// Default page size when the caller omits `limit`. See module docs.
pub const DEFAULT_LIMIT: usize = 50;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Query params + response wrapper
// ---------------------------------------------------------------------------

/// Standard query-param shape for list endpoints. Bind this in a
/// handler with `Query<PaginationParams>` and pass `cursor` /
/// `limit` to [`paginate`].
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PaginationParams {
    /// Opaque cursor returned by the previous page's `next_cursor`.
    /// `None` requests the first page.
    pub cursor: Option<String>,
    /// Caller-requested page size. Clamped to `[MIN_LIMIT, MAX_LIMIT]`
    /// before use; `None` falls back to [`DEFAULT_LIMIT`].
    pub limit: Option<usize>,
}

impl PaginationParams {
    /// Apply the workspace's clamping rules. Always returns a valid
    /// limit in `[MIN_LIMIT, MAX_LIMIT]`.
    pub fn effective_limit(&self) -> usize {
        self.limit
            .unwrap_or(DEFAULT_LIMIT)
            .clamp(MIN_LIMIT, MAX_LIMIT)
    }
}

/// Standard response wrapper for list endpoints. Carries the
/// requested page of items, the opaque cursor for the next page
/// (`None` when the caller has reached the end), and an optional
/// total-count estimate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Paginated<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_estimate: Option<u64>,
}

// ---------------------------------------------------------------------------
// Cursor — internal payload + signed wire form
// ---------------------------------------------------------------------------

/// Decoded cursor payload. Public so callers that want the raw
/// `last_key` (e.g. for debugging or custom iteration) can inspect
/// it. Never construct one directly off the wire — use
/// [`Cursor::decode`] so the HMAC tag gets verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    /// Raw fjall storage key of the last item the previous page
    /// returned. The next page begins **strictly after** this key.
    pub last_key: Vec<u8>,
    /// Unix-second timestamp at the time of minting. Currently
    /// opaque metadata — see module docs.
    pub snapshot_id: u64,
}

impl Cursor {
    /// Construct a cursor for the page that ends at `last_key`.
    pub fn new(last_key: Vec<u8>, snapshot_id: u64) -> Self {
        Self {
            last_key,
            snapshot_id,
        }
    }

    /// Encode + sign the cursor under `audit_key`. Returns the
    /// base64url-encoded wire form ready for `next_cursor`.
    pub fn encode(&self, audit_key: &[u8; 32]) -> String {
        self.encode_bound(audit_key, &[])
    }

    /// As [`Cursor::encode`], but additionally binds `binding` into the
    /// HMAC — without placing it on the wire.
    ///
    /// This is how a paginated query pins the filters a cursor was minted
    /// under. The bytes are covered by the tag but not transmitted, so the
    /// wire format is unchanged and a caller cannot rewrite them. Resuming
    /// with a *different* binding fails verification and surfaces as
    /// [`AppError::InvalidCursor`], which is what stops a consumer from
    /// paging with one filter set and continuing with another — a silent
    /// way to skip entries that must never happen on an audit log.
    ///
    /// Callers with no binding use [`Cursor::encode`], which passes an
    /// empty slice and is therefore wire- and tag-compatible with cursors
    /// minted before this method existed.
    pub fn encode_bound(&self, audit_key: &[u8; 32], binding: &[u8]) -> String {
        let mut buf = Vec::with_capacity(4 + self.last_key.len() + 8 + HMAC_TAG_LEN);
        buf.extend_from_slice(&(self.last_key.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.last_key);
        buf.extend_from_slice(&self.snapshot_id.to_be_bytes());

        let mut mac = HmacSha256::new_from_slice(audit_key).expect("32-byte HMAC key");
        mac.update(&buf);
        mac.update(binding);
        let tag = mac.finalize().into_bytes();
        buf.extend_from_slice(&tag);

        B64.encode(&buf)
    }

    /// Decode + verify a wire-form cursor. Returns
    /// [`AppError::InvalidCursor`] on any failure (malformed,
    /// tampered, or signed under a different key) — the error
    /// deliberately doesn't reveal which.
    pub fn decode(wire: &str, audit_key: &[u8; 32]) -> Result<Self, AppError> {
        Self::decode_bound(wire, audit_key, &[])
    }

    /// As [`Cursor::decode`], but requires the cursor to have been minted
    /// with the same `binding` (see [`Cursor::encode_bound`]). A mismatch
    /// is indistinguishable from a tampered cursor and yields
    /// [`AppError::InvalidCursor`].
    pub fn decode_bound(
        wire: &str,
        audit_key: &[u8; 32],
        binding: &[u8],
    ) -> Result<Self, AppError> {
        let raw = B64.decode(wire).map_err(|_| AppError::InvalidCursor)?;
        if raw.len() <= HMAC_TAG_LEN + 4 + 8 {
            return Err(AppError::InvalidCursor);
        }

        let payload_len = raw.len() - HMAC_TAG_LEN;
        let payload = &raw[..payload_len];
        let received_tag = &raw[payload_len..];

        let mut mac = HmacSha256::new_from_slice(audit_key).expect("32-byte HMAC key");
        mac.update(payload);
        mac.update(binding);
        mac.verify_slice(received_tag)
            .map_err(|_| AppError::InvalidCursor)?;

        let mut reader = IoCursor::new(payload);
        let mut key_len_buf = [0u8; 4];
        reader
            .read_exact(&mut key_len_buf)
            .map_err(|_| AppError::InvalidCursor)?;
        let key_len = u32::from_be_bytes(key_len_buf);
        if key_len > MAX_LAST_KEY_LEN {
            return Err(AppError::InvalidCursor);
        }

        let mut last_key = vec![0u8; key_len as usize];
        reader
            .read_exact(&mut last_key)
            .map_err(|_| AppError::InvalidCursor)?;

        let mut snapshot_buf = [0u8; 8];
        reader
            .read_exact(&mut snapshot_buf)
            .map_err(|_| AppError::InvalidCursor)?;
        let snapshot_id = u64::from_be_bytes(snapshot_buf);

        // Reject trailing garbage so a tampered cursor with a valid
        // suffix tag can't sneak through.
        if reader.position() as usize != payload_len {
            return Err(AppError::InvalidCursor);
        }

        Ok(Self {
            last_key,
            snapshot_id,
        })
    }
}

// ---------------------------------------------------------------------------
// CursorKey — signing key for maintainers with no audit-key store
// ---------------------------------------------------------------------------

/// Storage key the [`CursorKey`] material lives under. Deliberately
/// namespaced away from any `log:` / `audit_key:` prefix so a cursor
/// key can share a keyspace with the rows it paginates.
const CURSOR_KEY_STORAGE_KEY: &[u8] = b"pagination:cursor_key/v1";

/// A keyspace-persisted 32-byte HMAC key for signing pagination
/// cursors.
///
/// The VTC signs its cursors under the active `audit_key` from its
/// [`crate::audit::AuditKeyStore`]. The VTA has no such store — it
/// keeps a flat append-only log with no hash chain — but canonical
/// `audit/list` still requires cursors that cannot be forged into a
/// position the filters did not authorize. This is the minimum that
/// buys: a random key, generated once and persisted, used for nothing
/// but cursor MACs.
///
/// **Not** derived from the master seed. A cursor is ephemeral and
/// carries no long-term secret, so seed derivation would only widen
/// the seed's blast radius for no benefit; and a key that is *not*
/// reproduced by a backup+restore is the safer default, since a
/// cursor minted against one database should not silently resolve to
/// a position in another.
#[derive(Clone)]
pub struct CursorKey {
    ks: crate::store::KeyspaceHandle,
}

impl CursorKey {
    /// Wrap a keyspace. The key is created lazily on first [`Self::get`].
    pub fn new(ks: crate::store::KeyspaceHandle) -> Self {
        Self { ks }
    }

    /// Read the signing key, generating and persisting one if this is
    /// the first call against a fresh store.
    ///
    /// Creation is atomic via
    /// [`crate::store::KeyspaceHandle::insert_raw_if_absent`]: a
    /// concurrent creator loses the race and re-reads the winner's
    /// key, so two requests arriving together never mint cursors under
    /// different keys.
    pub async fn get(&self) -> Result<[u8; 32], AppError> {
        if let Some(existing) = self.read().await? {
            return Ok(existing);
        }

        let mut fresh = [0u8; 32];
        rand::fill(&mut fresh);
        self.ks
            .insert_raw_if_absent(CURSOR_KEY_STORAGE_KEY.to_vec(), fresh.to_vec())
            .await?;

        // Re-read unconditionally rather than trusting the bool: on a
        // lost race the winner's key is the one every other request is
        // already signing under.
        self.read().await?.ok_or_else(|| {
            AppError::Internal("cursor key vanished immediately after creation".into())
        })
    }

    async fn read(&self) -> Result<Option<[u8; 32]>, AppError> {
        let Some(raw) = self.ks.get_raw(CURSOR_KEY_STORAGE_KEY.to_vec()).await? else {
            return Ok(None);
        };
        let key: [u8; 32] = raw.try_into().map_err(|_| {
            AppError::Internal("stored cursor key is not 32 bytes; refusing to sign".into())
        })?;
        Ok(Some(key))
    }
}

// ---------------------------------------------------------------------------
// paginate helper
// ---------------------------------------------------------------------------

/// Paginate a materialised list of `(key, value)` pairs. The pairs
/// are walked in **caller-provided order** — typically the result of
/// `prefix_iter_raw`, which returns lexicographically-ordered keys
/// for fjall keyspaces.
///
/// Behaviour:
///
/// - When `cursor` is `Some`, skips entries with key `<= cursor.last_key`.
/// - Takes up to `limit` entries.
/// - If more entries remain after `limit`, sets `next_cursor` to a
///   freshly-signed cursor whose `last_key` is the last entry the
///   caller saw.
/// - Maps each entry's value bytes via `map_value`. Any per-row
///   deserialisation error short-circuits with that row's error;
///   callers that want resilience against bad rows should do the
///   filtering themselves before calling this.
///
/// `audit_key` signs minted cursors; `snapshot_id` is the wall-clock
/// the new cursor will carry (callers usually pass `Utc::now()` /
/// `chrono::Utc::now().timestamp().max(0) as u64`).
pub fn paginate<T, F>(
    pairs: Vec<RawKvPair>,
    cursor: Option<&Cursor>,
    limit: usize,
    audit_key: &[u8; 32],
    snapshot_id: u64,
    mut map_value: F,
) -> Result<Paginated<T>, AppError>
where
    F: FnMut(&[u8]) -> Result<T, AppError>,
{
    let limit = limit.clamp(MIN_LIMIT, MAX_LIMIT);

    let start = match cursor {
        Some(c) => {
            // Find the first pair whose key is strictly greater than
            // `last_key`. Linear scan is fine for Phase 0 list sizes;
            // see module docs for the long-term plan.
            pairs
                .iter()
                .position(|(k, _)| k.as_slice() > c.last_key.as_slice())
                .unwrap_or(pairs.len())
        }
        None => 0,
    };

    let mut items = Vec::with_capacity(limit.min(pairs.len().saturating_sub(start)));
    let mut idx = start;
    let mut last_seen_key: Option<Vec<u8>> = None;

    while items.len() < limit && idx < pairs.len() {
        let (key, value) = &pairs[idx];
        items.push(map_value(value)?);
        last_seen_key = Some(key.clone());
        idx += 1;
    }

    let next_cursor = if idx < pairs.len() {
        last_seen_key.map(|k| Cursor::new(k, snapshot_id).encode(audit_key))
    } else {
        None
    };

    Ok(Paginated {
        items,
        next_cursor,
        total_estimate: None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: [u8; 32] = [0xAA; 32];
    const KEY_B: [u8; 32] = [0xBB; 32];

    fn temp_ks() -> (crate::store::KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = crate::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = crate::store::Store::open(&cfg).expect("store");
        let ks = store.keyspace("cursor-key-test").expect("keyspace");
        (ks, dir)
    }

    /// The key must be stable across calls — a key regenerated per
    /// request would invalidate every cursor the moment it was handed
    /// out, so pagination would never advance past page one.
    #[tokio::test]
    async fn cursor_key_is_created_once_and_reused() {
        let (ks, _dir) = temp_ks();

        let first = CursorKey::new(ks.clone()).get().await.expect("mint");
        let second = CursorKey::new(ks.clone()).get().await.expect("reuse");
        assert_eq!(first, second);
        assert_ne!(first, [0u8; 32], "the key must be random, not zeroed");

        // A cursor minted under it survives a round trip through a
        // freshly-constructed handle over the same keyspace.
        let c = Cursor::new(b"log:00000000000000000001:abc".to_vec(), 1);
        let wire = c.encode_bound(&first, b"binding");
        assert_eq!(Cursor::decode_bound(&wire, &second, b"binding").unwrap(), c);
    }

    /// The key must survive an **encrypted** keyspace.
    ///
    /// This is the deployment case, not an edge case: the VTA's audit
    /// keyspace — where this key lives — is encrypted at rest. The key
    /// is stored via the raw byte API and read back with a 32-byte
    /// `try_into`, so if encrypt-on-write and decrypt-on-read were not
    /// symmetric the read would see ciphertext of the wrong length and
    /// every audit list call would fail. A plaintext-only test would
    /// never show it.
    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn cursor_key_round_trips_through_an_encrypted_keyspace() {
        let (ks, _dir) = temp_ks();
        let ks = ks.with_encryption([0x5A; 32]);
        assert!(
            ks.is_encrypted(),
            "the test must exercise the encrypted path"
        );

        let first = CursorKey::new(ks.clone()).get().await.expect("mint");
        let second = CursorKey::new(ks).get().await.expect("read back");
        assert_eq!(first, second, "the key must survive the encryption layer");
        assert_ne!(first, [0u8; 32]);
    }

    /// Two keyspaces are two independent keys, so a cursor cannot be
    /// replayed from one store against another.
    #[tokio::test]
    async fn cursor_keys_are_per_keyspace() {
        let (ks_a, _a) = temp_ks();
        let (ks_b, _b) = temp_ks();

        let key_a = CursorKey::new(ks_a).get().await.expect("a");
        let key_b = CursorKey::new(ks_b).get().await.expect("b");
        assert_ne!(key_a, key_b);

        let wire = Cursor::new(b"log:1:x".to_vec(), 1).encode(&key_a);
        assert!(matches!(
            Cursor::decode(&wire, &key_b),
            Err(AppError::InvalidCursor)
        ));
    }

    /// A bound cursor only decodes under the same binding. This is what
    /// stops a filtered listing from being resumed under different
    /// filters — a silent way to skip entries.
    #[test]
    fn a_bound_cursor_rejects_a_different_binding() {
        let c = Cursor::new(b"audit:2026-01-01:abc".to_vec(), 7);
        let wire = c.encode_bound(&KEY_A, b"action=MemberAdded");

        assert_eq!(
            Cursor::decode_bound(&wire, &KEY_A, b"action=MemberAdded").unwrap(),
            c
        );
        assert!(matches!(
            Cursor::decode_bound(&wire, &KEY_A, b"action=MemberRemoved"),
            Err(AppError::InvalidCursor)
        ));
        // Dropping the binding entirely is also a change.
        assert!(matches!(
            Cursor::decode(&wire, &KEY_A),
            Err(AppError::InvalidCursor)
        ));
        // And the key still has to match.
        assert!(matches!(
            Cursor::decode_bound(&wire, &KEY_B, b"action=MemberAdded"),
            Err(AppError::InvalidCursor)
        ));
    }

    /// Unbound encode/decode must stay byte-compatible with cursors
    /// minted before binding existed, so other paginated endpoints
    /// (e.g. policy list) are unaffected.
    #[test]
    fn an_unbound_cursor_round_trips_as_before() {
        let c = Cursor::new(b"policy:001".to_vec(), 3);
        let wire = c.encode(&KEY_A);
        assert_eq!(Cursor::decode(&wire, &KEY_A).unwrap(), c);
        assert_eq!(wire, c.encode_bound(&KEY_A, &[]));
    }

    fn make_pairs(count: usize) -> Vec<RawKvPair> {
        (0..count)
            .map(|i| {
                (
                    format!("item:{i:03}").into_bytes(),
                    format!(r#"{{"n":{i}}}"#).into_bytes(),
                )
            })
            .collect()
    }

    fn deserialize_value(bytes: &[u8]) -> Result<serde_json::Value, AppError> {
        serde_json::from_slice(bytes)
            .map_err(|e| AppError::Internal(format!("test value deserialize failed: {e}")))
    }

    // ──────────── Cursor encode/decode ────────────

    #[test]
    fn cursor_round_trips_through_encode_decode() {
        let c = Cursor::new(b"member:did:key:z6Mk".to_vec(), 1_700_000_000);
        let wire = c.encode(&KEY_A);
        let back = Cursor::decode(&wire, &KEY_A).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn cursor_decoded_with_different_key_is_rejected() {
        let c = Cursor::new(b"x".to_vec(), 42);
        let wire = c.encode(&KEY_A);
        let err = Cursor::decode(&wire, &KEY_B).expect_err("must reject");
        assert!(matches!(err, AppError::InvalidCursor));
    }

    /// End-to-end mapping: a cursor minted under one community's
    /// audit key (or under a community's pre-rotation key) MUST
    /// produce HTTP 400 when handed to a route running with a
    /// different active key. The unit test above proves the
    /// `Cursor::decode` arithmetic; this one nails the wire layer
    /// by walking through the `IntoResponse` impl so a future
    /// regression in `AppError`'s status mapping (or a misguided
    /// "treat invalid cursor as empty page" refactor) fails here.
    #[test]
    fn foreign_audit_key_cursor_maps_to_http_400() {
        use axum::response::IntoResponse;

        let c = Cursor::new(b"member:did:key:zAttacker".to_vec(), 17);
        let wire = c.encode(&KEY_A);
        let err = Cursor::decode(&wire, &KEY_B).expect_err("must reject");
        let response = err.into_response();
        assert_eq!(response.status(), 400);
    }

    #[test]
    fn cursor_with_tampered_payload_is_rejected() {
        let c = Cursor::new(b"safe-key".to_vec(), 1);
        let wire = c.encode(&KEY_A);
        // Mutate one byte of the base64 form (not the trailing tag)
        // and expect rejection.
        let mut bytes = B64.decode(&wire).unwrap();
        bytes[5] ^= 0xFF;
        let tampered = B64.encode(&bytes);
        let err = Cursor::decode(&tampered, &KEY_A).expect_err("tampered");
        assert!(matches!(err, AppError::InvalidCursor));
    }

    #[test]
    fn cursor_malformed_base64_is_rejected() {
        for bad in ["", "not!base64", "AAAA"] {
            let err = Cursor::decode(bad, &KEY_A).expect_err("malformed");
            assert!(matches!(err, AppError::InvalidCursor), "input {bad}");
        }
    }

    #[test]
    fn cursor_with_oversized_key_length_is_rejected() {
        // Construct a wire form claiming a huge last_key length.
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::MAX.to_be_bytes());
        payload.extend_from_slice(&0u64.to_be_bytes());
        let mut mac = HmacSha256::new_from_slice(&KEY_A).unwrap();
        mac.update(&payload);
        let tag = mac.finalize().into_bytes();
        payload.extend_from_slice(&tag);
        let wire = B64.encode(&payload);
        let err = Cursor::decode(&wire, &KEY_A).expect_err("oversized");
        assert!(matches!(err, AppError::InvalidCursor));
    }

    // ──────────── paginate ────────────

    #[test]
    fn paginate_first_page_no_cursor() {
        let pairs = make_pairs(7);
        let out: Paginated<serde_json::Value> =
            paginate(pairs, None, 3, &KEY_A, 100, deserialize_value).unwrap();
        assert_eq!(out.items.len(), 3);
        assert_eq!(out.items[0]["n"], 0);
        assert_eq!(out.items[2]["n"], 2);
        assert!(out.next_cursor.is_some());
    }

    #[test]
    fn paginate_walks_entire_collection_without_duplicates() {
        let pairs = make_pairs(7);
        let mut cursor: Option<Cursor> = None;
        let mut seen = Vec::new();
        for _ in 0..5 {
            let out: Paginated<serde_json::Value> = paginate(
                pairs.clone(),
                cursor.as_ref(),
                3,
                &KEY_A,
                100,
                deserialize_value,
            )
            .unwrap();
            for item in &out.items {
                seen.push(item["n"].as_u64().unwrap());
            }
            match out.next_cursor {
                Some(wire) => cursor = Some(Cursor::decode(&wire, &KEY_A).unwrap()),
                None => break,
            }
        }
        assert_eq!(seen, (0..7).collect::<Vec<_>>());
    }

    #[test]
    fn paginate_last_page_returns_no_next_cursor() {
        let pairs = make_pairs(3);
        let out: Paginated<serde_json::Value> =
            paginate(pairs, None, 10, &KEY_A, 100, deserialize_value).unwrap();
        assert_eq!(out.items.len(), 3);
        assert!(out.next_cursor.is_none(), "last page must not link onward");
    }

    #[test]
    fn paginate_clamps_limit() {
        let pairs = make_pairs(500);
        let out: Paginated<serde_json::Value> =
            paginate(pairs, None, 9_999, &KEY_A, 100, deserialize_value).unwrap();
        assert_eq!(out.items.len(), MAX_LIMIT);
    }

    #[test]
    fn paginate_skips_past_cursor_key_exclusive() {
        let pairs = make_pairs(5);
        let cursor = Cursor::new(b"item:001".to_vec(), 1);
        let out: Paginated<serde_json::Value> =
            paginate(pairs, Some(&cursor), 10, &KEY_A, 100, deserialize_value).unwrap();
        // We saw item:000 + item:001 → next page begins at item:002.
        let ns: Vec<_> = out.items.iter().map(|v| v["n"].as_u64().unwrap()).collect();
        assert_eq!(ns, vec![2, 3, 4]);
    }

    #[test]
    fn paginate_returns_empty_when_cursor_already_past_end() {
        let pairs = make_pairs(3);
        let cursor = Cursor::new(b"zzz".to_vec(), 1);
        let out: Paginated<serde_json::Value> =
            paginate(pairs, Some(&cursor), 10, &KEY_A, 100, deserialize_value).unwrap();
        assert!(out.items.is_empty());
        assert!(out.next_cursor.is_none());
    }

    #[test]
    fn pagination_params_effective_limit_clamps_and_defaults() {
        assert_eq!(
            PaginationParams {
                cursor: None,
                limit: None,
            }
            .effective_limit(),
            DEFAULT_LIMIT
        );
        assert_eq!(
            PaginationParams {
                cursor: None,
                limit: Some(0),
            }
            .effective_limit(),
            MIN_LIMIT
        );
        assert_eq!(
            PaginationParams {
                cursor: None,
                limit: Some(9999),
            }
            .effective_limit(),
            MAX_LIMIT
        );
        assert_eq!(
            PaginationParams {
                cursor: None,
                limit: Some(50),
            }
            .effective_limit(),
            50
        );
    }
}
