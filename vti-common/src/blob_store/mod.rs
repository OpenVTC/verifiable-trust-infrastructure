//! Where a data room's files live: a node-neutral store of opaque, already
//! encrypted blobs.
//!
//! A room file is a record plus a blob (`docs/05-design-notes/data-rooms-files.md`
//! §2). The record stays in the room's own keyspaces; the blob is the file's
//! ciphertext, too large for a record and too large for one Trust Task document,
//! so it lives in a [`BlobStore`]. Nothing here knows what a blob contains: the
//! bytes are ciphertext a host cannot open, and every check that matters — that
//! these are the bytes the uploader committed to — is made against digests before
//! a store ever sees them.
//!
//! Beside [`crate::backup_transfer`], for the same reason that module is here:
//! a standalone room host and a community both store room files, and the store
//! they write to is one implementation with one conformance suite
//! ([`conformance`]) rather than two that drift.
//!
//! # Backends
//!
//! - [`local::LocalDirStore`] — plain files under a directory. Always compiled,
//!   no extra dependencies, and the default.
//! - [`object::ObjectStoreBlobs`] — S3-compatible stores (feature `blob-s3`) and
//!   Google Cloud Storage (feature `blob-gcs`), through the `object_store` crate.
//!   Credentials come from the environment for now; the VTA-issued, room-scoped
//!   credentials of design note §7.4 plug in later through its credential
//!   provider.
//!
//! # Keys
//!
//! A blob is stored under [`BlobKey::for_room`]: `rooms/<first 32 hex of
//! SHA-256(roomId)>/<blobRef>`. The store learns which blobs belong together,
//! which the host knows anyway, but never a room's identifier — and a per-room
//! prefix is what lets a credential be downscoped to one room (§7.4).

use std::path::Path;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AppError;

pub mod local;

#[cfg(any(feature = "blob-s3", feature = "blob-gcs"))]
pub mod object;

#[cfg(any(test, feature = "test-support"))]
pub mod conformance;

/// The largest blob any store accepts: 4096 chunks of at most 256 KiB, the
/// chunked-transfer ceiling (`vta/_shared/0.1/backup-transfer`). A room's own
/// limits may be lower, never higher.
pub const MAX_BLOB_BYTES: u64 = 4_096 * 262_144;

/// Where a blob is stored within a store: a `/`-separated relative path.
///
/// Only [`BlobKey::for_room`] constructs one, from a validated BlobRef, so a key
/// can never carry `..`, an absolute path or a character a store would treat
/// specially. Scope values are built from validated identifiers, never
/// interpolated from caller strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlobKey(String);

impl BlobKey {
    /// The key for `blob_ref` in `room_id`.
    ///
    /// Refuses a BlobRef that is not a plain multibase string (`z` base58btc or
    /// `u` base64url-no-pad, the two encodings a `DigestMultibase` may use),
    /// which is also what keeps it a single safe path segment.
    pub fn for_room(room_id: &str, blob_ref: &str) -> Result<Self, AppError> {
        validate_blob_ref(blob_ref)?;
        Ok(Self(format!("{}{blob_ref}", room_prefix(room_id))))
    }

    /// The key as a relative path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The per-room prefix every blob of `room_id` is stored under, ending in `/`.
///
/// The first 32 hex characters of SHA-256(roomId): enough that two rooms do not
/// collide, and not the room's identifier.
pub fn room_prefix(room_id: &str) -> String {
    let digest = Sha256::digest(room_id.as_bytes());
    let mut hex = String::with_capacity(32);
    for b in &digest[..16] {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("rooms/{hex}/")
}

/// Refuse anything that is not a well-formed, sha2-256 `DigestMultibase`.
///
/// A BlobRef is the digest of a manifest, so a value that does not decode as one
/// names no blob at all.
pub fn validate_blob_ref(blob_ref: &str) -> Result<(), AppError> {
    let well_formed = blob_ref.len() <= 128
        && match blob_ref.as_bytes().first() {
            Some(b'z') => blob_ref[1..]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() && !matches!(c, b'0' | b'O' | b'I' | b'l')),
            Some(b'u') => blob_ref[1..]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
            _ => false,
        };
    if !well_formed || sha256_from_digest_multibase(blob_ref).is_none() {
        return Err(AppError::Validation(format!(
            "`{blob_ref}` is not a sha2-256 DigestMultibase"
        )));
    }
    Ok(())
}

/// The BlobRef of `manifest`: the sha2-256 `DigestMultibase` of its RFC 8785
/// (JCS) canonicalization (`rooms/_shared/0.1/blobs.schema.json`, `BlobRef`).
///
/// Computed by the host from the manifest it received, never taken from the
/// uploader, so the name a blob is stored under is the digest of what was
/// committed.
pub fn blob_ref_of_manifest(manifest: &serde_json::Value) -> Result<String, AppError> {
    let canonical = serde_json_canonicalizer::to_vec(manifest)
        .map_err(|e| AppError::Validation(format!("manifest cannot be canonicalised: {e}")))?;
    Ok(sha256_digest_multibase(&Sha256::digest(&canonical).into()))
}

/// Encode 32 SHA-256 bytes as a base58btc sha2-256 `DigestMultibase`.
pub fn sha256_digest_multibase(digest: &[u8; 32]) -> String {
    vta_sdk::protocols::backup_management::chunked::sha256_digest_multibase(digest)
}

/// Decode a sha2-256 `DigestMultibase` to its 32 bytes, in either permitted
/// base. `None` for any other hash, so an unknown algorithm is a refusal rather
/// than a skipped check.
pub fn sha256_from_digest_multibase(value: &str) -> Option<[u8; 32]> {
    vta_sdk::protocols::backup_management::chunked::sha256_from_digest_multibase(value)
}

/// What a store hands back for a stored blob, and what every later operation on
/// it is addressed by. Persisted in the host's blob index, so a store can be
/// reconfigured without losing track of what it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendRef {
    /// The store kind that wrote it (`local`, `s3`, `gcs`).
    pub kind: String,
    /// Where it was written.
    pub key: BlobKey,
}

/// What deleting a blob achieved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deletion {
    /// Gone from the store, or already was.
    Deleted,
    /// The store keeps it until a time it controls (a lease that is not
    /// renewed); it is unreadable to members once the room's keys are pruned.
    Lapses { at: chrono::DateTime<chrono::Utc> },
    /// The store cannot delete.
    Unsupported,
}

/// A store's own account of whether it is working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    pub ok: bool,
    /// What went wrong, verbatim from the store, when it is not.
    pub detail: Option<String>,
}

/// A store of opaque blobs, one instance per storage configuration.
///
/// # Contract
///
/// Every implementation passes [`conformance::run`]. In particular:
///
/// - [`put`](BlobStore::put) is **idempotent on the key**: storing the same
///   staged bytes under the same key again succeeds and changes nothing. Keys are
///   content addresses, so the same key always means the same bytes.
/// - [`get_range`](BlobStore::get_range) returns exactly `end - start` bytes or
///   fails; a short read is an error, never a shorter chunk.
/// - [`delete`](BlobStore::delete) of an absent blob is
///   [`Deletion::Deleted`], so a retried collection does not fail.
/// - A blob that is not there is [`AppError::NotFound`].
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// The kind this store records in its [`BackendRef`]s.
    fn kind(&self) -> &'static str;

    /// Store the `size` bytes staged at `staged` under `key`, durably, before
    /// returning.
    async fn put(&self, key: &BlobKey, staged: &Path, size: u64) -> Result<BackendRef, AppError>;

    /// Bytes `[start, end)` of the blob at `at`.
    async fn get_range(&self, at: &BackendRef, start: u64, end: u64) -> Result<Vec<u8>, AppError>;

    /// Remove the blob at `at`.
    async fn delete(&self, at: &BackendRef) -> Result<Deletion, AppError>;

    /// Whether the store is reachable and writable.
    async fn health(&self) -> Health;
}

/// Refuse a [`BackendRef`] written by a different kind of store. A blob index
/// naming the wrong store is a configuration mistake, and reading a key from
/// the wrong place would serve somebody else's bytes or nothing.
pub(crate) fn check_kind(store: &dyn BlobStore, at: &BackendRef) -> Result<(), AppError> {
    if at.kind != store.kind() {
        return Err(AppError::Internal(format!(
            "blob `{}` was stored by a `{}` store, not this `{}` one",
            at.key.as_str(),
            at.kind,
            store.kind()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_ref() -> String {
        sha256_digest_multibase(&[7u8; 32])
    }

    #[test]
    fn room_prefix_hides_the_room_and_is_stable() {
        let p = room_prefix("did:webvh:QmRoom:example.com:room");
        assert!(p.starts_with("rooms/") && p.ends_with('/'));
        assert_eq!(p.len(), "rooms/".len() + 32 + 1);
        assert!(!p.contains("example"));
        assert_eq!(p, room_prefix("did:webvh:QmRoom:example.com:room"));
        assert_ne!(p, room_prefix("did:webvh:QmOther:example.com:room"));
    }

    #[test]
    fn a_key_is_built_only_from_a_real_digest() {
        let key = BlobKey::for_room("did:key:zRoom", &a_ref()).unwrap();
        assert!(key.as_str().ends_with(&a_ref()));
        for bad in [
            "",
            "../etc/passwd",
            "zQm/../x",
            "sha256:abcd",
            "z0OIl",
            "uAAAA",
        ] {
            assert!(BlobKey::for_room("did:key:zRoom", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn blob_ref_is_over_the_canonical_form() {
        let a = serde_json::json!({"size": 5, "digest": "zX", "chunks": {"chunkSize": 16384}});
        let b: serde_json::Value =
            serde_json::from_str(r#"{"chunks":{"chunkSize":16384},"digest":"zX","size":5}"#)
                .unwrap();
        assert_eq!(
            blob_ref_of_manifest(&a).unwrap(),
            blob_ref_of_manifest(&b).unwrap()
        );
        validate_blob_ref(&blob_ref_of_manifest(&a).unwrap()).unwrap();
    }
}
