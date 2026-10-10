//! The behaviour every [`BlobStore`] must have, as one suite any backend runs.
//!
//! A backend's own test calls [`run`] with a fresh store and a scratch
//! directory. The suite is the contract in [`BlobStore`]'s documentation, so a
//! new backend is conforming when this passes and not before.

use std::path::Path;

use super::{BlobKey, BlobStore, Deletion, sha256_digest_multibase};
use crate::error::AppError;

/// Run every conformance check against `store`, staging files under `scratch`.
///
/// Panics on the first failure, naming the property that failed.
pub async fn run(store: &dyn BlobStore, scratch: &Path) {
    let room = "did:key:zConformanceRoom";
    let bytes: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    let staged = scratch.join(format!("conformance-{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&staged, &bytes).await.expect("stage");
    let key = BlobKey::for_room(room, &sha256_digest_multibase(&[0xA5; 32])).unwrap();

    assert!(
        store.health().await.ok,
        "a fresh store reports itself healthy"
    );

    // Stored, and readable by range.
    let at = store
        .put(&key, &staged, bytes.len() as u64)
        .await
        .expect("put stores a staged blob");
    assert_eq!(
        at.kind,
        store.kind(),
        "a BackendRef names the store that wrote it"
    );
    assert_eq!(
        store.get_range(&at, 0, 16_384).await.unwrap(),
        bytes[..16_384],
        "the first range"
    );
    assert_eq!(
        store.get_range(&at, 65_536, 70_000).await.unwrap(),
        bytes[65_536..],
        "a final, short range"
    );
    assert!(
        store.get_range(&at, 65_536, 70_001).await.is_err(),
        "a range past the end is an error, never a short read"
    );

    // Idempotent on the key.
    let again = store
        .put(&key, &staged, bytes.len() as u64)
        .await
        .expect("putting the same blob again succeeds");
    assert_eq!(again, at, "and names the same place");
    assert_eq!(store.get_range(&at, 0, 4).await.unwrap(), bytes[..4]);

    // A second blob does not disturb the first.
    let other_key = BlobKey::for_room(room, &sha256_digest_multibase(&[0x5A; 32])).unwrap();
    let other_staged = scratch.join(format!("conformance-{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&other_staged, b"other").await.unwrap();
    let other = store.put(&other_key, &other_staged, 5).await.unwrap();
    assert_eq!(store.get_range(&other, 0, 5).await.unwrap(), b"other");
    assert_eq!(store.get_range(&at, 0, 4).await.unwrap(), bytes[..4]);

    // Deleted, and deleting again is not a failure.
    assert_eq!(store.delete(&at).await.unwrap(), Deletion::Deleted);
    assert!(
        matches!(store.get_range(&at, 0, 4).await, Err(AppError::NotFound(_))),
        "a deleted blob is not found"
    );
    assert_eq!(
        store.delete(&at).await.unwrap(),
        Deletion::Deleted,
        "deleting an absent blob succeeds, so a retried collection does not fail"
    );
    assert_eq!(store.get_range(&other, 0, 5).await.unwrap(), b"other");
    store.delete(&other).await.unwrap();

    let _ = tokio::fs::remove_file(&staged).await;
    let _ = tokio::fs::remove_file(&other_staged).await;
}
