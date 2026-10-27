//! The node-neutral half of backup transfer: moving an already-encrypted
//! backup bundle between a node and its operator.
//!
//! A backup of any real node is too large for one Trust Task document, so it
//! moves as a **bundle**: a slot minted by `initiate-export` or
//! `initiate-import`, a manifest committed before any byte moves, the bytes
//! staged on disk, and a terminal step that releases or applies them. Nothing in
//! that is specific to the kind of node — the agent and the community both need
//! exactly this, which is why the Trust Task family is the node-neutral
//! `backup/*` (dtgwg-trust-tasks-tf#633), generalised from the agent's
//! `vta/backup/*`.
//!
//! This module is the half that does not know what a backup contains:
//!
//! - [`bundle_store`] — the [`BundleRecord`](bundle_store::BundleRecord) state
//!   machine and the bearer-token hashing the `stream` algorithm's blob endpoint
//!   checks;
//! - [`chunked`] — the `chunkedTrustTask` algorithm: staging, the per-chunk
//!   manifest, serving and accepting chunks by index, and the checks
//!   `finalize-import` makes before the bytes are trusted;
//! - [`sweeper`] — TTL expiry and retention of bundle records and their bytes;
//! - the ownership, TTL and open-bundle-cap rules every operation shares, below.
//!
//! What a bundle's bytes *are* — serializing a node's state into an encrypted
//! envelope, and applying one — stays with the node: `vta-backup` for the agent,
//! `vtc-service` for the community. Keeping the transfer here means the checks
//! that decide whether bytes are the committed ones exist once.

use std::path::Path;

use chrono::Duration;
use tracing::warn;
use uuid::Uuid;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

pub mod bundle_store;
pub mod chunked;
pub mod sweeper;

use bundle_store::{BundleKind, BundleRecord};

/// Default bundle TTL — five minutes of inactivity. Chunked transfers slide
/// their expiry forward on activity, up to [`MAX_BUNDLE_TTL_SECS`].
pub const DEFAULT_BUNDLE_TTL_SECS: u64 = 300;

/// Hard ceiling on a bundle's life. A descriptor sitting around for hours
/// invites token replay once the operator has closed their session.
pub const MAX_BUNDLE_TTL_SECS: u64 = 3600;

/// Per-DID cap on simultaneously open (non-terminal) bundles, so one operator
/// cannot tie up disk by initiating without ever finalizing.
pub const MAX_OPEN_BUNDLES_PER_DID: usize = 3;

/// One [`DEFAULT_BUNDLE_TTL_SECS`], as a duration.
pub fn bundle_ttl() -> Duration {
    Duration::seconds(DEFAULT_BUNDLE_TTL_SECS as i64)
}

/// Refuse a new bundle for `did` when it already holds
/// [`MAX_OPEN_BUNDLES_PER_DID`] open ones.
pub async fn enforce_open_bundle_cap(ks: &KeyspaceHandle, did: &str) -> Result<(), AppError> {
    let all = bundle_store::list_bundles(ks).await?;
    let open = all
        .iter()
        .filter(|r| r.created_by == did && !r.state.is_terminal())
        .count();
    if open >= MAX_OPEN_BUNDLES_PER_DID {
        return Err(AppError::Conflict(format!(
            "operator `{did}` has {open} open backup bundles; \
             abort or wait for expiry before initiating another \
             (cap: {MAX_OPEN_BUNDLES_PER_DID})"
        )));
    }
    Ok(())
}

/// Parse a wire `bundleId`.
pub fn parse_bundle_id(s: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(s).map_err(|e| AppError::Validation(format!("invalid bundle_id `{s}`: {e}")))
}

/// Look up a bundle and verify the caller owns it. Returns `NotFound` for both
/// "no such record" and "exists but another operator's", so the API does not
/// leak the existence of a peer's bundle.
pub async fn require_owned(
    ks: &KeyspaceHandle,
    id: &Uuid,
    caller_did: &str,
) -> Result<BundleRecord, AppError> {
    let record = bundle_store::get_bundle(ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("bundle not found: {id}")))?;
    if record.created_by != caller_did {
        warn!(
            bundle_id = %id,
            caller = %caller_did,
            owner = %record.created_by,
            "bundle owned by a different operator; treating as not-found"
        );
        return Err(AppError::NotFound(format!("bundle not found: {id}")));
    }
    Ok(record)
}

/// Refuse a bundle of the other direction as `NotFound`, so a handle never
/// reveals that a bundle of the other kind exists under the same id.
pub fn enforce_kind(record: &BundleRecord, expected: BundleKind) -> Result<(), AppError> {
    if record.kind != expected {
        return Err(AppError::NotFound(format!(
            "bundle not found: {}",
            record.bundle_id
        )));
    }
    Ok(())
}

/// Lowercase hex SHA-256 — the whole-bundle digest form the manifests carry.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let out = Sha256::digest(bytes);
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Restrict the staging directory to its owner.
#[cfg(unix)]
pub async fn set_dir_mode_700(path: &Path) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(AppError::Io)
}

/// Restrict a staged bundle file to its owner.
#[cfg(unix)]
pub async fn set_file_mode_600(path: &Path) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .await
        .map_err(AppError::Io)
}

/// Cancel an open bundle the caller owns: delete any staged bytes, mark it
/// `Aborted`, and drop a chunked bundle's plan. `Ok(false)` when the bundle was
/// already terminal, so a retried abort is safe.
///
/// Runs under the chunk lock every other read-modify-write of a bundle record
/// takes, and writes the record and the plan's removal as one store batch.
/// Outside it, an abort's stale copy of the record could overwrite a chunk
/// write's or a finalize's update (or be overwritten by one, un-aborting the
/// bundle), and two aborts could both report having aborted it.
pub async fn abort(ks: &KeyspaceHandle, caller_did: &str, id: &Uuid) -> Result<bool, AppError> {
    let _guard = chunked::chunk_lock().lock().await;
    let mut record = require_owned(ks, id, caller_did).await?;
    if record.state.is_terminal() {
        return Ok(false);
    }
    if let Some(path) = record.blob_path.clone()
        && let Err(e) = tokio::fs::remove_file(&path).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        // The sweeper retries; the abort still stands.
        warn!(
            bundle_id = %id,
            path = %path.display(),
            error = %e,
            "abort: failed to delete staged bytes; sweeper will retry"
        );
    }
    record.state = bundle_store::BundleState::Aborted;
    record.blob_path = None;
    let mut batch = crate::store::Batch::new();
    batch
        .insert(bundle_store::bundle_key(id), &record)?
        .remove(chunked::plan_key(id));
    ks.apply_batch(batch).await?;
    Ok(true)
}

#[cfg(test)]
mod abort_tests {
    use super::bundle_store::{BundleState, store_bundle};
    use super::*;
    use crate::config::StoreConfig;

    /// Aborts racing on one open bundle: exactly one aborts it, the rest find
    /// it already terminal. Unlocked, each read the open record and each
    /// reported having aborted it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn racing_aborts_abort_a_bundle_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace("backup_bundles_abort_test").unwrap();
        for _ in 0..40 {
            let now = chrono::Utc::now();
            let record = BundleRecord {
                bundle_id: Uuid::new_v4(),
                kind: BundleKind::Import,
                state: BundleState::ImportPending,
                created_at: now,
                expires_at: now + Duration::hours(1),
                created_by: "did:example:admin".into(),
                algorithm: "stream".into(),
                expected_sha256: "0".repeat(64),
                expected_size_bytes: 1,
                token_hash: [0u8; 32],
                blob_path: None,
            };
            store_bundle(&ks, &record).await.unwrap();
            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
            let mut tasks = Vec::new();
            for _ in 0..8 {
                let (ks, barrier, id) = (ks.clone(), barrier.clone(), record.bundle_id);
                tasks.push(tokio::spawn(async move {
                    barrier.wait().await;
                    abort(&ks, "did:example:admin", &id).await.unwrap()
                }));
            }
            let mut aborted = 0;
            for t in tasks {
                aborted += t.await.unwrap() as usize;
            }
            assert_eq!(aborted, 1, "{aborted} callers aborted one bundle");
        }
    }
}
