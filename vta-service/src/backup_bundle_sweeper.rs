//! Background pruning of expired + terminal backup bundles.
//!
//! Two passes on each invocation:
//!
//! 1. **TTL pass** — for every non-terminal bundle whose
//!    `expires_at` has passed, delete its blob file (if any) and
//!    transition the record to `Expired`. The expired record
//!    persists for the retention window so audit tools and the
//!    operator-facing CLI can still see what happened.
//!
//! 2. **Retention pass** — for every terminal bundle (Aborted,
//!    Expired, ExportAcked, ImportCommitted, ExportDownloaded)
//!    older than the retention cutoff, remove the record entirely.
//!    Default retention is 24h from `created_at` — long enough for
//!    operator audit follow-up, short enough that records don't
//!    accumulate.
//!
//! Called from the storage thread's interval loop in
//! `server::run()`. Failures log at `warn!` but don't abort the
//! loop — a transient fjall or filesystem error shouldn't take
//! down the storage thread.

use std::path::Path;

use chrono::{Duration, Utc};
use tracing::{debug, info, warn};

use crate::backup_bundle_store::{self, BundleRecord, BundleState};
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// How long a terminal bundle's record sticks around before the
/// retention pass deletes it. Long enough for operator audit
/// follow-up, short enough to keep the keyspace tidy.
pub const RETENTION_DURATION_HOURS: i64 = 24;

/// Sweeper result counters. Returned for the storage thread's
/// log line and consumed by tests asserting the right work
/// happened.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepStats {
    /// Number of records transitioned to `Expired` this pass.
    pub expired: usize,
    /// Number of records deleted from the keyspace this pass
    /// (terminal + past retention).
    pub deleted: usize,
    /// Number of blob files removed from disk this pass. Tracked
    /// independently of `expired`/`deleted` because crash-recovery
    /// pre-conditions may leave orphan files paired with
    /// already-cleaned records.
    pub blobs_removed: usize,
}

/// Run one sweep pass over the backup-bundle keyspace.
///
/// Safe to call concurrently with handler-driven mutations on the
/// same keyspace — fjall serialises individual key writes, and
/// every transition we apply here is idempotent (a record we
/// expire is one that wasn't terminal when we read it; if a
/// handler raced us and made it terminal first, our subsequent
/// `store_bundle` overwrites the terminal state with `Expired`,
/// which is also terminal — same outcome).
pub async fn sweep_bundles(
    bundles_ks: &KeyspaceHandle,
    blob_dir: &Path,
) -> Result<SweepStats, AppError> {
    let mut stats = SweepStats::default();
    let now = Utc::now();
    let retention_cutoff = now - Duration::hours(RETENTION_DURATION_HOURS);

    let all = backup_bundle_store::list_bundles(bundles_ks).await?;

    for record in all {
        if !record.state.is_terminal() && record.expires_at <= now {
            // TTL pass: expire this record.
            let removed_blob = if let Some(ref path) = record.blob_path {
                match tokio::fs::remove_file(path).await {
                    Ok(()) => true,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                    Err(e) => {
                        warn!(
                            bundle_id = %record.bundle_id,
                            path = %path.display(),
                            error = %e,
                            "sweeper: failed to delete blob during TTL expiry"
                        );
                        // Don't transition — try again next pass.
                        continue;
                    }
                }
            } else {
                false
            };
            let mut expired = record.clone();
            expired.state = BundleState::Expired;
            expired.blob_path = None;
            if let Err(e) = backup_bundle_store::store_bundle(bundles_ks, &expired).await {
                warn!(
                    bundle_id = %record.bundle_id,
                    error = %e,
                    "sweeper: failed to persist Expired state; retry next pass"
                );
                continue;
            }
            stats.expired += 1;
            if removed_blob {
                stats.blobs_removed += 1;
            }
            debug!(
                bundle_id = %record.bundle_id,
                expired_at = %record.expires_at,
                "sweeper: bundle expired"
            );
        } else if record.state.is_terminal() && record.created_at <= retention_cutoff {
            // Retention pass: remove the record. Also delete any
            // orphan blob_path that managed to survive (defence
            // against earlier sweeper bugs / partial failures).
            if let Some(ref path) = record.blob_path {
                match tokio::fs::remove_file(path).await {
                    Ok(()) => {
                        stats.blobs_removed += 1;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        warn!(
                            bundle_id = %record.bundle_id,
                            path = %path.display(),
                            error = %e,
                            "sweeper: failed to delete orphan blob during retention pass"
                        );
                        continue;
                    }
                }
            }
            if let Err(e) = backup_bundle_store::delete_bundle(bundles_ks, &record.bundle_id).await
            {
                warn!(
                    bundle_id = %record.bundle_id,
                    error = %e,
                    "sweeper: failed to delete terminal record; retry next pass"
                );
                continue;
            }
            stats.deleted += 1;
            debug!(
                bundle_id = %record.bundle_id,
                state = ?record.state,
                created_at = %record.created_at,
                "sweeper: terminal bundle past retention; record removed"
            );
        }
    }

    // Drop unused field-lint guard.
    let _ = blob_dir;

    if stats.expired > 0 || stats.deleted > 0 {
        info!(
            expired = stats.expired,
            deleted = stats.deleted,
            blobs_removed = stats.blobs_removed,
            "backup-bundle sweeper pruned bundles"
        );
    }
    Ok(stats)
}

/// `is_terminal` already lives on `BundleState` but we re-export
/// the predicate signature here as `pub` indirection so future
/// callers can write `backup_bundle_sweeper::is_terminal(state)`
/// without reaching into the store module's surface. Currently
/// referenced only by the sweeper itself + tests.
#[allow(dead_code)]
pub fn is_terminal(record: &BundleRecord) -> bool {
    record.state.is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup_bundle_store::{BundleKind, BundleRecord};
    use uuid::Uuid;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    async fn setup() -> (tempfile::TempDir, KeyspaceHandle, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store
            .keyspace(crate::keyspaces::BACKUP_BUNDLES_SWEEPER_TEST)
            .unwrap();
        let blob_dir = dir.path().join("backups");
        tokio::fs::create_dir_all(&blob_dir).await.unwrap();
        (dir, ks, blob_dir)
    }

    fn record(
        kind: BundleKind,
        state: BundleState,
        created_at: chrono::DateTime<Utc>,
        expires_at: chrono::DateTime<Utc>,
        blob_path: Option<std::path::PathBuf>,
    ) -> BundleRecord {
        BundleRecord {
            bundle_id: Uuid::new_v4(),
            kind,
            state,
            created_at,
            expires_at,
            created_by: "did:example:admin".into(),
            algorithm: "stream".into(),
            expected_sha256: "0".repeat(64),
            expected_size_bytes: 1,
            token_hash: [0u8; 32],
            blob_path,
        }
    }

    #[tokio::test]
    async fn ttl_pass_expires_non_terminal_records_past_deadline() {
        let (_dir, ks, blob_dir) = setup().await;
        let now = Utc::now();
        let blob = blob_dir.join("expired.vtabak");
        tokio::fs::write(&blob, b"bytes").await.unwrap();

        let r = record(
            BundleKind::Export,
            BundleState::ExportReady,
            now - Duration::minutes(10),
            now - Duration::minutes(5),
            Some(blob.clone()),
        );
        let id = r.bundle_id;
        backup_bundle_store::store_bundle(&ks, &r).await.unwrap();

        let stats = sweep_bundles(&ks, &blob_dir).await.unwrap();
        assert_eq!(stats.expired, 1);
        assert_eq!(stats.deleted, 0);
        assert_eq!(stats.blobs_removed, 1);

        let restored = backup_bundle_store::get_bundle(&ks, &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.state, BundleState::Expired);
        assert!(restored.blob_path.is_none());
        assert!(!blob.exists(), "blob file should be deleted");
    }

    #[tokio::test]
    async fn ttl_pass_ignores_records_still_within_ttl() {
        let (_dir, ks, blob_dir) = setup().await;
        let now = Utc::now();
        let r = record(
            BundleKind::Import,
            BundleState::ImportPending,
            now,
            now + Duration::minutes(5),
            None,
        );
        backup_bundle_store::store_bundle(&ks, &r).await.unwrap();

        let stats = sweep_bundles(&ks, &blob_dir).await.unwrap();
        assert_eq!(stats, SweepStats::default());
    }

    #[tokio::test]
    async fn ttl_pass_ignores_already_terminal_records() {
        // A bundle in `ExportAcked` (terminal) past its expires_at
        // must NOT be re-transitioned to Expired — it has its own
        // terminal state and we shouldn't churn the record.
        let (_dir, ks, blob_dir) = setup().await;
        let now = Utc::now();
        let r = record(
            BundleKind::Export,
            BundleState::ExportAcked,
            now - Duration::minutes(30),
            now - Duration::minutes(10),
            None,
        );
        let id = r.bundle_id;
        backup_bundle_store::store_bundle(&ks, &r).await.unwrap();

        let stats = sweep_bundles(&ks, &blob_dir).await.unwrap();
        // expires_at is past but state is terminal — TTL pass skips.
        // created_at is within retention (10 min ago < 24h) so
        // retention pass also skips.
        assert_eq!(stats, SweepStats::default());
        let restored = backup_bundle_store::get_bundle(&ks, &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.state, BundleState::ExportAcked);
    }

    #[tokio::test]
    async fn retention_pass_deletes_terminal_records_past_cutoff() {
        let (_dir, ks, blob_dir) = setup().await;
        let now = Utc::now();
        let r = record(
            BundleKind::Import,
            BundleState::ImportCommitted,
            now - Duration::hours(48),
            now - Duration::hours(47),
            None,
        );
        let id = r.bundle_id;
        backup_bundle_store::store_bundle(&ks, &r).await.unwrap();

        let stats = sweep_bundles(&ks, &blob_dir).await.unwrap();
        assert_eq!(stats.deleted, 1);
        assert_eq!(stats.expired, 0);
        assert!(
            backup_bundle_store::get_bundle(&ks, &id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn retention_pass_keeps_fresh_terminal_records() {
        let (_dir, ks, blob_dir) = setup().await;
        let now = Utc::now();
        let r = record(
            BundleKind::Export,
            BundleState::Aborted,
            now - Duration::hours(1),
            now - Duration::minutes(30),
            None,
        );
        let id = r.bundle_id;
        backup_bundle_store::store_bundle(&ks, &r).await.unwrap();

        let stats = sweep_bundles(&ks, &blob_dir).await.unwrap();
        assert_eq!(stats, SweepStats::default());
        assert!(
            backup_bundle_store::get_bundle(&ks, &id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn retention_pass_removes_orphan_blob_alongside_record() {
        // A terminal bundle with a stale blob_path (defence
        // against partial-cleanup) should have BOTH cleaned up.
        let (_dir, ks, blob_dir) = setup().await;
        let now = Utc::now();
        let blob = blob_dir.join("orphan.vtabak");
        tokio::fs::write(&blob, b"stale").await.unwrap();
        let r = record(
            BundleKind::Export,
            BundleState::ExportDownloaded,
            now - Duration::hours(48),
            now - Duration::hours(47),
            Some(blob.clone()),
        );
        let id = r.bundle_id;
        backup_bundle_store::store_bundle(&ks, &r).await.unwrap();

        let stats = sweep_bundles(&ks, &blob_dir).await.unwrap();
        assert_eq!(stats.deleted, 1);
        assert_eq!(stats.blobs_removed, 1);
        assert!(!blob.exists());
        assert!(
            backup_bundle_store::get_bundle(&ks, &id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn sweep_combines_ttl_and_retention_in_one_pass() {
        // Mix of records: one expires-now (ExportReady, past
        // expires_at), one terminal-and-old (Aborted, > 24h ago),
        // one terminal-but-fresh (ImportCommitted, 1h ago), one
        // not-yet-expired (ImportPending). After sweep:
        //   - first: state = Expired (TTL pass)
        //   - second: removed entirely (retention pass)
        //   - third: untouched
        //   - fourth: untouched
        let (_dir, ks, blob_dir) = setup().await;
        let now = Utc::now();

        let r1 = record(
            BundleKind::Export,
            BundleState::ExportReady,
            now - Duration::minutes(10),
            now - Duration::minutes(1),
            None,
        );
        let r1_id = r1.bundle_id;
        let r2 = record(
            BundleKind::Export,
            BundleState::Aborted,
            now - Duration::hours(48),
            now - Duration::hours(47),
            None,
        );
        let r2_id = r2.bundle_id;
        let r3 = record(
            BundleKind::Import,
            BundleState::ImportCommitted,
            now - Duration::hours(1),
            now - Duration::minutes(55),
            None,
        );
        let r3_id = r3.bundle_id;
        let r4 = record(
            BundleKind::Import,
            BundleState::ImportPending,
            now,
            now + Duration::minutes(5),
            None,
        );
        let r4_id = r4.bundle_id;

        for r in [&r1, &r2, &r3, &r4] {
            backup_bundle_store::store_bundle(&ks, r).await.unwrap();
        }

        let stats = sweep_bundles(&ks, &blob_dir).await.unwrap();
        assert_eq!(stats.expired, 1);
        assert_eq!(stats.deleted, 1);
        assert_eq!(stats.blobs_removed, 0);

        assert_eq!(
            backup_bundle_store::get_bundle(&ks, &r1_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            BundleState::Expired
        );
        assert!(
            backup_bundle_store::get_bundle(&ks, &r2_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            backup_bundle_store::get_bundle(&ks, &r3_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            BundleState::ImportCommitted
        );
        assert_eq!(
            backup_bundle_store::get_bundle(&ks, &r4_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            BundleState::ImportPending
        );
    }
}
