//! 30-day retention sweeper for `Rejected` + `Withdrawn` join
//! requests (spec §5.5).
//!
//! VP contents may include PII; the sole control on inadvertent
//! PII retention is this sweeper. Runs on a daemon-wide tokio
//! task spawned at startup; default cadence is hourly.

use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{debug, info, warn};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::{delete_join_request, list_join_requests};

/// Operator-controllable retention window for terminal join
/// requests (Rejected + Withdrawn).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestsConfig {
    /// Retention window in days. After this many days from
    /// `submitted_at`, terminal-state rows are purged on the next
    /// sweep. Default 30.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    /// How often the sweeper runs, in seconds. Default 3600 (1
    /// hour). Lower in tests via the config knob if needed.
    #[serde(default = "default_sweep_interval_secs")]
    pub sweep_interval_secs: u64,
}

pub fn default_retention_days() -> u32 {
    30
}

fn default_sweep_interval_secs() -> u64 {
    3600
}

impl Default for JoinRequestsConfig {
    fn default() -> Self {
        Self {
            retention_days: default_retention_days(),
            sweep_interval_secs: default_sweep_interval_secs(),
        }
    }
}

/// Owns the sweeper background task.
pub struct RetentionSweeper;

impl RetentionSweeper {
    /// Spawn the sweeper. Returns immediately; the task runs
    /// until the daemon's shutdown watcher fires.
    ///
    /// Sweeps four kinds of stale row each tick:
    /// - `Rejected` / `Withdrawn` join requests past the retention window
    ///   (PII in the submitted VP — the headline);
    /// - expired `present-challenge:` + `credx-pending:` rows (TTLs are
    ///   otherwise enforced only on the read path) — both in `join_requests_ks`;
    /// - `Failed` registry sync jobs past the retention window
    ///   (`sync_queue_ks`).
    pub fn spawn(
        join_requests_ks: KeyspaceHandle,
        sync_queue_ks: KeyspaceHandle,
        config: JoinRequestsConfig,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let interval = Duration::from_secs(config.sweep_interval_secs.max(60));
            info!(
                retention_days = config.retention_days,
                interval_secs = interval.as_secs(),
                "retention sweeper started"
            );
            // Sweep once on startup so a freshly-restarted daemon
            // catches up on rows that aged out while it was down.
            if let Err(e) = sweep_all(
                &join_requests_ks,
                &sync_queue_ks,
                config.retention_days,
                Utc::now(),
            )
            .await
            {
                warn!(error = %e, "initial retention sweep failed");
            }
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        info!("retention sweeper shutting down");
                        return;
                    }
                    _ = tokio::time::sleep(interval) => {
                        if let Err(e) = sweep_all(
                            &join_requests_ks,
                            &sync_queue_ks,
                            config.retention_days,
                            Utc::now(),
                        )
                        .await
                        {
                            warn!(error = %e, "retention sweep failed");
                        }
                    }
                }
            }
        })
    }
}

/// One full retention pass across all four stale-row kinds. Each sub-sweep is
/// independent; an error in one is propagated but the others on the same tick
/// have already run (sweeps are ordered, not transactional). `present-challenge:`
/// and `credx-pending:` share `join_requests_ks` with the join rows.
async fn sweep_all(
    join_requests_ks: &KeyspaceHandle,
    sync_queue_ks: &KeyspaceHandle,
    retention_days: u32,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    sweep_once(join_requests_ks, retention_days, now).await?;
    let challenges =
        crate::credentials::present_challenge::sweep_expired(join_requests_ks, now).await?;
    let offers = crate::credentials::exchange::sweep_expired_pending(join_requests_ks, now).await?;
    let failed_jobs =
        crate::registry::storage::sweep_failed_sync_jobs(sync_queue_ks, retention_days, now)
            .await?;
    if challenges + offers + failed_jobs > 0 {
        info!(
            expired_challenges = challenges,
            expired_offers = offers,
            failed_sync_jobs = failed_jobs,
            "retention sweep purged auxiliary stale rows"
        );
    }
    Ok(())
}

/// One pass: scan every row, delete those whose status is
/// `Rejected` / `Withdrawn` AND `submitted_at` is older than the
/// retention window.
async fn sweep_once(
    ks: &KeyspaceHandle,
    retention_days: u32,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let cutoff = now - ChronoDuration::days(retention_days as i64);
    let rows = list_join_requests(ks).await?;
    let mut purged = 0usize;
    for row in rows {
        if row.status.is_terminal_retainable() && row.submitted_at < cutoff {
            delete_join_request(ks, row.id).await?;
            purged += 1;
        }
    }
    if purged > 0 {
        info!(
            purged,
            retention_days, "join-request retention sweep complete"
        );
    } else {
        debug!(
            retention_days,
            "join-request retention sweep: nothing to purge"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::join::storage::store_join_request;
    use crate::join::{JoinRequest, JoinStatus};
    use chrono::{Duration as ChronoDuration, Utc};
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("join_requests").unwrap();
        (ks, dir)
    }

    fn at(submitted_at: chrono::DateTime<Utc>, status: JoinStatus) -> JoinRequest {
        JoinRequest {
            submitted_at,
            status,
            ..JoinRequest::new("did:key:z", serde_json::json!({}))
        }
    }

    #[tokio::test]
    async fn sweep_purges_old_rejected_rows() {
        let (ks, _dir) = temp_ks().await;
        let old = at(Utc::now() - ChronoDuration::days(31), JoinStatus::Rejected);
        let recent = at(Utc::now() - ChronoDuration::days(7), JoinStatus::Rejected);
        let pending_old = at(Utc::now() - ChronoDuration::days(60), JoinStatus::Pending);
        for r in [&old, &recent, &pending_old] {
            store_join_request(&ks, r).await.unwrap();
        }

        sweep_once(&ks, 30, Utc::now()).await.unwrap();

        let remaining = list_join_requests(&ks).await.unwrap();
        let dids: Vec<_> = remaining.iter().map(|r| r.id).collect();
        assert!(!dids.contains(&old.id), "old Rejected row must be purged");
        assert!(
            dids.contains(&recent.id),
            "recent Rejected row must be retained"
        );
        assert!(
            dids.contains(&pending_old.id),
            "Pending rows must never be swept"
        );
    }

    #[tokio::test]
    async fn sweep_purges_old_withdrawn_rows() {
        let (ks, _dir) = temp_ks().await;
        let old = at(Utc::now() - ChronoDuration::days(45), JoinStatus::Withdrawn);
        store_join_request(&ks, &old).await.unwrap();
        sweep_once(&ks, 30, Utc::now()).await.unwrap();
        assert!(
            list_join_requests(&ks).await.unwrap().is_empty(),
            "old Withdrawn rows must be purged"
        );
    }

    #[tokio::test]
    async fn sweep_does_not_purge_approved_rows() {
        let (ks, _dir) = temp_ks().await;
        let approved = at(Utc::now() - ChronoDuration::days(365), JoinStatus::Approved);
        store_join_request(&ks, &approved).await.unwrap();
        sweep_once(&ks, 30, Utc::now()).await.unwrap();
        assert_eq!(list_join_requests(&ks).await.unwrap().len(), 1);
    }

    /// `sweep_all` orchestrates all four kinds: a stale row of each is purged
    /// and a not-yet-expired row of each survives.
    #[tokio::test]
    async fn sweep_all_purges_every_stale_kind_and_keeps_fresh() {
        use crate::credentials::{exchange, present_challenge};
        use crate::registry::model::{SyncJob, SyncJobKind, SyncJobState};
        use crate::registry::storage::{list_sync_jobs, store_sync_job};

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let join_ks = store.keyspace("join_requests").unwrap();
        let sync_ks = store.keyspace("sync_queue").unwrap();
        let now = Utc::now();

        // --- stale rows (all must be purged) ---
        store_join_request(
            &join_ks,
            &at(now - ChronoDuration::days(31), JoinStatus::Rejected),
        )
        .await
        .unwrap();
        present_challenge::issue(
            &join_ks,
            "stale-thread",
            "did:web:v",
            present_challenge::DEFAULT_CHALLENGE_TTL,
            now - ChronoDuration::minutes(10),
        )
        .await
        .unwrap();
        exchange::make_offer(
            &join_ks,
            "https://issuer.example",
            vec!["VMC".into()],
            serde_json::json!({ "vc": 1 }),
            "did:key:zHolder",
            exchange::DEFAULT_OFFER_TTL,
            now - ChronoDuration::hours(1),
        )
        .await
        .unwrap();
        let mut failed = SyncJob::fresh(SyncJobKind::PublishMember, "did:key:zMember");
        failed.state = SyncJobState::Failed;
        failed.last_attempted_at = Some(now - ChronoDuration::days(40));
        store_sync_job(&sync_ks, &failed).await.unwrap();

        // --- fresh rows (all must survive) ---
        let fresh_join = at(now, JoinStatus::Rejected);
        store_join_request(&join_ks, &fresh_join).await.unwrap();
        present_challenge::issue(
            &join_ks,
            "fresh-thread",
            "did:web:v",
            present_challenge::DEFAULT_CHALLENGE_TTL,
            now,
        )
        .await
        .unwrap();

        sweep_all(&join_ks, &sync_ks, 30, now).await.unwrap();

        // Stale join purged, fresh join survives.
        let join_ids: Vec<_> = list_join_requests(&join_ks)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(
            join_ids,
            vec![fresh_join.id],
            "only the fresh Rejected row survives"
        );
        // Fresh challenge still consumable; stale one gone.
        assert!(
            present_challenge::consume(&join_ks, "fresh-thread", now)
                .await
                .is_ok()
        );
        assert!(
            present_challenge::consume(&join_ks, "stale-thread", now)
                .await
                .is_err()
        );
        // Expired credx-pending offer purged.
        assert!(
            join_ks
                .prefix_iter_raw(b"credx-pending:".to_vec())
                .await
                .unwrap()
                .is_empty()
        );
        // Old Failed sync job reaped.
        assert!(list_sync_jobs(&sync_ks).await.unwrap().is_empty());
    }
}
