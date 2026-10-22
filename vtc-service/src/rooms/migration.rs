//! The room-file migration runner (`vtc/rooms/storage/migrate/0.1`,
//! `docs/05-design-notes/data-rooms-files.md` §7.3).
//!
//! `migrate` records a migration and answers; this task does the work, one blob at a
//! time, through [`vti_rooms::blobs::BlobHost::migrate_step`] — copy, verify against the
//! manifest, switch, orphan the old copy. It is the **one retry owner** for a migration:
//! a failed copy is retried here with capped exponential backoff and full jitter, and
//! after [`vti_rooms::blobs::MIGRATION_MAX_ATTEMPTS`] the migration is `paused` until an
//! administrator issues the task again. Nothing else retries a step.
//!
//! One migration runs at a time on this host, oldest first; the others wait their turn
//! and are reported `running`. The copy rate is the requester's `maxBytesPerSecond`,
//! bounded by `[rooms.files] migration_max_bytes_per_second`.
//!
//! Every state change is audited as a `RoomStorageChanged` row — `migrationStarted`,
//! `migrationResumed`, `migrationCompleted`, `migrationPaused`, `migrationFailed` —
//! carrying the requester, the approvers, the room, the configs and the reason
//! (`migrate` item 8). Progress reaches an open console through the `rooms` topic: each
//! blob moved is a prompt, and a change of a migration's state is a hint.

use std::sync::LazyLock;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::Notify;
use vti_common::audit::RoomStorageChangedData;
use vti_rooms::blobs::{Migration, MigrationState, MigrationStep};

use crate::server::AppState;

/// The copy rate when `[rooms.files]` sets none: 8 MiB/s.
pub const DEFAULT_MAX_BYTES_PER_SECOND: u64 = 8 * 1024 * 1024;

/// How long the runner sleeps with nothing to do, unless woken.
const IDLE: Duration = Duration::from_secs(30);
/// After a step the store could not take (an internal error): try again in this long.
const AFTER_ERROR: Duration = Duration::from_secs(30);

static KICK: LazyLock<Notify> = LazyLock::new(Notify::new);

/// Wake the runner: a migration was started or resumed.
pub(crate) fn kick() {
    KICK.notify_one();
}

/// The `migrate` response: the migration and its progress so far.
pub fn response_json(m: &Migration) -> Value {
    json!({
        "migrationId": m.migration_id.to_string(),
        "roomId": m.room_id,
        "toConfig": m.to_config,
        "fromConfigs": m.from_configs,
        "state": m.state.as_str(),
        "totalFiles": m.total_files,
        "totalBytes": m.total_bytes,
        "doneFiles": m.done_files,
        "doneBytes": m.done_bytes,
    })
}

/// `vtc/rooms/get`'s `storage.migration` (`MigrationProgress`).
pub fn progress_json(m: &Migration) -> Value {
    json!({
        "migrationId": m.migration_id.to_string(),
        "state": m.state.as_str(),
        "totalFiles": m.total_files,
        "totalBytes": m.total_bytes,
        "doneFiles": m.done_files,
        "doneBytes": m.done_bytes,
    })
}

/// Audit a migration's change of state as `actor`. A failure is logged: the change has
/// already been written.
pub async fn audit_migration(state: &AppState, m: &Migration, event: &str, actor: &str) {
    let mut current = response_json(m);
    if let Some(e) = &m.last_error
        && matches!(m.state, MigrationState::Paused | MigrationState::Failed)
    {
        current["lastError"] = json!(e);
    }
    crate::trust_tasks::storage_tasks::audit(
        state,
        actor,
        RoomStorageChangedData {
            event: event.to_string(),
            config_id: m.to_config.clone(),
            room_id: Some(m.room_id.clone()),
            previous: Some(json!(m.from_configs)),
            current,
            approvers: m.approvers.clone(),
            reason: m.reason.clone(),
        },
    )
    .await;
}

/// Pause every running migration after a restore, auditing each: the restored index may
/// name copies the target no longer holds, so each waits for an administrator to resume
/// it, and is then verified again.
pub async fn pause_after_restore(state: &AppState) {
    match state
        .room_files
        .pause_running_migrations(
            "restored from a backup: issue vtc/rooms/storage/migrate again to resume; the blob \
             in flight is verified again first",
        )
        .await
    {
        Ok(paused) => {
            for m in paused {
                audit_migration(state, &m, "migrationPaused", &m.requested_by.clone()).await;
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "backup import: running migrations not paused");
        }
    }
}

/// Run migrations until shutdown.
pub fn spawn(state: AppState, rate_cap: u64, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(async move {
        if let Err(e) = state.room_files.clear_migration_staging().await {
            tracing::warn!(error = %e, "a migration's staging was not cleared");
        }
        loop {
            let wait = tokio::select! {
                _ = shutdown.changed() => return,
                wait = run(&state, rate_cap) => wait,
            };
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = KICK.notified() => {}
                _ = tokio::time::sleep(wait) => {}
            }
        }
    });
}

/// Step the oldest running migration until none is left to step now; how long to wait
/// before looking again.
///
/// Dropped at shutdown mid-step, which is what a crash does: a migration is resumable
/// from any point (`vti_rooms::blobs::migrate`).
pub async fn run(state: &AppState, rate_cap: u64) -> Duration {
    loop {
        let m = match state.room_files.next_migration().await {
            Ok(Some(m)) => m,
            Ok(None) => return IDLE,
            Err(e) => {
                tracing::warn!(error = %e, "migrations not read");
                return AFTER_ERROR;
            }
        };
        let step = match state.room_files.migrate_step(&m.room_id, rate_cap).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(migration = %m.migration_id, error = %e, "migration step failed");
                return AFTER_ERROR;
            }
        };
        match step {
            MigrationStep::Moved(_) | MigrationStep::Skipped(_) => {}
            MigrationStep::Complete(m) => {
                tracing::info!(migration = %m.migration_id, files = m.done_files, "room files migrated");
                audit_migration(state, &m, "migrationCompleted", &m.requested_by.clone()).await;
            }
            MigrationStep::Failed(m) => {
                tracing::warn!(migration = %m.migration_id, error = ?m.last_error, "room file migration failed");
                audit_migration(state, &m, "migrationFailed", &m.requested_by.clone()).await;
            }
            MigrationStep::Paused(m) => {
                tracing::warn!(migration = %m.migration_id, error = ?m.last_error, "room file migration paused");
                audit_migration(state, &m, "migrationPaused", &m.requested_by.clone()).await;
            }
            MigrationStep::Retrying(m) => {
                tracing::info!(migration = %m.migration_id, attempts = m.attempts, error = ?m.last_error, "room file migration will retry");
                return until(m.next_attempt_at);
            }
            MigrationStep::Waiting { until: at } => return until(Some(at)),
            // Changed under the step, or no longer running: look again shortly rather
            // than spin.
            _ => return Duration::from_secs(1),
        }
    }
}

/// How long until `at` (seconds), at least a second and at most [`IDLE`].
fn until(at: Option<u64>) -> Duration {
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let secs = at
        .map_or(1, |a| a.saturating_sub(now))
        .clamp(1, IDLE.as_secs());
    Duration::from_secs(secs)
}
