//! The room-file migration runner (`vtc/rooms/storage/migrate/0.2`, served beside 0.1;
//! `docs/05-design-notes/data-rooms-files.md` §7.3).
//!
//! `migrate` records a migration and answers; this task does the work, one blob at a
//! time, through [`vti_rooms::blobs::BlobHost::migrate_step`] — copy, verify against the
//! manifest, switch, orphan the old copy. It is the **one retry owner** for a migration
//! (`migrate/0.2` item 10): a failed copy, read, write or credential request is retried
//! here with capped exponential backoff and full jitter; after
//! [`vti_rooms::blobs::MIGRATION_MAX_ATTEMPTS`] in a row the migration is `paused`, with
//! its cause and last error, and this runner tries it again by itself at its
//! `nextAttemptAt` ([`vti_rooms::blobs::PAUSED_RETRY_SECS`] later, jittered) — or at
//! once, when an administrator issues the task again. Nothing else retries a step.
//!
//! Before each step it checks the migration's target as the community has it now: a
//! target no longer `active`, or with no usable credential, is a failed attempt like
//! any other (cause `destination` or `credential`), so a migration whose target is
//! retired under it backs off, pauses, and keeps trying at its `nextAttemptAt`
//! (`room-migration`'s `destination`: "or is no longer `active`").
//!
//! One migration per target config runs at a time; the others are `queued`, and are
//! started here, in the order they were approved, when the one ahead finishes
//! ([`vti_rooms::blobs::BlobHost::promote_queued`]). Running migrations to different
//! configs are stepped in turn. The copy rate is the requester's `maxBytesPerSecond`,
//! bounded by `[rooms.files] migration_max_bytes_per_second`.
//!
//! Every state change is audited as a `RoomStorageChanged` row — `migrationStarted`,
//! `migrationResumed`, `migrationCompleted`, `migrationPaused`, `migrationFailed` —
//! carrying the requester, the approvers, the room, the configs and the reason
//! (`migrate` item 8); a resumption the runner made by itself says so
//! (`"automatic": true`). Progress reaches an open console through the `rooms` topic:
//! each blob moved is a prompt, and a change of a migration's state is a hint.

use std::sync::LazyLock;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::Notify;
use vti_common::audit::RoomStorageChangedData;
use vti_rooms::blobs::{Migration, MigrationState, MigrationStep, PauseCause};

use crate::rooms::storage_configs::state_of;
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

/// Which version of `vtc/rooms/storage/migrate` and `vtc/rooms/get` an answer is for.
/// 0.1 knows no `queued` state, no `toConfig` in `rooms/get` and none of the pause
/// members; 0.2 reports all of them through `vtc/_shared/0.1/room-migration`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    V0_1,
    V0_2,
}

fn rfc3339(secs: u64) -> Option<String> {
    chrono::DateTime::from_timestamp(secs as i64, 0).map(|t| t.to_rfc3339())
}

fn now_secs() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

/// The members `migrate` and `rooms/get` share: the state and, at 0.2, why it is
/// paused or waiting (items 11, `room-migration`).
fn state_members(m: &Migration, wire: Wire, out: &mut Value) {
    match wire {
        Wire::V0_1 => {
            // 0.1's states: a queued migration is one waiting its turn, which 0.1
            // reported `running`.
            let state = match m.state {
                MigrationState::Queued => "running",
                s => s.as_str(),
            };
            out["state"] = json!(state);
        }
        Wire::V0_2 => {
            out["state"] = json!(m.state.as_str());
            match m.state {
                MigrationState::Paused => {
                    // Present exactly when paused. A record paused by a 0.1 host names
                    // no cause; its causes were backend failures and restores, both
                    // `destination` as near as the vocabulary allows.
                    let cause = m.paused_cause.unwrap_or(PauseCause::Destination);
                    out["pausedCause"] = json!(cause.as_str());
                    out["lastError"] = json!(m.last_error.as_deref().unwrap_or("paused"));
                    if let Some(at) = m.next_attempt_at.and_then(rfc3339) {
                        out["nextAttemptAt"] = json!(at);
                    }
                }
                // Waiting out a backoff: what failed, and when it is tried again.
                MigrationState::Running => {
                    if let Some(at) = m.next_attempt_at
                        && let Some(e) = &m.last_error
                    {
                        out["lastError"] = json!(e);
                        if let Some(at) = rfc3339(at) {
                            out["nextAttemptAt"] = json!(at);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// The `migrate` response: the migration and its progress so far.
pub fn response_json(m: &Migration, wire: Wire) -> Value {
    let mut out = json!({
        "migrationId": m.migration_id.to_string(),
        "roomId": m.room_id,
        "toConfig": m.to_config,
        "fromConfigs": m.from_configs,
        "totalFiles": m.total_files,
        "totalBytes": m.total_bytes,
        "doneFiles": m.done_files,
        "doneBytes": m.done_bytes,
    });
    state_members(m, wire, &mut out);
    out
}

/// `vtc/rooms/get`'s `storage.migration` (`MigrationProgress`); 0.2 names the config it
/// moves to, which differs from the room's assignment after a reassignment.
pub fn progress_json(m: &Migration, wire: Wire) -> Value {
    let mut out = json!({
        "migrationId": m.migration_id.to_string(),
        "totalFiles": m.total_files,
        "totalBytes": m.total_bytes,
        "doneFiles": m.done_files,
        "doneBytes": m.done_bytes,
    });
    if wire == Wire::V0_2 {
        out["toConfig"] = json!(m.to_config);
    }
    state_members(m, wire, &mut out);
    out
}

/// Audit a migration's change of state as `actor`. A failure is logged: the change has
/// already been written.
pub async fn audit_migration(state: &AppState, m: &Migration, event: &str, actor: &str) {
    audit_with(state, m, event, actor, None).await;
}

async fn audit_with(
    state: &AppState,
    m: &Migration,
    event: &str,
    actor: &str,
    extra: Option<(&str, Value)>,
) {
    let mut current = response_json(m, Wire::V0_2);
    // A failed migration's error names the blob that did not verify: kept for the
    // audit trail, never answered.
    if let Some(e) = &m.last_error
        && m.state == MigrationState::Failed
    {
        current["lastError"] = json!(e);
    }
    if let Some((k, v)) = extra {
        current[k] = v;
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

/// Why `config_id` cannot take a migration's writes now, as the community has it: the
/// cause a pause would be put down to and the error to report. `None` when it can.
async fn target_unfit(state: &AppState, config_id: &str) -> Option<(PauseCause, String)> {
    match state.room_storage.config(config_id).await {
        Ok(Some(record)) if state_of(&record) != "active" => Some((
            PauseCause::Destination,
            format!("put to {config_id}: the config is {}", state_of(&record)),
        )),
        Ok(Some(record)) if !state.room_storage.usable(&record) => Some((
            PauseCause::Credential,
            format!("credential for {config_id}: none usable"),
        )),
        Ok(Some(_)) => None,
        Ok(None) => Some((
            PauseCause::Destination,
            format!("put to {config_id}: no such config"),
        )),
        // The registry unreadable is this host's trouble, not the target's: the step
        // finds out for itself.
        Err(_) => None,
    }
}

/// Start what is due, then step every running migration until none can be stepped now;
/// how long to wait before looking again.
///
/// Dropped at shutdown mid-step, which is what a crash does: a migration is resumable
/// from any point (`vti_rooms::blobs::migrate`).
pub async fn run(state: &AppState, rate_cap: u64) -> Duration {
    loop {
        let now = now_secs();
        // The runner's own retry of a migration it paused (item 10).
        match state.room_files.resume_due(now).await {
            Ok(resumed) => {
                for m in resumed {
                    tracing::info!(migration = %m.migration_id, "room file migration resumed");
                    audit_with(
                        state,
                        &m,
                        "migrationResumed",
                        &m.requested_by.clone(),
                        Some(("automatic", json!(true))),
                    )
                    .await;
                }
            }
            Err(e) => tracing::warn!(error = %e, "paused migrations not resumed"),
        }
        // A queued migration whose turn has come (item 13).
        match state.room_files.promote_queued().await {
            Ok(started) => {
                for m in started {
                    tracing::info!(migration = %m.migration_id, "queued room file migration started");
                }
            }
            Err(e) => tracing::warn!(error = %e, "queued migrations not started"),
        }
        let running = match state.room_files.running_migrations().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "migrations not read");
                return AFTER_ERROR;
            }
        };
        if running.is_empty() {
            return IDLE;
        }
        let mut wait = IDLE;
        let mut progressed = false;
        for m in running {
            if let Some(at) = m.next_attempt_at
                && at > now
            {
                wait = wait.min(until(Some(at)));
                continue;
            }
            let step = match target_unfit(state, &m.to_config).await {
                Some((cause, why)) => {
                    state
                        .room_files
                        .migration_step_failed(&m.room_id, m.migration_id, cause, &why)
                        .await
                }
                None => state.room_files.migrate_step(&m.room_id, rate_cap).await,
            };
            let step = match step {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(migration = %m.migration_id, error = %e, "migration step failed");
                    wait = wait.min(AFTER_ERROR);
                    continue;
                }
            };
            match step {
                MigrationStep::Moved(_) | MigrationStep::Skipped(_) => progressed = true,
                MigrationStep::Complete(m) => {
                    progressed = true;
                    tracing::info!(migration = %m.migration_id, files = m.done_files, "room files migrated");
                    audit_migration(state, &m, "migrationCompleted", &m.requested_by.clone()).await;
                }
                MigrationStep::Failed(m) => {
                    progressed = true;
                    tracing::warn!(migration = %m.migration_id, error = ?m.last_error, "room file migration failed");
                    audit_migration(state, &m, "migrationFailed", &m.requested_by.clone()).await;
                }
                MigrationStep::Paused(m) => {
                    progressed = true;
                    tracing::warn!(migration = %m.migration_id, error = ?m.last_error, "room file migration paused");
                    audit_migration(state, &m, "migrationPaused", &m.requested_by.clone()).await;
                }
                MigrationStep::Retrying(m) => {
                    tracing::info!(migration = %m.migration_id, attempts = m.attempts, error = ?m.last_error, "room file migration will retry");
                    wait = wait.min(until(m.next_attempt_at));
                }
                MigrationStep::Waiting { until: at } => wait = wait.min(until(Some(at))),
                // Changed under the step, or no longer running: look again shortly
                // rather than spin.
                _ => wait = wait.min(Duration::from_secs(1)),
            }
        }
        if !progressed {
            return wait;
        }
    }
}

/// How long until `at` (seconds), at least a second and at most [`IDLE`].
fn until(at: Option<u64>) -> Duration {
    let now = now_secs();
    let secs = at
        .map_or(1, |a| a.saturating_sub(now))
        .clamp(1, IDLE.as_secs());
    Duration::from_secs(secs)
}
