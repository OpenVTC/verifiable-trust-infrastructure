//! Moving a room's existing files onto the storage config it is assigned to
//! (`vtc/rooms/storage/migrate/0.2`, served beside 0.1;
//! `docs/05-design-notes/data-rooms-files.md` §7.3).
//!
//! Reassigning a room sends its new uploads elsewhere and leaves its existing blobs
//! where they are, each naming its own config. A migration moves those too, one blob
//! at a time:
//!
//! 1. **copy** — read the ciphertext from the blob's config, checking every chunk
//!    against the committed manifest and the whole against its digest, stage it, and
//!    `put` it on the target config;
//! 2. **verify** — read the copy back from the target and check it the same way, so
//!    the bytes moved are provably the bytes the uploader committed to;
//! 3. **switch** — point the blob's entry at the copy, in one atomic batch with the
//!    rest of the step's bookkeeping, and only while the entry is exactly as it was
//!    when the copy began;
//! 4. **orphan** the old copy as a `moved:` row, which the collection pass deletes
//!    from its store after the orphan grace window.
//!
//! No key is involved at any step: the ciphertext is identical on both sides. Readers
//! notice nothing — a blob is named by its digest, and every read re-reads the entry.
//!
//! # The target is fixed at approval
//!
//! A migration's `to_config` is the room's assignment when it was approved, and it
//! keeps moving blobs there if the room is reassigned meanwhile (`migrate/0.2` item 9):
//! uploads begun after the reassignment go to the new assignment, and a later migration
//! — once this one is `complete` or `failed` — moves them all.
//!
//! # Orphans
//!
//! An orphaned blob — no record names it, and it awaits deletion — is never planned and
//! never counted (item 12). One orphaned (or collected) while the migration is open is
//! dropped from it at once ([`BlobHost::drop_from_migration`]), whichever side of its
//! switch it is on: before, its plan row and reservation go; after, the `mdone:` row
//! the switch wrote takes it back out of `doneFiles` and `totalFiles`.
//!
//! # Capacity
//!
//! The bytes to move are **reserved** on the target config (and the host-wide
//! counter) when the migration is approved, queued or not, so a migration cannot be
//! approved that the target cannot hold (item 2). Each switch converts its blob's
//! reservation into usage on the target; the old copy keeps counting against its own
//! config, and the host's storage, until the collection pass actually deletes it
//! (§6.1). A room's and a member's usage do not move: the file is the same file. A
//! migration under way therefore never runs out of room, and `capacity` is not a cause
//! this host pauses for.
//!
//! # Queueing
//!
//! One migration per target config runs at a time (item 13): one approved while
//! another to the same config is `running` or `paused` — or already waiting for it —
//! is `queued`, has copied nothing, and is started when those ahead of it are
//! `complete` or `failed`, in the order they were approved
//! ([`BlobHost::promote_queued`]). Per config rather than per community, so a target
//! that stops taking writes holds up only the migrations that need it.
//!
//! # Crash-safety and resumption
//!
//! Everything a migration knows is in this host's blob index — the migration record
//! (`migration:<room>`), one plan row per blob still to move (`mplan:<room>:<ref>`),
//! one row per blob it switched (`mdone:<room>:<ref>`) and the old copies awaiting
//! deletion (`moved:…`) — so a restart resumes it. The record names the blob in flight
//! and, once it is stored, its copy, so a process that dies mid-copy re-verifies or
//! redoes that one blob and never strands an object. The switch is one [`Batch`]:
//! entry, old-copy row, counters, plan row, done row and record land together or not
//! at all.
//!
//! # One retry owner
//!
//! The host's migration runner is the only thing that retries a step (item 10). A
//! failed copy, read, write or credential request is retried with capped exponential
//! backoff and full jitter, [`MIGRATION_MAX_ATTEMPTS`] times in a row; only then is the
//! migration `paused`, with its cause and last error, and the runner tries again by
//! itself at `next_attempt_at` ([`BlobHost::resume_due`]) — the same cycle, for as long
//! as it takes. Issuing the task again resumes a paused migration at once, as the same,
//! already approved, migration. A copy that does not verify is not retried: the
//! migration is `failed`, the blob stays where it is, and the rest of the reservation
//! is given back.

use std::time::Instant;

use vti_common::store::{Batch, ScanOpts};

use super::*;

/// The slowest copy rate a migration may be asked for (the specification's minimum
/// for `maxBytesPerSecond`).
pub const MIN_MIGRATION_BYTES_PER_SECOND: u64 = 65_536;

/// Failed copy attempts, in a row, before a migration is `paused`.
pub const MIGRATION_MAX_ATTEMPTS: u32 = 8;

/// The first retry's ceiling, doubled per attempt up to [`BACKOFF_CAP_SECS`].
const BACKOFF_BASE_SECS: u64 = 10;
const BACKOFF_CAP_SECS: u64 = 600;

/// How long a migration paused after its retries waits before the runner tries it
/// again by itself, plus up to [`PAUSED_RETRY_JITTER_SECS`].
pub const PAUSED_RETRY_SECS: u64 = 1_800;
const PAUSED_RETRY_JITTER_SECS: u64 = 300;

fn migration_key(room_id: &str) -> String {
    format!("migration:{}", room_hash(room_id))
}
fn plan_prefix(room_id: &str) -> String {
    format!("mplan:{}:", room_hash(room_id))
}
fn plan_key(room_id: &str, blob_ref: &str) -> String {
    format!("{}{blob_ref}", plan_prefix(room_id))
}
fn done_prefix(room_id: &str) -> String {
    format!("mdone:{}:", room_hash(room_id))
}
fn done_key(room_id: &str, blob_ref: &str) -> String {
    format!("{}{blob_ref}", done_prefix(room_id))
}
fn moved_prefix(room_id: &str, blob_ref: &str) -> String {
    format!("moved:{}:{blob_ref}:", room_hash(room_id))
}
fn moved_key(room_id: &str, blob_ref: &str, migration_id: &Uuid) -> String {
    format!("{}{migration_id}", moved_prefix(room_id, blob_ref))
}

/// Where a migration stands (`vtc/rooms/storage/migrate` *Migration states*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum MigrationState {
    /// Approved, and waiting for the migration ahead of it to the same config to
    /// finish. Nothing copied yet.
    Queued,
    /// Copying, or waiting out the backoff before its next attempt.
    Running,
    /// Halted after its retries ran out, or by a restore; resumed by issuing the task
    /// again, and by the runner itself at `next_attempt_at` when one is set.
    Paused,
    /// Every planned blob is on the target config, or was no longer the room's to move.
    Complete,
    /// A copy did not verify. That blob stays where it was.
    Failed,
}

impl MigrationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Complete => "complete",
            Self::Failed => "failed",
        }
    }

    /// Whether a request for the room answers with this migration rather than
    /// starting another (`migrate` item 5).
    pub fn is_open(self) -> bool {
        matches!(self, Self::Queued | Self::Running | Self::Paused)
    }
}

/// Why a migration is `paused` (`vtc/_shared/0.1/room-migration` `MigrationPauseCause`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum PauseCause {
    /// The target cannot hold the rest. Never set by this host, which reserves the
    /// bytes at approval; here so a record naming it still reads.
    Capacity,
    /// A config the blobs are moved off kept failing to serve them.
    Source,
    /// The target kept refusing writes, or is no longer `active`.
    Destination,
    /// No usable store — no credential — could be had for one of the configs.
    Credential,
}

impl PauseCause {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Capacity => "capacity",
            Self::Source => "source",
            Self::Destination => "destination",
            Self::Credential => "credential",
        }
    }
}

/// The blob a migration is moving now, and its copy once one is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InFlight {
    blob_ref: String,
    size: u64,
    /// The config and object the blob's entry named when the copy began. The
    /// switch happens only while the entry still names exactly these.
    source_config: String,
    source: BackendRef,
    /// The copy on the target config, once stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    copy: Option<BackendRef>,
}

/// One room's migration, as this host records it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Migration {
    pub migration_id: Uuid,
    pub room_id: String,
    /// The config the blobs are moved to: the room's assignment when it started,
    /// kept even if the room is reassigned meanwhile.
    pub to_config: String,
    /// The configs the planned blobs were on.
    pub from_configs: Vec<String>,
    pub state: MigrationState,
    pub total_files: u64,
    pub total_bytes: u64,
    pub done_files: u64,
    pub done_bytes: u64,
    /// The requester's bound on the copy rate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_second: Option<u64>,
    pub requested_by: String,
    /// The administrators whose approvals started it, when it was parked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvers: Vec<String>,
    pub reason: String,
    pub started_at: u64,
    pub updated_at: u64,
    /// Failed copy attempts in a row.
    #[serde(default)]
    pub attempts: u32,
    /// No step before this time (seconds), while backing off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<u64>,
    /// Why the last attempt failed, or why it paused or failed: the step, the config
    /// and the store's error, scrubbed of what could be a credential or a presigned
    /// URL and of the room's identifier and the blob's reference ([`scrub_error`]). A
    /// `failed` migration's names the blob that did not verify; it is audited, never
    /// answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Why it is `paused`; set exactly while it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_cause: Option<PauseCause>,
    /// Its place in the order migrations were approved in, which a queue keeps.
    #[serde(default)]
    pub seq: u64,
    /// Bytes still reserved on the target config for blobs not yet switched.
    #[serde(default)]
    pub reserved_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    in_flight: Option<InFlight>,
}

/// What [`BlobHost::start_migration`] is asked to do.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MigrationRequest {
    pub room_id: String,
    /// The room's assigned config: where the blobs go.
    pub to_config: String,
    /// The target config's capacity; `None` sets none.
    pub capacity_bytes: Option<u64>,
    pub max_bytes_per_second: Option<u64>,
    pub requested_by: String,
    pub approvers: Vec<String>,
    pub reason: String,
}

impl MigrationRequest {
    pub fn new(
        room_id: impl Into<String>,
        to_config: impl Into<String>,
        requested_by: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            room_id: room_id.into(),
            to_config: to_config.into(),
            capacity_bytes: None,
            max_bytes_per_second: None,
            requested_by: requested_by.into(),
            approvers: Vec::new(),
            reason: reason.into(),
        }
    }
}

/// What starting a migration did.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum MigrationStart {
    /// A new migration: `running`, `queued` behind another to the same config, or
    /// `complete` at once when nothing was to move.
    Started(Migration),
    /// One was already `queued` or `running`; this is it (its rate adopted from the
    /// request, when the request names one).
    InProgress(Migration),
    /// One was paused; it is running again.
    Resumed(Migration),
    /// The target cannot hold the bytes to move. Nothing was started.
    CapacityExceeded {
        capacity: u64,
        used: u64,
        requested: u64,
    },
}

/// What moving a room's blobs to a config would take, now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MigrationPlan {
    pub files: u64,
    pub bytes: u64,
    pub from_configs: Vec<String>,
}

/// What one [`BlobHost::migrate_step`] did.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum MigrationStep {
    /// The room has no running migration.
    Idle,
    /// Backing off until this time (seconds).
    Waiting { until: u64 },
    /// A blob moved.
    Moved(Migration),
    /// A planned blob was no longer the room's to move (collected, orphaned or
    /// changed), and was taken out of the totals.
    Skipped(Migration),
    /// A copy failed and will be retried.
    Retrying(Migration),
    /// A copy failed too often in a row; the migration is paused.
    Paused(Migration),
    /// A copy did not verify; the migration has failed.
    Failed(Migration),
    /// Nothing is left to move.
    Complete(Migration),
    /// The migration changed under the step (paused by a restore); nothing was
    /// switched, and what was copied is kept for when it resumes.
    Interrupted,
}

/// A blob's previous copy, awaiting deletion from its store after the grace window.
/// Counted against its config, and the host's storage, until deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MovedCopy {
    room_id: String,
    blob_ref: String,
    config_id: String,
    backend_ref: BackendRef,
    size: u64,
    moved_at: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct PlanItem {
    size: u64,
}

/// Why a copy could not be made or checked.
enum CopyError {
    /// The bytes are not the committed ones: the migration fails.
    Mismatch(String),
    /// The copy is not on the target (restored from a backup, say): copy again.
    Missing,
    /// Anything else: retried with backoff. Why, as the step, the config and the
    /// store's error, and what a pause for it would be put down to.
    Transient(PauseCause, String),
}

impl From<AppError> for CopyError {
    /// This host's own staging failed.
    fn from(e: AppError) -> Self {
        Self::Transient(PauseCause::Destination, format!("stage on this host: {e}"))
    }
}

/// Where a test stops a step, standing in for the process dying there.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopAfter {
    /// The blob is recorded as in flight; nothing copied.
    Chosen,
    /// The copy is stored on the target and recorded; not yet verified.
    Copied,
    /// The copy verified; not yet switched.
    Verified,
}

/// A retry delay: full jitter over a capped exponential.
fn backoff_secs(attempts: u32) -> u64 {
    let ceiling = BACKOFF_BASE_SECS
        .saturating_mul(1u64 << attempts.min(16))
        .min(BACKOFF_CAP_SECS);
    let r = (Uuid::new_v4().as_u128() % u128::from(ceiling + 1)) as u64;
    r.max(1)
}

/// When a migration paused after its retries is tried again by the runner itself.
fn paused_retry_at(now: u64) -> u64 {
    let jitter = (Uuid::new_v4().as_u128() % u128::from(PAUSED_RETRY_JITTER_SECS + 1)) as u64;
    now + PAUSED_RETRY_SECS + jitter
}

/// Sleep until `bytes` have taken at least `bytes / rate` seconds since `started`.
async fn throttle(started: Instant, bytes: u64, rate: u64) {
    let due = std::time::Duration::from_secs_f64(bytes as f64 / rate.max(1) as f64);
    let elapsed = started.elapsed();
    if due > elapsed {
        tokio::time::sleep(due - elapsed).await;
    }
}

/// A store's error, kept, reported and audited without what could be a credential — a
/// URL's query (where a presigned signature travels) and any long unbroken token — or
/// any of `hidden` (the room's identifier, its prefix, a blob's reference). At most 500
/// characters (`MigrationLastError`).
fn scrub_error(error: &str, hidden: &[&str]) -> String {
    let mut error = error.to_string();
    let mut hidden: Vec<&str> = hidden.iter().copied().filter(|h| !h.is_empty()).collect();
    hidden.sort_by_key(|h| std::cmp::Reverse(h.len()));
    for h in hidden {
        error = error.replace(h, "…");
    }
    let mut out = String::with_capacity(error.len());
    for word in error.split_inclusive(char::is_whitespace) {
        let (body, tail) = match word.find(char::is_whitespace) {
            Some(i) => word.split_at(i),
            None => (word, ""),
        };
        let body = match body.find('?') {
            Some(i) if body.contains("://") => format!("{}?…", &body[..i]),
            _ => body.to_string(),
        };
        let tokenish = body.len() >= 32
            && body
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=_-".contains(c));
        out.push_str(if tokenish { "…" } else { &body });
        out.push_str(tail);
    }
    let out: String = out.trim().chars().take(500).collect();
    if out.is_empty() {
        "failed".to_string()
    } else {
        out
    }
}

fn digest_matches(expected: &str, data: &[u8]) -> bool {
    blob_store::sha256_from_digest_multibase(expected) == Some(Sha256::digest(data).into())
}

/// A store that could not be had for `config_id`: the community cannot reach it with
/// any credential it holds now.
fn unreachable_config(config_id: &str, e: &AppError) -> CopyError {
    CopyError::Transient(
        PauseCause::Credential,
        format!("credential for {config_id}: {e}"),
    )
}

impl Migration {
    /// Running again from `paused`, as the same migration: its plan, its copy in
    /// flight, its target and its reason are kept; its retries start over.
    fn resume(&mut self, now: u64) {
        self.state = MigrationState::Running;
        self.paused_cause = None;
        self.attempts = 0;
        self.next_attempt_at = None;
        self.last_error = None;
        self.updated_at = now;
    }

    /// The blob being moved now, if any.
    pub fn in_flight_blob(&self) -> Option<&str> {
        self.in_flight.as_ref().map(|f| f.blob_ref.as_str())
    }
}

impl BlobHost {
    /// The room's migration — the last one, in whatever state.
    pub async fn migration(&self, room_id: &str) -> Result<Option<Migration>, AppError> {
        self.blobs.get(migration_key(room_id)).await
    }

    /// What `config_id`'s capacity is spent on now: the bytes stored on it, old copies
    /// awaiting deletion included, and the bytes reserved on it.
    pub async fn config_used_bytes(&self, config_id: &str) -> Result<u64, AppError> {
        let s = self.counter(&config_usage_key(config_id)).await?;
        Ok(s.bytes + s.reserved_bytes)
    }

    /// Delete what a copy interrupted by a restart left in staging. Call once, before
    /// the first [`Self::migrate_step`].
    pub async fn clear_migration_staging(&self) -> Result<(), AppError> {
        let mut dir = match tokio::fs::read_dir(&self.staging_dir).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(AppError::Io(e)),
        };
        while let Some(item) = dir.next_entry().await.map_err(AppError::Io)? {
            if item.file_name().to_string_lossy().starts_with("migrate-") {
                let _ = tokio::fs::remove_file(item.path()).await;
            }
        }
        Ok(())
    }

    /// Every migration this host records, oldest first.
    pub async fn migrations(&self) -> Result<Vec<Migration>, AppError> {
        let mut out: Vec<Migration> = self
            .blobs
            .prefix_iter_raw(b"migration:".to_vec())
            .await?
            .into_iter()
            .filter_map(|(_, raw)| serde_json::from_slice(&raw).ok())
            .collect();
        out.sort_by_key(|m| (m.started_at, m.seq, m.migration_id));
        Ok(out)
    }

    /// The migrations to work on now: every `running` one, oldest first. One per target
    /// config, but for migrations a 0.1 host left running side by side.
    pub async fn running_migrations(&self) -> Result<Vec<Migration>, AppError> {
        Ok(self
            .migrations()
            .await?
            .into_iter()
            .filter(|m| m.state == MigrationState::Running)
            .collect())
    }

    /// Start every `queued` migration whose target config has nothing `running` or
    /// `paused` ahead of it, the first approved first (`migrate` item 13).
    pub async fn promote_queued(&self) -> Result<Vec<Migration>, AppError> {
        let _guard = self.lock.lock().await;
        let all = self.migrations().await?;
        let mut busy: std::collections::HashSet<String> = all
            .iter()
            .filter(|m| matches!(m.state, MigrationState::Running | MigrationState::Paused))
            .map(|m| m.to_config.clone())
            .collect();
        let mut started = Vec::new();
        for mut m in all {
            if m.state != MigrationState::Queued || !busy.insert(m.to_config.clone()) {
                continue;
            }
            m.state = MigrationState::Running;
            m.updated_at = now_secs();
            self.blobs.insert(migration_key(&m.room_id), &m).await?;
            started.push(m);
        }
        if !started.is_empty() {
            crate::observe::changed();
        }
        Ok(started)
    }

    /// Resume every `paused` migration whose `next_attempt_at` has come: the runner's
    /// own retry after a pause (`migrate` item 10).
    pub async fn resume_due(&self, now: u64) -> Result<Vec<Migration>, AppError> {
        let _guard = self.lock.lock().await;
        let mut resumed = Vec::new();
        for mut m in self.migrations().await? {
            if m.state != MigrationState::Paused || m.next_attempt_at.is_none_or(|at| at > now) {
                continue;
            }
            m.resume(now);
            self.blobs.insert(migration_key(&m.room_id), &m).await?;
            resumed.push(m);
        }
        if !resumed.is_empty() {
            crate::observe::changed();
        }
        Ok(resumed)
    }

    /// A step of `room_id`'s running migration failed before it began — its target is
    /// no longer `active`, or has no usable credential, as the caller found: counted
    /// as a failed attempt like any other, so it backs off and then pauses with
    /// `cause` (`migrate` item 10).
    pub async fn migration_step_failed(
        &self,
        room_id: &str,
        migration_id: Uuid,
        cause: PauseCause,
        why: &str,
    ) -> Result<MigrationStep, AppError> {
        self.retry(migration_id, room_id, cause, why.to_string())
            .await
    }

    /// Drop `blob_ref` from `room_id`'s open migration: it was orphaned or collected,
    /// so it is neither moved nor counted (`migrate` item 12) — before its switch, its
    /// plan row and reservation go; after, it leaves `doneFiles` as well as the totals.
    /// The caller holds the host's lock, as every blob-entry write does.
    pub(super) async fn drop_from_migration(
        &self,
        room_id: &str,
        blob_ref: &str,
    ) -> Result<(), AppError> {
        let Some(mut m) = self.migration(room_id).await? else {
            return Ok(());
        };
        if !m.state.is_open() {
            return Ok(());
        }
        let mut batch = Batch::new();
        if let Some(p) = self
            .blobs
            .get::<PlanItem>(plan_key(room_id, blob_ref))
            .await?
        {
            batch.remove(plan_key(room_id, blob_ref));
            self.unreserve(&mut batch, &m.to_config, p.size).await?;
            m.reserved_bytes = m.reserved_bytes.saturating_sub(p.size);
            m.total_files = m.total_files.saturating_sub(1);
            m.total_bytes = m.total_bytes.saturating_sub(p.size);
        } else if let Some(p) = self
            .blobs
            .get::<PlanItem>(done_key(room_id, blob_ref))
            .await?
        {
            batch.remove(done_key(room_id, blob_ref));
            m.done_files = m.done_files.saturating_sub(1);
            m.done_bytes = m.done_bytes.saturating_sub(p.size);
            m.total_files = m.total_files.saturating_sub(1);
            m.total_bytes = m.total_bytes.saturating_sub(p.size);
        } else {
            return Ok(());
        }
        m.updated_at = now_secs();
        batch.insert(migration_key(room_id), &m)?;
        self.blobs.apply_batch(batch).await?;
        crate::observe::changed();
        Ok(())
    }

    /// The committed blobs of `room_id` on a config other than `to_config`, with
    /// their sizes: what a migration to it would move now. Orphaned blobs are left
    /// to collection.
    async fn plan_items(
        &self,
        room_id: &str,
        to_config: &str,
    ) -> Result<Vec<(String, u64, String)>, AppError> {
        let prefix = format!("blob:{}:", room_hash(room_id));
        let mut out = Vec::new();
        for (_, raw) in self.blobs.prefix_iter_raw(prefix.into_bytes()).await? {
            let Ok(entry) = serde_json::from_slice::<BlobEntry>(&raw) else {
                continue;
            };
            if entry.state == BlobState::Committed && entry.config_id != to_config {
                out.push((entry.blob_ref, entry.size, entry.config_id));
            }
        }
        Ok(out)
    }

    /// What a migration of `room_id` to `to_config` would move now.
    pub async fn plan_migration(
        &self,
        room_id: &str,
        to_config: &str,
    ) -> Result<MigrationPlan, AppError> {
        let items = self.plan_items(room_id, to_config).await?;
        let mut plan = MigrationPlan::default();
        for (_, size, config) in items {
            plan.files += 1;
            plan.bytes += size;
            if !plan.from_configs.contains(&config) {
                plan.from_configs.push(config);
            }
        }
        plan.from_configs.sort();
        Ok(plan)
    }

    /// Start moving `req.room_id`'s blobs to `req.to_config` — or, when the room
    /// already has a migration `queued`, `running` or `paused`, answer with that one,
    /// resuming a paused one at once (`migrate` item 5). Its `to_config` and `reason`
    /// are kept; the request's `max_bytes_per_second`, when it names one, is adopted.
    ///
    /// A new migration is `queued` when another to the same config is `running`,
    /// `paused` or itself queued (item 13), and its bytes are reserved either way.
    /// Refuses, starting nothing, when the target's capacity — or the host's storage
    /// capacity, which holds both copies until the old one is collected — cannot hold
    /// the bytes to move (item 2). A room with nothing to move gets a migration that
    /// is `complete` at once (item 7).
    pub async fn start_migration(&self, req: MigrationRequest) -> Result<MigrationStart, AppError> {
        let _guard = self.lock.lock().await;
        let now = now_secs();
        let key = migration_key(&req.room_id);
        if let Some(mut existing) = self.migration(&req.room_id).await?
            && existing.state.is_open()
        {
            let rate_changed = req.max_bytes_per_second.is_some()
                && req.max_bytes_per_second != existing.max_bytes_per_second;
            if rate_changed {
                existing.max_bytes_per_second = req.max_bytes_per_second;
                existing.updated_at = now;
            }
            if existing.state == MigrationState::Paused {
                existing.resume(now);
                self.blobs.insert(key, &existing).await?;
                crate::observe::changed();
                return Ok(MigrationStart::Resumed(existing));
            }
            if rate_changed {
                self.blobs.insert(key, &existing).await?;
            }
            return Ok(MigrationStart::InProgress(existing));
        }
        let all = self.migrations().await?;
        let behind = all
            .iter()
            .any(|o| o.room_id != req.room_id && o.to_config == req.to_config && o.state.is_open());
        let seq = all.iter().map(|o| o.seq).max().unwrap_or(0) + 1;

        let items = self.plan_items(&req.room_id, &req.to_config).await?;
        let files = items.len() as u64;
        let bytes: u64 = items.iter().map(|(_, s, _)| s).sum();
        let mut from_configs: Vec<String> = Vec::new();
        for (_, _, c) in &items {
            if !from_configs.contains(c) {
                from_configs.push(c.clone());
            }
        }
        from_configs.sort();

        let mut target = self.counter(&config_usage_key(&req.to_config)).await?;
        let mut storage = self.storage_usage().await?;
        if files > 0 {
            for (capacity, s) in [
                (req.capacity_bytes, &target),
                (self.limits.storage_capacity_bytes, &storage),
            ] {
                if let Some(capacity) = capacity {
                    let used = s.bytes + s.reserved_bytes;
                    if used + bytes > capacity {
                        return Ok(MigrationStart::CapacityExceeded {
                            capacity,
                            used,
                            requested: bytes,
                        });
                    }
                }
            }
        }

        let mut m = Migration {
            migration_id: Uuid::new_v4(),
            room_id: req.room_id.clone(),
            to_config: req.to_config.clone(),
            from_configs,
            state: if files == 0 {
                MigrationState::Complete
            } else if behind {
                MigrationState::Queued
            } else {
                MigrationState::Running
            },
            total_files: files,
            total_bytes: bytes,
            done_files: 0,
            done_bytes: 0,
            max_bytes_per_second: req.max_bytes_per_second,
            requested_by: req.requested_by,
            approvers: req.approvers,
            reason: req.reason,
            started_at: now,
            updated_at: now,
            attempts: 0,
            next_attempt_at: None,
            last_error: None,
            paused_cause: None,
            seq,
            reserved_bytes: bytes,
            in_flight: None,
        };
        if files == 0 {
            m.reserved_bytes = 0;
        }

        let mut batch = Batch::new();
        // Rows a previous migration left behind are not this one's plan.
        let planned: std::collections::HashSet<String> = items
            .iter()
            .map(|(r, ..)| plan_key(&req.room_id, r))
            .collect();
        for k in self
            .blobs
            .prefix_keys(plan_prefix(&req.room_id).into_bytes())
            .await?
        {
            if !planned.contains(String::from_utf8_lossy(&k).as_ref()) {
                batch.remove(k);
            }
        }
        for (blob_ref, size, _) in &items {
            batch.insert(plan_key(&req.room_id, blob_ref), &PlanItem { size: *size })?;
        }
        // Nor are the blobs a previous one moved this one's to take back out.
        for k in self
            .blobs
            .prefix_keys(done_prefix(&req.room_id).into_bytes())
            .await?
        {
            batch.remove(k);
        }
        if bytes > 0 {
            target.reserved_bytes += bytes;
            storage.reserved_bytes += bytes;
            batch.insert(config_usage_key(&req.to_config), &target)?;
            batch.insert(STORAGE_USAGE_KEY, &storage)?;
        }
        batch.insert(key, &m)?;
        self.blobs.apply_batch(batch).await?;
        crate::observe::changed();
        Ok(MigrationStart::Started(m))
    }

    /// Pause every `running` migration, keeping what each has copied for when it is
    /// resumed. A restore calls this: the restored index names copies the target may
    /// no longer hold, and an administrator resumes once the stores are in place —
    /// the blob in flight is then verified again before it is switched. The cause is
    /// `destination` (what is on the target is in doubt), and the runner does not
    /// resume it by itself: `next_attempt_at` stays unset. A `queued` one has copied
    /// nothing, and stays queued.
    pub async fn pause_running_migrations(&self, why: &str) -> Result<Vec<Migration>, AppError> {
        let _guard = self.lock.lock().await;
        let mut paused = Vec::new();
        for mut m in self.migrations().await? {
            if m.state != MigrationState::Running {
                continue;
            }
            m.state = MigrationState::Paused;
            m.paused_cause = Some(PauseCause::Destination);
            m.last_error = Some(why.to_string());
            m.next_attempt_at = None;
            m.updated_at = now_secs();
            self.blobs.insert(migration_key(&m.room_id), &m).await?;
            paused.push(m);
        }
        if !paused.is_empty() {
            crate::observe::changed();
        }
        Ok(paused)
    }

    /// Move one blob of `room_id`'s running migration — or settle it: skip a blob
    /// that is no longer the room's to move, finish when nothing is left, back off
    /// after a failed copy, pause after too many, fail on a copy that does not verify.
    ///
    /// `rate_cap` is the host's own bound on the copy rate; the migration's
    /// `maxBytesPerSecond` can only lower it, and nothing goes below
    /// [`MIN_MIGRATION_BYTES_PER_SECOND`].
    pub async fn migrate_step(
        &self,
        room_id: &str,
        rate_cap: u64,
    ) -> Result<MigrationStep, AppError> {
        self.step_inner(
            room_id,
            rate_cap,
            #[cfg(test)]
            None,
        )
        .await
    }

    async fn step_inner(
        &self,
        room_id: &str,
        rate_cap: u64,
        #[cfg(test)] stop: Option<StopAfter>,
    ) -> Result<MigrationStep, AppError> {
        let Some(mut m) = self.migration(room_id).await? else {
            return Ok(MigrationStep::Idle);
        };
        if m.state != MigrationState::Running {
            return Ok(MigrationStep::Idle);
        }
        let now = now_secs();
        if let Some(until) = m.next_attempt_at
            && until > now
        {
            return Ok(MigrationStep::Waiting { until });
        }

        // The blob in flight, or the next planned one.
        let flight = match m.in_flight.clone() {
            Some(f) => f,
            None => {
                let next = self
                    .blobs
                    .scan_raw(ScanOpts::new(plan_prefix(room_id).into_bytes(), 1))
                    .await?
                    .into_iter()
                    .next();
                let Some((key, raw)) = next else {
                    return self.finish(m.migration_id, room_id).await;
                };
                let blob_ref = String::from_utf8_lossy(&key)
                    .trim_start_matches(&plan_prefix(room_id))
                    .to_string();
                let planned: PlanItem = serde_json::from_slice(&raw)?;
                match self.blob(room_id, &blob_ref).await? {
                    Some(entry)
                        if entry.state == BlobState::Committed
                            && entry.config_id != m.to_config =>
                    {
                        let f = InFlight {
                            blob_ref,
                            size: entry.size,
                            source_config: entry.config_id,
                            source: entry.backend_ref,
                            copy: None,
                        };
                        if !self.record_flight(&m, Some(f.clone())).await? {
                            return Ok(MigrationStep::Interrupted);
                        }
                        m.in_flight = Some(f.clone());
                        f
                    }
                    _ => {
                        return self
                            .skip(m.migration_id, room_id, &blob_ref, planned.size, None)
                            .await;
                    }
                }
            }
        };
        #[cfg(test)]
        if stop == Some(StopAfter::Chosen) {
            return Ok(MigrationStep::Interrupted);
        }

        // Is the blob still the one the copy is of?
        let Some(entry) = self.blob(room_id, &flight.blob_ref).await? else {
            return self
                .skip(
                    m.migration_id,
                    room_id,
                    &flight.blob_ref,
                    flight.size,
                    flight.copy.clone(),
                )
                .await;
        };
        if entry.state != BlobState::Committed
            || entry.config_id != flight.source_config
            || entry.backend_ref != flight.source
        {
            return self
                .skip(
                    m.migration_id,
                    room_id,
                    &flight.blob_ref,
                    flight.size,
                    flight.copy.clone(),
                )
                .await;
        }
        let manifest = match Manifest::parse(&entry.manifest) {
            Ok(mf) => mf,
            Err(e) => {
                return self
                    .fail(
                        m.migration_id,
                        room_id,
                        format!(
                            "blob `{}`'s stored manifest cannot be checked against: {e}",
                            flight.blob_ref
                        ),
                        None,
                    )
                    .await;
            }
        };
        let rate = m
            .max_bytes_per_second
            .unwrap_or(rate_cap)
            .min(rate_cap)
            .max(MIN_MIGRATION_BYTES_PER_SECOND);

        // Copy, unless a copy is already recorded — then verify that one first.
        let mut copy = flight.copy.clone();
        let mut attempts_this_step = 0;
        let copy = loop {
            attempts_this_step += 1;
            let at = match copy.clone() {
                Some(at) => at,
                None => match self.copy_blob(&m, &flight, &manifest, rate).await {
                    Ok(at) => {
                        let mut f = flight.clone();
                        f.copy = Some(at.clone());
                        if !self.record_flight(&m, Some(f)).await? {
                            return Ok(MigrationStep::Interrupted);
                        }
                        #[cfg(test)]
                        if stop == Some(StopAfter::Copied) {
                            return Ok(MigrationStep::Interrupted);
                        }
                        at
                    }
                    Err(CopyError::Mismatch(why)) => {
                        return self.fail(m.migration_id, room_id, why, None).await;
                    }
                    Err(CopyError::Missing) => {
                        return self
                            .retry(
                                m.migration_id,
                                room_id,
                                PauseCause::Source,
                                format!(
                                    "get from {}: the object is not there",
                                    flight.source_config
                                ),
                            )
                            .await;
                    }
                    Err(CopyError::Transient(cause, why)) => {
                        return self.retry(m.migration_id, room_id, cause, why).await;
                    }
                },
            };
            match self.verify_copy(&m, &at, &manifest).await {
                Ok(()) => break at,
                // A copy recorded before this step (a restart, a restore) that is gone
                // or wrong is made again, once; one made in this step that does not
                // verify fails the migration.
                Err(CopyError::Missing) if attempts_this_step == 1 && flight.copy.is_some() => {
                    copy = None;
                }
                Err(CopyError::Mismatch(_)) if attempts_this_step == 1 && flight.copy.is_some() => {
                    self.discard_copy(&m.to_config, room_id, &flight.blob_ref, &at)
                        .await;
                    copy = None;
                }
                Err(CopyError::Missing) => {
                    return self
                        .fail(
                            m.migration_id,
                            room_id,
                            format!(
                                "the copy of blob `{}` on `{}` could not be read back",
                                flight.blob_ref, m.to_config
                            ),
                            None,
                        )
                        .await;
                }
                Err(CopyError::Mismatch(why)) => {
                    return self.fail(m.migration_id, room_id, why, Some(at)).await;
                }
                Err(CopyError::Transient(cause, why)) => {
                    return self.retry(m.migration_id, room_id, cause, why).await;
                }
            }
        };
        #[cfg(test)]
        if stop == Some(StopAfter::Verified) {
            return Ok(MigrationStep::Interrupted);
        }

        self.switch(m.migration_id, room_id, &flight, copy).await
    }

    /// Record `flight` as the migration's blob in flight, if the migration is still
    /// the running one. `false` when it changed meanwhile.
    async fn record_flight(
        &self,
        m: &Migration,
        flight: Option<InFlight>,
    ) -> Result<bool, AppError> {
        let _guard = self.lock.lock().await;
        let Some(mut current) = self.migration(&m.room_id).await? else {
            return Ok(false);
        };
        if current.migration_id != m.migration_id || current.state != MigrationState::Running {
            return Ok(false);
        }
        current.in_flight = flight;
        current.updated_at = now_secs();
        self.blobs
            .insert(migration_key(&m.room_id), &current)
            .await?;
        Ok(true)
    }

    /// Read the blob from its config, chunk by chunk, checking each against the
    /// manifest and the whole against its digest; stage it; store it on the target.
    async fn copy_blob(
        &self,
        m: &Migration,
        f: &InFlight,
        manifest: &Manifest,
        rate: u64,
    ) -> Result<BackendRef, CopyError> {
        let source = self
            .stores
            .store_for(&f.source_config, &m.room_id)
            .await
            .map_err(|e| unreachable_config(&f.source_config, &e))?;
        let target = self
            .stores
            .store_for(&m.to_config, &m.room_id)
            .await
            .map_err(|e| unreachable_config(&m.to_config, &e))?;
        tokio::fs::create_dir_all(&self.staging_dir)
            .await
            .map_err(AppError::Io)?;
        let staged = self
            .staging_dir
            .join(format!("migrate-{}", Uuid::new_v4().simple()));
        let result = async {
            self.stage(source.as_ref(), f, manifest, rate, &staged)
                .await?;
            // Same bytes, same content-derived key, another store.
            let put_failed = |e: AppError| {
                CopyError::Transient(
                    PauseCause::Destination,
                    format!("put to {}: {e}", m.to_config),
                )
            };
            let key = BlobKey::for_room(&m.room_id, &f.blob_ref).map_err(put_failed)?;
            self.reclaim_moved(&m.room_id, &f.blob_ref, &m.to_config)
                .await?;
            target
                .put(&key, &staged, manifest.size)
                .await
                .map_err(put_failed)
        }
        .await;
        let _ = tokio::fs::remove_file(&staged).await;
        result
    }

    async fn stage(
        &self,
        source: &dyn BlobStore,
        f: &InFlight,
        manifest: &Manifest,
        rate: u64,
        staged: &std::path::Path,
    ) -> Result<(), CopyError> {
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::File::create(staged)
            .await
            .map_err(AppError::Io)?;
        let mut whole = Sha256::new();
        let started = Instant::now();
        let mut copied = 0u64;
        for i in 0..manifest.chunk_count {
            let start = i * manifest.chunk_size;
            let end = (start + manifest.chunk_size).min(manifest.size);
            let data = match source.get_range(&f.source, start, end).await {
                Ok(d) => d,
                Err(AppError::NotFound(_)) => return Err(CopyError::Missing),
                Err(e) => {
                    return Err(CopyError::Transient(
                        PauseCause::Source,
                        format!("get from {}: {e}", f.source_config),
                    ));
                }
            };
            if !digest_matches(&manifest.chunk_digests[i as usize], &data) {
                return Err(CopyError::Mismatch(format!(
                    "chunk {i} of blob `{}` as stored on `{}` does not match its committed digest",
                    f.blob_ref, f.source_config
                )));
            }
            whole.update(&data);
            file.write_all(&data).await.map_err(AppError::Io)?;
            copied += data.len() as u64;
            throttle(started, copied, rate).await;
        }
        file.sync_all().await.map_err(AppError::Io)?;
        let whole: [u8; 32] = whole.finalize().into();
        if blob_store::sha256_from_digest_multibase(&manifest.digest) != Some(whole) {
            return Err(CopyError::Mismatch(format!(
                "blob `{}` as stored on `{}` does not match its committed digest",
                f.blob_ref, f.source_config
            )));
        }
        Ok(())
    }

    /// Read the copy back from the target and check it as the source was checked.
    async fn verify_copy(
        &self,
        m: &Migration,
        at: &BackendRef,
        manifest: &Manifest,
    ) -> Result<(), CopyError> {
        let target = self
            .stores
            .store_for(&m.to_config, &m.room_id)
            .await
            .map_err(|e| unreachable_config(&m.to_config, &e))?;
        let mut whole = Sha256::new();
        for i in 0..manifest.chunk_count {
            let start = i * manifest.chunk_size;
            let end = (start + manifest.chunk_size).min(manifest.size);
            let data = match target.get_range(at, start, end).await {
                Ok(d) => d,
                Err(AppError::NotFound(_)) => return Err(CopyError::Missing),
                Err(e) => {
                    return Err(CopyError::Transient(
                        PauseCause::Destination,
                        format!("read back from {}: {e}", m.to_config),
                    ));
                }
            };
            if !digest_matches(&manifest.chunk_digests[i as usize], &data) {
                return Err(CopyError::Mismatch(format!(
                    "chunk {i} of the copy of blob `{}` on `{}` does not match its committed \
                     digest",
                    manifest.blob_ref, m.to_config
                )));
            }
            whole.update(&data);
        }
        let whole: [u8; 32] = whole.finalize().into();
        if blob_store::sha256_from_digest_multibase(&manifest.digest) != Some(whole) {
            return Err(CopyError::Mismatch(format!(
                "the copy of blob `{}` on `{}` does not match its committed digest",
                manifest.blob_ref, m.to_config
            )));
        }
        Ok(())
    }

    /// An earlier copy of this blob on `config_id`, moved off it and awaiting deletion,
    /// is where the new copy is about to be written: take it back from collection, so
    /// the collection pass cannot delete what the switch is about to point at. Its
    /// bytes stop counting here; the switch counts them again.
    async fn reclaim_moved(
        &self,
        room_id: &str,
        blob_ref: &str,
        config_id: &str,
    ) -> Result<(), AppError> {
        let _guard = self.lock.lock().await;
        for (key, raw) in self
            .blobs
            .prefix_iter_raw(moved_prefix(room_id, blob_ref).into_bytes())
            .await?
        {
            let Ok(row) = serde_json::from_slice::<MovedCopy>(&raw) else {
                continue;
            };
            if row.config_id != config_id {
                continue;
            }
            let mut batch = Batch::new();
            batch.remove(key);
            self.uncount_copy(&mut batch, &row.config_id, row.size)
                .await?;
            self.blobs.apply_batch(batch).await?;
        }
        Ok(())
    }

    /// Add to `batch` the decrement of one stored copy of `size` bytes from
    /// `config_id`'s counter and the host's.
    async fn uncount_copy(
        &self,
        batch: &mut Batch,
        config_id: &str,
        size: u64,
    ) -> Result<(), AppError> {
        for key in [STORAGE_USAGE_KEY.to_string(), config_usage_key(config_id)] {
            let mut s = self.counter(&key).await?;
            s.files = checked_sub(s.files, 1, "storage files");
            s.bytes = checked_sub(s.bytes, size, "storage bytes");
            batch.insert(key, &s)?;
        }
        Ok(())
    }

    /// Delete a copy that will never be switched to. A failure is logged: the object
    /// is unreferenced, and the store's own lifecycle is the backstop.
    async fn discard_copy(&self, config_id: &str, room_id: &str, blob_ref: &str, at: &BackendRef) {
        // Never the object an entry now names.
        if let Ok(Some(entry)) = self.blob(room_id, blob_ref).await
            && entry.config_id == config_id
            && &entry.backend_ref == at
        {
            return;
        }
        let deleted = match self.stores.store_for(config_id, room_id).await {
            Ok(store) => store.delete(at).await,
            Err(e) => Err(e),
        };
        if let Err(e) = deleted {
            tracing::warn!(error = %e, "a migration's unused copy was not deleted");
        }
    }

    /// Point the blob at its verified copy: entry, the old copy's row, the target's
    /// counters, the plan row and the record, in one batch, and only while the entry
    /// is exactly as it was when the copy began.
    async fn switch(
        &self,
        migration_id: Uuid,
        room_id: &str,
        f: &InFlight,
        copy: BackendRef,
    ) -> Result<MigrationStep, AppError> {
        let guard = self.lock.lock().await;
        let Some(mut m) = self.migration(room_id).await? else {
            return Ok(MigrationStep::Interrupted);
        };
        if m.migration_id != migration_id || m.state != MigrationState::Running {
            return Ok(MigrationStep::Interrupted);
        }
        let key = blob_key(room_id, &f.blob_ref);
        let raw = self.blobs.get_raw(key.clone()).await?;
        let entry = raw
            .as_deref()
            .and_then(|r| serde_json::from_slice::<BlobEntry>(r).ok());
        let Some((raw, mut entry)) = raw.zip(entry) else {
            drop(guard);
            return self
                .skip(migration_id, room_id, &f.blob_ref, f.size, Some(copy))
                .await;
        };
        if entry.state != BlobState::Committed
            || entry.config_id != f.source_config
            || entry.backend_ref != f.source
        {
            drop(guard);
            return self
                .skip(migration_id, room_id, &f.blob_ref, f.size, Some(copy))
                .await;
        }

        let now = now_secs();
        let moved = MovedCopy {
            room_id: room_id.to_string(),
            blob_ref: f.blob_ref.clone(),
            config_id: entry.config_id.clone(),
            backend_ref: entry.backend_ref.clone(),
            size: entry.size,
            moved_at: now,
        };
        entry.config_id = m.to_config.clone();
        entry.backend_ref = copy;

        let mut batch = Batch::new();
        batch.require_unchanged(key.clone(), raw);
        batch.insert(key, &entry)?;
        batch.insert(moved_key(room_id, &f.blob_ref, &migration_id), &moved)?;
        for k in [
            STORAGE_USAGE_KEY.to_string(),
            config_usage_key(&m.to_config),
        ] {
            let mut s = self.counter(&k).await?;
            s.reserved_bytes = checked_sub(s.reserved_bytes, f.size, "migration reserved");
            s.bytes += f.size;
            s.files += 1;
            batch.insert(k, &s)?;
        }
        batch.remove(plan_key(room_id, &f.blob_ref));
        batch.insert(done_key(room_id, &f.blob_ref), &PlanItem { size: f.size })?;
        m.done_files += 1;
        m.done_bytes += f.size;
        m.reserved_bytes = m.reserved_bytes.saturating_sub(f.size);
        m.in_flight = None;
        m.attempts = 0;
        m.next_attempt_at = None;
        m.last_error = None;
        m.updated_at = now;
        batch.insert(migration_key(room_id), &m)?;
        if !self.blobs.apply_batch(batch).await?.is_applied() {
            // Nothing else writes the entry without this lock; say so if it happened.
            return Err(AppError::Internal(format!(
                "blob `{}` changed under the migration's lock",
                f.blob_ref
            )));
        }
        crate::observe::changed();
        Ok(MigrationStep::Moved(m))
    }

    /// A planned blob that is no longer the room's to move — collected, orphaned or
    /// rewritten — leaves the plan and the totals, and its reservation is given back,
    /// unless [`Self::drop_from_migration`] already took it out. Its copy, if one was
    /// made, is deleted.
    async fn skip(
        &self,
        migration_id: Uuid,
        room_id: &str,
        blob_ref: &str,
        size: u64,
        copy: Option<BackendRef>,
    ) -> Result<MigrationStep, AppError> {
        let m = {
            let _guard = self.lock.lock().await;
            let Some(mut m) = self.migration(room_id).await? else {
                return Ok(MigrationStep::Interrupted);
            };
            if m.migration_id != migration_id || m.state != MigrationState::Running {
                return Ok(MigrationStep::Interrupted);
            }
            let mut batch = Batch::new();
            if self
                .blobs
                .get_raw(plan_key(room_id, blob_ref))
                .await?
                .is_some()
            {
                batch.remove(plan_key(room_id, blob_ref));
                self.unreserve(&mut batch, &m.to_config, size).await?;
                m.total_files = m.total_files.saturating_sub(1);
                m.total_bytes = m.total_bytes.saturating_sub(size);
                m.reserved_bytes = m.reserved_bytes.saturating_sub(size);
            }
            if m.in_flight.as_ref().is_some_and(|f| f.blob_ref == blob_ref) {
                m.in_flight = None;
            }
            m.updated_at = now_secs();
            batch.insert(migration_key(room_id), &m)?;
            self.blobs.apply_batch(batch).await?;
            m
        };
        if let Some(at) = copy {
            self.discard_copy(&m.to_config, room_id, blob_ref, &at)
                .await;
        }
        crate::observe::changed();
        Ok(MigrationStep::Skipped(m))
    }

    /// Add to `batch` giving back `size` reserved bytes on `config_id` and the host.
    async fn unreserve(
        &self,
        batch: &mut Batch,
        config_id: &str,
        size: u64,
    ) -> Result<(), AppError> {
        if size == 0 {
            return Ok(());
        }
        for key in [STORAGE_USAGE_KEY.to_string(), config_usage_key(config_id)] {
            let mut s = self.counter(&key).await?;
            s.reserved_bytes = checked_sub(s.reserved_bytes, size, "migration reserved");
            batch.insert(key, &s)?;
        }
        Ok(())
    }

    /// Nothing is left to move: `complete`, and any reservation left over given back.
    async fn finish(&self, migration_id: Uuid, room_id: &str) -> Result<MigrationStep, AppError> {
        let _guard = self.lock.lock().await;
        let Some(mut m) = self.migration(room_id).await? else {
            return Ok(MigrationStep::Interrupted);
        };
        if m.migration_id != migration_id || m.state != MigrationState::Running {
            return Ok(MigrationStep::Interrupted);
        }
        let mut batch = Batch::new();
        self.unreserve(&mut batch, &m.to_config, m.reserved_bytes)
            .await?;
        self.forget_done(&mut batch, room_id).await?;
        m.reserved_bytes = 0;
        m.state = MigrationState::Complete;
        m.in_flight = None;
        m.next_attempt_at = None;
        m.updated_at = now_secs();
        batch.insert(migration_key(room_id), &m)?;
        self.blobs.apply_batch(batch).await?;
        crate::observe::changed();
        Ok(MigrationStep::Complete(m))
    }

    /// A copy did not verify: `failed`. The blob stays where it is, the plan goes and
    /// the reservation is given back (`migrate` item 3).
    async fn fail(
        &self,
        migration_id: Uuid,
        room_id: &str,
        why: String,
        copy: Option<BackendRef>,
    ) -> Result<MigrationStep, AppError> {
        let m = {
            let _guard = self.lock.lock().await;
            let Some(mut m) = self.migration(room_id).await? else {
                return Ok(MigrationStep::Interrupted);
            };
            if m.migration_id != migration_id || m.state != MigrationState::Running {
                return Ok(MigrationStep::Interrupted);
            }
            let mut batch = Batch::new();
            for k in self
                .blobs
                .prefix_keys(plan_prefix(room_id).into_bytes())
                .await?
            {
                batch.remove(k);
            }
            self.unreserve(&mut batch, &m.to_config, m.reserved_bytes)
                .await?;
            self.forget_done(&mut batch, room_id).await?;
            let in_flight = m.in_flight.take();
            m.reserved_bytes = 0;
            m.state = MigrationState::Failed;
            m.last_error = Some(why);
            m.next_attempt_at = None;
            m.updated_at = now_secs();
            batch.insert(migration_key(room_id), &m)?;
            self.blobs.apply_batch(batch).await?;
            (m, in_flight)
        };
        let (m, in_flight) = m;
        if let Some(f) = in_flight
            && let Some(at) = copy.or(f.copy)
        {
            self.discard_copy(&m.to_config, room_id, &f.blob_ref, &at)
                .await;
        }
        crate::observe::changed();
        Ok(MigrationStep::Failed(m))
    }

    /// Add to `batch` forgetting which blobs the room's migration switched: it is no
    /// longer open, so none of them can be dropped from it.
    async fn forget_done(&self, batch: &mut Batch, room_id: &str) -> Result<(), AppError> {
        for k in self
            .blobs
            .prefix_keys(done_prefix(room_id).into_bytes())
            .await?
        {
            batch.remove(k);
        }
        Ok(())
    }

    /// A step failed for a reason that may pass: back off, or — after
    /// [`MIGRATION_MAX_ATTEMPTS`] in a row — pause, put down to `cause`, until the
    /// runner tries again by itself at `next_attempt_at` (`migrate` items 10, 11). What
    /// was copied is kept.
    async fn retry(
        &self,
        migration_id: Uuid,
        room_id: &str,
        cause: PauseCause,
        why: String,
    ) -> Result<MigrationStep, AppError> {
        let _guard = self.lock.lock().await;
        let Some(mut m) = self.migration(room_id).await? else {
            return Ok(MigrationStep::Interrupted);
        };
        if m.migration_id != migration_id || m.state != MigrationState::Running {
            return Ok(MigrationStep::Interrupted);
        }
        let now = now_secs();
        let prefix = blob_store::room_prefix(room_id);
        let hash = room_hash(room_id);
        let blob = m.in_flight_blob().unwrap_or_default().to_string();
        m.attempts += 1;
        m.last_error = Some(scrub_error(&why, &[room_id, &prefix, &hash, &blob]));
        m.updated_at = now;
        let paused = m.attempts >= MIGRATION_MAX_ATTEMPTS;
        if paused {
            m.state = MigrationState::Paused;
            m.paused_cause = Some(cause);
            m.next_attempt_at = Some(paused_retry_at(now));
        } else {
            m.next_attempt_at = Some(now + backoff_secs(m.attempts));
        }
        self.blobs.insert(migration_key(room_id), &m).await?;
        crate::observe::changed();
        Ok(if paused {
            MigrationStep::Paused(m)
        } else {
            MigrationStep::Retrying(m)
        })
    }

    /// Delete the previous copies of moved blobs whose grace window has passed, from
    /// their stores, and stop counting them. Part of [`Self::sweep`].
    pub(super) async fn sweep_moved(&self, now: u64, grace: u64) -> Result<usize, AppError> {
        let mut collected = 0;
        for (key, _) in self.blobs.prefix_iter_raw(b"moved:".to_vec()).await? {
            let _guard = self.lock.lock().await;
            let Some(row) = self.blobs.get::<MovedCopy>(key.clone()).await? else {
                continue;
            };
            if row.moved_at + grace > now {
                continue;
            }
            // Moved back since onto the same object: the entry names it, so it stays.
            let live = self
                .blob(&row.room_id, &row.blob_ref)
                .await?
                .is_some_and(|e| e.config_id == row.config_id && e.backend_ref == row.backend_ref);
            if !live {
                let deleted = match self.stores.store_for(&row.config_id, &row.room_id).await {
                    Ok(store) => store.delete(&row.backend_ref).await,
                    Err(e) => Err(e),
                };
                match deleted {
                    Ok(Deletion::Deleted) | Ok(Deletion::Lapses { .. }) => {}
                    Ok(Deletion::Unsupported) => {
                        tracing::warn!(blob = %row.blob_ref, "store cannot delete a moved blob's old copy; forgetting it");
                    }
                    Err(e) => {
                        tracing::warn!(blob = %row.blob_ref, error = %e, "a moved blob's old copy was not deleted; retry next pass");
                        continue;
                    }
                }
            }
            let mut batch = Batch::new();
            batch.remove(key);
            self.uncount_copy(&mut batch, &row.config_id, row.size)
                .await?;
            self.blobs.apply_batch(batch).await?;
            crate::observe::changed();
            collected += 1;
        }
        Ok(collected)
    }

    /// The old copies awaiting deletion, by config: `(files, bytes)`. Part of
    /// [`Self::config_holdings`], so a draining config retires only once they are gone.
    pub(super) async fn moved_holdings(
        &self,
    ) -> Result<std::collections::HashMap<String, (u64, u64)>, AppError> {
        let mut out = std::collections::HashMap::<String, (u64, u64)>::new();
        for (_, raw) in self.blobs.prefix_iter_raw(b"moved:".to_vec()).await? {
            if let Ok(row) = serde_json::from_slice::<MovedCopy>(&raw) {
                let h = out.entry(row.config_id).or_default();
                h.0 += 1;
                h.1 += row.size;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use vti_common::blob_store::{local::LocalDirStore, sha256_digest_multibase};

    const CHUNK: usize = 16_384;
    const MEMBER: &str = "did:key:zMember";
    const FAST: u64 = 1 << 40;

    /// Configs `a` and `b` on two directories, `c` with no store; uploads go to the
    /// room's current assignment.
    struct Stores {
        stores: HashMap<String, Arc<dyn BlobStore>>,
        assigned: Mutex<String>,
    }

    #[async_trait::async_trait]
    impl BlobStores for Stores {
        async fn upload_target(&self, _room_id: &str) -> Result<UploadTarget, AppError> {
            Ok(UploadTarget {
                config_id: self.assigned.lock().unwrap().clone(),
                capacity_bytes: None,
            })
        }
        async fn store_for(
            &self,
            config_id: &str,
            _room_id: &str,
        ) -> Result<Arc<dyn BlobStore>, AppError> {
            self.stores
                .get(config_id)
                .cloned()
                .ok_or_else(|| AppError::Internal(format!("no store for `{config_id}`")))
        }
    }

    struct Fixture {
        dir: tempfile::TempDir,
        host: BlobHost,
        stores: Arc<Stores>,
    }

    fn fixture(limits: HostLimits) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().join("store"),
        })
        .unwrap();
        let mut map: HashMap<String, Arc<dyn BlobStore>> = HashMap::new();
        for c in ["a", "b"] {
            map.insert(
                c.into(),
                Arc::new(LocalDirStore::new(dir.path().join(format!("blobs-{c}")))),
            );
        }
        let stores = Arc::new(Stores {
            stores: map,
            assigned: Mutex::new("a".into()),
        });
        let host = BlobHost::new(
            store.keyspace(ROOM_BLOBS_KEYSPACE).unwrap(),
            store.keyspace(ROOM_BLOB_TRANSFERS_KEYSPACE).unwrap(),
            dir.path().join("staging"),
            stores.clone(),
            limits,
        );
        Fixture { dir, host, stores }
    }

    fn room() -> Room {
        Room {
            room_id: "did:key:zRoom".into(),
            owner_did: "did:key:zOwner".into(),
            visibility: Visibility::Attributed,
            retention_policy: crate::RetentionPolicy::Chained,
            anchor_cadence: Default::default(),
            epoch: 1,
            next_version: 1,
            retention_days: 90,
            epoch_expires_at: None,
            created_at: 0,
            updated_at: 0,
            mirror_of: None,
        }
    }

    /// A blob of `len` bytes, in 16 KiB chunks.
    fn blob(len: usize, seed: u8) -> (Vec<u8>, Manifest) {
        let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_add(seed)).collect();
        let digests: Vec<String> = bytes
            .chunks(CHUNK)
            .map(|c| sha256_digest_multibase(&Sha256::digest(c).into()))
            .collect();
        let raw = serde_json::json!({
            "size": len,
            "chunks": { "chunkSize": CHUNK, "chunkCount": digests.len(), "chunkDigests": digests },
            "digest": sha256_digest_multibase(&Sha256::digest(&bytes).into()),
        });
        (bytes, Manifest::parse(&raw).unwrap())
    }

    fn other_room(id: &str) -> Room {
        Room {
            room_id: id.into(),
            ..room()
        }
    }

    /// The record naming blob `seed` no longer does: the blob is orphaned.
    async fn orphan(f: &Fixture, seed: u8) {
        f.host
            .prepare_record(&room(), Some(MEMBER), &format!("rec-{seed}"), &[])
            .await
            .unwrap()
            .apply()
            .await
            .unwrap();
    }

    async fn upload(f: &Fixture, len: usize, seed: u8) -> String {
        upload_to(f, &room(), len, seed).await
    }

    async fn upload_to(f: &Fixture, r: &Room, len: usize, seed: u8) -> String {
        let r = r.clone();
        let (bytes, manifest) = blob(len, seed);
        let digests = manifest.chunk_digests.clone();
        let begun = f
            .host
            .begin(&r, MEMBER, Some(MEMBER), manifest)
            .await
            .unwrap();
        let id = begun.upload_id.to_string();
        for (i, chunk) in bytes.chunks(CHUNK).enumerate() {
            f.host
                .put_chunk(MEMBER, &id, i as u64, &digests[i], chunk)
                .await
                .unwrap();
        }
        let blob_ref = f.host.commit(MEMBER, &id).await.unwrap().blob_ref;
        // Named by a record, as a file is, so collection leaves it.
        f.host
            .prepare_record(
                &r,
                Some(MEMBER),
                &format!("rec-{seed}"),
                std::slice::from_ref(&blob_ref),
            )
            .await
            .unwrap()
            .apply()
            .await
            .unwrap();
        blob_ref
    }

    async fn read_all(f: &Fixture, blob_ref: &str) -> Vec<u8> {
        let r = room();
        let d = f
            .host
            .open_download(&r, MEMBER, Some(MEMBER), blob_ref)
            .await
            .unwrap();
        let manifest = Manifest::parse(&d.manifest).unwrap();
        let mut out = Vec::new();
        for i in 0..manifest.chunk_count {
            let c = f
                .host
                .read_chunk(MEMBER, &d.download_id.to_string(), i)
                .await
                .unwrap();
            out.extend(c.data);
        }
        out
    }

    fn reassign(f: &Fixture, config: &str) {
        *f.stores.assigned.lock().unwrap() = config.into();
    }

    async fn start(f: &Fixture, to: &str) -> MigrationStart {
        f.host
            .start_migration(MigrationRequest::new(
                room().room_id,
                to,
                "did:key:zAdmin",
                "move",
            ))
            .await
            .unwrap()
    }

    async fn run(f: &Fixture) -> Migration {
        for _ in 0..100 {
            match f.host.migrate_step(&room().room_id, FAST).await.unwrap() {
                MigrationStep::Complete(m)
                | MigrationStep::Failed(m)
                | MigrationStep::Paused(m) => {
                    return m;
                }
                MigrationStep::Idle => {
                    return f.host.migration(&room().room_id).await.unwrap().unwrap();
                }
                _ => {}
            }
        }
        panic!("the migration did not settle");
    }

    async fn counter(f: &Fixture, key: &str) -> StorageUsage {
        f.host.counter(key).await.unwrap()
    }

    fn object(f: &Fixture, config: &str, blob_ref: &str) -> std::path::PathBuf {
        let key = BlobKey::for_room(&room().room_id, blob_ref).unwrap();
        f.dir
            .path()
            .join(format!("blobs-{config}"))
            .join(key.as_str())
    }

    #[tokio::test]
    async fn every_blob_moves_verified_and_its_old_copy_is_collected_after_the_grace() {
        let f = fixture(HostLimits {
            orphan_grace_secs: 0,
            ..HostLimits::default()
        });
        let one = upload(&f, 40_000, 1).await;
        let two = upload(&f, 1_000, 2).await;
        reassign(&f, "b");

        let MigrationStart::Started(m) = start(&f, "b").await else {
            panic!("not started");
        };
        assert_eq!((m.total_files, m.total_bytes), (2, 41_000));
        assert_eq!(m.from_configs, vec!["a".to_string()]);
        assert_eq!(counter(&f, "usage:config:b").await.reserved_bytes, 41_000);

        let done = run(&f).await;
        assert_eq!(done.state, MigrationState::Complete);
        assert_eq!((done.done_files, done.done_bytes), (2, 41_000));
        for b in [&one, &two] {
            let e = f.host.blob(&room().room_id, b).await.unwrap().unwrap();
            assert_eq!(e.config_id, "b");
            assert!(object(&f, "b", b).exists());
        }
        assert_eq!(read_all(&f, &one).await, blob(40_000, 1).0);

        // Both copies count until the old one is deleted.
        let b = counter(&f, "usage:config:b").await;
        assert_eq!((b.files, b.bytes, b.reserved_bytes), (2, 41_000, 0));
        assert_eq!(counter(&f, "usage:config:a").await.bytes, 41_000);
        let held = f.host.config_holdings().await.unwrap();
        assert_eq!(held["a"].files, 2);
        assert_eq!(held["a"].pending_delete_bytes, 41_000);

        f.host.sweep().await.unwrap();
        assert!(!object(&f, "a", &one).exists());
        let a = counter(&f, "usage:config:a").await;
        assert_eq!((a.files, a.bytes), (0, 0));
        assert!(!f.host.config_holdings().await.unwrap().contains_key("a"));
        let s = counter(&f, STORAGE_USAGE_KEY).await;
        assert_eq!((s.files, s.bytes, s.reserved_bytes), (2, 41_000, 0));
        // The room's own usage never moved.
        assert_eq!(
            f.host.room_usage(&room().room_id).await.unwrap().bytes,
            41_000
        );
    }

    #[tokio::test]
    async fn a_room_with_nothing_to_move_completes_at_once() {
        let f = fixture(HostLimits::default());
        upload(&f, 100, 1).await;
        let MigrationStart::Started(m) = start(&f, "a").await else {
            panic!("not started");
        };
        assert_eq!(m.state, MigrationState::Complete);
        assert_eq!(m.total_files, 0);
    }

    #[tokio::test]
    async fn a_target_that_cannot_hold_the_bytes_starts_nothing() {
        let f = fixture(HostLimits::default());
        upload(&f, 1_000, 1).await;
        let mut req = MigrationRequest::new(room().room_id, "b", "did:key:zAdmin", "move");
        req.capacity_bytes = Some(500);
        let out = f.host.start_migration(req).await.unwrap();
        assert!(
            matches!(
                out,
                MigrationStart::CapacityExceeded {
                    capacity: 500,
                    used: 0,
                    requested: 1_000
                }
            ),
            "{out:?}"
        );
        assert!(f.host.migration(&room().room_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_second_request_answers_with_the_migration_and_resumes_a_paused_one() {
        let f = fixture(HostLimits::default());
        upload(&f, 1_000, 1).await;
        let MigrationStart::Started(first) = start(&f, "b").await else {
            panic!();
        };
        // Reassigned meanwhile: the migration keeps its target.
        let MigrationStart::InProgress(again) = start(&f, "c").await else {
            panic!();
        };
        assert_eq!(again.migration_id, first.migration_id);
        assert_eq!(again.to_config, "b");

        f.host.pause_running_migrations("restored").await.unwrap();
        let MigrationStart::Resumed(resumed) = start(&f, "b").await else {
            panic!();
        };
        assert_eq!(resumed.migration_id, first.migration_id);
        assert_eq!(resumed.state, MigrationState::Running);
        assert_eq!(run(&f).await.state, MigrationState::Complete);
    }

    #[tokio::test]
    async fn a_corrupt_source_fails_the_migration_and_the_blob_stays() {
        let f = fixture(HostLimits::default());
        let b = upload(&f, 1_000, 1).await;
        std::fs::write(object(&f, "a", &b), vec![0u8; 1_000]).unwrap();
        start(&f, "b").await;
        let m = run(&f).await;
        assert_eq!(m.state, MigrationState::Failed);
        assert!(m.last_error.unwrap().contains("committed digest"));
        let e = f.host.blob(&room().room_id, &b).await.unwrap().unwrap();
        assert_eq!(e.config_id, "a");
        assert_eq!(counter(&f, "usage:config:b").await.reserved_bytes, 0);
        assert_eq!(counter(&f, STORAGE_USAGE_KEY).await.reserved_bytes, 0);
        // A new request starts a new migration.
        assert!(matches!(start(&f, "b").await, MigrationStart::Started(_)));
    }

    /// The process dies after each step of a blob's move; the next step resumes it,
    /// the blob is readable throughout, and the end state is as if nothing happened.
    #[tokio::test]
    async fn a_migration_survives_dying_at_every_step() {
        for stop in [StopAfter::Chosen, StopAfter::Copied, StopAfter::Verified] {
            let f = fixture(HostLimits::default());
            let b = upload(&f, 40_000, 3).await;
            start(&f, "b").await;
            let out = f
                .host
                .step_inner(&room().room_id, FAST, Some(stop))
                .await
                .unwrap();
            assert!(matches!(out, MigrationStep::Interrupted), "{stop:?}");
            // Still served from where it was.
            assert_eq!(read_all(&f, &b).await, blob(40_000, 3).0, "{stop:?}");
            assert_eq!(
                f.host
                    .blob(&room().room_id, &b)
                    .await
                    .unwrap()
                    .unwrap()
                    .config_id,
                "a"
            );

            let m = run(&f).await;
            assert_eq!(m.state, MigrationState::Complete, "{stop:?}");
            assert_eq!((m.done_files, m.total_files), (1, 1), "{stop:?}");
            assert_eq!(read_all(&f, &b).await, blob(40_000, 3).0);
            let t = counter(&f, "usage:config:b").await;
            assert_eq!(
                (t.files, t.bytes, t.reserved_bytes),
                (1, 40_000, 0),
                "{stop:?}"
            );
            assert_eq!(f.host.moved_holdings().await.unwrap()["a"], (1, 40_000));
        }
    }

    /// A restore pauses a running migration; its recorded copy is gone (the bytes are
    /// never in a backup). Resumed, the copy is verified again, found missing and made
    /// again.
    #[tokio::test]
    async fn a_resumed_migration_verifies_its_copy_again() {
        let f = fixture(HostLimits::default());
        let b = upload(&f, 1_000, 4).await;
        start(&f, "b").await;
        f.host
            .step_inner(&room().room_id, FAST, Some(StopAfter::Copied))
            .await
            .unwrap();
        std::fs::remove_file(object(&f, "b", &b)).unwrap();
        let paused = f.host.pause_running_migrations("restored").await.unwrap();
        assert_eq!(paused.len(), 1);
        assert!(matches!(
            f.host.migrate_step(&room().room_id, FAST).await.unwrap(),
            MigrationStep::Idle
        ));
        assert!(matches!(start(&f, "b").await, MigrationStart::Resumed(_)));
        assert_eq!(run(&f).await.state, MigrationState::Complete);
        assert_eq!(read_all(&f, &b).await, blob(1_000, 4).0);
    }

    /// A blob orphaned between its copy and the switch is not switched: its copy is
    /// discarded and it leaves the totals.
    #[tokio::test]
    async fn a_blob_that_changed_under_the_copy_is_skipped() {
        let f = fixture(HostLimits::default());
        let b = upload(&f, 1_000, 5).await;
        let keep = upload(&f, 2_000, 6).await;
        start(&f, "b").await;
        // Plan rows are in key order; orphan whichever is first.
        let (gone, stays) = if b < keep { (&b, &keep) } else { (&keep, &b) };
        f.host
            .step_inner(&room().room_id, FAST, Some(StopAfter::Verified))
            .await
            .unwrap();
        let mut e = f.host.blob(&room().room_id, gone).await.unwrap().unwrap();
        e.state = BlobState::Orphaned;
        f.host
            .blobs
            .insert(blob_key(&room().room_id, gone), &e)
            .await
            .unwrap();
        let m = run(&f).await;
        assert_eq!(m.state, MigrationState::Complete);
        assert_eq!((m.total_files, m.done_files), (1, 1));
        assert!(!object(&f, "b", gone).exists());
        assert_eq!(
            f.host
                .blob(&room().room_id, stays)
                .await
                .unwrap()
                .unwrap()
                .config_id,
            "b"
        );
        assert_eq!(counter(&f, "usage:config:b").await.reserved_bytes, 0);
    }

    /// A target with no store is retried with backoff, then paused, keeping its plan.
    #[tokio::test]
    async fn an_unreachable_target_backs_off_then_pauses() {
        let f = fixture(HostLimits::default());
        upload(&f, 1_000, 7).await;
        start(&f, "c").await;
        let rid = room().room_id;
        let mut last = None;
        for i in 0..MIGRATION_MAX_ATTEMPTS {
            let out = f.host.migrate_step(&rid, FAST).await.unwrap();
            if i + 1 < MIGRATION_MAX_ATTEMPTS {
                assert!(matches!(out, MigrationStep::Retrying(_)), "{out:?}");
                assert!(matches!(
                    f.host.migrate_step(&rid, FAST).await.unwrap(),
                    MigrationStep::Waiting { .. }
                ));
                // The backoff has passed.
                let mut m = f.host.migration(&rid).await.unwrap().unwrap();
                m.next_attempt_at = None;
                f.host.blobs.insert(migration_key(&rid), &m).await.unwrap();
            }
            last = Some(out);
        }
        let Some(MigrationStep::Paused(m)) = last else {
            panic!("{last:?}");
        };
        assert_eq!(m.state, MigrationState::Paused);
        assert_eq!(m.reserved_bytes, 1_000);
        // Item 11: why, what failed, and when it is tried again by the runner itself.
        assert_eq!(m.paused_cause, Some(PauseCause::Credential));
        assert!(
            m.last_error
                .as_deref()
                .unwrap()
                .starts_with("credential for c:")
        );
        let at = m.next_attempt_at.expect("the runner tries again by itself");
        assert!(at >= now_secs() + PAUSED_RETRY_SECS - 5);
        assert!(f.host.running_migrations().await.unwrap().is_empty());

        // Not before its time; then resumed as the same migration, its retries anew.
        assert!(f.host.resume_due(at - 1).await.unwrap().is_empty());
        let resumed = f.host.resume_due(at).await.unwrap();
        assert_eq!(resumed.len(), 1);
        let r = &resumed[0];
        assert_eq!(r.migration_id, m.migration_id);
        assert_eq!(r.state, MigrationState::Running);
        assert_eq!(
            (r.attempts, r.paused_cause, r.next_attempt_at),
            (0, None, None)
        );
    }

    /// Item 10: a failure short of the cap leaves the migration `running`, waiting out a
    /// backoff that reports its error and next attempt; it never pauses early.
    #[tokio::test]
    async fn a_failure_short_of_the_cap_backs_off_running() {
        let f = fixture(HostLimits::default());
        upload(&f, 1_000, 9).await;
        start(&f, "c").await;
        let out = f.host.migrate_step(&room().room_id, FAST).await.unwrap();
        let MigrationStep::Retrying(m) = out else {
            panic!("{out:?}");
        };
        assert_eq!(m.state, MigrationState::Running);
        assert_eq!(m.paused_cause, None);
        assert!(m.last_error.is_some());
        assert!(m.next_attempt_at.unwrap() > now_secs());
    }

    /// The runner's own check of the target (no longer `active`) counts as a failed
    /// attempt, paused as `destination` once the retries run out.
    #[tokio::test]
    async fn a_target_no_longer_active_pauses_as_destination_after_its_retries() {
        let f = fixture(HostLimits::default());
        upload(&f, 1_000, 10).await;
        let MigrationStart::Started(m) = start(&f, "b").await else {
            panic!();
        };
        let rid = room().room_id;
        let mut last = None;
        for _ in 0..MIGRATION_MAX_ATTEMPTS {
            last = Some(
                f.host
                    .migration_step_failed(
                        &rid,
                        m.migration_id,
                        PauseCause::Destination,
                        "put to b: the config is draining",
                    )
                    .await
                    .unwrap(),
            );
        }
        let Some(MigrationStep::Paused(p)) = last else {
            panic!("{last:?}");
        };
        assert_eq!(p.paused_cause, Some(PauseCause::Destination));
        assert_eq!(
            p.last_error.as_deref(),
            Some("put to b: the config is draining")
        );
    }

    /// Item 9: reassigned while it runs, the migration keeps moving to the config it was
    /// approved for; new uploads go to the new assignment; a later migration moves
    /// everything, what the first moved included.
    #[tokio::test]
    async fn a_reassignment_mid_move_keeps_the_target() {
        let f = fixture(HostLimits::default());
        let one = upload(&f, 1_000, 11).await;
        let two = upload(&f, 2_000, 12).await;
        reassign(&f, "b");
        let MigrationStart::Started(m) = start(&f, "b").await else {
            panic!();
        };
        // One blob moves, then the room is reassigned back to `a`.
        assert!(matches!(
            f.host.migrate_step(&room().room_id, FAST).await.unwrap(),
            MigrationStep::Moved(_)
        ));
        reassign(&f, "a");
        let fresh = upload(&f, 500, 13).await;
        assert_eq!(
            f.host
                .blob(&room().room_id, &fresh)
                .await
                .unwrap()
                .unwrap()
                .config_id,
            "a"
        );
        // Asked again, now that the room is on `a`: the same migration, still to `b`.
        let MigrationStart::InProgress(again) = start(&f, "a").await else {
            panic!();
        };
        assert_eq!(
            (again.migration_id, again.to_config.as_str()),
            (m.migration_id, "b")
        );
        let done = run(&f).await;
        assert_eq!(done.state, MigrationState::Complete);
        assert_eq!(done.to_config, "b");
        assert_eq!((done.done_files, done.total_files), (2, 2));
        for b in [&one, &two] {
            assert_eq!(
                f.host
                    .blob(&room().room_id, b)
                    .await
                    .unwrap()
                    .unwrap()
                    .config_id,
                "b"
            );
        }
        assert_eq!(
            f.host
                .blob(&room().room_id, &fresh)
                .await
                .unwrap()
                .unwrap()
                .config_id,
            "a"
        );

        // Finished: a new migration moves the room's blobs to the config assigned now.
        let MigrationStart::Started(next) = start(&f, "a").await else {
            panic!();
        };
        assert_ne!(next.migration_id, m.migration_id);
        assert_eq!((next.total_files, next.total_bytes), (2, 3_000));
        assert_eq!(run(&f).await.state, MigrationState::Complete);
        for b in [&one, &two, &fresh] {
            assert_eq!(
                f.host
                    .blob(&room().room_id, b)
                    .await
                    .unwrap()
                    .unwrap()
                    .config_id,
                "a"
            );
        }
    }

    /// Item 12: an orphan is never planned or counted; one orphaned while the migration
    /// is open leaves it at once — before its switch, from the totals and the
    /// reservation; after, from the done counts too.
    #[tokio::test]
    async fn an_orphan_is_neither_moved_nor_counted() {
        let f = fixture(HostLimits::default());
        let already = upload(&f, 300, 14).await;
        orphan(&f, 14).await;
        let first = upload(&f, 1_000, 15).await;
        let second = upload(&f, 2_000, 16).await;
        let MigrationStart::Started(m) = start(&f, "b").await else {
            panic!();
        };
        assert_eq!((m.total_files, m.total_bytes), (2, 3_000));

        // Move whichever is planned first, then orphan each in turn.
        let MigrationStep::Moved(after_one) =
            f.host.migrate_step(&room().room_id, FAST).await.unwrap()
        else {
            panic!();
        };
        assert_eq!(after_one.done_files, 1);
        let (moved, pending, moved_seed, pending_seed, moved_size, pending_size) = if f
            .host
            .blob(&room().room_id, &first)
            .await
            .unwrap()
            .unwrap()
            .config_id
            == "b"
        {
            (&first, &second, 15, 16, 1_000, 2_000)
        } else {
            (&second, &first, 16, 15, 2_000, 1_000)
        };
        let _ = (moved, pending);

        orphan(&f, pending_seed).await;
        let m = f.host.migration(&room().room_id).await.unwrap().unwrap();
        assert_eq!((m.total_files, m.total_bytes), (1, moved_size));
        assert_eq!(m.reserved_bytes, 0);
        assert_eq!(counter(&f, "usage:config:b").await.reserved_bytes, 0);
        let _ = pending_size;

        orphan(&f, moved_seed).await;
        let m = f.host.migration(&room().room_id).await.unwrap().unwrap();
        assert_eq!(
            (m.total_files, m.total_bytes, m.done_files, m.done_bytes),
            (0, 0, 0, 0)
        );
        assert_eq!(run(&f).await.state, MigrationState::Complete);
        // The orphan from before was never touched.
        assert_eq!(
            f.host
                .blob(&room().room_id, &already)
                .await
                .unwrap()
                .unwrap()
                .config_id,
            "a"
        );
    }

    /// Item 13: one migration per target config at a time; the others are `queued`,
    /// copy nothing, are answered as they stand, and start in the order approved.
    #[tokio::test]
    async fn migrations_to_one_config_queue_in_order() {
        let f = fixture(HostLimits::default());
        let rooms = [
            room(),
            other_room("did:key:zRoom2"),
            other_room("did:key:zRoom3"),
        ];
        for (i, r) in rooms.iter().enumerate() {
            upload_to(&f, r, 1_000, 20 + i as u8).await;
        }
        let mut started = Vec::new();
        for r in &rooms {
            let MigrationStart::Started(m) = f
                .host
                .start_migration(MigrationRequest::new(
                    &r.room_id,
                    "b",
                    "did:key:zAdmin",
                    "move",
                ))
                .await
                .unwrap()
            else {
                panic!();
            };
            started.push(m);
        }
        assert_eq!(started[0].state, MigrationState::Running);
        assert_eq!(started[1].state, MigrationState::Queued);
        assert_eq!(started[2].state, MigrationState::Queued);
        // Every one's bytes are reserved at approval (item 2).
        assert_eq!(counter(&f, "usage:config:b").await.reserved_bytes, 3_000);
        // A queued one is not stepped, and is the answer to a second request; the rate
        // it names is adopted.
        assert!(matches!(
            f.host.migrate_step(&rooms[1].room_id, FAST).await.unwrap(),
            MigrationStep::Idle
        ));
        let mut again = MigrationRequest::new(&rooms[1].room_id, "a", "did:key:zOther", "other");
        again.max_bytes_per_second = Some(100_000);
        let MigrationStart::InProgress(q) = f.host.start_migration(again).await.unwrap() else {
            panic!();
        };
        assert_eq!(q.state, MigrationState::Queued);
        assert_eq!((q.to_config.as_str(), q.reason.as_str()), ("b", "move"));
        assert_eq!(q.max_bytes_per_second, Some(100_000));
        // Nothing starts while the first is open, paused included.
        assert!(f.host.promote_queued().await.unwrap().is_empty());
        f.host.pause_running_migrations("restored").await.unwrap();
        assert!(f.host.promote_queued().await.unwrap().is_empty());
        assert!(matches!(start(&f, "b").await, MigrationStart::Resumed(_)));
        assert_eq!(run(&f).await.state, MigrationState::Complete);

        // Then the next approved, and only it.
        let next = f.host.promote_queued().await.unwrap();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].migration_id, started[1].migration_id);
        assert!(f.host.promote_queued().await.unwrap().is_empty());
        for _ in 0..10 {
            f.host.migrate_step(&rooms[1].room_id, FAST).await.unwrap();
        }
        let next = f.host.promote_queued().await.unwrap();
        assert_eq!(next[0].migration_id, started[2].migration_id);

        // A migration to another config is not held up.
        upload_to(&f, &other_room("did:key:zRoom4"), 100, 30).await;
        let MigrationStart::Started(elsewhere) = f
            .host
            .start_migration(MigrationRequest::new(
                "did:key:zRoom4",
                "c",
                "did:key:zAdmin",
                "x",
            ))
            .await
            .unwrap()
        else {
            panic!();
        };
        assert_eq!(elsewhere.state, MigrationState::Running);
    }

    /// Moved off `a`, then back onto it before the old copy was collected: the
    /// collection pass does not delete the object the entry names again.
    #[tokio::test]
    async fn moving_back_within_the_grace_keeps_the_live_copy() {
        let f = fixture(HostLimits {
            orphan_grace_secs: 3_600,
            ..HostLimits::default()
        });
        let b = upload(&f, 1_000, 8).await;
        start(&f, "b").await;
        run(&f).await;
        start(&f, "a").await;
        assert_eq!(run(&f).await.state, MigrationState::Complete);
        let e = f.host.blob(&room().room_id, &b).await.unwrap().unwrap();
        assert_eq!(e.config_id, "a");
        // The reclaimed row is gone; `b`'s old copy is the only one pending.
        let pending = f.host.moved_holdings().await.unwrap();
        assert!(!pending.contains_key("a"), "{pending:?}");
        assert_eq!(pending["b"], (1, 1_000));
        let a = counter(&f, "usage:config:a").await;
        assert_eq!((a.files, a.bytes), (1, 1_000));
        f.host.sweep_moved(now_secs() + 7_200, 3_600).await.unwrap();
        assert!(object(&f, "a", &b).exists());
        assert_eq!(read_all(&f, &b).await, blob(1_000, 8).0);
    }

    #[test]
    fn a_kept_error_loses_what_could_be_a_credential() {
        let s = scrub_error(
            "GET https://b.s3.amazonaws.com/rooms/x?X-Amz-Signature=abc&X-Amz-Credential=AKIA failed",
            &[],
        );
        assert!(!s.contains("X-Amz"), "{s}");
        assert!(s.ends_with("failed"));
        // Item 11: never the room's identifier, nor a blob's reference.
        let s = scrub_error(
            "put to eu: room:z6MkRoom/zQmBlob: 503 SlowDown",
            &["room:z6MkRoom", "zQmBlob"],
        );
        assert_eq!(s, "put to eu: …/…: 503 SlowDown");
    }

    #[test]
    fn backoff_is_jittered_under_a_cap() {
        for a in 0..20 {
            let s = backoff_secs(a);
            assert!((1..=BACKOFF_CAP_SECS).contains(&s));
        }
    }
}
