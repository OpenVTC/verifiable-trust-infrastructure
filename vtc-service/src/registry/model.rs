//! Trust-registry persistence model.
//!
//! Two row shapes:
//!
//! - [`RegistryRecord`] (one per member) — mirrors spec §5.7.
//!   Captures what the registry knows about each member +
//!   when the local view was last synced.
//! - [`SyncJob`] (one per outstanding mutation) — pending /
//!   in-flight / failed reconciliation jobs. Drained by
//!   `MembershipSyncer` (M3.4).
//!
//! Plus [`exponential_backoff_seconds`] — the canonical
//! retry-schedule helper. Lives here so it can be unit-tested
//! independently of the syncer task.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Wire-form status for [`RegistryRecord::status`]. Mirrors the
/// `status ∈ { Active, Departed }` enumeration in spec §5.7.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RegistryStatus {
    Active,
    Departed,
}

/// Local mirror of a registry record. Updated when a
/// [`SyncJob`] completes successfully so the daemon can detect
/// drift at boot (e.g. registry contains a record we don't
/// know about, or vice versa).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RegistryRecord {
    pub member_did: String,
    pub status: RegistryStatus,
    pub active_from: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_to: Option<DateTime<Utc>>,
    pub last_synced_at: DateTime<Utc>,
}

impl RegistryRecord {
    /// Convenience constructor for an Active record being
    /// freshly published.
    pub fn fresh_active(member_did: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            member_did: member_did.into(),
            status: RegistryStatus::Active,
            active_from: now,
            active_to: None,
            last_synced_at: now,
        }
    }

    /// Convenience constructor for a Departed record (post-
    /// removal). Caller decides whether to populate
    /// `active_to` based on the disposition (Tombstone leaves
    /// it `None`; Historical fills it).
    pub fn departed(
        member_did: impl Into<String>,
        active_from: DateTime<Utc>,
        active_to: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            member_did: member_did.into(),
            status: RegistryStatus::Departed,
            active_from,
            active_to,
            last_synced_at: Utc::now(),
        }
    }
}

// ---------------------------------------------------------------------------
// SyncJob
// ---------------------------------------------------------------------------

/// Kind of mutation a [`SyncJob`] dispatches against the
/// registry. The reconciler maps `MemberAdded` → `PublishMember`,
/// `MemberRemoved` → `DeleteMember` (or `MarkDeparted`,
/// depending on disposition resolution), `RoleChanged` →
/// `UpdateMember`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SyncJobKind {
    /// First-time publish — `MemberAdded` audit event.
    PublishMember,
    /// Role / metadata change — `RoleChanged` /
    /// `MemberUpdated`. Re-publishes the record verbatim.
    UpdateMember,
    /// Removal — `MemberRemoved` with disposition `Purge`.
    DeleteMember,
    /// Removal — `MemberRemoved` with disposition `Tombstone`
    /// or `Historical`. Re-publishes the record with
    /// `status: Departed`.
    MarkDeparted,
}

impl SyncJobKind {
    /// Wire-form name (camelCase). Stable; used by audit
    /// envelopes + telemetry.
    pub fn as_str(self) -> &'static str {
        match self {
            SyncJobKind::PublishMember => "publishMember",
            SyncJobKind::UpdateMember => "updateMember",
            SyncJobKind::DeleteMember => "deleteMember",
            SyncJobKind::MarkDeparted => "markDeparted",
        }
    }
}

/// Lifecycle state of a [`SyncJob`]. Boot-time recovery flips
/// any `InFlight` rows back to `Pending` (the daemon may have
/// crashed between dispatch and storage update).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SyncJobState {
    Pending,
    InFlight,
    Complete,
    Failed,
}

/// Default cap on retry attempts before a job flips to
/// `Failed`. ~18 hours of retries at the exponential schedule
/// in [`exponential_backoff_seconds`]. After that, the row
/// surfaces in `/v1/health/diagnostics` for operator
/// intervention.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 16;

/// Hard cap on the per-retry sleep. Spec §8.3 implies
/// reconciliation should never lag by more than an hour
/// untouched.
pub const MAX_BACKOFF_SECONDS: i64 = 3600;

/// One outstanding reconciliation job.
///
/// `member_did` is stored in plaintext because the registry
/// HTTP / DIDComm call needs the unhashed DID. The hashed
/// form lives only on the audit envelope's actor field (per
/// §11.1). Rows are deleted on `Complete`; `Failed` rows age
/// out after the retention window via the daemon's retention
/// sweeper ([`super::storage::sweep_failed_sync_jobs`], spawned
/// from `server::run`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SyncJob {
    pub id: Uuid,
    pub kind: SyncJobKind,
    pub member_did: String,
    /// Pre-resolved disposition for the `DeleteMember` /
    /// `MarkDeparted` path. `None` on publish / update jobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
    pub created_at: DateTime<Utc>,
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempted_at: Option<DateTime<Utc>>,
    pub next_attempt_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub state: SyncJobState,
    /// `true` when this job's `next_attempt_at` was set by an
    /// RTBF batch trigger rather than a normal retry. Lets the
    /// RTBF timer (M3.7) identify its own jobs without
    /// re-scanning every disposition.
    #[serde(default)]
    pub rtbf_batched: bool,
}

impl SyncJob {
    /// Construct a fresh job, eligible for immediate dispatch.
    pub fn fresh(kind: SyncJobKind, member_did: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            kind,
            member_did: member_did.into(),
            disposition: None,
            created_at: now,
            attempts: 0,
            last_attempted_at: None,
            next_attempt_at: now,
            last_error: None,
            state: SyncJobState::Pending,
            rtbf_batched: false,
        }
    }

    /// `true` when the job is ready to dispatch (state is
    /// `Pending` and `next_attempt_at <= now`).
    pub fn is_dispatchable(&self, now: DateTime<Utc>) -> bool {
        matches!(self.state, SyncJobState::Pending) && self.next_attempt_at <= now
    }

    /// Record a failed attempt. Bumps `attempts`, sets
    /// `next_attempt_at` per the backoff schedule, retains the
    /// error message. Flips to `Failed` when `attempts >
    /// DEFAULT_MAX_ATTEMPTS`.
    pub fn record_failure(&mut self, error: impl Into<String>) {
        self.attempts += 1;
        self.last_attempted_at = Some(Utc::now());
        self.last_error = Some(error.into());
        if self.attempts > DEFAULT_MAX_ATTEMPTS {
            self.state = SyncJobState::Failed;
            return;
        }
        let backoff = exponential_backoff_seconds(self.attempts);
        self.next_attempt_at = Utc::now() + chrono::Duration::seconds(backoff);
        self.state = SyncJobState::Pending;
    }

    /// Record a successful dispatch. Caller is responsible for
    /// deleting the row from `sync_queue:` after marking
    /// complete — the audit envelope + the row deletion both
    /// happen inside the syncer.
    pub fn record_success(&mut self) {
        self.last_attempted_at = Some(Utc::now());
        self.last_error = None;
        self.state = SyncJobState::Complete;
    }
}

/// Exponential backoff with jitter, capped at
/// [`MAX_BACKOFF_SECONDS`]. Schedule:
///
/// `next_attempt = now + min(2^attempts + jitter, 3600)`
///
/// `attempts = 1` → ~2-4 seconds. `attempts = 10` → ~17 min.
/// `attempts = 12+` → 1 hour (cap). The jitter is `0..=attempts`
/// seconds so collocated daemons don't synchronise their
/// retry storms.
pub fn exponential_backoff_seconds(attempts: u32) -> i64 {
    use rand::RngExt;
    let base = 2_i64.saturating_pow(attempts.min(20));
    let jitter = rand::rng().random_range(0..=attempts as i64);
    (base + jitter).min(MAX_BACKOFF_SECONDS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_monotonic_until_cap() {
        // Run many trials so jitter doesn't dominate the
        // monotonicity check.
        for _ in 0..20 {
            let prev = exponential_backoff_seconds(1);
            let later = exponential_backoff_seconds(8);
            assert!(later >= prev, "expected backoff to grow with attempts");
        }
    }

    #[test]
    fn backoff_caps_at_one_hour() {
        for attempts in [12u32, 15, 20, 64] {
            let b = exponential_backoff_seconds(attempts);
            assert!(
                b <= MAX_BACKOFF_SECONDS,
                "backoff for attempts={attempts} exceeds cap: {b}"
            );
        }
    }

    #[test]
    fn fresh_job_is_immediately_dispatchable() {
        let job = SyncJob::fresh(SyncJobKind::PublishMember, "did:key:zX");
        assert!(job.is_dispatchable(Utc::now() + chrono::Duration::seconds(1)));
        assert_eq!(job.attempts, 0);
        assert_eq!(job.state, SyncJobState::Pending);
    }

    #[test]
    fn failure_bumps_attempts_and_schedules_retry() {
        let mut job = SyncJob::fresh(SyncJobKind::PublishMember, "did:key:zX");
        let before = job.next_attempt_at;
        // First failure.
        job.record_failure("transient");
        assert_eq!(job.attempts, 1);
        assert_eq!(job.state, SyncJobState::Pending);
        assert!(job.next_attempt_at > before);
        assert_eq!(job.last_error.as_deref(), Some("transient"));
    }

    #[test]
    fn failure_flips_to_failed_after_max_attempts() {
        let mut job = SyncJob::fresh(SyncJobKind::PublishMember, "did:key:zX");
        for _ in 0..=DEFAULT_MAX_ATTEMPTS {
            job.record_failure("nope");
        }
        assert_eq!(job.state, SyncJobState::Failed);
        assert!(job.attempts > DEFAULT_MAX_ATTEMPTS);
    }

    #[test]
    fn success_marks_complete_and_clears_error() {
        let mut job = SyncJob::fresh(SyncJobKind::PublishMember, "did:key:zX");
        job.record_failure("first try");
        assert!(job.last_error.is_some());
        job.record_success();
        assert_eq!(job.state, SyncJobState::Complete);
        assert!(job.last_error.is_none());
    }

    #[test]
    fn job_wire_round_trips() {
        let job = SyncJob::fresh(SyncJobKind::MarkDeparted, "did:key:zMember");
        let json = serde_json::to_string(&job).unwrap();
        let back: SyncJob = serde_json::from_str(&json).unwrap();
        assert_eq!(back, job);
        // Field names are camelCase wire form.
        assert!(json.contains("\"memberDid\""));
        assert!(json.contains("\"kind\":\"markDeparted\""));
        assert!(json.contains("\"state\":\"pending\""));
    }

    #[test]
    fn registry_record_wire_round_trips() {
        let rec = RegistryRecord::fresh_active("did:key:zMember");
        let json = serde_json::to_string(&rec).unwrap();
        let back: RegistryRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
        assert!(json.contains("\"status\":\"active\""));
    }

    #[test]
    fn departed_omits_active_to_when_none() {
        let from = Utc::now();
        let rec = RegistryRecord::departed("did:key:zMember", from, None);
        let v = serde_json::to_value(&rec).unwrap();
        assert!(
            v.get("activeTo").is_none(),
            "activeTo should be omitted, got {v}"
        );
    }
}
