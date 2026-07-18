//! Membership lifecycle hooks — capability grant propagation.
//!
//! Design: `design-docs/vtc-membership-hooks.md`. Membership changes emitted
//! to the audit log (`MemberAdded` / `MemberRemoved` / `RoleChanged`) are
//! mapped through the operator's hook configuration into capability writes —
//! today, `git-trust/grant|revoke` Trust Tasks against the community's trust
//! registry — and drained by a durable relay modeled on the registry
//! [`MembershipSyncer`](crate::registry::syncer::MembershipSyncer): a second
//! audit-tail consumer with its own cursor and fjall queue, so crash-replay
//! is inherited rather than reimplemented.
//!
//! Semantics:
//! - **Exactly-once-effective**: the job's idempotency root is the audit
//!   row key (`<timestamp>:<event_id>`); redelivery is safe because the
//!   registry answers `already_granted` / `not_granted`, which classify as
//!   [`WriteOutcome::IdempotentSuccess`].
//! - **Ordered**: queue keys are `<created_at>:<uuid>` and dispatch walks
//!   them in order, preserving per-member revoke→grant ordering for role
//!   changes.
//! - **Revocation is delivery-critical (R7.2)**: revoke jobs never fail out
//!   on transient/unreachable errors — they retry with capped backoff until
//!   the registry answers. Grants exhaust a retry budget and surface as
//!   `Failed`. Permanent rejections (e.g. the capability is disabled at the
//!   registry) fail immediately and loudly for both.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{debug, info, warn};
use uuid::Uuid;
use vti_common::audit::{AuditEnvelope, AuditEvent};
use vti_common::capability_client::WriteOutcome;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Default drain tick.
pub const DEFAULT_TICK_INTERVAL_SECONDS: u64 = 5;
/// Backoff: `5s * 2^attempts`, capped at one hour (syncer parity).
const BACKOFF_BASE_SECONDS: u64 = 5;
const BACKOFF_CAP_SECONDS: u64 = 3600;
/// Grants give up after this many attempts; revokes never give up on
/// transient failures.
const GRANT_MAX_ATTEMPTS: u32 = 20;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Operator hook configuration (`[hooks.git-trust]` in the service config).
/// Absent config = no hooks — the relay is not even spawned (R5.1).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HooksConfig {
    #[serde(default, rename = "git-trust")]
    pub git_trust: Option<GitTrustHooksConfig>,
}

/// The git-trust mapping: which community roles produce which
/// commit-signing grants.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GitTrustHooksConfig {
    /// role → the TRQP `resource` the grant covers (an org, or an
    /// `org/repo` slug). Roles not listed produce no grant.
    pub grant_on_role: BTreeMap<String, String>,
    /// Revoke every mapped grant when membership ends. Default true.
    #[serde(default = "default_true")]
    pub revoke_with_membership: bool,
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Job model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookOp {
    Grant,
    Revoke,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookJobState {
    Pending,
    InFlight,
    Failed,
}

/// One durable capability write derived from one audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookJob {
    pub id: Uuid,
    /// The audit row this job derives from (`<rfc3339>:<event_id>`) — the
    /// idempotency root and replay guard.
    pub audit_seq: String,
    pub op: HookOp,
    pub subject_did: String,
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Position within the source audit event's job batch. Part of the
    /// queue key so revoke→grant pairs from one event keep their order
    /// (they share `created_at`, and a UUID tiebreak would be random).
    #[serde(default)]
    pub order: u32,
    pub created_at: DateTime<Utc>,
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub next_attempt_at: DateTime<Utc>,
    pub state: HookJobState,
}

impl HookJob {
    fn new(
        audit_seq: String,
        op: HookOp,
        subject_did: String,
        resource: String,
        reason: Option<String>,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            audit_seq,
            op,
            subject_did,
            resource,
            reason,
            order: 0,
            created_at,
            attempts: 0,
            last_error: None,
            next_attempt_at: created_at,
            state: HookJobState::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// Audit → jobs mapping
// ---------------------------------------------------------------------------

/// Map one membership audit envelope to hook jobs under `config`.
///
/// - `MemberAdded{role}` → grant, when the role is mapped.
/// - `RoleChanged{previous, new}` → revoke(previous) then grant(new), for
///   whichever sides are mapped, skipping the no-op when both map to the
///   same resource.
/// - `MemberRemoved` → one revoke per **distinct** mapped resource, when
///   `revoke_with_membership` (role history is not tracked, so every mapped
///   resource is revoked — `not_granted` replies classify as idempotent
///   success for the ones the member never held).
pub fn jobs_for_event(config: &GitTrustHooksConfig, envelope: &AuditEnvelope) -> Vec<HookJob> {
    let mut jobs = jobs_for_event_unordered(config, envelope);
    for (i, job) in jobs.iter_mut().enumerate() {
        job.order = i as u32;
    }
    jobs
}

fn jobs_for_event_unordered(
    config: &GitTrustHooksConfig,
    envelope: &AuditEnvelope,
) -> Vec<HookJob> {
    let Some(subject) = envelope.target_did_plain.clone() else {
        return Vec::new();
    };
    let seq = format!("{}:{}", envelope.timestamp.to_rfc3339(), envelope.event_id);
    let at = envelope.timestamp;
    let job = |op, resource: &String, reason: Option<String>| {
        HookJob::new(
            seq.clone(),
            op,
            subject.clone(),
            resource.clone(),
            reason,
            at,
        )
    };

    match &envelope.event {
        AuditEvent::MemberAdded(data) => config
            .grant_on_role
            .get(&data.role)
            .map(|resource| vec![job(HookOp::Grant, resource, None)])
            .unwrap_or_default(),
        AuditEvent::RoleChanged(data) => {
            let previous = config.grant_on_role.get(&data.previous_role);
            let new = config.grant_on_role.get(&data.new_role);
            match (previous, new) {
                (Some(p), Some(n)) if p == n => Vec::new(),
                (previous, new) => {
                    let mut jobs = Vec::new();
                    if let Some(p) = previous {
                        jobs.push(job(
                            HookOp::Revoke,
                            p,
                            Some(format!("role changed to {}", data.new_role)),
                        ));
                    }
                    if let Some(n) = new {
                        jobs.push(job(HookOp::Grant, n, None));
                    }
                    jobs
                }
            }
        }
        AuditEvent::MemberRemoved(_) => {
            if !config.revoke_with_membership {
                return Vec::new();
            }
            let mut resources: Vec<&String> = config.grant_on_role.values().collect();
            resources.sort();
            resources.dedup();
            resources
                .into_iter()
                .map(|r| job(HookOp::Revoke, r, Some("membership ended".to_string())))
                .collect()
        }
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Storage (hooks_queue + hooks_cursor keyspaces)
// ---------------------------------------------------------------------------

const CURSOR_KEY: &[u8] = b"hooks_cursor";

/// Queue key: `<created_at rfc3339>:<order>:<uuid>` — chronological
/// iteration preserves enqueue order, with `order` breaking the tie between
/// jobs born from the same audit event (same timestamp).
fn job_key(job: &HookJob) -> String {
    format!(
        "{}:{:03}:{}",
        job.created_at.to_rfc3339(),
        job.order,
        job.id
    )
}

pub async fn store_job(ks: &KeyspaceHandle, job: &HookJob) -> Result<(), AppError> {
    ks.insert(job_key(job), job).await
}

pub async fn delete_job(ks: &KeyspaceHandle, job: &HookJob) -> Result<(), AppError> {
    ks.remove(job_key(job).into_bytes()).await
}

/// All jobs, in queue-key (chronological) order.
pub async fn list_jobs(ks: &KeyspaceHandle) -> Result<Vec<HookJob>, AppError> {
    let pairs = ks.prefix_iter_raw(Vec::new()).await?;
    let mut out = Vec::with_capacity(pairs.len());
    for (_k, v) in pairs {
        match serde_json::from_slice::<HookJob>(&v) {
            Ok(job) => out.push(job),
            Err(err) => warn!(error = %err, "skipping unparseable hook job row"),
        }
    }
    Ok(out)
}

pub async fn get_cursor(ks: &KeyspaceHandle) -> Result<Option<DateTime<Utc>>, AppError> {
    let Some(bytes) = ks.get_raw(CURSOR_KEY.to_vec()).await? else {
        return Ok(None);
    };
    let s = std::str::from_utf8(&bytes)
        .map_err(|e| AppError::Internal(format!("hooks_cursor not utf-8: {e}")))?;
    Ok(Some(
        DateTime::parse_from_rfc3339(s)
            .map_err(|e| AppError::Internal(format!("hooks_cursor not rfc3339: {e}")))?
            .with_timezone(&Utc),
    ))
}

pub async fn set_cursor(ks: &KeyspaceHandle, ts: DateTime<Utc>) -> Result<(), AppError> {
    ks.insert_raw(CURSOR_KEY.to_vec(), ts.to_rfc3339().into_bytes())
        .await
}

// ---------------------------------------------------------------------------
// The writer seam
// ---------------------------------------------------------------------------

/// Transport failures a capability write can hit before the registry answers.
/// A registry *answer* — including a rejection — is a [`WriteOutcome`], not
/// an error.
#[derive(Debug, Clone, PartialEq)]
pub enum HookWriteError {
    /// The write may succeed if retried (send failed, reply window elapsed).
    Transient(String),
    /// The registry could not be reached at all.
    Unreachable(String),
}

impl std::fmt::Display for HookWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transient(e) => write!(f, "transient: {e}"),
            Self::Unreachable(e) => write!(f, "unreachable: {e}"),
        }
    }
}

/// Performs one capability write for a job and returns the registry's
/// classified answer. The production implementation signs a
/// `git-trust/grant|revoke` document with the VTC authority key and sends it
/// over the DIDComm trust-task envelope, correlating the reply by
/// `threadId`; tests substitute a mock.
#[async_trait]
pub trait CapabilityWriter: Send + Sync {
    async fn write(&self, job: &HookJob) -> Result<WriteOutcome, HookWriteError>;
}

// ---------------------------------------------------------------------------
// The relay
// ---------------------------------------------------------------------------

/// The supervised drainer: tail-walks the audit log into the hooks queue and
/// dispatches due jobs FIFO through the [`CapabilityWriter`].
pub struct HookRelay {
    audit_ks: KeyspaceHandle,
    queue_ks: KeyspaceHandle,
    cursor_ks: KeyspaceHandle,
    config: GitTrustHooksConfig,
    writer: Arc<dyn CapabilityWriter>,
    tick_interval: Duration,
}

impl HookRelay {
    pub fn new(
        audit_ks: KeyspaceHandle,
        queue_ks: KeyspaceHandle,
        cursor_ks: KeyspaceHandle,
        config: GitTrustHooksConfig,
        writer: Arc<dyn CapabilityWriter>,
    ) -> Self {
        Self {
            audit_ks,
            queue_ks,
            cursor_ks,
            config,
            writer,
            tick_interval: Duration::from_secs(DEFAULT_TICK_INTERVAL_SECONDS),
        }
    }

    pub fn with_tick_interval(mut self, interval: Duration) -> Self {
        self.tick_interval = interval;
        self
    }

    /// Run until `shutdown` flips true. Boot recovery flips `InFlight` rows
    /// back to `Pending` (crash between dispatch and outcome), then every
    /// tick tail-walks and dispatches.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        info!(
            tick_interval_secs = self.tick_interval.as_secs(),
            "membership hook relay starting"
        );
        if let Err(e) = self.recover_in_flight().await {
            warn!("hook relay boot recovery failed: {e}");
        }
        let mut tick = tokio::time::interval(self.tick_interval);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if let Err(e) = self.walk_audit_tail().await {
                        warn!("hook tail walk failed: {e}");
                    }
                    if let Err(e) = self.dispatch_due().await {
                        warn!("hook dispatch failed: {e}");
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("membership hook relay stopping");
                        return;
                    }
                }
            }
        }
    }

    async fn recover_in_flight(&self) -> Result<(), AppError> {
        for mut job in list_jobs(&self.queue_ks).await? {
            if job.state == HookJobState::InFlight {
                job.state = HookJobState::Pending;
                store_job(&self.queue_ks, &job).await?;
            }
        }
        Ok(())
    }

    /// Walk audit envelopes newer than the cursor into hook jobs.
    ///
    /// v1 scans the audit keyspace and filters by timestamp (the seek
    /// optimization the registry tail uses, P3.8, is a follow-up); rows are
    /// already deduplicated by the cursor plus the per-row `audit_seq`.
    async fn walk_audit_tail(&self) -> Result<(), AppError> {
        let cursor = get_cursor(&self.cursor_ks).await?;
        let pairs = self.audit_ks.prefix_iter_raw(Vec::new()).await?;
        let mut newest = cursor;
        for (_k, v) in pairs {
            let Ok(envelope) = serde_json::from_slice::<AuditEnvelope>(&v) else {
                continue;
            };
            if cursor.is_some_and(|c| envelope.timestamp <= c) {
                continue;
            }
            for job in jobs_for_event(&self.config, &envelope) {
                debug!(
                    op = ?job.op,
                    subject = %job.subject_did,
                    resource = %job.resource,
                    "hook job enqueued"
                );
                store_job(&self.queue_ks, &job).await?;
            }
            if newest.is_none_or(|n| envelope.timestamp > n) {
                newest = Some(envelope.timestamp);
            }
        }
        if let Some(ts) = newest
            && Some(ts) != cursor
        {
            set_cursor(&self.cursor_ks, ts).await?;
        }
        Ok(())
    }

    /// Dispatch every due `Pending` job, in queue order.
    async fn dispatch_due(&self) -> Result<(), AppError> {
        let now = Utc::now();
        for mut job in list_jobs(&self.queue_ks).await? {
            if job.state != HookJobState::Pending || job.next_attempt_at > now {
                continue;
            }
            job.state = HookJobState::InFlight;
            store_job(&self.queue_ks, &job).await?;

            match self.writer.write(&job).await {
                Ok(WriteOutcome::Success) | Ok(WriteOutcome::IdempotentSuccess) => {
                    delete_job(&self.queue_ks, &job).await?;
                    info!(
                        op = ?job.op,
                        subject = %job.subject_did,
                        resource = %job.resource,
                        "hook write applied"
                    );
                }
                Ok(WriteOutcome::Rejected { code, message }) => {
                    // The registry answered no — retrying the same document
                    // cannot help (R1.4). Loud, terminal.
                    job.state = HookJobState::Failed;
                    job.last_error = Some(format!("rejected: {code}{}", detail_suffix(&message)));
                    store_job(&self.queue_ks, &job).await?;
                    warn!(
                        op = ?job.op,
                        subject = %job.subject_did,
                        resource = %job.resource,
                        code = %code,
                        "hook write rejected by the registry"
                    );
                }
                Err(e) => {
                    job.attempts += 1;
                    job.last_error = Some(e.to_string());
                    let give_up = job.op == HookOp::Grant && job.attempts >= GRANT_MAX_ATTEMPTS;
                    if give_up {
                        job.state = HookJobState::Failed;
                        warn!(
                            subject = %job.subject_did,
                            resource = %job.resource,
                            attempts = job.attempts,
                            "hook grant exhausted its retry budget"
                        );
                    } else {
                        // Revokes retry indefinitely (delivery-critical,
                        // R7.2); grants retry within budget.
                        job.state = HookJobState::Pending;
                        job.next_attempt_at = now + backoff(job.attempts);
                    }
                    store_job(&self.queue_ks, &job).await?;
                }
            }
        }
        Ok(())
    }
}

fn detail_suffix(message: &Option<String>) -> String {
    message
        .as_ref()
        .map(|m| format!(" — {m}"))
        .unwrap_or_default()
}

fn backoff(attempts: u32) -> chrono::Duration {
    let secs = BACKOFF_BASE_SECONDS
        .saturating_mul(2u64.saturating_pow(attempts.min(16)))
        .min(BACKOFF_CAP_SECONDS);
    chrono::Duration::seconds(secs as i64)
}

pub mod reply;
pub mod writer;

pub use reply::PendingReplies;
pub use writer::DidcommCapabilityWriter;

#[cfg(test)]
mod tests;
