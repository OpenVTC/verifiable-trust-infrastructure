//! The registry projection, and the projector task that runs it.
//!
//! # What is published
//!
//! Every live right is published as a TRQP authorization record under this
//! community's authority — `{subject, authority = VTC DID, action = the right
//! string, resource}` — written with `registry/record/put`, never with
//! `git-trust/grant`, whose action is fixed to `git.commit.sign`. Because
//! verifiers ask only about `git.commit.sign`, the implied commit right is
//! published explicitly (`git-ns/right/grant/0.1`, *Implied rights*):
//!
//! - for every `git.repo.own` and `git.repo.maintain`, on the same repository;
//! - for every `git.ns.admin`, on the namespace resource
//!   (trustoverip/dtgwg-trust-tasks-tf#623), which a repository's check counts
//!   through its namespace fallback.
//!
//! Nothing else implied is published: an implied right is evaluated by the
//! VTC and is never a record. The record's `context` carries what the TRQP
//! record has no member for — the framework it is made under (VTI-REG-002),
//! who granted it, when it took effect, and its expiry as `activeTo` (the
//! registry has no validity fields). A grant's `reason` is never published.
//!
//! A right is published only once its namespace is bound and its repository
//! is active (or orphaned, or archived — archiving withdraws the commit rights
//! by removing them, and keeps the governance record).
//!
//! # How it converges
//!
//! The desired set is a pure function of the records ([`desired`]). The
//! projection mirror ([`crate::store::keyspaces::GIT_NS_PROJECTION`]) records
//! what has been published. Each pass deletes what is published and no longer
//! desired, then puts what is desired and not yet published — so the
//! projection is idempotent, survives a crash between any two writes, and is
//! rebuilt from nothing by clearing the mirror.
//!
//! Deletes run first, and a repository whose old tuples could not be deleted
//! gets no new ones that pass: after a rename, the tuples published for the
//! old name are withdrawn *before* any are published for the new one, so a
//! repository later created at the old name can never be mistaken for the
//! renamed one (`git-ns/bridge/event`, `repoRenamed`). A delete that fails is
//! retried on every pass, forever.
//!
//! # Driven by the audit log
//!
//! The projector tails the audit log, as the membership syncer does; a
//! `GitNsOperation` or a membership change wakes a reconciliation at once. A
//! pass also runs at least once a minute, which is what heals a lost audit row
//! and publishes the lapse of an expiring grant.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::watch;
use tracing::{debug, info, warn};
use vti_common::audit::{AuditEnvelope, AuditEvent};
use vti_common::error::AppError;

use crate::registry::{RegistryError, TrustRegistryClient};
use crate::server::AppState;

use super::model::{NamespaceState, RepoState, Right, RightRow, Scope};
use super::ops::now;
use super::store::Snapshot;
use super::{bridge, lifecycle, wire};

/// What a published record says it asserts (VTI-REG-002): the rights model
/// of the `git-ns` family.
pub const FRAMEWORK: &str = "https://trusttasks.org/spec/git-ns/right/grant/0.1";

/// How often a pass runs with nothing new in the audit log.
const FULL_PASS_SECONDS: i64 = 60;
const BACKOFF_CAP_SECONDS: i64 = 3600;

/// One record the registry should hold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tuple {
    pub entity: String,
    pub action: String,
    pub resource: String,
    pub context: Value,
    /// The repository the tuple is for, so a rename can hold back the new
    /// name's tuples until the old name's are gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_id: Option<String>,
}

impl Tuple {
    pub fn key(&self) -> String {
        tuple_key(&self.entity, &self.action, &self.resource)
    }

    /// The TRQP `TrustRecord` for `registry/record/put`.
    pub fn record(&self, authority: &str) -> Value {
        json!({
            "entity_id": self.entity,
            "authority_id": authority,
            "action": self.action,
            "resource": self.resource,
            "record_type": "authorization",
            "authorized": true,
            "context": self.context,
        })
    }
}

pub fn tuple_key(entity: &str, action: &str, resource: &str) -> String {
    format!("{entity}|{action}|{resource}")
}

fn context(row: &RightRow, implied_by: Option<Right>) -> Value {
    let mut c = json!({
        "framework": FRAMEWORK,
        "grantedBy": row.granted_by,
        "activeFrom": wire::timestamp(row.granted_at),
    });
    if let Some(e) = row.expires_at {
        c["activeTo"] = json!(wire::timestamp(e));
    }
    if let Some(r) = implied_by {
        c["impliedBy"] = json!(r.as_str());
    }
    c
}

/// Merge a second source of the same tuple. An explicit record wins over an
/// implied one; the later of two expiries wins, and no expiry beats any.
fn merge(into: &mut Tuple, other: Tuple) {
    let explicit = |t: &Tuple| t.context.get("impliedBy").is_none();
    let active_to = |t: &Tuple| {
        t.context
            .get("activeTo")
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let merged_to = match (active_to(into), active_to(&other)) {
        (None, _) | (_, None) => None,
        (Some(a), Some(b)) => Some(a.max(b)),
    };
    if !explicit(into) && explicit(&other) {
        *into = other;
    }
    match merged_to {
        Some(t) => into.context["activeTo"] = json!(t),
        None => {
            if let Some(o) = into.context.as_object_mut() {
                o.remove("activeTo");
            }
        }
    }
}

/// Everything the registry should hold, from the records at `t`.
pub fn desired(snap: &Snapshot, t: DateTime<Utc>) -> BTreeMap<String, Tuple> {
    let mut out: BTreeMap<String, Tuple> = BTreeMap::new();
    let mut add = |tuple: Tuple| {
        let key = tuple.key();
        match out.get_mut(&key) {
            Some(existing) => merge(existing, tuple),
            None => {
                out.insert(key, tuple);
            }
        }
    };
    for (scope, set) in &snap.rights {
        let Some(ns) = snap.scope_namespace(scope) else {
            continue;
        };
        if ns.state != NamespaceState::Bound {
            continue;
        }
        let Some(resource) = snap.scope_resource(scope) else {
            continue;
        };
        let repo_id = match scope {
            Scope::Namespace(_) => None,
            Scope::Repo(id) => {
                let Some(repo) = snap.repo(id) else { continue };
                if !repo.state.publishes() {
                    continue;
                }
                Some(id.clone())
            }
        };
        let archived = repo_id
            .as_ref()
            .and_then(|id| snap.repo(id))
            .is_some_and(|r| r.state == RepoState::Archived);
        for row in set.rows.iter().filter(|r| r.is_live(t)) {
            let res = resource.to_string();
            let tuple = |action: Right, implied_by: Option<Right>| Tuple {
                entity: row.subject.clone(),
                action: action.as_str().to_string(),
                resource: res.clone(),
                context: context(row, implied_by),
                repo_id: repo_id.clone(),
            };
            // An archived repository's commit rights are withdrawn — records
            // and implications alike.
            if !(archived && row.right == Right::CommitSign) {
                add(tuple(row.right, None));
            }
            let implies_commit = matches!(
                row.right,
                Right::RepoOwn | Right::RepoMaintain | Right::NsAdmin
            );
            if implies_commit && !archived {
                add(tuple(Right::CommitSign, Some(row.right)));
            }
        }
    }
    out
}

// ── the mirror ──────────────────────────────────────────────────────────────

const MIRROR_PREFIX: &str = "t:";
const CURSOR_KEY: &str = "cursor";

/// One published record, as the mirror remembers it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Published {
    #[serde(flatten)]
    pub tuple: Tuple,
    pub published_at: DateTime<Utc>,
}

pub async fn published(state: &AppState) -> Result<BTreeMap<String, Published>, AppError> {
    let rows = state
        .git_ns
        .projection_ks
        .prefix_iter_raw(MIRROR_PREFIX.as_bytes().to_vec())
        .await?;
    let mut out = BTreeMap::new();
    for (_, v) in rows {
        if let Ok(p) = serde_json::from_slice::<Published>(&v) {
            out.insert(p.tuple.key(), p);
        }
    }
    Ok(out)
}

async fn mirror_put(state: &AppState, p: &Published) -> Result<(), AppError> {
    state
        .git_ns
        .projection_ks
        .insert(format!("{MIRROR_PREFIX}{}", p.tuple.key()), p)
        .await
}

async fn mirror_remove(state: &AppState, key: &str) -> Result<(), AppError> {
    state
        .git_ns
        .projection_ks
        .remove(format!("{MIRROR_PREFIX}{key}"))
        .await
}

/// What one reconciliation pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PassReport {
    pub put: usize,
    pub deleted: usize,
    pub failed: usize,
    pub held_back: usize,
}

/// Per-tuple retry schedule, in memory: a restart retries everything at once,
/// which is the right thing after a restart.
#[derive(Default)]
pub struct Backoff {
    next: HashMap<String, (u32, DateTime<Utc>)>,
}

impl Backoff {
    fn due(&self, key: &str, t: DateTime<Utc>) -> bool {
        self.next.get(key).is_none_or(|(_, at)| *at <= t)
    }

    fn failed(&mut self, key: &str, t: DateTime<Utc>) {
        let n = self.next.get(key).map_or(0, |(n, _)| *n) + 1;
        let secs = (5i64.saturating_mul(2i64.saturating_pow(n.min(16)))).min(BACKOFF_CAP_SECONDS);
        self.next
            .insert(key.to_string(), (n, t + chrono::Duration::seconds(secs)));
    }

    fn succeeded(&mut self, key: &str) {
        self.next.remove(key);
    }
}

/// One pass: delete what should not be published, then publish what should.
pub async fn reconcile(
    state: &AppState,
    client: &dyn TrustRegistryClient,
    authority: &str,
    backoff: &mut Backoff,
) -> Result<PassReport, AppError> {
    let t = now();
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let want = desired(&snap, t);
    let have = published(state).await?;
    let mut report = PassReport::default();

    // Deletes first. A repository with a delete outstanding is held back.
    let mut held: std::collections::BTreeSet<String> = Default::default();
    for (key, p) in &have {
        if want.contains_key(key) {
            continue;
        }
        if !backoff.due(key, t) {
            if let Some(id) = &p.tuple.repo_id {
                held.insert(id.clone());
            }
            report.failed += 1;
            continue;
        }
        match client
            .delete_trust_record(&p.tuple.entity, &p.tuple.action, &p.tuple.resource)
            .await
        {
            Ok(()) => {
                mirror_remove(state, key).await?;
                backoff.succeeded(key);
                report.deleted += 1;
                debug!(%key, "git-ns tuple withdrawn");
            }
            Err(e) => {
                log_failure("withdraw", key, &e);
                backoff.failed(key, t);
                if let Some(id) = &p.tuple.repo_id {
                    held.insert(id.clone());
                }
                report.failed += 1;
            }
        }
    }

    for (key, tuple) in &want {
        let current = have.get(key).map(|p| &p.tuple);
        if current == Some(tuple) {
            continue;
        }
        if let Some(id) = &tuple.repo_id
            && held.contains(id)
        {
            report.held_back += 1;
            continue;
        }
        if !backoff.due(key, t) {
            report.failed += 1;
            continue;
        }
        match client.put_trust_record(&tuple.record(authority)).await {
            Ok(()) => {
                mirror_put(
                    state,
                    &Published {
                        tuple: tuple.clone(),
                        published_at: t,
                    },
                )
                .await?;
                backoff.succeeded(key);
                report.put += 1;
                debug!(%key, "git-ns tuple published");
            }
            Err(e) => {
                log_failure("publish", key, &e);
                backoff.failed(key, t);
                report.failed += 1;
            }
        }
    }
    Ok(report)
}

fn log_failure(what: &str, key: &str, e: &RegistryError) {
    if e.is_retriable() {
        debug!(%key, error = %e, "git-ns projection could not {what} a tuple; will retry");
    } else {
        warn!(%key, error = %e, "git-ns projection could not {what} a tuple; will retry");
    }
}

// ── the audit tail ──────────────────────────────────────────────────────────

/// Whether the audit log has anything new that changes what is projected,
/// advancing the cursor past what it read.
pub async fn tail(state: &AppState) -> Result<bool, AppError> {
    let ks = &state.git_ns.projection_ks;
    let cursor: Option<DateTime<Utc>> = ks
        .get_raw(CURSOR_KEY.as_bytes().to_vec())
        .await?
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|d| d.with_timezone(&Utc));
    let rows = match cursor {
        Some(c) => {
            state
                .audit_ks
                .range_from_raw(format!("{}:", c.to_rfc3339()).into_bytes())
                .await?
        }
        None => state.audit_ks.prefix_iter_raw(Vec::new()).await?,
    };
    let mut newest = cursor;
    let mut relevant = false;
    for (_, v) in rows {
        let Ok(env) = serde_json::from_slice::<AuditEnvelope>(&v) else {
            continue;
        };
        if cursor.is_some_and(|c| env.timestamp <= c) {
            continue;
        }
        if matches!(
            env.event,
            AuditEvent::GitNsOperation(_)
                | AuditEvent::MemberRemoved(_)
                | AuditEvent::MemberAdded(_)
                | AuditEvent::RoleChanged(_)
        ) {
            relevant = true;
        }
        if newest.is_none_or(|n| env.timestamp > n) {
            newest = Some(env.timestamp);
        }
    }
    if let Some(n) = newest
        && Some(n) != cursor
    {
        ks.insert_raw(CURSOR_KEY.as_bytes().to_vec(), n.to_rfc3339().into_bytes())
            .await?;
    }
    Ok(relevant)
}

// ── the projector task ──────────────────────────────────────────────────────

/// The supervised loop: lifecycle sweeps, forge role projection, bridge job
/// dispatch, and registry reconciliation.
pub struct Projector {
    state: AppState,
    registry: Option<(Arc<dyn TrustRegistryClient>, String)>,
    tick: Duration,
    backoff: Backoff,
    last_full: Option<DateTime<Utc>>,
}

impl Projector {
    /// `registry` is the client and this community's DID, when both exist;
    /// without them the registry half is skipped and everything else runs.
    pub fn new(
        state: AppState,
        registry: Option<(Arc<dyn TrustRegistryClient>, String)>,
        tick: Duration,
    ) -> Self {
        Self {
            state,
            registry,
            tick,
            backoff: Backoff::default(),
            last_full: None,
        }
    }

    /// One pass of everything. Errors are logged, not returned: one failing
    /// half must not stop the others.
    pub async fn run_once(&mut self) {
        let woke = match tail(&self.state).await {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "git-ns audit tail failed");
                true
            }
        };
        let changed = match lifecycle::sweep(&self.state).await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "git-ns lifecycle sweep failed");
                false
            }
        };
        if let Err(e) = bridge::project_roles(&self.state, false).await {
            warn!(error = %e, "git-ns role projection failed");
        }
        if let Err(e) = bridge::dispatch_due(&self.state).await {
            warn!(error = %e, "git-ns bridge dispatch failed");
        }
        let t = now();
        let due = self
            .last_full
            .is_none_or(|l| l + chrono::Duration::seconds(FULL_PASS_SECONDS) <= t);
        if let Some((client, authority)) = &self.registry
            && (woke || changed || due)
        {
            match reconcile(&self.state, client.as_ref(), authority, &mut self.backoff).await {
                Ok(r) if r != PassReport::default() => {
                    info!(
                        put = r.put,
                        deleted = r.deleted,
                        failed = r.failed,
                        held_back = r.held_back,
                        "git-ns registry projection pass"
                    );
                }
                Ok(_) => {}
                Err(e) => warn!(error = %e, "git-ns registry reconciliation failed"),
            }
            self.last_full = Some(t);
        }
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        info!(
            tick_secs = self.tick.as_secs(),
            registry = self.registry.is_some(),
            "git-ns projector starting"
        );
        let mut tick = tokio::time::interval(self.tick);
        loop {
            tokio::select! {
                _ = tick.tick() => self.run_once().await,
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("git-ns projector stopping");
                        return;
                    }
                }
            }
        }
    }
}
