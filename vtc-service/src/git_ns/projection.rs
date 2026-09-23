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
//! when it took effect, and its expiry as `activeTo` (the registry has no
//! validity fields). Who granted a right and why stay inside the VTC
//! (`git-ns/right/grant/0.1`, *Correlation*: "`grantedBy` and `reason` stay
//! inside the VTC"), so neither is ever published.
//!
//! # One writer per registry key
//!
//! The v0.1 `[hooks.git-trust] grant_on_role` relay also writes
//! `git.commit.sign` tuples under this community's authority. Where a
//! role-derived resource lies inside a bound namespace, the two would write
//! the same key and each would delete what the other wanted. So such tuples
//! are a second *source* of this projection ([`desired_all`], origin
//! `roleDerived`), the hook relay skips resources inside a bound namespace, and
//! a key is withdrawn only when no source wants it.
//!
//! # Verify
//!
//! The mirror records what this VTC believes it published, and is not backed
//! up. So periodically — and first thing after a start, which is what a
//! restore is — the projector reads back what the registry holds under this
//! authority for the five git actions ([`verify`]), rebuilds the mirror from
//! that for every resource inside a bound namespace, and reconciles: a missing
//! tuple is put again, an unexpected one withdrawn.
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

use super::model::{NamespaceState, RepoState, Resource, Right, RightRow, Scope};
use super::ops::now;
use super::store::Snapshot;
use super::{bridge, lifecycle, wire};

/// What a published record says it asserts (VTI-REG-002): the rights model
/// of the `git-ns` family.
pub const FRAMEWORK: &str = "https://trusttasks.org/spec/git-ns/right/grant/0.1";

/// How often a pass runs with nothing new in the audit log.
const FULL_PASS_SECONDS: i64 = 60;
/// How often the projection is verified against the registry itself.
const VERIFY_SECONDS: i64 = 900;
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

/// The framework a role-derived (v0.1 hook) tuple is made under.
pub const ROLE_DERIVED_FRAMEWORK: &str = "https://trusttasks.org/spec/git-trust/grant/0.1";

/// Which source a tuple comes from, highest first: an explicit git-ns record,
/// a right it implies, a v0.1 role-derived grant.
fn rank(t: &Tuple) -> u8 {
    if t.context.get("origin").and_then(Value::as_str) == Some("roleDerived") {
        0
    } else if t.context.get("impliedBy").is_some() {
        1
    } else {
        2
    }
}

/// Merge a second source of the same tuple. The higher-ranked source's
/// context wins; the later of two expiries wins, and no expiry beats any.
fn merge(into: &mut Tuple, other: Tuple) {
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
    if rank(&other) > rank(into) {
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

/// Everything the registry should hold: the git-ns records ([`desired`])
/// plus the v0.1 role-derived grants whose resource lies inside a bound
/// namespace — which this projection, not the hook relay, then owns.
pub async fn desired_all(
    state: &AppState,
    snap: &Snapshot,
    t: DateTime<Utc>,
) -> Result<BTreeMap<String, Tuple>, AppError> {
    let mut out = desired(snap, t);
    for tuple in role_derived(state, snap).await? {
        let key = tuple.key();
        match out.get_mut(&key) {
            Some(existing) => merge(existing, tuple),
            None => {
                out.insert(key, tuple);
            }
        }
    }
    Ok(out)
}

/// Whether a resource belongs to this projection: inside a bound namespace.
pub fn in_bound_namespace(snap: &Snapshot, resource: &str) -> bool {
    Resource::parse(resource).is_ok_and(|r| {
        snap.namespaces
            .iter()
            .any(|n| n.state == NamespaceState::Bound && n.resource().contains(&r))
    })
}

/// The `grant_on_role` resources a bound namespace contains — the overlap the
/// boot check warns about, and the resources the hook relay leaves alone.
pub fn hook_overlaps(snap: &Snapshot, cfg: &crate::hooks::GitTrustHooksConfig) -> Vec<String> {
    let mut out: Vec<String> = cfg
        .grant_on_role
        .values()
        .filter(|r| in_bound_namespace(snap, r))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The v0.1 role-derived `git.commit.sign` tuples this projection owns: one
/// per current member whose role `grant_on_role` maps to a resource inside a
/// bound namespace.
async fn role_derived(state: &AppState, snap: &Snapshot) -> Result<Vec<Tuple>, AppError> {
    let Some(cfg) = state.config.read().await.hooks.git_trust.clone() else {
        return Ok(Vec::new());
    };
    if hook_overlaps(snap, &cfg).is_empty() {
        return Ok(Vec::new());
    }
    let now_epoch = crate::auth::session::now_epoch();
    let mut out = Vec::new();
    for entry in crate::acl::list_acl_entries(&state.acl_ks).await? {
        if entry.is_expired(now_epoch) {
            continue;
        }
        let Some(resource) = cfg.grant_on_role.get(&entry.role.to_string()) else {
            continue;
        };
        if !in_bound_namespace(snap, resource) {
            continue;
        }
        let member = crate::members::get_member(&state.members_ks, &entry.did).await?;
        if !member.is_some_and(|m| m.removed_at.is_none()) {
            continue;
        }
        out.push(Tuple {
            entity: entry.did.clone(),
            action: Right::CommitSign.as_str().to_string(),
            resource: resource.clone(),
            context: json!({ "framework": ROLE_DERIVED_FRAMEWORK, "origin": "roleDerived" }),
            repo_id: snap.repo_at(resource).map(|r| r.id.clone()),
        });
    }
    Ok(out)
}

/// Whether a tuple published at `resource` for some other repository (or
/// none) is still waiting to be withdrawn — published, and wanted by no
/// source. `except` is a repository whose own tuples do not count.
pub async fn withdrawal_pending(
    state: &AppState,
    snap: &Snapshot,
    resource: &str,
    except: Option<&str>,
) -> Result<bool, AppError> {
    let want = desired_all(state, snap, now()).await?;
    Ok(published(state).await?.iter().any(|(key, p)| {
        p.tuple.resource == resource
            && !want.contains_key(key)
            && (except.is_none() || p.tuple.repo_id.as_deref() != except)
    }))
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
    let want = desired_all(state, &snap, t).await?;
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

// ── verify ──────────────────────────────────────────────────────────────────

/// Rebuild the mirror from what the registry actually holds, then reconcile.
///
/// For every resource inside a bound namespace, the registry's answer
/// replaces the mirror's belief: a tuple the registry lacks is dropped from
/// the mirror (so the reconcile puts it again), and one the registry holds
/// that the mirror did not know is added (so the reconcile withdraws it if no
/// source wants it). Resources outside every bound namespace are left alone —
/// they are the hook relay's, or nobody's this VTC still governs.
///
/// Returns `Ok(None)` when the registry transport cannot enumerate records;
/// the projection then keeps running on the mirror alone.
pub async fn verify(
    state: &AppState,
    client: &dyn TrustRegistryClient,
    authority: &str,
    backoff: &mut Backoff,
) -> Result<Option<PassReport>, AppError> {
    let mut listed = Vec::new();
    for right in Right::ALL {
        match client.list_trust_records(right.as_str()).await {
            Ok(records) => listed.extend(records),
            Err(e) if e.is_retriable() => {
                debug!(error = %e, "git-ns verify could not read the registry; will retry");
                return Ok(None);
            }
            Err(e) => {
                debug!(error = %e, "git-ns verify: the registry cannot enumerate records");
                return Ok(None);
            }
        }
    }
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let have = published(state).await?;
    let t = now();
    let mut seen = std::collections::BTreeSet::new();
    for r in &listed {
        let field = |k: &str| {
            r.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        if r.get("authority_id").and_then(Value::as_str) != Some(authority) {
            continue;
        }
        // A record the registry keeps but marks unauthorized (a v0.1
        // git-trust revoke retains its record) is not a published right.
        if r.get("authorized").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        let (entity, action, resource) = (field("entity_id"), field("action"), field("resource"));
        if !in_bound_namespace(&snap, &resource) {
            continue;
        }
        let key = tuple_key(&entity, &action, &resource);
        seen.insert(key.clone());
        let repo_id = have
            .get(&key)
            .and_then(|p| p.tuple.repo_id.clone())
            .or_else(|| snap.repo_at(&resource).map(|r| r.id.clone()));
        mirror_put(
            state,
            &Published {
                tuple: Tuple {
                    entity,
                    action,
                    resource,
                    context: r.get("context").cloned().unwrap_or(Value::Null),
                    repo_id,
                },
                published_at: have.get(&key).map_or(t, |p| p.published_at),
            },
        )
        .await?;
    }
    for (key, p) in &have {
        if in_bound_namespace(&snap, &p.tuple.resource) && !seen.contains(key) {
            // The registry does not hold it: forget it, so it is put again.
            mirror_remove(state, key).await?;
        }
    }
    reconcile(state, client, authority, backoff).await.map(Some)
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
    last_verify: Option<DateTime<Utc>>,
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
            last_verify: None,
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
        let verify_due = self
            .last_verify
            .is_none_or(|l| l + chrono::Duration::seconds(VERIFY_SECONDS) <= t);
        if let Some((client, authority)) = &self.registry
            && verify_due
        {
            self.last_verify = Some(t);
            match verify(&self.state, client.as_ref(), authority, &mut self.backoff).await {
                Ok(Some(r)) => {
                    if r != PassReport::default() {
                        info!(
                            put = r.put,
                            deleted = r.deleted,
                            failed = r.failed,
                            "git-ns registry verify pass corrected the projection"
                        );
                    }
                    // A verify ends in a full reconcile.
                    self.last_full = Some(t);
                    return;
                }
                // The registry cannot enumerate: reconcile on the mirror alone.
                Ok(None) => {}
                Err(e) => warn!(error = %e, "git-ns registry verify failed"),
            }
        }
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
