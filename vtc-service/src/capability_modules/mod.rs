//! Capability modules — the pluggable governance capabilities a community
//! turns on or off (`governance/capability/{list,enable,disable}/0.1`).
//!
//! Design: `design-docs/vtc-capability-modules.md`. A capability module is a
//! named bundle of Trust Task families and trust-registry vocabulary —
//! `git-trust` is the first — described by a `CapabilityManifest`
//! (`governance/_shared/0.1`). **Not** the ACL capabilities on an
//! administrator's entry (`crate::acl::Capability`, `vtc.config.admin` and the
//! rest): those say what an administrator may do; a capability module says
//! what the community does. The two never share a type, a store or an audit
//! event.
//!
//! # The VTC is the source of truth; the registry is a projection
//!
//! Which modules a community has enabled — with their version, config, when
//! and by whom — lives here, in one row of the `community` keyspace
//! ([`STATE_STORAGE_KEY`]), backed up with the rest of the community's state.
//! The community's Trust Registry holds a *projection* of that decision: its
//! own `governance/capability/enable|disable` are admin-only and merely switch
//! which record families (`git-trust/grant|revoke`) it accepts. So an accepted
//! enable or disable is persisted here **first**, with its projection marked
//! pending, and the [`Projector`] then tells the registry — as its
//! administrator, over the registry client's transport selection (TSP >
//! DIDComm; the registry has no REST governance surface) — until the registry
//! answers that it holds the same state.
//!
//! Persist-then-project is the order R2.1 asks for once the flow is
//! resumable: a crash after the write leaves a pending projection the next
//! projector pass re-drives, and the registry's answers are convergent
//! (`alreadyEnabled` to an enable, `notEnabled` to a disable, are the state
//! wanted), so re-sending is never a second effect. Each decision carries a
//! `generation`; a projection result is recorded only against the generation
//! it was sent for, so an enable and a quick disable cannot have the first's
//! late answer mark the second applied.
//!
//! # A failed projection is visible, and re-converges
//!
//! A transient failure (registry unreachable, no reply inside the client's
//! finite window) retries with capped, jittered exponential backoff (R1.2,
//! R1.4). A permanent one (the registry refuses — this VTC is not among its
//! `admin_dids`, the registry is too old to route the task) marks the
//! projection `failed`, writes a `CapabilityModuleChanged{projectionFailed}`
//! audit row on the transition, logs at `warn`, and is still retried at the
//! backoff cap: a refusal an operator fixes on the registry side converges
//! without anyone re-sending the enable. The projection's status rides on
//! every enable / disable answer and on an administrator's `list`.
//!
//! # What this does not do (yet)
//!
//! The module's enablement here does not yet gate the VTC's own git-trust
//! machinery (the `[hooks.git-trust]` relay, the git-namespace projection):
//! those keep their existing configuration switches. And a module this VTC
//! holds no decision for is never projected — in particular never *disabled*
//! at a registry an operator enabled by hand before this existed.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::sync::{Mutex, Notify, watch};
use tracing::{info, warn};
use vti_common::audit::{AuditEvent, CapabilityModuleChangedData};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::registry::{CapabilityModuleChange, RegistryError};
use crate::server::AppState;

/// The one row holding every module decision, in the `community` keyspace
/// beside the profile and branding rows.
pub const STATE_STORAGE_KEY: &[u8] = b"capability-modules/state";

/// The enablement-config member naming the authority a module's registry
/// records are written under. The registry refuses to enable a
/// record-writing module without one.
pub const CONFIG_AUTHORITY: &str = "authority";

/// The `git-trust` module's slug.
pub const GIT_TRUST: &str = "git-trust";

/// Projector tick when nothing wakes it.
pub const DEFAULT_TICK_SECONDS: u64 = 5;
/// Backoff: `5s * 2^attempts`, capped at one hour (hook relay parity).
const BACKOFF_BASE_SECONDS: u64 = 5;
const BACKOFF_CAP_SECONDS: u64 = 3600;

/// Serialises every read-modify-write of [`STATE_STORAGE_KEY`]. Held across
/// local store operations only — never across the registry round trip
/// (R1.3).
static STATE_LOCK: Mutex<()> = Mutex::const_new(());

/// Wakes the projector as soon as a decision is written, so a projection does
/// not wait out a tick.
static WAKE: Notify = Notify::const_new();

// ---------------------------------------------------------------------------
// What this VTC knows how to project
// ---------------------------------------------------------------------------

/// A capability module this VTC can enable: its manifest and what its
/// enablement config must carry.
#[derive(Debug, Clone)]
pub struct ModuleDefinition {
    /// The module's `CapabilityManifest`, as the list response carries it.
    pub manifest: Value,
    /// Whether the module writes registry records, and so must be enabled
    /// with the `authority` they are written under.
    pub requires_authority: bool,
}

impl ModuleDefinition {
    /// The module's slug (`manifest.capability`).
    pub fn slug(&self) -> &str {
        self.manifest["capability"].as_str().unwrap_or_default()
    }

    /// The module version this build serves (`manifest.version`).
    pub fn version(&self) -> &str {
        self.manifest["version"].as_str().unwrap_or_default()
    }
}

/// The `git-trust` manifest.
///
/// Member-for-member the manifest `affinidi-trust-registry-rs` serves for the
/// same module (`trust-registry/src/capabilities/git_trust.rs`), because a
/// management surface that lists a community's capabilities must describe the
/// module the registry will actually run. No shared crate publishes it yet —
/// `vtc-capability-modules.md` §7 leans toward the trust-tasks registry — so
/// the copy is pinned by `the_git_trust_manifest_is_the_registrys`, and parsed
/// into the generated `CapabilityManifest` type on every read.
fn git_trust_manifest() -> Value {
    json!({
        "capability": GIT_TRUST,
        "version": "0.1",
        "title": "Git Commit Trust",
        "description": "Grant and revoke members' commit-signing authority; CI verifies each PR commit's signer DID against this community's registry.",
        "specs": ["git-trust/*"],
        "vocabulary": {
            "actions": ["git.commit.sign"],
            "resourcePattern": "<org>[/<repo>]"
        },
        "roles": { "grant": ["operator"], "view": ["member"] },
        "externalAdapters": [
            { "kind": "github-action", "ref": "OpenVTC/openvtc/.github/actions/verify-trust" }
        ]
    })
}

/// Every module this VTC can enable and project, in slug order.
pub fn available() -> Vec<ModuleDefinition> {
    vec![ModuleDefinition {
        manifest: git_trust_manifest(),
        requires_authority: true,
    }]
}

/// The module named `slug` at `version`, if this VTC serves it.
pub fn definition(slug: &str, version: &str) -> Option<ModuleDefinition> {
    available()
        .into_iter()
        .find(|d| d.slug() == slug && d.version() == version)
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Where a decision stands at the trust registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProjectionStatus {
    /// Not yet acknowledged by the registry (or no registry is configured).
    Pending,
    /// The registry answered that it holds this decision.
    Applied,
    /// The registry refused it; retried at the backoff cap until it accepts.
    Failed,
}

impl ProjectionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Failed => "failed",
        }
    }
}

/// The registry projection of one module's current decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Projection {
    pub status: ProjectionStatus,
    /// Attempts since the decision was made.
    #[serde(default)]
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub next_attempt_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_at: Option<DateTime<Utc>>,
}

/// One module's decision, as this community holds it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModuleState {
    pub version: String,
    pub enabled: bool,
    /// The enablement config (`authority`, for a record-writing module).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
    /// When the module was (last) enabled; kept across a disable, for audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_at: Option<DateTime<Utc>>,
    /// The administrator who (last) enabled it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_by: Option<String>,
    /// When the module was (last) disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_by: Option<String>,
    /// The operator's reason on the last disable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_reason: Option<String>,
    /// Bumped on every enable and disable; a projection result is recorded
    /// only against the generation it was sent for.
    pub generation: u64,
    pub projection: Projection,
}

/// Every module decision this community holds, by slug.
pub async fn load(ks: &KeyspaceHandle) -> Result<BTreeMap<String, ModuleState>, AppError> {
    match ks.get_raw(STATE_STORAGE_KEY.to_vec()).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("capability-module state decode: {e}"))),
        None => Ok(BTreeMap::new()),
    }
}

async fn save(ks: &KeyspaceHandle, all: &BTreeMap<String, ModuleState>) -> Result<(), AppError> {
    let key = String::from_utf8(STATE_STORAGE_KEY.to_vec()).expect("the storage key is ASCII");
    ks.insert(key, all).await
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

/// Why an enable or disable cannot be made. Each maps onto the code the
/// task's specification declares for it.
#[derive(Debug)]
pub enum ModuleError {
    /// `governance/capability/enable:unknownCapability`.
    UnknownCapability(String),
    /// `governance/capability/enable:alreadyEnabled`.
    AlreadyEnabled,
    /// `governance/capability/disable:notEnabled`.
    NotEnabled,
    /// `governance/capability/enable:configInvalid`.
    ConfigInvalid(String),
    Storage(AppError),
}

impl From<AppError> for ModuleError {
    fn from(e: AppError) -> Self {
        Self::Storage(e)
    }
}

/// A checked enable, ready to commit.
#[derive(Debug, Clone)]
pub struct EnablePlan {
    pub capability: String,
    pub version: String,
    pub config: Value,
}

/// Check an enable against what this VTC serves and the community as it is
/// now, without writing anything — so an administrator is not asked for a
/// step-up gesture for an enable that would be refused.
///
/// `config.authority` defaults to this community's DID: the community is the
/// authority its module's registry records are written under, and the
/// registry refuses a record-writing module without one. Any other authority
/// is refused — this VTC writes those records signed as itself, so a module
/// enabled under someone else's authority could never write one. Any other
/// config member is refused too: the git-trust role mapping lives in
/// `[hooks.git-trust]`, and accepting a `grantOnRole` here that nothing reads
/// would be a silently dropped setting (R3.2).
pub async fn plan_enable(
    ks: &KeyspaceHandle,
    vtc_did: &str,
    capability: &str,
    version: &str,
    config: &Map<String, Value>,
    has_delegate: bool,
) -> Result<EnablePlan, ModuleError> {
    let Some(def) = definition(capability, version) else {
        let served: Vec<String> = available()
            .iter()
            .map(|d| format!("{}@{}", d.slug(), d.version()))
            .collect();
        return Err(ModuleError::UnknownCapability(format!(
            "this community does not serve the capability module {capability}@{version} \
             (it serves {}); companion modules served by another DID are not supported yet",
            served.join(", ")
        )));
    };
    if has_delegate {
        return Err(ModuleError::ConfigInvalid(format!(
            "{capability} is built into this community; it takes no `delegate`"
        )));
    }
    let mut resolved = config.clone();
    if let Some(unknown) = resolved.keys().find(|k| *k != CONFIG_AUTHORITY) {
        return Err(ModuleError::ConfigInvalid(format!(
            "`{unknown}` is not a {capability} enablement setting; the only one is \
             `{CONFIG_AUTHORITY}` (role-derived grants are configured in `[hooks.git-trust]`)"
        )));
    }
    if def.requires_authority {
        match resolved.get(CONFIG_AUTHORITY) {
            None => {
                resolved.insert(CONFIG_AUTHORITY.to_string(), json!(vtc_did));
            }
            Some(Value::String(did)) if did == vtc_did => {}
            Some(other) => {
                return Err(ModuleError::ConfigInvalid(format!(
                    "`{CONFIG_AUTHORITY}` must be this community's DID ({vtc_did}): its {capability} \
                     records are written signed by this community; got {other}"
                )));
            }
        }
    }
    if load(ks).await?.get(capability).is_some_and(|m| m.enabled) {
        return Err(ModuleError::AlreadyEnabled);
    }
    Ok(EnablePlan {
        capability: capability.to_string(),
        version: version.to_string(),
        config: Value::Object(resolved),
    })
}

/// Check a disable: the module must be enabled now.
pub async fn plan_disable(ks: &KeyspaceHandle, capability: &str) -> Result<(), ModuleError> {
    if load(ks).await?.get(capability).is_some_and(|m| m.enabled) {
        Ok(())
    } else {
        Err(ModuleError::NotEnabled)
    }
}

fn pending_projection(state: &AppState, now: DateTime<Utc>) -> Projection {
    Projection {
        status: ProjectionStatus::Pending,
        attempts: 0,
        last_error: state.registry_client.is_none().then(|| {
            "no trust registry is configured ([registry] did); the decision is held here and \
             projected once one is"
                .to_string()
        }),
        next_attempt_at: now,
        applied_at: None,
    }
}

/// Commit a planned enable — re-checked under the state lock, so two racing
/// enables cannot both land — with its projection pending, then wake the
/// projector.
pub async fn commit_enable(
    state: &AppState,
    actor_did: &str,
    plan: EnablePlan,
) -> Result<ModuleState, ModuleError> {
    let now = Utc::now();
    let entry = {
        let _guard = STATE_LOCK.lock().await;
        let mut all = load(&state.community_ks).await?;
        let prior = all.get(&plan.capability);
        if prior.is_some_and(|m| m.enabled) {
            return Err(ModuleError::AlreadyEnabled);
        }
        let entry = ModuleState {
            version: plan.version,
            enabled: true,
            config: Some(plan.config),
            enabled_at: Some(now),
            enabled_by: Some(actor_did.to_string()),
            disabled_at: prior.and_then(|p| p.disabled_at),
            disabled_by: prior.and_then(|p| p.disabled_by.clone()),
            disable_reason: prior.and_then(|p| p.disable_reason.clone()),
            generation: prior.map_or(1, |p| p.generation + 1),
            projection: pending_projection(state, now),
        };
        all.insert(plan.capability.clone(), entry.clone());
        save(&state.community_ks, &all).await?;
        entry
    };
    WAKE.notify_one();
    Ok(entry)
}

/// Commit a disable. Disable is not delete: the decision row stays, with when
/// and by whom it was enabled, and the registry keeps the module's records.
pub async fn commit_disable(
    state: &AppState,
    actor_did: &str,
    capability: &str,
    reason: Option<String>,
) -> Result<ModuleState, ModuleError> {
    let now = Utc::now();
    let entry = {
        let _guard = STATE_LOCK.lock().await;
        let mut all = load(&state.community_ks).await?;
        let Some(entry) = all.get_mut(capability).filter(|m| m.enabled) else {
            return Err(ModuleError::NotEnabled);
        };
        entry.enabled = false;
        entry.disabled_at = Some(now);
        entry.disabled_by = Some(actor_did.to_string());
        entry.disable_reason = reason;
        entry.generation += 1;
        entry.projection = pending_projection(state, now);
        let entry = entry.clone();
        save(&state.community_ks, &all).await?;
        entry
    };
    WAKE.notify_one();
    Ok(entry)
}

/// The authority a module's config names, for audit rows.
pub fn authority_of(entry: &ModuleState) -> Option<String> {
    entry
        .config
        .as_ref()
        .and_then(|c| c.get(CONFIG_AUTHORITY))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Write a `CapabilityModuleChanged` audit row. A failure is logged, not
/// returned: the decision it records has already been committed.
pub async fn audit(
    state: &AppState,
    actor_did: &str,
    capability: &str,
    entry: &ModuleState,
    event: &str,
    error: Option<String>,
) {
    let Some(writer) = state.audit_writer.as_ref() else {
        return;
    };
    let data = CapabilityModuleChangedData {
        capability: capability.to_string(),
        version: entry.version.clone(),
        event: event.to_string(),
        authority: authority_of(entry),
        reason: (event == "disabled")
            .then(|| entry.disable_reason.clone())
            .flatten(),
        error,
    };
    if let Err(e) = writer
        .write(actor_did, None, AuditEvent::CapabilityModuleChanged(data))
        .await
    {
        warn!(error = %e, capability, event, "could not audit a capability-module change");
    }
}

// ---------------------------------------------------------------------------
// The projector
// ---------------------------------------------------------------------------

fn backoff(attempts: u32) -> chrono::Duration {
    let secs = BACKOFF_BASE_SECONDS
        .saturating_mul(2u64.saturating_pow(attempts.min(16)))
        .min(BACKOFF_CAP_SECONDS);
    // Up to a fifth again of jitter, so a fleet of communities pointed at one
    // registry that went down together does not come back in lockstep (R1.4).
    let jitter = rand::random::<u64>() % (secs / 5 + 1);
    chrono::Duration::seconds((secs + jitter) as i64)
}

/// Drives every pending or failed module decision to the trust registry.
///
/// The one retry owner for this failure domain: handlers never call the
/// registry themselves, they write the decision and wake this.
pub struct Projector {
    state: AppState,
    tick: Duration,
}

impl Projector {
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            tick: Duration::from_secs(DEFAULT_TICK_SECONDS),
        }
    }

    /// Run until `shutdown` flips true. A failed pass is logged and the loop
    /// carries on (R1.5).
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        info!(
            tick_seconds = self.tick.as_secs(),
            "capability-module projector starting"
        );
        let mut tick = tokio::time::interval(self.tick);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = WAKE.notified() => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("capability-module projector stopping");
                        return;
                    }
                    continue;
                }
            }
            if let Err(e) = project_due(&self.state).await {
                warn!(error = %e, "capability-module projection pass failed");
            }
        }
    }
}

/// One projection pass: every decision whose projection is not applied and is
/// due is sent to the registry, and its outcome recorded against the
/// generation it was sent for. Returns how many were sent.
pub async fn project_due(state: &AppState) -> Result<usize, AppError> {
    let Some(client) = state.registry_client.clone() else {
        return Ok(0);
    };
    let now = Utc::now();
    let due: Vec<(String, ModuleState)> = {
        let _guard = STATE_LOCK.lock().await;
        load(&state.community_ks)
            .await?
            .into_iter()
            .filter(|(_, m)| {
                m.projection.status != ProjectionStatus::Applied
                    && m.projection.next_attempt_at <= now
            })
            .collect()
    };
    let actor = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_else(|| "vtc-unknown".to_string());

    for (slug, sent) in &due {
        let change = CapabilityModuleChange {
            capability: slug.clone(),
            version: sent.version.clone(),
            enabled: sent.enabled,
            config: sent.config.clone(),
            reason: (!sent.enabled)
                .then(|| sent.disable_reason.clone())
                .flatten(),
        };
        // No lock held across the round trip (R1.3); the client's own reply
        // window bounds it (R1.2).
        let outcome = client.project_capability_module(&change).await;

        let settled = {
            let _guard = STATE_LOCK.lock().await;
            let mut all = load(&state.community_ks).await?;
            let Some(entry) = all.get_mut(slug) else {
                continue;
            };
            if entry.generation != sent.generation {
                // A newer decision was made while this one was in flight; it
                // is projected on its own, and this answer says nothing about
                // it.
                continue;
            }
            let was = entry.projection.status;
            let now = Utc::now();
            match &outcome {
                Ok(()) => {
                    entry.projection = Projection {
                        status: ProjectionStatus::Applied,
                        attempts: entry.projection.attempts + 1,
                        last_error: None,
                        next_attempt_at: now,
                        applied_at: Some(now),
                    };
                }
                Err(e) => {
                    let attempts = entry.projection.attempts + 1;
                    let permanent = matches!(
                        e,
                        RegistryError::Permanent(_) | RegistryError::Incompatible(_)
                    );
                    entry.projection = Projection {
                        status: if permanent {
                            ProjectionStatus::Failed
                        } else {
                            ProjectionStatus::Pending
                        },
                        attempts,
                        last_error: Some(e.to_string()),
                        next_attempt_at: now
                            + if permanent {
                                chrono::Duration::seconds(BACKOFF_CAP_SECONDS as i64)
                            } else {
                                backoff(attempts)
                            },
                        applied_at: None,
                    };
                }
            }
            let entry = entry.clone();
            save(&state.community_ks, &all).await?;
            (was, entry)
        };

        let (was, entry) = settled;
        let decision = if entry.enabled { "enable" } else { "disable" };
        match &outcome {
            Ok(()) => {
                // The registry answered with the state wanted (R6.3: an answer,
                // not a send).
                info!(
                    capability = %slug,
                    decision,
                    attempts = entry.projection.attempts,
                    "trust registry acknowledged the capability-module decision"
                );
                audit(state, &actor, slug, &entry, "projected", None).await;
            }
            Err(e) => {
                warn!(
                    capability = %slug,
                    decision,
                    attempts = entry.projection.attempts,
                    status = entry.projection.status.as_str(),
                    next_attempt_at = %entry.projection.next_attempt_at,
                    error = %e,
                    "trust registry has not taken the capability-module decision"
                );
                if entry.projection.status == ProjectionStatus::Failed
                    && was != ProjectionStatus::Failed
                {
                    audit(
                        state,
                        &actor,
                        slug,
                        &entry,
                        "projectionFailed",
                        Some(e.to_string()),
                    )
                    .await;
                }
            }
        }
    }
    Ok(due.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::specs::governance::capability::list::v0_1 as list_spec;
    use trust_tasks_rs::validate::ValidatedPayload;

    /// The manifest parses into the generated `CapabilityManifest` and
    /// validates against the list response's schema — the check every read
    /// relies on.
    #[test]
    fn every_available_manifest_is_a_schema_valid_capability_manifest() {
        for def in available() {
            serde_json::from_value::<list_spec::CapabilityManifest>(def.manifest.clone())
                .unwrap_or_else(|e| panic!("{}: {e}", def.slug()));
            let response =
                json!({ "capabilities": [{ "manifest": def.manifest, "enabled": false }] });
            list_spec::Response::validate_value(&response)
                .unwrap_or_else(|e| panic!("{}: {e}", def.slug()));
        }
    }

    /// The registry's own git-trust manifest, member for member
    /// (`affinidi-trust-registry-rs` `capabilities/git_trust.rs`). If the
    /// registry's changes, this copy must change with it — or, better, both
    /// move to a shared crate.
    #[test]
    fn the_git_trust_manifest_is_the_registrys() {
        let registry = json!({
            "capability": "git-trust",
            "version": "0.1",
            "title": "Git Commit Trust",
            "description": "Grant and revoke members' commit-signing authority; CI verifies each PR commit's signer DID against this community's registry.",
            "specs": ["git-trust/*"],
            "vocabulary": { "actions": ["git.commit.sign"], "resourcePattern": "<org>[/<repo>]" },
            "roles": { "grant": ["operator"], "view": ["member"] },
            "externalAdapters": [
                { "kind": "github-action", "ref": "OpenVTC/openvtc/.github/actions/verify-trust" }
            ]
        });
        assert_eq!(git_trust_manifest(), registry);
    }

    #[test]
    fn backoff_is_bounded() {
        for attempts in [0, 1, 5, 16, 40, u32::MAX] {
            let d = backoff(attempts).num_seconds() as u64;
            assert!(d >= BACKOFF_BASE_SECONDS, "{attempts}: {d}");
            assert!(
                d <= BACKOFF_CAP_SECONDS + BACKOFF_CAP_SECONDS / 5,
                "{attempts}: {d}"
            );
        }
    }
}
