//! Automatic vetter grants: a periodic sweep that names vetters by policy.
//!
//! A community with many members cannot name every vetter by hand. When an
//! admin turns automatic grants on (`PUT /v1/vetting/auto-grant`), a sweep
//! evaluates the community's `vetter_eligibility` policy (Rego package
//! `vtc.vetter_eligibility`) for every active member:
//!
//! - `allow` — grant a vetter role credential when the member holds no live
//!   grant ([`super::vetters::grant_locked`], origin `auto`);
//! - `deny` — revoke the live grants **the sweep issued**
//!   ([`super::vetters::revoke_auto_grants`]); an admin's grant is never
//!   touched;
//! - anything else — no decision, an unknown effect, an evaluation error —
//!   counts as an error and changes nothing. A broken policy must not revoke
//!   every automatic grant.
//!
//! ## The facts
//!
//! [`EligibilityFacts`]: `did`, `status`, `roles`, `tenureDays`, `admittedVia`
//! (`genesis` | `vetting` | `invitation` | `open`), `underReview`, and `depth`.
//! They are derived from the member row, the ACL row, the join request that
//! admitted the member and the vetting facts recorded for it
//! (`crate::join::StoredVettingFacts`), and the withdrawal notices:
//!
//! - `admittedVia` is `vetting` when the admitting request's vetting facts were
//!   satisfied by at least one counted statement, else `invitation` when the
//!   member joined on an invitation, else `open` when a join request admitted
//!   them, else `genesis` — a member the community did not admit through a
//!   join request (its founders).
//! - `underReview` is `true` when a statement that counted toward the member's
//!   admission has since been withdrawn.
//! - `depth` is `0` for a genesis member and one more than the shallowest
//!   counted vetter's depth for a vetted one; `null` when unknown — for an
//!   invitation or open admission, or when no counted vetter's depth is known.
//!
//! ## Configuration and the last sweep
//!
//! Stored in the `community` keyspace ([`CONFIG_STORAGE_KEY`],
//! [`LAST_SWEEP_STORAGE_KEY`]), so both survive a backup. The sweeper wakes
//! every minute and runs a sweep when one is enabled and due.

use std::collections::{HashMap, HashSet};
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{info, warn};

use vta_sdk::protocols::vetting::{
    AutoGrantConfig, AutoGrantStatus, AutoGrantSweep, CheckShape, DEFAULT_AUTO_GRANT_SWEEP_MINUTES,
    DEFAULT_VETTER_GRANT_VALIDITY_SECONDS, GrantOrigin,
};
use vti_common::audit::{AuditEvent, VetterAutoGrantConfiguredData, VetterAutoGrantSweptData};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::{revocation, vetters};
use crate::acl::get_acl_entry;
use crate::join::{JoinRequest, JoinStatus, get_vetting_facts, list_join_requests};
use crate::members::storage::list_members;
use crate::policy::{CompiledPolicy, PolicyPurpose, evaluate, load_active_compiled};
use crate::server::AppState;

/// The configuration's key in the `community` keyspace.
pub const CONFIG_STORAGE_KEY: &[u8] = b"vetting/auto-grant/config";
/// The last sweep's key in the `community` keyspace.
pub const LAST_SWEEP_STORAGE_KEY: &[u8] = b"vetting/auto-grant/last-sweep";

/// The query the sweep evaluates.
pub const DECISION_QUERY: &str = "data.vtc.vetter_eligibility.decision";

/// How often the sweeper wakes to see whether a sweep is due.
const TICK: StdDuration = StdDuration::from_secs(60);

/// The stored configuration, defaults applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredAutoGrantConfig {
    /// Whether the sweep runs.
    pub enabled: bool,
    /// Minutes between sweeps.
    pub sweep_minutes: u32,
    /// Validity of a grant the sweep issues.
    pub validity_seconds: u64,
}

impl Default for StoredAutoGrantConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sweep_minutes: DEFAULT_AUTO_GRANT_SWEEP_MINUTES,
            validity_seconds: DEFAULT_VETTER_GRANT_VALIDITY_SECONDS,
        }
    }
}

/// The stored configuration, or the defaults (off) when none was set.
pub async fn load_config(ks: &KeyspaceHandle) -> Result<StoredAutoGrantConfig, AppError> {
    match ks.get_raw(CONFIG_STORAGE_KEY).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("auto-grant config decode: {e}"))),
        None => Ok(StoredAutoGrantConfig::default()),
    }
}

async fn load_last_sweep(ks: &KeyspaceHandle) -> Result<Option<AutoGrantSweep>, AppError> {
    match ks.get_raw(LAST_SWEEP_STORAGE_KEY).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| AppError::Internal(format!("auto-grant last sweep decode: {e}"))),
        None => Ok(None),
    }
}

fn storage_key(key: &[u8]) -> String {
    String::from_utf8(key.to_vec()).expect("storage keys are ASCII")
}

/// The configuration and the last sweep, as `GET /v1/vetting/auto-grant`
/// reports them.
pub async fn status(state: &AppState) -> Result<AutoGrantStatus, AppError> {
    let config = load_config(&state.community_ks).await?;
    Ok(AutoGrantStatus {
        enabled: config.enabled,
        sweep_minutes: config.sweep_minutes,
        validity_seconds: config.validity_seconds,
        last_sweep: load_last_sweep(&state.community_ks).await?,
    })
}

/// Replace the configuration on behalf of `actor_did`, an admin, and audit it.
///
/// # Errors
///
/// [`AppError::Validation`] for out-of-bounds values; a 503
/// [`AppError::ServiceError`] when there is no audit writer — the change is
/// refused rather than made unaudited.
pub async fn configure(
    state: &AppState,
    actor_did: &str,
    body: &AutoGrantConfig,
) -> Result<AutoGrantStatus, AppError> {
    body.check_shape()
        .map_err(|e| AppError::Validation(e.to_string()))?;
    let writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured".into(),
        })?;
    let stored = StoredAutoGrantConfig {
        enabled: body.enabled,
        sweep_minutes: body
            .sweep_minutes
            .unwrap_or(DEFAULT_AUTO_GRANT_SWEEP_MINUTES),
        validity_seconds: body
            .validity_seconds
            .unwrap_or(DEFAULT_VETTER_GRANT_VALIDITY_SECONDS),
    };
    state
        .community_ks
        .insert(storage_key(CONFIG_STORAGE_KEY), &stored)
        .await?;
    writer
        .write(
            actor_did,
            None,
            AuditEvent::VetterAutoGrantConfigured(VetterAutoGrantConfiguredData {
                enabled: stored.enabled,
                sweep_minutes: stored.sweep_minutes,
                validity_seconds: stored.validity_seconds,
            }),
        )
        .await?;
    info!(
        enabled = stored.enabled,
        sweep_minutes = stored.sweep_minutes,
        "automatic vetter grants configured"
    );
    status(state).await
}

/// How a member came to be one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdmittedVia {
    /// Not admitted through a join request — a founding member.
    Genesis,
    /// Admitted on vetting statements that satisfied the requirements.
    Vetting,
    /// Admitted on an invitation.
    Invitation,
    /// Admitted through a join request with neither.
    Open,
}

/// The `input` the `vetter_eligibility` policy decides on, for one member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EligibilityFacts {
    /// The member.
    pub did: String,
    /// `active` — the sweep evaluates active members only.
    pub status: String,
    /// The member's community roles.
    pub roles: Vec<String>,
    /// Whole days since the member joined.
    pub tenure_days: i64,
    /// How the member was admitted.
    pub admitted_via: AdmittedVia,
    /// A statement that counted toward the admission has been withdrawn.
    pub under_review: bool,
    /// Vetting hops from a genesis member; `null` when unknown.
    pub depth: Option<u32>,
}

/// What the admitting join request says about one member.
struct Admission {
    via: AdmittedVia,
    counted_vetters: Vec<String>,
    under_review: bool,
}

/// The eligibility facts of every active member.
pub async fn eligibility_facts(
    state: &AppState,
    now: DateTime<Utc>,
) -> Result<Vec<EligibilityFacts>, AppError> {
    let members: Vec<_> = list_members(&state.members_ks)
        .await?
        .into_iter()
        .filter(|m| m.removed_at.is_none())
        .collect();

    let mut admitting: HashMap<String, JoinRequest> = HashMap::new();
    for request in list_join_requests(&state.join_requests_ks).await? {
        if request.status != JoinStatus::Approved {
            continue;
        }
        let newer = admitting
            .get(&request.applicant_did)
            .is_none_or(|seen| seen.submitted_at < request.submitted_at);
        if newer {
            admitting.insert(request.applicant_did.clone(), request);
        }
    }

    let withdrawn: HashSet<(String, String)> =
        revocation::list_notices(&state.vetting_revocations_ks)
            .await?
            .into_iter()
            .map(|n| (n.issuer, n.statement_id))
            .collect();

    let mut admissions: HashMap<String, Admission> = HashMap::new();
    for member in &members {
        let request = admitting.get(&member.did);
        let facts = match request {
            Some(r) => get_vetting_facts(&state.join_requests_ks, r.id)
                .await?
                .map(|s| s.facts),
            None => None,
        };
        let counted: Vec<(String, Option<String>)> = facts
            .iter()
            .flat_map(|f| f.statements.iter())
            .filter(|s| s.counted)
            .filter_map(|s| Some((s.issuer.clone()?, s.id.clone())))
            .collect();
        let vetted = facts.as_ref().is_some_and(|f| f.satisfied) && !counted.is_empty();
        let via = if vetted {
            AdmittedVia::Vetting
        } else if member.joined_via_invitation {
            AdmittedVia::Invitation
        } else if request.is_some() {
            AdmittedVia::Open
        } else {
            AdmittedVia::Genesis
        };
        let under_review = counted.iter().any(|(issuer, id)| {
            id.as_ref()
                .is_some_and(|id| withdrawn.contains(&(issuer.clone(), id.clone())))
        });
        let mut counted_vetters: Vec<String> = counted.into_iter().map(|(i, _)| i).collect();
        counted_vetters.sort();
        counted_vetters.dedup();
        admissions.insert(
            member.did.clone(),
            Admission {
                via,
                counted_vetters,
                under_review,
            },
        );
    }

    let mut depths: HashMap<String, Option<u32>> = HashMap::new();
    let mut out = Vec::with_capacity(members.len());
    for member in members {
        let roles = get_acl_entry(&state.acl_ks, &member.did)
            .await?
            .map(|acl| vec![acl.role.to_string()])
            .unwrap_or_default();
        let depth = depth_of(&member.did, &admissions, &mut depths, &mut HashSet::new());
        let admission = admissions
            .get(&member.did)
            .expect("every active member has an admission record");
        out.push(EligibilityFacts {
            did: member.did.clone(),
            status: "active".into(),
            roles,
            tenure_days: (now - member.joined_at).num_days().max(0),
            admitted_via: admission.via,
            under_review: admission.under_review,
            depth,
        });
    }
    Ok(out)
}

/// A member's vetting depth, memoised. A cycle — which a correct history
/// cannot produce, but a restored or edited store might — reads as unknown.
fn depth_of(
    did: &str,
    admissions: &HashMap<String, Admission>,
    memo: &mut HashMap<String, Option<u32>>,
    visiting: &mut HashSet<String>,
) -> Option<u32> {
    if let Some(known) = memo.get(did) {
        return *known;
    }
    let admission = admissions.get(did)?;
    let depth = match admission.via {
        AdmittedVia::Genesis => Some(0),
        AdmittedVia::Vetting => {
            if !visiting.insert(did.to_string()) {
                return None;
            }
            let shallowest = admission
                .counted_vetters
                .iter()
                .filter_map(|vetter| depth_of(vetter, admissions, memo, visiting))
                .min();
            visiting.remove(did);
            shallowest.and_then(|d| d.checked_add(1))
        }
        AdmittedVia::Invitation | AdmittedVia::Open => None,
    };
    memo.insert(did.to_string(), depth);
    depth
}

/// What the policy said about one member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Grant when no live grant exists.
    Allow,
    /// Revoke the sweep's own grants.
    Deny,
    /// No usable answer; nothing changes.
    Undecided(String),
}

/// Evaluate the policy for one member.
pub fn decide(policy: &CompiledPolicy, facts: &EligibilityFacts) -> Result<Decision, AppError> {
    let input = serde_json::to_value(facts)?;
    let results = evaluate(policy, DECISION_QUERY, input)?;
    let value = results
        .get("result")
        .and_then(|r| r.as_array())
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("expressions"))
        .and_then(|e| e.as_array())
        .and_then(|exprs| exprs.first())
        .and_then(|expr| expr.get("value"));
    Ok(
        match value.and_then(|v| v.get("effect")).and_then(|e| e.as_str()) {
            Some("allow") => Decision::Allow,
            Some("deny") => Decision::Deny,
            Some(other) => Decision::Undecided(format!("unsupported effect `{other}`")),
            None => Decision::Undecided("the policy answered nothing".into()),
        },
    )
}

/// Run one sweep now, whatever the configuration says, record it as the last
/// sweep, and audit it.
///
/// # Errors
///
/// Only for what stops the whole sweep: no active `vetter_eligibility` policy,
/// no community signer, no audit writer, or the store. A member the sweep
/// cannot decide or act on is counted in `errors` and logged.
pub async fn run_sweep(state: &AppState) -> Result<AutoGrantSweep, AppError> {
    let config = load_config(&state.community_ks).await?;
    let writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    let actor = state
        .credential_signer
        .as_ref()
        .map(|s| s.issuer_did().to_string())
        .ok_or_else(|| AppError::Internal("credential signer not configured".into()))?;
    let policy = load_active_compiled(
        &state.active_policies_ks,
        &state.policies_ks,
        PolicyPurpose::VetterEligibility,
    )
    .await?;

    let now = Utc::now();
    let (mut granted, mut revoked, mut errors) = (0u32, 0u32, 0u32);
    for facts in eligibility_facts(state, now).await? {
        match decide(&policy, &facts) {
            Ok(Decision::Allow) => {
                let result = {
                    let _guard = vetters::GRANT_LOCK.lock().await;
                    vetters::grant_locked(
                        state,
                        &actor,
                        &facts.did,
                        Some(config.validity_seconds),
                        GrantOrigin::Auto,
                    )
                    .await
                };
                match result {
                    Ok(grant) => {
                        // Delivered once the lock is released, as on the admin path.
                        if let Some(credential) = &grant.credential {
                            vetters::deliver_grant(state, &facts.did, credential).await;
                            granted += 1;
                        }
                    }
                    Err(e) => {
                        warn!(member = %facts.did, error = %e, "automatic vetter grant failed");
                        errors += 1;
                    }
                }
            }
            Ok(Decision::Deny) => {
                match vetters::revoke_auto_grants(state, &actor, &facts.did).await {
                    Ok(n) => revoked += n,
                    Err(e) => {
                        warn!(member = %facts.did, error = %e, "automatic vetter revocation failed");
                        errors += 1;
                    }
                }
            }
            Ok(Decision::Undecided(reason)) => {
                warn!(member = %facts.did, reason, "vetter_eligibility policy gave no decision");
                errors += 1;
            }
            Err(e) => {
                warn!(member = %facts.did, error = %e, "vetter_eligibility policy failed");
                errors += 1;
            }
        }
    }

    let sweep = AutoGrantSweep {
        ran_at: Utc::now(),
        granted,
        revoked,
        errors,
    };
    state
        .community_ks
        .insert(storage_key(LAST_SWEEP_STORAGE_KEY), &sweep)
        .await?;
    writer
        .write(
            &actor,
            None,
            AuditEvent::VetterAutoGrantSwept(VetterAutoGrantSweptData {
                granted,
                revoked,
                errors,
            }),
        )
        .await?;
    info!(
        granted,
        revoked, errors, "automatic vetter-grant sweep finished"
    );
    Ok(sweep)
}

/// Is a sweep due, `sweep_minutes` after the last?
pub fn sweep_due(sweep_minutes: u32, last: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    last.is_none_or(|ran| now - ran >= Duration::minutes(i64::from(sweep_minutes)))
}

/// Owns the sweeper task.
pub struct AutoGrantSweeper;

impl AutoGrantSweeper {
    /// Spawn the sweeper. It reads the configuration on every tick, so an
    /// admin's change takes effect within a minute, and returns when the
    /// shutdown watcher fires.
    pub fn spawn(
        state: AppState,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        info!("automatic vetter-grant sweeper shutting down");
                        return;
                    }
                    _ = tokio::time::sleep(TICK) => {
                        if let Err(e) = tick(&state).await {
                            warn!(error = %e, "automatic vetter-grant sweep failed");
                        }
                    }
                }
            }
        })
    }
}

async fn tick(state: &AppState) -> Result<(), AppError> {
    let config = load_config(&state.community_ks).await?;
    if !config.enabled {
        return Ok(());
    }
    let last = load_last_sweep(&state.community_ks).await?;
    if sweep_due(config.sweep_minutes, last.map(|s| s.ran_at), Utc::now()) {
        run_sweep(state).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::default::default_source;
    use crate::policy::engine::compile;

    fn facts(via: AdmittedVia, under_review: bool) -> EligibilityFacts {
        EligibilityFacts {
            did: "did:key:zCarol".into(),
            status: "active".into(),
            roles: vec!["member".into()],
            tenure_days: 400,
            admitted_via: via,
            under_review,
            depth: Some(0),
        }
    }

    fn default_policy() -> CompiledPolicy {
        compile(
            default_source(PolicyPurpose::VetterEligibility),
            uuid::Uuid::nil(),
        )
        .expect("the bundled vetter_eligibility policy compiles")
    }

    #[test]
    fn the_default_names_genesis_members_in_good_standing_only() {
        let policy = default_policy();
        assert_eq!(
            decide(&policy, &facts(AdmittedVia::Genesis, false)).unwrap(),
            Decision::Allow
        );
        assert_eq!(
            decide(&policy, &facts(AdmittedVia::Genesis, true)).unwrap(),
            Decision::Deny
        );
        for via in [
            AdmittedVia::Vetting,
            AdmittedVia::Invitation,
            AdmittedVia::Open,
        ] {
            assert_eq!(decide(&policy, &facts(via, false)).unwrap(), Decision::Deny);
        }
    }

    #[test]
    fn the_input_is_camel_case_with_a_nullable_depth() {
        let mut f = facts(AdmittedVia::Vetting, false);
        f.depth = None;
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["admittedVia"], "vetting");
        assert_eq!(v["tenureDays"], 400);
        assert_eq!(v["underReview"], false);
        assert!(
            v["depth"].is_null(),
            "depth is present and null when unknown"
        );
    }

    #[test]
    fn a_policy_that_answers_nothing_or_nonsense_decides_nothing() {
        let silent = compile(
            "package vtc.vetter_eligibility\nimport rego.v1\n",
            uuid::Uuid::nil(),
        )
        .unwrap();
        assert!(matches!(
            decide(&silent, &facts(AdmittedVia::Genesis, false)).unwrap(),
            Decision::Undecided(_)
        ));
        let odd = compile(
            "package vtc.vetter_eligibility\nimport rego.v1\ndecision := {\"effect\": \"refer\"}\n",
            uuid::Uuid::nil(),
        )
        .unwrap();
        assert!(matches!(
            decide(&odd, &facts(AdmittedVia::Genesis, false)).unwrap(),
            Decision::Undecided(_)
        ));
        let wrong_package = compile(
            "package vtc.join\nimport rego.v1\ndecision := {\"effect\": \"allow\"}\n",
            uuid::Uuid::nil(),
        )
        .unwrap();
        assert!(matches!(
            decide(&wrong_package, &facts(AdmittedVia::Genesis, false)).unwrap(),
            Decision::Undecided(_)
        ));
    }

    fn admission(via: AdmittedVia, vetters: &[&str]) -> Admission {
        Admission {
            via,
            counted_vetters: vetters.iter().map(|s| s.to_string()).collect(),
            under_review: false,
        }
    }

    #[test]
    fn depth_counts_hops_from_genesis_through_the_shallowest_vetter() {
        let admissions: HashMap<String, Admission> = [
            ("founder", admission(AdmittedVia::Genesis, &[])),
            ("alice", admission(AdmittedVia::Vetting, &["founder"])),
            (
                "bob",
                admission(AdmittedVia::Vetting, &["alice", "founder"]),
            ),
            ("carol", admission(AdmittedVia::Vetting, &["bob"])),
            ("dan", admission(AdmittedVia::Invitation, &[])),
            (
                "erin",
                admission(AdmittedVia::Vetting, &["dan", "departed"]),
            ),
            ("cycle-a", admission(AdmittedVia::Vetting, &["cycle-b"])),
            ("cycle-b", admission(AdmittedVia::Vetting, &["cycle-a"])),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let mut memo = HashMap::new();
        let mut depth = |did: &str| depth_of(did, &admissions, &mut memo, &mut HashSet::new());
        assert_eq!(depth("founder"), Some(0));
        assert_eq!(depth("alice"), Some(1));
        assert_eq!(depth("bob"), Some(1));
        assert_eq!(depth("carol"), Some(2));
        assert_eq!(depth("dan"), None);
        assert_eq!(depth("erin"), None);
        assert_eq!(depth("cycle-a"), None);
        assert_eq!(depth("nobody"), None);
    }

    #[test]
    fn a_sweep_is_due_after_its_interval() {
        let now = Utc::now();
        assert!(sweep_due(60, None, now));
        assert!(!sweep_due(60, Some(now - Duration::minutes(59)), now));
        assert!(sweep_due(60, Some(now - Duration::minutes(60)), now));
    }
}
