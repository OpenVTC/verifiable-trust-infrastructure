//! Runtime management of the VTA's AAL2 step-up policy (`auth/step-up/policy`).
//!
//! The *gate* (the resolution algorithm + `RequireStepUp` extractor) already
//! lives in [`crate::routes::trust_tasks::step_up`]. This module is the
//! *management* half: validating, canonicalizing, and durably applying a new
//! [`StepUpPolicy`], so an operator can change the VTA's posture at runtime
//! instead of editing the config TOML and restarting.
//!
//! Two callers share [`set_step_up_policy`]:
//! - the wire path — the `auth/step-up/policy/0.2` trust-task handler
//!   (`routes::trust_tasks::step_up_policy`), authorized by a super-admin bearer;
//! - the **break-glass** path — the offline `vta step-up policy` CLI (direct
//!   config access, no wire auth), which the spec REQUIRES so an over-strict
//!   policy can be recovered without traversing the step-up gate.
//!
//! Persistence mirrors the runtime-service-management ops: mutate the live
//! `RwLock<AppConfig>` and rewrite the config file (`AppConfig::save`), so the
//! change is both immediate and durable across restarts.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use tokio::sync::RwLock;

use trust_tasks_rs::specs::auth::step_up::policy::v0_2 as policy;
use vti_common::acl::list_acl_entries;
use vti_common::auth::step_up::{StepUpFloor, StepUpMode, StepUpPolicy, op_class};
use vti_common::store::KeyspaceHandle;

use crate::config::AppConfig;

/// Why setting a step-up policy was refused. Maps to the spec's `auth/step-up/policy`
/// error codes (the wire handler renders these as `trust-task-error`s; the CLI
/// prints them).
#[derive(Debug, thiserror::Error)]
pub enum SetPolicyError {
    /// A floor names an operation-class the maintainer does not gate
    /// (`unknownOperation`). Carries the offending slug.
    #[error("unknown operation-class '{0}': not a gated operation (or '*')")]
    UnknownOperation(String),
    /// Enabling would leave a `delegated` floor with no party able to satisfy it
    /// — no `AclEntry` carries a `stepUp.approver` — locking out every
    /// administrator (`lockoutRefused`).
    #[error("{0}")]
    LockoutRefused(String),
    /// Reading the ACL (for the lockout check) failed.
    #[error("acl read failed: {0}")]
    Store(String),
    /// Persisting the policy to the config file failed.
    #[error("policy persistence failed: {0}")]
    Persistence(String),
}

/// Validate, canonicalize, durably persist, and live-apply `requested`.
///
/// On success returns the **effective** (canonicalized) policy the maintainer
/// now holds — floors deduplicated by operation, last occurrence winning,
/// first-seen order preserved (mirrors the spec's `#response`).
///
/// Steps (spec §Conformance consumer rules 2–4):
/// 1. `unknownOperation` — every `floor.operation` is `*` or a gated op-class.
/// 2. canonicalize the floors.
/// 3. `lockoutRefused` — refuse enabling a delegated floor when no approver
///    exists anywhere in the ACL (only when `enabled`).
/// 4. apply atomically: update the live config + rewrite the config file.
pub async fn set_step_up_policy(
    config: &Arc<RwLock<AppConfig>>,
    acl_ks: &KeyspaceHandle,
    requested: StepUpPolicy,
) -> Result<StepUpPolicy, SetPolicyError> {
    // 1. unknownOperation.
    for floor in &requested.floors {
        if !op_class::is_recognized(&floor.operation) {
            return Err(SetPolicyError::UnknownOperation(floor.operation.clone()));
        }
    }

    // 2. canonicalize.
    let effective = canonicalize(requested);

    // 3. lockoutRefused (only relevant when enabling enforcement).
    if effective.enabled {
        lockout_check(&effective, acl_ks).await?;
    }

    // 4. apply atomically: live config + durable file.
    {
        let mut cfg = config.write().await;
        cfg.auth.step_up = effective.clone();
        cfg.save()
            .map_err(|e| SetPolicyError::Persistence(e.to_string()))?;
    }

    Ok(effective)
}

/// Deduplicate floors by `operation` (last occurrence wins) while preserving
/// first-seen order. `enabled` is carried through unchanged. Per-floor
/// `allow_aal1_if_non_escalating` is already a materialized `bool` on
/// [`StepUpFloor`](vti_common::auth::step_up::StepUpFloor), so "defaults
/// materialized" needs no extra work here.
fn canonicalize(policy: StepUpPolicy) -> StepUpPolicy {
    let mut order: Vec<String> = Vec::new();
    let mut by_op: HashMap<String, vti_common::auth::step_up::StepUpFloor> = HashMap::new();
    for floor in policy.floors {
        if !by_op.contains_key(&floor.operation) {
            order.push(floor.operation.clone());
        }
        by_op.insert(floor.operation.clone(), floor);
    }
    let floors = order
        .into_iter()
        .map(|op| by_op.remove(&op).expect("op was just inserted"))
        .collect();
    StepUpPolicy {
        enabled: policy.enabled,
        floors,
    }
}

/// Anti-lockout (spec §Security → *Anti-lockout*).
///
/// A `self` (or `none`) floor is always satisfiable: any `did:key` holder can
/// sign a did-signed approve-response for its **own** session with the key it
/// already holds, so enabling a `self` floor can never brick anyone. A
/// `delegated`/`delegatedAny` floor, however, can only be satisfied if some
/// party carries a `stepUp.approver` the request can be routed to. If enabling
/// would gate any operation-class at a delegated mode while **no** `AclEntry`
/// carries an approver, every administrator is locked out — refuse, prompting
/// the operator to register an approver first.
///
/// This is conservative (it refuses if *no* approver exists anywhere, rather
/// than reasoning per-principal), which is the safe direction for an
/// anti-lockout guard; the offline break-glass path remains the ultimate
/// recovery if a policy ever does over-constrain.
async fn lockout_check(
    policy: &StepUpPolicy,
    acl_ks: &KeyspaceHandle,
) -> Result<(), SetPolicyError> {
    let needs_delegated = policy
        .floors
        .iter()
        .any(|f| matches!(f.mode, StepUpMode::Delegated));
    let needs_delegated_any = policy
        .floors
        .iter()
        .any(|f| matches!(f.mode, StepUpMode::DelegatedAny));
    if !needs_delegated && !needs_delegated_any {
        return Ok(());
    }

    let entries = list_acl_entries(acl_ks)
        .await
        .map_err(|e| SetPolicyError::Store(e.to_string()))?;

    // `delegated` needs a bound approver routed to via `stepUp.approver`.
    if needs_delegated
        && !entries
            .iter()
            .any(|e| e.step_up_approver.as_deref().is_some_and(|a| !a.is_empty()))
    {
        return Err(SetPolicyError::LockoutRefused(
            "enabling a delegated floor would lock out all administrators: no AclEntry \
             carries a stepUp.approver. Register an approver (acl create/update \
             --step-up-approver), then enable."
                .to_string(),
        ));
    }

    // `delegated-any` is satisfiable by any admin meeting the criterion, so it
    // needs at least one admin entry to exist to ratify.
    if needs_delegated_any && !entries.iter().any(|e| e.is_admin()) {
        return Err(SetPolicyError::LockoutRefused(
            "enabling a delegated-any floor would lock out all administrators: no admin \
             AclEntry exists to ratify. Register an admin, then enable."
                .to_string(),
        ));
    }
    Ok(())
}

// ── conversions between the `auth/step-up/policy/0.2` wire binding and the
//    VTA's internal `StepUpPolicy` (shared by the trust-task handler and the
//    REST surface) ─────────────────────────────────────────────────────────

fn floormode_to_mode(m: policy::FloorMode) -> StepUpMode {
    match m {
        policy::FloorMode::None => StepUpMode::None,
        policy::FloorMode::Self_ => StepUpMode::SelfApprove,
        policy::FloorMode::Delegated => StepUpMode::Delegated,
        policy::FloorMode::DelegatedAny => StepUpMode::DelegatedAny,
    }
}

fn mode_to_floormode(m: StepUpMode) -> policy::FloorMode {
    match m {
        StepUpMode::None => policy::FloorMode::None,
        StepUpMode::SelfApprove => policy::FloorMode::Self_,
        StepUpMode::Delegated => policy::FloorMode::Delegated,
        StepUpMode::DelegatedAny => policy::FloorMode::DelegatedAny,
    }
}

/// Convert a parsed `auth/step-up/policy/0.2` payload to the internal policy.
pub fn policy_from_payload(p: &policy::Payload) -> StepUpPolicy {
    StepUpPolicy {
        enabled: p.enabled,
        floors: p
            .floors
            .iter()
            .map(|f| StepUpFloor {
                operation: f.operation.clone(),
                mode: floormode_to_mode(f.mode),
                allow_aal1_if_non_escalating: f.allow_aal1_if_non_escalating.unwrap_or(false),
            })
            .collect(),
    }
}

/// Parse a policy JSON value (the `0.2` payload shape — camelCase `mode`
/// values + `allowAal1IfNonEscalating`) into the internal policy. Used by the
/// REST `PUT /step-up/policy` surface. Returns a human-readable error on a
/// malformed body.
pub fn policy_from_value(v: &Value) -> Result<StepUpPolicy, String> {
    let payload: policy::Payload =
        serde_json::from_value(v.clone()).map_err(|e| format!("invalid step-up policy: {e}"))?;
    Ok(policy_from_payload(&payload))
}

/// Render a policy as the canonical `0.2` response value: every floor's
/// `allowAal1IfNonEscalating` materialized, mode values in camelCase
/// (`delegatedAny`). Shared by the trust-task `#response`, the REST `PUT`
/// result, and the `GET /step-up/policy` read.
pub fn effective_response(p: &StepUpPolicy) -> Value {
    let resp = policy::Response {
        enabled: p.enabled,
        ext: None,
        floors: p
            .floors
            .iter()
            .map(|f| policy::Floor {
                operation: f.operation.clone(),
                mode: mode_to_floormode(f.mode),
                allow_aal1_if_non_escalating: Some(f.allow_aal1_if_non_escalating),
            })
            .collect(),
    };
    serde_json::to_value(resp).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn floor(op: &str, mode: StepUpMode) -> StepUpFloor {
        StepUpFloor {
            operation: op.to_string(),
            mode,
            allow_aal1_if_non_escalating: false,
        }
    }

    #[test]
    fn canonicalize_dedupes_last_wins_preserving_order() {
        let p = StepUpPolicy {
            enabled: true,
            floors: vec![
                floor("acl/grant", StepUpMode::SelfApprove),
                floor("*", StepUpMode::SelfApprove),
                floor("acl/grant", StepUpMode::Delegated), // later wins
            ],
        };
        let c = canonicalize(p);
        // First-seen order: acl/grant, then *.
        assert_eq!(c.floors.len(), 2);
        assert_eq!(c.floors[0].operation, "acl/grant");
        assert_eq!(c.floors[0].mode, StepUpMode::Delegated); // last occurrence won
        assert_eq!(c.floors[1].operation, "*");
    }

    #[test]
    fn op_class_recognition() {
        assert!(op_class::is_recognized("*"));
        assert!(op_class::is_recognized("acl/grant"));
        assert!(op_class::is_recognized("key/revoke"));
        assert!(!op_class::is_recognized("acl/teleport"));
        assert!(!op_class::is_recognized(""));
    }
}
