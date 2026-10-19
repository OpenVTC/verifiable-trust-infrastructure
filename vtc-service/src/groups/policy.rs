//! The `groups` policy (`vtc.groups`): may this group be created, or joined?
//!
//! Asked only after the host's own checks pass — the caller manages what they
//! change, the member is active, the settings are well formed — and able only
//! to refuse. Nothing it returns makes anyone a member, a manager or a holder
//! of authority.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use vti_common::error::AppError;

use crate::policy::engine::{CompiledPolicy, evaluate};
use crate::policy::model::PolicyPurpose;
use crate::server::AppState;

const DECISION_QUERY: &str = "data.vtc.groups.decision";

/// The group a decision is about, as the policy sees it.
pub struct GroupFacts<'a> {
    /// Empty on `create`: the group has no identifier until it is stored.
    pub group_id: &'a str,
    pub join_policy: &'a str,
    pub visibility: &'a str,
    pub show_members: &'a str,
    pub issues_credentials: bool,
    pub member_count: usize,
}

/// What is being decided, and by whom.
pub struct Facts<'a> {
    /// `create` | `join` | `request`.
    pub operation: &'static str,
    pub now: DateTime<Utc>,
    pub actor_did: &'a str,
    pub actor_role: Option<&'a str>,
    pub actor_member: bool,
    pub actor_manager: bool,
    pub group: GroupFacts<'a>,
}

#[derive(Debug, Deserialize)]
struct Decision {
    effect: String,
    #[serde(default)]
    with: DecisionWith,
}

#[derive(Debug, Default, Deserialize)]
struct DecisionWith {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// `Ok(None)`: allowed. `Ok(Some(message))`: the policy refused, saying why.
pub fn judge(policy: &CompiledPolicy, facts: &Facts<'_>) -> Result<Option<String>, AppError> {
    let input = json!({
        "operation": facts.operation,
        "now": facts.now,
        "actor": {
            "did": facts.actor_did,
            "role": facts.actor_role,
            "member": facts.actor_member,
            "manager": facts.actor_manager,
        },
        "group": {
            "groupId": facts.group.group_id,
            "kind": "static",
            "joinPolicy": facts.group.join_policy,
            "visibility": facts.group.visibility,
            "showMembers": facts.group.show_members,
            "issuesCredentials": facts.group.issues_credentials,
            "memberCount": facts.group.member_count,
        },
    });
    let results = match evaluate(policy, DECISION_QUERY, input) {
        Ok(r) => r,
        // A pathological policy fails closed, as every policy here does.
        Err(e @ AppError::ResourceExhausted(_)) => {
            tracing::warn!(error = %e, "groups policy hit a resource bound; refusing");
            return Ok(Some(
                "the community's groups policy could not decide".into(),
            ));
        }
        Err(e) => return Err(e),
    };
    let value = results.pointer("/result/0/expressions/0/value");
    let Some(value) = value.filter(|v| !matches!(v, Value::Object(o) if o.is_empty())) else {
        // A policy that answers nothing is refused rather than read as consent.
        return Ok(Some(
            "the community's groups policy answered nothing".into(),
        ));
    };
    let decision: Decision = serde_json::from_value(value.clone()).map_err(|e| {
        AppError::Internal(format!(
            "the active groups policy returned a decision this service cannot read: {e}"
        ))
    })?;
    match decision.effect.as_str() {
        "allow" => Ok(None),
        _ => Ok(Some(
            decision
                .with
                .reason
                .or(decision.with.code)
                .unwrap_or_else(|| "refused by the community's groups policy".into()),
        )),
    }
}

/// [`judge`] under the community's active `groups` policy. A community with no
/// active policy refuses: the shipped default is installed at boot, so its
/// absence is a gap, not consent.
pub async fn decide(state: &AppState, facts: &Facts<'_>) -> Result<Option<String>, AppError> {
    let policy = crate::policy::load_active_compiled(
        &state.active_policies_ks,
        &state.policies_ks,
        PolicyPurpose::Groups,
    )
    .await?;
    judge(&policy, facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::engine::compile;

    fn facts(operation: &'static str, member_count: usize) -> Facts<'static> {
        Facts {
            operation,
            now: Utc::now(),
            actor_did: "did:example:carol",
            actor_role: Some("member"),
            actor_member: true,
            actor_manager: false,
            group: GroupFacts {
                group_id: "grp_AAAAAAAAAAAAAAAAAAAAAA",
                join_policy: "open",
                visibility: "members",
                show_members: "members",
                issues_credentials: true,
                member_count,
            },
        }
    }

    #[test]
    fn the_shipped_default_allows() {
        let p = compile(
            crate::policy::default::default_source(PolicyPurpose::Groups),
            uuid::Uuid::nil(),
        )
        .unwrap();
        assert_eq!(judge(&p, &facts("join", 0)).unwrap(), None);
        assert_eq!(judge(&p, &facts("create", 0)).unwrap(), None);
    }

    #[test]
    fn a_policy_can_cap_a_group() {
        let p = compile(
            r#"package vtc.groups
import rego.v1
default decision := {"effect": "allow"}
decision := {"effect": "deny", "with": {"code": "group-full", "reason": "this group is full"}} if {
    input.operation in {"join", "request"}
    input.group.memberCount >= 2
}
"#,
            uuid::Uuid::nil(),
        )
        .unwrap();
        assert_eq!(judge(&p, &facts("join", 1)).unwrap(), None);
        assert_eq!(
            judge(&p, &facts("join", 2)).unwrap().as_deref(),
            Some("this group is full")
        );
    }

    #[test]
    fn a_policy_that_answers_nothing_refuses() {
        let p = compile("package vtc.groups\nimport rego.v1\n", uuid::Uuid::nil()).unwrap();
        assert!(judge(&p, &facts("create", 0)).unwrap().is_some());
    }
}
