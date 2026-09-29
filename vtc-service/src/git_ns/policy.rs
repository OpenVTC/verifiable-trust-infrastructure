//! The community's git-namespace policy — `PolicyPurpose::GitNamespace`,
//! package `vtc.git_namespace`, the shipped default at
//! `policies/default/git_ns.rego`.
//!
//! The design names the package `vtc.git_ns`. It is `vtc.git_namespace`
//! because every other purpose's package is the snake_case of its wire name,
//! and the admin console derives the package from the purpose by that rule
//! (`pkgFor`) rather than from a list of exceptions.
//!
//! # Policy may only narrow
//!
//! Fixed rule 6: "After the rules above pass, the VTC evaluates the
//! community's git-namespace policy … Policy can refuse, with
//! `git-ns:policyDenied`; it can never admit a request the rules above
//! refuse." That is structural here, not a convention a policy author has to
//! follow: [`decide`] is called only after [`super::rules`] has passed, and it
//! returns either `Ok(())` or a refusal — there is no verdict it can return
//! that grants anything. A policy answering `allow` for a request the rules
//! refused never runs.
//!
//! # What a policy sees
//!
//! [`GitNsFacts`] — the actor (their DID, whether they are a member, their
//! community role, their git rights on the resource), the action, the
//! resource, the right, the subject (with the same membership facts), the
//! forge and what its namespace can do. Every DID in it was established by a
//! proof or read from this service's own records; nothing is a payload field
//! taken on trust — the same gate `rooms::policy` keeps.
//!
//! # Settings
//!
//! A policy may also answer `data.vtc.git_namespace.settings`, an object of the
//! community's choices the specification leaves to it: whether maintainers may
//! grant `git.commit.sign`, whether a departed member's grants are revoked with
//! them (`cascade_on_departure`), how role drift is answered, and how
//! break-glass is tightened (`break_glass`, `break_glass_delay_seconds`,
//! `break_glass_min_justification_chars`). An absent or unreadable settings
//! object reads as every setting off — the conservative reading — except
//! break-glass, which is on unless a policy says `"disabled"`: it exists for
//! the moment nobody else is available, which is not the moment to discover a
//! typo in a settings object turned it off.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::policy::engine::{CompiledPolicy, evaluate};
use crate::policy::model::PolicyPurpose;
use crate::server::AppState;
use vti_common::error::AppError;

use super::rules::{RuleSettings, RulesPassed};

const DECISION_QUERY: &str = "data.vtc.git_namespace.decision";
const SETTINGS_QUERY: &str = "data.vtc.git_namespace.settings";

/// The party making the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Party {
    pub did: String,
    pub member: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// The party's git rights on the resource, explicit or implied.
    #[serde(default)]
    pub rights: Vec<String>,
}

/// What the namespace's forge can do, as far as this VTC knows.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    /// A bridge serves the namespace.
    pub bridge: bool,
    /// A bot can create repositories there (bridge mode on an organisation).
    pub bot_can_create_repos: bool,
    /// `organization`, `user`, or absent until the binding completes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The DID of the bridge that serves the namespace, as the VTC recorded
    /// it at binding — what lets a policy recognise the one service grant a
    /// non-member receives (`bridge.serviceGrant`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_did: Option<String>,
}

/// The `input` document a git-namespace policy evaluates over.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitNsFacts {
    pub now: DateTime<Utc>,
    /// `namespace.bind`, `namespace.unbind`, `repo.create`, `repo.adopt`,
    /// `repo.transfer`, `repo.archive`, `right.grant`, `right.revoke`.
    pub action: String,
    pub actor: Party,
    pub resource: String,
    pub forge: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Party>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub capabilities: Capabilities,
    /// How the request arose, where that differs from the action: `drift.adopt`
    /// on the `right.grant` an adopted drift item is evaluated as
    /// (`git-ns/drift/resolve`, step 6), so a community can refuse to adopt
    /// forge-side changes while still granting. Absent for a direct request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

/// Facts that passed the fixed rules.
///
/// The only constructor, [`Self::after_fixed_rules`], consumes the
/// [`RulesPassed`] token that only the rule functions in [`super::rules`]
/// produce: a policy is evaluated over a request the fixed rules have already
/// admitted, and never instead of them — enforced by the type, not by
/// convention.
#[derive(Debug, Clone)]
pub struct VerifiedGitNsFacts(GitNsFacts);

impl VerifiedGitNsFacts {
    pub fn after_fixed_rules(facts: GitNsFacts, _passed: RulesPassed) -> Result<Self, AppError> {
        if facts.actor.did.trim().is_empty() {
            return Err(AppError::Forbidden(
                "a git-namespace request must name the party that signed it".into(),
            ));
        }
        Ok(Self(facts))
    }

    pub fn facts(&self) -> &GitNsFacts {
        &self.0
    }
}

/// Community settings read from the active policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Settings {
    pub rules: RuleSettings,
    /// Revoke the grants a departed member issued, rather than listing them
    /// for review (design §5.4). Off by default.
    pub cascade_on_departure: bool,
    /// Re-project forge roles when role drift is reported, rather than only
    /// reporting it (design §5.6, `drift_mode` for roles). Off by default:
    /// "report" for roles.
    pub enforce_role_drift: bool,
    /// How this community tightens break-glass (`git-ns/right/break-glass/0.1`,
    /// *Policy*). It can disable or tighten it; it can never quieten it.
    pub break_glass: BreakGlassSettings,
}

/// The community's break-glass choices. Enabled, with no delay, by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakGlassSettings {
    /// `settings.break_glass == "disabled"` turns break-glass off:
    /// `git-ns/right/break-glass:disabled`. Anything else, or nothing, is on.
    pub enabled: bool,
    /// `settings.break_glass_delay_seconds`: the right takes effect this long
    /// after it is recorded (`breakGlass.effectiveAt`), so other administrators
    /// have a window to revoke it before it confers anything.
    pub delay_seconds: u64,
    /// `settings.break_glass_min_justification_chars`: a justification with
    /// fewer non-whitespace characters is refused `git-ns:policyDenied`.
    pub min_justification_chars: usize,
}

impl Default for BreakGlassSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            delay_seconds: 0,
            min_justification_chars: 0,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
struct SettingsDoc {
    #[serde(default)]
    maintainer_grants_commit: bool,
    #[serde(default)]
    cascade_on_departure: bool,
    #[serde(default)]
    role_drift: Option<String>,
    #[serde(default)]
    break_glass: Option<String>,
    #[serde(default)]
    break_glass_delay_seconds: Option<u64>,
    #[serde(default)]
    break_glass_min_justification_chars: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
struct Decision {
    effect: String,
    #[serde(default)]
    with: DecisionWith,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct DecisionWith {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// The loaded, compiled active policy and its version, for the audit record.
pub struct ActivePolicy {
    pub compiled: CompiledPolicy,
    pub version: Option<u32>,
}

/// Load the active git-namespace policy.
///
/// A VTC with none refuses rather than admitting: the default installs at
/// boot, so the gap is an operator who removed it or a first boot that has not
/// reached it, and "not currently deciding" is a closed door (the reading
/// `rooms` takes for the same gap).
pub async fn load(state: &AppState) -> Result<ActivePolicy, AppError> {
    let compiled = crate::policy::load_active_compiled(
        &state.active_policies_ks,
        &state.policies_ks,
        PolicyPurpose::GitNamespace,
    )
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, "no active git-namespace policy; refusing");
        AppError::Forbidden(
            "git-namespace request denied (no-policy): this community has no active \
             `gitNamespace` policy. The shipped default installs at boot; check \
             `GET /v1/policies`."
                .into(),
        )
    })?;
    let version = active_version(state).await;
    Ok(ActivePolicy { compiled, version })
}

async fn active_version(state: &AppState) -> Option<u32> {
    let id = crate::policy::storage::get_active_policy_id(
        &state.active_policies_ks,
        PolicyPurpose::GitNamespace,
    )
    .await
    .ok()
    .flatten()?;
    crate::policy::storage::get_policy(&state.policies_ks, id)
        .await
        .ok()
        .flatten()
        .map(|p| p.version)
}

fn first_value(results: &Value) -> Option<&Value> {
    results
        .get("result")
        .and_then(|r| r.as_array())
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("expressions"))
        .and_then(|e| e.as_array())
        .and_then(|exprs| exprs.first())
        .and_then(|expr| expr.get("value"))
}

/// The community's settings from `policy`. Absent or unreadable reads as
/// every setting off.
pub fn settings(policy: &CompiledPolicy) -> Settings {
    let Ok(results) = evaluate(policy, SETTINGS_QUERY, serde_json::json!({})) else {
        return Settings::default();
    };
    let Some(value) = first_value(&results) else {
        return Settings::default();
    };
    let doc: SettingsDoc = serde_json::from_value(value.clone()).unwrap_or_default();
    Settings {
        rules: RuleSettings {
            maintainer_grants_commit: doc.maintainer_grants_commit,
        },
        cascade_on_departure: doc.cascade_on_departure,
        enforce_role_drift: doc.role_drift.as_deref() == Some("enforce"),
        break_glass: BreakGlassSettings {
            enabled: doc.break_glass.as_deref() != Some("disabled"),
            // A day at most: a longer delay is a disabled break-glass in all
            // but name, and should say so.
            delay_seconds: doc.break_glass_delay_seconds.unwrap_or(0).min(86_400),
            min_justification_chars: doc.break_glass_min_justification_chars.unwrap_or(0),
        },
    }
}

/// Settings from the active policy, or the defaults when there is none.
pub async fn active_settings(state: &AppState) -> Settings {
    match load(state).await {
        Ok(p) => settings(&p.compiled),
        Err(_) => Settings::default(),
    }
}

/// Why the policy refused, as `(code, message)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDenied {
    pub code: String,
    pub message: String,
}

/// Evaluate the policy over facts the fixed rules admitted.
///
/// `Ok(())` lets the request proceed; anything else is a refusal. A policy
/// that answers nothing is a refusal too — Rego reads a missing rule as an
/// empty result, and treating that as consent would turn a typo in a package
/// name into an open door.
pub fn decide(verified: &VerifiedGitNsFacts, policy: &CompiledPolicy) -> Result<(), PolicyDenied> {
    let input = serde_json::to_value(verified.facts()).map_err(|e| PolicyDenied {
        code: "unreadable-input".into(),
        message: format!("the request could not be put to the policy: {e}"),
    })?;
    let results = evaluate(policy, DECISION_QUERY, input).map_err(|e| PolicyDenied {
        code: "evaluation-failed".into(),
        message: format!("the git-namespace policy failed to evaluate: {e}"),
    })?;
    let Some(value) = first_value(&results) else {
        return Err(PolicyDenied {
            code: "no-decision".into(),
            message: "the active git-namespace policy answered nothing, which is refused \
                      rather than read as consent"
                .into(),
        });
    };
    let decision: Decision = serde_json::from_value(value.clone()).map_err(|e| PolicyDenied {
        code: "unreadable-decision".into(),
        message: format!("the git-namespace policy returned a decision this VTC cannot read: {e}"),
    })?;
    match decision.effect.as_str() {
        "allow" => Ok(()),
        "deny" => {
            let code = decision.with.code.unwrap_or_else(|| "denied".into());
            let message = match decision.with.reason {
                Some(r) => format!("git-namespace policy refused ({code}): {r}"),
                None => format!("git-namespace policy refused ({code})"),
            };
            Err(PolicyDenied { code, message })
        }
        // `refer` / `request-more` are the threaded ceremony verdicts; a
        // git-namespace request is one synchronous call, so the only safe
        // reading of a verdict it cannot carry out is refusal.
        other => Err(PolicyDenied {
            code: "unsupported-verdict".into(),
            message: format!(
                "the git-namespace policy answered `{other}`, which a git-namespace request \
                 cannot carry out"
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::default::default_source;
    use crate::policy::engine::compile;

    fn default_policy() -> CompiledPolicy {
        compile(
            default_source(PolicyPurpose::GitNamespace),
            uuid::Uuid::nil(),
        )
        .expect("the bundled git_ns policy compiles")
    }

    fn party(did: &str, member: bool) -> Party {
        Party {
            did: did.into(),
            member,
            role: member.then(|| "member".to_string()),
            rights: vec![],
        }
    }

    fn facts(action: &str, actor_member: bool, subject: Option<Party>) -> VerifiedGitNsFacts {
        VerifiedGitNsFacts::after_fixed_rules(
            GitNsFacts {
                now: "2026-09-23T12:00:00Z".parse().unwrap(),
                action: action.into(),
                actor: party("did:key:actor", actor_member),
                resource: "github.com/acme/widgets".into(),
                forge: "github.com".into(),
                right: Some("git.commit.sign".into()),
                subject,
                visibility: None,
                expires_at: None,
                capabilities: Capabilities::default(),
                via: None,
            },
            RulesPassed::for_test(),
        )
        .unwrap()
    }

    #[test]
    fn the_default_admits_members_granting_to_members() {
        let f = facts("right.grant", true, Some(party("did:key:s", true)));
        assert_eq!(decide(&f, &default_policy()), Ok(()));
    }

    #[test]
    fn the_default_refuses_external_signers() {
        let f = facts("right.grant", true, Some(party("did:key:s", false)));
        let err = decide(&f, &default_policy()).unwrap_err();
        assert_eq!(err.code, "external-signers-not-enabled");
    }

    #[test]
    fn the_default_refuses_a_non_member_actor() {
        let f = facts("repo.create", false, None);
        assert!(decide(&f, &default_policy()).is_err());
    }

    #[test]
    fn a_resignation_or_revocation_is_never_refused_for_a_non_member_subject() {
        // Taking a right away from an external signer must stay possible even
        // under a policy that never let one be granted.
        let f = facts("right.revoke", true, Some(party("did:key:s", false)));
        assert_eq!(decide(&f, &default_policy()), Ok(()));
    }

    fn service_grant(
        subject: &str,
        bridge: &str,
        resource: &str,
        right: &str,
    ) -> VerifiedGitNsFacts {
        VerifiedGitNsFacts::after_fixed_rules(
            GitNsFacts {
                now: "2026-09-23T12:00:00Z".parse().unwrap(),
                action: "bridge.serviceGrant".into(),
                actor: party("did:webvh:vtc", true),
                resource: resource.into(),
                forge: "github.com".into(),
                right: Some(right.into()),
                subject: Some(party(subject, false)),
                visibility: None,
                expires_at: None,
                capabilities: Capabilities {
                    bridge: true,
                    bridge_did: Some(bridge.into()),
                    ..Capabilities::default()
                },
                via: None,
            },
            RulesPassed::for_test(),
        )
        .unwrap()
    }

    #[test]
    fn the_default_admits_exactly_the_namespaces_own_bridge_service_grant() {
        let p = default_policy();
        let b = "did:key:bridge";
        assert_eq!(
            decide(
                &service_grant(b, b, "github.com/acme", "git.commit.sign"),
                &p
            ),
            Ok(())
        );
        // Another DID, a repository, another right: all refused.
        assert!(
            decide(
                &service_grant("did:key:x", b, "github.com/acme", "git.commit.sign"),
                &p
            )
            .is_err()
        );
        assert!(
            decide(
                &service_grant(b, b, "github.com/acme/w", "git.commit.sign"),
                &p
            )
            .is_err()
        );
        assert!(decide(&service_grant(b, b, "github.com/acme", "git.ns.admin"), &p).is_err());
    }

    #[test]
    fn the_default_settings_are_all_off() {
        assert_eq!(settings(&default_policy()), Settings::default());
    }

    #[test]
    fn a_policy_answering_nothing_is_a_refusal() {
        let p = compile(
            "package vtc.git_namespace\nimport rego.v1\n",
            uuid::Uuid::nil(),
        )
        .unwrap();
        let f = facts("right.grant", true, Some(party("did:key:s", true)));
        assert_eq!(decide(&f, &p).unwrap_err().code, "no-decision");
    }

    #[test]
    fn settings_are_read_from_the_policy() {
        let p = compile(
            "package vtc.git_namespace\nimport rego.v1\n\
             default decision := {\"effect\": \"allow\"}\n\
             settings := {\"maintainer_grants_commit\": true, \"cascade_on_departure\": true, \
             \"role_drift\": \"enforce\"}\n",
            uuid::Uuid::nil(),
        )
        .unwrap();
        let s = settings(&p);
        assert!(s.rules.maintainer_grants_commit);
        assert!(s.cascade_on_departure);
        assert!(s.enforce_role_drift);
    }
}
