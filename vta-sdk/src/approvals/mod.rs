//! The declarative **approvals** model — one answer to "does this operation
//! need an additional human decision?".
//!
//! A VTA used to answer that question three ways: `[auth.step_up]` floors keyed
//! by a closed list of op-class slugs, `[[policy.require_consent]]` rules keyed
//! by task type URI, and the messaging-consent approver registry. Two config
//! languages over two identifier spaces, only one of which was reachable at
//! runtime. This module is the single replacement: a list of [`ApprovalRule`]s
//! keyed on task type URI, plus the named [`ApproverSets`] a `consent` rule
//! draws its approvers from.
//!
//! # Where it lives
//!
//! The rules are **not** config. They are carried in the `ext` members of one
//! reserved row in the VTA's policy keyspace ([`DECLARATIVE_POLICY_ID`]),
//! managed at runtime through the canonical `policy/*` Trust Tasks — so they
//! are editable over DIDComm/TSP, not just REST, and they survive without a
//! config-file edit or a restart. Config carries the same shape only as a
//! **seed**, applied once when the row is absent (a fresh install or an
//! IaC-provisioned VTA).
//!
//! # Why the module is client-authored
//!
//! Canonical `policy/upsert` declares `module` (the Rego source) as
//! `minLength: 1` and authoritative — the maintainer validates it, it does not
//! invent it. So a declarative row does not ask the VTA to synthesize on the
//! caller's behalf: the **caller** runs [`synthesize_rego`] over its rules and
//! sends the result as `module`, with the rules themselves in
//! `ext["openvtc.approvals"]`. The VTA re-derives from `ext` and **byte-compares**
//! against the submitted module, rejecting a mismatch.
//!
//! That keeps three properties at once: the canonical contract is unbroken
//! (module stays client-authored and authoritative), nothing a caller sent is
//! silently overwritten, and no hand-edited Rego can ride in under a
//! declarative row's `ext` claiming to be something it isn't.
//!
//! Because both sides derive through this one function, its output is a wire
//! compatibility surface: changing the generated text changes what an older
//! client's row byte-compares against. Treat edits to [`synthesize_rego`] as
//! wire changes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Reserved id of the policy row carrying the declarative approvals model.
///
/// Owned by the approvals surface. An operator's hand-authored Rego uses its
/// own ids and is never touched by it.
pub const DECLARATIVE_POLICY_ID: &str = "approvals";

/// `name` on the reserved row (canonical `policy/upsert` requires one).
pub const DECLARATIVE_POLICY_NAME: &str = "Declarative approvals";

/// Priority of the reserved row: above the permissive baseline (0) so it fires
/// first for the task types it names, with headroom left for an operator's own
/// higher-priority Rego.
pub const DECLARATIVE_POLICY_PRIORITY: i32 = 100;

/// `ext` member carrying the [`ApprovalRule`] list (SPEC §4.5.1 reverse-DNS).
///
/// The canonical `ExtKey` pattern is `^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$` — lower
/// case and dashes only, which is why the sibling key below is
/// `approver-sets` and not `approverSets`.
pub const EXT_KEY_RULES: &str = "openvtc.approvals";

/// `ext` member carrying the [`ApproverSets`] map.
pub const EXT_KEY_APPROVER_SETS: &str = "openvtc.approver-sets";

/// What a gated task requires before it may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Requires {
    /// The caller re-authenticates: an AAL2 elevation of its **own** session,
    /// proven with a second factor it already holds.
    ///
    /// This is the whole of what step-up is now. The former `delegated` /
    /// `delegated-any` modes — a *different* party ratifying, which then
    /// elevated the caller's session for a 15-minute window — are gone: that is
    /// consent with weaker binding, and [`Requires::Consent`] does it properly.
    Reauth,
    /// Named approvers sign off on **this exact payload** (digest-bound,
    /// N-of-M, optionally excluding the requester), and the decision is
    /// re-asserted against the world at execution time.
    Consent,
}

/// One declarative rule: "this task type needs this kind of approval".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalRule {
    /// The Trust Task Type URI to gate, e.g.
    /// `https://trusttasks.org/spec/acl/grant/0.1`.
    ///
    /// Any URI — unlike the step-up floors this replaces, which could only name
    /// one of eleven hardcoded op-classes.
    pub task_type: String,
    /// Which kind of approval the task requires.
    pub requires: Requires,
    /// Named set the approvers must belong to. Required for
    /// [`Requires::Consent`], refused for [`Requires::Reauth`] (which has no
    /// third party).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_set: Option<String>,
    /// Distinct approvals needed. Defaults to 1; consent only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_approvals: Option<u32>,
    /// When true the requester's own DID cannot count toward the threshold,
    /// forcing a genuinely second party. Defaults to false; consent only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_requester: Option<bool>,
    /// Contexts this rule applies in. Empty ⇒ every context.
    ///
    /// Two rules may name the same `taskType` only if both scope to contexts
    /// and those scopes are disjoint — otherwise the generated Rego would have
    /// two complete rules with overlapping guards, which is an evaluation
    /// error, not a precedence rule. [`validate`] enforces it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contexts: Vec<String>,
}

impl ApprovalRule {
    /// A `reauth` rule for `task_type`, applying in every context.
    pub fn reauth(task_type: impl Into<String>) -> Self {
        Self {
            task_type: task_type.into(),
            requires: Requires::Reauth,
            approver_set: None,
            min_approvals: None,
            exclude_requester: None,
            contexts: Vec::new(),
        }
    }

    /// A `consent` rule for `task_type`, satisfied by `approver_set`.
    pub fn consent(task_type: impl Into<String>, approver_set: impl Into<String>) -> Self {
        Self {
            task_type: task_type.into(),
            requires: Requires::Consent,
            approver_set: Some(approver_set.into()),
            min_approvals: None,
            exclude_requester: None,
            contexts: Vec::new(),
        }
    }

    /// Distinct approvals needed — the declared value floored at 1, so a rule
    /// can never be satisfiable by zero approvals.
    pub fn effective_min_approvals(&self) -> u32 {
        self.min_approvals.unwrap_or(1).max(1)
    }

    /// Whether the requester is barred from counting toward the threshold.
    pub fn effective_exclude_requester(&self) -> bool {
        self.exclude_requester.unwrap_or(false)
    }
}

/// Named approver sets: set name → the DIDs permitted to approve.
///
/// `BTreeMap` for a deterministic iteration order — the synthesized module is
/// byte-compared, so nothing that feeds it may be hash-ordered.
pub type ApproverSets = BTreeMap<String, Vec<String>>;

/// Why a declarative approvals model was refused.
///
/// Every variant is a **write-time** refusal. The point is that an
/// unsatisfiable rule is caught when an operator writes it, not discovered by
/// the first caller it blocks — which is how a `delegated` step-up floor with
/// no approver used to fail.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalsError {
    #[error(
        "rule for `{task_type}` is not a Trust Task Type URI: expected \
         `https://trusttasks.org/spec/<slug>/<major>.<minor>`"
    )]
    MalformedTaskType { task_type: String },

    #[error("rule for `{task_type}` requires consent but names no approverSet")]
    MissingApproverSet { task_type: String },

    #[error(
        "rule for `{task_type}` requires reauth but names approverSet `{approver_set}`: \
         reauth elevates the caller's own session and has no third-party approver — \
         use requires = \"consent\" if another party must sign off"
    )]
    ApproverSetOnReauth {
        task_type: String,
        approver_set: String,
    },

    #[error(
        "rule for `{task_type}` names approver set `{approver_set}`, which is not defined; \
         define it before referencing it, or the rule could never be satisfied"
    )]
    UnknownApproverSet {
        task_type: String,
        approver_set: String,
    },

    #[error(
        "approver set `{approver_set}` is empty: a consent rule naming it could never reach \
         its threshold, so every task it gates would be permanently refused"
    )]
    EmptyApproverSet { approver_set: String },

    #[error(
        "rule for `{task_type}` needs {min_approvals} approvals but set `{approver_set}` has \
         only {members} member(s)"
    )]
    ThresholdExceedsSet {
        task_type: String,
        approver_set: String,
        min_approvals: u32,
        members: usize,
    },

    #[error(
        "two rules name `{task_type}` with overlapping scope: rules for one task type must \
         either be a single unscoped rule or carry disjoint `contexts`"
    )]
    OverlappingRules { task_type: String },

    #[error(
        "`{field}` is a consent-only field and cannot be set on the reauth rule for `{task_type}`"
    )]
    ConsentFieldOnReauth {
        task_type: String,
        field: &'static str,
    },
}

/// Structural check that `uri` is a canonical Trust Task Type URI.
///
/// Deliberately structural, not a registry lookup: a VTA may legitimately gate
/// a task the SDK's own catalogue does not name (a newer service, a private
/// namespace). The strict parse belongs to whatever routes the URI; here the
/// job is only to keep an obvious typo out of a policy that would then silently
/// gate nothing.
fn is_task_type_uri(uri: &str) -> bool {
    const PREFIX: &str = "https://trusttasks.org/spec/";
    let Some(rest) = uri.strip_prefix(PREFIX) else {
        return false;
    };
    let Some((slug, version)) = rest.rsplit_once('/') else {
        return false;
    };
    if slug.is_empty() {
        return false;
    }
    // `<major>.<minor>`, digits only.
    let Some((major, minor)) = version.split_once('.') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|b| b.is_ascii_digit())
        && minor.bytes().all(|b| b.is_ascii_digit())
}

/// Validate a complete declarative model.
///
/// Called by the CLI before it sends and by the VTA before it persists — the
/// same function, so a rule that the server would refuse is refused locally
/// first, with the same words.
pub fn validate(rules: &[ApprovalRule], sets: &ApproverSets) -> Result<(), ApprovalsError> {
    for rule in rules {
        if !is_task_type_uri(&rule.task_type) {
            return Err(ApprovalsError::MalformedTaskType {
                task_type: rule.task_type.clone(),
            });
        }
        match rule.requires {
            Requires::Reauth => {
                if let Some(set) = &rule.approver_set {
                    return Err(ApprovalsError::ApproverSetOnReauth {
                        task_type: rule.task_type.clone(),
                        approver_set: set.clone(),
                    });
                }
                // Silently ignoring these would let an operator write a rule
                // that reads as N-of-M and behaves as a self-elevation.
                for (present, field) in [
                    (rule.min_approvals.is_some(), "minApprovals"),
                    (rule.exclude_requester.is_some(), "excludeRequester"),
                ] {
                    if present {
                        return Err(ApprovalsError::ConsentFieldOnReauth {
                            task_type: rule.task_type.clone(),
                            field,
                        });
                    }
                }
            }
            Requires::Consent => {
                let Some(set_name) = rule.approver_set.as_deref() else {
                    return Err(ApprovalsError::MissingApproverSet {
                        task_type: rule.task_type.clone(),
                    });
                };
                let Some(members) = sets.get(set_name) else {
                    return Err(ApprovalsError::UnknownApproverSet {
                        task_type: rule.task_type.clone(),
                        approver_set: set_name.to_string(),
                    });
                };
                if members.is_empty() {
                    return Err(ApprovalsError::EmptyApproverSet {
                        approver_set: set_name.to_string(),
                    });
                }
                let min = rule.effective_min_approvals();
                if min as usize > members.len() {
                    return Err(ApprovalsError::ThresholdExceedsSet {
                        task_type: rule.task_type.clone(),
                        approver_set: set_name.to_string(),
                        min_approvals: min,
                        members: members.len(),
                    });
                }
            }
        }
    }

    // Guards must be mutually exclusive: the generated module uses complete
    // rules, and two that fire on the same input is an evaluation error rather
    // than a precedence decision.
    for (i, rule) in rules.iter().enumerate() {
        for other in &rules[i + 1..] {
            if other.task_type != rule.task_type {
                continue;
            }
            let disjoint = !rule.contexts.is_empty()
                && !other.contexts.is_empty()
                && rule
                    .contexts
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .is_disjoint(&other.contexts.iter().collect::<BTreeSet<_>>());
            if !disjoint {
                return Err(ApprovalsError::OverlappingRules {
                    task_type: rule.task_type.clone(),
                });
            }
        }
    }

    // An approver set nothing references is harmless (an operator staging one
    // before the rule that uses it), so it is deliberately not an error.
    Ok(())
}

/// Encode `s` as a Rego string literal.
///
/// Escapes the characters that would otherwise let operator-supplied text break
/// out of the literal and alter the generated policy's meaning — an approver
/// set named `", "decision": "allow` must not be able to rewrite the rule it
/// appears in.
fn rego_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Header of every generated module. Explains to whoever opens the stored row
/// why hand-editing it will be rejected.
const GENERATED_HEADER: &str = "\
# Generated from the declarative approvals rules — do not hand-edit.
#
# The VTA re-derives this module from ext[\"openvtc.approvals\"] on every upsert
# and refuses the write if the two disagree, so an edit here is not a way to
# change behaviour: change the rules instead.
";

/// Render `rules` as a `vta.policy` Rego module.
///
/// One complete `decision` rule per entry, each guarded on
/// `input.request.typeUri` (and `input.contextId` when the rule is scoped), so
/// the module is *undefined* — it abstains — for every task it does not name,
/// letting the permissive baseline underneath decide.
///
/// **Deterministic**: same rules in, byte-identical module out. That is what
/// makes the server's re-derive-and-compare check meaningful.
pub fn synthesize_rego(rules: &[ApprovalRule]) -> String {
    let mut out = String::from("package vta.policy\n\nimport rego.v1\n\n");
    out.push_str(GENERATED_HEADER);

    for rule in rules {
        out.push('\n');
        let guard_type = format!("input.request.typeUri == {}", rego_string(&rule.task_type));
        let guard_ctx = (!rule.contexts.is_empty()).then(|| {
            let set = rule
                .contexts
                .iter()
                .map(|c| rego_string(c))
                .collect::<Vec<_>>()
                .join(", ");
            format!("input.contextId in {{{set}}}")
        });

        let head = match rule.requires {
            Requires::Reauth => "decision := {\n\t\"decision\": \"requireStepUp\",\n}".to_string(),
            Requires::Consent => format!(
                "decision := {{\n\t\"decision\": \"requireConsent\",\n\t\"requireConsent\": \
                 {{\"approverSet\": {set}, \"minApprovals\": {min}, \"excludeRequester\": \
                 {exclude}}},\n}}",
                set = rego_string(rule.approver_set.as_deref().unwrap_or_default()),
                min = rule.effective_min_approvals(),
                exclude = rule.effective_exclude_requester(),
            ),
        };

        match guard_ctx {
            None => out.push_str(&format!("{head} if {guard_type}\n")),
            Some(ctx) => out.push_str(&format!("{head} if {{\n\t{guard_type}\n\t{ctx}\n}}\n")),
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACL_GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
    const WEBVH_UPDATE: &str = "https://trusttasks.org/spec/vta/webvh/dids/update/1.0";

    fn sets(name: &str, members: &[&str]) -> ApproverSets {
        let mut m = ApproverSets::new();
        m.insert(
            name.to_string(),
            members.iter().map(|s| s.to_string()).collect(),
        );
        m
    }

    #[test]
    fn synthesis_is_deterministic() {
        let rules = vec![
            ApprovalRule::reauth(ACL_GRANT),
            ApprovalRule::consent(WEBVH_UPDATE, "ops"),
        ];
        assert_eq!(synthesize_rego(&rules), synthesize_rego(&rules));
    }

    /// The generated shape is a wire contract (the server byte-compares it), so
    /// it is pinned rather than merely exercised.
    #[test]
    fn synthesis_shape_is_pinned() {
        let mut consent = ApprovalRule::consent(WEBVH_UPDATE, "webvh-approvers");
        consent.exclude_requester = Some(true);
        consent.contexts = vec!["openvtc".into()];
        let rego = synthesize_rego(&[ApprovalRule::reauth(ACL_GRANT), consent]);

        assert!(rego.starts_with("package vta.policy\n\nimport rego.v1\n\n"));
        assert!(rego.contains(
            "decision := {\n\t\"decision\": \"requireStepUp\",\n} if input.request.typeUri == \
             \"https://trusttasks.org/spec/acl/grant/0.1\"\n"
        ));
        assert!(rego.contains(
            "\t\"requireConsent\": {\"approverSet\": \"webvh-approvers\", \"minApprovals\": 1, \
             \"excludeRequester\": true},\n"
        ));
        assert!(rego.contains("\tinput.contextId in {\"openvtc\"}\n}"));
    }

    /// An approver-set name is operator-supplied text that lands inside a Rego
    /// literal. If it could close the string it could rewrite the decision.
    #[test]
    fn injection_through_an_approver_set_name_is_escaped() {
        let injected = "x\", \"decision\": \"allow";
        let rego = synthesize_rego(&[ApprovalRule::consent(WEBVH_UPDATE, injected)]);
        assert!(rego.contains("\\\""), "quote was not escaped: {rego}");
        // The only `"decision":` keys are the two this generator wrote.
        assert_eq!(rego.matches("\"decision\": \"require").count(), 1);
        assert!(!rego.contains("\"decision\": \"allow\""));
    }

    #[test]
    fn empty_rules_produce_an_abstaining_module() {
        let rego = synthesize_rego(&[]);
        assert!(!rego.contains("decision :="));
    }

    #[test]
    fn consent_without_a_set_is_refused() {
        let rule = ApprovalRule {
            approver_set: None,
            ..ApprovalRule::consent(WEBVH_UPDATE, "ops")
        };
        assert!(matches!(
            validate(&[rule], &ApproverSets::new()),
            Err(ApprovalsError::MissingApproverSet { .. })
        ));
    }

    #[test]
    fn unknown_and_empty_approver_sets_are_refused_at_write_time() {
        let rule = ApprovalRule::consent(WEBVH_UPDATE, "ops");
        assert!(matches!(
            validate(std::slice::from_ref(&rule), &ApproverSets::new()),
            Err(ApprovalsError::UnknownApproverSet { .. })
        ));
        assert!(matches!(
            validate(&[rule], &sets("ops", &[])),
            Err(ApprovalsError::EmptyApproverSet { .. })
        ));
    }

    #[test]
    fn a_threshold_no_set_could_meet_is_refused() {
        let mut rule = ApprovalRule::consent(WEBVH_UPDATE, "ops");
        rule.min_approvals = Some(3);
        assert!(matches!(
            validate(&[rule], &sets("ops", &["did:key:a", "did:key:b"])),
            Err(ApprovalsError::ThresholdExceedsSet { .. })
        ));
    }

    /// `reauth` has no third party. Accepting these fields and ignoring them
    /// would let a rule read as two-person control and behave as one.
    #[test]
    fn consent_only_fields_are_refused_on_a_reauth_rule() {
        let mut rule = ApprovalRule::reauth(ACL_GRANT);
        rule.min_approvals = Some(2);
        assert!(matches!(
            validate(&[rule], &ApproverSets::new()),
            Err(ApprovalsError::ConsentFieldOnReauth {
                field: "minApprovals",
                ..
            })
        ));

        let mut rule = ApprovalRule::reauth(ACL_GRANT);
        rule.approver_set = Some("ops".into());
        assert!(matches!(
            validate(&[rule], &sets("ops", &["did:key:a"])),
            Err(ApprovalsError::ApproverSetOnReauth { .. })
        ));
    }

    #[test]
    fn overlapping_rules_for_one_task_type_are_refused() {
        // Two unscoped rules: the generated module would have two complete
        // rules firing on the same input.
        let dup = vec![
            ApprovalRule::reauth(ACL_GRANT),
            ApprovalRule::reauth(ACL_GRANT),
        ];
        assert!(matches!(
            validate(&dup, &ApproverSets::new()),
            Err(ApprovalsError::OverlappingRules { .. })
        ));

        // Scoped but overlapping.
        let mut a = ApprovalRule::reauth(ACL_GRANT);
        a.contexts = vec!["x".into(), "y".into()];
        let mut b = ApprovalRule::reauth(ACL_GRANT);
        b.contexts = vec!["y".into()];
        assert!(matches!(
            validate(&[a, b], &ApproverSets::new()),
            Err(ApprovalsError::OverlappingRules { .. })
        ));
    }

    #[test]
    fn disjoint_scoped_rules_for_one_task_type_are_allowed() {
        let mut a = ApprovalRule::reauth(ACL_GRANT);
        a.contexts = vec!["x".into()];
        let mut b = ApprovalRule::consent(ACL_GRANT, "ops");
        b.contexts = vec!["y".into()];
        assert!(validate(&[a, b], &sets("ops", &["did:key:a"])).is_ok());
    }

    #[test]
    fn a_malformed_task_type_is_refused() {
        for bad in [
            "acl/grant/0.1",
            "https://trusttasks.org/acl/grant/0.1",
            "https://trusttasks.org/spec/acl/grant",
            "https://trusttasks.org/spec/acl/grant/v1",
            "https://trusttasks.org/spec/0.1",
        ] {
            let rule = ApprovalRule::reauth(bad);
            assert!(
                matches!(
                    validate(&[rule], &ApproverSets::new()),
                    Err(ApprovalsError::MalformedTaskType { .. })
                ),
                "{bad} should be refused"
            );
        }
        assert!(validate(&[ApprovalRule::reauth(ACL_GRANT)], &ApproverSets::new()).is_ok());
    }

    #[test]
    fn rules_round_trip_as_camel_case_json() {
        let mut rule = ApprovalRule::consent(WEBVH_UPDATE, "ops");
        rule.min_approvals = Some(2);
        rule.exclude_requester = Some(true);
        rule.contexts = vec!["openvtc".into()];
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(json["taskType"], WEBVH_UPDATE);
        assert_eq!(json["requires"], "consent");
        assert_eq!(json["approverSet"], "ops");
        assert_eq!(json["minApprovals"], 2);
        assert_eq!(json["excludeRequester"], true);
        assert_eq!(serde_json::from_value::<ApprovalRule>(json).unwrap(), rule);
    }

    /// Absent optional fields must not serialize — a stored row that grew empty
    /// members would byte-compare differently after a round-trip.
    #[test]
    fn absent_optionals_are_omitted() {
        let json = serde_json::to_value(ApprovalRule::reauth(ACL_GRANT)).unwrap();
        assert_eq!(
            json.as_object().unwrap().keys().collect::<BTreeSet<_>>(),
            BTreeSet::from([&"requires".to_string(), &"taskType".to_string()])
        );
    }

    #[test]
    fn unknown_rule_fields_are_refused() {
        let json = serde_json::json!({
            "taskType": ACL_GRANT,
            "requires": "reauth",
            "approverSets": ["typo-for-approverSet"],
        });
        assert!(serde_json::from_value::<ApprovalRule>(json).is_err());
    }
}
