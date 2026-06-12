//! The Evaluate stage — run a purpose's policy over verified facts
//! and parse the decision (ceremony-pipeline design §2 "Evaluate").
//!
//! This is the seam between the generic pipeline and the **reused**
//! MVP policy engine ([`crate::policy::engine`]): it takes a
//! [`VerifiedFacts`] (the only thing the pipeline lets reach a
//! policy), serializes it to the `input` document, runs the purpose's
//! `decision` query through `regorus`, and parses the result into a
//! [`Verdict`]. Crypto is already behind us (the [`VerifiedFacts`]
//! typestate guarantees it), so this stage never touches a signature.
//!
//! ## Structural totality is enforced twice
//!
//! The Rule-IR compiler appends `default decision := {deny}` to every
//! policy, so a well-formed module always yields a decision. This
//! stage adds a **host-side** backstop: if a policy somehow evaluates
//! to `undefined` (e.g. a hand-written escape-hatch module that
//! forgot the default), the host synthesizes
//! [`Verdict::default_deny`] rather than erroring or — far worse —
//! treating "no decision" as permission. Totality is a safety
//! property; we don't trust a single enforcement point for it.

use serde_json::Value as JsonValue;
use vti_common::error::AppError;

use super::verdict::Verdict;
use super::verify::VerifiedFacts;
use crate::policy::engine::{self, CompiledPolicy};

/// Evaluate a purpose's compiled policy over verified facts.
///
/// The `policy` must be the compiled module for `verified.purpose()`
/// — the query is derived from the purpose
/// ([`super::facts::Purpose::decision_query`]), so handing this the
/// wrong purpose's policy yields `undefined` → a host default-deny
/// rather than a wrong allow.
///
/// Returns the policy's [`Verdict`] (pre-invariant — the host
/// invariants are applied separately by
/// [`super::invariant::enforce`]). A malformed decision object is an
/// [`AppError::Internal`] (a policy/compiler bug, not caller input);
/// an `undefined` decision degrades to [`Verdict::default_deny`].
pub fn evaluate(verified: &VerifiedFacts, policy: &CompiledPolicy) -> Result<Verdict, AppError> {
    let input = verified.to_input()?;
    let query = verified.purpose().decision_query();
    let results = match engine::evaluate(policy, &query, input) {
        Ok(results) => results,
        // Resource-bound abort (time budget or input-size cap, P0.18). The
        // join decision runs on the unauthenticated submit route, so a
        // pathological policy / adversarial input must fail **closed** —
        // deny — not surface a 500 or hang the handler.
        Err(e @ AppError::ResourceExhausted(_)) => {
            tracing::warn!(
                purpose = verified.purpose().as_str(),
                error = %e,
                "ceremony policy evaluation hit a resource bound — failing closed (deny)",
            );
            return Ok(Verdict::default_deny());
        }
        Err(e) => return Err(e),
    };

    match decision_value(&results) {
        Some(decision) => Verdict::from_decision(decision),
        // Policy evaluated to `undefined` — structural-totality
        // backstop. A policy that yields no decision denies.
        None => Ok(Verdict::default_deny()),
    }
}

/// Pluck the decision object out of regorus's `QueryResults` shape
/// (`{ "result": [{ "expressions": [{ "value": V }] }] }`). Returns
/// `None` when the query was `undefined` — either no `result` rows,
/// or an empty-object `value` (regorus renders an undefined rule
/// reference as `{}`, per [`crate::policy::engine`]'s documented
/// behaviour).
fn decision_value(results: &JsonValue) -> Option<JsonValue> {
    let value = results.pointer("/result/0/expressions/0/value")?;
    if matches!(value, JsonValue::Object(o) if o.is_empty()) {
        return None;
    }
    Some(value.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::facts::{
        Actor, Context, Credential, CredentialStatus, Evidence, Facts, Presentation, Purpose,
        State, Subject,
    };
    use crate::policy::engine::compile;
    use serde_json::json;
    use uuid::Uuid;

    /// The example `join.rego` decision spine, trimmed to the two
    /// branches the tests exercise. Package `vtc.join` so
    /// `Purpose::Join.decision_query()` finds it.
    const JOIN_REGO: &str = r#"
package vtc.join

import future.keywords.if
import future.keywords.in

default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

decision := {"effect": "allow", "with": {"role": "member", "obligations": ["reciprocate_vmc"]}} if {
    cred_trusted("WitnessCredential")
}

cred_trusted(t) if {
    some c in input.evidence.presentation.credentials
    c.type == t
    c.issuer_trusted
    c.status == "valid"
}
"#;

    fn join_facts(issuer_trusted: bool) -> VerifiedFacts {
        let facts = Facts {
            purpose: Purpose::Join,
            now: "2026-05-30T12:00:00Z".parse().unwrap(),
            actor: Actor {
                did: "did:key:zHuman".into(),
                role: None,
                authenticated: true,
            },
            subject: Subject {
                did: "did:key:zHuman".into(),
            },
            context: Context {
                community_did: "did:webvh:acme.example".into(),
                channel: "rest".into(),
                member_count: 10,
            },
            evidence: Evidence {
                invitation: None,
                presentation: Some(Presentation {
                    verified: true,
                    holder: "did:key:zHuman".into(),
                    credentials: vec![Credential {
                        credential_type: "WitnessCredential".into(),
                        issuer: "did:webvh:notary.example".into(),
                        issuer_trusted,
                        status: CredentialStatus::Valid,
                        holder_bound: true,
                        claims: json!({}),
                        valid_until: None,
                    }],
                }),
                request: Some(json!({ "agreements": {} })),
            },
            state: State {
                subject_member: None,
            },
        };
        VerifiedFacts::assemble(facts).expect("verified")
    }

    /// A trusted witness credential matches the allow branch — the
    /// host parses it into a structured `Verdict::Allow`.
    #[test]
    fn allow_branch_parses_into_verdict() {
        let policy = compile(JOIN_REGO, Uuid::new_v4()).expect("join.rego compiles");
        let verdict = evaluate(&join_facts(true), &policy).expect("evaluate");
        assert_eq!(verdict.effect(), "allow");
        match verdict {
            Verdict::Allow(a) => {
                assert_eq!(a.role.as_deref(), Some("member"));
                assert_eq!(a.obligations, vec!["reciprocate_vmc".to_string()]);
            }
            other => panic!("expected allow, got {other:?}"),
        }
    }

    /// An untrusted issuer falls through to the compiler-appended
    /// default — the host sees the explicit deny.
    #[test]
    fn unmatched_falls_through_to_policy_default_deny() {
        let policy = compile(JOIN_REGO, Uuid::new_v4()).unwrap();
        let verdict = evaluate(&join_facts(false), &policy).expect("evaluate");
        assert_eq!(verdict, Verdict::default_deny());
    }

    /// A policy with no `default decision` that doesn't match yields
    /// `undefined` — the host's structural-totality backstop turns
    /// that into a deny, never a missing/permissive decision.
    #[test]
    fn undefined_decision_degrades_to_host_default_deny() {
        // No `default decision` line, and the rule body never fires
        // for our facts (requires an admin actor).
        const NO_DEFAULT: &str = r#"
package vtc.join

import future.keywords.if

decision := {"effect": "allow", "with": {"role": "admin"}} if {
    input.actor.role == "admin"
}
"#;
        let policy = compile(NO_DEFAULT, Uuid::new_v4()).unwrap();
        let verdict = evaluate(&join_facts(true), &policy).expect("evaluate");
        assert_eq!(verdict, Verdict::default_deny());
    }

    /// The query is derived from the facts' purpose; evaluating facts
    /// against a policy whose package doesn't match the purpose yields
    /// `undefined` → deny, not a cross-purpose allow.
    #[test]
    fn purpose_mismatched_policy_denies() {
        // A directory policy that would allow, but the facts are a
        // join — `data.vtc.join.decision` is undefined in this module.
        const DIRECTORY: &str = r#"
package vtc.directory

import future.keywords.if

default decision := {"effect": "allow", "with": {"fields": ["did"]}}
"#;
        let policy = compile(DIRECTORY, Uuid::new_v4()).unwrap();
        let verdict = evaluate(&join_facts(true), &policy).expect("evaluate");
        assert_eq!(verdict, Verdict::default_deny());
    }

    /// Fail-closed (P0.18): a join policy whose `decision` rule does
    /// pathological work trips the evaluator's resource budget. On the
    /// unauthenticated submit path this must degrade to a **deny**, not a
    /// 500 or a hang.
    #[test]
    fn resource_bound_abort_fails_closed_to_deny() {
        // The expensive comprehension runs whenever `decision` is
        // evaluated, so the timer trips before any allow can be returned.
        const RUNAWAY_JOIN: &str = r#"
package vtc.join

import rego.v1

xs := numbers.range(1, 10000)

default decision := {"effect": "deny", "with": {"code": "default"}}

decision := {"effect": "allow", "with": {"role": "member"}} if {
    count([1 | some i in xs; some j in xs; i == j]) >= 0
}
"#;
        let policy = compile(RUNAWAY_JOIN, Uuid::new_v4()).unwrap();
        let verdict = evaluate(&join_facts(true), &policy)
            .expect("resource-bound abort must not surface as an error");
        assert_eq!(
            verdict,
            Verdict::default_deny(),
            "a policy that exhausts its budget must fail closed (deny)"
        );
    }
}
