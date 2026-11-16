//! The VTA's policy decision over the shared bounded Rego engine.
//!
//! Compiling, the input-size cap and the CPU-time budget are
//! [`vti_common::policy_engine`]'s, shared with the VTC (#2577) so a bound
//! tightened or a regorus workaround applied in one place reaches both. What
//! stays here is what a VTA policy *means*: the `data.vta.policy.decision`
//! query, the [`PolicyInput`] it reads and the [`PolicyDecision`] it returns.
//!
//! The narrow surface is [`compile`] + [`evaluate_decision`]. Persistence and
//! priority-ordered orchestration layer on top in [`super::mod`].

use vti_common::error::AppError;
use vti_common::policy_engine;

pub use vti_common::policy_engine::POLICY_MODULE_PATH;

use super::types::{PolicyDecision, PolicyInput};

/// The rule the maintainer queries. Every policy module MUST define
/// `package vta.policy` and a `decision` rule; an undefined `decision`
/// (the rule didn't fire) reads as "this policy has no opinion".
pub const DECISION_QUERY: &str = "data.vta.policy.decision";

/// A Rego module that compiled cleanly and is ready to evaluate, stored under
/// the policy's string id.
pub type CompiledPolicy = policy_engine::CompiledPolicy<String>;

/// Compile Rego source into a [`CompiledPolicy`].
///
/// Returns [`AppError::Validation`] on parse failure so the upload handler
/// maps it straight to `malformedRequest`/400.
pub fn compile(rego_source: &str, id: &str) -> Result<CompiledPolicy, AppError> {
    policy_engine::compile(rego_source, id.to_string())
}

/// Evaluate one compiled policy's `decision` rule against a [`PolicyInput`].
///
/// Returns:
/// - `Ok(Some(decision))` — the policy's `decision` rule fired.
/// - `Ok(None)`           — the rule is undefined (this policy abstains).
/// - `Err(..)`            — a resource-budget abort or a genuine eval error.
///
/// The resource bounds are the shared engine's; both surface as
/// [`AppError::ResourceExhausted`] and the caller fails closed (deny).
pub fn evaluate_decision(
    compiled: &CompiledPolicy,
    input: &PolicyInput,
) -> Result<Option<PolicyDecision>, AppError> {
    let input_json = serde_json::to_value(input)?;
    let raw = policy_engine::evaluate(compiled, DECISION_QUERY, input_json)?;

    // QueryResults shape: { result: [ { expressions: [ { value: V } ] } ] }.
    // An undefined `decision` yields no result rows (or an empty object value):
    // treat both as "this policy abstains".
    let value = raw.pointer("/result/0/expressions/0/value");
    match value {
        None => Ok(None),
        Some(v)
            if v.is_null() || (v.is_object() && v.as_object().is_some_and(|m| m.is_empty())) =>
        {
            Ok(None)
        }
        Some(v) => {
            let decision: PolicyDecision = serde_json::from_value(v.clone()).map_err(|e| {
                AppError::Internal(format!(
                    "policy {} returned a decision that does not match PolicyDecision: {e}",
                    compiled.id()
                ))
            })?;
            Ok(Some(decision))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        Consumer, Discloses, Disposition, Exposure, PolicyRequest, SideEffectLevel,
    };

    fn input(side_effects: SideEffectLevel) -> PolicyInput {
        PolicyInput {
            request: PolicyRequest {
                type_uri: "https://trusttasks.org/spec/did-management/did/delete/0.1".into(),
                kind: None,
                subject: Some("did:webvh:abc".into()),
                payload_digest: None,
                side_effects,
                exposure: Exposure {
                    discloses: Discloses::None,
                    acts_as_subject: false,
                },
            },
            site: None,
            context_id: "ctx1".into(),
            consumer: Consumer {
                did: "did:key:zTest".into(),
                kind: None,
                device_id: None,
                last_user_verification_at: None,
                network_class: None,
                acr: None,
                amr: vec![],
            },
        }
    }

    #[test]
    fn compile_surfaces_parse_error() {
        let err = compile("package vta.policy\ndecision := {", "bad").unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn destructive_denied_by_a_simple_policy() {
        let src = r#"
            package vta.policy
            import rego.v1
            decision := {"decision": "deny", "explanation": "destructive tasks are blocked"} if {
                input.request.sideEffects == "destructive"
            }
        "#;
        let p = compile(src, "p1").unwrap();
        let d = evaluate_decision(&p, &input(SideEffectLevel::Destructive))
            .unwrap()
            .expect("decision rule should fire for a destructive task");
        assert_eq!(d.decision, Disposition::Deny);
    }

    #[test]
    fn abstains_when_rule_does_not_fire() {
        // Same policy, but a `none` task — the `if` guard fails, `decision`
        // is undefined, so this policy abstains (None).
        let src = r#"
            package vta.policy
            import rego.v1
            decision := {"decision": "deny"} if input.request.sideEffects == "destructive"
        "#;
        let p = compile(src, "p1").unwrap();
        let out = evaluate_decision(&p, &input(SideEffectLevel::None)).unwrap();
        assert!(out.is_none(), "non-matching policy must abstain, not deny");
    }
}
