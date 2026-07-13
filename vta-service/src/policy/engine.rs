//! Compile + evaluate Rego modules via `regorus`.
//!
//! Adapted from `vtc-service/src/policy/engine.rs` — the same proven pattern:
//! one [`CompiledPolicy`] per Rego module, cloned per evaluation (cheap under
//! the `arc` feature), with an input-size cap and a CPU-time budget so a
//! pathological policy or adversarial input can't burn CPU unbounded.
//!
//! The narrow surface is [`compile`] + [`evaluate_decision`]. Persistence and
//! priority-ordered orchestration layer on top in [`super::mod`].

use std::fmt;
use std::num::NonZeroU32;
use std::time::Duration;

use regorus::utils::limits::{ExecutionTimerConfig, LimitError};
use regorus::{Engine, Value as RegoValue};
use sha2::{Digest, Sha256};
use vti_common::error::AppError;

use super::types::{PolicyDecision, PolicyInput};

/// Wall-clock ceiling for a single policy evaluation. Real policies evaluate
/// in microseconds; the headroom is enormous while a runaway aborts fast.
const POLICY_EVAL_TIME_LIMIT: Duration = Duration::from_millis(250);

/// Evaluation "work units" between wall-clock checks — cheap monotonic reads
/// while still aborting a tight loop within a few ms of the ceiling.
const POLICY_EVAL_CHECK_INTERVAL: u32 = 1000;

/// Maximum serialized size of the `input` handed to a policy. Far above any
/// legitimate PolicyInput; evaluation fails closed (deny) when exceeded.
const MAX_POLICY_INPUT_BYTES: usize = 256 * 1024;

/// Diagnostic module path — surfaces in regorus compile-error messages as
/// `policy.rego:line:col`. Operators only ever see it on a parse failure.
pub const POLICY_MODULE_PATH: &str = "policy.rego";

/// The rule the maintainer queries. Every policy module MUST define
/// `package vta.policy` and a `decision` rule; an undefined `decision`
/// (the rule didn't fire) reads as "this policy has no opinion".
pub const DECISION_QUERY: &str = "data.vta.policy.decision";

/// A Rego module that compiled cleanly and is ready to evaluate.
///
/// `Engine` is `Send + Sync` (regorus `arc` feature) so this is shareable
/// across tasks; eval-time cloning is the expected access pattern.
#[derive(Clone)]
pub struct CompiledPolicy {
    id: String,
    source_sha256: [u8; 32],
    engine: Engine,
}

impl fmt::Debug for CompiledPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledPolicy")
            .field("id", &self.id)
            .field("source_sha256", &hex::encode(self.source_sha256))
            .finish_non_exhaustive()
    }
}

impl CompiledPolicy {
    pub fn id(&self) -> &str {
        &self.id
    }

    /// SHA-256 of the Rego source bytes — recorded in audit and echoed on
    /// upload confirmation. Stable across recompiles of identical source.
    pub fn source_sha256(&self) -> &[u8; 32] {
        &self.source_sha256
    }
}

/// Compile Rego source into a [`CompiledPolicy`].
///
/// Rego v1 (`import rego.v1`) is the default — regorus 0.10 is v1-first.
/// Returns [`AppError::Validation`] on parse failure so the upload handler
/// maps it straight to `malformedRequest`/400.
pub fn compile(rego_source: &str, id: &str) -> Result<CompiledPolicy, AppError> {
    let mut engine = Engine::new();
    engine
        .add_policy(POLICY_MODULE_PATH.to_string(), rego_source.to_string())
        .map_err(|e| AppError::Validation(format!("rego compile failed for policy {id}: {e}")))?;
    let source_sha256: [u8; 32] = Sha256::digest(rego_source.as_bytes()).into();
    Ok(CompiledPolicy {
        id: id.to_string(),
        source_sha256,
        engine,
    })
}

/// Evaluate one compiled policy's `decision` rule against a [`PolicyInput`].
///
/// Returns:
/// - `Ok(Some(decision))` — the policy's `decision` rule fired.
/// - `Ok(None)`           — the rule is undefined (this policy abstains).
/// - `Err(..)`            — a resource-budget abort or a genuine eval error.
///
/// Resource bounds: the input is size-capped before it reaches the interpreter,
/// and a regorus [`ExecutionTimerConfig`] interrupts a runaway. Both surface as
/// [`AppError::ResourceExhausted`]; the caller fails closed (deny). A
/// `tokio::time::timeout` would NOT work — regorus is synchronous and CPU-bound,
/// so only the in-engine cooperative timer actually stops the work.
pub fn evaluate_decision(
    compiled: &CompiledPolicy,
    input: &PolicyInput,
) -> Result<Option<PolicyDecision>, AppError> {
    let input_json = serde_json::to_value(input)?;
    let input_bytes = serde_json::to_vec(&input_json)?;
    if input_bytes.len() > MAX_POLICY_INPUT_BYTES {
        return Err(AppError::ResourceExhausted(format!(
            "policy input ({} bytes) exceeds the {MAX_POLICY_INPUT_BYTES}-byte cap",
            input_bytes.len()
        )));
    }

    // Clone so evaluate() keeps a `&CompiledPolicy` signature; under `arc` the
    // clone is an Arc bump of the compiled module tree.
    let mut engine = compiled.engine.clone();
    engine.set_execution_timer_config(ExecutionTimerConfig {
        limit: POLICY_EVAL_TIME_LIMIT,
        check_interval: NonZeroU32::new(POLICY_EVAL_CHECK_INTERVAL)
            .expect("POLICY_EVAL_CHECK_INTERVAL is non-zero"),
    });
    engine.set_input(RegoValue::from(input_json));

    let results = engine
        .eval_query(DECISION_QUERY.to_string(), false)
        .map_err(|e| {
            if e.downcast_ref::<LimitError>().is_some() {
                AppError::ResourceExhausted(format!(
                    "policy {} evaluation exceeded its resource budget",
                    compiled.id
                ))
            } else {
                AppError::Internal(format!(
                    "rego evaluation failed for policy {}: {e}",
                    compiled.id
                ))
            }
        })?;

    // QueryResults shape: { result: [ { expressions: [ { value: V } ] } ] }.
    // An undefined `decision` yields no result rows (or an empty object value):
    // treat both as "this policy abstains".
    let raw = serde_json::to_value(results)?;
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
                    compiled.id
                ))
            })?;
            Ok(Some(decision))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::types::{
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
