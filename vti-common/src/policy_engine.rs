//! The bounded `regorus` (Rego) engine both services evaluate policy with.
//!
//! One [`CompiledPolicy`] per Rego module, cloned per evaluation (an `Arc`
//! bump under regorus's `arc` feature), and one [`evaluate`] that applies the
//! two resource bounds every evaluation needs. The VTA's `vta-policy` and the
//! VTC's `vtc-service::policy` used to carry a copy each (#2577); a tightening
//! or a regorus workaround applied to one copy silently skipped the other,
//! and the VTC's copy guards an unauthenticated path (join submit).
//!
//! What stays with each service is what a policy *means*: the VTA's
//! `PolicyInput` / `PolicyDecision` and its `data.vta.policy.decision` query,
//! the VTC's purposes, packages and verdicts. This module knows only Rego
//! source, a JSON input, a query and a JSON result.
//!
//! ## Engine module path
//!
//! `regorus::Engine::add_policy` takes a "path" string that becomes the
//! diagnostic filename in compile-error messages. It is fixed to
//! [`POLICY_MODULE_PATH`], so an engine only ever holds exactly one module.
//!
//! ## Resource bounds
//!
//! - **Input-size cap.** The serialized `input` is rejected up front if it
//!   exceeds [`MAX_POLICY_INPUT_BYTES`].
//! - **Evaluation time budget.** A regorus [`ExecutionTimerConfig`] interrupts
//!   evaluation once it exceeds [`POLICY_EVAL_TIME_LIMIT`].
//!
//! Both surface as [`AppError::ResourceExhausted`] — distinct from the
//! `Internal` policy-bug error so callers can fail closed (deny) rather than
//! 500. A `tokio::time::timeout` would *not* work: regorus evaluation is
//! synchronous and CPU-bound, so a timeout future cannot pre-empt it — it
//! would leak a wedged worker thread. Only the in-engine cooperative timer
//! actually stops the work.

use std::fmt;
use std::num::NonZeroU32;
use std::time::Duration;

use regorus::utils::limits::{ExecutionTimerConfig, LimitError};
use regorus::{Engine, Value as RegoValue};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use crate::error::AppError;

/// Wall-clock ceiling for a single policy evaluation.
///
/// The VTC's join-decision policy is evaluated on the **unauthenticated**
/// submit route against attacker-influenced facts (the VP and claim graph
/// flow into `input`). Without a bound, a pathological operator-uploaded
/// policy or an adversarial input shape burns CPU per request unbounded.
/// Real policies evaluate in microseconds, so the headroom is ~1000×, while a
/// runaway aborts fast enough that the per-IP governor keeps total cost
/// bounded.
pub const POLICY_EVAL_TIME_LIMIT: Duration = Duration::from_millis(250);

/// How many evaluation "work units" the timer accumulates between wall-clock
/// checks. Larger = lower per-unit overhead, smaller = tighter abort latency.
/// 1000 keeps the monotonic-clock reads cheap while still aborting a tight
/// loop within a few milliseconds of the ceiling.
pub const POLICY_EVAL_CHECK_INTERVAL: u32 = 1000;

/// Maximum serialized size of the `input` document handed to a policy.
///
/// Caps attacker-influenced input *before* evaluation so a large (but under
/// the 1 MB global body cap) document can't be amplified into an expensive
/// evaluation. 256 KiB is far above any legitimate input.
pub const MAX_POLICY_INPUT_BYTES: usize = 256 * 1024;

/// Module path used for the single Rego source in every compiled policy.
/// Surfaces in regorus's compile-error messages as `policy.rego:line:col`.
/// Not stable wire — operators only ever see it when an upload fails to
/// parse.
pub const POLICY_MODULE_PATH: &str = "policy.rego";

/// A Rego module that has compiled cleanly and is ready to evaluate.
///
/// Constructed exclusively via [`compile`]. Generic over the identifier the
/// service stores its policies under (a `Uuid` at the VTC, a `String` at the
/// VTA), which only ever appears in diagnostics and on [`Self::id`].
///
/// The compiled engine is `Send + Sync` (regorus `arc` feature), so this is
/// safe to share across tasks; eval-time cloning is the access pattern.
#[derive(Clone)]
pub struct CompiledPolicy<Id> {
    id: Id,
    source_sha256: [u8; 32],
    engine: Engine,
}

impl<Id: fmt::Debug> fmt::Debug for CompiledPolicy<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledPolicy")
            .field("id", &self.id)
            .field("source_sha256", &hex::encode(self.source_sha256))
            .finish_non_exhaustive()
    }
}

impl<Id> CompiledPolicy<Id> {
    /// The id this module was compiled under — the caller's `id` argument to
    /// [`compile`], for log and audit lines and to round-trip back to the
    /// stored row.
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// SHA-256 of the Rego source bytes — what audit records (never the
    /// source) and what an upload confirmation echoes. Stable across
    /// recompilations of byte-identical source.
    pub fn source_sha256(&self) -> &[u8; 32] {
        &self.source_sha256
    }
}

/// Compile a Rego source into a [`CompiledPolicy`].
///
/// Rego v1 syntax (`import rego.v1`) is the default — regorus is v1-first.
/// Returns [`AppError::Validation`] on parse failure, naming the policy, so
/// an upload maps it straight to a malformed request.
pub fn compile<Id: fmt::Display>(
    rego_source: &str,
    id: Id,
) -> Result<CompiledPolicy<Id>, AppError> {
    let mut engine = Engine::new();
    engine
        .add_policy(POLICY_MODULE_PATH.to_string(), rego_source.to_string())
        .map_err(|e| AppError::Validation(format!("rego compile failed for policy {id}: {e}")))?;
    let source_sha256: [u8; 32] = Sha256::digest(rego_source.as_bytes()).into();
    Ok(CompiledPolicy {
        id,
        source_sha256,
        engine,
    })
}

/// Evaluate a Rego `query` against the compiled module, given a JSON `input`,
/// within the module's resource bounds (see the module docs).
///
/// The returned value is regorus's `QueryResults` serialized to JSON — the
/// same shape as `opa eval`: `{ "result": [{ "expressions": [{ "value": V }] }] }`.
/// An undefined rule is **not** an error: it yields no result rows (or an
/// empty object value), and the caller decides what abstention means.
///
/// Returns [`AppError::ResourceExhausted`] when a bound trips and
/// [`AppError::Internal`] on any other evaluation failure (a malformed query,
/// a runtime error in the policy).
pub fn evaluate<Id: fmt::Display>(
    compiled: &CompiledPolicy<Id>,
    query: &str,
    input: JsonValue,
) -> Result<JsonValue, AppError> {
    // Cap the (possibly attacker-influenced) input before it reaches the
    // interpreter.
    let input_bytes = serde_json::to_vec(&input)?;
    if input_bytes.len() > MAX_POLICY_INPUT_BYTES {
        return Err(AppError::ResourceExhausted(format!(
            "policy input ({} bytes) exceeds the {MAX_POLICY_INPUT_BYTES}-byte cap",
            input_bytes.len()
        )));
    }

    let mut engine = compiled.engine.clone();
    // The bound applies to this evaluation's clone; set after cloning so it
    // holds regardless of whether the compiled engine carried a config.
    engine.set_execution_timer_config(ExecutionTimerConfig {
        limit: POLICY_EVAL_TIME_LIMIT,
        check_interval: NonZeroU32::new(POLICY_EVAL_CHECK_INTERVAL)
            .expect("POLICY_EVAL_CHECK_INTERVAL is non-zero"),
    });
    engine.set_input(RegoValue::from(input));

    let results = engine.eval_query(query.to_string(), false).map_err(|e| {
        // A time-budget abort is a resource bound, not a policy bug —
        // surface it as ResourceExhausted so the caller fails closed.
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
    serde_json::to_value(results).map_err(AppError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ALLOW_POLICY: &str = "\
package vtc.test

import rego.v1

default allow := false

allow if input.role == \"admin\"
";

    const DENY_POLICY: &str = "\
package vtc.test

import rego.v1

default allow := false

allow if {
    input.role == \"admin\"
    input.context == \"prod\"
}
";

    const TEST_ID: &str = "policy-under-test";

    /// Happy path: a syntactically valid Rego module compiles and the
    /// returned CompiledPolicy carries the caller's id + a matching SHA-256.
    #[test]
    fn compile_happy_path() {
        let compiled = compile(ALLOW_POLICY, TEST_ID).expect("compile should succeed");
        assert_eq!(*compiled.id(), TEST_ID);
        let expected: [u8; 32] = Sha256::digest(ALLOW_POLICY.as_bytes()).into();
        assert_eq!(compiled.source_sha256(), &expected);
    }

    /// Parse error: a malformed Rego source surfaces as `AppError::Validation`
    /// with a message naming the policy id.
    #[test]
    fn compile_surfaces_parse_error() {
        let err =
            compile("not valid rego @@@ }}}", TEST_ID).expect_err("malformed source must fail");
        match err {
            AppError::Validation(msg) => {
                assert!(
                    msg.contains(TEST_ID),
                    "error message should name the policy id: {msg}"
                );
                assert!(
                    msg.contains("rego compile failed"),
                    "error message should be a compile-failure: {msg}"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_allow_true() {
        let compiled = compile(ALLOW_POLICY, TEST_ID).unwrap();
        let result = evaluate(&compiled, "data.vtc.test.allow", json!({ "role": "admin" }))
            .expect("evaluate must succeed");
        assert_eq!(pluck_expression_value(&result), &json!(true));
    }

    #[test]
    fn evaluate_allow_false() {
        let compiled = compile(DENY_POLICY, TEST_ID).unwrap();
        let result = evaluate(
            &compiled,
            "data.vtc.test.allow",
            json!({ "role": "admin", "context": "staging" }),
        )
        .expect("evaluate must succeed");
        assert_eq!(pluck_expression_value(&result), &json!(false));
    }

    /// Missing-rule semantics: querying an undefined symbol does **not**
    /// error — the QueryResults shape comes back without a value. A
    /// syntactically malformed query is the genuine error path.
    #[test]
    fn evaluate_undefined_returns_empty_and_malformed_query_errors() {
        let compiled = compile(ALLOW_POLICY, TEST_ID).unwrap();

        let ok = evaluate(&compiled, "data.vtc.test.does_not_exist", json!({}))
            .expect("undefined symbols must not surface as an error");
        let value = ok.pointer("/result/0/expressions/0/value");
        assert!(
            value.is_none() || matches!(value, Some(JsonValue::Object(o)) if o.is_empty()),
            "undefined rule should yield no value, got {ok}"
        );

        let err = evaluate(&compiled, "@@@ not a query @@@", json!({}))
            .expect_err("malformed query must fail");
        match err {
            AppError::Internal(msg) => assert!(
                msg.contains("rego evaluation failed"),
                "error message should be an evaluation failure: {msg}"
            ),
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    /// Recompiling identical source yields the same hash; different source a
    /// different one.
    #[test]
    fn compile_sha_is_deterministic() {
        let a = compile(ALLOW_POLICY, "a").unwrap();
        let b = compile(ALLOW_POLICY, "b").unwrap();
        assert_eq!(a.source_sha256(), b.source_sha256());
        let c = compile(DENY_POLICY, "c").unwrap();
        assert_ne!(a.source_sha256(), c.source_sha256());
    }

    /// Input-size cap: an `input` whose serialized form exceeds
    /// [`MAX_POLICY_INPUT_BYTES`] is rejected before evaluation with
    /// `ResourceExhausted`, never handed to the interpreter.
    #[test]
    fn evaluate_rejects_oversized_input() {
        let compiled = compile(ALLOW_POLICY, TEST_ID).unwrap();
        let blob = "x".repeat(MAX_POLICY_INPUT_BYTES + 1);
        let err = evaluate(&compiled, "data.vtc.test.allow", json!({ "blob": blob }))
            .expect_err("oversized input must be rejected");
        assert!(
            matches!(err, AppError::ResourceExhausted(_)),
            "expected ResourceExhausted, got {err:?}"
        );

        let ok = evaluate(&compiled, "data.vtc.test.allow", json!({ "role": "admin" }))
            .expect("normal input must still evaluate");
        assert_eq!(pluck_expression_value(&ok), &json!(true));
    }

    /// Time budget: a policy that does pathological work is interrupted by
    /// the execution timer and surfaces as `ResourceExhausted` rather than
    /// hanging the evaluation unbounded.
    #[test]
    fn evaluate_aborts_runaway_policy() {
        // A doubly-nested comprehension over a 10k range is ~100M iterations
        // — orders of magnitude past the 250ms ceiling.
        const RUNAWAY: &str = "\
package vtc.test

import rego.v1

xs := numbers.range(1, 10000)

allow if {
    count([1 | some i in xs; some j in xs; i == j]) >= 0
}
";
        let compiled = compile(RUNAWAY, TEST_ID).unwrap();
        let err = evaluate(&compiled, "data.vtc.test.allow", json!({}))
            .expect_err("runaway policy must abort");
        assert!(
            matches!(err, AppError::ResourceExhausted(_)),
            "expected ResourceExhausted, got {err:?}"
        );
    }

    fn pluck_expression_value(results: &JsonValue) -> &JsonValue {
        results
            .pointer("/result/0/expressions/0/value")
            .expect("regorus QueryResults must carry result[0].expressions[0].value")
    }
}
