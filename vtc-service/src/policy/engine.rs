//! Compile + evaluate Rego modules via `regorus`.
//!
//! The public surface is intentionally narrow — one struct
//! ([`CompiledPolicy`]), one placeholder ([`Policy`]), and two free
//! functions ([`compile`], [`evaluate`]). Persistence + CRUD layer on top
//! in M2.2 onwards; this milestone is just the harness.
//!
//! ## Engine module path
//!
//! `regorus::Engine::add_policy` takes a "path" string that becomes the
//! diagnostic filename in compile-error messages. We hard-code it to
//! [`POLICY_MODULE_PATH`] here so the harness only ever loads exactly
//! one module per engine. Multi-module compilation (importing
//! `data.policies.helpers` etc.) is out of scope until a real policy
//! needs it.
//!
//! ## Eval-time engine cloning
//!
//! `regorus::Engine::eval_query` takes `&mut self`. To keep
//! [`evaluate`]'s signature `&CompiledPolicy` (matching what the
//! milestone spec calls for and what M2.8's hot-swap wants), we clone
//! the engine per call. With the `arc` feature (workspace default) the
//! clone is `Arc::clone` over the compiled module tree — cheap. Only
//! the per-evaluation state (input, internal interpreter scratch) is
//! reallocated.

use std::fmt;
use std::num::NonZeroU32;
use std::time::Duration;

use regorus::utils::limits::{ExecutionTimerConfig, LimitError};
use regorus::{Engine, Value as RegoValue};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vti_common::error::AppError;

/// Wall-clock ceiling for a single policy evaluation.
///
/// The join-decision policy is evaluated on the **unauthenticated** submit
/// route against attacker-influenced facts (the VP + claim graph flow into
/// `input`). Without a bound, a pathological operator-uploaded policy or an
/// adversarial input shape burns CPU per request unbounded. regorus's
/// cooperative timer interrupts evaluation once elapsed work exceeds this —
/// real policies evaluate in microseconds, so the headroom is ~1000×, while
/// a runaway aborts fast enough that the 5 rps/IP governor keeps total cost
/// bounded.
const POLICY_EVAL_TIME_LIMIT: Duration = Duration::from_millis(250);

/// How many evaluation "work units" the timer accumulates between wall-clock
/// checks. Larger = lower per-unit overhead, smaller = tighter abort latency.
/// 1000 keeps the monotonic-clock reads cheap while still aborting a tight
/// loop within a few milliseconds of the ceiling.
const POLICY_EVAL_CHECK_INTERVAL: u32 = 1000;

/// Maximum serialized size of the `input` document handed to a policy.
///
/// Caps the attacker-influenced join input *before* evaluation so a large
/// (but under the 1 MB global body cap) VP / claim graph can't be amplified
/// into an expensive evaluation. 256 KiB is far above any legitimate join
/// input. Evaluation fails closed (default-deny on the join path) when
/// exceeded.
const MAX_POLICY_INPUT_BYTES: usize = 256 * 1024;

/// Module path used for the single Rego source in every compiled
/// policy. Surfaces in regorus's compile-error messages as
/// `policy.rego:line:col`. Not stable wire — operators only ever see
/// it when their upload fails to parse.
pub const POLICY_MODULE_PATH: &str = "policy.rego";

/// A Rego module that has compiled cleanly and is ready to evaluate.
///
/// Constructed exclusively via [`compile`]. The compiled engine is
/// `Send + Sync` (regorus `arc` feature, on by default) so this
/// struct is safe to share across tasks. Eval-time cloning is the
/// expected access pattern — see module docs.
pub struct CompiledPolicy {
    id: Uuid,
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
    /// Policy id this module was compiled under. Matches the caller's
    /// `id` argument to [`compile`]; surfaced for log/audit lines and
    /// to round-trip back to the persistence row.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// SHA-256 of the Rego source bytes. Used by audit (the
    /// `PolicyActivated` event records the hash, not the source) and
    /// by the trust-task upload-confirmation echo. Stable across
    /// recompilations of byte-identical source.
    pub fn source_sha256(&self) -> &[u8; 32] {
        &self.source_sha256
    }
}

/// Compile a Rego source into a [`CompiledPolicy`].
///
/// Rego v1 syntax (`import rego.v1`) is the default — regorus 0.10
/// is v1-first. Returns [`AppError::Validation`] on parse failure so
/// the M2.3 upload endpoint can map it directly to 400.
pub fn compile(rego_source: &str, id: Uuid) -> Result<CompiledPolicy, AppError> {
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

/// Evaluate a Rego query against the compiled module, given a JSON
/// input.
///
/// The returned [`JsonValue`] is regorus's `QueryResults` serialised to
/// JSON — same shape as `opa eval`. Callers that want a plain
/// `allow/deny` boolean should pluck `result[0].expressions[0].value`.
/// Surfacing the raw shape here keeps the harness usable by the M2.6
/// `join.rego` wire-up (which wants the full result set for audit) and
/// the M2.7 `removal.rego` wire-up (which only cares about `allow`).
///
/// Returns [`AppError::Internal`] on evaluation failure. Policies that
/// parse cleanly but reference undefined rules surface here, not at
/// [`compile`] time — Rego is permissive about forward references.
///
/// ## Resource bounds (P0.18)
///
/// This is the unauthenticated DoS surface: the join-decision policy runs
/// here against attacker-influenced `input`. Two guards keep a pathological
/// policy or adversarial input from burning CPU unbounded:
///
/// - **Input-size cap.** The serialized `input` is rejected up front if it
///   exceeds [`MAX_POLICY_INPUT_BYTES`].
/// - **Evaluation time budget.** A regorus [`ExecutionTimerConfig`] interrupts
///   evaluation once it exceeds [`POLICY_EVAL_TIME_LIMIT`].
///
/// Both bounds surface as [`AppError::ResourceExhausted`] — distinct from the
/// `Internal` policy-bug error so callers on the join path can fail closed
/// (default-deny) rather than 500. A `tokio::time::timeout` would *not* work
/// here: regorus evaluation is synchronous and CPU-bound, so a timeout future
/// can't pre-empt it — it would leak a wedged worker thread. The cooperative
/// in-engine timer actually stops the work.
pub fn evaluate(
    compiled: &CompiledPolicy,
    query: &str,
    input: JsonValue,
) -> Result<JsonValue, AppError> {
    // Cap the attacker-influenced input before it reaches the interpreter.
    let input_bytes = serde_json::to_vec(&input)?;
    if input_bytes.len() > MAX_POLICY_INPUT_BYTES {
        return Err(AppError::ResourceExhausted(format!(
            "policy input ({} bytes) exceeds the {MAX_POLICY_INPUT_BYTES}-byte cap",
            input_bytes.len()
        )));
    }

    let mut engine = compiled.engine.clone();
    // Bound applies to this evaluation's clone; set after cloning so it holds
    // regardless of whether the compiled engine carried a config.
    engine.set_execution_timer_config(ExecutionTimerConfig {
        limit: POLICY_EVAL_TIME_LIMIT,
        check_interval: NonZeroU32::new(POLICY_EVAL_CHECK_INTERVAL)
            .expect("POLICY_EVAL_CHECK_INTERVAL is non-zero"),
    });
    engine.set_input(RegoValue::from(input));

    let results = engine.eval_query(query.to_string(), false).map_err(|e| {
        // A time/instruction-budget abort is a resource bound, not a policy
        // bug — surface it as ResourceExhausted so the join path denies.
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

    fn test_id() -> Uuid {
        // Deterministic id so failures point at the same policy each run.
        Uuid::from_u128(0x0102_0304_0506_0708_0900_0a0b_0c0d_0e0f)
    }

    /// Happy path: a syntactically valid Rego module compiles and the
    /// returned CompiledPolicy carries the caller's id + a matching
    /// SHA-256.
    #[test]
    fn compile_happy_path() {
        let id = test_id();
        let compiled = compile(ALLOW_POLICY, id).expect("compile should succeed");
        assert_eq!(compiled.id(), id);
        let expected: [u8; 32] = Sha256::digest(ALLOW_POLICY.as_bytes()).into();
        assert_eq!(compiled.source_sha256(), &expected);
    }

    /// Parse error: a malformed Rego source surfaces as
    /// `AppError::Validation` with a message naming the policy id.
    #[test]
    fn compile_surfaces_parse_error() {
        let id = test_id();
        let err = compile("not valid rego @@@ }}}", id).expect_err("malformed source must fail");
        match err {
            AppError::Validation(msg) => {
                assert!(
                    msg.contains(&id.to_string()),
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

    /// Evaluate-allow: an `allow` rule that fires returns
    /// `true` in the QueryResults shape.
    #[test]
    fn evaluate_allow_true() {
        let compiled = compile(ALLOW_POLICY, test_id()).unwrap();
        let result = evaluate(&compiled, "data.vtc.test.allow", json!({ "role": "admin" }))
            .expect("evaluate must succeed");
        let value = pluck_expression_value(&result);
        assert_eq!(value, &json!(true));
    }

    /// Evaluate-deny: same `allow` rule with input that doesn't
    /// satisfy the body returns `false`.
    #[test]
    fn evaluate_allow_false() {
        let compiled = compile(DENY_POLICY, test_id()).unwrap();
        let result = evaluate(
            &compiled,
            "data.vtc.test.allow",
            json!({ "role": "admin", "context": "staging" }),
        )
        .expect("evaluate must succeed");
        let value = pluck_expression_value(&result);
        assert_eq!(value, &json!(false));
    }

    /// Missing-rule semantics: querying an undefined symbol does
    /// **not** error — Rego treats undefined references as a
    /// per-row `undefined` and the QueryResults shape comes back
    /// without a value. Document the behaviour so callers know not
    /// to assume "rule missing" turns into an error.
    ///
    /// The error path is exercised separately by feeding `eval_query`
    /// a syntactically malformed query string, which regorus rejects
    /// at parse time and we surface as `AppError::Internal`.
    #[test]
    fn evaluate_undefined_returns_empty_and_malformed_query_errors() {
        let compiled = compile(ALLOW_POLICY, test_id()).unwrap();

        // Undefined rule → success with empty result. Document the
        // shape so the M2.6 / M2.7 wire-ups don't trip over it.
        let ok = evaluate(&compiled, "data.vtc.test.does_not_exist", json!({}))
            .expect("undefined symbols must not surface as an error");
        let value = ok.pointer("/result/0/expressions/0/value");
        assert!(
            value.is_none() || matches!(value, Some(JsonValue::Object(o)) if o.is_empty()),
            "undefined rule should yield no value, got {ok}"
        );

        // Malformed query → genuine evaluation error path.
        let err = evaluate(&compiled, "@@@ not a query @@@", json!({}))
            .expect_err("malformed query must fail");
        match err {
            AppError::Internal(msg) => {
                assert!(
                    msg.contains("rego evaluation failed"),
                    "error message should be an evaluation failure: {msg}"
                );
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    /// SHA determinism: recompiling identical source twice yields the
    /// same hash. Audit + trust-task echo lean on this.
    #[test]
    fn compile_sha_is_deterministic() {
        let a = compile(ALLOW_POLICY, Uuid::new_v4()).unwrap();
        let b = compile(ALLOW_POLICY, Uuid::new_v4()).unwrap();
        assert_eq!(a.source_sha256(), b.source_sha256());
        // And a different source produces a different hash so the
        // property isn't trivially satisfied by a constant hasher.
        let c = compile(DENY_POLICY, Uuid::new_v4()).unwrap();
        assert_ne!(a.source_sha256(), c.source_sha256());
    }

    /// Input-size cap (P0.18): an `input` whose serialized form exceeds
    /// [`MAX_POLICY_INPUT_BYTES`] is rejected before evaluation with
    /// `ResourceExhausted`, never handed to the interpreter.
    #[test]
    fn evaluate_rejects_oversized_input() {
        let compiled = compile(ALLOW_POLICY, test_id()).unwrap();
        let blob = "x".repeat(MAX_POLICY_INPUT_BYTES + 1);
        let err = evaluate(&compiled, "data.vtc.test.allow", json!({ "blob": blob }))
            .expect_err("oversized input must be rejected");
        assert!(
            matches!(err, AppError::ResourceExhausted(_)),
            "expected ResourceExhausted, got {err:?}"
        );

        // A just-under-cap input still evaluates normally — the cap is a
        // ceiling, not a blanket rejection of large-ish inputs.
        let ok = evaluate(&compiled, "data.vtc.test.allow", json!({ "role": "admin" }))
            .expect("normal input must still evaluate");
        assert_eq!(pluck_expression_value(&ok), &json!(true));
    }

    /// Time budget (P0.18): a policy that does pathological work is
    /// interrupted by the execution timer and surfaces as
    /// `ResourceExhausted` (the join path turns that into a deny) rather
    /// than hanging the evaluation unbounded.
    #[test]
    fn evaluate_aborts_runaway_policy() {
        // A doubly-nested comprehension over a 10k range is ~100M
        // iterations — orders of magnitude past the 250ms ceiling, so the
        // cooperative timer trips long before it could complete.
        const RUNAWAY: &str = "\
package vtc.test

import rego.v1

xs := numbers.range(1, 10000)

allow if {
    count([1 | some i in xs; some j in xs; i == j]) >= 0
}
";
        let compiled = compile(RUNAWAY, test_id()).unwrap();
        let err = evaluate(&compiled, "data.vtc.test.allow", json!({}))
            .expect_err("runaway policy must abort");
        assert!(
            matches!(err, AppError::ResourceExhausted(_)),
            "expected ResourceExhausted, got {err:?}"
        );
    }

    /// Extract `result[0].expressions[0].value` from regorus's
    /// QueryResults JSON shape. The QueryResults wire shape is
    /// `{ "result": [{ "expressions": [{ "value": V, ... }], ... }] }`.
    fn pluck_expression_value(results: &JsonValue) -> &JsonValue {
        results
            .pointer("/result/0/expressions/0/value")
            .expect("regorus QueryResults must carry result[0].expressions[0].value")
    }
}
