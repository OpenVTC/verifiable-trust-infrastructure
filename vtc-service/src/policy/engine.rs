//! Compile + evaluate Rego modules — the VTC's use of the shared bounded
//! engine.
//!
//! Compiling, evaluating and the two resource bounds (an input-size cap and a
//! CPU-time budget) are [`vti_common::policy_engine`]'s, shared with the VTA
//! (#2577): the join-decision policy runs on the **unauthenticated** submit
//! route against attacker-influenced `input`, and a bound tightened in one
//! copy used to skip the other. See that module for the bounds and for why
//! only the in-engine timer, not a `tokio::time::timeout`, stops a runaway.
//!
//! What stays here is the VTC's: policies stored under a [`Uuid`], and
//! [`validate_purpose_package`], which knows the purposes and their packages.
//! Callers keep naming `crate::policy::engine::{compile, evaluate,
//! CompiledPolicy}`.

use serde_json::Value as JsonValue;
use uuid::Uuid;
use vti_common::error::AppError;
use vti_common::policy_engine;

pub use vti_common::policy_engine::{POLICY_MODULE_PATH, evaluate};

use super::model::PolicyPurpose;

/// A Rego module that has compiled cleanly and is ready to evaluate, stored
/// under the policy's `Uuid`.
pub type CompiledPolicy = policy_engine::CompiledPolicy<Uuid>;

/// Compile a Rego source into a [`CompiledPolicy`].
///
/// Returns [`AppError::Validation`] on parse failure so the upload endpoint
/// can map it directly to 400.
pub fn compile(rego_source: &str, id: Uuid) -> Result<CompiledPolicy, AppError> {
    policy_engine::compile(rego_source, id)
}

/// Reject an uploaded/activated policy whose Rego package doesn't match
/// its declared `purpose`.
///
/// For the four ceremony purposes the decision pipeline probes a fixed
/// package (`data.<pkg>.decision`); a module compiled into the *wrong*
/// package — or one that defines neither a four-valued `decision`
/// verdict nor a boolean `allow` — evaluates to `undefined` at decision
/// time, which the host reads as a silent default-deny for that whole
/// ceremony. The operator sees a clean upload + activate and a
/// community that quietly denies everything. Catch it by probing the
/// expected package against a trivial input.
///
/// Purposes with no single pinned decision package
/// ([`PolicyPurpose::expected_package`] → `None`: registry, personhood,
/// …) are not package-validated here.
pub fn validate_purpose_package(
    compiled: &CompiledPolicy,
    purpose: PolicyPurpose,
) -> Result<(), AppError> {
    let Some(pkg) = purpose.expected_package() else {
        return Ok(());
    };
    if yields_decision_or_allow(compiled, pkg) {
        return Ok(());
    }
    Err(AppError::Validation(format!(
        "policy declares purpose `{p}` but yields no decision in package `{pkg}` for a \
         trivial input — it must define a `decision` rule (or a boolean `allow`) under \
         `package {pkg}`. A module in the wrong package compiles cleanly but silently \
         denies every `{p}` request.",
        p = purpose.as_str(),
    )))
}

/// True when the policy yields either a four-valued `decision` verdict
/// (the pipeline shape) or a boolean `allow` (legacy / default-deny) in
/// `pkg` for an empty input. An undefined rule (wrong package, or no
/// default) yields neither.
fn yields_decision_or_allow(compiled: &CompiledPolicy, pkg: &str) -> bool {
    let empty = JsonValue::Object(serde_json::Map::new());
    if let Ok(r) = evaluate(compiled, &format!("data.{pkg}.decision"), empty.clone())
        && r.pointer("/result/0/expressions/0/value")
            .and_then(|v| v.get("effect"))
            .and_then(JsonValue::as_str)
            .is_some()
    {
        return true;
    }
    if let Ok(r) = evaluate(compiled, &format!("data.{pkg}.allow"), empty)
        && r.pointer("/result/0/expressions/0/value")
            .and_then(JsonValue::as_bool)
            .is_some()
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_id() -> Uuid {
        // Deterministic id so failures point at the same policy each run.
        Uuid::from_u128(0x0102_0304_0506_0708_0900_0a0b_0c0d_0e0f)
    }

    /// The VTC's policies are stored under a `Uuid`, and the compiled module
    /// carries it back. The engine's own behaviour (bounds, errors, hashing)
    /// is tested once, in `vti_common::policy_engine`.
    #[test]
    fn compile_carries_the_policy_uuid() {
        let id = test_id();
        let compiled = compile(
            "package vtc.test\nimport rego.v1\ndefault allow := false\n",
            id,
        )
        .expect("compile should succeed");
        assert_eq!(*compiled.id(), id);
    }

    // ---- validate_purpose_package (P1.5) ----

    #[test]
    fn validate_purpose_package_accepts_boolean_allow_in_right_package() {
        let src = "package vtc.join\nimport rego.v1\ndefault allow := false\n";
        let c = compile(src, test_id()).unwrap();
        assert!(validate_purpose_package(&c, PolicyPurpose::Join).is_ok());
    }

    #[test]
    fn validate_purpose_package_accepts_decision_rule_in_right_package() {
        let src = "package vtc.directory\nimport rego.v1\n\
                   default decision := {\"effect\": \"deny\"}\n";
        let c = compile(src, test_id()).unwrap();
        assert!(validate_purpose_package(&c, PolicyPurpose::Directory).is_ok());
    }

    #[test]
    fn validate_purpose_package_rejects_wrong_package() {
        // A join policy compiled into vtc.removal yields nothing at
        // data.vtc.join.{decision,allow} → silent default-deny footgun.
        let src = "package vtc.removal\nimport rego.v1\ndefault allow := false\n";
        let c = compile(src, test_id()).unwrap();
        let err = validate_purpose_package(&c, PolicyPurpose::Join).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(
                msg.contains("vtc.join"),
                "error must name the expected package: {msg}"
            ),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validate_purpose_package_rejects_missing_default_rule() {
        // Right package but no `default` — undefined for empty input,
        // which is the same silent-deny shape we reject.
        let src = "package vtc.join\nimport rego.v1\nallow if input.role == \"admin\"\n";
        let c = compile(src, test_id()).unwrap();
        assert!(validate_purpose_package(&c, PolicyPurpose::Join).is_err());
    }

    #[test]
    fn validate_purpose_package_skips_unpinned_purposes() {
        // Registry has no expected_package → never package-validated.
        let src = "package whatever\nimport rego.v1\ndefault publish_on_join := true\n";
        let c = compile(src, test_id()).unwrap();
        assert!(validate_purpose_package(&c, PolicyPurpose::Registry).is_ok());
    }
}
