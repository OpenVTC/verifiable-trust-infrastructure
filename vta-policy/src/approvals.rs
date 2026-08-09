//! Server half of the declarative approvals model.
//!
//! The model itself — [`ApprovalRule`], the approver sets, and the Rego
//! synthesizer — lives in `vta_sdk::approvals` so the CLI and the VTA derive
//! from one implementation. This module is what the VTA adds on top: reading
//! the reserved policy row, checking a submitted row against the rules it
//! claims to encode, and building the row when seeding a fresh install.
//!
//! # The byte-compare
//!
//! Canonical `policy/upsert` treats `module` as client-authored and
//! authoritative, so the VTA must not synthesize over what a caller sent. It
//! instead re-derives the module from `ext["openvtc.approvals"]` and rejects the
//! write unless the two are byte-identical ([`verify_declarative_row`]).
//!
//! The alternative — trusting `module` and treating `ext` as decoration — would
//! mean the rules an operator reads back through `pnm approvals list` need not
//! describe the Rego that actually decides. This check is what makes the
//! declarative view *true* rather than advisory.

use vta_sdk::approvals::{
    ApprovalRule, ApprovalsError, ApproverSets, DECLARATIVE_POLICY_ID, DECLARATIVE_POLICY_NAME,
    DECLARATIVE_POLICY_PRIORITY, EXT_KEY_APPROVER_SETS, EXT_KEY_RULES, synthesize_rego, validate,
};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::storage;
use super::types::PolicyModule;

/// The declarative approvals model as stored on the reserved policy row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeclarativeModel {
    pub rules: Vec<ApprovalRule>,
    pub approver_sets: ApproverSets,
}

impl DeclarativeModel {
    /// The rule governing `type_uri` in `context_id`, if any.
    ///
    /// A context-scoped rule wins over an unscoped one for the same task type;
    /// [`vta_sdk::approvals::validate`] guarantees at most one of each can
    /// match, so this cannot be ambiguous.
    pub fn rule_for(&self, type_uri: &str, context_id: &str) -> Option<&ApprovalRule> {
        let mut unscoped = None;
        for rule in &self.rules {
            if rule.task_type != type_uri {
                continue;
            }
            if rule.contexts.is_empty() {
                unscoped = Some(rule);
            } else if rule.contexts.iter().any(|c| c == context_id) {
                return Some(rule);
            }
        }
        unscoped
    }

    /// Members of a named approver set. Absent or empty both read as "nobody",
    /// which the gate treats as fail-closed.
    pub fn approver_set(&self, name: &str) -> &[String] {
        self.approver_sets.get(name).map_or(&[], Vec::as_slice)
    }
}

fn ext_field<T: serde::de::DeserializeOwned + Default>(
    ext: &serde_json::Value,
    key: &str,
) -> Result<T, AppError> {
    match ext.get(key) {
        None | Some(serde_json::Value::Null) => Ok(T::default()),
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| {
            AppError::Validation(format!(
                "policy ext[\"{key}\"] is not the expected shape: {e}"
            ))
        }),
    }
}

/// Whether `ext` marks a row as carrying the declarative model.
///
/// Keyed on the rules member alone: a row with approver sets but no rules is
/// still declarative (an operator staging sets before the rules that use them).
pub fn is_declarative(ext: &serde_json::Value) -> bool {
    ext.get(EXT_KEY_RULES).is_some_and(|v| !v.is_null())
}

/// Parse the declarative model out of a row's `ext`.
pub fn model_from_ext(ext: &serde_json::Value) -> Result<DeclarativeModel, AppError> {
    Ok(DeclarativeModel {
        rules: ext_field(ext, EXT_KEY_RULES)?,
        approver_sets: ext_field(ext, EXT_KEY_APPROVER_SETS)?,
    })
}

/// Render a model back into the `ext` object a policy row carries.
pub fn model_to_ext(model: &DeclarativeModel) -> serde_json::Value {
    serde_json::json!({
        EXT_KEY_RULES: model.rules,
        EXT_KEY_APPROVER_SETS: model.approver_sets,
    })
}

fn map_validation(e: ApprovalsError) -> AppError {
    AppError::Validation(e.to_string())
}

/// Validate a submitted declarative row: the rules must be coherent, and
/// `module` must be exactly what those rules synthesize to.
///
/// Returns the parsed model so the caller does not deserialize twice.
pub fn verify_declarative_row(
    ext: &serde_json::Value,
    module: &str,
) -> Result<DeclarativeModel, AppError> {
    let model = model_from_ext(ext)?;
    validate(&model.rules, &model.approver_sets).map_err(map_validation)?;

    let expected = synthesize_rego(&model.rules);
    if module != expected {
        return Err(AppError::Validation(format!(
            "the submitted `module` is not what ext[\"{EXT_KEY_RULES}\"] synthesizes to, so the \
             rules would not describe the policy that decides. Regenerate it from the rules \
             (the CLI does this for you) rather than editing the Rego by hand. Expected {} \
             bytes, got {}.",
            expected.len(),
            module.len(),
        )));
    }
    Ok(model)
}

/// Build the reserved policy row for `model`.
///
/// `version` is the caller's business (an upsert increments; a seed starts at
/// 1), as are the timestamps — this crate takes no clock.
pub fn declarative_row(
    model: &DeclarativeModel,
    version: u64,
    now_rfc3339: &str,
    created_at: &str,
) -> PolicyModule {
    PolicyModule {
        id: DECLARATIVE_POLICY_ID.to_string(),
        name: DECLARATIVE_POLICY_NAME.to_string(),
        description: Some(
            "Declarative approval rules (which tasks need re-authentication or consent). \
             Managed with `pnm approvals`; the Rego module is derived from the rules and \
             verified on write."
                .to_string(),
        ),
        module: synthesize_rego(&model.rules),
        applies_to: Vec::new(),
        priority: DECLARATIVE_POLICY_PRIORITY,
        enabled: true,
        version,
        created_at: created_at.to_string(),
        updated_at: now_rfc3339.to_string(),
        ext: model_to_ext(model),
    }
}

/// Read the declarative model from the policy keyspace.
///
/// A missing row is an empty model, not an error: a VTA that has never had an
/// approval rule gates nothing, which is the shipping default.
pub async fn load(policy_ks: &KeyspaceHandle) -> Result<DeclarativeModel, AppError> {
    match storage::get_policy(policy_ks, DECLARATIVE_POLICY_ID).await? {
        Some(row) => model_from_ext(&row.ext),
        None => Ok(DeclarativeModel::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine;
    use crate::types::{
        Consumer, Discloses, Disposition, Exposure, PolicyInput, PolicyRequest, SideEffectLevel,
    };
    use vta_sdk::approvals::Requires;

    const ACL_GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
    const WEBVH_UPDATE: &str = "https://trusttasks.org/spec/vta/webvh/dids/update/1.0";

    fn model(rules: Vec<ApprovalRule>, sets: &[(&str, &[&str])]) -> DeclarativeModel {
        DeclarativeModel {
            rules,
            approver_sets: sets
                .iter()
                .map(|(k, v)| {
                    (
                        k.to_string(),
                        v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                    )
                })
                .collect(),
        }
    }

    fn input(type_uri: &str, context_id: &str) -> PolicyInput {
        PolicyInput {
            request: PolicyRequest {
                type_uri: type_uri.to_string(),
                kind: None,
                subject: None,
                payload_digest: None,
                side_effects: SideEffectLevel::Mutating,
                exposure: Exposure {
                    discloses: Discloses::None,
                    acts_as_subject: false,
                },
            },
            site: None,
            context_id: context_id.to_string(),
            consumer: Consumer {
                did: "did:key:zRequester".to_string(),
                kind: None,
                device_id: None,
                last_user_verification_at: None,
                network_class: None,
                acr: Some("aal1".to_string()),
                amr: vec!["did".to_string()],
            },
        }
    }

    /// The whole design rests on the synthesized module being valid Rego. A
    /// generator that emits text regorus rejects would fail closed at the gate
    /// (a policy that won't compile is skipped), silently un-gating every task
    /// it named — so this compiles AND evaluates.
    #[test]
    fn synthesized_module_compiles_and_decides() {
        let mut consent = ApprovalRule::consent(WEBVH_UPDATE, "ops");
        consent.min_approvals = Some(2);
        consent.exclude_requester = Some(true);
        let m = model(
            vec![ApprovalRule::reauth(ACL_GRANT), consent],
            &[("ops", &["did:key:zA", "did:key:zB"])],
        );

        let compiled = engine::compile(&synthesize_rego(&m.rules), "test")
            .expect("synthesized module must compile");

        let d = engine::evaluate_decision(&compiled, &input(ACL_GRANT, "ctx"))
            .unwrap()
            .expect("reauth rule must fire");
        assert_eq!(d.decision, Disposition::RequireStepUp);

        let d = engine::evaluate_decision(&compiled, &input(WEBVH_UPDATE, "ctx"))
            .unwrap()
            .expect("consent rule must fire");
        assert_eq!(d.decision, Disposition::RequireConsent);
        let rc = d.require_consent.expect("requireConsent carrier");
        assert_eq!(rc.approver_set, "ops");
        assert_eq!(rc.min_approvals, 2);
        assert!(rc.exclude_requester);

        // A task the model does not name: the module abstains so the baseline
        // underneath decides.
        assert!(
            engine::evaluate_decision(
                &compiled,
                &input("https://trusttasks.org/spec/acl/list/0.1", "ctx")
            )
            .unwrap()
            .is_none()
        );
    }

    /// Context scoping must actually scope — a rule bound to `openvtc` must not
    /// gate the same task in another context.
    #[test]
    fn context_scoped_rules_compile_and_only_fire_in_scope() {
        let mut scoped = ApprovalRule::reauth(ACL_GRANT);
        scoped.contexts = vec!["openvtc".into(), "other".into()];
        let m = model(vec![scoped], &[]);
        let compiled = engine::compile(&synthesize_rego(&m.rules), "test").unwrap();

        for ctx in ["openvtc", "other"] {
            assert!(
                engine::evaluate_decision(&compiled, &input(ACL_GRANT, ctx))
                    .unwrap()
                    .is_some(),
                "rule should fire in {ctx}"
            );
        }
        assert!(
            engine::evaluate_decision(&compiled, &input(ACL_GRANT, "elsewhere"))
                .unwrap()
                .is_none()
        );
    }

    /// Two disjoint scoped rules for one task type are legal, and each must
    /// compile into a module whose complete rules never both fire.
    #[test]
    fn disjoint_scoped_rules_do_not_conflict_at_eval() {
        let mut a = ApprovalRule::reauth(ACL_GRANT);
        a.contexts = vec!["x".into()];
        let mut b = ApprovalRule::consent(ACL_GRANT, "ops");
        b.contexts = vec!["y".into()];
        let m = model(vec![a, b], &[("ops", &["did:key:zA"])]);
        let compiled = engine::compile(&synthesize_rego(&m.rules), "test").unwrap();

        assert_eq!(
            engine::evaluate_decision(&compiled, &input(ACL_GRANT, "x"))
                .unwrap()
                .unwrap()
                .decision,
            Disposition::RequireStepUp
        );
        assert_eq!(
            engine::evaluate_decision(&compiled, &input(ACL_GRANT, "y"))
                .unwrap()
                .unwrap()
                .decision,
            Disposition::RequireConsent
        );
    }

    #[test]
    fn a_matching_row_verifies_and_round_trips() {
        let m = model(vec![ApprovalRule::reauth(ACL_GRANT)], &[]);
        let row = declarative_row(&m, 1, "2026-08-09T00:00:00Z", "2026-08-09T00:00:00Z");
        assert!(is_declarative(&row.ext));
        assert_eq!(verify_declarative_row(&row.ext, &row.module).unwrap(), m);
    }

    /// The defect this check exists to stop: rules that say one thing, Rego
    /// that does another.
    #[test]
    fn a_row_whose_module_does_not_match_its_rules_is_refused() {
        let m = model(vec![ApprovalRule::reauth(ACL_GRANT)], &[]);
        let tampered = "package vta.policy\n\nimport rego.v1\n\ndecision := {\"decision\": \
                        \"allow\"} if true\n";
        let err = verify_declarative_row(&model_to_ext(&m), tampered).unwrap_err();
        assert!(
            matches!(err, AppError::Validation(ref s) if s.contains("synthesizes to")),
            "got {err:?}"
        );
    }

    /// Validation runs before the byte-compare, so an incoherent rule set is
    /// reported as the modelling error it is rather than as a module mismatch.
    #[test]
    fn an_unsatisfiable_rule_is_refused_before_the_byte_compare() {
        let m = model(vec![ApprovalRule::consent(WEBVH_UPDATE, "nobody")], &[]);
        let module = synthesize_rego(&m.rules);
        let err = verify_declarative_row(&model_to_ext(&m), &module).unwrap_err();
        assert!(
            matches!(err, AppError::Validation(ref s) if s.contains("not defined")),
            "got {err:?}"
        );
    }

    #[test]
    fn rule_lookup_prefers_a_scoped_rule_over_an_unscoped_one() {
        let mut scoped = ApprovalRule::consent(ACL_GRANT, "ops");
        scoped.contexts = vec!["openvtc".into()];
        let m = model(
            vec![ApprovalRule::reauth(ACL_GRANT), scoped],
            &[("ops", &["did:key:zA"])],
        );
        assert_eq!(
            m.rule_for(ACL_GRANT, "openvtc").unwrap().requires,
            Requires::Consent
        );
        assert_eq!(
            m.rule_for(ACL_GRANT, "elsewhere").unwrap().requires,
            Requires::Reauth
        );
        assert!(m.rule_for(WEBVH_UPDATE, "openvtc").is_none());
    }

    #[test]
    fn a_row_without_the_rules_member_is_not_declarative() {
        assert!(!is_declarative(&serde_json::json!({})));
        assert!(!is_declarative(&serde_json::json!({ EXT_KEY_RULES: null })));
        assert!(is_declarative(&serde_json::json!({ EXT_KEY_RULES: [] })));
    }

    #[test]
    fn malformed_ext_is_a_validation_error_not_a_panic() {
        let err =
            model_from_ext(&serde_json::json!({ EXT_KEY_RULES: "not-an-array" })).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }
}
