//! Boot-installed default policy.
//!
//! Mirrors vtc-service's `install_defaults`: seed a baseline only when the
//! operator hasn't already provided one, so uploads are never clobbered. Here
//! "already provided" is simply "the policy keyspace is non-empty".

use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::storage;
use super::types::PolicyModule;

/// Stable id of the boot-installed baseline.
pub const DEFAULT_POLICY_ID: &str = "default";

/// The baseline Rego, embedded at compile time. Validated by a test below so a
/// broken default can never ship.
pub const DEFAULT_POLICY_REGO: &str = include_str!("../../policies/default.rego");

/// Install the baseline policy iff the policy keyspace is empty.
///
/// Called once at boot after the store is opened. Idempotent: a second call is
/// a no-op because the keyspace is no longer empty. Never overwrites an
/// operator's policy set (if any row exists, this does nothing).
pub async fn install_default_policy(
    policy_ks: &KeyspaceHandle,
    now_rfc3339: &str,
) -> Result<(), AppError> {
    if !storage::list_policies(policy_ks).await?.is_empty() {
        return Ok(());
    }
    // Compile-check before storing so a malformed embedded default fails loudly
    // at boot rather than silently seeding an unparseable policy.
    super::engine::compile(DEFAULT_POLICY_REGO, DEFAULT_POLICY_ID)?;

    let baseline = PolicyModule {
        id: DEFAULT_POLICY_ID.to_string(),
        name: "Default baseline".to_string(),
        description: Some(
            "Boot-installed permissive baseline; operators layer higher-priority \
             policies to tighten. See policies/default.rego."
                .to_string(),
        ),
        module: DEFAULT_POLICY_REGO.to_string(),
        applies_to: Vec::new(), // all contexts
        priority: 0,
        enabled: true,
        version: 1,
        created_at: now_rfc3339.to_string(),
        updated_at: now_rfc3339.to_string(),
    };
    storage::store_policy(policy_ks, &baseline).await?;
    tracing::info!(
        policy = DEFAULT_POLICY_ID,
        "installed default PDP baseline policy"
    );
    Ok(())
}

/// Reserved policy id for the config-synthesized consent rules. Owned entirely by
/// the reconciler — an operator's own uploads use their own ids and are never
/// touched.
pub const CONFIG_CONSENT_POLICY_ID: &str = "config:require-consent";

/// Priority for the synthesized consent policy. Above the permissive baseline (0)
/// so it fires first for the task types it names, and below a large headroom so an
/// operator's hand-authored policy can still sit above it.
const CONFIG_CONSENT_PRIORITY: i32 = 100;

/// Reconcile the config-declared `require_consent` rules into the PDP.
///
/// Config is the source of truth, applied on **every** boot: the synthesized
/// policy is upserted when rules are present and deleted when they are not, so an
/// operator adds a rule and restarts to require consent, or removes it and
/// restarts to stop — no source edit, no data-dir wipe, no dependence on the
/// empty-keyspace install semantics `install_default_policy` relies on.
///
/// Runs *after* [`install_default_policy`] so the permissive baseline is present
/// underneath to handle every task these rules do not name.
pub async fn reconcile_config_consent_policy(
    policy_ks: &KeyspaceHandle,
    rules: &[crate::config::RequireConsentRule],
    now_rfc3339: &str,
) -> Result<(), AppError> {
    if rules.is_empty() {
        // No consent rules: ensure a previously-synthesized policy is gone, so
        // removing the config block actually turns consent back off.
        storage::delete_policy(policy_ks, CONFIG_CONSENT_POLICY_ID).await?;
        return Ok(());
    }

    let rego = synthesize_consent_rego(rules);
    // Compile-check before storing so a malformed synthesis fails loudly at boot
    // rather than seating an unparseable policy that would deny every task it is
    // consulted for.
    super::engine::compile(&rego, CONFIG_CONSENT_POLICY_ID)?;

    let module = PolicyModule {
        id: CONFIG_CONSENT_POLICY_ID.to_string(),
        name: "Config-declared consent".to_string(),
        description: Some(
            "Synthesized from [policy.require_consent]; reconciled every boot. \
             Edit config and restart, do not edit this row."
                .to_string(),
        ),
        module: rego,
        applies_to: Vec::new(),
        priority: CONFIG_CONSENT_PRIORITY,
        enabled: true,
        version: 1,
        created_at: now_rfc3339.to_string(),
        updated_at: now_rfc3339.to_string(),
    };
    storage::store_policy(policy_ks, &module).await?;
    tracing::info!(
        policy = CONFIG_CONSENT_POLICY_ID,
        rules = rules.len(),
        "reconciled config-declared consent policy"
    );
    Ok(())
}

/// Turn the declarative rules into a `vta.policy` Rego module.
///
/// One `decision` rule per task type, each guarded on `input.request.typeUri`, so
/// the module fires only for the named tasks and is *undefined* (abstains) for
/// everything else — which lets `decide()` fall through to the baseline. The
/// guards are mutually exclusive by construction (distinct URIs), so no two
/// complete rules ever conflict.
fn synthesize_consent_rego(rules: &[crate::config::RequireConsentRule]) -> String {
    let mut out = String::from("package vta.policy\n\nimport rego.v1\n\n");
    out.push_str(
        "# Generated from [policy.require_consent] in config.toml. Do not edit — \
         this row is reconciled on every boot.\n\n",
    );
    for rule in rules {
        let min = rule.min_approvals.unwrap_or(1).max(1);
        let exclude = rule.exclude_requester.unwrap_or(false);
        out.push_str(&format!(
            "decision := {{\n\t\"decision\": \"requireConsent\",\n\t\"requireConsent\": \
             {{\"approverSet\": {set}, \"minApprovals\": {min}, \"excludeRequester\": {exclude}}},\n\
             }} if input.request.typeUri == {task}\n\n",
            set = rego_string(&rule.approver_set),
            task = rego_string(&rule.task_type),
        ));
    }
    out
}

/// Encode a string as a Rego string literal, escaping the characters that would
/// otherwise let operator-supplied config alter the generated policy's meaning.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    async fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        (store.keyspace(crate::keyspaces::POLICY).unwrap(), dir)
    }

    #[test]
    fn embedded_default_compiles() {
        // The shipped baseline must always be valid Rego.
        super::super::engine::compile(DEFAULT_POLICY_REGO, "default")
            .expect("default.rego compiles");
    }

    #[tokio::test]
    async fn installs_when_empty_and_is_idempotent() {
        let (ks, _dir) = temp_ks().await;
        install_default_policy(&ks, "2026-01-01T00:00:00Z")
            .await
            .unwrap();
        let after_first = storage::list_policies(&ks).await.unwrap();
        assert_eq!(after_first.len(), 1);
        assert_eq!(after_first[0].id, DEFAULT_POLICY_ID);

        // Second call is a no-op.
        install_default_policy(&ks, "2026-02-02T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(storage::list_policies(&ks).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn does_not_clobber_an_operator_policy() {
        let (ks, _dir) = temp_ks().await;
        let op = PolicyModule {
            id: "operator".into(),
            name: "op".into(),
            description: None,
            module: "package vta.policy\nimport rego.v1\ndecision := {\"decision\": \"deny\"}"
                .into(),
            applies_to: vec![],
            priority: 100,
            enabled: true,
            version: 1,
            created_at: "x".into(),
            updated_at: "x".into(),
        };
        storage::store_policy(&ks, &op).await.unwrap();
        install_default_policy(&ks, "2026-01-01T00:00:00Z")
            .await
            .unwrap();
        // Non-empty keyspace ⇒ baseline NOT installed.
        let all = storage::list_policies(&ks).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "operator");
    }

    use crate::config::RequireConsentRule;
    use crate::policy::types::{
        Consumer, Discloses, Disposition, Exposure, PolicyInput, PolicyRequest, SideEffectLevel,
    };

    const UPDATE_URI: &str = "https://trusttasks.org/spec/vta/webvh/dids/update/1.0";
    const OTHER_URI: &str = "https://trusttasks.org/spec/vault/release/0.1";

    fn rule(task: &str) -> RequireConsentRule {
        RequireConsentRule {
            task_type: task.into(),
            approver_set: "ops".into(),
            min_approvals: Some(2),
            exclude_requester: Some(true),
        }
    }

    fn input_for(type_uri: &str) -> PolicyInput {
        PolicyInput {
            request: PolicyRequest {
                type_uri: type_uri.into(),
                kind: None,
                subject: None,
                payload_digest: None,
                side_effects: SideEffectLevel::Destructive,
                exposure: Exposure {
                    discloses: Discloses::None,
                    acts_as_subject: false,
                },
            },
            site: None,
            context_id: "default".into(),
            consumer: Consumer {
                did: "did:key:zReq".into(),
                kind: None,
                device_id: None,
                last_user_verification_at: None,
                network_class: None,
                acr: None,
                amr: vec![],
            },
        }
    }

    async fn decide_for(ks: &KeyspaceHandle, type_uri: &str) -> crate::policy::PolicyDecision {
        let policies = storage::load_active_for_context(ks, "default")
            .await
            .unwrap();
        crate::policy::decide(&policies, &input_for(type_uri))
    }

    /// The whole point: a config rule makes the named task require consent — with
    /// the operator's approver set, threshold and excludeRequester — through the
    /// real load + decide path, not just synthesis.
    #[tokio::test]
    async fn a_config_rule_requires_consent_for_its_task() {
        let (ks, _d) = temp_ks().await;
        install_default_policy(&ks, "2026-07-15T00:00:00Z")
            .await
            .unwrap();
        reconcile_config_consent_policy(&ks, &[rule(UPDATE_URI)], "2026-07-15T00:00:00Z")
            .await
            .unwrap();

        let d = decide_for(&ks, UPDATE_URI).await;
        assert_eq!(d.decision, Disposition::RequireConsent);
        let rc = d.require_consent.expect("requireConsent carrier");
        assert_eq!(rc.approver_set, "ops");
        assert_eq!(rc.min_approvals, 2);
        assert!(rc.exclude_requester);
    }

    /// An unnamed task falls through the config module (it abstains) to the
    /// permissive baseline.
    #[tokio::test]
    async fn an_unnamed_task_falls_through_to_the_baseline() {
        let (ks, _d) = temp_ks().await;
        install_default_policy(&ks, "2026-07-15T00:00:00Z")
            .await
            .unwrap();
        reconcile_config_consent_policy(&ks, &[rule(UPDATE_URI)], "2026-07-15T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(
            decide_for(&ks, OTHER_URI).await.decision,
            Disposition::Allow
        );
    }

    /// Config is authoritative every boot: reconciling with no rules removes a
    /// previously-synthesized policy, so deleting the config block turns consent
    /// back off without a data-dir wipe.
    #[tokio::test]
    async fn removing_the_rule_turns_consent_back_off() {
        let (ks, _d) = temp_ks().await;
        install_default_policy(&ks, "2026-07-15T00:00:00Z")
            .await
            .unwrap();
        reconcile_config_consent_policy(&ks, &[rule(UPDATE_URI)], "2026-07-15T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(
            decide_for(&ks, UPDATE_URI).await.decision,
            Disposition::RequireConsent
        );

        reconcile_config_consent_policy(&ks, &[], "2026-07-15T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(
            decide_for(&ks, UPDATE_URI).await.decision,
            Disposition::Allow
        );
        assert!(
            storage::get_policy(&ks, CONFIG_CONSENT_POLICY_ID)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Reconcile is idempotent, and never touches an operator's own policies.
    #[tokio::test]
    async fn reconcile_is_idempotent_and_leaves_operator_policies_alone() {
        let (ks, _d) = temp_ks().await;
        install_default_policy(&ks, "2026-07-15T00:00:00Z")
            .await
            .unwrap();

        let op = PolicyModule {
            id: "operator-custom".into(),
            name: "op".into(),
            description: None,
            module:
                "package vta.policy\nimport rego.v1\ndecision := {\"decision\": \"deny\"} if false"
                    .into(),
            applies_to: vec![],
            priority: 5,
            enabled: true,
            version: 1,
            created_at: "2026-07-15T00:00:00Z".into(),
            updated_at: "2026-07-15T00:00:00Z".into(),
        };
        storage::store_policy(&ks, &op).await.unwrap();

        for _ in 0..3 {
            reconcile_config_consent_policy(&ks, &[rule(UPDATE_URI)], "2026-07-15T00:00:00Z")
                .await
                .unwrap();
        }
        assert!(
            storage::get_policy(&ks, "operator-custom")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            storage::get_policy(&ks, CONFIG_CONSENT_POLICY_ID)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            decide_for(&ks, UPDATE_URI).await.decision,
            Disposition::RequireConsent
        );
    }

    /// A crafted approver-set name cannot break out of the generated Rego string.
    ///
    /// The teeth: an approver_set containing `", "decision": "allow` would, if
    /// unescaped, close the string literal and inject a second decision key. The
    /// property that proves it did NOT is that the task still resolves to
    /// requireConsent with the approver-set name returned *exactly as given* — the
    /// quote stayed inside the string.
    #[tokio::test]
    async fn synthesis_escapes_operator_strings() {
        let injected = r#"ops", "decision": "allow"#;
        let nasty = RequireConsentRule {
            task_type: "https://trusttasks.org/spec/vta/x/1.0".into(),
            approver_set: injected.into(),
            min_approvals: None,
            exclude_requester: None,
        };
        let (ks, _d) = temp_ks().await;
        install_default_policy(&ks, "2026-07-15T00:00:00Z")
            .await
            .unwrap();
        reconcile_config_consent_policy(&ks, std::slice::from_ref(&nasty), "2026-07-15T00:00:00Z")
            .await
            .unwrap();

        let d = decide_for(&ks, "https://trusttasks.org/spec/vta/x/1.0").await;
        assert_eq!(
            d.decision,
            Disposition::RequireConsent,
            "the injection must not turn the decision into allow"
        );
        assert_eq!(
            d.require_consent.unwrap().approver_set,
            injected,
            "the crafted quote stayed inside the string — it did not break out"
        );
    }
}
