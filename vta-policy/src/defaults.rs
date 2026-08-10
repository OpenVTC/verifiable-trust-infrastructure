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
pub const DEFAULT_POLICY_REGO: &str = include_str!("../policies/default.rego");

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
        ext: serde_json::Value::Null,
    };
    storage::store_policy(policy_ks, &baseline).await?;
    tracing::info!(
        policy = DEFAULT_POLICY_ID,
        "installed default PDP baseline policy"
    );
    Ok(())
}

/// Seed the declarative approvals row from config, **iff it does not exist**.
///
/// This is the bring-up path: a freshly-provisioned or IaC-managed VTA declares
/// its approval rules in `config.toml` and comes up already enforcing them,
/// without an operator having to run `pnm approvals` by hand afterwards.
///
/// # Why seed-once, and not reconcile-every-boot
///
/// The consent policy this supersedes was reconciled from config on *every*
/// boot, which made config the source of truth and the keyspace a cache. Once
/// the rules are editable at runtime that behaviour becomes a trap: an operator
/// changes a rule with `pnm approvals`, the change takes effect, and then the
/// next restart — hours or weeks later, for an unrelated reason — silently
/// reverts it to whatever the file still says. A security control that quietly
/// undoes itself on restart is worse than one that is awkward to change.
///
/// So the row wins once it exists. To re-seed deliberately, delete the row
/// (`pnm policy delete approvals`, or the offline break-glass) and restart.
pub async fn seed_declarative_approvals(
    policy_ks: &KeyspaceHandle,
    rules: &[vta_sdk::approvals::ApprovalRule],
    approver_sets: &std::collections::HashMap<String, Vec<String>>,
    now_rfc3339: &str,
) -> Result<(), AppError> {
    if rules.is_empty() && approver_sets.is_empty() {
        return Ok(());
    }
    if storage::get_policy(policy_ks, vta_sdk::approvals::DECLARATIVE_POLICY_ID)
        .await?
        .is_some()
    {
        tracing::debug!(
            "declarative approvals row already exists; leaving it alone (config is a seed, \
             not the source of truth)"
        );
        return Ok(());
    }

    let model = super::approvals::DeclarativeModel {
        rules: rules.to_vec(),
        approver_sets: approver_sets
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    };
    // Validate before seating. A config that cannot be satisfied — a rule naming
    // an approver set that isn't defined, a threshold larger than its set —
    // should stop the operator at boot, not at the first request it blocks.
    vta_sdk::approvals::validate(&model.rules, &model.approver_sets)
        .map_err(|e| AppError::Validation(format!("[policy] approvals seed is invalid: {e}")))?;
    let row = super::approvals::declarative_row(&model, 1, now_rfc3339, now_rfc3339);
    // Compile-check the synthesized module for the same reason the baseline is
    // compile-checked: a module that will not compile is skipped at load time,
    // which silently un-gates every task it named.
    super::engine::compile(&row.module, vta_sdk::approvals::DECLARATIVE_POLICY_ID)?;
    storage::store_policy(policy_ks, &row).await?;

    tracing::info!(
        rules = model.rules.len(),
        approver_sets = model.approver_sets.len(),
        "seeded the declarative approvals row from config (first boot without one)"
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

/// Remove a `config:require-consent` row left behind by a previous release.
///
/// `[[policy.require_consent]]` was the *third* way a VTA could be told an
/// operation needs a human — alongside the `[auth.step_up]` floors and the
/// declarative approvals row — and it is retired: `AppConfig` now refuses a
/// config that still declares it, pointing at `pnm approvals`.
///
/// Refusing the config is not enough on its own. The old reconciler synthesized
/// a Rego module under a reserved id and rewrote it on **every** boot, which is
/// what made "delete the config block, restart" turn consent back off. Simply
/// deleting the reconciler would strand that row: a VTA upgraded from a release
/// that had the block would keep enforcing a synthesized `requireConsent` that
/// no config declares, that `pnm approvals list` does not know about, and that
/// no command can remove — the exact undiagnosable state this convergence
/// exists to end.
///
/// So the reconciler becomes a one-way cleanup: the row is deleted, once, on the
/// first boot after the upgrade, and never written again. Idempotent, so it is
/// harmless on every boot after that. It runs *after* [`install_default_policy`]
/// so the permissive baseline is underneath to handle the tasks it used to name.
///
/// An operator who wanted those requirements keeps them by re-declaring them as
/// approvals rules — which is why the config refusal names the command rather
/// than only saying no.
pub async fn remove_stale_config_consent_policy(
    policy_ks: &KeyspaceHandle,
) -> Result<(), AppError> {
    storage::delete_policy(policy_ks, CONFIG_CONSENT_POLICY_ID).await
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
    use vta_config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        (store.keyspace(vta_keyspaces::POLICY).unwrap(), dir)
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
            ext: serde_json::Value::Null,
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

    use crate::types::{
        Consumer, Discloses, Disposition, Exposure, PolicyInput, PolicyRequest, SideEffectLevel,
    };

    const UPDATE_URI: &str = "https://trusttasks.org/spec/vta/webvh/dids/update/1.0";

    fn input_for(type_uri: &str) -> PolicyInput {
        PolicyInput {
            request: PolicyRequest {
                type_uri: type_uri.to_string(),
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
            context_id: "default".to_string(),
            consumer: Consumer {
                did: "did:key:zRequester".to_string(),
                kind: None,
                device_id: None,
                last_user_verification_at: None,
                network_class: None,
                acr: Some("aal1".to_string()),
                amr: vec![],
            },
        }
    }

    async fn decide_for(ks: &KeyspaceHandle, type_uri: &str) -> crate::PolicyDecision {
        let policies = storage::load_active_for_context(ks, "default")
            .await
            .unwrap();
        crate::decide(&policies, &input_for(type_uri))
    }

    /// A row synthesized by a previous release is dropped on the upgrade boot.
    ///
    /// This is the whole reason the reconciler became a cleanup rather than just
    /// disappearing. `[[policy.require_consent]]` rewrote this row on every boot,
    /// which is what made "delete the config block, restart" turn consent back
    /// off. Delete the reconciler outright and a VTA upgraded from a release that
    /// had the block keeps enforcing a `requireConsent` that no config declares,
    /// `pnm approvals list` cannot see, and no command can remove — a gate with
    /// no explanation, which is exactly what this convergence exists to end.
    ///
    /// So: the row must be gone, and the task must go back to deciding on the
    /// baseline alone.
    #[tokio::test]
    async fn an_upgrade_drops_a_row_a_previous_release_synthesized() {
        let (ks, _d) = temp_ks().await;
        install_default_policy(&ks, "2026-07-15T00:00:00Z")
            .await
            .unwrap();

        // Exactly what the retired reconciler used to write.
        storage::store_policy(
            &ks,
            &PolicyModule {
                id: CONFIG_CONSENT_POLICY_ID.to_string(),
                name: "Config-declared consent".to_string(),
                description: None,
                module: format!(
                    "package vta.policy\n\nimport rego.v1\n\n\
                     decision := {{\"decision\": \"requireConsent\", \"requireConsent\": \
                     {{\"approverSet\": \"ops\"}}}} if input.request.typeUri == \"{UPDATE_URI}\"\n"
                ),
                applies_to: Vec::new(),
                priority: CONFIG_CONSENT_PRIORITY,
                enabled: true,
                version: 1,
                created_at: "2026-07-15T00:00:00Z".to_string(),
                updated_at: "2026-07-15T00:00:00Z".to_string(),
                ext: serde_json::Value::Null,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            decide_for(&ks, UPDATE_URI).await.decision,
            Disposition::RequireConsent,
            "precondition: the stale row is in force before the upgrade boot"
        );

        remove_stale_config_consent_policy(&ks).await.unwrap();

        assert!(
            storage::get_policy(&ks, CONFIG_CONSENT_POLICY_ID)
                .await
                .unwrap()
                .is_none(),
            "the stale row must be gone, not merely disabled"
        );
        assert_eq!(
            decide_for(&ks, UPDATE_URI).await.decision,
            Disposition::Allow,
            "and the task must decide on the baseline alone"
        );

        // Idempotent: it runs on every boot, and there is nothing left to remove.
        remove_stale_config_consent_policy(&ks).await.unwrap();
    }

    /// The cleanup owns one reserved id and must not reach past it.
    #[tokio::test]
    async fn the_cleanup_leaves_an_operators_own_policies_alone() {
        let (ks, _d) = temp_ks().await;
        install_default_policy(&ks, "2026-07-15T00:00:00Z")
            .await
            .unwrap();
        let before = storage::list_policies(&ks).await.unwrap().len();

        remove_stale_config_consent_policy(&ks).await.unwrap();

        assert_eq!(
            storage::list_policies(&ks).await.unwrap().len(),
            before,
            "a VTA that never had the config block loses nothing"
        );
    }

    // ── Declarative approvals seeding ──────────────────────────────────────

    fn seed_rules() -> Vec<vta_sdk::approvals::ApprovalRule> {
        vec![vta_sdk::approvals::ApprovalRule::reauth(
            "https://trusttasks.org/spec/acl/grant/0.1",
        )]
    }

    #[tokio::test]
    async fn seeds_the_declarative_row_on_a_fresh_vta() {
        let (ks, _d) = temp_ks().await;
        seed_declarative_approvals(
            &ks,
            &seed_rules(),
            &Default::default(),
            "2026-08-09T00:00:00Z",
        )
        .await
        .unwrap();

        let row = storage::get_policy(&ks, vta_sdk::approvals::DECLARATIVE_POLICY_ID)
            .await
            .unwrap()
            .expect("row seeded");
        let model = crate::approvals::verify_declarative_row(&row.ext, &row.module)
            .expect("seeded row must verify against its own rules");
        assert_eq!(model.rules.len(), 1);
    }

    /// The trap this seeding deliberately avoids: config re-read on every boot
    /// would silently revert a runtime edit at the next restart — possibly weeks
    /// later, for an unrelated reason. The row wins once it exists.
    #[tokio::test]
    async fn a_runtime_edit_survives_a_restart() {
        let (ks, _d) = temp_ks().await;
        seed_declarative_approvals(
            &ks,
            &seed_rules(),
            &Default::default(),
            "2026-08-09T00:00:00Z",
        )
        .await
        .unwrap();

        // Operator changes the rules at runtime (what `pnm approvals` does).
        let edited = crate::approvals::DeclarativeModel {
            rules: vec![vta_sdk::approvals::ApprovalRule::reauth(
                "https://trusttasks.org/spec/keys/revoke/0.1",
            )],
            approver_sets: Default::default(),
        };
        let row = crate::approvals::declarative_row(
            &edited,
            2,
            "2026-08-09T01:00:00Z",
            "2026-08-09T00:00:00Z",
        );
        storage::store_policy(&ks, &row).await.unwrap();

        // Restart: seeding runs again against the same config.
        seed_declarative_approvals(
            &ks,
            &seed_rules(),
            &Default::default(),
            "2026-08-09T02:00:00Z",
        )
        .await
        .unwrap();

        let after = crate::approvals::load(&ks).await.unwrap();
        assert_eq!(
            after.rules, edited.rules,
            "the config seed clobbered a runtime edit on restart"
        );
    }

    /// A seed that could never be satisfied should stop the operator at boot,
    /// not at the first request it blocks.
    #[tokio::test]
    async fn an_unsatisfiable_seed_fails_at_boot() {
        let (ks, _d) = temp_ks().await;
        let rules = vec![vta_sdk::approvals::ApprovalRule::consent(
            "https://trusttasks.org/spec/acl/grant/0.1",
            "nobody",
        )];
        let err =
            seed_declarative_approvals(&ks, &rules, &Default::default(), "2026-08-09T00:00:00Z")
                .await
                .expect_err("a rule naming an undefined approver set must not seat");
        assert!(
            matches!(err, AppError::Validation(ref s) if s.contains("not defined")),
            "got {err:?}"
        );
        assert!(
            storage::get_policy(&ks, vta_sdk::approvals::DECLARATIVE_POLICY_ID)
                .await
                .unwrap()
                .is_none(),
            "nothing should have been written"
        );
    }

    #[tokio::test]
    async fn an_empty_seed_writes_nothing() {
        let (ks, _d) = temp_ks().await;
        seed_declarative_approvals(&ks, &[], &Default::default(), "2026-08-09T00:00:00Z")
            .await
            .unwrap();
        assert!(
            storage::get_policy(&ks, vta_sdk::approvals::DECLARATIVE_POLICY_ID)
                .await
                .unwrap()
                .is_none()
        );
    }
}
