//! The pre-dispatch Policy Decision Point gate.
//!
//! Every dispatched Trust Task routes through [`policy_gate`] before its handler
//! runs. The gate builds a [`PolicyInput`](crate::policy::PolicyInput) from the
//! task's authoritative class ([`super::class_for`] — compiled, not the
//! registry), evaluates the active policy set via [`crate::policy::decide`], and
//! maps the disposition to proceed-or-reject.
//!
//! ## Opt-in, fail-safe
//!
//! When `config.policy.enforcement` is false (the default) the gate is a no-op
//! that always proceeds — so it lands wired-but-inert and a deployment enables
//! it deliberately. When enabled, the boot-installed baseline still allows
//! current flows, so nothing breaks until an operator adds a restrictive
//! higher-priority policy. Any failure to load the policy set denies
//! (fail-closed).

use serde_json::Value;
use trust_tasks_rs::RejectReason;

use crate::auth::AuthClaims;
use crate::policy::{self, Disposition};
use crate::server::AppState;

/// Evaluate the PDP for a task about to be dispatched.
///
/// `Ok(())` → proceed to the handler. `Err(reason)` → reject before dispatch
/// (the caller still audits the rejected task).
pub(super) async fn policy_gate(
    state: &AppState,
    auth: &AuthClaims,
    type_uri: &str,
    payload: &Value,
) -> Result<(), RejectReason> {
    // Opt-in: inert unless an operator turns enforcement on.
    if !state.config.read().await.policy.enforcement {
        return Ok(());
    }

    let class = super::class_for(type_uri);
    let input = policy::build_policy_input(type_uri, payload, &auth.did, class);

    let policies = match policy::load_active_for_context(&state.policy_ks, &input.context_id).await
    {
        Ok(p) => p,
        Err(e) => {
            // Fail closed: if we can't load policy, we don't dispatch.
            tracing::error!(error = %e, type_uri, "policy load failed — denying (fail-closed)");
            return Err(RejectReason::PermissionDenied {
                reason: "policy evaluation unavailable".to_string(),
            });
        }
    };

    let decision = policy::decide(&policies, &input);
    match decision.decision {
        Disposition::Allow => Ok(()),
        Disposition::Deny => Err(RejectReason::PermissionDenied {
            reason: decision
                .explanation
                .unwrap_or_else(|| "denied by policy".to_string()),
        }),
        // Step-up / consent flows are surfaced as permission-denied with a
        // reason for now; wiring the actual step-up + approver-set ceremonies
        // into this decision path is a follow-up. Denying (rather than
        // proceeding) keeps the gate fail-safe until then.
        Disposition::RequireStepUp => Err(RejectReason::PermissionDenied {
            reason: format!(
                "step-up required: {}",
                decision
                    .explanation
                    .as_deref()
                    .unwrap_or("policy requires step-up")
            ),
        }),
        Disposition::RequireConsent => Err(RejectReason::PermissionDenied {
            reason: format!(
                "consent required: {}",
                decision
                    .explanation
                    .as_deref()
                    .unwrap_or("policy requires approver consent")
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::types::PolicyModule;

    fn module(id: &str, priority: i32, rego: &str) -> PolicyModule {
        PolicyModule {
            id: id.into(),
            name: id.into(),
            description: None,
            module: rego.into(),
            applies_to: vec![],
            priority,
            enabled: true,
            version: 1,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    const DENY_ALL: &str = "package vta.policy\nimport rego.v1\ndecision := {\"decision\": \"deny\", \"explanation\": \"blocked\"}";
    const ALLOW_ALL: &str =
        "package vta.policy\nimport rego.v1\ndecision := {\"decision\": \"allow\"}";

    #[tokio::test]
    async fn gate_is_inert_when_disabled_and_enforces_when_enabled() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let auth = crate::test_support::super_admin_claims();
        let type_uri = "https://trusttasks.org/spec/vault/release/0.1";
        let payload = serde_json::json!({ "contextId": "default" });

        // Enforcement OFF (default): proceeds even with an empty policy set,
        // which would otherwise default-deny. This is the migration-safe flip.
        assert!(
            policy_gate(&state, &auth, type_uri, &payload).await.is_ok(),
            "disabled gate must be inert"
        );

        // Turn enforcement ON. Empty policy set now default-denies.
        state.config.write().await.policy.enforcement = true;
        assert!(
            policy_gate(&state, &auth, type_uri, &payload)
                .await
                .is_err(),
            "enabled + no policy must default-deny"
        );

        // A deny policy rejects.
        crate::policy::storage::store_policy(&state.policy_ks, &module("deny", 0, DENY_ALL))
            .await
            .unwrap();
        assert!(
            policy_gate(&state, &auth, type_uri, &payload)
                .await
                .is_err()
        );

        // A higher-priority allow overrides it → proceeds.
        crate::policy::storage::store_policy(&state.policy_ks, &module("allow", 10, ALLOW_ALL))
            .await
            .unwrap();
        assert!(
            policy_gate(&state, &auth, type_uri, &payload).await.is_ok(),
            "higher-priority allow must let the task proceed"
        );
    }
}
