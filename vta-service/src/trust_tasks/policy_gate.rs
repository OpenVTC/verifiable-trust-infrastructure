//! The pre-dispatch Policy Decision Point gate — the single step-up authority.
//!
//! Every dispatched Trust Task routes through [`policy_gate`] before its handler
//! runs. The gate is now the one place step-up is decided, sourcing it from two
//! places and rejecting-with-`approve-request` if either demands it:
//!
//! 1. **Config floors** — the existing `[auth.step_up]` floors, via
//!    [`super::step_up::require_step_up`]. This subsumes the per-handler
//!    `require_step_up` calls (removed from the slices). Runs for the gated
//!    op-classes regardless of PDP enforcement, so the config-driven behaviour
//!    is unchanged; a no-op when no floor applies or the session is already
//!    `aal2`.
//! 2. **Rego policy** — when `config.policy.enforcement` is on, a policy may
//!    return `requireStepUp` (self-approve), `deny`, `requireConsent`, or
//!    `allow`. The session's assurance (`acr`/`amr`) is fed into
//!    `PolicyInput.consumer`, so a policy can gate on step-up state.
//!
//! ## Ordering note
//!
//! The inline `require_step_up` used to run *after* a handler's role check; the
//! gate runs *before* dispatch, hence before the role check. A caller lacking
//! the role now sees a step-up challenge before the role denial — they still
//! can't complete the op, so this is a UX/ordering change, not a security one.
//! It is inherent to a single pre-dispatch gate.
//!
//! ## Opt-in Rego, fail-safe
//!
//! The Rego arm is inert unless enforcement is enabled; the config-floor arm
//! preserves existing behaviour. Any failure to load the policy set denies.

use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};

use super::TrustTaskOutcome;
use super::helpers::reject_with;
use crate::auth::AuthClaims;
use crate::policy::{self, Disposition};
use crate::server::AppState;

/// The ACR a satisfied step-up reaches. Mirrors `step_up::STEP_UP_TARGET_ACR`.
const STEP_UP_TARGET_ACR: &str = "aal2";

/// Map a task's Type URI to its step-up operation-class, for the gated ops that
/// carry a config floor. Only the ops that previously called `require_step_up`
/// inline are mapped, preserving current behaviour (`acl/swap-key` had no inline
/// call and stays unmapped). Returns `None` for ungated tasks.
#[allow(deprecated)]
fn op_class_for(type_uri: &str) -> Option<&'static str> {
    use super::step_up::op;
    use vta_sdk::trust_tasks as t;
    match type_uri {
        t::TASK_ACL_CREATE_1_0 => Some(op::ACL_GRANT),
        t::TASK_ACL_UPDATE_1_0 => Some(op::ACL_CHANGE_ROLE),
        t::TASK_ACL_DELETE_1_0 => Some(op::ACL_REVOKE),
        t::TASK_CONTEXTS_DELETE_1_0 => Some(op::CONTEXT_DELETE),
        t::TASK_KEYS_REVOKE_1_0 => Some(op::KEY_REVOKE),
        t::TASK_VAULT_RELEASE_0_1 => Some(op::VAULT_RELEASE),
        t::TASK_VAULT_PROXY_LOGIN_0_1 => Some(op::VAULT_PROXY_LOGIN),
        t::TASK_VAULT_SIGN_TRUST_TASK_0_1 => Some(op::VAULT_SIGN_TRUST_TASK),
        t::TASK_VTA_CREDENTIALS_ISSUE_0_1 => Some(op::CREDENTIALS_ISSUE),
        t::TASK_VTA_CREDENTIALS_REVOKE_0_1 => Some(op::CREDENTIALS_REVOKE),
        _ => None,
    }
}

/// Evaluate the gate for a task about to be dispatched.
///
/// `None` → proceed to the handler. `Some(outcome)` → reject before dispatch
/// (the caller still audits the rejected task).
pub(super) async fn policy_gate(
    state: &AppState,
    auth: &AuthClaims,
    type_uri: &str,
    doc: &TrustTask<Value>,
) -> Option<TrustTaskOutcome> {
    // (1) Config-floor step-up (subsumes the inline require_step_up).
    if let Some(op_class) = op_class_for(type_uri)
        && let Some(reject) = super::step_up::require_step_up(state, auth, op_class, doc).await
    {
        return Some(reject);
    }

    // (2) Rego policy — only when enforcement is enabled.
    if !state.config.read().await.policy.enforcement {
        return None;
    }

    let class = super::class_for(type_uri);
    let input = policy::build_policy_input(
        type_uri,
        &doc.payload,
        &auth.did,
        &auth.acr,
        &auth.amr,
        class,
    );

    let policies = match policy::load_active_for_context(&state.policy_ks, &input.context_id).await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, type_uri, "policy load failed — denying (fail-closed)");
            return Some(reject_with(
                doc,
                RejectReason::PermissionDenied {
                    reason: "policy evaluation unavailable".to_string(),
                },
            ));
        }
    };

    let decision = policy::decide(&policies, &input);
    match decision.decision {
        Disposition::Allow => None,
        Disposition::Deny => Some(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: decision
                    .explanation
                    .unwrap_or_else(|| "denied by policy".to_string()),
            },
        )),
        Disposition::RequireStepUp => {
            if auth.acr == STEP_UP_TARGET_ACR {
                // Already elevated — the requirement is satisfied.
                None
            } else {
                Some(super::step_up::initiate_self_step_up(state, auth, doc).await)
            }
        }
        // Task-execution consent (approver-set + payload-digest binding) is
        // Phase B; until then surface it as a denial with a clear reason.
        Disposition::RequireConsent => Some(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "consent required: {}",
                    decision
                        .explanation
                        .as_deref()
                        .unwrap_or("policy requires approver consent")
                ),
            },
        )),
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
    // Step-up unless the session is already aal2 — the canonical policy shape
    // the acr feed enables. Explicitly allows at aal2 (an abstaining policy
    // would default-deny).
    const STEPUP_IF_NOT_AAL2: &str = "package vta.policy\nimport rego.v1\ndecision := {\"decision\": \"requireStepUp\"} if input.consumer.acr != \"aal2\"\ndecision := {\"decision\": \"allow\"} if input.consumer.acr == \"aal2\"";

    fn doc(type_uri: &str) -> TrustTask<Value> {
        serde_json::from_value(serde_json::json!({
            "id": "urn:uuid:00000000-0000-0000-0000-000000000001",
            "type": type_uri,
            "issuer": "did:key:zTestAdmin",
            "recipient": "did:example:vta",
            "issuedAt": "2026-05-20T00:00:00Z",
            "payload": { "contextId": "default" }
        }))
        .expect("valid trust task")
    }

    // An ungated task URI (not in op_class_for) so the config-floor arm is a
    // no-op and only the Rego arm runs.
    const UNGATED_URI: &str = "https://trusttasks.org/spec/vta/memory/list/0.1";

    #[tokio::test]
    async fn gate_inert_when_disabled_enforces_when_enabled() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let auth = crate::test_support::super_admin_claims();
        let d = doc(UNGATED_URI);

        // Disabled: proceed even with an empty policy set.
        assert!(policy_gate(&state, &auth, UNGATED_URI, &d).await.is_none());

        // Enabled + empty set → default-deny.
        state.config.write().await.policy.enforcement = true;
        assert!(policy_gate(&state, &auth, UNGATED_URI, &d).await.is_some());

        // Deny policy → reject.
        crate::policy::storage::store_policy(&state.policy_ks, &module("deny", 0, DENY_ALL))
            .await
            .unwrap();
        assert!(policy_gate(&state, &auth, UNGATED_URI, &d).await.is_some());

        // Higher-priority allow overrides → proceed.
        crate::policy::storage::store_policy(&state.policy_ks, &module("allow", 10, ALLOW_ALL))
            .await
            .unwrap();
        assert!(policy_gate(&state, &auth, UNGATED_URI, &d).await.is_none());
    }

    #[tokio::test]
    async fn rego_requires_step_up_when_session_not_elevated() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let mut auth = crate::test_support::super_admin_claims();
        let d = doc(UNGATED_URI);

        state.config.write().await.policy.enforcement = true;
        crate::policy::storage::store_policy(
            &state.policy_ks,
            &module("su", 0, STEPUP_IF_NOT_AAL2),
        )
        .await
        .unwrap();

        // aal1 session → policy demands step-up → rejected (with approve-request).
        auth.acr = "aal1".into();
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d).await.is_some(),
            "aal1 session must be sent to step-up"
        );

        // aal2 session → requirement already satisfied → proceed.
        auth.acr = "aal2".into();
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d).await.is_none(),
            "aal2 session must pass the step-up gate"
        );
    }
}
