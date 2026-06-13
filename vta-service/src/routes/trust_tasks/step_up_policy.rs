//! `auth/step-up/policy/0.2` — runtime step-up policy management (the wire half).
//!
//! Authorizes a super-admin bearer, converts the policy payload to the VTA's
//! internal `StepUpPolicy`, and delegates validation + persistence to
//! [`crate::operations::step_up_policy`]. Returns the effective (canonicalized)
//! policy as a `#response`, or a `trust-task-error` with the spec's
//! `notAuthorized` / `unknownOperation` / `lockoutRefused` codes.
//!
//! Authorization is the super-admin **bearer** (not a step-up gate — gating the
//! policy-set on a step-up would be circular: you could never enable the gate
//! that requires an approver). The spec's `proof` requirement is satisfied by
//! the authenticated caller; full TT-proof verification lands with the
//! session-pubkey binding (dispatcher Phase 3), as for every other mutating arm.

use axum::response::Response;
use serde_json::{Value, json};

use trust_tasks_rs::specs::auth::step_up::policy::v0_2 as policy;
use trust_tasks_rs::{RejectReason, TrustTask};

use vti_common::auth::AuthClaims;

use crate::operations::step_up_policy::{
    SetPolicyError, effective_response, policy_from_payload, set_step_up_policy,
};
use crate::server::AppState;

use super::helpers::{reject_with, success_response};

fn policy_failure(code: &str, details: Option<Value>) -> RejectReason {
    RejectReason::TaskFailed {
        reason: code.to_string(),
        details,
    }
}

/// Handle `auth/step-up/policy/0.2`: set the maintainer's step-up policy.
pub(super) async fn handle_set_step_up_policy(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    // Authz: only a super-admin may change the VTA's security posture.
    if !auth.is_super_admin() {
        return reject_with(
            &doc,
            policy_failure("auth/step-up/policy:not_authorized", None),
        );
    }

    // Parse the 0.2 payload.
    let payload: policy::Payload = match serde_json::from_value(doc.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("payload parse: {e}"),
                },
            );
        }
    };
    let requested = policy_from_payload(&payload);

    match set_step_up_policy(&state.config, &state.acl_ks, requested).await {
        Ok(effective) => success_response(&doc, effective_response(&effective)),
        Err(SetPolicyError::UnknownOperation(op)) => reject_with(
            &doc,
            policy_failure(
                "auth/step-up/policy:unknown_operation",
                Some(json!({ "operation": op })),
            ),
        ),
        Err(SetPolicyError::LockoutRefused(msg)) => reject_with(
            &doc,
            policy_failure(
                "auth/step-up/policy:lockout_refused",
                Some(json!({ "message": msg })),
            ),
        ),
        Err(e @ (SetPolicyError::Store(_) | SetPolicyError::Persistence(_))) => reject_with(
            &doc,
            RejectReason::InternalError {
                reason: e.to_string(),
            },
        ),
    }
}
