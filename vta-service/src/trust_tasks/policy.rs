//! `policy/*` slice trust-task handlers — runtime Policy Decision Point
//! management.
//!
//! Wire adapters only; the logic (and every authorization check) lives in
//! [`crate::operations::policy`], so the REST surface and the dispatcher cannot
//! diverge on who may do what.
//!
//! Auth: `list`/`get`/`evaluate` are admin, `upsert`/`delete` are super-admin —
//! enforced inside the operation functions, not here.

use serde_json::Value;
use trust_tasks_rs::TrustTask;

use vta_sdk::protocols::policy_management::{
    DeletePolicyBody, GetPolicyBody, ListPoliciesBody, UpsertPolicyBody,
};

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, parse_payload, success_response,
};
use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

/// Handler for canonical `policy/list/0.2`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: ListPoliciesBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::policy::list_policies(
        &state.policy_ks,
        auth,
        req.context_id.as_deref(),
        req.enabled_only,
        req.page_size,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for canonical `policy/get/0.1`.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: GetPolicyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::policy::get_policy(&state.policy_ks, auth, &req.id, TRANSPORT_TRUST_TASK)
        .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for canonical `policy/upsert/0.2`. Super-admin.
pub(super) async fn handle_upsert(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: UpsertPolicyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::policy::upsert_policy(
        &state.policy_ks,
        &state.audit_sink,
        auth,
        req,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for canonical `policy/delete/0.1`. Super-admin.
pub(super) async fn handle_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: DeletePolicyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::policy::delete_policy(
        &state.policy_ks,
        &state.audit_sink,
        auth,
        &req.id,
        req.expected_version,
        req.reason.as_deref(),
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}
