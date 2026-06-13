//! ACL slice trust-task handlers.
//!
//! Mirrors the legacy REST `/acl/*` routes one-for-one. Auth: Admin or
//! Initiator for list/create/get/delete; Admin-only for update.

use axum::response::Response;
use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};
use vta_sdk::protocols::acl_management::create::CreateAclBody;
use vta_sdk::protocols::acl_management::delete::DeleteAclBody;
use vta_sdk::protocols::acl_management::get::GetAclBody;
use vta_sdk::protocols::acl_management::list::ListAclBody;
use vta_sdk::protocols::acl_management::update::UpdateAclBody;

use crate::acl::Role;
use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, reject_with, success_response,
};

/// Handler for `spec/vta/acl/list/1.0`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    let req: ListAclBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::acl::list_acl(
        &state.acl_ks,
        auth,
        req.context.as_deref(),
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/acl/create/1.0`.
pub(super) async fn handle_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    // ACL grant is gated per the `acl/grant` step-up floor (operator policy).
    if let Some(resp) =
        super::step_up::require_step_up(state, auth, super::step_up::op::ACL_GRANT, &doc).await
    {
        return resp;
    }
    let req: CreateAclBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let role = match Role::parse(&req.role) {
        Ok(r) => r,
        Err(_) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("invalid role: {}", req.role),
                },
            );
        }
    };
    match operations::acl::create_acl(
        &state.acl_ks,
        &state.audit_ks,
        &state.contexts_ks,
        auth,
        &req.did,
        role,
        req.label,
        req.allowed_contexts,
        req.expires_at,
        req.step_up_approver,
        req.step_up_require,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/acl/get/1.0`.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    let req: GetAclBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::acl::get_acl(&state.acl_ks, auth, &req.did, TRANSPORT_TRUST_TASK).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/acl/update/1.0`. Admin-only — matches the
/// legacy REST `PATCH /acl/{did}` policy.
pub(super) async fn handle_update(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    // ACL change-role is gated per the `acl/change-role` step-up floor.
    if let Some(resp) =
        super::step_up::require_step_up(state, auth, super::step_up::op::ACL_CHANGE_ROLE, &doc)
            .await
    {
        return resp;
    }
    let req: UpdateAclBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let role = match req.role.as_deref() {
        Some(r) => match Role::parse(r) {
            Ok(parsed) => Some(parsed),
            Err(_) => {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: format!("invalid role: {r}"),
                    },
                );
            }
        },
        None => None,
    };
    match operations::acl::update_acl(
        &state.acl_ks,
        &state.audit_ks,
        &state.contexts_ks,
        auth,
        &req.did,
        operations::acl::UpdateAclParams {
            role,
            label: req.label,
            allowed_contexts: req.allowed_contexts,
            step_up_approver: req.step_up_approver,
            step_up_require: req.step_up_require,
        },
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/acl/delete/1.0`.
pub(super) async fn handle_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    // ACL revoke is gated per the `acl/revoke` step-up floor (operator policy).
    if let Some(resp) =
        super::step_up::require_step_up(state, auth, super::step_up::op::ACL_REVOKE, &doc).await
    {
        return resp;
    }
    let req: DeleteAclBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::acl::delete_acl(
        &state.acl_ks,
        &state.audit_ks,
        auth,
        &req.did,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}
