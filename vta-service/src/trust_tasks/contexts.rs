//! Contexts slice trust-task handlers.
//!
//! Mirrors the legacy REST `/contexts/*` routes. Auth: any
//! authenticated caller for list/get; admin for update-did;
//! super-admin for create/update/preview-delete/delete.

use super::helpers::TrustTaskOutcome;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::context_management::create::CreateContextBody;
use vta_sdk::protocols::context_management::delete::{DeleteContextBody, DeleteContextPreviewBody};
use vta_sdk::protocols::context_management::get::GetContextBody;
use vta_sdk::protocols::context_management::list::ListContextsBody;
use vta_sdk::protocols::context_management::update::UpdateContextBody;
use vta_sdk::protocols::context_management::update_did::UpdateContextDidBody;

use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

use super::helpers::{TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, success_response};

/// Handler for `spec/vta/contexts/list/1.0`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let _req: ListContextsBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::list_contexts(&state.contexts_ks, auth, TRANSPORT_TRUST_TASK).await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/create/1.0`. Super-admin only.
pub(super) async fn handle_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // Admin role required; `create_context` enforces the finer gate (super-admin
    // for a top-level context, admin-of-parent for a sub-context).
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: CreateContextBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::create_context(
        &state.contexts_ks,
        auth,
        &req.id,
        req.name,
        req.description,
        req.parent,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/get/1.0`.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: GetContextBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::get_context_op(
        &state.contexts_ks,
        auth,
        &req.id,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/update/1.0`. Super-admin only.
pub(super) async fn handle_update(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: UpdateContextBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::update_context(
        &state.contexts_ks,
        auth,
        &req.id,
        operations::contexts::UpdateContextParams {
            name: req.name,
            did: req.did,
            description: req.description,
        },
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/update-did/1.0`. Admin only.
pub(super) async fn handle_update_did(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: UpdateContextDidBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::update_context_did(
        &state.contexts_ks,
        auth,
        &req.id,
        req.did,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/preview-delete/1.0`. Super-admin only.
pub(super) async fn handle_preview_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // Admin role; the operation enforces access to the context or an ancestor.
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: DeleteContextPreviewBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::preview_delete_context(
        &state.contexts_ks,
        &state.keys_ks,
        &state.acl_ks,
        &state.did_templates_ks,
        #[cfg(feature = "webvh")]
        &state.webvh_ks,
        auth,
        &req.id,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/delete/1.0`. Admin role; the operation
/// enforces access to the context or an ancestor (folder authority) and
/// cascades the subtree with `force`.
pub(super) async fn handle_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    // Deleting a context is gated per the `context/delete` step-up floor.
    if let Some(resp) =
        super::step_up::require_step_up(state, auth, super::step_up::op::CONTEXT_DELETE, &doc).await
    {
        return resp;
    }
    let req: DeleteContextBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ks = operations::Keyspaces::from_app_state(state);
    match operations::contexts::delete_context(&ks, auth, &req.id, req.force, TRANSPORT_TRUST_TASK)
        .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}
