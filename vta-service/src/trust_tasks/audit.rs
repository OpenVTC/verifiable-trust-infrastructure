//! Audit slice trust-task handlers.
//!
//! Auth: Admin for list-logs and get-retention; Super-Admin for
//! update-retention (enforced inside the operation function).

use super::helpers::TrustTaskOutcome;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::audit_management::list::ListAuditLogsBody;
use vta_sdk::protocols::audit_management::retention::{GetRetentionBody, UpdateRetentionBody};

use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

use super::helpers::{TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, success_response};

/// Handler for `spec/vta/audit/list-logs/1.0`. Admin only.
pub(super) async fn handle_list_logs(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: ListAuditLogsBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::audit::list_audit_logs(&state.audit_ks, auth, &req, TRANSPORT_TRUST_TASK)
        .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/audit/get-retention/1.0`. Admin only.
pub(super) async fn handle_get_retention(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let _req: GetRetentionBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::audit::get_retention(&state.config, auth, TRANSPORT_TRUST_TASK).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/audit/update-retention/1.0`. Super-admin only.
pub(super) async fn handle_update_retention(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: UpdateRetentionBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::audit::update_retention(
        &state.config,
        &state.audit_ks,
        auth,
        req.retention_days,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}
