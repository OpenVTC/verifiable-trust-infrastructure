//! Config slice trust-task handlers.
//!
//! Auth: any authenticated caller for `get`; Super Admin for
//! `update` (enforced inside the operation function).

use axum::response::Response;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::vta_management::get_config::GetConfigBody;
use vta_sdk::protocols::vta_management::update_config::UpdateConfigBody;

use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

use super::helpers::{TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, success_response};

/// Handler for `spec/vta/config/get/1.0`.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    let _req: GetConfigBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::config::get_config(&state.config, auth, TRANSPORT_TRUST_TASK).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/config/update/1.0`. Super-admin only.
pub(super) async fn handle_update(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    let req: UpdateConfigBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::config::update_config(
        &state.config,
        auth,
        operations::config::UpdateConfigParams {
            vta_did: req.vta_did,
            vta_name: req.vta_name,
            public_url: req.public_url,
        },
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}
