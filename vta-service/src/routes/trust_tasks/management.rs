//! Management slice trust-task handler.
//!
//! Single URI today (`spec/vta/management/reload-services/1.0`) —
//! soft-reload of the VTA's internal service threads. Super-admin only.
//! Does NOT restart the process; calls `crate::server::trigger_restart`
//! on the in-process supervisor channel.

use axum::response::Response;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::vta_management::restart::{ReloadServicesBody, RestartResult};

use crate::audit::audit;
use crate::auth::AuthClaims;
use crate::server::AppState;

use super::helpers::{app_error_to_reject, parse_payload, success_response};

/// Handler for `spec/vta/management/reload-services/1.0`. Super-admin only.
pub(super) async fn handle_reload_services(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let _req: ReloadServicesBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    audit!(
        "vta.reload-services",
        actor = &auth.did,
        resource = "internal",
        outcome = "success"
    );

    crate::server::trigger_restart(&state.restart_tx);

    success_response(
        &doc,
        RestartResult {
            status: "restarting".to_string(),
        },
    )
}
