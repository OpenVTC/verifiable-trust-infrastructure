//! Management slice trust-task handler.
//!
//! Single URI today (`spec/vta/management/reload-services/1.0`) —
//! soft-reload of the VTA's internal service threads. Super-admin only.
//! Does NOT restart the process; calls `crate::server::trigger_restart`
//! on the in-process supervisor channel.

use super::helpers::TrustTaskOutcome;
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
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let _req: ReloadServicesBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Both forms, and they are not redundant — the same split `auth.rs`
    // documents for `session.revoke`.
    //
    // The `audit!` macro emits a `tracing` event on the `audit` target: a log
    // line. It does NOT reach the `AuditSink`, so nothing it records appears in
    // `audit/list` or in an operator's external sink. This handler had only the
    // macro, so a restart of the agent — every open session dropped, every
    // counterparty disconnected — was absent from the queryable trail. The
    // audit-coverage census could not see it either, because the task was
    // unspecced and therefore undriven, until #347.
    //
    // Recorded BEFORE `trigger_restart`, which is the whole reason the ordering
    // is worth a comment: the restart tears down the runtime this write is
    // running in. Recording after it is a write racing its own process going
    // away, and the failure mode is exactly the one this row exists to prevent
    // — a restart with nothing to show it happened.
    audit!(
        "vta.reload-services",
        actor = &auth.did,
        resource = "internal",
        outcome = "success"
    );
    if let Err(e) = crate::audit::record_with_detail(
        &state.audit_sink,
        "vta.reload-services",
        &auth.did,
        Some("internal"),
        "success",
        Some(super::helpers::TRANSPORT_TRUST_TASK),
        None,
        Some("transports restarting; all open sessions dropped"),
    )
    .await
    {
        tracing::warn!(error = %e, "audit record failed for vta.reload-services");
    }

    crate::server::trigger_restart(&state.restart_tx);

    success_response(
        &doc,
        RestartResult {
            status: "restarting".to_string(),
        },
    )
}
