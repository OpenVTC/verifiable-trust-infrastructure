//! `device/*` slice trust-task handlers.
//!
//! A `DeviceBinding` is the device-facing half of an `AclEntry`; these handlers
//! attach/refresh it on the caller's existing ACL entry. Auth: the caller
//! (`auth.did`, JWT-authenticated) acts on its **own** binding — registration
//! requires the DID to already be in the ACL (provision-integration +
//! acl/swap-key). See dtgwg `device/*`.

use axum::response::Response;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::device::heartbeat::v0_1 as heartbeat_spec;
use trust_tasks_rs::specs::device::register::v0_1 as register_spec;

use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

use super::helpers::{TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, success_response};

/// URIs handled by this slice. Aggregated by the dispatcher's parity harness.
#[allow(dead_code)] // consumed by the dispatcher's test-only parity harness
pub(super) const DISPATCHED_URIS: &[&str] = &[
    vta_sdk::trust_tasks::TASK_DEVICE_REGISTER_0_1,
    vta_sdk::trust_tasks::TASK_DEVICE_HEARTBEAT_0_1,
];

/// `device/register/0.1` — the caller claims its DeviceBinding. The DID must
/// already be in the ACL; re-registration is refused.
pub(super) async fn handle_register(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    let payload: register_spec::Payload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let consumer_kind = operations::device::wire_kind_to_internal(&payload.consumer_kind);
    let display_name = payload.display_name.to_string();
    let hpke_public_key = payload.hpke_public_key.as_ref().map(|k| k.to_string());
    // `attestation` and `keyCustody` are accepted but not yet acted on (spec:
    // policy input, not gate; verification is a follow-up).

    match operations::device::register_device(
        &state.acl_ks,
        &state.audit_ks,
        auth,
        consumer_kind,
        display_name,
        payload.platform,
        hpke_public_key,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `device/heartbeat/0.1` — periodic check-in; refreshes `lastSeenAt` (and
/// `platform` if changed) and returns server time + queued operations.
pub(super) async fn handle_heartbeat(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    let payload: heartbeat_spec::Payload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    match operations::device::heartbeat_device(&state.acl_ks, auth, payload.platform).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}
