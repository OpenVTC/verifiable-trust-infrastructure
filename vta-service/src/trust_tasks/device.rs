//! `device/*` slice trust-task handlers.
//!
//! A `DeviceBinding` is the device-facing half of an `AclEntry`; these handlers
//! attach/refresh it on the caller's existing ACL entry. Auth: the caller
//! (`auth.did`, JWT-authenticated) acts on its **own** binding — registration
//! requires the DID to already be in the ACL (provision-integration +
//! acl/swap-key). See dtgwg `device/*`.

use super::helpers::TrustTaskOutcome;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::device::disable::v0_1 as disable_spec;
use trust_tasks_rs::specs::device::heartbeat::v0_1 as heartbeat_spec;
use trust_tasks_rs::specs::device::list::v0_1 as list_spec;
use trust_tasks_rs::specs::device::register::v0_1 as register_spec;
use trust_tasks_rs::specs::device::set_wake::v0_1 as set_wake_spec;

use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

use super::helpers::{TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, success_response};

/// `device/register/0.1` — the caller claims its DeviceBinding. The DID must
/// already be in the ACL; re-registration is refused.
pub(super) async fn handle_register(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
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
) -> TrustTaskOutcome {
    let payload: heartbeat_spec::Payload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    match operations::device::heartbeat_device(&state.acl_ks, auth, payload.platform).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `device/list/0.1` — list the maintainer's registered devices (filtered).
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let payload: list_spec::Payload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    match operations::device::list_devices(&state.acl_ks, auth, &payload).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `device/disable/0.1` — disable a device by `deviceId`.
pub(super) async fn handle_disable(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let payload: disable_spec::Payload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let device_id = payload.device_id.to_string();
    match operations::device::disable_device(&state.acl_ks, &state.audit_ks, auth, &device_id).await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `device/set-wake/0.1` — the device conveys its opaque push WakeHandle; the
/// VTA records it and computes/returns the trigger allowlist.
pub(super) async fn handle_set_wake(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let payload: set_wake_spec::Payload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let wake = payload
        .wake_handle
        .map(|h| (h.gateway.to_string(), h.handle.to_string()));
    let suggested = payload
        .suggested_triggers
        .unwrap_or_default()
        .iter()
        .map(|t| t.to_string())
        .collect::<Vec<_>>();
    let vta_did = state.config.read().await.vta_did.clone();
    // Captured before the move into set_wake_device so the (DIDComm-only)
    // best-effort gateway provisioning below can use them.
    #[cfg(feature = "didcomm")]
    let provision_inputs = (wake.clone(), vta_did.clone());
    match operations::device::set_wake_device(
        &state.acl_ks,
        &state.audit_ks,
        auth,
        wake,
        suggested,
        vta_did,
    )
    .await
    {
        Ok(body) => {
            // Best-effort: provision the wake handle's allowlist to the gateway
            // over DIDComm. Spawned so the device's set-wake returns without
            // blocking on the gateway round-trip; failure is logged, not
            // surfaced (the VTA holds the authoritative wake state — a reconcile
            // pass can re-provision). Only when DIDComm is built and the
            // `gateway` is a DID (a URL gateway is provisioned over HTTPS —
            // follow-up).
            #[cfg(feature = "didcomm")]
            provision_gateway(state, &provision_inputs.0, &provision_inputs.1, &body);
            success_response(&doc, body)
        }
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Send a `push/provision` to the gateway DID over DIDComm (spawned,
/// best-effort) carrying the VTA-owned allowlist the set-wake just computed.
/// The authcrypt sender authenticates the VTA to the gateway — no doc proof.
#[cfg(feature = "didcomm")]
fn provision_gateway(
    state: &AppState,
    wake: &Option<(String, String)>,
    vta_did: &Option<String>,
    body: &Value,
) {
    /// DIDComm message type that carries a Trust Task envelope in its body.
    const TRUST_TASK_ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";

    let Some((gateway, handle)) = wake.clone() else {
        return;
    };
    if !gateway.starts_with("did:") {
        return; // URL gateway → HTTPS provisioning (follow-up), not this path.
    }
    let Some(triggers) = body
        .get("triggerPolicy")
        .and_then(|p| p.get("allowedTriggers"))
        .cloned()
    else {
        return;
    };
    let provision = serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/push/provision/0.1",
        "issuer": vta_did,
        "recipient": gateway,
        "payload": { "handle": handle, "policy": { "allowedTriggers": triggers } },
    });
    let bridge = state.didcomm_bridge.clone();
    tokio::spawn(async move {
        match bridge
            .send_and_wait(
                &gateway,
                TRUST_TASK_ENVELOPE_TYPE,
                provision,
                TRUST_TASK_ENVELOPE_TYPE,
                vta_sdk::protocols::PROBLEM_REPORT_TYPE,
                15,
            )
            .await
        {
            Ok(_) => tracing::info!(gateway = %gateway, "push gateway allowlist provisioned"),
            Err(e) => {
                tracing::warn!(error = %e, gateway = %gateway, "gateway provision failed (best-effort)")
            }
        }
    });
}
