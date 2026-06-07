//! Passkey-VM slice trust-task handlers.
//!
//! **Feature-gated** — requires both `webvh` (DID-doc mutation + log
//! entries) AND `didcomm` (mediator push for the updated DID). The
//! whole module is `#![cfg(all(feature = "webvh", feature = "didcomm"))]`
//! at the top; mod.rs's `mod passkey_vms;` declaration carries the
//! same gate. URIs are still declared in vta-sdk unconditionally — the
//! parity harness uses `KNOWN_FEATURE_GATED_URIS` to recognise them
//! when this module isn't compiled.
//!
//! See `docs/05-design-notes/trust-task-feature-gating.md` for the
//! convention. This module is the worked example.
//!
//! Auth: Admin role on the DID's context for every handler. Enforced
//! inside the operations layer (`operations::passkey_vms::*` calls
//! `auth.require_admin` or equivalent).

#![cfg(all(feature = "webvh", feature = "didcomm"))]

use axum::response::Response;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::did_management::passkey_vms::{
    EnrollPasskeyChallengeBody, EnrollPasskeySubmitBody, ListPasskeyVmsBody, RevokePasskeyVmBody,
    RevokePasskeyVmResponse,
};

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

use super::helpers::{TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, success_response};

/// URIs handled by this slice. Aggregated by the dispatcher's parity
/// harness — see the feature-gating convention in
/// `docs/05-design-notes/trust-task-feature-gating.md`.
#[allow(dead_code)] // consumed by the dispatcher's test-only parity harness
pub(super) const DISPATCHED_URIS: &[&str] = &[
    // Canonical 0.1 + retained pre-spec 1.0 (dual-accept; identical
    // payloads, reply echoes the request version).
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_CHALLENGE_0_1,
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_SUBMIT_0_1,
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_LIST_0_1,
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_REVOKE_0_1,
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_CHALLENGE_1_0,
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_SUBMIT_1_0,
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_LIST_1_0,
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_REVOKE_1_0,
];

/// Handler for `spec/vta/passkey-vms/enroll-challenge/1.0`. Admin only
/// (enforced by the operation function).
pub(super) async fn handle_enroll_challenge(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    let req: EnrollPasskeyChallengeBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let config = state.config.read().await;
    match operations::passkey_vms::start_enrollment(
        &state.webvh_ks,
        &state.passkey_vms_ks,
        &config,
        auth,
        &req.did,
        req.label,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, AppError::from(e)),
    }
}

/// Handler for `spec/vta/passkey-vms/enroll-submit/1.0`. Admin only
/// (enforced by the operation function). Appends the new VM to the
/// DID document via a WebVH LogEntry; pushes the update to the
/// configured mediator.
pub(super) async fn handle_enroll_submit(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    let req: EnrollPasskeySubmitBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let did_resolver = match state.did_resolver.as_ref() {
        Some(r) => r,
        None => {
            return app_error_to_reject(
                &doc,
                AppError::Internal("DID resolver not available".into()),
            );
        }
    };
    let vta_did = state.config.read().await.vta_did.clone();
    let config = state.config.read().await.clone();
    match operations::passkey_vms::finish_enrollment(
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &state.passkey_vms_ks,
        &*state.seed_store,
        auth,
        req,
        did_resolver,
        &state.didcomm_bridge,
        vta_did.as_deref(),
        &state.webvh_auth_locks,
        &config,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, AppError::from(e)),
    }
}

/// Handler for `spec/vta/passkey-vms/list/1.0`. Admin only (enforced
/// by the operation function).
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    let req: ListPasskeyVmsBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::passkey_vms::list_passkeys(&state.webvh_ks, auth, &req.did).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, AppError::from(e)),
    }
}

/// Handler for `spec/vta/passkey-vms/revoke/1.0`. Admin only (enforced
/// by the operation function). Removes the VM via a WebVH LogEntry
/// and pushes the update to the mediator.
pub(super) async fn handle_revoke(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    let req: RevokePasskeyVmBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let did_resolver = match state.did_resolver.as_ref() {
        Some(r) => r,
        None => {
            return app_error_to_reject(
                &doc,
                AppError::Internal("DID resolver not available".into()),
            );
        }
    };
    let vta_did = state.config.read().await.vta_did.clone();
    match operations::passkey_vms::revoke_passkey(
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &*state.seed_store,
        auth,
        &req.did,
        &req.fragment,
        did_resolver,
        &state.didcomm_bridge,
        vta_did.as_deref(),
        &state.webvh_auth_locks,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(()) => success_response(&doc, RevokePasskeyVmResponse::default()),
        Err(e) => app_error_to_reject(&doc, AppError::from(e)),
    }
}
