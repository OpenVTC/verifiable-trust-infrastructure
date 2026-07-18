//! ACL slice trust-task handlers.
//!
//! Mirrors the legacy REST `/acl/*` routes one-for-one. Auth: Admin or
//! Initiator for list/create/get/delete; Admin-only for update.

use super::helpers::TrustTaskOutcome;
use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, TrustTask};
use vta_sdk::protocols::acl_management::create::CreateAclBody;
use vta_sdk::protocols::acl_management::delete::DeleteAclBody;
use vta_sdk::protocols::acl_management::get::GetAclBody;
use vta_sdk::protocols::acl_management::list::ListAclBody;
use vta_sdk::protocols::acl_management::swap::SwapKeyBody;
use vta_sdk::protocols::acl_management::update::UpdateAclBody;

use crate::acl::Role;
use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations;
use crate::operations::step_up::{StepUpDecision, op, resolve_step_up};
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, reject_with, success_response,
};

/// Handler for `spec/vta/acl/list/1.0`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
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
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    // Step-up (acl/grant floor) is enforced centrally by the PDP gate.
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
        operations::acl::approve_scope_from_wire(req.approve_all_contexts, req.approve_contexts),
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
) -> TrustTaskOutcome {
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
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    // Step-up (acl/change-role floor) is enforced centrally by the PDP gate.
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
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    // Step-up (acl/revoke floor) is enforced centrally by the PDP gate.
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

/// Handler for the canonical `acl/swap-key/0.1` Trust Task — self-service
/// rotation of the caller's own ACL entry onto a new subject DID. Consolidates
/// the bespoke REST `/acl/swap` handler and the DIDComm `handle_swap_acl` onto
/// the shared dispatcher (so it works over REST, DIDComm, and TSP identically).
///
/// No `require_manage()`: the caller only moves their own grant. The
/// transport-authenticated sender (REST bearer / DIDComm authcrypt / TSP VID)
/// is bound to `currentSubject`; the `link_proof` VP-JWT proves control of
/// `newSubject`.
pub(super) async fn handle_swap_key(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: SwapKeyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // The authenticated caller must equal the declared currentSubject — stops a
    // sender from claiming to rotate someone else's entry.
    if req.current_subject != auth.did {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: format!(
                    "acl/swap-key: currentSubject {} does not equal authenticated caller {}",
                    req.current_subject, auth.did
                ),
            },
        );
    }

    // Step-up floor WITH the non-escalating carve-out (swap-key is self-service).
    // Deliberately NOT the escalating `require_step_up` helper: with the default
    // no-floor policy this resolves to `Allow`, so AAL1 sender-authenticated
    // transports (DIDComm/TSP) proceed. A floor that genuinely requires step-up
    // rejects here with guidance to use the REST session (which can reach AAL2).
    if !matches!(
        resolve_step_up(
            &state.config,
            &state.acl_ks,
            op::ACL_SWAP_KEY,
            &auth.did,
            true, // swap-key is non-escalating
        )
        .await,
        StepUpDecision::Allow
    ) {
        return reject_with(
            &doc,
            RejectReason::TaskFailed {
                reason: "auth:step_up_required".to_string(),
                details: Some(json!({
                    "requiredAcr": "aal2",
                    "reason": "acl/swap-key requires a stepped-up (AAL2) session under this \
                               VTA's step-up policy. Sender-authenticated transports \
                               (DIDComm/TSP) are AAL1 and cannot be elevated in-band — perform \
                               this self-service rotation over the authenticated REST session.",
                })),
            },
        );
    }

    let did_resolver = match state.did_resolver.as_ref() {
        Some(r) => r,
        None => {
            return app_error_to_reject(
                &doc,
                AppError::Internal("DID resolver not available".into()),
            );
        }
    };
    let vta_did = match state.config.read().await.vta_did.clone() {
        Some(v) => v,
        None => {
            return app_error_to_reject(&doc, AppError::Internal("VTA DID not configured".into()));
        }
    };

    match operations::acl::swap_acl(
        &state.acl_ks,
        &state.audit_ks,
        auth,
        &req.link_proof,
        did_resolver,
        &vta_did,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(result) => {
            // Cross-check the declared newSubject matches the VP holder the
            // operation actually verified (defence-in-depth over the proof).
            if req.new_subject != result.did {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: format!(
                            "acl/swap-key: newSubject {} does not match verified VP holder {}",
                            req.new_subject, result.did
                        ),
                    },
                );
            }
            success_response(&doc, result)
        }
        Err(e) => app_error_to_reject(&doc, e),
    }
}
