//! `POST /v1/join-requests/{id}/approve` + `/reject` — admin
//! decision endpoints (M1.10.1).
//!
//! Approve atomically writes the ACL row (`VtcRole::Member`),
//! the Member record, and the audit envelopes
//! (`JoinRequestApproved` + `MemberAdded`). The applicant_did is
//! already validated at submit time so the only failure modes
//! here are auth + duplicate-membership.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::{info, warn};
use uuid::Uuid;

use vti_common::audit::{AuditEvent, JoinRequestData, JoinRequestRejectedData};
use vti_common::error::AppError;

use crate::acl::VtcRole;
use crate::auth::AdminAuth;
use crate::ceremony::execute;
use crate::ceremony::{EffectOutcome, EffectPlan};
use crate::join::{JoinStatus, get_join_request, store_join_request};
use crate::server::AppState;

const REJECT_REASON_MAX: usize = 1024;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct DecideResponse {
    pub request_id: Uuid,
    pub status: String,
    /// Issued VMC (M2.12). Also pushed to the applicant's wallet over
    /// DIDComm on approve (best-effort); kept inline so the admin caller
    /// can still hand it over out-of-band if that delivery doesn't land.
    /// `None` on the reject path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmc: Option<JsonValue>,
    /// Issued role VEC. Same delivery story as `vmc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_vec: Option<JsonValue>,
}

// ---------------------------------------------------------------------------
// Approve
// ---------------------------------------------------------------------------

/// POST /join-requests/{id}/approve — admit the applicant + issue the VMC.
/// Auth: Admin.
#[utoipa::path(
    post, path = "/join-requests/{id}/approve", tag = "join-requests",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Join request id")),
    responses(
        (status = 201, description = "Applicant admitted; VMC + role VEC issued", body = DecideResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Join request not found"),
        (status = 409, description = "Request is not Pending, or applicant is already a member"),
    ),
)]
pub async fn approve(
    admin: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<DecideResponse>), AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let mut req = get_join_request(&state.join_requests_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("join request not found: {id}")))?;
    if req.status != JoinStatus::Pending {
        return Err(AppError::Conflict(format!(
            "join request {id} is {:?}, not Pending",
            req.status
        )));
    }
    // Effects: admit the applicant as a member. The ceremony effect
    // executor owns the duplicate-ACL guard, the ACL + Member writes,
    // and credential issuance (it is the single state-mutating seam —
    // see `ceremony::execute`). Approve wraps it with the join-request
    // status flip + audit. A duplicate ACL surfaces as the executor's
    // `Conflict` → 409, same as before.
    let plan = EffectPlan::Admit {
        subject: req.applicant_did.clone(),
        role: VtcRole::Member.to_string(),
        obligations: vec![],
    };
    let EffectOutcome::Admitted(creds) = execute::apply(&state, plan, &admin.0.did).await? else {
        return Err(AppError::Internal(
            "admit effect did not produce credentials".into(),
        ));
    };

    // Deliver the issued credentials to the applicant's wallet over DIDComm. A
    // referred-then-approved applicant presented over DIDComm and is not
    // connected now, so — like the auto-admit path — push the VMC + role VEC to
    // its mediator. Best-effort: the credentials are already issued and are also
    // returned inline below for out-of-band hand-off, so a delivery failure (no
    // mediator, unreachable holder) is logged, not fatal.
    if let Err(e) = crate::credentials::delivery::deliver_membership_credentials(
        &state,
        &req.applicant_did,
        &creds,
    )
    .await
    {
        warn!(
            request_id = %id,
            applicant = %req.applicant_did,
            error = %e,
            "membership-credential delivery failed on approve; credentials issued and returned inline"
        );
    }

    req.status = JoinStatus::Approved;
    store_join_request(&state.join_requests_ks, &req).await?;

    audit_writer
        .write(
            &admin.0.did,
            Some(&req.applicant_did),
            AuditEvent::JoinRequestApproved(JoinRequestData {
                request_id: id.to_string(),
                transport: "rest".to_string(),
            }),
        )
        .await?;
    // The MemberAdded + VmcIssued + VecIssued envelopes for the admit effect are
    // shared with the auto-admit path (see `super::audit`) so the two cannot
    // record divergent trails for the same effect.
    super::audit::emit_admit_audit(
        audit_writer,
        &admin.0.did,
        &req.applicant_did,
        &creds,
        &VtcRole::Member.to_string(),
        Some(id.to_string()),
    )
    .await?;

    info!(
        request_id = %id,
        applicant = %req.applicant_did,
        admin = %admin.0.did,
        status_list_index = creds.status_list_index,
        "join request approved"
    );

    Ok((
        StatusCode::OK,
        Json(DecideResponse {
            request_id: id,
            status: req.status.to_string(),
            vmc: Some(
                serde_json::to_value(&creds.vmc)
                    .map_err(|e| AppError::Internal(format!("serialise VMC for response: {e}")))?,
            ),
            role_vec: Some(
                serde_json::to_value(&creds.role_vec)
                    .map_err(|e| AppError::Internal(format!("serialise VEC for response: {e}")))?,
            ),
        }),
    ))
}

// ---------------------------------------------------------------------------
// Reject
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RejectBody {
    #[serde(default)]
    pub reason: Option<String>,
}

/// POST /join-requests/{id}/reject — reject a pending join request.
/// Auth: Admin.
#[utoipa::path(
    post, path = "/join-requests/{id}/reject", tag = "join-requests",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Join request id")),
    request_body = RejectBody,
    responses(
        (status = 201, description = "Join request rejected", body = DecideResponse),
        (status = 400, description = "Reject reason exceeds the length cap"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Join request not found"),
        (status = 409, description = "Request is not Pending"),
    ),
)]
pub async fn reject(
    admin: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<RejectBody>,
) -> Result<(StatusCode, Json<DecideResponse>), AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let reason = body.reason.unwrap_or_default();
    if reason.len() > REJECT_REASON_MAX {
        return Err(AppError::Validation(format!(
            "reject reason exceeds {REJECT_REASON_MAX} chars (got {})",
            reason.len(),
        )));
    }

    let mut req = get_join_request(&state.join_requests_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("join request not found: {id}")))?;
    if req.status != JoinStatus::Pending {
        return Err(AppError::Conflict(format!(
            "join request {id} is {:?}, not Pending",
            req.status
        )));
    }

    req.status = JoinStatus::Rejected;
    store_join_request(&state.join_requests_ks, &req).await?;

    audit_writer
        .write(
            &admin.0.did,
            Some(&req.applicant_did),
            AuditEvent::JoinRequestRejected(JoinRequestRejectedData {
                request_id: id.to_string(),
                reason: reason.clone(),
            }),
        )
        .await?;

    info!(
        request_id = %id,
        applicant = %req.applicant_did,
        admin = %admin.0.did,
        reason_present = !reason.is_empty(),
        "join request rejected"
    );

    Ok((
        StatusCode::OK,
        Json(DecideResponse {
            request_id: id,
            status: req.status.to_string(),
            vmc: None,
            role_vec: None,
        }),
    ))
}
