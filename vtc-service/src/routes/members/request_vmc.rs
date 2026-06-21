//! `POST /v1/members/{did}/request-vmc` — ask an active member to issue and
//! send their reciprocal VMC (member → community half of the membership pair).
//!
//! Admin-triggered. The VTC sends a `members/request-vmc/1.0` DIDComm message
//! to the member's agent naming the community DID the VMC must subject; the
//! member answers asynchronously with `members/vmc/1.0` (handled by
//! [`crate::members::inbound_vmc`]). This endpoint only dispatches the request —
//! it does not block on the member's reply.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use vta_sdk::protocols::members::{MEMBER_REQUEST_VMC_TYPE, RequestMemberVmcBody};
use vti_common::error::AppError;

use crate::auth::AdminAuth;
use crate::members::get_member;
use crate::server::AppState;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RequestVmcBody {
    /// Optional operator note ("renewal", "audit", …) relayed to the member.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RequestVmcResponse {
    pub member_did: String,
    /// Always `true` — the request was dispatched to the member's agent. The
    /// member replies asynchronously over `members/vmc/1.0`.
    pub requested: bool,
    /// DIDComm thread id of the dispatched request, for correlation.
    pub thread_id: String,
}

/// POST /members/{did}/request-vmc — dispatch a reciprocal-VMC request.
#[utoipa::path(
    post, path = "/members/{did}/request-vmc", tag = "members",
    params(("did" = String, Path, description = "Member DID")),
    request_body = RequestVmcBody,
    responses(
        (status = 202, description = "Request dispatched to the member", body = RequestVmcResponse),
        (status = 404, description = "No active member with that DID"),
        (status = 502, description = "Could not deliver the request to the member"),
    ),
)]
pub async fn request_vmc(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(member_did): Path<String>,
    Json(body): Json<RequestVmcBody>,
) -> Result<(StatusCode, Json<RequestVmcResponse>), AppError> {
    vti_common::identifier::validate_did("did", &member_did)?;

    // Only an active member has a membership edge to reciprocate.
    get_member(&state.members_ks, &member_did)
        .await?
        .filter(|m| !m.is_removed())
        .ok_or_else(|| AppError::NotFound(format!("no active member: {member_did}")))?;

    let community_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| {
            AppError::Internal("VTC DID not configured — cannot request a member VMC".into())
        })?;

    let thread_id = Uuid::new_v4().to_string();
    let request = RequestMemberVmcBody {
        community_did,
        reason: body.reason,
    };
    let request_body = serde_json::to_value(&request)
        .map_err(|e| AppError::Internal(format!("serialise request-vmc body: {e}")))?;

    crate::credentials::delivery::push_to_holder(
        &state,
        &member_did,
        &thread_id,
        MEMBER_REQUEST_VMC_TYPE,
        request_body,
    )
    .await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(RequestVmcResponse {
            member_did,
            requested: true,
            thread_id,
        }),
    ))
}
