//! `/v1/vetting/*` — the community-admin side of peer identity vetting.
//!
//! - `POST /v1/vetting/vetters` — name a member a vetter
//!   (`vtc/vetting/vetters/grant/0.1`). Auth: community Admin. The same task is
//!   dispatched as a Trust Task document for an admin on DIDComm or TSP; both
//!   go through [`crate::vetting::vetters::grant`]. A grant is withdrawn with
//!   `DELETE /v1/credentials/endorsements/{endorsementId}`.
//! - `GET /v1/vetting/vetters` — every vetter grant, with its member, validity,
//!   revocation, origin (automatic or manual) and the vetter's profile summary.
//! - `POST /v1/vetting/vetters/{memberDid}/resend` — deliver a vetter's live
//!   grant credential again (`vtc/vetting/vetters/resend/0.1`, which a vetter
//!   also sends for themselves).
//! - `GET`/`PUT /v1/vetting/auto-grant` — automatic vetter grants: the
//!   configuration and the last sweep.
//! - `GET /v1/vetting/revocations` — vetting statement withdrawal notices, with
//!   the admissions each one touches.
//!
//! The listing, auto-grant and revocations routes are admin REST with no Trust
//! Task of their own, so they are mounted without a binding.

use std::collections::{BTreeSet, HashMap};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;
use vta_sdk::protocols::vetting::{
    AutoGrantConfig, AutoGrantStatus, VetterGrantBody, VetterGrantListResponse,
    VetterGrantResponseBody, VetterResendResponseBody,
};
use vti_common::auth::{AdminAuth, AuthClaims};
use vti_common::error::AppError;

use crate::join::{JoinStatus, get_vetting_facts, list_join_requests};
use crate::members::storage::get_member;
use crate::server::AppState;
use crate::vetting::{auto_grant, revocation, vetters};

#[utoipa::path(
    post, path = "/vetting/vetters",
    operation_id = "vettingVetterGrant", tag = "vetting",
    security(("bearer_jwt" = [])),
    request_body = VetterGrantBody,
    responses(
        (status = 201, description = "Vetter role granted", body = VetterGrantResponseBody),
        (status = 200, description = "The member already holds a live vetter grant, which is returned", body = VetterGrantResponseBody),
        (status = 400, description = "Malformed body, or the member is not a current member"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a community admin"),
    ),
)]
pub async fn grant_vetter(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(body): Json<VetterGrantBody>,
) -> Result<(StatusCode, Json<VetterGrantResponseBody>), AppError> {
    let grant = vetters::grant(&state, &auth.did, &body).await?;
    let status = if grant.created() {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(grant.response)))
}

/// Every vetter grant, newest first.
#[utoipa::path(
    get, path = "/vetting/vetters",
    operation_id = "vettingVetterList", tag = "vetting",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Every vetter grant, newest first", body = VetterGrantListResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn list_vetters(
    _admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<VetterGrantListResponse>, AppError> {
    Ok(Json(VetterGrantListResponse {
        vetters: vetters::grant_rows(&state).await?,
    }))
}

/// Deliver a vetter's live grant credential again.
#[utoipa::path(
    post, path = "/vetting/vetters/{memberDid}/resend",
    operation_id = "vettingVetterResend", tag = "vetting",
    security(("bearer_jwt" = [])),
    params(("memberDid" = String, Path, description = "The vetter's member DID")),
    responses(
        (status = 200, description = "The credential was handed to the transport for delivery", body = VetterResendResponseBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a community admin"),
        (status = 404, description = "The member holds no live vetter grant whose credential the community kept"),
        (status = 503, description = "The delivery could not be handed to the transport"),
    ),
)]
pub async fn resend_vetter(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(member_did): Path<String>,
) -> Result<Json<VetterResendResponseBody>, AppError> {
    Ok(Json(
        vetters::resend_as_admin(&state, &auth.did, &member_did).await?,
    ))
}

/// The automatic vetter-grant configuration and the last sweep.
#[utoipa::path(
    get, path = "/vetting/auto-grant",
    operation_id = "vettingAutoGrantShow", tag = "vetting",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Configuration and last sweep", body = AutoGrantStatus),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn get_auto_grant(
    _admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<AutoGrantStatus>, AppError> {
    Ok(Json(auto_grant::status(&state).await?))
}

/// Replace the automatic vetter-grant configuration.
#[utoipa::path(
    put, path = "/vetting/auto-grant",
    operation_id = "vettingAutoGrantUpdate", tag = "vetting",
    security(("bearer_jwt" = [])),
    request_body = AutoGrantConfig,
    responses(
        (status = 200, description = "The stored configuration and the last sweep", body = AutoGrantStatus),
        (status = 400, description = "A value is out of bounds"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 503, description = "Audit writer not configured — change refused"),
    ),
)]
pub async fn put_auto_grant(
    admin: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<AutoGrantConfig>,
) -> Result<Json<AutoGrantStatus>, AppError> {
    Ok(Json(
        auto_grant::configure(&state, &admin.0.did, &body).await?,
    ))
}

/// Whether a withdrawn statement touches a standing membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum RevocationReviewState {
    /// No current member was admitted on the statement.
    NoAdmission,
    /// A current member was admitted with the statement counted: their
    /// admission rested on evidence its vetter has taken back.
    NeedsReview,
}

/// One withdrawal notice, and the admissions it touches.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VettingRevocationRow {
    /// The vetter who withdrew the statement.
    pub issuer: String,
    /// The statement's `id`.
    pub statement_id: String,
    /// The statement's `digestMultibase`.
    pub statement_digest_multibase: String,
    /// The vetter's reason, when given (`mistake`, `newInformation`,
    /// `keyCompromise`, `other`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When the community recorded the notice.
    pub recorded_at: DateTime<Utc>,
    /// Whether a current membership rests on the statement.
    pub review_state: RevocationReviewState,
    /// Approved join requests that counted the statement.
    pub affected_join_requests: Vec<Uuid>,
    /// Of their applicants, those who are current members.
    pub affected_members: Vec<String>,
}

/// `GET /v1/vetting/revocations` response: every notice, newest first.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VettingRevocationListResponse {
    /// The notices.
    pub revocations: Vec<VettingRevocationRow>,
}

/// Every vetting statement withdrawal notice, with the admissions it touches.
///
/// A notice is matched to the join requests whose recorded vetting facts
/// counted a statement with the notice's issuer and id. Review is not yet a
/// workflow: `needsReview` says an admin should look, and nothing records that
/// one did.
#[utoipa::path(
    get, path = "/vetting/revocations",
    operation_id = "vettingRevocationList", tag = "vetting",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Every withdrawal notice, newest first", body = VettingRevocationListResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn list_revocations(
    _admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<VettingRevocationListResponse>, AppError> {
    // (issuer, statement id) → approved requests that counted it.
    let mut counted_by: HashMap<(String, String), Vec<(Uuid, String)>> = HashMap::new();
    for request in list_join_requests(&state.join_requests_ks).await? {
        if request.status != JoinStatus::Approved {
            continue;
        }
        let Some(stored) = get_vetting_facts(&state.join_requests_ks, request.id).await? else {
            continue;
        };
        for statement in stored.facts.statements.iter().filter(|s| s.counted) {
            if let (Some(issuer), Some(id)) = (&statement.issuer, &statement.id) {
                counted_by
                    .entry((issuer.clone(), id.clone()))
                    .or_default()
                    .push((request.id, request.applicant_did.clone()));
            }
        }
    }

    let mut rows = Vec::new();
    for notice in revocation::list_notices(&state.vetting_revocations_ks).await? {
        let affected = counted_by
            .get(&(notice.issuer.clone(), notice.statement_id.clone()))
            .cloned()
            .unwrap_or_default();
        let mut members = BTreeSet::new();
        for (_, applicant) in &affected {
            if get_member(&state.members_ks, applicant)
                .await?
                .is_some_and(|m| m.removed_at.is_none())
            {
                members.insert(applicant.clone());
            }
        }
        rows.push(VettingRevocationRow {
            review_state: if members.is_empty() {
                RevocationReviewState::NoAdmission
            } else {
                RevocationReviewState::NeedsReview
            },
            affected_join_requests: affected.iter().map(|(id, _)| *id).collect(),
            affected_members: members.into_iter().collect(),
            reason: notice
                .reason
                .and_then(|r| serde_json::to_value(r).ok())
                .and_then(|v| v.as_str().map(str::to_string)),
            issuer: notice.issuer,
            statement_id: notice.statement_id,
            statement_digest_multibase: notice.statement_digest_multibase,
            recorded_at: notice.recorded_at,
        });
    }
    Ok(Json(VettingRevocationListResponse { revocations: rows }))
}
