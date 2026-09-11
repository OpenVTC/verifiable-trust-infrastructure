//! `GET /v1/join-requests` + `GET /v1/join-requests/{id}` — admin
//! read endpoints (M1.9.1).

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use vti_common::error::AppError;
use vti_common::pagination::{Cursor, MAX_LIMIT, Paginated};

use crate::auth::AdminAuth;
use crate::join::{JoinRequest, JoinStatus, get_join_request, list_join_requests_paginated};
use crate::server::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema, utoipa::IntoParams)]
pub struct ListJoinRequestsQuery {
    /// Filter by status. Default `pending` — the operator-facing
    /// surface usually wants the work queue.
    pub status: Option<JoinStatus>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

/// GET /join-requests — list join requests (admin work queue). Auth: Admin.
#[utoipa::path(
    get, path = "/join-requests", tag = "join-requests",
    security(("bearer_jwt" = [])),
    params(ListJoinRequestsQuery),
    responses(
        (status = 200, description = "Paginated join requests", body = Paginated<JoinRequest>),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn list_join_requests(
    _admin: AdminAuth,
    State(state): State<AppState>,
    Query(query): Query<ListJoinRequestsQuery>,
) -> Result<Json<Paginated<JoinRequest>>, AppError> {
    let limit = query.limit.unwrap_or(50).clamp(1, MAX_LIMIT);
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    let audit_key = audit_writer.active_key().await?;

    let decoded_cursor = match &query.cursor {
        Some(s) => Some(Cursor::decode(s, &audit_key.key)?),
        None => None,
    };

    let mut page = list_join_requests_paginated(
        &state.join_requests_ks,
        &audit_key,
        decoded_cursor.as_ref(),
        limit,
    )
    .await?;

    // Filter to the requested status (default Pending).
    let filter_status = query.status.unwrap_or(JoinStatus::Pending);
    page.items.retain(|r| r.status == filter_status);

    Ok(Json(page))
}

/// GET /join-requests/{id} — show a single join request. Auth: Admin.
#[utoipa::path(
    get, path = "/join-requests/{id}", tag = "join-requests",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Join request id")),
    responses(
        (status = 200, description = "Join request", body = JoinRequestEnvelope),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Join request not found"),
    ),
)]
pub async fn show_join_request(
    _admin: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<JoinRequestEnvelope>, AppError> {
    let req = get_join_request(&state.join_requests_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("join request not found: {id}")))?;
    Ok(Json(JoinRequestEnvelope { request: req }))
}

/// The vetting facts a join request was decided on.
#[utoipa::path(
    get, path = "/join-requests/{id}/vetting", tag = "join-requests",
    operation_id = "joinRequestVettingShow",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Join request id")),
    responses(
        (status = 200, description = "The vetting facts recorded for the request; `vetting` is absent when none were", body = JoinRequestVettingResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Join request not found"),
    ),
)]
pub async fn show_join_request_vetting(
    _admin: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<JoinRequestVettingResponse>, AppError> {
    get_join_request(&state.join_requests_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("join request not found: {id}")))?;
    let Some(stored) = crate::join::get_vetting_facts(&state.join_requests_ks, id).await? else {
        return Ok(Json(JoinRequestVettingResponse {
            request_id: id,
            vetting: None,
        }));
    };
    let withdrawn: std::collections::HashSet<(String, String)> =
        crate::vetting::revocation::list_notices(&state.vetting_revocations_ks)
            .await?
            .into_iter()
            .map(|n| (n.issuer, n.statement_id))
            .collect();
    let facts = stored.facts;
    Ok(Json(JoinRequestVettingResponse {
        request_id: id,
        vetting: Some(JoinRequestVetting {
            criterion_id: facts.criterion_id,
            requirements_digest: facts.requirements_digest,
            applicant_digest_matches: facts.applicant_digest_matches,
            statements: facts
                .statements
                .into_iter()
                .map(|s| JoinRequestVettingStatement {
                    withdrawn_now: match (&s.issuer, &s.id) {
                        (Some(issuer), Some(sid)) => {
                            withdrawn.contains(&(issuer.clone(), sid.clone()))
                        }
                        _ => false,
                    },
                    id: s.id,
                    issuer: s.issuer,
                    verified: s.verified,
                    eligible: s.eligible,
                    revoked: s.revoked,
                    method: s.method,
                    declared_relationship: s.declared_relationship,
                    counted: s.counted,
                    failures: s.failures,
                })
                .collect(),
            distinct_counted_vetters: facts.distinct_counted_vetters,
            by_method: facts.by_method,
            commitments_consistent: facts.commitments_consistent,
            independence_ok: facts.independence_ok,
            invitation_required: facts.invitation_required,
            satisfied: facts.satisfied,
            needs: facts.needs,
            recorded_at: stored.recorded_at,
        }),
    }))
}

/// `GET /v1/join-requests/{id}/vetting` response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestVettingResponse {
    /// The join request.
    pub request_id: Uuid,
    /// What the community established about its vetting evidence. Absent when
    /// no criterion required vetting when it was decided, or the request
    /// predates recording.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vetting: Option<JoinRequestVetting>,
}

/// The vetting facts a join request was decided on — the policy's
/// `input.evidence.vetting`, in lowerCamelCase.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestVetting {
    /// The criterion whose requirements were applied.
    pub criterion_id: String,
    /// That criterion's `requirementsDigest` at the decision.
    pub requirements_digest: String,
    /// The applicant named that digest.
    pub applicant_digest_matches: bool,
    /// Every identity-vetting statement the presentation carried.
    pub statements: Vec<JoinRequestVettingStatement>,
    /// Distinct eligible vetters counted.
    pub distinct_counted_vetters: u32,
    /// Counted statements by method.
    pub by_method: std::collections::BTreeMap<String, u32>,
    /// All counted statements carry one identity commitment.
    pub commitments_consistent: bool,
    /// No declared-relationship cap is exceeded.
    pub independence_ok: bool,
    /// The requirements demanded an invitation.
    pub invitation_required: bool,
    /// Count, method floors, consistency and independence all held.
    pub satisfied: bool,
    /// What was still missing, in the `vetting:*` grammar.
    pub needs: Vec<String>,
    /// When the facts were recorded.
    pub recorded_at: chrono::DateTime<chrono::Utc>,
}

/// One presented statement, as the community saw it at the decision.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestVettingStatement {
    /// The statement `id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The issuer DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Proof, type, window and body verified.
    pub verified: bool,
    /// The issuer was an eligible vetter.
    pub eligible: bool,
    /// Withdrawn by its vetter before the decision.
    pub revoked: bool,
    /// Withdrawn by its vetter now — after the decision, if `revoked` is false.
    pub withdrawn_now: bool,
    /// `inPerson` / `video` / `priorAcquaintance`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The vetter's declared relationship to the applicant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_relationship: Option<String>,
    /// It counted toward the requirements.
    pub counted: bool,
    /// Why it did not count.
    pub failures: Vec<String>,
}

/// `{ request: … }` — the shape `vtc/join-requests/show/0.1` publishes.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestEnvelope {
    pub request: JoinRequest,
}
