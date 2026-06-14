//! `GET /v1/join-requests` + `GET /v1/join-requests/{id}` — admin
//! read endpoints (M1.9.1).

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
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
        (status = 200, description = "Join request", body = JoinRequest),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Join request not found"),
    ),
)]
pub async fn show_join_request(
    _admin: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<JoinRequest>, AppError> {
    let req = get_join_request(&state.join_requests_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("join request not found: {id}")))?;
    Ok(Json(req))
}
