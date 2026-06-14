use axum::Json;
use axum::extract::{Query, State};

use vta_sdk::protocols::audit_management::list::{ListAuditLogsBody, ListAuditLogsResultBody};
use vta_sdk::protocols::audit_management::retention::{RetentionResultBody, UpdateRetentionBody};

use crate::auth::{AdminAuth, SuperAdminAuth};
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

// ---------- GET /audit/logs ----------

/// GET /audit/logs — query audit log entries with optional filters. Auth: Admin only.
#[utoipa::path(
    get, path = "/audit/logs", tag = "audit",
    security(("bearer_jwt" = [])),
    params(ListAuditLogsBody),
    responses(
        (status = 200, description = "Audit log entries", body = ListAuditLogsResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn list_audit_logs(
    auth: AdminAuth,
    State(state): State<AppState>,
    Query(params): Query<ListAuditLogsBody>,
) -> Result<Json<ListAuditLogsResultBody>, AppError> {
    let result =
        operations::audit::list_audit_logs(&state.audit_ks, &auth.0, &params, "rest").await?;
    Ok(Json(result))
}

// ---------- GET /audit/retention ----------

/// GET /audit/retention — retrieve the current audit log retention policy. Auth: Admin only.
#[utoipa::path(
    get, path = "/audit/retention", tag = "audit",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Current audit log retention policy", body = RetentionResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn get_retention(
    auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<RetentionResultBody>, AppError> {
    let result = operations::audit::get_retention(&state.config, &auth.0, "rest").await?;
    Ok(Json(result))
}

// ---------- PATCH /audit/retention ----------

/// PATCH /audit/retention — update the audit log retention period in days. Auth: Super Admin only.
#[utoipa::path(
    patch, path = "/audit/retention", tag = "audit",
    security(("bearer_jwt" = [])),
    request_body = UpdateRetentionBody,
    responses(
        (status = 200, description = "Updated audit log retention policy", body = RetentionResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
    ),
)]
pub async fn update_retention(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(body): Json<UpdateRetentionBody>,
) -> Result<Json<RetentionResultBody>, AppError> {
    let result = operations::audit::update_retention(
        &state.config,
        &state.audit_ks,
        &auth.0,
        body.retention_days,
        "rest",
    )
    .await?;
    Ok(Json(result))
}
