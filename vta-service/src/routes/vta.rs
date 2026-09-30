use axum::extract::State;
use axum::response::IntoResponse;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

// `POST /vta/restart` was a REST route here. It is
// `vta/management/reload-services/1.0` now (`crate::trust_tasks::management`),
// dispatched on `/trust-tasks` like every other authenticated operation.

/// GET /metrics — Prometheus text format metrics. Auth: any role (including Monitor).
#[utoipa::path(
    get, path = "/metrics", tag = "vta",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Prometheus metrics text", content_type = "text/plain"),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn metrics(
    _auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let handle = state
        .metrics_handle
        .as_ref()
        .ok_or_else(|| AppError::Internal("metrics not initialized".into()))?;
    Ok(handle.render())
}
