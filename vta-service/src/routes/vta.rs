use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::Serialize;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

#[derive(Serialize, utoipa::ToSchema)]
pub struct RestartResponse {
    status: &'static str,
}

/// Trigger a soft restart of the VTA.
///
/// All service threads (REST, DIDComm, storage) are shut down and
/// re-initialized with the current config and seed. Admin role required.
pub async fn restart(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<RestartResponse>, AppError> {
    auth.require_super_admin()?;

    // Log the restart request before triggering
    let _ = crate::audit::record(
        &state.audit_ks,
        "vta.restart",
        &auth.did,
        None,
        "success",
        Some("rest"),
        None,
    )
    .await;

    crate::server::trigger_restart(&state.restart_tx);

    Ok(Json(RestartResponse {
        status: "restarting",
    }))
}

/// GET /metrics — Prometheus text format metrics. Auth: any role (including Monitor).
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
