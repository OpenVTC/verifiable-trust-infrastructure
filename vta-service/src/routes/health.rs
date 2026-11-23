use axum::Json;
use axum::extract::State;
use vti_common::health::ReadyResponse;

use crate::server::AppState;
use serde::Serialize;

/// Minimal health response for load balancers and monitoring.
/// Returned by the unauthenticated `GET /health` endpoint.
/// Does NOT expose deployment details.
///
/// The richer report is two Trust Tasks, not a route: `vta/health/details/0.1`
/// (the public flags, the same for every caller) and `vta/restore/status/0.1`
/// (version and restore record, administrators only). See
/// `trust_tasks::health`.
#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
}

/// Minimal health check — no authentication required.
/// Returns only `{"status": "ok"}` to avoid leaking deployment details.
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// `GET /readyz` — `200` while this VTA can serve requests, `503` while its
/// store is unavailable. See `vti_common::health` for what it checks and why
/// the mediator connection is not one of them.
pub async fn readyz(State(state): State<AppState>) -> ReadyResponse {
    state.readiness.check().await
}
