use axum::Json;
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
