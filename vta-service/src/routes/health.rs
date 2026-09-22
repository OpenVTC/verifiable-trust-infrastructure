use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

/// Minimal health response for load balancers and monitoring.
/// Returned by the unauthenticated `GET /health` endpoint.
/// Does NOT expose deployment details to unauthenticated callers.
#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
}

/// Detailed health response with deployment information.
/// Returned by the authenticated `GET /health/details` endpoint.
#[derive(Serialize)]
pub struct HealthDetailsResponse {
    status: &'static str,
    version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    mediator_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mediator_did: Option<String>,
    #[cfg(feature = "tee")]
    #[serde(skip_serializing_if = "Option::is_none")]
    tee_status: Option<crate::tee::types::TeeStatus>,
    sealed: bool,
    storage_encrypted: bool,
    /// Whether this VTA advertises TSP (Trust Spanning Protocol) as a
    /// transport (`services.tsp`). TSP shares the same mediator as DIDComm
    /// (`mediator_did` above), so no separate endpoint is reported.
    tsp_enabled: bool,
    /// Present when this VTA's state derives from a backup restore: when, from
    /// which agent and kind of deployment, and what did not come back.
    /// VTI-VTA-051 — a node MUST be able to report that its current state
    /// derives from a restore, and from when.
    #[serde(skip_serializing_if = "Option::is_none")]
    restored: Option<RestoredFrom>,
}

/// The restore this VTA's state derives from.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoredFrom {
    applied_at: chrono::DateTime<chrono::Utc>,
    staged_at: chrono::DateTime<chrono::Utc>,
    staged_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_environment: Option<String>,
    target_environment: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    internal_keys_lost: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hosted_dids_detached: Vec<String>,
}

/// Minimal health check — no authentication required.
/// Returns only `{"status": "ok"}` to avoid leaking deployment details.
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// Detailed health check — requires authentication.
/// Exposes version, TEE status, seal state, and mediator configuration.
pub async fn health_details(
    _auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<HealthDetailsResponse>, AppError> {
    let config = state.config.read().await;
    let (mediator_url, mediator_did) = config
        .messaging
        .as_ref()
        .map(|m| (Some(m.mediator_url.clone()), Some(m.mediator_did.clone())))
        .unwrap_or((None, None));

    // Check seal status
    let sealed = crate::seal::get_seal(&state.acl_ks)
        .await
        .ok()
        .flatten()
        .is_some();

    // Check if storage encryption is active
    let storage_encrypted = state.keys_ks.is_encrypted();

    let tsp_enabled = config.services.tsp;

    let restored = vta_backup::restore::read_provenance(&state.backup_access().target())
        .await
        .ok()
        .flatten()
        .map(|p| RestoredFrom {
            applied_at: p.applied_at,
            staged_at: p.staged_at,
            staged_by: p.staged_by,
            source_did: p.source_did,
            source_environment: p.source_environment.map(|e| e.to_string()),
            target_environment: p.target_environment.to_string(),
            internal_keys_lost: p.internal_keys_lost,
            hosted_dids_detached: p.hosted_dids_detached,
        });

    Ok(Json(HealthDetailsResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        mediator_url,
        mediator_did,
        #[cfg(feature = "tee")]
        tee_status: state.tee.as_ref().map(|tc| tc.state.status.clone()),
        sealed,
        storage_encrypted,
        tsp_enabled,
        restored,
    }))
}
