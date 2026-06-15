use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::debug;
use vti_common::error::AppError;

use crate::auth::AdminAuth;
use crate::registry::{HealthStatus, list_sync_jobs};
use crate::server::AppState;

#[derive(Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    status: &'static str,
    version: &'static str,
    /// The VTC's own did:webvh, set during `vtc setup`. Kept on the
    /// unauth payload because it's the community's public identity —
    /// already served at `/.well-known/did.jsonl` and rendered by the
    /// default landing page. The `vta_did` / `mediator_url` /
    /// `mediator_did` fields used to live here too, but they're
    /// infrastructure detail (which VTA backs the community + the
    /// mediator's location) and now require auth — see
    /// [`DiagnosticsResponse`].
    #[serde(skip_serializing_if = "Option::is_none")]
    vtc_did: Option<String>,
}

/// `GET /health` — unauth, unthrottled liveness. Deliberately
/// minimal: `{status, version, vtc_did}`. It sits at the parent root
/// outside the governor, so it must not leak infrastructure topology
/// (the mediator URL was a free recon oracle). The DID/mediator
/// detail moved to the admin-gated [`diagnostics`] route.
pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    debug!("health check");
    let vtc_did = state.config.read().await.vtc_did.clone();
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        vtc_did,
    })
}

/// Phase 3 M3.8 — admin-gated diagnostics view.
///
/// Surfaces enough of the trust-registry reconciler's internal
/// state to debug "is sync stuck?" without shelling onto the
/// host. The fields are picked for *operator action*, not raw
/// metrics dump:
///
/// - `registry_status` — does the daemon think the registry
///   is reachable right now? Mirrors the same flag on
///   `GET /v1/community/profile` (M3.2).
/// - `queue_depth` — count of pending+InFlight rows. A
///   monotonically rising number means the registry is
///   refusing dispatch.
/// - `oldest_pending_age_seconds` — staleness of the
///   longest-waiting job. Drives the "≥1h behind →
///   degraded" SLI per spec §8.3.
/// - `rtbf_batched_count` — how many jobs are parked behind
///   the RTBF window. Lets operators verify the batch
///   protection is active without inspecting fjall.
/// - `failed_count` — terminal-failure rows the syncer gave
///   up on (`attempts > max_attempts` or
///   `RegistryError::Permanent`). These need operator
///   triage; the syncer won't retry them.
/// - `last_success_at` / `last_failure_at` / `last_error` —
///   replayed verbatim from the health probe state.
///
/// Diagnostics is **admin-gated**, not super-admin: ops staff
/// running on-call should be able to read this without
/// holding the super-admin role.
#[derive(Serialize, utoipa::ToSchema)]
pub struct DiagnosticsResponse {
    pub registry_status: String,
    pub queue_depth: u64,
    pub rtbf_batched_count: u64,
    pub failed_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_pending_age_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_failure_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// DID of the VTA the VTC was provisioned against. Moved here
    /// from the unauth `/health` payload (P3.7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vta_did: Option<String>,
    /// The mediator's HTTPS endpoint. Infrastructure topology —
    /// admin-gated so it's not a free unauth recon oracle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediator_url: Option<String>,
    /// The mediator's DID. Also surfaced (post-bootstrap) on the
    /// unauth `/v1/community/public-profile`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediator_did: Option<String>,
}

#[utoipa::path(
    get, path = "/health/diagnostics", tag = "health",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Trust-registry reconciler diagnostics", body = DiagnosticsResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn diagnostics(
    State(state): State<AppState>,
    _auth: AdminAuth,
) -> Result<Json<DiagnosticsResponse>, AppError> {
    let jobs = list_sync_jobs(&state.sync_queue_ks).await?;
    let now = Utc::now();
    let queue_depth = jobs
        .iter()
        .filter(|j| {
            matches!(
                j.state,
                crate::registry::SyncJobState::Pending | crate::registry::SyncJobState::InFlight
            )
        })
        .count() as u64;
    let rtbf_batched_count = jobs
        .iter()
        .filter(|j| j.rtbf_batched && j.state == crate::registry::SyncJobState::Pending)
        .count() as u64;
    let failed_count = jobs
        .iter()
        .filter(|j| j.state == crate::registry::SyncJobState::Failed)
        .count() as u64;
    // Oldest *dispatchable* pending job — RTBF-parked rows are
    // intentionally future-dated so they shouldn't count
    // against the "stuck" SLI.
    let oldest_pending_age_seconds = jobs
        .iter()
        .filter(|j| j.state == crate::registry::SyncJobState::Pending && j.next_attempt_at <= now)
        .map(|j| (now - j.created_at).num_seconds())
        .max();

    let snapshot = state.registry_health.snapshot().await;
    let registry_status = match snapshot.status {
        HealthStatus::Active => "active",
        HealthStatus::Degraded => "degraded",
    }
    .to_string();

    // Identity / mediator detail — folded down from the unauth
    // `/health` payload (P3.7), now only readable by an admin.
    let config = state.config.read().await;
    let vta_did = config.vta_did.clone();
    let (mediator_url, mediator_did) = config
        .messaging
        .as_ref()
        .map(|m| (Some(m.mediator_url.clone()), Some(m.mediator_did.clone())))
        .unwrap_or((None, None));
    drop(config);

    debug!(
        queue_depth,
        rtbf_batched_count,
        failed_count,
        registry_status = %registry_status,
        "diagnostics queried"
    );

    Ok(Json(DiagnosticsResponse {
        registry_status,
        queue_depth,
        rtbf_batched_count,
        failed_count,
        oldest_pending_age_seconds,
        last_success_at: snapshot.last_success_at,
        last_failure_at: snapshot.last_failure_at,
        last_error: snapshot.last_error,
        vta_did,
        mediator_url,
        mediator_did,
    }))
}
