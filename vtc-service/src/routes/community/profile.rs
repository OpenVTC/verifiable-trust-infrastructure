//! `GET / PUT /v1/community/profile` handlers.
//!
//! Per spec §5.1:
//!
//! - **GET**: any authenticated session may read. Returns 404
//!   `community_not_initialised` when no profile has been written
//!   yet (pre-bootstrap state).
//! - **PUT**: requires `Admin` role. Rejects changes to
//!   `community_did` (immutable). Emits a `CommunityProfileUpdated`
//!   audit event listing only the field names that actually changed.
//!
//! The trust-task validation happens in
//! [`crate::routes::router`]'s `route_with_task` layer; reaching a
//! handler implies the header matched.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::info;
use vti_common::audit::{AuditEvent, CommunityProfileUpdatedData};
use vti_common::auth::{AdminAuth, AuthClaims};
use vti_common::error::AppError;

use crate::community::{CommunityProfile, CommunityProfileUpdate, load_profile, store_profile};
use crate::registry::HealthStatus;
use crate::server::AppState;

/// GET response shape.
///
/// Wraps the persisted [`CommunityProfile`] + adds the live
/// `registryStatus` field surfaced by Phase 3 M3.2.
/// `registry_status` is read from `AppState` at request time,
/// not persisted on the profile row.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct CommunityProfileResponse {
    /// The persisted profile fields. Flattened on the wire so
    /// existing consumers see no shape change.
    #[serde(flatten)]
    pub profile: CommunityProfile,
    /// Trust-registry reachability — `"active"` when the last
    /// health probe succeeded, `"degraded"` otherwise (probe
    /// never ran, last probe failed, or `registry.url` is
    /// unset). Spec §8.1.
    pub registry_status: HealthStatus,
}

/// Public read shape — the curated subset of [`CommunityProfile`]
/// exposed unauthenticated at `GET /v1/community/public-profile`.
///
/// Drops `extensions` (operator-defined JSON, not guaranteed
/// public-safe) and `registryStatus` (operational telemetry that
/// belongs behind admin auth). Adds `mediator_did` so the default
/// landing page can render the community's full identity in one
/// fetch.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct PublicCommunityProfile {
    pub community_did: String,
    pub name: String,
    pub description: String,
    pub logo_url: Option<String>,
    pub public_url: Option<String>,
    pub contact_email: Option<String>,
    pub language: String,
    pub created_at: DateTime<Utc>,
    /// The community's DIDComm mediator DID, if one is configured.
    /// Sourced from the live daemon config (same as `/health`), not
    /// the persisted profile row.
    pub mediator_did: Option<String>,
}

/// Public GET handler. Trust-Task-exempt, no auth. Returns only the
/// curated subset of profile fields a visitor's browser should see.
/// GET /community/public-profile — curated public community profile.
/// Public, unauthenticated.
#[utoipa::path(
    get, path = "/community/public-profile", tag = "community",
    responses(
        (status = 200, description = "Public community profile", body = PublicCommunityProfile),
        (status = 404, description = "Community profile not initialised"),
    ),
)]
pub async fn get_public_profile(
    State(state): State<AppState>,
) -> Result<Json<PublicCommunityProfile>, AppError> {
    let profile = load_profile(&state.community_ks)
        .await?
        .ok_or_else(|| AppError::NotFound("community profile not initialised".into()))?;
    let mediator_did = state
        .config
        .read()
        .await
        .messaging
        .as_ref()
        .map(|m| m.mediator_did.clone());
    Ok(Json(PublicCommunityProfile {
        community_did: profile.community_did,
        name: profile.name,
        description: profile.description,
        logo_url: profile.logo_url,
        public_url: profile.public_url,
        contact_email: profile.contact_email,
        language: profile.language,
        created_at: profile.created_at,
        mediator_did,
    }))
}

/// GET handler. Returns the singleton profile + the live
/// trust-registry status.
/// GET /community/profile — full community profile + live registry status.
/// Auth: any authenticated session.
#[utoipa::path(
    get, path = "/community/profile", tag = "community",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Community profile + registry status", body = CommunityProfileResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "Community profile not initialised"),
    ),
)]
pub async fn get_profile(
    _auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<CommunityProfileResponse>, AppError> {
    let profile = load_profile(&state.community_ks)
        .await?
        .ok_or_else(|| AppError::NotFound("community profile not initialised".into()))?;
    let registry_status = state.registry_health.status().await;
    Ok(Json(CommunityProfileResponse {
        profile,
        registry_status,
    }))
}

/// PUT response shape — echoes the updated profile + the list of
/// fields that actually changed (operator-friendly + powers the
/// audit event emitter that lands alongside this in a follow-up).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct UpdateProfileResponse {
    pub profile: CommunityProfile,
    pub fields_changed: Vec<String>,
}

/// PUT handler. Admin-only. Refuses changes to `community_did`.
///
/// Emits a `CommunityProfileUpdated` audit event keyed to the
/// calling admin's real DID. Audit is fail-closed: a change that
/// can't be recorded (no `AuditWriter`) returns 503 rather than
/// persisting silently — matching the `/v1/admin/config` doors so
/// auditability doesn't depend on which surface the admin used.
/// PUT /community/profile — update the community profile. Auth: Admin.
/// Refuses changes to the immutable `community_did`.
#[utoipa::path(
    put, path = "/community/profile", tag = "community",
    security(("bearer_jwt" = [])),
    request_body = CommunityProfileUpdate,
    responses(
        (status = 200, description = "Updated profile + the fields that changed", body = UpdateProfileResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Community profile not initialised"),
        (status = 503, description = "Audit writer not configured — change refused"),
    ),
)]
pub async fn put_profile(
    admin: AdminAuth,
    State(state): State<AppState>,
    Json(update): Json<CommunityProfileUpdate>,
) -> Result<(StatusCode, Json<UpdateProfileResponse>), AppError> {
    let mut profile = load_profile(&state.community_ks).await?.ok_or_else(|| {
        AppError::NotFound("community profile not initialised — cannot PUT before bootstrap".into())
    })?;

    let fields_changed = update.apply(&mut profile)?;

    if fields_changed.is_empty() {
        // Nothing changed — return 200 with the existing profile.
        // PUT semantics tolerate idempotent no-ops.
        return Ok((
            StatusCode::OK,
            Json(UpdateProfileResponse {
                profile,
                fields_changed,
            }),
        ));
    }

    // Fail-closed: refuse to persist a change we can't audit.
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured".into(),
        })?;

    store_profile(&state.community_ks, &profile).await?;
    info!(
        community_did = %profile.community_did,
        fields_changed = ?fields_changed,
        "community profile updated"
    );

    audit_writer
        .write(
            &admin.0.did,
            None,
            AuditEvent::CommunityProfileUpdated(CommunityProfileUpdatedData {
                fields_changed: fields_changed.clone(),
            }),
        )
        .await?;

    Ok((
        StatusCode::OK,
        Json(UpdateProfileResponse {
            profile,
            fields_changed,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // Behavioural coverage lives in `tests/community_profile.rs` — those
    // exercise the full router stack (Trust-Task header, AdminAuth
    // extractor, JSON body) via `Router::oneshot`. Unit tests for the
    // underlying storage + patch semantics live in
    // `crate::community::profile::tests`.
}
