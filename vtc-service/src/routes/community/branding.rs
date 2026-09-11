//! `GET`/`PUT /v1/community/branding` — how the community presents itself to
//! an applicant's client, published as `branding` on
//! `join-requests/manifest/0.2`.
//!
//! Admin REST with no Trust Task of its own; mounted without a binding. The
//! body is [`CommunityBranding`], replaced whole.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use tracing::info;
use vta_sdk::protocols::join_requests::CommunityBranding;
use vti_common::audit::{AuditEvent, CommunityBrandingUpdatedData};
use vti_common::auth::{AdminAuth, AuthClaims};
use vti_common::error::AppError;

use crate::community::branding::{fields_changed, load_branding, store_branding};
use crate::server::AppState;

/// The community's branding; every member absent when none is set.
#[utoipa::path(
    get, path = "/community/branding",
    operation_id = "communityBrandingShow", tag = "community",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "The community's branding", body = CommunityBranding),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn get_branding(
    _auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<CommunityBranding>, AppError> {
    Ok(Json(load_branding(&state.community_ks).await?))
}

/// Replace the community's branding. An empty body clears it.
#[utoipa::path(
    put, path = "/community/branding",
    operation_id = "communityBrandingUpdate", tag = "community",
    security(("bearer_jwt" = [])),
    request_body = CommunityBranding,
    responses(
        (status = 200, description = "The stored branding", body = CommunityBranding),
        (status = 400, description = "A member breaks its bounds"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 503, description = "Audit writer not configured — change refused"),
    ),
)]
pub async fn put_branding(
    admin: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<CommunityBranding>,
) -> Result<Json<CommunityBranding>, AppError> {
    // Fail closed, as the profile route does: a change that cannot be audited
    // is not made.
    let writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured".into(),
        })?;
    let before = load_branding(&state.community_ks).await?;
    let stored = store_branding(&state.community_ks, &body).await?;
    let changed = fields_changed(&before, &stored);
    if !changed.is_empty() {
        writer
            .write(
                &admin.0.did,
                None,
                AuditEvent::CommunityBrandingUpdated(CommunityBrandingUpdatedData {
                    fields_changed: changed.clone(),
                }),
            )
            .await?;
        info!(fields_changed = ?changed, "community branding updated");
    }
    Ok(Json(stored))
}
