//! `GET`/`PUT /v1/community/join-discovery` — whether the join manifest
//! answers a caller this community cannot identify.
//!
//! Admin REST with no Trust Task of its own; mounted without a binding, like
//! [`super::branding`]. It is deliberately *not* a member of the community
//! profile: `vtc/community/profile/show/0.1` is a published schema with
//! `additionalProperties: false`, and this is an operational choice about how
//! one endpoint behaves rather than part of the community's published
//! description. See [`crate::community::join_discovery`].

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use tracing::info;
use vti_common::audit::{AuditEvent, CommunityJoinDiscoveryUpdatedData};
use vti_common::auth::{AdminAuth, AuthClaims};
use vti_common::error::AppError;

use crate::community::join_discovery::{JoinDiscovery, load_join_discovery, store_join_discovery};
use crate::server::AppState;

/// Whether the join manifest answers an unidentified caller.
#[utoipa::path(
    get, path = "/community/join-discovery",
    operation_id = "communityJoinDiscoveryShow", tag = "community",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "The community's join-discovery setting", body = JoinDiscovery),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn get_join_discovery(
    _auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<JoinDiscovery>, AppError> {
    Ok(Json(load_join_discovery(&state.community_ks).await?))
}

/// Replace the setting.
#[utoipa::path(
    put, path = "/community/join-discovery",
    operation_id = "communityJoinDiscoveryUpdate", tag = "community",
    security(("bearer_jwt" = [])),
    request_body = JoinDiscovery,
    responses(
        (status = 200, description = "The stored setting", body = JoinDiscovery),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 503, description = "Audit writer not configured — change refused"),
    ),
)]
pub async fn put_join_discovery(
    admin: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<JoinDiscovery>,
) -> Result<Json<JoinDiscovery>, AppError> {
    // Fail closed, as the profile and branding routes do: a change that cannot
    // be audited is not made. Who closed a community's requirements, and when,
    // is exactly the kind of change an operator later needs to account for.
    let writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured".into(),
        })?;
    let before = load_join_discovery(&state.community_ks).await?;
    let stored = store_join_discovery(&state.community_ks, &body).await?;
    if before != stored {
        writer
            .write(
                &admin.0.did,
                None,
                AuditEvent::CommunityJoinDiscoveryUpdated(CommunityJoinDiscoveryUpdatedData {
                    public: stored.public,
                }),
            )
            .await?;
        info!(public = stored.public, "community join discovery updated");
    }
    Ok(Json(stored))
}
