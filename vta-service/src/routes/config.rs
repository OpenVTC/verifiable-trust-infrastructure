use axum::Json;
use axum::extract::State;
use serde::Deserialize;

use vta_sdk::protocols::vta_management::get_config::GetConfigResultBody;

use crate::auth::{AuthClaims, SuperAdminAuth};
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateConfigRequest {
    pub vta_did: Option<String>,
    pub vta_name: Option<String>,
    pub public_url: Option<String>,
}

/// GET /config — retrieve the current VTA configuration. Auth: any authenticated user.
#[utoipa::path(
    get, path = "/config", tag = "config",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Current VTA configuration", body = GetConfigResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn get_config(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<GetConfigResultBody>, AppError> {
    let result = operations::config::get_config(&state.config, &auth, "rest").await?;
    Ok(Json(result))
}

/// PATCH /config — update VTA name, DID, or public URL. Auth: Super Admin only.
#[utoipa::path(
    patch, path = "/config", tag = "config",
    security(("bearer_jwt" = [])),
    request_body = UpdateConfigRequest,
    responses(
        (status = 200, description = "Updated VTA configuration", body = GetConfigResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
    ),
)]
pub async fn update_config(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<GetConfigResultBody>, AppError> {
    let result = operations::config::update_config(
        &state.config,
        &auth.0,
        operations::config::UpdateConfigParams {
            vta_did: req.vta_did,
            vta_name: req.vta_name,
            public_url: req.public_url,
        },
        "rest",
    )
    .await?;
    Ok(Json(result))
}
