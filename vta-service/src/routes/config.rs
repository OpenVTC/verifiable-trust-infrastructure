use axum::Json;
use axum::extract::State;

use vta_sdk::protocols::vta_management::get_config::GetConfigResultBody;
use vta_sdk::protocols::vta_management::update_config::{UpdateConfigBody, UpdateConfigResultBody};

use crate::auth::{AuthClaims, SuperAdminAuth};
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

/// REST body for `PATCH /config`, identical to the canonical
/// `config/patch/0.1` payload — the same interface the DIDComm and TSP
/// transports carry, rather than a REST-shaped variant of it.
pub type UpdateConfigRequest = UpdateConfigBody;

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
    let result = operations::config::get_config(&state.config, &auth, None, "rest").await?;
    Ok(Json(result))
}

/// PATCH /config — patch registered configuration keys. Auth: Super Admin only.
///
/// `vta_did` is readable but **not** patchable: it is a registry key marked
/// immutable, so naming it comes back under `rejected` rather than being
/// written. See `operations::config` for why.
#[utoipa::path(
    patch, path = "/config", tag = "config",
    security(("bearer_jwt" = [])),
    request_body = UpdateConfigRequest,
    responses(
        (status = 200, description = "Applied / pending-restart / rejected keys", body = UpdateConfigResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
    ),
)]
pub async fn update_config(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<UpdateConfigResultBody>, AppError> {
    let result =
        operations::config::update_config(&state.config, &auth.0, req.overrides, "rest").await?;
    Ok(Json(result))
}
