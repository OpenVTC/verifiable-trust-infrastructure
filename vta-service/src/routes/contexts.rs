use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;

use vta_sdk::protocols::context_management::{
    create::CreateContextResultBody, delete::DeleteContextPreviewResultBody,
    list::ListContextsResultBody,
};

use crate::auth::{AdminAuth, AuthClaims, SuperAdminAuth};
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;
use crate::trust_tasks::{ContextDeleteOp, RequireStepUp};

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateContextRequest {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    /// Parent context path to nest under, or absent for a top-level context.
    #[serde(default)]
    pub parent: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateContextRequest {
    pub name: Option<String>,
    pub did: Option<String>,
    pub description: Option<String>,
    /// Set this context's policy (super-admin only). Omitted leaves it
    /// unchanged; send an unrestricted policy to clear constraints.
    #[serde(default)]
    pub context_policy: Option<vta_sdk::context_policy::ContextPolicy>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DeleteContextQuery {
    #[serde(default)]
    pub force: bool,
}

/// GET /contexts — list all contexts visible to the caller. Auth: any authenticated user.
#[utoipa::path(
    get, path = "/contexts", tag = "contexts",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Contexts visible to the caller", body = ListContextsResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn list_contexts_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<ListContextsResultBody>, AppError> {
    let result = operations::contexts::list_contexts(&state.contexts_ks, &auth, "rest").await?;
    Ok(Json(result))
}

/// POST /contexts — create a context. Auth: **admin** (the operation enforces
/// the finer gate — super-admin for a top-level context, admin-of-parent for a
/// sub-context).
#[utoipa::path(
    post, path = "/contexts", tag = "contexts",
    security(("bearer_jwt" = [])),
    request_body = CreateContextRequest,
    responses(
        (status = 201, description = "Context created", body = CreateContextResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn create_context_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateContextRequest>,
) -> Result<(StatusCode, Json<CreateContextResultBody>), AppError> {
    let result = operations::contexts::create_context(
        &state.contexts_ks,
        &auth.0,
        &req.id,
        req.name,
        req.description,
        req.parent,
        "rest",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

/// GET /contexts/{id} — retrieve a single context by ID. Auth: any authenticated user.
#[utoipa::path(
    get, path = "/contexts/{id}", tag = "contexts",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Context identifier")),
    responses(
        (status = 200, description = "Context record", body = CreateContextResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "Context not found"),
    ),
)]
pub async fn get_context_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<CreateContextResultBody>, AppError> {
    let result =
        operations::contexts::get_context_op(&state.contexts_ks, &auth, &id, "rest").await?;
    Ok(Json(result))
}

/// PATCH /contexts/{id} — update a context's name, DID, or description. Auth: Super Admin only.
#[utoipa::path(
    patch, path = "/contexts/{id}", tag = "contexts",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Context identifier")),
    request_body = UpdateContextRequest,
    responses(
        (status = 200, description = "Context updated", body = CreateContextResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
        (status = 404, description = "Context not found"),
    ),
)]
pub async fn update_context_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateContextRequest>,
) -> Result<Json<CreateContextResultBody>, AppError> {
    let result = operations::contexts::update_context(
        &state.contexts_ks,
        &auth.0,
        &id,
        operations::contexts::UpdateContextParams {
            name: req.name,
            did: req.did,
            description: req.description,
            context_policy: req.context_policy,
        },
        "rest",
    )
    .await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateDidRequest {
    pub did: String,
}

/// PUT /contexts/{id}/did — update the DID for a context. Auth: Admin with context access.
#[utoipa::path(
    put, path = "/contexts/{id}/did", tag = "contexts",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Context identifier")),
    request_body = UpdateDidRequest,
    responses(
        (status = 200, description = "Context DID updated", body = CreateContextResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Context not found"),
    ),
)]
pub async fn update_context_did_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateDidRequest>,
) -> Result<Json<CreateContextResultBody>, AppError> {
    let result =
        operations::contexts::update_context_did(&state.contexts_ks, &auth.0, &id, req.did, "rest")
            .await?;
    Ok(Json(result))
}

/// GET /contexts/{id}/delete-preview — preview resources affected by deleting a
/// context. Auth: **admin** (the operation enforces access to the context or an
/// ancestor — folder authority).
#[utoipa::path(
    get, path = "/contexts/{id}/delete-preview", tag = "contexts",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Context identifier")),
    responses(
        (status = 200, description = "Resources affected by deleting the context", body = DeleteContextPreviewResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Context not found"),
    ),
)]
pub async fn preview_delete_context_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<DeleteContextPreviewResultBody>, AppError> {
    let result = operations::contexts::preview_delete_context(
        &state.contexts_ks,
        &state.keys_ks,
        &state.acl_ks,
        &state.did_templates_ks,
        #[cfg(feature = "webvh")]
        &state.webvh_ks,
        &auth.0,
        &id,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// DELETE /contexts/{id} — delete a context and its subtree + resources. Auth:
/// **admin** (the operation enforces access to the context or an ancestor —
/// folder authority); `force` cascades through sub-contexts.
#[utoipa::path(
    delete, path = "/contexts/{id}", tag = "contexts",
    security(("bearer_jwt" = [])),
    params(
        ("id" = String, Path, description = "Context identifier"),
        DeleteContextQuery,
    ),
    responses(
        (status = 204, description = "Context deleted"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Context not found"),
    ),
)]
pub async fn delete_context_handler(
    auth: AdminAuth,
    // Deleting a context requires a stepped-up (AAL2) session when the
    // `context/delete` policy floor demands it.
    _step_up: RequireStepUp<ContextDeleteOp>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<DeleteContextQuery>,
) -> Result<StatusCode, AppError> {
    let ks = operations::Keyspaces::from_app_state(&state);
    operations::contexts::delete_context(&ks, &auth.0, &id, query.force, "rest").await?;
    Ok(StatusCode::NO_CONTENT)
}
