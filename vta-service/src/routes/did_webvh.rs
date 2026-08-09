use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use serde::Deserialize;

use vta_sdk::protocols::did_management::{
    create::{CreateDidWebvhBody, CreateDidWebvhResultBody},
    get::GetDidWebvhResultBody,
    list::ListDidsWebvhResultBody,
    servers::{
        ListWebvhServersResultBody, RegisterDidWithServerBody, RegisterDidWithServerResultBody,
        RegisterWebvhServerResultBody,
    },
    update::UpdateDidWebvhBody,
};

use crate::auth::{AdminAuth, AuthClaims, SuperAdminAuth};
use crate::error::AppError;
use crate::operations;
use crate::operations::did_webvh::{
    RegisterDidWithServerError, RegisterDidWithServerParams, RotateDidWebvhKeysOptions,
    UpdateDidWebvhResult, register_did_with_server,
};
use crate::server::AppState;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AddServerRequest {
    pub id: String,
    pub did: String,
    pub label: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListDidsQuery {
    pub context_id: Option<String>,
    pub server_id: Option<String>,
}

// -- Server routes --

/// POST /webvh/servers — register a webvh hosting server. Auth: super-admin.
#[utoipa::path(
    post, path = "/webvh/servers", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    request_body = AddServerRequest,
    responses(
        (status = 201, description = "Server registered", body = RegisterWebvhServerResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
    ),
)]
pub async fn add_server_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<AddServerRequest>,
) -> Result<(StatusCode, Json<RegisterWebvhServerResultBody>), AppError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let result = operations::did_webvh::register_webvh_server(
        &state.webvh_ks,
        &auth.0,
        &req.id,
        Some(&req.did),
        req.label,
        Some(did_resolver),
        "rest",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

/// GET /webvh/servers — list registered webvh hosting servers. Auth: any authenticated user.
#[utoipa::path(
    get, path = "/webvh/servers", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Registered servers", body = ListWebvhServersResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn list_servers_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<ListWebvhServersResultBody>, AppError> {
    let result = operations::did_webvh::list_webvh_servers(&state.webvh_ks, &auth, "rest").await?;
    Ok(Json(result))
}

/// `GET /webvh/servers/:id/domains` — relay the registered hosting
/// server's `/api/me/domains` view to the caller. Used by
/// `pnm did-mgmt list-domains` and by the interactive `--domain`
/// prompt in `pnm did-mgmt dids create` / `register`. Authentication
/// to the hosting server uses the VTA's own credentials.
#[utoipa::path(
    get, path = "/webvh/servers/{id}/domains", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Server identifier")),
    responses(
        (status = 200, description = "Caller-scoped hosting domains", body = vta_sdk::protocols::did_management::servers::ListWebvhServerDomainsResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "Server not found"),
    ),
)]
pub async fn list_server_domains_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<
    Json<vta_sdk::protocols::did_management::servers::ListWebvhServerDomainsResultBody>,
    AppError,
> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let config = state.config.read().await;
    let deps = operations::did_webvh::WebvhDeps::from_app_state(&state, did_resolver);
    let result = operations::did_webvh::list_webvh_server_domains(
        &deps,
        &auth,
        config.vta_did.as_deref(),
        &id,
    )
    .await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateServerRequest {
    pub label: Option<String>,
}

/// PATCH /webvh/servers/{id} — update a registered server's metadata. Auth: super-admin.
#[utoipa::path(
    patch, path = "/webvh/servers/{id}", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Server identifier")),
    request_body = UpdateServerRequest,
    responses(
        (status = 200, description = "Server updated", body = RegisterWebvhServerResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
        (status = 404, description = "Server not found"),
    ),
)]
pub async fn update_server_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateServerRequest>,
) -> Result<Json<RegisterWebvhServerResultBody>, AppError> {
    // `did: None` keeps this a label-only patch: the merged op returns
    // NotFound for an unknown id rather than creating one, so PATCH's
    // 404 contract is unchanged — and it needs no resolver, exactly as
    // before the merge.
    let result = operations::did_webvh::register_webvh_server(
        &state.webvh_ks,
        &auth.0,
        &id,
        None,
        req.label,
        None,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// DELETE /webvh/servers/{id} — remove a registered server. Auth: super-admin.
#[utoipa::path(
    delete, path = "/webvh/servers/{id}", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Server identifier")),
    responses(
        (status = 204, description = "Server removed"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
        (status = 404, description = "Server not found"),
    ),
)]
pub async fn remove_server_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    operations::did_webvh::remove_webvh_server(&state.webvh_ks, &auth.0, &id, "rest").await?;
    Ok(StatusCode::NO_CONTENT)
}

// -- DID routes --

/// POST /webvh/dids — create a new webvh DID. Auth: admin.
#[utoipa::path(
    post, path = "/webvh/dids", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    request_body = CreateDidWebvhBody,
    responses(
        (status = 201, description = "DID created", body = CreateDidWebvhResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn create_did_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<CreateDidWebvhBody>,
) -> Result<(StatusCode, HeaderMap, Json<CreateDidWebvhResultBody>), AppError> {
    let config = state.config.read().await;
    let params = body.into();
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let deps =
        operations::did_webvh::CreateDidWebvhDeps::from_app_state(&state, &config, did_resolver);
    let result = operations::did_webvh::create_did_webvh(&deps, &auth.0, params, "rest").await?;
    // Deprecated: superseded by the `vta/webvh/dids/create/1.0` Trust-Task.
    let headers = crate::deprecation::superseded(
        "POST /webvh/dids",
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0,
    );
    Ok((StatusCode::CREATED, headers, Json(result)))
}

/// GET /webvh/dids — list webvh DIDs with optional filters. Auth: any authenticated user.
#[utoipa::path(
    get, path = "/webvh/dids", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(ListDidsQuery),
    responses(
        (status = 200, description = "DID records", body = ListDidsWebvhResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn list_dids_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Query(query): Query<ListDidsQuery>,
) -> Result<(HeaderMap, Json<ListDidsWebvhResultBody>), AppError> {
    let result = operations::did_webvh::list_dids_webvh(
        &state.webvh_ks,
        &auth,
        query.context_id.as_deref(),
        query.server_id.as_deref(),
        "rest",
    )
    .await?;
    // Deprecated: superseded by the `vta/webvh/dids/list/1.0` Trust-Task.
    let headers = crate::deprecation::superseded(
        "GET /webvh/dids",
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_LIST_1_0,
    );
    Ok((headers, Json(result)))
}

/// GET /webvh/dids/{did} — retrieve a single webvh DID record. Auth: any authenticated user.
#[utoipa::path(
    get, path = "/webvh/dids/{did}", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "DID identifier")),
    responses(
        (status = 200, description = "DID record", body = GetDidWebvhResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "DID not found"),
    ),
)]
pub async fn get_did_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Query(params): Query<GetDidQuery>,
) -> Result<Json<GetDidWebvhResultBody>, AppError> {
    let result = operations::did_webvh::get_did_webvh(
        &state.webvh_ks,
        &auth,
        &did,
        "rest",
        params.include_log,
    )
    .await?;
    Ok(Json(result))
}

/// Query params for [`get_did_handler`]. Mirrors the folded
/// `dids/get/1.0` payload so REST can fetch record + log in one call
/// rather than needing the separate `/log` path.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDidQuery {
    #[serde(default)]
    pub include_log: bool,
}

/// GET /webvh/dids/{did}/log — retrieve the did.jsonl log for a DID. Auth: any authenticated user.
#[utoipa::path(
    get, path = "/webvh/dids/{did}/log", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "DID identifier")),
    responses(
        (status = 200, description = "DID record with its log", body = GetDidWebvhResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "DID not found"),
    ),
)]
pub async fn get_did_log_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<GetDidWebvhResultBody>, AppError> {
    // Kept as a convenience path even though its Trust Task folded into
    // `dids/get`: the response is a strict superset of the old
    // `{did, log}`, so existing REST callers are unaffected.
    let result =
        operations::did_webvh::get_did_webvh(&state.webvh_ks, &auth, &did, "rest", true).await?;
    Ok(Json(result))
}

/// `GET /did/{did}/log` — public, unauthenticated.
///
/// Returns the raw `did.jsonl` bytes for a DID the VTA knows. 404 if
/// unknown. Matches webvh's native design: DID logs are world-readable
/// (security is cryptographic via signatures + SCID anchoring, not
/// access-gated). Rate-limited via the `unauth_layer` at the router.
///
/// This is a snapshot of the log at provisioning time — once the
/// integration boots and publishes on its own webvh host, that copy
/// becomes the live source of truth. Use this endpoint for audit,
/// debugging, or republication fallback; not as a general DID
/// resolver. See `docs/02-vta/provision-integration.md` §"did.jsonl
/// retrieval" for the full semantics.
#[utoipa::path(
    get, path = "/did/{did}/log", tag = "did-webvh",
    params(("did" = String, Path, description = "DID identifier")),
    responses(
        (status = 200, description = "did.jsonl log", content_type = "text/jsonl"),
        (status = 404, description = "DID not found"),
    ),
)]
pub async fn get_did_log_public_handler(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<
    (
        axum::http::StatusCode,
        [(&'static str, &'static str); 1],
        String,
    ),
    AppError,
> {
    use axum::http::StatusCode;
    let log = crate::webvh_store::get_did_log(&state.webvh_ks, &did).await?;
    let log = log.ok_or_else(|| AppError::NotFound(format!("webvh DID log not found: {did}")))?;
    Ok((StatusCode::OK, [("content-type", "text/jsonl")], log))
}

/// DELETE /webvh/dids/{did} — delete a webvh DID. Auth: admin.
#[utoipa::path(
    delete, path = "/webvh/dids/{did}", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "DID identifier")),
    responses(
        (status = 204, description = "DID deleted"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "DID not found"),
    ),
)]
pub async fn delete_did_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<StatusCode, AppError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let vta_did = state.config.read().await.vta_did.clone();
    let deps = operations::did_webvh::WebvhDeps::from_app_state(&state, did_resolver);
    operations::did_webvh::delete_did_webvh(&deps, &auth.0, &did, vta_did.as_deref(), "rest")
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /contexts/{ctx_id}/dids/{scid}/update` — apply a generic
/// update to an existing webvh DID. The `ctx_id` path component is
/// validated against the DID's context inside the operation; mismatches
/// surface as 404 to avoid cross-context existence leaks.
#[utoipa::path(
    post, path = "/contexts/{ctx_id}/dids/{scid}/update", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(
        ("ctx_id" = String, Path, description = "Context identifier"),
        ("scid" = String, Path, description = "DID SCID"),
    ),
    request_body = UpdateDidWebvhBody,
    responses(
        (status = 200, description = "DID updated", body = UpdateDidWebvhResult),
        (status = 400, description = "Malformed request body"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "DID not found"),
    ),
)]
/// Takes the **wire** body, not the op-layer options.
///
/// Deserialising straight into `UpdateDidWebvhOptions` silently dropped
/// `expectedVersionId` — the wire body is camelCase, that struct is snake_case
/// with no aliases — so the optimistic-concurrency precondition never applied
/// to REST callers. A precondition that is accepted and ignored is worse than
/// one that is absent: it reads in the caller's source as though the lost
/// update were handled. Conversion goes through the same
/// `update_body_to_options` the trust-task dispatcher uses.
pub async fn update_did_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((_ctx_id, scid)): Path<(String, String)>,
    Json(body): Json<UpdateDidWebvhBody>,
) -> Result<Json<UpdateDidWebvhResult>, AppError> {
    // NOT YET GATED — see `docs/05-design-notes/approvals-convergence.md`.
    //
    // This route is the other half of the consent bypass, and closing it needs
    // one more step than the ACL and context routes did. The planner parses the
    // gated payload as `UpdateDidWithDid { did, .. }` and the consent digest is
    // taken over it, but this handler is addressed by **SCID**: gating on what
    // it holds would produce a digest that disagrees with the trust-task path's
    // for the very same update, so an approval obtained over one transport
    // could not be consumed over the other. Resolving the SCID to its DID first
    // is the fix, and it belongs with the change that can test it end to end
    // rather than bolted on here.
    let options = crate::trust_tasks::webvh::update_body_to_options(body)
        .map_err(|e| AppError::Validation(format!("invalid update body: {e:?}")))?;
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let vta_did = state.config.read().await.vta_did.clone();
    let deps = operations::did_webvh::WebvhDeps::from_app_state(&state, did_resolver);
    let result = operations::did_webvh::update_did_webvh(
        &deps,
        &auth.0,
        &scid,
        options,
        vta_did.as_deref(),
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// `POST /contexts/{ctx_id}/dids/{scid}/rotate-keys` — rotate every
/// verificationMethod's keys + drive an update. Mirrors
/// [`update_did_handler`].
#[utoipa::path(
    post, path = "/contexts/{ctx_id}/dids/{scid}/rotate-keys", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(
        ("ctx_id" = String, Path, description = "Context identifier"),
        ("scid" = String, Path, description = "DID SCID"),
    ),
    request_body = RotateDidWebvhKeysOptions,
    responses(
        (status = 200, description = "Keys rotated", body = UpdateDidWebvhResult),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "DID not found"),
    ),
)]
pub async fn rotate_did_keys_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((_ctx_id, scid)): Path<(String, String)>,
    Json(body): Json<RotateDidWebvhKeysOptions>,
) -> Result<Json<UpdateDidWebvhResult>, AppError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let vta_did = state.config.read().await.vta_did.clone();
    let deps = operations::did_webvh::WebvhDeps::from_app_state(&state, did_resolver);
    let result = operations::did_webvh::rotate_did_webvh_keys(
        &deps,
        &auth.0,
        &scid,
        body,
        vta_did.as_deref(),
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// `POST /webvh/dids/{did}/register-server` — promote a serverless
/// DID to a server-managed one. Auth: super-admin. The DID in the
/// path must match the body's `did` field; the body's `server_id`
/// must be a previously-registered server.
#[utoipa::path(
    post, path = "/webvh/dids/{did}/register-server", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "DID identifier")),
    request_body = RegisterDidWithServerBody,
    responses(
        (status = 200, description = "DID registered with server", body = RegisterDidWithServerResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
        (status = 404, description = "DID or server not found"),
    ),
)]
pub async fn register_did_with_server_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(body): Json<RegisterDidWithServerBody>,
) -> Result<Json<RegisterDidWithServerResultBody>, AppError> {
    if did != body.did {
        return Err(AppError::Validation(format!(
            "DID in path (`{did}`) does not match body `did` (`{}`)",
            body.did
        )));
    }
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let vta_did = state.config.read().await.vta_did.clone();
    let deps = operations::did_webvh::WebvhDeps::from_app_state(&state, did_resolver);
    let result = register_did_with_server(
        &deps,
        &auth.0,
        RegisterDidWithServerParams {
            did: body.did,
            server_id: body.server_id,
            force: body.force,
            domain: body.domain,
        },
        vta_did.as_deref(),
        "rest",
    )
    .await
    .map_err(map_register_err)?;
    Ok(Json(RegisterDidWithServerResultBody {
        did: result.did,
        server_id: result.server_id,
        log_entry_count: result.log_entry_count,
    }))
}

/// Map `RegisterDidWithServerError` onto `AppError` so the
/// existing route-error machinery surfaces an appropriate status
/// (404 for missing DID/server/log, 409 for already-server-managed,
/// 400 for malformed DID URLs, 500 otherwise).
fn map_register_err(e: RegisterDidWithServerError) -> AppError {
    use RegisterDidWithServerError as E;
    match e {
        E::Auth(msg) => AppError::Forbidden(msg),
        E::DidNotFound(msg) | E::ServerNotFound(msg) | E::LogMissing(msg) => {
            AppError::NotFound(msg)
        }
        E::AlreadyServerManaged { .. } | E::Conflict(_) => AppError::Conflict(e.to_string()),
        E::Transport(msg) => AppError::Internal(format!("publish: {msg}")),
        // Pass the host's typed rejection through untouched. Wrapping it in
        // `Internal` told the operator the VTA had failed when in fact the
        // hosting server had refused their request for a reason they can act
        // on. See `RegisterDidWithServerError::Publish`.
        E::Publish(e) => e,
        E::DidUrlParse { .. } => AppError::Validation(e.to_string()),
        E::Storage(msg) => AppError::Internal(msg),
    }
}
