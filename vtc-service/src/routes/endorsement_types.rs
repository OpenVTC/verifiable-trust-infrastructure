//! `/v1/endorsement-types/*` — operator-uploaded endorsement
//! type registry (Phase 4 M4.8.1; D4 planning review).
//!
//! Three admin-gated endpoints:
//!
//! - `POST /v1/endorsement-types` — register a type.
//! - `GET /v1/endorsement-types` — paginated list.
//! - `DELETE /v1/endorsement-types/{uri}` — refuses while at
//!   least one live endorsement still references the type.
//!
//! ## Reserved type URIs
//!
//! `"CommunityRole"` is reserved by the workspace (VEC-
//! managed role grants). The registrar refuses to register
//! it; the issuance path can't see it on disk either way.
//!
//! ## URI encoding on the wire
//!
//! The `DELETE /v1/endorsement-types/{uri}` path parameter
//! is URL-decoded by axum before reaching the handler. The
//! storage layer percent-encodes again before forming the
//! fjall key — keeps colons and slashes in operator-supplied
//! URIs from colliding with the keyspace prefix discipline.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::info;
use vti_common::audit::{AuditEvent, EndorsementTypeDeletedData, EndorsementTypeRegisteredData};
use vti_common::auth::AdminAuth;
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, Paginated};

use crate::endorsement_types::{
    EndorsementType, RESERVED_TYPE_URIS, TYPE_URI_MAX_BYTES, delete_type, get_type, list_types,
    store_type,
};
use crate::endorsements::count_live_by_type;
use crate::server::AppState;

const LIST_MAX_LIMIT: usize = 200;

// ─── Register ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RegisterBody {
    pub type_uri: String,
    #[serde(default)]
    pub claim_schema: Option<JsonValue>,
    #[serde(default)]
    pub description: Option<String>,
}

#[utoipa::path(
    post, path = "/endorsement-types", tag = "endorsement-types",
    security(("bearer_jwt" = [])),
    request_body = RegisterBody,
    responses(
        (status = 201, description = "Endorsement type registered", body = EndorsementType),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn register(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<RegisterBody>,
) -> Result<(StatusCode, Json<EndorsementType>), AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    // Validation.
    let uri = body.type_uri.trim();
    if uri.is_empty() {
        return Err(AppError::Validation("type_uri cannot be empty".into()));
    }
    if uri.len() > TYPE_URI_MAX_BYTES {
        return Err(AppError::Validation(format!(
            "type_uri exceeds {TYPE_URI_MAX_BYTES} bytes"
        )));
    }
    if RESERVED_TYPE_URIS.contains(&uri) {
        return Err(AppError::Conflict(format!(
            "endorsement-type-reserved: '{uri}' is reserved by the workspace"
        )));
    }
    if get_type(&state.endorsement_types_ks, uri).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "endorsement-type-exists: '{uri}' already registered"
        )));
    }

    let row = EndorsementType {
        type_uri: uri.to_string(),
        claim_schema: body.claim_schema,
        description: body.description.clone(),
        created_at: Utc::now(),
        created_by_did: auth.0.did.clone(),
    };
    store_type(&state.endorsement_types_ks, &row).await?;

    audit_writer
        .write(
            &auth.0.did,
            None,
            AuditEvent::EndorsementTypeRegistered(EndorsementTypeRegisteredData {
                type_uri: uri.to_string(),
                description: body.description,
            }),
        )
        .await?;

    info!(type_uri = %uri, by = %auth.0.did, "endorsement type registered");

    Ok((StatusCode::CREATED, Json(row)))
}

// ─── List ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema, utoipa::IntoParams)]
pub struct ListQuery {
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

#[utoipa::path(
    get, path = "/endorsement-types", tag = "endorsement-types",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Paginated list of endorsement types", body = Paginated<EndorsementType>),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn list(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Paginated<EndorsementType>>, AppError> {
    let limit = query.limit.unwrap_or(50).clamp(1, LIST_MAX_LIMIT);
    let audit_key = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?
        .active_key()
        .await?;
    let cursor = query
        .cursor
        .as_deref()
        .map(|c| Cursor::decode(c, &audit_key.key))
        .transpose()
        .map_err(|e| AppError::Validation(format!("invalid cursor: {e}")))?;
    let page = list_types(
        &state.endorsement_types_ks,
        &audit_key,
        cursor.as_ref(),
        limit,
    )
    .await?;
    Ok(Json(page))
}

// ─── Delete ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct DeleteResponse {
    pub type_uri: String,
}

#[utoipa::path(
    delete, path = "/endorsement-types/{type_uri}", tag = "endorsement-types",
    security(("bearer_jwt" = [])),
    params(("type_uri" = String, Path, description = "Endorsement type URI")),
    responses(
        (status = 200, description = "Endorsement type deleted", body = DeleteResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Endorsement type not found"),
    ),
)]
pub async fn delete(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(type_uri): Path<String>,
) -> Result<(StatusCode, Json<DeleteResponse>), AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    if get_type(&state.endorsement_types_ks, &type_uri)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound(format!(
            "endorsement type '{type_uri}' not found"
        )));
    }

    // Refuse if any live endorsement still references the type.
    let in_use = count_live_by_type(&state.endorsements_ks, &type_uri).await?;
    if in_use > 0 {
        return Err(AppError::Conflict(format!(
            "endorsement-type-in-use: {in_use} live endorsement(s) of type '{type_uri}' \
             still exist; revoke them before deleting the type"
        )));
    }

    delete_type(&state.endorsement_types_ks, &type_uri).await?;

    audit_writer
        .write(
            &auth.0.did,
            None,
            AuditEvent::EndorsementTypeDeleted(EndorsementTypeDeletedData {
                type_uri: type_uri.clone(),
            }),
        )
        .await?;

    info!(type_uri = %type_uri, by = %auth.0.did, "endorsement type deleted");

    Ok((StatusCode::OK, Json(DeleteResponse { type_uri })))
}
