//! `/v1/schemas/*` — the community schema store admin surface (Phase 2 §8).
//!
//! Admin-gated CRUD over two registries living in the `schemas` keyspace:
//!
//! - **Per-type schemas** (`/v1/schemas`) — the Issues / Accepts
//!   [`SchemaEntry`] registry: each credential type the community mints or
//!   recognises, bound to a DTG catalog type + an optional JSON Schema.
//! - **Accepts criteria** (`/v1/schemas/accepts`) — named DCQL queries
//!   ([`AcceptsCriterion`]) over the per-type registry: a ceremony's
//!   required-evidence manifest.
//!
//! Every handler is gated by [`AdminAuth`]. Registering a per-type schema with
//! a `credentialSchema` validates that the schema is itself a well-formed JSON
//! Schema; registering an Accepts criterion validates the DCQL query and that
//! every type it references is registered (in [`store_accepts`]).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::info;
use vti_common::auth::AdminAuth;
use vti_common::error::AppError;

use crate::schemas::{
    AcceptsCriterion, SchemaEntry, SchemaKind, TYPE_URI_MAX_BYTES, delete_accepts, delete_schema,
    get_accepts, get_schema, list_accepts, list_schemas, store_accepts, store_schema,
};
use crate::server::AppState;

// ─── Per-type schema registry (Issues / Accepts) ─────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterSchemaBody {
    pub type_uri: String,
    #[serde(default)]
    pub dtg_type: Option<String>,
    #[serde(default)]
    pub credential_schema: Option<JsonValue>,
    pub kind: SchemaKind,
    #[serde(default)]
    pub description: Option<String>,
}

/// `POST /v1/schemas` — register (or update) a per-type schema entry.
pub async fn register(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<RegisterSchemaBody>,
) -> Result<(StatusCode, Json<SchemaEntry>), AppError> {
    let uri = body.type_uri.trim();
    if uri.is_empty() {
        return Err(AppError::Validation("type_uri cannot be empty".into()));
    }
    if uri.len() > TYPE_URI_MAX_BYTES {
        return Err(AppError::Validation(format!(
            "type_uri exceeds {TYPE_URI_MAX_BYTES} bytes"
        )));
    }
    // A credentialSchema, when present, must be a well-formed JSON Schema.
    if let Some(schema) = &body.credential_schema {
        jsonschema::validator_for(schema)
            .map_err(|e| AppError::Validation(format!("invalid credentialSchema: {e}")))?;
    }

    let entry = SchemaEntry {
        type_uri: uri.to_string(),
        dtg_type: body.dtg_type,
        credential_schema: body.credential_schema,
        kind: body.kind,
        description: body.description,
        created_at: Utc::now(),
        created_by_did: auth.0.did.clone(),
    };
    store_schema(&state.schemas_ks, &entry).await?;
    info!(type_uri = %uri, kind = ?entry.kind, by = %auth.0.did, "schema registered");
    Ok((StatusCode::CREATED, Json(entry)))
}

/// `GET /v1/schemas` — list every registered per-type schema.
pub async fn list(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<SchemaEntry>>, AppError> {
    Ok(Json(list_schemas(&state.schemas_ks).await?))
}

/// `GET /v1/schemas/{type_uri}` — fetch one registered schema.
pub async fn get_one(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(type_uri): Path<String>,
) -> Result<Json<SchemaEntry>, AppError> {
    get_schema(&state.schemas_ks, &type_uri)
        .await?
        .map(Json)
        .ok_or_else(|| AppError::NotFound(format!("schema `{type_uri}` not found")))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResponse {
    pub id: String,
}

/// `DELETE /v1/schemas/{type_uri}` — remove a registered schema.
pub async fn delete_one(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(type_uri): Path<String>,
) -> Result<(StatusCode, Json<DeleteResponse>), AppError> {
    if get_schema(&state.schemas_ks, &type_uri).await?.is_none() {
        return Err(AppError::NotFound(format!("schema `{type_uri}` not found")));
    }
    delete_schema(&state.schemas_ks, &type_uri).await?;
    info!(type_uri = %type_uri, by = %auth.0.did, "schema deleted");
    Ok((StatusCode::OK, Json(DeleteResponse { id: type_uri })))
}

// ─── Accepts criteria (DCQL over the registry) ───────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAcceptsBody {
    pub id: String,
    pub query: JsonValue,
    #[serde(default)]
    pub description: Option<String>,
}

/// `POST /v1/schemas/accepts` — register (or update) an Accepts criterion. The
/// DCQL query is validated and every referenced type checked against the
/// registry by [`store_accepts`].
pub async fn register_accepts(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<RegisterAcceptsBody>,
) -> Result<(StatusCode, Json<AcceptsCriterion>), AppError> {
    let id = body.id.trim();
    if id.is_empty() {
        return Err(AppError::Validation(
            "accepts criterion id cannot be empty".into(),
        ));
    }
    let criterion = AcceptsCriterion {
        id: id.to_string(),
        query: body.query,
        description: body.description,
        created_at: Utc::now(),
        created_by_did: auth.0.did.clone(),
    };
    store_accepts(&state.schemas_ks, &criterion).await?;
    info!(id = %id, by = %auth.0.did, "accepts criterion registered");
    Ok((StatusCode::CREATED, Json(criterion)))
}

/// `GET /v1/schemas/accepts` — list every Accepts criterion.
pub async fn list_accepts_route(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<AcceptsCriterion>>, AppError> {
    Ok(Json(list_accepts(&state.schemas_ks).await?))
}

/// `GET /v1/schemas/accepts/{id}` — fetch one Accepts criterion.
pub async fn get_accepts_route(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<AcceptsCriterion>, AppError> {
    get_accepts(&state.schemas_ks, &id)
        .await?
        .map(Json)
        .ok_or_else(|| AppError::NotFound(format!("accepts criterion `{id}` not found")))
}

/// `DELETE /v1/schemas/accepts/{id}` — remove an Accepts criterion.
pub async fn delete_accepts_route(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<DeleteResponse>), AppError> {
    if get_accepts(&state.schemas_ks, &id).await?.is_none() {
        return Err(AppError::NotFound(format!(
            "accepts criterion `{id}` not found"
        )));
    }
    delete_accepts(&state.schemas_ks, &id).await?;
    info!(id = %id, by = %auth.0.did, "accepts criterion deleted");
    Ok((StatusCode::OK, Json(DeleteResponse { id })))
}
