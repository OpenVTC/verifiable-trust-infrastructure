//! The community schema store (Phase 2 §8), served on the spine as
//! `vtc/schemas/{register,list,show,delete}/0.1` and
//! `vtc/schemas/accepts/{register,list,show,delete}/0.1`
//! (`trust_tasks::surface_tasks`). There is no REST route; these are the
//! operations the spine calls.
//!
//! CRUD over two registries living in the `schemas` keyspace:
//!
//! - **Per-type schemas** (`/v1/schemas`) — the Issues / Accepts
//!   [`SchemaEntry`] registry: each credential type the community mints or
//!   recognises, bound to a DTG catalog type + an optional JSON Schema.
//! - **Accepts criteria** (`/v1/schemas/accepts`) — named DCQL queries
//!   ([`AcceptsCriterion`]) over the per-type registry: a ceremony's
//!   required-evidence manifest.
//!
//! Every task is an administrator's (the old routes' `AdminAuth`). Registering a per-type schema with
//! a `credentialSchema` validates that the schema is itself a well-formed JSON
//! Schema; registering an Accepts criterion validates the DCQL query and that
//! every type it references is registered (in [`store_accepts`]).

use chrono::Utc;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use tracing::info;
use vta_sdk::protocols::vetting::VettingRequirements;
use vti_common::audit::{AuditEvent, SchemaChangeData};
use vti_common::error::AppError;

use crate::schemas::{
    AcceptsCriterion, SchemaEntry, SchemaKind, TYPE_URI_MAX_BYTES, delete_accepts, delete_schema,
    get_accepts, get_schema, store_accepts, store_schema,
};
use crate::server::AppState;

// ─── Per-type schema registry (Issues / Accepts) ─────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
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
pub(crate) async fn register_inner(
    state: &AppState,
    actor: &str,
    body: RegisterSchemaBody,
) -> Result<SchemaEntry, AppError> {
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
        created_by_did: actor.to_string(),
    };
    store_schema(&state.schemas_ks, &entry).await?;
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                actor,
                None,
                AuditEvent::SchemaRegistered(SchemaChangeData {
                    id: uri.to_string(),
                    kind: "schema".into(),
                }),
            )
            .await?;
    }
    info!(type_uri = %uri, kind = ?entry.kind, by = %actor, "schema registered");
    Ok(entry)
}

/// `DELETE /v1/schemas/{type_uri}` — remove a registered schema.
pub(crate) async fn delete_inner(
    state: &AppState,
    actor: &str,
    type_uri: &str,
) -> Result<String, AppError> {
    if get_schema(&state.schemas_ks, type_uri).await?.is_none() {
        return Err(AppError::NotFound(format!("schema `{type_uri}` not found")));
    }
    delete_schema(&state.schemas_ks, type_uri).await?;
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                actor,
                None,
                AuditEvent::SchemaDeleted(SchemaChangeData {
                    id: type_uri.to_string(),
                    kind: "schema".into(),
                }),
            )
            .await?;
    }
    info!(type_uri = %type_uri, by = %actor, "schema deleted");
    Ok(type_uri.to_string())
}

// ─── Accepts criteria (DCQL over the registry) ───────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RegisterAcceptsBody {
    pub id: String,
    pub query: JsonValue,
    #[serde(default)]
    pub description: Option<String>,
    /// Peer identity vetting this criterion requires, advertised in the join
    /// manifest (0.2). Its `statementType` must be a registered endorsement type.
    #[serde(default)]
    #[schema(value_type = Option<vta_sdk::openapi::JoinManifest02VettingRequirements>)]
    pub vetting: Option<VettingRequirements>,
    /// Hidden-vetter admission (ZKP, development branch `zkp-pcs`): the published
    /// parameters, stored verbatim (`crate::vetting::pcs::HiddenVettingConfig`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub hidden_vetting: Option<serde_json::Value>,
}

/// `POST /v1/schemas/accepts` — register (or update) an Accepts criterion. The
/// DCQL query is validated and every referenced type checked against the
/// registry by [`store_accepts`].
pub(crate) async fn register_accepts_inner(
    state: &AppState,
    actor: &str,
    body: RegisterAcceptsBody,
) -> Result<AcceptsCriterion, AppError> {
    let id = body.id.trim();
    if id.is_empty() {
        return Err(AppError::Validation(
            "accepts criterion id cannot be empty".into(),
        ));
    }
    // A criterion that counts statements of a type the community does not
    // recognise could never be satisfied — refuse it here, where the operator
    // can act on the error, rather than at an applicant's submit.
    if let Some(vetting) = &body.vetting
        && !crate::endorsement_types::storage::type_exists(
            &state.endorsement_types_ks,
            &vetting.statement_type,
        )
        .await?
    {
        return Err(AppError::Validation(format!(
            "vetting.statementType `{}` is not a registered endorsement type — register it \
             with vtc/endorsement-types/register first",
            vetting.statement_type
        )));
    }
    let criterion = AcceptsCriterion {
        id: id.to_string(),
        query: body.query,
        description: body.description,
        vetting: body.vetting,
        hidden_vetting: body.hidden_vetting,
        created_at: Utc::now(),
        created_by_did: actor.to_string(),
    };
    store_accepts(&state.schemas_ks, &criterion).await?;
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                actor,
                None,
                AuditEvent::SchemaRegistered(SchemaChangeData {
                    id: id.to_string(),
                    kind: "accepts".into(),
                }),
            )
            .await?;
    }
    info!(id = %id, by = %actor, "accepts criterion registered");
    Ok(criterion)
}

/// `DELETE /v1/schemas/accepts/{id}` — remove an Accepts criterion.
pub(crate) async fn delete_accepts_inner(
    state: &AppState,
    actor: &str,
    id: &str,
) -> Result<String, AppError> {
    if get_accepts(&state.schemas_ks, id).await?.is_none() {
        return Err(AppError::NotFound(format!(
            "accepts criterion `{id}` not found"
        )));
    }
    delete_accepts(&state.schemas_ks, id).await?;
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                actor,
                None,
                AuditEvent::SchemaDeleted(SchemaChangeData {
                    id: id.to_string(),
                    kind: "accepts".into(),
                }),
            )
            .await?;
    }
    info!(id = %id, by = %actor, "accepts criterion deleted");
    Ok(id.to_string())
}
