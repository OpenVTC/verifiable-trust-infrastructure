//! Encrypted backup / restore endpoints (P3.9).
//!
//! `POST /v1/backup/export` → encrypted [`BackupEnvelope`];
//! `POST /v1/backup/import` applies one (or, with `confirm = false`,
//! previews it). Both are super-admin only. The heavy lifting —
//! keyspace census, crypto, identity guard, crash-safe replay — lives in
//! [`crate::backup`].

use axum::Json;
use axum::extract::State;
use serde::Deserialize;

use crate::auth::SuperAdminAuth;
use crate::backup::{self, BackupEnvelope, ImportResult};
use crate::keys::seed_store::create_secret_store;
use crate::server::AppState;
use crate::store::keyspaces;
use vti_common::audit::{AuditEvent, BackupData};
use vti_common::error::AppError;

/// `POST /v1/backup/export` body.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ExportRequest {
    /// Encryption password (Argon2id). Minimum 12 characters.
    pub password: String,
    /// Include the audit log in the backup. Default `false` — audit logs
    /// can be large and carry plaintext DIDs.
    #[serde(default)]
    pub include_audit: bool,
}

/// `POST /v1/backup/import` body.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ImportRequest {
    /// The encrypted backup envelope produced by `export`.
    pub backup: BackupEnvelope,
    /// The password the backup was encrypted with.
    pub password: String,
    /// `false` (default) previews the restore (row counts, no mutation);
    /// `true` clears the backed-up keyspaces and applies the backup.
    #[serde(default)]
    pub confirm: bool,
}

#[utoipa::path(
    post, path = "/backup/export", tag = "backup",
    security(("bearer_jwt" = [])),
    request_body = ExportRequest,
    responses(
        (status = 200, description = "Encrypted full-state backup", body = BackupEnvelope),
        (status = 400, description = "Password too short"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
    ),
)]
pub async fn export(
    SuperAdminAuth(auth): SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<ExportRequest>,
) -> Result<Json<BackupEnvelope>, AppError> {
    let store = create_secret_store(&*state.config.read().await)?;
    let envelope =
        backup::export_backup(&state, store.as_ref(), &req.password, req.include_audit).await?;
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &auth.did,
                None,
                AuditEvent::BackupExported(BackupData {
                    keyspace_count: keyspaces::BACKED_UP.len() as u32,
                    vtc_did: envelope.source_did.clone(),
                }),
            )
            .await?;
    }
    Ok(Json(envelope))
}

#[utoipa::path(
    post, path = "/backup/import", tag = "backup",
    security(("bearer_jwt" = [])),
    request_body = ImportRequest,
    responses(
        (status = 200, description = "Import applied, or (confirm=false) a preview", body = ImportResult),
        (status = 400, description = "Malformed / unsupported backup"),
        (status = 401, description = "Wrong backup password or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
        (status = 409, description = "Backup vtc_did does not match this VTC"),
    ),
)]
pub async fn import(
    SuperAdminAuth(auth): SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<ImportRequest>,
) -> Result<Json<ImportResult>, AppError> {
    let store = create_secret_store(&*state.config.read().await)?;
    let result = backup::import_backup(
        &state,
        store.as_ref(),
        &req.backup,
        &req.password,
        req.confirm,
    )
    .await?;
    // Audit only a real restore — `confirm: false` is a preview (no writes).
    if result.status == "imported"
        && let Some(writer) = state.audit_writer.as_ref()
    {
        writer
            .write(
                &auth.did,
                None,
                AuditEvent::BackupImported(BackupData {
                    keyspace_count: result.counts.len() as u32,
                    vtc_did: result.source_did.clone(),
                }),
            )
            .await?;
    }
    Ok(Json(result))
}
