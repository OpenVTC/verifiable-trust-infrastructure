//! Encrypted backup / restore endpoints (P3.9).
//!
//! `POST /v1/backup/export` → encrypted [`BackupEnvelope`];
//! `POST /v1/backup/import` applies one (or, with `confirm = false`,
//! previews it). Both are super-admin only. The heavy lifting —
//! keyspace census, crypto, identity guard, crash-safe replay — lives in
//! [`crate::backup`].

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::auth::SuperAdminAuth;
use crate::backup::{self, BackupEnvelope, ImportResult};
use crate::error::TaskError;
use crate::keys::seed_store::create_secret_store;
use crate::server::AppState;
use crate::store::keyspaces;
use vti_common::audit::{AuditEvent, BackupData};

/// `POST /v1/backup/export` body.
#[derive(Deserialize, utoipa::ToSchema)]
#[schema(as = BackupExportRequest)]
#[serde(rename_all = "camelCase")]
pub struct ExportRequest {
    /// Encryption password (Argon2id). Minimum 15 characters.
    pub password: String,
    /// Include the audit log in the backup. Default `false` — audit logs
    /// can be large and carry plaintext DIDs.
    #[serde(default)]
    pub include_audit: bool,
}

/// Written by hand so the backup password never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for ExportRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportRequest")
            .field("password", &"<redacted>")
            .field("include_audit", &self.include_audit)
            .finish()
    }
}

/// `{ envelope: … }` — the shape `vtc/backup/export/0.1` publishes.
///
/// The handler returned the bare `BackupEnvelope` until #1059's witness put it
/// beside its own schema. The inner object always conformed member for member;
/// only the wrapper was missing.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[schema(as = BackupExportResponse)]
pub struct ExportResponse {
    pub envelope: BackupEnvelope,
}

/// `POST /v1/backup/import` body.
#[derive(Deserialize, utoipa::ToSchema)]
#[schema(as = BackupImportRequest)]
#[serde(rename_all = "camelCase")]
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

/// Written by hand so the backup password never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for ImportRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportRequest")
            .field("backup", &self.backup)
            .field("password", &"<redacted>")
            .field("confirm", &self.confirm)
            .finish()
    }
}

/// POST /backup/export — encrypted full-state backup. Auth: super-admin.
///
/// **Transitional bearer-token path (#1641).**
/// `vtc/backup/export/0.1` declares `proof` REQUIRED, and the authoritative
/// binding is the signed Trust Task document at `POST /v1/trust-tasks`, where
/// the proof authenticates the super-administrator and their authority is
/// read from their ACL entry. This route authenticates by bearer JWT and
/// verifies no document proof; it is kept because `vtc-client` calls it, and
/// it is removed once that client signs.
#[utoipa::path(
    post, path = "/backup/export", tag = "backup",
    security(("bearer_jwt" = [])),
    request_body = ExportRequest,
    responses(
        (status = 200, description = "Encrypted full-state backup", body = ExportResponse),
        (status = 400, description = "Password too short"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
    ),
)]
pub async fn export(
    SuperAdminAuth(auth): SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<ExportRequest>,
) -> Result<Json<ExportResponse>, TaskError> {
    export_inner(&state, &auth.did, &req.password, req.include_audit)
        .await
        .map(Json)
}

/// The export, independent of the door it was asked through — the bearer
/// route above and the signed `vtc/backup/export/0.1` document
/// (`trust_tasks::handle_backup_export`) both call this. `actor_did` is whoever
/// the door authenticated as a super-admin, and it is what the audit row names.
pub(crate) async fn export_inner(
    state: &AppState,
    actor_did: &str,
    password: &str,
    include_audit: bool,
) -> Result<ExportResponse, TaskError> {
    let store = create_secret_store(&*state.config.read().await)?;
    let envelope = backup::export_backup(state, store.as_ref(), password, include_audit).await?;
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                actor_did,
                None,
                AuditEvent::BackupExported(BackupData {
                    keyspace_count: keyspaces::BACKED_UP.len() as u32,
                    vtc_did: envelope.source_did.clone(),
                }),
            )
            .await?;
    }
    Ok(ExportResponse { envelope })
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
) -> Result<Json<ImportResult>, TaskError> {
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
