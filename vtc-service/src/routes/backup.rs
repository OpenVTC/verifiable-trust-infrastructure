//! Encrypted backup / restore endpoints (P3.9).
//!
//! `POST /v1/backup/export` and `POST /v1/backup/import` are **refused**: a
//! backup moves only over DIDComm or TSP. [`export_inner`] and
//! [`import_inner`] are what the Trust Task handlers call. The heavy lifting —
//! keyspace census, crypto, identity guard, crash-safe replay — lives in
//! [`crate::backup`].

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::auth::SuperAdminAuth;
use crate::backup::{self, BackupEnvelope, ImportResult};
use crate::error::TaskError;
use crate::keys::seed_store::create_secret_store;
use crate::server::AppState;
use crate::store::keyspaces;
use vti_common::audit::{AuditEvent, BackupData};
use vti_common::error::AppError;

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

/// POST /backup/export — **refused**. Auth: super-admin.
///
/// The request carries the backup password and the reply is the backup it
/// opens, so over REST both exist in plaintext wherever TLS terminates. A
/// community backup is exported only over DIDComm or TSP (`vtc/backup/export`
/// or the `backup/*` family), per the backup Channel requirement
/// (trustoverip/dtgwg-trust-tasks-tf#646). The route stays so an old client
/// gets a reason rather than a 404.
#[utoipa::path(
    post, path = "/backup/export", tag = "backup",
    security(("bearer_jwt" = [])),
    responses(
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Always: a backup is not exported over REST"),
    ),
)]
pub async fn export(
    SuperAdminAuth(_auth): SuperAdminAuth,
    State(_state): State<AppState>,
) -> Result<Json<ExportResponse>, TaskError> {
    Err(TaskError::App(AppError::Forbidden(
        REST_EXPORT_REFUSED.into(),
    )))
}

const REST_EXPORT_REFUSED: &str = "a backup export is refused over REST: the backup password \
    and the backup would exist in plaintext wherever TLS terminates. Export over DIDComm or TSP \
    (cnm backup export does)";

const REST_IMPORT_REFUSED: &str = "a backup import is refused over REST: the backup and the \
    password that opens it would exist in plaintext wherever TLS terminates. Import over DIDComm \
    or TSP (cnm backup import does)";

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
    // A backup carries the community's keys, and an unrecorded copy of them is
    // not permitted: with no audit trail to write to, the export is refused
    // before anything is serialized, and the row is written before the
    // envelope is returned. A failed write refuses the export.
    let Some(writer) = state.audit_writer.as_ref() else {
        return Err(TaskError::App(AppError::Internal(
            "the backup was not exported: this VTC has no audit trail to record it in, and an \
             unrecorded export is not permitted"
                .into(),
        )));
    };
    let store = create_secret_store(&*state.config.read().await)?;
    let envelope = backup::export_backup(state, store.as_ref(), password, include_audit).await?;
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
    Ok(ExportResponse { envelope })
}

/// POST /backup/import — **refused**. Auth: super-admin. Import over DIDComm
/// or TSP with the `backup/*` family instead; see [`export`].
#[utoipa::path(
    post, path = "/backup/import", tag = "backup",
    security(("bearer_jwt" = [])),
    responses(
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Always: a backup is not imported over REST"),
    ),
)]
pub async fn import(
    SuperAdminAuth(_auth): SuperAdminAuth,
    State(_state): State<AppState>,
) -> Result<Json<ImportResult>, TaskError> {
    Err(TaskError::App(AppError::Forbidden(
        REST_IMPORT_REFUSED.into(),
    )))
}

/// The import, independent of the door — this bearer route with the envelope
/// inline, and the chunked `backup/finalize-import/0.1` with the envelope
/// assembled from `put-chunk`s (`trust_tasks::backup_tasks`). `actor_did` is
/// the super-administrator the door authenticated; the audit row names it.
pub(crate) async fn import_inner(
    state: &AppState,
    actor_did: &str,
    envelope: &BackupEnvelope,
    password: &str,
    confirm: bool,
) -> Result<ImportResult, TaskError> {
    let store = create_secret_store(&*state.config.read().await)?;
    let result = backup::import_backup(state, store.as_ref(), envelope, password, confirm).await?;
    // Audit only a real restore — `confirm: false` is a preview (no writes).
    if result.status == "imported"
        && let Some(writer) = state.audit_writer.as_ref()
    {
        writer
            .write(
                actor_did,
                None,
                AuditEvent::BackupImported(BackupData {
                    keyspace_count: result.counts.len() as u32,
                    vtc_did: result.source_did.clone(),
                }),
            )
            .await?;
    }
    Ok(result)
}
