//! Encrypted backup / restore (P3.9), as the Trust Task handlers perform it.
//!
//! There is no REST route: a community backup moves only as the
//! `vtc/backup/export` and `backup/*` Trust Tasks over TSP or DIDComm, per the
//! backup Channel requirement (trustoverip/dtgwg-trust-tasks-tf#646).
//! [`export_inner`] and [`import_inner`] are what those handlers call. The
//! heavy lifting — keyspace census, crypto, identity guard, crash-safe replay
//! — lives in [`crate::backup`].

use serde::Serialize;

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

/// The export behind the signed `vtc/backup/export/0.1` document
/// (`trust_tasks::handle_backup_export`) and the chunked `backup/*` export.
/// `actor_did` is the super-admin the spine authenticated, and it is what the
/// audit row names.
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

/// The import behind the chunked `backup/finalize-import/0.1`, with the
/// envelope assembled from `put-chunk`s (`trust_tasks::backup_tasks`).
/// `actor_did` is the super-administrator the spine authenticated; the audit
/// row names it.
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
