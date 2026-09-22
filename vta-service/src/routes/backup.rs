use axum::Json;
use axum::extract::State;

use crate::auth::{AuthClaims, SuperAdminAuth};
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

use vta_sdk::protocols::backup_management::types::{
    BackupEnvelope, ExportRequest, ImportRequest, ImportResult,
};

/// POST /backup/export — export VTA state to an encrypted backup. Auth: Super Admin.
#[utoipa::path(
    post, path = "/backup/export", tag = "backup",
    security(("bearer_jwt" = [])),
    request_body = ExportRequest,
    responses(
        (status = 200, description = "Encrypted backup envelope", body = BackupEnvelope),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
    ),
)]
pub async fn export(
    SuperAdminAuth(auth): SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<ExportRequest>,
) -> Result<Json<BackupEnvelope>, AppError> {
    let config = state.config.read().await;
    let envelope = operations::backup::export_backup(
        &state.backup_access().target(),
        &*state.seed_store,
        &config,
        &auth,
        &req.password,
        req.include_audit,
    )
    .await?;

    let _ = crate::audit::record(
        &state.audit_sink,
        "backup.export",
        &auth.did,
        None,
        "success",
        Some("rest"),
        None,
    )
    .await;

    Ok(Json(envelope))
}

/// POST /backup/import — import VTA state from an encrypted backup.
#[utoipa::path(
    post, path = "/backup/import", tag = "backup",
    security(("bearer_jwt" = [])),
    request_body = ImportRequest,
    responses(
        (status = 200, description = "Import result or preview summary", body = ImportResult),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
    ),
)]
pub async fn import(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(req): Json<ImportRequest>,
) -> Result<Json<ImportResult>, AppError> {
    auth.require_super_admin()?;

    // Preview mode: decrypt and return summary without modifying state
    if !req.confirm {
        let running_did = state.config.read().await.vta_did.clone();
        let (_payload, preview) = operations::backup::preview_import_for(
            &req.backup,
            &req.password,
            running_did.as_deref(),
            req.replace_identity,
        )
        .await?;
        return Ok(Json(preview));
    }

    // Full import — decrypt once (skip building a throwaway preview)
    let payload = operations::backup::decrypt_backup(&req.backup, &req.password)?;
    let source_did = payload.config.vta_did.clone();

    let access = state.backup_access();
    let committer = access.committer().await;
    let result = operations::backup::stage_import(
        payload,
        operations::backup::StageRequest {
            target: &access.target(),
            config: &state.config,
            committer: &committer,
            auth: &auth,
            replace_identity: req.replace_identity,
        },
    )
    .await?;

    let _ = crate::audit::record(
        &state.audit_sink,
        "backup.import",
        &auth.did,
        source_did.as_deref(),
        "success",
        Some("rest"),
        None,
    )
    .await;

    // The restore applies on the next boot; the reply goes out first.
    crate::restore::request_reboot(&state.restart_tx);

    Ok(Json(result))
}
