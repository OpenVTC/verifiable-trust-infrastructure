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
    let ks = operations::Keyspaces::from_app_state(&state);
    let envelope = operations::backup::export_backup(
        &ks,
        &*state.seed_store,
        &config,
        &auth,
        &req.password,
        req.include_audit,
    )
    .await?;

    let _ = crate::audit::record(
        &state.audit_ks,
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
        let (_payload, preview) =
            operations::backup::preview_import(&req.backup, &req.password).await?;
        return Ok(Json(preview));
    }

    // Full import — decrypt once (skip building a throwaway preview)
    let payload = operations::backup::decrypt_backup(&req.backup, &req.password)?;

    let ks = operations::Keyspaces::from_app_state(&state);
    let result = operations::backup::apply_import(
        &payload,
        &ks,
        &state.seed_store,
        &state.config,
        None, // Store passed for TEE re-encryption (REST has no store access; handled on restart)
    )
    .await?;

    let _ = crate::audit::record(
        &state.audit_ks,
        "backup.import",
        &auth.did,
        payload.config.vta_did.as_deref(),
        "success",
        Some("rest"),
        None,
    )
    .await;

    crate::server::trigger_restart(&state.restart_tx);

    Ok(Json(result))
}
