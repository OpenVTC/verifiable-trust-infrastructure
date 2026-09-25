use axum::Json;
use axum::extract::State;

use crate::auth::{AuthClaims, SuperAdminAuth};
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

use vta_sdk::protocols::backup_management::types::{
    BackupEnvelope, ExportRequest, ImportRequest, ImportResult,
};

/// POST /backup/export — **refused**. Auth: Super Admin.
///
/// A backup carries the seed, sealed by the password the request carries.
/// Over REST both exist in plaintext wherever TLS terminates, so whoever holds
/// that point holds every key the VTA can derive. A backup is exported only
/// over a channel confidential to the two parties: DIDComm, or
/// `vta/backup/initiate-export` over DIDComm or TSP (VTI-VTA-003). The route
/// stays so an old client gets a reason rather than a 404.
#[utoipa::path(
    post, path = "/backup/export", tag = "backup",
    security(("bearer_jwt" = [])),
    request_body = ExportRequest,
    responses(
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Always: a backup is not exported over REST"),
    ),
)]
pub async fn export(
    SuperAdminAuth(_auth): SuperAdminAuth,
    State(_state): State<AppState>,
    Json(_req): Json<ExportRequest>,
) -> Result<Json<BackupEnvelope>, AppError> {
    Err(AppError::Forbidden(
        "a backup export is refused over REST: the password that seals the backup would \
         exist in plaintext wherever TLS terminates. Export over DIDComm, or send \
         vta/backup/initiate-export over DIDComm or TSP"
            .into(),
    ))
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
