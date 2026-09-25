use axum::Json;
use axum::extract::State;

use crate::auth::{AuthClaims, SuperAdminAuth};
use crate::error::AppError;
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

/// POST /backup/import — **refused**. Auth: Super Admin.
///
/// The request carries a backup and the password that opens it, which
/// together are every key the backup holds, and over REST both exist in
/// plaintext wherever TLS terminates. Import over DIDComm, or send the
/// `vta/backup/initiate-import` and `finalize-import` tasks over DIDComm or TSP
/// (their Channel requirement). The route stays so an old client gets a reason
/// rather than a 404.
#[utoipa::path(
    post, path = "/backup/import", tag = "backup",
    security(("bearer_jwt" = [])),
    request_body = ImportRequest,
    responses(
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Always: a backup is not imported over REST"),
    ),
)]
pub async fn import(
    auth: AuthClaims,
    State(_state): State<AppState>,
    Json(_req): Json<ImportRequest>,
) -> Result<Json<ImportResult>, AppError> {
    auth.require_super_admin()?;
    Err(AppError::Forbidden(
        "a backup import is refused over REST: the backup and the password that opens it \
         would exist in plaintext wherever TLS terminates. Import over DIDComm, or send \
         vta/backup/initiate-import and finalize-import over DIDComm or TSP"
            .into(),
    ))
}
