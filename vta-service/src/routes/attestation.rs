use axum::Json;
use axum::extract::State;
use axum::response::Response;

use crate::auth::SuperAdminAuth;
use crate::error::{AppError, tee_attestation_error};
use crate::server::AppState;
use crate::tee::mnemonic_guard::MnemonicExportStatus;

// The public attestation reads (`status`, a fresh or cached `report`,
// `config-report`) were REST routes here. They are the
// `vta/attestation/{status,report,config-report}/0.1` Trust Tasks now, served
// on `/trust-tasks` to anonymous callers over every transport
// (`crate::trust_tasks::attestation`). The cached, nonce-less report is not
// carried over: evidence nobody asked for is evidence anybody can replay.

/// GET /attestation/did-log — Return the auto-generated did.jsonl (unauthenticated).
///
/// The DID log is public data (it's published to a web server). This endpoint
/// is only available when the VTA auto-generated a did:webvh identity on first boot.
#[utoipa::path(
    get, path = "/attestation/did-log", tag = "attestation",
    responses(
        (status = 200, description = "Auto-generated did.jsonl", content_type = "text/jsonl"),
        (status = 304, description = "Not modified: If-None-Match names the current ETag"),
        (status = 429, description = "Rate limited by the VTA (`x-rate-limit-source: vta`)"),
        (status = 404, description = "No auto-generated DID log"),
    ),
)]
pub async fn did_log(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    let log_bytes = state
        .keys_ks
        .get_raw(crate::tee::did_autogen::DID_LOG_STORE_KEY)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(
                "no auto-generated DID log found — the VTA may not have \
                 been configured with a vta_did_template"
                    .into(),
            )
        })?;

    let log = String::from_utf8(log_bytes)
        .map_err(|e| AppError::Internal(format!("DID log is not valid UTF-8: {e}")))?;

    // did:webvh v1.0 SHOULDs text/jsonl for the log file (DID-to-HTTPS
    // Transformation §6). Content type, nosniff and the cache headers
    // (ETag, short max-age, If-None-Match → 304) match the other
    // did.jsonl-serving routes (see routes::self_hosted_did).
    Ok(super::self_hosted_did::did_log_response(&headers, log))
}

/// GET /attestation/mnemonic — Check mnemonic export window status (super admin only).
#[utoipa::path(
    get, path = "/attestation/mnemonic", tag = "attestation",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Mnemonic export window status", body = MnemonicExportStatus),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
        (status = 503, description = "Mnemonic export not available"),
    ),
)]
pub async fn mnemonic_status(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
) -> Result<Json<MnemonicExportStatus>, AppError> {
    let guard = state
        .tee
        .as_ref()
        .and_then(|tc| tc.mnemonic_guard.as_ref())
        .ok_or_else(|| {
            tee_attestation_error(
                "mnemonic export not available (TEE mode not active or no KMS bootstrap)",
            )
        })?;

    Ok(Json(guard.status()))
}

// `POST /attestation/mnemonic` was a REST route here — always refused (403):
// the mnemonic export is served only as `vta/attestation/mnemonic-export/1.0`,
// over an end-to-end channel or signed by the caller, never over a bearer
// token alone. The stub added nothing a caller couldn't already learn from
// that Trust Task's own refusal, so it's gone rather than kept as a
// permanent 403. `GET /attestation/mnemonic` (the status check above) stays —
// a documented `REST_EXCEPTIONS` keep until its own Trust-Task spec lands.
