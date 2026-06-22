use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;

use crate::auth::SuperAdminAuth;
use crate::error::{AppError, tee_attestation_error};
use crate::operations;
use crate::server::AppState;
use crate::tee::mnemonic_guard::{MnemonicExportResponse, MnemonicExportStatus};
use crate::tee::types::{AttestationReport, AttestationRequest, TeeStatus};

/// GET /attestation/status — TEE detection status (unauthenticated).
#[utoipa::path(
    get, path = "/attestation/status", tag = "attestation",
    responses(
        (status = 200, description = "TEE detection status", body = TeeStatus),
        (status = 503, description = "TEE attestation not enabled"),
    ),
)]
pub async fn status(State(state): State<AppState>) -> Result<Json<TeeStatus>, AppError> {
    let tee_state = state
        .tee
        .as_ref()
        .map(|tc| &tc.state)
        .ok_or_else(|| tee_attestation_error("TEE attestation is not enabled on this VTA"))?;

    Ok(Json(operations::attestation::get_tee_status(tee_state)))
}

/// POST /attestation/report — Generate a fresh attestation report with a client nonce (unauthenticated).
#[utoipa::path(
    post, path = "/attestation/report", tag = "attestation",
    request_body = AttestationRequest,
    responses(
        (status = 200, description = "Fresh attestation report", body = AttestationReport),
        (status = 503, description = "TEE attestation not enabled"),
    ),
)]
pub async fn generate_report(
    State(state): State<AppState>,
    Json(body): Json<AttestationRequest>,
) -> Result<Json<AttestationReport>, AppError> {
    let tee_state = state
        .tee
        .as_ref()
        .map(|tc| &tc.state)
        .ok_or_else(|| tee_attestation_error("TEE attestation is not enabled on this VTA"))?;

    let response =
        operations::attestation::generate_attestation_report(tee_state, &state.config, &body.nonce)
            .await?;

    Ok(Json(response))
}

/// GET /attestation/report — Return a cached attestation report (unauthenticated).
#[utoipa::path(
    get, path = "/attestation/report", tag = "attestation",
    responses(
        (status = 200, description = "Cached attestation report", body = AttestationReport),
        (status = 503, description = "TEE attestation not enabled"),
    ),
)]
pub async fn cached_report(
    State(state): State<AppState>,
) -> Result<Json<AttestationReport>, AppError> {
    let tee_state = state
        .tee
        .as_ref()
        .map(|tc| &tc.state)
        .ok_or_else(|| tee_attestation_error("TEE attestation is not enabled on this VTA"))?;

    let response = operations::attestation::get_cached_report(tee_state, &state.config).await?;

    Ok(Json(response))
}

/// GET /attestation/did-log — Return the auto-generated did.jsonl (unauthenticated).
///
/// The DID log is public data (it's published to a web server). This endpoint
/// is only available when the VTA auto-generated a did:webvh identity on first boot.
#[utoipa::path(
    get, path = "/attestation/did-log", tag = "attestation",
    responses(
        (status = 200, description = "Auto-generated did.jsonl", content_type = "text/jsonl"),
        (status = 404, description = "No auto-generated DID log"),
    ),
)]
pub async fn did_log(State(state): State<AppState>) -> Result<Response, AppError> {
    let log_bytes = state.keys_ks.get_raw("tee:did_log").await?.ok_or_else(|| {
        AppError::NotFound(
            "no auto-generated DID log found — the VTA may not have \
                 been configured with a vta_did_template"
                .into(),
        )
    })?;

    let log = String::from_utf8(log_bytes)
        .map_err(|e| AppError::Internal(format!("DID log is not valid UTF-8: {e}")))?;

    // did:webvh v1.0 SHOULDs text/jsonl for the log file (DID-to-HTTPS
    // Transformation §6); previously this returned a bare String, which axum
    // served as text/plain, contradicting the OpenAPI annotation. nosniff
    // matches the other did.jsonl-serving routes (see routes::self_hosted_did).
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/jsonl")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(log))
        .expect("static headers + owned body always build a valid response"))
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

/// POST /attestation/mnemonic — Export the BIP-39 mnemonic (super admin only, time-limited).
///
/// Requirements:
/// - VTA must have been started with `VTA_MNEMONIC_EXPORT_WINDOW=<seconds>`
/// - Must be within the export window since boot
/// - Caller must be a super admin (JWT-authenticated)
/// - One-time operation: after successful export, the entropy is zeroed
#[utoipa::path(
    post, path = "/attestation/mnemonic", tag = "attestation",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Exported BIP-39 mnemonic (one-time)", body = MnemonicExportResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
        (status = 503, description = "Mnemonic export not available or window closed"),
    ),
)]
pub async fn mnemonic_export(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
) -> Result<Json<MnemonicExportResponse>, AppError> {
    let guard = state
        .tee
        .as_ref()
        .and_then(|tc| tc.mnemonic_guard.as_ref())
        .ok_or_else(|| {
            tee_attestation_error(
                "mnemonic export not available (TEE mode not active or no KMS bootstrap)",
            )
        })?;

    let response = guard.export()?;
    Ok(Json(response))
}
