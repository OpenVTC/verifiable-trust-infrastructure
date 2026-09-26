use axum::Json;
use axum::extract::State;
use axum::response::Response;

use crate::auth::SuperAdminAuth;
use crate::error::{AppError, tee_attestation_error};
use crate::operations;
use crate::server::AppState;
use crate::tee::mnemonic_guard::{MnemonicExportResponse, MnemonicExportStatus};
use crate::tee::types::{AttestationReport, AttestationRequest, TeeStatus};
use vta_sdk::attestation_report::ConfigAttestationReport;

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

/// POST /attestation/config-report — Fresh, nonce-bound attestation committing a
/// digest of the config this enclave booted (unauthenticated).
///
/// The verifiable pull path for the un-baked tenant config: the parent supplies
/// `tee.kms.key_arn` and the rest, so a tenant/verifier calls this with a fresh
/// nonce and verifies the returned `ConfigAttestationReport` — signature chains
/// to the AWS Nitro root, `PCR0` matches the approved image, `nonce` is bound,
/// and `user_data == SHA-384(configView)` authenticates the returned canonical
/// view. The verifier then enforces its policy on that authenticated view (the
/// tenant's expected `tee.kms.key_arn`) before onboarding. It does NOT re-derive
/// an expected config from base+overlay.
#[utoipa::path(
    post, path = "/attestation/config-report", tag = "attestation",
    request_body = AttestationRequest,
    responses(
        (status = 200, description = "Fresh config attestation report", body = ConfigAttestationReport),
        (status = 503, description = "TEE attestation not enabled, or this build captured no effective-config snapshot at boot (only the enclave front-end does)"),
    ),
)]
pub async fn config_report(
    State(state): State<AppState>,
    Json(body): Json<AttestationRequest>,
) -> Result<Json<ConfigAttestationReport>, AppError> {
    let tee_state = state
        .tee
        .as_ref()
        .map(|tc| &tc.state)
        .ok_or_else(|| tee_attestation_error("TEE attestation is not enabled on this VTA"))?;

    let response =
        operations::attestation::generate_config_attestation(tee_state, &state.config, &body.nonce)
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
    SuperAdminAuth(auth): SuperAdminAuth,
    State(state): State<AppState>,
) -> Result<Json<MnemonicExportResponse>, AppError> {
    // The root seed is the export of every key this VTA holds: the same
    // capability as any other export (VTI-VTA-003), not only the role.
    crate::operations::keys::ensure_may_export(&state.acl_ks, &auth, "attestation/mnemonic")
        .await?;
    let guard = state
        .tee
        .as_ref()
        .and_then(|tc| tc.mnemonic_guard.as_ref())
        .ok_or_else(|| {
            tee_attestation_error(
                "mnemonic export not available (TEE mode not active or no KMS bootstrap)",
            )
        })?;

    // The root mnemonic is the most consequential export this VTA has, and it
    // used to leave only a tracing line. Recorded durably *before* the entropy
    // is released, and a failed write refuses the export — the same rule as
    // `keys/export-secret` (VTI-VTA-003): once the words are out they cannot be
    // taken back, so an unrecorded release is not permitted. The row names the
    // caller and the transport; never the words.
    crate::audit::record(
        &state.audit_sink,
        "seed.mnemonic_export",
        &auth.did,
        None,
        "success",
        Some("rest"),
        None,
    )
    .await
    .map_err(|e| {
        tracing::error!(
            target: vta_audit::AUDIT_WRITE_FAILURE_TARGET,
            error = %e, actor = %auth.did,
            "mnemonic export refused: its audit row could not be written"
        );
        AppError::Internal(
            "the mnemonic was not released: the export could not be recorded in the audit \
             trail, and an unrecorded export is not permitted (VTI-VTA-003)"
                .into(),
        )
    })?;
    match guard.export() {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            // The row above claimed a release that did not happen; say so.
            crate::audit::record_best_effort(
                &state.audit_sink,
                "seed.mnemonic_export",
                &auth.did,
                None,
                "failure:not_released",
                Some("rest"),
                None,
            )
            .await;
            Err(e)
        }
    }
}
