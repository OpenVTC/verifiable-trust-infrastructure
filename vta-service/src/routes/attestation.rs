use axum::Json;
use axum::extract::State;
use axum::response::Response;

use crate::auth::SuperAdminAuth;
use crate::error::{AppError, tee_attestation_error};
use crate::operations;
use crate::server::AppState;
use crate::tee::mnemonic_guard::MnemonicExportStatus;
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

/// POST /attestation/mnemonic — **refused**: the mnemonic export is served only
/// as the Trust Task, over an end-to-end channel or signed by the caller.
///
/// Use `spec/vta/attestation/mnemonic-export/1.0` over DIDComm or TSP, or at
/// first boot over Trust Tasks on HTTPS, signed by the caller with `clientDid`
/// set to the caller's own DID. A bearer token alone never releases it. The
/// mnemonic is the VTA's root derivation material (VTI-VTA-001, VTI-KEY-033);
/// even sealed to the requester, a REST exchange carries the request and its
/// answer in the clear wherever TLS terminates — for a TEE deployment, outside
/// the enclave by definition. Checked after entitlement, like the backup export
/// (`vta/backup/*` channel requirement), so a caller without the authority
/// learns nothing about the channel rule.
#[utoipa::path(
    post, path = "/attestation/mnemonic", tag = "attestation",
    security(("bearer_jwt" = [])),
    responses(
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Always: the caller is not a super admin with key-export, or \
            the export was asked for over REST, which is hop-by-hop. Send \
            spec/vta/attestation/mnemonic-export/1.0 over DIDComm or TSP, or \
            at first boot as a Trust Task signed by the caller with clientDid \
            set to the caller's own DID"),
    ),
)]
pub async fn mnemonic_export(
    SuperAdminAuth(auth): SuperAdminAuth,
    State(state): State<AppState>,
) -> Result<Json<()>, AppError> {
    crate::operations::keys::ensure_may_export(&state.acl_ks, &auth, "attestation/mnemonic")
        .await?;
    Err(AppError::Forbidden(
        "the mnemonic export is refused over REST: a bearer token alone never releases it. \
         Send spec/vta/attestation/mnemonic-export/1.0 over DIDComm or TSP, or at first boot \
         as a Trust Task signed by the caller with clientDid set to the caller's own DID"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// REST is hop-by-hop, so the mnemonic export is refused there even for a
    /// super admin holding `key-export`, and the guard is left untouched.
    #[tokio::test]
    async fn the_rest_mnemonic_export_is_refused() {
        let (mut state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let guard = Arc::new(crate::tee::mnemonic_guard::MnemonicExportGuard::new(
            [0x42; 32], 60,
        ));
        let tee = crate::tee::init_tee(&crate::config::TeeConfig {
            mode: crate::config::TeeMode::Simulated,
            ..Default::default()
        })
        .unwrap()
        .unwrap();
        state.tee = Some(crate::server::TeeContext {
            state: tee,
            mnemonic_guard: Some(guard.clone()),
        });
        let err = mnemonic_export(
            SuperAdminAuth(crate::test_support::super_admin_claims()),
            State(state),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("DIDComm or TSP")),
            "{err:?}"
        );
        assert!(!guard.status().already_exported);
    }
}
