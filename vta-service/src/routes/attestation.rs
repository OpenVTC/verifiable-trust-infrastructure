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

/// Response to `POST /attestation/mnemonic`: the mnemonic as a sealed bundle.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct SealedMnemonicResponse {
    /// ASCII-armored sealed bundle carrying a `SeedMnemonic` payload, sealed
    /// to the request's `client_did` under an `Attested` producer assertion.
    pub bundle: String,
    /// SHA-256 of the bundle — confirm it out of band before opening.
    pub digest: String,
    /// Seconds that were left in the export window.
    pub window_remaining_secs: u64,
}

/// Serializes exports: the guard's reservation already refuses a second
/// concurrent one, and this keeps the refusal from racing the audit row.
static MNEMONIC_EXPORT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// POST /attestation/mnemonic — Export the BIP-39 mnemonic **sealed** to the
/// operator (super admin only, time-limited, one time).
///
/// The body is a `BootstrapRequest` (`pnm bootstrap request --out req.json`):
/// the operator's ephemeral `did:key` and a fresh nonce. The mnemonic is sealed
/// to that key with sealed-transfer under an `Attested` assertion whose quote
/// binds `SHA256(client_ed25519 || nonce || producer_ed25519)`, and opened
/// with `pnm bootstrap open --expect-digest <digest>` on the machine that will
/// hold the backup.
///
/// It used to be returned as plaintext JSON. The mnemonic is the VTA's root
/// derivation material (VTI-VTA-001, VTI-KEY-033), and over REST that response
/// exists in the clear wherever TLS terminates — for a TEE deployment, outside
/// the enclave by definition.
///
/// Requirements:
/// - VTA must have been started with `VTA_MNEMONIC_EXPORT_WINDOW=<seconds>`
/// - Must be within the export window since boot
/// - Caller must be a super admin (JWT-authenticated)
/// - One-time operation: after a successful export, the entropy is zeroed. A
///   failure before the bundle is built leaves the export available to retry.
#[utoipa::path(
    post, path = "/attestation/mnemonic", tag = "attestation",
    security(("bearer_jwt" = [])),
    request_body = vta_sdk::sealed_transfer::BootstrapRequest,
    responses(
        (status = 200, description = "Sealed mnemonic bundle (one-time)", body = SealedMnemonicResponse),
        (status = 400, description = "Malformed request: version, client_did or nonce"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
        (status = 503, description = "Mnemonic export not available or window closed"),
    ),
)]
pub async fn mnemonic_export(
    SuperAdminAuth(auth): SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<vta_sdk::sealed_transfer::BootstrapRequest>,
) -> Result<Json<SealedMnemonicResponse>, AppError> {
    use sha2::{Digest, Sha256};
    use vta_sdk::sealed_transfer::{
        AssertionProof, AttestationQuoteAssertion, ProducerAssertion, SealedPayloadV1,
        SeedMnemonicBundle, armor, bundle_digest, generate_ed25519_keypair, seal_payload,
    };

    // The root seed is the export of every key this VTA holds: the same
    // capability as any other export (VTI-VTA-003), not only the role.
    crate::operations::keys::ensure_may_export(&state.acl_ks, &auth, "attestation/mnemonic")
        .await?;

    if req.version != 1 {
        return Err(AppError::Validation(format!(
            "unsupported request version: {}",
            req.version
        )));
    }
    let client_ed25519_pub = req
        .decode_client_ed25519_pub()
        .map_err(|e| AppError::Validation(format!("invalid client_did: {e}")))?;
    let client_x25519_pub = req
        .decode_client_x25519_pub()
        .map_err(|e| AppError::Validation(format!("invalid client_did: {e}")))?;
    let bundle_id = req
        .decode_nonce()
        .map_err(|e| AppError::Validation(format!("invalid nonce: {e}")))?;

    let tee = state.tee.as_ref().ok_or_else(|| {
        tee_attestation_error("mnemonic export not available (TEE mode not active)")
    })?;
    let guard = tee.mnemonic_guard.as_ref().ok_or_else(|| {
        tee_attestation_error(
            "mnemonic export not available (TEE mode not active or no KMS bootstrap)",
        )
    })?;

    let _serial = MNEMONIC_EXPORT_LOCK.lock().await;
    // Two-phase: the entropy is consumed only once the bundle exists and the
    // release is recorded, so a failure here cannot lose the root seed.
    let reservation = guard.reserve()?;

    let (_producer_seed, producer_ed_pub) = generate_ed25519_keypair();
    let producer_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&producer_ed_pub);
    let mut hasher = Sha256::new();
    hasher.update(client_ed25519_pub);
    hasher.update(bundle_id);
    hasher.update(producer_ed_pub);
    let user_data = hasher.finalize();
    let report = tee
        .state
        .provider
        .attest(user_data.as_slice(), &bundle_id)
        .map_err(|e| AppError::Internal(format!("tee attest failed: {e}")))?;
    let assertion = ProducerAssertion {
        producer_did,
        proof: AssertionProof::Attested(AttestationQuoteAssertion {
            format: format!("{}", report.tee_type),
            quote_b64: report.evidence,
        }),
    };
    let vta_did = state.config.read().await.vta_did.clone();
    let payload = SealedPayloadV1::SeedMnemonic(Box::new(SeedMnemonicBundle {
        mnemonic: reservation.mnemonic().to_string(),
        vta_did,
    }));
    let nonce_store =
        crate::sealed_nonce_store::PersistentNonceStore::new(state.sealed_nonces_ks.clone());
    let sealed = seal_payload(
        &client_x25519_pub,
        bundle_id,
        assertion,
        &payload,
        &nonce_store,
    )
    .await;
    drop(payload);
    let bundle =
        sealed.map_err(|e| AppError::Internal(format!("sealed-transfer seal failed: {e}")))?;
    let digest = bundle_digest(&bundle);

    // Recorded durably before the bundle leaves, and a failed write refuses
    // the export — the same rule as `keys/export-secret` (VTI-VTA-003). The
    // row names the caller, the recipient key and the transport; never the
    // words.
    crate::audit::record_with_detail(
        &state.audit_sink,
        "seed.mnemonic_export",
        &auth.did,
        Some(&req.client_did),
        "success",
        Some("rest/sealed"),
        None,
        Some(&format!("bundle_sha256:{digest}")),
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

    let window_remaining_secs = reservation.window_remaining_secs();
    reservation.commit();
    Ok(Json(SealedMnemonicResponse {
        bundle: armor::encode(&bundle),
        digest,
        window_remaining_secs,
    }))
}
