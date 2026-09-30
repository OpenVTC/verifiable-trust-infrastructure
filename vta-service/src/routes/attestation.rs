use axum::extract::State;
use axum::response::Response;

use crate::error::AppError;
use crate::server::AppState;

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

// `GET /attestation/mnemonic` (status check) and `POST /attestation/mnemonic`
// (always refused, 403) were REST routes here. They are
// `vta/attestation/mnemonic-status/0.1` (super-admin only) and
// `vta/attestation/mnemonic-export/1.0` (end-to-end only, or signed at first
// boot) now, both served on `/trust-tasks`
// (`crate::trust_tasks::attestation`).
