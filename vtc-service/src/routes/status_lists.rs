//! Public BitstringStatusList route — `GET
//! /v1/status-lists/{purpose}` (M2.11).
//!
//! Verifier-facing, unauthenticated, Trust-Task-exempt — same
//! rationale as `/.well-known/did.jsonl`: external verifiers
//! resolve credentials through standard W3C verification flows
//! that don't carry our extension header.
//!
//! Responses:
//!
//! - `200` with the freshly-signed `BitstringStatusListCredential`
//!   VC as JSON.
//! - `404` for `purpose` values other than `revocation` /
//!   `suspension`, or when the daemon has not provisioned that
//!   purpose yet (pre-`public_url` deployment).
//! - `503` when the credential signer or state row aren't ready
//!   (the daemon booted without a `VtcKeyBundle`).
//!
//! `Cache-Control: no-store` is set on every response — flips
//! land in real time and a stale cached copy would mask a
//! revocation.

use affinidi_status_list::StatusPurpose;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::Value as JsonValue;
use vti_common::error::AppError;

use crate::server::AppState;
use crate::status_list;

/// Parse the wire-form `purpose` path segment. Returns `None` for
/// unknown values (which the handler maps to 404).
fn parse_purpose(s: &str) -> Option<StatusPurpose> {
    match s {
        "revocation" => Some(StatusPurpose::Revocation),
        "suspension" => Some(StatusPurpose::Suspension),
        _ => None,
    }
}

/// GET /status-lists/{purpose} — public BitstringStatusList credential.
/// Unauthenticated, Trust-Task-exempt verifier endpoint.
#[utoipa::path(
    get, path = "/status-lists/{purpose}", tag = "status-lists",
    params(("purpose" = String, Path, description = "'revocation' or 'suspension'")),
    responses(
        (status = 200, description = "Bitstring status list credential", content_type = "application/json"),
        (status = 404, description = "Unknown or unprovisioned purpose"),
        (status = 503, description = "Credential signer or state not ready"),
    ),
)]
pub async fn show(
    State(state): State<AppState>,
    Path(purpose_str): Path<String>,
) -> Result<Response, AppError> {
    let purpose = parse_purpose(&purpose_str).ok_or_else(|| {
        AppError::NotFound(format!(
            "unknown status-list purpose '{purpose_str}' \
             (expected 'revocation' or 'suspension')"
        ))
    })?;

    let signer = state.credential_signer.as_ref().ok_or_else(|| {
        // Same shape `routes::install` returns when the secret
        // store is unset — operators get a clear "run setup first"
        // signal rather than an opaque 500.
        AppError::Internal(format!(
            "credential signer not initialised — status list for {purpose} unavailable"
        ))
    })?;

    let row = status_list::get_state(&state.status_lists_ks, purpose).await?;
    let row = row.ok_or_else(|| {
        AppError::NotFound(format!(
            "status list for {purpose} not provisioned — \
             set `public_url` and restart the daemon to initialise"
        ))
    })?;

    let vc = status_list::build_status_list_credential(signer, &row).await?;
    let body = serde_json::to_value(&vc)
        .map_err(|e| AppError::Internal(format!("status-list VC serialize: {e}")))?;

    // `Cache-Control: no-store` — spec §6.2 calls flips
    // "immediate locally". A CDN cache between us and a verifier
    // would defeat that.
    Ok((
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
        ],
        axum::Json::<JsonValue>(body),
    )
        .into_response())
}
