//! `POST /v1/join-requests` — REST submit (M1.8.1) + a shared
//! inner `submit_inner` the DIDComm handler (M1.8.2) calls into.
//!
//! ## Holder binding
//!
//! Phase 1 plan §D4 requires only the holder-binding proof: the
//! signature must verify against the applicant_did's intrinsic
//! Ed25519 public key (did:key only — did:webvh resolution lands
//! in Phase 2).
//!
//! Wire shape:
//!
//! ```text
//! {
//!   "applicantDid": "did:key:z…",
//!   "vp":               { … opaque JSON … },
//!   "registryConsent":  ? bool,
//!   "extensions":       ? object,
//!   "audience":         "<this VTC's did>",
//!   "created":          <unix-seconds>,
//!   "signature":        "<hex Ed25519 signature>"
//! }
//! ```
//!
//! Canonical signing payload:
//!
//! ```text
//! "vtc-join-request/v1\0" || canonical_json({
//!   "applicantDid":     applicant_did,
//!   "vp":               vp,
//!   "registryConsent":  registry_consent (default false),
//!   "extensions":       extensions (default null),
//!   "audience":         audience,
//!   "created":          created,
//! })
//! ```
//!
//! `canonical_json` is just `serde_json::to_vec` on a
//! key-ordered object — sufficient because both sides agree on
//! the field ordering via the typed struct.
//!
//! `audience` (must equal this VTC's `vtc_did`) and `created` (within a
//! short freshness window) are bound into the signature so a captured body
//! can't be replayed against another community or after the window (P0.13).
//! On the DIDComm path the authcrypt envelope authenticates + addresses the
//! sender, so it carries no separate signature/audience/created.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use vti_common::error::AppError;

use crate::join::{HolderBinding, JoinTransport, submit_inner};
use crate::server::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct SubmitRequestBody {
    pub applicant_did: String,
    pub vp: JsonValue,
    #[serde(default)]
    pub registry_consent: bool,
    #[serde(default)]
    pub extensions: JsonValue,
    /// The VTC this submission is addressed to — must equal this VTC's
    /// `vtc_did`. Bound into the holder signature so a body captured for one
    /// community can't be replayed against another (P0.13).
    pub audience: String,
    /// Unix-seconds the applicant signed at. Must be within
    /// [`JOIN_SUBMIT_FRESHNESS_SECS`] of now (small future skew allowed). Bound
    /// into the signature so a stale captured body is rejected (P0.13).
    pub created: i64,
    /// Hex-encoded Ed25519 signature over the canonical payload (which now
    /// includes `audience` + `created`).
    pub signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct SubmitResponse {
    pub request_id: Uuid,
    pub status: String,
    /// Issued VMC — present only when the join policy **auto-admitted**
    /// (verdict `allow`). The applicant, who proved holder-binding,
    /// receives their membership credential inline. `None` when the
    /// request was queued (`pending`/`deferred`) or rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmc: Option<JsonValue>,
    /// Issued role VEC — same delivery story as [`Self::vmc`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_vec: Option<JsonValue>,
}

/// POST /join-requests — submit a join request. Public: the holder-binding
/// signature (REST) or authcrypt sender (DIDComm) IS the auth.
#[utoipa::path(
    post, path = "/join-requests", tag = "join-requests",
    request_body = SubmitRequestBody,
    responses(
        (status = 201, description = "Join request submitted", body = SubmitResponse),
        (status = 400, description = "Holder-binding / audience / freshness validation failed"),
        (status = 409, description = "An open join request already exists for this applicant"),
    ),
)]
pub async fn submit(
    State(state): State<AppState>,
    Json(req): Json<SubmitRequestBody>,
) -> Result<(StatusCode, Json<SubmitResponse>), AppError> {
    let outcome = submit_inner(
        &state,
        req.applicant_did,
        req.vp,
        req.registry_consent,
        req.extensions,
        Some(HolderBinding {
            signature_hex: &req.signature,
            audience: &req.audience,
            created: req.created,
        }),
        JoinTransport::Rest,
    )
    .await?;

    let (vmc, role_vec) = match &outcome.admit {
        Some(a) => (
            Some(
                serde_json::to_value(&a.vmc)
                    .map_err(|e| AppError::Internal(format!("serialise VMC: {e}")))?,
            ),
            Some(
                serde_json::to_value(&a.role_vec)
                    .map_err(|e| AppError::Internal(format!("serialise VEC: {e}")))?,
            ),
        ),
        None => (None, None),
    };

    Ok((
        StatusCode::CREATED,
        Json(SubmitResponse {
            request_id: outcome.request.id,
            status: outcome.request.status.to_string(),
            vmc,
            role_vec,
        }),
    ))
}
