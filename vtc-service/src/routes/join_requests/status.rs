//! `POST /v1/join-requests/{id}/status` — applicant-facing poll
//! (`join-requests/status/1.0`) + a shared `status_inner` the DIDComm
//! handler calls into.
//!
//! The applicant polls their own request's lifecycle while it is in
//! flight (after a `refer` → `Pending`, or a `request_more` →
//! `Deferred`). It is the holder-authenticated counterpart to the
//! admin-only `show`: it returns only non-sensitive lifecycle fields
//! (never the stored VP), and — when `Deferred` — what the applicant
//! must present next, projected from the stored `request_more` verdict.
//!
//! ## Auth
//!
//! Holder-bound to the request's `applicantDid`, like `submit`/`accept`:
//! - REST carries an Ed25519 `signature` over the domain-tagged
//!   ([`JOIN_STATUS_DOMAIN_TAG`]) canonical `{ applicantDid, requestId }`.
//! - DIDComm omits it — the authcrypt sender binds `applicantDid`
//!   (`signature_hex = None`).

use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use vta_sdk::protocols::join_requests::JoinRequestStatusResponseBody;
use vti_common::error::AppError;

use crate::ceremony::Verdict;
use crate::join::{JoinStatus, get_join_request};
use crate::server::AppState;

/// Domain tag prefixing the REST holder-binding signature payload.
/// Distinct from `submit`/`accept` so a status signature can't be
/// replayed against another verb.
pub const JOIN_STATUS_DOMAIN_TAG: &[u8] = b"vtc-join-status/v1\0";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusRequestBody {
    pub applicant_did: String,
    /// Hex-encoded Ed25519 signature over the canonical body.
    pub signature: String,
}

pub async fn status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<StatusRequestBody>,
) -> Result<Json<JoinRequestStatusResponseBody>, AppError> {
    let resp = status_inner(&state, id, body.applicant_did, Some(&body.signature)).await?;
    Ok(Json(resp))
}

/// Shared poll for REST + DIDComm.
///
/// `signature_hex` is `Some` for REST (explicit holder binding) and
/// `None` for DIDComm (the authcrypt sender already authenticated
/// `applicant_did`).
pub async fn status_inner(
    state: &AppState,
    id: Uuid,
    applicant_did: String,
    signature_hex: Option<&str>,
) -> Result<JoinRequestStatusResponseBody, AppError> {
    if let Some(hex_sig) = signature_hex {
        verify_holder_signature(&applicant_did, id, hex_sig)?;
    }

    let req = get_join_request(&state.join_requests_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("join request not found: {id}")))?;
    if req.applicant_did != applicant_did {
        return Err(AppError::Validation(
            "applicantDid does not match the join request applicant".into(),
        ));
    }

    // Project the outstanding requirements only for a Deferred request
    // (a `request_more` verdict the daemon persisted on `policy_decision`).
    let (needs, presentation_definition) = if req.status == JoinStatus::Deferred {
        match req
            .policy_decision
            .and_then(|pd| serde_json::from_value::<Verdict>(pd).ok())
        {
            Some(Verdict::RequestMore(rm)) => (rm.needs, Some(rm.presentation_definition)),
            _ => (Vec::new(), None),
        }
    } else {
        (Vec::new(), None)
    };

    Ok(JoinRequestStatusResponseBody {
        request_id: id,
        status: req.status.to_string(),
        needs,
        presentation_definition,
    })
}

/// Verify the Ed25519 holder-binding signature over the canonical body
/// (`applicantDid` + `requestId`), domain-tagged.
fn verify_holder_signature(
    applicant_did: &str,
    request_id: Uuid,
    signature_hex: &str,
) -> Result<(), AppError> {
    let payload = canonical_payload(applicant_did, request_id)?;
    crate::holder_signature::verify_domain_signed(
        applicant_did,
        JOIN_STATUS_DOMAIN_TAG,
        &payload,
        signature_hex,
    )
    .map_err(AppError::Validation)
}

/// Canonical signing payload — typed struct, field order pinned by the
/// derive (both sides build it identically).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalPayload<'a> {
    applicant_did: &'a str,
    request_id: String,
}

fn canonical_payload(applicant_did: &str, request_id: Uuid) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(&CanonicalPayload {
        applicant_did,
        request_id: request_id.to_string(),
    })
    .map_err(|e| AppError::Internal(format!("canonical payload serialize: {e}")))
}
