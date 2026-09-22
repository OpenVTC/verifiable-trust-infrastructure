//! `POST /v1/credential-exchange/request` — redeem a credential offer over
//! HTTPS (`credential-exchange/request/0.1`).
//!
//! The messaging bindings carry this task already (`messaging.rs`); this is
//! the route for a holder with no messaging service — the invitee who scanned
//! a `vtc/invitations/deliver` QR code (Keyring VTI-32). Unauthenticated, like
//! join submit: what authorises the release is the OID4VCI key-binding proof
//! inside the request, which must be by a key of the DID the offer was made
//! for. Where a messaging binding answers on-thread with a
//! `credential-exchange/issue` document, HTTPS answers with its payload.

use axum::Json;
use axum::extract::State;
use vta_sdk::openapi::{CredentialIssue01Payload, CredentialRequest01Payload};
use vti_common::error::AppError;

use crate::credentials::vm_resolver::DidVmResolver;
use crate::server::AppState;

#[utoipa::path(
    post, path = "/credential-exchange/request",
    operation_id = "credentialRequest", tag = "credentials",
    request_body = CredentialRequest01Payload,
    responses(
        (status = 200, description = "The credential, for the proven holder", body = CredentialIssue01Payload),
        (status = 400, description = "Malformed request, or a proof that does not verify"),
        (status = 403, description = "The proof is by a key of a DID the offer was not made for"),
        (status = 404, description = "No live offer for this code"),
    ),
)]
pub async fn request(
    State(state): State<AppState>,
    Json(body): Json<CredentialRequest01Payload>,
) -> Result<Json<CredentialIssue01Payload>, AppError> {
    let request: affinidi_openid4vci::CredentialRequest = serde_json::from_value(
        serde_json::Value::Object(body.into_inner().credential_request),
    )
    .map_err(|e| AppError::Validation(format!("malformed credential request: {e}")))?;
    let response = crate::credentials::redeem(
        &state.join_requests_ks,
        &request,
        chrono::Utc::now(),
        &DidVmResolver::new(state.did_resolver.clone()),
    )
    .await?;
    let issue = serde_json::json!({ "credential_response": response });
    let payload: trust_tasks_rs::specs::credential_exchange::issue::v0_1::Payload =
        serde_json::from_value(issue)
            .map_err(|e| AppError::Internal(format!("build issue payload: {e}")))?;
    Ok(Json(payload.into()))
}
