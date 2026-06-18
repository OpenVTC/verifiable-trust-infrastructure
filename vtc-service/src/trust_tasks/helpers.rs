// Helpers return an owned `TrustTaskOutcome` (status + serialised document
// bytes) rather than the large `Result<_, Response>` the VTA uses — the
// transport adapters render it for REST or DIDComm.
#![allow(clippy::result_large_err)]

//! Shared helpers for the VTC join-request Trust Task dispatcher.
//!
//! Mirrors `vta-service/src/trust_tasks/helpers.rs`:
//! - `TrustTaskOutcome` — the transport-neutral dispatch result.
//! - `parse_payload<T>` — typed payload extraction (→ `MalformedRequest`).
//! - `success_response` / `verdict_response` — `#response` document
//!   construction via `TrustTask::respond_with`.
//! - `reject_with` / `app_error_to_reject` / `error_response` —
//!   `trust-task-error` document construction (the framework reject path).
//! - `body_parse_error_response` — unrouted reject for a body that is not a
//!   Trust Task document at all.
//! - `verify_trust_task_proof` — the holder's `eddsa-jcs-2022` DI proof
//!   verifier for the REST path (ported from the VTA's `auth::di_proof`).

use affinidi_data_integrity::{DataIntegrityProof, DidKeyResolver, VerifyOptions};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::Value;
use trust_tasks_https::status_for_code;
use trust_tasks_rs::{ErrorPayload, ErrorResponse, RejectReason, TrustTask, TypeUri};
use uuid::Uuid;
use vti_common::error::AppError;

use vta_sdk::protocols::join_requests::VerdictResponse;

/// The transport-neutral result of dispatching a Trust Task: the framework
/// HTTP status code plus the serialised result/error document bytes.
///
/// Both transports render from this one value — the REST route turns it into
/// an `axum::Response` via [`IntoResponse`]; the DIDComm handler reads
/// [`body`](Self::body) straight as the reply envelope. The body stays raw
/// bytes (not a `serde_json::Value`) so the wire output is byte-identical to
/// direct document serialisation (serde_json has no `preserve_order` here, so
/// a `Value` round-trip would alphabetise object keys).
pub(crate) struct TrustTaskOutcome {
    pub(crate) status: StatusCode,
    pub(crate) body: Vec<u8>,
}

impl IntoResponse for TrustTaskOutcome {
    fn into_response(self) -> Response {
        (
            self.status,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            self.body,
        )
            .into_response()
    }
}

/// Parse a Trust Task document's `payload` field as the typed body `T`, or
/// return a `MalformedRequest` rejection response.
pub(crate) fn parse_payload<T: serde::de::DeserializeOwned>(
    doc: &TrustTask<Value>,
) -> Result<T, TrustTaskOutcome> {
    serde_json::from_value::<T>(doc.payload.clone()).map_err(|e| {
        reject_with(
            doc,
            RejectReason::MalformedRequest {
                reason: format!("payload parse: {e}"),
            },
        )
    })
}

/// Map an `AppError` into a routed Trust Task error response with the
/// appropriate framework reject code — the same taxonomy the VTA uses, and
/// the same 4xx distinction the VTC's REST boundary preserves:
///
/// - `Authentication` / `Unauthorized` / `Forbidden` / `StepUpRequired` →
///   `permission_denied`
/// - `Validation` / `TrustTaskMalformed` / `TrustTaskMissing` /
///   `InvalidCursor` → `malformed_request`
/// - `NotFound` / `Conflict` / `IdempotencyKeyConflict` → `task_failed`
/// - everything else → `internal_error`
pub(crate) fn app_error_to_reject(doc: &TrustTask<Value>, err: &AppError) -> TrustTaskOutcome {
    let message = err.to_string();
    let reason = match err {
        AppError::Authentication(_)
        | AppError::Unauthorized(_)
        | AppError::Forbidden(_)
        | AppError::StepUpRequired(_) => RejectReason::PermissionDenied { reason: message },
        AppError::Validation(_)
        | AppError::TrustTaskMalformed(_)
        | AppError::TrustTaskMissing
        | AppError::InvalidCursor => RejectReason::MalformedRequest { reason: message },
        AppError::NotFound(_) | AppError::Conflict(_) | AppError::IdempotencyKeyConflict => {
            RejectReason::TaskFailed {
                reason: message,
                details: None,
            }
        }
        _ => RejectReason::InternalError { reason: message },
    };
    reject_with(doc, reason)
}

/// Build a routed rejection document for the given reason. The framework
/// computes the status code from the reject's standard code.
pub(crate) fn reject_with(doc: &TrustTask<Value>, reason: RejectReason) -> TrustTaskOutcome {
    let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), reason);
    error_response(routed)
}

/// Build a routed `#response` document with the given payload and wrap it in
/// an HTTP 200 response.
pub(crate) fn success_response<R: Serialize>(
    doc: &TrustTask<Value>,
    payload: R,
) -> TrustTaskOutcome {
    let response_doc = doc.respond_with(format!("urn:uuid:{}", Uuid::new_v4()), payload);
    let body = match serde_json::to_vec(&response_doc) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "failed to serialise Trust Task success document");
            return reject_with(
                doc,
                RejectReason::InternalError {
                    reason: format!("response serialisation: {e}"),
                },
            );
        }
    };
    TrustTaskOutcome {
        status: StatusCode::OK,
        body,
    }
}

/// Convenience wrapper over [`success_response`] for the `request`/`present`
/// verbs, whose response payload is always a [`VerdictResponse`].
pub(crate) fn verdict_response(
    doc: &TrustTask<Value>,
    verdict: VerdictResponse,
) -> TrustTaskOutcome {
    success_response(doc, verdict)
}

/// Wrap a routed [`ErrorResponse`] in an outcome with the right status code
/// per the framework's status table.
pub(crate) fn error_response(err_doc: ErrorResponse) -> TrustTaskOutcome {
    let status = StatusCode::from_u16(status_for_code(&err_doc.payload.code))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = serde_json::to_vec(&err_doc).unwrap_or_default();
    TrustTaskOutcome { status, body }
}

/// Build a `trust-task-error/0.1` document for a body-parse failure.
/// Unrouted (no issuer / recipient) — the framework permits this on
/// malformed-body failures since the producer can correlate on the response
/// `id`.
pub(crate) fn body_parse_error_response(reason: &str) -> TrustTaskOutcome {
    let reject = RejectReason::MalformedRequest {
        reason: format!("body did not parse as a Trust Task document: {reason}"),
    };
    let payload: ErrorPayload = reject.into();
    let type_uri: TypeUri = "https://trusttasks.org/spec/trust-task-error/0.1"
        .parse()
        .expect("framework error Type URI parses");
    let err = ErrorResponse {
        id: format!("urn:uuid:{}", Uuid::new_v4()),
        thread_id: None,
        type_uri,
        issuer: None,
        recipient: None,
        issued_at: Some(chrono::Utc::now()),
        expires_at: None,
        payload,
        context: None,
        proof: None,
        extra: Default::default(),
    };
    error_response(err)
}

/// Verify the holder's `eddsa-jcs-2022` Data-Integrity proof on `doc` and
/// return the proven signer DID — the base DID (before `#`) of the proof's
/// `verificationMethod`. Ported from `vta-service::auth::di_proof`.
///
/// The signature is verified over the document with its `proof` removed
/// (`eddsa-jcs-2022` canonicalises the proofless document via JCS). The
/// returned DID is *proven*, not merely claimed — binding it to an expected
/// identity is the caller's job. `did:key` resolution is local (no network).
pub(crate) async fn verify_trust_task_proof(doc: &TrustTask<Value>) -> Result<String, AppError> {
    let proof = doc
        .proof
        .as_ref()
        .ok_or_else(|| AppError::Unauthorized("Trust Task document has no proof".into()))?;

    let di: DataIntegrityProof = serde_json::to_value(proof)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or_else(|| {
            AppError::Unauthorized("Trust Task proof is not a Data Integrity proof".into())
        })?;

    let signer_did = di
        .verification_method
        .split('#')
        .next()
        .unwrap_or_default()
        .to_string();
    if signer_did.is_empty() {
        return Err(AppError::Unauthorized(
            "Trust Task proof verificationMethod carries no DID".into(),
        ));
    }

    let mut unsigned = doc.clone();
    unsigned.proof = None;
    di.verify(&unsigned, &DidKeyResolver, VerifyOptions::new())
        .await
        .map_err(|e| {
            AppError::Unauthorized(format!("Trust Task proof verification failed: {e}"))
        })?;

    Ok(signer_did)
}
