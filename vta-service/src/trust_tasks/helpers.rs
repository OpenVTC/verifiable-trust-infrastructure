// Helpers share the same `Result<_, Response>` shape as the slice
// handlers (see `vault.rs` for the same allow). The Response is owned
// and emitted on the same stack frame as the Err — boxing buys nothing.
#![allow(clippy::result_large_err)]

//! Shared helpers for the trust-task dispatcher and its per-slice
//! handler modules.
//!
//! Centralises:
//! - The `TRANSPORT_TRUST_TASK` audit-log channel label.
//! - Payload parsing (`parse_payload<T>`).
//! - `AppError` → reject-response mapping (`app_error_to_reject`).
//! - Reject + success document construction (`reject_with`,
//!   `success_response`, `error_response`).
//! - Wire-shape error helpers used by the dispatcher itself
//!   (`body_parse_error_response`, `method_not_found`).
//! - `not_implemented_yet` placeholder for Phase 3 slice stubs.
//!
//! All helpers are `pub(super)` — visible to the dispatcher (`mod.rs`)
//! and to the per-slice handler modules, but not to the wider crate.
//! Callers outside `routes::trust_tasks` should not depend on these
//! shapes; the entry point is `dispatch_trust_task` in `mod.rs`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use trust_tasks_https::status_for_code;
use trust_tasks_rs::{ErrorPayload, ErrorResponse, RejectReason, TrustTask, TypeUri};
use uuid::Uuid;

use crate::error::AppError;

/// Transport label passed to operations for audit-log discrimination
/// between the legacy REST path (`"rest"`) and the new trust-task
/// envelope (`"trust-task"`).
pub(super) const TRANSPORT_TRUST_TASK: &str = "trust-task";

/// The transport-neutral result of dispatching a Trust Task: the framework
/// HTTP status code plus the serialised result/error document bytes.
///
/// Both transports render from this one value — the REST route turns it into
/// an `axum::Response` via [`IntoResponse`]; the DIDComm `handle_trust_task`
/// reads [`body`](Self::body) straight as the reply envelope, with no
/// round-trip through an `axum::Response` to re-extract the JSON. The body
/// stays raw bytes (not a `serde_json::Value`) so the wire output is
/// byte-identical to direct document serialisation: serde_json has no
/// `preserve_order` feature here, so a `Value` round-trip would alphabetise
/// object keys and change the bytes.
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

/// Parse a trust-task document's `payload` field as the typed body
/// `T`, or return a `MalformedRequest` rejection response.
///
/// Consolidates the per-handler boilerplate where the only thing that
/// changes is the target type.
pub(super) fn parse_payload<T: serde::de::DeserializeOwned>(
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

/// Map an `AppError` (the operation-layer error type) into a routed
/// trust-task error response with the appropriate framework reject
/// code:
///
/// - `Authentication` / `Unauthorized` / `Forbidden` → `permission_denied`
/// - `Validation` / `TrustTaskMalformed` → `malformed_request`
/// - `NotFound` / `Conflict` → `task_failed`
/// - everything else → `internal_error`
pub(super) fn app_error_to_reject(doc: &TrustTask<Value>, err: AppError) -> TrustTaskOutcome {
    let message = err.to_string();
    let reason = match err {
        AppError::Authentication(_) | AppError::Unauthorized(_) | AppError::Forbidden(_) => {
            RejectReason::PermissionDenied { reason: message }
        }
        AppError::Validation(_) | AppError::TrustTaskMalformed(_) => {
            RejectReason::MalformedRequest { reason: message }
        }
        AppError::NotFound(_) | AppError::Conflict(_) => RejectReason::TaskFailed {
            reason: message,
            details: None,
        },
        _ => RejectReason::InternalError { reason: message },
    };
    reject_with(doc, reason)
}

/// Build a routed rejection document for the given reason and wrap it
/// in an HTTP response. The framework computes the status code from
/// the reject's standard code.
pub(super) fn reject_with(doc: &TrustTask<Value>, reason: RejectReason) -> TrustTaskOutcome {
    let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), reason);
    error_response(routed)
}

/// Build a routed success document with the given payload and wrap
/// it in an HTTP 200 response.
pub(super) fn success_response<R: serde::Serialize>(
    doc: &TrustTask<Value>,
    payload: R,
) -> TrustTaskOutcome {
    let response_doc = doc.respond_with(format!("urn:uuid:{}", Uuid::new_v4()), payload);
    let body = match serde_json::to_vec(&response_doc) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "failed to serialise success response doc");
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

/// Build a routed `task_failed` rejection for a URI we know about but
/// haven't implemented yet. Kept available for Phase 3+ slices that
/// land their match arms before the handler body — each new slice can
/// stub via this helper, then replace with a real handler.
#[allow(dead_code)]
pub(super) fn not_implemented_yet(doc: TrustTask<Value>, reason: &str) -> TrustTaskOutcome {
    let reject = RejectReason::TaskFailed {
        reason: reason.to_string(),
        details: None,
    };
    let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), reject);
    error_response(routed)
}

/// Build an `unsupported_type` rejection for an unrecognised type URI.
pub(super) fn method_not_found(doc: TrustTask<Value>, type_uri: &str) -> TrustTaskOutcome {
    let reject = RejectReason::UnsupportedType {
        type_uri: type_uri.to_string(),
    };
    let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), reject);
    error_response(routed)
}

/// Wrap a routed `ErrorResponse` in an HTTP response with the right
/// status code per the framework's status table.
pub(super) fn error_response(err_doc: ErrorResponse) -> TrustTaskOutcome {
    let status = StatusCode::from_u16(status_for_code(&err_doc.payload.code))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = serde_json::to_vec(&err_doc).unwrap_or_else(|_| Vec::new());
    TrustTaskOutcome { status, body }
}

/// Build a `trust-task-error/0.1` document for a body-parse failure.
/// Unrouted (no issuer / recipient) — the framework permits this on
/// malformed-body failures since the producer can correlate on the
/// response `id`.
pub(super) fn body_parse_error_response(reason: &str) -> TrustTaskOutcome {
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
