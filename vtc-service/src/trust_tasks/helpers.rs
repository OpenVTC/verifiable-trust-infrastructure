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
//!   verifier for the REST path (an adapter over the shared
//!   `vti_common::auth::di_proof`, which both services now use).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::Value;
use trust_tasks_https::status_for_code;
use trust_tasks_rs::{
    ErrorPayload, ErrorResponse, RejectReason, TrustTask, TrustTaskCode, TypeUri,
};
use uuid::Uuid;
use vti_common::error::AppError;

use crate::server::AppState;

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
        // `Gone` is a terminal caller-visible outcome, not a server fault —
        // keep it out of the `internal_error` fallback, which would tell the
        // client to retry a permanently-consumed resource.
        AppError::NotFound(_)
        | AppError::Conflict(_)
        | AppError::Gone(_)
        | AppError::IdempotencyKeyConflict => RejectReason::TaskFailed {
            reason: message,
            details: None,
        },
        _ => RejectReason::InternalError { reason: message },
    };
    reject_with(doc, reason)
}

/// Framework 0.5.0, *Bounding `details`*: where a specification declares no
/// bound, 4096 bytes of JCS and 16 immediate members apply.
const DETAILS_MAX_JCS_BYTES: usize = 4096;
/// Companion to [`DETAILS_MAX_JCS_BYTES`].
const DETAILS_MAX_MEMBERS: usize = 16;

/// Drop a `details` annex that exceeds the framework's bound, keeping the code.
///
/// Twin of `vta-service`'s function of the same name and deliberately identical
/// — the bound is a framework rule, not a per-service policy, so the two must
/// not drift into different ideas of how much a rejection may carry.
///
/// An oversized `details` is **ignored, never grounds to discard the `code`**:
/// the code is what the receiving party actually needs, and dropping a whole
/// rejection because its annex was too long would turn a verbose explanation
/// into an unexplained failure.
fn bound_details(details: Option<Value>) -> Option<Value> {
    let details = details?;
    let too_many_members = details
        .as_object()
        .is_some_and(|o| o.len() > DETAILS_MAX_MEMBERS);
    let too_large = serde_json_canonicalizer::to_string(&details)
        .map(|jcs| jcs.len() > DETAILS_MAX_JCS_BYTES)
        // Uncanonicalisable is worse than oversized: it cannot be bounded, so
        // it does not go out.
        .unwrap_or(true);
    if too_many_members || too_large {
        tracing::warn!(
            members = details.as_object().map(serde_json::Map::len),
            "error `details` exceeds the framework bound and was dropped; the code still went out"
        );
        return None;
    }
    Some(details)
}

/// Build a routed rejection document for the given reason. The framework
/// computes the status code from the reject's standard code.
pub(crate) fn reject_with(doc: &TrustTask<Value>, reason: RejectReason) -> TrustTaskOutcome {
    // Bound `details` here rather than at each construction site: this is the
    // funnel every `RejectReason`-shaped rejection passes through, so a new
    // site cannot be added that skips the check.
    let reason = match reason {
        RejectReason::TaskFailed { reason, details } => RejectReason::TaskFailed {
            reason,
            details: bound_details(details),
        },
        other => other,
    };
    let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), reason);
    error_response(routed)
}

/// Reject with an explicit [`TrustTaskCode`] and a `details` annex.
///
/// [`RejectReason`] carries `details` on `TaskFailed` alone, so a rejection
/// under any other standard code has no way to attach machine-readable data
/// through [`reject_with`]. The framework itself is not the limitation:
/// `ErrorPayload::new` takes any code and `TrustTask::reject_with` takes a
/// payload. This is the seam between the two, and the twin of `vta-service`'s
/// helper of the same name.
///
/// `details` passes through [`bound_details`] exactly as in [`reject_with`], so
/// this cannot become the construction site that skips the framework's bound.
pub(crate) fn reject_with_code(
    doc: &TrustTask<Value>,
    code: TrustTaskCode,
    message: impl Into<String>,
    details: Option<Value>,
) -> TrustTaskOutcome {
    let mut payload = ErrorPayload::new(code).with_message(message);
    if let Some(d) = bound_details(details) {
        payload = payload.with_details(d);
    }
    let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), payload);
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

/// The framework's error-document Type URI — the one `TrustTask::reject_with`
/// stamps on every *routed* rejection this service emits.
///
/// Named here because `trust-tasks-rs` keeps `trust_task_error_type_uri()`
/// `pub(crate)`, so the only unrouted path — where there is no request document
/// to reject from — has to write the value out. It said `0.1` while every
/// routed reject went out as `0.3` (the framework has emitted `0.3` since its
/// own 0.3 release, for the §8.2 `inResponseTo` member that `0.2`'s
/// `additionalProperties: false` payload schema cannot admit). One service
/// emitting two versions is a trap for exactly the consumer that pins one of
/// them.
///
/// Now `0.5`, tracking `trust-tasks-rs` 0.9. The framework moved twice for the
/// same reason it moved to `0.3`: a new standard code the older payload
/// schema's `code` enum does not list and whose extended-code pattern does not
/// match, so a document carrying it would fail to validate as the older
/// version. `0.4` carries `idConflict`, `0.5` carries `cancelled` (SPEC §8.3).
/// SPEC §5.2 forward-minor compatibility means a consumer pinned to `0.3`
/// SHOULD still accept these.
///
/// Pinned by `unrouted_and_routed_errors_agree_on_the_type_uri` below, which
/// compares it against a real `reject_with`, so a framework bump fails a test
/// rather than splitting this service into two dialects — which is exactly how
/// this bump was caught.
pub(crate) fn framework_error_type_uri() -> TypeUri {
    "https://trusttasks.org/spec/trust-task-error/0.5"
        .parse()
        .expect("framework error Type URI parses")
}

/// Build a framework error document for a body-parse failure.
/// Unrouted (no issuer / recipient) — the framework permits this on
/// malformed-body failures since the producer can correlate on the response
/// `id`.
pub(crate) fn body_parse_error_response(reason: &str) -> TrustTaskOutcome {
    let reject = RejectReason::MalformedRequest {
        reason: format!("body did not parse as a Trust Task document: {reason}"),
    };
    let payload: ErrorPayload = reject.into();
    let type_uri: TypeUri = framework_error_type_uri();
    let err = ErrorResponse {
        id: format!("urn:uuid:{}", Uuid::new_v4()),
        thread_id: None,
        // Unrouted: there is no parent thread to name either, for the same
        // reason there is no issuer — the body never parsed.
        parent_thread_id: None,
        type_uri,
        issuer: None,
        recipient: None,
        issued_at: Some(chrono::Utc::now()),
        expires_at: None,
        payload,
        context: None,
        // No ceremony, for the same reason as `parent_thread_id` above: SPEC
        // §7.1 carries the member forward from the request so a rejection stays
        // inside the enactment it belonged to, and here there is no request to
        // carry it from — the body never parsed into one. The *routed* rejects
        // get this right for free, because `reject_with` copies it.
        ceremony: None,
        proof: None,
        extra: Default::default(),
    };
    error_response(err)
}

/// Verify the holder's `eddsa-jcs-2022` Data-Integrity proof on `doc` and
/// return the proven signer DID — the base DID (before `#`) of the proof's
/// `verificationMethod`.
///
/// Thin adapter over [`vti_common::auth::di_proof::verify_trust_task_proof`],
/// the single implementation both services share. This used to be a *port* of
/// the VTA's copy; a proof means the same thing at both ends of the mesh, so a
/// second implementation was only ever a chance for the two to disagree. Only
/// the error mapping is local — the join dispatcher renders `AppError`.
///
/// The signature is verified over the document with its `proof` removed
/// (`eddsa-jcs-2022` canonicalises the proofless document via JCS). The
/// returned DID is *proven*, not merely claimed — binding it to an expected
/// identity is the caller's job. `did:key` resolution is local (no network).
pub(crate) async fn verify_trust_task_proof(
    state: &AppState,
    doc: &TrustTask<Value>,
) -> Result<String, AppError> {
    vti_common::auth::di_proof::verify_trust_task_proof_with(doc, &state.trust_task_vm_resolver())
        .await
        .map_err(|e| AppError::Unauthorized(format!("Trust Task {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A probe request to reject. Deliberately typed with a URI this crate
    /// **already binds** (`acl/list/0.1`): `trust_task_manifest`'s census scans
    /// this source tree for `trusttasks.org/spec/` literals and asserts every
    /// one is served by the registry, so inventing a plausible-looking type
    /// here — even in a test — adds a binding the registry has never published
    /// and fails the build. Which is the census working: a URI written down is
    /// a claim about what the registry serves, wherever it is written.
    fn doc() -> TrustTask<Value> {
        let uri: TypeUri = "https://trusttasks.org/spec/acl/list/0.1"
            .parse()
            .expect("acl/list Type URI parses");
        TrustTask::new("urn:uuid:test", uri, json!({}))
    }

    /// The unrouted body-parse error must claim the same document type as a
    /// routed one. It cannot ask the framework — `trust_task_error_type_uri()`
    /// is `pub(crate)` there — so it names the version, and this compares that
    /// against what `reject_with` actually stamps. A framework bump fails here
    /// instead of splitting this service into two dialects, which is how the
    /// unrouted path came to say `0.1` while every routed reject said `0.3`.
    #[test]
    fn unrouted_and_routed_errors_agree_on_the_type_uri() {
        let routed = doc().reject_with(
            "urn:uuid:routed",
            RejectReason::InternalError {
                reason: "probe".into(),
            },
        );
        assert_eq!(
            framework_error_type_uri(),
            routed.type_uri,
            "the unrouted body-parse error names a different document type than \
             the framework stamps on a routed rejection"
        );
    }

    /// …and the bytes on the wire carry it, not just the value we compute.
    #[test]
    fn the_body_parse_error_goes_out_as_a_framework_error_document() {
        let outcome = body_parse_error_response("not json");
        let doc: Value = serde_json::from_slice(&outcome.body).expect("error doc parses");
        assert_eq!(
            doc["type"].as_str().expect("type present"),
            framework_error_type_uri().to_string()
        );
    }
}
