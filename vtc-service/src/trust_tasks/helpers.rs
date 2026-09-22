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
//!   `vti_common::auth`, re-exported from `vta_sdk::trust_task_proof` so a client
//!   verifies its replies with the same code a service verifies its requests).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::Value;
use trust_tasks_https::status_for_code;
use trust_tasks_rs::{
    ErrorPayload, ErrorResponse, RejectReason, TrustTask, TrustTaskCode, TypeUri,
};
use uuid::Uuid;
use vta_sdk::protocols::trust_task_reject_reasons as reasons;
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
/// - `NotFound` / `Conflict` / `IdempotencyKeyConflict` / `Gone` →
///   `task_failed`, each discriminated by a `details.reason` from
///   [`vta_sdk::protocols::trust_task_reject_reasons`] so the client recovers
///   the typed variant
/// - everything else → `internal_error`, with the cause logged and **not**
///   sent
pub(crate) fn app_error_to_reject<P>(doc: &TrustTask<P>, err: &AppError) -> TrustTaskOutcome {
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
        // These have no standard code of their own — §8.3 defines no
        // `notFound` / `conflict` / `gone` — so all of them ride out under
        // `taskFailed`. That is the correct wire code and it is not enough on
        // its own: a caller cannot tell "the row you asked for is absent",
        // very often a *normal* state it knows how to handle, from "this
        // operation genuinely failed", and the distinction that REST keeps in
        // an HTTP status is simply lost.
        //
        // So the discriminator goes in `details.reason`, which is what
        // `VtaClient::trust_task_error` reads back into the same typed
        // `VtaError` variant the REST and problem-report paths produce. The
        // VTA has done this since its own gate went in; the VTC never did, so
        // every `NotFound`, `Conflict` and `Gone` this service produced
        // reached a Trust Task client as an opaque `Protocol(String)` — the
        // exact collapse `CLAUDE.md` names ("never collapse a Conflict into a
        // string"), and the same defect #1602 fixed from the client end for
        // the one code whose local part happens to be `notFound`.
        //
        // `Gone` is a terminal caller-visible outcome, not a server fault, so
        // it stays out of the `internal_error` fallback, which would tell the
        // client to retry a permanently-consumed resource.
        AppError::NotFound(_) => task_failed_because(message, reasons::NOT_FOUND),
        AppError::Conflict(_) | AppError::IdempotencyKeyConflict => {
            task_failed_because(message, reasons::CONFLICT)
        }
        AppError::Gone(_) => task_failed_because(message, reasons::GONE),
        // Framework 0.5.0, *What a `message` May Not Say*: a `message` MUST
        // NOT reveal consumer-internal state. Passing `err.to_string()` out
        // sent the cause verbatim — "vtc_did not configured",
        // "audit_writer not initialised", a fjall or serde failure — which
        // tells an unauthenticated caller the deployment's shape and which
        // internal invariant just broke.
        //
        // The producer needs one fact from an `internalError`: the failure was
        // not its document's doing, so re-sending may work. The cause is what
        // the *operator* needs, and it goes to the log where the operator is.
        // Every other arm above describes the caller's own request back to it,
        // which is not consumer-internal state, and passes through unchanged.
        other => {
            tracing::error!(cause = %other, "trust task failed with an internal error");
            RejectReason::InternalError {
                reason: OPAQUE_INTERNAL_ERROR.to_string(),
            }
        }
    };
    reject_with(doc, reason)
}

/// Map a [`TaskError`](crate::error::TaskError) into a routed rejection.
///
/// An undeclared error goes through [`app_error_to_reject`] unchanged. A
/// declared one goes out under its task's extended code (SPEC §8.5) — the
/// thing the generic mapping cannot do, and the reason `withdraw` (#1591) and
/// `supplement` (#1593) each grew a hand-written arm. A `NotFound` /
/// `Conflict` / `Gone` keeps its `details.reason` marker beside the code, so a
/// client that does not know the code still recovers the typed variant.
pub(crate) fn task_error_to_reject<P>(
    doc: &TrustTask<P>,
    err: &crate::error::TaskError,
) -> TrustTaskOutcome {
    use crate::error::TaskError;
    match err {
        TaskError::App(e) => app_error_to_reject(doc, e),
        TaskError::Declared { code, error } => {
            let message = error.to_string();
            let marker = match error {
                AppError::NotFound(_) => Some(reasons::NOT_FOUND),
                AppError::Conflict(_) | AppError::IdempotencyKeyConflict => Some(reasons::CONFLICT),
                AppError::Gone(_) => Some(reasons::GONE),
                _ => None,
            };
            match marker {
                Some(reason) => {
                    reject_with_code_because(doc, extended_code(code), message, None, reason)
                }
                None => reject_with_code(doc, extended_code(code), message, None),
            }
        }
    }
}

/// A specification-extended error code, `<slug>:<local>`, as a framework code.
pub(crate) fn extended_code(code: &str) -> TrustTaskCode {
    let (slug, local) = code
        .rsplit_once(':')
        .expect("an extended code is <slug>:<local>");
    TrustTaskCode::Extended {
        slug: slug.to_string(),
        local: local.to_string(),
    }
}

/// A `taskFailed` carrying the `details.reason` discriminator a client reads
/// back into a typed [`vta_sdk::error::VtaError`]. Twin of `vta-service`'s
/// function of the same name — the two services must not disagree about how a
/// missing row reaches a caller.
fn task_failed_because(message: String, reason: &str) -> RejectReason {
    RejectReason::TaskFailed {
        reason: message,
        details: Some(serde_json::json!({ "reason": reason })),
    }
}

/// [`reject_with_code`] plus the `details.reason` discriminator.
///
/// An extended code is what a client *should* branch on, but only if it knows
/// that code. SPEC §8.5's fallback says one that does not treats the error as
/// `taskFailed` — at which point it is back to needing the marker to tell an
/// absent row from a failure. #1602 recovered `NotFound` for codes whose local
/// part is literally `notFound`; nothing recovers `Conflict` or `Gone`, so a
/// declared `:alreadyDecided` or `:requestAlreadyOpen` reached every client as
/// an opaque `Protocol(String)`.
///
/// Carrying both means a client that knows the code gets the precise reason
/// and one that does not still gets the right typed variant.
pub(crate) fn reject_with_code_because<P>(
    doc: &TrustTask<P>,
    code: TrustTaskCode,
    message: impl Into<String>,
    details: Option<Value>,
    reason: &str,
) -> TrustTaskOutcome {
    let details = match details {
        // Merge rather than replace: the spec'd annex members (`requestId`,
        // `status`) are what the applicant's client acts on.
        Some(Value::Object(mut map)) => {
            map.insert("reason".into(), Value::String(reason.to_string()));
            Value::Object(map)
        }
        // A non-object `details` is not a shape this service emits, and
        // silently dropping it would hide that. Nothing calls it that way.
        Some(other) => {
            tracing::warn!(
                "non-object `details` on a coded reject; the reason marker was added beside it"
            );
            serde_json::json!({ "reason": reason, "details": other })
        }
        None => serde_json::json!({ "reason": reason }),
    };
    reject_with_code(doc, code, message, Some(details))
}

/// What an `internalError` says instead of the cause.
///
/// It tells the producer the one thing it can act on — the failure was not its
/// document's fault — and nothing an unauthenticated caller could probe with.
/// Deliberately the same sentence `vta-service` uses.
pub(crate) const OPAQUE_INTERNAL_ERROR: &str =
    "the consumer could not complete this task; the request itself was accepted";

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
pub(crate) fn reject_with<P>(doc: &TrustTask<P>, reason: RejectReason) -> TrustTaskOutcome {
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
pub(crate) fn reject_with_code<P>(
    doc: &TrustTask<P>,
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
pub(crate) fn success_response<P, R: Serialize>(
    doc: &TrustTask<P>,
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
/// Thin adapter over [`vti_common::auth::verify_trust_task_proof`],
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
    vti_common::auth::verify_trust_task_proof_with(doc, &state.trust_task_vm_resolver())
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

    /// Framework 0.5.0, *What a `message` May Not Say*: an `internalError`
    /// must not carry consumer-internal state. This service used to send
    /// `err.to_string()` verbatim, so an unauthenticated caller learned which
    /// internal invariant broke and, with it, the deployment's shape.
    ///
    /// The cause still has to reach the operator, so it goes to the log. This
    /// test only pins that it does not reach the wire.
    #[test]
    fn an_internal_error_does_not_send_its_cause() {
        let secret = "vtc_did not configured";
        let out = app_error_to_reject(&doc(), &AppError::Internal(secret.into()));
        let body = String::from_utf8(out.body).expect("the reject body is UTF-8");

        assert!(
            !body.contains(secret),
            "the cause must not reach the wire: {body}"
        );
        assert!(
            body.contains(OPAQUE_INTERNAL_ERROR),
            "and the opaque sentence must: {body}"
        );

        // A second cause of a different shape, because the leak was in a
        // catch-all arm rather than in `Internal` alone.
        let out = app_error_to_reject(
            &doc(),
            &AppError::SecretStore("keyring backend unavailable at /run/user/1000".into()),
        );
        let body = String::from_utf8(out.body).expect("the reject body is UTF-8");
        assert!(!body.contains("keyring backend"), "{body}");
        assert!(body.contains(OPAQUE_INTERNAL_ERROR), "{body}");
    }

    /// The three caller-visible outcomes carry the marker a client reads back
    /// into a typed `VtaError`, and still say what happened in prose — they
    /// describe the caller's own request, which is not internal state.
    #[test]
    fn caller_visible_failures_carry_their_reason_marker() {
        for (err, want) in [
            (AppError::NotFound("no such row".into()), reasons::NOT_FOUND),
            (AppError::Conflict("already open".into()), reasons::CONFLICT),
            (AppError::Gone("withdrawn".into()), reasons::GONE),
            (AppError::IdempotencyKeyConflict, reasons::CONFLICT),
        ] {
            let out = app_error_to_reject(&doc(), &err);
            let body: Value = serde_json::from_slice(&out.body).expect("reject body is JSON");
            assert_eq!(
                body.pointer("/payload/details/reason")
                    .and_then(Value::as_str),
                Some(want),
                "{err:?} must carry {want}: {body}"
            );
        }
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
