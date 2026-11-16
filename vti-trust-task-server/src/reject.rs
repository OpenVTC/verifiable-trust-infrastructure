//! Building answers: `#response` documents and framework `trust-task-error`
//! documents, routed (answering a request) or unrouted (a body that never
//! parsed).
//!
//! Every refusal passes through [`reject_with`] or [`reject_with_code`], which
//! bound `details` to the framework's limits, so no construction site can skip
//! that check. The HTTP status of a refusal is the framework's
//! (`trust_tasks_https::status_for_code`).

use axum::http::StatusCode;
use serde::Serialize;
use serde_json::Value;
use trust_tasks_https::status_for_code;
use trust_tasks_rs::{
    ErrorPayload, ErrorResponse, RejectReason, StandardCode, TrustTask, TrustTaskCode, TypeUri,
};
use uuid::Uuid;
use vta_sdk::protocols::trust_task_reject_reasons as reasons;
use vti_common::error::AppError;

use crate::TrustTaskOutcome;

/// Parse a Trust Task document's `payload` field as the typed body `T`, or
/// return a `malformedRequest` refusal.
pub fn parse_payload<T: serde::de::DeserializeOwned>(
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

/// Map an `AppError` into a routed refusal with the matching framework code:
///
/// - `Authentication` / `Unauthorized` / `Forbidden` / `StepUpRequired` →
///   `permissionDenied`
/// - `Validation` / `TrustTaskMalformed` / `TrustTaskMissing` /
///   `InvalidCursor` → `malformedRequest`
/// - `NotFound` / `Conflict` / `IdempotencyKeyConflict` / `Gone` →
///   `taskFailed`, each discriminated by a `details.reason` from
///   [`vta_sdk::protocols::trust_task_reject_reasons`] so a client recovers
///   the typed variant
/// - `ApprovalRequired` → `taskFailed` with its code as `details.reason`
/// - `NoMatchingProtocol` → `taskFailed`, discriminated
///   (`no_matching_protocol`) with what it names
/// - `UnsupportedDidMethod` → `proofInvalid`, `details.reason`
///   `unsupportedDidMethod` and the `method` (VTI-KEY-009)
/// - everything else → `internalError`, with the cause logged and **not** sent
///   ([`OPAQUE_INTERNAL_ERROR`])
///
/// A service that renders some `AppError` differently (an operation parked for
/// approval answered with a next-step document, say) checks for that first and
/// falls through to this.
pub fn app_error_to_reject<P>(doc: &TrustTask<P>, err: &AppError) -> TrustTaskOutcome {
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
        // §8.3 defines no `notFound` / `conflict` / `gone`, so all of them ride
        // out under `taskFailed`, with the discriminator in `details.reason`
        // (what `VtaClient::trust_task_error` reads back into a typed
        // `VtaError`). `Gone` is a terminal caller-visible outcome, not a
        // server fault, so it stays out of the `internalError` fallback, which
        // would tell the client to retry a permanently-consumed resource.
        AppError::NotFound(_) => task_failed_because(message, reasons::NOT_FOUND),
        AppError::Conflict(_) | AppError::IdempotencyKeyConflict => {
            task_failed_because(message, reasons::CONFLICT)
        }
        AppError::Gone(_) => task_failed_because(message, reasons::GONE),
        // No transport in common with a peer this service had to reach: the
        // same `taskFailed` and `details` the VTA answers with, so the SDK
        // reads both back into `VtaError::NoMatchingProtocol`.
        AppError::NoMatchingProtocol(refusal) => RejectReason::TaskFailed {
            reason: message,
            details: Some(serde_json::json!({
                "reason": reasons::NO_MATCHING_PROTOCOL,
                "counterpartyDid": refusal.peer,
                "ours": refusal.ours,
                "theirs": refusal.theirs,
            })),
        },
        // VTI-KEY-009, receiving side: the proof needs a method this service
        // does not resolve. `proofInvalid` is what it is; the discriminator
        // and the method say why.
        AppError::UnsupportedDidMethod { method } => {
            return reject_with_code(
                doc,
                TrustTaskCode::Standard(StandardCode::ProofInvalid),
                message,
                Some(serde_json::json!({
                    "reason": reasons::UNSUPPORTED_DID_METHOD,
                    "method": method,
                })),
            );
        }
        // A decision the caller can still obtain — another party's consent
        // (VTI-APV-002), said the way the VTA's gate says it.
        AppError::ApprovalRequired { code, details } => {
            let mut details = details.clone();
            if let Some(map) = details.as_object_mut() {
                map.insert("reason".into(), Value::String((*code).to_string()));
            }
            RejectReason::TaskFailed {
                reason: (*code).to_string(),
                details: Some(details),
            }
        }
        // Framework 0.5.0, *What a `message` May Not Say*: a `message` MUST
        // NOT reveal consumer-internal state. The producer needs one fact — the
        // failure was not its document's doing — and the cause goes to the
        // operator's log.
        other => {
            tracing::error!(cause = %other, "trust task failed with an internal error");
            RejectReason::InternalError {
                reason: OPAQUE_INTERNAL_ERROR.to_string(),
            }
        }
    };
    reject_with(doc, reason)
}

/// A task-declared code (SPEC §8.5) as a framework code: usually an extended
/// `<slug>:<local>`, but a task may declare a framework code
/// (`malformedRequest`) for a refusal it names no code of its own for, so the
/// code is parsed the way the framework parses any code.
///
/// # Panics
///
/// When `code` is not a Trust Task code at all — a programming error in the
/// declaration, not a runtime condition.
pub fn declared_code(code: &str) -> TrustTaskCode {
    code.parse()
        .unwrap_or_else(|e| panic!("declared code {code:?} is not a Trust Task code: {e}"))
}

/// A specification-extended error code, `<slug>:<local>`, as a framework code.
///
/// # Panics
///
/// When `code` has no `:`.
pub fn extended_code(code: &str) -> TrustTaskCode {
    let (slug, local) = code
        .rsplit_once(':')
        .expect("an extended code is <slug>:<local>");
    TrustTaskCode::Extended {
        slug: slug.to_string(),
        local: local.to_string(),
    }
}

/// A `taskFailed` carrying the `details.reason` discriminator a client reads
/// back into a typed `VtaError`.
fn task_failed_because(message: String, reason: &str) -> RejectReason {
    RejectReason::TaskFailed {
        reason: message,
        details: Some(serde_json::json!({ "reason": reason })),
    }
}

/// [`reject_with_code`] plus the `details.reason` discriminator.
///
/// A client that knows the extended code gets the precise reason, and one that
/// does not (SPEC §8.5 fallback: treat it as `taskFailed`) still recovers the
/// typed variant from the marker.
pub fn reject_with_code_because<P>(
    doc: &TrustTask<P>,
    code: TrustTaskCode,
    message: impl Into<String>,
    details: Option<Value>,
    reason: &str,
) -> TrustTaskOutcome {
    let details = match details {
        // Merge rather than replace: the spec'd annex members are what the
        // client acts on.
        Some(Value::Object(mut map)) => {
            map.insert("reason".into(), Value::String(reason.to_string()));
            Value::Object(map)
        }
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

/// What an `internalError` says instead of the cause: the failure was not the
/// document's fault, and nothing an unauthenticated caller could probe with.
pub const OPAQUE_INTERNAL_ERROR: &str =
    "the consumer could not complete this task; the request itself was accepted";

/// Framework 0.5.0, *Bounding `details`*: where a specification declares no
/// bound, 4096 bytes of JCS and 16 immediate members apply.
pub const DETAILS_MAX_JCS_BYTES: usize = 4096;
/// Companion to [`DETAILS_MAX_JCS_BYTES`].
pub const DETAILS_MAX_MEMBERS: usize = 16;

/// Members a `details` may shed, in this order, before the whole of it is
/// dropped — each paired with the member that replaces it and says how many
/// items went (an array's length; `1` for anything else).
///
/// A member belongs here when it is a *convenience* the receiver can do
/// without, and the rest of the `details` is what it cannot. The one entry:
/// `auth:consent_required` carries one signed `task-consent/request` per
/// approver so a requester can relay them where the service has no route. Each
/// is around a kilobyte, so three approvers pass the default bound — and
/// without shedding the whole annex went, taking the digest, correlator and
/// challenge with it: the requester was told consent was required and given
/// nothing to act on (Keyring VTI-37). Shedding the requests keeps the
/// ceremony's coordinates on the wire; the count tells the requester the relay
/// copies exist and did not fit, rather than that there were none.
///
/// Whole or not at all: a partial list would read as "these are the approvers",
/// and a requester relaying to the ones it was given would silently skip the
/// rest. Matched by member name on every bounded `details`.
pub const SHEDDABLE_DETAILS_MEMBERS: &[(&str, &str)] =
    &[("consentRequests", "consentRequestsOmitted")];

/// Is `details` within the framework's default bound? Uncanonicalisable is
/// out of bound: it cannot be measured, so it does not go out.
pub fn details_within_bound(details: &Value) -> bool {
    let too_many_members = details
        .as_object()
        .is_some_and(|o| o.len() > DETAILS_MAX_MEMBERS);
    let too_large = serde_json_canonicalizer::to_string(details)
        .map(|jcs| jcs.len() > DETAILS_MAX_JCS_BYTES)
        .unwrap_or(true);
    !too_many_members && !too_large
}

/// Bring a `details` within the framework's bound, keeping the code.
///
/// An oversized `details` first sheds the members in
/// [`SHEDDABLE_DETAILS_MEMBERS`], in order, until it fits; if it still does
/// not, it is **ignored, never grounds to discard the `code`** — the code is
/// what the receiving party needs. Omitting members to stay within the bound
/// conforms; exceeding it does not.
fn bound_details(details: Option<Value>) -> Option<Value> {
    let mut details = details?;
    if details_within_bound(&details) {
        return Some(details);
    }
    let original_members = details.as_object().map(serde_json::Map::len);

    let mut shed: Vec<&str> = Vec::new();
    for (member, marker) in SHEDDABLE_DETAILS_MEMBERS {
        let Some(obj) = details.as_object_mut() else {
            break;
        };
        let Some(removed) = obj.remove(*member) else {
            continue;
        };
        let count = removed.as_array().map_or(1, Vec::len);
        obj.insert((*marker).to_string(), Value::from(count));
        shed.push(member);
        if details_within_bound(&details) {
            tracing::warn!(
                shed = ?shed,
                "error `details` exceeds the framework bound; shed the listed members \
                 (their count went out in their place) and sent the rest with the code"
            );
            return Some(details);
        }
    }

    tracing::warn!(
        members = original_members,
        shed = ?shed,
        "error `details` exceeds the framework bound even after shedding; dropped the whole \
         of it and the code still went out"
    );
    None
}

/// Build a routed refusal for `reason`; the status follows from its code.
pub fn reject_with<P>(doc: &TrustTask<P>, reason: RejectReason) -> TrustTaskOutcome {
    // Bound `details` here: this is the funnel every `RejectReason`-shaped
    // refusal passes through.
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

/// Refuse with an explicit [`TrustTaskCode`] and a `details` annex.
///
/// [`RejectReason`] carries `details` on `TaskFailed` alone; this is the seam
/// for any other code. `details` is bounded exactly as in [`reject_with`].
pub fn reject_with_code<P>(
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

/// Build a routed `#response` document with `payload`, answered `200`.
pub fn success_response<P, R: Serialize>(doc: &TrustTask<P>, payload: R) -> TrustTaskOutcome {
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

/// The courtesy acknowledgement of a fire-and-forget task (SPEC §4.4.2): the
/// originating type with `#response` and a payload of exactly `{}`.
///
/// Only for a task whose specification defines **no** success response.
pub fn acknowledge<P>(doc: &TrustTask<P>) -> TrustTaskOutcome {
    success_response(doc, serde_json::Map::new())
}

/// Wrap a routed [`ErrorResponse`] with the status the framework's table gives
/// its code.
pub fn error_response(err_doc: ErrorResponse) -> TrustTaskOutcome {
    let status = StatusCode::from_u16(status_for_code(&err_doc.payload.code))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = serde_json::to_vec(&err_doc).unwrap_or_default();
    TrustTaskOutcome { status, body }
}

/// The framework's error-document Type URI — the one `TrustTask::reject_with`
/// stamps on every *routed* refusal.
///
/// `trust-tasks-rs` keeps `trust_task_error_type_uri()` crate-private, so the
/// unrouted path, which has no request to reject from, writes the value out.
/// Pinned against a real `reject_with` by this crate's tests, so a framework
/// bump fails a test rather than splitting a service into two dialects.
pub fn framework_error_type_uri() -> TypeUri {
    "https://trusttasks.org/spec/trust-task-error/0.6"
        .parse()
        .expect("framework error Type URI parses")
}

/// A framework error document for a body that did not parse as a Trust Task.
/// Unrouted: the producer correlates on the response `id`.
pub fn body_parse_error_response(reason: &str) -> TrustTaskOutcome {
    let reject = RejectReason::MalformedRequest {
        reason: format!("body did not parse as a Trust Task document: {reason}"),
    };
    unrouted_error_response(reject.into())
}

/// A refusal of a body that was never parsed into a document — so there is no
/// issuer to name, no thread and no ceremony to carry forward.
pub fn unrouted_error_response(payload: ErrorPayload) -> TrustTaskOutcome {
    let type_uri: TypeUri = framework_error_type_uri();
    let err = ErrorResponse {
        id: format!("urn:uuid:{}", Uuid::new_v4()),
        thread_id: None,
        parent_thread_id: None,
        type_uri,
        issuer: None,
        recipient: None,
        issued_at: Some(chrono::Utc::now()),
        expires_at: None,
        payload,
        context: None,
        ceremony: None,
        proof: None,
        extra: Default::default(),
    };
    error_response(err)
}

/// The family of a Trust Task Type URI: everything before its trailing version
/// segment (SPEC §3.1). `None` for a URI with no `/`.
pub fn task_family(type_uri: &str) -> Option<&str> {
    type_uri.rsplit_once('/').map(|(family, _version)| family)
}

/// Refuse a Type URI the dispatcher has no arm for, telling the two failures
/// apart.
///
/// A URI whose family `served` contains at another version is
/// `unsupportedVersion`, naming the served versions in `message` and in
/// `details.servedVersions` (the operator's fix is an upgrade). Anything else
/// is `unsupportedType`, whose message is the framework's own rendering.
/// `node` names the service in the message ("this VTC serves …").
pub fn unsupported_type_or_version<'s, P>(
    doc: &TrustTask<P>,
    type_uri: &str,
    served: impl IntoIterator<Item = &'s str>,
    node: &str,
) -> TrustTaskOutcome {
    use vta_sdk::protocols::trust_task_reject_details as details;

    let family = task_family(type_uri);
    let mut served: Vec<&str> = served
        .into_iter()
        .filter(|uri| family.is_some() && task_family(uri) == family)
        .collect();
    served.sort_unstable();
    served.dedup();

    if served.is_empty() {
        return reject_with_code(
            doc,
            TrustTaskCode::Standard(StandardCode::UnsupportedType),
            format!("unsupported type: {type_uri}"),
            Some(serde_json::json!({ details::REQUESTED_TYPE: type_uri })),
        );
    }

    reject_with_code(
        doc,
        TrustTaskCode::Standard(StandardCode::UnsupportedVersion),
        format!(
            "unsupported version: {type_uri} — this {node} serves {}",
            served.join(", ")
        ),
        Some(serde_json::json!({
            details::REQUESTED_TYPE: type_uri,
            details::SERVED_VERSIONS: served,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc() -> TrustTask<Value> {
        let uri: TypeUri = "https://trusttasks.org/spec/acl/list/0.3"
            .parse()
            .expect("Type URI parses");
        TrustTask::new("urn:uuid:test", uri, json!({}))
    }

    /// An `internalError` must not carry consumer-internal state; the cause
    /// goes to the log, not the wire.
    #[test]
    fn an_internal_error_does_not_send_its_cause() {
        let secret = "vtc_did not configured";
        let out = app_error_to_reject(&doc(), &AppError::Internal(secret.into()));
        let body = String::from_utf8(out.body).expect("the reject body is UTF-8");
        assert!(!body.contains(secret), "{body}");
        assert!(body.contains(OPAQUE_INTERNAL_ERROR), "{body}");

        let out = app_error_to_reject(
            &doc(),
            &AppError::SecretStore("keyring backend unavailable at /run/user/1000".into()),
        );
        let body = String::from_utf8(out.body).expect("the reject body is UTF-8");
        assert!(!body.contains("keyring backend"), "{body}");
        assert!(body.contains(OPAQUE_INTERNAL_ERROR), "{body}");
    }

    /// The caller-visible outcomes carry the marker a client reads back into a
    /// typed `VtaError`.
    #[test]
    fn caller_visible_failures_carry_their_reason_marker() {
        for (err, want) in [
            (AppError::NotFound("no such row".into()), reasons::NOT_FOUND),
            (AppError::Conflict("already open".into()), reasons::CONFLICT),
            (AppError::Gone("withdrawn".into()), reasons::GONE),
            (AppError::IdempotencyKeyConflict, reasons::CONFLICT),
            (
                vti_common::error::NoMatchingProtocol {
                    peer: "did:webvh:Qm:peer.example".into(),
                    ours: vec![],
                    theirs: vec![],
                    note: None,
                }
                .into(),
                reasons::NO_MATCHING_PROTOCOL,
            ),
            (
                AppError::UnsupportedDidMethod {
                    method: "example".into(),
                },
                reasons::UNSUPPORTED_DID_METHOD,
            ),
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

    /// VTI-KEY-009: a document relying on an unresolved method is
    /// `proofInvalid`, naming the method; never `permissionDenied` or an
    /// `internalError`.
    #[test]
    fn vti_key_009_an_unsupported_method_is_proof_invalid_naming_it() {
        let out = app_error_to_reject(
            &doc(),
            &AppError::UnsupportedDidMethod {
                method: "example".into(),
            },
        );
        let body: Value = serde_json::from_slice(&out.body).expect("reject body is JSON");
        assert_eq!(body["payload"]["code"], "proofInvalid", "{body}");
        assert_eq!(body["payload"]["details"]["method"], "example", "{body}");
    }

    /// The unrouted error claims the same document type a routed one does.
    #[test]
    fn unrouted_and_routed_errors_agree_on_the_type_uri() {
        let routed = doc().reject_with(
            "urn:uuid:routed",
            RejectReason::InternalError {
                reason: "probe".into(),
            },
        );
        assert_eq!(framework_error_type_uri(), routed.type_uri);
    }

    #[test]
    fn the_body_parse_error_goes_out_as_a_framework_error_document() {
        let outcome = body_parse_error_response("not json");
        let doc: Value = serde_json::from_slice(&outcome.body).expect("error doc parses");
        assert_eq!(
            doc["type"].as_str().expect("type present"),
            framework_error_type_uri().to_string()
        );
    }

    /// An oversized `details` is dropped and the code still goes out.
    #[test]
    fn oversized_details_are_dropped_but_the_code_is_kept() {
        let big: serde_json::Map<String, Value> = (0..=DETAILS_MAX_MEMBERS)
            .map(|i| (format!("k{i}"), json!(i)))
            .collect();
        let out = reject_with_code(
            &doc(),
            extended_code("acl/list:probe"),
            "probe",
            Some(Value::Object(big)),
        );
        let body: Value = serde_json::from_slice(&out.body).expect("JSON");
        assert_eq!(body["payload"]["code"], "acl/list:probe");
        assert!(body["payload"].get("details").is_none(), "{body}");
    }

    #[test]
    fn a_known_family_at_another_version_is_unsupported_version() {
        let served = ["https://trusttasks.org/spec/acl/list/0.2"];
        let out = unsupported_type_or_version(
            &doc(),
            "https://trusttasks.org/spec/acl/list/0.3",
            served,
            "node",
        );
        let body: Value = serde_json::from_slice(&out.body).expect("JSON");
        assert_eq!(body["payload"]["code"], "unsupportedVersion", "{body}");
        assert_eq!(
            body["payload"]["details"]["servedVersions"],
            json!(served),
            "{body}"
        );
        let out = unsupported_type_or_version(
            &doc(),
            "https://trusttasks.org/spec/acl/list/0.3",
            [],
            "node",
        );
        let body: Value = serde_json::from_slice(&out.body).expect("JSON");
        assert_eq!(body["payload"]["code"], "unsupportedType", "{body}");
    }
}
