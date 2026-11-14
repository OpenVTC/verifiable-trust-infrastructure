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
//! The answer-building helpers are thin wrappers over
//! `vti_trust_task_server::reject` (#2571), shared with the VTC: only the
//! VTA's own `AppError` case (an upstream peer's failure) and the
//! version-naming `method_not_found` are decided here.
//!
//! All helpers are `pub(super)` — visible to the dispatcher (`mod.rs`)
//! and to the per-slice handler modules, but not to the wider crate.
//! Callers outside `routes::trust_tasks` should not depend on these
//! shapes; the entry point is `dispatch_trust_task` in `mod.rs`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use trust_tasks_rs::{ErrorResponse, RejectReason, StandardCode, TrustTask, TrustTaskCode};
use vta_sdk::protocols::trust_task_reject_reasons as reasons;
use vti_trust_task_server::reject as shared;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;
use vti_common::acl::Capability;
// The SDK owns the spelling of every `details` member both sides touch,
// so the service cannot drift from the client that reads it.
use vta_sdk::protocols::trust_task_reject_details as details;

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
    pub(crate) restart: bool,
}

impl TrustTaskOutcome {
    pub(crate) fn with_restart(mut self) -> Self {
        self.restart = true;
        self
    }
}

impl TrustTaskOutcome {
    /// The response, holding `restart` until the body has been handed to the
    /// connection — dropped with the body, it fires then, and on a client that
    /// hangs up too. `Content-Length` is set so the reply stays unchunked.
    pub(crate) fn into_response_firing(self, restart: crate::server::RestartOnDrop) -> Response {
        use futures_util::StreamExt;
        let len = self.body.len();
        let chunk = axum::body::Bytes::from(self.body);
        let stream = futures_util::stream::iter([Ok::<_, std::convert::Infallible>(chunk)]).map(
            move |chunk| {
                let _held = &restart;
                chunk
            },
        );
        (
            self.status,
            [
                (
                    axum::http::header::CONTENT_TYPE,
                    "application/json".to_string(),
                ),
                (axum::http::header::CONTENT_LENGTH, len.to_string()),
            ],
            axum::body::Body::from_stream(stream),
        )
            .into_response()
    }
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

// ─── Answers: the shared reject/response helpers (#2571) ─────────────────
//
// Building `#response` and `trust-task-error` documents, bounding `details`,
// and mapping an `AppError` to a framework code all live in
// `vti_trust_task_server::reject`, which the VTC uses too, so a transport or
// spec rule (§7.2 ordering, the opaque `internalError`, the `details` bound) is
// fixed once. These wrappers only lift the shared outcome into this service's
// `TrustTaskOutcome`, which also carries `restart`.

/// The one `trust-task-error` version this service emits.
#[cfg(test)]
pub(crate) use vti_trust_task_server::reject::framework_error_type_uri;
use vti_trust_task_server::reject::task_family;

impl From<vti_trust_task_server::TrustTaskOutcome> for TrustTaskOutcome {
    fn from(outcome: vti_trust_task_server::TrustTaskOutcome) -> Self {
        Self {
            status: outcome.status,
            body: outcome.body,
            restart: false,
        }
    }
}

/// Parse a trust-task document's `payload` field as the typed body `T`, or
/// return a `malformedRequest` refusal ([`shared::parse_payload`]).
pub(super) fn parse_payload<T: serde::de::DeserializeOwned>(
    doc: &TrustTask<Value>,
) -> Result<T, TrustTaskOutcome> {
    shared::parse_payload(doc).map_err(Into::into)
}

/// Map an `AppError` (the operation-layer error type) into a routed refusal.
///
/// The VTA's own case comes first, then [`shared::app_error_to_reject`], which
/// is where every other mapping lives — as that function's documentation
/// invites a service to:
///
/// - `ServiceError` at `502` / `504` → `taskFailed`, `details.reason`
///   `upstream_unavailable`: a peer failed, not this VTA. A peer this VTA had
///   to reach — a DID-hosting server, another agent — did not answer or
///   refused. Left to the catch-all it went out as `internalError`, which tells
///   the producer "this VTA broke" and points everyone at the wrong machine: a
///   join that failed because the hosting server never answered its TSP
///   request read, in openvtc, as an unexplained internal error in the user's
///   own VTA. The cause still does not go on the wire — a bad-gateway message
///   can carry a peer's URL, its transport error and the body it sent back, the
///   class of detail the opaque `internalError` keeps off it — so the fixed
///   text and `details.reason` say the *kind* of failure, and the operator's
///   log says which peer and how.
pub(super) fn app_error_to_reject(doc: &TrustTask<Value>, err: AppError) -> TrustTaskOutcome {
    match &err {
        AppError::ServiceError { status, message }
            if *status == StatusCode::BAD_GATEWAY || *status == StatusCode::GATEWAY_TIMEOUT =>
        {
            tracing::error!(cause = %message, "trust task failed: an upstream peer did not answer or refused");
            reject_with(
                doc,
                RejectReason::TaskFailed {
                    reason: UPSTREAM_UNAVAILABLE_MESSAGE.to_string(),
                    details: Some(serde_json::json!({ "reason": reasons::UPSTREAM_UNAVAILABLE })),
                },
            )
        }
        _ => shared::app_error_to_reject(doc, &err).into(),
    }
}

/// What an upstream failure says on the wire. Fixed for the same reason as
/// [`OPAQUE_INTERNAL_ERROR`](shared::OPAQUE_INTERNAL_ERROR); see [`app_error_to_reject`].
pub(super) const UPSTREAM_UNAVAILABLE_MESSAGE: &str = "a service this VTA depends on did not answer or refused the request; \
     the VTA's log names which one and why";

/// A routed refusal for `reason`, `details` bounded ([`shared::reject_with`]).
pub(super) fn reject_with(doc: &TrustTask<Value>, reason: RejectReason) -> TrustTaskOutcome {
    shared::reject_with(doc, reason).into()
}

/// Refuse with an explicit code — a specification-extended one
/// (`<slug>:<local>`, SPEC §8.5) a task declares, which [`RejectReason`]
/// cannot express ([`shared::reject_with_code`]). Use it only for a code the
/// task's specification actually declares.
pub(super) fn reject_with_code(
    doc: &TrustTask<Value>,
    code: TrustTaskCode,
    message: impl Into<String>,
    details: Option<Value>,
) -> TrustTaskOutcome {
    shared::reject_with_code(doc, code, message, details).into()
}

/// A routed `#response` with `payload`, answered `200`
/// ([`shared::success_response`]).
pub(super) fn success_response<R: serde::Serialize>(
    doc: &TrustTask<Value>,
    payload: R,
) -> TrustTaskOutcome {
    shared::success_response(doc, payload).into()
}

/// The courtesy acknowledgement of a fire-and-forget task (SPEC §4.4.2), only
/// for a task whose specification defines **no** success response
/// ([`shared::acknowledge`]).
pub(super) fn acknowledge(doc: &TrustTask<Value>) -> TrustTaskOutcome {
    shared::acknowledge(doc).into()
}

/// A routed `ErrorResponse` with the status the framework's table gives its
/// code ([`shared::error_response`]).
pub(super) fn error_response(err_doc: ErrorResponse) -> TrustTaskOutcome {
    shared::error_response(err_doc).into()
}

/// An unrouted framework error for a body that did not parse as a Trust Task
/// ([`shared::body_parse_error_response`]).
pub(super) fn body_parse_error_response(reason: &str) -> TrustTaskOutcome {
    shared::body_parse_error_response(reason).into()
}

/// An unrouted `malformedRequest` carrying `reason` **verbatim**.
///
/// Not every malformed request is a malformed *document*. A transport binding
/// can refuse a payload whose document would have parsed perfectly — a TSP
/// frame that is not wrapped in the binding envelope, say — and telling that
/// sender "body did not parse as a Trust Task document" sends them to inspect a
/// document that is fine. During a binding cutover that is the single most
/// misleading thing this service could say, so the wording stays the caller's.
pub(crate) fn malformed_request_response(reason: String) -> TrustTaskOutcome {
    shared::unrouted_error_response(RejectReason::MalformedRequest { reason }.into()).into()
}

/// The capability gate every gated task goes through.
///
/// # Why this reads the ACL rather than the token
///
/// A caller's role rides in their access token; their *narrowing* does not. It is
/// read from the entry, per call, on purpose:
///
/// - A capability set is a **restriction**, and a restriction that takes effect
///   at the subject's next token mint is a restriction with a fifteen-minute hole
///   in it. Narrowing an entry stops the next call, not the next login.
/// - The alternative — a `capabilities` claim in the JWT — would put the set in
///   `AuthClaims`, a published struct built by literal in 130 places, and would
///   still leave every unexpired token holding what it held before.
///
/// The read is one keyspace hit on the tasks that are capability-gated, which are
/// already reading vault or memory keyspaces to do their work.
///
/// # An entry that is not there
///
/// Falls back to the role's own set. The offline CLI synthesizes claims under a
/// `cli:<channel>` DID that is deliberately in no ACL, and DIDs authenticated
/// before an entry existed behave as they always did. This gate narrows what an
/// entry says to narrow; it is not an authorization check of its own, and the
/// authenticated role is what it defers to.
pub(super) async fn require_capability(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    cap: Capability,
    what: &str,
) -> Result<(), TrustTaskOutcome> {
    // A store error reads as "not carried"; the operator gets the reason in
    // the log, the caller only that the capability is missing.
    let allowed = crate::operations::acl::caller_has_capability(&state.acl_ks, auth, cap).await;

    if allowed {
        return Ok(());
    }
    Err(reject_with(
        doc,
        RejectReason::PermissionDenied {
            reason: format!(
                "{what} denied: {} does not carry the {cap:?} capability",
                auth.did
            ),
        },
    ))
}

/// Reject with a code the task's own specification declares
/// (`<slug>:<local>`, SPEC §8.5), from its generated `error_codes`.
#[cfg_attr(not(any(feature = "webvh", feature = "tee")), allow(dead_code))]
pub(super) fn reject_declared(
    doc: &TrustTask<Value>,
    code: trust_tasks_rs::DeclaredErrorCode,
    message: impl Into<String>,
) -> TrustTaskOutcome {
    reject_with_code(
        doc,
        TrustTaskCode::Extended {
            slug: code.namespace().to_string(),
            local: code.local().to_string(),
        },
        message,
        None,
    )
}

/// No reply at all. Every transport reads an empty body as "nothing goes back"
/// (`accept_from_proven_sender`). For a fire-and-forget task that was accepted
/// but not yet performed, where an acknowledgement would claim too much — the
/// absence of a reply carries no information (SPEC §4.4.2 item 3).
pub(super) fn silence() -> TrustTaskOutcome {
    TrustTaskOutcome {
        status: StatusCode::NO_CONTENT,
        body: Vec::new(),
        restart: false,
    }
}

/// Build a routed `task_failed` rejection for a URI we know about but
/// haven't implemented yet. Kept available for Phase 3+ slices that
/// land their match arms before the handler body — each new slice can
/// stub via this helper, then replace with a real handler.
#[allow(dead_code)]
pub(super) fn not_implemented_yet(doc: TrustTask<Value>, reason: &str) -> TrustTaskOutcome {
    reject_with(
        &doc,
        RejectReason::TaskFailed {
            reason: reason.to_string(),
            details: None,
        },
    )
}

/// Build an `unsupported_type` rejection for a type URI this VTA has never
/// heard of.
///
/// The narrow arm of [`method_not_found`], which reaches it only after ruling
/// out the family being served at another version.
fn unsupported_type(doc: TrustTask<Value>, type_uri: &str) -> TrustTaskOutcome {
    // The message is the framework's own `RejectReason::UnsupportedType`
    // rendering, kept byte-identical so a consumer matching on it does not
    // break; `details.requestedType` is the same fact machine-readably, which
    // is the half the framework's shape leaves out. A client otherwise has to
    // recover the URI by string-slicing a human-readable sentence.
    reject_with_code(
        &doc,
        TrustTaskCode::Standard(StandardCode::UnsupportedType),
        format!("unsupported type: {type_uri}"),
        Some(serde_json::json!({ details::REQUESTED_TYPE: type_uri })),
    )
}

/// Versions of `type_uri`'s family that this VTA *does* dispatch, sorted.
///
/// Derived from the dispatch table itself ([`super::dispatched_uris`]) rather
/// than a hand-kept list, for the same reason `trust-task-discovery` is: a
/// second source of truth for "what we support" goes stale the first time a
/// handler is added without remembering it exists, and a migration hint that
/// names a version the VTA does not serve is worse than no hint.
fn served_versions_of_family(type_uri: &str) -> Vec<&'static str> {
    let Some(family) = task_family(type_uri) else {
        return Vec::new();
    };
    let mut served: Vec<&'static str> = super::dispatched_uris()
        .into_iter()
        .filter(|uri| task_family(uri) == Some(family))
        .collect();
    served.sort_unstable();
    served.dedup();
    served
}

/// Reject a type URI this dispatcher has no arm for.
///
/// Two different failures wear one code if you let them. "I have never heard
/// of this task" and "I know this task, at a different version" send the
/// operator to completely different places — the first to whether the feature
/// exists at all, the second to which side is out of date — and only the
/// second is recoverable by upgrading something.
///
/// So when the unknown URI's family matches something this VTA dispatches, the
/// rejection is `unsupportedVersion` (SPEC's code for exactly this: "the
/// consumer recognizes the type but not at this MAJOR.MINOR") and names the
/// versions actually served, in `message` for a human and in
/// `details.servedVersions` for a client. Otherwise it stays
/// `unsupportedType`.
///
/// This exists because of a live incident (2026-08-31): #1147 cut
/// `provision/integration` 0.2 → 0.3 with no dual-accept window — the two
/// response schemas are mutually exclusive, so there could not be one — and an
/// operator whose VTA predated the cut got
///
/// ```text
/// unsupported type: https://trusttasks.org/spec/provision/integration/0.3
/// ```
///
/// against a VTA that was serving 0.2 two lines further down its own dispatch
/// table. Accurate, and it reads as "this VTA cannot do provisioning" rather
/// than "this VTA is older than your client". The VTA knew the answer; it just
/// did not say it.
///
/// A family this build does not compile in at all (`provision/integration` is
/// `#[cfg(feature = "webvh")]`) has no served versions and so still gets
/// `unsupportedType` — correct, if terse: there is no version to migrate to,
/// and naming absent features would report the build's configuration to a
/// caller that has no use for it.
pub(super) fn method_not_found(doc: TrustTask<Value>, type_uri: &str) -> TrustTaskOutcome {
    let served = served_versions_of_family(type_uri);
    if served.is_empty() {
        return unsupported_type(doc, type_uri);
    }

    reject_with_code(
        &doc,
        TrustTaskCode::Standard(StandardCode::UnsupportedVersion),
        format!(
            "unsupported version: {type_uri} — this VTA serves {}{}",
            served.join(", "),
            vta_sdk::error::version_age_hint(
                type_uri,
                &served.iter().map(|s| s.to_string()).collect::<Vec<_>>()
            ),
        ),
        Some(serde_json::json!({
            details::REQUESTED_TYPE: type_uri,
            details::SERVED_VERSIONS: served,
        })),
    )
}

// ─── Purpose of use (VTI-ACL-100 – 110) ──────────────────────────────────
//
// Shared by every purpose-bound operation (VTI-ACL-102): agent memory reads and
// the room key holder's opening of records and release of file keys.

/// Judge `requested` against the caller's **stored** entry (VTI-ACL-103,
/// -104), never a token: a narrowing binds at the next read. A caller with no
/// readable entry is refused, never read as holding `any` (VTI-ACL-101).
pub(super) async fn decide_purpose(
    state: &AppState,
    auth: &AuthClaims,
    requested: Option<&str>,
) -> vti_common::acl::PurposeDecision {
    match crate::acl::get_acl_entry(&state.acl_ks, &auth.did).await {
        Ok(Some(entry)) => entry.purposes.admit(requested),
        _ => match requested {
            Some(p) => vti_common::acl::PurposeDecision::NotGranted(p.to_string()),
            None => vti_common::acl::PurposeDecision::Unnamed,
        },
    }
}

/// Refuse a read whose purpose is not granted (VTI-ACL-104): the version's
/// `purposeNotGranted` where it declares one, else a `taskFailed` saying so —
/// either way distinct from the access refusal, and carrying no content.
pub(super) fn purpose_refusal(
    doc: &TrustTask<Value>,
    decision: &vti_common::acl::PurposeDecision,
    code: Option<trust_tasks_rs::DeclaredErrorCode>,
) -> TrustTaskOutcome {
    let message = match decision {
        vti_common::acl::PurposeDecision::NotGranted(p) => {
            format!("this entry does not grant the purpose `{p}` (VTI-ACL-104)")
        }
        _ => "name the purpose you will use this content for: this entry lists more than one \
              (VTI-ACL-103)"
            .to_string(),
    };
    let details = decision.refusal_details();
    match code {
        Some(c) => reject_with_code(
            doc,
            trust_tasks_rs::TrustTaskCode::Extended {
                slug: c.namespace().to_string(),
                local: c.local().to_string(),
            },
            message,
            details,
        ),
        None => reject_with(
            doc,
            trust_tasks_rs::RejectReason::TaskFailed {
                reason: format!("purposeNotGranted: {message}"),
                details,
            },
        ),
    }
}

/// For a hand-written payload type `T` that refuses unknown members (#2621):
/// every member the pinned schema of `type_uri` declares is one `T` reads — so
/// `deny_unknown_fields` refuses only what the specification does not define —
/// and a member it does not declare is refused.
#[cfg(test)]
pub(super) fn assert_reads_exactly_the_schema_members<T: serde::de::DeserializeOwned>(
    type_uri: &str,
) {
    let schema: Value = serde_json::from_str(
        vti_specs::schema_index::schema_for(type_uri)
            .unwrap_or_else(|| panic!("{type_uri} is not pinned")),
    )
    .expect("a pinned schema is JSON");
    let members = schema["properties"]
        .as_object()
        .unwrap_or_else(|| panic!("{type_uri}: the payload schema names no properties"));
    for name in members.keys() {
        let mut one = serde_json::Map::new();
        one.insert(name.clone(), Value::Null);
        if let Err(e) = serde_json::from_value::<T>(Value::Object(one)) {
            assert!(
                !e.to_string().contains("unknown field"),
                "{type_uri}: `{name}` is a member of the schema, and the payload type refuses it: {e}"
            );
        }
    }
    let err = serde_json::from_value::<T>(serde_json::json!({ "notAMember": null }))
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        err.contains("unknown field"),
        "{type_uri}: a member the schema does not define must be refused, got `{err}`"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use trust_tasks_rs::TypeUri;
    use vti_trust_task_server::reject::{
        DETAILS_MAX_JCS_BYTES, DETAILS_MAX_MEMBERS, OPAQUE_INTERNAL_ERROR, details_within_bound,
    };

    fn doc() -> TrustTask<Value> {
        let uri: TypeUri = vta_sdk::trust_tasks::TASK_WEBVH_DIDS_UPDATE_1_0
            .parse()
            .expect("update uri");
        TrustTask::new("urn:uuid:test", uri, json!({}))
    }

    fn message_of(outcome: TrustTaskOutcome) -> String {
        let doc: Value = serde_json::from_slice(&outcome.body).expect("error doc parses");
        doc["payload"]["message"]
            .as_str()
            .expect("payload carries a message")
            .to_string()
    }

    fn details_of(outcome: TrustTaskOutcome) -> Value {
        let doc: Value = serde_json::from_slice(&outcome.body).expect("error doc parses");
        doc["payload"]["details"].clone()
    }

    /// The regression: three distinct outcomes all leave as `taskFailed`, so
    /// without a discriminator a caller cannot tell an absent resource from a
    /// genuine failure — and an absent resource is very often a normal state.
    ///
    /// `pnm approvals list` is the case that broke. A VTA that has never had an
    /// approval rule has no `approvals` policy row (the shipping default); the
    /// CLI reads it and treats a missing row as an empty model, but with the
    /// type erased that arm could never fire. Every `pnm approvals` subcommand
    /// failed on a fresh VTA, `require` among them — so the first rule could
    /// not be created, because `require` reads the row before writing it.
    ///
    /// REST keeps this distinction in an HTTP status and DIDComm
    /// protocol-messages keep it in a problem-report code. This is what stops
    /// the Trust-Task transport being the one that loses it.
    #[test]
    fn a_not_found_is_discriminated_from_a_plain_task_failure() {
        let outcome = app_error_to_reject(&doc(), AppError::NotFound("policy `x`".into()));
        assert_eq!(details_of(outcome)["reason"], reasons::NOT_FOUND);
    }

    #[test]
    fn a_conflict_is_discriminated_from_a_plain_task_failure() {
        let outcome = app_error_to_reject(&doc(), AppError::Conflict("already exists".into()));
        assert_eq!(details_of(outcome)["reason"], reasons::CONFLICT);
    }

    #[test]
    fn a_gone_is_discriminated_from_a_plain_task_failure() {
        let outcome = app_error_to_reject(&doc(), AppError::Gone("carve-out closed".into()));
        assert_eq!(details_of(outcome)["reason"], reasons::GONE);
    }

    /// The reasons must stay distinct. Collapsing any pair would let a caller
    /// act on the wrong one — retrying a `Gone` that can never succeed, or
    /// reading a `Conflict` as "absent" and creating a duplicate.
    #[test]
    fn the_reasons_are_distinct() {
        let all = [
            reasons::NOT_FOUND,
            reasons::CONFLICT,
            reasons::GONE,
            reasons::UPSTREAM_UNAVAILABLE,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for r in all {
            assert!(seen.insert(r), "`{r}` is used for more than one outcome");
        }
    }

    /// A family split on its trailing version segment, nothing else.
    ///
    /// Written against synthetic paths rather than real Type URIs: a URI
    /// literal anywhere under `vta-service/src` is counted by
    /// `produced_census` as a document this service emits, and a test fixture
    /// is not one.
    #[test]
    fn task_family_strips_only_the_version_segment() {
        assert_eq!(
            task_family("scheme://host/spec/a/b/0.3"),
            Some("scheme://host/spec/a/b")
        );
        assert_eq!(
            task_family("scheme://host/spec/a/b/c-d/1.0"),
            Some("scheme://host/spec/a/b/c-d")
        );
        assert_eq!(task_family("no-slashes-at-all"), None);
    }

    /// The migration hint is derived from the live dispatch table.
    ///
    /// Asserted against a URI the table definitely carries — a hard-coded
    /// expectation here would be the second source of truth the function
    /// exists to avoid.
    #[test]
    fn served_versions_come_from_the_dispatch_table() {
        let served = crate::trust_tasks::dispatched_uris();
        let real = served
            .first()
            .expect("the dispatch table is not empty")
            .to_string();
        let family = task_family(&real).expect("a task URI has a family");
        let bogus = format!("{family}/99.99");

        let found = served_versions_of_family(&bogus);
        assert!(
            found.contains(&real.as_str()),
            "{real} is dispatched, so a bogus version of its family should name it; got {found:?}"
        );
    }

    /// A type this VTA has never heard of still gets `unsupportedType`.
    ///
    /// The version arm must not swallow the plain case: "I do not implement
    /// this" and "I implement this at another version" are different answers
    /// and only the second is fixed by upgrading something.
    #[test]
    fn an_unknown_family_is_still_unsupported_type() {
        // The URI `produced_census::NOT_PRODUCED` already carries as its
        // negative fixture. Reused rather than minting a second one, so the
        // census has one entry to explain instead of two.
        let outcome = method_not_found(doc(), "https://trusttasks.org/spec/does-not-exist/9.9");
        let parsed: Value = serde_json::from_slice(&outcome.body).expect("error doc");
        assert_eq!(parsed["payload"]["code"], "unsupportedType");
        assert!(parsed["payload"]["details"].get("servedVersions").is_none());
    }

    /// A known family at an unknown version names the versions served.
    ///
    /// REGRESSION (2026-08-31): #1147 cut `provision/integration` 0.2 → 0.3
    /// with no dual-accept window, and a VTA still on 0.2 answered a 0.3
    /// client with a bare `unsupported type` — while carrying 0.2 in the very
    /// table it had just failed to match. The operator read it as "this VTA
    /// cannot provision" and went looking in the wrong place.
    #[test]
    fn a_known_family_at_an_unknown_version_names_what_is_served() {
        let real = crate::trust_tasks::dispatched_uris()
            .first()
            .expect("the dispatch table is not empty")
            .to_string();
        let family = task_family(&real).expect("a task URI has a family");
        let bogus = format!("{family}/99.99");

        let outcome = method_not_found(doc(), &bogus);
        let parsed: Value = serde_json::from_slice(&outcome.body).expect("error doc");

        assert_eq!(parsed["payload"]["code"], "unsupportedVersion");
        let message = parsed["payload"]["message"]
            .as_str()
            .expect("a message")
            .to_string();
        assert!(
            message.contains(&real),
            "the message must name the served version; got {message}"
        );
        assert_eq!(parsed["payload"]["details"]["servedVersions"][0], real);
    }

    /// An extended code reaches the wire in its `<slug>:<local>` spelling.
    ///
    /// `RejectReason` cannot express one — every variant maps to a standard
    /// code — so before `reject_with_code` a task whose own specification
    /// declared an error code had to render it as prose in `message` and let
    /// the caller string-match, which is the thing machine-readable codes
    /// exist to prevent.
    #[test]
    fn an_extended_code_survives_to_the_wire() {
        let code: TrustTaskCode = "provision/integration:contextRequired"
            .parse()
            .expect("a legal extended code");
        let outcome = reject_with_code(
            &doc(),
            code,
            "which context?",
            Some(json!({ "candidates": ["a", "b"] })),
        );
        let parsed: Value = serde_json::from_slice(&outcome.body).expect("error doc");
        assert_eq!(
            parsed["payload"]["code"],
            "provision/integration:contextRequired"
        );
        assert_eq!(parsed["payload"]["details"]["candidates"][1], "b");
    }

    /// The `details` bound is enforced on this path too.
    ///
    /// `reject_with`'s comment calls itself "the one funnel every rejection
    /// passes through, so a new site cannot be added that skips the check" —
    /// `reject_with_code` is a second funnel, and this is what keeps that
    /// sentence true.
    #[test]
    fn an_extended_code_rejection_bounds_its_details_too() {
        let code: TrustTaskCode = "provision/integration:contextRequired"
            .parse()
            .expect("a legal extended code");
        let huge = json!({ "explanation": "x".repeat(DETAILS_MAX_JCS_BYTES + 1) });
        let outcome = reject_with_code(&doc(), code, "which context?", Some(huge));
        let parsed: Value = serde_json::from_slice(&outcome.body).expect("error doc");
        assert_eq!(
            parsed["payload"]["code"], "provision/integration:contextRequired",
            "an oversized annex must never cost the code: {parsed}"
        );
        assert!(
            parsed["payload"]["details"].is_null(),
            "the oversized details should have been dropped: {parsed}"
        );
    }

    /// An oversized `details` is dropped, and the `code` still goes out.
    ///
    /// The live instance this bound exists for: a policy denial puts the Rego
    /// module's `explanation` on the wire, and that string is authored by
    /// whoever wrote the policy with no length anybody checks.
    #[test]
    fn an_oversized_details_is_dropped_but_the_code_survives() {
        let huge = serde_json::json!({ "explanation": "x".repeat(DETAILS_MAX_JCS_BYTES + 1) });
        let outcome = reject_with(
            &doc(),
            RejectReason::TaskFailed {
                reason: "policy denied".into(),
                details: Some(huge),
            },
        );
        let parsed: Value = serde_json::from_slice(&outcome.body).expect("error doc");
        assert_eq!(
            parsed["payload"]["code"], "taskFailed",
            "an oversized annex must never cost the code: {parsed}"
        );
        assert!(
            parsed["payload"].get("details").is_none_or(Value::is_null),
            "the oversized details must not go out: {parsed}"
        );
    }

    /// Too many members is the other half of the bound, and is not implied by
    /// the byte count — sixteen short members are small and still refused.
    #[test]
    fn a_details_with_too_many_members_is_dropped() {
        let mut wide = serde_json::Map::new();
        for i in 0..=DETAILS_MAX_MEMBERS {
            wide.insert(format!("k{i}"), serde_json::json!(1));
        }
        let outcome = reject_with(
            &doc(),
            RejectReason::TaskFailed {
                reason: "policy denied".into(),
                details: Some(Value::Object(wide)),
            },
        );
        let parsed: Value = serde_json::from_slice(&outcome.body).expect("error doc");
        assert_eq!(parsed["payload"]["code"], "taskFailed");
        assert!(parsed["payload"].get("details").is_none_or(Value::is_null));
    }

    /// A `details` inside the bound is untouched — the bound must not become a
    /// reason nothing useful is ever returned.
    #[test]
    fn a_small_details_still_goes_out() {
        let outcome = reject_with(
            &doc(),
            RejectReason::TaskFailed {
                reason: "policy denied".into(),
                details: Some(serde_json::json!({ "reason": "auth:consent_required" })),
            },
        );
        let parsed: Value = serde_json::from_slice(&outcome.body).expect("error doc");
        assert_eq!(
            parsed["payload"]["details"]["reason"], "auth:consent_required",
            "{parsed}"
        );
    }

    /// The core members of an `auth:consent_required` annex — everything the
    /// requester needs to follow the ceremony, and nothing it can relay.
    const CONSENT_CORE_MEMBERS: &[&str] = &[
        "reason",
        "payloadDigest",
        "correlator",
        "challenge",
        "approverSet",
        "minApprovals",
        "excludeRequester",
    ];

    /// A signed `task-consent/request` of the size the gate mints: the
    /// envelope, a payload with one rotation effect and a state pin, and an
    /// `eddsa-jcs-2022` proof. The e2e suite measures real ones; this keeps the
    /// unit bound honest about the order of magnitude.
    fn signed_consent_request(approver: usize) -> Value {
        let vta = "did:webvh:QmSCIDabcdefghijklmnopqrstuvwxyz0123456789ABCD:vta.example.com";
        json!({
            "id": format!("urn:uuid:00000000-0000-4000-8000-{approver:012}"),
            "type": crate::trust_tasks::consent_request::TASK_CONSENT_REQUEST_0_1,
            "issuer": vta,
            "recipient": format!("did:key:z6Mk{approver:0>44}"),
            "issuedAt": "2026-09-23T00:00:00Z",
            "payload": {
                "challenge": "c".repeat(43),
                "taskType": vta_sdk::trust_tasks::TASK_WEBVH_DIDS_UPDATE_1_0,
                "payloadDigest": "d".repeat(64),
                "sideEffects": "stateChanging",
                "exposure": "privileged",
                "effects": [{
                    "kind": "keyRotation",
                    "did": "did:webvh:QmSCIDabcdefghijklmnopqrstuvwxyz0123456789ABCD:files.example.com:acme",
                    "from": ["z6Mk".to_string() + &"a".repeat(44)],
                    "to": ["z6Mk".to_string() + &"b".repeat(44)],
                }],
                "requester": format!("did:key:z6Mk{:0>44}", 0),
                "approverSet": "operators",
                "minApprovals": 1,
                "excludeRequester": true,
                "expiresAt": "2026-09-23T00:05:00Z",
                "statePin": { "versionId": format!("3-Qm{}", "e".repeat(44)) },
            },
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": format!("{vta}#key-0"),
                "proofPurpose": "assertionMethod",
                "created": "2026-09-23T00:00:00Z",
                "proofValue": format!("z{}", "f".repeat(87)),
            },
        })
    }

    fn consent_required_details(approvers: usize) -> Value {
        json!({
            "reason": "auth:consent_required",
            "payloadDigest": "d".repeat(64),
            "correlator": "r".repeat(43),
            "challenge": "c".repeat(43),
            "approverSet": "operators",
            "minApprovals": 1,
            "excludeRequester": true,
            "consentRequests": (0..approvers).map(signed_consent_request).collect::<Vec<_>>(),
        })
    }

    /// Keyring VTI-37: an `auth:consent_required` annex with enough approvers
    /// to pass the default bound used to be dropped whole, so the requester got
    /// a bare code — no digest, no correlator, nothing to relay. Now the relay
    /// copies are shed and counted, and the ceremony's coordinates always go
    /// out; the requests go out only whole.
    #[test]
    fn a_consent_required_annex_sheds_its_requests_before_its_coordinates() {
        for approvers in [1, 2, 3, 5] {
            let sent = consent_required_details(approvers);
            let fits_whole = details_within_bound(&sent);
            let details = details_of(reject_with(
                &doc(),
                RejectReason::TaskFailed {
                    reason: "auth:consent_required".into(),
                    details: Some(sent.clone()),
                },
            ));

            for member in CONSENT_CORE_MEMBERS {
                assert_eq!(
                    details[*member], sent[*member],
                    "{approvers} approver(s): core member `{member}` must always go out: {details}"
                );
            }
            if fits_whole {
                assert_eq!(
                    details["consentRequests"].as_array().map(Vec::len),
                    Some(approvers),
                    "{approvers} approver(s): requests that fit go out whole: {details}"
                );
                assert!(details.get("consentRequestsOmitted").is_none(), "{details}");
            } else {
                assert!(
                    details.get("consentRequests").is_none(),
                    "{approvers} approver(s): never a partial list: {details}"
                );
                assert_eq!(
                    details["consentRequestsOmitted"],
                    json!(approvers),
                    "{approvers} approver(s): the count of what was shed: {details}"
                );
            }
            assert!(
                details_within_bound(&details),
                "{approvers} approver(s): what goes out is within the bound: {details}"
            );
            let jcs = serde_json_canonicalizer::to_string(&details).expect("jcs");
            assert!(jcs.len() <= DETAILS_MAX_JCS_BYTES, "{} bytes", jcs.len());
            assert!(details.as_object().expect("object").len() <= DETAILS_MAX_MEMBERS);
        }

        // The ends are not left to the size estimate above.
        assert!(details_within_bound(&consent_required_details(1)));
        assert!(!details_within_bound(&consent_required_details(5)));
    }

    /// The same shedding holds on the extended-code funnel.
    #[test]
    fn an_extended_code_rejection_sheds_rather_than_drops() {
        let code: TrustTaskCode = "provision/integration:contextRequired"
            .parse()
            .expect("a legal extended code");
        let outcome = reject_with_code(&doc(), code, "held", Some(consent_required_details(5)));
        let details = details_of(outcome);
        assert_eq!(details["challenge"], json!("c".repeat(43)), "{details}");
        assert_eq!(details["consentRequestsOmitted"], json!(5), "{details}");
    }

    /// Shedding is not a way around the bound: an annex still oversized once
    /// every sheddable member is gone is dropped whole, as before.
    #[test]
    fn an_annex_still_oversized_after_shedding_is_dropped() {
        let mut details = consent_required_details(5);
        details["explanation"] = json!("x".repeat(DETAILS_MAX_JCS_BYTES + 1));
        let outcome = reject_with(
            &doc(),
            RejectReason::TaskFailed {
                reason: "auth:consent_required".into(),
                details: Some(details),
            },
        );
        let parsed: Value = serde_json::from_slice(&outcome.body).expect("error doc");
        assert_eq!(parsed["payload"]["code"], "taskFailed");
        assert!(
            parsed["payload"].get("details").is_none_or(Value::is_null),
            "{parsed}"
        );
    }

    /// An `internalError` says nothing about the consumer's internals.
    ///
    /// Framework 0.5.0, *What a `message` May Not Say*: a `message` MUST NOT
    /// reveal consumer-internal state, now normative for every code. This
    /// service used to pass the cause through verbatim, so a caller — on the
    /// unauthenticated routes, not yet anybody — learned the deployment's
    /// shape from its failures.
    ///
    /// The earlier version of this test asserted the opposite, that the cause
    /// *was* on the wire; its subject was a doubled "internal error:" prefix,
    /// which the fixed text also settles.
    #[test]
    fn an_internal_error_reveals_no_internal_state() {
        let secret = "log entry has no update_keys";
        let message = message_of(app_error_to_reject(
            &doc(),
            AppError::Internal(secret.into()),
        ));
        assert!(
            !message.contains(secret),
            "the cause must reach the operator's log, never the wire: {message}"
        );
        assert!(
            message.contains(OPAQUE_INTERNAL_ERROR),
            "the producer still needs to be told the failure was not its \
             document's doing: {message}"
        );
        assert!(
            !message.contains("internal error: internal error"),
            "{message}"
        );
    }

    /// Every `AppError` that is not a caller-facing class lands on the same
    /// opaque text, not just `Internal`.
    ///
    /// The catch-all arm was the quieter leak: it rendered whatever `Display`
    /// the error happened to have, so a variant added later would start
    /// publishing itself without anyone choosing to.
    #[test]
    fn the_catch_all_arm_is_opaque_too() {
        let message = message_of(app_error_to_reject(
            &doc(),
            AppError::SecretStore("vault backend at 10.0.0.7 refused the token".into()),
        ));
        assert!(!message.contains("10.0.0.7"), "{message}");
        assert!(!message.contains("vault backend"), "{message}");
        assert!(message.contains(OPAQUE_INTERNAL_ERROR), "{message}");
    }

    /// REGRESSION (2026-09-21): an openvtc join failed because the DID-hosting
    /// server never answered the VTA's TSP request, and the user saw only
    /// "internal error: the consumer could not complete this task" — a
    /// failure in *their own VTA*, by that wording. An upstream failure is a
    /// `taskFailed` with its own reason, and still says nothing about which
    /// peer or how.
    #[test]
    fn an_upstream_failure_is_named_as_one_without_its_cause() {
        for status in [StatusCode::BAD_GATEWAY, StatusCode::GATEWAY_TIMEOUT] {
            let err = || AppError::ServiceError {
                status,
                message: "bad gateway: `did:webvh:QmHost:dids.example` at \
                          https://10.0.0.7/trust-tasks did not answer"
                    .into(),
            };
            let parsed: Value = serde_json::from_slice(&app_error_to_reject(&doc(), err()).body)
                .expect("error doc parses");
            assert_eq!(parsed["payload"]["code"], "taskFailed", "{status}");
            assert_eq!(
                parsed["payload"]["details"]["reason"],
                reasons::UPSTREAM_UNAVAILABLE,
                "{status}"
            );
            let message = message_of(app_error_to_reject(&doc(), err()));
            assert!(message.contains(UPSTREAM_UNAVAILABLE_MESSAGE), "{message}");
            assert!(!message.contains("10.0.0.7"), "{message}");
            assert!(!message.contains("QmHost"), "{message}");
            assert!(!message.contains(OPAQUE_INTERNAL_ERROR), "{message}");
        }
    }

    /// REGRESSION (data-rooms run, 2026-10): a VTA that shared no transport
    /// with the room's host answered `malformedRequest`, because the refusal
    /// rode `AppError::Validation` — telling the client its document was wrong
    /// and losing both sets. It is `taskFailed`, not retryable, with the sets in
    /// `details`, and the SDK recovers `VtaError::NoMatchingProtocol` from it.
    #[test]
    fn no_matching_protocol_is_task_failed_with_both_sets_and_reads_back_typed() {
        use vta_sdk::protocol::matching::Protocol;
        let err = AppError::from(vti_common::error::NoMatchingProtocol {
            peer: "did:webvh:vtc.example".into(),
            ours: vec![Protocol::Rest],
            theirs: vec![Protocol::Didcomm],
            note: None,
        });
        let parsed: Value = serde_json::from_slice(&app_error_to_reject(&doc(), err).body)
            .expect("error doc parses");
        let payload = &parsed["payload"];
        assert_eq!(payload["code"], "taskFailed", "{payload}");
        assert_ne!(
            payload["retryable"], true,
            "the same sets meet a retry: {payload}"
        );
        assert_eq!(payload["details"]["reason"], reasons::NO_MATCHING_PROTOCOL);
        assert_eq!(payload["details"]["ours"], serde_json::json!(["rest"]));
        assert_eq!(payload["details"]["theirs"], serde_json::json!(["didcomm"]));
        match vta_sdk::error::VtaError::no_matching_protocol_from(&payload["details"]) {
            Some(vta_sdk::error::VtaError::NoMatchingProtocol {
                counterparty_did,
                ours,
                theirs,
            }) => {
                assert_eq!(counterparty_did, "did:webvh:vtc.example");
                assert_eq!(ours, vec![Protocol::Rest]);
                assert_eq!(theirs, vec![Protocol::Didcomm]);
            }
            other => panic!("expected the typed variant back, got {other:?}"),
        }
    }

    /// VTI-KEY-009, receiving side: material that needs a method this VTA
    /// does not resolve is refused `proofInvalid`, discriminated
    /// `unsupportedDidMethod` with the method, and reads back typed.
    #[test]
    fn vti_key_009_unsupported_did_method_is_proof_invalid_and_reads_back_typed() {
        let err = AppError::UnsupportedDidMethod {
            method: "example".into(),
        };
        let parsed: Value = serde_json::from_slice(&app_error_to_reject(&doc(), err).body)
            .expect("error doc parses");
        let payload = &parsed["payload"];
        assert_eq!(payload["code"], "proofInvalid", "{payload}");
        assert_eq!(payload["details"]["reason"], "unsupportedDidMethod");
        assert_eq!(payload["details"]["method"], "example");
        assert!(matches!(
            vta_sdk::error::VtaError::method_refusal_from(&payload["details"]),
            Some(vta_sdk::error::VtaError::UnsupportedDidMethod { method }) if method == "example"
        ));
    }

    /// Only the gateway statuses are upstream failures. Any other
    /// `ServiceError` (a key-derivation or attestation failure) is this VTA's
    /// own and stays opaque.
    #[test]
    fn other_service_errors_stay_internal() {
        let message = message_of(app_error_to_reject(
            &doc(),
            AppError::ServiceError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "key derivation failed at m/26'/2'".into(),
            },
        ));
        assert!(message.contains(OPAQUE_INTERNAL_ERROR), "{message}");
        assert!(!message.contains("m/26'"), "{message}");
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

    /// The other arms pair a differently-worded reject reason with the variant,
    /// so their `Display` is not redundant and stays — a `NotFound` still reads
    /// "task failed: not found: …", naming both the framework's verdict and ours.
    /// Pinned so a future tidy-up does not strip the cause along with the stutter.
    #[test]
    fn a_not_found_keeps_the_cause_the_operator_needs() {
        let message = message_of(app_error_to_reject(
            &doc(),
            AppError::NotFound("SCID QmNope not found".into()),
        ));
        assert!(message.contains("SCID QmNope not found"), "{message}");
    }

    /// `Gone` must not fall through to the `internal_error` catch-all. A
    /// consumed single-use resource is a terminal outcome the *caller* has to
    /// act on; `internal_error` reads as "server bug, try again", which is the
    /// one instruction that can never work here.
    #[test]
    fn a_gone_is_a_task_failure_not_an_internal_error() {
        let message = message_of(app_error_to_reject(
            &doc(),
            AppError::Gone("carve-out has already been used".into()),
        ));
        assert!(
            message.contains("carve-out has already been used"),
            "{message}"
        );
        assert!(
            !message.starts_with("internal error"),
            "a consumed resource must not report as a server fault: {message}"
        );
    }

    /// #2571: the VTA's mapping now falls through to the shared one. Every
    /// `AppError` the VTA's own copy mapped still leaves with the same code and
    /// `details.reason`; the four it used to collapse into `internalError`
    /// (which tells a client to retry) now get the shared mapping.
    #[test]
    fn every_app_error_maps_to_the_code_it_did_before_the_merge() {
        use axum::http::StatusCode as S;
        let peer = || vti_common::error::NoMatchingProtocol {
            peer: "did:webvh:Qm:peer.example".into(),
            ours: vec![],
            theirs: vec![],
            note: None,
        };
        let cases: Vec<(AppError, &str, Option<&str>)> = vec![
            // Mapped by the VTA's copy before the merge: unchanged.
            (
                AppError::Authentication("a".into()),
                "permissionDenied",
                None,
            ),
            (AppError::Unauthorized("a".into()), "permissionDenied", None),
            (AppError::Forbidden("a".into()), "permissionDenied", None),
            (AppError::Validation("a".into()), "malformedRequest", None),
            (
                AppError::TrustTaskMalformed("a".into()),
                "malformedRequest",
                None,
            ),
            (AppError::InvalidCursor, "malformedRequest", None),
            (
                AppError::NotFound("a".into()),
                "taskFailed",
                Some(reasons::NOT_FOUND),
            ),
            (
                AppError::Conflict("a".into()),
                "taskFailed",
                Some(reasons::CONFLICT),
            ),
            (
                AppError::Gone("a".into()),
                "taskFailed",
                Some(reasons::GONE),
            ),
            (
                AppError::ServiceError {
                    status: S::BAD_GATEWAY,
                    message: "a".into(),
                },
                "taskFailed",
                Some(reasons::UPSTREAM_UNAVAILABLE),
            ),
            (
                AppError::ServiceError {
                    status: S::GATEWAY_TIMEOUT,
                    message: "a".into(),
                },
                "taskFailed",
                Some(reasons::UPSTREAM_UNAVAILABLE),
            ),
            (
                AppError::ServiceError {
                    status: S::INTERNAL_SERVER_ERROR,
                    message: "a".into(),
                },
                "internalError",
                None,
            ),
            (
                peer().into(),
                "taskFailed",
                Some(reasons::NO_MATCHING_PROTOCOL),
            ),
            (
                AppError::UnsupportedDidMethod {
                    method: "example".into(),
                },
                "proofInvalid",
                Some(reasons::UNSUPPORTED_DID_METHOD),
            ),
            (AppError::Internal("a".into()), "internalError", None),
            (AppError::SecretStore("a".into()), "internalError", None),
            // Were `internalError` here; the shared mapping's answers now.
            (
                AppError::StepUpRequired("a".into()),
                "permissionDenied",
                None,
            ),
            (AppError::TrustTaskMissing, "malformedRequest", None),
            (
                AppError::IdempotencyKeyConflict,
                "taskFailed",
                Some(reasons::CONFLICT),
            ),
            (
                AppError::ApprovalRequired {
                    code: "auth:consent_required",
                    details: json!({}),
                },
                "taskFailed",
                Some("auth:consent_required"),
            ),
        ];
        for (err, code, reason) in cases {
            let label = format!("{err:?}");
            let out = app_error_to_reject(&doc(), err);
            let body: Value = serde_json::from_slice(&out.body).expect("reject body is JSON");
            assert_eq!(body["payload"]["code"], code, "{label}: {body}");
            assert_eq!(
                body.pointer("/payload/details/reason")
                    .and_then(Value::as_str),
                reason,
                "{label}: {body}"
            );
        }
    }
}
