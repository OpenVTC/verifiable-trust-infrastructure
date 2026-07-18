//! Local replacements for the handful of `affinidi-messaging-didcomm-service`
//! types the ~50 DIDComm handlers depend on.
//!
//! The D2 P2a cut-over removed the `affinidi-messaging-didcomm-service`
//! framework (its type-routed `Router` + middleware) in favour of the
//! reliable-messaging delivery layer (`MessagingService`), exactly as the VTC
//! pilot did. The handler *bodies* in [`super::handlers`] /
//! [`super::handlers_protocol`] are unchanged: they still take
//! `(HandlerContext, Message, Extension<T>)` and return
//! `Result<Option<DIDCommResponse>, DIDCommServiceError>`. This module supplies
//! those four types locally so the bodies compile verbatim, while
//! [`super::router::dispatch`] — not a framework `Router` — is what actually
//! calls them (a `msg.typ` match built directly, so no `handler_fn` /
//! `FromMessageParts` extraction machinery is needed; `Extension<T>` is a plain
//! tuple the dispatch constructs at each call site).
//!
//! [`ProblemReport`] is re-declared here (byte-identical serde to the framework
//! / mediator-common shape) rather than re-exported, because the
//! `affinidi-messaging-sdk` crate is optional in this build (only on under the
//! `tsp` feature) and the framework re-exported it from there.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Per-message context handed to each handler. The delivery-layer inbound loop
/// builds this from the neutral `Inbound`; `sender_did` is the
/// **cryptographically-authenticated** sender (the `#620` verified-sender-or-
/// none rule — see [`super::router::dispatch`]), i.e. the same value the loop
/// stamps onto `Message::from`. Only [`super::handlers::handle_credential_query`]
/// reads it; every other handler re-derives auth via `auth_from_message`
/// (which reads that same `from`).
#[derive(Clone, Default)]
pub struct HandlerContext {
    /// The authenticated sender DID, or `None` for an anonymous / spoofed
    /// (and therefore rejected) sender.
    pub sender_did: Option<String>,
}

/// Extractor-shaped wrapper so a handler can destructure its shared state in
/// the parameter position (`Extension(state): Extension<Arc<VtaState>>`),
/// exactly as under the framework. The dispatch constructs it directly — there
/// is no type-map extraction.
pub struct Extension<T>(pub T);

/// Handler error. The framework surfaced many variants; the handlers only ever
/// construct [`DIDCommServiceError::Handler`] (via `handler_err`), so that is
/// the only variant carried forward. Rendered as an `internal-error`
/// problem-report by the dispatch when a handler returns `Err`.
#[derive(Debug, thiserror::Error)]
pub enum DIDCommServiceError {
    #[error("Handler error: {0}")]
    Handler(String),
}

/// A reply a handler asks the loop to pack + send back to the sender.
///
/// Replaces the framework `DIDCommResponse`. The delivery-layer inbound loop
/// reads [`Self::type_`] / [`Self::body`] / [`Self::thid`], builds a plaintext
/// [`affinidi_tdk::didcomm::Message`] (from = the VTA's DID, to = the request
/// sender), authcrypt-packs it, and `send`s it `BestEffort`. When `thid` is
/// `None` the loop threads the reply to the inbound message's id (the
/// framework's default).
#[derive(Debug)]
pub struct DIDCommResponse {
    pub type_: String,
    pub body: Value,
    pub thid: Option<String>,
}

impl DIDCommResponse {
    pub fn new(type_: impl Into<String>, body: Value) -> Self {
        Self {
            type_: type_.into(),
            body,
            thid: None,
        }
    }

    /// A problem-report reply. Uses the same DIDComm v2 report-problem type URI
    /// the framework did (`vta_sdk::protocols::PROBLEM_REPORT_TYPE`).
    pub fn problem_report(report: ProblemReport) -> Self {
        Self::new(vta_sdk::protocols::PROBLEM_REPORT_TYPE, report.to_body())
    }

    /// Thread this reply to `thid` (the request's own id or thread id).
    pub fn thid(mut self, thid: impl Into<String>) -> Self {
        self.thid = Some(thid.into());
        self
    }
}

/// DIDComm problem-report body. Byte-identical serde to the framework's
/// (mediator-common) `ProblemReport`, so on-wire reports are unchanged.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProblemReport {
    pub code: String,
    pub comment: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub args: Vec<String>,
    #[serde(rename = "escalate_to", skip_serializing_if = "Option::is_none")]
    pub escalate_to: Option<String>,
}

/// `e.p.msg.*` problem-report codes (the framework's `problem_report::codes`).
pub mod codes {
    pub const ERROR_UNAUTHORIZED: &str = "e.p.msg.unauthorized";
    pub const ERROR_BAD_REQUEST: &str = "e.p.msg.bad-request";
    pub const ERROR_NOT_FOUND: &str = "e.p.msg.not-found";
    pub const ERROR_CONFLICT: &str = "e.p.msg.conflict";
    pub const ERROR_INTERNAL: &str = "e.p.msg.internal-error";
}

/// Convenience constructors + `to_body`, mirroring the framework trait of the
/// same name so the handler call-sites (`ProblemReport::conflict(..)`,
/// `.to_body()`, etc.) compile unchanged.
pub trait ServiceProblemReport {
    fn unauthorized(comment: impl Into<String>) -> Self;
    fn bad_request(comment: impl Into<String>) -> Self;
    fn not_found(comment: impl Into<String>) -> Self;
    fn conflict(comment: impl Into<String>) -> Self;
    fn internal_error(comment: impl Into<String>) -> Self;
    fn with_args(self, args: Vec<String>) -> Self;
    fn with_escalate_to(self, escalate_to: String) -> Self;
    fn to_body(&self) -> Value;
}

impl ProblemReport {
    fn from_code(code: &str, comment: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            comment: comment.into(),
            args: Vec::new(),
            escalate_to: None,
        }
    }
}

impl ServiceProblemReport for ProblemReport {
    fn unauthorized(comment: impl Into<String>) -> Self {
        Self::from_code(codes::ERROR_UNAUTHORIZED, comment)
    }
    fn bad_request(comment: impl Into<String>) -> Self {
        Self::from_code(codes::ERROR_BAD_REQUEST, comment)
    }
    fn not_found(comment: impl Into<String>) -> Self {
        Self::from_code(codes::ERROR_NOT_FOUND, comment)
    }
    fn conflict(comment: impl Into<String>) -> Self {
        Self::from_code(codes::ERROR_CONFLICT, comment)
    }
    fn internal_error(comment: impl Into<String>) -> Self {
        Self::from_code(codes::ERROR_INTERNAL, comment)
    }
    fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }
    fn with_escalate_to(mut self, escalate_to: String) -> Self {
        self.escalate_to = Some(escalate_to);
        self
    }
    fn to_body(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Failed to serialize problem report");
            serde_json::json!({
                "code": codes::ERROR_INTERNAL,
                "comment": "Failed to serialize problem report"
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problem_report_serializes_like_the_framework() {
        // args + escalate_to elided when empty/none (matches mediator-common).
        let body = ProblemReport::bad_request("nope").to_body();
        assert_eq!(body["code"], codes::ERROR_BAD_REQUEST);
        assert_eq!(body["comment"], "nope");
        assert!(body.get("args").is_none());
        assert!(body.get("escalate_to").is_none());

        let body = ProblemReport::bad_request("x")
            .with_args(vec!["a".into()])
            .with_escalate_to("support".into())
            .to_body();
        assert_eq!(body["args"], serde_json::json!(["a"]));
        assert_eq!(body["escalate_to"], "support");
    }
}
