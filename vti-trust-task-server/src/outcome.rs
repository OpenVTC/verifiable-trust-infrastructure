//! [`TrustTaskOutcome`], the transport-neutral result of handling a document.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// The transport-neutral result of dispatching a Trust Task: the framework
/// HTTP status code plus the serialised result/error document bytes.
///
/// Every transport renders from this one value — the HTTPS route turns it into
/// an `axum::Response` via [`IntoResponse`]; a DIDComm or TSP handler reads
/// [`body`](Self::body) straight as the reply envelope. The body stays raw
/// bytes (not a `serde_json::Value`) so the wire output is byte-identical to
/// direct document serialisation (serde_json has no `preserve_order` here, so
/// a `Value` round-trip would alphabetise object keys).
///
/// An empty `body` is an answer with no document: a duplicate still in flight
/// (`202`), one completed without a recordable response (`204`), or a refusal
/// by the transport's own admission (`429`), which the transport replaces.
#[derive(Debug)]
pub struct TrustTaskOutcome {
    /// The framework status (`trust_tasks_https::status_for_code` for a
    /// refusal).
    pub status: StatusCode,
    /// The serialised `#response`, `trust-task-error` or next-step document.
    pub body: Vec<u8>,
}

impl TrustTaskOutcome {
    /// An outcome with no document.
    pub fn empty(status: StatusCode) -> Self {
        Self {
            status,
            body: Vec::new(),
        }
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
