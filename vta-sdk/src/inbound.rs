//! What an inbound Trust Task document *is*, before anything acts on it.
//!
//! # The distinction every layer was re-deriving, differently
//!
//! A Trust Task frame arriving on a transport is one of three things, and
//! almost everything a receiver does next depends on which:
//!
//! | kind | authorize it? | dispatch it? | answer it? |
//! |---|---|---|---|
//! | [`Request`](Inbound::Request) | yes | yes | yes |
//! | [`Response`](Inbound::Response) | **no** — we asked for it | no, deliver it to the waiter | no |
//! | [`Error`](Inbound::Error) | no | **no** | **never** |
//!
//! Nothing named that distinction, so each layer inferred it from whatever was
//! to hand — and the ones that inferred nothing treated every frame as a
//! request. Two live failures came out of exactly that:
//!
//! - A reply from a DID hosting server reached a VTA that had authorized it
//!   *before* reading it, so a message the VTA had itself asked for was ACL-
//!   refused as though it were an unsolicited request. Under DIDComm this could
//!   not happen — the transport correlated on `thid` — so it looked like an ACL
//!   regression, and the tempting fix was to grant the peer standing it should
//!   never need.
//! - An error document was dispatched as if it were a request, failed
//!   validation, and was answered with another error — which the peer then did
//!   too. Neither side recognised the other's error as terminal, so one failure
//!   became a permanent exchange that stopped only when the mediator began
//!   rate-limiting.
//!
//! Both are the same missing idea, and both stop being expressible once the
//! answer comes from one place.
//!
//! # Why in the SDK
//!
//! It is a fact about the *document*, so it is the same fact for everyone who
//! reads one — the VTA, a DID hosting service, any other peer. Put it in one
//! end and the other end's copy drifts; the TSP binding already taught that
//! lesson once. Same reasoning, and same home, as
//! [`tsp_binding`](crate::tsp_binding) and [`budget`](crate::budget).

use serde_json::Value;

/// The `type` URI prefix every terminal error document carries.
///
/// A prefix rather than an exact match: the version moves (`0.5` today) and a
/// receiver that stopped recognising the next one would start answering errors
/// again, which is the loop.
pub const TRUST_TASK_ERROR_PREFIX: &str = "https://trusttasks.org/spec/trust-task-error/";

/// What an inbound Trust Task document is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inbound {
    /// Unsolicited. Authorize it, dispatch it, answer it.
    Request,
    /// Threaded by `threadId` (SPEC §4.9), so it *may* answer something we
    /// sent.
    ///
    /// This is a **shape, not a verdict**, and the difference matters. Threading
    /// alone does not make a document a reply: a step-up `approve-response` and
    /// a `task-consent/decision` both thread to the request that provoked them
    /// and are nonetheless requests — they carry the approval, and treating them
    /// as replies would strand every ceremony waiting on a human.
    ///
    /// Only the receiver can settle it, by looking for a waiter on that thread.
    /// If one is holding it, the document is its answer: it carries no authority,
    /// asks for nothing, and must not be authorized or dispatched. If nobody is,
    /// it is an ordinary request.
    Response,
    /// A terminal error — a response that reports failure.
    ///
    /// Treated apart from [`Response`](Self::Response) for one reason: it must
    /// never be answered, **even when nothing is waiting for it**. An
    /// uncorrelated response can reasonably be dropped in silence; an error
    /// answered with an error is a loop that runs until something external
    /// stops it.
    Error,
}

impl Inbound {
    /// Whether this document may ever be authorized and dispatched.
    ///
    /// True for [`Response`](Self::Response) as well as
    /// [`Request`](Self::Request), because a threaded document with no waiter is
    /// an ordinary request — see `Response`. Only an
    /// [`Error`](Self::Error) is excluded outright.
    #[must_use]
    pub fn may_dispatch(self) -> bool {
        !matches!(self, Self::Error)
    }

    /// Whether a reply may ever be sent for this document.
    ///
    /// False only for [`Error`](Self::Error), and that is the whole reason it is
    /// a kind of its own: answering an error is what turns a single failure into
    /// an exchange that ends when something external stops it.
    #[must_use]
    pub fn may_answer(self) -> bool {
        !matches!(self, Self::Error)
    }
}

/// Classify a parsed Trust Task document.
///
/// Order matters. An error document usually *also* carries a `threadId`, and it
/// is the error-ness that decides what may be done with it, so that is tested
/// first.
#[must_use]
pub fn classify(document: &Value) -> Inbound {
    let type_uri = document
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if type_uri.starts_with(TRUST_TASK_ERROR_PREFIX) {
        return Inbound::Error;
    }
    // A `threadId` naming the document this answers is SPEC §4.9's correlation
    // rule and the only thing that distinguishes a response from a request —
    // `id` is present on both.
    match document.get("threadId").and_then(Value::as_str) {
        Some(t) if !t.is_empty() => Inbound::Response,
        _ => Inbound::Request,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_fresh_document_is_a_request() {
        let doc =
            json!({"id": "urn:uuid:1", "type": "https://trusttasks.org/spec/keys/create/0.1"});
        assert_eq!(classify(&doc), Inbound::Request);
        assert!(classify(&doc).may_dispatch());
        assert!(classify(&doc).may_answer());
    }

    /// The failure that looked like an ACL regression: a reply the VTA had
    /// asked for, authorized as though it were an unsolicited request.
    #[test]
    fn a_threaded_document_is_response_shaped_but_may_still_be_a_request() {
        let doc = json!({
            "id": "urn:uuid:2",
            "threadId": "urn:uuid:1",
            "type": "https://trusttasks.org/spec/did-management/did/problem-report/0.1",
        });
        assert_eq!(classify(&doc), Inbound::Response);
        // A shape, not a verdict: with no waiter holding the thread this is an
        // ordinary request, and a ceremony approval depends on that.
        assert!(classify(&doc).may_dispatch());
        assert!(classify(&doc).may_answer());
    }

    /// The loop: an error answered with an error, forever.
    #[test]
    fn an_error_is_terminal_even_when_it_is_threaded() {
        let doc = json!({
            "id": "urn:uuid:3",
            "threadId": "urn:uuid:1",
            "type": "https://trusttasks.org/spec/trust-task-error/0.5",
            "payload": {"code": "malformed_request"},
        });
        assert_eq!(
            classify(&doc),
            Inbound::Error,
            "error-ness outranks threading"
        );
        assert!(!classify(&doc).may_answer(), "answering this is the loop");
    }

    /// An error with no thread is still terminal — that is the whole reason
    /// `Error` is not folded into `Response`.
    #[test]
    fn an_unthreaded_error_is_still_never_answered() {
        let doc =
            json!({"id": "urn:uuid:4", "type": "https://trusttasks.org/spec/trust-task-error/0.5"});
        assert_eq!(classify(&doc), Inbound::Error);
        assert!(!classify(&doc).may_answer());
    }

    /// The version will move. A receiver that only knew `0.5` would start
    /// answering the next one, which is the loop again.
    ///
    /// The URI is composed from [`TRUST_TASK_ERROR_PREFIX`] rather than written
    /// out. `vtc-service`'s `every_bound_canonical_task_exists_in_the_registry`
    /// scans this workspace's sources for `trusttasks.org/spec/` strings ending
    /// in a `MAJOR.MINOR` segment and asserts the registry publishes each one —
    /// so a made-up version spelled literally here reads as a real binding on an
    /// authority nobody serves. Composing it keeps the case without claiming a
    /// spec that does not exist.
    #[test]
    fn a_future_error_version_is_still_an_error() {
        let doc = json!({"id": "urn:uuid:5", "type": format!("{TRUST_TASK_ERROR_PREFIX}9.9")});
        assert_eq!(classify(&doc), Inbound::Error);
    }
}
