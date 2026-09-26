//! Waiters for replies to Trust Tasks this agent sent.
//!
//! # Why this is in the spine and not in a transport
//!
//! A reply is recognised by its `threadId` — SPEC §4.9's correlation rule,
//! falling back to `id`. That is a fact about the **document**, and this service
//! has exactly one place that reads documents: `dispatch_trust_task_core`. A
//! transport that correlated for itself would be reading the document, which is
//! the thing every binding is supposed not to do (see
//! `only_the_spine_parses_a_trust_task_document`), and it would have to be
//! written again for the next transport.
//!
//! Putting it in the spine means **every** transport gets reply correlation at
//! once. TSP is what needs it today — its inbound path treats every frame as a
//! request — but nothing here is TSP-specific.
//!
//! # Why an agent needs this at all
//!
//! TSP has no request/response semantics: `trust-tasks-tsp` offers `pack` and
//! `unpack` and nothing else, deliberately, because correlation belongs to the
//! document layer. So "send a Trust Task over TSP and get the answer" is not one
//! call on the transport — it is a send, and later an inbound document that
//! threads to it. Without somewhere to hold the waiter between those two events,
//! a VTA can only *receive* over TSP, which is why `OUTBOUND_SUPPORTED` could not
//! name it.
//!
//! Modelled on `vtc-service`'s `PendingReplies`, which solves the same problem
//! on the other side of the ecosystem.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tokio::sync::oneshot;
use trust_tasks_rs::TrustTask;

/// The `threadId` a reply to `request` will carry.
///
/// **Not the request's `id`**, and that distinction is the whole of the
/// correlation contract. `trust-tasks-rs` builds every response — success
/// (`TrustTask::respond_with`) and rejection (`build_error_response`) alike —
/// with `thread_id = request.thread_id.or(Some(request.id))`, per SPEC §4.9. So
/// a request that is already inside a thread is answered *in that thread*, and
/// a waiter keyed on its `id` would never be woken: the reply would fall
/// through to the dispatcher as an unsolicited request while the sender sat
/// waiting for a document that had already arrived.
///
/// Both sides of the registry read this one rule, which is why it is a function
/// rather than an expression written twice. `complete` reads the reply's
/// `threadId` directly, because by then the far side has already applied it.
#[must_use]
pub fn reply_thread_of(request: &Value) -> Option<&str> {
    request
        .get("threadId")
        .and_then(Value::as_str)
        .or_else(|| request.get("id").and_then(Value::as_str))
}

/// One outstanding request: the peer it went to, and the waiter for its reply.
struct Waiter {
    /// Base DID of the party the request was sent to. Only a reply whose
    /// verified signer is this DID releases the waiter.
    peer: String,
    tx: oneshot::Sender<TrustTask<Value>>,
}

/// Reply waiters, keyed on the thread the reply will name.
#[derive(Clone, Default)]
pub struct PendingReplies {
    inner: Arc<Mutex<HashMap<String, Waiter>>>,
}

fn base_did(did: &str) -> &str {
    did.split('#').next().unwrap_or(did)
}

impl PendingReplies {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a waiter for `thread` **before the request is sent**, so a fast
    /// reply cannot arrive before there is anything to receive it.
    ///
    /// `thread` is what [`reply_thread_of`] computes — the `threadId` the reply
    /// will carry, which is not always the request's `id`. `peer` is the DID the
    /// request goes to: only a reply that party verifiably signed releases the
    /// waiter.
    #[must_use]
    pub fn register(&self, thread: &str, peer: &str) -> oneshot::Receiver<TrustTask<Value>> {
        let (tx, rx) = oneshot::channel();
        self.lock().insert(
            thread.to_string(),
            Waiter {
                peer: base_did(peer).to_string(),
                tx,
            },
        );
        rx
    }

    /// Drop the waiter for `thread` — a send that failed, or a wait that timed
    /// out. Leaving it would hold the entry until the process restarted, and a
    /// much later reply would find a receiver nobody is reading.
    pub fn abandon(&self, thread: &str) {
        self.lock().remove(thread);
    }

    /// Hand `document` to whoever is waiting for it, if anyone is — and only
    /// when `verified_signer` (the DID the document's own proof verifies as,
    /// bound to its `issuer`; `None` when it carries no such proof) is the peer
    /// the request went to.
    ///
    /// `true` means this was a reply to something we sent and has been
    /// delivered; the caller must not dispatch it as a request. `false` means
    /// nobody is waiting for it from this signer — an ordinary inbound request,
    /// a reply that arrived after its waiter gave up, or a document threading
    /// to our request that the peer did not sign. The last is left for the
    /// genuine reply rather than consuming the waiter.
    ///
    /// Correlation is `threadId`, per SPEC §4.9. A document with none is not a
    /// reply to anything and is left alone: falling back to matching on `id`
    /// here would let an unrelated *request* whose id happened to collide with
    /// an outstanding one be swallowed as a reply, which is the same document
    /// disappearing rather than being answered.
    pub fn complete(&self, document: &TrustTask<Value>, verified_signer: Option<&str>) -> bool {
        let Some(thread_id) = document.thread_id.as_deref() else {
            return false;
        };
        let Some(signer) = verified_signer.map(base_did) else {
            return false;
        };
        let waiter = {
            let mut map = self.lock();
            match map.get(thread_id) {
                Some(w) if w.peer == signer => map.remove(thread_id),
                _ => None,
            }
        };
        let Some(waiter) = waiter else {
            return false;
        };
        // A failed `send` means the receiver is gone — the waiter timed out
        // between the `remove` above and here. Still `true`: the document *is* a
        // reply to something we sent, and saying otherwise would send it to the
        // dispatcher to be executed as a request. Dropping a late answer is the
        // lesser outcome by a long way.
        let _ = waiter.tx.send(document.clone());
        true
    }

    /// How many waiters are outstanding. For tests and diagnostics.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Waiter>> {
        // A poisoned lock here means a previous holder panicked while holding
        // it. The map is a registry of channels, not an invariant that can be
        // half-updated, so recovering is correct and losing every outstanding
        // waiter to a propagated panic is not.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::TypeUri;

    const PEER: &str = "did:key:z6MkPeer";

    /// Only the peer the request went to can release its waiter: an unsigned
    /// document, or one signed by someone else, on the right thread falls
    /// through and leaves the waiter for the genuine reply.
    #[tokio::test]
    async fn only_the_peer_releases_its_waiter() {
        let replies = PendingReplies::new();
        let waiting = replies.register("urn:uuid:thread-p", PEER);
        let reply = request("urn:uuid:res-p", Some("urn:uuid:thread-p"));
        assert!(!replies.complete(&reply, None), "unsigned");
        assert!(
            !replies.complete(&reply, Some("did:key:z6MkSomeoneElse")),
            "signed by another party"
        );
        assert_eq!(replies.outstanding(), 1, "the waiter is still there");
        assert!(replies.complete(&reply, Some(&format!("{PEER}#key-0"))));
        assert_eq!(waiting.await.expect("woken").id, "urn:uuid:res-p");
    }

    fn request(id: &str, thread: Option<&str>) -> TrustTask<Value> {
        let type_uri: TypeUri = "https://trusttasks.org/spec/auth/revoke-session/0.1"
            .parse()
            .expect("a well-formed Type URI");
        let mut doc = TrustTask::new(id, type_uri, serde_json::json!({}));
        doc.thread_id = thread.map(str::to_string);
        doc
    }

    /// **The registration key is read off the reply the framework actually
    /// builds, not off what this module believes it builds.**
    ///
    /// `reply_thread_of` encodes a rule that lives in `trust-tasks-rs`. Asserting
    /// it against a hand-written expectation would pass forever while the
    /// framework moved underneath it, and the symptom of being wrong is silent:
    /// the waiter is never woken and the sender times out on a reply that
    /// arrived. So the far side of the assertion is a real `respond_with`.
    #[test]
    fn the_key_matches_the_reply_the_framework_builds() {
        // A request that starts its own thread: the reply names the request id.
        let fresh = request("urn:uuid:req-1", None);
        let answer = fresh.respond_with("urn:uuid:res-1", serde_json::json!({}));
        assert_eq!(
            reply_thread_of(&serde_json::to_value(&fresh).unwrap()),
            answer.thread_id.as_deref(),
            "a request with no threadId is answered in a thread named by its id"
        );

        // A request already inside a thread: the reply names *that* thread, not
        // the request id. Keying on `id` here is the bug this pins — the reply
        // would fall through to the dispatcher as an unsolicited request while
        // the sender waited out its timeout.
        let threaded = request("urn:uuid:req-2", Some("urn:uuid:thread-a"));
        let answer = threaded.respond_with("urn:uuid:res-2", serde_json::json!({}));
        assert_eq!(answer.thread_id.as_deref(), Some("urn:uuid:thread-a"));
        assert_eq!(
            reply_thread_of(&serde_json::to_value(&threaded).unwrap()),
            answer.thread_id.as_deref(),
            "a request already in a thread is answered in that thread"
        );
    }

    /// The same rule holds for a rejection, which is the reply a caller is most
    /// likely to actually receive.
    #[test]
    fn the_key_matches_a_rejection_too() {
        let threaded = request("urn:uuid:req-3", Some("urn:uuid:thread-b"));
        let reject = threaded.reject_with(
            "urn:uuid:err-1",
            trust_tasks_rs::RejectReason::MalformedRequest {
                reason: "nope".into(),
            },
        );
        assert_eq!(
            reply_thread_of(&serde_json::to_value(&threaded).unwrap()),
            reject.thread_id.as_deref(),
            "a rejection threads the same way a success does"
        );
    }

    #[tokio::test]
    async fn a_reply_reaches_the_waiter_and_is_not_dispatched() {
        let replies = PendingReplies::new();
        let waiting = replies.register("urn:uuid:thread-c", PEER);
        assert_eq!(replies.outstanding(), 1);

        let reply = request("urn:uuid:res-4", Some("urn:uuid:thread-c"));
        assert!(
            replies.complete(&reply, Some(PEER)),
            "`true` is what tells the spine not to dispatch this as a request"
        );

        let received = waiting.await.expect("the waiter is woken");
        assert_eq!(received.id, "urn:uuid:res-4");
        assert_eq!(
            replies.outstanding(),
            0,
            "a delivered waiter is removed, so a duplicate cannot be delivered twice"
        );
    }

    /// **An ordinary request must not be swallowed.** This is the failure mode
    /// that matters most: `complete` returning `true` for something nobody sent
    /// means a real inbound request is answered with `204 No Content` and never
    /// reaches a handler — a request that vanishes rather than one that is
    /// refused.
    #[test]
    fn a_document_nobody_is_waiting_for_falls_through() {
        let replies = PendingReplies::new();
        let _waiting = replies.register("urn:uuid:thread-d", PEER);

        // Right shape, wrong thread.
        let other = request("urn:uuid:req-5", Some("urn:uuid:thread-elsewhere"));
        assert!(!replies.complete(&other, Some(PEER)));

        // No thread at all — an opening request. Note its `id` deliberately
        // collides with the outstanding thread: matching on `id` as a fallback
        // would swallow this, which is why `complete` reads `threadId` only.
        let opening = request("urn:uuid:thread-d", None);
        assert!(
            !replies.complete(&opening, Some(PEER)),
            "a request whose id collides with an outstanding thread is still a request"
        );

        assert_eq!(replies.outstanding(), 1, "neither took the waiter");
    }

    #[test]
    fn an_abandoned_waiter_lets_a_late_reply_fall_through() {
        let replies = PendingReplies::new();
        let _waiting = replies.register("urn:uuid:thread-e", PEER);
        replies.abandon("urn:uuid:thread-e");
        assert_eq!(replies.outstanding(), 0);

        let late = request("urn:uuid:res-6", Some("urn:uuid:thread-e"));
        assert!(
            !replies.complete(&late, Some(PEER)),
            "after a timeout the entry is gone, so a late answer is not claimed"
        );
    }

    /// A waiter whose receiver was dropped still **claims** the document.
    /// Returning `false` would send a reply to the dispatcher to be executed as
    /// a request; dropping a late answer is much the lesser outcome.
    #[test]
    fn a_reply_whose_waiter_gave_up_is_still_claimed() {
        let replies = PendingReplies::new();
        drop(replies.register("urn:uuid:thread-f", PEER));

        let reply = request("urn:uuid:res-7", Some("urn:uuid:thread-f"));
        assert!(replies.complete(&reply, Some(PEER)));
        assert_eq!(replies.outstanding(), 0);
    }
}
