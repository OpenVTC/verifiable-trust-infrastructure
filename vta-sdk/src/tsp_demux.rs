//! Reply correlation for TSP, shared by every TSP-carrying session.
//!
//! TSP frames carry no transport-level thread id — correlation is explicitly the
//! application's job. So any session that wants request/response over TSP needs
//! the same three things: a registry of in-flight requests, one definition of
//! "is this frame the reply to that request", and somewhere to put a frame that
//! answers *no* so it isn't dropped.
//!
//! Both TSP-carrying sessions in this crate need exactly that:
//!
//! - [`crate::session::TspSession`] — its own raw-TSP websocket, frames read and
//!   unpacked by hand.
//! - [`crate::didcomm_session::DIDCommSession`]'s TSP leg — TSP frames arriving
//!   already-unpacked on the **DIDComm** session's single multiplexed mediator
//!   socket (see that module for why there is only ever one socket per DID).
//!
//! They differ only in where a document comes from, so the bookkeeping lives
//! here and each session keeps its own pump loop. One implementation of
//! [`correlates`] is the point: it is the guard against handing back a *stale*
//! reply, and a second copy of that rule is how it would rot.

use std::collections::{HashMap, VecDeque};

use tokio::sync::{Mutex, oneshot};
use tracing::{debug, warn};

/// One in-flight request: how to recognise its reply, and where to deliver it.
struct PendingRequest {
    /// Echoed-`nonce` fallback for a responder that replies with a fresh
    /// document instead of a threaded `#response`.
    nonce: Option<String>,
    tx: oneshot::Sender<String>,
}

/// What [`TspDemux::route`] did with a document.
pub(crate) enum Routed {
    /// It was the reply to an in-flight request and went to that waiter.
    Delivered,
    /// No in-flight request wanted it — a VTA-pushed document, or a stale inbox
    /// entry. The caller decides: hand it to a push consumer, or
    /// [`park`](TspDemux::park) it for one.
    Uncorrelated(String),
}

/// How many uncorrelated documents may wait in [`TspDemux::park`] before the
/// oldest is discarded.
///
/// The queue used to be unbounded, which was survivable for a short-lived CLI
/// session but is not for a long-running process that only ever calls
/// `request` — every unsolicited VTA push would accumulate for the life of the
/// process with nothing ever draining it. Bounded + a `warn!` turns that into a
/// visible symptom instead of a slow leak; 256 is far above any legitimate
/// backlog for a consumer that polls its inbox at all.
const PARKED_CAPACITY: usize = 256;

/// In-flight TSP requests plus the parking lot for frames none of them wanted.
pub(crate) struct TspDemux {
    /// Waiters keyed by request document `id`. Whichever task currently holds
    /// the frame source reads on behalf of *all* of them and hands each reply to
    /// its own waiter.
    pending: Mutex<HashMap<String, PendingRequest>>,
    /// Documents that matched no in-flight request — VTA-pushed
    /// `task-consent/request`s and the like. Parked rather than dropped, so a
    /// request waiting on an unrelated reply cannot eat a push.
    parked: Mutex<VecDeque<String>>,
}

impl TspDemux {
    pub(crate) fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            parked: Mutex::new(VecDeque::new()),
        }
    }

    /// Register a waiter for `request_id` and return its receiver.
    ///
    /// Register **before** sending: a reply can land while the send call is
    /// still returning, and a waiter registered afterwards would miss it.
    pub(crate) async fn register(
        &self,
        request_id: String,
        nonce: Option<String>,
    ) -> oneshot::Receiver<String> {
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .await
            .insert(request_id, PendingRequest { nonce, tx });
        rx
    }

    /// Drop `request_id`'s waiter. Always call this once a request is finished —
    /// a timed-out or failed request must not leave a waiter behind for the pump
    /// to deliver into.
    pub(crate) async fn deregister(&self, request_id: &str) {
        self.pending.lock().await.remove(request_id);
    }

    /// Route one unpacked Trust-Task document (as JSON text) to the request it
    /// answers, or hand it back as [`Routed::Uncorrelated`].
    ///
    /// A document that isn't JSON at all can correlate with nothing, so it comes
    /// straight back uncorrelated rather than being discarded — the push
    /// consumer decides what to do with it.
    pub(crate) async fn route(&self, json: String) -> Routed {
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(&json) else {
            return Routed::Uncorrelated(json);
        };

        let mut pending = self.pending.lock().await;
        let hit = pending
            .iter()
            .find(|(id, p)| correlates(&doc, id, p.nonce.as_deref()))
            .map(|(id, _)| id.clone());
        match hit {
            Some(id) => {
                if let Some(p) = pending.remove(&id) {
                    // A dropped receiver (the requester timed out and left) is
                    // not an error — the frame is simply no longer wanted.
                    let _ = p.tx.send(json);
                }
                Routed::Delivered
            }
            None => {
                drop(pending);
                debug!(
                    thread_id = doc
                        .get("threadId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<none>"),
                    "TSP frame matched no in-flight request (push, or a stale inbox entry)"
                );
                Routed::Uncorrelated(json)
            }
        }
    }

    /// Hold an uncorrelated document for a push consumer to collect later.
    /// Bounded by [`PARKED_CAPACITY`]; the oldest is discarded once full.
    pub(crate) async fn park(&self, doc: String) {
        let mut parked = self.parked.lock().await;
        if parked.len() >= PARKED_CAPACITY {
            parked.pop_front();
            warn!(
                capacity = PARKED_CAPACITY,
                "TSP push queue is full — discarding the oldest parked document. \
                 Nothing is draining inbound pushes on this session."
            );
        }
        parked.push_back(doc);
    }

    /// Take the oldest parked document, if any. A push consumer must drain this
    /// before reading the frame source, or a push that already arrived would sit
    /// unseen behind a fresh read.
    pub(crate) async fn take_parked(&self) -> Option<String> {
        self.parked.lock().await.pop_front()
    }

    /// Drop every waiter, so an in-flight request fails fast with "session shut
    /// down" instead of blocking until its own deadline on a frame source that
    /// is about to disappear.
    pub(crate) async fn clear(&self) {
        self.pending.lock().await.clear();
    }

    /// Pull the correlation keys out of an outbound request document: its `id`
    /// (what a threaded `#response` sets `threadId` to) and any
    /// `payload.nonce` (the fallback an unthreaded responder echoes).
    ///
    /// Returns `String` errors, not `Box<dyn Error>` — see [`crate::session`]'s
    /// `await_reply` note: a boxed error is not `Send`, and one living across an
    /// await makes the whole call chain `!Send`.
    pub(crate) fn request_keys(document: &[u8]) -> Result<(String, Option<String>), String> {
        let parsed: serde_json::Value = serde_json::from_slice(document)
            .map_err(|e| format!("TSP request document is not JSON: {e}"))?;
        let request_id = parsed
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("TSP request document has no `id` to correlate its reply on")?
            .to_string();
        let nonce = parsed
            .get("payload")
            .and_then(|p| p.get("nonce"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        Ok((request_id, nonce))
    }
}

/// Does `doc` correlate to the request identified by `request_id` (and
/// optionally `nonce`)?
///
/// The single implementation of "is this frame the reply to that request",
/// shared by every TSP session. It was written for the ping path and welded
/// there; every other caller would otherwise have re-derived `threadId` matching
/// from the raw inner document.
///
/// Correlation is the Trust-Task `threadId`, which a responder sets to the
/// request's `id` (`doc.respond_with`). The echoed `payload.nonce` is accepted
/// as a fallback for a responder that replies with a fresh document rather than
/// a threaded `#response`.
///
/// **Why this cannot be "the first frame that parses".** The client's mediator
/// inbox is durable and flushes on connect, so every reply a previous process
/// run never collected is queued and lands the moment we reconnect. Accepting
/// the first frame therefore returns a *stale* reply — which is the exact fault
/// that made the #749 delivery bug look intermittent.
pub(crate) fn correlates(doc: &serde_json::Value, request_id: &str, nonce: Option<&str>) -> bool {
    if doc.get("threadId").and_then(|v| v.as_str()) == Some(request_id) {
        return true;
    }
    match nonce {
        Some(n) => {
            doc.get("payload")
                .and_then(|p| p.get("nonce"))
                .and_then(|v| v.as_str())
                == Some(n)
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn response(thread_id: &str) -> String {
        json!({
            "id": "urn:uuid:reply",
            "type": "https://trusttasks.org/spec/messaging/ping/0.1#response",
            "threadId": thread_id,
            "payload": { "ok": true },
        })
        .to_string()
    }

    /// The property that makes TSP request/response safe: a frame that is not
    /// *this* request's reply must not be accepted as one.
    ///
    /// The mediator inbox is durable and flushes on connect, so every reply a
    /// previous process run never collected lands the moment we reconnect.
    /// "First frame that parses" would therefore return a stale reply — the
    /// exact fault that made the #749 delivery bug look intermittent.
    #[test]
    fn a_stale_frame_is_not_mistaken_for_our_reply() {
        let stale = json!({
            "id": "urn:uuid:reply-to-something-else",
            "threadId": "urn:uuid:a-previous-run",
            "payload": { "nonce": "some-other-nonce" },
        });
        assert!(!correlates(
            &stale,
            "urn:uuid:our-request",
            Some("our-nonce")
        ));
    }

    /// A document with neither field correlates with nothing — it is a push,
    /// and must be parked for the receive consumer rather than eaten.
    #[test]
    fn a_push_correlates_with_no_request() {
        let push = json!({
            "id": "urn:uuid:pushed",
            "type": "https://trusttasks.org/spec/task-consent/request/0.1",
            "payload": { "taskId": "t1" },
        });
        assert!(!correlates(
            &push,
            "urn:uuid:our-request",
            Some("our-nonce")
        ));
    }

    #[test]
    fn correlates_on_thread_id() {
        let doc = json!({ "threadId": "urn:uuid:req-1" });
        assert!(correlates(&doc, "urn:uuid:req-1", None));
        assert!(!correlates(&doc, "urn:uuid:req-2", None));
    }

    /// A responder that replies with a fresh document rather than a threaded
    /// `#response` still correlates, via the echoed nonce.
    #[test]
    fn correlates_on_echoed_nonce_when_unthreaded() {
        let doc = json!({ "id": "urn:uuid:fresh", "payload": { "nonce": "n-1" } });
        assert!(correlates(&doc, "urn:uuid:req-1", Some("n-1")));
        assert!(!correlates(&doc, "urn:uuid:req-1", Some("n-2")));
        // Without a nonce to fall back on there is nothing else to match.
        assert!(!correlates(&doc, "urn:uuid:req-1", None));
    }

    #[tokio::test]
    async fn a_reply_reaches_its_own_waiter() {
        let demux = TspDemux::new();
        let mut rx = demux.register("urn:uuid:req-1".into(), None).await;
        assert!(matches!(
            demux.route(response("urn:uuid:req-1")).await,
            Routed::Delivered
        ));
        let got = rx.try_recv().expect("the waiter received its reply");
        assert!(got.contains("urn:uuid:req-1"));
    }

    /// Two requests in flight: each reply goes to its own waiter, and neither
    /// can consume the other's.
    #[tokio::test]
    async fn concurrent_waiters_do_not_steal_from_each_other() {
        let demux = TspDemux::new();
        let mut rx_a = demux.register("urn:uuid:a".into(), None).await;
        let mut rx_b = demux.register("urn:uuid:b".into(), None).await;

        demux.route(response("urn:uuid:b")).await;
        assert!(
            rx_a.try_recv().is_err(),
            "A's waiter must not receive B's reply"
        );
        assert!(rx_b.try_recv().is_ok(), "B's waiter receives B's reply");

        demux.route(response("urn:uuid:a")).await;
        assert!(rx_a.try_recv().is_ok(), "A's waiter still receives its own");
    }

    /// The invariant that keeps a push from being eaten by an unrelated
    /// request: an uncorrelated frame comes back to the caller, and parking it
    /// makes it collectable.
    #[tokio::test]
    async fn an_uncorrelated_document_is_returned_and_can_be_parked() {
        let demux = TspDemux::new();
        let _rx = demux.register("urn:uuid:req-1".into(), None).await;

        let push = json!({ "id": "urn:uuid:push", "type": "task-consent/request" }).to_string();
        let Routed::Uncorrelated(doc) = demux.route(push.clone()).await else {
            panic!("a push must not be delivered to an unrelated waiter");
        };
        assert_eq!(doc, push);

        demux.park(doc).await;
        assert_eq!(demux.take_parked().await.as_deref(), Some(push.as_str()));
        assert!(demux.take_parked().await.is_none());
    }

    /// Non-JSON can correlate with nothing, so it must be handed up rather than
    /// silently dropped.
    #[tokio::test]
    async fn a_non_json_frame_is_uncorrelated_not_dropped() {
        let demux = TspDemux::new();
        assert!(matches!(
            demux.route("not json at all".into()).await,
            Routed::Uncorrelated(_)
        ));
    }

    /// `clear()` (what shutdown calls) drops every waiter, so an in-flight
    /// request fails immediately instead of waiting out its deadline.
    #[tokio::test]
    async fn clear_wakes_waiters_with_a_closed_channel() {
        let demux = TspDemux::new();
        let mut rx = demux.register("urn:uuid:req-1".into(), None).await;
        demux.clear().await;
        assert!(
            matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Closed)),
            "a cleared waiter must observe the channel closed, not stay pending"
        );
    }

    /// The parking lot is bounded: a session that never drains pushes drops the
    /// oldest rather than growing without limit.
    #[tokio::test]
    async fn parking_is_bounded_and_drops_the_oldest() {
        let demux = TspDemux::new();
        for i in 0..PARKED_CAPACITY + 1 {
            demux.park(format!("doc-{i}")).await;
        }
        assert_eq!(
            demux.take_parked().await.as_deref(),
            Some("doc-1"),
            "doc-0 must have been discarded to make room"
        );
    }

    #[test]
    fn request_keys_reads_id_and_nonce() {
        let doc = json!({ "id": "urn:uuid:req-1", "payload": { "nonce": "n-1" } });
        let (id, nonce) = TspDemux::request_keys(&serde_json::to_vec(&doc).unwrap()).unwrap();
        assert_eq!(id, "urn:uuid:req-1");
        assert_eq!(nonce.as_deref(), Some("n-1"));
    }

    /// A document with no `id` has nothing to correlate a reply on, so it is
    /// refused up front rather than sent and silently un-awaitable.
    #[test]
    fn request_keys_refuses_a_document_with_no_id() {
        let doc = json!({ "payload": { "nonce": "n-1" } });
        assert!(TspDemux::request_keys(&serde_json::to_vec(&doc).unwrap()).is_err());
        assert!(TspDemux::request_keys(b"not json").is_err());
    }
}
