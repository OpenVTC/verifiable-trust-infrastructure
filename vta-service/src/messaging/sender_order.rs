//! Per-sender ordering for inbound frames: a relationship-control message is a
//! **barrier** for the traffic its sender sends after it (Keyring VTI-43).
//!
//! # The bug this exists for
//!
//! [`run_inbound_loop`](super::service::run_inbound_loop) reads frames in
//! arrival order but spawns each onto its own task, so two frames from one peer
//! race. A phone sent a TSP relationship invite (`XRFI`) and, 16 ms later, a
//! Trust Task. The task's reply (a ~2 ms `permissionDenied`) was sent ~328 ms
//! *before* the VTA finished answering the invite with `XRFA` — the accept
//! resolves the peer's VID and POSTs, and only then is the relationship
//! `Bidirectional`. The phone admits application messages only on a
//! bidirectional relationship, so it received a reply on a relationship it did
//! not yet have, and dropped it. When the accept happened to win the race,
//! everything worked.
//!
//! # The shape of the fix
//!
//! Not "serialise each sender". A Trust Task can legitimately wait on a *later*
//! message from the same peer — a step-up approval, say, arriving from the very
//! phone that sent the task — and a per-sender FIFO would deadlock that task on
//! its own answer. The ordering the protocol actually needs is narrower:
//!
//! - a **barrier** frame (relationship control) runs after every earlier
//!   barrier from the same sender, so the relationship's state transitions
//!   apply in the order the peer sent them;
//! - a **follower** frame (application traffic) runs after every earlier
//!   barrier from the same sender, so it is answered on the relationship the
//!   peer established first — but followers do not wait for each other, nor
//!   does a barrier wait for earlier followers (which is what keeps the
//!   step-up case above deadlock-free);
//! - frames from different senders never wait for each other.
//!
//! # Why the order is taken on the reader task
//!
//! Acquiring a per-sender lock *inside* the spawned task would not fix the
//! race, only move it: two spawned tasks reach the lock in whatever order the
//! scheduler runs them, which is not arrival order. [`SenderOrder::admit`] is
//! synchronous and is called on the reader task, frame by frame, so the chain
//! it builds is arrival order by construction. The spawned task then only
//! *waits* on the chain ([`Ticket::ready`]).
//!
//! # Bounded
//!
//! The map holds one entry per sender with a barrier **in flight** and drops it
//! when that sender's last barrier finishes, so it is bounded by the inbound
//! loop's concurrency cap rather than by the number of peers ever seen. A wait
//! is bounded too ([`BARRIER_WAIT_LIMIT`], R1.3): a barrier whose network
//! answer hangs degrades the frames behind it to the old unordered behaviour
//! instead of wedging that peer.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::warn;

/// How long a frame waits for the barrier ahead of it before giving up and
/// running anyway. Generous next to a normal accept (hundreds of ms: a VID
/// resolution plus one POST), short enough that a hung one does not strand the
/// peer's traffic.
pub const BARRIER_WAIT_LIMIT: Duration = Duration::from_secs(15);

/// What a frame is, for ordering purposes. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameOrder {
    /// Runs after every earlier barrier from its sender; later frames from the
    /// sender run after it.
    Barrier,
    /// Runs after every earlier barrier from its sender; orders nothing.
    Follower,
    /// Takes no part in ordering (no authenticated sender, or a protocol with
    /// no relationship state to race).
    Unordered,
}

#[derive(Default)]
struct Inner {
    /// Next barrier sequence number, so a finishing barrier can tell whether it
    /// is still its sender's latest (and so may evict the entry).
    next_seq: u64,
    /// Per sender: the latest in-flight barrier's sequence number and the token
    /// cancelled when it (and so, transitively, every earlier one) finishes.
    tails: HashMap<String, (u64, CancellationToken)>,
}

/// Arrival-order bookkeeping for inbound frames, keyed by authenticated sender.
#[derive(Default, Clone)]
pub struct SenderOrder {
    inner: Arc<Mutex<Inner>>,
}

impl SenderOrder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one frame, **in arrival order** (call this on the reader task,
    /// before spawning). Never blocks: the returned [`Ticket`] is what waits.
    pub fn admit(&self, sender: Option<&str>, order: FrameOrder) -> Ticket {
        let Some(sender) = sender else {
            return Ticket::unordered();
        };
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        match order {
            FrameOrder::Unordered => Ticket::unordered(),
            FrameOrder::Follower => Ticket {
                wait: inner.tails.get(sender).map(|(_, t)| t.clone()),
                _done: None,
            },
            FrameOrder::Barrier => {
                let seq = inner.next_seq;
                inner.next_seq = inner.next_seq.wrapping_add(1);
                let token = CancellationToken::new();
                let wait = inner
                    .tails
                    .insert(sender.to_string(), (seq, token.clone()))
                    .map(|(_, t)| t);
                Ticket {
                    wait,
                    _done: Some(BarrierDone {
                        order: self.clone(),
                        sender: sender.to_string(),
                        seq,
                        token,
                    }),
                }
            }
        }
    }

    /// Senders with a barrier in flight. For tests and diagnostics.
    pub fn tracked_senders(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .tails
            .len()
    }
}

/// One frame's place in its sender's order. Hold it for as long as the frame is
/// being handled: dropping a barrier's ticket is what releases the frames
/// behind it — on success, failure or panic alike.
#[must_use = "a ticket orders nothing unless it is awaited and held while the frame is handled"]
pub struct Ticket {
    wait: Option<CancellationToken>,
    // Held only for its `Drop`, which releases the frames behind a barrier.
    _done: Option<BarrierDone>,
}

impl Ticket {
    fn unordered() -> Self {
        Self {
            wait: None,
            _done: None,
        }
    }

    /// Wait until every earlier barrier from this sender has finished, or
    /// [`BARRIER_WAIT_LIMIT`] has passed.
    pub async fn ready(&self) {
        self.ready_within(BARRIER_WAIT_LIMIT).await;
    }

    async fn ready_within(&self, limit: Duration) {
        let Some(wait) = &self.wait else { return };
        if tokio::time::timeout(limit, wait.cancelled()).await.is_err() {
            warn!(
                waited = ?limit,
                "an earlier relationship-control message from this sender is still being \
                 answered — handling this frame without waiting for it",
            );
        }
    }
}

struct BarrierDone {
    order: SenderOrder,
    sender: String,
    seq: u64,
    token: CancellationToken,
}

impl Drop for BarrierDone {
    fn drop(&mut self) {
        self.token.cancel();
        let mut inner = self.order.inner.lock().unwrap_or_else(|p| p.into_inner());
        // Evict only if no later barrier from this sender has taken the slot —
        // that one's followers are waiting on *its* token, not ours.
        if inner
            .tails
            .get(&self.sender)
            .is_some_and(|(seq, _)| *seq == self.seq)
        {
            inner.tails.remove(&self.sender);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::{mpsc, oneshot};

    const PHONE: &str = "did:peer:2.phone";
    const OTHER: &str = "did:peer:2.other";

    /// Spawn a "handler" that waits on its ticket, optionally blocks on `gate`
    /// (standing in for a slow network answer), then records `label`.
    fn handle(
        ticket: Ticket,
        label: &'static str,
        gate: Option<oneshot::Receiver<()>>,
        log: mpsc::UnboundedSender<&'static str>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            ticket.ready().await;
            if let Some(gate) = gate {
                let _ = gate.await;
            }
            let _ = log.send(label);
            drop(ticket);
        })
    }

    /// VTI-43: an invite then a Trust Task from the same peer. The accept is
    /// slow and the task is instant, yet the reply must come second.
    #[tokio::test]
    async fn a_reply_waits_for_the_earlier_relationship_accept() {
        let order = SenderOrder::new();
        let (log_tx, mut log) = mpsc::unbounded_channel();
        let (release_accept, accept_gate) = oneshot::channel();

        // Admission is on the "reader", in arrival order.
        let xrfi = order.admit(Some(PHONE), FrameOrder::Barrier);
        let task = order.admit(Some(PHONE), FrameOrder::Follower);

        let accept = handle(xrfi, "XRFA", Some(accept_gate), log_tx.clone());
        let reply = handle(task, "reply", None, log_tx.clone());

        // Give the reply every chance to overtake — it must not.
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert!(log.try_recv().is_err(), "the reply overtook the accept");

        release_accept.send(()).unwrap();
        accept.await.unwrap();
        reply.await.unwrap();
        assert_eq!(log.recv().await, Some("XRFA"));
        assert_eq!(log.recv().await, Some("reply"));
        assert_eq!(order.tracked_senders(), 0, "a finished barrier is evicted");
    }

    /// The same frames with no ordering reproduce the bug — the test above
    /// would fail without the barrier.
    #[tokio::test]
    async fn without_a_barrier_the_reply_overtakes() {
        let order = SenderOrder::new();
        let (log_tx, mut log) = mpsc::unbounded_channel();
        let (release_accept, accept_gate) = oneshot::channel();

        let xrfi = order.admit(Some(PHONE), FrameOrder::Unordered);
        let task = order.admit(Some(PHONE), FrameOrder::Follower);
        let accept = handle(xrfi, "XRFA", Some(accept_gate), log_tx.clone());
        let reply = handle(task, "reply", None, log_tx.clone());

        reply.await.unwrap();
        assert_eq!(log.recv().await, Some("reply"));
        release_accept.send(()).unwrap();
        accept.await.unwrap();
    }

    /// Another peer's traffic is never held up by this peer's accept.
    #[tokio::test]
    async fn other_senders_are_not_blocked() {
        let order = SenderOrder::new();
        let (log_tx, mut log) = mpsc::unbounded_channel();
        let (release_accept, accept_gate) = oneshot::channel();

        let xrfi = order.admit(Some(PHONE), FrameOrder::Barrier);
        let other = order.admit(Some(OTHER), FrameOrder::Follower);
        let accept = handle(xrfi, "XRFA", Some(accept_gate), log_tx.clone());
        handle(other, "other", None, log_tx.clone()).await.unwrap();
        assert_eq!(log.recv().await, Some("other"));

        release_accept.send(()).unwrap();
        accept.await.unwrap();
    }

    /// Followers do not wait for each other — a task awaiting a later message
    /// from the same peer (a step-up approval) must not deadlock on it.
    #[tokio::test]
    async fn followers_run_concurrently() {
        let order = SenderOrder::new();
        let (log_tx, mut log) = mpsc::unbounded_channel();
        let (release_first, first_gate) = oneshot::channel();

        let first = order.admit(Some(PHONE), FrameOrder::Follower);
        let second = order.admit(Some(PHONE), FrameOrder::Follower);
        let first = handle(first, "first", Some(first_gate), log_tx.clone());
        handle(second, "second", None, log_tx.clone())
            .await
            .unwrap();
        assert_eq!(log.recv().await, Some("second"));

        release_first.send(()).unwrap();
        first.await.unwrap();
    }

    /// Barriers from one sender apply in arrival order, and a follower behind
    /// two of them waits for both.
    #[tokio::test]
    async fn barriers_chain_in_arrival_order() {
        let order = SenderOrder::new();
        let (log_tx, mut log) = mpsc::unbounded_channel();
        let (release_a, gate_a) = oneshot::channel();

        let a = order.admit(Some(PHONE), FrameOrder::Barrier);
        let b = order.admit(Some(PHONE), FrameOrder::Barrier);
        let f = order.admit(Some(PHONE), FrameOrder::Follower);

        // Spawn in reverse to show spawn order is irrelevant.
        let f = handle(f, "follower", None, log_tx.clone());
        let b = handle(b, "b", None, log_tx.clone());
        let a = handle(a, "a", Some(gate_a), log_tx.clone());
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert!(log.try_recv().is_err());

        release_a.send(()).unwrap();
        for h in [a, b, f] {
            h.await.unwrap();
        }
        assert_eq!(log.recv().await, Some("a"));
        assert_eq!(log.recv().await, Some("b"));
        assert_eq!(log.recv().await, Some("follower"));
        assert_eq!(order.tracked_senders(), 0);
    }

    /// A barrier whose handler panics still releases what is behind it.
    #[tokio::test]
    async fn a_panicking_barrier_releases_its_followers() {
        let order = SenderOrder::new();
        let xrfi = order.admit(Some(PHONE), FrameOrder::Barrier);
        let task = order.admit(Some(PHONE), FrameOrder::Follower);

        let crashed = tokio::spawn(async move {
            let _held = xrfi;
            panic!("accept handler blew up");
        });
        assert!(crashed.await.is_err());
        tokio::time::timeout(Duration::from_secs(1), task.ready())
            .await
            .expect("follower released");
        assert_eq!(order.tracked_senders(), 0);
    }

    /// A hung barrier degrades to unordered after the limit instead of
    /// stranding the peer's traffic (R1.3).
    #[tokio::test]
    async fn a_hung_barrier_does_not_strand_followers() {
        let order = SenderOrder::new();
        let _hung = order.admit(Some(PHONE), FrameOrder::Barrier);
        let task = order.admit(Some(PHONE), FrameOrder::Follower);
        tokio::time::timeout(
            Duration::from_secs(5),
            task.ready_within(Duration::from_millis(20)),
        )
        .await
        .expect("the wait is bounded");
        assert_eq!(order.tracked_senders(), 1, "still in flight, still tracked");
    }

    /// No authenticated sender, no ordering (and no map entry).
    #[tokio::test]
    async fn an_anonymous_frame_is_unordered() {
        let order = SenderOrder::new();
        let t = order.admit(None, FrameOrder::Barrier);
        t.ready().await;
        assert_eq!(order.tracked_senders(), 0);
    }
}
