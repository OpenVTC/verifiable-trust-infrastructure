//! Per-keyspace write tracking — when a value derived from a keyspace may be
//! cached, and when it must not be.
//!
//! Every handle the store hands out for a keyspace name shares one
//! [`KeyspaceWrites`]. Every write through any of them goes through a
//! [`WriteGuard`]:
//!
//! - **Begin** bumps the *generation* and counts the write as in flight —
//!   before its request leaves the enclave.
//! - **End** (completed, failed or dropped) bumps the generation again and
//!   uncounts it. A write that ends without a reply **after its frame was
//!   completely written** — the transport failed, or its future was dropped —
//!   marks the keyspace *unknown*: the parent may still apply it. A write that
//!   ends before its frame was completely written (no connection, pool
//!   closed, a failed write) cannot have been applied — the parent acts only
//!   on a whole frame — so its outcome is known and it marks nothing.
//! - The *unknown* mark clears when a write that **began after it**
//!   completes, or once it is [`UNKNOWN_SETTLE`] old: by then an abandoned
//!   frame has been applied or never will be.
//!
//! A reader asks for a [`ticket`](KeyspaceWrites::ticket) before reading. It
//! gets one only while nothing is in flight and nothing is unknown, and may
//! cache what it read only if the ticket is still current afterwards: no
//! write began or ended in between. A cached value is served only against a
//! current ticket for the same generation. So:
//!
//! - a value read while a write was in flight, or whose outcome is unknown,
//!   is never cached (the reader still reads through);
//! - any write — started, finished or abandoned — retires every cached value;
//! - a write applied by the parent after its future was cancelled cannot
//!   leave the pre-write value cached: the cancellation marked the keyspace
//!   unknown, so nothing read in the gap was cached.
//!
//! The local backend runs each write to completion inside a blocking closure
//! whatever happens to the awaiting future, so its writes always end with a
//! known outcome (a panic excepted, which marks unknown).
//!
//! State is process-local: nothing here says anything about a row across a
//! restart, and the offline CLI paths (daemon stopped) share nothing with a
//! running service. Cache owners still bound a value's age — see
//! [`crate::audit::AuditKeyStore`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// How long an *unknown* mark withholds tickets when no later write clears
/// it.
///
/// It must outlast any plausible gap between an abandoned frame reaching the
/// parent and the parent applying it. The parent applies a frame as soon as
/// it has read it, in milliseconds; the frame is already in its socket buffer
/// when the enclave gives up, and the pool drops that connection, so nothing
/// more can arrive on it. A parent stalled long enough to apply it later than
/// 30 s would already be failing every storage call the service makes (the
/// local store gives an operation the same 30 s). After that the frame has
/// landed or never will.
///
/// Without it, one write that timed out on a keyspace written once in weeks —
/// `audit_key` — would disable that keyspace's cache until the next rotation:
/// two extra storage reads per audited operation for weeks.
pub(crate) const UNKNOWN_SETTLE: Duration = Duration::from_secs(30);

struct State {
    /// Bumped when a write begins and again when it ends.
    generation: u64,
    /// Writes begun and not yet ended.
    in_flight: u64,
    /// Set when a write ended without a known outcome: the generation and
    /// time at that moment. Cleared by a write that began after it and
    /// completed, or once it is `settle` old.
    unknown_since: Option<(u64, Instant)>,
    settle: Duration,
}

/// One keyspace's write state, shared by every handle for that keyspace.
pub(crate) struct KeyspaceWrites(Mutex<State>);

impl Default for KeyspaceWrites {
    fn default() -> Self {
        Self::with_settle(UNKNOWN_SETTLE)
    }
}

impl KeyspaceWrites {
    fn with_settle(settle: Duration) -> Self {
        Self(Mutex::new(State {
            generation: 0,
            in_flight: 0,
            unknown_since: None,
            settle,
        }))
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // The lock guards a few integers and is never held across an await;
        // a poisoned one holds nothing half-updated worth refusing.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Start a write. Hold the guard across the write, pass
    /// [`WriteGuard::sent`] to the transport, and call
    /// [`WriteGuard::completed`] once its reply has arrived.
    pub(crate) fn begin(self: &Arc<Self>) -> WriteGuard {
        let mut s = self.state();
        s.generation += 1;
        s.in_flight += 1;
        WriteGuard {
            writes: Arc::clone(self),
            began_at: s.generation,
            sent: AtomicBool::new(false),
            completed: false,
            known_on_drop: false,
        }
    }

    /// A cache ticket: the current generation, if nothing is in flight and no
    /// write's outcome is (still) unknown. `None` means "read through, cache
    /// nothing".
    pub(crate) fn ticket(&self) -> Option<u64> {
        let mut s = self.state();
        if let Some((_, at)) = s.unknown_since
            && at.elapsed() >= s.settle
        {
            s.unknown_since = None;
        }
        (s.in_flight == 0 && s.unknown_since.is_none()).then_some(s.generation)
    }
}

/// A write in progress. Dropping it ends the write; see the module docs.
pub(crate) struct WriteGuard {
    writes: Arc<KeyspaceWrites>,
    began_at: u64,
    /// Set by the transport once the request frame has completely left; see
    /// `vsock_pool::ConnectionPool::request_tracked`.
    sent: AtomicBool,
    completed: bool,
    /// The local backend: dropped at the end of a closure that ran the write
    /// to completion, so the outcome is known unless the thread is panicking.
    known_on_drop: bool,
}

impl WriteGuard {
    /// The flag the transport sets once this write's frame has completely
    /// left the enclave. Until it is set, the write cannot have been applied.
    #[cfg(any(feature = "vsock-store", test))]
    pub(crate) fn sent(&self) -> &AtomicBool {
        &self.sent
    }

    /// The reply came back: the parent has applied or refused the write, so
    /// its outcome is known. (The local backend's writes are known on drop.)
    #[cfg(any(feature = "vsock-store", test))]
    pub(crate) fn completed(mut self) {
        self.completed = true;
    }

    /// For a write that always runs to completion where the guard is dropped
    /// (the local backend's blocking closures).
    pub(crate) fn known_on_drop(mut self) -> Self {
        self.known_on_drop = true;
        self
    }

    /// Whether the parent may have applied this write without our knowing:
    /// it ended with no reply, after its frame had left.
    fn outcome_unknown(&self) -> bool {
        if self.completed {
            return false;
        }
        if self.known_on_drop {
            return std::thread::panicking();
        }
        self.sent.load(Ordering::SeqCst)
    }
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        let unknown = self.outcome_unknown();
        let mut s = self.writes.state();
        s.generation += 1;
        s.in_flight -= 1;
        if unknown {
            s.unknown_since = Some((s.generation, Instant::now()));
        } else if self.completed
            && s.unknown_since
                .is_some_and(|(since, _)| self.began_at > since)
        {
            s.unknown_since = None;
        }
    }
}

/// Keyspace name → its [`KeyspaceWrites`], owned by a store so separately
/// obtained handles for the same name share it.
#[derive(Clone)]
pub(crate) struct Generations {
    by_name: Arc<Mutex<HashMap<String, Arc<KeyspaceWrites>>>>,
    settle: Duration,
}

impl Default for Generations {
    fn default() -> Self {
        Self {
            by_name: Default::default(),
            settle: UNKNOWN_SETTLE,
        }
    }
}

impl Generations {
    /// Test-only: a shorter [`UNKNOWN_SETTLE`] for every keyspace.
    #[cfg(all(test, feature = "vsock-store"))]
    pub(crate) fn with_settle(settle: Duration) -> Self {
        Self {
            by_name: Default::default(),
            settle,
        }
    }

    /// The write state for `name`, created on first use.
    pub(crate) fn for_keyspace(&self, name: &str) -> Arc<KeyspaceWrites> {
        self.by_name
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(KeyspaceWrites::with_settle(self.settle)))
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writes() -> Arc<KeyspaceWrites> {
        Arc::new(KeyspaceWrites::default())
    }

    /// A write whose frame left and that got no reply.
    fn abandoned_after_send(w: &Arc<KeyspaceWrites>) {
        let g = w.begin();
        g.sent().store(true, Ordering::SeqCst);
        drop(g);
    }

    #[test]
    fn a_write_in_flight_withholds_tickets_and_retires_them() {
        let w = writes();
        let before = w.ticket().expect("idle");
        let guard = w.begin();
        assert_eq!(w.ticket(), None, "in flight: no ticket");
        guard.completed();
        let after = w.ticket().expect("idle again");
        assert_ne!(before, after, "the write retired the old ticket");
    }

    #[test]
    fn a_write_that_failed_before_sending_marks_nothing() {
        let w = writes();
        let before = w.ticket().expect("idle");
        drop(w.begin()); // connect error / pool closed: the frame never left
        let after = w.ticket().expect("a known not-applied outcome");
        assert_ne!(before, after, "it still retires cached values");
    }

    #[test]
    fn an_abandoned_write_withholds_tickets_until_a_later_write_completes() {
        let w = writes();
        abandoned_after_send(&w);
        assert_eq!(w.ticket(), None);

        // A write that began *before* the abandonment does not clear it.
        let earlier = w.begin();
        abandoned_after_send(&w);
        earlier.completed();
        assert_eq!(w.ticket(), None, "an earlier write proves nothing");

        w.begin().completed();
        assert!(w.ticket().is_some(), "a later completed write clears it");
    }

    #[test]
    fn an_unknown_mark_settles_on_its_own() {
        let w = Arc::new(KeyspaceWrites::with_settle(Duration::from_millis(100)));
        abandoned_after_send(&w);
        assert_eq!(w.ticket(), None, "unknown: no ticket");
        std::thread::sleep(Duration::from_millis(150));
        assert!(w.ticket().is_some(), "settled with no later write");
    }

    #[test]
    fn a_local_write_dropped_normally_is_known() {
        let w = writes();
        drop(w.begin().known_on_drop());
        assert!(w.ticket().is_some());
    }
}
