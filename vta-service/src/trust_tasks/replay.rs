//! Trust-task replay dedup.
//!
//! The dispatcher records each `(actor, envelope-id)` it processes and rejects a
//! re-submission of the same id within a short window, so a retry — including a
//! client's cross-transport fallback (TSP → DIDComm → REST) — cannot
//! double-apply a *mutating* task. Envelope ids are unique per request (a fresh
//! UUID), so this only ever fires on a genuine resubmission of the identical
//! request, never on two distinct requests.
//!
//! **Semantics: record-before-dispatch (at-most-once).** The id is recorded
//! before the handler runs, so a crash between recording and the effect landing
//! leaves the retry rejected rather than double-applied — the safe direction for
//! mutating operations.
//!
//! **Bounded, in-memory, best-effort.** The dedup window (`TTL`) comfortably
//! covers retries/fallback (seconds); genuinely old replays are already caught
//! by the dispatcher's `validate_basic` expiry check. The cache is size-capped
//! and does not persist across restarts — cross-restart replay is not the threat
//! model here (an expired envelope is rejected regardless). A persistent,
//! result-caching *idempotency* layer (return the prior response on replay,
//! enabling automatic retry-with-result) is a deliberate follow-up.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// How long a processed `(actor, id)` is remembered. Comfortably longer than any
/// retry/fallback window; shorter than the dispatcher's own expiry enforcement.
const TTL: Duration = Duration::from_secs(600);

/// Upper bound on remembered entries — prevents unbounded growth under load.
/// When exceeded, expired entries are pruned before inserting.
const MAX_ENTRIES: usize = 100_000;

static SEEN: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Record `(actor, id)` and report whether it is **fresh**.
///
/// Returns `true` if this is the first time `(actor, id)` has been seen within
/// the dedup window (and records it), or `false` if it is a replay of an id
/// already processed within `TTL`.
pub(super) fn check_and_record(actor: &str, id: &str) -> bool {
    let key = format!("{actor}|{id}");
    let now = Instant::now();
    let mut seen = SEEN.lock().unwrap_or_else(|p| p.into_inner());

    if let Some(&recorded) = seen.get(&key)
        && now.duration_since(recorded) < TTL
    {
        return false; // replay within the window
    }

    // Fresh (or the prior record has aged out). Prune before growing past the cap.
    if seen.len() >= MAX_ENTRIES {
        seen.retain(|_, &mut t| now.duration_since(t) < TTL);
    }
    seen.insert(key, now);
    true
}

#[cfg(test)]
pub(super) fn reset_for_test() {
    SEEN.lock().unwrap_or_else(|p| p.into_inner()).clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_submission_is_fresh_replay_is_not() {
        reset_for_test();
        assert!(check_and_record("did:web:a", "id-1"), "first is fresh");
        assert!(!check_and_record("did:web:a", "id-1"), "replay is caught");
        // A different id, or a different actor with the same id, is independent.
        assert!(check_and_record("did:web:a", "id-2"));
        assert!(check_and_record("did:web:b", "id-1"));
    }
}
