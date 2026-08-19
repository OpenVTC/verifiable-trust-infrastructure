//! Client-side idempotency: one key held across every attempt of one operation.
//!
//! The VTA deduplicates keyed Trust Tasks on an `idempotencyKey`
//! ([`crate::retry_safety`] says which tasks). That only helps if the *retry*
//! carries the *same* key as the attempt it is retrying — and that is precisely
//! what a hand-rolled retry loop cannot do, because it re-invokes a client
//! method that builds a fresh document each time.
//!
//! That is not a hypothetical. Every dispatch mints a new `urn:uuid:` envelope
//! id, so the VTA's `(actor, envelope-id)` replay dedup never fires on a genuine
//! retry either. A key minted inside the client method has exactly the same
//! problem: attempt two gets a new one, the VTA sees an unrelated request, and
//! the second durable effect happens anyway.
//!
//! So the key has to be scoped *outside* the call. [`VtaClient::idempotent`]
//! does that: it mints one key, holds it in a task-local for the duration of a
//! closure, and retries transient faults inside that scope. Every dispatch the
//! closure makes carries the same key.
//!
//! ```no_run
//! # async fn f(
//! #     client: &vta_sdk::client::VtaClient,
//! #     build: impl Fn() -> vta_sdk::client::CreateKeyRequest,
//! # ) -> Result<(), vta_sdk::error::VtaError> {
//! // One key across all attempts, so a lost reply converges on the first
//! // result instead of minting a second key. The request is rebuilt inside
//! // the closure because each attempt re-invokes it from scratch.
//! let key = client.idempotent(|| client.create_key(build())).await?;
//! # Ok(()) }
//! ```
//!
//! # One retry owner
//!
//! Retry layers compose badly: the messaging delivery layer already retries a
//! durable outbox with backoff, so an application loop on top multiplies
//! attempts against a server that dedups at neither. [`VtaClient::idempotent`]
//! is the application-layer owner — callers should use it *instead of* their own
//! loop, not around one.
//!
//! It also refuses to guess. A task the classification marks
//! [`RetrySafety::Keyed`](crate::retry_safety::RetrySafety::Keyed) is only
//! retried because the key makes the retry safe; a task with no classification
//! is treated as unsafe rather than assumed benign.

use std::time::Duration;

use crate::error::VtaError;

/// Attempts made in total, including the first. Bounded low on purpose: the
/// fault this recovers from is a stale socket that reconnects almost
/// immediately, and beyond a couple of attempts the useful signal is "this is
/// down", not "try harder".
pub const MAX_ATTEMPTS: usize = 3;

/// Base backoff, doubled per attempt (0.5s, then 1s).
pub const RETRY_BASE: Duration = Duration::from_millis(500);

/// Ceiling on a server-supplied `retryAfter`.
///
/// The hint is honoured, but not unconditionally: an unbounded wait on a value
/// the server chooses is a stall the server can trigger at will. Beyond this
/// the client falls back to its own backoff and lets the attempt budget run
/// out, which surfaces as an error the caller can see rather than a hang.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

tokio::task_local! {
    /// The idempotency key in scope for the current operation, set by
    /// [`VtaClient::idempotent`](crate::client::VtaClient::idempotent) and read
    /// by the dispatcher when it builds each Trust Task document.
    ///
    /// A task-local rather than a parameter because it has to reach *every*
    /// typed client method — `create_key`, `create_did_webvh`, and the twenty
    /// others — without changing twenty signatures, and because it is
    /// genuinely ambient: it belongs to the operation, not to the call.
    pub(crate) static IDEMPOTENCY_KEY: String;
}

/// The key in scope, if any.
pub fn current_key() -> Option<String> {
    IDEMPOTENCY_KEY.try_with(|k| k.clone()).ok()
}

/// A fresh idempotency key.
///
/// A UUID: the key needs to be unguessable and unique per operation, and
/// nothing reads structure out of it. Deliberately *not* derived from the
/// request — two genuinely separate creates of the same thing are two
/// operations, and a content-derived key would silently merge them.
pub fn new_key() -> String {
    format!("urn:uuid:{}", uuid::Uuid::new_v4())
}

/// Whether a failed attempt is worth repeating.
///
/// True for faults where the request most likely never arrived, or where the
/// VTA has explicitly said "ask again":
///
/// - transport and network faults — the motivating case is a stale always-on
///   DIDComm socket that the messaging layer reconnects underneath, so the next
///   send lands on a live one;
/// - 5xx, transient in the same way;
/// - [`VtaError::Unavailable`], which the VTA's idempotency layer returns while
///   a first attempt on this key is still running. Treating that as terminal
///   would abandon the one answer the caller was told to wait for.
///
/// Deterministic faults — validation, conflict, not-found, auth, gone — are
/// never retried. Re-sending cannot change them.
pub fn is_transient(e: &VtaError) -> bool {
    matches!(
        e,
        VtaError::DidcommTransport(_)
            | VtaError::TspTransport(_)
            | VtaError::Network(_)
            | VtaError::Server { .. }
            | VtaError::Unavailable { .. }
    )
}

/// How long to wait before the next attempt.
///
/// Prefers the server's hint when it gave one, capped by [`MAX_RETRY_AFTER`];
/// otherwise exponential backoff from [`RETRY_BASE`].
pub(crate) fn backoff_for(e: &VtaError, attempt: usize) -> Duration {
    if let VtaError::Unavailable {
        retry_after: Some(at),
    } = e
    {
        let delta = *at - chrono::Utc::now();
        if let Ok(d) = delta.to_std() {
            return d.min(MAX_RETRY_AFTER);
        }
        // Already in the past, or unrepresentable: retry promptly rather than
        // treating a stale hint as a reason to wait.
        return Duration::ZERO;
    }
    RETRY_BASE * (1 << (attempt.saturating_sub(1)) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_unique() {
        assert_ne!(new_key(), new_key());
    }

    #[test]
    fn transient_faults_are_retried_and_deterministic_ones_are_not() {
        assert!(is_transient(&VtaError::DidcommTransport("stale".into())));
        assert!(is_transient(&VtaError::Server {
            status: 502,
            body: String::new()
        }));
        assert!(is_transient(&VtaError::Unavailable { retry_after: None }));

        assert!(!is_transient(&VtaError::Validation("bad".into())));
        assert!(!is_transient(&VtaError::Conflict("exists".into())));
        assert!(!is_transient(&VtaError::NotFound("gone".into())));
        assert!(!is_transient(&VtaError::Auth("expired".into())));
        assert!(!is_transient(&VtaError::Gone("consumed".into())));
    }

    #[test]
    fn backoff_doubles_without_a_server_hint() {
        let e = VtaError::DidcommTransport("x".into());
        assert_eq!(backoff_for(&e, 1), RETRY_BASE);
        assert_eq!(backoff_for(&e, 2), RETRY_BASE * 2);
    }

    #[test]
    fn a_server_hint_is_honoured_but_capped() {
        let far = VtaError::Unavailable {
            retry_after: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        };
        assert_eq!(
            backoff_for(&far, 1),
            MAX_RETRY_AFTER,
            "an unbounded server-chosen wait is a stall the server can trigger"
        );

        let soon = VtaError::Unavailable {
            retry_after: Some(chrono::Utc::now() + chrono::Duration::seconds(2)),
        };
        let d = backoff_for(&soon, 1);
        assert!(
            d <= Duration::from_secs(2) && d > Duration::from_millis(500),
            "{d:?}"
        );
    }

    #[test]
    fn a_stale_hint_retries_promptly_rather_than_waiting() {
        let past = VtaError::Unavailable {
            retry_after: Some(chrono::Utc::now() - chrono::Duration::seconds(30)),
        };
        assert_eq!(backoff_for(&past, 1), Duration::ZERO);
    }

    #[tokio::test]
    async fn a_key_is_visible_only_inside_its_scope() {
        assert_eq!(current_key(), None);
        let k = new_key();
        IDEMPOTENCY_KEY
            .scope(k.clone(), async {
                assert_eq!(current_key().as_deref(), Some(k.as_str()));
            })
            .await;
        assert_eq!(current_key(), None);
    }
}
