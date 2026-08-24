//! Per-member publish rate limiting, keyed on a hashed DID.
//!
//! The per-IP governor in front of the unauthenticated routes cannot do this
//! job. It runs before any proof is verified, so it does not know who is
//! calling, and an address is a poor stand-in for a member: one member moving
//! between addresses evades it, while a community behind one NAT is throttled
//! as though it were a single caller.
//!
//! This runs *after* the document's proof is verified, where the caller is
//! known. The two are different controls and both are wanted — the governor
//! bounds how much signature verification an anonymous caller can force, and
//! this bounds what an admitted member can do to the community's graph.
//!
//! ## Why the key is hashed
//!
//! A counter keyed on raw DIDs is a live register of who is active in this
//! community, readable by anything that can see the process. Keying on an HMAC
//! of the DID counts the same member without being that register — the same
//! discipline `vti_common::audit` applies to actors, and for the same reason.
//!
//! ## Why it is in memory
//!
//! A rate limit is about the recent past, and losing it on restart fails open
//! for one window rather than corrupting anything. Persisting it would put a
//! write on the hot path of every publish to defend against an attacker who
//! can already restart the process. `tower-governor`, in front of the same
//! route, makes the same trade.
//!
//! The consequence to know: the window is **per process**. Several replicas
//! behind a load balancer each enforce it separately, so the effective limit
//! is the configured one times the replica count. That is a property to size
//! the limit against, not a bug to work around here.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::sync::Mutex;

/// How many publications one member may make inside [`WINDOW_SECS`].
///
/// Deliberately generous. This is not a spam filter: it is a bound on what a
/// single admitted member can do to the graph before an operator notices. A
/// member establishing relationships in bulk is doing something ordinary; a
/// member publishing thousands in a minute is not.
pub const MAX_PER_WINDOW: usize = 60;

/// The window [`MAX_PER_WINDOW`] is measured over.
pub const WINDOW_SECS: i64 = 60;

/// A sliding window of recent publications, keyed by HMAC of the member's DID.
#[derive(Clone)]
pub struct PublishRateLimiter {
    inner: Arc<Mutex<HashMap<[u8; 32], Vec<DateTime<Utc>>>>>,
    key: Arc<[u8; 32]>,
}

impl std::fmt::Debug for PublishRateLimiter {
    /// Deliberately opaque: the map's keys are member-derived and its shape
    /// leaks how many members are active. Nothing needs to see either.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PublishRateLimiter(..)")
    }
}

impl PublishRateLimiter {
    /// `key` is the HMAC key the DIDs are hashed under. It never leaves this
    /// type, and the limiter is useless without it — two limiters with
    /// different keys count the same member separately, which is why the key
    /// is fixed for the process rather than rotated underneath a live window.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            key: Arc::new(key),
        }
    }

    fn hash(&self, did: &str) -> [u8; 32] {
        let mut mac =
            <Hmac<Sha256>>::new_from_slice(&*self.key).expect("HMAC accepts any key size");
        mac.update(did.as_bytes());
        mac.finalize().into_bytes().into()
    }

    /// Record a publication by `did` and report whether it is within the
    /// window's allowance.
    ///
    /// Returns `false` when the member has already used their allowance, and
    /// in that case records nothing — a refused request must not extend the
    /// window it was refused by, or a member at the limit could be held there
    /// indefinitely by their own retries.
    pub async fn check_and_record(&self, did: &str, now: DateTime<Utc>) -> bool {
        let cutoff = now - Duration::seconds(WINDOW_SECS);
        let k = self.hash(did);
        let mut map = self.inner.lock().await;

        let hits = map.entry(k).or_default();
        hits.retain(|t| *t > cutoff);
        if hits.len() >= MAX_PER_WINDOW {
            return false;
        }
        hits.push(now);

        // Drop members whose window has emptied, so an idle community does not
        // hold one entry per member who has ever published.
        if map.len() > 1024 {
            map.retain(|_, hits| hits.iter().any(|t| *t > cutoff));
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> PublishRateLimiter {
        PublishRateLimiter::new([7u8; 32])
    }

    #[tokio::test]
    async fn allows_up_to_the_limit_then_refuses() {
        let l = limiter();
        let now = Utc::now();
        for i in 0..MAX_PER_WINDOW {
            assert!(l.check_and_record("did:key:zA", now).await, "call {i}");
        }
        assert!(!l.check_and_record("did:key:zA", now).await);
    }

    /// Members are counted separately, which is the whole point of keying on
    /// the DID rather than the address they arrived from.
    #[tokio::test]
    async fn one_member_at_the_limit_does_not_block_another() {
        let l = limiter();
        let now = Utc::now();
        for _ in 0..MAX_PER_WINDOW {
            l.check_and_record("did:key:zA", now).await;
        }
        assert!(!l.check_and_record("did:key:zA", now).await);
        assert!(l.check_and_record("did:key:zB", now).await);
    }

    #[tokio::test]
    async fn the_window_slides() {
        let l = limiter();
        let start = Utc::now();
        for _ in 0..MAX_PER_WINDOW {
            l.check_and_record("did:key:zA", start).await;
        }
        assert!(!l.check_and_record("did:key:zA", start).await);
        let later = start + Duration::seconds(WINDOW_SECS + 1);
        assert!(l.check_and_record("did:key:zA", later).await);
    }

    /// A refused call must not extend the window, or a member who keeps
    /// retrying holds themselves at the limit for as long as they retry.
    #[tokio::test]
    async fn a_refusal_does_not_extend_the_window() {
        let l = limiter();
        let start = Utc::now();
        for _ in 0..MAX_PER_WINDOW {
            l.check_and_record("did:key:zA", start).await;
        }
        // Retry throughout the window; none of these should be recorded.
        for s in 1..WINDOW_SECS {
            assert!(
                !l.check_and_record("did:key:zA", start + Duration::seconds(s))
                    .await
            );
        }
        // One second past the original burst, the allowance is back.
        let after = start + Duration::seconds(WINDOW_SECS + 1);
        assert!(l.check_and_record("did:key:zA", after).await);
    }

    /// The stored key is an HMAC, not the DID. Nothing in the map should be
    /// recoverable to a member without the key.
    #[tokio::test]
    async fn keys_are_hashed_not_stored_plain() {
        let l = limiter();
        l.check_and_record("did:key:zAlice", Utc::now()).await;
        let map = l.inner.lock().await;
        let k = map.keys().next().expect("one entry");
        assert_ne!(&k[..], b"did:key:zAlice".as_slice());
        assert_eq!(k.len(), 32);
    }
}
