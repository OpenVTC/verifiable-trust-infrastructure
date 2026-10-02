//! Reaching a TSP peer on another mediator — shared by every node that starts
//! a TSP exchange (the VTA's outbound, the VTC's registry and git-ns bridge
//! clients).
//!
//! # Why this exists (VTI-56)
//!
//! A mediator delivers a Direct TSP message only to an account it hosts, and
//! refuses one for anybody else (`e.p.direct_delivery.denied`). So everything a
//! node sends to a peer on *another* mediator has to be routed through that
//! mediator:
//!
//! - **The relationship invite.** The SDK routes it, from 0.31.1
//!   (affinidi-tdk-rs #913): with no mediator learned for the peer, it uses the
//!   one the peer's DID document names in its `TSPTransport` service. Before
//!   that, a node starting a relationship sent its invite to its own mediator,
//!   which refused it on every attempt, and nothing reached the other mediator.
//!   That was the field report. The workspace floor is 0.31.1 for this reason.
//! - **The payload.** The SDK's `send_reestablishing` sends it along the route
//!   it is given. `[our_mediator, peer]` ends at a mediator that does not host
//!   the peer, so it has to go `[our_mediator, peer_mediator]`, nested, and
//!   [`send_reestablishing`] here does that.
//!
//! - **The reply.** A node answering a peer that wrote to it — a Trust-Task
//!   reply, a join-request status — routed `[our_mediator, peer]` too, and so
//!   never reached a peer on another mediator. The request arrived; the answer
//!   was refused at our mediator. [`send_reply`] looks the peer's mediator up
//!   and routes the same way the payload above does.
//!
//! The peer's mediator is the `#tsp` (`TSPTransport`) endpoint of its DID
//! document, which every caller already read to choose TSP. A reply has not
//! read it, so [`send_reply`] asks the SDK, which prefers a mediator learned
//! from the peer's routed invite and falls back to that document.
//! `vti_56_a_cold_relationship_with_a_cross_mediator_peer_forms` (vta-service)
//! holds both halves.
//!
//! # A rate-limited reply is retried
//!
//! A mediator, or a CDN in front of it, can refuse the reply's HTTP post with a
//! `429`. Nothing about the reply was wrong, and it is the only copy of the
//! answer: a secret-bearing response (`provision/integration`'s sealed bundle)
//! is answered "already performed" on a retry of the request, never sent
//! again. Dropping it turned a completed provisioning into one the caller could
//! not finish (field report: Cloudflare `1015` on `/mediator/v1/inbound`). So
//! [`send_reply`] re-sends a rate-limited reply with backoff, honouring
//! `Retry-After`, for at most [`REPLY_RATE_LIMIT_RETRY`]. Every other failure is
//! returned at once, as before.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_sdk::protocols::tsp::{SendReadiness, invite_refusal_is_benign};
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use rand::RngExt;
use tracing::{info, warn};

/// How long [`send_reply`] waits to learn the peer's mediator. The lookup can
/// resolve a DID document over the network; a hung resolver must cost a reply
/// this long and then fall back, not hold the inbound loop (R1.2).
pub const PEER_MEDIATOR_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// How long [`send_reply`] keeps re-sending a reply a rate limiter refused.
/// The value is [`vta_sdk::budget::TSP_REPLY_RATE_LIMIT_RETRY_SECS`], which the
/// client's wait budget already includes.
pub const REPLY_RATE_LIMIT_RETRY: Duration =
    Duration::from_secs(vta_sdk::budget::TSP_REPLY_RATE_LIMIT_RETRY_SECS);

/// First backoff ceiling for a rate-limited reply with no `Retry-After`.
const REPLY_RETRY_BASE: Duration = Duration::from_secs(1);

/// Largest backoff ceiling for a rate-limited reply with no `Retry-After`.
const REPLY_RETRY_CAP: Duration = Duration::from_secs(8);

/// `peer_mediator` when it is a mediator other than `own_mediator` — the case
/// that needs routing through it.
#[must_use]
pub fn cross_mediator<'a>(own_mediator: &str, peer_mediator: Option<&'a str>) -> Option<&'a str> {
    peer_mediator.filter(|m| *m != own_mediator)
}

/// The recovery-aware send (Rev 3 §7.2.2) to `peer`, wherever it lives: invite
/// first when no relationship is on record, then `body` behind it (§3.6).
///
/// Same mediator, or `peer_mediator` unknown: the SDK's own
/// `send_reestablishing`, routed `[own_mediator, peer]`. Another mediator: the
/// same steps, with `body` nested `[own_mediator, peer_mediator]` and the SDK's
/// benign-refusal re-read for the case where the peer re-formed the
/// relationship first.
pub async fn send_reestablishing(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    own_mediator: &str,
    peer: &str,
    peer_mediator: Option<&str>,
    body: &[u8],
) -> Result<(), ATMError> {
    let tsp = atm.tsp();
    let Some(peer_mediator) = cross_mediator(own_mediator, peer_mediator) else {
        return tsp
            .send_reestablishing(
                profile,
                peer,
                &[own_mediator.to_string(), peer.to_string()],
                body,
            )
            .await;
    };
    if tsp.send_readiness(profile, peer).await? == SendReadiness::Reestablish
        && let Err(e) = tsp.form_relationship_routed(profile, peer).await
        && !invite_refusal_is_benign(tsp.send_readiness(profile, peer).await?)
    {
        return Err(e);
    }
    tsp.send_nested_routed(
        profile,
        &[own_mediator.to_string(), peer_mediator.to_string()],
        peer,
        body,
    )
    .await
}

/// Send `body` to `peer` over an existing relationship, wherever `peer` lives:
/// routed `[own_mediator, peer]` when it shares our mediator (or its mediator
/// is unknown), nested `[own_mediator, peer_mediator]` when it is on another.
///
/// No invite: the caller already holds a relationship with `peer` — it is
/// answering a frame `peer` just sent, or has formed one already.
pub async fn send_routed_to(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    own_mediator: &str,
    peer: &str,
    peer_mediator: Option<&str>,
    body: &[u8],
) -> Result<(), ATMError> {
    let tsp = atm.tsp();
    match cross_mediator(own_mediator, peer_mediator) {
        Some(peer_mediator) => {
            tsp.send_nested_routed(
                profile,
                &[own_mediator.to_string(), peer_mediator.to_string()],
                peer,
                body,
            )
            .await
        }
        None => {
            tsp.send_routed(profile, &[own_mediator.to_string(), peer.to_string()], body)
                .await
        }
    }
}

/// Answer `peer`, which just sent us a verified frame, wherever it lives.
///
/// The peer's mediator comes from the SDK ([`TspOps::peer_mediator`]): one
/// learned from its routed invite first, else its DID document's `#tsp`
/// service. A lookup that fails or outlasts [`PEER_MEDIATOR_LOOKUP_TIMEOUT`]
/// falls back to our own mediator — the only route there was before, and the
/// right one for a peer that shares it — with a warning, because for a peer
/// on another mediator that reply will be refused.
///
/// [`TspOps::peer_mediator`]: affinidi_messaging_sdk::protocols::tsp::TspOps::peer_mediator
pub async fn send_reply(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    own_mediator: &str,
    peer: &str,
    body: &[u8],
) -> Result<(), ATMError> {
    let peer_mediator = match tokio::time::timeout(
        PEER_MEDIATOR_LOOKUP_TIMEOUT,
        atm.tsp().peer_mediator(profile, peer),
    )
    .await
    {
        Ok(Ok(found)) => found,
        Ok(Err(e)) => {
            warn!(peer, error = %e, "could not look up the peer's TSP mediator; replying through ours");
            None
        }
        Err(_) => {
            warn!(
                peer,
                timeout_secs = PEER_MEDIATOR_LOOKUP_TIMEOUT.as_secs(),
                "timed out looking up the peer's TSP mediator; replying through ours"
            );
            None
        }
    };
    let peer_mediator = peer_mediator.as_deref();
    retry_rate_limited(
        peer,
        RetryWindow {
            budget: REPLY_RATE_LIMIT_RETRY,
            base: REPLY_RETRY_BASE,
            cap: REPLY_RETRY_CAP,
        },
        || send_routed_to(atm, profile, own_mediator, peer, peer_mediator, body),
    )
    .await
}

/// The bounds of [`retry_rate_limited`]: give up once `budget` is spent, and
/// back off (absent `Retry-After`) with full jitter from `base` up to `cap`.
#[derive(Debug, Clone, Copy)]
struct RetryWindow {
    budget: Duration,
    base: Duration,
    cap: Duration,
}

/// Run `send`, re-running it while it fails rate-limited (HTTP 429) and the
/// window allows another attempt. Any other outcome is returned as it is.
async fn retry_rate_limited<F, Fut>(
    peer: &str,
    window: RetryWindow,
    mut send: F,
) -> Result<(), ATMError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), ATMError>>,
{
    let deadline = tokio::time::Instant::now() + window.budget;
    let mut attempt: u32 = 0;
    loop {
        let err = match send().await {
            Ok(()) => {
                if attempt > 0 {
                    info!(
                        peer,
                        retries = attempt,
                        "TSP reply sent after rate-limit retries"
                    );
                }
                return Ok(());
            }
            Err(err) if err.is_rate_limited() => err,
            Err(err) => return Err(err),
        };
        let status = err.http_status();
        let retry_after = status.and_then(|s| s.retry_after());
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(delay) = next_delay(attempt, retry_after, remaining, window, jitter) else {
            warn!(
                peer,
                retries = attempt,
                budget_secs = window.budget.as_secs(),
                retry_after_secs = retry_after.map(|d| d.as_secs()),
                "TSP reply still rate-limited; giving up"
            );
            return Err(err);
        };
        warn!(
            peer,
            attempt = attempt + 1,
            rate_limit_source = status
                .and_then(|s| s.rate_limit_source.as_deref())
                .unwrap_or("unattributed"),
            retry_after_secs = retry_after.map(|d| d.as_secs()),
            delay_ms = delay.as_millis() as u64,
            "TSP reply rate-limited; retrying"
        );
        tokio::time::sleep(delay).await;
        attempt += 1;
    }
}

/// How long to wait before re-sending attempt `attempt` (0-based), or `None`
/// when the next attempt would not start inside `remaining`.
///
/// `Retry-After` is a floor — sending sooner only earns another `429` — with up
/// to `base` of jitter on top so a burst of refused replies does not return in
/// lock-step. Without it, full jitter over `min(cap, base * 2^attempt)`.
fn next_delay(
    attempt: u32,
    retry_after: Option<Duration>,
    remaining: Duration,
    window: RetryWindow,
    jitter: impl FnOnce(Duration) -> Duration,
) -> Option<Duration> {
    let delay = match retry_after {
        Some(floor) => floor + jitter(window.base),
        None => {
            let ceiling = window
                .base
                .saturating_mul(2u32.saturating_pow(attempt))
                .min(window.cap);
            jitter(ceiling)
        }
    };
    (delay < remaining).then_some(delay)
}

/// A uniform random duration in `[0, ceiling]`.
fn jitter(ceiling: Duration) -> Duration {
    let max_ms = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
    if max_ms == 0 {
        return Duration::ZERO;
    }
    Duration::from_millis(rand::rng().random_range(0..=max_ms))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use affinidi_messaging_sdk::errors::{ATMError, HttpStatusError};

    use super::{RetryWindow, cross_mediator, next_delay, retry_rate_limited};

    const WINDOW: RetryWindow = RetryWindow {
        budget: Duration::from_millis(500),
        base: Duration::from_millis(5),
        cap: Duration::from_millis(20),
    };

    fn rate_limited(retry_after: Option<&str>) -> ATMError {
        HttpStatusError::from_parts(
            "send TSP message",
            429,
            None,
            retry_after,
            "error code: 1015",
        )
        .into()
    }

    /// The field report: the mediator's edge refused the reply once, and the
    /// answer has to arrive anyway.
    #[tokio::test]
    async fn a_rate_limited_reply_is_sent_again() {
        let calls = AtomicU32::new(0);
        let result = retry_rate_limited("did:key:peer", WINDOW, || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 {
                    Err(rate_limited(None))
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    /// Only a rate limit is retried; any other refusal is the caller's at once.
    #[tokio::test]
    async fn any_other_failure_is_returned_without_a_retry() {
        let calls = AtomicU32::new(0);
        let result = retry_rate_limited("did:key:peer", WINDOW, || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err(HttpStatusError::new("send TSP message", 403).into()) }
        })
        .await;
        assert!(!result.unwrap_err().is_rate_limited());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A limiter that never relents costs the window and no more, and the
    /// caller gets the 429 to log.
    #[tokio::test]
    async fn a_limiter_that_never_relents_gives_up_inside_the_window() {
        let started = std::time::Instant::now();
        let result =
            retry_rate_limited("did:key:peer", WINDOW, || async { Err(rate_limited(None)) }).await;
        assert!(result.unwrap_err().is_rate_limited());
        assert!(started.elapsed() < WINDOW.budget + Duration::from_millis(250));
    }

    /// `Retry-After` longer than what is left: give up now rather than send
    /// early into a certain second refusal.
    #[tokio::test]
    async fn a_retry_after_past_the_window_is_not_attempted() {
        let calls = AtomicU32::new(0);
        let result = retry_rate_limited("did:key:peer", WINDOW, || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err(rate_limited(Some("10"))) }
        })
        .await;
        assert!(result.unwrap_err().is_rate_limited());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn retry_after_is_a_floor() {
        let max = |c: Duration| c;
        let delay = next_delay(
            0,
            Some(Duration::from_millis(100)),
            Duration::from_secs(1),
            WINDOW,
            max,
        );
        assert_eq!(delay, Some(Duration::from_millis(105)));
    }

    #[test]
    fn backoff_doubles_up_to_the_cap() {
        let max = |c: Duration| c;
        let at = |n| next_delay(n, None, Duration::from_secs(1), WINDOW, max).unwrap();
        assert_eq!(at(0), Duration::from_millis(5));
        assert_eq!(at(1), Duration::from_millis(10));
        assert_eq!(at(2), Duration::from_millis(20));
        assert_eq!(at(10), Duration::from_millis(20));
        assert_eq!(at(u32::MAX), Duration::from_millis(20));
    }

    #[test]
    fn only_another_mediator_is_cross() {
        assert_eq!(cross_mediator("did:m:a", Some("did:m:b")), Some("did:m:b"));
        assert_eq!(cross_mediator("did:m:a", Some("did:m:a")), None);
        assert_eq!(cross_mediator("did:m:a", None), None);
    }
}
