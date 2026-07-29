//! Startup self-readiness gate for the mediator DIDComm connection.
//!
//! During cold start a VTA can fire its outbound mediator handshake before its
//! own public DID document is externally reachable — the LB target isn't
//! healthy yet, so a fetch of the VTA's `did.jsonl` returns 503. The mediator
//! then can't get the VTA's key to decrypt the authcrypt auth message and
//! returns 403; the VTA burns its short retry burst and (today) gives up. The
//! visible blast radius is an LB 5XX burst and mediator auth/resolve failures.
//!
//! This gate makes the VTA wait until its own public DID is fully resolvable
//! over the network — an HTTP 200 on its `did.jsonl` *and* a complete
//! `did:webvh` resolution (the same path the mediator takes) — before
//! initiating the mediator connection. Only network-resolved DID methods
//! (`did:webvh`) are gated; a `did:key` VTA publishes no external endpoint, so
//! it skips the wait (AC #2).
//!
//! The gate is bounded: it retries with capped exponential backoff and full
//! jitter (the AWS "Exponential Backoff And Jitter" scheme) up to a maximum
//! wait, then applies a configured timeout policy (skip / proceed / fail). The
//! jitter keeps the VTA from hammering its own still-unhealthy LB target in
//! lock-step while it waits. See [`vta_config::MediatorReadinessConfig`].

use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
use rand::RngExt;
use tracing::{debug, info, warn};
use vta_config::{MediatorReadinessConfig, ReadinessTimeoutPolicy};

/// What the caller should do after the gate runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    /// Go ahead and establish the mediator DIDComm connection.
    Proceed,
    /// Do not start DIDComm this boot. `/health` stays live so the LB can turn
    /// the target healthy; a later restart reconnects.
    Skip,
}

/// Returned only when the gate times out **and** the configured policy is
/// [`ReadinessTimeoutPolicy::Fail`].
#[derive(Debug, Clone)]
pub struct ReadinessTimeout {
    pub url: String,
    pub waited_secs: u64,
}

impl std::fmt::Display for ReadinessTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "own public DID endpoint {} not reachable after {}s",
            self.url, self.waited_secs
        )
    }
}

impl std::error::Error for ReadinessTimeout {}

/// Run the self-readiness gate for `vta_did` and return the caller's decision.
///
/// Returns `Ok(Proceed)` when the endpoint became reachable, when the method
/// needs no external endpoint (e.g. `did:key`), or when the gate is disabled.
/// Returns `Ok(Skip)` on timeout under the `skip` policy. Returns
/// `Err(ReadinessTimeout)` only on timeout under the `fail` policy.
pub async fn run_gate(
    vta_did: &str,
    cfg: &MediatorReadinessConfig,
    resolver_url: Option<&str>,
) -> Result<GateDecision, ReadinessTimeout> {
    if !cfg.enabled {
        info!("mediator self-readiness gate disabled; connecting without waiting");
        return Ok(GateDecision::Proceed);
    }

    let Some(url) = self_did_jsonl_url(vta_did) else {
        // did:key (or a method we can't derive a URL for): nothing external to
        // wait for — the mediator resolves it without a network fetch.
        info!(
            vta_did,
            "self-readiness gate skipped: DID method needs no reachable public endpoint"
        );
        return Ok(GateDecision::Proceed);
    };

    let base = Duration::from_secs(cfg.retry_secs.max(1));
    // Cap can never be below the base, else backoff couldn't grow.
    let cap = Duration::from_secs(cfg.backoff_cap_secs.max(cfg.retry_secs.max(1)));
    let max_wait = Duration::from_secs(cfg.max_wait_secs);
    let url_str = url.to_string();
    info!(
        url = %url_str,
        base_secs = base.as_secs(),
        backoff_cap_secs = cap.as_secs(),
        max_wait_secs = cfg.max_wait_secs,
        "waiting for own public DID endpoint to become reachable before mediator connect \
         (exponential backoff + full jitter)"
    );

    let client = build_probe_client(base);
    let vta_did_owned = vta_did.to_string();
    let resolver_url_owned = resolver_url.map(str::to_string);
    let became_ready = run_readiness_loop(base, cap, max_wait, move || {
        let client = client.clone();
        let url = url.clone();
        let did = vta_did_owned.clone();
        let resolver_url = resolver_url_owned.clone();
        async move { probe_self_ready(&client, url, &did, resolver_url.as_deref()).await }
    })
    .await;

    if became_ready {
        info!(url = %url_str, "own public DID endpoint reachable (200); proceeding to mediator connect");
        return Ok(GateDecision::Proceed);
    }

    apply_timeout_policy(cfg.on_timeout, &url_str, cfg.max_wait_secs)
}

/// Map a timed-out gate to the caller decision per the configured policy.
/// Extracted so the policy mapping is unit-testable without any network I/O.
fn apply_timeout_policy(
    policy: ReadinessTimeoutPolicy,
    url: &str,
    waited_secs: u64,
) -> Result<GateDecision, ReadinessTimeout> {
    match policy {
        ReadinessTimeoutPolicy::Proceed => {
            warn!(
                url,
                waited_secs,
                "self-readiness gate timed out; connecting to mediator anyway (best-effort)"
            );
            Ok(GateDecision::Proceed)
        }
        ReadinessTimeoutPolicy::Skip => {
            warn!(
                url,
                waited_secs,
                "self-readiness gate timed out; skipping DIDComm startup this boot \
                 (/health stays live; a later restart reconnects)"
            );
            Ok(GateDecision::Skip)
        }
        ReadinessTimeoutPolicy::Fail => Err(ReadinessTimeout {
            url: url.to_string(),
            waited_secs,
        }),
    }
}

/// The public `did.jsonl` URL for `vta_did`, or `None` when the method needs no
/// reachable public endpoint (`did:key`) or a URL can't be derived (unknown
/// method, or built without the `webvh` feature).
pub fn self_did_jsonl_url(vta_did: &str) -> Option<reqwest::Url> {
    if vta_did.starts_with("did:key:") {
        return None;
    }

    #[cfg(feature = "webvh")]
    if vta_did.starts_with("did:webvh:") {
        return match didwebvh_rs::url::WebVHURL::parse_did_url(vta_did) {
            Ok(webvh) => match webvh.get_http_url(None) {
                Ok(url) => reqwest::Url::parse(url.as_str()).ok(),
                Err(e) => {
                    warn!(vta_did, error = %e, "self-readiness: cannot derive did.jsonl URL from DID");
                    None
                }
            },
            Err(e) => {
                warn!(vta_did, error = %e, "self-readiness: cannot parse did:webvh DID");
                None
            }
        };
    }

    let _ = vta_did;
    None
}

/// Build the probe HTTP client with a bounded per-attempt timeout so a hung
/// connect can't stall the retry cadence.
fn build_probe_client(retry: Duration) -> reqwest::Client {
    let per_attempt = retry
        .min(Duration::from_secs(10))
        .max(Duration::from_secs(1));
    reqwest::Client::builder()
        .timeout(per_attempt)
        .user_agent("vta-self-readiness-gate")
        .build()
        .expect("static reqwest client config (timeout + user agent) is always valid")
}

/// One readiness probe used by the gate loop: `true` iff the VTA's own public
/// DID is fully resolvable over the network — the same path the mediator takes
/// to fetch the authcrypt sender key. This is the "don't touch the
/// mediator until the VTA has resolved *itself*" gate upgrade: a bare HTTP 200
/// on `did.jsonl` isn't enough (a 200 with malformed/partial content still
/// fails mediator resolution), so after the cheap HTTP check we run a full
/// `did:webvh` resolution through a throwaway resolver.
async fn probe_self_ready(
    client: &reqwest::Client,
    url: reqwest::Url,
    vta_did: &str,
    resolver_url: Option<&str>,
) -> bool {
    // Fast path: the mediator fetches `did.jsonl` over HTTP first. While that
    // isn't 200 yet there's no point paying for a full resolution.
    if !probe_endpoint_200(client, url).await {
        return false;
    }
    resolve_self_did(vta_did, resolver_url).await
}

/// `true` iff the endpoint answers HTTP 200.
async fn probe_endpoint_200(client: &reqwest::Client, url: reqwest::Url) -> bool {
    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status == reqwest::StatusCode::OK {
                true
            } else {
                debug!(%status, "self-readiness probe: endpoint not ready (non-200)");
                false
            }
        }
        Err(e) => {
            debug!(error = %e, "self-readiness probe: request failed");
            false
        }
    }
}

/// `true` iff the VTA's own DID fully resolves over the network right now.
///
/// Builds a **throwaway** [`DIDCacheClient`] per call — network mode against the
/// configured `resolver_url` when set, local mode otherwise — so it resolves
/// the VTA the same way the mediator does, while a preloaded self-DID entry
/// (see `server::preload_self_did_document`) or a stale negative entry in the
/// long-lived resolver can't mask the real state.
async fn resolve_self_did(vta_did: &str, resolver_url: Option<&str>) -> bool {
    let mut builder = DIDCacheConfigBuilder::default();
    if let Some(url) = resolver_url {
        builder = builder.with_network_mode(url);
    }
    let resolver = match DIDCacheClient::new(builder.build()).await {
        Ok(r) => r,
        Err(e) => {
            debug!(error = %e, "self-readiness: could not build resolver for self-resolution probe");
            return false;
        }
    };
    match resolver.resolve(vta_did).await {
        Ok(_) => true,
        Err(e) => {
            debug!(error = %e, "self-readiness: full self-DID resolution not yet succeeding");
            false
        }
    }
}

/// Single-shot: can the VTA resolve its own DID over the network right now?
///
/// The persistent-reconnect supervisor calls this before every
/// mediator connect attempt, so a cold VTA never storms the mediator with
/// unresolvable-sender auth attempts while it can't even resolve itself.
/// Endpoint-less methods (`did:key`) have nothing external to resolve and are
/// always considered ready.
pub async fn self_did_network_resolvable(vta_did: &str, resolver_url: Option<&str>) -> bool {
    let Some(url) = self_did_jsonl_url(vta_did) else {
        return true;
    };
    let client = build_probe_client(Duration::from_secs(5));
    probe_self_ready(&client, url, vta_did, resolver_url).await
}

/// Poll `probe` until it returns `true` or `max_wait` elapses. Between attempts
/// it waits a capped-exponential-backoff-with-full-jitter interval: attempt `n`
/// (0-based) sleeps a uniform random duration in
/// `[0, min(cap, base * 2^n)]`, always clamped so it never overshoots the
/// deadline. Returns `true` if it became ready, `false` on timeout. At least
/// one probe attempt always runs (even with `max_wait == 0`). Pure of any
/// concrete I/O so it can be driven by an injected probe in tests.
async fn run_readiness_loop<F, Fut>(
    base: Duration,
    cap: Duration,
    max_wait: Duration,
    mut probe: F,
) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + max_wait;
    let mut attempt: u32 = 0;
    loop {
        if probe().await {
            return true;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return false;
        }
        let ceiling = backoff_ceiling(base, cap, attempt);
        // Full jitter, then clamp to the remaining time so we don't overshoot.
        let sleep_for = jittered_backoff(ceiling).min(deadline - now);
        debug!(
            attempt = attempt + 1,
            ceiling_secs = ceiling.as_secs_f64(),
            sleep_secs = sleep_for.as_secs_f64(),
            "self-readiness endpoint not ready; backing off before retry"
        );
        tokio::time::sleep(sleep_for).await;
        attempt = attempt.saturating_add(1);
    }
}

/// Upper bound on the backoff interval for a 0-based `attempt`:
/// `min(cap, base * 2^attempt)`. Saturating — never panics on overflow.
pub(crate) fn backoff_ceiling(base: Duration, cap: Duration, attempt: u32) -> Duration {
    let factor = 1u64.checked_shl(attempt).unwrap_or(u64::MAX); // 2^attempt, saturating
    let ceil_ms = base
        .as_millis()
        .saturating_mul(factor as u128)
        .min(cap.as_millis());
    Duration::from_millis(ceil_ms as u64)
}

/// Full jitter (AWS blog): a uniform random duration in `[0, ceiling]`.
pub(crate) fn jittered_backoff(ceiling: Duration) -> Duration {
    let max_ms = ceiling.as_millis().min(u128::from(u64::MAX)) as u64;
    if max_ms == 0 {
        return Duration::ZERO;
    }
    Duration::from_millis(rand::rng().random_range(0..=max_ms))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn did_key_has_no_public_endpoint() {
        assert!(self_did_jsonl_url("did:key:z6MkExampleKeyValue").is_none());
    }

    #[cfg(feature = "webvh")]
    #[test]
    fn did_webvh_derives_public_jsonl_url() {
        let did = "did:webvh:QmExampleScid:example.com:budget-engine";
        let url = self_did_jsonl_url(did).expect("did:webvh yields a public URL");
        assert_eq!(url.as_str(), "https://example.com/budget-engine/did.jsonl");
    }

    #[test]
    fn unknown_method_is_not_probed() {
        assert!(self_did_jsonl_url("did:peer:2zSomething").is_none());
    }

    #[test]
    fn timeout_policy_maps_to_decision() {
        assert_eq!(
            apply_timeout_policy(ReadinessTimeoutPolicy::Skip, "https://x/did.jsonl", 30).unwrap(),
            GateDecision::Skip
        );
        assert_eq!(
            apply_timeout_policy(ReadinessTimeoutPolicy::Proceed, "https://x/did.jsonl", 30)
                .unwrap(),
            GateDecision::Proceed
        );
        assert!(
            apply_timeout_policy(ReadinessTimeoutPolicy::Fail, "https://x/did.jsonl", 30).is_err()
        );
    }

    #[tokio::test]
    async fn loop_times_out_when_never_ready() {
        let calls = Cell::new(0u64);
        let ready = run_readiness_loop(
            Duration::from_millis(2),
            Duration::from_millis(8),
            Duration::from_millis(20),
            || {
                calls.set(calls.get() + 1);
                async { false }
            },
        )
        .await;
        assert!(
            !ready,
            "should time out when the endpoint never becomes ready"
        );
        assert!(calls.get() >= 1, "at least one probe attempt must run");
    }

    #[tokio::test]
    async fn loop_succeeds_after_a_few_attempts() {
        let calls = Cell::new(0u64);
        let ready = run_readiness_loop(
            Duration::from_millis(1),
            Duration::from_millis(4),
            Duration::from_secs(5),
            || {
                let n = calls.get() + 1;
                calls.set(n);
                async move { n >= 3 }
            },
        )
        .await;
        assert!(ready);
        assert_eq!(calls.get(), 3, "should stop probing once ready");
    }

    #[test]
    fn backoff_ceiling_doubles_then_caps() {
        let base = Duration::from_secs(5);
        let cap = Duration::from_secs(30);
        assert_eq!(backoff_ceiling(base, cap, 0), Duration::from_secs(5)); // 5 * 1
        assert_eq!(backoff_ceiling(base, cap, 1), Duration::from_secs(10)); // 5 * 2
        assert_eq!(backoff_ceiling(base, cap, 2), Duration::from_secs(20)); // 5 * 4
        assert_eq!(backoff_ceiling(base, cap, 3), Duration::from_secs(30)); // 40 -> cap 30
        assert_eq!(backoff_ceiling(base, cap, 10), Duration::from_secs(30)); // capped
        // Must not panic on a huge attempt count (saturating shift).
        assert_eq!(
            backoff_ceiling(base, cap, u32::MAX),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn jitter_stays_within_ceiling() {
        let ceiling = Duration::from_secs(30);
        for _ in 0..1000 {
            assert!(jittered_backoff(ceiling) <= ceiling);
        }
        assert_eq!(jittered_backoff(Duration::ZERO), Duration::ZERO);
    }

    #[tokio::test]
    async fn disabled_gate_proceeds_without_probing() {
        let cfg = MediatorReadinessConfig {
            enabled: false,
            ..Default::default()
        };
        assert_eq!(
            run_gate("did:webvh:QmScid:example.com:agent", &cfg, None)
                .await
                .unwrap(),
            GateDecision::Proceed
        );
    }

    #[tokio::test]
    async fn did_key_skips_gate_and_proceeds() {
        let cfg = MediatorReadinessConfig::default();
        assert_eq!(
            run_gate("did:key:z6MkExampleKeyValue", &cfg, None)
                .await
                .unwrap(),
            GateDecision::Proceed
        );
    }
}
