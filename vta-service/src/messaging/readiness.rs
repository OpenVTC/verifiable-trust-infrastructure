//! Startup self-readiness gate for the mediator DIDComm connection.
//!
//! During cold start a VTA can fire its outbound mediator handshake before its
//! own DID document is externally resolvable — the DID host hasn't published
//! it, or the load-balancer target fronting it isn't healthy yet. The mediator
//! authenticates us by resolving our DID itself, so it can't get the key to
//! decrypt the authcrypt auth message and returns 403; the VTA burns its short
//! retry burst and (before this gate) gave up until the next restart.
//!
//! This gate makes the VTA wait until its own DID **fully resolves over the
//! network** before initiating the mediator connection — the same operation the
//! mediator performs to fetch our sender key, so a pass here means the mediator
//! can authenticate us. Only network-resolved methods (`did:webvh`, `did:web`)
//! are gated; a `did:key` VTA resolves from its own identifier with no network
//! fetch at all, so it skips the wait.
//!
//! Resolution — not an HTTP probe of the `did.jsonl` URL — is deliberately the
//! whole check:
//!
//! - A bare 200 on `did.jsonl` doesn't imply resolvability (a 200 serving a
//!   partial or malformed log still fails resolution), so the HTTP probe was
//!   never sufficient on its own.
//! - More importantly, a direct HTTP probe tests *the VTA's own egress to the
//!   DID host*, which is the wrong path in exactly the deployment that needs
//!   this gate most: when egress is restricted to a resolver sidecar
//!   (`resolver_url`), the VTA cannot reach the DID host directly at all, so
//!   the probe could never return 200 and the gate would always time out.
//!   Resolving through the configured resolver exercises the real path.
//!
//! The gate is bounded: it retries with capped exponential backoff and full
//! jitter (the AWS "Exponential Backoff And Jitter" scheme) up to a maximum
//! wait, then applies a configured timeout policy (skip / proceed / fail). The
//! jitter keeps a fleet of VTAs from probing in lock-step. It is also
//! cancellable — a shutdown signal mid-wait abandons the gate immediately
//! rather than holding the process open for the rest of the horizon. See
//! [`vta_config::MediatorReadinessConfig`].

use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
use rand::RngExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use vta_config::{MediatorReadinessConfig, ReadinessTimeoutPolicy};

/// DID method prefixes whose resolution requires a network fetch, and whose
/// document therefore has to be published before a mediator can authenticate
/// us. Anything else (`did:key`, `did:peer`, `did:jwk`, or a method we don't
/// recognise) is not gated — `did:key` and friends resolve straight from the
/// identifier, and an unrecognised method must not have DIDComm withheld from
/// it on the strength of a probe we can't reason about.
const NETWORK_RESOLVED_METHODS: &[&str] = &["did:webvh:", "did:web:"];

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
    /// The DID that would not resolve.
    pub vta_did: String,
    /// Where its document is expected to be published, when we can derive it —
    /// the single most useful thing for an operator to go check.
    pub endpoint: Option<String>,
    pub waited_secs: u64,
}

impl std::fmt::Display for ReadinessTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "own DID {} did not resolve over the network after {}s",
            self.vta_did, self.waited_secs
        )?;
        if let Some(endpoint) = &self.endpoint {
            write!(f, " (expected its document at {endpoint})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ReadinessTimeout {}

/// `true` when `vta_did`'s method needs a network fetch to resolve, so the
/// document must be published before the mediator can authenticate us.
pub fn needs_network_probe(vta_did: &str) -> bool {
    NETWORK_RESOLVED_METHODS
        .iter()
        .any(|prefix| vta_did.starts_with(prefix))
}

/// Where `vta_did`'s document is expected to be published, for **operator
/// diagnostics only** — never fetched. `None` when we can't derive it (a
/// non-`webvh` method, an unparseable DID, or a build without the `webvh`
/// feature).
pub fn self_did_endpoint_hint(vta_did: &str) -> Option<String> {
    #[cfg(feature = "webvh")]
    if vta_did.starts_with("did:webvh:") {
        return match didwebvh_rs::url::WebVHURL::parse_did_url(vta_did) {
            Ok(webvh) => match webvh.get_http_url(None) {
                Ok(url) => Some(url.to_string()),
                Err(e) => {
                    debug!(vta_did, error = %e, "self-readiness: cannot derive did.jsonl URL");
                    None
                }
            },
            Err(e) => {
                debug!(vta_did, error = %e, "self-readiness: cannot parse did:webvh DID");
                None
            }
        };
    }

    let _ = vta_did;
    None
}

/// Run the self-readiness gate for `vta_did` and return the caller's decision.
///
/// Returns `Ok(Proceed)` when the DID resolved, when its method needs no
/// network fetch (e.g. `did:key`), or when the gate is disabled. Returns
/// `Ok(Skip)` on timeout under the `skip` policy, and on cancellation. Returns
/// `Err(ReadinessTimeout)` only on timeout under the `fail` policy.
pub async fn run_gate(
    vta_did: &str,
    cfg: &MediatorReadinessConfig,
    resolver_url: Option<&str>,
    shutdown: &CancellationToken,
) -> Result<GateDecision, ReadinessTimeout> {
    if !cfg.enabled {
        info!("mediator self-readiness gate disabled; connecting without waiting");
        return Ok(GateDecision::Proceed);
    }

    if !needs_network_probe(vta_did) {
        info!(
            vta_did,
            "self-readiness gate skipped: DID method resolves without a network fetch"
        );
        return Ok(GateDecision::Proceed);
    }

    let base = Duration::from_secs(cfg.retry_secs.max(1));
    // Cap can never be below the base, else backoff couldn't grow.
    let cap = Duration::from_secs(cfg.backoff_cap_secs.max(cfg.retry_secs.max(1)));
    let max_wait = Duration::from_secs(cfg.max_wait_secs);
    let endpoint = self_did_endpoint_hint(vta_did);
    info!(
        vta_did,
        endpoint = endpoint.as_deref().unwrap_or("<unknown>"),
        base_secs = base.as_secs(),
        backoff_cap_secs = cap.as_secs(),
        max_wait_secs = cfg.max_wait_secs,
        "waiting for own DID to resolve over the network before mediator connect \
         (exponential backoff + full jitter)"
    );

    let did = vta_did.to_string();
    let resolver_url = resolver_url.map(str::to_string);
    let outcome = run_readiness_loop(base, cap, max_wait, shutdown, move || {
        let did = did.clone();
        let resolver_url = resolver_url.clone();
        async move { self_did_resolves(&did, resolver_url.as_deref()).await }
    })
    .await;

    match outcome {
        LoopOutcome::Ready => {
            info!(
                vta_did,
                "own DID resolves over the network; proceeding to mediator connect"
            );
            Ok(GateDecision::Proceed)
        }
        LoopOutcome::Cancelled => {
            info!("shutdown during self-readiness wait; not starting DIDComm");
            Ok(GateDecision::Skip)
        }
        LoopOutcome::TimedOut => apply_timeout_policy(
            cfg.on_timeout,
            vta_did,
            endpoint.as_deref(),
            cfg.max_wait_secs,
        ),
    }
}

/// Map a timed-out gate to the caller decision per the configured policy.
/// Extracted so the policy mapping is unit-testable without any network I/O.
fn apply_timeout_policy(
    policy: ReadinessTimeoutPolicy,
    vta_did: &str,
    endpoint: Option<&str>,
    waited_secs: u64,
) -> Result<GateDecision, ReadinessTimeout> {
    match policy {
        ReadinessTimeoutPolicy::Proceed => {
            warn!(
                vta_did,
                waited_secs,
                "self-readiness gate timed out; connecting to mediator anyway (best-effort)"
            );
            Ok(GateDecision::Proceed)
        }
        ReadinessTimeoutPolicy::Skip => {
            warn!(
                vta_did,
                waited_secs,
                "self-readiness gate timed out; skipping DIDComm startup this boot \
                 (/health stays live; a later restart reconnects)"
            );
            Ok(GateDecision::Skip)
        }
        ReadinessTimeoutPolicy::Fail => Err(ReadinessTimeout {
            vta_did: vta_did.to_string(),
            endpoint: endpoint.map(str::to_string),
            waited_secs,
        }),
    }
}

/// `true` iff `vta_did` fully resolves over the network right now.
///
/// Builds a **throwaway** [`DIDCacheClient`] per call — network mode against
/// the configured `resolver_url` when set, local mode otherwise — so it
/// resolves the VTA the same way the mediator does, while a preloaded self-DID
/// entry (see `server::preload_self_did_document`) or a stale entry in the
/// long-lived resolver can't mask the real state.
async fn self_did_resolves(vta_did: &str, resolver_url: Option<&str>) -> bool {
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

    let resolved = resolver.resolve(vta_did).await;

    // MUST stop before dropping. In network mode `DIDCacheClient::new` spawns a
    // supervised task holding a websocket to the resolver sidecar that
    // reconnects on its own timer, and the SDK has no `Drop` impl — dropping the
    // client abandons the task rather than ending it. Since this probe runs
    // before *every* connect attempt and the reconnect horizon is unbounded by
    // default, skipping this leaks one task + one reconnecting socket per
    // attempt for the life of the process.
    resolver.stop();

    match resolved {
        Ok(_) => true,
        Err(e) => {
            debug!(error = %e, "self-readiness: self-DID resolution not yet succeeding");
            false
        }
    }
}

/// Single-shot: can the VTA resolve its own DID over the network right now?
///
/// The persistent-reconnect supervisor calls this before every mediator connect
/// attempt, so a cold VTA never storms the mediator with unresolvable-sender
/// auth attempts while it can't even resolve itself. Methods that resolve
/// without a network fetch (`did:key`) are always considered ready.
pub async fn self_did_network_resolvable(vta_did: &str, resolver_url: Option<&str>) -> bool {
    if !needs_network_probe(vta_did) {
        return true;
    }
    self_did_resolves(vta_did, resolver_url).await
}

/// Why [`run_readiness_loop`] stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopOutcome {
    /// The probe returned `true`.
    Ready,
    /// `max_wait` elapsed with the probe still returning `false`.
    TimedOut,
    /// Shutdown was signalled while waiting.
    Cancelled,
}

/// Poll `probe` until it returns `true`, `max_wait` elapses, or `shutdown` is
/// cancelled. Between attempts it waits a capped-exponential-backoff-with-full-
/// jitter interval: attempt `n` (0-based) sleeps a uniform random duration in
/// `[0, min(cap, base * 2^n)]`, always clamped so it never overshoots the
/// deadline. At least one probe attempt always runs (even with
/// `max_wait == 0`). Pure of any concrete I/O so it can be driven by an
/// injected probe in tests.
async fn run_readiness_loop<F, Fut>(
    base: Duration,
    cap: Duration,
    max_wait: Duration,
    shutdown: &CancellationToken,
    mut probe: F,
) -> LoopOutcome
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + max_wait;
    let mut attempt: u32 = 0;
    loop {
        if probe().await {
            return LoopOutcome::Ready;
        }
        if shutdown.is_cancelled() {
            return LoopOutcome::Cancelled;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return LoopOutcome::TimedOut;
        }
        let ceiling = backoff_ceiling(base, cap, attempt);
        // Full jitter, then clamp to the remaining time so we don't overshoot.
        let sleep_for = jittered_backoff(ceiling).min(deadline - now);
        debug!(
            attempt = attempt + 1,
            ceiling_secs = ceiling.as_secs_f64(),
            sleep_secs = sleep_for.as_secs_f64(),
            "self-readiness probe not ready; backing off before retry"
        );
        // Cancellable: a SIGTERM during the wait must not hold the process open
        // for the remainder of the (up to `max_wait_secs`) horizon.
        tokio::select! {
            _ = shutdown.cancelled() => return LoopOutcome::Cancelled,
            _ = tokio::time::sleep(sleep_for) => {}
        }
        attempt = attempt.saturating_add(1);
    }
}

/// A mediator session must last at least this long before it counts as
/// "healthy" and resets the reconnect backoff.
///
/// Without this floor, a connect that succeeds and then immediately drops resets
/// the backoff to its base every time, turning a flapping mediator into a
/// reconnect storm at full rate — which is how the SDK's own
/// reset-backoff-on-connect produced the dual-websocket churn storm this
/// workspace already had to chase down. A session shorter than the floor is
/// treated as a failed attempt and keeps escalating the backoff.
pub(crate) const MIN_HEALTHY_SESSION: Duration = Duration::from_secs(60);

/// Retry policy for the mediator connect/reconnect loop.
///
/// Extracted from `server::MessagingConnect` so the decisions — keep trying or
/// give up, and how long to wait — are unit-testable without a mediator, an
/// `AppState`, or any I/O. The supervisor owns the effects; this owns the
/// arithmetic.
#[derive(Debug, Clone)]
pub(crate) struct ReconnectPolicy {
    base: Duration,
    cap: Duration,
    /// `None` = never give up.
    horizon: Option<Duration>,
    reconnect: bool,
}

impl ReconnectPolicy {
    pub(crate) fn from_config(cfg: &MediatorReadinessConfig) -> Self {
        let base_secs = cfg.retry_secs.max(1);
        Self {
            base: Duration::from_secs(base_secs),
            // Cap can never be below the base, else backoff couldn't grow.
            cap: Duration::from_secs(cfg.reconnect_backoff_cap_secs.max(base_secs)),
            // 0 = never give up (retry forever at the capped, jittered interval).
            horizon: (cfg.reconnect_max_elapsed_secs > 0)
                .then(|| Duration::from_secs(cfg.reconnect_max_elapsed_secs)),
            reconnect: cfg.reconnect,
        }
    }

    /// How long to wait before retry number `attempt` (0-based), or `None` to
    /// stop retrying — because reconnect is disabled, or `failing_for` has
    /// exhausted the configured horizon.
    ///
    /// `failing_for` is the length of the *current run of failures*, not the
    /// process lifetime: the supervisor resets it after any healthy session.
    pub(crate) fn next_backoff(&self, attempt: u32, failing_for: Duration) -> Option<Duration> {
        if !self.reconnect {
            return None;
        }
        if let Some(horizon) = self.horizon
            && failing_for >= horizon
        {
            return None;
        }
        Some(jittered_backoff(backoff_ceiling(
            self.base, self.cap, attempt,
        )))
    }

    /// The un-jittered upper bound this policy would use for `attempt`. Exposed
    /// for logging so an operator sees the schedule, not just the sampled wait.
    pub(crate) fn ceiling_for(&self, attempt: u32) -> Duration {
        backoff_ceiling(self.base, self.cap, attempt)
    }

    /// Whether a session that lasted `session` counts as healthy — long enough
    /// to reset both the backoff escalation and the horizon window.
    pub(crate) fn session_was_healthy(&self, session: Duration) -> bool {
        session >= MIN_HEALTHY_SESSION
    }
}

/// Upper bound on the backoff interval for a 0-based `attempt`:
/// `min(cap, base * 2^attempt)`. Saturating — never panics on overflow.
fn backoff_ceiling(base: Duration, cap: Duration, attempt: u32) -> Duration {
    let factor = 1u64.checked_shl(attempt).unwrap_or(u64::MAX); // 2^attempt, saturating
    let ceil_ms = base
        .as_millis()
        .saturating_mul(factor as u128)
        .min(cap.as_millis());
    Duration::from_millis(ceil_ms as u64)
}

/// Full jitter (AWS blog): a uniform random duration in `[0, ceiling]`.
fn jittered_backoff(ceiling: Duration) -> Duration {
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
    fn did_key_needs_no_network_probe() {
        assert!(!needs_network_probe("did:key:z6MkExampleKeyValue"));
    }

    #[test]
    fn webvh_and_web_need_a_network_probe() {
        assert!(needs_network_probe("did:webvh:QmScid:example.com:agent"));
        assert!(needs_network_probe("did:web:example.com:agent"));
    }

    #[test]
    fn unknown_method_is_not_gated() {
        // An unrecognised method must not have DIDComm withheld from it on the
        // strength of a probe we can't reason about.
        assert!(!needs_network_probe("did:peer:2zSomething"));
        assert!(!needs_network_probe("did:example:whatever"));
    }

    #[cfg(feature = "webvh")]
    #[test]
    fn webvh_endpoint_hint_is_derived_for_diagnostics() {
        let did = "did:webvh:QmExampleScid:example.com:budget-engine";
        assert_eq!(
            self_did_endpoint_hint(did).as_deref(),
            Some("https://example.com/budget-engine/did.jsonl")
        );
    }

    #[test]
    fn no_endpoint_hint_for_did_key() {
        assert!(self_did_endpoint_hint("did:key:z6MkExampleKeyValue").is_none());
    }

    #[test]
    fn timeout_policy_maps_to_decision() {
        let did = "did:webvh:QmScid:example.com:agent";
        assert_eq!(
            apply_timeout_policy(ReadinessTimeoutPolicy::Skip, did, None, 30).unwrap(),
            GateDecision::Skip
        );
        assert_eq!(
            apply_timeout_policy(ReadinessTimeoutPolicy::Proceed, did, None, 30).unwrap(),
            GateDecision::Proceed
        );
        assert!(apply_timeout_policy(ReadinessTimeoutPolicy::Fail, did, None, 30).is_err());
    }

    #[test]
    fn timeout_error_names_the_endpoint_when_known() {
        let err = apply_timeout_policy(
            ReadinessTimeoutPolicy::Fail,
            "did:webvh:QmScid:example.com:agent",
            Some("https://example.com/agent/did.jsonl"),
            300,
        )
        .expect_err("fail policy errors");
        let msg = err.to_string();
        assert!(msg.contains("did:webvh:QmScid:example.com:agent"), "{msg}");
        assert!(msg.contains("https://example.com/agent/did.jsonl"), "{msg}");
        assert!(msg.contains("300s"), "{msg}");
    }

    #[tokio::test]
    async fn loop_times_out_when_never_ready() {
        let calls = Cell::new(0u64);
        let outcome = run_readiness_loop(
            Duration::from_millis(2),
            Duration::from_millis(8),
            Duration::from_millis(20),
            &CancellationToken::new(),
            || {
                calls.set(calls.get() + 1);
                async { false }
            },
        )
        .await;
        assert_eq!(outcome, LoopOutcome::TimedOut);
        assert!(calls.get() >= 1, "at least one probe attempt must run");
    }

    #[tokio::test]
    async fn loop_succeeds_after_a_few_attempts() {
        let calls = Cell::new(0u64);
        let outcome = run_readiness_loop(
            Duration::from_millis(1),
            Duration::from_millis(4),
            Duration::from_secs(5),
            &CancellationToken::new(),
            || {
                let n = calls.get() + 1;
                calls.set(n);
                async move { n >= 3 }
            },
        )
        .await;
        assert_eq!(outcome, LoopOutcome::Ready);
        assert_eq!(calls.get(), 3, "should stop probing once ready");
    }

    #[tokio::test]
    async fn loop_abandons_the_wait_on_shutdown() {
        // A cancelled token must cut the wait short rather than burn the whole
        // (here: 60s) horizon — otherwise a SIGTERM mid-gate holds the process
        // open with no listener.
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let calls = Cell::new(0u64);
        let started = tokio::time::Instant::now();
        let outcome = run_readiness_loop(
            Duration::from_secs(5),
            Duration::from_secs(30),
            Duration::from_secs(60),
            &shutdown,
            || {
                calls.set(calls.get() + 1);
                async { false }
            },
        )
        .await;
        assert_eq!(outcome, LoopOutcome::Cancelled);
        assert_eq!(calls.get(), 1, "one probe runs, then cancellation wins");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "cancellation must not wait out the horizon"
        );
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

    // ── ReconnectPolicy: the supervisor's give-up / keep-trying decisions ────

    #[test]
    fn policy_retries_forever_by_default() {
        let policy = ReconnectPolicy::from_config(&MediatorReadinessConfig::default());
        // Default `reconnect_max_elapsed_secs = 0` means no horizon at all, so
        // even an absurd failure run still yields a wait rather than giving up.
        assert!(policy.next_backoff(0, Duration::from_secs(0)).is_some());
        assert!(
            policy
                .next_backoff(99, Duration::from_secs(86_400 * 365))
                .is_some(),
            "0 horizon must mean never give up"
        );
    }

    #[test]
    fn policy_with_reconnect_disabled_never_retries() {
        let policy = ReconnectPolicy::from_config(&MediatorReadinessConfig {
            reconnect: false,
            ..Default::default()
        });
        assert!(
            policy.next_backoff(0, Duration::ZERO).is_none(),
            "reconnect = false must preserve legacy single-shot behaviour"
        );
    }

    #[test]
    fn policy_gives_up_once_the_horizon_is_exhausted() {
        let policy = ReconnectPolicy::from_config(&MediatorReadinessConfig {
            reconnect_max_elapsed_secs: 120,
            ..Default::default()
        });
        assert!(policy.next_backoff(3, Duration::from_secs(119)).is_some());
        assert!(
            policy.next_backoff(3, Duration::from_secs(120)).is_none(),
            "at the horizon exactly, stop"
        );
        assert!(policy.next_backoff(3, Duration::from_secs(600)).is_none());
    }

    #[test]
    fn policy_backoff_is_bounded_by_the_reconnect_cap() {
        let policy = ReconnectPolicy::from_config(&MediatorReadinessConfig {
            retry_secs: 5,
            reconnect_backoff_cap_secs: 60,
            ..Default::default()
        });
        assert_eq!(policy.ceiling_for(0), Duration::from_secs(5));
        assert_eq!(policy.ceiling_for(4), Duration::from_secs(60)); // 80 -> cap
        for attempt in 0..40 {
            let waited = policy
                .next_backoff(attempt, Duration::ZERO)
                .expect("no horizon set");
            assert!(
                waited <= Duration::from_secs(60),
                "attempt {attempt} slept {waited:?}, past the cap"
            );
        }
    }

    #[test]
    fn policy_cap_below_base_still_grows() {
        // A misconfigured cap under the base would otherwise pin the backoff at
        // the (smaller) cap and defeat the escalation entirely.
        let policy = ReconnectPolicy::from_config(&MediatorReadinessConfig {
            retry_secs: 30,
            reconnect_backoff_cap_secs: 5,
            ..Default::default()
        });
        assert_eq!(policy.ceiling_for(0), Duration::from_secs(30));
    }

    #[test]
    fn only_a_long_enough_session_counts_as_healthy() {
        let policy = ReconnectPolicy::from_config(&MediatorReadinessConfig::default());
        // A connect that succeeds and instantly drops must NOT reset the
        // backoff — that is what turns a flapping mediator into a storm.
        assert!(!policy.session_was_healthy(Duration::from_secs(1)));
        assert!(!policy.session_was_healthy(MIN_HEALTHY_SESSION - Duration::from_secs(1)));
        assert!(policy.session_was_healthy(MIN_HEALTHY_SESSION));
        assert!(policy.session_was_healthy(Duration::from_secs(3600)));
    }

    #[tokio::test]
    async fn disabled_gate_proceeds_without_probing() {
        let cfg = MediatorReadinessConfig {
            enabled: false,
            ..Default::default()
        };
        assert_eq!(
            run_gate(
                "did:webvh:QmScid:example.com:agent",
                &cfg,
                None,
                &CancellationToken::new()
            )
            .await
            .unwrap(),
            GateDecision::Proceed
        );
    }

    #[tokio::test]
    async fn did_key_skips_gate_and_proceeds() {
        let cfg = MediatorReadinessConfig::default();
        assert_eq!(
            run_gate(
                "did:key:z6MkExampleKeyValue",
                &cfg,
                None,
                &CancellationToken::new()
            )
            .await
            .unwrap(),
            GateDecision::Proceed
        );
    }
}
