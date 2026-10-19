//! Per-client-IP rate limiting for the VTA's unauthenticated REST surface.
//!
//! Five independent limiters, each its own per-IP bucket:
//!
//! | [`Limiter`] | Routes | Quota from `[server]` |
//! |---|---|---|
//! | `auth` | auth challenge, passkey login, `/bootstrap/request`, TEE attestation reports | `rate_limit_interval_secs` / `rate_limit_burst` |
//! | `auth-authenticate` | `auth/authenticate` | same values as `auth`, separate bucket |
//! | `auth-refresh` | `auth/refresh` | same values as `auth`, separate bucket |
//! | `did-log` | public `did.jsonl` retrieval (`/.well-known/did.jsonl`, the canonical `/<path>/did.jsonl` catch-all, `/did/{did}/log`, TEE `/attestation/did-log`) | `did_log_rate_limit_interval_secs` / `did_log_rate_limit_burst` |
//! | `backup-blob` | token-gated `/backup/blob/*` | same values as `auth`, separate bucket |
//!
//! The DID-log routes have their own limiter because resolving the VTA's DID
//! is the first step of every client command — a `pnm` call resolves the DID
//! (a `did.jsonl` fetch) and then runs challenge + authenticate from the same
//! IP, and the mediator and the VTA's own readiness gate fetch the log too.
//! Sharing one budget made a handful of consecutive commands return 429 even
//! though serving the log is a store read with no crypto. The auth limiter
//! stays tight because those endpoints *do* run crypto on caller input. The
//! steps of a login draw on separate buckets for the reason given on
//! [`apply_trust_tasks`].
//!
//! Authenticated (JWT-gated) routes are not rate-limited — the token is the
//! gate — and neither is DIDComm / TSP traffic, which never reaches this
//! router.
//!
//! ## Units
//!
//! **An interval is seconds per token, not a rate.** `(5, 10)` is 10
//! back-to-back requests, then one every 5 s. A *bigger* interval is a
//! *tighter* limit.
//!
//! ## Runtime tuning
//!
//! The quotas are read from the live configuration
//! (`AppState::config`), not captured when the router is built. Each limiter
//! compares the configured quota with the one its buckets were built for on
//! every request; when they differ it swaps in a fresh keyed limiter at the new
//! quota. So a `config/patch` of any of the four keys (`pnm config update
//! --rate-limit-burst …`) takes effect on the next request, with no restart.
//!
//! **A swap resets that limiter's bucket state**: every client IP starts again
//! from a full burst at the new quota. That is deliberate — carrying token
//! counts across two different quotas has no meaning — and harmless, since
//! only a super-admin can trigger it. A patch that leaves a limiter's quota
//! unchanged (including a patch of an unrelated key) keeps its buckets.
//!
//! `trust_xff_cidrs` is not runtime-tunable: it selects the key extractor when
//! the router is built, and changes on restart.
//!
//! ## The 429 contract
//!
//! Every 429 a limiter here produces carries:
//!
//! - `x-rate-limit-source: vta` — so a client can tell the VTA's own limiter
//!   from a mediator's, a DID host's, or a reverse proxy's 429. **Clients rely
//!   on this header name and value; do not rename either.**
//! - `x-rate-limit-scope: <auth|auth-authenticate|auth-refresh|did-log|backup-blob>`
//!   — which limiter tripped.
//! - `retry-after: <seconds>` (and the legacy `x-ratelimit-after`, same value).
//! - an `application/json` body, with no configuration values or other
//!   internal detail:
//!
//!   ```json
//!   {"error":"rate_limited","limiter":"did-log",
//!    "message":"Too Many Requests: rejected by the VTA's `did-log` rate limiter. Retry after 3 s.",
//!    "retryAfterSecs":3}
//!   ```
//!
//!   `vta_sdk::rate_limit` reads `limiter` from it; the header set is the
//!   primary signal and the body names the limiter for a human too.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Response, StatusCode, header};
use axum::middleware::Next;
use axum::response::IntoResponse;
use governor::clock::{Clock, DefaultClock};
use governor::{DefaultKeyedRateLimiter, RateLimiter};
use ipnetwork::IpNetwork;
use tokio::sync::RwLock;
use tower_governor::key_extractor::KeyExtractor;
use utoipa_axum::router::OpenApiRouter;
use vta_config::{AppConfig, ServerConfig};
use vti_common::rate_limit::TrustedProxyKeyExtractor;

/// Response header naming who produced a 429. Always `vta` here.
///
/// A client-side contract, so the name is `vta_sdk::rate_limit`'s — the module
/// the SDK reads it with — rather than a second literal that could drift.
pub const RATE_LIMIT_SOURCE_HEADER: &str = vta_sdk::rate_limit::SOURCE_HEADER;

/// Value of [`RATE_LIMIT_SOURCE_HEADER`] on every 429 the VTA itself emits.
/// `vta_sdk::rate_limit::RateLimitSource::from_source_header` maps it to
/// `RateLimitSource::Vta`; a test below holds the two together.
pub const RATE_LIMIT_SOURCE_VTA: &str = "vta";

/// Response header naming which VTA limiter produced a 429 — the
/// [`Limiter::name`] of the tripped limiter.
pub const RATE_LIMIT_SCOPE_HEADER: &str = "x-rate-limit-scope";

/// Legacy header `tower_governor` has always set alongside `retry-after`.
/// Kept, with the same value, so existing clients that read it keep working.
const LEGACY_RATE_LIMIT_AFTER_HEADER: &str = vta_sdk::rate_limit::LEGACY_RETRY_AFTER_HEADER;

/// Default auth-limiter interval (seconds per token). Mirrors
/// `vta_config::ServerConfig::default()`; used by callers with no config (the
/// OpenAPI spec builder).
pub(crate) const AUTH_INTERVAL_SECS: u64 = 5;
/// Default auth-limiter burst.
pub(crate) const AUTH_BURST: u32 = 10;
/// Default DID-log-limiter interval (seconds per token).
pub(crate) const DID_LOG_INTERVAL_SECS: u64 = 1;
/// Default DID-log-limiter burst.
pub(crate) const DID_LOG_BURST: u32 = 60;

/// Largest interval (seconds per token) the runtime `config/patch` accepts.
/// One token an hour is already a limiter that has effectively closed; past
/// that a value is far more likely a typo than an intent.
pub const MAX_INTERVAL_SECS: u64 = 3600;

/// Largest burst the runtime `config/patch` accepts. Far above any legitimate
/// per-IP burst against these endpoints, low enough that a stray extra digit
/// is refused rather than quietly turning the limiter off.
pub const MAX_BURST: u32 = 10_000;

/// Which limiter a route branch sits behind. Its [`name`](Self::name) is what
/// a 429 reports in [`RATE_LIMIT_SCOPE_HEADER`] and in the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Limiter {
    /// Unauthenticated endpoints that run crypto on caller input.
    Auth,
    /// `auth/authenticate`, at the `auth` quota in a bucket of its own, so
    /// that issuing challenges cannot spend the budget needed to redeem them.
    AuthAuthenticate,
    /// `auth/refresh`, at the `auth` quota in a bucket of its own, so that a
    /// host's refreshing sessions and its new logins do not starve each other.
    AuthRefresh,
    /// Public `did.jsonl` retrieval.
    DidLog,
    /// Token-gated backup blob upload / download.
    BackupBlob,
}

impl Limiter {
    /// Stable, operator-facing name of the limiter.
    pub const fn name(self) -> &'static str {
        match self {
            Limiter::Auth => "auth",
            Limiter::AuthAuthenticate => "auth-authenticate",
            Limiter::AuthRefresh => "auth-refresh",
            Limiter::DidLog => "did-log",
            Limiter::BackupBlob => "backup-blob",
        }
    }
}

/// One limiter's quota: a replenishment interval in **seconds per token** and
/// a burst size. Both are clamped to ≥1 on construction — a zero period or
/// burst has no token-bucket meaning, and an operator writing `0` means "no
/// limit", which a limiter cannot express. Clamping keeps the strictest
/// reading instead of panicking the REST thread on a typo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    interval_secs: u64,
    burst: u32,
}

impl Quota {
    /// Build a quota, clamping both values to ≥1.
    pub fn new(interval_secs: u64, burst: u32) -> Self {
        Self {
            interval_secs: interval_secs.max(1),
            burst: burst.max(1),
        }
    }

    /// Seconds per replenished token (≥1).
    pub fn interval_secs(self) -> u64 {
        self.interval_secs
    }

    /// Burst size (≥1).
    pub fn burst(self) -> u32 {
        self.burst
    }

    fn to_governor(self) -> governor::Quota {
        governor::Quota::with_period(Duration::from_secs(self.interval_secs))
            .expect("interval is clamped to >= 1 s, so the period is non-zero")
            .allow_burst(NonZeroU32::new(self.burst).expect("burst is clamped to >= 1"))
    }
}

/// The quotas for every limiter on the router. The backup-blob limiter uses
/// the auth quota (in its own bucket).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimits {
    auth: Quota,
    did_log: Quota,
}

impl RateLimits {
    /// Build from explicit quotas.
    pub fn new(auth: Quota, did_log: Quota) -> Self {
        Self { auth, did_log }
    }

    /// Read the four `[server]` keys.
    pub fn from_server_config(server: &ServerConfig) -> Self {
        Self::new(
            Quota::new(server.rate_limit_interval_secs, server.rate_limit_burst),
            Quota::new(
                server.did_log_rate_limit_interval_secs,
                server.did_log_rate_limit_burst,
            ),
        )
    }

    /// The quota a given limiter enforces.
    pub fn quota(self, limiter: Limiter) -> Quota {
        match limiter {
            Limiter::Auth
            | Limiter::AuthAuthenticate
            | Limiter::AuthRefresh
            | Limiter::BackupBlob => self.auth,
            Limiter::DidLog => self.did_log,
        }
    }
}

impl Default for RateLimits {
    fn default() -> Self {
        Self::new(
            Quota::new(AUTH_INTERVAL_SECS, AUTH_BURST),
            Quota::new(DID_LOG_INTERVAL_SECS, DID_LOG_BURST),
        )
    }
}

/// Where the limiters read their quotas from.
#[derive(Clone)]
pub enum QuotaSource {
    /// The live configuration: `[server]` is re-read on every request, so a
    /// runtime `config/patch` applies without a restart. What the running
    /// service uses.
    Live(Arc<RwLock<AppConfig>>),
    /// Fixed quotas, for callers with no configuration (the OpenAPI spec
    /// builder, [`super::router`]).
    Fixed(RateLimits),
}

impl QuotaSource {
    async fn current(&self, limiter: Limiter) -> Quota {
        match self {
            QuotaSource::Live(config) => {
                RateLimits::from_server_config(&config.read().await.server).quota(limiter)
            }
            QuotaSource::Fixed(limits) => limits.quota(limiter),
        }
    }
}

/// A keyed limiter at one quota.
struct Buckets {
    quota: Quota,
    limiter: DefaultKeyedRateLimiter<IpAddr>,
}

impl Buckets {
    fn new(quota: Quota) -> Arc<Self> {
        Arc::new(Self {
            quota,
            limiter: RateLimiter::keyed(quota.to_governor()),
        })
    }
}

/// One limiter instance: its name, how it keys clients, where its quota comes
/// from, and the buckets for the quota currently in force.
struct LimiterState {
    limiter: Limiter,
    extractor: TrustedProxyKeyExtractor,
    source: QuotaSource,
    /// Held only for a pointer clone or swap — never across an await.
    buckets: StdRwLock<Arc<Buckets>>,
}

impl LimiterState {
    fn new(limiter: Limiter, trust_xff_cidrs: &[IpNetwork], source: &QuotaSource) -> Self {
        // Seed the buckets at the default quota; the first request compares
        // against the configured quota and swaps if they differ, before any
        // client has been charged.
        let initial = match source {
            QuotaSource::Fixed(limits) => limits.quota(limiter),
            QuotaSource::Live(_) => RateLimits::default().quota(limiter),
        };
        Self {
            limiter,
            extractor: TrustedProxyKeyExtractor::new(trust_xff_cidrs.to_vec()),
            source: source.clone(),
            buckets: StdRwLock::new(Buckets::new(initial)),
        }
    }

    /// The buckets for `quota`, swapping in fresh ones if the quota changed
    /// since they were built. See the module docs: a swap resets bucket state.
    fn buckets_for(&self, quota: Quota) -> Arc<Buckets> {
        {
            let current = self.buckets.read().unwrap_or_else(|e| e.into_inner());
            if current.quota == quota {
                return Arc::clone(&current);
            }
        }
        let mut current = self.buckets.write().unwrap_or_else(|e| e.into_inner());
        // Re-check under the write lock: a concurrent request may have swapped
        // already, and swapping twice would reset the buckets twice.
        if current.quota != quota {
            tracing::info!(
                limiter = self.limiter.name(),
                interval_secs = quota.interval_secs(),
                burst = quota.burst(),
                "rate limit quota changed; limiter buckets reset"
            );
            *current = Buckets::new(quota);
        }
        Arc::clone(&current)
    }

    fn client_ip(&self, req: &Request) -> Option<IpAddr> {
        self.extractor.extract(req).ok()
    }
}

/// Wrap `router` in the per-IP limiter `limiter`, reading its quota from
/// `source`. Each call creates its own buckets, so every branch is
/// independent — a flood on one branch cannot spend another's budget.
pub(super) fn apply<S>(
    router: OpenApiRouter<S>,
    limiter: Limiter,
    trust_xff_cidrs: &[IpNetwork],
    source: &QuotaSource,
) -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    let state = Arc::new(LimiterState::new(limiter, trust_xff_cidrs, source));
    router.layer(axum::middleware::from_fn_with_state(state, enforce))
}

/// The `/trust-tasks` limiter: charges only requests that present **no**
/// credential (`vti_common::auth::presents_credential`), each to the bucket
/// for what it asks for — `auth/authenticate` to [`Limiter::AuthAuthenticate`],
/// `auth/refresh` to [`Limiter::AuthRefresh`], everything else (a challenge,
/// a public task) to [`Limiter::Auth`]. Authenticated callers stay off the
/// limiter: their credential is the gate.
///
/// The credential test is the extractor's own, so a request cannot dodge the
/// limiter with a junk header and still be served anonymously: what this lets
/// through uncharged is either authenticated or refused by the extractor.
///
/// Why per step: a login is a challenge then an authenticate, and with one
/// bucket every token that refilled went to whichever request arrived first.
/// Behind one IP, new challenges took each token and every authenticate was
/// refused, so no login finished. The step is read from the document's
/// `type`, not from the client-chosen `Trust-Task` header, so a bucket bounds
/// exactly the work it is named for — sending challenges labelled as
/// authenticates does not buy more of them.
///
/// The header still matters for cost: a labelled request is charged to the
/// step it names *before* its body is read, so a client over budget is refused
/// without the server reading up to 64 KiB of it. If the document turns out to
/// be another step, that step's bucket is charged too. An unlabelled request
/// is read (within the anonymous ceiling) and then charged.
pub(super) fn apply_trust_tasks<S>(
    router: OpenApiRouter<S>,
    trust_xff_cidrs: &[IpNetwork],
    source: &QuotaSource,
) -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    let state = Arc::new(TrustTaskLimiters {
        auth: LimiterState::new(Limiter::Auth, trust_xff_cidrs, source),
        authenticate: LimiterState::new(Limiter::AuthAuthenticate, trust_xff_cidrs, source),
        refresh: LimiterState::new(Limiter::AuthRefresh, trust_xff_cidrs, source),
    });
    router.layer(axum::middleware::from_fn_with_state(
        state,
        enforce_trust_tasks,
    ))
}

struct TrustTaskLimiters {
    auth: LimiterState,
    authenticate: LimiterState,
    refresh: LimiterState,
}

impl TrustTaskLimiters {
    fn for_type(&self, type_uri: Option<&str>) -> &LimiterState {
        use vta_sdk::trust_tasks::{
            TASK_AUTH_AUTHENTICATE_0_2, TASK_AUTH_AUTHENTICATE_0_3, TASK_AUTH_REFRESH_0_2,
        };
        match type_uri {
            Some(t) if t == TASK_AUTH_AUTHENTICATE_0_2 || t == TASK_AUTH_AUTHENTICATE_0_3 => {
                &self.authenticate
            }
            Some(t) if t == TASK_AUTH_REFRESH_0_2 => &self.refresh,
            _ => &self.auth,
        }
    }
}

async fn enforce_trust_tasks(
    State(limiters): State<Arc<TrustTaskLimiters>>,
    req: Request,
    next: Next,
) -> Response<Body> {
    if vti_common::auth::extractor::presents_credential(req.headers()) {
        return next.run(req).await;
    }
    let limit = crate::trust_tasks::PUBLIC_TASK_BODY_LIMIT;

    // A request that names its step in the `Trust-Task` header is charged for
    // that step before its body is read, so a client already over budget is
    // turned away for the price of a header, not a body read. The label is
    // only the client's claim: the document's `type` decides below.
    let labelled = req
        .headers()
        .get(TRUST_TASK_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|t| limiters.for_type(Some(t)));
    if let Some(state) = labelled
        && let Some(refused) = refusal(state, state.client_ip(&req)).await
    {
        return refused;
    }

    // Reading the body to find its `type` is bounded by the ceiling the
    // handler applies to every anonymous request anyway. A larger one —
    // declared, or found while reading — is charged as a challenge would be
    // (unless its label already paid) and refused here.
    let declared_too_large = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > limit as u64);
    let (parts, body) = req.into_parts();
    let bytes = if declared_too_large {
        None
    } else {
        axum::body::to_bytes(body, limit).await.ok()
    };
    let Some(bytes) = bytes else {
        let refused = Request::from_parts(parts, Body::empty());
        if labelled.is_none()
            && let Some(limited) = refusal(&limiters.auth, limiters.auth.client_ip(&refused)).await
        {
            return limited;
        }
        return vti_common::error::AppError::Validation(format!(
            "an anonymous request is limited to {limit} bytes"
        ))
        .into_response();
    };

    let type_uri = crate::trust_tasks::ceremony::peek_type_uri(&bytes);
    let actual = limiters.for_type(type_uri.as_deref());
    let req = Request::from_parts(parts, Body::from(bytes));
    // A label that named another step paid for the wrong bucket: the request
    // pays for the step it really is as well, so mislabelling buys nothing.
    if labelled.map(|l| l.limiter) != Some(actual.limiter)
        && let Some(limited) = refusal(actual, actual.client_ip(&req)).await
    {
        return limited;
    }
    next.run(req).await
}

/// The Trust Task URI header (`Trust-Task`) a client may send beside the
/// document. The VTA dispatches on the document's `type`; this limiter reads
/// the header only to charge a labelled request before reading its body.
const TRUST_TASK_HEADER: &str = "trust-task";

async fn enforce(
    State(state): State<Arc<LimiterState>>,
    req: Request,
    next: Next,
) -> Response<Body> {
    charge(&state, req, |req| next.run(req)).await
}

/// Charge `req`'s client one token from `state`'s bucket and run `serve` on
/// it, or answer 429 without running it.
async fn charge<F, Fut>(state: &LimiterState, req: Request, serve: F) -> Response<Body>
where
    F: FnOnce(Request) -> Fut,
    Fut: std::future::Future<Output = Response<Body>>,
{
    match refusal(state, state.client_ip(&req)).await {
        None => serve(req).await,
        Some(refused) => refused,
    }
}

/// Charge client `ip` (from [`LimiterState::client_ip`]) one token from
/// `state`'s bucket: `None` if it was charged, or the response that refuses
/// it. Takes the address rather than the request, which is not `Sync` and so
/// cannot be borrowed across the quota lookup's await.
async fn refusal(state: &LimiterState, ip: Option<IpAddr>) -> Option<Response<Body>> {
    let Some(ip) = ip else {
        // Same outcome as the tower_governor layer this replaced: no
        // attributable client means no request, not an unlimited one.
        return Some(
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Unable To Extract Key!"))
                .expect("static response always builds"),
        );
    };
    let quota = state.source.current(state.limiter).await;
    let buckets = state.buckets_for(quota);
    let not_until = buckets.limiter.check_key(&ip).err()?;
    let wait = not_until.wait_time_from(DefaultClock::default().now());
    Some(too_many_requests(state.limiter, ceil_secs(wait)))
}

/// Whole seconds, rounded up: a client honouring `retry-after` must never be
/// told to come back before a token is actually available.
fn ceil_secs(d: Duration) -> u64 {
    d.as_secs() + u64::from(d.subsec_nanos() > 0)
}

/// The VTA's 429: see the module docs for the contract. `retry_after_secs` is
/// clamped to ≥1 so a client never busy-loops on `retry-after: 0`.
pub(crate) fn too_many_requests(limiter: Limiter, retry_after_secs: u64) -> Response<Body> {
    let retry_after = retry_after_secs.max(1);
    let body = serde_json::json!({
        "error": "rate_limited",
        "limiter": limiter.name(),
        "message": format!(
            "Too Many Requests: rejected by the VTA's `{}` rate limiter. Retry after {retry_after} s.",
            limiter.name()
        ),
        "retryAfterSecs": retry_after,
    })
    .to_string();
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::RETRY_AFTER, HeaderValue::from(retry_after))
        .header(
            LEGACY_RATE_LIMIT_AFTER_HEADER,
            HeaderValue::from(retry_after),
        )
        .header(RATE_LIMIT_SOURCE_HEADER, RATE_LIMIT_SOURCE_VTA)
        .header(RATE_LIMIT_SCOPE_HEADER, limiter.name())
        .body(Body::from(body))
        .expect("static header names and numeric values always build")
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::to_bytes;
    use axum::http::Request as HttpRequest;
    use axum::routing::get;
    use tower::ServiceExt;

    async fn ok() -> &'static str {
        "ok"
    }

    fn trusted_loopback() -> Vec<IpNetwork> {
        vec!["127.0.0.1/32".parse().unwrap()]
    }

    /// Two branches, each behind its own limiter, merged into one router —
    /// the same shape `build_api_router` uses.
    fn two_branch_router(source: QuotaSource) -> axum::Router {
        let auth = apply(
            OpenApiRouter::<()>::new().route("/auth", get(ok)),
            Limiter::Auth,
            &trusted_loopback(),
            &source,
        );
        let did_log = apply(
            OpenApiRouter::<()>::new().route("/did.jsonl", get(ok)),
            Limiter::DidLog,
            &trusted_loopback(),
            &source,
        );
        let (router, _) = OpenApiRouter::<()>::new()
            .merge(auth)
            .merge(did_log)
            .split_for_parts();
        router.layer(axum::middleware::from_fn(
            vti_common::rate_limit::insert_default_connect_info_if_missing,
        ))
    }

    async fn get_from(app: &axum::Router, uri: &str, ip: &str) -> Response<Body> {
        let req = HttpRequest::builder()
            .uri(uri)
            .header("x-forwarded-for", ip)
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(req).await.unwrap()
    }

    /// Long intervals so no token replenishes during a test.
    fn tight() -> RateLimits {
        RateLimits::new(Quota::new(3600, 2), Quota::new(3600, 3))
    }

    fn live_config(limits: (u64, u32, u64, u32)) -> Arc<RwLock<AppConfig>> {
        let mut config = crate::test_support::test_app_config("unused".into());
        config.server.rate_limit_interval_secs = limits.0;
        config.server.rate_limit_burst = limits.1;
        config.server.did_log_rate_limit_interval_secs = limits.2;
        config.server.did_log_rate_limit_burst = limits.3;
        Arc::new(RwLock::new(config))
    }

    /// How many back-to-back requests pass before the first 429.
    async fn admitted(app: &axum::Router, uri: &str, ip: &str, cap: usize) -> usize {
        for i in 0..cap {
            if get_from(app, uri, ip).await.status() == StatusCode::TOO_MANY_REQUESTS {
                return i;
            }
        }
        cap
    }

    #[tokio::test]
    async fn did_log_burst_does_not_spend_auth_budget() {
        let app = two_branch_router(QuotaSource::Fixed(tight()));
        assert_eq!(admitted(&app, "/did.jsonl", "198.51.100.1", 10).await, 3);
        assert_eq!(
            admitted(&app, "/auth", "198.51.100.1", 10).await,
            2,
            "exhausting did-log must not spend the auth bucket"
        );
    }

    #[tokio::test]
    async fn auth_burst_does_not_spend_did_log_budget() {
        let app = two_branch_router(QuotaSource::Fixed(tight()));
        assert_eq!(admitted(&app, "/auth", "198.51.100.2", 10).await, 2);
        assert_eq!(
            admitted(&app, "/did.jsonl", "198.51.100.2", 10).await,
            3,
            "exhausting auth must not spend the did-log bucket"
        );
    }

    #[tokio::test]
    async fn limits_are_per_ip() {
        let app = two_branch_router(QuotaSource::Fixed(tight()));
        assert_eq!(admitted(&app, "/auth", "198.51.100.3", 10).await, 2);
        assert_eq!(
            get_from(&app, "/auth", "198.51.100.4").await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn rejection_carries_the_vta_429_contract() {
        let app = two_branch_router(QuotaSource::Fixed(tight()));
        for (uri, scope, n) in [("/auth", "auth", 2), ("/did.jsonl", "did-log", 3)] {
            for _ in 0..n {
                get_from(&app, uri, "198.51.100.5").await;
            }
            let r = get_from(&app, uri, "198.51.100.5").await;
            assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
            let h = r.headers();
            assert_eq!(h[RATE_LIMIT_SOURCE_HEADER], "vta");
            assert_eq!(h[RATE_LIMIT_SCOPE_HEADER], scope);
            let retry: u64 = h[header::RETRY_AFTER].to_str().unwrap().parse().unwrap();
            assert!(
                (1..=3600).contains(&retry),
                "retry-after must be within one interval, got {retry}"
            );
            assert_eq!(h[LEGACY_RATE_LIMIT_AFTER_HEADER], h[header::RETRY_AFTER]);
            assert_eq!(h[header::CONTENT_TYPE], "application/json");
            let body = to_bytes(r.into_body(), usize::MAX).await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            // Exactly this and nothing more: the VTA, the limiter, the wait.
            // No burst size or other configuration detail.
            assert_eq!(
                body,
                serde_json::json!({
                    "error": "rate_limited",
                    "limiter": scope,
                    "message": format!(
                        "Too Many Requests: rejected by the VTA's `{scope}` rate limiter. \
                         Retry after {retry} s."
                    ),
                    "retryAfterSecs": retry,
                })
            );
        }
    }

    #[tokio::test]
    async fn live_quota_change_applies_without_rebuilding_the_router() {
        let config = live_config((3600, 2, 3600, 3));
        let app = two_branch_router(QuotaSource::Live(Arc::clone(&config)));
        assert_eq!(admitted(&app, "/auth", "198.51.100.6", 20).await, 2);

        // Loosen the auth burst in the shared config — what `config/patch`
        // does — and the same router admits the new burst.
        config.write().await.server.rate_limit_burst = 5;
        assert_eq!(
            admitted(&app, "/auth", "198.51.100.6", 20).await,
            5,
            "a quota change swaps in fresh buckets at the new burst"
        );

        // Tighten it again: applies just the same.
        config.write().await.server.rate_limit_burst = 1;
        assert_eq!(admitted(&app, "/auth", "198.51.100.6", 20).await, 1);

        // The did-log limiter was untouched throughout.
        assert_eq!(admitted(&app, "/did.jsonl", "198.51.100.6", 20).await, 3);
    }

    #[tokio::test]
    async fn unrelated_config_change_keeps_bucket_state() {
        let config = live_config((3600, 2, 3600, 3));
        let app = two_branch_router(QuotaSource::Live(Arc::clone(&config)));
        assert_eq!(admitted(&app, "/auth", "198.51.100.7", 20).await, 2);

        // A patch of another key — or of the other limiter's quota — must not
        // hand this limiter's clients a fresh burst.
        {
            let mut c = config.write().await;
            c.vta_name = Some("renamed".into());
            c.server.did_log_rate_limit_burst = 50;
        }
        assert_eq!(
            get_from(&app, "/auth", "198.51.100.7").await.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "auth buckets must survive a change that leaves the auth quota alone"
        );
    }

    #[tokio::test]
    async fn live_source_honours_configured_quota_from_the_first_request() {
        // Seeded at the defaults (burst 10); the configured burst of 1 must
        // apply before any client is charged.
        let config = live_config((3600, 1, 3600, 1));
        let app = two_branch_router(QuotaSource::Live(config));
        assert_eq!(admitted(&app, "/auth", "198.51.100.8", 20).await, 1);
    }

    /// A request with no `ConnectInfo` has no un-spoofable anchor, so it must
    /// be refused rather than charged to a placeholder. Asserted on **both**
    /// attribution modes: the trusted-CIDR mode is the one that matters, since
    /// a placeholder peer inside a trusted CIDR would let the request name its
    /// own bucket through `x-forwarded-for`.
    #[tokio::test]
    async fn no_attributable_client_is_refused_not_unlimited() {
        for cidrs in [vec![], trusted_loopback()] {
            let router = apply(
                OpenApiRouter::<()>::new().route("/auth", get(ok)),
                Limiter::Auth,
                &cidrs,
                &QuotaSource::Fixed(RateLimits::default()),
            );
            let (app, _) = router.split_for_parts();
            let resp = get_from(&app, "/auth", "198.51.100.9").await;
            assert_eq!(
                resp.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "cidrs={cidrs:?}"
            );
        }
    }

    #[test]
    fn ceil_secs_rounds_up() {
        assert_eq!(ceil_secs(Duration::from_secs(4)), 4);
        assert_eq!(ceil_secs(Duration::from_millis(4001)), 5);
        assert_eq!(ceil_secs(Duration::from_millis(1)), 1);
        assert_eq!(ceil_secs(Duration::ZERO), 0);
    }

    /// The server's label and the SDK's reading of it are one contract.
    #[test]
    fn source_label_is_what_the_sdk_reads_as_vta() {
        use vta_sdk::rate_limit::RateLimitSource;
        assert_eq!(
            RateLimitSource::from_source_header(Some(RATE_LIMIT_SOURCE_VTA)),
            RateLimitSource::Vta
        );
        assert_eq!(RATE_LIMIT_SOURCE_HEADER, "x-rate-limit-source");
    }

    #[test]
    fn scope_names_are_stable() {
        assert_eq!(Limiter::Auth.name(), "auth");
        assert_eq!(Limiter::DidLog.name(), "did-log");
        assert_eq!(Limiter::BackupBlob.name(), "backup-blob");
        assert_eq!(Limiter::AuthAuthenticate.name(), "auth-authenticate");
        assert_eq!(Limiter::AuthRefresh.name(), "auth-refresh");
    }

    #[test]
    fn zero_quota_is_clamped() {
        let q = Quota::new(0, 0);
        assert_eq!((q.interval_secs(), q.burst()), (1, 1));

        let server = {
            let mut c = ServerConfig::default();
            c.rate_limit_interval_secs = 0;
            c.rate_limit_burst = 0;
            c.did_log_rate_limit_interval_secs = 0;
            c.did_log_rate_limit_burst = 0;
            c
        };
        let limits = RateLimits::from_server_config(&server);
        assert_eq!(limits.quota(Limiter::DidLog), Quota::new(1, 1));
        assert_eq!(limits.quota(Limiter::Auth), Quota::new(1, 1));
        // And a limiter at a zero-configured quota builds without panicking.
        let _ = two_branch_router(QuotaSource::Fixed(limits));
    }

    #[test]
    fn defaults_match_server_config_defaults() {
        assert_eq!(
            RateLimits::default(),
            RateLimits::from_server_config(&ServerConfig::default()),
            "the no-config defaults must match vta-config's [server] defaults"
        );
    }

    #[test]
    fn backup_blob_uses_the_auth_quota() {
        let limits = tight();
        assert_eq!(
            limits.quota(Limiter::BackupBlob),
            limits.quota(Limiter::Auth)
        );
    }

    #[test]
    fn the_auth_steps_use_the_auth_quota() {
        let limits = tight();
        for step in [Limiter::AuthAuthenticate, Limiter::AuthRefresh] {
            assert_eq!(limits.quota(step), limits.quota(Limiter::Auth));
        }
    }

    // ── /trust-tasks: one bucket per pre-session step ───────────────

    use vta_sdk::trust_tasks::{
        TASK_AUTH_AUTHENTICATE_0_2, TASK_AUTH_AUTHENTICATE_0_3, TASK_AUTH_CHALLENGE_0_1,
        TASK_AUTH_REFRESH_0_2,
    };

    fn trust_tasks_router() -> axum::Router {
        let (router, _) = apply_trust_tasks(
            OpenApiRouter::<()>::new().route("/trust-tasks", axum::routing::post(ok)),
            &trusted_loopback(),
            &QuotaSource::Fixed(tight()),
        )
        .split_for_parts();
        router.layer(axum::middleware::from_fn(
            vti_common::rate_limit::insert_default_connect_info_if_missing,
        ))
    }

    fn task_request(type_uri: &str, ip: &str) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method("POST")
            .uri("/trust-tasks")
            .header("x-forwarded-for", ip)
            .body(Body::from(
                serde_json::json!({ "type": type_uri, "payload": {} }).to_string(),
            ))
            .unwrap()
    }

    async fn send(app: &axum::Router, req: HttpRequest<Body>) -> Response<Body> {
        app.clone().oneshot(req).await.unwrap()
    }

    /// The livelock: with challenges and authenticates in one bucket, behind
    /// one IP every refilled token went to a new challenge and no login ever
    /// finished. Spent challenges must leave authenticate and refresh whole.
    #[tokio::test]
    async fn spent_challenges_leave_authenticate_and_refresh_budgets_whole() {
        let app = trust_tasks_router();
        let ip = "198.51.100.20";
        for _ in 0..2 {
            let r = send(&app, task_request(TASK_AUTH_CHALLENGE_0_1, ip)).await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        let refused = send(&app, task_request(TASK_AUTH_CHALLENGE_0_1, ip)).await;
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(refused.headers()[RATE_LIMIT_SCOPE_HEADER], "auth");

        for type_uri in [
            TASK_AUTH_AUTHENTICATE_0_2,
            TASK_AUTH_AUTHENTICATE_0_3,
            TASK_AUTH_REFRESH_0_2,
        ] {
            let r = send(&app, task_request(type_uri, ip)).await;
            assert_eq!(r.status(), StatusCode::OK, "{type_uri} has its own budget");
        }
        // Both authenticate versions share one bucket: its burst is now spent.
        let r = send(&app, task_request(TASK_AUTH_AUTHENTICATE_0_2, ip)).await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(r.headers()[RATE_LIMIT_SCOPE_HEADER], "auth-authenticate");
    }

    /// The bucket follows the document's `type`, not the client-chosen
    /// `Trust-Task` header — or a caller could label challenges as
    /// authenticates and draw on both budgets.
    #[tokio::test]
    async fn the_step_is_read_from_the_document_not_the_header() {
        let app = trust_tasks_router();
        let ip = "198.51.100.21";
        let mut statuses = Vec::new();
        for _ in 0..3 {
            let mut req = task_request(TASK_AUTH_CHALLENGE_0_1, ip);
            req.headers_mut().insert(
                "trust-task",
                HeaderValue::from_static(TASK_AUTH_AUTHENTICATE_0_2),
            );
            let r = send(&app, req).await;
            statuses.push(r.status());
        }
        assert_eq!(
            statuses,
            [
                StatusCode::OK,
                StatusCode::OK,
                StatusCode::TOO_MANY_REQUESTS
            ]
        );
    }

    #[tokio::test]
    async fn an_oversized_anonymous_body_is_charged_and_refused() {
        let app = trust_tasks_router();
        let ip = "198.51.100.22";
        let big = vec![b' '; crate::trust_tasks::PUBLIC_TASK_BODY_LIMIT + 1];
        let oversized = || {
            HttpRequest::builder()
                .method("POST")
                .uri("/trust-tasks")
                .header("x-forwarded-for", ip)
                .body(Body::from(big.clone()))
                .unwrap()
        };
        assert_eq!(
            send(&app, oversized()).await.status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(&app, oversized()).await.status(),
            StatusCode::BAD_REQUEST
        );
        let r = send(&app, oversized()).await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(r.headers()[RATE_LIMIT_SCOPE_HEADER], "auth");
    }

    /// A labelled request over its step's budget is refused before its body
    /// is read: the body here fails if polled, which would answer 400.
    #[tokio::test]
    async fn a_labelled_request_over_budget_is_refused_without_reading_its_body() {
        let app = trust_tasks_router();
        let ip = "198.51.100.24";
        for _ in 0..2 {
            let mut req = task_request(TASK_AUTH_AUTHENTICATE_0_2, ip);
            req.headers_mut().insert(
                "trust-task",
                HeaderValue::from_static(TASK_AUTH_AUTHENTICATE_0_2),
            );
            assert_eq!(send(&app, req).await.status(), StatusCode::OK);
        }
        let unreadable = Body::from_stream(futures_util::stream::once(async {
            Err::<axum::body::Bytes, _>(std::io::Error::other("body must not be read"))
        }));
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/trust-tasks")
            .header("x-forwarded-for", ip)
            .header("trust-task", TASK_AUTH_AUTHENTICATE_0_2)
            .body(unreadable)
            .unwrap();
        let r = send(&app, req).await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(r.headers()[RATE_LIMIT_SCOPE_HEADER], "auth-authenticate");
    }

    /// A body that declares itself over the anonymous ceiling is refused
    /// without being read: this one never ends, so reading it would hang.
    #[tokio::test]
    async fn a_declared_oversized_body_is_refused_without_reading_it() {
        let app = trust_tasks_router();
        let endless = Body::from_stream(futures_util::stream::pending::<
            Result<axum::body::Bytes, std::io::Error>,
        >());
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/trust-tasks")
            .header("x-forwarded-for", "198.51.100.25")
            .header(
                header::CONTENT_LENGTH,
                (crate::trust_tasks::PUBLIC_TASK_BODY_LIMIT + 1).to_string(),
            )
            .body(endless)
            .unwrap();
        let r = tokio::time::timeout(Duration::from_secs(5), send(&app, req))
            .await
            .expect("refused without reading the body");
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_credentialed_request_is_not_charged() {
        let app = trust_tasks_router();
        for _ in 0..5 {
            let mut req = task_request(TASK_AUTH_CHALLENGE_0_1, "198.51.100.23");
            req.headers_mut().insert(
                header::AUTHORIZATION,
                HeaderValue::from_static("Bearer some.jwt.value"),
            );
            assert_eq!(send(&app, req).await.status(), StatusCode::OK);
        }
    }
}
