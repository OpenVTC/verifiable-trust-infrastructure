//! Per-client-IP rate limiting for the VTA's unauthenticated REST surface.
//!
//! Three independent limiters, each its own per-IP bucket:
//!
//! | [`Limiter`] | Routes | Quota from `[server]` |
//! |---|---|---|
//! | `auth` | auth challenge / authenticate / refresh, passkey login, `/bootstrap/request`, TEE attestation reports | `rate_limit_interval_secs` / `rate_limit_burst` |
//! | `did-log` | public `did.jsonl` retrieval (`/.well-known/did.jsonl`, the canonical `/<path>/did.jsonl` catch-all, `/did/{did}/log`, TEE `/attestation/did-log`) | `did_log_rate_limit_interval_secs` / `did_log_rate_limit_burst` |
//! | `backup-blob` | token-gated `/backup/blob/*` | same values as `auth`, separate bucket |
//!
//! The DID-log routes have their own limiter because resolving the VTA's DID
//! is the first step of every client command — a `pnm` call resolves the DID
//! (a `did.jsonl` fetch) and then runs challenge + authenticate from the same
//! IP, and the mediator and the VTA's own readiness gate fetch the log too.
//! Sharing one budget made a handful of consecutive commands return 429 even
//! though serving the log is a store read with no crypto. The auth limiter
//! stays tight because those endpoints *do* run crypto on caller input.
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
//! ## The 429 contract
//!
//! Every 429 a limiter here produces carries:
//!
//! - `x-rate-limit-source: vta` — so a client can tell the VTA's own limiter
//!   from a mediator's, a DID host's, or a reverse proxy's 429. **Clients rely
//!   on this header name and value; do not rename either.**
//! - `x-rate-limit-scope: <auth|did-log|backup-blob>` — which limiter tripped.
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

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode, header};
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::{GovernorError, GovernorLayer};
use utoipa_axum::router::OpenApiRouter;
use vta_config::ServerConfig;

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
/// test harness, the OpenAPI spec builder).
pub(crate) const AUTH_INTERVAL_SECS: u64 = 5;
/// Default auth-limiter burst.
pub(crate) const AUTH_BURST: u32 = 10;
/// Default DID-log-limiter interval (seconds per token).
pub(crate) const DID_LOG_INTERVAL_SECS: u64 = 1;
/// Default DID-log-limiter burst.
pub(crate) const DID_LOG_BURST: u32 = 60;

/// Which limiter a route branch sits behind. Its [`name`](Self::name) is what
/// a 429 reports in [`RATE_LIMIT_SCOPE_HEADER`] and in the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limiter {
    /// Unauthenticated endpoints that run crypto on caller input.
    Auth,
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
            Limiter::DidLog => "did-log",
            Limiter::BackupBlob => "backup-blob",
        }
    }
}

/// One limiter's quota: a replenishment interval in **seconds per token** and
/// a burst size. Both are clamped to ≥1 on construction —
/// `GovernorConfigBuilder::finish` returns `None` on a zero period or burst,
/// and an operator writing `0` means "no limit", which a limiter cannot
/// express. Clamping keeps the strictest reading instead of panicking the REST
/// thread on a typo.
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
            Limiter::Auth | Limiter::BackupBlob => self.auth,
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

/// Wrap `router` in the per-IP limiter `limiter`, at the quota `limits` gives
/// it. Each call builds a fresh governor, so every branch gets its own
/// buckets — a flood on one branch cannot spend another's budget.
///
/// `trust_xff`: `false` keys on the socket peer (`PeerIpKeyExtractor`,
/// spoof-safe for direct binding); `true` honours `X-Forwarded-For`
/// (`SmartIpKeyExtractor`, only safe behind a header-sanitising proxy). The two
/// extractors instantiate `GovernorConfig` at distinct generic types, which is
/// why the branches are built separately; the returned router is uniform.
pub(super) fn apply<S>(
    router: OpenApiRouter<S>,
    limiter: Limiter,
    trust_xff: bool,
    limits: RateLimits,
) -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    let quota = limits.quota(limiter);
    let on_error = move |err: GovernorError| governor_error_response(limiter, err);
    if trust_xff {
        let cfg = Arc::new(
            GovernorConfigBuilder::default()
                .per_second(quota.interval_secs())
                .burst_size(quota.burst())
                .key_extractor(tower_governor::key_extractor::SmartIpKeyExtractor)
                .finish()
                .expect("Quota clamps interval and burst to >= 1"),
        );
        router.layer(GovernorLayer::new(cfg).error_handler(on_error))
    } else {
        let cfg = Arc::new(
            GovernorConfigBuilder::default()
                .per_second(quota.interval_secs())
                .burst_size(quota.burst())
                .key_extractor(tower_governor::key_extractor::PeerIpKeyExtractor)
                .finish()
                .expect("Quota clamps interval and burst to >= 1"),
        );
        router.layer(GovernorLayer::new(cfg).error_handler(on_error))
    }
}

/// Map a governor error to a response. Only the 429 is reshaped; the other
/// variants (key extraction failure → 500) keep tower_governor's response.
fn governor_error_response(limiter: Limiter, err: GovernorError) -> Response<Body> {
    match err {
        // tower_governor truncates the wait to whole seconds, so a 4.7 s wait
        // arrives as 4 — and a client that honoured it would be rejected
        // again. Round up instead: never early, at most one second late.
        GovernorError::TooManyRequests { wait_time, .. } => {
            too_many_requests(limiter, wait_time.saturating_add(1))
        }
        other => other.into_response().map(Body::from),
    }
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
    use axum::http::Request;
    use axum::routing::get;
    use tower::ServiceExt;

    async fn ok() -> &'static str {
        "ok"
    }

    /// Two branches, each behind its own limiter, merged into one router —
    /// the same shape `build_api_router` uses.
    fn two_branch_router(limits: RateLimits) -> axum::Router {
        let auth = apply(
            OpenApiRouter::<()>::new().route("/auth", get(ok)),
            Limiter::Auth,
            true,
            limits,
        );
        let did_log = apply(
            OpenApiRouter::<()>::new().route("/did.jsonl", get(ok)),
            Limiter::DidLog,
            true,
            limits,
        );
        let (router, _) = OpenApiRouter::<()>::new()
            .merge(auth)
            .merge(did_log)
            .split_for_parts();
        router
    }

    async fn get_status(app: &axum::Router, uri: &str, ip: &str) -> Response<Body> {
        let req = Request::builder()
            .uri(uri)
            .header("x-forwarded-for", ip)
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(req).await.unwrap()
    }

    fn tight() -> RateLimits {
        // Long intervals so no token replenishes during the test.
        RateLimits::new(Quota::new(3600, 2), Quota::new(3600, 3))
    }

    #[tokio::test]
    async fn did_log_burst_does_not_spend_auth_budget() {
        let app = two_branch_router(tight());
        for _ in 0..3 {
            let r = get_status(&app, "/did.jsonl", "198.51.100.1").await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        let r = get_status(&app, "/did.jsonl", "198.51.100.1").await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);

        // The same IP's auth budget is untouched.
        for _ in 0..2 {
            let r = get_status(&app, "/auth", "198.51.100.1").await;
            assert_eq!(
                r.status(),
                StatusCode::OK,
                "exhausting did-log must not spend the auth bucket"
            );
        }
    }

    #[tokio::test]
    async fn auth_burst_does_not_spend_did_log_budget() {
        let app = two_branch_router(tight());
        for _ in 0..2 {
            assert_eq!(
                get_status(&app, "/auth", "198.51.100.2").await.status(),
                StatusCode::OK
            );
        }
        assert_eq!(
            get_status(&app, "/auth", "198.51.100.2").await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        for _ in 0..3 {
            assert_eq!(
                get_status(&app, "/did.jsonl", "198.51.100.2")
                    .await
                    .status(),
                StatusCode::OK,
                "exhausting auth must not spend the did-log bucket"
            );
        }
    }

    #[tokio::test]
    async fn limits_are_per_ip() {
        let app = two_branch_router(tight());
        for _ in 0..2 {
            get_status(&app, "/auth", "198.51.100.3").await;
        }
        assert_eq!(
            get_status(&app, "/auth", "198.51.100.3").await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            get_status(&app, "/auth", "198.51.100.4").await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn rejection_carries_the_vta_429_contract() {
        let app = two_branch_router(tight());
        for (uri, scope, n) in [("/auth", "auth", 2), ("/did.jsonl", "did-log", 3)] {
            for _ in 0..n {
                get_status(&app, uri, "198.51.100.5").await;
            }
            let r = get_status(&app, uri, "198.51.100.5").await;
            assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
            let h = r.headers();
            assert_eq!(h[RATE_LIMIT_SOURCE_HEADER], "vta");
            assert_eq!(h[RATE_LIMIT_SCOPE_HEADER], scope);
            let retry: u64 = h[header::RETRY_AFTER].to_str().unwrap().parse().unwrap();
            assert!(retry >= 1, "retry-after must be at least 1 s, got {retry}");
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
    }

    #[test]
    fn zero_quota_is_clamped() {
        let q = Quota::new(0, 0);
        assert_eq!((q.interval_secs(), q.burst()), (1, 1));

        let server = ServerConfig {
            rate_limit_interval_secs: 0,
            rate_limit_burst: 0,
            did_log_rate_limit_interval_secs: 0,
            did_log_rate_limit_burst: 0,
            ..Default::default()
        };
        let limits = RateLimits::from_server_config(&server);
        assert_eq!(limits.quota(Limiter::DidLog), Quota::new(1, 1));
        assert_eq!(limits.quota(Limiter::Auth), Quota::new(1, 1));
        // And a limiter at a zero-configured quota builds without panicking.
        let _ = two_branch_router(limits);
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
}
