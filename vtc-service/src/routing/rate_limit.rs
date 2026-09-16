//! The one shape every VTC rate-limit refusal takes.
//!
//! An operator whose request crosses a VTA, a mediator, a DID host and this
//! VTC used to receive a bare `429` and had to guess which of them sent it.
//! The ecosystem contract answers that on the response itself. Every `429` a
//! service's *own* limiter emits carries:
//!
//! - `x-rate-limit-source: <service>` — `vtc` here (`vta`, `mediator`,
//!   `did-host` elsewhere);
//! - `Retry-After: <seconds>`, never `0`;
//! - an `application/json` body
//!   `{"error":"rate_limited","limiter":"<name>","message":"…","retryAfterSecs":N}`,
//!   where `limiter` names which of the service's limiters refused.
//!
//! A `429` without the source header therefore did not come from this
//! service's limiters — it came from something in front of it. The client
//! side of the contract is `vta_sdk::rate_limit`, which reads a refusal
//! from here as `RateLimitSource::Vtc`.
//!
//! The VTC's limiters, and the name each one reports:
//!
//! | limiter                | name              | keyed on            |
//! |------------------------|-------------------|---------------------|
//! | `tower-governor` on the unauthenticated chain ([`crate::routes`]) | [`UNAUTH_LIMITER`] | source IP |
//! | per-member publish window ([`crate::relationships::rate_limit`]) | [`RELATIONSHIPS_LIMITER`] | HMAC of the signer DID |
//!
//! Both are HTTP-only: the Trust Task framework (`trust_tasks_rs::StandardCode`)
//! defines no rate-limit error code, and neither limiter sits on the DIDComm or
//! TSP dispatch path, so no Trust Task error document ever reports one.

use axum::Json;
use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tower_governor::GovernorError;
use vta_sdk::rate_limit::SOURCE_HEADER;

/// Header naming the service whose limiter refused the request. The name is
/// the SDK's, so the server and the parser that reads it cannot drift apart.
pub const RATE_LIMIT_SOURCE_HEADER: HeaderName = HeaderName::from_static(SOURCE_HEADER);

/// This service's value for [`RATE_LIMIT_SOURCE_HEADER`].
pub const RATE_LIMIT_SOURCE: &str = "vtc";

/// The `error` member of every rate-limit body.
pub const RATE_LIMITED_ERROR: &str = "rate_limited";

/// The per-IP `tower-governor` in front of the unauthenticated routes.
pub const UNAUTH_LIMITER: &str = "unauth";

/// The per-member relationship publish window.
pub const RELATIONSHIPS_LIMITER: &str = "relationships";

/// The JSON body of a rate-limit refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitedBody {
    /// Always `rate_limited`.
    pub error: String,
    /// Which of this service's limiters refused the request.
    pub limiter: String,
    /// Operator-readable explanation.
    pub message: String,
    /// Seconds to wait before retrying; the same value as `Retry-After`.
    pub retry_after_secs: u64,
}

/// A refusal by one of this service's limiters, rendered per the contract
/// above.
#[derive(Debug, Clone)]
pub struct RateLimited {
    limiter: &'static str,
    retry_after_secs: u64,
    message: String,
}

impl RateLimited {
    /// `retry_after_secs` is raised to at least 1: a limiter that has just
    /// refused is not ready again "now", and `Retry-After: 0` invites exactly
    /// the immediate retry that was refused.
    #[must_use]
    pub fn new(limiter: &'static str, retry_after_secs: u64, message: impl Into<String>) -> Self {
        Self {
            limiter,
            retry_after_secs: retry_after_secs.max(1),
            message: message.into(),
        }
    }

    #[must_use]
    pub fn limiter(&self) -> &'static str {
        self.limiter
    }

    #[must_use]
    pub fn retry_after_secs(&self) -> u64 {
        self.retry_after_secs
    }
}

impl IntoResponse for RateLimited {
    fn into_response(self) -> Response {
        let retry_after = self.retry_after_secs;
        let body = RateLimitedBody {
            error: RATE_LIMITED_ERROR.to_string(),
            limiter: self.limiter.to_string(),
            message: self.message,
            retry_after_secs: retry_after,
        };
        let mut res = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
        let headers = res.headers_mut();
        headers.insert(
            RATE_LIMIT_SOURCE_HEADER,
            HeaderValue::from_static(RATE_LIMIT_SOURCE),
        );
        headers.insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
        res
    }
}

/// `tower-governor` error handler for the unauthenticated chain.
///
/// Only the rate-limit refusal is reshaped. Key-extraction failures keep the
/// governor's own response: they are a deployment fault (no peer address, no
/// forwarding header), not a limit, and dressing them as a `429` would send an
/// operator looking at the wrong thing.
pub fn governor_error_response(err: GovernorError) -> Response<Body> {
    match err {
        GovernorError::TooManyRequests { wait_time, headers } => {
            let limited = RateLimited::new(
                UNAUTH_LIMITER,
                wait_time,
                "too many unauthenticated requests from this address; wait for \
                 the Retry-After period before retrying",
            );
            let mut res = limited.into_response();
            // Keep the governor's informational `x-ratelimit-*` headers, but
            // never let one displace a contract header set above.
            if let Some(extra) = headers {
                for (name, value) in &extra {
                    if !res.headers().contains_key(name) {
                        res.headers_mut().insert(name.clone(), value.clone());
                    }
                }
            }
            res
        }
        other => other.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use http_body_util::BodyExt;

    async fn json(res: Response) -> serde_json::Value {
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn a_refusal_carries_the_source_retry_after_and_body() {
        let res = RateLimited::new(RELATIONSHIPS_LIMITER, 17, "slow down").into_response();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(res.headers()[SOURCE_HEADER], "vtc");
        assert_eq!(res.headers()[header::RETRY_AFTER], "17");
        assert_eq!(res.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(
            json(res).await,
            serde_json::json!({
                "error": "rate_limited",
                "limiter": "relationships",
                "message": "slow down",
                "retryAfterSecs": 17,
            })
        );
    }

    #[tokio::test]
    async fn retry_after_is_never_zero() {
        let res = RateLimited::new(UNAUTH_LIMITER, 0, "x").into_response();
        assert_eq!(res.headers()[header::RETRY_AFTER], "1");
        assert_eq!(json(res).await["retryAfterSecs"], 1);
    }

    #[tokio::test]
    async fn governor_refusal_is_reshaped_and_keeps_its_informational_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-after", 4.into());
        headers.insert("retry-after", 4.into());
        let res = governor_error_response(GovernorError::TooManyRequests {
            wait_time: 4,
            headers: Some(headers),
        });
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(res.headers()[SOURCE_HEADER], "vtc");
        assert_eq!(res.headers()[header::RETRY_AFTER], "4");
        assert_eq!(res.headers()["x-ratelimit-after"], "4");
        assert_eq!(res.headers()[header::CONTENT_TYPE], "application/json");
        let body = json(res).await;
        assert_eq!(body["error"], "rate_limited");
        assert_eq!(body["limiter"], "unauth");
        assert_eq!(body["retryAfterSecs"], 4);
    }

    /// The SDK's parser reads this service's refusal back as the VTC's, with
    /// the limiter name and wait hint intact. If either side of the contract
    /// moves, this fails.
    #[tokio::test]
    async fn the_sdk_parser_attributes_a_refusal_to_the_vtc() {
        use vta_sdk::error::VtaError;
        use vta_sdk::rate_limit::RateLimitSource;

        let res = RateLimited::new(RELATIONSHIPS_LIMITER, 30, "slow down").into_response();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        let before = chrono::Utc::now();

        let err = VtaError::rate_limited_from_http(
            status,
            &headers,
            &body,
            "https://vtc.example.com/v1/relationships",
        )
        .expect("a 429 parses as a rate limit");
        match err {
            VtaError::RateLimited {
                limited_by,
                retry_after,
                limiter,
                url,
            } => {
                assert_eq!(limited_by, RateLimitSource::Vtc);
                assert_eq!(limiter.as_deref(), Some("relationships"));
                let wait = retry_after.expect("Retry-After is read") - before;
                assert!((29..=31).contains(&wait.num_seconds()), "wait {wait}");
                assert_eq!(
                    url.as_deref(),
                    Some("https://vtc.example.com/v1/relationships")
                );
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_key_extraction_failure_is_not_dressed_as_a_rate_limit() {
        let res = governor_error_response(GovernorError::UnableToExtractKey);
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!res.headers().contains_key(SOURCE_HEADER));
    }
}
