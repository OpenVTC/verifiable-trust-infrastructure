//! Browser security-header middleware (Phase 5 M5.3.2).
//!
//! Attached to the admin UX + website sub-routers — both surfaces
//! serve HTML/JS to a browser. The API sub-router does **not** get
//! these headers; it's a JSON wire surface for programmatic clients
//! and CSP is meaningless there.
//!
//! Headers attached:
//!
//! - `X-Content-Type-Options: nosniff` — refuses browser MIME
//!   sniffing. Always on.
//! - `X-Frame-Options: DENY` — legacy clickjacking guard. Paired
//!   with `frame-ancestors 'none'` in the CSP below for browsers
//!   that don't honour XFO.
//! - `Referrer-Policy: no-referrer` — passkey-login URLs and the
//!   install-claim ceremony shouldn't leak via outbound `Referer`.
//! - `Strict-Transport-Security` — not here: [`strict_transport_security`]
//!   attaches it to every response when the community's `public_url` is
//!   `https` (#2661). The request cannot say: the daemon serves plain HTTP
//!   behind a TLS-terminating proxy, and an origin-form HTTP/1.1 request
//!   carries no scheme, so a check of `request.uri().scheme_str()` was
//!   never true and HSTS was never sent.
//! - `Content-Security-Policy` — default policy below. Spec §12.1
//!   lets operators relax this per-site for SPA needs once the
//!   website handler (M5.4) reads a `.vtc-website.toml` override.
//!   `font-src 'self' data:` accommodates the @fontsource-variable
//!   subsets that Vite inlines under its 4 KiB asset threshold;
//!   `style-src 'unsafe-inline'` covers React's `style={{...}}`
//!   prop usage. Neither widens the attack surface beyond what a
//!   typical SPA already accepts. `frame-ancestors 'none'` blocks
//!   framing of the admin UX + install ceremony — phishing sites
//!   can't embed `/admin/install?token=…` in an iframe to trick
//!   operators into completing the claim against a wrong RP.
//!
//! When the response already carries one of these headers (e.g. a
//! handler wants a stricter `Cache-Control: no-store` and bundled
//! its own CSP), the middleware **does not overwrite** — it only
//! fills in missing headers.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::header::{
    CONTENT_SECURITY_POLICY, HeaderName, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::middleware::Next;
use axum::response::Response;

/// Default CSP attached to admin UX + website responses. The
/// `frame-ancestors 'none'` directive is the modern replacement for
/// `X-Frame-Options: DENY`; both ship together because IE/legacy
/// only honours XFO.
pub const DEFAULT_CSP: &str = "default-src 'self'; \
     script-src 'self'; \
     style-src 'self' 'unsafe-inline'; \
     font-src 'self' data:; \
     img-src 'self' data:; \
     object-src 'none'; \
     base-uri 'self'; \
     frame-ancestors 'none'";

/// HSTS — two-year max-age, includeSubDomains.
const HSTS_VALUE: &str = "max-age=63072000; includeSubDomains";

/// Whether this community is served over HTTPS, read once from its
/// `public_url` — the origin its operator declared and browsers reach.
/// Browsers ignore `Strict-Transport-Security` received over plain HTTP
/// (RFC 6797 §8.1), so sending it on every response of an `https` community is
/// safe even where a request reached the daemon unencrypted from its proxy; an
/// `http` (or absent) `public_url` — a local or staging deployment — gets none,
/// so no browser is left with sticky upgrade state for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HstsPolicy {
    enabled: bool,
}

impl HstsPolicy {
    /// The policy for a community whose public origin is `public_url`.
    pub fn from_public_url(public_url: Option<&str>) -> Self {
        // The scheme is case-insensitive (RFC 3986 §3.1).
        let enabled = public_url
            .and_then(|u| u.trim().get(..8))
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"));
        Self { enabled }
    }

    /// Whether `Strict-Transport-Security` is sent.
    pub fn enabled(self) -> bool {
        self.enabled
    }
}

/// Tower middleware attaching `Strict-Transport-Security` to every response
/// when [`HstsPolicy::enabled`] (#2661). Wire via
/// `axum::middleware::from_fn_with_state(policy, strict_transport_security)`
/// outside the router, so console, portal, website and API responses alike
/// carry it. A response that already set the header keeps its own.
pub async fn strict_transport_security(
    axum::extract::State(policy): axum::extract::State<HstsPolicy>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    if policy.enabled && !response.headers().contains_key(STRICT_TRANSPORT_SECURITY) {
        response.headers_mut().insert(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(HSTS_VALUE),
        );
    }
    response
}

/// Tower middleware function. Wire via
/// `axum::middleware::from_fn(security_headers)` on the admin UX
/// and website sub-routers.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    if !headers.contains_key(X_CONTENT_TYPE_OPTIONS) {
        headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    }
    if !headers.contains_key(X_FRAME_OPTIONS) {
        headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    }
    if !headers.contains_key(REFERRER_POLICY) {
        headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    }
    // `Permissions-Policy` is non-canonical in the `http` crate header
    // map, so we build the name manually. Refuse every default-on
    // browser capability — the admin UX never needs camera, mic, USB,
    // payments, geolocation, etc.
    let permissions_policy: HeaderName = HeaderName::from_static("permissions-policy");
    if !headers.contains_key(&permissions_policy) {
        headers.insert(
            permissions_policy,
            HeaderValue::from_static(
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
                 magnetometer=(), microphone=(), payment=(), usb=()",
            ),
        );
    }
    if !headers.contains_key(CONTENT_SECURITY_POLICY) {
        // `from_static` is safe — `DEFAULT_CSP` is ASCII.
        headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(DEFAULT_CSP),
        );
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt;

    async fn hsts_of(public_url: Option<&str>) -> Option<String> {
        let policy = HstsPolicy::from_public_url(public_url);
        let app = Router::new().route("/", get(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(policy, strict_transport_security),
        );
        // An origin-form request, as a TLS-terminating proxy forwards it: no
        // scheme in the request line.
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        resp.headers()
            .get(STRICT_TRANSPORT_SECURITY)
            .map(|v| v.to_str().unwrap().to_string())
    }

    /// #2661: an `https` community sends HSTS though the request reaching the
    /// daemon names no scheme.
    #[tokio::test]
    async fn issue_2661_an_https_public_url_sends_hsts_on_an_origin_form_request() {
        assert_eq!(
            hsts_of(Some("https://vtc.example.com")).await.as_deref(),
            Some(HSTS_VALUE)
        );
    }

    #[tokio::test]
    async fn an_http_or_absent_public_url_sends_no_hsts() {
        assert_eq!(hsts_of(Some("http://localhost:8200")).await, None);
        assert_eq!(hsts_of(None).await, None);
        assert_eq!(hsts_of(Some("not a url")).await, None);
    }
}
