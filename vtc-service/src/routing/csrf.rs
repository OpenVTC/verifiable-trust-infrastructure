//! CSRF protection for admin mutating endpoints (Phase 5 M5.2.2).
//!
//! Tower middleware enforces one of two checks on every
//! `POST` / `PUT` / `PATCH` / `DELETE` request to the API surface:
//!
//! 1. **`Sec-Fetch-Site: same-origin`** — modern browsers stamp
//!    this header on fetches initiated from the same origin as the
//!    receiving server. Non-browser clients (cnm-cli, programmatic
//!    SDK consumers, DIDComm bridges) don't set it, so the second
//!    check carries them.
//!
//! 2. **CSRF double-submit cookie** — the request must carry a
//!    `csrf` cookie value that matches the `X-CSRF-Token`
//!    request header. The cookie is set by the admin-login flow
//!    (M5.2.3); programmatic clients ignore this entirely.
//!
//! Either check passing → request continues. Both failing → 403
//! `CsrfFailed`. The two checks are belt-and-braces: a malicious
//! cross-origin POST from a public-website XSS would have neither
//! `Sec-Fetch-Site: same-origin` (it'd be `cross-site`) nor the
//! `csrf` cookie's matching token (it can't read the cookie value
//! across origins).
//!
//! ## Exemptions
//!
//! - **GET / HEAD / OPTIONS** are not state-mutating and pass through.
//! - **`POST /v1/join-requests`** is the public form-encoded submit
//!   endpoint (§9.3) — public-site JS posts directly without
//!   preflight via simple-request semantics. Exempted by path
//!   prefix match.
//! - **`POST /v1/auth/challenge` / `/v1/auth/` / `/v1/auth/refresh`**
//!   are the JWT-issuance unauth flows — the bearer token IS the
//!   auth credential, no cookie session yet exists to bind a CSRF
//!   token to. Exempted by path prefix match.
//! - **`POST /v1/install/claim/{start,finish}`** are the install
//!   ceremony unauth endpoints — same rationale. Exempted.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, Method, Response, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use serde_json::json;
use subtle::ConstantTimeEq;

/// Paths exempt from CSRF: unauth bootstrapping flows + the public
/// form-post target. Each is documented in the module-level
/// rationale.
const CSRF_EXEMPT_PATHS: &[&str] = &[
    "/v1/join-requests",
    "/v1/auth/challenge",
    "/v1/auth/",
    // VTA-wallet header-exempt auth surface (unauthenticated bootstrap,
    // same rationale as `/v1/auth/*` above — no session cookie yet).
    "/v1/wallet/auth/challenge",
    "/v1/wallet/auth/",
    "/v1/auth/refresh",
    "/v1/auth/admin-login",
    "/v1/install/claim/start",
    "/v1/install/claim/finish",
];

/// Tower middleware function. Wire via
/// `axum::middleware::from_fn(enforce)` at the parent-router level
/// so the layer sees the full path including the API mount prefix
/// (the exemption matcher compares against the post-nest URI).
pub async fn enforce(request: Request, next: Next) -> Response<Body> {
    // Method gate — only state-mutating verbs are checked.
    match *request.method() {
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE => {}
        _ => return next.run(request).await,
    }

    let path = request.uri().path();

    // Path gate — bootstrapping flows + public form post bypass.
    if CSRF_EXEMPT_PATHS.contains(&path) {
        return next.run(request).await;
    }

    // Check 1 — modern browser stamp.
    if request
        .headers()
        .get("sec-fetch-site")
        .map(|v| v == HeaderValue::from_static("same-origin"))
        .unwrap_or(false)
    {
        return next.run(request).await;
    }

    // Check 2 — double-submit cookie + matching header.
    let cookie_token = request
        .headers()
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(|s| s.trim())
        .find_map(|kv| kv.strip_prefix("csrf="));
    let header_token = request
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok());

    // Constant-time comparison on the bytes. A naive `c == h` on a
    // String would short-circuit at the first mismatching byte, which
    // leaks prefix-match length over response timing. `ct_eq` runs
    // in time proportional to the longer slice regardless of where
    // the bytes diverge. Also gate on `len()` matching first so the
    // unequal-length path doesn't fall into `ct_eq`'s zero-pad.
    if let (Some(c), Some(h)) = (cookie_token, header_token)
        && !c.is_empty()
        && c.len() == h.len()
        && bool::from(c.as_bytes().ct_eq(h.as_bytes()))
    {
        return next.run(request).await;
    }

    let body = json!({
        "error": "CsrfFailed",
        "message": "POST/PUT/PATCH/DELETE requests require Sec-Fetch-Site: same-origin or a matching csrf cookie + X-CSRF-Token header",
    });
    (StatusCode::FORBIDDEN, axum::Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::post;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn ok() -> &'static str {
        "ok"
    }

    fn app() -> Router {
        Router::new()
            .route("/v1/members", post(ok).get(ok))
            .route("/v1/join-requests", post(ok))
            .route("/v1/auth/challenge", post(ok))
            .layer(axum::middleware::from_fn(enforce))
    }

    #[tokio::test]
    async fn get_bypasses() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/members")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn post_without_csrf_returns_403() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/members")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(body["error"], "CsrfFailed");
    }

    #[tokio::test]
    async fn post_with_sec_fetch_site_same_origin_passes() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/members")
                    .header("sec-fetch-site", "same-origin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn post_with_matching_csrf_cookie_and_header_passes() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/members")
                    .header("cookie", "csrf=abc123; other=foo")
                    .header("x-csrf-token", "abc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn post_with_non_matching_csrf_header_returns_403() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/members")
                    .header("cookie", "csrf=abc123")
                    .header("x-csrf-token", "different")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn public_join_request_post_bypasses() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/join-requests")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_challenge_post_bypasses() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/challenge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
