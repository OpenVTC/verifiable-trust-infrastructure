//! CSRF protection for admin mutating endpoints (Phase 5 M5.2.2).
//!
//! ## What CSRF actually defends
//!
//! The only attack CSRF stops is a forged cross-site request riding
//! the victim's **ambient cookie session**: the browser auto-attaches
//! the `vtc_admin_session` cookie to a POST initiated by an attacker
//! page, so the request authenticates as the victim. The defense is
//! to require proof the request was *intended* — either a same-origin
//! stamp the attacker can't forge, or a double-submit token the
//! attacker can't read across origins.
//!
//! A request that carries **no session cookie** can't be
//! authenticated-as-victim and therefore can't be a CSRF attack —
//! there is nothing to protect. So CSRF is enforced **only on
//! cookie-session requests**; everything else passes through and the
//! per-route auth layer decides (returning a clean `401` for a
//! genuinely unauthenticated call instead of a misleading
//! `CsrfFailed`). This is the P3.2 fix: the earlier code gated *every*
//! mutating request, so programmatic clients and credential-less
//! probes alike got a 403 the threat model never warranted.
//!
//! ## Enforcement (cookie-session requests only)
//!
//! For a mutating request that carries the `vtc_admin_session`
//! cookie, one of two checks must pass:
//!
//! 1. **`Sec-Fetch-Site: same-origin`** — modern browsers stamp
//!    this header on fetches initiated from the same origin as the
//!    receiving server. An attacker page's cross-site POST is stamped
//!    `cross-site`, not `same-origin`.
//! 2. **CSRF double-submit cookie** — the request must carry a
//!    `csrf` cookie value that matches the `X-CSRF-Token` request
//!    header. The cookie is set by the admin-login flow (M5.2.3); an
//!    attacker can't read it across origins to echo it in the header.
//!
//! Either check passing → request continues. Both failing → 403
//! `CsrfFailed`.
//!
//! ## Pass-through (before enforcement)
//!
//! - **GET / HEAD / OPTIONS** are not state-mutating.
//! - **`Authorization: Bearer` requests** are structurally
//!   CSRF-immune: a browser never auto-attaches an `Authorization`
//!   header the way it replays cookies, so a forged cross-site request
//!   can't carry the bearer credential. Programmatic CLI / wallet /
//!   SDK clients authenticate this way. Checked explicitly (and first)
//!   so a bearer call still passes even if a stale session cookie
//!   tags along — the auth extractor prefers the bearer token too.
//! - **No `vtc_admin_session` cookie** — not a cookie session, so not
//!   forgeable (see above). This subsumes the unauthenticated
//!   bootstrap flows (`/auth/*`, `/install/claim/*`, `/auth/recognise*`,
//!   passkey login) and the public CLI/wallet join surface
//!   (`/join-requests`, `…/{id}/accept`, `…/{id}/status`), none of
//!   which carry a session cookie.
//! - **[`CSRF_EXEMPT_PATHS`] + the join holder suffixes** — an
//!   explicit belt-and-braces list for the known unauthenticated
//!   bootstrap + public-form endpoints, kept so they pass even on the
//!   off chance a request reaches them carrying a stale session
//!   cookie (e.g. a re-login while an old cookie lingers). The
//!   holder-facing `…/{id}/accept` / `…/{id}/status` POSTs are
//!   suffix-matched; the admin `approve`/`reject` endpoints on the
//!   same mount are deliberately left to the cookie-session gate.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use serde_json::json;
use subtle::ConstantTimeEq;

// Single source of truth for the cookie name: the same constant the
// auth extractor reads to authenticate a cookie session. If a new
// auth cookie is ever added there, the CSRF gate must learn about it
// too — keep them pinned to the same symbol so the coupling is loud.
use vti_common::auth::extractor::ADMIN_SESSION_COOKIE;

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
    // First-admin finalisation — unauthenticated (the setup-session JWT in
    // the body is the credential), driven by the install page + CNM CLI.
    "/v1/admin/bootstrap",
];

/// True when the request carries an `Authorization: Bearer …` header.
/// Such requests are structurally CSRF-immune (a browser never
/// auto-attaches `Authorization` the way it replays cookies), so they
/// skip the cookie/origin checks entirely — see the module rationale.
fn has_bearer_auth(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        // RFC 7235 auth-scheme is case-insensitive; tolerate leading
        // whitespace. `get(..7)` keeps the slice on a char boundary so
        // a multibyte value can't panic.
        .and_then(|v| v.trim_start().get(..7))
        .map(|scheme| scheme.eq_ignore_ascii_case("bearer "))
        .unwrap_or(false)
}

/// True when `path` is exempt from CSRF enforcement: the static
/// bootstrapping flows in [`CSRF_EXEMPT_PATHS`] plus the parametrised
/// public holder endpoints on the join surface
/// (`/v1/join-requests/{id}/accept`, `…/{id}/status`), which can't be
/// exact-matched. Suffix-matching `/accept` / `/status` under the
/// join-requests prefix deliberately leaves the admin `approve` /
/// `reject` endpoints on the same mount gated.
fn is_csrf_exempt(path: &str) -> bool {
    if CSRF_EXEMPT_PATHS.contains(&path) {
        return true;
    }
    if let Some(rest) = path.strip_prefix("/v1/join-requests/") {
        return rest.ends_with("/accept") || rest.ends_with("/status");
    }
    false
}

/// True when the request carries the `vtc_admin_session` cookie — the
/// only credential a CSRF attack can ride. Requests without it can't
/// be authenticated-as-victim, so they're not a CSRF vector and skip
/// enforcement (the auth layer 401s them if they're unauthenticated).
fn has_session_cookie(headers: &HeaderMap) -> bool {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(|s| s.trim())
        .filter_map(|kv| kv.split_once('='))
        .any(|(name, _)| name == ADMIN_SESSION_COOKIE)
}

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

    // Bearer gate — programmatic clients authenticating with an
    // `Authorization: Bearer` token are structurally CSRF-immune.
    // Checked first so a bearer call passes even if a stale session
    // cookie tags along (the auth extractor prefers bearer too).
    if has_bearer_auth(request.headers()) {
        return next.run(request).await;
    }

    let path = request.uri().path();

    // Path gate — explicit belt-and-braces exemption for the known
    // unauth bootstrap flows + public join surface.
    if is_csrf_exempt(path) {
        return next.run(request).await;
    }

    // Session-cookie gate — CSRF only protects cookie-session
    // requests (ambient-credential replay is the entire threat). A
    // request with no `vtc_admin_session` cookie can't be forged, so
    // it passes here and the per-route auth layer returns a clean 401
    // if it's actually unauthenticated.
    if !has_session_cookie(request.headers()) {
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

    /// A `Cookie` header value carrying the admin session cookie, so a
    /// request looks like a real cookie session to the gate. The unit
    /// `app()` has no auth layer, so the handler returns 200 once CSRF
    /// passes — these tests assert the CSRF decision, not auth.
    const SESSION_COOKIE: &str = "vtc_admin_session=jwt.header.sig";

    fn app() -> Router {
        Router::new()
            .route("/v1/members", post(ok).get(ok))
            .route("/v1/join-requests", post(ok))
            .route("/v1/join-requests/{id}/accept", post(ok))
            .route("/v1/join-requests/{id}/status", post(ok))
            .route("/v1/join-requests/{id}/approve", post(ok))
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
    async fn cookie_session_post_without_csrf_returns_403() {
        // A real cookie session (carries `vtc_admin_session`) with no
        // origin stamp and no csrf token is the genuine CSRF-exposed
        // case → 403.
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/members")
                    .header("cookie", SESSION_COOKIE)
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
    async fn post_without_session_cookie_passes_csrf() {
        // No bearer, no session cookie, no origin stamp: not a cookie
        // session, so not a CSRF vector. CSRF passes it through; the
        // auth layer (absent in this unit harness) is what would 401 a
        // genuinely unauthenticated call. This is the P3.2 fix — the
        // old code 403'd here, masking the auth layer's 401.
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
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cookie_session_post_with_sec_fetch_site_same_origin_passes() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/members")
                    .header("cookie", SESSION_COOKIE)
                    .header("sec-fetch-site", "same-origin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cookie_session_post_with_matching_csrf_cookie_and_header_passes() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/members")
                    .header(
                        "cookie",
                        format!("{SESSION_COOKIE}; csrf=abc123; other=foo"),
                    )
                    .header("x-csrf-token", "abc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cookie_session_post_with_non_matching_csrf_header_returns_403() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/members")
                    .header("cookie", format!("{SESSION_COOKIE}; csrf=abc123"))
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

    #[tokio::test]
    async fn bearer_post_without_cookie_or_origin_passes() {
        // Programmatic CLI/SDK client: bearer token, no Sec-Fetch-Site,
        // no csrf cookie. Structurally CSRF-immune → passes.
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/members")
                    .header("authorization", "Bearer eyJabc.def.ghi")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn bearer_scheme_is_case_insensitive() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/members")
                    .header("authorization", "bearer eyJabc.def.ghi")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn non_bearer_authorization_scheme_on_cookie_session_stays_gated() {
        // A `Basic` (or any non-bearer) Authorization header is not the
        // CSRF-immune bearer case. With a real cookie session and no
        // origin stamp / csrf token it must still 403 — the non-bearer
        // scheme doesn't open the bearer skip.
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/members")
                    .header("authorization", "Basic dXNlcjpwYXNz")
                    .header("cookie", SESSION_COOKIE)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn holder_accept_post_bypasses() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/join-requests/req-123/accept")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn holder_status_post_bypasses() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/join-requests/req-123/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_approve_on_join_mount_stays_gated() {
        // `approve` shares the join-requests mount but is an admin
        // action — a cookie-session POST with no token must 403 (only
        // the holder `accept`/`status` suffixes are exempt, and only a
        // cookie session is gated at all).
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/join-requests/req-123/approve")
                    .header("cookie", SESSION_COOKIE)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn session_cookie_detected_among_others() {
        // The gate must find the session cookie regardless of position
        // / surrounding pairs, and not false-positive on a lookalike.
        let mut present = HeaderMap::new();
        present.insert(
            "cookie",
            "foo=1; vtc_admin_session=abc; csrf=t".parse().unwrap(),
        );
        assert!(has_session_cookie(&present));

        let mut absent = HeaderMap::new();
        absent.insert("cookie", "csrf=t; other_session=abc".parse().unwrap());
        assert!(!has_session_cookie(&absent));
    }
}
