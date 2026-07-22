//! Cookie-bearing admin session integration tests (Phase 5 M5.2.3
//! + M5.3.1).
//!
//! Covers:
//!
//! - The `vti_common::auth::extractor::AuthClaims` cookie fallback:
//!   a request that carries the `vtc_admin_session` cookie (but no
//!   `Authorization` header) authenticates exactly like a bearer
//!   request would.
//! - Wrong cookie name → 401.
//! - Bearer + cookie both present → bearer wins (documented
//!   precedence per `AuthClaims::from_request_parts`).
//! - The cookie value carrying a foreign-audience JWT is rejected
//!   the same way a bearer foreign-audience JWT is — the cookie
//!   path doesn't widen the audience-isolation invariant
//!   (§9.7 / CLAUDE.md).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use vti_common::auth::extractor::ADMIN_SESSION_COOKIE;
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

const ADMIN_DID: &str = "did:key:z6MkAdminCookie";
const ACL_TRUST_TASK: &str = "https://trusttasks.org/spec/acl/list/0.1";

struct Fixture {
    router: axum::Router,
    state: AppState,
    jwt_keys: Arc<JwtKeys>,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    // Held only for Drop (this suite mints tokens via `jwt_keys` directly).
    _vtc: TestVtc,
}

async fn build_fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .vtc_did("did:key:z6MkTestVTC")
        .build()
        .await;
    let state = vtc.state.clone();

    // Insert admin ACL entry so the protected route doesn't 403.
    store_acl_entry(
        &state.acl_ks,
        &VtcAclEntry {
            did: ADMIN_DID.into(),
            role: VtcRole::Admin,
            label: None,
            allowed_contexts: vec![],
            created_at: now_epoch(),
            created_by: "test".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("acl insert");

    Fixture {
        router: vtc.router.clone(),
        state,
        jwt_keys: vtc.jwt_keys.clone(),
        _vtc: vtc,
    }
}

/// Mint a session row + JWT for `did:key:z6MkAdminCookie` with
/// admin role. The token is bound to the session ID so the
/// extractor's `get_session` lookup succeeds.
async fn mint_session(fix: &Fixture, audience: &str) -> String {
    let session_id = format!("sess-{}", uuid::Uuid::new_v4());
    store_session(
        &fix.state.sessions_ks,
        &Session {
            session_id: session_id.clone(),
            did: ADMIN_DID.into(),
            challenge: "test".into(),
            state: SessionState::Authenticated,
            created_at: now_epoch(),
            last_seen: now_epoch(),
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: Vec::new(),
            acr: String::new(),
            acr_expires_at: None,
            token_id: None,
            session_pubkey_b58btc: None,
        },
    )
    .await
    .expect("store session");

    // For the foreign-audience tests, mint with a different
    // JwtKeys; otherwise reuse the fixture's VTC keys.
    let keys = if audience == "VTC" {
        fix.jwt_keys.clone()
    } else {
        Arc::new(JwtKeys::from_ed25519_bytes(&[0x42u8; 32], audience).unwrap())
    };
    let claims = keys.new_claims(
        ADMIN_DID.to_string(),
        session_id,
        "admin".to_string(),
        vec![],
        900,
        false,
    );
    keys.encode(&claims).expect("encode")
}

async fn request(router: &axum::Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = router.clone().oneshot(req).await.expect("request");
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn admin_cookie_authenticates_protected_route() {
    let fix = build_fixture().await;
    let jwt = mint_session(&fix, "VTC").await;

    let req = Request::builder()
        .method("GET")
        .uri("/v1/acl")
        .header("Trust-Task", ACL_TRUST_TASK)
        .header("Cookie", format!("{ADMIN_SESSION_COOKIE}={jwt}"))
        .body(Body::empty())
        .unwrap();
    let (status, _body) = request(&fix.router, req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "cookie-bearing request must authenticate the admin route"
    );
}

#[tokio::test]
async fn wrong_cookie_name_returns_401() {
    let fix = build_fixture().await;
    let jwt = mint_session(&fix, "VTC").await;

    let req = Request::builder()
        .method("GET")
        .uri("/v1/acl")
        .header("Trust-Task", ACL_TRUST_TASK)
        // Wrong cookie name — the fallback path requires the
        // exact `vtc_admin_session` cookie. A bare
        // `session=<jwt>` value must not authenticate.
        .header("Cookie", format!("session={jwt}; other=foo"))
        .body(Body::empty())
        .unwrap();
    let (status, _body) = request(&fix.router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cookie_alongside_other_cookies_authenticates() {
    let fix = build_fixture().await;
    let jwt = mint_session(&fix, "VTC").await;

    let req = Request::builder()
        .method("GET")
        .uri("/v1/acl")
        .header("Trust-Task", ACL_TRUST_TASK)
        // Order + presence of other cookies must not break the
        // session-cookie parser.
        .header(
            "Cookie",
            format!("csrf=abc123; {ADMIN_SESSION_COOKIE}={jwt}; analytics=enabled"),
        )
        .body(Body::empty())
        .unwrap();
    let (status, _body) = request(&fix.router, req).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn bearer_takes_precedence_over_cookie() {
    let fix = build_fixture().await;
    // Bearer with a valid VTC token; cookie with an invalid
    // (foreign-audience) token. The extractor must prefer the
    // bearer and authenticate.
    let valid_bearer = mint_session(&fix, "VTC").await;
    let foreign_cookie = mint_session(&fix, "EVIL-AUD").await;

    let req = Request::builder()
        .method("GET")
        .uri("/v1/acl")
        .header("Trust-Task", ACL_TRUST_TASK)
        .header("Authorization", format!("Bearer {valid_bearer}"))
        .header("Cookie", format!("{ADMIN_SESSION_COOKIE}={foreign_cookie}"))
        .body(Body::empty())
        .unwrap();
    let (status, _body) = request(&fix.router, req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Bearer header takes precedence; cookie ignored when bearer is present"
    );
}

#[tokio::test]
async fn foreign_audience_cookie_rejected() {
    // The cookie path does NOT widen the audience-isolation
    // invariant. A foreign-audience JWT in the
    // `vtc_admin_session` cookie must be rejected at decode
    // time, same as a foreign-audience bearer token would be.
    let fix = build_fixture().await;
    let foreign = mint_session(&fix, "EVIL-AUD").await;

    let req = Request::builder()
        .method("GET")
        .uri("/v1/acl")
        .header("Trust-Task", ACL_TRUST_TASK)
        .header("Cookie", format!("{ADMIN_SESSION_COOKIE}={foreign}"))
        .body(Body::empty())
        .unwrap();
    let (status, _body) = request(&fix.router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ─── CSRF enforcement through the real router (P3.2) ─────────
//
// These assert that the CSRF layer is actually wired into the
// assembled router the harness builds (it used to be attached only in
// `server.rs`, so CSRF was invisible to integration tests). They also
// pin the cookie-session gate: a mutating *cookie-session* request is
// gated, while bearer and no-cookie requests are not.

#[tokio::test]
async fn cookie_session_mutation_without_csrf_token_is_forbidden() {
    // A cookie session POSTing with neither a same-origin stamp nor a
    // matching csrf double-submit is the genuine CSRF-exposed case.
    // The CSRF layer (now wired into the harness) must reject it with
    // `CsrfFailed` *before* the handler runs.
    let fix = build_fixture().await;
    let jwt = mint_session(&fix, "VTC").await;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/acl")
        .header("Trust-Task", ACL_TRUST_TASK)
        .header("Cookie", format!("{ADMIN_SESSION_COOKIE}={jwt}"))
        .body(Body::empty())
        .unwrap();
    let (status, body) = request(&fix.router, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "cookie-session POST: {body}");
    assert!(
        body.contains("CsrfFailed"),
        "expected a CSRF rejection, got: {body}"
    );
}

#[tokio::test]
async fn cookie_session_mutation_with_same_origin_passes_csrf() {
    // The same cookie session with a `Sec-Fetch-Site: same-origin`
    // stamp clears CSRF and reaches the handler — so it is never the
    // `CsrfFailed` rejection (the handler may still 4xx the body, but
    // that's past CSRF).
    let fix = build_fixture().await;
    let jwt = mint_session(&fix, "VTC").await;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/acl")
        .header("Trust-Task", ACL_TRUST_TASK)
        .header("Cookie", format!("{ADMIN_SESSION_COOKIE}={jwt}"))
        .header("Sec-Fetch-Site", "same-origin")
        .body(Body::empty())
        .unwrap();
    let (_status, body) = request(&fix.router, req).await;
    assert!(
        !body.contains("CsrfFailed"),
        "same-origin cookie POST must clear CSRF, got: {body}"
    );
}

#[tokio::test]
async fn bearer_mutation_bypasses_csrf() {
    // A bearer-authenticated POST carries no ambient cookie to forge,
    // so it bypasses CSRF entirely even with no stamp / token — the
    // programmatic-client case the P3.2 exemption fixes.
    let fix = build_fixture().await;
    let jwt = mint_session(&fix, "VTC").await;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/acl")
        .header("Trust-Task", ACL_TRUST_TASK)
        .header("Authorization", format!("Bearer {jwt}"))
        .body(Body::empty())
        .unwrap();
    let (_status, body) = request(&fix.router, req).await;
    assert!(
        !body.contains("CsrfFailed"),
        "bearer POST must bypass CSRF, got: {body}"
    );
}
