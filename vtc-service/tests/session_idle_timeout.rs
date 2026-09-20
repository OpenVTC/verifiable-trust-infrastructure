//! The admin console's sliding session: activity tracking, the
//! configurable idle timeout, and the cookie refresh path.
//!
//! Before this existed a console session was a hard cliff — the cookie's
//! `Max-Age` was the access token's remaining life (300s after a passkey
//! login, since that mints at `acr=aal2`), nothing extended it, and the
//! operator learned of expiry from a failed request. These tests pin the
//! three pieces that replace it:
//!
//! - `last_seen` advances on **cookie** requests and not on bearer ones,
//!   because the idle timeout is an admin-console policy and every
//!   programmatic caller would otherwise pay a store write per call.
//! - `handle_refresh` refuses once `now - last_seen` exceeds the
//!   configured timeout, and answers with its own message rather than
//!   the generic "authentication failed" the other auth failures share.
//! - The cookie refresh re-issues all three cookies, and is CSRF-gated
//!   now that a cookie alone can authenticate it — while the body-token
//!   refresh that SDK and CLI clients use stays exempt.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vti_common::auth::extractor::{ADMIN_REFRESH_COOKIE, ADMIN_SESSION_COOKIE};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::session::{
    Session, SessionState, get_session, now_epoch, store_refresh_index, store_session,
};

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

const ADMIN_DID: &str = "did:key:z6MkAdminIdle";
const ACL_TRUST_TASK: &str = "https://trusttasks.org/spec/acl/list/0.1";
const REFRESH_TASK: &str = "https://trusttasks.org/spec/auth/refresh/0.1";

struct Fixture {
    router: axum::Router,
    state: AppState,
    jwt_keys: Arc<JwtKeys>,
    _vtc: TestVtc,
}

async fn build() -> Fixture {
    let vtc = TestVtc::builder()
        .vtc_did("did:key:z6MkTestVTCIdle")
        .build()
        .await;
    let state = vtc.state.clone();

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
    .expect("store acl");

    let jwt_keys = state.jwt_keys.clone().expect("jwt keys configured");
    Fixture {
        router: vtc.router.clone(),
        state,
        jwt_keys,
        _vtc: vtc,
    }
}

/// A live session whose `last_seen` is `idle_secs` in the past.
///
/// Returns `(access_token, refresh_token, session_id)`.
async fn seed_session(fix: &Fixture, idle_secs: u64) -> (String, String, String) {
    let session_id = format!("sess-{}", uuid::Uuid::new_v4());
    let refresh_token = uuid::Uuid::new_v4().to_string();
    let now = now_epoch();

    let claims = fix.jwt_keys.new_claims(
        ADMIN_DID.to_string(),
        session_id.clone(),
        "admin".to_string(),
        vec![],
        900,
        false,
    );
    let token_id = claims.jti.clone();
    let access_token = fix.jwt_keys.encode(&claims).expect("encode");

    store_session(
        &fix.state.sessions_ks,
        &Session {
            session_id: session_id.clone(),
            did: ADMIN_DID.into(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: now.saturating_sub(idle_secs),
            last_seen: now.saturating_sub(idle_secs),
            refresh_token: Some(refresh_token.clone()),
            refresh_expires_at: Some(now + 86_400),
            tee_attested: false,
            amr: vec!["passkey".into()],
            acr: "aal1".into(),
            acr_expires_at: None,
            token_id: Some(token_id),
            session_pubkey_b58btc: None,
        },
    )
    .await
    .expect("store session");
    store_refresh_index(&fix.state.sessions_ks, &refresh_token, &session_id)
        .await
        .expect("store refresh index");

    (access_token, refresh_token, session_id)
}

async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = router.clone().oneshot(req).await.expect("request");
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

// ─── Activity tracking ───────────────────────────────────────────────

#[tokio::test]
async fn a_cookie_request_records_activity() {
    let fix = build().await;
    let (access, _refresh, session_id) = seed_session(&fix, 600).await;

    let before = get_session(&fix.state.sessions_ks, &session_id)
        .await
        .unwrap()
        .unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/v1/acl")
        .header("cookie", format!("{ADMIN_SESSION_COOKIE}={access}"))
        .header("trust-task", ACL_TRUST_TASK)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&fix.router, req).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let after = get_session(&fix.state.sessions_ks, &session_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        after.last_seen > before.last_seen,
        "a cookie request is the operator doing something; it must reset \
         the idle clock (before={}, after={})",
        before.last_seen,
        after.last_seen
    );
}

/// The counterpart, and the reason the touch is gated on the token's
/// source: every CLI and service integration authenticates with a
/// bearer token, has no idle timeout, and would otherwise pay a session
/// write on every single call.
#[tokio::test]
async fn a_bearer_request_does_not_record_activity() {
    let fix = build().await;
    let (access, _refresh, session_id) = seed_session(&fix, 600).await;

    let before = get_session(&fix.state.sessions_ks, &session_id)
        .await
        .unwrap()
        .unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/v1/acl")
        .header("authorization", format!("Bearer {access}"))
        .header("trust-task", ACL_TRUST_TASK)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&fix.router, req).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let after = get_session(&fix.state.sessions_ks, &session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after.last_seen, before.last_seen,
        "a bearer request must leave the idle clock alone"
    );
}

// ─── The idle timeout ────────────────────────────────────────────────

#[tokio::test]
async fn refresh_succeeds_inside_the_idle_window() {
    let fix = build().await;
    // Default timeout is 900s; 60s idle is comfortably inside it.
    let (_access, refresh, _session_id) = seed_session(&fix, 60).await;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/refresh")
        .header("content-type", "application/json")
        .header("trust-task", REFRESH_TASK)
        .body(Body::from(
            json!({
                "type": REFRESH_TASK,
                "id": uuid::Uuid::new_v4().to_string(),
                "payload": { "refreshToken": refresh },
            })
            .to_string(),
        ))
        .unwrap();
    let (status, body) = send(&fix.router, req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn refresh_is_refused_once_the_session_has_idled_out() {
    let fix = build().await;
    // Past the 900s default.
    let (_access, refresh, _session_id) = seed_session(&fix, 1_200).await;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/refresh")
        .header("content-type", "application/json")
        .header("trust-task", REFRESH_TASK)
        .body(Body::from(
            json!({
                "type": REFRESH_TASK,
                "id": uuid::Uuid::new_v4().to_string(),
                "payload": { "refreshToken": refresh },
            })
            .to_string(),
        ))
        .unwrap();
    let (status, body) = send(&fix.router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    // Not the generic "authentication failed" the other auth failures
    // share: reaching this point proves possession of a valid refresh
    // token, so there is no one left to withhold the reason from, and
    // "you were away" sends an operator somewhere different from "your
    // session hit its ceiling".
    assert!(
        body.contains("inactivity"),
        "the refusal should say why, got: {body}"
    );
}

/// The timeout is a live config value, not a boot-time constant — the
/// console's Save is a `config/patch` + `config/reload`, and neither
/// restarts the daemon.
#[tokio::test]
async fn the_idle_window_follows_the_running_config() {
    let fix = build().await;
    let (_access, refresh, _session_id) = seed_session(&fix, 1_200).await;

    // 1200s idle is past the 900s default but inside a 1800s setting.
    {
        let mut cfg = fix.state.config.write().await;
        cfg.auth.admin_idle_timeout = 1_800;
    }

    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/refresh")
        .header("content-type", "application/json")
        .header("trust-task", REFRESH_TASK)
        .body(Body::from(
            json!({
                "type": REFRESH_TASK,
                "id": uuid::Uuid::new_v4().to_string(),
                "payload": { "refreshToken": refresh },
            })
            .to_string(),
        ))
        .unwrap();
    let (status, body) = send(&fix.router, req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a widened timeout must apply without a restart: {body}"
    );
}

/// Rotation must not reset the idle clock. If it did, a console that
/// renews on a timer would hold its session open for as long as the tab
/// stayed open and the timeout could never fire at all.
#[tokio::test]
async fn refreshing_does_not_count_as_activity() {
    let fix = build().await;
    let (_access, refresh, session_id) = seed_session(&fix, 300).await;

    let before = get_session(&fix.state.sessions_ks, &session_id)
        .await
        .unwrap()
        .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/refresh")
        .header("content-type", "application/json")
        .header("trust-task", REFRESH_TASK)
        .body(Body::from(
            json!({
                "type": REFRESH_TASK,
                "id": uuid::Uuid::new_v4().to_string(),
                "payload": { "refreshToken": refresh },
            })
            .to_string(),
        ))
        .unwrap();
    let (status, body) = send(&fix.router, req).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let after = get_session(&fix.state.sessions_ks, &session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after.last_seen, before.last_seen,
        "a token rotation is the client's timer, not the operator"
    );
}

// ─── The cookie refresh path ─────────────────────────────────────────

#[tokio::test]
async fn a_cookie_refresh_reissues_every_cookie() {
    let fix = build().await;
    let (_access, refresh, _session_id) = seed_session(&fix, 60).await;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/refresh")
        .header(
            "cookie",
            format!("{ADMIN_REFRESH_COOKIE}={refresh}; csrf=tok"),
        )
        .header("x-csrf-token", "tok")
        .header("trust-task", REFRESH_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.expect("request");
    assert_eq!(resp.status(), StatusCode::OK);

    let cookies: Vec<String> = resp
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();

    assert!(
        cookies.iter().any(|c| c.starts_with(ADMIN_SESSION_COOKIE)),
        "the new access token has to land in the session cookie: {cookies:?}"
    );
    assert!(
        cookies.iter().any(|c| c.starts_with(ADMIN_REFRESH_COOKIE)),
        "rotation invalidated the old refresh token, so leaving the stale \
         cookie would break the *next* renewal: {cookies:?}"
    );
    let csrf = cookies
        .iter()
        .find(|c| c.starts_with("csrf="))
        .expect("csrf cookie re-sent to extend its Max-Age");
    assert!(
        csrf.starts_with("csrf=tok;"),
        "the csrf value must survive: the SPA has already mirrored it into \
         its header state, and a new one mid-flight 403s every mutation \
         issued before it re-reads document.cookie — got {csrf}"
    );
}

/// The CSRF exemption on `/v1/auth/refresh` was safe only while the
/// credential lived in the request body. A cookie the browser attaches
/// on its own makes a forged cross-site refresh possible, which would
/// rotate the victim's token out from under them.
#[tokio::test]
async fn a_cookie_refresh_without_a_csrf_token_is_refused() {
    let fix = build().await;
    let (_access, refresh, _session_id) = seed_session(&fix, 60).await;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/refresh")
        .header(
            "cookie",
            format!("{ADMIN_REFRESH_COOKIE}={refresh}; csrf=tok"),
        )
        .header("trust-task", REFRESH_TASK)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&fix.router, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("CsrfFailed"), "{body}");
}

/// …while the callers that were always safe stay unaffected. An SDK or
/// CLI refresh carries no cookies, so it is structurally CSRF-immune and
/// must not be made to carry a header it has no way to obtain.
#[tokio::test]
async fn a_body_token_refresh_still_needs_no_csrf_token() {
    let fix = build().await;
    let (_access, refresh, _session_id) = seed_session(&fix, 60).await;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/refresh")
        .header("content-type", "application/json")
        .header("trust-task", REFRESH_TASK)
        .body(Body::from(
            json!({
                "type": REFRESH_TASK,
                "id": uuid::Uuid::new_v4().to_string(),
                "payload": { "refreshToken": refresh },
            })
            .to_string(),
        ))
        .unwrap();
    let (status, body) = send(&fix.router, req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn an_idled_out_cookie_refresh_is_refused_too() {
    let fix = build().await;
    let (_access, refresh, _session_id) = seed_session(&fix, 1_200).await;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/refresh")
        .header(
            "cookie",
            format!("{ADMIN_REFRESH_COOKIE}={refresh}; csrf=tok"),
        )
        .header("x-csrf-token", "tok")
        .header("trust-task", REFRESH_TASK)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&fix.router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body.contains("inactivity"), "{body}");
}

// ─── Sign-out ────────────────────────────────────────────────────────

/// A refresh cookie outlives the session cookie, so a sign-out that
/// cleared only the latter would leave the browser holding a credential
/// that still mints access tokens.
#[tokio::test]
async fn sign_out_clears_the_refresh_cookie_too() {
    let fix = build().await;
    let (access, _refresh, _session_id) = seed_session(&fix, 60).await;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/sign-out")
        .header("authorization", format!("Bearer {access}"))
        .header(
            "trust-task",
            "https://trusttasks.org/spec/auth/revoke-session/0.1",
        )
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.expect("request");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let cleared: Vec<String> = resp
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();

    let refresh_clear = cleared
        .iter()
        .find(|c| c.starts_with(ADMIN_REFRESH_COOKIE))
        .unwrap_or_else(|| panic!("no refresh-cookie clear in {cleared:?}"));
    assert!(refresh_clear.contains("Max-Age=0"), "got {refresh_clear}");
}

/// Reading the effective config is how the console renders the control;
/// the key has to actually be in the registry for that to work.
#[tokio::test]
async fn the_idle_timeout_is_in_the_effective_config() {
    let fix = build().await;
    let (access, _refresh, _session_id) = seed_session(&fix, 60).await;

    let req = Request::builder()
        .method("GET")
        .uri("/v1/admin/config")
        .header("authorization", format!("Bearer {access}"))
        .header("trust-task", "https://trusttasks.org/spec/config/show/0.1")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&fix.router, req).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let doc: Value = serde_json::from_str(&body).expect("json");
    let field = doc["fields"]
        .as_array()
        .expect("fields array")
        .iter()
        .find(|f| f["key"] == "auth.admin_idle_timeout")
        .unwrap_or_else(|| panic!("key missing from effective config: {body}"));
    assert_eq!(field["value"], 900);
    assert_eq!(field["requiresRestart"], false);
}
