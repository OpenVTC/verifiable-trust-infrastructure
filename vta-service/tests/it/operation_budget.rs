//! The operation budgets over REST (VTI-TRN-029): authenticated Trust Tasks
//! past `[server] operation_rate_limit_per_sec`, or past one client's
//! `operation_rate_limit_per_subject_per_sec`, are refused with
//! the VTA's 429 before they run, with the same header contract as the per-IP
//! limiters, and an unconfigured VTA refuses nothing.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, TestAppOptions, build_test_app_with};
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

const CALLER_SEED: u8 = 0x91;

/// A signed `auth/sessions/list/0.1` (weight 1), as sent.
fn document(n: usize) -> Vec<u8> {
    let did = vta_service::test_support::did_for_seed(CALLER_SEED).0;
    let mut typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:operation-budget-{n}"),
        "type": "https://trusttasks.org/spec/auth/sessions/list/0.1",
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": did,
        "recipient": "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD",
        "payload": {},
    }))
    .unwrap();
    vta_service::test_support::sign_as(CALLER_SEED, &mut typed);
    serde_json::to_vec(&typed).unwrap()
}

/// The caller's session, which the bearer names.
async fn app(operation_rate_limit_per_sec: Option<u32>) -> (axum::Router, TestAppContext) {
    app_with(TestAppOptions {
        operation_rate_limit_per_sec,
        ..Default::default()
    })
    .await
}

async fn app_with(opts: TestAppOptions) -> (axum::Router, TestAppContext) {
    let (router, ctx) = build_test_app_with(opts).await;
    let session = Session {
        session_id: "sess-budget".into(),
        did: vta_service::test_support::did_for_seed(CALLER_SEED).0,
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        last_seen: now_epoch(),
        refresh_token: Some("rt-budget".into()),
        refresh_expires_at: Some(now_epoch() + 3_600),
        tee_attested: false,
        amr: vec!["did".into()],
        acr: "aal1".into(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
        not_after: None,
    };
    store_session(&ctx.sessions_ks, &session).await.unwrap();
    (router, ctx)
}

async fn post(
    router: &axum::Router,
    ctx: &TestAppContext,
    body: Vec<u8>,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let did = vta_service::test_support::did_for_seed(CALLER_SEED).0;
    let claims = ctx.jwt_keys.new_claims(
        did,
        "sess-budget".into(),
        "admin".into(),
        vec![],
        900,
        false,
    );
    let token = ctx.jwt_keys.encode(&claims).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/trust-tasks")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn sessions_list(
    router: &axum::Router,
    ctx: &TestAppContext,
    n: usize,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    post(router, ctx, document(n)).await
}

#[tokio::test]
async fn work_past_the_budget_is_refused_with_the_vtas_429() {
    // One a second: the burst is raised to the heaviest task's weight (10), so
    // ten requests are served and the eleventh is refused.
    let (router, ctx) = app(Some(1)).await;
    for n in 0..10 {
        let (status, _, body) = sessions_list(&router, &ctx, n).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "request {n} is within the burst: {body}"
        );
    }
    let (status, headers, body) = sessions_list(&router, &ctx, 10).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(headers["x-rate-limit-source"], "vta");
    assert_eq!(headers["x-rate-limit-scope"], "operations");
    assert_eq!(headers["retry-after"], "1");
    assert_eq!(body["limiter"], "operations", "{body}");
}

#[tokio::test]
async fn an_unconfigured_vta_refuses_nothing() {
    let (router, ctx) = app(None).await;
    for n in 0..30 {
        let (status, _, body) = sessions_list(&router, &ctx, n).await;
        assert_eq!(status, StatusCode::OK, "request {n}: {body}");
    }
}

/// A refused request has not run, and its `id` was not recorded: once the
/// budget has room, resending the same document is served, not an `idConflict`
/// or a replay.
#[tokio::test]
async fn a_refused_document_can_be_resent_once_the_budget_has_room() {
    // One a second, not ten: at ten a token refills every 100 ms, and ten
    // requests on a busy runner can take longer than that, letting the
    // document through on its first send.
    let (router, ctx) = app(Some(1)).await;
    for n in 0..10 {
        let (status, _, body) = sessions_list(&router, &ctx, n).await;
        assert_eq!(status, StatusCode::OK, "request {n}: {body}");
    }
    let resent = document(100);
    let (status, _, _) = post(&router, &ctx, resent.clone()).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let (status, _, body) = post(&router, &ctx, resent).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// One client past its own share is refused with the `operations-subject`
/// scope, though the appliance budget has room.
#[tokio::test]
async fn a_client_past_its_own_share_is_refused_as_a_subject() {
    let (router, ctx) = app_with(TestAppOptions {
        operation_rate_limit_per_sec: Some(1_000),
        operation_rate_limit_per_subject_per_sec: Some(1),
        ..Default::default()
    })
    .await;
    for n in 0..10 {
        let (status, _, body) = sessions_list(&router, &ctx, n).await;
        assert_eq!(status, StatusCode::OK, "request {n}: {body}");
    }
    let (status, headers, body) = sessions_list(&router, &ctx, 10).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(headers["x-rate-limit-source"], "vta");
    assert_eq!(headers["x-rate-limit-scope"], "operations-subject");
    assert_eq!(body["limiter"], "operations-subject", "{body}");
}
