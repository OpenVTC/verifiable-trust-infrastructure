//! A route that only the access-token extractor guards, for the suites that
//! test that extractor — cookie fallback, bearer precedence, audience
//! isolation, the idle timeout.
//!
//! They used `GET /v1/auth/whoami` for this until #1641 made whoami a signed
//! document answered for a session's bound key (`trust_tasks::whoami_tasks`).
//! No production route is a plain "is this token a live session?" probe any
//! more, so the suites mount this one beside the router under test. It runs
//! `vtc_service::auth::AuthClaims` against the VTC's own state, exactly as
//! every handler that takes it does.

use axum::Json;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vtc_service::auth::AuthClaims;
use vtc_service::test_support::TestVtc;

pub const PROBE_PATH: &str = "/test/session-probe";

/// A router answering `GET /test/session-probe` with the caller's DID and
/// session id when `AuthClaims` admits the request, and the extractor's own
/// refusal otherwise.
pub fn probe_router(vtc: &TestVtc) -> axum::Router {
    axum::Router::new()
        .route(
            PROBE_PATH,
            get(|claims: AuthClaims| async move {
                Json(json!({ "did": claims.did, "sessionId": claims.session_id }))
            }),
        )
        .with_state(vtc.state.clone())
}

/// `GET` the probe with `headers`: the status, and the body as JSON.
pub async fn probe(vtc: &TestVtc, headers: &[(&str, String)]) -> (StatusCode, Value) {
    let mut req = Request::builder().method("GET").uri(PROBE_PATH);
    for (name, value) in headers {
        req = req.header(*name, value.as_str());
    }
    let res = probe_router(vtc)
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
