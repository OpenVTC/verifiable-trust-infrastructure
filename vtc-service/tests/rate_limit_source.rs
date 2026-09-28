//! Every `429` the VTC's own limiters emit says who refused.
//!
//! Ecosystem contract (shared with the VTA, mediator and DID hosts): status
//! 429, `x-rate-limit-source: vtc`, `Retry-After: <seconds>`, and a JSON body
//! `{"error":"rate_limited","limiter":"<name>","message":…,"retryAfterSecs":N}`.
//!
//! This file drives the per-IP `tower-governor` on the unauthenticated chain
//! through the real router, and the per-signer budget on `POST /v1/trust-tasks`
//! that a signer the community knows is charged instead. The per-member
//! relationship publish limiter is covered in `relationships.rs`, where a
//! signed publish can be built.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_sdk::error::VtaError;
use vta_sdk::rate_limit::{RateLimitSource, SOURCE_HEADER};
use vtc_service::test_support::TestVtc;
use vti_rooms_dtg::test_support::Party;

/// Post `uri` until the governor refuses, returning the refusal. The governor
/// allows a burst of 10, so 40 sequential in-memory requests always trip it.
async fn flood_until_refused(
    router: &axum::Router,
    uri: &str,
    task: &str,
) -> axum::response::Response {
    for _ in 0..40 {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header("Trust-Task", task)
            .body(Body::from(json!({}).to_string()))
            .unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        if res.status() == StatusCode::TOO_MANY_REQUESTS {
            return res;
        }
        // A request the governor let through is answered by the handler, and
        // no handler refusal may claim to be this limiter.
        assert!(
            !res.headers().contains_key(SOURCE_HEADER),
            "{uri}: a non-429 answer ({}) carried the rate-limit source header",
            res.status()
        );
    }
    panic!("{uri}: no 429 in 40 requests — is the route still behind the unauth governor?");
}

async fn assert_unauth_contract(res: axum::response::Response) {
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    // The client half of the contract reads this refusal as the VTC's. Checked
    // against the SDK's own parser so the two cannot drift.
    let parsed = VtaError::rate_limited_from_http(
        res.status(),
        res.headers(),
        "",
        "https://vtc.example.com/v1/",
    );
    assert!(
        matches!(
            parsed,
            Some(VtaError::RateLimited {
                limited_by: RateLimitSource::Vtc,
                retry_after: Some(_),
                ..
            })
        ),
        "the SDK must attribute this 429 to the VTC: {parsed:?}"
    );
    assert_eq!(res.headers()[SOURCE_HEADER], "vtc");
    assert_eq!(res.headers()["content-type"], "application/json");
    let retry_after: u64 = res.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .expect("Retry-After is whole seconds");
    assert!(
        retry_after >= 1,
        "Retry-After must never invite an immediate retry"
    );

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).expect("the refusal body is JSON");
    assert_eq!(body["error"], "rate_limited");
    assert_eq!(body["limiter"], "unauth");
    assert_eq!(body["retryAfterSecs"], retry_after);
    assert!(body["message"].as_str().is_some_and(|m| !m.is_empty()));
    assert_eq!(
        body.as_object().unwrap().len(),
        4,
        "the body carries exactly the contract's members: {body}"
    );
}

#[tokio::test]
async fn unauth_governor_refusal_on_trust_tasks_carries_the_contract() {
    let vtc = TestVtc::builder().build().await;
    let res = flood_until_refused(
        &vtc.router,
        "/v1/trust-tasks",
        "https://trusttasks.org/spec/vtc/join/submit/0.1",
    )
    .await;
    assert_unauth_contract(res).await;
}

/// The install claim — the brute-force surface the claim secret's entropy is
/// sized against — is limited by the same governor, and says so.
#[tokio::test]
async fn unauth_governor_refusal_on_install_claim_carries_the_contract() {
    let vtc = TestVtc::builder().build().await;
    let res = flood_until_refused(
        &vtc.router,
        "/v1/install/claim/start",
        "https://trusttasks.org/spec/vtc/install/claim/start/0.2",
    )
    .await;
    assert_unauth_contract(res).await;
}

#[tokio::test]
async fn unauth_governor_refusal_on_auth_challenge_carries_the_contract() {
    let vtc = TestVtc::builder().build().await;
    let res = flood_until_refused(
        &vtc.router,
        "/v1/auth/challenge",
        "https://trusttasks.org/spec/auth/challenge/0.1",
    )
    .await;
    assert_unauth_contract(res).await;
}

const CONFIG_SHOW: &str = "https://trusttasks.org/spec/config/show/0.1";

/// Post `count` fresh documents signed by `from`, all from one address, and
/// return the status of each.
async fn signed_from_one_address(vtc: &TestVtc, from: &Party, count: usize) -> Vec<StatusCode> {
    let peer = std::net::SocketAddr::from(([192, 0, 2, 77], 40_000));
    let mut statuses = Vec::with_capacity(count);
    for _ in 0..count {
        let doc = common::signed::signed(from, CONFIG_SHOW, json!({})).await;
        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/trust-tasks")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&doc).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        let res = vtc.router.clone().oneshot(req).await.unwrap();
        statuses.push(res.status());
        if res.status() == StatusCode::TOO_MANY_REQUESTS {
            assert_unauth_contract(res).await;
            break;
        }
    }
    statuses
}

/// A console's reads are signed Trust Tasks: an administrator navigating it
/// sends far more than the anonymous burst of 10 from one address, and is
/// charged its own signer bucket (a burst of 60) instead.
#[tokio::test]
async fn a_signer_the_community_knows_is_not_held_to_the_anonymous_burst() {
    let vtc = TestVtc::builder().build().await;
    let admin = common::signed::admin(&vtc).await;
    let statuses = signed_from_one_address(&vtc, &admin, 30).await;
    assert_eq!(statuses.len(), 30);
    assert!(
        statuses.iter().all(|s| *s != StatusCode::TOO_MANY_REQUESTS),
        "an ACL signer was rate limited within its own burst: {statuses:?}"
    );
}

/// A signer with no ACL entry buys nothing by signing: minting a DID is free,
/// so it pays the per-address anonymous governor and is refused at 10.
#[tokio::test]
async fn a_signer_the_community_does_not_know_is_refused_at_the_anonymous_burst() {
    let vtc = TestVtc::builder().build().await;
    let stranger = Party::new();
    let statuses = signed_from_one_address(&vtc, &stranger, 30).await;
    assert_eq!(
        statuses.len(),
        11,
        "ten pass, the eleventh is refused: {statuses:?}"
    );
    assert!(
        statuses[..10]
            .iter()
            .all(|s| *s != StatusCode::TOO_MANY_REQUESTS)
    );
}
