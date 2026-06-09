//! Coverage harness for `vta_sdk::protocol` (DIDComm protocol-management
//! REST surface on `VtaClient`). These calls are REST-only by design —
//! `enable_didcomm` runs before any DIDComm transport exists, and the
//! disable / migrate / drain-cancel / report operations are mirrored
//! over DIDComm in `vta-service` but the SDK side just shapes JSON
//! requests, so wiremock is sufficient here.

#![cfg(feature = "client")]

use serde_json::{Value, json};
use vta_sdk::client::VtaClient;
use vta_sdk::error::VtaError;
use vta_sdk::protocol::{
    DisableDidcommRequest, DrainCancelRequest, EnableDidcommRequest, UpdateDidcommRequest,
};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "test-token";

async fn client(server: &MockServer) -> VtaClient {
    let c = VtaClient::new(&server.uri());
    c.set_token_async(TOKEN.into()).await;
    c
}

fn auth() -> impl wiremock::Match {
    header("authorization", &*format!("Bearer {TOKEN}"))
}

// ── enable_didcomm ──────────────────────────────────────────────────

#[tokio::test]
async fn enable_didcomm_posts_request_and_decodes_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/didcomm/enable"))
        .and(auth())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "new_version_id": "2-zVer",
            "mediator_did": "did:peer:2.med",
            "mediator_endpoint": "https://mediator.example.com"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    let req = EnableDidcommRequest::new("did:peer:2.med")
        .force(true)
        .handshake_timeout_secs(20);
    let resp = c.enable_didcomm(req).await.unwrap();
    assert_eq!(resp.new_version_id, "2-zVer");
    assert_eq!(resp.mediator_did, "did:peer:2.med");
}

#[tokio::test]
async fn enable_didcomm_409_maps_to_conflict() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/didcomm/enable"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error": "didcomm_already_enabled",
            "mediator_did": "did:peer:2.med"
        })))
        .mount(&server)
        .await;
    let c = client(&server).await;
    let err = c
        .enable_didcomm(EnableDidcommRequest::new("did:peer:2.med"))
        .await
        .unwrap_err();
    assert!(err.is_conflict(), "got {err:?}");
    match err {
        VtaError::Conflict(body) => {
            let body: Value = serde_json::from_str(&body).unwrap();
            assert_eq!(body["mediator_did"], "did:peer:2.med");
        }
        other => panic!("expected conflict, got {other:?}"),
    }
}

#[tokio::test]
async fn didcomm_status_gets_and_decodes_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/services/didcomm"))
        .and(auth())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "enabled": true,
            "mediator_did": "did:peer:2.med",
            "websocket_status": "connected"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    let resp = c.didcomm_status().await.unwrap();
    assert!(resp.enabled);
    assert_eq!(resp.mediator_did.as_deref(), Some("did:peer:2.med"));
    assert_eq!(resp.websocket_status.as_deref(), Some("connected"));
}

// ── disable_didcomm ─────────────────────────────────────────────────

#[tokio::test]
async fn disable_didcomm_with_immediate_drain() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/didcomm/disable"))
        .and(auth())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "new_version_id": "3-zVer",
            "prior_mediator_did": "did:peer:2.med",
            "drains_until": null
        })))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    let resp = c
        .disable_didcomm(DisableDidcommRequest::new(0))
        .await
        .unwrap();
    assert_eq!(resp.prior_mediator_did, "did:peer:2.med");
    assert!(resp.drains_until.is_none());
}

#[tokio::test]
async fn disable_didcomm_with_drain_window() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/didcomm/disable"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "new_version_id": "3-zVer",
            "prior_mediator_did": "did:peer:2.med",
            "drains_until": "2026-05-12T00:00:00Z"
        })))
        .mount(&server)
        .await;
    let c = client(&server).await;
    let resp = c
        .disable_didcomm(DisableDidcommRequest::new(3600))
        .await
        .unwrap();
    assert_eq!(resp.drains_until.as_deref(), Some("2026-05-12T00:00:00Z"));
}

// ── update_didcomm ────────────────────────────────────────────────

#[tokio::test]
async fn update_didcomm_posts_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/didcomm/update"))
        .and(auth())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "new_version_id": "4-zVer",
            "prior_mediator_did": "did:peer:2.old",
            "active_mediator_did": "did:peer:2.new",
            "active_mediator_endpoint": "https://new.mediator.example.com",
            "drains_until": "2026-05-12T00:00:00Z"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    let req = UpdateDidcommRequest::new("did:peer:2.new", 3600)
        .force(false)
        .rollback(true)
        .handshake_timeout_secs(15);
    let resp = c.update_didcomm(req).await.unwrap();
    assert_eq!(resp.active_mediator_did, "did:peer:2.new");
    assert_eq!(resp.prior_mediator_did, "did:peer:2.old");
}

#[tokio::test]
async fn update_didcomm_500_maps_to_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/didcomm/update"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"error": "handshake failed"})),
        )
        .mount(&server)
        .await;
    let c = client(&server).await;
    let err = c
        .update_didcomm(UpdateDidcommRequest::new("did:peer:2.new", 3600))
        .await
        .unwrap_err();
    match err {
        VtaError::Server { status, .. } => assert_eq!(status, 500),
        other => panic!("expected Server, got {other:?}"),
    }
}

// ── drain_cancel ────────────────────────────────────────────────────

#[tokio::test]
async fn drain_cancel_posts_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mediators/drain/cancel"))
        .and(auth())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "mediator_did": "did:peer:2.draining"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    let req = DrainCancelRequest {
        mediator_did: "did:peer:2.draining".into(),
    };
    let resp = c.drain_cancel(req).await.unwrap();
    assert_eq!(resp.mediator_did, "did:peer:2.draining");
}

#[tokio::test]
async fn drain_cancel_404_when_not_in_drain() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mediators/drain/cancel"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error": "not draining"})))
        .mount(&server)
        .await;
    let c = client(&server).await;
    let err = c
        .drain_cancel(DrainCancelRequest {
            mediator_did: "did:peer:2.x".into(),
        })
        .await
        .unwrap_err();
    assert!(err.is_not_found(), "got {err:?}");
}

// ── mediator_report ─────────────────────────────────────────────────

fn report_body() -> Value {
    json!({
        "since": "2026-05-01T00:00:00Z",
        "until": "2026-05-05T00:00:00Z",
        "mediators": [{
            "mediator_did": "did:peer:2.med",
            "inbound_count": 42,
            "first_seen": "2026-05-01T00:00:00Z",
            "last_seen": "2026-05-04T00:00:00Z"
        }],
        "senders": [{
            "sender_did": "did:key:zSender",
            "last_seen_mediator": "did:peer:2.med",
            "last_seen_at": "2026-05-04T12:00:00Z"
        }]
    })
}

#[tokio::test]
async fn mediator_report_no_query_params() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/mediators/report"))
        .and(auth())
        .respond_with(ResponseTemplate::new(200).set_body_json(report_body()))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    let resp = c.mediator_report(None, None).await.unwrap();
    assert_eq!(resp.mediators.len(), 1);
    assert_eq!(resp.mediators[0].inbound_count, 42);
    assert_eq!(resp.senders[0].last_seen_mediator, "did:peer:2.med");
}

#[tokio::test]
async fn mediator_report_with_since_until_url_encodes_timestamps() {
    let server = MockServer::start().await;
    // RFC 3339 timestamps contain `:` which must be %3A-encoded.
    // wiremock's `query_param` matches against the *decoded* value, so
    // assert on what the SDK conceptually sent: literal `:` after decode.
    Mock::given(method("GET"))
        .and(path("/mediators/report"))
        .and(auth())
        .and(query_param("since", "2026-05-01T00:00:00Z"))
        .and(query_param("until", "2026-05-05T00:00:00Z"))
        .respond_with(ResponseTemplate::new(200).set_body_json(report_body()))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    c.mediator_report(Some("2026-05-01T00:00:00Z"), Some("2026-05-05T00:00:00Z"))
        .await
        .unwrap();
}

#[tokio::test]
async fn mediator_report_only_since() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/mediators/report"))
        .and(query_param("since", "2026-05-01T00:00:00Z"))
        .respond_with(ResponseTemplate::new(200).set_body_json(report_body()))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    c.mediator_report(Some("2026-05-01T00:00:00Z"), None)
        .await
        .unwrap();
}

#[tokio::test]
async fn mediator_report_only_until() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/mediators/report"))
        .and(query_param("until", "2026-05-05T00:00:00Z"))
        .respond_with(ResponseTemplate::new(200).set_body_json(report_body()))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    c.mediator_report(None, Some("2026-05-05T00:00:00Z"))
        .await
        .unwrap();
}

#[tokio::test]
async fn mediator_report_403_when_not_authorized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/mediators/report"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"error": "no"})))
        .mount(&server)
        .await;
    let c = client(&server).await;
    let err = c.mediator_report(None, None).await.unwrap_err();
    assert!(err.is_auth(), "got {err:?}");
}
