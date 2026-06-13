//! Integration coverage for `/v1/admin/config`.
//!
//! Exercises the full router stack — Trust-Task header → AdminAuth
//! extractor → handler → three-layer effective view → db-overlay
//! persistence — via `Router::oneshot`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

const CONFIG_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/config/manage/1.0";

/// Thin wrapper over [`TestVtc`] preserving this suite's original
/// fixture API (`fix.router`, `fix.state`). The keyspace + `AppState`
/// wiring now lives in `vtc_service::test_support`.
struct Fixture {
    router: axum::Router,
    state: AppState,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    vtc: TestVtc,
}

async fn build() -> Fixture {
    build_with(false, None).await
}

async fn build_with(
    with_audit: bool,
    supervisor: Option<vtc_service::supervisor::SupervisorKind>,
) -> Fixture {
    let vtc = TestVtc::builder()
        .with_audit(with_audit)
        .supervisor(supervisor)
        .build()
        .await;
    Fixture {
        router: vtc.router.clone(),
        state: vtc.state.clone(),
        vtc,
    }
}

async fn token_for(fix: &Fixture, role: &str) -> String {
    fix.vtc.token("did:key:z6MkAdmin", role, vec![]).await
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

// ──────────────────────── GET ────────────────────────

#[tokio::test]
async fn get_returns_effective_config_with_defaults() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);

    let fields = body["fields"].as_array().unwrap();
    let by_key: std::collections::HashMap<_, _> = fields
        .iter()
        .map(|f| (f["key"].as_str().unwrap(), f))
        .collect();

    assert_eq!(by_key["server.host"]["value"], "0.0.0.0");
    assert_eq!(by_key["server.host"]["source"], "default");
    assert_eq!(by_key["server.host"]["requiresRestart"], true);

    assert_eq!(by_key["server.port"]["value"], 8200);
    assert_eq!(by_key["server.port"]["source"], "default");

    assert_eq!(by_key["log.level"]["value"], "info");
    assert_eq!(by_key["log.level"]["source"], "default");
    assert_eq!(by_key["log.level"]["requiresRestart"], false);
}

#[tokio::test]
async fn get_requires_admin_role() {
    let fix = build().await;
    let token = token_for(&fix, "reader").await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn get_requires_authentication() {
    let fix = build().await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ──────────────────────── PATCH ────────────────────────

#[tokio::test]
async fn patch_applies_reloadable_key_immediately() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"log.level":"debug"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], json!(["log.level"]));
    assert_eq!(body["pendingRestart"], json!([]));
    assert_eq!(body["rejected"], json!([]));

    // GET reflects the new value with source = db.
    let req = Request::builder()
        .method("GET")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (_, body) = body_value(resp).await;
    let level = body["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["key"] == "log.level")
        .unwrap();
    assert_eq!(level["value"], "debug");
    assert_eq!(level["source"], "db");
}

#[tokio::test]
async fn patch_restart_required_key_is_pending() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"server.port":9100}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], json!([]));
    assert_eq!(body["pendingRestart"], json!(["server.port"]));
    assert_eq!(body["rejected"], json!([]));
}

#[tokio::test]
async fn patch_unknown_key_rejected_with_reason() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"made.up.key":"value"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    let rejected = body["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["key"], "made.up.key");
    assert!(
        rejected[0]["reason"]
            .as_str()
            .unwrap()
            .contains("unknown config key")
    );
}

#[tokio::test]
async fn patch_invalid_value_rejected_with_reason() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"log.level":"verbose"}"#)) // not in enum
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    let rejected = body["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["key"], "log.level");
    assert!(
        rejected[0]["reason"]
            .as_str()
            .unwrap()
            .contains("must be one of")
    );
}

#[tokio::test]
async fn patch_mixed_batch_partitions_correctly() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    let body = json!({
        "log.level": "debug",      // applied
        "server.port": 9100,        // pendingRestart
        "made.up": "x",             // rejected (unknown)
        "log.level_v2": "debug",    // rejected (unknown)
    });
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(body["applied"], json!(["log.level"]));
    assert_eq!(body["pendingRestart"], json!(["server.port"]));
    let rejected: Vec<&str> = body["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["key"].as_str().unwrap())
        .collect();
    assert_eq!(rejected.len(), 2);
    assert!(rejected.contains(&"made.up"));
    assert!(rejected.contains(&"log.level_v2"));
}

#[tokio::test]
async fn patch_requires_admin_role() {
    let fix = build().await;
    let token = token_for(&fix, "reader").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"log.level":"debug"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn patch_empty_body_returns_empty_response() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], json!([]));
    assert_eq!(body["pendingRestart"], json!([]));
    assert_eq!(body["rejected"], json!([]));
}

#[tokio::test]
async fn patch_emits_config_changed_audit_with_real_actor() {
    use vti_common::audit::{AuditEnvelope, AuditEvent};

    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"log.level":"debug","server.port":9100}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);

    let raw = fix
        .state
        .audit_ks
        .prefix_iter_raw(b"2".to_vec())
        .await
        .unwrap();
    let envelopes: Vec<AuditEnvelope> = raw
        .iter()
        .map(|(_, v)| serde_json::from_slice(v).unwrap())
        .collect();
    let changed: Vec<&AuditEnvelope> = envelopes
        .iter()
        .filter(|e| matches!(e.event, AuditEvent::ConfigChanged(_)))
        .collect();
    assert_eq!(changed.len(), 1, "exactly one ConfigChanged envelope");
    let env = changed[0];
    // Actor is the calling admin's real DID, not the old sentinel.
    assert_eq!(env.actor_did_plain.as_deref(), Some("did:key:z6MkAdmin"));
    let AuditEvent::ConfigChanged(data) = &env.event else {
        unreachable!()
    };
    assert!(
        data.requires_restart,
        "server.port change flags requires_restart"
    );
    let keys: Vec<&str> = data.changes.iter().map(|c| c.key.as_str()).collect();
    assert!(keys.contains(&"log.level"));
    assert!(keys.contains(&"server.port"));
}

#[tokio::test]
async fn patch_rejects_only_does_not_need_audit_writer() {
    // A PATCH that applies nothing (only rejects) emits no audit, so
    // it must not 503 even when no AuditWriter is configured.
    let fix = build_with(false, None).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"made.up.key":"value"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], json!([]));
    assert_eq!(body["rejected"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn patch_503_when_audit_writer_missing() {
    // A PATCH that would apply a real change is refused (fail-closed)
    // when the change can't be audited.
    let fix = build_with(false, None).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"log.level":"debug"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

// ──────────────────────── Trust-Task gate ────────────────────────

#[tokio::test]
async fn get_with_wrong_trust_task_returns_415() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/admin/config")
        .header(
            "Trust-Task",
            "https://trusttasks.org/openvtc/vtc/community/profile/manage/1.0",
        )
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ──────────────────────── Reload ────────────────────────

const RELOAD_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/config/reload/1.0";
const RESTART_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/config/restart/1.0";

async fn reload(fix: &Fixture, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/config/reload")
        .header("Trust-Task", RELOAD_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    body_value(resp).await
}

async fn restart(fix: &Fixture, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/config/restart")
        .header("Trust-Task", RESTART_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    body_value(resp).await
}

#[tokio::test]
async fn reload_no_diff_returns_empty_keys_reloaded() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    let (status, body) = reload(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["keysReloaded"], json!([]));
}

#[tokio::test]
async fn reload_applies_hot_reloadable_diff() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;

    // Write `log.level = "debug"` via PATCH so the db-layer differs
    // from the live in-memory `info`. reload must pick up the
    // delta.
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header(
            "Trust-Task",
            "https://trusttasks.org/openvtc/vtc/admin/config/manage/1.0",
        )
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"log.level":"debug"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = reload(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["keysReloaded"], json!(["log.level"]));

    // In-memory `AppConfig.log.level` now reflects the new value.
    assert_eq!(fix.state.config.read().await.log.level, "debug");

    // Second reload is a no-op (no diff left).
    let (_, body) = reload(&fix, &token).await;
    assert_eq!(body["keysReloaded"], json!([]));
}

#[tokio::test]
async fn reload_requires_admin_role() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "reader").await;
    let (status, _) = reload(&fix, &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reload_503_when_audit_writer_missing() {
    let fix = build_with(false, None).await;
    let token = token_for(&fix, "admin").await;
    let (status, _) = reload(&fix, &token).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

// ──────────────────────── Restart ────────────────────────

#[tokio::test]
async fn restart_without_supervisor_returns_412() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    let (status, body) = restart(&fix, &token).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("SupervisorRequired"),
        "got {body}",
    );
}

#[tokio::test]
async fn restart_with_supervisor_triggers_shutdown() {
    use vtc_service::supervisor::SupervisorKind;
    let fix = build_with(true, Some(SupervisorKind::Manual)).await;
    let token = token_for(&fix, "admin").await;

    // Subscribe to the shutdown channel BEFORE the request so we
    // can assert the flip.
    let mut rx = fix.state.shutdown_tx.subscribe();
    assert!(!*rx.borrow_and_update());

    let (status, body) = restart(&fix, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["supervisor"], "manual");
    assert!(body["drainTimeoutSeconds"].as_u64().unwrap() > 0);

    // Shutdown was signalled.
    assert!(*rx.borrow_and_update());
}

#[tokio::test]
async fn restart_emits_audit_event_before_signal() {
    use vtc_service::supervisor::SupervisorKind;
    let fix = build_with(true, Some(SupervisorKind::Systemd)).await;
    let token = token_for(&fix, "admin").await;

    let (status, _) = restart(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);

    // Confirm exactly one RestartRequested envelope landed.
    let raw = fix
        .state
        .audit_ks
        .prefix_iter_raw(b"2".to_vec())
        .await
        .unwrap();
    let envelopes: Vec<vti_common::audit::AuditEnvelope> = raw
        .iter()
        .map(|(_, v)| serde_json::from_slice(v).unwrap())
        .collect();
    let restart_events: Vec<_> = envelopes
        .iter()
        .filter(|e| matches!(e.event, vti_common::audit::AuditEvent::RestartRequested(_)))
        .collect();
    assert_eq!(restart_events.len(), 1);
}

#[tokio::test]
async fn restart_requires_admin_role() {
    use vtc_service::supervisor::SupervisorKind;
    let fix = build_with(true, Some(SupervisorKind::Manual)).await;
    let token = token_for(&fix, "reader").await;
    let (status, _) = restart(&fix, &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn restart_503_when_audit_writer_missing() {
    use vtc_service::supervisor::SupervisorKind;
    let fix = build_with(false, Some(SupervisorKind::Manual)).await;
    let token = token_for(&fix, "admin").await;
    let (status, _) = restart(&fix, &token).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn restart_wrong_trust_task_returns_415() {
    use vtc_service::supervisor::SupervisorKind;
    let fix = build_with(true, Some(SupervisorKind::Manual)).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/config/restart")
        .header("Trust-Task", RELOAD_TASK) // wrong
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _) = body_value(resp).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ──────────────────────── Export / Import ────────────────────────

const EXPORT_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/config/export/1.0";
const IMPORT_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/config/import/1.0";

async fn export_post(fix: &Fixture, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/config/export")
        .header("Trust-Task", EXPORT_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    body_value(resp).await
}

async fn import_post(
    fix: &Fixture,
    token: &str,
    confirm: bool,
    body: Value,
) -> (StatusCode, Value) {
    let uri = if confirm {
        "/v1/admin/config/import?confirm=true"
    } else {
        "/v1/admin/config/import"
    };
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("Trust-Task", IMPORT_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    body_value(resp).await
}

async fn seed_profile(fix: &Fixture) -> vtc_service::community::CommunityProfile {
    use vtc_service::community::CommunityProfile;
    let mut p = CommunityProfile::new("did:webvh:vtc.example.com:abc", "Example");
    p.description = "the original".to_string();
    vtc_service::community::store_profile(&fix.state.community_ks, &p)
        .await
        .unwrap();
    p
}

#[tokio::test]
async fn export_empty_fresh_install_returns_v1_schema_no_profile_no_overrides() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    let (status, body) = export_post(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["schemaVersion"], 1);
    assert!(body["communityProfile"].is_null());
    assert_eq!(body["configOverrides"], json!({}));
    assert!(body["exportedAt"].as_str().unwrap().contains("T"));
}

#[tokio::test]
async fn export_includes_profile_and_db_overrides() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    seed_profile(&fix).await;

    // Seed a db-layer override via PATCH so the export reflects it.
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"log.level":"debug"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (status, body) = export_post(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["communityProfile"]["name"], "Example");
    assert_eq!(body["communityProfile"]["description"], "the original");
    assert_eq!(body["configOverrides"]["log.level"], "debug");
}

#[tokio::test]
async fn export_requires_admin_role() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "reader").await;
    let (status, _) = export_post(&fix, &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn import_dry_run_returns_diff_without_persisting() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    seed_profile(&fix).await;

    let payload = json!({
        "schemaVersion": 1,
        "exportedAt": "2026-05-12T03:42:00Z",
        "communityProfile": {
            "communityDid": "did:webvh:vtc.example.com:abc",
            "name": "Renamed",
            "description": "the original",
            "logoUrl": null,
            "publicUrl": null,
            "contactEmail": null,
            "language": "en",
            "createdAt": "2026-05-12T00:00:00Z",
            "extensions": null
        },
        "configOverrides": { "log.level": "debug" }
    });
    let (status, body) = import_post(&fix, &token, false, payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["confirmed"], false);

    // Diff lists the changed name + the new db-layer override.
    let profile_keys: Vec<_> = body["communityProfileDiff"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["key"].as_str().unwrap().to_string())
        .collect();
    assert!(profile_keys.contains(&"name".to_string()));
    let overrides_keys: Vec<_> = body["configOverridesDiff"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["key"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(overrides_keys, vec!["log.level"]);

    // Nothing applied.
    assert_eq!(body["communityProfileApplied"], json!([]));
    assert_eq!(body["configOverridesApplied"], json!([]));

    // Live profile unchanged.
    let live = vtc_service::community::load_profile(&fix.state.community_ks)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(live.name, "Example");
}

#[tokio::test]
async fn import_confirm_applies_profile_and_overrides() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    seed_profile(&fix).await;

    let payload = json!({
        "schemaVersion": 1,
        "exportedAt": "2026-05-12T03:42:00Z",
        "communityProfile": {
            "communityDid": "did:webvh:vtc.example.com:abc",
            "name": "Renamed",
            "description": "the original",
            "logoUrl": null,
            "publicUrl": null,
            "contactEmail": null,
            "language": "fr",
            "createdAt": "2026-05-12T00:00:00Z",
            "extensions": null
        },
        "configOverrides": { "log.level": "debug" }
    });
    let (status, body) = import_post(&fix, &token, true, payload).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["confirmed"], true);

    let applied: Vec<_> = body["communityProfileApplied"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(applied.contains(&"name".to_string()));
    assert!(applied.contains(&"language".to_string()));
    assert_eq!(body["configOverridesApplied"], json!(["log.level"]));

    // Live profile reflects the import.
    let live = vtc_service::community::load_profile(&fix.state.community_ks)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(live.name, "Renamed");
    assert_eq!(live.language, "fr");

    // Both audit events landed.
    let raw = fix
        .state
        .audit_ks
        .prefix_iter_raw(b"2".to_vec())
        .await
        .unwrap();
    let envelopes: Vec<vti_common::audit::AuditEnvelope> = raw
        .iter()
        .map(|(_, v)| serde_json::from_slice(v).unwrap())
        .collect();
    let mut saw_profile = false;
    let mut saw_config = false;
    for env in &envelopes {
        match &env.event {
            vti_common::audit::AuditEvent::CommunityProfileUpdated(_) => {
                saw_profile = true;
                // Actor is the importing admin's real DID, not the sentinel.
                assert_eq!(env.actor_did_plain.as_deref(), Some("did:key:z6MkAdmin"));
            }
            vti_common::audit::AuditEvent::ConfigChanged(_) => {
                saw_config = true;
                assert_eq!(env.actor_did_plain.as_deref(), Some("did:key:z6MkAdmin"));
            }
            _ => {}
        }
    }
    assert!(saw_profile, "CommunityProfileUpdated missing");
    assert!(saw_config, "ConfigChanged missing");
}

#[tokio::test]
async fn import_refuses_mismatched_community_did_with_409() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    seed_profile(&fix).await;

    let payload = json!({
        "schemaVersion": 1,
        "exportedAt": "2026-05-12T03:42:00Z",
        "communityProfile": {
            "communityDid": "did:webvh:OTHER.example.com:xyz",
            "name": "Foreign",
            "description": "",
            "logoUrl": null,
            "publicUrl": null,
            "contactEmail": null,
            "language": "en",
            "createdAt": "2026-05-12T00:00:00Z",
            "extensions": null
        },
        "configOverrides": {}
    });
    let (status, body) = import_post(&fix, &token, true, payload).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["error"].as_str().unwrap().contains("communityDid"));
}

#[tokio::test]
async fn import_round_trip_export_then_import_equivalence() {
    // Set up source VTC with profile + override, export.
    let src = build_with(true, None).await;
    let token = token_for(&src, "admin").await;
    seed_profile(&src).await;

    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"log.level":"debug"}"#))
        .unwrap();
    let _ = src.router.clone().oneshot(req).await.unwrap();

    let (_, exported) = export_post(&src, &token).await;

    // Fresh VTC: import the export, confirm.
    let dst = build_with(true, None).await;
    let dst_token = token_for(&dst, "admin").await;
    let (status, body) = import_post(&dst, &dst_token, true, exported.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Export the destination and confirm it round-trips.
    let (_, dst_exported) = export_post(&dst, &dst_token).await;

    // Compare semantically — `exportedAt` differs, but
    // `communityProfile` (minus `createdAt`, which we accept varying
    // across instances) and `configOverrides` must match.
    let strip_volatile = |mut v: Value| -> Value {
        v["exportedAt"] = json!("<stripped>");
        if let Some(p) = v.get_mut("communityProfile")
            && let Some(o) = p.as_object_mut()
        {
            o.insert("createdAt".to_string(), json!("<stripped>"));
        }
        v
    };
    assert_eq!(strip_volatile(exported), strip_volatile(dst_exported));
}

#[tokio::test]
async fn import_rejects_unknown_config_key() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    let payload = json!({
        "schemaVersion": 1,
        "exportedAt": "2026-05-12T03:42:00Z",
        "communityProfile": null,
        "configOverrides": { "godmode.enable": true }
    });
    let (status, body) = import_post(&fix, &token, true, payload).await;
    assert_eq!(status, StatusCode::OK);
    let rejected = body["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["key"], "godmode.enable");
}

#[tokio::test]
async fn import_rejects_invalid_value_with_reason() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    let payload = json!({
        "schemaVersion": 1,
        "exportedAt": "2026-05-12T03:42:00Z",
        "communityProfile": null,
        "configOverrides": { "log.level": "shouting" }
    });
    let (status, body) = import_post(&fix, &token, true, payload).await;
    assert_eq!(status, StatusCode::OK);
    let rejected = body["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["key"], "log.level");
    assert!(
        rejected[0]["reason"]
            .as_str()
            .unwrap()
            .contains("validation failed"),
        "got {}",
        rejected[0]["reason"]
    );
}

#[tokio::test]
async fn import_wrong_schema_version_returns_400() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    let payload = json!({
        "schemaVersion": 99,
        "exportedAt": "2026-05-12T03:42:00Z",
        "communityProfile": null,
        "configOverrides": {}
    });
    let (status, _) = import_post(&fix, &token, false, payload).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn import_apply_503_when_audit_writer_missing() {
    let fix = build_with(false, None).await;
    let token = token_for(&fix, "admin").await;
    let payload = json!({
        "schemaVersion": 1,
        "exportedAt": "2026-05-12T03:42:00Z",
        "communityProfile": null,
        "configOverrides": { "log.level": "debug" }
    });
    let (status, _) = import_post(&fix, &token, true, payload).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn import_dry_run_works_without_audit_writer() {
    // Pure dry-run never emits an audit event, so 503 is the wrong
    // answer — we should return 200 with the diff.
    let fix = build_with(false, None).await;
    let token = token_for(&fix, "admin").await;
    let payload = json!({
        "schemaVersion": 1,
        "exportedAt": "2026-05-12T03:42:00Z",
        "communityProfile": null,
        "configOverrides": { "log.level": "debug" }
    });
    let (status, body) = import_post(&fix, &token, false, payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["confirmed"], false);
}
