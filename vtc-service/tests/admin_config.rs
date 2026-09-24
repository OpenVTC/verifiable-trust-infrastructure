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
use vti_rooms_dtg::test_support::Party;

const SHOW_TASK: &str = "https://trusttasks.org/spec/config/show/0.1";
const PATCH_TASK: &str = "https://trusttasks.org/spec/config/patch/0.1";

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
        .header("Trust-Task", SHOW_TASK)
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
        .header("Trust-Task", SHOW_TASK)
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
        .header("Trust-Task", SHOW_TASK)
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
        .header("Trust-Task", PATCH_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"overrides":{"log.level":"debug"}}"#))
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
        .header("Trust-Task", SHOW_TASK)
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
        .header("Trust-Task", PATCH_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"overrides":{"server.port":9100}}"#))
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
        .header("Trust-Task", PATCH_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"overrides":{"made.up.key":"value"}}"#))
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
        .header("Trust-Task", PATCH_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"overrides":{"log.level":"verbose"}}"#)) // not in enum
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
    let body = json!({ "overrides": {
        "log.level": "debug",      // applied
        "server.port": 9100,        // pendingRestart
        "made.up": "x",             // rejected (unknown)
        "log.level_v2": "debug",    // rejected (unknown)
    }});
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", PATCH_TASK)
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
        .header("Trust-Task", PATCH_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"overrides":{"log.level":"debug"}}"#))
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
        .header("Trust-Task", PATCH_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"overrides":{}}"#))
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
        .header("Trust-Task", PATCH_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"overrides":{"log.level":"debug","server.port":9100}}"#,
        ))
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
        .header("Trust-Task", PATCH_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"overrides":{"made.up.key":"value"}}"#))
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
        .header("Trust-Task", PATCH_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"overrides":{"log.level":"debug"}}"#))
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
            "https://trusttasks.org/spec/vtc/community/profile/show/0.1",
        )
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

/// GET and PATCH share `/v1/admin/config` but carry **separate** canonical
/// Trust Tasks. Each verb must reject its *sibling's* task, not just some
/// unrelated one — otherwise the split is cosmetic and either task would
/// authorise either verb.
#[tokio::test]
async fn each_verb_rejects_its_siblings_trust_task() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;

    // GET presented with the PATCH task → 415.
    let req = Request::builder()
        .method("GET")
        .uri("/v1/admin/config")
        .header("Trust-Task", PATCH_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, _) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "GET must not accept the config/patch task"
    );

    // PATCH presented with the SHOW task → 415.
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", SHOW_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"overrides":{"log.level":"debug"}}"#))
        .unwrap();
    let (status, _) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "PATCH must not accept the config/show task"
    );
}

/// The PATCH body is the canonical `{"overrides": {...}}` envelope, not a
/// bare key→value map. A top-level config key is now an unknown member.
#[tokio::test]
async fn patch_rejects_the_pre_migration_flattened_body() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", PATCH_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"log.level":"debug"}"#))
        .unwrap();
    let (status, _) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the flattened pre-migration body must not be silently accepted"
    );
}

// ──────────────────────── Reload ────────────────────────

const RELOAD_TASK: &str = "https://trusttasks.org/spec/config/reload/0.1";
const RESTART_TASK: &str = "https://trusttasks.org/spec/config/restart/0.1";

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
        .header("Trust-Task", "https://trusttasks.org/spec/config/patch/0.1")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"overrides":{"log.level":"debug"}}"#))
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
//
// `vtc/config/{export,import}/0.1` declare `proof` REQUIRED, and since #1641
// phase 2 batch 3 they are served **only** as signed Trust Task documents at
// `POST /v1/trust-tasks`. The bearer routes `POST /v1/admin/config/{export,
// import}` were removed rather than kept as transitional paths: no client —
// the admin console, `vtc-client`, `cnm`, openvtc — called either. These tests
// drive the full router with signed documents, and authority is the signer's
// ACL row, read when the document is executed.
//
// Two tests went with the routes rather than being ported, because what they
// held no longer exists: `import_ignores_the_pre_migration_confirm_query_param`
// (a document has no query string) and the header-shaped Trust-Task gate.

const EXPORT_TASK: &str = "https://trusttasks.org/spec/vtc/config/export/0.1";
const IMPORT_TASK: &str = "https://trusttasks.org/spec/vtc/config/import/0.1";

// #1600 — the codes `vtc/config/import/0.1` declares, from the generated
// bindings.
const IMPORT_ERR_COMMUNITY_DID_MISMATCH: &str =
    trust_tasks_rs::specs::vtc::config::import::v0_1::error_codes::COMMUNITY_DID_MISMATCH.code;
const IMPORT_ERR_UNSUPPORTED_SCHEMA_VERSION: &str =
    trust_tasks_rs::specs::vtc::config::import::v0_1::error_codes::UNSUPPORTED_SCHEMA_VERSION.code;

/// The community DID every fixture profile carries — the test VTC's own.
const COMMUNITY_DID: &str = vtc_service::test_support::TEST_VTC_DID;

/// A fixture able to answer signed documents: the spine signs its replies, so
/// it needs the VTC's signers, which the bearer-route suites above do not.
async fn build_signed(with_audit: bool) -> Fixture {
    let vtc = TestVtc::builder()
        .with_audit(with_audit)
        .with_signers(true)
        .build()
        .await;
    Fixture {
        router: vtc.router.clone(),
        state: vtc.state.clone(),
        vtc,
    }
}

/// A signing identity with an ACL row of `role`.
async fn signer(fix: &Fixture, role: vtc_service::acl::VtcRole) -> Party {
    let party = Party::new();
    vtc_service::acl::store_acl_entry(
        &fix.state.acl_ks,
        &vtc_service::acl::VtcAclEntry {
            did: party.did.clone(),
            role,
            label: None,
            allowed_contexts: vec![],
            created_at: 0,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("seed ACL row");
    party
}

async fn admin(fix: &Fixture) -> Party {
    signer(fix, vtc_service::acl::VtcRole::Admin).await
}

/// POST `payload` as a `type_uri` document signed by `from`. Returns the HTTP
/// status and the reply document's `payload` — the response on success, the
/// `trust-task-error` body (with its `code`) on a refusal.
async fn post_signed(
    fix: &Fixture,
    from: &Party,
    type_uri: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let mut doc =
        vta_sdk::trust_task_sign::build_unsigned(type_uri, payload, &from.did, COMMUNITY_DID)
            .expect("build the document");
    let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(&from.did, &from.secret_multibase)
        .expect("a did:key names its own verification method");
    vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
        .await
        .expect("sign the document");

    let req = Request::builder()
        .method("POST")
        .uri("/v1/trust-tasks")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    (status, body["payload"].clone())
}

async fn export_signed(fix: &Fixture, from: &Party) -> (StatusCode, Value) {
    let (status, payload) = post_signed(fix, from, EXPORT_TASK, json!({})).await;
    // `vtc/config/export/0.1#response` wraps the portable document under
    // `document`; these tests assert on the document itself.
    let document = payload.get("document").cloned().unwrap_or(payload);
    (status, document)
}

/// `confirm` rides in the payload — one interface over every transport.
async fn import_signed(
    fix: &Fixture,
    from: &Party,
    confirm: bool,
    document: Value,
) -> (StatusCode, Value) {
    post_signed(
        fix,
        from,
        IMPORT_TASK,
        json!({ "document": document, "confirm": confirm }),
    )
    .await
}

/// The `code` of a `trust-task-error` reply payload — empty on a success.
fn tt_error_code(payload: &Value) -> &str {
    payload["code"].as_str().unwrap_or_default()
}

async fn seed_profile(fix: &Fixture) -> vtc_service::community::CommunityProfile {
    use vtc_service::community::CommunityProfile;
    let mut p = CommunityProfile::new(COMMUNITY_DID, "Example");
    p.description = "the original".to_string();
    vtc_service::community::store_profile(&fix.state.community_ks, &p)
        .await
        .unwrap();
    p
}

/// A schema-valid document carrying a profile named `name` in `language`.
fn document_with_profile(community_did: &str, name: &str, language: &str) -> Value {
    json!({
        "schemaVersion": 1,
        "exportedAt": "2026-05-12T03:42:00Z",
        "communityProfile": {
            "communityDid": community_did,
            "name": name,
            "description": "the original",
            "language": language,
            "createdAt": "2026-05-12T00:00:00Z"
        },
        "configOverrides": { "log.level": "debug" }
    })
}

/// A schema-valid document carrying only `overrides`.
fn document_with_overrides(overrides: Value) -> Value {
    json!({
        "schemaVersion": 1,
        "exportedAt": "2026-05-12T03:42:00Z",
        "configOverrides": overrides
    })
}

#[tokio::test]
async fn export_empty_fresh_install_returns_v1_schema_no_profile_no_overrides() {
    let fix = build_signed(true).await;
    let admin = admin(&fix).await;
    let (status, body) = export_signed(&fix, &admin).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["schemaVersion"], 1);
    assert!(body["communityProfile"].is_null());
    assert_eq!(body["configOverrides"], json!({}));
    assert!(body["exportedAt"].as_str().unwrap().contains("T"));
}

#[tokio::test]
async fn export_includes_profile_and_db_overrides() {
    let fix = build_signed(true).await;
    let admin = admin(&fix).await;
    seed_profile(&fix).await;
    vtc_service::config_store::ConfigStore::new(fix.state.config_ks.clone())
        .put("log.level", &json!("debug"))
        .await
        .unwrap();

    let (status, body) = export_signed(&fix, &admin).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["communityProfile"]["name"], "Example");
    assert_eq!(body["communityProfile"]["description"], "the original");
    assert_eq!(body["configOverrides"]["log.level"], "debug");
}

#[tokio::test]
async fn export_requires_admin_role() {
    let fix = build_signed(true).await;
    let member = signer(&fix, vtc_service::acl::VtcRole::Member).await;
    let (_, body) = export_signed(&fix, &member).await;
    assert_eq!(tt_error_code(&body), "permissionDenied", "{body}");
}

/// The signed door is the only one: the bearer route is gone, not merely
/// undocumented, so a bearer-token call finds nothing to answer it.
#[tokio::test]
async fn the_bearer_routes_are_gone() {
    let fix = build_signed(true).await;
    let token = token_for(&fix, "admin").await;
    for (uri, task) in [
        ("/v1/admin/config/export", EXPORT_TASK),
        ("/v1/admin/config/import", IMPORT_TASK),
    ] {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("Trust-Task", task)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let resp = fix.router.clone().oneshot(req).await.unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ),
            "{uri} must no longer be served; got {}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn import_dry_run_returns_diff_without_persisting() {
    let fix = build_signed(true).await;
    let admin = admin(&fix).await;
    seed_profile(&fix).await;

    let document = document_with_profile(COMMUNITY_DID, "Renamed", "en");
    let (status, body) = import_signed(&fix, &admin, false, document).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "preview");

    // Diff lists the changed name + the new db-layer override.
    let profile_keys: Vec<_> = body["profileChanges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["key"].as_str().unwrap().to_string())
        .collect();
    assert!(profile_keys.contains(&"name".to_string()));
    let overrides_keys: Vec<_> = body["overrideChanges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["key"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(overrides_keys, vec!["log.level"]);

    // `log.level` is hot-reloadable, so a preview of it implies no downtime.
    assert_eq!(body["pendingRestart"], json!([]));

    // Live profile unchanged.
    let live = vtc_service::community::load_profile(&fix.state.community_ks)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(live.name, "Example");
}

#[tokio::test]
async fn import_confirm_applies_profile_and_overrides() {
    let fix = build_signed(true).await;
    let admin = admin(&fix).await;
    seed_profile(&fix).await;

    let document = document_with_profile(COMMUNITY_DID, "Renamed", "fr");
    let (status, body) = import_signed(&fix, &admin, true, document).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "imported");

    // On `imported` the change arrays carry what was actually written, so the
    // applied fields are read off them rather than a separate list.
    let applied: Vec<_> = body["profileChanges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["key"].as_str().unwrap().to_string())
        .collect();
    assert!(applied.contains(&"name".to_string()));
    assert!(applied.contains(&"language".to_string()));
    let overrides_applied: Vec<_> = body["overrideChanges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["key"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(overrides_applied, vec!["log.level"]);

    // Live profile reflects the import.
    let live = vtc_service::community::load_profile(&fix.state.community_ks)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(live.name, "Renamed");
    assert_eq!(live.language, "fr");

    // Both audit events landed, and both name the signer — the key that
    // authored the document, not a session.
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
                assert_eq!(env.actor_did_plain.as_deref(), Some(admin.did.as_str()));
            }
            vti_common::audit::AuditEvent::ConfigChanged(_) => {
                saw_config = true;
                assert_eq!(env.actor_did_plain.as_deref(), Some(admin.did.as_str()));
            }
            _ => {}
        }
    }
    assert!(saw_profile, "CommunityProfileUpdated missing");
    assert!(saw_config, "ConfigChanged missing");
}

#[tokio::test]
async fn import_refuses_mismatched_community_did() {
    let fix = build_signed(true).await;
    let admin = admin(&fix).await;
    seed_profile(&fix).await;

    let document = document_with_profile("did:webvh:OTHER.example.com:xyz", "Foreign", "en");
    let (_, body) = import_signed(&fix, &admin, true, document).await;
    assert_eq!(
        tt_error_code(&body),
        IMPORT_ERR_COMMUNITY_DID_MISMATCH,
        "{body}"
    );
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("communityDid"),
        "{body}"
    );
}

#[tokio::test]
async fn import_round_trip_export_then_import_equivalence() {
    // Set up source VTC with profile + override, export.
    let src = build_signed(true).await;
    let src_admin = admin(&src).await;
    seed_profile(&src).await;
    vtc_service::config_store::ConfigStore::new(src.state.config_ks.clone())
        .put("log.level", &json!("debug"))
        .await
        .unwrap();
    let (_, exported) = export_signed(&src, &src_admin).await;

    // Fresh VTC: import the export, confirm.
    let dst = build_signed(true).await;
    let dst_admin = admin(&dst).await;
    let (status, body) = import_signed(&dst, &dst_admin, true, exported.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Export the destination and confirm it round-trips.
    let (_, dst_exported) = export_signed(&dst, &dst_admin).await;

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
    let fix = build_signed(true).await;
    let admin = admin(&fix).await;
    let document = document_with_overrides(json!({ "godmode.enable": true }));
    let (status, body) = import_signed(&fix, &admin, true, document).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rejected = body["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["key"], "godmode.enable");
}

#[tokio::test]
async fn import_rejects_invalid_value_with_reason() {
    let fix = build_signed(true).await;
    let admin = admin(&fix).await;
    let document = document_with_overrides(json!({ "log.level": "shouting" }));
    let (status, body) = import_signed(&fix, &admin, true, document).await;
    assert_eq!(status, StatusCode::OK, "{body}");
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
async fn import_wrong_schema_version_is_refused() {
    let fix = build_signed(true).await;
    let admin = admin(&fix).await;
    let mut document = document_with_overrides(json!({}));
    document["schemaVersion"] = json!(99);
    let (_, body) = import_signed(&fix, &admin, false, document).await;
    assert_eq!(
        tt_error_code(&body),
        IMPORT_ERR_UNSUPPORTED_SCHEMA_VERSION,
        "{body}"
    );
}

/// Applying is fail-closed on audit: a change that cannot be recorded is not
/// made.
#[tokio::test]
async fn import_apply_is_refused_when_audit_writer_missing() {
    let fix = build_signed(false).await;
    let admin = admin(&fix).await;
    let document = document_with_overrides(json!({ "log.level": "debug" }));
    let (status, body) = import_signed(&fix, &admin, true, document).await;
    assert!(!status.is_success(), "{status} {body}");
    assert!(
        !tt_error_code(&body).is_empty(),
        "a refusal carries a code: {body}"
    );
    let store = vtc_service::config_store::ConfigStore::new(fix.state.config_ks.clone());
    assert_eq!(store.get("log.level").await.unwrap(), None);
}

#[tokio::test]
async fn import_dry_run_works_without_audit_writer() {
    // Pure dry-run never emits an audit event, so refusing it for want of an
    // audit writer would be the wrong answer — the diff comes back.
    let fix = build_signed(false).await;
    let admin = admin(&fix).await;
    let document = document_with_overrides(json!({ "log.level": "debug" }));
    let (status, body) = import_signed(&fix, &admin, false, document).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "preview");
}

/// A restart-gated key is reported as `pendingRestart` on the **preview**, not
/// only after applying. An operator should learn that confirming implies
/// downtime while they are still deciding whether to confirm.
#[tokio::test]
async fn import_preview_reports_pending_restart_before_confirming() {
    let fix = build_signed(true).await;
    let admin = admin(&fix).await;
    let document = document_with_overrides(json!({ "server.port": 9100 }));

    let (status, body) = import_signed(&fix, &admin, false, document.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "preview");
    assert_eq!(body["pendingRestart"], json!(["server.port"]), "{body}");

    // Nothing was written — the preview said so, and the store agrees.
    let store = vtc_service::config_store::ConfigStore::new(fix.state.config_ks.clone());
    assert_eq!(store.get("server.port").await.unwrap(), None);

    // …and confirming reports the same key, now actually applied.
    let (status, body) = import_signed(&fix, &admin, true, document).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "imported");
    assert_eq!(body["pendingRestart"], json!(["server.port"]), "{body}");
    assert_eq!(store.get("server.port").await.unwrap(), Some(json!(9100)));
}

/// The document is the payload's own member, so an unknown top-level member is
/// refused rather than silently dropped — the canonical payload is
/// `additionalProperties: false`.
#[tokio::test]
async fn import_rejects_an_unknown_top_level_member() {
    let fix = build_signed(true).await;
    let admin = admin(&fix).await;
    let (_, body) = post_signed(
        &fix,
        &admin,
        IMPORT_TASK,
        json!({
            "document": document_with_overrides(json!({})),
            "__notARealMember__": true
        }),
    )
    .await;
    assert_eq!(tt_error_code(&body), "malformedRequest", "{body}");
}

/// An import onto a VTC with **no stored profile** meets the same caps an edit
/// does. It used to store the imported profile verbatim, so it was the one way
/// to publish a `javascript:` logo URL on the unauthenticated public-profile
/// page — every other path goes through `CommunityProfileUpdate::apply`.
#[tokio::test]
async fn an_import_with_no_stored_profile_meets_the_edit_caps() {
    let fix = build_signed(true).await;
    let admin = admin(&fix).await;
    let mut document = document_with_profile(COMMUNITY_DID, "Imported", "en");
    document["communityProfile"]["logoUrl"] = json!("javascript:alert(1)");

    let (status, body) = import_signed(&fix, &admin, true, document).await;
    assert!(!status.is_success(), "{status} {body}");
    assert_eq!(tt_error_code(&body), "malformedRequest", "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("logoUrl"),
        "the refusal names the member: {body}"
    );
    assert!(
        vtc_service::community::load_profile(&fix.state.community_ks)
            .await
            .unwrap()
            .is_none(),
        "a refused import must not store a profile"
    );
}

/// With no stored profile, an import that passes the caps is stored — keeping
/// the imported `createdAt` — and reports the members it set.
#[tokio::test]
async fn an_import_with_no_stored_profile_stores_it_and_reports_the_members() {
    let fix = build_signed(true).await;
    let admin = admin(&fix).await;
    let document = document_with_profile(COMMUNITY_DID, "Imported", "fr");

    let (status, body) = import_signed(&fix, &admin, true, document).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let applied: Vec<_> = body["profileChanges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["key"].as_str().unwrap().to_string())
        .collect();
    for key in ["name", "description", "language"] {
        assert!(applied.contains(&key.to_string()), "{key}: {body}");
    }

    let stored = vtc_service::community::load_profile(&fix.state.community_ks)
        .await
        .unwrap()
        .expect("the import stored a profile");
    assert_eq!(stored.community_did, COMMUNITY_DID);
    assert_eq!(stored.name, "Imported");
    assert_eq!(stored.language, "fr");
    assert_eq!(stored.created_at.to_rfc3339(), "2026-05-12T00:00:00+00:00");
}
