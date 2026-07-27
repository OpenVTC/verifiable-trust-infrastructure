//! Community identity stays immutable at runtime after `/v1/config` was
//! retired (#710).
//!
//! The deleted legacy surface enforced this with an explicit 409: a
//! `PATCH /v1/config` carrying `vtc_did` or `vta_did` was refused before it
//! could strand the daemon auth-dead or re-point the recovery authority. That
//! check went away with the route, so this suite pins the guarantee on the two
//! surfaces that replaced it — where it holds *structurally* rather than by a
//! runtime branch:
//!
//! - `PATCH /v1/admin/config` (`spec/config/patch/0.1`) can only write keys in
//!   the config-store `REGISTRY`, which has four entries — `server.host`,
//!   `server.port`, `log.level`, `public_url`. Neither identity key is one, so
//!   both come back under `rejected`.
//! - `PUT /v1/community/profile` (`spec/vtc/community/profile/update/0.1`)
//!   deserialises into `CommunityProfileUpdate`, which has no `community_did`
//!   field at all. That is covered by `community_profile.rs`
//!   (`put_does_not_accept_community_did_in_request`).
//!
//! Also pinned here: `public_url`, the one legacy field whose owner is the
//! config-store overlay rather than the profile. `admin_config.rs` exercises
//! the pending-restart path with `server.port`; this suite does it with the
//! key the legacy PATCH actually wrote, so the migration of that field is
//! covered end to end.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vtc_service::config_store::ConfigStore;
use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

const SHOW_TASK: &str = "https://trusttasks.org/spec/config/show/0.1";
const PATCH_TASK: &str = "https://trusttasks.org/spec/config/patch/0.1";
/// The URI the deleted `GET, PATCH /v1/config` mount used to enforce.
const LEGACY_CONFIG_TASK: &str = "https://trusttasks.org/openvtc/vtc/config/legacy/manage/1.0";

struct Fixture {
    router: axum::Router,
    state: AppState,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    vtc: TestVtc,
}

async fn build() -> Fixture {
    build_with_audit(false).await
}

/// A patch that actually applies a key needs an audit writer — config
/// mutation is fail-closed (503 rather than a silent apply).
async fn build_with_audit(with_audit: bool) -> Fixture {
    let vtc = TestVtc::builder().with_audit(with_audit).build().await;
    Fixture {
        router: vtc.router.clone(),
        state: vtc.state.clone(),
        vtc,
    }
}

async fn admin_token(fix: &Fixture) -> String {
    fix.vtc.token("did:key:z6MkAdmin", "admin", vec![]).await
}

async fn send(
    fix: &Fixture,
    method: &str,
    uri: &str,
    task: Option<&str>,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {token}"));
    if let Some(task) = task {
        req = req.header("Trust-Task", task);
    }
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    let resp = fix
        .router
        .clone()
        .oneshot(req.body(body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, v)
}

/// The retired route is gone from the router, not merely un-gated.
///
/// Asserted on the response's media type rather than its status: the public
/// website is mounted as a catch-all fallback at `/`, so an unrouted `/v1/…`
/// path is answered by the website with HTML, not a 404. What matters is that
/// nothing serves the legacy config JSON any more.
#[tokio::test]
async fn legacy_config_surface_is_no_longer_routed() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    for method in ["GET", "PATCH"] {
        let req = Request::builder()
            .method(method)
            .uri("/v1/config")
            .header("content-type", "application/json")
            .header("Trust-Task", LEGACY_CONFIG_TASK)
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = fix.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(
            !content_type.starts_with("application/json"),
            "{method} /v1/config still answers with JSON ({status}): {}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

/// Neither identity key can be written through the canonical config patch —
/// they are not registry keys, so they are rejected rather than applied.
#[tokio::test]
async fn canonical_patch_cannot_rewrite_community_identity() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    let before = fix.state.config.read().await.vtc_did.clone();

    let (status, body) = send(
        &fix,
        "PATCH",
        "/v1/admin/config",
        Some(PATCH_TASK),
        &token,
        Some(json!({ "overrides": {
            "vtc_did": "did:key:zEvilNewIdentity",
            "vta_did": "did:key:zNewRecoveryAuthority",
        }})),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["applied"], json!([]), "nothing may be applied: {body}");
    let rejected: Vec<String> = body["rejected"]
        .as_array()
        .expect("rejected array")
        .iter()
        .map(|r| r["key"].as_str().expect("key").to_owned())
        .collect();
    assert!(
        rejected.contains(&"vtc_did".to_string()) && rejected.contains(&"vta_did".to_string()),
        "both identity keys must be rejected: {body}"
    );

    // And the running identity is untouched.
    assert_eq!(fix.state.config.read().await.vtc_did, before);
    assert_eq!(
        before.as_deref(),
        Some(vtc_service::test_support::TEST_VTC_DID)
    );
}

/// `public_url` — the one legacy field the profile does not own — round-trips
/// through the canonical patch: stored in the db-overlay, reported as
/// pending-restart, and deliberately *not* applied to the running config
/// (mutating it would diverge the live WebAuthn RP / status-list URLs from the
/// stored value).
#[tokio::test]
async fn canonical_patch_owns_public_url_and_defers_it_to_restart() {
    let fix = build_with_audit(true).await;
    let token = admin_token(&fix).await;
    let before = fix.state.config.read().await.public_url.clone();

    let (status, body) = send(
        &fix,
        "PATCH",
        "/v1/admin/config",
        Some(PATCH_TASK),
        &token,
        Some(json!({ "overrides": { "public_url": "https://vtc.example.com" }})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["applied"], json!([]), "boot-stable key: {body}");
    assert_eq!(body["pendingRestart"], json!(["public_url"]), "got {body}");
    assert_eq!(body["rejected"], json!([]), "got {body}");

    // Canonical store: the db-overlay (`config` keyspace), not config.toml.
    let store = ConfigStore::new(fix.state.config_ks.clone());
    assert_eq!(
        store.get("public_url").await.unwrap(),
        Some(json!("https://vtc.example.com")),
        "public_url must land in the config_store overlay"
    );

    // Running value untouched — applied only at the next boot.
    assert_eq!(fix.state.config.read().await.public_url, before);

    // …and the canonical read surface reflects the pending value.
    let (status, body) = send(
        &fix,
        "GET",
        "/v1/admin/config",
        Some(SHOW_TASK),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    let shown = body
        .as_object()
        .and_then(|_| serde_json::to_string(&body).ok())
        .expect("serialisable body");
    assert!(
        shown.contains("https://vtc.example.com"),
        "config/show must surface the pending public_url: {body}"
    );
}
