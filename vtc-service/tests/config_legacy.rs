//! Integration coverage for the legacy `/v1/config` surface (P1.1).
//!
//! Exercises the full router stack — Trust-Task header → auth extractor →
//! handler → community/config keyspaces — through `Router::oneshot`, pinning
//! the P1.1 invariants: identity is immutable at runtime, `CommunityProfile`
//! owns name/description, and a boot-stable key reports `pending_restart`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vtc_service::community::{CommunityProfile, store_profile};
use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

const CONFIG_TASK: &str = "https://trusttasks.org/openvtc/vtc/config/legacy/manage/1.0";
const ADMIN_DID: &str = "did:key:z6MkAdmin";

struct Fixture {
    router: axum::Router,
    state: AppState,
    vtc: TestVtc,
}

async fn build() -> Fixture {
    let vtc = TestVtc::builder().build().await;
    Fixture {
        router: vtc.router.clone(),
        state: vtc.state.clone(),
        vtc,
    }
}

/// Super-admin = admin role + empty `allowed_contexts`.
async fn super_admin_token(fix: &Fixture) -> String {
    fix.vtc.token(ADMIN_DID, "admin", vec![]).await
}

async fn send(
    fix: &Fixture,
    method: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri("/v1/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {token}"));
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

async fn seed_profile(fix: &Fixture, name: &str) {
    let p = CommunityProfile::new("did:webvh:vtc.example.com:abc", name);
    store_profile(&fix.state.community_ks, &p).await.unwrap();
}

#[tokio::test]
async fn patch_vtc_did_is_rejected_409() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    // The request body is snake_case (no rename_all on `UpdateConfigRequest`).
    let (status, body) = send(
        &fix,
        "PATCH",
        &token,
        Some(json!({ "vtc_did": "did:key:zEvilNewIdentity" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "vtc_did rewrite must be refused: {body}"
    );
    // The in-memory identity is unchanged.
    assert_eq!(
        fix.state.config.read().await.vtc_did.as_deref(),
        Some(vtc_service::test_support::TEST_VTC_DID)
    );
}

#[tokio::test]
async fn patch_vta_did_is_rejected_409() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    let (status, body) = send(
        &fix,
        "PATCH",
        &token,
        Some(json!({ "vta_did": "did:key:zNewRecoveryAuthority" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "vta_did rewrite must be refused: {body}"
    );
}

#[tokio::test]
async fn patch_name_writes_to_profile_and_get_reads_it_back() {
    let fix = build().await;
    seed_profile(&fix, "Original").await;
    let token = super_admin_token(&fix).await;

    let (status, _) = send(
        &fix,
        "PATCH",
        &token,
        Some(json!({ "vtc_name": "Renamed Community", "vtc_description": "New desc" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The profile is the authoritative store…
    let profile = vtc_service::community::load_profile(&fix.state.community_ks)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(profile.name, "Renamed Community");
    assert_eq!(profile.description, "New desc");

    // …and GET /v1/config reads name/description back from it.
    let (status, body) = send(&fix, "GET", &token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["vtc_name"], "Renamed Community");
    assert_eq!(body["vtc_description"], "New desc");
}

#[tokio::test]
async fn patch_name_without_a_profile_is_409() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    let (status, body) = send(
        &fix,
        "PATCH",
        &token,
        Some(json!({ "vtc_name": "No Profile Yet" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "name change without a profile must 409: {body}"
    );
}

#[tokio::test]
async fn patch_public_url_flags_pending_restart_and_persists_to_toml() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;

    // Point the in-memory config at a real on-disk config.toml so the
    // env-safe atomic write has a base to read.
    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg_path = cfg_dir.path().join("config.toml");
    std::fs::write(&cfg_path, "vtc_did = \"did:webvh:vtc.example.com:abc\"\n").unwrap();
    {
        let mut c = fix.state.config.write().await;
        c.config_path = cfg_path.clone();
    }

    let (status, body) = send(
        &fix,
        "PATCH",
        &token,
        Some(json!({ "public_url": "https://vtc.example.com" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(
        body["pending_restart"],
        json!(["public_url"]),
        "public_url is boot-stable → pending_restart: {body}"
    );
    assert_eq!(body["public_url"], "https://vtc.example.com");

    // Persisted to the on-disk TOML, base preserved.
    let written = std::fs::read_to_string(&cfg_path).unwrap();
    let doc: toml::Table = toml::from_str(&written).unwrap();
    assert_eq!(
        doc.get("public_url").and_then(|v| v.as_str()),
        Some("https://vtc.example.com")
    );
    assert_eq!(
        doc.get("vtc_did").and_then(|v| v.as_str()),
        Some("did:webvh:vtc.example.com:abc")
    );
}
