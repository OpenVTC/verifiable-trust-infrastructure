//! Integration coverage for `/v1/community/profile`.
//!
//! Exercises the full router stack — Trust-Task header → auth
//! extractor → handler → community keyspace — through
//! `Router::oneshot`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower::ServiceExt;
use vti_common::auth::jwt::JwtKeys;
use vti_common::config::StoreConfig;
use vti_common::store::Store;

use vtc_service::community::{CommunityProfile, store_profile};
use vtc_service::config::AppConfig;
use vtc_service::routes;
use vtc_service::server::AppState;

const PROFILE_TASK: &str = "https://trusttasks.org/openvtc/vtc/community/profile/manage/1.0";

fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

struct Fixture {
    router: axum::Router,
    jwt_keys: Arc<JwtKeys>,
    state: AppState,
    _dir: tempfile::TempDir,
}

async fn build() -> Fixture {
    init_jwt_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .expect("open store");

    let sessions_ks = store.keyspace("sessions").unwrap();
    let acl_ks = store.keyspace("acl").unwrap();
    let community_ks = store.keyspace("community").unwrap();
    let config_ks = store.keyspace("config").unwrap();
    let passkey_ks = store.keyspace("passkey").unwrap();
    let install_ks = store.keyspace("install").unwrap();
    let members_ks = store.keyspace("members").unwrap();
    let join_requests_ks = store.keyspace("join_requests").unwrap();
    let policies_ks = store.keyspace("policies").unwrap();
    let active_policies_ks = store.keyspace("active_policies").unwrap();
    let status_lists_ks = store.keyspace("status_lists").unwrap();
    let registry_records_ks = store.keyspace("registry_records").unwrap();
    let sync_queue_ks = store.keyspace("sync_queue").unwrap();
    let sync_cursor_ks = store.keyspace("sync_cursor").unwrap();
    let relationships_ks = store.keyspace("relationships").unwrap();
    let relationships_by_did_ks = store.keyspace("relationships_by_did").unwrap();
    let endorsement_types_ks = store.keyspace("endorsement_types").unwrap();
    let endorsements_ks = store.keyspace("endorsements").unwrap();
    let audit_ks = store.keyspace("audit").unwrap();
    let audit_key_ks = store.keyspace("audit_key").unwrap();

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").expect("jwt keys"));

    let config: AppConfig = toml::from_str(&format!(
        r#"
        vtc_did = "did:webvh:vtc.example.com:abc"
        [store]
        data_dir = "{}"
        [auth]
        jwt_signing_key = "{}"
        "#,
        dir.path().display(),
        BASE64.encode(jwt_seed),
    ))
    .expect("parse config");

    let state = AppState {
        sessions_ks: sessions_ks.clone(),
        acl_ks,
        community_ks,
        config_ks,
        passkey_ks,
        install_ks: install_ks.clone(),
        members_ks: members_ks.clone(),
        join_requests_ks: join_requests_ks.clone(),
        policies_ks: policies_ks.clone(),
        active_policies_ks: active_policies_ks.clone(),
        status_lists_ks: status_lists_ks.clone(),
        registry_records_ks: registry_records_ks.clone(),
        sync_queue_ks: sync_queue_ks.clone(),
        sync_cursor_ks: sync_cursor_ks.clone(),
        relationships_ks: relationships_ks.clone(),
        relationships_by_did_ks: relationships_by_did_ks.clone(),
        endorsement_types_ks: endorsement_types_ks.clone(),
        schemas_ks: store.keyspace("schemas").unwrap(),
        endorsements_ks: endorsements_ks.clone(),
        registry_client: None,
        registry_health: vtc_service::registry::RegistryHealth::new(),
        credential_signer: None,
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: Some(jwt_keys.clone()),
        atm: None,
        webauthn: None,
        public_url: None,
        install_signer: None,
        install_store: vtc_service::install::InstallTokenStore::new(install_ks),
        audit_ks,
        audit_key_ks,
        audit_writer: None,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
    };

    let router = routes::router().with_state(state.clone());
    Fixture {
        router,
        jwt_keys,
        state,
        _dir: dir,
    }
}

async fn token_for(fix: &Fixture, role: &str) -> String {
    use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

    let session_id = format!("sess-{}", uuid::Uuid::new_v4());
    let session = Session {
        session_id: session_id.clone(),
        did: "did:key:z6MkAdmin".into(),
        challenge: "test".into(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        refresh_token: None,
        refresh_expires_at: None,
        tee_attested: false,
        amr: Vec::new(),
        acr: String::new(),
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&fix.state.sessions_ks, &session)
        .await
        .unwrap();

    let claims = fix.jwt_keys.new_claims(
        "did:key:z6MkAdmin".to_string(),
        session_id,
        role.to_string(),
        vec![],
        900,
        false,
    );
    fix.jwt_keys.encode(&claims).expect("encode")
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

async fn seed_profile(fix: &Fixture) -> CommunityProfile {
    let p = CommunityProfile::new("did:webvh:vtc.example.com:abc", "Example Community");
    store_profile(&fix.state.community_ks, &p).await.unwrap();
    p
}

// ──────────────────────── GET ────────────────────────

#[tokio::test]
async fn get_returns_404_when_not_initialised() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_returns_profile_when_initialised() {
    let fix = build().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Example Community");
    assert_eq!(body["communityDid"], "did:webvh:vtc.example.com:abc");
    assert_eq!(body["language"], "en");
    // M3.2: registryStatus surfaces on the GET response. No
    // registry URL configured → reads `degraded`.
    assert_eq!(body["registryStatus"], "degraded");
}

#[tokio::test]
async fn get_requires_authentication() {
    let fix = build().await;
    seed_profile(&fix).await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ──────────────────────── PUT ────────────────────────

#[tokio::test]
async fn put_requires_admin_role() {
    let fix = build().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "reader").await;
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"name":"Renamed"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn put_updates_profile_and_lists_changed_fields() {
    let fix = build().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"name":"Renamed","description":"new","logoUrl":"https://x/y.png"}"#,
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    let changed = body["fieldsChanged"].as_array().unwrap();
    let names: Vec<&str> = changed.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(names.contains(&"name"));
    assert!(names.contains(&"description"));
    assert!(names.contains(&"logoUrl"));
    assert_eq!(body["profile"]["name"], "Renamed");
    assert_eq!(body["profile"]["logoUrl"], "https://x/y.png");
}

#[tokio::test]
async fn put_idempotent_noop_returns_empty_changeset() {
    let fix = build().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "admin").await;
    let body = r#"{"name":"Example Community"}"#; // already the value
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["fieldsChanged"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn put_returns_404_when_profile_not_initialised() {
    let fix = build().await;
    // No seed_profile call — store is empty.
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"name":"Renamed"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn put_rejects_oversized_extensions() {
    let fix = build().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "admin").await;

    // Build a clearly-too-large extensions value (~32 KiB).
    let mut huge_value = String::new();
    huge_value.push('"');
    huge_value.push_str(&"a".repeat(32 * 1024));
    huge_value.push('"');
    let body = format!(r#"{{"extensions":{{"k":{huge_value}}}}}"#);

    let req = Request::builder()
        .method("PUT")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_does_not_accept_community_did_in_request() {
    let fix = build().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "admin").await;

    // `communityDid` is not a field on the update DTO; serde_json
    // with `additionalProperties = no` would reject it, but our
    // CommunityProfileUpdate has no such guard at the type level
    // (serde silently ignores extra fields by default). The
    // important property is that it never reaches the stored
    // profile.
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"name":"Renamed","communityDid":"did:webvh:attacker:steal"}"#,
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    // Profile's communityDid is unchanged.
    assert_eq!(
        body["profile"]["communityDid"],
        "did:webvh:vtc.example.com:abc"
    );
    // Only `name` made it into the changeset.
    let changed = body["fieldsChanged"].as_array().unwrap();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0], "name");
}

// ──────────────────────── Public profile (unauth) ─────────────

#[tokio::test]
async fn public_profile_returns_curated_subset_unauthenticated() {
    // Drives the default public website. Trust-Task-exempt and
    // unauthenticated — neither header is set on the request.
    let fix = build().await;
    seed_profile(&fix).await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/community/public-profile")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Example Community");
    assert_eq!(body["communityDid"], "did:webvh:vtc.example.com:abc");
    assert_eq!(body["language"], "en");
    // Curated subset — operational + opaque fields stay private.
    assert!(body.get("registryStatus").is_none());
    assert!(body.get("extensions").is_none());
}

#[tokio::test]
async fn public_profile_returns_404_when_not_initialised() {
    let fix = build().await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/community/public-profile")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ──────────────────────── Trust-Task gate ────────────────────────

#[tokio::test]
async fn get_with_wrong_trust_task_returns_415() {
    let fix = build().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/community/profile")
        .header(
            "Trust-Task",
            "https://trusttasks.org/openvtc/vtc/acl/legacy/manage/1.0",
        )
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}
