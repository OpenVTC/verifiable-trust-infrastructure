//! Integration coverage for `GET /v1/status-lists/{purpose}`
//! (Phase 2 M2.11).
//!
//! Verifies:
//! - Route serves the seeded status-list VC.
//! - Trust-Task header is **not** required (verifier-facing
//!   exemption).
//! - Unknown purpose → 404.
//! - 503 path when the credential signer isn't initialised.

mod common;

use std::sync::Arc;

use affinidi_status_list::StatusPurpose;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tokio::sync::RwLock;
use tower::ServiceExt;
use vti_common::audit::{AuditKeyStore, AuditWriter};
use vti_common::auth::jwt::JwtKeys;
use vti_common::config::StoreConfig;
use vti_common::store::Store;

use vtc_service::config::AppConfig;
use vtc_service::credentials::LocalSigner;
use vtc_service::install::InstallTokenStore;
use vtc_service::routes;
use vtc_service::server::AppState;
use vtc_service::status_list;

const VTC_DID: &str = "did:webvh:vtc.example.com:abc";
const PUBLIC_URL: &str = "https://vtc.example.com";

fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

struct Fixture {
    router: axum::Router,
    signer: Arc<LocalSigner>,
    _dir: tempfile::TempDir,
}

async fn build_fixture(with_signer: bool) -> Fixture {
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
    let install_store = InstallTokenStore::new(install_ks.clone());

    // Seed both status lists like `server::run` does at boot.
    let signer = Arc::new(LocalSigner::from_ed25519_seed(VTC_DID.into(), &[0xCC; 32]));
    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        let url = format!("{PUBLIC_URL}/v1/status-lists/{purpose}");
        status_list::ensure_initial(&status_lists_ks, purpose, url)
            .await
            .unwrap();
    }

    let key_store = AuditKeyStore::new(audit_key_ks.clone());
    key_store.ensure_initial(&[0xAB; 32]).await.unwrap();
    let audit_writer = Some(AuditWriter::new(audit_ks.clone(), key_store));

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").unwrap());

    let config: AppConfig = toml::from_str(&format!(
        r#"
        vtc_did = "{VTC_DID}"
        public_url = "{PUBLIC_URL}"
        [store]
        data_dir = "{}"
        "#,
        dir.path().display(),
    ))
    .expect("parse config");

    let state = AppState {
        sessions_ks,
        acl_ks,
        community_ks,
        config_ks,
        passkey_ks,
        install_ks,
        members_ks,
        join_requests_ks,
        policies_ks,
        active_policies_ks,
        status_lists_ks,
        registry_records_ks,
        sync_queue_ks,
        sync_cursor_ks,
        relationships_ks,
        relationships_by_did_ks,
        endorsement_types_ks,
        schemas_ks: store.keyspace("schemas").unwrap(),
        endorsements_ks,
        registry_client: None,
        registry_health: vtc_service::registry::RegistryHealth::new(),
        audit_ks,
        audit_key_ks,
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: Some(jwt_keys),
        atm: None,
        webauthn: None,
        public_url: Some(PUBLIC_URL.into()),
        install_signer: None,
        credential_signer: with_signer.then(|| signer.clone()),
        install_store,
        audit_writer,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
    };

    let router = routes::router().with_state(state);

    Fixture {
        router,
        signer,
        _dir: dir,
    }
}

async fn body_json(body: Body) -> Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        let raw = String::from_utf8_lossy(&bytes);
        panic!("response body was not JSON ({e}): {raw}")
    })
}

/// GET without a Trust-Task header returns the status-list VC.
/// Confirms the route_exempt path is wired.
#[tokio::test]
async fn show_returns_signed_vc_without_trust_task_header() {
    let fix = build_fixture(true).await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/status-lists/revocation")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Cache-Control: no-store header set per spec §6.2.
    let headers = resp.headers().clone();
    assert_eq!(
        headers.get("cache-control").map(|v| v.to_str().unwrap()),
        Some("no-store"),
    );

    let body = body_json(resp.into_body()).await;

    // Shape: VC with the BitstringStatusListCredential type.
    let types = body["type"].as_array().expect("type array");
    assert!(types.iter().any(|t| t == "VerifiableCredential"));
    assert!(types.iter().any(|t| t == "BitstringStatusListCredential"));

    // Subject details.
    assert_eq!(body["credentialSubject"]["statusPurpose"], "revocation");
    assert_eq!(body["credentialSubject"]["type"], "BitstringStatusList");
    assert!(body["credentialSubject"]["encodedList"].is_string());

    // Proof verifies against the signer used in the fixture.
    let vc: affinidi_vc::VerifiableCredential = serde_json::from_value(body).unwrap();
    fix.signer.verify(&vc).expect("status-list VC must verify");
}

/// `suspension` purpose is also served (both purposes seeded
/// at boot).
#[tokio::test]
async fn show_serves_suspension_purpose() {
    let fix = build_fixture(true).await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/status-lists/suspension")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["credentialSubject"]["statusPurpose"], "suspension");
}

/// An unknown purpose value returns 404.
#[tokio::test]
async fn show_unknown_purpose_returns_404() {
    let fix = build_fixture(true).await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/status-lists/disco")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// When the credential signer is `None` (daemon not yet
/// provisioned), the route returns 500 with a "signer not
/// initialised" message. `AppError::Internal` maps to 500 in
/// the workspace.
#[tokio::test]
async fn show_returns_5xx_when_signer_missing() {
    let fix = build_fixture(false).await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/status-lists/revocation")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert!(
        resp.status().is_server_error(),
        "expected 5xx when signer missing, got {}",
        resp.status()
    );
}
