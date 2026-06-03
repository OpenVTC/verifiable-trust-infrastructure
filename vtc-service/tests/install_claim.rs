//! End-to-end coverage for `POST /v1/install/claim/{start,finish}`.
//!
//! Drives the full install ceremony through `Router::oneshot`,
//! using the soft EdDSA authenticator harness (`tests/common`) to
//! produce real WebAuthn responses and the install module's own
//! signer/store to mint and consume install tokens.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration as ChronoDuration, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::auth::passkey::build_webauthn;
use vti_common::config::StoreConfig;
use vti_common::store::Store;
use webauthn_rs::prelude::CreationChallengeResponse;

use vtc_service::config::AppConfig;
use vtc_service::install::{InstallTokenSigner, InstallTokenStore, mint_install_token};
use vtc_service::routes;
use vtc_service::server::AppState;

use common::webauthn_harness::SoftEd25519Authenticator;

const RP_ORIGIN: &str = "https://vtc.example.com";
const START_TASK: &str = "https://trusttasks.org/openvtc/vtc/install/claim/start/1.0";
const FINISH_TASK: &str = "https://trusttasks.org/openvtc/vtc/install/claim/finish/1.0";

fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

struct Fixture {
    router: axum::Router,
    install_signer: Arc<InstallTokenSigner>,
    install_store: InstallTokenStore,
    _dir: tempfile::TempDir,
}

async fn build_fixture(public_url: Option<&str>, with_install_signer: bool) -> Fixture {
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

    let config: AppConfig = toml::from_str(&format!(
        r#"
        vtc_did = "did:webvh:vtc.example.com:abc"
        [store]
        data_dir = "{}"
        "#,
        dir.path().display(),
    ))
    .expect("parse config");

    let webauthn = public_url.map(|u| Arc::new(build_webauthn(u).expect("build webauthn")));
    let install_signer = if with_install_signer {
        // 64 bytes of test entropy mirror what production loads from
        // the secret store (32 Ed25519 + 32 X25519); HKDF only cares
        // about length.
        Some(Arc::new(
            InstallTokenSigner::from_master_seed(&[0xAB; 64]).unwrap(),
        ))
    } else {
        None
    };

    let state = AppState {
        sessions_ks,
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
        audit_ks,
        audit_key_ks,
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: None,
        atm: None,
        webauthn,
        public_url: public_url.map(|s| s.to_string()),
        install_signer: install_signer.clone(),
        install_store: install_store.clone(),
        audit_writer: None,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
    };

    let router = routes::router().with_state(state);

    Fixture {
        router,
        install_signer: install_signer.clone().unwrap_or_else(|| {
            Arc::new(InstallTokenSigner::from_master_seed(&[0xCD; 64]).unwrap())
        }),
        install_store,
        _dir: dir,
    }
}

async fn mint_token_and_record(fix: &Fixture, ttl_seconds: u64) -> (String, Uuid) {
    mint_token_and_record_with_secret(fix, ttl_seconds, None).await
}

async fn mint_token_and_record_with_secret(
    fix: &Fixture,
    ttl_seconds: u64,
    claim_secret_hash: Option<String>,
) -> (String, Uuid) {
    let minted = mint_install_token(
        &fix.install_signer,
        "did:webvh:vtc.example.com:abc",
        "did:key:z6MkAdmin",
        ttl_seconds,
    )
    .expect("mint install token");
    let exp = Utc::now() + ChronoDuration::seconds(ttl_seconds as i64);
    fix.install_store
        .record_issued(
            &minted.jti,
            minted.cnonce_bytes,
            *minted.ephemeral_signing_key,
            exp,
            claim_secret_hash,
            Some("did:key:z6MkAdmin".into()),
        )
        .await
        .expect("record_issued");
    (minted.jwt, minted.jti)
}

async fn post_json(
    router: &axum::Router,
    path: &str,
    trust_task: &str,
    body: Value,
) -> (StatusCode, Value) {
    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("Trust-Task", trust_task)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("oneshot");
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

fn parse_ccr(body: &Value) -> CreationChallengeResponse {
    serde_json::from_value(body.get("options").cloned().expect("options field"))
        .expect("CreationChallengeResponse parses")
}

// ---------------------------------------------------------------------------
// Happy-path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_ceremony_completes_end_to_end() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (token, _jti) = mint_token_and_record(&fix, 600).await;

    // -- start ---------------------------------------------------------
    let (status, body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "start: {body}");

    let registration_id = body["registrationId"].as_str().unwrap().to_string();
    let ccr = parse_ccr(&body);

    // -- harness produces the registration response --------------------
    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, _ed25519_pub) = authenticator.register(&ccr, RP_ORIGIN);

    // -- finish --------------------------------------------------------
    let (status, body) = post_json(
        &fix.router,
        "/v1/install/claim/finish",
        FINISH_TASK,
        json!({
            "install_token": token,
            "registration_id": registration_id,
            "webauthn_response": register_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "finish: {body}");
    let admin_did = body["adminDid"].as_str().unwrap();
    assert!(admin_did.starts_with("did:key:z"));
    assert!(!body["setupSessionToken"].as_str().unwrap().is_empty());

    // -- replay finish: must fail (token is now Consumed) --------------
    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/finish",
        FINISH_TASK,
        json!({
            "install_token": token,
            "registration_id": registration_id,
            "webauthn_response": register_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Claim-secret paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn claim_secret_happy_path_completes_ceremony() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let secret = "ABCDEFGHJK";
    let hash = vtc_service::install::claim_secret::hash(secret).unwrap();
    let (token, _jti) = mint_token_and_record_with_secret(&fix, 600, Some(hash)).await;

    let (status, body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": token, "claim_secret": secret }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "start with correct secret: {body}");
    assert!(body["registrationId"].as_str().is_some());
}

#[tokio::test]
async fn claim_secret_missing_returns_required_code() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let hash = vtc_service::install::claim_secret::hash("WHATEVER12").unwrap();
    let (token, _) = mint_token_and_record_with_secret(&fix, 600, Some(hash)).await;

    let (status, body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(
        body["error"].as_str(),
        Some("claim_secret_required"),
        "discriminated error code; got {body}"
    );
}

#[tokio::test]
async fn claim_secret_wrong_returns_invalid_code() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let hash = vtc_service::install::claim_secret::hash("CORRECT123").unwrap();
    let (token, _) = mint_token_and_record_with_secret(&fix, 600, Some(hash)).await;

    let (status, body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": token, "claim_secret": "WRONGWRONG" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(
        body["error"].as_str(),
        Some("claim_secret_invalid"),
        "discriminated error code; got {body}"
    );
}

// ---------------------------------------------------------------------------
// 503 paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_returns_503_when_install_signer_missing() {
    let fix = build_fixture(Some(RP_ORIGIN), false).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": "bogus" }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn start_returns_503_when_webauthn_missing() {
    let fix = build_fixture(None, true).await;
    let (token, _jti) = mint_token_and_record(&fix, 600).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

// ---------------------------------------------------------------------------
// Failure modes — auth + ceremony state
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_rejects_unsigned_token() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": "not.a.real.jwt" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn start_rejects_unknown_jti() {
    // Mint a valid token but never call `record_issued` — the install
    // store has no state for the jti and `start_claim` must fail.
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let minted = mint_install_token(
        &fix.install_signer,
        "did:webvh:vtc.example.com:abc",
        "did:key:z6MkAdmin",
        600,
    )
    .unwrap();
    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": minted.jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn second_concurrent_start_within_window_is_conflict() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (token, _jti) = mint_token_and_record(&fix, 600).await;

    let (status1, _) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": &token }),
    )
    .await;
    assert_eq!(status1, StatusCode::OK);

    let (status2, _) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": &token }),
    )
    .await;
    assert_eq!(status2, StatusCode::CONFLICT);
}

#[tokio::test]
async fn finish_rejects_mismatched_registration_id() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (token, _jti) = mint_token_and_record(&fix, 600).await;

    let (_status, body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": token }),
    )
    .await;
    let ccr = parse_ccr(&body);
    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, _pub) = authenticator.register(&ccr, RP_ORIGIN);

    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/finish",
        FINISH_TASK,
        json!({
            "install_token": token,
            "registration_id": Uuid::new_v4().to_string(),
            "webauthn_response": register_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn finish_without_start_fails() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (token, jti) = mint_token_and_record(&fix, 600).await;

    // Skip start. Fabricate a registration_id and a placeholder
    // webauthn_response — finish must refuse because no
    // registration state exists for this jti.
    let dummy_cred = json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "response": {
            "attestationObject": "AA",
            "clientDataJSON": "AA"
        },
        "type": "public-key"
    });

    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/finish",
        FINISH_TASK,
        json!({
            "install_token": token,
            "registration_id": jti.to_string(),
            "webauthn_response": dummy_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Trust-Task gate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_trust_task_header_returns_400() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let res = fix
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/install/claim/start")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"install_token":"x"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn wrong_trust_task_header_returns_415() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        FINISH_TASK, // start endpoint with finish task
        json!({ "install_token": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}
