//! End-to-end coverage for `POST /v1/admin/bootstrap`.
//!
//! Drives the full install → claim → bootstrap chain through
//! `Router::oneshot`, using the soft EdDSA harness for the WebAuthn
//! ceremony. Verifies the M0.6.2 acceptance criteria:
//!
//! - Happy path writes an `Admin` ACL entry, an `AdminEntry`, and a
//!   `CommunityInstalled` audit envelope.
//! - Bootstrap-after-bootstrap is rejected (409).
//! - Replay of the same setup-session JWT is rejected by the
//!   duplicate-admin check (409).
//! - Tampered / wrong-audience / expired tokens are rejected as 401.
//! - 503 when install signer or audit writer aren't configured.

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
use vti_common::acl::{Role, list_acl_entries};
use vti_common::audit::{AuditEvent, AuditKeyStore, AuditWriter};
use vti_common::auth::passkey::build_webauthn;
use vti_common::config::StoreConfig;
use vti_common::store::Store;

use vtc_service::acl::admin::get_admin_entry;
use vtc_service::config::AppConfig;
use vtc_service::install::{InstallTokenSigner, InstallTokenStore, mint_install_token};
use vtc_service::routes;
use vtc_service::server::AppState;

use common::webauthn_harness::SoftEd25519Authenticator;

const RP_ORIGIN: &str = "https://vtc.example.com";
const START_TASK: &str = "https://trusttasks.org/openvtc/vtc/install/claim/start/1.0";
const FINISH_TASK: &str = "https://trusttasks.org/openvtc/vtc/install/claim/finish/1.0";
const BOOTSTRAP_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/bootstrap/1.0";

fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

struct Fixture {
    state: AppState,
    router: axum::Router,
    install_signer: Arc<InstallTokenSigner>,
    install_store: InstallTokenStore,
    _dir: tempfile::TempDir,
}

async fn build_fixture(with_install_signer: bool, with_audit: bool) -> Fixture {
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

    let webauthn = Some(Arc::new(build_webauthn(RP_ORIGIN).expect("build webauthn")));
    let install_signer = if with_install_signer {
        Some(Arc::new(
            InstallTokenSigner::from_master_seed(&[0xAB; 64]).unwrap(),
        ))
    } else {
        None
    };

    let audit_writer = if with_audit {
        let key_store = AuditKeyStore::new(audit_key_ks.clone());
        key_store.ensure_initial(&[0xAB; 64]).await.unwrap();
        Some(AuditWriter::new(audit_ks.clone(), key_store))
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
        audit_ks: audit_ks.clone(),
        audit_key_ks,
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: None,
        atm: None,
        webauthn,
        public_url: Some(RP_ORIGIN.to_string()),
        install_signer: install_signer.clone(),
        install_store: install_store.clone(),
        audit_writer,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
    };

    let router = routes::router().with_state(state.clone());

    Fixture {
        state,
        router,
        install_signer: install_signer.unwrap_or_else(|| {
            Arc::new(InstallTokenSigner::from_master_seed(&[0xCD; 64]).unwrap())
        }),
        install_store,
        _dir: dir,
    }
}

async fn mint_token_and_record(fix: &Fixture, ttl_seconds: u64) -> String {
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
            None,
            None,
        )
        .await
        .unwrap();
    minted.jwt
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

/// Drive a full claim ceremony and return the setup-session JWT plus
/// the candidate admin DID the server returned.
async fn run_claim_ceremony(fix: &Fixture) -> (String, String) {
    let token = mint_token_and_record(fix, 600).await;

    let (status, body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "start: {body}");

    let registration_id = body["registrationId"].as_str().unwrap().to_string();
    let ccr: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(body["options"].clone()).unwrap();

    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, _ed25519_pub) = authenticator.register(&ccr, RP_ORIGIN);

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
    let session_jwt = body["setupSessionToken"].as_str().unwrap().to_string();
    let admin_did = body["adminDid"].as_str().unwrap().to_string();
    (session_jwt, admin_did)
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_install_to_bootstrap_succeeds() {
    let fix = build_fixture(true, true).await;
    let (session_jwt, admin_did) = run_claim_ceremony(&fix).await;

    let (status, body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": session_jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bootstrap: {body}");
    assert_eq!(body["adminDid"].as_str().unwrap(), admin_did);
    let event_id = body["eventId"].as_str().unwrap();
    let _: Uuid = event_id.parse().expect("eventId is a UUID");

    // ACL: one Admin entry for our DID.
    let acl = list_acl_entries(&fix.state.acl_ks).await.unwrap();
    assert_eq!(acl.len(), 1);
    assert_eq!(acl[0].did, admin_did);
    assert_eq!(acl[0].role, Role::Admin);

    // AdminEntry written with one passkey.
    let admin_entry = get_admin_entry(&fix.state.passkey_ks, &admin_did)
        .await
        .unwrap()
        .expect("admin entry persisted");
    assert_eq!(admin_entry.passkeys.len(), 1);

    // Audit envelope present and references the install jti.
    // `envelope_storage_key` formats as `<rfc3339-timestamp>:<event_id>`
    // — there's no fixed string prefix, so a `2` literal works for
    // every realistic timestamp (it's the first digit of the year).
    let raw = fix
        .state
        .audit_ks
        .prefix_iter_raw(b"2".to_vec())
        .await
        .unwrap();
    assert_eq!(raw.len(), 1, "exactly one audit envelope expected");
    let envelope: vti_common::audit::AuditEnvelope = serde_json::from_slice(&raw[0].1).unwrap();
    match envelope.event {
        AuditEvent::CommunityInstalled(data) => {
            assert_eq!(data.community_did, "did:webvh:vtc.example.com:abc");
            // install_token_jti is non-empty.
            assert!(!data.install_token_jti.is_empty());
        }
        other => panic!("expected CommunityInstalled, got {other:?}"),
    }

    // Community profile singleton is initialised with the configured
    // VTC DID. Spec §5.1: `community_did` is immutable, set at install
    // time. The form-editable fields (name, description, etc.) default
    // to empty so the operator fills them in via the admin UI.
    let profile = vtc_service::community::load_profile(&fix.state.community_ks)
        .await
        .unwrap()
        .expect("community profile initialised at bootstrap");
    assert_eq!(profile.community_did, "did:webvh:vtc.example.com:abc");
    assert_eq!(profile.name, "");
    assert_eq!(profile.description, "");
    assert_eq!(profile.language, "en");
}

// ---------------------------------------------------------------------------
// 409 — bootstrap-after-bootstrap
// ---------------------------------------------------------------------------

#[tokio::test]
async fn second_bootstrap_returns_409() {
    let fix = build_fixture(true, true).await;
    let (session_jwt_a, _) = run_claim_ceremony(&fix).await;

    let (s1, _) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": session_jwt_a }),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    // Try to replay the same session JWT.
    let (s2, body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": session_jwt_a }),
    )
    .await;
    assert_eq!(
        s2,
        StatusCode::CONFLICT,
        "duplicate-admin check must catch the replay: {body}"
    );
}

// ---------------------------------------------------------------------------
// 401 paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_rejects_unsigned_token() {
    let fix = build_fixture(true, true).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": "not.a.real.jwt" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bootstrap_rejects_install_token_as_setup_token() {
    // An attacker who intercepted the install URL still cannot drive
    // bootstrap directly — the install JWT has `aud = "vtc-install"`,
    // which the session decoder rejects.
    let fix = build_fixture(true, true).await;
    let install_jwt = mint_token_and_record(&fix, 600).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": install_jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bootstrap_rejects_when_no_passkey_user_exists() {
    // Forge a valid setup-session JWT for a DID that never went
    // through claim/finish. Decoder accepts the signature; the
    // passkey-user lookup fails.
    let fix = build_fixture(true, true).await;
    let session_jwt = vtc_service::install::mint_install_session_token(
        &fix.install_signer,
        "did:webvh:vtc.example.com:abc",
        "did:key:zNobody",
        &Uuid::new_v4().to_string(),
        600,
    )
    .unwrap();
    let (status, _body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": session_jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// 503 paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_returns_503_when_install_signer_missing() {
    let fix = build_fixture(false, true).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn bootstrap_returns_503_when_audit_writer_missing() {
    let fix = build_fixture(true, false).await;
    let session_jwt = vtc_service::install::mint_install_session_token(
        &fix.install_signer,
        "did:webvh:vtc.example.com:abc",
        "did:key:zAnyone",
        &Uuid::new_v4().to_string(),
        600,
    )
    .unwrap();
    let (status, _body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": session_jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

// ---------------------------------------------------------------------------
// Trust-Task gate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wrong_trust_task_returns_415() {
    let fix = build_fixture(true, true).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        FINISH_TASK,
        json!({ "setup_session_token": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn missing_trust_task_returns_400() {
    let fix = build_fixture(true, true).await;
    let res = fix
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"setup_session_token":"x"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}
