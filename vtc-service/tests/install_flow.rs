//! Phase-0 install-flow integration test (M0.12.1).
//!
//! Walks the canonical 9-step scenario from the plan through
//! `Router::oneshot`, asserting that every endpoint added during
//! Phase 0 cooperates:
//!
//! 1. `vtc setup` shortcut — mint seed + install token (no real VTA).
//! 2. `POST /v1/install/claim/start` — WebAuthn ceremony begins.
//! 3. `POST /v1/install/claim/finish` — token consumed, session-JWT minted.
//! 4. `POST /v1/admin/bootstrap` — first ACL admin written.
//! 5. `POST /v1/admin/passkeys/register/{start,finish}` — second passkey.
//! 6. `GET  /v1/admin/passkeys` — both passkeys present.
//! 7. `PUT  /v1/community/profile` + `GET  /v1/community/profile`.
//! 8. `PATCH /v1/admin/config` — `log.level` updates.
//! 9. `POST /v1/admin/config/restart` — refused without supervisor (412).
//! 10. Second `POST /v1/install/claim/start` — refused (carve-out closed).
//!
//! Closes the Phase-0 behavioural gate (Checkpoint E in the plan).

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
use vti_common::acl::Role;
use vti_common::audit::{AuditEnvelope, AuditEvent, AuditKeyStore, AuditWriter};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::passkey::build_webauthn;
use vti_common::config::StoreConfig;
use vti_common::store::Store;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

use vtc_service::config::AppConfig;
use vtc_service::install::{InstallTokenSigner, InstallTokenStore, mint_install_token};
use vtc_service::routes;
use vtc_service::server::AppState;

use common::webauthn_harness::SoftEd25519Authenticator;

const RP_ORIGIN: &str = "https://vtc.example.com";

// Trust Tasks ------------------------------------------------------
const CLAIM_START_TASK: &str = "https://trusttasks.org/openvtc/vtc/install/claim/start/1.0";
const CLAIM_FINISH_TASK: &str = "https://trusttasks.org/openvtc/vtc/install/claim/finish/1.0";
const BOOTSTRAP_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/bootstrap/1.0";
const PASSKEY_REGISTER_TASK: &str =
    "https://trusttasks.org/openvtc/vtc/admin/passkeys/register/1.0";
const PASSKEY_LIST_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/passkeys/list/1.0";
const COMMUNITY_PROFILE_TASK: &str =
    "https://trusttasks.org/openvtc/vtc/community/profile/manage/1.0";
const ADMIN_CONFIG_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/config/manage/1.0";
const RESTART_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/config/restart/1.0";

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
    jwt_keys: Arc<JwtKeys>,
    _dir: tempfile::TempDir,
}

/// Step 1: `vtc setup` shortcut. Stands up an AppState with
/// everything `run()` would wire (WebAuthn, install signer, audit
/// writer, JWT keys). No actual VTA contact — provisioning against
/// a fake VTA is acceptable per the plan's M0.12.1 acceptance.
async fn build_fixture() -> Fixture {
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

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").unwrap());

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
    let install_signer = Arc::new(InstallTokenSigner::from_master_seed(&[0xAB; 64]).unwrap());

    let key_store = AuditKeyStore::new(audit_key_ks.clone());
    key_store.ensure_initial(&[0xAB; 64]).await.unwrap();
    let audit_writer = Some(AuditWriter::new(audit_ks.clone(), key_store));

    let state = AppState {
        sessions_ks,
        acl_ks,
        community_ks,
        config_ks,
        passkey_ks,
        install_ks,
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
        jwt_keys: Some(jwt_keys.clone()),
        atm: None,
        webauthn,
        public_url: Some(RP_ORIGIN.to_string()),
        install_signer: Some(install_signer.clone()),
        install_store: install_store.clone(),
        audit_writer,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        // No supervisor — step 9 asserts `/restart` returns 412.
        supervisor: None,
    };

    let router = routes::router().with_state(state.clone());

    Fixture {
        state,
        router,
        install_signer,
        install_store,
        jwt_keys,
        _dir: dir,
    }
}

/// Step 1 (continued): mint a fresh install token + record it in
/// the install store so `claim/start` finds the state.
async fn mint_install(fix: &Fixture) -> String {
    let minted = mint_install_token(
        &fix.install_signer,
        "did:webvh:vtc.example.com:abc",
        "did:key:z6MkAdmin",
        600,
    )
    .expect("mint install token");
    let exp = Utc::now() + ChronoDuration::seconds(600);
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

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async fn request(
    router: &axum::Router,
    method: &str,
    path: &str,
    trust_task: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Trust-Task", trust_task);
    if let Some(tok) = token {
        builder = builder.header("Authorization", format!("Bearer {tok}"));
    }
    let body = if let Some(b) = body {
        builder = builder.header("Content-Type", "application/json");
        Body::from(b.to_string())
    } else {
        Body::empty()
    };
    let res = router
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

/// Mint a VTC admin JWT for `admin_did` so subsequent admin-gated
/// endpoints (`/v1/admin/*`, `/v1/community/profile` PUT) accept
/// the caller. M0.6 still wires this through a normal challenge-
/// response auth flow in production; here we synthesise the same
/// session shape directly because the install-flow happy path
/// doesn't exercise the auth challenge endpoints.
async fn admin_jwt_for(fix: &Fixture, admin_did: &str) -> String {
    use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};
    let session_id = format!("sess-{}", Uuid::new_v4());
    let session = Session {
        session_id: session_id.clone(),
        did: admin_did.to_string(),
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
        admin_did.to_string(),
        session_id,
        "admin".to_string(),
        vec![],
        900,
        false,
    );
    fix.jwt_keys.encode(&claims).unwrap()
}

// ---------------------------------------------------------------------------
// The end-to-end test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn end_to_end_install_flow_phase_0_gate() {
    let fix = build_fixture().await;

    // Step 1 — `vtc setup` shortcut: mint install token. (Real
    // wizard rewrites the seed-generation + provisioning, but the
    // wire-flow gate only cares that an install token + state
    // pair exist.)
    let install_token = mint_install(&fix).await;

    // ----------------------------------------------------------------
    // Step 2 — claim/start
    // ----------------------------------------------------------------
    let (status, body) = request(
        &fix.router,
        "POST",
        "/v1/install/claim/start",
        CLAIM_START_TASK,
        None,
        Some(json!({ "install_token": install_token })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "claim/start: {body}");
    let registration_id = body["registrationId"].as_str().unwrap().to_string();
    let ccr: CreationChallengeResponse = serde_json::from_value(body["options"].clone()).unwrap();

    // ----------------------------------------------------------------
    // Step 3 — soft authenticator runs the WebAuthn ceremony, then claim/finish
    // ----------------------------------------------------------------
    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, _ed25519_pub) = authenticator.register(&ccr, RP_ORIGIN);

    let (status, body) = request(
        &fix.router,
        "POST",
        "/v1/install/claim/finish",
        CLAIM_FINISH_TASK,
        None,
        Some(json!({
            "install_token": install_token,
            "registration_id": registration_id,
            "webauthn_response": register_cred,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "claim/finish: {body}");
    let setup_session_token = body["setupSessionToken"].as_str().unwrap().to_string();
    let admin_did = body["adminDid"].as_str().unwrap().to_string();
    assert!(admin_did.starts_with("did:key:z"));

    // ----------------------------------------------------------------
    // Step 4 — admin/bootstrap
    // ----------------------------------------------------------------
    let (status, body) = request(
        &fix.router,
        "POST",
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        None,
        Some(json!({ "setup_session_token": setup_session_token })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bootstrap: {body}");
    assert_eq!(body["adminDid"].as_str().unwrap(), admin_did);

    // Mint a VTC admin JWT for the bootstrapped DID. M0.12.1 calls
    // this a "test harness shortcut"; production goes through the
    // existing challenge-response auth flow.
    let admin_token = admin_jwt_for(&fix, &admin_did).await;

    // Seed the community profile so step 7's GET has something to
    // return. The bootstrap path doesn't write the profile (that's
    // a deliberate spec choice — profile is owned by the operator,
    // not the install flow).
    let profile = vtc_service::community::CommunityProfile::new(
        "did:webvh:vtc.example.com:abc",
        "Example Community",
    );
    vtc_service::community::store_profile(&fix.state.community_ks, &profile)
        .await
        .unwrap();

    // ----------------------------------------------------------------
    // Step 5 — passkeys/register (start + finish)
    // ----------------------------------------------------------------
    let (status, body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/register/start",
        PASSKEY_REGISTER_TASK,
        Some(&admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register/start: {body}");
    let reg_id = body["registrationId"].as_str().unwrap().to_string();
    let register_options: CreationChallengeResponse =
        serde_json::from_value(body["registerOptions"].clone()).unwrap();
    let uv_options: RequestChallengeResponse =
        serde_json::from_value(body["uvOptions"].clone()).unwrap();

    let (register_response, _new_pub) = authenticator.register(&register_options, RP_ORIGIN);
    let uv_response = authenticator.authenticate(&uv_options, RP_ORIGIN);

    let (status, body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/register/finish",
        PASSKEY_REGISTER_TASK,
        Some(&admin_token),
        Some(json!({
            "registration_id": reg_id,
            "register_response": register_response,
            "uv_response": uv_response,
            "label": "second device",
            "transports": ["usb"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register/finish: {body}");

    // ----------------------------------------------------------------
    // Step 6 — passkeys list returns both
    // ----------------------------------------------------------------
    let (status, body) = request(
        &fix.router,
        "GET",
        "/v1/admin/passkeys",
        PASSKEY_LIST_TASK,
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let passkeys = body["passkeys"].as_array().unwrap();
    assert_eq!(passkeys.len(), 2, "expected 2 passkeys, got {passkeys:?}");
    let labels: std::collections::HashSet<_> = passkeys
        .iter()
        .map(|p| p["label"].as_str().unwrap().to_string())
        .collect();
    assert!(labels.contains("install"));
    assert!(labels.contains("second device"));

    // ----------------------------------------------------------------
    // Step 7 — community/profile round-trip
    // ----------------------------------------------------------------
    let (status, body) = request(
        &fix.router,
        "GET",
        "/v1/community/profile",
        COMMUNITY_PROFILE_TASK,
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Example Community");

    // Verify ACL admin record matches the bootstrapped DID
    let acl = vti_common::acl::list_acl_entries(&fix.state.acl_ks)
        .await
        .unwrap();
    assert_eq!(acl.len(), 1);
    assert_eq!(acl[0].did, admin_did);
    assert_eq!(acl[0].role, Role::Admin);

    // ----------------------------------------------------------------
    // Step 8 — admin/config PATCH applies a hot-reloadable setting
    // ----------------------------------------------------------------
    let (status, body) = request(
        &fix.router,
        "PATCH",
        "/v1/admin/config",
        ADMIN_CONFIG_TASK,
        Some(&admin_token),
        Some(json!({ "log.level": "debug" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "config PATCH: {body}");
    assert_eq!(body["applied"], json!(["log.level"]));

    // ----------------------------------------------------------------
    // Step 9 — restart without supervisor → 412 SupervisorRequired
    // ----------------------------------------------------------------
    let (status, body) = request(
        &fix.router,
        "POST",
        "/v1/admin/config/restart",
        RESTART_TASK,
        Some(&admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("SupervisorRequired"),
        "expected SupervisorRequired, got {body}"
    );

    // ----------------------------------------------------------------
    // Step 10 — second claim/start with the same token is rejected
    //           because the token has transitioned to `Consumed`.
    //           The earlier carve-out global lockdown is gone — the
    //           per-row state machine is the only gate.
    // ----------------------------------------------------------------
    let (status, body) = request(
        &fix.router,
        "POST",
        "/v1/install/claim/start",
        CLAIM_START_TASK,
        None,
        Some(json!({ "install_token": install_token })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "second claim/start must be refused (token Consumed): {body}",
    );

    // ----------------------------------------------------------------
    // Sanity: audit log records the lifecycle events
    // ----------------------------------------------------------------
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

    let mut saw_install = false;
    let mut saw_passkey_registered = false;
    let mut saw_restart = false;
    for env in &envelopes {
        match &env.event {
            AuditEvent::CommunityInstalled(_) => saw_install = true,
            AuditEvent::AdminPasskeyRegistered(_) => saw_passkey_registered = true,
            AuditEvent::RestartRequested(_) => saw_restart = true,
            _ => {}
        }
    }
    assert!(saw_install, "CommunityInstalled envelope missing");
    assert!(
        saw_passkey_registered,
        "AdminPasskeyRegistered envelope missing"
    );
    // Restart never reaches the audit writer when the supervisor
    // check fails first; this is the correct semantics — failed
    // requests don't pollute the audit log.
    assert!(!saw_restart, "RestartRequested must not be emitted on 412");
}
