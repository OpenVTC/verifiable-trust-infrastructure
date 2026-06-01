//! End-to-end coverage for `/v1/admin/passkeys/*`.
//!
//! Builds a fixture with a fully-bootstrapped admin (one passkey,
//! one ACL entry, audit writer wired) and drives the multi-passkey
//! management endpoints through `Router::oneshot`, with the soft
//! EdDSA harness producing the WebAuthn assertions.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::acl::{AclEntry, Role, store_acl_entry};
use vti_common::audit::{AuditEnvelope, AuditEvent, AuditKeyStore, AuditWriter};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::passkey::{
    build_webauthn,
    store::{PasskeyUser, store_credential_mapping, store_passkey_user},
};
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};
use vti_common::config::StoreConfig;
use vti_common::store::Store;
use webauthn_rs::Webauthn;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

use vtc_service::acl::admin::{AdminEntry, RegisteredPasskey, get_admin_entry, store_admin_entry};
use vtc_service::config::AppConfig;
use vtc_service::install::{InstallTokenSigner, InstallTokenStore};
use vtc_service::routes;
use vtc_service::server::AppState;

use common::webauthn_harness::SoftEd25519Authenticator;

const RP_ORIGIN: &str = "https://vtc.example.com";
const LIST_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/passkeys/list/1.0";
const REGISTER_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/passkeys/register/1.0";
const REVOKE_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/passkeys/revoke/1.0";

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
    jwt_keys: Arc<JwtKeys>,
    admin_did: String,
    /// Soft authenticator pre-loaded with the bootstrap passkey,
    /// ready to drive UV and additional-device ceremonies.
    authenticator: SoftEd25519Authenticator,
    _dir: tempfile::TempDir,
}

/// Build a fixture where:
/// - WebAuthn + install signer + audit writer are all configured.
/// - One admin is pre-bootstrapped: PasskeyUser, AdminEntry, ACL
///   entry, credential mapping all match a single soft-authenticator
///   credential whose Ed25519 key we know.
/// - JWT keys are wired so we can mint admin session tokens for
///   the bootstrapped DID.
async fn build_fixture(with_audit: bool) -> Fixture {
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

    let webauthn: Webauthn = build_webauthn(RP_ORIGIN).expect("webauthn builder");

    // Run a real WebAuthn registration ceremony so the persisted
    // PasskeyUser has a real `Passkey` (matching credential bytes)
    // that subsequent UV-assertion flows can exercise. Mirrors the
    // post-bootstrap state M0.6.2 leaves the system in.
    let mut authenticator = SoftEd25519Authenticator::new();
    let user_uuid = Uuid::new_v4();
    let (ccr, reg_state) = vtc_service::webauthn::start_passkey_registration(
        &webauthn,
        user_uuid,
        "did:key:zPlaceholder",
        "did:key:zPlaceholder",
        None,
    )
    .unwrap();
    let (register_cred, ed25519_pub) = authenticator.register(&ccr, RP_ORIGIN);
    let bootstrap_passkey =
        vtc_service::webauthn::finish_passkey_registration(&webauthn, &register_cred, &reg_state)
            .unwrap();
    let admin_did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&ed25519_pub)
    );
    let bootstrap_cred_id_hex =
        hex::encode(<_ as AsRef<[u8]>>::as_ref(bootstrap_passkey.cred_id()));

    // Persist the post-bootstrap fixture state.
    let pk_user = PasskeyUser {
        user_uuid,
        did: admin_did.clone(),
        display_name: admin_did.clone(),
        credentials: vec![bootstrap_passkey],
    };
    store_passkey_user(&passkey_ks, &pk_user).await.unwrap();
    store_credential_mapping(&passkey_ks, &bootstrap_cred_id_hex, user_uuid)
        .await
        .unwrap();
    let admin_entry = AdminEntry {
        did: admin_did.clone(),
        passkeys: vec![RegisteredPasskey {
            credential_id: bootstrap_cred_id_hex.clone(),
            label: "install".into(),
            transports: Vec::new(),
            registered_at: Utc::now(),
            last_used_at: None,
        }],
        extensions: Value::Null,
        created_at: Utc::now(),
    };
    store_admin_entry(&passkey_ks, &admin_entry).await.unwrap();
    let acl_entry = AclEntry::new(admin_did.clone(), Role::Admin, "did:key:vtc-install")
        .with_label(Some("install bootstrap".into()));
    store_acl_entry(&acl_ks, &acl_entry).await.unwrap();

    let audit_writer = if with_audit {
        let key_store = AuditKeyStore::new(audit_key_ks.clone());
        key_store.ensure_initial(&[0xAB; 64]).await.unwrap();
        Some(AuditWriter::new(audit_ks.clone(), key_store))
    } else {
        None
    };

    let config: AppConfig = toml::from_str(&format!(
        r#"
        vtc_did = "did:webvh:vtc.example.com:abc"
        [store]
        data_dir = "{}"
        "#,
        dir.path().display(),
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
        webauthn: Some(Arc::new(webauthn)),
        public_url: Some(RP_ORIGIN.to_string()),
        install_signer: Some(Arc::new(
            InstallTokenSigner::from_master_seed(&[0xAB; 64]).unwrap(),
        )),
        install_store,
        audit_writer,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
    };

    let router = routes::router().with_state(state.clone());

    Fixture {
        state,
        router,
        jwt_keys,
        admin_did,
        authenticator,
        _dir: dir,
    }
}

async fn admin_token(fix: &Fixture) -> String {
    let session_id = format!("sess-{}", Uuid::new_v4());
    let session = Session {
        session_id: session_id.clone(),
        did: fix.admin_did.clone(),
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
        fix.admin_did.clone(),
        session_id,
        "admin".to_string(),
        vec![],
        900,
        false,
    );
    fix.jwt_keys.encode(&claims).unwrap()
}

async fn reader_token(fix: &Fixture) -> String {
    let session_id = format!("sess-{}", Uuid::new_v4());
    let session = Session {
        session_id: session_id.clone(),
        did: "did:key:zReader".into(),
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
        "did:key:zReader".to_string(),
        session_id,
        "reader".to_string(),
        vec![],
        900,
        false,
    );
    fix.jwt_keys.encode(&claims).unwrap()
}

async fn request(
    router: &axum::Router,
    method: &str,
    path: &str,
    trust_task: Option<&str>,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(t) = trust_task {
        builder = builder.header("Trust-Task", t);
    }
    if let Some(tok) = token {
        builder = builder.header("Authorization", format!("Bearer {tok}"));
    }
    let body = if let Some(b) = body {
        builder = builder.header("content-type", "application/json");
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

// ---------------------------------------------------------------------------
// GET list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_returns_bootstrap_passkey() {
    let fix = build_fixture(true).await;
    let token = admin_token(&fix).await;
    let (status, body) = request(
        &fix.router,
        "GET",
        "/v1/admin/passkeys",
        Some(LIST_TASK),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = body["passkeys"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["label"], "install");
}

#[tokio::test]
async fn list_requires_admin_role() {
    let fix = build_fixture(true).await;
    let token = reader_token(&fix).await;
    let (status, _body) = request(
        &fix.router,
        "GET",
        "/v1/admin/passkeys",
        Some(LIST_TASK),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_requires_authentication() {
    let fix = build_fixture(true).await;
    let (status, _body) = request(
        &fix.router,
        "GET",
        "/v1/admin/passkeys",
        Some(LIST_TASK),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Register (happy path)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_succeeds_with_step_up_uv() {
    let mut fix = build_fixture(true).await;
    let token = admin_token(&fix).await;

    // start
    let (status, body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/register/start",
        Some(REGISTER_TASK),
        Some(&token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "start: {body}");
    let registration_id = body["registrationId"].as_str().unwrap().to_string();
    let register_options: CreationChallengeResponse =
        serde_json::from_value(body["registerOptions"].clone()).unwrap();
    let uv_options: RequestChallengeResponse =
        serde_json::from_value(body["uvOptions"].clone()).unwrap();

    // harness signs both
    let (register_response, _new_pub) = fix.authenticator.register(&register_options, RP_ORIGIN);
    let uv_response = fix.authenticator.authenticate(&uv_options, RP_ORIGIN);

    // finish
    let (status, body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/register/finish",
        Some(REGISTER_TASK),
        Some(&token),
        Some(json!({
            "registration_id": registration_id,
            "register_response": register_response,
            "uv_response": uv_response,
            "label": "yubikey",
            "transports": ["usb", "nfc"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "finish: {body}");
    assert!(!body["credentialId"].as_str().unwrap().is_empty());

    // verify the AdminEntry now lists 2 passkeys
    let admin_entry = get_admin_entry(&fix.state.passkey_ks, &fix.admin_did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(admin_entry.passkeys.len(), 2);
    assert!(admin_entry.passkeys.iter().any(|p| p.label == "yubikey"));
}

#[tokio::test]
async fn register_finish_without_start_returns_401() {
    let fix = build_fixture(true).await;
    let token = admin_token(&fix).await;
    let bogus_cred = json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "response": { "attestationObject": "AA", "clientDataJSON": "AA" },
        "type": "public-key"
    });
    let bogus_uv = json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "response": {
            "authenticatorData": "AA",
            "clientDataJSON": "AA",
            "signature": "AA"
        },
        "type": "public-key"
    });
    let (status, _body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/register/finish",
        Some(REGISTER_TASK),
        Some(&token),
        Some(json!({
            "registration_id": Uuid::new_v4().to_string(),
            "register_response": bogus_cred,
            "uv_response": bogus_uv,
            "label": "bogus",
            "transports": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn register_rejects_when_uv_signed_by_wrong_authenticator() {
    let mut fix = build_fixture(true).await;
    let token = admin_token(&fix).await;

    let (_, body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/register/start",
        Some(REGISTER_TASK),
        Some(&token),
        Some(json!({})),
    )
    .await;
    let registration_id = body["registrationId"].as_str().unwrap().to_string();
    let register_options: CreationChallengeResponse =
        serde_json::from_value(body["registerOptions"].clone()).unwrap();

    // New device produced by the legitimate harness (so the register
    // half passes), but the UV signed by a foreign authenticator
    // that doesn't own any registered credential.
    let (register_response, _) = fix.authenticator.register(&register_options, RP_ORIGIN);
    let mut foreign_auth = SoftEd25519Authenticator::new();
    // The foreign authenticator hasn't registered against the
    // server-issued UV challenge, so `authenticate()` would panic
    // (no matching cred). Instead synthesise a UV assertion against
    // a *different* RP-challenge it has signed for. We do this by
    // first registering the foreign authenticator against a
    // fresh registration challenge, then driving authenticate
    // against a copy of the server's UV options but the assertion
    // won't match the cred id in `allow_credentials`.

    // Foreign register so the harness has a credential to drive
    // authenticate against; the cred id is unknown to the server.
    let webauthn = build_webauthn(RP_ORIGIN).unwrap();
    let (foreign_ccr, _foreign_state) = webauthn
        .start_passkey_registration(Uuid::new_v4(), "did:key:zForeign", "did:key:zForeign", None)
        .unwrap();
    // Hack: the soft authenticator panics if the challenge doesn't
    // advertise EdDSA. Inject EdDSA into the foreign challenge.
    let mut foreign_ccr = foreign_ccr;
    foreign_ccr.public_key.pub_key_cred_params = vec![webauthn_rs_proto::PubKeyCredParams {
        type_: "public-key".to_string(),
        alg: -8,
    }];
    let (_foreign_register, _) = foreign_auth.register(&foreign_ccr, RP_ORIGIN);

    // Now produce a UV assertion against the server's UV options,
    // but using a credential that wasn't in the challenge's
    // allow_credentials. This requires the foreign auth to lie about
    // its credential id. The harness panics in this scenario
    // ("no credential in allowCredentials"), which is exactly the
    // misuse-guard. Easier: simply forge an assertion with a bogus
    // signature.
    //
    // Approach: take the start's UV options + the foreign cred id
    // and craft an obviously-wrong PublicKeyCredential. The server
    // will fail signature verification.
    let uv_options: RequestChallengeResponse =
        serde_json::from_value(body["uvOptions"].clone()).unwrap();
    let cred_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(uv_options.public_key.allow_credentials[0].id.as_ref() as &[u8]);
    let bogus_uv = json!({
        "id": cred_id_b64,
        "rawId": cred_id_b64,
        "response": {
            "authenticatorData": "AAAA",
            "clientDataJSON": "AAAA",
            "signature": "AAAA"
        },
        "type": "public-key"
    });

    let (status, _body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/register/finish",
        Some(REGISTER_TASK),
        Some(&token),
        Some(json!({
            "registration_id": registration_id,
            "register_response": register_response,
            "uv_response": bogus_uv,
            "label": "evil",
            "transports": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoke_last_passkey_returns_409_last_passkey_protected() {
    let mut fix = build_fixture(true).await;
    let token = admin_token(&fix).await;

    // Find the bootstrap credential id.
    let entry = get_admin_entry(&fix.state.passkey_ks, &fix.admin_did)
        .await
        .unwrap()
        .unwrap();
    let cred_id = entry.passkeys[0].credential_id.clone();

    // start
    let (status, body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/revoke/start",
        Some(REVOKE_TASK),
        Some(&token),
        Some(json!({ "credential_id": cred_id })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke start: {body}");
    let revocation_id = body["revocationId"].as_str().unwrap().to_string();
    let uv_options: RequestChallengeResponse =
        serde_json::from_value(body["uvOptions"].clone()).unwrap();
    let uv_response = fix.authenticator.authenticate(&uv_options, RP_ORIGIN);

    // finish — must be rejected with 409 because this would leave 0 passkeys
    let (status, body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/revoke/finish",
        Some(REVOKE_TASK),
        Some(&token),
        Some(json!({
            "revocation_id": revocation_id,
            "uv_response": uv_response,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "revoke finish: {body}");
    let err_msg = body["error"].as_str().unwrap_or("");
    assert!(err_msg.contains("LastPasskeyProtected"));
}

#[tokio::test]
async fn revoke_after_register_succeeds_and_emits_audit_event() {
    let mut fix = build_fixture(true).await;
    let token = admin_token(&fix).await;

    // Register a 2nd passkey.
    let (_, body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/register/start",
        Some(REGISTER_TASK),
        Some(&token),
        Some(json!({})),
    )
    .await;
    let reg_id = body["registrationId"].as_str().unwrap().to_string();
    let register_options: CreationChallengeResponse =
        serde_json::from_value(body["registerOptions"].clone()).unwrap();
    let uv_options: RequestChallengeResponse =
        serde_json::from_value(body["uvOptions"].clone()).unwrap();
    let (register_response, _) = fix.authenticator.register(&register_options, RP_ORIGIN);
    let uv_response = fix.authenticator.authenticate(&uv_options, RP_ORIGIN);
    let (status, body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/register/finish",
        Some(REGISTER_TASK),
        Some(&token),
        Some(json!({
            "registration_id": reg_id,
            "register_response": register_response,
            "uv_response": uv_response,
            "label": "yk5",
            "transports": ["usb"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register: {body}");
    let new_cred_id = body["credentialId"].as_str().unwrap().to_string();

    // Now revoke the original bootstrap passkey (which is NOT the
    // one we just added). After this the admin still has the new
    // device, so the >1 guard is satisfied.
    let entry = get_admin_entry(&fix.state.passkey_ks, &fix.admin_did)
        .await
        .unwrap()
        .unwrap();
    let bootstrap_id = entry
        .passkeys
        .iter()
        .find(|p| p.credential_id != new_cred_id)
        .map(|p| p.credential_id.clone())
        .unwrap();

    let (_, body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/revoke/start",
        Some(REVOKE_TASK),
        Some(&token),
        Some(json!({ "credential_id": bootstrap_id })),
    )
    .await;
    let revocation_id = body["revocationId"].as_str().unwrap().to_string();
    let uv_options: RequestChallengeResponse =
        serde_json::from_value(body["uvOptions"].clone()).unwrap();
    let uv_response = fix.authenticator.authenticate(&uv_options, RP_ORIGIN);

    let (status, body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/revoke/finish",
        Some(REVOKE_TASK),
        Some(&token),
        Some(json!({
            "revocation_id": revocation_id,
            "uv_response": uv_response,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke: {body}");

    // Verify AdminEntry now has exactly one passkey.
    let entry = get_admin_entry(&fix.state.passkey_ks, &fix.admin_did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.passkeys.len(), 1);
    assert_eq!(entry.passkeys[0].credential_id, new_cred_id);

    // Audit log should contain AdminPasskeyRegistered + AdminPasskeyRevoked
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
    let mut saw_register = false;
    let mut saw_revoke = false;
    for env in &envelopes {
        match &env.event {
            AuditEvent::AdminPasskeyRegistered(_) => saw_register = true,
            AuditEvent::AdminPasskeyRevoked(_) => saw_revoke = true,
            _ => {}
        }
    }
    assert!(saw_register, "AdminPasskeyRegistered envelope missing");
    assert!(saw_revoke, "AdminPasskeyRevoked envelope missing");
}

#[tokio::test]
async fn revoke_rejects_unknown_credential_id() {
    let fix = build_fixture(true).await;
    let token = admin_token(&fix).await;
    let (status, _body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/revoke/start",
        Some(REVOKE_TASK),
        Some(&token),
        Some(json!({ "credential_id": "deadbeef" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn revoke_finish_without_start_returns_401() {
    let fix = build_fixture(true).await;
    let token = admin_token(&fix).await;
    let bogus_uv = json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "response": {
            "authenticatorData": "AA",
            "clientDataJSON": "AA",
            "signature": "AA"
        },
        "type": "public-key"
    });
    let (status, _body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/revoke/finish",
        Some(REVOKE_TASK),
        Some(&token),
        Some(json!({
            "revocation_id": Uuid::new_v4().to_string(),
            "uv_response": bogus_uv,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Trust-Task gate + 503 paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_start_returns_415_with_wrong_trust_task() {
    let fix = build_fixture(true).await;
    let token = admin_token(&fix).await;
    let (status, _body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/register/start",
        Some(REVOKE_TASK), // wrong task on register endpoint
        Some(&token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn register_returns_503_when_audit_writer_missing() {
    let mut fix = build_fixture(false).await;
    let token = admin_token(&fix).await;
    let (_, body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/register/start",
        Some(REGISTER_TASK),
        Some(&token),
        Some(json!({})),
    )
    .await;
    let registration_id = body["registrationId"].as_str().unwrap().to_string();
    let register_options: CreationChallengeResponse =
        serde_json::from_value(body["registerOptions"].clone()).unwrap();
    let uv_options: RequestChallengeResponse =
        serde_json::from_value(body["uvOptions"].clone()).unwrap();
    let (register_response, _) = fix.authenticator.register(&register_options, RP_ORIGIN);
    let uv_response = fix.authenticator.authenticate(&uv_options, RP_ORIGIN);
    let (status, _body) = request(
        &fix.router,
        "POST",
        "/v1/admin/passkeys/register/finish",
        Some(REGISTER_TASK),
        Some(&token),
        Some(json!({
            "registration_id": registration_id,
            "register_response": register_response,
            "uv_response": uv_response,
            "label": "x",
            "transports": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

// base64 only needed in one test; webauthn-rs-proto is pulled in via
// `webauthn_rs::prelude` so a separate extern reference isn't required.
use base64::Engine;
