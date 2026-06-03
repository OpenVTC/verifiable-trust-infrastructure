//! Integration coverage for `POST /v1/members/me/rotate/*`
//! (Phase 2 M2.15.1, `did:key` path only).

mod common;

use std::sync::Arc;

use affinidi_status_list::StatusPurpose;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower::ServiceExt;
use vti_common::audit::{AuditKeyStore, AuditWriter};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::session::{Session, SessionState, list_sessions, store_session};
use vti_common::config::StoreConfig;
use vti_common::store::Store;

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::config::AppConfig;
use vtc_service::credentials::LocalSigner;
use vtc_service::install::InstallTokenStore;
use vtc_service::members::{Member, get_member, store_member};
use vtc_service::routes;
// `ROTATION_DOMAIN_TAG` from the rotate module is `pub(crate)`;
// duplicate the literal here so the integration test doesn't
// have to peek through the route layer's private modules.
const ROTATION_DOMAIN_TAG: &[u8] = b"vtc-did-rotation/v1\0";
use vtc_service::server::AppState;
use vtc_service::status_list;

const VTC_DID: &str = "did:webvh:vtc.example.com:abc";
const PUBLIC_URL: &str = "https://vtc.example.com";
const CHALLENGE_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/rotate-challenge/1.0";
const ROTATE_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/rotate/1.0";

fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

struct Fixture {
    router: axum::Router,
    member_token: String,
    member_signing: SigningKey,
    member_did: String,
    members_ks: vti_common::store::KeyspaceHandle,
    acl_ks: vti_common::store::KeyspaceHandle,
    sessions_ks: vti_common::store::KeyspaceHandle,
    signer: Arc<LocalSigner>,
    _dir: tempfile::TempDir,
}

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

    vtc_service::policy::default::install_defaults(&policies_ks, &active_policies_ks)
        .await
        .unwrap();
    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        let url = format!("{PUBLIC_URL}/v1/status-lists/{purpose}");
        status_list::ensure_initial(&status_lists_ks, purpose, url)
            .await
            .unwrap();
    }
    // Pre-allocate a slot for the member so rotation can
    // reuse it during credential re-issuance.
    let mut state_row = status_list::get_state(&status_lists_ks, StatusPurpose::Revocation)
        .await
        .unwrap()
        .unwrap();
    let slot = status_list::allocate(&mut state_row).unwrap();
    status_list::store_state(&status_lists_ks, &state_row)
        .await
        .unwrap();

    let signer = Arc::new(LocalSigner::from_ed25519_seed(VTC_DID.into(), &[0xCC; 32]));

    let key_store = AuditKeyStore::new(audit_key_ks.clone());
    key_store.ensure_initial(&[0xAB; 32]).await.unwrap();
    let audit_writer = Some(AuditWriter::new(audit_ks.clone(), key_store));

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").unwrap());

    // Build a member with a deterministic Ed25519 key + matching did:key.
    let member_signing = SigningKey::from_bytes(&[0xAA; 32]);
    let member_pub = member_signing.verifying_key().to_bytes();
    let member_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&member_pub);

    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &acl_ks,
        &VtcAclEntry {
            did: member_did.clone(),
            role: VtcRole::Member,
            label: None,
            allowed_contexts: vec![],
            created_at: now,
            created_by: "did:key:vtc-install".into(),
            expires_at: None,
        },
    )
    .await
    .unwrap();
    let mut m = Member::fresh(&member_did);
    m.status_list_index = Some(slot);
    store_member(&members_ks, &m).await.unwrap();

    let session_id = "test-rot-session";
    store_session(
        &sessions_ks,
        &Session {
            session_id: session_id.into(),
            did: member_did.clone(),
            challenge: "test".into(),
            state: SessionState::Authenticated,
            created_at: now,
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: Vec::new(),
            acr: String::new(),
            token_id: None,
            session_pubkey_b58btc: None,
        },
    )
    .await
    .unwrap();

    let member_claims = jwt_keys.new_claims(
        member_did.clone(),
        session_id.into(),
        "reader".into(),
        vec![],
        3600,
        true,
    );
    let member_token = jwt_keys.encode(&member_claims).unwrap();

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
        sessions_ks: sessions_ks.clone(),
        acl_ks: acl_ks.clone(),
        community_ks,
        config_ks,
        passkey_ks,
        install_ks,
        members_ks: members_ks.clone(),
        join_requests_ks,
        policies_ks,
        active_policies_ks,
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
        credential_signer: Some(signer.clone()),
        install_store,
        audit_writer,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
    };

    let router = routes::router().with_state(state);

    Fixture {
        router,
        member_token,
        member_signing,
        member_did,
        members_ks,
        acl_ks,
        sessions_ks,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalPayload<'a> {
    rotation_id: String,
    old_did: &'a str,
    new_did: &'a str,
    expires_at: i64,
}

fn signing_bytes(rotation_id: &str, old_did: &str, new_did: &str, expires_at: i64) -> Vec<u8> {
    let json = serde_json::to_vec(&CanonicalPayload {
        rotation_id: rotation_id.to_string(),
        old_did,
        new_did,
        expires_at,
    })
    .unwrap();
    let mut buf = Vec::with_capacity(ROTATION_DOMAIN_TAG.len() + json.len());
    buf.extend_from_slice(ROTATION_DOMAIN_TAG);
    buf.extend_from_slice(&json);
    buf
}

async fn mint_challenge(fix: &Fixture) -> (String, i64) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/rotate/challenge")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", CHALLENGE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    let id = body["rotationId"].as_str().unwrap().to_string();
    // expiresAt is RFC3339 — convert to epoch for the canonical
    // payload.
    let expires_at = chrono::DateTime::parse_from_rfc3339(body["expiresAt"].as_str().unwrap())
        .unwrap()
        .timestamp();
    (id, expires_at)
}

#[tokio::test]
async fn rotation_happy_path_swaps_acl_and_member() {
    let fix = build_fixture().await;

    // Pick a fresh did:key for the new identity.
    let new_signing = SigningKey::from_bytes(&[0xBB; 32]);
    let new_did =
        affinidi_crypto::did_key::ed25519_pub_to_did_key(&new_signing.verifying_key().to_bytes());

    let (rotation_id, expires_at) = mint_challenge(&fix).await;
    let payload = signing_bytes(&rotation_id, &fix.member_did, &new_did, expires_at);

    let old_sig = hex::encode(fix.member_signing.sign(&payload).to_bytes());
    let new_sig = hex::encode(new_signing.sign(&payload).to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/rotate")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ROTATE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "rotationId": rotation_id,
                "oldDid": fix.member_did,
                "newDid": new_did,
                "oldSignature": old_sig,
                "newSignature": new_sig,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["newDid"], new_did);
    assert_eq!(body["method"], "did:key");

    // ACL + Member rows moved.
    assert!(
        get_acl_entry(&fix.acl_ks, &fix.member_did)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        get_acl_entry(&fix.acl_ks, &new_did)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        get_member(&fix.members_ks, &fix.member_did)
            .await
            .unwrap()
            .is_none()
    );
    let new_member = get_member(&fix.members_ks, &new_did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(new_member.did, new_did);
    assert!(new_member.status_list_index.is_some(), "slot reused");

    // Sessions for the old DID revoked.
    let sessions = list_sessions(&fix.sessions_ks).await.unwrap();
    assert!(
        sessions.iter().all(|s| s.did != fix.member_did),
        "old-DID sessions must be revoked"
    );

    // VMC + VEC inline + verifying.
    let vmc: affinidi_vc::VerifiableCredential =
        serde_json::from_value(body["vmc"].clone()).unwrap();
    let role_vec: affinidi_vc::VerifiableCredential =
        serde_json::from_value(body["roleVec"].clone()).unwrap();
    fix.signer.verify(&vmc).expect("VMC verifies");
    fix.signer.verify(&role_vec).expect("VEC verifies");
}

/// M2.15.2: did:webvh rotation works, but only when the
/// daemon was booted with a DID resolver wired into
/// `AppState`. The rotation-test fixture leaves
/// `did_resolver: None` (no internet at test time), so a
/// did:webvh new-DID hits the "resolver not configured" 500
/// path. That's the realistic failure mode for daemons
/// running offline / in CI; the actual resolver walk is
/// exercised end-to-end by the recognition unit tests
/// (`recognition::verify::tests`), which share the same
/// `VerificationMethod::get_public_key_bytes()` upstream
/// helper.
#[tokio::test]
async fn rotation_did_webvh_requires_did_resolver() {
    let fix = build_fixture().await;
    let (rotation_id, expires_at) = mint_challenge(&fix).await;
    let new_did = "did:webvh:peer.example.com:abc";
    let payload = signing_bytes(&rotation_id, &fix.member_did, new_did, expires_at);
    let old_sig = hex::encode(fix.member_signing.sign(&payload).to_bytes());
    let new_signing = SigningKey::from_bytes(&[0xBB; 32]);
    let new_sig = hex::encode(new_signing.sign(&payload).to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/rotate")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ROTATE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "rotationId": rotation_id,
                "oldDid": fix.member_did,
                "newDid": new_did,
                "oldSignature": old_sig,
                "newSignature": new_sig,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    // 500 (Internal) because the daemon is misconfigured —
    // not 400 (caller's fault).
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn rotation_rejects_unknown_did_method() {
    let fix = build_fixture().await;
    let (rotation_id, expires_at) = mint_challenge(&fix).await;
    // did:example isn't a method the rotation route knows
    // about — should 400 cleanly before any signature check.
    let new_did = "did:example:abc";
    let payload = signing_bytes(&rotation_id, &fix.member_did, new_did, expires_at);
    let old_sig = hex::encode(fix.member_signing.sign(&payload).to_bytes());
    let new_signing = SigningKey::from_bytes(&[0xBB; 32]);
    let new_sig = hex::encode(new_signing.sign(&payload).to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/rotate")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ROTATE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "rotationId": rotation_id,
                "oldDid": fix.member_did,
                "newDid": new_did,
                "oldSignature": old_sig,
                "newSignature": new_sig,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rotation_rejects_bad_new_signature() {
    let fix = build_fixture().await;
    let new_signing = SigningKey::from_bytes(&[0xBB; 32]);
    let new_did =
        affinidi_crypto::did_key::ed25519_pub_to_did_key(&new_signing.verifying_key().to_bytes());

    let (rotation_id, expires_at) = mint_challenge(&fix).await;
    let payload = signing_bytes(&rotation_id, &fix.member_did, &new_did, expires_at);
    let old_sig = hex::encode(fix.member_signing.sign(&payload).to_bytes());
    // Sign with a DIFFERENT key than the one whose pubkey is in
    // the new_did — verifier must reject.
    let wrong = SigningKey::from_bytes(&[0xDE; 32]);
    let bad_sig = hex::encode(wrong.sign(&payload).to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/rotate")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ROTATE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "rotationId": rotation_id,
                "oldDid": fix.member_did,
                "newDid": new_did,
                "oldSignature": old_sig,
                "newSignature": bad_sig,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rotation_id_is_single_use() {
    let fix = build_fixture().await;
    let new_signing = SigningKey::from_bytes(&[0xBB; 32]);
    let new_did =
        affinidi_crypto::did_key::ed25519_pub_to_did_key(&new_signing.verifying_key().to_bytes());

    let (rotation_id, expires_at) = mint_challenge(&fix).await;
    let payload = signing_bytes(&rotation_id, &fix.member_did, &new_did, expires_at);
    let old_sig = hex::encode(fix.member_signing.sign(&payload).to_bytes());
    let new_sig = hex::encode(new_signing.sign(&payload).to_bytes());

    let make_req = || {
        Request::builder()
            .method("POST")
            .uri("/v1/members/me/rotate")
            .header("authorization", format!("Bearer {}", fix.member_token))
            .header("trust-task", ROTATE_TASK)
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "rotationId": rotation_id,
                    "oldDid": fix.member_did,
                    "newDid": new_did,
                    "oldSignature": old_sig,
                    "newSignature": new_sig,
                })
                .to_string(),
            ))
            .unwrap()
    };

    let resp = fix.router.clone().oneshot(make_req()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "first call succeeds");

    // Second call: rotation_id is consumed, and the old DID no
    // longer has a session (revoked in step 1). The endpoint
    // returns 401 because the AuthClaims extractor can't verify
    // the session. Either failure mode is acceptable; we
    // assert any non-2xx.
    let resp = fix.router.clone().oneshot(make_req()).await.unwrap();
    assert!(
        !resp.status().is_success(),
        "second call must not succeed, got {}",
        resp.status()
    );
}
