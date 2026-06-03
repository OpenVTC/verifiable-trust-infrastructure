//! Integration coverage for `POST /v1/members/me/renew`
//! (Phase 2 M2.13).
//!
//! Verifies:
//! - Happy path re-mints VMC + role VEC and stamps the new
//!   ids on the Member row.
//! - Renewal reuses the same status-list slot the member was
//!   allocated at join time.
//! - 404 when the caller isn't a member.
//! - Both signed VCs verify against the daemon's signer.

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
use vti_common::auth::session::{Session, SessionState, store_session};
use vti_common::config::StoreConfig;
use vti_common::store::Store;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::config::AppConfig;
use vtc_service::credentials::LocalSigner;
use vtc_service::install::InstallTokenStore;
use vtc_service::members::{Member, get_member, store_member};
use vtc_service::routes;
use vtc_service::server::AppState;
use vtc_service::status_list;

const VTC_DID: &str = "did:webvh:vtc.example.com:abc";
const PUBLIC_URL: &str = "https://vtc.example.com";
const RENEW_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/renew/1.0";
const MEMBER_DID: &str = "did:key:zRenewMember";

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
    signer: Arc<LocalSigner>,
    members_ks: vti_common::store::KeyspaceHandle,
    status_lists_ks: vti_common::store::KeyspaceHandle,
    policies_ks: vti_common::store::KeyspaceHandle,
    active_policies_ks: vti_common::store::KeyspaceHandle,
    audit_ks: vti_common::store::KeyspaceHandle,
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
        .expect("install default policies");

    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        let url = format!("{PUBLIC_URL}/v1/status-lists/{purpose}");
        status_list::ensure_initial(&status_lists_ks, purpose, url)
            .await
            .unwrap();
    }

    let signer = Arc::new(LocalSigner::from_ed25519_seed(VTC_DID.into(), &[0xCC; 32]));

    let key_store = AuditKeyStore::new(audit_key_ks.clone());
    key_store.ensure_initial(&[0xAB; 32]).await.unwrap();
    let audit_writer = Some(AuditWriter::new(audit_ks.clone(), key_store));

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").unwrap());

    // Seed a Member ACL row + Member metadata row.
    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &acl_ks,
        &VtcAclEntry {
            did: MEMBER_DID.into(),
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
    store_member(&members_ks, &Member::fresh(MEMBER_DID))
        .await
        .unwrap();

    let session_id = "test-member-session";
    store_session(
        &sessions_ks,
        &Session {
            session_id: session_id.into(),
            did: MEMBER_DID.into(),
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
        MEMBER_DID.into(),
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
        sessions_ks,
        acl_ks,
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

    let router = routes::router().with_state(state.clone());

    Fixture {
        router,
        member_token,
        signer,
        members_ks,
        status_lists_ks,
        policies_ks: state.policies_ks,
        active_policies_ks: state.active_policies_ks,
        audit_ks: state.audit_ks,
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

#[tokio::test]
async fn renew_mints_fresh_vmc_and_role_vec() {
    let fix = build_fixture().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/renew")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", RENEW_TASK)
        .header("content-type", "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;

    assert_eq!(body["did"], MEMBER_DID);
    assert_eq!(body["personhood"], false);
    assert_eq!(body["personhoodChanged"], false);

    let vmc: affinidi_vc::VerifiableCredential =
        serde_json::from_value(body["vmc"].clone()).unwrap();
    let role_vec: affinidi_vc::VerifiableCredential =
        serde_json::from_value(body["roleVec"].clone()).unwrap();
    fix.signer.verify(&vmc).expect("VMC verifies");
    fix.signer.verify(&role_vec).expect("VEC verifies");

    // Member row updated with the new ids + the freshly-
    // allocated slot.
    let m = get_member(&fix.members_ks, MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    assert!(m.current_vmc_id.is_some());
    assert!(m.current_role_vec_id.is_some());
    assert!(m.status_list_index.is_some());
}

#[tokio::test]
async fn renew_reuses_existing_status_list_slot() {
    let fix = build_fixture().await;

    // Pre-allocate a slot for the member.
    let mut state = status_list::get_state(&fix.status_lists_ks, StatusPurpose::Revocation)
        .await
        .unwrap()
        .unwrap();
    let pinned_slot = status_list::allocate(&mut state).unwrap();
    status_list::store_state(&fix.status_lists_ks, &state)
        .await
        .unwrap();
    let mut m = get_member(&fix.members_ks, MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    m.status_list_index = Some(pinned_slot);
    store_member(&fix.members_ks, &m).await.unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/renew")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", RENEW_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let m = get_member(&fix.members_ks, MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        m.status_list_index,
        Some(pinned_slot),
        "renewal must reuse the existing slot"
    );
}

#[tokio::test]
async fn renew_requires_authentication() {
    let fix = build_fixture().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/renew")
        .header("trust-task", RENEW_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Phase 4 M4.2.2: renewal personhood eval ─────────────

#[tokio::test]
async fn renew_preserves_personhood_when_already_asserted() {
    // Member.personhood = true, default policy preserves on
    // renewal. The new VMC should carry personhood: true.
    let fix = build_fixture().await;
    let mut m = get_member(&fix.members_ks, MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    m.personhood = true;
    m.personhood_asserted_at = Some(chrono::Utc::now());
    store_member(&fix.members_ks, &m).await.unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/renew")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", RENEW_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["personhood"], true);
    assert_eq!(body["personhoodChanged"], false);

    let m2 = get_member(&fix.members_ks, MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    assert!(m2.personhood);
    assert!(m2.personhood_asserted_at.is_some());
}

#[tokio::test]
async fn renew_default_downgrades_when_policy_drops_flag() {
    // Member.personhood = true but we activate a strict
    // policy that denies for everyone. With default
    // on_personhood_fail = Downgrade, renewal succeeds with
    // personhood: false; Member row flips + paired
    // PersonhoodRevoked envelope is emitted.
    //
    // The Refuse-mode arm is exercised by a Fixture variant
    // that takes a PersonhoodFailMode parameter — deferred
    // to PR-2 alongside the assert/revoke endpoints.
    use vti_common::audit::AuditEvent;

    let fix = build_fixture().await;

    let mut m = get_member(&fix.members_ks, MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    m.personhood = true;
    m.personhood_asserted_at = Some(chrono::Utc::now());
    store_member(&fix.members_ks, &m).await.unwrap();

    // Activate a strict deny-all personhood policy via the
    // fixture's already-open keyspace handles (fjall is
    // single-process-locked; can't re-open the dir).
    let src = "package vtc.personhood\nimport rego.v1\ndefault allow := false\n";
    use sha2::{Digest, Sha256};
    let sha: [u8; 32] = Sha256::digest(src.as_bytes()).into();
    let id = uuid::Uuid::new_v4();
    let strict = vtc_service::policy::Policy {
        id,
        purpose: vtc_service::policy::PolicyPurpose::Personhood,
        rego_source: src.into(),
        sha256: sha,
        activated_at: Some(chrono::Utc::now()),
        author_did: "did:key:test".into(),
        created_at: chrono::Utc::now(),
        version: 1,
    };
    vtc_service::policy::store_policy(&fix.policies_ks, &strict)
        .await
        .unwrap();
    vtc_service::policy::set_active_policy_id(
        &fix.active_policies_ks,
        vtc_service::policy::PolicyPurpose::Personhood,
        id,
    )
    .await
    .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/renew")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", RENEW_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "downgrade must succeed");

    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["personhood"], false, "downgraded");
    assert_eq!(body["personhoodChanged"], true);

    let m2 = get_member(&fix.members_ks, MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    assert!(!m2.personhood);
    assert!(m2.personhood_asserted_at.is_none());

    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw_revoked = false;
    for (_k, v) in pairs {
        let env: vti_common::audit::AuditEnvelope = serde_json::from_slice(&v).unwrap();
        if let AuditEvent::PersonhoodRevoked(data) = env.event
            && data.reason == "renewal-policy"
        {
            saw_revoked = true;
            break;
        }
    }
    assert!(
        saw_revoked,
        "downgrade path must emit PersonhoodRevoked with reason=renewal-policy"
    );
}
