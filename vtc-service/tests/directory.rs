//! Integration coverage for the directory ceremony
//! (`GET /v1/directory/{did}`).
//!
//! Exercises the full decision pipeline through a real HTTP request:
//! auth → facts-assembly (ACL + member reads) → evaluate (active
//! `directory.rego`) → invariant → decide → PII-bounded projection.
//!
//! The viewers below carry a JWT `role` of `admin` regardless of their
//! community standing — the directory route reads the *community* role
//! from the ACL keyspace, not the JWT. The member viewer getting a
//! member-level projection despite an `admin` JWT role is the assertion
//! that proves that separation.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tokio::sync::RwLock;
use tower::ServiceExt;
use vti_common::audit::{AuditKeyStore, AuditWriter};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::passkey::build_webauthn;
use vti_common::auth::session::{Session, SessionState, store_session};
use vti_common::config::StoreConfig;
use vti_common::store::{KeyspaceHandle, Store};

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::config::AppConfig;
use vtc_service::install::InstallTokenStore;
use vtc_service::members::{Member, store_member};
use vtc_service::policy::default::install_defaults;
use vtc_service::routes;
use vtc_service::server::AppState;

const RP_ORIGIN: &str = "https://vtc.example.com";
const DIRECTORY_TASK: &str = "https://trusttasks.org/openvtc/vtc/directory/query/1.0";
const ADMIN_DID: &str = "did:key:zAdmin1";

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
    sessions_ks: KeyspaceHandle,
    acl_ks: KeyspaceHandle,
    members_ks: KeyspaceHandle,
    admin_token: String,
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

    // The directory route reads the active `directory` policy, so the
    // bundled defaults must be installed (server boot does this).
    install_defaults(&policies_ks, &active_policies_ks)
        .await
        .expect("install default policies");

    let install_store = InstallTokenStore::new(install_ks.clone());
    let webauthn = Some(Arc::new(build_webauthn(RP_ORIGIN).expect("build webauthn")));

    let key_store = AuditKeyStore::new(audit_key_ks.clone());
    key_store.ensure_initial(&[0xAB; 32]).await.unwrap();
    let audit_writer = Some(AuditWriter::new(audit_ks.clone(), key_store));

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").unwrap());

    // Admin viewer: community-admin ACL row + an authenticated session.
    store_acl_entry(
        &acl_ks,
        &VtcAclEntry {
            did: ADMIN_DID.into(),
            role: VtcRole::Admin,
            label: Some("test admin".into()),
            allowed_contexts: vec![],
            created_at: vtc_service::auth::session::now_epoch(),
            created_by: "did:key:vtc-install".into(),
            expires_at: None,
        },
    )
    .await
    .unwrap();

    let config: AppConfig = toml::from_str(&format!(
        r#"
        vtc_did = "did:webvh:vtc.example.com:abc"
        public_url = "{RP_ORIGIN}"
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
        credential_signer: None,
        audit_ks,
        audit_key_ks,
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: Some(jwt_keys.clone()),
        atm: None,
        webauthn,
        public_url: Some(RP_ORIGIN.to_string()),
        install_signer: None,
        install_store,
        audit_writer,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
    };

    let router = routes::router().with_state(state);
    let admin_token = mint_token(&jwt_keys, &sessions_ks, ADMIN_DID).await;

    Fixture {
        router,
        jwt_keys,
        sessions_ks,
        acl_ks,
        members_ks,
        admin_token,
        _dir: dir,
    }
}

/// Mint an authenticated session + matching JWT for `did`. The JWT
/// `role` is always `admin`; the directory route ignores it and reads
/// the community role from the ACL.
async fn mint_token(jwt_keys: &Arc<JwtKeys>, sessions_ks: &KeyspaceHandle, did: &str) -> String {
    let now = vtc_service::auth::session::now_epoch();
    let session_id = format!("session-{did}");
    let session = Session {
        session_id: session_id.clone(),
        did: did.into(),
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
    };
    store_session(sessions_ks, &session).await.unwrap();
    let claims = jwt_keys.new_claims(did.into(), session_id, "admin".into(), vec![], 3600, true);
    jwt_keys.encode(&claims).unwrap()
}

/// Seed a member: an ACL row (community role) + a Member record.
async fn seed_member(fix: &Fixture, did: &str, role: VtcRole) {
    store_acl_entry(
        &fix.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role,
            label: None,
            allowed_contexts: vec![],
            created_at: vtc_service::auth::session::now_epoch(),
            created_by: "did:key:vtc-install".into(),
            expires_at: None,
        },
    )
    .await
    .unwrap();
    store_member(&fix.members_ks, &Member::fresh(did))
        .await
        .unwrap();
}

async fn get_directory(
    router: &axum::Router,
    subject: &str,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("GET")
        .uri(format!("/v1/directory/{subject}"))
        .header("Trust-Task", DIRECTORY_TASK);
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let res = router
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
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

/// An admin viewer sees the fuller projection (did, role, joined_at,
/// status) of a member subject.
#[tokio::test]
async fn admin_viewer_sees_full_record() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zSubject", VtcRole::Member).await;

    let (status, body) =
        get_directory(&fix.router, "did:key:zSubject", Some(&fix.admin_token)).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["subject"], "did:key:zSubject");
    let fields = &body["fields"];
    assert_eq!(fields["did"], "did:key:zSubject");
    assert_eq!(fields["role"], "member");
    assert_eq!(fields["status"], "active");
    assert!(
        fields["joined_at"].is_string(),
        "joined_at present for admin: {body}"
    );
}

/// A community-member viewer sees only `did` + `role` — the PII
/// boundary + the member branch of the policy drop the rest. The
/// viewer's JWT role is `admin`; getting a member-level projection
/// proves the route reads the community role from the ACL, not the JWT.
#[tokio::test]
async fn member_viewer_sees_did_and_role_only() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zViewer", VtcRole::Member).await;
    seed_member(&fix, "did:key:zSubject", VtcRole::Member).await;
    let viewer_token = mint_token(&fix.jwt_keys, &fix.sessions_ks, "did:key:zViewer").await;

    let (status, body) = get_directory(&fix.router, "did:key:zSubject", Some(&viewer_token)).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    let fields = &body["fields"];
    assert_eq!(fields["did"], "did:key:zSubject");
    assert_eq!(fields["role"], "member");
    // PII boundary: a member viewer never sees status / joined_at.
    assert!(
        fields.get("status").is_none(),
        "status must be hidden from member viewer: {body}"
    );
    assert!(
        fields.get("joined_at").is_none(),
        "joined_at must be hidden from member viewer: {body}"
    );
}

/// An unauthenticated request is rejected by the auth extractor before
/// the ceremony runs.
#[tokio::test]
async fn unauthenticated_is_rejected() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zSubject", VtcRole::Member).await;

    let (status, _) = get_directory(&fix.router, "did:key:zSubject", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// An admin viewer querying a non-member subject gets only the echoed
/// `did` — there is no member row to project the other fields from, so
/// the projection drops them rather than inventing them.
#[tokio::test]
async fn non_member_subject_projects_did_only() {
    let fix = build_fixture().await;

    let (status, body) = get_directory(&fix.router, "did:key:zGhost", Some(&fix.admin_token)).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    let fields = &body["fields"];
    assert_eq!(fields["did"], "did:key:zGhost");
    assert!(
        fields.get("role").is_none(),
        "no role for a non-member: {body}"
    );
    assert!(fields.get("status").is_none());
    assert!(fields.get("joined_at").is_none());
}
