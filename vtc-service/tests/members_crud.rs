//! Integration coverage for `/v1/members/*` (Phase 1 M1.4–M1.6).
//!
//! Tests the wire shapes + auth gates of the list/show/update +
//! promote-to-admin endpoints. The full UV ceremony for
//! promote-to-admin needs the WebAuthn soft authenticator and
//! lives separately (mirrors the admin/passkeys test split).

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
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
use vtc_service::routes;
use vtc_service::server::AppState;

const RP_ORIGIN: &str = "https://vtc.example.com";
const LIST_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/list/1.0";
const SHOW_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/show/1.0";
const PROMOTE_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/promote-to-admin/1.0";

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
    admin_token: String,
    acl_ks: KeyspaceHandle,
    members_ks: KeyspaceHandle,
    #[allow(dead_code)]
    join_requests_ks: KeyspaceHandle,
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

    // Role changes (PATCH /v1/members/{did}) run through the
    // role-change ceremony, which needs the active decision policy + a
    // credential signer to re-mint the role VEC.
    vtc_service::policy::default::install_defaults(&policies_ks, &active_policies_ks)
        .await
        .expect("install default policies");
    let credential_signer = Some(Arc::new(
        vtc_service::credentials::LocalSigner::from_ed25519_seed(
            "did:webvh:vtc.example.com:abc".into(),
            &[0xCC; 32],
        ),
    ));

    let install_store = InstallTokenStore::new(install_ks.clone());
    let webauthn = Some(Arc::new(build_webauthn(RP_ORIGIN).expect("build webauthn")));

    let key_store = AuditKeyStore::new(audit_key_ks.clone());
    key_store.ensure_initial(&[0xAB; 32]).await.unwrap();
    let audit_writer = Some(AuditWriter::new(audit_ks.clone(), key_store));

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").unwrap());

    // Seed an admin ACL row + Member row so the existing fixture
    // helpers can mint a session token for the admin DID.
    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &acl_ks,
        &VtcAclEntry {
            did: ADMIN_DID.into(),
            role: VtcRole::Admin,
            label: Some("test admin".into()),
            allowed_contexts: vec![],
            created_at: now,
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

    // Mint a session row that matches the JWT we hand back. The
    // AuthClaims extractor requires both a valid JWT AND a
    // matching `session_id` row in the sessions keyspace.
    let session_id = "test-admin-session";
    let session = Session {
        session_id: session_id.into(),
        did: ADMIN_DID.into(),
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
    store_session(&sessions_ks, &session).await.unwrap();

    let admin_claims = jwt_keys.new_claims(
        ADMIN_DID.into(),
        session_id.into(),
        "admin".into(),
        vec![],
        3600,
        true,
    );
    let admin_token = jwt_keys.encode(&admin_claims).unwrap();

    let state = AppState {
        sessions_ks,
        acl_ks: acl_ks.clone(),
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
        credential_signer,
        audit_ks,
        audit_key_ks,
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: Some(jwt_keys),
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

    Fixture {
        router,
        admin_token,
        acl_ks,
        members_ks,
        join_requests_ks,
        _dir: dir,
    }
}

async fn seed_member(fix: &Fixture, did: &str, role: VtcRole) {
    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &fix.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role,
            label: None,
            allowed_contexts: vec![],
            created_at: now,
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

async fn send(
    router: &axum::Router,
    method: &str,
    uri: &str,
    trust_task: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("Trust-Task", trust_task);
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let res = router
        .clone()
        .oneshot(
            req.body(
                body.map(|v| Body::from(v.to_string()))
                    .unwrap_or(Body::empty()),
            )
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

// ---------------------------------------------------------------------------
// M1.4 — list + show
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_members_empty_returns_empty_items() {
    let fix = build_fixture().await;
    let (status, body) = send(
        &fix.router,
        "GET",
        "/v1/members",
        LIST_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["items"], json!([]));
    assert!(body["nextCursor"].is_null());
}

#[tokio::test]
async fn list_members_returns_seeded_members() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zMember1", VtcRole::Member).await;
    seed_member(&fix, "did:key:zMember2", VtcRole::Moderator).await;

    let (status, body) = send(
        &fix.router,
        "GET",
        "/v1/members",
        LIST_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let roles: Vec<&str> = items.iter().map(|m| m["role"].as_str().unwrap()).collect();
    assert!(roles.contains(&"member"));
    assert!(roles.contains(&"moderator"));
}

#[tokio::test]
async fn list_members_filter_by_role_drops_non_matching() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zMember1", VtcRole::Member).await;
    seed_member(&fix, "did:key:zMod1", VtcRole::Moderator).await;

    let (status, body) = send(
        &fix.router,
        "GET",
        "/v1/members?role=moderator",
        LIST_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["did"], "did:key:zMod1");
}

#[tokio::test]
async fn list_members_requires_admin_role() {
    let fix = build_fixture().await;
    let (status, _) = send(&fix.router, "GET", "/v1/members", LIST_TASK, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn show_member_returns_joined_response() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zM1", VtcRole::Issuer).await;

    let (status, body) = send(
        &fix.router,
        "GET",
        "/v1/members/did:key:zM1",
        SHOW_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["did"], "did:key:zM1");
    assert_eq!(body["role"], "issuer");
    assert!(body["joinedAt"].is_string());
    assert_eq!(body["publishConsent"], false);
    assert_eq!(body["departurePreference"], "policydefault");
}

#[tokio::test]
async fn show_member_returns_404_for_unknown_did() {
    let fix = build_fixture().await;
    let (status, _) = send(
        &fix.router,
        "GET",
        "/v1/members/did:key:zNobody",
        SHOW_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// M1.5 — PATCH
// ---------------------------------------------------------------------------

#[tokio::test]
async fn patch_member_role_member_to_moderator_succeeds_and_emits_audit() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zM1", VtcRole::Member).await;

    let (status, body) = send(
        &fix.router,
        "PATCH",
        "/v1/members/did:key:zM1",
        SHOW_TASK,
        Some(&fix.admin_token),
        Some(json!({ "role": "moderator" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["role"], "moderator");

    // Confirm the on-disk ACL row reflects the change.
    let entry = vtc_service::acl::get_acl_entry(&fix.acl_ks, "did:key:zM1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.role, VtcRole::Moderator);
}

#[tokio::test]
async fn patch_member_role_admin_is_refused_with_promote_hint() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zM1", VtcRole::Member).await;

    let (status, body) = send(
        &fix.router,
        "PATCH",
        "/v1/members/did:key:zM1",
        SHOW_TASK,
        Some(&fix.admin_token),
        Some(json!({ "role": "admin" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "got {body}");
    let msg = body.to_string();
    assert!(
        msg.contains("promote-to-admin"),
        "expected operator hint, got {msg}"
    );
}

#[tokio::test]
async fn patch_member_profile_only_emits_member_updated() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zM1", VtcRole::Member).await;

    let (status, body) = send(
        &fix.router,
        "PATCH",
        "/v1/members/did:key:zM1",
        SHOW_TASK,
        Some(&fix.admin_token),
        Some(json!({
            "publishConsent": true,
            "departurePreference": "purge",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["publishConsent"], true);
    assert_eq!(body["departurePreference"], "purge");
    // Role unchanged.
    assert_eq!(body["role"], "member");
}

#[tokio::test]
async fn patch_member_404_for_unknown_did() {
    let fix = build_fixture().await;
    let (status, _) = send(
        &fix.router,
        "PATCH",
        "/v1/members/did:key:zNobody",
        SHOW_TASK,
        Some(&fix.admin_token),
        Some(json!({ "publishConsent": true })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// M1.6 — promote-to-admin pre-flight (full UV ceremony is in
// `tests/admin_passkeys.rs`-style harness coverage, separate)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn promote_rejects_caller_promoting_themselves() {
    let fix = build_fixture().await;
    let (status, body) = send(
        &fix.router,
        "POST",
        &format!("/v1/members/{ADMIN_DID}/promote-to-admin/start"),
        PROMOTE_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "got {body}");
    let msg = body.to_string();
    assert!(msg.contains("cannot promote yourself"), "got {msg}");
}

#[tokio::test]
async fn promote_404_for_non_member_target() {
    let fix = build_fixture().await;
    let (status, _) = send(
        &fix.router,
        "POST",
        "/v1/members/did:key:zNobody/promote-to-admin/start",
        PROMOTE_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn promote_409_when_target_is_already_admin() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zSecondAdmin", VtcRole::Admin).await;
    let (status, _) = send(
        &fix.router,
        "POST",
        "/v1/members/did:key:zSecondAdmin/promote-to-admin/start",
        PROMOTE_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}
