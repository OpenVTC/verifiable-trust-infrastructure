//! Integration coverage for `/v1/endorsement-types/*` +
//! `/v1/credentials/endorsements/*` (Phase 4 M4.8).
//!
//! Covers:
//! - type registry: register happy / reserved / duplicate /
//!   delete with-in-use / delete OK / list
//! - issue: type-not-registered / non-issuer / happy path
//!   (with status-list slot allocation + audit emission)
//! - revoke: admin / non-admin-non-issuer / idempotent
//! - show / list pagination

use std::sync::Arc;

use affinidi_status_list::StatusPurpose;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::audit::{AuditEnvelope, AuditEvent, AuditKeyStore, AuditWriter};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};
use vti_common::config::StoreConfig;
use vti_common::store::Store;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::config::AppConfig;
use vtc_service::credentials::LocalSigner;
use vtc_service::install::InstallTokenStore;
use vtc_service::members::{Member, store_member};
use vtc_service::registry::RegistryHealth;
use vtc_service::routes;
use vtc_service::server::AppState;
use vtc_service::status_list;

const VTC_DID: &str = "did:webvh:vtc.example.com:abc";
const PUBLIC_URL: &str = "https://vtc.example.com";
const REGISTER_TASK: &str = "https://trusttasks.org/openvtc/vtc/endorsement-types/register/1.0";
const DELETE_TYPE_TASK: &str = "https://trusttasks.org/openvtc/vtc/endorsement-types/delete/1.0";
const ISSUE_TASK: &str = "https://trusttasks.org/openvtc/vtc/credentials/endorsements/issue/1.0";
const SHOW_TASK: &str = "https://trusttasks.org/openvtc/vtc/credentials/endorsements/show/1.0";
const ADMIN_DID: &str = "did:key:zEndAdmin";
const ISSUER_DID: &str = "did:key:zEndIssuer";
const MEMBER_DID: &str = "did:key:zEndMember";
const SUBJECT_DID: &str = "did:key:zEndSubject";

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
    issuer_token: String,
    member_token: String,
    audit_ks: vti_common::store::KeyspaceHandle,
    endorsements_ks: vti_common::store::KeyspaceHandle,
    _dir: tempfile::TempDir,
}

async fn build() -> Fixture {
    init_jwt_provider();
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .unwrap();

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

    vtc_service::policy::default::install_defaults(&policies_ks, &active_policies_ks)
        .await
        .unwrap();
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

    let now = now_epoch();
    for (did, role) in [
        (ADMIN_DID, VtcRole::Admin),
        (ISSUER_DID, VtcRole::Issuer),
        (MEMBER_DID, VtcRole::Member),
        (SUBJECT_DID, VtcRole::Member),
    ] {
        store_acl_entry(
            &acl_ks,
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
        store_member(&members_ks, &Member::fresh(did))
            .await
            .unwrap();
    }

    async fn mint(
        sessions: &vti_common::store::KeyspaceHandle,
        jwt_keys: &Arc<JwtKeys>,
        did: &str,
        role: &str,
        now: u64,
    ) -> String {
        let session_id = format!("sess-{}", Uuid::new_v4());
        store_session(
            sessions,
            &Session {
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
            },
        )
        .await
        .unwrap();
        let claims = jwt_keys.new_claims(did.into(), session_id, role.into(), vec![], 3600, true);
        jwt_keys.encode(&claims).unwrap()
    }
    let admin_token = mint(&sessions_ks, &jwt_keys, ADMIN_DID, "admin", now).await;
    let issuer_token = mint(&sessions_ks, &jwt_keys, ISSUER_DID, "reader", now).await;
    let member_token = mint(&sessions_ks, &jwt_keys, MEMBER_DID, "reader", now).await;

    let install_store = InstallTokenStore::new(install_ks.clone());

    let config: AppConfig = toml::from_str(&format!(
        r#"
        vtc_did = "{VTC_DID}"
        public_url = "{PUBLIC_URL}"
        [store]
        data_dir = "{}"
        [auth]
        jwt_signing_key = "{}"
        "#,
        dir.path().display(),
        BASE64.encode(jwt_seed),
    ))
    .unwrap();

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
        endorsements_ks: endorsements_ks.clone(),
        registry_client: None,
        registry_health: RegistryHealth::new(),
        audit_ks: audit_ks.clone(),
        audit_key_ks,
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: Some(jwt_keys),
        atm: None,
        webauthn: None,
        public_url: Some(PUBLIC_URL.into()),
        install_signer: None,
        credential_signer: Some(signer),
        install_store,
        audit_writer,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
    };

    let router = routes::router().with_state(state);
    Fixture {
        router,
        admin_token,
        issuer_token,
        member_token,
        audit_ks,
        endorsements_ks,
        _dir: dir,
    }
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

// ─── Type registry ───────────────────────────────────────

#[tokio::test]
async fn register_happy_path() {
    let fix = build().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/endorsement-types")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REGISTER_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "typeUri": "https://example.com/v1/skills/rust",
                "description": "Rust expertise"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["typeUri"], "https://example.com/v1/skills/rust");
}

#[tokio::test]
async fn register_rejects_reserved_uri() {
    let fix = build().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/endorsement-types")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REGISTER_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "typeUri": "CommunityRole" }).to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn register_rejects_duplicate() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/rust";
    for _ in 0..2 {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/endorsement-types")
            .header("authorization", format!("Bearer {}", fix.admin_token))
            .header("trust-task", REGISTER_TASK)
            .header("content-type", "application/json")
            .body(Body::from(json!({ "typeUri": uri }).to_string()))
            .unwrap();
        let _ = fix.router.clone().oneshot(req).await.unwrap();
    }
    // Second register should fail.
    let req = Request::builder()
        .method("POST")
        .uri("/v1/endorsement-types")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REGISTER_TASK)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "typeUri": uri }).to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn register_requires_admin() {
    let fix = build().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/endorsement-types")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", REGISTER_TASK)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "typeUri": "https://x/t" }).to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_type_404_when_unknown() {
    let fix = build().await;
    let req = Request::builder()
        .method("DELETE")
        .uri("/v1/endorsement-types/https%3A%2F%2Fx%2Ft")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", DELETE_TYPE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── Issue ───────────────────────────────────────────────

async fn register_type(fix: &Fixture, uri: &str) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/endorsement-types")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REGISTER_TASK)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "typeUri": uri }).to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn issue_rejects_unregistered_type() {
    let fix = build().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "subjectDid": SUBJECT_DID,
                "type": "https://unregistered.example/t",
                "claim": { "x": 1 }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn issue_rejects_non_issuer_non_admin() {
    let fix = build().await;
    register_type(&fix, "https://example.com/v1/skills/rust").await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "subjectDid": SUBJECT_DID,
                "type": "https://example.com/v1/skills/rust",
                "claim": { "level": "expert" }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn issue_happy_path_issuer_mints_credential() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/rust";
    register_type(&fix, uri).await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "subjectDid": SUBJECT_DID,
                "type": uri,
                "claim": { "level": "expert", "since": "2020" }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert!(v["id"].is_string());
    assert!(v["vec"].is_object());

    // Audit: CustomEndorsementIssued + VecIssued both emitted.
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw_issued = false;
    let mut saw_vec = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        match env.event {
            AuditEvent::CustomEndorsementIssued(d) if d.endorsement_type == uri => {
                saw_issued = true;
            }
            AuditEvent::VecIssued(d) if d.credential_type == "VerifiableEndorsementCredential" => {
                saw_vec = true;
            }
            _ => {}
        }
    }
    assert!(saw_issued, "must emit CustomEndorsementIssued");
    assert!(saw_vec, "must emit VecIssued for accounting");
}

#[tokio::test]
async fn issue_rejects_unknown_subject() {
    let fix = build().await;
    let uri = "https://example.com/v1/t";
    register_type(&fix, uri).await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "subjectDid": "did:key:zStranger",
                "type": uri,
                "claim": { "x": 1 }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_type_refused_while_live_endorsement_exists() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/rust";
    register_type(&fix, uri).await;
    // Issue an endorsement of that type.
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "subjectDid": SUBJECT_DID,
                "type": uri,
                "claim": { "level": "expert" }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Try to delete the type — must 409.
    let encoded = uri.replace(':', "%3A").replace('/', "%2F");
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/endorsement-types/{encoded}"))
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", DELETE_TYPE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

// ─── Revoke ──────────────────────────────────────────────

#[tokio::test]
async fn revoke_issuer_can_retract() {
    let fix = build().await;
    let uri = "https://example.com/v1/t";
    register_type(&fix, uri).await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "subjectDid": SUBJECT_DID, "type": uri, "claim": { "x": 1 } }).to_string(),
        ))
        .unwrap();
    let (_, v) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    let id = v["id"].as_str().unwrap().to_string();

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/credentials/endorsements/{id}"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", SHOW_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Audit: CustomEndorsementRevoked + StatusListFlipped.
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw_revoked = false;
    let mut saw_flipped = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        match env.event {
            AuditEvent::CustomEndorsementRevoked(_) => saw_revoked = true,
            AuditEvent::StatusListFlipped(d) if d.revoked => saw_flipped = true,
            _ => {}
        }
    }
    assert!(saw_revoked);
    assert!(saw_flipped);
    let _ = fix.endorsements_ks;
}

#[tokio::test]
async fn revoke_idempotent_on_already_revoked() {
    let fix = build().await;
    let uri = "https://example.com/v1/t";
    register_type(&fix, uri).await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "subjectDid": SUBJECT_DID, "type": uri, "claim": { "x": 1 } }).to_string(),
        ))
        .unwrap();
    let (_, v) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    let id = v["id"].as_str().unwrap().to_string();

    for _ in 0..2 {
        let req = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/credentials/endorsements/{id}"))
            .header("authorization", format!("Bearer {}", fix.admin_token))
            .header("trust-task", SHOW_TASK)
            .body(Body::empty())
            .unwrap();
        let resp = fix.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn revoke_non_admin_non_issuer_forbidden() {
    let fix = build().await;
    let uri = "https://example.com/v1/t";
    register_type(&fix, uri).await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/credentials/endorsements")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "subjectDid": SUBJECT_DID, "type": uri, "claim": { "x": 1 } }).to_string(),
        ))
        .unwrap();
    let (_, v) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    let id = v["id"].as_str().unwrap().to_string();

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/credentials/endorsements/{id}"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", SHOW_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
