//! Integration coverage for `/v1/relationships*` (Phase 4
//! M4.6).
//!
//! The publish happy path needs a live DID resolver to verify
//! the VRC's data-integrity proof — same constraint as M3.10
//! recognise + M4.3 personhood assert. Integration tests here
//! cover:
//! - publish: caller != issuer → 403
//! - publish: missing resolver → 500
//! - revoke: issuer revokes own row (with hand-seeded state)
//! - revoke: subject (non-issuer) → 403
//! - revoke: admin revokes any row
//! - revoke: 404 on unknown id
//! - list: pagination + §12.3 strip on Purge-removed party

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

use vtc_service::acl::{VtcAclEntry, VtcRole, delete_acl_entry, store_acl_entry};
use vtc_service::config::AppConfig;
use vtc_service::credentials::LocalSigner;
use vtc_service::install::InstallTokenStore;
use vtc_service::members::{Member, delete_member, store_member};
use vtc_service::registry::RegistryHealth;
use vtc_service::relationships::{Relationship, store_relationship};
use vtc_service::routes;
use vtc_service::server::AppState;
use vtc_service::status_list;

const VTC_DID: &str = "did:webvh:vtc.example.com:abc";
const PUBLIC_URL: &str = "https://vtc.example.com";
const PUBLISH_TASK: &str = "https://trusttasks.org/openvtc/vtc/relationships/publish/1.0";
const LIST_TASK: &str = "https://trusttasks.org/openvtc/vtc/relationships/list/1.0";
const REVOKE_TASK: &str = "https://trusttasks.org/openvtc/vtc/relationships/revoke/1.0";
const ISSUER_DID: &str = "did:key:zVrcIssuer";
const SUBJECT_DID: &str = "did:key:zVrcSubject";
const STRANGER_DID: &str = "did:key:zStranger";
const ADMIN_DID: &str = "did:key:zVrcAdmin";

fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

struct Fixture {
    router: axum::Router,
    issuer_token: String,
    subject_token: String,
    admin_token: String,
    relationships_ks: vti_common::store::KeyspaceHandle,
    relationships_by_did_ks: vti_common::store::KeyspaceHandle,
    acl_ks: vti_common::store::KeyspaceHandle,
    members_ks: vti_common::store::KeyspaceHandle,
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

    // Seed ACL + Member rows for issuer, subject, admin.
    let now = now_epoch();
    for (did, role) in [
        (ISSUER_DID, VtcRole::Member),
        (SUBJECT_DID, VtcRole::Member),
        (ADMIN_DID, VtcRole::Admin),
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

    let issuer_token = mint(&sessions_ks, &jwt_keys, ISSUER_DID, "reader", now).await;
    let subject_token = mint(&sessions_ks, &jwt_keys, SUBJECT_DID, "reader", now).await;
    let admin_token = mint(&sessions_ks, &jwt_keys, ADMIN_DID, "admin", now).await;

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
    .expect("parse config");

    let state = AppState {
        sessions_ks,
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
        relationships_ks: relationships_ks.clone(),
        relationships_by_did_ks: relationships_by_did_ks.clone(),
        endorsement_types_ks: endorsement_types_ks.clone(),
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
        issuer_token,
        subject_token,
        admin_token,
        relationships_ks,
        relationships_by_did_ks,
        acl_ks,
        members_ks,
        audit_ks,
        _dir: dir,
    }
}

fn fake_vrc(issuer: &str, subject: &str) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "VerifiableRecognitionCredential"],
        "issuer": issuer,
        "credentialSubject": {
            "id": subject,
            "endorsement": { "type": "endorses" }
        },
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": format!("{issuer}#key-0"),
            "proofValue": "z00"
        }
    })
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

// ─── Publish ─────────────────────────────────────────────

#[tokio::test]
async fn publish_rejects_caller_not_issuer() {
    let fix = build_fixture().await;
    // Subject member tries to publish a VRC issued by someone else.
    let vrc = fake_vrc(ISSUER_DID, SUBJECT_DID);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/relationships")
        .header("authorization", format!("Bearer {}", fix.subject_token))
        .header("trust-task", PUBLISH_TASK)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "vrc": vrc }).to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn publish_returns_500_when_resolver_unconfigured() {
    let fix = build_fixture().await;
    let vrc = fake_vrc(ISSUER_DID, SUBJECT_DID);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/relationships")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", PUBLISH_TASK)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "vrc": vrc }).to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    // Caller passes the issuer == VC.issuer gate; resolver
    // path is next + the fixture has did_resolver: None.
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn publish_rejects_malformed_vrc() {
    let fix = build_fixture().await;
    // No `issuer` field → 400 (Validation).
    let vrc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "credentialSubject": { "id": SUBJECT_DID }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/relationships")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", PUBLISH_TASK)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "vrc": vrc }).to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Revoke ──────────────────────────────────────────────

async fn seed_relationship(fix: &Fixture, issuer: &str, subject: &str) -> Uuid {
    let id = Uuid::new_v4();
    let rel = Relationship {
        id,
        issuer_did: issuer.into(),
        subject_did: subject.into(),
        vrc_jsonld: fake_vrc(issuer, subject),
        vrc_sha256: format!("seed-{id}"),
        created_at: chrono::Utc::now(),
    };
    store_relationship(&fix.relationships_ks, &fix.relationships_by_did_ks, &rel)
        .await
        .unwrap();
    id
}

#[tokio::test]
async fn revoke_issuer_can_retract_own() {
    let fix = build_fixture().await;
    let id = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/relationships/{id}"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Row gone.
    let got = vtc_service::relationships::get_relationship(&fix.relationships_ks, id)
        .await
        .unwrap();
    assert!(got.is_none());

    // Audit envelope carries revoked_by: "issuer".
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        if let AuditEvent::VrcRevoked(d) = env.event
            && d.revoked_by == "issuer"
        {
            saw = true;
        }
    }
    assert!(saw, "issuer revoke must emit revoked_by=issuer");
}

#[tokio::test]
async fn revoke_subject_is_forbidden() {
    let fix = build_fixture().await;
    let id = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/relationships/{id}"))
        .header("authorization", format!("Bearer {}", fix.subject_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn revoke_admin_can_revoke_any() {
    let fix = build_fixture().await;
    let id = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/relationships/{id}"))
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Audit reason = "admin".
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw_admin = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        if let AuditEvent::VrcRevoked(d) = env.event
            && d.revoked_by == "admin"
        {
            saw_admin = true;
        }
    }
    assert!(saw_admin);
}

#[tokio::test]
async fn revoke_404_on_unknown() {
    let fix = build_fixture().await;
    let id = Uuid::new_v4();
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/relationships/{id}"))
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── List ────────────────────────────────────────────────

#[tokio::test]
async fn list_returns_issued_and_received_edges() {
    let fix = build_fixture().await;
    let r1 = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;
    let r2 = seed_relationship(&fix, SUBJECT_DID, ISSUER_DID).await; // reverse
    // Stranger row that shouldn't appear for the issuer's list.
    store_acl_entry(
        &fix.acl_ks,
        &VtcAclEntry {
            did: STRANGER_DID.into(),
            role: VtcRole::Member,
            label: None,
            allowed_contexts: vec![],
            created_at: now_epoch(),
            created_by: "did:key:vtc-install".into(),
            expires_at: None,
        },
    )
    .await
    .unwrap();
    store_member(&fix.members_ks, &Member::fresh(STRANGER_DID))
        .await
        .unwrap();
    let _r3 = seed_relationship(&fix, STRANGER_DID, SUBJECT_DID).await;

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/members/{ISSUER_DID}/relationships"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", LIST_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let items = v["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2, "issuer's list = own issued + received");
    let ids: Vec<_> = items
        .iter()
        .map(|x| x["id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains(&r1.to_string()));
    assert!(ids.contains(&r2.to_string()));
}

#[tokio::test]
async fn list_strips_rows_where_other_party_purged() {
    let fix = build_fixture().await;
    let _r = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;

    // Purge SUBJECT: delete ACL row + Member row.
    delete_acl_entry(&fix.acl_ks, SUBJECT_DID).await.unwrap();
    delete_member(&fix.members_ks, SUBJECT_DID).await.unwrap();

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/members/{ISSUER_DID}/relationships"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", LIST_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    let items = v["items"].as_array().unwrap();
    assert!(
        items.is_empty(),
        "Purge-removed subject must strip the edge: {v}"
    );
}

#[tokio::test]
async fn list_keeps_rows_for_tombstoned_other_party() {
    let fix = build_fixture().await;
    let _r = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;

    // Tombstone SUBJECT: stamp removed_at on the Member row.
    let mut m = vtc_service::members::get_member(&fix.members_ks, SUBJECT_DID)
        .await
        .unwrap()
        .unwrap();
    m.tombstone();
    store_member(&fix.members_ks, &m).await.unwrap();

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/members/{ISSUER_DID}/relationships"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", LIST_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    let items = v["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        1,
        "Tombstoned subject keeps the edge visible: {v}"
    );
}
