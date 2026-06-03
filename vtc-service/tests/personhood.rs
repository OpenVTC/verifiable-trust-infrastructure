//! Integration coverage for `/v1/members/{did}/personhood/*`
//! (Phase 4 M4.3 + M4.4).
//!
//! Covers:
//! - challenge mint happy path + non-member 404
//! - assert without challenge → 422
//! - assert without configured DID resolver → 500
//!   (daemon-misconfigured class)
//! - revoke admin path — flag flips + VMC re-mints + audit
//! - revoke self path — same outcome, `reason: "self"`
//! - revoke unauthorized (member-A → member-B) → 403
//! - revoke idempotent on already-false → 200 no-op without
//!   audit
//!
//! The assert happy path requires a live DID resolver to
//! verify the VP's `#key-0` proof; like the M3.10 recognise
//! integration tests, the route-level happy path is exercised
//! end-to-end via mocked credentials in the unit-test layer
//! (see `recognition::verify::tests`) — the integration
//! coverage here pins the failure-mode + audit surfaces.

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
use vti_common::audit::{AuditEnvelope, AuditEvent, AuditKeyStore, AuditWriter};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};
use vti_common::config::StoreConfig;
use vti_common::store::Store;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::config::AppConfig;
use vtc_service::credentials::LocalSigner;
use vtc_service::install::InstallTokenStore;
use vtc_service::members::{Member, get_member, store_member};
use vtc_service::registry::RegistryHealth;
use vtc_service::routes;
use vtc_service::server::AppState;
use vtc_service::status_list;

const VTC_DID: &str = "did:webvh:vtc.example.com:abc";
const PUBLIC_URL: &str = "https://vtc.example.com";
const CHALLENGE_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/personhood/challenge/1.0";
const ASSERT_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/personhood/assert/1.0";
const MEMBER_DID: &str = "did:key:zPerson1";
const OTHER_MEMBER_DID: &str = "did:key:zPerson2";
const ADMIN_DID: &str = "did:key:zPersonAdmin";

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
    other_member_token: String,
    admin_token: String,
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

    // Seed ACL + Member rows for member, other-member, admin.
    let now = now_epoch();
    for (did, role) in [
        (MEMBER_DID, VtcRole::Member),
        (OTHER_MEMBER_DID, VtcRole::Member),
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

    let make_token = |did: &str, role: &str| -> String {
        let session_id = format!("sess-{}", uuid::Uuid::new_v4());
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
        let sessions = sessions_ks.clone();
        let claims = jwt_keys.new_claims(did.into(), session_id, role.into(), vec![], 3600, true);
        let token = jwt_keys.encode(&claims).unwrap();
        // store_session is async; wrap synchronously by leaking
        // a tokio handle.
        tokio::runtime::Handle::current().block_on(async move {
            store_session(&sessions, &session).await.unwrap();
        });
        token
    };
    // Hack: build_fixture is async, but the closure can't be —
    // call store_session inline instead.
    let member_token = {
        let session_id = "sess-member";
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
        let claims = jwt_keys.new_claims(
            MEMBER_DID.into(),
            session_id.into(),
            "reader".into(),
            vec![],
            3600,
            true,
        );
        jwt_keys.encode(&claims).unwrap()
    };
    let other_member_token = {
        let session_id = "sess-other";
        store_session(
            &sessions_ks,
            &Session {
                session_id: session_id.into(),
                did: OTHER_MEMBER_DID.into(),
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
        let claims = jwt_keys.new_claims(
            OTHER_MEMBER_DID.into(),
            session_id.into(),
            "reader".into(),
            vec![],
            3600,
            true,
        );
        jwt_keys.encode(&claims).unwrap()
    };
    let admin_token = {
        let session_id = "sess-admin";
        store_session(
            &sessions_ks,
            &Session {
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
            },
        )
        .await
        .unwrap();
        let claims = jwt_keys.new_claims(
            ADMIN_DID.into(),
            session_id.into(),
            "admin".into(),
            vec![],
            3600,
            true,
        );
        jwt_keys.encode(&claims).unwrap()
    };
    let _ = make_token; // silence unused

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
        acl_ks,
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
        member_token,
        other_member_token,
        admin_token,
        members_ks,
        audit_ks,
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

// ─── Challenge endpoint ────────────────────────────────────

#[tokio::test]
async fn challenge_happy_path_returns_uuid_and_expiry() {
    let fix = build_fixture().await;
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/members/{MEMBER_DID}/personhood/challenge"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", CHALLENGE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["challengeId"].is_string());
    assert!(v["expiresAt"].is_string());
}

#[tokio::test]
async fn challenge_returns_404_for_non_member() {
    let fix = build_fixture().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/did:key:zStranger/personhood/challenge")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", CHALLENGE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── Assert endpoint (failure-mode coverage) ───────────────

#[tokio::test]
async fn assert_without_did_resolver_returns_500() {
    let fix = build_fixture().await;
    // First mint a challenge so the early-exit on missing
    // challenge doesn't fire.
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/members/{MEMBER_DID}/personhood/challenge"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", CHALLENGE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (_, v) = body_value(resp).await;
    let challenge_id = v["challengeId"].as_str().unwrap().to_string();

    let body = json!({
        "presentation": {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": MEMBER_DID,
            "verifiableCredential": [],
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": format!("{MEMBER_DID}#key-0"),
                "challenge": challenge_id,
                "proofValue": "z00".to_string(),
            }
        }
    });

    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/members/{MEMBER_DID}/personhood"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ASSERT_TASK)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    // Fixture has did_resolver: None → 500.
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn assert_with_unknown_challenge_returns_400() {
    let fix = build_fixture().await;
    let body = json!({
        "presentation": {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": MEMBER_DID,
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": format!("{MEMBER_DID}#key-0"),
                "challenge": uuid::Uuid::new_v4().to_string(),
                "proofValue": "z00",
            }
        }
    });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/members/{MEMBER_DID}/personhood"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ASSERT_TASK)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    // AppError::Validation → 400 in this workspace.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Revoke endpoint ───────────────────────────────────────

#[tokio::test]
async fn revoke_admin_flips_member_row_and_emits_audit() {
    let fix = build_fixture().await;
    // Mark member as previously asserted.
    let mut m = get_member(&fix.members_ks, MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    m.personhood = true;
    m.personhood_asserted_at = Some(chrono::Utc::now());
    m.status_list_index = Some(7); // pre-allocated for re-mint
    store_member(&fix.members_ks, &m).await.unwrap();

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/members/{MEMBER_DID}/personhood"))
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", ASSERT_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["personhood"], false);
    assert!(v["vmc"].is_object());

    // Member row flipped + timestamp cleared.
    let m2 = get_member(&fix.members_ks, MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    assert!(!m2.personhood);
    assert!(m2.personhood_asserted_at.is_none());

    // Audit envelope carries reason: "admin".
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        if let AuditEvent::PersonhoodRevoked(d) = env.event
            && d.reason == "admin"
        {
            saw = true;
            break;
        }
    }
    assert!(saw, "admin revoke must emit PersonhoodRevoked reason=admin");
}

#[tokio::test]
async fn revoke_self_emits_audit_reason_self() {
    let fix = build_fixture().await;
    let mut m = get_member(&fix.members_ks, MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    m.personhood = true;
    m.personhood_asserted_at = Some(chrono::Utc::now());
    m.status_list_index = Some(8);
    store_member(&fix.members_ks, &m).await.unwrap();

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/members/{MEMBER_DID}/personhood"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ASSERT_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw_self = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        if let AuditEvent::PersonhoodRevoked(d) = env.event
            && d.reason == "self"
        {
            saw_self = true;
            break;
        }
    }
    assert!(saw_self, "self-revoke must emit reason=self");
}

#[tokio::test]
async fn revoke_unauthorized_when_member_revokes_someone_else() {
    let fix = build_fixture().await;
    // Mark other_member as asserted; member tries to revoke
    // on their behalf — must 403.
    let mut m = get_member(&fix.members_ks, OTHER_MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    m.personhood = true;
    m.personhood_asserted_at = Some(chrono::Utc::now());
    m.status_list_index = Some(9);
    store_member(&fix.members_ks, &m).await.unwrap();

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/members/{OTHER_MEMBER_DID}/personhood"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ASSERT_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn revoke_already_false_is_idempotent_noop() {
    let fix = build_fixture().await;
    // Member.personhood already false (default). Revoke
    // returns 200 + no VMC re-mint + no audit envelope.
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/members/{MEMBER_DID}/personhood"))
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", ASSERT_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["personhood"], false);
    assert!(
        v.get("vmc").is_none_or(|x| x.is_null()),
        "no-op must omit vmc: {v}"
    );

    // No PersonhoodRevoked envelope.
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        if let AuditEvent::PersonhoodRevoked(_) = env.event {
            saw = true;
            break;
        }
    }
    assert!(!saw, "idempotent no-op must not emit PersonhoodRevoked");
}

#[tokio::test]
async fn revoke_returns_404_for_unknown_member() {
    let fix = build_fixture().await;
    let req = Request::builder()
        .method("DELETE")
        .uri("/v1/members/did:key:zStranger/personhood")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", ASSERT_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // Silence unused warning on other_member_token in this
    // test (used in revoke_unauthorized_*).
    let _ = &fix.other_member_token;
}
