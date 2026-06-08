//! Integration coverage for `/v1/join-requests/*` (M1.7–M1.10).
//!
//! Exercises the REST surface end-to-end through `Router::oneshot`.
//! DIDComm twin is covered separately by unit-testing the
//! handler's `submit_inner` invocation pattern; an end-to-end
//! DIDComm round-trip needs the mediator harness and lives in
//! `vti-e2e-tests`.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::audit::{AuditKeyStore, AuditWriter};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::passkey::build_webauthn;
use vti_common::auth::session::{Session, SessionState, store_session};
use vti_common::config::StoreConfig;
use vti_common::store::{KeyspaceHandle, Store};

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::config::AppConfig;
use vtc_service::install::InstallTokenStore;
use vtc_service::members::get_member;
use vtc_service::routes;
use vtc_service::server::AppState;

/// Mirror of the constant in `vtc_service::routes::join_requests::submit`
/// — the route module is `pub(crate)` so we can't import it from a
/// test. Keeping a single-line copy here is cheaper than widening
/// the module's visibility for one test.
const JOIN_REQUEST_SUBMIT_DOMAIN_TAG: &[u8] = b"vtc-join-request/v1\0";
/// Mirror of `routes::join_requests::accept::JOIN_ACCEPT_DOMAIN_TAG`.
const JOIN_ACCEPT_DOMAIN_TAG: &[u8] = b"vtc-join-accept/v1\0";

const RP_ORIGIN: &str = "https://vtc.example.com";
const SUBMIT_TASK: &str = "https://trusttasks.org/openvtc/vtc/join-requests/submit/1.0";
const SHOW_TASK: &str = "https://trusttasks.org/openvtc/vtc/join-requests/show/1.0";
const APPROVE_TASK: &str = "https://trusttasks.org/openvtc/vtc/join-requests/approve/1.0";
const REJECT_TASK: &str = "https://trusttasks.org/openvtc/vtc/join-requests/reject/1.0";
const ACCEPT_TASK: &str = "https://trusttasks.org/openvtc/vtc/join-requests/accept/1.0";
/// The VTC DID the fixture configures — the issuer of every VMC and the
/// community a reciprocal VC must acknowledge.
const VTC_DID: &str = "did:webvh:vtc.example.com:abc";
/// Member seed shared by `applicant_pair` (so a `LocalSigner` over the
/// same seed signs reciprocal VCs that verify against the member did:key).
const MEMBER_SEED: [u8; 32] = [0xCD; 32];
const POLICY_UPLOAD_TASK: &str = "https://trusttasks.org/openvtc/vtc/policies/upload/1.0";
const POLICY_ACTIVATE_TASK: &str = "https://trusttasks.org/openvtc/vtc/policies/activate/1.0";

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
    state: AppState,
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
    let install_store = InstallTokenStore::new(install_ks.clone());

    // Install workspace-shipped default policies the same way
    // `server::run` does at boot (M2.5). The submit handler
    // (M2.6) evaluates `join.rego` against every submission,
    // so an empty active-policy set would fail closed.
    vtc_service::policy::default::install_defaults(&policies_ks, &active_policies_ks)
        .await
        .expect("install default policies");

    // M2.10 + M2.12: seed both status lists so the approve
    // handler can allocate a slot when issuing the VMC.
    for purpose in [
        affinidi_status_list::StatusPurpose::Revocation,
        affinidi_status_list::StatusPurpose::Suspension,
    ] {
        let url = format!("{RP_ORIGIN}/v1/status-lists/{purpose}");
        vtc_service::status_list::ensure_initial(&status_lists_ks, purpose, url)
            .await
            .expect("ensure_initial status list");
    }

    // M2.12 credential signer — deterministic seed for stable
    // test fixtures.
    let credential_signer = Some(Arc::new(
        vtc_service::credentials::LocalSigner::from_ed25519_seed(
            "did:webvh:vtc.example.com:abc".into(),
            &[0xCC; 32],
        ),
    ));

    let webauthn = Some(Arc::new(build_webauthn(RP_ORIGIN).expect("build webauthn")));

    let key_store = AuditKeyStore::new(audit_key_ks.clone());
    key_store.ensure_initial(&[0xAB; 32]).await.unwrap();
    let audit_writer = Some(AuditWriter::new(audit_ks.clone(), key_store));

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").unwrap());

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

    let session_id = "test-admin-session";
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

    let admin_claims = jwt_keys.new_claims(
        ADMIN_DID.into(),
        session_id.into(),
        "admin".into(),
        vec![],
        3600,
        true,
    );
    let admin_token = jwt_keys.encode(&admin_claims).unwrap();

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

    let router = routes::router().with_state(state.clone());

    Fixture {
        router,
        state,
        admin_token,
        acl_ks,
        members_ks,
        join_requests_ks,
        _dir: dir,
    }
}

/// Build a canonical-signing-payload signature for the holder-
/// binding check. Mirrors the verifier's payload construction.
fn sign_holder_payload(
    sk: &SigningKey,
    applicant_did: &str,
    vp: &Value,
    registry_consent: bool,
    extensions: &Value,
) -> String {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Payload<'a> {
        applicant_did: &'a str,
        vp: &'a Value,
        registry_consent: bool,
        extensions: &'a Value,
    }
    let payload = serde_json::to_vec(&Payload {
        applicant_did,
        vp,
        registry_consent,
        extensions,
    })
    .unwrap();
    let mut signing = Vec::with_capacity(JOIN_REQUEST_SUBMIT_DOMAIN_TAG.len() + payload.len());
    signing.extend_from_slice(JOIN_REQUEST_SUBMIT_DOMAIN_TAG);
    signing.extend_from_slice(&payload);
    hex::encode(sk.sign(&signing).to_bytes())
}

fn applicant_pair() -> (SigningKey, String) {
    let sk = SigningKey::from_bytes(&[0xCD; 32]);
    let pub_bytes = sk.verifying_key().to_bytes();
    let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);
    (sk, did)
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
// M1.8.1 — REST submit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rest_submit_happy_path_persists_pending() {
    let fix = build_fixture().await;
    let (sk, applicant_did) = applicant_pair();
    let vp = json!({ "type": "VerifiablePresentation", "holder": applicant_did });
    let signature = sign_holder_payload(&sk, &applicant_did, &vp, false, &Value::Null);

    let (status, body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests",
        SUBMIT_TASK,
        None,
        Some(json!({
            "applicantDid": applicant_did,
            "vp": vp,
            "signature": signature,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "got {body}");
    assert_eq!(body["status"], "pending");
    assert!(body["requestId"].is_string());
}

#[tokio::test]
async fn rest_submit_rejects_wrong_signer() {
    let fix = build_fixture().await;
    let (_a_sk, applicant_did) = applicant_pair();
    let other = SigningKey::from_bytes(&[0xEE; 32]);
    let vp = json!({});
    let bad_sig = sign_holder_payload(&other, &applicant_did, &vp, false, &Value::Null);

    let (status, body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests",
        SUBMIT_TASK,
        None,
        Some(json!({
            "applicantDid": applicant_did,
            "vp": vp,
            "signature": bad_sig,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "got {body}");
}

#[tokio::test]
async fn rest_submit_rejects_non_did_key_applicant() {
    let fix = build_fixture().await;
    let (status, _) = send(
        &fix.router,
        "POST",
        "/v1/join-requests",
        SUBMIT_TASK,
        None,
        Some(json!({
            "applicantDid": "did:web:not-supported.example.com",
            "vp": {},
            "signature": "00",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// M1.9.1 — list + show
// ---------------------------------------------------------------------------

async fn submit_pending(fix: &Fixture) -> Uuid {
    let (sk, applicant_did) = applicant_pair();
    let vp = json!({"a":"b"});
    let sig = sign_holder_payload(&sk, &applicant_did, &vp, false, &Value::Null);
    let (_, body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests",
        SUBMIT_TASK,
        None,
        Some(json!({
            "applicantDid": applicant_did,
            "vp": vp,
            "signature": sig,
        })),
    )
    .await;
    Uuid::parse_str(body["requestId"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn list_returns_pending_by_default() {
    let fix = build_fixture().await;
    let id = submit_pending(&fix).await;
    let (status, body) = send(
        &fix.router,
        "GET",
        "/v1/join-requests",
        SUBMIT_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], id.to_string());
    assert_eq!(items[0]["status"], "pending");
}

#[tokio::test]
async fn show_returns_full_request_including_vp() {
    let fix = build_fixture().await;
    let id = submit_pending(&fix).await;
    let (status, body) = send(
        &fix.router,
        "GET",
        &format!("/v1/join-requests/{id}"),
        SHOW_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["status"], "pending");
    assert!(body["vp"].is_object());
}

// ---------------------------------------------------------------------------
// M1.10.1 — approve + reject
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approve_writes_acl_and_member_atomically() {
    let fix = build_fixture().await;
    let (sk, applicant_did) = applicant_pair();
    let vp = json!({});
    let sig = sign_holder_payload(&sk, &applicant_did, &vp, false, &Value::Null);
    let (_, body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests",
        SUBMIT_TASK,
        None,
        Some(json!({
            "applicantDid": applicant_did,
            "vp": vp,
            "signature": sig,
        })),
    )
    .await;
    let id = body["requestId"].as_str().unwrap();

    let (status, body) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/approve"),
        APPROVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["status"], "approved");

    let acl = get_acl_entry(&fix.acl_ks, &applicant_did)
        .await
        .unwrap()
        .expect("ACL row written");
    assert_eq!(acl.role, VtcRole::Member);

    let member = get_member(&fix.members_ks, &applicant_did)
        .await
        .unwrap()
        .expect("Member row written");
    assert_eq!(member.did, applicant_did);

    // M2.12: approve now mints a VMC + role VEC and stamps the
    // pointers on the Member row.
    assert!(
        member.status_list_index.is_some(),
        "approve must allocate a status-list slot"
    );
    let vmc_id = member.current_vmc_id.as_deref().expect("VMC id stamped");
    let vec_id = member
        .current_role_vec_id
        .as_deref()
        .expect("VEC id stamped");
    assert!(vmc_id.starts_with("urn:uuid:"), "got {vmc_id}");
    assert!(vec_id.starts_with("urn:uuid:"), "got {vec_id}");

    // Response carries the signed VCs inline.
    let vmc = &body["vmc"];
    let role_vec = &body["roleVec"];
    assert_eq!(vmc["id"], vmc_id);
    assert_eq!(vec_id, role_vec["id"].as_str().unwrap());

    // VMC carries the credentialStatus block pointing at the
    // allocated slot.
    let slot = member.status_list_index.unwrap();
    let cs = &vmc["credentialStatus"];
    assert_eq!(cs["statusPurpose"], "revocation");
    assert_eq!(cs["statusListIndex"], slot.to_string());

    // Both VCs verify against the fixture's signer.
    let signer = vtc_service::credentials::LocalSigner::from_ed25519_seed(
        "did:webvh:vtc.example.com:abc".into(),
        &[0xCC; 32],
    );
    let vmc_vc: affinidi_vc::VerifiableCredential =
        serde_json::from_value(vmc.clone()).expect("VMC parses");
    signer.verify(&vmc_vc).expect("VMC proof must verify");
    let vec_vc: affinidi_vc::VerifiableCredential =
        serde_json::from_value(role_vec.clone()).expect("VEC parses");
    signer.verify(&vec_vc).expect("VEC proof must verify");
}

#[tokio::test]
async fn approve_409_when_duplicate_acl_exists() {
    let fix = build_fixture().await;
    let (sk, applicant_did) = applicant_pair();
    let vp = json!({});
    let sig = sign_holder_payload(&sk, &applicant_did, &vp, false, &Value::Null);
    let (_, body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests",
        SUBMIT_TASK,
        None,
        Some(json!({
            "applicantDid": applicant_did,
            "vp": vp,
            "signature": sig,
        })),
    )
    .await;
    let id = body["requestId"].as_str().unwrap();

    // Pre-existing ACL row collides with the approve write.
    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &fix.acl_ks,
        &VtcAclEntry {
            did: applicant_did.clone(),
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

    let (status, _) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/approve"),
        APPROVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn reject_leaves_no_acl_or_member_rows() {
    let fix = build_fixture().await;
    let (sk, applicant_did) = applicant_pair();
    let vp = json!({});
    let sig = sign_holder_payload(&sk, &applicant_did, &vp, false, &Value::Null);
    let (_, body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests",
        SUBMIT_TASK,
        None,
        Some(json!({
            "applicantDid": applicant_did,
            "vp": vp,
            "signature": sig,
        })),
    )
    .await;
    let id = body["requestId"].as_str().unwrap();

    let (status, body) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/reject"),
        REJECT_TASK,
        Some(&fix.admin_token),
        Some(json!({ "reason": "policy says no" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["status"], "rejected");

    assert!(
        get_acl_entry(&fix.acl_ks, &applicant_did)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        get_member(&fix.members_ks, &applicant_did)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn approve_404_for_unknown_id() {
    let fix = build_fixture().await;
    let id = Uuid::new_v4();
    let (status, _) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/approve"),
        APPROVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn approve_409_when_request_already_decided() {
    let fix = build_fixture().await;
    let (sk, applicant_did) = applicant_pair();
    let vp = json!({});
    let sig = sign_holder_payload(&sk, &applicant_did, &vp, false, &Value::Null);
    let (_, body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests",
        SUBMIT_TASK,
        None,
        Some(json!({
            "applicantDid": applicant_did,
            "vp": vp,
            "signature": sig,
        })),
    )
    .await;
    let id = body["requestId"].as_str().unwrap();

    // First approve — succeeds.
    let _ = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/approve"),
        APPROVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    // Second approve — 409.
    let (status, _) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/approve"),
        APPROVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn reject_rejects_overlong_reason() {
    let fix = build_fixture().await;
    let id = submit_pending(&fix).await;

    let huge = "x".repeat(1025);
    let (status, _) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/reject"),
        REJECT_TASK,
        Some(&fix.admin_token),
        Some(json!({ "reason": huge })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Auth gating sanity check
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// M2.6 — Policy step at submit time
// ---------------------------------------------------------------------------

/// Upload + activate a join policy. The active pointer is flipped
/// server-side; subsequent submits see the new policy's semantics.
async fn activate_join_policy(fix: &Fixture, source: &str) {
    let (status, body) = send(
        &fix.router,
        "POST",
        "/v1/policies",
        POLICY_UPLOAD_TASK,
        Some(&fix.admin_token),
        Some(json!({ "purpose": "join", "regoSource": source })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "upload failed: {body}");
    let id = body["id"].as_str().unwrap();
    let (status, body) = send(
        &fix.router,
        "POST",
        &format!("/v1/policies/{id}/activate"),
        POLICY_ACTIVATE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "activate failed: {body}");
}

async fn activate_deny_all_join_policy(fix: &Fixture) {
    activate_join_policy(
        fix,
        "package vtc.join\nimport rego.v1\n\n\
         default decision := {\"effect\": \"deny\", \"with\": {\"code\": \"closed\"}}\n",
    )
    .await;
}

/// An `allow` join policy auto-admits: the submit handler runs the
/// Admit effect, the row lands `approved`, the membership credentials
/// come back inline, and the applicant is now a member.
#[tokio::test]
async fn rest_submit_under_allow_policy_auto_admits() {
    let fix = build_fixture().await;
    activate_join_policy(
        &fix,
        "package vtc.join\nimport rego.v1\n\n\
         default decision := {\"effect\": \"allow\", \"with\": {\"role\": \"member\"}}\n",
    )
    .await;

    let (sk, applicant_did) = applicant_pair();
    let vp = json!({ "type": "VerifiablePresentation", "holder": applicant_did });
    let signature = sign_holder_payload(&sk, &applicant_did, &vp, false, &Value::Null);

    let (status, body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests",
        SUBMIT_TASK,
        None,
        Some(json!({
            "applicantDid": applicant_did,
            "vp": vp,
            "signature": signature,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "got {body}");
    assert_eq!(body["status"], "approved");
    assert!(body["vmc"]["id"].is_string(), "VMC returned inline: {body}");
    assert!(
        body["roleVec"]["id"].is_string(),
        "role VEC returned: {body}"
    );

    // The applicant is now a member (ACL + Member rows exist).
    let acl = vtc_service::acl::get_acl_entry(&fix.acl_ks, &applicant_did)
        .await
        .unwrap()
        .expect("auto-admitted applicant has an ACL row");
    assert_eq!(acl.role, VtcRole::Member);
    assert!(
        vtc_service::members::get_member(&fix.members_ks, &applicant_did)
            .await
            .unwrap()
            .is_some(),
        "auto-admitted applicant has a Member row"
    );
}

/// With the default `policies.open` join policy the submit
/// handler routes through the policy step and lands the row as
/// Pending. The `vpClaims` projection is populated from the VP
/// on the request row.
#[tokio::test]
async fn rest_submit_under_default_join_policy_lands_pending_with_vp_claims() {
    let fix = build_fixture().await;
    let (sk, applicant_did) = applicant_pair();
    let vp = json!({
        "type": "VerifiablePresentation",
        "holder": applicant_did,
        "verifiableCredential": [
            {
                "issuer": "did:key:zIssuerA",
                "type": ["VerifiableCredential", "EmailCredential"],
                "credentialSubject": { "email": "applicant@example.com" }
            }
        ]
    });
    let signature = sign_holder_payload(&sk, &applicant_did, &vp, false, &Value::Null);

    let (status, body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests",
        SUBMIT_TASK,
        None,
        Some(json!({
            "applicantDid": applicant_did,
            "vp": vp,
            "signature": signature,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "got {body}");
    assert_eq!(body["status"], "pending");
    let id = body["requestId"].as_str().unwrap();

    // Fetch via admin show — `vpClaims` is on the persisted row.
    let (status, row) = send(
        &fix.router,
        "GET",
        &format!("/v1/join-requests/{id}"),
        SHOW_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(row["status"], "pending");
    assert!(
        row["policyDecision"].is_null(),
        "allow path must not populate policy_decision: {row}"
    );
    assert_eq!(row["vpClaims"]["holder"], applicant_did);
    let creds = row["vpClaims"]["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0]["issuer"], "did:key:zIssuerA");
    assert_eq!(
        creds[0]["credentialSubject"]["email"],
        "applicant@example.com"
    );
}

/// After activating a deny-all join policy, a fresh submission
/// lands as Rejected and `policy_decision` carries the regorus
/// QueryResults shape so admins can see why.
#[tokio::test]
async fn rest_submit_under_deny_all_policy_persists_rejected_with_decision() {
    let fix = build_fixture().await;
    activate_deny_all_join_policy(&fix).await;

    let (sk, applicant_did) = applicant_pair();
    let vp = json!({ "type": "VerifiablePresentation", "holder": applicant_did });
    let signature = sign_holder_payload(&sk, &applicant_did, &vp, false, &Value::Null);

    let (status, body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests",
        SUBMIT_TASK,
        None,
        Some(json!({
            "applicantDid": applicant_did,
            "vp": vp,
            "signature": signature,
        })),
    )
    .await;
    // Submission still 201 — the row persists either way; the
    // status field is the decision channel.
    assert_eq!(status, StatusCode::CREATED, "got {body}");
    assert_eq!(body["status"], "rejected");
    let id = body["requestId"].as_str().unwrap();

    let (status, row) = send(
        &fix.router,
        "GET",
        &format!("/v1/join-requests/{id}"),
        SHOW_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(row["status"], "rejected");
    // `policyDecision` now carries the four-valued verdict the policy
    // returned — a deny with the policy's code.
    assert_eq!(
        row["policyDecision"],
        json!({ "effect": "deny", "with": { "code": "closed" } }),
    );
}

/// Trying to re-approve a policy-rejected row fails the same way
/// admin-rejected ones do (409 already decided). Confirms the
/// policy-deny path uses the same JoinStatus::Rejected sink.
#[tokio::test]
async fn policy_rejected_row_cannot_be_approved() {
    let fix = build_fixture().await;
    activate_deny_all_join_policy(&fix).await;

    let (sk, applicant_did) = applicant_pair();
    let vp = json!({ "type": "VerifiablePresentation", "holder": applicant_did });
    let signature = sign_holder_payload(&sk, &applicant_did, &vp, false, &Value::Null);
    let (status, body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests",
        SUBMIT_TASK,
        None,
        Some(json!({
            "applicantDid": applicant_did,
            "vp": vp,
            "signature": signature,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "got {body}");
    let id = body["requestId"].as_str().unwrap();

    let (status, _body) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/approve"),
        APPROVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

// ---------------------------------------------------------------------------
// Auth gating sanity check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_requires_authentication() {
    let fix = build_fixture().await;
    let (status, _) = send(
        &fix.router,
        "GET",
        "/v1/join-requests",
        SUBMIT_TASK,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Credential-exchange present → join decision (close-the-join-loop, part 2)
// ---------------------------------------------------------------------------

/// Build a real SD-JWT-VC `MembershipCredential` presentation bound to
/// `aud` + `nonce`, framed as an OID4VP DCQL `vp_token` map (keyed by
/// credential-query id) — exactly the shape `vta-service`'s `present_query`
/// emits. Returns `(holder_did, vp_token)`.
fn build_membership_vp_token(
    holder_seed: u8,
    aud: &str,
    nonce: &str,
    now_ts: i64,
) -> (String, Value) {
    use affinidi_sd_jwt::error::SdJwtError;
    use affinidi_sd_jwt::hasher::Sha256Hasher;
    use affinidi_sd_jwt::holder::{KbJwtInput, present, select_disclosures};
    use affinidi_sd_jwt::signer::JwtSigner;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    struct SdSigner {
        key: SigningKey,
        kid: String,
    }
    impl JwtSigner for SdSigner {
        fn algorithm(&self) -> &str {
            "EdDSA"
        }
        fn key_id(&self) -> Option<&str> {
            Some(&self.kid)
        }
        fn sign_jwt(&self, header: &Value, payload: &Value) -> Result<String, SdJwtError> {
            let h = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(header).map_err(|e| SdJwtError::Verification(e.to_string()))?,
            );
            let p = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(payload).map_err(|e| SdJwtError::Verification(e.to_string()))?,
            );
            let input = format!("{h}.{p}");
            let sig = self.key.sign(input.as_bytes());
            Ok(format!(
                "{input}.{}",
                URL_SAFE_NO_PAD.encode(sig.to_bytes())
            ))
        }
    }

    let issuer = SigningKey::from_bytes(&[9u8; 32]);
    let issuer_did =
        affinidi_crypto::did_key::ed25519_pub_to_did_key(issuer.verifying_key().as_bytes());
    let issuer_signer = SdSigner {
        key: SigningKey::from_bytes(&[9u8; 32]),
        kid: format!("{issuer_did}#key-0"),
    };

    let holder = SigningKey::from_bytes(&[holder_seed; 32]);
    let holder_vk = holder.verifying_key();
    let holder_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(holder_vk.as_bytes());
    let holder_signer = SdSigner {
        key: SigningKey::from_bytes(&[holder_seed; 32]),
        kid: format!(
            "{holder_did}#{}",
            holder_did.strip_prefix("did:key:").unwrap()
        ),
    };

    let vct = "https://openvtc.org/credentials/MembershipCredential";
    let claims = json!({
        "iss": issuer_did, "sub": holder_did, "vct": vct,
        "iat": now_ts, "exp": now_ts + 3600, "givenName": "Alice"
    });
    let frame = json!({ "_sd": ["givenName"] });
    let hasher = Sha256Hasher;
    let holder_jwk = json!({
        "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(holder_vk.to_bytes())
    });
    let sd =
        affinidi_sd_jwt::issuer::issue(&claims, &frame, &issuer_signer, &hasher, Some(&holder_jwk))
            .unwrap();
    let selected = select_disclosures(&sd, &["givenName"]);
    let kb = KbJwtInput {
        audience: aud,
        nonce,
        signer: &holder_signer,
        iat: now_ts as u64,
    };
    let presentation = present(&sd, &selected, Some(&kb), &hasher).unwrap();
    (
        holder_did,
        json!({ "membership": presentation.serialize() }),
    )
}

const VTC_AUD: &str = "did:webvh:vtc.example.com:abc";

/// A cryptographically-verified credential-exchange presentation drives the join
/// decision: under an `allow` policy the holder is auto-admitted and the
/// MembershipCredential is issued inline.
#[tokio::test]
async fn credential_exchange_present_auto_admits_under_allow_policy() {
    use vtc_service::join::{JoinStatus, JoinTransport};
    use vtc_service::routes::join_requests::present::present_and_decide_join;

    let fix = build_fixture().await;
    activate_join_policy(
        &fix,
        "package vtc.join\nimport rego.v1\n\n\
         default decision := {\"effect\": \"allow\", \"with\": {\"role\": \"member\"}}\n",
    )
    .await;

    let now = chrono::Utc::now();
    let nonce = "vtc-issued-nonce-1";
    let (holder_did, vp_token) = build_membership_vp_token(0x42, VTC_AUD, nonce, now.timestamp());

    let outcome = present_and_decide_join(
        &fix.state,
        &vp_token,
        VTC_AUD,
        nonce,
        JoinTransport::DIDComm,
        now,
    )
    .await
    .expect("present and decide");

    assert_eq!(outcome.request.status, JoinStatus::Approved);
    assert!(
        outcome.admit.is_some(),
        "MembershipCredential issued on allow"
    );
    // The proven holder is now a member.
    let acl = vtc_service::acl::get_acl_entry(&fix.acl_ks, &holder_did)
        .await
        .unwrap()
        .expect("auto-admitted holder has an ACL row");
    assert_eq!(acl.role, VtcRole::Member);
    assert!(
        vtc_service::members::get_member(&fix.members_ks, &holder_did)
            .await
            .unwrap()
            .is_some(),
        "auto-admitted holder has a Member row"
    );
}

/// Under the default join policy a verified presentation lands `pending` (the
/// decision pipeline routed it; no auto-admit).
#[tokio::test]
async fn credential_exchange_present_defers_under_default_policy() {
    use vtc_service::join::{JoinStatus, JoinTransport};
    use vtc_service::routes::join_requests::present::present_and_decide_join;

    let fix = build_fixture().await;
    let now = chrono::Utc::now();
    let nonce = "n";
    let (_holder, vp_token) = build_membership_vp_token(0x43, VTC_AUD, nonce, now.timestamp());

    let outcome = present_and_decide_join(
        &fix.state,
        &vp_token,
        VTC_AUD,
        nonce,
        JoinTransport::DIDComm,
        now,
    )
    .await
    .expect("present and decide");

    assert_eq!(outcome.request.status, JoinStatus::Pending);
    assert!(outcome.admit.is_none());
}

/// A presentation bound to a different nonce than the verifier expects is
/// refused — no decision runs (replay / wrong-challenge protection at the
/// crypto layer).
#[tokio::test]
async fn credential_exchange_present_rejects_a_wrong_nonce() {
    use vtc_service::join::JoinTransport;
    use vtc_service::routes::join_requests::present::present_and_decide_join;

    let fix = build_fixture().await;
    let now = chrono::Utc::now();
    let (_holder, vp_token) =
        build_membership_vp_token(0x44, VTC_AUD, "right-nonce", now.timestamp());

    let refused = matches!(
        present_and_decide_join(
            &fix.state,
            &vp_token,
            VTC_AUD,
            "wrong-nonce",
            JoinTransport::DIDComm,
            now,
        )
        .await,
        Err(vti_common::error::AppError::Validation(_))
    );
    assert!(
        refused,
        "a presentation bound to a different nonce must be refused"
    );
}

/// The wire freshness model end to end: the VTC issues a single-use challenge
/// (nonce keyed by the query's thread), the holder presents bound to it, the
/// `present` handler consumes the challenge and decides — and a replay on the
/// same thread is refused (single-use). Exercises the same path the
/// `credential-exchange/present` DIDComm handler drives.
#[tokio::test]
async fn credential_exchange_present_over_a_single_use_challenge_closes_the_loop() {
    use vtc_service::credentials::present_challenge::{DEFAULT_CHALLENGE_TTL, consume, issue};
    use vtc_service::join::{JoinStatus, JoinTransport};
    use vtc_service::routes::join_requests::present::present_and_decide_join;

    let fix = build_fixture().await;
    activate_join_policy(
        &fix,
        "package vtc.join\nimport rego.v1\n\n\
         default decision := {\"effect\": \"allow\", \"with\": {\"role\": \"member\"}}\n",
    )
    .await;

    let now = chrono::Utc::now();
    let thread = "query-thread-1";

    // VTC issues the single-use challenge it sent with its DCQL query.
    let nonce = issue(
        &fix.state.join_requests_ks,
        thread,
        VTC_AUD,
        DEFAULT_CHALLENGE_TTL,
        now,
    )
    .await
    .expect("issue challenge");

    // Holder presents bound to (aud, nonce).
    let (holder_did, vp_token) = build_membership_vp_token(0x45, VTC_AUD, &nonce, now.timestamp());

    // Handler: consume the challenge (freshness/replay), then decide.
    let challenge = consume(&fix.state.join_requests_ks, thread, now)
        .await
        .expect("consume challenge");
    assert_eq!(challenge.nonce, nonce);
    assert_eq!(challenge.aud, VTC_AUD);

    let outcome = present_and_decide_join(
        &fix.state,
        &vp_token,
        &challenge.aud,
        &challenge.nonce,
        JoinTransport::DIDComm,
        now,
    )
    .await
    .expect("present and decide");
    assert_eq!(outcome.request.status, JoinStatus::Approved);
    assert!(outcome.admit.is_some(), "VMC issued on allow");
    assert!(
        vtc_service::acl::get_acl_entry(&fix.acl_ks, &holder_did)
            .await
            .unwrap()
            .is_some(),
        "admitted holder has an ACL row"
    );

    // Replay: the challenge for this thread is gone — single-use.
    assert!(
        consume(&fix.state.join_requests_ks, thread, now)
            .await
            .is_err(),
        "a replayed presentation finds no challenge"
    );
}

/// The query-send side: an admin asks the VTC to prepare a credential-exchange
/// query from a registered Accepts criterion. The VTC issues a single-use
/// challenge (bound to its own DID) and returns the DCQL `QueryBody` to deliver;
/// the challenge is then consumable on the returned thread.
#[tokio::test]
async fn admin_query_send_prepares_a_dcql_query_and_issues_a_challenge() {
    use vtc_service::credentials::present_challenge::consume;
    use vtc_service::schemas::accepts::{AcceptsCriterion, store_accepts};

    let fix = build_fixture().await;

    // A `type_values` DCQL query references no `vct_values` types, so it stores
    // without registering schemas first.
    let criterion = AcceptsCriterion {
        id: "join-evidence".into(),
        query: json!({
            "credentials": [{
                "id": "membership",
                "format": "ldp_vc",
                "meta": { "type_values": ["MembershipCredential"] }
            }]
        }),
        description: Some("present a MembershipCredential to join".into()),
        created_at: chrono::Utc::now(),
        created_by_did: ADMIN_DID.into(),
    };
    store_accepts(&fix.state.schemas_ks, &criterion)
        .await
        .expect("store accepts criterion");

    let (status, body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests/query",
        "x",
        Some(&fix.admin_token),
        Some(json!({ "holderDid": "did:key:zHolder", "criterionId": "join-evidence" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    let thread_id = body["threadId"].as_str().expect("threadId").to_string();
    assert_eq!(body["holderDid"], "did:key:zHolder");
    assert!(
        body["query"]["dcql_query"]["credentials"].is_array(),
        "DCQL query present: {body}"
    );
    let nonce = body["query"]["nonce"].as_str().expect("nonce").to_string();
    assert_eq!(
        body["query"]["purpose"],
        "present a MembershipCredential to join"
    );
    // No mediator is configured in the fixture, so the DIDComm push is skipped —
    // the query is returned for relay delivery.
    assert_eq!(body["delivered"], false, "no mediator → not pushed: {body}");

    // The single-use challenge is consumable on that thread, bound to the VTC DID.
    let challenge = consume(&fix.state.join_requests_ks, &thread_id, chrono::Utc::now())
        .await
        .expect("consume challenge");
    assert_eq!(challenge.aud, VTC_AUD);
    assert_eq!(challenge.nonce, nonce);
}

/// An unregistered criterion id is a 404 (no challenge issued).
#[tokio::test]
async fn admin_query_send_404s_an_unknown_criterion() {
    let fix = build_fixture().await;
    let (status, _body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests/query",
        "x",
        Some(&fix.admin_token),
        Some(json!({ "holderDid": "did:key:zHolder", "criterionId": "does-not-exist" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The query-send route is admin-gated.
#[tokio::test]
async fn admin_query_send_requires_admin() {
    let fix = build_fixture().await;
    let (status, _body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests/query",
        "x",
        None,
        Some(json!({ "holderDid": "did:key:zHolder", "criterionId": "join-evidence" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Accept — reciprocal VMC (join-requests/accept/1.0)
// ---------------------------------------------------------------------------

/// Submit then admin-approve an applicant, returning
/// `(member sk, member_did, request_id, vmc_id)`.
async fn admit_member(fix: &Fixture) -> (SigningKey, String, Uuid, String) {
    let (sk, member_did) = applicant_pair();
    let vp = json!({});
    let sig = sign_holder_payload(&sk, &member_did, &vp, false, &Value::Null);
    let (_, body) = send(
        &fix.router,
        "POST",
        "/v1/join-requests",
        SUBMIT_TASK,
        None,
        Some(json!({ "applicantDid": member_did, "vp": vp, "signature": sig })),
    )
    .await;
    let id = Uuid::parse_str(body["requestId"].as_str().unwrap()).unwrap();

    let (status, body) = send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/approve"),
        APPROVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approve failed: {body}");
    let vmc_id = body["vmc"]["id"].as_str().unwrap().to_string();
    (sk, member_did, id, vmc_id)
}

/// Build + sign a member-issued reciprocal VC (the counter-signature).
async fn build_reciprocal_vc(
    member_did: &str,
    vmc_id: &str,
    community_did: &str,
    id: &str,
) -> Value {
    let signer = vtc_service::credentials::LocalSigner::from_ed25519_seed(
        member_did.to_string(),
        &MEMBER_SEED,
    );
    let mut vc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "MembershipAcknowledgement"],
        "id": id,
        "issuer": member_did,
        "credentialSubject": { "id": community_did, "reciprocates": vmc_id },
    });
    signer.sign_doc(&mut vc).await.expect("sign reciprocal vc");
    vc
}

/// Holder-binding signature over the canonical accept body. Mirrors
/// `routes::join_requests::accept`'s construction.
fn sign_accept_payload(sk: &SigningKey, member_did: &str, vmc_id: &str, vc: &Value) -> String {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Payload<'a> {
        member_did: &'a str,
        vmc_id: &'a str,
        vc: &'a Value,
    }
    let payload = serde_json::to_vec(&Payload {
        member_did,
        vmc_id,
        vc,
    })
    .unwrap();
    let mut signing = Vec::with_capacity(JOIN_ACCEPT_DOMAIN_TAG.len() + payload.len());
    signing.extend_from_slice(JOIN_ACCEPT_DOMAIN_TAG);
    signing.extend_from_slice(&payload);
    hex::encode(sk.sign(&signing).to_bytes())
}

async fn post_accept(
    fix: &Fixture,
    id: Uuid,
    member_did: &str,
    vmc_id: &str,
    vc: &Value,
    signature: &str,
) -> (StatusCode, Value) {
    send(
        &fix.router,
        "POST",
        &format!("/v1/join-requests/{id}/accept"),
        ACCEPT_TASK,
        None,
        Some(json!({
            "memberDid": member_did,
            "vmcId": vmc_id,
            "vc": vc,
            "signature": signature,
        })),
    )
    .await
}

#[tokio::test]
async fn accept_records_the_reciprocal_edge() {
    let fix = build_fixture().await;
    let (sk, member_did, id, vmc_id) = admit_member(&fix).await;
    let recip_id = "urn:uuid:recip-1";
    let vc = build_reciprocal_vc(&member_did, &vmc_id, VTC_DID, recip_id).await;
    let sig = sign_accept_payload(&sk, &member_did, &vmc_id, &vc);

    let (status, body) = post_accept(&fix, id, &member_did, &vmc_id, &vc, &sig).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["status"], "accepted");
    assert_eq!(body["reciprocalVcId"], recip_id);

    let member = get_member(&fix.members_ks, &member_did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(member.reciprocal_vc_id.as_deref(), Some(recip_id));
    assert!(member.accepted_at.is_some(), "accepted_at stamped");
}

#[tokio::test]
async fn accept_is_idempotent_for_the_same_vc() {
    let fix = build_fixture().await;
    let (sk, member_did, id, vmc_id) = admit_member(&fix).await;
    let vc = build_reciprocal_vc(&member_did, &vmc_id, VTC_DID, "urn:uuid:recip-1").await;
    let sig = sign_accept_payload(&sk, &member_did, &vmc_id, &vc);

    let (s1, _) = post_accept(&fix, id, &member_did, &vmc_id, &vc, &sig).await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, b2) = post_accept(&fix, id, &member_did, &vmc_id, &vc, &sig).await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "re-accept of the same VC is a no-op: {b2}"
    );
    assert_eq!(b2["reciprocalVcId"], "urn:uuid:recip-1");
}

#[tokio::test]
async fn accept_conflicts_on_a_different_vc_after_reciprocation() {
    let fix = build_fixture().await;
    let (sk, member_did, id, vmc_id) = admit_member(&fix).await;
    let vc1 = build_reciprocal_vc(&member_did, &vmc_id, VTC_DID, "urn:uuid:recip-1").await;
    let sig1 = sign_accept_payload(&sk, &member_did, &vmc_id, &vc1);
    let (s1, _) = post_accept(&fix, id, &member_did, &vmc_id, &vc1, &sig1).await;
    assert_eq!(s1, StatusCode::OK);

    let vc2 = build_reciprocal_vc(&member_did, &vmc_id, VTC_DID, "urn:uuid:recip-2").await;
    let sig2 = sign_accept_payload(&sk, &member_did, &vmc_id, &vc2);
    let (s2, _) = post_accept(&fix, id, &member_did, &vmc_id, &vc2, &sig2).await;
    assert_eq!(s2, StatusCode::CONFLICT);
}

#[tokio::test]
async fn accept_rejects_a_wrong_holder_signature() {
    let fix = build_fixture().await;
    let (_sk, member_did, id, vmc_id) = admit_member(&fix).await;
    let vc = build_reciprocal_vc(&member_did, &vmc_id, VTC_DID, "urn:uuid:recip-1").await;
    let other = SigningKey::from_bytes(&[0xEE; 32]);
    let bad_sig = sign_accept_payload(&other, &member_did, &vmc_id, &vc);

    let (status, _) = post_accept(&fix, id, &member_did, &vmc_id, &vc, &bad_sig).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn accept_conflicts_when_not_yet_approved() {
    let fix = build_fixture().await;
    let id = submit_pending(&fix).await;
    let (sk, member_did) = applicant_pair();
    // No VMC exists yet; build a placeholder vc — the status guard fires first.
    let vc = build_reciprocal_vc(&member_did, "urn:uuid:none", VTC_DID, "urn:uuid:recip-1").await;
    let sig = sign_accept_payload(&sk, &member_did, "urn:uuid:none", &vc);

    let (status, _) = post_accept(&fix, id, &member_did, "urn:uuid:none", &vc, &sig).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn accept_conflicts_on_vmc_id_mismatch() {
    let fix = build_fixture().await;
    let (sk, member_did, id, _vmc_id) = admit_member(&fix).await;
    let wrong = "urn:uuid:not-the-current-vmc";
    let vc = build_reciprocal_vc(&member_did, wrong, VTC_DID, "urn:uuid:recip-1").await;
    let sig = sign_accept_payload(&sk, &member_did, wrong, &vc);

    let (status, _) = post_accept(&fix, id, &member_did, wrong, &vc, &sig).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn accept_rejects_a_reciprocal_vc_for_another_community() {
    let fix = build_fixture().await;
    let (sk, member_did, id, vmc_id) = admit_member(&fix).await;
    // Subject acknowledges a different community than this VTC.
    let vc = build_reciprocal_vc(
        &member_did,
        &vmc_id,
        "did:web:evil.example",
        "urn:uuid:recip-1",
    )
    .await;
    let sig = sign_accept_payload(&sk, &member_did, &vmc_id, &vc);

    let (status, _) = post_accept(&fix, id, &member_did, &vmc_id, &vc, &sig).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn accept_rejects_a_tampered_reciprocal_vc() {
    let fix = build_fixture().await;
    let (sk, member_did, id, vmc_id) = admit_member(&fix).await;
    let mut vc = build_reciprocal_vc(&member_did, &vmc_id, VTC_DID, "urn:uuid:recip-1").await;
    // Mutate the signed `id` after signing — the issuer proof no longer covers it.
    vc["id"] = json!("urn:uuid:swapped");
    let sig = sign_accept_payload(&sk, &member_did, &vmc_id, &vc);

    let (status, _) = post_accept(&fix, id, &member_did, &vmc_id, &vc, &sig).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
