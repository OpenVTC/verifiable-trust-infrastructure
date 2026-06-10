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
use tower::ServiceExt;
use vti_common::auth::session::{Session, SessionState, store_session};

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::credentials::LocalSigner;
use vtc_service::members::{Member, get_member, store_member};
use vtc_service::status_list;
use vtc_service::test_support::TestVtc;

const VTC_DID: &str = "did:webvh:vtc.example.com:abc";
const PUBLIC_URL: &str = "https://vtc.example.com";
const RENEW_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/renew/1.0";
const MEMBER_DID: &str = "did:key:zRenewMember";

struct Fixture {
    router: axum::Router,
    member_token: String,
    signer: Arc<LocalSigner>,
    members_ks: vti_common::store::KeyspaceHandle,
    status_lists_ks: vti_common::store::KeyspaceHandle,
    policies_ks: vti_common::store::KeyspaceHandle,
    active_policies_ks: vti_common::store::KeyspaceHandle,
    audit_ks: vti_common::store::KeyspaceHandle,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

async fn build_fixture() -> Fixture {
    // The fixture verifies re-issued VMC/VEC against this signer, so the
    // AppState must issue with this exact instance.
    let signer = Arc::new(LocalSigner::from_ed25519_seed(VTC_DID.into(), &[0xCC; 32]));
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_public_url(PUBLIC_URL)
        .with_credential_signer(signer.clone())
        .build()
        .await;

    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .expect("install default policies");

    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        let url = format!("{PUBLIC_URL}/v1/status-lists/{purpose}");
        status_list::ensure_initial(&vtc.state.status_lists_ks, purpose, url)
            .await
            .unwrap();
    }

    // Seed a Member ACL row + Member metadata row.
    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &vtc.state.acl_ks,
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
    store_member(&vtc.state.members_ks, &Member::fresh(MEMBER_DID))
        .await
        .unwrap();

    let session_id = "test-member-session";
    store_session(
        &vtc.state.sessions_ks,
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

    let member_claims = vtc.jwt_keys.new_claims(
        MEMBER_DID.into(),
        session_id.into(),
        "reader".into(),
        vec![],
        3600,
        true,
    );
    let member_token = vtc.jwt_keys.encode(&member_claims).unwrap();

    let members_ks = vtc.state.members_ks.clone();
    let status_lists_ks = vtc.state.status_lists_ks.clone();
    let policies_ks = vtc.state.policies_ks.clone();
    let active_policies_ks = vtc.state.active_policies_ks.clone();
    let audit_ks = vtc.state.audit_ks.clone();
    let router = vtc.router.clone();

    Fixture {
        router,
        member_token,
        signer,
        members_ks,
        status_lists_ks,
        policies_ks,
        active_policies_ks,
        audit_ks,
        _vtc: vtc,
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
