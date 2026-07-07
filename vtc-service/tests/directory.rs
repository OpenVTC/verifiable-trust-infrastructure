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
use tower::ServiceExt;
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::session::{Session, SessionState, store_session};
use vti_common::store::KeyspaceHandle;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::members::{Member, store_member};
use vtc_service::policy::default::install_defaults;
use vtc_service::test_support::TestVtc;

const RP_ORIGIN: &str = "https://vtc.example.com";
const DIRECTORY_TASK: &str = "https://trusttasks.org/openvtc/vtc/directory/query/1.0";
const ADMIN_DID: &str = "did:key:zAdmin1";

struct Fixture {
    router: axum::Router,
    jwt_keys: Arc<JwtKeys>,
    sessions_ks: KeyspaceHandle,
    acl_ks: KeyspaceHandle,
    members_ks: KeyspaceHandle,
    admin_token: String,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

async fn build_fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_public_url(RP_ORIGIN)
        .build()
        .await;

    // The directory route reads the active `directory` policy, so the
    // bundled defaults must be installed (server boot does this).
    install_defaults(&vtc.state.policies_ks, &vtc.state.active_policies_ks)
        .await
        .expect("install default policies");

    // Admin viewer: community-admin ACL row + an authenticated session.
    store_acl_entry(
        &vtc.state.acl_ks,
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

    let admin_token = mint_token(&vtc.jwt_keys, &vtc.state.sessions_ks, ADMIN_DID).await;

    let jwt_keys = vtc.jwt_keys.clone();
    let sessions_ks = vtc.state.sessions_ks.clone();
    let acl_ks = vtc.state.acl_ks.clone();
    let members_ks = vtc.state.members_ks.clone();
    let router = vtc.router.clone();

    Fixture {
        router,
        jwt_keys,
        sessions_ks,
        acl_ks,
        members_ks,
        admin_token,
        _vtc: vtc,
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
        last_seen: now,
        refresh_token: None,
        refresh_expires_at: None,
        tee_attested: false,
        amr: Vec::new(),
        acr: String::new(),
        acr_expires_at: None,
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
