//! Integration coverage for `POST /v1/invitations` — the operator-side VIC
//! issuance route (the admin UI calls this to mint an invitation).
//!
//! Covers: admin happy path (a signed, revocable VIC bound to the invitee),
//! the non-privileged caller 403, and the already-a-member 409.

use std::sync::Arc;

use affinidi_status_list::StatusPurpose;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::members::{Member, store_member};
use vtc_service::status_list;
use vtc_service::test_support::TestVtc;

const PUBLIC_URL: &str = "https://vtc.example.com";
const ISSUE_TASK: &str = "https://trusttasks.org/openvtc/vtc/invitations/issue/1.0";
const ADMIN_DID: &str = "did:key:zInvAdmin";
const MEMBER_DID: &str = "did:key:zInvMember";
const INVITEE_DID: &str = "did:key:zInvitee";

struct Fixture {
    router: axum::Router,
    admin_token: String,
    member_token: String,
    _vtc: TestVtc,
}

async fn build() -> Fixture {
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_signers(true)
        .with_public_url(PUBLIC_URL)
        .build()
        .await;

    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .unwrap();
    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        let url = format!("{PUBLIC_URL}/v1/status-lists/{purpose}");
        status_list::ensure_initial(&vtc.state.status_lists_ks, purpose, url)
            .await
            .unwrap();
    }

    let now = now_epoch();
    for (did, role) in [(ADMIN_DID, VtcRole::Admin), (MEMBER_DID, VtcRole::Member)] {
        store_acl_entry(
            &vtc.state.acl_ks,
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
        store_member(&vtc.state.members_ks, &Member::fresh(did))
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

    let admin_token = mint(
        &vtc.state.sessions_ks,
        &vtc.jwt_keys,
        ADMIN_DID,
        "admin",
        now,
    )
    .await;
    let member_token = mint(
        &vtc.state.sessions_ks,
        &vtc.jwt_keys,
        MEMBER_DID,
        "reader",
        now,
    )
    .await;

    let router = vtc.router.clone();
    Fixture {
        router,
        admin_token,
        member_token,
        _vtc: vtc,
    }
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

fn issue_req(token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/invitations")
        .header("authorization", format!("Bearer {token}"))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn admin_issues_a_revocable_vic_bound_to_the_invitee() {
    let fix = build().await;
    let req = issue_req(&fix.admin_token, json!({ "subjectDid": INVITEE_DID }));
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");

    assert_eq!(v["subjectDid"], INVITEE_DID);
    let vic = &v["vic"];
    assert_eq!(vic["credentialSubject"]["id"], INVITEE_DID);
    let types: Vec<String> = serde_json::from_value(vic["type"].clone()).unwrap();
    assert!(
        types.iter().any(|t| t == "InvitationCredential"),
        "issued credential is an InvitationCredential: {types:?}"
    );
    assert!(
        vic.get("credentialStatus").is_some(),
        "the VIC must be revocable"
    );
    assert!(vic.get("proof").is_some(), "the VIC must be signed");
}

#[tokio::test]
async fn non_privileged_member_cannot_issue() {
    let fix = build().await;
    let req = issue_req(&fix.member_token, json!({ "subjectDid": INVITEE_DID }));
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _) = body_value(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn inviting_an_existing_member_is_a_conflict() {
    let fix = build().await;
    // MEMBER_DID already has a member row.
    let req = issue_req(&fix.admin_token, json!({ "subjectDid": MEMBER_DID }));
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _) = body_value(resp).await;
    assert_eq!(status, StatusCode::CONFLICT);
}
