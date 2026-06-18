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
const LIST_TASK: &str = "https://trusttasks.org/openvtc/vtc/invitations/issue/1.0";
const REVOKE_TASK: &str = "https://trusttasks.org/openvtc/vtc/invitations/revoke/1.0";
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

#[tokio::test]
async fn issuing_an_invitation_emits_audit() {
    use vti_common::audit::{AuditEnvelope, AuditEvent};

    let fix = build().await;
    let req = issue_req(
        &fix.admin_token,
        json!({ "subjectDid": INVITEE_DID, "role": "moderator" }),
    );
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _) = body_value(resp).await;
    assert_eq!(status, StatusCode::CREATED);

    let raw = fix
        ._vtc
        .state
        .audit_ks
        .prefix_iter_raw(b"2".to_vec())
        .await
        .unwrap();
    let envelopes: Vec<AuditEnvelope> = raw
        .iter()
        .map(|(_, v)| serde_json::from_slice(v).unwrap())
        .collect();
    let issued: Vec<&AuditEnvelope> = envelopes
        .iter()
        .filter(|e| matches!(e.event, AuditEvent::InvitationIssued(_)))
        .collect();
    assert_eq!(issued.len(), 1, "exactly one InvitationIssued envelope");
    assert_eq!(issued[0].target_did_plain.as_deref(), Some(INVITEE_DID));
    let AuditEvent::InvitationIssued(data) = &issued[0].event else {
        unreachable!()
    };
    assert_eq!(data.subject_did, INVITEE_DID);
    assert_eq!(data.role.as_deref(), Some("moderator"));
}

#[tokio::test]
async fn inviting_a_departed_tombstoned_did_is_allowed() {
    let fix = build().await;
    // A departed member: a tombstone Member row (removed_at set) with NO ACL —
    // the ACL was deleted on a Tombstone/Historical departure. Re-inviting them
    // must succeed (re-join overwrites the tombstone), not 409.
    let departed = "did:key:z6MkDeparted000000000000000000000000000000000";
    let mut gone = Member::fresh(departed);
    gone.tombstone();
    store_member(&fix._vtc.state.members_ks, &gone)
        .await
        .unwrap();

    let req = issue_req(&fix.admin_token, json!({ "subjectDid": departed }));
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a departed (tombstoned) DID can be re-invited: {v}"
    );
}

#[tokio::test]
async fn invite_can_grant_a_role_via_scopes() {
    let fix = build().await;
    let req = issue_req(
        &fix.admin_token,
        json!({ "subjectDid": INVITEE_DID, "role": "moderator" }),
    );
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let scopes = v["vic"]["credentialSubject"]["scopes"]
        .as_array()
        .expect("VIC carries credentialSubject.scopes");
    assert!(
        scopes.iter().any(|s| s == "role:moderator"),
        "role rides in scopes: {scopes:?}"
    );
}

#[tokio::test]
async fn issue_list_revoke_round_trip() {
    let fix = build().await;

    // Issue → the registry lists it as live.
    let req = issue_req(&fix.admin_token, json!({ "subjectDid": INVITEE_DID }));
    let (status, v) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let vic_id = v["vic"]["id"].as_str().expect("vic id").to_string();

    let list_req = Request::builder()
        .method("GET")
        .uri("/v1/invitations")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", LIST_TASK)
        .body(Body::empty())
        .unwrap();
    let (status, v) = body_value(fix.router.clone().oneshot(list_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let row = v["invitations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == json!(vic_id))
        .expect("issued invitation is listed");
    assert!(
        row.get("revokedAt").is_none(),
        "live invite has no revokedAt"
    );

    // Revoke → 200, newlyRevoked.
    let del = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/invitations/{vic_id}"))
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let (status, v) = body_value(fix.router.clone().oneshot(del).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["newlyRevoked"], json!(true));

    // Revoking again is idempotent (newlyRevoked = false).
    let del2 = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/invitations/{vic_id}"))
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let (status, v) = body_value(fix.router.clone().oneshot(del2).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["newlyRevoked"], json!(false));
}

#[tokio::test]
async fn revoke_unknown_invitation_is_404() {
    let fix = build().await;
    let del = Request::builder()
        .method("DELETE")
        .uri("/v1/invitations/urn:uuid:does-not-exist")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let (status, _) = body_value(fix.router.clone().oneshot(del).await.unwrap()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invite_refuses_admin_role() {
    let fix = build().await;
    let req = issue_req(
        &fix.admin_token,
        json!({ "subjectDid": INVITEE_DID, "role": "admin" }),
    );
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _) = body_value(resp).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an invite may not grant admin"
    );
}
