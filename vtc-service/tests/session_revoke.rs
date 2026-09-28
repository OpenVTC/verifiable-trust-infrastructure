//! `auth/revoke-session/0.2` on `DELETE /v1/auth/sessions[/{id}|?did=]`.
//!
//! Ending another subject's sessions takes the authority to withdraw that
//! subject's access (the `acl/revoke` check), not the admin role alone: a
//! context admin cannot sign out an unrestricted admin, nor an admin whose
//! scope reaches past its own. A named session that is absent, already gone,
//! or outside the caller's authority is answered identically, with
//! `revokedCount: 0`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use vti_common::auth::session::{Session, SessionState, get_session, now_epoch, store_session};

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::TestVtc;

const TASK: &str = "https://trusttasks.org/spec/auth/revoke-session/0.2";
const SUPER: &str = "did:key:z6MkRevokeSuper";
const SCOPED: &str = "did:key:z6MkRevokeScopedA";
const IN_A: &str = "did:key:z6MkRevokeAdminA";
const IN_AB: &str = "did:key:z6MkRevokeAdminAB";

async fn seed_admin(vtc: &TestVtc, did: &str, contexts: &[&str]) {
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role: VtcRole::Admin,
            label: None,
            allowed_contexts: contexts.iter().map(|c| c.to_string()).collect(),
            created_at: now_epoch(),
            created_by: "test".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("store acl");
}

/// A live session for `did`, returning its id.
async fn seed_session(vtc: &TestVtc, did: &str) -> String {
    let session_id = format!("sess-{}", uuid::Uuid::new_v4());
    store_session(
        &vtc.state.sessions_ks,
        &Session {
            session_id: session_id.clone(),
            did: did.into(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: now_epoch(),
            last_seen: now_epoch(),
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: Vec::new(),
            acr: String::new(),
            acr_expires_at: None,
            token_id: None,
            session_pubkey_b58btc: None,
        },
    )
    .await
    .expect("store session");
    session_id
}

async fn fixture() -> TestVtc {
    let vtc = TestVtc::builder().build().await;
    seed_admin(&vtc, SUPER, &[]).await;
    seed_admin(&vtc, SCOPED, &["ctx-a"]).await;
    seed_admin(&vtc, IN_A, &["ctx-a"]).await;
    seed_admin(&vtc, IN_AB, &["ctx-a", "ctx-b"]).await;
    vtc
}

async fn delete(vtc: &TestVtc, token: &str, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("Trust-Task", TASK)
        .body(Body::empty())
        .unwrap();
    let res = vtc.router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn alive(vtc: &TestVtc, session_id: &str) -> bool {
    get_session(&vtc.state.sessions_ks, session_id)
        .await
        .unwrap()
        .is_some()
}

#[tokio::test]
async fn a_named_session_outside_the_callers_authority_is_answered_as_absent() {
    let vtc = fixture().await;
    let scoped = vtc.token(SCOPED, "admin", vec!["ctx-a".into()]).await;

    let super_session = seed_session(&vtc, SUPER).await;
    let wide_session = seed_session(&vtc, IN_AB).await;
    for id in [&super_session, &wide_session, &"sess-no-such".to_string()] {
        let (status, body) = delete(&vtc, &scoped, &format!("/v1/auth/sessions/{id}")).await;
        assert_eq!(status, StatusCode::OK, "{id}: {body}");
        assert_eq!(body, serde_json::json!({ "revokedCount": 0 }), "{id}");
    }
    assert!(
        alive(&vtc, &super_session).await,
        "a context admin signed out a super-admin"
    );
    assert!(
        alive(&vtc, &wide_session).await,
        "a context admin signed out a wider admin"
    );
}

#[tokio::test]
async fn a_named_session_is_ended_once_and_a_retry_succeeds() {
    let vtc = fixture().await;
    let scoped = vtc.token(SCOPED, "admin", vec!["ctx-a".into()]).await;
    let covered = seed_session(&vtc, IN_A).await;

    let uri = format!("/v1/auth/sessions/{covered}");
    let (status, body) = delete(&vtc, &scoped, &uri).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, serde_json::json!({ "revokedCount": 1 }))
    );
    assert!(!alive(&vtc, &covered).await);

    let (status, body) = delete(&vtc, &scoped, &uri).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, serde_json::json!({ "revokedCount": 0 }))
    );
}

#[tokio::test]
async fn revoking_by_subject_needs_authority_over_the_subjects_whole_scope() {
    let vtc = fixture().await;
    let scoped = vtc.token(SCOPED, "admin", vec!["ctx-a".into()]).await;
    let wide_session = seed_session(&vtc, IN_AB).await;
    let super_session = seed_session(&vtc, SUPER).await;

    for subject in [IN_AB, SUPER, "did:key:z6MkRevokeNobody"] {
        let (status, _) = delete(&vtc, &scoped, &format!("/v1/auth/sessions?did={subject}")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{subject}");
    }
    assert!(alive(&vtc, &wide_session).await);
    assert!(alive(&vtc, &super_session).await);

    seed_session(&vtc, IN_A).await;
    let (status, body) = delete(&vtc, &scoped, &format!("/v1/auth/sessions?did={IN_A}")).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, serde_json::json!({ "revokedCount": 1 }))
    );

    let superadmin = vtc.token(SUPER, "admin", vec![]).await;
    let (status, body) = delete(&vtc, &superadmin, &format!("/v1/auth/sessions?did={IN_AB}")).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, serde_json::json!({ "revokedCount": 1 }))
    );
}
