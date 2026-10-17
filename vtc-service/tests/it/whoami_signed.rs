//! `auth/whoami/0.1` on the signed door (#1641): answered for the key a
//! sign-in bound to the session (`Session::session_pubkey_b58btc`), or for a
//! console key acting for its administrator — never for a cookie. The bearer
//! route `GET /v1/auth/whoami` is gone.

use axum::http::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;
use vti_common::auth::session::{Session, SessionState, delete_session, now_epoch, store_session};
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{AdminAuthority, AdminRole, VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::TestVtc;

use crate::common::signed::{
    assert_conforms, bearer_route_served, call, error_code, post, seed_role, unsigned,
};

const WHOAMI: &str = "https://trusttasks.org/spec/auth/whoami/0.1";

/// A console session for `did`, bound to `key` (if any), as a sign-in writes
/// one. Returns its id.
async fn seed_session(
    vtc: &TestVtc,
    did: &str,
    key: Option<&Party>,
    edit: impl FnOnce(&mut Session),
) -> String {
    let now = now_epoch();
    let session_id = Uuid::new_v4().to_string();
    let mut session = Session {
        session_id: session_id.clone(),
        did: did.to_string(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now,
        last_seen: now,
        refresh_token: None,
        refresh_expires_at: Some(now + 3600),
        tee_attested: false,
        amr: vec!["passkey".into()],
        acr: "aal2".into(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: key.map(|k| k.did["did:key:".len()..].to_string()),
        not_after: None,
    };
    edit(&mut session);
    store_session(&vtc.state.sessions_ks, &session)
        .await
        .unwrap();
    session_id
}

async fn admin(vtc: &TestVtc) -> String {
    let did = format!("did:key:z6MkWhoamiAdmin{}", Uuid::new_v4().simple());
    seed_role(vtc, &did, VtcRole::Admin, &[]).await;
    did
}

fn session_of(doc: &Value) -> &Value {
    &doc["payload"]["session"]
}

#[tokio::test]
async fn whoami_signed_by_the_key_bound_to_a_live_session_answers_for_it() {
    let vtc = TestVtc::builder().build().await;
    let did = admin(&vtc).await;
    let key = Party::new();
    let id = seed_session(&vtc, &did, Some(&key), |_| {}).await;

    let (status, doc) = call(&vtc, &key, WHOAMI, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_conforms(WHOAMI, &doc);
    assert_eq!(session_of(&doc)["id"], id.as_str());
    assert_eq!(session_of(&doc)["subject"], did.as_str());
    assert_eq!(session_of(&doc)["amr"], json!(["passkey"]));
    assert_eq!(doc["payload"]["roles"], json!(["admin"]));
}

/// VTI-OPS-020: the specification declares `proof` REQUIRED.
#[tokio::test]
async fn an_unsigned_whoami_is_refused() {
    let vtc = TestVtc::builder().build().await;
    let did = admin(&vtc).await;
    let key = Party::new();
    seed_session(&vtc, &did, Some(&key), |_| {}).await;

    let (status, doc) = post(&vtc, &unsigned(&key, WHOAMI, json!({}))).await;
    assert_ne!(status, StatusCode::OK, "{doc}");
    assert!(error_code(&doc).is_some(), "{doc}");
}

/// A key answers for the session it is bound to and no other — another
/// administrator's session, live beside it, is not reachable through it.
#[tokio::test]
async fn a_key_answers_only_for_the_session_it_is_bound_to() {
    let vtc = TestVtc::builder().build().await;
    let alice = admin(&vtc).await;
    let bob = admin(&vtc).await;
    let alice_key = Party::new();
    let bob_key = Party::new();
    seed_session(&vtc, &alice, Some(&alice_key), |_| {}).await;
    let bobs = seed_session(&vtc, &bob, Some(&bob_key), |_| {}).await;

    let (_, doc) = call(&vtc, &alice_key, WHOAMI, json!({})).await;
    assert_eq!(session_of(&doc)["subject"], alice.as_str());
    assert_ne!(session_of(&doc)["id"], bobs.as_str());
}

/// A key bound to no session — the cookie's session included — is refused:
/// the cookie confers nothing here.
#[tokio::test]
async fn a_key_bound_to_no_session_is_refused() {
    let vtc = TestVtc::builder().build().await;
    let did = admin(&vtc).await;
    seed_session(&vtc, &did, None, |_| {}).await;

    let stranger = Party::new();
    let (status, doc) = call(&vtc, &stranger, WHOAMI, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{doc}");
    assert_eq!(error_code(&doc), Some("permissionDenied"));
}

/// Signing out deletes the session, and its key speaks for nothing after.
#[tokio::test]
async fn whoami_fails_after_sign_out() {
    let vtc = TestVtc::builder().build().await;
    let did = admin(&vtc).await;
    let key = Party::new();
    let id = seed_session(&vtc, &did, Some(&key), |_| {}).await;
    assert_eq!(call(&vtc, &key, WHOAMI, json!({})).await.0, StatusCode::OK);

    delete_session(&vtc.state.sessions_ks, &id).await.unwrap();
    let (status, doc) = call(&vtc, &key, WHOAMI, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{doc}");
}

/// A session past its refresh expiry, its absolute end, or the idle timeout
/// is one `auth/refresh` would not renew, and its key answers nothing.
#[tokio::test]
async fn whoami_fails_once_the_session_has_ended() {
    let vtc = TestVtc::builder().build().await;
    let did = admin(&vtc).await;
    let now = now_epoch();
    let idle = vtc.state.config.read().await.auth.admin_idle_timeout;
    let cases: [(&str, Box<dyn FnOnce(&mut Session)>); 3] = [
        (
            "past its refresh expiry",
            Box::new(move |s: &mut Session| s.refresh_expires_at = Some(now - 1)),
        ),
        (
            "past its absolute end",
            Box::new(move |s: &mut Session| s.not_after = Some(now - 1)),
        ),
        (
            "idle past the timeout",
            Box::new(move |s: &mut Session| s.last_seen = now - idle - 5),
        ),
    ];
    for (why, edit) in cases {
        let key = Party::new();
        seed_session(&vtc, &did, Some(&key), edit).await;
        let (status, doc) = call(&vtc, &key, WHOAMI, json!({})).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{why}: {doc}");
    }
}

/// An administrator removed from the ACL since signing in gets no answer,
/// though the session row is still there.
#[tokio::test]
async fn whoami_fails_for_a_subject_no_longer_an_administrator() {
    let vtc = TestVtc::builder().build().await;
    let did = admin(&vtc).await;
    let key = Party::new();
    seed_session(&vtc, &did, Some(&key), |_| {}).await;
    vtc_service::acl::delete_acl_entry(&vtc.state.acl_ks, &did)
        .await
        .unwrap();
    let (status, doc) = call(&vtc, &key, WHOAMI, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{doc}");
}

/// A console key acts for the administrator that enrolled it, as for every
/// administrator verb — answering with that administrator's live session —
/// and stops the moment its delegation is revoked.
#[tokio::test]
async fn a_console_key_answers_for_its_administrators_session() {
    let vtc = TestVtc::builder().build().await;
    let did = admin(&vtc).await;
    let id = seed_session(&vtc, &did, Some(&Party::new()), |_| {}).await;
    let console = Party::new();
    vtc_service::acl::console_key::enrol_delegation(
        &vtc.state.console_keys_ks,
        &vtc.state.acl_ks,
        &console.did,
        &did,
        None,
        None,
    )
    .await
    .unwrap();

    let (status, doc) = call(&vtc, &console, WHOAMI, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(session_of(&doc)["id"], id.as_str());

    vtc_service::acl::console_key::revoke_delegation(
        &vtc.state.console_keys_ks,
        &console.did,
        &did,
    )
    .await
    .unwrap();
    assert_eq!(
        call(&vtc, &console, WHOAMI, json!({})).await.0,
        StatusCode::FORBIDDEN
    );
}

/// A console key whose administrator has no live session answers nothing —
/// a delegation is not a session.
#[tokio::test]
async fn a_console_key_with_no_live_session_is_refused() {
    let vtc = TestVtc::builder().build().await;
    let did = admin(&vtc).await;
    let console = Party::new();
    vtc_service::acl::console_key::enrol_delegation(
        &vtc.state.console_keys_ks,
        &vtc.state.acl_ks,
        &console.did,
        &did,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        call(&vtc, &console, WHOAMI, json!({})).await.0,
        StatusCode::FORBIDDEN
    );
}

/// `auth/whoami/0.1` answers what the caller's entry lets it do **now** —
/// `capabilities`, as enforced — so a console renders navigation per
/// capability rather than per session role (`vtc-admin-roles.md` §4). The
/// administrative role and what it may approve ride in `ext["org.openvtc"]`.
#[tokio::test]
async fn whoami_names_the_callers_live_capabilities() {
    let vtc = TestVtc::builder().build().await;
    let did = "did:key:z6MkAuditorWhoami";
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry::new(
            did,
            VtcRole::Member,
            AdminAuthority::for_role(AdminRole::Auditor),
            "did:key:vtc-install",
        ),
    )
    .await
    .unwrap();
    let key = Party::new();
    seed_session(&vtc, did, Some(&key), |_| {}).await;
    let (status, doc) = call(&vtc, &key, WHOAMI, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let v = &doc["payload"];
    assert_eq!(v["capabilities"], json!(["vtc.audit.read"]));
    assert_eq!(v["ext"]["org.openvtc"]["adminRole"], "auditor");
    assert_eq!(v["ext"]["org.openvtc"]["approves"], json!([]));
}

/// `GET /v1/auth/whoami` is gone (#1641).
#[tokio::test]
async fn the_bearer_whoami_route_is_gone() {
    let vtc = TestVtc::builder().build().await;
    assert!(!bearer_route_served(&vtc, "GET", "/v1/auth/whoami").await);
}
