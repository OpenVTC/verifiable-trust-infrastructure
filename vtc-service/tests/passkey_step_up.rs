//! End-to-end coverage for `purpose: stepUp` on `/v1/auth/passkey-login/*`.
//!
//! The canonical `auth/passkey/login/{start,finish}/0.2` task serves two
//! ceremonies. `login` mints a session; `stepUp` elevates one the caller
//! already holds, stamping the bounded window that
//! `vti_common::auth::extractor::StepUpAuth` reads.
//!
//! What these tests pin is the *difference* between the two — the checks that
//! stop a step-up from being satisfied by anything other than the session
//! holder, present, right now:
//!
//! - a step-up needs an authenticated session (login does not);
//! - the assertion must come from that session's own passkey;
//! - the ceremony is bound to the session that started it;
//! - it elevates in place — no new session, no new tokens;
//! - and the elevation carries a deadline, which is the whole point.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::acl::{AclEntry, Role, store_acl_entry};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::passkey::{
    build_webauthn,
    store::{PasskeyUser, store_credential_mapping, store_passkey_user},
};
use vti_common::auth::session::{Session, SessionState, get_session, now_epoch, store_session};
use webauthn_rs::Webauthn;
use webauthn_rs::prelude::RequestChallengeResponse;

use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

use common::webauthn_harness::SoftEd25519Authenticator;

/// Re-wrap the inner WebAuthn options as webauthn-rs's `{publicKey: …}`.
///
/// The `auth/passkey/*/start` tasks send the *inner* options — the value a
/// browser passes as `get({ publicKey: … })` — because that is what the
/// canonical `CredentialRequestOptions` component describes. The
/// soft-authenticator harness deserialises webauthn-rs's wrapper type, so the
/// test does the same re-wrap a real client does.
fn wrap_options<T: serde::de::DeserializeOwned>(inner: &serde_json::Value) -> T {
    serde_json::from_value(serde_json::json!({ "publicKey": inner })).expect("options re-wrap")
}

const RP_ORIGIN: &str = "https://vtc.example.com";
const START_TASK: &str = "https://trusttasks.org/spec/auth/passkey/login/start/0.2";
const FINISH_TASK: &str = "https://trusttasks.org/spec/auth/passkey/login/finish/0.2";
const UPDATE_TASK: &str = "https://trusttasks.org/spec/vtc/members/update/0.1";

struct Fixture {
    state: AppState,
    router: axum::Router,
    jwt_keys: Arc<JwtKeys>,
    admin_did: String,
    authenticator: SoftEd25519Authenticator,
    _vtc: TestVtc,
}

/// A VTC with one enrolled admin whose passkey the soft authenticator can
/// drive, plus a second enrolled admin used to prove that *someone else's*
/// passkey cannot satisfy a step-up.
async fn build_fixture() -> (Fixture, String) {
    let vtc = TestVtc::builder().with_public_url(RP_ORIGIN).build().await;
    let webauthn: Webauthn = build_webauthn(RP_ORIGIN).expect("webauthn builder");
    let mut authenticator = SoftEd25519Authenticator::new();

    let enrol = |authenticator: &mut SoftEd25519Authenticator| {
        let user_uuid = Uuid::new_v4();
        let (ccr, reg_state) = vtc_service::webauthn::start_passkey_registration(
            &webauthn,
            user_uuid,
            "did:key:zPlaceholder",
            "did:key:zPlaceholder",
            None,
        )
        .unwrap();
        let (register_cred, ed25519_pub) = authenticator.register(&ccr, RP_ORIGIN);
        let passkey = vtc_service::webauthn::finish_passkey_registration(
            &webauthn,
            &register_cred,
            &reg_state,
        )
        .unwrap();
        let did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&ed25519_pub)
        );
        let cred_id_hex = hex::encode(<_ as AsRef<[u8]>>::as_ref(passkey.cred_id()));
        (user_uuid, did, cred_id_hex, passkey)
    };

    let (uuid_a, did_a, cred_a, passkey_a) = enrol(&mut authenticator);
    let (uuid_b, did_b, cred_b, passkey_b) = enrol(&mut authenticator);

    for (uuid, did, cred, passkey) in [
        (uuid_a, did_a.clone(), cred_a, passkey_a),
        (uuid_b, did_b.clone(), cred_b, passkey_b),
    ] {
        store_passkey_user(
            &vtc.state.passkey_ks,
            &PasskeyUser {
                user_uuid: uuid,
                did: did.clone(),
                display_name: did.clone(),
                credentials: vec![passkey],
            },
        )
        .await
        .unwrap();
        store_credential_mapping(&vtc.state.passkey_ks, &cred, uuid)
            .await
            .unwrap();
        store_acl_entry(
            &vtc.state.acl_ks,
            &AclEntry::new(did, Role::Admin, "did:key:vtc-install")
                .with_label(Some("install bootstrap".into())),
        )
        .await
        .unwrap();
    }

    let state = vtc.state.clone();
    let router = vtc.router.clone();
    let jwt_keys = vtc.jwt_keys.clone();
    (
        Fixture {
            state,
            router,
            jwt_keys,
            admin_did: did_a,
            authenticator,
            _vtc: vtc,
        },
        did_b,
    )
}

/// Mint a live session for `did` and return `(session_id, bearer token)`.
/// `acr = "aal2"` with **no** elevation window — exactly the state a passkey
/// sign-in leaves behind, and the state a step-up must upgrade.
async fn session_for(fix: &Fixture, did: &str) -> (String, String) {
    let session_id = format!("sess-{}", Uuid::new_v4());
    store_session(
        &fix.state.sessions_ks,
        &Session {
            session_id: session_id.clone(),
            did: did.to_string(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: now_epoch(),
            last_seen: now_epoch(),
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: vec!["passkey".into()],
            acr: "aal2".into(),
            acr_expires_at: None,
            token_id: None,
            session_pubkey_b58btc: None,
        },
    )
    .await
    .unwrap();
    let claims = fix
        .jwt_keys
        .new_claims(
            did.to_string(),
            session_id.clone(),
            "admin".to_string(),
            vec![],
            900,
            false,
        )
        .with_aal(vec!["passkey".into()], "aal2");
    (session_id, fix.jwt_keys.encode(&claims).unwrap())
}

async fn request_method(
    router: &axum::Router,
    method: &str,
    path: &str,
    trust_task: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Trust-Task", trust_task);
    if let Some(tok) = token {
        builder = builder.header("Authorization", format!("Bearer {tok}"));
    }
    let body = match body {
        Some(b) => {
            builder = builder.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let res = router
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

/// POST helper — every ceremony leg is a POST.
async fn request(
    router: &axum::Router,
    path: &str,
    trust_task: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    request_method(router, "POST", path, trust_task, token, body).await
}

/// Run `start` with `purpose: stepUp` and return `(auth_id, options)`.
async fn step_up_start(fix: &Fixture, token: Option<&str>) -> (StatusCode, Value) {
    request(
        &fix.router,
        "/v1/auth/passkey-login/start",
        START_TASK,
        token,
        Some(json!({ "purpose": "stepUp" })),
    )
    .await
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn step_up_elevates_the_session_in_place() {
    let (mut fix, _other) = build_fixture().await;
    let (session_id, token) = session_for(&fix, &fix.admin_did.clone()).await;

    let (status, body) = step_up_start(&fix, Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "start: {body}");
    let auth_id = body["authId"].as_str().unwrap().to_string();
    let options: RequestChallengeResponse = wrap_options(&body["options"]);
    let assertion = fix.authenticator.authenticate(&options, RP_ORIGIN);

    let (status, body) = request(
        &fix.router,
        "/v1/auth/passkey-login/finish",
        FINISH_TASK,
        Some(&token),
        Some(json!({ "auth_id": auth_id, "credential": assertion })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "finish: {body}");

    // Spec 0.2: the step-up branch returns the elevated session and **no**
    // tokens — the caller's existing ones stay valid and pick up the elevation.
    assert_eq!(body["purpose"], "stepUp");
    assert_eq!(body["session"]["id"], session_id);
    assert_eq!(body["session"]["subject"], fix.admin_did);
    assert!(
        body.get("tokens").is_none(),
        "step-up must not mint tokens, got {body}"
    );
    assert!(
        body["ext"]["org.openvtc.step-up"]["expiresAt"].is_string(),
        "the elevation deadline must be reported, got {body}"
    );

    // Elevated in place: same row, now carrying a live window.
    let session = get_session(&fix.state.sessions_ks, &session_id)
        .await
        .unwrap()
        .expect("the session must still exist — step-up elevates, never replaces");
    assert_eq!(session.acr, "aal2");
    assert!(session.amr.iter().any(|m| m == "passkey"));
    let deadline = session
        .acr_expires_at
        .expect("step-up must stamp an elevation deadline");
    assert!(
        session.elevation_active(now_epoch()),
        "the window must be open immediately after the ceremony"
    );
    assert!(
        !session.elevation_active(deadline),
        "and closed once it lapses"
    );
}

#[tokio::test]
async fn step_up_requires_an_authenticated_session() {
    // A login is unauthenticated by nature; a step-up has nothing to elevate.
    let (fix, _other) = build_fixture().await;
    let (status, _body) = step_up_start(&fix, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn step_up_refuses_another_subjects_passkey() {
    // `allowCredentials` is a client-side hint. A caller that ignores it and
    // presents a *different* enrolled admin's passkey must not elevate their
    // own session — otherwise any operator standing at an enrolled machine
    // could step up someone else's session.
    let (mut fix, other_did) = build_fixture().await;
    let (_session_id, token) = session_for(&fix, &fix.admin_did.clone()).await;

    let (status, body) = step_up_start(&fix, Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "start: {body}");
    let auth_id = body["authId"].as_str().unwrap().to_string();

    // Re-issue the challenge against the *other* admin's credentials so the
    // harness signs with a passkey the bound session does not own.
    let (status, other_body) = request(
        &fix.router,
        "/v1/auth/passkey-login/start",
        START_TASK,
        None,
        Some(json!({ "subject": other_did })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "other start: {other_body}");
    let other_options: RequestChallengeResponse = wrap_options(&other_body["options"]);
    let foreign_assertion = fix.authenticator.authenticate(&other_options, RP_ORIGIN);

    // Spend the *step-up* auth_id with the foreign assertion. The WebAuthn
    // challenge won't match either, so this asserts the request is refused —
    // the subject check is the backstop that makes it refused for the right
    // reason when a caller can produce a matching challenge.
    let (status, _body) = request(
        &fix.router,
        "/v1/auth/passkey-login/finish",
        FINISH_TASK,
        Some(&token),
        Some(json!({ "auth_id": auth_id, "credential": foreign_assertion })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn step_up_is_bound_to_the_session_that_started_it() {
    // Two live sessions for the same admin. The ceremony started by one must
    // not elevate the other — the elevation is per-session, not per-subject.
    let (mut fix, _other) = build_fixture().await;
    let admin = fix.admin_did.clone();
    let (bound_session, bound_token) = session_for(&fix, &admin).await;
    let (_other_session, other_token) = session_for(&fix, &admin).await;

    let (status, body) = step_up_start(&fix, Some(&bound_token)).await;
    assert_eq!(status, StatusCode::OK, "start: {body}");
    let auth_id = body["authId"].as_str().unwrap().to_string();
    let options: RequestChallengeResponse = wrap_options(&body["options"]);
    let assertion = fix.authenticator.authenticate(&options, RP_ORIGIN);

    let (status, _body) = request(
        &fix.router,
        "/v1/auth/passkey-login/finish",
        FINISH_TASK,
        Some(&other_token),
        Some(json!({ "auth_id": auth_id, "credential": assertion })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let session = get_session(&fix.state.sessions_ks, &bound_session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        session.acr_expires_at, None,
        "a rejected step-up must leave no elevation behind"
    );
}

#[tokio::test]
async fn step_up_subject_must_match_the_session() {
    // Naming someone else as the subject of *your* step-up is a contradiction.
    // Refuse it rather than quietly answering for the session holder.
    let (fix, other_did) = build_fixture().await;
    let (_session_id, token) = session_for(&fix, &fix.admin_did.clone()).await;

    let (status, _body) = request(
        &fix.router,
        "/v1/auth/passkey-login/start",
        START_TASK,
        Some(&token),
        Some(json!({ "purpose": "stepUp", "subject": other_did })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn plain_login_is_unchanged_by_the_purpose_field() {
    // The admin SPA posts no body at all. That must keep reading as
    // `purpose: login` — unauthenticated, discoverable across every
    // registered passkey, minting a fresh session with tokens.
    let (mut fix, _other) = build_fixture().await;

    let (status, body) = request(
        &fix.router,
        "/v1/auth/passkey-login/start",
        START_TASK,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "start: {body}");
    let auth_id = body["authId"].as_str().unwrap().to_string();
    let options: RequestChallengeResponse = wrap_options(&body["options"]);
    let assertion = fix.authenticator.authenticate(&options, RP_ORIGIN);

    let (status, body) = request(
        &fix.router,
        "/v1/auth/passkey-login/finish",
        FINISH_TASK,
        None,
        Some(json!({ "auth_id": auth_id, "credential": assertion })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "finish: {body}");
    assert!(
        body["tokens"]["accessToken"].is_string(),
        "a login still mints tokens, got {body}"
    );

    // And a login carries **no** elevation window: it is `aal2` from its first
    // request, which is exactly why `StepUpAuth` cannot accept it as a
    // step-up. This is the property the whole ceremony exists to add.
    let session_id = body["session"]["id"].as_str().unwrap();
    let session = get_session(&fix.state.sessions_ks, session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.acr, "aal2");
    assert_eq!(
        session.acr_expires_at, None,
        "a sign-in is not a step-up; it must stamp no elevation window"
    );
    assert!(!session.elevation_active(now_epoch()));
}

#[tokio::test]
async fn a_step_up_authorises_the_promotion_it_was_run_for() {
    // The whole point of the API split, end to end: the ceremony that proves
    // the operator is present is a *different request* from the operation it
    // authorises, and the elevation window is what ties them together.
    let (mut fix, other_did) = build_fixture().await;
    let admin = fix.admin_did.clone();
    let (_session_id, token) = session_for(&fix, &admin).await;

    // The second enrolled admin is already `Admin` in the fixture, so promote
    // a plain member instead.
    let target = "did:key:zMemberToPromote";
    store_acl_entry(
        &fix.state.acl_ks,
        &AclEntry::new(target.to_string(), Role::Reader, &admin),
    )
    .await
    .unwrap();
    let _ = other_did;

    // Without an elevation the promotion is refused, and says why.
    let (status, body) = request_method(
        &fix.router,
        "PATCH",
        &format!("/v1/members/{target}"),
        UPDATE_TASK,
        Some(&token),
        Some(json!({ "role": "admin" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "got {body}");
    assert_eq!(body["error"], "step_up_required", "got {body}");

    // Step up, then retry. (The promotion itself needs a member row + policy
    // fixture this suite doesn't build, so we assert the *gate* opened: the
    // request gets past `step_up_required` to the member lookup.)
    let (status, body) = step_up_start(&fix, Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "start: {body}");
    let auth_id = body["authId"].as_str().unwrap().to_string();
    let options: RequestChallengeResponse = wrap_options(&body["options"]);
    let assertion = fix.authenticator.authenticate(&options, RP_ORIGIN);
    let (status, _) = request(
        &fix.router,
        "/v1/auth/passkey-login/finish",
        FINISH_TASK,
        Some(&token),
        Some(json!({ "auth_id": auth_id, "credential": assertion })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = request_method(
        &fix.router,
        "PATCH",
        &format!("/v1/members/{target}"),
        UPDATE_TASK,
        Some(&token),
        Some(json!({ "role": "admin" })),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "the elevation must open the gate, got {body}"
    );
}

#[tokio::test]
async fn a_step_up_ceremony_cannot_be_replayed() {
    let (mut fix, _other) = build_fixture().await;
    let (session_id, token) = session_for(&fix, &fix.admin_did.clone()).await;

    let (status, body) = step_up_start(&fix, Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "start: {body}");
    let auth_id = body["authId"].as_str().unwrap().to_string();
    let options: RequestChallengeResponse = wrap_options(&body["options"]);
    let assertion = fix.authenticator.authenticate(&options, RP_ORIGIN);

    let finish = json!({ "auth_id": auth_id, "credential": assertion });
    let (status, _) = request(
        &fix.router,
        "/v1/auth/passkey-login/finish",
        FINISH_TASK,
        Some(&token),
        Some(finish.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Roll the window back so a successful replay would be observable as a
    // re-opened elevation rather than being masked by the first one.
    let mut session = get_session(&fix.state.sessions_ks, &session_id)
        .await
        .unwrap()
        .unwrap();
    session.acr_expires_at = None;
    vti_common::auth::session::update_session(&fix.state.sessions_ks, &session)
        .await
        .unwrap();

    let (status, _) = request(
        &fix.router,
        "/v1/auth/passkey-login/finish",
        FINISH_TASK,
        Some(&token),
        Some(finish),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the ceremony state is consumed once"
    );

    let session = get_session(&fix.state.sessions_ks, &session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        session.acr_expires_at, None,
        "a replayed ceremony must not re-elevate"
    );
}
