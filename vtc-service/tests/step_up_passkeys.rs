//! Members' step-up passkeys (`auth/passkey/enroll/invite/0.2`,
//! `purpose: stepUp`; `crate::step_up_passkey`).
//!
//! The loop: a community administrator invites a member; the member redeems
//! the invite with its claim code and a real WebAuthn registration from the
//! soft authenticator; an operation-bound step-up issued to the member is then
//! answered with that passkey — by an **unsigned** approve-response, since a
//! member who is no console user has no console key. And the refusals that
//! make the anchor worth having: no session ever sees the credential, a wrong
//! code is counted, a second passkey needs a gesture from the first, only a
//! community administrator invites, nobody invites themselves, and a revoked
//! passkey cannot answer a step-up that was already pending.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::auth::passkey::build_webauthn;
use vti_common::auth::passkey::store::{
    PasskeyUser, get_all_passkeys, store_credential_mapping, store_passkey_user,
};
use vti_common::error::AppError;
use vti_rooms_dtg::test_support::Party;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RequestChallengeResponse,
};

use vtc_service::acl::bound_step_up::{self, Gate};
use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::step_up_passkey::{self, MAX_WRONG_CODES};
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

use common::webauthn_harness::SoftEd25519Authenticator;

const RP_ORIGIN: &str = "https://vtc.example.com";
const APPROVE_RESPONSE: &str = "https://trusttasks.org/spec/auth/step-up/approve-response/0.4";
const BREAK_GLASS: &str = "https://trusttasks.org/spec/git-ns/right/break-glass/0.1";

struct Fixture {
    vtc: TestVtc,
    /// The administrator's authenticator.
    admin_key: SoftEd25519Authenticator,
    /// The member's.
    member_key: SoftEd25519Authenticator,
    admin: Party,
    member: Party,
}

fn row(did: &str, role: VtcRole) -> VtcAclEntry {
    VtcAclEntry {
        did: did.to_string(),
        role,
        label: None,
        allowed_contexts: vec![],
        created_at: 0,
        created_by: "did:key:vtc-install".into(),
        updated_at: None,
        updated_by: None,
        expires_at: None,
    }
}

/// A community administrator with a session passkey, and a member with none.
async fn fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .with_public_url(RP_ORIGIN)
        .with_signers(true)
        .build()
        .await;
    let admin = Party::new();
    let member = Party::new();
    store_acl_entry(&vtc.state.acl_ks, &row(&admin.did, VtcRole::Admin))
        .await
        .unwrap();
    store_acl_entry(&vtc.state.acl_ks, &row(&member.did, VtcRole::Member))
        .await
        .unwrap();
    let mut fix = Fixture {
        vtc,
        admin_key: SoftEd25519Authenticator::new(),
        member_key: SoftEd25519Authenticator::new(),
        admin,
        member,
    };
    let did = fix.admin.did.clone();
    let webauthn = build_webauthn(RP_ORIGIN).unwrap();
    let user_uuid = Uuid::new_v4();
    let (ccr, reg) =
        vtc_service::webauthn::start_passkey_registration(&webauthn, user_uuid, &did, &did, None)
            .unwrap();
    let (cred, _) = fix.admin_key.register(&ccr, RP_ORIGIN);
    let passkey =
        vtc_service::webauthn::finish_passkey_registration(&webauthn, &cred, &reg).unwrap();
    let hex_id = hex::encode(<_ as AsRef<[u8]>>::as_ref(passkey.cred_id()));
    let ks = &fix.vtc.state.passkey_ks;
    store_passkey_user(
        ks,
        &PasskeyUser {
            user_uuid,
            did: did.clone(),
            display_name: did,
            credentials: vec![passkey],
        },
    )
    .await
    .unwrap();
    store_credential_mapping(ks, &hex_id, user_uuid)
        .await
        .unwrap();
    fix
}

fn creation(
    options: &webauthn_rs_proto::PublicKeyCredentialCreationOptions,
) -> CreationChallengeResponse {
    serde_json::from_value(json!({ "publicKey": serde_json::to_value(options).unwrap() })).unwrap()
}

fn request_options(
    options: &webauthn_rs_proto::PublicKeyCredentialRequestOptions,
) -> RequestChallengeResponse {
    serde_json::from_value(json!({ "publicKey": serde_json::to_value(options).unwrap() })).unwrap()
}

/// Invite the member and redeem it with `member_key`. The credential id.
async fn enrol(fix: &mut Fixture) -> String {
    let issued = step_up_passkey::issue_invite(
        &fix.vtc.state,
        &fix.admin.did,
        &fix.member.did,
        Some("Carol's laptop".into()),
        None,
    )
    .await
    .unwrap();
    assert!(
        !issued.invite.url.contains(&issued.claim_code),
        "the claim code must never ride in the URL"
    );
    assert!(
        issued.invite.url.contains("#token="),
        "{}",
        issued.invite.url
    );
    let started = step_up_passkey::redeem_start(
        &fix.vtc.state,
        &issued.invite.token,
        &issued.claim_code.to_lowercase(),
    )
    .await
    .expect("the claim code is accepted whatever its case");
    assert_eq!(started.subject, fix.member.did);
    let (cred, _) = fix
        .member_key
        .register(&creation(&started.options), RP_ORIGIN);
    let uv = started
        .uv_options
        .as_ref()
        .map(|o| fix.member_key.authenticate(&request_options(o), RP_ORIGIN));
    let done = step_up_passkey::redeem_finish(
        &fix.vtc.state,
        &started.enrollment_id,
        &cred,
        uv.as_ref(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(done.subject, fix.member.did);
    assert_eq!(done.device_label.as_deref(), Some("Carol's laptop"));
    done.credential_id
}

fn assertion(cred: &PublicKeyCredential) -> Value {
    let v = serde_json::to_value(cred).unwrap();
    let mut response = json!({
        "authenticatorData": v["response"]["authenticatorData"],
        "clientDataJSON": v["response"]["clientDataJSON"],
        "signature": v["response"]["signature"],
    });
    if v["response"]["userHandle"].is_string() {
        response["userHandle"] = v["response"]["userHandle"].clone();
    }
    json!({
        "id": v["id"], "rawId": v["rawId"], "type": "public-key",
        "response": response, "clientExtensionResults": {},
    })
}

/// Answer `request` with `cred`, **unsigned**: the member's browser holds no
/// key this community knows.
async fn approve_unsigned(
    fix: &Fixture,
    request: &Value,
    cred: &PublicKeyCredential,
) -> (StatusCode, Value) {
    let doc = vta_sdk::trust_task_sign::build_unsigned(
        APPROVE_RESPONSE,
        json!({
            "subject": request["subject"],
            "challenge": request["challenge"],
            "decision": "approved",
            "evidence": { "kind": "webauthn", "assertion": assertion(cred) },
        }),
        &fix.member.did,
        TEST_VTC_DID,
    )
    .unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/trust-tasks")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let resp = fix.vtc.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body["payload"].clone())
}

fn break_glass_payload() -> Value {
    json!({
        "right": "git.repo.own",
        "resource": "github.com/acme/widgets",
        "justification": "Both owners unreachable; CVE fix must ship tonight",
    })
}

async fn request_step_up(fix: &Fixture) -> Value {
    match bound_step_up::redeem_or_request(
        &fix.vtc.state,
        &fix.member.did,
        BREAK_GLASS,
        &break_glass_payload(),
        "break the glass",
    )
    .await
    .unwrap()
    {
        Gate::Required(r) => serde_json::to_value(*r).unwrap(),
        Gate::Satisfied => panic!("no gesture was recorded yet"),
    }
}

fn step_up_options(request: &Value) -> RequestChallengeResponse {
    let mut inner = request["webauthn"].clone();
    inner["timeout"] = inner.get("timeout").cloned().unwrap_or(json!(60000));
    serde_json::from_value(json!({ "publicKey": inner })).unwrap()
}

fn code_of(e: &AppError) -> String {
    e.to_string()
}

#[tokio::test]
async fn a_member_enrols_a_step_up_passkey_and_answers_a_bound_step_up_with_it() {
    let mut fix = fixture().await;
    // Before: the member has no passkey at all, so a bound step-up cannot
    // even be asked of them.
    let err = bound_step_up::redeem_or_request(
        &fix.vtc.state,
        &fix.member.did,
        BREAK_GLASS,
        &break_glass_payload(),
        "break the glass",
    )
    .await
    .unwrap_err();
    assert!(
        code_of(&err).contains("invite them to enrol a step-up passkey"),
        "{err}"
    );

    let cred_id = enrol(&mut fix).await;

    // Never in the store login and session step-up read.
    let session_passkeys = get_all_passkeys(&fix.vtc.state.passkey_ks).await.unwrap();
    assert_eq!(
        session_passkeys.len(),
        1,
        "only the admin's session passkey"
    );
    assert!(
        session_passkeys
            .iter()
            .all(|p| hex::encode(<_ as AsRef<[u8]>>::as_ref(p.cred_id())) != cred_id)
    );

    // A bound step-up now offers it, and an unsigned answer records it.
    let request = request_step_up(&fix).await;
    let offered = request["webauthn"]["allowCredentials"].as_array().unwrap();
    assert_eq!(offered.len(), 1, "{request}");
    let answer = fix
        .member_key
        .authenticate(&step_up_options(&request), RP_ORIGIN);
    let (status, ack) = approve_unsigned(&fix, &request, &answer).await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["status"], "recorded", "{ack}");

    // The operation spends it once.
    let spent = bound_step_up::redeem_or_request(
        &fix.vtc.state,
        &fix.member.did,
        BREAK_GLASS,
        &break_glass_payload(),
        "break the glass",
    )
    .await
    .unwrap();
    assert!(matches!(spent, Gate::Satisfied));

    let listed = step_up_passkey::list(&fix.vtc.state.step_up_passkeys_ks, Some(&fix.member.did))
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].last_used_at.is_some());
    assert_eq!(listed[0].invited_by, fix.admin.did);
}

#[tokio::test]
async fn wrong_claim_codes_are_counted_and_then_the_invite_is_gone() {
    let fix = fixture().await;
    let issued =
        step_up_passkey::issue_invite(&fix.vtc.state, &fix.admin.did, &fix.member.did, None, None)
            .await
            .unwrap();
    // A wrong token and a wrong code are the same refusal.
    let e =
        step_up_passkey::redeem_start(&fix.vtc.state, "sup_not-a-token-at-all", &issued.claim_code)
            .await
            .unwrap_err();
    assert!(code_of(&e).contains("redeem/start:inviteInvalid"), "{e}");
    for _ in 1..MAX_WRONG_CODES {
        let e = step_up_passkey::redeem_start(&fix.vtc.state, &issued.invite.token, "WRONGWRONG")
            .await
            .unwrap_err();
        assert!(code_of(&e).contains("redeem/start:inviteInvalid"), "{e}");
    }
    let e = step_up_passkey::redeem_start(&fix.vtc.state, &issued.invite.token, "WRONGWRONG")
        .await
        .unwrap_err();
    assert!(code_of(&e).contains("redeem/start:tooManyAttempts"), "{e}");
    let e = step_up_passkey::redeem_start(&fix.vtc.state, &issued.invite.token, &issued.claim_code)
        .await
        .unwrap_err();
    assert!(code_of(&e).contains("redeem/start:inviteInvalid"), "{e}");
}

#[tokio::test]
async fn an_invite_redeems_once_and_a_second_passkey_needs_a_gesture_from_the_first() {
    let mut fix = fixture().await;
    let issued =
        step_up_passkey::issue_invite(&fix.vtc.state, &fix.admin.did, &fix.member.did, None, None)
            .await
            .unwrap();
    let started =
        step_up_passkey::redeem_start(&fix.vtc.state, &issued.invite.token, &issued.claim_code)
            .await
            .unwrap();
    assert!(started.uv_options.is_none());
    let (cred, _) = fix
        .member_key
        .register(&creation(&started.options), RP_ORIGIN);
    step_up_passkey::redeem_finish(&fix.vtc.state, &started.enrollment_id, &cred, None, None)
        .await
        .unwrap();
    // Spent.
    let e = step_up_passkey::redeem_start(&fix.vtc.state, &issued.invite.token, &issued.claim_code)
        .await
        .unwrap_err();
    assert!(code_of(&e).contains("inviteInvalid"), "{e}");

    // A second invite: the start now asks for the first passkey too, and a
    // finish without that gesture binds nothing.
    let again =
        step_up_passkey::issue_invite(&fix.vtc.state, &fix.admin.did, &fix.member.did, None, None)
            .await
            .unwrap();
    let started =
        step_up_passkey::redeem_start(&fix.vtc.state, &again.invite.token, &again.claim_code)
            .await
            .unwrap();
    assert!(started.uv_options.is_some());
    let mut other = SoftEd25519Authenticator::new();
    let (cred2, _) = other.register(&creation(&started.options), RP_ORIGIN);
    let e =
        step_up_passkey::redeem_finish(&fix.vtc.state, &started.enrollment_id, &cred2, None, None)
            .await
            .unwrap_err();
    assert!(
        code_of(&e).contains("redeem/finish:userVerificationFailed"),
        "{e}"
    );
    assert_eq!(
        step_up_passkey::list(&fix.vtc.state.step_up_passkeys_ks, None)
            .await
            .unwrap()
            .len(),
        1
    );
    // With it, the second binds.
    let started =
        step_up_passkey::redeem_start(&fix.vtc.state, &again.invite.token, &again.claim_code)
            .await
            .unwrap();
    let (cred2, _) = other.register(&creation(&started.options), RP_ORIGIN);
    let uv = fix.member_key.authenticate(
        &request_options(started.uv_options.as_ref().unwrap()),
        RP_ORIGIN,
    );
    step_up_passkey::redeem_finish(
        &fix.vtc.state,
        &started.enrollment_id,
        &cred2,
        Some(&uv),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        step_up_passkey::list(&fix.vtc.state.step_up_passkeys_ks, None)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn only_a_community_administrator_invites_and_never_themselves() {
    let fix = fixture().await;
    let e =
        step_up_passkey::issue_invite(&fix.vtc.state, &fix.admin.did, &fix.admin.did, None, None)
            .await
            .unwrap_err();
    assert!(code_of(&e).contains("invite:roleNotPermitted"), "{e}");
    let e =
        step_up_passkey::issue_invite(&fix.vtc.state, &fix.member.did, &fix.admin.did, None, None)
            .await
            .unwrap_err();
    assert!(code_of(&e).contains("invite:roleNotPermitted"), "{e}");
    let stranger = Party::new();
    let e =
        step_up_passkey::issue_invite(&fix.vtc.state, &fix.admin.did, &stranger.did, None, None)
            .await
            .unwrap_err();
    assert!(code_of(&e).contains("invite:subjectUnknown"), "{e}");
}

#[tokio::test]
async fn a_revoked_step_up_passkey_cannot_answer_a_step_up_already_pending() {
    let mut fix = fixture().await;
    let cred_id = enrol(&mut fix).await;
    let request = request_step_up(&fix).await;

    // The administrator revokes it, verifying with their own passkey.
    let started =
        step_up_passkey::revoke_start(&fix.vtc.state, &fix.admin.did, &fix.member.did, &cred_id)
            .await
            .unwrap();
    let uv = fix
        .admin_key
        .authenticate(&request_options(&started.uv_options), RP_ORIGIN);
    let revoked =
        step_up_passkey::revoke_finish(&fix.vtc.state, &fix.admin.did, &started.revocation_id, &uv)
            .await
            .unwrap();
    assert_eq!(
        revoked.remaining, 0,
        "a step-up passkey may be revoked to none"
    );

    let answer = fix
        .member_key
        .authenticate(&step_up_options(&request), RP_ORIGIN);
    let (_, refusal) = approve_unsigned(&fix, &request, &answer).await;
    assert_eq!(
        refusal["code"], "auth/step-up/approve-response:assertionInvalid",
        "{refusal}"
    );
    assert!(
        step_up_passkey::list(&fix.vtc.state.step_up_passkeys_ks, None)
            .await
            .unwrap()
            .is_empty()
    );

    // A member cannot revoke through the administrator's door.
    let e =
        step_up_passkey::revoke_start(&fix.vtc.state, &fix.member.did, &fix.member.did, &cred_id)
            .await
            .unwrap_err();
    assert!(code_of(&e).contains("revoke/start:notAuthorized"), "{e}");
}
