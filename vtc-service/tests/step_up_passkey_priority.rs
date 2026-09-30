//! Once a subject holds a dedicated step-up passkey, it is the **only**
//! passkey that may answer an operation-bound step-up for them: their
//! ordinary session/console passkey stops counting, and so does any
//! non-passkey (`didSigned`/wallet-signed) evidence — which never counted for
//! anyone, on this door, in the first place. Security decision 2026-09-30.
//!
//! These drive [`bound_step_up`] and [`step_up_passkey`] directly, in-process:
//! the document-signing and proof-verification layer that sits in front of
//! them (`trust_tasks::handle_step_up_approve_response`) is already covered
//! by `signed_step_up.rs`, so nothing here needs a signed envelope.

mod common;

use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RequestChallengeResponse,
};

use trust_tasks_rs::specs::auth::passkey::enroll::invite::v0_2 as invite_spec;
use trust_tasks_rs::specs::auth::passkey::enroll::redeem::finish::v0_1 as redeem_finish_spec;
use trust_tasks_rs::specs::auth::passkey::enroll::redeem::start::v0_1 as redeem_start_spec;
use trust_tasks_rs::specs::auth::step_up::approve_response::v0_4 as approve_response_spec;

use vtc_service::acl::bound_step_up::{self, ApproveError, Approved, Gate};
use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::auth::session::{Session, SessionState, get_session, now_epoch, store_session};
use vtc_service::step_up_passkey;
use vtc_service::test_support::TestVtc;
use vtc_service::webauthn::{finish_passkey_registration, start_passkey_registration};

use common::webauthn_harness::SoftEd25519Authenticator;

const RP_ORIGIN: &str = "https://vtc.example.com";
/// The operation these tests bind gestures to. Which task it is does not
/// matter to any assertion here — only who may answer for the subject does.
const BREAK_GLASS: &str = "https://trusttasks.org/spec/git-ns/right/break-glass/0.1";

/// A distinct payload per gesture — `redeem_or_request` keys its mark on the
/// digest of type + payload, so reusing one across calls in the same test
/// would let an earlier gesture's recorded mark answer a later request
/// instead of asking for a fresh one.
fn payload(marker: &str) -> Value {
    json!({
        "right": "git.repo.own",
        "resource": format!("github.com/acme/{marker}"),
        "justification": "priority test fixture",
    })
}

fn admin_row(did: &str) -> VtcAclEntry {
    VtcAclEntry {
        did: did.to_string(),
        role: VtcRole::Admin,
        label: None,
        allowed_contexts: vec![],
        created_at: 0,
        created_by: "did:key:vtc-install".into(),
        updated_at: None,
        updated_by: None,
        expires_at: None,
    }
}

/// A webauthn-rs result as the published, base64url-encoded wire shape the
/// spec's payloads carry — matching `step_up_passkeys.rs`'s convention.
fn published(v: impl serde::Serialize) -> Value {
    fn strip_nulls(v: &mut Value) {
        if let Value::Object(map) = v {
            map.retain(|_, v| !v.is_null());
            map.values_mut().for_each(strip_nulls);
        }
    }
    let mut v = serde_json::to_value(v).unwrap();
    let obj = v.as_object_mut().unwrap();
    obj.remove("extensions");
    obj.insert("clientExtensionResults".into(), json!({}));
    strip_nulls(&mut v);
    v
}

/// Register a **console/session** passkey for `did` directly in the
/// `passkey` store — the store `routes/auth.rs`'s bearer step-up reads, and
/// the store `bound_step_up` used to also accept unconditionally.
async fn enrol_console_passkey(
    vtc: &TestVtc,
    authenticator: &mut SoftEd25519Authenticator,
    did: &str,
) {
    use uuid::Uuid;
    use vti_common::auth::passkey::build_webauthn;
    use vti_common::auth::passkey::store::{
        PasskeyUser, store_credential_mapping, store_passkey_user,
    };

    let webauthn = build_webauthn(RP_ORIGIN).unwrap();
    let user_uuid = Uuid::new_v4();
    let (ccr, reg_state) =
        start_passkey_registration(&webauthn, user_uuid, did, did, None).unwrap();
    let (cred, _) = authenticator.register(&ccr, RP_ORIGIN);
    let passkey = finish_passkey_registration(&webauthn, &cred, &reg_state).unwrap();
    let cred_hex = hex::encode(<_ as AsRef<[u8]>>::as_ref(passkey.cred_id()));
    let ks = &vtc.state.passkey_ks;
    store_passkey_user(
        ks,
        &PasskeyUser {
            user_uuid,
            did: did.to_string(),
            display_name: did.to_string(),
            credentials: vec![passkey],
        },
    )
    .await
    .unwrap();
    store_credential_mapping(ks, &cred_hex, user_uuid)
        .await
        .unwrap();
}

/// Enrol a dedicated **step-up** passkey for `subject`, through a community
/// administrator's invite (`inviter`, who must be a different admin) —
/// `auth/passkey/enroll/{invite,redeem/start,redeem/finish}`, called
/// in-process exactly as the Trust Task spine calls them.
async fn enrol_step_up_passkey(
    vtc: &TestVtc,
    authenticator: &mut SoftEd25519Authenticator,
    inviter: &str,
    subject: &str,
) {
    let invite_payload: invite_spec::Payload =
        serde_json::from_value(json!({ "subject": subject, "purpose": "stepUp" })).unwrap();
    let issued = step_up_passkey::issue_invite(&vtc.state, inviter, &invite_payload)
        .await
        .expect("issue step-up passkey invite");
    let issued = serde_json::to_value(&issued).unwrap();

    let start_payload: redeem_start_spec::Payload = serde_json::from_value(json!({
        "token": issued["invite"]["token"],
        "claimCode": issued["claimCode"],
    }))
    .unwrap();
    let started = step_up_passkey::redeem_start(&vtc.state, subject, &start_payload)
        .await
        .expect("redeem/start");
    let started = serde_json::to_value(&started).unwrap();

    let ccr: CreationChallengeResponse =
        serde_json::from_value(json!({ "publicKey": started["options"] })).unwrap();
    let (cred, _) = authenticator.register(&ccr, RP_ORIGIN);

    let finish_payload: redeem_finish_spec::Payload = serde_json::from_value(json!({
        "enrollmentId": started["enrollmentId"],
        "credential": published(&cred),
    }))
    .unwrap();
    step_up_passkey::redeem_finish(&vtc.state, Some(subject), &finish_payload)
        .await
        .expect("redeem/finish");
}

/// A bound step-up asked of `did` over `payload` — the inline `approve-request`
/// as JSON, the same shape `signed_step_up.rs` works with.
async fn request_for(vtc: &TestVtc, did: &str, payload: &Value) -> Value {
    match bound_step_up::redeem_or_request(&vtc.state, did, BREAK_GLASS, payload, "test")
        .await
        .unwrap()
    {
        Gate::Required(r) => serde_json::to_value(*r).unwrap(),
        Gate::Satisfied => panic!("nothing was recorded yet for this payload"),
    }
}

/// The WebAuthn options as webauthn-rs's `{publicKey: …}` wrapper, which the
/// soft authenticator reads — matching `signed_step_up.rs::options`.
fn options(request: &Value) -> RequestChallengeResponse {
    let mut inner = request["webauthn"].clone();
    inner["timeout"] = inner.get("timeout").cloned().unwrap_or(json!(60000));
    serde_json::from_value(json!({ "publicKey": inner })).expect("options re-wrap")
}

fn approve_payload(
    did: &str,
    request: &Value,
    cred: &PublicKeyCredential,
) -> approve_response_spec::Payload {
    serde_json::from_value(json!({
        "subject": did,
        "challenge": request["challenge"],
        "decision": "approved",
        "evidence": { "kind": "webauthn", "assertion": published(cred) },
    }))
    .unwrap()
}

/// A subject with **both** a console passkey and a dedicated step-up passkey:
/// the console passkey no longer answers, and the step-up passkey does.
#[tokio::test]
async fn once_enrolled_a_step_up_passkey_is_the_only_gesture_that_counts() {
    let vtc = TestVtc::builder().with_public_url(RP_ORIGIN).build().await;
    let mut authenticator = SoftEd25519Authenticator::new();

    let inviter = Party::new();
    store_acl_entry(&vtc.state.acl_ks, &admin_row(&inviter.did))
        .await
        .unwrap();
    let admin = Party::new();
    store_acl_entry(&vtc.state.acl_ks, &admin_row(&admin.did))
        .await
        .unwrap();
    enrol_console_passkey(&vtc, &mut authenticator, &admin.did).await;

    // Before enrolment: the console passkey is today's route, and it's the
    // only credential the ceremony offers.
    let request = request_for(&vtc, &admin.did, &payload("before")).await;
    let allowed = request["webauthn"]["allowCredentials"].clone();
    assert_eq!(
        allowed.as_array().map(Vec::len),
        Some(1),
        "only the admin's own (console) credential is offered: {request}"
    );
    let cred = authenticator.authenticate(&options(&request), RP_ORIGIN);
    let approved =
        bound_step_up::approve(&vtc.state, &approve_payload(&admin.did, &request, &cred))
            .await
            .expect("the console passkey answers before any step-up passkey exists");
    assert!(matches!(approved, Approved::Recorded { .. }));

    // Enrol a dedicated step-up passkey for the same admin.
    enrol_step_up_passkey(&vtc, &mut authenticator, &inviter.did, &admin.did).await;

    // After enrolment: the ceremony offers only the step-up passkey.
    let request = request_for(&vtc, &admin.did, &payload("after-1")).await;
    let offered_now = request["webauthn"]["allowCredentials"].clone();
    assert_eq!(offered_now.as_array().map(Vec::len), Some(1), "{request}");
    assert_ne!(
        offered_now, allowed,
        "the offered credential changed from the console passkey to the step-up passkey"
    );

    // The console passkey no longer answers, even crafted onto the request —
    // the way `another_admins_passkey_is_refused` substitutes a credential in
    // `signed_step_up.rs` — because the ceremony state behind the challenge
    // was built only from the step-up passkey.
    let mut console_request = request_for(&vtc, &admin.did, &payload("after-2")).await;
    console_request["webauthn"]["allowCredentials"] = allowed;
    let console_cred = authenticator.authenticate(&options(&console_request), RP_ORIGIN);
    let refused = bound_step_up::approve(
        &vtc.state,
        &approve_payload(&admin.did, &console_request, &console_cred),
    )
    .await;
    assert!(
        matches!(refused, Err(ApproveError::AssertionInvalid(_))),
        "{refused:?}"
    );

    // The step-up passkey does.
    let request = request_for(&vtc, &admin.did, &payload("after-3")).await;
    let cred = authenticator.authenticate(&options(&request), RP_ORIGIN);
    let approved =
        bound_step_up::approve(&vtc.state, &approve_payload(&admin.did, &request, &cred))
            .await
            .expect("the step-up passkey answers");
    assert!(matches!(approved, Approved::Recorded { .. }));
}

/// A subject with no step-up passkey keeps today's route: their session
/// passkey still answers.
#[tokio::test]
async fn a_subject_with_no_step_up_passkey_keeps_the_session_passkey_route() {
    let vtc = TestVtc::builder().with_public_url(RP_ORIGIN).build().await;
    let mut authenticator = SoftEd25519Authenticator::new();
    let admin = Party::new();
    store_acl_entry(&vtc.state.acl_ks, &admin_row(&admin.did))
        .await
        .unwrap();
    enrol_console_passkey(&vtc, &mut authenticator, &admin.did).await;

    let request = request_for(&vtc, &admin.did, &payload("solo")).await;
    let cred = authenticator.authenticate(&options(&request), RP_ORIGIN);
    let approved =
        bound_step_up::approve(&vtc.state, &approve_payload(&admin.did, &request, &cred))
            .await
            .expect("the session passkey still answers with no step-up passkey enrolled");
    assert!(matches!(approved, Approved::Recorded { .. }));
}

/// A non-passkey (`didSigned`, or absent `evidence`) answer never counts on
/// this door, whether or not the subject holds a step-up passkey.
#[tokio::test]
async fn a_wallet_signed_answer_never_satisfies_the_gesture() {
    let vtc = TestVtc::builder().with_public_url(RP_ORIGIN).build().await;
    let admin = Party::new();
    store_acl_entry(&vtc.state.acl_ks, &admin_row(&admin.did))
        .await
        .unwrap();
    let mut authenticator = SoftEd25519Authenticator::new();
    enrol_console_passkey(&vtc, &mut authenticator, &admin.did).await;

    let request = request_for(&vtc, &admin.did, &payload("wallet")).await;
    let wallet_signed: approve_response_spec::Payload = serde_json::from_value(json!({
        "subject": admin.did,
        "challenge": request["challenge"],
        "decision": "approved",
    }))
    .unwrap();
    let refused = bound_step_up::approve(&vtc.state, &wallet_signed).await;
    assert!(matches!(refused, Err(ApproveError::NoGate)), "{refused:?}");
}

/// Enrolling a step-up passkey revokes a session elevation granted before it
/// existed — the stronger of "expire" and "revoke": immediately, not left to
/// lapse on its own bounded window.
#[tokio::test]
async fn enrolling_a_step_up_passkey_drops_an_existing_session_elevation() {
    let vtc = TestVtc::builder().with_public_url(RP_ORIGIN).build().await;
    let mut authenticator = SoftEd25519Authenticator::new();

    let inviter = Party::new();
    store_acl_entry(&vtc.state.acl_ks, &admin_row(&inviter.did))
        .await
        .unwrap();
    let admin = Party::new();
    store_acl_entry(&vtc.state.acl_ks, &admin_row(&admin.did))
        .await
        .unwrap();

    // A session already elevated by a step-up ceremony before any step-up
    // passkey existed for this subject.
    let session_id = "sess-priority-test".to_string();
    let now = now_epoch();
    store_session(
        &vtc.state.sessions_ks,
        &Session {
            session_id: session_id.clone(),
            did: admin.did.clone(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: now,
            last_seen: now,
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: vec!["passkey".into()],
            acr: "aal2".into(),
            acr_expires_at: Some(now + 900),
            token_id: None,
            session_pubkey_b58btc: None,
        },
    )
    .await
    .unwrap();

    enrol_step_up_passkey(&vtc, &mut authenticator, &inviter.did, &admin.did).await;

    let session = get_session(&vtc.state.sessions_ks, &session_id)
        .await
        .unwrap()
        .expect("session still exists");
    assert!(
        session.acr_expires_at.is_none(),
        "the existing elevation was revoked on enrolment: {session:?}"
    );
    // `acr` is left alone — the login it reflects still genuinely happened.
    assert_eq!(session.acr, "aal2");
}
