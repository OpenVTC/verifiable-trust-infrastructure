//! Operation-bound step-up on the signed-document door (#1641).
//!
//! `acl/grant` conferring admin authority needs a passkey gesture. On the
//! bearer route that gesture is a live session elevation; a signed document
//! has no session, so the gesture is **bound to the one grant** by a digest of
//! its type and payload, recorded by `auth/step-up/approve-response/0.4`, and
//! spent by the grant. Design: `docs/05-design-notes/vtc-operation-bound-step-up.md`.
//!
//! These drive the whole loop end to end — refusal with the ceremony inline, a
//! real WebAuthn assertion from the soft authenticator, `recorded`, the re-send
//! — and pin the refusals that make the binding worth having (design note §6,
//! step 2): one gesture redeems one act; a different payload and the same
//! payload twice are refused; a console key cannot create a mark; a silent
//! assertion and another admin's passkey are refused.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::auth::passkey::build_webauthn;
use vti_common::auth::passkey::store::{PasskeyUser, store_credential_mapping, store_passkey_user};
use vti_rooms_dtg::test_support::Party;
use webauthn_rs::prelude::{PublicKeyCredential, RequestChallengeResponse};

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

use crate::common::webauthn_harness::SoftEd25519Authenticator;

const RP_ORIGIN: &str = "https://vtc.example.com";
const GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
const APPROVE_RESPONSE: &str = "https://trusttasks.org/spec/auth/step-up/approve-response/0.4";
const CHANGE_ROLE: &str = "https://trusttasks.org/spec/acl/change-role/0.1";

struct Fixture {
    vtc: TestVtc,
    authenticator: SoftEd25519Authenticator,
}

/// A VTC whose WebAuthn relying party is `RP_ORIGIN`, with the spine's
/// signers so replies are signed as they are in production.
async fn fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .with_public_url(RP_ORIGIN)
        .with_signers(true)
        .build()
        .await;
    // A promotion is the role-change ceremony, which decides against the
    // default `role_change` policy.
    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .unwrap();
    Fixture {
        vtc,
        authenticator: SoftEd25519Authenticator::new(),
    }
}

/// An unrestricted admin who signs documents with `Party`'s key and holds a
/// passkey the soft authenticator can assert with.
async fn admin_with_passkey(fix: &mut Fixture) -> Party {
    let party = Party::new();
    store_acl_entry(&fix.vtc.state.acl_ks, &row(&party.did, VtcRole::Admin))
        .await
        .unwrap();
    enrol_passkey(fix, &party.did).await;
    party
}

fn row(did: &str, role: VtcRole) -> VtcAclEntry {
    VtcAclEntry {
        did: did.to_string(),
        admin: role.implied_authority(),
        delegated_by: None,
        role,
        label: None,
        created_at: 0,
        created_by: "did:key:vtc-install".into(),
        updated_at: None,
        updated_by: None,
        expires_at: None,
        resource_grants: Vec::new(),
        label_set_by_subject: false,
    }
}

async fn enrol_passkey(fix: &mut Fixture, did: &str) {
    let webauthn = build_webauthn(RP_ORIGIN).unwrap();
    let user_uuid = Uuid::new_v4();
    let (ccr, reg_state) =
        vtc_service::webauthn::start_passkey_registration(&webauthn, user_uuid, did, did, None)
            .unwrap();
    let (cred, _) = fix.authenticator.register(&ccr, RP_ORIGIN);
    let passkey =
        vtc_service::webauthn::finish_passkey_registration(&webauthn, &cred, &reg_state).unwrap();
    let cred_hex = hex::encode(<_ as AsRef<[u8]>>::as_ref(passkey.cred_id()));
    let ks = &fix.vtc.state.passkey_ks;
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

/// A signed document, ready to send — and to send again unchanged.
async fn signed(from: &Party, type_uri: &str, payload: Value) -> Value {
    let mut doc =
        vta_sdk::trust_task_sign::build_unsigned(type_uri, payload, &from.did, TEST_VTC_DID)
            .unwrap();
    let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(&from.did, &from.secret_multibase)
        .unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
        .await
        .unwrap();
    serde_json::to_value(doc).unwrap()
}

/// POST a document; the reply's status and `payload`.
async fn post(fix: &Fixture, doc: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/trust-tasks")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(doc).unwrap()))
        .unwrap();
    let resp = fix.vtc.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body["payload"].clone())
}

/// A grant of administrative authority that confers nothing
/// authority-conferring: a moderator (the 0.1 role implies the `moderator`
/// administrative role). These tests are about the gesture; a grant of an
/// authority-conferring capability also needs another holder's consent
/// (VTI-APV-018), which `unrestricted_admin_consent.rs` drives.
fn grant_admin(subject: &str) -> Value {
    json!({ "entry": { "subject": subject, "role": "moderator" } })
}

/// The inline approve-request a refusal carries, checked for the shape
/// approve-request 0.3 gives it.
fn step_up_request(refusal: &Value) -> Value {
    assert_eq!(refusal["code"], "permissionDenied", "{refusal}");
    let req = refusal["details"]["stepUpRequest"].clone();
    assert!(req.is_object(), "no inline step-up request: {refusal}");
    assert!(
        req.get("sessionId").is_none(),
        "a bound step-up has no session: {req}"
    );
    assert!(req["boundTo"].is_string(), "{req}");
    assert_eq!(req["webauthn"]["challenge"], req["challenge"], "{req}");
    req
}

/// The WebAuthn options as webauthn-rs's `{publicKey: …}` wrapper, which the
/// soft authenticator reads — the re-wrap a browser client does.
fn options(request: &Value) -> RequestChallengeResponse {
    let mut inner = request["webauthn"].clone();
    // Members the published component leaves optional and webauthn-rs's
    // struct does not.
    inner["timeout"] = inner.get("timeout").cloned().unwrap_or(json!(60000));
    serde_json::from_value(json!({ "publicKey": inner })).expect("options re-wrap")
}

/// The published `AssertionResponse` for a webauthn-rs credential.
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
        "id": v["id"],
        "rawId": v["rawId"],
        "type": "public-key",
        "response": response,
        "clientExtensionResults": {},
    })
}

async fn approve(
    fix: &Fixture,
    signer: &Party,
    request: &Value,
    cred: &PublicKeyCredential,
) -> (StatusCode, Value) {
    let doc = signed(
        signer,
        APPROVE_RESPONSE,
        json!({
            "subject": request["subject"],
            "challenge": request["challenge"],
            "decision": "approved",
            "evidence": { "kind": "webauthn", "assertion": assertion(cred) },
        }),
    )
    .await;
    post(fix, &doc).await
}

/// The same answer, unsigned: the console's, whose browser holds a session
/// passkey of the admin's and no key of theirs.
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
        request["subject"].as_str().unwrap(),
        TEST_VTC_DID,
    )
    .unwrap();
    post(fix, &serde_json::to_value(doc).unwrap()).await
}

/// The whole loop: refused with the ceremony inline, the gesture recorded
/// against that grant, the identical document re-sent and accepted.
#[tokio::test]
async fn vti_apv_015_a_gesture_bound_to_the_grant_lets_the_same_document_through() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let subject = Party::new();

    let grant = signed(&admin, GRANT, grant_admin(&subject.did)).await;
    let (status, refusal) = post(&fix, &grant).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    let request = step_up_request(&refusal);
    assert_eq!(request["subject"], admin.did.as_str());
    assert!(
        get_acl_entry(&fix.vtc.state.acl_ks, &subject.did)
            .await
            .unwrap()
            .is_none(),
        "nothing is written before the gesture"
    );

    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);
    let (status, ack) = approve(&fix, &admin, &request, &cred).await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(
        ack["status"], "recorded",
        "a bound gesture elevates nothing"
    );
    assert_eq!(ack["boundTo"], request["boundTo"]);

    let (status, reply) = post(&fix, &grant).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["entry"]["subject"], subject.did.as_str());
    let written = get_acl_entry(&fix.vtc.state.acl_ks, &subject.did)
        .await
        .unwrap()
        .expect("the grant was written");
    assert_eq!(written.role, VtcRole::Moderator);
    assert_eq!(written.created_by, admin.did);
}

/// A gesture authorizes one payload. A grant to someone else — a different
/// digest — finds nothing, and is asked for a gesture of its own.
#[tokio::test]
async fn a_gesture_for_one_grant_does_not_authorize_another() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let intended = Party::new();
    let other = Party::new();

    let (_, refusal) = post(
        &fix,
        &signed(&admin, GRANT, grant_admin(&intended.did)).await,
    )
    .await;
    let request = step_up_request(&refusal);
    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);
    let (status, _) = approve(&fix, &admin, &request, &cred).await;
    assert_eq!(status, StatusCode::OK);

    let (status, refusal) = post(&fix, &signed(&admin, GRANT, grant_admin(&other.did)).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    step_up_request(&refusal);
    assert!(
        get_acl_entry(&fix.vtc.state.acl_ks, &other.did)
            .await
            .unwrap()
            .is_none()
    );
}

/// Spent by the grant it authorized. The same payload in a new document — a
/// fresh `id`, so not a redelivery — needs a new gesture.
#[tokio::test]
async fn a_gesture_is_spent_by_its_grant() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let subject = Party::new();

    let grant = signed(&admin, GRANT, grant_admin(&subject.did)).await;
    let (_, refusal) = post(&fix, &grant).await;
    let request = step_up_request(&refusal);
    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);
    approve(&fix, &admin, &request, &cred).await;
    let (status, _) = post(&fix, &grant).await;
    assert_eq!(status, StatusCode::OK);

    // Undo the grant so the second one is a conferral again, then ask twice.
    vtc_service::acl::delete_acl_entry(&fix.vtc.state.acl_ks, &subject.did)
        .await
        .unwrap();
    let again = signed(&admin, GRANT, grant_admin(&subject.did)).await;
    let (status, refusal) = post(&fix, &again).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    step_up_request(&refusal);
}

/// A challenge is answerable once: a second approve-response over it finds no
/// pending step-up.
#[tokio::test]
async fn a_challenge_is_answered_once() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let subject = Party::new();

    let (_, refusal) = post(
        &fix,
        &signed(&admin, GRANT, grant_admin(&subject.did)).await,
    )
    .await;
    let request = step_up_request(&refusal);
    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);
    let (status, _) = approve(&fix, &admin, &request, &cred).await;
    assert_eq!(status, StatusCode::OK);

    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);
    let (status, reply) = approve(&fix, &admin, &request, &cred).await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(
        reply["code"], "auth/step-up/approve-response:challengeUnknown",
        "{reply}"
    );
}

/// Possession of a signing key is not the second factor. An approve-response
/// with no webauthn evidence — gated only by its document proof, which a
/// console key could produce — records nothing.
#[tokio::test]
async fn a_signature_alone_cannot_record_a_gesture() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let subject = Party::new();

    let grant = signed(&admin, GRANT, grant_admin(&subject.did)).await;
    let (_, refusal) = post(&fix, &grant).await;
    let request = step_up_request(&refusal);

    let doc = signed(
        &admin,
        APPROVE_RESPONSE,
        json!({
            "subject": request["subject"],
            "challenge": request["challenge"],
            "decision": "approved",
        }),
    )
    .await;
    let (status, reply) = post(&fix, &doc).await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(
        reply["code"], "auth/step-up/approve-response:noGate",
        "{reply}"
    );

    let (status, _) = post(&fix, &grant).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no gesture was recorded");
}

/// A console key acts as its admin: it signs the grant and may redeem the
/// gesture, but the gesture is the admin's passkey — the key cannot supply it,
/// and its proof is never accepted on the answer (`auth/signing-key/enroll`
/// item 7). The console answers unsigned, with the passkey as the gate.
#[tokio::test]
async fn a_console_key_redeems_its_admins_gesture_but_cannot_make_one() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let console = Party::new();
    vtc_service::acl::console_key::enrol_delegation(
        &fix.vtc.state.console_keys_ks,
        &fix.vtc.state.acl_ks,
        &console.did,
        &admin.did,
        Some("test browser".into()),
        None,
    )
    .await
    .unwrap();
    let subject = Party::new();

    let grant = signed(&console, GRANT, grant_admin(&subject.did)).await;
    let (_, refusal) = post(&fix, &grant).await;
    let request = step_up_request(&refusal);
    assert_eq!(
        request["subject"],
        admin.did.as_str(),
        "the gesture is asked of the admin the key acts for"
    );

    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);
    let (status, refused) = approve(&fix, &console, &request, &cred).await;
    assert_ne!(status, StatusCode::OK, "{refused}");
    assert_eq!(refused["code"], "permissionDenied", "{refused}");

    // A fresh ceremony — the refused answer consumed nothing, but the
    // challenge is best asked again as the console would.
    let (_, refusal) = post(&fix, &grant).await;
    let request = step_up_request(&refusal);
    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);
    let (status, ack) = approve_unsigned(&fix, &request, &cred).await;
    assert_eq!(status, StatusCode::OK, "{ack}");

    let (status, reply) = post(&fix, &grant).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
}

/// A touch without user verification is one factor, and is refused.
#[tokio::test]
async fn a_silent_assertion_is_refused() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let subject = Party::new();

    let grant = signed(&admin, GRANT, grant_admin(&subject.did)).await;
    let (_, refusal) = post(&fix, &grant).await;
    let request = step_up_request(&refusal);
    let cred = fix
        .authenticator
        .authenticate_without_uv(&options(&request), RP_ORIGIN);
    let (status, reply) = approve(&fix, &admin, &request, &cred).await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(
        reply["code"], "auth/step-up/approve-response:assertionInvalid",
        "{reply}"
    );

    let (status, _) = post(&fix, &grant).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no gesture was recorded");
}

/// Only the acting admin's passkey counts. Another admin, present at the same
/// machine, cannot answer for them — even by pointing the ceremony at their
/// own credential.
#[tokio::test]
async fn another_admins_passkey_is_refused() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let colleague = admin_with_passkey(&mut fix).await;
    let subject = Party::new();

    let grant = signed(&admin, GRANT, grant_admin(&subject.did)).await;
    let (_, refusal) = post(&fix, &grant).await;
    let mut request = step_up_request(&refusal);
    let offered = request["webauthn"]["allowCredentials"].clone();
    assert_eq!(
        offered.as_array().map(Vec::len),
        Some(1),
        "only the admin's own credential is offered"
    );

    // The colleague's credential, substituted into the options.
    let (_, colleague_refusal) = post(
        &fix,
        &signed(&colleague, GRANT, grant_admin(&Party::new().did)).await,
    )
    .await;
    let colleague_request = step_up_request(&colleague_refusal);
    request["webauthn"]["allowCredentials"] =
        colleague_request["webauthn"]["allowCredentials"].clone();
    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);

    let (status, reply) = approve(&fix, &admin, &request, &cred).await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(
        reply["code"], "auth/step-up/approve-response:assertionInvalid",
        "{reply}"
    );
    let (status, _) = post(&fix, &grant).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The approve-response is the subject admin's own attestation: signed by
/// another admin, it is refused before the challenge is consulted, and the
/// admin can still answer it.
#[tokio::test]
async fn an_approve_response_signed_by_another_admin_is_refused() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let colleague = admin_with_passkey(&mut fix).await;
    let subject = Party::new();

    let grant = signed(&admin, GRANT, grant_admin(&subject.did)).await;
    let (_, refusal) = post(&fix, &grant).await;
    let request = step_up_request(&refusal);
    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);

    let (status, reply) = approve(&fix, &colleague, &request, &cred).await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(
        reply["code"], "auth/step-up/approve-response:subjectMismatch",
        "{reply}"
    );

    // The challenge was not spent by the refused document.
    let (status, ack) = approve(&fix, &admin, &request, &cred).await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    let (status, reply) = post(&fix, &grant).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
}

/// A grant that confers nothing new asks for no gesture — the console's label
/// edit, on this door as on the bearer route.
#[tokio::test]
async fn a_grant_that_confers_nothing_needs_no_gesture() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let colleague = Party::new();
    store_acl_entry(&fix.vtc.state.acl_ks, &row(&colleague.did, VtcRole::Admin))
        .await
        .unwrap();

    let relabel = json!({
        "entry": { "subject": colleague.did, "role": "admin", "scopes": [], "label": "ops" }
    });
    let (status, reply) = post(&fix, &signed(&admin, GRANT, relabel).await).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["entry"]["label"], "ops");
}

/// The step-up comes after every other check: a grant that would be refused
/// anyway is refused for its own reason, without asking anyone for a gesture.
#[tokio::test]
async fn a_refused_grant_never_asks_for_a_gesture() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let moderator = Party::new();
    store_acl_entry(
        &fix.vtc.state.acl_ks,
        &row(&moderator.did, VtcRole::Moderator),
    )
    .await
    .unwrap();

    // A role change dressed as a grant — refused as the wrong task, which is
    // what the caller needs to hear, not as a missing gesture.
    let (status, reply) = post(
        &fix,
        &signed(
            &admin,
            GRANT,
            json!({ "entry": { "subject": moderator.did, "role": "issuer" } }),
        )
        .await,
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{reply}");
    assert_ne!(reply["code"], "permissionDenied", "{reply}");
    assert!(
        reply["details"].get("stepUpRequest").is_none(),
        "a doomed grant must not ask for a passkey gesture: {reply}"
    );
}

// ─── acl/change-role ─────────────────────────────────────────────────────

/// A plain member, ready to promote — to `moderator`, so the promotion confers
/// administrative authority but nothing authority-conferring, and the gesture
/// is the whole gate. A promotion to `admin` confers `vtc.roles.assign`, which
/// also needs another holder's consent (VTI-APV-018).
async fn member(fix: &Fixture) -> Party {
    let party = Party::new();
    let entry = row(&party.did, VtcRole::Member);
    store_acl_entry(&fix.vtc.state.acl_ks, &entry)
        .await
        .unwrap();
    vtc_service::members::store_member(
        &fix.vtc.state.members_ks,
        &vtc_service::members::Member::fresh(&party.did),
    )
    .await
    .unwrap();
    party
}

fn promote(subject: &str) -> Value {
    json!({ "subject": subject, "fromRole": "member", "toRole": "moderator" })
}

/// The promotion loop on the signed door: refused with the ceremony inline,
/// the gesture recorded, the identical document re-sent and completed through
/// the role-change ceremony.
#[tokio::test]
async fn vti_apv_015_a_gesture_bound_to_the_promotion_lets_the_same_document_through() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let subject = member(&fix).await;

    let doc = signed(&admin, CHANGE_ROLE, promote(&subject.did)).await;
    let (status, refusal) = post(&fix, &doc).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    let request = step_up_request(&refusal);
    assert_eq!(
        get_acl_entry(&fix.vtc.state.acl_ks, &subject.did)
            .await
            .unwrap()
            .unwrap()
            .role,
        VtcRole::Member,
        "nothing moves before the gesture"
    );

    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);
    let (status, ack) = approve(&fix, &admin, &request, &cred).await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["status"], "recorded");

    let (status, reply) = post(&fix, &doc).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["entry"]["role"], "moderator", "{reply}");
    let entry = get_acl_entry(&fix.vtc.state.acl_ks, &subject.did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.role, VtcRole::Moderator);
    assert!(entry.is_administrator(), "the role carries what it implies");
    assert_eq!(entry.updated_by.as_deref(), Some(admin.did.as_str()));
}

/// A gesture for a grant does not promote: the digest covers the task's type,
/// so a promotion finds nothing for it.
#[tokio::test]
async fn a_gesture_for_a_grant_does_not_authorize_a_promotion() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let subject = member(&fix).await;

    let other = Party::new();
    let (_, refusal) = post(&fix, &signed(&admin, GRANT, grant_admin(&other.did)).await).await;
    let request = step_up_request(&refusal);
    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);
    let (status, _) = approve(&fix, &admin, &request, &cred).await;
    assert_eq!(status, StatusCode::OK);

    let doc = signed(&admin, CHANGE_ROLE, promote(&subject.did)).await;
    let (status, refusal) = post(&fix, &doc).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    step_up_request(&refusal);
}

/// A stale `fromRole` is the compare-and-swap conflict, on this door as on the
/// bearer route — and asks for nothing.
#[tokio::test]
async fn a_stale_from_role_is_a_conflict_not_a_gesture() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let subject = member(&fix).await;

    let stale = json!({ "subject": subject.did, "fromRole": "issuer", "toRole": "moderator" });
    let (status, reply) = post(&fix, &signed(&admin, CHANGE_ROLE, stale).await).await;
    assert_ne!(status, StatusCode::OK, "{reply}");
    // The task's own declared code for a compare-and-swap miss.
    assert_eq!(reply["code"], "acl/change-role:stateMismatch", "{reply}");
}

/// A demotion confers nothing, but it ends an administrator's authority — the
/// hole by which one admin could strip every other (VTI-APV-019). It takes a
/// gesture bound to it, and for an unrestricted subject the consent of an
/// admin who is neither party, before anything is written.
#[tokio::test]
async fn vti_apv_019_a_demotion_needs_a_gesture_and_a_third_party() {
    let mut fix = fixture().await;
    let third = admin_with_passkey(&mut fix).await;
    let colleague = admin_with_passkey(&mut fix).await;
    let actor = admin_with_passkey(&mut fix).await;
    vtc_service::members::store_member(
        &fix.vtc.state.members_ks,
        &vtc_service::members::Member::fresh(&colleague.did),
    )
    .await
    .unwrap();

    let demote = signed(
        &actor,
        CHANGE_ROLE,
        json!({ "subject": colleague.did, "fromRole": "admin", "toRole": "member" }),
    )
    .await;
    let (status, reply) = post(&fix, &demote).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    let request = step_up_request(&reply);
    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);
    let (status, ack) = approve(&fix, &actor, &request, &cred).await;
    assert_eq!(status, StatusCode::OK, "{ack}");

    // Parked for a third party, never the subject (VTI-APV-019); it runs on
    // that approval (VTI-APV-017).
    let (status, reply) = post(&fix, &demote).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{reply}");
    let action_id = reply["expects"][0]["hint"]["actionId"]
        .as_str()
        .expect("parked as an action")
        .to_string();
    let (_, shown) =
        crate::common::second_party::show_action(&fix.vtc, &colleague, &action_id).await;
    assert!(
        shown["payload"]["action"].get("challenge").is_none(),
        "the subject is not asked: {shown}"
    );
    let (status, ack) =
        crate::common::second_party::decide(&fix.vtc, &third, &action_id, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["payload"]["status"], "granted", "{ack}");
    assert_eq!(
        get_acl_entry(&fix.vtc.state.acl_ks, &colleague.did)
            .await
            .unwrap()
            .unwrap()
            .role,
        VtcRole::Member
    );
}

/// Changing roles is an administrator's act. A member's signature is refused
/// before anything else is looked at — including the member promoting
/// themselves.
#[tokio::test]
async fn a_non_admin_signer_cannot_change_roles() {
    let fix = fixture().await;
    let signer = member(&fix).await;
    let subject = member(&fix).await;

    for target in [&subject.did, &signer.did] {
        let doc = signed(&signer, CHANGE_ROLE, promote(target)).await;
        let (status, reply) = post(&fix, &doc).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
        assert!(reply["details"].get("stepUpRequest").is_none(), "{reply}");
    }
}

// ─── auth/signing-key/{enroll,list,revoke}/0.1 ──────────────────────────
//
// The console enrols its key with nothing but the key and a passkey: the
// enrolment is signed by the key (proof of possession), and control of the
// identity it names is a passkey gesture of that identity bound to that one
// document, answered unsigned from the requester's own browser.

const ENROLL: &str = "https://trusttasks.org/spec/auth/signing-key/enroll/0.1";
const KEY_LIST: &str = "https://trusttasks.org/spec/auth/signing-key/list/0.1";
const KEY_REVOKE: &str = "https://trusttasks.org/spec/auth/signing-key/revoke/0.1";
const ACL_LIST: &str = "https://trusttasks.org/spec/acl/list/0.1";

fn enrolment(key: &Party, identity: &str, label: &str) -> Value {
    json!({
        "signingKeyDid": key.did,
        "identityDid": identity,
        "scope": "console",
        "deviceLabel": label,
    })
}

/// Enrol `key` for `identity` end to end: refused with the ceremony, the
/// identity's passkey answers unsigned, the identical document goes through.
/// The reply's status and payload.
async fn enrol_with_gesture(fix: &mut Fixture, key: &Party, identity: &str) -> (StatusCode, Value) {
    let doc = signed(key, ENROLL, enrolment(key, identity, "Work laptop")).await;
    let (status, refusal) = post(fix, &doc).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    let request = step_up_request(&refusal);
    assert_eq!(request["subject"], identity, "{request}");
    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);
    let (status, ack) = approve_unsigned(fix, &request, &cred).await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["status"], "recorded", "{ack}");
    post(fix, &doc).await
}

#[tokio::test]
async fn a_signing_key_is_enrolled_by_the_identitys_bound_gesture() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let key = Party::new();

    let (status, reply) = enrol_with_gesture(&mut fix, &key, &admin.did).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let enrolled = &reply["signingKey"];
    assert_eq!(enrolled["signingKeyDid"], key.did.as_str());
    assert_eq!(enrolled["identityDid"], admin.did.as_str());
    assert_eq!(enrolled["scope"], "console");
    assert_eq!(enrolled["active"], true);
    // Always an expiry, and never more than 30 days out (item 6).
    let expires: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(enrolled["expiresAt"].clone()).unwrap();
    assert!(expires <= chrono::Utc::now() + chrono::Duration::days(30));

    // The key now signs as the admin, and lists the admin's keys.
    let (status, listed) = post(&fix, &signed(&key, ACL_LIST, json!({})).await).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let (_, keys) = post(&fix, &signed(&key, KEY_LIST, json!({})).await).await;
    assert_eq!(
        keys["signingKeys"][0]["signingKeyDid"],
        key.did.as_str(),
        "{keys}"
    );
}

/// A requested expiry past the ceiling is capped, not honoured.
#[tokio::test]
async fn a_requested_lifetime_is_capped() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let key = Party::new();
    let mut body = enrolment(&key, &admin.did, "Laptop");
    body["expiresAt"] = json!((chrono::Utc::now() + chrono::Duration::days(365)).to_rfc3339());
    let doc = signed(&key, ENROLL, body).await;
    let (_, refusal) = post(&fix, &doc).await;
    let request = step_up_request(&refusal);
    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);
    approve_unsigned(&fix, &request, &cred).await;
    let (status, reply) = post(&fix, &doc).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let expires: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(reply["signingKey"]["expiresAt"].clone()).unwrap();
    assert!(
        expires <= chrono::Utc::now() + chrono::Duration::days(30),
        "{reply}"
    );
}

/// The first answer is the same whoever the identity is (item 5, *not an
/// oracle*): an administrator and a DID the community has never heard of get
/// the same refusal offering the same credentials, and nothing is enrolled.
#[tokio::test]
async fn the_first_answer_does_not_depend_on_the_identitys_standing() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let key = Party::new();
    let other = Party::new();

    let (_, for_admin) = post(
        &fix,
        &signed(&key, ENROLL, enrolment(&key, &admin.did, "L")).await,
    )
    .await;
    let (_, for_nobody) = post(
        &fix,
        &signed(
            &other,
            ENROLL,
            enrolment(&other, "did:key:z6MkNobodyAtAll", "L"),
        )
        .await,
    )
    .await;
    let a = step_up_request(&for_admin);
    let b = step_up_request(&for_nobody);
    assert_eq!(
        a["webauthn"]["allowCredentials"],
        b["webauthn"]["allowCredentials"]
    );
    assert_eq!(for_admin["code"], for_nobody["code"]);

    // A gesture that could only come from the admin's passkey does not answer
    // for somebody else, so the stranger's enrolment never completes.
    let cred = fix.authenticator.authenticate(&options(&b), RP_ORIGIN);
    let (status, _) = approve_unsigned(&fix, &b, &cred).await;
    assert_ne!(status, StatusCode::OK);
}

/// The gesture binds the whole document (item 4): a changed label, or another
/// key, finds no gesture and is asked again.
#[tokio::test]
async fn a_gesture_for_one_enrolment_does_not_enrol_another() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let key = Party::new();
    let doc = signed(&key, ENROLL, enrolment(&key, &admin.did, "Work laptop")).await;
    let (_, refusal) = post(&fix, &doc).await;
    let request = step_up_request(&refusal);
    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);
    approve_unsigned(&fix, &request, &cred).await;

    let wider = signed(
        &key,
        ENROLL,
        enrolment(&key, &admin.did, "Somebody else's laptop"),
    )
    .await;
    let (status, refusal) = post(&fix, &wider).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    step_up_request(&refusal);
    let (status, reply) = post(&fix, &doc).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the original is still covered: {reply}"
    );
}

#[tokio::test]
async fn the_key_rules_are_refused_with_their_codes() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let key = Party::new();
    let code = |v: &Value| v["code"].as_str().unwrap_or_default().to_string();

    // Signed by a key other than the one named.
    let other = Party::new();
    let (_, r) = post(
        &fix,
        &signed(&other, ENROLL, enrolment(&key, &admin.did, "L")).await,
    )
    .await;
    assert_eq!(code(&r), "auth/signing-key/enroll:keyNotIssuer", "{r}");
    // The key as its own identity.
    let (_, r) = post(
        &fix,
        &signed(&key, ENROLL, enrolment(&key, &key.did, "L")).await,
    )
    .await;
    assert_eq!(code(&r), "auth/signing-key/enroll:selfDelegation", "{r}");
    // A key that holds standing of its own.
    let (_, r) = post(
        &fix,
        &signed(&admin, ENROLL, enrolment(&admin, "did:key:z6MkX", "L")).await,
    )
    .await;
    assert_eq!(code(&r), "auth/signing-key/enroll:keyHoldsStanding", "{r}");
    // An expiry already past.
    let mut past = enrolment(&key, &admin.did, "L");
    past["expiresAt"] = json!("2020-01-01T00:00:00Z");
    let (_, r) = post(&fix, &signed(&key, ENROLL, past).await).await;
    assert_eq!(code(&r), "auth/signing-key/enroll:expiryInPast", "{r}");

    // Enrolled, then enrolled again, then revoked and enrolled again.
    let (status, _) = enrol_with_gesture(&mut fix, &key, &admin.did).await;
    assert_eq!(status, StatusCode::OK);
    let (_, r) = post(
        &fix,
        &signed(&key, ENROLL, enrolment(&key, &admin.did, "Again")).await,
    )
    .await;
    assert_eq!(code(&r), "auth/signing-key/enroll:alreadyEnrolled", "{r}");
    let (status, _) = post(
        &fix,
        &signed(&key, KEY_REVOKE, json!({ "signingKeyDid": key.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, r) = post(
        &fix,
        &signed(&key, ENROLL, enrolment(&key, &admin.did, "Again")).await,
    )
    .await;
    assert_eq!(code(&r), "auth/signing-key/enroll:keyRevoked", "{r}");
}

/// An identity holds at most five active keys (item 8).
#[tokio::test]
async fn an_identity_holds_a_bounded_number_of_keys() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    for _ in 0..vtc_service::acl::console_key::MAX_ACTIVE_PER_IDENTITY {
        vtc_service::acl::console_key::enrol_delegation(
            &fix.vtc.state.console_keys_ks,
            &fix.vtc.state.acl_ks,
            &Party::new().did,
            &admin.did,
            None,
            None,
        )
        .await
        .unwrap();
    }
    let (_, reply) = enrol_with_gesture(&mut fix, &Party::new(), &admin.did).await;
    assert_eq!(
        reply["code"], "auth/signing-key/enroll:tooManyKeys",
        "{reply}"
    );
    assert_eq!(
        reply["details"]["maxActiveKeys"],
        vtc_service::acl::console_key::MAX_ACTIVE_PER_IDENTITY
    );
    // 0.1's `details` schema holds one member; the list is 0.2's.
    assert!(reply["details"].get("activeKeys").is_none(), "{reply}");
}

// ─── auth/signing-key/enroll/0.2 ────────────────────────────────────────
//
// 0.2 adds the identity's own signed authorization (a VTA-wallet sign-in has
// the identity's key and no passkey here) and `replaces` at the cap.

const ENROLL_V0_2: &str = "https://trusttasks.org/spec/auth/signing-key/enroll/0.2";
const AUTHORIZE: &str = "https://trusttasks.org/spec/auth/signing-key/authorize/0.1";

/// An administrator with no passkey — signs in with their own key.
async fn admin_without_passkey(fix: &Fixture) -> Party {
    let party = Party::new();
    store_acl_entry(&fix.vtc.state.acl_ks, &row(&party.did, VtcRole::Admin))
        .await
        .unwrap();
    party
}

/// An `enroll/0.2` by `key` on `terms`, carrying `by`'s signed authorization
/// of exactly those terms.
async fn authorized_enrolment(key: &Party, by: &Party, terms: Value) -> Value {
    let mut payload = terms.clone();
    payload["authorization"] = signed(by, AUTHORIZE, terms).await;
    signed(key, ENROLL_V0_2, payload).await
}

/// VTI-SPEC auth/signing-key/enroll/0.2 item 13: the identity's own signature
/// over the terms is the evidence; no step-up is asked for.
#[tokio::test]
async fn an_identity_signed_authorization_enrols_without_a_gesture() {
    let fix = fixture().await;
    let admin = admin_without_passkey(&fix).await;
    let key = Party::new();
    let doc = authorized_enrolment(&key, &admin, enrolment(&key, &admin.did, "Wallet")).await;
    let (status, reply) = post(&fix, &doc).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["signingKey"]["signingKeyDid"], key.did.as_str());
    assert_eq!(reply["signingKey"]["identityDid"], admin.did.as_str());
    assert_eq!(reply["signingKey"]["active"], true);
    // And it signs as the admin.
    let (status, listed) = post(&fix, &signed(&key, ACL_LIST, json!({})).await).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
}

/// Item 13: the authorization covers exactly these terms. Anything else —
/// another label, another signer — is `authorizationInvalid`, never a fallback
/// to the step-up.
#[tokio::test]
async fn an_authorization_for_other_terms_or_by_another_party_is_refused() {
    let fix = fixture().await;
    let admin = admin_without_passkey(&fix).await;
    let key = Party::new();
    let code = |v: &Value| v["code"].as_str().unwrap_or_default().to_string();

    // Signed for one label, enrolling another.
    let mut payload = enrolment(&key, &admin.did, "Somebody else's laptop");
    payload["authorization"] =
        signed(&admin, AUTHORIZE, enrolment(&key, &admin.did, "Wallet")).await;
    let (_, r) = post(&fix, &signed(&key, ENROLL_V0_2, payload).await).await;
    assert_eq!(
        code(&r),
        "auth/signing-key/enroll:authorizationInvalid",
        "{r}"
    );

    // The right terms, signed by somebody who is not the identity.
    let stranger = Party::new();
    let doc = authorized_enrolment(&key, &stranger, enrolment(&key, &admin.did, "Wallet")).await;
    let (_, r) = post(&fix, &doc).await;
    assert_eq!(
        code(&r),
        "auth/signing-key/enroll:authorizationInvalid",
        "{r}"
    );

    // A signature that does not verify.
    let mut payload = enrolment(&key, &admin.did, "Wallet");
    let mut inner = signed(&admin, AUTHORIZE, payload.clone()).await;
    inner["proof"]["proofValue"] = json!(
        "z3FXQjecWufY46yg5abdVZsXqLhxhueuSoZgNSARiKBk9czhSePTFehP8c3PGfb6a22gkfUKY5MKk7XYKKDpq4m"
    );
    payload["authorization"] = inner;
    let (_, r) = post(&fix, &signed(&key, ENROLL_V0_2, payload).await).await;
    assert_eq!(
        code(&r),
        "auth/signing-key/enroll:authorizationInvalid",
        "{r}"
    );

    // Nothing was enrolled by any of them.
    assert!(
        vtc_service::acl::console_key::get_delegation(&fix.vtc.state.console_keys_ks, &key.did)
            .await
            .unwrap()
            .is_none()
    );
}

/// Items 8 and 14: at the cap, once the evidence is accepted, the refusal
/// lists the identity's active keys, and an enrolment naming one in
/// `replaces` swaps it out — the count stays at the cap.
#[tokio::test]
async fn at_the_cap_an_enrolment_can_replace_a_listed_key() {
    use vtc_service::acl::console_key::{MAX_ACTIVE_PER_IDENTITY, active_count, get_delegation};
    let fix = fixture().await;
    let admin = admin_without_passkey(&fix).await;
    for _ in 0..MAX_ACTIVE_PER_IDENTITY {
        delegated_key(&fix, &admin.did).await;
    }
    let key = Party::new();
    let (_, refusal) = post(
        &fix,
        &authorized_enrolment(&key, &admin, enrolment(&key, &admin.did, "New")).await,
    )
    .await;
    assert_eq!(
        refusal["code"], "auth/signing-key/enroll:tooManyKeys",
        "{refusal}"
    );
    let listed = refusal["details"]["activeKeys"]
        .as_array()
        .expect("{refusal}");
    assert_eq!(listed.len(), MAX_ACTIVE_PER_IDENTITY, "{refusal}");
    let old = listed[0]["signingKeyDid"].as_str().unwrap().to_string();

    // A new payload, so a new authorization (item 15).
    let mut terms = enrolment(&key, &admin.did, "New");
    terms["replaces"] = json!(old);
    let (status, reply) = post(&fix, &authorized_enrolment(&key, &admin, terms).await).await;
    assert_eq!(status, StatusCode::OK, "{reply}");

    let ks = &fix.vtc.state.console_keys_ks;
    let replaced = get_delegation(ks, &old).await.unwrap().unwrap();
    assert!(replaced.revoked_at.is_some(), "the replaced key is revoked");
    assert_eq!(
        active_count(ks, &admin.did, chrono::Utc::now())
            .await
            .unwrap(),
        MAX_ACTIVE_PER_IDENTITY
    );
}

/// Item 8: before the evidence is accepted, nobody learns an identity's keys —
/// a step-up-path enrolment at the cap is asked for its gesture, not shown
/// the list.
#[tokio::test]
async fn the_active_keys_are_not_listed_before_the_evidence() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    for _ in 0..vtc_service::acl::console_key::MAX_ACTIVE_PER_IDENTITY {
        delegated_key(&fix, &admin.did).await;
    }
    let key = Party::new();
    let (status, refusal) = post(
        &fix,
        &signed(&key, ENROLL_V0_2, enrolment(&key, &admin.did, "New")).await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    step_up_request(&refusal);
    assert!(refusal["details"].get("activeKeys").is_none(), "{refusal}");
}

/// Item 14: `replaces` must name an active key of this identity. Another
/// identity's key gets the same answer as one that does not exist.
#[tokio::test]
async fn replacing_a_key_that_is_not_the_identitys_is_refused() {
    let fix = fixture().await;
    let admin = admin_without_passkey(&fix).await;
    let other_admin = admin_without_passkey(&fix).await;
    let theirs = delegated_key(&fix, &other_admin.did).await;
    let code = |v: &Value| v["code"].as_str().unwrap_or_default().to_string();

    for target in [theirs.did.clone(), Party::new().did] {
        let key = Party::new();
        let mut terms = enrolment(&key, &admin.did, "New");
        terms["replaces"] = json!(target);
        let (_, r) = post(&fix, &authorized_enrolment(&key, &admin, terms).await).await;
        assert_eq!(code(&r), "auth/signing-key/enroll:replaceNotFound", "{r}");
    }
    let still =
        vtc_service::acl::console_key::get_delegation(&fix.vtc.state.console_keys_ks, &theirs.did)
            .await
            .unwrap()
            .unwrap();
    assert!(
        still.revoked_at.is_none(),
        "another identity's key is untouched"
    );
}

/// A delegation of a fresh key to `admin`, written directly.
async fn delegated_key(fix: &Fixture, admin: &str) -> Party {
    let key = Party::new();
    vtc_service::acl::console_key::enrol_delegation(
        &fix.vtc.state.console_keys_ks,
        &fix.vtc.state.acl_ks,
        &key.did,
        admin,
        None,
        None,
    )
    .await
    .unwrap();
    key
}

async fn revoke(by: &Party, key: &Party) -> Value {
    signed(by, KEY_REVOKE, json!({ "signingKeyDid": key.did })).await
}

/// Revoked by the key itself or its identity; a context-scoped admin cannot
/// disarm a peer's key and is told `notFound`; an unrestricted admin can; a
/// second revocation changes nothing.
#[tokio::test]
async fn a_key_is_revoked_by_itself_its_identity_or_an_unrestricted_admin() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let own = delegated_key(&fix, &admin.did).await;
    let (status, reply) = post(&fix, &revoke(&own, &own).await).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let first = reply["revokedAt"].clone();
    let (_, again) = post(&fix, &revoke(&admin, &own).await).await;
    assert_eq!(
        again["revokedAt"], first,
        "a second revocation changes nothing"
    );

    let peer_key = delegated_key(&fix, &admin.did).await;
    let scoped = Party::new();
    store_acl_entry(
        &fix.vtc.state.acl_ks,
        &VtcAclEntry {
            admin: vtc_service::acl::legacy_seed_authority(&VtcRole::Admin, &["ctx-a"]),
            ..row(&scoped.did, VtcRole::Admin)
        },
    )
    .await
    .unwrap();
    let (_, reply) = post(&fix, &revoke(&scoped, &peer_key).await).await;
    assert_eq!(reply["code"], "auth/signing-key/revoke:notFound", "{reply}");
    let root = Party::new();
    store_acl_entry(&fix.vtc.state.acl_ks, &row(&root.did, VtcRole::Admin))
        .await
        .unwrap();
    let (status, reply) = post(&fix, &revoke(&root, &peer_key).await).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["remainingActive"], 0);

    // A revoked key authorizes nothing.
    let (status, _) = post(&fix, &signed(&peer_key, ACL_LIST, json!({})).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A key's list is its identity's, and a signer speaking for nobody is refused.
#[tokio::test]
async fn a_list_is_the_signers_identitys_own() {
    let mut fix = fixture().await;
    let admin = admin_with_passkey(&mut fix).await;
    let (_, empty) = post(&fix, &signed(&admin, KEY_LIST, json!({})).await).await;
    assert_eq!(empty["signingKeys"], json!([]), "{empty}");
    let (status, _) = post(&fix, &signed(&Party::new(), KEY_LIST, json!({})).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_console_keys_bearer_routes_are_gone() {
    let fix = fixture().await;
    for (method, path) in [
        ("GET", "/v1/admin/console-keys"),
        ("POST", "/v1/admin/console-keys"),
        ("DELETE", "/v1/admin/console-keys/did:key:z6MkGone"),
    ] {
        assert!(
            !crate::common::signed::bearer_route_served(&fix.vtc, method, path).await,
            "{method} {path}"
        );
    }
}
