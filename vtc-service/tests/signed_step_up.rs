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

mod common;

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

use common::webauthn_harness::SoftEd25519Authenticator;

const RP_ORIGIN: &str = "https://vtc.example.com";
const GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
const APPROVE_RESPONSE: &str = "https://trusttasks.org/spec/auth/step-up/approve-response/0.4";

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

fn grant_admin(subject: &str) -> Value {
    json!({ "entry": { "subject": subject, "role": "admin", "scopes": [] } })
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
    assert_eq!(written.role, VtcRole::Admin);
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
/// gesture, but the gesture is the admin's passkey — the key cannot supply it.
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
    let (status, ack) = approve(&fix, &console, &request, &cred).await;
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
        &signed(&admin, GRANT, grant_admin(&moderator.did)).await,
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{reply}");
    assert_ne!(reply["code"], "permissionDenied", "{reply}");
    assert!(
        reply["details"].get("stepUpRequest").is_none(),
        "a doomed grant must not ask for a passkey gesture: {reply}"
    );
}
