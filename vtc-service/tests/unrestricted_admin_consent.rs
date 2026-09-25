//! Second-party consent for unrestricted admin authority — **VTI-APV-014**.
//!
//! Creating an unrestricted admin, or widening an entry to unrestricted, needs
//! another unrestricted admin's consent as well as the requester's own passkey
//! gesture. These drive both doors end to end: the gesture, the
//! `auth:consent_required` refusal with its VTC-signed requests, another
//! admin's `task-consent/decision/0.1`, and the identical operation re-sent.
//! Design: `docs/05-design-notes/vtc-operation-bound-step-up.md` §4.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::auth::passkey::build_webauthn;
use vti_common::auth::passkey::store::{PasskeyUser, store_credential_mapping, store_passkey_user};
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};
use vti_rooms_dtg::test_support::Party;
use webauthn_rs::prelude::{PublicKeyCredential, RequestChallengeResponse};

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

use common::webauthn_harness::SoftEd25519Authenticator;

const RP_ORIGIN: &str = "https://vtc.example.com";
const GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
const CHANGE_ROLE: &str = "https://trusttasks.org/spec/acl/change-role/0.1";
const APPROVE_RESPONSE: &str = "https://trusttasks.org/spec/auth/step-up/approve-response/0.4";
const DECISION: &str = "https://trusttasks.org/spec/task-consent/decision/0.1";
const REQUEST: &str = "https://trusttasks.org/spec/task-consent/request/0.1";
const THRESHOLD_KEY: &str = "acl.unrestricted_admin_consent_threshold";

struct Fixture {
    vtc: TestVtc,
    authenticator: SoftEd25519Authenticator,
}

async fn fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .with_public_url(RP_ORIGIN)
        .with_signers(true)
        .with_audit(true)
        .build()
        .await;
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

fn row(did: &str, role: VtcRole, scopes: &[&str]) -> VtcAclEntry {
    VtcAclEntry {
        did: did.to_string(),
        role,
        label: None,
        allowed_contexts: scopes.iter().map(|s| s.to_string()).collect(),
        created_at: 0,
        created_by: "did:key:vtc-install".into(),
        updated_at: None,
        updated_by: None,
        expires_at: None,
    }
}

/// An unrestricted admin who signs with `Party`'s key and holds a passkey.
async fn admin_with_passkey(fix: &mut Fixture) -> Party {
    let party = admin(fix).await;
    enrol_passkey(fix, &party.did).await;
    party
}

/// An unrestricted admin with no passkey — enough to consent, which is a
/// signed decision.
async fn admin(fix: &Fixture) -> Party {
    let party = Party::new();
    store_acl_entry(&fix.vtc.state.acl_ks, &row(&party.did, VtcRole::Admin, &[]))
        .await
        .unwrap();
    party
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

fn grant_unrestricted(subject: &str) -> Value {
    json!({ "entry": { "subject": subject, "role": "admin", "scopes": [] } })
}

fn options(request: &Value) -> RequestChallengeResponse {
    let mut inner = request["webauthn"].clone();
    inner["timeout"] = inner.get("timeout").cloned().unwrap_or(json!(60000));
    serde_json::from_value(json!({ "publicKey": inner })).expect("options re-wrap")
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
        "id": v["id"],
        "rawId": v["rawId"],
        "type": "public-key",
        "response": response,
        "clientExtensionResults": {},
    })
}

/// Answer the step-up refusal `refusal` with the requester's passkey.
async fn make_gesture(fix: &mut Fixture, requester: &Party, refusal: &Value) {
    assert_eq!(refusal["code"], "permissionDenied", "{refusal}");
    let request = refusal["details"]["stepUpRequest"].clone();
    assert!(request.is_object(), "expected a step-up request: {refusal}");
    let cred = fix
        .authenticator
        .authenticate(&options(&request), RP_ORIGIN);
    let doc = signed(
        requester,
        APPROVE_RESPONSE,
        json!({
            "subject": request["subject"],
            "challenge": request["challenge"],
            "decision": "approved",
            "evidence": { "kind": "webauthn", "assertion": assertion(&cred) },
        }),
    )
    .await;
    let (status, ack) = post(fix, &doc).await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["status"], "recorded", "{ack}");
}

/// The consent refusal, checked for the shape the VTA's gate gives it.
fn consent_required(refusal: &Value) -> Value {
    assert_eq!(refusal["code"], "taskFailed", "{refusal}");
    let details = refusal["details"].clone();
    assert_eq!(details["reason"], "auth:consent_required", "{refusal}");
    assert_eq!(details["approverSet"], "unrestricted-admins");
    assert_eq!(details["excludeRequester"], true);
    assert!(
        details["payloadDigest"]
            .as_str()
            .is_some_and(|d| d.starts_with('z'))
    );
    assert!(details["challenge"].is_string());
    details
}

async fn decide(
    fix: &Fixture,
    approver: &Party,
    details: &Value,
    decision: &str,
) -> (StatusCode, Value) {
    let doc = signed(
        approver,
        DECISION,
        json!({
            "challenge": details["challenge"],
            "payloadDigest": details["payloadDigest"],
            "decision": decision,
        }),
    )
    .await;
    post(fix, &doc).await
}

async fn entry(fix: &Fixture, did: &str) -> Option<VtcAclEntry> {
    get_acl_entry(&fix.vtc.state.acl_ks, did).await.unwrap()
}

/// The whole loop on the signed door: the requester's gesture, then another
/// admin's consent, then the identical document goes through. Nothing is
/// written before both, and the consent refusal does not cost the gesture.
#[tokio::test]
async fn vti_apv_014_an_unrestricted_grant_needs_another_admins_consent() {
    let mut fix = fixture().await;
    let requester = admin_with_passkey(&mut fix).await;
    let approver = admin(&fix).await;
    let subject = Party::new();

    let grant = signed(&requester, GRANT, grant_unrestricted(&subject.did)).await;

    // 1. The gesture first — nobody else has been asked yet.
    let (status, refusal) = post(&fix, &grant).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    make_gesture(&mut fix, &requester, &refusal).await;

    // 2. Then the consent.
    let (status, refusal) = post(&fix, &grant).await;
    assert_eq!(status.as_u16() / 100, 4, "{refusal}");
    let details = consent_required(&refusal);
    assert_eq!(details["minApprovals"], 1);
    assert!(
        entry(&fix, &subject.did).await.is_none(),
        "nothing written yet"
    );

    // The request relayed to the approver: VTC-signed, addressed to them, and
    // never to the requester.
    let requests = details["consentRequests"].as_array().expect("relay copies");
    assert_eq!(requests.len(), 1, "one request per approver: {requests:?}");
    let req = &requests[0];
    assert_eq!(req["type"], REQUEST);
    assert_eq!(req["issuer"], TEST_VTC_DID);
    assert_eq!(req["recipient"], approver.did.as_str());
    assert!(req["proof"].is_object(), "the request is signed");
    assert_eq!(req["payload"]["payloadDigest"], details["payloadDigest"]);
    assert_eq!(req["payload"]["subject"], subject.did.as_str());
    assert_eq!(req["payload"]["requester"], requester.did.as_str());

    // Asking again re-finds the same request; it does not raise a new one.
    let (_, again) = post(&fix, &grant).await;
    assert_eq!(consent_required(&again)["challenge"], details["challenge"]);

    // 3. Another admin approves.
    let (status, ack) = decide(&fix, &approver, &details, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["status"], "granted", "{ack}");
    assert_eq!(ack["payloadDigest"], details["payloadDigest"]);

    // 4. The identical document goes through, on the gesture made in step 1.
    let (status, reply) = post(&fix, &grant).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let written = entry(&fix, &subject.did)
        .await
        .expect("the grant was written");
    assert_eq!(written.role, VtcRole::Admin);
    assert!(written.is_super_admin());

    // The consent is spent: with the entry gone again, the same grant in a
    // fresh document is asked for consent again.
    vtc_service::acl::delete_acl_entry(&fix.vtc.state.acl_ks, &subject.did)
        .await
        .unwrap();
    let fresh = signed(&requester, GRANT, grant_unrestricted(&subject.did)).await;
    let (_, refusal) = post(&fix, &fresh).await;
    make_gesture(&mut fix, &requester, &refusal).await;
    let (_, refusal) = post(&fix, &fresh).await;
    consent_required(&refusal);
}

/// VTI-APV-007: the requester never counts.
#[tokio::test]
async fn vti_apv_007_the_requester_cannot_consent_to_their_own_grant() {
    let mut fix = fixture().await;
    let requester = admin_with_passkey(&mut fix).await;
    let _approver = admin(&fix).await;
    let subject = Party::new();

    let grant = signed(&requester, GRANT, grant_unrestricted(&subject.did)).await;
    let (_, refusal) = post(&fix, &grant).await;
    make_gesture(&mut fix, &requester, &refusal).await;
    let (_, refusal) = post(&fix, &grant).await;
    let details = consent_required(&refusal);

    let (status, reply) = decide(&fix, &requester, &details, "approve").await;
    assert_ne!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        reply["code"], "task-consent/decision:requesterExcluded",
        "{reply}"
    );
    assert!(entry(&fix, &subject.did).await.is_none());
}

/// VTI-APV-006: approving an unrestricted entry takes unrestricted authority. A
/// scoped admin and a member are refused.
#[tokio::test]
async fn vti_apv_006_only_an_unrestricted_admin_can_consent() {
    let mut fix = fixture().await;
    let requester = admin_with_passkey(&mut fix).await;
    let _approver = admin(&fix).await;
    let scoped = Party::new();
    store_acl_entry(
        &fix.vtc.state.acl_ks,
        &row(&scoped.did, VtcRole::Admin, &["ctx-a"]),
    )
    .await
    .unwrap();
    let member = Party::new();
    store_acl_entry(
        &fix.vtc.state.acl_ks,
        &row(&member.did, VtcRole::Member, &[]),
    )
    .await
    .unwrap();
    let subject = Party::new();

    let grant = signed(&requester, GRANT, grant_unrestricted(&subject.did)).await;
    let (_, refusal) = post(&fix, &grant).await;
    make_gesture(&mut fix, &requester, &refusal).await;
    let (_, refusal) = post(&fix, &grant).await;
    let details = consent_required(&refusal);

    // A scoped admin reaches the decision and is told it is not an approver.
    let (status, reply) = decide(&fix, &scoped, &details, "approve").await;
    assert_ne!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        reply["code"], "task-consent/decision:notAnApprover",
        "{reply}"
    );
    // A member never gets that far: the signed admin door refuses a signer who
    // may not act there, as it does for every admin verb.
    let (status, reply) = decide(&fix, &member, &details, "approve").await;
    assert_ne!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["code"], "permissionDenied", "{reply}");

    // Neither counted: the requester still has no consent.
    let (_, refusal) = post(&fix, &grant).await;
    consent_required(&refusal);
    assert!(entry(&fix, &subject.did).await.is_none());
}

/// A declined consent is gone. The next ask raises a new request with a new
/// challenge, and the old one cannot be approved.
#[tokio::test]
async fn a_declined_consent_is_not_redeemable() {
    let mut fix = fixture().await;
    let requester = admin_with_passkey(&mut fix).await;
    let approver = admin(&fix).await;
    let subject = Party::new();

    let grant = signed(&requester, GRANT, grant_unrestricted(&subject.did)).await;
    let (_, refusal) = post(&fix, &grant).await;
    make_gesture(&mut fix, &requester, &refusal).await;
    let (_, refusal) = post(&fix, &grant).await;
    let first = consent_required(&refusal);

    let (status, ack) = decide(&fix, &approver, &first, "deny").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["status"], "denied");

    let (_, refusal) = post(&fix, &grant).await;
    let second = consent_required(&refusal);
    assert_ne!(second["challenge"], first["challenge"], "a new request");

    let (status, reply) = decide(&fix, &approver, &first, "approve").await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(reply["code"], "task-consent/decision:noPending", "{reply}");
    assert!(entry(&fix, &subject.did).await.is_none());
}

/// VTI-APV-004: a consent binds one payload. Consent to one grant does not
/// authorize a grant to someone else.
#[tokio::test]
async fn vti_apv_004_consent_to_one_grant_does_not_authorize_another() {
    let mut fix = fixture().await;
    let requester = admin_with_passkey(&mut fix).await;
    let approver = admin(&fix).await;
    let intended = Party::new();
    let other = Party::new();

    let grant = signed(&requester, GRANT, grant_unrestricted(&intended.did)).await;
    let (_, refusal) = post(&fix, &grant).await;
    make_gesture(&mut fix, &requester, &refusal).await;
    let (_, refusal) = post(&fix, &grant).await;
    let details = consent_required(&refusal);
    let (status, _) = decide(&fix, &approver, &details, "approve").await;
    assert_eq!(status, StatusCode::OK);

    let wrong = signed(&requester, GRANT, grant_unrestricted(&other.did)).await;
    let (_, refusal) = post(&fix, &wrong).await;
    make_gesture(&mut fix, &requester, &refusal).await;
    let (_, refusal) = post(&fix, &wrong).await;
    let other_details = consent_required(&refusal);
    assert_ne!(other_details["payloadDigest"], details["payloadDigest"]);
    assert!(entry(&fix, &other.did).await.is_none());
}

/// A community with one unrestricted admin has nobody to consent. It is told
/// how to add one, and it is told before being asked for a gesture it could
/// not use.
#[tokio::test]
async fn a_sole_admin_is_told_how_to_add_a_second_before_any_gesture() {
    let mut fix = fixture().await;
    let requester = admin_with_passkey(&mut fix).await;
    let subject = Party::new();

    let grant = signed(&requester, GRANT, grant_unrestricted(&subject.did)).await;
    let (status, refusal) = post(&fix, &grant).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    assert!(
        refusal["details"].get("stepUpRequest").is_none(),
        "no gesture for an act that cannot be consented to: {refusal}"
    );
    let message = refusal["message"].as_str().unwrap_or_default();
    assert!(message.contains("vtc acl add"), "names the fix: {message}");
    assert!(message.contains("VTI-APV-014"), "{message}");
}

/// A scoped admin grant is a conferral, not an unrestricted one: it takes the
/// gesture and nothing else.
#[tokio::test]
async fn a_scoped_admin_grant_needs_no_consent() {
    let mut fix = fixture().await;
    let requester = admin_with_passkey(&mut fix).await;
    let subject = Party::new();

    let grant = signed(
        &requester,
        GRANT,
        json!({ "entry": { "subject": subject.did, "role": "admin", "scopes": ["ctx-a"] } }),
    )
    .await;
    let (_, refusal) = post(&fix, &grant).await;
    make_gesture(&mut fix, &requester, &refusal).await;
    let (status, reply) = post(&fix, &grant).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(!entry(&fix, &subject.did).await.unwrap().is_super_admin());
}

/// A consent is judged against the community when it is spent. An approver who
/// has since lost unrestricted authority no longer counts, and the requester
/// is asked again.
#[tokio::test]
async fn a_consent_lapses_when_its_approver_loses_authority() {
    let mut fix = fixture().await;
    let requester = admin_with_passkey(&mut fix).await;
    let approver = admin(&fix).await;
    let _third = admin(&fix).await;
    let subject = Party::new();

    let grant = signed(&requester, GRANT, grant_unrestricted(&subject.did)).await;
    let (_, refusal) = post(&fix, &grant).await;
    make_gesture(&mut fix, &requester, &refusal).await;
    let (_, refusal) = post(&fix, &grant).await;
    let details = consent_required(&refusal);
    let (status, _) = decide(&fix, &approver, &details, "approve").await;
    assert_eq!(status, StatusCode::OK);

    store_acl_entry(
        &fix.vtc.state.acl_ks,
        &row(&approver.did, VtcRole::Admin, &["ctx-a"]),
    )
    .await
    .unwrap();

    let (_, refusal) = post(&fix, &grant).await;
    let again = consent_required(&refusal);
    assert_ne!(again["challenge"], details["challenge"], "asked again");
    assert!(entry(&fix, &subject.did).await.is_none());
}

/// `acl/change-role` promoting a scopeless member lands an unrestricted admin,
/// so it takes the same two things.
#[tokio::test]
async fn vti_apv_014_promoting_a_scopeless_member_needs_consent() {
    let mut fix = fixture().await;
    let requester = admin_with_passkey(&mut fix).await;
    let approver = admin(&fix).await;
    let member = Party::new();
    store_acl_entry(
        &fix.vtc.state.acl_ks,
        &row(&member.did, VtcRole::Member, &[]),
    )
    .await
    .unwrap();

    let promote = signed(
        &requester,
        CHANGE_ROLE,
        json!({ "subject": member.did, "fromRole": "member", "toRole": "admin" }),
    )
    .await;
    let (_, refusal) = post(&fix, &promote).await;
    make_gesture(&mut fix, &requester, &refusal).await;
    let (_, refusal) = post(&fix, &promote).await;
    let details = consent_required(&refusal);
    assert_eq!(
        entry(&fix, &member.did).await.unwrap().role,
        VtcRole::Member
    );

    let (status, _) = decide(&fix, &approver, &details, "approve").await;
    assert_eq!(status, StatusCode::OK);
    let (status, reply) = post(&fix, &promote).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(entry(&fix, &member.did).await.unwrap().is_super_admin());
}

/// An admin bearer whose session carries a live step-up.
async fn stepped_up_token(fix: &Fixture, did: &str) -> String {
    let session_id = format!("stepped-up-{}", Uuid::new_v4());
    store_session(
        &fix.vtc.state.sessions_ks,
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
            amr: vec!["passkey".into()],
            acr: "aal2".into(),
            acr_expires_at: Some(now_epoch() + 600),
            token_id: None,
            session_pubkey_b58btc: None,
        },
    )
    .await
    .unwrap();
    let claims = fix
        .vtc
        .jwt_keys
        .new_claims(did.into(), session_id, "admin".into(), vec![], 900, false)
        .with_aal(vec!["passkey".into()], "aal2");
    fix.vtc.jwt_keys.encode(&claims).unwrap()
}

async fn bearer(
    fix: &Fixture,
    method: &str,
    uri: &str,
    task: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("Trust-Task", task)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = fix.vtc.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// VTI-APV-002: the bearer route reaches the same decision. A stepped-up
/// session is not enough; another admin's consent is.
#[tokio::test]
async fn vti_apv_002_the_bearer_route_needs_consent_too() {
    let fix = fixture().await;
    let requester = admin(&fix).await;
    let approver = admin(&fix).await;
    let subject = Party::new();
    let token = stepped_up_token(&fix, &requester.did).await;
    let body = grant_unrestricted(&subject.did);

    let (status, refusal) = bearer(&fix, "POST", "/v1/acl", GRANT, &token, body.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    assert_eq!(refusal["error"], "auth:consent_required", "{refusal}");
    assert!(entry(&fix, &subject.did).await.is_none());

    let (status, ack) = decide(&fix, &approver, &refusal, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");

    let (status, reply) = bearer(&fix, "POST", "/v1/acl", GRANT, &token, body).await;
    assert_eq!(status, StatusCode::CREATED, "{reply}");
    assert!(entry(&fix, &subject.did).await.unwrap().is_super_admin());
}

async fn patch_threshold(fix: &Fixture, token: &str, n: u64) -> Value {
    let (status, reply) = bearer(
        fix,
        "PATCH",
        "/v1/admin/config",
        "https://trusttasks.org/spec/config/patch/0.1",
        token,
        json!({ "overrides": { THRESHOLD_KEY: n } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    reply
}

/// VTI-APV-009: a threshold the community cannot meet is refused when it is
/// written. One it can meet binds the next grant straight away, without a
/// reload.
#[tokio::test]
async fn vti_apv_009_an_unmeetable_threshold_is_refused_when_written() {
    let fix = fixture().await;
    let requester = admin(&fix).await;
    let first = admin(&fix).await;
    let token = stepped_up_token(&fix, &requester.did).await;

    // Two unrestricted admins: at most one can approve anyone's grant.
    let reply = patch_threshold(&fix, &token, 2).await;
    assert_eq!(reply["rejected"][0]["key"], THRESHOLD_KEY, "{reply}");
    assert!(
        reply["rejected"][0]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("could never be met")),
        "{reply}"
    );

    // A third makes two approvals possible.
    let second = admin(&fix).await;
    let reply = patch_threshold(&fix, &token, 2).await;
    assert_eq!(reply["applied"][0], THRESHOLD_KEY, "{reply}");

    let subject = Party::new();
    let body = grant_unrestricted(&subject.did);
    let (_, refusal) = bearer(&fix, "POST", "/v1/acl", GRANT, &token, body.clone()).await;
    assert_eq!(refusal["minApprovals"], 2, "{refusal}");

    let (_, ack) = decide(&fix, &first, &refusal, "approve").await;
    assert_eq!(ack["status"], "pending", "{ack}");
    assert_eq!(ack["approvals"], 1);
    assert_eq!(ack["needed"], 2);
    let (status, _) = bearer(&fix, "POST", "/v1/acl", GRANT, &token, body.clone()).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "one approval of two is not enough"
    );

    let (_, ack) = decide(&fix, &second, &refusal, "approve").await;
    assert_eq!(ack["status"], "granted", "{ack}");
    let (status, reply) = bearer(&fix, "POST", "/v1/acl", GRANT, &token, body).await;
    assert_eq!(status, StatusCode::CREATED, "{reply}");
}

// ─── attrition (VTI-APV-009): ending an unrestricted admin ─────────────────

const REVOKE: &str = "https://trusttasks.org/spec/acl/revoke/0.1";

/// Three unrestricted admins and a threshold of 2: removing any one would leave
/// two, of whom only one could ever approve the other's grant.
async fn three_admins_threshold_two(fix: &Fixture) -> (Party, Party, Party, String) {
    let a = admin(fix).await;
    let b = admin(fix).await;
    let c = admin(fix).await;
    let token = stepped_up_token(fix, &a.did).await;
    let reply = patch_threshold(fix, &token, 2).await;
    assert_eq!(reply["applied"][0], THRESHOLD_KEY, "{reply}");
    (a, b, c, token)
}

/// `acl/revoke` of an unrestricted admin that would strand the threshold is
/// refused, names the fix, and writes nothing. Lowering the threshold first
/// lets it through.
#[tokio::test]
async fn vti_apv_009_a_revoke_that_would_strand_the_threshold_is_refused() {
    let fix = fixture().await;
    let (_a, _b, c, token) = three_admins_threshold_two(&fix).await;

    let (status, body) = bearer(
        &fix,
        "DELETE",
        &format!("/v1/acl/{}", c.did),
        REVOKE,
        &token,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let message = body.to_string();
    assert!(message.contains("config/patch"), "names the fix: {message}");
    assert!(entry(&fix, &c.did).await.is_some(), "nothing removed");

    patch_threshold(&fix, &token, 1).await;
    let (status, body) = bearer(
        &fix,
        "DELETE",
        &format!("/v1/acl/{}", c.did),
        REVOKE,
        &token,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

/// At the default threshold a two-admin community can still remove one of
/// them: the compromised-admin case must never be a lockout.
#[tokio::test]
async fn a_two_admin_community_can_still_remove_one_at_the_default_threshold() {
    let fix = fixture().await;
    let a = admin(&fix).await;
    let b = admin(&fix).await;
    let token = stepped_up_token(&fix, &a.did).await;
    let (status, body) = bearer(
        &fix,
        "DELETE",
        &format!("/v1/acl/{}", b.did),
        REVOKE,
        &token,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

/// An `acl/grant` rewrite that narrows an unrestricted admin to a scoped one is
/// attrition too.
#[tokio::test]
async fn vti_apv_009_narrowing_an_unrestricted_admin_is_attrition() {
    let fix = fixture().await;
    let (_a, _b, c, token) = three_admins_threshold_two(&fix).await;
    let narrow = json!({ "entry": { "subject": c.did, "role": "admin", "scopes": ["ctx-a"] } });

    let (status, body) = bearer(&fix, "POST", "/v1/acl", GRANT, &token, narrow.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        entry(&fix, &c.did).await.unwrap().is_super_admin(),
        "unchanged"
    );

    patch_threshold(&fix, &token, 1).await;
    let (status, body) = bearer(&fix, "POST", "/v1/acl", GRANT, &token, narrow).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!entry(&fix, &c.did).await.unwrap().is_super_admin());
}

/// A demotion through `acl/change-role` is attrition too.
#[tokio::test]
async fn vti_apv_009_demoting_an_unrestricted_admin_is_attrition() {
    let fix = fixture().await;
    let (_a, _b, c, token) = three_admins_threshold_two(&fix).await;
    let (status, body) = bearer(
        &fix,
        "PATCH",
        &format!("/v1/acl/{}", c.did),
        CHANGE_ROLE,
        &token,
        json!({ "fromRole": "admin", "toRole": "member" }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(entry(&fix, &c.did).await.unwrap().role, VtcRole::Admin);
}

/// The last unrestricted admin cannot demote themselves while a scoped admin
/// remains — the old last-admin guard counted the scoped admin and let it
/// through, leaving nobody who could ever consent to an unrestricted grant.
#[tokio::test]
async fn the_last_unrestricted_admin_cannot_step_down_behind_a_scoped_one() {
    let fix = fixture().await;
    let a = admin(&fix).await;
    let scoped = Party::new();
    store_acl_entry(
        &fix.vtc.state.acl_ks,
        &row(&scoped.did, VtcRole::Admin, &["ctx-a"]),
    )
    .await
    .unwrap();
    let token = stepped_up_token(&fix, &a.did).await;
    let (status, body) = bearer(
        &fix,
        "PATCH",
        &format!("/v1/acl/{}", a.did),
        CHANGE_ROLE,
        &token,
        json!({ "fromRole": "admin", "toRole": "member" }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body.to_string().contains("last unrestricted admin"),
        "{body}"
    );
    assert!(entry(&fix, &a.did).await.unwrap().is_super_admin());
}

// ─── invites: an invited admin is unrestricted ─────────────────────────────

const CREATE_INVITE: &str = "https://trusttasks.org/spec/vtc/admin/invites/create/0.1";

async fn invite_fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .with_public_url(RP_ORIGIN)
        .with_signers(true)
        .with_audit(true)
        .with_install_signer(std::sync::Arc::new(
            vtc_service::install::InstallTokenSigner::from_master_seed(&[0xAB; 64]).unwrap(),
        ))
        .build()
        .await;
    Fixture {
        vtc,
        authenticator: SoftEd25519Authenticator::new(),
    }
}

/// A scoped admin cannot invite: the entry an invite writes is unrestricted.
/// Before VTI-APV-014 this was a way for a scoped admin to mint a community-wide
/// one.
#[tokio::test]
async fn a_scoped_admin_cannot_invite_an_admin() {
    let fix = invite_fixture().await;
    let scoped = Party::new();
    store_acl_entry(
        &fix.vtc.state.acl_ks,
        &row(&scoped.did, VtcRole::Admin, &["ctx-a"]),
    )
    .await
    .unwrap();
    let token = fix
        .vtc
        .token(&scoped.did, "admin", vec!["ctx-a".into()])
        .await;
    let invitee = Party::new();
    let (status, body) = bearer(
        &fix,
        "POST",
        "/v1/admin/invites",
        CREATE_INVITE,
        &token,
        json!({ "did": invitee.did }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(entry(&fix, &invitee.did).await.is_none());
}

/// An unrestricted admin's invite needs the step-up and another admin's
/// consent, like the grant it is.
#[tokio::test]
async fn vti_apv_014_an_invite_needs_the_step_up_and_another_admins_consent() {
    let fix = invite_fixture().await;
    let requester = admin(&fix).await;
    let approver = admin(&fix).await;
    let invitee = Party::new();
    let body = json!({ "did": invitee.did });

    // An unelevated session is asked to step up first.
    let plain = fix.vtc.token(&requester.did, "admin", vec![]).await;
    let (status, reply) = bearer(
        &fix,
        "POST",
        "/v1/admin/invites",
        CREATE_INVITE,
        &plain,
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert_eq!(reply["error"], "step_up_required", "{reply}");

    let token = stepped_up_token(&fix, &requester.did).await;
    let (status, refusal) = bearer(
        &fix,
        "POST",
        "/v1/admin/invites",
        CREATE_INVITE,
        &token,
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    assert_eq!(refusal["error"], "auth:consent_required", "{refusal}");
    assert!(entry(&fix, &invitee.did).await.is_none(), "nothing written");

    let (status, ack) = decide(&fix, &approver, &refusal, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");

    let (status, minted) = bearer(
        &fix,
        "POST",
        "/v1/admin/invites",
        CREATE_INVITE,
        &token,
        body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    assert!(minted["installUrl"].is_string(), "{minted}");
    assert!(entry(&fix, &invitee.did).await.unwrap().is_super_admin());
}
