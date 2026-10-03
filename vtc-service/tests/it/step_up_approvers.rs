//! Step-up approvers end to end on the signed-document door — the factor a
//! wallet administrator steps up with (approver design note
//! `vtc-approver-step-up.md`).
//!
//! - **VTI-APV-015** (as amended): an approver's signature counts only from a
//!   key bound as a factor under VTI-APV-016, distinct from the caller's
//!   signing keys. The gate tests below pin every refusal design note §5c
//!   lists: a statement by an unbound approver, by an approver of another
//!   subject, for another audience, over another challenge or `boundTo`, an
//!   answer signed by a console key, and an approver that is the subject.
//! - **VTI-APV-016**: a binding rests on an anchor independent of the
//!   subject's signing key, proves possession, and is audited naming it — the
//!   invite, redemption, self-service enrolment and revocation tests.
//! - **VTI-SES-001–004**: the challenge is single use (an answered challenge is
//!   `challengeUnknown` the second time) and a statement's `id` is spent once.

use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::VtcRole;
use vtc_service::test_support::TestVtc;

use crate::common::signed::{
    call, error_code, party_with_role, payload, post, seed_role, signed_to,
};
use crate::common::webauthn_harness::SoftEd25519Authenticator;

const RP_ORIGIN: &str = "https://vtc.example.com";
const INVITE: &str = "https://trusttasks.org/spec/auth/step-up/approver/invite/0.1";
const REDEEM_START: &str = "https://trusttasks.org/spec/auth/step-up/approver/redeem/start/0.1";
const REDEEM_FINISH: &str = "https://trusttasks.org/spec/auth/step-up/approver/redeem/finish/0.1";
const ENROLL: &str = "https://trusttasks.org/spec/auth/step-up/approver/enroll/0.1";
const LIST: &str = "https://trusttasks.org/spec/auth/step-up/approver/list/0.1";
const REVOKE: &str = "https://trusttasks.org/spec/auth/step-up/approver/revoke/0.1";
const ATTEST: &str = "https://trusttasks.org/spec/auth/step-up/approver/attest/0.1";
const APPROVE_V06: &str = "https://trusttasks.org/spec/auth/step-up/approve-response/0.6";
const APPROVE_V04: &str = "https://trusttasks.org/spec/auth/step-up/approve-response/0.4";

async fn vtc() -> TestVtc {
    TestVtc::builder()
        .with_public_url(RP_ORIGIN)
        .with_audit(true)
        .with_signers(true)
        .build()
        .await
}

async fn vtc_did(vtc: &TestVtc) -> String {
    vtc.state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .expect("the test VTC has a DID")
}

/// A community administrator who signs with a wallet persona and holds a step-up
/// approver — and no passkey at all.
async fn wallet_admin(vtc: &TestVtc) -> (Party, Party) {
    let admin = party_with_role(vtc, VtcRole::Admin, &[]).await;
    let approver = Party::new();
    vtc_service::acl::approver::bind_for_test(&vtc.state, &admin.did, &approver.did)
        .await
        .unwrap();
    (admin, approver)
}

/// An `auth/step-up/approver/attest/0.1` statement by `approver`, to `recipient`.
async fn statement_to(approver: &Party, recipient: &str, payload: Value) -> Value {
    signed_to(approver, recipient, ATTEST, payload).await
}

/// The step-up statement `approver` makes for `subject` over `request`.
async fn step_up_statement(
    vtc: &TestVtc,
    approver: &Party,
    subject: &str,
    request: &Value,
) -> Value {
    let audience = vtc_did(vtc).await;
    statement_to(
        approver,
        &audience,
        json!({
            "purpose": "stepUp",
            "subject": subject,
            "audience": audience,
            "challenge": request["challenge"],
            "boundTo": request["boundTo"],
        }),
    )
    .await
}

/// The approve-response 0.6 `signer` sends for `request`, carrying `statement`.
async fn answer(
    vtc: &TestVtc,
    signer: &Party,
    request: &Value,
    statement: Value,
) -> (StatusCode, Value) {
    call(
        vtc,
        signer,
        APPROVE_V06,
        json!({
            "subject": request["subject"],
            "challenge": request["challenge"],
            "decision": "approved",
            "evidence": { "kind": "approverSigned", "statement": statement },
        }),
    )
    .await
}

/// The inline step-up request a refusal carries.
fn step_up_request(reply: &Value) -> Value {
    assert_eq!(error_code(reply), Some("permissionDenied"), "{reply}");
    let req = reply["payload"]["details"]["stepUpRequest"].clone();
    assert!(req.is_object(), "no step-up was asked for: {reply}");
    req
}

/// Send `doc`; when refused for a step-up, answer it with `approver`'s statement
/// and send the identical document again.
async fn send_stepped_up(vtc: &TestVtc, subject: &Party, approver: &Party, doc: &Value) -> Value {
    let (_, first) = post(vtc, doc).await;
    let request = step_up_request(&first);
    let st = step_up_statement(vtc, approver, &subject.did, &request).await;
    let (status, ack) = answer(vtc, subject, &request, st).await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(payload(&ack)["status"], "recorded", "{ack}");
    let (_, done) = post(vtc, doc).await;
    done
}

/// A signed invite for `subject`, issued by `admin` behind their approver's step-up.
async fn invite(vtc: &TestVtc, admin: &Party, approver: &Party, subject: &str) -> Value {
    let doc = signed_to(
        admin,
        &vtc_did(vtc).await,
        INVITE,
        json!({ "subject": subject, "label": "Browser plugin" }),
    )
    .await;
    let issued = send_stepped_up(vtc, admin, approver, &doc).await;
    assert!(error_code(&issued).is_none(), "{issued}");
    payload(&issued).clone()
}

fn token_of(issued: &Value) -> String {
    let url = issued["url"].as_str().unwrap();
    assert!(
        url.starts_with(&format!("{RP_ORIGIN}/admin/enrol-approver#token=")),
        "{url}"
    );
    assert!(!url.contains(issued["claimCode"].as_str().unwrap()));
    url.split("#token=").nth(1).unwrap().to_string()
}

/// Redeem `issued` as `subject`, binding `approver`; the finish reply.
async fn redeem(vtc: &TestVtc, subject: &Party, approver: &Party, issued: &Value) -> Value {
    let (status, started) = call(
        vtc,
        subject,
        REDEEM_START,
        json!({ "token": token_of(issued), "claimCode": issued["claimCode"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{started}");
    let started = payload(&started).clone();
    let st = statement_to(
        approver,
        started["audience"].as_str().unwrap(),
        json!({
            "purpose": "enrol",
            "subject": subject.did,
            "audience": started["audience"],
            "challenge": started["challenge"],
            "boundTo": started["enrollmentId"],
        }),
    )
    .await;
    let (_, finished) = call(
        vtc,
        subject,
        REDEEM_FINISH,
        json!({
            "enrollmentId": started["enrollmentId"],
            "approverDid": approver.did,
            "label": "Work laptop",
            "statement": st,
        }),
    )
    .await;
    finished
}

async fn live_approvers(vtc: &TestVtc, subject: &str) -> Vec<String> {
    vtc_service::acl::approver::live_approvers(&vtc.state, subject)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.approver_did)
        .collect()
}

/// The `(stage, enrolledVia)` of each step-up approver audit row, oldest first.
async fn audited(vtc: &TestVtc) -> Vec<(String, Option<String>)> {
    let rows = vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap();
    let mut out = Vec::new();
    for (_, value) in rows {
        if let Ok(env) = serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&value)
            && let vti_common::audit::AuditEvent::StepUpApproverChanged(d) = env.event
        {
            out.push((env.timestamp, d.stage, d.enrolled_via));
        }
    }
    out.sort_by_key(|(t, _, _)| *t);
    out.into_iter().map(|(_, s, v)| (s, v)).collect()
}

// ── the gate (approve-request 0.4, approve-response 0.6) ─────────────────────

/// VTI-APV-015: a wallet administrator with no passkey steps up with their
/// approver. The request accepts only `approverSigned` and names the approver;
/// the answer is recorded, nothing is elevated, and the act completes; the
/// challenge is then spent (VTI-SES-004).
#[tokio::test]
async fn vti_apv_015_an_approver_statement_answers_a_bound_step_up() {
    let vtc = vtc().await;
    let (admin, approver) = wallet_admin(&vtc).await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let doc = signed_to(
        &admin,
        &vtc_did(&vtc).await,
        INVITE,
        json!({ "subject": member.did }),
    )
    .await;

    let (_, first) = post(&vtc, &doc).await;
    let request = step_up_request(&first);
    assert_eq!(request["accepts"], json!(["approverSigned"]), "{request}");
    assert_eq!(request["approvers"], json!([approver.did]));
    assert!(
        request.get("webauthn").is_none(),
        "no passkey is offered: {request}"
    );

    let st = step_up_statement(&vtc, &approver, &admin.did, &request).await;
    let (status, ack) = answer(&vtc, &admin, &request, st.clone()).await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(payload(&ack)["status"], "recorded");
    assert_eq!(payload(&ack)["boundTo"], request["boundTo"]);

    let (_, done) = post(&vtc, &doc).await;
    assert!(error_code(&done).is_none(), "{done}");
    assert!(payload(&done)["claimCode"].is_string());

    // The same answer again finds nothing: the challenge was single use.
    let (_, again) = answer(&vtc, &admin, &request, st).await;
    assert_eq!(
        error_code(&again),
        Some("auth/step-up/approve-response:challengeUnknown"),
        "{again}"
    );

    // Its use is recorded on the binding.
    let rec = vtc_service::acl::approver::get(&vtc.state.step_up_approvers_ks, &approver.did)
        .await
        .unwrap()
        .unwrap();
    assert!(rec.last_used_at.is_some());
}

/// Every refusal design note §5c lists, each leaving the step-up asked for —
/// the right answer still records afterwards.
#[tokio::test]
async fn vti_apv_015_a_statement_is_refused_unless_it_is_the_bound_approvers_over_this_step_up() {
    let vtc = vtc().await;
    let (admin, approver) = wallet_admin(&vtc).await;
    let (other_admin, other_approver) = wallet_admin(&vtc).await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let audience = vtc_did(&vtc).await;
    let doc = signed_to(&admin, &audience, INVITE, json!({ "subject": member.did })).await;

    let ask = || async {
        let (_, refusal) = post(&vtc, &doc).await;
        step_up_request(&refusal)
    };
    let bad = |request: &Value, overrides: Value| {
        let mut p = json!({
            "purpose": "stepUp",
            "subject": admin.did,
            "audience": audience,
            "challenge": request["challenge"],
            "boundTo": request["boundTo"],
        });
        for (k, v) in overrides.as_object().unwrap() {
            p[k] = v.clone();
        }
        p
    };

    // A statement by an approver bound to nobody.
    let request = ask().await;
    let stranger = Party::new();
    let st = statement_to(&stranger, &audience, bad(&request, json!({}))).await;
    let (_, out) = answer(&vtc, &admin, &request, st).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approve-response:approverNotBound"),
        "an unbound approver: {out}"
    );

    // An approver bound to another administrator.
    let request = ask().await;
    let st = statement_to(&other_approver, &audience, bad(&request, json!({}))).await;
    let (_, out) = answer(&vtc, &admin, &request, st).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approve-response:approverNotBound"),
        "another subject's approver: {out}"
    );

    // Made for another relying party (audience and recipient).
    let request = ask().await;
    let elsewhere = "did:webvh:QmOther:elsewhere.example";
    let st = statement_to(
        &approver,
        elsewhere,
        bad(&request, json!({ "audience": elsewhere })),
    )
    .await;
    let (_, out) = answer(&vtc, &admin, &request, st).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approve-response:statementInvalid"),
        "wrong audience: {out}"
    );
    // The audience alone wrong, the recipient right.
    let request = ask().await;
    let st = statement_to(
        &approver,
        &audience,
        bad(&request, json!({ "audience": elsewhere })),
    )
    .await;
    let (_, out) = answer(&vtc, &admin, &request, st).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approve-response:statementInvalid"),
        "wrong audience member: {out}"
    );

    // Over another challenge, and bound to another operation.
    let request = ask().await;
    let st = statement_to(
        &approver,
        &audience,
        bad(
            &request,
            json!({ "challenge": "c29tZS1vdGhlci1jaGFsbGVuZ2UtdmFsdWU" }),
        ),
    )
    .await;
    let (_, out) = answer(&vtc, &admin, &request, st).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approve-response:statementInvalid"),
        "challenge mismatch: {out}"
    );
    let request = ask().await;
    let st = statement_to(
        &approver,
        &audience,
        bad(&request, json!({ "boundTo": "zSomethingElse" })),
    )
    .await;
    let (_, out) = answer(&vtc, &admin, &request, st).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approve-response:statementInvalid"),
        "boundTo mismatch: {out}"
    );

    // A statement for another purpose (an enrolment statement is never a step-up).
    let request = ask().await;
    let st = statement_to(
        &approver,
        &audience,
        bad(&request, json!({ "purpose": "enrol" })),
    )
    .await;
    let (_, out) = answer(&vtc, &admin, &request, st).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approve-response:statementInvalid"),
        "wrong purpose: {out}"
    );

    // The approver is the subject: the subject's own key is no second factor.
    let request = ask().await;
    let st = statement_to(&admin, &audience, bad(&request, json!({}))).await;
    let (_, out) = answer(&vtc, &admin, &request, st).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approve-response:statementInvalid"),
        "the subject signing for itself: {out}"
    );

    // Another administrator signing the answer around the right statement.
    let request = ask().await;
    let st = step_up_statement(&vtc, &approver, &admin.did, &request).await;
    let (_, out) = answer(&vtc, &other_admin, &request, st.clone()).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approve-response:subjectMismatch"),
        "another signer: {out}"
    );
    // ... which, refused before the step-up was looked up, left it in place.
    let (_, ok) = answer(&vtc, &admin, &request, st).await;
    assert_eq!(payload(&ok)["status"], "recorded", "{ok}");
}

/// The answer's own proof must be the subject's own DID: a console key — a
/// delegation acting for them — is refused before the step-up is looked up,
/// and the step-up stays answerable (approve-response 0.6 item 1a).
#[tokio::test]
async fn vti_apv_015_a_console_key_cannot_sign_an_approver_answer() {
    let vtc = vtc().await;
    let (admin, approver) = wallet_admin(&vtc).await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let console = Party::new();
    let now = chrono::Utc::now();
    vtc_service::acl::console_key::store_delegation(
        &vtc.state.console_keys_ks,
        &vtc_service::acl::console_key::ConsoleKeyDelegation {
            console_did: console.did.clone(),
            admin_did: admin.did.clone(),
            scope: vtc_service::acl::console_key::DelegationScope::Console,
            label: Some("console".into()),
            created_at: now,
            expires_at: now + chrono::Duration::days(1),
            last_used_at: None,
            revoked_at: None,
            revoked_by: None,
        },
    )
    .await
    .unwrap();

    // The console key can sign the act itself — it acts for the admin.
    let doc = signed_to(
        &console,
        &vtc_did(&vtc).await,
        INVITE,
        json!({ "subject": member.did }),
    )
    .await;
    let (_, first) = post(&vtc, &doc).await;
    let request = step_up_request(&first);
    assert_eq!(request["subject"], admin.did);

    let st = step_up_statement(&vtc, &approver, &admin.did, &request).await;
    let (_, out) = answer(&vtc, &console, &request, st.clone()).await;
    assert!(
        matches!(
            error_code(&out),
            Some("permissionDenied") | Some("auth/step-up/approve-response:subjectMismatch")
        ),
        "a console key's proof is never an approver answer: {out}"
    );
    let (_, ok) = answer(&vtc, &admin, &request, st).await;
    assert_eq!(payload(&ok)["status"], "recorded", "{ok}");
}

/// The factor-union rule (design note §4): once a subject holds a step-up
/// approver, their session passkeys stop counting — the request offers no
/// WebAuthn, and a passkey answer is `noGate`. Without one, the passkey is
/// still the route.
#[tokio::test]
async fn a_dedicated_factor_supersedes_the_subjects_session_passkeys() {
    let vtc = vtc().await;
    let admin = party_with_role(&vtc, VtcRole::Admin, &[]).await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let mut authenticator = SoftEd25519Authenticator::new();
    enrol_session_passkey(&vtc, &mut authenticator, &admin.did).await;
    let audience = vtc_did(&vtc).await;
    let doc = signed_to(&admin, &audience, INVITE, json!({ "subject": member.did })).await;

    // Passkey only: webauthn is offered, and nothing else.
    let (_, first) = post(&vtc, &doc).await;
    let request = step_up_request(&first);
    assert_eq!(request["accepts"], json!(["webauthn"]), "{request}");
    let allow = request["webauthn"]["allowCredentials"].clone();
    assert!(request.get("approvers").is_none());

    // Bind an approver: the passkey stops counting.
    let approver = Party::new();
    vtc_service::acl::approver::bind_for_test(&vtc.state, &admin.did, &approver.did)
        .await
        .unwrap();
    let (_, second) = post(&vtc, &doc).await;
    let request = step_up_request(&second);
    assert_eq!(request["accepts"], json!(["approverSigned"]), "{request}");
    assert!(request.get("webauthn").is_none());

    // A passkey assertion over this challenge is not a gate it offered.
    let options: webauthn_rs::prelude::RequestChallengeResponse = serde_json::from_value(json!({
        "publicKey": {
            "challenge": request["challenge"],
            "rpId": "vtc.example.com",
            "allowCredentials": allow,
            "userVerification": "required",
        }
    }))
    .unwrap();
    let assertion = authenticator.authenticate(&options, RP_ORIGIN);
    let mut assertion = serde_json::to_value(&assertion).unwrap();
    let obj = assertion.as_object_mut().unwrap();
    obj.remove("extensions");
    obj.insert("clientExtensionResults".into(), json!({}));
    let (_, out) = call(
        &vtc,
        &admin,
        APPROVE_V04,
        json!({
            "subject": admin.did,
            "challenge": request["challenge"],
            "decision": "approved",
            "evidence": { "kind": "webauthn", "assertion": assertion },
        }),
    )
    .await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approve-response:noGate"),
        "{out}"
    );
}

/// A subject with no factor at all is told the routes that exist for them —
/// another administrator's invite, or the offline command — never a
/// self-invite.
#[tokio::test]
async fn a_subject_with_no_factor_is_pointed_at_an_invite_or_the_host() {
    let vtc = vtc().await;
    let admin = party_with_role(&vtc, VtcRole::Admin, &[]).await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let (_, out) = call(&vtc, &admin, INVITE, json!({ "subject": member.did })).await;
    let message = out["payload"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(message.contains("vtc admin enrol-approver"), "{out}");
    assert!(message.contains("Invite to enrol an approver"), "{out}");
}

async fn enrol_session_passkey(
    vtc: &TestVtc,
    authenticator: &mut SoftEd25519Authenticator,
    did: &str,
) {
    use vti_common::auth::passkey::store::{
        PasskeyUser, store_credential_mapping, store_passkey_user,
    };
    let webauthn = vtc.state.webauthn.clone().expect("webauthn is configured");
    let user_uuid = uuid::Uuid::new_v4();
    let (ccr, reg) =
        vtc_service::webauthn::start_passkey_registration(&webauthn, user_uuid, did, did, None)
            .unwrap();
    let (cred, _) = authenticator.register(&ccr, RP_ORIGIN);
    let passkey =
        vtc_service::webauthn::finish_passkey_registration(&webauthn, &cred, &reg).unwrap();
    let hex_id = hex::encode(<_ as AsRef<[u8]>>::as_ref(passkey.cred_id()));
    store_passkey_user(
        &vtc.state.passkey_ks,
        &PasskeyUser {
            user_uuid,
            did: did.to_string(),
            display_name: did.to_string(),
            credentials: vec![passkey],
        },
    )
    .await
    .unwrap();
    store_credential_mapping(&vtc.state.passkey_ks, &hex_id, user_uuid)
        .await
        .unwrap();
}

// ── R2: invite → redeem ──────────────────────────────────────────────────────

/// VTI-APV-016: an administrator's invite (behind their own step-up), redeemed
/// by the invited subject's own signature with the approver's proof of
/// possession, binds the approver with `enrolledVia: invite` — audited — and is
/// single use. The new approver then answers the subject's step-ups.
#[tokio::test]
async fn vti_apv_016_an_invite_redeemed_by_the_subject_binds_their_approver() {
    let vtc = vtc().await;
    let (admin, admin_approver) = wallet_admin(&vtc).await;
    let subject = party_with_role(&vtc, VtcRole::Admin, &["ctx-a"]).await;
    let approver = Party::new();

    let issued = invite(&vtc, &admin, &admin_approver, &subject.did).await;
    let finished = redeem(&vtc, &subject, &approver, &issued).await;
    assert!(error_code(&finished).is_none(), "{finished}");
    let bound = &payload(&finished)["approver"];
    assert_eq!(bound["approverDid"], approver.did);
    assert_eq!(bound["subject"], subject.did);
    assert_eq!(bound["enrolledVia"], "invite");
    assert_eq!(bound["label"], "Work laptop");
    assert_eq!(
        live_approvers(&vtc, &subject.did).await,
        std::slice::from_ref(&approver.did)
    );

    // Single use.
    let (_, again) = call(
        &vtc,
        &subject,
        REDEEM_START,
        json!({ "token": token_of(&issued), "claimCode": issued["claimCode"] }),
    )
    .await;
    assert_eq!(
        error_code(&again),
        Some("auth/step-up/approver/redeem/start:inviteNotFound"),
        "{again}"
    );
    let stages = audited(&vtc).await;
    assert!(
        stages.contains(&("invited".into(), Some("invite".into()))),
        "{stages:?}"
    );
    assert!(
        stages.contains(&("enrolled".into(), Some("invite".into()))),
        "{stages:?}"
    );

    // The approver now answers the subject's own step-up.
    let member = party_with_role(&vtc, VtcRole::Member, &["ctx-a"]).await;
    let doc = signed_to(
        &subject,
        &vtc_did(&vtc).await,
        LIST,
        json!({ "subject": member.did }),
    )
    .await;
    let (_, listed) = post(&vtc, &doc).await;
    assert!(
        error_code(&listed).is_none(),
        "a scoped admin lists a member in scope: {listed}"
    );
}

/// invite/0.1's refusals, each decided before any step-up is asked for.
#[tokio::test]
async fn an_invite_is_refused_before_any_step_up_for_self_strangers_and_long_ttls() {
    let vtc = vtc().await;
    let (admin, _approver) = wallet_admin(&vtc).await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let cases = [
        (
            &admin,
            json!({ "subject": admin.did }),
            "auth/step-up/approver/invite:selfInvite",
        ),
        (
            &admin,
            json!({ "subject": "did:key:z6MkNotAMember" }),
            "auth/step-up/approver/invite:subjectUnknown",
        ),
        (
            &admin,
            json!({ "subject": member.did, "ttl": 86401 }),
            "auth/step-up/approver/invite:ttlTooLong",
        ),
        (&member, json!({ "subject": admin.did }), "permissionDenied"),
    ];
    for (from, p, code) in cases {
        let (_, out) = call(&vtc, from, INVITE, p).await;
        assert_eq!(error_code(&out), Some(code), "{out}");
        assert!(
            out["payload"]["details"].get("stepUpRequest").is_none(),
            "no step-up is asked for an act refused anyway: {out}"
        );
        if code.ends_with("ttlTooLong") {
            assert_eq!(out["payload"]["details"]["maxTtl"], 86400);
        }
    }
    assert!(audited(&vtc).await.is_empty());
}

/// redeem/start/0.1: only the invited subject's own signed attempts count; a
/// wrong code says how many remain; the fifth voids the invite for good.
#[tokio::test]
async fn redeem_start_counts_only_the_subjects_attempts_and_five_wrong_codes_void() {
    let vtc = vtc().await;
    let (admin, admin_approver) = wallet_admin(&vtc).await;
    let subject = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let issued = invite(&vtc, &admin, &admin_approver, &subject.did).await;
    let token = token_of(&issued);

    // Someone else holding both halves is refused, and not counted.
    let stranger = party_with_role(&vtc, VtcRole::Member, &[]).await;
    for _ in 0..6 {
        let (_, out) = call(
            &vtc,
            &stranger,
            REDEEM_START,
            json!({ "token": token, "claimCode": "WRONGCODE9" }),
        )
        .await;
        assert_eq!(
            error_code(&out),
            Some("auth/step-up/approver/redeem/start:notInvitedSubject"),
            "{out}"
        );
    }
    let (_, out) = call(
        &vtc,
        &subject,
        REDEEM_START,
        json!({ "token": "sua_not-an-invite-token-at-all", "claimCode": "WRONGCODE9" }),
    )
    .await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approver/redeem/start:inviteNotFound"),
        "{out}"
    );
    for remaining in (1..5).rev() {
        let (_, out) = call(
            &vtc,
            &subject,
            REDEEM_START,
            json!({ "token": token, "claimCode": "WRONGCODE9" }),
        )
        .await;
        assert_eq!(
            error_code(&out),
            Some("auth/step-up/approver/redeem/start:codeMismatch"),
            "{out}"
        );
        assert_eq!(out["payload"]["details"]["attemptsRemaining"], remaining);
    }
    let (_, out) = call(
        &vtc,
        &subject,
        REDEEM_START,
        json!({ "token": token, "claimCode": "WRONGCODE9" }),
    )
    .await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approver/redeem/start:inviteVoided"),
        "the fifth: {out}"
    );
    let (_, out) = call(
        &vtc,
        &subject,
        REDEEM_START,
        json!({ "token": token, "claimCode": issued["claimCode"] }),
    )
    .await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approver/redeem/start:inviteVoided"),
        "void for good: {out}"
    );
    assert!(audited(&vtc).await.iter().any(|(s, _)| s == "inviteVoided"));
}

/// redeem/finish/0.1's refusals: a statement for another ceremony, an approver
/// that is no distinct factor, one already bound elsewhere, a revoked (burned)
/// one, and the cap of five.
#[tokio::test]
async fn redeem_finish_refuses_bad_statements_undistinct_bound_burned_and_the_sixth_approver() {
    let vtc = vtc().await;
    let (admin, admin_approver) = wallet_admin(&vtc).await;
    let subject = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let audience = vtc_did(&vtc).await;

    async fn start(vtc: &TestVtc, subject: &Party, issued: &Value) -> Value {
        let (_, started) = call(
            vtc,
            subject,
            REDEEM_START,
            json!({ "token": token_of(issued), "claimCode": issued["claimCode"] }),
        )
        .await;
        payload(&started).clone()
    }
    async fn finish(
        vtc: &TestVtc,
        subject: &Party,
        started: &Value,
        approver_did: &str,
        statement: Value,
    ) -> Value {
        let (_, out) = call(
            vtc,
            subject,
            REDEEM_FINISH,
            json!({
                "enrollmentId": started["enrollmentId"],
                "approverDid": approver_did,
                "statement": statement,
            }),
        )
        .await;
        out
    }
    let enrol_payload = |started: &Value, bound_to: &Value| {
        json!({
            "purpose": "enrol",
            "subject": subject.did,
            "audience": audience,
            "challenge": started["challenge"],
            "boundTo": bound_to,
        })
    };

    let issued = invite(&vtc, &admin, &admin_approver, &subject.did).await;
    let started = start(&vtc, &subject, &issued).await;

    // Bound to another ceremony.
    let approver = Party::new();
    let st = statement_to(
        &approver,
        &audience,
        enrol_payload(&started, &json!("enr_someotherceremony")),
    )
    .await;
    let out = finish(&vtc, &subject, &started, &approver.did, st).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approver/redeem/finish:statementInvalid"),
        "{out}"
    );
    // Signed by someone other than the invited subject.
    let st = statement_to(
        &approver,
        &audience,
        enrol_payload(&started, &started["enrollmentId"]),
    )
    .await;
    let (_, out) = call(
        &vtc,
        &admin,
        REDEEM_FINISH,
        json!({ "enrollmentId": started["enrollmentId"], "approverDid": approver.did, "statement": st }),
    )
    .await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approver/redeem/finish:notInvitedSubject"),
        "{out}"
    );
    // An approver that holds standing of its own is no distinct factor.
    let standing = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let st = statement_to(
        &standing,
        &audience,
        enrol_payload(&started, &started["enrollmentId"]),
    )
    .await;
    let out = finish(&vtc, &subject, &started, &standing.did, st).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approver/redeem/finish:approverNotDistinct"),
        "{out}"
    );
    // One already bound to another subject.
    let st = statement_to(
        &admin_approver,
        &audience,
        enrol_payload(&started, &started["enrollmentId"]),
    )
    .await;
    let out = finish(&vtc, &subject, &started, &admin_approver.did, st).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approver/redeem/finish:approverAlreadyBound"),
        "{out}"
    );

    // A revoked approver stays burned: bind, revoke, try to bind it again.
    let burned = Party::new();
    vtc_service::acl::approver::bind_for_test(&vtc.state, &subject.did, &burned.did)
        .await
        .unwrap();
    let revoke_doc = signed_to(
        &subject,
        &audience,
        REVOKE,
        json!({ "approverDid": burned.did, "reason": "device lost" }),
    )
    .await;
    let revoked = send_stepped_up(&vtc, &subject, &burned, &revoke_doc).await;
    assert_eq!(payload(&revoked)["remainingApprovers"], 0, "{revoked}");
    let st = statement_to(
        &burned,
        &audience,
        enrol_payload(&started, &started["enrollmentId"]),
    )
    .await;
    let out = finish(&vtc, &subject, &started, &burned.did, st).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approver/redeem/finish:approverAlreadyBound"),
        "a burned approver: {out}"
    );

    // Five live approvers: the sixth is refused.
    for _ in 0..5 {
        vtc_service::acl::approver::bind_for_test(&vtc.state, &subject.did, &Party::new().did)
            .await
            .unwrap();
    }
    let sixth = Party::new();
    let st = statement_to(
        &sixth,
        &audience,
        enrol_payload(&started, &started["enrollmentId"]),
    )
    .await;
    let out = finish(&vtc, &subject, &started, &sixth.did, st).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approver/redeem/finish:tooManyApprovers"),
        "{out}"
    );
    // The invite survived every refusal (none was consumed).
    assert_eq!(live_approvers(&vtc, &subject.did).await.len(), 5);
}

// ── R3: self-service enrolment ───────────────────────────────────────────────

/// enroll/0.1: the subject adds an approver behind a factor they already hold
/// — the existing approver's step-up over these terms — and the new approver's
/// statement over that step-up's challenge, bound to the terms digest. With
/// `replaces`, the old one is revoked in the same step.
#[tokio::test]
async fn vti_apv_016_self_service_enrolment_rests_on_a_factor_already_held() {
    let vtc = vtc().await;
    let (admin, old) = wallet_admin(&vtc).await;
    let new = Party::new();
    let audience = vtc_did(&vtc).await;
    let terms = json!({ "approverDid": new.did, "label": "New laptop", "replaces": old.did });

    // First send: the authority evidence is asked for.
    let (_, first) = call(&vtc, &admin, ENROLL, terms.clone()).await;
    let request = step_up_request(&first);
    assert_eq!(request["accepts"], json!(["approverSigned"]));
    let st = step_up_statement(&vtc, &old, &admin.did, &request).await;
    let (_, ack) = answer(&vtc, &admin, &request, st).await;
    assert_eq!(payload(&ack)["status"], "recorded", "{ack}");

    // A statement bound to anything but these terms is refused, and the
    // recorded step-up survives the refusal.
    let challenge = request["challenge"].as_str().unwrap();
    let wrong = statement_to(
        &new,
        &audience,
        json!({ "purpose": "enrol", "subject": admin.did, "audience": audience, "challenge": challenge, "boundTo": "zNotTheTerms" }),
    )
    .await;
    let mut with = terms.clone();
    with["statement"] = wrong;
    let (_, out) = call(&vtc, &admin, ENROLL, with).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approver/enroll:statementInvalid"),
        "{out}"
    );

    let digest =
        vtc_service::step_up_approver::terms_digest(&admin.did, challenge, &terms).unwrap();
    let st = statement_to(
        &new,
        &audience,
        json!({ "purpose": "enrol", "subject": admin.did, "audience": audience, "challenge": challenge, "boundTo": digest }),
    )
    .await;
    let mut with = terms.clone();
    with["statement"] = st;
    let (status, out) = call(&vtc, &admin, ENROLL, with).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(payload(&out)["approver"]["enrolledVia"], "selfService");
    assert_eq!(
        live_approvers(&vtc, &admin.did).await,
        std::slice::from_ref(&new.did),
        "the old one was replaced"
    );
    assert!(
        audited(&vtc)
            .await
            .contains(&("enrolled".into(), Some("selfService".into())))
    );
}

/// enroll/0.1 items 1 and 2: a console key is never the subject, and a
/// subject with no factor is pointed at an invite.
#[tokio::test]
async fn self_service_enrolment_refuses_a_console_key_and_a_subject_with_no_factor() {
    let vtc = vtc().await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let (_, out) = call(
        &vtc,
        &member,
        ENROLL,
        json!({ "approverDid": Party::new().did }),
    )
    .await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approver/enroll:noFactorHeld"),
        "{out}"
    );

    let (admin, _approver) = wallet_admin(&vtc).await;
    let console = Party::new();
    let now = chrono::Utc::now();
    vtc_service::acl::console_key::store_delegation(
        &vtc.state.console_keys_ks,
        &vtc_service::acl::console_key::ConsoleKeyDelegation {
            console_did: console.did.clone(),
            admin_did: admin.did.clone(),
            scope: vtc_service::acl::console_key::DelegationScope::Console,
            label: None,
            created_at: now,
            expires_at: now + chrono::Duration::days(1),
            last_used_at: None,
            revoked_at: None,
            revoked_by: None,
        },
    )
    .await
    .unwrap();
    let (_, out) = call(
        &vtc,
        &console,
        ENROLL,
        json!({ "approverDid": Party::new().did }),
    )
    .await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approver/enroll:subjectMismatch"),
        "{out}"
    );
}

// ── list / revoke ────────────────────────────────────────────────────────────

/// list/0.1: the subject's own, an administrator's over a member, and nothing
/// for anyone else — identically whether or not the subject exists.
#[tokio::test]
async fn approvers_are_listed_to_their_subject_and_administrators_over_them() {
    let vtc = vtc().await;
    let (admin, _) = wallet_admin(&vtc).await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let approver = Party::new();
    vtc_service::acl::approver::bind_for_test(&vtc.state, &member.did, &approver.did)
        .await
        .unwrap();

    let (_, own) = call(&vtc, &member, LIST, json!({})).await;
    assert_eq!(
        payload(&own)["approvers"][0]["approverDid"],
        approver.did,
        "{own}"
    );
    let (_, by_admin) = call(&vtc, &admin, LIST, json!({ "subject": member.did })).await;
    assert_eq!(payload(&by_admin)["approvers"].as_array().unwrap().len(), 1);

    let other = party_with_role(&vtc, VtcRole::Member, &[]).await;
    for subject in [member.did.as_str(), "did:key:z6MkNobodyAtAll"] {
        let (_, out) = call(&vtc, &other, LIST, json!({ "subject": subject })).await;
        assert_eq!(error_code(&out), Some("permissionDenied"), "{out}");
    }
}

/// revoke/0.1: an administrator revokes a member's approver behind their own
/// step-up; the last one may go; a repeat changes nothing; anyone without
/// standing is told `notFound`. The revoked approver answers nothing more.
#[tokio::test]
async fn an_administrator_revokes_a_members_last_approver_and_it_answers_nothing_after() {
    let vtc = vtc().await;
    let (admin, admin_approver) = wallet_admin(&vtc).await;
    let member = party_with_role(&vtc, VtcRole::Admin, &["ctx-a"]).await;
    let approver = Party::new();
    vtc_service::acl::approver::bind_for_test(&vtc.state, &member.did, &approver.did)
        .await
        .unwrap();
    let audience = vtc_did(&vtc).await;

    let stranger = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let (_, out) = call(
        &vtc,
        &stranger,
        REVOKE,
        json!({ "approverDid": approver.did, "subject": member.did }),
    )
    .await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approver/revoke:notFound"),
        "{out}"
    );

    // A step-up the member's approver was offered, still pending when it is
    // revoked: liveness is checked when the statement arrives, not when it was
    // listed (approve-response 0.6, *Approver liveness at use*).
    let (_, pending) = call(
        &vtc,
        &member,
        ENROLL,
        json!({ "approverDid": Party::new().did }),
    )
    .await;
    let pending = step_up_request(&pending);
    assert_eq!(pending["approvers"], json!([approver.did]));

    let doc = signed_to(
        &admin,
        &audience,
        REVOKE,
        json!({ "approverDid": approver.did, "subject": member.did, "reason": "Laptop reported lost" }),
    )
    .await;
    let done = send_stepped_up(&vtc, &admin, &admin_approver, &doc).await;
    assert!(error_code(&done).is_none(), "{done}");
    assert_eq!(payload(&done)["remainingApprovers"], 0);
    assert_eq!(payload(&done)["revoked"]["approverDid"], approver.did);
    assert!(live_approvers(&vtc, &member.did).await.is_empty());
    let st = step_up_statement(&vtc, &approver, &member.did, &pending).await;
    let (_, out) = answer(&vtc, &member, &pending, st).await;
    assert_eq!(
        error_code(&out),
        Some("auth/step-up/approve-response:approverNotBound"),
        "a revoked approver answers nothing: {out}"
    );

    // Repeated: success, nothing changes, no step-up asked.
    let again = signed_to(
        &admin,
        &audience,
        REVOKE,
        json!({ "approverDid": approver.did, "subject": member.did }),
    )
    .await;
    let (_, out) = post(&vtc, &again).await;
    assert!(error_code(&out).is_none(), "{out}");
    assert_eq!(payload(&out)["revokedAt"], payload(&done)["revokedAt"]);
    assert!(
        audited(&vtc)
            .await
            .iter()
            .filter(|(s, _)| s == "revoked")
            .count()
            == 1
    );
}

/// R4 + VTI-APV-016: `vtc admin enrol-approver` mints an invite on the host
/// and queues a break-glass marker; the daemon audits it at its next start;
/// the subject redeems it like any invite, and the binding says `offline`.
#[tokio::test]
async fn vti_apv_016_an_offline_invite_is_audited_at_boot_and_redeems_as_offline() {
    let vtc = vtc().await;
    let subject = Party::new();
    seed_role(&vtc, &subject.did, VtcRole::Admin, &[]).await;
    let minted = vtc_service::step_up_approver::mint_offline_invite(
        &vtc.store,
        RP_ORIGIN,
        &subject.did,
        900,
    )
    .await
    .unwrap();

    vtc_service::server::audit_offline_break_glass(&vtc.state).await;
    let rows = vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap();
    let marker = rows.iter().find_map(|(_, v)| {
        let env: vti_common::audit::AuditEnvelope = serde_json::from_slice(v).ok()?;
        match env.event {
            vti_common::audit::AuditEvent::AclBreakGlassWritten(d) => Some(d),
            _ => None,
        }
    });
    let marker = marker.expect("the offline invite is audited at boot");
    assert_eq!(marker.command, "vtc admin enrol-approver");
    assert_eq!(marker.did, subject.did);

    let issued = json!({ "url": minted.url, "claimCode": minted.claim_code });
    let approver = Party::new();
    let finished = redeem(&vtc, &subject, &approver, &issued).await;
    assert!(error_code(&finished).is_none(), "{finished}");
    assert_eq!(payload(&finished)["approver"]["enrolledVia"], "offline");
}
