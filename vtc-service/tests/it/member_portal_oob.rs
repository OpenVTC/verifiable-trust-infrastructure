//! Wallet sign-in started by a trigger link (`auth/oob/*`,
//! `trust_tasks::oob_tasks`, `member_portal::oob`): the state machine and the
//! checks of base design §7, with the trigger-link contract's C5 and C9.
//!
//! Every document goes through `POST /v1/trust-tasks`, the door a wallet
//! reaches through the community's trust-task HTTPS service.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, VerifyOptions};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use vti_common::auth::session::now_epoch;
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::credentials::LocalSigner;
use vtc_service::member_portal::oob::{self, OobRequest, OobState};
use vtc_service::members::{Member, store_member};
use vtc_service::test_support::TestVtc;

const VTC_DID: &str = "did:webvh:scidoob:vtc.example.com";
const PORTAL: &str = "https://vtc.example.com";
const BASE: &str = "https://trusttasks.org/spec/auth/oob";
const UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const SEED: [u8; 32] = [42; 32];

fn t(task: &str) -> String {
    format!("{BASE}/{task}/0.1")
}

struct Fixture {
    vtc: TestVtc,
    signer: LocalSigner,
}

async fn fixture() -> Fixture {
    oob::set_redeem_hold_for_tests(Duration::from_millis(300));
    let signer = LocalSigner::from_ed25519_seed(VTC_DID.into(), &SEED);
    let vtc = TestVtc::builder()
        .vtc_did(VTC_DID)
        .with_public_url(PORTAL)
        .with_credential_signer(std::sync::Arc::new(LocalSigner::from_ed25519_seed(
            VTC_DID.into(),
            &SEED,
        )))
        .build()
        .await;
    Fixture { vtc, signer }
}

async fn enrol_member(vtc: &TestVtc, did: &str, label: Option<&str>) {
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            admin: VtcRole::Member.implied_authority(),
            role: VtcRole::Member,
            label: label.map(str::to_string),
            delegated_by: None,
            created_at: now_epoch(),
            created_by: "test".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
            resource_grants: Vec::new(),
            label_set_by_subject: false,
            suspension: None,
        },
    )
    .await
    .unwrap();
    store_member(&vtc.state.members_ks, &Member::fresh(did))
        .await
        .unwrap();
}

/// A document from `from`, signed for `purpose`, with an optional
/// `parentThreadId`.
async fn doc(
    from: &Party,
    type_uri: &str,
    payload: Value,
    parent: Option<&str>,
    purpose: &str,
) -> Value {
    let mut d = vta_sdk::trust_task_sign::build_unsigned(type_uri, payload, &from.did, VTC_DID)
        .expect("build");
    d.parent_thread_id = parent.map(str::to_string);
    let mut v = serde_json::to_value(&d).unwrap();
    v.as_object_mut().unwrap().remove("proof");
    let proof = DataIntegrityProof::sign(
        &v,
        &from.secret,
        SignOptions::new()
            .with_proof_purpose(purpose)
            .with_created(chrono::Utc::now() - chrono::Duration::seconds(5)),
    )
    .await
    .expect("sign");
    v["proof"] = serde_json::to_value(proof).unwrap();
    v
}

async fn op(from: &Party, task: &str, payload: Value, parent: Option<&str>) -> Value {
    doc(from, &t(task), payload, parent, "authentication").await
}

struct Reply {
    status: StatusCode,
    body: Value,
    cookies: Vec<String>,
    cache_control: Option<String>,
}

async fn post(vtc: &TestVtc, body: &Value, ip: &str, origin: Option<&str>) -> Reply {
    let peer = SocketAddr::new(ip.parse::<IpAddr>().unwrap(), 40_000);
    let mut req = Request::builder()
        .method("POST")
        .uri("/v1/trust-tasks")
        .header("content-type", "application/json")
        .header("user-agent", UA)
        .header("host", "vtc.example.com");
    if let Some(o) = origin {
        req = req.header("origin", o);
    }
    let mut req = req
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    let res = vtc.router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let cookies = res
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    let cache_control = res
        .headers()
        .get(axum::http::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        cookies,
        cache_control,
    }
}

fn code(r: &Reply) -> &str {
    r.body["payload"]["code"].as_str().unwrap_or_default()
}

/// The browser: `K_b` and its address.
struct Browser {
    key: Party,
    ip: &'static str,
}

/// The phone: `K_a` and its address.
struct Phone {
    key: Party,
    ip: &'static str,
}

async fn start(f: &Fixture, b: &Browser) -> String {
    let r = post(
        &f.vtc,
        &op(
            &b.key,
            "request",
            json!({ "purpose": "login", "mode": "scan" }),
            None,
        )
        .await,
        b.ip,
        Some(PORTAL),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.cache_control.as_deref(), Some("no-store"));
    let p = &r.body["payload"];
    let id = p["requestId"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 22);
    // C9: epoch seconds, the trigger link's `_exp`, inside the 120 s window.
    let deadline = p["claimDeadline"].as_u64().expect("integer claimDeadline");
    assert!(deadline > now_epoch() && deadline <= now_epoch() + 120);
    id
}

async fn claim(f: &Fixture, p: &Phone, id: &str) -> Reply {
    post(
        &f.vtc,
        &op(&p.key, "claim", json!({ "requestId": id }), Some(id)).await,
        p.ip,
        None,
    )
    .await
}

async fn redeem(f: &Fixture, b: &Browser, id: &str) -> Reply {
    post(
        &f.vtc,
        &op(&b.key, "redeem", json!({ "requestId": id }), None).await,
        b.ip,
        Some(PORTAL),
    )
    .await
}

async fn identify(member: &Party, id: &str, approver: &str, number: &str) -> Value {
    doc(
        member,
        &t("identify"),
        json!({ "requestId": id, "approverKey": approver, "enteredNumber": number }),
        None,
        "authentication",
    )
    .await
}

async fn prove(f: &Fixture, p: &Phone, identify: Value) -> Reply {
    post(
        &f.vtc,
        &op(&p.key, "prove", json!({ "identify": identify }), None).await,
        p.ip,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn grant(
    member: &Party,
    id: &str,
    decision: &str,
    session_key: &str,
    approver: &str,
    origin: &str,
    context_digest: &str,
    purpose: &str,
) -> Value {
    doc(
        member,
        &t("grant"),
        json!({
            "requestId": id,
            "decision": decision,
            "sessionKey": session_key,
            "approverKey": approver,
            "origin": origin,
            "contextDigest": context_digest,
            "notAfter": now_epoch() + 3600,
        }),
        None,
        purpose,
    )
    .await
}

async fn respond(f: &Fixture, p: &Phone, grant: Value) -> Reply {
    post(
        &f.vtc,
        &op(&p.key, "respond", json!({ "grant": grant }), None).await,
        p.ip,
        None,
    )
    .await
}

async fn record(f: &Fixture, id: &str) -> OobRequest {
    oob::load(&f.vtc.state.member_sessions_ks, id)
        .await
        .unwrap()
        .expect("request row")
}

/// The VTC's step 1 / step 2 response is signed for `assertionMethod` by its
/// own key (contract C5).
fn assert_vtc_attested(f: &Fixture, doc: &Value) {
    let proof: DataIntegrityProof = serde_json::from_value(doc["proof"].clone()).unwrap();
    assert_eq!(proof.proof_purpose, "assertionMethod");
    assert!(proof.verification_method.starts_with(VTC_DID));
    let mut unsigned = doc.clone();
    unsigned.as_object_mut().unwrap().remove("proof");
    proof
        .verify_with_public_key(&unsigned, f.signer.public_bytes(), VerifyOptions::new())
        .expect("the VTC's signature verifies");
}

/// Claim, read the number from the browser's poll, and return it.
async fn claim_and_number(f: &Fixture, b: &Browser, p: &Phone, id: &str) -> (Value, String) {
    let c = claim(f, p, id).await;
    assert_eq!(c.status, StatusCode::OK, "{}", c.body);
    let r = redeem(f, b, id).await;
    assert_eq!(code(&r), "auth/oob/redeem:pending", "{}", r.body);
    assert_eq!(r.body["payload"]["details"]["state"], "claimed");
    let n = r.body["payload"]["details"]["matchNumber"]
        .as_str()
        .expect("number once claimed")
        .to_string();
    (c.body, n)
}

#[tokio::test]
async fn wallet_sign_in_end_to_end_sets_a_member_session_bound_to_k_b() {
    let f = fixture().await;
    let member = Party::new();
    enrol_member(&f.vtc, &member.did, Some("Alice")).await;
    let b = Browser {
        key: Party::new(),
        ip: "198.51.100.7",
    };
    let p = Phone {
        key: Party::new(),
        ip: "198.51.100.7",
    };

    let id = start(&f, &b).await;
    // Before a claim the browser learns only that it waits — no number.
    let r = redeem(&f, &b, &id).await;
    assert_eq!(code(&r), "auth/oob/redeem:pending");
    assert_eq!(r.body["payload"]["details"]["state"], "pending");
    assert!(r.body["payload"]["details"].get("matchNumber").is_none());

    let (step1, number) = claim_and_number(&f, &b, &p, &id).await;
    assert_vtc_attested(&f, &step1);
    let s1 = &step1["payload"];
    assert_eq!(s1["requestId"], id.as_str());
    assert_eq!(s1["service"]["did"], VTC_DID);
    assert_eq!(s1["origin"], PORTAL);
    assert_eq!(s1["purpose"], "login");
    assert!(s1["decisionDeadline"].as_u64().is_some());
    // Step 1 says nothing about the browser.
    assert!(s1.get("sessionKey").is_none() && s1.get("requester").is_none());

    let pr = prove(&f, &p, identify(&member, &id, &p.key.did, &number).await).await;
    assert_eq!(pr.status, StatusCode::OK, "{}", pr.body);
    assert_vtc_attested(&f, &pr.body);
    let s2 = &pr.body["payload"];
    for k in [
        "requestId",
        "service",
        "origin",
        "purpose",
        "decisionDeadline",
    ] {
        assert_eq!(s2[k], s1[k], "step 2 repeats step 1's {k}");
    }
    assert_eq!(s2["sessionKey"], b.key.did.as_str());
    assert_eq!(s2["identifiedAs"], member.did.as_str());
    assert_eq!(s2["requester"]["browser"], "Chrome");
    assert_eq!(s2["requester"]["os"], "macOS");
    assert_eq!(s2["requester"]["location"], "unknown");
    assert_eq!(s2["requester"]["sameNetwork"], true);
    assert!(
        !pr.body.to_string().contains("198.51.100.7"),
        "never the address"
    );

    let digest = oob::context_digest(&pr.body).unwrap();
    assert!(digest.starts_with('z'));
    let g = grant(
        &member,
        &id,
        "approve",
        &b.key.did,
        &p.key.did,
        PORTAL,
        &digest,
        "assertionMethod",
    )
    .await;
    let rs = respond(&f, &p, g).await;
    assert_eq!(rs.status, StatusCode::OK, "{}", rs.body);
    assert_eq!(rs.body["payload"]["status"], "approved");
    assert!(!rs.body.to_string().contains("vtc_member_session"));

    let done = redeem(&f, &b, &id).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    assert_eq!(done.cache_control.as_deref(), Some("no-store"));
    let body = &done.body["payload"];
    assert_eq!(body["subject"], member.did.as_str());
    assert_eq!(body["displayName"], "Alice");
    assert_eq!(body["amr"], json!(["did", "oob", "uv"]));
    assert!(body["notAfter"].as_u64().unwrap() <= now_epoch() + 3600);
    // No tokens in the body; the session is in HttpOnly cookies.
    assert!(body.get("accessToken").is_none() && body.get("sessionId").is_none());
    let session = done
        .cookies
        .iter()
        .find(|c| c.starts_with("vtc_member_session="))
        .expect("session cookie");
    assert!(session.contains("HttpOnly") && session.contains("Secure"));
    assert_eq!(record(&f, &id).await.state, OobState::Consumed);

    // The cookie opens the portal as the member, wallet-proven.
    let token = session
        .split(';')
        .next()
        .unwrap()
        .trim_start_matches("vtc_member_session=");
    let req = Request::builder()
        .uri("/v1/member/me")
        .header("cookie", format!("vtc_member_session={token}"))
        .body(Body::empty())
        .unwrap();
    let res = f.vtc.router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let me: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(me["did"], member.did.as_str());
    assert_eq!(me["canManagePasskeys"], true);

    // Single use: a second redeem gets nothing.
    let again = redeem(&f, &b, &id).await;
    assert_eq!(code(&again), "auth/oob:alreadyDecided");
    assert!(again.cookies.is_empty());
}

#[tokio::test]
async fn request_only_from_the_portal_origin_and_only_by_an_ed25519_did_key() {
    let f = fixture().await;
    let b = Party::new();
    let body = op(
        &b,
        "request",
        json!({ "purpose": "login", "mode": "scan" }),
        None,
    )
    .await;
    let r = post(&f.vtc, &body, "203.0.113.1", Some("https://evil.example")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    let body = op(
        &b,
        "request",
        json!({ "purpose": "login", "mode": "scan" }),
        None,
    )
    .await;
    let r = post(&f.vtc, &body, "203.0.113.1", None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    let body = op(
        &b,
        "request",
        json!({ "purpose": "step-up", "mode": "scan" }),
        None,
    )
    .await;
    let r = post(&f.vtc, &body, "203.0.113.1", Some(PORTAL)).await;
    assert_eq!(code(&r), "auth/oob/request:purposeUnsupported");

    // T21: a did:webvh signer is refused before its proof is read.
    let mut forged = op(
        &b,
        "request",
        json!({ "purpose": "login", "mode": "scan" }),
        None,
    )
    .await;
    forged["issuer"] = json!("did:webvh:abc:attacker.example");
    let r = post(&f.vtc, &forged, "203.0.113.1", Some(PORTAL)).await;
    assert_eq!(code(&r), "auth/oob:keyUnsupported", "{}", r.body);
}

#[tokio::test]
async fn bystander_claim_locks_the_request_and_cannot_pass_step_2() {
    let f = fixture().await;
    let member = Party::new();
    enrol_member(&f.vtc, &member.did, None).await;
    let b = Browser {
        key: Party::new(),
        ip: "198.51.100.10",
    };
    let bystander = Phone {
        key: Party::new(),
        ip: "203.0.113.20",
    };
    let owner = Phone {
        key: Party::new(),
        ip: "198.51.100.10",
    };
    let id = start(&f, &b).await;

    // The bystander claims first; the member's own scan is refused with no
    // details (T3).
    let (_, number) = claim_and_number(&f, &b, &bystander, &id).await;
    let second = claim(&f, &owner, &id).await;
    assert_eq!(
        code(&second),
        "auth/oob/claim:alreadyClaimed",
        "{}",
        second.body
    );
    assert!(second.body["payload"].get("details").is_none());

    // Not a member: generic refusal, and the request ends (T15).
    let stranger = Party::new();
    let r = prove(
        &f,
        &bystander,
        identify(&stranger, &id, &bystander.key.did, &number).await,
    )
    .await;
    assert_eq!(code(&r), "auth/oob:notAuthorized", "{}", r.body);
    assert_eq!(record(&f, &id).await.state, OobState::Declined);
    let r = redeem(&f, &b, &id).await;
    assert_eq!(code(&r), "auth/oob/redeem:declined");
}

#[tokio::test]
async fn a_wrong_number_declines_the_request() {
    let f = fixture().await;
    let member = Party::new();
    enrol_member(&f.vtc, &member.did, None).await;
    let b = Browser {
        key: Party::new(),
        ip: "198.51.100.11",
    };
    let p = Phone {
        key: Party::new(),
        ip: "198.51.100.12",
    };
    let id = start(&f, &b).await;
    let (_, number) = claim_and_number(&f, &b, &p, &id).await;
    let wrong = format!("{:02}", (number.parse::<u32>().unwrap() + 1) % 100);

    let r = prove(&f, &p, identify(&member, &id, &p.key.did, &wrong).await).await;
    assert_eq!(code(&r), "auth/oob/prove:numberMismatch", "{}", r.body);
    assert_eq!(record(&f, &id).await.state, OobState::Declined);
    // One attempt per request: the right number afterwards does not help.
    let r = prove(&f, &p, identify(&member, &id, &p.key.did, &number).await).await;
    assert_ne!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn only_the_lock_holder_k_a_may_prove() {
    let f = fixture().await;
    let member = Party::new();
    enrol_member(&f.vtc, &member.did, None).await;
    let b = Browser {
        key: Party::new(),
        ip: "198.51.100.13",
    };
    let p = Phone {
        key: Party::new(),
        ip: "198.51.100.14",
    };
    let other = Phone {
        key: Party::new(),
        ip: "198.51.100.15",
    };
    let id = start(&f, &b).await;
    let (_, number) = claim_and_number(&f, &b, &p, &id).await;

    // Another key wrapping the member's identify: refused, nothing changes (T6).
    let r = prove(
        &f,
        &other,
        identify(&member, &id, &p.key.did, &number).await,
    )
    .await;
    assert_eq!(code(&r), "auth/oob:notClaimant", "{}", r.body);
    assert_eq!(record(&f, &id).await.state, OobState::Claimed);

    // An identify naming a different lock, from the lock holder: declined.
    let r = prove(
        &f,
        &p,
        identify(&member, &id, &other.key.did, &number).await,
    )
    .await;
    assert_eq!(code(&r), "auth/oob:notAuthorized");
    assert_eq!(record(&f, &id).await.state, OobState::Declined);
}

#[tokio::test]
async fn identify_signed_for_assertion_method_is_refused() {
    // Contract C5: identify is verified against `authentication`.
    let f = fixture().await;
    let member = Party::new();
    enrol_member(&f.vtc, &member.did, None).await;
    let b = Browser {
        key: Party::new(),
        ip: "198.51.100.16",
    };
    let p = Phone {
        key: Party::new(),
        ip: "198.51.100.17",
    };
    let id = start(&f, &b).await;
    let (_, number) = claim_and_number(&f, &b, &p, &id).await;
    let wrong_purpose = doc(
        &member,
        &t("identify"),
        json!({ "requestId": id, "approverKey": p.key.did, "enteredNumber": number }),
        None,
        "assertionMethod",
    )
    .await;
    let r = prove(&f, &p, wrong_purpose).await;
    assert_eq!(code(&r), "auth/oob:notAuthorized");
}

/// Claim and prove; returns the step 2 digest.
async fn to_identified(f: &Fixture, b: &Browser, p: &Phone, member: &Party, id: &str) -> String {
    let (_, number) = claim_and_number(f, b, p, id).await;
    let pr = prove(f, p, identify(member, id, &p.key.did, &number).await).await;
    assert_eq!(pr.status, StatusCode::OK, "{}", pr.body);
    oob::context_digest(&pr.body).unwrap()
}

#[tokio::test]
async fn a_grant_for_another_context_is_refused_and_ends_the_request() {
    let f = fixture().await;
    let member = Party::new();
    enrol_member(&f.vtc, &member.did, None).await;
    let b = Browser {
        key: Party::new(),
        ip: "198.51.100.18",
    };
    let p = Phone {
        key: Party::new(),
        ip: "198.51.100.19",
    };
    let id = start(&f, &b).await;
    let _digest = to_identified(&f, &b, &p, &member, &id).await;

    // A digest of something the member was not shown (T9).
    let other_digest = oob::context_digest(&json!({ "not": "step 2" })).unwrap();
    let g = grant(
        &member,
        &id,
        "approve",
        &b.key.did,
        &p.key.did,
        PORTAL,
        &other_digest,
        "assertionMethod",
    )
    .await;
    let r = respond(&f, &p, g).await;
    assert_eq!(code(&r), "auth/oob/respond:contextMismatch", "{}", r.body);
    assert_eq!(record(&f, &id).await.state, OobState::Declined);
    let r = redeem(&f, &b, &id).await;
    assert_eq!(code(&r), "auth/oob/redeem:declined");
}

#[tokio::test]
async fn a_grant_naming_another_browser_key_is_refused() {
    let f = fixture().await;
    let member = Party::new();
    enrol_member(&f.vtc, &member.did, None).await;
    let b = Browser {
        key: Party::new(),
        ip: "198.51.100.20",
    };
    let p = Phone {
        key: Party::new(),
        ip: "198.51.100.21",
    };
    let id = start(&f, &b).await;
    let digest = to_identified(&f, &b, &p, &member, &id).await;
    let attacker = Party::new();
    let g = grant(
        &member,
        &id,
        "approve",
        &attacker.did,
        &p.key.did,
        PORTAL,
        &digest,
        "assertionMethod",
    )
    .await;
    let r = respond(&f, &p, g).await;
    assert_eq!(code(&r), "auth/oob/respond:contextMismatch");
}

#[tokio::test]
async fn a_grant_must_be_an_assertion_method_attestation() {
    // Contract C5: the grant is verified against `assertionMethod`.
    let f = fixture().await;
    let member = Party::new();
    enrol_member(&f.vtc, &member.did, None).await;
    let b = Browser {
        key: Party::new(),
        ip: "198.51.100.22",
    };
    let p = Phone {
        key: Party::new(),
        ip: "198.51.100.23",
    };
    let id = start(&f, &b).await;
    let digest = to_identified(&f, &b, &p, &member, &id).await;
    let g = grant(
        &member,
        &id,
        "approve",
        &b.key.did,
        &p.key.did,
        PORTAL,
        &digest,
        "authentication",
    )
    .await;
    let r = respond(&f, &p, g).await;
    assert_eq!(code(&r), "auth/oob:notAuthorized", "{}", r.body);
    assert_eq!(record(&f, &id).await.state, OobState::Declined);
}

#[tokio::test]
async fn a_member_decline_ends_the_request() {
    let f = fixture().await;
    let member = Party::new();
    enrol_member(&f.vtc, &member.did, None).await;
    let b = Browser {
        key: Party::new(),
        ip: "198.51.100.24",
    };
    let p = Phone {
        key: Party::new(),
        ip: "198.51.100.25",
    };
    let id = start(&f, &b).await;
    let digest = to_identified(&f, &b, &p, &member, &id).await;
    let g = grant(
        &member,
        &id,
        "decline",
        &b.key.did,
        &p.key.did,
        PORTAL,
        &digest,
        "assertionMethod",
    )
    .await;
    let r = respond(&f, &p, g).await;
    assert_eq!(r.body["payload"]["status"], "declined", "{}", r.body);
    let r = redeem(&f, &b, &id).await;
    assert_eq!(code(&r), "auth/oob/redeem:declined");
    assert_eq!(r.body["payload"]["details"]["state"], "declined");
}

#[tokio::test]
async fn replays_are_refused() {
    let f = fixture().await;
    let member = Party::new();
    enrol_member(&f.vtc, &member.did, None).await;
    let b = Browser {
        key: Party::new(),
        ip: "198.51.100.26",
    };
    let p = Phone {
        key: Party::new(),
        ip: "198.51.100.27",
    };
    let id = start(&f, &b).await;

    // A claim's handle must travel as parentThreadId (VTI-LNK-054).
    let unthreaded = op(&p.key, "claim", json!({ "requestId": id }), None).await;
    let r = post(&f.vtc, &unthreaded, p.ip, None).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.body);
    assert_eq!(record(&f, &id).await.state, OobState::Pending);

    // The same claim document twice is one claim: the redelivery is answered
    // with the original response, and the lock does not move.
    let first = op(&p.key, "claim", json!({ "requestId": id }), Some(&id)).await;
    let a = post(&f.vtc, &first, p.ip, None).await;
    let again = post(&f.vtc, &first, p.ip, None).await;
    assert_eq!(a.status, StatusCode::OK);
    assert_eq!(again.body, a.body);
    let number = record(&f, &id).await.match_number.unwrap();

    // A carried identify is spent once: replaying it in a fresh prove from
    // the lock holder ends the request.
    let ident = identify(&member, &id, &p.key.did, &number).await;
    let ok = prove(&f, &p, ident.clone()).await;
    assert_eq!(ok.status, StatusCode::OK);
    let digest = oob::context_digest(&ok.body).unwrap();
    // A second prove on an identified request is refused.
    let r = prove(&f, &p, ident).await;
    assert_eq!(code(&r), "auth/oob:notAuthorized");

    // A grant is decided once.
    let g = grant(
        &member,
        &id,
        "approve",
        &b.key.did,
        &p.key.did,
        PORTAL,
        &digest,
        "assertionMethod",
    )
    .await;
    assert_eq!(respond(&f, &p, g.clone()).await.status, StatusCode::OK);
    let r = respond(&f, &p, g).await;
    assert_eq!(code(&r), "auth/oob:alreadyDecided", "{}", r.body);

    // Only the starter's key redeems.
    let thief = Browser {
        key: Party::new(),
        ip: "203.0.113.99",
    };
    let r = redeem(&f, &thief, &id).await;
    assert_eq!(code(&r), "auth/oob:notStarter");
    assert!(r.cookies.is_empty());
    assert_eq!(redeem(&f, &b, &id).await.status, StatusCode::OK);
}

/// Move a request's clocks into the past.
async fn age(f: &Fixture, id: &str, claim: bool) {
    let mut rec = record(f, id).await;
    let past = now_epoch() - 1;
    if claim {
        rec.claim_deadline = past;
    } else {
        rec.decision_deadline = Some(past);
    }
    f.vtc
        .state
        .member_sessions_ks
        .insert(oob::record_key(id), &rec)
        .await
        .unwrap();
}

#[tokio::test]
async fn the_claim_window_expires() {
    let f = fixture().await;
    let b = Browser {
        key: Party::new(),
        ip: "198.51.100.28",
    };
    let p = Phone {
        key: Party::new(),
        ip: "198.51.100.29",
    };
    let id = start(&f, &b).await;
    age(&f, &id, true).await;
    let r = claim(&f, &p, &id).await;
    assert_eq!(code(&r), "auth/oob:requestExpired", "{}", r.body);
    let rec = record(&f, &id).await;
    assert_eq!(rec.state, OobState::Expired);
    assert!(
        rec.start_network.is_none(),
        "the address is dropped when it ends (T22)"
    );
    let r = redeem(&f, &b, &id).await;
    assert_eq!(code(&r), "auth/oob:requestExpired");
}

#[tokio::test]
async fn the_decision_window_expires_after_a_claim() {
    let f = fixture().await;
    let member = Party::new();
    enrol_member(&f.vtc, &member.did, None).await;
    let b = Browser {
        key: Party::new(),
        ip: "198.51.100.30",
    };
    let p = Phone {
        key: Party::new(),
        ip: "198.51.100.31",
    };
    let id = start(&f, &b).await;
    let (_, number) = claim_and_number(&f, &b, &p, &id).await;
    age(&f, &id, false).await;
    let r = prove(&f, &p, identify(&member, &id, &p.key.did, &number).await).await;
    assert_eq!(code(&r), "auth/oob:requestExpired", "{}", r.body);
    assert_eq!(record(&f, &id).await.state, OobState::Expired);
}

#[tokio::test]
async fn a_cancelled_request_redeems_as_declined_with_state_cancelled() {
    let f = fixture().await;
    let b = Browser {
        key: Party::new(),
        ip: "198.51.100.32",
    };
    let p = Phone {
        key: Party::new(),
        ip: "198.51.100.33",
    };
    let id = start(&f, &b).await;
    claim_and_number(&f, &b, &p, &id).await;
    // A stranger cannot cancel.
    let stranger = Party::new();
    let r = post(
        &f.vtc,
        &op(&stranger, "cancel", json!({ "requestId": id }), None).await,
        "203.0.113.40",
        None,
    )
    .await;
    assert_eq!(code(&r), "auth/oob:notAuthorized");
    // The starter can.
    let r = post(
        &f.vtc,
        &op(&b.key, "cancel", json!({ "requestId": id }), None).await,
        b.ip,
        Some(PORTAL),
    )
    .await;
    assert_eq!(r.body["payload"]["status"], "cancelled", "{}", r.body);
    let r = redeem(&f, &b, &id).await;
    assert_eq!(code(&r), "auth/oob/redeem:declined");
    assert_eq!(r.body["payload"]["details"]["state"], "cancelled");
}

#[tokio::test]
async fn bare_identify_and_grant_documents_are_not_tasks() {
    let f = fixture().await;
    let member = Party::new();
    let r = post(
        &f.vtc,
        &identify(&member, "x", "did:key:z6Mkx", "00").await,
        "203.0.113.41",
        None,
    )
    .await;
    assert_eq!(code(&r), "unsupportedType", "{}", r.body);
}

#[tokio::test]
async fn sign_in_config_names_the_link_host_and_the_member_page_is_hardened() {
    let f = fixture().await;
    let req = Request::builder()
        .uri("/v1/member/sign-in/config")
        .body(Body::empty())
        .unwrap();
    let res = f.vtc.router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let v: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(v["vtcDid"], VTC_DID);
    assert_eq!(v["linkHost"], "link.trustoverip.org");
    assert_eq!(v["flow"], "/vti/flow/sign-in/0.1");

    // Both pages that show a trigger link: the portal, and the console's
    // login page (VTI-LNK-082).
    for page in ["/members/", "/admin/"] {
        let req = Request::builder().uri(page).body(Body::empty()).unwrap();
        let res = f.vtc.router.clone().oneshot(req).await.unwrap();
        let h = res.headers();
        assert_eq!(h["referrer-policy"], "no-referrer", "{page}");
        assert_eq!(h["cache-control"], "no-store", "{page}");
        assert!(
            h["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'"),
            "{page}"
        );
    }
}

// ── Operator console: the `admin` session audience ──────────────────────────
//
// The console's login page asks for an admin session by putting
// `ext["org.openvtc.session"].audience = "admin"` on the request. The VTC
// repeats it, signed, in step 1 and step 2, so the grant's `contextDigest`
// covers it, and `redeem` issues the console's session — for an administrator
// only — and never the portal's. A request without it is a member sign-in,
// exactly as before (T19).

const SESSION_EXT: &str = "org.openvtc.session";
const WHOAMI_TASK: &str = "https://trusttasks.org/spec/auth/whoami/0.1";

fn admin_ext() -> Value {
    json!({ SESSION_EXT: { "audience": "admin" } })
}

/// An administrator's ACL entry, with no member record: the console's gate
/// is the ACL role, not membership.
async fn enrol_admin(vtc: &TestVtc, did: &str, label: Option<&str>) {
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            admin: VtcRole::Admin.implied_authority(),
            role: VtcRole::Admin,
            label: label.map(str::to_string),
            delegated_by: None,
            created_at: now_epoch(),
            created_by: "test".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
            resource_grants: Vec::new(),
            label_set_by_subject: false,
            suspension: None,
        },
    )
    .await
    .unwrap();
}

/// Open a request with the given `ext`, from the portal's origin.
async fn start_with(f: &Fixture, b: &Browser, ext: Option<Value>) -> Reply {
    let mut payload = json!({ "purpose": "login", "mode": "scan" });
    if let Some(ext) = ext {
        payload["ext"] = ext;
    }
    post(
        &f.vtc,
        &op(&b.key, "request", payload, None).await,
        b.ip,
        Some(PORTAL),
    )
    .await
}

/// Open an operator-console request; the VTC echoes the audience it read.
async fn start_admin(f: &Fixture, b: &Browser) -> String {
    let r = start_with(f, b, Some(admin_ext())).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(
        r.body["payload"]["ext"],
        admin_ext(),
        "the audience is echoed"
    );
    r.body["payload"]["requestId"].as_str().unwrap().to_string()
}

/// Claim, prove, and approve with a grant over the real step 2.
async fn approve(f: &Fixture, b: &Browser, p: &Phone, who: &Party, id: &str) -> Value {
    let (_, number) = claim_and_number(f, b, p, id).await;
    let pr = prove(f, p, identify(who, id, &p.key.did, &number).await).await;
    assert_eq!(pr.status, StatusCode::OK, "{}", pr.body);
    let digest = oob::context_digest(&pr.body).unwrap();
    let g = grant(
        who,
        id,
        "approve",
        &b.key.did,
        &p.key.did,
        PORTAL,
        &digest,
        "assertionMethod",
    )
    .await;
    let rs = respond(f, p, g).await;
    assert_eq!(rs.status, StatusCode::OK, "{}", rs.body);
    pr.body
}

fn cookie_value<'a>(r: &'a Reply, name: &str) -> Option<&'a str> {
    r.cookies.iter().find_map(|c| {
        c.split(';')
            .next()
            .and_then(|kv| kv.strip_prefix(&format!("{name}=")))
    })
}

async fn whoami_with_admin_cookie(f: &Fixture, token: &str) -> StatusCode {
    let req = Request::builder()
        .uri("/v1/auth/whoami")
        .header("Trust-Task", WHOAMI_TASK)
        .header("cookie", format!("vtc_admin_session={token}"))
        .body(Body::empty())
        .unwrap();
    f.vtc.router.clone().oneshot(req).await.unwrap().status()
}

async fn member_me_with_cookie(f: &Fixture, token: &str) -> StatusCode {
    let req = Request::builder()
        .uri("/v1/member/me")
        .header("cookie", format!("vtc_member_session={token}"))
        .body(Body::empty())
        .unwrap();
    f.vtc.router.clone().oneshot(req).await.unwrap().status()
}

fn browser(ip: &'static str) -> Browser {
    Browser {
        key: Party::new(),
        ip,
    }
}

fn phone(ip: &'static str) -> Phone {
    Phone {
        key: Party::new(),
        ip,
    }
}

#[tokio::test]
async fn an_admin_request_by_an_administrator_opens_a_console_session() {
    let f = fixture().await;
    let admin = Party::new();
    enrol_admin(&f.vtc, &admin.did, Some("Operator Olu")).await;
    let b = browser("198.51.100.60");
    let p = phone("198.51.100.60");

    let id = start_admin(&f, &b).await;
    assert_eq!(record(&f, &id).await.audience, oob::SessionAudience::Admin);

    // Step 1 says so, signed: the wallet can show "operator console".
    let (step1, number) = claim_and_number(&f, &b, &p, &id).await;
    assert_vtc_attested(&f, &step1);
    assert_eq!(step1["payload"]["ext"], admin_ext());
    assert_eq!(step1["payload"]["purpose"], "login", "purpose is unchanged");

    // Step 2 repeats it, so the grant's contextDigest covers it.
    let pr = prove(&f, &p, identify(&admin, &id, &p.key.did, &number).await).await;
    assert_eq!(pr.status, StatusCode::OK, "{}", pr.body);
    assert_vtc_attested(&f, &pr.body);
    assert_eq!(pr.body["payload"]["ext"], admin_ext());
    let digest = oob::context_digest(&pr.body).unwrap();
    let g = grant(
        &admin,
        &id,
        "approve",
        &b.key.did,
        &p.key.did,
        PORTAL,
        &digest,
        "assertionMethod",
    )
    .await;
    let rs = respond(&f, &p, g).await;
    assert_eq!(rs.status, StatusCode::OK, "{}", rs.body);

    let done = redeem(&f, &b, &id).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    let body = &done.body["payload"];
    assert_eq!(body["subject"], admin.did.as_str());
    assert_eq!(body["displayName"], "Operator Olu");
    assert_eq!(body["amr"], json!(["did", "oob", "uv"]));
    assert_eq!(
        body["ext"],
        admin_ext(),
        "the redeem says which session it is"
    );
    assert!(body.get("accessToken").is_none(), "no tokens in the body");

    // The console's cookie trio, as passkey login sets it — and nothing of
    // the portal's.
    let session = done
        .cookies
        .iter()
        .find(|c| c.starts_with("vtc_admin_session="))
        .expect("admin session cookie");
    for flag in ["Path=/;", "SameSite=Strict", "Secure", "HttpOnly"] {
        assert!(session.contains(flag), "{flag} in {session}");
    }
    assert!(cookie_value(&done, "csrf").is_some(), "csrf cookie");
    assert!(
        done.cookies
            .iter()
            .any(|c| c.starts_with(vti_common::auth::extractor::ADMIN_REFRESH_COOKIE)),
        "refresh cookie"
    );
    assert!(cookie_value(&done, "vtc_member_session").is_none());
    assert_eq!(record(&f, &id).await.state, OobState::Consumed);

    // It opens the console (audience `VTC`) and not the portal.
    let token = cookie_value(&done, "vtc_admin_session").unwrap();
    assert_eq!(whoami_with_admin_cookie(&f, token).await, StatusCode::OK);
    assert_eq!(
        member_me_with_cookie(&f, token).await,
        StatusCode::UNAUTHORIZED
    );

    // The session row is a console session, in the console's keyspace.
    let sessions = vtc_service::auth::session::list_sessions(&f.vtc.state.sessions_ks)
        .await
        .unwrap();
    let s = sessions
        .iter()
        .find(|s| s.did == admin.did)
        .expect("console session row");
    assert_eq!(s.amr, vec!["did", "oob", "uv"]);
    assert_eq!(s.acr, "aal2");
}

#[tokio::test]
async fn an_admin_request_by_a_member_only_did_is_declined_with_no_session() {
    let f = fixture().await;
    let member = Party::new();
    enrol_member(&f.vtc, &member.did, None).await;
    let b = browser("198.51.100.61");
    let p = phone("198.51.100.62");

    let id = start_admin(&f, &b).await;
    let (_, number) = claim_and_number(&f, &b, &p, &id).await;
    // The member proved the DID is theirs, so they are told why.
    let pr = prove(&f, &p, identify(&member, &id, &p.key.did, &number).await).await;
    assert_eq!(code(&pr), "auth/oob:notAuthorized", "{}", pr.body);
    assert_eq!(pr.body["payload"]["details"]["reason"], "notAnAdmin");
    assert_eq!(
        pr.body["payload"]["message"],
        "This identity isn't an administrator of this community."
    );
    // The request is spent.
    let rec = record(&f, &id).await;
    assert_eq!(rec.state, OobState::Declined);
    assert_eq!(rec.decline_reason.as_deref(), Some("notAnAdmin"));

    // The console is told the same, and gets no session of either kind.
    let r = redeem(&f, &b, &id).await;
    assert_eq!(code(&r), "auth/oob/redeem:declined", "{}", r.body);
    assert_eq!(r.body["payload"]["details"]["state"], "declined");
    assert_eq!(r.body["payload"]["details"]["reason"], "notAnAdmin");
    assert!(r.cookies.is_empty(), "{:?}", r.cookies);
    let sessions = vtc_service::auth::session::list_sessions(&f.vtc.state.sessions_ks)
        .await
        .unwrap();
    assert!(sessions.iter().all(|s| s.did != member.did));
}

#[tokio::test]
async fn an_administrator_removed_after_approving_is_declined_at_redeem() {
    let f = fixture().await;
    let admin = Party::new();
    enrol_admin(&f.vtc, &admin.did, None).await;
    let b = browser("198.51.100.63");
    let p = phone("198.51.100.64");
    let id = start_admin(&f, &b).await;
    approve(&f, &b, &p, &admin, &id).await;

    vtc_service::acl::delete_acl_entry(&f.vtc.state.acl_ks, &admin.did)
        .await
        .unwrap();
    let r = redeem(&f, &b, &id).await;
    assert_eq!(code(&r), "auth/oob/redeem:declined", "{}", r.body);
    assert_eq!(r.body["payload"]["details"]["reason"], "notAnAdmin");
    assert!(r.cookies.is_empty());
    // Spent: it cannot be redeemed again once the entry is back.
    enrol_admin(&f.vtc, &admin.did, None).await;
    assert_eq!(record(&f, &id).await.state, OobState::Consumed);
    let again = redeem(&f, &b, &id).await;
    assert_eq!(code(&again), "auth/oob:alreadyDecided");
    assert!(again.cookies.is_empty());
}

#[tokio::test]
async fn a_member_request_by_an_administrator_gives_a_member_session_only() {
    let f = fixture().await;
    let both = Party::new();
    // An administrator who is also a member.
    enrol_admin(&f.vtc, &both.did, Some("Both")).await;
    store_member(&f.vtc.state.members_ks, &Member::fresh(&both.did))
        .await
        .unwrap();
    let b = browser("198.51.100.65");
    let p = phone("198.51.100.66");

    let r = start_with(&f, &b, None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(
        r.body["payload"].get("ext").is_none(),
        "unchanged for members"
    );
    let id = r.body["payload"]["requestId"].as_str().unwrap().to_string();
    let step2 = approve(&f, &b, &p, &both, &id).await;
    // A member sign-in's responses carry no extension, as before.
    assert!(step2["payload"].get("ext").is_none());

    let done = redeem(&f, &b, &id).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    assert!(done.body["payload"].get("ext").is_none());
    let token = cookie_value(&done, "vtc_member_session").expect("member session");
    assert!(cookie_value(&done, "vtc_admin_session").is_none());
    assert!(
        cookie_value(&done, "csrf").is_none(),
        "the console's csrf is not set"
    );
    // The member token does not open the console (T19).
    assert_eq!(
        whoami_with_admin_cookie(&f, token).await,
        StatusCode::UNAUTHORIZED
    );
    let sessions = vtc_service::auth::session::list_sessions(&f.vtc.state.sessions_ks)
        .await
        .unwrap();
    assert!(
        sessions.iter().all(|s| s.did != both.did),
        "no console session"
    );

    // `"member"` named explicitly is the same.
    let r = start_with(
        &f,
        &browser("198.51.100.67"),
        Some(json!({ SESSION_EXT: { "audience": "member" } })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let id = r.body["payload"]["requestId"].as_str().unwrap();
    assert_eq!(record(&f, id).await.audience, oob::SessionAudience::Member);
}

#[tokio::test]
async fn an_unknown_audience_is_refused_and_other_ext_members_are_ignored() {
    let f = fixture().await;
    let b = browser("198.51.100.68");
    for bad in [
        json!({ SESSION_EXT: { "audience": "superuser" } }),
        json!({ SESSION_EXT: "admin" }),
        json!({ SESSION_EXT: {} }),
    ] {
        let r = start_with(&f, &b, Some(bad.clone())).await;
        assert_eq!(code(&r), "malformedRequest", "{bad}: {}", r.body);
    }
    // Someone else's namespace is carried through unread.
    let r = start_with(
        &f,
        &b,
        Some(json!({ "com.example": { "audience": "admin" } })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let id = r.body["payload"]["requestId"].as_str().unwrap();
    assert_eq!(record(&f, id).await.audience, oob::SessionAudience::Member);
}

#[tokio::test]
async fn the_audience_cannot_be_altered_after_the_claim() {
    let f = fixture().await;
    let admin = Party::new();
    enrol_admin(&f.vtc, &admin.did, None).await;
    store_member(&f.vtc.state.members_ks, &Member::fresh(&admin.did))
        .await
        .unwrap();

    // 1. A wallet's documents cannot ask for another audience: an `ext` on
    //    the claim or prove is not read.
    let b = browser("198.51.100.70");
    let p = phone("198.51.100.71");
    let r = start_with(&f, &b, None).await;
    let id = r.body["payload"]["requestId"].as_str().unwrap().to_string();
    let c = post(
        &f.vtc,
        &op(
            &p.key,
            "claim",
            json!({ "requestId": id, "ext": admin_ext() }),
            Some(&id),
        )
        .await,
        p.ip,
        None,
    )
    .await;
    assert_eq!(c.status, StatusCode::OK, "{}", c.body);
    assert!(c.body["payload"].get("ext").is_none());
    assert_eq!(record(&f, &id).await.audience, oob::SessionAudience::Member);

    // 2. A grant over a step 2 whose audience was changed is a grant for
    //    something the member was not shown: refused, and the request ends.
    let rr = redeem(&f, &b, &id).await;
    let number = rr.body["payload"]["details"]["matchNumber"]
        .as_str()
        .unwrap()
        .to_string();
    let pr = prove(&f, &p, identify(&admin, &id, &p.key.did, &number).await).await;
    assert_eq!(pr.status, StatusCode::OK, "{}", pr.body);
    let mut altered = pr.body.clone();
    altered["payload"]["ext"] = admin_ext();
    let g = grant(
        &admin,
        &id,
        "approve",
        &b.key.did,
        &p.key.did,
        PORTAL,
        &oob::context_digest(&altered).unwrap(),
        "assertionMethod",
    )
    .await;
    let rs = respond(&f, &p, g).await;
    assert_eq!(code(&rs), "auth/oob/respond:contextMismatch", "{}", rs.body);
    assert_eq!(record(&f, &id).await.state, OobState::Declined);

    // 3. A record altered after the approval issues nothing: the audience
    //    `redeem` acts on must be the one the member's grant covered.
    //    A member approval can't become a console session…
    let b = browser("198.51.100.72");
    let p = phone("198.51.100.73");
    let r = start_with(&f, &b, None).await;
    let id = r.body["payload"]["requestId"].as_str().unwrap().to_string();
    approve(&f, &b, &p, &admin, &id).await;
    oob::transition(&f.vtc.state.member_sessions_ks, &id, |r| {
        r.audience = oob::SessionAudience::Admin;
        Ok::<_, ()>(())
    })
    .await
    .unwrap();
    let done = redeem(&f, &b, &id).await;
    assert_eq!(code(&done), "auth/oob:notAuthorized", "{}", done.body);
    assert!(done.cookies.is_empty(), "{:?}", done.cookies);

    //    …nor a console approval a member session.
    let b = browser("198.51.100.74");
    let p = phone("198.51.100.75");
    let id = start_admin(&f, &b).await;
    approve(&f, &b, &p, &admin, &id).await;
    oob::transition(&f.vtc.state.member_sessions_ks, &id, |r| {
        r.audience = oob::SessionAudience::Member;
        Ok::<_, ()>(())
    })
    .await
    .unwrap();
    let done = redeem(&f, &b, &id).await;
    assert_eq!(code(&done), "auth/oob:notAuthorized", "{}", done.body);
    assert!(done.cookies.is_empty(), "{:?}", done.cookies);
    let sessions = vtc_service::auth::session::list_sessions(&f.vtc.state.sessions_ks)
        .await
        .unwrap();
    assert!(sessions.iter().all(|s| s.did != admin.did));
}

#[tokio::test]
async fn a_request_stored_before_the_audience_existed_loads_as_a_member_sign_in() {
    let f = fixture().await;
    // A row exactly as the previous release wrote it: no `audience`, no
    // `declineReason`.
    let id = oob::new_request_id();
    let old = json!({
        "requestId": id,
        "state": "pending",
        "startKey": Party::new().did,
        "startNetwork": "198.51.100.80",
        "purpose": "login",
        "mode": "scan",
        "origin": PORTAL,
        "matchNumberDelivered": false,
        "requester": {
            "location": "unknown",
            "browser": "Chrome",
            "os": "macOS",
            "createdAt": "2026-10-10T00:00:00Z"
        },
        "createdAt": now_epoch(),
        "claimDeadline": now_epoch() + 120
    });
    f.vtc
        .state
        .member_sessions_ks
        .insert(oob::record_key(&id), &old)
        .await
        .unwrap();
    let rec = record(&f, &id).await;
    assert_eq!(rec.audience, oob::SessionAudience::Member);
    assert_eq!(rec.decline_reason, None);
    // And a member row is still written without the new fields.
    let written = serde_json::to_value(&rec).unwrap();
    assert!(written.get("audience").is_none() && written.get("declineReason").is_none());

    // The old row is claimable, and its step 1 is the member one.
    let p = phone("198.51.100.81");
    let c = claim(&f, &p, &id).await;
    assert_eq!(c.status, StatusCode::OK, "{}", c.body);
    assert!(c.body["payload"].get("ext").is_none());
}
