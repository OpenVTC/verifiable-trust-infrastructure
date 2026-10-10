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

    let req = Request::builder()
        .uri("/members/")
        .body(Body::empty())
        .unwrap();
    let res = f.vtc.router.clone().oneshot(req).await.unwrap();
    let h = res.headers();
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert_eq!(h["cache-control"], "no-store");
    assert!(
        h["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
}
