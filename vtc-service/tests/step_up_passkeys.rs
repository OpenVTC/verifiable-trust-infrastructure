//! Members' step-up passkeys (`crate::step_up_passkey`), redeemed and used as
//! Trust Tasks over every transport the VTC serves: DIDComm and TSP through a
//! real mediator, and HTTPS posted to `POST /v1/trust-tasks`.
//!
//! The spine unit tests (`trust_tasks::step_up_passkey_tasks`) drive every
//! task and refusal with each transport's context. This is the rest of the
//! path — the client seals and routes, the mediator forwards, the production
//! listener unpacks and dispatches, and the reply comes back the same way — so
//! a wiring change that strands a task on one transport fails here.
//!
//! On each transport the member whose DID that transport proves:
//!
//! 1. redeems a community administrator's invite, signing
//!    `auth/passkey/enroll/redeem/start/0.1` as themselves;
//! 2. binds the passkey the soft authenticator creates
//!    (`enroll/redeem/finish/0.1`) — over HTTPS unsigned, as the browser that
//!    ran `navigator.credentials.create` sends it;
//! 3. answers an operation-bound step-up asked of them (a break-glass) with a
//!    **signed** `auth/step-up/approve-response` carrying that passkey's
//!    assertion — the passkey beside the member's proof, never instead of it.
//!
//! Requires `--features tsp,didcomm-harness`; CI runs it.

#![cfg(all(feature = "didcomm-harness", feature = "tsp"))]

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use vti_rooms_dtg::test_support::Party;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

use vtc_service::acl::bound_step_up::{self, Gate};
use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::{MockVtcDidcomm, ReplyOutcome, TestTspPeer};

use common::webauthn_harness::SoftEd25519Authenticator;

const REDEEM_START: &str = "https://trusttasks.org/spec/auth/passkey/enroll/redeem/start/0.1";
const REDEEM_FINISH: &str = "https://trusttasks.org/spec/auth/passkey/enroll/redeem/finish/0.1";
const APPROVE_RESPONSE: &str = "https://trusttasks.org/spec/auth/step-up/approve-response/0.4";
const BREAK_GLASS: &str = "https://trusttasks.org/spec/git-ns/right/break-glass/0.1";
/// `MockVtcDidcomm`'s WebAuthn relying party.
const RP_ORIGIN: &str = "https://vtc.test";
const WAIT: Duration = Duration::from_secs(20);
const TRANSPORTS: [&str; 3] = ["didcomm", "tsp", "https"];

struct Harness {
    mock: MockVtcDidcomm,
    tsp: TestTspPeer,
    https: Party,
    /// A community administrator, who issues the invites.
    admin: Party,
}

async fn seed(mock: &MockVtcDidcomm, did: &str, role: VtcRole) {
    store_acl_entry(
        &mock.vtc.state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role,
            label: None,
            allowed_contexts: vec![],
            created_at: 0,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("seed ACL row");
}

async fn harness() -> Harness {
    let mock = MockVtcDidcomm::start_with_tsp().await;
    let tsp = mock.connect_tsp_peer().await;
    let (https, admin) = (Party::new(), Party::new());
    for did in [
        mock.client.did().to_string(),
        tsp.did().to_string(),
        https.did.clone(),
    ] {
        seed(&mock, &did, VtcRole::Member).await;
    }
    seed(&mock, &admin.did, VtcRole::Admin).await;
    Harness {
        mock,
        tsp,
        https,
        admin,
    }
}

/// The member `transport` proves.
fn member(h: &Harness, transport: &str) -> String {
    match transport {
        "didcomm" => h.mock.client.did().to_string(),
        "tsp" => h.tsp.did().to_string(),
        _ => h.https.did.clone(),
    }
}

async fn post(h: &Harness, doc: &impl serde::Serialize) -> Value {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/trust-tasks")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(doc).unwrap()))
        .unwrap();
    let resp = h.mock.vtc.router.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::NOT_FOUND);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("a Trust Task document")
}

/// The reply document to `uri`, signed by the member and sent as `transport`.
async fn send(h: &Harness, transport: &str, uri: &str, payload: Value) -> Value {
    let vtc = h.mock.vtc_did().to_string();
    match transport {
        "didcomm" => match h.mock.client.try_request(&vtc, uri, payload, WAIT).await {
            ReplyOutcome::Reply(doc) => doc,
            ReplyOutcome::Problem(p) => p.body,
            ReplyOutcome::Timeout => panic!("{uri}: no DIDComm reply"),
        },
        "tsp" => h
            .tsp
            .request_tsp(&vtc, uri, payload, WAIT)
            .await
            .unwrap_or_else(|| panic!("{uri}: no TSP reply")),
        "https" => {
            let mut doc =
                vta_sdk::trust_task_sign::build_unsigned(uri, payload, &h.https.did, &vtc).unwrap();
            let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(
                &h.https.did,
                &h.https.secret_multibase,
            )
            .unwrap();
            vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
                .await
                .unwrap();
            post(h, &doc).await
        }
        other => unreachable!("{other}"),
    }
}

fn payload_ok(doc: &Value, what: &str) -> Value {
    assert!(
        !doc["type"]
            .as_str()
            .is_some_and(|t| t.contains("trust-task-error")),
        "{what}: {doc}"
    );
    doc["payload"].clone()
}

/// A webauthn-rs result as the browser's published JSON.
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

fn break_glass() -> Value {
    json!({
        "right": "git.repo.own",
        "resource": "github.com/acme/widgets",
        "justification": "Both owners unreachable; the fix must ship tonight",
    })
}

/// An invite for `did`, issued by the harness's administrator. Its own
/// gesture gate is the spine's, driven in the unit tests; here it is issued
/// directly. `(token, claimCode)`.
async fn invite(h: &Harness, did: &str) -> (String, String) {
    let payload: trust_tasks_rs::specs::auth::passkey::enroll::invite::v0_2::Payload =
        serde_json::from_value(json!({ "subject": did, "purpose": "stepUp" })).unwrap();
    let issued =
        vtc_service::step_up_passkey::issue_invite(&h.mock.vtc.state, &h.admin.did, &payload)
            .await
            .expect("issue the invite");
    (
        String::from(issued.invite.token),
        String::from(issued.claim_code),
    )
}

/// A bound step-up asked of `did`, as a break-glass would ask it.
async fn bound_request(h: &Harness, did: &str) -> Value {
    match bound_step_up::redeem_or_request(
        &h.mock.vtc.state,
        did,
        BREAK_GLASS,
        &break_glass(),
        "break the glass",
    )
    .await
    .unwrap()
    {
        Gate::Required(r) => serde_json::to_value(*r).unwrap(),
        Gate::Satisfied => panic!("nothing was recorded yet"),
    }
}

#[tokio::test]
async fn a_member_enrols_and_uses_a_step_up_passkey_on_every_transport() {
    let h = harness().await;
    for t in TRANSPORTS {
        let did = member(&h, t);
        let mut key = SoftEd25519Authenticator::new();
        let (token, code) = invite(&h, &did).await;

        let started = send(
            &h,
            t,
            REDEEM_START,
            json!({ "token": token, "claimCode": code }),
        )
        .await;
        let started = payload_ok(&started, &format!("{t}: redeem/start"));
        assert_eq!(started["subject"], did, "{t}");
        let ccr: CreationChallengeResponse =
            serde_json::from_value(json!({ "publicKey": started["options"] })).unwrap();
        let (cred, _) = key.register(&ccr, RP_ORIGIN);
        let finish =
            json!({ "enrollmentId": started["enrollmentId"], "credential": published(&cred) });
        let finished = if t == "https" {
            // The browser that made the passkey holds no key of the member's.
            let doc = vta_sdk::trust_task_sign::build_unsigned(
                REDEEM_FINISH,
                finish,
                &did,
                h.mock.vtc_did(),
            )
            .unwrap();
            post(&h, &doc).await
        } else {
            send(&h, t, REDEEM_FINISH, finish).await
        };
        let finished = payload_ok(&finished, &format!("{t}: redeem/finish"));
        assert_eq!(finished["purpose"], "stepUp", "{t}");

        let request = bound_request(&h, &did).await;
        let rcr: RequestChallengeResponse =
            serde_json::from_value(json!({ "publicKey": request["webauthn"] })).unwrap();
        let assertion = key.authenticate(&rcr, RP_ORIGIN);
        let recorded = send(
            &h,
            t,
            APPROVE_RESPONSE,
            json!({
                "subject": did,
                "challenge": request["challenge"],
                "decision": "approved",
                "evidence": { "kind": "webauthn", "assertion": published(&assertion) },
            }),
        )
        .await;
        assert_eq!(
            payload_ok(&recorded, &format!("{t}: approve-response"))["status"],
            "recorded",
            "{t}"
        );
        let spent = bound_step_up::redeem_or_request(
            &h.mock.vtc.state,
            &did,
            BREAK_GLASS,
            &break_glass(),
            "break the glass",
        )
        .await
        .unwrap();
        assert!(matches!(spent, Gate::Satisfied), "{t}");
    }
    h.tsp.shutdown().await;
    h.mock.shutdown().await;
}

/// The assertion alone is not an answer: over HTTPS an unsigned
/// approve-response is refused before the pending step-up is touched, so the
/// member's own signed answer still spends it.
#[tokio::test]
async fn an_unsigned_answer_is_refused_and_leaves_the_step_up_for_the_member() {
    let h = harness().await;
    let did = h.https.did.clone();
    let mut key = SoftEd25519Authenticator::new();
    let (token, code) = invite(&h, &did).await;
    let started = send(
        &h,
        "https",
        REDEEM_START,
        json!({ "token": token, "claimCode": code }),
    )
    .await;
    let started = payload_ok(&started, "redeem/start");
    let ccr: CreationChallengeResponse =
        serde_json::from_value(json!({ "publicKey": started["options"] })).unwrap();
    let (cred, _) = key.register(&ccr, RP_ORIGIN);
    payload_ok(
        &send(
            &h,
            "https",
            REDEEM_FINISH,
            json!({ "enrollmentId": started["enrollmentId"], "credential": published(&cred) }),
        )
        .await,
        "redeem/finish",
    );

    let request = bound_request(&h, &did).await;
    let rcr: RequestChallengeResponse =
        serde_json::from_value(json!({ "publicKey": request["webauthn"] })).unwrap();
    let answer = json!({
        "subject": did,
        "challenge": request["challenge"],
        "decision": "approved",
        "evidence": { "kind": "webauthn", "assertion": published(key.authenticate(&rcr, RP_ORIGIN)) },
    });
    let bare = vta_sdk::trust_task_sign::build_unsigned(
        APPROVE_RESPONSE,
        answer.clone(),
        &did,
        h.mock.vtc_did(),
    )
    .unwrap();
    let refused = post(&h, &bare).await;
    assert_eq!(refused["payload"]["code"], "proofRequired", "{refused}");

    let signed = send(&h, "https", APPROVE_RESPONSE, answer).await;
    assert_eq!(payload_ok(&signed, "signed answer")["status"], "recorded");
    h.tsp.shutdown().await;
    h.mock.shutdown().await;
}

/// No REST route issues, redeems, revokes or lists one: the spine is the
/// only door. The listing is `auth/passkey/admin-list/0.1`, and
/// `GET /v1/admin/step-up-passkeys` is gone.
///
/// An unrouted `GET` is not a 404 here: it falls through to the router's
/// catch-all, like any path nobody serves. So a `GET` must be answered
/// exactly as a path that never existed is — never with the listing.
#[tokio::test]
async fn no_rest_route_issues_redeems_revokes_or_lists_one() {
    let h = harness().await;
    let call = |method: &'static str, path: &'static str| {
        let router = h.mock.vtc.router.clone();
        async move {
            let req = Request::builder()
                .method(method)
                .uri(path)
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .unwrap();
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let content_type = resp
                .headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap_or_default().to_string());
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (status, content_type, body)
        }
    };
    for path in [
        "/v1/admin/step-up-passkeys/invites",
        "/v1/admin/step-up-passkeys/revoke/start",
        "/v1/admin/step-up-passkeys/revoke/finish",
        "/v1/step-up-passkeys/redeem/start",
        "/v1/step-up-passkeys/redeem/finish",
    ] {
        let (status, _, _) = call("POST", path).await;
        assert!(
            matches!(
                status,
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ),
            "{path}: {status}"
        );
    }
    let never = call("GET", "/v1/admin/no-such-route-ever").await;
    for path in [
        "/v1/admin/step-up-passkeys",
        "/v1/admin/step-up-passkeys?subject=did:key:z6Mkcarol",
    ] {
        let (status, content_type, body) = call("GET", path).await;
        assert_eq!(
            (status, &content_type),
            (never.0, &never.1),
            "{path} is answered as an unrouted path"
        );
        assert!(
            !String::from_utf8_lossy(&body).contains("credentials"),
            "{path} returned a listing"
        );
    }
    h.tsp.shutdown().await;
    h.mock.shutdown().await;
}
