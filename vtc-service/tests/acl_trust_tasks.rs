//! The community's ACL, administered as Trust Tasks over every transport the
//! VTC serves: `acl/{show,list,update,revoke}/0.1` sent over a real mediator as
//! DIDComm and as TSP, and posted to `POST /v1/trust-tasks` over HTTPS.
//!
//! The spine unit tests (`trust_tasks::acl_tasks`) drive the dispatcher with
//! each transport's context; this is the rest of the path — the client seals
//! and routes, the mediator forwards, the production listener unpacks and
//! dispatches, and the reply comes back the same way — so a wiring change that
//! strands one of these tasks on one transport fails here.
//!
//! Every task is answered the same on every transport, which is the property
//! under test: each one is driven over all three, and the answers compared.
//!
//! Requires `--features tsp,didcomm-harness`; CI runs it.

#![cfg(all(feature = "didcomm-harness", feature = "tsp"))]

use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::test_support::{MockVtcDidcomm, ReplyOutcome, TestTspPeer};

const SHOW: &str = "https://trusttasks.org/spec/acl/show/0.1";
const LIST: &str = "https://trusttasks.org/spec/acl/list/0.1";
const UPDATE: &str = "https://trusttasks.org/spec/acl/update/0.1";
const REVOKE: &str = "https://trusttasks.org/spec/acl/revoke/0.1";

const WAIT: Duration = Duration::from_secs(20);

/// The three principals — one per transport — each an unrestricted admin, and
/// the VTC they administer.
struct Harness {
    mock: MockVtcDidcomm,
    tsp: TestTspPeer,
    https: Party,
}

async fn seed(mock: &MockVtcDidcomm, did: &str, role: VtcRole, scopes: &[&str]) {
    store_acl_entry(
        &mock.vtc.state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role,
            label: None,
            allowed_contexts: scopes.iter().map(|s| s.to_string()).collect(),
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
    let https = Party::new();
    for did in [
        mock.client.did().to_string(),
        tsp.did().to_string(),
        https.did.clone(),
    ] {
        seed(&mock, &did, VtcRole::Admin, &[]).await;
    }
    Harness { mock, tsp, https }
}

/// The reply document to `uri` sent as `transport` — the whole
/// `#response` or `trust-task-error` document, whichever came back.
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
            let mut doc = vta_sdk::trust_task_sign::build_unsigned(
                uri,
                payload,
                &h.https.did,
                // The same audience every transport addresses.
                &vtc,
            )
            .unwrap();
            let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(
                &h.https.did,
                &h.https.secret_multibase,
            )
            .unwrap();
            vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
                .await
                .unwrap();
            let req = Request::builder()
                .method("POST")
                .uri("/v1/trust-tasks")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&doc).unwrap()))
                .unwrap();
            let resp = h.mock.vtc.router.clone().oneshot(req).await.unwrap();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice(&bytes).expect("a Trust Task document")
        }
        other => unreachable!("{other}"),
    }
}

const TRANSPORTS: [&str; 3] = ["didcomm", "tsp", "https"];

fn is_error(doc: &Value) -> bool {
    doc["type"]
        .as_str()
        .is_some_and(|t| t.contains("trust-task-error"))
}

async fn stored(h: &Harness, did: &str) -> Option<VtcAclEntry> {
    get_acl_entry(&h.mock.vtc.state.acl_ks, did).await.unwrap()
}

#[tokio::test]
async fn acl_show_answers_alike_on_every_transport() {
    let h = harness().await;
    seed(
        &h.mock,
        "did:key:z6MkShowTarget",
        VtcRole::Moderator,
        &["ctx-a"],
    )
    .await;
    let mut answers = Vec::new();
    for t in TRANSPORTS {
        let doc = send(&h, t, SHOW, json!({ "subject": "did:key:z6MkShowTarget" })).await;
        assert!(!is_error(&doc), "{t}: {doc}");
        assert_eq!(doc["payload"]["entry"]["role"], "moderator", "{t}");
        answers.push(doc["payload"].clone());

        let missing = send(&h, t, SHOW, json!({ "subject": "did:key:z6MkNobody" })).await;
        assert!(is_error(&missing), "{t}: {missing}");
        assert_eq!(missing["payload"]["details"]["reason"], "not_found", "{t}");
    }
    assert!(answers.windows(2).all(|w| w[0] == w[1]), "{answers:?}");
    h.tsp.shutdown().await;
    h.mock.shutdown().await;
}

#[tokio::test]
async fn acl_list_answers_alike_on_every_transport() {
    let h = harness().await;
    seed(&h.mock, "did:key:z6MkListA", VtcRole::Member, &["ctx-a"]).await;
    seed(&h.mock, "did:key:z6MkListB", VtcRole::Member, &["ctx-b"]).await;
    let mut answers = Vec::new();
    for t in TRANSPORTS {
        let doc = send(&h, t, LIST, json!({ "scope": "ctx-a" })).await;
        assert!(!is_error(&doc), "{t}: {doc}");
        let subjects: Vec<&str> = doc["payload"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["subject"].as_str().unwrap())
            .collect();
        assert_eq!(subjects, vec!["did:key:z6MkListA"], "{t}");
        assert_eq!(doc["payload"]["truncated"], false, "{t}");
        answers.push(doc["payload"].clone());
    }
    assert!(answers.windows(2).all(|w| w[0] == w[1]), "{answers:?}");
    h.tsp.shutdown().await;
    h.mock.shutdown().await;
}

#[tokio::test]
async fn acl_update_amends_and_refuses_alike_on_every_transport() {
    let h = harness().await;
    for t in TRANSPORTS {
        let subject = format!("did:key:z6MkUpdate{t}");
        seed(&h.mock, &subject, VtcRole::Member, &["ctx-a"]).await;

        let doc = send(
            &h,
            t,
            UPDATE,
            json!({ "subject": subject, "label": "ops", "scopes": ["ctx-a", "ctx-b"] }),
        )
        .await;
        assert!(!is_error(&doc), "{t}: {doc}");
        assert_eq!(doc["payload"]["entry"]["label"], "ops", "{t}");
        let entry = stored(&h, &subject).await.unwrap();
        assert_eq!(entry.allowed_contexts, vec!["ctx-a", "ctx-b"], "{t}");
        assert_eq!(entry.role, VtcRole::Member, "{t}");

        let narrowing = send(
            &h,
            t,
            UPDATE,
            json!({ "subject": subject, "scopes": ["ctx-a"] }),
        )
        .await;
        assert_eq!(
            narrowing["payload"]["code"], "acl/update:narrowingNotPermitted",
            "{t}: {narrowing}"
        );
        assert_eq!(
            stored(&h, &subject).await.unwrap().allowed_contexts,
            vec!["ctx-a", "ctx-b"],
            "{t}"
        );
    }
    h.tsp.shutdown().await;
    h.mock.shutdown().await;
}

#[tokio::test]
async fn acl_revoke_reduces_removes_and_refuses_alike_on_every_transport() {
    let h = harness().await;
    for t in TRANSPORTS {
        let subject = format!("did:key:z6MkRevoke{t}");
        seed(&h.mock, &subject, VtcRole::Member, &["ctx-a", "ctx-b"]).await;

        let reduced = send(
            &h,
            t,
            REVOKE,
            json!({ "subject": subject, "scopes": ["ctx-b"] }),
        )
        .await;
        assert!(!is_error(&reduced), "{t}: {reduced}");
        assert_eq!(
            reduced["payload"]["entry"]["scopes"],
            json!(["ctx-a"]),
            "{t}"
        );

        let removed = send(&h, t, REVOKE, json!({ "subject": subject })).await;
        assert!(!is_error(&removed), "{t}: {removed}");
        assert!(removed["payload"]["entry"].is_null(), "{t}: {removed}");
        assert!(stored(&h, &subject).await.is_none(), "{t}");

        let again = send(&h, t, REVOKE, json!({ "subject": subject })).await;
        assert_eq!(
            again["payload"]["code"], "acl/revoke:subjectNotPresent",
            "{t}: {again}"
        );
    }
    h.tsp.shutdown().await;
    h.mock.shutdown().await;
}
