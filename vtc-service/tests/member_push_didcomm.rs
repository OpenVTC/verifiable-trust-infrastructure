//! A member push goes over the transport the member's DID document offers, and
//! moves on when one yields no evidence of delivery (`crate::member_push`).
//!
//! TSP, then DIDComm, then REST. REST is reached only through a `TrustTaskHTTPS`
//! service, and a push over it is a `POST {base}/trust-tasks` of the document
//! (HTTPS binding 0.2). These drive both ends with a real mediator: a peer
//! that offers only REST gets the document by POST, and one whose DIDComm
//! attempt produces no evidence inside its window gets it by REST next
//! (VTI-TRN-042).
//!
//! Requires `--features didcomm-harness`; CI runs it.

#![cfg(feature = "didcomm-harness")]

use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::dids::{
    DID, KeyType, OneOrMany, PeerKeyRole, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
};
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use vta_sdk::protocol::matching::Protocol;
use vtc_service::member_push;
use vtc_service::test_support::MockVtcDidcomm;

/// A peer's Trust-Task HTTPS endpoint: records what is POSTed to
/// `/trust-tasks` and answers `204`, which the binding gives a task that
/// defines no response.
async fn trust_task_server() -> (String, Arc<Mutex<Vec<Value>>>) {
    let received: Arc<Mutex<Vec<Value>>> = Arc::default();
    let app = Router::new()
        .route(
            "/trust-tasks",
            post(
                |State(seen): State<Arc<Mutex<Vec<Value>>>>, body: axum::Json<Value>| async move {
                    seen.lock().await.push(body.0);
                    StatusCode::NO_CONTENT
                },
            ),
        )
        .with_state(received.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), received)
}

fn service(type_: &str, uri: &str) -> PeerService {
    PeerService {
        type_: type_.into(),
        endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
            uri: uri.to_string(),
            accept: vec![],
            routing_keys: vec![],
        })),
        id: None,
    }
}

fn mint_peer(services: Vec<PeerService>) -> String {
    let (did, _secrets) = DID::generate_did_peer_with_services(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(services),
    )
    .expect("mint did:peer");
    assert!(did.len() < 1_000, "did:peer over the resolver's size limit");
    did
}

fn document(recipient: &str) -> Value {
    json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/vtc/members/removal-notice/0.1",
        "recipient": recipient,
        "payload": { "note": "member push test" },
    })
}

/// Sweep until the push has an outcome, or give up after `limit`.
async fn settle(
    mock: &MockVtcDidcomm,
    id: &str,
    limit: Duration,
) -> Option<(bool, Protocol, String)> {
    let deadline = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < deadline {
        member_push::sweep(&mock.vtc.state).await.expect("sweep");
        if let Some(outcome) = member_push::outcome(&mock.vtc.state, id).await.unwrap() {
            return Some(outcome);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    None
}

/// A peer offering only `TrustTaskHTTPS` is pushed to by POST, and the push is
/// recorded delivered on the recipient's own acknowledgement (class 2).
#[tokio::test]
async fn a_rest_only_peer_gets_the_document_by_post() {
    let mock = MockVtcDidcomm::start().await;
    let (base, received) = trust_task_server().await;
    let peer = mint_peer(vec![service("TrustTaskHTTPS", &base)]);
    let doc = document(&peer);

    let id =
        member_push::push_trust_task(&mock.vtc.state, &peer, doc.clone(), Duration::from_secs(60))
            .await
            .expect("queued");

    let outcome = settle(&mock, &id, Duration::from_secs(30))
        .await
        .expect("the push settled");
    assert_eq!(outcome, (true, Protocol::Rest, "reply".to_string()));
    let got = received.lock().await.clone();
    assert_eq!(got, vec![doc], "the signed document is the body, unchanged");
}

/// A DIDComm attempt that yields no evidence in its window moves to the next
/// transport the peer offers (VTI-TRN-042). The peer's DIDComm mediator is one
/// nothing can reach, so the DIDComm attempt can never be collected; its share
/// of the deadline passes and REST delivers.
#[tokio::test]
async fn vti_trn_042_no_evidence_on_didcomm_escalates_to_rest() {
    let mock = MockVtcDidcomm::start().await;
    let (base, received) = trust_task_server().await;
    let peer = mint_peer(vec![
        service("DIDCommMessaging", "did:web:unreachable-mediator.invalid"),
        service("TrustTaskHTTPS", &base),
    ]);
    let doc = document(&peer);

    // Two transports, so the DIDComm attempt gets half the deadline.
    let id =
        member_push::push_trust_task(&mock.vtc.state, &peer, doc.clone(), Duration::from_secs(20))
            .await
            .expect("queued");

    let outcome = settle(&mock, &id, Duration::from_secs(45))
        .await
        .expect("the push settled");
    assert_eq!(
        outcome,
        (true, Protocol::Rest, "reply".to_string()),
        "escalated from DIDComm to REST and delivered there"
    );
    assert_eq!(received.lock().await.clone(), vec![doc]);
}

/// A service type nothing recognises reads as advertising nothing, so the push
/// takes the shared mediator over DIDComm, as every member push did before —
/// and never REST under a type other than `TrustTaskHTTPS`.
#[tokio::test]
async fn an_unrecognised_transport_falls_back_to_the_shared_mediator() {
    let mock = MockVtcDidcomm::start().await;
    let peer = mint_peer(vec![service("SomeOtherTransport", "https://peer.invalid")]);
    let queued = member_push::push_trust_task(
        &mock.vtc.state,
        &peer,
        document(&peer),
        Duration::from_secs(20),
    )
    .await;
    let id = queued.expect("a peer with no recognised transport takes the shared mediator");
    member_push::sweep(&mock.vtc.state).await.unwrap();
    assert!(
        member_push::outcome(&mock.vtc.state, &id)
            .await
            .unwrap()
            .is_none(),
        "in flight over DIDComm, not delivered by a transport it never offered"
    );
}
