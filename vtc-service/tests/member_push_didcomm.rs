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

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

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

/// A peer offering `TSPTransport` gets the document over **TSP**, and the push
/// is recorded delivered on the mediator's evidence that the peer collected it
/// (class 3).
///
/// The peer stays offline until the VTC's outbox poll has seen the TSP message
/// waiting at the mediator, so this also covers the outbox listing the delivery
/// layer falls back to. The peer advertises TSP alone, so a push that fell back
/// to DIDComm could not pass.
#[cfg(feature = "tsp")]
#[tokio::test]
async fn a_tsp_peer_gets_the_document_over_tsp_and_its_collection_is_recorded() {
    use affinidi_messaging_delivery::OutboxStore as _;

    init_tracing();
    let mock = MockVtcDidcomm::start_with_tsp().await;
    let pending = mock.register_tsp_peer().await;
    let doc = document(pending.did());

    let id = member_push::push_trust_task(
        &mock.vtc.state,
        pending.did(),
        doc.clone(),
        Duration::from_secs(120),
    )
    .await
    .expect("queued");

    // The VTC's own outbox poll sees the sealed TSP message waiting for the
    // peer. `0:tsp`: the first attempt, over TSP — the only transport the peer
    // offers.
    let outbox = vti_common::outbox_store::VtiOutboxStore::new(mock.vtc.state.outbox_ks.clone());
    let key = format!("{id}:0:tsp");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    loop {
        let entry = outbox.get(&key).await.expect("read outbox");
        if entry.as_ref().is_some_and(|e| e.outbox_observed) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the TSP push was never seen waiting at the mediator: {entry:?}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let peer = pending.connect().await;
    let got = peer
        .next_trust_task(Duration::from_secs(30))
        .await
        .expect("the document reached the peer over TSP");
    assert_eq!(
        got, doc,
        "the signed document, unchanged, out of the binding envelope"
    );

    let outcome = settle(&mock, &id, Duration::from_secs(40))
        .await
        .expect("the push settled");
    assert_eq!(
        outcome,
        (true, Protocol::Tsp, "collected".to_string()),
        "delivered over TSP, on the mediator's evidence of collection"
    );
    peer.shutdown().await;
}

/// A peer that is already connected collects the push before any outbox poll
/// could see it waiting, and the push still settles delivered, on the first
/// transport, with no re-send.
///
/// This is affinidi-tdk-rs#896. Before mediator receipts, the delivery layer
/// counted a collection only after observing the message queued; a live peer
/// never produced that observation, so its push ran out its window unconfirmed
/// and escalated — re-sent on the next transport it offered. The mediator now
/// records that the recipient collected it (`messaging/message/status`), and the
/// delivery layer settles on that.
#[cfg(feature = "tsp")]
#[tokio::test]
async fn a_live_peer_that_collects_at_once_is_confirmed_not_re_sent() {
    init_tracing();
    let mock = MockVtcDidcomm::start_with_tsp().await;
    let peer = mock.connect_tsp_peer().await;
    let doc = document(peer.did());

    let id = member_push::push_trust_task(
        &mock.vtc.state,
        peer.did(),
        doc.clone(),
        Duration::from_secs(120),
    )
    .await
    .expect("queued");
    let got = peer
        .next_trust_task(Duration::from_secs(30))
        .await
        .expect("the live peer collected the document");
    assert_eq!(got, doc);

    let outcome = settle(&mock, &id, Duration::from_secs(40))
        .await
        .expect("the push settled");
    assert_eq!(
        outcome,
        (true, Protocol::Tsp, "collected".to_string()),
        "confirmed on the mediator's receipt, on the first transport"
    );
    assert!(
        peer.next_trust_task(Duration::from_secs(2)).await.is_none(),
        "the document was not sent again"
    );
    peer.shutdown().await;
}

/// A peer whose DID document advertises no transport — a `did:key` wallet, in
/// production — is pushed to over TSP once the VTC has seen it sending over TSP
/// (`tsp_reach`), rather than over DIDComm as its document alone would imply.
/// The peer passes on only what arrives over TSP, so receiving the document is
/// the proof.
#[tokio::test]
async fn a_silent_peer_seen_on_tsp_is_pushed_to_over_tsp() {
    use affinidi_messaging_delivery::OutboxStore as _;

    init_tracing();
    let mock = MockVtcDidcomm::start_with_tsp().await;
    let peer = mock.connect_silent_tsp_peer().await;
    // What `handle_tsp` records for every verified inbound TSP frame.
    mock.vtc.state.tsp_reach.record(peer.did());
    let doc = document(peer.did());

    let id = member_push::push_trust_task(
        &mock.vtc.state,
        peer.did(),
        doc.clone(),
        Duration::from_secs(120),
    )
    .await
    .expect("queued");

    let got = peer
        .next_trust_task(Duration::from_secs(30))
        .await
        .expect("the document reached the silent peer over TSP");
    assert_eq!(got, doc);

    // The first attempt was the TSP one.
    let outbox = vti_common::outbox_store::VtiOutboxStore::new(mock.vtc.state.outbox_ks.clone());
    assert!(
        outbox
            .get(&format!("{id}:0:tsp"))
            .await
            .expect("read outbox")
            .is_some(),
        "the push's first attempt was queued over TSP"
    );
    peer.shutdown().await;
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
