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
//! Requires `--features transport-harness`; CI runs it.

#![cfg(feature = "transport-harness")]

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
use vtc_service::test_support::MockVtcTransport;

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
    mock: &MockVtcTransport,
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
    let mock = MockVtcTransport::start_with_tsp().await;
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
    let mock = MockVtcTransport::start_with_tsp().await;
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
    let mock = MockVtcTransport::start_with_tsp().await;
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
    let mock = MockVtcTransport::start().await;
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
    let mock = MockVtcTransport::start().await;
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

/// A TSP attempt whose hand-off keeps failing moves to the next transport the
/// peer offers after a few refusals, not after its hour-long window
/// (VTI-TRN-042, `FAILED_SENDS_BEFORE_ESCALATION`). The peer's TSP mediator is
/// one nothing can resolve, so every TSP send fails; with a two-hour deadline
/// the TSP attempt's window is the full `ATTEMPT_WINDOW`, so delivery over REST
/// inside a minute can only come from the early escalation.
#[cfg(feature = "tsp")]
#[tokio::test]
async fn vti_trn_042_a_refused_tsp_hand_off_escalates_before_its_window() {
    init_tracing();
    let mock = MockVtcTransport::start_with_tsp().await;
    let (base, received) = trust_task_server().await;
    let peer = mint_peer(vec![
        service("TSPTransport", "did:web:unreachable-mediator.invalid"),
        service("TrustTaskHTTPS", &base),
    ]);
    let doc = document(&peer);

    let id = member_push::push_trust_task(
        &mock.vtc.state,
        &peer,
        doc.clone(),
        Duration::from_secs(2 * 60 * 60),
    )
    .await
    .expect("queued");

    let outcome = settle(&mock, &id, Duration::from_secs(60))
        .await
        .expect("the push settled inside a minute, not at the end of the TSP window");
    assert_eq!(
        outcome,
        (true, Protocol::Rest, "reply".to_string()),
        "escalated from TSP to REST on repeated refusals"
    );
    assert_eq!(received.lock().await.clone(), vec![doc]);

    // The TSP attempt was settled when the push left it, so the delivery layer
    // is no longer retrying it.
    use affinidi_messaging_delivery::OutboxStore as _;
    let outbox = vti_common::outbox_store::VtiOutboxStore::new(mock.vtc.state.outbox_ks.clone());
    let abandoned = outbox
        .get(&format!("{id}:0:tsp"))
        .await
        .expect("read outbox")
        .expect("the TSP attempt was queued");
    assert!(
        abandoned.state.is_terminal(),
        "the abandoned TSP attempt is settled, not still retrying: {:?}",
        abandoned.state
    );
}

/// A service type nothing recognises reads as advertising nothing, so the push
/// takes the shared mediator over DIDComm, as every member push did before —
/// and never REST under a type other than `TrustTaskHTTPS`.
#[tokio::test]
async fn an_unrecognised_transport_falls_back_to_the_shared_mediator() {
    let mock = MockVtcTransport::start().await;
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

// ── Freshness: a push outlives the document it started with ─────────────

/// A document as a push holds it once it has outlived its acceptance window:
/// signed by the VTC, issued more than `ACCEPTANCE_WINDOW` ago, keyed.
async fn stale_signed_document(mock: &MockVtcTransport, recipient: &str) -> Value {
    let issued = chrono::Utc::now()
        - vti_common::trust_task::ACCEPTANCE_WINDOW
        - chrono::TimeDelta::minutes(5);
    let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let mut doc = json!({
        "id": id,
        "type": "https://trusttasks.org/spec/vtc/members/removal-notice/0.1",
        "issuer": mock.vtc_did(),
        "recipient": recipient,
        "issuedAt": issued.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "idempotencyKey": id,
        "payload": { "note": "member push freshness test" },
    });
    mock.vtc
        .state
        .credential_signer
        .as_ref()
        .expect("the harness VTC has a signer")
        .sign_operational_doc(&mut doc)
        .await
        .expect("sign the original");
    doc
}

/// What the recipient must get instead of `original`: a new attempt (SPEC
/// §8.4) — never the original re-signed under its own `id`, which a consumer
/// that accepted it must refuse as `idConflict` — inside the window, in the
/// original's thread, under the same idempotency key, signed again.
fn assert_new_attempt_at(got: &Value, original: &Value) {
    assert_ne!(got["id"], original["id"], "a fresh id: {got}");
    assert_eq!(got["threadId"], original["id"], "in the original's thread");
    assert_eq!(
        got["idempotencyKey"], original["idempotencyKey"],
        "one key across every attempt (VTI-OPS-064)"
    );
    assert_eq!(got["payload"], original["payload"]);
    let issued: chrono::DateTime<chrono::Utc> = got["issuedAt"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("an issuedAt");
    assert!(
        chrono::Utc::now() - issued < vti_common::trust_task::ACCEPTANCE_WINDOW,
        "issued inside the window the recipient accepts: {issued}"
    );
    assert_eq!(
        got["proof"]["proofPurpose"], "authentication",
        "signed again, the way the original was"
    );
    assert_ne!(got["proof"], original["proof"]);
}

/// REST: a push whose document outlived its window — here, handed over that
/// way — is delivered as a new attempt the recipient accepts, once.
#[tokio::test]
async fn a_rest_push_past_its_freshness_window_is_delivered_once_as_a_new_attempt() {
    let mock = MockVtcTransport::start().await;
    let (base, received) = trust_task_server().await;
    let peer = mint_peer(vec![service("TrustTaskHTTPS", &base)]);
    let original = stale_signed_document(&mock, &peer).await;

    let id = member_push::push_trust_task(
        &mock.vtc.state,
        &peer,
        original.clone(),
        Duration::from_secs(60),
    )
    .await
    .expect("queued");
    let outcome = settle(&mock, &id, Duration::from_secs(30))
        .await
        .expect("the push settled");
    assert_eq!(outcome, (true, Protocol::Rest, "reply".to_string()));

    let got = received.lock().await.clone();
    assert_eq!(got.len(), 1, "delivered once: {got:?}");
    assert_new_attempt_at(&got[0], &original);
}

/// DIDComm: the same, to a connected DIDComm member.
#[tokio::test]
async fn a_didcomm_push_past_its_freshness_window_is_delivered_once_as_a_new_attempt() {
    init_tracing();
    let mock = MockVtcTransport::start().await;
    let member = mock.client.did().to_string();
    let original = stale_signed_document(&mock, &member).await;

    member_push::push_trust_task(
        &mock.vtc.state,
        &member,
        original.clone(),
        Duration::from_secs(60),
    )
    .await
    .expect("queued");
    let got = mock
        .client
        .next_pushed_document(Duration::from_secs(30))
        .await
        .expect("the member received the push over DIDComm");
    assert_new_attempt_at(&got, &original);
    assert!(
        mock.client
            .next_pushed_document(Duration::from_secs(2))
            .await
            .is_none(),
        "and received it once"
    );
}

/// TSP: the same, to a live TSP peer.
#[cfg(feature = "tsp")]
#[tokio::test]
async fn a_tsp_push_past_its_freshness_window_is_delivered_once_as_a_new_attempt() {
    init_tracing();
    let mock = MockVtcTransport::start_with_tsp().await;
    let peer = mock.connect_tsp_peer().await;
    let original = stale_signed_document(&mock, peer.did()).await;

    member_push::push_trust_task(
        &mock.vtc.state,
        peer.did(),
        original.clone(),
        Duration::from_secs(60),
    )
    .await
    .expect("queued");
    let got = peer
        .next_trust_task(Duration::from_secs(30))
        .await
        .expect("the peer received the push over TSP");
    assert_new_attempt_at(&got, &original);
    assert!(
        peer.next_trust_task(Duration::from_secs(2)).await.is_none(),
        "and received it once"
    );
    peer.shutdown().await;
}

/// A document still inside its window is sent as it is — the engine re-issues
/// only what a consumer would refuse, so a fresh push is untouched and the
/// recipient's replay record dedupes its copies by `id` as before.
#[tokio::test]
async fn a_push_inside_its_freshness_window_is_sent_unchanged() {
    let mock = MockVtcTransport::start().await;
    let (base, received) = trust_task_server().await;
    let peer = mint_peer(vec![service("TrustTaskHTTPS", &base)]);
    let mut doc = document(&peer);
    doc["issuedAt"] = json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));

    let id =
        member_push::push_trust_task(&mock.vtc.state, &peer, doc.clone(), Duration::from_secs(60))
            .await
            .expect("queued");
    settle(&mock, &id, Duration::from_secs(30))
        .await
        .expect("the push settled");
    assert_eq!(received.lock().await.clone(), vec![doc]);
}
