//! Regression guard: one DID, one websocket, **both** protocols (#803).
//!
//! ## Why this exists
//!
//! `vta-sdk` could only produce a Trust-Task-over-TSP client by opening its own
//! websocket (`TspSession::connect`). The mediator permits **one websocket per
//! DID**, so a consumer already holding a `DIDCommSession` on that DID got
//! `duplicate-channel` and two duelling reconnect loops. On the reference
//! deployment `#tsp` and `#vta-didcomm` resolve to the *same* mediator, so that
//! was the normal case — and because a split-mediator deployment *would* have
//! worked, the failure only showed up on the topology everyone actually runs.
//!
//! The fix is the client-side mirror of what the VTA already does on the server
//! side: TSP rides the DIDComm session's existing socket. Send is an HTTP post
//! to the mediator; receive arrives on the pickup socket already multiplexed
//! (`live_stream_next_frame` tags each frame's protocol).
//!
//! ## What these tests pin
//!
//! 1. A TSP frame addressed to a DID whose only connection is a `DIDCommSession`
//!    reaches that session — with **no** TSP socket of its own.
//! 2. Both legs work on that one session: a DIDComm send and a TSP send from the
//!    same connection.
//! 3. `request_tsp` correlates its own reply, and an unrelated push is parked for
//!    `receive_next_tsp` rather than eaten.
//! 4. A `VtaClient` with the leg attached reports TSP for trust tasks and
//!    DIDComm for protocol messages — the per-surface model, not a third
//!    client-wide transport.
//! 5. Attaching a *separate* TSP session for a DID on the mediator it is already
//!    connected to is refused: the defect is unrepresentable through the API.
//!
//! Hermetic — `TestMediator`, no network, no deployed VTA — so these run in CI
//! unignored.

use std::time::Duration;

use affinidi_messaging_test_mediator::TestMediator;
use ed25519_dalek::SigningKey;
use vta_sdk::client::{SurfaceTransport, VtaClient};
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::didcomm_session::DIDCommSession;
use vta_sdk::session::TspSession;

mod common;

/// Deterministic `did:key` + matching multibase private key from a seed byte.
/// Mirrors `tsp_round_trip.rs` so both binaries build identities identically.
fn did_key_from_seed(seed_byte: u8) -> (String, String) {
    let seed = [seed_byte; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    let did = format!("did:key:{}", ed25519_multibase_pubkey(&pk));
    let mut buf = vec![0x80, 0x26];
    buf.extend_from_slice(&seed);
    let priv_mb = multibase::encode(multibase::Base::Base58Btc, &buf);
    (did, priv_mb)
}

/// A minimal Trust-Task-shaped request. TSP carries these bytes directly (no
/// DIDComm envelope), which is what the VTA's `tsp_inbound::dispatch_one`
/// expects, so this matches the real wire shape.
fn request_doc(id: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": id,
        "type": "https://trusttasks.org/spec/messaging/ping/0.1",
        "payload": { "nonce": id },
    }))
    .expect("serialize request document")
}

/// The threaded `#response` a responder sends back — `threadId` is the request's
/// `id`, which is what correlation matches on.
fn response_doc(thread_id: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": format!("{thread_id}-reply"),
        "type": "https://trusttasks.org/spec/messaging/ping/0.1#response",
        "threadId": thread_id,
        "payload": { "pong": true },
    }))
    .expect("serialize response document")
}

/// Pull the `id` out of a received Trust-Task document.
fn doc_id(json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(json)
        .expect("received frame is JSON")
        .get("id")
        .and_then(|v| v.as_str())
        .expect("received document has an id")
        .to_string()
}

/// **The core case.** A DID whose only connection is a `DIDCommSession` still
/// receives TSP.
///
/// Before the fix this required a second websocket for that DID, which the
/// mediator rejects. Here the `DIDCommSession` is the *only* connection the
/// recipient has: no `TspSession`, no second socket, and the frame still lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_didcomm_session_receives_tsp_on_its_own_socket() {
    common::init_tracing();

    let (recipient_did, recipient_priv) = did_key_from_seed(0x71);
    let (sender_did, sender_priv) = did_key_from_seed(0x72);

    let mediator = TestMediator::builder()
        .local_did(recipient_did.clone())
        .local_did(sender_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    // The recipient's ONLY connection — a DIDComm session. No TSP socket.
    let recipient =
        DIDCommSession::connect(&recipient_did, &recipient_priv, &sender_did, mediator.did())
            .await
            .expect("recipient DIDComm session connects");

    let sender = TspSession::connect(&sender_did, &sender_priv, mediator.did())
        .await
        .expect("sender TSP session connects");
    sender
        .send_document(
            &recipient_did,
            mediator.did(),
            &request_doc("urn:uuid:dual-1"),
        )
        .await
        .expect("TSP send reports success");

    // Generous budget: the failure mode is a drop, not slowness, so a short
    // timeout would muddle "never delivered" with "still in flight".
    let received = recipient
        .receive_next_tsp(20)
        .await
        .expect("receive_next_tsp must not error");

    sender.shutdown().await;
    recipient.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");

    let frame = received.expect(
        "a TSP frame addressed to a DID holding only a DIDComm session was never \
         delivered — the multiplexed receive path is broken, and TSP is once again \
         reachable only by opening a second socket for this DID (#803)",
    );
    assert_eq!(doc_id(&frame), "urn:uuid:dual-1");
}

/// Both legs, one session, one socket: a DIDComm send and a TSP send from the
/// same connection.
///
/// This is the property that makes per-surface routing possible — `rpc` on
/// DIDComm and `dispatch_trust_task` on TSP without the two fighting over the
/// DID's single websocket slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_session_carries_both_protocols() {
    common::init_tracing();

    let (client_did, client_priv) = did_key_from_seed(0x73);
    let (peer_did, peer_priv) = did_key_from_seed(0x74);

    let mediator = TestMediator::builder()
        .local_did(client_did.clone())
        .local_did(peer_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    let session = DIDCommSession::connect(&client_did, &client_priv, &peer_did, mediator.did())
        .await
        .expect("DIDComm session connects");
    // The peer only needs to be reachable; a TSP inbox proves the frame routed.
    let peer = TspSession::connect(&peer_did, &peer_priv, mediator.did())
        .await
        .expect("peer TSP session connects");

    session
        .send_one_way(
            &peer_did,
            "https://trusttasks.org/binding/didcomm/0.1/envelope",
            serde_json::json!({ "id": "urn:uuid:didcomm-leg" }),
        )
        .await
        .expect("the DIDComm leg still works");

    session
        .send_tsp_document(&peer_did, &request_doc("urn:uuid:tsp-leg"))
        .await
        .expect("the TSP leg sends over the same session");

    let delivered = peer
        .receive_next(20)
        .await
        .expect("peer receive must not error");

    session.shutdown().await;
    peer.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");

    let frame = delivered.expect("the TSP frame sent from the DIDComm session never arrived");
    assert_eq!(doc_id(&frame), "urn:uuid:tsp-leg");
}

/// The full request/response round trip over the multiplexed socket, plus the
/// invariant that keeps it safe: an **unrelated** push must not be handed back
/// as the reply.
///
/// The peer deliberately sends a push *first*, then the threaded `#response`.
/// A "first frame that parses" implementation would return the push and report a
/// successful round trip against a document nobody asked for — the exact fault
/// class that made #749 look intermittent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_tsp_correlates_its_reply_and_parks_the_push() {
    common::init_tracing();

    let (client_did, client_priv) = did_key_from_seed(0x75);
    let (peer_did, peer_priv) = did_key_from_seed(0x76);

    let mediator = TestMediator::builder()
        .local_did(client_did.clone())
        .local_did(peer_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    let session = DIDCommSession::connect(&client_did, &client_priv, &peer_did, mediator.did())
        .await
        .expect("DIDComm session connects");
    let peer = TspSession::connect(&peer_did, &peer_priv, mediator.did())
        .await
        .expect("peer TSP session connects");

    // The responder: wait for the request, send an unrelated push, then reply.
    let peer_mediator = mediator.did().to_string();
    let client_did_for_peer = client_did.clone();
    let responder = tokio::spawn(async move {
        let request = peer
            .receive_next(20)
            .await
            .expect("peer receive must not error")
            .expect("peer received the request");
        let request_id = doc_id(&request);

        peer.send_document(
            &client_did_for_peer,
            &peer_mediator,
            &request_doc("urn:uuid:unrelated-push"),
        )
        .await
        .expect("push send succeeds");
        peer.send_document(
            &client_did_for_peer,
            &peer_mediator,
            &response_doc(&request_id),
        )
        .await
        .expect("reply send succeeds");
        peer.shutdown().await;
        request_id
    });

    let request_id = "urn:uuid:correlated-request";
    let reply = session
        .request_tsp(&peer_did, &request_doc(request_id), Duration::from_secs(25))
        .await
        .expect("request_tsp must return the correlated reply");

    let received_request_id = responder.await.expect("responder task joins");

    // The push must still be collectable — parked, not eaten by the request.
    let parked = session
        .receive_next_tsp(20)
        .await
        .expect("receive_next_tsp must not error");

    session.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");

    assert_eq!(received_request_id, request_id, "the peer saw our request");

    let reply_doc: serde_json::Value = serde_json::from_str(&reply).expect("reply is JSON");
    assert_eq!(
        reply_doc.get("threadId").and_then(|v| v.as_str()),
        Some(request_id),
        "request_tsp returned a document that is not the reply to our request \
         (correlation is broken — a stale or unrelated frame can now be reported \
         as a successful round trip): {reply}"
    );

    let push = parked.expect(
        "the unrelated push was consumed by the in-flight request instead of being \
         parked — a VTA-pushed task-consent request would be silently lost",
    );
    assert_eq!(doc_id(&push), "urn:uuid:unrelated-push");
}

/// The per-surface model at the `VtaClient` level: trust tasks on TSP, protocol
/// messages on DIDComm, on one client.
///
/// A single "which transport is this client on" answer is wrong by construction
/// — TSP carries Trust Tasks only, so selecting it client-wide would break
/// `key-management/1.0/*`, `create_did_webvh` and `list_contexts`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_reports_tsp_for_trust_tasks_and_didcomm_for_protocol_messages() {
    common::init_tracing();

    let (client_did, client_priv) = did_key_from_seed(0x77);
    let (vta_did, _) = did_key_from_seed(0x78);

    let mediator = TestMediator::builder()
        .local_did(client_did.clone())
        .local_did(vta_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    let mut client =
        VtaClient::connect_didcomm(&client_did, &client_priv, &vta_did, mediator.did(), None)
            .await
            .expect("DIDComm client connects");

    assert_eq!(client.trust_task_transport(), SurfaceTransport::Didcomm);

    // The VTA advertises the same mediator for `#tsp` — the reference topology.
    // No I/O, no second socket.
    client
        .enable_tsp_trust_tasks(mediator.did())
        .expect("enabling the TSP leg on the same mediator must not fail");

    assert_eq!(
        client.trust_task_transport(),
        SurfaceTransport::Tsp,
        "trust tasks must move to TSP"
    );
    assert_eq!(
        client.protocol_message_transport(),
        SurfaceTransport::Didcomm,
        "protocol messages must stay on DIDComm — TSP has no dispatcher for them"
    );

    // Attaching a *separate* TSP session for this DID on the mediator it is
    // already connected to is the #803 defect. The API refuses it rather than
    // letting a caller reintroduce the duplicate socket.
    let stray = std::sync::Arc::new(
        TspSession::connect(&client_did, &client_priv, mediator.did())
            .await
            .expect("a raw TSP session can still be built directly"),
    );
    let refused = client.attach_tsp_leg(std::sync::Arc::clone(&stray), mediator.did());
    // Refused, so the client will not shut it down for us — and a leaked TSP
    // socket is the very thing under test.
    stray.shutdown().await;
    assert!(
        refused.is_err(),
        "attaching a second socket for this DID on its own mediator must be refused"
    );
    let msg = refused.unwrap_err().to_string();
    assert!(
        msg.contains("duplicate-channel") && msg.contains("enable_tsp_trust_tasks"),
        "the refusal must name the failure and the fix: {msg}"
    );

    client.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");
}
