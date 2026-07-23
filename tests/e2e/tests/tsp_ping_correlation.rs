//! A TSP ping must measure *its own* reply, not whatever was in the inbox.
//!
//! ## Why this exists
//!
//! `pnm health`'s TSP probe used to accept the first frame that unpacked and
//! parsed as JSON. That looks harmless until you remember the mediator inbox is
//! durable: every reply an earlier probe failed to collect is still queued, and
//! the mediator flushes the backlog onto the socket the instant it connects. So
//! the probe could hand back a pong from a previous run — a green tick and a
//! fabricated latency for a round trip that never happened on this run. During
//! the TSP delivery outage (mediator never marked raw-TSP sockets live, so
//! replies were stored and never pushed) that is exactly what happened: the
//! warm-up ping "succeeded" off the backlog and the measured ping then failed,
//! which is what made the fault look intermittent instead of total.
//!
//! A health probe that can be satisfied by a stale frame cannot be trusted to
//! report a broken transport, so this pins the correlation.
//!
//! ## Version note
//!
//! [`a_stale_inbox_frame_does_not_satisfy_a_ping`] runs against any mediator —
//! it only needs flush-on-connect. [`a_correlated_reply_satisfies_the_ping`] is
//! a live TSP round trip, so it needs a mediator that actually pushes frames to
//! a connected raw-TSP socket: `affinidi-messaging-mediator` >= 0.17.7 /
//! `affinidi-messaging-sdk` >= 0.18.62. Against older versions it fails for the
//! upstream reason, not this one.

use std::time::Duration;

use affinidi_messaging_test_mediator::TestMediator;
use ed25519_dalek::SigningKey;
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::session::{TspPingSession, TspSession};

mod common;

/// Deterministic `did:key` + matching multibase private key from a seed byte.
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

/// A well-formed Trust-Task response document that belongs to *someone else's*
/// exchange — the shape a leftover reply from an earlier probe has.
fn stale_reply(peer_did: &str, client_did: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": "urn:uuid:stale-response-from-an-earlier-run",
        "threadId": "urn:uuid:a-ping-this-process-never-sent",
        "type": "https://trusttasks.org/spec/messaging/ping/0.1#response",
        "issuer": peer_did,
        "recipient": client_did,
        "payload": { "nonce": "a-nonce-from-an-earlier-run" },
    }))
    .expect("serialize stale reply")
}

/// Queue a stale reply for the prober *before* it connects, then ping a peer
/// that never answers. The stale frame is flushed onto the socket on connect,
/// so an uncorrelated probe reports success off it; a correlated one must let
/// the ping time out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_inbox_frame_does_not_satisfy_a_ping() {
    common::init_tracing();

    let (client_did, client_priv) = did_key_from_seed(0x71);
    let (peer_did, peer_priv) = did_key_from_seed(0x72);

    let mediator = TestMediator::builder()
        .local_did(client_did.clone())
        .local_did(peer_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    // The peer plants a reply for the client and goes silent — it will not
    // answer the ping that follows.
    let peer = TspSession::connect(&peer_did, &peer_priv, mediator.did())
        .await
        .expect("peer TSP session connects");
    peer.send_document(
        &client_did,
        mediator.did(),
        &stale_reply(&peer_did, &client_did),
    )
    .await
    .expect("stale reply is accepted by the mediator");
    peer.shutdown().await;

    // Give the mediator a moment to store it, so it is genuinely waiting in the
    // inbox when the prober connects and gets the flush-on-connect drain.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut prober = TspPingSession::new(&client_did, &client_priv, mediator.did())
        .await
        .expect("prober TSP session connects");
    let result = prober.ping(&peer_did, Duration::from_secs(3)).await;
    prober.shutdown().await;

    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");

    match result {
        Ok(latency) => panic!(
            "ping reported success ({latency}ms) off a stale inbox frame — nobody answered \
             this ping, so a health probe built on this would show green against a dead \
             transport"
        ),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("timed out"),
                "expected the ping to time out having skipped the uncorrelated frame, got: {msg}"
            );
        }
    }
}

/// The other half of the contract: a correctly-threaded reply still satisfies
/// the ping. Without this, "reject everything" would pass the test above.
///
/// The peer plays the VTA: it reads the ping off its own TSP inbox and answers
/// with `threadId` set to the request id, exactly as `doc.respond_with` does on
/// the real dispatch spine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_correlated_reply_satisfies_the_ping() {
    common::init_tracing();

    let (client_did, client_priv) = did_key_from_seed(0x73);
    let (peer_did, peer_priv) = did_key_from_seed(0x74);

    let mediator = TestMediator::builder()
        .local_did(client_did.clone())
        .local_did(peer_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    let peer = TspSession::connect(&peer_did, &peer_priv, mediator.did())
        .await
        .expect("peer TSP session connects");

    let mediator_did = mediator.did().to_string();
    let client_for_peer = client_did.clone();
    let peer_did_for_task = peer_did.clone();
    let responder = tokio::spawn(async move {
        let Ok(Some(frame)) = peer.receive_next(20).await else {
            return;
        };
        let doc: serde_json::Value = serde_json::from_str(&frame).expect("ping is JSON");
        let request_id = doc.get("id").and_then(|v| v.as_str()).unwrap_or_default();
        let reply = serde_json::to_vec(&serde_json::json!({
            "id": "urn:uuid:the-response",
            "threadId": request_id,
            "type": "https://trusttasks.org/spec/messaging/ping/0.1#response",
            "issuer": peer_did_for_task,
            "recipient": client_for_peer,
            "payload": { "status": "ok" },
        }))
        .expect("serialize reply");
        peer.send_document(&client_for_peer, &mediator_did, &reply)
            .await
            .expect("reply is accepted");
        peer.shutdown().await;
    });

    let mut prober = TspPingSession::new(&client_did, &client_priv, mediator.did())
        .await
        .expect("prober TSP session connects");
    let result = prober.ping(&peer_did, Duration::from_secs(20)).await;
    prober.shutdown().await;
    let _ = responder.await;

    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");

    result.expect("a reply threaded to our request id must satisfy the ping");
}
