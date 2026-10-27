//! A TSP reply that misses its first deadline is still collected.
//!
//! ## Why this exists
//!
//! OpenVTC #501: `openvtc setup` sent `provision/integration` over TSP, the
//! VTA minted the long-term admin and replied, and the mediator stored the
//! reply without pushing it (affinidi-tdk-rs#957 — a notify-before-store race
//! fixed in mediator 0.43.0). `TspSession::request` timed out and gave up. The
//! reply sat in the inbox for days, holding the only copy of the new admin's
//! key, and the setup DID's one-time hand-off was already spent.
//!
//! `request` now reconnects once on a reply timeout — raw-TSP sockets are
//! flush-on-connect, so a stored reply is delivered by the reconnect — and
//! keeps the same waiter for `STRANDED_REPLY_GRACE`. Nothing is resent.
//!
//! The race itself is fixed in the fixture mediator, so this cannot strand a
//! reply on purpose. It pins what the recovery depends on instead: a reply
//! that arrives after the first deadline, across the reconnect, still reaches
//! the request that is waiting for it — before the change it was an error.
//!
//! Hermetic — an embedded `TestMediator`, a client, and a peer playing a slow VTA.

use std::time::{Duration, Instant};

use affinidi_messaging_test_mediator::TestMediator;
use ed25519_dalek::SigningKey;
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::session::{STRANDED_REPLY_GRACE, TspSession};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reply_after_the_first_deadline_is_collected_across_a_reconnect() {
    common::init_tracing();
    let (client_did, client_priv) = did_key_from_seed(0x91);
    let (peer_did, peer_priv) = did_key_from_seed(0x92);

    let mediator = TestMediator::builder()
        .local_did(client_did.clone())
        .local_did(peer_did.clone())
        // The §7.2.2 invite is a direct control message; see
        // `tsp_ping_correlation.rs`.
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn test mediator");

    let first_deadline = Duration::from_secs(2);
    let peer_delay = Duration::from_secs(4);

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
        let doc: serde_json::Value = serde_json::from_str(&frame).expect("request is JSON");
        let request_id = doc["id"].as_str().unwrap_or_default().to_string();
        // A slow VTA: the reply lands after the client's first deadline, so
        // only the recovery can deliver it.
        tokio::time::sleep(peer_delay).await;
        let reply = serde_json::to_vec(&serde_json::json!({
            "id": "urn:uuid:the-late-response",
            "threadId": request_id,
            "type": "https://trusttasks.org/spec/provision/integration/0.3#response",
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

    let client = TspSession::connect(&client_did, &client_priv, mediator.did())
        .await
        .expect("client TSP session connects");
    client
        .relate(&peer_did)
        .await
        .expect("client forms a TSP relationship with the peer");
    let request = serde_json::to_vec(&serde_json::json!({
        "id": "urn:uuid:a-request-whose-reply-is-late",
        "type": "https://trusttasks.org/spec/provision/integration/0.3",
        "issuer": client_did,
        "recipient": peer_did,
        "payload": {},
    }))
    .expect("serialize request");

    let started = Instant::now();
    let result = client
        .request(&peer_did, mediator.did(), &request, first_deadline)
        .await
        .map_err(|e| e.to_string());
    let elapsed = started.elapsed();
    client.shutdown().await;
    let _ = responder.await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");

    let reply = result.expect("a reply landing after the first deadline must still be collected");
    assert!(
        reply.contains("urn:uuid:the-late-response"),
        "the late reply, not another frame: {reply}"
    );
    // Bounded (R1.2): the first deadline plus at most one grace window and the
    // reconnect, which is itself bounded by the grace.
    assert!(
        elapsed < first_deadline + STRANDED_REPLY_GRACE * 2,
        "took {elapsed:?}"
    );
}

/// The other half: no reply at all is still a reply timeout, after the grace,
/// not a hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_reply_still_times_out_after_the_grace() {
    common::init_tracing();
    let (client_did, client_priv) = did_key_from_seed(0x93);
    let (peer_did, _) = did_key_from_seed(0x94);

    let mediator = TestMediator::builder()
        .local_did(client_did.clone())
        .local_did(peer_did.clone())
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn test mediator");

    let client = TspSession::connect(&client_did, &client_priv, mediator.did())
        .await
        .expect("client TSP session connects");
    let request = serde_json::to_vec(&serde_json::json!({
        "id": "urn:uuid:a-request-nobody-answers",
        "payload": {},
    }))
    .expect("serialize request");

    let started = Instant::now();
    let result = client
        .request(&peer_did, mediator.did(), &request, Duration::from_secs(1))
        .await
        .map_err(|e| e.to_string());
    let elapsed = started.elapsed();
    client.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");

    let err = result.expect_err("nobody answered");
    assert!(err.contains("timed out waiting for the TSP reply"), "{err}");
    assert!(
        elapsed >= STRANDED_REPLY_GRACE,
        "the grace was given: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(1) + STRANDED_REPLY_GRACE * 2,
        "took {elapsed:?}"
    );
}
