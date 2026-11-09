//! A `TspSession` outlives the mediator closing its socket.
//!
//! ## Why this exists
//!
//! The mediator closes every websocket when the access token it was opened
//! with expires (close 1008, "authentication token expired"; 900 s by
//! default). `TspSession::request` reconnected only after a reply *timeout*,
//! so a long-lived session — `vtc-mcp` holds one for the life of the MCP
//! server — kept the dead socket, and every request after the first quarter
//! of an hour failed at once with "TSP websocket closed by the mediator".
//!
//! `request` now treats a closed socket as a reason to reconnect once (a fresh
//! authentication, so a fresh token) and keep waiting on the same waiter. The
//! request went out over the HTTP post, so the reply is in the inbox and the
//! new socket's flush-on-connect delivers it. Nothing is resent.
//!
//! Non-vacuous: before the change both tests below fail with "closed by the
//! mediator" — the client's socket is closed before its request is sent.
//!
//! Hermetic — an embedded `TestMediator` with a short access-token lifetime, a
//! client, and a peer playing the community.

use std::time::Duration;

use affinidi_messaging_test_mediator::TestMediator;
use ed25519_dalek::SigningKey;
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::session::TspSession;

mod common;

/// Long enough to connect and relate inside it, short enough to wait out.
const ACCESS_TOKEN_LIFETIME: Duration = Duration::from_secs(5);

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

fn request_doc(id: &str, issuer: &str, recipient: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": id,
        "type": "https://trusttasks.org/spec/vtc/members/list/0.2",
        "issuer": issuer,
        "recipient": recipient,
        "payload": {},
    }))
    .expect("serialize request")
}

/// A peer that answers `count` requests, each with a reply threaded to it.
/// Connected only after the client's socket has been closed, so its own
/// short-lived socket is fresh while it works.
fn spawn_responder(
    peer: TspSession,
    peer_did: String,
    client_did: String,
    mediator_did: String,
    count: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for _ in 0..count {
            let Ok(Some(frame)) = peer.receive_next(20).await else {
                break;
            };
            let doc: serde_json::Value = serde_json::from_str(&frame).expect("request is JSON");
            let request_id = doc["id"].as_str().unwrap_or_default().to_string();
            let reply = serde_json::to_vec(&serde_json::json!({
                "id": format!("{request_id}#reply"),
                "threadId": request_id,
                "type": "https://trusttasks.org/spec/vtc/members/list/0.2#response",
                "issuer": peer_did,
                "recipient": client_did,
                "payload": { "items": [] },
            }))
            .expect("serialize reply");
            peer.send_document(&client_did, &mediator_did, &reply)
                .await
                .expect("reply is accepted");
        }
        peer.shutdown().await;
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_after_the_token_expired_reconnects_and_gets_its_reply() {
    common::init_tracing();
    let (client_did, client_priv) = did_key_from_seed(0xa1);
    let (peer_did, peer_priv) = did_key_from_seed(0xa2);

    let mediator = TestMediator::builder()
        .local_did(client_did.clone())
        .local_did(peer_did.clone())
        .local_direct_delivery(true, false)
        .jwt_expiry(ACCESS_TOKEN_LIFETIME, Duration::from_secs(600))
        .spawn()
        .await
        .expect("spawn test mediator");
    let mediator_did = mediator.did().to_string();

    let client = TspSession::connect(&client_did, &client_priv, &mediator_did)
        .await
        .expect("client TSP session connects");
    client
        .relate(&peer_did)
        .await
        .expect("client forms a TSP relationship with the peer");

    // Outlive the token: the mediator closes the client's socket.
    tokio::time::sleep(ACCESS_TOKEN_LIFETIME + Duration::from_secs(2)).await;

    let peer = TspSession::connect(&peer_did, &peer_priv, &mediator_did)
        .await
        .expect("peer TSP session connects");
    let responder = spawn_responder(
        peer,
        peer_did.clone(),
        client_did.clone(),
        mediator_did.clone(),
        1,
    );

    let result = client
        .request(
            &peer_did,
            &mediator_did,
            &request_doc("urn:uuid:after-the-token-expired", &client_did, &peer_did),
            Duration::from_secs(15),
        )
        .await
        .map_err(|e| e.to_string());
    client.shutdown().await;
    let _ = responder.await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");

    let reply = result.expect("a closed socket must be reopened, not fail every request");
    assert!(
        reply.contains("urn:uuid:after-the-token-expired#reply"),
        "the reply to this request: {reply}"
    );
}

/// Several requests failing on the same close share one reconnect. Were each
/// to open its own socket, each would evict the last, and a reply already
/// flushed onto an evicted socket would be lost with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_on_a_closed_socket_all_get_their_replies() {
    common::init_tracing();
    let (client_did, client_priv) = did_key_from_seed(0xa3);
    let (peer_did, peer_priv) = did_key_from_seed(0xa4);

    let mediator = TestMediator::builder()
        .local_did(client_did.clone())
        .local_did(peer_did.clone())
        .local_direct_delivery(true, false)
        .jwt_expiry(ACCESS_TOKEN_LIFETIME, Duration::from_secs(600))
        .spawn()
        .await
        .expect("spawn test mediator");
    let mediator_did = mediator.did().to_string();

    let client = std::sync::Arc::new(
        TspSession::connect(&client_did, &client_priv, &mediator_did)
            .await
            .expect("client TSP session connects"),
    );
    client
        .relate(&peer_did)
        .await
        .expect("client forms a TSP relationship with the peer");

    tokio::time::sleep(ACCESS_TOKEN_LIFETIME + Duration::from_secs(2)).await;

    let peer = TspSession::connect(&peer_did, &peer_priv, &mediator_did)
        .await
        .expect("peer TSP session connects");
    const REQUESTS: usize = 3;
    let responder = spawn_responder(
        peer,
        peer_did.clone(),
        client_did.clone(),
        mediator_did.clone(),
        REQUESTS,
    );

    let mut waiting = Vec::new();
    for n in 0..REQUESTS {
        let client = client.clone();
        let (client_did, peer_did, mediator_did) =
            (client_did.clone(), peer_did.clone(), mediator_did.clone());
        waiting.push(tokio::spawn(async move {
            let id = format!("urn:uuid:concurrent-{n}");
            let reply = client
                .request(
                    &peer_did,
                    &mediator_did,
                    &request_doc(&id, &client_did, &peer_did),
                    Duration::from_secs(15),
                )
                .await
                .map_err(|e| e.to_string());
            (id, reply)
        }));
    }
    let mut results = Vec::new();
    for w in waiting {
        results.push(w.await.expect("request task joins"));
    }
    client.shutdown().await;
    let _ = responder.await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");

    for (id, reply) in results {
        let reply = reply.unwrap_or_else(|e| panic!("{id} got no reply: {e}"));
        assert!(reply.contains(&format!("{id}#reply")), "{id} got {reply}");
    }
}
