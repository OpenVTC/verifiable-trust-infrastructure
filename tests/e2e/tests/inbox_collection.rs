//! A reply refused because its recipient is not collecting is recognised as
//! that, against the real mediator's wire.
//!
//! ## Why this exists
//!
//! On 2026-10-05 two OpenVTC admin sessions stopped collecting their mediator
//! inboxes. Each VTA reply to them queued, and at the mediator's per-peer cap
//! (`limits.queue.peer`, 50 by default) every further reply was refused `503
//! e.p.limits.queue.peer`. The VTA logged `failed to send TSP reply` with the
//! raw body about every 30 s per session, which said "something failed" and
//! not "this client is not collecting".
//!
//! `vti_common::inbox::refused_recipient_not_collecting` is what now tells the
//! two apart, and `UncollectedPeers` folds the refusals into one warning per
//! recipient. Both are unit-tested on a hand-built body; this pins them to the
//! body the mediator actually sends, so a change of wire shape on either side
//! fails here rather than silently returning the VTA to one warning per reply.
//!
//! Hermetic — an embedded `TestMediator` with a per-peer cap of 3, a TSP sender,
//! and a recipient that is registered but never connects (nothing collects).

use std::time::{Duration, Instant};

use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_test_mediator::TestMediator;
use ed25519_dalek::SigningKey;
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::session::TspSession;
use vti_common::inbox::{UncollectedPeers, refused_recipient_not_collecting};

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
async fn a_per_peer_refusal_is_recognised_as_the_recipient_not_collecting() {
    common::init_tracing();
    let (client_did, _) = did_key_from_seed(0x5a);
    let (vta_did, vta_priv) = did_key_from_seed(0x5b);

    let mediator = TestMediator::builder()
        .local_did(client_did.clone())
        .local_did(vta_did.clone())
        .local_direct_delivery(true, false)
        .queue_send_limit_per_peer(3)
        .spawn()
        .await
        .expect("spawn the test mediator");

    // The "VTA": a TSP sender. The client never connects, so nothing it is
    // sent is ever collected — the state the OpenVTC sessions were in.
    let vta = TspSession::connect(&vta_did, &vta_priv, mediator.did())
        .await
        .expect("the sender connects");
    vta.relate(&client_did)
        .await
        .expect("the invite is accepted by the mediator");

    let mut refusal = None;
    for i in 0..10 {
        let body = format!(r#"{{"id":"urn:uuid:reply-{i}","payload":{{}}}}"#);
        if let Err(e) = vta
            .send_document(&client_did, mediator.did(), body.as_bytes())
            .await
        {
            refusal = Some(e);
            break;
        }
    }
    let refusal =
        refusal.expect("the per-peer cap refuses a send to a recipient that never collects");
    let atm_err = refusal
        .downcast_ref::<ATMError>()
        .unwrap_or_else(|| panic!("the refusal keeps its typed ATMError: {refusal}"));
    assert!(
        refused_recipient_not_collecting(atm_err),
        "a `limits.queue.peer` refusal is classified as the recipient not collecting: {atm_err}"
    );

    // One warning per recipient, not one per refused reply.
    let peers = UncollectedPeers::new();
    let now = Instant::now();
    assert!(peers.record_refusal(&client_did, now));
    assert!(!peers.record_refusal(&client_did, now + Duration::from_secs(30)));
    assert!(peers.is_marked(&client_did, now + Duration::from_secs(30)));

    vta.shutdown().await;
    mediator.shutdown();
    let _ = mediator.join().await;
}
