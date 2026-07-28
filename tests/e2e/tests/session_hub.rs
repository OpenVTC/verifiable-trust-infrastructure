//! Coverage for `vta_sdk::session_hub::SessionHub` against a live
//! `TestMediator` — the parts of #830 that only a real socket can show.
//!
//! Two claims are under test here, and both need the mediator:
//!
//! 1. **`shutdown()` actually stops the websocket.** Before #830 no session in
//!    the SDK registered its `ATMProfile` with the ATM, and
//!    `ATM::graceful_shutdown` stops websockets by iterating that profile map —
//!    so `shutdown()` stopped the deletion handler and left a live,
//!    auto-reconnecting socket behind for the life of the process. Nothing else
//!    could ever stop it: the transport task transitively owns the only `Sender`
//!    for its own command channel, so the channel never closes on its own.
//! 2. **Identities on one hub are independent.** Tearing one down must leave its
//!    siblings connected — otherwise sharing an ATM would trade N ATMs for a
//!    shared failure domain, which is not a trade worth making.

use affinidi_messaging_test_mediator::TestMediator;
use ed25519_dalek::SigningKey;
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::didcomm_session::DIDCommSession;
use vta_sdk::session_hub::SessionHub;

mod common;

/// Build a deterministic `did:key` + matching multibase private-key string.
/// Same helper as `didcomm_session.rs`; each test binary is self-contained.
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

/// The regression test for the defect #830 surfaced: a session that has been
/// shut down must not still hold a live mediator socket.
///
/// `is_connected()` reads the transport's own `ConnState` watch, and reports
/// `false` once the transport is gone — so this fails if `shutdown()` ever stops
/// detaching the identity (which is what sends the transport its `Stop`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_stops_the_mediator_websocket() {
    common::init_tracing();

    let (client_did, client_priv) = did_key_from_seed(0x31);
    let (vta_did, _) = did_key_from_seed(0x32);

    let mediator = TestMediator::builder()
        .local_did(client_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    let session = DIDCommSession::connect(&client_did, &client_priv, &vta_did, mediator.did())
        .await
        .expect("session connects");

    assert!(
        session.is_connected().await,
        "a freshly connected session must report a live socket"
    );

    session.shutdown().await;

    assert!(
        !session.is_connected().await,
        "after shutdown() the websocket transport must be gone — a session that \
         reports connected here is the orphaned, auto-reconnecting socket #830 \
         is about"
    );

    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");
}

/// Two identities, one hub: each gets its own socket, and shutting one down
/// leaves the other alone. This is the shape a multi-tenant front door needs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_identities_share_one_hub_and_shut_down_independently() {
    common::init_tracing();

    let (alice_did, alice_priv) = did_key_from_seed(0x33);
    let (bob_did, bob_priv) = did_key_from_seed(0x34);
    let (vta_did, _) = did_key_from_seed(0x35);

    // Both DIDs must be local accounts on the mediator for the websocket
    // upgrade to succeed.
    let mediator = TestMediator::builder()
        .local_did(alice_did.clone())
        .local_did(bob_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    let hub = SessionHub::new().await.expect("build hub");

    let alice = DIDCommSession::connect_on(&hub, &alice_did, &alice_priv, &vta_did, mediator.did())
        .await
        .expect("alice connects on the hub");
    let bob = DIDCommSession::connect_on(&hub, &bob_did, &bob_priv, &vta_did, mediator.did())
        .await
        .expect("bob connects on the same hub");

    let mut identities = hub.identities().await;
    identities.sort();
    let mut expected = vec![alice_did.clone(), bob_did.clone()];
    expected.sort();
    assert_eq!(identities, expected, "both identities are on the one hub");

    assert!(alice.is_connected().await, "alice has her own live socket");
    assert!(bob.is_connected().await, "bob has his own live socket");

    // Tearing one identity down must not disturb the other.
    alice.shutdown().await;

    assert!(!alice.is_connected().await, "alice's socket is stopped");
    assert!(
        bob.is_connected().await,
        "bob's socket must survive alice's shutdown — sharing an ATM must not \
         mean sharing a failure domain"
    );
    assert_eq!(
        hub.identities().await,
        vec![bob_did.clone()],
        "only bob remains attached"
    );

    bob.shutdown().await;
    assert!(!bob.is_connected().await);
    assert!(hub.identities().await.is_empty());

    hub.shutdown().await;

    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");
}

/// A second session for a DID that already has one on the same hub is refused,
/// and the refusal must not disturb the live session.
///
/// This is the one-socket-per-DID rule expressed where a consumer will actually
/// hit it: the mediator would evict the older socket as `duplicate-channel` and
/// the two reconnect loops would duel, so failing the *second* connect is
/// strictly better than letting both exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_session_for_the_same_did_is_refused() {
    common::init_tracing();

    let (client_did, client_priv) = did_key_from_seed(0x36);
    let (vta_did, _) = did_key_from_seed(0x37);

    let mediator = TestMediator::builder()
        .local_did(client_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    let hub = SessionHub::new().await.expect("build hub");

    let first =
        DIDCommSession::connect_on(&hub, &client_did, &client_priv, &vta_did, mediator.did())
            .await
            .expect("first session connects");

    // Not `expect_err`: an unexpected `Ok` would drop a live session, and a
    // dropped-without-shutdown session trips the SDK's leak `debug_assert`,
    // masking this assertion's message with an unrelated panic.
    let msg =
        match DIDCommSession::connect_on(&hub, &client_did, &client_priv, &vta_did, mediator.did())
            .await
        {
            Err(e) => e.to_string(),
            Ok(second) => {
                second.shutdown().await;
                panic!("a second session for the same DID must be refused");
            }
        };
    assert!(
        msg.contains("one websocket per DID"),
        "the error must say why, not just that it failed: {msg}"
    );

    assert!(
        first.is_connected().await,
        "the refused second connect must leave the first session untouched"
    );

    first.shutdown().await;
    hub.shutdown().await;

    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");
}
