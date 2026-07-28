//! End-to-end test for the VTA's transient mediator handshake.
//!
//! Spins up a real `TestMediator` (in-memory backend, ephemeral port,
//! fresh `did:peer:2.*` identity) and a `TestVta` (also `did:peer:2`),
//! then drives the 5-step handshake the VTA runs at first-enable time.
//! Asserts the resolved mediator surface matches what the test mediator
//! actually exposed.
//!
//! This is the lowest-overhead live-mediator test in the suite: no
//! AppConfig, no fjall store, no webvh log entry, no DIDCommBridge —
//! just the `run_transient_handshake` entry point that `enable_didcomm`
//! delegates to at step 4. If this works, the harness is solid enough
//! to layer the full `enable_didcomm` flow on top.

use std::time::Duration;

use affinidi_messaging_test_mediator::TestMediator;
use vta_service::messaging::handshake::{HandshakeOptions, HandshakeStage};

mod common;

use common::test_vta::TestVta;

// The mediator's WebSocket handler refuses upgrades unless the
// authenticated session has the LOCAL ACL bit, so we register the
// VTA's DID as a local account on the test mediator before spawning
// it. `TestMediatorBuilder::local_did` (added upstream in tdk-rs PR
// #303) inserts the DID into the account store with the LOCAL bit set
// at startup.
#[tokio::test]
async fn transient_handshake_against_live_mediator_succeeds() {
    common::init_tracing();

    let vta = TestVta::spawn().await.expect("spawn test VTA");
    let mediator = TestMediator::builder()
        .local_did(vta.did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    let opts = HandshakeOptions {
        timeout: Duration::from_secs(10),
        force: false,
    };

    let resolved = vta
        .run_transient_handshake(mediator.did(), opts)
        .await
        .expect("transient handshake against live mediator");

    assert_eq!(
        resolved.mediator_did,
        mediator.did(),
        "resolved mediator DID must echo the input"
    );
    assert!(
        !resolved.endpoint.is_empty(),
        "resolved mediator endpoint should be non-empty for a did:peer with a service URI"
    );
    assert!(
        resolved
            .endpoint
            .contains(&mediator.bound_addr().port().to_string()),
        "resolved endpoint {} should reference the mediator's bound port {}",
        resolved.endpoint,
        mediator.bound_addr().port(),
    );

    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");
}

/// The handshake must leave **no live websocket** behind.
///
/// Observing that from outside needs a lever, and the mediator has one: a
/// per-DID connection cap that *refuses* the new connection (POLICY close,
/// "per-DID connection limit reached") rather than evicting the old one. So with
/// the cap at 1, a second handshake for the same DID can only succeed if the
/// first one's socket is really gone.
///
/// Before the fix it was not. `transient_prove` never registered its profile
/// with the ATM, and its teardown was a comment claiming that dropping the
/// service and ATM closes the socket — which it does not: the transport task
/// transitively owns the only `Sender` for its own command channel, so nothing
/// going out of scope can end it. Every first-enable handshake leaked one
/// reconnecting socket for the VTA's own DID. This test fails (at Connect) on
/// that code.
#[tokio::test]
async fn transient_handshake_leaves_no_socket_behind() {
    common::init_tracing();

    let vta = TestVta::spawn().await.expect("spawn test VTA");
    let mediator = TestMediator::builder()
        .local_did(vta.did.clone())
        // One at a time: a second concurrent socket for this DID is refused,
        // which is what turns "the first one leaked" into a test failure.
        .max_websocket_connections_per_did(1)
        .spawn()
        .await
        .expect("spawn test mediator");

    let opts = HandshakeOptions {
        timeout: Duration::from_secs(10),
        force: false,
    };

    vta.run_transient_handshake(mediator.did(), opts.clone())
        .await
        .expect("first handshake succeeds");

    // The teardown is asynchronous at the mediator end (it decrements its count
    // when the connection handler returns), so give it a moment to settle. This
    // cannot mask the defect it guards: a leaked socket is still there after any
    // sleep — it reconnects on its own timer and never goes away.
    tokio::time::sleep(Duration::from_secs(1)).await;

    vta.run_transient_handshake(mediator.did(), opts)
        .await
        .expect(
            "second handshake for the same DID must succeed — if it fails at Connect, \
             the first handshake's websocket is still holding the mediator's per-DID slot",
        );

    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");
}

#[tokio::test]
async fn transient_handshake_unresolvable_did_fails_at_resolve_stage() {
    common::init_tracing();

    let vta = TestVta::spawn().await.expect("spawn test VTA");

    // A syntactically valid but unresolvable did:peer:2.* — the cache
    // resolver will reject it at step 1 before any network round trip.
    let bogus_did = "did:peer:2.unresolvable";
    let opts = HandshakeOptions {
        timeout: Duration::from_secs(2),
        force: false,
    };

    let err = vta
        .run_transient_handshake(bogus_did, opts)
        .await
        .expect_err("handshake against an unresolvable DID must fail");

    let vta_service::messaging::handshake::HandshakeError::Failed { stage, .. } = err;
    assert_eq!(
        stage,
        HandshakeStage::Resolve,
        "unresolvable DID should fail at the Resolve stage"
    );
}
