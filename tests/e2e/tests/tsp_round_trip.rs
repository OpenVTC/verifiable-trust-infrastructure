//! Regression guard: a TSP frame must be delivered between two local accounts
//! on a mediator, and be readable on **both** socket modes.
//!
//! ## Why this exists
//!
//! TSP submissions against a deployed VTA used to round-trip intermittently —
//! the send reported success and the reply never arrived, in multi-minute
//! bursts, while DIDComm over the same mediator stayed reliable throughout.
//! Client-side probing could not separate the candidate causes, because the
//! good/bad windows moved underneath every A/B.
//!
//! The root cause was below the VTA: the mediator never marked raw-TSP sockets
//! `Live`, so frames were accepted and then silently dropped rather than routed.
//! Fixed upstream in `affinidi-messaging-mediator` 0.17.7 (tdk #646), with the
//! SDK-side reply correlation in #750. The same shape had bitten the DIDComm
//! service earlier (#595/#618), which is why it is worth pinning here: the VTA
//! drives a *different* crate (`affinidi-messaging-delivery`), so a recurrence
//! would not be caught by the upstream test.
//!
//! ## What this tests, and what it deliberately does not
//!
//! The narrowest useful question: **can the mediator route a TSP frame from one
//! local account to another, and can the recipient read it?** No VTA, no Trust
//! Task dispatch, no ACL — just the transport. A failure here means the fault is
//! below everything the VTA or the device does.
//!
//! Each TSP case is paired with a **DIDComm control over the same mediator**, so
//! a failure is attributable to TSP rather than to harness or fixture noise.
//!
//! These are hermetic — `TestMediator`, no network, no deployed VTA — so they
//! run in CI unignored.

use std::time::Duration;

use affinidi_messaging_test_mediator::TestMediator;
use ed25519_dalek::SigningKey;
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::didcomm_session::DIDCommSession;
use vta_sdk::session::TspSession;

mod common;

/// Deterministic `did:key` + matching multibase private key from a seed byte.
/// Mirrors `didcomm_session.rs` so both binaries build identities identically.
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

/// A minimal Trust-Task-shaped document. TSP carries these bytes directly (no
/// DIDComm envelope), which is what the VTA's `tsp_inbound::dispatch_one`
/// expects, so this matches the real wire shape.
fn doc(id: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": id,
        "type": "https://trusttasks.org/spec/messaging/ping/0.1",
        "payload": { "nonce": id },
    }))
    .expect("serialize probe document")
}

/// **The core case.** Two local accounts, one mediator, one TSP frame.
///
/// `send_document` routes `[mediator, recipient]` — exactly what the device and
/// the VTA both do — and the recipient polls its own inbox on the raw-TSP
/// socket. This is the exact path that silently dropped frames before mediator
/// 0.17.7; a failure here is that regression returning.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tsp_frame_routes_between_two_local_accounts() {
    common::init_tracing();

    let (sender_did, sender_priv) = did_key_from_seed(0x31);
    let (recipient_did, recipient_priv) = did_key_from_seed(0x32);

    // BOTH DIDs must be local accounts: the sender needs the websocket upgrade,
    // and the recipient needs the mediator willing to hold a frame for it.
    let mediator = TestMediator::builder()
        .local_did(sender_did.clone())
        .local_did(recipient_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    let recipient = TspSession::connect(&recipient_did, &recipient_priv, mediator.did())
        .await
        .expect("recipient TSP inbox connects");
    let sender = TspSession::connect(&sender_did, &sender_priv, mediator.did())
        .await
        .expect("sender TSP session connects");

    let body = doc("urn:uuid:tsp-local-probe");
    sender
        .send_document(&recipient_did, mediator.did(), &body)
        .await
        .expect("send_document reports success");

    // Generous budget: the remote failure is a silent drop, not slowness, so a
    // short timeout would muddle "dropped" with "still in flight".
    let received = recipient
        .receive_next(20)
        .await
        .expect("receive_next must not error");

    sender.shutdown().await;
    recipient.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");

    let frame = received.expect(
        "TSP frame was sent successfully but never delivered — the pre-0.17.7 \
         silent-drop regression is back on the raw-TSP socket",
    );
    assert!(
        frame.contains("urn:uuid:tsp-local-probe"),
        "delivered frame was not the document we sent: {frame}"
    );
}

/// Control for the test above, over the *same* mediator fixture. If TSP fails
/// while this passes, the fault is TSP-specific rather than the harness.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn didcomm_control_over_the_same_mediator() {
    common::init_tracing();

    let (sender_did, sender_priv) = did_key_from_seed(0x41);
    let (recipient_did, _) = did_key_from_seed(0x42);

    let mediator = TestMediator::builder()
        .local_did(sender_did.clone())
        .local_did(recipient_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    let session =
        DIDCommSession::connect(&sender_did, &sender_priv, &recipient_did, mediator.did())
            .await
            .expect("DIDComm session connects");
    session
        .send_one_way(
            &recipient_did,
            "https://trusttasks.org/binding/didcomm/0.1/envelope",
            serde_json::json!({ "id": "urn:uuid:didcomm-control" }),
        )
        .await
        .expect("DIDComm one-way send succeeds over the same mediator");

    session.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");
}

/// Repetition, because the original failure was *bursty*: a single green run
/// proves little. Reports a count rather than asserting on the first failure, so
/// a regression's output distinguishes "never works" from "works 7 times in 10"
/// — the latter being exactly how this bug presented.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tsp_round_trip_is_not_intermittent() {
    common::init_tracing();

    const ROUNDS: usize = 10;
    let (sender_did, sender_priv) = did_key_from_seed(0x51);
    let (recipient_did, recipient_priv) = did_key_from_seed(0x52);

    let mediator = TestMediator::builder()
        .local_did(sender_did.clone())
        .local_did(recipient_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    let recipient = TspSession::connect(&recipient_did, &recipient_priv, mediator.did())
        .await
        .expect("recipient inbox connects");
    let sender = TspSession::connect(&sender_did, &sender_priv, mediator.did())
        .await
        .expect("sender connects");

    let mut delivered = 0usize;
    for round in 0..ROUNDS {
        let id = format!("urn:uuid:burst-{round}");
        sender
            .send_document(&recipient_did, mediator.did(), &doc(&id))
            .await
            .expect("send reports success");

        match recipient.receive_next(10).await {
            Ok(Some(f)) if f.contains(&id) => delivered += 1,
            Ok(Some(f)) => eprintln!("  round {round}: got an unexpected frame: {f}"),
            Ok(None) => eprintln!("  round {round}: ❌ silent drop (send reported success)"),
            Err(e) => eprintln!("  round {round}: ❌ receive error: {e}"),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    sender.shutdown().await;
    recipient.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");

    eprintln!("\n=== TSP local round trip: {delivered}/{ROUNDS} delivered ===");
    assert_eq!(
        delivered,
        ROUNDS,
        "TSP dropped {} of {ROUNDS} frames locally — the remote intermittency reproduces here",
        ROUNDS - delivered
    );
}

/// **The other socket mode.** Same send as
/// [`tsp_frame_routes_between_two_local_accounts`], but the recipient listens on
/// the **message-pickup** socket (`profile_enable_websocket` +
/// `live_stream_next_frame`) instead of the raw-TSP socket that
/// `TspSession::connect` opens.
///
/// The mediator *stores* an inbound TSP frame for a local recipient (see its
/// "TSP/bridged message stored for local recipient" log), and stored messages
/// are drained by message pickup. Both modes must deliver, because the workspace
/// uses both: the VTA's inbound loop reads pickup, while the device's
/// `TspMediatorSession` reads raw TSP.
///
/// Keeping both pinned is what makes a future failure *attributable*. When only
/// the raw-TSP socket was broken (pre-0.17.7), the two tests disagreed, and that
/// disagreement was the diagnosis.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tsp_frame_arrives_on_the_pickup_socket() {
    use affinidi_tdk::common::TDKSharedState;
    use affinidi_tdk::common::config::TDKConfig;
    // `insert` lives on the SecretsResolver trait — must be in scope.
    use affinidi_tdk::messaging::ATM;
    use affinidi_tdk::messaging::config::ATMConfig;
    use affinidi_tdk::messaging::profiles::ATMProfile;
    use affinidi_tdk::secrets_resolver::SecretsResolver;
    use std::sync::Arc;

    common::init_tracing();

    let (sender_did, sender_priv) = did_key_from_seed(0x61);
    let (recipient_did, recipient_priv) = did_key_from_seed(0x62);

    let mediator = TestMediator::builder()
        .local_did(sender_did.clone())
        .local_did(recipient_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    // Recipient on the PICKUP socket (the path the VTA uses), not raw TSP.
    let seed = vta_sdk::did_key::decode_private_key_multibase(&recipient_priv).expect("seed");
    let secrets = vta_sdk::did_key::secrets_from_did_key(&recipient_did, &seed).expect("secrets");
    let tdk = TDKSharedState::new(TDKConfig::builder().build().expect("tdk cfg"))
        .await
        .expect("tdk");
    tdk.secrets_resolver().insert(secrets.signing).await;
    tdk.secrets_resolver().insert(secrets.key_agreement).await;
    let atm = ATM::new(
        ATMConfig::builder().build().expect("atm cfg"),
        Arc::new(tdk),
    )
    .await
    .expect("atm");
    let profile = Arc::new(
        ATMProfile::new(
            &atm,
            None,
            recipient_did.clone(),
            Some(mediator.did().to_string()),
        )
        .await
        .expect("profile"),
    );
    // Registered so `graceful_shutdown` below can stop it; an unregistered
    // profile's socket survives every teardown (vta-sdk #830).
    let profile = atm
        .profile_add(&profile, false)
        .await
        .expect("register pickup profile");
    atm.profile_enable_websocket(&profile)
        .await
        .expect("enable pickup websocket");

    let sender = TspSession::connect(&sender_did, &sender_priv, mediator.did())
        .await
        .expect("sender connects");
    sender
        .send_document(
            &recipient_did,
            mediator.did(),
            &doc("urn:uuid:pickup-probe"),
        )
        .await
        .expect("send succeeds");

    // Enabling live delivery immediately yields a `messagepickup/3.0/status`
    // DIDComm frame; the TSP frame follows. Keep pulling until a `Tsp` variant
    // appears (or we run out of budget) rather than judging on the first frame.
    let mut tsp_frame: Option<String> = None;
    for _ in 0..6 {
        match atm
            .message_pickup()
            .live_stream_next_frame(&profile, Some(Duration::from_secs(5)), true)
            .await
            .expect("live_stream_next_frame must not error")
        {
            Some(affinidi_tdk::messaging::protocols::message_pickup::InboundFrame::Tsp(raw)) => {
                tsp_frame = Some(*raw);
                break;
            }
            Some(other) => eprintln!(
                "  (skipping non-TSP frame: {:?})",
                std::mem::discriminant(&other)
            ),
            None => {}
        }
    }

    sender.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins");

    match tsp_frame {
        Some(f) => eprintln!(
            "\n=== ✅ pickup socket received the TSP frame ({} bytes) ===",
            f.len()
        ),
        None => panic!(
            "pickup socket received no TSP frame — TSP delivery to the store-and-pickup \
             path is broken (this is the path the VTA's inbound loop reads)"
        ),
    }
}
