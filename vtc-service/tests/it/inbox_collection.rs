//! A frame the VTC cannot unpack is deleted from its mediator inbox, and named.
//!
//! What this pins: the messaging SDK reports a live frame it cannot unpack on
//! its unprocessable channel and otherwise leaves it in the inbox. There it is
//! redelivered on every catch-up for its whole life, and it counts against its
//! **sender's** per-peer quota (`limits.queue.peer`) the whole time — so one
//! unreadable frame becomes a sender that can no longer reach the VTC, and a
//! catch-up loop that asks for redelivery every 30 s forever.
//!
//! The VTC now deletes such a frame on its second delivery (the first may be a
//! transient failure, and the catch-up is the retry), through the production
//! listener (`run_didcomm_service`) on a real embedded mediator. Without the
//! fix the three frames below are still waiting after the redelivery.
//!
//! Requires `--features transport-harness`; CI runs it.

#![cfg(feature = "transport-harness")]

use std::time::Duration;

use vtc_service::test_support::MockVtcTransport;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

/// Poll `check` until it holds, for at most `limit`.
async fn eventually(limit: Duration, mut check: impl AsyncFnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < deadline {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_frame_is_deleted_on_its_second_delivery() {
    init_tracing();
    let t = MockVtcTransport::start().await;
    let vtc = t
        .vtc
        .state
        .didcomm
        .get()
        .expect("the listener published its messaging handle")
        .clone();

    const FRAMES: u64 = 3;
    for _ in 0..FRAMES {
        t.client.send_unreadable(t.vtc_did()).await;
    }

    // First delivery: reported and named, but kept — the failure might have
    // been transient, and the catch-up's redelivery is the retry.
    assert!(
        eventually(Duration::from_secs(20), async || {
            vtc.inbox.snapshot().unprocessable_seen >= FRAMES
        })
        .await,
        "every unreadable frame was reported: {:?}",
        vtc.inbox.snapshot()
    );
    assert_eq!(vtc.inbox.snapshot().unprocessable_deleted, 0);

    // The redelivery the inbox watch asks for once a message has waited 30 s.
    vtc.atm
        .message_pickup()
        .toggle_live_delivery(&vtc.profile, true)
        .await
        .expect("ask the mediator to redeliver the inbox");

    assert!(
        eventually(Duration::from_secs(20), async || {
            vtc.inbox.snapshot().unprocessable_deleted >= FRAMES
        })
        .await,
        "a frame that failed on two deliveries is deleted: {:?}",
        vtc.inbox.snapshot()
    );

    // And the mediator agrees: nothing is left counting against the sender.
    let drained = eventually(Duration::from_secs(20), async || {
        vtc.atm
            .message_pickup()
            .send_status_request(&vtc.profile, true, Some(Duration::from_secs(5)))
            .await
            .ok()
            .flatten()
            .is_some_and(|s| s.message_count == 0)
    })
    .await;
    assert!(
        drained,
        "the VTC's mediator inbox is empty after the deletes"
    );

    t.shutdown().await;
}
