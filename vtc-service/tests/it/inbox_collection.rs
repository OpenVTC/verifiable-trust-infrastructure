//! A frame the VTC cannot unpack is deleted from its mediator inbox — by the
//! messaging SDK, once — and counted.
//!
//! What this pins: a frame left in the inbox is redelivered on every catch-up
//! for its whole life, and it counts against its **sender's** per-peer quota
//! (`limits.queue.peer`) the whole time — so one unreadable frame becomes a
//! sender that can no longer reach the VTC.
//!
//! From `affinidi-messaging-sdk` 0.33.2 the SDK's live stream deletes such a
//! frame itself (`with_delete_unprocessable`), and the VTC only counts the
//! SDK's reports; `vti_common::inbox` explains why there is one owner. The
//! frames below are anoncrypt, which the VTC's unpack policy rejects, so the
//! SDK deletes each on its first delivery, with no redelivery needed, through
//! the production listener (`run_didcomm_service`) on a real embedded
//! mediator. `/diagnostics` reports both halves: `unprocessableSeen` from the
//! VTC and `receive.unprocessableDeleted` from the SDK.
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
async fn an_unreadable_frame_is_deleted_by_the_sdk_and_counted() {
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

    // Each is reported to the VTC, and deleted by the SDK on its first
    // delivery: a policy rejection cannot become readable on a second one.
    assert!(
        eventually(Duration::from_secs(20), async || {
            let h = vtc.inbox.snapshot();
            h.unprocessable_seen >= FRAMES
                && h.receive
                    .as_ref()
                    .is_some_and(|r| r.unprocessable_deleted >= FRAMES)
        })
        .await,
        "every unreadable frame was reported and deleted: {:?}",
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
