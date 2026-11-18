//! Waking a device through its own mediator (#2663, design C; VTI-TRN-070 –
//! 074, VTI-APV-024).
//!
//! A pushed document waits in the recipient's mediator queue until its device
//! connects. Where the recipient holds an ACL `DeviceBinding` with a wake
//! channel, the VTA rings the device's push gateway itself
//! ([`crate::trust_tasks::step_up`]'s `trigger_gateway_wake`) — that path stays
//! first. Where it holds none (an approver this VTA never bound a device for),
//! the VTA asks the recipient's **mediator** to ring it instead, with
//! `messaging/wake/request/0.1` naming the message it just queued by the id
//! that mediator stores it under. The mediator decides: it rings only a device
//! that gave it a wake handle, only for mail actually queued from this sender,
//! and paces it.
//!
//! What this module holds to:
//!
//! - **Once per push, never re-rung** (VTI-TRN-072): a request names the first
//!   attempt's stored id, and an id named once is never named again, whatever
//!   re-polls or re-pushes follow.
//! - **Fire-and-forget** (VTI-TRN-074): the mediator answers every request
//!   with the same empty `#response`, which says nothing; the inbound spine
//!   drops it as a reply no waiter claimed.
//! - **An older mediator falls back silently**: one that predates the task
//!   answers with a `trust-task-error`. That refusal is recognised by its
//!   sender (a mediator this VTA just asked) and consumed quietly, and the
//!   mediator is not asked again for [`REFUSED_FOR`] — the device collects on
//!   its next connection, exactly as before.
//!
//! The record is in memory: after a restart every mediator is asked again, and
//! a stored id from before the restart can no longer be queued (the push it
//! belonged to has moved on or finished).

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::Duration;

/// How long a mediator that refused a wake request is not asked again.
pub const REFUSED_FOR: Duration = Duration::from_secs(60 * 60);

/// How long after a request a `trust-task-error` from the mediator it went to
/// is read as that request's refusal.
pub const REFUSAL_WINDOW: Duration = Duration::from_secs(2 * 60);

/// How long a stored id is remembered as rung. Longer than any push attempt's
/// window ([`vti_common::trust_task_push::ATTEMPT_WINDOW`]), after which the
/// mediator no longer holds the message under it for waking anyway.
const RUNG_FOR: Duration = Duration::from_secs(2 * 60 * 60);

/// Above this many remembered entries, stale ones are dropped.
const MAX_ENTRIES: usize = 4096;

/// The process's record of wake requests sent.
#[derive(Default)]
pub struct MediatorWake {
    /// Stored ids already named in a request, with when.
    rung: Mutex<HashMap<String, u64>>,
    /// Mediators that refused the task, with when.
    refused: Mutex<HashMap<String, u64>>,
    /// Mediators asked recently, with when — to recognise a refusal.
    asked: Mutex<HashMap<String, u64>>,
}

/// The record this process keeps.
pub static WAKE: LazyLock<MediatorWake> = LazyLock::new(MediatorWake::default);

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn within(at: u64, now: u64, span: Duration) -> bool {
    now.saturating_sub(at) <= span.as_millis() as u64
}

fn prune(map: &mut HashMap<String, u64>, now: u64, span: Duration) {
    if map.len() > MAX_ENTRIES {
        map.retain(|_, at| within(*at, now, span));
    }
}

impl MediatorWake {
    /// Claim the one request `msg_id` may carry, to `mediator`, at `now`.
    /// `false` when that id was already named (never re-ring a pending
    /// request, VTI-TRN-072) or `mediator` refused the task within
    /// [`REFUSED_FOR`]. A `true` records both the id and the ask.
    pub fn claim(&self, mediator: &str, msg_id: &str, now: u64) -> bool {
        {
            let refused = self.refused.lock().unwrap_or_else(PoisonError::into_inner);
            if refused
                .get(mediator)
                .is_some_and(|at| within(*at, now, REFUSED_FOR))
            {
                return false;
            }
        }
        {
            let mut rung = self.rung.lock().unwrap_or_else(PoisonError::into_inner);
            if rung
                .get(msg_id)
                .is_some_and(|at| within(*at, now, RUNG_FOR))
            {
                return false;
            }
            rung.insert(msg_id.to_string(), now);
            prune(&mut rung, now, RUNG_FOR);
        }
        let mut asked = self.asked.lock().unwrap_or_else(PoisonError::into_inner);
        asked.insert(mediator.to_string(), now);
        prune(&mut asked, now, REFUSAL_WINDOW);
        true
    }

    /// A `trust-task-error` arrived from `sender` at `now`. `true` when
    /// `sender` is a mediator this VTA asked to wake a device within
    /// [`REFUSAL_WINDOW`]: the error is that request's refusal, and the
    /// mediator is not asked again for [`REFUSED_FOR`].
    pub fn note_refusal(&self, sender: &str, now: u64) -> bool {
        let was_asked = self
            .asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(sender)
            .is_some_and(|at| within(at, now, REFUSAL_WINDOW));
        if was_asked {
            let mut refused = self.refused.lock().unwrap_or_else(PoisonError::into_inner);
            refused.insert(sender.to_string(), now);
            prune(&mut refused, now, REFUSED_FOR);
        }
        was_asked
    }
}

/// [`MediatorWake::note_refusal`] on the process's record, now.
pub fn note_refusal(sender: &str) -> bool {
    WAKE.note_refusal(sender, now_ms())
}

/// How often the stored id of a just-queued push is looked for.
#[cfg(feature = "didcomm")]
const STORED_ID_POLL: Duration = Duration::from_secs(1);

/// How long the stored id is waited for: the push's first attempt is handed
/// off by the delivery layer's drain within seconds when the mediator is up.
#[cfg(feature = "didcomm")]
const STORED_ID_WAIT: Duration = Duration::from_secs(60);

/// Ask `mediator` — the mediator holding `recipient`'s queue — to wake
/// `recipient`'s device for push `push`, once (spawned, best-effort).
///
/// Waits for the push's first attempt to be handed off, to learn the id the
/// mediator stores it under, then sends one `messaging/wake/request/0.1`
/// naming it. Nothing is sent when no id appears (the attempt was not handed
/// off over a transport that reports one), when the id was already named, or
/// when the mediator refused the task recently.
#[cfg(feature = "didcomm")]
pub fn request_wake(state: &crate::server::AppState, recipient: &str, mediator: &str, push: &str) {
    #[cfg(test)]
    REQUESTED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((recipient.to_string(), push.to_string()));
    let state = state.clone();
    let recipient = recipient.to_string();
    let mediator = mediator.to_string();
    let push = push.to_string();
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + STORED_ID_WAIT;
        let msg_id = loop {
            match vti_common::trust_task_push::stored_message_id(
                &state.trust_task_pushes_ks,
                &state.outbox_ks,
                &push,
            )
            .await
            {
                Ok(Some(id)) => break id,
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!(push = %push, error = %e, "wake request: push state unreadable");
                    return;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::debug!(
                    push = %push, recipient = %recipient,
                    "wake request not sent: the push was not handed off with a stored id"
                );
                return;
            }
            tokio::time::sleep(STORED_ID_POLL).await;
        };
        send_once(&state, &recipient, &mediator, &msg_id).await;
    });
}

/// Every `(recipient, push)` [`request_wake`] was asked for (unit tests).
#[cfg(all(test, feature = "didcomm"))]
pub(crate) static REQUESTED: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

/// What [`send_once`] did.
#[cfg(feature = "didcomm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WakeSend {
    /// Handed to this VTA's mediator.
    Sent,
    /// Not sent: the message was already named in a request, or the mediator
    /// refused the task recently.
    NotAsked,
    /// Claimed, but no messaging session to send it on.
    NoMessaging,
    /// Claimed, and the send failed (best-effort; not retried).
    Failed,
}

/// Send the one wake request `msg_id` may carry. Separated from
/// [`request_wake`]'s wait so the rule is testable without a live push.
#[cfg(feature = "didcomm")]
pub(crate) async fn send_once(
    state: &crate::server::AppState,
    recipient: &str,
    mediator: &str,
    msg_id: &str,
) -> WakeSend {
    if !WAKE.claim(mediator, msg_id, now_ms()) {
        tracing::debug!(
            recipient = %recipient, mediator = %mediator,
            "wake request not sent: already asked for this message, or the mediator does \
             not serve the task"
        );
        return WakeSend::NotAsked;
    }
    let Some((atm, profile)) = state.didcomm_bridge.wake_wiring() else {
        tracing::debug!(recipient = %recipient, "wake request not sent: messaging is not running");
        return WakeSend::NoMessaging;
    };
    match atm
        .trust_tasks()
        .wake_request(
            &profile,
            mediator,
            recipient,
            &[msg_id.to_string()],
            Some(affinidi_tdk::messaging::tasks::messaging::wake::request::v0_1::PayloadUrgency::Interactive),
        )
        .await
    {
        Ok(()) => {
            tracing::info!(
                recipient = %recipient, mediator = %mediator,
                "asked the recipient's mediator to wake its device (no ACL wake channel)"
            );
            WakeSend::Sent
        }
        Err(e) => {
            tracing::debug!(
                recipient = %recipient, mediator = %mediator, error = %e,
                "wake request not sent (best-effort; the device collects on its next connection)"
            );
            WakeSend::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEDIATOR: &str = "did:web:mediator.example";

    #[test]
    fn vti_trn_072_a_stored_id_is_named_once() {
        let wake = MediatorWake::default();
        assert!(wake.claim(MEDIATOR, "id-1", 1_000));
        assert!(
            !wake.claim(MEDIATOR, "id-1", 2_000),
            "a pending request is never rung again"
        );
        assert!(
            wake.claim(MEDIATOR, "id-2", 3_000),
            "another message may ring"
        );
    }

    #[test]
    fn an_older_mediators_refusal_is_recognised_and_remembered() {
        let wake = MediatorWake::default();
        assert!(
            !wake.note_refusal(MEDIATOR, 1_000),
            "an error from a mediator never asked is not a refusal of a wake request"
        );
        assert!(wake.claim(MEDIATOR, "id-1", 1_000));
        assert!(wake.note_refusal(MEDIATOR, 2_000));
        assert!(
            !wake.claim(MEDIATOR, "id-2", 3_000),
            "a mediator that refused the task is not asked again within the hour"
        );
        let later = 2_000 + REFUSED_FOR.as_millis() as u64 + 1;
        assert!(
            wake.claim(MEDIATOR, "id-3", later),
            "and is asked again after it"
        );
    }

    #[test]
    fn an_error_long_after_the_request_is_not_its_refusal() {
        let wake = MediatorWake::default();
        assert!(wake.claim(MEDIATOR, "id-1", 1_000));
        let late = 1_000 + REFUSAL_WINDOW.as_millis() as u64 + 1;
        assert!(!wake.note_refusal(MEDIATOR, late));
        assert!(wake.claim(MEDIATOR, "id-2", late));
    }
}
