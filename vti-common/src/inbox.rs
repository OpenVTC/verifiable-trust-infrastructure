//! Keeping a node's mediator inbox collected — shared by the VTA and the VTC.
//!
//! # Why this exists
//!
//! A message sent to a node waits in the node's mediator inbox until the node
//! deletes it, and while it waits it counts against its **sender's** per-peer
//! quota (`limits.queue.peer`, 50 by default). So a node that stops collecting
//! does not fail on its own side: its peers start being refused
//! `e.p.limits.queue.peer` and cannot answer it, while the node's own sends
//! still succeed. That is the "send alive, receive dead" state of the
//! 2026-10-05 incident, and three things here keep a node out of it or make
//! it visible when it is in it:
//!
//! - [`run_inbox_watch`] asks the mediator, every [`CHECK_INTERVAL`], how much
//!   is waiting. A message that has waited longer than a live push takes is
//!   asked for again (the VTC's VTI-50 catch-up, now shared). A request that
//!   goes **unanswered** while the socket reports connected is the receive leg
//!   failing end to end — the reply rides the same live stream as every other
//!   inbound message — and after [`UNANSWERED_ALARM`] in a row it is reported
//!   and the socket is reconnected ([`ATMProfile::reconnect_websocket`]),
//!   at most once per [`RECONNECT_MIN_INTERVAL`] and backing off while
//!   reconnects do not help ([`ReconnectGovernor`], R1.4).
//! - The catch-up is **bounded** (R1.4). A message that survives a redelivery
//!   is one the node cannot collect, and asking again every 30 s forever only
//!   re-pushes it. The interval backs off to [`MAX_REDELIVERY_BACKOFF`] and the
//!   condition is reported once.
//! - [`InboxHealth`] carries the messaging SDK's own view of the receive side
//!   ([`ReceiveLegHealth`]: last data frame, frames held for the application,
//!   a stalled consumer, its probe, and the frames it could not unpack), so a
//!   health endpoint shows both what the mediator says and what the socket saw.
//!
//! # Who deletes a frame this node cannot unpack
//!
//! The messaging SDK, and only the SDK. From `affinidi-messaging-sdk` 0.33.2
//! its live stream deletes a DIDComm frame that cannot be unpacked by the same
//! rule its pickup drain already used: a failure that is a property of the
//! bytes is deleted at once, a transient one only after three failures over at
//! least an hour, and one for want of this node's own key (`SecretsError`)
//! **never**. TSP frames were already deleted by its TSP adapter. This module
//! used to delete such frames itself on their second delivery, which would now
//! be a second owner with a weaker rule — it would delete a `SecretsError`
//! frame, and a transient failure after a minute. So
//! [`run_unprocessable_report`] only counts what the SDK reports; it is given
//! no handle that could delete anything.
//!
//! Peers that do the same to *us* are handled by [`UncollectedPeers`]: a send
//! refused `limits.queue.peer` means the recipient is not collecting, and it is
//! reported once per recipient rather than once per reply.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use affinidi_messaging_core::{ConnState, MessagingError, QueueFullGate};
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::ReceiveHealth;
use affinidi_tdk::messaging::errors::ATMError;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::protocols::message_pickup::{
    MessagePickupStatusReply, UnprocessableMessage,
};
use serde::Serialize;
use tokio::sync::{broadcast, watch};
use tracing::{debug, info, warn};

// ─── inbox watch ─────────────────────────────────────────────────────────

/// How often the mediator is asked how much is waiting. Well inside the
/// shortest message expiry seen in practice (300 s), so a missed push is
/// collected with most of its life left.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// How long a message may wait while the socket is live before it counts as
/// missed. A message pushed live is acked (and so deleted) within a second or
/// two; one that has waited this long was not pushed, or the push did not
/// arrive.
pub const STALE_AFTER_SECS: u64 = 30;

/// Consecutive unanswered status requests, while the socket reports
/// connected, before the receive leg is declared not delivering. Three at
/// [`CHECK_INTERVAL`] is about 90 s: long enough that one slow mediator answer
/// does not trip it, short enough that peers are not refused for long.
pub const UNANSWERED_ALARM: u32 = 3;

/// Longest wait between redelivery requests for a backlog that redelivery
/// does not clear.
pub const MAX_REDELIVERY_BACKOFF: Duration = Duration::from_secs(30 * 60);

/// Two status readings name the same oldest message when their arrival times
/// agree to within this. Only needed when the mediator reports an age but not
/// an arrival time, where `now - age` jitters by the request's latency.
const SAME_OLDEST_TOLERANCE_SECS: u64 = 2;

/// Whether a node is collecting its mediator inbox, as last observed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum InboxCollection {
    /// No answer observed yet (just started, or the socket is down).
    #[default]
    Unknown,
    /// Nothing has waited longer than a live push takes.
    Collecting,
    /// Messages are waiting that live delivery did not bring; redelivery has
    /// been asked for.
    Backlogged,
    /// The socket reports connected, but the mediator's answers are not
    /// arriving: nothing sent to this node is reaching it.
    NotDelivering,
}

/// What a health endpoint reports about inbox collection. A snapshot, driven by
/// a signal that can go false again (R6.2) — every field is re-observed each
/// check.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct InboxHealth {
    pub state: InboxCollection,
    /// Messages waiting at the mediator at the last answered check.
    pub waiting: Option<u32>,
    /// Age of the oldest of them, in seconds.
    pub longest_waited_secs: Option<u64>,
    /// Status requests in a row that went unanswered while connected.
    pub unanswered_status_requests: u32,
    /// Redelivery requests in a row that left the same oldest message waiting.
    pub unproductive_redeliveries: u32,
    /// Unix seconds of the last answered status request.
    pub last_answered_at: Option<u64>,
    /// Inbound frames the messaging SDK reported it could not unpack, since
    /// start — on the live stream and on a pickup drain. Whether each was
    /// deleted is the SDK's decision; its count is
    /// [`ReceiveLegHealth::unprocessable_deleted`].
    pub unprocessable_seen: u64,
    /// Socket reconnects the watch asked for because the receive leg was not
    /// delivering, since start. The SDK's own probe reconnects are counted
    /// separately, in [`ReceiveLegHealth::probe_reconnects`].
    pub reconnects_requested: u64,
    /// Unix seconds of the last of them.
    pub last_reconnect_at: Option<u64>,
    /// Unix seconds before which no further reconnect will be asked for
    /// ([`ReconnectGovernor`]). `None` until the first.
    pub next_reconnect_not_before: Option<u64>,
    /// The messaging SDK's own view of the websocket's receive side, read when
    /// the snapshot is taken. `None` when no websocket transport is running.
    pub receive: Option<ReceiveLegHealth>,
}

/// The messaging SDK's [`ReceiveHealth`], as a health endpoint reports it.
///
/// A mirror rather than the SDK type itself because it is a wire shape: it is
/// serialised, documented in the VTC's OpenAPI document and generated into the
/// admin console's types, and an SDK field added later must not change that
/// contract without a change here. Times are Unix seconds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ReceiveLegHealth {
    /// When the last data frame arrived on the socket (not a ping or pong,
    /// which prove the socket and nothing about delivery).
    pub last_data_frame_at: Option<u64>,
    /// Frames held by the transport waiting for this node to take them.
    pub held_frames: u32,
    /// Set while frames have been held and not taken for longer than the SDK's
    /// stall threshold: this node is not reading, so nothing is being deleted
    /// at the mediator. A reconnect does not cure this.
    pub consumer_stalled_since: Option<u64>,
    /// Set while the SDK's receive-leg probe (a live-delivery request written
    /// after inbound went quiet) is waiting for any frame to arrive.
    pub probe_outstanding_since: Option<u64>,
    /// Reconnects the SDK forced because its probe went unanswered.
    pub probe_reconnects: u64,
    /// Frames the SDK could not unpack and deleted from the mediator, so they
    /// stop counting against their sender's queue.
    pub unprocessable_deleted: u64,
    /// Frames that failed to unpack transiently, or for want of this node's
    /// own key, and are being left at the mediator.
    pub unprocessable_retained: u32,
}

impl From<&ReceiveHealth> for ReceiveLegHealth {
    fn from(h: &ReceiveHealth) -> Self {
        Self {
            last_data_frame_at: h.last_data_frame_at,
            held_frames: h.held_frames,
            consumer_stalled_since: h.consumer_stalled_since,
            probe_outstanding_since: h.probe_outstanding_since,
            probe_reconnects: h.probe_reconnects,
            unprocessable_deleted: h.unprocessable_deleted,
            unprocessable_retained: h.unprocessable_retained,
        }
    }
}

/// A shared handle on [`InboxHealth`], written by [`run_inbox_watch`] and
/// [`run_unprocessable_report`] and read by health endpoints.
#[derive(Clone, Default)]
pub struct InboxWatch {
    inner: Arc<Mutex<InboxHealth>>,
    /// The SDK's receive-health channel, read at snapshot time so the report
    /// is never older than the SDK's own last publish.
    receive: Arc<Mutex<Option<watch::Receiver<ReceiveHealth>>>>,
}

impl InboxWatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// The latest observation, with the SDK's receive-side view as it stands.
    pub fn snapshot(&self) -> InboxHealth {
        let mut health = self.inner.lock().expect("inbox health mutex").clone();
        health.receive = self
            .receive
            .lock()
            .expect("receive health mutex")
            .as_ref()
            .map(|rx| ReceiveLegHealth::from(&*rx.borrow()));
        health
    }

    /// Report the SDK's receive-side view ([`ATMProfile::receive_health`])
    /// alongside the watch's own. [`run_inbox_watch`] does this itself.
    pub fn attach_receive_health(&self, rx: watch::Receiver<ReceiveHealth>) {
        *self.receive.lock().expect("receive health mutex") = Some(rx);
    }

    fn update(&self, f: impl FnOnce(&mut InboxHealth)) {
        f(&mut self.inner.lock().expect("inbox health mutex"));
    }
}

/// The part of a status reply the watch decides on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboxStatus {
    pub waiting: u32,
    pub longest_waited_secs: Option<u64>,
    /// Unix seconds the oldest waiting message arrived, when reported.
    pub oldest_received_time: Option<u64>,
}

impl From<&MessagePickupStatusReply> for InboxStatus {
    fn from(s: &MessagePickupStatusReply) -> Self {
        Self {
            waiting: s.message_count,
            longest_waited_secs: s.longest_waited_seconds,
            oldest_received_time: s.oldest_received_time,
        }
    }
}

impl InboxStatus {
    /// Whether this shows a message live delivery missed.
    ///
    /// Messages waiting with no age reported (a mediator that does not report
    /// ages) count as missed: redelivery is at-least-once and idempotent at the
    /// mediator, so asking needlessly costs one redelivery, and not asking loses
    /// the message.
    pub fn needs_catch_up(&self) -> bool {
        self.waiting > 0
            && self
                .longest_waited_secs
                .is_none_or(|waited| waited >= STALE_AFTER_SECS)
    }

    /// The arrival time of the oldest waiting message, as best it can be
    /// known: reported, or derived from its age.
    fn oldest_arrival(&self, now: u64) -> Option<u64> {
        self.oldest_received_time.or_else(|| {
            self.longest_waited_secs
                .map(|waited| now.saturating_sub(waited))
        })
    }
}

/// The outcome of one status request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// The mediator answered with a status.
    Answered(InboxStatus),
    /// The mediator answered, but not with a status (a problem report). The
    /// receive leg works; there is nothing to decide about the inbox.
    Refused,
    /// The request was written to the socket and no answer came back.
    Unanswered,
    /// The request was not sent (the socket is reconnecting, or packing it
    /// failed). Says nothing about the receive leg.
    NotSent,
}

/// Classify a failed status request.
///
/// `send_status_request` writes the request and then waits for the reply on the
/// live stream. A reply that does not come is `MsgSendError("No response from
/// API")`; a frame that was never written is a `TransportError` (R1.1), and a
/// socket that dropped while waiting is `Disconnected`. Only the first is
/// evidence against the receive leg, so only it counts toward
/// [`UNANSWERED_ALARM`].
pub fn classify_status_error(err: &ATMError) -> Probe {
    match err {
        ATMError::MsgSendError(msg) if msg.contains("No response") => Probe::Unanswered,
        ATMError::ProblemReport(..) | ATMError::MediatorError(..) => Probe::Refused,
        _ => Probe::NotSent,
    }
}

/// What the watch does after a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Nothing to do.
    Nothing,
    /// Ask the mediator to redeliver the inbox.
    Redeliver,
    /// The receive leg is not delivering.
    NotDelivering,
}

/// The catch-up decision, kept free of I/O so it can be tested.
#[derive(Debug, Default)]
pub struct CatchUp {
    unanswered: u32,
    unproductive: u32,
    /// Arrival time of the oldest message when redelivery was last asked for.
    asked_for_oldest: Option<u64>,
    /// Unix seconds before which redelivery is not asked for again.
    redeliver_not_before: u64,
    stuck_reported: bool,
    not_delivering_reported: bool,
}

/// Wait before the next redelivery request after `unproductive` requests in a
/// row left the same message waiting: none for the first, then doubling from
/// [`CHECK_INTERVAL`] to [`MAX_REDELIVERY_BACKOFF`].
pub fn redelivery_backoff(unproductive: u32) -> Duration {
    if unproductive == 0 {
        return Duration::ZERO;
    }
    let factor = 1u32.checked_shl(unproductive - 1).unwrap_or(u32::MAX);
    CHECK_INTERVAL
        .saturating_mul(factor)
        .min(MAX_REDELIVERY_BACKOFF)
}

impl CatchUp {
    /// Fold one probe in at unix time `now` and say what to do.
    pub fn step(&mut self, probe: Probe, now: u64) -> Step {
        match probe {
            Probe::NotSent => Step::Nothing,
            Probe::Unanswered => {
                self.unanswered = self.unanswered.saturating_add(1);
                if self.unanswered >= UNANSWERED_ALARM {
                    Step::NotDelivering
                } else {
                    Step::Nothing
                }
            }
            Probe::Refused => {
                self.unanswered = 0;
                self.not_delivering_reported = false;
                Step::Nothing
            }
            Probe::Answered(status) => {
                self.unanswered = 0;
                self.not_delivering_reported = false;
                if !status.needs_catch_up() {
                    self.unproductive = 0;
                    self.asked_for_oldest = None;
                    self.redeliver_not_before = 0;
                    self.stuck_reported = false;
                    return Step::Nothing;
                }
                let oldest = status.oldest_arrival(now);
                let same_as_last_ask = match (self.asked_for_oldest, oldest) {
                    (Some(asked), Some(now_oldest)) => {
                        asked.abs_diff(now_oldest) <= SAME_OLDEST_TOLERANCE_SECS
                    }
                    _ => false,
                };
                if now < self.redeliver_not_before {
                    return Step::Nothing;
                }
                if same_as_last_ask {
                    self.unproductive = self.unproductive.saturating_add(1);
                } else {
                    self.unproductive = 0;
                    self.stuck_reported = false;
                }
                self.asked_for_oldest = oldest;
                self.redeliver_not_before =
                    now.saturating_add(redelivery_backoff(self.unproductive).as_secs());
                Step::Redeliver
            }
        }
    }

    /// Unanswered requests in a row.
    pub fn unanswered(&self) -> u32 {
        self.unanswered
    }

    /// Redelivery requests in a row that left the same message waiting.
    pub fn unproductive(&self) -> u32 {
        self.unproductive
    }

    /// Start counting unanswered requests afresh, on a socket just reconnected.
    /// The new socket earns its own [`UNANSWERED_ALARM`] strikes, and a
    /// receive leg still dead after a reconnect is reported again.
    pub fn restart_receive_leg(&mut self) {
        self.unanswered = 0;
        self.not_delivering_reported = false;
    }

    /// Whether the stuck-backlog warning is due now (once per episode, from
    /// the second unproductive redelivery).
    fn take_stuck_report(&mut self) -> bool {
        if self.unproductive >= 2 && !self.stuck_reported {
            self.stuck_reported = true;
            return true;
        }
        false
    }

    /// Whether the not-delivering alarm is due now (once per episode).
    fn take_not_delivering_report(&mut self) -> bool {
        if self.unanswered >= UNANSWERED_ALARM && !self.not_delivering_reported {
            self.not_delivering_reported = true;
            return true;
        }
        false
    }
}

/// How [`run_inbox_watch`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchExit {
    /// The receive leg stopped delivering, reconnecting the socket did not
    /// restore it (or the socket could not be asked to), and the caller's
    /// [`Escalation::EndSession`] asked to be told, so it can tear the session
    /// down and build it again.
    NotDelivering,
}

// ─── receive-leg reconnects ──────────────────────────────────────────────

/// The fewest minutes between two reconnects the watch asks for. A reconnect
/// drops every request in flight on the socket and makes the mediator
/// redeliver the whole inbox, so it is not free; and the SDK's own receive
/// probe (60 s idle, 30 s to answer) usually reconnects first.
pub const RECONNECT_MIN_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// The longest wait between reconnects that keep failing to restore delivery.
pub const RECONNECT_MAX_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// How long asking the transport to reconnect may take. The request is a
/// command queued to the transport's task; a task that does not take it in
/// this long is wedged, which a reconnect request cannot fix (R1.2).
pub const RECONNECT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Up to this fraction of the wait is added at random, so nodes whose receive
/// legs died together (a mediator restart) do not reconnect together.
const RECONNECT_JITTER: f64 = 0.1;

/// The wait after `unproductive` remedies in a row that did not restore
/// delivery: [`RECONNECT_MIN_INTERVAL`] after the first, doubling to
/// [`RECONNECT_MAX_INTERVAL`].
pub fn reconnect_backoff(unproductive: u32) -> Duration {
    let factor = 1u32
        .checked_shl(unproductive.saturating_sub(1))
        .unwrap_or(u32::MAX);
    RECONNECT_MIN_INTERVAL
        .saturating_mul(factor)
        .min(RECONNECT_MAX_INTERVAL)
}

/// What a node does when a reconnect has not restored delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escalation {
    /// Keep reconnecting the socket, backing off. For a node whose messaging
    /// session is published once and cannot be rebuilt (the VTC).
    Never,
    /// Alternate: when a reconnect has not helped, the next remedy is to end
    /// the session ([`WatchExit::NotDelivering`]) so the caller rebuilds it —
    /// new ATM, new authentication — and the one after that is a reconnect
    /// again. For a node with a session supervisor (the VTA).
    EndSession,
}

/// What to do about a receive leg that is not delivering, now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remedy {
    /// Drop the socket and connect again ([`ATMProfile::reconnect_websocket`]).
    Reconnect,
    /// End the session so its supervisor rebuilds it.
    EndSession,
    /// The last remedy was too recent; report and wait.
    Wait,
}

#[derive(Debug, Default)]
struct GovernorState {
    unproductive: u32,
    last_at: Option<Instant>,
    not_before: Option<Instant>,
    last_remedy: Option<Remedy>,
    requested: u64,
}

/// Bounds the reconnects [`run_inbox_watch`] asks for (R1.4): at most one per
/// [`RECONNECT_MIN_INTERVAL`], backing off to [`RECONNECT_MAX_INTERVAL`] while
/// they do not restore delivery, with jitter.
///
/// A reconnect that works — the mediator answers again — resets the backoff
/// but not the floor, so a receive leg that keeps dying a minute after each
/// reconnect is still reconnected at most every [`RECONNECT_MIN_INTERVAL`].
///
/// Shared (`Arc`) so a node that rebuilds its session keeps the same budget
/// across sessions: a fresh session is not a reason to reconnect sooner.
#[derive(Debug)]
pub struct ReconnectGovernor {
    escalation: Escalation,
    state: Mutex<GovernorState>,
}

impl ReconnectGovernor {
    pub fn new(escalation: Escalation) -> Self {
        Self {
            escalation,
            state: Mutex::default(),
        }
    }

    pub fn escalation(&self) -> Escalation {
        self.escalation
    }

    /// The receive leg is not delivering at `now`. Say what to do, and if it is
    /// a remedy, record it. `jitter` is a sample in `[0, 1]`.
    pub fn decide(&self, now: Instant, jitter: f64) -> Remedy {
        let mut s = self.state.lock().expect("reconnect governor mutex");
        if s.not_before.is_some_and(|not_before| now < not_before) {
            return Remedy::Wait;
        }
        let remedy = match (self.escalation, s.last_remedy) {
            (Escalation::EndSession, Some(Remedy::Reconnect)) => Remedy::EndSession,
            _ => Remedy::Reconnect,
        };
        s.unproductive = s.unproductive.saturating_add(1);
        s.requested = s.requested.saturating_add(1);
        s.last_at = Some(now);
        s.last_remedy = Some(remedy);
        let wait = reconnect_backoff(s.unproductive);
        let spread = wait.mul_f64(RECONNECT_JITTER * jitter.clamp(0.0, 1.0));
        s.not_before = Some(now + wait + spread);
        remedy
    }

    /// The receive leg delivered again: the remedies so far worked. The next
    /// episode starts from the cheapest remedy and the shortest wait, but no
    /// sooner than [`RECONNECT_MIN_INTERVAL`] after the last one.
    pub fn recovered(&self) {
        let mut s = self.state.lock().expect("reconnect governor mutex");
        if s.unproductive == 0 {
            return;
        }
        s.unproductive = 0;
        s.last_remedy = None;
        s.not_before = s.last_at.map(|last| last + RECONNECT_MIN_INTERVAL);
    }

    /// Remedies asked for since start (reconnects and session ends).
    pub fn requested(&self) -> u64 {
        self.state
            .lock()
            .expect("reconnect governor mutex")
            .requested
    }

    /// When the next remedy may be asked for, if one is being held off.
    pub fn not_before(&self) -> Option<Instant> {
        self.state
            .lock()
            .expect("reconnect governor mutex")
            .not_before
    }
}

/// `instant` as Unix seconds, by its distance from `now`.
fn unix_at(instant: Instant, now: Instant, unix_now: u64) -> u64 {
    if instant >= now {
        unix_now.saturating_add(instant.duration_since(now).as_secs())
    } else {
        unix_now.saturating_sub(now.duration_since(instant).as_secs())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Watch `profile`'s mediator inbox every [`CHECK_INTERVAL`] while `conn`
/// reports connected (a disconnected socket is skipped: its reconnect
/// re-enables live delivery, which redelivers the inbox by itself).
///
/// Each check sends a Message Pickup 3.0 status request on the profile's
/// socket. A backlog live delivery missed is asked for again with
/// live-delivery-change `true`, which makes the mediator redeliver the stored
/// inbox down the live stream, so every redelivered message takes the one
/// inbound path (`DidCommTransport` → `MessagingService` → dispatch → ack) —
/// no second socket, no delivery request bypassing the delivery layer's ack.
///
/// Once [`UNANSWERED_ALARM`] requests in a row go unanswered while connected,
/// the receive leg is not delivering, and `reconnects` says what to do about
/// it: reconnect the socket ([`ATMProfile::reconnect_websocket`], which
/// re-registers for live delivery and redelivers the inbox), wait because the
/// last remedy was too recent, or — under [`Escalation::EndSession`], when a
/// reconnect has not helped or the transport would not take the request —
/// return [`WatchExit::NotDelivering`] so the caller rebuilds the session.
/// Under [`Escalation::Never`] it never returns.
///
/// The SDK's receive-side view ([`ATMProfile::receive_health`]) is attached
/// to `health` here, so it is reported alongside.
pub async fn run_inbox_watch(
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    conn: Option<watch::Receiver<ConnState>>,
    health: InboxWatch,
    reconnects: Arc<ReconnectGovernor>,
) -> WatchExit {
    if let Some(rx) = profile.receive_health().await {
        health.attach_receive_health(rx);
    }
    let mut tick = tokio::time::interval(CHECK_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick fires at once; the connect has just redelivered the inbox.
    tick.tick().await;
    let mut catch_up = CatchUp::default();
    let alias = profile.inner.alias.clone();
    loop {
        tick.tick().await;
        if conn
            .as_ref()
            .is_some_and(|c| *c.borrow() != ConnState::Connected)
        {
            health.update(|h| h.state = InboxCollection::Unknown);
            continue;
        }
        let probe = match atm
            .message_pickup()
            .send_status_request(&profile, true, Some(Duration::from_secs(10)))
            .await
        {
            Ok(Some(status)) => Probe::Answered(InboxStatus::from(&status)),
            Ok(None) => Probe::Refused,
            Err(e) => {
                let probe = classify_status_error(&e);
                debug!(profile = %alias, error = %e, ?probe, "inbox watch: status request failed");
                probe
            }
        };
        let was_not_delivering = catch_up.unanswered() >= UNANSWERED_ALARM;
        let now = unix_now();
        let step = catch_up.step(probe, now);
        if matches!(probe, Probe::Answered(_) | Probe::Refused) {
            reconnects.recovered();
        }

        health.update(|h| {
            h.unanswered_status_requests = catch_up.unanswered();
            h.unproductive_redeliveries = catch_up.unproductive();
            match probe {
                Probe::Answered(status) => {
                    h.waiting = Some(status.waiting);
                    h.longest_waited_secs = status.longest_waited_secs;
                    h.last_answered_at = Some(now);
                    h.state = if status.needs_catch_up() {
                        InboxCollection::Backlogged
                    } else {
                        InboxCollection::Collecting
                    };
                }
                Probe::Refused => {
                    h.last_answered_at = Some(now);
                    if h.state == InboxCollection::NotDelivering {
                        h.state = InboxCollection::Unknown;
                    }
                }
                Probe::Unanswered if step == Step::NotDelivering => {
                    h.state = InboxCollection::NotDelivering;
                }
                _ => {}
            }
        });

        if was_not_delivering && catch_up.unanswered() == 0 {
            info!(
                profile = %alias,
                "the mediator is answering again — inbound messages are reaching this node"
            );
        }

        match step {
            Step::Nothing => {}
            Step::NotDelivering => {
                if catch_up.take_not_delivering_report() {
                    warn!(
                        profile = %alias,
                        unanswered = catch_up.unanswered(),
                        interval_secs = CHECK_INTERVAL.as_secs(),
                        "the mediator socket reports connected, but status requests go \
                         unanswered: nothing sent to this node is reaching it, and its peers \
                         will be refused `limits.queue.peer` once their queue to it fills"
                    );
                }
                let at = Instant::now();
                let remedy = reconnects.decide(at, rand::random::<f64>());
                let not_before = reconnects
                    .not_before()
                    .map(|instant| unix_at(instant, at, now));
                health.update(|h| {
                    h.next_reconnect_not_before = not_before;
                    if remedy != Remedy::Wait {
                        h.reconnects_requested = h.reconnects_requested.saturating_add(1);
                        h.last_reconnect_at = Some(now);
                    }
                });
                match remedy {
                    Remedy::Wait => {}
                    Remedy::EndSession => {
                        warn!(
                            profile = %alias,
                            "a reconnect did not restore delivery; ending the messaging \
                             session so it is rebuilt"
                        );
                        return WatchExit::NotDelivering;
                    }
                    Remedy::Reconnect => {
                        catch_up.restart_receive_leg();
                        let failure = match tokio::time::timeout(
                            RECONNECT_REQUEST_TIMEOUT,
                            profile.reconnect_websocket(),
                        )
                        .await
                        {
                            Ok(Ok(())) => {
                                warn!(
                                    profile = %alias,
                                    next_not_before = ?not_before,
                                    "reconnecting the mediator socket so it re-registers for \
                                     live delivery and the mediator redelivers the inbox"
                                );
                                None
                            }
                            Ok(Err(e)) => Some(format!(
                                "the messaging SDK has no websocket transport to reconnect \
                                 for this profile: {e}"
                            )),
                            Err(_) => Some(format!(
                                "the websocket transport did not take a reconnect request \
                                 within {}s — its task is not running its command loop",
                                RECONNECT_REQUEST_TIMEOUT.as_secs()
                            )),
                        };
                        if let Some(failure) = failure {
                            if reconnects.escalation() == Escalation::EndSession {
                                warn!(
                                    profile = %alias,
                                    "could not reconnect the mediator socket ({failure}); \
                                     ending the messaging session so it is rebuilt"
                                );
                                return WatchExit::NotDelivering;
                            }
                            warn!(
                                profile = %alias,
                                next_not_before = ?not_before,
                                "could not reconnect the mediator socket ({failure}); the \
                                 receive leg stays down until the transport reconnects itself"
                            );
                        }
                    }
                }
            }
            Step::Redeliver => {
                if let Probe::Answered(status) = probe {
                    if catch_up.take_stuck_report() {
                        warn!(
                            profile = %alias,
                            waiting = status.waiting,
                            longest_waited_secs = ?status.longest_waited_secs,
                            redeliveries = catch_up.unproductive(),
                            next_in_secs = redelivery_backoff(catch_up.unproductive()).as_secs(),
                            "messages are waiting in the mediator inbox that redelivery does not \
                             collect — most likely frames this node cannot unpack and the \
                             messaging SDK is keeping (see its 'could not unpack' warnings, \
                             which name their senders and why each is kept); backing off \
                             redelivery requests"
                        );
                    } else {
                        info!(
                            profile = %alias,
                            waiting = status.waiting,
                            longest_waited_secs = ?status.longest_waited_secs,
                            "mediator inbox holds messages live delivery did not bring; asking for \
                             redelivery"
                        );
                    }
                }
                if let Err(e) = atm
                    .message_pickup()
                    .toggle_live_delivery(&profile, true)
                    .await
                {
                    warn!(
                        profile = %alias,
                        error = %e,
                        "inbox watch: could not ask the mediator to redeliver; retrying next tick"
                    );
                }
            }
        }
    }
}

// ─── unprocessable frames ────────────────────────────────────────────────

/// Count the inbound frames the messaging SDK reports it could not unpack, on
/// its unprocessable channel (`ATMConfigBuilder::with_unprocessable_message_channel`).
///
/// Reporting only. Deleting them is the SDK's (`with_delete_unprocessable`,
/// on by default from 0.33.2; see the module documentation for why there is
/// one owner). This function is not given the ATM or the profile, so it cannot
/// delete anything — in particular not a frame sent to a key this node has not
/// loaded (`SecretsError`), which the SDK keeps on purpose. The SDK names each
/// frame in its own WARN; here it is counted, and logged at debug.
pub async fn run_unprocessable_report(
    mut rx: broadcast::Receiver<UnprocessableMessage>,
    health: InboxWatch,
) {
    loop {
        match rx.recv().await {
            Ok(frame) => {
                health.update(|h| h.unprocessable_seen = h.unprocessable_seen.saturating_add(1));
                debug!(
                    frame = frame.attachment_id.as_deref().unwrap_or("<no id>"),
                    reason = %frame.reason,
                    "the messaging SDK could not unpack an inbound message"
                );
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                health.update(|h| {
                    h.unprocessable_seen = h.unprocessable_seen.saturating_add(skipped)
                });
                debug!(
                    skipped,
                    "unprocessable-frame reports lagged; counted, not described"
                );
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

// ─── peers that are not collecting ───────────────────────────────────────

/// How long a recipient refused `limits.queue.peer` stays marked as not
/// collecting. Within it, further refusals are logged at debug and optional
/// sends to it (relationship accepts) are skipped; after it, the next send
/// tries again, and success clears the mark.
pub const UNCOLLECTED_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Whether a send was refused because the recipient has too many messages
/// waiting **from us** — the mediator's per-peer gate. That gate moves only
/// when one relationship is over-full, and for a reply-only relationship it
/// means the recipient is not collecting its inbox.
pub fn refused_recipient_not_collecting(err: &ATMError) -> bool {
    err.http_status()
        .and_then(|s| s.queue_full())
        .is_some_and(|gate| gate == QueueFullGate::Peer)
}

/// [`refused_recipient_not_collecting`] for a delivery-layer error.
pub fn messaging_refused_recipient_not_collecting(err: &MessagingError) -> bool {
    err.queue_full() == Some(QueueFullGate::Peer)
}

/// Recipients recently refused by the mediator's per-peer gate.
///
/// A node answering a peer that has stopped collecting gets one refusal per
/// reply, and before this logged one warning per reply — every 30 s, per peer,
/// for as long as the peer's client kept retrying. The fact worth an operator's
/// attention is one sentence per recipient.
#[derive(Default)]
pub struct UncollectedPeers {
    marked: Mutex<HashMap<String, Instant>>,
}

impl UncollectedPeers {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a send to `did` was refused by the per-peer gate. Returns
    /// whether this is the first refusal in [`UNCOLLECTED_WINDOW`] — the one to
    /// warn about.
    pub fn record_refusal(&self, did: &str, now: Instant) -> bool {
        let mut marked = self.marked.lock().expect("uncollected peers mutex");
        marked.retain(|_, at| now.duration_since(*at) < UNCOLLECTED_WINDOW);
        match marked.get(did) {
            Some(_) => false,
            None => {
                marked.insert(did.to_string(), now);
                true
            }
        }
    }

    /// Record that a send to `did` was accepted: it is collecting again.
    /// Returns whether it had been marked.
    pub fn record_accepted(&self, did: &str) -> bool {
        self.marked
            .lock()
            .expect("uncollected peers mutex")
            .remove(did)
            .is_some()
    }

    /// Whether `did` was refused within [`UNCOLLECTED_WINDOW`] of `now`.
    pub fn is_marked(&self, did: &str, now: Instant) -> bool {
        self.marked
            .lock()
            .expect("uncollected peers mutex")
            .get(did)
            .is_some_and(|at| now.duration_since(*at) < UNCOLLECTED_WINDOW)
    }

    /// Log the outcome of a send to `did`, folding per-peer refusals into one
    /// warning per recipient. Returns whether the failure was handled here — a
    /// per-peer refusal — so the caller logs anything else as before.
    pub fn observe_send(&self, did: &str, what: &str, refused_not_collecting: bool) -> bool {
        if !refused_not_collecting {
            return false;
        }
        if self.record_refusal(did, Instant::now()) {
            warn!(
                recipient = %did,
                send = what,
                window_secs = UNCOLLECTED_WINDOW.as_secs(),
                "{did} is not collecting its mediator inbox; replies to it are being dropped"
            );
        } else {
            debug!(
                recipient = %did,
                send = what,
                "reply dropped: the recipient is still not collecting its mediator inbox"
            );
        }
        true
    }

    /// Note a send to `did` that succeeded, logging the recovery once.
    pub fn observe_delivered(&self, did: &str) {
        if self.record_accepted(did) {
            info!(recipient = %did, "{did} is collecting its mediator inbox again");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_core::HttpStatusError;

    fn status(waiting: u32, waited: Option<u64>, oldest: Option<u64>) -> Probe {
        Probe::Answered(InboxStatus {
            waiting,
            longest_waited_secs: waited,
            oldest_received_time: oldest,
        })
    }

    #[test]
    fn vti_50_only_a_message_live_delivery_missed_triggers_catch_up() {
        let s = |waiting, waited| InboxStatus {
            waiting,
            longest_waited_secs: waited,
            oldest_received_time: None,
        };
        assert!(!s(0, None).needs_catch_up(), "empty inbox");
        assert!(!s(1, Some(2)).needs_catch_up(), "fresh push in flight");
        assert!(s(1, Some(STALE_AFTER_SECS)).needs_catch_up(), "missed push");
        assert!(s(1, None).needs_catch_up(), "age unreported: ask");
    }

    #[test]
    fn vti_50_catch_up_runs_well_inside_a_short_message_expiry() {
        assert!(CHECK_INTERVAL.as_secs() * 3 < 300);
    }

    /// The defect: the catch-up asked for redelivery every 30 s forever for a
    /// message that redelivery could not collect (R1.4). It now backs off.
    #[test]
    fn a_backlog_redelivery_does_not_clear_is_asked_for_less_and_less_often() {
        let mut c = CatchUp::default();
        let oldest = Some(1_000);
        let mut now = 1_100;
        let mut asks = Vec::new();
        for _ in 0..200 {
            if c.step(status(4, None, oldest), now) == Step::Redeliver {
                asks.push(now);
            }
            now += CHECK_INTERVAL.as_secs();
        }
        let gaps: Vec<u64> = asks.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(
            gaps.windows(2).all(|w| w[1] >= w[0]),
            "gaps never shrink: {gaps:?}"
        );
        assert!(
            *gaps.last().unwrap() >= MAX_REDELIVERY_BACKOFF.as_secs(),
            "reaches the cap: {gaps:?}"
        );
        assert!(asks.len() < 20, "200 checks, {} asks", asks.len());
    }

    #[test]
    fn a_new_backlog_is_asked_for_at_once() {
        let mut c = CatchUp::default();
        assert_eq!(c.step(status(1, None, Some(100)), 200), Step::Redeliver);
        assert_eq!(c.step(status(1, None, Some(100)), 230), Step::Redeliver);
        assert_eq!(c.unproductive(), 1);
        // A different oldest message: redelivery worked, a new one is waiting.
        assert_eq!(c.step(status(1, None, Some(240)), 290), Step::Redeliver);
        assert_eq!(c.unproductive(), 0);
    }

    #[test]
    fn a_drained_inbox_resets_the_backoff() {
        let mut c = CatchUp::default();
        for t in 0..5 {
            c.step(status(1, None, Some(10)), 100 + t * 30);
        }
        assert!(c.unproductive() > 0);
        assert_eq!(c.step(status(0, None, None), 400), Step::Nothing);
        assert_eq!(c.unproductive(), 0);
        assert_eq!(c.step(status(1, None, Some(390)), 430), Step::Redeliver);
    }

    #[test]
    fn age_alone_identifies_the_same_oldest_message() {
        let mut c = CatchUp::default();
        assert_eq!(c.step(status(1, Some(40), None), 1_000), Step::Redeliver);
        // 30 s later the same message is 70-71 s old.
        assert_eq!(c.step(status(1, Some(71), None), 1_030), Step::Redeliver);
        assert_eq!(c.unproductive(), 1);
    }

    #[test]
    fn three_unanswered_requests_while_connected_mean_not_delivering() {
        let mut c = CatchUp::default();
        assert_eq!(c.step(Probe::Unanswered, 0), Step::Nothing);
        assert_eq!(c.step(Probe::Unanswered, 30), Step::Nothing);
        assert_eq!(c.step(Probe::Unanswered, 60), Step::NotDelivering);
        assert!(c.take_not_delivering_report());
        assert_eq!(c.step(Probe::Unanswered, 90), Step::NotDelivering);
        assert!(!c.take_not_delivering_report(), "reported once per episode");
        // Any answer ends the episode.
        assert_eq!(c.step(status(0, None, None), 120), Step::Nothing);
        assert_eq!(c.unanswered(), 0);
    }

    #[test]
    fn a_request_that_was_never_sent_is_not_evidence() {
        let mut c = CatchUp::default();
        for t in 0..10 {
            assert_eq!(c.step(Probe::NotSent, t), Step::Nothing);
        }
        assert_eq!(c.unanswered(), 0);
    }

    #[test]
    fn status_errors_are_classified_by_what_they_prove() {
        assert_eq!(
            classify_status_error(&ATMError::MsgSendError("No response from API".into())),
            Probe::Unanswered
        );
        assert_eq!(
            classify_status_error(&ATMError::TransportError(
                "WebSocket message not transmitted: websocket is not connected".into()
            )),
            Probe::NotSent
        );
        assert_eq!(
            classify_status_error(&ATMError::Disconnected("socket dropped".into())),
            Probe::NotSent
        );
        assert_eq!(
            classify_status_error(&ATMError::ProblemReport(
                "e.p.x".into(),
                "c".into(),
                "".into()
            )),
            Probe::Refused
        );
    }

    #[test]
    fn redelivery_backoff_doubles_to_its_cap() {
        assert_eq!(redelivery_backoff(0), Duration::ZERO);
        assert_eq!(redelivery_backoff(1), CHECK_INTERVAL);
        assert_eq!(redelivery_backoff(2), CHECK_INTERVAL * 2);
        assert_eq!(redelivery_backoff(40), MAX_REDELIVERY_BACKOFF);
    }

    // ─── reconnects (R1.4) ───────────────────────────────────────────────

    #[test]
    fn reconnect_backoff_starts_at_the_floor_and_doubles_to_its_cap() {
        assert_eq!(reconnect_backoff(0), RECONNECT_MIN_INTERVAL);
        assert_eq!(reconnect_backoff(1), RECONNECT_MIN_INTERVAL);
        assert_eq!(reconnect_backoff(2), RECONNECT_MIN_INTERVAL * 2);
        assert_eq!(reconnect_backoff(3), RECONNECT_MIN_INTERVAL * 4);
        assert_eq!(reconnect_backoff(40), RECONNECT_MAX_INTERVAL);
    }

    #[test]
    fn a_dead_receive_leg_is_reconnected_at_most_once_per_interval() {
        let g = ReconnectGovernor::new(Escalation::Never);
        let t = Instant::now();
        assert_eq!(g.decide(t, 0.0), Remedy::Reconnect);
        // Every check while it stays dead, up to the floor: wait.
        let mut at = t;
        while at < t + RECONNECT_MIN_INTERVAL {
            assert_eq!(g.decide(at, 0.0), Remedy::Wait);
            at += CHECK_INTERVAL;
        }
        assert_eq!(g.decide(t + RECONNECT_MIN_INTERVAL, 0.0), Remedy::Reconnect);
        assert_eq!(g.requested(), 2);
    }

    #[test]
    fn reconnects_that_do_not_help_back_off_to_the_cap() {
        let g = ReconnectGovernor::new(Escalation::Never);
        let start = Instant::now();
        let mut now = start;
        let mut asked = Vec::new();
        // Twelve hours of a receive leg that never comes back, checked every 30 s.
        while now < start + Duration::from_secs(12 * 3600) {
            if g.decide(now, 1.0) == Remedy::Reconnect {
                asked.push(now);
            }
            now += CHECK_INTERVAL;
        }
        let gaps: Vec<Duration> = asked.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(
            gaps.iter().all(|g| *g >= RECONNECT_MIN_INTERVAL),
            "{gaps:?}"
        );
        assert!(
            gaps.windows(2).all(|w| w[1] >= w[0]),
            "never shrinks: {gaps:?}"
        );
        assert!(
            *gaps.last().unwrap() >= RECONNECT_MAX_INTERVAL,
            "reaches the cap: {gaps:?}"
        );
        // Jitter adds at most 10%.
        assert!(
            *gaps.last().unwrap()
                <= RECONNECT_MAX_INTERVAL + RECONNECT_MAX_INTERVAL / 10 + CHECK_INTERVAL,
            "{gaps:?}"
        );
        assert!(asked.len() < 20, "12 h, {} reconnects", asked.len());
    }

    #[test]
    fn a_reconnect_that_works_resets_the_backoff_but_not_the_floor() {
        let g = ReconnectGovernor::new(Escalation::Never);
        let t = Instant::now();
        g.decide(t, 0.0);
        let t2 = t + RECONNECT_MIN_INTERVAL;
        g.decide(t2, 0.0);
        // Two unproductive: the next is 10 min out.
        assert_eq!(g.not_before(), Some(t2 + RECONNECT_MIN_INTERVAL * 2));
        // Delivery comes back, then dies again a minute later.
        g.recovered();
        assert_eq!(g.not_before(), Some(t2 + RECONNECT_MIN_INTERVAL));
        assert_eq!(g.decide(t2 + Duration::from_secs(60), 0.0), Remedy::Wait);
        assert_eq!(
            g.decide(t2 + RECONNECT_MIN_INTERVAL, 0.0),
            Remedy::Reconnect
        );
    }

    #[test]
    fn a_node_that_cannot_rebuild_its_session_never_ends_it() {
        let g = ReconnectGovernor::new(Escalation::Never);
        let mut now = Instant::now();
        for _ in 0..50 {
            assert_ne!(g.decide(now, 0.0), Remedy::EndSession);
            now += RECONNECT_MAX_INTERVAL * 2;
        }
    }

    #[test]
    fn a_node_with_a_supervisor_rebuilds_its_session_when_a_reconnect_did_not_help() {
        let g = ReconnectGovernor::new(Escalation::EndSession);
        let t = Instant::now();
        // The cheap remedy first.
        assert_eq!(g.decide(t, 0.0), Remedy::Reconnect);
        // Still dead when the next is due: rebuild the session.
        let t2 = t + reconnect_backoff(1);
        assert_eq!(g.decide(t2, 0.0), Remedy::EndSession);
        // Still dead in the new session: reconnect again before another rebuild.
        let t3 = t2 + reconnect_backoff(2);
        assert_eq!(g.decide(t3 - Duration::from_secs(1), 0.0), Remedy::Wait);
        assert_eq!(g.decide(t3, 0.0), Remedy::Reconnect);
        // Recovery puts it back at the start: the next episode reconnects first.
        g.recovered();
        assert_eq!(
            g.decide(t3 + RECONNECT_MIN_INTERVAL, 0.0),
            Remedy::Reconnect
        );
    }

    #[test]
    fn a_reconnected_socket_earns_its_own_strikes() {
        let mut c = CatchUp::default();
        for t in 0..3 {
            c.step(Probe::Unanswered, t * 30);
        }
        assert!(c.take_not_delivering_report());
        c.restart_receive_leg();
        assert_eq!(c.step(Probe::Unanswered, 120), Step::Nothing);
        assert_eq!(c.step(Probe::Unanswered, 150), Step::Nothing);
        assert_eq!(c.step(Probe::Unanswered, 180), Step::NotDelivering);
        assert!(
            c.take_not_delivering_report(),
            "reported again after a reconnect"
        );
    }

    #[test]
    fn instants_are_reported_as_unix_seconds() {
        let now = Instant::now();
        assert_eq!(unix_at(now + Duration::from_secs(300), now, 1_000), 1_300);
        assert_eq!(unix_at(now, now, 1_000), 1_000);
    }

    // ─── what a health endpoint reports ──────────────────────────────────

    #[test]
    fn the_sdk_receive_view_is_reported_alongside_the_watch() {
        let watch = InboxWatch::new();
        assert_eq!(watch.snapshot().receive, None, "no transport, no view");

        let mut sdk = ReceiveHealth::default();
        sdk.last_data_frame_at = Some(1_000);
        sdk.held_frames = 2;
        sdk.probe_reconnects = 1;
        sdk.unprocessable_deleted = 3;
        sdk.unprocessable_retained = 1;
        let (tx, rx) = watch::channel(sdk);
        watch.attach_receive_health(rx);
        let r = watch.snapshot().receive.expect("attached");
        assert_eq!(r.held_frames, 2);
        assert_eq!(r.unprocessable_deleted, 3);

        // Read at snapshot time: the SDK's next publish shows up without the
        // watch doing anything.
        tx.send_modify(|h| h.consumer_stalled_since = Some(1_060));
        assert_eq!(
            watch.snapshot().receive.unwrap().consumer_stalled_since,
            Some(1_060)
        );
    }

    #[test]
    fn inbox_health_serialises_in_the_shape_diagnostics_publish() {
        let watch = InboxWatch::new();
        let mut sdk = ReceiveHealth::default();
        sdk.probe_outstanding_since = Some(5);
        let (_tx, rx) = watch::channel(sdk);
        watch.attach_receive_health(rx);
        let v = serde_json::to_value(watch.snapshot()).unwrap();
        for key in [
            "state",
            "unansweredStatusRequests",
            "unprocessableSeen",
            "reconnectsRequested",
            "lastReconnectAt",
            "nextReconnectNotBefore",
            "receive",
        ] {
            assert!(v.get(key).is_some(), "missing {key}: {v}");
        }
        assert!(
            v.get("unprocessableDeleted").is_none(),
            "deletion is the SDK's, reported under `receive`: {v}"
        );
        let receive = &v["receive"];
        for key in [
            "lastDataFrameAt",
            "heldFrames",
            "consumerStalledSince",
            "probeOutstandingSince",
            "probeReconnects",
            "unprocessableDeleted",
            "unprocessableRetained",
        ] {
            assert!(receive.get(key).is_some(), "missing receive.{key}: {v}");
        }
        assert_eq!(receive["probeOutstandingSince"], 5);
    }

    #[tokio::test]
    async fn unprocessable_frames_are_counted_and_nothing_else() {
        let (tx, rx) = broadcast::channel(4);
        let watch = InboxWatch::new();
        let task = tokio::spawn(run_unprocessable_report(rx, watch.clone()));
        for reason in ["SecretsError: no key", "DIDComm error: bad tag"] {
            tx.send(UnprocessableMessage {
                attachment_id: Some("f".into()),
                raw: String::new(),
                reason: reason.into(),
            })
            .unwrap();
        }
        drop(tx);
        task.await.unwrap();
        assert_eq!(watch.snapshot().unprocessable_seen, 2);
    }

    fn peer_refusal() -> ATMError {
        HttpStatusError::from_parts(
            "send TSP message",
            503,
            None,
            None,
            r#"{"httpCode":503,"message":"{\"code\":\"e.p.limits.queue.peer\",\"comment\":\"Too many messages already waiting for this recipient\"}"}"#.to_string(),
        )
        .into()
    }

    #[test]
    fn a_per_peer_refusal_means_the_recipient_is_not_collecting() {
        assert!(refused_recipient_not_collecting(&peer_refusal()));
        let sender_gate: ATMError = HttpStatusError::from_parts(
            "send TSP message",
            503,
            None,
            None,
            r#"{"message":"{\"code\":\"e.p.limits.queue.sender\"}"}"#.to_string(),
        )
        .into();
        assert!(!refused_recipient_not_collecting(&sender_gate));
        assert!(!refused_recipient_not_collecting(
            &ATMError::TransportError("connection refused".into())
        ));
        let messaging = MessagingError::from(
            peer_refusal()
                .http_status()
                .expect("an http status")
                .clone(),
        );
        assert!(messaging_refused_recipient_not_collecting(&messaging));
    }

    #[test]
    fn a_recipient_is_reported_once_per_window() {
        let peers = UncollectedPeers::new();
        let t = Instant::now();
        assert!(peers.record_refusal("did:key:a", t), "first refusal warns");
        assert!(!peers.record_refusal("did:key:a", t + Duration::from_secs(30)));
        assert!(peers.record_refusal("did:key:b", t), "per recipient");
        assert!(peers.is_marked("did:key:a", t + Duration::from_secs(60)));
        assert!(!peers.is_marked("did:key:a", t + UNCOLLECTED_WINDOW));
        assert!(peers.record_refusal("did:key:a", t + UNCOLLECTED_WINDOW + Duration::from_secs(1)));
        assert!(peers.record_accepted("did:key:a"));
        assert!(!peers.is_marked("did:key:a", t + UNCOLLECTED_WINDOW + Duration::from_secs(2)));
    }
}
