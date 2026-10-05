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
//!   inbound message — and after [`UNANSWERED_ALARM`] in a row it is reported,
//!   and optionally ends the session so the caller can reconnect.
//! - The catch-up is **bounded** (R1.4). A message that survives a redelivery
//!   is one the node cannot collect, and asking again every 30 s forever only
//!   re-pushes it. The interval backs off to [`MAX_REDELIVERY_BACKOFF`] and the
//!   condition is reported once.
//! - [`run_unprocessable_quarantine`] deletes frames this node cannot unpack.
//!   The messaging SDK reports them on its unprocessable channel and otherwise
//!   leaves them in the inbox, where they are redelivered on every catch-up and
//!   count against their sender's quota indefinitely. Each one is named in a
//!   WARN (sender, envelope, type, reason) and deleted on its second delivery.
//!
//! Peers that do the same to *us* are handled by [`UncollectedPeers`]: a send
//! refused `limits.queue.peer` means the recipient is not collecting, and it is
//! reported once per recipient rather than once per reply.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use affinidi_messaging_core::{ConnState, MessagingError, QueueFullGate};
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::errors::ATMError;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::protocols::message_pickup::{
    MessagePickupStatusReply, UnprocessableMessage,
};
use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};
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
    /// Inbound frames this node could not unpack, since start.
    pub unprocessable_seen: u64,
    /// Of those, the ones deleted from the mediator.
    pub unprocessable_deleted: u64,
}

/// A shared handle on [`InboxHealth`], written by [`run_inbox_watch`] and
/// [`run_unprocessable_quarantine`] and read by health endpoints.
#[derive(Clone, Default)]
pub struct InboxWatch {
    inner: Arc<Mutex<InboxHealth>>,
}

impl InboxWatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// The latest observation.
    pub fn snapshot(&self) -> InboxHealth {
        self.inner.lock().expect("inbox health mutex").clone()
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
    /// The receive leg stopped delivering and the caller asked to be told, so
    /// it can tear the session down and reconnect.
    NotDelivering,
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
/// With `exit_when_not_delivering`, returns [`WatchExit::NotDelivering`] once
/// [`UNANSWERED_ALARM`] requests in a row go unanswered while connected, so the
/// caller can reconnect; otherwise it keeps watching and reports.
pub async fn run_inbox_watch(
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    conn: Option<watch::Receiver<ConnState>>,
    health: InboxWatch,
    exit_when_not_delivering: bool,
) -> WatchExit {
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
                if exit_when_not_delivering {
                    return WatchExit::NotDelivering;
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
                             collect — most likely frames this node cannot unpack (see the \
                             'cannot unpack' warnings, which name their senders); backing off \
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

/// Deliveries of one unprocessable frame before it is deleted. Two, not one:
/// a failure on the first delivery may be transient — the sender's DID did not
/// resolve for a moment — and the catch-up redelivers within a minute, which
/// is the retry. A frame that fails twice, a catch-up interval apart, is not
/// going to unpack.
pub const UNPROCESSABLE_DELETE_AFTER: u32 = 2;

/// Frames remembered for the sighting count. Bounds the memory a hostile
/// sender can take here; the oldest is forgotten first.
const UNPROCESSABLE_CAPACITY: usize = 1024;

/// How long a sighting is remembered.
const UNPROCESSABLE_TTL: Duration = Duration::from_secs(60 * 60);

/// How long one delete may take to enqueue.
const DELETE_ENQUEUE_TIMEOUT: Duration = Duration::from_secs(5);

/// What can be said about a frame without decrypting it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrameDescription {
    /// `authcrypt`, `anoncrypt`, `signed`, `plaintext`, or `unknown`.
    pub envelope: &'static str,
    /// The sender's key id or DID, where the envelope names one. Unverified —
    /// it is the claim the frame makes, which is the point: it says whose queue
    /// the frame was counting against.
    pub sender: Option<String>,
    /// The message type, readable only for plaintext and the JWE `typ`.
    pub message_type: Option<String>,
}

fn b64_json(segment: &str) -> Option<serde_json::Value> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment.trim_end_matches('='))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn str_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key).and_then(|v| v.as_str()).map(str::to_string)
}

/// Describe a DIDComm frame from its outer envelope alone.
pub fn describe_frame(raw: &str) -> FrameDescription {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return FrameDescription {
            envelope: "unknown",
            ..Default::default()
        };
    };
    // JWE (authcrypt / anoncrypt).
    if value.get("ciphertext").is_some() {
        let header = value
            .get("protected")
            .and_then(|p| p.as_str())
            .and_then(b64_json)
            .unwrap_or_default();
        let alg = str_field(&header, "alg").unwrap_or_default();
        let envelope = if alg.starts_with("ECDH-1PU") {
            "authcrypt"
        } else if alg.starts_with("ECDH-ES") {
            "anoncrypt"
        } else {
            "unknown"
        };
        let sender = str_field(&header, "skid").or_else(|| {
            str_field(&header, "apu").and_then(|apu| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(apu.trim_end_matches('='))
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
            })
        });
        return FrameDescription {
            envelope,
            sender,
            message_type: str_field(&header, "typ"),
        };
    }
    // JWS (signed).
    if value.get("signatures").is_some() || value.get("signature").is_some() {
        let first = value
            .get("signatures")
            .and_then(|s| s.as_array())
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or_else(|| value.clone());
        let sender = first
            .get("header")
            .and_then(|h| str_field(h, "kid"))
            .or_else(|| {
                first
                    .get("protected")
                    .and_then(|p| p.as_str())
                    .and_then(b64_json)
                    .and_then(|h| str_field(&h, "kid"))
            });
        return FrameDescription {
            envelope: "signed",
            sender,
            message_type: None,
        };
    }
    // Plaintext.
    if value.get("type").is_some() || value.get("body").is_some() {
        return FrameDescription {
            envelope: "plaintext",
            sender: str_field(&value, "from"),
            message_type: str_field(&value, "type"),
        };
    }
    FrameDescription {
        envelope: "unknown",
        ..Default::default()
    }
}

/// The mediator's id for a frame: the lowercase hex `sha256` of the bytes it
/// stored and delivered.
pub fn frame_id(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

/// Per-frame sighting counts, bounded in size and age.
#[derive(Default)]
pub struct Sightings {
    counts: HashMap<String, (u32, Instant)>,
    order: VecDeque<String>,
}

impl Sightings {
    /// Record one delivery of `id` at `now` and return how many there have
    /// been, this one included.
    pub fn record(&mut self, id: &str, now: Instant) -> u32 {
        self.expire(now);
        if let Some((count, _)) = self.counts.get_mut(id) {
            *count = count.saturating_add(1);
            return *count;
        }
        self.counts.insert(id.to_string(), (1, now));
        self.order.push_back(id.to_string());
        while self.order.len() > UNPROCESSABLE_CAPACITY {
            if let Some(evicted) = self.order.pop_front() {
                self.counts.remove(&evicted);
            }
        }
        1
    }

    /// Forget `id` (it has been deleted).
    pub fn forget(&mut self, id: &str) {
        self.counts.remove(id);
        self.order.retain(|x| x != id);
    }

    fn expire(&mut self, now: Instant) {
        while let Some(id) = self.order.front() {
            match self.counts.get(id) {
                Some((_, first)) if now.duration_since(*first) < UNPROCESSABLE_TTL => break,
                _ => {
                    let id = self.order.pop_front().expect("front was just observed");
                    self.counts.remove(&id);
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.counts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}

/// Delete inbound frames `profile` cannot unpack, reported on the SDK's
/// unprocessable channel (`ATMConfigBuilder::with_unprocessable_message_channel`).
///
/// # The tradeoff (R1.6)
///
/// This deletes a message that was never handled — ack-before-handoff,
/// deliberately, as a poison-message defence. Left in the inbox, a frame that
/// cannot be unpacked is redelivered on every catch-up for its whole life and
/// counts against its sender's per-peer quota the whole time, so one bad frame
/// becomes a sender who can no longer reach this node. A transient failure (the
/// sender's DID briefly unresolvable) is not treated as poison: the first
/// delivery is only reported, and the frame is deleted on its
/// [`UNPROCESSABLE_DELETE_AFTER`]th, a catch-up interval or more later.
pub async fn run_unprocessable_quarantine(
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    mut rx: broadcast::Receiver<UnprocessableMessage>,
    health: InboxWatch,
) {
    let mut sightings = Sightings::default();
    loop {
        let frame = match rx.recv().await {
            Ok(frame) => frame,
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(
                    skipped,
                    "unprocessable-frame reports were dropped before they could be counted; \
                     those frames stay in the mediator inbox until they are redelivered"
                );
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => return,
        };
        let id = frame
            .attachment_id
            .clone()
            .unwrap_or_else(|| frame_id(&frame.raw));
        let described = describe_frame(&frame.raw);
        let seen = sightings.record(&id, Instant::now());
        health.update(|h| h.unprocessable_seen = h.unprocessable_seen.saturating_add(1));

        if seen < UNPROCESSABLE_DELETE_AFTER {
            warn!(
                frame = %id,
                sender = described.sender.as_deref().unwrap_or("<not named>"),
                envelope = described.envelope,
                message_type = described.message_type.as_deref().unwrap_or("<encrypted>"),
                reason = %frame.reason,
                "cannot unpack an inbound message; leaving it at the mediator for one more \
                 delivery in case the failure is transient"
            );
            continue;
        }

        match tokio::time::timeout(
            DELETE_ENQUEUE_TIMEOUT,
            atm.delete_message_background(&profile, &id),
        )
        .await
        {
            Ok(Ok(())) => {
                sightings.forget(&id);
                health.update(|h| {
                    h.unprocessable_deleted = h.unprocessable_deleted.saturating_add(1)
                });
                warn!(
                    frame = %id,
                    deliveries = seen,
                    sender = described.sender.as_deref().unwrap_or("<not named>"),
                    envelope = described.envelope,
                    message_type = described.message_type.as_deref().unwrap_or("<encrypted>"),
                    reason = %frame.reason,
                    "cannot unpack an inbound message — deleting it from the mediator so it \
                     stops being redelivered and stops counting against its sender's queue"
                );
            }
            Ok(Err(e)) => warn!(
                frame = %id,
                error = %e,
                "could not delete an unprocessable inbound message; it will be redelivered"
            ),
            Err(_) => warn!(
                frame = %id,
                timeout_secs = DELETE_ENQUEUE_TIMEOUT.as_secs(),
                "timed out queueing the delete of an unprocessable inbound message; it will be \
                 redelivered"
            ),
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

    fn b64(v: &serde_json::Value) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    }

    #[test]
    fn an_authcrypt_frame_names_its_sender_key() {
        let protected = b64(&serde_json::json!({
            "alg": "ECDH-1PU+A256KW",
            "skid": "did:key:z6Mkexample#z6LSexample",
            "typ": "application/didcomm-encrypted+json",
        }));
        let raw = serde_json::json!({"protected": protected, "ciphertext": "x"}).to_string();
        let d = describe_frame(&raw);
        assert_eq!(d.envelope, "authcrypt");
        assert_eq!(d.sender.as_deref(), Some("did:key:z6Mkexample#z6LSexample"));
    }

    #[test]
    fn an_authcrypt_frame_without_skid_names_its_sender_from_apu() {
        let apu = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("did:web:a#k");
        let protected = b64(&serde_json::json!({"alg": "ECDH-1PU+A256KW", "apu": apu}));
        let raw = serde_json::json!({"protected": protected, "ciphertext": "x"}).to_string();
        assert_eq!(describe_frame(&raw).sender.as_deref(), Some("did:web:a#k"));
    }

    #[test]
    fn an_anoncrypt_frame_names_no_sender() {
        let protected = b64(&serde_json::json!({"alg": "ECDH-ES+A256KW"}));
        let raw = serde_json::json!({"protected": protected, "ciphertext": "x"}).to_string();
        let d = describe_frame(&raw);
        assert_eq!(d.envelope, "anoncrypt");
        assert_eq!(d.sender, None);
    }

    #[test]
    fn a_signed_and_a_plaintext_frame_are_described() {
        let jws = serde_json::json!({
            "payload": "x",
            "signatures": [{"header": {"kid": "did:key:z6Mk#k"}, "signature": "s"}],
        })
        .to_string();
        let d = describe_frame(&jws);
        assert_eq!(
            (d.envelope, d.sender.as_deref()),
            ("signed", Some("did:key:z6Mk#k"))
        );

        let plain = serde_json::json!({
            "id": "1", "type": "https://example/x", "from": "did:web:b", "body": {}
        })
        .to_string();
        let d = describe_frame(&plain);
        assert_eq!(d.envelope, "plaintext");
        assert_eq!(d.sender.as_deref(), Some("did:web:b"));
        assert_eq!(d.message_type.as_deref(), Some("https://example/x"));

        assert_eq!(describe_frame("-ETSP...").envelope, "unknown");
    }

    #[test]
    fn a_frame_id_is_the_hex_sha256_of_its_bytes() {
        assert_eq!(
            frame_id("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sightings_count_and_stay_bounded() {
        let mut s = Sightings::default();
        let t = Instant::now();
        assert_eq!(s.record("a", t), 1);
        assert_eq!(s.record("a", t), 2);
        s.forget("a");
        assert_eq!(s.record("a", t), 1);
        for i in 0..(UNPROCESSABLE_CAPACITY + 50) {
            s.record(&format!("f{i}"), t);
        }
        assert!(s.len() <= UNPROCESSABLE_CAPACITY);
        // Expired entries are forgotten.
        let later = t + UNPROCESSABLE_TTL + Duration::from_secs(1);
        assert_eq!(s.record("f9999", later), 1);
        assert_eq!(s.len(), 1);
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
