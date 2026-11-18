//! `rooms/watch/0.1` and `0.2`, and `rooms/changed/0.1`, host side and host-neutral: a
//! member asks a room's host for a content-free signal, sent to an address it names, when the
//! room moves past the version it has read to — **one** per arming (trust-tasks-tf #1036),
//! or, for a **live** watch (0.2, trust-tasks-tf #1087), one per change while a
//! conversation is open.
//!
//! Both hosts serve it — `room-host` and the VTC — and each keeps its own transport and
//! chain verification. A host authorizes the request exactly as a listing (`read`, the
//! chain rules of `rooms/records/put`), then calls [`RoomWatches::watch`] (0.1) or
//! [`RoomWatches::watch_v2`] (0.2); after any task that may have moved a room it calls
//! [`RoomWatches::room_moved`]; when a room's signal delay is set back to `randomised` it
//! calls [`RoomWatches::end_live_watches`]; and it lends a [`Signals`] that resolves an
//! address and sends one one-way Trust Task to it over the host's own outbound transport
//! (TSP before DIDComm, by what the address's DID document advertises).
//!
//! # What a watch is, and is not
//!
//! Host state, never room state (Host item 10): a watch grants nothing, is consulted to
//! authorize nothing, is shown to nobody, and does not move with the room. One per room and
//! address (item 3). It is forgotten when a one-shot watch fires, when it is cancelled, or
//! when it lapses at `expiresAt` — never later than the first credential of the
//! presentation that armed it stops being valid (item 8) — and never fires for a
//! presentation the room's held revocation list withdraws.
//!
//! # One signal per arming
//!
//! A one-shot watch fires once: the first time the room's latest version is above its
//! watermark — at once if it already is (item 4) — and is removed **before** its signal is
//! sent, under one lock, so two writes landing together send one signal, not two. The
//! signal carries the room and its latest version when sent, and nothing about what moved
//! it (item 9), and goes after a short randomised delay so its time does not mark one write
//! (`rooms/changed/0.1` Producer item 4) — unless the room's own signal delay is `none`
//! ([`crate::signal_delay`]), when it goes as soon as the change is stored. The room's
//! setting decides, never the watch request. Delivery is the delivery layer's: a signal is
//! never queued per change, re-sent or retried here (Producer item 5) — a lost one costs the
//! member nothing its next listing does not recover.
//!
//! # A live watch
//!
//! A live watch (`rooms/watch/0.2` `live: true`) is held only on a room whose signal delay
//! is `none` (item 6: refused `liveNotPermitted` otherwise, leaving any watch the request
//! named as it was), for a lease of at most [`MAX_LIVE_LEASE`] from each renewal (item 7).
//! It does not disarm when it signals: each time the room is above its watermark it sends
//! one signal carrying the latest version and **moves the watermark to it** (item 5). Its
//! signals are paced per watch at least [`LIVE_SIGNAL_SPACING`] apart: a change landing
//! within the spacing of the last signal arms one timer, and whatever landed by the time it
//! runs goes in the one signal it sends — never a queue per change, never a resend. A room
//! set back to `randomised` ends its live watches at once, sending nothing
//! ([`RoomWatches::end_live_watches`]); a live watch found on such a room is dropped
//! whenever the room is checked, so none is ever held there. The host keeps the watermark
//! and, in memory only, when it last signalled — the spacing needs it — and forgets both
//! with the watch.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use vti_specs_rooms::rooms::changed::v0_1 as changed_spec;
use vti_specs_rooms::rooms::watch::v0_1 as watch_spec;
use vti_specs_rooms::rooms::watch::v0_2 as watch_v2;

use crate::authz::{Action, AuthorizedAction, MAX_CHAIN_DEPTH};
use crate::blob_tasks::{Refusal, TaskResult, checked, declared, parse};
use crate::revocation::Presented;
use crate::signal_delay::SignalDelay;
use crate::wire::AuthorityPresentation;
use crate::{Room, Visibility, storage};

/// `rooms/watch/0.1`.
pub const WATCH_TYPE: &str = crate::wire::ROOMS_WATCH_TYPE;
/// `rooms/watch/0.2`: 0.1, and a live watch.
pub const WATCH_V2_TYPE: &str = crate::wire::ROOMS_WATCH_V2_TYPE;
/// `rooms/changed/0.1`, the signal a watch sends. One-way: it has no `#response`.
pub const CHANGED_TYPE: &str = <changed_spec::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Keyspace holding the watches a host has armed. Host state, never room state: it is not
/// backed up or migrated with a room (`rooms/watch/0.1`, *A watch does not move with the
/// room*).
pub const ROOM_WATCHES_KEYSPACE: &str = "room_watches";

/// The lease a watch gets when the request names none.
pub const DEFAULT_LEASE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// The longest lease a watch may hold (the schema's `leaseSeconds` maximum, 30 days).
pub const MAX_LEASE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// The longest lease a live watch is granted from a request, whatever it asks
/// (`rooms/watch/0.2` Host item 7).
pub const MAX_LIVE_LEASE: Duration = Duration::from_secs(120);
/// The least time between two signals of one live watch (`rooms/watch/0.2` Host item 5: at
/// least one second).
pub const LIVE_SIGNAL_SPACING: Duration = Duration::from_secs(1);
/// The most watches a host holds for one room (`rooms/watch:limitReached`).
pub const MAX_WATCHES_PER_ROOM: usize = 1024;
/// The most watches a host holds for one presenter in one room, where the tier discloses
/// the presenter's member (`rooms/watch:limitReached`).
pub const MAX_WATCHES_PER_PRESENTER: usize = 16;
/// The randomised interval a signal waits after the change that fires it, in milliseconds
/// (`rooms/changed/0.1` Producer item 4: "a few seconds"), in a room whose signal delay is
/// `randomised` — the default. A room whose signal delay is `none` waits not at all.
pub const SIGNAL_DELAY_MS: std::ops::RangeInclusive<u64> = 2_000..=6_000;

/// How a host reaches a watch's address: its own outbound transport, chosen by what the
/// address's DID document advertises — TSP before DIDComm — and never REST.
#[async_trait::async_trait]
pub trait Signals: Send + Sync {
    /// Whether `address` resolves to a DID document advertising a transport this host
    /// speaks. Sends nothing (`rooms/watch/0.1` Host item 2).
    async fn reachable(&self, address: &str) -> bool;

    /// Send one `rooms/changed/0.1` document carrying `payload` to `address`, one-way. `Ok`
    /// means the delivery layer accepted it, not that it was delivered; a failure is logged
    /// by the caller and never retried.
    async fn send_changed(&self, address: &str, payload: Value) -> Result<(), String>;
}

/// One armed watch, as stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Watch {
    room_id: String,
    address: String,
    /// The watermark: the watch fires once the room's latest version is above it. For a
    /// live watch, the version it last signalled once it has signalled.
    since_version: u64,
    /// The `leaseSeconds` asked for, if any — so that a repeat of the same request answers
    /// as the first did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lease_asked: Option<u64>,
    /// When the host forgets the watch, if it has not fired.
    expires_at: DateTime<Utc>,
    /// The member the presentation descends from, where the tier discloses one: what the
    /// per-presenter bound counts. Never shown to anyone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    member: Option<String>,
    /// The credentials the presentation carried, so that a watch whose presentation the
    /// room's list withdraws after it was armed never fires (Host item 8).
    presented: Presented,
    /// A live watch (`rooms/watch/0.2`): a signal per change, not one per arming. Absent —
    /// every watch armed before 0.2 — is one-shot.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    live: bool,
}

fn watch_key(room_id: &str, address: &str) -> Vec<u8> {
    let mut k = room_prefix(room_id);
    k.extend_from_slice(address.as_bytes());
    k
}

fn room_prefix(room_id: &str) -> Vec<u8> {
    let mut k = room_id.as_bytes().to_vec();
    k.push(0);
    k
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Check a `rooms/watch/0.1` payload against its schema (`malformedRequest` otherwise),
/// before the room is looked up.
#[allow(deprecated)] // still served beside 0.2 (trust-tasks-tf #1087)
pub fn check_payload(payload: &Value) -> Result<(), Refusal> {
    <watch_spec::Payload as trust_tasks_rs::validate::ValidatedPayload>::validate_value(payload)
        .map_err(|e| Refusal::Malformed(e.messages().join("; ")))?;
    parse::<watch_spec::Payload>(payload).map(|_| ())
}

/// Check a `rooms/watch/0.2` payload against its schema (`malformedRequest` otherwise),
/// before the room is looked up.
pub fn check_payload_v2(payload: &Value) -> Result<(), Refusal> {
    <watch_v2::Payload as trust_tasks_rs::validate::ValidatedPayload>::validate_value(payload)
        .map_err(|e| Refusal::Malformed(e.messages().join("; ")))?;
    parse::<watch_v2::Payload>(payload).map(|_| ())
}

/// Read a checked ([`check_payload`], [`check_payload_v2`]) `rooms/watch` request's
/// presentation, after the checks its own error codes declare: a chain of at most
/// [`MAX_CHAIN_DEPTH`] links (`rooms/watch:chainTooDeep`) and, on a `private` room, a
/// subject binding (`rooms/watch:subjectBindingMissing`) — the same codes at 0.1 and 0.2.
/// The host then authorizes it for [`Action::Read`].
pub fn presentation(payload: &Value, room: &Room) -> Result<AuthorityPresentation, Refusal> {
    use watch_spec::error_codes as codes;
    let presentation: AuthorityPresentation =
        serde_json::from_value(payload["presentation"].clone())
            .map_err(|e| Refusal::Malformed(format!("presentation: {e}")))?;
    if presentation.authority.len() > MAX_CHAIN_DEPTH {
        return Err(declared(
            codes::CHAIN_TOO_DEEP,
            format!(
                "the authority chain is {} links; at most {MAX_CHAIN_DEPTH}",
                presentation.authority.len()
            ),
            None,
        ));
    }
    if room.visibility == Visibility::Private && presentation.subject_binding.is_none() {
        return Err(declared(
            codes::SUBJECT_BINDING_MISSING,
            "a private room's presentation carries a subject binding",
            None,
        ));
    }
    Ok(presentation)
}

/// Which `rooms/watch` a request came in as, and so how it is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    V0_1,
    V0_2,
}

/// When a live watch last signalled, and whether a timer is set to send the next: the
/// pacing of Host item 5. In memory only, and forgotten with the watch.
#[derive(Debug, Default)]
struct Pace {
    last_sent: Option<tokio::time::Instant>,
    timer: bool,
}

/// What [`Inner::pace`] decided for a live watch whose room is above its watermark.
enum Paced {
    /// Signal now.
    Now,
    /// Within the spacing of the last signal: a timer set for this long sends the next.
    Later(Duration),
    /// A timer is already set; it will carry this change too.
    Pending,
}

/// The watches a host holds, and the one lock arming, cancelling and firing take, so a
/// one-shot watch fires once and a cancel is never overtaken by a signal it should have
/// stopped.
pub struct RoomWatches {
    inner: Arc<Inner>,
}

struct Inner {
    watches: KeyspaceHandle,
    rooms: KeyspaceHandle,
    revocations: KeyspaceHandle,
    signals: std::sync::RwLock<Option<Arc<dyn Signals>>>,
    lock: tokio::sync::Mutex<()>,
    /// The randomised delay before a signal, in milliseconds: [`SIGNAL_DELAY_MS`], or a
    /// test's own.
    delay_ms: std::sync::RwLock<(u64, u64)>,
    /// The spacing of a live watch's signals: [`LIVE_SIGNAL_SPACING`], or a test's own.
    spacing: std::sync::RwLock<Duration>,
    /// Each live watch's pace, by watch key.
    paces: std::sync::Mutex<HashMap<Vec<u8>, Pace>>,
}

impl std::fmt::Debug for RoomWatches {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoomWatches").finish_non_exhaustive()
    }
}

impl RoomWatches {
    /// Watches kept in `watches` ([`ROOM_WATCHES_KEYSPACE`]), over the host's `rooms` and
    /// `revocations` keyspaces. No signals until [`Self::set_signals`]: until then every
    /// address is unreachable, and a watch is refused `addressUnreachable` (Host item 2).
    pub fn new(
        watches: KeyspaceHandle,
        rooms: KeyspaceHandle,
        revocations: KeyspaceHandle,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                watches,
                rooms,
                revocations,
                signals: std::sync::RwLock::new(None),
                lock: tokio::sync::Mutex::new(()),
                delay_ms: std::sync::RwLock::new((
                    *SIGNAL_DELAY_MS.start(),
                    *SIGNAL_DELAY_MS.end(),
                )),
                spacing: std::sync::RwLock::new(LIVE_SIGNAL_SPACING),
                paces: std::sync::Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Shorten the randomised delay before a signal, for a host's own tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_signal_delay_ms(&self, from: u64, to: u64) {
        *self
            .inner
            .delay_ms
            .write()
            .unwrap_or_else(|p| p.into_inner()) = (from, to.max(from));
    }

    /// Change the spacing of a live watch's signals, for a host's own tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_live_spacing(&self, spacing: Duration) {
        *self
            .inner
            .spacing
            .write()
            .unwrap_or_else(|p| p.into_inner()) = spacing;
    }

    /// Lend the host's outbound transport, once it has one.
    pub fn set_signals(&self, signals: Arc<dyn Signals>) {
        *self
            .inner
            .signals
            .write()
            .unwrap_or_else(|p| p.into_inner()) = Some(signals);
    }

    /// `rooms/watch/0.1`, once [`presentation`] passed and the host authorized it for
    /// [`Action::Read`] against `room`. Arms, re-arms or cancels the one-shot watch on
    /// `room` and the payload's `address` — a live watch it names becomes one-shot (Host
    /// item 3) — and, once the authorization is released, fires it at once if the room is
    /// already past its watermark.
    pub async fn watch(
        &self,
        room: &Room,
        authorized: AuthorizedAction,
        payload: &Value,
        now: DateTime<Utc>,
    ) -> TaskResult {
        self.inner
            .arm(room, authorized, payload, now, Version::V0_1)
            .await
    }

    /// `rooms/watch/0.2`: 0.1, and with `live: true` arms or renews a live watch — only on a
    /// room whose signal delay is `none`, refused `liveNotPermitted` otherwise (Host item
    /// 6), and for at most [`MAX_LIVE_LEASE`] (item 7). Answers `live: true` for one.
    pub async fn watch_v2(
        &self,
        room: &Room,
        authorized: AuthorizedAction,
        payload: &Value,
        now: DateTime<Utc>,
    ) -> TaskResult {
        self.inner
            .arm(room, authorized, payload, now, Version::V0_2)
            .await
    }

    /// The room may have moved: fire every watch on `room_id` whose watermark the room's
    /// latest version is above — removing each one-shot watch before its signal is sent,
    /// moving each live watch's watermark on — and forget those that lapsed. Never fails
    /// the caller: a host calls this after a task has committed, and nothing here may undo
    /// or fail that task.
    pub async fn room_moved(&self, room_id: &str) {
        self.inner.room_moved(room_id).await
    }

    /// The room's signal delay was set to `randomised`: end every live watch on it at once,
    /// sending nothing to their addresses (`rooms/watch/0.2` Host item 6). One-shot watches
    /// stay. Never fails the caller, who has already recorded the setting; a live watch it
    /// misses is dropped the next time the room is checked. Returns how many it ended.
    pub async fn end_live_watches(&self, room_id: &str) -> usize {
        match self.inner.end_live(room_id).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(room = %room_id, error = %e, "could not end the room's live watches");
                0
            }
        }
    }

    /// Forget every watch that lapsed. A host runs this now and then; a room's own watches
    /// are also swept whenever the room moves.
    pub async fn sweep(&self, now: DateTime<Utc>) -> Result<usize, AppError> {
        let inner = &self.inner;
        let _held = inner.lock.lock().await;
        let mut removed = 0;
        for (k, v) in inner.watches.prefix_iter_raw(Vec::new()).await? {
            let lapsed = serde_json::from_slice::<Watch>(&v).map_or(true, |w| w.expires_at <= now);
            if lapsed {
                inner.watches.remove(k.clone()).await?;
                inner.forget_pace(&k);
                removed += 1;
            }
        }
        Ok(removed)
    }
}

impl Inner {
    fn signals(&self) -> Option<Arc<dyn Signals>> {
        self.signals
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn forget_pace(&self, key: &[u8]) {
        self.paces
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(key);
    }

    /// Host item 5's pacing for a live watch whose room is above its watermark.
    fn pace(&self, key: &[u8]) -> Paced {
        let spacing = *self.spacing.read().unwrap_or_else(|p| p.into_inner());
        let mut paces = self.paces.lock().unwrap_or_else(|p| p.into_inner());
        let pace = paces.entry(key.to_vec()).or_default();
        if pace.timer {
            return Paced::Pending;
        }
        let now = tokio::time::Instant::now();
        match pace.last_sent {
            Some(t) if now.duration_since(t) < spacing => {
                pace.timer = true;
                Paced::Later(spacing - now.duration_since(t))
            }
            _ => {
                pace.last_sent = Some(now);
                Paced::Now
            }
        }
    }

    fn timer_ran(&self, key: &[u8]) {
        if let Some(p) = self
            .paces
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(key)
        {
            p.timer = false;
        }
    }

    async fn room_watches(&self, room_id: &str) -> Result<Vec<(Vec<u8>, Watch)>, AppError> {
        Ok(self
            .watches
            .prefix_iter_raw(room_prefix(room_id))
            .await?
            .into_iter()
            .filter_map(|(k, v)| Some((k, serde_json::from_slice::<Watch>(&v).ok()?)))
            .collect())
    }

    async fn arm(
        self: &Arc<Self>,
        room: &Room,
        authorized: AuthorizedAction,
        payload: &Value,
        now: DateTime<Utc>,
        version: Version,
    ) -> TaskResult {
        use watch_v2::error_codes as codes;
        if authorized.action() != Action::Read || authorized.room_id() != room.room_id {
            return Err(Refusal::Internal(
                "a watch is authorized for `read` on its own room".into(),
            ));
        }
        let address = payload["address"]
            .as_str()
            .ok_or_else(|| Refusal::Malformed("address".into()))?
            .to_string();
        let key = watch_key(&room.room_id, &address);
        #[allow(deprecated)] // 0.1 is still answered beside 0.2
        let answer = |body: Value| match version {
            Version::V0_1 => checked::<watch_spec::Response>(body),
            Version::V0_2 => checked::<watch_v2::Response>(body),
        };

        // A host ignores `live`, `sinceVersion` and `leaseSeconds` on a cancel.
        if payload.get("cancel").and_then(Value::as_bool) == Some(true) {
            let _held = self.lock.lock().await;
            self.watches
                .remove(key.clone())
                .await
                .map_err(Refusal::App)?;
            self.forget_pace(&key);
            return answer(json!({
                "roomId": room.room_id,
                "address": address,
                "armed": false,
            }));
        }

        // `live` exists only at 0.2; a 0.1 request is one-shot, and its schema refuses the
        // member anyway.
        let live =
            version == Version::V0_2 && payload.get("live").and_then(Value::as_bool) == Some(true);
        // Host item 6: only on a room whose signal delay is `none`, and refused before
        // anything is touched, so a watch the request named stays as it was.
        if live && room.signal_delay != SignalDelay::None {
            return Err(declared(
                codes::LIVE_NOT_PERMITTED,
                format!(
                    "this room's signal delay is `{}`; a live watch is permitted only on a room \
                     whose signal delay is `none`. Nothing is armed, and any watch at this \
                     address is as it was; arm a one-shot watch instead",
                    room.signal_delay
                ),
                None,
            ));
        }

        let reachable = match self.signals() {
            Some(s) => s.reachable(&address).await,
            None => false,
        };
        if !reachable {
            return Err(declared(
                codes::ADDRESS_UNREACHABLE,
                "the address does not resolve to a DID document advertising a transport this \
                 host speaks; nothing is armed",
                None,
            ));
        }

        let asked_since = payload.get("sinceVersion").and_then(Value::as_u64);
        let lease_asked = payload.get("leaseSeconds").and_then(Value::as_u64);
        let mut lease = lease_asked
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_LEASE)
            .min(MAX_LEASE);
        if live {
            // Host item 7: at most 120 seconds from this request, whatever was asked.
            lease = lease.min(MAX_LIVE_LEASE);
        }
        let mut expires_at = now + chrono::Duration::from_std(lease).unwrap_or_default();
        if let Some(until) = authorized.valid_until() {
            expires_at = expires_at.min(until);
        }
        let member = authorized.member().map(str::to_string);
        let armed = {
            let _held = self.lock.lock().await;
            let held = self
                .room_watches(&room.room_id)
                .await
                .map_err(Refusal::App)?;
            let current = held
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, w)| w)
                .filter(|w| w.expires_at > now);
            // Host item 3: a live request that omits `sinceVersion` keeps the watermark of
            // the watch it names — for a live watch, the version it last signalled. Any other
            // request without one starts at the room's latest version.
            let since = asked_since.unwrap_or_else(|| match current {
                Some(w) if live => w.since_version,
                _ => room.watermark(),
            });
            match current {
                // A repeat of the one-shot request that armed it: the same answer (*A
                // repeated request*). A live renewal always takes a new lease (item 7).
                Some(w)
                    if !live
                        && !w.live
                        && w.since_version == since
                        && w.lease_asked == lease_asked =>
                {
                    w.clone()
                }
                _ => {
                    let others: Vec<&Watch> = held
                        .iter()
                        .filter(|(k, w)| *k != key && w.expires_at > now)
                        .map(|(_, w)| w)
                        .collect();
                    let by_member = member.as_ref().map_or(0, |m| {
                        others
                            .iter()
                            .filter(|w| w.member.as_ref() == Some(m))
                            .count()
                    });
                    if others.len() >= MAX_WATCHES_PER_ROOM
                        || by_member >= MAX_WATCHES_PER_PRESENTER
                    {
                        return Err(declared(
                            codes::LIMIT_REACHED,
                            "this host holds as many watches for this room as it allows; \
                             cancel one no longer needed and try again",
                            None,
                        ));
                    }
                    let w = Watch {
                        room_id: room.room_id.clone(),
                        address: address.clone(),
                        since_version: since,
                        lease_asked,
                        expires_at,
                        member,
                        presented: authorized.presented().clone(),
                        live,
                    };
                    self.watches
                        .insert(key.clone(), &w)
                        .await
                        .map_err(Refusal::App)?;
                    if !live {
                        // A watch made one-shot has no pace to keep.
                        self.forget_pace(&key);
                    }
                    w
                }
            }
        };
        let mut body = json!({
            "roomId": room.room_id,
            "address": address,
            "armed": true,
            "expiresAt": rfc3339(armed.expires_at),
        });
        if armed.live {
            body["live"] = json!(true);
        }
        let response = answer(body)?;
        // The room's gate is released before the room is read again and anything sent.
        drop(authorized);
        self.room_moved(&room.room_id).await;
        Ok(response)
    }

    async fn room_moved(self: &Arc<Self>, room_id: &str) {
        if let Err(e) = self.fire(room_id).await {
            tracing::warn!(room = %room_id, error = %e, "could not check the room's watches");
        }
    }

    /// [`Self::room_moved`] after `wait`, for a live watch's pacing timer — boxed, because it
    /// runs from inside [`Self::fire`].
    fn room_moved_later(
        self: Arc<Self>,
        room_id: String,
        key: Vec<u8>,
        wait: Duration,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            tokio::time::sleep(wait).await;
            self.timer_ran(&key);
            self.room_moved(&room_id).await;
        })
    }

    async fn end_live(&self, room_id: &str) -> Result<usize, AppError> {
        let _held = self.lock.lock().await;
        let mut ended = 0;
        for (k, w) in self.room_watches(room_id).await? {
            if w.live {
                self.watches.remove(k.clone()).await?;
                self.forget_pace(&k);
                ended += 1;
            }
        }
        Ok(ended)
    }

    async fn fire(self: &Arc<Self>, room_id: &str) -> Result<(), AppError> {
        let now = Utc::now();
        // Each due watch, with the version a live one signals (the watermark it moved to);
        // a one-shot one reads the latest version when it sends.
        let (due, delay): (Vec<(Watch, Option<u64>)>, SignalDelay) = {
            let _held = self.lock.lock().await;
            let held = self.room_watches(room_id).await?;
            if held.is_empty() {
                return Ok(());
            }
            let room = match storage::get_room(&self.rooms, room_id).await {
                Ok(r) => r,
                // A room this host no longer holds: its watches lapse (*A watch does not
                // move with the room*).
                Err(AppError::NotFound(_)) => {
                    for (k, _) in held {
                        self.watches.remove(k.clone()).await?;
                        self.forget_pace(&k);
                    }
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            let latest = room.watermark();
            let list = crate::authz::held_list(&self.revocations, room_id).await?;
            let mut due = Vec::new();
            for (k, mut w) in held {
                let lapsed = w.expires_at <= now;
                let withdrawn = list
                    .as_ref()
                    .is_some_and(|l| l.withdraws(room.visibility, &w.presented, now));
                // Never a live watch on a room whose signal delay is not `none` (Host item
                // 6), however it came to be there.
                let live_not_permitted = w.live && room.signal_delay != SignalDelay::None;
                if lapsed || withdrawn || live_not_permitted {
                    self.watches.remove(k.clone()).await?;
                    self.forget_pace(&k);
                } else if latest > w.since_version {
                    if w.live {
                        match self.pace(&k) {
                            Paced::Now => {
                                // Item 5: the watermark becomes the version signalled.
                                w.since_version = latest;
                                self.watches.insert(k, &w).await?;
                                due.push((w, Some(latest)));
                            }
                            Paced::Later(wait) => {
                                tokio::spawn(self.clone().room_moved_later(
                                    room_id.to_string(),
                                    k,
                                    wait,
                                ));
                            }
                            Paced::Pending => {}
                        }
                    } else {
                        // Disarmed before it is sent: one signal per arming.
                        self.watches.remove(k).await?;
                        due.push((w, None));
                    }
                }
            }
            // The room's own setting, read with the watches it fires — never anything the
            // watch request said (`rooms/changed/0.1` Producer item 4).
            (due, room.signal_delay)
        };
        if due.is_empty() {
            return Ok(());
        }
        let Some(signals) = self.signals() else {
            return Ok(());
        };
        let rooms = self.rooms.clone();
        // `randomised`: the wait of Producer item 4. `none`: no wait of this host's own
        // (`rooms/signal-delay/set/0.1` item 3) — and a live watch is held only there.
        let wait = match delay {
            SignalDelay::None => None,
            _ => Some(*self.delay_ms.read().unwrap_or_else(|p| p.into_inner())),
        };
        for (w, version) in due {
            let signals = signals.clone();
            let rooms = rooms.clone();
            tokio::spawn(async move {
                if let Some((from, to)) = wait {
                    tokio::time::sleep(signal_delay(from, to)).await;
                }
                // The room's latest version when the signal is sent (`rooms/changed/0.1`
                // Producer item 2) — for a live watch, the one it moved its watermark to —
                // never anything about what moved it.
                let latest = match version {
                    Some(v) => v,
                    None => match storage::get_room(&rooms, &w.room_id).await {
                        Ok(r) => r.watermark(),
                        Err(_) => return,
                    },
                };
                let payload = match changed_payload(&w.room_id, latest) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(error = %e, "could not build a rooms/changed signal");
                        return;
                    }
                };
                // Accepted locally is all a send says (R1.1); a lost signal is recovered by
                // the next one or the member's next listing, so it is never re-sent.
                if let Err(e) = signals.send_changed(&w.address, payload).await {
                    tracing::debug!(error = %e, "a rooms/changed signal was not accepted for delivery");
                }
            });
        }
        Ok(())
    }
}

/// A `rooms/changed/0.1` payload: the room and its latest version, nothing else.
pub fn changed_payload(room_id: &str, latest_version: u64) -> Result<Value, String> {
    let payload = json!({ "roomId": room_id, "latestVersion": latest_version });
    serde_json::from_value::<changed_spec::Payload>(payload.clone())
        .map_err(|e| format!("not a rooms/changed/0.1 payload: {e}"))?;
    Ok(payload)
}

fn signal_delay(from: u64, to: u64) -> Duration {
    let span = to - from + 1;
    let r = (uuid::Uuid::new_v4().as_u128() % u128::from(span)) as u64;
    Duration::from_millis(from + r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{ChainVerifier, VerifiedChain, authorize};
    use std::sync::Mutex;

    const ROOM: &str = "did:key:zWatchedRoom";
    const PRESENTER: &str = "did:key:zMember";
    const ADDRESS: &str = "did:peer:2.address";

    /// Vouches for `read`, with credentials lapsing at `until`.
    struct Reads(Option<DateTime<Utc>>);

    #[async_trait::async_trait]
    impl ChainVerifier for Reads {
        async fn verify(
            &self,
            _room: &Room,
            _p: &AuthorityPresentation,
            _a: Action,
            presenter: &str,
        ) -> Result<VerifiedChain, AppError> {
            Ok(VerifiedChain {
                subject: presenter.into(),
                actions: vec!["read".into()],
                member: Some(presenter.into()),
                presented: Default::default(),
                valid_until: self.0,
                purposes: Default::default(),
            })
        }
    }

    /// Records every signal; reaches every address but `did:key:zNowhere`.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<(String, Value)>>, Mutex<Vec<std::time::Instant>>);

    #[async_trait::async_trait]
    impl Signals for Recorder {
        async fn reachable(&self, address: &str) -> bool {
            address != "did:key:zNowhere"
        }
        async fn send_changed(&self, address: &str, payload: Value) -> Result<(), String> {
            self.0.lock().unwrap().push((address.into(), payload));
            self.1.lock().unwrap().push(std::time::Instant::now());
            Ok(())
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        rooms: KeyspaceHandle,
        watches: RoomWatches,
        signals: Arc<Recorder>,
    }

    async fn fixture(next_version: u64) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let rooms = store.keyspace(crate::ROOMS_KEYSPACE).unwrap();
        let revocations = store.keyspace(crate::ROOM_REVOCATIONS_KEYSPACE).unwrap();
        let watches = RoomWatches::new(
            store.keyspace(ROOM_WATCHES_KEYSPACE).unwrap(),
            rooms.clone(),
            revocations,
        );
        let signals = Arc::new(Recorder::default());
        watches.set_signals(signals.clone());
        watches.set_signal_delay_ms(10, 50);
        let mut room = room();
        room.next_version = next_version;
        storage::create_room(&rooms, &room).await.unwrap();
        Fixture {
            _dir: dir,
            rooms,
            watches,
            signals,
        }
    }

    fn room() -> Room {
        Room {
            room_id: ROOM.into(),
            owner_did: "did:key:zOwner".into(),
            visibility: Visibility::Attributed,
            retention_policy: crate::RetentionPolicy::Chained,
            anchor_cadence: Default::default(),
            epoch: 1,
            next_version: 1,
            retention_days: 90,
            epoch_expires_at: None,
            created_at: 0,
            updated_at: 0,
            mirror_of: None,
            record_retention: None,
            last_prune: None,
            signal_delay: Default::default(),
            epoch_floor: None,
            frozen_at: None,
        }
    }

    fn request(extra: Value) -> Value {
        let mut p = json!({
            "roomId": ROOM,
            "presentation": { "membership": "vmc", "authority": ["vac"] },
            "address": ADDRESS,
        });
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        p
    }

    async fn arm(f: &Fixture, payload: Value, until: Option<DateTime<Utc>>) -> TaskResult {
        check_payload(&payload)?;
        let room = storage::get_room(&f.rooms, ROOM).await.unwrap();
        let presentation = presentation(&payload, &room)?;
        let authorized = authorize(
            &room,
            &presentation,
            Action::Read,
            PRESENTER,
            1_800_000_000,
            &Reads(until),
            crate::revocation::test_keyspace(),
        )
        .await
        .map_err(Refusal::App)?;
        f.watches
            .watch(&room, authorized, &payload, Utc::now())
            .await
    }

    /// Moves the room on by one version, as a put would.
    async fn put(f: &Fixture) {
        let mut room = storage::get_room(&f.rooms, ROOM).await.unwrap();
        room.next_version += 1;
        f.rooms.remove(storage::room_key(ROOM)).await.unwrap();
        storage::create_room(&f.rooms, &room).await.unwrap();
        f.watches.room_moved(ROOM).await;
    }

    async fn signals_after_delay(f: &Fixture) -> Vec<(String, Value)> {
        tokio::time::sleep(Duration::from_millis(400)).await;
        f.signals.0.lock().unwrap().clone()
    }

    fn code_of(r: &Refusal) -> &str {
        match r {
            Refusal::Declared { code, .. } => code.code,
            _ => "",
        }
    }

    /// One signal per arming, carrying the room and its latest version and nothing else;
    /// a second change before re-arming sends nothing (Host item 4).
    #[tokio::test]
    async fn a_watch_fires_once_and_then_is_gone() {
        let f = fixture(5).await; // latest version 4
        let armed = arm(&f, request(json!({ "sinceVersion": 4 })), None)
            .await
            .unwrap();
        assert_eq!(armed["armed"], true);
        assert!(armed["expiresAt"].is_string());
        assert!(
            signals_after_delay(&f).await.is_empty(),
            "not past the watermark"
        );

        put(&f).await;
        put(&f).await;
        let sent = signals_after_delay(&f).await;
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0].0, ADDRESS);
        assert_eq!(sent[0].1, json!({ "roomId": ROOM, "latestVersion": 6 }));

        put(&f).await;
        assert_eq!(
            signals_after_delay(&f).await.len(),
            1,
            "disarmed after firing"
        );
    }

    /// A room already past the watermark fires at once on arming.
    #[tokio::test]
    async fn a_room_already_past_the_watermark_fires_at_once() {
        let f = fixture(10).await;
        arm(&f, request(json!({ "sinceVersion": 3 })), None)
            .await
            .unwrap();
        let sent = signals_after_delay(&f).await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1["latestVersion"], 9);
    }

    /// Absent `sinceVersion` is the room's latest version when armed.
    #[tokio::test]
    async fn no_watermark_means_the_latest_version() {
        let f = fixture(10).await;
        arm(&f, request(json!({})), None).await.unwrap();
        assert!(signals_after_delay(&f).await.is_empty());
        put(&f).await;
        assert_eq!(signals_after_delay(&f).await.len(), 1);
    }

    /// A cancel ends the watch, and cancelling one the host does not hold succeeds.
    #[tokio::test]
    async fn a_cancelled_watch_never_fires() {
        let f = fixture(2).await;
        arm(&f, request(json!({ "sinceVersion": 1 })), None)
            .await
            .unwrap();
        let cancelled = arm(&f, request(json!({ "cancel": true })), None)
            .await
            .unwrap();
        assert_eq!(
            cancelled,
            json!({ "roomId": ROOM, "address": ADDRESS, "armed": false })
        );
        put(&f).await;
        assert!(signals_after_delay(&f).await.is_empty());
        let again = arm(&f, request(json!({ "cancel": true })), None)
            .await
            .unwrap();
        assert_eq!(again["armed"], false);
    }

    /// The lease is bounded by the first credential's lapse, and a repeat of the same
    /// request answers as the first did.
    #[tokio::test]
    async fn the_lease_never_outlives_the_presentation() {
        let f = fixture(2).await;
        let until = Utc::now() + chrono::Duration::hours(1);
        let armed = arm(
            &f,
            request(json!({ "sinceVersion": 1, "leaseSeconds": 2592000 })),
            Some(until),
        )
        .await
        .unwrap();
        let expires: DateTime<Utc> = armed["expiresAt"].as_str().unwrap().parse().unwrap();
        assert!(expires <= until, "{expires} > {until}");

        let f = fixture(2).await;
        let first = arm(
            &f,
            request(json!({ "sinceVersion": 1, "leaseSeconds": 600 })),
            None,
        )
        .await
        .unwrap();
        let second = arm(
            &f,
            request(json!({ "sinceVersion": 1, "leaseSeconds": 600 })),
            None,
        )
        .await
        .unwrap();
        assert_eq!(first, second, "a repeated request sets the same state");
    }

    /// An address that resolves to no transport the host speaks arms nothing, and a host
    /// with no transport at all reaches no address.
    #[tokio::test]
    async fn an_unreachable_address_is_refused() {
        let f = fixture(2).await;
        let err = arm(&f, request(json!({ "address": "did:key:zNowhere" })), None)
            .await
            .unwrap_err();
        assert!(code_of(&err).ends_with("addressUnreachable"), "{err:?}");

        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let bare = RoomWatches::new(
            store.keyspace(ROOM_WATCHES_KEYSPACE).unwrap(),
            f.rooms.clone(),
            store.keyspace(crate::ROOM_REVOCATIONS_KEYSPACE).unwrap(),
        );
        let payload = request(json!({}));
        let room = storage::get_room(&f.rooms, ROOM).await.unwrap();
        let authorized = authorize(
            &room,
            &presentation(&payload, &room).unwrap(),
            Action::Read,
            PRESENTER,
            1_800_000_000,
            &Reads(None),
            crate::revocation::test_keyspace(),
        )
        .await
        .unwrap();
        let err = bare
            .watch(&room, authorized, &payload, Utc::now())
            .await
            .unwrap_err();
        assert!(code_of(&err).ends_with("addressUnreachable"), "{err:?}");
    }

    /// The task's own codes: a chain over eight links, and a private room's missing
    /// binding; and the schema's bounds.
    #[test]
    fn the_declared_presentation_checks() {
        let mut deep = request(json!({}));
        deep["presentation"]["authority"] =
            json!((0..9).map(|i| format!("vac-{i}")).collect::<Vec<_>>());
        let err = presentation(&deep, &room()).unwrap_err();
        assert!(code_of(&err).ends_with("chainTooDeep"), "{err:?}");

        let mut private = room();
        private.visibility = Visibility::Private;
        let err = presentation(&request(json!({})), &private).unwrap_err();
        assert!(code_of(&err).ends_with("subjectBindingMissing"), "{err:?}");

        assert!(
            check_payload(&request(json!({ "cancel": false }))).is_err(),
            "only `true` cancels"
        );
        assert!(check_payload(&request(json!({ "leaseSeconds": 59 }))).is_err());
        assert!(check_payload(&request(json!({ "address": "mailto:x" }))).is_err());
    }

    /// Sets the room's signal delay, as `rooms/signal-delay/set` would.
    async fn set_delay(f: &Fixture, delay: crate::signal_delay::SignalDelay) {
        storage::set_signal_delay(&f.rooms, ROOM, delay, 1)
            .await
            .unwrap();
    }

    /// A room whose signal delay is `none` signals with no wait of the host's own, however
    /// long the host's randomised wait is (`rooms/signal-delay/set/0.1` item 3).
    #[tokio::test]
    async fn a_room_with_no_signal_delay_signals_at_once() {
        let f = fixture(2).await;
        f.watches.set_signal_delay_ms(60_000, 60_000);
        set_delay(&f, crate::signal_delay::SignalDelay::None).await;
        arm(&f, request(json!({ "sinceVersion": 1 })), None)
            .await
            .unwrap();
        put(&f).await;
        let sent = signals_after_delay(&f).await;
        assert_eq!(sent.len(), 1, "sent without the minute's wait: {sent:?}");
        assert_eq!(sent[0].1["latestVersion"], 2);
    }

    /// A `randomised` room — and one that never set a delay — still waits; a room turned
    /// back to `randomised` waits again.
    #[tokio::test]
    async fn a_randomised_room_waits() {
        let f = fixture(2).await;
        f.watches.set_signal_delay_ms(60_000, 60_000);
        arm(&f, request(json!({ "sinceVersion": 1 })), None)
            .await
            .unwrap();
        put(&f).await;
        assert!(
            signals_after_delay(&f).await.is_empty(),
            "the default is the randomised wait"
        );

        let f = fixture(2).await;
        f.watches.set_signal_delay_ms(60_000, 60_000);
        set_delay(&f, crate::signal_delay::SignalDelay::None).await;
        set_delay(&f, crate::signal_delay::SignalDelay::Randomised).await;
        arm(&f, request(json!({ "sinceVersion": 1 })), None)
            .await
            .unwrap();
        put(&f).await;
        assert!(signals_after_delay(&f).await.is_empty(), "turned back on");
    }

    /// The signal carries the room and its latest version, nothing else.
    #[test]
    fn the_signal_is_the_room_and_its_version() {
        assert_eq!(
            changed_payload(ROOM, 7).unwrap(),
            json!({ "roomId": ROOM, "latestVersion": 7 })
        );
        assert!(
            changed_payload(ROOM, 0).is_err(),
            "latestVersion is at least 1"
        );
    }

    // ---- rooms/watch/0.2: live watches (trust-tasks-tf #1087) ----

    async fn arm_v2(f: &Fixture, payload: Value) -> TaskResult {
        check_payload_v2(&payload)?;
        let room = storage::get_room(&f.rooms, ROOM).await.unwrap();
        let presentation = presentation(&payload, &room)?;
        let authorized = authorize(
            &room,
            &presentation,
            Action::Read,
            PRESENTER,
            1_800_000_000,
            &Reads(None),
            crate::revocation::test_keyspace(),
        )
        .await
        .map_err(Refusal::App)?;
        f.watches
            .watch_v2(&room, authorized, &payload, Utc::now())
            .await
    }

    /// A room whose signal delay is `none`, with a short live spacing for the test.
    async fn live_fixture(next_version: u64, spacing_ms: u64) -> Fixture {
        let f = fixture(next_version).await;
        set_delay(&f, crate::signal_delay::SignalDelay::None).await;
        f.watches
            .set_live_spacing(Duration::from_millis(spacing_ms));
        f
    }

    fn sent(f: &Fixture) -> Vec<(String, Value)> {
        f.signals.0.lock().unwrap().clone()
    }

    /// Host item 6: a live watch on a `randomised` room is refused `liveNotPermitted`, and
    /// the watch the request named is left as it was.
    #[tokio::test]
    async fn vti_watch_v2_live_is_refused_on_a_randomised_room() {
        let f = fixture(2).await;
        arm_v2(&f, request(json!({ "sinceVersion": 1 })))
            .await
            .unwrap();
        let err = arm_v2(&f, request(json!({ "sinceVersion": 1, "live": true })))
            .await
            .unwrap_err();
        assert!(code_of(&err).ends_with("liveNotPermitted"), "{err:?}");
        f.watches.set_signal_delay_ms(10, 20);
        put(&f).await;
        put(&f).await;
        let sent = signals_after_delay(&f).await;
        assert_eq!(
            sent.len(),
            1,
            "the one-shot watch stood, and fired once: {sent:?}"
        );
    }

    /// Host item 5: a live watch signals each change, carrying the latest version, and does
    /// not disarm; a burst within the spacing is one signal with the latest version — never
    /// a queue per change — and signals are at least the spacing apart.
    #[tokio::test]
    async fn vti_watch_v2_live_signals_each_change_coalesced() {
        let f = live_fixture(5, 300).await; // latest 4
        let armed = arm_v2(&f, request(json!({ "sinceVersion": 4, "live": true })))
            .await
            .unwrap();
        assert_eq!(armed["live"], true);

        put(&f).await; // 5: signalled at once
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(sent(&f).len(), 1);
        assert_eq!(sent(&f)[0].1["latestVersion"], 5);

        // A burst inside the spacing: one more signal, with the last version.
        put(&f).await;
        put(&f).await;
        put(&f).await; // 8
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(sent(&f).len(), 1, "held for the spacing");
        tokio::time::sleep(Duration::from_millis(400)).await;
        let all = sent(&f);
        assert_eq!(all.len(), 2, "coalesced into one: {all:?}");
        assert_eq!(all[1].1, json!({ "roomId": ROOM, "latestVersion": 8 }));
        let times = f.signals.1.lock().unwrap().clone();
        assert!(
            times[1].duration_since(times[0]) >= Duration::from_millis(290),
            "at least the spacing apart"
        );

        // Still armed, and nothing more without a change.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(sent(&f).len(), 2);
        put(&f).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(sent(&f).len(), 3, "a live watch does not disarm");
    }

    /// The spacing a host uses is never under a second (Host item 5).
    #[test]
    fn vti_watch_v2_live_spacing_is_at_least_a_second() {
        assert!(LIVE_SIGNAL_SPACING >= Duration::from_secs(1));
    }

    /// Host item 7: a live watch's lease is at most 120 seconds, whatever was asked, and the
    /// response says `live: true`.
    #[tokio::test]
    async fn vti_watch_v2_live_lease_is_capped_at_120_seconds() {
        let f = live_fixture(2, 1000).await;
        let before = Utc::now();
        let armed = arm_v2(
            &f,
            request(json!({ "sinceVersion": 1, "leaseSeconds": 2592000, "live": true })),
        )
        .await
        .unwrap();
        assert_eq!(armed["live"], true);
        let expires: DateTime<Utc> = armed["expiresAt"].as_str().unwrap().parse().unwrap();
        assert!(
            expires <= before + chrono::Duration::seconds(121),
            "{expires}"
        );

        // A one-shot 0.2 watch keeps the long lease, and answers without `live`.
        let one_shot = arm_v2(
            &f,
            request(json!({ "address": "did:peer:2.other", "leaseSeconds": 2592000 })),
        )
        .await
        .unwrap();
        assert!(one_shot.get("live").is_none());
        let expires: DateTime<Utc> = one_shot["expiresAt"].as_str().unwrap().parse().unwrap();
        assert!(expires > before + chrono::Duration::days(29));
    }

    /// Host item 3: a renewal without `sinceVersion` keeps the watermark (the version last
    /// signalled) and extends the lease; one with it replaces the watermark and signals at
    /// once if the room is above it.
    #[tokio::test]
    async fn vti_watch_v2_renewal_keeps_or_replaces_the_watermark() {
        let f = live_fixture(5, 100).await; // latest 4
        arm_v2(&f, request(json!({ "sinceVersion": 4, "live": true })))
            .await
            .unwrap();
        put(&f).await; // 5, signalled
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(sent(&f).len(), 1);

        let renewed = arm_v2(&f, request(json!({ "live": true }))).await.unwrap();
        assert_eq!(renewed["live"], true);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            sent(&f).len(),
            1,
            "the watermark is the version last signalled"
        );

        arm_v2(&f, request(json!({ "sinceVersion": 2, "live": true })))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let all = sent(&f);
        assert_eq!(
            all.len(),
            2,
            "a replaced watermark below the room signals at once"
        );
        assert_eq!(all[1].1["latestVersion"], 5);
    }

    /// Host item 6: when the room's signal delay changes to `randomised`, every live watch
    /// ends at once and nothing is sent to it; a one-shot watch on the room stays.
    #[tokio::test]
    async fn vti_watch_v2_randomised_ends_live_watches_silently() {
        let f = live_fixture(5, 50).await;
        arm_v2(&f, request(json!({ "sinceVersion": 4, "live": true })))
            .await
            .unwrap();
        arm_v2(
            &f,
            request(json!({ "address": "did:peer:2.oneshot", "sinceVersion": 4 })),
        )
        .await
        .unwrap();
        set_delay(&f, crate::signal_delay::SignalDelay::Randomised).await;
        assert_eq!(f.watches.end_live_watches(ROOM).await, 1);
        f.watches.set_signal_delay_ms(10, 20);
        put(&f).await;
        let all = signals_after_delay(&f).await;
        assert_eq!(all.len(), 1, "{all:?}");
        assert_eq!(
            all[0].0, "did:peer:2.oneshot",
            "only the one-shot watch fired"
        );
        let again = arm_v2(&f, request(json!({ "live": true })))
            .await
            .unwrap_err();
        assert!(code_of(&again).ends_with("liveNotPermitted"));

        // A live watch found on a randomised room however it got there is dropped, unsent.
        let f = live_fixture(5, 50).await;
        arm_v2(&f, request(json!({ "sinceVersion": 4, "live": true })))
            .await
            .unwrap();
        set_delay(&f, crate::signal_delay::SignalDelay::Randomised).await;
        f.watches.set_signal_delay_ms(10, 20);
        put(&f).await;
        assert!(signals_after_delay(&f).await.is_empty());
        assert_eq!(f.watches.end_live_watches(ROOM).await, 0, "already gone");
    }

    /// Host item 3: a request without `live` on a live watch makes it one-shot again.
    #[tokio::test]
    async fn vti_watch_v2_a_request_without_live_makes_the_watch_one_shot() {
        let f = live_fixture(5, 50).await;
        arm_v2(&f, request(json!({ "sinceVersion": 4, "live": true })))
            .await
            .unwrap();
        let one_shot = arm(&f, request(json!({ "sinceVersion": 4 })), None)
            .await
            .unwrap();
        assert!(one_shot.get("live").is_none());
        put(&f).await;
        put(&f).await;
        let all = signals_after_delay(&f).await;
        assert_eq!(all.len(), 1, "one signal, then disarmed: {all:?}");
    }

    /// A cancel ends a live watch: a timer set before it sends nothing.
    #[tokio::test]
    async fn vti_watch_v2_a_cancelled_live_watch_sends_nothing_more() {
        let f = live_fixture(5, 300).await;
        arm_v2(&f, request(json!({ "sinceVersion": 4, "live": true })))
            .await
            .unwrap();
        put(&f).await;
        put(&f).await; // within the spacing: a timer
        let cancelled = arm_v2(&f, request(json!({ "cancel": true, "live": true })))
            .await
            .unwrap();
        assert_eq!(cancelled["armed"], false);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(sent(&f).len(), 1);
    }

    /// The 0.2 schema accepts only `live: true`.
    #[test]
    fn vti_watch_v2_only_true_is_live() {
        assert!(check_payload_v2(&request(json!({ "live": false }))).is_err());
        assert!(check_payload_v2(&request(json!({ "live": true }))).is_ok());
        assert!(
            check_payload(&request(json!({ "live": true }))).is_err(),
            "0.1 has no live"
        );
    }
}
