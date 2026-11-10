//! `rooms/watch/0.1` and `rooms/changed/0.1`, host side and host-neutral: a member asks a
//! room's host for **one** content-free signal, sent to an address it names, the first time
//! the room moves past the version it has read to (trust-tasks-tf #1036).
//!
//! Both hosts serve it — `room-host` and the VTC — and each keeps its own transport and
//! chain verification. A host authorizes the request exactly as a listing (`read`, the
//! chain rules of `rooms/records/put`), then calls [`RoomWatches::watch`]; after any task
//! that may have moved a room it calls [`RoomWatches::room_moved`]; and it lends a
//! [`Signals`] that resolves an address and sends one one-way Trust Task to it over the
//! host's own outbound transport (TSP before DIDComm, by what the address's DID document
//! advertises).
//!
//! # What a watch is, and is not
//!
//! Host state, never room state (Host item 7): a watch grants nothing, is consulted to
//! authorize nothing, is shown to nobody, and does not move with the room. One per room and
//! address (item 3). It is forgotten when it fires, is cancelled, or lapses at `expiresAt` —
//! never later than the first credential of the presentation that armed it stops being
//! valid (item 5) — and never fires for a presentation the room's held revocation list
//! withdraws.
//!
//! # One signal per arming
//!
//! A watch fires once: the first time the room's latest version is above its watermark —
//! at once if it already is (item 4) — and is removed **before** its signal is sent, under
//! one lock, so two writes landing together send one signal, not two. The signal carries
//! the room and its latest version when sent, and nothing about what moved it (item 6), and
//! goes after a short randomised delay so its time does not mark one write
//! (`rooms/changed/0.1` Producer item 4). Delivery is the delivery layer's: a signal is
//! never queued per change, re-sent or retried here (Producer item 5) — a lost one costs the
//! member nothing its next listing does not recover.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use vti_specs_rooms::rooms::changed::v0_1 as changed_spec;
use vti_specs_rooms::rooms::watch::v0_1 as watch_spec;

use crate::authz::{Action, AuthorizedAction, MAX_CHAIN_DEPTH};
use crate::blob_tasks::{Refusal, TaskResult, checked, declared, parse};
use crate::revocation::Presented;
use crate::wire::AuthorityPresentation;
use crate::{Room, Visibility, storage};

/// `rooms/watch/0.1`.
pub const WATCH_TYPE: &str = crate::wire::ROOMS_WATCH_TYPE;
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
/// The most watches a host holds for one room (`rooms/watch:limitReached`).
pub const MAX_WATCHES_PER_ROOM: usize = 1024;
/// The most watches a host holds for one presenter in one room, where the tier discloses
/// the presenter's member (`rooms/watch:limitReached`).
pub const MAX_WATCHES_PER_PRESENTER: usize = 16;
/// The randomised interval a signal waits after the change that fires it, in milliseconds
/// (`rooms/changed/0.1` Producer item 4: "a few seconds").
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
    /// The watermark: the watch fires once the room's latest version is above it.
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
    /// room's list withdraws after it was armed never fires (Host item 5).
    presented: Presented,
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
pub fn check_payload(payload: &Value) -> Result<(), Refusal> {
    <watch_spec::Payload as trust_tasks_rs::validate::ValidatedPayload>::validate_value(payload)
        .map_err(|e| Refusal::Malformed(e.messages().join("; ")))?;
    parse::<watch_spec::Payload>(payload).map(|_| ())
}

/// Read a checked ([`check_payload`]) `rooms/watch/0.1` request's presentation, after the
/// checks its own error codes declare: a chain of at most [`MAX_CHAIN_DEPTH`] links
/// (`rooms/watch:chainTooDeep`) and, on a `private` room, a subject binding
/// (`rooms/watch:subjectBindingMissing`). The host then authorizes it for [`Action::Read`].
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

/// The watches a host holds, and the one lock arming, cancelling and firing take, so a watch
/// fires once and a cancel is never overtaken by a signal it should have stopped.
pub struct RoomWatches {
    watches: KeyspaceHandle,
    rooms: KeyspaceHandle,
    revocations: KeyspaceHandle,
    signals: std::sync::RwLock<Option<Arc<dyn Signals>>>,
    lock: tokio::sync::Mutex<()>,
    /// The randomised delay before a signal, in milliseconds: [`SIGNAL_DELAY_MS`], or a
    /// test's own.
    delay_ms: std::sync::RwLock<(u64, u64)>,
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
            watches,
            rooms,
            revocations,
            signals: std::sync::RwLock::new(None),
            lock: tokio::sync::Mutex::new(()),
            delay_ms: std::sync::RwLock::new((*SIGNAL_DELAY_MS.start(), *SIGNAL_DELAY_MS.end())),
        }
    }

    /// Shorten the randomised delay before a signal, for a host's own tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_signal_delay_ms(&self, from: u64, to: u64) {
        *self.delay_ms.write().unwrap_or_else(|p| p.into_inner()) = (from, to.max(from));
    }

    /// Lend the host's outbound transport, once it has one.
    pub fn set_signals(&self, signals: Arc<dyn Signals>) {
        *self.signals.write().unwrap_or_else(|p| p.into_inner()) = Some(signals);
    }

    fn signals(&self) -> Option<Arc<dyn Signals>> {
        self.signals
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
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

    /// `rooms/watch/0.1`, once [`presentation`] passed and the host authorized it for
    /// [`Action::Read`] against `room`. Arms, re-arms or cancels the watch on `room` and the
    /// payload's `address`, and — once the authorization is released — fires it at once if
    /// the room is already past its watermark.
    pub async fn watch(
        &self,
        room: &Room,
        authorized: AuthorizedAction,
        payload: &Value,
        now: DateTime<Utc>,
    ) -> TaskResult {
        use watch_spec::error_codes as codes;
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

        if payload.get("cancel").and_then(Value::as_bool) == Some(true) {
            let _held = self.lock.lock().await;
            self.watches.remove(key).await.map_err(Refusal::App)?;
            return checked::<watch_spec::Response>(json!({
                "roomId": room.room_id,
                "address": address,
                "armed": false,
            }));
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

        let since = payload
            .get("sinceVersion")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| room.watermark());
        let lease_asked = payload.get("leaseSeconds").and_then(Value::as_u64);
        let lease = lease_asked
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_LEASE)
            .min(MAX_LEASE);
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
            match current {
                // A repeat of the request that armed it: the same answer (*A repeated request*).
                Some(w) if w.since_version == since && w.lease_asked == lease_asked => w.clone(),
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
                    };
                    self.watches.insert(key, &w).await.map_err(Refusal::App)?;
                    w
                }
            }
        };
        let response = checked::<watch_spec::Response>(json!({
            "roomId": room.room_id,
            "address": address,
            "armed": true,
            "expiresAt": rfc3339(armed.expires_at),
        }))?;
        // The room's gate is released before the room is read again and anything sent.
        drop(authorized);
        self.room_moved(&room.room_id).await;
        Ok(response)
    }

    /// The room may have moved: fire every watch on `room_id` whose watermark the room's
    /// latest version is above — removing each before its signal is sent — and forget
    /// those that lapsed. Never fails the caller: a host calls this after a task has
    /// committed, and nothing here may undo or fail that task.
    pub async fn room_moved(&self, room_id: &str) {
        if let Err(e) = self.fire(room_id).await {
            tracing::warn!(room = %room_id, error = %e, "could not check the room's watches");
        }
    }

    async fn fire(&self, room_id: &str) -> Result<(), AppError> {
        let now = Utc::now();
        let due: Vec<Watch> = {
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
                        self.watches.remove(k).await?;
                    }
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            let latest = room.watermark();
            let list = crate::authz::held_list(&self.revocations, room_id).await?;
            let mut due = Vec::new();
            for (k, w) in held {
                let lapsed = w.expires_at <= now;
                let withdrawn = list
                    .as_ref()
                    .is_some_and(|l| l.withdraws(room.visibility, &w.presented, now));
                if lapsed || withdrawn {
                    self.watches.remove(k).await?;
                } else if latest > w.since_version {
                    // Disarmed before it is sent: one signal per arming.
                    self.watches.remove(k).await?;
                    due.push(w);
                }
            }
            due
        };
        if due.is_empty() {
            return Ok(());
        }
        let Some(signals) = self.signals() else {
            return Ok(());
        };
        let rooms = self.rooms.clone();
        let (from, to) = *self.delay_ms.read().unwrap_or_else(|p| p.into_inner());
        for w in due {
            let signals = signals.clone();
            let rooms = rooms.clone();
            tokio::spawn(async move {
                tokio::time::sleep(signal_delay(from, to)).await;
                // The room's latest version when the signal is sent (`rooms/changed/0.1`
                // Producer item 2), never anything about what moved it.
                let latest = match storage::get_room(&rooms, &w.room_id).await {
                    Ok(r) => r.watermark(),
                    Err(_) => return,
                };
                let payload = match changed_payload(&w.room_id, latest) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(error = %e, "could not build a rooms/changed signal");
                        return;
                    }
                };
                // Accepted locally is all a send says (R1.1); a lost signal is recovered by
                // the member's next listing, so it is never re-sent.
                if let Err(e) = signals.send_changed(&w.address, payload).await {
                    tracing::debug!(error = %e, "a rooms/changed signal was not accepted for delivery");
                }
            });
        }
        Ok(())
    }

    /// Forget every watch that lapsed. A host runs this now and then; a room's own watches
    /// are also swept whenever the room moves.
    pub async fn sweep(&self, now: DateTime<Utc>) -> Result<usize, AppError> {
        let _held = self.lock.lock().await;
        let mut removed = 0;
        for (k, v) in self.watches.prefix_iter_raw(Vec::new()).await? {
            let lapsed = serde_json::from_slice::<Watch>(&v).map_or(true, |w| w.expires_at <= now);
            if lapsed {
                self.watches.remove(k).await?;
                removed += 1;
            }
        }
        Ok(removed)
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
    struct Recorder(Mutex<Vec<(String, Value)>>);

    #[async_trait::async_trait]
    impl Signals for Recorder {
        async fn reachable(&self, address: &str) -> bool {
            address != "did:key:zNowhere"
        }
        async fn send_changed(&self, address: &str, payload: Value) -> Result<(), String> {
            self.0.lock().unwrap().push((address.into(), payload));
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
}
