//! The administrator console's **live channel** — a hint-only event stream
//! (`vtc/admin/events/subscribe`, `vtc/admin/events/event`), carried over
//! HTTPS as a streamed response (HTTPS binding 0.3 §2.1).
//!
//! ## Versions
//!
//! Served at 0.1, 0.2 and 0.3. The topic set is closed per version (subscribe
//! 0.2 *What 0.2 adds*, 0.3 *What 0.3 adds*): 0.2 adds `rooms` and 0.3 adds
//! `directory` and `groups`, so a console asks for each only at the version
//! that has it, and a stream answers — its `#response` and every hint after it
//! — at the version it was opened with ([`Version`]). An older console is
//! unchanged.
//!
//! ## What travels on it
//!
//! Hints, never records. A hint names one [`Topic`] that changed, when, and —
//! for the three count topics — the recipient's badge count. It carries no
//! record, no record identifier and no DID (event 0.1 producer rule 3); the
//! console reacts by re-reading that topic through the signed read it already
//! uses, and that read authorizes itself. So the stream needs no authorization
//! model of its own beyond "may this caller read this topic now", which is
//! asked when the stream opens and again before every hint (subscribe 0.1
//! consumer rules 4 and 7).
//!
//! ## The pieces
//!
//! - **The bus** ([`notify`]). One process-wide `tokio::sync::broadcast` fed by
//!   the storage seams every write already passes through: an action record
//!   saved or deleted (`admin_actions`), a join request stored or deleted, a
//!   member row stored, edited or deleted, an ACL entry stored or deleted, a
//!   configuration override or the community profile written. A signal carries
//!   a topic and a time — nothing from the row. The bus is process-wide rather
//!   than per [`AppState`] because those seams take a keyspace handle, not the
//!   state; a VTC is one process, and a stream only ever *reads* through its
//!   own state, so a signal from elsewhere costs at most a re-read that finds
//!   nothing changed (see fingerprints below).
//!   The rooms seams are a configuration's write (`rooms::storage_configs`)
//!   and, inside `vti_rooms`, a room registered or renewed and a holdings or
//!   limit write ([`notify_rooms`], through `vti_rooms::observe`). The
//!   `directory` seams are the directory's own writes — a field, a card or a
//!   value, an external card, a picture, a note — and the `groups` seams a
//!   group, a membership or a join request stored or removed, and every ACL
//!   write (a manager's appointment is a resource grant).
//! - **Fingerprints.** "A change the caller's read would not show them
//!   produces no hint" (subscribe 0.1 §Authorization). For `actions`,
//!   `acknowledgements` and `joinRequests` each stream keeps a digest of what
//!   the recipient's read would show and sends a hint only when it moves.
//!   `rooms` is fingerprinted too, over exactly what event 0.2 producer rule 4
//!   names: which rooms are hosted, each room's lifecycle state, and the 80 /
//!   95 / 100 percent band of each room's usage against its limits and of each
//!   storage config's held bytes against its capacity, beside each config as
//!   stored. Holdings move on every upload; only a band crossing hints.
//!   `groups` is fingerprinted per recipient over the groups they may manage
//!   — each group, its members, its requests and its managers — so a manager
//!   qualified to one group is never hinted about another's change (subscribe
//!   0.3 §Authorization). `directory` is not fingerprinted: its holders are
//!   hinted about every change, coalesced to one hint in
//!   [`DIRECTORY_HINT_INTERVAL`] so one member's edits do not read as a rhythm
//!   (subscribe 0.3 §Correlation).
//!   Lifecycle is computed from the clock, never written, so a stream holding
//!   `rooms` also wakes at the next moment a room's state would change
//!   (`vti_rooms::Room::next_lifecycle_change`).
//! - **Resumption.** A bounded, in-memory history of which topic changed at
//!   which position ([`HISTORY_SECS`], [`HISTORY_MAX`]). A resume token is an
//!   opaque, MAC'd, per-caller-masked encoding of a position, under a key that
//!   lives only in this process. A token from another caller, another process
//!   (a restart), or older than the history is simply unknown: the stream
//!   opens with `resumed: false` and the console re-reads everything — never
//!   an error, so a token cannot be probed (consumer rule 5).
//! - **Caps** ([`MAX_STREAMS_PER_SUBJECT`], [`MAX_STREAMS_TOTAL`]). Counted per
//!   *subject* — the administrator a console key acts for — so several tabs or
//!   devices fit and a runaway client does not hold the process's sockets.
//!
//! ## Ending a stream
//!
//! The stream ends — the response simply finishes, carrying no reason and
//! never a `trust-task-error` (binding 0.3 §2.1.4) — when the client goes, the
//! service shuts down, the credential that opened it expires (the signer's ACL
//! entry, the console key's delegation, or the subscribe document's own
//! `expiresAt`), [`STREAM_LIFETIME`] passes, a write stalls for twice the
//! heartbeat, or the caller's readable topics shrink below the stream's
//! effective topics (consumer rule 7). Every one of those costs the console a
//! freshly signed subscribe, which re-checks everything.
//!
//! ## Locks
//!
//! The only locks here are `std::sync::Mutex`es over in-memory maps, taken and
//! released inside non-async blocks — never across an `.await` (R1.3). The
//! live/offline status is the console's to derive from bytes arriving (R6.2);
//! nothing here latches one.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, mpsc};
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::vtc::admin::events::{
    event::v0_1 as event, event::v0_2 as event_v0_2, event::v0_3 as event_v0_3,
    subscribe::v0_1 as subscribe, subscribe::v0_2 as subscribe_v0_2,
    subscribe::v0_3 as subscribe_v0_3,
};
use vti_common::error::AppError;

use crate::server::AppState;

/// The declared error codes of `vtc/admin/events/subscribe`, read off the
/// generated specification — what the tests that witness each one compare
/// against. 0.1, 0.2 and 0.3 declare the same three, under the same codes.
pub mod codes {
    use trust_tasks_rs::specs::vtc::admin::events::subscribe::v0_1::error_codes as e;

    pub const NOT_ADMINISTRATOR: &str = e::NOT_ADMINISTRATOR.code;
    pub const STREAM_UNAVAILABLE: &str = e::STREAM_UNAVAILABLE.code;
    pub const TOO_MANY_STREAMS: &str = e::TOO_MANY_STREAMS.code;
}

// ─── topics ──────────────────────────────────────────────────────────────

/// The version a stream was opened at: its `#response` and its hints are
/// documents of that version, and its topics are that version's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Version {
    V0_1,
    V0_2,
    V0_3,
}

/// One kind of change a console can be told about — the shared `Topic` of
/// `vtc/admin/events/_shared/0.3` (0.1's, plus `rooms`, `directory` and
/// `groups`). The generated modules
/// each carry their own copy of that enum; this one is the service's, with a
/// conversion to each through the wire name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Topic {
    Actions,
    Acknowledgements,
    JoinRequests,
    Members,
    SingleAdminMode,
    Config,
    /// Added in 0.2: the rooms this community hosts and where their files are
    /// kept.
    Rooms,
    /// Added in 0.3: the member directory as administrators see it.
    Directory,
    /// Added in 0.3: the community's groups, their members, bindings and join
    /// requests.
    Groups,
}

impl Topic {
    pub const ALL: [Topic; 9] = [
        Topic::Actions,
        Topic::Acknowledgements,
        Topic::JoinRequests,
        Topic::Members,
        Topic::SingleAdminMode,
        Topic::Config,
        Topic::Rooms,
        Topic::Directory,
        Topic::Groups,
    ];

    /// The name the shared schema gives it.
    pub fn wire(self) -> &'static str {
        match self {
            Topic::Actions => "actions",
            Topic::Acknowledgements => "acknowledgements",
            Topic::JoinRequests => "joinRequests",
            Topic::Members => "members",
            Topic::SingleAdminMode => "singleAdminMode",
            Topic::Config => "config",
            Topic::Rooms => "rooms",
            Topic::Directory => "directory",
            Topic::Groups => "groups",
        }
    }

    pub(crate) fn from_wire(name: &str) -> Option<Topic> {
        Topic::ALL.into_iter().find(|t| t.wire() == name)
    }

    /// Whether `version`'s closed topic set holds it.
    pub(crate) fn in_version(self, version: Version) -> bool {
        version >= self.since()
    }

    /// The version that added it.
    fn since(self) -> Version {
        match self {
            Topic::Rooms => Version::V0_2,
            Topic::Directory | Topic::Groups => Version::V0_3,
            _ => Version::V0_1,
        }
    }

    /// The topics a stream keeps a digest of, hinting only when it moves: the
    /// count topics, `rooms` (event 0.2 producer rule 4), and `groups`, whose
    /// digest is of the groups the recipient may manage.
    fn is_fingerprinted(self) -> bool {
        self.is_count() || matches!(self, Topic::Rooms | Topic::Groups)
    }

    /// The least time between two hints of this topic (consumer rule 6's one
    /// per second, and longer for `directory`).
    fn min_hint_interval(self) -> Duration {
        match self {
            Topic::Directory => DIRECTORY_HINT_INTERVAL,
            _ => MIN_HINT_INTERVAL,
        }
    }

    /// The count topics: their hints carry the recipient's badge count, and
    /// no other topic's may (event 0.1 producer rule 4).
    pub fn is_count(self) -> bool {
        matches!(
            self,
            Topic::Actions | Topic::Acknowledgements | Topic::JoinRequests
        )
    }

    pub(crate) fn from_subscribe(t: &subscribe::Topic) -> Option<Topic> {
        // A topic a newer specification adds is one this service cannot say it
        // reads; it is never effective.
        Topic::from_wire(&t.to_string()).filter(|t| t.in_version(Version::V0_1))
    }

    pub(crate) fn from_subscribe_v0_2(t: &subscribe_v0_2::Topic) -> Option<Topic> {
        Topic::from_wire(&t.to_string()).filter(|t| t.in_version(Version::V0_2))
    }

    pub(crate) fn from_subscribe_v0_3(t: &subscribe_v0_3::Topic) -> Option<Topic> {
        Topic::from_wire(&t.to_string())
    }
}

// ─── the bus ─────────────────────────────────────────────────────────────

/// What a storage seam reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Signal {
    /// The state behind a topic's read changed.
    Changed(Topic),
    /// Somebody's authority may have changed (an ACL write): every stream
    /// re-checks its caller's readable topics before its next byte.
    Authority,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Change {
    pub signal: Signal,
    pub at: DateTime<Utc>,
}

/// How long a change stays in the resumption history. "Minutes, not days"
/// (subscribe 0.1 §Retention).
pub const HISTORY_SECS: i64 = 10 * 60;
/// The most changes the history keeps, whatever their age.
pub const HISTORY_MAX: usize = 4096;
/// The broadcast buffer. A stream that falls this far behind is told every
/// one of its topics changed ([`broadcast::error::RecvError::Lagged`]), which
/// is always safe: a hint only prompts a re-read.
const BUS_CAPACITY: usize = 1024;

struct History {
    /// Position of the newest change (0 = none yet).
    position: u64,
    /// The highest position dropped from `entries` — a `since` at or below it
    /// cannot be resumed from, because what happened after it is partly gone.
    dropped_through: u64,
    entries: VecDeque<(u64, Topic, DateTime<Utc>)>,
}

struct Bus {
    tx: broadcast::Sender<Change>,
    history: Mutex<History>,
}

static BUS: LazyLock<Bus> = LazyLock::new(|| Bus {
    tx: broadcast::channel(BUS_CAPACITY).0,
    history: Mutex::new(History {
        position: 0,
        dropped_through: 0,
        entries: VecDeque::new(),
    }),
});

fn lock_history() -> std::sync::MutexGuard<'static, History> {
    // A poisoned lock means a panic while appending to a VecDeque; the data
    // is still a valid history, so keep using it rather than taking every
    // later write down with it.
    BUS.history.lock().unwrap_or_else(|p| p.into_inner())
}

/// Report that the state behind `topic`'s read changed. Cheap and
/// non-blocking; safe to call from any storage seam, with or without
/// subscribers.
pub fn notify(topic: Topic) {
    // The same seams feed the facts a dynamic group's rule reads — a role, a
    // member record, an administrator's directory value — so a change wakes its
    // recompute as well (`groups::dynamic`).
    if matches!(topic, Topic::Members | Topic::Directory) {
        crate::groups::dynamic::kick();
    }
    let at = Utc::now();
    {
        let mut h = lock_history();
        h.position += 1;
        let position = h.position;
        // Only a topic's latest change answers "did it change after `since`",
        // so an earlier entry for it is dropped rather than kept. That holds the
        // history at one entry per topic however busy a seam is (a room's
        // holdings move on every upload), without moving `dropped_through`:
        // nothing a resume could need is lost.
        h.entries.retain(|e| e.1 != topic);
        h.entries.push_back((position, topic, at));
        let horizon = at - chrono::TimeDelta::seconds(HISTORY_SECS);
        while h.entries.len() > HISTORY_MAX || h.entries.front().is_some_and(|e| e.2 < horizon) {
            if let Some((p, _, _)) = h.entries.pop_front() {
                h.dropped_through = p;
            }
        }
    }
    let _ = BUS.tx.send(Change {
        signal: Signal::Changed(topic),
        at,
    });
}

/// [`notify`] for the `rooms` topic — a plain `fn`, so it can be the hook
/// `vti_rooms::observe` calls after a room is registered or renewed, or a
/// room's or a storage config's holdings or limits move. A prompt to look,
/// carrying nothing: each stream re-reads and hints only when what the rooms
/// reads report crossed a line (event 0.2 producer rule 4).
pub fn notify_rooms() {
    notify(Topic::Rooms);
}

/// [`notify`] for an action record: both topics read the action list.
pub(crate) fn notify_actions() {
    notify(Topic::Actions);
    notify(Topic::Acknowledgements);
}

/// Report that an ACL entry was written or removed. Every open stream
/// re-checks its caller's standing; the member list (which joins the ACL) and
/// the action list (whose approver sets and expected acknowledgers follow the
/// administrators) may have changed too.
pub(crate) fn notify_authority() {
    let _ = BUS.tx.send(Change {
        signal: Signal::Authority,
        at: Utc::now(),
    });
    notify(Topic::Members);
    // A group manager's appointment is a resource grant on their entry; the
    // `groups` fingerprint drops what changed nothing a recipient manages.
    notify(Topic::Groups);
    notify_actions();
}

/// The current position.
fn position() -> u64 {
    lock_history().position
}

/// The topics changed after `since`, or `None` when the history no longer
/// covers everything after it (or `since` is in the future of this process).
fn changed_since(since: u64) -> Option<Vec<(Topic, DateTime<Utc>)>> {
    let h = lock_history();
    if since > h.position || since < h.dropped_through {
        return None;
    }
    let mut latest: Vec<(Topic, DateTime<Utc>)> = Vec::new();
    for (p, topic, at) in h.entries.iter() {
        if *p <= since {
            continue;
        }
        match latest.iter_mut().find(|(t, _)| t == topic) {
            Some(slot) => slot.1 = *at,
            None => latest.push((*topic, *at)),
        }
    }
    Some(latest)
}

// ─── resume tokens ───────────────────────────────────────────────────────

/// The process's token key. Never persisted: a restart forgets the history
/// too, so every older token must read as unknown.
static TOKEN_KEY: LazyLock<[u8; 32]> = LazyLock::new(|| {
    let mut k = [0u8; 32];
    rand::fill(&mut k);
    k
});

const TOKEN_PREFIX: &str = "e1";
const TOKEN_MAC_LEN: usize = 12;

fn keyed(label: &[u8], caller: &str, extra: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(&*TOKEN_KEY).expect("HMAC accepts any key size");
    mac.update(label);
    mac.update(&(caller.len() as u64).to_be_bytes());
    mac.update(caller.as_bytes());
    mac.update(extra);
    mac.finalize().into_bytes().into()
}

/// A position on `caller`'s stream: the bus position, then this stream's own
/// counter, so that every token on one stream is after the one before it
/// (event 0.1 producer rule 5) even when several hints share a bus position.
///
/// The twelve bytes are masked with a per-caller key stream, so two callers'
/// tokens for the same position share nothing (the SHOULD on unlinkability),
/// and MAC'd over the caller and the clear position, so a token minted for
/// one caller is unknown to every other.
fn mint_token(caller: &str, position: u64, n: u32) -> String {
    let mut clear = [0u8; 12];
    clear[..8].copy_from_slice(&position.to_be_bytes());
    clear[8..].copy_from_slice(&n.to_be_bytes());
    let mask = keyed(b"vtc-admin-events/mask\0", caller, &[]);
    let mut masked = clear;
    for (b, m) in masked.iter_mut().zip(mask.iter()) {
        *b ^= m;
    }
    let tag = keyed(b"vtc-admin-events/mac\0", caller, &clear);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{TOKEN_PREFIX}.{}.{}",
        b64.encode(masked),
        b64.encode(&tag[..TOKEN_MAC_LEN])
    )
}

/// The bus position `token` names, if this process minted it for `caller`.
fn redeem_token(caller: &str, token: &str) -> Option<u64> {
    let mut parts = token.split('.');
    let (Some(TOKEN_PREFIX), Some(masked), Some(tag), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let masked: [u8; 12] = b64.decode(masked).ok()?.try_into().ok()?;
    let tag = b64.decode(tag).ok()?;
    if tag.len() != TOKEN_MAC_LEN {
        return None;
    }
    let mask = keyed(b"vtc-admin-events/mask\0", caller, &[]);
    let mut clear = masked;
    for (b, m) in clear.iter_mut().zip(mask.iter()) {
        *b ^= m;
    }
    let mut mac = <Hmac<Sha256>>::new_from_slice(&*TOKEN_KEY).expect("HMAC accepts any key size");
    mac.update(b"vtc-admin-events/mac\0");
    mac.update(&(caller.len() as u64).to_be_bytes());
    mac.update(caller.as_bytes());
    mac.update(&clear);
    mac.verify_truncated_left(&tag).ok()?;
    Some(u64::from_be_bytes(clear[..8].try_into().ok()?))
}

// ─── caps ────────────────────────────────────────────────────────────────

/// Concurrent streams one administrator may hold — several tabs or devices
/// (subscribe 0.1 consumer rule 11), each console key counting against the
/// administrator it acts for.
pub const MAX_STREAMS_PER_SUBJECT: usize = 5;
/// Concurrent streams the whole service holds. Each is one idle connection
/// and one parked task; past this, a console polls.
pub const MAX_STREAMS_TOTAL: usize = 256;

static OPEN: LazyLock<Mutex<(usize, HashMap<String, usize>)>> =
    LazyLock::new(|| Mutex::new((0, HashMap::new())));

/// One open stream's place under the caps, released when the stream's task
/// ends (or when a granted stream is never opened).
pub(crate) struct StreamPermit {
    subject: String,
}

fn acquire(subject: &str) -> Option<StreamPermit> {
    let mut open = OPEN.lock().unwrap_or_else(|p| p.into_inner());
    let mine = open.1.get(subject).copied().unwrap_or(0);
    if mine >= MAX_STREAMS_PER_SUBJECT || open.0 >= MAX_STREAMS_TOTAL {
        return None;
    }
    open.0 += 1;
    open.1.insert(subject.to_string(), mine + 1);
    Some(StreamPermit {
        subject: subject.to_string(),
    })
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        let mut open = OPEN.lock().unwrap_or_else(|p| p.into_inner());
        open.0 = open.0.saturating_sub(1);
        if let Some(n) = open.1.get_mut(&self.subject) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                open.1.remove(&self.subject);
            }
        }
    }
}

// ─── timing ──────────────────────────────────────────────────────────────

/// The heartbeat a response announces, in seconds: 25, the specification's
/// suggested default, short enough for the usual 30–60 s proxy idle timeouts.
pub const DEFAULT_HEARTBEAT_SECS: u64 = 25;
static HEARTBEAT_SECS: AtomicU64 = AtomicU64::new(DEFAULT_HEARTBEAT_SECS);

/// Set the heartbeat (clamped to the schema's 5–60). For tests, which cannot
/// wait 25 seconds to see one.
#[doc(hidden)]
pub fn set_heartbeat_seconds(secs: u64) {
    HEARTBEAT_SECS.store(secs.clamp(5, 60), Ordering::Relaxed);
}

fn heartbeat() -> Duration {
    Duration::from_secs(HEARTBEAT_SECS.load(Ordering::Relaxed))
}

/// The longest any one stream lives (consumer rule 9's "for example to an
/// hour"): each end costs a freshly signed subscribe, which re-authorizes.
pub const STREAM_LIFETIME: Duration = Duration::from_secs(60 * 60);
/// How long a burst of changes is gathered before its hints go.
const GATHER: Duration = Duration::from_millis(150);
/// No more than one hint per topic per second (consumer rule 6).
const MIN_HINT_INTERVAL: Duration = Duration::from_secs(1);
/// `directory` hints are coalesced harder, so that one member editing their
/// card is not legible as a rhythm (subscribe 0.3 §Correlation's SHOULD).
pub const DIRECTORY_HINT_INTERVAL: Duration = Duration::from_secs(10);
/// A queued frame that cannot be handed to the connection within this long
/// means the client has stopped reading; the stream ends.
fn write_stall() -> Duration {
    heartbeat() * 2
}

// ─── who may read what ───────────────────────────────────────────────────

/// What each topic's read demands **beyond being an administrator** — one
/// source of truth for the read handlers and for the topic's entitlement.
///
/// | Topic | Read it prompts | Gate |
/// |---|---|---|
/// | `actions`, `acknowledgements` | `vtc/admin/actions/list` | any administrator |
/// | `singleAdminMode` | the action list's `ext` | any administrator |
/// | `members` | `vtc/members/list` | any administrator |
/// | `joinRequests` | `vtc/join-requests/list` | any administrator |
/// | `config` | `vtc/config/export` | `vtc.config.admin` |
/// | `rooms` | `vtc/rooms/list`, `vtc/rooms/usage`, `vtc/storage/configs/list` | `vtc.rooms.admin` |
/// | `directory` | the `vtc/directory/*` reads | `vtc.directory.admin` **or** `vtc.directory.notes` ([`readable`]) |
/// | `groups` | the `vtc/groups/*` reads | `vtc.groups.manage`, unqualified **or** for any one group ([`readable`]) |
///
/// The handlers of `vtc/members/list`, `vtc/join-requests/list` and
/// `vtc/config/export` (`trust_tasks`) read their capability from here; the
/// three rooms reads gate on `vtc.rooms.admin` themselves, which a test here
/// pins (subscribe 0.2 §Authorization: "holders of `vtc.rooms.admin`, who are
/// answered on all three").
pub(crate) fn read_capability(topic: Topic) -> Option<crate::acl::Capability> {
    match topic {
        Topic::Config => Some(crate::acl::Capability::ConfigAdmin),
        Topic::Rooms => Some(crate::acl::Capability::RoomsAdmin),
        Topic::Directory => Some(crate::acl::Capability::DirectoryAdmin),
        Topic::Groups => Some(crate::acl::Capability::GroupsManage),
        Topic::Actions
        | Topic::Acknowledgements
        | Topic::SingleAdminMode
        | Topic::Members
        | Topic::JoinRequests => None,
    }
}

/// Whether `entry` may read `topic` — [`read_capability`], widened where a
/// topic's reads answer more than one holding: `directory` either holder of
/// `vtc.directory.admin` or `vtc.directory.notes` (a hint names nothing, and
/// the read shows each only what theirs lets it), and `groups` a manager of
/// any one group as well as of every group.
fn readable(topic: Topic, entry: &crate::acl::VtcAclEntry) -> bool {
    use crate::acl::Capability;
    match topic {
        Topic::Directory => {
            entry.can(Capability::DirectoryAdmin, None)
                || entry.can(Capability::DirectoryNotes, None)
        }
        Topic::Groups => managed_groups(entry).is_none_or(|g| !g.is_empty()),
        t => read_capability(t).is_none_or(|cap| entry.can(cap, None)),
    }
}

/// The groups `entry` may manage: `None` for every group (the capability
/// unqualified), else those it holds an appointment to.
fn managed_groups(entry: &crate::acl::VtcAclEntry) -> Option<BTreeSet<String>> {
    use crate::acl::{Capability, ResourceQualifier};
    if entry.can(Capability::GroupsManage, None) {
        return None;
    }
    Some(
        entry
            .resource_grants
            .iter()
            .filter_map(|g| match (&g.capability, &g.resource) {
                (Capability::GroupsManage, ResourceQualifier::Group(id)) => Some(id.clone()),
                _ => None,
            })
            .filter(|id| {
                entry.can(
                    Capability::GroupsManage,
                    Some(&ResourceQualifier::Group(id.clone())),
                )
            })
            .collect(),
    )
}

/// A caller's standing, read now from the community's own records.
#[derive(Debug, Clone)]
pub(crate) struct Standing {
    /// The administrator the signer is, or acts for (a console key).
    pub principal: String,
    /// The topics whose reads the community would answer this caller.
    pub topics: BTreeSet<Topic>,
    /// Holds `vtc.audit.read`: observes every action, not only its own.
    pub unrestricted: bool,
    /// When the authority the stream rests on lapses: the ACL entry's expiry,
    /// and a console key's delegation's.
    pub expires_at: Option<DateTime<Utc>>,
}

/// `signer`'s standing, or `None` when it holds no administrative role here
/// — resolved the way every administrator verb resolves its signer
/// (`trust_tasks::admin_signer`): the signer's own row; failing that, the
/// row of the administrator an active console-key delegation names.
///
/// A topic is readable exactly when the community would answer its read
/// (subscribe 0.1 §Authorization): every administrator, plus whatever
/// [`read_capability`] says that read demands — the same function the read
/// handlers gate on, so the two cannot drift.
pub(crate) async fn standing(state: &AppState, signer: &str) -> Result<Option<Standing>, AppError> {
    let own = crate::acl::get_acl_entry(&state.acl_ks, signer).await?;
    let (principal, entry, delegated_until) = match own {
        Some(entry) => (signer.to_string(), entry, None),
        None => {
            let Some(d) =
                crate::acl::console_key::resolve_delegated_admin(&state.console_keys_ks, signer)
                    .await?
            else {
                return Ok(None);
            };
            match crate::acl::get_acl_entry(&state.acl_ks, &d.admin_did).await? {
                Some(entry) => (d.admin_did.clone(), entry, Some(d.expires_at)),
                None => return Ok(None),
            }
        }
    };
    if !entry.is_administrator() {
        return Ok(None);
    }
    let topics: BTreeSet<Topic> = if entry.is_suspended() {
        // Suspended pending a cooling-off reduction (`vtc-action-list.md`
        // §8.2): the action about itself and the mode banner, nothing more.
        [Topic::Actions, Topic::SingleAdminMode]
            .into_iter()
            .collect()
    } else {
        Topic::ALL
            .into_iter()
            .filter(|t| readable(*t, &entry))
            .collect()
    };
    let entry_until = entry
        .expires_at
        .and_then(|e| DateTime::<Utc>::from_timestamp(e as i64, 0));
    let expires_at = match (entry_until, delegated_until) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    Ok(Some(Standing {
        principal,
        topics,
        unrestricted: entry.can(crate::acl::Capability::AuditRead, None),
        expires_at,
    }))
}

// ─── what the recipient's reads show ─────────────────────────────────────

/// A fingerprinted topic's count (0 where it has none) and a digest of what
/// its read would show, for one recipient. The digest moves when — and only
/// when — something the read shows them, that the topic hints about, moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Observed {
    count: u64,
    digest: [u8; 32],
}

/// What [`observe`] saw.
#[derive(Debug, Default)]
struct Observation {
    topics: HashMap<Topic, Observed>,
    /// With `rooms`: the next moment a hosted room's lifecycle state changes
    /// by the clock alone, when the stream must look again unprompted.
    rooms_wake: Option<DateTime<Utc>>,
}

/// Observe the fingerprinted topics among `topics` for `standing`.
async fn observe(
    state: &AppState,
    standing: &Standing,
    topics: &BTreeSet<Topic>,
) -> Result<Observation, AppError> {
    let mut out = HashMap::new();
    let mut rooms_wake = None;
    if topics.contains(&Topic::Groups) {
        let digest = groups_fingerprint(state, &standing.principal).await?;
        out.insert(Topic::Groups, Observed { count: 0, digest });
    }
    if topics.contains(&Topic::Rooms) {
        let (digest, wake) = rooms_fingerprint(state).await?;
        out.insert(Topic::Rooms, Observed { count: 0, digest });
        rooms_wake = wake;
    }
    if topics.contains(&Topic::Actions) || topics.contains(&Topic::Acknowledgements) {
        // The same computation `vtc/admin/actions/list` makes for its
        // `counts` and `ext` (limit 0: no page is rendered).
        let page = crate::admin_actions::list(
            state,
            &standing.principal,
            standing.unrestricted,
            crate::admin_actions::View::WaitingForMe,
            None,
            0,
            0,
            crate::admin_actions::WireVersion::V0_2,
        )
        .await?;
        if topics.contains(&Topic::Actions) {
            let mut visible: Vec<Value> = crate::admin_actions::all(state)
                .await?
                .iter()
                .filter(|r| {
                    crate::admin_actions::visible_to(r, &standing.principal, standing.unrestricted)
                })
                .filter_map(|r| serde_json::to_value(r).ok())
                .collect();
            visible.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
            out.insert(
                Topic::Actions,
                Observed {
                    count: page.waiting_for_me,
                    digest: digest(&(page.waiting_for_me, &visible)),
                },
            );
        }
        if topics.contains(&Topic::Acknowledgements) {
            let owed = page.ext["operatorWritesUnacknowledged"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            out.insert(
                Topic::Acknowledgements,
                Observed {
                    count: owed.len() as u64,
                    digest: digest(&owed),
                },
            );
        }
    }
    if topics.contains(&Topic::JoinRequests) {
        // The count is the read's own: `vtc/join-requests/list`'s default
        // (pending) filter, its exact `totalEstimate`, from a one-row page —
        // the same `limit: 1` read the console's badge and tile make.
        let pending = crate::routes::join_requests::read::list_join_requests_inner(
            state,
            crate::routes::join_requests::read::ListJoinRequestsQuery {
                status: Some(crate::join::JoinStatus::Pending),
                cursor: None,
                limit: Some(1),
            },
        )
        .await?
        .total_estimate
        .unwrap_or(0);
        // The digest spans every status the page can be filtered to.
        let requests = crate::join::list_join_requests(&state.join_requests_ks).await?;
        let mut shape: Vec<Value> = requests
            .iter()
            .filter_map(|r| serde_json::to_value(r).ok())
            .collect();
        shape.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        out.insert(
            Topic::JoinRequests,
            Observed {
                count: pending,
                digest: digest(&shape),
            },
        );
    }
    Ok(Observation {
        topics: out,
        rooms_wake,
    })
}

/// The 80 / 95 / 100 percent band `used` has reached of `limit` (0 under
/// 80), as the console draws it (`admin-ui/src/lib/rooms-api.ts`,
/// `thresholdOf`): a limit of 0 refuses everything, so it reads as full.
fn band(used: u64, limit: u64) -> u8 {
    if limit == 0 {
        return 100;
    }
    let (used, limit) = (u128::from(used) * 100, u128::from(limit));
    [100u8, 95, 80]
        .into_iter()
        .find(|pct| used >= limit * u128::from(*pct))
        .unwrap_or(0)
}

/// What the `rooms` topic hints about (event 0.2 producer rule 4), as the
/// three rooms reads report it, digested — and when a room's lifecycle next
/// moves by the clock.
///
/// - every hosted room (`vtc/rooms/list`) and its lifecycle state;
/// - each room's band: its holdings — reserved bytes included — against the
///   room limits `vtc/rooms/usage` reports for it, the larger of bytes and
///   files, for the rooms that report has rows for (those that have held
///   files);
/// - every storage config as stored (`vtc/storage/configs/list`: created,
///   changed, a new state), and the band of its held bytes against its
///   capacity;
/// - each room's migration (`vtc/rooms/get`'s `storage.migration`) and its
///   state — beyond what rule 4 names, because a console showing one needs to
///   learn it ended; the hint still names nothing.
///
/// Nothing finer: a room's or a config's holdings moving inside a band, a
/// migration's progress inside its state, a renewal of a live room or a new
/// owner produce no hint.
async fn rooms_fingerprint(
    state: &AppState,
) -> Result<([u8; 32], Option<DateTime<Utc>>), AppError> {
    let now = Utc::now().timestamp().max(0) as u64;
    let files = &state.room_files;
    let with_files: std::collections::HashSet<String> =
        files.rooms_with_files().await?.into_iter().collect();
    let mut rooms = vti_rooms::storage::list_rooms(&state.rooms_ks).await?;
    rooms.sort_by(|a, b| a.room_id.cmp(&b.room_id));
    let mut shape: Vec<Value> = Vec::with_capacity(rooms.len());
    let mut wake: Option<u64> = None;
    for room in &rooms {
        let room_band = if with_files.contains(&room.room_id) {
            let usage = files.room_usage(&room.room_id).await?;
            let limits = files.effective_limits(room).await?.room;
            let bytes = limits
                .max_bytes
                .map_or(0, |l| band(usage.bytes + usage.reserved_bytes, l));
            let count = limits.max_files.map_or(0, |l| band(usage.files, l));
            bytes.max(count)
        } else {
            0
        };
        shape.push(serde_json::json!([
            room.room_id,
            room.lifecycle(now).as_str(),
            room_band
        ]));
        if let Some(next) = room.next_lifecycle_change(now) {
            wake = Some(wake.map_or(next, |w| w.min(next)));
        }
    }
    let holdings = files.config_holdings().await?;
    let mut configs = state.room_storage.configs().await?;
    configs.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    for config in configs {
        let id = config["id"].as_str().unwrap_or_default();
        let held = holdings.get(id).map_or(0, |h| h.bytes);
        let config_band = config["capacityBytes"]
            .as_u64()
            .map_or(0, |cap| band(held, cap));
        shape.push(serde_json::json!([config, config_band]));
    }
    // A room's migration starting, finishing, pausing or failing: what `vtc/rooms/get`
    // reports as `storage.migration`'s state. Its progress inside a state is polled.
    for m in files.migrations().await? {
        shape.push(serde_json::json!([
            m.room_id,
            m.migration_id,
            m.state.as_str()
        ]));
    }
    let wake = wake.and_then(|w| DateTime::<Utc>::from_timestamp(w as i64, 0));
    Ok((digest(&shape), wake))
}

/// What the `groups` topic hints about for `principal`: each group they may
/// manage as the `vtc/groups/*` reads show it to a manager — the group, its
/// members, its join requests and its managers. A change to a group they do
/// not manage moves nothing here (subscribe 0.3 §Authorization).
async fn groups_fingerprint(state: &AppState, principal: &str) -> Result<[u8; 32], AppError> {
    let Some(entry) = crate::acl::get_acl_entry(&state.acl_ks, principal).await? else {
        return Ok(digest(&()));
    };
    let managed = managed_groups(&entry);
    let ks = state.directory.ks();
    let mut groups = crate::groups::all(ks).await?;
    groups.retain(|g| managed.as_ref().is_none_or(|m| m.contains(&g.group_id)));
    groups.sort_by(|a, b| a.group_id.cmp(&b.group_id));
    let requests = crate::groups::all_requests(ks).await?;
    // Every group's appointed managers, from one pass over the ACL.
    let now = Utc::now();
    let mut managers: HashMap<String, BTreeSet<String>> = HashMap::new();
    for e in crate::acl::list_acl_entries(&state.acl_ks).await? {
        for g in &e.resource_grants {
            if let (crate::acl::Capability::GroupsManage, crate::acl::ResourceQualifier::Group(id)) =
                (&g.capability, &g.resource)
                && g.is_live(now)
            {
                managers
                    .entry(id.clone())
                    .or_default()
                    .insert(e.did.clone());
            }
        }
    }
    let mut shape: Vec<Value> = Vec::with_capacity(groups.len());
    for g in &groups {
        let mut members: Vec<Value> = crate::groups::members_of(ks, &g.group_id)
            .await?
            .iter()
            .filter_map(|m| serde_json::to_value(m).ok())
            .collect();
        members.sort_by(|a, b| a["entryId"].as_str().cmp(&b["entryId"].as_str()));
        let mut asked: Vec<Value> = requests
            .iter()
            .filter(|r| r.group_id == g.group_id)
            .filter_map(|r| serde_json::to_value(r).ok())
            .collect();
        asked.sort_by(|a, b| a["requestId"].as_str().cmp(&b["requestId"].as_str()));
        shape.push(serde_json::json!([
            g,
            members,
            asked,
            managers.get(&g.group_id)
        ]));
    }
    Ok(digest(&shape))
}

fn digest<T: serde::Serialize>(v: &T) -> [u8; 32] {
    Sha256::digest(serde_json::to_vec(v).unwrap_or_default()).into()
}

// ─── the HTTPS stream slot ───────────────────────────────────────────────

/// What the HTTPS door tells the subscribe handler about the request, and
/// where the handler leaves a granted stream for the door to open.
///
/// Set only by the HTTPS door around its dispatch. Every other transport
/// (DIDComm, TSP, a direct call) dispatches without one, and the handler
/// answers `streamUnavailable`: no other binding defines a streamed response.
#[derive(Clone)]
pub(crate) struct StreamSlot {
    inner: Arc<SlotInner>,
}

struct SlotInner {
    accepts_stream: bool,
    last_event_id: Option<String>,
    grant: Mutex<Option<Grant>>,
}

tokio::task_local! {
    static STREAM_SLOT: StreamSlot;
}

impl StreamSlot {
    pub(crate) fn new(accepts_stream: bool, last_event_id: Option<String>) -> Self {
        Self {
            inner: Arc::new(SlotInner {
                accepts_stream,
                last_event_id,
                grant: Mutex::new(None),
            }),
        }
    }

    pub(crate) fn accepts_stream(&self) -> bool {
        self.inner.accepts_stream
    }

    pub(crate) fn last_event_id(&self) -> Option<&str> {
        self.inner.last_event_id.as_deref()
    }

    pub(crate) fn grant(&self, grant: Grant) {
        *self.inner.grant.lock().unwrap_or_else(|p| p.into_inner()) = Some(grant);
    }

    pub(crate) fn take(&self) -> Option<Grant> {
        self.inner
            .grant
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
    }

    /// Run `fut` with this slot visible to the subscribe handler.
    ///
    /// Not an `async fn`, and the future is boxed: the spine's dispatch is one
    /// of the largest futures in the service, and an async wrapper holding it
    /// inline adds its whole size to the poll frame of every document the door
    /// dispatches — which overflowed the 2 MiB test-thread stack on the
    /// deepest paths (a reduction's notice, a join review) under
    /// `vetting-pcs`. Boxed, the wrapper costs a pointer.
    pub(crate) fn scope<'a, T>(
        &self,
        fut: std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>,
    ) -> tokio::task::futures::TaskLocalFuture<
        StreamSlot,
        std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>,
    > {
        STREAM_SLOT.scope(self.clone(), fut)
    }
}

/// The slot of the request being dispatched, when it arrived at the HTTPS
/// door.
pub(crate) fn current_slot() -> Option<StreamSlot> {
    STREAM_SLOT.try_with(|s| s.clone()).ok()
}

/// Whether an `Accept` header asks for an event stream — `text/event-stream`
/// listed with a non-zero quality (binding 0.3 §2.1.1).
pub(crate) fn accepts_event_stream(accept: Option<&str>) -> bool {
    let Some(accept) = accept else { return false };
    accept.split(',').any(|range| {
        let mut parts = range.split(';').map(str::trim);
        let media = parts.next().unwrap_or_default();
        if !media.eq_ignore_ascii_case("text/event-stream") {
            return false;
        }
        parts
            .filter_map(|p| p.split_once('='))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case("q"))
            .is_none_or(|(_, q)| q.trim().parse::<f32>().is_ok_and(|q| q > 0.0))
    })
}

// ─── granting a stream ───────────────────────────────────────────────────

/// A stream the subscribe handler has granted, waiting for the door to open
/// it behind the signed `#response`.
pub(crate) struct Grant {
    rx: broadcast::Receiver<Change>,
    _permit: StreamPermit,
    signer: String,
    vtc_did: String,
    parent_thread: String,
    topics: BTreeSet<Topic>,
    version: Version,
    backlog: Vec<(Topic, DateTime<Utc>)>,
    baseline: HashMap<Topic, Observed>,
    rooms_wake: Option<DateTime<Utc>>,
    deadline: DateTime<Utc>,
    first_id: String,
    position: u64,
}

/// What the subscribe handler answers with, the `#response` payload — the
/// generated `Response` of the stream's version, serialised — and the stream
/// behind it.
pub(crate) struct Opened {
    pub response: Value,
    pub grant: Grant,
}

/// Why a subscribe is refused after its standing is known.
pub(crate) enum Refusal {
    /// No requested topic is one the caller may read.
    NoTopics,
    /// The caller already holds [`MAX_STREAMS_PER_SUBJECT`] streams, or the
    /// service [`MAX_STREAMS_TOTAL`].
    TooMany,
    Internal(AppError),
}

/// Grant a stream of `requested ∩ standing.topics` to `signer`, at
/// `version`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn open(
    state: &AppState,
    signer: &str,
    standing: &Standing,
    version: Version,
    requested: &BTreeSet<Topic>,
    since: Option<&str>,
    parent_thread: String,
    document_expires: Option<DateTime<Utc>>,
) -> Result<Opened, Refusal> {
    let topics: BTreeSet<Topic> = requested
        .intersection(&standing.topics)
        .copied()
        .filter(|t| t.in_version(version))
        .collect();
    if topics.is_empty() {
        return Err(Refusal::NoTopics);
    }
    let permit = acquire(&standing.principal).ok_or(Refusal::TooMany)?;

    // Subscribe before reading the position, so nothing published between the
    // two is missed: anything after the position the response names arrives
    // on `rx`.
    let rx = BUS.tx.subscribe();
    let position = position();

    let (resumed, backlog) = match since
        .and_then(|t| redeem_token(signer, t))
        .and_then(changed_since)
    {
        Some(changed) => (
            true,
            changed
                .into_iter()
                .filter(|(t, _)| topics.contains(t))
                .collect(),
        ),
        None => (false, Vec::new()),
    };

    let observation = observe(state, standing, &topics)
        .await
        .map_err(Refusal::Internal)?;
    let mut baseline = observation.topics;
    // A resumed topic changed while the console was away: its hint goes
    // whatever the stream observes now, so it has no baseline to match.
    for (topic, _) in &backlog {
        baseline.remove(topic);
    }

    let now = Utc::now();
    let lifetime =
        chrono::TimeDelta::from_std(STREAM_LIFETIME).unwrap_or(chrono::TimeDelta::hours(1));
    let deadline = [Some(now + lifetime), document_expires, standing.expires_at]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(now + lifetime);

    let first_id = mint_token(signer, position, 0);
    let response =
        subscribe_response(version, &topics, resumed, &first_id).map_err(Refusal::Internal)?;

    let vtc_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_default();
    Ok(Opened {
        response,
        grant: Grant {
            rx,
            _permit: permit,
            signer: signer.to_string(),
            vtc_did,
            parent_thread,
            topics,
            version,
            backlog,
            baseline,
            rooms_wake: observation.rooms_wake,
            deadline,
            first_id,
            position,
        },
    })
}

/// The generated `#response` payload of `version`, serialised. The two
/// versions' shapes are the same; only the topic set differs.
fn subscribe_response(
    version: Version,
    topics: &BTreeSet<Topic>,
    resumed: bool,
    token: &str,
) -> Result<Value, AppError> {
    let internal = |e: &dyn std::fmt::Display| AppError::Internal(e.to_string());
    macro_rules! build {
        ($m:ident) => {{
            let topics = topics
                .iter()
                .map(|t| t.wire().parse::<$m::Topic>().map_err(|e| internal(&e)))
                .collect::<Result<Vec<_>, _>>()?;
            let response = $m::Response::builder()
                .topics(topics)
                .heartbeat_seconds(heartbeat().as_secs() as i64)
                .resumed(resumed)
                .resume_token($m::ResumeToken::try_from(token).map_err(|e| internal(&e))?);
            let response = $m::Response::try_from(response).map_err(|e| internal(&e))?;
            serde_json::to_value(response).map_err(|e| internal(&e))
        }};
    }
    match version {
        Version::V0_1 => build!(subscribe),
        Version::V0_2 => build!(subscribe_v0_2),
        Version::V0_3 => build!(subscribe_v0_3),
    }
}

/// One hint as the generated `event` document of `grant`'s version,
/// unsigned: the topic, `at`, `count` on a count topic, and the resume token
/// — nothing else (event 0.2 producer rules 3 and 5).
fn hint_document(
    grant: &Grant,
    topic: Topic,
    at: DateTime<Utc>,
    count: Option<u64>,
    token: &str,
) -> Option<Value> {
    macro_rules! build {
        ($m:ident) => {{
            let mut builder = $m::Payload::builder()
                .topic(topic.wire().parse::<$m::Topic>().ok()?)
                .at(at)
                .resume_token($m::ResumeToken::try_from(token).ok()?);
            if let Some(c) = count {
                builder = builder.count(Some(c));
            }
            let payload = $m::Payload::try_from(builder).ok()?;
            let mut doc =
                TrustTask::for_payload(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload);
            doc.parent_thread_id = Some(grant.parent_thread.clone());
            doc.issuer = Some(grant.vtc_did.clone());
            doc.recipient = Some(grant.signer.clone());
            doc.issued_at = DateTime::<Utc>::from_timestamp(Utc::now().timestamp(), 0);
            serde_json::to_value(&doc).ok()
        }};
    }
    match grant.version {
        Version::V0_1 => build!(event),
        Version::V0_2 => build!(event_v0_2),
        Version::V0_3 => build!(event_v0_3),
    }
}

// ─── the stream ──────────────────────────────────────────────────────────

/// `id: <token>` + one `data:` line holding one whole document, no `event:`
/// field (binding 0.3 §2.1.2 items 1–3).
fn frame(id: &str, document: &[u8]) -> Option<Bytes> {
    // Compact JSON never holds a raw line break (string breaks are escaped);
    // checked anyway, because a frame that splits would desynchronise the
    // client's parser for the rest of the stream.
    if document.contains(&b'\n') || document.contains(&b'\r') || id.contains(['\n', '\r', '\0']) {
        return None;
    }
    let mut out = Vec::with_capacity(document.len() + id.len() + 16);
    out.extend_from_slice(b"id: ");
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(b"\ndata: ");
    out.extend_from_slice(document);
    out.extend_from_slice(b"\n\n");
    Some(Bytes::from(out))
}

/// An SSE comment: the heartbeat. Its text means nothing (§2.1.2 item 5).
const HEARTBEAT_FRAME: &[u8] = b": heartbeat\n\n";

/// Open the granted stream: `200 OK`, `text/event-stream`, the signed
/// `#response` as its first event, hints after it.
pub(crate) fn respond(state: AppState, grant: Grant, response_document: Vec<u8>) -> Response {
    let (tx, mut rx) = mpsc::channel::<Bytes>(16);
    let Some(first) = frame(&grant.first_id, &response_document) else {
        // Unreachable for a document this service serialised; answer the
        // document unstreamed rather than open a stream that cannot frame it.
        tracing::error!("subscribe #response does not frame as one SSE event");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "application/json")],
            response_document,
        )
            .into_response();
    };
    // The channel is empty, so this cannot fail.
    let _ = tx.try_send(first);
    tokio::spawn(run(state, grant, tx));

    let body = Body::from_stream(futures_util::stream::poll_fn(move |cx| {
        rx.poll_recv(cx)
            .map(|b| b.map(Ok::<_, std::convert::Infallible>))
    }));
    let mut res = Response::new(body);
    *res.status_mut() = StatusCode::OK;
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // Proxies that buffer responses (nginx) would hold every hint back.
    h.insert("x-accel-buffering", HeaderValue::from_static("no"));
    res
}

/// Why a stream ended — for the log only; the client is told nothing.
#[derive(Debug)]
enum Ended {
    ClientGone,
    Shutdown,
    Deadline,
    Stalled,
    StandingShrank,
    BusClosed,
}

async fn write(tx: &mpsc::Sender<Bytes>, bytes: Bytes) -> Result<(), Ended> {
    match tokio::time::timeout(write_stall(), tx.send(bytes)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(Ended::ClientGone),
        Err(_) => Err(Ended::Stalled),
    }
}

struct Stream {
    state: AppState,
    grant: Grant,
    /// Topics with a change not yet hinted, and the latest change time.
    pending: HashMap<Topic, DateTime<Utc>>,
    /// When each topic was last hinted.
    last_sent: HashMap<Topic, tokio::time::Instant>,
    /// Re-check standing before the next byte.
    recheck: bool,
    /// When a hosted room's lifecycle next changes by the clock: `rooms` is
    /// looked at then, unprompted.
    rooms_wake: Option<tokio::time::Instant>,
    /// This stream's own counter, the second half of every token.
    n: u32,
}

async fn run(state: AppState, mut grant: Grant, tx: mpsc::Sender<Bytes>) {
    let mut shutdown = state.shutdown_tx.subscribe();
    let backlog = std::mem::take(&mut grant.backlog);
    let rooms_wake = grant.rooms_wake.map(wake_instant);
    let mut stream = Stream {
        state,
        grant,
        pending: backlog.into_iter().collect(),
        last_sent: HashMap::new(),
        recheck: false,
        rooms_wake,
        n: 0,
    };
    let ended = stream.drive(&tx, &mut shutdown).await;
    tracing::debug!(?ended, "admin event stream ended");
}

/// The instant just after `at`, when the state it names has changed. Further
/// off than the longest stream lives is as good as never: the stream ends
/// first, and the next one looks again.
fn wake_instant(at: DateTime<Utc>) -> tokio::time::Instant {
    let left = (at - Utc::now()).to_std().unwrap_or(Duration::ZERO);
    tokio::time::Instant::now() + left.min(STREAM_LIFETIME) + Duration::from_secs(1)
}

impl Stream {
    fn deadline_instant(&self) -> tokio::time::Instant {
        let left = (self.grant.deadline - Utc::now())
            .to_std()
            .unwrap_or(Duration::ZERO);
        tokio::time::Instant::now() + left
    }

    /// When the pending set next becomes sendable.
    fn next_flush(&self) -> Option<tokio::time::Instant> {
        if self.pending.is_empty() && !self.recheck {
            return None;
        }
        let now = tokio::time::Instant::now();
        let earliest = self
            .pending
            .keys()
            .map(|t| {
                self.last_sent
                    .get(t)
                    .map_or(now, |s| (*s + t.min_hint_interval()).max(now))
            })
            .min()
            .unwrap_or(now);
        Some(earliest.max(now) + GATHER)
    }

    async fn drive(
        &mut self,
        tx: &mpsc::Sender<Bytes>,
        shutdown: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Ended {
        if *shutdown.borrow() {
            return Ended::Shutdown;
        }
        let mut beat = tokio::time::Instant::now() + heartbeat();
        loop {
            // Re-derived every turn: a re-read standing may pull it in.
            let deadline = self.deadline_instant();
            let flush_at = self.next_flush();
            let rooms_wake = self.rooms_wake;
            tokio::select! {
                biased;
                _ = tx.closed() => return Ended::ClientGone,
                _ = shutdown.changed() => return Ended::Shutdown,
                _ = tokio::time::sleep_until(deadline) => return Ended::Deadline,
                msg = self.grant.rx.recv() => match msg {
                    Ok(change) => self.absorb(change),
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Missed some: every topic may have moved.
                        let now = Utc::now();
                        for t in self.grant.topics.clone() {
                            self.pending.insert(t, now);
                        }
                        self.recheck = true;
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ended::BusClosed,
                },
                _ = async { tokio::time::sleep_until(flush_at.expect("guarded")).await },
                    if flush_at.is_some() =>
                {
                    match self.flush(tx).await {
                        Ok(true) => beat = tokio::time::Instant::now() + heartbeat(),
                        Ok(false) => {}
                        Err(ended) => return ended,
                    }
                }
                _ = async { tokio::time::sleep_until(rooms_wake.expect("guarded")).await },
                    if rooms_wake.is_some() =>
                {
                    // A room's lifecycle state moves with the clock, with no
                    // write to say so: look, as a seam would have prompted.
                    self.rooms_wake = None;
                    let now = Utc::now();
                    let at = self.pending.entry(Topic::Rooms).or_insert(now);
                    *at = (*at).max(now);
                }
                _ = tokio::time::sleep_until(beat) => {
                    // Authority is re-read at least once a heartbeat, so a
                    // revoked console key or a lapsed entry ends the stream
                    // within one interval even if nothing else happens.
                    if let Err(ended) = self.check_standing().await {
                        return ended;
                    }
                    if let Err(ended) = write(tx, Bytes::from_static(HEARTBEAT_FRAME)).await {
                        return ended;
                    }
                    beat = tokio::time::Instant::now() + heartbeat();
                }
            }
        }
    }

    fn absorb(&mut self, change: Change) {
        match change.signal {
            Signal::Changed(topic) if self.grant.topics.contains(&topic) => {
                let at = self.pending.entry(topic).or_insert(change.at);
                *at = (*at).max(change.at);
            }
            Signal::Changed(_) => {}
            Signal::Authority => self.recheck = true,
        }
    }

    /// Re-read the caller's standing; end the stream if its readable topics
    /// no longer cover the stream's effective topics (consumer rule 7), and
    /// pull the deadline in if the authority now lapses sooner.
    async fn check_standing(&mut self) -> Result<Standing, Ended> {
        self.recheck = false;
        let standing = match standing(&self.state, &self.grant.signer).await {
            Ok(Some(s)) => s,
            Ok(None) => return Err(Ended::StandingShrank),
            // A store that cannot answer cannot authorize the next hint.
            Err(e) => {
                tracing::warn!(error = %e, "admin event stream: standing unreadable; ending");
                return Err(Ended::StandingShrank);
            }
        };
        if !self.grant.topics.is_subset(&standing.topics) {
            return Err(Ended::StandingShrank);
        }
        if let Some(until) = standing.expires_at {
            if until <= Utc::now() {
                return Err(Ended::Deadline);
            }
            // The entry or delegation now lapses sooner than when the stream
            // opened: the stream goes with it.
            self.grant.deadline = self.grant.deadline.min(until);
        }
        Ok(standing)
    }

    /// Send what is pending and sendable. `Ok(true)` when anything was
    /// written.
    async fn flush(&mut self, tx: &mpsc::Sender<Bytes>) -> Result<bool, Ended> {
        let standing = self.check_standing().await?;
        let now = tokio::time::Instant::now();
        let due: BTreeSet<Topic> = self
            .pending
            .keys()
            .filter(|t| {
                self.last_sent
                    .get(*t)
                    .is_none_or(|s| now.duration_since(*s) >= t.min_hint_interval())
            })
            .copied()
            .collect();
        if due.is_empty() {
            return Ok(false);
        }
        let fingerprinted: BTreeSet<Topic> = due
            .iter()
            .copied()
            .filter(|t| t.is_fingerprinted())
            .collect();
        let observed = if fingerprinted.is_empty() {
            HashMap::new()
        } else {
            match observe(&self.state, &standing, &fingerprinted).await {
                Ok(o) => {
                    if fingerprinted.contains(&Topic::Rooms) {
                        self.rooms_wake = o.rooms_wake.map(wake_instant);
                    }
                    o.topics
                }
                Err(e) => {
                    tracing::warn!(error = %e, "admin event stream: topic unreadable; ending");
                    return Err(Ended::StandingShrank);
                }
            }
        };
        let mut wrote = false;
        for topic in due {
            let Some(at) = self.pending.remove(&topic) else {
                continue;
            };
            let count = if topic.is_fingerprinted() {
                let Some(seen) = observed.get(&topic).copied() else {
                    continue;
                };
                // Nothing the recipient's read shows moved: no hint.
                if self.grant.baseline.get(&topic) == Some(&seen) {
                    continue;
                }
                self.grant.baseline.insert(topic, seen);
                topic.is_count().then_some(seen.count)
            } else {
                None
            };
            self.n = self.n.saturating_add(1);
            let token = mint_token(
                &self.grant.signer,
                position().max(self.grant.position),
                self.n,
            );
            let Some(bytes) = self.hint(topic, at, count, &token).await else {
                continue;
            };
            write(tx, bytes).await?;
            self.last_sent.insert(topic, tokio::time::Instant::now());
            wrote = true;
        }
        Ok(wrote)
    }

    /// One `vtc/admin/events/event` document of the stream's version,
    /// framed. Carries the topic, `at`, `count` on a count topic, and the
    /// resume token — nothing else (event 0.2 producer rules 3 and 5).
    async fn hint(
        &self,
        topic: Topic,
        at: DateTime<Utc>,
        count: Option<u64>,
        token: &str,
    ) -> Option<Bytes> {
        let mut value = hint_document(&self.grant, topic, at, count, token)?;
        // RECOMMENDED: the hint is attributable to this community. A failed
        // signature still sends it — a hint grants nothing either way.
        if let Some(signer) = self.state.credential_signer.as_ref()
            && let Err(e) = signer.sign_operational_doc(&mut value).await
        {
            tracing::warn!(error = %e, "admin event hint sent unsigned");
        }
        let bytes = serde_json::to_vec(&value).ok()?;
        frame(token, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_round_trips_for_its_caller_only() {
        let t = mint_token("did:key:zA", 42, 3);
        assert!(
            t.chars()
                .all(|c| c.is_ascii_alphanumeric() || "._~-".contains(c))
        );
        assert!(subscribe::ResumeToken::try_from(t.as_str()).is_ok());
        assert_eq!(redeem_token("did:key:zA", &t), Some(42));
        assert_eq!(redeem_token("did:key:zB", &t), None);
        assert_eq!(redeem_token("did:key:zA", "evt.000141"), None);
        assert_eq!(redeem_token("did:key:zA", ""), None);
    }

    #[test]
    fn two_callers_tokens_for_one_position_share_nothing() {
        let a = mint_token("did:key:zA", 7, 0);
        let b = mint_token("did:key:zB", 7, 0);
        assert_ne!(a.split('.').nth(1), b.split('.').nth(1));
    }

    #[test]
    fn tokens_on_one_stream_are_distinct_positions() {
        assert_ne!(
            mint_token("did:key:zA", 7, 1),
            mint_token("did:key:zA", 7, 2)
        );
    }

    #[test]
    fn accept_negotiation() {
        assert!(accepts_event_stream(Some(
            "text/event-stream, application/json;q=0.5"
        )));
        assert!(accepts_event_stream(Some("TEXT/EVENT-STREAM")));
        assert!(!accepts_event_stream(Some("application/json")));
        assert!(!accepts_event_stream(Some("text/event-stream;q=0")));
        assert!(!accepts_event_stream(None));
    }

    #[test]
    fn a_frame_is_one_id_and_one_data_line() {
        let f = frame("e1.a.b", br#"{"a":"x\ny"}"#).unwrap();
        assert_eq!(
            &f[..],
            b"id: e1.a.b\ndata: {\"a\":\"x\\ny\"}\n\n".as_slice()
        );
        assert!(frame("e1", b"{\n}").is_none());
    }

    #[test]
    fn caps_hold_per_subject() {
        let subject = format!("did:key:zCap{}", uuid::Uuid::new_v4());
        let permits: Vec<_> = (0..MAX_STREAMS_PER_SUBJECT)
            .map(|_| acquire(&subject).expect("under the cap"))
            .collect();
        assert!(acquire(&subject).is_none());
        drop(permits);
        assert!(acquire(&subject).is_some());
    }

    #[test]
    fn bands_are_the_consoles() {
        // `admin-ui/src/lib/rooms-api.ts` `thresholdOf(fullness(..))`.
        assert_eq!(band(0, 100), 0);
        assert_eq!(band(79, 100), 0);
        assert_eq!(band(80, 100), 80);
        assert_eq!(band(94, 100), 80);
        assert_eq!(band(95, 100), 95);
        assert_eq!(band(100, 100), 100);
        assert_eq!(band(250, 100), 100);
        assert_eq!(band(0, 0), 100, "a limit of 0 refuses everything: full");
        assert_eq!(band(u64::MAX, u64::MAX), 100);
    }

    #[test]
    fn the_topic_set_is_closed_per_version() {
        for t in Topic::ALL {
            assert_eq!(Topic::from_wire(t.wire()), Some(t));
            assert!(t.wire().parse::<subscribe_v0_3::Topic>().is_ok());
            assert!(t.wire().parse::<event_v0_3::Topic>().is_ok());
            assert_eq!(
                t.wire().parse::<subscribe_v0_2::Topic>().is_ok(),
                t.in_version(Version::V0_2)
            );
            assert_eq!(
                t.wire().parse::<event_v0_2::Topic>().is_ok(),
                t.in_version(Version::V0_2)
            );
            assert_eq!(
                t.wire().parse::<subscribe::Topic>().is_ok(),
                t.in_version(Version::V0_1)
            );
            assert_eq!(
                t.wire().parse::<event::Topic>().is_ok(),
                t.in_version(Version::V0_1)
            );
        }
        assert!(!Topic::Rooms.in_version(Version::V0_1));
        assert!(!Topic::Rooms.is_count(), "rooms carries no count");
    }

    /// Subscribe 0.2 §Authorization: `rooms` goes to holders of
    /// `vtc.rooms.admin`, who are answered on all three of its reads — which
    /// gate on that capability themselves (`surface_tasks::handle_rooms_list`,
    /// `storage_tasks::rooms_admin`).
    #[test]
    fn rooms_is_read_with_the_rooms_capability() {
        assert_eq!(
            read_capability(Topic::Rooms),
            Some(crate::acl::Capability::RoomsAdmin)
        );
    }

    #[test]
    fn the_history_keeps_one_entry_per_topic_and_still_resumes() {
        let before = position();
        for _ in 0..50 {
            notify(Topic::Rooms);
        }
        let h = lock_history();
        assert!(
            h.entries.iter().filter(|e| e.1 == Topic::Rooms).count() <= 1,
            "a busy seam does not crowd the history"
        );
        drop(h);
        let changed = changed_since(before).expect("still covered");
        assert!(changed.iter().any(|(t, _)| *t == Topic::Rooms));
    }

    #[test]
    fn history_answers_what_changed_after_a_position() {
        let before = position();
        notify(Topic::Config);
        let changed = changed_since(before).expect("covered");
        assert!(changed.iter().any(|(t, _)| *t == Topic::Config));
        assert!(changed_since(position() + 1).is_none());
    }
}
