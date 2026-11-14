//! A room's **signal delay** (`rooms/_shared/0.2` `SignalDelay`) and the tasks that set and
//! serve it: `rooms/signal-delay/set/0.1`, `rooms/create/0.3` and `rooms/info/0.4`
//! (trust-tasks-tf #1084).
//!
//! # What it decides
//!
//! Whether this host waits a short randomised interval before it sends a
//! `rooms/changed/0.1` signal for the room ([`crate::watch::RoomWatches`]): `randomised`, the
//! default and what every room that never set one has, waits
//! [`crate::watch::SIGNAL_DELAY_MS`]; `none` sends as soon as the change that fired the watch
//! is stored, with no wait of the host's own.
//!
//! # The room's, never a watcher's
//!
//! The wait blurs, for every writer in the room, the line between a write reaching the host
//! and a signal leaving it. One watcher with no wait would undo that for all of them, so the
//! setting is a term of the room — changed by a holder of `admin`, served to every member in
//! `rooms/info` 0.4 — and no watch request can change it (`rooms/changed/0.1` Producer item 4).
//!
//! Both hosts — `room-host` and the VTC — call in here once they hold the room and the
//! verified chain, as they do for the record-retention tasks ([`crate::record_tasks`]).

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(feature = "host")]
use vti_common::error::AppError;
#[cfg(feature = "host")]
use vti_common::store::KeyspaceHandle;
#[cfg(feature = "host")]
use vti_specs_rooms::rooms::create::v0_3 as create_v3;
#[cfg(feature = "host")]
use vti_specs_rooms::rooms::info::v0_4 as info_v4;
#[cfg(feature = "host")]
use vti_specs_rooms::rooms::signal_delay::set::v0_1 as set_spec;

#[cfg(feature = "host")]
use crate::Room;
#[cfg(feature = "host")]
use crate::authz::{Action, AuthorizedAction};
#[cfg(feature = "host")]
use crate::blob_tasks::{Refusal, TaskResult, checked, declared, parse};
#[cfg(feature = "host")]
use crate::blobs::BlobHost;
#[cfg(feature = "host")]
use crate::record_retention::RecordRetention;
#[cfg(feature = "host")]
use crate::storage;

pub use crate::wire::{
    ROOMS_CREATE_V3_TYPE as CREATE_V3_TYPE, ROOMS_INFO_V4_TYPE as INFO_V4_TYPE,
    ROOMS_SIGNAL_DELAY_SET_TYPE as SET_TYPE,
};

/// A room's signal delay (`rooms/_shared/0.2` `SignalDelay`).
///
/// **Absent means [`SignalDelay::Randomised`]** — every room stored before this existed,
/// and every room created at `rooms/create` 0.2 — so an upgraded host needs no migration and
/// no room loses the wait it had.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum SignalDelay {
    /// The host waits a few seconds, at random, before a signal: its time does not mark one
    /// write exactly.
    #[default]
    Randomised,
    /// No wait of the host's own: for a room members use as a conversation.
    None,
}

impl SignalDelay {
    /// The wire value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Randomised => "randomised",
            Self::None => "none",
        }
    }

    /// Read one from the wire; anything but the schema's two values is refused.
    pub fn from_wire(value: &Value) -> Result<Self, String> {
        serde_json::from_value(value.clone())
            .map_err(|_| format!("`signalDelay` is `{value}`; it is `randomised` or `none`"))
    }

    /// Whether this is the default — what a stored room omits.
    pub fn is_randomised(&self) -> bool {
        matches!(self, Self::Randomised)
    }
}

impl std::fmt::Display for SignalDelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which signal delays a host's governance applies (`rooms/signal-delay/set/0.1` Host item
/// 2). A host that keeps the delay for every room it holds refuses `none` rather than
/// record a setting it would not apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignalDelayPolicy {
    /// Either setting, as the room's administrator chooses. The default.
    Either,
    /// Every room keeps the randomised delay; `none` is refused.
    AlwaysRandomised,
}

impl SignalDelayPolicy {
    /// Whether this governance applies `delay`.
    pub fn permits(&self, delay: SignalDelay) -> bool {
        match self {
            Self::Either => true,
            Self::AlwaysRandomised => delay.is_randomised(),
        }
    }
}

/// What a signal-delay change leaves in the host's audit trail (`rooms/signal-delay/set/0.1`
/// item 5): the setting replaced, the one recorded and the reason. The requester is the
/// host's to add, where the tier discloses one ([`crate::audit::for_operation`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalDelayAudit {
    /// The setting in force before.
    pub previous: SignalDelay,
    /// The setting now in force.
    pub recorded: SignalDelay,
    /// Why, as the administrator gave it.
    pub reason: String,
}

impl SignalDelayAudit {
    /// A JSON detail for the host's audit row.
    pub fn detail(&self) -> Value {
        json!({
            "previous": self.previous.as_str(),
            "signalDelay": self.recorded.as_str(),
            "reason": self.reason,
        })
    }
}

/// `rooms/signal-delay/set/0.1`, once the chain has been verified for `admin`.
///
/// Records the setting (item 3) and answers it with the one it replaced (item 4); a request
/// naming the setting already in force succeeds and changes nothing. `policy` refuses a
/// setting this host will not apply with `signalDelayNotPermitted`, recording nothing (item
/// 2). Changes nothing but the timing of signals (item 6): no watch is touched here.
///
/// Returns the response body and what to audit (item 5), which the host records with the
/// requester where the tier discloses one.
#[cfg(feature = "host")]
pub async fn set(
    files: &BlobHost,
    rooms: &KeyspaceHandle,
    room: &Room,
    authorized: &AuthorizedAction,
    payload: &Value,
    policy: SignalDelayPolicy,
    now: u64,
) -> Result<(Value, SignalDelayAudit), Refusal> {
    use set_spec::error_codes as codes;
    let req: set_spec::Payload = parse(payload)?;
    // Item 1: `admin`, the grant that decides the room's other terms.
    if authorized.action() != Action::Admin {
        return Err(Refusal::Internal(
            "rooms/signal-delay/set was dispatched without an admin chain".into(),
        ));
    }
    let wanted = SignalDelay::from_wire(&payload["signalDelay"]).map_err(Refusal::Malformed)?;
    if !policy.permits(wanted) {
        return Err(declared(
            codes::SIGNAL_DELAY_NOT_PERMITTED,
            format!(
                "this host keeps the randomised delay on every room's signals; it will not \
                 record `{wanted}`"
            ),
            None,
        ));
    }
    // Under the record-write lock: the room record is rewritten whole, and a write landing
    // between the read and the write must not be lost.
    let _lock = files.records_lock(&room.room_id).await;
    let previous = storage::set_signal_delay(rooms, &room.room_id, wanted, now)
        .await
        .map_err(Refusal::App)?;
    if previous != wanted {
        crate::observe::changed();
    }
    let body = json!({
        "roomId": room.room_id,
        "signalDelay": wanted.as_str(),
        "previous": previous.as_str(),
    });
    checked::<set_spec::Response>(body).map(|b| {
        (
            b,
            SignalDelayAudit {
                previous,
                recorded: wanted,
                reason: req.reason.to_string(),
            },
        )
    })
}

/// What a `rooms/create/0.3` asks for: the record retention (`None` when it states none),
/// the signal delay (`randomised` when absent), and the payload read as 0.1, which the
/// hosts' create path takes for everything else.
#[cfg(feature = "host")]
pub fn create_v3_parts(
    payload: &Value,
) -> Result<(Option<RecordRetention>, SignalDelay, Value), Refusal> {
    parse::<create_v3::Payload>(payload)?;
    let retention = match payload.get("recordRetention") {
        Some(v) => Some(RecordRetention::from_wire(v).map_err(Refusal::Malformed)?),
        None => None,
    };
    let delay = match payload.get("signalDelay") {
        Some(v) => SignalDelay::from_wire(v).map_err(Refusal::Malformed)?,
        None => SignalDelay::Randomised,
    };
    let mut v0_1 = payload.clone();
    if let Some(obj) = v0_1.as_object_mut() {
        obj.remove("recordRetention");
        obj.remove("signalDelay");
    }
    Ok((retention, delay, v0_1))
}

/// Refuse a create whose signal delay this host's governance will not apply, rather than
/// register the room under another (`rooms/create/0.3`: "**MUST** refuse the create rather
/// than record a different one").
#[cfg(feature = "host")]
pub fn create_v3_permitted(delay: SignalDelay, policy: SignalDelayPolicy) -> Result<(), Refusal> {
    if policy.permits(delay) {
        return Ok(());
    }
    // `rooms/create` declares no code of its own for this; the standard `permissionDenied`
    // says the host will not do what was asked.
    Err(Refusal::App(AppError::Forbidden(format!(
        "this host keeps the randomised delay on every room's signals; it will not register a \
         room with signalDelay `{delay}`"
    ))))
}

/// The 0.1 members of a `rooms/create` response, with what 0.3 echoes: the record retention
/// recorded (absent when none was) and the signal delay recorded, always present.
#[cfg(feature = "host")]
pub fn create_v3_response(
    response: impl serde::Serialize,
    recorded: Option<&RecordRetention>,
    delay: SignalDelay,
) -> TaskResult {
    let mut body =
        serde_json::to_value(response).map_err(|e| Refusal::App(AppError::Serialization(e)))?;
    if let Some(r) = recorded {
        body["recordRetention"] = r.to_wire();
    }
    body["signalDelay"] = json!(delay.as_str());
    checked::<create_v3::Response>(body)
}

/// `rooms/info/0.4`: 0.3's answer, and the signal delay the host applies to the room's
/// signals — always present, `randomised` for a room that never set one (item 8).
#[cfg(feature = "host")]
pub async fn info_v4(
    files: &BlobHost,
    room: &Room,
    authorized: &AuthorizedAction,
    payload: &Value,
) -> TaskResult {
    parse::<info_v4::Payload>(payload)?;
    let mut body = crate::blob_tasks::info_body(files, room, authorized).await?;
    if let Some(r) = room
        .record_retention
        .as_ref()
        .filter(|r| !r.is_empty() || r.ext.is_some())
    {
        body["recordRetention"] = r.to_wire();
    }
    if let Some(mark) = &room.last_prune {
        body["lastPrune"] = mark.to_wire();
    }
    body["signalDelay"] = json!(room.signal_delay.as_str());
    checked::<info_v4::Response>(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_is_randomised_and_the_wire_form_is_the_schemas() {
        assert_eq!(SignalDelay::default(), SignalDelay::Randomised);
        assert_eq!(
            SignalDelay::from_wire(&json!("none")).unwrap(),
            SignalDelay::None
        );
        assert_eq!(
            SignalDelay::from_wire(&json!("randomised")).unwrap(),
            SignalDelay::Randomised
        );
        assert!(SignalDelay::from_wire(&json!("randomized")).is_err());
        assert!(SignalDelay::from_wire(&json!(null)).is_err());
        assert_eq!(serde_json::to_value(SignalDelay::None).unwrap(), "none");
    }

    #[test]
    fn a_host_that_keeps_the_delay_refuses_none_only() {
        assert!(SignalDelayPolicy::AlwaysRandomised.permits(SignalDelay::Randomised));
        assert!(!SignalDelayPolicy::AlwaysRandomised.permits(SignalDelay::None));
        assert!(SignalDelayPolicy::Either.permits(SignalDelay::None));
    }

    #[test]
    #[cfg(feature = "host")]
    fn create_v3_takes_both_settings_apart() {
        let payload = json!({
            "roomId": "did:webvh:QmRoom:rooms.example:chat",
            "visibility": "attributed",
            "ownerDid": "did:key:z6MkOwner",
            "recordRetention": { "tombstoneDays": 7 },
            "signalDelay": "none",
        });
        let (retention, delay, v0_1) = create_v3_parts(&payload).unwrap();
        assert_eq!(retention.unwrap().tombstone_days, Some(7));
        assert_eq!(delay, SignalDelay::None);
        assert!(v0_1.get("signalDelay").is_none());
        assert!(v0_1.get("recordRetention").is_none());

        let mut plain = payload.clone();
        plain.as_object_mut().unwrap().remove("signalDelay");
        let (_, delay, _) = create_v3_parts(&plain).unwrap();
        assert_eq!(delay, SignalDelay::Randomised, "absent is randomised");

        let mut bad = payload;
        bad["signalDelay"] = json!("sometimes");
        assert!(create_v3_parts(&bad).is_err());
    }

    #[test]
    #[cfg(feature = "host")]
    fn the_create_response_always_echoes_the_delay() {
        let body = create_v3_response(
            json!({ "roomId": "did:webvh:QmRoom:rooms.example:chat", "epoch": 1 }),
            None,
            SignalDelay::Randomised,
        )
        .unwrap();
        assert_eq!(body["signalDelay"], "randomised");
    }
}
