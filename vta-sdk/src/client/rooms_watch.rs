//! Watching rooms through the member's own VTA: `rooms/keys/watch/0.1` (trust-tasks-tf
//! #1040), and `rooms/keys/act/0.12` for a client that names an address of its own.
//!
//! [`VtaClient::room_watch`] asks the VTA to arm `rooms/watch` at one host for up to
//! [`ROOM_WATCH_MAX_ROOMS`] rooms, as the member, at addresses the VTA controls. Each signal
//! comes back to this client's own DID as a one-way `rooms/keys/changed/0.1` document from
//! the VTA, the way `task-consent/granted` does; read it with [`room_changed_signal`]. One
//! signal per arming: read the room, then arm again with the version read to.
//!
//! [`VtaClient::room_watch_live`] is `rooms/keys/watch/0.2` (trust-tasks-tf #1087): a
//! **live** watch for a conversation on screen — the VTA passes on every signal the host
//! sends, coalesced to at most one a second, until the watch ends. The host leases it for
//! at most 120 seconds; renew it with the same call about every 60 seconds while the room
//! is on screen, and cancel it ([`VtaClient::room_watch_cancel`]) when the screen closes.
//! Treat it as live only when the outcome says `live: true`. A room whose signal delay is
//! not `none` refuses it — `hostRefused` with `hostCode` `rooms/watch:liveNotPermitted` —
//! and the VTA never falls back to a one-shot watch on the client's behalf.
//!
//! A VTA that predates the task answers [`VtaError::UnsupportedTaskType`]. There is nothing
//! to fall back to without an address of the client's own: such a client polls the room,
//! or arms the host's `rooms/watch` itself through [`VtaClient::room_act_v0_12`] with an
//! address it receives at (`rooms/keys/act/0.12` Producer item 6 says which it may be, and binds the client).

use serde_json::{Value, json};

use super::VtaClient;
use crate::error::VtaError;
use crate::trust_tasks;

#[allow(deprecated)] // 0.1 is still sent for one-shot watches, beside 0.2 for live ones
use vti_specs::rooms::keys::watch::v0_1 as watch;
use vti_specs::rooms::keys::{
    act::v0_12 as act, changed::v0_1 as changed, watch::v0_2 as watch_v2,
};

/// `hostCode` of a host's refusal of a live watch on a room whose signal delay is not `none`
/// (`rooms/watch/0.2`).
pub const LIVE_NOT_PERMITTED: &str =
    vti_specs::rooms::watch::v0_2::error_codes::LIVE_NOT_PERMITTED.code;

/// How often a live watch is renewed while its room is on screen (`rooms/keys/watch/0.2`
/// Producer item 6: about every 60 seconds, inside the host's lease of at most 120).
pub const LIVE_RENEW_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// The most rooms one `rooms/keys/watch/0.1` request names.
pub const ROOM_WATCH_MAX_ROOMS: usize = 64;

/// Round-trip timeout (seconds) for a watch: the VTA arms each room at the host in turn,
/// up to 64 of them.
const ROOM_WATCH_TIMEOUT: u64 = 120;

/// Completing one request is local work at the VTA.
const ROOM_ACT_TIMEOUT: u64 = 30;

/// One room to watch, with the highest version the client has read it to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomWatch {
    /// The room.
    pub room_id: String,
    /// The highest version read; `None` takes the room's latest when the host arms it.
    pub since_version: Option<u64>,
}

impl VtaClient {
    /// `rooms/keys/watch/0.1` — arm (or re-arm) a watch on each of `rooms` at `host`, as
    /// `member`, which must be one of the members `rooms/keys/list` says this client reads
    /// the rooms as. `lease_seconds` (60 to 2 592 000) is how long each lasts if it does not
    /// fire; `None` is the host's default. One outcome per room, in order.
    #[allow(deprecated)] // one-shot watches are still sent as 0.1
    pub async fn room_watch(
        &self,
        member: &str,
        host: &str,
        rooms: &[RoomWatch],
        lease_seconds: Option<u64>,
    ) -> Result<watch::Response, VtaError> {
        let rooms: Vec<Value> = rooms
            .iter()
            .map(|r| {
                let mut room = json!({ "roomId": r.room_id });
                if let Some(v) = r.since_version {
                    room["sinceVersion"] = json!(v);
                }
                room
            })
            .collect();
        let mut payload = json!({ "member": member, "host": host, "rooms": rooms });
        if let Some(l) = lease_seconds {
            payload["leaseSeconds"] = json!(l);
        }
        self.send_room_watch(payload).await
    }

    /// `rooms/keys/watch/0.2` with `live: true` — arm, or renew, a **live** watch on each of
    /// `rooms` at `host` as `member`: every signal the host sends is passed on, until the
    /// watch ends. Renew with the same call about every [`LIVE_RENEW_EVERY`]; a room's
    /// `sinceVersion` may be `None` on a renewal, which keeps the watch's watermark. A
    /// room's outcome is live only when it says `live: true`.
    pub async fn room_watch_live(
        &self,
        member: &str,
        host: &str,
        rooms: &[RoomWatch],
        lease_seconds: Option<u64>,
    ) -> Result<watch_v2::Response, VtaError> {
        let rooms: Vec<Value> = rooms
            .iter()
            .map(|r| {
                let mut room = json!({ "roomId": r.room_id });
                if let Some(v) = r.since_version {
                    room["sinceVersion"] = json!(v);
                }
                room
            })
            .collect();
        let mut payload = json!({ "member": member, "host": host, "rooms": rooms, "live": true });
        if let Some(l) = lease_seconds {
            payload["leaseSeconds"] = json!(l);
        }
        check_rooms(&payload)?;
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_WATCH_0_2,
                payload,
                ROOM_WATCH_TIMEOUT,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| {
            VtaError::Protocol(format!(
                "rooms/keys/watch/0.2 response does not match its schema: {e}"
            ))
        })
    }

    /// `rooms/keys/watch/0.1` with `cancel` — end the watches on `rooms` at `host` as
    /// `member`. A room with no watch answers `armed: false`, so a retry is harmless.
    #[allow(deprecated)] // one-shot watches are still sent as 0.1
    pub async fn room_watch_cancel(
        &self,
        member: &str,
        host: &str,
        rooms: &[&str],
    ) -> Result<watch::Response, VtaError> {
        let rooms: Vec<Value> = rooms.iter().map(|r| json!({ "roomId": r })).collect();
        self.send_room_watch(
            json!({ "member": member, "host": host, "rooms": rooms, "cancel": true }),
        )
        .await
    }

    #[allow(deprecated)] // one-shot watches are still sent as 0.1
    async fn send_room_watch(&self, payload: Value) -> Result<watch::Response, VtaError> {
        check_rooms(&payload)?;
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_WATCH_0_1,
                payload,
                ROOM_WATCH_TIMEOUT,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| {
            VtaError::Protocol(format!(
                "rooms/keys/watch response does not match its schema: {e}"
            ))
        })
    }

    /// `rooms/keys/act/0.12` — [`VtaClient::room_act_v0_11`], whose table adds
    /// `rooms/watch/0.1` (`read`). Build `document` with [`unsigned_room_request_v0_12`]. A
    /// watch's `address` must be a DID this client receives at and uses for watches only —
    /// never the identifier it authenticates to the VTA with, the VTA's DID or the
    /// member's (Producer item 6). That rule is the caller's to keep: the VTA completes the
    /// request without reading, checking or changing the address (Recipient item 6). A VTA
    /// that does not serve 0.12
    /// answers [`VtaError::UnsupportedTaskType`].
    pub async fn room_act_v0_12(
        &self,
        document: &act::UnsignedRoomRequest,
    ) -> Result<act::Response, VtaError> {
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_ACT_0_12,
                json!({ "document": document }),
                ROOM_ACT_TIMEOUT,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| {
            VtaError::Protocol(format!(
                "rooms/keys/act response does not match its schema: {e}"
            ))
        })
    }
}

fn check_rooms(payload: &Value) -> Result<(), VtaError> {
    let rooms = payload["rooms"].as_array().map_or(0, Vec::len);
    if rooms == 0 || rooms > ROOM_WATCH_MAX_ROOMS {
        return Err(VtaError::Validation(format!(
            "a watch names 1 to {ROOM_WATCH_MAX_ROOMS} rooms at one host, not {rooms}"
        )));
    }
    Ok(())
}

/// [`super::unsigned_room_request`], as `rooms/keys/act/0.12` takes it.
pub fn unsigned_room_request_v0_12(
    type_uri: &str,
    host: &str,
    issuer: Option<&str>,
    payload: Value,
) -> Result<act::UnsignedRoomRequest, VtaError> {
    let base = super::unsigned_room_request(type_uri, host, issuer, payload)?;
    serde_json::from_value(serde_json::to_value(base)?)
        .map_err(|e| VtaError::Validation(format!("not a room request this can complete: {e}")))
}

/// A `rooms/keys/changed/0.1` document this client received, read as the signal it is — or
/// `None` for anything else. The caller acts on it only when its `issuer` is its own VTA and
/// it names a watch the caller armed (the same `member`, `host` and `roomId`), and only by
/// reading the room (Consumer items 1 and 2).
pub fn room_changed_signal(document: &Value) -> Option<changed::Payload> {
    let type_uri = document.get("type")?.as_str()?;
    if type_uri.split('#').next() != Some(trust_tasks::TASK_ROOMS_KEYS_CHANGED_0_1) {
        return None;
    }
    serde_json::from_value(document.get("payload")?.clone()).ok()
}

/// A `rooms/keys/read-marker/moved/0.1` document this client received — the member's read
/// marker for a room moved on another of their devices — or `None` for anything else. The
/// caller acts on it only when its `issuer` is its own VTA and it names a room and member
/// the caller watches through that VTA (Consumer item 1): it takes the marker as the one in
/// force, whether further on or behind, recounts unread, and clears notifications at or
/// before it. It is not a signal that the room changed, and does not touch the watch.
pub fn room_read_marker_moved(
    document: &Value,
) -> Option<vti_specs::rooms::keys::read_marker::moved::v0_1::Payload> {
    let type_uri = document.get("type")?.as_str()?;
    if type_uri.split('#').next() != Some(trust_tasks::TASK_ROOMS_KEYS_READ_MARKER_MOVED_0_1) {
        return None;
    }
    serde_json::from_value(document.get("payload")?.clone()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_moved_notice_is_read_only_from_its_own_type() {
        let doc = json!({
            "type": trust_tasks::TASK_ROOMS_KEYS_READ_MARKER_MOVED_0_1,
            "payload": {
                "roomId": "did:example:room",
                "member": "did:example:member",
                "readMarker": { "version": 415, "createdAt": "2027-02-01T10:14:02Z" }
            }
        });
        let m = room_read_marker_moved(&doc).expect("a notice");
        assert_eq!(m.read_marker.version, 415);
        let mut other = doc.clone();
        other["type"] = json!(trust_tasks::TASK_ROOMS_KEYS_CHANGED_0_1);
        assert!(room_read_marker_moved(&other).is_none());
        let mut extra = doc;
        extra["payload"]["setBy"] = json!("did:example:phone");
        assert!(
            room_read_marker_moved(&extra).is_none(),
            "the schema is closed: nothing says which device moved it"
        );
    }

    #[test]
    fn a_signal_is_read_only_from_its_own_type() {
        let doc = json!({
            "type": trust_tasks::TASK_ROOMS_KEYS_CHANGED_0_1,
            "payload": {
                "roomId": "did:example:room",
                "member": "did:example:member",
                "host": "did:example:host",
                "latestVersion": 415
            }
        });
        let s = room_changed_signal(&doc).expect("a signal");
        assert_eq!(s.latest_version.get(), 415);
        let mut other = doc.clone();
        other["type"] = json!(trust_tasks::TASK_ROOMS_CHANGED_0_1);
        assert!(room_changed_signal(&other).is_none());
        let mut extra = doc;
        extra["payload"]["address"] = json!("did:example:address");
        assert!(
            room_changed_signal(&extra).is_none(),
            "the schema is closed: an address never rides a pass-on"
        );
    }

    #[test]
    fn an_act_0_12_document_carries_a_watch() {
        let d = unsigned_room_request_v0_12(
            "https://trusttasks.org/spec/rooms/watch/0.1",
            "did:example:host",
            None,
            json!({ "roomId": "did:example:room", "address": "did:example:address" }),
        )
        .unwrap();
        let v = serde_json::to_value(d).unwrap();
        assert_eq!(v["payload"]["address"], "did:example:address");
    }
}
