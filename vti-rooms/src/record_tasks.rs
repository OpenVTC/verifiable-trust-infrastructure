//! The record-retention Trust Tasks, host-neutral: `rooms/records/prune/0.1`,
//! `rooms/records/retention/set/0.1`, and what `rooms/create/0.2`, `rooms/info/0.2` and
//! `rooms/records/list/0.3` add to their predecessors (trust-tasks-tf #868).
//!
//! Both hosts — `room-host` and the VTC — call in here once they hold the room, the
//! authenticated presenter and what the chain authorized, exactly as they do for the file
//! tasks ([`crate::blob_tasks`]). What comes back is a body that already reads as the task's
//! **generated** response type, or a [`Refusal`] in the task's declared codes. One mapping,
//! so the two hosts cannot answer one task two ways.

use serde_json::{Value, json};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
#[allow(deprecated)]
use vti_specs_rooms::rooms::create::v0_2 as create_v2;
use vti_specs_rooms::rooms::info::v0_3 as info_v3;
use vti_specs_rooms::rooms::records::list::v0_5 as list_v5;
use vti_specs_rooms::rooms::records::list::v0_6 as list_v6;
use vti_specs_rooms::rooms::records::list::v0_7 as list_v7;
use vti_specs_rooms::rooms::records::prune::v0_2 as prune_spec;
use vti_specs_rooms::rooms::records::retention::set::v0_1 as set_spec;

use crate::Room;
use crate::authz::{Action, AuthorizedAction};
use crate::blob_tasks::{Refusal, TaskResult, checked, declared, parse};
use crate::blobs::{BlobHost, ReadSnapshot};
use crate::record_retention::{PruneKind, RecordPrune, RecordRetention};
use crate::storage::{self, RecordOrder};

pub use crate::wire::{
    ROOMS_CREATE_V2_TYPE as CREATE_V2_TYPE, ROOMS_INFO_V3_TYPE as INFO_V3_TYPE,
    ROOMS_RECORDS_LIST_V5_TYPE as LIST_V5_TYPE, ROOMS_RECORDS_LIST_V6_TYPE as LIST_V6_TYPE,
    ROOMS_RECORDS_LIST_V7_TYPE as LIST_V7_TYPE, ROOMS_RECORDS_PRUNE_V2_TYPE as PRUNE_TYPE,
    ROOMS_RECORDS_RETENTION_SET_TYPE as RETENTION_SET_TYPE,
};

/// What a prune or a retention change leaves in the host's audit trail
/// (`rooms/records/prune/0.2` *The audit trail*; `retention/set/0.1` item 5): the mark, the
/// reason, the retention applied and the kinds asked — never a removed record's key or
/// anything it said. The requester is the host's to add, where the tier discloses one
/// ([`crate::audit::for_operation`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetentionAudit {
    /// A prune that removed records. A dry run, and a prune that removed nothing, leave none.
    Pruned {
        mark: RecordPrune,
        reason: String,
        retention: RecordRetention,
        kinds: Vec<PruneKind>,
        blobs_released: u64,
    },
    /// The record retention was replaced.
    RetentionSet {
        previous: Option<RecordRetention>,
        recorded: Option<RecordRetention>,
        reason: String,
    },
}

impl RetentionAudit {
    /// A JSON detail for the host's audit row: counts and rules, nothing a record said.
    pub fn detail(&self) -> Value {
        match self {
            Self::Pruned {
                mark,
                reason,
                retention,
                kinds,
                blobs_released,
            } => json!({
                "prune": mark.to_wire(),
                "reason": reason,
                "recordRetention": retention.to_wire(),
                "kinds": kinds.iter().map(PruneKind::as_str).collect::<Vec<_>>(),
                "blobsReleased": blobs_released,
            }),
            Self::RetentionSet {
                previous,
                recorded,
                reason,
            } => json!({
                "previous": RecordRetention::wire_of(previous.as_ref()),
                "recordRetention": RecordRetention::wire_of(recorded.as_ref()),
                "reason": reason,
            }),
        }
    }
}

/// The kinds a prune request names, from its JSON (a set: duplicates are refused by the
/// schema already).
fn kinds_of(payload: &Value) -> Vec<PruneKind> {
    payload["kinds"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|k| serde_json::from_value::<PruneKind>(k.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// `rooms/records/prune/0.2`, once the chain has been verified for `admin`. Its `prune`
/// names the mark's instant `prunedAt` (`rooms/_shared/0.2`).
///
/// Holds the record-write lock ([`BlobHost::records_lock`]) for the whole decision and
/// removal, so eligibility is decided over exactly the records it removes and no read sees
/// half of it. Returns the response body and, when records were removed, what to audit.
pub async fn prune(
    files: &BlobHost,
    rooms: &KeyspaceHandle,
    records: &KeyspaceHandle,
    room: &Room,
    authorized: &AuthorizedAction,
    payload: &Value,
    now: u64,
) -> Result<(Value, Option<RetentionAudit>), Refusal> {
    use prune_spec::error_codes as codes;
    let req: prune_spec::Payload = parse(payload)?;
    // Item 1: `admin`, never `curate` or `write`. The host verified the chain for the action
    // it was asked to; this is the check that it was asked for `admin`.
    if authorized.action() != Action::Admin {
        return Err(Refusal::Internal(
            "rooms/records/prune was dispatched without an admin chain".into(),
        ));
    }
    // Item 2: a prune is a write, and a lapsed room is read-only until renewed.
    if !room.lifecycle(now).accepts_writes() {
        return Err(declared(
            codes::ROOM_NOT_LIVE,
            format!(
                "room `{}` has lapsed; it is read-only until its owner renews it",
                room.room_id
            ),
            None,
        ));
    }
    let kinds = kinds_of(payload);
    let reason = req.reason.to_string();
    let dry_run = req.dry_run.unwrap_or(false);

    let lock = files.records_lock().await;
    // Re-read under the lock: the retention and the records are decided together.
    let room = storage::get_room(rooms, &room.room_id)
        .await
        .map_err(Refusal::App)?;
    let retention = room.record_retention.clone().unwrap_or_default();
    // Item 3: a request none of whose kinds the retention states a rule for is refused,
    // never answered `removed: 0`.
    if !kinds.iter().any(|k| retention.states(*k)) {
        let details = match &room.record_retention {
            Some(r) => json!({ "recordRetention": r.to_wire() }),
            None => json!({}),
        };
        return Err(declared(
            codes::NO_RETENTION,
            format!(
                "room `{}` states no record retention for {}: no record is eligible, and \
                 none ever was. Set one with rooms/records/retention/set.",
                room.room_id,
                kinds
                    .iter()
                    .map(PruneKind::as_str)
                    .collect::<Vec<_>>()
                    .join(" or ")
            ),
            Some(details),
        ));
    }

    let eligible = storage::eligible_records(records, &room.room_id, &retention, &kinds, now)
        .await
        .map_err(Refusal::App)?;
    let keys: Vec<String> = eligible.iter().map(|r| r.key.clone()).collect();
    let blobs_released = lock
        .released_by(&room.room_id, &keys)
        .await
        .map_err(Refusal::App)?;

    let mut body = json!({
        "roomId": room.room_id,
        "removed": keys.len(),
        "recordRetention": retention.to_wire(),
    });
    if blobs_released > 0 {
        body["blobsReleased"] = json!(blobs_released);
    }
    // Item 4: a dry run reports and changes nothing.
    if dry_run {
        body["dryRun"] = json!(true);
        return checked::<prune_spec::Response>(body).map(|b| (b, None));
    }
    if keys.is_empty() {
        // Nothing eligible: a success, and no version, no mark.
        return checked::<prune_spec::Response>(body).map(|b| (b, None));
    }

    let mark = storage::remove_pruned(rooms, records, &room.room_id, &keys, now)
        .await
        .map_err(Refusal::App)?;
    // Item 5: every blob a removed record named is released, as a retraction releases it.
    if let Err(e) = lock.release(&room.room_id, &keys).await {
        // The records are gone; only their blob references are not. Said loudly, because
        // usage now disagrees with the room.
        tracing::error!(error = %e, room = %room.room_id,
            "records pruned but their blobs were not released");
    }
    drop(lock);
    body["prune"] = mark.to_wire();
    crate::observe::changed();
    checked::<prune_spec::Response>(body).map(|b| {
        (
            b,
            Some(RetentionAudit::Pruned {
                mark,
                reason,
                retention,
                kinds,
                blobs_released,
            }),
        )
    })
}

/// `rooms/records/retention/set/0.1`, once the chain has been verified for `admin`.
///
/// Replaces the retention whole (item 4); `{}` clears it. Nothing is removed here (item 6).
/// `max_days`, where a host's governance sets one, refuses a longer retention with
/// `retentionNotPermitted` rather than recording a shorter one (item 3).
pub async fn retention_set(
    files: &BlobHost,
    rooms: &KeyspaceHandle,
    room: &Room,
    authorized: &AuthorizedAction,
    payload: &Value,
    max_days: Option<u32>,
    now: u64,
) -> Result<(Value, RetentionAudit), Refusal> {
    use set_spec::error_codes as codes;
    let req: set_spec::Payload = parse(payload)?;
    if authorized.action() != Action::Admin {
        return Err(Refusal::Internal(
            "rooms/records/retention/set was dispatched without an admin chain".into(),
        ));
    }
    // Read from the JSON as given, so `ext` is recorded exactly as sent.
    let wanted =
        RecordRetention::from_wire(&payload["recordRetention"]).map_err(Refusal::Malformed)?;
    let expected = match payload.get("expectedRetention") {
        Some(v) => Some(RecordRetention::from_wire(v).map_err(Refusal::Malformed)?),
        None => None,
    };
    if let Some(max) = max_days {
        for days in [wanted.tombstone_days, wanted.record_days]
            .into_iter()
            .flatten()
        {
            if days > max {
                return Err(declared(
                    codes::RETENTION_NOT_PERMITTED,
                    format!("this host keeps records for at most {max} days"),
                    None,
                ));
            }
        }
    }

    // Under the record-write lock, so a prune never decides eligibility under one retention
    // while this replaces it.
    let _lock = files.records_lock().await;
    let current = storage::get_room(rooms, &room.room_id)
        .await
        .map_err(Refusal::App)?;
    if let Some(expected) = &expected
        && !RecordRetention::same_as(Some(expected), current.record_retention.as_ref())
    {
        return Err(declared(
            codes::RETENTION_CONFLICT,
            "the record retention in force is not the one expected",
            Some(json!({
                "recordRetention": RecordRetention::wire_of(current.record_retention.as_ref())
            })),
        ));
    }
    let recorded = (!wanted.is_empty() || wanted.ext.is_some()).then_some(wanted);
    let previous = storage::set_record_retention(rooms, &room.room_id, recorded.clone(), now)
        .await
        .map_err(Refusal::App)?;
    crate::observe::changed();
    let body = json!({
        "roomId": room.room_id,
        "recordRetention": RecordRetention::wire_of(recorded.as_ref()),
        "previous": RecordRetention::wire_of(previous.as_ref()),
    });
    checked::<set_spec::Response>(body).map(|b| {
        (
            b,
            RetentionAudit::RetentionSet {
                previous,
                recorded,
                reason: req.reason.to_string(),
            },
        )
    })
}

/// The record retention a `rooms/create/0.2` asks for, after checking the payload is that
/// task's — `None` when it states none — and the payload read as 0.1, which the hosts'
/// create path takes for everything else.
#[allow(deprecated)] // still served beside create/0.3 (trust-tasks-tf #1084)
pub fn create_v2_parts(payload: &Value) -> Result<(Option<RecordRetention>, Value), Refusal> {
    parse::<create_v2::Payload>(payload)?;
    let retention = match payload.get("recordRetention") {
        Some(v) => Some(RecordRetention::from_wire(v).map_err(Refusal::Malformed)?),
        None => None,
    };
    let mut v0_1 = payload.clone();
    if let Some(obj) = v0_1.as_object_mut() {
        obj.remove("recordRetention");
    }
    Ok((retention, v0_1))
}

/// The 0.1 members of a `rooms/create` response, with what 0.2 echoes: the record retention the host
/// recorded, absent when none was.
#[allow(deprecated)] // still served beside create/0.3 (trust-tasks-tf #1084)
pub fn create_v2_response(
    response: impl serde::Serialize,
    recorded: Option<&RecordRetention>,
) -> TaskResult {
    let mut body =
        serde_json::to_value(response).map_err(|e| Refusal::App(AppError::Serialization(e)))?;
    if let Some(r) = recorded {
        body["recordRetention"] = r.to_wire();
    }
    checked::<create_v2::Response>(body)
}

/// `rooms/info/0.3`: 0.1's answer, and the record retention in force (omitted when there is
/// none) and the room's latest prune, its instant named `prunedAt` (`rooms/_shared/0.2`).
/// [`crate::signal_delay::info_v4`] adds the room's signal delay.
#[allow(deprecated)] // still served beside info/0.4 (trust-tasks-tf #1084)
pub async fn info_v3(
    files: &BlobHost,
    room: &Room,
    authorized: &AuthorizedAction,
    payload: &Value,
) -> TaskResult {
    parse::<info_v3::Payload>(payload)?;
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
    checked::<info_v3::Response>(body)
}

/// A listing as `rooms/records/list/0.5` answers: each record's `blobs`, the room's
/// `lastPrune` on every page once the room has been pruned (omitted otherwise), and the
/// continuation token named `nextCursor` (0.4), absent on the last page.
#[allow(deprecated)] // still served beside list/0.6, to readers that ask for it (trust-tasks-tf #1027)
pub async fn list_v5_response(
    snapshot: &ReadSnapshot<'_>,
    room: &Room,
    response: impl serde::Serialize,
) -> TaskResult {
    let body = list_v5_body(snapshot, room, response).await?;
    checked::<list_v5::Response>(body)
}

/// A listing as `rooms/records/list/0.6` answers: 0.5's, with rows that are
/// `RecordMetadataV3` — which the host builds with [`crate::Record::metadata_v3`] for the
/// room's tier — and `blobs` on each, as before.
#[allow(deprecated)] // still served beside list/0.7, to readers that ask for it (trust-tasks-tf #1088)
pub async fn list_v6_response(
    snapshot: &ReadSnapshot<'_>,
    room: &Room,
    response: impl serde::Serialize,
) -> TaskResult {
    let body = list_v5_body(snapshot, room, response).await?;
    checked::<list_v6::Response>(body)
}

/// A `rooms/records/list/0.7` request, checked against its schema, as the order it asks
/// for and the payload read as 0.1 — which the hosts' listing takes for everything else.
///
/// The cursor is checked here, against the order, so a cursor issued under the other order
/// (or not by this host) is the task's declared `invalidCursor` (*Order* item 5) and never
/// a page read in the wrong direction.
pub fn list_v7_parts(payload: &Value) -> Result<(RecordOrder, Value), Refusal> {
    let req: list_v7::Payload = parse(payload)?;
    let order = match req.order {
        Some(list_v7::ListOrder::NewestFirst) => RecordOrder::NewestFirst,
        Some(list_v7::ListOrder::OldestFirst) | None => RecordOrder::OldestFirst,
        Some(other) => {
            return Err(Refusal::Malformed(format!(
                "`order` {other:?} is not one this host lists in"
            )));
        }
    };
    if let Some(cursor) = payload.get("cursor").and_then(Value::as_str)
        && let Err(e) = storage::decode_cursor(cursor, order)
    {
        return Err(declared(
            list_v7::error_codes::INVALID_CURSOR,
            e.to_string(),
            None,
        ));
    }
    let mut v0_1 = crate::blob_tasks::as_v0_1(payload.clone());
    if let Some(obj) = v0_1.as_object_mut() {
        obj.remove("order");
    }
    Ok((order, v0_1))
}

/// A listing as `rooms/records/list/0.7` answers: 0.6's page, its rows in the order the
/// request asked for. The response shape is 0.6's; only its type moves.
pub async fn list_v7_response(
    snapshot: &ReadSnapshot<'_>,
    room: &Room,
    response: impl serde::Serialize,
) -> TaskResult {
    let body = list_v5_body(snapshot, room, response).await?;
    checked::<list_v7::Response>(body)
}

/// 0.5's page before its schema check, which 0.6 shares.
async fn list_v5_body(
    snapshot: &ReadSnapshot<'_>,
    room: &Room,
    response: impl serde::Serialize,
) -> Result<Value, Refusal> {
    let mut body = crate::blob_tasks::list_v2_body(snapshot, &room.room_id, response).await?;
    if let Some(obj) = body.as_object_mut()
        && let Some(cursor) = obj.remove("cursor")
        && !cursor.is_null()
    {
        obj.insert("nextCursor".into(), cursor);
    }
    if let Some(mark) = &room.last_prune {
        body["lastPrune"] = mark.to_wire();
    }
    Ok(body)
}

/// A `rooms/epoch/chain/0.1` response answered as 0.2: the same rungs (a host serves none at
/// or below the floor at either version), and the room's `epochFloor` on every response once
/// its chain has been pruned — whatever `fromEpoch` and `limit` named, `links` empty too
/// (trust-tasks-tf #869).
pub fn epoch_chain_v2_response(response: impl serde::Serialize, room: &Room) -> TaskResult {
    let mut body =
        serde_json::to_value(response).map_err(|e| Refusal::App(AppError::Serialization(e)))?;
    if let Some(floor) = room.epoch_floor {
        body["epochFloor"] = json!(floor);
    }
    checked::<vti_specs_rooms::rooms::epoch::chain::v0_2::Response>(body)
}

/// The 0.1 members of a `rooms/epoch/prune` response, answered as 0.2: and the room's epoch floor after the
/// prune, which 0.2 requires.
pub fn epoch_prune_v2_response(response: impl serde::Serialize, floor: u32) -> TaskResult {
    let mut body =
        serde_json::to_value(response).map_err(|e| Refusal::App(AppError::Serialization(e)))?;
    body["epochFloor"] = json!(floor);
    checked::<vti_specs_rooms::rooms::epoch::prune::v0_2::Response>(body)
}

/// Whether a task is one of these, which a host routes here.
pub fn is_retention_task(type_uri: &str) -> bool {
    [PRUNE_TYPE, RETENTION_SET_TYPE].contains(&type_uri)
}
