//! `rooms/revocations/put/0.1` and `rooms/revocations/get/0.1`, host-neutral.
//!
//! Both hosts — `room-host` and the VTC — serve these, each with its own transport and
//! document handling, and call in here once they know the room and the authenticated
//! presenter. What comes back is a response body that already reads as the task's
//! generated response type, or a [`Refusal`] the host renders as it renders a room-file
//! refusal — so the two hosts cannot answer one list two ways.
//!
//! # The order of a delivery (`rooms/revocations/put`, conformance)
//!
//! 1. The room's gate, **exclusively**: from here until the list is stored, nothing is
//!    authorized on the room and nothing already authorized is still to commit
//!    (*Enforcement* item 3).
//! 2. The presentation, `admin`, against the list **already held** (item 1) — never the one
//!    being delivered, or the order of two deliveries would decide which one counts.
//! 3. The list: shape and `roomId`, then the room's signature (item 2, `listInvalid`).
//! 4. The tier (item 3, `entryNotPermitted`), then sequence and append-only (item 4).
//! 5. Stored durably, then answered with the head (item 5).
//!
//! A refusal at any step changes nothing.

use chrono::Utc;
use serde_json::{Value, json};
use trust_tasks_rs::specs::rooms::revocations::get::v0_1 as get_spec;
use trust_tasks_rs::specs::rooms::revocations::put::v0_1 as put_spec;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::Room;
use crate::authz::{self, AuthorizedAction, ChainVerifier, Gate};
use crate::blob_tasks::{Refusal, TaskResult};
use crate::revocation::{self, Acceptance, HeldList, ListRefusal, RevocationList, gate};
use crate::wire::AuthorityPresentation;

pub use crate::wire::{
    ROOMS_REVOCATIONS_GET_TYPE as GET_TYPE, ROOMS_REVOCATIONS_PUT_TYPE as PUT_TYPE,
};

/// A declared refusal of `rooms/revocations/put`.
fn put_refusal(e: ListRefusal) -> Refusal {
    use put_spec::error_codes as codes;
    let message = e.to_string();
    let (code, details) = match e {
        ListRefusal::ListInvalid(_) => (codes::LIST_INVALID, None),
        ListRefusal::EntryNotPermitted => (codes::ENTRY_NOT_PERMITTED, None),
        ListRefusal::Stale { held_sequence } => {
            (codes::STALE, Some(json!({ "heldSequence": held_sequence })))
        }
        ListRefusal::SequenceConflict => (codes::SEQUENCE_CONFLICT, None),
        ListRefusal::NotAppendOnly => (codes::NOT_APPEND_ONLY, None),
    };
    Refusal::Declared {
        code,
        message,
        details,
    }
}

/// The presentation a list task carries.
fn presentation(payload: &Value) -> Result<AuthorityPresentation, Refusal> {
    serde_json::from_value(payload["presentation"].clone())
        .map_err(|e| Refusal::Malformed(format!("presentation: {e}")))
}

/// `body`, once it reads as the generated response type `R`.
fn checked<R: serde::de::DeserializeOwned>(body: Value) -> TaskResult {
    match serde_json::from_value::<R>(body.clone()) {
        Ok(_) => Ok(body),
        Err(e) => Err(Refusal::Internal(format!(
            "this host built a response its specification refuses: {e}"
        ))),
    }
}

/// `rooms/revocations/put/0.1`: hold `payload.list` for `room` if the room signed it and it
/// moves the room's withdrawals forward.
///
/// Returns the response body and the authorization, which the host audits and then drops.
pub async fn put(
    room: &Room,
    presenter: &str,
    payload: &Value,
    verifier: &dyn ChainVerifier,
    revocations: &KeyspaceHandle,
) -> Result<(Value, AuthorizedAction), Refusal> {
    crate::blob_tasks::parse::<put_spec::Payload>(payload)?;
    if payload["roomId"].as_str() != Some(room.room_id.as_str()) {
        return Err(Refusal::Malformed(
            "`roomId` is not the room this request was routed to".into(),
        ));
    }
    let presentation = presentation(payload)?;
    let delivered = &payload["list"];

    // 1. Exclusively, from before the held list is read until the new one is stored.
    let exclusive = gate::write(&room.room_id).await;
    let held_row = revocation::held(revocations, &room.room_id)
        .await
        .map_err(Refusal::App)?;
    let held = authz::held_list(revocations, &room.room_id)
        .await
        .map_err(Refusal::App)?;

    // 2. `admin`, against the list already held.
    let now = Utc::now();
    let authorized = authz::authorize_list_admin(
        room,
        &presentation,
        presenter,
        now.timestamp().max(0) as u64,
        verifier,
        held.clone(),
        Gate::Exclusive(exclusive),
    )
    .await
    .map_err(Refusal::App)?;

    // 3. The room's statement, or nothing.
    let list = RevocationList::parse(delivered, &room.room_id).map_err(put_refusal)?;
    if let Err(e) = verifier.verify_room_signature(room, delivered).await {
        tracing::warn!(room = %room.room_id, error = %e, security_alert = true,
            "a revocation list delivered for this room is not the room's signature");
        return Err(put_refusal(ListRefusal::ListInvalid(
            "its proof does not verify with a key the room lists for assertionMethod".into(),
        )));
    }

    // 4. Tier, then sequence and append-only.
    let in_force_at = match list
        .accept(room.visibility, held.as_ref(), now)
        .map_err(|e| {
            if matches!(e, ListRefusal::SequenceConflict) {
                // Two lists at one sequence: the room's key is signing in two places. The
                // held list stays; the operator should hear of it.
                tracing::error!(room = %room.room_id, sequence = list.sequence(),
                    security_alert = true,
                    "the room has signed two different revocation lists at one sequence");
            }
            put_refusal(e)
        })? {
        Acceptance::Repeat => held_row.map(|h| h.in_force_at).unwrap_or(now),
        Acceptance::New => {
            // 5. Durably, before answering.
            revocation::store(
                revocations,
                &room.room_id,
                &HeldList {
                    list: delivered.clone(),
                    in_force_at: now,
                },
            )
            .await
            .map_err(Refusal::App)?;
            tracing::info!(room = %room.room_id, sequence = list.sequence(),
                "a revocation list is in force");
            now
        }
    };

    let body = checked::<put_spec::Response>(json!({
        "roomId": room.room_id,
        "head": list.head().to_wire(),
        "inForceAt": revocation::rfc3339(in_force_at),
    }))?;
    Ok((body, authorized))
}

/// `rooms/revocations/get/0.1`: the list this host holds for `room`, unaltered, or none.
pub async fn get(
    room: &Room,
    presenter: &str,
    payload: &Value,
    verifier: &dyn ChainVerifier,
    revocations: &KeyspaceHandle,
) -> Result<(Value, AuthorizedAction), Refusal> {
    crate::blob_tasks::parse::<get_spec::Payload>(payload)?;
    if payload["roomId"].as_str() != Some(room.room_id.as_str()) {
        return Err(Refusal::Malformed(
            "`roomId` is not the room this request was routed to".into(),
        ));
    }
    let presentation = presentation(payload)?;
    let shared = gate::read(&room.room_id).await;
    let held_row = revocation::held(revocations, &room.room_id)
        .await
        .map_err(Refusal::App)?;
    let held = authz::held_list(revocations, &room.room_id)
        .await
        .map_err(Refusal::App)?;
    let authorized = authz::authorize_list_admin(
        room,
        &presentation,
        presenter,
        Utc::now().timestamp().max(0) as u64,
        verifier,
        held,
        Gate::Shared(shared),
    )
    .await
    .map_err(Refusal::App)?;

    let mut body = json!({ "roomId": room.room_id });
    if let Some(h) = held_row {
        body["list"] = h.list;
        body["inForceAt"] = Value::String(revocation::rfc3339(h.in_force_at));
    }
    Ok((checked::<get_spec::Response>(body)?, authorized))
}

/// Whether a transfer opened under `presented` may take its next step — the steps of an
/// upload or a download that present nothing (`rooms/revocations/put`, *Enforcement*
/// item 3: "authorized again at each step that presents, and the step that commits it is
/// refused"; item 4: a host serving from storage it controls SHOULD refuse those too).
///
/// Returns the room's gate, shared, for the caller to hold until the step has committed.
/// A transfer opened before this host recorded what it was opened with (`presented` is
/// `None`) is refused while the room holds a list that withdraws anything.
pub async fn transfer_step(
    room: &Room,
    presented: Option<&revocation::Presented>,
    revocations: &KeyspaceHandle,
) -> Result<gate::Shared, AppError> {
    let shared = gate::read(&room.room_id).await;
    if let Some(list) = authz::held_list(revocations, &room.room_id).await? {
        let withdrawn = match presented {
            Some(p) => list.withdraws(room.visibility, p, Utc::now()),
            None => !list.entries().is_empty(),
        };
        if withdrawn {
            return Err(authz::withdrawn(&room.room_id));
        }
    }
    Ok(shared)
}

/// [`transfer_step`] for the transfer a document names (`uploadId` or `downloadId`): its
/// room and the credentials that opened it, held to the room's list.
///
/// For a step that presents nothing: an upload's `chunk` and `commit`, a download's
/// `chunk`. Not for `abort`, which gives everything back and is never worth refusing.
/// `Ok(None)` for a transfer this host does not hold — the task itself answers that.
pub async fn hold_transfer_step(
    files: &crate::blobs::BlobHost,
    rooms: &KeyspaceHandle,
    revocations: &KeyspaceHandle,
    payload: &Value,
) -> Result<Option<gate::Shared>, Refusal> {
    let Some(id) = payload["uploadId"]
        .as_str()
        .or_else(|| payload["downloadId"].as_str())
    else {
        return Ok(None);
    };
    let Some((room_id, presented)) = files.transfer_presented(id).await else {
        return Ok(None);
    };
    let room = match crate::storage::get_room(rooms, &room_id).await {
        Ok(r) => r,
        Err(AppError::NotFound(_)) => return Ok(None),
        Err(e) => return Err(Refusal::App(e)),
    };
    transfer_step(&room, presented.as_ref(), revocations)
        .await
        .map(Some)
        .map_err(Refusal::App)
}
