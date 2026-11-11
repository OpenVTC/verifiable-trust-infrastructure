//! A member's read marker for a room, kept here so every one of their devices agrees on
//! what is unread — `rooms/keys/read-marker/set/0.1`, the notice to the member's other
//! watching clients, `rooms/keys/read-marker/moved/0.1`, and the list that returns it,
//! `rooms/keys/list/0.3` ([`super::room_label::handle_list_v0_3`]); trust-tasks-tf #1086.
//!
//! # Who may set one
//!
//! Exactly as for `rooms/keys/label/0.1`, for the same reasons:
//!
//! 1. **Capability**: [`Capability::RoomOpen`], as `rooms/keys/list`.
//! 2. **Not a delegate** (Recipient item 1): what an agent read is not what the member has
//!    seen — `permissionDenied`.
//! 3. **The member**: `member` must be a persona the caller may act as **and** hold group
//!    state for `roomId`. Both failures are one `notHeld` (item 2), decided before the
//!    stored marker is read.
//!
//! # The merge
//!
//! [`room_groups::set_read_marker`]: forward only — the greater `version`, then the later
//! `createdAt` as an instant, an absent one earliest — unless `rewind` (items 3–4). The
//! marker is never checked against the room or its host (item 5); `createdAt` is stored and
//! returned as received, so it is read from the payload as received, not from the generated
//! type (which reparses it).
//!
//! # Where a marker goes
//!
//! To the caller, through this response and `rooms/keys/list/0.3` with `includePersonal`;
//! and, when it moved, to the member's **other** clients holding a `rooms/keys/watch` on the
//! room as the member ([`send_moved`]) — and nowhere else (item 8). Neither its values nor
//! when it moved are logged or audited (item 9): this module writes no audit row and no log
//! line for a set, the dispatch spine names no read-marker set in its receipt log, keeps no
//! response for redelivery, and quotes no payload in a schema error
//! (`super::carries_personal_state`). It counts sets ([`MARKERS_SET_METRIC`]), which item
//! 9 allows.

use std::time::Duration;

use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use vti_common::acl::Capability;
use vti_common::error::AppError;
use vti_specs::rooms::keys::read_marker::set::v0_1 as set_spec;

use crate::auth::AuthClaims;
use crate::operations::{room_groups, room_member};
use crate::server::AppState;

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, malformed_request_response, parse_payload,
    reject_declared, reject_with, success_response,
};

/// How long a `moved` notice waits for further sets before it is sent: Producer item 3's
/// "a few seconds", so a member moving through a room on one device sends one document to
/// another, not a stream.
#[cfg(not(test))]
pub(crate) const MOVED_COALESCE: Duration = Duration::from_secs(3);
#[cfg(test)]
pub(crate) const MOVED_COALESCE: Duration = Duration::from_millis(50);

/// The counter of sets that moved a marker — the one thing about markers this VTA records
/// for its own operation (Recipient item 9): a total, with no room, member or time.
pub(crate) const MARKERS_SET_METRIC: &str = "room_read_markers_set_total";

/// `rooms/keys/read-marker/set/0.1`.
pub(super) async fn handle_set(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomOpen,
        "keeping a read marker for a room this VTA holds keys for",
    )
    .await
    {
        return r;
    }
    if let Err(r) = refuse_delegate(state, auth, &doc).await {
        return r;
    }
    let req: set_spec::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // Item 5: `createdAt` exactly as received — from the payload, not the generated type.
    let created_at = doc.payload["readMarker"]
        .get("createdAt")
        .and_then(Value::as_str)
        .map(str::to_string);
    let requested = match room_groups::ReadMarker::new(req.read_marker.version, created_at) {
        Ok(m) => m,
        Err(e) => return malformed_request_response(e.to_string()),
    };
    let rewind = req.rewind == Some(true);
    let room_id = req.room_id.as_str();
    let member_did = req.member.as_str();

    // Item 2: one answer for "no group state as this member" and "not a member you act as",
    // decided before the stored marker is read.
    let member = match room_member::acting_as(state, auth, room_id, Some(member_did)).await {
        Ok(Some(m)) => m,
        Ok(None) => return not_held(&doc),
        Err(e) => return app_error_to_reject(&doc, e),
    };

    let (marker, moved) = match room_groups::set_read_marker(
        &state.room_groups_ks,
        &member,
        &requested,
        rewind,
    )
    .await
    {
        Ok(room_groups::ReadMarkerOutcome::Applied { marker, moved }) => (marker, moved),
        // The group state went between the check above and the write.
        Ok(room_groups::ReadMarkerOutcome::NotHeld) => return not_held(&doc),
        Err(e) => return app_error_to_reject(&doc, e),
    };

    if moved {
        metrics::counter!(MARKERS_SET_METRIC).increment(1);
        // Item 6: the member's other watching clients, once the window closes.
        if state
            .room_key_watches
            .schedule_moved(room_id, member_did, &auth.did)
        {
            let state = state.clone();
            let (room_id, member_did) = (room_id.to_string(), member_did.to_string());
            tokio::spawn(async move {
                tokio::time::sleep(MOVED_COALESCE).await;
                if let Some(setter) = state.room_key_watches.take_moved(&room_id, &member_did) {
                    send_moved(&state, &room_id, &member_did, &setter).await;
                }
            });
        }
    }

    let payload = json!({
        "roomId": room_id,
        "member": member_did,
        "readMarker": marker,
        "moved": moved,
    });
    match serde_json::from_value::<set_spec::Response>(payload.clone()) {
        // The payload as built, not re-serialised from the generated type, so `createdAt`
        // goes back exactly as it was stored (item 5).
        Ok(_) => success_response(&doc, payload),
        Err(e) => app_error_to_reject(
            &doc,
            AppError::Internal(format!(
                "the read-marker response does not fit its schema: {e}"
            )),
        ),
    }
}

/// `rooms/keys/read-marker/set:notHeld`, in the one wording both of its causes share.
fn not_held(doc: &TrustTask<Value>) -> TrustTaskOutcome {
    reject_declared(
        doc,
        set_spec::error_codes::NOT_HELD,
        "No group state for this room is held for a member you act as.",
    )
}

/// Item 1: a delegate is refused with the standard `permissionDenied`. Being unable to
/// tell is not evidence of being the member, so a store error refuses too.
async fn refuse_delegate(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
) -> Result<(), TrustTaskOutcome> {
    let refuse = || {
        reject_with(
            doc,
            trust_tasks_rs::RejectReason::PermissionDenied {
                reason: "a read marker is the member's: what a delegate has read is not what \
                         the member has seen"
                    .into(),
            },
        )
    };
    match super::room_act::is_delegate(state, auth).await {
        Ok(false) => Ok(()),
        Ok(true) => Err(refuse()),
        Err(e) => {
            tracing::error!(error = %e, did = %auth.did, "could not read the caller's ACL entry; refusing");
            Err(refuse())
        }
    }
}

/// The clients `rooms/keys/read-marker/moved/0.1` goes to for `member`'s marker in
/// `room_id` (Producer item 1): each client holding an unlapsed watch on the room as the
/// member, other than `setter`, that may act as the member now — once each, with the room
/// and member as that client named them when it armed. Never a delegate.
pub(crate) async fn moved_recipients(
    state: &AppState,
    room_id: &str,
    member: &str,
    setter: &str,
) -> Result<Vec<(String, String, String)>, AppError> {
    let now = chrono::Utc::now().timestamp();
    let mut out: Vec<(String, String, String)> = Vec::new();
    for w in state.room_key_watches.all().await? {
        if w.room_id != room_id
            || w.member != member
            || w.lapsed(now)
            || w.caller == setter
            || out.iter().any(|(c, _, _)| *c == w.caller)
        {
            continue;
        }
        let Some(auth) = super::room_key_watch::standing_of(state, &w.caller).await? else {
            continue;
        };
        if room_member::acting_as(state, &auth, room_id, Some(member))
            .await?
            .is_none()
        {
            continue;
        }
        out.push((w.caller, w.room_id, w.member));
    }
    Ok(out)
}

/// The `rooms/keys/read-marker/moved/0.1` document for one client: the room, the member and
/// the marker in force — nothing about which client moved it, or when (Producer item 2).
pub(crate) fn moved_document(
    vta_did: Option<&str>,
    recipient: &str,
    room_id: &str,
    member: &str,
    marker: &room_groups::ReadMarker,
) -> Value {
    let mut doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": vta_sdk::trust_tasks::TASK_ROOMS_KEYS_READ_MARKER_MOVED_0_1,
        "recipient": recipient,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": {
            "roomId": room_id,
            "member": member,
            "readMarker": marker,
        },
    });
    if let Some(did) = vta_did {
        doc["issuer"] = json!(did);
    }
    doc
}

/// Send the marker now in force to the member's other watching clients, the way
/// `rooms/keys/changed` reaches a client (Producer item 4): signed, pushed once with a
/// deadline of one attempt's window, no doorbell (item 6). Best effort and silent — a queued
/// push is not a delivery (R1.1), a lost one costs the client nothing its next
/// `rooms/keys/list` does not restore, and a log line here would record when the member
/// read (`rooms/keys/read-marker/set/0.1` item 9). The watches are not touched (item 5).
pub(crate) async fn send_moved(state: &AppState, room_id: &str, member: &str, setter: &str) {
    let Ok(m) = room_groups::Member::new(room_id, member) else {
        return;
    };
    // The newest marker, never one since replaced; none when the state was discarded.
    let Ok(Some(marker)) = room_groups::read_marker(&state.room_groups_ks, &m).await else {
        return;
    };
    let Ok(recipients) = moved_recipients(state, room_id, member, setter).await else {
        return;
    };
    if recipients.is_empty() {
        return;
    }
    let vta_did = state.config.read().await.vta_did.clone();
    for (caller, room_id, member) in recipients {
        let mut doc = moved_document(vta_did.as_deref(), &caller, &room_id, &member, &marker);
        if !super::sign_outbound_request(state, &mut doc).await {
            return;
        }
        #[cfg(any(feature = "didcomm", feature = "tsp"))]
        let _ = super::step_up::push_to_device_with(
            state,
            &caller,
            &doc,
            super::room_key_watch::PASS_ON_DELIVER_BY,
            false,
        )
        .await;
    }
}

#[cfg(test)]
#[path = "room_read_marker_tests.rs"]
mod tests;
