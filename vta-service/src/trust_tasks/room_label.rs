//! A member's own name for a room — `rooms/keys/label/0.1` — and the list that shows it
//! back, `rooms/keys/list/0.2` (trust-tasks-tf #806).
//!
//! A member holding several rooms can tell them apart only by names other parties gave
//! them — the room's profile, a community's offer label — or by their DIDs. A **personal
//! label** is the member's own: a name, a description, notes and tags, kept here beside
//! the group state for that room and member ([`room_groups::set_label`]), and shown to
//! nobody else.
//!
//! # Who may ask
//!
//! The entitlement is acting as the member — the question every `rooms/keys/*` task asks:
//!
//! 1. **Capability**: [`Capability::RoomOpen`], as `rooms/keys/list` — a caller that may
//!    not enumerate a principal's rooms has no business naming them.
//! 2. **Not a delegate** (recipient item 1): an agent holding a chain attenuated to it by
//!    `rooms/keys/present` was given narrow authority in one room, not the member's
//!    standing — `permissionDenied`, as `rooms/keys/act` answers it.
//! 3. **The member**: `member` must be a persona the caller may act as **and** hold group
//!    state for `roomId`. Both failures are one `notHeld` (item 2), decided before anything
//!    about the stored label is read, so a caller in one context cannot learn whether
//!    another persona holds the room.
//!
//! # Where a label goes
//!
//! To the caller that wrote it, through this response and `rooms/keys/list/0.2` with
//! `includePersonal`, and **nowhere else** (item 9): nothing that completes, signs or seals
//! for the member reads it. Its text is never logged or audited (item 10) — the audit row
//! says that a label for a room and member was written, and whether it changed — and the
//! dispatch spine neither logs it in a schema error nor keeps either response for
//! redelivery (`carries_personal_text`).

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::rooms::keys::{label::v0_1 as label_spec, list::v0_2 as list_spec};
use vti_common::acl::Capability;
use vti_common::error::AppError;

use crate::auth::AuthClaims;
use crate::operations::{room_groups, room_member};
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, malformed_request_response,
    parse_payload, reject_declared, reject_with, success_response,
};

/// `rooms/keys/label/0.1`.
pub(super) async fn handle_label(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomOpen,
        "naming a room this VTA holds keys for",
    )
    .await
    {
        return r;
    }
    if let Err(r) = refuse_delegate(state, auth, &doc).await {
        return r;
    }

    let req: label_spec::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let change = match change_of(&req) {
        Ok(c) => c,
        Err(reason) => return malformed_request_response(reason),
    };
    let room_id = req.room_id.as_str();
    let member_did = req.member.as_str();

    // Item 2: one answer for "no group state as this member" and "not a member you act as",
    // decided before the stored label is read.
    let member = match room_member::acting_as(state, auth, room_id, Some(member_did)).await {
        Ok(Some(m)) => m,
        Ok(None) => return not_held(&doc),
        Err(e) => return app_error_to_reject(&doc, e),
    };

    let outcome =
        match room_groups::set_label(&state.room_groups_ks, &member, &change, chrono::Utc::now())
            .await
        {
            Ok(o) => o,
            Err(e) => return app_error_to_reject(&doc, e),
        };
    let (label, changed) = match outcome {
        room_groups::LabelOutcome::Applied { label, changed } => (label, changed),
        // The group state went between the check above and the write.
        room_groups::LabelOutcome::NotHeld => return not_held(&doc),
    };

    // Item 10: that the label for this room and member was written, and whether it changed
    // — never what it says.
    audit_label(state, auth, room_id, member_did, changed).await;

    let mut payload = serde_json::json!({
        "roomId": room_id,
        "member": member_did,
        "changed": changed,
    });
    if let Some(label) = label {
        payload["personal"] = match serde_json::to_value(&label) {
            Ok(v) => v,
            Err(e) => return app_error_to_reject(&doc, AppError::Internal(e.to_string())),
        };
    }
    match serde_json::from_value::<label_spec::Response>(payload) {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(
            &doc,
            AppError::Internal(format!("the label response does not fit its schema: {e}")),
        ),
    }
}

/// The changes a request names, or why it names none (item 3).
///
/// The schema's `minProperties` counts `roomId` and `member`, so a request whose only other
/// member is `ext` passes it while naming no change — refused here. A detail both given and
/// removed is refused by the schema's `dependentSchemas` before this runs, and again here
/// for a caller that reached the handler some other way.
fn change_of(req: &label_spec::Payload) -> Result<room_groups::LabelChange, String> {
    fn detail<T>(
        given: Option<T>,
        remove: Option<bool>,
        name: &str,
    ) -> Result<room_groups::LabelDetail<T>, String> {
        match (given, remove) {
            (Some(_), Some(true)) => Err(format!(
                "`{name}` is both given and removed; a request does one or the other"
            )),
            (Some(v), _) => Ok(room_groups::LabelDetail::Set(v)),
            (None, Some(true)) => Ok(room_groups::LabelDetail::Remove),
            (None, _) => Ok(room_groups::LabelDetail::Unchanged),
        }
    }
    let change = room_groups::LabelChange {
        label: detail(
            req.label.as_ref().map(|v| v.to_string()),
            req.remove_label,
            "label",
        )?,
        description: detail(
            req.description.as_ref().map(|v| v.to_string()),
            req.remove_description,
            "description",
        )?,
        notes: detail(
            req.notes.as_ref().map(|v| v.to_string()),
            req.remove_notes,
            "notes",
        )?,
        tags: detail(
            req.tags
                .as_ref()
                .map(|t| t.iter().map(|tag| tag.to_string()).collect::<Vec<_>>()),
            req.remove_tags,
            "tags",
        )?,
    };
    let names_nothing = [
        matches!(change.label, room_groups::LabelDetail::Unchanged),
        matches!(change.description, room_groups::LabelDetail::Unchanged),
        matches!(change.notes, room_groups::LabelDetail::Unchanged),
        matches!(change.tags, room_groups::LabelDetail::Unchanged),
    ]
    .iter()
    .all(|u| *u);
    if names_nothing {
        return Err(
            "the request names no change: give a detail (`label`, `description`, `notes`, \
             `tags`) or remove one (`removeLabel`, …); `ext` is not a change"
                .into(),
        );
    }
    Ok(change)
}

/// `rooms/keys/label:notHeld`, in the one wording both of its causes share.
fn not_held(doc: &TrustTask<Value>) -> TrustTaskOutcome {
    reject_declared(
        doc,
        label_spec::error_codes::NOT_HELD,
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
                reason: "a label is the member's: a delegate acts in a room under its own \
                         identifier and does not read or write what the member calls it"
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

/// The audit row for a label write: the room, the member and whether it changed — never a
/// detail's text (item 10).
async fn audit_label(
    state: &AppState,
    auth: &AuthClaims,
    room_id: &str,
    member: &str,
    changed: bool,
) {
    let detail = format!(
        "member {member}; {}",
        if changed { "changed" } else { "unchanged" }
    );
    if let Err(e) = crate::audit::record_with_detail(
        &state.audit_sink,
        "rooms.keys.label",
        &auth.did,
        Some(room_id),
        "success",
        Some(TRANSPORT_TRUST_TASK),
        None,
        Some(&detail),
    )
    .await
    {
        tracing::error!(error = %e, "failed to record a room-label audit entry");
    }
}

/// `rooms/keys/list/0.2`.
///
/// 0.1's answer, with each entry naming its `member` (recipient item 1: one entry per room
/// and member the caller may act as) and — only when the request sets `includePersonal` —
/// the member's personal label (item 2). A delegate acts as no member, so it is answered
/// with no entries.
///
/// `ext["org.openvtc.rooms"].held` stays, index for index as on 0.1, for what the entry has
/// no member for: the trust context each member's key lives in, and the actions the room's
/// grant to it confers.
pub(super) async fn handle_list_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomOpen,
        "listing the rooms this VTA holds keys for",
    )
    .await
    {
        return r;
    }
    let req: list_spec::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let include_personal = req.include_personal == Some(true);

    let delegate = match super::room_act::is_delegate(state, auth).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, did = %auth.did, "could not read the caller's ACL entry; listing nothing");
            true
        }
    };
    let members = if delegate {
        Vec::new()
    } else {
        match room_member::held_by_caller(state, auth).await {
            Ok(m) => m,
            Err(e) => return app_error_to_reject(&doc, e),
        }
    };

    let mut rooms = Vec::with_capacity(members.len());
    for m in &members {
        let held = match room_groups::held_room(&state.room_groups_ks, m).await {
            Ok(r) => r,
            Err(e) => return app_error_to_reject(&doc, e),
        };
        let mut entry = serde_json::json!({
            "roomId": held.room_id,
            "member": m.persona(),
            "epoch": held.epoch,
            "earliestReadableEpoch": held.earliest_readable_epoch,
        });
        if include_personal {
            match room_groups::personal_label(&state.room_groups_ks, m).await {
                Ok(Some(label)) => {
                    entry["personal"] = match serde_json::to_value(&label) {
                        Ok(v) => v,
                        Err(e) => {
                            return app_error_to_reject(&doc, AppError::Internal(e.to_string()));
                        }
                    };
                }
                Ok(None) => {}
                Err(e) => return app_error_to_reject(&doc, e),
            }
        }
        rooms.push((entry, super::room_group::held_by(state, auth, m).await));
    }
    rooms.sort_by(|(a, _), (b, _)| {
        a["roomId"]
            .as_str()
            .cmp(&b["roomId"].as_str())
            .then_with(|| a["member"].as_str().cmp(&b["member"].as_str()))
    });
    let (rooms, held): (Vec<_>, Vec<_>) = rooms.into_iter().unzip();

    super::room_group::record(state, "rooms.keys.list", auth, "").await;
    let mut payload = serde_json::json!({ "rooms": rooms });
    if !held.is_empty() {
        payload["ext"] = serde_json::json!({ room_member::MEMBER_EXT: { "held": held } });
    }
    match serde_json::from_value::<list_spec::Response>(payload) {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(
            &doc,
            AppError::Internal(format!("the list response does not fit its schema: {e}")),
        ),
    }
}

#[cfg(test)]
#[path = "room_label_tests.rs"]
mod tests;
