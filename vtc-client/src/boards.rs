//! Community boards: the `vtc/boards/*/0.1` tasks (VTI-BRD-001 – 093).
//!
//! Members propose ideas and leave notes; a facilitator accepts, declines and merges ideas
//! (accepting opens the idea's election from the board's template), selects among them once
//! their elections are tallied, and hides notes. Voting itself is not a board task: it is the
//! idea's election, through [`crate::elections`] and the member's own VTA.
//!
//! The methods here send as every `acl/*` call does ([`crate::acl`]), signed with a
//! [`HolderKey`] or over the client's session — what an operator's tool (`cnm`) holds. A member
//! whose key lives in their VTA has the VTA sign the document as them
//! (`vault/sign-trust-task`) and sends it with [`VtcClient::send_signed_document`]; build its
//! payload with [`checked`] so it is refused here, not by the community, when out of schema.
//!
//! Requests are validated against the published schema before they are sent, and replies are
//! decoded into the generated `Response` types.

use serde_json::{Value, json};
use trust_tasks_rs::validate::ValidatedPayload;

use crate::{HolderKey, VtcClient, VtcError};

/// The generated wire types, re-exported so a caller names the reply types without depending
/// on `trust-tasks-rs` itself.
pub use vti_specs::vtc::boards::{
    create::v0_1 as create,
    delete::v0_1 as delete,
    facilitators::{
        add::v0_1 as facilitators_add, list::v0_1 as facilitators_list,
        remove::v0_1 as facilitators_remove,
    },
    ideas::{
        decide::v0_1 as ideas_decide, propose::v0_1 as ideas_propose, select::v0_1 as ideas_select,
        update::v0_1 as ideas_update, withdraw::v0_1 as ideas_withdraw,
    },
    list::v0_1 as list,
    notes::{
        add::v0_1 as notes_add, hide::v0_1 as notes_hide, list::v0_1 as notes_list,
        withdraw::v0_1 as notes_withdraw,
    },
    show::v0_1 as show,
    update::v0_1 as update,
};

/// The Type URI of each task, read off the generated payloads.
pub mod task {
    use trust_tasks_rs::Payload;

    pub const CREATE: &str = <super::create::Payload as Payload>::TYPE_URI;
    pub const UPDATE: &str = <super::update::Payload as Payload>::TYPE_URI;
    pub const DELETE: &str = <super::delete::Payload as Payload>::TYPE_URI;
    pub const LIST: &str = <super::list::Payload as Payload>::TYPE_URI;
    pub const SHOW: &str = <super::show::Payload as Payload>::TYPE_URI;
    pub const IDEAS_PROPOSE: &str = <super::ideas_propose::Payload as Payload>::TYPE_URI;
    pub const IDEAS_UPDATE: &str = <super::ideas_update::Payload as Payload>::TYPE_URI;
    pub const IDEAS_WITHDRAW: &str = <super::ideas_withdraw::Payload as Payload>::TYPE_URI;
    pub const IDEAS_DECIDE: &str = <super::ideas_decide::Payload as Payload>::TYPE_URI;
    pub const IDEAS_SELECT: &str = <super::ideas_select::Payload as Payload>::TYPE_URI;
    pub const NOTES_ADD: &str = <super::notes_add::Payload as Payload>::TYPE_URI;
    pub const NOTES_LIST: &str = <super::notes_list::Payload as Payload>::TYPE_URI;
    pub const NOTES_WITHDRAW: &str = <super::notes_withdraw::Payload as Payload>::TYPE_URI;
    pub const NOTES_HIDE: &str = <super::notes_hide::Payload as Payload>::TYPE_URI;
    pub const FACILITATORS_ADD: &str = <super::facilitators_add::Payload as Payload>::TYPE_URI;
    pub const FACILITATORS_REMOVE: &str =
        <super::facilitators_remove::Payload as Payload>::TYPE_URI;
    pub const FACILITATORS_LIST: &str = <super::facilitators_list::Payload as Payload>::TYPE_URI;
}

/// `payload` for `type_uri`, once it validates against that task's published schema.
///
/// # Errors
/// [`VtcError::InvalidPayload`] for a payload out of schema, or a Type URI that is not one of
/// the board tasks.
pub fn checked(type_uri: &str, payload: Value) -> Result<Value, VtcError> {
    fn v<P: ValidatedPayload>(p: &Value) -> Result<(), VtcError> {
        P::validate_value(p).map_err(|e| VtcError::InvalidPayload(e.to_string()))
    }
    match type_uri {
        task::CREATE => v::<create::Payload>(&payload)?,
        task::UPDATE => v::<update::Payload>(&payload)?,
        task::LIST => v::<list::Payload>(&payload)?,
        task::SHOW => v::<show::Payload>(&payload)?,
        task::IDEAS_PROPOSE => v::<ideas_propose::Payload>(&payload)?,
        task::IDEAS_UPDATE => v::<ideas_update::Payload>(&payload)?,
        task::IDEAS_WITHDRAW => v::<ideas_withdraw::Payload>(&payload)?,
        task::IDEAS_DECIDE => v::<ideas_decide::Payload>(&payload)?,
        task::IDEAS_SELECT => v::<ideas_select::Payload>(&payload)?,
        task::NOTES_ADD => v::<notes_add::Payload>(&payload)?,
        task::NOTES_LIST => v::<notes_list::Payload>(&payload)?,
        task::NOTES_WITHDRAW => v::<notes_withdraw::Payload>(&payload)?,
        task::NOTES_HIDE => v::<notes_hide::Payload>(&payload)?,
        task::DELETE => v::<delete::Payload>(&payload)?,
        task::FACILITATORS_ADD => v::<facilitators_add::Payload>(&payload)?,
        task::FACILITATORS_REMOVE => v::<facilitators_remove::Payload>(&payload)?,
        task::FACILITATORS_LIST => v::<facilitators_list::Payload>(&payload)?,
        other => {
            return Err(VtcError::InvalidPayload(format!(
                "{other} is not a vtc/boards task"
            )));
        }
    }
    Ok(payload)
}

/// The error codes `type_uri` declares, for decoding a refusal.
#[must_use]
pub fn declared(type_uri: &str) -> &'static [trust_tasks_rs::DeclaredErrorCode] {
    match type_uri {
        task::CREATE => create::ERROR_CODES,
        task::UPDATE => update::ERROR_CODES,
        task::DELETE => delete::ERROR_CODES,
        task::LIST => list::ERROR_CODES,
        task::FACILITATORS_ADD => facilitators_add::ERROR_CODES,
        task::FACILITATORS_REMOVE => facilitators_remove::ERROR_CODES,
        task::FACILITATORS_LIST => facilitators_list::ERROR_CODES,
        task::SHOW => show::ERROR_CODES,
        task::IDEAS_PROPOSE => ideas_propose::ERROR_CODES,
        task::IDEAS_UPDATE => ideas_update::ERROR_CODES,
        task::IDEAS_WITHDRAW => ideas_withdraw::ERROR_CODES,
        task::IDEAS_DECIDE => ideas_decide::ERROR_CODES,
        task::IDEAS_SELECT => ideas_select::ERROR_CODES,
        task::NOTES_ADD => notes_add::ERROR_CODES,
        task::NOTES_LIST => notes_list::ERROR_CODES,
        task::NOTES_WITHDRAW => notes_withdraw::ERROR_CODES,
        task::NOTES_HIDE => notes_hide::ERROR_CODES,
        _ => &[],
    }
}

/// `{ cursor?, limit? }` merged into `body`.
fn paged(mut body: Value, cursor: Option<&str>, limit: Option<u32>) -> Value {
    if let Some(c) = cursor {
        body["cursor"] = json!(c);
    }
    if let Some(l) = limit {
        body["limit"] = json!(l);
    }
    body
}

impl VtcClient {
    /// One board task, checked against its schema, signed with `key` (or over the session) and
    /// decoded into `R`.
    async fn board_task<R: serde::de::DeserializeOwned>(
        &self,
        type_uri: &str,
        payload: Value,
        key: &HolderKey,
    ) -> Result<R, VtcError> {
        let payload = checked(type_uri, payload)?;
        self.acl_task(type_uri, payload, key, declared(type_uri))
            .await
    }

    /// `vtc/boards/create/0.1` — a board from `body` (title, audience, windows, template, …).
    /// Takes `vtc.boards.manage` and `vtc.elections.manage`, both unqualified (VTI-BRD-002).
    ///
    /// # Errors
    /// [`VtcError::InvalidPayload`] out of schema; the VTC's refusal otherwise
    /// (`templateInvalid`, `ballotBoxNotTrusted`, `scheduleInvalid`, …).
    pub async fn boards_create(
        &self,
        body: Value,
        key: &HolderKey,
    ) -> Result<create::Response, VtcError> {
        self.board_task(task::CREATE, body, key).await
    }

    /// `vtc/boards/update/0.1` — change a board, or close or archive it (`status`).
    ///
    /// # Errors
    /// As [`Self::boards_create`].
    pub async fn boards_update(
        &self,
        body: Value,
        key: &HolderKey,
    ) -> Result<update::Response, VtcError> {
        self.board_task(task::UPDATE, body, key).await
    }

    /// `vtc/boards/delete/0.1` — delete a closed board whose voting has ended: its ideas, notes
    /// and each election's content go, each election keeping a tombstone for the community's
    /// retention (VTI-BRD-007, VTI-BRD-008). Takes `vtc.boards.manage` unqualified and a step-up
    /// bound to this one request; without the gesture the refusal carries `stepUpRequest`.
    ///
    /// # Errors
    /// [`VtcError::InvalidPayload`] out of schema; the VTC's refusal otherwise (`notClosed`,
    /// `electionsRunning`, `notFound`, `permissionDenied`).
    pub async fn boards_delete(
        &self,
        board_id: &str,
        reason: &str,
        key: &HolderKey,
    ) -> Result<delete::Response, VtcError> {
        self.board_task(
            task::DELETE,
            json!({ "boardId": board_id, "reason": reason }),
            key,
        )
        .await
    }

    /// `vtc/boards/facilitators/add/0.1` — appoint the active member `entry_id` a facilitator
    /// of `board_id` (VTI-BRD-090): `vtc.boards.manage` qualified to that board, written on their
    /// entry and delegated by the signer, who must facilitate the board themselves.
    ///
    /// # Errors
    /// [`VtcError::InvalidPayload`] out of schema; the VTC's refusal otherwise (`notFound`,
    /// `entryNotFound`, `alreadyFacilitator`, `permissionDenied`).
    pub async fn boards_facilitators_add(
        &self,
        board_id: &str,
        entry_id: &str,
        reason: Option<&str>,
        key: &HolderKey,
    ) -> Result<facilitators_add::Response, VtcError> {
        let mut body = json!({ "boardId": board_id, "entryId": entry_id });
        if let Some(r) = reason {
            body["reason"] = json!(r);
        }
        self.board_task(task::FACILITATORS_ADD, body, key).await
    }

    /// `vtc/boards/facilitators/remove/0.1` — end `entry_id`'s appointment to facilitate
    /// `board_id`: one's own, or anyone's with `vtc.boards.manage` unqualified (VTI-BRD-091).
    ///
    /// # Errors
    /// [`VtcError::InvalidPayload`] out of schema; the VTC's refusal otherwise (`notFound`,
    /// `notFacilitator`, `permissionDenied`).
    pub async fn boards_facilitators_remove(
        &self,
        board_id: &str,
        entry_id: &str,
        reason: Option<&str>,
        key: &HolderKey,
    ) -> Result<facilitators_remove::Response, VtcError> {
        let mut body = json!({ "boardId": board_id, "entryId": entry_id });
        if let Some(r) = reason {
            body["reason"] = json!(r);
        }
        self.board_task(task::FACILITATORS_REMOVE, body, key).await
    }

    /// `vtc/boards/facilitators/list/0.1` — who is appointed to facilitate `board_id`, by entry,
    /// with when, by whom, and any review under way (VTI-BRD-093).
    ///
    /// # Errors
    /// The VTC's refusal (`notFound`, `permissionDenied`).
    pub async fn boards_facilitators_list(
        &self,
        board_id: &str,
        key: &HolderKey,
    ) -> Result<facilitators_list::Response, VtcError> {
        self.board_task(task::FACILITATORS_LIST, json!({ "boardId": board_id }), key)
            .await
    }

    /// `vtc/boards/list/0.1` — the boards the caller may see.
    ///
    /// # Errors
    /// The VTC's refusal.
    pub async fn boards_list(
        &self,
        status: Option<&str>,
        cursor: Option<&str>,
        limit: Option<u32>,
        key: &HolderKey,
    ) -> Result<list::Response, VtcError> {
        let mut body = json!({});
        if let Some(s) = status {
            body["status"] = json!(s);
        }
        self.board_task(task::LIST, paged(body, cursor, limit), key)
            .await
    }

    /// `vtc/boards/show/0.1` — one board and a page of its ideas, optionally only those in
    /// `states`.
    ///
    /// # Errors
    /// `notFound` for a board the caller may not see; the VTC's refusal otherwise.
    pub async fn boards_show(
        &self,
        board_id: &str,
        states: &[&str],
        cursor: Option<&str>,
        limit: Option<u32>,
        key: &HolderKey,
    ) -> Result<show::Response, VtcError> {
        let mut body = json!({ "boardId": board_id });
        if !states.is_empty() {
            body["state"] = json!(states);
        }
        self.board_task(task::SHOW, paged(body, cursor, limit), key)
            .await
    }

    /// `vtc/boards/ideas/decide/0.1` — `accept` (opens the idea's election), `decline` (with a
    /// reason), `merge` (into `merge_into`) or `reopen`.
    ///
    /// # Errors
    /// The VTC's refusal (`stateInvalid`, `ownIdea`, `electionRefused`, …).
    pub async fn boards_decide(
        &self,
        idea_id: &str,
        decision: &str,
        reason: Option<&str>,
        merge_into: Option<&str>,
        key: &HolderKey,
    ) -> Result<ideas_decide::Response, VtcError> {
        let mut body = json!({ "ideaId": idea_id, "decision": decision });
        if let Some(r) = reason {
            body["reason"] = json!(r);
        }
        if let Some(m) = merge_into {
            body["mergeInto"] = json!(m);
        }
        self.board_task(task::IDEAS_DECIDE, body, key).await
    }

    /// `vtc/boards/ideas/select/0.1` — `selected` (optionally into `slot_id`) or `notSelected`,
    /// once the idea's election is tallied.
    ///
    /// # Errors
    /// The VTC's refusal (`notTallied`, `slotTaken`, `reasonRequired`, …).
    pub async fn boards_select(
        &self,
        idea_id: &str,
        decision: &str,
        slot_id: Option<&str>,
        departs_from_rule: bool,
        reason: Option<&str>,
        key: &HolderKey,
    ) -> Result<ideas_select::Response, VtcError> {
        let mut body = json!({ "ideaId": idea_id, "decision": decision });
        if let Some(s) = slot_id {
            body["slotId"] = json!(s);
        }
        if departs_from_rule {
            body["departsFromRule"] = json!(true);
        }
        if let Some(r) = reason {
            body["reason"] = json!(r);
        }
        self.board_task(task::IDEAS_SELECT, body, key).await
    }

    /// `vtc/boards/notes/list/0.1` — the notes on a board (`scope` `board` or `all`), or on one
    /// idea.
    ///
    /// # Errors
    /// The VTC's refusal.
    pub async fn boards_notes(
        &self,
        board_id: &str,
        idea_id: Option<&str>,
        scope: Option<&str>,
        cursor: Option<&str>,
        limit: Option<u32>,
        key: &HolderKey,
    ) -> Result<notes_list::Response, VtcError> {
        let mut body = json!({ "boardId": board_id });
        if let Some(i) = idea_id {
            body["ideaId"] = json!(i);
        }
        if let Some(s) = scope {
            body["scope"] = json!(s);
        }
        self.board_task(task::NOTES_LIST, paged(body, cursor, limit), key)
            .await
    }

    /// `vtc/boards/notes/hide/0.1` — hide a note with a reason, or show it again.
    ///
    /// # Errors
    /// The VTC's refusal (`stateInvalid`, `reasonRequired`, …).
    pub async fn boards_hide_note(
        &self,
        note_id: &str,
        hide: bool,
        reason: Option<&str>,
        key: &HolderKey,
    ) -> Result<notes_hide::Response, VtcError> {
        let mut body = json!({ "noteId": note_id, "action": if hide { "hide" } else { "unhide" } });
        if let Some(r) = reason {
            body["reason"] = json!(r);
        }
        self.board_task(task::NOTES_HIDE, body, key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOARD: &str = "brd_Uc7N2qLm4Rt8Vx1Z00";
    const IDEA: &str = "ida_Pk3Wq9Ls2Dn6Hy4B00";

    #[test]
    fn requests_out_of_schema_are_refused_before_sending() {
        assert!(checked(task::SHOW, json!({ "boardId": BOARD })).is_ok());
        assert!(checked(task::SHOW, json!({ "boardId": "board-1" })).is_err());
        assert!(
            checked(
                task::IDEAS_DECIDE,
                json!({ "ideaId": IDEA, "decision": "accept" })
            )
            .is_ok()
        );
        assert!(
            checked(
                task::IDEAS_DECIDE,
                json!({ "ideaId": IDEA, "decision": "approve" })
            )
            .is_err()
        );
        assert!(checked(task::NOTES_ADD, json!({ "boardId": BOARD, "text": "" })).is_err());
        assert!(checked(task::LIST, json!({ "limit": 500 })).is_err());
    }

    #[test]
    fn a_type_uri_outside_the_family_is_refused() {
        assert!(checked("https://trusttasks.org/spec/vtc/groups/list/0.2", json!({})).is_err());
        assert!(declared("https://trusttasks.org/spec/vtc/groups/list/0.2").is_empty());
    }

    #[test]
    fn every_task_names_its_declared_codes() {
        for t in [
            task::CREATE,
            task::UPDATE,
            task::SHOW,
            task::IDEAS_PROPOSE,
            task::IDEAS_DECIDE,
            task::IDEAS_SELECT,
            task::NOTES_ADD,
            task::NOTES_HIDE,
        ] {
            assert!(!declared(t).is_empty(), "{t}");
        }
    }
}
