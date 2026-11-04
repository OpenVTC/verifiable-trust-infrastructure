//! The community's boards on the signed-document spine (`vtc/boards/*`, VTI-BRD-001 – 080;
//! [`crate::boards`]).
//!
//! | task | authority (read now) |
//! |---|---|
//! | `create/0.1` | `vtc.boards.manage` unqualified **and** `vtc.elections.manage` (VTI-BRD-002) |
//! | `update/0.1` | `vtc.boards.manage` for the board; a new `template` as `create` |
//! | `list/0.1`, `show/0.1`, `notes/list/0.1` | an active member, each board as their standing lets them see it, or a facilitator |
//! | `ideas/{propose,update,withdraw}/0.1` | a member of the board's audience; update and withdraw only the proposer |
//! | `ideas/{decide,select}/0.1`, `notes/hide/0.1` | `vtc.boards.manage` for the board — never a portal key (VTI-BRD-051) |
//! | `notes/{add,withdraw}/0.1` | a member of the board's audience; withdraw only the author |
//!
//! The member tasks accept a document signed by the portal's sign-in key for the member's
//! live session (`member_portal::delegation`, VTI-BRD-050); the facilitator tasks take the
//! signer's own key only. A board the caller may not see is `notFound`, exactly as one that
//! does not exist, on every task. None has a REST route.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trust_tasks_rs::{Payload, RejectReason, StandardCode, TrustTask, TrustTaskCode};
use vti_common::audit::{AuditEvent, BoardChangedData};
use vti_common::error::AppError;
use vti_specs::vtc::boards::{
    create::v0_1 as board_create,
    delete::v0_1 as board_delete,
    ideas::{
        decide::v0_1 as ideas_decide, propose::v0_1 as ideas_propose, select::v0_1 as ideas_select,
        update::v0_1 as ideas_update, withdraw::v0_1 as ideas_withdraw,
    },
    list::v0_1 as board_list,
    notes::{
        add::v0_1 as notes_add, hide::v0_1 as notes_hide, list::v0_1 as notes_list,
        withdraw::v0_1 as notes_withdraw,
    },
    show::v0_1 as board_show,
    update::v0_1 as board_update,
};

use super::admin_tasks::member_signer;
use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response,
};
use super::{JoinAuthCtx, parse_spec_payload};
use crate::acl::{Capability, ResourceQualifier};
use crate::boards::{
    self, Authors, Board, BoardAudience, BoardStatus, Decision, Idea, Note, NoteState, Slot,
    StoredIdeaState, Who, Window,
};
use crate::server::AppState;

pub(crate) const CREATE_TYPE: &str = <board_create::Payload as Payload>::TYPE_URI;
pub(crate) const UPDATE_TYPE: &str = <board_update::Payload as Payload>::TYPE_URI;
pub(crate) const DELETE_TYPE: &str = <board_delete::Payload as Payload>::TYPE_URI;
pub(crate) const LIST_TYPE: &str = <board_list::Payload as Payload>::TYPE_URI;
pub(crate) const SHOW_TYPE: &str = <board_show::Payload as Payload>::TYPE_URI;
pub(crate) const IDEAS_PROPOSE_TYPE: &str = <ideas_propose::Payload as Payload>::TYPE_URI;
pub(crate) const IDEAS_UPDATE_TYPE: &str = <ideas_update::Payload as Payload>::TYPE_URI;
pub(crate) const IDEAS_WITHDRAW_TYPE: &str = <ideas_withdraw::Payload as Payload>::TYPE_URI;
pub(crate) const IDEAS_DECIDE_TYPE: &str = <ideas_decide::Payload as Payload>::TYPE_URI;
pub(crate) const IDEAS_SELECT_TYPE: &str = <ideas_select::Payload as Payload>::TYPE_URI;
pub(crate) const NOTES_ADD_TYPE: &str = <notes_add::Payload as Payload>::TYPE_URI;
pub(crate) const NOTES_LIST_TYPE: &str = <notes_list::Payload as Payload>::TYPE_URI;
pub(crate) const NOTES_WITHDRAW_TYPE: &str = <notes_withdraw::Payload as Payload>::TYPE_URI;
pub(crate) const NOTES_HIDE_TYPE: &str = <notes_hide::Payload as Payload>::TYPE_URI;

/// Every type this module serves.
pub(crate) const URIS: &[&str] = &[
    CREATE_TYPE,
    UPDATE_TYPE,
    DELETE_TYPE,
    LIST_TYPE,
    SHOW_TYPE,
    IDEAS_PROPOSE_TYPE,
    IDEAS_UPDATE_TYPE,
    IDEAS_WITHDRAW_TYPE,
    IDEAS_DECIDE_TYPE,
    IDEAS_SELECT_TYPE,
    NOTES_ADD_TYPE,
    NOTES_LIST_TYPE,
    NOTES_WITHDRAW_TYPE,
    NOTES_HIDE_TYPE,
];

macro_rules! codes {
    ($($name:ident = $module:ident :: $code:ident;)*) => {
        $(pub(crate) const $name: &str = $module::error_codes::$code.code;)*
    };
}

codes! {
    CREATE_ERR_TEMPLATE_INVALID = board_create::TEMPLATE_INVALID;
    CREATE_ERR_BALLOT_BOX_NOT_TRUSTED = board_create::BALLOT_BOX_NOT_TRUSTED;
    CREATE_ERR_GROUP_NOT_FOUND = board_create::GROUP_NOT_FOUND;
    CREATE_ERR_SCHEDULE_INVALID = board_create::SCHEDULE_INVALID;
    CREATE_ERR_TIMETABLE_INVALID = board_create::TIMETABLE_INVALID;
    UPDATE_ERR_NOT_FOUND = board_update::NOT_FOUND;
    DELETE_ERR_NOT_FOUND = board_delete::NOT_FOUND;
    DELETE_ERR_NOT_CLOSED = board_delete::NOT_CLOSED;
    DELETE_ERR_ELECTIONS_RUNNING = board_delete::ELECTIONS_RUNNING;
    UPDATE_ERR_FIXED_AFTER_VOTING_OPENS = board_update::FIXED_AFTER_VOTING_OPENS;
    UPDATE_ERR_STATUS_INVALID = board_update::STATUS_INVALID;
    UPDATE_ERR_ARCHIVED = board_update::ARCHIVED;
    UPDATE_ERR_TEMPLATE_INVALID = board_update::TEMPLATE_INVALID;
    UPDATE_ERR_BALLOT_BOX_NOT_TRUSTED = board_update::BALLOT_BOX_NOT_TRUSTED;
    UPDATE_ERR_SCHEDULE_INVALID = board_update::SCHEDULE_INVALID;
    UPDATE_ERR_TIMETABLE_INVALID = board_update::TIMETABLE_INVALID;
    LIST_ERR_CURSOR_INVALID = board_list::CURSOR_INVALID;
    SHOW_ERR_NOT_FOUND = board_show::NOT_FOUND;
    SHOW_ERR_CURSOR_INVALID = board_show::CURSOR_INVALID;
    PROPOSE_ERR_NOT_FOUND = ideas_propose::NOT_FOUND;
    PROPOSE_ERR_PROPOSALS_CLOSED = ideas_propose::PROPOSALS_CLOSED;
    PROPOSE_ERR_LIMIT_REACHED = ideas_propose::LIMIT_REACHED;
    PROPOSE_ERR_TOPIC_UNKNOWN = ideas_propose::TOPIC_UNKNOWN;
    PROPOSE_ERR_FORMAT_UNKNOWN = ideas_propose::FORMAT_UNKNOWN;
    IDEA_UPDATE_ERR_NOT_FOUND = ideas_update::NOT_FOUND;
    IDEA_UPDATE_ERR_IDEA_NOT_FOUND = ideas_update::IDEA_NOT_FOUND;
    IDEA_UPDATE_ERR_NOT_PROPOSER = ideas_update::NOT_PROPOSER;
    IDEA_UPDATE_ERR_NOT_PROPOSED = ideas_update::NOT_PROPOSED;
    IDEA_UPDATE_ERR_TOPIC_UNKNOWN = ideas_update::TOPIC_UNKNOWN;
    IDEA_UPDATE_ERR_FORMAT_UNKNOWN = ideas_update::FORMAT_UNKNOWN;
    WITHDRAW_ERR_NOT_FOUND = ideas_withdraw::NOT_FOUND;
    WITHDRAW_ERR_IDEA_NOT_FOUND = ideas_withdraw::IDEA_NOT_FOUND;
    WITHDRAW_ERR_NOT_PROPOSER = ideas_withdraw::NOT_PROPOSER;
    WITHDRAW_ERR_NOT_PROPOSED = ideas_withdraw::NOT_PROPOSED;
    DECIDE_ERR_NOT_FOUND = ideas_decide::NOT_FOUND;
    DECIDE_ERR_IDEA_NOT_FOUND = ideas_decide::IDEA_NOT_FOUND;
    DECIDE_ERR_STATE_INVALID = ideas_decide::STATE_INVALID;
    DECIDE_ERR_OWN_IDEA = ideas_decide::OWN_IDEA;
    DECIDE_ERR_MERGE_TARGET_INVALID = ideas_decide::MERGE_TARGET_INVALID;
    DECIDE_ERR_REASON_REQUIRED = ideas_decide::REASON_REQUIRED;
    DECIDE_ERR_VOTING_CLOSED = ideas_decide::VOTING_CLOSED;
    DECIDE_ERR_ELECTION_REFUSED = ideas_decide::ELECTION_REFUSED;
    SELECT_ERR_NOT_FOUND = ideas_select::NOT_FOUND;
    SELECT_ERR_IDEA_NOT_FOUND = ideas_select::IDEA_NOT_FOUND;
    SELECT_ERR_NOT_TALLIED = ideas_select::NOT_TALLIED;
    SELECT_ERR_STATE_INVALID = ideas_select::STATE_INVALID;
    SELECT_ERR_SLOT_UNKNOWN = ideas_select::SLOT_UNKNOWN;
    SELECT_ERR_SLOT_TAKEN = ideas_select::SLOT_TAKEN;
    SELECT_ERR_REASON_REQUIRED = ideas_select::REASON_REQUIRED;
    NOTES_ADD_ERR_NOT_FOUND = notes_add::NOT_FOUND;
    NOTES_ADD_ERR_IDEA_NOT_FOUND = notes_add::IDEA_NOT_FOUND;
    NOTES_ADD_ERR_BOARD_CLOSED = notes_add::BOARD_CLOSED;
    NOTES_ADD_ERR_IDEA_WITHDRAWN = notes_add::IDEA_WITHDRAWN;
    NOTES_ADD_ERR_RATE_LIMITED = notes_add::RATE_LIMITED;
    NOTES_LIST_ERR_NOT_FOUND = notes_list::NOT_FOUND;
    NOTES_LIST_ERR_IDEA_NOT_FOUND = notes_list::IDEA_NOT_FOUND;
    NOTES_LIST_ERR_CURSOR_INVALID = notes_list::CURSOR_INVALID;
    NOTE_WITHDRAW_ERR_NOTE_NOT_FOUND = notes_withdraw::NOTE_NOT_FOUND;
    NOTE_WITHDRAW_ERR_NOT_AUTHOR = notes_withdraw::NOT_AUTHOR;
    NOTE_WITHDRAW_ERR_ALREADY_WITHDRAWN = notes_withdraw::ALREADY_WITHDRAWN;
    HIDE_ERR_NOTE_NOT_FOUND = notes_hide::NOTE_NOT_FOUND;
    HIDE_ERR_STATE_INVALID = notes_hide::STATE_INVALID;
    HIDE_ERR_REASON_REQUIRED = notes_hide::REASON_REQUIRED;
}

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        CREATE_TYPE => handle_create(state, ctx, doc).await,
        UPDATE_TYPE => handle_update(state, ctx, doc).await,
        DELETE_TYPE => handle_delete(state, ctx, doc).await,
        LIST_TYPE => handle_list(state, ctx, doc).await,
        SHOW_TYPE => handle_show(state, ctx, doc).await,
        IDEAS_PROPOSE_TYPE => handle_propose(state, ctx, doc).await,
        IDEAS_UPDATE_TYPE => handle_idea_update(state, ctx, doc).await,
        IDEAS_WITHDRAW_TYPE => handle_idea_withdraw(state, ctx, doc).await,
        IDEAS_DECIDE_TYPE => handle_decide(state, ctx, doc).await,
        IDEAS_SELECT_TYPE => handle_select(state, ctx, doc).await,
        NOTES_ADD_TYPE => handle_note_add(state, ctx, doc).await,
        NOTES_LIST_TYPE => handle_notes_list(state, ctx, doc).await,
        NOTES_WITHDRAW_TYPE => handle_note_withdraw(state, ctx, doc).await,
        NOTES_HIDE_TYPE => handle_note_hide(state, ctx, doc).await,
        _ => return None,
    })
}

// ─── shared ──────────────────────────────────────────────────────────────

fn declared(doc: &TrustTask<Value>, code: &str, message: impl Into<String>) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, None)
}

fn denied(doc: &TrustTask<Value>, why: &str) -> TrustTaskOutcome {
    reject_with(
        doc,
        RejectReason::PermissionDenied {
            reason: why.to_string(),
        },
    )
}

/// A member's act: the signer's own key, or the portal's key for the member's live session
/// (VTI-BRD-050).
async fn member(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<Who, TrustTaskOutcome> {
    let delegated = match ctx.verified_signer.as_deref() {
        Some(signer) => crate::member_portal::delegation::accept(
            state,
            signer,
            &doc.type_uri.to_string(),
            &doc.id.to_string(),
        )
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?,
        None => None,
    };
    let did = match delegated {
        Some(m) => m,
        None => member_signer(state, ctx, doc).await?.did,
    };
    Who::read(state, &did)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))
}

/// A facilitator's act: the signer's own key only — never the portal's delegated key
/// (VTI-BRD-051), which `member_signer` does not accept.
async fn facilitator(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<Who, TrustTaskOutcome> {
    let did = member_signer(state, ctx, doc).await?.did;
    Who::read(state, &did)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))
}

/// A board change is never unaudited (VTI-BRD-080).
async fn audit(state: &AppState, actor: &str, data: BoardChangedData) -> Result<(), AppError> {
    let writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured: board changes are refused rather than made \
                      unaudited"
                .into(),
        })?;
    writer
        .write(actor, None, AuditEvent::BoardChanged(data))
        .await
        .map(drop)
}

fn changed(board_id: &str, change: &str) -> BoardChangedData {
    BoardChangedData {
        board_id: board_id.to_string(),
        idea_id: None,
        note_id: None,
        change: change.to_string(),
        election_id: None,
        fields: Vec::new(),
        own_idea: false,
    }
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn string_list(v: &Value, key: &str) -> Option<Vec<String>> {
    v.get(key).and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    })
}

/// The caller's directory entry, made if they have none yet (as groups do).
async fn own_entry(state: &AppState, who: &Who) -> Result<String, AppError> {
    if let Some(e) = &who.entry_id {
        return Ok(e.clone());
    }
    let dir = &state.directory;
    let own = crate::acl::get_acl_entry(&state.acl_ks, &who.did)
        .await?
        .filter(|e| e.label_set_by_subject)
        .and_then(|e| e.label);
    Ok(
        crate::directory::cards::ensure(dir.ks(), &who.did, &dir.settings(), own.as_deref())
            .await?
            .entry_id,
    )
}

// ── paging: an offset bound to the caller and the question ──

fn cursor_mac(binding: &str, offset: usize) -> String {
    let mut h = Sha256::new();
    h.update(b"vtc/boards/cursor/v1\0");
    for part in [binding, &offset.to_string()] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    hex::encode(&h.finalize()[..12])
}

fn cursor_for(binding: &str, offset: usize) -> String {
    format!("{offset}.{}", cursor_mac(binding, offset))
}

fn offset_of(payload: &Value, binding: &str) -> Result<usize, ()> {
    let Some(c) = str_of(payload, "cursor") else {
        return Ok(0);
    };
    let (n, mac) = c.split_once('.').ok_or(())?;
    let offset: usize = n.parse().map_err(|_| ())?;
    (cursor_mac(binding, offset) == mac)
        .then_some(offset)
        .ok_or(())
}

fn limit_of(payload: &Value) -> usize {
    payload
        .get("limit")
        .and_then(Value::as_u64)
        .map_or(50, |l| l as usize)
        .clamp(1, 200)
}

// ── the board's own checks ──

/// VTI-BRD-001's ordering: each window closes after it opens, voting opens after proposals
/// open and closes after they close.
fn schedule_ok(proposals: &Window, voting: &Window) -> bool {
    proposals.opens_at < proposals.closes_at
        && voting.opens_at < voting.closes_at
        && voting.opens_at >= proposals.opens_at
        && voting.closes_at >= proposals.closes_at
}

fn timetable_ok(slots: &[Slot]) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    slots
        .iter()
        .all(|s| s.starts_at < s.ends_at && seen.insert(s.slot_id.as_str()))
}

fn window(v: &Value) -> Option<Window> {
    serde_json::from_value(v.clone()).ok()
}

fn slots(v: &Value) -> Option<Vec<Slot>> {
    serde_json::from_value(v.clone()).ok()
}

fn audience(v: &Value) -> Option<BoardAudience> {
    serde_json::from_value(v.clone()).ok()
}

#[cfg(feature = "voting")]
async fn template_check(state: &AppState, board: &Board) -> Result<(), (&'static str, String)> {
    crate::boards::ops::check_template(state, board, Utc::now()).await
}

#[cfg(not(feature = "voting"))]
async fn template_check(_state: &AppState, _board: &Board) -> Result<(), (&'static str, String)> {
    // A community that runs no elections cannot offer boards (Community Boards chapter).
    Err((
        "templateInvalid",
        "this community does not run elections, which a board's ideas are put to".into(),
    ))
}

/// The board `board_id`, where `who` may see it.
async fn visible_board(
    state: &AppState,
    who: &Who,
    board_id: &str,
) -> Result<Option<Board>, AppError> {
    Ok(boards::get_board(&state.boards_ks, board_id)
        .await?
        .filter(|b| who.sees(b)))
}

/// The idea `idea_id` and its board, where `who` may see both: a withdrawn idea only to its
/// proposer and the board's facilitators. `Ok(Err(board_seen))` otherwise.
async fn visible_idea(
    state: &AppState,
    who: &Who,
    idea_id: &str,
) -> Result<Result<(Board, Idea), bool>, AppError> {
    let Some(idea) = boards::get_idea(&state.boards_ks, idea_id).await? else {
        return Ok(Err(false));
    };
    let Some(board) = visible_board(state, who, &idea.board_id).await? else {
        return Ok(Err(false));
    };
    if idea.state == StoredIdeaState::Withdrawn
        && !who.facilitates(&board.board_id)
        && !who.is(&idea.proposer)
    {
        return Ok(Err(true));
    }
    Ok(Ok((board, idea)))
}

async fn notes_readable_on(
    state: &AppState,
    who: &Who,
    board: &Board,
) -> Result<Vec<Note>, AppError> {
    let facilitator = who.facilitates(&board.board_id);
    Ok(boards::notes_of(&state.boards_ks, &board.board_id)
        .await?
        .into_iter()
        .filter(|n| boards::reads_text(n, who, facilitator))
        .collect())
}

async fn idea_answer(
    state: &AppState,
    doc: &TrustTask<Value>,
    who: &Who,
    idea: &Idea,
) -> TrustTaskOutcome {
    let facilitator = who.facilitates(&idea.board_id);
    let authors = match Authors::for_viewer(state, who).await {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    let board = Board {
        board_id: idea.board_id.clone(),
        ..placeholder_board()
    };
    let count = match notes_readable_on(state, who, &board).await {
        Ok(n) => n
            .iter()
            .filter(|n| n.idea_id.as_deref() == Some(idea.idea_id.as_str()))
            .count(),
        Err(e) => return app_error_to_reject(doc, &e),
    };
    match boards::idea_wire(state, idea, facilitator, &authors, count).await {
        Ok(w) => success_response(doc, json!({ "idea": w })),
        Err(e) => app_error_to_reject(doc, &e),
    }
}

fn placeholder_board() -> Board {
    let t = DateTime::<Utc>::UNIX_EPOCH;
    Board {
        board_id: String::new(),
        title: String::new(),
        description: None,
        status: BoardStatus::Open,
        audience: BoardAudience::Members,
        proposals: Window {
            opens_at: t,
            closes_at: t,
        },
        voting: Window {
            opens_at: t,
            closes_at: t,
        },
        topics: Vec::new(),
        formats: Vec::new(),
        max_ideas_per_member: None,
        selection_rule: None,
        timetable: Vec::new(),
        template: Value::Null,
        created_at: t,
        created_by: String::new(),
    }
}

async fn board_answer(
    state: &AppState,
    doc: &TrustTask<Value>,
    who: &Who,
    board: &Board,
) -> TrustTaskOutcome {
    match boards::board_wire(state, board, who).await {
        Ok(w) => success_response(doc, json!({ "board": w })),
        Err(e) => app_error_to_reject(doc, &e),
    }
}

// ─── create, update ──────────────────────────────────────────────────────

/// `create/0.1` (items 1 – 6).
async fn handle_create(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match facilitator(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    // Item 1 (VTI-BRD-002).
    if !(who.manages_all() && who.can(Capability::ElectionsManage)) {
        return denied(
            &doc,
            "creating a board takes vtc.boards.manage and vtc.elections.manage",
        );
    }
    if let Err(r) = parse_spec_payload::<board_create::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let (Some(proposals), Some(voting), Some(audience)) = (
        window(&p["proposals"]),
        window(&p["voting"]),
        audience(&p["audience"]),
    ) else {
        return declared(
            &doc,
            CREATE_ERR_SCHEDULE_INVALID,
            "The schedule does not read.",
        );
    };
    // Item 2.
    if !schedule_ok(&proposals, &voting) {
        return declared(
            &doc,
            CREATE_ERR_SCHEDULE_INVALID,
            "Each window must close after it opens, and voting must open and close no earlier \
             than proposals do.",
        );
    }
    let timetable = match p.get("timetable") {
        Some(v) => match slots(v) {
            Some(s) if timetable_ok(&s) => s,
            _ => {
                return declared(
                    &doc,
                    CREATE_ERR_TIMETABLE_INVALID,
                    "Two slots share an identifier, or a slot ends before it starts.",
                );
            }
        },
        None => Vec::new(),
    };
    // Item 4.
    if let BoardAudience::Group { group_id } = &audience {
        match crate::groups::get(state.directory.ks(), group_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return declared(
                    &doc,
                    CREATE_ERR_GROUP_NOT_FOUND,
                    "The audience names no group of this community.",
                );
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    let now = Utc::now();
    let board = Board {
        board_id: boards::new_board_id(),
        title: str_of(p, "title").unwrap_or_default().to_string(),
        description: str_of(p, "description").map(str::to_string),
        status: BoardStatus::Open,
        audience,
        proposals,
        voting,
        topics: string_list(p, "topics").unwrap_or_default(),
        formats: string_list(p, "formats").unwrap_or_default(),
        max_ideas_per_member: p
            .get("maxIdeasPerMember")
            .and_then(Value::as_u64)
            .map(|n| n as u32),
        selection_rule: str_of(p, "selectionRule").map(str::to_string),
        timetable,
        template: p["template"].clone(),
        created_at: now,
        created_by: who.did.clone(),
    };
    // Item 3.
    if let Err((code, why)) = template_check(state, &board).await {
        let code = if code == "ballotBoxNotTrusted" {
            CREATE_ERR_BALLOT_BOX_NOT_TRUSTED
        } else {
            CREATE_ERR_TEMPLATE_INVALID
        };
        return declared(&doc, code, why);
    }
    // Item 6, then item 5: never stored unaudited.
    if let Err(e) = audit(state, &who.did, changed(&board.board_id, "created")).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = boards::put_board(&state.boards_ks, &board).await {
        return app_error_to_reject(&doc, &e);
    }
    board_answer(state, &doc, &who, &board).await
}

/// `update/0.1` (items 1 – 5).
async fn handle_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match facilitator(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<board_update::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let board_id = str_of(p, "boardId").unwrap_or_default();
    let _guard = boards::WRITE_LOCK.lock().await;
    let mut board = match visible_board(state, &who, board_id).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            return declared(
                &doc,
                UPDATE_ERR_NOT_FOUND,
                "No board you may see has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // Item 1.
    if !who.facilitates(&board.board_id) {
        return denied(&doc, "you do not facilitate this board");
    }
    if p.get("template").is_some() && !(who.manages_all() && who.can(Capability::ElectionsManage)) {
        return denied(
            &doc,
            "changing a board's election template takes vtc.boards.manage and vtc.elections.manage",
        );
    }
    // Item 2.
    if board.status == BoardStatus::Archived {
        return declared(
            &doc,
            UPDATE_ERR_ARCHIVED,
            "This board is archived and takes no change.",
        );
    }
    let now = Utc::now();
    let mut fields = Vec::new();
    if let Some(a) = p.get("audience") {
        let Some(a) = audience(a) else {
            return declared(
                &doc,
                UPDATE_ERR_SCHEDULE_INVALID,
                "The audience does not read.",
            );
        };
        if a != board.audience {
            if now >= board.voting.opens_at {
                return declared(
                    &doc,
                    UPDATE_ERR_FIXED_AFTER_VOTING_OPENS,
                    "A board's audience is fixed once voting has opened.",
                );
            }
            board.audience = a;
            fields.push("audience".to_string());
        }
    }
    if let Some(v) = p.get("voting") {
        let Some(v) = window(v) else {
            return declared(
                &doc,
                UPDATE_ERR_SCHEDULE_INVALID,
                "The voting window does not read.",
            );
        };
        if v != board.voting {
            if now >= board.voting.opens_at {
                return declared(
                    &doc,
                    UPDATE_ERR_FIXED_AFTER_VOTING_OPENS,
                    "A board's voting window is fixed once voting has opened.",
                );
            }
            board.voting = v;
            fields.push("voting".to_string());
        }
    }
    if let Some(v) = p.get("proposals") {
        let Some(v) = window(v) else {
            return declared(
                &doc,
                UPDATE_ERR_SCHEDULE_INVALID,
                "The proposal window does not read.",
            );
        };
        board.proposals = v;
        fields.push("proposals".to_string());
    }
    if !schedule_ok(&board.proposals, &board.voting) {
        return declared(
            &doc,
            UPDATE_ERR_SCHEDULE_INVALID,
            "Each window must close after it opens, and voting must open and close no earlier \
             than proposals do.",
        );
    }
    if let Some(v) = p.get("timetable") {
        let Some(s) = slots(v).filter(|s| timetable_ok(s)) else {
            return declared(
                &doc,
                UPDATE_ERR_TIMETABLE_INVALID,
                "Two slots share an identifier, or a slot ends before it starts.",
            );
        };
        // A slot a selected idea is placed in stays.
        let ideas = match boards::ideas_of(&state.boards_ks, &board.board_id).await {
            Ok(i) => i,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        let held = ideas.iter().filter_map(|i| {
            (i.state == StoredIdeaState::Selected)
                .then(|| i.decision.as_ref().and_then(|d| d.slot_id.clone()))
                .flatten()
        });
        for slot in held {
            if !s.iter().any(|x| x.slot_id == slot) {
                return declared(
                    &doc,
                    UPDATE_ERR_TIMETABLE_INVALID,
                    "A slot a selected idea is placed in cannot be removed.",
                );
            }
        }
        board.timetable = s;
        fields.push("timetable".to_string());
    }
    if let Some(v) = str_of(p, "title") {
        board.title = v.to_string();
        fields.push("title".into());
    }
    if let Some(v) = str_of(p, "description") {
        board.description = Some(v.to_string());
        fields.push("description".into());
    }
    if let Some(v) = str_of(p, "selectionRule") {
        board.selection_rule = Some(v.to_string());
        fields.push("selectionRule".into());
    }
    if let Some(v) = string_list(p, "topics") {
        board.topics = v;
        fields.push("topics".into());
    }
    if let Some(v) = string_list(p, "formats") {
        board.formats = v;
        fields.push("formats".into());
    }
    if let Some(n) = p.get("maxIdeasPerMember").and_then(Value::as_u64) {
        board.max_ideas_per_member = Some(n as u32);
        fields.push("maxIdeasPerMember".into());
    }
    if let Some(t) = p.get("template") {
        board.template = t.clone();
        fields.push("template".into());
        if let Err((code, why)) = template_check(state, &board).await {
            let code = if code == "ballotBoxNotTrusted" {
                UPDATE_ERR_BALLOT_BOX_NOT_TRUSTED
            } else {
                UPDATE_ERR_TEMPLATE_INVALID
            };
            return declared(&doc, code, why);
        }
    }
    let mut change = "updated";
    let mut closes = false;
    if let Some(s) = str_of(p, "status") {
        closes = board.status == BoardStatus::Open;
        let next = match (board.status, s) {
            (BoardStatus::Open, "closed") => BoardStatus::Closed,
            (BoardStatus::Open | BoardStatus::Closed, "archived") => BoardStatus::Archived,
            _ => {
                return declared(
                    &doc,
                    UPDATE_ERR_STATUS_INVALID,
                    "A board moves from open to closed to archived, never back.",
                );
            }
        };
        board.status = next;
        change = next.as_str();
        fields.push("status".into());
    }
    // Item 4: audited, then stored.
    let data = BoardChangedData {
        fields,
        ..changed(&board.board_id, change)
    };
    if let Err(e) = audit(state, &who.did, data).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = boards::put_board(&state.boards_ks, &board).await {
        return app_error_to_reject(&doc, &e);
    }
    if !closes {
        return board_answer(state, &doc, &who, &board).await;
    }
    // Item 6: recorded closed first; then its voting is ended (VTI-BRD-006), outside the board
    // lock (R1.3). The answer does not wait for the ballot box.
    drop(_guard);
    #[cfg(feature = "voting")]
    let closing = match boards::ops::end_voting(state, &board, now).await {
        Ok(c) => c.wire(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    #[cfg(not(feature = "voting"))]
    let closing = json!({ "closedEarly": 0, "cancelled": 0, "runningToClose": [] });
    match boards::board_wire(state, &board, &who).await {
        Ok(w) => success_response(&doc, json!({ "board": w, "closing": closing })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// Without voting a board opens no election, so none can still be running at a deletion.
#[cfg(not(feature = "voting"))]
const _: &str = DELETE_ERR_ELECTIONS_RUNNING;

/// `delete/0.1` (items 1 – 7, VTI-BRD-007, VTI-BRD-008).
async fn handle_delete(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::acl::bound_step_up::{self, Gate};
    let who = match facilitator(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<board_delete::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let board_id = str_of(p, "boardId").unwrap_or_default().to_string();
    let reason = str_of(p, "reason").unwrap_or_default().to_string();
    let now = Utc::now();
    // Item 1.
    let board = match visible_board(state, &who, &board_id).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            return declared(
                &doc,
                DELETE_ERR_NOT_FOUND,
                "No board you may see has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if !who.manages_all() {
        return denied(
            &doc,
            "deleting a board takes vtc.boards.manage unqualified; a facilitator of one board may \
             close it, not delete it",
        );
    }
    // Item 3: closed, and its voting over.
    if board.status == BoardStatus::Open {
        return declared(
            &doc,
            DELETE_ERR_NOT_CLOSED,
            "This board is open. Close it first, which ends its voting (VTI-BRD-006).",
        );
    }
    let ideas = match boards::ideas_of(&state.boards_ks, &board.board_id).await {
        Ok(i) => i,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    #[cfg(feature = "voting")]
    let mut records = Vec::new();
    #[cfg(feature = "voting")]
    {
        let mut running = Vec::new();
        for idea in &ideas {
            let Some(id) = &idea.election_id else {
                continue;
            };
            match crate::elections::store::get(state.elections.ks(), id).await {
                Ok(Some(rec)) => {
                    if !matches!(rec.state(now), "closed" | "tallied" | "cancelled") {
                        running.push(idea.idea_id.clone());
                    }
                    records.push(rec);
                }
                Ok(None) => {}
                Err(e) => return app_error_to_reject(&doc, &e),
            }
        }
        if !running.is_empty() {
            return declared(
                &doc,
                DELETE_ERR_ELECTIONS_RUNNING,
                format!(
                    "{} idea(s) on this board still have an election running ({}). Retry once \
                     each has closed or been cancelled.",
                    running.len(),
                    running.join(", ")
                ),
            );
        }
    }
    // Item 2: a step-up bound to this one document, spent only once every check above passed.
    match bound_step_up::redeem_or_request(state, &who.did, DELETE_TYPE, &doc.payload, &reason)
        .await
    {
        Ok(Gate::Satisfied) => {}
        Ok(Gate::Required(request)) => {
            return reject_with_code(
                &doc,
                TrustTaskCode::Standard(StandardCode::PermissionDenied),
                "a passkey gesture bound to this deletion is required",
                Some(bound_step_up::refusal_details(&request)),
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    let retention = state.config.read().await.boards.tombstone_retention;
    let remove_at = retention.remove_at(now);
    // Item 6: audited before anything is removed; the reason and counts, never any text.
    let data = BoardChangedData {
        fields: vec![
            format!("reason:{reason}"),
            format!("tombstones:{}", retention.describe()),
        ],
        ..changed(&board.board_id, "deleted")
    };
    if let Err(e) = audit(state, &who.did, data).await {
        return app_error_to_reject(&doc, &e);
    }
    // Item 4: each election's content goes, its tombstone stays for the retention.
    #[allow(unused_mut)]
    let mut elections_removed = 0u64;
    #[allow(unused_mut)]
    let mut kept = 0u64;
    #[cfg(feature = "voting")]
    for rec in &records {
        let ks = state.elections.ks();
        if retention.keeps() {
            let t = crate::elections::store::Tombstone::of(rec, now, remove_at);
            if let Err(e) = crate::elections::store::put_tombstone(ks, &t).await {
                return app_error_to_reject(&doc, &e);
            }
            kept += 1;
        }
        if let Err(e) = crate::elections::store::remove_tickets(ks, &rec.election_id).await {
            return app_error_to_reject(&doc, &e);
        }
        if let Err(e) = crate::elections::store::remove(ks, &rec.election_id).await {
            return app_error_to_reject(&doc, &e);
        }
        elections_removed += 1;
    }
    let _guard = boards::WRITE_LOCK.lock().await;
    let (ideas_removed, notes_removed) =
        match boards::remove_board(&state.boards_ks, &board.board_id).await {
            Ok(n) => n,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
    drop(ideas);
    let mut tombstones = json!({ "kept": kept });
    if kept > 0
        && let Some(at) = remove_at
    {
        tombstones["removeAt"] = json!(at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    }
    success_response(
        &doc,
        json!({
            "boardId": board.board_id,
            "ideasRemoved": ideas_removed,
            "notesRemoved": notes_removed,
            "electionsRemoved": elections_removed,
            "tombstones": tombstones,
        }),
    )
}

// ─── reads ───────────────────────────────────────────────────────────────

/// `list/0.1` (items 1 – 3).
async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    // Item 1.
    if !(who.active_member || who.facilitates_any()) {
        return denied(
            &doc,
            "boards are read by this community's active members and facilitators",
        );
    }
    if let Err(r) = parse_spec_payload::<board_list::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let status = str_of(p, "status");
    let include_archived = p
        .get("includeArchived")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    // Item 2.
    let mut all: Vec<Board> = match boards::all_boards(&state.boards_ks).await {
        Ok(b) => b
            .into_iter()
            .filter(|b| who.sees(b))
            .filter(|b| {
                b.status != BoardStatus::Archived
                    || (include_archived && who.facilitates(&b.board_id))
            })
            .filter(|b| status.is_none_or(|s| s == b.status.as_str()))
            .collect(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // Item 3.
    all.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then(a.board_id.cmp(&b.board_id))
    });
    let binding = format!("list|{}|{status:?}|{include_archived}", who.did);
    let Ok(start) = offset_of(p, &binding) else {
        return declared(
            &doc,
            LIST_ERR_CURSOR_INVALID,
            "This cursor is not this caller's for these filters.",
        );
    };
    let limit = limit_of(p);
    let start = start.min(all.len());
    let page = &all[start..(start + limit).min(all.len())];
    let mut items = Vec::with_capacity(page.len());
    for b in page {
        match boards::board_wire(state, b, &who).await {
            Ok(w) => items.push(w),
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    let mut body = json!({ "boards": items });
    if start + page.len() < all.len() {
        body["nextCursor"] = json!(cursor_for(&binding, start + page.len()));
    }
    success_response(&doc, body)
}

/// `show/0.1` (items 1 – 6).
async fn handle_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<board_show::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let board = match visible_board(state, &who, str_of(p, "boardId").unwrap_or_default()).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            return declared(
                &doc,
                SHOW_ERR_NOT_FOUND,
                "No board you may see has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let facilitator = who.facilitates(&board.board_id);
    let states = string_list(p, "state");
    let topic = str_of(p, "topic");
    let now = Utc::now();
    let mut ideas: Vec<(Idea, &'static str)> = Vec::new();
    match boards::ideas_of(&state.boards_ks, &board.board_id).await {
        Ok(all) => {
            for i in all {
                if i.state == StoredIdeaState::Withdrawn && !facilitator && !who.is(&i.proposer) {
                    continue;
                }
                if topic.is_some_and(|t| i.topic.as_deref() != Some(t)) {
                    continue;
                }
                let v = match boards::view(state, &i, facilitator, now).await {
                    Ok(v) => v,
                    Err(e) => return app_error_to_reject(&doc, &e),
                };
                if states
                    .as_ref()
                    .is_some_and(|s| !s.iter().any(|x| x == v.state))
                {
                    continue;
                }
                ideas.push((i, v.state));
            }
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    ideas.sort_by(|a, b| {
        b.0.proposed_at
            .cmp(&a.0.proposed_at)
            .then(a.0.idea_id.cmp(&b.0.idea_id))
    });
    let binding = format!("show|{}|{}|{states:?}|{topic:?}", who.did, board.board_id);
    let Ok(start) = offset_of(p, &binding) else {
        return declared(
            &doc,
            SHOW_ERR_CURSOR_INVALID,
            "This cursor is not this caller's for this board.",
        );
    };
    let limit = limit_of(p);
    let start = start.min(ideas.len());
    let page = &ideas[start..(start + limit).min(ideas.len())];
    let notes = match notes_readable_on(state, &who, &board).await {
        Ok(n) => n,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let authors = match Authors::for_viewer(state, &who).await {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut items = Vec::with_capacity(page.len());
    for (i, _) in page {
        let count = notes
            .iter()
            .filter(|n| n.idea_id.as_deref() == Some(i.idea_id.as_str()))
            .count();
        match boards::idea_wire(state, i, facilitator, &authors, count).await {
            Ok(w) => items.push(w),
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    let board_wire = match boards::board_wire(state, &board, &who).await {
        Ok(w) => w,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut body = json!({ "board": board_wire, "ideas": items });
    if start + page.len() < ideas.len() {
        body["nextCursor"] = json!(cursor_for(&binding, start + page.len()));
    }
    success_response(&doc, body)
}

// ─── ideas: a member's own ───────────────────────────────────────────────

fn topic_ok(board: &Board, topic: Option<&str>) -> bool {
    board.topics.is_empty() || topic.is_some_and(|t| board.topics.iter().any(|x| x == t))
}

fn format_ok(board: &Board, format: Option<&str>) -> bool {
    board.formats.is_empty() || format.is_some_and(|f| board.formats.iter().any(|x| x == f))
}

/// `ideas/propose/0.1` (items 1 – 4).
async fn handle_propose(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let mut who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<ideas_propose::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let board = match visible_board(state, &who, str_of(p, "boardId").unwrap_or_default()).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            return declared(
                &doc,
                PROPOSE_ERR_NOT_FOUND,
                "No board you may see has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // Item 1 (VTI-BRD-010).
    if !who.in_audience(&board) {
        return denied(
            &doc,
            "ideas are proposed by the members this board's audience admits",
        );
    }
    let now = Utc::now();
    // Item 2.
    if board.status != BoardStatus::Open || !board.proposals.contains(now) {
        return declared(
            &doc,
            PROPOSE_ERR_PROPOSALS_CLOSED,
            "This board is not taking proposals now.",
        );
    }
    let topic = str_of(p, "topic");
    let format = str_of(p, "format");
    if !topic_ok(&board, topic) {
        return declared(
            &doc,
            PROPOSE_ERR_TOPIC_UNKNOWN,
            "Choose one of this board's topics.",
        );
    }
    if !format_ok(&board, format) {
        return declared(
            &doc,
            PROPOSE_ERR_FORMAT_UNKNOWN,
            "Choose one of this board's formats.",
        );
    }
    let entry_id = match own_entry(state, &who).await {
        Ok(e) => e,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    who.entry_id = Some(entry_id.clone());
    let _guard = boards::WRITE_LOCK.lock().await;
    if let Some(max) = board.max_ideas_per_member {
        let held = match boards::ideas_of(&state.boards_ks, &board.board_id).await {
            Ok(i) => i
                .iter()
                .filter(|i| {
                    i.proposer == entry_id
                        && !matches!(
                            i.state,
                            StoredIdeaState::Withdrawn | StoredIdeaState::Declined
                        )
                })
                .count(),
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        if held >= max as usize {
            return declared(
                &doc,
                PROPOSE_ERR_LIMIT_REACHED,
                format!("You already have this board's limit of {max} ideas."),
            );
        }
    }
    // Item 3.
    let idea = Idea {
        idea_id: boards::new_idea_id(),
        board_id: board.board_id.clone(),
        state: StoredIdeaState::Proposed,
        title: str_of(p, "title").map(str::to_string),
        description: str_of(p, "description").map(str::to_string),
        format: format.map(str::to_string),
        topic: topic.map(str::to_string),
        proposer: entry_id,
        proposed_at: now,
        election_id: None,
        accepted_at: None,
        refusal: None,
        decision: None,
    };
    if let Err(e) = boards::put_idea(&state.boards_ks, &idea).await {
        return app_error_to_reject(&doc, &e);
    }
    drop(_guard);
    idea_answer(state, &doc, &who, &idea).await
}

/// The idea a proposer acts on: `notFound`, `ideaNotFound`, `notProposer` or `notProposed`
/// (ideas/update and ideas/withdraw item 1).
async fn own_proposed_idea(
    state: &AppState,
    doc: &TrustTask<Value>,
    who: &Who,
    codes: [&str; 4],
) -> Result<(Board, Idea), TrustTaskOutcome> {
    let [not_found, idea_not_found, not_proposer, not_proposed] = codes;
    let idea_id = str_of(&doc.payload, "ideaId").unwrap_or_default();
    let (board, idea) = match visible_idea(state, who, idea_id).await {
        Ok(Ok(bi)) => bi,
        Ok(Err(false)) => {
            return Err(declared(
                doc,
                not_found,
                "No board you may see holds this idea.",
            ));
        }
        Ok(Err(true)) => {
            return Err(declared(
                doc,
                idea_not_found,
                "No idea on this board you may see has this identifier.",
            ));
        }
        Err(e) => return Err(app_error_to_reject(doc, &e)),
    };
    if !who.is(&idea.proposer) {
        return Err(declared(
            doc,
            not_proposer,
            "You did not propose this idea.",
        ));
    }
    let opening = match boards::is_opening(state, &idea).await {
        Ok(o) => o,
        Err(e) => return Err(app_error_to_reject(doc, &e)),
    };
    if idea.state != StoredIdeaState::Proposed || idea.election_id.is_some() || opening {
        return Err(declared(
            doc,
            not_proposed,
            "This idea is no longer proposed; once an election is opened its title and \
             description are its manifest's.",
        ));
    }
    Ok((board, idea))
}

/// `ideas/update/0.1` (items 1 – 3).
async fn handle_idea_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<ideas_update::Payload>(&doc) {
        return r;
    }
    let _guard = boards::WRITE_LOCK.lock().await;
    let (board, mut idea) = match own_proposed_idea(
        state,
        &doc,
        &who,
        [
            IDEA_UPDATE_ERR_NOT_FOUND,
            IDEA_UPDATE_ERR_IDEA_NOT_FOUND,
            IDEA_UPDATE_ERR_NOT_PROPOSER,
            IDEA_UPDATE_ERR_NOT_PROPOSED,
        ],
    )
    .await
    {
        Ok(bi) => bi,
        Err(r) => return r,
    };
    let p = &doc.payload;
    if let Some(t) = str_of(p, "topic") {
        if !topic_ok(&board, Some(t)) {
            return declared(
                &doc,
                IDEA_UPDATE_ERR_TOPIC_UNKNOWN,
                "Choose one of this board's topics.",
            );
        }
        idea.topic = Some(t.to_string());
    }
    if let Some(f) = str_of(p, "format") {
        if !format_ok(&board, Some(f)) {
            return declared(
                &doc,
                IDEA_UPDATE_ERR_FORMAT_UNKNOWN,
                "Choose one of this board's formats.",
            );
        }
        idea.format = Some(f.to_string());
    }
    if let Some(t) = str_of(p, "title") {
        idea.title = Some(t.to_string());
    }
    if let Some(d) = str_of(p, "description") {
        idea.description = Some(d.to_string());
    }
    if let Err(e) = boards::put_idea(&state.boards_ks, &idea).await {
        return app_error_to_reject(&doc, &e);
    }
    drop(_guard);
    idea_answer(state, &doc, &who, &idea).await
}

/// `ideas/withdraw/0.1` (items 1 – 2).
async fn handle_idea_withdraw(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<ideas_withdraw::Payload>(&doc) {
        return r;
    }
    let _guard = boards::WRITE_LOCK.lock().await;
    let (_board, mut idea) = match own_proposed_idea(
        state,
        &doc,
        &who,
        [
            WITHDRAW_ERR_NOT_FOUND,
            WITHDRAW_ERR_IDEA_NOT_FOUND,
            WITHDRAW_ERR_NOT_PROPOSER,
            WITHDRAW_ERR_NOT_PROPOSED,
        ],
    )
    .await
    {
        Ok(bi) => bi,
        Err(r) => return r,
    };
    idea.state = StoredIdeaState::Withdrawn;
    if let Err(e) = boards::put_idea(&state.boards_ks, &idea).await {
        return app_error_to_reject(&doc, &e);
    }
    drop(_guard);
    idea_answer(state, &doc, &who, &idea).await
}

// ─── ideas: a facilitator's ──────────────────────────────────────────────

/// Whether anyone but `who` facilitates `board_id` now (VTI-BRD-013).
async fn another_facilitator(
    state: &AppState,
    who: &Who,
    board_id: &str,
) -> Result<bool, AppError> {
    let q = ResourceQualifier::Board(board_id.to_string());
    Ok(crate::acl::list_acl_entries(&state.acl_ks)
        .await?
        .iter()
        .any(|e| e.did != who.did && e.can(Capability::BoardsManage, Some(&q))))
}

/// The idea a facilitator acts on: `notFound` / `ideaNotFound`, then `permissionDenied`.
async fn facilitated_idea(
    state: &AppState,
    doc: &TrustTask<Value>,
    who: &Who,
    not_found: &str,
    idea_not_found: &str,
) -> Result<(Board, Idea), TrustTaskOutcome> {
    let idea_id = str_of(&doc.payload, "ideaId").unwrap_or_default();
    let (board, idea) = match visible_idea(state, who, idea_id).await {
        Ok(Ok(bi)) => bi,
        Ok(Err(false)) => {
            return Err(declared(
                doc,
                not_found,
                "No board you may see holds this idea.",
            ));
        }
        Ok(Err(true)) => {
            return Err(declared(
                doc,
                idea_not_found,
                "No idea on this board you may see has this identifier.",
            ));
        }
        Err(e) => return Err(app_error_to_reject(doc, &e)),
    };
    if !who.facilitates(&board.board_id) {
        return Err(denied(doc, "you do not facilitate this board"));
    }
    Ok((board, idea))
}

/// `ideas/decide/0.1` (items 1 – 6).
async fn handle_decide(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match facilitator(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<ideas_decide::Payload>(&doc) {
        return r;
    }
    let mut _guard = boards::WRITE_LOCK.lock().await;
    let (board, mut idea) = match facilitated_idea(
        state,
        &doc,
        &who,
        DECIDE_ERR_NOT_FOUND,
        DECIDE_ERR_IDEA_NOT_FOUND,
    )
    .await
    {
        Ok(bi) => bi,
        Err(r) => return r,
    };
    let p = &doc.payload;
    let decision = str_of(p, "decision").unwrap_or_default();
    let reason = str_of(p, "reason").map(str::to_string);
    let now = Utc::now();
    // Item 1: nobody decides their own idea while another facilitator exists.
    let own_idea = who.is(&idea.proposer);
    if own_idea {
        match another_facilitator(state, &who, &board.board_id).await {
            Ok(true) => {
                return declared(
                    &doc,
                    DECIDE_ERR_OWN_IDEA,
                    "You proposed this idea; another facilitator of this board decides it.",
                );
            }
            Ok(false) => {}
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    let opening = match boards::is_opening(state, &idea).await {
        Ok(o) => o,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // An election that names this idea and stands (registered, pending or refused later).
    let has_election = match &idea.election_id {
        Some(id) => match crate::elections::store::get(state.elections.ks(), id).await {
            Ok(r) => r.is_some(),
            Err(e) => return app_error_to_reject(&doc, &e),
        },
        None => false,
    };
    let proposed = idea.state == StoredIdeaState::Proposed && !has_election;
    // Item 4: a repeated accept of an idea being opened is answered with it as it stands.
    if decision == "accept" && opening {
        drop(_guard);
        return idea_answer(state, &doc, &who, &idea).await;
    }
    let state_invalid = |why: &str| declared(&doc, DECIDE_ERR_STATE_INVALID, why.to_string());
    if board.status == BoardStatus::Archived {
        return state_invalid("This board is archived.");
    }
    let mut audit_data = BoardChangedData {
        idea_id: Some(idea.idea_id.clone()),
        own_idea,
        ..changed(&board.board_id, "")
    };
    match decision {
        "accept" => {
            if !proposed {
                return state_invalid("Only a proposed idea is accepted.");
            }
            if now >= board.voting.closes_at {
                return declared(
                    &doc,
                    DECIDE_ERR_VOTING_CLOSED,
                    "This board's voting has closed.",
                );
            }
            // A closed board opens no election (VTI-BRD-005): closing it ended its voting.
            if board.status != BoardStatus::Open {
                return declared(
                    &doc,
                    DECIDE_ERR_VOTING_CLOSED,
                    "This board is closed, and its voting has ended; no idea on it is put to a vote.",
                );
            }
            #[cfg(feature = "voting")]
            {
                // Recorded before the election is created (module docs of `crate::boards`).
                let election_id = boards::election_id_for(&board.board_id, &idea.idea_id);
                idea.election_id = Some(election_id.clone());
                idea.accepted_at = Some(now);
                idea.refusal = None;
                if let Err(e) = boards::put_idea(&state.boards_ks, &idea).await {
                    return app_error_to_reject(&doc, &e);
                }
                // The election is created over the ballot box's link: never under the board
                // lock (R1.3). The id is recorded and deterministic, so an accept racing this
                // one finds the election and is answered with the idea as it stands.
                drop(_guard);
                let opened =
                    crate::boards::ops::open_election(state, &board, &idea, &who.did, now).await;
                _guard = boards::WRITE_LOCK.lock().await;
                // Re-read: another decision may have landed while the lock was free.
                idea = match boards::get_idea(&state.boards_ks, &idea.idea_id).await {
                    Ok(Some(i)) => i,
                    Ok(None) => {
                        return declared(&doc, DECIDE_ERR_IDEA_NOT_FOUND, "No such idea.");
                    }
                    Err(e) => return app_error_to_reject(&doc, &e),
                };
                match opened {
                    Ok(_) => {}
                    Err(crate::boards::ops::OpenError::AlreadyOpening) => {
                        drop(_guard);
                        return idea_answer(state, &doc, &who, &idea).await;
                    }
                    Err(crate::boards::ops::OpenError::Refused { code, message }) => {
                        // Withdraw the id only while it still names this election and nothing
                        // created it since.
                        let still_ours = idea.election_id.as_deref() == Some(election_id.as_str());
                        let created =
                            match crate::elections::store::get(state.elections.ks(), &election_id)
                                .await
                            {
                                Ok(r) => r.is_some(),
                                Err(e) => return app_error_to_reject(&doc, &e),
                            };
                        if still_ours && !created {
                            idea.election_id = None;
                            idea.accepted_at = None;
                            idea.refusal = Some(crate::boards::Refusal {
                                code: code.clone(),
                                refused_at: now,
                            });
                            if let Err(e) = boards::put_idea(&state.boards_ks, &idea).await {
                                return app_error_to_reject(&doc, &e);
                            }
                        }
                        return reject_with_code(
                            &doc,
                            extended_code(DECIDE_ERR_ELECTION_REFUSED),
                            format!("The election was refused ({code}): {message}"),
                            None,
                        );
                    }
                    Err(crate::boards::ops::OpenError::App(e)) => {
                        return app_error_to_reject(&doc, &e);
                    }
                }
                audit_data.change = "ideaAccepted".into();
                audit_data.election_id = Some(election_id);
            }
            #[cfg(not(feature = "voting"))]
            {
                return declared(
                    &doc,
                    DECIDE_ERR_ELECTION_REFUSED,
                    "This community does not run elections.",
                );
            }
        }
        "decline" => {
            if !proposed {
                return state_invalid("Only a proposed idea is declined.");
            }
            if reason.is_none() {
                return declared(
                    &doc,
                    DECIDE_ERR_REASON_REQUIRED,
                    "Say why the idea is declined.",
                );
            }
            idea.state = StoredIdeaState::Declined;
            audit_data.change = "ideaDeclined".into();
        }
        "merge" => {
            if !proposed {
                return state_invalid("Only a proposed idea is merged.");
            }
            let target = str_of(p, "mergeInto").unwrap_or_default();
            let ok = target != idea.idea_id
                && match boards::get_idea(&state.boards_ks, target).await {
                    Ok(Some(t)) => {
                        t.board_id == board.board_id
                            && !matches!(
                                t.state,
                                StoredIdeaState::Withdrawn
                                    | StoredIdeaState::Declined
                                    | StoredIdeaState::Merged
                            )
                    }
                    Ok(None) => false,
                    Err(e) => return app_error_to_reject(&doc, &e),
                };
            if !ok {
                return declared(
                    &doc,
                    DECIDE_ERR_MERGE_TARGET_INVALID,
                    "Merge into another live idea on the same board.",
                );
            }
            idea.state = StoredIdeaState::Merged;
            audit_data.change = "ideaMerged".into();
        }
        "reopen" => {
            if idea.state != StoredIdeaState::Declined || !board.proposals.contains(now) {
                return state_invalid(
                    "Only a declined idea is reopened, while proposals are open.",
                );
            }
            idea.state = StoredIdeaState::Proposed;
            idea.decision = None;
            audit_data.change = "ideaReopened".into();
        }
        _ => return state_invalid("Unknown decision."),
    }
    if decision != "accept" && decision != "reopen" {
        idea.decision = Some(Decision {
            decided_at: now,
            reason,
            merged_into: (decision == "merge")
                .then(|| str_of(p, "mergeInto").map(str::to_string))
                .flatten(),
            slot_id: None,
            departs_from_rule: None,
            own_idea,
            decided_by: who.did.clone(),
            result_head: None,
            result_certified: None,
        });
    }
    // Item 6: audited, then stored.
    if let Err(e) = audit(state, &who.did, audit_data).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = boards::put_idea(&state.boards_ks, &idea).await {
        return app_error_to_reject(&doc, &e);
    }
    drop(_guard);
    idea_answer(state, &doc, &who, &idea).await
}

/// `ideas/select/0.1` (items 1 – 6).
async fn handle_select(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match facilitator(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<ideas_select::Payload>(&doc) {
        return r;
    }
    let _guard = boards::WRITE_LOCK.lock().await;
    let (board, mut idea) = match facilitated_idea(
        state,
        &doc,
        &who,
        SELECT_ERR_NOT_FOUND,
        SELECT_ERR_IDEA_NOT_FOUND,
    )
    .await
    {
        Ok(bi) => bi,
        Err(r) => return r,
    };
    let p = &doc.payload;
    let now = Utc::now();
    // Item 2.
    let view = match boards::view(state, &idea, true, now).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if !matches!(view.state, "open" | "selected" | "notSelected") || idea.election_id.is_none() {
        return declared(
            &doc,
            SELECT_ERR_STATE_INVALID,
            "Only an idea put to an election is selected.",
        );
    }
    let election_id = idea.election_id.clone().unwrap_or_default();
    #[cfg(feature = "voting")]
    let result = crate::boards::ops::result_for(state, &election_id, now).await;
    #[cfg(not(feature = "voting"))]
    let result: Result<Option<(Value, bool)>, String> = Ok(None);
    let (result, certified) = match result {
        Ok(Some(r)) => r,
        Ok(None) => {
            return declared(
                &doc,
                SELECT_ERR_NOT_TALLIED,
                "This idea's election has not been tallied.",
            );
        }
        Err(why) => {
            return declared(
                &doc,
                SELECT_ERR_NOT_TALLIED,
                format!("This idea's election has no result that verifies yet: {why}"),
            );
        }
    };
    let decision = str_of(p, "decision").unwrap_or_default();
    let selected = decision == "selected";
    let slot_id = str_of(p, "slotId").filter(|_| selected).map(str::to_string);
    // Item 3.
    if let Some(slot) = &slot_id {
        if !board.timetable.iter().any(|s| &s.slot_id == slot) {
            return declared(
                &doc,
                SELECT_ERR_SLOT_UNKNOWN,
                "The board's timetable has no such slot.",
            );
        }
        let taken = match boards::ideas_of(&state.boards_ks, &board.board_id).await {
            Ok(i) => i.iter().any(|o| {
                o.idea_id != idea.idea_id
                    && o.state == StoredIdeaState::Selected
                    && o.decision.as_ref().and_then(|d| d.slot_id.as_ref()) == Some(slot)
            }),
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        if taken {
            return declared(
                &doc,
                SELECT_ERR_SLOT_TAKEN,
                "Another selected idea is in that slot.",
            );
        }
    }
    let departs = p.get("departsFromRule").and_then(Value::as_bool);
    let reason = str_of(p, "reason").map(str::to_string);
    if departs == Some(true) && reason.is_none() {
        return declared(
            &doc,
            SELECT_ERR_REASON_REQUIRED,
            "Say why the decision departs from the board's selection rule.",
        );
    }
    // Item 4: with the result it was made with, read from the community's own records.
    idea.state = if selected {
        StoredIdeaState::Selected
    } else {
        StoredIdeaState::NotSelected
    };
    idea.decision = Some(Decision {
        decided_at: now,
        reason,
        merged_into: None,
        slot_id,
        departs_from_rule: departs,
        own_idea: false,
        decided_by: who.did.clone(),
        result_head: Some(result["head"].clone()),
        result_certified: Some(certified),
    });
    // Item 6, then the record. Selecting grants nothing (VTI-BRD-042).
    let data = BoardChangedData {
        idea_id: Some(idea.idea_id.clone()),
        election_id: Some(election_id),
        ..changed(
            &board.board_id,
            if selected {
                "ideaSelected"
            } else {
                "ideaNotSelected"
            },
        )
    };
    if let Err(e) = audit(state, &who.did, data).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = boards::put_idea(&state.boards_ks, &idea).await {
        return app_error_to_reject(&doc, &e);
    }
    drop(_guard);
    idea_answer(state, &doc, &who, &idea).await
}

// ─── notes ───────────────────────────────────────────────────────────────

/// At most this many notes per author in [`NOTE_WINDOW`] (VTI-BRD-020's SHOULD).
const NOTES_PER_WINDOW: usize = 10;
const NOTE_WINDOW: chrono::Duration = chrono::Duration::minutes(1);

static NOTE_TIMES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, Vec<DateTime<Utc>>>>,
> = std::sync::LazyLock::new(Default::default);

/// Whether `entry_id` may add a note now; records it when so.
fn note_allowed(entry_id: &str, now: DateTime<Utc>) -> bool {
    let mut map = NOTE_TIMES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    map.retain(|_, v| {
        v.retain(|t| now - *t < NOTE_WINDOW);
        !v.is_empty()
    });
    let times = map.entry(entry_id.to_string()).or_default();
    if times.len() >= NOTES_PER_WINDOW {
        return false;
    }
    times.push(now);
    true
}

async fn note_answer(
    state: &AppState,
    doc: &TrustTask<Value>,
    who: &Who,
    note: &Note,
) -> TrustTaskOutcome {
    let authors = match Authors::for_viewer(state, who).await {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    let facilitator = who.facilitates(&note.board_id);
    let w = boards::note_wire(state, note, who, facilitator, &authors).await;
    success_response(doc, json!({ "note": w }))
}

/// `notes/add/0.1` (items 1 – 5).
async fn handle_note_add(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let mut who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<notes_add::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let board = match visible_board(state, &who, str_of(p, "boardId").unwrap_or_default()).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            return declared(
                &doc,
                NOTES_ADD_ERR_NOT_FOUND,
                "No board you may see has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if !who.in_audience(&board) {
        return denied(
            &doc,
            "notes are added by the members this board's audience admits",
        );
    }
    if board.status != BoardStatus::Open {
        return declared(
            &doc,
            NOTES_ADD_ERR_BOARD_CLOSED,
            "This board takes no new notes.",
        );
    }
    let idea_id = str_of(p, "ideaId").map(str::to_string);
    if let Some(id) = &idea_id {
        match boards::get_idea(&state.boards_ks, id).await {
            Ok(Some(i)) if i.board_id == board.board_id => {
                if i.state == StoredIdeaState::Withdrawn {
                    return if who.facilitates(&board.board_id) || who.is(&i.proposer) {
                        declared(
                            &doc,
                            NOTES_ADD_ERR_IDEA_WITHDRAWN,
                            "This idea was withdrawn.",
                        )
                    } else {
                        declared(
                            &doc,
                            NOTES_ADD_ERR_IDEA_NOT_FOUND,
                            "No idea on this board you may see has this identifier.",
                        )
                    };
                }
            }
            Ok(_) => {
                return declared(
                    &doc,
                    NOTES_ADD_ERR_IDEA_NOT_FOUND,
                    "No idea on this board you may see has this identifier.",
                );
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    let entry_id = match own_entry(state, &who).await {
        Ok(e) => e,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    who.entry_id = Some(entry_id.clone());
    let now = Utc::now();
    if !note_allowed(&entry_id, now) {
        return declared(
            &doc,
            NOTES_ADD_ERR_RATE_LIMITED,
            "You added many notes just now; try again in a minute.",
        );
    }
    let note = Note {
        note_id: boards::new_note_id(),
        board_id: board.board_id.clone(),
        idea_id,
        author: entry_id,
        text: str_of(p, "text").map(str::to_string),
        created_at: now,
        state: NoteState::Visible,
        hidden_reason: None,
        hidden_by: None,
    };
    if let Err(e) = boards::put_note(&state.boards_ks, &note).await {
        return app_error_to_reject(&doc, &e);
    }
    note_answer(state, &doc, &who, &note).await
}

/// `notes/list/0.1` (items 1 – 3).
async fn handle_notes_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<notes_list::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let board = match visible_board(state, &who, str_of(p, "boardId").unwrap_or_default()).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            return declared(
                &doc,
                NOTES_LIST_ERR_NOT_FOUND,
                "No board you may see has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let facilitator = who.facilitates(&board.board_id);
    let idea_id = str_of(p, "ideaId");
    if let Some(id) = idea_id {
        let seen = match boards::get_idea(&state.boards_ks, id).await {
            Ok(Some(i)) => {
                i.board_id == board.board_id
                    && (i.state != StoredIdeaState::Withdrawn || facilitator || who.is(&i.proposer))
            }
            Ok(None) => false,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        if !seen {
            return declared(
                &doc,
                NOTES_LIST_ERR_IDEA_NOT_FOUND,
                "No idea on this board you may see has this identifier.",
            );
        }
    }
    let scope_all = str_of(p, "scope") == Some("all");
    let notes: Vec<Note> = match boards::notes_of(&state.boards_ks, &board.board_id).await {
        Ok(n) => n
            .into_iter()
            .filter(|n| match idea_id {
                Some(id) => n.idea_id.as_deref() == Some(id),
                None => scope_all || n.idea_id.is_none(),
            })
            .collect(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let binding = format!(
        "notes|{}|{}|{idea_id:?}|{scope_all}",
        who.did, board.board_id
    );
    let Ok(start) = offset_of(p, &binding) else {
        return declared(
            &doc,
            NOTES_LIST_ERR_CURSOR_INVALID,
            "This cursor is not this caller's for these notes.",
        );
    };
    let limit = limit_of(p);
    let start = start.min(notes.len());
    let page = &notes[start..(start + limit).min(notes.len())];
    let authors = match Authors::for_viewer(state, &who).await {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut items = Vec::with_capacity(page.len());
    for n in page {
        items.push(boards::note_wire(state, n, &who, facilitator, &authors).await);
    }
    let mut body = json!({ "notes": items });
    if start + page.len() < notes.len() {
        body["nextCursor"] = json!(cursor_for(&binding, start + page.len()));
    }
    success_response(&doc, body)
}

/// The note `note_id` where `who` may see its board.
async fn visible_note(
    state: &AppState,
    who: &Who,
    note_id: &str,
) -> Result<Option<Note>, AppError> {
    let Some(note) = boards::get_note(&state.boards_ks, note_id).await? else {
        return Ok(None);
    };
    Ok(visible_board(state, who, &note.board_id)
        .await?
        .map(|_| note))
}

/// `notes/withdraw/0.1` (items 1 – 2).
async fn handle_note_withdraw(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<notes_withdraw::Payload>(&doc) {
        return r;
    }
    let _guard = boards::WRITE_LOCK.lock().await;
    let mut note = match visible_note(
        state,
        &who,
        str_of(&doc.payload, "noteId").unwrap_or_default(),
    )
    .await
    {
        Ok(Some(n)) => n,
        Ok(None) => {
            return declared(
                &doc,
                NOTE_WITHDRAW_ERR_NOTE_NOT_FOUND,
                "No note you may see has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if !who.is(&note.author) {
        return declared(
            &doc,
            NOTE_WITHDRAW_ERR_NOT_AUTHOR,
            "You did not write this note.",
        );
    }
    if note.state == NoteState::Withdrawn {
        return declared(
            &doc,
            NOTE_WITHDRAW_ERR_ALREADY_WITHDRAWN,
            "This note is already withdrawn.",
        );
    }
    note.state = NoteState::Withdrawn;
    if let Err(e) = boards::put_note(&state.boards_ks, &note).await {
        return app_error_to_reject(&doc, &e);
    }
    drop(_guard);
    note_answer(state, &doc, &who, &note).await
}

/// `notes/hide/0.1` (items 1 – 3).
async fn handle_note_hide(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match facilitator(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<notes_hide::Payload>(&doc) {
        return r;
    }
    let _guard = boards::WRITE_LOCK.lock().await;
    let mut note = match visible_note(
        state,
        &who,
        str_of(&doc.payload, "noteId").unwrap_or_default(),
    )
    .await
    {
        Ok(Some(n)) => n,
        Ok(None) => {
            return declared(
                &doc,
                HIDE_ERR_NOTE_NOT_FOUND,
                "No note you may see has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if !who.facilitates(&note.board_id) {
        return denied(&doc, "you do not facilitate this note's board");
    }
    let hide = str_of(&doc.payload, "action") == Some("hide");
    let change = if hide {
        if note.state != NoteState::Visible {
            return declared(
                &doc,
                HIDE_ERR_STATE_INVALID,
                "Only a visible note is hidden.",
            );
        }
        let Some(reason) = str_of(&doc.payload, "reason") else {
            return declared(
                &doc,
                HIDE_ERR_REASON_REQUIRED,
                "Say why the note is hidden.",
            );
        };
        note.state = NoteState::Hidden;
        note.hidden_reason = Some(reason.to_string());
        note.hidden_by = Some(who.did.clone());
        "noteHidden"
    } else {
        if note.state != NoteState::Hidden {
            return declared(
                &doc,
                HIDE_ERR_STATE_INVALID,
                "Only a hidden note is shown again.",
            );
        }
        note.state = NoteState::Visible;
        note.hidden_reason = None;
        note.hidden_by = None;
        "noteShown"
    };
    let data = BoardChangedData {
        note_id: Some(note.note_id.clone()),
        idea_id: note.idea_id.clone(),
        ..changed(&note.board_id, change)
    };
    if let Err(e) = audit(state, &who.did, data).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = boards::put_note(&state.boards_ks, &note).await {
        return app_error_to_reject(&doc, &e);
    }
    drop(_guard);
    note_answer(state, &doc, &who, &note).await
}
