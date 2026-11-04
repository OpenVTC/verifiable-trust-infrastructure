//! Community boards (`vtc/boards/*`, VTI-BRD-001 – 080): shared spaces where members propose
//! ideas and leave notes, each idea a facilitator accepts is put to an election of its own, and
//! the board's facilitators select among them.
//!
//! # What is kept here, and what is not
//!
//! A board, its ideas and its notes live in the `boards` keyspace. An accepted idea keeps only
//! the identifier of its election and when it was accepted: where the election stands — being
//! registered, refused, open, cancelled, its ballot count and its result — is read from the
//! election's own record (`crate::elections`) every time, never copied here. Nothing here
//! records or reports whether anyone took a ticket or cast a ballot (VTI-BRD-033); the
//! community's registrar records tickets, and the ballot box ballots, as for any election.
//!
//! # Who may do what
//!
//! A board is seen by its facilitators (`vtc.boards.manage`, unqualified or `board:<boardId>`)
//! and by the active members its audience admits (VTI-BRD-003). Proposing, editing and
//! withdrawing one's own idea, and adding and withdrawing one's own note, are a member's acts
//! and may be signed by the portal's delegated key (VTI-BRD-050); deciding, selecting and
//! hiding are a facilitator's and never are (VTI-BRD-051).
//!
//! # Ordering
//!
//! Accepting an idea records the election's identifier on the idea **before** the election is
//! created, so a crash between the two leaves an idea that names an election the community
//! never created — read as `proposed`, accepted again by the next `accept` — never an election
//! no idea names. The election module's sweeper is the one retry owner of its registration.

#[cfg(feature = "voting")]
pub mod ops;

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::acl::{Capability, ResourceQualifier, VtcAclEntry};
use crate::elections::store::{ElectionRecord, Standing as ElectionStanding};
use crate::server::AppState;

/// The prefix every election opened for an idea carries: `board.<boardId>.<ideaId>`.
/// `[boards]`: host configuration for the community's boards.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardsConfig {
    /// How long a deleted board's tombstones are kept (VTI-BRD-008): a number of days — `0`
    /// keeps none, so deleting a board removes everything — or `"forever"`. Default 365.
    #[serde(default)]
    pub tombstone_retention: TombstoneRetention,
}

impl BoardsConfig {
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// How long a deleted board's tombstones are kept (VTI-BRD-008).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum TombstoneRetention {
    /// This many days from the deletion; `0` keeps none.
    Days(u32),
    /// Never removed: `"forever"`.
    Forever(Forever),
}

/// The word `forever`, and only it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Forever {
    Forever,
}

impl Default for TombstoneRetention {
    /// Twelve months (VTI-BRD-008's SHOULD).
    fn default() -> Self {
        Self::Days(365)
    }
}

impl TombstoneRetention {
    /// Whether any tombstone is kept.
    #[must_use]
    pub fn keeps(self) -> bool {
        self != Self::Days(0)
    }

    /// When a tombstone kept at `deleted_at` is removed; `None` for ever.
    #[must_use]
    pub fn remove_at(self, deleted_at: DateTime<Utc>) -> Option<DateTime<Utc>> {
        match self {
            Self::Days(d) => Some(deleted_at + chrono::Duration::days(i64::from(d))),
            Self::Forever(_) => None,
        }
    }

    /// In words, for the person deleting a board.
    #[must_use]
    pub fn describe(self) -> String {
        match self {
            Self::Days(0) => "not kept".into(),
            Self::Days(1) => "kept for 1 day".into(),
            Self::Days(d) => format!("kept for {d} days"),
            Self::Forever(_) => "kept for ever".into(),
        }
    }
}

pub const ELECTION_PREFIX: &str = "board.";

/// The election an idea is put to.
#[must_use]
pub fn election_id_for(board_id: &str, idea_id: &str) -> String {
    format!("{ELECTION_PREFIX}{board_id}.{idea_id}")
}

/// Whether `election_id` was opened for a board's idea.
#[must_use]
pub fn is_board_election(election_id: &str) -> bool {
    election_id.starts_with(ELECTION_PREFIX)
}

fn new_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    use base64::Engine as _;
    format!(
        "{prefix}_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

#[must_use]
pub fn new_board_id() -> String {
    new_id("brd")
}
#[must_use]
pub fn new_idea_id() -> String {
    new_id("ida")
}
#[must_use]
pub fn new_note_id() -> String {
    new_id("bnt")
}

// ─── records ─────────────────────────────────────────────────────────────

/// `BoardStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BoardStatus {
    Open,
    Closed,
    Archived,
}

impl BoardStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Archived => "archived",
        }
    }
}

/// `BoardAudience`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum BoardAudience {
    Members,
    #[serde(rename_all = "camelCase")]
    Group {
        group_id: String,
    },
}

/// `Window`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Window {
    pub opens_at: DateTime<Utc>,
    pub closes_at: DateTime<Utc>,
}

impl Window {
    #[must_use]
    pub fn contains(&self, t: DateTime<Utc>) -> bool {
        self.opens_at <= t && t < self.closes_at
    }
}

/// `Slot`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Slot {
    pub slot_id: String,
    pub label: String,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
}

/// One board (VTI-BRD-001).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Board {
    pub board_id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub status: BoardStatus,
    pub audience: BoardAudience,
    pub proposals: Window,
    pub voting: Window,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub topics: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub formats: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ideas_per_member: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timetable: Vec<Slot>,
    /// The `ElectionTemplate`, as received and checked.
    pub template: Value,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

/// Where an idea stands **as stored**. `open` is never stored: an idea is open when the
/// election it names is registered, read from that election's record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StoredIdeaState {
    Proposed,
    Selected,
    NotSelected,
    Declined,
    Merged,
    Withdrawn,
}

/// A facilitator's decision on an idea (`IdeaDecision`), with — for a selection — the result it
/// was made with (VTI-BRD-040).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub decided_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merged_into: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub departs_from_rule: Option<bool>,
    #[serde(default)]
    pub own_idea: bool,
    /// The facilitator who decided: audited, never shown to the audience.
    pub decided_by: String,
    /// A selection's result: the head it was computed from, and whether it was certified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_head: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_certified: Option<bool>,
}

/// An election refused before an idea opened (`IdeaOpening.refusal`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Refusal {
    pub code: String,
    pub refused_at: DateTime<Utc>,
}

/// One idea (VTI-BRD-010).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Idea {
    pub idea_id: String,
    pub board_id: String,
    pub state: StoredIdeaState,
    /// `None` once erased (VTI-BRD-060).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// The proposer's directory entry, never their DID.
    pub proposer: String,
    pub proposed_at: DateTime<Utc>,
    /// The election accepting it opened, and when.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub election_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<DateTime<Utc>>,
    /// The last acceptance's refusal, where the ballot box refused it at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Refusal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
}

/// `NoteState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NoteState {
    Visible,
    Withdrawn,
    Hidden,
}

/// One note (VTI-BRD-020).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    pub note_id: String,
    pub board_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idea_id: Option<String>,
    /// The author's directory entry.
    pub author: String,
    /// `None` once erased (VTI-BRD-060).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub created_at: DateTime<Utc>,
    pub state: NoteState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden_by: Option<String>,
}

// ─── store ───────────────────────────────────────────────────────────────

const BOARD: &str = "board:";
const IDEA: &str = "idea:";
const NOTE: &str = "note:";

fn board_key(id: &str) -> String {
    format!("{BOARD}{id}")
}
fn idea_key(board_id: &str, idea_id: &str) -> String {
    format!("{IDEA}{board_id}:{idea_id}")
}
fn idea_index(idea_id: &str) -> String {
    format!("ideaof:{idea_id}")
}
fn note_key(board_id: &str, note_id: &str) -> String {
    format!("{NOTE}{board_id}:{note_id}")
}
fn note_index(note_id: &str) -> String {
    format!("noteof:{note_id}")
}

fn parse<T: serde::de::DeserializeOwned>(what: &str, v: &[u8]) -> Result<T, AppError> {
    serde_json::from_slice(v)
        .map_err(|e| AppError::Internal(format!("a {what} does not parse: {e}")))
}

/// # Errors
/// A store failure.
pub async fn get_board(ks: &KeyspaceHandle, board_id: &str) -> Result<Option<Board>, AppError> {
    ks.get(board_key(board_id)).await
}

/// # Errors
/// A store failure.
pub async fn put_board(ks: &KeyspaceHandle, b: &Board) -> Result<(), AppError> {
    ks.insert(board_key(&b.board_id), b).await
}

/// Every board.
///
/// # Errors
/// A store failure, or a record that does not parse.
pub async fn all_boards(ks: &KeyspaceHandle) -> Result<Vec<Board>, AppError> {
    ks.prefix_iter_raw(BOARD)
        .await?
        .into_iter()
        .map(|(_, v)| parse("board", &v))
        .collect()
}

/// # Errors
/// A store failure.
pub async fn get_idea(ks: &KeyspaceHandle, idea_id: &str) -> Result<Option<Idea>, AppError> {
    let Some(board_id): Option<String> = ks.get(idea_index(idea_id)).await? else {
        return Ok(None);
    };
    ks.get(idea_key(&board_id, idea_id)).await
}

/// # Errors
/// A store failure.
pub async fn put_idea(ks: &KeyspaceHandle, i: &Idea) -> Result<(), AppError> {
    ks.insert(idea_index(&i.idea_id), &i.board_id).await?;
    ks.insert(idea_key(&i.board_id, &i.idea_id), i).await
}

/// Every idea on `board_id`.
///
/// # Errors
/// A store failure, or a record that does not parse.
pub async fn ideas_of(ks: &KeyspaceHandle, board_id: &str) -> Result<Vec<Idea>, AppError> {
    ks.prefix_iter_raw(format!("{IDEA}{board_id}:"))
        .await?
        .into_iter()
        .map(|(_, v)| parse("idea", &v))
        .collect()
}

/// Every idea on every board.
///
/// # Errors
/// A store failure, or a record that does not parse.
pub async fn all_ideas(ks: &KeyspaceHandle) -> Result<Vec<Idea>, AppError> {
    ks.prefix_iter_raw(IDEA)
        .await?
        .into_iter()
        .map(|(_, v)| parse("idea", &v))
        .collect()
}

/// # Errors
/// A store failure.
pub async fn get_note(ks: &KeyspaceHandle, note_id: &str) -> Result<Option<Note>, AppError> {
    let Some(board_id): Option<String> = ks.get(note_index(note_id)).await? else {
        return Ok(None);
    };
    ks.get(note_key(&board_id, note_id)).await
}

/// # Errors
/// A store failure.
pub async fn put_note(ks: &KeyspaceHandle, n: &Note) -> Result<(), AppError> {
    ks.insert(note_index(&n.note_id), &n.board_id).await?;
    ks.insert(note_key(&n.board_id, &n.note_id), n).await
}

/// Every note on `board_id`, oldest first.
///
/// # Errors
/// A store failure, or a record that does not parse.
pub async fn notes_of(ks: &KeyspaceHandle, board_id: &str) -> Result<Vec<Note>, AppError> {
    let mut notes: Vec<Note> = ks
        .prefix_iter_raw(format!("{NOTE}{board_id}:"))
        .await?
        .into_iter()
        .map(|(_, v)| parse("note", &v))
        .collect::<Result<_, _>>()?;
    notes.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.note_id.cmp(&b.note_id))
    });
    Ok(notes)
}

/// Every note on every board.
///
/// # Errors
/// Remove `board_id`, every idea and every note on it, with their indexes (VTI-BRD-007).
/// Returns how many ideas and notes went. The caller deals with the ideas' elections first.
///
/// # Errors
/// A store failure.
pub async fn remove_board(ks: &KeyspaceHandle, board_id: &str) -> Result<(usize, usize), AppError> {
    let ideas = ideas_of(ks, board_id).await?;
    for i in &ideas {
        ks.remove(idea_key(board_id, &i.idea_id)).await?;
        ks.remove(idea_index(&i.idea_id)).await?;
    }
    let notes = notes_of(ks, board_id).await?;
    for n in &notes {
        ks.remove(note_key(board_id, &n.note_id)).await?;
        ks.remove(note_index(&n.note_id)).await?;
    }
    ks.remove(board_key(board_id)).await?;
    Ok((ideas.len(), notes.len()))
}

/// A store failure, or a record that does not parse.
pub async fn all_notes(ks: &KeyspaceHandle) -> Result<Vec<Note>, AppError> {
    ks.prefix_iter_raw(NOTE)
        .await?
        .into_iter()
        .map(|(_, v)| parse("note", &v))
        .collect()
}

/// Serialises every board write that reads before it writes (a proposal's limit, an
/// acceptance, a selection's slot).
pub static WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ─── who is asking ───────────────────────────────────────────────────────

/// The caller's standing towards boards, read from the live records on every request.
pub struct Who {
    pub did: String,
    /// Their directory entry, where they have one.
    pub entry_id: Option<String>,
    pub active_member: bool,
    /// The groups they belong to, active.
    pub member_of: BTreeSet<String>,
    entry: Option<VtcAclEntry>,
}

impl Who {
    /// # Errors
    /// A store failure.
    pub async fn read(state: &AppState, did: &str) -> Result<Self, AppError> {
        let g = crate::groups::Standing::read(state, did).await?;
        let entry = crate::acl::get_acl_entry(&state.acl_ks, did).await?;
        Ok(Self {
            did: did.to_string(),
            entry_id: g.entry_id,
            active_member: g.active_member,
            member_of: g.member_of,
            entry,
        })
    }

    /// Holds `vtc.boards.manage` unqualified.
    #[must_use]
    pub fn manages_all(&self) -> bool {
        self.can(Capability::BoardsManage)
    }

    /// Holds `cap` unqualified.
    #[must_use]
    pub fn can(&self, cap: Capability) -> bool {
        self.entry.as_ref().is_some_and(|e| e.can(cap, None))
    }

    /// Facilitates `board_id`: `vtc.boards.manage` unqualified or `board:<boardId>`.
    #[must_use]
    pub fn facilitates(&self, board_id: &str) -> bool {
        self.entry.as_ref().is_some_and(|e| {
            e.can(
                Capability::BoardsManage,
                Some(&ResourceQualifier::Board(board_id.to_string())),
            )
        })
    }

    /// Facilitates any board (unqualified, or by any `board:` qualifier).
    #[must_use]
    pub fn facilitates_any(&self) -> bool {
        self.entry
            .as_ref()
            .is_some_and(|e| e.can_any(Capability::BoardsManage))
    }

    /// In `board`'s audience now (VTI-BRD-003).
    #[must_use]
    pub fn in_audience(&self, board: &Board) -> bool {
        self.active_member
            && match &board.audience {
                BoardAudience::Members => true,
                BoardAudience::Group { group_id } => self.member_of.contains(group_id),
            }
    }

    /// May see `board` at all (VTI-BRD-003).
    #[must_use]
    pub fn sees(&self, board: &Board) -> bool {
        self.facilitates(&board.board_id) || self.in_audience(board)
    }

    /// Whether this caller wrote what `entry_id` names.
    #[must_use]
    pub fn is(&self, entry_id: &str) -> bool {
        self.entry_id.as_deref() == Some(entry_id)
    }
}

// ─── where an idea stands ────────────────────────────────────────────────

/// An idea's state as shown (`IdeaState`), with what the election record says about it.
pub struct IdeaView {
    pub state: &'static str,
    /// The election, once registered (`IdeaElection`).
    pub election: Option<Value>,
    /// Facilitators only: an acceptance not yet registered (`IdeaOpening`).
    pub opening: Option<Value>,
}

fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The latest board head's tree size, where the manifest's board is public and voting is open
/// (VTI-BRD-033), with when the head was issued.
fn ballots_on_board(rec: &ElectionRecord, now: DateTime<Utc>) -> Option<(u64, Value)> {
    if rec.state(now) != "voting" || rec.manifest["board"]["visibility"] != "public" {
        return None;
    }
    let head = &rec.checkpoints.last()?["head"];
    Some((head["treeSize"].as_u64()?, head["issuedAt"].clone()))
}

/// The election as a board shows it (`IdeaElection`): never who took a ticket or cast a ballot.
fn election_wire(rec: &ElectionRecord, now: DateTime<Utc>) -> Value {
    let result = rec
        .certified
        .as_ref()
        .map(|c| (c["result"].clone(), true))
        .or_else(|| rec.verified.as_ref().map(|v| (v["result"].clone(), false)));
    let state = if result.is_some() {
        "tallied"
    } else {
        match rec.state(now) {
            "pendingRegistration" | "registrationRefused" => "registered",
            s => s,
        }
    };
    let mut out = json!({ "electionId": rec.election_id, "state": state });
    if let Some((n, at)) = ballots_on_board(rec, now) {
        out["ballotsOnBoard"] = json!(n);
        if at.is_string() {
            out["boardHeadIssuedAt"] = at;
        }
    }
    if let Some((result, certified)) = result {
        out["result"] = result;
        out["certified"] = json!(certified);
    }
    out
}

/// Where `idea` stands, read from its election's record (module docs).
///
/// # Errors
/// A store failure.
pub async fn view(
    state: &AppState,
    idea: &Idea,
    facilitator: bool,
    now: DateTime<Utc>,
) -> Result<IdeaView, AppError> {
    let rec = match &idea.election_id {
        Some(id) => crate::elections::store::get(state.elections.ks(), id).await?,
        None => None,
    };
    let stored = match idea.state {
        StoredIdeaState::Proposed => "proposed",
        StoredIdeaState::Selected => "selected",
        StoredIdeaState::NotSelected => "notSelected",
        StoredIdeaState::Declined => "declined",
        StoredIdeaState::Merged => "merged",
        StoredIdeaState::Withdrawn => "withdrawn",
    };
    let refusal_wire = |r: &Refusal| json!({ "code": r.code, "refusedAt": stamp(r.refused_at) });
    match (idea.state, rec) {
        (StoredIdeaState::Proposed, Some(rec)) => match rec.standing {
            ElectionStanding::PendingRegistration | ElectionStanding::RegistrationRefused => {
                let opening = facilitator.then(|| {
                    let mut o = json!({
                        "electionId": rec.election_id,
                        "startedAt": stamp(idea.accepted_at.unwrap_or(rec.created_at)),
                    });
                    if let Some(r) = &rec.refusal {
                        o["refusal"] = json!({
                            "code": r.code,
                            "refusedAt": stamp(rec.delivery.as_ref().map_or(rec.created_at, |d| d.next_at)),
                        });
                    }
                    o
                });
                Ok(IdeaView {
                    state: "proposed",
                    election: None,
                    opening,
                })
            }
            // An idea whose election is cancelled is not selected (VTI-BRD-032).
            ElectionStanding::Cancelled => Ok(IdeaView {
                state: "notSelected",
                election: Some(election_wire(&rec, now)),
                opening: None,
            }),
            _ => Ok(IdeaView {
                state: "open",
                election: Some(election_wire(&rec, now)),
                opening: None,
            }),
        },
        (_, rec) => Ok(IdeaView {
            state: stored,
            election: rec.as_ref().map(|r| election_wire(r, now)),
            opening: match (&idea.refusal, facilitator, idea.state) {
                (Some(r), true, StoredIdeaState::Proposed) => Some(json!({
                    "electionId": election_id_for(&idea.board_id, &idea.idea_id),
                    "startedAt": stamp(r.refused_at),
                    "refusal": refusal_wire(r),
                })),
                _ => None,
            },
        }),
    }
}

/// Whether an accepted idea is still being opened: its election names it but is not
/// registered.
///
/// # Errors
/// A store failure.
pub async fn is_opening(state: &AppState, idea: &Idea) -> Result<bool, AppError> {
    let Some(id) = &idea.election_id else {
        return Ok(false);
    };
    Ok(crate::elections::store::get(state.elections.ks(), id)
        .await?
        .is_some_and(|r| r.standing == ElectionStanding::PendingRegistration))
}

// ─── authors ─────────────────────────────────────────────────────────────

/// Projects authors as the directory shows them to one viewer (`Author`).
pub struct Authors {
    viewer: Option<crate::directory::project::Viewer>,
    viewer_entry: Option<String>,
}

impl Authors {
    /// # Errors
    /// A store failure.
    pub async fn for_viewer(state: &AppState, who: &Who) -> Result<Self, AppError> {
        Ok(Self {
            viewer: Some(crate::directory::read::viewer(state, &who.did).await?),
            viewer_entry: who.entry_id.clone(),
        })
    }

    /// `entry_id` as this viewer may see them. A departed member is `formerMember` with
    /// nothing else (VTI-BRD-060).
    pub async fn author(&self, state: &AppState, entry_id: &str) -> Value {
        let card = crate::directory::cards::get(state.directory.ks(), entry_id)
            .await
            .ok()
            .flatten();
        let active = match &card {
            Some(c) => crate::member_portal::active::active_member(state, &c.did)
                .await
                .ok()
                .flatten()
                .is_some(),
            None => false,
        };
        if !active {
            return json!({ "formerMember": true });
        }
        let mut out = json!({ "entryId": entry_id });
        if self.viewer_entry.as_deref() == Some(entry_id) {
            out["you"] = json!(true);
        }
        if let Some(v) = &self.viewer {
            use crate::directory::read::{ShowBy, show};
            if let Ok(entry) = show(state, v, &ShowBy::Entry(entry_id.to_string())).await {
                let name = &entry["fields"]["displayName"];
                let name = name.as_str().or_else(|| name["value"].as_str());
                if let Some(n) = name.filter(|n| !n.is_empty()) {
                    out["name"] = json!(n.chars().take(200).collect::<String>());
                }
            }
        }
        out
    }
}

// ─── wire forms ──────────────────────────────────────────────────────────

/// `Board` for `who`.
///
/// # Errors
/// A store failure.
pub async fn board_wire(state: &AppState, board: &Board, who: &Who) -> Result<Value, AppError> {
    let facilitator = who.facilitates(&board.board_id);
    let now = Utc::now();
    let mut counts = serde_json::Map::new();
    for idea in ideas_of(&state.boards_ks, &board.board_id).await? {
        if idea.state == StoredIdeaState::Withdrawn && !facilitator && !who.is(&idea.proposer) {
            continue;
        }
        let v = view(state, &idea, facilitator, now).await?;
        let n = counts.entry(v.state).or_insert(json!(0));
        *n = json!(n.as_u64().unwrap_or(0) + 1);
    }
    let mut out = json!({
        "boardId": board.board_id,
        "title": board.title,
        "status": board.status.as_str(),
        "audience": board.audience,
        "proposals": board.proposals,
        "voting": board.voting,
        "template": board.template,
        "createdAt": stamp(board.created_at),
        "facilitator": facilitator,
        "ideaCounts": counts,
    });
    for (k, v) in [
        ("description", board.description.as_ref().map(|d| json!(d))),
        (
            "selectionRule",
            board.selection_rule.as_ref().map(|d| json!(d)),
        ),
        (
            "maxIdeasPerMember",
            board.max_ideas_per_member.map(|n| json!(n)),
        ),
        (
            "topics",
            (!board.topics.is_empty()).then(|| json!(board.topics)),
        ),
        (
            "formats",
            (!board.formats.is_empty()).then(|| json!(board.formats)),
        ),
        (
            "timetable",
            (!board.timetable.is_empty()).then(|| json!(board.timetable)),
        ),
    ] {
        if let Some(v) = v {
            out[k] = v;
        }
    }
    // Windows and slots in whole seconds, as every instant this community writes.
    for w in ["proposals", "voting"] {
        for e in ["opensAt", "closesAt"] {
            if let Some(t) = out[w][e]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            {
                out[w][e] = json!(stamp(t.with_timezone(&Utc)));
            }
        }
    }
    if let Some(slots) = out["timetable"].as_array_mut() {
        for s in slots {
            for e in ["startsAt", "endsAt"] {
                if let Some(t) = s[e]
                    .as_str()
                    .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                {
                    s[e] = json!(stamp(t.with_timezone(&Utc)));
                }
            }
        }
    }
    Ok(out)
}

/// `Idea` for a viewer.
///
/// # Errors
/// A store failure.
pub async fn idea_wire(
    state: &AppState,
    idea: &Idea,
    facilitator: bool,
    authors: &Authors,
    note_count: usize,
) -> Result<Value, AppError> {
    let now = Utc::now();
    let v = view(state, idea, facilitator, now).await?;
    let mut out = json!({
        "ideaId": idea.idea_id,
        "boardId": idea.board_id,
        "state": v.state,
        "title": idea.title.clone().unwrap_or_else(|| "(removed)".into()),
        "description": idea.description.clone().unwrap_or_else(|| "(removed)".into()),
        "proposer": authors.author(state, &idea.proposer).await,
        "proposedAt": stamp(idea.proposed_at),
        "noteCount": note_count,
    });
    if let Some(f) = &idea.format {
        out["format"] = json!(f);
    }
    if let Some(t) = &idea.topic {
        out["topic"] = json!(t);
    }
    if let Some(e) = v.election {
        out["election"] = e;
    }
    if let Some(o) = v.opening {
        out["opening"] = o;
    }
    if let Some(d) = &idea.decision {
        let mut dw = json!({ "decidedAt": stamp(d.decided_at) });
        if let Some(r) = &d.reason {
            dw["reason"] = json!(r);
        }
        if let Some(m) = &d.merged_into {
            dw["mergedInto"] = json!(m);
        }
        if let Some(s) = &d.slot_id {
            dw["slotId"] = json!(s);
        }
        if let Some(b) = d.departs_from_rule {
            dw["departsFromRule"] = json!(b);
        }
        if d.own_idea {
            dw["ownIdea"] = json!(true);
        }
        out["decision"] = dw;
    }
    Ok(out)
}

/// Whether `who` may read `note`'s text (VTI-BRD-021).
#[must_use]
pub fn reads_text(note: &Note, who: &Who, facilitator: bool) -> bool {
    note.state == NoteState::Visible || facilitator || who.is(&note.author)
}

/// `Note` for a viewer.
pub async fn note_wire(
    state: &AppState,
    note: &Note,
    who: &Who,
    facilitator: bool,
    authors: &Authors,
) -> Value {
    let mut out = json!({
        "noteId": note.note_id,
        "boardId": note.board_id,
        "author": authors.author(state, &note.author).await,
        "createdAt": stamp(note.created_at),
        "state": match note.state {
            NoteState::Visible => "visible",
            NoteState::Withdrawn => "withdrawn",
            NoteState::Hidden => "hidden",
        },
    });
    if let Some(i) = &note.idea_id {
        out["ideaId"] = json!(i);
    }
    if reads_text(note, who, facilitator)
        && let Some(t) = &note.text
    {
        out["text"] = json!(t);
    }
    if let Some(r) = &note.hidden_reason
        && note.state == NoteState::Hidden
    {
        out["hiddenReason"] = json!(r);
    }
    out
}

// ─── departure ───────────────────────────────────────────────────────────

/// A member's departure (VTI-BRD-060): every idea of theirs still proposed and not being
/// opened is withdrawn; on erasure (`erase`), the text of their notes and of their ideas that
/// no election carries is removed.
///
/// # Errors
/// A store failure.
pub async fn on_departure(
    state: &AppState,
    entry_id: &str,
    erase: bool,
) -> Result<usize, AppError> {
    let _guard = WRITE_LOCK.lock().await;
    let ks = &state.boards_ks;
    let mut withdrawn = 0;
    for mut idea in all_ideas(ks).await? {
        if idea.proposer != entry_id {
            continue;
        }
        let mut changed = false;
        if idea.state == StoredIdeaState::Proposed && idea.election_id.is_none() {
            idea.state = StoredIdeaState::Withdrawn;
            withdrawn += 1;
            changed = true;
        }
        if erase && idea.election_id.is_none() {
            idea.title = None;
            idea.description = None;
            changed = true;
        }
        if changed {
            put_idea(ks, &idea).await?;
        }
    }
    if erase {
        for mut note in all_notes(ks).await? {
            if note.author == entry_id && note.text.is_some() {
                note.text = None;
                put_note(ks, &note).await?;
            }
        }
    }
    Ok(withdrawn)
}
