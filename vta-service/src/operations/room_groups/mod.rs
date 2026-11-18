//! A member's MLS group for each room they belong to.
//!
//! The custody half of the room oracle. [`crate::operations::room_oracle`] mints
//! presentations from credentials; this holds the *keys*, which is what
//! `rooms/keys/open` needs and what nothing before this stored.
//!
//! # Three steps, and the third is the one people forget
//!
//! A group arrives once and then has to be kept current:
//!
//! 1. [`mint_key_package`] — the joining side produces something the owner can add.
//! 2. [`join`] — the owner's Welcome arrives and the group exists.
//! 3. [`apply_commit`] — every membership change after that. **This is not optional.** A
//!    member who misses one is stuck at their last epoch and can open nothing sealed after
//!    it, and the symptom is "this record does not open", which reads like corruption
//!    rather than a missed message.
//!
//! # What authorizes each
//!
//! Deliberately three different answers, because they are three different acts:
//!
//! - **Minting** is gated on holding an invitation, because minting retains a private key
//!   against a Welcome that may never come. A key-holder that minted for any room on any
//!   request is one anyone can fill.
//! - **Joining** is gated on that same invitation, *consumed*. This is where the design's
//!   "joining is consent" stops being ceremonial: a Welcome carries a group's secrets, and
//!   a recipient that accepts an uninvited one has made the invitation decorative.
//! - **Committing** is gated *inside the group* — MLS authenticates the committer as a
//!   member of the group we already hold. Never from an ACL of our own, which is the same
//!   rule the rest of the room family follows.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use vti_common::error::AppError;
use vti_common::store::{KeyspaceHandle, MoveOutcome};
use vti_rooms::error::RoomKeyError;
use vti_rooms::mls::{GroupSnapshot, IdentitySnapshot, RoomGroup};
use vti_rooms::sealed::SealedRoom;
use vti_rooms::wire::EpochLink;
/// One member's place in one room: the key everything here is stored under.
///
/// # Per (room, persona), never per room
///
/// One VTA serves several principals, and one person may hold several personas, so two
/// members of one room can share a key holder — a family on one VTA, a team on a company
/// VTA. Each is a different leaf in the room's MLS group with different secrets, so each
/// has its own group state, pending KeyPackage, pending advance, epoch chain and root
/// memory. Keyed by room alone, the second member's Welcome was refused as a second join.
///
/// Constructed by [`Member::new`], which refuses identifiers that would make the storage
/// key ambiguous. *Which* persona a request acts as is not decided here — that is
/// [`crate::operations::room_member`], where the caller's contexts are known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    room_id: String,
    persona: String,
}

impl Member {
    /// `room_id` and `persona` are DIDs, and a DID has no `/` — which is what makes
    /// `<kind>/<room>/<persona>` unambiguous, so anything carrying one is refused rather
    /// than stored under a key another pair could also produce.
    pub fn new(room_id: &str, persona: &str) -> Result<Self, AppError> {
        for (what, v) in [("room id", room_id), ("member DID", persona)] {
            if v.is_empty() || v.contains('/') {
                return Err(AppError::Validation(format!(
                    "`{v}` is not a usable {what}: a DID is non-empty and has no `/`"
                )));
            }
        }
        Ok(Self {
            room_id: room_id.to_string(),
            persona: persona.to_string(),
        })
    }

    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    /// The persona DID: the member's identity in the room, and their MLS leaf.
    pub fn persona(&self) -> &str {
        &self.persona
    }

    fn key(&self, kind: &str) -> String {
        format!("{kind}/{}/{}", self.room_id, self.persona)
    }
}

/// Group state, per member: `room-group/<roomId>/<persona>`.
const GROUP: &str = "room-group";

/// A pending KeyPackage, per member: `room-kp/<roomId>/<persona>`.
const KEY_PACKAGE: &str = "room-kp";

/// The one pending epoch advance, per member: `room-advance/<roomId>/<persona>`.
///
/// **One key, so one slot.** `rooms/owner/group/{add,remove}/0.1` item 3: a key holder
/// holds at most one pending advance per room — per group it holds, which is per member.
/// Two would be two candidate successors of the same live group, of which the host can
/// accept at most one; keeping both under one key makes the second unrepresentable rather
/// than merely unlikely.
const ADVANCE: &str = "room-advance";

/// What hosts have said about the room's tree, per member: `room-roots/<roomId>/<persona>`.
const ROOTS: &str = "room-roots";

/// That a commit removed this member, per member: `room-removed/<roomId>/<persona>`.
///
/// Written when [`apply_commit`] processes the commit that removes the member's own leaf.
/// While it stands the member has no current epoch: nothing is sealed under the group it
/// sits beside (`noGroup` for seal and file-key-to-seal), which only opens what it could.
/// The group state stays as it was (what was readable before the removal still is), so
/// without this row the group alone says only "behind", and every record sealed after the
/// removal read as a commit somebody had not delivered — whose remedy, applying commits,
/// can never work.
///
/// **Group state with this row is a prior membership, not a join** (`rooms/keys/welcome/0.1`,
/// `rooms/keys/open/0.2`): a Welcome for the member after it re-admits them, and [`join`]
/// moves the group and this row's epoch into [`PRIOR`] and clears the row. A member removed
/// while idle has no such row; [`join`] then learns of the removal from the Welcome's tree.
const REMOVED: &str = "room-removed";

/// The member's earlier memberships of the room, each ended by a removal, per member:
/// `room-prior/<roomId>/<persona>` — one row holding a list, oldest first
/// ([`PriorMembership`]).
///
/// A member removed, admitted again, and removed again holds one entry per removal. Each
/// opens the epochs from its join epoch ([`JOINED`]) up to, not including, its removal
/// epoch, as far as its chain reaches (`rooms/keys/open/0.2`, `rooms/keys/file-key/0.2`):
/// what was readable before a removal stays readable after a re-admission, an epoch between
/// a removal and the next join is `removed`, one below the first join is `beyondChain`, and
/// nothing is ever sealed under prior state.
///
/// In [`ROOM_GROUPS`](crate::keyspaces::ROOM_GROUPS) beside the current group, under the same
/// storage encryption and carried by a backup with it; discarded by [`forget`] with the
/// group, and subject to the room's epoch floor (`rooms/epoch/prune/0.2`):
/// [`apply_epoch_floor`] drops its rungs at or below the floor, and the whole entry once
/// every epoch it opened is below it. Never matched by the `room-group/` prefix
/// [`held_members`] and [`holders`] list by.
const PRIOR: &str = "room-prior";

/// The room epoch the member's current membership was joined at, per member:
/// `room-joined/<roomId>/<persona>` — written by [`join`] with the group it describes, and
/// carried into [`PriorMembership::joined_epoch`] when a later re-admission ends that
/// membership. A prior membership covers the epochs from its join epoch up to, not
/// including, its removal epoch (`rooms/keys/open/0.2`); an epoch below the first join
/// epoch is `beyondChain`. Absent for a group joined before the row existed, or founded by
/// [`create_group`]; the earliest epoch the chain reaches then stands in for it.
const JOINED: &str = "room-joined";

/// The room's epoch floor as this member's key holder last learnt it, per member:
/// `room-epoch-floor/<roomId>/<persona>` (`rooms/_shared/0.1` `EpochFloor`; trust-tasks-tf
/// #869). Kept apart from the group row so it outlives whatever the group row is rewritten
/// to, and kept for as long as anything is held for the room (item 4): it is what stops a
/// rung or key below it being stored or derived again.
const EPOCH_FLOOR: &str = "room-epoch-floor";

/// The last admission this owner applied, per owner: `room-admitted/<roomId>/<persona>`.
///
/// `rooms/owner/group/add/0.3` item 8: kept so that a caller who lost the answer and sends
/// the identical request again gets the Welcome it needs, rather than `alreadyMember`. Short
/// on purpose — until this owner builds its next advance of the room, or
/// [`ADMISSION_RETENTION_SECS`] after it was applied, whichever is first — because the
/// Welcome is secret-bearing ciphertext and a request after either is no longer a retry of
/// anything.
///
/// In [`ROOM_GROUPS`](crate::keyspaces::ROOM_GROUPS), beside the pending advance it is promoted
/// from, which already holds the same Welcome: under the same storage encryption, carried by
/// a backup with the group it belongs to, and gone with the member's DID. A separate keyspace
/// excluded from backup would buy nothing — the pending advance it is made from is backed up
/// — and a restored row is still bounded by its `appliedAt`.
const ADMITTED: &str = "room-admitted";

/// The member's own personal label for the room, per member: `room-label/<roomId>/<persona>`
/// (`rooms/keys/label/0.1`).
///
/// Beside the group state it describes, in the same keyspace, on purpose
/// (`rooms/keys/label/0.1` recipient item 8): protected as the group state is, carried by a
/// backup with it, and discarded by [`forget`] with it — and by nothing else. Not on the
/// member's removal from the room ([`REMOVED`] keeps the group state, and so the label), not
/// on a re-admission after one (the label is the member's for the room, and [`join`] moves
/// only the group into [`PRIOR`]), not on a lapse, not on a change of host or owner: a room a
/// member can no longer write in is the one they most need to recognise.
///
/// **Never leaves this VTA except to a caller that acts as its member** (item 9): nothing
/// that completes, signs or seals for the member reads it, and its text is never logged
/// or audited (item 10).
const LABEL: &str = "room-label";

/// The member's read marker for the room, per member: `room-read-marker/<roomId>/<persona>`
/// (`rooms/keys/read-marker/set/0.1`, trust-tasks-tf #1086).
///
/// Beside the group state, as the [`LABEL`] is, for the same reasons (Recipient item 7):
/// protected as the group state is, carried by a backup with it (which the specification
/// allows, *Retention*), and discarded by [`forget`] with it — and by nothing else. Only the
/// marker in force: never an earlier one, when it was set, or which client set it.
///
/// **Never leaves this VTA except to a caller that acts as its member** (item 8): nothing
/// that completes, signs or seals for the member reads it, and neither its values nor when
/// it moved are logged or audited (item 9).
const READ_MARKER: &str = "room-read-marker";

/// The [`REMOVED`] row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemovalRecord {
    /// The first room epoch this member cannot open.
    epoch: u32,
    /// Unix seconds when the removing commit was processed here.
    removed_at: u64,
}

/// One [`PRIOR`] entry: a membership a removal ended, kept so that what it opened still
/// opens after the member is admitted again (`rooms/keys/welcome/0.1`,
/// `rooms/keys/open/0.2`).
///
/// # A removal known, or one only evidenced
///
/// `rooms/keys/welcome/0.1` (*Rejoining after a removal*) gives two pieces of evidence that a
/// membership ended. A removal this VTA processed ([`apply_commit`] → [`REMOVED`]) says at
/// which epoch. A Welcome whose ratchet tree no longer holds this membership's own leaf
/// ([`join`]) says only that it ended somewhere above the epoch the state holds and at or
/// below the epoch the Welcome admits the member at — a member idle at its removal never
/// applied the removing commit, and could not fetch it afterwards. Such an entry has no
/// `removed_epoch` until a repair applies the room's commits to it
/// ([`apply_prior_commit`]) and reaches the removing one.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PriorMembership {
    /// The group state as the removal left it — or, while the removal is not yet known, as
    /// far as this VTA has carried it — with its epoch links.
    pub group: RoomGroupRecord,
    /// The room epoch this membership was joined at ([`JOINED`]); absent for one joined
    /// before that was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined_epoch: Option<u32>,
    /// The first room epoch this membership cannot open. Absent while the removal is known
    /// only from a Welcome: the membership then covers every epoch from its join epoch up
    /// to the next join epoch, and one above the epoch its group holds is a commit not yet
    /// delivered to it (`rooms/keys/open/0.2`), never `removed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_epoch: Option<u32>,
    /// Unix seconds when the removing commit was processed here; absent with
    /// `removed_epoch`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<u64>,
}

impl PriorMembership {
    /// The signature key of this membership's own leaf: what identifies it among the
    /// member's prior memberships, and what a Welcome's ratchet tree is searched for.
    fn signature_key(&self) -> Result<Vec<u8>, AppError> {
        self.group
            .snapshot
            .signature_public_key()
            .map_err(|e| AppError::Internal(format!("read a prior membership's leaf key: {e}")))
    }
}

/// The rows a build keyed by room alone wrote, read only to migrate them
/// ([`migrate_legacy`]). `room-add:` is older still: the admission-only advance slot.
mod legacy {
    pub(super) const GROUP_PREFIX: &str = "room-group:";
    pub(super) fn group(room_id: &str) -> String {
        format!("{GROUP_PREFIX}{room_id}")
    }
    pub(super) fn key_package(room_id: &str) -> String {
        format!("room-kp:{room_id}")
    }
    pub(super) fn advance(room_id: &str) -> String {
        format!("room-advance:{room_id}")
    }
    pub(super) fn add(room_id: &str) -> String {
        format!("room-add:{room_id}")
    }
    pub(super) fn roots(room_id: &str) -> String {
        format!("room-roots:{room_id}")
    }
}

/// What this VTA holds for one room.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoomGroupRecord {
    /// The group, at whatever epoch it last reached.
    pub snapshot: GroupSnapshot,
    /// The member this group is for.
    pub member_did: String,
    /// The room's epoch key chain, as far as this VTA holds it.
    ///
    /// Retained here rather than fetched per open because this is the custody point: a link
    /// is key material, wrapped, and the VTA is where the room's key material lives. Every
    /// commit this VTA applies appends one, so a member who has kept up holds the chain back
    /// to the epoch they joined at without asking anyone.
    ///
    /// **Empty for a room joined before the chain existed**, and for one whose owner has not
    /// sent the history. `open` then reads only from the joining epoch forward and says so
    /// — see `RoomKeyError::EpochUnreachable`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<EpochLink>,
    /// Unix seconds of the last change.
    pub updated_at: u64,
}

/// The group this VTA holds for `member`, if any.
pub async fn load(
    groups: &KeyspaceHandle,
    member: &Member,
) -> Result<Option<RoomGroupRecord>, AppError> {
    groups.get(member.key(GROUP)).await.map_err(|e| {
        AppError::Internal(format!("read group state for `{}`: {e}", member.room_id()))
    })
}

/// The refusal for a member with no group state. Says nothing about whether another persona
/// on this VTA holds the room — that is not the caller's to learn.
fn no_group(member: &Member) -> AppError {
    AppError::NotFound(format!(
        "this VTA holds no group state for room `{}`",
        member.room_id()
    ))
}

async fn store(
    groups: &KeyspaceHandle,
    member: &Member,
    group: &RoomGroup,
    links: Vec<EpochLink>,
    now: u64,
) -> Result<(), AppError> {
    let record = record_of(member, group, links, now)?;
    groups
        .insert(member.key(GROUP), &record)
        .await
        .map_err(|e| {
            AppError::Internal(format!("store group state for `{}`: {e}", member.room_id()))
        })
}

fn record_of(
    member: &Member,
    group: &RoomGroup,
    links: Vec<EpochLink>,
    now: u64,
) -> Result<RoomGroupRecord, AppError> {
    Ok(RoomGroupRecord {
        snapshot: group
            .snapshot()
            .map_err(|e| AppError::Internal(format!("snapshot the group: {e}")))?,
        member_did: member.persona().to_string(),
        links,
        updated_at: now,
    })
}

/// Write rows as the per-room build did, for tests of an upgraded store.
#[cfg(test)]
pub(crate) mod legacy_for_test {
    use super::*;

    pub(crate) async fn store_group(
        groups: &KeyspaceHandle,
        room_id: &str,
        record: &RoomGroupRecord,
    ) {
        groups.insert(legacy::group(room_id), record).await.unwrap();
    }

    pub(crate) async fn store_pending_add(
        groups: &KeyspaceHandle,
        room_id: &str,
        pending: &serde_json::Value,
    ) {
        groups.insert(legacy::add(room_id), pending).await.unwrap();
    }
}

/// Store a group as `join` would, for tests that need a room held at some epoch.
#[cfg(test)]
pub(crate) async fn store_for_test(
    groups: &KeyspaceHandle,
    member: &Member,
    group: &RoomGroup,
    links: Vec<EpochLink>,
) -> Result<(), AppError> {
    store(groups, member, group, links, 0).await
}

/// Move the retained admission's `appliedAt` `secs` into the past, for tests of item 8's
/// 24 hours.
#[cfg(test)]
pub(crate) async fn age_retained_admission_for_test(
    groups: &KeyspaceHandle,
    owner: &Member,
    secs: u64,
) {
    let mut row: RetainedAdmission = groups.get(owner.key(ADMITTED)).await.unwrap().unwrap();
    row.applied_at = row.applied_at.saturating_sub(secs);
    groups.insert(owner.key(ADMITTED), &row).await.unwrap();
}

/// Whether a retained admission row exists at all, expired or not.
#[cfg(test)]
pub(crate) async fn has_retained_admission_row(groups: &KeyspaceHandle, owner: &Member) -> bool {
    groups.get_raw(owner.key(ADMITTED)).await.unwrap().is_some()
}

/// Record that a commit removed `member` at `epoch`, as [`apply_commit`] does on
/// processing it — for tests of how a removed member's refusals read.
#[cfg(test)]
pub(crate) async fn record_removal_for_test(
    groups: &KeyspaceHandle,
    member: &Member,
    epoch: u32,
) -> Result<(), AppError> {
    record_removal(groups, member, epoch, 0).await
}

mod advance;
mod custody;
mod join;
mod migrate;
mod open;
mod personal;

pub use advance::*;
pub use custody::*;
pub use join::*;
pub use migrate::*;
pub use open::*;
pub use personal::*;
