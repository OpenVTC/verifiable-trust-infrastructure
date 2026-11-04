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

/// How long a retained admission is kept at most — `rooms/owner/group/add/0.3` item 8's
/// 24 hours.
pub const ADMISSION_RETENTION_SECS: u64 = 24 * 60 * 60;

/// The [`ADMITTED`] row: `rooms/owner/group/add/0.3` item 8's retained admission.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetainedAdmission {
    /// The DID admitted, compared with a repeat's `member` as a string — never normalised,
    /// never resolved.
    pub member: String,
    /// The admitted KeyPackage's `KeyPackageRef` (RFC 9420 §5.2), base64url.
    pub key_package_ref: String,
    /// The room epoch the admission produced.
    pub epoch: u32,
    /// The Welcome, base64url.
    pub welcome: String,
    /// The ratchet tree, base64url, where the admission returned one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
    /// Unix seconds when it was applied here.
    pub applied_at: u64,
}

impl RetainedAdmission {
    /// Whether it is still kept at `now` (item 8's 24 hours).
    pub fn kept_at(&self, now: u64) -> bool {
        now < self.applied_at.saturating_add(ADMISSION_RETENTION_SECS)
    }

    /// Whether a request for `member` with a KeyPackage whose reference is
    /// `key_package_ref` repeats this admission — the exact match item 8 asks for.
    pub fn repeated_by(&self, member: &str, key_package_ref: &[u8]) -> bool {
        self.member == member && self.key_package_ref == B64.encode(key_package_ref)
    }
}

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

/// Storage key for a consumed invitation.
///
/// Keyed by the invitation's credential id, which already names one subject — so it is
/// per member without saying so, and stays as it was.
pub(super) fn invitation_key(credential_id: &str) -> String {
    format!("room-vic:{credential_id}")
}

/// A minted key package, awaiting the Welcome that consumes it.
///
/// The private half lives in the snapshot; this row *is* the retained key material, which is
/// why it is bounded rather than kept forever.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingKeyPackage {
    /// The identity holding the package's private half.
    pub snapshot: IdentitySnapshot,
    /// The KeyPackage itself, base64url — public, and what travels to the owner.
    pub key_package: String,
    /// Unix seconds after which this is discarded unused.
    pub expires_at: u64,
    /// The credential id of the invitation it was minted against, for one minted by
    /// `rooms/keys/key-package/0.2` — which returns it again, while it is outstanding, to
    /// a request for the same room, member and invitation ([`outstanding_or_mint`]).
    /// Absent for one `0.1` minted, which no later request returns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation_id: Option<String>,
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

/// Mint an MLS KeyPackage for `room_id` and retain its private half.
///
/// **Per room, never reused across rooms.** A KeyPackage is a stable public identifier, so
/// the same one offered to two rooms tells anyone who sees both that one party is in both —
/// the correlation a `private` room exists to deny, arriving through the door rather than
/// the wall.
///
/// The package's leaf identifies `member`'s persona, and the private half is kept under
/// that member, so two personas on one VTA invited to one room each mint their own.
pub async fn mint_key_package(
    groups: &KeyspaceHandle,
    member: &Member,
    lifetime_secs: u64,
    now: u64,
) -> Result<PendingKeyPackage, AppError> {
    let (snapshot, package) = IdentitySnapshot::mint(member.persona())
        .map_err(|e| AppError::Internal(format!("mint a key package: {e}")))?;

    let pending = PendingKeyPackage {
        snapshot,
        key_package: B64.encode(&package),
        expires_at: now + lifetime_secs,
        invitation_id: None,
    };
    groups
        .insert(member.key(KEY_PACKAGE), &pending)
        .await
        .map_err(|e| AppError::Internal(format!("store the pending key package: {e}")))?;
    Ok(pending)
}

/// Serialises [`outstanding_or_mint`]'s read-then-mint, so two requests for the same room,
/// member and invitation arriving together are given the same KeyPackage
/// (`rooms/keys/key-package/0.2` recipient item 7). One lock for every member: a mint is
/// cheap, and a second KeyPackage minted by a race would overwrite the first's private half
/// — the one a Welcome the owner already made may be sealed to.
static OUTSTANDING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `rooms/keys/key-package/0.2`: the KeyPackage this VTA already holds for `member` against
/// the invitation `invitation_id`, while it is outstanding (recipient item 3), or a new one
/// minted against it (item 4). Answers whether it was already minted.
///
/// **Outstanding** is item 5's: minted, not yet consumed by a Welcome ([`join`] discards
/// it), not expired. A package minted against another invitation — before a removal and
/// re-admission (item 6) — or by `0.1`, which records no invitation, is not returned; a new
/// one replaces it.
///
/// This is what lets a member finish, from any surface, an acceptance another began: the
/// surface asks again, is given the KeyPackage the community already admitted, and the
/// community answers that acceptance with the Welcome it kept.
pub async fn outstanding_or_mint(
    groups: &KeyspaceHandle,
    member: &Member,
    invitation_id: &str,
    lifetime_secs: u64,
    now: u64,
) -> Result<(PendingKeyPackage, bool), AppError> {
    let _one_at_a_time = OUTSTANDING.lock().await;
    let held: Option<PendingKeyPackage> = groups
        .get(member.key(KEY_PACKAGE))
        .await
        .map_err(|e| AppError::Internal(format!("read the pending key package: {e}")))?;
    if let Some(held) = held.filter(|p| {
        p.expires_at > now
            && p.snapshot.member_did() == member.persona()
            && p.invitation_id.as_deref() == Some(invitation_id)
    }) {
        return Ok((held, true));
    }
    let (snapshot, package) = IdentitySnapshot::mint(member.persona())
        .map_err(|e| AppError::Internal(format!("mint a key package: {e}")))?;
    let pending = PendingKeyPackage {
        snapshot,
        key_package: B64.encode(&package),
        expires_at: now + lifetime_secs,
        invitation_id: Some(invitation_id.to_string()),
    };
    groups
        .insert(member.key(KEY_PACKAGE), &pending)
        .await
        .map_err(|e| AppError::Internal(format!("store the pending key package: {e}")))?;
    Ok((pending, false))
}

/// Whether `key_package` is one this VTA minted for `member` with
/// [`mint_key_package`] and still holds the private half of — not yet used (a Welcome
/// consumes it, [`join`]) and not expired. `rooms/keys/act/0.3` recipient item 10.
///
/// **Compared by `KeyPackageRef`, never by the leaf credential.** A leaf credential is
/// signed by the leaf's own key, so anybody can make one naming the member; only the
/// reference names the exact KeyPackage — and so the init and signature keys — this VTA
/// minted. A KeyPackage that does not parse, or that this VTA never minted for this room
/// and member, is not held.
pub async fn holds_key_package(
    groups: &KeyspaceHandle,
    member: &Member,
    key_package: &[u8],
    now: u64,
) -> Result<bool, AppError> {
    let Ok(asked) = vti_rooms::mls::key_package_ref(key_package) else {
        return Ok(false);
    };
    let pending: Option<PendingKeyPackage> = groups
        .get(member.key(KEY_PACKAGE))
        .await
        .map_err(|e| AppError::Internal(format!("read the pending key package: {e}")))?;
    let Some(pending) = pending else {
        return Ok(false);
    };
    if pending.expires_at <= now || pending.snapshot.member_did() != member.persona() {
        return Ok(false);
    }
    let Ok(minted) = B64.decode(pending.key_package.as_bytes()) else {
        return Ok(false);
    };
    Ok(vti_rooms::mls::key_package_ref(&minted).is_ok_and(|r| r == asked))
}

/// A KeyPackage the per-room build minted for `member` before an upgrade, moved under
/// them — so a Welcome arriving after the upgrade still joins. Only when its leaf
/// identifies `member`: a package minted for anybody else is not theirs to join with.
async fn legacy_key_package(
    groups: &KeyspaceHandle,
    member: &Member,
) -> Result<Option<PendingKeyPackage>, AppError> {
    let old = legacy::key_package(member.room_id());
    let Some(raw) = groups.get_raw(old.clone()).await? else {
        return Ok(None);
    };
    let Ok(kp) = serde_json::from_slice::<PendingKeyPackage>(&raw) else {
        return Ok(None);
    };
    if kp.snapshot.member_did() != member.persona() {
        return Ok(None);
    }
    move_row(groups, old, raw, member.key(KEY_PACKAGE), &kp).await?;
    Ok(Some(kp))
}

/// Why a Welcome could not be accepted.
#[derive(Debug)]
#[non_exhaustive]
pub enum JoinError {
    /// This member already holds current group state for the room — `alreadyJoined`: no
    /// removal recorded, and the Welcome's tree still holds the state's own leaf.
    AlreadyJoined,
    /// The KeyPackage the Welcome is sealed to expired before it arrived. Its private half
    /// has been discarded (`rooms/keys/key-package/0.2` *The private half is retained*: it **MUST** be
    /// discarded at expiry), so the Welcome can never process — `welcomeInvalid`.
    KeyPackageExpired,
    /// The Welcome is for an MLS group other than the one this member's held state is in,
    /// so its ratchet tree is no evidence that the state ended (`rooms/keys/welcome/0.1`,
    /// *Rejoining after a removal*) — `welcomeInvalid`. Nothing was consumed or changed.
    WelcomeForAnotherGroup,
    App(AppError),
}

impl From<AppError> for JoinError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

/// Join `member`'s room's group from a Welcome.
///
/// Refuses a second join **by the same member** rather than merging: two current group
/// states for one member in one room is a condition nothing downstream can resolve —
/// sealing has no way to choose, and choosing wrong seals for a group the room has left.
/// Another persona on this VTA holding the room is a different member with a different
/// leaf, and is no reason to refuse this one.
///
/// # A removal ends a membership; a Welcome after it starts the next
///
/// Group state a removal ended is a **prior membership**, not a join
/// (`rooms/keys/welcome/0.1`, *Rejoining after a removal*): the member was removed, and the
/// owner admitted them again with a fresh invitation, a new leaf and a new Welcome. That
/// Welcome is accepted. The old group moves into [`PRIOR`] — so every record it opened still
/// opens ([`open_record`], `rooms/keys/open/0.2`) — the new group becomes the current one, and
/// the removal row is cleared, in one conditional write.
///
/// Two things show that a removal ended the state held:
///
/// 1. **A removal recorded** ([`REMOVED`]) — this VTA applied the removing commit, and the
///    prior membership's removal epoch is known.
/// 2. **The Welcome.** A member idle when it was removed never applied that commit, and
///    cannot fetch it now: the host serves commits under the `read` grant the removal
///    withdrew. So with no removal recorded the Welcome is processed anyway — without
///    keeping what it forms — and its ratchet tree searched for the held state's own leaf,
///    by that leaf's **signature key**, never the member's DID: the re-admitted leaf carries
///    the same DID under a new key. Still there, the member was never removed and the
///    state is current: [`JoinError::AlreadyJoined`], with nothing kept and the KeyPackage
///    not consumed. Gone from a Welcome for **another** MLS group, it says nothing — such a
///    group has none of the held state's leaves by construction — and the Welcome is
///    refused ([`JoinError::WelcomeForAnotherGroup`], `welcomeInvalid`) with nothing consumed
///    or changed. Gone from one for the same group (equal group ids), the member was removed
///    by a commit producing an epoch above the one the state holds and at or below the
///    Welcome's: the prior membership is kept with
///    its removal epoch not yet known, and a repair fixes it later
///    ([`apply_prior_commit`]). The join never waits for, or fetches, that commit.
///
/// Where the state is current by every evidence available — no removal recorded and no
/// Welcome this VTA can process to look in (no held KeyPackage, an expired one, a Welcome
/// that does not process) — the answer is [`JoinError::AlreadyJoined`], as it always was,
/// and nothing is discarded.
pub async fn join(
    groups: &KeyspaceHandle,
    member: &Member,
    welcome: &[u8],
    now: u64,
) -> Result<u64, JoinError> {
    let room_id = member.room_id();
    // What the join ends, if anything: the current group, and the removal that ended it
    // where one is recorded, exactly as read, so the write below lands only on what was
    // decided from.
    let held = match groups.get_raw(member.key(GROUP)).await? {
        None => None,
        Some(group_raw) => Some((group_raw, groups.get_raw(member.key(REMOVED)).await?)),
    };
    // State no removal is recorded for is current unless the Welcome shows otherwise.
    let unproven = matches!(held, Some((_, None)));

    // The KeyPackage the owner added is the one we minted, so the private half is in the
    // pending record — joining with a fresh identity would produce a group whose leaf
    // nobody added.
    let pending: Option<PendingKeyPackage> = groups
        .get(member.key(KEY_PACKAGE))
        .await
        .map_err(|e| AppError::Internal(format!("read the pending key package: {e}")))?;
    let pending = match pending {
        Some(p) => Some(p),
        None => legacy_key_package(groups, member).await?,
    };
    let Some(pending) = pending else {
        // No Welcome this VTA can process, so no evidence against the state it holds.
        if unproven {
            return Err(JoinError::AlreadyJoined);
        }
        return Err(AppError::Validation(format!(
            "no key package was minted for room `{room_id}`; a welcome can only be accepted \
             against the package the owner was given"
        ))
        .into());
    };
    // The same bound `holds_key_package` applies (act 0.3 item 10): a package past its
    // expiry is not held. Its private half is discarded here rather than used — retaining
    // it past expiry keeps a key alive for a join nobody is still expecting, and accepting
    // a Welcome against it would make the expiry decorative.
    if pending.expires_at <= now {
        if unproven {
            return Err(JoinError::AlreadyJoined);
        }
        groups
            .remove(member.key(KEY_PACKAGE))
            .await
            .map_err(|e| AppError::Internal(format!("discard an expired key package: {e}")))?;
        return Err(JoinError::KeyPackageExpired);
    }

    // Processing a Welcome stores nothing: the group lives in memory until the batch below.
    let group = match RoomGroup::join_from_identity(&pending.snapshot, welcome) {
        Ok(g) => g,
        Err(_) if unproven => return Err(JoinError::AlreadyJoined),
        Err(e) => {
            return Err(AppError::Validation(format!("the welcome did not process: {e}")).into());
        }
    };
    let epoch = group.epoch();
    let joined = record_of(member, &group, Vec::new(), now)?;

    let mut batch = vti_common::store::Batch::new();
    match held {
        None => {
            batch.require_absent(member.key(GROUP));
        }
        Some((group_raw, removed_raw)) => {
            let ended_group: RoomGroupRecord = serde_json::from_slice(&group_raw).map_err(|e| {
                AppError::Internal(format!("decode group state for `{room_id}`: {e}"))
            })?;
            let (removed_epoch, removed_at) = match &removed_raw {
                Some(raw) => {
                    let removal: RemovalRecord = serde_json::from_slice(raw).map_err(|e| {
                        AppError::Internal(format!(
                            "decode the removal record for `{room_id}`: {e}"
                        ))
                    })?;
                    (Some(removal.epoch), Some(removal.removed_at))
                }
                // No removal processed: the Welcome is the evidence, or there is none.
                None => {
                    let own_leaf = ended_group.snapshot.signature_public_key().map_err(|e| {
                        AppError::Internal(format!("read the held leaf's key for `{room_id}`: {e}"))
                    })?;
                    if group.has_leaf_with_signature_key(&own_leaf) {
                        // The held state's leaf is in the room's tree at the Welcome's epoch:
                        // the member was never removed, and this would be a second join.
                        // Nothing the Welcome formed is kept, and the KeyPackage stays.
                        return Err(JoinError::AlreadyJoined);
                    }
                    // An absent leaf is evidence only in the same group: a Welcome for any
                    // other has none of the held state's leaves by construction, and would
                    // retire current state on nothing. Refused before anything is written.
                    let held_group = ended_group.snapshot.group_id().map_err(|e| {
                        AppError::Internal(format!("read the held group's id for `{room_id}`: {e}"))
                    })?;
                    if group.group_id() != held_group {
                        return Err(JoinError::WelcomeForAnotherGroup);
                    }
                    let held_epoch = RoomGroup::restore(&ended_group.snapshot)
                        .map_err(|e| AppError::Internal(format!("restore the group: {e}")))?
                        .epoch();
                    if held_epoch >= epoch {
                        // A removal is a commit after the state held and at or before the
                        // Welcome; a Welcome at or below the held epoch cannot show one.
                        return Err(JoinError::AlreadyJoined);
                    }
                    (None, None)
                }
            };
            let prior_raw = groups.get_raw(member.key(PRIOR)).await?;
            let mut prior: Vec<PriorMembership> = match &prior_raw {
                Some(raw) => serde_json::from_slice(raw).map_err(|e| {
                    AppError::Internal(format!("decode the prior memberships of `{room_id}`: {e}"))
                })?,
                None => Vec::new(),
            };
            // Appended: a membership ends before the next begins, so the list stays in the
            // order the memberships were held, oldest first.
            prior.push(PriorMembership {
                group: ended_group,
                joined_epoch: joined_epoch(groups, member).await?,
                removed_epoch,
                removed_at,
            });
            batch.require_unchanged(member.key(GROUP), group_raw);
            match removed_raw {
                Some(raw) => batch.require_unchanged(member.key(REMOVED), raw),
                None => batch.require_absent(member.key(REMOVED)),
            };
            match prior_raw {
                Some(raw) => batch.require_unchanged(member.key(PRIOR), raw),
                None => batch.require_absent(member.key(PRIOR)),
            };
            batch.insert(member.key(PRIOR), &prior)?;
        }
    }
    batch.insert(member.key(GROUP), &joined)?;
    // The room epoch is the MLS epoch plus one, as `SealedRoom::room_epoch` has it.
    batch.insert(
        member.key(JOINED),
        &u32::try_from(epoch + 1).unwrap_or(u32::MAX),
    )?;
    // A member admitted again is a member again: the removal now describes the prior
    // membership it was moved into, not the group this VTA holds.
    batch.remove(member.key(REMOVED));
    // The package is consumed. MLS consumes it on add, and a retained private half for a
    // used package is key material kept for nothing.
    batch.remove(member.key(KEY_PACKAGE));
    match groups.apply_batch(batch).await? {
        vti_common::store::BatchOutcome::Applied => Ok(epoch),
        // Another Welcome for the same member landed while this one was processing: that
        // one is the join, and this would be a second.
        vti_common::store::BatchOutcome::Refused { .. } => Err(JoinError::AlreadyJoined),
    }
}

/// Whether `member` holds a **current** membership of the room as far as this VTA knows:
/// group state with no removal recorded. Group state a removal ended is a prior membership
/// (`rooms/keys/welcome/0.1`), and a Welcome for it is a re-admission, not `alreadyJoined`.
/// A removal this VTA never processed is not known here; [`join`] learns of it from the
/// re-admitting Welcome.
pub async fn holds_current(groups: &KeyspaceHandle, member: &Member) -> Result<bool, AppError> {
    Ok(load(groups, member).await?.is_some() && removed_at(groups, member).await?.is_none())
}

/// The memberships of the room a removal ended for `member`, oldest first ([`PRIOR`]).
pub async fn prior_memberships(
    groups: &KeyspaceHandle,
    member: &Member,
) -> Result<Vec<PriorMembership>, AppError> {
    let prior: Option<Vec<PriorMembership>> = groups.get(member.key(PRIOR)).await.map_err(|e| {
        AppError::Internal(format!(
            "read the prior memberships of `{}`: {e}",
            member.room_id()
        ))
    })?;
    Ok(prior.unwrap_or_default())
}

/// Which of `member`'s group states a repair works on: the current one, or one prior
/// membership, named by its own leaf's signature key (stable for as long as the entry is held,
/// unlike its place in the list or its epoch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairTarget {
    Current,
    Prior { signature_key: Vec<u8> },
}

/// Which of `member`'s memberships answers for one room epoch.
enum Holding {
    /// This group — the current one, or a prior membership whose range holds the epoch —
    /// and which it is.
    Group {
        record: RoomGroupRecord,
        target: RepairTarget,
    },
    /// The epoch falls after a removal and before the next join: no group of this member's
    /// was ever given its key.
    Removed { removed_at: u32 },
    /// The epoch is below the first membership's join epoch (`beyondChain`), and `earliest`
    /// is the earliest epoch any membership of this member's opens.
    BeforeFirstJoin { earliest: u32 },
}

/// The group state that opens room epoch `epoch` for `member` (`rooms/keys/open/0.2`,
/// `rooms/keys/file-key/0.2`), `None` when this VTA holds no group for them.
///
/// With no prior membership, the current group answers every epoch, as it always has —
/// including those below its join epoch that a backfill reached. With one or more:
///
/// - At or above the current group's join epoch, the current group answers, and says
///   itself whether the epoch is ahead of it or after its own removal.
/// - Otherwise the newest prior membership first: an epoch at or after its known removal
///   (and so before the next join) is `removed`, with that removal's epoch; one at or above
///   its join epoch is its to open, with its own epoch links — and its chain says whether it
///   reaches (`beyondChain` under the room's epoch floor). A prior membership whose removal
///   is not yet known ([`PriorMembership::removed_epoch`] absent) answers every epoch from
///   its join epoch up to the next join, and an epoch above the one its group holds is then
///   `notDelivered` with that group's epoch — never `removed` before the removing commit is
///   applied to it.
/// - Below the first join epoch, `beyondChain`.
///
/// A membership's join epoch is its [`JOINED`] row; one joined before that row existed
/// has none, and the earliest epoch its chain reaches stands in for it.
///
/// Only opening and repair ask this; sealing always uses the current group
/// ([`current_for_seal`]).
async fn holding_for(
    groups: &KeyspaceHandle,
    member: &Member,
    epoch: u32,
    floor: u32,
) -> Result<Option<Holding>, AppError> {
    let Some(current) = load(groups, member).await? else {
        return Ok(None);
    };
    let prior = prior_memberships(groups, member).await?;
    if prior.is_empty() {
        return Ok(Some(Holding::Group {
            record: current,
            target: RepairTarget::Current,
        }));
    }
    let joined = joined_epoch(groups, member).await?;
    if epoch >= start_of(member, &current, joined, floor)? {
        return Ok(Some(Holding::Group {
            record: current,
            target: RepairTarget::Current,
        }));
    }
    let mut earliest = u32::MAX;
    for p in prior.into_iter().rev() {
        if let Some(removed) = p.removed_epoch
            && epoch >= removed
        {
            return Ok(Some(Holding::Removed {
                removed_at: removed,
            }));
        }
        let start = start_of(member, &p.group, p.joined_epoch, floor)?;
        if epoch >= start {
            let signature_key = p.signature_key()?;
            return Ok(Some(Holding::Group {
                record: p.group,
                target: RepairTarget::Prior { signature_key },
            }));
        }
        earliest = start.max(floor);
    }
    Ok(Some(Holding::BeforeFirstJoin { earliest }))
}

/// The first room epoch a membership covers: its join epoch where it was recorded, and
/// otherwise the earliest epoch its chain reaches under `floor`.
fn start_of(
    member: &Member,
    record: &RoomGroupRecord,
    joined: Option<u32>,
    floor: u32,
) -> Result<u32, AppError> {
    match joined {
        Some(j) => Ok(j),
        None => reach_of(member, record, floor),
    }
}

/// The room epoch the current membership was joined at ([`JOINED`]), if recorded.
async fn joined_epoch(groups: &KeyspaceHandle, member: &Member) -> Result<Option<u32>, AppError> {
    groups.get(member.key(JOINED)).await.map_err(|e| {
        AppError::Internal(format!(
            "read the join epoch for `{}`: {e}",
            member.room_id()
        ))
    })
}

/// The earliest room epoch `record`'s chain reaches under `floor`.
fn reach_of(member: &Member, record: &RoomGroupRecord, floor: u32) -> Result<u32, AppError> {
    sealed_room(member, record, floor)?
        .earliest_readable_epoch()
        .map_err(|e| AppError::Internal(format!("walk the chain for `{}`: {e}", member.room_id())))
}

/// `record` restored as a room ready to open: the epoch floor applied, its links added.
fn sealed_room(
    member: &Member,
    record: &RoomGroupRecord,
    floor: u32,
) -> Result<SealedRoom, AppError> {
    let group = RoomGroup::restore(&record.snapshot)
        .map_err(|e| AppError::Internal(format!("restore the group: {e}")))?;
    let mut room = SealedRoom::new(member.room_id(), group);
    room.apply_epoch_floor(floor);
    room.add_links(record.links.clone());
    Ok(room)
}

/// Apply a commit, advancing one epoch.
///
/// Ordering is the whole contract. A replay is a no-op success — a retry that failed would
/// make every unreliable transport a liveness problem — and a gap is refused with the epoch
/// we actually hold, so the sender resumes rather than guesses.
pub async fn apply_commit(
    groups: &KeyspaceHandle,
    member: &Member,
    commit: &[u8],
    claimed_epoch: u64,
    now: u64,
) -> Result<u64, AppError> {
    let room_id = member.room_id();
    let record = load(groups, member)
        .await?
        .ok_or_else(|| no_group(member))?;
    // A `SealedRoom` rather than a bare group: the epoch link this commit produces is bound
    // to the room, so minting one needs the room's identifier and the group does not carry
    // it. Restoring through the room type is what makes the link mintable at all.
    let mut room = SealedRoom::new(
        room_id,
        RoomGroup::restore(&record.snapshot)
            .map_err(|e| AppError::Internal(format!("restore the group: {e}")))?,
    );
    let current = room.group().epoch();

    if claimed_epoch == current {
        // Already applied. Reporting success with the unchanged epoch is what makes
        // delivery retryable.
        return Ok(current);
    }
    if claimed_epoch != current + 1 {
        return Err(AppError::Conflict(format!(
            "commit produces epoch {claimed_epoch} but room `{room_id}` is at {current}; \
             resume from {}",
            current + 1
        )));
    }

    // The link is what keeps everything already in the room readable across this commit.
    // Dropping it here would advance the epoch and silently sever the history — the defect
    // the chain exists to fix, so it is retained in the same write that advances the group.
    let (_, link) = match room.apply_commit(commit) {
        Ok(applied) => applied,
        Err(e) => {
            // Remembered, so a later open of a record sealed after the removal says
            // "removed" rather than "a commit has not been delivered". Replaying the same
            // commit lands here again and rewrites the same row.
            if let RoomKeyError::Removed { epoch } = e {
                record_removal(groups, member, epoch, now).await?;
            }
            return Err(AppError::Validation(format!(
                "the commit did not process: {e}"
            )));
        }
    };
    let epoch = room.group().epoch();

    let mut links = record.links;
    if let Some(link) = link {
        links.push(link);
    }
    store(groups, member, room.group(), links, now).await?;
    Ok(epoch)
}

/// The group `member` seals with: the current membership's, and `None` when there is none
/// — no group at all, or only state a removal ended. A removed member that has not been
/// admitted again has no current epoch, so nothing is sealed under the state the removal
/// left (`rooms/keys/open/0.2`, `rooms/keys/file-key/0.2`: `noGroup`); that state only
/// opens what it already could.
async fn current_for_seal(
    groups: &KeyspaceHandle,
    member: &Member,
) -> Result<Option<RoomGroupRecord>, AppError> {
    if removed_at(groups, member).await?.is_some() {
        return Ok(None);
    }
    load(groups, member).await
}

/// Seal a record body with the room's current epoch key.
///
/// The mirror of [`open_record`], and the reason a client can write to a sealed room at all:
/// the key never leaves, so the caller sends plaintext and receives ciphertext.
///
/// # It does not write
///
/// The caller takes the result to a host and presents its own authority there. Sealing and
/// being allowed to store are different questions asked of different parties — this VTA
/// knows the key and nothing about the room's ACL; the host knows the credentials and cannot
/// read a byte. Doing both here would make this VTA the party that decides what goes into a
/// room, which is the one thing the design keeps it out of.
pub async fn seal_record(
    groups: &KeyspaceHandle,
    member: &Member,
    key: &str,
    version: u64,
    plaintext: &[u8],
) -> Result<vti_rooms::wire::SealedContent, AppError> {
    let room_id = member.room_id();
    let record = current_for_seal(groups, member)
        .await?
        .ok_or_else(|| no_group(member))?;
    let group = RoomGroup::restore(&record.snapshot)
        .map_err(|e| AppError::Internal(format!("restore the group: {e}")))?;

    SealedRoom::new(room_id, group)
        .seal_record(key, version, plaintext)
        .map_err(|e| AppError::Validation(e.to_string()))
}

/// Why a file key could not be derived.
///
/// `#[non_exhaustive]` because it has already grown once ([`Self::Removed`]) and the
/// epoch cases are exactly where a new remedy would add another.
#[derive(Debug)]
#[non_exhaustive]
pub enum FileKeyError {
    /// This VTA holds no group for the room.
    NoGroup,
    /// Anything else that is not an unreachable epoch: a store error, a group that does not
    /// restore.
    App(AppError),
    /// The file is sealed under an epoch later than the one this VTA holds: a commit has not
    /// been delivered.
    NotDelivered { epoch: u32, held: u32 },
    /// The epoch chain reaches back only to `earliest`.
    BeyondChain { epoch: u32, earliest: u32 },
    /// A commit this VTA applied removed the member from the group at `removed_at`, and
    /// the file is sealed under `epoch`, at or after it: its key will never be derivable
    /// here. Apart from [`Self::NotDelivered`] for the reason [`OpenError::Removed`] is:
    /// that one's remedy, applying commits, cannot work for this one.
    Removed { epoch: u32, removed_at: u32 },
}

/// One file's key — `rooms/keys/file-key/0.2`.
///
/// `open_epoch` is `None` to seal (the current epoch, which is returned) and the file's
/// epoch to open, walked out of the retained chain exactly as [`open_record`] walks it.
///
/// # A key, unlike every other answer here
///
/// `rooms/keys/open` keeps the key and returns plaintext; this returns a key, because file
/// bytes must not pass through this VTA. What it releases opens one file and nothing else:
/// the room's storage key does not leave, so no sibling can be derived from it.
pub async fn file_key(
    groups: &KeyspaceHandle,
    member: &Member,
    file_id: &vti_rooms::files::FileId,
    open_epoch: Option<u32>,
) -> Result<(vti_rooms::files::FileKey, u32), FileKeyError> {
    let room_id = member.room_id();
    let Some(epoch) = open_epoch else {
        // Sealing is always the current group's, and a member a removal left with only
        // prior state has none (`rooms/keys/file-key/0.2`): `noGroup`.
        let record = current_for_seal(groups, member)
            .await
            .map_err(FileKeyError::App)?
            .ok_or(FileKeyError::NoGroup)?;
        let group = RoomGroup::restore(&record.snapshot).map_err(|e| {
            FileKeyError::App(AppError::Internal(format!("restore the group: {e}")))
        })?;
        return SealedRoom::new(room_id, group)
            .file_key_for_seal(file_id)
            .map_err(|e| FileKeyError::App(AppError::Internal(e.to_string())));
    };
    // Opening is the group of whichever membership held the file's epoch
    // (`rooms/keys/file-key/0.2`): the current one, or a prior one a removal ended.
    let floor = epoch_floor(groups, member)
        .await
        .map_err(FileKeyError::App)?;
    let (record, target) = match holding_for(groups, member, epoch, floor)
        .await
        .map_err(FileKeyError::App)?
    {
        None => return Err(FileKeyError::NoGroup),
        Some(Holding::Removed { removed_at }) => {
            return Err(FileKeyError::Removed { epoch, removed_at });
        }
        Some(Holding::BeforeFirstJoin { earliest }) => {
            return Err(FileKeyError::BeyondChain { epoch, earliest });
        }
        Some(Holding::Group { record, target }) => (record, target),
    };
    let mut room = sealed_room(member, &record, floor).map_err(FileKeyError::App)?;
    match room.file_key_for_open(file_id, epoch) {
        Ok(key) => Ok((key, epoch)),
        Err(RoomKeyError::EpochAhead { sealed, held }) => {
            // A removal leaves the group where it was, so a file sealed after it is also
            // "ahead of the group". The row says which — as `open_record_detailed` reads it.
            // Only the current group's: a prior membership's known removal was answered
            // above, and one not yet known is `notDelivered` until a repair applies it.
            if target == RepairTarget::Current
                && let Some(removed_at) = removed_at(groups, member)
                    .await
                    .map_err(FileKeyError::App)?
                && sealed >= removed_at
            {
                return Err(FileKeyError::Removed {
                    epoch: sealed,
                    removed_at,
                });
            }
            Err(FileKeyError::NotDelivered {
                epoch: sealed,
                held,
            })
        }
        Err(RoomKeyError::EpochUnreachable { sealed, earliest }) => {
            Err(FileKeyError::BeyondChain {
                epoch: sealed,
                earliest,
            })
        }
        Err(e) => Err(FileKeyError::App(AppError::Validation(e.to_string()))),
    }
}

/// Where the room's profile is stored — `profile_key(E)` (`rooms/_shared/0.1`
/// `RoomProfileStatement`) — for `epoch`, or for the current epoch when `epoch` is `None`;
/// with the epoch it is for.
///
/// Computed here and only here because it is derived from the epoch's storage key, which
/// never leaves this VTA: a member's surface cannot find the room's profile without it, and
/// the location itself is all this returns — never the key it is derived from.
pub async fn profile_location(
    groups: &KeyspaceHandle,
    member: &Member,
    epoch: Option<u32>,
) -> Result<(String, u32), AppError> {
    let room_id = member.room_id();
    match epoch {
        None => {
            let record = current_for_seal(groups, member)
                .await?
                .ok_or_else(|| no_group(member))?;
            let group = RoomGroup::restore(&record.snapshot)
                .map_err(|e| AppError::Internal(format!("restore the group: {e}")))?;
            SealedRoom::new(room_id, group)
                .profile_key_for_seal()
                .map_err(|e| AppError::Internal(e.to_string()))
        }
        // The membership that held `epoch` computes it — a prior one included, so a
        // profile written before a removal is still found after a re-admission.
        Some(epoch) => {
            let floor = epoch_floor(groups, member).await?;
            let record = match holding_for(groups, member, epoch, floor).await? {
                None => return Err(no_group(member)),
                Some(Holding::Removed { removed_at }) => {
                    return Err(OpenError::Removed { epoch, removed_at }.into());
                }
                Some(Holding::BeforeFirstJoin { earliest }) => {
                    return Err(OpenError::BeyondChain { epoch, earliest }.into());
                }
                Some(Holding::Group { record, .. }) => record,
            };
            sealed_room(member, &record, floor)?
                .profile_key_for_open(epoch)
                .map(|key| (key, epoch))
                .map_err(|e| AppError::Validation(e.to_string()))
        }
    }
}

/// Every profile location `member` can compute, newest epoch first, down to the earliest
/// epoch its chain reaches and at most `bound` of them — the walk `rooms/keys/profile/read`
/// item 2 makes, and the set `rooms/keys/{read,browse}` keep the profile out of.
///
/// The current membership's range first, then each prior membership's (newest first),
/// each below its own removal epoch: an epoch between a removal and the next join has no
/// location this member can compute, so it is not in the walk.
pub async fn profile_locations(
    groups: &KeyspaceHandle,
    member: &Member,
    bound: usize,
) -> Result<Vec<(u32, String)>, AppError> {
    let room_id = member.room_id();
    let record = load(groups, member)
        .await?
        .ok_or_else(|| no_group(member))?;
    let floor = epoch_floor(groups, member).await?;
    let prior = prior_memberships(groups, member).await?;
    // (group, its join epoch, the highest epoch it answers for). With no prior membership
    // the current group's whole reach is walked, as it always was; with one, each
    // membership covers only its join epoch up, as `holding_for` reads them.
    let joined = if prior.is_empty() {
        None
    } else {
        joined_epoch(groups, member).await?
    };
    let mut ranges = vec![(record, joined, None)];
    // A prior membership whose removal is not yet known reaches as far as its group holds.
    ranges.extend(prior.into_iter().rev().map(|p| {
        (
            p.group,
            p.joined_epoch,
            p.removed_epoch.map(|r| r.saturating_sub(1)),
        )
    }));
    let mut out: Vec<(u32, String)> = Vec::new();
    // Epochs below this are not yet walked, so an epoch is listed once.
    let mut below = u32::MAX;
    for (record, joined, last) in ranges {
        let mut room = sealed_room(member, &record, floor)?;
        let top = last
            .unwrap_or_else(|| room.room_epoch())
            .min(below.saturating_sub(1));
        let earliest = room
            .earliest_readable_epoch()
            .map_err(|e| AppError::Internal(format!("walk the chain for `{room_id}`: {e}")))?
            .max(joined.unwrap_or(0))
            .max(1);
        if top < earliest {
            continue;
        }
        for epoch in (earliest..=top).rev() {
            if out.len() >= bound {
                return Ok(out);
            }
            let key = room
                .profile_key_for_open(epoch)
                .map_err(|e| AppError::Internal(format!("the profile location at {epoch}: {e}")))?;
            out.push((epoch, key));
        }
        below = below.min(earliest);
    }
    Ok(out)
}

/// Every member this VTA holds group state for, by room — keys only, nothing decrypted.
///
/// **Not an answer to give a caller.** It names every persona of every principal this VTA
/// serves; [`crate::operations::room_member`] filters it to the personas the caller may act
/// as before anything leaves.
pub async fn held_members(groups: &KeyspaceHandle) -> Result<Vec<Member>, AppError> {
    members_under(groups, &format!("{GROUP}/")).await
}

/// The members holding group state for `room_id`.
pub async fn holders(groups: &KeyspaceHandle, room_id: &str) -> Result<Vec<Member>, AppError> {
    members_under(groups, &format!("{GROUP}/{room_id}/")).await
}

async fn members_under(groups: &KeyspaceHandle, prefix: &str) -> Result<Vec<Member>, AppError> {
    let keys = groups.prefix_keys(prefix.as_bytes().to_vec()).await?;
    let mut out = Vec::with_capacity(keys.len());
    for k in keys {
        let k = String::from_utf8_lossy(&k);
        let Some(rest) = k.strip_prefix(&format!("{GROUP}/")) else {
            continue;
        };
        // `<room>/<persona>`, neither carrying a `/` (see [`Member::new`]).
        if let Some((room, persona)) = rest.split_once('/')
            && let Ok(m) = Member::new(room, persona)
        {
            out.push(m);
        }
    }
    Ok(out)
}

/// How far `member`'s group reads, as `rooms/keys/list` reports it.
///
/// # Custody, not membership
///
/// This answers "what can I open", never "what am I a member of". A principal may hold a
/// perfectly good membership credential for a room whose Welcome never arrived — absent
/// here, correctly. And a VTA not yet told of a removal still holds keys for a room its
/// principal has left: it cannot write there, because the host checks credentials that no
/// longer verify, and it can still open what it already had. That is what removal has always
/// meant, and a caller MUST NOT read this list as authority to act.
///
/// The epoch and reach are the **current** group's. Prior memberships a removal ended
/// ([`PRIOR`]) are not folded in: their ranges have gaps between them, and an earliest
/// epoch below a gap would read as a contiguous history this member does not have. A read
/// repair (`room_catch_up`) asks [`repair_state`] instead, which picks the membership by the
/// record's epoch.
pub async fn held_room(groups: &KeyspaceHandle, member: &Member) -> Result<HeldRoom, AppError> {
    let room_id = member.room_id();
    let record = load(groups, member)
        .await?
        .ok_or_else(|| no_group(member))?;

    // Restoring to answer is deliberate. The epoch could be read from the snapshot, but
    // `earliestReadableEpoch` is only knowable by *walking* the chain — and a number
    // derived two different ways is a number that will eventually disagree with itself.
    let group = RoomGroup::restore(&record.snapshot)
        .map_err(|e| AppError::Internal(format!("restore the group for `{room_id}`: {e}")))?;
    let mut room = SealedRoom::new(room_id, group);
    room.apply_epoch_floor(epoch_floor(groups, member).await?);
    room.add_links(record.links);

    let epoch = room.room_epoch();
    let earliest = room
        .earliest_readable_epoch()
        .map_err(|e| AppError::Internal(format!("walk the chain for `{room_id}`: {e}")))?;

    Ok(HeldRoom {
        room_id: room_id.to_string(),
        epoch,
        earliest_readable_epoch: earliest,
    })
}

/// The group state a repair of room epoch `epoch` works on, and how far it reads
/// (`room_catch_up`).
#[derive(Debug, Clone)]
pub struct RepairState {
    /// The membership `epoch` chose: the current group, or a prior membership.
    pub target: RepairTarget,
    /// The room epoch that group holds.
    pub epoch: u32,
    /// The earliest room epoch its chain reaches.
    pub earliest_readable_epoch: u32,
}

/// Which of `member`'s group states opens room epoch `epoch`, as [`open_record`] chooses it
/// (`rooms/keys/open/0.2`), and how far that state reads — `None` when no state does
/// (no group, an epoch a known removal put out of reach, or one below the first join), so
/// nothing can repair it.
///
/// A prior membership whose removal is not yet known is chosen for an epoch above the one
/// it holds, and a repair applies the room's commits to it ([`apply_prior_commit`]) until
/// it reaches the removing one.
pub async fn repair_state(
    groups: &KeyspaceHandle,
    member: &Member,
    epoch: u32,
) -> Result<Option<RepairState>, AppError> {
    let floor = epoch_floor(groups, member).await?;
    let Some(Holding::Group { record, target }) = holding_for(groups, member, epoch, floor).await?
    else {
        return Ok(None);
    };
    let mut room = sealed_room(member, &record, floor)?;
    let earliest = room.earliest_readable_epoch().map_err(|e| {
        AppError::Internal(format!("walk the chain for `{}`: {e}", member.room_id()))
    })?;
    Ok(Some(RepairState {
        target,
        epoch: room.room_epoch(),
        earliest_readable_epoch: earliest,
    }))
}

/// What applying a commit to a prior membership did ([`apply_prior_commit`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorCommit {
    /// The membership's group advanced to (or was already at) this MLS epoch.
    Applied(u64),
    /// The membership's removal is known, at this room epoch: the commit applied now removed
    /// the member, or one applied before did. Nothing later applies to it.
    Removed { epoch: u32 },
}

/// Apply a commit to the prior membership whose own leaf's signature key is
/// `signature_key` — the repair of a membership that a Welcome showed ended, at an epoch this
/// VTA has not seen (`rooms/keys/welcome/0.1`, *Rejoining after a removal*).
///
/// Ordered exactly as [`apply_commit`]: a replay is a no-op success and a gap is refused with
/// the epoch held. The commit that removes the member fixes the membership's removal epoch
/// ([`PriorCommit::Removed`]) and leaves its group where it was, as a removal leaves the
/// current group; from then on it is a prior membership with a known removal. Only a
/// membership whose removal is not yet known is advanced, and never to the epoch the member
/// joined at again or past it: the Welcome showed the removal at or below that epoch.
///
/// Written conditionally on the [`PRIOR`] row it read, so a join or an epoch floor applied
/// meanwhile is not overwritten; such a race is `Conflict`. The caller holds the member's
/// repair lock (`room_catch_up`), so two repairs do not race each other.
pub async fn apply_prior_commit(
    groups: &KeyspaceHandle,
    member: &Member,
    signature_key: &[u8],
    commit: &[u8],
    claimed_epoch: u64,
    now: u64,
) -> Result<PriorCommit, AppError> {
    let room_id = member.room_id();
    let Some(prior_raw) = groups.get_raw(member.key(PRIOR)).await? else {
        return Err(no_prior(member));
    };
    let mut prior: Vec<PriorMembership> = serde_json::from_slice(&prior_raw).map_err(|e| {
        AppError::Internal(format!("decode the prior memberships of `{room_id}`: {e}"))
    })?;
    let mut at = None;
    for (i, p) in prior.iter().enumerate() {
        if p.signature_key()? == signature_key {
            at = Some(i);
            break;
        }
    }
    let Some(at) = at else {
        return Err(no_prior(member));
    };
    if let Some(epoch) = prior[at].removed_epoch {
        return Ok(PriorCommit::Removed { epoch });
    }
    // The epoch the member joined at next: the next prior membership's, or the current one's.
    let next_join = match prior.get(at + 1) {
        Some(next) => next.joined_epoch,
        None => joined_epoch(groups, member).await?,
    };

    let mut room = SealedRoom::new(
        room_id,
        RoomGroup::restore(&prior[at].group.snapshot)
            .map_err(|e| AppError::Internal(format!("restore the group: {e}")))?,
    );
    let current = room.group().epoch();
    if claimed_epoch == current {
        return Ok(PriorCommit::Applied(current));
    }
    if claimed_epoch != current + 1 {
        return Err(AppError::Conflict(format!(
            "commit produces epoch {claimed_epoch} but this member's prior membership of room \
             `{room_id}` is at {current}; resume from {}",
            current + 1
        )));
    }
    // Room epoch `claimed + 1`: never at or past the next join, where the Welcome showed
    // this membership had already ended.
    if let Some(next_join) = next_join
        && claimed_epoch + 1 >= u64::from(next_join)
    {
        return Err(AppError::Conflict(format!(
            "a prior membership of room `{room_id}` cannot advance to room epoch {}: the member \
             joined again at {next_join}, and was removed before it",
            claimed_epoch + 1
        )));
    }

    let outcome = match room.apply_commit(commit) {
        Ok((_, link)) => {
            let p = &mut prior[at];
            if let Some(link) = link {
                p.group.links.push(link);
            }
            p.group = record_of(
                member,
                room.group(),
                std::mem::take(&mut p.group.links),
                now,
            )?;
            PriorCommit::Applied(room.group().epoch())
        }
        Err(RoomKeyError::Removed { epoch }) => {
            let p = &mut prior[at];
            p.removed_epoch = Some(epoch);
            p.removed_at = Some(now);
            PriorCommit::Removed { epoch }
        }
        Err(e) => {
            return Err(AppError::Validation(format!(
                "the commit did not process: {e}"
            )));
        }
    };
    let mut batch = vti_common::store::Batch::new();
    batch.require_unchanged(member.key(PRIOR), prior_raw);
    batch.insert(member.key(PRIOR), &prior)?;
    match groups.apply_batch(batch).await? {
        vti_common::store::BatchOutcome::Applied => Ok(outcome),
        vti_common::store::BatchOutcome::Refused { .. } => Err(AppError::Conflict(format!(
            "the prior memberships of room `{room_id}` changed while a commit was applied; \
             try again"
        ))),
    }
}

/// The refusal for a prior membership this VTA no longer holds.
fn no_prior(member: &Member) -> AppError {
    AppError::NotFound(format!(
        "this VTA holds no such prior membership of room `{}`",
        member.room_id()
    ))
}

/// One room this VTA can open, as `rooms/keys/list` reports it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeldRoom {
    pub room_id: String,
    pub epoch: u32,
    pub earliest_readable_epoch: u32,
}

/// Retain epoch links this VTA's principal fetched from the room's host.
///
/// The last leg of a joining member's backfill. A key holder accrues a rung for every
/// membership change it lives through — [`apply_commit`] keeps one from each — so what
/// arrives here is the history it did **not** live through.
///
/// Returns `(earliest_readable_epoch, stored)`.
///
/// # Why the answer is not "how many arrived"
///
/// A rung extends reach only if every rung above it is present too, so counting what was
/// delivered says nothing about what can now be read. The number worth returning is the one
/// this VTA can only get by *walking* what it holds — which is why the specification puts it
/// in the response and why a host serving the same rungs could not have answered it.
///
/// # A rung already held is never replaced
///
/// Same rule the hosts follow. A second rung for an epoch is either a replay — which must be
/// a no-op rather than an error, or a retried delivery becomes a failure — or an attempt to
/// re-point this member's history at key material of somebody else's choosing. Keeping the
/// first is the only reading that is safe under both.
pub async fn store_links(
    groups: &KeyspaceHandle,
    member: &Member,
    incoming: Vec<EpochLink>,
    now: u64,
) -> Result<(u32, usize), AppError> {
    let room_id = member.room_id();
    let record = load(groups, member)
        .await?
        .ok_or_else(|| no_group(member))?;

    // A rung at or below the floor is forgotten, whoever sends it — a member relaying a
    // mirror that has not been pruned — and is neither kept nor counted, nor refused.
    let floor = epoch_floor(groups, member).await?;
    let mut links: Vec<EpochLink> = record
        .links
        .into_iter()
        .filter(|l| l.epoch > floor)
        .collect();
    let mut stored = 0;
    for link in incoming {
        if link.epoch > floor && !links.iter().any(|held| held.epoch == link.epoch) {
            links.push(link);
            stored += 1;
        }
    }
    links.sort_by_key(|l| l.epoch);

    let group = RoomGroup::restore(&record.snapshot)
        .map_err(|e| AppError::Internal(format!("restore the group: {e}")))?;
    let mut room = SealedRoom::new(room_id, group);
    room.apply_epoch_floor(floor);
    room.add_links(links.clone());
    let earliest = room
        .earliest_readable_epoch()
        .map_err(|e| AppError::Internal(format!("walk the chain: {e}")))?;

    store(groups, member, room.group(), links, now).await?;
    Ok((earliest, stored))
}

/// Open a sealed record with the room's group key.
///
/// The key never leaves. That is the whole design: the caller sends ciphertext and gets
/// plaintext, and an oracle that returned the key would be a key-release call wearing a
/// different name.
pub async fn open_record(
    groups: &KeyspaceHandle,
    member: &Member,
    key: &str,
    version: u64,
    ciphertext: &str,
    nonce: &str,
    epoch: u32,
) -> Result<Vec<u8>, AppError> {
    open_record_detailed(groups, member, key, version, ciphertext, nonce, epoch)
        .await
        .map_err(AppError::from)
}

/// Why [`open_record_detailed`] did not open a record.
///
/// The epoch cases are apart from [`Self::App`] because their remedies differ, and
/// `rooms/keys/open/0.2` names each as an `unknownEpoch` reason: a member who is behind
/// applies the commits it missed, a member whose chain does not reach back needs it
/// extended (or cannot open the record at all), and a member who was removed can apply
/// nothing that will ever open the record.
#[derive(Debug)]
#[non_exhaustive]
pub enum OpenError {
    /// The record is sealed under a later epoch than this VTA's group: a commit has not
    /// been delivered. `held` is the room epoch the group is at.
    NotDelivered { epoch: u32, held: u64 },
    /// A commit this VTA applied removed the member from the group at `removed_at`, and
    /// the record is sealed under `epoch`, at or after it: it will never open here.
    Removed { epoch: u32, removed_at: u32 },
    /// The record is sealed under `epoch`, earlier than this VTA's group, and the retained
    /// epoch chain reaches back only to `earliest` (`rooms/keys/open/0.2`'s `beyondChain`).
    BeyondChain { epoch: u32, earliest: u32 },
    /// Anything else: no group, a group that does not restore, a record that did not open.
    App(AppError),
}

impl From<AppError> for OpenError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDelivered { epoch, held } => write!(
                f,
                "record is sealed under epoch {epoch} and this VTA holds the room at epoch \
                 {held}; a commit has not been delivered"
            ),
            Self::Removed { epoch, removed_at } => write!(
                f,
                "record is sealed under epoch {epoch}, and this member was removed from the \
                 room's group at epoch {removed_at}: nothing sealed from then on opens here"
            ),
            // `RoomKeyError::EpochUnreachable`'s words, which is what this case said before
            // it had a variant of its own.
            Self::BeyondChain { epoch, earliest } => write!(
                f,
                "{}",
                RoomKeyError::EpochUnreachable {
                    sealed: *epoch,
                    earliest: *earliest,
                }
            ),
            Self::App(e) => write!(f, "{e}"),
        }
    }
}

impl From<OpenError> for AppError {
    fn from(e: OpenError) -> Self {
        match e {
            OpenError::App(e) => e,
            other => AppError::Validation(other.to_string()),
        }
    }
}

/// [`open_record`], saying which epoch case refused it.
pub async fn open_record_detailed(
    groups: &KeyspaceHandle,
    member: &Member,
    key: &str,
    version: u64,
    ciphertext: &str,
    nonce: &str,
    epoch: u32,
) -> Result<Vec<u8>, OpenError> {
    open_record_at(
        groups,
        member,
        key,
        version,
        ciphertext,
        nonce,
        epoch,
        Search::Exact,
    )
    .await
    .map(|(plaintext, _)| plaintext)
}

/// Where [`open_record_at`] looks for the version a body was sealed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Search {
    /// The version given, only: the caller knows it, from `sealed.version` or because the
    /// record has not been curated since it was written.
    Exact,
    /// The version given, then each earlier one, newest first.
    ///
    /// For a record a host curated before it kept `sealed.version` (rooms `_shared/0.1`
    /// `SealedRecord`, `SealedRecordBody` *A record curated before `sealed.version`
    /// existed*): its version moved, the body stayed bound to the one it was sealed at, and
    /// nothing recorded which. The AEAD makes a wrong guess fail rather than mislead, and a
    /// reader checks the author's signed location against the version that opened, so the
    /// search recovers the record without trusting the host for the answer. Never above the
    /// version given: a body cannot have been sealed for a version the room had not reached.
    Earlier,
}

/// Open a record at the version its body was sealed at, and say which version that was.
///
/// The returned version is the one the AEAD opened at — the location a reader verifies
/// the author's signature against. It differs from `version` only where `search` is
/// [`Search::Earlier`] and an earlier version opened.
#[allow(clippy::too_many_arguments)]
pub async fn open_record_at(
    groups: &KeyspaceHandle,
    member: &Member,
    key: &str,
    version: u64,
    ciphertext: &str,
    nonce: &str,
    epoch: u32,
    search: Search,
) -> Result<(Vec<u8>, u64), OpenError> {
    let room_id = member.room_id();
    // The membership that held `epoch` opens it (`rooms/keys/open/0.2`): the current one,
    // or a prior one a removal ended — and an epoch between a removal and the next join is
    // `removed`, with that removal's epoch.
    let floor = epoch_floor(groups, member).await?;
    let (record, target) = match holding_for(groups, member, epoch, floor).await? {
        None => return Err(no_group(member).into()),
        Some(Holding::Removed { removed_at }) => {
            return Err(OpenError::Removed { epoch, removed_at });
        }
        Some(Holding::BeforeFirstJoin { earliest }) => {
            return Err(OpenError::BeyondChain { epoch, earliest });
        }
        Some(Holding::Group { record, target }) => (record, target),
    };
    let group = RoomGroup::restore(&record.snapshot)
        .map_err(|e| AppError::Internal(format!("restore the group: {e}")))?;

    let held = group.epoch() + 1;
    if u64::from(epoch) > held {
        // A removal leaves the group where it was, so "ahead of the group" is also what a
        // record sealed after it looks like. The row says which — the current group's
        // only: a prior membership's known removal was answered above, and one only a
        // Welcome evidenced is `notDelivered`, with that membership's epoch, until a repair
        // applies the removing commit to it (`rooms/keys/open/0.2`).
        if target == RepairTarget::Current
            && let Some(removed_at) = removed_at(groups, member).await?
            && epoch >= removed_at
        {
            return Err(OpenError::Removed { epoch, removed_at });
        }
        // Saying which epoch we hold turns "it does not open" — which reads like corruption
        // — into "you are behind", which an operator can act on.
        return Err(OpenError::NotDelivered { epoch, held });
    }

    // A record older than the current epoch is opened with *its own* epoch's key, walked out
    // of the retained chain. Without the links this VTA reaches only the epoch it is at, and
    // the error says which — an unreachable epoch is history that was severed or never
    // delivered, not a record that failed to decrypt.
    let mut room = SealedRoom::new(room_id, group);
    room.apply_epoch_floor(floor);
    room.add_links(record.links);
    let sealed = vti_rooms::wire::SealedContent {
        ciphertext: ciphertext.to_string(),
        nonce: nonce.to_string(),
        epoch,
        version: None,
    };
    let refuse = |e: RoomKeyError| match e {
        RoomKeyError::EpochUnreachable { sealed, earliest } => OpenError::BeyondChain {
            epoch: sealed,
            earliest,
        },
        e => OpenError::App(AppError::Validation(e.to_string())),
    };

    let first = match room.open_record(key, version, &sealed) {
        Ok(plaintext) => return Ok((plaintext, version)),
        Err(e) => e,
    };
    if search == Search::Exact || !matches!(first, RoomKeyError::DidNotOpen) {
        return Err(refuse(first));
    }
    for earlier in (1..version).rev() {
        match room.open_record(key, earlier, &sealed) {
            Ok(plaintext) => return Ok((plaintext, earlier)),
            Err(RoomKeyError::DidNotOpen) => {}
            Err(e) => return Err(refuse(e)),
        }
    }
    Err(refuse(first))
}

/// The room's epoch floor this key holder holds for `member`, `0` when it has learnt none.
pub async fn epoch_floor(groups: &KeyspaceHandle, member: &Member) -> Result<u32, AppError> {
    let floor: Option<u32> = groups.get(member.key(EPOCH_FLOOR)).await.map_err(|e| {
        AppError::Internal(format!(
            "read the epoch floor for `{}`: {e}",
            member.room_id()
        ))
    })?;
    Ok(floor.unwrap_or(0))
}

/// Apply a room's epoch floor learnt from any source — a host's `rooms/epoch/chain/0.2`,
/// the principal's `rooms/keys/chain/0.2`, a backfill — as `EpochFloor` requires, and
/// return the floor now held.
///
/// On a floor above the one held, **before returning**: keeps the higher floor (it never
/// falls), and rewrites the group row without every rung numbered at or below it. This key
/// holder keeps no derived storage, file or profile key between requests — each is walked
/// out of the chain on use — so the rungs are what there is to discard; from now on
/// [`store_links`] never stores one at or below the floor and every open, file key and
/// profile location refuses below it (`beyondChain`, an earliest epoch at or above the
/// floor), whatever it still holds. A lower or equal floor changes nothing.
pub async fn apply_epoch_floor(
    groups: &KeyspaceHandle,
    member: &Member,
    floor: u32,
    now: u64,
) -> Result<u32, AppError> {
    let held = epoch_floor(groups, member).await?;
    if floor <= held {
        return Ok(held);
    }
    // The floor first: a process that dies before the rungs go still refuses below it, and
    // the next application finds the same floor and discards them.
    groups
        .insert(member.key(EPOCH_FLOOR), &floor)
        .await
        .map_err(|e| {
            AppError::Internal(format!(
                "keep the epoch floor for `{}`: {e}",
                member.room_id()
            ))
        })?;
    if let Some(record) = load(groups, member).await? {
        let group = RoomGroup::restore(&record.snapshot)
            .map_err(|e| AppError::Internal(format!("restore the group: {e}")))?;
        let kept: Vec<EpochLink> = record
            .links
            .into_iter()
            .filter(|l| l.epoch > floor)
            .collect();
        store(groups, member, &group, kept, now).await?;
    }
    // The prior memberships likewise: one wholly below the floor — every epoch it opened,
    // up to the one before its removal, below the floor — has nothing left to open and goes
    // whole; the rest lose their rungs at or below it.
    // A membership whose removal is not yet known ends, at the latest, below the next one's
    // join epoch — the next prior membership's, or the current group's.
    let prior = prior_memberships(groups, member).await?;
    if !prior.is_empty() {
        let current_join = joined_epoch(groups, member).await?;
        let next_joins: Vec<Option<u32>> = prior
            .iter()
            .skip(1)
            .map(|p| p.joined_epoch)
            .chain(std::iter::once(current_join))
            .collect();
        let kept: Vec<PriorMembership> = prior
            .into_iter()
            .zip(next_joins)
            .filter(|(p, next_join)| match p.removed_epoch.or(*next_join) {
                Some(end) => end > floor,
                None => true,
            })
            .map(|(mut p, _)| {
                p.group.links.retain(|l| l.epoch > floor);
                p
            })
            .collect();
        let write = if kept.is_empty() {
            groups.remove(member.key(PRIOR)).await
        } else {
            groups.insert(member.key(PRIOR), &kept).await
        };
        write.map_err(|e| {
            AppError::Internal(format!(
                "prune the prior memberships of `{}`: {e}",
                member.room_id()
            ))
        })?;
    }
    Ok(floor)
}

/// The first room epoch `member` cannot open because a commit removed them, if one did.
pub async fn removed_at(groups: &KeyspaceHandle, member: &Member) -> Result<Option<u32>, AppError> {
    let row: Option<RemovalRecord> = groups.get(member.key(REMOVED)).await.map_err(|e| {
        AppError::Internal(format!(
            "read the removal record for `{}`: {e}",
            member.room_id()
        ))
    })?;
    Ok(row.map(|r| r.epoch))
}

async fn record_removal(
    groups: &KeyspaceHandle,
    member: &Member,
    epoch: u32,
    now: u64,
) -> Result<(), AppError> {
    groups
        .insert(
            member.key(REMOVED),
            &RemovalRecord {
                epoch,
                removed_at: now,
            },
        )
        .await
        .map_err(|e| {
            AppError::Internal(format!(
                "record the removal from `{}`: {e}",
                member.room_id()
            ))
        })
}

/// Record an invitation as consumed, refusing a second use.
///
/// Single use means single use, and this record is the only thing that remembers. It
/// deliberately outlives the group it admitted: a member who leaves a room discards the
/// group, and without this row the same invitation would let them be re-added with no fresh
/// consent from the owner.
pub async fn consume_invitation(
    invitations: &KeyspaceHandle,
    credential_id: &str,
    room_id: &str,
    now: u64,
) -> Result<(), AppError> {
    let key = invitation_key(credential_id);
    if invitations
        .get_raw(key.clone())
        .await
        .map_err(|e| AppError::Internal(format!("read the invitation record: {e}")))?
        .is_some()
    {
        return Err(AppError::Conflict(format!(
            "invitation `{credential_id}` has already been used"
        )));
    }
    invitations
        .insert(
            key,
            &serde_json::json!({ "roomId": room_id, "consumedAt": now }),
        )
        .await
        .map_err(|e| AppError::Internal(format!("record the invitation: {e}")))
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

/// Why a group could not be founded.
#[derive(Debug)]
#[non_exhaustive]
pub enum CreateGroupError {
    /// This VTA already holds group state for the room, at this room epoch.
    AlreadyExists {
        epoch: u32,
    },
    App(AppError),
}

/// Found `room_id`'s group with `member_did` as its only leaf —
/// `rooms/owner/group/create/0.1`.
///
/// Returns the room epoch, 1: MLS counts from 0 and a room from 1, so a group
/// founded here agrees with the epoch a host records at registration without
/// anything being minted.
///
/// **Never replaces a group.** A group this VTA joined by a Welcome, or founded
/// earlier, holds the key schedule every sealed record of the room depends on;
/// founding over it would leave those records unopenable by this member, and
/// the member's commits unreadable by everyone else.
pub async fn create_group(
    groups: &KeyspaceHandle,
    member: &Member,
    now: u64,
) -> Result<u32, CreateGroupError> {
    let room_id = member.room_id();
    if let Some(existing) = load(groups, member).await.map_err(CreateGroupError::App)? {
        let group = RoomGroup::restore(&existing.snapshot).map_err(|e| {
            CreateGroupError::App(AppError::Internal(format!("restore the group: {e}")))
        })?;
        return Err(CreateGroupError::AlreadyExists {
            epoch: SealedRoom::new(room_id, group).room_epoch(),
        });
    }
    let group = RoomGroup::create(member.persona())
        .map_err(|e| CreateGroupError::App(AppError::Internal(format!("found the group: {e}"))))?;
    // The room epoch is the MLS epoch plus one, as `SealedRoom::room_epoch` has it.
    let epoch = u32::try_from(group.epoch() + 1).unwrap_or(u32::MAX);
    store(groups, member, &group, Vec::new(), now)
        .await
        .map_err(CreateGroupError::App)?;
    Ok(epoch)
}

/// Which epoch advance a pending advance makes — a membership change, or none.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum AdvanceKind {
    /// `rooms/owner/group/add`. The default because every row written before
    /// the field existed was one.
    #[default]
    Admission,
    /// `rooms/owner/group/remove`.
    Removal,
    /// `rooms/owner/group/renew`: a commit that adds and removes nobody.
    Renewal,
}

impl AdvanceKind {
    /// The noun an operator reads.
    pub fn noun(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::Removal => "removal",
            Self::Renewal => "renewal",
        }
    }
}

/// An epoch advance the host has not yet confirmed — items 3 to 6 of
/// `rooms/owner/group/add/0.3`, `rooms/owner/group/remove/0.4`, and
/// `rooms/owner/group/renew/0.2`.
///
/// # Why the whole advanced group, and not just the commit
///
/// MLS lets a member process other members' commits from the wire, never its
/// own: the committer's path secrets exist only in the state that produced the
/// commit. So once the change is built, the *advanced group* is the only way to
/// reach the next epoch. It is kept here, beside the live group it would
/// replace, until the host's answer says which of the two is true.
///
/// The live group is not touched until then. A record sealed while an advance
/// is pending is sealed at the epoch the room is still at — which, for a
/// removal, the member being removed can still read. That is the cost of
/// remote-first, and it lasts only until the host answers.
///
/// Serialises as the admission-only row it generalises did, plus `kind`, so a
/// row written before removal existed reads as an admission.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingAdvance {
    /// Admission, removal or renewal.
    #[serde(default)]
    pub kind: AdvanceKind,
    /// The group after the change.
    pub snapshot: GroupSnapshot,
    /// The live group's links plus the one this advance produced.
    pub links: Vec<EpochLink>,
    /// Who is being admitted or removed. A renewal changes nobody's membership, and
    /// names the committer — the owner persona whose leaf it updates.
    pub member: String,
    /// The host the epoch advance goes to, so a later request can reconcile
    /// against the same one.
    pub host: String,
    /// The room epoch the change produces.
    pub epoch: u32,
    /// The rung this advance produced, for `rooms/epoch/mint`.
    pub link: Option<EpochLink>,
    /// The commit, base64url, for `rooms/epoch/mint`.
    pub commit: String,
    /// The Welcome, base64url, for the newcomer's key holder. An admission's
    /// only; a removal welcomes nobody.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome: Option<String>,
    /// The admitted KeyPackage's `KeyPackageRef`, base64url. An admission's only — what
    /// the admission is remembered by once applied (`rooms/owner/group/add/0.3` item 8). An
    /// admission retained before the field existed has none, and is applied without being
    /// retained: a repeat of it is `alreadyMember`, as it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_package_ref: Option<String>,
    /// Unix seconds it was built.
    pub created_at: u64,
    /// A removal at `rooms/owner/group/remove/0.4` on an attributed room: the revocation
    /// list withdrawing the member, signed and kept before anything was sent (item 5), and
    /// delivered to the host **before** the advance (item 6). Absent on every other
    /// advance, on a private room's removal, and on one left pending by 0.1 — each settled
    /// by item 8.3 alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<PendingRevocation>,
}

/// The withdrawal half of a pending removal (`rooms/owner/group/remove/0.4`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingRevocation {
    /// The list as signed.
    pub list: serde_json::Value,
    /// The list held before it, restored if no host accepts this one (item 6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<serde_json::Value>,
    /// The withdrawal's `revokedAt`.
    pub revoked_at: String,
    /// Whether the host answered the delivery with this list's head. Until it has, the
    /// advance has not been sent, and a later request delivers the list again first
    /// (item 8).
    #[serde(default)]
    pub confirmed: bool,
}

/// Why an admission could not be built.
#[derive(Debug)]
#[non_exhaustive]
pub enum PrepareAddError {
    NoGroup,
    AlreadyMember,
    KeyPackageInvalid(String),
    App(AppError),
}

/// Retain `pending` as the room's one pending advance, durably — the step
/// every advance takes **before** anything is sent to a host (item 3).
///
/// Refuses when the slot is taken: the caller settles what it finds first
/// (item 6), so an occupied slot here is a request racing another for the same
/// room, and overwriting it would lose an advance the host may have accepted.
/// The claim is one atomic insert-if-absent, so of two racing requests exactly
/// one holds the slot.
async fn retain(
    groups: &KeyspaceHandle,
    owner: &Member,
    pending: &PendingAdvance,
) -> Result<(), AppError> {
    let room_id = owner.room_id();
    let taken = |found: &PendingAdvance| {
        AppError::Conflict(format!(
            "room `{room_id}` already has a pending {} to epoch {} waiting on host `{}`; \
             it is settled before another advance is built",
            found.kind.noun(),
            found.epoch,
            found.host
        ))
    };
    let claimed = groups
        .insert_if_absent(owner.key(ADVANCE), pending)
        .await
        .map_err(|e| {
            AppError::Internal(format!("store the pending {}: {e}", pending.kind.noun()))
        })?;
    if !claimed {
        let found = pending_advance(groups, owner)
            .await?
            .unwrap_or_else(|| pending.clone());
        return Err(taken(&found));
    }
    // `rooms/owner/group/add/0.3` item 8: the last admission is kept until the owner builds
    // its next advance of the room. This is that moment — a request after it is no longer a
    // retry of anything (the advance may itself remove the member).
    discard_retained_admission(groups, owner).await
}

/// Build the admission of `member` to `owner`'s group from their KeyPackage and retain it,
/// durably, as a [`PendingAdvance`] — **before** anything is sent to a host
/// (items 2 and 3). The live group is unchanged.
pub async fn prepare_add(
    groups: &KeyspaceHandle,
    owner: &Member,
    host: &str,
    member: &str,
    key_package: &[u8],
    now: u64,
) -> Result<PendingAdvance, PrepareAddError> {
    let room_id = owner.room_id();
    let record = load(groups, owner)
        .await
        .map_err(PrepareAddError::App)?
        .ok_or(PrepareAddError::NoGroup)?;
    let group = RoomGroup::restore(&record.snapshot)
        .map_err(|e| PrepareAddError::App(AppError::Internal(format!("restore the group: {e}"))))?;
    if group.leaf_of(member).is_some() {
        return Err(PrepareAddError::AlreadyMember);
    }
    let mut room = SealedRoom::new(room_id, group);
    room.apply_epoch_floor(
        epoch_floor(groups, owner)
            .await
            .map_err(PrepareAddError::App)?,
    );
    room.add_links(record.links);

    let (change, link) = room
        .add_member(key_package)
        .map_err(|e| PrepareAddError::KeyPackageInvalid(e.to_string()))?;
    // The leaf must be the party the owner named. A KeyPackage is a stranger's
    // bytes; one carrying another identity would admit somebody the owner
    // never meant, under the name they did.
    if room.group().leaf_of(member).is_none() {
        return Err(PrepareAddError::KeyPackageInvalid(format!(
            "the KeyPackage's leaf does not identify `{member}`"
        )));
    }
    let welcome = change.welcome.ok_or_else(|| {
        PrepareAddError::App(AppError::Internal("an add produced no Welcome".into()))
    })?;
    // What the admission is remembered by once applied (`rooms/owner/group/add/0.3` item 8).
    // The add above already validated the KeyPackage, so this cannot fail on its bytes.
    let key_package_ref = vti_rooms::mls::key_package_ref(key_package)
        .map_err(|e| PrepareAddError::KeyPackageInvalid(e.to_string()))?;

    let pending = PendingAdvance {
        kind: AdvanceKind::Admission,
        snapshot: room.group().snapshot().map_err(|e| {
            PrepareAddError::App(AppError::Internal(format!("snapshot the group: {e}")))
        })?,
        links: room.links(),
        member: member.to_string(),
        host: host.to_string(),
        epoch: room.room_epoch(),
        link,
        commit: B64.encode(&change.commit),
        welcome: Some(B64.encode(&welcome)),
        key_package_ref: Some(B64.encode(&key_package_ref)),
        created_at: now,
        revocation: None,
    };
    retain(groups, owner, &pending)
        .await
        .map_err(PrepareAddError::App)?;
    Ok(pending)
}

/// Why a removal could not be built — `rooms/owner/group/remove/0.4` item 1.
#[derive(Debug)]
#[non_exhaustive]
pub enum PrepareRemoveError {
    /// This agent holds no group for the room.
    NoGroup,
    /// `member` has no leaf in the group.
    NotMember,
    /// `member` is this agent's own leaf. A key holder does not remove itself.
    OwnLeaf,
    App(AppError),
}

/// Build the removal of `member`'s leaf from `owner`'s group and retain it, durably, as a
/// [`PendingAdvance`] — **before** anything is sent to a host
/// (`rooms/owner/group/remove/0.4` items 1 to 3). The live group is unchanged:
/// the commit and the link are made on a copy, which is what is kept.
///
/// `ownLeaf` is `owner`'s own persona only. Another persona this VTA holds for somebody
/// else is a different member of the room, and removable like any other.
pub async fn prepare_remove(
    groups: &KeyspaceHandle,
    owner: &Member,
    host: &str,
    member: &str,
    now: u64,
) -> Result<PendingAdvance, PrepareRemoveError> {
    let room_id = owner.room_id();
    if owner.persona() == member {
        return Err(PrepareRemoveError::OwnLeaf);
    }
    let record = load(groups, owner)
        .await
        .map_err(PrepareRemoveError::App)?
        .ok_or(PrepareRemoveError::NoGroup)?;
    if record.member_did == member {
        return Err(PrepareRemoveError::OwnLeaf);
    }
    let group = RoomGroup::restore(&record.snapshot).map_err(|e| {
        PrepareRemoveError::App(AppError::Internal(format!("restore the group: {e}")))
    })?;
    let leaf = group.leaf_of(member).ok_or(PrepareRemoveError::NotMember)?;
    let mut room = SealedRoom::new(room_id, group);
    room.apply_epoch_floor(
        epoch_floor(groups, owner)
            .await
            .map_err(PrepareRemoveError::App)?,
    );
    room.add_links(record.links);

    // Item 2: the commit and the link that seals the outgoing epoch's key under the
    // incoming one — so the members who remain keep reading what came before, and the
    // one removed reads nothing after.
    let (change, link) = room.remove_member(leaf).map_err(|e| {
        PrepareRemoveError::App(AppError::Internal(format!("build the removal: {e}")))
    })?;

    let pending = PendingAdvance {
        kind: AdvanceKind::Removal,
        snapshot: room.group().snapshot().map_err(|e| {
            PrepareRemoveError::App(AppError::Internal(format!("snapshot the group: {e}")))
        })?,
        links: room.links(),
        member: member.to_string(),
        host: host.to_string(),
        epoch: room.room_epoch(),
        link,
        commit: B64.encode(&change.commit),
        welcome: None,
        key_package_ref: None,
        created_at: now,
        revocation: None,
    };
    retain(groups, owner, &pending)
        .await
        .map_err(PrepareRemoveError::App)?;
    Ok(pending)
}

/// Build the renewal of `owner`'s group — a commit that adds and removes nobody, updating
/// the owner's own leaf — and retain it, durably, as a [`PendingAdvance`] **before**
/// anything is sent to a host (`rooms/owner/group/renew/0.2` items 2 and 3). The live
/// group is unchanged: the commit and the link are made on a copy, which is what is kept.
///
/// `None` when this agent holds no group for the room (item 1, `noGroup`).
pub async fn prepare_renew(
    groups: &KeyspaceHandle,
    owner: &Member,
    host: &str,
    now: u64,
) -> Result<Option<PendingAdvance>, AppError> {
    let Some(record) = load(groups, owner).await? else {
        return Ok(None);
    };
    let group = RoomGroup::restore(&record.snapshot)
        .map_err(|e| AppError::Internal(format!("restore the group: {e}")))?;
    let mut room = SealedRoom::new(owner.room_id(), group);
    room.apply_epoch_floor(epoch_floor(groups, owner).await?);
    room.add_links(record.links);

    // Item 2 (and item 7): an update of the committer's own leaf, carrying no proposal
    // that adds or removes anybody, and the link sealing the outgoing epoch's key under
    // the incoming one so every member who applies it keeps reading what came before.
    let (change, link) = room
        .renew()
        .map_err(|e| AppError::Internal(format!("build the renewal: {e}")))?;

    let pending = PendingAdvance {
        kind: AdvanceKind::Renewal,
        snapshot: room
            .group()
            .snapshot()
            .map_err(|e| AppError::Internal(format!("snapshot the group: {e}")))?,
        links: room.links(),
        member: owner.persona().to_string(),
        host: host.to_string(),
        epoch: room.room_epoch(),
        link,
        commit: B64.encode(&change.commit),
        welcome: None,
        key_package_ref: None,
        created_at: now,
        revocation: None,
    };
    retain(groups, owner, &pending).await?;
    Ok(Some(pending))
}

/// The advance `owner`'s group has waiting on its host, if any — admission, removal or
/// renewal.
///
/// The admission-only slot an earlier build wrote (`room-add:<room>`) is moved here by
/// [`migrate_legacy`], so a row left there is settled, not lost.
pub async fn pending_advance(
    groups: &KeyspaceHandle,
    owner: &Member,
) -> Result<Option<PendingAdvance>, AppError> {
    groups
        .get::<PendingAdvance>(owner.key(ADVANCE))
        .await
        .map_err(|e| AppError::Internal(format!("read the pending advance: {e}")))
}

/// The host accepted the advance: the pending group becomes the live one
/// (item 5). One write replaces the group, then the pending row goes; a crash
/// between the two leaves a pending row whose epoch the live group already
/// has, which [`reconcile_pending_advance`] recognises and clears.
pub async fn promote_pending_advance(
    groups: &KeyspaceHandle,
    owner: &Member,
    pending: &PendingAdvance,
    now: u64,
) -> Result<(), AppError> {
    load(groups, owner).await?.ok_or_else(|| no_group(owner))?;
    let group = RoomGroup::restore(&pending.snapshot)
        .map_err(|e| AppError::Internal(format!("restore the pending group: {e}")))?;
    store(groups, owner, &group, pending.links.clone(), now).await?;
    // Before the pending row goes: a crash between the two leaves the pending row, which
    // the next request recognises as promoted and retains again.
    retain_admission(groups, owner, pending, now).await?;
    discard_pending_advance(groups, owner).await
}

/// An applied admission becomes the room's retained admission (`rooms/owner/group/add/0.3`
/// items 6 and 8). A removal or renewal retains nothing — and was preceded, when it was
/// built, by the discard of whatever was retained.
async fn retain_admission(
    groups: &KeyspaceHandle,
    owner: &Member,
    pending: &PendingAdvance,
    now: u64,
) -> Result<(), AppError> {
    let (AdvanceKind::Admission, Some(welcome), Some(key_package_ref)) =
        (pending.kind, &pending.welcome, &pending.key_package_ref)
    else {
        return Ok(());
    };
    groups
        .insert(
            owner.key(ADMITTED),
            &RetainedAdmission {
                member: pending.member.clone(),
                key_package_ref: key_package_ref.clone(),
                epoch: pending.epoch,
                welcome: welcome.clone(),
                ratchet_tree: None,
                applied_at: now,
            },
        )
        .await
        .map_err(|e| AppError::Internal(format!("retain the applied admission: {e}")))
}

/// The admission `owner` last applied in the room, while it is still kept
/// (`rooms/owner/group/add/0.3` item 8). One kept past its 24 hours is discarded here, so
/// it is never served late even before the sweep reaches it.
pub async fn retained_admission(
    groups: &KeyspaceHandle,
    owner: &Member,
    now: u64,
) -> Result<Option<RetainedAdmission>, AppError> {
    let row: Option<RetainedAdmission> = groups
        .get(owner.key(ADMITTED))
        .await
        .map_err(|e| AppError::Internal(format!("read the retained admission: {e}")))?;
    match row {
        Some(r) if r.kept_at(now) => Ok(Some(r)),
        Some(_) => {
            discard_retained_admission(groups, owner).await?;
            Ok(None)
        }
        None => Ok(None),
    }
}

async fn discard_retained_admission(
    groups: &KeyspaceHandle,
    owner: &Member,
) -> Result<(), AppError> {
    groups
        .remove(owner.key(ADMITTED))
        .await
        .map_err(|e| AppError::Internal(format!("discard the retained admission: {e}")))
}

/// Discard every retained admission past its 24 hours (`rooms/owner/group/add/0.3` item 8,
/// "and MUST discard it then"), for the storage thread's sweep. [`retained_admission`]
/// already refuses to serve one late; this is what removes the Welcome from disk when
/// nobody asks again. Returns how many were discarded.
pub async fn sweep_retained_admissions(
    groups: &KeyspaceHandle,
    now: u64,
) -> Result<usize, AppError> {
    let rows = groups
        .prefix_iter_raw(format!("{ADMITTED}/").into_bytes())
        .await
        .map_err(|e| AppError::Internal(format!("scan retained admissions: {e}")))?;
    let mut discarded = 0;
    for (key, raw) in rows {
        // A row that does not read is not one this build can ever serve: discard it too.
        let keep = serde_json::from_slice::<RetainedAdmission>(&raw).is_ok_and(|r| r.kept_at(now));
        if !keep {
            groups
                .remove(key)
                .await
                .map_err(|e| AppError::Internal(format!("discard a retained admission: {e}")))?;
            discarded += 1;
        }
    }
    Ok(discarded)
}

/// The host refused, or the room has moved past it: forget the advance
/// (items 5 and 6). The live group never changed.
pub async fn discard_pending_advance(
    groups: &KeyspaceHandle,
    owner: &Member,
) -> Result<(), AppError> {
    groups
        .remove(owner.key(ADVANCE))
        .await
        .map_err(|e| AppError::Internal(format!("clear the pending advance: {e}")))
}

/// Record the pending advance as it now stands — a removal's signed list attached (item 5)
/// or confirmed by its host (item 6) — over the row [`retain`] claimed.
pub async fn update_pending_advance(
    groups: &KeyspaceHandle,
    owner: &Member,
    pending: &PendingAdvance,
) -> Result<(), AppError> {
    groups
        .insert(owner.key(ADVANCE), pending)
        .await
        .map_err(|e| AppError::Internal(format!("record the pending advance: {e}")))?;
    groups.persist().await
}

/// What a found pending advance turned out to be, given the host's epoch.
#[derive(Debug, PartialEq, Eq)]
pub enum Reconciled {
    /// The host is at the pending epoch: it accepted. Applied.
    Applied,
    /// The host is at the live group's epoch: it never did. Discarded.
    Discarded,
    /// The host is somewhere else — another admin advanced the room. Discarded,
    /// and the live group is behind the host.
    Conflict,
}

/// Item 6: settle a pending advance against the epoch the host reports.
pub async fn reconcile_pending_advance(
    groups: &KeyspaceHandle,
    owner: &Member,
    pending: &PendingAdvance,
    host_epoch: u32,
    now: u64,
) -> Result<Reconciled, AppError> {
    let live_epoch = match load(groups, owner).await? {
        Some(r) => SealedRoom::new(
            owner.room_id(),
            RoomGroup::restore(&r.snapshot)
                .map_err(|e| AppError::Internal(format!("restore the group: {e}")))?,
        )
        .room_epoch(),
        None => 0,
    };
    if live_epoch == pending.epoch {
        // Promoted already; only the pending row survived a crash — perhaps before the
        // admission was retained, so it is retained (again) here.
        retain_admission(groups, owner, pending, now).await?;
        discard_pending_advance(groups, owner).await?;
        return Ok(Reconciled::Applied);
    }
    if host_epoch == pending.epoch {
        promote_pending_advance(groups, owner, pending, now).await?;
        return Ok(Reconciled::Applied);
    }
    discard_pending_advance(groups, owner).await?;
    Ok(if host_epoch == live_epoch {
        Reconciled::Discarded
    } else {
        Reconciled::Conflict
    })
}

// ─── Migration from the per-room keying ──────────────────────────────────

/// Rooms with a group row the per-room build wrote (`room-group:<roomId>`), not yet moved.
pub async fn legacy_rooms(groups: &KeyspaceHandle) -> Result<Vec<String>, AppError> {
    let keys = groups
        .prefix_keys(legacy::GROUP_PREFIX.as_bytes().to_vec())
        .await?;
    Ok(keys
        .into_iter()
        .filter_map(|k| {
            String::from_utf8_lossy(&k)
                .strip_prefix(legacy::GROUP_PREFIX)
                .map(str::to_string)
        })
        .collect())
}

/// The group row the per-room build wrote for `room_id`, if it is still there.
pub async fn legacy_group(
    groups: &KeyspaceHandle,
    room_id: &str,
) -> Result<Option<RoomGroupRecord>, AppError> {
    groups
        .get(legacy::group(room_id))
        .await
        .map_err(|e| AppError::Internal(format!("read legacy group state for `{room_id}`: {e}")))
}

/// What [`migrate_legacy`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Migrated {
    /// Nothing to move.
    Nothing,
    /// The room's rows now live under the member.
    Moved,
    /// The member already holds group state of its own for the room: the legacy row was
    /// left where it is, unmerged, rather than chosen between.
    Kept,
}

/// Move what a build keyed by room alone holds for `member.room_id()` under `member`.
///
/// The caller decides who the rows belong to ([`crate::operations::room_member`] — the
/// persona the group's own leaf identifies); this only moves them, so it is safe to run on
/// every touch and from any number of requests at once:
///
/// - The pending KeyPackage, advance (either slot) and root memory move first, the group
///   row last. Each is one atomic [`KeyspaceHandle::move_if_unchanged`], so a crash leaves
///   the group row in place and the next touch finishes the job.
/// - A KeyPackage is moved only when its leaf identifies `member`: a package minted for
///   somebody else is not theirs to join with.
/// - Nothing already under `member` is overwritten. A target that exists wins, and the
///   legacy row is left alone rather than merged — two group states are not reconcilable.
/// - [`REMOVED`] and [`PRIOR`] have no legacy form: the per-room build wrote neither, and a
///   [`PRIOR`] row exists only beside a group already under its member, which a legacy row
///   never overwrites. So there is nothing of either to move.
pub async fn migrate_legacy(
    groups: &KeyspaceHandle,
    member: &Member,
) -> Result<Migrated, AppError> {
    let room_id = member.room_id();
    let Some(group_raw) = groups.get_raw(legacy::group(room_id)).await? else {
        return Ok(Migrated::Nothing);
    };

    // The KeyPackage, only if it is this member's.
    if let Some(raw) = groups.get_raw(legacy::key_package(room_id)).await?
        && let Ok(kp) = serde_json::from_slice::<PendingKeyPackage>(&raw)
        && kp.snapshot.member_did() == member.persona()
    {
        move_row(
            groups,
            legacy::key_package(room_id),
            raw,
            member.key(KEY_PACKAGE),
            &kp,
        )
        .await?;
    }
    // The advance — the generalised slot, then the admission-only one. One slot per member,
    // so whichever arrives second finds it taken and stays put (and is reported below).
    for old in [legacy::advance(room_id), legacy::add(room_id)] {
        if let Some(raw) = groups.get_raw(old.clone()).await?
            && let Ok(advance) = serde_json::from_slice::<PendingAdvance>(&raw)
        {
            move_row(groups, old, raw, member.key(ADVANCE), &advance).await?;
        }
    }
    if let Some(raw) = groups.get_raw(legacy::roots(room_id)).await?
        && let Ok(roots) = serde_json::from_slice::<RootHistory>(&raw)
    {
        move_row(
            groups,
            legacy::roots(room_id),
            raw,
            member.key(ROOTS),
            &roots,
        )
        .await?;
    }

    let record: RoomGroupRecord = serde_json::from_slice(&group_raw).map_err(|e| {
        AppError::Internal(format!("decode legacy group state for `{room_id}`: {e}"))
    })?;
    Ok(
        match move_row(
            groups,
            legacy::group(room_id),
            group_raw,
            member.key(GROUP),
            &record,
        )
        .await?
        {
            MoveOutcome::Moved | MoveOutcome::SourceMissing | MoveOutcome::SourceChanged => {
                Migrated::Moved
            }
            MoveOutcome::TargetExists => {
                tracing::warn!(
                    room = %room_id,
                    member = %member.persona(),
                    "a group row from before per-member keying was left in place: this \
                     member already holds group state of its own for the room"
                );
                Migrated::Kept
            }
        },
    )
}

async fn move_row<V: serde::Serialize>(
    groups: &KeyspaceHandle,
    old: String,
    expected: Vec<u8>,
    new: String,
    value: &V,
) -> Result<MoveOutcome, AppError> {
    groups
        .move_if_unchanged(old, expected, new, value)
        .await
        .map_err(|e| AppError::Internal(format!("migrate room state: {e}")))
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

/// How many `(headVersion, root)` observations to keep per room.
///
/// One is weaker than it looks in a specific way, and stronger than it looks in
/// another. It *does* catch a host that alternates at one version — `(V, A)`
/// then `(V, B)` differ, and differ again on the way back. What it misses is a
/// head that **advances and then goes backwards**: `(V, A)`, `(V+1, X)`,
/// `(V, B)` leaves the agent holding `V+1` with nothing to compare `V` against.
/// That is the mirror case and the rollback case, which are the two this is for.
///
/// Sixteen versions is more history than a member reads across in a session, and
/// a few hundred bytes.
const KEEP_ROOTS: usize = 16;

/// What a host has said about a room's tree, over time.
///
/// **Keyed by room and member, not by host**, and the host half is the decision worth
/// not undoing. A
/// room's tree at version `V` is a fact about the *room*; who served it is not
/// part of that fact. Keying by `(room, host)` would file two hosts of one room
/// in two drawers and never compare them — and a room may deliberately have
/// several, a mirror serving reads while its primary takes writes.
///
/// Keyed this way, a member who reads the same room from two of its hosts gets
/// the comparison for free: two hosts reporting **different roots at one
/// `headVersion`** is exactly as damning as one host disagreeing with itself.
/// That is a comparison the specification's own list does not include, and it
/// needs no gossip channel, no anchor and no second member.
///
/// The member half is context isolation. It is a record of when one member read one room,
/// and two personas sharing this VTA are two people whose reading is none of each other's
/// business — so each keeps its own, as each keeps its own group.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootHistory {
    /// Observations, most recent `headVersion` last. At most [`KEEP_ROOTS`].
    pub seen: Vec<RootObservation>,
    /// The highest `headVersion` ever seen for this room.
    ///
    /// Separate from `seen` because it answers a question no single pair can:
    /// **has this room gone backwards?** A pruned observation still leaves this
    /// behind.
    pub highest: u64,
    /// The version at which this room was caught, if it ever was.
    ///
    /// **Remembered rather than recomputed.** A conflict is a fact about the
    /// past, and the pair that revealed it is prunable — an agent that inferred
    /// "caught" from what it still holds would exonerate a host by doing enough
    /// reading. Once set it is never cleared here: it is cleared by
    /// [`forget`], with the membership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caught_at: Option<u64>,
}

/// One thing a host said about a room's tree.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootObservation {
    pub head_version: u64,
    /// The root, as the wire spells it — a `DigestMultibase`.
    pub root: String,
}

/// What comparing a root against what is held came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootVerdict {
    /// Seen at this head before, same root.
    Agree,
    /// Seen at this head before, **different root**. A host caught: there is no
    /// write to attribute the difference to, because a write would have moved
    /// the head.
    Conflict,
    /// First observation at this head. Not evidence of anything — a memory of
    /// one is not a comparison.
    NoneHeld,
}

/// Record what a host asserted, and say what it came to.
///
/// The write happens either way, including on a conflict: an agent that stopped
/// recording once it caught a host would forget the evidence at the moment it
/// acquired it.
pub async fn observe_head(
    groups: &KeyspaceHandle,
    member: &Member,
    head_version: u64,
    root: &str,
) -> Result<RootVerdict, AppError> {
    let room_id = member.room_id();
    let key = member.key(ROOTS);
    let mut history = root_history(groups, member).await?;

    let verdict = match history.seen.iter().find(|o| o.head_version == head_version) {
        Some(prior) if prior.root == root => RootVerdict::Agree,
        Some(_) => RootVerdict::Conflict,
        None => RootVerdict::NoneHeld,
    };

    if matches!(verdict, RootVerdict::Conflict) {
        // Earliest wins: the first version at which this host was caught is the
        // one worth naming, and later conflicts do not make the first less true.
        history.caught_at = Some(
            history
                .caught_at
                .map_or(head_version, |v| v.min(head_version)),
        );
    }
    if matches!(verdict, RootVerdict::NoneHeld) {
        history.seen.push(RootObservation {
            head_version,
            root: root.to_string(),
        });
        history.seen.sort_by_key(|o| o.head_version);
        // Drop the OLDEST versions, not the oldest writes: what a member is
        // likely to read again is what the room is at now.
        if history.seen.len() > KEEP_ROOTS {
            let excess = history.seen.len() - KEEP_ROOTS;
            history.seen.drain(0..excess);
        }
    }
    history.highest = history.highest.max(head_version);

    groups
        .insert(key, &history)
        .await
        .map_err(|e| AppError::Internal(format!("record the root history of `{room_id}`: {e}")))?;
    Ok(verdict)
}

/// Everything this agent has been told about a room's tree, for a caller that
/// wants to compare out of band.
///
/// A member with none of its own reads the one the per-room build kept, if any: that
/// memory was this VTA's before members were told apart, and dropping it on upgrade would
/// exonerate a host it had already caught. The member's first observation then writes it
/// forward under the member.
pub async fn root_history(
    groups: &KeyspaceHandle,
    member: &Member,
) -> Result<RootHistory, AppError> {
    let room_id = member.room_id();
    let read =
        |e: AppError| AppError::Internal(format!("read the root history of `{room_id}`: {e}"));
    if let Some(h) = groups.get(member.key(ROOTS)).await.map_err(read)? {
        return Ok(h);
    }
    Ok(groups
        .get(legacy::roots(room_id))
        .await
        .map_err(read)?
        .unwrap_or_default())
}

// ─── The member's personal label (`rooms/keys/label/0.1`) ─────────────────

/// A member's personal label for one room, as this VTA keeps it ([`LABEL`]).
///
/// At least one detail, always: a label whose last detail is removed is deleted, never
/// stored empty (`rooms/keys/label/0.1` recipient item 4). Every string is kept exactly as
/// it arrived — never trimmed, case-folded or normalised (item 7). No earlier value is kept.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersonalLabel {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// A set: order carries no meaning, and is kept as the member last gave it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// When a detail last changed. A request that changed nothing does not move it.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl PersonalLabel {
    fn has_detail(&self) -> bool {
        self.label.is_some()
            || self.description.is_some()
            || self.notes.is_some()
            || self.tags.is_some()
    }

    /// The details, compared as `rooms/keys/label/0.1` item 5 says: strings exactly, tags
    /// as a set. `updatedAt` is not a detail.
    fn same_details(&self, other: &Self) -> bool {
        fn set(t: &Option<Vec<String>>) -> Option<std::collections::BTreeSet<&str>> {
            t.as_ref().map(|v| v.iter().map(String::as_str).collect())
        }
        self.label == other.label
            && self.description == other.description
            && self.notes == other.notes
            && set(&self.tags) == set(&other.tags)
    }
}

/// What a request does to one detail of a label.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum LabelDetail<T> {
    /// Absent from the request: the stored value stays.
    #[default]
    Unchanged,
    /// Replace the stored value (`tags`: the whole set).
    Set(T),
    /// `removeX`: remove the stored value.
    Remove,
}

impl<T: Clone> LabelDetail<T> {
    fn apply(&self, current: &Option<T>) -> Option<T> {
        match self {
            LabelDetail::Unchanged => current.clone(),
            LabelDetail::Set(v) => Some(v.clone()),
            LabelDetail::Remove => None,
        }
    }
}

/// Every change one `rooms/keys/label` request names, applied together or not at all.
#[derive(Debug, Clone, Default)]
pub struct LabelChange {
    pub label: LabelDetail<String>,
    pub description: LabelDetail<String>,
    pub notes: LabelDetail<String>,
    pub tags: LabelDetail<Vec<String>>,
}

/// What [`set_label`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelOutcome {
    /// This VTA holds no group state for the room as this member — nothing was written.
    NotHeld,
    /// The label as it now stands (`None` once no detail remains), and whether this
    /// request changed it.
    Applied {
        label: Option<PersonalLabel>,
        changed: bool,
    },
}

/// How many times [`set_label`] re-reads after a concurrent write moved the row under it.
/// A person racing themselves across a few devices; past this, something is wrong.
const LABEL_WRITE_ATTEMPTS: usize = 8;

/// Apply `change` to `member`'s personal label for its room (`rooms/keys/label/0.1`).
///
/// Detail by detail (item 3): each detail given replaces the stored one, each removal
/// removes one, each absent detail is unchanged — so a rename on one device does not
/// overwrite notes written on another. Nothing is written when nothing would change
/// (item 5), and a label left with no detail is deleted (item 4).
///
/// The write is one [`Batch`](vti_common::store::Batch) conditional on the group state
/// still being held and the label row being as it was read, so a label can never be
/// written beside group state [`forget`] has just discarded, and two writes racing on
/// different details both land. A refusal re-reads and retries.
///
/// The caller has decided that it acts as `member`; this does not ask again.
pub async fn set_label(
    groups: &KeyspaceHandle,
    member: &Member,
    change: &LabelChange,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<LabelOutcome, AppError> {
    let read = |e: AppError| AppError::Internal(format!("read a personal label: {e}"));
    for _ in 0..LABEL_WRITE_ATTEMPTS {
        if groups.get_raw(member.key(GROUP)).await?.is_none() {
            return Ok(LabelOutcome::NotHeld);
        }
        let raw = groups.get_raw(member.key(LABEL)).await.map_err(read)?;
        let current: Option<PersonalLabel> = match &raw {
            Some(bytes) => Some(serde_json::from_slice(bytes).map_err(|e| {
                AppError::Internal(format!("decode the personal label for a room: {e}"))
            })?),
            None => None,
        };

        let next = PersonalLabel {
            label: change
                .label
                .apply(&current.as_ref().and_then(|c| c.label.clone())),
            description: change
                .description
                .apply(&current.as_ref().and_then(|c| c.description.clone())),
            notes: change
                .notes
                .apply(&current.as_ref().and_then(|c| c.notes.clone())),
            tags: change
                .tags
                .apply(&current.as_ref().and_then(|c| c.tags.clone())),
            updated_at: now,
        };
        let unchanged = match &current {
            Some(c) => c.same_details(&next),
            None => !next.has_detail(),
        };
        if unchanged {
            return Ok(LabelOutcome::Applied {
                label: current,
                changed: false,
            });
        }

        let mut batch = vti_common::store::Batch::new();
        batch.require_present(member.key(GROUP));
        match raw {
            Some(bytes) => batch.require_unchanged(member.key(LABEL), bytes),
            None => batch.require_absent(member.key(LABEL)),
        };
        let stored = if next.has_detail() {
            batch.insert(member.key(LABEL), &next)?;
            Some(next)
        } else {
            batch.remove(member.key(LABEL));
            None
        };
        match groups.apply_batch(batch).await? {
            vti_common::store::BatchOutcome::Applied => {
                return Ok(LabelOutcome::Applied {
                    label: stored,
                    changed: true,
                });
            }
            // The group state went while this was deciding.
            vti_common::store::BatchOutcome::Refused { check: 0 } => {
                return Ok(LabelOutcome::NotHeld);
            }
            // Another write moved the label: read it again and re-apply.
            vti_common::store::BatchOutcome::Refused { .. } => continue,
        }
    }
    Err(AppError::Conflict(
        "the personal label kept changing while this request was applying; send it again".into(),
    ))
}

/// `member`'s personal label for its room, if it has one — for `rooms/keys/list/0.2` with
/// `includePersonal`, and for nothing that completes, signs or seals for the member
/// (`rooms/keys/label/0.1` recipient item 9).
pub async fn personal_label(
    groups: &KeyspaceHandle,
    member: &Member,
) -> Result<Option<PersonalLabel>, AppError> {
    groups
        .get(member.key(LABEL))
        .await
        .map_err(|e| AppError::Internal(format!("read a personal label: {e}")))
}

/// Discard everything this VTA holds for a room.
///
/// The discard of the member's group state — the current group and every prior membership
/// a removal ended ([`PRIOR`]) — and with it the member's personal label
/// (`rooms/keys/label/0.1` recipient item 8). A commit removing the member does **not**
/// come here: [`apply_commit`] records the removal and keeps the group state, so what was
/// readable before it still is — and the label stays with it. Nor does a re-admission:
/// [`join`] moves the ended group into [`PRIOR`] and keeps reading it.
///
/// One member's, and only theirs: another persona on this VTA in the same room was not
/// removed.
pub async fn forget(groups: &KeyspaceHandle, member: &Member) -> Result<(), AppError> {
    let room_id = member.room_id();
    groups
        .remove(member.key(GROUP))
        .await
        .map_err(|e| AppError::Internal(format!("discard group state for `{room_id}`: {e}")))?;
    groups
        .remove(member.key(JOINED))
        .await
        .map_err(|e| AppError::Internal(format!("discard the join epoch for `{room_id}`: {e}")))?;
    // Key material for the epochs a removal ended is still key material for the room.
    groups.remove(member.key(PRIOR)).await.map_err(|e| {
        AppError::Internal(format!("discard the prior memberships of `{room_id}`: {e}"))
    })?;
    groups
        .remove(member.key(KEY_PACKAGE))
        .await
        .map_err(|e| AppError::Internal(format!("discard a pending key package: {e}")))?;
    // An advance this agent built for a group it no longer holds can never be
    // promoted; leaving it would hand whoever rejoins a stale successor to settle.
    discard_pending_advance(groups, member).await?;
    discard_retained_admission(groups, member).await?;
    // The personal label is kept with the group state and goes with it
    // (`rooms/keys/label/0.1` recipient item 8) — here, and nowhere else.
    groups.remove(member.key(LABEL)).await.map_err(|e| {
        AppError::Internal(format!("discard the personal label for `{room_id}`: {e}"))
    })?;
    // The root history goes with the membership. It carries no record content,
    // but it is a record of when this member read this room, and an agent that
    // kept it afterwards would be keeping a diary of a room its principal can no
    // longer open.
    groups
        .remove(member.key(ROOTS))
        .await
        .map_err(|e| AppError::Internal(format!("discard the root history of `{room_id}`: {e}")))
}

/// The MLS epoch authenticator for a room this agent holds.
///
/// Every member of the group derives this independently and **no host can
/// compute it**, which is the whole reason it is worth anchoring: a member whose
/// own authenticator differs from the anchored one is in a *forked group*.
pub async fn epoch_authenticator(
    groups: &KeyspaceHandle,
    member: &Member,
) -> Result<(u64, Vec<u8>), AppError> {
    let room_id = member.room_id();
    let record = load(groups, member).await?.ok_or_else(|| {
        AppError::Validation(format!(
            "this agent holds no group state for `{room_id}`, so it cannot say what epoch the \
             room is at"
        ))
    })?;
    let group = RoomGroup::restore(&record.snapshot)
        .map_err(|e| AppError::Internal(format!("restore the group for `{room_id}`: {e}")))?;
    // The epoch travels with it: an authenticator names the epoch it was
    // derived at, and one published beside a different number is a statement
    // about a group nobody is in.
    Ok((group.epoch(), group.epoch_authenticator()))
}

#[cfg(test)]
mod root_memory_tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    const ROOM: &str = "did:webvh:example.com:rooms:northwind";

    fn member() -> Member {
        Member::new(ROOM, "did:key:zAlice").unwrap()
    }
    const A: &str = "zQmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR";
    const B: &str = "zQmXo1sV5aJ7bT2kQdF9wRnPzYcH4uMgLtEjV6NrBqWsDpK";

    async fn open() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::ROOM_GROUPS).unwrap();
        (dir, ks)
    }

    /// A memory of one is not a comparison, and the first read must say so.
    #[tokio::test]
    async fn a_first_reading_holds_nothing_to_compare() {
        let (_d, ks) = open().await;
        assert_eq!(
            observe_head(&ks, &member(), 412, A).await.unwrap(),
            RootVerdict::NoneHeld
        );
    }

    /// The whole mechanism: same state, two roots, no write to blame.
    #[tokio::test]
    async fn two_roots_at_one_version_is_a_host_caught() {
        let (_d, ks) = open().await;
        observe_head(&ks, &member(), 412, A).await.unwrap();
        assert_eq!(
            observe_head(&ks, &member(), 412, A).await.unwrap(),
            RootVerdict::Agree
        );
        assert_eq!(
            observe_head(&ks, &member(), 412, B).await.unwrap(),
            RootVerdict::Conflict
        );
    }

    /// A room that moved is not a host that lied, and the version is what tells
    /// them apart. Without it every second read would look like equivocation.
    #[tokio::test]
    async fn a_different_version_is_a_different_moment() {
        let (_d, ks) = open().await;
        observe_head(&ks, &member(), 412, A).await.unwrap();
        assert_eq!(
            observe_head(&ks, &member(), 413, B).await.unwrap(),
            RootVerdict::NoneHeld,
            "a write moved the head, so a different root explains itself"
        );
    }

    /// One slot would miss this, which is why the memory is a map.
    ///
    /// The head advances and then a host serves the older version again — the
    /// mirror case and the rollback case. An agent keeping only the latest pair
    /// is holding `V+1` and has nothing to compare `V` against.
    #[tokio::test]
    async fn a_head_that_goes_backwards_is_still_compared() {
        let (_d, ks) = open().await;
        observe_head(&ks, &member(), 412, A).await.unwrap();
        observe_head(&ks, &member(), 500, B).await.unwrap();
        assert_eq!(
            observe_head(&ks, &member(), 412, B).await.unwrap(),
            RootVerdict::Conflict,
            "the older version is still held, and its root still disagrees"
        );
    }

    /// The bound drops the OLDEST versions and keeps the highest-ever anyway,
    /// because "has this room gone backwards" is a question no single pair can
    /// answer.
    #[tokio::test]
    async fn the_history_is_bounded_and_the_high_water_mark_survives_it() {
        let (_d, ks) = open().await;
        for v in 1..=(KEEP_ROOTS as u64 + 5) {
            observe_head(&ks, &member(), v, A).await.unwrap();
        }
        let history = root_history(&ks, &member()).await.unwrap();
        assert_eq!(history.seen.len(), KEEP_ROOTS);
        assert_eq!(history.highest, KEEP_ROOTS as u64 + 5);
        assert_eq!(
            history.seen.first().unwrap().head_version,
            6,
            "the oldest versions are what gets dropped"
        );
    }

    /// Bounded by membership. An agent that kept this after a removal would keep
    /// a record of when its principal read a room it can no longer open.
    #[tokio::test]
    async fn forgetting_a_room_forgets_what_its_host_said() {
        let (_d, ks) = open().await;
        observe_head(&ks, &member(), 412, A).await.unwrap();
        forget(&ks, &member()).await.unwrap();
        assert_eq!(
            observe_head(&ks, &member(), 412, B).await.unwrap(),
            RootVerdict::NoneHeld,
            "nothing survived the removal to compare against"
        );
    }
}

#[cfg(test)]
mod file_key_tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    const ROOM: &str = "did:webvh:example.com:rooms:northwind";

    fn member() -> Member {
        Member::new(ROOM, "did:key:zAlice").unwrap()
    }

    async fn open() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::ROOM_GROUPS).unwrap();
        (dir, ks)
    }

    /// A room this VTA holds at epoch 2, with the rung back to 1 when `chained`.
    async fn held(ks: &KeyspaceHandle, chained: bool) -> SealedRoom {
        let mut room = SealedRoom::new(ROOM, RoomGroup::create("did:key:zAlice").unwrap());
        let (_bob, kp) = IdentitySnapshot::mint("did:key:zBob").unwrap();
        room.add_member(&kp).unwrap();
        let links = if chained { room.links() } else { Vec::new() };
        store(ks, &member(), room.group(), links, 0).await.unwrap();
        room
    }

    #[tokio::test]
    async fn a_sealing_key_is_the_current_epoch_and_opens_later() {
        let (_d, ks) = open().await;
        let room = held(&ks, true).await;
        let id = [4u8; 32];

        let (seal_key, epoch) = file_key(&ks, &member(), &id, None).await.unwrap();
        assert_eq!(epoch, 2, "a sealing key is always the current epoch");
        assert_eq!(seal_key, room.file_key_for_seal(&id).unwrap().0);

        let (open_key, e) = file_key(&ks, &member(), &id, Some(2)).await.unwrap();
        assert_eq!((open_key, e), (seal_key, 2));
    }

    #[tokio::test]
    async fn an_earlier_epoch_is_reached_through_the_chain() {
        let (_d, ks) = open().await;
        held(&ks, true).await;
        let (k1, e) = file_key(&ks, &member(), &[4u8; 32], Some(1)).await.unwrap();
        assert_eq!(e, 1);
        assert_ne!(
            k1,
            file_key(&ks, &member(), &[4u8; 32], Some(2))
                .await
                .unwrap()
                .0
        );
    }

    #[tokio::test]
    async fn the_two_unreachable_cases_say_which_they_are() {
        let (_d, ks) = open().await;
        held(&ks, false).await;
        assert!(matches!(
            file_key(&ks, &member(), &[4u8; 32], Some(3)).await,
            Err(FileKeyError::NotDelivered { epoch: 3, held: 2 })
        ));
        assert!(matches!(
            file_key(&ks, &member(), &[4u8; 32], Some(1)).await,
            Err(FileKeyError::BeyondChain {
                epoch: 1,
                earliest: 2
            })
        ));
    }

    #[tokio::test]
    async fn no_group_is_not_found() {
        let (_d, ks) = open().await;
        assert!(matches!(
            file_key(&ks, &member(), &[4u8; 32], None).await,
            Err(FileKeyError::NoGroup)
        ));
    }
}

#[cfg(test)]
mod per_member_storage_tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    const ROOM: &str = "did:webvh:example.com:rooms:northwind";
    const ALICE: &str = "did:key:zAlice";
    const BOB: &str = "did:key:zBob";

    async fn open() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::ROOM_GROUPS).unwrap();
        (dir, ks)
    }

    fn m(persona: &str) -> Member {
        Member::new(ROOM, persona).unwrap()
    }

    /// A key that two different (room, persona) pairs could both produce would put one
    /// member's secrets under another's name.
    #[test]
    fn identifiers_that_would_make_the_key_ambiguous_are_refused() {
        assert!(Member::new("did:key:zA/b", ALICE).is_err());
        assert!(Member::new(ROOM, "did:key:zA/b").is_err());
        assert!(Member::new("", ALICE).is_err());
    }

    /// Two members of one room on one VTA are two rows, found by room.
    #[tokio::test]
    async fn two_members_of_one_room_are_two_groups() {
        let (_d, ks) = open().await;
        for who in [ALICE, BOB] {
            create_group(&ks, &m(who), 0).await.unwrap();
        }
        let mut held: Vec<String> = holders(&ks, ROOM)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.persona().to_string())
            .collect();
        held.sort();
        assert_eq!(held, vec![ALICE.to_string(), BOB.to_string()]);
        assert!(matches!(
            create_group(&ks, &m(ALICE), 0).await,
            Err(CreateGroupError::AlreadyExists { .. })
        ));
    }

    /// A host caught by one member's reading is that member's finding. The other member's
    /// memory is its own — a record of when somebody else read the room is not theirs.
    #[tokio::test]
    async fn root_memory_is_the_members_own() {
        let (_d, ks) = open().await;
        observe_head(&ks, &m(ALICE), 412, "zA").await.unwrap();
        assert_eq!(
            observe_head(&ks, &m(ALICE), 412, "zB").await.unwrap(),
            RootVerdict::Conflict
        );
        assert_eq!(
            observe_head(&ks, &m(BOB), 412, "zB").await.unwrap(),
            RootVerdict::NoneHeld,
            "bob holds no memory of alice's reading"
        );
        assert!(
            root_history(&ks, &m(BOB))
                .await
                .unwrap()
                .caught_at
                .is_none()
        );
    }

    /// Everything the per-room build kept moves with the group, under the member its leaf
    /// identifies; a package minted for somebody else stays put; and a second run is a
    /// no-op rather than a second move.
    #[tokio::test]
    async fn a_legacy_room_moves_whole_under_its_member() {
        let (_d, ks) = open().await;
        let group = RoomGroup::create(ALICE).unwrap();
        let record = RoomGroupRecord {
            snapshot: group.snapshot().unwrap(),
            member_did: ALICE.into(),
            links: Vec::new(),
            updated_at: 7,
        };
        ks.insert(legacy::group(ROOM), &record).await.unwrap();
        let (snapshot, kp) = IdentitySnapshot::mint(BOB).unwrap();
        let bobs_package = PendingKeyPackage {
            snapshot,
            key_package: B64.encode(kp),
            expires_at: 9,
            invitation_id: None,
        };
        ks.insert(legacy::key_package(ROOM), &bobs_package)
            .await
            .unwrap();
        ks.insert(
            legacy::roots(ROOM),
            &RootHistory {
                caught_at: Some(3),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            migrate_legacy(&ks, &m(ALICE)).await.unwrap(),
            Migrated::Moved
        );
        assert_eq!(load(&ks, &m(ALICE)).await.unwrap().unwrap().updated_at, 7);
        assert_eq!(
            root_history(&ks, &m(ALICE)).await.unwrap().caught_at,
            Some(3),
            "a host caught before the upgrade stays caught"
        );
        assert!(ks.get_raw(legacy::group(ROOM)).await.unwrap().is_none());
        assert!(ks.get_raw(legacy::roots(ROOM)).await.unwrap().is_none());
        assert!(
            ks.get_raw(legacy::key_package(ROOM))
                .await
                .unwrap()
                .is_some(),
            "bob's package is not alice's to take"
        );
        assert!(
            ks.get_raw(m(ALICE).key(KEY_PACKAGE))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            migrate_legacy(&ks, &m(ALICE)).await.unwrap(),
            Migrated::Nothing
        );

        // Bob's package moves when bob's Welcome looks for it.
        assert_eq!(
            legacy_key_package(&ks, &m(BOB))
                .await
                .unwrap()
                .map(|p| p.expires_at),
            Some(9)
        );
        assert!(
            ks.get_raw(legacy::key_package(ROOM))
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A member who already holds a group of their own is not given a second one: the
    /// legacy row stays where it is, unmerged.
    #[tokio::test]
    async fn a_legacy_row_never_overwrites_a_members_own_group() {
        let (_d, ks) = open().await;
        create_group(&ks, &m(ALICE), 42).await.unwrap();
        let record = RoomGroupRecord {
            snapshot: RoomGroup::create(ALICE).unwrap().snapshot().unwrap(),
            member_did: ALICE.into(),
            links: Vec::new(),
            updated_at: 7,
        };
        ks.insert(legacy::group(ROOM), &record).await.unwrap();
        assert_eq!(
            migrate_legacy(&ks, &m(ALICE)).await.unwrap(),
            Migrated::Kept
        );
        assert_eq!(load(&ks, &m(ALICE)).await.unwrap().unwrap().updated_at, 42);
        assert!(ks.get_raw(legacy::group(ROOM)).await.unwrap().is_some());
    }
}

#[cfg(test)]
mod removal_tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    const ROOM: &str = "did:webvh:example.com:rooms:northwind";
    const BOB: &str = "did:key:zBob";

    /// rooms `_shared/0.1` `SealedRecord.version`: a curation moves a record past the
    /// version its body was sealed at, and the body stays bound to that version. Opened at
    /// the record's own version it fails for everyone (the defect); opened at the sealed-at
    /// version it opens; and a record curated by a host that predates `sealed.version` is
    /// found by searching earlier versions — never later ones.
    #[tokio::test]
    async fn a_curated_record_opens_at_the_version_its_body_was_sealed_at() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::ROOM_GROUPS).unwrap();
        let bob = Member::new(ROOM, BOB).unwrap();
        let pending = mint_key_package(&ks, &bob, 3600, 0).await.unwrap();
        let mut alice = SealedRoom::new(ROOM, RoomGroup::create("did:key:zAlice").unwrap());
        let (added, _) = alice
            .add_member(&B64.decode(&pending.key_package).unwrap())
            .unwrap();
        join(&ks, &bob, &added.welcome.unwrap(), 0).await.unwrap();

        // Written at version 3; curated since, so the record is now at 7.
        let s = alice.seal_record("k", 3, b"archived").unwrap();
        let open = |version, search| {
            open_record_at(
                &ks,
                &bob,
                "k",
                version,
                &s.ciphertext,
                &s.nonce,
                s.epoch,
                search,
            )
        };

        assert!(
            open(7, Search::Exact).await.is_err(),
            "at the version a curation moved it to, the body does not open"
        );
        assert_eq!(
            open(3, Search::Exact).await.unwrap(),
            (b"archived".to_vec(), 3),
            "at `sealed.version` it does"
        );
        assert_eq!(
            open(7, Search::Earlier).await.unwrap(),
            (b"archived".to_vec(), 3),
            "with no `sealed.version`, earlier versions are searched and the one that opened is named"
        );
        assert!(
            open(2, Search::Earlier).await.is_err(),
            "never a version later than the one given"
        );
    }

    /// After the commit that removes this VTA's member is applied, a record sealed after
    /// the removal says "removed" — not "a commit has not been delivered", whose remedy
    /// (apply the commits) can never open it — and what was sealed before still opens.
    #[tokio::test]
    async fn a_record_sealed_after_the_members_removal_says_removed() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::ROOM_GROUPS).unwrap();
        let bob = Member::new(ROOM, BOB).unwrap();

        let pending = mint_key_package(&ks, &bob, 3600, 0).await.unwrap();
        let mut alice = SealedRoom::new(ROOM, RoomGroup::create("did:key:zAlice").unwrap());
        let (added, _) = alice
            .add_member(&B64.decode(&pending.key_package).unwrap())
            .unwrap();
        join(&ks, &bob, &added.welcome.unwrap(), 0).await.unwrap();

        let before = alice.seal_record("k", 1, b"before").unwrap();
        let leaf = alice.group().leaf_of(BOB).unwrap();
        let (removal, _) = alice.remove_member(leaf).unwrap();
        let after = alice.seal_record("k", 2, b"after").unwrap();

        // Before the removal is applied, this VTA cannot know: it is only behind.
        assert!(matches!(
            open_record_detailed(
                &ks,
                &bob,
                "k",
                2,
                &after.ciphertext,
                &after.nonce,
                after.epoch
            )
            .await,
            Err(OpenError::NotDelivered { .. })
        ));
        let file = [7u8; 32];
        assert!(matches!(
            file_key(&ks, &bob, &file, Some(after.epoch)).await.err(),
            Some(FileKeyError::NotDelivered { .. })
        ));

        let err = apply_commit(&ks, &bob, &removal.commit, removal.epoch, 5)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("removed this holder"), "{err}");
        assert_eq!(removed_at(&ks, &bob).await.unwrap(), Some(after.epoch));

        match open_record_detailed(
            &ks,
            &bob,
            "k",
            2,
            &after.ciphertext,
            &after.nonce,
            after.epoch,
        )
        .await
        {
            Err(OpenError::Removed { epoch, removed_at }) => {
                assert_eq!((epoch, removed_at), (after.epoch, after.epoch))
            }
            other => panic!("expected Removed, got {other:?}"),
        }
        // A file's key is the same question (`rooms/keys/file-key`): sealed at or after
        // the removal is `Removed`, never `NotDelivered`, whose remedy cannot work.
        match file_key(&ks, &bob, &file, Some(after.epoch)).await.err() {
            Some(FileKeyError::Removed { epoch, removed_at }) => {
                assert_eq!((epoch, removed_at), (after.epoch, after.epoch))
            }
            other => panic!("expected FileKeyError::Removed, got {other:?}"),
        }
        assert!(
            file_key(&ks, &bob, &file, Some(before.epoch)).await.is_ok(),
            "a file sealed before the removal still derives"
        );
        assert_eq!(
            open_record(
                &ks,
                &bob,
                "k",
                1,
                &before.ciphertext,
                &before.nonce,
                before.epoch
            )
            .await
            .unwrap(),
            b"before"
        );
    }
}

#[cfg(test)]
mod readmission_tests {
    //! `rooms/keys/welcome/0.1` and `rooms/keys/open/0.2`: group state with a removal
    //! recorded is a prior membership, not a join. A member removed and admitted again
    //! accepts the new Welcome; what each membership opened still opens, an epoch between a
    //! removal and the next join is `removed`, and sealing is the current group's.
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    const ROOM: &str = "did:webvh:example.com:rooms:northwind";
    const BOB: &str = "did:key:zBob";

    struct Room {
        _dir: tempfile::TempDir,
        ks: KeyspaceHandle,
        bob: Member,
        alice: SealedRoom,
    }

    impl Room {
        async fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = Store::open(&StoreConfig {
                data_dir: dir.path().to_path_buf(),
            })
            .unwrap();
            let ks = store.keyspace(crate::keyspaces::ROOM_GROUPS).unwrap();
            Self {
                _dir: dir,
                ks,
                bob: Member::new(ROOM, BOB).unwrap(),
                alice: SealedRoom::new(ROOM, RoomGroup::create("did:key:zAlice").unwrap()),
            }
        }

        /// The owner admits Bob with a fresh KeyPackage; Bob's VTA takes the Welcome.
        async fn admit(&mut self) -> Result<u64, JoinError> {
            let pending = mint_key_package(&self.ks, &self.bob, 3600, 0)
                .await
                .unwrap();
            let (added, _) = self
                .alice
                .add_member(&B64.decode(&pending.key_package).unwrap())
                .unwrap();
            join(&self.ks, &self.bob, &added.welcome.unwrap(), 1).await
        }

        /// The owner removes Bob, and Bob's VTA processes the commit that removed it.
        async fn remove(&mut self) -> u32 {
            let leaf = self.alice.group().leaf_of(BOB).unwrap();
            let (removal, _) = self.alice.remove_member(leaf).unwrap();
            let err = apply_commit(&self.ks, &self.bob, &removal.commit, removal.epoch, 2)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("removed this holder"), "{err}");
            removed_at(&self.ks, &self.bob).await.unwrap().unwrap()
        }

        fn seal(&self, key: &str, body: &[u8]) -> vti_rooms::wire::SealedContent {
            self.alice.seal_record(key, 1, body).unwrap()
        }

        async fn open(
            &self,
            key: &str,
            s: &vti_rooms::wire::SealedContent,
        ) -> Result<Vec<u8>, OpenError> {
            open_record_detailed(
                &self.ks,
                &self.bob,
                key,
                1,
                &s.ciphertext,
                &s.nonce,
                s.epoch,
            )
            .await
        }
    }

    #[tokio::test]
    async fn a_member_removed_and_admitted_again_reads_both_memberships_and_not_the_gap() {
        let mut r = Room::new().await;
        let founding = r.seal("notes/founding", b"founding");
        assert_eq!(founding.epoch, 1);
        r.admit().await.unwrap();
        let before = r.seal("notes/before", b"before");
        assert_eq!(before.epoch, 2);

        let first_removal = r.remove().await;
        assert_eq!(first_removal, 3);
        let during = r.seal("notes/during", b"during");
        assert_eq!(during.epoch, 3);

        // Removed and not yet admitted again: no current epoch, so nothing is sealed under
        // the state the removal left — `noGroup` — while what it opened still opens.
        assert!(matches!(
            seal_record(&r.ks, &r.bob, "notes/x", 1, b"x").await,
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            file_key(&r.ks, &r.bob, &[9u8; 32], None).await,
            Err(FileKeyError::NoGroup)
        ));
        assert!(profile_location(&r.ks, &r.bob, None).await.is_err());
        assert!(!holds_current(&r.ks, &r.bob).await.unwrap());
        assert_eq!(r.open("notes/before", &before).await.unwrap(), b"before");

        // The re-admission: a fresh KeyPackage and a new Welcome, accepted.
        let joined = r
            .admit()
            .await
            .expect("a Welcome after a removal is a re-admission, not alreadyJoined");
        assert_eq!(joined + 1, 4, "the current group is the new one");
        assert_eq!(
            removed_at(&r.ks, &r.bob).await.unwrap(),
            None,
            "the removal row is cleared on join"
        );
        assert!(holds_current(&r.ks, &r.bob).await.unwrap());
        let after = r.seal("notes/after", b"after");
        assert_eq!(after.epoch, 4);

        assert_eq!(r.open("notes/before", &before).await.unwrap(), b"before");
        match r.open("notes/during", &during).await {
            Err(OpenError::Removed { epoch, removed_at }) => {
                assert_eq!((epoch, removed_at), (3, 3))
            }
            other => panic!("expected Removed, got {other:?}"),
        }
        assert_eq!(r.open("notes/after", &after).await.unwrap(), b"after");

        // A file key is the same question.
        let file = [9u8; 32];
        assert!(file_key(&r.ks, &r.bob, &file, Some(2)).await.is_ok());
        assert!(matches!(
            file_key(&r.ks, &r.bob, &file, Some(3)).await,
            Err(FileKeyError::Removed {
                epoch: 3,
                removed_at: 3
            })
        ));
        let (sealing, at) = file_key(&r.ks, &r.bob, &file, None).await.unwrap();
        assert_eq!(at, 4, "sealing is always the current group's");
        assert_eq!(sealing, r.alice.file_key_for_seal(&file).unwrap().0);

        // Sealing as Bob uses the current group, which the owner opens.
        let from_bob = seal_record(&r.ks, &r.bob, "notes/bob", 1, b"from bob")
            .await
            .unwrap();
        assert_eq!(from_bob.epoch, 4);
        assert_eq!(
            r.alice.open_record("notes/bob", 1, &from_bob).unwrap(),
            b"from bob"
        );

        // A backfill that reaches the current group's chain below its join epoch changes
        // neither rule: the gap is still `removed`, and an epoch below the first join is
        // `beyondChain` (`rooms/keys/open/0.2`).
        store_links(&r.ks, &r.bob, r.alice.links(), 3)
            .await
            .unwrap();
        assert!(matches!(
            r.open("notes/during", &during).await,
            Err(OpenError::Removed {
                epoch: 3,
                removed_at: 3
            })
        ));
        match r.open("notes/founding", &founding).await {
            Err(OpenError::BeyondChain { epoch, earliest }) => {
                assert_eq!((epoch, earliest), (1, 2))
            }
            other => panic!("expected BeyondChain, got {other:?}"),
        }
        assert_eq!(r.open("notes/before", &before).await.unwrap(), b"before");

        // A second Welcome while the membership is current is still alreadyJoined.
        assert!(matches!(r.admit().await, Err(JoinError::AlreadyJoined)));
    }

    #[tokio::test]
    async fn prior_memberships_pile_up_and_each_answers_for_its_own_range() {
        let mut r = Room::new().await;
        r.admit().await.unwrap(); // 2
        let e2 = r.seal("k2", b"two");
        assert_eq!(r.remove().await, 3);
        let e3 = r.seal("k3", b"three");
        r.admit().await.unwrap(); // 4
        let e4 = r.seal("k4", b"four");
        assert_eq!(r.remove().await, 5);
        let e5 = r.seal("k5", b"five");
        r.admit().await.unwrap(); // 6
        let e6 = r.seal("k6", b"six");

        let prior = prior_memberships(&r.ks, &r.bob).await.unwrap();
        assert_eq!(
            prior.iter().map(|p| p.removed_epoch).collect::<Vec<_>>(),
            [Some(3), Some(5)]
        );
        let opens: [(&str, &vti_rooms::wire::SealedContent, &[u8]); 3] = [
            ("k2", &e2, b"two"),
            ("k4", &e4, b"four"),
            ("k6", &e6, b"six"),
        ];
        for (k, s, body) in opens {
            assert_eq!(r.open(k, s).await.unwrap(), body, "{k}");
        }
        for (k, s, removal) in [("k3", &e3, 3), ("k5", &e5, 5)] {
            match r.open(k, s).await {
                Err(OpenError::Removed { epoch, removed_at }) => {
                    assert_eq!((epoch, removed_at), (s.epoch, removal))
                }
                other => panic!("{k}: expected Removed, got {other:?}"),
            }
        }

        // The profile walk covers each membership's range and none of the gaps.
        let walked: Vec<u32> = profile_locations(&r.ks, &r.bob, usize::MAX)
            .await
            .unwrap()
            .into_iter()
            .map(|(e, _)| e)
            .collect();
        assert_eq!(walked, [6, 4, 2]);
        assert_eq!(
            profile_location(&r.ks, &r.bob, Some(4)).await.unwrap(),
            (r.alice.profile_key_for_open(4).unwrap(), 4)
        );

        // An epoch floor of 4 leaves the first membership (epochs below 3) nothing to
        // open: it goes whole, and the second stays.
        apply_epoch_floor(&r.ks, &r.bob, 4, 3).await.unwrap();
        let prior = prior_memberships(&r.ks, &r.bob).await.unwrap();
        assert_eq!(
            prior.iter().map(|p| p.removed_epoch).collect::<Vec<_>>(),
            [Some(5)]
        );
        assert!(matches!(
            r.open("k2", &e2).await,
            Err(OpenError::BeyondChain { epoch: 2, .. })
        ));
        assert_eq!(r.open("k4", &e4).await.unwrap(), b"four");

        // `forget` discards the prior memberships with the current group.
        forget(&r.ks, &r.bob).await.unwrap();
        assert!(prior_memberships(&r.ks, &r.bob).await.unwrap().is_empty());
        assert!(load(&r.ks, &r.bob).await.unwrap().is_none());
    }

    impl Room {
        /// The owner admits Bob with a fresh KeyPackage, without Bob's VTA taking the
        /// Welcome: the Welcome, and the KeyPackage it is sealed to.
        async fn welcome_for_fresh_key_package(&mut self) -> (Vec<u8>, Vec<u8>) {
            let pending = mint_key_package(&self.ks, &self.bob, 3600, 0)
                .await
                .unwrap();
            let kp = B64.decode(&pending.key_package).unwrap();
            let (added, _) = self.alice.add_member(&kp).unwrap();
            (added.welcome.unwrap(), kp)
        }
    }

    /// `rooms/keys/welcome/0.1`, *Rejoining after a removal*, the second piece of evidence:
    /// a member idle when it was removed never applies the removing commit (and cannot fetch
    /// it — the host serves commits under the grant the removal withdrew), so its VTA comes
    /// to the re-admission holding state at h with no removal recorded. The Welcome's tree
    /// no longer holds that state's leaf, so the Welcome is accepted, and the state is a
    /// prior membership whose removal epoch is not yet known. Records at or below h open;
    /// one in (h, j) is `notDelivered` with the prior's held epoch until commits are applied
    /// to that state, and then opens below r and is `removed` in [r, j); records after the
    /// re-admission open under the current group (`rooms/keys/open/0.2`,
    /// `rooms/keys/file-key/0.2`). The host round trip is driven at the operations level:
    /// the commits are the owner's own, handed to [`apply_prior_commit`] as
    /// `room_catch_up` hands it what `rooms/epoch/commits` serves.
    #[tokio::test]
    async fn a_member_that_never_applied_its_removal_is_admitted_again_by_the_welcome() {
        let mut r = Room::new().await;
        r.admit().await.unwrap(); // room epoch 2: Bob's VTA holds h = 2 from here on
        let before = r.seal("notes/before", b"before");
        assert_eq!(before.epoch, 2);

        // The room moves on; Bob's VTA applies none of it.
        let (renewal, _) = r.alice.renew().unwrap(); // 3
        let between = r.seal("notes/between", b"between");
        assert_eq!(between.epoch, 3);
        let leaf = r.alice.group().leaf_of(BOB).unwrap();
        let (removal, _) = r.alice.remove_member(leaf).unwrap(); // 4 = r
        let during = r.seal("notes/during", b"during");
        assert_eq!(during.epoch, 4);
        assert_eq!(removed_at(&r.ks, &r.bob).await.unwrap(), None);
        assert!(holds_current(&r.ks, &r.bob).await.unwrap());

        // Re-admitted at j = 5: the Welcome is the evidence, and nothing is fetched first.
        let (welcome, _) = r.welcome_for_fresh_key_package().await;
        let joined = join(&r.ks, &r.bob, &welcome, 1)
            .await
            .expect("a Welcome whose tree lacks the held leaf is a re-admission");
        assert_eq!(joined + 1, 5);
        let after = r.seal("notes/after", b"after");
        assert_eq!(after.epoch, 5);
        let prior = prior_memberships(&r.ks, &r.bob).await.unwrap();
        assert_eq!(prior.len(), 1);
        assert_eq!(
            prior[0].removed_epoch, None,
            "the removal epoch is not yet known"
        );
        assert_eq!(prior[0].joined_epoch, Some(2));
        let signature_key = prior[0].signature_key().unwrap();

        // At or below h: opens. After the re-admission: opens, and sealing is current.
        assert_eq!(r.open("notes/before", &before).await.unwrap(), b"before");
        assert_eq!(r.open("notes/after", &after).await.unwrap(), b"after");
        let file = [7u8; 32];
        assert_eq!(file_key(&r.ks, &r.bob, &file, None).await.unwrap().1, 5);

        // In (h, j) before any repair: `notDelivered`, with the prior's held epoch — never
        // `removed`, whichever side of the unseen removal the record is on.
        for s in [&between, &during] {
            match r.open("k", s).await {
                Err(OpenError::NotDelivered { epoch, held }) => {
                    assert_eq!((epoch, held), (s.epoch, 2))
                }
                other => panic!("epoch {}: expected NotDelivered, got {other:?}", s.epoch),
            }
            assert!(matches!(
                file_key(&r.ks, &r.bob, &file, Some(s.epoch)).await,
                Err(FileKeyError::NotDelivered { held: 2, .. })
            ));
        }
        // And a repair is pointed at that prior membership, by the record's epoch.
        let state = repair_state(&r.ks, &r.bob, 3).await.unwrap().unwrap();
        assert_eq!(
            state.target,
            RepairTarget::Prior {
                signature_key: signature_key.clone()
            }
        );
        assert_eq!(state.epoch, 2);
        assert_eq!(
            repair_state(&r.ks, &r.bob, 5)
                .await
                .unwrap()
                .unwrap()
                .target,
            RepairTarget::Current
        );

        // The repair applies the commits to the prior state. A gap is refused, a replay is
        // a no-op, and the renewal opens the record between h and r.
        assert!(matches!(
            apply_prior_commit(&r.ks, &r.bob, &signature_key, &removal.commit, 3, 2).await,
            Err(AppError::Conflict(_))
        ));
        assert_eq!(
            apply_prior_commit(&r.ks, &r.bob, &signature_key, &renewal.commit, 2, 2)
                .await
                .unwrap(),
            PriorCommit::Applied(2)
        );
        assert_eq!(
            apply_prior_commit(&r.ks, &r.bob, &signature_key, &renewal.commit, 2, 2)
                .await
                .unwrap(),
            PriorCommit::Applied(2)
        );
        assert_eq!(r.open("notes/between", &between).await.unwrap(), b"between");
        assert!(file_key(&r.ks, &r.bob, &file, Some(3)).await.is_ok());
        match r.open("notes/during", &during).await {
            Err(OpenError::NotDelivered { epoch, held }) => assert_eq!((epoch, held), (4, 3)),
            other => panic!("expected NotDelivered before the removal applies, got {other:?}"),
        }

        // The removing commit fixes r; [r, j) is `removed` from then on.
        assert_eq!(
            apply_prior_commit(&r.ks, &r.bob, &signature_key, &removal.commit, 3, 3)
                .await
                .unwrap(),
            PriorCommit::Removed { epoch: 4 }
        );
        let prior = prior_memberships(&r.ks, &r.bob).await.unwrap();
        assert_eq!(prior[0].removed_epoch, Some(4));
        assert_eq!(prior[0].removed_at, Some(3));
        match r.open("notes/during", &during).await {
            Err(OpenError::Removed { epoch, removed_at }) => {
                assert_eq!((epoch, removed_at), (4, 4))
            }
            other => panic!("expected Removed, got {other:?}"),
        }
        assert!(matches!(
            file_key(&r.ks, &r.bob, &file, Some(4)).await,
            Err(FileKeyError::Removed {
                epoch: 4,
                removed_at: 4
            })
        ));
        assert!(repair_state(&r.ks, &r.bob, 4).await.unwrap().is_none());
        assert_eq!(
            apply_prior_commit(&r.ks, &r.bob, &signature_key, &removal.commit, 4, 3)
                .await
                .unwrap(),
            PriorCommit::Removed { epoch: 4 },
            "nothing applies to a membership once its removal is known"
        );

        // Everything else still answers as before.
        assert_eq!(r.open("notes/before", &before).await.unwrap(), b"before");
        assert_eq!(r.open("notes/between", &between).await.unwrap(), b"between");
        assert_eq!(r.open("notes/after", &after).await.unwrap(), b"after");
        let walked: Vec<u32> = profile_locations(&r.ks, &r.bob, usize::MAX)
            .await
            .unwrap()
            .into_iter()
            .map(|(e, _)| e)
            .collect();
        assert_eq!(walked, [5, 3, 2]);
    }

    /// `rooms/keys/welcome/0.1`, *Rejoining after a removal*: an absent leaf is evidence
    /// only in the same MLS group. A Welcome for another group — which has none of the held
    /// state's leaves by construction — is `welcomeInvalid`, and retires nothing: the held
    /// group, its join epoch and the KeyPackage stay exactly as they were.
    #[tokio::test]
    async fn a_welcome_for_another_group_retires_nothing() {
        let mut r = Room::new().await;
        r.admit().await.unwrap(); // 2
        let held = load(&r.ks, &r.bob).await.unwrap().unwrap();

        // Another group entirely adds Bob under a fresh KeyPackage.
        let pending = mint_key_package(&r.ks, &r.bob, 3600, 0).await.unwrap();
        let kp = B64.decode(&pending.key_package).unwrap();
        let mut other = SealedRoom::new(ROOM, RoomGroup::create("did:key:zMallory").unwrap());
        other.renew().unwrap();
        other.renew().unwrap(); // its epoch is above Bob's, so only the group id tells
        let (added, _) = other.add_member(&kp).unwrap();
        assert_ne!(other.group().group_id(), held.snapshot.group_id().unwrap());

        assert!(matches!(
            join(&r.ks, &r.bob, &added.welcome.unwrap(), 1).await,
            Err(JoinError::WelcomeForAnotherGroup)
        ));
        assert!(
            holds_key_package(&r.ks, &r.bob, &kp, 1).await.unwrap(),
            "the KeyPackage is not consumed"
        );
        let still = load(&r.ks, &r.bob).await.unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(&still.snapshot).unwrap(),
            serde_json::to_value(&held.snapshot).unwrap(),
            "the held group is untouched"
        );
        assert!(prior_memberships(&r.ks, &r.bob).await.unwrap().is_empty());
        assert_eq!(joined_epoch(&r.ks, &r.bob).await.unwrap(), Some(2));
        assert_eq!(removed_at(&r.ks, &r.bob).await.unwrap(), None);
        assert!(holds_current(&r.ks, &r.bob).await.unwrap());
    }

    /// `rooms/keys/welcome/0.1`: a Welcome whose ratchet tree still holds the leaf of the
    /// state this VTA has is a second join — `alreadyJoined` — and the refused join keeps
    /// nothing it formed and does not consume the KeyPackage it was sealed to.
    #[tokio::test]
    async fn a_welcome_that_still_holds_the_members_leaf_is_already_joined_and_consumes_nothing() {
        let mut r = Room::new().await;
        r.admit().await.unwrap(); // 2
        let held = load(&r.ks, &r.bob).await.unwrap().unwrap();

        // The owner adds a second leaf for Bob while the first is still in the group.
        let (welcome, kp) = r.welcome_for_fresh_key_package().await; // 3
        assert!(
            r.alice
                .group()
                .has_leaf_with_signature_key(&held.snapshot.signature_public_key().unwrap()),
            "the held leaf is still in the tree"
        );
        assert!(matches!(
            join(&r.ks, &r.bob, &welcome, 1).await,
            Err(JoinError::AlreadyJoined)
        ));
        assert!(
            holds_key_package(&r.ks, &r.bob, &kp, 1).await.unwrap(),
            "a refused join does not consume the KeyPackage"
        );
        let still = load(&r.ks, &r.bob).await.unwrap().unwrap();
        assert_eq!(
            still.snapshot.signature_public_key().unwrap(),
            held.snapshot.signature_public_key().unwrap(),
            "the held group is untouched"
        );
        assert!(prior_memberships(&r.ks, &r.bob).await.unwrap().is_empty());
        assert_eq!(joined_epoch(&r.ks, &r.bob).await.unwrap(), Some(2));
    }
}

#[cfg(test)]
mod epoch_floor_tests {
    //! `rooms/_shared/0.1` `EpochFloor` at a member's key holder (trust-tasks-tf #869): on
    //! learning a floor it discards every rung at or below it, refuses to derive below it,
    //! never stores such a rung again, and keeps the floor — which only rises.
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    const ROOM: &str = "did:webvh:example.com:rooms:northwind";

    fn member() -> Member {
        Member::new(ROOM, "did:key:zAlice").unwrap()
    }

    /// A room this VTA holds at epoch 4, with every rung back to 1.
    async fn held() -> (tempfile::TempDir, KeyspaceHandle, Vec<EpochLink>) {
        let dir = tempfile::tempdir().unwrap();
        let store_ = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store_.keyspace(crate::keyspaces::ROOM_GROUPS).unwrap();
        let mut room = SealedRoom::new(ROOM, RoomGroup::create("did:key:zAlice").unwrap());
        for joiner in ["did:key:zBob", "did:key:zCarol", "did:key:zDave"] {
            let (_s, kp) = IdentitySnapshot::mint(joiner).unwrap();
            room.add_member(&kp).unwrap();
        }
        assert_eq!(room.room_epoch(), 4);
        let links = room.links();
        store(&ks, &member(), room.group(), links.clone(), 0)
            .await
            .unwrap();
        (dir, ks, links)
    }

    #[tokio::test]
    async fn a_learnt_floor_forgets_below_itself_and_keeps_out_what_comes_back() {
        let (_d, ks, links) = held().await;
        let id = [7u8; 32];
        assert!(
            file_key(&ks, &member(), &id, Some(1)).await.is_ok(),
            "before the floor"
        );
        assert_eq!(
            held_room(&ks, &member())
                .await
                .unwrap()
                .earliest_readable_epoch,
            1
        );

        // A prune with `beforeEpoch: 4` → floor 3.
        assert_eq!(apply_epoch_floor(&ks, &member(), 3, 1).await.unwrap(), 3);
        let rungs: Vec<u32> = load(&ks, &member())
            .await
            .unwrap()
            .unwrap()
            .links
            .iter()
            .map(|l| l.epoch)
            .collect();
        assert_eq!(rungs, [4], "rungs numbered 3 and below are discarded");
        for below in [1, 2] {
            assert!(
                matches!(
                    file_key(&ks, &member(), &id, Some(below)).await,
                    Err(FileKeyError::BeyondChain { earliest, .. }) if earliest >= 3
                ),
                "epoch {below} is below the floor"
            );
        }
        assert!(
            file_key(&ks, &member(), &id, Some(3)).await.is_ok(),
            "the floor reads"
        );
        assert_eq!(
            held_room(&ks, &member())
                .await
                .unwrap()
                .earliest_readable_epoch,
            3
        );

        // A mirror that was not pruned serves the rungs back: none is kept or counted.
        let (earliest, stored) = store_links(&ks, &member(), links, 2).await.unwrap();
        assert_eq!((earliest, stored), (3, 0));

        // Monotonic, and kept.
        assert_eq!(apply_epoch_floor(&ks, &member(), 2, 3).await.unwrap(), 3);
        assert_eq!(epoch_floor(&ks, &member()).await.unwrap(), 3);
    }
}
