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
    };
    groups
        .insert(member.key(KEY_PACKAGE), &pending)
        .await
        .map_err(|e| AppError::Internal(format!("store the pending key package: {e}")))?;
    Ok(pending)
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
pub enum JoinError {
    /// This member already holds group state for the room — `alreadyJoined`.
    AlreadyJoined,
    App(AppError),
}

impl From<AppError> for JoinError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

/// Join `member`'s room's group from a Welcome.
///
/// Refuses a second join **by the same member** rather than merging: two group states for
/// one member in one room is a condition nothing downstream can resolve — [`open_record`]
/// has no way to choose, and choosing wrong returns "did not open" for a record the member
/// can plainly see. Another persona on this VTA holding the room is a different member with
/// a different leaf, and is no reason to refuse this one.
pub async fn join(
    groups: &KeyspaceHandle,
    member: &Member,
    welcome: &[u8],
    now: u64,
) -> Result<u64, JoinError> {
    let room_id = member.room_id();
    if load(groups, member).await?.is_some() {
        return Err(JoinError::AlreadyJoined);
    }

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
    let pending = pending.ok_or_else(|| {
        AppError::Validation(format!(
            "no key package was minted for room `{room_id}`; a welcome can only be accepted \
             against the package the owner was given"
        ))
    })?;

    let group = RoomGroup::join_from_identity(&pending.snapshot, welcome)
        .map_err(|e| AppError::Validation(format!("the welcome did not process: {e}")))?;
    let epoch = group.epoch();

    store(groups, member, &group, Vec::new(), now).await?;
    // The package is consumed. MLS consumes it on add, and a retained private half for a
    // used package is key material kept for nothing.
    groups
        .remove(member.key(KEY_PACKAGE))
        .await
        .map_err(|e| AppError::Internal(format!("clear the pending key package: {e}")))?;
    Ok(epoch)
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
    let (_, link) = room
        .apply_commit(commit)
        .map_err(|e| AppError::Validation(format!("the commit did not process: {e}")))?;
    let epoch = room.group().epoch();

    let mut links = record.links;
    if let Some(link) = link {
        links.push(link);
    }
    store(groups, member, room.group(), links, now).await?;
    Ok(epoch)
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
    let record = load(groups, member)
        .await?
        .ok_or_else(|| no_group(member))?;
    let group = RoomGroup::restore(&record.snapshot)
        .map_err(|e| AppError::Internal(format!("restore the group: {e}")))?;

    SealedRoom::new(room_id, group)
        .seal_record(key, version, plaintext)
        .map_err(|e| AppError::Validation(e.to_string()))
}

/// Why a file key could not be derived.
#[derive(Debug)]
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
}

/// One file's key — `rooms/keys/file-key/0.1`.
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
    let record = load(groups, member)
        .await
        .map_err(FileKeyError::App)?
        .ok_or(FileKeyError::NoGroup)?;
    let group = RoomGroup::restore(&record.snapshot)
        .map_err(|e| FileKeyError::App(AppError::Internal(format!("restore the group: {e}"))))?;
    let mut room = SealedRoom::new(room_id, group);

    let Some(epoch) = open_epoch else {
        return room
            .file_key_for_seal(file_id)
            .map_err(|e| FileKeyError::App(AppError::Internal(e.to_string())));
    };
    room.add_links(record.links);
    match room.file_key_for_open(file_id, epoch) {
        Ok(key) => Ok((key, epoch)),
        Err(RoomKeyError::EpochAhead { sealed, held }) => Err(FileKeyError::NotDelivered {
            epoch: sealed,
            held,
        }),
        Err(RoomKeyError::EpochUnreachable { sealed, earliest }) => {
            Err(FileKeyError::BeyondChain {
                epoch: sealed,
                earliest,
            })
        }
        Err(e) => Err(FileKeyError::App(AppError::Validation(e.to_string()))),
    }
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

    let mut links = record.links;
    let mut stored = 0;
    for link in incoming {
        if !links.iter().any(|held| held.epoch == link.epoch) {
            links.push(link);
            stored += 1;
        }
    }
    links.sort_by_key(|l| l.epoch);

    let group = RoomGroup::restore(&record.snapshot)
        .map_err(|e| AppError::Internal(format!("restore the group: {e}")))?;
    let mut room = SealedRoom::new(room_id, group);
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
    let room_id = member.room_id();
    let record = load(groups, member)
        .await?
        .ok_or_else(|| no_group(member))?;
    let group = RoomGroup::restore(&record.snapshot)
        .map_err(|e| AppError::Internal(format!("restore the group: {e}")))?;

    let held = group.epoch() + 1;
    if u64::from(epoch) > held {
        // Saying which epoch we hold turns "it does not open" — which reads like corruption
        // — into "you are behind", which an operator can act on.
        return Err(AppError::Validation(format!(
            "record is sealed under epoch {epoch} and this VTA holds room `{room_id}` at \
             epoch {held}; a commit has not been delivered"
        )));
    }

    // A record older than the current epoch is opened with *its own* epoch's key, walked out
    // of the retained chain. Without the links this VTA reaches only the epoch it is at, and
    // the error says which — an unreachable epoch is history that was severed or never
    // delivered, not a record that failed to decrypt.
    let mut room = SealedRoom::new(room_id, group);
    room.add_links(record.links);

    room.open_record(
        key,
        version,
        &vti_rooms::wire::SealedContent {
            ciphertext: ciphertext.to_string(),
            nonce: nonce.to_string(),
            epoch,
        },
    )
    .map_err(|e| AppError::Validation(e.to_string()))
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
    let record = RoomGroupRecord {
        snapshot: group
            .snapshot()
            .map_err(|e| AppError::Internal(format!("snapshot the group: {e}")))?,
        member_did: member.persona().to_string(),
        links,
        updated_at: now,
    };
    groups
        .insert(member.key(GROUP), &record)
        .await
        .map_err(|e| {
            AppError::Internal(format!("store group state for `{}`: {e}", member.room_id()))
        })
}

/// Why a group could not be founded.
#[derive(Debug)]
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
/// `rooms/owner/group/add/0.1`, `rooms/owner/group/remove/0.1` and
/// `rooms/owner/group/renew/0.1`.
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
    /// Unix seconds it was built.
    pub created_at: u64,
}

/// Why an admission could not be built.
#[derive(Debug)]
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
    Ok(())
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
        created_at: now,
    };
    retain(groups, owner, &pending)
        .await
        .map_err(PrepareAddError::App)?;
    Ok(pending)
}

/// Why a removal could not be built — `rooms/owner/group/remove/0.1` item 1.
#[derive(Debug)]
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
/// (`rooms/owner/group/remove/0.1` items 1 to 3). The live group is unchanged:
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
        created_at: now,
    };
    retain(groups, owner, &pending)
        .await
        .map_err(PrepareRemoveError::App)?;
    Ok(pending)
}

/// Build the renewal of `owner`'s group — a commit that adds and removes nobody, updating
/// the owner's own leaf — and retain it, durably, as a [`PendingAdvance`] **before**
/// anything is sent to a host (`rooms/owner/group/renew/0.1` items 2 and 3). The live
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
        created_at: now,
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
    discard_pending_advance(groups, owner).await
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
        // Promoted already; only the pending row survived a crash.
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

/// Discard everything this VTA holds for a room.
///
/// Called on removal from the group. A key-holder that kept its state would retain the
/// ability to open everything sealed up to the epoch it was removed at — which is exactly
/// what the removal was for.
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
        .remove(member.key(KEY_PACKAGE))
        .await
        .map_err(|e| AppError::Internal(format!("discard a pending key package: {e}")))?;
    // An advance this agent built for a group it no longer holds can never be
    // promoted; leaving it would hand whoever rejoins a stale successor to settle.
    discard_pending_advance(groups, member).await?;
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
