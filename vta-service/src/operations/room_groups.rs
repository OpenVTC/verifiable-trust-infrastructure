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
use vti_common::store::KeyspaceHandle;
use vti_rooms::mls::{GroupSnapshot, IdentitySnapshot, RoomGroup};
use vti_rooms::sealed::SealedRoom;

/// Storage key for a room's group state.
fn group_key(room_id: &str) -> String {
    format!("room-group:{room_id}")
}

/// Storage key for a consumed invitation.
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
    /// Unix seconds of the last change.
    pub updated_at: u64,
}

/// Mint an MLS KeyPackage for `room_id` and retain its private half.
///
/// **Per room, never reused across rooms.** A KeyPackage is a stable public identifier, so
/// the same one offered to two rooms tells anyone who sees both that one party is in both —
/// the correlation a `private` room exists to deny, arriving through the door rather than
/// the wall.
pub async fn mint_key_package(
    groups: &KeyspaceHandle,
    room_id: &str,
    member_did: &str,
    lifetime_secs: u64,
    now: u64,
) -> Result<PendingKeyPackage, AppError> {
    let (snapshot, package) = IdentitySnapshot::mint(member_did)
        .map_err(|e| AppError::Internal(format!("mint a key package: {e}")))?;

    let pending = PendingKeyPackage {
        snapshot,
        key_package: B64.encode(&package),
        expires_at: now + lifetime_secs,
    };
    groups
        .insert(pending_key(room_id), &pending)
        .await
        .map_err(|e| AppError::Internal(format!("store the pending key package: {e}")))?;
    Ok(pending)
}

/// Storage key for a pending key package.
fn pending_key(room_id: &str) -> String {
    format!("room-kp:{room_id}")
}

/// Join `room_id`'s group from a Welcome.
///
/// Refuses a second join rather than merging: two group states for one room is a condition
/// nothing downstream can resolve — [`open`] has no way to choose, and choosing wrong
/// returns "did not open" for a record the member can plainly see.
pub async fn join(
    groups: &KeyspaceHandle,
    room_id: &str,
    member_did: &str,
    welcome: &[u8],
    now: u64,
) -> Result<u64, AppError> {
    if load(groups, room_id).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "this VTA already holds group state for room `{room_id}`; leaving and rejoining \
             is a removal and a fresh invitation, not a second welcome"
        )));
    }

    // The KeyPackage the owner added is the one we minted, so the private half is in the
    // pending record — joining with a fresh identity would produce a group whose leaf
    // nobody added.
    let pending: Option<PendingKeyPackage> = groups
        .get(pending_key(room_id))
        .await
        .map_err(|e| AppError::Internal(format!("read the pending key package: {e}")))?;
    let pending = pending.ok_or_else(|| {
        AppError::Validation(format!(
            "no key package was minted for room `{room_id}`; a welcome can only be accepted \
             against the package the owner was given"
        ))
    })?;

    let group = RoomGroup::join_from_identity(&pending.snapshot, welcome)
        .map_err(|e| AppError::Validation(format!("the welcome did not process: {e}")))?;
    let epoch = group.epoch();

    store(groups, room_id, member_did, &group, now).await?;
    // The package is consumed. MLS consumes it on add, and a retained private half for a
    // used package is key material kept for nothing.
    groups
        .remove(pending_key(room_id))
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
    room_id: &str,
    commit: &[u8],
    claimed_epoch: u64,
    now: u64,
) -> Result<u64, AppError> {
    let record = load(groups, room_id).await?.ok_or_else(|| {
        AppError::NotFound(format!(
            "this VTA holds no group state for room `{room_id}`"
        ))
    })?;
    let mut group = RoomGroup::restore(&record.snapshot)
        .map_err(|e| AppError::Internal(format!("restore the group: {e}")))?;
    let current = group.epoch();

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

    group
        .apply_commit(commit)
        .map_err(|e| AppError::Validation(format!("the commit did not process: {e}")))?;
    let epoch = group.epoch();
    store(groups, room_id, &record.member_did, &group, now).await?;
    Ok(epoch)
}

/// Open a sealed record with the room's group key.
///
/// The key never leaves. That is the whole design: the caller sends ciphertext and gets
/// plaintext, and an oracle that returned the key would be a key-release call wearing a
/// different name.
pub async fn open_record(
    groups: &KeyspaceHandle,
    room_id: &str,
    key: &str,
    version: u64,
    ciphertext: &str,
    nonce: &str,
    epoch: u32,
) -> Result<Vec<u8>, AppError> {
    let record = load(groups, room_id).await?.ok_or_else(|| {
        AppError::NotFound(format!(
            "this VTA holds no group state for room `{room_id}`"
        ))
    })?;
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

    SealedRoom::new(room_id, group)
        .open_record(
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

/// The group this VTA holds for `room_id`, if any.
pub async fn load(
    groups: &KeyspaceHandle,
    room_id: &str,
) -> Result<Option<RoomGroupRecord>, AppError> {
    groups
        .get(group_key(room_id))
        .await
        .map_err(|e| AppError::Internal(format!("read group state for `{room_id}`: {e}")))
}

async fn store(
    groups: &KeyspaceHandle,
    room_id: &str,
    member_did: &str,
    group: &RoomGroup,
    now: u64,
) -> Result<(), AppError> {
    let record = RoomGroupRecord {
        snapshot: group
            .snapshot()
            .map_err(|e| AppError::Internal(format!("snapshot the group: {e}")))?,
        member_did: member_did.to_string(),
        updated_at: now,
    };
    groups
        .insert(group_key(room_id), &record)
        .await
        .map_err(|e| AppError::Internal(format!("store group state for `{room_id}`: {e}")))
}

/// Discard everything this VTA holds for a room.
///
/// Called on removal from the group. A key-holder that kept its state would retain the
/// ability to open everything sealed up to the epoch it was removed at — which is exactly
/// what the removal was for.
pub async fn forget(groups: &KeyspaceHandle, room_id: &str) -> Result<(), AppError> {
    groups
        .remove(group_key(room_id))
        .await
        .map_err(|e| AppError::Internal(format!("discard group state for `{room_id}`: {e}")))?;
    groups
        .remove(pending_key(room_id))
        .await
        .map_err(|e| AppError::Internal(format!("discard a pending key package: {e}")))
}
