//! Getting a group: key packages minted against an invitation, the Welcome that
//! consumes it, and an owner creating a room's group.

use super::*;

/// Storage key for a consumed invitation.
///
/// Keyed by the invitation's credential id, which already names one subject — so it is
/// per member without saying so, and stays as it was.
pub(in crate::operations) fn invitation_key(credential_id: &str) -> String {
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
pub(super) static OUTSTANDING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
pub(super) async fn legacy_key_package(
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
    /// The Welcome is for an MLS group other than the one this member's held state is in —
    /// with a removal recorded or not (`rooms/keys/welcome/0.1`, *Same group, whatever the
    /// evidence*): a re-admission is into the same group, and another group's tree is no
    /// evidence that the state ended — `welcomeInvalid`. Nothing was consumed or changed.
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
/// **Same group, whatever the evidence.** Under either, a Welcome for an MLS group other than
/// the held state's (different group ids) is [`JoinError::WelcomeForAnotherGroup`]
/// (`welcomeInvalid`), refused before anything is written: a removal from one group is no
/// reason to make another the room's current group.
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
            // Same group, whatever the evidence (`rooms/keys/welcome/0.1`): a re-admission is
            // into the group the held state is in. A removal from it is no reason to take a
            // Welcome for another group as the room's current one, and a Welcome for another
            // group has none of the held state's leaves by construction, so its tree is no
            // evidence of a removal either. Refused before anything is written.
            let held_group = ended_group.snapshot.group_id().map_err(|e| {
                AppError::Internal(format!("read the held group's id for `{room_id}`: {e}"))
            })?;
            if group.group_id() != held_group {
                return Err(JoinError::WelcomeForAnotherGroup);
            }
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
