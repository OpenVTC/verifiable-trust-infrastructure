//! Keeping a held group current: which group a member holds and from when,
//! commits (current and prior memberships), the epoch chain, removals, and
//! forgetting a room.

use super::*;

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
#[derive(Clone, PartialEq, Eq)]
pub enum RepairTarget {
    Current,
    Prior { signature_key: Vec<u8> },
}

/// Written by hand so no log line carries key bytes: the leaf's signature key is public,
/// but the workspace's rule (`vta-sdk/tests/secret_debug_census.rs`) is that a `*_key`
/// field is never formatted by a derived `Debug`.
impl std::fmt::Debug for RepairTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Current => f.write_str("Current"),
            Self::Prior { signature_key } => f
                .debug_struct("Prior")
                .field(
                    "signature_key",
                    &format_args!("<{} bytes>", signature_key.len()),
                )
                .finish(),
        }
    }
}

/// Which of `member`'s memberships answers for one room epoch.
pub(super) enum Holding {
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
pub(super) async fn holding_for(
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
pub(super) fn start_of(
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
pub(super) async fn joined_epoch(
    groups: &KeyspaceHandle,
    member: &Member,
) -> Result<Option<u32>, AppError> {
    groups.get(member.key(JOINED)).await.map_err(|e| {
        AppError::Internal(format!(
            "read the join epoch for `{}`: {e}",
            member.room_id()
        ))
    })
}

/// The earliest room epoch `record`'s chain reaches under `floor`.
pub(super) fn reach_of(
    member: &Member,
    record: &RoomGroupRecord,
    floor: u32,
) -> Result<u32, AppError> {
    sealed_room(member, record, floor)?
        .earliest_readable_epoch()
        .map_err(|e| AppError::Internal(format!("walk the chain for `{}`: {e}", member.room_id())))
}

/// `record` restored as a room ready to open: the epoch floor applied, its links added.
pub(super) fn sealed_room(
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

pub(super) async fn members_under(
    groups: &KeyspaceHandle,
    prefix: &str,
) -> Result<Vec<Member>, AppError> {
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
pub(super) fn no_prior(member: &Member) -> AppError {
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

pub(super) async fn record_removal(
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

/// Discard everything this VTA holds for a room.
///
/// The discard of the member's group state — the current group and every prior membership
/// a removal ended ([`PRIOR`]) — and with it the member's personal label
/// (`rooms/keys/label/0.1` recipient item 8) and read marker
/// (`rooms/keys/read-marker/set/0.1` recipient item 7). A commit removing the member does **not**
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
    // So is the read marker (`rooms/keys/read-marker/set/0.1` recipient item 7).
    groups
        .remove(member.key(READ_MARKER))
        .await
        .map_err(|e| AppError::Internal(format!("discard the read marker for `{room_id}`: {e}")))?;
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
