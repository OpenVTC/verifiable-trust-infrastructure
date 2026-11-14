//! Sealing and opening records: the epoch to seal under, record and file keys,
//! profile locations, and the epoch floor a prune leaves.

use super::*;

/// The group `member` seals with: the current membership's, and `None` when there is none
/// — no group at all, or only state a removal ended. A removed member that has not been
/// admitted again has no current epoch, so nothing is sealed under the state the removal
/// left (`rooms/keys/open/0.2`, `rooms/keys/file-key/0.2`: `noGroup`); that state only
/// opens what it already could.
pub(super) async fn current_for_seal(
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
