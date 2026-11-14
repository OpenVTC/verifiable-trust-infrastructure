//! CRUD over the `rooms:` and `room_records:` keyspaces.
//!
//! # Key layout
//!
//! ```text
//! rooms:<roomId>                                 -> Room
//! room_records/v2:<len>:<roomId>:<key>           -> Record
//! room_epoch_links/v2:<len>:<roomId>:<epoch>     -> EpochLink   (room_epoch_links keyspace)
//! room-commit/v2:<len>:<roomId>:<epoch>          -> commit      (room_epoch_links keyspace)
//! room_leaf/v1:<len>:<roomId>:<key>              -> leaf hash   (room_records keyspace)
//! room_by_version/v1:<len>:<roomId>:<version>    -> record key  (room_records keyspace)
//! room_head/v1:<len>:<roomId>                    -> tree head   (room_records keyspace)
//! ```
//!
//! The last three are the record indexes (`index` module): each record's leaf hash, the
//! room in version order, and the room's cached tree head, written in the same atomic batch
//! as the record they describe, and built from the records the first time a room written
//! before they existed is read or written.
//!
//! `<len>` is the room identifier's length in bytes, in decimal. A room identifier is a
//! DID and contains `:` itself, so without it the key of one room's row could be the key
//! of another's: `did:web:a`'s record `b:k` and `did:web:a:b`'s record `k` were both
//! `room_records:did:web:a:b:k` — one row, written by either room (#2382). With the length
//! in front, the identifier is read off by count, not by looking for a separator it may
//! contain: two rooms' rows never share a key, and a room's scan prefix
//! (`…/v2:<len>:<roomId>:`) is a prefix of no other room's, so one room's listing, chain
//! and prune never reach another's, in the store layer as well as at the authorization
//! layer above it.
//!
//! Rows written in the earlier layout (no `/v2`, no length) are moved by
//! [`migrate_room_keys`], which each host runs at boot.
//!
//! # Version assignment
//!
//! Versions are allocated from [`super::Room::next_version`], monotonic **per room**. A
//! write reads the room, takes the next number, writes the record, then writes the room
//! back. That read-modify-write is not atomic across the two keyspaces, and the failure it
//! can produce is a *skipped* version rather than a duplicated one — which is the direction
//! it has to fail in, because `sinceVersion` only needs monotonicity, not density. A
//! duplicate would make two records indistinguishable to a watermark; a gap costs nothing.

use vti_common::error::AppError;
use vti_common::identifier::validate_did;
use vti_common::store::KeyspaceHandle;

use super::{Record, RecordStatus, Room};

mod index;
#[cfg(test)]
mod index_tests;
use crate::wire::EpochLink;

/// `rooms:<roomId>`.
pub const ROOMS_PREFIX: &str = "rooms:";
/// `room_records/v2:<len>:<roomId>:<key>`.
const RECORDS_PREFIX: &str = "room_records/v2:";
/// `room_epoch_links/v2:<len>:<roomId>:<epoch>`.
const EPOCH_LINKS_PREFIX: &str = "room_epoch_links/v2:";
/// `room-commit/v2:<len>:<roomId>:<epoch>`, in the epoch-links keyspace.
const COMMITS_PREFIX: &str = "room-commit/v2:";

/// The earlier layouts, `<prefix><roomId>:<…>`, which [`migrate_room_keys`] moves. Nothing
/// else reads them: their keys are ambiguous (module docs).
const LEGACY_RECORDS_PREFIX: &str = "room_records:";
const LEGACY_EPOCH_LINKS_PREFIX: &str = "room_epoch_links:";
const LEGACY_COMMITS_PREFIX: &str = "room-commit:";

pub(crate) fn room_key(room_id: &str) -> String {
    format!("{ROOMS_PREFIX}{room_id}")
}

/// `<prefix><len>:<roomId>:` — every row of one room and of no other (module docs).
fn room_scope(prefix: &str, room_id: &str) -> String {
    format!("{prefix}{}:{room_id}:", room_id.len())
}

fn record_key(room_id: &str, key: &str) -> String {
    format!("{}{key}", record_prefix(room_id))
}

/// The storage key of record `key` in `room_id`, for a host that has to reach the row
/// directly (a test ageing a record, say). Everything else goes through this module.
pub fn record_storage_key(room_id: &str, key: &str) -> String {
    record_key(room_id, key)
}

/// Every record in one room.
fn record_prefix(room_id: &str) -> String {
    room_scope(RECORDS_PREFIX, room_id)
}

/// `room_epoch_links/v2:<len>:<roomId>:<epoch>`, zero-padded so a scan is ordered.
///
/// Ten digits: `u32::MAX` is ten, so no epoch a room can reach sorts out of place. A chain
/// scanned in the wrong order is a chain walked in the wrong order.
fn epoch_link_key(room_id: &str, epoch: u32) -> String {
    format!("{}{epoch:010}", epoch_link_prefix(room_id))
}

/// Every link in one room.
fn epoch_link_prefix(room_id: &str) -> String {
    room_scope(EPOCH_LINKS_PREFIX, room_id)
}

/// Every relayed commit of one room.
fn commit_prefix(room_id: &str) -> String {
    room_scope(COMMITS_PREFIX, room_id)
}

/// Store one epoch link.
///
/// **Refuses to replace an existing one.** A link is minted once, at the commit that
/// produced its epoch, by the only party then holding both keys. A second one for the same
/// epoch is either a replay or a host being asked to re-point a room's history at key
/// material of somebody else's choosing — and the members who already walked the original
/// would never see the difference.
pub async fn put_epoch_link(
    links: &KeyspaceHandle,
    room_id: &str,
    link: &EpochLink,
) -> Result<(), AppError> {
    if link.epoch < 2 {
        return Err(AppError::Validation(format!(
            "epoch {} has no predecessor to link to",
            link.epoch
        )));
    }
    let k = epoch_link_key(room_id, link.epoch);
    if links.get_raw(k.clone()).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "room `{room_id}` already has an epoch link at {}",
            link.epoch
        )));
    }
    links.insert(k, link).await
}

/// Every epoch link a room has, ascending.
///
/// Served to a member so they can read the room's history. This service hands out
/// ciphertext it cannot read: the key that opens a link is the storage key of the epoch it
/// names, and no host holds one.
pub async fn list_epoch_links(
    links: &KeyspaceHandle,
    room_id: &str,
) -> Result<Vec<EpochLink>, AppError> {
    let pairs = links.prefix_iter_raw(epoch_link_prefix(room_id)).await?;
    let mut out = Vec::with_capacity(pairs.len());
    for (_k, v) in pairs {
        let link: EpochLink = serde_json::from_slice(&v)
            .map_err(|e| AppError::Internal(format!("decode epoch link in `{room_id}`: {e}")))?;
        out.push(link);
    }
    out.sort_by_key(|l| l.epoch);
    Ok(out)
}

/// Sever the chain below `epoch`: **cryptographic deletion** of everything sealed before it.
///
/// Returns how many links were dropped.
///
/// # Why this is deletion and a record purge is not
///
/// [`purge_record`] asks a host to erase bytes and trusts it to have done so — against a
/// backup, a snapshot, or a host that simply did not, it is a promise. Dropping a link is
/// different in kind: it destroys the only path from a key any member holds to the keys
/// those records were sealed under. A host that retains every byte of a pruned epoch retains
/// ciphertext that nobody, member or host, can ever open again.
///
/// **Irreversible, and not partially.** A member who has already walked past this rung keeps
/// what they derived — the chain is how you *reach* a key, not where it is kept. This bounds
/// who can read the old material to those who already could, which is the strongest property
/// deletion of shared data can have.
pub async fn prune_epoch_links_before(
    links: &KeyspaceHandle,
    room_id: &str,
    epoch: u32,
) -> Result<usize, AppError> {
    let pairs = links.prefix_iter_raw(epoch_link_prefix(room_id)).await?;
    let mut dropped = 0;
    for (k, v) in pairs {
        let link: EpochLink = serde_json::from_slice(&v)
            .map_err(|e| AppError::Internal(format!("decode epoch link in `{room_id}`: {e}")))?;
        if link.epoch <= epoch {
            let key = String::from_utf8(k)
                .map_err(|e| AppError::Internal(format!("epoch link key is not utf-8: {e}")))?;
            links.remove(key).await?;
            dropped += 1;
        }
    }
    Ok(dropped)
}

/// Drop the chain below `before_epoch`, and report how far back it still reaches.
///
/// # Two numbers, because they are not the same question
///
/// `pruned` is what this call removed. `earliest_rung` is how far back a member
/// can now actually walk — and those come apart, because **a chain can already
/// have a gap**: rungs are delivered per commit and a delivery that never
/// happened leaves one. A prune below an existing gap removes rungs and changes
/// nothing about reach, and reporting `before_epoch` back would tell an operator
/// they had achieved something they had not.
///
/// `earliest_rung` is read from what survives rather than computed from the
/// request, which is the only way it can be true.
pub async fn prune_chain(
    links: &KeyspaceHandle,
    room_id: &str,
    before_epoch: u32,
) -> Result<(usize, u32), AppError> {
    // `prune_epoch_links_before` drops `epoch <= n`, and this drops *below*
    // `before_epoch` — so the boundary is one lower. Off by one here would
    // silently take the epoch the caller meant to keep.
    let dropped = prune_epoch_links_before(links, room_id, before_epoch.saturating_sub(1)).await?;
    let remaining = list_epoch_links(links, room_id).await?;
    let earliest = remaining
        .iter()
        .map(|l| l.epoch)
        .min()
        .unwrap_or(before_epoch);
    Ok((dropped, earliest))
}

/// [`prune_chain`], and the room's **epoch floor** raised to the higher of the floor it held
/// and `before_epoch − 1` (`rooms/epoch/prune/0.2`, *The floor, and the off-by-one*) —
/// raised even when no rung is dropped (a gap, a `fromJoin` room), and never lowered.
/// Every version of the prune raises it: the floor is a property of the room, not of the
/// request that moved it. Returns `(pruned, earliest_rung, epoch_floor)`.
///
/// The floor is written **before** the rungs go, so a prune interrupted between the two
/// leaves a room that already refuses to serve what it is about to erase.
pub async fn prune_chain_to_floor(
    rooms: &KeyspaceHandle,
    links: &KeyspaceHandle,
    room_id: &str,
    before_epoch: u32,
    now: u64,
) -> Result<(usize, u32, u32), AppError> {
    let mut room = get_room(rooms, room_id).await?;
    let floor = room
        .epoch_floor
        .unwrap_or(0)
        .max(before_epoch.saturating_sub(1))
        .max(1);
    room.epoch_floor = Some(floor);
    room.updated_at = now;
    rooms.insert(room_key(room_id), &room).await?;
    let (pruned, earliest) = prune_chain(links, room_id, before_epoch).await?;
    Ok((pruned, earliest, floor))
}

/// The rungs a host may serve for `room`: every one it holds numbered **above** the room's
/// epoch floor (`EpochFloor`: a host never serves a rung at or below it), ascending.
pub async fn servable_epoch_links(
    links: &KeyspaceHandle,
    room: &Room,
) -> Result<Vec<EpochLink>, AppError> {
    let floor = room.epoch_floor.unwrap_or(0);
    Ok(list_epoch_links(links, &room.room_id)
        .await?
        .into_iter()
        .filter(|l| l.epoch > floor)
        .collect())
}

/// Store a rung for `room`, refusing one numbered at or below the room's epoch floor
/// (`EpochFloor`: a host never stores or accepts such a rung) as well as everything
/// [`put_epoch_link`] refuses.
pub async fn put_epoch_link_above_floor(
    links: &KeyspaceHandle,
    room: &Room,
    link: &EpochLink,
) -> Result<(), AppError> {
    if let Some(floor) = room.epoch_floor
        && link.epoch <= floor
    {
        return Err(AppError::Validation(format!(
            "room `{}` has forgotten its history below epoch {floor}; it accepts no rung at \
             or below it",
            room.room_id
        )));
    }
    put_epoch_link(links, &room.room_id, link).await
}

/// Storage key for one relayed commit. Zero-padded so a prefix scan is ordered.
fn commit_key(room_id: &str, epoch: u32) -> String {
    format!("{}{epoch:010}", commit_prefix(room_id))
}

/// Store the commit that produced an epoch, for members who were not online.
///
/// **Refuses to replace an existing one**, for the same reason `put_epoch_link`
/// does and with a sharper consequence: the first commit published is the one
/// members may already have applied, and a second would fork the very group the
/// relay exists to keep together.
pub async fn put_commit(
    commits: &KeyspaceHandle,
    room_id: &str,
    epoch: u32,
    commit: &str,
) -> Result<(), AppError> {
    let key = commit_key(room_id, epoch);
    if commits.get_raw(key.clone()).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "a commit for epoch {epoch} of `{room_id}` is already held; replacing it would \
             fork the members who have applied it"
        )));
    }
    commits
        .insert(key, &commit.to_string())
        .await
        .map_err(|e| AppError::Internal(format!("store the commit for `{room_id}`: {e}")))
}

/// The commits above `since_epoch`, in order and **stopping at the first gap**.
///
/// MLS commits apply in sequence: one applied out of order, or over a gap, is
/// rejected by the group. So a host that is missing one returns the run it holds
/// *up to* the gap rather than skipping past it — a short answer is recoverable,
/// while a set with a hole in it is a member stuck at an epoch who cannot say
/// why.
pub async fn commits_since(
    commits: &KeyspaceHandle,
    room_id: &str,
    since_epoch: u32,
    limit: usize,
) -> Result<Vec<crate::wire::RelayedCommit>, AppError> {
    let pairs = commits.prefix_iter_raw(commit_prefix(room_id)).await?;
    let mut held: Vec<(u32, String)> = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        let key = String::from_utf8(k)
            .map_err(|e| AppError::Internal(format!("commit key is not utf-8: {e}")))?;
        let Some(epoch) = key.rsplit(':').next().and_then(|e| e.parse::<u32>().ok()) else {
            continue;
        };
        let commit: String = serde_json::from_slice(&v)
            .map_err(|e| AppError::Internal(format!("decode a commit in `{room_id}`: {e}")))?;
        held.push((epoch, commit));
    }
    held.sort_by_key(|(epoch, _)| *epoch);

    let mut out = Vec::new();
    let mut expected = since_epoch + 1;
    for (epoch, commit) in held {
        if epoch < expected {
            continue;
        }
        // The gap. Stop rather than skip.
        if epoch != expected {
            break;
        }
        out.push(crate::wire::RelayedCommit { epoch, commit });
        expected += 1;
        if out.len() >= limit {
            break;
        }
    }
    Ok(out)
}

/// Register a room.
///
/// Refuses to replace an existing one: re-registering would silently reset the epoch and
/// the version counter, which a client would read as the room having been rolled back.
pub async fn create_room(rooms: &KeyspaceHandle, room: &Room) -> Result<(), AppError> {
    validate_did("ownerDid", &room.owner_did)?;
    if rooms.get_raw(room_key(&room.room_id)).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "room `{}` is already registered here",
            room.room_id
        )));
    }
    rooms.insert(room_key(&room.room_id), room).await?;
    // A room registered: the host's rooms list moved (`crate::observe`).
    crate::observe::changed();
    Ok(())
}

/// How long a minted epoch is good for, in seconds.
///
/// Not yet a per-room parameter: `rooms/create/0.2` has no member for it, and inventing one
/// locally would put this implementation's rooms out of conformance with the published
/// schema. A room that wants a different lifetime is a spec change first.
fn epoch_lifetime_seconds() -> u64 {
    u64::from(crate::lifecycle::DEFAULT_EPOCH_LIFETIME_DAYS) * 24 * 60 * 60
}

/// Fetch a room, or [`AppError::NotFound`].
pub async fn get_room(rooms: &KeyspaceHandle, room_id: &str) -> Result<Room, AppError> {
    let raw = rooms
        .get_raw(room_key(room_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("room `{room_id}` not found")))?;
    serde_json::from_slice(&raw)
        .map_err(|e| AppError::Internal(format!("decode room `{room_id}`: {e}")))
}

/// Advance a room's epoch.
///
/// `new_epoch` must be exactly one greater than the current one. A gap would leave records
/// sealed under an epoch no member was ever given a key for, and a repeat would let a
/// removed member's key open material written after their removal — which is the whole
/// point of advancing.
///
/// This service records the number. It never learns the key.
///
/// **Minting an epoch is how a room is renewed.** It resets `epoch_expires_at`, which is the
/// clock the whole lifecycle hangs off (§9) — so a room in use renews itself in the course
/// of being used, and a lapsed one is brought back by the single operation its members were
/// already going to perform. There is no separate "renew" verb, and there should not be: one
/// that could be called without committing would let a room look live while its key material
/// stood still.
pub async fn advance_epoch(
    rooms: &KeyspaceHandle,
    room_id: &str,
    new_epoch: u32,
    now: u64,
) -> Result<Room, AppError> {
    let mut room = get_room(rooms, room_id).await?;
    if new_epoch != room.epoch + 1 {
        return Err(AppError::Validation(format!(
            "epoch must advance by exactly one: room `{room_id}` is at {}, got {new_epoch}",
            room.epoch
        )));
    }
    room.epoch = new_epoch;
    room.epoch_expires_at = Some(now + epoch_lifetime_seconds());
    room.updated_at = now;
    rooms.insert(room_key(room_id), &room).await?;
    // A renewal may bring the room back from a lapse (`crate::observe`).
    crate::observe::changed();
    Ok(room)
}

/// Record a new owner.
///
/// Both `rooms/owner/transfer` and `rooms/owner/claim` end here — they differ entirely in
/// what has to be true *before* this is reached, and not at all in what it does.
///
/// **Does not renew the room.** A claim takes a dormant room and leaves it dormant; only
/// minting an epoch makes it live again. That is deliberate: the new owner's first act
/// should be the one that proves they can perform it, and a claim that silently renewed
/// would hand ownership to someone who might turn out to be unable to commit — with the
/// room looking healthy until the next lapse a year later. If they do not renew, the next
/// nominee can claim in turn, which is the succession chain working rather than failing.
pub async fn set_owner(
    rooms: &KeyspaceHandle,
    room_id: &str,
    new_owner_did: &str,
    now: u64,
) -> Result<Room, AppError> {
    // The owner is what a host addresses about quota, abuse and lifecycle, so a value that
    // is not an identifier at all is a room nobody can be reached about. Cheap to refuse
    // here and impossible to fix later, since the party who could correct it is the one the
    // bad value replaced.
    validate_did("ownerDid", new_owner_did)?;

    let mut room = get_room(rooms, room_id).await?;
    room.owner_did = new_owner_did.to_string();
    room.updated_at = now;
    rooms.insert(room_key(room_id), &room).await?;
    Ok(room)
}

/// Freeze or thaw a room ([`Room::frozen_at`]): `Some(at)` is the owner's archive
/// (`vtc/rooms/community/archive/0.1`), `None` their unarchive.
///
/// Called **only on the owner's request** — a freeze is the owner's switch, never a host
/// judgement. Bumps `updated_at` (to the freeze time, or to now on a thaw), never lowering
/// it.
///
/// Idempotent: freezing a frozen room moves its `frozen_at` to the new time, thawing a room
/// that is not frozen changes nothing a reader can see. [`AppError::NotFound`] when the
/// room is not held.
pub async fn set_frozen(
    rooms: &KeyspaceHandle,
    room_id: &str,
    frozen_at: Option<u64>,
) -> Result<(), AppError> {
    let mut room = get_room(rooms, room_id).await?;
    room.frozen_at = frozen_at;
    room.updated_at = room.updated_at.max(frozen_at.unwrap_or_else(now_secs));
    rooms.insert(room_key(room_id), &room).await?;
    // Whether the room accepts writes changed (`crate::observe`).
    crate::observe::changed();
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What [`migrate_room_keys`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigratedKeys {
    /// Records moved to the current layout.
    pub records: u64,
    /// Epoch links moved.
    pub epoch_links: u64,
    /// Relayed commits moved.
    pub commits: u64,
    /// Rows left in the earlier layout, each with why: one that cannot be attributed to
    /// exactly one room (a record that does not decode, or whose key does not end in the
    /// key it carries; an epoch row without a ten-digit epoch), or whose key in the
    /// current layout is already taken. Nothing reads them; the host reports them.
    pub left: Vec<String>,
}

impl MigratedKeys {
    /// Whether there was anything to do.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// The room identifier of a row in an earlier layout, `<prefix><roomId>:<suffix>`, where
/// `suffix` is what the row itself says it is (a record's key, an epoch's ten digits). The
/// key alone is ambiguous (module docs); with the suffix fixed by the row, it is not.
fn legacy_room_of(key: &[u8], prefix: &str, suffix: &[u8]) -> Option<String> {
    let room = key
        .strip_prefix(prefix.as_bytes())?
        .strip_suffix(suffix)?
        .strip_suffix(b":")?;
    let room = std::str::from_utf8(room).ok()?;
    (!room.is_empty()).then(|| room.to_string())
}

/// The trailing ten-digit epoch of a row in an earlier layout.
fn legacy_epoch(key: &[u8]) -> Option<(u32, &[u8])> {
    let digits = key.get(key.len().checked_sub(10)?..)?;
    if !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let epoch = std::str::from_utf8(digits).ok()?.parse().ok()?;
    Some((epoch, digits))
}

/// Move one row from `old` to `new`, byte for byte, in one atomic batch that holds only
/// while `old` is as read and `new` is empty. `Err(reason)` when it did not move.
async fn move_row(
    ks: &KeyspaceHandle,
    old: Vec<u8>,
    value: Vec<u8>,
    new: String,
    also_remove: Option<String>,
) -> Result<Result<(), String>, AppError> {
    let mut batch = vti_common::store::Batch::new();
    batch
        .require_unchanged(old.clone(), value.clone())
        .require_absent(new.clone())
        .insert_raw(new.clone(), value)
        .remove(old.clone());
    if let Some(k) = also_remove {
        batch.remove(k);
    }
    Ok(match ks.apply_batch(batch).await? {
        vti_common::store::BatchOutcome::Applied => Ok(()),
        vti_common::store::BatchOutcome::Refused { check: 0 } => {
            Err("changed while it was being moved".into())
        }
        vti_common::store::BatchOutcome::Refused { .. } => Err(format!("`{new}` is already held")),
    })
}

/// Move every room row still in the earlier key layout — `<prefix><roomId>:<…>`, whose
/// keys are ambiguous because a room identifier contains `:` (#2382) — to the current one
/// (module docs). Each host runs it at boot, before it serves a room, and after a restore.
///
/// # Attribution
///
/// The room a legacy row belongs to is read with the row's own help: a record carries its
/// key, so the identifier is what lies between the prefix and `:<key>`; an epoch link or a
/// commit ends in its ten-digit epoch. A row that cannot be attributed that way is left
/// where it is and reported in [`MigratedKeys::left`], never guessed at. A record two rooms
/// both wrote to under the old layout is one row; it moves to the room whose write it holds.
///
/// # Idempotent and resumable
///
/// Each row moves in one atomic batch, so an interrupted migration is finished by running
/// it again, and a store with nothing left in the earlier layout moves nothing.
pub async fn migrate_room_keys(
    records: &KeyspaceHandle,
    epoch_links: &KeyspaceHandle,
) -> Result<MigratedKeys, AppError> {
    let mut out = MigratedKeys::default();
    let lossy = |k: &[u8]| String::from_utf8_lossy(k).into_owned();

    for (k, v) in records.prefix_iter_raw(LEGACY_RECORDS_PREFIX).await? {
        let Ok(record) = serde_json::from_slice::<Record>(&v) else {
            out.left
                .push(format!("{}: does not decode as a record", lossy(&k)));
            continue;
        };
        let Some(room_id) = legacy_room_of(&k, LEGACY_RECORDS_PREFIX, record.key.as_bytes()) else {
            out.left.push(format!(
                "{}: does not end in the key it carries, `{}`",
                lossy(&k),
                record.key
            ));
            continue;
        };
        let new = record_key(&room_id, &record.key);
        // The room's index no longer accounts for its records, so its head goes in the same
        // batch and the next reader rebuilds the index (`index` module).
        let head = index::head_key(&room_id);
        match move_row(records, k.clone(), v, new, Some(head)).await? {
            Ok(()) => out.records += 1,
            Err(why) => out.left.push(format!("{}: {why}", lossy(&k))),
        }
    }

    for (legacy, current, count) in [
        (
            LEGACY_EPOCH_LINKS_PREFIX,
            EPOCH_LINKS_PREFIX,
            &mut out.epoch_links,
        ),
        (LEGACY_COMMITS_PREFIX, COMMITS_PREFIX, &mut out.commits),
    ] {
        for (k, v) in epoch_links.prefix_iter_raw(legacy).await? {
            let Some((room_id, epoch)) = legacy_epoch(&k)
                .and_then(|(epoch, digits)| Some((legacy_room_of(&k, legacy, digits)?, epoch)))
            else {
                out.left
                    .push(format!("{}: does not end in a ten-digit epoch", lossy(&k)));
                continue;
            };
            let new = format!("{}{epoch:010}", room_scope(current, &room_id));
            match move_row(epoch_links, k.clone(), v, new, None).await? {
                Ok(()) => *count += 1,
                Err(why) => out.left.push(format!("{}: {why}", lossy(&k))),
            }
        }
    }
    Ok(out)
}

/// What [`purge_room_rows`] removed, by kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgedRows {
    /// Records, tombstones included.
    pub records: u64,
    /// Epoch links (rungs).
    pub epoch_links: u64,
    /// Relayed MLS commits.
    pub commits: u64,
    /// Whether a held revocation list was discarded.
    pub revocations: bool,
    /// Whether the `rooms:<roomId>` row itself was removed.
    pub room: bool,
}

/// Remove **every row this host's room keyspaces hold for one room**: its records
/// (tombstones included), its epoch links and relayed MLS commits, its held revocation
/// list, and finally the `rooms:<roomId>` row itself (`vtc/rooms/community/remove/0.1`).
/// Blobs are [`crate::blobs::BlobHost::purge_room`]'s.
///
/// `epoch_links` is the keyspace both [`put_epoch_link`] and [`put_commit`] are given —
/// each host stores a room's commits beside its rungs ([`crate::ROOM_EPOCH_LINKS_KEYSPACE`]).
///
/// # Idempotent and resumable
///
/// Every step removes what is there and tolerates what is not, so a purge that died
/// part-way is finished by calling it again, and a purge of a room already gone removes
/// nothing and succeeds. The room row goes **last**: while any of the room's data remains,
/// the row that names it does too, so an interrupted purge never leaves rows no listing
/// could find the room for.
///
/// # Room-exact
///
/// Each scan prefix carries the identifier's length (module docs), so it covers this room's
/// rows and none of a room whose identifier extends this one's.
pub async fn purge_room_rows(
    rooms: &KeyspaceHandle,
    records: &KeyspaceHandle,
    epoch_links: &KeyspaceHandle,
    revocations: &KeyspaceHandle,
    room_id: &str,
) -> Result<PurgedRows, AppError> {
    let mut out = PurgedRows::default();

    // The index first, head before rows: an interrupted purge leaves the room unindexed,
    // and a read before the next attempt rebuilds it from what records remain.
    index::purge(records, room_id).await?;
    for k in records.prefix_keys(record_prefix(room_id)).await? {
        records.remove(k).await?;
        out.records += 1;
    }
    for k in epoch_links.prefix_keys(epoch_link_prefix(room_id)).await? {
        epoch_links.remove(k).await?;
        out.epoch_links += 1;
    }
    for k in epoch_links.prefix_keys(commit_prefix(room_id)).await? {
        epoch_links.remove(k).await?;
        out.commits += 1;
    }

    // By key rather than by `held`, so a list this host can no longer decode is still
    // discarded rather than stalling the purge for ever.
    let revocation_key = format!("{}{room_id}", crate::revocation::REVOCATIONS_PREFIX);
    if revocations.get_raw(revocation_key).await?.is_some() {
        crate::revocation::discard(revocations, room_id).await?;
        out.revocations = true;
    }

    // Last, so the room stays nameable until everything else is gone.
    if rooms.get_raw(room_key(room_id)).await?.is_some() {
        rooms.remove(room_key(room_id)).await?;
        out.room = true;
        // A room left the host's list (`crate::observe`).
        crate::observe::changed();
    }
    Ok(out)
}

/// Write a record, assigning it the room's next version.
///
/// `expected_version` is an optional precondition:
/// - `None` — overwrite unconditionally.
/// - `Some(0)` — create only; fails if the key exists.
/// - `Some(n)` — fails unless the stored record is at version `n`.
///
/// On mismatch the error carries the **current version**, so a caller does not have to
/// re-read to learn what it lost to. A bare rejection would force a re-read, and between
/// the rejection and the re-read the record can change again — the pattern has no fixed
/// point under contention.
pub async fn put_record(
    rooms: &KeyspaceHandle,
    records: &KeyspaceHandle,
    room_id: &str,
    mut record: Record,
    expected_version: Option<u64>,
    now: u64,
) -> Result<Record, AppError> {
    let mut room = get_room(rooms, room_id).await?;
    index::ensure(records, room_id).await?;

    let existing = get_record(records, room_id, &record.key).await.ok();

    if let Some(expected) = expected_version {
        match (&existing, expected) {
            (Some(_), 0) => {
                return Err(AppError::Conflict(format!(
                    "record `{}` already exists (create-only requested)",
                    record.key
                )));
            }
            (None, 0) => {}
            (Some(current), n) if current.version != n => {
                return Err(AppError::Conflict(format!(
                    "record `{}` is at version {}, not {n}",
                    record.key, current.version
                )));
            }
            (None, n) => {
                return Err(AppError::Conflict(format!(
                    "record `{}` does not exist, so it cannot be at version {n}",
                    record.key
                )));
            }
            _ => {}
        }
    }

    // Content shape must match the room's visibility. Enforced here rather than in the
    // type, because the invariant belongs to the room and the type belongs to the record.
    if room.visibility.stores_cleartext() {
        if record.sealed.is_some() {
            return Err(AppError::Validation(
                "an open room stores cleartext records; `sealed` was supplied".into(),
            ));
        }
        if record.cleartext.is_none() {
            return Err(AppError::Validation(
                "an open room requires `cleartext`".into(),
            ));
        }
    } else {
        if record.cleartext.is_some() {
            return Err(AppError::Validation(format!(
                "room `{room_id}` is {:?}; cleartext must not be stored here",
                room.visibility
            )));
        }
        if record.sealed.is_none() {
            return Err(AppError::Validation(
                "a sealed room requires `sealed` content".into(),
            ));
        }
        // The epoch a record was sealed under must be the room's current one, or a reader
        // holding the current key cannot open it.
        if record.epoch != Some(room.epoch) {
            return Err(AppError::Validation(format!(
                "record is sealed under epoch {:?}, room `{room_id}` is at {}",
                record.epoch, room.epoch
            )));
        }
    }

    // A `Private` room must not carry an author here: on that tier authorship lives inside
    // the sealed body, where only members can read it.
    if matches!(room.visibility, super::Visibility::Private) && record.author.is_some() {
        return Err(AppError::Validation(
            "a private room does not record an author; authorship belongs inside the sealed body"
                .into(),
        ));
    }

    // A new body is sealed for the version it is about to take, and that is recorded now —
    // the one moment it is known (rooms `_shared/0.1` `SealedRecord.version`: "MUST record
    // the version a body was sealed at when it stores it"). Whatever an earlier body at this
    // key was sealed at no longer applies.
    record.sealed_version = record.sealed.as_ref().map(|_| room.next_version);
    // The host's own times and first author (`rooms/records/put/0.5` Host items 16–17),
    // whichever put version wrote this: they are the host's metadata, not the writer's, so
    // what a caller supplied is replaced. A record's first version sets `createdAt` and
    // `createdBy`; every later one keeps what the first recorded — `None` included, for a
    // record stored before this host kept them, which stays unknown rather than guessed.
    // Every put stores a new author body, so `bodyStoredAt` is now.
    match &existing {
        Some(current) => {
            record.created_at = current.created_at;
            record.created_by = current.created_by.clone();
        }
        None => {
            record.created_at = Some(now);
            // The author it authenticated, where the tier discloses one — `None` on a
            // private room, which was refused above if it carried one.
            record.created_by = record.author.clone();
        }
    }
    record.body_stored_at = Some(now);
    record.version = room.next_version;
    record.updated_at = now;
    room.next_version += 1;
    room.updated_at = now;

    write_record(records, room_id, existing.as_ref(), &record).await?;
    rooms.insert(room_key(room_id), &room).await?;
    Ok(record)
}

/// Write `record` over `existing` (what its key held, if anything), with its index rows,
/// in one batch. The room must be indexed ([`index::ensure`]).
async fn write_record(
    records: &KeyspaceHandle,
    room_id: &str,
    existing: Option<&Record>,
    record: &Record,
) -> Result<(), AppError> {
    let mut batch = vti_common::store::Batch::new();
    batch.insert(record_key(room_id, &record.key), record)?;
    index::stage(&mut batch, room_id, existing, Some(record))?;
    index::apply(records, batch).await
}

/// Remove `existing` and its index rows, in one batch. The room must be indexed.
async fn remove_record(
    records: &KeyspaceHandle,
    room_id: &str,
    existing: &Record,
) -> Result<(), AppError> {
    let mut batch = vti_common::store::Batch::new();
    batch.remove(record_key(room_id, &existing.key));
    index::stage(&mut batch, room_id, Some(existing), None)?;
    index::apply(records, batch).await
}

/// Make the room's record indexes rebuild from its records on their next use.
///
/// For a host that wrote a record row directly through [`record_storage_key`] (a test
/// ageing a record, say): the indexes are kept in step by this module's writes, and a
/// row written around them leaves them describing the record it replaced.
pub async fn reindex_room(records: &KeyspaceHandle, room_id: &str) -> Result<(), AppError> {
    index::forget(records, room_id).await
}

/// Store a record **pulled from a primary**, exactly as the primary assigned it.
///
/// The mirror path, and it differs from [`put_record`] in the one way that
/// matters: the version is the primary's, not this host's. A mirror that
/// re-numbered what it copied would produce a room whose records disagree with
/// their own AEAD binding — every sealed record commits to
/// `roomId | key | version | epoch`, so a renumbered copy does not open — and
/// whose watermark means something different from the primary's, which is the
/// number every `sinceVersion` pull and every client's staleness check compares.
///
/// # What this deliberately does not check
///
/// The visibility/epoch shape checks `put_record` runs are the *primary's* job,
/// and were run there before the record was ever signed. Re-running them here
/// would mean a mirror refusing to copy a record its primary accepted — which
/// is a mirror silently diverging, the one failure mode a copy must not have.
/// What a mirror can still not do is forge: it holds ciphertext it cannot read
/// and signatures it cannot produce.
///
/// # Refusing to go backwards
///
/// A pulled version at or below the mirror's watermark is refused. Records only
/// ever gain versions, so a lower one means either a replayed pull or a primary
/// that has rolled back — and quietly accepting it would let a mirror serve a
/// fresh member an older room than the one it already had (R2‑5).
pub async fn store_mirrored_record(
    rooms: &KeyspaceHandle,
    records: &KeyspaceHandle,
    room_id: &str,
    record: Record,
    now: u64,
) -> Result<Record, AppError> {
    let mut room = get_room(rooms, room_id).await?;
    if !room.is_mirror() {
        // Writing a "mirrored" record into a room this host is the primary of
        // would put a version on the row that its own counter did not assign,
        // and the next local write would then collide with it.
        return Err(AppError::Validation(format!(
            "room `{room_id}` is primaried here; a mirrored record has no meaning on a primary"
        )));
    }
    if record.version <= room.watermark() && room.watermark() > 0 {
        return Err(AppError::Conflict(format!(
            "record `{}` arrived at version {}, at or below this mirror's watermark {};              a mirror does not go backwards",
            record.key,
            record.version,
            room.watermark()
        )));
    }

    // The mirror's watermark tracks the primary's numbering rather than counting
    // its own writes, so a gap in what it has pulled stays a gap it can see.
    room.next_version = record.version + 1;
    room.updated_at = now;

    index::ensure(records, room_id).await?;
    let existing = get_record(records, room_id, &record.key).await.ok();
    write_record(records, room_id, existing.as_ref(), &record).await?;
    rooms.insert(room_key(room_id), &room).await?;
    Ok(record)
}

/// Fetch one record.
pub async fn get_record(
    records: &KeyspaceHandle,
    room_id: &str,
    key: &str,
) -> Result<Record, AppError> {
    let raw = records
        .get_raw(record_key(room_id, key))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("record `{key}` not found in `{room_id}`")))?;
    serde_json::from_slice(&raw)
        .map_err(|e| AppError::Internal(format!("decode record `{key}`: {e}")))
}

/// Every room this host holds, for its operator.
///
/// # Why a host may enumerate what it cannot read
///
/// A room's *contents* and *membership* are withheld from a host by construction. What it
/// stores about the room itself — the owner, the tier, the epoch number, the lifecycle clock
/// — it stores precisely so it can be operated: quota, abuse, and the reclamation notice
/// §9 requires it to send. Invariant I1 makes the owner visible at **every** tier for this
/// reason, so an operator listing their rooms learns nothing the design withheld.
///
/// What this deliberately cannot return is a member list, because no host has one.
///
/// # Not paginated, and that is a decision with a shelf life
///
/// A host's room count is bounded by what its operator agreed to store, not by anything a
/// caller controls. If that stops being true this needs the cursor treatment
/// [`list_records`] already has — the shape to copy is there.
pub async fn list_rooms(rooms: &KeyspaceHandle) -> Result<Vec<Room>, AppError> {
    let pairs = rooms.prefix_iter_raw(ROOMS_PREFIX.to_string()).await?;
    let mut out = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        let room: Room = serde_json::from_slice(&v).map_err(|e| {
            let which = String::from_utf8_lossy(&k).to_string();
            AppError::Internal(format!("decode room at `{which}`: {e}"))
        })?;
        out.push(room);
    }
    out.sort_by(|a, b| a.room_id.cmp(&b.room_id));
    Ok(out)
}

/// List a room's records, optionally filtered by key prefix and a `since_version`
/// watermark.
///
/// **Tombstones are returned**, and that is not an oversight. A caller pulling by watermark
/// that never sees a retraction learns of every create and update and never of a delete, so
/// retracted records resurrect on its next full rebuild and disagree with peers that saw
/// the retraction. A retraction is a change like any other.
pub async fn list_records(
    records: &KeyspaceHandle,
    room_id: &str,
    key_prefix: Option<&str>,
    since_version: Option<u64>,
) -> Result<Vec<Record>, AppError> {
    let scan_prefix = match key_prefix {
        Some(p) => format!("{}{p}", record_prefix(room_id)),
        None => record_prefix(room_id),
    };
    let pairs = records.prefix_iter_raw(scan_prefix).await?;
    let mut out = Vec::with_capacity(pairs.len());
    for (_k, v) in pairs {
        let record: Record = serde_json::from_slice(&v)
            .map_err(|e| AppError::Internal(format!("decode record in `{room_id}`: {e}")))?;
        if let Some(since) = since_version
            && record.version <= since
        {
            continue;
        }
        out.push(record);
    }
    out.sort_by_key(|r| r.version);
    Ok(out)
}

/// The largest page a host will serve, however much a caller asks for.
///
/// A listing used to be unbounded: `limit` was applied with `take` and anything
/// beyond it was dropped **silently**, so a short page and a complete room were
/// the same bytes. That is worse than not paginating at all, because a caller
/// cannot tell the two apart and every client that "worked" was one that had
/// not yet met a big enough room.
///
/// The ceiling is the host's own, not the caller's: a response carrying an
/// entire room is a denial-of-service surface a host hands out for free.
pub const MAX_PAGE: usize = 500;

/// One page of a listing, and where the next one starts.
#[derive(Debug, Clone)]
pub struct Page {
    pub records: Vec<Record>,
    /// `Some` when more records remain. **Absence is the only end-of-listing
    /// signal** — a consumer MUST NOT infer exhaustion from a short page.
    pub cursor: Option<String>,
}

/// Which end of the room a listing starts from (`rooms/records/list/0.7` *Order*).
///
/// `OldestFirst` is ascending `version`, what every listing before 0.7 returns and what an
/// incremental sync reads in. `NewestFirst` is descending `version`: a reader opening a
/// conversation at its newest records reads the room's head first and pages backwards,
/// with `since_version` still a lower bound.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RecordOrder {
    #[default]
    OldestFirst,
    NewestFirst,
}

/// The cursor's shape: the order it continues in, and the version of the last record on
/// the page — `v<N>` (oldest first: continue *above* `N`) or `n<N>` (newest first:
/// continue *below* `N`).
///
/// # Why it is not authenticated, and does not need to be
///
/// `rooms/records/list/0.1` calls this an opaque token and says a host MUST NOT
/// accept one it did not issue, which reads as though it wants a signature. It
/// does not, and pretending otherwise would be security theatre with a key
/// nobody has: a cursor here expresses *start above version N* (or *below* it,
/// newest first), which is what `sinceVersion` — or a shorter listing — already
/// lets any caller ask for directly. A forged cursor can skip a caller's own
/// records and nothing else.
///
/// What the host does enforce is the **shape**, so a value from somewhere else is
/// refused rather than silently reinterpreted — and the **order**: a cursor read in the
/// direction it was not issued for would skip records or repeat them, and nothing on the
/// page would show which (`rooms/records/list/0.7` *Order* item 5).
fn encode_cursor(version: u64, order: RecordOrder) -> String {
    match order {
        RecordOrder::OldestFirst => format!("v{version}"),
        RecordOrder::NewestFirst => format!("n{version}"),
    }
}

/// Why a cursor is refused: it is not this host's shape, or it was issued under the other
/// order. Both are `rooms/records/list:invalidCursor` on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CursorError {
    /// Not a cursor this host issues.
    NotIssued(String),
    /// A cursor this host issued under the other [`RecordOrder`].
    OtherOrder(String),
}

impl std::fmt::Display for CursorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotIssued(c) => write!(
                f,
                "`{c}` is not a cursor this host issued; continue a listing with the \
                 `cursor` from its previous page, or start again without one"
            ),
            Self::OtherOrder(c) => write!(
                f,
                "cursor `{c}` was issued under the other `order`; continue a listing with \
                 the `order` it began with, or start again without a cursor"
            ),
        }
    }
}

impl std::error::Error for CursorError {}

impl From<CursorError> for AppError {
    fn from(e: CursorError) -> Self {
        AppError::Validation(e.to_string())
    }
}

/// The version a cursor continues from, if it is this host's and was issued under `order`.
pub fn decode_cursor(cursor: &str, order: RecordOrder) -> Result<u64, CursorError> {
    let (issued_under, rest) = if let Some(rest) = cursor.strip_prefix('v') {
        (RecordOrder::OldestFirst, rest)
    } else if let Some(rest) = cursor.strip_prefix('n') {
        (RecordOrder::NewestFirst, rest)
    } else {
        return Err(CursorError::NotIssued(cursor.to_string()));
    };
    // Digits only: `u64::from_str` would also take a leading `+`.
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CursorError::NotIssued(cursor.to_string()));
    }
    let version = rest
        .parse::<u64>()
        .map_err(|_| CursorError::NotIssued(cursor.to_string()))?;
    if issued_under != order {
        return Err(CursorError::OtherOrder(cursor.to_string()));
    }
    Ok(version)
}

/// One page of a room's records, oldest first, with an honest cursor: what every listing
/// before `rooms/records/list/0.7` serves. See [`list_records_page_in`].
pub async fn list_records_page(
    records: &KeyspaceHandle,
    room_id: &str,
    key_prefix: Option<&str>,
    since_version: Option<u64>,
    cursor: Option<&str>,
    limit: Option<usize>,
) -> Result<Page, AppError> {
    list_records_page_in(
        records,
        room_id,
        key_prefix,
        since_version,
        cursor,
        limit,
        RecordOrder::OldestFirst,
    )
    .await
}

/// One page of a room's records in `order`, with an honest cursor.
///
/// # The filters are the caller's to repeat
///
/// A cursor carries **position and direction, nothing else**. A caller that continues with
/// a different `prefix` or `since_version` gets that different query resumed from this
/// position, which is a coherent thing to ask for and almost never what anyone means.
/// Repeat the filters.
///
/// # Newest first
///
/// Rows in descending `version`, continuing downward page by page; `since_version` is still
/// a **lower** bound, so a newest-first catch-up ends at the reader's watermark; tombstones
/// are returned exactly as oldest first returns them (`rooms/records/list/0.7` *Order*
/// items 2–4).
///
/// # A seek, not a scan
///
/// Read through the room's version index (`index` module), which every write keeps in the
/// same batch as the record: a page reads the version rows it walks and the records it
/// returns, so a caller polling with `since_version` pays for what changed, not for the
/// room (#2595).
pub async fn list_records_page_in(
    records: &KeyspaceHandle,
    room_id: &str,
    key_prefix: Option<&str>,
    since_version: Option<u64>,
    cursor: Option<&str>,
    limit: Option<usize>,
    order: RecordOrder,
) -> Result<Page, AppError> {
    let position = cursor.map(|c| decode_cursor(c, order)).transpose()?;
    let page = limit.unwrap_or(MAX_PAGE).clamp(1, MAX_PAGE);
    let (above, below) = match order {
        // A cursor and a watermark say the same kind of thing, so the later of the two
        // wins rather than one silently overriding the other.
        RecordOrder::OldestFirst => (
            match position {
                Some(after) => Some(after.max(since_version.unwrap_or(0))),
                None => since_version,
            },
            None,
        ),
        // The watermark bounds the listing from below, the cursor from above.
        RecordOrder::NewestFirst => (since_version, position),
    };
    // One more than the page, to know whether another follows.
    let mut all = index::page(records, room_id, key_prefix, above, below, order, page + 1).await?;

    let more = all.len() > page;
    all.truncate(page);
    let cursor = more
        .then(|| all.last().map(|r| encode_cursor(r.version, order)))
        .flatten();
    Ok(Page {
        records: all,
        cursor,
    })
}

/// The room's data commitment — the root of its record tree — with its count and head
/// version.
///
/// Over **every** record the room holds, never the page being returned: a
/// page-scoped root is one a host satisfies by construction and could never
/// fail, which would let a member feel checked while checking nothing.
///
/// # Cached, and never stale
///
/// Kept beside the records (`index` module): every leaf hash is computed once, when its
/// record is written, and the head is cached in a row every write replaces with a stale
/// marker in the same batch. **A stale root is worse than a slow one** — it is a *wrong*
/// commitment, and the failure it produces is an honest host appearing to equivocate — so
/// a head is cached only over the marker it was computed after, and a write in between
/// leaves it uncached. The commitment is byte-for-byte [`crate::merkle::tree_head`] over
/// the records.
pub async fn tree_head(
    records: &KeyspaceHandle,
    room_id: &str,
) -> Result<crate::merkle::TreeHead, AppError> {
    Ok(index::head(records, room_id, None).await?.0)
}

/// The room's data commitment **and** the trace for one record, from one scan.
///
/// # Why they are computed together and not separately
///
/// A trace is a statement about the tree it was cut from, and a room moves. Two
/// calls — one for the root, one for the path — can straddle a write, and the
/// pair a host then serves is *individually* correct and *jointly* false: the
/// trace does not reach the root, the reader concludes the host is equivocating,
/// and the host has done nothing wrong. That is the worst available failure,
/// because it discredits the mechanism rather than the host.
///
/// The specification requires the same snapshot for both. One function is how
/// that requirement is held rather than remembered: both come from one read of the
/// room's leaf rows.
///
/// `None` for the trace means the key is not in the room, which a caller that
/// has just read the record can only see as a race with a retraction — the root
/// is still honest and is still returned, so the read answers with a
/// commitment and no path rather than failing.
pub async fn tree_head_with_trace(
    records: &KeyspaceHandle,
    room_id: &str,
    key: &str,
) -> Result<
    (
        crate::merkle::TreeHead,
        Option<crate::merkle::InclusionProof>,
    ),
    AppError,
> {
    index::head(records, room_id, Some(key)).await
}

/// What one curation changes.
///
/// A struct rather than three parameters because they are one *decision* — a curator
/// demoting and pinning in the same breath is making a single statement about a record, and
/// it lands as a single version for others to converge on.
#[derive(Debug, Clone, Default)]
pub struct Curation {
    /// The standing to move to. `None` leaves it alone.
    pub status: Option<RecordStatus>,
    /// Whether to pin. `None` leaves it alone.
    pub pinned: Option<bool>,
    /// Optional precondition: the record's current version.
    pub expected_version: Option<u64>,
}

/// Curate a record: change its standing without rewriting it.
///
/// The one entry point for `deprecated`, `retracted`, restoring a demotion, and pinning —
/// they are one operation because they are one *decision*, and because every one of them
/// has to assign a new version for the same reason (below).
///
/// # Retraction is a tombstone, not an erasure
///
/// The body goes; the key, version and epoch stay. Dropping the body is what a member
/// asking to retract wants. Keeping the rest is what makes incremental sync **converge** —
/// a caller synchronising on `since_version` learns about the retraction by seeing the
/// tombstone, and one that never saw it resurrects the record on its next full rebuild.
/// That is why [`list_records`] returns tombstones rather than filtering them.
///
/// Restoring a retracted record to `Active` is refused rather than reported as a success
/// that restored nothing: the body is already gone, and a status change cannot bring it
/// back. Hard removal is [`purge_record`], a separate and higher-trust act.
///
/// # Every curation assigns a new version
///
/// A demotion other members are expected to converge on is a change like any other, and one
/// that left the version alone would be invisible to every `since_version` watermark in the
/// room. This is the reason pinning is here too rather than being a cheap side-channel: a
/// pin nobody syncs is a pin only its author can see.
pub async fn curate_record(
    rooms: &KeyspaceHandle,
    records: &KeyspaceHandle,
    room_id: &str,
    key: &str,
    curation: Curation,
    now: u64,
) -> Result<Record, AppError> {
    let Curation {
        status,
        pinned,
        expected_version,
    } = curation;
    index::ensure(records, room_id).await?;
    let mut record = get_record(records, room_id, key).await?;
    let before = record.clone();

    if let Some(expected) = expected_version
        && record.version != expected
    {
        return Err(AppError::Conflict(format!(
            "record `{key}` is at version {}, not {expected}",
            record.version
        )));
    }

    if matches!(record.status, RecordStatus::Retracted)
        && matches!(status, Some(RecordStatus::Active))
    {
        return Err(AppError::Validation(format!(
            "record `{key}` is retracted; its body is gone and a status change cannot bring \
             it back"
        )));
    }

    let mut room = get_room(rooms, room_id).await?;

    if let Some(status) = status {
        record.status = status;
        // Only a retraction drops content. A demotion leaves the body exactly where it is —
        // `deprecated` means *demote in recall*, not *hide*, and an agent that could no
        // longer read a deprecated record could not explain why it ranked it lower.
        if matches!(status, RecordStatus::Retracted) {
            record.sealed = None;
            record.nonce = None;
            record.sealed_version = None;
            record.cleartext = None;
        }
    }
    if let Some(pinned) = pinned {
        record.pinned = pinned;
    }

    // A kept sealed body stays bound to the version it was sealed at, which `put_record`
    // recorded; a curation moves the record and leaves that alone. Where nothing was recorded
    // — a record stored before `sealed_version` existed — it is not inferred from the version
    // here: a host that predates the field may already have curated the record, so its
    // version need not be the one the body was sealed at. Unknown stays unknown, and readers
    // search for it.
    record.version = room.next_version;
    record.updated_at = now;
    room.next_version += 1;
    room.updated_at = now;

    write_record(records, room_id, Some(&before), &record).await?;
    rooms.insert(room_key(room_id), &room).await?;
    Ok(record)
}

/// Permanently remove a record, tombstone included.
///
/// The erasure path, separate from [`curate_record`] on purpose: a retraction keeps the
/// tombstone that makes sync converge, and removing it is a decision about retention rather
/// than about the record.
pub async fn purge_record(
    records: &KeyspaceHandle,
    room_id: &str,
    key: &str,
) -> Result<(), AppError> {
    index::ensure(records, room_id).await?;
    let existing = get_record(records, room_id, key).await?;
    remove_record(records, room_id, &existing).await
}

/// The records a prune of `kinds` at `now` would remove under `retention`
/// ([`crate::record_retention::is_eligible`]), tombstones included, by version.
///
/// The caller holds the record-write lock ([`crate::blobs::BlobHost::records_lock`]), so
/// the set it removes is the set decided here.
pub async fn eligible_records(
    records: &KeyspaceHandle,
    room_id: &str,
    retention: &crate::record_retention::RecordRetention,
    kinds: &[crate::record_retention::PruneKind],
    now: u64,
) -> Result<Vec<Record>, AppError> {
    Ok(list_records(records, room_id, None, None)
        .await?
        .into_iter()
        .filter(|r| crate::record_retention::is_eligible(r, retention, kinds, now))
        .collect())
}

/// Remove the records `keys` outright — key, version, status, body, tombstone — and leave
/// the room its mark: the next version from its counter, the time and the count
/// (`rooms/records/prune/0.1` item 5). `keys` must not be empty: a prune that removed
/// nothing takes no version and leaves no mark.
///
/// # Order, for a process that dies part-way
///
/// The room row — the version and the mark — is written **first**, then the records go. A
/// prune interrupted after the mark leaves records the mark already counted; they are
/// still eligible, and the next prune removes them under a mark of its own. The other order
/// would leave records gone with no mark, so an incremental reader could never learn they
/// went — the failure `lastPrune` exists to prevent. Nothing of a removed record is kept.
pub async fn remove_pruned(
    rooms: &KeyspaceHandle,
    records: &KeyspaceHandle,
    room_id: &str,
    keys: &[String],
    now: u64,
) -> Result<crate::record_retention::RecordPrune, AppError> {
    if keys.is_empty() {
        return Err(AppError::Internal(
            "a prune that removes nothing leaves no mark".into(),
        ));
    }
    let mut room = get_room(rooms, room_id).await?;
    let mark = crate::record_retention::RecordPrune {
        version: room.next_version,
        at: now,
        removed: keys.len() as u64,
    };
    room.next_version += 1;
    room.last_prune = Some(mark);
    room.updated_at = now;
    rooms.insert(room_key(room_id), &room).await?;
    index::ensure(records, room_id).await?;
    for key in keys {
        match get_record(records, room_id, key).await {
            Ok(existing) => remove_record(records, room_id, &existing).await?,
            // Gone already: a prune that died part-way, finished by this one.
            Err(AppError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(mark)
}

/// Replace the room's record retention whole (`rooms/records/retention/set/0.1` item 4);
/// `None` clears it. Returns the one it replaced. Removes nothing.
pub async fn set_record_retention(
    rooms: &KeyspaceHandle,
    room_id: &str,
    retention: Option<crate::record_retention::RecordRetention>,
    now: u64,
) -> Result<Option<crate::record_retention::RecordRetention>, AppError> {
    let mut room = get_room(rooms, room_id).await?;
    let previous = std::mem::replace(&mut room.record_retention, retention);
    room.updated_at = now;
    rooms.insert(room_key(room_id), &room).await?;
    Ok(previous)
}

/// Record the room's signal delay (`rooms/signal-delay/set/0.1` item 3). Returns the one it
/// replaced — `randomised` for a room that never set one. A request naming the setting in
/// force writes nothing (item 4).
pub async fn set_signal_delay(
    rooms: &KeyspaceHandle,
    room_id: &str,
    delay: crate::signal_delay::SignalDelay,
    now: u64,
) -> Result<crate::signal_delay::SignalDelay, AppError> {
    let mut room = get_room(rooms, room_id).await?;
    let previous = std::mem::replace(&mut room.signal_delay, delay);
    if previous != delay {
        room.updated_at = now;
        rooms.insert(room_key(room_id), &room).await?;
    }
    Ok(previous)
}

/// [`tree_head`], with `headVersion` taken as the higher of the highest record's version
/// and the room's latest prune (`HeadVersion`): a prune removes leaves and takes a version
/// like any other change to the tree, so a root before it and a root after it are never
/// labelled alike.
///
/// A snapshot only under the record-write lock: a prune writes the room's mark and removes
/// records under it, so a host computing a head for an answer holds it too
/// ([`crate::blobs::BlobHost::read_snapshot`]).
pub async fn room_tree_head(
    rooms: &KeyspaceHandle,
    records: &KeyspaceHandle,
    room_id: &str,
) -> Result<crate::merkle::TreeHead, AppError> {
    let mut head = tree_head(records, room_id).await?;
    head.head_version = head.head_version.max(pruned_at(rooms, room_id).await?);
    Ok(head)
}

/// [`tree_head_with_trace`], with `headVersion` as [`room_tree_head`] takes it.
pub async fn room_tree_head_with_trace(
    rooms: &KeyspaceHandle,
    records: &KeyspaceHandle,
    room_id: &str,
    key: &str,
) -> Result<
    (
        crate::merkle::TreeHead,
        Option<crate::merkle::InclusionProof>,
    ),
    AppError,
> {
    let (mut head, trace) = tree_head_with_trace(records, room_id, key).await?;
    head.head_version = head.head_version.max(pruned_at(rooms, room_id).await?);
    Ok((head, trace))
}

/// The version of the room's latest prune, `0` if it has none.
async fn pruned_at(rooms: &KeyspaceHandle, room_id: &str) -> Result<u64, AppError> {
    Ok(get_room(rooms, room_id)
        .await?
        .last_prune
        .map_or(0, |p| p.version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Visibility;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn open() -> (tempfile::TempDir, KeyspaceHandle, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let rooms = store.keyspace(crate::ROOMS_KEYSPACE).unwrap();
        let records = store.keyspace(crate::ROOM_RECORDS_KEYSPACE).unwrap();
        (dir, rooms, records)
    }

    async fn open_links() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let links = store.keyspace(crate::ROOM_EPOCH_LINKS_KEYSPACE).unwrap();
        (dir, links)
    }

    fn link(epoch: u32) -> EpochLink {
        EpochLink {
            epoch,
            wrapped: format!("d3JhcHBlZA{epoch}"),
            nonce: "bm9uY2U".into(),
        }
    }

    fn room(id: &str, visibility: Visibility) -> Room {
        Room {
            room_id: id.into(),
            owner_did: "did:key:zOwner".into(),
            visibility,
            retention_policy: crate::RetentionPolicy::Chained,
            anchor_cadence: Default::default(),
            epoch: 1,
            next_version: 1,
            retention_days: 90,
            epoch_expires_at: None,
            created_at: 0,
            updated_at: 0,
            mirror_of: None,
            record_retention: None,
            last_prune: None,
            signal_delay: Default::default(),
            epoch_floor: None,
            frozen_at: None,
        }
    }

    fn sealed_record(key: &str, epoch: u32) -> Record {
        Record {
            key: key.into(),
            version: 0,
            epoch: Some(epoch),
            status: RecordStatus::Active,
            pinned: false,
            sealed: Some("c2VhbGVk".into()),
            nonce: Some("bm9uY2U".into()),
            sealed_version: None,
            cleartext: None,
            author: None,
            updated_at: 0,
            created_at: None,
            created_by: None,
            body_stored_at: None,
        }
    }

    fn open_record(key: &str) -> Record {
        Record {
            key: key.into(),
            version: 0,
            epoch: None,
            status: RecordStatus::Active,
            pinned: false,
            sealed: None,
            nonce: None,
            sealed_version: None,
            cleartext: Some(serde_json::json!({ "body": "hello" })),
            author: Some("did:key:zBob".into()),
            updated_at: 0,
            created_at: None,
            created_by: None,
            body_stored_at: None,
        }
    }

    #[tokio::test]
    async fn a_room_cannot_be_registered_twice() {
        let (_d, rooms, _rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        let err = create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::Conflict(_)),
            "re-registering would reset the epoch and version counter: {err:?}"
        );
    }

    /// The property the commitment exists for, at the storage layer: a host that
    /// serves a listing missing a record commits to a different room than the
    /// one it holds. Without this the value is decoration.
    #[tokio::test]
    async fn a_missing_record_changes_the_rooms_commitment() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        for (i, key) in ["a", "b", "c"].iter().enumerate() {
            put_record(&rooms, &rec, "r1", open_record(key), None, i as u64 + 1)
                .await
                .unwrap();
        }

        let whole_room = tree_head(&rec, "r1").await.unwrap().root;

        // What a host serving two of the three records would be committing to.
        let mut short = list_records(&rec, "r1", None, None).await.unwrap();
        short.retain(|r| r.key != "b");
        let partial = crate::merkle::commit_records(&mut short).unwrap();

        assert_ne!(
            whole_room, partial,
            "dropping a record left the commitment unchanged"
        );
    }

    /// The commitment covers the room, not a query. A prefix or `sinceVersion`
    /// narrows what a caller *sees*; a root that narrowed with it would be one
    /// the host satisfies by construction.
    #[tokio::test]
    async fn the_commitment_ignores_the_filters_a_listing_applies() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        for (i, key) in ["alpha", "beta", "gamma"].iter().enumerate() {
            put_record(&rooms, &rec, "r1", open_record(key), None, i as u64 + 1)
                .await
                .unwrap();
        }

        let root = tree_head(&rec, "r1").await.unwrap().root;
        // A filtered listing returns fewer records; the room is unchanged, so
        // the commitment must be too.
        let filtered = list_records(&rec, "r1", Some("a"), None).await.unwrap();
        assert!(filtered.len() < 3, "the fixture must actually filter");
        assert_eq!(tree_head(&rec, "r1").await.unwrap().root, root);
    }

    /// A listing pages to its end, and the cursor is the only thing that says so.
    ///
    /// The defect this replaces was silent: `take(limit)` dropped the remainder
    /// without a word, so a short page and a complete room were the same bytes
    /// and every client that "worked" was one that had not met a big enough
    /// room yet.
    #[tokio::test]
    async fn a_listing_pages_to_its_end() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        for i in 0..7u64 {
            put_record(
                &rooms,
                &rec,
                "r1",
                open_record(&format!("k{i}")),
                None,
                i + 1,
            )
            .await
            .unwrap();
        }

        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0;
        loop {
            let page = list_records_page(&rec, "r1", None, None, cursor.as_deref(), Some(3))
                .await
                .unwrap();
            pages += 1;
            seen.extend(page.records.iter().map(|r| r.key.clone()));
            match page.cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
            assert!(pages < 10, "the listing never ended");
        }
        assert_eq!(pages, 3, "7 records at 3 a page is three pages");
        assert_eq!(seen.len(), 7, "every record was returned exactly once");
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 7, "a record was served on two pages");
    }

    /// The boundary that decides whether "short page means the end" is safe.
    ///
    /// With exactly a page's worth left there is no cursor — so a caller that
    /// inferred the end from a *full* page would ask for one more and a caller
    /// that inferred it from a *short* page would be right by luck. Only the
    /// cursor's absence is load-bearing.
    #[tokio::test]
    async fn an_exactly_full_last_page_carries_no_cursor() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        for i in 0..4u64 {
            put_record(
                &rooms,
                &rec,
                "r1",
                open_record(&format!("k{i}")),
                None,
                i + 1,
            )
            .await
            .unwrap();
        }

        let first = list_records_page(&rec, "r1", None, None, None, Some(2))
            .await
            .unwrap();
        assert_eq!(first.records.len(), 2);
        let cursor = first.cursor.expect("two of four remain");

        let second = list_records_page(&rec, "r1", None, None, Some(&cursor), Some(2))
            .await
            .unwrap();
        assert_eq!(second.records.len(), 2, "the last page is full");
        assert!(
            second.cursor.is_none(),
            "a full page with nothing after it must still say it is the end"
        );
    }

    /// A cursor from somewhere else is refused rather than reinterpreted.
    #[tokio::test]
    async fn a_cursor_this_host_did_not_issue_is_refused() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        assert!(
            list_records_page(&rec, "r1", None, None, Some("412"), None)
                .await
                .is_err(),
            "a bare number is not this host's cursor shape"
        );
        assert!(
            list_records_page(&rec, "r1", None, None, Some("vNaN"), None)
                .await
                .is_err()
        );
    }

    /// A host bounds its own response even when the caller asks for everything.
    #[tokio::test]
    async fn a_host_caps_the_page_it_will_serve() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        for i in 0..3u64 {
            put_record(
                &rooms,
                &rec,
                "r1",
                open_record(&format!("k{i}")),
                None,
                i + 1,
            )
            .await
            .unwrap();
        }
        // Asking for more than the ceiling gets the ceiling, not the ask.
        let page = list_records_page(&rec, "r1", None, None, None, Some(MAX_PAGE * 10))
            .await
            .unwrap();
        assert_eq!(page.records.len(), 3);
        assert!(page.cursor.is_none());
    }

    /// A room of `n` open records `k0`…`k{n-1}`, at versions 1…n.
    async fn room_of(n: u64) -> (tempfile::TempDir, KeyspaceHandle, KeyspaceHandle) {
        let (d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        for i in 0..n {
            put_record(
                &rooms,
                &rec,
                "r1",
                open_record(&format!("k{i}")),
                None,
                i + 1,
            )
            .await
            .unwrap();
        }
        (d, rooms, rec)
    }

    async fn newest(
        rec: &KeyspaceHandle,
        since: Option<u64>,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page, AppError> {
        list_records_page_in(
            rec,
            "r1",
            None,
            since,
            cursor,
            Some(limit),
            RecordOrder::NewestFirst,
        )
        .await
    }

    fn versions(page: &Page) -> Vec<u64> {
        page.records.iter().map(|r| r.version).collect()
    }

    /// `rooms/records/list/0.7` *Order* item 2: newest first is descending `version`, and
    /// each page its cursor leads to continues downward, so paging to the end reads the
    /// room from its head down — every record exactly once.
    #[tokio::test]
    async fn newest_first_pages_downward_from_the_head() {
        let (_d, _rooms, rec) = room_of(7).await;
        let first = newest(&rec, None, None, 3).await.unwrap();
        assert_eq!(versions(&first), [7, 6, 5]);
        let c1 = first.cursor.clone().expect("four remain");
        let second = newest(&rec, None, Some(&c1), 3).await.unwrap();
        assert_eq!(versions(&second), [4, 3, 2]);
        let c2 = second.cursor.clone().expect("one remains");
        let last = newest(&rec, None, Some(&c2), 3).await.unwrap();
        assert_eq!(versions(&last), [1]);
        assert!(last.cursor.is_none(), "the end of the listing says so");
    }

    /// Item 3: `sinceVersion` is a lower bound under either order, so a newest-first
    /// catch-up ends at the reader's watermark rather than at the room's first record.
    #[tokio::test]
    async fn newest_first_stops_at_the_watermark() {
        let (_d, _rooms, rec) = room_of(6).await;
        let first = newest(&rec, Some(3), None, 2).await.unwrap();
        assert_eq!(versions(&first), [6, 5]);
        let rest = newest(&rec, Some(3), first.cursor.as_deref(), 2)
            .await
            .unwrap();
        assert_eq!(versions(&rest), [4], "nothing at or below the watermark");
        assert!(rest.cursor.is_none());
    }

    /// Item 4: tombstones are returned newest first exactly as oldest first returns them —
    /// a retraction moves its record to the head.
    #[tokio::test]
    async fn newest_first_returns_tombstones() {
        let (_d, rooms, rec) = room_of(3).await;
        curate_record(
            &rooms,
            &rec,
            "r1",
            "k0",
            Curation {
                status: Some(RecordStatus::Retracted),
                pinned: None,
                expected_version: None,
            },
            10,
        )
        .await
        .unwrap();
        let page = newest(&rec, None, None, 10).await.unwrap();
        assert_eq!(
            page.records[0].key, "k0",
            "the retraction is the newest change"
        );
        assert_eq!(page.records[0].status, RecordStatus::Retracted);
        assert_eq!(page.records.len(), 3);
    }

    /// Item 5: a cursor belongs to the order it was issued under, and is refused under the
    /// other — read the other way it would skip records or repeat them.
    #[tokio::test]
    async fn a_cursor_is_refused_under_the_other_order() {
        let (_d, _rooms, rec) = room_of(4).await;
        let oldest = list_records_page(&rec, "r1", None, None, None, Some(2))
            .await
            .unwrap();
        let up = oldest.cursor.expect("two remain");
        assert_eq!(
            newest(&rec, None, Some(&up), 2)
                .await
                .unwrap_err()
                .to_string(),
            AppError::from(CursorError::OtherOrder(up.clone())).to_string()
        );
        let down = newest(&rec, None, None, 2).await.unwrap().cursor.unwrap();
        assert!(
            list_records_page(&rec, "r1", None, None, Some(&down), Some(2))
                .await
                .is_err(),
            "a newest-first cursor continues no oldest-first listing"
        );
        assert_eq!(
            decode_cursor(&down, RecordOrder::OldestFirst),
            Err(CursorError::OtherOrder(down.clone()))
        );
        for bad in ["412", "n", "n+4", "x4", "nNaN"] {
            assert_eq!(
                decode_cursor(bad, RecordOrder::NewestFirst),
                Err(CursorError::NotIssued(bad.into())),
                "{bad}"
            );
        }
    }

    /// *A room that moves while it is listed*: a record edited between two newest-first
    /// pages takes a version above the listing's first row, so the rest of the listing does
    /// not return it — and a reader that, having read to the end, takes the FIRST page's
    /// highest version as its watermark finds it on the next catch-up. A watermark from a
    /// later page would have skipped nothing here only by luck; from the first page it is
    /// guaranteed.
    #[tokio::test]
    async fn an_edit_while_paging_is_found_from_the_first_pages_watermark() {
        let (_d, rooms, rec) = room_of(6).await;
        let first = newest(&rec, None, None, 2).await.unwrap();
        assert_eq!(versions(&first), [6, 5]);
        let watermark = first.records[0].version;

        // `k1` (version 2), not yet listed, is edited: it moves to version 7.
        let mut edit = open_record("k1");
        edit.cleartext = Some(serde_json::json!({ "body": "edited" }));
        let edited = put_record(&rooms, &rec, "r1", edit, None, 20)
            .await
            .unwrap();
        assert_eq!(edited.version, 7);

        let mut seen: Vec<u64> = versions(&first);
        let mut cursor = first.cursor;
        while let Some(c) = cursor {
            let page = newest(&rec, None, Some(&c), 2).await.unwrap();
            seen.extend(versions(&page));
            cursor = page.cursor;
        }
        assert_eq!(
            seen,
            [6, 5, 4, 3, 1],
            "the moved record is not met again below"
        );

        let catch_up = newest(&rec, Some(watermark), None, 10).await.unwrap();
        assert_eq!(versions(&catch_up), [7]);
        assert_eq!(catch_up.records[0].key, "k1");
    }

    /// The order changes which rows a page carries, never what the room holds (item 6):
    /// a whole room read newest first is the room read oldest first, reversed.
    #[tokio::test]
    async fn both_orders_read_the_same_room() {
        let (_d, _rooms, rec) = room_of(5).await;
        let mut down = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = newest(&rec, None, cursor.as_deref(), 2).await.unwrap();
            down.extend(versions(&page));
            match page.cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        let up = list_records_page(&rec, "r1", None, None, None, None)
            .await
            .unwrap();
        let mut up = versions(&up);
        up.reverse();
        assert_eq!(down, up);
    }

    /// The head's three values describe one set, and they are read from it.
    ///
    /// `head_version` is deliberately **not** the room's `next_version - 1`,
    /// even though the two agree here. A counter is a second read, and a write
    /// landing between the two labels a root with a version from another
    /// moment — two honest members then hold roots over different trees under
    /// one version, which reads as equivocation and is not. This test pins the
    /// values; the doc on `merkle::TreeHead` pins the reason.
    #[tokio::test]
    async fn the_head_reports_the_set_it_committed_to() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        for (i, key) in ["a", "b", "c"].iter().enumerate() {
            put_record(&rooms, &rec, "r1", open_record(key), None, i as u64 + 1)
                .await
                .unwrap();
        }

        let head = tree_head(&rec, "r1").await.unwrap();
        assert_eq!(head.record_count, 3);
        assert_eq!(
            head.head_version,
            get_room(&rooms, "r1").await.unwrap().next_version - 1,
            "with no erasure the committed maximum is the room's last assigned version"
        );

        // A retraction is a mutation: it takes a version, keeps its tombstone,
        // and so moves the head without changing the count.
        curate_record(
            &rooms,
            &rec,
            "r1",
            "b",
            Curation {
                status: Some(RecordStatus::Retracted),
                ..Curation::default()
            },
            4,
        )
        .await
        .unwrap();
        let after = tree_head(&rec, "r1").await.unwrap();
        assert_eq!(after.record_count, 3, "a tombstone is still a record");
        assert!(
            after.head_version > head.head_version,
            "a retraction advances the head"
        );
        assert_ne!(after.root, head.root, "and it moves the root");
    }

    /// An empty room has an honest commitment rather than no commitment.
    #[tokio::test]
    async fn an_empty_room_commits_to_the_empty_root() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        assert_eq!(
            tree_head(&rec, "r1").await.unwrap().root,
            crate::merkle::empty_root()
        );
    }

    #[tokio::test]
    async fn versions_are_monotonic_across_records_in_a_room() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();

        let a = put_record(&rooms, &rec, "r1", open_record("a"), None, 1)
            .await
            .unwrap();
        let b = put_record(&rooms, &rec, "r1", open_record("b"), None, 2)
            .await
            .unwrap();
        let a2 = put_record(&rooms, &rec, "r1", open_record("a"), None, 3)
            .await
            .unwrap();

        assert_eq!((a.version, b.version, a2.version), (1, 2, 3));
        // One comparable number per room is what a `sinceVersion` watermark needs.
        assert!(
            a2.version > b.version,
            "rewriting `a` must advance past `b`"
        );
    }

    #[tokio::test]
    async fn a_version_precondition_reports_what_it_lost_to() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        put_record(&rooms, &rec, "r1", open_record("a"), None, 1)
            .await
            .unwrap();

        let err = put_record(&rooms, &rec, "r1", open_record("a"), Some(99), 2)
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("is at version 1"),
            "the conflict must carry the current version so a caller need not re-read: {msg}"
        );
    }

    #[tokio::test]
    async fn create_only_refuses_an_existing_key() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        put_record(&rooms, &rec, "r1", open_record("a"), Some(0), 1)
            .await
            .unwrap();
        let err = put_record(&rooms, &rec, "r1", open_record("a"), Some(0), 2)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)), "{err:?}");
    }

    /// The tier promise, enforced in the store rather than trusted to callers.
    #[tokio::test]
    async fn a_sealed_room_refuses_cleartext_and_an_open_room_refuses_ciphertext() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("sealed", Visibility::Attributed))
            .await
            .unwrap();
        create_room(&rooms, &room("plain", Visibility::Open))
            .await
            .unwrap();

        let err = put_record(&rooms, &rec, "sealed", open_record("a"), None, 1)
            .await
            .unwrap_err();
        assert!(
            format!("{err}").contains("cleartext must not be stored"),
            "{err}"
        );

        let err = put_record(&rooms, &rec, "plain", sealed_record("a", 1), None, 1)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("stores cleartext"), "{err}");
    }

    #[tokio::test]
    async fn a_private_room_refuses_a_recorded_author() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("p", Visibility::Private))
            .await
            .unwrap();
        let mut r = sealed_record("a", 1);
        r.author = Some("did:key:zBob".into());
        let err = put_record(&rooms, &rec, "p", r, None, 1).await.unwrap_err();
        assert!(
            format!("{err}").contains("inside the sealed body"),
            "on a private room the author must not reach this service: {err}"
        );
    }

    #[tokio::test]
    async fn a_record_sealed_under_a_stale_epoch_is_refused() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Attributed))
            .await
            .unwrap();
        advance_epoch(&rooms, "r1", 2, 10).await.unwrap();
        let err = put_record(&rooms, &rec, "r1", sealed_record("a", 1), None, 11)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("room `r1` is at 2"), "{err}");
    }

    /// The round trip §9 turns on: a room lapses, and the single operation its members
    /// were already going to perform brings it back. Nothing else moves the clock.
    #[tokio::test]
    async fn minting_an_epoch_renews_a_lapsed_room() {
        use crate::lifecycle::Lifecycle;
        let (_d, rooms, _rec) = open().await;

        let mut r = room("r1", Visibility::Open);
        r.epoch_expires_at = Some(1_000);
        create_room(&rooms, &r).await.expect("create");

        let now = 2_000;
        assert_eq!(
            get_room(&rooms, "r1").await.unwrap().lifecycle(now),
            Lifecycle::Lapsed,
            "expired an epoch ago"
        );

        let renewed = advance_epoch(&rooms, "r1", 2, now).await.expect("renew");
        assert_eq!(renewed.lifecycle(now), Lifecycle::Live);
        assert!(
            renewed.epoch_expires_at.expect("renewal sets an expiry") > now,
            "a renewal moves the clock forward, it does not merely clear it"
        );

        // And it is durable, not just returned.
        assert_eq!(
            get_room(&rooms, "r1").await.unwrap().lifecycle(now),
            Lifecycle::Live
        );
    }

    #[tokio::test]
    async fn an_epoch_must_advance_by_exactly_one() {
        let (_d, rooms, _rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Attributed))
            .await
            .unwrap();

        assert!(
            advance_epoch(&rooms, "r1", 3, 1).await.is_err(),
            "a gap is refused"
        );
        assert!(
            advance_epoch(&rooms, "r1", 1, 1).await.is_err(),
            "a repeat is refused"
        );
        assert_eq!(advance_epoch(&rooms, "r1", 2, 1).await.unwrap().epoch, 2);
    }

    #[tokio::test]
    async fn one_room_never_lists_anothers_records() {
        let (_d, rooms, rec) = open().await;
        // `a` is a string prefix of `ab` — the trailing `:` is what keeps them apart.
        create_room(&rooms, &room("a", Visibility::Open))
            .await
            .unwrap();
        create_room(&rooms, &room("ab", Visibility::Open))
            .await
            .unwrap();
        put_record(&rooms, &rec, "a", open_record("x"), None, 1)
            .await
            .unwrap();
        put_record(&rooms, &rec, "ab", open_record("y"), None, 2)
            .await
            .unwrap();

        let listed = list_records(&rec, "a", None, None).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key, "x");
    }

    /// Without this, deletions never propagate and retracted records resurrect.
    #[tokio::test]
    async fn a_watermark_listing_returns_tombstones() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        put_record(&rooms, &rec, "r1", open_record("a"), None, 1)
            .await
            .unwrap();
        let seen = put_record(&rooms, &rec, "r1", open_record("b"), None, 2)
            .await
            .unwrap()
            .version;

        let tomb = curate_record(
            &rooms,
            &rec,
            "r1",
            "a",
            Curation {
                status: Some(RecordStatus::Retracted),
                pinned: None,
                expected_version: None,
            },
            3,
        )
        .await
        .unwrap();
        assert!(
            tomb.sealed.is_none() && tomb.cleartext.is_none(),
            "body is dropped"
        );

        let changed = list_records(&rec, "r1", Some(""), Some(seen))
            .await
            .unwrap();
        assert_eq!(changed.len(), 1, "only what changed since the watermark");
        assert_eq!(changed[0].key, "a");
        assert!(
            matches!(changed[0].status, RecordStatus::Retracted),
            "the retraction must reach a puller, or the record resurrects"
        );
    }

    /// A demotion leaves the body where it is. `deprecated` means *demote in recall*, not
    /// *hide* — an agent that could no longer read a deprecated record could not explain
    /// why it ranked it lower.
    #[tokio::test]
    async fn deprecating_demotes_without_dropping_the_body() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        put_record(&rooms, &rec, "r1", open_record("a"), None, 1)
            .await
            .unwrap();

        let out = curate_record(
            &rooms,
            &rec,
            "r1",
            "a",
            Curation {
                status: Some(RecordStatus::Deprecated),
                pinned: None,
                expected_version: None,
            },
            2,
        )
        .await
        .unwrap();
        assert_eq!(out.status, RecordStatus::Deprecated);
        assert!(out.cleartext.is_some(), "a demotion keeps the body");
        assert_eq!(out.version, 2, "and assigns a new version to converge on");
    }

    /// The body is already gone. Reporting success would tell a member their record was
    /// restored when it was not.
    #[tokio::test]
    async fn a_retracted_record_cannot_be_restored() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        put_record(&rooms, &rec, "r1", open_record("a"), None, 1)
            .await
            .unwrap();
        curate_record(
            &rooms,
            &rec,
            "r1",
            "a",
            Curation {
                status: Some(RecordStatus::Retracted),
                pinned: None,
                expected_version: None,
            },
            2,
        )
        .await
        .unwrap();

        let err = curate_record(
            &rooms,
            &rec,
            "r1",
            "a",
            Curation {
                status: Some(RecordStatus::Active),
                pinned: None,
                expected_version: None,
            },
            3,
        )
        .await
        .unwrap_err();
        assert!(format!("{err}").contains("cannot bring it back"), "{err}");
    }

    /// Pinning is orthogonal to status — a room may want its superseded canonical decision
    /// kept in view.
    #[tokio::test]
    async fn a_record_can_be_pinned_and_deprecated_at_once() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        put_record(&rooms, &rec, "r1", open_record("a"), None, 1)
            .await
            .unwrap();

        let out = curate_record(
            &rooms,
            &rec,
            "r1",
            "a",
            Curation {
                status: Some(RecordStatus::Deprecated),
                pinned: Some(true),
                expected_version: None,
            },
            2,
        )
        .await
        .unwrap();
        assert!(out.pinned);
        assert_eq!(out.status, RecordStatus::Deprecated);
    }

    /// A curator who read a record before deciding to demote it can require that nothing
    /// replaced it in between.
    #[tokio::test]
    async fn curation_honours_a_version_precondition() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        put_record(&rooms, &rec, "r1", open_record("a"), None, 1)
            .await
            .unwrap();

        let err = curate_record(
            &rooms,
            &rec,
            "r1",
            "a",
            Curation {
                status: Some(RecordStatus::Deprecated),
                pinned: None,
                expected_version: Some(99),
            },
            2,
        )
        .await
        .unwrap_err();
        assert!(format!("{err}").contains("is at version 1"), "{err}");
    }

    fn curation(status: Option<RecordStatus>, pinned: Option<bool>) -> Curation {
        Curation {
            status,
            pinned,
            expected_version: None,
        }
    }

    /// rooms `_shared/0.1` `SealedRecord.version`, curate/0.1 *Curation assigns a new
    /// version*: a curation moves the record and keeps its body, and the body stays bound
    /// to the version it was sealed at — so that version is recorded when the body is
    /// stored, and served from the first curation on. Every curation after it moves the
    /// record again and the body with it stays where it was sealed.
    #[tokio::test]
    async fn curating_a_sealed_record_keeps_the_version_its_body_was_sealed_at() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Private))
            .await
            .unwrap();
        let put = put_record(&rooms, &rec, "r1", sealed_record("a", 1), None, 1)
            .await
            .unwrap();
        assert_eq!(put.version, 1);
        assert_eq!(
            put.sealed_version,
            Some(1),
            "recorded when the body is stored"
        );
        assert_eq!(
            put.committed().sealed.unwrap().version,
            None,
            "nothing changes shape until a curation needs it"
        );

        let archived = curate_record(
            &rooms,
            &rec,
            "r1",
            "a",
            curation(Some(RecordStatus::Deprecated), None),
            2,
        )
        .await
        .unwrap();
        assert_eq!(archived.version, 2);
        assert_eq!(archived.sealed_version, Some(1));
        assert_eq!(archived.committed().sealed.unwrap().version, Some(1));

        let pinned = curate_record(&rooms, &rec, "r1", "a", curation(None, Some(true)), 3)
            .await
            .unwrap();
        let restored = curate_record(
            &rooms,
            &rec,
            "r1",
            "a",
            curation(Some(RecordStatus::Active), None),
            4,
        )
        .await
        .unwrap();
        assert_eq!((pinned.version, pinned.sealed_version), (3, Some(1)));
        assert_eq!((restored.version, restored.sealed_version), (4, Some(1)));
        assert_eq!(
            get_record(&rec, "r1", "a").await.unwrap().sealed_version,
            Some(1),
            "it is stored, not derived"
        );
    }

    /// A new body is sealed for the version it takes, so an earlier body's sealed-at
    /// version is replaced by that one; a retraction drops the body and has nothing to keep.
    #[tokio::test]
    async fn a_new_body_replaces_the_sealed_at_version_and_a_retraction_clears_it() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Private))
            .await
            .unwrap();
        put_record(&rooms, &rec, "r1", sealed_record("a", 1), None, 1)
            .await
            .unwrap();
        put_record(&rooms, &rec, "r1", sealed_record("b", 1), None, 1)
            .await
            .unwrap();
        for key in ["a", "b"] {
            curate_record(
                &rooms,
                &rec,
                "r1",
                key,
                curation(Some(RecordStatus::Deprecated), None),
                2,
            )
            .await
            .unwrap();
        }

        let rewritten = put_record(&rooms, &rec, "r1", sealed_record("a", 1), Some(3), 5)
            .await
            .unwrap();
        assert_eq!(rewritten.sealed_version, Some(rewritten.version));
        assert_eq!(rewritten.committed().sealed.unwrap().version, None);

        let retracted = curate_record(
            &rooms,
            &rec,
            "r1",
            "b",
            curation(Some(RecordStatus::Retracted), None),
            6,
        )
        .await
        .unwrap();
        assert_eq!(retracted.sealed_version, None);
        assert!(retracted.committed().sealed.is_none());
    }

    /// A record stored before `sealed_version` existed carries none, and a host that
    /// predates it may already have curated it — so its version is not evidence of where the
    /// body was sealed. A curation must leave it unknown, never stamp the version it finds:
    /// stamped, a record archived by the old host and restored by this one was served with a
    /// `sealed.version` it was never sealed at, and opened for nobody.
    #[tokio::test]
    async fn a_curation_does_not_guess_the_sealed_at_version_of_an_older_record() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Private))
            .await
            .unwrap();
        put_record(&rooms, &rec, "r1", sealed_record("a", 1), None, 1)
            .await
            .unwrap();
        // As an older host left it: sealed at 1, archived to 2, nothing recorded.
        let mut legacy = get_record(&rec, "r1", "a").await.unwrap();
        legacy.sealed_version = None;
        legacy.status = RecordStatus::Deprecated;
        legacy.version = 2;
        rec.insert(record_key("r1", "a"), &legacy).await.unwrap();
        let mut r = get_room(&rooms, "r1").await.unwrap();
        r.next_version = 3;
        rooms.insert(room_key("r1"), &r).await.unwrap();

        let restored = curate_record(
            &rooms,
            &rec,
            "r1",
            "a",
            curation(Some(RecordStatus::Active), None),
            3,
        )
        .await
        .unwrap();
        assert_eq!(restored.version, 3);
        assert_eq!(
            restored.sealed_version, None,
            "not 2, which it was never sealed at"
        );
        assert_eq!(
            restored.committed().sealed.unwrap().version,
            None,
            "served without one, so readers search earlier versions"
        );
    }

    /// An open room's record has no sealed body, so a curation has nothing to bind.
    #[tokio::test]
    async fn curating_an_open_record_records_no_sealed_at_version() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        put_record(&rooms, &rec, "r1", open_record("a"), None, 1)
            .await
            .unwrap();
        let archived = curate_record(
            &rooms,
            &rec,
            "r1",
            "a",
            curation(Some(RecordStatus::Deprecated), None),
            2,
        )
        .await
        .unwrap();
        assert_eq!(archived.sealed_version, None);
    }

    #[tokio::test]
    async fn purge_removes_the_tombstone_and_is_not_idempotent() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        put_record(&rooms, &rec, "r1", open_record("a"), None, 1)
            .await
            .unwrap();
        curate_record(
            &rooms,
            &rec,
            "r1",
            "a",
            Curation {
                status: Some(RecordStatus::Retracted),
                pinned: None,
                expected_version: None,
            },
            2,
        )
        .await
        .unwrap();

        purge_record(&rec, "r1", "a").await.unwrap();
        assert!(
            list_records(&rec, "r1", None, None)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            purge_record(&rec, "r1", "a").await.is_err(),
            "purging an absent record reports not-found rather than succeeding quietly"
        );
    }

    /// The owner is who a host addresses about quota, abuse and lifecycle. A transfer to
    /// something that is not an identifier produces a room nobody can be reached about —
    /// and the party who could correct it is exactly the one the bad value replaced.
    #[tokio::test]
    async fn an_owner_must_be_a_did() {
        let (_d, rooms, _records) = open().await;
        create_room(&rooms, &room("did:key:zRoom", Visibility::Open))
            .await
            .expect("a real DID");

        for bad in ["", "alice@example.com", "did:key:z Alice", "not-a-did"] {
            set_owner(&rooms, "did:key:zRoom", bad, 1)
                .await
                .unwrap_err();
        }

        assert_eq!(
            get_room(&rooms, "did:key:zRoom").await.unwrap().owner_did,
            "did:key:zOwner",
            "and a refused transfer left the room where it was"
        );

        let moved = set_owner(&rooms, "did:key:zRoom", "did:key:zBob", 99)
            .await
            .expect("a real DID");
        assert_eq!(moved.owner_did, "did:key:zBob");
        assert_eq!(moved.updated_at, 99);
    }

    // ── read mirrors (§7.3) ─────────────────────────────────────────────────

    /// A mirror room, primaried elsewhere.
    fn mirror(id: &str, visibility: Visibility) -> Room {
        Room {
            mirror_of: Some("https://primary.example.org".into()),
            record_retention: None,
            last_prune: None,
            signal_delay: Default::default(),
            epoch_floor: None,
            frozen_at: None,
            ..room(id, visibility)
        }
    }

    /// The property that makes a copy usable: the primary's numbering survives.
    /// A mirror that renumbered would break every sealed record's AEAD binding
    /// and give its watermark a different meaning from the one clients compare.
    #[tokio::test]
    async fn a_mirrored_record_keeps_the_primarys_version() {
        let (_d, rooms, records) = open().await;
        create_room(&rooms, &mirror("r1", Visibility::Open))
            .await
            .unwrap();

        let mut pulled = open_record("k1");
        pulled.version = 42; // assigned by the primary, not by this host
        let stored = store_mirrored_record(&rooms, &records, "r1", pulled, 10)
            .await
            .expect("a mirror stores what its primary assigned");
        assert_eq!(stored.version, 42, "the primary's number, verbatim");

        // …and the watermark tracks the primary rather than counting local writes,
        // so the next pull resumes from the right place.
        let room = get_room(&rooms, "r1").await.unwrap();
        assert_eq!(room.watermark(), 42);
        assert_eq!(room.next_version, 43);
    }

    /// R2-5: records only gain versions, so a lower one means a replayed pull or
    /// a rolled-back primary. Accepting it would let the mirror serve a fresh
    /// member an older room than the one it already had.
    #[tokio::test]
    async fn a_mirror_does_not_go_backwards() {
        let (_d, rooms, records) = open().await;
        create_room(&rooms, &mirror("r1", Visibility::Open))
            .await
            .unwrap();

        let mut first = open_record("k1");
        first.version = 42;
        store_mirrored_record(&rooms, &records, "r1", first, 10)
            .await
            .unwrap();

        let mut replayed = open_record("k2");
        replayed.version = 41;
        let err = store_mirrored_record(&rooms, &records, "r1", replayed, 11)
            .await
            .expect_err("a version at or below the watermark is refused");
        assert!(
            matches!(err, AppError::Conflict(ref m) if m.contains("backwards")),
            "got {err:?}"
        );
    }

    /// A "mirrored" record on a primary would carry a version its own counter
    /// never assigned, and the next local write would collide with it.
    #[tokio::test]
    async fn a_primary_refuses_a_mirrored_record() {
        let (_d, rooms, records) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();

        let mut pulled = open_record("k1");
        pulled.version = 42;
        let err = store_mirrored_record(&rooms, &records, "r1", pulled, 10)
            .await
            .expect_err("this host is the primary");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    /// A mirror copies what its primary accepted, including shapes this host
    /// would refuse to originate. Re-running the primary's validation here is
    /// how a copy silently diverges from the room it is copying.
    #[tokio::test]
    async fn a_mirror_copies_a_record_sealed_under_another_epoch() {
        let (_d, rooms, records) = open().await;
        create_room(&rooms, &mirror("r1", Visibility::Attributed))
            .await
            .unwrap();

        // The room row says epoch 1; the record was sealed under 7 at the
        // primary. `put_record` would refuse this. A mirror must not.
        let mut pulled = sealed_record("k1", 7);
        pulled.version = 3;
        store_mirrored_record(&rooms, &records, "r1", pulled, 10)
            .await
            .expect("a mirror stores what the primary sealed");
    }

    // ─── Epoch links ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn links_round_trip_in_epoch_order() {
        let (_d, links) = open_links().await;
        // Inserted out of order: the chain must be walked in order regardless.
        for e in [4u32, 2, 3] {
            put_epoch_link(&links, "r1", &link(e)).await.expect("put");
        }

        let got = list_epoch_links(&links, "r1").await.expect("list");
        assert_eq!(
            got.iter().map(|l| l.epoch).collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
    }

    /// A second link for one epoch is a replay or a re-pointing of the room's history,
    /// and the members who already walked the original would never see the difference.
    #[tokio::test]
    async fn a_link_cannot_be_replaced() {
        let (_d, links) = open_links().await;
        put_epoch_link(&links, "r1", &link(2)).await.expect("put");

        let err = put_epoch_link(&links, "r1", &link(2)).await.unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn the_first_epoch_has_no_link() {
        let (_d, links) = open_links().await;
        for e in [0u32, 1] {
            assert!(matches!(
                put_epoch_link(&links, "r1", &link(e)).await.unwrap_err(),
                AppError::Validation(_)
            ));
        }
    }

    /// One room's chain is never another's — the same guard the record prefix has.
    #[tokio::test]
    async fn a_scan_is_room_exact() {
        let (_d, links) = open_links().await;
        put_epoch_link(&links, "a", &link(2)).await.expect("put");
        put_epoch_link(&links, "ab", &link(3)).await.expect("put");

        let got = list_epoch_links(&links, "a").await.expect("list");
        assert_eq!(got.len(), 1, "`a` must not pick up `ab`'s chain");
        assert_eq!(got[0].epoch, 2);
    }

    #[tokio::test]
    async fn pruning_severs_at_and_below_the_named_epoch() {
        let (_d, links) = open_links().await;
        for e in 2..=5u32 {
            put_epoch_link(&links, "r1", &link(e)).await.expect("put");
        }

        let dropped = prune_epoch_links_before(&links, "r1", 3)
            .await
            .expect("prune");
        assert_eq!(dropped, 2, "links 2 and 3");

        let left = list_epoch_links(&links, "r1").await.expect("list");
        assert_eq!(left.iter().map(|l| l.epoch).collect::<Vec<_>>(), vec![4, 5]);
    }

    /// Pruning what is already gone is not an error — a retry of a severance must not
    /// look like a failure, and there is nothing to be idempotent *about*: the bytes are
    /// gone either way.
    #[tokio::test]
    async fn pruning_is_idempotent() {
        let (_d, links) = open_links().await;
        put_epoch_link(&links, "r1", &link(2)).await.expect("put");

        assert_eq!(
            prune_epoch_links_before(&links, "r1", 2)
                .await
                .expect("first"),
            1
        );
        assert_eq!(
            prune_epoch_links_before(&links, "r1", 2)
                .await
                .expect("again"),
            0
        );
    }

    /// A pruned rung cannot be restored by writing it back: the guard that refuses a
    /// replacement is what makes severance mean severed.
    #[tokio::test]
    async fn a_pruned_link_is_gone_and_the_epoch_is_still_spent() {
        let (_d, links) = open_links().await;
        put_epoch_link(&links, "r1", &link(2)).await.expect("put");
        prune_epoch_links_before(&links, "r1", 2)
            .await
            .expect("prune");

        // The row is gone, so a write succeeds — but it can only carry key material the
        // writer can still produce, and the epoch key it wrapped is what was destroyed.
        // Nothing here can resurrect a key; this asserts only that the store is honest
        // about what it holds.
        assert!(
            list_epoch_links(&links, "r1")
                .await
                .expect("list")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn listing_rooms_returns_every_room_in_identifier_order() {
        let (_d, rooms, _r) = open().await;
        for id in ["r3", "r1", "r2"] {
            create_room(&rooms, &room(id, Visibility::Attributed))
                .await
                .expect("create");
        }

        let got = list_rooms(&rooms).await.expect("list");
        assert_eq!(
            got.iter().map(|r| r.room_id.as_str()).collect::<Vec<_>>(),
            vec!["r1", "r2", "r3"],
            "an operator's list is stable, or two reads disagree about nothing"
        );
    }

    /// The scan is prefix-bound to the rooms keyspace, so nothing else it may share a
    /// store with can appear in an operator's room list.
    #[tokio::test]
    async fn listing_rooms_is_empty_on_a_host_that_holds_none() {
        let (_d, rooms, _r) = open().await;
        assert!(list_rooms(&rooms).await.expect("list").is_empty());
    }
}

#[cfg(test)]
mod relay_and_prune_tests {
    use super::*;
    use crate::wire::EpochLink;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    const ROOM: &str = "r1";

    async fn open2() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("rooms").unwrap();
        (dir, ks)
    }

    fn link(epoch: u32) -> EpochLink {
        EpochLink {
            epoch,
            wrapped: "d3JhcHBlZA".into(),
            nonce: "bm9uY2U".into(),
        }
    }

    /// The boundary. `before_epoch` means *below*, so the epoch named survives —
    /// off by one here silently takes the rung the caller meant to keep.
    #[tokio::test]
    async fn pruning_below_an_epoch_keeps_that_epoch() {
        let (_d, ks) = open2().await;
        // From 2: a rung wraps the PREVIOUS epoch's key, so epoch 1 has no
        // predecessor to link to and `put_epoch_link` refuses one. The chain
        // ending at 2 is what a room that has always been chained looks like.
        for e in 2..=5 {
            put_epoch_link(&ks, ROOM, &link(e)).await.unwrap();
        }
        let (pruned, earliest) = prune_chain(&ks, ROOM, 4).await.unwrap();
        assert_eq!(pruned, 2, "epochs 2 and 3 go");
        assert_eq!(earliest, 4, "and 4 is what the caller asked to keep");
    }

    /// `earliest_rung` is read from what survives, not from the request — a
    /// chain with a gap already stopped somewhere, and echoing the request would
    /// tell an operator they had achieved something they had not.
    #[tokio::test]
    async fn a_prune_below_an_existing_gap_reports_the_gap() {
        let (_d, ks) = open2().await;
        // 2, 3, then nothing until 7: a delivery that never happened.
        for e in [2u32, 3, 7, 8] {
            put_epoch_link(&ks, ROOM, &link(e)).await.unwrap();
        }
        let (pruned, earliest) = prune_chain(&ks, ROOM, 4).await.unwrap();
        assert_eq!(pruned, 2);
        assert_eq!(
            earliest, 7,
            "reach is 7 whatever the request said, because the chain already stopped there"
        );
    }

    /// Nothing to do is a success, not a failure to retry.
    #[tokio::test]
    async fn pruning_a_chain_that_is_already_short_is_a_success() {
        let (_d, ks) = open2().await;
        put_epoch_link(&ks, ROOM, &link(9)).await.unwrap();
        let (pruned, earliest) = prune_chain(&ks, ROOM, 5).await.unwrap();
        assert_eq!(pruned, 0);
        assert_eq!(earliest, 9);
    }

    /// A commit is published once. The first is the one members may already have
    /// applied, and a second would fork the group the relay exists to hold
    /// together.
    #[tokio::test]
    async fn a_commit_is_never_replaced() {
        let (_d, ks) = open2().await;
        put_commit(&ks, ROOM, 3, "AAEC").await.unwrap();
        assert!(
            put_commit(&ks, ROOM, 3, "ZZZZ").await.is_err(),
            "replacing a published commit must be refused"
        );
    }

    /// The rule that keeps a catching-up member from being handed something the
    /// group will reject: stop at the gap rather than skipping it.
    #[tokio::test]
    async fn the_relay_stops_at_a_gap_rather_than_skipping_it() {
        let (_d, ks) = open2().await;
        for e in [4u32, 5, 7] {
            put_commit(&ks, ROOM, e, "AAEC").await.unwrap();
        }
        let served = commits_since(&ks, ROOM, 3, 100).await.unwrap();
        assert_eq!(
            served.iter().map(|c| c.epoch).collect::<Vec<_>>(),
            vec![4, 5],
            "7 is past a gap at 6, and serving it would produce a commit the group rejects"
        );
    }

    /// Ordered and bounded, and a member asks again from where they reached.
    #[tokio::test]
    async fn the_relay_serves_in_order_and_honours_the_page() {
        let (_d, ks) = open2().await;
        for e in 1..=6u32 {
            put_commit(&ks, ROOM, e, "AAEC").await.unwrap();
        }
        let first = commits_since(&ks, ROOM, 0, 3).await.unwrap();
        assert_eq!(
            first.iter().map(|c| c.epoch).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        let next = commits_since(&ks, ROOM, 3, 3).await.unwrap();
        assert_eq!(
            next.iter().map(|c| c.epoch).collect::<Vec<_>>(),
            vec![4, 5, 6]
        );
    }
}

#[cfg(test)]
mod purge_and_freeze_tests {
    use super::*;
    use crate::Visibility;
    use crate::wire::EpochLink;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    /// A room, and one whose identifier extends it. Under the earlier key layout the scan
    /// prefix of the first (`…did:web:a:`) also covered the second's rows, and the first's
    /// record `b:k` was the second's record `k` (#2382).
    const ROOM: &str = "did:web:a";
    const LONGER: &str = "did:web:a:b";

    struct Ks {
        _dir: tempfile::TempDir,
        rooms: KeyspaceHandle,
        records: KeyspaceHandle,
        links: KeyspaceHandle,
        revs: KeyspaceHandle,
    }

    fn open() -> Ks {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        Ks {
            rooms: store.keyspace(crate::ROOMS_KEYSPACE).unwrap(),
            records: store.keyspace(crate::ROOM_RECORDS_KEYSPACE).unwrap(),
            links: store.keyspace(crate::ROOM_EPOCH_LINKS_KEYSPACE).unwrap(),
            revs: store.keyspace(crate::ROOM_REVOCATIONS_KEYSPACE).unwrap(),
            _dir: dir,
        }
    }

    fn room(id: &str) -> Room {
        Room {
            room_id: id.into(),
            owner_did: "did:key:zOwner".into(),
            visibility: Visibility::Open,
            retention_policy: crate::RetentionPolicy::Chained,
            anchor_cadence: Default::default(),
            epoch: 1,
            next_version: 1,
            retention_days: 90,
            epoch_expires_at: None,
            created_at: 0,
            updated_at: 5,
            mirror_of: None,
            record_retention: None,
            last_prune: None,
            signal_delay: Default::default(),
            epoch_floor: None,
            frozen_at: None,
        }
    }

    fn record(key: &str) -> Record {
        Record {
            key: key.into(),
            version: 0,
            epoch: None,
            status: RecordStatus::Active,
            pinned: false,
            sealed: None,
            nonce: None,
            sealed_version: None,
            cleartext: Some(serde_json::json!({ "body": "hello" })),
            author: Some("did:key:zBob".into()),
            updated_at: 0,
            created_at: None,
            created_by: None,
            body_stored_at: None,
        }
    }

    async fn populate(ks: &Ks, id: &str) {
        create_room(&ks.rooms, &room(id)).await.unwrap();
        for (i, key) in ["k1", "k2", "b:k3"].iter().enumerate() {
            put_record(&ks.rooms, &ks.records, id, record(key), None, i as u64 + 1)
                .await
                .unwrap();
        }
        for e in 2..=3 {
            let link = EpochLink {
                epoch: e,
                wrapped: "d3JhcHBlZA".into(),
                nonce: "bm9uY2U".into(),
            };
            put_epoch_link(&ks.links, id, &link).await.unwrap();
            put_commit(&ks.links, id, e, "Y29tbWl0").await.unwrap();
        }
        ks.revs
            .insert_raw(
                format!("{}{id}", crate::revocation::REVOCATIONS_PREFIX),
                b"{}".to_vec(),
            )
            .await
            .unwrap();
    }

    async fn purge(ks: &Ks, id: &str) -> PurgedRows {
        purge_room_rows(&ks.rooms, &ks.records, &ks.links, &ks.revs, id)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_purge_removes_every_row_of_the_room_and_none_of_a_longer_ids() {
        let ks = open();
        populate(&ks, ROOM).await;
        populate(&ks, LONGER).await;

        let out = purge(&ks, ROOM).await;
        assert_eq!(
            out,
            PurgedRows {
                records: 3,
                epoch_links: 2,
                commits: 2,
                revocations: true,
                room: true,
            }
        );
        assert!(matches!(
            get_room(&ks.rooms, ROOM).await,
            Err(AppError::NotFound(_))
        ));
        // By key: a listing of `did:web:a` scans `…did:web:a:` and so would show the
        // longer room's rows, which is the point of keeping them.
        for k in ["k1", "k2", "b:k3"] {
            assert!(get_record(&ks.records, ROOM, k).await.is_err(), "{k}");
        }
        for e in 2..=3u32 {
            assert!(
                ks.links
                    .get_raw(epoch_link_key(ROOM, e))
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                ks.links
                    .get_raw(commit_key(ROOM, e))
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            ks.revs
                .get_raw(format!("{}{ROOM}", crate::revocation::REVOCATIONS_PREFIX))
                .await
                .unwrap()
                .is_none()
        );

        // The room whose identifier extends it keeps everything.
        get_room(&ks.rooms, LONGER).await.unwrap();
        for k in ["k1", "k2", "b:k3"] {
            get_record(&ks.records, LONGER, k).await.unwrap();
        }
        for e in 2..=3u32 {
            assert!(
                ks.links
                    .get_raw(epoch_link_key(LONGER, e))
                    .await
                    .unwrap()
                    .is_some()
            );
            assert!(
                ks.links
                    .get_raw(commit_key(LONGER, e))
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        assert!(
            ks.revs
                .get_raw(format!("{}{LONGER}", crate::revocation::REVOCATIONS_PREFIX))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_purge_is_idempotent_and_resumes_after_an_interruption() {
        let ks = open();
        populate(&ks, ROOM).await;
        // Interrupted after the records went: the room row is still there to name it.
        for r in list_records(&ks.records, ROOM, None, None).await.unwrap() {
            purge_record(&ks.records, ROOM, &r.key).await.unwrap();
        }
        let out = purge(&ks, ROOM).await;
        assert_eq!(out.records, 0);
        assert!(out.room && out.revocations && out.epoch_links == 2);

        assert_eq!(purge(&ks, ROOM).await, PurgedRows::default());
        assert_eq!(purge(&ks, "did:web:never").await, PurgedRows::default());
    }

    #[tokio::test]
    async fn freezing_and_thawing_a_room_round_trips_and_bumps_updated_at() {
        let ks = open();
        create_room(&ks.rooms, &room(ROOM)).await.unwrap();

        set_frozen(&ks.rooms, ROOM, Some(1_000)).await.unwrap();
        let frozen = get_room(&ks.rooms, ROOM).await.unwrap();
        assert_eq!(frozen.frozen_at, Some(1_000));
        assert!(frozen.is_frozen());
        assert_eq!(frozen.updated_at, 1_000);

        set_frozen(&ks.rooms, ROOM, None).await.unwrap();
        let thawed = get_room(&ks.rooms, ROOM).await.unwrap();
        assert_eq!(thawed.frozen_at, None);
        assert!(thawed.updated_at >= 1_000);

        assert!(matches!(
            set_frozen(&ks.rooms, "did:web:never", Some(1)).await,
            Err(AppError::NotFound(_))
        ));
    }

    fn body(r: &Record) -> serde_json::Value {
        r.cleartext.clone().unwrap()["body"].clone()
    }

    fn keys(rs: &[Record]) -> Vec<&str> {
        let mut k: Vec<&str> = rs.iter().map(|r| r.key.as_str()).collect();
        k.sort();
        k
    }

    /// #2382: `did:web:a`'s record `b:k` and `did:web:a:b`'s record `k` were one row, so
    /// either room overwrote the other's.
    #[tokio::test]
    async fn a_room_never_writes_the_record_of_a_room_whose_id_extends_its_own() {
        let ks = open();
        create_room(&ks.rooms, &room(ROOM)).await.unwrap();
        create_room(&ks.rooms, &room(LONGER)).await.unwrap();
        let mut mine = record("b:k");
        mine.cleartext = Some(serde_json::json!({ "body": "a's" }));
        let mut theirs = record("k");
        theirs.cleartext = Some(serde_json::json!({ "body": "a:b's" }));
        put_record(&ks.rooms, &ks.records, LONGER, theirs, None, 1)
            .await
            .unwrap();
        put_record(&ks.rooms, &ks.records, ROOM, mine, None, 2)
            .await
            .unwrap();

        let got = get_record(&ks.records, LONGER, "k").await.unwrap();
        assert_eq!(body(&got), "a:b's", "the other room's record is untouched");
        let got = get_record(&ks.records, ROOM, "b:k").await.unwrap();
        assert_eq!(body(&got), "a's");
        let a = list_records(&ks.records, ROOM, None, None).await.unwrap();
        let ab = list_records(&ks.records, LONGER, None, None).await.unwrap();
        assert_eq!((keys(&a), keys(&ab)), (vec!["b:k"], vec!["k"]));
        // A key-prefix listing is bounded by the room too.
        let b = list_records(&ks.records, ROOM, Some("b"), None)
            .await
            .unwrap();
        assert_eq!(keys(&b), vec!["b:k"]);
    }

    /// #2382: a room's chain, relay and prune never reach a room whose identifier extends
    /// its own.
    #[tokio::test]
    async fn a_rooms_chain_relay_and_prune_stay_in_that_room() {
        let ks = open();
        populate(&ks, ROOM).await;
        populate(&ks, LONGER).await;

        assert_eq!(list_epoch_links(&ks.links, ROOM).await.unwrap().len(), 2);
        let relayed = commits_since(&ks.links, ROOM, 1, 10).await.unwrap();
        assert_eq!(
            relayed.iter().map(|c| c.epoch).collect::<Vec<_>>(),
            vec![2, 3]
        );

        assert_eq!(
            prune_epoch_links_before(&ks.links, ROOM, 3).await.unwrap(),
            2
        );
        assert!(list_epoch_links(&ks.links, ROOM).await.unwrap().is_empty());
        assert_eq!(
            list_epoch_links(&ks.links, LONGER).await.unwrap().len(),
            2,
            "the longer room's chain is not pruned"
        );
    }

    async fn put_legacy(ks: &KeyspaceHandle, key: &str, value: Vec<u8>) {
        ks.insert_raw(key.to_string(), value).await.unwrap();
    }

    fn legacy_record(key: &str, body: &str) -> Vec<u8> {
        let mut r = record(key);
        r.cleartext = Some(serde_json::json!({ "body": body }));
        serde_json::to_vec(&r).unwrap()
    }

    fn legacy_link(epoch: u32) -> Vec<u8> {
        serde_json::to_vec(&EpochLink {
            epoch,
            wrapped: "d3JhcHBlZA".into(),
            nonce: "bm9uY2U".into(),
        })
        .unwrap()
    }

    /// Rows in the earlier layout move to the room each one's own contents name, and what
    /// cannot be attributed stays put and is reported.
    #[tokio::test]
    async fn the_migration_moves_each_legacy_row_to_the_room_it_belongs_to() {
        let ks = open();
        create_room(&ks.rooms, &room(ROOM)).await.unwrap();
        create_room(&ks.rooms, &room(LONGER)).await.unwrap();
        // `did:web:a`'s `b:k` and `did:web:a:b`'s `x`: the keys alone cannot tell which.
        put_legacy(
            &ks.records,
            "room_records:did:web:a:b:k",
            legacy_record("b:k", "a's"),
        )
        .await;
        put_legacy(
            &ks.records,
            "room_records:did:web:a:b:x",
            legacy_record("x", "a:b's"),
        )
        .await;
        put_legacy(
            &ks.records,
            "room_records:did:web:a:k1",
            legacy_record("k1", "a's"),
        )
        .await;
        put_legacy(
            &ks.records,
            "room_records:did:web:z:junk",
            b"not json".to_vec(),
        )
        .await;
        put_legacy(
            &ks.records,
            "room_records:did:web:z:k9",
            legacy_record("other", "?"),
        )
        .await;
        put_legacy(
            &ks.links,
            "room_epoch_links:did:web:a:0000000002",
            legacy_link(2),
        )
        .await;
        put_legacy(
            &ks.links,
            "room_epoch_links:did:web:a:b:0000000002",
            legacy_link(2),
        )
        .await;
        put_legacy(
            &ks.links,
            "room_epoch_links:did:web:a:latest",
            legacy_link(9),
        )
        .await;
        put_legacy(
            &ks.links,
            "room-commit:did:web:a:b:0000000003",
            serde_json::to_vec("Y29tbWl0").unwrap(),
        )
        .await;

        let out = migrate_room_keys(&ks.records, &ks.links).await.unwrap();
        assert_eq!((out.records, out.epoch_links, out.commits), (3, 2, 1));
        assert_eq!(out.left.len(), 3, "{:?}", out.left);

        let a = list_records(&ks.records, ROOM, None, None).await.unwrap();
        let ab = list_records(&ks.records, LONGER, None, None).await.unwrap();
        assert_eq!((keys(&a), keys(&ab)), (vec!["b:k", "k1"], vec!["x"]));
        assert_eq!(body(&ab[0]), "a:b's");
        assert_eq!(list_epoch_links(&ks.links, ROOM).await.unwrap().len(), 1);
        assert_eq!(list_epoch_links(&ks.links, LONGER).await.unwrap().len(), 1);
        let relayed = commits_since(&ks.links, LONGER, 2, 10).await.unwrap();
        assert_eq!(relayed.iter().map(|c| c.epoch).collect::<Vec<_>>(), vec![3]);
        assert!(
            commits_since(&ks.links, ROOM, 0, 10)
                .await
                .unwrap()
                .is_empty()
        );

        // Only what could not be attributed is still in the earlier layout.
        assert_eq!(
            ks.records.prefix_keys("room_records:").await.unwrap().len(),
            2
        );

        // Run again: nothing more moves, and the same rows are reported.
        let again = migrate_room_keys(&ks.records, &ks.links).await.unwrap();
        assert_eq!((again.records, again.epoch_links, again.commits), (0, 0, 0));
        assert_eq!(again.left, out.left);
    }

    /// A legacy row whose current key is already held is left, not written over.
    #[tokio::test]
    async fn the_migration_never_replaces_a_row_in_the_current_layout() {
        let ks = open();
        create_room(&ks.rooms, &room(ROOM)).await.unwrap();
        put_record(&ks.rooms, &ks.records, ROOM, record("k1"), None, 1)
            .await
            .unwrap();
        put_legacy(
            &ks.records,
            "room_records:did:web:a:k1",
            legacy_record("k1", "old"),
        )
        .await;

        let out = migrate_room_keys(&ks.records, &ks.links).await.unwrap();
        assert_eq!(out.records, 0);
        assert!(out.left[0].contains("already held"), "{:?}", out.left);
        let got = get_record(&ks.records, ROOM, "k1").await.unwrap();
        assert_eq!(body(&got), "hello");
    }

    #[tokio::test]
    async fn a_store_with_nothing_legacy_migrates_nothing() {
        let ks = open();
        populate(&ks, ROOM).await;
        assert!(
            migrate_room_keys(&ks.records, &ks.links)
                .await
                .unwrap()
                .is_empty()
        );
    }
}

/// The host's record times and first author (`rooms/records/put/0.5` Host items 16–17), and
/// how `rooms/records/list/0.6` and `rooms/records/get/0.3` serve them (trust-tasks-tf #1027).
#[cfg(test)]
mod record_times_tests {
    use super::*;
    use crate::Visibility;
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn open() -> (tempfile::TempDir, KeyspaceHandle, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let rooms = store.keyspace(crate::ROOMS_KEYSPACE).unwrap();
        let records = store.keyspace(crate::ROOM_RECORDS_KEYSPACE).unwrap();
        (dir, rooms, records)
    }

    fn room(visibility: Visibility) -> Room {
        Room {
            room_id: "r1".into(),
            owner_did: "did:key:zOwner".into(),
            visibility,
            retention_policy: crate::RetentionPolicy::Chained,
            anchor_cadence: Default::default(),
            epoch: 1,
            next_version: 1,
            retention_days: 90,
            epoch_expires_at: None,
            created_at: 0,
            updated_at: 0,
            mirror_of: None,
            record_retention: None,
            last_prune: None,
            signal_delay: Default::default(),
            epoch_floor: None,
            frozen_at: None,
        }
    }

    /// A write as a host builds it: the author where the tier discloses one, and host times
    /// a writer tried to choose, which the store replaces.
    fn write(visibility: Visibility, author: &str, cleartext: serde_json::Value) -> Record {
        let open = visibility.stores_cleartext();
        Record {
            key: "k".into(),
            version: 0,
            epoch: (!open).then_some(1),
            status: RecordStatus::Active,
            pinned: false,
            sealed: (!open).then(|| "c2VhbGVk".to_string()),
            nonce: (!open).then(|| "bm9uY2U".to_string()),
            sealed_version: None,
            cleartext: open.then_some(cleartext),
            author: visibility.discloses_actor().then(|| author.to_string()),
            updated_at: 0,
            created_at: Some(1),
            created_by: Some("did:key:zForged".into()),
            body_stored_at: Some(1),
        }
    }

    fn curation(status: Option<RecordStatus>, pinned: Option<bool>) -> Curation {
        Curation {
            status,
            pinned,
            expected_version: None,
        }
    }

    /// Host items 16–17 on both tiers that record an author: `createdAt` and `createdBy` are
    /// set by the first version and never move — not by an edit (by another member too), a
    /// pin, a demotion or a retraction — while `bodyStoredAt` moves with each put and with
    /// nothing else. What a writer put in any of them is replaced.
    #[tokio::test]
    async fn created_at_and_by_are_set_once_and_body_stored_at_moves_only_with_a_body() {
        for visibility in [Visibility::Open, Visibility::Attributed] {
            let (_d, rooms, rec) = open().await;
            create_room(&rooms, &room(visibility)).await.unwrap();

            let first = put_record(
                &rooms,
                &rec,
                "r1",
                write(visibility, "did:key:zAlice", json!({ "body": "one" })),
                None,
                100,
            )
            .await
            .unwrap();
            assert_eq!(first.created_at, Some(100), "{visibility:?}");
            assert_eq!(first.created_by.as_deref(), Some("did:key:zAlice"));
            assert_eq!(
                first.body_stored_at,
                Some(100),
                "first version: equals createdAt"
            );

            // An edit, by someone else: a new body, the first version's creation kept.
            let edited = put_record(
                &rooms,
                &rec,
                "r1",
                write(visibility, "did:key:zBob", json!({ "body": "two" })),
                None,
                200,
            )
            .await
            .unwrap();
            assert_eq!(edited.created_at, Some(100));
            assert_eq!(edited.created_by.as_deref(), Some("did:key:zAlice"));
            assert_eq!(edited.body_stored_at, Some(200));

            for (when, c) in [
                (300, curation(None, Some(true))),
                (400, curation(Some(RecordStatus::Deprecated), None)),
                (500, curation(Some(RecordStatus::Retracted), None)),
            ] {
                let curated = curate_record(&rooms, &rec, "r1", "k", c, when)
                    .await
                    .unwrap();
                assert_eq!(curated.updated_at, when);
                assert_eq!(curated.created_at, Some(100), "curation at {when}");
                assert_eq!(curated.created_by.as_deref(), Some("did:key:zAlice"));
                assert_eq!(curated.body_stored_at, Some(200), "no new body at {when}");
            }
            let stored = get_record(&rec, "r1", "k").await.unwrap();
            assert_eq!(stored.created_at, Some(100));
            assert_eq!(stored.created_by.as_deref(), Some("did:key:zAlice"));
        }
    }

    /// Host item 17: a `private` room's host records no author, so it has none to keep or
    /// serve. The times are kept on every tier.
    #[tokio::test]
    async fn created_by_is_never_recorded_on_a_private_room() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room(Visibility::Private))
            .await
            .unwrap();
        let stored = put_record(
            &rooms,
            &rec,
            "r1",
            write(Visibility::Private, "did:key:zAlice", json!({})),
            None,
            100,
        )
        .await
        .unwrap();
        assert_eq!(stored.created_by, None);
        assert_eq!(stored.created_at, Some(100));
        assert_eq!(stored.body_stored_at, Some(100));
        let row = stored.metadata_v3(Visibility::Private);
        assert!(row.get("createdBy").is_none(), "{row}");
        assert_eq!(row["createdAt"], "1970-01-01T00:01:40Z");
        assert_eq!(row["bodyStoredAt"], "1970-01-01T00:01:40Z");
    }

    /// A record stored before the host kept these times reads cleanly, serves none of them,
    /// and keeps `createdAt` and `createdBy` unknown after an edit — they describe the first
    /// version, which this host did not time. Only the new body's time is known.
    #[tokio::test]
    async fn a_record_stored_before_the_times_serves_them_absent() {
        let (_d, rooms, rec) = open().await;
        let mut r = room(Visibility::Open);
        r.next_version = 8;
        create_room(&rooms, &r).await.unwrap();
        // A row as an earlier host wrote it: none of the three members.
        let legacy = json!({
            "key": "k",
            "version": 7,
            "epoch": null,
            "status": "active",
            "cleartext": { "body": "old", "kind": "message" },
            "author": "did:key:zAlice",
            "updatedAt": 50,
        });
        rec.insert(record_key("r1", "k"), &legacy).await.unwrap();

        let stored = get_record(&rec, "r1", "k").await.unwrap();
        assert_eq!(stored.created_at, None);
        assert_eq!(stored.created_by, None);
        assert_eq!(stored.body_stored_at, None);
        let row = stored.metadata_v3(Visibility::Open);
        for absent in ["createdAt", "createdBy", "bodyStoredAt"] {
            assert!(row.get(absent).is_none(), "{absent} guessed: {row}");
        }
        assert_eq!(row["kind"], "message");

        let edited = put_record(
            &rooms,
            &rec,
            "r1",
            write(Visibility::Open, "did:key:zAlice", json!({ "body": "new" })),
            None,
            100,
        )
        .await
        .unwrap();
        assert_eq!(edited.created_at, None);
        assert_eq!(edited.created_by, None);
        assert_eq!(edited.body_stored_at, Some(100));
    }

    /// list/0.6: `kind` exactly as the open record's cleartext carries it, absent where it
    /// carries none and on a tombstone, and never on a sealed tier.
    #[tokio::test]
    async fn kind_is_served_on_an_open_room_only_and_never_on_a_tombstone() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room(Visibility::Open)).await.unwrap();
        let mut r = write(
            Visibility::Open,
            "did:key:zAlice",
            json!({ "body": "hi", "kind": "message" }),
        );
        let stored = put_record(&rooms, &rec, "r1", r.clone(), None, 100)
            .await
            .unwrap();
        let row = stored.metadata_v3(Visibility::Open);
        assert_eq!(row["kind"], "message");
        assert_eq!(row["createdBy"], "did:key:zAlice");
        assert_eq!(row["bodyStoredAt"], row["createdAt"]);
        // 0.5's rows are unchanged.
        let v2 = stored.metadata();
        for m in ["kind", "createdAt", "createdBy", "bodyStoredAt"] {
            assert!(v2.get(m).is_none(), "{m} on a 0.5 row: {v2}");
        }

        // None carried: none served, not a default.
        r.key = "plain".into();
        r.cleartext = Some(json!({ "body": "note" }));
        let plain = put_record(&rooms, &rec, "r1", r, None, 110).await.unwrap();
        assert!(plain.metadata_v3(Visibility::Open).get("kind").is_none());

        let tomb = curate_record(
            &rooms,
            &rec,
            "r1",
            "k",
            curation(Some(RecordStatus::Retracted), None),
            120,
        )
        .await
        .unwrap();
        let row = tomb.metadata_v3(Visibility::Open);
        assert!(
            row.get("kind").is_none(),
            "a tombstone keeps no body: {row}"
        );
        assert_eq!(row["createdBy"], "did:key:zAlice");

        // A sealed tier never serves it, whatever a row holds.
        for v in [Visibility::Attributed, Visibility::Private] {
            assert!(stored.metadata_v3(v).get("kind").is_none(), "{v:?}");
        }
        assert!(
            stored
                .metadata_v3(Visibility::Private)
                .get("createdBy")
                .is_none()
        );
    }

    /// get/0.3's members are not committed: removing them (and `blobs`) from the response,
    /// as the specification tells a reader to, leaves exactly the committed record — so the
    /// leaf a reader hashes is the one in the host's tree, and its trace reaches the root.
    #[tokio::test]
    async fn the_get_0_3_leaf_is_unchanged_by_the_record_times() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room(Visibility::Attributed))
            .await
            .unwrap();
        let stored = put_record(
            &rooms,
            &rec,
            "r1",
            write(Visibility::Attributed, "did:key:zAlice", json!({})),
            None,
            100,
        )
        .await
        .unwrap();
        let (head, trace) = tree_head_with_trace(&rec, "r1", "k").await.unwrap();
        let trace = trace.expect("a held record has a trace");

        let mut body = serde_json::to_value(crate::wire::GetRecordResponse::of(
            &stored,
            Some(&head),
            Some(trace.clone()),
        ))
        .unwrap();
        for (name, value) in stored.host_times(Visibility::Attributed) {
            body[name] = value;
        }
        assert!(body.get("createdAt").is_some() && body.get("createdBy").is_some());
        // What get/0.3 *The leaf preimage is this response* removes.
        let obj = body.as_object_mut().unwrap();
        for m in [
            "dataCommitment",
            "recordCount",
            "headVersion",
            "trace",
            "ext",
            "blobs",
            "createdAt",
            "createdBy",
            "bodyStoredAt",
        ] {
            obj.remove(m);
        }
        let reassembled: crate::wire::CommittedRecord = serde_json::from_value(body).unwrap();
        let leaf = crate::merkle::leaf_hash(&reassembled).unwrap();
        assert_eq!(leaf, crate::merkle::leaf_hash(&stored.committed()).unwrap());
        assert!(
            crate::merkle::verify_inclusion(&head.root, &leaf, &trace),
            "the reassembled leaf reaches the host's root"
        );
    }
}
