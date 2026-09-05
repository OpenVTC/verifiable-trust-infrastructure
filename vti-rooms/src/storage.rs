//! CRUD over the `rooms:` and `room_records:` keyspaces.
//!
//! # Key layout
//!
//! ```text
//! rooms:<roomId>                        -> Room
//! room_records:<roomId>:<key>           -> Record
//! ```
//!
//! The trailing `:` on the record prefix makes a scan room-exact — a prefix of `a:` never
//! matches `ab:` — so one room's listing can never return another's, in the store layer as
//! well as at the authorization layer above it.
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

/// `rooms:<roomId>`.
pub const ROOMS_PREFIX: &str = "rooms:";
/// `room_records:<roomId>:<key>`.
pub const RECORDS_PREFIX: &str = "room_records:";

fn room_key(room_id: &str) -> String {
    format!("{ROOMS_PREFIX}{room_id}")
}

fn record_key(room_id: &str, key: &str) -> String {
    format!("{RECORDS_PREFIX}{room_id}:{key}")
}

/// Every record in one room. The trailing `:` is what makes this room-exact.
fn record_prefix(room_id: &str) -> String {
    format!("{RECORDS_PREFIX}{room_id}:")
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
    rooms.insert(room_key(&room.room_id), room).await
}

/// How long a minted epoch is good for, in seconds.
///
/// Not yet a per-room parameter: `rooms/create/0.1` has no member for it, and inventing one
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

    record.version = room.next_version;
    record.updated_at = now;
    room.next_version += 1;
    room.updated_at = now;

    records
        .insert(record_key(room_id, &record.key), &record)
        .await?;
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
    let mut record = get_record(records, room_id, key).await?;

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
            record.cleartext = None;
        }
    }
    if let Some(pinned) = pinned {
        record.pinned = pinned;
    }

    record.version = room.next_version;
    record.updated_at = now;
    room.next_version += 1;
    room.updated_at = now;

    records.insert(record_key(room_id, key), &record).await?;
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
    let k = record_key(room_id, key);
    if records.get_raw(k.clone()).await?.is_none() {
        return Err(AppError::NotFound(format!(
            "record `{key}` not found in `{room_id}`"
        )));
    }
    records.remove(k).await
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

    fn room(id: &str, visibility: Visibility) -> Room {
        Room {
            room_id: id.into(),
            owner_did: "did:key:zOwner".into(),
            visibility,
            epoch: 1,
            next_version: 1,
            retention_days: 90,
            epoch_expires_at: None,
            created_at: 0,
            updated_at: 0,
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
            cleartext: None,
            author: None,
            updated_at: 0,
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
            cleartext: Some(serde_json::json!({ "body": "hello" })),
            author: Some("did:key:zBob".into()),
            updated_at: 0,
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
}
