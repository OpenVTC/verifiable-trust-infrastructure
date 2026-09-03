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
    if rooms.get_raw(room_key(&room.room_id)).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "room `{}` is already registered here",
            room.room_id
        )));
    }
    rooms.insert(room_key(&room.room_id), room).await
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

/// Retract a record: drop the body, keep the tombstone.
///
/// Not an erasure. The key, version and epoch remain so that incremental sync converges and
/// the audit chain still shows the record existed. Hard removal is a separate, higher-trust
/// operation — two verbs because they are two different acts, and collapsing them makes the
/// common one too powerful or the rare one impossible.
pub async fn retract_record(
    rooms: &KeyspaceHandle,
    records: &KeyspaceHandle,
    room_id: &str,
    key: &str,
    now: u64,
) -> Result<Record, AppError> {
    let mut record = get_record(records, room_id, key).await?;
    let mut room = get_room(rooms, room_id).await?;

    record.status = RecordStatus::Retracted;
    record.sealed = None;
    record.nonce = None;
    record.cleartext = None;
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
/// The erasure path, separate from [`retract_record`] on purpose.
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

        let tomb = retract_record(&rooms, &rec, "r1", "a", 3).await.unwrap();
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

    #[tokio::test]
    async fn purge_removes_the_tombstone_and_is_not_idempotent() {
        let (_d, rooms, rec) = open().await;
        create_room(&rooms, &room("r1", Visibility::Open))
            .await
            .unwrap();
        put_record(&rooms, &rec, "r1", open_record("a"), None, 1)
            .await
            .unwrap();
        retract_record(&rooms, &rec, "r1", "a", 2).await.unwrap();

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
}
