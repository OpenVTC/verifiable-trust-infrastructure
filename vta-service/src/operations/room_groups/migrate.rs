//! Moving rows written by the per-room build to the per-member layout.

use super::*;

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

pub(super) async fn move_row<V: serde::Serialize>(
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
