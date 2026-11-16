//! The owner's side of a membership change: preparing an add, remove or renew,
//! the pending advance and revocation it retains until the host answers, and
//! the admission retained for a readmission.

use super::*;

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
pub(super) async fn retain(
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
pub(super) async fn retain_admission(
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

pub(super) async fn discard_retained_admission(
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

    /// *Same group, whatever the evidence*: a member whose removal **was** recorded is not
    /// thereby admitted to another MLS group. The Welcome is `welcomeInvalid`, and nothing
    /// moves: the ended group, its removal row, the prior list (none), the join epoch and the
    /// KeyPackage all stay as they were — and a Welcome for the room's own group still joins.
    #[tokio::test]
    async fn a_removed_member_is_not_admitted_to_another_group() {
        let mut r = Room::new().await;
        r.admit().await.unwrap(); // 2
        assert_eq!(r.remove().await, 3);
        let held_raw = r.ks.get_raw(r.bob.key(GROUP)).await.unwrap().unwrap();
        let removed_raw = r.ks.get_raw(r.bob.key(REMOVED)).await.unwrap().unwrap();

        let pending = mint_key_package(&r.ks, &r.bob, 3600, 0).await.unwrap();
        let kp = B64.decode(&pending.key_package).unwrap();
        let mut other = SealedRoom::new(ROOM, RoomGroup::create("did:key:zMallory").unwrap());
        for _ in 0..3 {
            other.renew().unwrap(); // above the removal, so only the group id tells
        }
        let (added, _) = other.add_member(&kp).unwrap();

        assert!(matches!(
            join(&r.ks, &r.bob, &added.welcome.unwrap(), 1).await,
            Err(JoinError::WelcomeForAnotherGroup)
        ));
        assert!(holds_key_package(&r.ks, &r.bob, &kp, 1).await.unwrap());
        assert_eq!(
            r.ks.get_raw(r.bob.key(GROUP)).await.unwrap().unwrap(),
            held_raw,
            "the ended group is untouched"
        );
        assert_eq!(
            r.ks.get_raw(r.bob.key(REMOVED)).await.unwrap().unwrap(),
            removed_raw,
            "the removal row stays"
        );
        assert!(prior_memberships(&r.ks, &r.bob).await.unwrap().is_empty());
        assert_eq!(joined_epoch(&r.ks, &r.bob).await.unwrap(), Some(2));
        assert!(!holds_current(&r.ks, &r.bob).await.unwrap());

        // The room's own group still re-admits.
        let (welcome, _) = r.welcome_for_fresh_key_package().await;
        join(&r.ks, &r.bob, &welcome, 1).await.unwrap();
        assert_eq!(
            prior_memberships(&r.ks, &r.bob).await.unwrap()[0].removed_epoch,
            Some(3)
        );
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
