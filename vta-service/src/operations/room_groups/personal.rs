//! The member's own state beside a group: the roots it has observed, its
//! personal label for the room, and its read marker.

use super::*;

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
pub(super) const KEEP_ROOTS: usize = 16;

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

// ─── The member's personal label (`rooms/keys/label/0.1`) ─────────────────

/// A member's personal label for one room, as this VTA keeps it ([`LABEL`]).
///
/// At least one detail, always: a label whose last detail is removed is deleted, never
/// stored empty (`rooms/keys/label/0.1` recipient item 4). Every string is kept exactly as
/// it arrived — never trimmed, case-folded or normalised (item 7). No earlier value is kept.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersonalLabel {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// A set: order carries no meaning, and is kept as the member last gave it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// When a detail last changed. A request that changed nothing does not move it.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl PersonalLabel {
    fn has_detail(&self) -> bool {
        self.label.is_some()
            || self.description.is_some()
            || self.notes.is_some()
            || self.tags.is_some()
    }

    /// The details, compared as `rooms/keys/label/0.1` item 5 says: strings exactly, tags
    /// as a set. `updatedAt` is not a detail.
    fn same_details(&self, other: &Self) -> bool {
        fn set(t: &Option<Vec<String>>) -> Option<std::collections::BTreeSet<&str>> {
            t.as_ref().map(|v| v.iter().map(String::as_str).collect())
        }
        self.label == other.label
            && self.description == other.description
            && self.notes == other.notes
            && set(&self.tags) == set(&other.tags)
    }
}

/// What a request does to one detail of a label.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum LabelDetail<T> {
    /// Absent from the request: the stored value stays.
    #[default]
    Unchanged,
    /// Replace the stored value (`tags`: the whole set).
    Set(T),
    /// `removeX`: remove the stored value.
    Remove,
}

impl<T: Clone> LabelDetail<T> {
    fn apply(&self, current: &Option<T>) -> Option<T> {
        match self {
            LabelDetail::Unchanged => current.clone(),
            LabelDetail::Set(v) => Some(v.clone()),
            LabelDetail::Remove => None,
        }
    }
}

/// Every change one `rooms/keys/label` request names, applied together or not at all.
#[derive(Debug, Clone, Default)]
pub struct LabelChange {
    pub label: LabelDetail<String>,
    pub description: LabelDetail<String>,
    pub notes: LabelDetail<String>,
    pub tags: LabelDetail<Vec<String>>,
}

/// What [`set_label`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelOutcome {
    /// This VTA holds no group state for the room as this member — nothing was written.
    NotHeld,
    /// The label as it now stands (`None` once no detail remains), and whether this
    /// request changed it.
    Applied {
        label: Option<PersonalLabel>,
        changed: bool,
    },
}

/// How many times [`set_label`] re-reads after a concurrent write moved the row under it.
/// A person racing themselves across a few devices; past this, something is wrong.
pub(super) const LABEL_WRITE_ATTEMPTS: usize = 8;

/// Apply `change` to `member`'s personal label for its room (`rooms/keys/label/0.1`).
///
/// Detail by detail (item 3): each detail given replaces the stored one, each removal
/// removes one, each absent detail is unchanged — so a rename on one device does not
/// overwrite notes written on another. Nothing is written when nothing would change
/// (item 5), and a label left with no detail is deleted (item 4).
///
/// The write is one [`Batch`](vti_common::store::Batch) conditional on the group state
/// still being held and the label row being as it was read, so a label can never be
/// written beside group state [`forget`] has just discarded, and two writes racing on
/// different details both land. A refusal re-reads and retries.
///
/// The caller has decided that it acts as `member`; this does not ask again.
pub async fn set_label(
    groups: &KeyspaceHandle,
    member: &Member,
    change: &LabelChange,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<LabelOutcome, AppError> {
    let read = |e: AppError| AppError::Internal(format!("read a personal label: {e}"));
    for _ in 0..LABEL_WRITE_ATTEMPTS {
        if groups.get_raw(member.key(GROUP)).await?.is_none() {
            return Ok(LabelOutcome::NotHeld);
        }
        let raw = groups.get_raw(member.key(LABEL)).await.map_err(read)?;
        let current: Option<PersonalLabel> = match &raw {
            Some(bytes) => Some(serde_json::from_slice(bytes).map_err(|e| {
                AppError::Internal(format!("decode the personal label for a room: {e}"))
            })?),
            None => None,
        };

        let next = PersonalLabel {
            label: change
                .label
                .apply(&current.as_ref().and_then(|c| c.label.clone())),
            description: change
                .description
                .apply(&current.as_ref().and_then(|c| c.description.clone())),
            notes: change
                .notes
                .apply(&current.as_ref().and_then(|c| c.notes.clone())),
            tags: change
                .tags
                .apply(&current.as_ref().and_then(|c| c.tags.clone())),
            updated_at: now,
        };
        let unchanged = match &current {
            Some(c) => c.same_details(&next),
            None => !next.has_detail(),
        };
        if unchanged {
            return Ok(LabelOutcome::Applied {
                label: current,
                changed: false,
            });
        }

        let mut batch = vti_common::store::Batch::new();
        batch.require_present(member.key(GROUP));
        match raw {
            Some(bytes) => batch.require_unchanged(member.key(LABEL), bytes),
            None => batch.require_absent(member.key(LABEL)),
        };
        let stored = if next.has_detail() {
            batch.insert(member.key(LABEL), &next)?;
            Some(next)
        } else {
            batch.remove(member.key(LABEL));
            None
        };
        match groups.apply_batch(batch).await? {
            vti_common::store::BatchOutcome::Applied => {
                return Ok(LabelOutcome::Applied {
                    label: stored,
                    changed: true,
                });
            }
            // The group state went while this was deciding.
            vti_common::store::BatchOutcome::Refused { check: 0 } => {
                return Ok(LabelOutcome::NotHeld);
            }
            // Another write moved the label: read it again and re-apply.
            vti_common::store::BatchOutcome::Refused { .. } => continue,
        }
    }
    Err(AppError::Conflict(
        "the personal label kept changing while this request was applying; send it again".into(),
    ))
}

/// `member`'s personal label for its room, if it has one — for `rooms/keys/list/0.2` with
/// `includePersonal`, and for nothing that completes, signs or seals for the member
/// (`rooms/keys/label/0.1` recipient item 9).
pub async fn personal_label(
    groups: &KeyspaceHandle,
    member: &Member,
) -> Result<Option<PersonalLabel>, AppError> {
    groups
        .get(member.key(LABEL))
        .await
        .map_err(|e| AppError::Internal(format!("read a personal label: {e}")))
}

// ─── The member's read marker (`rooms/keys/read-marker/set/0.1`) ───────────

/// A member's read marker for one room, as this VTA keeps it ([`READ_MARKER`]).
///
/// `created_at` is kept **exactly as received** (Recipient item 5) — the string, never a
/// reparsed timestamp, which would rewrite its precision or offset — and compared as an
/// instant ([`ReadMarker::further_than`]).
///
/// No `Debug` derive: a marker is not to reach a log (item 9), and a derived `Debug` is how
/// a value ends up in one.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadMarker {
    /// The highest room version the member has seen the conversation to; `0` is none.
    pub version: u64,
    /// The host's `createdAt` of the newest message the member has seen, as received.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

impl std::fmt::Debug for ReadMarker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadMarker(<redacted>)")
    }
}

impl ReadMarker {
    /// A marker from what a request carried: `created_at` must be an RFC 3339 instant.
    pub fn new(version: u64, created_at: Option<String>) -> Result<Self, AppError> {
        if let Some(t) = &created_at {
            chrono::DateTime::parse_from_rfc3339(t).map_err(|_| {
                AppError::Validation("`readMarker.createdAt` is not an RFC 3339 date-time".into())
            })?;
        }
        Ok(Self {
            version,
            created_at,
        })
    }

    /// `createdAt` as an instant; an absent one is earlier than any present one.
    fn instant(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.created_at.as_deref().and_then(|t| {
            chrono::DateTime::parse_from_rfc3339(t)
                .ok()
                .map(|d| d.with_timezone(&chrono::Utc))
        })
    }

    /// The total order *Further on* defines: `version`, then `createdAt` as an instant, an
    /// absent `createdAt` before any present one (`Option`'s order is exactly that).
    pub fn position(&self) -> (u64, Option<chrono::DateTime<chrono::Utc>>) {
        (self.version, self.instant())
    }

    /// Whether `self` is further on than `other` (Recipient item 3).
    pub fn further_than(&self, other: &Self) -> bool {
        self.position() > other.position()
    }

    /// Whether the two stand at the same place (Recipient item 4's "equal"): the same
    /// version and the same instant, whatever its spelling.
    pub fn same_place(&self, other: &Self) -> bool {
        self.position() == other.position()
    }
}

/// What [`set_read_marker`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadMarkerOutcome {
    /// This VTA holds no group state for the room as this member — nothing was written.
    NotHeld,
    /// The marker now in force, and whether this request moved it.
    Applied { marker: ReadMarker, moved: bool },
}

/// How many times [`set_read_marker`] re-reads after a concurrent write moved the row.
pub(super) const READ_MARKER_WRITE_ATTEMPTS: usize = 8;

/// Move `member`'s read marker for its room (`rooms/keys/read-marker/set/0.1`).
///
/// Without `rewind`, the further of the stored marker and `requested` is kept (Recipient
/// item 3): `requested` replaces the stored one whole when it is further on, and nothing is
/// written otherwise. With `rewind`, `requested` replaces the stored one unless they stand
/// at the same place (item 4). The write is one [`Batch`](vti_common::store::Batch)
/// conditional on the group state still being held and the marker row being as it was
/// read, so a marker is never written beside group state [`forget`] has discarded, and two
/// devices setting at once converge on the further marker. A refusal re-reads and retries.
///
/// The caller has decided that it acts as `member`; this does not ask again.
pub async fn set_read_marker(
    groups: &KeyspaceHandle,
    member: &Member,
    requested: &ReadMarker,
    rewind: bool,
) -> Result<ReadMarkerOutcome, AppError> {
    for _ in 0..READ_MARKER_WRITE_ATTEMPTS {
        if groups.get_raw(member.key(GROUP)).await?.is_none() {
            return Ok(ReadMarkerOutcome::NotHeld);
        }
        let raw = groups
            .get_raw(member.key(READ_MARKER))
            .await
            .map_err(|e| AppError::Internal(format!("read a read marker: {e}")))?;
        let current: Option<ReadMarker> = match &raw {
            Some(bytes) => Some(serde_json::from_slice(bytes).map_err(|e| {
                AppError::Internal(format!("decode the read marker for a room: {e}"))
            })?),
            None => None,
        };
        let moves = match &current {
            None => true,
            Some(c) if rewind => !requested.same_place(c),
            Some(c) => requested.further_than(c),
        };
        if !moves {
            return Ok(ReadMarkerOutcome::Applied {
                marker: current.unwrap_or_else(|| requested.clone()),
                moved: false,
            });
        }

        let mut batch = vti_common::store::Batch::new();
        batch.require_present(member.key(GROUP));
        match raw {
            Some(bytes) => batch.require_unchanged(member.key(READ_MARKER), bytes),
            None => batch.require_absent(member.key(READ_MARKER)),
        };
        batch.insert(member.key(READ_MARKER), requested)?;
        match groups.apply_batch(batch).await? {
            vti_common::store::BatchOutcome::Applied => {
                return Ok(ReadMarkerOutcome::Applied {
                    marker: requested.clone(),
                    moved: true,
                });
            }
            vti_common::store::BatchOutcome::Refused { check: 0 } => {
                return Ok(ReadMarkerOutcome::NotHeld);
            }
            // Another device moved the marker: read it again and decide again.
            vti_common::store::BatchOutcome::Refused { .. } => continue,
        }
    }
    Err(AppError::Conflict(
        "the read marker kept moving while this request was applying; send it again".into(),
    ))
}

/// `member`'s read marker for its room, if one is held — for `rooms/keys/list/0.3` with
/// `includePersonal` and for `rooms/keys/read-marker/moved`, and for nothing that
/// completes, signs or seals for the member (`rooms/keys/read-marker/set/0.1` item 8).
pub async fn read_marker(
    groups: &KeyspaceHandle,
    member: &Member,
) -> Result<Option<ReadMarker>, AppError> {
    groups
        .get(member.key(READ_MARKER))
        .await
        .map_err(|e| AppError::Internal(format!("read a read marker: {e}")))
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
