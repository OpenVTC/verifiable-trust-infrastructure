//! Usage reporting and limit overrides
//! (`docs/05-design-notes/data-rooms-files.md` §6.2–6.3).
//!
//! # Activity and the daily history
//!
//! Holdings (files, bytes) are the counters the limits are enforced against.
//! Activity — uploads committed, downloads begun, chunk bytes served — is
//! counted here as it happens, into one row per room per UTC day, and one per
//! member per room per day on rooms that are not `private`. A day's row also
//! carries the holdings as they stood when it was last touched, so the last
//! row of a day is that day's closing figure. The collection pass writes
//! today's row for every room and member that has one, so a quiet day still
//! has a level, and drops rows older than [`RETENTION_DAYS`].
//!
//! Activity is counted under its own lock, never the upload lock: a download
//! must not wait behind a commit that is writing a gigabyte to a store.
//!
//! # Overrides
//!
//! `vtc/rooms/limits/set` replaces one scope's limits for one room: the room,
//! its members by default, or one named member. An override replaces the
//! scope wholesale — an absent measure sets no limit at that scope — and the
//! host-wide ceiling bounds every one. Lowering a limit below current use
//! deletes nothing; it refuses new uploads.
//!
//! # What is never kept
//!
//! A file name, record key or anything from a room's contents: this module
//! sees blobs, sizes and the members uploads are charged to, and that is all
//! it records.

use std::collections::BTreeMap;

use chrono::{Days, NaiveDate};

use super::*;

/// How long the daily history is kept: a year compared with the one before
/// (`vtc/rooms/usage` item 7).
pub const RETENTION_DAYS: u64 = 400;

const META_INDEXED: &str = "meta:usage-indexed";
const META_PRUNED: &str = "meta:days-pruned";
const META_FIRST_DAY: &str = "meta:first-day";

fn day_prefix(room_id: &str) -> String {
    format!("daily:{}:", room_hash(room_id))
}
fn day_key(room_id: &str, date: NaiveDate) -> String {
    format!("{}{}", day_prefix(room_id), date.format("%Y-%m-%d"))
}
fn member_day_prefix(room_id: &str, member: &str) -> String {
    format!("mdaily:{}:{}:", room_hash(room_id), short_hash(&[member]))
}
fn member_day_key(room_id: &str, member: &str, date: NaiveDate) -> String {
    format!(
        "{}{}",
        member_day_prefix(room_id, member),
        date.format("%Y-%m-%d")
    )
}
fn room_index_key(room_id: &str) -> String {
    format!("room:{}", room_hash(room_id))
}
fn member_index_prefix(room_id: &str) -> String {
    format!("member:{}:", room_hash(room_id))
}
fn member_index_key(room_id: &str, member: &str) -> String {
    format!("{}{}", member_index_prefix(room_id), short_hash(&[member]))
}
fn room_override_key(room_id: &str) -> String {
    format!("limits:room:{}", room_hash(room_id))
}
fn member_override_prefix(room_id: &str) -> String {
    format!("limits:member:{}:", room_hash(room_id))
}
fn member_override_key(room_id: &str, member: &str) -> String {
    format!(
        "{}{}",
        member_override_prefix(room_id),
        short_hash(&[member])
    )
}

fn today() -> NaiveDate {
    Utc::now().date_naive()
}

/// The date at the end of a day key, which every `daily:` / `mdaily:` key has.
fn date_of_key(key: &[u8]) -> Option<NaiveDate> {
    let key = std::str::from_utf8(key).ok()?;
    let date = key.rsplit(':').next()?;
    NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()
}

// ─── stored rows ─────────────────────────────────────────────────────────

/// A room that has had file activity: the index the collection pass and the
/// reports walk, since every other key names the room only by hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoomIndex {
    room_id: String,
}

/// A member who has added files to a room. The usage counters key members by
/// hash; this is where the DID is, for the reports that name it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberIndex {
    room_id: String,
    member: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_upload_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DayRow {
    files: u64,
    bytes: u64,
    uploads: u64,
    downloads: u64,
    egress_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoomOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    files_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    room: Option<ScopeLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    member_default: Option<ScopeLimits>,
}

impl RoomOverride {
    fn is_empty(&self) -> bool {
        self.files_enabled.is_none() && self.room.is_none() && self.member_default.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberOverride {
    member: String,
    limits: ScopeLimits,
}

// ─── public shapes ───────────────────────────────────────────────────────

/// Uploads committed, downloads begun and chunk bytes served.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Activity {
    pub uploads: u64,
    pub downloads: u64,
    pub egress_bytes: u64,
}

impl Activity {
    pub(super) fn upload() -> Self {
        Self {
            uploads: 1,
            ..Self::default()
        }
    }
    pub(super) fn download() -> Self {
        Self {
            downloads: 1,
            ..Self::default()
        }
    }
    pub(super) fn egress(bytes: u64) -> Self {
        Self {
            egress_bytes: bytes,
            ..Self::default()
        }
    }
    /// A download served straight from storage: begun, and `bytes` counted as
    /// served when the target is issued, since no byte passes through the host to
    /// be counted later. A reader that fetches only some ranges, or fetches twice
    /// within the target's few minutes, is counted once at the blob's size.
    pub(super) fn direct_download(bytes: u64) -> Self {
        Self {
            downloads: 1,
            egress_bytes: bytes,
            ..Self::default()
        }
    }
    fn add(&mut self, other: Activity) {
        self.uploads += other.uploads;
        self.downloads += other.downloads;
        self.egress_bytes += other.egress_bytes;
    }
}

/// One day of one room or member: holdings at the day's close, activity during
/// it. The `DailyUsage` shape of `vtc/_shared/0.1/room-storage.schema.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DailyUsage {
    pub date: NaiveDate,
    pub files: u64,
    pub bytes: u64,
    pub uploads: u64,
    pub downloads: u64,
    pub egress_bytes: u64,
}

impl DailyUsage {
    /// This day's activity.
    pub fn activity(&self) -> Activity {
        Activity {
            uploads: self.uploads,
            downloads: self.downloads,
            egress_bytes: self.egress_bytes,
        }
    }
}

/// One member of one room, as `rooms/usage` and `vtc/rooms/usage` report them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemberUsage {
    pub member: String,
    pub usage: Usage,
    pub limits: ScopeLimits,
    pub overridden: bool,
    /// Seconds since the epoch.
    pub last_upload_at: Option<u64>,
}

/// What a room's blobs are, from one scan of its index: what each config holds
/// of it, its orphans, and its largest blobs by size alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RoomBlobsSummary {
    /// Blobs not yet deleted, by the config they are recorded under.
    pub by_config: BTreeMap<String, ConfigHoldings>,
    pub orphan_files: u64,
    pub orphan_bytes: u64,
    /// Seconds since the epoch.
    pub oldest_orphaned_at: Option<u64>,
    /// At most the number asked for, largest first: size, config, committed at.
    pub largest: Vec<(u64, String, u64)>,
}

/// Which scope of a room an override sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitTarget {
    Room,
    /// Every member of the room without an override of their own.
    MemberDefault,
    /// One member, by DID.
    Member(String),
}

/// What an override replaced, for the audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OverrideChange {
    pub previous: Option<ScopeLimits>,
    pub previous_files_enabled: Option<bool>,
}

/// Why an override was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum OverrideError {
    /// A `maxFileBytes` above the host-wide ceiling, which is never clamped
    /// silently.
    AboveCeiling {
        requested: u64,
        ceiling: u64,
    },
    /// A member scope on a `private` room, whose members the host cannot tell
    /// apart.
    MemberLimitsUnavailable,
    App(AppError),
}

impl From<AppError> for OverrideError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

impl std::fmt::Display for OverrideError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AboveCeiling { requested, ceiling } => write!(
                f,
                "maxFileBytes {requested} is above this host's ceiling of {ceiling} bytes"
            ),
            Self::MemberLimitsUnavailable => f.write_str(
                "a private room has no per-member limits: the host cannot tell its members apart",
            ),
            Self::App(e) => write!(f, "{e}"),
        }
    }
}

/// The limits one upload is checked against.
pub(super) struct Applied {
    pub(super) files_enabled: bool,
    pub(super) room: ScopeLimits,
    /// The uploading member's, or the room's per-member default when there is
    /// no member. Both as set, before the ceiling.
    pub(super) member: ScopeLimits,
}

impl BlobHost {
    // ─── limits ──────────────────────────────────────────────────────────

    async fn room_override(&self, room_id: &str) -> Result<RoomOverride, AppError> {
        Ok(self
            .blobs
            .get(room_override_key(room_id))
            .await?
            .unwrap_or_default())
    }

    async fn member_override(
        &self,
        room_id: &str,
        member: &str,
    ) -> Result<Option<MemberOverride>, AppError> {
        self.blobs.get(member_override_key(room_id, member)).await
    }

    /// The room scope's limits as reported: bounded by the ceiling, since a
    /// limit the host would not enforce is not a limit.
    fn report_room(&self, room: ScopeLimits) -> ScopeLimits {
        room.capped(self.limits.max_file_bytes)
    }

    /// A member scope's limits as reported: bounded by the ceiling and by the
    /// room's largest file, which a member's is never more than.
    fn report_member(&self, member: ScopeLimits, room: &ScopeLimits) -> ScopeLimits {
        member
            .capped(self.limits.max_file_bytes)
            .min_file(room.max_file_bytes)
    }

    pub(super) async fn limits_for(
        &self,
        room_id: &str,
        member: Option<&str>,
    ) -> Result<Applied, AppError> {
        // As set, not as reported: `check_limits` names the scope a refusing
        // limit was set at, which capping every scope would blur.
        let o = self.room_override(room_id).await?;
        let room = o.room.unwrap_or(self.limits.room);
        let named = match member {
            Some(m) => self.member_override(room_id, m).await?.map(|m| m.limits),
            None => None,
        };
        let member = named.or(o.member_default).unwrap_or(self.limits.member);
        Ok(Applied {
            files_enabled: self.limits.files_enabled && o.files_enabled.unwrap_or(true),
            member,
            room,
        })
    }

    /// The limits this host enforces on `room`, and where each scope's came
    /// from.
    pub async fn effective_limits(&self, room: &Room) -> Result<EffectiveLimits, AppError> {
        let o = self.room_override(&room.room_id).await?;
        let room_limits = o.room.unwrap_or(self.limits.room);
        let source = |set: bool| {
            if set {
                LimitSource::Override
            } else {
                LimitSource::Default
            }
        };
        Ok(EffectiveLimits {
            files_enabled: self.limits.files_enabled && o.files_enabled.unwrap_or(true),
            member: self
                .report_member(o.member_default.unwrap_or(self.limits.member), &room_limits),
            room: self.report_room(room_limits),
            room_source: source(o.room.is_some() || o.files_enabled.is_some()),
            member_source: source(o.member_default.is_some()),
            host_ceiling_bytes: self.limits.max_file_bytes,
        })
    }

    async fn reported_member(&self, room_id: &str, member: &str) -> Result<ScopeLimits, AppError> {
        let applied = self.limits_for(room_id, Some(member)).await?;
        Ok(self.report_member(applied.member, &applied.room))
    }

    /// The limits `member` is held to in `room`.
    pub async fn member_limits(&self, room: &Room, member: &str) -> Result<MemberLimits, AppError> {
        let overridden = self.member_override(&room.room_id, member).await?.is_some();
        Ok(MemberLimits {
            limits: self.reported_member(&room.room_id, member).await?,
            overridden,
        })
    }

    /// The override `target` holds now, if any, without the ceiling applied.
    pub async fn limit_override(
        &self,
        room: &Room,
        target: &LimitTarget,
    ) -> Result<Option<ScopeLimits>, AppError> {
        Ok(match target {
            LimitTarget::Room => self.room_override(&room.room_id).await?.room,
            LimitTarget::MemberDefault => self.room_override(&room.room_id).await?.member_default,
            LimitTarget::Member(m) => self
                .member_override(&room.room_id, m)
                .await?
                .map(|o| o.limits),
        })
    }

    /// Store (`Some`) or clear (`None`) `target`'s override, and for the room
    /// target set `files_enabled` when given. Clearing the room's limits leaves
    /// a `files_enabled` override in place: turning files back on is its own
    /// decision, never a side effect of another.
    ///
    /// Takes the upload lock, so an upload begun after this returns is checked
    /// against the new limits; one already reserved completes under its old.
    pub async fn set_limit_override(
        &self,
        room: &Room,
        target: &LimitTarget,
        limits: Option<ScopeLimits>,
        files_enabled: Option<bool>,
    ) -> Result<OverrideChange, OverrideError> {
        if room.visibility == Visibility::Private && *target != LimitTarget::Room {
            return Err(OverrideError::MemberLimitsUnavailable);
        }
        if let Some(requested) = limits.and_then(|l| l.max_file_bytes)
            && requested > self.limits.max_file_bytes
        {
            return Err(OverrideError::AboveCeiling {
                requested,
                ceiling: self.limits.max_file_bytes,
            });
        }
        let _guard = self.lock.lock().await;
        let room_id = room.room_id.as_str();
        match target {
            LimitTarget::Room | LimitTarget::MemberDefault => {
                let mut o = self.room_override(room_id).await?;
                let change = if *target == LimitTarget::Room {
                    let change = OverrideChange {
                        previous: o.room,
                        previous_files_enabled: o.files_enabled,
                    };
                    match (limits, files_enabled) {
                        (Some(l), _) => o.room = Some(l),
                        // `clear`: the room's limits go back to the default.
                        (None, None) => o.room = None,
                        // `filesEnabled` alone leaves the limits as they are.
                        (None, Some(_)) => {}
                    }
                    if files_enabled.is_some() {
                        o.files_enabled = files_enabled;
                    }
                    change
                } else {
                    let change = OverrideChange {
                        previous: o.member_default,
                        previous_files_enabled: None,
                    };
                    o.member_default = limits;
                    change
                };
                if o.is_empty() {
                    self.blobs.remove(room_override_key(room_id)).await?;
                } else {
                    self.blobs.insert(room_override_key(room_id), &o).await?;
                }
                // The room's limits moved, so may its band (`crate::observe`).
                crate::observe::changed();
                Ok(change)
            }
            LimitTarget::Member(member) => {
                let key = member_override_key(room_id, member);
                let previous = self
                    .blobs
                    .get::<MemberOverride>(key.clone())
                    .await?
                    .map(|o| o.limits);
                match limits {
                    Some(limits) => {
                        let row = MemberOverride {
                            member: member.clone(),
                            limits,
                        };
                        self.blobs.insert(key, &row).await?;
                    }
                    None => self.blobs.remove(key).await?,
                }
                Ok(OverrideChange {
                    previous,
                    previous_files_enabled: None,
                })
            }
        }
    }

    // ─── activity ────────────────────────────────────────────────────────

    /// Count `a` under today's row for the room, and the member's when there
    /// is one, with each row's holdings refreshed from the counters.
    pub(super) async fn record_activity(
        &self,
        room_id: &str,
        member: Option<&str>,
        a: Activity,
    ) -> Result<(), AppError> {
        let _guard = self.activity.lock().await;
        self.touch_room(room_id, a).await?;
        if let Some(m) = member {
            self.touch_member(room_id, m, a, None).await?;
        }
        Ok(())
    }

    /// An upload committed: counted, and the member's last upload moved on.
    pub(super) async fn record_upload(
        &self,
        room_id: &str,
        member: Option<&str>,
    ) -> Result<(), AppError> {
        let _guard = self.activity.lock().await;
        self.touch_room(room_id, Activity::upload()).await?;
        if let Some(m) = member {
            self.touch_member(room_id, m, Activity::upload(), Some(now_secs()))
                .await?;
        }
        Ok(())
    }

    async fn touch_room(&self, room_id: &str, a: Activity) -> Result<(), AppError> {
        let index = room_index_key(room_id);
        if self.blobs.get::<RoomIndex>(index.clone()).await?.is_none() {
            let row = RoomIndex {
                room_id: room_id.to_string(),
            };
            self.blobs.insert(index, &row).await?;
        }
        let level = self.room_usage(room_id).await?;
        self.touch_day(day_key(room_id, today()), level, a).await
    }

    async fn touch_member(
        &self,
        room_id: &str,
        member: &str,
        a: Activity,
        uploaded_at: Option<u64>,
    ) -> Result<(), AppError> {
        let index = member_index_key(room_id, member);
        let existing = self.blobs.get::<MemberIndex>(index.clone()).await?;
        // Written when new or when an upload moves it on, not on every chunk
        // a reader fetches.
        if existing.is_none() || uploaded_at.is_some() {
            let row = MemberIndex {
                room_id: room_id.to_string(),
                member: member.to_string(),
                last_upload_at: uploaded_at.or(existing.and_then(|r| r.last_upload_at)),
            };
            self.blobs.insert(index, &row).await?;
        }
        let level = self.member_usage(room_id, member).await?;
        self.touch_day(member_day_key(room_id, member, today()), level, a)
            .await
    }

    async fn touch_day(&self, key: String, level: Usage, a: Activity) -> Result<(), AppError> {
        let mut row = match self.blobs.get::<DayRow>(key.clone()).await? {
            Some(r) => r,
            None => {
                // The earliest day any row is for, which bounds what a report
                // may ask for (`vtc/rooms/usage` item 2).
                let date = date_of_key(key.as_bytes()).unwrap_or_else(today);
                let first = self.blobs.get::<NaiveDate>(META_FIRST_DAY).await?;
                if first.is_none_or(|f| date < f) {
                    self.blobs.insert(META_FIRST_DAY, &date).await?;
                }
                DayRow {
                    files: 0,
                    bytes: 0,
                    uploads: 0,
                    downloads: 0,
                    egress_bytes: 0,
                }
            }
        };
        row.files = level.files;
        row.bytes = level.bytes;
        row.uploads += a.uploads;
        row.downloads += a.downloads;
        row.egress_bytes += a.egress_bytes;
        self.blobs.insert(key, &row).await
    }

    /// The collection pass's share: index what predates the index, write
    /// today's row for every room and member that has had activity, and once a
    /// day drop rows past [`RETENTION_DAYS`].
    pub(super) async fn roll_days(&self) -> Result<(), AppError> {
        if self.blobs.get::<bool>(META_INDEXED).await?.is_none() {
            self.index_existing().await?;
        }
        let _guard = self.activity.lock().await;
        for (_, raw) in self.blobs.prefix_iter_raw(b"room:".to_vec()).await? {
            if let Ok(r) = serde_json::from_slice::<RoomIndex>(&raw) {
                self.touch_room(&r.room_id, Activity::default()).await?;
            }
        }
        for (_, raw) in self.blobs.prefix_iter_raw(b"member:".to_vec()).await? {
            if let Ok(r) = serde_json::from_slice::<MemberIndex>(&raw) {
                self.touch_member(&r.room_id, &r.member, Activity::default(), None)
                    .await?;
            }
        }
        let day = today();
        if self.blobs.get::<NaiveDate>(META_PRUNED).await? != Some(day) {
            let cutoff = day - Days::new(RETENTION_DAYS);
            for prefix in [&b"daily:"[..], &b"mdaily:"[..]] {
                for (key, _) in self.blobs.prefix_iter_raw(prefix.to_vec()).await? {
                    if date_of_key(&key).is_some_and(|d| d < cutoff) {
                        self.blobs.remove(key).await?;
                    }
                }
            }
            self.blobs.insert(META_PRUNED, &day).await?;
        }
        Ok(())
    }

    /// Index every room and member the blob index already charges, once: a
    /// host that stored files before reporting existed has counters naming
    /// members only by hash.
    async fn index_existing(&self) -> Result<(), AppError> {
        let _guard = self.lock.lock().await;
        let mut seen = std::collections::HashSet::new();
        let mut charged = Vec::new();
        for (_, raw) in self.blobs.prefix_iter_raw(b"blob:".to_vec()).await? {
            if let Ok(e) = serde_json::from_slice::<BlobEntry>(&raw) {
                charged.push((e.room_id, e.charged_to, Some(e.committed_at)));
            }
        }
        for (_, raw) in self.blobs.prefix_iter_raw(b"upload:".to_vec()).await? {
            if let Ok(r) = serde_json::from_slice::<UploadRecord>(&raw)
                && r.phase == UploadPhase::Open
            {
                charged.push((r.room_id, r.charged_to, None));
            }
        }
        for (room_id, member, at) in charged {
            if seen.insert(room_index_key(&room_id)) {
                let row = RoomIndex {
                    room_id: room_id.clone(),
                };
                self.blobs.insert(room_index_key(&room_id), &row).await?;
            }
            if let Some(member) = member {
                let key = member_index_key(&room_id, &member);
                let mut row =
                    self.blobs
                        .get::<MemberIndex>(key.clone())
                        .await?
                        .unwrap_or(MemberIndex {
                            room_id,
                            member,
                            last_upload_at: None,
                        });
                row.last_upload_at = row.last_upload_at.max(at);
                self.blobs.insert(key, &row).await?;
            }
        }
        self.blobs.insert(META_INDEXED, &true).await
    }

    // ─── reports ─────────────────────────────────────────────────────────

    /// The oldest day the history can answer for: its first row, or the
    /// retention cutoff once that has passed it. `None` before any activity.
    pub async fn oldest_retained_day(&self) -> Result<Option<NaiveDate>, AppError> {
        let cutoff = today() - Days::new(RETENTION_DAYS - 1);
        Ok(self
            .blobs
            .get::<NaiveDate>(META_FIRST_DAY)
            .await?
            .map(|first| first.max(cutoff)))
    }

    /// Every room that has had file activity on this host.
    pub async fn rooms_with_files(&self) -> Result<Vec<String>, AppError> {
        let mut out = Vec::new();
        for (_, raw) in self.blobs.prefix_iter_raw(b"room:".to_vec()).await? {
            if let Ok(r) = serde_json::from_slice::<RoomIndex>(&raw) {
                out.push(r.room_id);
            }
        }
        Ok(out)
    }

    /// The room's days from `from` to `to` inclusive, oldest first. A day with
    /// no row of its own (the host was down, or nothing happened before the
    /// collection pass ran) carries the previous day's holdings and no
    /// activity. Days before the room's first row, and after today, are not
    /// reported.
    pub async fn room_days(
        &self,
        room_id: &str,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<DailyUsage>, AppError> {
        self.days(day_prefix(room_id), from, to).await
    }

    /// One member's days in a room, as [`Self::room_days`].
    pub async fn member_days(
        &self,
        room_id: &str,
        member: &str,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<DailyUsage>, AppError> {
        self.days(member_day_prefix(room_id, member), from, to)
            .await
    }

    async fn days(
        &self,
        prefix: String,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<DailyUsage>, AppError> {
        let mut rows = BTreeMap::new();
        for (key, raw) in self.blobs.prefix_iter_raw(prefix.into_bytes()).await? {
            if let (Some(date), Ok(row)) =
                (date_of_key(&key), serde_json::from_slice::<DayRow>(&raw))
            {
                rows.insert(date, row);
            }
        }
        let to = to.min(today());
        let mut level = rows
            .range(..from)
            .next_back()
            .map(|(_, r)| (r.files, r.bytes));
        let mut out = Vec::new();
        let mut day = from;
        while day <= to {
            match rows.get(&day) {
                Some(r) => {
                    level = Some((r.files, r.bytes));
                    out.push(DailyUsage {
                        date: day,
                        files: r.files,
                        bytes: r.bytes,
                        uploads: r.uploads,
                        downloads: r.downloads,
                        egress_bytes: r.egress_bytes,
                    });
                }
                None => {
                    if let Some((files, bytes)) = level {
                        out.push(DailyUsage {
                            date: day,
                            files,
                            bytes,
                            uploads: 0,
                            downloads: 0,
                            egress_bytes: 0,
                        });
                    }
                }
            }
            day = match day.succ_opt() {
                Some(d) => d,
                None => break,
            };
        }
        Ok(out)
    }

    /// The room's activity from `from` to `to` inclusive.
    pub async fn room_activity(
        &self,
        room_id: &str,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Activity, AppError> {
        let mut a = Activity::default();
        for d in self.room_days(room_id, from, to).await? {
            a.add(d.activity());
        }
        Ok(a)
    }

    /// One member's activity in a room from `from` to `to` inclusive.
    pub async fn member_activity(
        &self,
        room_id: &str,
        member: &str,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Activity, AppError> {
        let mut a = Activity::default();
        for d in self.member_days(room_id, member, from, to).await? {
            a.add(d.activity());
        }
        Ok(a)
    }

    /// The members of `room` who hold or have reserved storage there, or for
    /// whom an override is set (`rooms/usage` item 3). Not a roster: a member
    /// who has added nothing and holds no override is not here, because the
    /// host has never seen them. Empty on a `private` room.
    pub async fn members_with_usage(&self, room: &Room) -> Result<Vec<MemberUsage>, AppError> {
        if room.visibility == Visibility::Private {
            return Ok(Vec::new());
        }
        let room_id = room.room_id.as_str();
        let mut members: BTreeMap<String, Option<u64>> = BTreeMap::new();
        for (_, raw) in self
            .blobs
            .prefix_iter_raw(member_index_prefix(room_id).into_bytes())
            .await?
        {
            if let Ok(r) = serde_json::from_slice::<MemberIndex>(&raw) {
                members.insert(r.member, r.last_upload_at);
            }
        }
        let mut overridden = std::collections::HashSet::new();
        for (_, raw) in self
            .blobs
            .prefix_iter_raw(member_override_prefix(room_id).into_bytes())
            .await?
        {
            if let Ok(o) = serde_json::from_slice::<MemberOverride>(&raw) {
                members.entry(o.member.clone()).or_insert(None);
                overridden.insert(o.member);
            }
        }
        let mut out = Vec::new();
        for (member, last_upload_at) in members {
            let usage = self.member_usage(room_id, &member).await?;
            let is_overridden = overridden.contains(&member);
            let holds = usage.files + usage.bytes + usage.reserved_bytes + usage.reserved_files > 0;
            if !holds && !is_overridden {
                continue;
            }
            let limits = self.reported_member(room_id, &member).await?;
            out.push(MemberUsage {
                member,
                usage,
                limits,
                overridden: is_overridden,
                last_upload_at,
            });
        }
        Ok(out)
    }

    /// What `room_id`'s blobs are, from one scan: holdings per config, orphans,
    /// and the `largest` biggest blobs by size. Sizes only — never what a blob
    /// is.
    pub async fn room_blobs_summary(
        &self,
        room_id: &str,
        largest: usize,
    ) -> Result<RoomBlobsSummary, AppError> {
        let mut out = RoomBlobsSummary::default();
        let prefix = format!("blob:{}:", room_hash(room_id));
        for (_, raw) in self.blobs.prefix_iter_raw(prefix.into_bytes()).await? {
            let Ok(e) = serde_json::from_slice::<BlobEntry>(&raw) else {
                continue;
            };
            let h = out.by_config.entry(e.config_id.clone()).or_default();
            h.files += 1;
            h.bytes += e.size;
            if e.state == BlobState::Orphaned {
                h.pending_delete_bytes += e.size;
                out.orphan_files += 1;
                out.orphan_bytes += e.size;
                if let Some(at) = e.orphaned_at {
                    out.oldest_orphaned_at = Some(out.oldest_orphaned_at.map_or(at, |o| o.min(at)));
                }
            } else {
                out.largest.push((e.size, e.config_id, e.committed_at));
            }
        }
        out.largest.sort_by_key(|l| std::cmp::Reverse(l.0));
        out.largest.truncate(largest);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::blob_store::{local::LocalDirStore, sha256_digest_multibase};

    const CHUNK: usize = 16_384;
    const MEMBER: &str = "did:key:zMember";
    const OTHER: &str = "did:key:zOther";

    struct Fixture {
        _dir: tempfile::TempDir,
        host: BlobHost,
    }

    fn fixture(limits: HostLimits) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().join("store"),
        })
        .unwrap();
        let host = BlobHost::new(
            store.keyspace(ROOM_BLOBS_KEYSPACE).unwrap(),
            store.keyspace(ROOM_BLOB_TRANSFERS_KEYSPACE).unwrap(),
            dir.path().join("staging"),
            Arc::new(FixedStore::new(
                "local",
                Arc::new(LocalDirStore::new(dir.path().join("blobs"))),
            )),
            limits,
        );
        Fixture { _dir: dir, host }
    }

    fn room(visibility: Visibility) -> Room {
        Room {
            room_id: "did:key:zRoom".into(),
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
            epoch_floor: None,
        }
    }

    /// A one-chunk blob of `len` bytes.
    fn blob(len: usize, seed: u8) -> (Vec<u8>, Manifest) {
        let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_add(seed)).collect();
        let digest = sha256_digest_multibase(&Sha256::digest(&bytes).into());
        let raw = serde_json::json!({
            "size": len,
            "chunks": { "chunkSize": CHUNK, "chunkCount": 1, "chunkDigests": [digest] },
            "digest": digest,
        });
        (bytes, Manifest::parse(&raw).unwrap())
    }

    async fn upload(
        h: &BlobHost,
        room: &Room,
        member: Option<&str>,
        len: usize,
        seed: u8,
    ) -> String {
        let (bytes, manifest) = blob(len, seed);
        let digest = manifest.chunk_digests[0].clone();
        let begun = h.begin(room, MEMBER, member, manifest).await.unwrap();
        let id = begun.upload_id.to_string();
        h.put_chunk(MEMBER, &id, 0, &digest, &bytes).await.unwrap();
        h.commit(MEMBER, &id).await.unwrap().blob_ref
    }

    fn scope(max_files: u64) -> ScopeLimits {
        ScopeLimits {
            max_files: Some(max_files),
            max_file_bytes: None,
            max_bytes: None,
        }
    }

    #[tokio::test]
    async fn uploads_downloads_and_egress_are_counted_for_the_room_and_the_member() {
        let f = fixture(HostLimits::default());
        let r = room(Visibility::Attributed);
        let blob_ref = upload(&f.host, &r, Some(MEMBER), 1000, 1).await;

        let d = f
            .host
            .open_download(&r, MEMBER, Some(MEMBER), &blob_ref)
            .await
            .unwrap();
        let id = d.download_id.to_string();
        // A chunk fetched twice left the store twice.
        f.host.read_chunk(MEMBER, &id, 0).await.unwrap();
        f.host.read_chunk(MEMBER, &id, 0).await.unwrap();

        let day = today();
        let rows = f.host.room_days(&r.room_id, day, day).await.unwrap();
        assert_eq!(rows.len(), 1);
        let row = rows[0];
        assert_eq!((row.files, row.bytes), (1, 1000));
        assert_eq!((row.uploads, row.downloads, row.egress_bytes), (1, 1, 2000));
        let m = f
            .host
            .member_activity(&r.room_id, MEMBER, day, day)
            .await
            .unwrap();
        assert_eq!((m.uploads, m.downloads, m.egress_bytes), (1, 1, 2000));

        let members = f.host.members_with_usage(&r).await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].member, MEMBER);
        assert_eq!(members[0].usage.bytes, 1000);
        assert!(members[0].last_upload_at.is_some());
        assert!(!members[0].overridden);
        assert_eq!(
            f.host.rooms_with_files().await.unwrap(),
            vec![r.room_id.clone()]
        );
    }

    #[tokio::test]
    async fn a_private_room_counts_the_room_and_never_a_member() {
        let f = fixture(HostLimits::default());
        let r = room(Visibility::Private);
        let blob_ref = upload(&f.host, &r, Some(MEMBER), 500, 2).await;
        let d = f
            .host
            .open_download(&r, MEMBER, Some(MEMBER), &blob_ref)
            .await
            .unwrap();
        f.host
            .read_chunk(MEMBER, &d.download_id.to_string(), 0)
            .await
            .unwrap();

        let day = today();
        let a = f.host.room_activity(&r.room_id, day, day).await.unwrap();
        assert_eq!((a.uploads, a.downloads, a.egress_bytes), (1, 1, 500));
        assert!(
            f.host
                .member_days(&r.room_id, MEMBER, day, day)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(f.host.members_with_usage(&r).await.unwrap().is_empty());
        for target in [
            LimitTarget::MemberDefault,
            LimitTarget::Member(MEMBER.into()),
        ] {
            assert!(matches!(
                f.host
                    .set_limit_override(&r, &target, Some(scope(1)), None)
                    .await,
                Err(OverrideError::MemberLimitsUnavailable)
            ));
        }
    }

    #[tokio::test]
    async fn overrides_are_enforced_at_the_next_begin_and_report_their_source() {
        let f = fixture(HostLimits::default());
        let r = room(Visibility::Attributed);
        upload(&f.host, &r, Some(MEMBER), 100, 3).await;

        let e = f.host.effective_limits(&r).await.unwrap();
        assert_eq!(
            (e.room_source, e.member_source),
            (LimitSource::Default, LimitSource::Default)
        );

        // One member held to the one file they have; another is not.
        let named = LimitTarget::Member(MEMBER.into());
        f.host
            .set_limit_override(&r, &named, Some(scope(1)), None)
            .await
            .unwrap();
        let refused = f.host.begin(&r, MEMBER, Some(MEMBER), blob(100, 4).1).await;
        let Err(BlobError::LimitExceeded(l)) = refused else {
            panic!("{refused:?}")
        };
        assert_eq!(
            (l.scope, l.measure, l.limit),
            (LimitScope::Member, "maxFiles", 1)
        );
        f.host
            .begin(&r, OTHER, Some(OTHER), blob(100, 5).1)
            .await
            .unwrap();

        let m = f.host.member_limits(&r, MEMBER).await.unwrap();
        assert!(m.overridden);
        assert_eq!(m.limits.max_files, Some(1));
        let listed = f.host.members_with_usage(&r).await.unwrap();
        assert!(listed.iter().any(|u| u.member == MEMBER && u.overridden));

        // The room as a whole, below what it holds: nothing is deleted, the next
        // upload is refused.
        f.host
            .set_limit_override(&r, &LimitTarget::Room, Some(scope(1)), None)
            .await
            .unwrap();
        let refused = f.host.begin(&r, OTHER, Some(OTHER), blob(100, 6).1).await;
        let Err(BlobError::LimitExceeded(l)) = refused else {
            panic!("{refused:?}")
        };
        assert_eq!(l.scope, LimitScope::Room);
        assert_eq!(f.host.room_usage(&r.room_id).await.unwrap().files, 1);
        assert_eq!(
            f.host.effective_limits(&r).await.unwrap().room_source,
            LimitSource::Override
        );

        // Clearing puts the default back.
        let change = f
            .host
            .set_limit_override(&r, &LimitTarget::Room, None, None)
            .await
            .unwrap();
        assert_eq!(change.previous, Some(scope(1)));
        f.host
            .set_limit_override(&r, &named, None, None)
            .await
            .unwrap();
        f.host
            .begin(&r, MEMBER, Some(MEMBER), blob(100, 7).1)
            .await
            .unwrap();
        assert!(!f.host.member_limits(&r, MEMBER).await.unwrap().overridden);
    }

    #[tokio::test]
    async fn files_off_for_a_room_outlives_clearing_its_limits() {
        let f = fixture(HostLimits::default());
        let r = room(Visibility::Attributed);
        f.host
            .set_limit_override(&r, &LimitTarget::Room, None, Some(false))
            .await
            .unwrap();
        assert!(matches!(
            f.host.begin(&r, MEMBER, Some(MEMBER), blob(10, 8).1).await,
            Err(BlobError::FilesDisabled)
        ));
        f.host
            .set_limit_override(&r, &LimitTarget::Room, Some(scope(5)), None)
            .await
            .unwrap();
        f.host
            .set_limit_override(&r, &LimitTarget::Room, None, None)
            .await
            .unwrap();
        let e = f.host.effective_limits(&r).await.unwrap();
        assert!(
            !e.files_enabled,
            "clearing limits is not turning files back on"
        );
        assert_eq!(e.room_source, LimitSource::Override);
        f.host
            .set_limit_override(&r, &LimitTarget::Room, None, Some(true))
            .await
            .unwrap();
        f.host
            .begin(&r, MEMBER, Some(MEMBER), blob(10, 9).1)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn an_override_above_the_host_ceiling_is_refused_not_clamped() {
        let f = fixture(HostLimits {
            max_file_bytes: 1000,
            ..Default::default()
        });
        let r = room(Visibility::Attributed);
        let over = ScopeLimits {
            max_file_bytes: Some(1001),
            ..Default::default()
        };
        assert!(matches!(
            f.host
                .set_limit_override(&r, &LimitTarget::Room, Some(over), None)
                .await,
            Err(OverrideError::AboveCeiling {
                requested: 1001,
                ceiling: 1000
            })
        ));
        assert_eq!(
            f.host.limit_override(&r, &LimitTarget::Room).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn a_quiet_day_carries_the_previous_holdings_and_no_activity() {
        let f = fixture(HostLimits::default());
        let r = room(Visibility::Attributed);
        let day = today();
        let at = |n: u64| day - Days::new(n);
        let level = Usage {
            files: 2,
            bytes: 20,
            ..Default::default()
        };
        f.host
            .touch_day(day_key(&r.room_id, at(4)), level, Activity::upload())
            .await
            .unwrap();
        let later = Usage {
            files: 3,
            bytes: 30,
            ..Default::default()
        };
        f.host
            .touch_day(day_key(&r.room_id, at(2)), later, Activity::download())
            .await
            .unwrap();

        let rows = f.host.room_days(&r.room_id, at(6), day).await.unwrap();
        let summary: Vec<_> = rows
            .iter()
            .map(|d| (d.date, d.files, d.uploads, d.downloads))
            .collect();
        assert_eq!(
            summary,
            vec![
                (at(4), 2, 1, 0),
                (at(3), 2, 0, 0),
                (at(2), 3, 0, 1),
                (at(1), 3, 0, 0),
                (at(0), 3, 0, 0),
            ],
            "nothing before the first row, and carried to today"
        );
        // A range that starts after the last row still knows the level.
        let rows = f.host.room_days(&r.room_id, at(1), at(1)).await.unwrap();
        assert_eq!((rows[0].files, rows[0].bytes), (3, 30));
        // Nothing is reported for days still to come.
        assert!(
            f.host
                .room_days(&r.room_id, day + Days::new(1), day + Days::new(3))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn rows_past_retention_are_dropped_once_a_day() {
        let f = fixture(HostLimits::default());
        let r = room(Visibility::Attributed);
        let day = today();
        let old = day - Days::new(RETENTION_DAYS + 1);
        let kept = day - Days::new(RETENTION_DAYS - 1);
        for d in [old, kept] {
            f.host
                .touch_day(day_key(&r.room_id, d), Usage::default(), Activity::upload())
                .await
                .unwrap();
            f.host
                .touch_day(
                    member_day_key(&r.room_id, MEMBER, d),
                    Usage::default(),
                    Activity::upload(),
                )
                .await
                .unwrap();
        }
        f.host.roll_days().await.unwrap();
        assert!(
            f.host
                .blobs
                .get::<DayRow>(day_key(&r.room_id, old))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            f.host
                .blobs
                .get::<DayRow>(member_day_key(&r.room_id, MEMBER, old))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            f.host
                .blobs
                .get::<DayRow>(day_key(&r.room_id, kept))
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(f.host.oldest_retained_day().await.unwrap(), Some(kept));
    }

    #[tokio::test]
    async fn files_stored_before_reporting_are_indexed_by_the_collection_pass() {
        let f = fixture(HostLimits::default());
        let r = room(Visibility::Attributed);
        upload(&f.host, &r, Some(MEMBER), 64, 10).await;
        // As a host that stored this before the index existed would hold it.
        for prefix in [
            &b"room:"[..],
            &b"member:"[..],
            &b"daily:"[..],
            &b"mdaily:"[..],
        ] {
            for (k, _) in f.host.blobs.prefix_iter_raw(prefix.to_vec()).await.unwrap() {
                f.host.blobs.remove(k).await.unwrap();
            }
        }
        f.host.blobs.remove(META_INDEXED).await.unwrap();
        assert!(f.host.members_with_usage(&r).await.unwrap().is_empty());

        f.host.sweep().await.unwrap();
        let members = f.host.members_with_usage(&r).await.unwrap();
        assert_eq!(members.len(), 1);
        assert!(members[0].last_upload_at.is_some());
        let day = today();
        let rows = f.host.room_days(&r.room_id, day, day).await.unwrap();
        assert_eq!((rows[0].files, rows[0].bytes, rows[0].uploads), (1, 64, 0));
    }

    #[tokio::test]
    async fn the_room_summary_names_sizes_and_configs_only() {
        let f = fixture(HostLimits::default());
        let r = room(Visibility::Attributed);
        for (len, seed) in [(300, 11), (100, 12), (200, 13)] {
            upload(&f.host, &r, Some(MEMBER), len, seed).await;
        }
        let s = f.host.room_blobs_summary(&r.room_id, 2).await.unwrap();
        assert_eq!(
            s.largest.iter().map(|l| l.0).collect::<Vec<_>>(),
            vec![300, 200]
        );
        assert_eq!(s.by_config["local"].files, 3);
        assert_eq!(s.by_config["local"].bytes, 600);
        assert_eq!(s.orphan_files, 0);
    }
}
