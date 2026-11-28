//! Community events (`vtc/events/*`, VTI-EVT-001 – 095): calendars, the events in them, who
//! registered for each, and reports of an event to the community's administrators.
//!
//! # What is kept here, and what is not
//!
//! Calendars, events, registrations and reports live in the `events` keyspace. An event's
//! hosts are access-control appointments (`vtc.events.manage` at `event:<eventId>`,
//! [`hosts`]), never a list on the event. Whether a published event has ended is read from its
//! time, never stored (VTI-EVT-004). The community sends no reminder: the hosts' suggested
//! reminders are for the member's own agent (VTI-EVT-040).
//!
//! # Who may do what
//!
//! A calendar is run by whoever holds `vtc.events.manage` unqualified (the community's
//! calendars) or for its group — `vtc.events.manage` at `group:<groupId>`, or managing that
//! group (VTI-EVT-013). An event is run by its calendar's runners and by its appointed hosts
//! (VTI-EVT-070). Members see the events whose audience admits them (VTI-EVT-020, checked
//! live, VTI-EVT-021), and an event they hold a registration for; a draft is seen only by
//! those who run it (VTI-EVT-004). Anything else is `notFound`, as if it did not exist
//! (VTI-EVT-023).
//!
//! # Time
//!
//! An event's time is JSCalendar's: a local `start` read in an IANA `timeZone`, and a
//! `duration` (VTI-EVT-005). The instant it starts is computed when it is read, so a change in
//! a zone's rules moves nothing a host chose. A local time a zone skips (the hour clocks go
//! forward) moves forward to the first time that exists; one it repeats takes the first.

pub mod door;
pub mod hosts;
pub mod identity;
pub mod invitations;
pub mod policy;
pub mod tickets;

use std::collections::BTreeSet;
use std::sync::LazyLock;

use chrono::{DateTime, Duration, LocalResult, NaiveDateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::acl::{Capability, ResourceQualifier, VtcAclEntry};
use crate::directory::model::FieldDef;
use crate::directory::project::Subject;
use crate::server::AppState;

/// Serialises every write that reads registrations and writes them back (capacity, the
/// waitlist), so two registrations never both take the last place.
pub static WRITE_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

/// `[events]`: host configuration for the community's events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct EventsConfig {
    /// Events on or off (VTI-EVT-007). Off, every event task answers as if no event existed,
    /// and a change is refused `eventsOff`. Default on.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The most reports one member may make in a day (VTI-EVT-081). Default 10.
    #[serde(default = "ten")]
    pub reports_per_day: u32,
    /// Days after an event ends that registration answers are kept (VTI-EVT-090). Default 30.
    #[serde(default = "thirty")]
    pub answers_retention_days: u32,
    /// The most invitations one member may make in a day, where an event lets members invite
    /// (VTI-EVT-105). Default 20.
    #[serde(default = "twenty")]
    pub invitations_per_day: u32,
    /// The most announcements an event's hosts may post to it in a day (VTI-EVT-120).
    /// Default 10.
    #[serde(default = "ten")]
    pub announcements_per_day: u32,
}

fn twenty() -> u32 {
    20
}

fn yes() -> bool {
    true
}
fn ten() -> u32 {
    10
}
fn thirty() -> u32 {
    30
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            reports_per_day: 10,
            answers_retention_days: 30,
            invitations_per_day: 20,
            announcements_per_day: 10,
        }
    }
}

impl EventsConfig {
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// The count threshold when an event names none (VTI-EVT-054).
pub const DEFAULT_COUNT_THRESHOLD: u32 = 5;

// ─── identifiers ─────────────────────────────────────────────────────────

fn new_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    use base64::Engine as _;
    format!(
        "{prefix}_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// A new identifier with `prefix`, for the records of this module's submodules.
#[must_use]
pub fn new_id_with(prefix: &str) -> String {
    new_id(prefix)
}

#[must_use]
pub fn new_calendar_id() -> String {
    new_id("cal")
}
#[must_use]
pub fn new_event_id() -> String {
    new_id("evt")
}
#[must_use]
pub fn new_registration_id() -> String {
    new_id("reg")
}
#[must_use]
pub fn new_report_id() -> String {
    new_id("rpt")
}

// ─── time ────────────────────────────────────────────────────────────────

/// Why an event's time cannot be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhenError {
    /// The zone is not an IANA zone this community knows.
    TimeZoneUnknown(String),
    /// The start, the duration or the all-day shape is malformed.
    Invalid(String),
}

/// A JSCalendar duration (`P1W2DT3H4M5S`, no months or years).
#[must_use]
pub fn parse_duration(s: &str) -> Option<Duration> {
    let rest = s.strip_prefix('P')?;
    if rest.is_empty() {
        return None;
    }
    let (date, time) = match rest.split_once('T') {
        Some((d, t)) => {
            if t.is_empty() {
                return None;
            }
            (d, Some(t))
        }
        None => (rest, None),
    };
    let mut total = Duration::zero();
    let mut take = |part: &str, units: &[(char, i64)]| -> Option<()> {
        let mut num = String::new();
        let mut last = None;
        for c in part.chars() {
            if c.is_ascii_digit() {
                num.push(c);
                continue;
            }
            let pos = units.iter().position(|(u, _)| *u == c)?;
            if last.is_some_and(|l| l >= pos) || num.is_empty() {
                return None;
            }
            let n: i64 = num.parse().ok()?;
            total = total.checked_add(&Duration::seconds(n.checked_mul(units[pos].1)?))?;
            num.clear();
            last = Some(pos);
        }
        num.is_empty().then_some(())
    };
    take(date, &[('W', 604_800), ('D', 86_400)])?;
    if let Some(t) = time {
        take(t, &[('H', 3_600), ('M', 60), ('S', 1)])?;
    }
    Some(total)
}

/// `When` (event.schema.json): JSCalendar's start, zone and duration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct When {
    pub start: String,
    pub time_zone: String,
    pub duration: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_without_time: Option<bool>,
}

impl When {
    /// The instants the event starts and ends (VTI-EVT-005).
    ///
    /// # Errors
    /// An unknown zone, a malformed start or duration, or an all-day event whose start is not
    /// midnight or whose duration is not whole days.
    pub fn interval(&self) -> Result<(DateTime<Utc>, DateTime<Utc>), WhenError> {
        let tz: chrono_tz::Tz = self
            .time_zone
            .parse()
            .map_err(|_| WhenError::TimeZoneUnknown(self.time_zone.clone()))?;
        let local = NaiveDateTime::parse_from_str(&self.start, "%Y-%m-%dT%H:%M:%S")
            .map_err(|_| WhenError::Invalid("`start` is not a local date-time".into()))?;
        let duration = parse_duration(&self.duration)
            .ok_or_else(|| WhenError::Invalid("`duration` is not a JSCalendar duration".into()))?;
        if self.show_without_time == Some(true) {
            if local.time() != chrono::NaiveTime::MIN {
                return Err(WhenError::Invalid(
                    "an all-day event starts at T00:00:00".into(),
                ));
            }
            if duration.num_seconds() % 86_400 != 0 || duration.is_zero() {
                return Err(WhenError::Invalid(
                    "an all-day event lasts whole days".into(),
                ));
            }
        }
        let start = resolve_local(&tz, local)
            .ok_or_else(|| WhenError::Invalid("`start` does not exist in the zone".into()))?;
        let end = start
            .checked_add_signed(duration)
            .ok_or_else(|| WhenError::Invalid("`duration` is too long".into()))?;
        Ok((start, end))
    }
}

/// A local time in `tz` as an instant: the first of two where the zone repeats it, and the
/// first time that exists after a gap where the zone skips it (RFC 5545 §3.3.5).
fn resolve_local(tz: &chrono_tz::Tz, local: NaiveDateTime) -> Option<DateTime<Utc>> {
    for step in 0..=16 {
        let candidate = local + Duration::minutes(15 * step);
        match tz.from_local_datetime(&candidate) {
            LocalResult::Single(t) | LocalResult::Ambiguous(t, _) => {
                return Some(t.with_timezone(&Utc));
            }
            LocalResult::None => continue,
        }
    }
    None
}

// ─── records ─────────────────────────────────────────────────────────────

/// `RosterSetting` (VTI-EVT-050).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Roster {
    Visible,
    Hidden,
}

impl Roster {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Visible => "visible",
            Self::Hidden => "hidden",
        }
    }
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "visible" => Some(Self::Visible),
            "hidden" => Some(Self::Hidden),
            _ => None,
        }
    }
}

/// A calendar's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CalendarState {
    Active,
    Archived,
}

/// One calendar (VTI-EVT-010 – 014).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Calendar {
    pub calendar_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(default)]
    pub community: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_roster: Option<Roster>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_reminder_minutes: Vec<u32>,
    /// Whether its events allow check-in without a door challenge, and whether such a
    /// check-in counts toward attendance (VTI-EVT-164, VTI-EVT-181).
    #[serde(default)]
    pub self_check_in: SelfCheckIn,
    /// The attendance default for its events (VTI-EVT-180); absent, they count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts_attendance: Option<bool>,
    pub state: CalendarState,
    pub created_at: DateTime<Utc>,
}

/// `EventSelfCheckIn` (VTI-EVT-164).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SelfCheckIn {
    /// Never without a door challenge.
    #[default]
    None,
    /// Allowed during the event; it does not count toward attendance.
    Allowed,
    /// Allowed during the event, and it counts.
    Counting,
}

impl SelfCheckIn {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Allowed => "allowed",
            Self::Counting => "counting",
        }
    }
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "none" => Self::None,
            "allowed" => Self::Allowed,
            "counting" => Self::Counting,
            _ => return None,
        })
    }
}

/// `EventGuestAdmission` (VTI-EVT-150).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GuestAdmission {
    #[default]
    None,
    Invited,
    Open,
}

impl GuestAdmission {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Invited => "invited",
            Self::Open => "open",
        }
    }
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "none" => Self::None,
            "invited" => Self::Invited,
            "open" => Self::Open,
            _ => return None,
        })
    }
}

/// An event's own identity (VTI-EVT-140 – 145): the DID the community's VTA minted from the
/// `vtc-event` template, the key it signs with there, and the community's authority
/// credential to it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventIdentity {
    pub did: String,
    pub signing_key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_log_path: Option<String>,
    pub authority: crate::groups::Authority,
    /// When the authority was revoked, if it was (VTI-EVT-142).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// `EventLifecycle` (VTI-EVT-004).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Lifecycle {
    Draft,
    Published,
    Cancelled,
}

impl Lifecycle {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::Cancelled => "cancelled",
        }
    }
}

/// One event (VTI-EVT-001). Members whose shape the specification gives in full
/// (`access`, `audience`, `registration`, `accessibility`) are kept as received and checked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventRecord {
    pub event_id: String,
    pub calendar_id: String,
    /// `event` or `meeting`, fixed for life (VTI-EVT-003).
    pub kind: String,
    pub status: Lifecycle,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub when: When,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Value>,
    pub audience: Value,
    pub registration: Value,
    pub roster: Roster,
    #[serde(default)]
    pub show_count: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count_threshold: Option<u32>,
    pub listed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessibility: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suggested_reminder_minutes: Vec<u32>,
    /// How it invites its audience (VTI-EVT-100).
    #[serde(default)]
    pub invite: invitations::InviteMode,
    /// Members of the audience may invite other members of it (VTI-EVT-105).
    #[serde(default)]
    pub members_may_invite: bool,
    /// Its own identity, where it was given one at creation (VTI-EVT-140).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<EventIdentity>,
    /// Whether it admits guests (VTI-EVT-150).
    #[serde(default)]
    pub guests: GuestAdmission,
    /// Whether registrants going are issued tickets (VTI-EVT-170).
    #[serde(default)]
    pub tickets: bool,
    /// Whether it counts toward attendance; absent, the calendar's default (VTI-EVT-180).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts_attendance: Option<bool>,
    /// The badge offered on check-in (VTI-EVT-186).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attendance_badge: Option<String>,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancelled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// The creator's directory entry.
    pub created_by: String,
}

/// `RegistrationMode` (VTI-EVT-031).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Open,
    Approval,
    Closed,
}

/// An event's registration settings, read from its `registration` member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub mode: Mode,
    pub capacity: Option<u32>,
    pub waitlist: bool,
    pub plus_ones: u32,
    pub opens_at: Option<DateTime<Utc>>,
    pub closes_at: Option<DateTime<Utc>>,
    pub questions: Vec<Value>,
    pub code_of_conduct: Option<String>,
}

fn instant(v: Option<&Value>) -> Option<DateTime<Utc>> {
    v.and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&Utc))
}

impl Settings {
    #[must_use]
    pub fn read(registration: &Value) -> Self {
        let mode = match registration.get("mode").and_then(Value::as_str) {
            Some("approval") => Mode::Approval,
            Some("closed") => Mode::Closed,
            _ => Mode::Open,
        };
        let u = |k: &str| {
            registration
                .get(k)
                .and_then(Value::as_u64)
                .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
        };
        Settings {
            mode,
            capacity: u("capacity"),
            waitlist: registration
                .get("waitlist")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            plus_ones: u("plusOnes").unwrap_or(0),
            opens_at: instant(registration.get("opensAt")),
            closes_at: instant(registration.get("closesAt")),
            questions: registration
                .get("questions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            code_of_conduct: registration
                .pointer("/codeOfConduct/sha256")
                .and_then(Value::as_str)
                .map(str::to_string),
        }
    }
}

impl EventRecord {
    /// The event's start and end (VTI-EVT-005).
    ///
    /// # Errors
    /// As [`When::interval`]; a stored event was checked when written, so only a zone a later
    /// database no longer knows fails here.
    pub fn interval(&self) -> Result<(DateTime<Utc>, DateTime<Utc>), WhenError> {
        self.when.interval()
    }

    /// Whether it has ended at `now` — read from its time, never stored (VTI-EVT-004).
    #[must_use]
    pub fn ended(&self, now: DateTime<Utc>) -> bool {
        self.interval().is_ok_and(|(_, end)| end <= now)
    }

    #[must_use]
    pub fn settings(&self) -> Settings {
        Settings::read(&self.registration)
    }

    /// When registrations close: `closesAt`, or the event's start (VTI-EVT-038).
    #[must_use]
    pub fn closes_at(&self) -> Option<DateTime<Utc>> {
        self.settings()
            .closes_at
            .or_else(|| self.interval().ok().map(|(s, _)| s))
    }

    #[must_use]
    pub fn threshold(&self) -> u32 {
        self.count_threshold.unwrap_or(DEFAULT_COUNT_THRESHOLD)
    }
}

/// `RegistrationStatus` (VTI-EVT-032).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RegStatus {
    Going,
    Maybe,
    Pending,
    Waitlisted,
    Withdrawn,
    Declined,
    Removed,
}

impl RegStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Going => "going",
            Self::Maybe => "maybe",
            Self::Pending => "pending",
            Self::Waitlisted => "waitlisted",
            Self::Withdrawn => "withdrawn",
            Self::Declined => "declined",
            Self::Removed => "removed",
        }
    }
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "going" => Self::Going,
            "maybe" => Self::Maybe,
            "pending" => Self::Pending,
            "waitlisted" => Self::Waitlisted,
            "withdrawn" => Self::Withdrawn,
            "declined" => Self::Declined,
            "removed" => Self::Removed,
            _ => return None,
        })
    }
    /// Still in play: going, maybe, pending or waitlisted.
    #[must_use]
    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Going | Self::Maybe | Self::Pending | Self::Waitlisted
        )
    }
}

/// One registrant's registration for one event (VTI-EVT-030).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub registration_id: String,
    pub event_id: String,
    /// The member's directory entry — or, for a partner's member (VTI-EVT-134), the DID they
    /// presented as, which is also `registrant_did`. The registration's key either way.
    pub entry_id: String,
    /// A registrant who is not a member: a partner's member, by the DID they presented as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registrant_did: Option<String>,
    /// A guest — a party who is no member (VTI-EVT-151); `registrant_did` names them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub guest: bool,
    /// Their check-in, where one is recorded (VTI-EVT-165). Who did not check in is never
    /// recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_in: Option<CheckIn>,
    /// Their ticket, kept exactly as issued (VTI-EVT-170, VTI-EVT-174).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<Ticket>,
    pub status: RegStatus,
    pub guests: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answers: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_of_conduct_acknowledged: Option<String>,
    /// When it joined the waitlist: the queue's order (VTI-EVT-033).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waitlisted_at: Option<DateTime<Utc>>,
    pub roster: Roster,
    pub event_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// `EventCheckInMethod` (VTI-EVT-162 – 164).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CheckInMethod {
    Challenge,
    Staff,
    #[serde(rename = "self")]
    SelfCheckIn,
}

impl CheckInMethod {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Challenge => "challenge",
            Self::Staff => "staff",
            Self::SelfCheckIn => "self",
        }
    }
}

/// A recorded check-in (VTI-EVT-165).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckIn {
    pub at: DateTime<Utc>,
    pub method: CheckInMethod,
    /// Door staff who checked them in by name (VTI-EVT-163), by entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// Whether it counts toward the registrant's attendance (VTI-EVT-181 – 183).
    pub counts: bool,
}

/// A ticket issued to a registrant (VTI-EVT-170 – 172).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ticket {
    /// The signed credential, exactly as issued.
    pub credential: Value,
    pub valid_until: DateTime<Utc>,
    /// Its slot in the community's revocation list.
    pub status_list_index: u32,
    #[serde(default)]
    pub revoked: bool,
}

/// One member's report of an event (VTI-EVT-081).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub report_id: String,
    pub event_id: String,
    pub entry_id: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub closed: bool,
}

// ─── storage ─────────────────────────────────────────────────────────────

const COMMUNITY_CALENDAR: &str = "calcomm";

fn cal_key(id: &str) -> String {
    format!("cal:{id}")
}
fn calgrp_key(group: &str) -> String {
    format!("calgrp:{group}")
}
fn evt_key(id: &str) -> String {
    format!("evt:{id}")
}
fn reg_key(event: &str, entry: &str) -> String {
    format!("reg:{event}:{entry}")
}
fn rid_key(id: &str) -> String {
    format!("rid:{id}")
}
fn mreg_key(entry: &str, event: &str) -> String {
    format!("mreg:{entry}:{event}")
}
fn rpt_key(id: &str) -> String {
    format!("rpt:{id}")
}
fn rptm_key(event: &str, entry: &str) -> String {
    format!("rptm:{event}:{entry}")
}

async fn values<T: serde::de::DeserializeOwned>(
    ks: &KeyspaceHandle,
    prefix: &str,
) -> Result<Vec<T>, AppError> {
    let mut out = Vec::new();
    for (_, raw) in ks.prefix_iter_raw(prefix.as_bytes().to_vec()).await? {
        match serde_json::from_slice(&raw) {
            Ok(v) => out.push(v),
            Err(e) => {
                tracing::warn!(prefix, error = %e, "an events record could not be read; skipped");
            }
        }
    }
    Ok(out)
}

async fn text(ks: &KeyspaceHandle, key: String) -> Result<Option<String>, AppError> {
    Ok(ks
        .get_raw(key)
        .await?
        .and_then(|b| String::from_utf8(b).ok()))
}

/// # Errors
/// A store failure.
pub async fn get_calendar(ks: &KeyspaceHandle, id: &str) -> Result<Option<Calendar>, AppError> {
    ks.get(cal_key(id)).await
}

/// # Errors
/// A store failure.
pub async fn put_calendar(ks: &KeyspaceHandle, cal: &Calendar) -> Result<(), AppError> {
    if let Some(g) = &cal.group_id {
        ks.insert_raw(calgrp_key(g), cal.calendar_id.clone().into_bytes())
            .await?;
    }
    if cal.community {
        ks.insert_raw(
            COMMUNITY_CALENDAR.to_string(),
            cal.calendar_id.clone().into_bytes(),
        )
        .await?;
    }
    ks.insert(cal_key(&cal.calendar_id), cal).await
}

/// # Errors
/// A store failure.
pub async fn calendars(ks: &KeyspaceHandle) -> Result<Vec<Calendar>, AppError> {
    values(ks, "cal:").await
}

/// The group's active calendar, if it has one (VTI-EVT-012).
///
/// # Errors
/// A store failure.
pub async fn group_calendar(
    ks: &KeyspaceHandle,
    group: &str,
) -> Result<Option<Calendar>, AppError> {
    let Some(id) = text(ks, calgrp_key(group)).await? else {
        return Ok(None);
    };
    Ok(get_calendar(ks, &id)
        .await?
        .filter(|c| c.state == CalendarState::Active))
}

/// The community's own calendar, made on first need (VTI-EVT-011).
///
/// # Errors
/// A store failure.
pub async fn community_calendar(ks: &KeyspaceHandle) -> Result<Calendar, AppError> {
    if let Some(id) = text(ks, COMMUNITY_CALENDAR.to_string()).await?
        && let Some(cal) = get_calendar(ks, &id).await?
    {
        return Ok(cal);
    }
    let cal = Calendar {
        calendar_id: new_calendar_id(),
        name: "Community".into(),
        description: None,
        color: None,
        group_id: None,
        community: true,
        default_roster: None,
        default_reminder_minutes: Vec::new(),
        self_check_in: SelfCheckIn::None,
        counts_attendance: None,
        state: CalendarState::Active,
        created_at: Utc::now(),
    };
    put_calendar(ks, &cal).await?;
    Ok(cal)
}

/// # Errors
/// A store failure.
pub async fn get_event(ks: &KeyspaceHandle, id: &str) -> Result<Option<EventRecord>, AppError> {
    ks.get(evt_key(id)).await
}

/// # Errors
/// A store failure.
pub async fn put_event(ks: &KeyspaceHandle, ev: &EventRecord) -> Result<(), AppError> {
    ks.insert(evt_key(&ev.event_id), ev).await
}

/// Every event, unordered.
///
/// # Errors
/// A store failure.
pub async fn events(ks: &KeyspaceHandle) -> Result<Vec<EventRecord>, AppError> {
    values(ks, "evt:").await
}

/// Remove a draft and anything recorded against it (VTI-EVT-093).
///
/// # Errors
/// A store failure.
pub async fn delete_event(ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    for reg in registrations_of(ks, id).await? {
        ks.remove(rid_key(&reg.registration_id)).await?;
        ks.remove(mreg_key(&reg.entry_id, id)).await?;
        ks.remove(reg_key(id, &reg.entry_id)).await?;
    }
    ks.remove(evt_key(id)).await
}

/// # Errors
/// A store failure.
pub async fn get_registration(
    ks: &KeyspaceHandle,
    event: &str,
    entry: &str,
) -> Result<Option<Registration>, AppError> {
    ks.get(reg_key(event, entry)).await
}

/// # Errors
/// A store failure.
pub async fn registration_by_id(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<Registration>, AppError> {
    let Some(at) = text(ks, rid_key(id)).await? else {
        return Ok(None);
    };
    let Some((event, entry)) = at.split_once(' ') else {
        return Ok(None);
    };
    get_registration(ks, event, entry).await
}

/// # Errors
/// A store failure.
pub async fn put_registration(ks: &KeyspaceHandle, reg: &Registration) -> Result<(), AppError> {
    ks.insert_raw(
        rid_key(&reg.registration_id),
        format!("{} {}", reg.event_id, reg.entry_id).into_bytes(),
    )
    .await?;
    ks.insert_raw(mreg_key(&reg.entry_id, &reg.event_id), Vec::new())
        .await?;
    ks.insert(reg_key(&reg.event_id, &reg.entry_id), reg).await
}

/// Every registration for `event`.
///
/// # Errors
/// A store failure.
pub async fn registrations_of(
    ks: &KeyspaceHandle,
    event: &str,
) -> Result<Vec<Registration>, AppError> {
    values(ks, &format!("reg:{event}:")).await
}

/// Every registration `entry` holds.
///
/// # Errors
/// A store failure.
pub async fn registrations_by(
    ks: &KeyspaceHandle,
    entry: &str,
) -> Result<Vec<Registration>, AppError> {
    let prefix = format!("mreg:{entry}:");
    let mut out = Vec::new();
    for key in ks.prefix_keys(prefix.as_bytes().to_vec()).await? {
        let Ok(key) = String::from_utf8(key) else {
            continue;
        };
        if let Some(event) = key.strip_prefix(&prefix)
            && let Some(r) = get_registration(ks, event, entry).await?
        {
            out.push(r);
        }
    }
    Ok(out)
}

/// # Errors
/// A store failure.
pub async fn put_report(ks: &KeyspaceHandle, r: &Report) -> Result<(), AppError> {
    if r.closed {
        ks.remove(rptm_key(&r.event_id, &r.entry_id)).await?;
    } else {
        ks.insert_raw(
            rptm_key(&r.event_id, &r.entry_id),
            r.report_id.clone().into_bytes(),
        )
        .await?;
    }
    ks.insert(rpt_key(&r.report_id), r).await
}

/// The member's open report of `event`, if any (VTI-EVT-081).
///
/// # Errors
/// A store failure.
pub async fn open_report(
    ks: &KeyspaceHandle,
    event: &str,
    entry: &str,
) -> Result<Option<Report>, AppError> {
    let Some(id) = text(ks, rptm_key(event, entry)).await? else {
        return Ok(None);
    };
    ks.get(rpt_key(&id)).await
}

/// # Errors
/// A store failure.
pub async fn reports(ks: &KeyspaceHandle) -> Result<Vec<Report>, AppError> {
    values(ks, "rpt:").await
}

// ─── places and the waitlist ─────────────────────────────────────────────

/// People going, plus-ones included (VTI-EVT-033).
#[must_use]
pub fn places_taken(regs: &[Registration]) -> u32 {
    regs.iter()
        .filter(|r| r.status == RegStatus::Going)
        .map(|r| 1 + r.guests)
        .sum()
}

/// Whether `extra` more people fit.
#[must_use]
pub fn fits(settings: &Settings, regs: &[Registration], extra: u32) -> bool {
    settings
        .capacity
        .is_none_or(|cap| places_taken(regs) + extra <= cap)
}

/// The waitlist, first first.
#[must_use]
pub fn waitlist(regs: &[Registration]) -> Vec<&Registration> {
    let mut w: Vec<&Registration> = regs
        .iter()
        .filter(|r| r.status == RegStatus::Waitlisted)
        .collect();
    w.sort_by(|a, b| {
        (a.waitlisted_at.unwrap_or(a.created_at), &a.registration_id)
            .cmp(&(b.waitlisted_at.unwrap_or(b.created_at), &b.registration_id))
    });
    w
}

/// A registrant's place on the waitlist, 1 first.
#[must_use]
pub fn waitlist_position(regs: &[Registration], registration_id: &str) -> Option<u32> {
    waitlist(regs)
        .iter()
        .position(|r| r.registration_id == registration_id)
        .map(|p| p as u32 + 1)
}

/// Move the waitlisted who now fit to going, in order — each that fits, skipping one that does
/// not (VTI-EVT-033). Joining a waitlist is consent to be moved. Returns the registrations
/// changed; the caller stores them.
#[must_use]
pub fn promote(ev: &EventRecord, regs: &[Registration], now: DateTime<Utc>) -> Vec<Registration> {
    let settings = ev.settings();
    let mut taken = places_taken(regs);
    let mut changed = Vec::new();
    for r in waitlist(regs) {
        let need = 1 + r.guests;
        if settings.capacity.is_none_or(|cap| taken + need <= cap) {
            let mut moved = r.clone();
            moved.status = RegStatus::Going;
            moved.waitlisted_at = None;
            moved.event_sequence = ev.sequence;
            moved.updated_at = now;
            taken += need;
            changed.push(moved);
        }
    }
    changed
}

// ─── departure and retention ─────────────────────────────────────────────

/// A member leaves the community (VTI-EVT-039): each registration still in play is removed,
/// freeing its places for the waitlist; a purge also erases their answers. Their host
/// appointments go with their access-control entry. Returns the registrations removed.
///
/// # Errors
/// A store failure.
pub async fn on_departure(
    state: &AppState,
    entry_id: &str,
    erase: bool,
) -> Result<usize, AppError> {
    let _guard = WRITE_LOCK.lock().await;
    let ks = &state.events_ks;
    let now = Utc::now();
    let mut removed = 0;
    for mut reg in registrations_by(ks, entry_id).await? {
        let live = reg.status.is_live();
        if !live && !(erase && reg.answers.is_some()) {
            continue;
        }
        if live {
            reg.status = RegStatus::Removed;
            reg.waitlisted_at = None;
            reg.note = Some("Left the community.".into());
            removed += 1;
        }
        if erase {
            reg.answers = None;
        }
        reg.updated_at = now;
        put_registration(ks, &reg).await?;
        if live
            && let Some(ev) = get_event(ks, &reg.event_id).await?
            && ev.status == Lifecycle::Published
            && !ev.ended(now)
        {
            let regs = registrations_of(ks, &ev.event_id).await?;
            for moved in promote(&ev, &regs, now) {
                put_registration(ks, &moved).await?;
            }
        }
    }
    Ok(removed)
}

/// One retention pass (VTI-EVT-090): answers to an event's questions are deleted
/// `retention_days` after it ends; the registrations' statuses stay. Returns the
/// registrations whose answers were deleted.
///
/// # Errors
/// A store failure.
pub async fn sweep_answers(state: &AppState, retention_days: u32) -> Result<usize, AppError> {
    let ks = &state.events_ks;
    let now = Utc::now();
    let mut cleared = 0;
    for ev in events(ks).await? {
        let Ok((_, end)) = ev.interval() else {
            continue;
        };
        if end + Duration::days(i64::from(retention_days)) > now {
            continue;
        }
        let _guard = WRITE_LOCK.lock().await;
        for mut reg in registrations_of(ks, &ev.event_id).await? {
            // Check-in records go on the same schedule; the monthly tallies stay
            // (VTI-EVT-166, VTI-EVT-185).
            let answers = reg.answers.take().is_some();
            let check_in = reg.checked_in.take().is_some();
            if answers || check_in {
                put_registration(ks, &reg).await?;
                cleared += 1;
            }
        }
    }
    Ok(cleared)
}

/// Wakes the events sweeper now: an event published, changed or cancelled, an invitation
/// made or revoked, a member's standing moved.
static KICK: LazyLock<tokio::sync::Notify> = LazyLock::new(tokio::sync::Notify::new);

/// Wake the events sweeper, so invitations and their notifications follow a change at once.
pub fn kick() {
    KICK.notify_one();
}

/// The events sweeper: answers past their retention and host appointments whose granter
/// departed (VTI-EVT-074, VTI-EVT-090), once an hour.
pub fn spawn_sweeper(state: AppState, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(async move {
        let mut last_hourly: Option<std::time::Instant> = None;
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
                _ = KICK.notified() => {}
            }
            // Invitations and their notifications: the one sender (VTI-EVT-102).
            if let Err(e) = invitations::settle(&state, Utc::now()).await {
                tracing::warn!(error = %e, "event invitations could not be settled; the next pass tries again");
            }
            // Tickets owed, and tickets no longer valid: the one issuer and revoker
            // (VTI-EVT-170, VTI-EVT-172).
            if let Err(e) = tickets::sweep(&state, Utc::now()).await {
                tracing::warn!(error = %e, "event tickets could not be settled; the next pass tries again");
            }
            if let Err(e) = door::sweep_challenges(&state.events_ks, Utc::now()).await {
                tracing::warn!(error = %e, "expired door challenges could not be removed");
            }
            if last_hourly.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(3600)) {
                continue;
            }
            last_hourly = Some(std::time::Instant::now());
            let days = state.config.read().await.events.answers_retention_days;
            if let Err(e) = sweep_answers(&state, days).await {
                tracing::warn!(error = %e, "events retention sweep failed; it runs again within the hour");
            }
            if let Err(e) = reconcile_reports(&state).await {
                tracing::warn!(error = %e, "event reports could not be raised on the action list; the next pass tries again");
            }
            if let Err(e) = hosts::sweep(&state).await {
                tracing::warn!(error = %e, "event host review sweep failed; it runs again within the hour");
            }
            if let Err(e) = renew_identities(&state, Utc::now()).await {
                tracing::warn!(error = %e, "event identities could not be renewed; the next pass tries again");
            }
        }
    });
}

/// Renew each live event identity's authority once half its life is spent, in the slot it
/// holds (VTI-EVT-142), as groups renew theirs. The sweeper is the one retry owner.
///
/// # Errors
/// A store failure.
pub async fn renew_identities(state: &AppState, now: DateTime<Utc>) -> Result<usize, AppError> {
    let ks = &state.events_ks;
    let mut renewed = 0;
    for ev in events(ks).await? {
        if ev.identity.is_none() || ev.status == Lifecycle::Cancelled || ev.ended(now) {
            continue;
        }
        let mut id = ev.identity.clone().expect("checked");
        match identity::renew_if_due(state, &mut id, now).await {
            Ok(true) => {
                let _guard = WRITE_LOCK.lock().await;
                if let Some(mut fresh) = get_event(ks, &ev.event_id).await? {
                    fresh.identity = Some(id);
                    put_event(ks, &fresh).await?;
                    renewed += 1;
                }
            }
            Ok(false) => {}
            Err(why) => {
                tracing::warn!(event = %ev.event_id, why, "an event identity's authority could not be renewed");
            }
        }
    }
    Ok(renewed)
}

// ─── reports ─────────────────────────────────────────────────────────────

async fn close_reports(ks: &KeyspaceHandle, event_id: &str) -> Result<usize, AppError> {
    let mut closed = 0;
    for mut r in reports(ks).await? {
        if r.event_id == event_id && !r.closed {
            r.closed = true;
            put_report(ks, &r).await?;
            closed += 1;
        }
    }
    Ok(closed)
}

async fn audit_as(
    state: &AppState,
    actor: &str,
    event_id: &str,
    change: &str,
) -> Result<(), AppError> {
    let writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured: event changes are refused rather than made \
                      unaudited"
                .into(),
        })?;
    writer
        .write(
            actor,
            None,
            vtc_audit::AuditEvent::EventChanged(vtc_audit::EventChangedData {
                event_id: Some(event_id.to_string()),
                calendar_id: None,
                registration_id: None,
                entry_id: None,
                change: change.to_string(),
                fields: Vec::new(),
            }),
        )
        .await
        .map(drop)
}

/// An administrator upholds the reports of `event_id` from the action list (VTI-EVT-081):
/// the event is cancelled as `vtc/events/cancel` cancels it, and every open report closes.
///
/// # Errors
/// A store failure, or an event that cannot be cancelled now (not published, or ended) —
/// which leaves the item open.
pub async fn uphold_reports(
    state: &AppState,
    event_id: &str,
    decider: &str,
    reason: Option<&str>,
) -> Result<Value, AppError> {
    let ks = &state.events_ks;
    let now = Utc::now();
    {
        let _guard = WRITE_LOCK.lock().await;
        let mut ev = get_event(ks, event_id)
            .await?
            .ok_or_else(|| AppError::NotFound("the event no longer exists".into()))?;
        if ev.status != Lifecycle::Published || ev.ended(now) {
            return Err(AppError::Conflict(
                "only a published event that has not ended is cancelled; dismiss the report \
                 instead"
                    .into(),
            ));
        }
        ev.status = Lifecycle::Cancelled;
        ev.cancelled_at = Some(now);
        ev.cancel_reason = Some(
            reason
                .map(str::to_string)
                .unwrap_or_else(|| "Cancelled by the community's administrators.".into()),
        );
        ev.sequence += 1;
        ev.updated_at = now;
        put_event(ks, &ev).await?;
    }
    let closed = close_reports(ks, event_id).await?;
    audit_as(state, decider, event_id, "cancelled").await?;
    Ok(json!({ "eventId": event_id, "cancelled": true, "reportsClosed": closed }))
}

/// An administrator dismisses the reports of `event_id`: every open report closes and the
/// event stands.
///
/// # Errors
/// A store failure.
pub async fn dismiss_reports(state: &AppState, event_id: &str) -> Result<Value, AppError> {
    let closed = close_reports(&state.events_ks, event_id).await?;
    Ok(json!({ "eventId": event_id, "cancelled": false, "reportsClosed": closed }))
}

/// Raise a review for every event with an open report and no open item (the crash between a
/// report and its item, a restored backup).
///
/// # Errors
/// A store failure.
pub async fn reconcile_reports(state: &AppState) -> Result<(), AppError> {
    let mut seen = BTreeSet::new();
    for r in reports(&state.events_ks).await? {
        if r.closed || !seen.insert(r.event_id.clone()) {
            continue;
        }
        let title = get_event(&state.events_ks, &r.event_id)
            .await?
            .map(|e| e.title)
            .unwrap_or_default();
        crate::admin_actions::queues::raise_event_report(state, &r, &title).await?;
    }
    Ok(())
}

// ─── who is looking ──────────────────────────────────────────────────────

/// The caller as the events module sees them.
#[derive(Debug, Clone)]
pub struct Viewer {
    pub did: String,
    pub entry_id: Option<String>,
    pub active_member: bool,
    /// What the community's records say of them, for the audience (VTI-EVT-020).
    pub subject: Option<Subject>,
    /// For a party who is not a member: the partner community whose membership credential
    /// they presented with this request, verified before any event was looked up
    /// (VTI-EVT-132, VTI-EVT-133). Never kept beyond the request.
    pub partner: Option<String>,
    /// A party who is no member, acting as a guest (VTI-EVT-151): they see only an event they
    /// hold a registration for, or the one this request admits them to.
    pub guest: bool,
    /// Set by `guests/register` once the event's admission (VTI-EVT-150, 151) let this guest in.
    pub guest_admitted: bool,
    entry: Option<VtcAclEntry>,
}

impl Viewer {
    /// # Errors
    /// A store failure.
    pub async fn read(state: &AppState, did: &str) -> Result<Self, AppError> {
        let entry = crate::acl::get_acl_entry(&state.acl_ks, did).await?;
        let active_member = crate::member_portal::active::active_member(state, did)
            .await?
            .is_some();
        let mut subject = crate::directory::read::subject_by_did(state, did).await?;
        // An active member with no directory entry yet gets one, as groups and boards make it
        // on a member's first act: the audience reads what the entry says of them.
        if subject.is_none() && active_member {
            let dir = &state.directory;
            let own = entry
                .as_ref()
                .filter(|e| e.label_set_by_subject)
                .and_then(|e| e.label.clone());
            crate::directory::cards::ensure(dir.ks(), did, &dir.settings(), own.as_deref()).await?;
            subject = crate::directory::read::subject_by_did(state, did).await?;
        }
        let entry_id = match &subject {
            Some(s) => Some(s.card.entry_id.clone()),
            None => crate::directory::cards::entry_of(state.directory.ks(), did).await?,
        };
        Ok(Self {
            did: did.to_string(),
            entry_id,
            active_member,
            subject,
            partner: None,
            guest: false,
            guest_admitted: false,
            entry,
        })
    }

    /// Whether the partner they proved, if any, is one `audience` names (VTI-EVT-132).
    #[must_use]
    pub fn partner_admitted(&self, audience: &Value) -> bool {
        let Some(p) = &self.partner else {
            return false;
        };
        audience
            .get("partners")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|x| x.as_str() == Some(p)))
    }

    fn can(&self, cap: Capability, at: Option<&ResourceQualifier>) -> bool {
        self.entry.as_ref().is_some_and(|e| e.can(cap, at))
    }

    /// Runs the community's calendars and every event (`vtc.events.manage` unqualified).
    #[must_use]
    pub fn runs_all(&self) -> bool {
        self.can(Capability::EventsManage, None)
    }

    /// May create and run events in `cal` (VTI-EVT-013).
    #[must_use]
    pub fn runs_calendar(&self, cal: &Calendar) -> bool {
        if self.runs_all() {
            return true;
        }
        let Some(g) = &cal.group_id else {
            return false;
        };
        let at = ResourceQualifier::Group(g.clone());
        self.can(Capability::EventsManage, Some(&at))
            || self.can(Capability::GroupsManage, Some(&at))
    }

    /// Runs `ev`: its calendar's runners, or a host by appointment (VTI-EVT-070).
    #[must_use]
    pub fn hosts(&self, ev: &EventRecord, cal: Option<&Calendar>) -> bool {
        cal.is_some_and(|c| self.runs_calendar(c))
            || self.can(
                Capability::EventsManage,
                Some(&ResourceQualifier::Event(ev.event_id.clone())),
            )
    }

    /// Door staff for `ev`: its hosts, and holders of `vtc.events.checkin` at it
    /// (VTI-EVT-160).
    #[must_use]
    pub fn door_staff(&self, ev: &EventRecord, cal: Option<&Calendar>) -> bool {
        self.hosts(ev, cal)
            || self.can(
                Capability::EventsCheckIn,
                Some(&ResourceQualifier::Event(ev.event_id.clone())),
            )
    }

    /// The audience admits them (VTI-EVT-020): an active member whom the scope and the rule
    /// both admit.
    #[must_use]
    pub fn in_audience(&self, audience: &Value, schema: &[FieldDef]) -> bool {
        self.active_member
            && self
                .subject
                .as_ref()
                .is_some_and(|s| audience_admits(audience, s, schema))
    }
}

/// Whether `audience` admits `subject` (VTI-EVT-020).
#[must_use]
pub fn audience_admits(audience: &Value, subject: &Subject, schema: &[FieldDef]) -> bool {
    if !subject.active {
        return false;
    }
    let names = |k: &str| -> BTreeSet<String> {
        audience
            .get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let scope = match audience.get("scope").and_then(Value::as_str) {
        Some("members") => true,
        Some("groups") => names("groups").iter().any(|g| subject.groups.contains(g)),
        Some("roles") => names("roles").contains(&subject.role),
        _ => false,
    };
    scope
        && audience
            .get("rule")
            .is_none_or(|rule| crate::groups::dynamic::admits(rule, subject, schema))
}

// ─── what is answered ────────────────────────────────────────────────────

fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// `Calendar` as the wire states it.
#[must_use]
pub fn calendar_wire(cal: &Calendar) -> Value {
    let mut o = Map::new();
    o.insert("calendarId".into(), json!(cal.calendar_id));
    o.insert("name".into(), json!(cal.name));
    if let Some(d) = &cal.description {
        o.insert("description".into(), json!(d));
    }
    if let Some(c) = &cal.color {
        o.insert("color".into(), json!(c));
    }
    if let Some(g) = &cal.group_id {
        o.insert("groupId".into(), json!(g));
    }
    if cal.community {
        o.insert("community".into(), json!(true));
    }
    if let Some(r) = cal.default_roster {
        o.insert("defaultRoster".into(), json!(r.as_str()));
    }
    if cal.self_check_in != SelfCheckIn::None {
        o.insert("selfCheckIn".into(), json!(cal.self_check_in.as_str()));
    }
    if let Some(c) = cal.counts_attendance {
        o.insert("countsAttendance".into(), json!(c));
    }
    if !cal.default_reminder_minutes.is_empty() {
        o.insert(
            "defaultReminderMinutes".into(),
            json!(cal.default_reminder_minutes),
        );
    }
    o.insert(
        "state".into(),
        json!(match cal.state {
            CalendarState::Active => "active",
            CalendarState::Archived => "archived",
        }),
    );
    o.insert("createdAt".into(), json!(stamp(cal.created_at)));
    Value::Object(o)
}

/// `Count` for someone who is not a host (VTI-EVT-054); `None` where it is not shown.
#[must_use]
pub fn count_for(ev: &EventRecord, going: u32, host: bool) -> Option<Value> {
    if host {
        return Some(json!({ "exact": going }));
    }
    if !ev.show_count {
        return None;
    }
    let k = ev.threshold();
    Some(if going >= k {
        json!({ "exact": going })
    } else {
        json!({ "fewerThan": k })
    })
}

/// `Event` as the caller may see it.
#[must_use]
pub fn event_wire(ev: &EventRecord, host: bool, regs: &[Registration], hosts: &[String]) -> Value {
    let mut o = Map::new();
    o.insert("eventId".into(), json!(ev.event_id));
    o.insert("calendarId".into(), json!(ev.calendar_id));
    o.insert("kind".into(), json!(ev.kind));
    o.insert("status".into(), json!(ev.status.as_str()));
    o.insert("title".into(), json!(ev.title));
    if let Some(d) = &ev.description {
        o.insert("description".into(), json!(d));
    }
    o.insert(
        "when".into(),
        serde_json::to_value(&ev.when).unwrap_or(Value::Null),
    );
    if let Some(p) = &ev.place_summary {
        o.insert("placeSummary".into(), json!(p));
    }
    if let Some(a) = &ev.access {
        let public = a.get("public").and_then(Value::as_bool).unwrap_or(false);
        if host || public {
            o.insert("access".into(), a.clone());
        }
    }
    o.insert("audience".into(), ev.audience.clone());
    o.insert("registration".into(), ev.registration.clone());
    o.insert("roster".into(), json!(ev.roster.as_str()));
    if ev.show_count {
        o.insert("showCount".into(), json!(true));
    }
    if let Some(k) = ev.count_threshold {
        o.insert("countThreshold".into(), json!(k));
    }
    o.insert("listed".into(), json!(ev.listed));
    if let Some(a) = &ev.accessibility {
        o.insert("accessibility".into(), a.clone());
    }
    if !ev.suggested_reminder_minutes.is_empty() {
        o.insert(
            "suggestedReminderMinutes".into(),
            json!(ev.suggested_reminder_minutes),
        );
    }
    if !hosts.is_empty() {
        o.insert("hosts".into(), json!(hosts));
    }
    if ev.invite != invitations::InviteMode::None {
        o.insert("invite".into(), json!(ev.invite.as_str()));
    }
    if ev.members_may_invite {
        o.insert("membersMayInvite".into(), json!(true));
    }
    if let Some(id) = &ev.identity {
        // The authority's expiry is the hosts' to see (VTI-EVT-142).
        let mut identity = json!({ "did": id.did });
        if host {
            identity["authorityValidUntil"] = json!(stamp(id.authority.valid_until));
        }
        o.insert("identity".into(), identity);
    }
    if ev.guests != GuestAdmission::None {
        o.insert("guests".into(), json!(ev.guests.as_str()));
    }
    if ev.tickets {
        o.insert("tickets".into(), json!(true));
    }
    if let Some(c) = ev.counts_attendance {
        o.insert("countsAttendance".into(), json!(c));
    }
    if let Some(b) = &ev.attendance_badge {
        o.insert("attendanceBadge".into(), json!(b));
    }
    let going = places_taken(regs);
    if let Some(c) = count_for(ev, going, host) {
        o.insert("goingCount".into(), c);
    }
    let settings = ev.settings();
    if let Some(cap) = settings.capacity {
        o.insert("full".into(), json!(going >= cap));
    }
    o.insert("sequence".into(), json!(ev.sequence));
    if let Some(r) = &ev.cancel_reason {
        o.insert("cancelReason".into(), json!(r));
    }
    if let Some(t) = ev.published_at {
        o.insert("publishedAt".into(), json!(stamp(t)));
    }
    if let Some(t) = ev.cancelled_at {
        o.insert("cancelledAt".into(), json!(stamp(t)));
    }
    o.insert("createdAt".into(), json!(stamp(ev.created_at)));
    o.insert("updatedAt".into(), json!(stamp(ev.updated_at)));
    Value::Object(o)
}

/// `Registration` in full: the registrant's and the hosts' view (VTI-EVT-053).
#[must_use]
pub fn registration_wire(reg: &Registration, regs: &[Registration]) -> Value {
    let mut o = Map::new();
    o.insert("registrationId".into(), json!(reg.registration_id));
    o.insert("eventId".into(), json!(reg.event_id));
    match &reg.registrant_did {
        Some(did) => o.insert("registrantDid".into(), json!(did)),
        None => o.insert("entryId".into(), json!(reg.entry_id)),
    };
    o.insert("status".into(), json!(reg.status.as_str()));
    o.insert("guests".into(), json!(reg.guests));
    if let Some(a) = &reg.answers {
        o.insert("answers".into(), a.clone());
    }
    if let Some(c) = &reg.code_of_conduct_acknowledged {
        o.insert("codeOfConductAcknowledged".into(), json!(c));
    }
    if reg.status == RegStatus::Waitlisted
        && let Some(p) = waitlist_position(regs, &reg.registration_id)
    {
        o.insert("waitlistPosition".into(), json!(p));
    }
    o.insert("roster".into(), json!(reg.roster.as_str()));
    o.insert("eventSequence".into(), json!(reg.event_sequence));
    if let Some(n) = &reg.note {
        o.insert("note".into(), json!(n));
    }
    o.insert("createdAt".into(), json!(stamp(reg.created_at)));
    o.insert("updatedAt".into(), json!(stamp(reg.updated_at)));
    Value::Object(o)
}

/// What another registrant sees of one on a `visible` roster (VTI-EVT-053).
#[must_use]
pub fn roster_item(reg: &Registration) -> Value {
    json!({
        "entryId": reg.entry_id,
        "status": reg.status.as_str(),
        "guests": reg.guests,
    })
}

/// `EventRef`: what a receipt says of the event (VTI-EVT-092).
#[must_use]
pub fn event_ref(ev: &EventRecord) -> Value {
    let mut r = json!({
        "eventId": ev.event_id,
        "title": ev.title,
        "when": serde_json::to_value(&ev.when).unwrap_or(Value::Null),
        "status": ev.status.as_str(),
        "sequence": ev.sequence,
    });
    // What a registrant's agent needs to remind and to show where, without reading the event
    // itself (VTI-CAL-041, VTI-CAL-011): the hosts' suggested reminders and the coarse place.
    if !ev.suggested_reminder_minutes.is_empty() {
        r["suggestedReminderMinutes"] = json!(ev.suggested_reminder_minutes);
    }
    if let Some(p) = &ev.place_summary {
        r["placeSummary"] = json!(p);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse_as_jscalendar_states_them() {
        assert_eq!(parse_duration("PT1H30M"), Some(Duration::minutes(90)));
        assert_eq!(parse_duration("P1D"), Some(Duration::days(1)));
        assert_eq!(parse_duration("P2W"), Some(Duration::weeks(2)));
        assert_eq!(
            parse_duration("P1DT2H"),
            Some(Duration::days(1) + Duration::hours(2))
        );
        for bad in ["P", "PT", "1H", "PT1H1H", "PM1T", "P1M", "PT30M1H", "P1DT"] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
    }

    fn when(start: &str, tz: &str, duration: &str) -> When {
        When {
            start: start.into(),
            time_zone: tz.into(),
            duration: duration.into(),
            show_without_time: None,
        }
    }

    /// VTI-EVT-005: local time in its zone, so London in winter is UTC and in summer an hour
    /// ahead.
    #[test]
    fn vti_evt_005_local_time_is_read_in_its_zone() {
        let (s, e) = when("2026-11-30T18:30:00", "Europe/London", "PT1H30M")
            .interval()
            .unwrap();
        assert_eq!(stamp(s), "2026-11-30T18:30:00Z");
        assert_eq!(stamp(e), "2026-11-30T20:00:00Z");
        let (s, _) = when("2026-07-01T18:30:00", "Europe/London", "PT1H")
            .interval()
            .unwrap();
        assert_eq!(stamp(s), "2026-07-01T17:30:00Z");
    }

    /// A skipped local time moves forward; a repeated one takes the first (RFC 5545 §3.3.5).
    #[test]
    fn vti_evt_005_daylight_saving_gaps_and_folds() {
        // Clocks go forward at 01:00 on 29 March 2026 in London: 01:30 does not exist.
        let (s, _) = when("2026-03-29T01:30:00", "Europe/London", "PT1H")
            .interval()
            .unwrap();
        assert_eq!(stamp(s), "2026-03-29T01:00:00Z");
        // Clocks go back at 02:00 on 25 October 2026: 01:30 happens twice; the first is BST.
        let (s, _) = when("2026-10-25T01:30:00", "Europe/London", "PT1H")
            .interval()
            .unwrap();
        assert_eq!(stamp(s), "2026-10-25T00:30:00Z");
    }

    #[test]
    fn vti_evt_005_unknown_zones_and_all_day_shape_are_refused() {
        assert_eq!(
            when("2026-11-30T18:30:00", "Mars/Olympus", "PT1H").interval(),
            Err(WhenError::TimeZoneUnknown("Mars/Olympus".into()))
        );
        let mut w = when("2026-11-30T09:00:00", "Europe/London", "P1D");
        w.show_without_time = Some(true);
        assert!(matches!(w.interval(), Err(WhenError::Invalid(_))));
        let mut w = when("2026-11-30T00:00:00", "Europe/London", "PT5H");
        w.show_without_time = Some(true);
        assert!(matches!(w.interval(), Err(WhenError::Invalid(_))));
        let mut w = when("2026-11-30T00:00:00", "Europe/London", "P2D");
        w.show_without_time = Some(true);
        assert!(w.interval().is_ok());
    }

    fn reg(id: &str, status: RegStatus, guests: u32, at: i64) -> Registration {
        let t = DateTime::from_timestamp(1_800_000_000 + at, 0).unwrap();
        Registration {
            registration_id: id.into(),
            event_id: "evt_x".into(),
            entry_id: format!("dir_{id}"),
            registrant_did: None,
            status,
            guests,
            answers: None,
            code_of_conduct_acknowledged: None,
            waitlisted_at: (status == RegStatus::Waitlisted).then_some(t),
            roster: Roster::Hidden,
            event_sequence: 0,
            note: None,
            guest: false,
            checked_in: None,
            ticket: None,
            created_at: t,
            updated_at: t,
        }
    }

    fn event_with(registration: Value) -> EventRecord {
        let t = Utc::now();
        EventRecord {
            event_id: "evt_x".into(),
            calendar_id: "cal_x".into(),
            kind: "event".into(),
            status: Lifecycle::Published,
            title: "t".into(),
            description: None,
            when: when("2026-11-30T18:30:00", "Europe/London", "PT1H"),
            place_summary: None,
            access: None,
            audience: json!({ "scope": "members" }),
            registration,
            roster: Roster::Hidden,
            show_count: false,
            count_threshold: None,
            listed: true,
            accessibility: None,
            suggested_reminder_minutes: Vec::new(),
            invite: Default::default(),
            members_may_invite: false,
            sequence: 3,
            cancel_reason: None,
            published_at: None,
            cancelled_at: None,
            created_at: t,
            updated_at: t,
            identity: None,
            guests: Default::default(),
            tickets: false,
            counts_attendance: None,
            attendance_badge: None,
            created_by: "dir_creator".into(),
        }
    }

    /// VTI-EVT-033: places count plus-ones; maybe holds none; the waitlist moves in order, each
    /// that fits.
    #[test]
    fn vti_evt_033_capacity_and_the_waitlist() {
        let ev = event_with(json!({ "mode": "open", "capacity": 4, "waitlist": true }));
        let regs = vec![
            reg("a", RegStatus::Going, 1, 0),
            reg("b", RegStatus::Maybe, 3, 1),
            reg("c", RegStatus::Waitlisted, 2, 2),
            reg("d", RegStatus::Waitlisted, 0, 3),
            reg("e", RegStatus::Waitlisted, 0, 4),
        ];
        assert_eq!(places_taken(&regs), 2);
        assert_eq!(waitlist_position(&regs, "d"), Some(2));
        let moved = promote(&ev, &regs, Utc::now());
        // c (3 people) does not fit beside 2 going; d and e do, in order.
        let ids: Vec<&str> = moved.iter().map(|r| r.registration_id.as_str()).collect();
        assert_eq!(ids, ["d", "e"]);
        assert!(
            moved
                .iter()
                .all(|r| r.status == RegStatus::Going && r.event_sequence == 3)
        );
    }

    /// VTI-CAL-041: the receipt's and `mine/list`'s `EventRef` carries the hosts' suggested
    /// reminders and the place hint, so a registrant's agent need not read the event; neither
    /// appears when the event has none.
    #[test]
    fn vti_cal_041_event_ref_carries_reminders_and_place() {
        let mut ev = event_with(json!({ "mode": "open" }));
        let bare = event_ref(&ev);
        assert!(bare.get("suggestedReminderMinutes").is_none());
        assert!(bare.get("placeSummary").is_none());
        ev.suggested_reminder_minutes = vec![1440, 60];
        ev.place_summary = Some("Central London".into());
        let r = event_ref(&ev);
        assert_eq!(r["suggestedReminderMinutes"], json!([1440, 60]));
        assert_eq!(r["placeSummary"], json!("Central London"));
    }

    /// VTI-EVT-054: hosts see the exact count; others only with `showCount`, and below the
    /// threshold as `fewerThan`.
    #[test]
    fn vti_evt_054_counts_below_the_threshold_are_not_exact() {
        let mut ev = event_with(json!({ "mode": "open" }));
        assert_eq!(count_for(&ev, 3, true), Some(json!({ "exact": 3 })));
        assert_eq!(count_for(&ev, 3, false), None);
        ev.show_count = true;
        assert_eq!(count_for(&ev, 3, false), Some(json!({ "fewerThan": 5 })));
        assert_eq!(count_for(&ev, 5, false), Some(json!({ "exact": 5 })));
        ev.count_threshold = Some(10);
        assert_eq!(count_for(&ev, 9, false), Some(json!({ "fewerThan": 10 })));
    }
}
