//! The member's calendar (`vta/calendar/*/0.1`, VTI-CAL-001 – 071, dtgwg-vti-spec
//! `10b-vta-calendar.md`).
//!
//! The VTA gathers its principal's events from every community they belong to into one
//! calendar, per trust context:
//!
//! - **mine** — events the principal holds a registration for, read from each community with
//!   `vtc/events/mine/list/0.2` signed as the membership identifier held there and no other
//!   (VTI-CAL-011), incrementally by `updatedSince` (VTI-CAL-012), and only where the context's
//!   `sync` setting is on (VTI-CAL-010, off until the principal chooses);
//! - **notified** — events the VTA holds only an `event` notification for (VTI-NTF-064 – 067),
//!   shown only as the notification states them, never opened by the VTA (VTI-CAL-021).
//!
//! It keeps the community's signed replies as receipts, exactly as received (VTI-CAL-030),
//! fires reminders itself and wakes the principal's devices with no content (VTI-CAL-040 – 043),
//! serves iCalendar feeds as a subscription interface addressed by a bearer token kept only as a
//! digest (VTI-CAL-050 – 055, VTI-OPS-111 – 113), and records the principal's choice to share
//! busy times with a booking page (VTI-CAL-060).
//!
//! Everything is kept in the `calendar` keyspace, keyed by trust context; nothing held in one
//! context is answered to a caller without authority in it (VTI-CAL-001, VTI-CAL-002).

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, NaiveDateTime, NaiveTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::auth::AuthClaims;
use crate::server::AppState;

/// The type a community's own-registrations read is (VTI-CAL-011).
pub const MINE_LIST_TYPE: &str =
    <vti_specs::vtc::events::mine::list::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The most feeds one VTA keeps live (`feeds/create:limitReached`).
pub const MAX_LIVE_FEEDS: usize = 32;
/// How far ahead busy times are ever shared (VTI-CAL-061).
pub const BUSY_HORIZON_DAYS: i64 = 90;

static WRITE_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn new_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    use base64::Engine as _;
    format!(
        "{prefix}_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

fn hex_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// ─── records ─────────────────────────────────────────────────────────────

/// `VtaCalendarQuietHours`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuietHours {
    pub starts_at: String,
    pub ends_at: String,
    pub time_zone: String,
}

impl QuietHours {
    /// Whether `at` falls in the quiet period (VTI-CAL-042), and when it ends.
    #[must_use]
    pub fn covers(&self, at: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let tz: chrono_tz::Tz = self.time_zone.parse().ok()?;
        let start = NaiveTime::parse_from_str(&self.starts_at, "%H:%M").ok()?;
        let end = NaiveTime::parse_from_str(&self.ends_at, "%H:%M").ok()?;
        let local = at.with_timezone(&tz);
        let date = local.date_naive();
        // The period that could contain `at`: started today, or (past midnight) yesterday.
        for start_date in [date, date.pred_opt()?] {
            let s = start_date.and_time(start);
            let e = if end > start {
                start_date.and_time(end)
            } else {
                start_date.succ_opt()?.and_time(end)
            };
            let s = tz.from_local_datetime(&s).earliest()?.with_timezone(&Utc);
            let e = tz.from_local_datetime(&e).earliest()?.with_timezone(&Utc);
            if s <= at && at < e {
                return Some(e);
            }
        }
        None
    }

    /// Well formed: both clocks parse, the zone is known and the period is not empty.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.time_zone.parse::<chrono_tz::Tz>().is_ok()
            && NaiveTime::parse_from_str(&self.starts_at, "%H:%M").is_ok()
            && NaiveTime::parse_from_str(&self.ends_at, "%H:%M").is_ok()
            && self.starts_at != self.ends_at
    }
}

/// A context's calendar settings (VTI-CAL-070).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub context_id: String,
    pub sync: bool,
    pub default_reminder_minutes: Vec<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiet_hours: Option<QuietHours>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
}

impl Settings {
    #[must_use]
    pub fn default_for(context: &str) -> Self {
        Self {
            context_id: context.to_string(),
            sync: false,
            default_reminder_minutes: Vec::new(),
            quiet_hours: None,
            updated_at: None,
            updated_by: None,
        }
    }

    #[must_use]
    pub fn to_wire(&self) -> Value {
        let mut v = json!({
            "contextId": self.context_id,
            "sync": self.sync,
            "defaultReminderMinutes": self.default_reminder_minutes,
        });
        if let Some(q) = &self.quiet_hours {
            v["quietHours"] = json!(q);
        }
        if let Some(t) = self.updated_at {
            v["updatedAt"] = json!(stamp(t));
        }
        if let Some(b) = &self.updated_by {
            v["updatedBy"] = json!(b);
        }
        v
    }
}

/// One `mine` entry: an event and the principal's registration as its community last answered
/// them (VTI-CAL-013).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub context_id: String,
    pub community: String,
    pub identifier: String,
    pub event_id: String,
    /// `EventRef` as received.
    pub event: Value,
    /// `Registration` as received.
    pub registration: Value,
    pub read_at: DateTime<Utc>,
    /// The reminder offsets already fired, for the sequence they were computed from.
    #[serde(default)]
    pub fired_sequence: u64,
    #[serde(default)]
    pub fired: Vec<u32>,
}

impl Entry {
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.event
            .get("sequence")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    }
    #[must_use]
    pub fn status(&self) -> &str {
        self.registration
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("")
    }
    #[must_use]
    pub fn cancelled(&self) -> bool {
        self.event.get("status").and_then(Value::as_str) == Some("cancelled")
    }
    /// The instants the event runs, from its local start, zone and duration.
    #[must_use]
    pub fn period(&self) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
        period_of(self.event.get("when")?)
    }
    /// A reminder may fire for it (VTI-CAL-040).
    #[must_use]
    pub fn remindable(&self) -> bool {
        matches!(self.status(), "going" | "maybe") && !self.cancelled()
    }
}

/// JSCalendar `when` as instants: local `start` in `timeZone`, plus `duration`.
#[must_use]
pub fn period_of(when: &Value) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let tz: chrono_tz::Tz = when.get("timeZone")?.as_str()?.parse().ok()?;
    let local =
        NaiveDateTime::parse_from_str(when.get("start")?.as_str()?, "%Y-%m-%dT%H:%M:%S").ok()?;
    let duration = parse_duration(when.get("duration")?.as_str()?)?;
    let mut start = None;
    for step in 0..=16 {
        match tz.from_local_datetime(&(local + Duration::minutes(15 * step))) {
            chrono::LocalResult::Single(t) | chrono::LocalResult::Ambiguous(t, _) => {
                start = Some(t.with_timezone(&Utc));
                break;
            }
            chrono::LocalResult::None => {}
        }
    }
    let start = start?;
    Some((start, start + duration))
}

/// A JSCalendar duration (`P1W2DT3H4M5S`).
#[must_use]
pub fn parse_duration(s: &str) -> Option<Duration> {
    let rest = s.strip_prefix('P')?;
    let (date, time) = match rest.split_once('T') {
        Some((d, t)) if !t.is_empty() => (d, Some(t)),
        Some(_) => return None,
        None => (rest, None),
    };
    let mut total = 0i64;
    let mut take = |part: &str, units: &[(char, i64)]| -> Option<()> {
        let mut num = String::new();
        for c in part.chars() {
            if c.is_ascii_digit() {
                num.push(c);
            } else {
                let (_, secs) = units.iter().find(|(u, _)| *u == c)?;
                total += num.parse::<i64>().ok()? * secs;
                num.clear();
            }
        }
        num.is_empty().then_some(())
    };
    take(date, &[('W', 604_800), ('D', 86_400)])?;
    if let Some(t) = time {
        take(t, &[('H', 3_600), ('M', 60), ('S', 1)])?;
    }
    (!rest.is_empty()).then(|| Duration::seconds(total))
}

/// Where the VTA stands with one community: the last read it completed (VTI-CAL-012).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadMark {
    pub context_id: String,
    pub community: String,
    pub identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_read_at: Option<DateTime<Utc>>,
    /// The `updatedSince` the next read asks for: when the last completed read started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<DateTime<Utc>>,
}

/// The principal's own reminders for one event (VTI-CAL-041).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub context_id: String,
    pub community: String,
    pub event_id: String,
    pub reminder_minutes: Vec<u32>,
}

/// A feed (VTI-CAL-050 – 055). Its address is never kept: only its digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Feed {
    pub feed_id: String,
    pub label: String,
    pub context_ids: Vec<String>,
    pub detail: String,
    pub tiers: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_fetched_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub fetch_count: u64,
    /// Who created it, whose standing the feed's contexts follow (VTI-CAL-055).
    pub created_by: String,
    pub token_digest: String,
    /// Per-feed salt for event UIDs (VTI-CAL-053).
    pub uid_salt: String,
}

impl Feed {
    #[must_use]
    pub fn live(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }

    #[must_use]
    pub fn to_wire(&self) -> Value {
        let mut v = json!({
            "feedId": self.feed_id,
            "label": self.label,
            "contextIds": self.context_ids,
            "detail": self.detail,
            "tiers": self.tiers,
            "createdAt": stamp(self.created_at),
            "expiresAt": stamp(self.expires_at),
            "fetchCount": self.fetch_count,
        });
        if let Some(t) = self.revoked_at {
            v["revokedAt"] = json!(stamp(t));
        }
        if let Some(t) = self.last_fetched_at {
            v["lastFetchedAt"] = json!(stamp(t));
        }
        v
    }
}

/// A community's signed reply kept for the principal, exactly as received (VTI-CAL-030).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub receipt_id: String,
    pub context_id: String,
    pub community: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    pub reply_type: String,
    pub received_at: DateTime<Utc>,
    pub document: Value,
    pub document_digest: String,
}

impl Receipt {
    #[must_use]
    pub fn to_wire(&self) -> Value {
        let mut v = json!({
            "receiptId": self.receipt_id,
            "contextId": self.context_id,
            "community": self.community,
            "replyType": self.reply_type,
            "receivedAt": stamp(self.received_at),
            "document": self.document,
        });
        if let Some(e) = &self.event_id {
            v["eventId"] = json!(e);
        }
        v
    }
}

/// The principal's choice to share busy times with one booking page (VTI-CAL-060).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BusyShare {
    pub context_id: String,
    pub holder: String,
    pub page_id: String,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_shared_at: Option<DateTime<Utc>>,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}

impl BusyShare {
    #[must_use]
    pub fn to_wire(&self) -> Value {
        let mut v = json!({
            "contextId": self.context_id,
            "target": { "holder": self.holder, "pageId": self.page_id },
            "enabled": self.enabled,
        });
        if let Some(t) = self.last_shared_at {
            v["lastSharedAt"] = json!(stamp(t));
        }
        v
    }
}

// ─── storage ─────────────────────────────────────────────────────────────

fn set_key(ctx: &str) -> String {
    format!("set:{ctx}")
}
fn ent_prefix(ctx: &str) -> String {
    format!("ent:{ctx}\0")
}
fn ent_key(ctx: &str, community: &str, event: &str) -> String {
    format!("ent:{ctx}\0{community}\0{event}")
}
fn mark_key(ctx: &str, community: &str) -> String {
    format!("mark:{ctx}\0{community}")
}
fn alert_key(ctx: &str, community: &str, event: &str) -> String {
    format!("alert:{ctx}\0{community}\0{event}")
}
fn feed_key(id: &str) -> String {
    format!("feed:{id}")
}
fn feed_digest_key(digest: &str) -> String {
    format!("feeddig:{digest}")
}
fn rcpt_prefix(ctx: &str) -> String {
    format!("rcpt:{ctx}\0")
}
fn rcpt_key(ctx: &str, id: &str) -> String {
    format!("rcpt:{ctx}\0{id}")
}
fn rcpt_digest_key(ctx: &str, digest: &str) -> String {
    format!("rcptdig:{ctx}\0{digest}")
}
fn busy_prefix(ctx: &str) -> String {
    format!("busy:{ctx}\0")
}
fn busy_key(ctx: &str, holder: &str, page: &str) -> String {
    format!("busy:{ctx}\0{holder}\0{page}")
}

async fn values<T: serde::de::DeserializeOwned>(
    ks: &KeyspaceHandle,
    prefix: String,
) -> Result<Vec<T>, AppError> {
    Ok(ks
        .prefix_iter_raw(prefix)
        .await?
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect())
}

/// # Errors
/// A store failure.
pub async fn settings(ks: &KeyspaceHandle, ctx: &str) -> Result<Settings, AppError> {
    Ok(ks
        .get::<Settings>(set_key(ctx))
        .await?
        .unwrap_or_else(|| Settings::default_for(ctx)))
}

/// # Errors
/// A store failure.
pub async fn put_settings(ks: &KeyspaceHandle, s: &Settings) -> Result<(), AppError> {
    ks.insert(set_key(&s.context_id), s).await
}

/// # Errors
/// A store failure.
pub async fn entries(ks: &KeyspaceHandle, ctx: &str) -> Result<Vec<Entry>, AppError> {
    values(ks, ent_prefix(ctx)).await
}

/// # Errors
/// A store failure.
pub async fn alert(
    ks: &KeyspaceHandle,
    ctx: &str,
    community: &str,
    event: &str,
) -> Result<Option<Alert>, AppError> {
    ks.get(alert_key(ctx, community, event)).await
}

/// # Errors
/// A store failure.
pub async fn feeds(ks: &KeyspaceHandle) -> Result<Vec<Feed>, AppError> {
    values(ks, "feed:".into()).await
}

/// # Errors
/// A store failure.
pub async fn receipts(ks: &KeyspaceHandle, ctx: &str) -> Result<Vec<Receipt>, AppError> {
    values(ks, rcpt_prefix(ctx)).await
}

/// # Errors
/// A store failure.
pub async fn busy_shares(ks: &KeyspaceHandle, ctx: &str) -> Result<Vec<BusyShare>, AppError> {
    values(ks, busy_prefix(ctx)).await
}

// ─── standing ────────────────────────────────────────────────────────────

/// The contexts `auth` has standing in, among those named — or, with none named, every context
/// this VTA has (VTI-CAL-002). A named context without standing is dropped silently: a listing
/// never says another context holds anything.
///
/// # Errors
/// A store failure.
pub async fn contexts_for(
    state: &AppState,
    auth: &AuthClaims,
    named: Option<&[String]>,
) -> Result<Vec<String>, AppError> {
    let mut out: Vec<String> = match named {
        Some(n) => n.to_vec(),
        None => vta_support::contexts::list_contexts(&state.contexts_ks)
            .await?
            .into_iter()
            .map(|c| c.id)
            .collect(),
    };
    out.retain(|c| auth.has_context_access(c));
    out.sort();
    out.dedup();
    Ok(out)
}

// ─── reminders (VTI-CAL-040 – 042) ───────────────────────────────────────

/// Where an entry's reminders come from, and the offsets (VTI-CAL-041): the principal's alert
/// for the event, else the offsets the event suggests (`suggestedReminderMinutes` on the
/// `EventRef` that `vtc/events/mine/list` answered), else the context's default.
#[must_use]
pub fn reminders_for(
    entry: &Entry,
    alert: Option<&Alert>,
    settings: &Settings,
) -> (&'static str, Vec<u32>) {
    if !entry.remindable() {
        return ("none", Vec::new());
    }
    if let Some(a) = alert {
        return if a.reminder_minutes.is_empty() {
            ("none", Vec::new())
        } else {
            ("alert", a.reminder_minutes.clone())
        };
    }
    let suggested: Vec<u32> = entry
        .event
        .get("suggestedReminderMinutes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_u64)
                .filter_map(|n| u32::try_from(n).ok())
                .collect()
        })
        .unwrap_or_default();
    if !suggested.is_empty() {
        return ("event", suggested);
    }
    if settings.default_reminder_minutes.is_empty() {
        ("none", Vec::new())
    } else {
        ("default", settings.default_reminder_minutes.clone())
    }
}

/// The reminders due at `now` for an entry: offsets whose time has come, not yet fired for the
/// event's current sequence, outside quiet hours; one held by quiet hours fires when they end,
/// or not at all if the event has started by then (VTI-CAL-042).
#[must_use]
pub fn due_reminders(
    entry: &Entry,
    offsets: &[u32],
    quiet: Option<&QuietHours>,
    now: DateTime<Utc>,
) -> Vec<u32> {
    let Some((start, _)) = entry.period() else {
        return Vec::new();
    };
    if now >= start {
        return Vec::new();
    }
    let fired: BTreeSet<u32> = if entry.fired_sequence == entry.sequence() {
        entry.fired.iter().copied().collect()
    } else {
        BTreeSet::new()
    };
    let mut due: Vec<u32> = offsets
        .iter()
        .copied()
        .filter(|o| !fired.contains(o))
        .filter(|o| start - Duration::minutes(i64::from(*o)) <= now)
        .collect();
    if !due.is_empty() && quiet.and_then(|q| q.covers(now)).is_some() {
        due.clear();
    }
    due.sort_unstable_by(|a, b| b.cmp(a));
    due
}

// ─── busy times (VTI-CAL-061) ────────────────────────────────────────────

/// Busy intervals from `periods`: merged, widened to whole quarter hours, no further than
/// ninety days ahead of `now`, and nothing else.
#[must_use]
pub fn busy_intervals(
    periods: &[(DateTime<Utc>, DateTime<Utc>)],
    now: DateTime<Utc>,
) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
    let horizon = now + Duration::days(BUSY_HORIZON_DAYS);
    let q = 900i64;
    let floor = |t: DateTime<Utc>| {
        DateTime::from_timestamp(t.timestamp().div_euclid(q) * q, 0).unwrap_or(t)
    };
    let ceil = |t: DateTime<Utc>| {
        let s = t.timestamp();
        let c = if s.rem_euclid(q) == 0 && t.timestamp_subsec_nanos() == 0 {
            s
        } else {
            (s.div_euclid(q) + 1) * q
        };
        DateTime::from_timestamp(c, 0).unwrap_or(t)
    };
    let mut v: Vec<(DateTime<Utc>, DateTime<Utc>)> = periods
        .iter()
        .filter(|(s, e)| *e > now && *s < horizon)
        .map(|(s, e)| (floor((*s).max(now)), ceil((*e).min(horizon))))
        .collect();
    v.sort();
    let mut merged: Vec<(DateTime<Utc>, DateTime<Utc>)> = Vec::new();
    for (s, e) in v {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    merged
}

// ─── the listing (VTI-CAL-020 – 023) ─────────────────────────────────────

/// One listed entry, in either tier.
#[derive(Debug, Clone)]
pub struct Listed {
    pub context_id: String,
    pub community: String,
    pub event_id: String,
    pub tier: &'static str,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub wire: Value,
}

/// The notified tier of `ctx`: held `event` notifications (VTI-CAL-020), shown only as they
/// state themselves — community, event, period — withdrawn ones as withdrawn (VTI-CAL-022).
async fn notified(state: &AppState, ctx: &str) -> Result<Vec<Listed>, AppError> {
    let rows = state
        .notifications_ks
        .prefix_iter_raw(format!("held:{ctx}\0"))
        .await?;
    let mut out = Vec::new();
    for (_, raw) in rows {
        let Ok(rec) = serde_json::from_slice::<crate::operations::notifications::HeldRecord>(&raw)
        else {
            continue;
        };
        if rec.context_id != ctx || rec.kind != vta_sdk::notifications::KIND_EVENT {
            continue;
        }
        let n = &rec.notification;
        let at = |k: &str| {
            n.get(k)
                .and_then(Value::as_str)
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|t| t.with_timezone(&Utc))
        };
        let (Some(start), Some(end)) = (at("validFrom"), at("validUntil")) else {
            continue;
        };
        let (Some(community), Some(event_id)) = (
            n.pointer("/subject/heldBy").and_then(Value::as_str),
            n.pointer("/subject/id").and_then(Value::as_str),
        ) else {
            continue;
        };
        let mut wire = json!({
            "contextId": ctx,
            "community": community,
            "eventId": event_id,
            "tier": "notified",
            "period": { "startsAt": stamp(start), "endsAt": stamp(end) },
            "identifier": rec.addressee,
            "notificationRecordId": rec.record_id,
            "reminderSource": "none",
        });
        if rec.withdrawn {
            wire["withdrawn"] = json!(true);
        }
        out.push(Listed {
            context_id: ctx.to_string(),
            community: community.to_string(),
            event_id: event_id.to_string(),
            tier: "notified",
            start,
            end,
            wire,
        });
    }
    Ok(out)
}

/// The mine tier of `ctx`.
async fn mine(state: &AppState, ctx: &str) -> Result<Vec<Listed>, AppError> {
    let ks = &state.calendar_ks;
    let settings = settings(ks, ctx).await?;
    let mut out = Vec::new();
    for e in entries(ks, ctx).await? {
        let Some((start, end)) = e.period() else {
            continue;
        };
        let a = alert(ks, ctx, &e.community, &e.event_id).await?;
        let (source, reminders) = reminders_for(&e, a.as_ref(), &settings);
        let mut wire = json!({
            "contextId": ctx,
            "community": e.community,
            "eventId": e.event_id,
            "tier": "mine",
            "period": { "startsAt": stamp(start), "endsAt": stamp(end) },
            "identifier": e.identifier,
            "event": e.event,
            "reminders": reminders,
            "reminderSource": source,
            "readAt": stamp(e.read_at),
        });
        if let Some(s) = e.registration.get("status") {
            wire["registrationStatus"] = s.clone();
        }
        out.push(Listed {
            context_id: ctx.to_string(),
            community: e.community.clone(),
            event_id: e.event_id.clone(),
            tier: "mine",
            start,
            end,
            wire,
        });
    }
    Ok(out)
}

/// Every entry of `contexts` in `[from, to)` of the tiers asked for, earliest start first, with
/// overlaps marked among them only (VTI-CAL-023).
///
/// # Errors
/// A store failure.
pub async fn list(
    state: &AppState,
    contexts: &[String],
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    tiers: &[String],
) -> Result<Vec<Listed>, AppError> {
    let want = |t: &str| tiers.is_empty() || tiers.iter().any(|x| x == t);
    let mut all = Vec::new();
    for ctx in contexts {
        if want("mine") {
            all.extend(mine(state, ctx).await?);
        }
        if want("notified") {
            all.extend(notified(state, ctx).await?);
        }
    }
    all.retain(|l| l.end > from && l.start < to);
    all.sort_by(|a, b| {
        (a.start, &a.community, &a.event_id).cmp(&(b.start, &b.community, &b.event_id))
    });
    // Overlaps among live entries only: a withdrawn notification or a cancelled event is no
    // commitment (VTI-CAL-022).
    let live = |l: &Listed| {
        l.wire.get("withdrawn").and_then(Value::as_bool) != Some(true)
            && l.wire.pointer("/event/status").and_then(Value::as_str) != Some("cancelled")
    };
    let n = all.len();
    let mut overlaps = vec![false; n];
    for i in 0..n {
        for j in (i + 1)..n {
            if all[j].start >= all[i].end {
                break;
            }
            if live(&all[i]) && live(&all[j]) {
                overlaps[i] = true;
                overlaps[j] = true;
            }
        }
    }
    for (l, o) in all.iter_mut().zip(overlaps) {
        if o {
            l.wire["overlaps"] = json!(true);
        }
    }
    Ok(all)
}

// ─── reading communities (VTI-CAL-010 – 014) ─────────────────────────────

/// One community the principal holds a membership of in `ctx`, and the identifier the
/// membership is held under (VTI-CAL-011).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Membership {
    pub community: String,
    pub identifier: String,
}

/// The memberships held in `ctx`: membership credentials in the vault, live, in that context,
/// one identifier per community (the first, deterministically).
///
/// # Errors
/// A store failure.
pub async fn memberships(state: &AppState, ctx: &str) -> Result<Vec<Membership>, AppError> {
    let scope = vta_sdk::acl::ActScope::Contexts(vec![ctx.to_string()]);
    let query = vta_vault::query::CredentialQuery {
        r#type: Some("MembershipCredential".into()),
        ..Default::default()
    };
    let found = vta_vault::query::search(&state.vault_ks, &query, &scope).await?;
    let mut by_community: BTreeMap<String, String> = BTreeMap::new();
    for d in found {
        if matches!(
            d.status,
            vta_vault::model::CredentialStatus::Revoked
                | vta_vault::model::CredentialStatus::Expired
        ) {
            continue;
        }
        let Some(full) = vta_vault::storage::get(&state.vault_ks, &d.id).await? else {
            continue;
        };
        if full.context_id.as_deref() != Some(ctx) {
            continue;
        }
        let (Some(subject), Some(community)) = (
            full.subject_did.clone(),
            full.community_did.clone().or(full.issuer_did.clone()),
        ) else {
            continue;
        };
        by_community
            .entry(community)
            .and_modify(|s| {
                if subject < *s {
                    s.clone_from(&subject);
                }
            })
            .or_insert(subject);
    }
    Ok(by_community
        .into_iter()
        .map(|(community, identifier)| Membership {
            community,
            identifier,
        })
        .collect())
}

/// How one community's read went (`VtaCalendarSyncResult`).
#[derive(Debug, Clone)]
pub struct SyncResult {
    pub context_id: String,
    pub community: String,
    pub status: &'static str,
    pub changed: u64,
    pub last_read_at: Option<DateTime<Utc>>,
    pub code: Option<String>,
}

impl SyncResult {
    #[must_use]
    pub fn to_wire(&self) -> Value {
        let mut v = json!({
            "contextId": self.context_id,
            "community": self.community,
            "status": self.status,
        });
        if self.status == "read" {
            v["changed"] = json!(self.changed);
        }
        if let Some(t) = self.last_read_at {
            v["lastReadAt"] = json!(stamp(t));
        }
        if let Some(c) = &self.code {
            v["code"] = json!(c);
        }
        v
    }
}

/// The authority a background read acts under: an administrator of exactly the context the
/// identifier's key lives in, as room list redelivery acts (`room_list_delivery::acting_as`).
fn acting_as(ctx: &str) -> AuthClaims {
    AuthClaims {
        did: "internal:calendar-sync".into(),
        role: vti_common::acl::Role::Admin,
        allowed_contexts: vec![ctx.to_string()],
        session_id: "internal:calendar-sync".into(),
        ..Default::default()
    }
}

/// What reading one community answered.
enum ReadOutcome {
    Items(Vec<(Value, Value)>),
    Refused(String),
    Unavailable(String),
}

/// One `vtc/events/mine/list/0.2` read, paged to the end, signed as `m.identifier` and sent to
/// `m.community` (VTI-CAL-011, 012).
async fn read_community(
    state: &AppState,
    auth: &AuthClaims,
    m: &Membership,
    since: Option<DateTime<Utc>>,
) -> Result<ReadOutcome, AppError> {
    let Some(resolver) = state.did_resolver.as_ref() else {
        return Ok(ReadOutcome::Unavailable(
            "this VTA has no DID resolver".into(),
        ));
    };
    let out = crate::operations::outbound::Outbound::from_app_state(state, resolver);
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..50 {
        let mut payload = json!({ "limit": 100 });
        if let Some(t) = since {
            payload["updatedSince"] = json!(stamp(t));
        }
        if let Some(c) = &cursor {
            payload["cursor"] = json!(c);
        }
        let doc = crate::operations::room_host::build_room_task(
            MINE_LIST_TYPE,
            &m.community,
            &m.identifier,
            payload,
        );
        let signed = crate::operations::room_act::sign_as(state, auth, &m.identifier, doc).await?;
        let reply = match out
            .send(
                &m.community,
                signed,
                crate::operations::outbound::ReplyTrust::SignedByRecipient,
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return Ok(ReadOutcome::Unavailable(e.to_string())),
        };
        let ty = reply.get("type").and_then(Value::as_str).unwrap_or("");
        if ty != format!("{MINE_LIST_TYPE}#response") {
            let code = reply
                .pointer("/payload/code")
                .and_then(Value::as_str)
                .unwrap_or("refused")
                .to_string();
            return Ok(ReadOutcome::Refused(code));
        }
        let p = reply.get("payload").cloned().unwrap_or(Value::Null);
        if serde_json::from_value::<vti_specs::vtc::events::mine::list::v0_2::Response>(p.clone())
            .is_err()
        {
            return Ok(ReadOutcome::Refused("responseInvalid".into()));
        }
        for it in p
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            if let (Some(r), Some(e)) = (it.get("registration"), it.get("event")) {
                items.push((r.clone(), e.clone()));
            }
        }
        match p.get("nextCursor").and_then(Value::as_str) {
            Some(c) => cursor = Some(c.to_string()),
            None => return Ok(ReadOutcome::Items(items)),
        }
    }
    Ok(ReadOutcome::Items(items))
}

/// Read every community of `ctx` once (VTI-CAL-010 – 013). `auth` decides the identifiers the
/// VTA may sign as; a context whose `sync` is off is answered `notSyncing` and read not at all.
///
/// # Errors
/// A store failure.
pub async fn sync_context(
    state: &AppState,
    ctx: &str,
    now: DateTime<Utc>,
) -> Result<Vec<SyncResult>, AppError> {
    let ks = &state.calendar_ks;
    let s = settings(ks, ctx).await?;
    let members = memberships(state, ctx).await?;
    if !s.sync {
        return Ok(members
            .into_iter()
            .map(|m| SyncResult {
                context_id: ctx.to_string(),
                community: m.community,
                status: "notSyncing",
                changed: 0,
                last_read_at: None,
                code: None,
            })
            .collect());
    }
    let auth = acting_as(ctx);
    let mut results = Vec::new();
    for m in members {
        let mark = ks
            .get::<ReadMark>(mark_key(ctx, &m.community))
            .await?
            // A changed identifier starts afresh: what was read as another is not this one's.
            .filter(|r| r.identifier == m.identifier);
        let since = mark.as_ref().and_then(|r| r.since);
        let started = now;
        let outcome = read_community(state, &auth, &m, since).await?;
        let (status, changed, code) = match outcome {
            ReadOutcome::Items(items) => {
                let _g = WRITE_LOCK.lock().await;
                let mut changed = 0u64;
                for (registration, event) in items {
                    let Some(event_id) = event.get("eventId").and_then(Value::as_str) else {
                        continue;
                    };
                    let key = ent_key(ctx, &m.community, event_id);
                    let prior = ks.get::<Entry>(key.clone()).await?;
                    let mut entry = Entry {
                        context_id: ctx.to_string(),
                        community: m.community.clone(),
                        identifier: m.identifier.clone(),
                        event_id: event_id.to_string(),
                        event,
                        registration,
                        read_at: now,
                        fired_sequence: 0,
                        fired: Vec::new(),
                    };
                    // VTI-CAL-013: a later answer replaces; reminders computed from an
                    // earlier sequence go with it.
                    if let Some(p) = prior {
                        if p.sequence() == entry.sequence() {
                            entry.fired_sequence = p.fired_sequence;
                            entry.fired = p.fired;
                        }
                        if p.event == entry.event && p.registration == entry.registration {
                            entry.read_at = p.read_at;
                            ks.insert(key, &entry).await?;
                            continue;
                        }
                    }
                    ks.insert(key, &entry).await?;
                    changed += 1;
                }
                ks.insert(
                    mark_key(ctx, &m.community),
                    &ReadMark {
                        context_id: ctx.to_string(),
                        community: m.community.clone(),
                        identifier: m.identifier.clone(),
                        last_read_at: Some(now),
                        since: Some(started - Duration::seconds(60)),
                    },
                )
                .await?;
                ("read", changed, None)
            }
            ReadOutcome::Refused(c) => ("refused", 0, Some(c)),
            ReadOutcome::Unavailable(why) => {
                tracing::debug!(community = %m.community, %why, "calendar read unavailable");
                ("unavailable", 0, None)
            }
        };
        let last = ks
            .get::<ReadMark>(mark_key(ctx, &m.community))
            .await?
            .and_then(|r| r.last_read_at);
        results.push(SyncResult {
            context_id: ctx.to_string(),
            community: m.community,
            status,
            changed,
            last_read_at: last,
            code,
        });
    }
    Ok(results)
}

// ─── settings, alerts, shares ────────────────────────────────────────────

/// Apply a settings change, recording who made it (VTI-CAL-070).
///
/// # Errors
/// A store failure.
pub async fn update_settings(
    state: &AppState,
    ctx: &str,
    by: &str,
    sync: Option<bool>,
    default_reminder_minutes: Option<Vec<u32>>,
    quiet_hours: Option<Option<QuietHours>>,
    now: DateTime<Utc>,
) -> Result<Settings, AppError> {
    let _g = WRITE_LOCK.lock().await;
    let ks = &state.calendar_ks;
    let mut s = settings(ks, ctx).await?;
    if let Some(v) = sync {
        s.sync = v;
    }
    if let Some(v) = default_reminder_minutes {
        s.default_reminder_minutes = v;
    }
    if let Some(v) = quiet_hours {
        s.quiet_hours = v;
    }
    s.updated_at = Some(now);
    s.updated_by = Some(by.to_string());
    put_settings(ks, &s).await?;
    Ok(s)
}

/// Whether the VTA holds an entry for the event, in either tier.
///
/// # Errors
/// A store failure.
pub async fn holds_event(
    state: &AppState,
    ctx: &str,
    community: &str,
    event: &str,
) -> Result<bool, AppError> {
    if state
        .calendar_ks
        .get::<Entry>(ent_key(ctx, community, event))
        .await?
        .is_some()
    {
        return Ok(true);
    }
    Ok(notified(state, ctx)
        .await?
        .iter()
        .any(|l| l.community == community && l.event_id == event))
}

/// # Errors
/// A store failure.
pub async fn set_alert(state: &AppState, a: &Alert) -> Result<(), AppError> {
    state
        .calendar_ks
        .insert(alert_key(&a.context_id, &a.community, &a.event_id), a)
        .await
}

/// `true` where there was an alert to clear.
///
/// # Errors
/// A store failure.
pub async fn clear_alert(
    state: &AppState,
    ctx: &str,
    community: &str,
    event: &str,
) -> Result<bool, AppError> {
    let key = alert_key(ctx, community, event);
    let had = state.calendar_ks.get::<Alert>(key.clone()).await?.is_some();
    if had {
        state.calendar_ks.remove(key).await?;
    }
    Ok(had)
}

/// # Errors
/// A store failure.
pub async fn set_busy_share(state: &AppState, s: &BusyShare) -> Result<(), AppError> {
    state
        .calendar_ks
        .insert(busy_key(&s.context_id, &s.holder, &s.page_id), s)
        .await
}

/// # Errors
/// A store failure.
pub async fn busy_share(
    state: &AppState,
    ctx: &str,
    holder: &str,
    page: &str,
) -> Result<Option<BusyShare>, AppError> {
    state.calendar_ks.get(busy_key(ctx, holder, page)).await
}

// ─── feeds (VTI-CAL-050 – 055, VTI-OPS-111 – 113) ────────────────────────

/// A new feed and the token its address carries — 256 bits, returned once, kept only as a
/// digest (VTI-CAL-051).
///
/// # Errors
/// A store failure.
pub async fn create_feed(
    state: &AppState,
    created_by: &str,
    label: &str,
    contexts: Vec<String>,
    detail: &str,
    tiers: Vec<String>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(Feed, String), AppError> {
    let mut raw = [0u8; 32];
    rand::fill(&mut raw);
    let token = hex::encode(raw);
    let mut salt = [0u8; 16];
    rand::fill(&mut salt);
    let feed = Feed {
        feed_id: new_id("feed"),
        label: label.to_string(),
        context_ids: contexts,
        detail: detail.to_string(),
        tiers,
        created_at: now,
        expires_at,
        revoked_at: None,
        last_fetched_at: None,
        fetch_count: 0,
        created_by: created_by.to_string(),
        token_digest: hex_digest(token.as_bytes()),
        uid_salt: hex::encode(salt),
    };
    let ks = &state.calendar_ks;
    ks.insert_raw(
        feed_digest_key(&feed.token_digest),
        feed.feed_id.clone().into_bytes(),
    )
    .await?;
    ks.insert(feed_key(&feed.feed_id), &feed).await?;
    Ok((feed, token))
}

/// # Errors
/// A store failure.
pub async fn get_feed(state: &AppState, id: &str) -> Result<Option<Feed>, AppError> {
    state.calendar_ks.get(feed_key(id)).await
}

/// # Errors
/// A store failure.
pub async fn put_feed(state: &AppState, f: &Feed) -> Result<(), AppError> {
    state.calendar_ks.insert(feed_key(&f.feed_id), f).await
}

/// The feed a token opens, if live; `None` alike for unknown, revoked and expired
/// (VTI-CAL-052). Records the read (VTI-CAL-054).
///
/// # Errors
/// A store failure.
pub async fn open_feed(
    state: &AppState,
    token: &str,
    now: DateTime<Utc>,
) -> Result<Option<Feed>, AppError> {
    let ks = &state.calendar_ks;
    let digest = hex_digest(token.as_bytes());
    let Some(id) = ks
        .get_raw(feed_digest_key(&digest))
        .await?
        .and_then(|b| String::from_utf8(b).ok())
    else {
        return Ok(None);
    };
    let _g = WRITE_LOCK.lock().await;
    let Some(mut feed) = ks.get::<Feed>(feed_key(&id)).await? else {
        return Ok(None);
    };
    if !feed.live(now) || feed.token_digest != digest {
        return Ok(None);
    }
    feed.last_fetched_at = Some(now);
    feed.fetch_count += 1;
    ks.insert(feed_key(&feed.feed_id), &feed).await?;
    Ok(Some(feed))
}

/// The contexts a feed still covers: those whose standing its creator keeps (VTI-CAL-055).
///
/// # Errors
/// A store failure.
pub async fn feed_contexts(state: &AppState, feed: &Feed) -> Result<Vec<String>, AppError> {
    let Some(entry) = crate::acl::get_acl_entry(&state.acl_ks, &feed.created_by).await? else {
        return Ok(Vec::new());
    };
    let now = vti_common::auth::session::now_epoch();
    if entry.is_expired(now) {
        return Ok(Vec::new());
    }
    let scope = entry.act_scope();
    Ok(feed
        .context_ids
        .iter()
        .filter(|c| scope.covers(c))
        .cloned()
        .collect())
}

fn ics_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace('\n', "\\n")
}

fn ics_time(t: DateTime<Utc>) -> String {
    t.format("%Y%m%dT%H%M%SZ").to_string()
}

/// An iCalendar object of `listed`, carrying only what `detail` admits (VTI-CAL-053): titles
/// and times by default, never access details, registrants, receipts or an identifier of the
/// principal; a notified entry only as busy time. Event UIDs are derived from `uid_salt` and
/// the event, so they differ between feeds.
#[must_use]
pub fn to_ics(listed: &[Listed], detail: &str, uid_salt: &str, now: DateTime<Utc>) -> String {
    let mut out = String::from(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//OpenVTC//VTA calendar//EN\r\nCALSCALE:GREGORIAN\r\n",
    );
    for l in listed {
        if l.wire.get("withdrawn").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let uid = hex_digest(format!("{uid_salt}\0{}\0{}", l.community, l.event_id).as_bytes());
        out.push_str("BEGIN:VEVENT\r\n");
        out.push_str(&format!("UID:{}@vta-calendar\r\n", &uid[..32]));
        out.push_str(&format!("DTSTAMP:{}\r\n", ics_time(now)));
        out.push_str(&format!("DTSTART:{}\r\n", ics_time(l.start)));
        out.push_str(&format!("DTEND:{}\r\n", ics_time(l.end)));
        let title = l
            .wire
            .pointer("/event/title")
            .and_then(Value::as_str)
            .filter(|_| l.tier == "mine" && detail != "busy");
        match title {
            Some(t) => out.push_str(&format!("SUMMARY:{}\r\n", ics_escape(t))),
            None => out.push_str("SUMMARY:Busy\r\nTRANSP:OPAQUE\r\nCLASS:CONFIDENTIAL\r\n"),
        }
        // A feed that admits places carries the event's coarse hint, never an address (the
        // community never puts one there, VTI-EVT-062).
        if detail == "titlesAndPlaces"
            && l.tier == "mine"
            && let Some(place) = l
                .wire
                .pointer("/event/placeSummary")
                .and_then(Value::as_str)
        {
            out.push_str(&format!("LOCATION:{}\r\n", ics_escape(place)));
        }
        if l.wire.pointer("/event/status").and_then(Value::as_str) == Some("cancelled") {
            out.push_str("STATUS:CANCELLED\r\n");
        }
        out.push_str("END:VEVENT\r\n");
    }
    out.push_str("END:VCALENDAR\r\n");
    out
}

// ─── receipts (VTI-CAL-030 – 032) ────────────────────────────────────────

/// Why a deposited receipt was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReceiptError {
    /// Not a community's reply to a registration, a withdrawal, a decision or an answer.
    NotAReply(String),
    /// Addressed to no identifier this VTA holds in the context.
    NotAddressed,
    /// The proof does not verify as the issuer's.
    ProofInvalid(String),
    Store(AppError),
}

/// The reply types a receipt may be (VTI-EVT-092, VTI-CAL-030).
fn receipt_type(ty: &str) -> bool {
    let bare = ty.strip_suffix("#response").unwrap_or("");
    [
        "/vtc/events/registrations/register/",
        "/vtc/events/registrations/withdraw/",
        "/vtc/events/registrations/decide/",
        "/vtc/events/registrations/remove/",
        "/vtc/events/invitations/respond/",
    ]
    .iter()
    .any(|p| bare.contains(p))
}

/// Keep `document` as a receipt in `ctx`: a community's signed reply about a registration,
/// addressed to an identifier this VTA holds in `ctx`, proof verified as the issuer's.
/// A document already kept answers the receipt kept, `true`.
///
/// # Errors
/// See [`ReceiptError`].
pub async fn deposit_receipt(
    state: &AppState,
    ctx: &str,
    document: &Value,
    now: DateTime<Utc>,
) -> Result<(Receipt, bool), ReceiptError> {
    let ty = document.get("type").and_then(Value::as_str).unwrap_or("");
    if !receipt_type(ty) {
        return Err(ReceiptError::NotAReply(format!(
            "`{ty}` is not a community's reply about a registration"
        )));
    }
    let issuer = document
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| ReceiptError::NotAReply("the reply names no issuer".into()))?
        .to_string();
    let recipient = document
        .get("recipient")
        .and_then(Value::as_str)
        .ok_or(ReceiptError::NotAddressed)?;
    let holds = crate::operations::persona::persona_signing_key(
        crate::operations::persona::PersonaStores::from_state(state),
        &AuthClaims {
            did: "internal:calendar-receipt".into(),
            role: vti_common::acl::Role::Admin,
            allowed_contexts: vec![ctx.to_string()],
            session_id: "internal:calendar-receipt".into(),
            ..Default::default()
        },
        recipient,
    )
    .await
    .map_err(ReceiptError::Store)?
    .is_some();
    if !holds {
        return Err(ReceiptError::NotAddressed);
    }
    let signer =
        vti_common::auth::verify_trust_task_proof_value(document, &state.trust_task_vm_resolver())
            .await
            .map_err(|e| ReceiptError::ProofInvalid(e.to_string()))?;
    if signer.split('#').next() != Some(issuer.as_str()) {
        return Err(ReceiptError::ProofInvalid(
            "the proof is not the issuer's".into(),
        ));
    }
    let bytes = serde_json::to_vec(document).map_err(|e| ReceiptError::Store(e.into()))?;
    let digest = hex_digest(&bytes);
    let ks = &state.calendar_ks;
    let _g = WRITE_LOCK.lock().await;
    if let Some(id) = ks
        .get_raw(rcpt_digest_key(ctx, &digest))
        .await
        .map_err(ReceiptError::Store)?
        .and_then(|b| String::from_utf8(b).ok())
        && let Some(r) = ks
            .get::<Receipt>(rcpt_key(ctx, &id))
            .await
            .map_err(ReceiptError::Store)?
    {
        return Ok((r, true));
    }
    let receipt = Receipt {
        receipt_id: new_id("rcpt"),
        context_id: ctx.to_string(),
        community: issuer,
        event_id: document
            .pointer("/payload/event/eventId")
            .and_then(Value::as_str)
            .map(str::to_string),
        reply_type: ty.to_string(),
        received_at: now,
        document: document.clone(),
        document_digest: digest.clone(),
    };
    ks.insert_raw(
        rcpt_digest_key(ctx, &digest),
        receipt.receipt_id.clone().into_bytes(),
    )
    .await
    .map_err(ReceiptError::Store)?;
    ks.insert(rcpt_key(ctx, &receipt.receipt_id), &receipt)
        .await
        .map_err(ReceiptError::Store)?;
    Ok((receipt, false))
}

// ─── the sweepers ────────────────────────────────────────────────────────

/// One reminder pass: every remindable entry of every context, firing what is due and waking
/// the principal's devices once if anything fired (VTI-CAL-040 – 043). Returns the reminders
/// fired. The one retry owner of reminders: a wake that does not reach a device is not
/// retried — the reminder stays visible in the calendar the device reads.
///
/// # Errors
/// A store failure.
pub async fn remind_once(state: &AppState, now: DateTime<Utc>) -> Result<usize, AppError> {
    let ks = &state.calendar_ks;
    let mut fired_total = 0;
    let mut contexts_fired: BTreeSet<String> = BTreeSet::new();
    for c in vta_support::contexts::list_contexts(&state.contexts_ks).await? {
        let ctx = c.id;
        let s = settings(ks, &ctx).await?;
        for mut e in entries(ks, &ctx).await? {
            let a = alert(ks, &ctx, &e.community, &e.event_id).await?;
            let (_, offsets) = reminders_for(&e, a.as_ref(), &s);
            let due = due_reminders(&e, &offsets, s.quiet_hours.as_ref(), now);
            if due.is_empty() {
                continue;
            }
            let _g = WRITE_LOCK.lock().await;
            if e.fired_sequence != e.sequence() {
                e.fired.clear();
                e.fired_sequence = e.sequence();
            }
            e.fired.extend(due.iter().copied());
            ks.insert(ent_key(&ctx, &e.community, &e.event_id), &e)
                .await?;
            fired_total += due.len();
            contexts_fired.insert(ctx.clone());
        }
    }
    for ctx in contexts_fired {
        crate::trust_tasks::wake_devices_in_context(state, &ctx).await;
    }
    Ok(fired_total)
}

/// Remove `context`'s calendar — settings, entries, read marks, alerts, receipts, sharing
/// choices — and take it out of every feed, deleting a feed left covering nothing. A context
/// created again under the id starts with an empty calendar and sync off. Returns the rows
/// removed.
///
/// # Errors
/// A store failure.
pub async fn purge_context(ks: &KeyspaceHandle, context: &str) -> Result<usize, AppError> {
    let _g = WRITE_LOCK.lock().await;
    let mut removed = 0;
    let mut keys: Vec<Vec<u8>> = vec![set_key(context).into_bytes()];
    for prefix in [
        ent_prefix(context),
        format!("mark:{context}\0"),
        format!("alert:{context}\0"),
        rcpt_prefix(context),
        format!("rcptdig:{context}\0"),
        busy_prefix(context),
    ] {
        keys.extend(ks.prefix_keys(prefix).await?);
    }
    for k in keys {
        if ks.get_raw(k.clone()).await?.is_some() {
            ks.remove(k).await?;
            removed += 1;
        }
    }
    for (k, raw) in ks.prefix_iter_raw("feed:").await? {
        let Ok(mut feed) = serde_json::from_slice::<Feed>(&raw) else {
            continue;
        };
        if !feed.context_ids.iter().any(|c| c == context) {
            continue;
        }
        feed.context_ids.retain(|c| c != context);
        if feed.context_ids.is_empty() {
            ks.remove(feed_digest_key(&feed.token_digest)).await?;
            ks.remove(k).await?;
        } else {
            ks.insert(feed_key(&feed.feed_id), &feed).await?;
        }
        removed += 1;
    }
    Ok(removed)
}

/// Write `e` as a sync would have left it. Tests only.
///
/// # Errors
/// A store failure.
#[cfg(test)]
pub async fn put_entry(ks: &KeyspaceHandle, e: &Entry) -> Result<(), AppError> {
    ks.insert(ent_key(&e.context_id, &e.community, &e.event_id), e)
        .await
}

/// The calendar sweepers: reminders every minute, and a read of every syncing context every
/// fifteen minutes. The one retry owner of each: a community that did not answer is read
/// again next pass, and a reminder pass that failed is run again a minute later. Runs until
/// dropped — `server::run` selects it against shutdown.
pub async fn sweep_loop(state: AppState) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
    let mut passes = 0u64;
    loop {
        tick.tick().await;
        if let Err(e) = remind_once(&state, Utc::now()).await {
            tracing::warn!(error = %e, "calendar reminder pass failed; the next pass tries again");
        }
        if passes.is_multiple_of(15) {
            match vta_support::contexts::list_contexts(&state.contexts_ks).await {
                Ok(cs) => {
                    for c in cs {
                        if let Err(e) = sync_context(&state, &c.id, Utc::now()).await {
                            tracing::warn!(context = %c.id, error = %e, "calendar sync pass failed; the next pass tries again");
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "calendar sync could not list contexts"),
            }
        }
        passes = passes.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(start: &str, status: &str, sequence: u64) -> Entry {
        Entry {
            context_id: "ctx".into(),
            community: "did:example:c".into(),
            identifier: "did:example:me".into(),
            event_id: "evt_AAAAAAAAAAAAAAAA".into(),
            event: json!({
                "eventId": "evt_AAAAAAAAAAAAAAAA",
                "title": "Soldering night",
                "when": { "start": start, "timeZone": "Etc/UTC", "duration": "PT2H" },
                "status": "published",
                "sequence": sequence,
            }),
            registration: json!({ "status": status }),
            read_at: Utc::now(),
            fired_sequence: 0,
            fired: Vec::new(),
        }
    }

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    /// VTI-CAL-041: an alert beats the default; an empty alert removes reminders; a withdrawn
    /// registration or cancelled event is never reminded (VTI-CAL-040).
    #[test]
    fn vti_cal_041_reminder_offsets() {
        let e = entry("2026-12-01T18:00:00", "going", 1);
        let mut s = Settings::default_for("ctx");
        s.default_reminder_minutes = vec![60];
        assert_eq!(reminders_for(&e, None, &s), ("default", vec![60]));
        let a = Alert {
            context_id: "ctx".into(),
            community: e.community.clone(),
            event_id: e.event_id.clone(),
            reminder_minutes: vec![1440, 30],
        };
        assert_eq!(reminders_for(&e, Some(&a), &s), ("alert", vec![1440, 30]));
        let none = Alert {
            reminder_minutes: vec![],
            ..a
        };
        assert_eq!(reminders_for(&e, Some(&none), &s).0, "none");
        let w = entry("2026-12-01T18:00:00", "withdrawn", 1);
        assert_eq!(reminders_for(&w, None, &s).0, "none");
    }

    /// VTI-CAL-041: with no alert of the principal's, the event's own suggestion comes before
    /// the context's default; an alert still beats it.
    #[test]
    fn vti_cal_041_the_events_suggestion_comes_before_the_default() {
        let mut e = entry("2026-12-01T18:00:00", "going", 1);
        e.event["suggestedReminderMinutes"] = json!([1440, 60]);
        let mut s = Settings::default_for("ctx");
        s.default_reminder_minutes = vec![15];
        assert_eq!(reminders_for(&e, None, &s), ("event", vec![1440, 60]));
        let a = Alert {
            context_id: "ctx".into(),
            community: e.community.clone(),
            event_id: e.event_id.clone(),
            reminder_minutes: vec![30],
        };
        assert_eq!(reminders_for(&e, Some(&a), &s), ("alert", vec![30]));
        e.event["suggestedReminderMinutes"] = json!([]);
        assert_eq!(reminders_for(&e, None, &s), ("default", vec![15]));
    }

    /// VTI-CAL-041, 013: due offsets fire once per sequence; a new sequence re-arms them; an
    /// event that started fires nothing.
    #[test]
    fn vti_cal_013_due_once_per_sequence() {
        let mut e = entry("2026-12-01T18:00:00", "going", 1);
        let now = at("2026-12-01T17:10:00Z");
        assert_eq!(due_reminders(&e, &[1440, 60], None, now), vec![1440, 60]);
        e.fired_sequence = 1;
        e.fired = vec![1440, 60];
        assert!(due_reminders(&e, &[1440, 60], None, now).is_empty());
        e.event["sequence"] = json!(2);
        assert_eq!(due_reminders(&e, &[60], None, now), vec![60]);
        assert!(due_reminders(&e, &[60], None, at("2026-12-01T18:00:01Z")).is_empty());
    }

    /// VTI-CAL-042: nothing fires in quiet hours, including a period past midnight.
    #[test]
    fn vti_cal_042_quiet_hours() {
        let q = QuietHours {
            starts_at: "22:00".into(),
            ends_at: "07:00".into(),
            time_zone: "Etc/UTC".into(),
        };
        assert!(q.is_valid());
        assert_eq!(
            q.covers(at("2026-12-01T23:30:00Z")),
            Some(at("2026-12-02T07:00:00Z"))
        );
        assert_eq!(
            q.covers(at("2026-12-02T06:00:00Z")),
            Some(at("2026-12-02T07:00:00Z"))
        );
        assert_eq!(q.covers(at("2026-12-02T12:00:00Z")), None);
        let e = entry("2026-12-02T09:00:00", "going", 1);
        assert!(due_reminders(&e, &[720], Some(&q), at("2026-12-01T23:30:00Z")).is_empty());
        assert_eq!(
            due_reminders(&e, &[720], Some(&q), at("2026-12-02T07:00:00Z")),
            vec![720]
        );
    }

    /// VTI-CAL-061: merged, widened to quarter hours, ninety days at most.
    #[test]
    fn vti_cal_061_busy_coarsening() {
        let now = at("2026-12-01T00:00:00Z");
        let p = vec![
            (at("2026-12-01T09:05:00Z"), at("2026-12-01T09:40:00Z")),
            (at("2026-12-01T09:50:00Z"), at("2026-12-01T10:10:00Z")),
            (at("2026-12-01T13:00:00Z"), at("2026-12-01T13:30:00Z")),
            (at("2027-06-01T09:00:00Z"), at("2027-06-01T10:00:00Z")),
        ];
        let b = busy_intervals(&p, now);
        assert_eq!(
            b,
            vec![
                (at("2026-12-01T09:00:00Z"), at("2026-12-01T10:15:00Z")),
                (at("2026-12-01T13:00:00Z"), at("2026-12-01T13:30:00Z")),
            ]
        );
    }

    /// VTI-CAL-053: titles and times only; UIDs differ between feeds; busy detail drops titles.
    #[test]
    fn vti_cal_053_feed_content() {
        let e = entry("2026-12-01T18:00:00", "going", 1);
        let (start, end) = e.period().unwrap();
        let l = Listed {
            context_id: "ctx".into(),
            community: e.community.clone(),
            event_id: e.event_id.clone(),
            tier: "mine",
            start,
            end,
            wire: json!({ "event": e.event, "identifier": "did:example:me" }),
        };
        let now = Utc::now();
        let a = to_ics(std::slice::from_ref(&l), "titles", "salt-a", now);
        let b = to_ics(std::slice::from_ref(&l), "titles", "salt-b", now);
        assert!(a.contains("SUMMARY:Soldering night"));
        assert!(!a.contains("did:example"), "no identifier of the principal");
        let uid = |s: &str| {
            s.lines()
                .find(|l| l.starts_with("UID:"))
                .unwrap()
                .to_string()
        };
        assert_ne!(uid(&a), uid(&b));
        let busy = to_ics(&[l], "busy", "salt-a", now);
        assert!(busy.contains("SUMMARY:Busy") && !busy.contains("Soldering"));
    }

    /// VTI-CAL-041, 053: a `titlesAndPlaces` feed carries the event's place hint; a titles-only
    /// feed does not.
    #[test]
    fn vti_cal_041_places_only_in_a_feed_that_admits_them() {
        let mut e = entry("2026-12-01T18:00:00", "going", 1);
        e.event["placeSummary"] = json!("Mill Lane, Riverside");
        let (start, end) = e.period().unwrap();
        let l = Listed {
            context_id: "ctx".into(),
            community: e.community.clone(),
            event_id: e.event_id.clone(),
            tier: "mine",
            start,
            end,
            wire: json!({ "event": e.event }),
        };
        let now = Utc::now();
        let places = to_ics(std::slice::from_ref(&l), "titlesAndPlaces", "salt", now);
        assert!(
            places.contains("LOCATION:Mill Lane\\, Riverside\r\n"),
            "{places}"
        );
        let titles = to_ics(&[l], "titles", "salt", now);
        assert!(!titles.contains("LOCATION"), "{titles}");
    }
}
