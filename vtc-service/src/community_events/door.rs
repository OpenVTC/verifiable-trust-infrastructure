//! The door (VTI-EVT-160 – 166) and attendance (VTI-EVT-180 – 186).
//!
//! # Door challenges
//!
//! Door staff ask the community for a challenge: 128 random bits, bound to the event, accepted
//! for [`CHALLENGE_TTL_SECS`] and never after (VTI-EVT-161). Only its SHA-256 digest is kept.
//! A challenge is not consumed by a check-in: the door shows one for a few minutes and every
//! registrant in front of it signs over the same value; it is the registrant's own signature,
//! made now, that proves they were there. A challenge this community did not issue, one for
//! another event and one past its time are refused alike (VTI-EVT-162).
//!
//! # Attendance
//!
//! A check-in is recorded against the registration (`attended`, VTI-EVT-165); nothing is ever
//! recorded of who did not come. A check-in that counts (VTI-EVT-181 – 183) adds one to the
//! member's tally for the event's calendar and month — `att:<entryId>:<calendarId>:<YYYY-MM>` —
//! which is what attendance is counted from, and all that survives the check-in records'
//! deletion (VTI-EVT-185).

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use chrono::{DateTime, Datelike, Duration, Utc};
use sha2::{Digest, Sha256};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::{Calendar, CheckIn, CheckInMethod, EventRecord, Registration, SelfCheckIn};
use crate::server::AppState;

/// How long a door challenge is accepted after it is issued (VTI-EVT-161: a stated short
/// time).
pub const CHALLENGE_TTL_SECS: i64 = 300;

fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn chal_key(event_id: &str, value: &str) -> String {
    format!("chal:{event_id}:{}", digest(value))
}

/// Issue a fresh challenge for `event_id` (VTI-EVT-161): its value and when it stops being
/// accepted.
///
/// # Errors
/// A store failure.
pub async fn issue_challenge(
    ks: &KeyspaceHandle,
    event_id: &str,
    now: DateTime<Utc>,
) -> Result<(String, DateTime<Utc>), AppError> {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    use base64::Engine as _;
    let value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let expires = now + Duration::seconds(CHALLENGE_TTL_SECS);
    ks.insert_raw(
        chal_key(event_id, &value),
        expires.timestamp().to_string().into_bytes(),
    )
    .await?;
    Ok((value, expires))
}

/// Whether `value` is a challenge this community issued for `event_id` and still accepts at
/// `now` (VTI-EVT-162).
///
/// # Errors
/// A store failure.
pub async fn challenge_accepted(
    ks: &KeyspaceHandle,
    event_id: &str,
    value: &str,
    now: DateTime<Utc>,
) -> Result<bool, AppError> {
    let Some(raw) = ks.get_raw(chal_key(event_id, value)).await? else {
        return Ok(false);
    };
    let expires = String::from_utf8(raw)
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    Ok(now.timestamp() < expires)
}

/// Remove challenges past their time.
///
/// # Errors
/// A store failure.
pub async fn sweep_challenges(ks: &KeyspaceHandle, now: DateTime<Utc>) -> Result<usize, AppError> {
    let mut removed = 0;
    for (key, raw) in ks.prefix_iter_raw(b"chal:".to_vec()).await? {
        let expires = String::from_utf8(raw)
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        if now.timestamp() >= expires {
            ks.remove(key).await?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Whether the event counts toward attendance: its own setting, else its calendar's, else yes
/// (VTI-EVT-180).
#[must_use]
pub fn event_counts(ev: &EventRecord, cal: Option<&Calendar>) -> bool {
    ev.counts_attendance
        .or_else(|| cal.and_then(|c| c.counts_attendance))
        .unwrap_or(true)
}

/// Whether a check-in by `method` for `reg` counts toward a member's attendance
/// (VTI-EVT-181 – 183): only a member's own registration, only an event that counts, and a
/// check-in without a challenge only where the calendar lets self check-in count.
#[must_use]
pub fn check_in_counts(
    ev: &EventRecord,
    cal: Option<&Calendar>,
    reg: &Registration,
    method: CheckInMethod,
) -> bool {
    if reg.registrant_did.is_some() || reg.guest {
        return false;
    }
    if !event_counts(ev, cal) {
        return false;
    }
    match method {
        CheckInMethod::Challenge | CheckInMethod::Staff => true,
        CheckInMethod::SelfCheckIn => cal.is_some_and(|c| c.self_check_in == SelfCheckIn::Counting),
    }
}

fn tally_key(entry_id: &str, calendar_id: &str, month: &str) -> String {
    format!("att:{entry_id}:{calendar_id}:{month}")
}

/// `YYYY-MM` of an instant.
#[must_use]
pub fn month_of(t: DateTime<Utc>) -> String {
    format!("{:04}-{:02}", t.year(), t.month())
}

/// Record `method`'s check-in on `reg`, and — where it counts — add it to the member's tally
/// for the event's calendar and the month the event starts in. The caller holds
/// `community_events::WRITE_LOCK` and has checked `reg` is `going` with no check-in yet.
///
/// # Errors
/// A store failure.
pub async fn record(
    ks: &KeyspaceHandle,
    ev: &EventRecord,
    cal: Option<&Calendar>,
    reg: &mut Registration,
    method: CheckInMethod,
    by: Option<String>,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let counts = check_in_counts(ev, cal, reg, method);
    reg.checked_in = Some(CheckIn {
        at: now,
        method,
        by,
        counts,
    });
    reg.updated_at = now;
    super::put_registration(ks, reg).await?;
    if counts {
        let start = ev.interval().map(|(s, _)| s).unwrap_or(now);
        let key = tally_key(&reg.entry_id, &ev.calendar_id, &month_of(start));
        let n = ks
            .get_raw(key.clone())
            .await?
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        ks.insert_raw(key, (n + 1).to_string().into_bytes()).await?;
    }
    Ok(())
}

/// One tally: a calendar, a month and the counting events attended in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tally {
    pub calendar_id: String,
    pub month: String,
    pub count: u64,
}

/// Every tally of `entry_id`'s attendance, oldest month first (VTI-EVT-185).
///
/// # Errors
/// A store failure.
pub async fn tallies(ks: &KeyspaceHandle, entry_id: &str) -> Result<Vec<Tally>, AppError> {
    let prefix = format!("att:{entry_id}:");
    let mut out = Vec::new();
    for (key, raw) in ks.prefix_iter_raw(prefix.as_bytes().to_vec()).await? {
        let Ok(key) = String::from_utf8(key) else {
            continue;
        };
        let Some(rest) = key.strip_prefix(&prefix) else {
            continue;
        };
        let Some((calendar_id, month)) = rest.split_once(':') else {
            continue;
        };
        let count = String::from_utf8(raw)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        out.push(Tally {
            calendar_id: calendar_id.to_string(),
            month: month.to_string(),
            count,
        });
    }
    out.sort_by(|a, b| (&a.month, &a.calendar_id).cmp(&(&b.month, &b.calendar_id)));
    Ok(out)
}

/// Events attended, from `tallies`, optionally only in `calendar_id` and only in months that
/// fall within `within_days` before `now` (VTI-EVT-184). A month counts when it began on or
/// after the cut-off's month: the tally keeps months, nothing finer (VTI-EVT-185).
#[must_use]
pub fn attended(
    tallies: &[Tally],
    calendar_id: Option<&str>,
    within_days: Option<u32>,
    now: DateTime<Utc>,
) -> u64 {
    let cutoff = within_days.map(|d| month_of(now - Duration::days(i64::from(d))));
    tallies
        .iter()
        .filter(|t| calendar_id.is_none_or(|c| t.calendar_id == c))
        .filter(|t| cutoff.as_deref().is_none_or(|c| t.month.as_str() >= c))
        .map(|t| t.count)
        .sum()
}

/// Offer `ev`'s attendance badge to the member checked in on `reg` (VTI-EVT-186), as an award
/// they accept or decline (VTI-BDG-020). Nothing is offered to a guest or a partner's member,
/// for a badge that is not an active community badge, while they hold an open offer of it, or
/// when it is not repeatable and they hold it. Returns the award offered.
///
/// # Errors
/// A store failure.
pub async fn offer_attendance_badge(
    state: &AppState,
    ev: &EventRecord,
    reg: &Registration,
    now: DateTime<Utc>,
) -> Result<Option<String>, AppError> {
    use crate::badges::{self, AwardState, BadgeKind, BadgeState};
    let Some(badge_id) = &ev.attendance_badge else {
        return Ok(None);
    };
    if reg.registrant_did.is_some() || reg.guest {
        return Ok(None);
    }
    let Some(badge) = badges::get_badge(&state.badges_ks, badge_id).await? else {
        return Ok(None);
    };
    if badge.kind != BadgeKind::Community || badge.state != BadgeState::Active {
        return Ok(None);
    }
    let _guard = badges::WRITE_LOCK.lock().await;
    let existing = badges::awards_of_badge(&state.badges_ks, badge_id).await?;
    let mine = existing.iter().filter(|a| a.entry_id == reg.entry_id);
    let mut open = false;
    let mut held = false;
    for a in mine {
        open |= a.is_open();
        held |= a.is_accepted();
    }
    if open || (held && !badge.repeatable) {
        return Ok(None);
    }
    let settings = badges::settings(&state.badges_ks).await?;
    let award = badges::Award {
        award_id: badges::new_award_id(),
        badge_id: badge_id.clone(),
        entry_id: reg.entry_id.clone(),
        given_by: None,
        note: Some(format!("Attended {}", ev.title)),
        state: AwardState::Offered,
        offered_at: now,
        decided_at: None,
        expires_at: settings
            .limits
            .offer_expires_after_days
            .map(|d| now + Duration::days(i64::from(d))),
        credential_id: None,
        revoke_reason: None,
        shared: None,
    };
    if let Some(writer) = state.audit_writer.as_ref() {
        let community = crate::notifications::own_did(state)
            .await
            .unwrap_or_default();
        writer
            .write(
                &community,
                None,
                vtc_audit::AuditEvent::BadgeChanged(vtc_audit::BadgeChangedData {
                    badge_id: badge_id.clone(),
                    award_id: Some(award.award_id.clone()),
                    entry_id: Some(reg.entry_id.clone()),
                    change: "offered".into(),
                    fields: vec![format!("event:{}", ev.event_id)],
                    group_id: None,
                }),
            )
            .await?;
    }
    badges::put_award(&state.badges_ks, &award).await?;
    Ok(Some(award.award_id))
}

// ─── guests' bound (VTI-EVT-154) ─────────────────────────────────────────

/// Operations one guest may send per hour. A guest has no standing in the community, so every
/// operation they send is bounded per guest identifier (VTI-EVT-154).
pub const GUEST_OPERATIONS_PER_HOUR: u32 = 30;

static GUEST_WINDOWS: LazyLock<Mutex<HashMap<String, (i64, u32)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Charge one operation to `guest_did`. `Err(retry_at)` when the hour's bound is spent.
pub fn charge_guest(guest_did: &str, now: DateTime<Utc>) -> Result<(), DateTime<Utc>> {
    let hour = now.timestamp() / 3600;
    let mut windows = GUEST_WINDOWS.lock().unwrap_or_else(|p| p.into_inner());
    // Bounded memory: forget past hours as they go.
    windows.retain(|_, (h, _)| *h == hour);
    let slot = windows.entry(guest_did.to_string()).or_insert((hour, 0));
    if slot.1 >= GUEST_OPERATIONS_PER_HOUR {
        return Err(DateTime::from_timestamp((hour + 1) * 3600, 0).unwrap_or(now));
    }
    slot.1 += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(m: &str, c: u64, cal: &str) -> Tally {
        Tally {
            calendar_id: cal.into(),
            month: m.into(),
            count: c,
        }
    }

    /// VTI-EVT-184, 185: counted from the monthly tally, by calendar and by window.
    #[test]
    fn vti_evt_184_attended_reads_the_monthly_tally() {
        let now = DateTime::parse_from_rfc3339("2026-12-15T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let tallies = vec![
            t("2026-01", 2, "cal_a"),
            t("2026-11", 3, "cal_a"),
            t("2026-12", 1, "cal_b"),
        ];
        assert_eq!(attended(&tallies, None, None, now), 6);
        assert_eq!(attended(&tallies, Some("cal_a"), None, now), 5);
        assert_eq!(attended(&tallies, None, Some(60), now), 4);
        assert_eq!(attended(&tallies, Some("cal_b"), Some(10), now), 1);
    }

    #[test]
    fn vti_evt_154_a_guest_is_bounded_per_hour() {
        let now = Utc::now();
        let did = format!("did:key:z6Mk{}", uuid::Uuid::new_v4().simple());
        for _ in 0..GUEST_OPERATIONS_PER_HOUR {
            assert!(charge_guest(&did, now).is_ok());
        }
        assert!(charge_guest(&did, now).is_err());
    }
}
