//! Event mode: the exception to the constant drip, and the conditions that keep it survivable.
//!
//! A vetter's ordinary rate is a few tokens a tick, whether or not they have vetted anyone. That
//! is the right rate for ordinary weeks and the wrong one for a conference desk. Event mode is
//! the answer, and §5.1 is careful that it is **not** a bigger drip under the same key: it is a
//! separate token label for a named event, with its own rate, its own expiry, and a group of
//! vetters large enough that a spend under it still hides one.
//!
//! What this module holds is the community's half: the record of who asked, and the gate that
//! decides whether the event's label may be drawn under at all. Four conditions, every one of
//! them checked here rather than assumed from the configuration:
//!
//! 1. **An approver has named themselves**, and is not one of the vetters in the group. Raising
//!    your own cap is exactly what a coerced vetter would be made to do.
//! 2. **The group is at least `group_floor`.** An event key with one holder is a name; with two
//!    it is a coin flip.
//! 3. **The day is inside the window**, up to `closes_after`. The label dying shortly after the
//!    event is what stops a three-day burst becoming a month-long stockpile.
//! 4. **This member asked.** Membership of the group is what a member requested for themselves,
//!    never what a configuration says about them.
//!
//! The wire is `vtc/vetting/vetters/event-mode/0.1`, served by [`super::pcs_tasks`]; the request
//! it carries is only ever a request. Approval is an act by an admin of the community, through
//! the criterion that publishes the event — deliberately not a Trust Task, because a task the
//! vetter could send is a task a vetter could be made to send.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use vti_common::error::AppError;

use super::pcs::{HiddenVettingConfig, HiddenVettingEvent};
use crate::server::AppState;

/// What the community recorded when a vetter asked to be in an event. One row per member per
/// event; its existence is the membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventRequestRecord {
    /// The tier the vetter picked from the published menu.
    pub tier: String,
    /// The days they expect to be vetting, inside the event's own.
    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
    pub requested_at: DateTime<Utc>,
}

/// Where a vetter's request stands, as the task reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventState {
    /// Recorded, waiting for an approver or for the floor.
    Pending,
    /// The label is live and this vetter may draw under it.
    Approved,
}

impl EventState {
    /// The wire word.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
        }
    }
}

/// Length-framed, so an event id ending in what looks like a DID cannot read as part of one.
fn request_key(event_id: &str, member_did: &str) -> Vec<u8> {
    let mut key = group_prefix(event_id);
    key.extend_from_slice(member_did.as_bytes());
    key
}

/// Every request for one event sorts under this.
fn group_prefix(event_id: &str) -> Vec<u8> {
    format!("pcs-event:{}:{event_id}:", event_id.len()).into_bytes()
}

/// Record a vetter's request to be in an event.
///
/// The record is written with `insert_if_absent`, which is what makes `alreadyRequested` a rule
/// rather than a race: a second request neither overwrites the tier of the first nor counts
/// twice towards the floor.
///
/// # Errors
///
/// [`AppError::Forbidden`] when the member holds no live vetter grant; [`AppError::Validation`]
/// for an unknown event or tier, a window outside the event's own, an event whose label has
/// already closed, or a member who has already asked.
pub async fn request(
    state: &AppState,
    config: &HiddenVettingConfig,
    member_did: &str,
    event_id: &str,
    tier: &str,
    window: (NaiveDate, NaiveDate),
    now: DateTime<Utc>,
) -> Result<(EventState, usize, HiddenVettingEvent), AppError> {
    if !super::vetter_eligible(state, member_did, "vetter", now).await? {
        return Err(AppError::Forbidden(format!(
            "{member_did} holds no live vetter grant in this community"
        )));
    }
    let event = config
        .events
        .iter()
        .find(|e| e.event_id == event_id)
        .ok_or_else(|| {
            AppError::NotFound(format!("this community is running no event `{event_id}`"))
        })?
        .clone();

    if event.tier(tier).is_none() {
        return Err(AppError::Validation(format!(
            "`{tier}` is not a tier `{event_id}` publishes"
        )));
    }
    if now.date_naive() > event.closes_after() {
        return Err(AppError::Conflict(format!(
            "event `{event_id}` closed after {}",
            event.closes_after()
        )));
    }
    let (from, until) = window;
    if until < from || from < event.start_date || until > event.end_date {
        return Err(AppError::Validation(format!(
            "a window of {from}..={until} is not inside `{event_id}`, which runs {}..={}",
            event.start_date, event.end_date
        )));
    }

    let written = state
        .vetting_pcs_issue_ks
        .insert_if_absent(
            request_key(event_id, member_did),
            &EventRequestRecord {
                tier: tier.to_string(),
                start_date: from,
                end_date: until,
                requested_at: now,
            },
        )
        .await?;
    if !written {
        return Err(AppError::Conflict(format!(
            "{member_did} has already asked to be in `{event_id}`"
        )));
    }

    let size = group_size(state, event_id).await?;
    let state_now = match gate(state, config, member_did, &event.label(), now).await {
        Ok(()) => EventState::Approved,
        Err(_) => EventState::Pending,
    };
    Ok((state_now, size, event))
}

/// How many vetters have asked to be in this event.
///
/// A count, never a list. Who else is at the event **is** the anonymity set, so the number is the
/// most a member may be told about it — enough to tell "nobody has approved it" from "not enough
/// people have asked", which are the two reasons a request sits pending.
///
/// # Errors
///
/// Whatever the store returns.
pub async fn group_size(state: &AppState, event_id: &str) -> Result<usize, AppError> {
    Ok(state
        .vetting_pcs_issue_ks
        .prefix_keys(group_prefix(event_id))
        .await?
        .len())
}

/// Whether `member_did` has asked to vet at `event_id` — the self-approval check publish makes
/// before it stores an approval, the same one [`gate`] makes at every draw.
///
/// # Errors
///
/// Whatever the store returns.
pub async fn has_asked(
    state: &AppState,
    event_id: &str,
    member_did: &str,
) -> Result<bool, AppError> {
    Ok(state
        .vetting_pcs_issue_ks
        .get::<EventRequestRecord>(request_key(event_id, member_did))
        .await?
        .is_some())
}

/// Whether `label` is an event label, and if so which event it names.
#[must_use]
pub fn event_of<'a>(
    config: &'a HiddenVettingConfig,
    label: &str,
) -> Option<&'a HiddenVettingEvent> {
    let id = label.strip_prefix("token/event/")?;
    config.events.iter().find(|e| e.event_id == id)
}

/// The gate a drip under an event label passes before anything is signed.
///
/// A plain `Ok(())` for a label that names no event this community runs: the ordinary monthly
/// labels do not come through here, and a label that merely *looks* like an event's is caught by
/// the live-label check that precedes it.
///
/// # Errors
///
/// [`AppError::Forbidden`] when the event is not open to this member — unapproved, self-approved,
/// under the floor, closed, or a member who never asked. The message says which, because a vetter
/// waiting on a desk needs to know whether to chase an approver or a colleague.
pub async fn gate(
    state: &AppState,
    config: &HiddenVettingConfig,
    member_did: &str,
    label: &str,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let Some(event) = event_of(config, label) else {
        return Ok(());
    };
    let today = now.date_naive();
    if today > event.closes_after() {
        return Err(AppError::Forbidden(format!(
            "event `{}` closed after {}",
            event.event_id,
            event.closes_after()
        )));
    }
    let Some(approver) = event.approved_by.as_deref() else {
        return Err(AppError::Forbidden(format!(
            "event `{}` has not been approved",
            event.event_id
        )));
    };
    // An approver who is themselves in the group has approved their own cap, whoever else is in
    // it. Checked here rather than at approval time because approval is a configuration edit,
    // and a configuration edit is what a coerced approver would be asked for.
    if state
        .vetting_pcs_issue_ks
        .get::<EventRequestRecord>(request_key(&event.event_id, approver))
        .await?
        .is_some()
    {
        return Err(AppError::Forbidden(format!(
            "event `{}` was approved by a vetter in its own group",
            event.event_id
        )));
    }
    if state
        .vetting_pcs_issue_ks
        .get::<EventRequestRecord>(request_key(&event.event_id, member_did))
        .await?
        .is_none()
    {
        return Err(AppError::Forbidden(format!(
            "{member_did} did not ask to be in event `{}`",
            event.event_id
        )));
    }
    let size = group_size(state, &event.event_id).await?;
    if size < event.group_floor {
        return Err(AppError::Forbidden(format!(
            "event `{}` has {size} vetter(s) and this community's floor is {}",
            event.event_id, event.group_floor
        )));
    }
    Ok(())
}

/// The rate an event label drips at: the tier this member asked for, not the community's ordinary
/// rate and not the largest tier on the menu.
///
/// Falls back to `config.drip_per_tick` for a label naming no event, which is every ordinary
/// draw.
///
/// # Errors
///
/// Whatever the store returns.
pub async fn quota(
    state: &AppState,
    config: &HiddenVettingConfig,
    member_did: &str,
    label: &str,
) -> Result<usize, AppError> {
    let Some(event) = event_of(config, label) else {
        return Ok(config.drip_per_tick);
    };
    let Some(row) = state
        .vetting_pcs_issue_ks
        .get::<EventRequestRecord>(request_key(&event.event_id, member_did))
        .await?
    else {
        return Ok(config.drip_per_tick);
    };
    Ok(event
        .tier(&row.tier)
        .map_or(config.drip_per_tick, |t| t.drip_per_tick))
}
