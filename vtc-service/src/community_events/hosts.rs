//! Who hosts an event by appointment: `vtc.events.manage` qualified `event:<eventId>`, a
//! resource grant on the host's access-control entry (`vtc/events/hosts/{appoint,remove}`,
//! VTI-EVT-070 – 074), beside their role and never inside its ceiling, so a member with no
//! administrative role may hold it.
//!
//! The grant, its review when its granter departs or no longer covers it
//! (`acl.grants.review`, `eventGrants`), and its withdrawal are
//! [`crate::acl::appointment`]'s, shared with group managers and board facilitators.

use serde::{Deserialize, Serialize};
use tracing::warn;
use vti_common::error::AppError;

use crate::acl::appointment::{self, Held, Kind};
use crate::server::AppState;

const KIND: Kind = Kind::EventHost;

/// One grant under a granter's review, as the action item lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewItem {
    pub subject: String,
    pub event_id: String,
}

impl From<&ReviewItem> for Held {
    fn from(i: &ReviewItem) -> Self {
        Held {
            subject: i.subject.clone(),
            id: i.event_id.clone(),
        }
    }
}

fn held(items: &[ReviewItem]) -> Vec<Held> {
    items.iter().map(Held::from).collect()
}

/// Write `subject`'s appointment to host `event_id`, delegated by `granter`. The caller has
/// checked the granter covers it (VTI-EVT-071).
///
/// # Errors
/// A store failure, or no access-control entry for `subject`.
pub async fn appoint(
    state: &AppState,
    granter: &str,
    subject: &str,
    event_id: &str,
) -> Result<(), AppError> {
    appointment::appoint(state, KIND, granter, subject, event_id, None).await
}

/// Remove `subject`'s appointment to host `event_id`. `false`: they held none.
///
/// # Errors
/// A store failure.
pub async fn withdraw(state: &AppState, subject: &str, event_id: &str) -> Result<bool, AppError> {
    appointment::withdraw(state, KIND, subject, event_id).await
}

/// Remove every appointment to host `event_id`, as deleting a draft does.
///
/// # Errors
/// A store failure.
pub async fn withdraw_all(state: &AppState, event_id: &str) -> Result<usize, AppError> {
    appointment::withdraw_all(state, KIND, event_id).await
}

/// The entries appointed to host `event_id`, sorted. Holders of `vtc.events.manage` for the
/// whole community or the calendar's group run the event without being listed.
///
/// # Errors
/// A store failure.
pub async fn entries(state: &AppState, event_id: &str) -> Result<Vec<String>, AppError> {
    appointment::holder_entries(state, KIND, event_id).await
}

/// One pass over every event host's appointment ([`appointment::sweep`]): one review item per
/// granter who departed or no longer covers what they granted, and the appointments withdrawn
/// at its deadline (VTI-EVT-074). Returns the grants withdrawn.
///
/// # Errors
/// A store failure.
pub async fn sweep(state: &AppState) -> Result<usize, AppError> {
    let swept = appointment::sweep(state, KIND).await?;
    for (granter, items) in swept.raised {
        let items: Vec<ReviewItem> = items
            .into_iter()
            .map(|h| ReviewItem {
                subject: h.subject,
                event_id: h.id,
            })
            .collect();
        warn!(
            granter,
            grants = items.len(),
            "event host appointments are under review, and withdrawn unless re-affirmed \
             (VTI-ACL-071)"
        );
        if let Err(e) = crate::admin_actions::raise_event_grants_review(
            state,
            &granter,
            &items,
            swept.deadline.timestamp().max(0) as u64,
        )
        .await
        {
            warn!(granter, error = %e, "the event grants review could not be raised; the sweep still withdraws at the deadline");
        }
    }
    Ok(swept.withdrawn.len())
}

/// Re-affirm each listed appointment still under `granter`'s review under the first approver
/// whose own entry covers it, who becomes its granter.
///
/// # Errors
/// A store failure.
pub async fn reaffirm(
    state: &AppState,
    granter: &str,
    items: &[ReviewItem],
    approvers: &[String],
) -> Result<serde_json::Value, AppError> {
    appointment::reaffirm(state, KIND, granter, &held(items), approvers).await
}

/// Withdraw each listed appointment still under `granter`'s review, as a declined review does.
///
/// # Errors
/// A store failure.
pub async fn withdraw_reviewed(
    state: &AppState,
    granter: &str,
    items: &[ReviewItem],
) -> Result<(), AppError> {
    appointment::withdraw_reviewed(state, KIND, granter, &held(items)).await
}
