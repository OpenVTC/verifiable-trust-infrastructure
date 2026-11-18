//! Who manages a group: `vtc.groups.manage` qualified `group:<groupId>`, a
//! resource grant on the manager's access-control entry
//! (`vtc/groups/managers/{add,remove}`), beside their role and never inside its
//! ceiling, so a member with no administrative role may hold it.
//!
//! The grant, its review when its granter departs or no longer covers it
//! (`acl.grants.review`, `groupGrants`), and its withdrawal are
//! [`crate::acl::appointment`]'s, shared with board facilitators.

use serde::{Deserialize, Serialize};
use tracing::warn;
use vti_common::error::AppError;

use crate::acl::VtcAclEntry;
use crate::acl::appointment::{self, Held, Kind};
use crate::server::AppState;

const KIND: Kind = Kind::GroupManager;

/// One grant under a granter's review, as the action item lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewItem {
    pub subject: String,
    pub group_id: String,
}

impl From<&ReviewItem> for Held {
    fn from(i: &ReviewItem) -> Self {
        Held {
            subject: i.subject.clone(),
            id: i.group_id.clone(),
        }
    }
}

fn held(items: &[ReviewItem]) -> Vec<Held> {
    items.iter().map(Held::from).collect()
}

/// Whether `entry` holds an appointment to manage `group_id` (not the
/// capability unqualified: that is no appointment).
pub fn appointed(entry: &VtcAclEntry, group_id: &str) -> bool {
    appointment::appointed(entry, KIND, group_id)
}

/// Write `subject`'s appointment to manage `group_id`, delegated by `granter`
/// (`managers/add` items 3 – 4). The caller has checked the granter covers it.
pub async fn appoint(
    state: &AppState,
    granter: &str,
    subject: &str,
    group_id: &str,
    reason: Option<String>,
) -> Result<(), AppError> {
    appointment::appoint(state, KIND, granter, subject, group_id, reason).await
}

/// Remove `subject`'s appointment to manage `group_id`. `false`: they held none.
pub async fn withdraw(state: &AppState, subject: &str, group_id: &str) -> Result<bool, AppError> {
    appointment::withdraw(state, KIND, subject, group_id).await
}

/// Remove every appointment to manage `group_id`, as its deletion does.
pub async fn withdraw_all(state: &AppState, group_id: &str) -> Result<usize, AppError> {
    appointment::withdraw_all(state, KIND, group_id).await
}

/// One pass over every group manager's appointment ([`appointment::sweep`]),
/// raising one review item per granter. Returns the grants withdrawn.
pub async fn sweep(state: &AppState) -> Result<usize, AppError> {
    let swept = appointment::sweep(state, KIND).await?;
    for (granter, items) in swept.raised {
        let items: Vec<ReviewItem> = items
            .into_iter()
            .map(|h| ReviewItem {
                subject: h.subject,
                group_id: h.id,
            })
            .collect();
        warn!(
            granter,
            grants = items.len(),
            "group manager appointments are under review, and withdrawn unless re-affirmed \
             (VTI-ACL-071)"
        );
        if let Err(e) = crate::admin_actions::raise_group_grants_review(
            state,
            &granter,
            &items,
            swept.deadline.timestamp().max(0) as u64,
        )
        .await
        {
            warn!(granter, error = %e, "the group grants review could not be raised; the sweep still withdraws at the deadline");
        }
    }
    Ok(swept.withdrawn.len())
}

/// Re-affirm each listed appointment still under `granter`'s review under the
/// first approver whose own entry covers it, who becomes its granter.
pub async fn reaffirm(
    state: &AppState,
    granter: &str,
    items: &[ReviewItem],
    approvers: &[String],
) -> Result<serde_json::Value, AppError> {
    appointment::reaffirm(state, KIND, granter, &held(items), approvers).await
}

/// Withdraw each listed appointment still under `granter`'s review, as a
/// declined review does.
pub async fn withdraw_reviewed(
    state: &AppState,
    granter: &str,
    items: &[ReviewItem],
) -> Result<(), AppError> {
    appointment::withdraw_reviewed(state, KIND, granter, &held(items)).await
}
