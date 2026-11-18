//! Who facilitates a board by appointment: `vtc.boards.manage` qualified `board:<boardId>`, a
//! resource grant on the facilitator's access-control entry
//! (`vtc/boards/facilitators/{add,remove}`, VTI-BRD-090 – 092), beside their role and never inside its
//! ceiling, so a member with no administrative role may hold it.
//!
//! The grant, its review when its granter departs or no longer covers it
//! (`acl.grants.review`, `boardGrants`), and its withdrawal are
//! [`crate::acl::appointment`]'s, shared with group managers.

use serde::{Deserialize, Serialize};
use tracing::warn;
use vti_common::error::AppError;

use crate::acl::VtcAclEntry;
use crate::acl::appointment::{self, Held, Kind};
use crate::server::AppState;

const KIND: Kind = Kind::BoardFacilitator;

/// One grant under a granter's review, as the action item lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewItem {
    pub subject: String,
    pub board_id: String,
}

impl From<&ReviewItem> for Held {
    fn from(i: &ReviewItem) -> Self {
        Held {
            subject: i.subject.clone(),
            id: i.board_id.clone(),
        }
    }
}

fn held(items: &[ReviewItem]) -> Vec<Held> {
    items.iter().map(Held::from).collect()
}

/// Whether `entry` holds an appointment to facilitate `board_id` (not the
/// capability unqualified: that is no appointment).
pub fn appointed(entry: &VtcAclEntry, board_id: &str) -> bool {
    appointment::appointed(entry, KIND, board_id)
}

/// Write `subject`'s appointment to facilitate `board_id`, delegated by `granter`
/// (`facilitators/add` items 3 – 4). The caller has checked the granter covers it.
pub async fn appoint(
    state: &AppState,
    granter: &str,
    subject: &str,
    board_id: &str,
    reason: Option<String>,
) -> Result<(), AppError> {
    appointment::appoint(state, KIND, granter, subject, board_id, reason).await
}

/// Remove `subject`'s appointment to facilitate `board_id`. `false`: they held none.
pub async fn withdraw(state: &AppState, subject: &str, board_id: &str) -> Result<bool, AppError> {
    appointment::withdraw(state, KIND, subject, board_id).await
}

/// Remove every appointment to facilitate `board_id`, as its deletion does (VTI-BRD-092).
pub async fn withdraw_all(state: &AppState, board_id: &str) -> Result<usize, AppError> {
    appointment::withdraw_all(state, KIND, board_id).await
}

/// One pass over every board facilitator's appointment ([`appointment::sweep`]),
/// raising one review item per granter and auditing each appointment withdrawn at its
/// review's deadline (VTI-BRD-080). Returns the grants withdrawn.
pub async fn sweep(state: &AppState) -> Result<usize, AppError> {
    let swept = appointment::sweep(state, KIND).await?;
    for (granter, items) in swept.raised {
        let items: Vec<ReviewItem> = items
            .into_iter()
            .map(|h| ReviewItem {
                subject: h.subject,
                board_id: h.id,
            })
            .collect();
        warn!(
            granter,
            grants = items.len(),
            "board facilitator appointments are under review, and withdrawn unless re-affirmed \
             (VTI-ACL-071)"
        );
        if let Err(e) = crate::admin_actions::raise_board_grants_review(
            state,
            &granter,
            &items,
            swept.deadline.timestamp().max(0) as u64,
        )
        .await
        {
            warn!(granter, error = %e, "the board grants review could not be raised; the sweep still withdraws at the deadline");
        }
    }
    let community = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_default();
    for h in &swept.withdrawn {
        let entry = crate::directory::cards::entry_of(state.directory.ks(), &h.subject)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        if let Err(e) = super::audit_facilitator(
            state,
            &community,
            &h.id,
            &entry,
            "facilitatorWithdrawn",
            None,
        )
        .await
        {
            warn!(board = %h.id, error = %e, "a withdrawn facilitator appointment could not be audited");
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

/// The entries appointed to facilitate `board_id`, sorted (VTI-BRD-093). Holders of
/// `vtc.boards.manage` unqualified or through a role are not appointed, and not listed.
pub async fn entries(state: &AppState, board_id: &str) -> Result<Vec<String>, AppError> {
    appointment::holder_entries(state, KIND, board_id).await
}

/// Every live appointment to facilitate `board_id`, oldest first.
pub async fn appointments(
    state: &AppState,
    board_id: &str,
) -> Result<Vec<appointment::Appointment>, AppError> {
    appointment::holders(state, KIND, board_id).await
}
