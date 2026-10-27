//! Who manages a group: `vtc.groups.manage` qualified `group:<groupId>`, a
//! resource grant on the manager's access-control entry
//! (`vtc/groups/managers/{add,remove}`), beside their role and never inside its
//! ceiling, so a member with no administrative role may hold it.
//!
//! A grant is a delegation (VTI-ACL-071): it is bounded at write time by the
//! signer's own holding, and when its granter departs the community, or no
//! longer covers it, it goes **to review** — an `acl.grants.review` item
//! (`groupGrants`) asks the community's administrators to re-affirm it under
//! their own authority. Declined, or not re-affirmed by the deadline (the
//! action lifetime), it is withdrawn ([`sweep`]). Never left standing
//! silently.
//!
//! Every write takes the git-namespace write lock: an `acl/*` write re-reads
//! an entry's resource grants under it (`routes::acl::commit_grant`), so a
//! grant written here is never lost to a racing role change.

use std::collections::BTreeMap;

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use vti_common::error::AppError;

use crate::acl::resource_grant::{GrantReview, ResourceGrant};
use crate::acl::{Capability, ResourceQualifier, VtcAclEntry, get_acl_entry, store_acl_entry};
use crate::server::AppState;

/// One grant under a granter's review, as the action item lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewItem {
    pub subject: String,
    pub group_id: String,
}

fn qualifier(group_id: &str) -> ResourceQualifier {
    ResourceQualifier::Group(group_id.to_string())
}

fn is_appointment(g: &ResourceGrant, group_id: &str) -> bool {
    g.capability == Capability::GroupsManage && g.resource == qualifier(group_id)
}

/// The group `g` appoints its holder to manage, if it is such a grant.
fn appointment(g: &ResourceGrant) -> Option<&str> {
    match (&g.capability, &g.resource) {
        (Capability::GroupsManage, ResourceQualifier::Group(id)) => Some(id.as_str()),
        _ => None,
    }
}

/// Whether `entry` holds an appointment to manage `group_id` (not the
/// capability unqualified: that is no appointment).
pub fn appointed(entry: &VtcAclEntry, group_id: &str) -> bool {
    let now = Utc::now();
    entry
        .resource_grants
        .iter()
        .any(|g| is_appointment(g, group_id) && g.is_live(now))
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
    let _guard = crate::git_ns::store::write_lock().await;
    let mut entry = get_acl_entry(&state.acl_ks, subject)
        .await?
        .ok_or_else(|| AppError::NotFound("no access-control entry".into()))?;
    if appointed(&entry, group_id) {
        return Ok(());
    }
    let grant: ResourceGrant = serde_json::from_value(serde_json::json!({
        "capability": Capability::GroupsManage.as_str(),
        "resource": qualifier(group_id).to_string(),
        "delegatedBy": granter,
        "grantedAt": Utc::now(),
        "reason": reason,
        "subjectWasMember": true,
        "granterWasMember": crate::member_portal::active::active_member(state, granter)
            .await?
            .is_some(),
    }))
    .map_err(|e| AppError::Internal(format!("group manager grant: {e}")))?;
    entry.resource_grants.push(grant);
    store_acl_entry(&state.acl_ks, &entry).await
}

/// Remove `subject`'s appointment to manage `group_id`. `false`: they held none.
pub async fn withdraw(state: &AppState, subject: &str, group_id: &str) -> Result<bool, AppError> {
    let _guard = crate::git_ns::store::write_lock().await;
    let Some(mut entry) = get_acl_entry(&state.acl_ks, subject).await? else {
        return Ok(false);
    };
    let before = entry.resource_grants.len();
    entry
        .resource_grants
        .retain(|g| !is_appointment(g, group_id));
    if entry.resource_grants.len() == before {
        return Ok(false);
    }
    store_acl_entry(&state.acl_ks, &entry).await?;
    Ok(true)
}

/// Remove every appointment to manage `group_id`, as its deletion does.
pub async fn withdraw_all(state: &AppState, group_id: &str) -> Result<usize, AppError> {
    let _guard = crate::git_ns::store::write_lock().await;
    let mut n = 0;
    for mut entry in crate::acl::list_acl_entries(&state.acl_ks).await? {
        let before = entry.resource_grants.len();
        entry
            .resource_grants
            .retain(|g| !is_appointment(g, group_id));
        if entry.resource_grants.len() != before {
            n += before - entry.resource_grants.len();
            store_acl_entry(&state.acl_ks, &entry).await?;
        }
    }
    Ok(n)
}

/// Whether `granter` stands behind an appointment to `group_id`: still an
/// active member, and still covering the grant.
async fn stands_behind(state: &AppState, granter: &str, group_id: &str) -> Result<bool, AppError> {
    if crate::member_portal::active::active_member(state, granter)
        .await?
        .is_none()
    {
        // An administrator with no member record still stands behind what
        // they granted while their entry covers it.
        let entry = get_acl_entry(&state.acl_ks, granter).await?;
        return Ok(entry.is_some_and(|e| {
            e.is_administrator() && e.can(Capability::GroupsManage, Some(&qualifier(group_id)))
        }));
    }
    Ok(get_acl_entry(&state.acl_ks, granter)
        .await?
        .is_some_and(|e| e.can(Capability::GroupsManage, Some(&qualifier(group_id)))))
}

/// One pass over every group manager's appointment: a granter who departed or
/// no longer covers it puts it under review (raising one item per granter), a
/// granter back behind it clears the review, and a review past its deadline
/// withdraws the grant. Returns the grants withdrawn.
pub async fn sweep(state: &AppState) -> Result<usize, AppError> {
    let lifetime = crate::admin_actions::setting(state, crate::config_store::ACTION_LIFETIME)
        .await
        .unwrap_or(7 * 24 * 3600);
    let now = Utc::now();
    let deadline = now + Duration::seconds(lifetime.min(i64::MAX as u64) as i64);
    let mut raised: BTreeMap<String, Vec<ReviewItem>> = BTreeMap::new();
    let mut withdrawn = 0;
    let _guard = crate::git_ns::store::write_lock().await;
    for mut entry in crate::acl::list_acl_entries(&state.acl_ks).await? {
        let mut changed = false;
        let mut kept = Vec::with_capacity(entry.resource_grants.len());
        for mut g in entry.resource_grants.clone() {
            let Some(group_id) = appointment(&g).map(str::to_string) else {
                kept.push(g);
                continue;
            };
            // A grant the granter made to themselves has no granter to depart.
            if g.delegated_by == entry.did {
                kept.push(g);
                continue;
            }
            let behind = stands_behind(state, &g.delegated_by, &group_id).await?;
            match (&g.review, behind) {
                (None, false) => {
                    g.review = Some(GrantReview {
                        granter: g.delegated_by.clone(),
                        raised_at: now,
                        deadline,
                    });
                    raised
                        .entry(g.delegated_by.clone())
                        .or_default()
                        .push(ReviewItem {
                            subject: entry.did.clone(),
                            group_id,
                        });
                    changed = true;
                }
                (Some(r), false) if r.deadline <= now => {
                    info!(group = %group_id, "a group manager's appointment was withdrawn: its granter no longer stands behind it");
                    withdrawn += 1;
                    changed = true;
                    continue;
                }
                (Some(_), true) => {
                    g.review = None;
                    changed = true;
                }
                _ => {}
            }
            kept.push(g);
        }
        if changed {
            entry.resource_grants = kept;
            store_acl_entry(&state.acl_ks, &entry).await?;
        }
    }
    drop(_guard);
    for (granter, items) in raised {
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
            deadline.timestamp().max(0) as u64,
        )
        .await
        {
            warn!(granter, error = %e, "the group grants review could not be raised; the sweep still withdraws at the deadline");
        }
    }
    Ok(withdrawn)
}

/// Re-affirm each listed appointment still under `granter`'s review under the
/// first approver whose own entry covers it, who becomes its granter.
pub async fn reaffirm(
    state: &AppState,
    granter: &str,
    items: &[ReviewItem],
    approvers: &[String],
) -> Result<serde_json::Value, AppError> {
    let _guard = crate::git_ns::store::write_lock().await;
    let mut deciders = Vec::new();
    for d in approvers {
        if let Some(e) = get_acl_entry(&state.acl_ks, d).await? {
            deciders.push(e);
        }
    }
    let (mut reaffirmed, mut uncovered) = (0usize, 0usize);
    for item in items {
        let Some(mut entry) = get_acl_entry(&state.acl_ks, &item.subject).await? else {
            continue;
        };
        let decider = deciders.iter().find(|d| {
            d.did != item.subject
                && d.can(Capability::GroupsManage, Some(&qualifier(&item.group_id)))
        });
        let Some(g) = entry.resource_grants.iter_mut().find(|g| {
            is_appointment(g, &item.group_id)
                && g.review.as_ref().is_some_and(|r| r.granter == granter)
        }) else {
            continue;
        };
        match decider {
            Some(d) => {
                g.delegated_by = d.did.clone();
                g.review = None;
                reaffirmed += 1;
                store_acl_entry(&state.acl_ks, &entry).await?;
            }
            None => uncovered += 1,
        }
    }
    Ok(serde_json::json!({ "reaffirmed": reaffirmed, "uncovered": uncovered }))
}

/// Withdraw each listed appointment still under `granter`'s review, as a
/// declined review does.
pub async fn withdraw_reviewed(
    state: &AppState,
    granter: &str,
    items: &[ReviewItem],
) -> Result<(), AppError> {
    let _guard = crate::git_ns::store::write_lock().await;
    for item in items {
        let Some(mut entry) = get_acl_entry(&state.acl_ks, &item.subject).await? else {
            continue;
        };
        let before = entry.resource_grants.len();
        entry.resource_grants.retain(|g| {
            !(is_appointment(g, &item.group_id)
                && g.review.as_ref().is_some_and(|r| r.granter == granter))
        });
        if entry.resource_grants.len() != before {
            store_acl_entry(&state.acl_ks, &entry).await?;
        }
    }
    Ok(())
}
