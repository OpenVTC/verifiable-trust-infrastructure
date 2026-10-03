//! A departed granter's grants — `docs/05-design-notes/vtc-admin-roles.md`
//! §6.3 and §11.2; **VTI-ACL-071**, **VTI-ACL-073**.
//!
//! A grant is a delegation, recorded in the entry's `delegated_by`. A delegated
//! entry must not retain authority its delegator has since lost
//! (`acl/_shared/0.2` CONVENTIONS §9): when a granter's entry is removed or
//! narrowed so that it no longer covers an entry it granted
//! ([`super::granting::covers_entry`]), that entry goes **to review**, and is
//! **withdrawn** — its administrative authority removed, its membership kept —
//! unless an administrator re-affirms it within the action lifetime
//! (`acl.action_lifetime`).
//!
//! ## What re-affirming is
//!
//! Writing the entry again with `acl/update` (0.1 or 0.2) — even unchanged — by
//! an administrator who covers it. That write is a grant like any other: bounded
//! by the writer's own authority (§6.3) and gated as one, and it records the
//! writer as the new `delegated_by`, which is exactly what re-affirming means.
//! The review is then closed ([`clear`]).
//!
//! ## Where a review is decided
//!
//! In the **action list**: every review a departed granter leaves behind is
//! raised as one approval item (kind `acl.grants.review`,
//! [`crate::admin_actions::raise_grants_review`]) for the holders who may
//! approve `vtc.roles.assign`, other than the granter and the entries under
//! review. **Approving** re-affirms each listed grant the approver covers
//! ([`reaffirm`]) — the approver becomes its `delegated_by`, exactly as an
//! `acl/update` by that administrator would make it. **Declining** withdraws
//! them at once ([`withdraw_reviewed`]). **Letting it lapse** leaves them to
//! [`sweep`], the backstop that withdraws every review past its deadline
//! whether or not an item was raised (none is, when nobody could approve one).
//!
//! `acl/show` and `acl/list` (0.2) still render an entry under review with
//! `ext["org.openvtc"].delegationReview` = `{granter, deadline}`.
//!
//! ## What departs
//!
//! A granter departs when its entry is removed, narrowed so that it no longer
//! covers what it granted, or **expires**: the sweeper notices an expired (or
//! vanished) granter on its next pass, since nothing writes on expiry.

use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use vti_common::audit::{AclChangeData, AuditEvent};
use vti_common::error::AppError;

use super::{AdminAuthority, VtcAclEntry, get_acl_entry, list_acl_entries, store_acl_entry};
use crate::auth::session::now_epoch;
use crate::server::AppState;

const REVIEW_PREFIX: &str = "delegation-review:";

/// An entry whose granter no longer covers it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationReview {
    /// The delegated entry under review.
    pub subject: String,
    /// The granter it was delegated from, who has left or narrowed.
    pub granter: String,
    pub raised_at: u64,
    /// When it is withdrawn unless re-affirmed.
    pub deadline: u64,
}

fn key(subject: &str) -> String {
    format!("{REVIEW_PREFIX}{subject}")
}

/// The open review for `subject`, if any.
pub async fn review_for(
    state: &AppState,
    subject: &str,
) -> Result<Option<DelegationReview>, AppError> {
    state.admin_actions_ks.get(key(subject)).await
}

/// Every open review.
pub async fn list(state: &AppState) -> Result<Vec<DelegationReview>, AppError> {
    let mut out = Vec::new();
    for (_, v) in state
        .admin_actions_ks
        .prefix_iter_raw(REVIEW_PREFIX.as_bytes().to_vec())
        .await?
    {
        match serde_json::from_slice::<DelegationReview>(&v) {
            Ok(r) => out.push(r),
            Err(e) => warn!(error = %e, "delegation review: unreadable record"),
        }
    }
    Ok(out)
}

/// Close `subject`'s review: re-affirmed, or the entry is gone.
pub async fn clear(state: &AppState, subject: &str) -> Result<(), AppError> {
    state.admin_actions_ks.remove(key(subject)).await
}

/// `granter`'s entry has been removed (`after = None`) or rewritten to
/// `after`: put every live entry it delegated, and no longer covers, to review.
/// Returns how many were raised.
///
/// Called by every door that removes or narrows an entry, after its write.
pub async fn on_granter_changed(
    state: &AppState,
    granter: &str,
    after: Option<&VtcAclEntry>,
) -> Result<usize, AppError> {
    let now = now_epoch();
    let lifetime =
        crate::admin_actions::setting(state, crate::config_store::ACTION_LIFETIME).await?;
    let mut raised = Vec::new();
    for e in list_acl_entries(&state.acl_ks).await? {
        if e.delegated_by.as_deref() != Some(granter)
            || e.is_expired(now)
            || !e.admin.is_administrator()
        {
            continue;
        }
        if after.is_some_and(|a| super::granting::covers_entry(a, &e, now)) {
            continue;
        }
        if review_for(state, &e.did).await?.is_some() {
            continue;
        }
        let review = DelegationReview {
            subject: e.did.clone(),
            granter: granter.to_string(),
            raised_at: now,
            deadline: now.saturating_add(lifetime),
        };
        state.admin_actions_ks.insert(key(&e.did), &review).await?;
        warn!(
            subject = %e.did,
            granter,
            deadline = review.deadline,
            "a delegated ACL entry's granter no longer covers it: under review, and withdrawn \
             unless re-affirmed (VTI-ACL-071)"
        );
        raised.push(e.did.clone());
    }
    // One item in the action list for all of them (§6.3).
    if let Err(e) = crate::admin_actions::raise_grants_review(
        state,
        granter,
        &raised,
        now.saturating_add(lifetime),
    )
    .await
    {
        warn!(granter, error = %e, "the grants review could not be raised; the sweeper still withdraws at the deadline");
    }
    Ok(raised.len())
}

/// `old` rolled its entry to `new` (`acl/swap-key`, a member's own rotation):
/// the same granter under a new name, not a departure. Every entry it
/// delegated now names `new`, and every open review follows its subject or
/// granter. Returns how many entries were re-pointed.
pub async fn repoint(state: &AppState, old: &str, new: &str) -> Result<u32, AppError> {
    let mut repointed = 0;
    for mut e in list_acl_entries(&state.acl_ks).await? {
        if e.delegated_by.as_deref() == Some(old) {
            e.delegated_by = Some(new.to_string());
            store_acl_entry(&state.acl_ks, &e).await?;
            repointed += 1;
        }
    }
    for mut review in list(state).await? {
        let moved = review.subject == old;
        if moved {
            state.admin_actions_ks.remove(key(old)).await?;
            review.subject = new.to_string();
        }
        if review.granter == old {
            review.granter = new.to_string();
        }
        if moved || review.granter == new {
            state
                .admin_actions_ks
                .insert(key(&review.subject), &review)
                .await?;
        }
    }
    Ok(repointed)
}

/// Re-affirm the grants `granter` made that are still under its review,
/// under the authority of the first of `approvers` who covers each — what an
/// approved `acl.grants.review` item does. Returns what was re-affirmed and
/// what nobody among them covered (left for the sweeper).
pub async fn reaffirm(
    state: &AppState,
    granter: &str,
    subjects: &[String],
    approvers: &[String],
) -> Result<serde_json::Value, AppError> {
    let now = now_epoch();
    let mut deciders = Vec::new();
    for d in approvers {
        if let Some(e) = get_acl_entry(&state.acl_ks, d).await? {
            deciders.push(e);
        }
    }
    let (mut reaffirmed, mut uncovered) = (Vec::new(), Vec::new());
    for subject in subjects {
        let Some(mut entry) = get_acl_entry(&state.acl_ks, subject).await? else {
            continue;
        };
        // Re-affirmed or rewritten since: nothing left of this review.
        if entry.delegated_by.as_deref() != Some(granter)
            || review_for(state, subject).await?.is_none()
        {
            continue;
        }
        let Some(by) = deciders
            .iter()
            .find(|d| super::granting::covers_entry(d, &entry, now))
        else {
            uncovered.push(subject.clone());
            continue;
        };
        entry.delegated_by = Some(by.did.clone());
        entry.updated_at = Some(now);
        entry.updated_by = Some(by.did.clone());
        store_acl_entry(&state.acl_ks, &entry).await?;
        clear(state, subject).await?;
        if let Some(writer) = state.audit_writer.as_ref() {
            writer
                .write(
                    &by.did,
                    Some(subject),
                    AuditEvent::AclUpdated(AclChangeData {
                        did: entry.did.clone(),
                        role: entry
                            .admin
                            .admin_role
                            .as_ref()
                            .map(|r| r.to_string())
                            .unwrap_or_else(|| entry.role.to_string()),
                        contexts: entry.capability_list(),
                        expires_at: entry.expires_at.map(|e| e.to_string()),
                    }),
                )
                .await?;
        }
        info!(subject, granter, by = %by.did, "a departed granter's grant was re-affirmed");
        reaffirmed.push(subject.clone());
    }
    Ok(serde_json::json!({ "reaffirmed": reaffirmed, "notCovered": uncovered }))
}

/// Withdraw, now, the grants `granter` made that are still under its review —
/// a declined `acl.grants.review` item. Returns how many were withdrawn.
pub async fn withdraw_reviewed(
    state: &AppState,
    granter: &str,
    subjects: &[String],
) -> Result<usize, AppError> {
    let now = now_epoch();
    let mut withdrawn = 0;
    for subject in subjects {
        let Some(review) = review_for(state, subject).await? else {
            continue;
        };
        if review.granter != granter {
            continue;
        }
        let Some(mut entry) = get_acl_entry(&state.acl_ks, subject).await? else {
            clear(state, subject).await?;
            continue;
        };
        if entry.delegated_by.as_deref() != Some(granter) {
            clear(state, subject).await?;
            continue;
        }
        if super::admin_consent::is_live_role_assigner(&entry, now) {
            let _guard = crate::ceremony::lock_admin_set().await;
            if super::admin_consent::check_attrition(state, &entry.did)
                .await
                .is_err()
            {
                warn!(
                    subject,
                    "a declined review's grant is the last holder of vtc.roles.assign: kept"
                );
                continue;
            }
            withdraw(state, &mut entry, now).await?;
        } else {
            withdraw(state, &mut entry, now).await?;
        }
        clear(state, subject).await?;
        withdrawn += 1;
    }
    Ok(withdrawn)
}

/// Withdraw every entry whose review has passed its deadline unre-affirmed: its
/// administrative authority is removed (the membership and community role
/// stay), its sessions revoked and the change audited. Returns how many were
/// withdrawn.
pub async fn sweep(state: &AppState) -> Result<usize, AppError> {
    let now = now_epoch();
    // A granter that expired (or vanished) has departed as surely as one that
    // was removed, but nothing wrote when it did: raise its grants' review now.
    let entries = list_acl_entries(&state.acl_ks).await?;
    let mut departed: Vec<String> = entries
        .iter()
        .filter(|e| !e.is_expired(now) && e.admin.is_administrator())
        .filter_map(|e| e.delegated_by.clone())
        .filter(|g| {
            entries
                .iter()
                .find(|x| &x.did == g)
                .is_none_or(|x| x.is_expired(now))
        })
        .collect();
    departed.sort();
    departed.dedup();
    for granter in departed {
        on_granter_changed(state, &granter, None).await?;
    }
    let mut withdrawn = 0;
    for review in list(state).await? {
        if review.deadline > now {
            continue;
        }
        let Some(mut entry) = get_acl_entry(&state.acl_ks, &review.subject).await? else {
            clear(state, &review.subject).await?;
            continue;
        };
        // Re-affirmed since (a newer granter recorded): nothing to withdraw.
        if entry.delegated_by.as_deref() != Some(review.granter.as_str()) {
            clear(state, &review.subject).await?;
            continue;
        }
        // Never strand the community: the last holder of vtc.roles.assign is
        // kept, and the review stays open for a human to resolve.
        if super::admin_consent::is_live_role_assigner(&entry, now) {
            let _guard = crate::ceremony::lock_admin_set().await;
            if super::admin_consent::check_attrition(state, &entry.did)
                .await
                .is_err()
            {
                warn!(
                    subject = %entry.did,
                    "a delegated entry under review is the last holder of vtc.roles.assign: \
                     not withdrawn"
                );
                continue;
            }
            withdraw(state, &mut entry, now).await?;
        } else {
            withdraw(state, &mut entry, now).await?;
        }
        clear(state, &review.subject).await?;
        withdrawn += 1;
    }
    Ok(withdrawn)
}

async fn withdraw(state: &AppState, entry: &mut VtcAclEntry, now: u64) -> Result<(), AppError> {
    let granter = entry.delegated_by.clone().unwrap_or_default();
    entry.admin = AdminAuthority::none();
    entry.delegated_by = None;
    entry.updated_at = Some(now);
    entry.updated_by = Some("vtc:delegation-review".into());
    store_acl_entry(&state.acl_ks, entry).await?;
    let _ = crate::routes::auth::revoke_sessions_for_did(&state.sessions_ks, &entry.did).await;
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                "vtc:delegation-review",
                Some(&entry.did),
                AuditEvent::AclUpdated(AclChangeData {
                    did: entry.did.clone(),
                    role: entry.role.to_string(),
                    contexts: Vec::new(),
                    expires_at: entry.expires_at.map(|e| e.to_string()),
                }),
            )
            .await?;
    }
    info!(
        subject = %entry.did,
        granter,
        "delegated ACL entry withdrawn: its granter left and nobody re-affirmed it"
    );
    // Its own grants are now uncovered too.
    let did = entry.did.clone();
    on_granter_changed(state, &did, Some(&*entry)).await?;
    Ok(())
}
