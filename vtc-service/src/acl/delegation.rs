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
//! ## Where a review is visible
//!
//! `acl/show` and `acl/list` (0.2) render an entry under review with
//! `ext["org.openvtc"].delegationReview` = `{granter, deadline}`; the console
//! shows it on the Access-control page. The action list does not carry review
//! items yet: its acknowledge-style items arrive with the action-list
//! follow-ups, and this module is the listing and the withdrawal sweeper they
//! will sit on.

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
    let mut raised = 0;
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
        raised += 1;
    }
    Ok(raised)
}

/// Withdraw every entry whose review has passed its deadline unre-affirmed: its
/// administrative authority is removed (the membership and community role
/// stay), its sessions revoked and the change audited. Returns how many were
/// withdrawn.
pub async fn sweep(state: &AppState) -> Result<usize, AppError> {
    let now = now_epoch();
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
