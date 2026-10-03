//! Rights that end without anyone asking: a member leaves, a grant lapses.
//!
//! # Departure (design §5.4, VTI-MEM-033)
//!
//! "A departure MUST propagate to whatever the community has published about
//! the member." A departed member's git rights are revoked — every one, on
//! every resource — and so withdrawn from the registry and, through the next
//! role projection, from the forge. Repositories whose last owner left pass to
//! the namespace admins by implication and are marked `orphaned` until one of
//! them names a new owner (`git-ns/right/grant`, fixed rule 3).
//!
//! Grants the departed member **issued** stay: they were issued under the
//! community's authority, not the member's. They are listed for review on the
//! admin surface, and a community whose policy sets `cascade_on_departure`
//! revokes them instead.
//!
//! Departure is detected from the records rather than from the audit log's
//! `MemberRemoved` row: a right remembers whether its subject was a member
//! when it was granted, and a subject who was and no longer is has left. The
//! audit row wakes the projector sooner; this is what makes the outcome not
//! depend on it — an erasure nulls the row's plaintext DID, and the sweep
//! must still find the rights.
//!
//! # Expiry
//!
//! "The VTC withdraws a lapsed right from its registry projection and records
//! the lapse, just as it would a revocation." The projection never publishes a
//! lapsed row (it filters on the clock), so withdrawal does not wait for this
//! sweep; the sweep removes the row and records the lapse.

use std::collections::{BTreeMap, BTreeSet};

use tracing::{info, warn};
use vti_common::error::AppError;

use crate::server::AppState;

use super::model::{LinkState, NamespaceState, RepoState, Right, Scope};
use super::ops::{Audit, audit, now, standing};
use super::policy;
use super::rules;
use super::store::{self, Snapshot};

/// How long a bridge-mode binding may wait for its forge-side proof before
/// the pending namespace is discarded. The bridge's nonce is valid for
/// fifteen minutes (design §4.1); a day is generous and bounded.
const PENDING_BIND_HOURS: i64 = 24;
/// How long a finished link attempt is remembered for `link-status`.
const LINK_MEMORY_DAYS: i64 = 7;

/// Run every sweep once. Returns whether anything changed.
pub async fn sweep(state: &AppState) -> Result<bool, AppError> {
    let mut changed = false;
    changed |= sweep_departures(state).await?;
    changed |= sweep_departed_links(state).await?;
    changed |= sweep_expiry(state).await?;
    changed |= sweep_pending(state).await?;
    Ok(changed)
}

/// Revoke the rights of members who have left, orphan what they owned alone,
/// and put what they granted to review — or, under `cascade_on_departure`,
/// revoke it at once.
///
/// A departure reaches this two ways. A removed entry takes its resource
/// grants with it (they confer nothing without it, **VTI-ACL-037**) and leaves
/// them aside for this sweep to record ([`crate::acl::resource_grant::departed`]);
/// a departure that keeps the entry (the member row's `removed_at`) leaves the
/// grants on it, and they are revoked here.
///
/// # A departed granter's grants (`vtc-admin-roles.md` §6.3, VTI-ACL-071)
///
/// A grant is a delegation. When its granter is no longer a member, the grant
/// goes **to review**: it stays in force, marked, and an `acl.grants.review`
/// item asks the community's administrators to re-affirm it under their own
/// authority. Declined, or not re-affirmed by the deadline (the action
/// lifetime), it is **withdrawn**. A grant the granter made to itself (a
/// binding's first admin, a creator's ownership, a break-glass) and one the
/// community made as itself (the bridge's service grant) have no granter to
/// depart and are never reviewed.
pub async fn sweep_departures(state: &AppState) -> Result<bool, AppError> {
    let settings = policy::active_settings(state).await;
    let _guard = store::write_lock().await;
    let mut changed = record_removed_entries(state).await?;
    let snap = Snapshot::load(&state.git_ns).await?;
    let t = now();

    // Who is a question: every subject that was a member, and every granter
    // that was.
    let mut candidates = BTreeSet::new();
    for set in snap.rights.values() {
        for row in &set.rows {
            if row.subject_was_member {
                candidates.insert(row.subject.clone());
            }
            if row.granter_was_member {
                candidates.insert(row.granted_by.clone());
            }
        }
    }
    let mut departed = BTreeSet::new();
    for did in candidates {
        if !standing(state, &did).await?.member {
            departed.insert(did);
        }
    }

    let lifetime = crate::admin_actions::setting(state, crate::config_store::ACTION_LIFETIME)
        .await
        .unwrap_or(7 * 24 * 3600);
    let deadline = t + chrono::Duration::seconds(lifetime.min(i64::MAX as u64) as i64);
    let vtc = vtc_actor(state).await;
    let mut raised: BTreeMap<String, Vec<ReviewItem>> = BTreeMap::new();
    for (scope, set) in &snap.rights {
        let resource = snap
            .scope_resource(scope)
            .map(|r| r.to_string())
            .unwrap_or_default();
        let ns_id = snap.scope_namespace(scope).map(|n| n.id.clone());
        let mut gone = Vec::new();
        let mut next = set.clone();
        next.rows.clear();
        let mut touched = false;
        for row in &set.rows {
            let subject_left = row.subject_was_member && departed.contains(&row.subject);
            let delegated = row.granter_was_member && row.granted_by != row.subject;
            let granter_left = delegated && departed.contains(&row.granted_by);
            if subject_left {
                gone.push((row.clone(), "departed"));
                continue;
            }
            if granter_left && settings.cascade_on_departure {
                gone.push((row.clone(), "granterDeparted"));
                continue;
            }
            let mut row = row.clone();
            match (&row.review, granter_left) {
                // The granter has left: review it, or withdraw it at the
                // deadline.
                (None, true) => {
                    row.review = Some(crate::acl::resource_grant::GrantReview {
                        granter: row.granted_by.clone(),
                        raised_at: t,
                        deadline,
                    });
                    touched = true;
                    raised
                        .entry(row.granted_by.clone())
                        .or_default()
                        .push(ReviewItem {
                            subject: row.subject.clone(),
                            right: row.right,
                            resource: resource.clone(),
                            scope: scope.clone(),
                        });
                }
                (Some(r), true) if r.deadline <= t => {
                    gone.push((row.clone(), "granterDeparted"));
                    continue;
                }
                // The granter is back (or it was re-affirmed under another):
                // nothing left to review.
                (Some(_), false) => {
                    row.review = None;
                    touched = true;
                }
                _ => {}
            }
            next.rows.push(row);
        }
        if gone.is_empty() && !touched {
            continue;
        }
        changed = true;
        for (row, why) in &gone {
            info!(right = %row.right, %resource, why, "git right revoked");
            // The community acted, not the member; and a departed member's
            // DID does not go into a new audit row in plaintext, because the
            // departure may be an erasure and this row would outlive it. The
            // revocation of a *cascaded* or withdrawn grant names its (still
            // present) subject as usual.
            let target = (!departed.contains(&row.subject)).then_some(row.subject.as_str());
            audit(
                state,
                &vtc,
                target,
                Audit {
                    action: "gitNs.right.revoked",
                    namespace: ns_id.as_deref(),
                    resource: Some(resource.clone()),
                    right: Some(row.right),
                    policy_version: None,
                    detail: Some((*why).into()),
                },
            )
            .await;
        }
        store::put_rights(&state.git_ns, scope, &next).await?;
        let lost: Vec<Right> = gone.iter().map(|(r, _)| r.right).collect();
        after_loss(state, &vtc, &snap, scope, &lost).await?;
    }
    for (granter, items) in raised {
        raise_review(state, &granter, &items, deadline).await;
    }

    Ok(changed)
}

/// One grant under a departed granter's review, as the action item lists it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewItem {
    pub subject: String,
    pub right: Right,
    pub resource: String,
    /// Where the grant is held — by id, so a rename between the review and
    /// its decision changes nothing.
    pub scope: Scope,
}

/// Raise the `acl.grants.review` item for `granter`'s git grants. A failure is
/// logged: the sweep still withdraws them at the deadline.
async fn raise_review(
    state: &AppState,
    granter: &str,
    items: &[ReviewItem],
    deadline: chrono::DateTime<chrono::Utc>,
) {
    warn!(
        granter,
        grants = items.len(),
        "a departed member's git grants are under review, and withdrawn unless re-affirmed \
         (VTI-ACL-071)"
    );
    if let Err(e) = crate::admin_actions::raise_git_grants_review(
        state,
        granter,
        items,
        deadline.timestamp().max(0) as u64,
    )
    .await
    {
        warn!(granter, error = %e, "the git grants review could not be raised; the sweep still withdraws at the deadline");
    }
}

/// What follows from losing `lost` on `scope`: a repository whose last owner
/// went is orphaned, governed by the namespace admins; a namespace whose last
/// admin went is said so.
async fn after_loss(
    state: &AppState,
    vtc: &str,
    snap: &Snapshot,
    scope: &Scope,
    lost: &[Right],
) -> Result<(), AppError> {
    let t = now();
    let current = store::get_rights(&state.git_ns, scope).await?;
    if let Scope::Repo(id) = scope
        && lost.contains(&Right::RepoOwn)
        && !current
            .rows
            .iter()
            .any(|r| r.right == Right::RepoOwn && r.is_live(t))
        && let Some(mut repo) = snap.repo(id).cloned()
        && repo.state == RepoState::Active
    {
        repo.state = RepoState::Orphaned;
        store::put_repo(&state.git_ns.ks, &repo).await?;
        audit(
            state,
            vtc,
            None,
            Audit {
                action: "gitNs.repo.orphaned",
                namespace: Some(&repo.namespace_id),
                resource: Some(repo.resource.clone()),
                right: None,
                policy_version: None,
                detail: None,
            },
        )
        .await;
    }
    if let Scope::Namespace(id) = scope
        && lost.contains(&Right::NsAdmin)
        && !current
            .rows
            .iter()
            .any(|r| r.right == Right::NsAdmin && r.is_live(t))
    {
        warn!(
            namespace = %id,
            "the last git.ns.admin of this namespace has left the community; it has no \
             admin until it is reseated, or unbound and bound again"
        );
    }
    Ok(())
}

/// Record the grants of entries that were removed — a departure, an ACL
/// revocation, an emergency bootstrap — and orphan what they owned alone.
/// The grants themselves went with the entry.
async fn record_removed_entries(state: &AppState) -> Result<bool, AppError> {
    let kept = crate::acl::resource_grant::departed(&state.git_ns.acl_ks).await?;
    if kept.is_empty() {
        return Ok(false);
    }
    let snap = Snapshot::load(&state.git_ns).await?;
    let vtc = vtc_actor(state).await;
    for (did, grants) in kept {
        let mut lost: BTreeMap<Scope, Vec<Right>> = BTreeMap::new();
        for g in &grants {
            let Some(right) = g.git_right() else { continue };
            let scope = match &g.resource {
                crate::acl::ResourceQualifier::GitRepo(_) => {
                    crate::acl::resource_grant::repo_id_of(&g.resource)
                        .filter(|id| snap.repo(id).is_some())
                        .map(|id| Scope::Repo(id.to_string()))
                }
                crate::acl::ResourceQualifier::GitNs(path) => snap
                    .namespace_at(path)
                    .map(|n| Scope::Namespace(n.id.clone())),
                _ => None,
            };
            let Some(scope) = scope else { continue };
            let resource = snap
                .scope_resource(&scope)
                .map(|r| r.to_string())
                .unwrap_or_default();
            info!(%right, %resource, why = "departed", "git right revoked");
            // A departed member's DID stays out of the new row (the departure
            // may be an erasure); a non-member's is named.
            let target = (!g.subject_was_member).then_some(did.as_str());
            audit(
                state,
                &vtc,
                target,
                Audit {
                    action: "gitNs.right.revoked",
                    namespace: snap.scope_namespace(&scope).map(|n| n.id.as_str()),
                    resource: Some(resource),
                    right: Some(right),
                    policy_version: None,
                    detail: Some("departed".into()),
                },
            )
            .await;
            lost.entry(scope).or_default().push(right);
        }
        for (scope, rights) in &lost {
            after_loss(state, &vtc, &snap, scope, rights).await?;
        }
        crate::acl::resource_grant::forget_departed(&state.git_ns.acl_ks, &did).await?;
    }
    Ok(true)
}

/// Re-affirm the git grants `granter` made that are still under its review —
/// an approved `acl.grants.review` item. Each is re-affirmed under the first
/// of `approvers` whose own entry holds what it is delegated from
/// (**VTI-ACL-071**), who becomes its granter; one nobody covers is left for
/// the sweep. Returns what was re-affirmed and what nobody covered.
pub async fn reaffirm(
    state: &AppState,
    granter: &str,
    items: &[ReviewItem],
    approvers: &[String],
) -> Result<serde_json::Value, AppError> {
    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns).await?;
    let mut deciders = Vec::new();
    for d in approvers {
        if standing(state, d).await?.member
            && let Some(e) = crate::acl::get_acl_entry(&state.acl_ks, d).await?
        {
            deciders.push(e);
        }
    }
    let (mut reaffirmed, mut uncovered) = (Vec::new(), Vec::new());
    for item in items {
        let scope = item.scope.clone();
        if snap.scope_resource(&scope).is_none() {
            continue;
        }
        let Some(q) = store::scope_qualifier(&state.git_ns.ks, &scope).await? else {
            continue;
        };
        let mut set = store::get_rights(&state.git_ns, &scope).await?;
        let Some(row) = set.rows.iter_mut().find(|r| {
            r.subject == item.subject
                && r.right == item.right
                && r.review.as_ref().is_some_and(|v| v.granter == granter)
        }) else {
            continue;
        };
        let Some(by) = deciders.iter().find(|d| {
            d.did != item.subject && crate::acl::resource_grant::granter_covers(d, item.right, &q)
        }) else {
            uncovered.push(item.clone());
            continue;
        };
        row.granted_by = by.did.clone();
        row.granter_was_member = true;
        row.review = None;
        store::put_rights(&state.git_ns, &scope, &set).await?;
        audit(
            state,
            &by.did,
            Some(&item.subject),
            Audit {
                action: "gitNs.right.granted",
                namespace: snap.scope_namespace(&scope).map(|n| n.id.as_str()),
                resource: Some(item.resource.clone()),
                right: Some(item.right),
                policy_version: None,
                detail: Some("reaffirmed".into()),
            },
        )
        .await;
        reaffirmed.push(item.clone());
    }
    Ok(serde_json::json!({ "reaffirmed": reaffirmed, "notCovered": uncovered }))
}

/// Withdraw, now, the git grants `granter` made that are still under its
/// review — a declined `acl.grants.review` item. Returns how many went.
pub async fn withdraw_reviewed(
    state: &AppState,
    granter: &str,
    items: &[ReviewItem],
) -> Result<usize, AppError> {
    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns).await?;
    let vtc = vtc_actor(state).await;
    let mut withdrawn = 0;
    for item in items {
        let scope = item.scope.clone();
        if snap.scope_resource(&scope).is_none() {
            continue;
        }
        let mut set = store::get_rights(&state.git_ns, &scope).await?;
        let before = set.rows.len();
        set.rows.retain(|r| {
            !(r.subject == item.subject
                && r.right == item.right
                && r.review.as_ref().is_some_and(|v| v.granter == granter))
        });
        if set.rows.len() == before {
            continue;
        }
        store::put_rights(&state.git_ns, &scope, &set).await?;
        audit(
            state,
            &vtc,
            Some(&item.subject),
            Audit {
                action: "gitNs.right.revoked",
                namespace: snap.scope_namespace(&scope).map(|n| n.id.as_str()),
                resource: Some(item.resource.clone()),
                right: Some(item.right),
                policy_version: None,
                detail: Some("granterDeparted".into()),
            },
        )
        .await;
        after_loss(state, &vtc, &snap, &scope, &[item.right]).await?;
        withdrawn += 1;
    }
    Ok(withdrawn)
}

/// A departed member's forge accounts go with them (git-ns/account/link,
/// *Consent/purpose*: "MUST delete it when the member leaves").
///
/// Its own pass, not part of [`sweep_departures`]: that one returns early when
/// no departed member held a right, and a member who linked an account and
/// held no right would then keep the link for good.
pub async fn sweep_departed_links(state: &AppState) -> Result<bool, AppError> {
    let _guard = store::write_lock().await;
    let mut changed = false;
    for m in crate::members::list_members(&state.members_ks).await? {
        if m.removed_at.is_some() && m.extensions.get("forges").is_some_and(|f| !f.is_null()) {
            crate::members::storage::edit_member(&state.members_ks, &m.did, |m| {
                m.removed_at.is_some()
                    && m.extensions
                        .as_object_mut()
                        .is_some_and(|o| o.remove("forges").is_some())
            })
            .await?;
            changed = true;
        }
    }
    Ok(changed)
}

/// The DID a sweep's audit rows name as actor: the community itself.
async fn vtc_actor(state: &AppState) -> String {
    state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_else(|| "vtc-unknown".into())
}

/// Remove lapsed rows and record each lapse.
pub async fn sweep_expiry(state: &AppState) -> Result<bool, AppError> {
    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns).await?;
    let t = now();
    let mut changed = false;
    for (scope, set) in &snap.rights {
        let (lapsed, live): (Vec<_>, Vec<_>) =
            set.rows.iter().cloned().partition(|r| r.is_lapsed(t));
        if lapsed.is_empty() {
            continue;
        }
        changed = true;
        let resource = snap
            .scope_resource(scope)
            .map(|r| r.to_string())
            .unwrap_or_default();
        let ns_id = snap.scope_namespace(scope).map(|n| n.id.clone());
        let vtc = vtc_actor(state).await;
        for row in &lapsed {
            // The community lapses the right; the granter may have left.
            audit(
                state,
                &vtc,
                Some(&row.subject),
                Audit {
                    action: "gitNs.right.lapsed",
                    namespace: ns_id.as_deref(),
                    resource: Some(resource.clone()),
                    right: Some(row.right),
                    policy_version: None,
                    detail: None,
                },
            )
            .await;
        }
        let mut next = set.clone();
        next.rows = live;
        store::put_rights(&state.git_ns, scope, &next).await?;
        if let Scope::Repo(id) = scope
            && lapsed.iter().any(|r| r.right == Right::RepoOwn)
            && !next.rows.iter().any(|r| r.right == Right::RepoOwn)
            && let Some(mut repo) = snap.repo(id).cloned()
            && repo.state == RepoState::Active
        {
            repo.state = RepoState::Orphaned;
            store::put_repo(&state.git_ns.ks, &repo).await?;
        }
    }
    Ok(changed)
}

/// Discard bindings nobody completed and forget old link attempts.
pub async fn sweep_pending(state: &AppState) -> Result<bool, AppError> {
    let _guard = store::write_lock().await;
    let t = now();
    let mut changed = false;
    for ns in store::list_namespaces(&state.git_ns.ks).await? {
        if ns.state == NamespaceState::Pending
            && ns.requested_at + chrono::Duration::hours(PENDING_BIND_HOURS) < t
        {
            store::delete_namespace(&state.git_ns.ks, &ns.id).await?;
            audit(
                state,
                &ns.bound_by,
                None,
                Audit {
                    action: "gitNs.namespace.bindExpired",
                    namespace: Some(&ns.id),
                    resource: Some(ns.resource().to_string()),
                    right: None,
                    policy_version: None,
                    detail: None,
                },
            )
            .await;
            changed = true;
        }
    }
    for mut link in store::list_links(&state.git_ns.ks).await? {
        if link.state == LinkState::Pending && link.expires_at <= t {
            link.state = LinkState::Expired;
            link.finished_at = Some(t);
            store::put_link(&state.git_ns.ks, &link).await?;
        } else if link.state != LinkState::Pending
            && link
                .finished_at
                .is_some_and(|f| f + chrono::Duration::days(LINK_MEMORY_DAYS) < t)
        {
            store::delete_link(&state.git_ns.ks, &link.id).await?;
        }
    }
    Ok(changed)
}

/// Rights issued by members who have since left — the *Issued by departed
/// members* review list (design §5.4). Keyed by granter.
pub async fn issued_by_departed(
    state: &AppState,
) -> Result<BTreeMap<String, Vec<(Scope, super::model::RightRow)>>, AppError> {
    let snap = Snapshot::load(&state.git_ns).await?;
    let mut out: BTreeMap<String, Vec<(Scope, super::model::RightRow)>> = BTreeMap::new();
    let mut cache: BTreeMap<String, bool> = BTreeMap::new();
    for (scope, set) in &snap.rights {
        for row in &set.rows {
            if !row.granter_was_member {
                continue;
            }
            let member = match cache.get(&row.granted_by) {
                Some(m) => *m,
                None => {
                    let m = standing(state, &row.granted_by).await?.member;
                    cache.insert(row.granted_by.clone(), m);
                    m
                }
            };
            if !member {
                out.entry(row.granted_by.clone())
                    .or_default()
                    .push((scope.clone(), row.clone()));
            }
        }
    }
    Ok(out)
}

/// Namespaces bound with no live admin, for the admin surface.
pub fn headless(snap: &Snapshot) -> Vec<String> {
    let t = now();
    snap.namespaces
        .iter()
        .filter(|n| n.state == NamespaceState::Bound && rules::admins(snap, &n.id, t).is_empty())
        .map(|n| n.id.clone())
        .collect()
}
