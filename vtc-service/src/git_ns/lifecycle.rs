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
    changed |= sweep_expiry(state).await?;
    changed |= sweep_pending(state).await?;
    Ok(changed)
}

/// Revoke the rights of members who have left, orphan what they owned alone,
/// and — under `cascade_on_departure` — revoke what they granted.
pub async fn sweep_departures(state: &AppState) -> Result<bool, AppError> {
    let settings = policy::active_settings(state).await;
    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let t = now();

    // Who is a question: every subject that was a member, and every granter
    // that was, when cascading.
    let mut candidates = BTreeSet::new();
    for set in snap.rights.values() {
        for row in &set.rows {
            if row.subject_was_member {
                candidates.insert(row.subject.clone());
            }
            if settings.cascade_on_departure && row.granter_was_member {
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
    if departed.is_empty() {
        return Ok(false);
    }

    let mut changed = false;
    let vtc = vtc_actor(state).await;
    for (scope, set) in &snap.rights {
        let resource = snap
            .scope_resource(scope)
            .map(|r| r.to_string())
            .unwrap_or_default();
        let ns_id = snap.scope_namespace(scope).map(|n| n.id.clone());
        let (gone, kept): (Vec<_>, Vec<_>) = set.rows.iter().cloned().partition(|r| {
            (r.subject_was_member && departed.contains(&r.subject))
                || (settings.cascade_on_departure
                    && r.granter_was_member
                    && departed.contains(&r.granted_by))
        });
        if gone.is_empty() {
            continue;
        }
        changed = true;
        for row in &gone {
            let why = if departed.contains(&row.subject) {
                "departed"
            } else {
                "granterDeparted"
            };
            info!(right = %row.right, %resource, why, "git right revoked");
            // The community acted, not the member; and a departed member's
            // DID does not go into a new audit row in plaintext, because the
            // departure may be an erasure and this row would outlive it. The
            // revocation of a *cascaded* grant names its (still present)
            // subject as usual.
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
                    detail: Some(why.into()),
                },
            )
            .await;
        }
        let mut next = set.clone();
        next.rows = kept;
        store::put_rights(&state.git_ns.ks, scope, &next).await?;

        // Last owner gone → orphaned, governed by the namespace admins.
        if let Scope::Repo(id) = scope
            && gone.iter().any(|r| r.right == Right::RepoOwn)
            && !next
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
                &vtc,
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
            && gone.iter().any(|r| r.right == Right::NsAdmin)
            && !next
                .rows
                .iter()
                .any(|r| r.right == Right::NsAdmin && r.is_live(t))
        {
            warn!(
                namespace = %id,
                "the last git.ns.admin of this namespace has left the community; it has no \
                 admin until it is unbound and bound again"
            );
        }
    }

    // A departed member's forge accounts go with them (git-ns/account/link,
    // *Consent/purpose*: "MUST delete it when the member leaves").
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
    let snap = Snapshot::load(&state.git_ns.ks).await?;
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
        store::put_rights(&state.git_ns.ks, scope, &next).await?;
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
    let snap = Snapshot::load(&state.git_ns.ks).await?;
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
