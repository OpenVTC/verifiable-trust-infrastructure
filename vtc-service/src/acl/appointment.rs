//! Appointments: one resource of one kind run by a member who holds a capability
//! qualified to it as a **resource grant** on their access-control entry, beside their
//! role and never inside its ceiling, so a member with no administrative role may hold
//! it. Two kinds exist:
//!
//! | kind | grant | tasks |
//! |---|---|---|
//! | [`Kind::GroupManager`] | `vtc.groups.manage` qualified `group:<groupId>` | `vtc/groups/managers/*` |
//! | [`Kind::BoardFacilitator`] | `vtc.boards.manage` qualified `board:<boardId>` | `vtc/boards/facilitators/*` (VTI-BRD-090 – 093) |
//!
//! An appointment is a delegation (VTI-ACL-071): it is bounded at write time by the
//! signer's own holding, and when its granter departs the community, or no longer covers
//! it, it goes **to review** — an `acl.grants.review` item asks the community's
//! administrators to re-affirm it under their own authority. Declined, or not re-affirmed
//! by the deadline (the action lifetime), it is withdrawn ([`sweep`]). Never left
//! standing silently.
//!
//! Every write takes the git-namespace write lock: an `acl/*` write re-reads an entry's
//! resource grants under it (`acl::ops::commit_grant`), so a grant written here is
//! never lost to a racing role change.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use tracing::info;
use vti_common::error::AppError;

use crate::acl::resource_grant::{GrantReview, ResourceGrant};
use crate::acl::{Capability, ResourceQualifier, VtcAclEntry, get_acl_entry, store_acl_entry};
use crate::server::AppState;

/// What an appointment appoints its holder to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A manager of one community group.
    GroupManager,
    /// A facilitator of one community board.
    BoardFacilitator,
}

impl Kind {
    /// The capability the grant carries.
    #[must_use]
    pub fn capability(self) -> Capability {
        match self {
            Kind::GroupManager => Capability::GroupsManage,
            Kind::BoardFacilitator => Capability::BoardsManage,
        }
    }

    /// The qualifier naming resource `id`.
    #[must_use]
    pub fn qualifier(self, id: &str) -> ResourceQualifier {
        match self {
            Kind::GroupManager => ResourceQualifier::Group(id.to_string()),
            Kind::BoardFacilitator => ResourceQualifier::Board(id.to_string()),
        }
    }

    /// The resource `g` appoints its holder to run, if it is an appointment of this kind.
    #[must_use]
    pub fn of(self, g: &ResourceGrant) -> Option<&str> {
        if g.capability != self.capability() {
            return None;
        }
        match (self, &g.resource) {
            (Kind::GroupManager, ResourceQualifier::Group(id))
            | (Kind::BoardFacilitator, ResourceQualifier::Board(id)) => Some(id.as_str()),
            _ => None,
        }
    }

    fn is(self, g: &ResourceGrant, id: &str) -> bool {
        self.of(g) == Some(id)
    }

    fn label(self) -> &'static str {
        match self {
            Kind::GroupManager => "group manager",
            Kind::BoardFacilitator => "board facilitator",
        }
    }
}

/// One appointment under review: who holds it, and to what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub subject: String,
    pub id: String,
}

/// Whether `entry` holds a live appointment of `kind` to `id` (not the capability
/// unqualified: that is no appointment).
#[must_use]
pub fn appointed(entry: &VtcAclEntry, kind: Kind, id: &str) -> bool {
    let now = Utc::now();
    entry
        .resource_grants
        .iter()
        .any(|g| kind.is(g, id) && g.is_live(now))
}

/// Write `subject`'s appointment of `kind` to `id`, delegated by `granter`. The caller has
/// checked the granter covers it.
///
/// # Errors
/// `NotFound` when `subject` has no access-control entry; a store failure.
pub async fn appoint(
    state: &AppState,
    kind: Kind,
    granter: &str,
    subject: &str,
    id: &str,
    reason: Option<String>,
) -> Result<(), AppError> {
    let _guard = crate::git_ns::store::write_lock().await;
    let mut entry = get_acl_entry(&state.acl_ks, subject)
        .await?
        .ok_or_else(|| AppError::NotFound("no access-control entry".into()))?;
    if appointed(&entry, kind, id) {
        return Ok(());
    }
    let grant: ResourceGrant = serde_json::from_value(serde_json::json!({
        "capability": kind.capability().as_str(),
        "resource": kind.qualifier(id).to_string(),
        "delegatedBy": granter,
        "grantedAt": Utc::now(),
        "reason": reason,
        "subjectWasMember": true,
        "granterWasMember": crate::member_portal::active::active_member(state, granter)
            .await?
            .is_some(),
    }))
    .map_err(|e| AppError::Internal(format!("{} grant: {e}", kind.label())))?;
    entry.resource_grants.push(grant);
    store_acl_entry(&state.acl_ks, &entry).await
}

/// Remove `subject`'s appointment of `kind` to `id`. `false`: they held none.
///
/// # Errors
/// A store failure.
pub async fn withdraw(
    state: &AppState,
    kind: Kind,
    subject: &str,
    id: &str,
) -> Result<bool, AppError> {
    let _guard = crate::git_ns::store::write_lock().await;
    let Some(mut entry) = get_acl_entry(&state.acl_ks, subject).await? else {
        return Ok(false);
    };
    let before = entry.resource_grants.len();
    entry.resource_grants.retain(|g| !kind.is(g, id));
    if entry.resource_grants.len() == before {
        return Ok(false);
    }
    store_acl_entry(&state.acl_ks, &entry).await?;
    Ok(true)
}

/// Remove every appointment of `kind` to `id`, as the resource's deletion does.
///
/// # Errors
/// A store failure.
pub async fn withdraw_all(state: &AppState, kind: Kind, id: &str) -> Result<usize, AppError> {
    let _guard = crate::git_ns::store::write_lock().await;
    let mut n = 0;
    for mut entry in crate::acl::list_acl_entries(&state.acl_ks).await? {
        let before = entry.resource_grants.len();
        entry.resource_grants.retain(|g| !kind.is(g, id));
        if entry.resource_grants.len() != before {
            n += before - entry.resource_grants.len();
            store_acl_entry(&state.acl_ks, &entry).await?;
        }
    }
    Ok(n)
}

/// One live appointment as the access-control list holds it.
#[derive(Debug, Clone)]
pub struct Appointment {
    /// The holder's DID.
    pub subject: String,
    /// The granter's DID.
    pub granter: String,
    pub granted_at: DateTime<Utc>,
    /// When it is withdrawn unless re-affirmed, while it is under review.
    pub review_deadline: Option<DateTime<Utc>>,
}

/// Every live appointment of `kind` to `id`, oldest first.
///
/// # Errors
/// A store failure.
pub async fn holders(state: &AppState, kind: Kind, id: &str) -> Result<Vec<Appointment>, AppError> {
    let now = Utc::now();
    let mut out = Vec::new();
    for entry in crate::acl::list_acl_entries(&state.acl_ks).await? {
        for g in &entry.resource_grants {
            if kind.is(g, id) && g.is_live(now) {
                out.push(Appointment {
                    subject: entry.did.clone(),
                    granter: g.delegated_by.clone(),
                    granted_at: g.granted_at,
                    review_deadline: g.review.as_ref().map(|r| r.deadline),
                });
            }
        }
    }
    out.sort_by_key(|a| a.granted_at);
    Ok(out)
}

/// The directory entries holding a live appointment of `kind` to `id`, sorted:
/// informational, read from the access-control list.
///
/// # Errors
/// A store failure.
pub async fn holder_entries(
    state: &AppState,
    kind: Kind,
    id: &str,
) -> Result<Vec<String>, AppError> {
    let mut out = BTreeSet::new();
    for a in holders(state, kind, id).await? {
        if let Some(e) = crate::directory::cards::entry_of(state.directory.ks(), &a.subject).await?
        {
            out.insert(e);
        }
    }
    Ok(out.into_iter().collect())
}

/// Whether `granter` stands behind an appointment of `kind` to `id`: still an active
/// member, and still covering the grant.
async fn stands_behind(
    state: &AppState,
    kind: Kind,
    granter: &str,
    id: &str,
) -> Result<bool, AppError> {
    let q = kind.qualifier(id);
    if crate::member_portal::active::active_member(state, granter)
        .await?
        .is_none()
    {
        // An administrator with no member record still stands behind what they granted
        // while their entry covers it.
        let entry = get_acl_entry(&state.acl_ks, granter).await?;
        return Ok(
            entry.is_some_and(|e| e.is_administrator() && e.can(kind.capability(), Some(&q)))
        );
    }
    Ok(get_acl_entry(&state.acl_ks, granter)
        .await?
        .is_some_and(|e| e.can(kind.capability(), Some(&q))))
}

/// What one [`sweep`] pass found: the appointments withdrawn, and those newly put to
/// review, by granter, with the review's deadline.
pub struct Swept {
    pub withdrawn: Vec<Held>,
    pub raised: BTreeMap<String, Vec<Held>>,
    pub deadline: DateTime<Utc>,
}

/// One pass over every appointment of `kind`: a granter who departed or no longer covers
/// it puts it under review, a granter back behind it clears the review, and a review past
/// its deadline withdraws the grant. The caller raises one review item per granter in
/// [`Swept::raised`].
///
/// # Errors
/// A store failure.
pub async fn sweep(state: &AppState, kind: Kind) -> Result<Swept, AppError> {
    let lifetime = crate::admin_actions::setting(state, crate::config_store::ACTION_LIFETIME)
        .await
        .unwrap_or(7 * 24 * 3600);
    let now = Utc::now();
    let deadline = now + Duration::seconds(lifetime.min(i64::MAX as u64) as i64);
    let mut raised: BTreeMap<String, Vec<Held>> = BTreeMap::new();
    let mut withdrawn = Vec::new();
    let _guard = crate::git_ns::store::write_lock().await;
    for mut entry in crate::acl::list_acl_entries(&state.acl_ks).await? {
        let mut changed = false;
        let mut kept = Vec::with_capacity(entry.resource_grants.len());
        for mut g in entry.resource_grants.clone() {
            let Some(id) = kind.of(&g).map(str::to_string) else {
                kept.push(g);
                continue;
            };
            // A grant the granter made to themselves has no granter to depart.
            if g.delegated_by == entry.did {
                kept.push(g);
                continue;
            }
            let behind = stands_behind(state, kind, &g.delegated_by, &id).await?;
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
                        .push(Held {
                            subject: entry.did.clone(),
                            id,
                        });
                    changed = true;
                }
                (Some(r), false) if r.deadline <= now => {
                    info!(resource = %id, kind = kind.label(), "an appointment was withdrawn: its granter no longer stands behind it");
                    withdrawn.push(Held {
                        subject: entry.did.clone(),
                        id,
                    });
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
    Ok(Swept {
        withdrawn,
        raised,
        deadline,
    })
}

/// Re-affirm each listed appointment still under `granter`'s review under the first
/// approver whose own entry covers it, who becomes its granter.
///
/// # Errors
/// A store failure.
pub async fn reaffirm(
    state: &AppState,
    kind: Kind,
    granter: &str,
    items: &[Held],
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
            d.did != item.subject && d.can(kind.capability(), Some(&kind.qualifier(&item.id)))
        });
        let Some(g) = entry.resource_grants.iter_mut().find(|g| {
            kind.is(g, &item.id) && g.review.as_ref().is_some_and(|r| r.granter == granter)
        }) else {
            continue;
        };
        match decider {
            Some(d) => {
                g.delegated_by = d.did.clone();
                g.granted_at = Utc::now();
                g.review = None;
                reaffirmed += 1;
                store_acl_entry(&state.acl_ks, &entry).await?;
            }
            None => uncovered += 1,
        }
    }
    Ok(serde_json::json!({ "reaffirmed": reaffirmed, "uncovered": uncovered }))
}

/// Withdraw each listed appointment still under `granter`'s review, as a declined review
/// does.
///
/// # Errors
/// A store failure.
pub async fn withdraw_reviewed(
    state: &AppState,
    kind: Kind,
    granter: &str,
    items: &[Held],
) -> Result<(), AppError> {
    let _guard = crate::git_ns::store::write_lock().await;
    for item in items {
        let Some(mut entry) = get_acl_entry(&state.acl_ks, &item.subject).await? else {
            continue;
        };
        let before = entry.resource_grants.len();
        entry.resource_grants.retain(|g| {
            !(kind.is(g, &item.id) && g.review.as_ref().is_some_and(|r| r.granter == granter))
        });
        if entry.resource_grants.len() != before {
            store_acl_entry(&state.acl_ks, &entry).await?;
        }
    }
    Ok(())
}
