//! Persistence for the git-namespace records, over the service's ordinary
//! keyspace abstraction.
//!
//! Three keyspaces, split by what a backup should carry:
//!
//! - [`crate::store::keyspaces::GIT_NS`] — namespaces, repositories, rights
//!   and account-link attempts. The source of truth; backed up.
//! - [`crate::store::keyspaces::GIT_NS_JOBS`] — bridge jobs. Durable while
//!   they are outstanding, re-derivable from the store when they are not.
//! - [`crate::store::keyspaces::GIT_NS_PROJECTION`] — the mirror of what has
//!   been published to the Trust Registry. A cache of a remote effect,
//!   rebuildable by reconciling against the store, exactly like the
//!   membership mirror in `registry_records`.
//!
//! ## One writer at a time
//!
//! The fixed rules include two invariants over *sets* of rows — a repository
//! keeps an owner, a namespace keeps an admin — and a check-then-write over a
//! set is a race between two revocations that each see the other's row. Every
//! mutation of the records therefore runs under [`write_lock`], a process-wide
//! async mutex, which is sound because one VTC is one process: the same shape
//! as the `MODE_B_LOCK` the bootstrap carve-out relies on.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use tokio::sync::{Mutex, MutexGuard};
use tracing::warn;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::GitNsHandles;
use super::model::{LinkAttempt, Namespace, Repo, RightRow, RightsSet, Scope};

static WRITE_LOCK: Mutex<()> = Mutex::const_new(());

/// Serialise every mutation of the git-namespace records.
pub async fn write_lock() -> MutexGuard<'static, ()> {
    WRITE_LOCK.lock().await
}

const NS_PREFIX: &str = "ns:";
const REPO_PREFIX: &str = "repo:";
/// Where rights lived before phase C3 moved them onto the ACL entries; read
/// only by [`super::migrate`].
pub(crate) const RIGHTS_PREFIX: &str = "rights:";
const LINK_PREFIX: &str = "link:";

pub(crate) async fn list_prefix<T: DeserializeOwned>(
    ks: &KeyspaceHandle,
    prefix: &str,
) -> Result<Vec<(String, T)>, AppError> {
    let rows = ks.prefix_iter_raw(prefix.as_bytes().to_vec()).await?;
    let mut out = Vec::with_capacity(rows.len());
    for (k, v) in rows {
        let key = String::from_utf8_lossy(&k).to_string();
        match serde_json::from_slice::<T>(&v) {
            Ok(t) => out.push((key, t)),
            Err(e) => warn!(key, error = %e, "skipping unreadable git-ns row"),
        }
    }
    Ok(out)
}

pub async fn get_namespace(ks: &KeyspaceHandle, id: &str) -> Result<Option<Namespace>, AppError> {
    ks.get(format!("{NS_PREFIX}{id}")).await
}

pub async fn put_namespace(ks: &KeyspaceHandle, ns: &Namespace) -> Result<(), AppError> {
    ks.insert(format!("{NS_PREFIX}{}", ns.id), ns).await
}

pub async fn delete_namespace(ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    ks.remove(format!("{NS_PREFIX}{id}")).await
}

pub async fn list_namespaces(ks: &KeyspaceHandle) -> Result<Vec<Namespace>, AppError> {
    Ok(list_prefix(ks, NS_PREFIX)
        .await?
        .into_iter()
        .map(|(_, v)| v)
        .collect())
}

pub async fn get_repo(ks: &KeyspaceHandle, id: &str) -> Result<Option<Repo>, AppError> {
    ks.get(format!("{REPO_PREFIX}{id}")).await
}

pub async fn put_repo(ks: &KeyspaceHandle, repo: &Repo) -> Result<(), AppError> {
    ks.insert(format!("{REPO_PREFIX}{}", repo.id), repo).await
}

pub async fn delete_repo(ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    ks.remove(format!("{REPO_PREFIX}{id}")).await
}

pub async fn list_repos(ks: &KeyspaceHandle) -> Result<Vec<Repo>, AppError> {
    Ok(list_prefix(ks, REPO_PREFIX)
        .await?
        .into_iter()
        .map(|(_, v)| v)
        .collect())
}

/// The rights recorded on one scope, read from the ACL entries that hold them
/// (phase C3: every right is a resource grant on its holder's entry,
/// [`crate::acl::resource_grant`]).
pub async fn get_rights(h: &GitNsHandles, scope: &Scope) -> Result<RightsSet, AppError> {
    let mut set = RightsSet::default();
    for entry in holders(&h.acl_ks).await? {
        for g in &entry.resource_grants {
            if grant_on_scope(&h.ks, g, scope).await?
                && let Some(row) = row_of(&entry.did, g)
            {
                set.rows.push(row);
            }
        }
    }
    sort_rows(&mut set.rows);
    Ok(set)
}

/// Write a scope's rights: each subject's entry is made to hold exactly the
/// rows `set` gives it on this scope, as resource grants.
///
/// - A subject with no entry gets one of the `application` community role —
///   a non-member holding only grants (the bridge, an external signer) — so
///   no grant ever sits on nothing (**VTI-ACL-037**). An elevated right never
///   goes to one: the fixed rules give elevated rights to members only (rule
///   5), and this refuses rather than writes if a caller gets that wrong.
/// - An `application` entry left holding nothing is removed.
/// - Entries that gain a grant are written before entries that only lose one,
///   so a crash part-way through a transfer leaves two owners, never none.
///
/// Callers hold [`write_lock`].
pub async fn put_rights(h: &GitNsHandles, scope: &Scope, set: &RightsSet) -> Result<(), AppError> {
    use crate::acl::resource_grant as rg;
    let qualifier = scope_qualifier(&h.ks, scope).await?;
    if qualifier.is_none() && !set.rows.is_empty() {
        return Err(AppError::Internal(format!(
            "git-ns: no namespace or repository record for {}; its rights cannot be written",
            scope.key()
        )));
    }
    let mut desired: BTreeMap<String, Vec<rg::ResourceGrant>> = BTreeMap::new();
    if let Some(q) = qualifier.as_ref() {
        for row in &set.rows {
            desired
                .entry(row.subject.clone())
                .or_default()
                .push(grant_of(row, q.clone()));
        }
    }

    let (mut gaining, mut losing, mut removing) = (Vec::new(), Vec::new(), Vec::new());
    for mut entry in holders(&h.acl_ks).await? {
        let mut kept = Vec::with_capacity(entry.resource_grants.len());
        let mut before = Vec::new();
        for g in std::mem::take(&mut entry.resource_grants) {
            if grant_on_scope(&h.ks, &g, scope).await? {
                before.push(g);
            } else {
                kept.push(g);
            }
        }
        let after = desired.remove(&entry.did).unwrap_or_default();
        if before == after {
            continue;
        }
        let gains = after.iter().any(|g| !before.contains(g));
        kept.extend(after);
        entry.resource_grants = kept;
        if entry.resource_grants.is_empty() && entry.is_application() {
            removing.push(entry.did.clone());
        } else if gains {
            gaining.push(entry);
        } else {
            losing.push(entry);
        }
    }
    // Subjects the index does not name: an entry with no grants yet, or none.
    for (did, grants) in desired {
        let entry = match crate::acl::get_acl_entry(&h.acl_ks, &did).await? {
            Some(mut e) => {
                e.resource_grants.extend(grants);
                e
            }
            None => {
                if let Some(g) = grants
                    .iter()
                    .find(|g| g.git_right().is_some_and(|r| r.is_elevated()))
                {
                    return Err(AppError::Internal(format!(
                        "git-ns: refusing to write {} to {did}, which holds no membership — an \
                         elevated right goes to a current member only",
                        g.display()
                    )));
                }
                let by = grants
                    .first()
                    .map(|g| g.delegated_by.clone())
                    .unwrap_or_default();
                let mut e = crate::acl::VtcAclEntry::new(
                    did.clone(),
                    crate::acl::VtcRole::Application,
                    crate::acl::AdminAuthority::none(),
                    by,
                );
                e.label = Some("holds git rights without membership".into());
                e.resource_grants = grants;
                e
            }
        };
        gaining.push(entry);
    }

    for e in gaining.iter().chain(losing.iter()) {
        crate::acl::store_acl_entry(&h.acl_ks, e).await?;
        if e.resource_grants.is_empty() {
            rg::index_holder(&h.acl_ks, &e.did, false).await?;
        }
    }
    for did in removing {
        h.acl_ks.remove(format!("acl:{did}")).await?;
        rg::index_holder(&h.acl_ks, &did, false).await?;
    }
    Ok(())
}

/// The entries that hold resource grants, read through the holder index.
async fn holders(acl_ks: &KeyspaceHandle) -> Result<Vec<crate::acl::VtcAclEntry>, AppError> {
    let mut out = Vec::new();
    for did in crate::acl::resource_grant::indexed_holders(acl_ks).await? {
        if let Some(e) = crate::acl::get_acl_entry(acl_ks, &did).await?
            && !e.resource_grants.is_empty()
        {
            out.push(e);
        }
    }
    Ok(out)
}

/// The qualifier a scope's rights are held at, if its records exist.
pub async fn scope_qualifier(
    ks: &KeyspaceHandle,
    scope: &Scope,
) -> Result<Option<crate::acl::ResourceQualifier>, AppError> {
    use crate::acl::resource_grant as rg;
    Ok(match scope {
        Scope::Namespace(id) => get_namespace(ks, id)
            .await?
            .map(|n| rg::namespace_qualifier(&n.forge, &n.owner)),
        Scope::Repo(id) => match get_repo(ks, id).await? {
            Some(r) => get_namespace(ks, &r.namespace_id)
                .await?
                .map(|n| rg::repo_qualifier(&n.forge, &n.owner, id)),
            None => None,
        },
    })
}

/// Whether `g` is a grant on `scope`. A repository grant is matched by the id
/// its qualifier names, so the rights of a repository whose record is already
/// gone can still be cleared.
async fn grant_on_scope(
    ks: &KeyspaceHandle,
    g: &crate::acl::resource_grant::ResourceGrant,
    scope: &Scope,
) -> Result<bool, AppError> {
    use crate::acl::ResourceQualifier as Q;
    if g.git_right().is_none() {
        return Ok(false);
    }
    Ok(match (scope, &g.resource) {
        (Scope::Repo(id), Q::GitRepo(_)) => {
            crate::acl::resource_grant::repo_id_of(&g.resource) == Some(id.as_str())
        }
        (Scope::Namespace(_), Q::GitNs(_)) => {
            scope_qualifier(ks, scope).await?.as_ref() == Some(&g.resource)
        }
        _ => false,
    })
}

/// The right row a grant is, as the fixed rules read it.
pub fn row_of(subject: &str, g: &crate::acl::resource_grant::ResourceGrant) -> Option<RightRow> {
    Some(RightRow {
        subject: subject.to_string(),
        right: g.git_right()?,
        granted_by: g.delegated_by.clone(),
        granted_at: g.granted_at,
        expires_at: g.expires_at,
        reason: g.reason.clone(),
        subject_was_member: g.subject_was_member,
        granter_was_member: g.granter_was_member,
        break_glass: g.break_glass.clone(),
        review: g.review.clone(),
    })
}

/// The grant a right row is, at `resource`.
pub fn grant_of(
    row: &RightRow,
    resource: crate::acl::ResourceQualifier,
) -> crate::acl::resource_grant::ResourceGrant {
    let (capability, grade) = crate::acl::resource_grant::capability_for(row.right);
    crate::acl::resource_grant::ResourceGrant {
        capability,
        resource,
        grade,
        delegated_by: row.granted_by.clone(),
        granted_at: row.granted_at,
        expires_at: row.expires_at,
        reason: row.reason.clone(),
        subject_was_member: row.subject_was_member,
        granter_was_member: row.granter_was_member,
        break_glass: row.break_glass.clone(),
        review: row.review.clone(),
    }
}

/// Grant order: oldest first, so "the owners, in grant order" reads the same
/// as it did when each scope kept its rows in a list.
fn sort_rows(rows: &mut [RightRow]) {
    rows.sort_by(|a, b| {
        (a.granted_at, &a.subject, a.right).cmp(&(b.granted_at, &b.subject, b.right))
    });
}

pub async fn get_link(ks: &KeyspaceHandle, id: &str) -> Result<Option<LinkAttempt>, AppError> {
    ks.get(format!("{LINK_PREFIX}{id}")).await
}

pub async fn put_link(ks: &KeyspaceHandle, link: &LinkAttempt) -> Result<(), AppError> {
    ks.insert(format!("{LINK_PREFIX}{}", link.id), link).await
}

pub async fn delete_link(ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    ks.remove(format!("{LINK_PREFIX}{id}")).await
}

pub async fn list_links(ks: &KeyspaceHandle) -> Result<Vec<LinkAttempt>, AppError> {
    Ok(list_prefix(ks, LINK_PREFIX)
        .await?
        .into_iter()
        .map(|(_, v)| v)
        .collect())
}

/// Every record at one instant — what the fixed rules, the view and the
/// projection are evaluated over.
///
/// Loaded whole because each of those questions is a question about sets
/// ("is this the last owner", "who holds what on this repository"), and a
/// community's namespaces are small enough that answering them from memory is
/// both simpler and cheaper than indexing.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub namespaces: Vec<Namespace>,
    pub repos: Vec<Repo>,
    pub rights: BTreeMap<Scope, RightsSet>,
}

impl Snapshot {
    /// Every record, the rights read from the ACL entries that hold them.
    ///
    /// A grant on an expired entry is left out: it confers nothing without a
    /// live entry (**VTI-ACL-037**). A grant whose namespace or repository has
    /// no record is left out too — it names nothing this community governs.
    pub async fn load(h: &GitNsHandles) -> Result<Snapshot, AppError> {
        use crate::acl::ResourceQualifier as Q;
        let mut snap = Snapshot::load_records(&h.ks).await?;
        let epoch = crate::auth::session::now_epoch();
        let mut rights: BTreeMap<Scope, RightsSet> = BTreeMap::new();
        for entry in holders(&h.acl_ks).await? {
            if entry.is_expired(epoch) {
                continue;
            }
            for g in &entry.resource_grants {
                let scope = match &g.resource {
                    Q::GitRepo(_) => crate::acl::resource_grant::repo_id_of(&g.resource)
                        .filter(|id| snap.repo(id).is_some())
                        .map(|id| Scope::Repo(id.to_string())),
                    Q::GitNs(path) => snap
                        .namespace_at(path)
                        .map(|n| Scope::Namespace(n.id.clone())),
                    _ => None,
                };
                if let (Some(scope), Some(row)) = (scope, row_of(&entry.did, g)) {
                    rights.entry(scope).or_default().rows.push(row);
                }
            }
        }
        for set in rights.values_mut() {
            sort_rows(&mut set.rows);
        }
        snap.rights = rights;
        Ok(snap)
    }

    /// Namespaces and repositories only — for a reader that asks nothing of
    /// rights (the hook relay's "is this resource the projection's").
    pub async fn load_records(ks: &KeyspaceHandle) -> Result<Snapshot, AppError> {
        Ok(Snapshot {
            namespaces: list_namespaces(ks).await?,
            repos: list_repos(ks).await?,
            rights: BTreeMap::new(),
        })
    }

    /// The namespace a `git-ns:` qualifier path names: the bound one, or the
    /// only one at that path.
    pub fn namespace_at(&self, path: &str) -> Option<&Namespace> {
        let at = |n: &&Namespace| format!("{}/{}", n.forge, n.owner) == path;
        self.namespaces
            .iter()
            .filter(at)
            .find(|n| n.state == super::model::NamespaceState::Bound)
            .or_else(|| self.namespaces.iter().find(at))
    }

    /// This snapshot with every unratified break-glass row left out — the
    /// rights a ratifier's authority may be counted through
    /// (`git-ns/right/ratify/0.1`, *Authorization*).
    pub fn without_unratified_break_glass(&self) -> Snapshot {
        let mut out = self.clone();
        for set in out.rights.values_mut() {
            set.rows.retain(|r| !r.is_unratified_break_glass());
        }
        out
    }

    pub fn namespace(&self, id: &str) -> Option<&Namespace> {
        self.namespaces.iter().find(|n| n.id == id)
    }

    pub fn repo(&self, id: &str) -> Option<&Repo> {
        self.repos.iter().find(|r| r.id == id)
    }

    /// The namespace, bound or pending, whose resource contains `resource`.
    pub fn namespace_containing(&self, resource: &super::model::Resource) -> Option<&Namespace> {
        self.namespaces
            .iter()
            .find(|n| n.resource().contains(resource))
    }

    /// The repository recorded at `resource`, or why there is no one answer.
    ///
    /// A name is held by at most one repository that is not `detached` — the
    /// bridge's events and adoption keep it so — and that one is the answer.
    /// Two such rows are an inconsistency nothing may act on: `Err`, for an
    /// administrator to resolve, never a guess. With no live row, the most
    /// recently created `detached` one — what the name last was, which
    /// adoption takes up with its rights and forge id cleared, so which of two
    /// equally old detached rows it takes changes nothing.
    pub fn lookup_repo(&self, resource: &str) -> Result<Option<&Repo>, String> {
        let detached = |r: &&Repo| r.state == super::model::RepoState::Detached;
        let at: Vec<&Repo> = self
            .repos
            .iter()
            .filter(|r| r.resource == resource)
            .collect();
        let live: Vec<&Repo> = at.iter().copied().filter(|r| !detached(r)).collect();
        match live.len() {
            0 => Ok(at
                .into_iter()
                .filter(detached)
                .max_by(|a, b| a.created_at.cmp(&b.created_at).then(b.id.cmp(&a.id)))),
            1 => Ok(Some(live[0])),
            n => Err(format!(
                "{n} governed repositories are recorded at {resource}; an administrator must \
                 resolve which one it is before anything is done there"
            )),
        }
    }

    /// [`Self::lookup_repo`] for reads: an ambiguous name is logged and reads
    /// as unrecorded. Anything that writes uses `lookup_repo` and refuses.
    pub fn repo_at(&self, resource: &str) -> Option<&Repo> {
        match self.lookup_repo(resource) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("{e}");
                None
            }
        }
    }

    /// Whether a live repository other than `except` already holds `forge_id`
    /// — forge ids are the forge's, so in any namespace.
    pub fn forge_id_held_elsewhere(&self, forge_id: &str, except: &str) -> Option<&Repo> {
        self.repos.iter().find(|r| {
            r.id != except
                && r.state != super::model::RepoState::Detached
                && r.forge_id.as_deref() == Some(forge_id)
        })
    }

    /// The live repository the forge knows as `forge_id`. A detached row is
    /// never an answer: it is history, not something an event can address,
    /// and the forge id may since have been recorded for a live one.
    pub fn repo_by_forge_id(&self, namespace_id: &str, forge_id: &str) -> Option<&Repo> {
        self.repos.iter().find(|r| {
            r.namespace_id == namespace_id
                && r.state != super::model::RepoState::Detached
                && r.forge_id.as_deref() == Some(forge_id)
        })
    }

    pub fn rows(&self, scope: &Scope) -> &[RightRow] {
        self.rights.get(scope).map_or(&[], |s| s.rows.as_slice())
    }

    /// The resource a scope's rights are on, if the scope still exists.
    pub fn scope_resource(&self, scope: &Scope) -> Option<super::model::Resource> {
        match scope {
            Scope::Namespace(id) => self.namespace(id).map(Namespace::resource),
            Scope::Repo(id) => self.repo(id).and_then(Repo::resource),
        }
    }

    /// The namespace a scope lies in.
    pub fn scope_namespace(&self, scope: &Scope) -> Option<&Namespace> {
        match scope {
            Scope::Namespace(id) => self.namespace(id),
            Scope::Repo(id) => self.repo(id).and_then(|r| self.namespace(&r.namespace_id)),
        }
    }
}
