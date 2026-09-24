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

use super::model::{LinkAttempt, Namespace, Repo, RightRow, RightsSet, Scope};

static WRITE_LOCK: Mutex<()> = Mutex::const_new(());

/// Serialise every mutation of the git-namespace records.
pub async fn write_lock() -> MutexGuard<'static, ()> {
    WRITE_LOCK.lock().await
}

const NS_PREFIX: &str = "ns:";
const REPO_PREFIX: &str = "repo:";
const RIGHTS_PREFIX: &str = "rights:";
const LINK_PREFIX: &str = "link:";

async fn list_prefix<T: DeserializeOwned>(
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

pub async fn get_rights(ks: &KeyspaceHandle, scope: &Scope) -> Result<RightsSet, AppError> {
    Ok(ks
        .get::<RightsSet>(format!("{RIGHTS_PREFIX}{}", scope.key()))
        .await?
        .unwrap_or_default())
}

/// Write a scope's rights. An empty set removes the row rather than storing
/// an empty one, so the keyspace never accumulates husks.
pub async fn put_rights(
    ks: &KeyspaceHandle,
    scope: &Scope,
    set: &RightsSet,
) -> Result<(), AppError> {
    let key = format!("{RIGHTS_PREFIX}{}", scope.key());
    if set.rows.is_empty() {
        ks.remove(key).await
    } else {
        ks.insert(key, set).await
    }
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
    pub async fn load(ks: &KeyspaceHandle) -> Result<Snapshot, AppError> {
        let namespaces = list_namespaces(ks).await?;
        let repos = list_repos(ks).await?;
        let mut rights = BTreeMap::new();
        for (key, set) in list_prefix::<RightsSet>(ks, RIGHTS_PREFIX).await? {
            let rest = &key[RIGHTS_PREFIX.len()..];
            let scope = if let Some(id) = rest.strip_prefix("ns:") {
                Scope::Namespace(id.to_string())
            } else if let Some(id) = rest.strip_prefix("repo:") {
                Scope::Repo(id.to_string())
            } else {
                warn!(key, "skipping a rights row with an unknown scope");
                continue;
            };
            rights.insert(scope, set);
        }
        Ok(Snapshot {
            namespaces,
            repos,
            rights,
        })
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

    pub fn repo_by_forge_id(&self, namespace_id: &str, forge_id: &str) -> Option<&Repo> {
        self.repos
            .iter()
            .find(|r| r.namespace_id == namespace_id && r.forge_id.as_deref() == Some(forge_id))
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
