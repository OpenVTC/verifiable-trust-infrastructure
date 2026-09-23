//! `git-ns/view/0.1` — what a member may see, and the administrator's
//! complete view the admin console reads.
//!
//! The member's view is the specification's (*Request*):
//!
//! 1. every namespace that contains or is contained by `resource`;
//! 2. every repository recorded in it, except `unmanaged` ones, which only a
//!    `git.ns.admin` over them sees — they are the only people who can adopt
//!    them — each with its owners, because who owns a repository is visible
//!    to every member;
//! 3. the recorded rights (never implied ones) the caller holds, plus every
//!    right on a resource the caller governs (`own` or `ns.admin`, explicit or
//!    implied), with `reason` only on those governed resources.
//!
//! A resource that matches nothing yields empty lists, not an error.

use serde_json::{Value, json};
use trust_tasks_rs::specs::git_ns::view::v0_1 as view_wire;
use vti_common::error::AppError;

use super::model::{RepoState, Resource};
use super::ops::now;
use super::rules;
use super::store::Snapshot;
use super::wire;

/// Who is looking.
pub enum Viewer<'a> {
    /// A member, seeing what the specification entitles them to.
    Member(&'a str),
    /// A community administrator on the admin console, seeing every record
    /// and every reason. Not a git right: the console's authority is the
    /// administrator's ACL entry, and it confers reading, never granting.
    Administrator,
}

fn related(filter: Option<&Resource>, r: &Resource) -> bool {
    match filter {
        None => true,
        Some(f) => f.contains(r) || r.contains(f),
    }
}

/// Build the view as JSON in the specification's response shape.
pub fn build(snap: &Snapshot, viewer: Viewer<'_>, filter: Option<&Resource>) -> Value {
    let t = now();
    let governs = |res: &Resource| match &viewer {
        Viewer::Administrator => true,
        Viewer::Member(did) => rules::governs(snap, did, res, t),
    };

    let namespaces: Vec<Value> = snap
        .namespaces
        .iter()
        .filter(|n| related(filter, &n.resource()))
        .map(wire::namespace)
        .collect();

    let mut repos = Vec::new();
    for repo in &snap.repos {
        let Some(res) = repo.resource() else {
            continue;
        };
        if let Some(f) = filter
            && !f.contains(&res)
        {
            continue;
        }
        if repo.state == RepoState::Unmanaged {
            let admin = match &viewer {
                Viewer::Administrator => true,
                Viewer::Member(did) => rules::governs(snap, did, &res.namespace_resource(), t),
            };
            if !admin {
                continue;
            }
        }
        let owners = rules::owners(snap, &repo.id, t);
        repos.push(wire::repo_summary(repo, &owners));
    }

    let mut rights = Vec::new();
    for (scope, set) in &snap.rights {
        let Some(res) = snap.scope_resource(scope) else {
            continue;
        };
        // "That resource and everything it contains" — a namespace-wide right
        // is not *on* a repository, so a repository filter leaves it out.
        if let Some(f) = filter
            && !f.contains(&res)
        {
            continue;
        }
        let governed = governs(&res);
        for row in set.rows.iter().filter(|r| r.is_live(t)) {
            let own = matches!(&viewer, Viewer::Member(did) if *did == row.subject);
            if governed || own {
                rights.push(wire::right_record(row, &res, governed));
            }
        }
    }

    json!({ "namespaces": namespaces, "repos": repos, "rights": rights })
}

/// The member's view, as the generated response type.
pub fn for_member(
    snap: &Snapshot,
    did: &str,
    filter: Option<&Resource>,
) -> Result<view_wire::Response, AppError> {
    wire::into(build(snap, Viewer::Member(did), filter))
}

/// The administrator's view, as the generated response type.
pub fn for_administrator(
    snap: &Snapshot,
    filter: Option<&Resource>,
) -> Result<view_wire::Response, AppError> {
    wire::into(build(snap, Viewer::Administrator, filter))
}
