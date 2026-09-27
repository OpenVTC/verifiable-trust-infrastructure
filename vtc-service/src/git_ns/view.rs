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
//!
//! `git-ns/view/0.5` adds the administrator's read (`scope: administrator`):
//! every record in the namespaces the caller administers, reasons included —
//! [`administrator_v5`] — and `breakGlass: true`, which narrows either answer
//! to break-glass records ([`narrow_to_break_glass`]).

use std::collections::BTreeSet;

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
    build_with(snap, viewer, filter, Shape::default(), None)
}

/// What a version of the view adds.
#[derive(Debug, Clone, Copy, Default)]
struct Shape {
    /// `git-ns/view/0.4`: records carry `breakGlass`, and every unratified
    /// break-glass record goes to every administrator it concerns.
    break_glass: bool,
    /// The caller holds the community-administrator capability.
    community_admin: bool,
}

/// `within`, when given, keeps the answer to those namespaces (by identifier):
/// a namespace outside it, a repository recorded in another, and a right on
/// either are left out — and so is a repository whose namespace is no longer
/// bound, which is in no namespace at all.
fn build_with(
    snap: &Snapshot,
    viewer: Viewer<'_>,
    filter: Option<&Resource>,
    shape: Shape,
    within: Option<&BTreeSet<String>>,
) -> Value {
    let t = now();
    let inside = |ns_id: &str| within.is_none_or(|w| w.contains(ns_id));
    let governs = |res: &Resource| match &viewer {
        Viewer::Administrator => true,
        Viewer::Member(did) => rules::governs(snap, did, res, t),
    };

    let namespaces: Vec<Value> = snap
        .namespaces
        .iter()
        .filter(|n| related(filter, &n.resource()) && inside(&n.id))
        .map(wire::namespace)
        .collect();

    let mut repos = Vec::new();
    for repo in &snap.repos {
        let Some(res) = repo.resource() else {
            continue;
        };
        if within.is_some()
            && (!inside(&repo.namespace_id) || snap.namespace(&repo.namespace_id).is_none())
        {
            continue;
        }
        if let Some(f) = filter
            && !f.contains(&res)
        {
            continue;
        }
        // A repository left behind by an unbound namespace is governed by
        // nobody; a member has no namespace to see it through. The console
        // still lists it, for an administrator deciding whether to bind again.
        if matches!(viewer, Viewer::Member(_)) && snap.namespace(&repo.namespace_id).is_none() {
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
        if within.is_some() && !snap.scope_namespace(scope).is_some_and(|n| inside(&n.id)) {
            continue;
        }
        // "That resource and everything it contains" — a namespace-wide right
        // is not *on* a repository, so a repository filter leaves it out.
        if let Some(f) = filter
            && !f.contains(&res)
        {
            continue;
        }
        let governed = governs(&res);
        // `git-ns/view/0.4`, item 3: every unratified break-glass record in a
        // namespace the caller administers — the community-administrator
        // capability or `git.ns.admin` — or on a resource they own, whatever
        // else they may see. Owning or administering is `governed`.
        let bg_visible = shape.break_glass && (governed || shape.community_admin);
        for row in set.rows.iter() {
            let unratified_bg = row.is_recorded(t) && row.is_unratified_break_glass();
            if !(row.is_live(t) || (shape.break_glass && unratified_bg)) {
                continue;
            }
            let own = matches!(&viewer, Viewer::Member(did) if *did == row.subject);
            if governed || own || (unratified_bg && bg_visible) {
                if shape.break_glass {
                    rights.push(wire::right_record_full(row, &res, governed));
                } else if row.is_live(t) {
                    rights.push(wire::right_record(row, &res, governed));
                }
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

/// `git-ns/view/0.2`'s `accounts`: the forge accounts linked to the caller's
/// own DID, from their member row — never another member's, whoever is
/// asking — narrowed to `filter`'s forge. Empty when there are none.
pub fn linked_accounts_of(
    member: Option<&crate::members::Member>,
    filter: Option<&Resource>,
) -> Vec<Value> {
    let Some(forges) = member
        .filter(|m| m.removed_at.is_none())
        .and_then(|m| m.extensions.get("forges"))
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (host, acct) in forges {
        if filter.is_some_and(|f| f.forge != *host) {
            continue;
        }
        let s = |k: &str| acct.get(k).and_then(Value::as_str);
        let (Some(id), Some(login), Some(at)) = (s("id"), s("login"), s("linkedAt")) else {
            continue;
        };
        out.push(json!({
            "account": { "forge": host, "id": id, "login": login },
            "linkedAt": at,
        }));
    }
    out
}

/// The member's view as `git-ns/view/0.2`: 0.1's answer and their own
/// linked accounts.
pub fn for_member_v2(
    snap: &Snapshot,
    did: &str,
    filter: Option<&Resource>,
    member: Option<&crate::members::Member>,
) -> Result<trust_tasks_rs::specs::git_ns::view::v0_2::Response, AppError> {
    let mut v = build(snap, Viewer::Member(did), filter);
    v["accounts"] = Value::Array(linked_accounts_of(member, filter));
    wire::into(v)
}

/// The member's view as `git-ns/view/0.4`.
pub fn for_member_v4(
    snap: &Snapshot,
    did: &str,
    community_admin: bool,
    filter: Option<&Resource>,
    member: Option<&crate::members::Member>,
) -> Result<trust_tasks_rs::specs::git_ns::view::v0_4::Response, AppError> {
    wire::into(member_v4(snap, did, community_admin, filter, member))
}

/// `git-ns/view/0.4`'s answer, as JSON — also `git-ns/view/0.5`'s under
/// `scope: member`.
pub fn member_v4(
    snap: &Snapshot,
    did: &str,
    community_admin: bool,
    filter: Option<&Resource>,
    member: Option<&crate::members::Member>,
) -> Value {
    let mut v = build_with(
        snap,
        Viewer::Member(did),
        filter,
        Shape {
            break_glass: true,
            community_admin,
        },
        None,
    );
    v["accounts"] = Value::Array(linked_accounts_of(member, filter));
    v
}

/// `git-ns/view/0.5` under `scope: administrator`, as JSON: every namespace in
/// `within` (every one, and every repository whose namespace is no longer
/// bound, when it is `None` — a community administrator), with every
/// repository and every live or unratified break-glass record in them,
/// reasons and `breakGlass` in full. `accounts` is still the caller's own.
pub fn administrator_v5(
    snap: &Snapshot,
    within: Option<&BTreeSet<String>>,
    filter: Option<&Resource>,
    member: Option<&crate::members::Member>,
) -> Value {
    let mut v = build_with(
        snap,
        Viewer::Administrator,
        filter,
        Shape {
            break_glass: true,
            community_admin: true,
        },
        within,
    );
    v["accounts"] = Value::Array(linked_accounts_of(member, filter));
    v
}

/// `git-ns/view/0.5`'s `breakGlass: true`: keep only the records carrying
/// `breakGlass`, and the namespaces and repositories that contain one.
/// `accounts` is left as it is. It narrows and never widens: it can only drop
/// what the answer already held.
pub fn narrow_to_break_glass(v: &mut Value) {
    let rights: Vec<Value> = v["rights"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r.get("breakGlass").is_some())
        .cloned()
        .collect();
    let held: Vec<Resource> = rights
        .iter()
        .filter_map(|r| r["resource"].as_str())
        .filter_map(|r| Resource::parse(r).ok())
        .collect();
    let keep_ns = |n: &Value| {
        let (Some(forge), Some(owner)) = (n["forge"].as_str(), n["owner"].as_str()) else {
            return false;
        };
        let ns = Resource::namespace(forge, owner);
        held.iter().any(|r| ns.contains(r))
    };
    let keep_repo = |r: &Value| {
        r["resource"]
            .as_str()
            .and_then(|s| Resource::parse(s).ok())
            .is_some_and(|res| held.contains(&res))
    };
    if let Some(ns) = v["namespaces"].as_array_mut() {
        ns.retain(keep_ns);
    }
    if let Some(repos) = v["repos"].as_array_mut() {
        repos.retain(keep_repo);
    }
    v["rights"] = Value::Array(rights);
}
