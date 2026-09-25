//! The bridge's **role map** — which forge role each repository right is
//! given, as the forge applies it — and everything the VTC derives from it.
//!
//! Normative: `git-ns/bridge/event/0.3` (`roleMapReported`, *Definitions* and
//! request step 5). The bridge reports, per namespace, the map it applies,
//! the repositories whose own map differs, and the repositories it last
//! projected under a different map (`stale`). The VTC keeps the report on the
//! namespace ([`RoleMapReport`]) and uses it wherever it shows or derives a
//! forge role:
//!
//! - the console's effective forge role of a right ([`RoleMap::role_for`]);
//! - the *projected right of a role* of `git-ns/drift/resolve`
//!   ([`RoleMap::projected_right`]) — the **lowest** right whose role is that
//!   role, so a map that gives maintainers `admin` adopts a forge `admin` as
//!   `git.repo.maintain`, never as `git.repo.own`;
//! - the impact of a drift revert ([`RoleMap::revert_takes_ownership`]).
//!
//! Without a report the VTC assumes the default map ([`RoleMap::default_for`]).
//!
//! **A namespace admin projects to no forge role, whatever the map** (decided
//! 2026-09-25): a map has no member for `git.ns.admin` or `git.repo.create`,
//! and [`RoleMap::role_for`] answers `none` for both.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use trust_tasks_rs::specs::git_ns::bridge::event::v0_3 as event_wire;

use super::model::{Namespace, OwnerKind, Resource, Right};

/// A level of the bridge's forge-neutral role ladder, lowest first — the
/// vocabulary role drift's `observed` and `expected` use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForgeLevel {
    None,
    Read,
    Triage,
    Write,
    Maintain,
    Admin,
}

impl ForgeLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            ForgeLevel::None => "none",
            ForgeLevel::Read => "read",
            ForgeLevel::Triage => "triage",
            ForgeLevel::Write => "write",
            ForgeLevel::Maintain => "maintain",
            ForgeLevel::Admin => "admin",
        }
    }

    /// A role as a drift item reports it. Anything outside the ladder is not
    /// a level this VTC can reason about, and projects nothing.
    pub fn parse(role: &str) -> Option<ForgeLevel> {
        Some(match role {
            "none" => ForgeLevel::None,
            "read" => ForgeLevel::Read,
            "triage" => ForgeLevel::Triage,
            "write" => ForgeLevel::Write,
            "maintain" => ForgeLevel::Maintain,
            "admin" => ForgeLevel::Admin,
            _ => return None,
        })
    }

    fn from_wire(r: event_wire::MappedRole) -> Result<ForgeLevel, String> {
        ForgeLevel::parse(&r.to_string()).ok_or_else(|| format!("unknown forge role `{r}`"))
    }
}

/// The forge role `own`, `maintain` and `commit.sign` each project to.
/// Always ordered (`own ≥ maintain ≥ commit`, `commit ≤ write`): [`RoleMap::new`]
/// refuses anything else, and deserialising a stored one goes through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawRoleMap")]
pub struct RoleMap {
    pub own: ForgeLevel,
    pub maintain: ForgeLevel,
    pub commit: ForgeLevel,
}

#[derive(Deserialize)]
struct RawRoleMap {
    own: ForgeLevel,
    maintain: ForgeLevel,
    commit: ForgeLevel,
}

impl TryFrom<RawRoleMap> for RoleMap {
    type Error = String;
    fn try_from(r: RawRoleMap) -> Result<Self, String> {
        RoleMap::new(r.own, r.maintain, r.commit)
    }
}

impl RoleMap {
    /// Refused unless ordered (`git-ns/bridge/event/0.3`, *Role map*).
    pub fn new(own: ForgeLevel, maintain: ForgeLevel, commit: ForgeLevel) -> Result<Self, String> {
        if maintain > own {
            return Err(format!(
                "maintain (`{}`) is above own (`{}`)",
                maintain.as_str(),
                own.as_str()
            ));
        }
        if commit > maintain {
            return Err(format!(
                "commit (`{}`) is above maintain (`{}`)",
                commit.as_str(),
                maintain.as_str()
            ));
        }
        if commit > ForgeLevel::Write {
            return Err(format!("commit (`{}`) is above write", commit.as_str()));
        }
        Ok(RoleMap {
            own,
            maintain,
            commit,
        })
    }

    /// The default role map, rounded as far as this VTC can tell the forge's
    /// ladder: on a personal account the one collaborator level is `write`.
    pub fn default_for(kind: Option<OwnerKind>) -> RoleMap {
        match kind {
            Some(OwnerKind::User) => RoleMap {
                own: ForgeLevel::Write,
                maintain: ForgeLevel::Write,
                commit: ForgeLevel::None,
            },
            _ => RoleMap {
                own: ForgeLevel::Admin,
                maintain: ForgeLevel::Maintain,
                commit: ForgeLevel::None,
            },
        }
    }

    fn from_wire(m: &event_wire::RoleMap) -> Result<RoleMap, String> {
        RoleMap::new(
            ForgeLevel::from_wire(m.own)?,
            ForgeLevel::from_wire(m.maintain)?,
            ForgeLevel::from_wire(m.commit)?,
        )
    }

    /// The forge role `right` projects to. `git.ns.admin` and
    /// `git.repo.create` project to none, whatever the map.
    pub fn role_for(&self, right: Right) -> ForgeLevel {
        match right {
            Right::RepoOwn => self.own,
            Right::RepoMaintain => self.maintain,
            Right::CommitSign => self.commit,
            Right::NsAdmin | Right::RepoCreate => ForgeLevel::None,
        }
    }

    /// The *projected right of a role* (`git-ns/drift/resolve`): the lowest
    /// right whose role is `role`. `none`, or a role no right's is, has none.
    pub fn projected_right(&self, role: &str) -> Option<Right> {
        let level = ForgeLevel::parse(role)?;
        if level == ForgeLevel::None {
            return None;
        }
        [Right::CommitSign, Right::RepoMaintain, Right::RepoOwn]
            .into_iter()
            .find(|r| self.role_for(*r) == level)
    }

    /// Whether taking `role` away — or lowering it — takes away the forge
    /// control `git.repo.own` projects to: `role` is at least `own`'s role.
    /// A role above it (a forge `admin` where owners get `maintain`) counts
    /// too, since removing it removes at least that much.
    pub fn revert_takes_ownership(&self, role: &str) -> bool {
        self.own != ForgeLevel::None && ForgeLevel::parse(role).is_some_and(|l| l >= self.own)
    }
}

/// One repository's own map, where it differs from the namespace's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoRoleMap {
    pub resource: String,
    pub role_map: RoleMap,
}

/// The bridge's last `roleMapReported` for a namespace, as the VTC keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleMapReport {
    pub role_map: RoleMap,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<RepoRoleMap>,
    /// Repositories still projected under an earlier map. A repository leaves
    /// the list when a `projectRoles` job for it succeeds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale: Vec<String>,
    /// The bridge that reported it. A report is never carried over to another
    /// bridge (request step 5.5).
    pub bridge_did: String,
    pub reported_at: DateTime<Utc>,
}

/// Where a repository's effective map comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The bridge's last report.
    Reported,
    /// No report (or one from a bridge that no longer serves the namespace):
    /// the default, assumed.
    Default,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Reported => "reported",
            Source::Default => "default",
        }
    }
}

/// The report the namespace holds, if it is from the bridge serving it now.
fn current_report(ns: &Namespace) -> Option<&RoleMapReport> {
    ns.role_map
        .as_ref()
        .filter(|r| ns.bridge_did.as_deref() == Some(r.bridge_did.as_str()))
}

/// The map in force on `repo` (a resource in `ns`), and where it comes from.
pub fn for_repo(ns: &Namespace, repo: &str) -> (RoleMap, Source) {
    match current_report(ns) {
        Some(r) => (
            r.repos
                .iter()
                .find(|e| e.resource == repo)
                .map(|e| e.role_map)
                .unwrap_or(r.role_map),
            Source::Reported,
        ),
        None => (RoleMap::default_for(ns.kind), Source::Default),
    }
}

/// The namespace-wide map (repositories without their own), and its source.
pub fn for_namespace(ns: &Namespace) -> (RoleMap, Source) {
    match current_report(ns) {
        Some(r) => (r.role_map, Source::Reported),
        None => (RoleMap::default_for(ns.kind), Source::Default),
    }
}

/// Whether `repo` was last projected under an earlier map than the bridge's.
pub fn is_stale(ns: &Namespace, repo: &str) -> bool {
    current_report(ns).is_some_and(|r| r.stale.iter().any(|s| s == repo))
}

/// Read a `roleMapReported` event into the report the VTC keeps (request
/// step 5.1): every map ordered, each repository in `repos` once, and every
/// resource inside the namespace (step 2 — `inside` is the event handler's
/// containment check, which refuses with `permissionDenied`).
pub fn read_report<E>(
    event: &serde_json::Value,
    bridge_did: &str,
    at: DateTime<Utc>,
    mut inside: impl FnMut(&str) -> Result<Resource, E>,
) -> Result<Result<RoleMapReport, String>, E> {
    let parsed: event_wire::ForgeEvent = match serde_json::from_value(event.clone()) {
        Ok(p) => p,
        Err(e) => return Ok(Err(format!("roleMapReported: {e}"))),
    };
    let event_wire::ForgeEvent::RoleMapReported {
        repos,
        role_map,
        stale,
    } = parsed
    else {
        return Ok(Err("not a roleMapReported event".into()));
    };
    // Containment first: an event that crosses namespaces applies nothing,
    // and says so as permissionDenied rather than as a malformed map.
    for e in &repos {
        inside(&e.resource)?;
    }
    for s in stale.iter().flatten() {
        inside(s)?;
    }
    let role_map = match RoleMap::from_wire(&role_map) {
        Ok(m) => m,
        Err(e) => return Ok(Err(format!("roleMap: {e}"))),
    };
    let mut out_repos: Vec<RepoRoleMap> = Vec::with_capacity(repos.len());
    for e in &repos {
        let resource = e.resource.to_string();
        if out_repos.iter().any(|r| r.resource == resource) {
            return Ok(Err(format!("repos lists {resource} twice")));
        }
        match RoleMap::from_wire(&e.role_map) {
            Ok(m) => out_repos.push(RepoRoleMap {
                resource,
                role_map: m,
            }),
            Err(err) => return Ok(Err(format!("repos[{resource}].roleMap: {err}"))),
        }
    }
    let mut out_stale: Vec<String> = Vec::new();
    for s in stale.iter().flatten() {
        let s = s.to_string();
        if !out_stale.contains(&s) {
            out_stale.push(s);
        }
    }
    Ok(Ok(RoleMapReport {
        role_map,
        repos: out_repos,
        stale: out_stale,
        bridge_did: bridge_did.to_string(),
        reported_at: at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ForgeLevel::*;

    fn map(own: ForgeLevel, maintain: ForgeLevel, commit: ForgeLevel) -> RoleMap {
        RoleMap::new(own, maintain, commit).unwrap()
    }

    #[test]
    fn a_map_is_ordered_and_a_committer_gets_at_most_write() {
        assert!(RoleMap::new(Maintain, Admin, None).is_err());
        assert!(RoleMap::new(Admin, Write, Maintain).is_err());
        assert!(RoleMap::new(Admin, Admin, Admin).is_err());
        assert!(RoleMap::new(Admin, Admin, Write).is_ok());
        // Stored maps are held to the same rule.
        assert!(
            serde_json::from_value::<RoleMap>(
                serde_json::json!({ "own": "write", "maintain": "admin", "commit": "none" })
            )
            .is_err()
        );
    }

    #[test]
    fn the_default_map_is_the_old_inverse() {
        let org = RoleMap::default_for(Some(OwnerKind::Organization));
        assert_eq!(org.projected_right("admin"), Some(Right::RepoOwn));
        assert_eq!(org.projected_right("maintain"), Some(Right::RepoMaintain));
        assert_eq!(org.projected_right("write"), Option::None);
        assert_eq!(org.projected_right("triage"), Option::None);
        let user = RoleMap::default_for(Some(OwnerKind::User));
        // own and maintain both collapse to write: the lower one.
        assert_eq!(user.projected_right("write"), Some(Right::RepoMaintain));
        assert_eq!(user.projected_right("admin"), Option::None);
    }

    #[test]
    fn the_projected_right_is_the_lowest_right_with_that_role() {
        // Forgejo, maintainers given admin: a forge admin is a maintainer.
        let m = map(Admin, Admin, None);
        assert_eq!(m.projected_right("admin"), Some(Right::RepoMaintain));
        // Committers given write.
        let m = map(Admin, Maintain, Write);
        assert_eq!(m.projected_right("write"), Some(Right::CommitSign));
        // Owners given only maintain: nothing projects to admin.
        let m = map(Maintain, Write, None);
        assert_eq!(m.projected_right("admin"), Option::None);
        assert_eq!(m.projected_right("maintain"), Some(Right::RepoOwn));
        // `none` and unknown roles never project.
        assert_eq!(m.projected_right("none"), Option::None);
        assert_eq!(m.projected_right("owner"), Option::None);
    }

    #[test]
    fn a_namespace_admin_projects_to_no_role_under_any_map() {
        for m in [
            map(Admin, Maintain, None),
            map(Admin, Admin, Write),
            map(Write, Write, None),
        ] {
            assert_eq!(m.role_for(Right::NsAdmin), None);
            assert_eq!(m.role_for(Right::RepoCreate), None);
        }
    }

    #[test]
    fn reverting_a_role_at_or_above_owns_weighs_as_revoking_own() {
        let m = map(Maintain, Write, None);
        assert!(m.revert_takes_ownership("maintain"));
        assert!(m.revert_takes_ownership("admin"));
        assert!(!m.revert_takes_ownership("write"));
        assert!(!map(None, None, None).revert_takes_ownership("read"));
    }
}
