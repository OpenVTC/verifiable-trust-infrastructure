//! The bridge's **role map** — which forge role each repository right is
//! given, as the forge applies it — and everything the VTC derives from it.
//!
//! Normative: `git-ns/bridge/event/0.3` (`roleMapReported`, *Definitions* and
//! request step 5). The bridge reports, per namespace, the map it applies,
//! the forge's ladder, the repositories whose own map differs, and the
//! repositories it last projected under a different map (`stale`). The VTC
//! keeps the report on the namespace ([`RoleMapReport`]) and uses it wherever
//! it shows or derives a forge role:
//!
//! - the console's effective forge role of a right ([`RoleMap::role_for`]);
//! - the *projected right of a role* of `git-ns/drift/resolve`
//!   ([`projected_right`]) — the **lowest** right whose role is that role, so
//!   a map that gives maintainers `admin` adopts a forge `admin` as
//!   `git.repo.maintain`, never as `git.repo.own`;
//! - the impact of a drift revert ([`revert_takes_ownership`]);
//! - whether a right is elevated for the self-grant rules
//!   ([`Right::is_elevated_in`]): one the map projects to forge `admin` is.
//!
//! **No map is ever assumed.** Until the bridge serving the namespace reports,
//! the map is *unknown* ([`Source::Unknown`]) — after binding, after the
//! namespace comes to be served by another bridge, and for good on a bridge
//! older than event 0.3. Nothing is derived from a guess meanwhile: an
//! adoption is refused (`git-ns:roleMapUnknown`), a revert of any role is
//! weighed as revoking `git.repo.own`, and `git.repo.maintain` counts as
//! elevated. The default map holds only when a bridge reports it.
//!
//! Reports are ordered by the document's `issuedAt` (request step 5.2): one
//! issued before the report held from the same bridge is ignored.
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

use ForgeLevel as L;

/// The ladders this VTC knows independently of any report
/// (`git-ns/bridge/event/0.3`, *Ladder*), by forge host and namespace kind.
/// `None` where it cannot tell: a report's own `ladder` is then checked only
/// against its maps.
pub fn known_ladder(forge: &str, kind: Option<OwnerKind>) -> Option<&'static [ForgeLevel]> {
    const GITHUB_ORG: [ForgeLevel; 5] = [L::Read, L::Triage, L::Write, L::Maintain, L::Admin];
    const GITHUB_USER: [ForgeLevel; 1] = [L::Write];
    const FORGEJO: [ForgeLevel; 4] = [L::Read, L::Write, L::Maintain, L::Admin];
    match (forge, kind) {
        ("github.com", Some(OwnerKind::Organization)) => Some(&GITHUB_ORG),
        ("github.com", Some(OwnerKind::User)) => Some(&GITHUB_USER),
        ("codeberg.org", Some(_)) => Some(&FORGEJO),
        _ => None,
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

    fn from_wire(m: &event_wire::RoleMap) -> Result<RoleMap, String> {
        RoleMap::new(
            ForgeLevel::from_wire(m.own)?,
            ForgeLevel::from_wire(m.maintain)?,
            ForgeLevel::from_wire(m.commit)?,
        )
    }

    /// Every role of the map is `none` or on `ladder` (request step 5.1).
    fn on_ladder(&self, ladder: &[ForgeLevel]) -> Result<(), String> {
        for (name, level) in [
            ("own", self.own),
            ("maintain", self.maintain),
            ("commit", self.commit),
        ] {
            if level != ForgeLevel::None && !ladder.contains(&level) {
                return Err(format!(
                    "{name} (`{}`) is not a level the forge offers here",
                    level.as_str()
                ));
            }
        }
        Ok(())
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
    /// The levels the forge offers here, lowest first, without `none`.
    pub ladder: Vec<ForgeLevel>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<RepoRoleMap>,
    /// Repositories still projected under an earlier map, among those the
    /// VTC records `active` or `orphaned`. A repository leaves the list when
    /// a `projectRoles` job for it succeeds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale: Vec<String>,
    /// The bridge that reported it. A report is never carried over to another
    /// bridge (request step 5.6).
    pub bridge_did: String,
    /// The report document's `issuedAt`, on the bridge's clock: what orders
    /// reports (request step 5.2).
    pub issued_at: DateTime<Utc>,
    /// When this VTC took it, on its own clock: what a job's `created_at`
    /// is compared with to tell whether it was queued after the report.
    pub received_at: DateTime<Utc>,
}

/// Where a namespace's map comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The last report of the bridge serving the namespace.
    Reported,
    /// That bridge has not reported: nothing is derived from any map.
    Unknown,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Reported => "reported",
            Source::Unknown => "unknown",
        }
    }
}

/// The report the namespace holds, if it is from the bridge serving it now.
pub fn current_report(ns: &Namespace) -> Option<&RoleMapReport> {
    ns.role_map
        .as_ref()
        .filter(|r| ns.bridge_did.as_deref() == Some(r.bridge_did.as_str()))
}

/// Whether the namespace's map is reported or unknown.
pub fn source(ns: &Namespace) -> Source {
    if current_report(ns).is_some() {
        Source::Reported
    } else {
        Source::Unknown
    }
}

/// The map in force on `repo` (a resource in `ns`); `None` while unknown.
pub fn for_repo(ns: &Namespace, repo: &str) -> Option<RoleMap> {
    current_report(ns).map(|r| {
        r.repos
            .iter()
            .find(|e| e.resource == repo)
            .map(|e| e.role_map)
            .unwrap_or(r.role_map)
    })
}

/// The namespace-wide map (repositories without their own); `None` while
/// unknown.
pub fn for_namespace(ns: &Namespace) -> Option<RoleMap> {
    current_report(ns).map(|r| r.role_map)
}

/// Whether `repo` was last projected under an earlier map than the bridge's.
pub fn is_stale(ns: &Namespace, repo: &str) -> bool {
    current_report(ns).is_some_and(|r| r.stale.iter().any(|s| s == repo))
}

/// The role map is unknown: the bridge serving the namespace has not
/// reported it (`git-ns/bridge/event/0.3`, request step 5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unknown;

/// The *projected right of a role* on `repo`: [`RoleMap::projected_right`]
/// under the reported map. Unknown while the map is: never derived from an
/// assumed one.
pub fn projected_right(ns: &Namespace, repo: &str, role: &str) -> Result<Option<Right>, Unknown> {
    for_repo(ns, repo)
        .map(|m| m.projected_right(role))
        .ok_or(Unknown)
}

/// Whether reverting (removing or lowering) `role` on `repo` has the impact
/// of revoking `git.repo.own`. While the map is unknown any role but `none`
/// might be the one `own` projects to, so every such revert does.
pub fn revert_takes_ownership(ns: &Namespace, repo: &str, role: &str) -> bool {
    match for_repo(ns, repo) {
        Some(m) => m.revert_takes_ownership(role),
        None => ForgeLevel::parse(role).is_some_and(|l| l > ForgeLevel::None),
    }
}

impl Right {
    /// [`Right::is_elevated`], or projected by the namespace's role map to
    /// forge `admin` on `resource` (`git-ns/bridge/event/0.3`, request step
    /// 5.4): the self-grant rules of `git-ns/right/grant/0.3` and
    /// `git-ns/drift/resolve/0.3` refuse it for oneself. A map that gives
    /// maintainers `admin` makes `git.repo.maintain` elevated. On the
    /// namespace resource, any map in the report counts. While the map is
    /// unknown every right an ordered map could project to `admin` counts —
    /// `git.repo.own` and `git.repo.maintain` — which fails closed.
    pub fn is_elevated_in(self, ns: &Namespace, resource: &str) -> bool {
        if self.is_elevated() {
            return true;
        }
        let Some(report) = current_report(ns) else {
            return matches!(self, Right::RepoMaintain);
        };
        let admin = |m: &RoleMap| m.role_for(self) == ForgeLevel::Admin;
        if resource == ns.resource().to_string() {
            admin(&report.role_map) || report.repos.iter().any(|e| admin(&e.role_map))
        } else {
            for_repo(ns, resource).is_some_and(|m| admin(&m))
        }
    }
}

/// Read a `roleMapReported` event into the report the VTC keeps (request
/// step 5.1): every map ordered and on the ladder, the ladder strictly
/// ascending and the one this VTC knows for the namespace where it knows
/// one, each repository in `repos` once, and every resource inside the
/// namespace (step 2 — `inside` is the event handler's containment check,
/// which refuses with `permissionDenied`).
pub fn read_report<E>(
    event: &serde_json::Value,
    ns: &Namespace,
    bridge_did: &str,
    issued_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
    mut inside: impl FnMut(&str) -> Result<Resource, E>,
) -> Result<Result<RoleMapReport, String>, E> {
    let parsed: event_wire::ForgeEvent = match serde_json::from_value(event.clone()) {
        Ok(p) => p,
        Err(e) => return Ok(Err(format!("roleMapReported: {e}"))),
    };
    let event_wire::ForgeEvent::RoleMapReported {
        ladder,
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
    let mut levels: Vec<ForgeLevel> = Vec::with_capacity(ladder.len());
    for r in &ladder {
        let l = match ForgeLevel::from_wire(*r) {
            Ok(l) => l,
            Err(e) => return Ok(Err(format!("ladder: {e}"))),
        };
        if l == ForgeLevel::None {
            return Ok(Err("ladder lists `none`, which every forge has".into()));
        }
        if levels.last().is_some_and(|prev| *prev >= l) {
            return Ok(Err("ladder is not strictly ascending".into()));
        }
        levels.push(l);
    }
    if levels.is_empty() {
        return Ok(Err("ladder lists no level".into()));
    }
    if let Some(known) = known_ladder(&ns.forge, ns.kind)
        && known != levels.as_slice()
    {
        return Ok(Err(format!(
            "ladder [{}] is not the forge's ladder for this namespace, [{}]",
            levels
                .iter()
                .map(|l| l.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            known
                .iter()
                .map(|l| l.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let role_map =
        match RoleMap::from_wire(&role_map).and_then(|m| m.on_ladder(&levels).map(|()| m)) {
            Ok(m) => m,
            Err(e) => return Ok(Err(format!("roleMap: {e}"))),
        };
    let mut out_repos: Vec<RepoRoleMap> = Vec::with_capacity(repos.len());
    for e in &repos {
        let resource = e.resource.to_string();
        if out_repos.iter().any(|r| r.resource == resource) {
            return Ok(Err(format!("repos lists {resource} twice")));
        }
        match RoleMap::from_wire(&e.role_map).and_then(|m| m.on_ladder(&levels).map(|()| m)) {
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
        ladder: levels,
        repos: out_repos,
        stale: out_stale,
        bridge_did: bridge_did.to_string(),
        issued_at,
        received_at,
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
    fn the_default_map_as_reported_is_the_old_inverse() {
        let org = map(Admin, Maintain, None);
        assert_eq!(org.projected_right("admin"), Some(Right::RepoOwn));
        assert_eq!(org.projected_right("maintain"), Some(Right::RepoMaintain));
        assert_eq!(org.projected_right("write"), Option::None);
        assert_eq!(org.projected_right("triage"), Option::None);
        // A personal account: own and maintain both collapse to write, and
        // the projected right is the lower one.
        let user = map(Write, Write, None);
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

    #[test]
    fn a_map_is_on_its_ladder() {
        let forgejo = [Read, Write, Maintain, Admin];
        assert!(map(Admin, Maintain, Write).on_ladder(&forgejo).is_ok());
        assert!(map(Admin, Triage, None).on_ladder(&forgejo).is_err());
        let user = [Write];
        assert!(map(Write, Write, None).on_ladder(&user).is_ok());
        assert!(map(Admin, Write, None).on_ladder(&user).is_err());
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;
    use crate::git_ns::model::{Mode, NamespaceState};
    use serde_json::json;

    const WIDGETS: &str = "github.com/acme/widgets";

    fn ns_kind(bridge: &str, report: Option<(&str, RoleMap)>, kind: OwnerKind) -> Namespace {
        Namespace {
            id: "ns_1".into(),
            forge: "github.com".into(),
            owner: "acme".into(),
            mode: Mode::Bridge,
            state: NamespaceState::Bound,
            owner_id: None,
            kind: Some(kind),
            bridge_did: Some(bridge.into()),
            bind_job_id: None,
            bound_by: "did:key:z6Mk".into(),
            requested_at: Utc::now(),
            bound_at: None,
            roles_digest: None,
            installation_removed: false,
            forge_status: None,
            role_map: report.map(|(b, m)| RoleMapReport {
                role_map: m,
                ladder: vec![
                    ForgeLevel::Read,
                    ForgeLevel::Triage,
                    ForgeLevel::Write,
                    ForgeLevel::Maintain,
                    ForgeLevel::Admin,
                ],
                repos: vec![],
                stale: vec![WIDGETS.into()],
                bridge_did: b.into(),
                issued_at: Utc::now(),
                received_at: Utc::now(),
            }),
        }
    }

    fn ns(bridge: &str, report_from: Option<&str>) -> Namespace {
        let admin_map =
            RoleMap::new(ForgeLevel::Admin, ForgeLevel::Admin, ForgeLevel::None).unwrap();
        ns_kind(
            bridge,
            report_from.map(|b| (b, admin_map)),
            OwnerKind::Organization,
        )
    }

    #[test]
    fn another_bridges_report_is_unknown_and_derives_nothing() {
        let reseated = ns("did:key:new", Some("did:key:old"));
        assert_eq!(source(&reseated), Source::Unknown);
        assert_eq!(for_namespace(&reseated), Option::None);
        assert!(!is_stale(&reseated, WIDGETS));
        assert_eq!(projected_right(&reseated, WIDGETS, "admin"), Err(Unknown));
        // Unbound-to-a-report: unknown too, never the default.
        let fresh = ns("did:key:new", None);
        assert_eq!(source(&fresh), Source::Unknown);
        assert_eq!(projected_right(&fresh, WIDGETS, "admin"), Err(Unknown));
        let held = ns("did:key:old", Some("did:key:old"));
        assert_eq!(source(&held), Source::Reported);
        assert_eq!(
            projected_right(&held, WIDGETS, "admin"),
            Ok(Some(Right::RepoMaintain))
        );
    }

    #[test]
    fn an_unknown_map_weighs_every_revert_as_revoking_own() {
        let fresh = ns("did:key:new", None);
        for role in ["read", "triage", "write", "maintain", "admin"] {
            assert!(revert_takes_ownership(&fresh, WIDGETS, role), "{role}");
        }
        assert!(!revert_takes_ownership(&fresh, WIDGETS, "none"));
        // Reported: only a role at or above own's.
        let held = ns("did:key:old", Some("did:key:old"));
        assert!(revert_takes_ownership(&held, WIDGETS, "admin"));
        assert!(!revert_takes_ownership(&held, WIDGETS, "maintain"));
    }

    #[test]
    fn a_right_the_map_projects_to_admin_is_elevated() {
        let b = "did:key:b";
        let default =
            RoleMap::new(ForgeLevel::Admin, ForgeLevel::Maintain, ForgeLevel::None).unwrap();
        let maintain_admin =
            RoleMap::new(ForgeLevel::Admin, ForgeLevel::Admin, ForgeLevel::None).unwrap();
        // maintain → admin: maintain is elevated, on the repository and on
        // the namespace.
        let n = ns_kind(b, Some((b, maintain_admin)), OwnerKind::Organization);
        assert!(Right::RepoMaintain.is_elevated_in(&n, WIDGETS));
        assert!(Right::RepoMaintain.is_elevated_in(&n, "github.com/acme"));
        assert!(!Right::CommitSign.is_elevated_in(&n, WIDGETS));
        // The default map, reported: maintain is not.
        let n = ns_kind(b, Some((b, default)), OwnerKind::Organization);
        assert!(!Right::RepoMaintain.is_elevated_in(&n, WIDGETS));
        assert!(Right::RepoOwn.is_elevated_in(&n, WIDGETS));
        // One repository giving maintainers admin makes maintain elevated
        // there and on the namespace, not on the others.
        let mut n = n;
        n.role_map.as_mut().unwrap().repos.push(RepoRoleMap {
            resource: WIDGETS.into(),
            role_map: maintain_admin,
        });
        assert!(Right::RepoMaintain.is_elevated_in(&n, WIDGETS));
        assert!(Right::RepoMaintain.is_elevated_in(&n, "github.com/acme"));
        assert!(!Right::RepoMaintain.is_elevated_in(&n, "github.com/acme/gadgets"));
        // Unknown: maintain counts as elevated, commit never.
        let n = ns_kind(b, Option::None, OwnerKind::Organization);
        assert!(Right::RepoMaintain.is_elevated_in(&n, WIDGETS));
        assert!(!Right::CommitSign.is_elevated_in(&n, WIDGETS));
        assert!(Right::NsAdmin.is_elevated_in(&n, "github.com/acme"));
    }

    fn read(ns: &Namespace, event: serde_json::Value) -> Result<RoleMapReport, String> {
        read_report(&event, ns, "did:key:b", Utc::now(), Utc::now(), |r| {
            Resource::parse(r).map_err(|_| ())
        })
        .unwrap()
    }

    #[test]
    fn a_report_is_held_to_the_forges_ladder() {
        let org = ns("did:key:b", Option::None);
        let user = ns_kind("did:key:b", Option::None, OwnerKind::User);
        let org_ladder = json!(["read", "triage", "write", "maintain", "admin"]);
        let ok = |n: &Namespace, m: serde_json::Value, l: serde_json::Value| {
            read(
                n,
                json!({ "type": "roleMapReported", "roleMap": m, "ladder": l }),
            )
        };
        assert!(
            ok(
                &org,
                json!({ "own": "admin", "maintain": "maintain", "commit": "none" }),
                org_ladder.clone()
            )
            .is_ok()
        );
        // own: admin on a GitHub personal account.
        assert!(
            ok(
                &user,
                json!({ "own": "admin", "maintain": "write", "commit": "none" }),
                json!(["write"])
            )
            .is_err()
        );
        assert!(
            ok(
                &user,
                json!({ "own": "write", "maintain": "write", "commit": "none" }),
                json!(["write"])
            )
            .is_ok()
        );
        // A ladder that is not the one the VTC knows for the namespace.
        assert!(
            ok(
                &user,
                json!({ "own": "admin", "maintain": "write", "commit": "none" }),
                org_ladder.clone()
            )
            .is_err()
        );
        // A role off the reported ladder (Forgejo has no triage), on a host
        // whose ladder the VTC does not know.
        let mut forgejo = ns("did:key:b", Option::None);
        forgejo.forge = "git.example.org".into();
        forgejo.owner = "acme".into();
        let fj = json!(["read", "write", "maintain", "admin"]);
        assert!(
            ok(
                &forgejo,
                json!({ "own": "admin", "maintain": "triage", "commit": "none" }),
                fj.clone()
            )
            .is_err()
        );
        assert!(
            ok(
                &forgejo,
                json!({ "own": "admin", "maintain": "maintain", "commit": "write" }),
                fj
            )
            .is_ok()
        );
        // A ladder with `none`, or out of order.
        assert!(
            ok(
                &forgejo,
                json!({ "own": "admin", "maintain": "maintain", "commit": "none" }),
                json!(["none", "admin"])
            )
            .is_err()
        );
        assert!(
            ok(
                &forgejo,
                json!({ "own": "admin", "maintain": "maintain", "commit": "none" }),
                json!(["admin", "maintain"])
            )
            .is_err()
        );
        // On Codeberg the VTC knows the Forgejo ladder.
        let mut cb = ns("did:key:b", Option::None);
        cb.forge = "codeberg.org".into();
        assert!(
            ok(
                &cb,
                json!({ "own": "admin", "maintain": "maintain", "commit": "none" }),
                org_ladder
            )
            .is_err()
        );
    }
}
