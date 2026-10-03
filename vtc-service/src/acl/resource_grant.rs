//! **Resource grants** — the qualified capabilities a subject holds on one of
//! the community's resources, on its own ACL entry (**VTI-ACL-035 – 037**,
//! **VTI-VTC-020**).
//!
//! Phase C3 of `docs/05-design-notes/vtc-admin-roles.md`: the git-namespace
//! rights that used to live in a store of their own (`rights:*` in the `git_ns`
//! keyspace) are capabilities on the holder's entry, qualified by namespace or
//! by repository **id**. There is one authority model: every `git-ns/*` task
//! authorizes from the entries, and [`super::VtcAclEntry::can`] answers the
//! same question for the console and the approver sets.
//!
//! ## Why beside the role, not inside it
//!
//! An administrative role is a ceiling over community administration, one per
//! entry (§11.1). A git right is held by whoever a namespace's own
//! administrators chose — a member with no administrative role, an external
//! signer, the bridge — and each grant carries its own granter, expiry and
//! history, because each is separately a delegation (VTI-ACL-071). So a grant
//! is a row in the entry's `resourceGrants`, never a member of the role's
//! `capabilities`, and it is bounded at write time by the granter's own holding
//! at a covering qualifier (VTI-ACL-037), not by a role ceiling. It confers
//! nothing without the live entry it sits on: an expired entry holds nothing,
//! and removing the entry removes them.
//!
//! ## The mapping (`vtc-admin-roles.md` §9)
//!
//! | git-ns right | capability | qualifier | grade |
//! |---|---|---|---|
//! | `git.ns.admin` | `git.ns.admin` | `git-ns:<forge>/<owner>` | — |
//! | `git.repo.create` | `git.repo.manage` | `git-ns:<forge>/<owner>` | `create` |
//! | `git.repo.own` | `git.repo.manage` | `git-repo:<forge>/<owner>/<repo-id>` | `own` |
//! | `git.repo.maintain` | `git.repo.manage` | `git-repo:<forge>/<owner>/<repo-id>` | `maintain` |
//! | `git.commit.sign` | `git.commit.sign` | either | — |
//!
//! A **grade** narrows `git.repo.manage` (VTI-ACL-035 bounds what a qualified
//! capability confers from above; a grade confers less). `own` is the
//! capability in full on one repository. `maintain` is the maintainer's share
//! of it — what the forge projection turns into a maintainer role — and
//! confers no management. `create` is repository creation in a namespace, and
//! confers nothing over the repositories already in it: a creator owns what it
//! creates by a separate `own` grant, never by the namespace qualifier. The
//! grade is what keeps owner and maintainer apart for the forge roles and for
//! the fixed rules of `git-ns/right/grant/0.3`, which this module does not
//! re-implement: they run in `crate::git_ns::rules` over the same grants.
//!
//! Implication follows the rights model: `git.ns.admin` at a namespace implies
//! `git.repo.manage` (`create` there, `own` on every repository inside) and
//! `git.commit.sign` throughout it; `own` implies `maintain` and
//! `git.commit.sign` on its repository; `maintain` implies `git.commit.sign`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::capability::{CapRef, Capability, ResourceQualifier};
use crate::git_ns::model::{BreakGlassMark, Right, SingleAdminMark};

/// How much of `git.repo.manage` a grant confers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RepoGrade {
    /// Creating repositories in a namespace (`git.repo.create`).
    Create,
    /// Owning one repository (`git.repo.own`): the capability in full there.
    Own,
    /// Maintaining one repository (`git.repo.maintain`).
    Maintain,
}

/// A departed (or narrowed) granter's grant waiting to be re-affirmed or
/// withdrawn (`vtc-admin-roles.md` §6.3, **VTI-ACL-071**).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantReview {
    /// The granter who no longer stands behind it.
    pub granter: String,
    pub raised_at: DateTime<Utc>,
    /// Withdrawn at this instant unless re-affirmed.
    pub deadline: DateTime<Utc>,
}

/// One qualified capability held on an entry (`resourceGrants`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceGrant {
    pub capability: Capability,
    /// Always present: a resource grant is qualified by definition.
    pub resource: ResourceQualifier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grade: Option<RepoGrade>,
    /// The subject whose authority this grant was delegated from
    /// (**VTI-ACL-072**) — the granter, or the community's own DID for a grant
    /// it made as itself (the bridge's service grant).
    pub delegated_by: String,
    pub granted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// The granter's free text. Shown only to those who govern the resource;
    /// never published and never audited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether the subject was a member when this was granted.
    #[serde(default)]
    pub subject_was_member: bool,
    /// Whether the granter was a member when they granted it.
    #[serde(default)]
    pub granter_was_member: bool,
    /// Present exactly when the subject gave this to itself through
    /// `git-ns/right/break-glass/0.1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub break_glass: Option<BreakGlassMark>,
    /// Open while the granter has departed and nobody has re-affirmed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<GrantReview>,
    /// Present exactly when the subject recorded this for itself under
    /// single-administrator mode (VTI-APV-022, `git_ns::single_admin`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub single_admin: Option<SingleAdminMark>,
}

impl ResourceGrant {
    /// The git right this grant is, or `None` for a grant no git right maps
    /// onto (a shape this build never writes).
    pub fn git_right(&self) -> Option<Right> {
        use ResourceQualifier as Q;
        match (self.capability, &self.resource, self.grade) {
            (Capability::GitNsAdmin, Q::GitNs(_), None) => Some(Right::NsAdmin),
            (Capability::GitRepoManage, Q::GitNs(_), Some(RepoGrade::Create)) => {
                Some(Right::RepoCreate)
            }
            (Capability::GitRepoManage, Q::GitRepo(_), Some(RepoGrade::Own)) => {
                Some(Right::RepoOwn)
            }
            (Capability::GitRepoManage, Q::GitRepo(_), Some(RepoGrade::Maintain)) => {
                Some(Right::RepoMaintain)
            }
            (Capability::GitCommitSign, Q::GitNs(_) | Q::GitRepo(_), None) => {
                Some(Right::CommitSign)
            }
            _ => None,
        }
    }

    /// `cap[/grade]@resource`, the form an operator display and an audit row
    /// carry.
    pub fn display(&self) -> String {
        match self.grade {
            Some(g) => format!(
                "{}/{}@{}",
                self.capability,
                serde_json::to_value(g)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default(),
                self.resource
            ),
            None => format!("{}@{}", self.capability, self.resource),
        }
    }

    /// Lapsed: past its own `expiresAt`.
    pub fn is_lapsed(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|e| e <= now)
    }

    /// In effect now: not lapsed, and not a break-glass still waiting for its
    /// `effectiveAt`.
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        !self.is_lapsed(now)
            && !self
                .break_glass
                .as_ref()
                .and_then(|b| b.effective_at)
                .is_some_and(|e| e > now)
    }

    /// Whether this grant, in effect, confers `cap` at `wanted` (`None` =
    /// community-wide, which no qualified grant covers) — with the
    /// implications of the rights model (module docs).
    pub fn confers(&self, cap: Capability, wanted: Option<&ResourceQualifier>) -> bool {
        let Some(wanted) = wanted else {
            return false;
        };
        let inside = self.resource.covers(wanted);
        let exact = self.resource == *wanted;
        match (self.capability, self.grade) {
            (Capability::GitNsAdmin, _) => {
                inside
                    && matches!(
                        cap,
                        Capability::GitNsAdmin
                            | Capability::GitRepoManage
                            | Capability::GitCommitSign
                    )
            }
            (Capability::GitRepoManage, Some(RepoGrade::Own) | None) => {
                inside && matches!(cap, Capability::GitRepoManage | Capability::GitCommitSign)
            }
            (Capability::GitRepoManage, Some(RepoGrade::Maintain)) => {
                inside && cap == Capability::GitCommitSign
            }
            // Creation in the namespace itself, and nothing inside it.
            (Capability::GitRepoManage, Some(RepoGrade::Create)) => {
                exact && cap == Capability::GitRepoManage
            }
            (Capability::GitCommitSign, _) => inside && cap == Capability::GitCommitSign,
            _ => false,
        }
    }

    /// The reference this grant answers `can` for.
    pub fn cap_ref(&self) -> CapRef {
        CapRef::new(self.capability, Some(self.resource.clone()))
    }
}

/// `(capability, grade)` a git right is held as (module docs).
pub fn capability_for(right: Right) -> (Capability, Option<RepoGrade>) {
    match right {
        Right::NsAdmin => (Capability::GitNsAdmin, None),
        Right::RepoCreate => (Capability::GitRepoManage, Some(RepoGrade::Create)),
        Right::RepoOwn => (Capability::GitRepoManage, Some(RepoGrade::Own)),
        Right::RepoMaintain => (Capability::GitRepoManage, Some(RepoGrade::Maintain)),
        Right::CommitSign => (Capability::GitCommitSign, None),
    }
}

/// The qualifier of a namespace: `git-ns:<forge>/<owner>`.
pub fn namespace_qualifier(forge: &str, owner: &str) -> ResourceQualifier {
    ResourceQualifier::GitNs(format!("{forge}/{owner}"))
}

/// The qualifier of a repository: `git-repo:<forge>/<owner>/<repo-id>` — by
/// **id**, so a rename on the forge moves nothing and a new repository at an
/// old name inherits nothing.
pub fn repo_qualifier(forge: &str, owner: &str, repo_id: &str) -> ResourceQualifier {
    ResourceQualifier::GitRepo(format!("{forge}/{owner}/{repo_id}"))
}

/// The repository id a `git-repo:` qualifier names.
pub fn repo_id_of(q: &ResourceQualifier) -> Option<&str> {
    match q {
        ResourceQualifier::GitRepo(v) => v.rsplit('/').next(),
        _ => None,
    }
}

/// **VTI-ACL-037** / **VTI-ACL-071** at write time: whether `granter` holds,
/// on its own live entry, the capability `right` is held as at a qualifier
/// covering `at` — a grant may never be wider than what its granter holds.
///
/// The fixed rules of `git-ns/right/grant/0.3` decide *which* holdings carry
/// grant authority (a committer grants nothing, `git.repo.create` is not
/// re-delegable); this is the floor under them, read from the ACL entry.
pub fn granter_covers(granter: &super::VtcAclEntry, right: Right, at: &ResourceQualifier) -> bool {
    let (cap, grade) = capability_for(right);
    let now = Utc::now();
    let epoch = vti_common::auth::session::now_epoch();
    if granter.is_expired(epoch) {
        return false;
    }
    // Unqualified administrative authority (a community administrator's
    // `git.ns.admin`) covers every namespace's resources.
    if granter.admin.can(cap, Some(at)) || granter.admin.can(Capability::GitNsAdmin, Some(at)) {
        return true;
    }
    granter.resource_grants.iter().any(|g| {
        g.is_live(now)
            && match grade {
                // A maintainer grant needs at least a maintainer's holding.
                Some(RepoGrade::Maintain) => {
                    g.confers(Capability::GitRepoManage, Some(at))
                        || (g.capability == Capability::GitRepoManage
                            && g.grade == Some(RepoGrade::Maintain)
                            && g.resource.covers(at))
                }
                // Creation is held only at the namespace, by an admin of it or
                // a creator there.
                Some(RepoGrade::Create) => g.confers(Capability::GitRepoManage, Some(at)),
                _ => g.confers(cap, Some(at)),
            }
    })
}

// ─── storage: the holder index and departure tombstones ──────────────────

/// Index of the DIDs whose entries hold resource grants, so the git-namespace
/// snapshot reads those entries and not the whole ACL. A superset is harmless
/// (an indexed entry without grants contributes none); every writer of
/// grants keeps it from being a subset, and boot rebuilds it
/// ([`rebuild_holder_index`]).
const HOLDER_PREFIX: &str = "git-holder:";
/// The resource grants an entry held when it was removed, kept only until the
/// git-namespace lifecycle has recorded each revocation and orphaned what
/// the subject owned alone. They confer nothing: no entry, no authority
/// (**VTI-ACL-037**).
const DEPARTED_PREFIX: &str = "git-departed:";

/// Mark `did` as holding resource grants, or not.
pub async fn index_holder(
    ks: &vti_common::store::KeyspaceHandle,
    did: &str,
    holds: bool,
) -> Result<(), vti_common::error::AppError> {
    let key = format!("{HOLDER_PREFIX}{did}");
    if holds {
        ks.insert_raw(key.into_bytes(), b"1".to_vec()).await
    } else {
        ks.remove(key).await
    }
}

/// Every DID the holder index names.
pub async fn indexed_holders(
    ks: &vti_common::store::KeyspaceHandle,
) -> Result<Vec<String>, vti_common::error::AppError> {
    Ok(ks
        .prefix_keys(HOLDER_PREFIX.as_bytes().to_vec())
        .await?
        .into_iter()
        .map(|k| String::from_utf8_lossy(&k[HOLDER_PREFIX.len()..]).into_owned())
        .collect())
}

/// Rebuild the holder index from every entry — at boot, so an index that
/// drifted (a crash between an entry write and its index write) heals.
pub async fn rebuild_holder_index(
    ks: &vti_common::store::KeyspaceHandle,
) -> Result<usize, vti_common::error::AppError> {
    let holders: std::collections::BTreeSet<String> = super::entry::iter(ks)
        .await?
        .into_iter()
        .filter(|e| !e.resource_grants.is_empty())
        .map(|e| e.did)
        .collect();
    for stale in indexed_holders(ks).await? {
        if !holders.contains(&stale) {
            index_holder(ks, &stale, false).await?;
        }
    }
    for did in &holders {
        index_holder(ks, did, true).await?;
    }
    Ok(holders.len())
}

/// Keep the resource grants of an entry being removed for the git-namespace
/// lifecycle. Merged with any already kept for the same DID.
pub async fn keep_departed(
    ks: &vti_common::store::KeyspaceHandle,
    did: &str,
    grants: &[ResourceGrant],
) -> Result<(), vti_common::error::AppError> {
    if grants.is_empty() {
        return Ok(());
    }
    let key = format!("{DEPARTED_PREFIX}{did}");
    let mut kept: Vec<ResourceGrant> = ks.get(key.clone()).await?.unwrap_or_default();
    kept.extend(grants.iter().cloned());
    ks.insert(key, &kept).await
}

/// Every departed subject's kept grants.
pub async fn departed(
    ks: &vti_common::store::KeyspaceHandle,
) -> Result<Vec<(String, Vec<ResourceGrant>)>, vti_common::error::AppError> {
    let mut out = Vec::new();
    for (k, v) in ks
        .prefix_iter_raw(DEPARTED_PREFIX.as_bytes().to_vec())
        .await?
    {
        let did = String::from_utf8_lossy(&k[DEPARTED_PREFIX.len()..]).into_owned();
        match serde_json::from_slice::<Vec<ResourceGrant>>(&v) {
            Ok(g) => out.push((did, g)),
            Err(e) => tracing::warn!(did, error = %e, "unreadable departed resource grants"),
        }
    }
    Ok(out)
}

/// Forget a departed subject's kept grants, once recorded.
pub async fn forget_departed(
    ks: &vti_common::store::KeyspaceHandle,
    did: &str,
) -> Result<(), vti_common::error::AppError> {
    ks.remove(format!("{DEPARTED_PREFIX}{did}")).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AdminAuthority, VtcAclEntry, VtcRole};

    fn grant(right: Right, q: &str) -> ResourceGrant {
        let (capability, grade) = capability_for(right);
        ResourceGrant {
            capability,
            resource: q.parse().unwrap(),
            grade,
            delegated_by: "did:key:zG".into(),
            granted_at: Utc::now(),
            expires_at: None,
            reason: None,
            subject_was_member: true,
            granter_was_member: true,
            break_glass: None,
            review: None,
            single_admin: None,
        }
    }

    fn q(s: &str) -> ResourceQualifier {
        s.parse().unwrap()
    }

    const NS: &str = "git-ns:github.com/acme";
    const REPO: &str = "git-repo:github.com/acme/repo_1";
    const OTHER: &str = "git-repo:github.com/acme/repo_2";

    #[test]
    fn every_right_round_trips_its_grant() {
        for (right, at) in [
            (Right::NsAdmin, NS),
            (Right::RepoCreate, NS),
            (Right::RepoOwn, REPO),
            (Right::RepoMaintain, REPO),
            (Right::CommitSign, NS),
            (Right::CommitSign, REPO),
        ] {
            let g = grant(right, at);
            assert_eq!(g.git_right(), Some(right), "{right}@{at}");
            let v = serde_json::to_value(&g).unwrap();
            assert_eq!(serde_json::from_value::<ResourceGrant>(v).unwrap(), g);
        }
    }

    /// VTI-ACL-035: a namespace admin's grant covers the repositories inside
    /// it and nothing beside them; it implies management and commit signing.
    #[test]
    fn vti_acl_035_ns_admin_covers_its_repositories() {
        let g = grant(Right::NsAdmin, NS);
        assert!(g.confers(Capability::GitRepoManage, Some(&q(REPO))));
        assert!(g.confers(Capability::GitCommitSign, Some(&q(REPO))));
        assert!(g.confers(Capability::GitNsAdmin, Some(&q(NS))));
        assert!(!g.confers(
            Capability::GitRepoManage,
            Some(&q("git-repo:github.com/acme-labs/repo_1"))
        ));
        assert!(!g.confers(Capability::GitNsAdmin, None));
    }

    /// A creator holds creation at the namespace and nothing over the
    /// repositories already in it — the grade narrows the capability.
    #[test]
    fn creation_confers_nothing_inside_the_namespace() {
        let g = grant(Right::RepoCreate, NS);
        assert!(g.confers(Capability::GitRepoManage, Some(&q(NS))));
        assert!(!g.confers(Capability::GitRepoManage, Some(&q(REPO))));
        assert!(!g.confers(Capability::GitCommitSign, Some(&q(REPO))));
    }

    #[test]
    fn a_repository_grant_is_confined_to_its_repository() {
        let own = grant(Right::RepoOwn, REPO);
        assert!(own.confers(Capability::GitRepoManage, Some(&q(REPO))));
        assert!(!own.confers(Capability::GitRepoManage, Some(&q(OTHER))));
        assert!(!own.confers(Capability::GitRepoManage, Some(&q(NS))));
        let maintain = grant(Right::RepoMaintain, REPO);
        assert!(!maintain.confers(Capability::GitRepoManage, Some(&q(REPO))));
        assert!(maintain.confers(Capability::GitCommitSign, Some(&q(REPO))));
    }

    fn entry_with(grants: Vec<ResourceGrant>) -> VtcAclEntry {
        let mut e = VtcAclEntry::new(
            "did:key:zG",
            VtcRole::Member,
            AdminAuthority::none(),
            "did:key:zI",
        );
        e.resource_grants = grants;
        e
    }

    /// VTI-ACL-037 / VTI-ACL-071: a grant is never wider than its granter's
    /// own holding at a covering qualifier.
    #[test]
    fn vti_acl_037_a_grant_is_bounded_by_the_granters_holding() {
        let owner = entry_with(vec![grant(Right::RepoOwn, REPO)]);
        assert!(granter_covers(&owner, Right::RepoMaintain, &q(REPO)));
        assert!(granter_covers(&owner, Right::CommitSign, &q(REPO)));
        assert!(!granter_covers(&owner, Right::RepoOwn, &q(OTHER)));
        assert!(!granter_covers(&owner, Right::CommitSign, &q(NS)));
        assert!(!granter_covers(&owner, Right::NsAdmin, &q(NS)));

        let admin = entry_with(vec![grant(Right::NsAdmin, NS)]);
        assert!(granter_covers(&admin, Right::RepoOwn, &q(OTHER)));
        assert!(granter_covers(&admin, Right::RepoCreate, &q(NS)));
        assert!(!granter_covers(
            &admin,
            Right::NsAdmin,
            &q("git-ns:github.com/other")
        ));

        // A community administrator's unqualified git.ns.admin covers every
        // namespace (it is what binds and reseats).
        let mut ca = entry_with(vec![]);
        ca.admin = AdminAuthority::community_admin();
        assert!(granter_covers(&ca, Right::NsAdmin, &q(NS)));

        // An expired entry holds nothing.
        let mut expired = entry_with(vec![grant(Right::NsAdmin, NS)]);
        expired.expires_at = Some(1);
        assert!(!granter_covers(&expired, Right::CommitSign, &q(NS)));
    }
}
