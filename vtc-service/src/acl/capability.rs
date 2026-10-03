//! Role-based administration at the VTC: **capabilities**, **resource
//! qualifiers** and **administrative roles**.
//!
//! Design: `docs/05-design-notes/vtc-admin-roles.md` §4–§8. Wire shape:
//! `acl/_shared/0.2` (`CONVENTIONS.md` §4–§9).
//!
//! ## The model in one paragraph
//!
//! A [`Capability`] is one administrative power; the registry is fixed in code
//! and grows only by release (**VTI-ACL-032**). A capability may be qualified by
//! a [`ResourceQualifier`] naming a VTC-owned resource — never a VTA context
//! (**VTI-VTC-010**, **VTI-ACL-035**). An [`AdminRole`] is a **ceiling**, never
//! a grant (**VTI-ACL-010**): the capabilities an entry with that role *may*
//! hold. The entry states what it *does* hold in a [`CapabilityScope`] —
//! `ceiling`, `none` or a listed set — and its effective set is the ceiling
//! intersected with the listed grants, plus any additive grant
//! (**VTI-ACL-030**, **VTI-ACL-033**). Act and approve scope are stated, never
//! inferred from the shape of a list (**VTI-ACL-020…023**, **VTI-ACL-040**):
//! [`VtcActScope`] is `all` or `none`, because a VTC has no contexts.
//!
//! ## One question, one function
//!
//! Every authorization decision asks [`AdminAuthority::can`] — through
//! [`super::VtcAclEntry::can`], which adds the entry's expiry. Nothing reads a
//! list's emptiness to decide anything: each scope is a closed sum type with no
//! default, as `acl/_shared/0.2` CONVENTIONS §5 asks of typed implementations.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use vti_common::error::AppError;

use crate::policy::PolicyPurpose;

// ─── capabilities ────────────────────────────────────────────────────────

/// One administrative power — the registry of `vtc-admin-roles.md` §4.
///
/// Closed: a capability this build does not know is not a value of this type,
/// so it can never be granted (**VTI-ACL-032**). A stored entry naming one fails
/// to decode and confers nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    /// Granting, changing and removing roles and capabilities on others'
    /// entries, bounded by `vtc-admin-roles.md` §6.3.
    RolesAssign,
    /// The approvals rule list.
    ApprovalsAdmin,
    /// Uploading and activating policy, qualified by purpose.
    PolicyAdmin,
    /// `config/patch` / `import` / `reload` / `restart`.
    ConfigAdmin,
    /// Backup export.
    BackupExport,
    /// Backup import — it replaces the ACL.
    BackupRestore,
    /// Audit list and verify.
    AuditRead,
    /// `did-management/did/register`.
    DidAdmin,
    /// Suspend, remove, purge, change a member's non-administrative role.
    MembersManage,
    /// Join review decisions.
    JoinDecide,
    /// Issue and revoke invitations.
    InvitationsManage,
    /// Endorsements, personhood, status-list flips — issuing.
    CredentialsIssue,
    /// Endorsements, personhood, status-list flips — revoking.
    CredentialsRevoke,
    /// Granting and revoking vetters, auto-grant, vetting-withdrawal review.
    VettingManage,
    /// Profile, branding, website, schemas, endorsement types, join criteria.
    SurfaceAdmin,
    /// Registry sync jobs, recognition.
    RegistryAdmin,
    /// Revoking others' sessions and console keys (incident response).
    SessionsRevoke,
    /// A git namespace (qualified by namespace).
    GitNsAdmin,
    /// Repository create, adopt, archive, transfer.
    GitRepoManage,
    /// The CI-accepted commit right.
    GitCommitSign,
}

impl Capability {
    /// Every capability, in registry order.
    pub const ALL: [Capability; 20] = [
        Capability::RolesAssign,
        Capability::ApprovalsAdmin,
        Capability::PolicyAdmin,
        Capability::ConfigAdmin,
        Capability::BackupExport,
        Capability::BackupRestore,
        Capability::AuditRead,
        Capability::DidAdmin,
        Capability::MembersManage,
        Capability::JoinDecide,
        Capability::InvitationsManage,
        Capability::CredentialsIssue,
        Capability::CredentialsRevoke,
        Capability::VettingManage,
        Capability::SurfaceAdmin,
        Capability::RegistryAdmin,
        Capability::SessionsRevoke,
        Capability::GitNsAdmin,
        Capability::GitRepoManage,
        Capability::GitCommitSign,
    ];

    /// The registry identifier (`acl/_shared/0.2` `Capability` grammar).
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::RolesAssign => "vtc.roles.assign",
            Capability::ApprovalsAdmin => "vtc.approvals.admin",
            Capability::PolicyAdmin => "vtc.policy.admin",
            Capability::ConfigAdmin => "vtc.config.admin",
            Capability::BackupExport => "vtc.backup.export",
            Capability::BackupRestore => "vtc.backup.restore",
            Capability::AuditRead => "vtc.audit.read",
            Capability::DidAdmin => "vtc.did.admin",
            Capability::MembersManage => "vtc.members.manage",
            Capability::JoinDecide => "vtc.join.decide",
            Capability::InvitationsManage => "vtc.invitations.manage",
            Capability::CredentialsIssue => "vtc.credentials.issue",
            Capability::CredentialsRevoke => "vtc.credentials.revoke",
            Capability::VettingManage => "vtc.vetting.manage",
            Capability::SurfaceAdmin => "vtc.surface.admin",
            Capability::RegistryAdmin => "vtc.registry.admin",
            Capability::SessionsRevoke => "vtc.sessions.revoke",
            Capability::GitNsAdmin => "git.ns.admin",
            Capability::GitRepoManage => "git.repo.manage",
            Capability::GitCommitSign => "git.commit.sign",
        }
    }

    /// Whether holding this capability **at `resource`** lets a subject create
    /// authority — its own or someone else's (`vtc-admin-roles.md` §4). Granting
    /// or widening one is an N-of-M action in every case (**VTI-APV-018**, the
    /// generalised **VTI-APV-014**).
    ///
    /// `vtc.policy.admin` confers authority unqualified, or qualified by a
    /// purpose that decides authority (`PolicyPurpose::decides_authority`).
    pub fn is_authority_conferring(self, resource: Option<&ResourceQualifier>) -> bool {
        match self {
            Capability::RolesAssign
            | Capability::ApprovalsAdmin
            | Capability::ConfigAdmin
            | Capability::BackupRestore
            | Capability::DidAdmin
            | Capability::GitNsAdmin => true,
            Capability::PolicyAdmin => match resource {
                None => true,
                Some(ResourceQualifier::Policy(p)) => p.decides_authority(),
                Some(_) => false,
            },
            _ => false,
        }
    }

    /// Whether the registry classes this capability as **additive**: one no
    /// role implies, so it never appears in a role's ceiling — not a built-in
    /// one, and not a custom one (`vtc/roles/define/0.1`
    /// `additiveCapability`). Held only as an additive grant beside a role,
    /// which only an unrestricted granter makes (**VTI-ACL-033**).
    ///
    /// `git.commit.sign` is the one: the CI-accepted commit right a bridge or
    /// a contributor holds, not administration, and no built-in role's ceiling
    /// names it.
    pub fn is_registry_additive(self) -> bool {
        matches!(self, Capability::GitCommitSign)
    }

    /// Whether `resource` is a qualifier this capability can carry — a policy
    /// purpose for `vtc.policy.admin`, a criterion for `vtc.vetting.manage`, a
    /// namespace or repository for the `git.*` capabilities. `vtc.roles.assign`
    /// takes any, since it is bounded by what it may assign (§6.3).
    pub fn admits(self, resource: &ResourceQualifier) -> bool {
        use ResourceQualifier as Q;
        match self {
            Capability::RolesAssign => true,
            Capability::PolicyAdmin => matches!(resource, Q::Policy(_)),
            Capability::VettingManage => matches!(resource, Q::Criterion(_)),
            Capability::GitNsAdmin => matches!(resource, Q::GitNs(_)),
            Capability::GitRepoManage | Capability::GitCommitSign => {
                matches!(resource, Q::GitNs(_) | Q::GitRepo(_))
            }
            _ => false,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Capability {
    type Err = AppError;
    fn from_str(s: &str) -> Result<Self, AppError> {
        Capability::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "unknown capability '{s}' — this community recognises {} (VTI-ACL-032)",
                    Capability::ALL.map(|c| c.as_str()).join(", ")
                ))
            })
    }
}

impl Serialize for Capability {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// ─── resource qualifiers ─────────────────────────────────────────────────

/// A VTC-owned resource a capability is narrowed to (`vtc-admin-roles.md` §5).
///
/// Never a VTA context (**VTI-VTC-010**). Repository qualifiers name the
/// repository **id**, as git-ns rights do, so a rename moves the right and a
/// new repository with an old name inherits nothing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResourceQualifier {
    /// `git-ns:<forge>/<namespace>` — one namespace and every repository in it.
    GitNs(String),
    /// `git-repo:<forge>/<namespace>/<repo-id>` — one repository.
    GitRepo(String),
    /// `policy:<purpose>` — one policy purpose.
    Policy(PolicyPurpose),
    /// `criterion:<id>` — one join criterion.
    Criterion(String),
}

impl ResourceQualifier {
    /// Whether holding a capability at `self` covers acting on `other` — the
    /// resource itself, or one inside it (a namespace covers its
    /// repositories). **VTI-ACL-035**.
    pub fn covers(&self, other: &ResourceQualifier) -> bool {
        use ResourceQualifier as Q;
        match (self, other) {
            (a, b) if a == b => true,
            (Q::GitNs(ns), Q::GitRepo(repo)) => repo
                .strip_prefix(ns.as_str())
                .is_some_and(|rest| rest.starts_with('/')),
            (Q::GitNs(outer), Q::GitNs(inner)) => inner
                .strip_prefix(outer.as_str())
                .is_some_and(|rest| rest.starts_with('/')),
            _ => false,
        }
    }
}

impl fmt::Display for ResourceQualifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceQualifier::GitNs(v) => write!(f, "git-ns:{v}"),
            ResourceQualifier::GitRepo(v) => write!(f, "git-repo:{v}"),
            ResourceQualifier::Policy(p) => write!(f, "policy:{}", p.as_str()),
            ResourceQualifier::Criterion(v) => write!(f, "criterion:{v}"),
        }
    }
}

impl FromStr for ResourceQualifier {
    type Err = AppError;
    fn from_str(s: &str) -> Result<Self, AppError> {
        let bad = |why: &str| {
            AppError::Validation(format!(
                "resource qualifier '{s}' {why} — expected git-ns:<namespace>, \
                 git-repo:<repository-id>, policy:<purpose> or criterion:<id>"
            ))
        };
        let (kind, value) = s.split_once(':').ok_or_else(|| bad("has no kind"))?;
        if value.is_empty() || value.len() > 500 {
            return Err(bad("has an empty or oversized value"));
        }
        match kind {
            "git-ns" => Ok(ResourceQualifier::GitNs(value.to_string())),
            "git-repo" => Ok(ResourceQualifier::GitRepo(value.to_string())),
            "criterion" => Ok(ResourceQualifier::Criterion(value.to_string())),
            "policy" => serde_json::from_value::<PolicyPurpose>(serde_json::Value::String(
                value.to_string(),
            ))
            .map(ResourceQualifier::Policy)
            .map_err(|_| bad("names no policy purpose this community has")),
            _ => Err(bad("is of an unknown kind")),
        }
    }
}

impl Serialize for ResourceQualifier {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ResourceQualifier {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// ─── references and grants ───────────────────────────────────────────────

/// A capability, optionally qualified — `acl/_shared/0.2` `CapabilityRef`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapRef {
    pub capability: Capability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceQualifier>,
}

impl CapRef {
    pub fn new(capability: Capability, resource: Option<ResourceQualifier>) -> Self {
        Self {
            capability,
            resource,
        }
    }

    /// An unqualified reference — every resource of the capability's kind.
    pub fn all(capability: Capability) -> Self {
        Self::new(capability, None)
    }

    /// Whether holding `self` covers `wanted`: the same capability, and either
    /// unqualified or at a qualifier covering `wanted`'s (**VTI-ACL-035**). An
    /// unqualified `wanted` is covered only by an unqualified holding.
    pub fn covers(&self, wanted: &CapRef) -> bool {
        self.capability == wanted.capability
            && match (&self.resource, &wanted.resource) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(held), Some(want)) => held.covers(want),
            }
    }

    /// `cap@resource`, the form the CLI takes and audit rows carry.
    pub fn display(&self) -> String {
        match &self.resource {
            None => self.capability.to_string(),
            Some(r) => format!("{}@{r}", self.capability),
        }
    }

    /// Whether this reference is authority-conferring (§4).
    pub fn is_authority_conferring(&self) -> bool {
        self.capability
            .is_authority_conferring(self.resource.as_ref())
    }
}

impl FromStr for CapRef {
    type Err = AppError;
    /// `cap` or `cap@resource`.
    fn from_str(s: &str) -> Result<Self, AppError> {
        let (cap, res) = match s.split_once('@') {
            Some((c, r)) => (c, Some(r.parse::<ResourceQualifier>()?)),
            None => (s, None),
        };
        let capability: Capability = cap.parse()?;
        if let Some(r) = res.as_ref()
            && !capability.admits(r)
        {
            return Err(AppError::Validation(format!(
                "{capability} cannot be qualified by {r}"
            )));
        }
        Ok(CapRef::new(capability, res))
    }
}

/// A capability an entry holds — `acl/_shared/0.2` `CapabilityGrant`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityGrant {
    pub capability: Capability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceQualifier>,
    /// An additive grant: one no role implies, held beside the role
    /// (**VTI-ACL-033**). Only an unrestricted granter makes one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub additive: bool,
}

impl CapabilityGrant {
    pub fn cap_ref(&self) -> CapRef {
        CapRef::new(self.capability, self.resource.clone())
    }
}

impl From<CapRef> for CapabilityGrant {
    fn from(r: CapRef) -> Self {
        CapabilityGrant {
            capability: r.capability,
            resource: r.resource,
            additive: false,
        }
    }
}

// ─── scopes ──────────────────────────────────────────────────────────────

/// A VTC entry's act or approve scope (**VTI-ACL-020…023**, **VTI-ACL-040**).
///
/// `all` or `none` only: a VTC holds no contexts (**VTI-VTC-010**), and narrows
/// by resource qualifier instead (`vtc-admin-roles.md` §8). No default — a
/// stored entry without one does not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
pub enum VtcActScope {
    All,
    None,
}

impl VtcActScope {
    pub fn is_all(self) -> bool {
        matches!(self, VtcActScope::All)
    }
}

/// Which capabilities an entry holds, or may approve — `acl/_shared/0.2`
/// `CapabilityScope` / `ApproveCapabilityScope`.
///
/// `Listed` is never empty: the constructor and the decoder both refuse an
/// empty list (CONVENTIONS §4 rule 1), so emptiness can never mean anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "scope", rename_all = "camelCase")]
pub enum CapabilityScope {
    /// The role's full ceiling, unnarrowed.
    Ceiling,
    /// No capabilities on this axis.
    None,
    /// Exactly these grants (intersected with the ceiling, plus additive).
    Listed { grants: Vec<CapabilityGrant> },
}

impl CapabilityScope {
    /// A listed scope. Refuses an empty list.
    pub fn listed(grants: Vec<CapabilityGrant>) -> Result<Self, AppError> {
        if grants.is_empty() {
            return Err(AppError::Validation(
                "a listed capability scope names at least one capability — say `none` instead \
                 (acl/_shared/0.2 CONVENTIONS §4)"
                    .into(),
            ));
        }
        Ok(CapabilityScope::Listed { grants })
    }
}

impl<'de> Deserialize<'de> for CapabilityScope {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
        enum Raw {
            Ceiling,
            None,
            Listed { grants: Vec<CapabilityGrant> },
        }
        Ok(match Raw::deserialize(d)? {
            Raw::Ceiling => CapabilityScope::Ceiling,
            Raw::None => CapabilityScope::None,
            Raw::Listed { grants } => {
                CapabilityScope::listed(grants).map_err(serde::de::Error::custom)?
            }
        })
    }
}

// ─── roles ───────────────────────────────────────────────────────────────

/// Whether a ceiling admits a capability unqualified, qualified, or either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualification {
    /// Held community-wide only.
    Unqualified,
    /// Held at a qualifier only (`repo-manager`'s `git.ns.admin`).
    Required,
    /// Either.
    Optional,
}

/// One element of a role's ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CeilingItem {
    pub capability: Capability,
    pub qualification: Qualification,
}

impl CeilingItem {
    const fn new(capability: Capability, qualification: Qualification) -> Self {
        Self {
            capability,
            qualification,
        }
    }

    /// Whether this item admits `r` (capability and qualifier both).
    fn admits(&self, r: &CapRef) -> bool {
        self.capability == r.capability
            && !matches!(
                (&r.resource, self.qualification),
                (None, Qualification::Required) | (Some(_), Qualification::Unqualified)
            )
    }
}

/// An entry's **administrative role** — `vtc-admin-roles.md` §6.1.
///
/// One per entry (§11.1), beside the community role its membership carries
/// (`super::VtcRole`). A role is a ceiling, never a grant (**VTI-ACL-010**).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AdminRole {
    CommunityAdmin,
    Moderator,
    VettingLead,
    RepoManager,
    CredentialOfficer,
    Auditor,
    /// The least-privilege approver (**VTI-ACL-041**): no act authority, an
    /// approve scope as granted.
    Approver,
    /// A community-defined role (§6.2): a record in the ACL model
    /// ([`super::roles`]) naming a ceiling and an approve ceiling. The name
    /// alone confers nothing: an entry holding it is resolved against the
    /// stored definition when it is read ([`AdminAuthority::custom`]), and one
    /// naming a role with no definition confers nothing (**VTI-ACL-011**).
    Custom(String),
}

impl AdminRole {
    /// The built-in roles, in §6.1 order.
    pub const BUILT_IN: [AdminRole; 7] = [
        AdminRole::CommunityAdmin,
        AdminRole::Moderator,
        AdminRole::VettingLead,
        AdminRole::RepoManager,
        AdminRole::CredentialOfficer,
        AdminRole::Auditor,
        AdminRole::Approver,
    ];

    pub fn as_str(&self) -> &str {
        match self {
            AdminRole::CommunityAdmin => "community-admin",
            AdminRole::Moderator => "moderator",
            AdminRole::VettingLead => "vetting-lead",
            AdminRole::RepoManager => "repo-manager",
            AdminRole::CredentialOfficer => "credential-officer",
            AdminRole::Auditor => "auditor",
            AdminRole::Approver => "approver",
            AdminRole::Custom(name) => name,
        }
    }

    /// Whether this is a built-in role (§6.1) — fixed by this build, never
    /// defined, replaced or deleted through `vtc/roles/*`.
    pub fn is_built_in(&self) -> bool {
        !matches!(self, AdminRole::Custom(_))
    }

    /// The ceiling: the capabilities an entry with this role may hold
    /// (§6.1).
    pub fn ceiling(&self) -> Vec<CeilingItem> {
        use Capability as C;
        use Qualification as Q;
        match self {
            AdminRole::CommunityAdmin => {
                let mut out: Vec<CeilingItem> = Capability::ALL
                    .into_iter()
                    .filter(|c| c.as_str().starts_with("vtc."))
                    .map(|c| CeilingItem::new(c, Q::Optional))
                    .collect();
                // `git.ns.admin` unqualified; `git.repo.manage` too, so a
                // community-admin can make a repo manager (§7: "a
                // community-admin can, because their ceiling covers it").
                out.push(CeilingItem::new(C::GitNsAdmin, Q::Optional));
                out.push(CeilingItem::new(C::GitRepoManage, Q::Optional));
                out
            }
            AdminRole::Moderator => vec![
                CeilingItem::new(C::MembersManage, Q::Unqualified),
                CeilingItem::new(C::JoinDecide, Q::Unqualified),
                CeilingItem::new(C::InvitationsManage, Q::Unqualified),
            ],
            AdminRole::VettingLead => vec![CeilingItem::new(C::VettingManage, Q::Optional)],
            AdminRole::RepoManager => vec![
                CeilingItem::new(C::GitRepoManage, Q::Required),
                CeilingItem::new(C::GitNsAdmin, Q::Required),
            ],
            AdminRole::CredentialOfficer => vec![
                CeilingItem::new(C::CredentialsIssue, Q::Unqualified),
                CeilingItem::new(C::CredentialsRevoke, Q::Unqualified),
            ],
            AdminRole::Auditor => vec![CeilingItem::new(C::AuditRead, Q::Unqualified)],
            AdminRole::Approver | AdminRole::Custom(_) => vec![],
        }
    }

    /// The approve ceiling: what an entry with this role may approve
    /// (§6.1, "Approve scope (default)").
    pub fn approve_ceiling(&self) -> Vec<CeilingItem> {
        match self {
            AdminRole::CommunityAdmin | AdminRole::Approver => Capability::ALL
                .into_iter()
                .map(|c| CeilingItem::new(c, Qualification::Optional))
                .collect(),
            AdminRole::Auditor | AdminRole::Custom(_) => vec![],
            other => other.ceiling(),
        }
    }

    /// Whether `r` lies inside this built-in role's ceiling. A custom role
    /// admits nothing here: ask [`AdminAuthority::ceiling_admits`], which reads
    /// its stored definition.
    pub fn ceiling_admits(&self, r: &CapRef) -> bool {
        self.ceiling().iter().any(|i| i.admits(r))
    }

    fn approve_ceiling_admits(&self, r: &CapRef) -> bool {
        self.approve_ceiling().iter().any(|i| i.admits(r))
    }

    /// The ceiling as capability references, the shape `vtc/roles/_shared`
    /// `RoleDefinition` states it in: each capability once, unqualified — an
    /// item held only at a qualifier is admitted at any qualifier inside it.
    pub fn ceiling_refs(&self) -> Vec<CapRef> {
        self.ceiling()
            .into_iter()
            .map(|i| CapRef::all(i.capability))
            .collect()
    }

    /// [`Self::ceiling_refs`] for the approve ceiling.
    pub fn approve_ceiling_refs(&self) -> Vec<CapRef> {
        self.approve_ceiling()
            .into_iter()
            .map(|i| CapRef::all(i.capability))
            .collect()
    }

    /// The default act scope a role is granted with when none is stated by a
    /// 0.1 client: `none` for the least-privilege approver, `all` otherwise.
    pub fn default_act(&self) -> VtcActScope {
        match self {
            AdminRole::Approver => VtcActScope::None,
            _ => VtcActScope::All,
        }
    }

    /// The default approve scope (§6.1).
    pub fn default_approve(&self) -> VtcActScope {
        match self {
            AdminRole::Auditor | AdminRole::Custom(_) => VtcActScope::None,
            _ => VtcActScope::All,
        }
    }
}

impl fmt::Display for AdminRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AdminRole {
    type Err = AppError;
    fn from_str(s: &str) -> Result<Self, AppError> {
        if let Some(r) = AdminRole::BUILT_IN.iter().find(|r| r.as_str() == s) {
            return Ok(r.clone());
        }
        let valid = !s.is_empty()
            && s.len() <= 64
            && s.chars()
                .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-' | '_'));
        if valid && s != "member" {
            Ok(AdminRole::Custom(s.to_string()))
        } else {
            Err(AppError::Validation(format!(
                "'{s}' is not an administrative role — the built-in roles are {}",
                AdminRole::BUILT_IN
                    .map(|r| r.as_str().to_string())
                    .join(", ")
            )))
        }
    }
}

impl Serialize for AdminRole {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AdminRole {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// ─── the authority an entry holds ────────────────────────────────────────

/// An entry's administrative authority: role, act scope, capabilities, approve
/// scope and approvable capabilities — every axis stated
/// (`acl/_shared/0.2` CONVENTIONS §4).
///
/// Flattened into [`super::VtcAclEntry`] on disk, so the stored row carries
/// `adminRole`, `act`, `capabilities`, `approve` and `approveCapabilities`
/// beside the membership fields. None of them has a default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminAuthority {
    /// `None` = no administrative role: the entry is a member (or an
    /// integration) with no administrative power, whatever its community role.
    pub admin_role: Option<AdminRole>,
    pub act: VtcActScope,
    pub capabilities: CapabilityScope,
    pub approve: VtcActScope,
    pub approve_capabilities: CapabilityScope,
    /// A custom role's stored definition, resolved when the entry is read
    /// ([`super::roles::resolve`]). Never stored on the entry and never taken
    /// from a caller: the definition is the record in the ACL model, read now.
    /// `None` for a built-in role, and for a custom role with no definition —
    /// which then confers nothing (**VTI-ACL-011**).
    #[serde(skip)]
    pub custom: Option<Arc<RoleCeilings>>,
}

/// A custom role's two ceilings, as its stored definition states them
/// (`vtc/roles/_shared/0.1` `RoleDefinition`). A ceiling reference admits an
/// entry's grant at its own qualifier or one inside it (**VTI-ACL-035**).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleCeilings {
    pub ceiling: Vec<CapRef>,
    pub approve: Vec<CapRef>,
}

impl AdminAuthority {
    /// No administrative authority at all.
    pub fn none() -> Self {
        Self {
            admin_role: None,
            act: VtcActScope::None,
            capabilities: CapabilityScope::None,
            approve: VtcActScope::None,
            approve_capabilities: CapabilityScope::None,
            custom: None,
        }
    }

    /// `role` with its full ceiling and its default act and approve scopes —
    /// what a 0.1 grant, an install bootstrap and the offline CLI write.
    pub fn for_role(role: AdminRole) -> Self {
        let approve = role.default_approve();
        Self {
            act: role.default_act(),
            capabilities: CapabilityScope::Ceiling,
            approve,
            approve_capabilities: if approve.is_all() {
                CapabilityScope::Ceiling
            } else {
                CapabilityScope::None
            },
            admin_role: Some(role),
            custom: None,
        }
    }

    /// A `community-admin` with the full ceiling: what this community used to
    /// call an unrestricted administrator (§6.1).
    pub fn community_admin() -> Self {
        Self::for_role(AdminRole::CommunityAdmin)
    }

    /// Whether this entry holds any administrative role. What console sign-in
    /// admits (any role, not only `community-admin`).
    pub fn is_administrator(&self) -> bool {
        match self.admin_role.as_ref() {
            None => false,
            // A custom role with no definition is not a role this community
            // recognises: the entry confers nothing, sign-in included
            // (VTI-ACL-011).
            Some(AdminRole::Custom(_)) => self.custom.is_some(),
            Some(_) => true,
        }
    }

    /// The capabilities this entry holds **when its act scope is `all`** —
    /// `ceiling ∩ listed ∪ additive` (**VTI-ACL-030**, **-033**). A listed grant
    /// outside the ceiling is never effective, even if one was written around
    /// the write-time check.
    pub fn effective(&self) -> Vec<CapRef> {
        match &self.capabilities {
            CapabilityScope::None => vec![],
            CapabilityScope::Ceiling => match self.admin_role.as_ref() {
                None => vec![],
                Some(AdminRole::Custom(_)) => self
                    .custom
                    .as_ref()
                    .map(|d| d.ceiling.clone())
                    .unwrap_or_default(),
                Some(role) => role
                    .ceiling()
                    .into_iter()
                    .filter(|i| i.qualification != Qualification::Required)
                    .map(|i| CapRef::all(i.capability))
                    .collect(),
            },
            CapabilityScope::Listed { grants } => grants
                .iter()
                .map(|g| (g.cap_ref(), g.additive))
                .filter(|(r, additive)| *additive || self.ceiling_admits(r))
                .map(|(r, _)| r)
                .collect(),
        }
    }

    /// Whether `r` lies inside this entry's role ceiling — a built-in role's,
    /// or a custom role's stored one. Nothing lies inside no role, or inside a
    /// custom role with no definition (**VTI-ACL-011**).
    pub fn ceiling_admits(&self, r: &CapRef) -> bool {
        match self.admin_role.as_ref() {
            None => false,
            Some(AdminRole::Custom(_)) => self
                .custom
                .as_ref()
                .is_some_and(|d| d.ceiling.iter().any(|c| c.covers(r))),
            Some(role) => role.ceiling_admits(r),
        }
    }

    /// [`Self::ceiling_admits`] for the approve ceiling.
    fn approve_ceiling_admits(&self, r: &CapRef) -> bool {
        match self.admin_role.as_ref() {
            None => false,
            Some(AdminRole::Custom(_)) => self
                .custom
                .as_ref()
                .is_some_and(|d| d.approve.iter().any(|c| c.covers(r))),
            Some(role) => role.approve_ceiling_admits(r),
        }
    }

    /// Whether the role's ceiling names `cap` at all — what makes an additive
    /// grant of it redundant (**VTI-ACL-033**).
    fn ceiling_names(&self, cap: Capability) -> bool {
        match self.admin_role.as_ref() {
            None => false,
            Some(AdminRole::Custom(_)) => self
                .custom
                .as_ref()
                .is_some_and(|d| d.ceiling.iter().any(|c| c.capability == cap)),
            Some(role) => role.ceiling().iter().any(|i| i.capability == cap),
        }
    }

    /// The capabilities this entry may approve **when its approve scope is
    /// `all`** (**VTI-ACL-040**). Bounded by `approve`: with approve `none`
    /// nothing, whatever this lists.
    pub fn effective_approvable(&self) -> Vec<CapRef> {
        let Some(role) = self.admin_role.as_ref() else {
            return vec![];
        };
        match &self.approve_capabilities {
            CapabilityScope::None => vec![],
            CapabilityScope::Ceiling => match role {
                AdminRole::Custom(_) => self
                    .custom
                    .as_ref()
                    .map(|d| d.approve.clone())
                    .unwrap_or_default(),
                role => role
                    .approve_ceiling()
                    .into_iter()
                    .filter(|i| i.qualification != Qualification::Required)
                    .map(|i| CapRef::all(i.capability))
                    .collect(),
            },
            CapabilityScope::Listed { grants } => grants
                .iter()
                .map(CapabilityGrant::cap_ref)
                .filter(|r| self.approve_ceiling_admits(r))
                .collect(),
        }
    }

    /// **The** authorization question: may this authority exercise `cap` on
    /// `resource` (`None` = community-wide)? Expiry is the entry's, and is
    /// checked by [`super::VtcAclEntry::can`].
    pub fn can(&self, cap: Capability, resource: Option<&ResourceQualifier>) -> bool {
        let wanted = CapRef::new(cap, resource.cloned());
        self.act.is_all() && self.effective().iter().any(|h| h.covers(&wanted))
    }

    /// Whether this authority holds `cap` at **any** qualifier — the gate on a
    /// read that lists a capability's resources (a policy list, say).
    pub fn can_any(&self, cap: Capability) -> bool {
        self.act.is_all() && self.effective().iter().any(|h| h.capability == cap)
    }

    /// May this authority approve an action needing `wanted`?
    pub fn can_approve(&self, wanted: &CapRef) -> bool {
        self.approve.is_all() && self.effective_approvable().iter().any(|h| h.covers(wanted))
    }

    /// Whether this authority holds `wanted` (at a covering qualifier).
    pub fn holds(&self, wanted: &CapRef) -> bool {
        self.can(wanted.capability, wanted.resource.as_ref())
    }

    /// The authority-conferring capabilities this entry holds.
    pub fn conferring(&self) -> Vec<CapRef> {
        if !self.act.is_all() {
            return vec![];
        }
        self.effective()
            .into_iter()
            .filter(CapRef::is_authority_conferring)
            .collect()
    }

    /// What this authority can exercise: its effective set, or nothing when
    /// it may not act.
    fn exercisable(&self) -> Vec<CapRef> {
        if self.act.is_all() {
            self.effective()
        } else {
            vec![]
        }
    }

    /// What this authority can approve: its approvable set, or nothing when
    /// its approve scope is `none`.
    fn approvable(&self) -> Vec<CapRef> {
        if self.approve.is_all() {
            self.effective_approvable()
        } else {
            vec![]
        }
    }

    /// Whether moving from `prev` to `self` gives the subject anything it could
    /// not exercise or approve before — a capability, a wider qualifier, or
    /// approve authority (CONVENTIONS §9: every axis that can be narrowed can be
    /// widened again).
    pub fn widens_from(&self, prev: &AdminAuthority) -> bool {
        let (held, approvable) = (prev.exercisable(), prev.approvable());
        self.exercisable()
            .iter()
            .any(|c| !held.iter().any(|h| h.covers(c)))
            || self
                .approvable()
                .iter()
                .any(|c| !approvable.iter().any(|h| h.covers(c)))
    }

    /// Whether moving from `prev` to `self` takes anything away — a privilege
    /// reduction, audited and applied at the subject's next authorization
    /// decision (CONVENTIONS §10).
    pub fn narrows_from(&self, prev: &AdminAuthority) -> bool {
        prev.widens_from(self)
    }

    /// Check what a grant writes against the role's ceilings — the write-time
    /// half of **VTI-ACL-030…033** that does not depend on the granter.
    pub fn validate_against_ceiling(&self) -> Result<(), CeilingError> {
        let Some(role) = self.admin_role.as_ref() else {
            // No role: nothing but additive grants may be held, and an additive
            // grant to a role-less entry is the only way an integration gets
            // one. `ceiling` on no role confers nothing; refuse it as
            // meaningless rather than store it.
            if let CapabilityScope::Listed { grants } = &self.capabilities
                && let Some(g) = grants.iter().find(|g| !g.additive)
            {
                return Err(CeilingError::OutsideCeiling(vec![g.cap_ref().display()]));
            }
            return Ok(());
        };
        // A custom role with no stored definition is not one this community
        // recognises (VTI-ACL-011): never written, whatever it lists.
        if !role.is_built_in() && self.custom.is_none() {
            return Err(CeilingError::RoleNotRecognized(role.to_string()));
        }
        if let CapabilityScope::Listed { grants } = &self.capabilities {
            for g in grants {
                if let Some(r) = g.resource.as_ref()
                    && !g.capability.admits(r)
                {
                    return Err(CeilingError::BadQualifier(g.cap_ref().display()));
                }
            }
            let outside: Vec<String> = grants
                .iter()
                .filter(|g| !g.additive && !self.ceiling_admits(&g.cap_ref()))
                .map(|g| g.cap_ref().display())
                .collect();
            if !outside.is_empty() {
                return Err(CeilingError::OutsideCeiling(outside));
            }
            let within: Vec<String> = grants
                .iter()
                .filter(|g| g.additive && self.ceiling_names(g.capability))
                .map(|g| g.cap_ref().display())
                .collect();
            if !within.is_empty() {
                return Err(CeilingError::AdditiveWithinCeiling(within));
            }
        }
        if matches!(self.capabilities, CapabilityScope::Ceiling)
            && role.is_built_in()
            && role
                .ceiling()
                .iter()
                .all(|i| i.qualification == Qualification::Required)
            && !role.ceiling().is_empty()
        {
            return Err(CeilingError::NeedsQualifiers(role.to_string()));
        }
        if let CapabilityScope::Listed { grants } = &self.approve_capabilities {
            let outside: Vec<String> = grants
                .iter()
                .filter(|g| !self.approve_ceiling_admits(&g.cap_ref()))
                .map(|g| g.cap_ref().display())
                .collect();
            if !outside.is_empty() {
                return Err(CeilingError::OutsideCeiling(outside));
            }
        }
        Ok(())
    }
}

/// Why a written entry does not fit its role (`acl/grant/0.2` codes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeilingError {
    /// `roleNotRecognized`.
    RoleNotRecognized(String),
    /// `capabilityOutsideCeiling`.
    OutsideCeiling(Vec<String>),
    /// `additiveWithinCeiling`.
    AdditiveWithinCeiling(Vec<String>),
    /// A qualifier the capability cannot carry (`malformedRequest`).
    BadQualifier(String),
    /// A role whose whole ceiling is qualified, granted `ceiling`.
    NeedsQualifiers(String),
}

impl fmt::Display for CeilingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CeilingError::RoleNotRecognized(r) => write!(
                f,
                "'{r}' is not a role this community can grant — the built-in roles are {}, and \
                 vtc/roles/list names its custom roles (VTI-ACL-011)",
                AdminRole::BUILT_IN
                    .map(|r| r.as_str().to_string())
                    .join(", ")
            ),
            CeilingError::OutsideCeiling(c) => write!(
                f,
                "{} lie outside the role's ceiling — choose a role whose ceiling includes them \
                 (VTI-ACL-031)",
                c.join(", ")
            ),
            CeilingError::AdditiveWithinCeiling(c) => write!(
                f,
                "{} are marked additive but the role's ceiling already includes them — grant \
                 them as ordinary capabilities (VTI-ACL-033)",
                c.join(", ")
            ),
            CeilingError::BadQualifier(c) => {
                write!(f, "{c} names a qualifier its capability cannot carry")
            }
            CeilingError::NeedsQualifiers(r) => write!(
                f,
                "{r}'s ceiling is held only at a qualifier — list the grants with the resources \
                 they apply to rather than `ceiling`"
            ),
        }
    }
}

// ─── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn q(s: &str) -> ResourceQualifier {
        s.parse().unwrap()
    }

    fn listed(items: &[(&str, bool)]) -> CapabilityScope {
        CapabilityScope::listed(
            items
                .iter()
                .map(|(s, additive)| {
                    let r: CapRef = s.parse().unwrap();
                    CapabilityGrant {
                        capability: r.capability,
                        resource: r.resource,
                        additive: *additive,
                    }
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn every_capability_round_trips_its_registry_name() {
        for c in Capability::ALL {
            assert_eq!(c.as_str().parse::<Capability>().unwrap(), c);
            let json = serde_json::to_string(&c).unwrap();
            assert_eq!(serde_json::from_str::<Capability>(&json).unwrap(), c);
        }
    }

    /// VTI-ACL-032: a capability this build does not know is never granted —
    /// it is not a value of the type, so a stored grant naming one fails to
    /// decode rather than being read as held.
    #[test]
    fn vti_acl_032_an_unknown_capability_does_not_decode() {
        assert!("vtc.everything".parse::<Capability>().is_err());
        assert!(
            serde_json::from_value::<CapabilityScope>(serde_json::json!({
                "scope": "listed", "grants": [{"capability": "vtc.everything"}]
            }))
            .is_err()
        );
    }

    /// CONVENTIONS §4 rule 1: an empty list is not a fourth value.
    #[test]
    fn an_empty_listed_scope_is_refused_on_construction_and_decode() {
        assert!(CapabilityScope::listed(vec![]).is_err());
        assert!(
            serde_json::from_value::<CapabilityScope>(
                serde_json::json!({"scope": "listed", "grants": []})
            )
            .is_err()
        );
    }

    /// No scope has a default (VTI-ACL-006…008): an authority without `act`
    /// or `capabilities` does not decode.
    #[test]
    fn absence_derives_nothing() {
        let missing_act = serde_json::json!({
            "adminRole": "community-admin",
            "capabilities": {"scope": "ceiling"},
            "approve": {"scope": "none"},
            "approveCapabilities": {"scope": "none"},
        });
        assert!(serde_json::from_value::<AdminAuthority>(missing_act).is_err());
    }

    /// VTI-ACL-035: a namespace qualifier covers its repositories and nothing
    /// beside them; a repository covers only itself.
    #[test]
    fn vti_acl_035_a_namespace_covers_its_repositories() {
        let ns = q("git-ns:github.com/acme");
        assert!(ns.covers(&q("git-repo:github.com/acme/r#4211")));
        assert!(ns.covers(&ns));
        assert!(!ns.covers(&q("git-repo:github.com/acme-evil/r#1")));
        assert!(!ns.covers(&q("git-ns:github.com/other")));
        let repo = q("git-repo:github.com/acme/r#4211");
        assert!(!repo.covers(&ns));
        assert!(!q("policy:join").covers(&q("policy:removal")));
    }

    #[test]
    fn an_unqualified_holding_covers_every_resource_and_a_qualified_one_does_not_cover_all() {
        let all = CapRef::all(Capability::GitRepoManage);
        let acme: CapRef = "git.repo.manage@git-ns:github.com/acme".parse().unwrap();
        assert!(all.covers(&acme));
        assert!(!acme.covers(&all));
        assert!(
            acme.covers(
                &"git.repo.manage@git-repo:github.com/acme/r#1"
                    .parse()
                    .unwrap()
            )
        );
    }

    #[test]
    fn a_qualifier_the_capability_cannot_carry_is_refused() {
        assert!(
            "vtc.audit.read@git-ns:github.com/acme"
                .parse::<CapRef>()
                .is_err()
        );
        assert!("vtc.policy.admin@criterion:x".parse::<CapRef>().is_err());
        assert!("vtc.policy.admin@policy:join".parse::<CapRef>().is_ok());
        assert!(
            "vtc.policy.admin@policy:nonsense"
                .parse::<CapRef>()
                .is_err()
        );
    }

    /// VTI-ACL-030: effective = ceiling ∩ listed (+ additive).
    #[test]
    fn vti_acl_030_effective_is_the_ceiling_intersected_with_the_listed_set() {
        let mut a = AdminAuthority::for_role(AdminRole::Moderator);
        a.capabilities = listed(&[("vtc.join.decide", false), ("vtc.audit.read", false)]);
        // `vtc.audit.read` is outside the moderator ceiling: never effective,
        // even when written around the check.
        assert!(a.can(Capability::JoinDecide, None));
        assert!(!a.can(Capability::AuditRead, None));
        assert!(!a.can(Capability::MembersManage, None), "narrowed away");
        assert!(a.validate_against_ceiling().is_err());
    }

    /// VTI-ACL-033: an additive grant is held beside the role.
    #[test]
    fn vti_acl_033_an_additive_grant_is_held_beside_the_role() {
        let mut a = AdminAuthority::for_role(AdminRole::Auditor);
        a.capabilities = listed(&[("vtc.audit.read", false), ("vtc.backup.export", true)]);
        assert!(a.validate_against_ceiling().is_ok());
        assert!(a.can(Capability::BackupExport, None));
        assert!(a.can(Capability::AuditRead, None));
        // Additive on something the ceiling includes is refused.
        a.capabilities = listed(&[("vtc.audit.read", true)]);
        assert!(matches!(
            a.validate_against_ceiling(),
            Err(CeilingError::AdditiveWithinCeiling(_))
        ));
    }

    /// VTI-ACL-021: act `none` holds nothing, whatever its capabilities say.
    #[test]
    fn vti_acl_021_act_none_can_do_nothing() {
        let mut a = AdminAuthority::community_admin();
        a.act = VtcActScope::None;
        for c in Capability::ALL {
            assert!(!a.can(c, None), "{c}");
        }
    }

    /// VTI-ACL-041: the least-privilege approver approves and acts nowhere.
    #[test]
    fn vti_acl_041_the_approver_role_approves_without_acting() {
        let a = AdminAuthority::for_role(AdminRole::Approver);
        assert_eq!(a.act, VtcActScope::None);
        assert!(Capability::ALL.into_iter().all(|c| !a.can(c, None)));
        assert!(a.can_approve(&CapRef::all(Capability::RolesAssign)));
    }

    #[test]
    fn community_admin_with_the_full_ceiling_holds_every_vtc_capability() {
        let a = AdminAuthority::community_admin();
        for c in Capability::ALL {
            let expected = c != Capability::GitCommitSign;
            assert_eq!(a.can(c, None), expected, "{c}");
        }
        assert!(a.can(Capability::PolicyAdmin, Some(&q("policy:join"))));
    }

    #[test]
    fn a_qualified_repo_manager_is_confined_to_its_namespace() {
        let mut a = AdminAuthority::for_role(AdminRole::RepoManager);
        a.capabilities = listed(&[("git.repo.manage@git-ns:github.com/acme", false)]);
        assert!(a.validate_against_ceiling().is_ok());
        assert!(a.can(
            Capability::GitRepoManage,
            Some(&q("git-repo:github.com/acme/r#1"))
        ));
        assert!(!a.can(
            Capability::GitRepoManage,
            Some(&q("git-ns:github.com/other"))
        ));
        assert!(!a.can(Capability::GitRepoManage, None));
        // Unqualified is outside a repo manager's ceiling.
        a.capabilities = listed(&[("git.repo.manage", false)]);
        assert!(a.validate_against_ceiling().is_err());
        // And `ceiling` cannot stand for qualified grants.
        a.capabilities = CapabilityScope::Ceiling;
        assert!(matches!(
            a.validate_against_ceiling(),
            Err(CeilingError::NeedsQualifiers(_))
        ));
    }

    #[test]
    fn authority_conferring_classification_follows_the_registry() {
        assert!(Capability::RolesAssign.is_authority_conferring(None));
        assert!(Capability::PolicyAdmin.is_authority_conferring(None));
        assert!(Capability::PolicyAdmin.is_authority_conferring(Some(&q("policy:join"))));
        assert!(!Capability::PolicyAdmin.is_authority_conferring(Some(&q("policy:directory"))));
        assert!(Capability::GitNsAdmin.is_authority_conferring(Some(&q("git-ns:a/b"))));
        assert!(!Capability::AuditRead.is_authority_conferring(None));
        assert!(!Capability::MembersManage.is_authority_conferring(None));
    }

    /// VTI-ACL-011: a custom role confers nothing until its stored definition
    /// is resolved onto the entry, and then exactly its ceiling.
    #[test]
    fn vti_acl_011_a_custom_role_confers_only_its_resolved_definition() {
        let r: AdminRole = "events-team".parse().unwrap();
        assert_eq!(r, AdminRole::Custom("events-team".into()));
        let mut a = AdminAuthority::for_role(r);
        assert!(matches!(
            a.validate_against_ceiling(),
            Err(CeilingError::RoleNotRecognized(_))
        ));
        assert!(Capability::ALL.into_iter().all(|c| !a.can(c, None)));

        a.custom = Some(Arc::new(RoleCeilings {
            ceiling: vec![
                CapRef::all(Capability::SurfaceAdmin),
                "git.repo.manage@git-ns:github.com/acme".parse().unwrap(),
            ],
            approve: vec![CapRef::all(Capability::SurfaceAdmin)],
        }));
        a.approve = VtcActScope::All;
        a.approve_capabilities = CapabilityScope::Ceiling;
        assert!(a.validate_against_ceiling().is_ok());
        assert!(a.can(Capability::SurfaceAdmin, None));
        assert!(a.can(
            Capability::GitRepoManage,
            Some(&q("git-repo:github.com/acme/r#1"))
        ));
        assert!(!a.can(Capability::GitRepoManage, None));
        assert!(!a.can(Capability::InvitationsManage, None));
        assert!(a.can_approve(&CapRef::all(Capability::SurfaceAdmin)));
        assert!(!a.can_approve(&CapRef::all(Capability::RolesAssign)));

        // A listed grant outside the stored ceiling is refused, and never
        // effective.
        a.capabilities = listed(&[("vtc.audit.read", false)]);
        assert!(matches!(
            a.validate_against_ceiling(),
            Err(CeilingError::OutsideCeiling(_))
        ));
        assert!(!a.can(Capability::AuditRead, None));
        assert!("member".parse::<AdminRole>().is_err());
        assert!("Bad Name".parse::<AdminRole>().is_err());
    }

    #[test]
    fn authority_round_trips_its_stored_shape() {
        let mut a = AdminAuthority::for_role(AdminRole::VettingLead);
        a.capabilities = listed(&[("vtc.vetting.manage@criterion:age-over-18", false)]);
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["adminRole"], "vetting-lead");
        assert_eq!(v["act"], serde_json::json!({"scope": "all"}));
        assert_eq!(
            v["capabilities"]["grants"][0]["resource"],
            "criterion:age-over-18"
        );
        assert_eq!(serde_json::from_value::<AdminAuthority>(v).unwrap(), a);
    }
}
