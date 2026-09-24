//! The records the VTC keeps for its forge namespaces.
//!
//! These are **storage** shapes, not wire shapes. What goes on the wire is the
//! generated type of the task being answered (`trust_tasks_rs::specs::git_ns`),
//! built from these by [`super::wire`]. Keeping the two apart is what lets a
//! repository's rights stay keyed by an internal identifier — and so survive a
//! rename on the forge — while every task still speaks in resources.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One of the five git rights (`git-ns/right/grant/0.1`, *The rights model*).
///
/// Each string is also the TRQP `action` the right is published under, so the
/// spelling is the specification's, carried verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Right {
    #[serde(rename = "git.ns.admin")]
    NsAdmin,
    #[serde(rename = "git.repo.create")]
    RepoCreate,
    #[serde(rename = "git.repo.own")]
    RepoOwn,
    #[serde(rename = "git.repo.maintain")]
    RepoMaintain,
    #[serde(rename = "git.commit.sign")]
    CommitSign,
}

/// Which level of resource a right applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Namespace,
    Repository,
    /// `git.commit.sign` may be held on a repository or on a whole namespace.
    Either,
}

impl Right {
    pub const ALL: [Right; 5] = [
        Right::NsAdmin,
        Right::RepoCreate,
        Right::RepoOwn,
        Right::RepoMaintain,
        Right::CommitSign,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Right::NsAdmin => "git.ns.admin",
            Right::RepoCreate => "git.repo.create",
            Right::RepoOwn => "git.repo.own",
            Right::RepoMaintain => "git.repo.maintain",
            Right::CommitSign => "git.commit.sign",
        }
    }

    pub fn parse(s: &str) -> Option<Right> {
        Right::ALL.into_iter().find(|r| r.as_str() == s)
    }

    /// The level of resource this right is granted on. Fixed rule 1's second
    /// half: a repository right named on a namespace, or a namespace right on a
    /// repository, is a `scopeViolation`.
    pub fn level(self) -> Level {
        match self {
            Right::NsAdmin | Right::RepoCreate => Level::Namespace,
            Right::RepoOwn | Right::RepoMaintain => Level::Repository,
            Right::CommitSign => Level::Either,
        }
    }

    /// Rank among the repository rights, for "highest effective right".
    /// `own` > `maintain` > `commit.sign`; namespace rights rank above all
    /// because `ns.admin` implies `own` everywhere in its namespace.
    pub fn rank(self) -> u8 {
        match self {
            Right::NsAdmin => 5,
            Right::RepoCreate => 4,
            Right::RepoOwn => 3,
            Right::RepoMaintain => 2,
            Right::CommitSign => 1,
        }
    }

    /// Whether the right is namespace-level for the members-only floor
    /// (fixed rule 5).
    pub fn is_namespace_right(self) -> bool {
        matches!(self, Right::NsAdmin | Right::RepoCreate)
    }
}

impl std::fmt::Display for Right {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A forge-qualified resource: `<forge-host>/<owner>` or
/// `<forge-host>/<owner>/<repo>`, lowercase (`git-ns/right/grant/0.1`,
/// *Resources*).
///
/// Parsed, never assumed: an unqualified `owner/repo` is refused, because the
/// forge host is the segment that keeps `github.com/acme` and
/// `codeberg.org/acme` — which may belong to different people — apart.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Resource {
    pub forge: String,
    pub owner: String,
    pub repo: Option<String>,
}

impl Resource {
    /// Parse a resource as it arrives on the wire.
    ///
    /// Strict rather than normalising: the specification makes lowercasing the
    /// producer's job ("a producer lowercases before sending"), and the
    /// registry compares by exact string, so a mixed-case resource accepted
    /// here would publish a tuple no verifier ever queries.
    pub fn parse(raw: &str) -> Result<Resource, String> {
        if raw != raw.to_lowercase() {
            return Err(format!(
                "`{raw}` is not lowercase; resources are lowercase on the wire"
            ));
        }
        let parts: Vec<&str> = raw.split('/').collect();
        let (forge, owner, repo) = match parts.as_slice() {
            [f, o] => (*f, *o, None),
            [f, o, r] => (*f, *o, Some(*r)),
            _ => {
                return Err(format!(
                    "`{raw}` is not `<forge-host>/<owner>` or `<forge-host>/<owner>/<repo>`"
                ));
            }
        };
        if !is_forge_host(forge) {
            return Err(format!(
                "`{forge}` is not a forge host; a resource always names its forge \
                 (`github.com/acme`, never `acme`)"
            ));
        }
        if !is_segment(owner) {
            return Err(format!("`{owner}` is not a valid owner name"));
        }
        if let Some(r) = repo
            && !is_segment(r)
        {
            return Err(format!("`{r}` is not a valid repository name"));
        }
        Ok(Resource {
            forge: forge.to_string(),
            owner: owner.to_string(),
            repo: repo.map(str::to_string),
        })
    }

    pub fn namespace(forge: &str, owner: &str) -> Resource {
        Resource {
            forge: forge.to_string(),
            owner: owner.to_string(),
            repo: None,
        }
    }

    pub fn is_namespace(&self) -> bool {
        self.repo.is_none()
    }

    /// The namespace resource this one lies in (itself, for a namespace).
    pub fn namespace_resource(&self) -> Resource {
        Resource::namespace(&self.forge, &self.owner)
    }

    /// With a repository name appended.
    pub fn child(&self, repo: &str) -> Resource {
        Resource {
            forge: self.forge.clone(),
            owner: self.owner.clone(),
            repo: Some(repo.to_string()),
        }
    }

    /// Fixed rule 1: containment by whole path segment. `github.com/acme`
    /// contains `github.com/acme/widgets` and itself; it does not contain
    /// `github.com/acme-labs/x` or `codeberg.org/acme/widgets`.
    ///
    /// The same rule, and the same function, the ACL gate uses for contexts —
    /// a second segment matcher here is a second place for the
    /// `acme`/`acme-labs` confusion to come back.
    pub fn contains(&self, other: &Resource) -> bool {
        vta_sdk::context_path::is_ancestor_or_self(&self.to_string(), &other.to_string())
    }
}

impl std::fmt::Display for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.repo {
            Some(r) => write!(f, "{}/{}/{}", self.forge, self.owner, r),
            None => write!(f, "{}/{}", self.forge, self.owner),
        }
    }
}

/// `ForgeHost` in the shared schema: a lowercased DNS host with at least one
/// dot, no scheme, no port, no path.
pub fn is_forge_host(s: &str) -> bool {
    if s.len() < 3 || s.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// `Segment` in the shared schema: `^[a-z0-9_-][a-z0-9._-]*$`, 1–100 chars.
/// A leading `.` is refused, which rules out `.` and `..`.
pub fn is_segment(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    s.len() <= 100
        && (first.is_ascii_lowercase() || first.is_ascii_digit() || first == '_' || first == '-')
        && chars.all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-'
        })
}

/// How a namespace is operated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    /// The community's bridge holds forge credentials and carries out jobs.
    Bridge,
    /// No automation: repositories are set up by people, and adopted.
    Manual,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Bridge => "bridge",
            Mode::Manual => "manual",
        }
    }
}

/// Organisation or personal account, as the forge reported at binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OwnerKind {
    Organization,
    User,
}

impl OwnerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            OwnerKind::Organization => "organization",
            OwnerKind::User => "user",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NamespaceState {
    /// Waiting for the forge-side proof (bridge mode only).
    Pending,
    Bound,
}

/// The VTC's binding to one owner on one forge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Namespace {
    pub id: String,
    pub forge: String,
    pub owner: String,
    pub mode: Mode,
    pub state: NamespaceState,
    /// The forge's own id for the owner — survives a rename of the owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<OwnerKind>,
    /// The bridge that serves this namespace (bridge mode). Recorded at bind
    /// so a later change of configuration cannot silently hand an existing
    /// namespace to another bridge: results and events are accepted only from
    /// this DID (`git-ns/bridge/result`, `git-ns/bridge/event` — *Authorization*).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_did: Option<String>,
    /// The `beginBind` job whose `bindCompleted` event completes a pending
    /// binding. Cleared once bound, so a replayed completion finds nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_job_id: Option<String>,
    /// The administrator who asked to bind, who receives the first
    /// `git.ns.admin` when the binding completes.
    pub bound_by: String,
    pub requested_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<DateTime<Utc>>,
    /// Digest of the last namespace-level role set sent to the bridge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles_digest: Option<String>,
    /// The bridge reported it lost access to the namespace.
    #[serde(default)]
    pub installation_removed: bool,
    /// What the bridge last reported about its standing on the forge owner —
    /// see [`NamespaceForgeStatus`]. Absent until the bridge says anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forge_status: Option<NamespaceForgeStatus>,
}

/// The bridge's report of its own standing on a namespace's forge owner.
///
/// None of this is in the specification's event or result payloads; a bridge
/// carries it in their `ext` member under [`FORGE_REPORT_EXT`], and the VTC
/// keeps it only to show an administrator. It changes no right and no
/// decision. Every member is optional: a field the bridge has not reported is
/// absent, not `false`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceForgeStatus {
    /// The forge's installation of the community's app (GitHub).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_slug: Option<String>,
    /// Where the app's manifest registration stands (`registered`,
    /// `pending`, …), in the bridge's words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_registration: Option<String>,
    /// Permissions the app needs and the installation has not granted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_permissions: Vec<String>,
    /// A new app version asks for permissions the owner has not approved yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_upgrade_pending: Option<bool>,
    /// Organisation rulesets are available on the owner's plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_rulesets: Option<bool>,
    /// The org ruleset's required workflow (design §9) is in force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_workflow: Option<bool>,
    /// The bridge can post the verify-trust check itself (the fallback mode
    /// of design §9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_posted_check: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_at: Option<DateTime<Utc>>,
}

/// The `ext` key a bridge reports forge status under, in
/// `git-ns/bridge/result` and `git-ns/bridge/event`:
/// `{"namespace": NamespaceForgeStatus, "repo": RepoForgeReport}`.
pub const FORGE_REPORT_EXT: &str = "org.openvtc.git-ns";

/// The bridge's report on one repository beyond what the specification's
/// result carries.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoForgeReport {
    /// The guard actually in force against a pull request satisfying its own
    /// check (design §9): `requiredWorkflow`, `codeOwnerReview`,
    /// `bridgePostedCheck`, `protectedFiles`, or `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<String>,
    /// The last verify-trust check the bridge saw: `{conclusion, at, sha?}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_check: Option<Value>,
    /// The per-step outcomes of the last create, bootstrap or inspect job, as
    /// the bridge reported them (`{step, outcome, detail?}`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Value>,
}

impl Namespace {
    pub fn resource(&self) -> Resource {
        Resource::namespace(&self.forge, &self.owner)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Visibility {
    Public,
    Private,
}

impl Visibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Private => "private",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RepoState {
    PendingCreate,
    Active,
    Archived,
    Detached,
    Orphaned,
    Unmanaged,
}

impl RepoState {
    pub fn as_str(self) -> &'static str {
        match self {
            RepoState::PendingCreate => "pendingCreate",
            RepoState::Active => "active",
            RepoState::Archived => "archived",
            RepoState::Detached => "detached",
            RepoState::Orphaned => "orphaned",
            RepoState::Unmanaged => "unmanaged",
        }
    }

    /// Whether rights on a repository in this state are published to the
    /// registry. A reservation's owner is published only once it is active
    /// (`git-ns/repo/create`, step 4); an orphaned repository stays governed.
    pub fn publishes(self) -> bool {
        matches!(
            self,
            RepoState::Active | RepoState::Orphaned | RepoState::Archived
        )
    }
}

/// Whether each step that turns commit trust on is in place, as last reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bootstrap {
    pub workflow: bool,
    pub keyring: bool,
    pub variables: bool,
    pub required_check: bool,
}

impl Bootstrap {
    /// The forge-neutral step names that are not in place.
    pub fn missing_steps(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.workflow {
            out.push("workflow");
        }
        if !self.keyring {
            out.push("keyring");
        }
        if !self.variables {
            out.push("variables");
        }
        if !self.required_check {
            out.push("requiredCheck");
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SyncState {
    InSync,
    Drift,
    Pending,
    Unchecked,
}

impl SyncState {
    pub fn as_str(self) -> &'static str {
        match self {
            SyncState::InSync => "inSync",
            SyncState::Drift => "drift",
            SyncState::Pending => "pending",
            SyncState::Unchecked => "unchecked",
        }
    }
}

/// How the forge compares with the projection for one repository.
///
/// `drift` holds the bridge's items as it sent them — each one already a
/// `DriftItem` of the shared schema — so what an owner sees is what the bridge
/// reported, not a re-telling of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    pub state: SyncState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub drift: Vec<Value>,
}

impl SyncStatus {
    pub fn new(state: SyncState) -> Self {
        Self {
            state,
            checked_at: None,
            drift: Vec::new(),
        }
    }
}

/// One repository as the VTC records it.
///
/// Keyed by [`Self::id`], not by resource and not by forge id: the resource
/// changes when the forge renames the repository, and the forge id is unknown
/// until the bridge reports it. Rights hang off the id, so a rename moves them
/// with the repository, and a new repository later created at the old name is
/// a new id and inherits nothing (`git-ns/bridge/event`, `repoRenamed`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Repo {
    pub id: String,
    pub namespace_id: String,
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forge_id: Option<String>,
    pub visibility: Visibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub state: RepoState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub bootstrap: Bootstrap,
    pub sync: SyncStatus,
    /// The bootstrap step that failed on the last create or bootstrap job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_step: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Digest of the last role set sent to the bridge for this repository.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles_digest: Option<String>,
    /// What the bridge last reported beyond the specification's members.
    #[serde(default)]
    pub forge_report: RepoForgeReport,
}

impl Repo {
    pub fn resource(&self) -> Option<Resource> {
        Resource::parse(&self.resource).ok()
    }
}

/// One recorded right.
///
/// The resource is not stored on the row: it is the resource of the scope the
/// row lives under (a namespace, or a repository by id), so a repository's
/// rename moves every row at once and cannot leave one behind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RightRow {
    pub subject: String,
    pub right: Right,
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// The granter's free text. Shown only to owners and namespace admins of
    /// the resource (`git-ns/view`), never published, never audited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether the subject was a member of the community when the right was
    /// granted.
    ///
    /// What lets the departure sweep tell a member who left from an external
    /// signer the community chose to trust: both have no live member row
    /// afterwards, and only the first loses their rights (design §5.4). Read
    /// from this flag rather than from the audit log's plaintext DID, which an
    /// erasure nulls.
    #[serde(default)]
    pub subject_was_member: bool,
    /// Whether the granter was a member when they granted it — what lets the
    /// admin surface list *grants issued by departed members* for review, and
    /// what `cascade_on_departure` revokes (design §5.4).
    #[serde(default)]
    pub granter_was_member: bool,
}

impl RightRow {
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|e| e > now)
    }
}

/// Where a set of rights hangs: a namespace, or one repository.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "id")]
pub enum Scope {
    Namespace(String),
    Repo(String),
}

impl Scope {
    pub fn key(&self) -> String {
        match self {
            Scope::Namespace(id) => format!("ns:{id}"),
            Scope::Repo(id) => format!("repo:{id}"),
        }
    }
}

/// Every right recorded on one scope, as one row, so a change that touches
/// several of them — a transfer is a grant and a revoke — is one write.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RightsSet {
    #[serde(default)]
    pub rows: Vec<RightRow>,
}

/// A member's account on one forge, as the bridge reported it.
/// `id` is authoritative; `login` is for display only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForgeAccount {
    pub forge: String,
    pub id: String,
    pub login: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LinkState {
    Pending,
    Linked,
    Expired,
    Failed,
}

impl LinkState {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkState::Pending => "pending",
            LinkState::Linked => "linked",
            LinkState::Expired => "expired",
            LinkState::Failed => "failed",
        }
    }
}

/// One attempt to link a member's forge account (`git-ns/account/link`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkAttempt {
    pub id: String,
    pub member: String,
    pub forge: String,
    pub namespace_id: String,
    pub job_id: String,
    pub state: LinkState,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<ForgeAccount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
}

/// A fresh opaque identifier with a readable prefix (`ns_…`, `repo_…`).
/// A DID as DID-core's ABNF has it, and nothing else — see
/// [`vta_sdk::identifier::validate_did_core`], which `cnm` applies too.
/// Stricter than the `git-ns/_shared` schema's `Did` pattern
/// (`^did:[a-z0-9]+:\S+$`), which admits shell metacharacters.
pub fn validate_did_core(label: &str, value: &str) -> Result<(), String> {
    vta_sdk::identifier::validate_did_core(label, value).map_err(|e| e.0)
}

pub fn new_id(prefix: &str) -> String {
    let u = uuid::Uuid::new_v4().simple().to_string();
    format!("{prefix}_{}", &u[..20])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_resource_names_its_forge() {
        assert!(Resource::parse("acme/widgets").is_err());
        assert!(Resource::parse("acme").is_err());
        let r = Resource::parse("github.com/acme/widgets").unwrap();
        assert_eq!(r.forge, "github.com");
        assert_eq!(r.owner, "acme");
        assert_eq!(r.repo.as_deref(), Some("widgets"));
        assert_eq!(r.to_string(), "github.com/acme/widgets");
    }

    #[test]
    fn a_mixed_case_resource_is_refused_not_normalised() {
        assert!(Resource::parse("github.com/Acme/widgets").is_err());
        assert!(Resource::parse("GitHub.com/acme").is_err());
    }

    #[test]
    fn a_dot_segment_is_refused() {
        assert!(Resource::parse("github.com/acme/..").is_err());
        assert!(Resource::parse("github.com/./x").is_err());
        assert!(Resource::parse("github.com/acme/x/y").is_err());
    }

    #[test]
    fn containment_is_by_whole_segment_and_never_crosses_forges() {
        let ns = Resource::parse("github.com/acme").unwrap();
        assert!(ns.contains(&Resource::parse("github.com/acme/widgets").unwrap()));
        assert!(ns.contains(&ns));
        assert!(!ns.contains(&Resource::parse("github.com/acme-labs/x").unwrap()));
        assert!(!ns.contains(&Resource::parse("codeberg.org/acme/widgets").unwrap()));
        let repo = Resource::parse("github.com/acme/widgets").unwrap();
        assert!(
            !repo.contains(&ns),
            "a repository does not contain its namespace"
        );
        assert!(!repo.contains(&Resource::parse("github.com/acme/widgets-core").unwrap()));
    }

    #[test]
    fn rights_carry_their_wire_spelling() {
        for r in Right::ALL {
            assert_eq!(Right::parse(r.as_str()), Some(r));
            assert_eq!(
                serde_json::to_value(r).unwrap(),
                serde_json::json!(r.as_str())
            );
        }
    }
}
