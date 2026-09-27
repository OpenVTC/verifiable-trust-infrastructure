//! The administrator's reads over the community's git namespaces, as signed
//! Trust Tasks — what the admin console's *Repos* plugin and `cnm git`'s
//! listings render:
//!
//! - `git-ns/namespace/list/0.1` — the administered namespaces, with their
//!   admins, bridge, role map and forge status ([`namespace_list`]);
//! - `git-ns/repo/list/0.1` — the repositories in them, with owners, right
//!   counts, bootstrap, sync and the bridge's report ([`repo_list`]);
//! - `git-ns/view/0.5` — `git-ns/view` with `scope: administrator` (every
//!   record and reason in the administered namespaces) and `breakGlass: true`
//!   (only break-glass records) ([`view_v5`]).
//!
//! They replace the bearer-authenticated `GET /v1/git-ns/{namespaces,repos,
//! view,break-glass}` console views, which answered any admin session — a
//! context-scoped administrator included — with every namespace, and carried
//! no proof of who asked. Each is served on the document dispatcher the same
//! way over TSP, DIDComm and HTTPS (`super::tasks`).
//!
//! # Who is answered
//!
//! A namespace's administrators: the community-administrator capability
//! (every namespace) or a live, explicitly recorded `git.ns.admin` on it, held
//! by a current member. Nothing else — not `git.repo.own`, not an admin role
//! scoped to some contexts. A caller who administers no namespace, or who
//! names one they do not administer or one that does not exist, is refused
//! with the task's `notAdministrator`, the same way in all three cases.
//!
//! # Stand-ins
//!
//! TODO(trust-tasks release carrying trust-tasks #659): replace the three
//! `*_v0_*` modules below with the generated
//! `trust_tasks_rs::specs::git_ns::{view::v0_5, namespace::list::v0_1,
//! repo::list::v0_1}` (their `Payload`s, `Response`s and `error_codes`), drop
//! the `spec/git-ns/` entry from `UNPUBLISHED_CANONICAL_OK` in
//! `tests/trust_task_manifest.rs`, and type the console's reads from the
//! published `@openvtc/trust-tasks` binding. Until then this build's registry
//! cannot declare the proof requirement to the spine, so every handler refuses
//! an unsigned document itself (`super::tasks::signer`), and each stand-in
//! declares it on its own `Payload` impl as well.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::Value;
use trust_tasks_rs::specs::git_ns::view::v0_4 as view4;

use super::model::{RepoState, Resource, Right, Scope};
use super::ops::{self, OpError, OpResult, declared, now};
use super::store::Snapshot;
use super::{lifecycle, role_map, rules, view, wire};
use crate::server::AppState;

/// The framework `Ext` rule on a stand-in payload: at least one member, each
/// key a reverse-DNS namespace — what the generated `Ext` newtype checks.
type Ext = view4::Ext;

/// `git-ns/view/0.5`. Hand-written until trust-tasks-rs publishes #659.
pub mod view_v0_5 {
    use serde::{Deserialize, Serialize};

    /// The bare type URI.
    pub const TYPE_URI: &str = "https://trusttasks.org/spec/git-ns/view/0.5";

    /// The codes the specification declares.
    pub mod error_codes {
        /// `scope: administrator`, and the caller administers no namespace
        /// within `resource` — answered alike for one that does not exist.
        pub const NOT_ADMINISTRATOR: &str = "git-ns/view:notAdministrator";
    }

    /// `scope`: which entitlement answers.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub enum Scope {
        #[default]
        Member,
        Administrator,
    }

    /// The request payload: 0.4's, plus `scope` and `breakGlass`.
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct Payload {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<super::view4::Resource>,
        #[serde(default)]
        pub scope: Scope,
        #[serde(default)]
        pub break_glass: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ext: Option<super::Ext>,
    }

    impl trust_tasks_rs::Payload for Payload {
        const TYPE_URI: &'static str = TYPE_URI;
        const IS_PROOF_REQUIRED: bool = true;
        const IS_RECIPIENT_REQUIRED: bool = true;
    }

    /// The response is 0.4's, unchanged.
    pub type Response = super::view4::Response;
}

/// `git-ns/namespace/list/0.1`. Hand-written until trust-tasks-rs publishes
/// #659.
pub mod namespace_list_v0_1 {
    use serde::{Deserialize, Serialize};

    /// The bare type URI.
    pub const TYPE_URI: &str = "https://trusttasks.org/spec/git-ns/namespace/list/0.1";

    /// The codes the specification declares.
    pub mod error_codes {
        /// The caller administers no namespace, or not the one named, or it
        /// does not exist.
        pub const NOT_ADMINISTRATOR: &str = "git-ns/namespace/list:notAdministrator";
    }

    /// The request payload.
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct Payload {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub namespace: Option<super::view4::NamespaceId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ext: Option<super::Ext>,
    }

    impl trust_tasks_rs::Payload for Payload {
        const TYPE_URI: &'static str = TYPE_URI;
        const IS_PROOF_REQUIRED: bool = true;
        const IS_RECIPIENT_REQUIRED: bool = true;
    }

    /// The response payload.
    pub type Response = super::GitNsNamespaceList;
}

/// `git-ns/repo/list/0.1`. Hand-written until trust-tasks-rs publishes #659.
pub mod repo_list_v0_1 {
    use serde::{Deserialize, Serialize};

    /// The bare type URI.
    pub const TYPE_URI: &str = "https://trusttasks.org/spec/git-ns/repo/list/0.1";

    /// The codes the specification declares.
    pub mod error_codes {
        /// The caller administers no namespace, or not the one named, or it
        /// does not exist.
        pub const NOT_ADMINISTRATOR: &str = "git-ns/repo/list:notAdministrator";
    }

    /// The request payload.
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct Payload {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub namespace: Option<super::view4::NamespaceId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ext: Option<super::Ext>,
    }

    impl trust_tasks_rs::Payload for Payload {
        const TYPE_URI: &'static str = TYPE_URI;
        const IS_PROOF_REQUIRED: bool = true;
        const IS_RECIPIENT_REQUIRED: bool = true;
    }

    /// The response payload.
    pub type Response = super::GitNsRepoList;
}

// ── response bodies ─────────────────────────────────────────────────────────
//
// Registered as OpenAPI components (`routes::openapi_spec`) although no route
// returns them, so the console's wire types stay generated from the daemon.

/// One namespace, as the console's Namespaces card shows it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsNamespaceRow {
    pub id: String,
    pub forge: String,
    pub owner: String,
    /// `github.com/acme`.
    pub resource: String,
    /// `bridge` | `manual`.
    pub mode: String,
    /// `pending` | `bound`.
    pub state: String,
    /// `organization` | `user`, once the forge has said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    /// The bridge that serves it (bridge mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bridge_did: Option<String>,
    /// The administrator who bound it.
    pub bound_by: String,
    pub requested_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<String>,
    /// Its explicit `git.ns.admin` holders — every one of them can grant
    /// anything in the namespace.
    pub admins: Vec<String>,
    pub repo_count: usize,
    /// Bound, with no live admin: its last admin left or lapsed. Nobody can
    /// grant in it until it is unbound and bound again.
    pub headless: bool,
    /// The bridge reported losing its access to the forge owner.
    pub installation_removed: bool,
    /// What the bridge last reported about its app and the owner's plan —
    /// absent until it reports. Display only; it changes no decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forge_status: Option<GitNsForgeStatus>,
    /// The active policy's `role_drift` setting in effect: `report` or
    /// `enforce`.
    pub role_drift: String,
    /// The active policy's `cascade_on_departure` setting in effect.
    pub cascade_on_departure: bool,
    /// The forge role each right projects to on a repository without a map
    /// of its own, as the bridge serving the namespace reported it
    /// (`git-ns/bridge/event/0.3` `roleMapReported`). Absent while it has not
    /// reported: no map, the default included, is assumed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_map: Option<GitNsRoleMap>,
    /// `reported` — the bridge serving the namespace said so; `unknown` — it
    /// has not reported since the namespace was bound or came to be served by
    /// it (or it predates event 0.3). While unknown, drift adoption is
    /// refused (`git-ns:roleMapUnknown`) and every role revert is weighed as
    /// revoking `git.repo.own`.
    pub role_map_source: String,
    /// The `issuedAt` of the report held, on the bridge's clock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_map_reported_at: Option<String>,
}

/// Which forge role `git.repo.own`, `git.repo.maintain` and
/// `git.commit.sign` project to — `none`, `read`, `triage`, `write`,
/// `maintain` or `admin`, as the forge applies it. `git.ns.admin` projects to
/// no forge role under any map.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GitNsRoleMap {
    pub own: String,
    pub maintain: String,
    pub commit: String,
}

impl From<crate::git_ns::role_map::RoleMap> for GitNsRoleMap {
    fn from(m: crate::git_ns::role_map::RoleMap) -> Self {
        GitNsRoleMap {
            own: m.own.as_str().to_string(),
            maintain: m.maintain.as_str().to_string(),
            commit: m.commit.as_str().to_string(),
        }
    }
}

/// The bridge's report of its standing on a namespace's forge owner, carried
/// in the `ext` member (`org.openvtc.git-ns`) of its results and events.
/// Every field is absent until the bridge reports it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsForgeStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_slug: Option<String>,
    /// The app's manifest registration state, in the bridge's words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_registration: Option<String>,
    /// Permissions the app needs and the installation lacks.
    pub missing_permissions: Vec<String>,
    /// A new app version awaits the owner's approval of more permissions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_upgrade_pending: Option<bool>,
    /// Organisation rulesets are available on the owner's plan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_rulesets: Option<bool>,
    /// The org ruleset's required workflow is in force (design §9).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_workflow: Option<bool>,
    /// The bridge can post the verify-trust check itself (fallback mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bridge_posted_check: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_at: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GitNsNamespaceList {
    pub namespaces: Vec<GitNsNamespaceRow>,
}

/// Whether each step that turns commit trust on is in place.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsBootstrapStatus {
    pub workflow: bool,
    pub keyring: bool,
    pub variables: bool,
    pub required_check: bool,
}

/// One repository, as the console's Repos table shows it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsRepoRow {
    pub id: String,
    pub namespace: String,
    pub resource: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forge_id: Option<String>,
    /// `public` | `private`.
    pub visibility: String,
    /// `pendingCreate` | `active` | `archived` | `detached` | `orphaned` |
    /// `unmanaged`.
    pub state: String,
    pub owners: Vec<String>,
    pub maintainers: usize,
    pub committers: usize,
    pub bootstrap: GitNsBootstrapStatus,
    /// `inSync` | `drift` | `pending` | `unchecked`.
    pub sync_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
    pub drift_count: usize,
    /// The step that failed on the last create or bootstrap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_step: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    pub created_at: String,
    /// The guard actually in force against a pull request satisfying its own
    /// check, as the bridge last reported it: `requiredWorkflow`,
    /// `codeOwnerReview`, `bridgePostedCheck`, `protectedFiles` or `none`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard: Option<String>,
    /// Per-step outcomes of the last create, bootstrap or inspect job.
    pub steps: Vec<GitNsStepOutcome>,
    /// The last verify-trust check run the bridge saw.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_check: Option<GitNsLastCheck>,
    /// The forge role each right projects to on this repository, under the
    /// bridge's reported map. Absent while the namespace's map is unknown
    /// (`roleMapSource`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_map: Option<GitNsRoleMap>,
    /// The bridge last projected this repository's roles under an earlier
    /// role map; a re-projection is queued and has not yet succeeded.
    pub role_map_stale: bool,
}

/// One bootstrap step's outcome, as the bridge reported it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsStepOutcome {
    pub step: String,
    /// `applied` | `unchanged` | `failed` | `skipped`.
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The last verify-trust check run the bridge saw on a repository.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GitNsLastCheck {
    /// In the forge's words (`success`, `failure`).
    pub conclusion: String,
    pub at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GitNsRepoList {
    pub repos: Vec<GitNsRepoRow>,
}

// ── who administers what ────────────────────────────────────────────────────

/// The namespaces a caller administers.
pub(crate) struct Administered {
    /// Holds the community-administrator capability: every namespace.
    pub community_admin: bool,
    /// The namespaces administered, by identifier.
    pub namespaces: BTreeSet<String>,
}

impl Administered {
    fn none(&self) -> bool {
        !self.community_admin && self.namespaces.is_empty()
    }
}

/// Who `did` administers, from the VTC's own records at this instant: every
/// namespace for a community administrator; otherwise those on which they
/// hold a live, explicitly recorded `git.ns.admin`. A departed or non-member
/// DID administers nothing, whatever records name it.
pub(crate) async fn administered(
    state: &AppState,
    snap: &Snapshot,
    did: &str,
) -> OpResult<Administered> {
    let caller = ops::standing(state, did).await?;
    if !caller.member {
        return Ok(Administered {
            community_admin: false,
            namespaces: BTreeSet::new(),
        });
    }
    let t = now();
    let namespaces = snap
        .namespaces
        .iter()
        .filter(|n| {
            caller.community_admin || rules::admins(snap, &n.id, t).iter().any(|a| a == did)
        })
        .map(|n| n.id.clone())
        .collect();
    Ok(Administered {
        community_admin: caller.community_admin,
        namespaces,
    })
}

/// The namespaces a listing covers: the caller's administered ones, or the
/// one named — which must be among them. `code` is the task's
/// `notAdministrator`.
fn covered(
    admin: &Administered,
    named: Option<&str>,
    code: &'static str,
) -> OpResult<BTreeSet<String>> {
    if admin.none() {
        return Err(declared(
            code,
            "this lists the namespaces you administer, and you administer none: it needs the \
             community-administrator capability or git.ns.admin on a namespace",
        ));
    }
    match named {
        None => Ok(admin.namespaces.clone()),
        Some(n) if admin.namespaces.contains(n) => Ok(std::iter::once(n.to_string()).collect()),
        Some(n) => Err(declared(
            code,
            format!("you do not administer a namespace `{n}`"),
        )),
    }
}

/// `s`, cut to at most `max` characters: the specification bounds every
/// free-text member, and the bridge's report is stored as it was sent.
fn bounded(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn bounded_opt(s: Option<&String>, max: usize) -> Option<String> {
    s.map(|s| bounded(s, max)).filter(|s| !s.is_empty())
}

// ── git-ns/namespace/list/0.1 ───────────────────────────────────────────────

/// `git-ns/namespace/list/0.1`.
pub(crate) async fn namespace_list(
    state: &AppState,
    actor: &str,
    p: namespace_list_v0_1::Payload,
) -> OpResult<GitNsNamespaceList> {
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let admin = administered(state, &snap, actor).await?;
    let named = p.namespace.map(String::from);
    let covered = covered(
        &admin,
        named.as_deref(),
        namespace_list_v0_1::error_codes::NOT_ADMINISTRATOR,
    )?;
    let t = now();
    let headless = lifecycle::headless(&snap);
    let settings = crate::git_ns::policy::active_settings(state).await;
    let role_drift = if settings.enforce_role_drift {
        "enforce"
    } else {
        "report"
    };
    let mut namespaces: Vec<GitNsNamespaceRow> = snap
        .namespaces
        .iter()
        .filter(|ns| covered.contains(&ns.id))
        .map(|ns| {
            let v = wire::namespace(ns);
            let ns_map_source = role_map::source(ns);
            GitNsNamespaceRow {
                id: ns.id.clone(),
                forge: ns.forge.clone(),
                owner: ns.owner.clone(),
                resource: ns.resource().to_string(),
                mode: ns.mode.as_str().to_string(),
                state: v["state"].as_str().unwrap_or_default().to_string(),
                kind: ns.kind.map(|k| k.as_str().to_string()),
                owner_id: ns.owner_id.clone(),
                bridge_did: ns.bridge_did.clone(),
                bound_by: ns.bound_by.clone(),
                requested_at: wire::timestamp(ns.requested_at),
                bound_at: ns.bound_at.map(wire::timestamp),
                admins: rules::admins(&snap, &ns.id, t),
                repo_count: snap
                    .repos
                    .iter()
                    .filter(|r| r.namespace_id == ns.id)
                    .count(),
                headless: headless.contains(&ns.id),
                installation_removed: ns.installation_removed,
                forge_status: ns.forge_status.as_ref().map(|s| GitNsForgeStatus {
                    installation_id: bounded_opt(s.installation_id.as_ref(), 64),
                    app_name: bounded_opt(s.app_name.as_ref(), 256),
                    app_slug: bounded_opt(s.app_slug.as_ref(), 256),
                    app_registration: bounded_opt(s.app_registration.as_ref(), 256),
                    missing_permissions: s
                        .missing_permissions
                        .iter()
                        .filter(|p| !p.is_empty())
                        .map(|p| bounded(p, 128))
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .take(256)
                        .collect(),
                    permission_upgrade_pending: s.permission_upgrade_pending,
                    org_rulesets: s.org_rulesets,
                    required_workflow: s.required_workflow,
                    bridge_posted_check: s.bridge_posted_check,
                    reported_at: s.reported_at.map(wire::timestamp),
                }),
                role_drift: role_drift.to_string(),
                cascade_on_departure: settings.cascade_on_departure,
                role_map: role_map::for_namespace(ns).map(Into::into),
                role_map_source: ns_map_source.as_str().to_string(),
                role_map_reported_at: role_map::current_report(ns)
                    .map(|r| wire::timestamp(r.issued_at)),
            }
        })
        .collect();
    namespaces.sort_by(|a, b| a.resource.cmp(&b.resource));
    Ok(GitNsNamespaceList { namespaces })
}

// ── git-ns/repo/list/0.1 ────────────────────────────────────────────────────

/// `git-ns/repo/list/0.1`.
pub(crate) async fn repo_list(
    state: &AppState,
    actor: &str,
    p: repo_list_v0_1::Payload,
) -> OpResult<GitNsRepoList> {
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let admin = administered(state, &snap, actor).await?;
    let named = p.namespace.map(String::from);
    let covered = covered(
        &admin,
        named.as_deref(),
        repo_list_v0_1::error_codes::NOT_ADMINISTRATOR,
    )?;
    // A community administrator's whole listing also carries the repositories
    // an unbound namespace left behind: nobody else administers those.
    let orphans = admin.community_admin && named.is_none();
    let t = now();
    let mut repos: Vec<GitNsRepoRow> = snap
        .repos
        .iter()
        .filter(|r| {
            covered.contains(&r.namespace_id)
                || (orphans && snap.namespace(&r.namespace_id).is_none())
        })
        .map(|r| {
            let rows = snap.rows(&Scope::Repo(r.id.clone()));
            let count = |right: Right| {
                rows.iter()
                    .filter(|x| x.right == right && x.is_live(t))
                    .count()
            };
            GitNsRepoRow {
                id: r.id.clone(),
                namespace: r.namespace_id.clone(),
                resource: r.resource.clone(),
                forge_id: r.forge_id.clone(),
                visibility: r.visibility.as_str().to_string(),
                state: r.state.as_str().to_string(),
                owners: rules::owners(&snap, &r.id, t),
                maintainers: count(Right::RepoMaintain),
                committers: count(Right::CommitSign),
                bootstrap: GitNsBootstrapStatus {
                    workflow: r.bootstrap.workflow,
                    keyring: r.bootstrap.keyring,
                    variables: r.bootstrap.variables,
                    required_check: r.bootstrap.required_check,
                },
                sync_state: r.sync.state.as_str().to_string(),
                checked_at: r.sync.checked_at.map(wire::timestamp),
                drift_count: r.sync.drift.len(),
                failed_step: bounded_opt(r.failed_step.as_ref(), 64),
                last_error: bounded_opt(r.last_error.as_ref(), 4096),
                created_by: r.created_by.clone(),
                created_at: wire::timestamp(r.created_at),
                guard: bounded_opt(r.forge_report.guard.as_ref(), 64),
                steps: r
                    .forge_report
                    .steps
                    .iter()
                    .filter_map(|s| {
                        let step = s["step"].as_str().filter(|x| !x.is_empty())?;
                        let outcome = s["outcome"].as_str().filter(|x| !x.is_empty())?;
                        Some(GitNsStepOutcome {
                            step: bounded(step, 64),
                            outcome: bounded(outcome, 32),
                            detail: s
                                .get("detail")
                                .and_then(Value::as_str)
                                .filter(|d| !d.is_empty())
                                .map(|d| bounded(d, 4096)),
                        })
                    })
                    .take(64)
                    .collect(),
                last_check: r.forge_report.last_check.as_ref().and_then(last_check),
                role_map: snap
                    .namespace(&r.namespace_id)
                    .and_then(|ns| role_map::for_repo(ns, &r.resource))
                    .map(Into::into),
                role_map_stale: matches!(r.state, RepoState::Active | RepoState::Orphaned)
                    && snap
                        .namespace(&r.namespace_id)
                        .is_some_and(|ns| role_map::is_stale(ns, &r.resource)),
            }
        })
        .collect();
    repos.sort_by(|a, b| a.resource.cmp(&b.resource));
    Ok(GitNsRepoList { repos })
}

/// The bridge's `lastCheck` report, as the specification's `LastCheck` — or
/// nothing, where it lacks a conclusion or a time.
fn last_check(v: &Value) -> Option<GitNsLastCheck> {
    let s = |k: &str| v.get(k).and_then(Value::as_str).filter(|x| !x.is_empty());
    Some(GitNsLastCheck {
        conclusion: bounded(s("conclusion")?, 64),
        at: s("at")?.to_string(),
        sha: s("sha").map(|x| bounded(x, 64)),
    })
}

// ── git-ns/view/0.5 ─────────────────────────────────────────────────────────

/// `git-ns/view/0.5`: 0.4's member view, or with `scope: administrator`
/// every record in the namespaces the caller administers; either narrowed to
/// break-glass records with `breakGlass: true`.
pub(crate) async fn view_v5(
    state: &AppState,
    actor: &str,
    p: view_v0_5::Payload,
) -> OpResult<view_v0_5::Response> {
    let standing = ops::standing(state, actor).await?;
    if !standing.member {
        return Err(OpError::PermissionDenied(
            "git-ns/view answers members of this community".into(),
        ));
    }
    let filter = match &p.resource {
        Some(r) => Some(Resource::parse(&r.to_string()).map_err(OpError::Malformed)?),
        None => None,
    };
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let member = crate::members::get_member(&state.members_ks, actor).await?;
    let mut v = match p.scope {
        view_v0_5::Scope::Member => view::member_v4(
            &snap,
            actor,
            standing.community_admin,
            filter.as_ref(),
            member.as_ref(),
        ),
        view_v0_5::Scope::Administrator => {
            let admin = administered(state, &snap, actor).await?;
            let within = if admin.community_admin {
                None
            } else {
                let related = |n: &Resource| {
                    filter
                        .as_ref()
                        .is_none_or(|f| f.contains(n) || n.contains(f))
                };
                let any = snap
                    .namespaces
                    .iter()
                    .any(|n| admin.namespaces.contains(&n.id) && related(&n.resource()));
                if !any {
                    return Err(declared(
                        view_v0_5::error_codes::NOT_ADMINISTRATOR,
                        "scope: administrator answers for the namespaces you administer, and you \
                         administer none within this resource",
                    ));
                }
                Some(admin.namespaces)
            };
            view::administrator_v5(&snap, within.as_ref(), filter.as_ref(), member.as_ref())
        }
    };
    if p.break_glass {
        view::narrow_to_break_glass(&mut v);
    }
    Ok(wire::into(v)?)
}
