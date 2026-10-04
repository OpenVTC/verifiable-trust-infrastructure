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
//!   (only break-glass records) ([`view_v5`]);
//! - `git-ns/right/list/0.1` — every right the VTC knows of, recorded and
//!   role-derived, across every namespace ([`right_list`]);
//! - `git-ns/right/issued-by-departed/0.1` — recorded rights whose granter has
//!   since left, grouped by granter ([`right_issued_by_departed`]);
//! - `git-ns/bridge/job/list/0.1` and `0.2` — bridge jobs in the namespaces the caller
//!   administers, with kind, queue state and last error
//!   ([`bridge_job_list`]);
//! - `git-ns/projection/show/0.1` — what is published to the Trust Registry,
//!   and how many records the next reconciliation pass will change
//!   ([`projection_show`]);
//! - `git-ns/account/list/0.1` — every member's linked forge account,
//!   community-wide ([`account_list`]);
//! - `git-ns/activity/list/0.1` — rights changes, drift and bridge jobs in the
//!   namespaces the caller administers, newest first ([`activity_list`]).
//!
//! They replace the bearer-authenticated `GET /v1/git-ns/{namespaces,repos,
//! view,break-glass,rights,rights/issued-by-departed,jobs,projection,
//! accounts,activity}` console views, which answered any admin session — a
//! context-scoped administrator included — with every namespace (or, for the
//! four community-administrator-only reads, an admin session scoped to any
//! context at all), and carried no proof of who asked. Each is served on the
//! document dispatcher the same way over TSP, DIDComm and HTTPS
//! (`super::tasks`).
//!
//! # Who is answered
//!
//! `right/list`, `right/issued-by-departed`, `projection/show` and
//! `account/list` answer the community-administrator capability alone: each
//! spans every namespace and, for the rights reads, every granter's reason, so
//! holding `git.ns.admin` on some namespace is not enough (their own
//! specifications say so explicitly). A caller who lacks the capability is
//! refused with the task's `notCommunityAdministrator`.
//!
//! `bridge/job/list` and `activity/list`, like `namespace/list` and
//! `repo/list`, answer a namespace's administrators: the community-
//! administrator capability (every namespace) or a live, explicitly recorded
//! `git.ns.admin` on it, held by a current member. A caller who administers
//! no namespace, or who names one they do not administer or one that does not
//! exist, is refused with the task's `notAdministrator`, the same way in all
//! three cases.
//!
//! # Paging
//!
//! Every one of these six listings clamps `limit` to 1..=500 (default 100)
//! and pages by an opaque `cursor` — the offset of the next item, bound to a
//! short digest of the request's own filters ([`filter_tag`]) so that a
//! request which changes a filter mid-page is refused with `malformedRequest`
//! rather than silently reinterpreted, as each specification's *Request*
//! section requires.
//!
//! # Generated types
//!
//! `view_v0_5`, `namespace_list_v0_1`, `repo_list_v0_1`, `right_list_v0_1`,
//! `right_issued_by_departed_v0_1`, `bridge_job_list_v0_1`,
//! `projection_show_v0_1`, `account_list_v0_1` and `activity_list_v0_1` are
//! the generated `trust_tasks_rs::specs::git_ns::*` modules (trust-tasks-rs
//! 0.23.4 for the first three, trustoverip/dtgwg-trust-tasks-tf#659; 0.24.7
//! for the other six, trustoverip/dtgwg-trust-tasks-tf#686): their `Payload`s
//! already declare the proof REQUIRED, so the dispatch spine refuses an
//! unsigned document before a handler runs — no handler-level refusal is
//! needed here. Each op still builds the console's own row types (registered
//! as OpenAPI components below, for the admin-ui's generated wire types) and
//! converts them into the generated `Response` through [`wire::into`], the
//! same way `view_v5` already did for 0.4.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use serde_json::{Value, json};
pub(crate) use trust_tasks_rs::specs::git_ns::account::list::v0_1 as account_list_v0_1;
pub(crate) use trust_tasks_rs::specs::git_ns::activity::list::v0_1 as activity_list_v0_1;
pub(crate) use trust_tasks_rs::specs::git_ns::bridge::job::list::v0_1 as bridge_job_list_v0_1;
pub(crate) use trust_tasks_rs::specs::git_ns::bridge::job::list::v0_2 as bridge_job_list_v0_2;
pub(crate) use trust_tasks_rs::specs::git_ns::namespace::list::v0_1 as namespace_list_v0_1;
pub(crate) use trust_tasks_rs::specs::git_ns::projection::show::v0_1 as projection_show_v0_1;
pub(crate) use trust_tasks_rs::specs::git_ns::repo::list::v0_1 as repo_list_v0_1;
pub(crate) use trust_tasks_rs::specs::git_ns::right::issued_by_departed::v0_1 as right_issued_by_departed_v0_1;
pub(crate) use trust_tasks_rs::specs::git_ns::right::list::v0_1 as right_list_v0_1;
use trust_tasks_rs::specs::git_ns::view::v0_4 as view4;
pub(crate) use trust_tasks_rs::specs::git_ns::view::v0_5 as view_v0_5;

use super::bridge::{self, BridgeJob};
use super::model::{RepoState, Resource, Right, RightRow, Scope};
use super::ops::{self, OpError, OpResult, declared, now, standing};
use super::store::Snapshot;
use super::{lifecycle, projection, role_map, rules, view, wire};
use crate::server::AppState;

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

// ── paging ───────────────────────────────────────────────────────────────

/// Every filter a request to one of the six community-administrator and
/// administrator listings carries besides `cursor`, `limit` and `ext` —
/// serialized to whatever shape the caller chooses (usually `json!({...})`
/// naming each filter member) and reduced to a short digest by
/// [`filter_tag`]. A cursor is bound to that digest, so a request that
/// changes a filter mid-page fails [`page_of`] rather than silently paging
/// through a different answer.
const CURSOR_PREFIX: &str = "offset:";

/// A short digest of `filters`, stable across calls with the same JSON.
fn filter_tag(filters: &Value) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(filters).unwrap_or_default();
    hex::encode(&Sha256::digest(&bytes)[..8])
}

fn encode_cursor(offset: usize, tag: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{CURSOR_PREFIX}{offset}:{tag}"))
}

fn cursor_refused() -> OpError {
    OpError::Malformed("cursor is not one this listing issued for these filters".into())
}

fn decode_cursor(cursor: &str, tag: &str) -> Result<usize, OpError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| cursor_refused())?;
    let text = String::from_utf8(bytes).map_err(|_| cursor_refused())?;
    let rest = text
        .strip_prefix(CURSOR_PREFIX)
        .ok_or_else(cursor_refused)?;
    let (digits, bound) = rest.split_once(':').ok_or_else(cursor_refused)?;
    if bound != tag
        || digits.is_empty()
        || digits.len() > 9
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(cursor_refused());
    }
    digits.parse().map_err(|_| cursor_refused())
}

/// One page of `items`, already in the order the specification wants, bound
/// to `filters` by [`filter_tag`]. Every task in this family clamps `limit`
/// to 1..=500 (default 100).
fn page_of<T>(
    mut items: Vec<T>,
    filters: &Value,
    cursor: Option<&str>,
    limit: Option<std::num::NonZeroU64>,
) -> Result<(Vec<T>, Option<String>), OpError> {
    let tag = filter_tag(filters);
    let start = match cursor {
        Some(c) => decode_cursor(c, &tag)?,
        None => 0,
    };
    let total = items.len();
    if start > total {
        return Err(cursor_refused());
    }
    let limit = limit.map_or(100, |n| n.get().min(500)) as usize;
    let end = start.saturating_add(limit).min(total);
    let next = (end < total).then(|| encode_cursor(end, &tag));
    let page = items.drain(start..end).collect();
    Ok((page, next))
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
) -> OpResult<namespace_list_v0_1::Response> {
    let snap = Snapshot::load(&state.git_ns).await?;
    let admin = administered(state, &snap, actor).await?;
    let named = p.namespace.map(String::from);
    let covered = covered(
        &admin,
        named.as_deref(),
        namespace_list_v0_1::error_codes::NOT_ADMINISTRATOR.code,
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
    let list = GitNsNamespaceList { namespaces };
    Ok(wire::into(
        serde_json::to_value(&list).map_err(vti_common::error::AppError::from)?,
    )?)
}

// ── git-ns/repo/list/0.1 ────────────────────────────────────────────────────

/// `git-ns/repo/list/0.1`.
pub(crate) async fn repo_list(
    state: &AppState,
    actor: &str,
    p: repo_list_v0_1::Payload,
) -> OpResult<repo_list_v0_1::Response> {
    let snap = Snapshot::load(&state.git_ns).await?;
    let admin = administered(state, &snap, actor).await?;
    let named = p.namespace.map(String::from);
    let covered = covered(
        &admin,
        named.as_deref(),
        repo_list_v0_1::error_codes::NOT_ADMINISTRATOR.code,
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
    let list = GitNsRepoList { repos };
    Ok(wire::into(
        serde_json::to_value(&list).map_err(vti_common::error::AppError::from)?,
    )?)
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
) -> OpResult<view4::Response> {
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
    let snap = Snapshot::load(&state.git_ns).await?;
    let member = crate::members::get_member(&state.members_ks, actor).await?;
    let mut v = match p.scope.unwrap_or(view_v0_5::PayloadScope::Member) {
        view_v0_5::PayloadScope::Administrator => {
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
                        view_v0_5::error_codes::NOT_ADMINISTRATOR.code,
                        "scope: administrator answers for the namespaces you administer, and you \
                         administer none within this resource",
                    ));
                }
                Some(admin.namespaces)
            };
            view::administrator_v5(&snap, within.as_ref(), filter.as_ref(), member.as_ref())
        }
        // `member` (the schema's default), and any future variant this build
        // does not know: the narrowest reading, never administrator scope by
        // default.
        _ => view::member_v4(
            &snap,
            actor,
            standing.community_admin,
            filter.as_ref(),
            member.as_ref(),
        ),
    };
    if p.break_glass.unwrap_or(false) {
        view::narrow_to_break_glass(&mut v);
    }
    Ok(wire::into(v)?)
}

// ── git-ns/right/list/0.1 and git-ns/right/issued-by-departed/0.1 ──────────

/// One git right, recorded or role-derived — `AdminRightRow` of the shared
/// schema. Both tasks below produce it; only `git-ns/right/list` fills
/// `resource` outside a `DepartedGranter` grouping (the response schemas are
/// otherwise identical row for row).
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsRightRow {
    pub subject: String,
    pub right: String,
    pub resource: String,
    /// `recorded` — a `git-ns/*` record, governed by the rights model;
    /// `roleDerived` — a v0.1 `[hooks.git-trust] grant_on_role` grant,
    /// published by the hook relay and managed only through configuration.
    pub origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether the subject is a current member (an external signer is not).
    pub subject_member: bool,
    /// Whether the granter has since left the community.
    pub granter_departed: bool,
    /// Present exactly when the subject gave themselves this right through
    /// `git-ns/right/break-glass/0.1`. Unratified while `ratifiedBy` is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub break_glass: Option<GitNsBreakGlassMark>,
}

/// A record's `breakGlass` (`git-ns/_shared/0.5` `BreakGlass`).
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsBreakGlassMark {
    pub by: String,
    pub at: String,
    pub justification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratified_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratified_at: Option<String>,
}

impl From<&crate::git_ns::model::BreakGlassMark> for GitNsBreakGlassMark {
    fn from(b: &crate::git_ns::model::BreakGlassMark) -> Self {
        Self {
            by: b.by.clone(),
            at: wire::timestamp(b.at),
            justification: b.justification.clone(),
            effective_at: b.effective_at.map(wire::timestamp),
            ratified_by: b.ratified_by.clone(),
            ratified_at: b.ratified_at.map(wire::timestamp),
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsRightList {
    pub rights: Vec<GitNsRightRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// The grants one departed member issued.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsDepartedGranter {
    pub granter: String,
    pub rights: Vec<GitNsRightRow>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsDepartedGrants {
    /// Whether the active policy revokes these instead
    /// (`cascade_on_departure`). While it is off they stay, for review.
    pub cascade_on_departure: bool,
    pub granters: Vec<GitNsDepartedGranter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// A per-request cache of [`ops::standing`]'s `member` flag: `right/list` and
/// `right/issued-by-departed` each look up the same handful of DIDs (a row's
/// subject and its granter) over and over across every resource.
async fn member_cached(
    state: &AppState,
    cache: &mut BTreeMap<String, bool>,
    did: &str,
) -> Result<bool, OpError> {
    if let Some(m) = cache.get(did) {
        return Ok(*m);
    }
    let m = standing(state, did).await?.member;
    cache.insert(did.to_string(), m);
    Ok(m)
}

/// Render one recorded right, with the membership facts an administrator's
/// console shows.
async fn right_row(
    state: &AppState,
    cache: &mut BTreeMap<String, bool>,
    row: &RightRow,
    resource: &Resource,
) -> Result<GitNsRightRow, OpError> {
    let subject_member = member_cached(state, cache, &row.subject).await?;
    let granter_member = member_cached(state, cache, &row.granted_by).await?;
    Ok(GitNsRightRow {
        subject: row.subject.clone(),
        right: row.right.as_str().to_string(),
        resource: resource.to_string(),
        origin: "recorded".into(),
        granted_by: Some(row.granted_by.clone()),
        granted_at: Some(wire::timestamp(row.granted_at)),
        expires_at: row.expires_at.map(wire::timestamp),
        reason: row.reason.clone(),
        subject_member,
        granter_departed: row.granter_was_member && !granter_member,
        break_glass: row.break_glass.as_ref().map(Into::into),
    })
}

/// `git-ns/right/list/0.1`.
pub(crate) async fn right_list(
    state: &AppState,
    actor: &str,
    p: right_list_v0_1::Payload,
) -> OpResult<right_list_v0_1::Response> {
    let caller = ops::standing(state, actor).await?;
    if !caller.community_admin {
        return Err(declared(
            right_list_v0_1::error_codes::NOT_COMMUNITY_ADMINISTRATOR.code,
            "this lists every right the VTC knows of, across every namespace: it needs the \
             community-administrator capability, not git.ns.admin on a namespace",
        ));
    }
    let filter = match &p.resource {
        Some(r) => Some(Resource::parse(&r.to_string()).map_err(OpError::Malformed)?),
        None => None,
    };
    let subject = p.subject.as_ref().map(|s| s.to_string());
    let snap = Snapshot::load(&state.git_ns).await?;
    let t = now();
    let mut cache = BTreeMap::new();
    let mut rights = Vec::new();
    for (scope, set) in &snap.rights {
        let Some(res) = snap.scope_resource(scope) else {
            continue;
        };
        if filter.as_ref().is_some_and(|f| !f.contains(&res)) {
            continue;
        }
        // A break-glass record waiting out a policy delay is listed too: it
        // is exactly the one other administrators have a window to revoke.
        for row in set
            .rows
            .iter()
            .filter(|r| r.is_live(t) || (r.is_recorded(t) && r.break_glass.is_some()))
        {
            if subject.as_deref().is_some_and(|s| s != row.subject) {
                continue;
            }
            rights.push(right_row(state, &mut cache, row, &res).await?);
        }
    }
    // The v0.1 hook grants: shown so the console tells the whole story of who
    // may sign, marked as what they are — role-derived, and managed only
    // through `[hooks.git-trust] grant_on_role`, never through `git-ns/*`.
    let hooks = state.config.read().await.hooks.git_trust.clone();
    if let Some(cfg) = hooks {
        for entry in crate::acl::list_acl_entries(&state.acl_ks).await? {
            let Some(resource) = cfg.grant_on_role.get(&entry.role.to_string()) else {
                continue;
            };
            if subject.as_deref().is_some_and(|s| s != entry.did) {
                continue;
            }
            if let Some(f) = &filter
                && Resource::parse(resource).map(|r| f.contains(&r)) != Ok(true)
            {
                continue;
            }
            rights.push(GitNsRightRow {
                subject: entry.did.clone(),
                right: Right::CommitSign.as_str().to_string(),
                resource: resource.clone(),
                origin: "roleDerived".into(),
                granted_by: None,
                granted_at: None,
                expires_at: None,
                reason: None,
                subject_member: ops::standing(state, &entry.did).await?.member,
                granter_departed: false,
                break_glass: None,
            });
        }
    }
    rights.sort_by(|a, b| (&a.resource, &a.subject).cmp(&(&b.resource, &b.subject)));
    let filters =
        json!({ "resource": p.resource.as_ref().map(|r| r.to_string()), "subject": subject });
    let (page, next_cursor) = page_of(rights, &filters, p.cursor.as_deref(), p.limit)?;
    let list = GitNsRightList {
        rights: page,
        next_cursor,
    };
    Ok(wire::into(
        serde_json::to_value(&list).map_err(vti_common::error::AppError::from)?,
    )?)
}

/// `git-ns/right/issued-by-departed/0.1`.
pub(crate) async fn right_issued_by_departed(
    state: &AppState,
    actor: &str,
    p: right_issued_by_departed_v0_1::Payload,
) -> OpResult<right_issued_by_departed_v0_1::Response> {
    let caller = ops::standing(state, actor).await?;
    if !caller.community_admin {
        return Err(declared(
            right_issued_by_departed_v0_1::error_codes::NOT_COMMUNITY_ADMINISTRATOR.code,
            "a departed granter's surviving rights are not scoped to any namespace a caller \
             might administer: this needs the community-administrator capability",
        ));
    }
    let settings = crate::git_ns::policy::active_settings(state).await;
    let snap = Snapshot::load(&state.git_ns).await?;
    let mut cache = BTreeMap::new();
    let mut granters = Vec::new();
    for (granter, rows) in lifecycle::issued_by_departed(state).await? {
        let mut out = Vec::new();
        for (scope, row) in rows {
            if let Some(res) = snap.scope_resource(&scope) {
                out.push(right_row(state, &mut cache, &row, &res).await?);
            }
        }
        granters.push(GitNsDepartedGranter {
            granter,
            rights: out,
        });
    }
    let (page, next_cursor) = page_of(granters, &json!({}), p.cursor.as_deref(), p.limit)?;
    let grants = GitNsDepartedGrants {
        cascade_on_departure: settings.cascade_on_departure,
        granters: page,
        next_cursor,
    };
    Ok(wire::into(
        serde_json::to_value(&grants).map_err(vti_common::error::AppError::from)?,
    )?)
}

// ── git-ns/bridge/job/list/0.1 ──────────────────────────────────────────────

/// One bridge job, as the administrator's console shows it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsJobRow {
    pub job_id: String,
    pub namespace: String,
    pub bridge_did: String,
    /// `projectRoles` | `createRepo` | `bootstrap` | `archive` | `inspect` |
    /// `beginBind` | `beginAccountLink` | `closePullRequest` (0.2 only).
    pub kind: String,
    /// `pending` | `accepted` | `succeeded` | `partial` | `failed` |
    /// `cancelled`.
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// The pull request a `closePullRequest` job closes, in `repo`. Absent for
    /// every other kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<u64>,
    pub attempts: u32,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsJobList {
    pub jobs: Vec<GitNsJobRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

fn job_state_str(j: &BridgeJob) -> String {
    serde_json::to_value(j.state)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn job_row(j: &BridgeJob) -> GitNsJobRow {
    GitNsJobRow {
        job_id: j.job_id.clone(),
        namespace: j.namespace_id.clone(),
        bridge_did: j.bridge_did.clone(),
        kind: j.kind.as_str().to_string(),
        state: job_state_str(j),
        repo: j
            .payload
            .get("repo")
            .and_then(Value::as_str)
            .map(str::to_string),
        number: (j.kind == bridge::JobKind::ClosePullRequest)
            .then(|| j.payload.get("number").and_then(Value::as_u64))
            .flatten(),
        attempts: j.attempts,
        created_at: wire::timestamp(j.created_at),
        accepted_at: j.accepted_at.map(wire::timestamp),
        last_error: j.last_error.clone(),
    }
}

/// The administrator's job list, as `git-ns/bridge/job/list` 0.1 and 0.2
/// both answer it. `with_pull_requests` is 0.2: 0.1's `JobKind` is job 0.4's
/// seven kinds, so a 0.1 answer MUST leave `closePullRequest` jobs out
/// (`git-ns/bridge/job/list/0.2`, *Which version a VTC answers*) — before
/// paging, so `limit` and `nextCursor` still apply to the jobs it returns.
async fn job_list(
    state: &AppState,
    actor: &str,
    namespace: Option<String>,
    state_filter: Option<String>,
    cursor: Option<&str>,
    limit: Option<std::num::NonZeroU64>,
    not_administrator: &'static str,
    with_pull_requests: bool,
) -> OpResult<GitNsJobList> {
    let snap = Snapshot::load(&state.git_ns).await?;
    let admin = administered(state, &snap, actor).await?;
    let covered = covered(&admin, namespace.as_deref(), not_administrator)?;
    let mut jobs: Vec<BridgeJob> = bridge::list_jobs(&state.git_ns.jobs_ks)
        .await?
        .into_iter()
        .filter(|j| covered.contains(&j.namespace_id))
        .filter(|j| with_pull_requests || j.kind != bridge::JobKind::ClosePullRequest)
        .filter(|j| {
            state_filter
                .as_deref()
                .is_none_or(|s| s == job_state_str(j))
        })
        .collect();
    jobs.sort_by_key(|j| std::cmp::Reverse(j.created_at));
    let rows: Vec<GitNsJobRow> = jobs.iter().map(job_row).collect();
    let filters = json!({ "namespace": namespace, "state": state_filter });
    let (page, next_cursor) = page_of(rows, &filters, cursor, limit)?;
    Ok(GitNsJobList {
        jobs: page,
        next_cursor,
    })
}

/// `git-ns/bridge/job/list/0.1` — every job but `closePullRequest`.
pub(crate) async fn bridge_job_list(
    state: &AppState,
    actor: &str,
    p: bridge_job_list_v0_1::Payload,
) -> OpResult<bridge_job_list_v0_1::Response> {
    let list = job_list(
        state,
        actor,
        p.namespace.as_ref().map(|n| n.to_string()),
        p.state.as_ref().map(|s| s.to_string()),
        p.cursor.as_deref(),
        p.limit,
        bridge_job_list_v0_1::error_codes::NOT_ADMINISTRATOR.code,
        false,
    )
    .await?;
    Ok(wire::into(
        serde_json::to_value(&list).map_err(vti_common::error::AppError::from)?,
    )?)
}

/// `git-ns/bridge/job/list/0.2` — every job, `closePullRequest` with its
/// pull request's `number`.
pub(crate) async fn bridge_job_list_v2(
    state: &AppState,
    actor: &str,
    p: bridge_job_list_v0_2::Payload,
) -> OpResult<bridge_job_list_v0_2::Response> {
    let list = job_list(
        state,
        actor,
        p.namespace.as_ref().map(|n| n.to_string()),
        p.state.as_ref().map(|s| s.to_string()),
        p.cursor.as_deref(),
        p.limit,
        bridge_job_list_v0_2::error_codes::NOT_ADMINISTRATOR.code,
        true,
    )
    .await?;
    Ok(wire::into(
        serde_json::to_value(&list).map_err(vti_common::error::AppError::from)?,
    )?)
}

// ── git-ns/projection/show/0.1 ──────────────────────────────────────────────

/// One record published to the Trust Registry.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsPublishedRow {
    pub entity: String,
    pub action: String,
    pub resource: String,
    /// The record's `context` as published (framework, origin,
    /// activeFrom, activeTo, impliedBy).
    #[schema(value_type = Object)]
    pub context: Value,
    pub published_at: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsProjection {
    /// Whether this VTC can publish at all (a registry and its DID are
    /// configured). With none, the list is what was last published.
    pub registry_configured: bool,
    pub published: Vec<GitNsPublishedRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Records that should be published and are not yet, or that are
    /// published and should not be — what the next pass will change. Counted
    /// across the whole VTC, regardless of `resource` or paging.
    pub pending_changes: usize,
}

/// `git-ns/projection/show/0.1`.
pub(crate) async fn projection_show(
    state: &AppState,
    actor: &str,
    p: projection_show_v0_1::Payload,
) -> OpResult<projection_show_v0_1::Response> {
    let caller = ops::standing(state, actor).await?;
    if !caller.community_admin {
        return Err(declared(
            projection_show_v0_1::error_codes::NOT_COMMUNITY_ADMINISTRATOR.code,
            "publishing configuration and the projection mirror are community-wide facts: this \
             needs the community-administrator capability",
        ));
    }
    let filter = match &p.resource {
        Some(r) => Some(Resource::parse(&r.to_string()).map_err(OpError::Malformed)?),
        None => None,
    };
    let registry_configured =
        state.registry_client.is_some() && state.config.read().await.vtc_did.is_some();
    let snap = Snapshot::load(&state.git_ns).await?;
    let want = projection::desired_all(state, &snap, now()).await?;
    let have = projection::published(state).await?;
    let pending_changes = want
        .iter()
        .filter(|(k, t)| have.get(*k).map(|p| &p.tuple) != Some(*t))
        .count()
        + have.keys().filter(|k| !want.contains_key(*k)).count();
    let mut published: Vec<GitNsPublishedRow> = have
        .into_values()
        .filter(|p| {
            filter
                .as_ref()
                .is_none_or(|f| Resource::parse(&p.tuple.resource).is_ok_and(|r| f.contains(&r)))
        })
        .map(|p| GitNsPublishedRow {
            entity: p.tuple.entity,
            action: p.tuple.action,
            resource: p.tuple.resource,
            context: p.tuple.context,
            published_at: wire::timestamp(p.published_at),
        })
        .collect();
    published.sort_by(|a, b| {
        (&a.resource, &a.action, &a.entity).cmp(&(&b.resource, &b.action, &b.entity))
    });
    let filters = json!({ "resource": p.resource.as_ref().map(|r| r.to_string()) });
    let (page, next_cursor) = page_of(published, &filters, p.cursor.as_deref(), p.limit)?;
    let projection = GitNsProjection {
        registry_configured,
        published: page,
        next_cursor,
        pending_changes,
    };
    Ok(wire::into(
        serde_json::to_value(&projection).map_err(vti_common::error::AppError::from)?,
    )?)
}

// ── git-ns/account/list/0.1 ──────────────────────────────────────────────────

/// One member's account on one forge, as linked through `git-ns/account/link`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsAccountRow {
    pub member: String,
    pub account: GitNsForgeAccount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linked_at: Option<String>,
    /// Whether the member is still a current member. One whose access lapsed
    /// keeps the link — no one else may link the account — but it projects
    /// no forge role, and a forge role it holds cannot be adopted as a right.
    pub member_current: bool,
}

/// A member's account on one forge (the shared `ForgeAccount` shape).
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsForgeAccount {
    pub forge: String,
    /// The forge's id for the account — authoritative.
    pub id: String,
    /// The login — display only: logins are renamed and re-registered.
    pub login: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsAccountList {
    pub accounts: Vec<GitNsAccountRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// `git-ns/account/list/0.1`.
pub(crate) async fn account_list(
    state: &AppState,
    actor: &str,
    p: account_list_v0_1::Payload,
) -> OpResult<account_list_v0_1::Response> {
    let caller = ops::standing(state, actor).await?;
    if !caller.community_admin {
        return Err(declared(
            account_list_v0_1::error_codes::NOT_COMMUNITY_ADMINISTRATOR.code,
            "a linked account is not scoped to any namespace: this community-wide roster needs \
             the community-administrator capability",
        ));
    }
    let member_filter = p.member.as_ref().map(|m| m.to_string());
    let forge_filter = p.forge.as_ref().map(|f| f.to_string());
    let mut accounts = Vec::new();
    for m in crate::members::list_members(&state.members_ks).await? {
        if m.removed_at.is_some() {
            continue;
        }
        if member_filter.as_deref().is_some_and(|f| f != m.did) {
            continue;
        }
        let Some(forges) = m.extensions.get("forges").and_then(Value::as_object) else {
            continue;
        };
        let member_current = ops::standing(state, &m.did).await?.member;
        for (forge, a) in forges {
            if forge_filter.as_deref().is_some_and(|f| f != forge) {
                continue;
            }
            let (Some(id), Some(login)) = (
                a.get("id").and_then(Value::as_str),
                a.get("login").and_then(Value::as_str),
            ) else {
                continue;
            };
            accounts.push(GitNsAccountRow {
                member: m.did.clone(),
                account: GitNsForgeAccount {
                    forge: forge.clone(),
                    id: id.to_string(),
                    login: login.to_string(),
                },
                linked_at: a
                    .get("linkedAt")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                member_current,
            });
        }
    }
    accounts.sort_by(|a, b| (&a.member, &a.account.forge).cmp(&(&b.member, &b.account.forge)));
    let filters = json!({ "member": member_filter, "forge": forge_filter });
    let (page, next_cursor) = page_of(accounts, &filters, p.cursor.as_deref(), p.limit)?;
    let list = GitNsAccountList {
        accounts: page,
        next_cursor,
    };
    Ok(wire::into(
        serde_json::to_value(&list).map_err(vti_common::error::AppError::from)?,
    )?)
}

// ── git-ns/activity/list/0.1 ────────────────────────────────────────────────

/// One thing that happened in a namespace.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsActivityItem {
    pub at: String,
    /// `gitNs.right.granted`, `gitNs.repo.renamed`, `gitNs.drift.reported`,
    /// `gitNs.job.createRepo`, …
    pub action: String,
    /// `audit` or `job`.
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub right: Option<String>,
    /// Who acted. Absent when an erasure has removed it from the audit row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Whose right it was. Absent likewise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// A machine-readable qualifier (`departed`, the old name of a rename, a
    /// job's state, a drift count).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsActivity {
    pub items: Vec<GitNsActivityItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// `git-ns/activity/list/0.1`.
pub(crate) async fn activity_list(
    state: &AppState,
    actor: &str,
    p: activity_list_v0_1::Payload,
) -> OpResult<activity_list_v0_1::Response> {
    let snap = Snapshot::load(&state.git_ns).await?;
    let admin = administered(state, &snap, actor).await?;
    let named = p.namespace.as_ref().map(|n| n.to_string());
    let covered = covered(
        &admin,
        named.as_deref(),
        activity_list_v0_1::error_codes::NOT_ADMINISTRATOR.code,
    )?;
    let mut items: Vec<(chrono::DateTime<chrono::Utc>, GitNsActivityItem)> = Vec::new();
    for (_, v) in state.audit_ks.prefix_iter_raw(Vec::new()).await? {
        let Ok(env) = serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v) else {
            continue;
        };
        let vti_common::audit::AuditEvent::GitNsOperation(d) = env.event else {
            continue;
        };
        // A row for a namespace since unbound is still the history of a
        // namespace the caller no longer administers, so only a community
        // administrator sees rows outside the covered set.
        let visible = match &d.namespace {
            Some(n) => covered.contains(n),
            None => admin.community_admin && named.is_none(),
        };
        if !visible {
            continue;
        }
        items.push((
            env.timestamp,
            GitNsActivityItem {
                at: wire::timestamp(env.timestamp),
                action: d.action,
                source: "audit".into(),
                namespace: d.namespace,
                resource: d.resource,
                right: d.right,
                actor: env.actor_did_plain,
                subject: env.target_did_plain,
                detail: d.detail,
            },
        ));
    }
    for job in bridge::list_jobs(&state.git_ns.jobs_ks).await? {
        if !covered.contains(&job.namespace_id) {
            continue;
        }
        let row = job_row(&job);
        let at = job.accepted_at.unwrap_or(job.created_at);
        items.push((
            at,
            GitNsActivityItem {
                at: wire::timestamp(at),
                action: format!("gitNs.job.{}", job.kind.as_str()),
                source: "job".into(),
                namespace: Some(job.namespace_id.clone()),
                resource: row.repo,
                right: None,
                actor: None,
                subject: None,
                detail: Some(row.state),
            },
        ));
    }
    items.sort_by(|(a, _), (b, _)| b.cmp(a));
    let rows: Vec<GitNsActivityItem> = items.into_iter().map(|(_, i)| i).collect();
    let filters = json!({ "namespace": named });
    let (page, next_cursor) = page_of(rows, &filters, p.cursor.as_deref(), p.limit)?;
    let activity = GitNsActivity {
        items: page,
        next_cursor,
    };
    Ok(wire::into(
        serde_json::to_value(&activity).map_err(vti_common::error::AppError::from)?,
    )?)
}
