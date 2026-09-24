//! The administrator's read surface over the community's git namespaces —
//! what the admin console's *Repos* plugin renders.
//!
//! Read-only, and deliberately so. Every change to a git right is a signed
//! `git-ns/*` Trust Task, authorized by the signer's own git rights
//! (`git-ns/right/grant/0.1`, *Authorization*: "a VTC administrator who holds
//! no git right grants nothing through this task"). A bearer session carries
//! no proof, and these tasks declare one REQUIRED, so there is no bearer door
//! to them here; the console acts by having the administrator sign.
//!
//! Each route is gated on an admin session; the ones that disclose every
//! grant's reason, every member's linked forge account or the published
//! record set — `view`, `rights`, `rights/issued-by-departed`, `accounts`,
//! `projection` — on the community-administrator capability (a super-admin
//! session, as `/audit` is), not on any context-scoped admin. `view` also carries the
//! `git-ns/view/0.1` Trust-Task header, because its body is that task's
//! response; the others are console projections no specification defines,
//! and carry no Trust-Task URL rather than one whose response they do not
//! match:
//!
//! - `GET /v1/git-ns/view`                         — `git-ns/view/0.1#response`, every record, every reason
//! - `GET /v1/git-ns/namespaces`                   — bound and pending namespaces, with their admins and bridge
//! - `GET /v1/git-ns/repos`                        — repositories, owners, bootstrap and sync status
//! - `GET /v1/git-ns/rights`                       — recorded rights plus the v0.1 role-derived ones
//! - `GET /v1/git-ns/rights/issued-by-departed`    — grants whose granter has left (design §5.4)
//! - `GET /v1/git-ns/drift`                        — repositories whose forge differs from the projection
//! - `GET /v1/git-ns/jobs`                         — bridge jobs and their state
//! - `GET /v1/git-ns/projection`                   — what is published to the Trust Registry
//! - `GET /v1/git-ns/accounts`                     — members' linked forge accounts
//!
//! And one read that is not the community administrator's alone:
//!
//! - `GET /v1/git-ns/activity` — rights changes, drift and bridge jobs in the
//!   namespaces the caller administers (`git.ns.admin`), for any authenticated
//!   session; a community administrator sees every namespace. The VTC issues
//!   sessions to admin-role entries only, so in practice this is a
//!   context-scoped administrator reading the namespaces they administer; a
//!   namespace admin who is an ordinary member has no session and no route
//!   here — there is no `git-ns/*` Trust Task for an activity read. It is read from
//!   the git-ns audit rows and the job queue, so a namespace admin needs no
//!   access to the community's whole audit log to see their own namespace.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use vta_sdk::openapi::GitNsView01Response;
use vti_common::auth::{AdminAuth, SuperAdminAuth};
use vti_common::error::AppError;

use crate::git_ns::bridge::{self, BridgeJob};
use crate::git_ns::model::{Resource, Right, RightRow, Scope};
use crate::git_ns::ops::{now, standing};
use crate::git_ns::store::Snapshot;
use crate::git_ns::{lifecycle, projection, rules, view, wire};
use crate::server::AppState;

// ── query parameters ────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct ResourceFilter {
    /// Narrow to this forge-qualified resource and everything it contains
    /// (`github.com/acme`, `github.com/acme/widgets`).
    pub resource: Option<String>,
}

#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct RepoFilter {
    /// Only repositories in this namespace (its identifier).
    pub namespace: Option<String>,
}

#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct RightFilter {
    /// Only rights on this resource or inside it.
    pub resource: Option<String>,
    /// Only rights held by this DID.
    pub subject: Option<String>,
}

fn parse_filter(raw: Option<&str>) -> Result<Option<Resource>, AppError> {
    raw.map(|r| Resource::parse(r).map_err(AppError::Validation))
        .transpose()
}

// ── response bodies ─────────────────────────────────────────────────────────

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
    /// The last verify-trust check the bridge saw (`{conclusion, at, sha?}`).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub last_check: Option<Value>,
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

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GitNsRepoList {
    pub repos: Vec<GitNsRepoRow>,
}

/// One git right, recorded or role-derived.
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
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GitNsRightList {
    pub rights: Vec<GitNsRightRow>,
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
}

/// The outstanding drift on one repository.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsDriftRow {
    pub resource: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
    /// The bridge's items, each a `DriftItem` of the shared schema.
    #[schema(value_type = Vec<vta_sdk::openapi::GitNsView01DriftItem>)]
    pub drift: Vec<Value>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GitNsDriftList {
    pub repos: Vec<GitNsDriftRow>,
}

/// One bridge job.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsJobRow {
    pub job_id: String,
    pub namespace: String,
    pub bridge_did: String,
    /// `projectRoles` | `createRepo` | `bootstrap` | `archive` | `inspect` |
    /// `beginBind` | `beginAccountLink`.
    pub kind: String,
    /// `pending` | `accepted` | `succeeded` | `partial` | `failed` |
    /// `cancelled`.
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    pub attempts: u32,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GitNsJobList {
    pub jobs: Vec<GitNsJobRow>,
}

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
    /// Records that should be published and are not yet, or that are
    /// published and should not be — what the next pass will change.
    pub pending_changes: usize,
}

// ── handlers ────────────────────────────────────────────────────────────────

#[utoipa::path(
    get, path = "/git-ns/view",
    operation_id = "gitNsAdminView", tag = "git-ns",
    params(ResourceFilter),
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Every namespace, repository and recorded right, reasons included", body = GitNsView01Response),
        (status = 400, description = "The resource is not a forge-qualified resource"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a community administrator"),
    ),
)]
pub async fn admin_view(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
    Query(q): Query<ResourceFilter>,
) -> Result<Json<GitNsView01Response>, AppError> {
    let filter = parse_filter(q.resource.as_deref())?;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    Ok(Json(GitNsView01Response(view::for_administrator(
        &snap,
        filter.as_ref(),
    )?)))
}

#[utoipa::path(
    get, path = "/git-ns/namespaces",
    operation_id = "gitNsNamespacesList", tag = "git-ns",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Bound and pending namespaces", body = GitNsNamespaceList),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn namespaces_list(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<GitNsNamespaceList>, AppError> {
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let t = now();
    let headless = lifecycle::headless(&snap);
    let settings = crate::git_ns::policy::active_settings(&state).await;
    let role_drift = if settings.enforce_role_drift {
        "enforce"
    } else {
        "report"
    };
    let namespaces = snap
        .namespaces
        .iter()
        .map(|ns| {
            let v = wire::namespace(ns);
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
                    installation_id: s.installation_id.clone(),
                    app_name: s.app_name.clone(),
                    app_slug: s.app_slug.clone(),
                    app_registration: s.app_registration.clone(),
                    missing_permissions: s.missing_permissions.clone(),
                    permission_upgrade_pending: s.permission_upgrade_pending,
                    org_rulesets: s.org_rulesets,
                    required_workflow: s.required_workflow,
                    bridge_posted_check: s.bridge_posted_check,
                    reported_at: s.reported_at.map(wire::timestamp),
                }),
                role_drift: role_drift.to_string(),
                cascade_on_departure: settings.cascade_on_departure,
            }
        })
        .collect();
    Ok(Json(GitNsNamespaceList { namespaces }))
}

#[utoipa::path(
    get, path = "/git-ns/repos",
    operation_id = "gitNsReposList", tag = "git-ns",
    params(RepoFilter),
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Recorded repositories", body = GitNsRepoList),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn repos_list(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Query(q): Query<RepoFilter>,
) -> Result<Json<GitNsRepoList>, AppError> {
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let t = now();
    let mut repos: Vec<GitNsRepoRow> = snap
        .repos
        .iter()
        .filter(|r| q.namespace.as_deref().is_none_or(|n| r.namespace_id == n))
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
                failed_step: r.failed_step.clone(),
                last_error: r.last_error.clone(),
                created_by: r.created_by.clone(),
                created_at: wire::timestamp(r.created_at),
                guard: r.forge_report.guard.clone(),
                steps: r
                    .forge_report
                    .steps
                    .iter()
                    .map(|s| GitNsStepOutcome {
                        step: s["step"].as_str().unwrap_or_default().to_string(),
                        outcome: s["outcome"].as_str().unwrap_or_default().to_string(),
                        detail: s.get("detail").and_then(Value::as_str).map(str::to_string),
                    })
                    .collect(),
                last_check: r.forge_report.last_check.clone(),
            }
        })
        .collect();
    repos.sort_by(|a, b| a.resource.cmp(&b.resource));
    Ok(Json(GitNsRepoList { repos }))
}

async fn member_cached(
    state: &AppState,
    cache: &mut BTreeMap<String, bool>,
    did: &str,
) -> Result<bool, AppError> {
    if let Some(m) = cache.get(did) {
        return Ok(*m);
    }
    let m = standing(state, did).await?.member;
    cache.insert(did.to_string(), m);
    Ok(m)
}

/// Render one recorded right, with the membership facts the console shows.
async fn right_row(
    state: &AppState,
    cache: &mut BTreeMap<String, bool>,
    row: &RightRow,
    resource: &Resource,
) -> Result<GitNsRightRow, AppError> {
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
    })
}

#[utoipa::path(
    get, path = "/git-ns/rights",
    operation_id = "gitNsRightsList", tag = "git-ns",
    params(RightFilter),
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Recorded and role-derived git rights", body = GitNsRightList),
        (status = 400, description = "The resource is not a forge-qualified resource"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a community administrator"),
    ),
)]
pub async fn rights_list(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
    Query(q): Query<RightFilter>,
) -> Result<Json<GitNsRightList>, AppError> {
    let filter = parse_filter(q.resource.as_deref())?;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
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
        for row in set.rows.iter().filter(|r| r.is_live(t)) {
            if q.subject.as_deref().is_some_and(|s| s != row.subject) {
                continue;
            }
            rights.push(right_row(&state, &mut cache, row, &res).await?);
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
            if q.subject.as_deref().is_some_and(|s| s != entry.did) {
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
                subject_member: standing(&state, &entry.did).await?.member,
                granter_departed: false,
            });
        }
    }
    Ok(Json(GitNsRightList { rights }))
}

#[utoipa::path(
    get, path = "/git-ns/rights/issued-by-departed",
    operation_id = "gitNsRightsIssuedByDeparted", tag = "git-ns",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Grants whose granter has left the community", body = GitNsDepartedGrants),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a community administrator"),
    ),
)]
pub async fn issued_by_departed(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
) -> Result<Json<GitNsDepartedGrants>, AppError> {
    let settings = crate::git_ns::policy::active_settings(&state).await;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let mut cache = BTreeMap::new();
    let mut granters = Vec::new();
    for (granter, rows) in lifecycle::issued_by_departed(&state).await? {
        let mut out = Vec::new();
        for (scope, row) in rows {
            if let Some(res) = snap.scope_resource(&scope) {
                out.push(right_row(&state, &mut cache, &row, &res).await?);
            }
        }
        granters.push(GitNsDepartedGranter {
            granter,
            rights: out,
        });
    }
    Ok(Json(GitNsDepartedGrants {
        cascade_on_departure: settings.cascade_on_departure,
        granters,
    }))
}

#[utoipa::path(
    get, path = "/git-ns/drift",
    operation_id = "gitNsDriftList", tag = "git-ns",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Repositories whose forge differs from the projection", body = GitNsDriftList),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a community administrator"),
    ),
)]
pub async fn drift_list(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
) -> Result<Json<GitNsDriftList>, AppError> {
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let repos = snap
        .repos
        .iter()
        .filter(|r| !r.sync.drift.is_empty())
        .map(|r| GitNsDriftRow {
            resource: r.resource.clone(),
            state: r.sync.state.as_str().to_string(),
            checked_at: r.sync.checked_at.map(wire::timestamp),
            drift: r.sync.drift.clone(),
        })
        .collect();
    Ok(Json(GitNsDriftList { repos }))
}

fn job_row(j: &BridgeJob) -> GitNsJobRow {
    let as_str = |v: &Value| v.as_str().unwrap_or_default().to_string();
    GitNsJobRow {
        job_id: j.job_id.clone(),
        namespace: j.namespace_id.clone(),
        bridge_did: j.bridge_did.clone(),
        kind: j.kind.as_str().to_string(),
        state: as_str(&serde_json::to_value(j.state).unwrap_or_default()),
        repo: j
            .payload
            .get("repo")
            .and_then(Value::as_str)
            .map(str::to_string),
        attempts: j.attempts,
        created_at: wire::timestamp(j.created_at),
        accepted_at: j.accepted_at.map(wire::timestamp),
        last_error: j.last_error.clone(),
    }
}

#[utoipa::path(
    get, path = "/git-ns/jobs",
    operation_id = "gitNsJobsList", tag = "git-ns",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Bridge jobs, oldest first", body = GitNsJobList),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn jobs_list(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<GitNsJobList>, AppError> {
    let jobs = bridge::list_jobs(&state.git_ns.jobs_ks)
        .await?
        .iter()
        .map(job_row)
        .collect();
    Ok(Json(GitNsJobList { jobs }))
}

#[utoipa::path(
    get, path = "/git-ns/projection",
    operation_id = "gitNsProjection", tag = "git-ns",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "What is published to the Trust Registry", body = GitNsProjection),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a community administrator"),
    ),
)]
pub async fn projection_show(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
) -> Result<Json<GitNsProjection>, AppError> {
    let registry_configured =
        state.registry_client.is_some() && state.config.read().await.vtc_did.is_some();
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let want = projection::desired_all(&state, &snap, now()).await?;
    let have = projection::published(&state).await?;
    let pending_changes = want
        .iter()
        .filter(|(k, t)| have.get(*k).map(|p| &p.tuple) != Some(*t))
        .count()
        + have.keys().filter(|k| !want.contains_key(*k)).count();
    let published = have
        .into_values()
        .map(|p| GitNsPublishedRow {
            entity: p.tuple.entity,
            action: p.tuple.action,
            resource: p.tuple.resource,
            context: p.tuple.context,
            published_at: wire::timestamp(p.published_at),
        })
        .collect();
    Ok(Json(GitNsProjection {
        registry_configured,
        published,
        pending_changes,
    }))
}

// ── linked forge accounts ───────────────────────────────────────────────────

/// One member's account on one forge, as linked through `git-ns/account/link`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitNsAccountRow {
    pub member: String,
    pub forge: String,
    /// The forge's id for the account — authoritative.
    pub id: String,
    /// The login — display only: logins are renamed and re-registered.
    pub login: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linked_at: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GitNsAccountList {
    pub accounts: Vec<GitNsAccountRow>,
}

#[utoipa::path(
    get, path = "/git-ns/accounts",
    operation_id = "gitNsAccountsList", tag = "git-ns",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Members' linked forge accounts", body = GitNsAccountList),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a community administrator"),
    ),
)]
pub async fn accounts_list(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
) -> Result<Json<GitNsAccountList>, AppError> {
    let mut accounts = Vec::new();
    for m in crate::members::list_members(&state.members_ks).await? {
        if m.removed_at.is_some() {
            continue;
        }
        let Some(forges) = m.extensions.get("forges").and_then(Value::as_object) else {
            continue;
        };
        for (forge, a) in forges {
            let (Some(id), Some(login)) = (
                a.get("id").and_then(Value::as_str),
                a.get("login").and_then(Value::as_str),
            ) else {
                continue;
            };
            accounts.push(GitNsAccountRow {
                member: m.did.clone(),
                forge: forge.clone(),
                id: id.to_string(),
                login: login.to_string(),
                linked_at: a
                    .get("linkedAt")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            });
        }
    }
    Ok(Json(GitNsAccountList { accounts }))
}

// ── activity ────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct ActivityFilter {
    /// Only this namespace (its identifier).
    pub namespace: Option<String>,
    /// At most this many items, newest first. Default 100, at most 500.
    pub limit: Option<usize>,
}

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
pub struct GitNsActivity {
    pub items: Vec<GitNsActivityItem>,
}

#[utoipa::path(
    get, path = "/git-ns/activity",
    operation_id = "gitNsActivity", tag = "git-ns",
    params(ActivityFilter),
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Recent activity in the namespaces the caller administers", body = GitNsActivity),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "The caller administers no namespace (or not the one named)"),
    ),
)]
pub async fn activity(
    auth: vti_common::auth::AuthClaims,
    State(state): State<AppState>,
    Query(q): Query<ActivityFilter>,
) -> Result<Json<GitNsActivity>, AppError> {
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let t = now();
    let caller = standing(&state, &auth.did).await?;
    // Which namespaces: all for a community administrator; otherwise the ones
    // the caller holds `git.ns.admin` on. Held by explicit record only — the
    // one thing that implies it is itself.
    let mut allowed: std::collections::BTreeSet<String> = snap
        .namespaces
        .iter()
        .filter(|n| caller.community_admin || rules::admins(&snap, &n.id, t).contains(&auth.did))
        .map(|n| n.id.clone())
        .collect();
    if let Some(n) = &q.namespace {
        if !allowed.contains(n) {
            return Err(AppError::Forbidden(format!(
                "you do not administer namespace `{n}`"
            )));
        }
        allowed = std::iter::once(n.clone()).collect();
    }
    if allowed.is_empty() && !caller.community_admin {
        return Err(AppError::Forbidden(
            "git-ns activity is for namespace administrators; you hold git.ns.admin on no \
             namespace"
                .into(),
        ));
    }
    let limit = q.limit.unwrap_or(100).clamp(1, 500);

    let mut items = Vec::new();
    for (_, v) in state.audit_ks.prefix_iter_raw(Vec::new()).await? {
        let Ok(env) = serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v) else {
            continue;
        };
        let vti_common::audit::AuditEvent::GitNsOperation(d) = env.event else {
            continue;
        };
        // A row for a namespace since unbound is still the history of a
        // namespace the caller no longer administers, so only a community
        // administrator sees rows outside the allowed set.
        let visible = match &d.namespace {
            Some(n) => allowed.contains(n),
            None => caller.community_admin && q.namespace.is_none(),
        };
        if !visible {
            continue;
        }
        items.push(GitNsActivityItem {
            at: wire::timestamp(env.timestamp),
            action: d.action,
            source: "audit".into(),
            namespace: d.namespace,
            resource: d.resource,
            right: d.right,
            actor: env.actor_did_plain,
            subject: env.target_did_plain,
            detail: d.detail,
        });
    }
    for job in bridge::list_jobs(&state.git_ns.jobs_ks).await? {
        if !allowed.contains(&job.namespace_id) {
            continue;
        }
        let row = job_row(&job);
        items.push(GitNsActivityItem {
            at: wire::timestamp(job.accepted_at.unwrap_or(job.created_at)),
            action: format!("gitNs.job.{}", job.kind.as_str()),
            source: "job".into(),
            namespace: Some(job.namespace_id.clone()),
            resource: row.repo,
            right: None,
            actor: None,
            subject: None,
            detail: Some(row.state),
        });
    }
    items.sort_by(|a, b| b.at.cmp(&a.at));
    items.truncate(limit);
    Ok(Json(GitNsActivity { items }))
}
