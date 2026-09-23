//! The `git-ns/*` operations, with no transport in them.
//!
//! Each function is one task's *Request* section, in the order the
//! specification lists its steps: resolve what the request names, check the
//! entitlement, apply the fixed rules ([`super::rules`]), the consent-class
//! gate ([`consent_gate`]), then the community's policy ([`super::policy`]),
//! and only then write. A write is durable before the function returns — the
//! grant and revoke specifications forbid answering first — and each accepted
//! change leaves a `GitNsOperation` audit row, which is what wakes the
//! projector.
//!
//! The actor is always a DID the caller has already established: the signer
//! of the document's proof, verified by the dispatch spine against the
//! document as received. Nothing here reads an identity from a payload.

use chrono::{DateTime, Timelike, Utc};
use serde_json::json;
use trust_tasks_rs::specs::git_ns::account::{
    link::v0_1 as link, link_status::v0_1 as link_status,
};
use trust_tasks_rs::specs::git_ns::bridge::job::v0_1 as job_wire;
use trust_tasks_rs::specs::git_ns::namespace::{bind::v0_1 as bind, unbind::v0_1 as unbind};
use trust_tasks_rs::specs::git_ns::repo::{
    adopt::v0_1 as adopt, archive::v0_1 as archive, create::v0_1 as create,
    transfer::v0_1 as transfer,
};
use trust_tasks_rs::specs::git_ns::right::{grant::v0_1 as grant, revoke::v0_1 as revoke};
use vti_common::audit::{AuditEvent, GitNsOperationData};
use vti_common::error::AppError;

use crate::acl::VtcRole;
use crate::server::AppState;

use super::bridge::{self, JobKind, NewJob};
use super::model::{
    Bootstrap, LinkAttempt, LinkState, Mode, Namespace, NamespaceState, OwnerKind, Repo, RepoState,
    Resource, Right, RightRow, Scope, SyncState, SyncStatus, Visibility, new_id,
};
use super::policy::{self, Capabilities, GitNsFacts, Party, VerifiedGitNsFacts};
use super::rules::{self, Refusal};
use super::store::{self, Snapshot};
use super::wire;

// ── the codes this family declares ──────────────────────────────────────────

pub const UNKNOWN_NAMESPACE: &str = grant::error_codes::UNKNOWN_NAMESPACE.code;
pub const NAMESPACE_NOT_BOUND: &str = grant::error_codes::NAMESPACE_NOT_BOUND.code;
pub const UNKNOWN_REPO: &str = grant::error_codes::UNKNOWN_REPO.code;
pub const REPO_NOT_ACTIVE: &str = grant::error_codes::REPO_NOT_ACTIVE.code;
pub const SCOPE_VIOLATION: &str = grant::error_codes::SCOPE_VIOLATION.code;
pub const ESCALATION: &str = grant::error_codes::ESCALATION.code;
pub const MEMBERS_ONLY: &str = grant::error_codes::MEMBERS_ONLY.code;
pub const POLICY_DENIED: &str = grant::error_codes::POLICY_DENIED.code;
pub const EXPIRY_IN_PAST: &str = grant::error_codes::EXPIRY_IN_PAST.code;
pub const LAST_OWNER: &str = revoke::error_codes::LAST_OWNER.code;
pub const LAST_ADMIN: &str = revoke::error_codes::LAST_ADMIN.code;
pub const NOT_GRANTED: &str = revoke::error_codes::NOT_GRANTED.code;
pub const ALREADY_BOUND: &str = bind::error_codes::ALREADY_BOUND.code;
pub const NO_BRIDGE: &str = bind::error_codes::NO_BRIDGE.code;
pub const NAME_TAKEN: &str = create::error_codes::NAME_TAKEN.code;
pub const ALREADY_MANAGED: &str = adopt::error_codes::ALREADY_MANAGED.code;
pub const NOT_OWNER: &str = transfer::error_codes::NOT_OWNER.code;
pub const SELF_TRANSFER: &str = transfer::error_codes::SELF_TRANSFER.code;
pub const UNSUPPORTED_FORGE: &str = link::error_codes::UNSUPPORTED_FORGE.code;
pub const UNKNOWN_LINK: &str = link_status::error_codes::UNKNOWN_LINK.code;

/// Why an operation refused, as the wire will carry it.
#[derive(Debug)]
pub enum OpError {
    /// A code the task's specification declares.
    Declared {
        code: &'static str,
        message: String,
    },
    /// The framework's `permissionDenied`.
    PermissionDenied(String),
    /// The framework's `malformedRequest`.
    Malformed(String),
    /// The framework's `unavailable`: a bridge that must answer in-line did
    /// not. Retryable, and honest about it.
    Unavailable(String),
    Internal(AppError),
}

impl From<AppError> for OpError {
    fn from(e: AppError) -> Self {
        OpError::Internal(e)
    }
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpError::Declared { code, message } => write!(f, "{code}: {message}"),
            OpError::PermissionDenied(m) => write!(f, "permissionDenied: {m}"),
            OpError::Malformed(m) => write!(f, "malformedRequest: {m}"),
            OpError::Unavailable(m) => write!(f, "unavailable: {m}"),
            OpError::Internal(e) => write!(f, "internal: {e}"),
        }
    }
}

fn declared(code: &'static str, message: impl Into<String>) -> OpError {
    OpError::Declared {
        code,
        message: message.into(),
    }
}

impl From<Refusal> for OpError {
    fn from(r: Refusal) -> Self {
        match r {
            Refusal::PermissionDenied(m) => OpError::PermissionDenied(m),
            Refusal::ScopeViolation(m) => declared(SCOPE_VIOLATION, m),
            Refusal::Escalation(m) => declared(ESCALATION, m),
            Refusal::MembersOnly(m) => declared(MEMBERS_ONLY, m),
        }
    }
}

pub type OpResult<T> = Result<T, OpError>;

/// Now, to the second — the resolution every record and every response
/// carries, so a record read back compares equal to the one written.
pub fn now() -> DateTime<Utc> {
    let n = Utc::now();
    n.with_nanosecond(0).unwrap_or(n)
}

// ── who is asking ───────────────────────────────────────────────────────────

/// What this community knows about a DID.
#[derive(Debug, Clone, Default)]
pub struct Standing {
    pub did: String,
    /// A current member: an unexpired ACL entry, and no departure recorded on
    /// the member row. The ACL entry is what membership removal deletes, so it
    /// is the authoritative half; the row's `removed_at` covers a departure
    /// that kept the row.
    pub member: bool,
    pub role: Option<String>,
    /// Holds the community-administrator capability: an unexpired `admin`
    /// entry whose act scope is the whole community.
    pub community_admin: bool,
}

pub async fn standing(state: &AppState, did: &str) -> Result<Standing, AppError> {
    let entry = crate::acl::get_acl_entry(&state.acl_ks, did).await?;
    let entry = entry.filter(|e| !e.is_expired(crate::auth::session::now_epoch()));
    let row = crate::members::get_member(&state.members_ks, did).await?;
    let departed = row.as_ref().is_some_and(|m| m.removed_at.is_some());
    let member = entry.is_some() && !departed;
    let community_admin = member
        && entry.as_ref().is_some_and(|e| {
            e.role == VtcRole::Admin && matches!(e.act_scope(), vti_common::acl::ActScope::All)
        });
    Ok(Standing {
        did: did.to_string(),
        member,
        role: entry.map(|e| e.role.to_string()),
        community_admin,
    })
}

fn party(s: &Standing, rights: impl IntoIterator<Item = Right>) -> Party {
    Party {
        did: s.did.clone(),
        member: s.member,
        role: s.role.clone(),
        rights: rights.into_iter().map(|r| r.as_str().to_string()).collect(),
    }
}

// ── consent classes (design §6) ─────────────────────────────────────────────

/// How much confirmation an action warrants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConsentClass {
    Normal,
    Elevated,
    Destructive,
}

/// Design §6: `normal` — grant/revoke `commit.sign` and `maintain`, create,
/// link; `elevated` — grant/revoke `own`, transfer, archive, adopt, grant
/// `repo.create`; `destructive` — bind, unbind, grant `ns.admin`.
///
/// The design names the grant of `repo.create` and `ns.admin`; revoking one
/// is classed the same, because taking a namespace-level right away is the
/// same weight of decision as conferring it.
pub fn consent_class(action: &str, right: Option<Right>) -> ConsentClass {
    match (action, right) {
        ("namespace.bind" | "namespace.unbind", _) => ConsentClass::Destructive,
        ("right.grant" | "right.revoke", Some(Right::NsAdmin)) => ConsentClass::Destructive,
        ("right.grant" | "right.revoke", Some(Right::RepoOwn | Right::RepoCreate)) => {
            ConsentClass::Elevated
        }
        ("repo.transfer" | "repo.archive" | "repo.adopt", _) => ConsentClass::Elevated,
        _ => ConsentClass::Normal,
    }
}

/// The stand-in for the step-up this VTC cannot yet ask a member for — see
/// [`super::GitNsConfig::elevated_requires_admin`]. It narrows, never widens:
/// the actor must already be entitled by the rights model to reach here.
async fn consent_gate(
    state: &AppState,
    actor: &Standing,
    action: &str,
    right: Option<Right>,
) -> OpResult<()> {
    let class = consent_class(action, right);
    if class == ConsentClass::Normal {
        return Ok(());
    }
    let gated = state.config.read().await.git_ns.elevated_requires_admin;
    if gated && !actor.community_admin {
        let what = match class {
            ConsentClass::Destructive => "destructive",
            _ => "elevated",
        };
        return Err(OpError::PermissionDenied(format!(
            "{action} is a {what} action, which needs a step-up this community cannot yet ask a \
             member for; until it can, only a community administrator may perform it \
             (`[git_ns] elevated_requires_admin`)"
        )));
    }
    Ok(())
}

// ── policy ──────────────────────────────────────────────────────────────────

pub struct PolicyInput<'a> {
    pub action: &'a str,
    pub actor: &'a Standing,
    pub actor_rights: Vec<Right>,
    pub resource: &'a Resource,
    pub right: Option<Right>,
    pub subject: Option<(&'a Standing, Vec<Right>)>,
    pub visibility: Option<Visibility>,
    pub expires_at: Option<DateTime<Utc>>,
    pub namespace: Option<&'a Namespace>,
}

/// Fixed rule 6: evaluated after the fixed rules, and able only to refuse.
/// Returns the policy's version, for the audit row (VTI-VTC-031).
pub(crate) async fn check_policy(
    state: &AppState,
    input: PolicyInput<'_>,
) -> OpResult<Option<u32>> {
    let active = policy::load(state).await.map_err(|e| {
        declared(
            POLICY_DENIED,
            e.to_string().trim_start_matches("forbidden: "),
        )
    })?;
    let caps = match input.namespace {
        Some(ns) => Capabilities {
            bridge: ns.mode == Mode::Bridge,
            bot_can_create_repos: can_bot_create(ns),
            kind: ns.kind.map(|k| k.as_str().to_string()),
            bridge_did: ns.bridge_did.clone(),
        },
        None => Capabilities::default(),
    };
    let facts = GitNsFacts {
        now: now(),
        action: input.action.to_string(),
        actor: party(input.actor, input.actor_rights),
        resource: input.resource.to_string(),
        forge: input.resource.forge.clone(),
        right: input.right.map(|r| r.as_str().to_string()),
        subject: input.subject.map(|(s, rights)| party(s, rights)),
        visibility: input.visibility.map(|v| v.as_str().to_string()),
        expires_at: input.expires_at,
        capabilities: caps,
    };
    let verified = VerifiedGitNsFacts::after_fixed_rules(facts)?;
    policy::decide(&verified, &active.compiled).map_err(|d| declared(POLICY_DENIED, d.message))?;
    Ok(active.version)
}

/// Whether a bot can create repositories in `ns` — a bridge serves it and
/// the owner is an organisation (`git-ns/bridge/job`: `createRepo` is refused
/// `notCapable` on a personal account).
pub fn can_bot_create(ns: &Namespace) -> bool {
    ns.mode == Mode::Bridge && ns.kind == Some(OwnerKind::Organization)
}

// ── audit ───────────────────────────────────────────────────────────────────

pub struct Audit<'a> {
    pub action: &'a str,
    pub namespace: Option<&'a str>,
    pub resource: Option<String>,
    pub right: Option<Right>,
    pub policy_version: Option<u32>,
    pub detail: Option<String>,
}

/// Record one git-namespace change.
///
/// A failed write is logged and swallowed, as `rooms` does: the change is
/// already durable, and refusing it now would tell the caller a write failed
/// that did not. The projector does not depend on this row either — it also
/// reconciles on a timer — so a lost row delays a projection, never loses it.
pub async fn audit(state: &AppState, actor: &str, target: Option<&str>, a: Audit<'_>) {
    let Some(writer) = state.audit_writer.as_ref() else {
        return;
    };
    let data = GitNsOperationData {
        action: a.action.to_string(),
        namespace: a.namespace.map(str::to_string),
        resource: a.resource,
        right: a.right.map(|r| r.as_str().to_string()),
        policy_version: a.policy_version,
        detail: a.detail,
    };
    if let Err(e) = writer
        .write(actor, target, AuditEvent::GitNsOperation(data))
        .await
    {
        tracing::error!(error = %e, action = a.action, "failed to record a git-ns audit entry");
    }
}

// ── lookups ─────────────────────────────────────────────────────────────────

fn parse_resource(raw: &str) -> OpResult<Resource> {
    Resource::parse(raw).map_err(OpError::Malformed)
}

/// Step "refuses a resource inside no bound namespace with
/// `git-ns:unknownNamespace`, and one inside a pending namespace with
/// `git-ns:namespaceNotBound`".
fn bound_namespace_for<'a>(snap: &'a Snapshot, resource: &Resource) -> OpResult<&'a Namespace> {
    let ns = snap.namespace_containing(resource).ok_or_else(|| {
        declared(
            UNKNOWN_NAMESPACE,
            format!("no namespace bound to this VTC contains {resource}"),
        )
    })?;
    if ns.state != NamespaceState::Bound {
        return Err(declared(
            NAMESPACE_NOT_BOUND,
            format!(
                "{} is still pending: its binding has not completed",
                ns.resource()
            ),
        ));
    }
    Ok(ns)
}

fn namespace_by_id<'a>(snap: &'a Snapshot, id: &str) -> OpResult<&'a Namespace> {
    snap.namespace(id).ok_or_else(|| {
        declared(
            UNKNOWN_NAMESPACE,
            format!("no namespace `{id}` is bound to this VTC"),
        )
    })
}

fn repo_at<'a>(snap: &'a Snapshot, resource: &Resource) -> OpResult<&'a Repo> {
    snap.repo_at(&resource.to_string()).ok_or_else(|| {
        declared(
            UNKNOWN_REPO,
            format!("this VTC records no repository at {resource}"),
        )
    })
}

/// The scope a resource's rights hang on, if it is recorded.
fn scope_for(snap: &Snapshot, resource: &Resource) -> Option<Scope> {
    if resource.is_namespace() {
        snap.namespaces
            .iter()
            .find(|n| n.resource() == *resource)
            .map(|n| Scope::Namespace(n.id.clone()))
    } else {
        snap.repo_at(&resource.to_string())
            .map(|r| Scope::Repo(r.id.clone()))
    }
}

async fn settings(state: &AppState) -> policy::Settings {
    policy::active_settings(state).await
}

fn right_from_wire(s: &str) -> OpResult<Right> {
    Right::parse(s).ok_or_else(|| OpError::Malformed(format!("`{s}` is not a git right")))
}

fn visibility_from_wire(s: &str) -> OpResult<Visibility> {
    match s {
        "public" => Ok(Visibility::Public),
        "private" => Ok(Visibility::Private),
        other => Err(OpError::Malformed(format!("`{other}` is not a visibility"))),
    }
}

fn to_string_json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn new_row(subject: &str, right: Right, granted_by: &str, subject_member: bool) -> RightRow {
    RightRow {
        subject: subject.to_string(),
        right,
        granted_by: granted_by.to_string(),
        granted_at: now(),
        expires_at: None,
        reason: None,
        subject_was_member: subject_member,
        granter_was_member: true,
    }
}

// ── git-ns/namespace/bind/0.1 ───────────────────────────────────────────────

pub async fn bind(state: &AppState, actor_did: &str, p: bind::Payload) -> OpResult<bind::Response> {
    let actor = standing(state, actor_did).await?;
    // Item 1 — the community-administrator capability. No git right suffices:
    // before binding there are none.
    if !actor.community_admin {
        return Err(OpError::PermissionDenied(
            "binding a namespace needs the community-administrator capability".into(),
        ));
    }
    let forge = p.forge.to_string();
    let owner = p.owner.to_string();
    let mode = match to_string_json(&p.mode).as_str() {
        "bridge" => Mode::Bridge,
        "manual" => Mode::Manual,
        other => return Err(OpError::Malformed(format!("mode `{other}` is not served"))),
    };
    let resource = Resource::namespace(&forge, &owner);

    let bridge_did = {
        let _guard = store::write_lock().await;
        let snap = Snapshot::load(&state.git_ns.ks).await?;
        // Item 2.
        if snap
            .namespaces
            .iter()
            .any(|n| n.forge == forge && n.owner == owner)
        {
            return Err(declared(
                ALREADY_BOUND,
                format!("{resource} is already bound, or being bound, to this VTC"),
            ));
        }
        consent_gate(state, &actor, "namespace.bind", None).await?;
        // Item 3.
        let version = check_policy(
            state,
            PolicyInput {
                action: "namespace.bind",
                actor: &actor,
                actor_rights: vec![],
                resource: &resource,
                right: Some(Right::NsAdmin),
                subject: None,
                visibility: None,
                expires_at: None,
                namespace: None,
            },
        )
        .await?;

        if mode == Mode::Manual {
            // Item 5 — bound at once, and the binder is its first admin.
            let ns = Namespace {
                id: new_id("ns"),
                forge: forge.clone(),
                owner: owner.clone(),
                mode,
                state: NamespaceState::Bound,
                owner_id: None,
                kind: None,
                bridge_did: None,
                bind_job_id: None,
                bound_by: actor.did.clone(),
                requested_at: now(),
                bound_at: Some(now()),
                roles_digest: None,
                installation_removed: false,
                forge_status: None,
            };
            store::put_namespace(&state.git_ns.ks, &ns).await?;
            let scope = Scope::Namespace(ns.id.clone());
            let mut set = store::get_rights(&state.git_ns.ks, &scope).await?;
            set.rows.push(new_row(
                &actor.did,
                Right::NsAdmin,
                &actor.did,
                actor.member,
            ));
            store::put_rights(&state.git_ns.ks, &scope, &set).await?;
            audit(
                state,
                &actor.did,
                None,
                Audit {
                    action: "gitNs.namespace.bound",
                    namespace: Some(&ns.id),
                    resource: Some(resource.to_string()),
                    right: None,
                    policy_version: version,
                    detail: Some("manual".into()),
                },
            )
            .await;
            audit(
                state,
                &actor.did,
                Some(&actor.did),
                Audit {
                    action: "gitNs.right.granted",
                    namespace: Some(&ns.id),
                    resource: Some(resource.to_string()),
                    right: Some(Right::NsAdmin),
                    policy_version: version,
                    detail: Some("binding".into()),
                },
            )
            .await;
            return Ok(wire::into(json!({ "namespace": wire::namespace(&ns) }))?);
        }

        // Item 4 — bridge mode needs a bridge for this forge.
        let bridges = state.config.read().await.git_ns.bridges.clone();
        bridges.get(&forge).cloned().ok_or_else(|| {
            declared(
                NO_BRIDGE,
                format!(
                    "no bridge serving {forge} is configured for this VTC; add \
                     `[git_ns.bridges] \"{forge}\" = \"<bridge DID>\"`, or bind in manual mode"
                ),
            )
        })?
    };

    // The bridge must answer in-line: `next.url` is what this response
    // carries. The lock is not held across the round trip — a slow bridge
    // must not stall every other git-namespace write — so the namespace is
    // recorded only once the bridge has accepted the job (R2.1: nothing local
    // before the remote effect), and the duplicate check is repeated then.
    let ns_id = new_id("ns");
    let job_id = new_id("job");
    let payload = json!({
        "jobId": job_id,
        "namespace": ns_id,
        "kind": "beginBind",
        "target": { "forge": forge, "owner": owner },
    });
    let ack = bridge::send_inline(state, &bridge_did, &payload).await?;
    let next = ack.next.ok_or_else(|| {
        OpError::Unavailable(
            "the bridge accepted the binding but returned nowhere to send you".into(),
        )
    })?;

    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    if snap
        .namespaces
        .iter()
        .any(|n| n.forge == forge && n.owner == owner)
    {
        return Err(declared(
            ALREADY_BOUND,
            format!("{resource} is already bound, or being bound, to this VTC"),
        ));
    }
    let ns = Namespace {
        id: ns_id.clone(),
        forge: forge.clone(),
        owner: owner.clone(),
        mode,
        state: NamespaceState::Pending,
        owner_id: None,
        kind: None,
        bridge_did: Some(bridge_did.clone()),
        bind_job_id: Some(job_id.clone()),
        bound_by: actor.did.clone(),
        requested_at: now(),
        bound_at: None,
        roles_digest: None,
        installation_removed: false,
        forge_status: None,
    };
    store::put_namespace(&state.git_ns.ks, &ns).await?;
    bridge::record_inline_job(
        state,
        &bridge_did,
        &ns_id,
        JobKind::BeginBind,
        payload,
        None,
        None,
    )
    .await?;
    audit(
        state,
        &actor.did,
        None,
        Audit {
            action: "gitNs.namespace.bindRequested",
            namespace: Some(&ns.id),
            resource: Some(resource.to_string()),
            right: None,
            policy_version: None,
            detail: Some("bridge".into()),
        },
    )
    .await;
    Ok(wire::into(json!({
        "namespace": wire::namespace(&ns),
        "next": { "url": next.url },
    }))?)
}

// ── git-ns/namespace/unbind/0.1 ─────────────────────────────────────────────

pub async fn unbind(
    state: &AppState,
    actor_did: &str,
    p: unbind::Payload,
) -> OpResult<unbind::Response> {
    let actor = standing(state, actor_did).await?;
    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let t = now();
    // Item 1.
    let ns = namespace_by_id(&snap, &p.namespace)?.clone();
    let resource = ns.resource();
    // Item 2 — `git.ns.admin` on the namespace, or the community-administrator
    // capability, which could bind it again anyway.
    let holds = rules::effective_on(&snap, &actor.did, &resource, t).contains(&Right::NsAdmin);
    if !holds && !actor.community_admin {
        return Err(OpError::PermissionDenied(format!(
            "unbinding {resource} needs git.ns.admin on it, or the community-administrator \
             capability"
        )));
    }
    consent_gate(state, &actor, "namespace.unbind", None).await?;
    let version = check_policy(
        state,
        PolicyInput {
            action: "namespace.unbind",
            actor: &actor,
            actor_rights: rules::effective_on(&snap, &actor.did, &resource, t)
                .into_iter()
                .collect(),
            resource: &resource,
            right: None,
            subject: None,
            visibility: None,
            expires_at: None,
            namespace: Some(&ns),
        },
    )
    .await?;

    // Item 3 — every record in the namespace, admins included: the invariants
    // do not apply to a namespace that is going away.
    let mut revoked = 0u64;
    let ns_scope = Scope::Namespace(ns.id.clone());
    let mut scopes = vec![(ns_scope.clone(), resource.clone())];
    let repos: Vec<Repo> = snap
        .repos
        .iter()
        .filter(|r| r.namespace_id == ns.id)
        .cloned()
        .collect();
    for r in &repos {
        if let Some(res) = r.resource() {
            scopes.push((Scope::Repo(r.id.clone()), res));
        }
    }
    for (scope, res) in &scopes {
        for row in snap.rows(scope) {
            revoked += 1;
            audit(
                state,
                &actor.did,
                Some(&row.subject),
                Audit {
                    action: "gitNs.right.revoked",
                    namespace: Some(&ns.id),
                    resource: Some(res.to_string()),
                    right: Some(row.right),
                    policy_version: version,
                    detail: Some("unbound".into()),
                },
            )
            .await;
        }
        store::put_rights(&state.git_ns.ks, scope, &Default::default()).await?;
    }
    // Item 4 — detached, and no job to the bridge: removing the app or bot
    // is for a forge owner to do.
    for mut r in repos.clone() {
        r.state = RepoState::Detached;
        r.roles_digest = None;
        store::put_repo(&state.git_ns.ks, &r).await?;
    }
    bridge::cancel_namespace_jobs(state, &ns.id).await?;
    // Item 5.
    store::delete_namespace(&state.git_ns.ks, &ns.id).await?;
    audit(
        state,
        &actor.did,
        None,
        Audit {
            action: "gitNs.namespace.unbound",
            namespace: Some(&ns.id),
            resource: Some(resource.to_string()),
            right: None,
            policy_version: version,
            detail: None,
        },
    )
    .await;
    Ok(wire::into(json!({
        "namespace": ns.id,
        "rightsRevoked": revoked,
        "reposDetached": repos.len(),
    }))?)
}

// ── git-ns/repo/create/0.1 ──────────────────────────────────────────────────

pub async fn repo_create(
    state: &AppState,
    actor_did: &str,
    p: create::Payload,
) -> OpResult<create::Response> {
    let actor = standing(state, actor_did).await?;
    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let t = now();
    // Item 1.
    let ns = namespace_by_id(&snap, &p.namespace)?.clone();
    if ns.state != NamespaceState::Bound {
        return Err(declared(
            NAMESPACE_NOT_BOUND,
            format!(
                "{} is still pending: its binding has not completed",
                ns.resource()
            ),
        ));
    }
    let ns_res = ns.resource();
    // Item 2 — `git.repo.create` on the namespace, explicit or implied.
    let actor_rights = rules::effective_on(&snap, &actor.did, &ns_res, t);
    if !actor_rights.contains(&Right::RepoCreate) {
        return Err(OpError::PermissionDenied(format!(
            "creating a repository in {ns_res} needs git.repo.create on it"
        )));
    }
    let visibility = visibility_from_wire(&to_string_json(&p.visibility))?;
    let name = p.name.to_string();
    let resource = ns_res.child(&name);
    consent_gate(state, &actor, "repo.create", None).await?;
    let version = check_policy(
        state,
        PolicyInput {
            action: "repo.create",
            actor: &actor,
            actor_rights: actor_rights.into_iter().collect(),
            resource: &resource,
            right: Some(Right::RepoOwn),
            subject: None,
            visibility: Some(visibility),
            expires_at: None,
            namespace: Some(&ns),
        },
    )
    .await?;
    // Item 3.
    if snap.repo_at(&resource.to_string()).is_some() {
        return Err(declared(
            NAME_TAKEN,
            format!("this VTC already records a repository at {resource}"),
        ));
    }
    // Item 4 — reserved, and the requester owns the reservation. Published
    // only once active.
    let bot = can_bot_create(&ns);
    let repo = Repo {
        id: new_id("repo"),
        namespace_id: ns.id.clone(),
        resource: resource.to_string(),
        forge_id: None,
        visibility,
        description: p.description.as_ref().map(|d| d.to_string()),
        state: RepoState::PendingCreate,
        created_by: Some(actor.did.clone()),
        created_at: t,
        bootstrap: Bootstrap::default(),
        sync: SyncStatus::new(if bot {
            SyncState::Pending
        } else {
            SyncState::Unchecked
        }),
        failed_step: None,
        last_error: None,
        roles_digest: None,
        forge_report: Default::default(),
    };
    store::put_repo(&state.git_ns.ks, &repo).await?;
    let scope = Scope::Repo(repo.id.clone());
    let mut set = store::get_rights(&state.git_ns.ks, &scope).await?;
    set.rows.push(new_row(
        &actor.did,
        Right::RepoOwn,
        &actor.did,
        actor.member,
    ));
    store::put_rights(&state.git_ns.ks, &scope, &set).await?;
    audit(
        state,
        &actor.did,
        None,
        Audit {
            action: "gitNs.repo.reserved",
            namespace: Some(&ns.id),
            resource: Some(resource.to_string()),
            right: None,
            policy_version: version,
            detail: None,
        },
    )
    .await;
    audit(
        state,
        &actor.did,
        Some(&actor.did),
        Audit {
            action: "gitNs.right.granted",
            namespace: Some(&ns.id),
            resource: Some(resource.to_string()),
            right: Some(Right::RepoOwn),
            policy_version: version,
            detail: Some("creator".into()),
        },
    )
    .await;

    let owners = vec![actor.did.clone()];
    let mut response = json!({ "repo": wire::repo_summary(&repo, &owners) });
    if bot {
        // Item 5 — the bridge creates it and turns commit trust on.
        let mut spec = json!({ "visibility": visibility.as_str() });
        if let Some(d) = &repo.description {
            spec["description"] = json!(d);
        }
        let roles = bridge::desired_roles_for_repo(state, &snap, &ns, &repo, &owners).await?;
        let mut payload = json!({
            "namespace": ns.id,
            "kind": "createRepo",
            "repo": resource.to_string(),
            "spec": spec,
        });
        if !roles.is_empty() {
            payload["desiredRoles"] = json!(roles);
        }
        bridge::enqueue(
            state,
            NewJob {
                namespace_id: ns.id.clone(),
                kind: JobKind::CreateRepo,
                payload,
                repo_id: Some(repo.id.clone()),
                link_id: None,
            },
        )
        .await?;
    } else {
        // Item 6 — the steps a person must take. The last is always to adopt.
        let vtc_did = state
            .config
            .read()
            .await
            .vtc_did
            .clone()
            .unwrap_or_default();
        response["manualSteps"] = json!([
            format!(
                "Create the repository `{}/{}` on {}, {}, with no initial commit.",
                ns.owner,
                name,
                ns.forge,
                visibility.as_str()
            ),
            format!(
                "In a clone of it, run `vgi repo init --vtc {vtc_did} --resource {resource}` to \
                 commit the verify-trust workflow and set its variables and branch protection."
            ),
            format!(
                "Run `cnm git adopt {resource} --owner {}` to tell the VTC the repository exists.",
                actor.did
            ),
        ]);
    }
    Ok(wire::into(response)?)
}

// ── git-ns/repo/adopt/0.1 ───────────────────────────────────────────────────

pub async fn repo_adopt(
    state: &AppState,
    actor_did: &str,
    p: adopt::Payload,
) -> OpResult<adopt::Response> {
    let actor = standing(state, actor_did).await?;
    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let t = now();
    let resource = parse_resource(&p.resource)?;
    // Item 1.
    let ns = bound_namespace_for(&snap, &resource)?.clone();
    // Item 2.
    let existing = snap.repo_at(&resource.to_string()).cloned();
    if let Some(r) = &existing
        && matches!(
            r.state,
            RepoState::Active | RepoState::Orphaned | RepoState::Archived
        )
    {
        return Err(declared(
            ALREADY_MANAGED,
            format!("this VTC already manages {resource}"),
        ));
    }
    // Item 3 — `git.ns.admin`, or an explicit `own` on a `pendingCreate`
    // reservation (the person who ran the manual steps finishing the job).
    let is_admin =
        rules::effective_on(&snap, &actor.did, &ns.resource(), t).contains(&Right::NsAdmin);
    let owns_reservation = existing.as_ref().is_some_and(|r| {
        r.state == RepoState::PendingCreate
            && snap.rows(&Scope::Repo(r.id.clone())).iter().any(|row| {
                row.subject == actor.did && row.right == Right::RepoOwn && row.is_live(t)
            })
    });
    if !is_admin && !owns_reservation {
        return Err(OpError::PermissionDenied(format!(
            "adopting {resource} needs git.ns.admin on {}, or ownership of its reservation",
            ns.resource()
        )));
    }
    if p.owners.is_empty() {
        return Err(OpError::Malformed(
            "a repository always has an owner: name at least one".into(),
        ));
    }
    // Naming owners is a grant of `own` to each, under the same fixed rules
    // and policy as `git-ns/right/grant`.
    let st = settings(state).await;
    if !owns_reservation {
        rules::authority_to_grant(&snap, &actor.did, Right::RepoOwn, &resource, st.rules, t)?;
    }
    consent_gate(state, &actor, "repo.adopt", None).await?;
    let actor_rights: Vec<Right> = rules::effective_on(&snap, &actor.did, &resource, t)
        .into_iter()
        .collect();
    let mut version = None;
    let mut owner_standing = Vec::new();
    for o in &p.owners {
        let s = standing(state, o).await?;
        version = check_policy(
            state,
            PolicyInput {
                action: "repo.adopt",
                actor: &actor,
                actor_rights: actor_rights.clone(),
                resource: &resource,
                right: Some(Right::RepoOwn),
                subject: Some((&s, vec![])),
                visibility: None,
                expires_at: None,
                namespace: Some(&ns),
            },
        )
        .await?;
        owner_standing.push(s);
    }

    // Item 4.
    let mut repo = match existing {
        Some(mut r) => {
            // A detached repository gets no rights back beyond `owners`.
            if r.state != RepoState::PendingCreate {
                store::put_rights(
                    &state.git_ns.ks,
                    &Scope::Repo(r.id.clone()),
                    &Default::default(),
                )
                .await?;
            }
            r.namespace_id = ns.id.clone();
            r
        }
        None => Repo {
            id: new_id("repo"),
            namespace_id: ns.id.clone(),
            resource: resource.to_string(),
            forge_id: None,
            visibility: Visibility::Public,
            description: None,
            state: RepoState::Active,
            created_by: None,
            created_at: t,
            bootstrap: Bootstrap::default(),
            sync: SyncStatus::new(SyncState::Unchecked),
            failed_step: None,
            last_error: None,
            roles_digest: None,
            forge_report: Default::default(),
        },
    };
    repo.state = RepoState::Active;
    repo.roles_digest = None;
    repo.sync = SyncStatus::new(if ns.mode == Mode::Bridge {
        SyncState::Pending
    } else {
        SyncState::Unchecked
    });
    store::put_repo(&state.git_ns.ks, &repo).await?;
    let scope = Scope::Repo(repo.id.clone());
    let mut set = store::get_rights(&state.git_ns.ks, &scope).await?;
    for s in &owner_standing {
        if !set
            .rows
            .iter()
            .any(|r| r.subject == s.did && r.right == Right::RepoOwn && r.is_live(t))
        {
            set.rows
                .retain(|r| !(r.subject == s.did && r.right == Right::RepoOwn));
            set.rows
                .push(new_row(&s.did, Right::RepoOwn, &actor.did, s.member));
            audit(
                state,
                &actor.did,
                Some(&s.did),
                Audit {
                    action: "gitNs.right.granted",
                    namespace: Some(&ns.id),
                    resource: Some(resource.to_string()),
                    right: Some(Right::RepoOwn),
                    policy_version: version,
                    detail: Some("adopted".into()),
                },
            )
            .await;
        }
    }
    store::put_rights(&state.git_ns.ks, &scope, &set).await?;
    audit(
        state,
        &actor.did,
        None,
        Audit {
            action: "gitNs.repo.adopted",
            namespace: Some(&ns.id),
            resource: Some(resource.to_string()),
            right: None,
            policy_version: version,
            detail: None,
        },
    )
    .await;
    // Item 5 — inspect, then bootstrap what is missing (on the result).
    if ns.mode == Mode::Bridge {
        bridge::enqueue(
            state,
            NewJob {
                namespace_id: ns.id.clone(),
                kind: JobKind::Inspect,
                payload: json!({
                    "namespace": ns.id,
                    "kind": "inspect",
                    "repo": resource.to_string(),
                }),
                repo_id: Some(repo.id.clone()),
                link_id: None,
            },
        )
        .await?;
    }
    let owners: Vec<String> = set
        .rows
        .iter()
        .filter(|r| r.right == Right::RepoOwn && r.is_live(t))
        .map(|r| r.subject.clone())
        .collect();
    Ok(wire::into(
        json!({ "repo": wire::repo_summary(&repo, &owners) }),
    )?)
}

// ── git-ns/repo/transfer/0.1 ────────────────────────────────────────────────

pub async fn repo_transfer(
    state: &AppState,
    actor_did: &str,
    p: transfer::Payload,
) -> OpResult<transfer::Response> {
    let actor = standing(state, actor_did).await?;
    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let t = now();
    let resource = parse_resource(&p.resource)?;
    // Item 1.
    let repo = repo_at(&snap, &resource)?.clone();
    if !matches!(repo.state, RepoState::Active | RepoState::Orphaned) {
        return Err(declared(
            REPO_NOT_ACTIVE,
            format!(
                "{resource} is {}; only an active or orphaned repository changes hands",
                repo.state.as_str()
            ),
        ));
    }
    let ns = snap.namespace(&repo.namespace_id).cloned().ok_or_else(|| {
        declared(
            UNKNOWN_NAMESPACE,
            format!("{resource} lies in no bound namespace"),
        )
    })?;
    let scope = Scope::Repo(repo.id.clone());
    // Item 2 — an explicit record to hand over. Implied ownership has none.
    if !snap
        .rows(&scope)
        .iter()
        .any(|r| r.subject == actor.did && r.right == Right::RepoOwn && r.is_live(t))
    {
        return Err(declared(
            NOT_OWNER,
            format!(
                "you hold no explicit git.repo.own record on {resource} to hand over; a namespace \
                 admin names an owner with git-ns/right/grant instead"
            ),
        ));
    }
    let to = p.to.to_string();
    if to == actor.did {
        return Err(declared(SELF_TRANSFER, "`to` is you"));
    }
    let to_standing = standing(state, &to).await?;
    consent_gate(state, &actor, "repo.transfer", Some(Right::RepoOwn)).await?;
    let version = check_policy(
        state,
        PolicyInput {
            action: "repo.transfer",
            actor: &actor,
            actor_rights: rules::effective_on(&snap, &actor.did, &resource, t)
                .into_iter()
                .collect(),
            resource: &resource,
            right: Some(Right::RepoOwn),
            subject: Some((
                &to_standing,
                rules::effective_on(&snap, &to, &resource, t)
                    .into_iter()
                    .collect(),
            )),
            visibility: None,
            expires_at: None,
            namespace: Some(&ns),
        },
    )
    .await?;
    // Item 3 — one write: the grant and the revoke land together or not at
    // all, so the repository never has fewer owners than before.
    let mut set = store::get_rights(&state.git_ns.ks, &scope).await?;
    let to_already = set
        .rows
        .iter()
        .any(|r| r.subject == to && r.right == Right::RepoOwn && r.is_live(t));
    if !to_already {
        set.rows
            .retain(|r| !(r.subject == to && r.right == Right::RepoOwn));
        set.rows
            .push(new_row(&to, Right::RepoOwn, &actor.did, to_standing.member));
    }
    set.rows
        .retain(|r| !(r.subject == actor.did && r.right == Right::RepoOwn));
    store::put_rights(&state.git_ns.ks, &scope, &set).await?;
    let mut repo = repo;
    if repo.state == RepoState::Orphaned {
        repo.state = RepoState::Active;
        store::put_repo(&state.git_ns.ks, &repo).await?;
    }
    if !to_already {
        audit(
            state,
            &actor.did,
            Some(&to),
            Audit {
                action: "gitNs.right.granted",
                namespace: Some(&ns.id),
                resource: Some(resource.to_string()),
                right: Some(Right::RepoOwn),
                policy_version: version,
                detail: Some("transfer".into()),
            },
        )
        .await;
    }
    audit(
        state,
        &actor.did,
        Some(&actor.did),
        Audit {
            action: "gitNs.right.revoked",
            namespace: Some(&ns.id),
            resource: Some(resource.to_string()),
            right: Some(Right::RepoOwn),
            policy_version: version,
            detail: Some("transfer".into()),
        },
    )
    .await;
    let owners: Vec<String> = set
        .rows
        .iter()
        .filter(|r| r.right == Right::RepoOwn && r.is_live(t))
        .map(|r| r.subject.clone())
        .collect();
    Ok(wire::into(
        json!({ "repo": wire::repo_summary(&repo, &owners) }),
    )?)
}

// ── git-ns/repo/archive/0.1 ─────────────────────────────────────────────────

pub async fn repo_archive(
    state: &AppState,
    actor_did: &str,
    p: archive::Payload,
) -> OpResult<archive::Response> {
    let actor = standing(state, actor_did).await?;
    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let t = now();
    let resource = parse_resource(&p.resource)?;
    // Item 1.
    let mut repo = repo_at(&snap, &resource)?.clone();
    if matches!(
        repo.state,
        RepoState::PendingCreate | RepoState::Detached | RepoState::Unmanaged
    ) {
        return Err(declared(
            REPO_NOT_ACTIVE,
            format!(
                "{resource} is {}; there is nothing to archive",
                repo.state.as_str()
            ),
        ));
    }
    let scope = Scope::Repo(repo.id.clone());
    // Item 2 — `own`, explicit or implied by `ns.admin`.
    let actor_rights = rules::effective_on(&snap, &actor.did, &resource, t);
    if !actor_rights.contains(&Right::RepoOwn) {
        return Err(OpError::PermissionDenied(format!(
            "archiving {resource} needs git.repo.own on it"
        )));
    }
    let owners_now = rules::owners(&snap, &repo.id, t);
    // Item 3 — repeating an archive is safe.
    if repo.state == RepoState::Archived {
        return Ok(wire::into(json!({
            "repo": wire::repo_summary(&repo, &owners_now),
            "rightsRevoked": 0,
        }))?);
    }
    let ns = snap.namespace(&repo.namespace_id).cloned();
    consent_gate(state, &actor, "repo.archive", None).await?;
    let version = check_policy(
        state,
        PolicyInput {
            action: "repo.archive",
            actor: &actor,
            actor_rights: actor_rights.into_iter().collect(),
            resource: &resource,
            right: None,
            subject: None,
            visibility: None,
            expires_at: None,
            namespace: ns.as_ref(),
        },
    )
    .await?;
    // Item 4.
    repo.state = RepoState::Archived;
    store::put_repo(&state.git_ns.ks, &repo).await?;
    let mut set = store::get_rights(&state.git_ns.ks, &scope).await?;
    let (gone, kept): (Vec<RightRow>, Vec<RightRow>) = set
        .rows
        .drain(..)
        .partition(|r| r.right == Right::CommitSign);
    set.rows = kept;
    store::put_rights(&state.git_ns.ks, &scope, &set).await?;
    for row in &gone {
        audit(
            state,
            &actor.did,
            Some(&row.subject),
            Audit {
                action: "gitNs.right.revoked",
                namespace: Some(&repo.namespace_id),
                resource: Some(resource.to_string()),
                right: Some(Right::CommitSign),
                policy_version: version,
                detail: Some("archived".into()),
            },
        )
        .await;
    }
    audit(
        state,
        &actor.did,
        None,
        Audit {
            action: "gitNs.repo.archived",
            namespace: Some(&repo.namespace_id),
            resource: Some(resource.to_string()),
            right: None,
            policy_version: version,
            detail: None,
        },
    )
    .await;
    if let Some(ns) = ns.filter(|n| n.mode == Mode::Bridge) {
        bridge::enqueue(
            state,
            NewJob {
                namespace_id: ns.id.clone(),
                kind: JobKind::Archive,
                payload: json!({
                    "namespace": ns.id,
                    "kind": "archive",
                    "repo": resource.to_string(),
                }),
                repo_id: Some(repo.id.clone()),
                link_id: None,
            },
        )
        .await?;
    }
    Ok(wire::into(json!({
        "repo": wire::repo_summary(&repo, &owners_now),
        "rightsRevoked": gone.len(),
    }))?)
}

// ── git-ns/right/grant/0.1 ──────────────────────────────────────────────────

pub async fn right_grant(
    state: &AppState,
    actor_did: &str,
    p: grant::Payload,
) -> OpResult<grant::Response> {
    let actor = standing(state, actor_did).await?;
    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let t = now();
    let resource = parse_resource(&p.resource)?;
    let right = right_from_wire(&to_string_json(&p.right))?;
    let subject = p.subject.to_string();

    // Item 2.
    let ns = bound_namespace_for(&snap, &resource)?.clone();
    // Item 3.
    let scope = if resource.is_namespace() {
        if ns.resource() != resource {
            // Contained by a namespace yet not a repository and not the
            // namespace itself: cannot happen with a two-segment resource,
            // kept as a refusal rather than a panic.
            return Err(declared(
                UNKNOWN_NAMESPACE,
                format!("{resource} is not a bound namespace"),
            ));
        }
        Scope::Namespace(ns.id.clone())
    } else {
        let repo = repo_at(&snap, &resource)?;
        if matches!(
            repo.state,
            RepoState::Archived | RepoState::Detached | RepoState::Unmanaged
        ) {
            return Err(declared(
                REPO_NOT_ACTIVE,
                format!("{resource} is {}; it takes no grants", repo.state.as_str()),
            ));
        }
        Scope::Repo(repo.id.clone())
    };
    // Item 4 — the fixed rules, in order, then policy.
    let st = settings(state).await;
    rules::authority_to_grant(&snap, &actor.did, right, &resource, st.rules, t)?;
    let subject_standing = standing(state, &subject).await?;
    rules::members_only(right, subject_standing.member)?;
    consent_gate(state, &actor, "right.grant", Some(right)).await?;
    let expires_at = p.expires_at;
    let version = check_policy(
        state,
        PolicyInput {
            action: "right.grant",
            actor: &actor,
            actor_rights: rules::effective_on(&snap, &actor.did, &resource, t)
                .into_iter()
                .collect(),
            resource: &resource,
            right: Some(right),
            subject: Some((
                &subject_standing,
                rules::effective_on(&snap, &subject, &resource, t)
                    .into_iter()
                    .collect(),
            )),
            visibility: None,
            expires_at,
            namespace: Some(&ns),
        },
    )
    .await?;
    // Item 5.
    if let Some(e) = expires_at
        && e <= t
    {
        return Err(declared(EXPIRY_IN_PAST, "`expiresAt` is not in the future"));
    }
    // Item 6 — a live record already there is returned unchanged.
    let mut set = store::get_rights(&state.git_ns.ks, &scope).await?;
    if let Some(existing) = set
        .rows
        .iter()
        .find(|r| r.subject == subject && r.right == right && r.is_live(t))
    {
        return Ok(wire::into(json!({
            "right": wire::right_record(existing, &resource, true),
        }))?);
    }
    // Item 7.
    set.rows
        .retain(|r| !(r.subject == subject && r.right == right));
    let mut row = new_row(&subject, right, &actor.did, subject_standing.member);
    row.expires_at = expires_at.map(|e| e.with_nanosecond(0).unwrap_or(e));
    row.reason = p.reason.as_ref().map(|r| r.to_string());
    row.granter_was_member = actor.member;
    set.rows.push(row.clone());
    store::put_rights(&state.git_ns.ks, &scope, &set).await?;
    // A named owner ends an orphaned repository's orphanhood.
    if let Scope::Repo(id) = &scope
        && right == Right::RepoOwn
        && let Some(mut repo) = snap.repo(id).cloned()
        && repo.state == RepoState::Orphaned
    {
        repo.state = RepoState::Active;
        store::put_repo(&state.git_ns.ks, &repo).await?;
    }
    audit(
        state,
        &actor.did,
        Some(&subject),
        Audit {
            action: "gitNs.right.granted",
            namespace: Some(&ns.id),
            resource: Some(resource.to_string()),
            right: Some(right),
            policy_version: version,
            detail: expires_at.map(|_| "expiring".to_string()),
        },
    )
    .await;
    Ok(wire::into(
        json!({ "right": wire::right_record(&row, &resource, true) }),
    )?)
}

// ── git-ns/right/revoke/0.1 ─────────────────────────────────────────────────

pub async fn right_revoke(
    state: &AppState,
    actor_did: &str,
    p: revoke::Payload,
) -> OpResult<revoke::Response> {
    let actor = standing(state, actor_did).await?;
    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let t = now();
    let resource = parse_resource(&p.resource)?;
    let right = right_from_wire(&to_string_json(&p.right))?;
    let subject = p.subject.to_string();
    let not_granted = || {
        declared(
            NOT_GRANTED,
            format!(
                "no live record gives {subject} {right} on {resource}; implied rights are not \
                 records and cannot be revoked"
            ),
        )
    };
    // Item 1.
    let scope = scope_for(&snap, &resource).ok_or_else(not_granted)?;
    let row = snap
        .rows(&scope)
        .iter()
        .find(|r| r.subject == subject && r.right == right && r.is_live(t))
        .cloned()
        .ok_or_else(not_granted)?;
    // Item 2.
    let st = settings(state).await;
    rules::authority_to_revoke(&snap, &actor.did, &row, &resource, st.rules, t)?;
    // Item 3 — resignations too.
    match &scope {
        Scope::Repo(id) => {
            let unmanaged = snap
                .repo(id)
                .is_some_and(|r| r.state == RepoState::Unmanaged);
            if right == Right::RepoOwn && !unmanaged && rules::is_last_owner(&snap, id, &subject, t)
            {
                return Err(declared(
                    LAST_OWNER,
                    format!(
                        "{subject} is the last owner of {resource}; name another owner first, or \
                         transfer with git-ns/repo/transfer"
                    ),
                ));
            }
        }
        Scope::Namespace(id) => {
            let bound = snap
                .namespace(id)
                .is_some_and(|n| n.state == NamespaceState::Bound);
            if right == Right::NsAdmin && bound && rules::is_last_admin(&snap, id, &subject, t) {
                return Err(declared(
                    LAST_ADMIN,
                    format!(
                        "{subject} is the last git.ns.admin of {resource}; grant another first"
                    ),
                ));
            }
        }
    }
    consent_gate(state, &actor, "right.revoke", Some(right)).await?;
    let subject_standing = standing(state, &subject).await?;
    // Item 4.
    let version = check_policy(
        state,
        PolicyInput {
            action: "right.revoke",
            actor: &actor,
            actor_rights: rules::effective_on(&snap, &actor.did, &resource, t)
                .into_iter()
                .collect(),
            resource: &resource,
            right: Some(right),
            subject: Some((&subject_standing, vec![right])),
            visibility: None,
            expires_at: None,
            namespace: snap.scope_namespace(&scope),
        },
    )
    .await?;
    // Item 5.
    let mut set = store::get_rights(&state.git_ns.ks, &scope).await?;
    set.rows
        .retain(|r| !(r.subject == subject && r.right == right));
    store::put_rights(&state.git_ns.ks, &scope, &set).await?;
    audit(
        state,
        &actor.did,
        Some(&subject),
        Audit {
            action: "gitNs.right.revoked",
            namespace: snap.scope_namespace(&scope).map(|n| n.id.as_str()),
            resource: Some(resource.to_string()),
            right: Some(right),
            policy_version: version,
            detail: (actor.did == subject).then(|| "resigned".to_string()),
        },
    )
    .await;
    Ok(wire::into(
        json!({ "revoked": wire::right_record(&row, &resource, true) }),
    )?)
}

// ── git-ns/account/link/0.1 ─────────────────────────────────────────────────

pub async fn account_link(
    state: &AppState,
    actor_did: &str,
    p: link::Payload,
) -> OpResult<link::Response> {
    let actor = standing(state, actor_did).await?;
    // Item 1.
    if !actor.member {
        return Err(OpError::PermissionDenied(
            "linking a forge account is for members of this community".into(),
        ));
    }
    let forge = p.forge.to_string();
    // Item 2.
    let (ns, bridge_did) = {
        let snap = Snapshot::load(&state.git_ns.ks).await?;
        let ns = snap
            .namespaces
            .iter()
            .find(|n| {
                n.forge == forge
                    && n.mode == Mode::Bridge
                    && n.state == NamespaceState::Bound
                    && n.bridge_did.is_some()
            })
            .cloned()
            .ok_or_else(|| {
                declared(
                    UNSUPPORTED_FORGE,
                    format!("this VTC has no bridge-mode namespace on {forge} to complete a link"),
                )
            })?;
        let did = ns.bridge_did.clone().unwrap_or_default();
        (ns, did)
    };
    consent_gate(state, &actor, "account.link", None).await?;
    // Item 3 — in-line: the response is where the member goes next.
    let job_id = new_id("job");
    let payload = json!({
        "jobId": job_id,
        "namespace": ns.id,
        "kind": "beginAccountLink",
        "subject": actor.did,
    });
    let ack = bridge::send_inline(state, &bridge_did, &payload).await?;
    let next = ack.next.ok_or_else(|| {
        OpError::Unavailable("the bridge accepted the link but returned nowhere to send you".into())
    })?;
    let _guard = store::write_lock().await;
    let attempt = LinkAttempt {
        id: new_id("lnk"),
        member: actor.did.clone(),
        forge: forge.clone(),
        namespace_id: ns.id.clone(),
        job_id: job_id.clone(),
        state: LinkState::Pending,
        created_at: now(),
        expires_at: next.expires_at,
        account: None,
        finished_at: None,
    };
    store::put_link(&state.git_ns.ks, &attempt).await?;
    bridge::record_inline_job(
        state,
        &bridge_did,
        &ns.id,
        JobKind::BeginAccountLink,
        payload,
        None,
        Some(attempt.id.clone()),
    )
    .await?;
    let mut out = json!({
        "linkId": attempt.id,
        "url": next.url,
        "expiresAt": wire::timestamp(next.expires_at),
    });
    if let Some(code) = next.user_code {
        out["userCode"] = json!(code.to_string());
    }
    Ok(wire::into(out)?)
}

// ── git-ns/account/link-status/0.1 ──────────────────────────────────────────

pub async fn account_link_status(
    state: &AppState,
    actor_did: &str,
    p: link_status::Payload,
) -> OpResult<link_status::Response> {
    let unknown = || {
        declared(
            UNKNOWN_LINK,
            "no link with this identifier was begun by you, or this VTC no longer remembers it",
        )
    };
    let _guard = store::write_lock().await;
    // The entitlement is having begun the link: anyone else gets the same
    // answer as for an identifier that does not exist.
    let mut attempt = store::get_link(&state.git_ns.ks, &p.link_id)
        .await?
        .filter(|a| a.member == actor_did)
        .ok_or_else(unknown)?;
    if attempt.state == LinkState::Pending && attempt.expires_at <= now() {
        attempt.state = LinkState::Expired;
        attempt.finished_at = Some(now());
        store::put_link(&state.git_ns.ks, &attempt).await?;
    }
    let mut out = json!({ "state": attempt.state.as_str() });
    if attempt.state == LinkState::Linked
        && let Some(a) = &attempt.account
    {
        out["account"] = json!({ "forge": a.forge, "id": a.id, "login": a.login });
    }
    Ok(wire::into(out)?)
}

/// Build the `beginBind` / `beginAccountLink` acknowledgement type's `next`,
/// for [`bridge::send_inline`]'s callers.
pub type JobAck = job_wire::Response;
