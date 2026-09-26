//! `git-ns/drift/resolve/0.1` — an owner answers one drift item the bridge
//! reported: **adopt** records the forge-side role as a right, exactly as a
//! `git-ns/right/grant` from the resolver would; **revert** has the bridge
//! undo the forge-side change and changes no right.
//!
//! Drift items have no identifier. They are selected by `type`, by the
//! account for the three role types (at most one role item per account), and
//! — required for `adopt` — by the `observed` value the caller last read, so a
//! decision about one forge state is never applied to another.
//!
//! Taking a role the bridge does not manage off a repository (`roleAdded`) is
//! a `projectRoles` job with `removeAccounts`, sent in-line, because a bridge
//! that refuses it must be answered `notRevertible` rather than reported as
//! done. Every other revert is queued. Every job is `git-ns/bridge/job` 0.4.

use serde_json::{Value, json};
use trust_tasks_rs::specs::git_ns::drift::resolve::v0_1 as resolve;
use trust_tasks_rs::specs::git_ns::right::grant::v0_1 as grant;

use crate::server::AppState;

use super::bridge::{self, BridgeSendError, JobKind, NewJob};
use super::model::{Mode, Namespace, OwnerKind, Repo, RepoState, Resource, Right, SyncState};
use super::ops::{
    self, Audit, OpError, OpResult, PolicyInput, audit, check_policy, consent_gate, declared, now,
    standing,
};
use super::rules;
use super::store::{self, Snapshot};
use super::wire;

pub const DRIFT_NOT_FOUND: &str = resolve::error_codes::DRIFT_NOT_FOUND.code;
pub const NOT_ADOPTABLE: &str = resolve::error_codes::NOT_ADOPTABLE.code;
pub const ACCOUNT_NOT_LINKED: &str = resolve::error_codes::ACCOUNT_NOT_LINKED.code;
pub const NO_MATCHING_RIGHT: &str = resolve::error_codes::NO_MATCHING_RIGHT.code;
pub const NOT_REVERTIBLE: &str = resolve::error_codes::NOT_REVERTIBLE.code;

const ROLE_TYPES: [&str; 3] = ["roleAdded", "roleRemoved", "roleChanged"];

/// The selector, as read from the request.
#[derive(Debug, Clone)]
struct Selector {
    kind: String,
    /// `(forge, id)` — `login` is display only.
    account: Option<(String, String)>,
    observed: Option<String>,
}

impl Selector {
    fn matches(&self, item: &Value) -> bool {
        let s = |k: &str| item.get(k).and_then(Value::as_str);
        if s("type") != Some(self.kind.as_str()) {
            return false;
        }
        if let Some((forge, id)) = &self.account {
            let a = item.get("account");
            let af = a.and_then(|a| a.get("forge")).and_then(Value::as_str);
            let ai = a.and_then(|a| a.get("id")).and_then(Value::as_str);
            if af != Some(forge.as_str()) || ai != Some(id.as_str()) {
                return false;
            }
        }
        if let Some(o) = &self.observed
            && s("observed") != Some(o.as_str())
        {
            return false;
        }
        true
    }
}

/// The right the namespace's forge adapter maps to `role` on a repository:
/// the inverse of the mapping `desiredRoles` is projected with (the bridge's
/// `RoleMap` default). On a GitHub or Forgejo organisation `admin` projects
/// `git.repo.own` and `maintain` `git.repo.maintain`; `write` projects
/// `git.commit.sign` only where committers are given `write`, which this VTC
/// is not told, so it projects nothing here. On a personal account `own` and
/// `maintain` both collapse to collaborator `write`, whose projected right is
/// the lower one. `triage` and `read` project nothing.
pub fn projected_right(kind: Option<OwnerKind>, role: &str) -> Option<Right> {
    match (kind, role) {
        (Some(OwnerKind::User), "write") => Some(Right::RepoMaintain),
        (Some(OwnerKind::User), _) => None,
        (_, "admin") => Some(Right::RepoOwn),
        (_, "maintain") => Some(Right::RepoMaintain),
        _ => None,
    }
}

fn sync_json(repo: &Repo) -> Value {
    let mut v = json!({ "state": repo.sync.state.as_str(), "drift": repo.sync.drift });
    if let Some(at) = repo.sync.checked_at {
        v["checkedAt"] = json!(wire::timestamp(at));
    }
    v
}

/// What phase one decided, carried to the writes.
struct Decided {
    ns: Namespace,
    repo: Repo,
    resource: Resource,
    selector: Selector,
    items: Vec<Value>,
}

pub async fn drift_resolve(
    state: &AppState,
    actor_did: &str,
    p: resolve::Payload,
) -> OpResult<resolve::Response> {
    let actor = standing(state, actor_did).await?;
    let action = serde_json::to_value(p.action)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let reason = p.reason.as_ref().map(|r| r.to_string());

    // Steps 2 to 5, under the store lock, on one snapshot.
    let d = {
        let _guard = store::write_lock().await;
        let snap = Snapshot::load(&state.git_ns.ks).await?;
        let t = now();
        let resource = ops::parse_resource(&p.resource)?;
        // Step 2.
        let ns = ops::bound_namespace_for(&snap, &resource)?.clone();
        let repo = ops::repo_at(&snap, &resource)?.clone();
        if !matches!(repo.state, RepoState::Active | RepoState::Orphaned) {
            return Err(declared(
                ops::REPO_NOT_ACTIVE,
                format!(
                    "{resource} is {}; drift is resolved on an active or orphaned repository",
                    repo.state.as_str()
                ),
            ));
        }
        // Step 3 — `git.repo.own`, explicit or implied.
        if !rules::effective_on(&snap, &actor.did, &resource, t).contains(&Right::RepoOwn) {
            return Err(OpError::PermissionDenied(format!(
                "resolving drift on {resource} is an owner's decision: it needs git.repo.own \
                 there, explicit or implied"
            )));
        }
        // Step 4.
        let kind = serde_json::to_value(p.drift.type_)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        let is_role = ROLE_TYPES.contains(&kind.as_str());
        match (&p.drift.account, is_role) {
            (None, true) => {
                return Err(OpError::Malformed(format!(
                    "a `{kind}` item is selected by its account; `drift.account` is required"
                )));
            }
            (Some(_), false) => {
                return Err(OpError::Malformed(format!(
                    "a `{kind}` item has no account; leave `drift.account` out"
                )));
            }
            _ => {}
        }
        if action == "adopt" && p.drift.observed.is_none() {
            return Err(OpError::Malformed(
                "`adopt` records a right derived from the observed role, so `drift.observed` \
                 — as you read it — is required"
                    .into(),
            ));
        }
        let selector = Selector {
            kind,
            account: p
                .drift
                .account
                .as_ref()
                .map(|a| (a.forge.to_string(), a.id.to_string())),
            observed: p.drift.observed.as_ref().map(|o| o.to_string()),
        };
        // Step 5.
        let items: Vec<Value> = repo
            .sync
            .drift
            .iter()
            .filter(|i| selector.matches(i))
            .cloned()
            .collect();
        if items.is_empty() {
            return Err(declared(
                DRIFT_NOT_FOUND,
                format!(
                    "no outstanding `{}` drift on {resource} matches: resolved already, changed \
                     on the forge since you read it, or never reported",
                    selector.kind
                ),
            ));
        }
        Decided {
            ns,
            repo,
            resource,
            selector,
            items,
        }
    };

    let right = if action == "adopt" {
        Some(adopt(state, &actor, &d, reason.clone()).await?)
    } else {
        revert(state, &actor, &d).await?;
        None
    };

    // Step 8 — record it, and take the item off the outstanding drift.
    let repo = {
        let _guard = store::write_lock().await;
        let mut repo = store::get_repo(&state.git_ns.ks, &d.repo.id)
            .await?
            .unwrap_or_else(|| d.repo.clone());
        repo.sync.drift.retain(|i| !d.selector.matches(i));
        repo.sync.state = if repo.sync.drift.is_empty() {
            SyncState::Pending
        } else {
            SyncState::Drift
        };
        store::put_repo(&state.git_ns.ks, &repo).await?;
        repo
    };
    let detail = json!({
        "action": action,
        "items": d.items,
        "reason": reason,
    });
    audit(
        state,
        &actor.did,
        None,
        Audit {
            action: "gitNs.drift.resolved",
            namespace: Some(&d.ns.id),
            resource: Some(d.resource.to_string()),
            right: right.as_ref().and_then(|r| {
                r.get("right")
                    .and_then(Value::as_str)
                    .and_then(Right::parse)
            }),
            policy_version: None,
            detail: Some(detail.to_string()),
        },
    )
    .await;
    // Step 9 — confirm rather than assume.
    bridge::enqueue(
        state,
        NewJob {
            namespace_id: d.ns.id.clone(),
            kind: JobKind::Inspect,
            payload: json!({ "namespace": d.ns.id, "kind": "inspect", "repo": d.resource.to_string() }),
            repo_id: Some(d.repo.id.clone()),
            link_id: None,
        },
    )
    .await?;

    let mut body = json!({ "action": action, "sync": sync_json(&repo) });
    if let Some(r) = right {
        body["right"] = r;
    }
    Ok(wire::into(body)?)
}

/// *Adopt*, steps 1 to 6.
async fn adopt(
    state: &AppState,
    actor: &ops::Standing,
    d: &Decided,
    reason: Option<String>,
) -> OpResult<Value> {
    let item = &d.items[0];
    // Step 1.
    if d.selector.kind != "roleAdded" && d.selector.kind != "roleChanged" {
        return Err(declared(
            NOT_ADOPTABLE,
            format!(
                "a `{}` item records no right; revert it, or revoke with git-ns/right/revoke",
                d.selector.kind
            ),
        ));
    }
    // Step 2 — whose account it is.
    let (forge, id) = d.selector.account.clone().unwrap_or_default();
    let accounts = bridge::linked_accounts(state).await?;
    let member = accounts
        .iter()
        .find(|(_, forges)| forges.get(&forge).is_some_and(|a| a.id == id))
        .map(|(did, _)| did.clone());
    let Some(member) = member else {
        return Err(declared(
            ACCOUNT_NOT_LINKED,
            format!("{forge} account {id} is not linked to a member; it can only be reverted"),
        ));
    };
    if !standing(state, &member).await?.member {
        return Err(declared(
            ACCOUNT_NOT_LINKED,
            format!("{forge} account {id} is not linked to a current member"),
        ));
    }
    // Step 3.
    let observed = item.get("observed").and_then(Value::as_str).unwrap_or("");
    let Some(right) = projected_right(d.ns.kind, observed) else {
        return Err(declared(
            NO_MATCHING_RIGHT,
            format!(
                "no git right projects to `{observed}` on {}; revert it, or grant a right and \
                 then revert the role",
                d.resource
            ),
        ));
    };
    // Step 4 — a forge-side lowering is accepted by revoking, not adopting.
    if d.selector.kind == "roleChanged" {
        let snap = Snapshot::load(&state.git_ns.ks).await?;
        let held = rules::effective_on(&snap, &member, &d.resource, now())
            .into_iter()
            .filter(|r| matches!(r, Right::RepoOwn | Right::RepoMaintain | Right::CommitSign))
            .map(Right::rank)
            .max()
            .unwrap_or(0);
        if right.rank() <= held {
            return Err(declared(
                NOT_ADOPTABLE,
                format!(
                    "`{observed}` is no higher than what the member already holds on {}; accept \
                     a lowering with git-ns/right/revoke",
                    d.resource
                ),
            ));
        }
    }
    // Step 5 — exactly as the resolver's own grant.
    let mut payload = json!({
        "subject": member,
        "right": right.as_str(),
        "resource": d.resource.to_string(),
    });
    if let Some(r) = reason {
        payload["reason"] = json!(r);
    }
    let grant: grant::Payload = serde_json::from_value(payload)
        .map_err(|e| OpError::Malformed(format!("the adopted right does not fit a grant: {e}")))?;
    // Exactly as the resolver's grant — but said to the policy as an adoption
    // (`via: drift.adopt`), and only while the item is still outstanding as
    // it was selected, checked under the lock the grant is written under: a
    // forge that changed since the item was read adopts nothing.
    let repo_id = d.repo.id.clone();
    let selector = d.selector.clone();
    let still_holds = move |snap: &Snapshot| -> OpResult<()> {
        let outstanding = snap
            .repo(&repo_id)
            .is_some_and(|r| r.sync.drift.iter().any(|i| selector.matches(i)));
        if outstanding {
            Ok(())
        } else {
            Err(declared(
                DRIFT_NOT_FOUND,
                "the drift item changed while it was being adopted; read it again",
            ))
        }
    };
    let granted = ops::right_grant_via(
        state,
        &actor.did,
        grant,
        Some(ops::GrantVia {
            via: "drift.adopt",
            still_holds: &still_holds,
        }),
    )
    .await?;
    // Step 6 — the complete desired roles, now with the member at the right.
    force_role_projection(state, &d.repo.id).await?;
    Ok(serde_json::to_value(granted.right).map_err(vti_common::error::AppError::from)?)
}

/// Make the projector send the repository's complete `desiredRoles` again.
async fn force_role_projection(state: &AppState, repo_id: &str) -> OpResult<()> {
    {
        let _guard = store::write_lock().await;
        if let Some(mut repo) = store::get_repo(&state.git_ns.ks, repo_id).await? {
            repo.roles_digest = None;
            store::put_repo(&state.git_ns.ks, &repo).await?;
        }
    }
    bridge::project_roles(state, false).await?;
    Ok(())
}

/// *Revert*.
async fn revert(state: &AppState, actor: &ops::Standing, d: &Decided) -> OpResult<()> {
    let item = &d.items[0];
    let observed = item.get("observed").and_then(Value::as_str).unwrap_or("");
    // Removing or lowering the role `own` projects to has the impact of
    // revoking `own`; any other revert at most that of revoking `maintain`.
    let impact = if ROLE_TYPES.contains(&d.selector.kind.as_str())
        && d.selector.kind != "roleRemoved"
        && projected_right(d.ns.kind, observed) == Some(Right::RepoOwn)
    {
        Right::RepoOwn
    } else {
        Right::RepoMaintain
    };
    let (Mode::Bridge, Some(bridge_did)) = (d.ns.mode, d.ns.bridge_did.clone()) else {
        return Err(declared(
            NOT_REVERTIBLE,
            format!(
                "{} is governed in manual mode: no bridge can undo a forge-side change",
                d.ns.resource()
            ),
        ));
    };
    {
        let snap = Snapshot::load(&state.git_ns.ks).await?;
        let passed = rules::drift_revert_admitted(&snap, &actor.did, &d.resource, now())?;
        consent_gate(state, actor, "right.revoke", Some(impact)).await?;
        check_policy(
            state,
            PolicyInput {
                action: "drift.revert",
                actor,
                actor_rights: rules::effective_on(&snap, &actor.did, &d.resource, now())
                    .into_iter()
                    .collect(),
                resource: &d.resource,
                right: Some(impact),
                subject: None,
                visibility: None,
                expires_at: None,
                namespace: Some(&d.ns),
                passed,
            },
        )
        .await?;
    }

    match d.selector.kind.as_str() {
        "roleAdded" => {
            // `removeAccounts`, and only here.
            let snap = Snapshot::load(&state.git_ns.ks).await?;
            let roles = bridge::desired_roles_now(state, &snap, &d.ns, &d.repo).await?;
            let account = item.get("account").cloned().unwrap_or(Value::Null);
            let (forge, id) = d.selector.account.clone().unwrap_or_default();
            // An account listed at `git.ns.admin` — a namespace admin with no
            // right of their own here — is projected to no role, so its forge
            // role may be taken off; `git-ns/bridge/job` 0.4 lets
            // `removeAccounts` name it, and a bridge before 0.4 is sent no
            // such entry at all.
            if roles.iter().any(|r| {
                r.pointer("/account/forge").and_then(Value::as_str) == Some(forge.as_str())
                    && r.pointer("/account/id").and_then(Value::as_str) == Some(id.as_str())
                    && r.get("right").and_then(Value::as_str) != Some(Right::NsAdmin.as_str())
            }) {
                // Never revert by changing the projection: this account is a
                // member's, holding a right here.
                return Err(declared(
                    NOT_REVERTIBLE,
                    "that account belongs to a member the projection gives a role here; adopt \
                     the forge-side role, or revoke the member's right",
                ));
            }
            let payload = json!({
                "jobId": super::model::new_id("job"),
                "namespace": d.ns.id,
                "kind": "projectRoles",
                "repo": d.resource.to_string(),
                "desiredRoles": roles,
                "removeAccounts": [account],
            });
            match bridge::send_job_inline(state, &bridge_did, &payload).await {
                Ok(_) => {
                    bridge::record_inline_job(
                        state,
                        &bridge_did,
                        &d.ns.id,
                        JobKind::ProjectRoles,
                        payload,
                        Some(d.repo.id.clone()),
                        None,
                    )
                    .await?;
                }
                Err(BridgeSendError::Rejected { code, message }) => {
                    return Err(declared(
                        NOT_REVERTIBLE,
                        format!("the bridge refused the revert ({code}: {message})"),
                    ));
                }
                Err(BridgeSendError::Outdated(m)) => {
                    return Err(declared(NOT_REVERTIBLE, m));
                }
                Err(BridgeSendError::Transient(m)) => {
                    return Err(OpError::Unavailable(format!(
                        "the bridge {bridge_did} did not answer: {m}"
                    )));
                }
            }
        }
        "roleChanged" | "roleRemoved" => {
            // 0.1 suffices: the complete desiredRoles list the account at
            // its projected level.
            force_role_projection(state, &d.repo.id).await?;
        }
        "requiredCheckMissing" | "protectionWeakened" => {
            bootstrap(state, d, Some(vec!["requiredCheck"])).await?;
        }
        _ => {
            // bootstrapMissing: the whole plan, which changes only what is
            // missing.
            bootstrap(state, d, None).await?;
        }
    }
    Ok(())
}

async fn bootstrap(state: &AppState, d: &Decided, steps: Option<Vec<&str>>) -> OpResult<()> {
    let mut payload = json!({
        "namespace": d.ns.id,
        "kind": "bootstrap",
        "repo": d.resource.to_string(),
    });
    if let Some(s) = steps {
        payload["steps"] = json!(s);
    }
    bridge::enqueue(
        state,
        NewJob {
            namespace_id: d.ns.id.clone(),
            kind: JobKind::Bootstrap,
            payload,
            repo_id: Some(d.repo.id.clone()),
            link_id: None,
        },
    )
    .await?;
    Ok(())
}
