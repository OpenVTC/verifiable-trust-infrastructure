//! `git-ns/drift/resolve` — an owner answers one drift item the bridge
//! reported: **adopt** records the forge-side role as a right for the member
//! the resolver names, exactly as a `git-ns/right/grant` from the resolver
//! would; **revert** has the bridge undo the forge-side change and changes no
//! right.
//!
//! Served at 0.3, and at 0.1 for `revert` only. A 0.3 adopt carries
//! `subject`, the member the resolver read as linked to the item's account,
//! and adopts only while the account is still linked to exactly that member
//! (`subjectChanged` otherwise), checked again under the store lock the right
//! is written under — the same lock every link and unlink is written under
//! (`bridge::handle_event`, `lifecycle::sweep_departures`), so no relink can
//! fall between the check and the write. A 0.1 adopt names no recipient, and
//! the VTC would have to pick one from the link as it stands when the task
//! runs, which may not be the member the resolver saw; it is refused
//! (`unsupportedVersion`) rather than granted to someone nobody named
//! (drift/resolve 0.3, *Security & Privacy*, "Binding the recipient").
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
use trust_tasks_rs::specs::git_ns::drift::resolve::{v0_1 as resolve1, v0_3 as resolve};
use trust_tasks_rs::specs::git_ns::right::grant::v0_1 as grant;

use crate::server::AppState;
use vti_common::error::AppError;

use super::bridge::{self, BridgeSendError, JobKind, NewJob};
use super::model::{Mode, Namespace, Repo, RepoState, Resource, Right, SyncState};
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
pub const SUBJECT_CHANGED: &str = resolve::error_codes::SUBJECT_CHANGED.code;
pub const SELF_GRANT_NOT_ALLOWED: &str = resolve::error_codes::SELF_GRANT_NOT_ALLOWED.code;
/// `git-ns:roleMapUnknown`, a namespace-wide code. The 0.1 and 0.2 specs
/// declare it; 0.3 (authored in parallel) does not re-declare it, so it is
/// taken from 0.1's generated codes. An adopt under either version is refused
/// with it while the bridge has not reported its role map.
pub const ROLE_MAP_UNKNOWN: &str = resolve1::error_codes::ROLE_MAP_UNKNOWN.code;

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

/// The right the namespace's bridge maps to `role` on `repo`: the *projected
/// right of a role* of `git-ns/drift/resolve`, the **lowest** right whose
/// role in the role map the bridge reported (`git-ns/bridge/event/0.3`
/// `roleMapReported`, see [`super::role_map`]) is `role`. With the default
/// map on an organisation `admin` projects `git.repo.own` and `maintain`
/// `git.repo.maintain`; on a personal account `own` and `maintain` both
/// collapse to collaborator `write`, whose projected right is the lower one.
/// `git.ns.admin` is never a projected right: a namespace admin projects to
/// no forge role.
///
/// `Ok(None)`: no right projects to `role`. Refused with
/// `git-ns:roleMapUnknown` while the serving bridge has not reported its
/// map: no map, the default included, is assumed (request step 5.7).
pub fn projected_right(ns: &Namespace, repo: &str, role: &str) -> OpResult<Option<Right>> {
    super::role_map::projected_right(ns, repo, role).map_err(|_| {
        declared(
            ROLE_MAP_UNKNOWN,
            format!(
                "the bridge serving {} has not reported its role map yet, so this VTC cannot \
                 tell which right a forge `{role}` projects; adopt once it has reported \
                 (it does when it starts serving the namespace and whenever its link comes \
                 up), or revert the role",
                ns.resource()
            ),
        )
    })
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
    /// For `adopt`: the member the resolver named.
    subject: Option<String>,
}

/// `git-ns/drift/resolve/0.1`: `revert` only. A 0.1 document is a 0.3 one
/// without `subject`, answered in 0.1's own response shape (identical to
/// 0.3's).
pub async fn drift_resolve_v1(
    state: &AppState,
    actor_did: &str,
    p: resolve1::Payload,
) -> OpResult<resolve1::Response> {
    if matches!(p.action, resolve1::PayloadAction::Adopt) {
        return Err(OpError::UnsupportedVersion(
            "an adoption over git-ns/drift/resolve 0.1 names no recipient, so this VTC would \
             grant the right to whoever the account is linked to now, who may not be the member \
             you saw. Adopt with git-ns/drift/resolve 0.3, which names the member (`subject`); \
             0.1 still reverts"
                .into(),
        ));
    }
    let p3: resolve::Payload = wire::into(serde_json::to_value(&p).map_err(AppError::from)?)?;
    let r = drift_resolve(state, actor_did, p3).await?;
    Ok(wire::into(
        serde_json::to_value(&r).map_err(AppError::from)?,
    )?)
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
        match (action.as_str(), &p.subject) {
            ("adopt", None) => {
                return Err(OpError::Malformed(
                    "`adopt` records a right for the member you read as linked to the account, \
                     so `subject` — that member's DID — is required"
                        .into(),
                ));
            }
            ("revert", Some(_)) => {
                return Err(OpError::Malformed(
                    "a `revert` changes no right and has no recipient; leave `subject` out".into(),
                ));
            }
            _ => {}
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
            subject: p.subject.as_ref().map(|s| s.to_string()),
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
    // Step 3 (0.3) — the member the resolver named, and nobody else.
    let named = d.subject.clone().unwrap_or_default();
    if member != named {
        return Err(subject_changed(&forge, &id));
    }
    if !standing(state, &member).await?.member {
        return Err(declared(
            ACCOUNT_NOT_LINKED,
            format!("{forge} account {id} is not linked to a current member"),
        ));
    }
    // Step 4.
    let observed = item.get("observed").and_then(Value::as_str).unwrap_or("");
    let Some(right) = projected_right(&d.ns, &d.repo.resource, observed)? else {
        return Err(declared(
            NO_MATCHING_RIGHT,
            format!(
                "no git right projects to `{observed}` on {}; revert it, or grant a right and \
                 then revert the role",
                d.resource
            ),
        ));
    };
    // Step 5 (0.3) — a forge-side lowering is accepted by revoking, not
    // adopting. Compared with the member's *projected* right — what the
    // forge is meant to show for them, from rights in their own name — not
    // their effective rights: a namespace admin projects to no forge role, so
    // one who holds `maintain` here can adopt a forge `admin` as `own`.
    if d.selector.kind == "roleChanged" {
        let snap = Snapshot::load(&state.git_ns.ks).await?;
        let held = bridge::projected_repo_right(&snap, &d.ns, &d.repo, &member, now())
            .map(Right::rank)
            .unwrap_or(0);
        if right.rank() <= held {
            return Err(declared(
                NOT_ADOPTABLE,
                format!(
                    "`{observed}` projects no higher than the member is already projected at on \
                     {}; accept a lowering with git-ns/right/revoke",
                    d.resource
                ),
            ));
        }
    }
    // Step 6 (0.3) — separation of duties: nobody adopts an elevated right
    // for themselves — elevated as the role map makes it (`is_elevated_in`):
    // where maintainers get forge `admin`, `maintain` is elevated too. `actor.did` is the DID the signer was resolved to,
    // after any console-key delegation (`tasks::acting_as`), so a
    // console key cannot adopt for its admin what the admin could not adopt
    // themselves. Fixed: it runs before policy, which cannot waive it.
    if member == actor.did && right.is_elevated_in(&d.ns, &d.repo.resource) {
        // Break-glass carries only ns.admin, repo.create and own, so a right
        // elevated only by the map is pointed at another owner.
        let way = if right.is_elevated() {
            "ask another owner or namespace admin to adopt it, or, if nobody else can, break \
             the glass with git-ns/right/break-glass, which is audited and shown to every \
             administrator until another one ratifies or revokes it"
        } else {
            "the bridge's role map gives it the forge's admin role here (or the bridge has not \
             reported its map). Ask another owner or namespace admin to adopt it"
        };
        return Err(declared(
            SELF_GRANT_NOT_ALLOWED,
            format!(
                "adopting this role would record {right} on {} for you, and {right} is an \
                 elevated right you cannot grant yourself: {way}",
                d.resource
            ),
        ));
    }
    // Step 7 — exactly as the resolver's own grant.
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
    let link = ops::LinkedTo {
        forge: forge.clone(),
        id: id.clone(),
        member: named.clone(),
    };
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
            linked_to: Some(&link),
        }),
    )
    .await?;
    // Step 8 — the complete desired roles, now with the member at the right.
    force_role_projection(state, &d.repo.id).await?;
    Ok(serde_json::to_value(granted.right).map_err(vti_common::error::AppError::from)?)
}

/// The account's link no longer resolves to the member the adoption names.
pub(super) fn subject_changed(forge: &str, id: &str) -> OpError {
    declared(
        SUBJECT_CHANGED,
        format!(
            "{forge} account {id} is linked to another member than the one this adoption names; \
             read the drift item again and decide about the member it now names"
        ),
    )
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
    // Removing or lowering the role `own` projects to (or one above it) has
    // the impact of revoking `own`; any other revert at most that of revoking
    // `maintain`. While the map is unknown, any role but `none` might be
    // `own`'s, so every such revert weighs as revoking `own`.
    let impact = if ROLE_TYPES.contains(&d.selector.kind.as_str())
        && d.selector.kind != "roleRemoved"
        && super::role_map::revert_takes_ownership(&d.ns, &d.repo.resource, observed)
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
