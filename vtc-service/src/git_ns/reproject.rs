//! `git-ns/roles/reproject/0.1` — a community administrator, a namespace
//! admin, or (for one repository) its owner has the VTC send its bridge the complete forge roles of one
//! repository, or of every active or orphaned repository in a namespace,
//! again.
//!
//! A change of what rights *mean* on the forge — the bridge's role map —
//! otherwise reaches a repository only at its next unrelated projection. The
//! bridge reports such a change (`git-ns/bridge/event/0.3`
//! `roleMapReported`) and the VTC re-projects the repositories it names by
//! itself ([`super::bridge::handle_event`]); this task is the same
//! re-projection, asked for. It records, changes and publishes no right: it
//! forgets the digest of what was last sent, so the next pass of the
//! projector sends each repository's complete `desiredRoles` again.

use serde_json::json;
use trust_tasks_rs::specs::git_ns::roles::reproject::v0_1 as reproject;

use crate::server::AppState;

use super::bridge;
use super::model::{Mode, RepoState, Right};
use super::ops::{
    self, Audit, OpError, OpResult, PolicyInput, audit, check_policy, consent_gate, declared, now,
    standing,
};
use super::rules;
use super::store::{self, Snapshot};
use super::wire;

pub const MANUAL_MODE: &str = reproject::error_codes::MANUAL_MODE.code;
pub const NO_FORGE_ACCESS: &str = reproject::error_codes::NO_FORGE_ACCESS.code;

pub async fn roles_reproject(
    state: &AppState,
    actor_did: &str,
    p: reproject::Payload,
) -> OpResult<reproject::Response> {
    let actor = standing(state, actor_did).await?;
    let reason = p.reason.as_ref().map(|r| r.to_string());
    let (ns, repos) = {
        let _guard = store::write_lock().await;
        let snap = Snapshot::load(&state.git_ns.ks).await?;
        let t = now();
        let resource = ops::parse_resource(&p.resource)?;
        // Step 1.
        let ns = ops::bound_namespace_for(&snap, &resource)?.clone();
        // Step 2 — for a namespace, the capability or `git.ns.admin` by
        // explicit record; for a repository, either of those or
        // `git.repo.own` on it, explicit or implied. Checked before the
        // repository is looked up, so a caller entitled to nothing learns
        // nothing about which names are recorded.
        let explicit_admin = rules::admins(&snap, &ns.id, t).contains(&actor.did);
        let owner = !resource.is_namespace()
            && rules::effective_on(&snap, &actor.did, &resource, t).contains(&Right::RepoOwn);
        let passed =
            rules::reproject_admitted(actor.community_admin, actor.member, explicit_admin, owner)
                .ok_or_else(|| {
                OpError::PermissionDenied(if resource.is_namespace() {
                    format!(
                        "re-projecting every repository in {} needs the community-administrator \
                     capability or git.ns.admin on it by explicit record",
                        ns.resource()
                    )
                } else {
                    format!(
                        "re-projecting {resource} needs git.repo.own on it, git.ns.admin on {} by \
                     explicit record, or the community-administrator capability",
                        ns.resource()
                    )
                })
            })?;
        // Step 3.
        if ns.mode != Mode::Bridge || ns.bridge_did.is_none() {
            return Err(declared(
                MANUAL_MODE,
                format!(
                    "{} is governed in manual mode: no bridge projects its roles",
                    ns.resource()
                ),
            ));
        }
        if ns.installation_removed {
            return Err(declared(
                NO_FORGE_ACCESS,
                format!(
                    "the bridge reported losing its access to {}; re-project once a forge owner \
                     restores it",
                    ns.resource()
                ),
            ));
        }
        // Step 4.
        let covered: Vec<_> = if resource.is_namespace() {
            snap.repos
                .iter()
                .filter(|r| {
                    r.namespace_id == ns.id
                        && matches!(r.state, RepoState::Active | RepoState::Orphaned)
                })
                .cloned()
                .collect()
        } else {
            let repo = ops::repo_at(&snap, &resource)?;
            if !matches!(repo.state, RepoState::Active | RepoState::Orphaned) {
                return Err(declared(
                    ops::REPO_NOT_ACTIVE,
                    format!(
                        "{resource} is {}; roles are projected on an active or orphaned \
                         repository",
                        repo.state.as_str()
                    ),
                ));
            }
            vec![repo.clone()]
        };
        // No right is at stake: the consent class is normal, which the gate
        // passes; kept so a change of class cannot be missed here.
        consent_gate(state, &actor, "roles.reproject", None).await?;
        // Step 5.
        let version = check_policy(
            state,
            PolicyInput {
                action: "roles.reproject",
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
                passed,
            },
        )
        .await?;
        // Step 6 — forget what was sent, under the lock the projector reads
        // under, so its next pass sends each repository's complete set.
        for repo in &covered {
            let mut updated = repo.clone();
            updated.roles_digest = None;
            store::put_repo(&state.git_ns.ks, &updated).await?;
        }
        let repos: Vec<String> = covered.iter().map(|r| r.resource.clone()).collect();
        // Step 7.
        audit(
            state,
            &actor.did,
            None,
            Audit {
                action: "gitNs.roles.reprojected",
                namespace: Some(&ns.id),
                resource: Some(resource.to_string()),
                right: None,
                policy_version: version,
                detail: Some(json!({ "repos": repos, "reason": reason }).to_string()),
            },
        )
        .await;
        (ns, repos)
    };
    // Queue now rather than wait for the projector's tick, so the answer
    // names jobs that exist. `project_roles` recomputes every set from the
    // records and supersedes a queued, unsent job for the same repository.
    if !repos.is_empty() {
        bridge::project_roles(state, false).await?;
    }
    tracing::info!(
        namespace = %ns.id,
        repos = repos.len(),
        "git-ns roles re-projected"
    );
    Ok(wire::into(json!({ "repos": repos }))?)
}
