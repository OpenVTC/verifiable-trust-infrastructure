//! Runtime Policy Decision Point management — the operations behind the
//! canonical `policy/{list,get,upsert,delete}` Trust Tasks.
//!
//! Before this, the VTA had no runtime policy surface: policy rows were written
//! only by the boot installer, and the sole operator control was editing
//! `config.toml` and restarting. That is why the declarative approvals model
//! now lives in a policy row — it is the first thing that needed to be editable
//! at runtime over whatever transport the VTA actually advertises.
//!
//! # Why writing policy is super-admin, and gateable
//!
//! Whoever can write policy can delete the rule that gates them, so `upsert` and
//! `delete` are super-admin. They are deliberately **not** exempt from the PDP
//! gate: an operator who wants two-person control over changes to the gate
//! itself gets it by writing a `consent` rule for `policy/upsert/0.2`, and that
//! is a feature worth having.
//!
//! The lockout that arrangement risks — approvers whose keys are gone — is
//! answered by the offline break-glass (`vta approvals …`, direct keyspace
//! access with the daemon stopped), not by making the surface ungateable. The
//! same trade the mnemonic-export guard and the Mode-B carve-out make: keep the
//! online path strict, keep one physical-possession escape hatch.

use vta_policy::approvals;
use vta_policy::storage;
use vta_policy::types::PolicyModule;

use vta_sdk::protocols::policy_management::{
    DeletePolicyResultBody, GetPolicyResultBody, ListPoliciesResultBody, PolicyModuleView,
    UpsertPolicyBody, UpsertPolicyResultBody,
};

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Default page size for `policy/list` when the caller names none.
const DEFAULT_PAGE_SIZE: usize = 50;
/// Ceiling on `pageSize`, so one call can't be asked to serialize the world.
const MAX_PAGE_SIZE: usize = 200;

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn view(row: PolicyModule) -> PolicyModuleView {
    PolicyModuleView {
        id: row.id,
        name: row.name,
        description: row.description,
        module: row.module,
        applies_to: row.applies_to,
        priority: row.priority,
        enabled: row.enabled,
        version: row.version,
        created_at: row.created_at,
        updated_at: row.updated_at,
        ext: row.ext,
    }
}

/// `policy/list/0.2`. Auth: admin (reading policy is not a secret-bearing act,
/// but it does disclose the shape of the VTA's defences).
pub async fn list_policies(
    policy_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    context_id: Option<&str>,
    enabled_only: bool,
    page_size: Option<u64>,
    channel: &str,
) -> Result<ListPoliciesResultBody, AppError> {
    auth.require_manage()?;

    let mut rows = storage::list_policies(policy_ks).await?;
    // Deterministic order: priority desc (the order they actually evaluate in),
    // then id, so paging is stable across calls.
    rows.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));

    let mut matching: Vec<PolicyModule> = rows
        .into_iter()
        .filter(|r| !enabled_only || r.enabled)
        .filter(|r| match context_id {
            // An unscoped policy applies everywhere, so it matches every
            // context filter — filtering it out would misreport what governs
            // that context.
            Some(ctx) => r.applies_to.is_empty() || r.applies_to.iter().any(|c| c == ctx),
            None => true,
        })
        .collect();

    let limit = page_size
        .map(|n| (n as usize).clamp(1, MAX_PAGE_SIZE))
        .unwrap_or(DEFAULT_PAGE_SIZE);
    let truncated = matching.len() > limit;
    matching.truncate(limit);

    tracing::info!(
        channel,
        caller = %auth.did,
        count = matching.len(),
        truncated,
        "policy list"
    );
    Ok(ListPoliciesResultBody {
        policies: matching.into_iter().map(view).collect(),
        truncated,
        // Cursor paging is not implemented: the policy set is operator-authored
        // and small (single digits). `truncated` tells a caller to raise
        // `pageSize` rather than promising a cursor that does nothing.
        cursor: None,
    })
}

/// `policy/get/0.1`. Auth: admin.
pub async fn get_policy(
    policy_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    channel: &str,
) -> Result<GetPolicyResultBody, AppError> {
    auth.require_manage()?;
    let row = storage::get_policy(policy_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("policy `{id}` not found")))?;
    tracing::info!(channel, caller = %auth.did, policy = id, "policy get");
    Ok(GetPolicyResultBody { policy: view(row) })
}

/// `policy/upsert/0.2`. Auth: super-admin.
///
/// Order of checks is deliberate: authorize, then validate the *content*, then
/// take the optimistic-concurrency decision, then write. A caller with a stale
/// `expectedVersion` and a broken module should hear about the broken module —
/// it is the thing they can fix without re-reading state.
pub async fn upsert_policy(
    policy_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    req: UpsertPolicyBody,
    channel: &str,
) -> Result<UpsertPolicyResultBody, AppError> {
    auth.require_super_admin()?;

    let id = req
        .id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // A module that does not compile is skipped at load time with an error log,
    // which silently un-gates every task it named. Refuse it at the door.
    vta_policy::compile(&req.module, &id)
        .map_err(|e| AppError::Validation(format!("policy `{id}` does not compile: {e}")))?;

    // The reserved declarative row and the declarative `ext` marker must imply
    // each other. Without both guards, an operator could either overwrite the
    // approvals row with unrelated Rego (leaving `pnm approvals list` reporting
    // rules that no longer decide anything) or stand up a second row claiming
    // to be the model.
    let declares = approvals::is_declarative(&req.ext);
    let is_reserved = id == vta_sdk::approvals::DECLARATIVE_POLICY_ID;
    match (is_reserved, declares) {
        (true, true) => {
            approvals::verify_declarative_row(&req.ext, &req.module)?;
        }
        (true, false) => {
            return Err(AppError::Validation(format!(
                "policy id `{id}` is reserved for the declarative approvals model and must carry \
                 its rules in ext[\"{}\"]. Manage it with `pnm approvals`, or use a different id \
                 for hand-authored Rego.",
                vta_sdk::approvals::EXT_KEY_RULES,
            )));
        }
        (false, true) => {
            return Err(AppError::Validation(format!(
                "only the reserved policy id `{}` may carry ext[\"{}\"]; a second declarative row \
                 would make it ambiguous which rules are in force",
                vta_sdk::approvals::DECLARATIVE_POLICY_ID,
                vta_sdk::approvals::EXT_KEY_RULES,
            )));
        }
        (false, false) => {}
    }

    let existing = storage::get_policy(policy_ks, &id).await?;
    if let Some(expected) = req.expected_version {
        let current = existing.as_ref().map_or(0, |r| r.version);
        if expected != current {
            return Err(AppError::Conflict(format!(
                "policy `{id}` is at version {current}, not the expected {expected} — it changed \
                 since you read it. Re-read it and re-apply your change."
            )));
        }
    }

    let now = now_rfc3339();
    let created = existing.is_none();
    let row = PolicyModule {
        id: id.clone(),
        name: req.name,
        description: req.description,
        module: req.module,
        applies_to: req.applies_to,
        priority: req.priority.unwrap_or(0),
        enabled: req.enabled,
        version: existing.as_ref().map_or(1, |r| r.version + 1),
        created_at: existing
            .as_ref()
            .map_or_else(|| now.clone(), |r| r.created_at.clone()),
        updated_at: now,
        ext: req.ext,
    };
    storage::store_policy(policy_ks, &row).await?;

    crate::audit::record(
        audit_ks,
        "policy.upsert",
        &auth.did,
        Some(&id),
        "success",
        Some(channel),
        None,
    )
    .await
    .ok();
    tracing::info!(
        channel, caller = %auth.did, policy = %id, version = row.version, created,
        "policy upserted"
    );

    Ok(UpsertPolicyResultBody {
        policy: view(row),
        created,
    })
}

/// `policy/delete/0.1`. Auth: super-admin.
pub async fn delete_policy(
    policy_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    expected_version: Option<u64>,
    reason: Option<&str>,
    channel: &str,
) -> Result<DeletePolicyResultBody, AppError> {
    auth.require_super_admin()?;

    // The boot-installed baseline is what every task the operator's own
    // policies do not name falls through to. Deleting it turns the PDP's
    // default-deny into the answer for all of them the moment enforcement is
    // on — and it is only reinstalled when the keyspace is *empty*, so the
    // mistake does not heal on restart.
    if id == vta_policy::defaults::DEFAULT_POLICY_ID {
        return Err(AppError::Validation(format!(
            "`{id}` is the baseline every unmatched task falls through to; deleting it would \
             make the PDP deny them all once enforcement is on, and it is not reinstalled while \
             other policies exist. Disable it (`enabled: false`) if you mean to stop it firing."
        )));
    }

    let existing = storage::get_policy(policy_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("policy `{id}` not found")))?;
    if let Some(expected) = expected_version
        && expected != existing.version
    {
        return Err(AppError::Conflict(format!(
            "policy `{id}` is at version {}, not the expected {expected}",
            existing.version
        )));
    }

    let deleted_at = now_rfc3339();
    storage::delete_policy(policy_ks, id).await?;
    crate::audit::record_with_detail(
        audit_ks,
        "policy.delete",
        &auth.did,
        Some(id),
        "success",
        Some(channel),
        None,
        reason,
    )
    .await
    .ok();
    tracing::info!(channel, caller = %auth.did, policy = id, "policy deleted");

    Ok(DeletePolicyResultBody {
        id: id.to_string(),
        deleted_at,
    })
}
