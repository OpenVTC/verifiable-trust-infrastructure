//! `… policy …` — raw Rego policy management over the canonical `policy/*`
//! Trust Tasks.
//!
//! This is the power-user surface: hand-authored Rego, for posture the
//! declarative approvals model cannot express. The common case — "this task
//! needs re-authentication / needs a human to approve" — belongs to
//! `… approvals …`, which writes one reserved row through this same family.
//!
//! Transport-agnostic: every call goes through the SDK's `rpc_tt`, so this
//! works on a VTA that advertises only DIDComm or TSP. The step-up policy
//! surface it replaces was REST-only in the SDK, which meant an operator on a
//! mediator-only VTA could not read the policy that was blocking them.

use vta_sdk::prelude::*;
use vta_sdk::protocols::policy_management::{
    DeletePolicyBody, ListPoliciesBody, PolicyModuleView, UpsertPolicyBody,
};

/// `policy list` — enumerate stored policy modules.
pub async fn cmd_list(
    client: &VtaClient,
    context: Option<String>,
    enabled_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client
        .list_policies(ListPoliciesBody {
            context_id: context,
            enabled_only,
            cursor: None,
            page_size: None,
        })
        .await?;

    if crate::render::is_json_output() {
        println!("{}", serde_json::to_string_pretty(&result.policies)?);
        return Ok(());
    }

    if result.policies.is_empty() {
        println!("No policies stored.");
        return Ok(());
    }

    println!(
        "{:<24} {:<8} {:<8} {:<7} {}",
        "ID", "PRIORITY", "ENABLED", "VERSION", "NAME"
    );
    for p in &result.policies {
        println!(
            "{:<24} {:<8} {:<8} {:<7} {}",
            truncate(&p.id, 24),
            p.priority,
            if p.enabled { "yes" } else { "no" },
            p.version,
            p.name
        );
    }
    if result.truncated {
        println!(
            "\n(more policies exist than were returned — this VTA does not page, \
             so nothing further can be listed)"
        );
    }
    Ok(())
}

/// `policy show <id>` — print one policy module, Rego and all.
pub async fn cmd_show(client: &VtaClient, id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let p = client.get_policy(id).await?.policy;
    if crate::render::is_json_output() {
        println!("{}", serde_json::to_string_pretty(&p)?);
        return Ok(());
    }
    print_header(&p);
    println!("\n--- module ---\n{}", p.module);
    if !p.ext.is_null() {
        println!("--- ext ---\n{}", serde_json::to_string_pretty(&p.ext)?);
    }
    Ok(())
}

/// `policy upsert` — create or revise a hand-authored policy.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_upsert(
    client: &VtaClient,
    id: Option<String>,
    name: String,
    module: String,
    description: Option<String>,
    contexts: Vec<String>,
    priority: Option<i32>,
    disabled: bool,
    expected_version: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client
        .upsert_policy(UpsertPolicyBody {
            id,
            name,
            description,
            module,
            applies_to: contexts,
            priority,
            enabled: !disabled,
            expected_version,
            // Only the reserved approvals row carries `ext`, and the VTA
            // refuses it here — hand-authored Rego is not a declarative row.
            ext: serde_json::Value::Null,
        })
        .await?;

    println!(
        "Policy {} ({}):",
        if result.created { "created" } else { "updated" },
        result.policy.id
    );
    print_header(&result.policy);
    Ok(())
}

/// `policy delete <id>` — remove a policy module.
pub async fn cmd_delete(
    client: &VtaClient,
    id: &str,
    expected_version: Option<u64>,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client
        .delete_policy(DeletePolicyBody {
            id: id.to_string(),
            expected_version,
            reason,
        })
        .await?;
    println!("Deleted policy {} at {}", result.id, result.deleted_at);
    Ok(())
}

fn print_header(p: &PolicyModuleView) {
    println!("  ID:        {}", p.id);
    println!("  Name:      {}", p.name);
    if let Some(d) = &p.description {
        println!("  Purpose:   {d}");
    }
    println!("  Priority:  {}", p.priority);
    println!("  Enabled:   {}", if p.enabled { "yes" } else { "no" });
    println!("  Version:   {}", p.version);
    println!(
        "  Contexts:  {}",
        if p.applies_to.is_empty() {
            "all".to_string()
        } else {
            p.applies_to.join(", ")
        }
    );
    println!("  Updated:   {}", p.updated_at);
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{head}…")
}
