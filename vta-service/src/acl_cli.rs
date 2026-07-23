use crate::acl::{
    AclEntry, Role, delete_acl_entry, get_acl_entry, list_acl_entries, store_acl_entry,
};
use crate::config::AppConfig;
use crate::store::Store;
use chrono::{TimeZone, Utc};
use dialoguer::Confirm;
use std::path::PathBuf;

pub async fn run_acl_list(
    config_path: Option<PathBuf>,
    context: Option<String>,
    role: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let role_filter = role.map(|r| Role::parse(&r)).transpose()?;

    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let acl_ks = store.keyspace(crate::keyspaces::ACL)?;

    let mut entries = list_acl_entries(&acl_ks).await?;

    // Apply filters
    if let Some(ref role) = role_filter {
        entries.retain(|e| &e.role == role);
    }
    if let Some(ref ctx) = context {
        entries.retain(|e| e.allowed_contexts.is_empty() || e.allowed_contexts.contains(ctx));
    }

    if entries.is_empty() {
        eprintln!("No ACL entries found.");
        return Ok(());
    }

    eprintln!("{} ACL entries:\n", entries.len());
    for entry in &entries {
        eprintln!("  DID:      {}", entry.did);
        eprintln!("  Role:     {}", format_role(entry));
        if let Some(label) = &entry.label {
            eprintln!("  Label:    {label}");
        }
        eprintln!("  Contexts: {}", format_contexts(entry));
        eprintln!("  Created:  {}", format_timestamp(entry.created_at));
        eprintln!();
    }

    Ok(())
}

pub async fn run_acl_get(
    config_path: Option<PathBuf>,
    did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let acl_ks = store.keyspace(crate::keyspaces::ACL)?;

    let entry = get_acl_entry(&acl_ks, &did)
        .await?
        .ok_or_else(|| format!("no ACL entry found for {did}"))?;

    print_entry_details(&entry);
    Ok(())
}

pub async fn run_acl_update(
    config_path: Option<PathBuf>,
    did: String,
    role: Option<String>,
    label: Option<String>,
    contexts: Option<Vec<String>>,
    step_up_approver: Option<String>,
    step_up_require: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if role.is_none()
        && label.is_none()
        && contexts.is_none()
        && step_up_approver.is_none()
        && step_up_require.is_none()
    {
        return Err("nothing to update — specify --role, --label, --contexts, \
             --step-up-approver, or --step-up-require"
            .into());
    }

    let new_role = role.map(|r| Role::parse(&r)).transpose()?;

    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let acl_ks = store.keyspace(crate::keyspaces::ACL)?;

    let mut entry = get_acl_entry(&acl_ks, &did)
        .await?
        .ok_or_else(|| format!("no ACL entry found for {did}"))?;

    if let Some(role) = new_role {
        entry.role = role;
    }
    if let Some(label) = label {
        entry.label = if label.is_empty() { None } else { Some(label) };
    }
    if let Some(contexts) = contexts {
        entry.allowed_contexts = contexts;
    }
    if let Some(approver) = step_up_approver {
        // Empty string clears the delegated approver; any value sets it.
        entry.step_up_approver = if approver.is_empty() {
            None
        } else {
            Some(approver)
        };
    }
    if let Some(require) = step_up_require {
        // Empty string clears the per-entry override; otherwise parse + validate.
        entry.step_up_require = if require.trim().is_empty() {
            None
        } else {
            crate::operations::acl::parse_step_up_require(Some(&require))?
        };
    }

    store_acl_entry(&acl_ks, &entry).await?;
    store.persist().await?;

    eprintln!("ACL entry updated:\n");
    print_entry_details(&entry);
    Ok(())
}

pub async fn run_acl_delete(
    config_path: Option<PathBuf>,
    did: String,
    skip_confirm: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let acl_ks = store.keyspace(crate::keyspaces::ACL)?;

    let entry = get_acl_entry(&acl_ks, &did)
        .await?
        .ok_or_else(|| format!("no ACL entry found for {did}"))?;

    eprintln!("About to delete:\n");
    print_entry_details(&entry);

    if !skip_confirm
        && !Confirm::new()
            .with_prompt("Delete this ACL entry?")
            .default(false)
            .interact()?
    {
        eprintln!("Aborted.");
        return Ok(());
    }

    delete_acl_entry(&acl_ks, &did).await?;
    store.persist().await?;

    eprintln!("ACL entry deleted: {did}");
    Ok(())
}

fn print_entry_details(entry: &AclEntry) {
    eprintln!("  DID:        {}", entry.did);
    eprintln!("  Role:       {}", format_role(entry));
    if let Some(label) = &entry.label {
        eprintln!("  Label:      {label}");
    }
    eprintln!("  Contexts:   {}", format_contexts(entry));
    eprintln!("  Created:    {}", format_timestamp(entry.created_at));
    eprintln!("  Created by: {}", entry.created_by);
    eprintln!();
}

/// Role-aware, for the same reason as the `pnm` copy in
/// `vta-cli-common::commands::acl`: an empty `allowed_contexts` grants every
/// context to an admin (`is_super_admin`) and none to any other role
/// (`has_context_access` iterates the list, and an empty list matches nothing).
/// Rendering both as `(unrestricted)` said the opposite of the truth for every
/// non-admin entry.
fn format_contexts(entry: &AclEntry) -> String {
    if !entry.allowed_contexts.is_empty() {
        return entry.allowed_contexts.join(", ");
    }
    if entry.role == Role::Admin {
        "(unrestricted)".into()
    } else {
        "(none — acts nowhere)".into()
    }
}

fn format_role(entry: &AclEntry) -> String {
    if entry.role == Role::Admin && entry.allowed_contexts.is_empty() {
        "admin (super admin)".into()
    } else {
        entry.role.to_string()
    }
}

fn format_timestamp(epoch: u64) -> String {
    match Utc.timestamp_opt(epoch as i64, 0) {
        chrono::LocalResult::Single(dt) => dt
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S %:z")
            .to_string(),
        _ => format!("{epoch}"),
    }
}
