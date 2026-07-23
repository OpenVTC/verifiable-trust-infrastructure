use crate::acl::{
    AclEntry, ApproveScope, Role, acl_entry_can_act_in, delete_acl_entry, get_acl_entry,
    list_acl_entries, store_acl_entry,
};
use crate::config::AppConfig;
use crate::store::Store;
use chrono::{TimeZone, Utc};
use dialoguer::Confirm;
use std::path::PathBuf;

/// Create an ACL entry directly in the store.
///
/// **Break-glass: no authorization check is performed.** There is no
/// authenticated caller on this surface — it is direct store access by whoever
/// holds the filesystem — so `validate_role_assignment`,
/// `validate_acl_modification` and `validate_approve_scope_grant` are not
/// consulted. That matches what `run_acl_update` already does, and it is the
/// point of the surface rather than an omission: this is the path that exists
/// when the daemon is down and the online `pnm acl create` cannot be reached.
/// The `Create` help text states it so nobody reads the missing super-admin
/// check as a bug.
///
/// The gap this closes: `vta import-did` was the only offline entry-minting
/// path, and it hardcodes an admin role with empty contexts behind the
/// bootstrap seal. It cannot mint a reader entry and cannot set an approve
/// scope — so with `update` unable to change `approve_scope` either (until
/// now), there was no offline route to an approver entry at all.
#[allow(clippy::too_many_arguments)]
pub async fn run_acl_create(
    config_path: Option<PathBuf>,
    did: String,
    role: String,
    label: Option<String>,
    contexts: Vec<String>,
    expires: Option<String>,
    step_up_approver: Option<String>,
    step_up_require: Option<String>,
    approve_all: bool,
    approve_contexts: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let role = Role::parse(&role)?;
    let expires_at = expires
        .as_deref()
        .map(parse_duration_to_expiry)
        .transpose()?;
    let step_up_require =
        crate::operations::acl::parse_step_up_require(step_up_require.as_deref())?;
    let approve_scope = if approve_all {
        ApproveScope::All
    } else if !approve_contexts.is_empty() {
        ApproveScope::Contexts(approve_contexts)
    } else {
        ApproveScope::None
    };

    // Shape validation still applies — it is not an authorization check. A
    // context id of `""` or `a//b` is unstorable through every other path
    // (#747), and the break-glass surface should not be the one that plants a
    // malformed id in the store.
    for ctx in contexts.iter().chain(match &approve_scope {
        ApproveScope::Contexts(cs) => cs.iter(),
        _ => [].iter(),
    }) {
        vti_common::context_path::validate_context_path(ctx)?;
    }

    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let acl_ks = store.keyspace(crate::keyspaces::ACL)?;

    if get_acl_entry(&acl_ks, &did).await?.is_some() {
        return Err(format!(
            "an ACL entry already exists for {did} — use 'vta acl update' to change it"
        )
        .into());
    }

    let entry = AclEntry::new(&did, role, "vta-cli (break-glass)")
        .with_label(label)
        .with_contexts(contexts)
        .with_expires_at(expires_at)
        .with_step_up_approver(step_up_approver)
        .with_step_up_require(step_up_require)
        .with_approve_scope(approve_scope);

    store_acl_entry(&acl_ks, &entry).await?;
    store.persist().await?;

    eprintln!("ACL entry created:\n");
    print_entry_details(&entry);
    Ok(())
}

/// `N[s|m|h|d|w]` (or bare seconds) from now, as an absolute epoch. Mirrors
/// `vta_cli_common::duration`, which this crate does not depend on.
fn parse_duration_to_expiry(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty --expires value".into());
    }
    let (num, mult) = match s.as_bytes().last().copied() {
        Some(b's') => (&s[..s.len() - 1], 1u64),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3_600),
        Some(b'd') => (&s[..s.len() - 1], 86_400),
        Some(b'w') => (&s[..s.len() - 1], 604_800),
        Some(c) if c.is_ascii_digit() => (s, 1),
        _ => return Err(format!("invalid --expires '{s}' (use N[s|m|h|d|w])").into()),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid --expires number in '{s}'"))?;
    if n == 0 {
        return Err("--expires must be positive".into());
    }
    Ok(crate::auth::session::now_epoch().saturating_add(n.saturating_mul(mult)))
}

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
        // Shared with the online `list_acl` so the two surfaces cannot answer
        // the same question differently. The previous `is_empty() ||
        // contains()` matched an *acts-nowhere* entry under every context.
        entries.retain(|e| acl_entry_can_act_in(e, ctx));
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

/// Resolve the three mutually-exclusive approve flags into a wire value.
/// `None` leaves the scope unchanged; revoking needs its own flag because an
/// empty list cannot mean both "confer nothing" and "don't touch it".
fn approve_scope_from_flags(
    approve_all: bool,
    approve_contexts: Option<Vec<String>>,
    approve_none: bool,
) -> Option<ApproveScope> {
    if approve_none {
        Some(ApproveScope::None)
    } else if approve_all {
        Some(ApproveScope::All)
    } else {
        approve_contexts.map(ApproveScope::Contexts)
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_acl_update(
    config_path: Option<PathBuf>,
    did: String,
    role: Option<String>,
    label: Option<String>,
    contexts: Option<Vec<String>>,
    step_up_approver: Option<String>,
    step_up_require: Option<String>,
    approve_all: bool,
    approve_contexts: Option<Vec<String>>,
    approve_none: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let approve_scope = approve_scope_from_flags(approve_all, approve_contexts, approve_none);
    if role.is_none()
        && label.is_none()
        && contexts.is_none()
        && step_up_approver.is_none()
        && step_up_require.is_none()
        && approve_scope.is_none()
    {
        return Err("nothing to update — specify --role, --label, --contexts, \
             --step-up-approver, --step-up-require, --approve-all, \
             --approve-contexts, or --approve-none"
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

    if let Some(scope) = approve_scope {
        entry.approve_scope = scope;
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
