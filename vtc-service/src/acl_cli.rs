//! Offline ACL management for the `vtc` CLI.
//!
//! `vtc acl {list,add,remove}` — direct fjall access to the `acl`
//! keyspace, no running daemon and no auth ceremony (the operator's
//! filesystem access *is* the authority, same trust model as
//! `vtc create-did-key --admin` and `vtc admin invite`). Run on a
//! **stopped** daemon — fjall takes an exclusive lock, so the commands
//! fail while the server holds the store open. Not for TEE deployments
//! (the store lives behind the vsock proxy there).
//!
//! For online ACL management against a running VTC, use the admin UI
//! (ACL plugin), `cnm`, or the signed `acl/*` Trust Tasks.

use crate::store::keyspaces;
use vta_sdk::display_name::{NameBook, NameSource, shorten_did};

use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::acl::{
    AdminAuthority, AdminRole, CapRef, CapabilityGrant, CapabilityScope, VtcAclEntry, VtcRole,
    delete_acl_entry, get_acl_entry, list_acl_entries, store_acl_entry,
};
use crate::config::AppConfig;

type CliResult = Result<(), Box<dyn std::error::Error>>;

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// `vtc acl list` — print every ACL entry.
pub async fn run_acl_list(config_path: Option<PathBuf>) -> CliResult {
    let config = AppConfig::load(config_path)?;
    let store = crate::store::offline::open_offline(&config.store)?;
    let acl_ks = store.keyspace(keyspaces::ACL)?;

    let mut entries = list_acl_entries(&acl_ks).await?;
    if entries.is_empty() {
        println!("No ACL entries.");
        return Ok(());
    }
    entries.sort_by(|a, b| a.did.cmp(&b.did));

    // Names come from the entries' own labels. Promote them to their own
    // leading column — the label used to be tacked onto the end behind the
    // contexts, which is the last place an operator scans.
    let mut book = NameBook::new();
    for e in &entries {
        book.insert_opt(&e.did, e.label.as_deref(), NameSource::AclLabel);
    }
    let show_names = book.names_any(entries.iter().map(|e| e.did.as_str()));

    let now = now_epoch();
    if show_names {
        println!(
            "   {:<24} {:<44} {:<14} {:<12} ADMINISTRATION",
            "NAME", "DID", "ROLE", "EXPIRES"
        );
    } else {
        println!(
            "   {:<44} {:<14} {:<12} ADMINISTRATION",
            "DID", "ROLE", "EXPIRES"
        );
    }
    for e in &entries {
        let expires = match e.expires_at {
            None => "never".to_string(),
            Some(t) if t <= now => "EXPIRED".to_string(),
            Some(t) => format!("{}s", t - now),
        };
        // The administrative authority, said in words: "everything" only
        // for a community administrator holding its full ceiling, "nothing"
        // for an entry with no administrative role (#746 class: never let two
        // different authorities print alike).
        let contexts = describe_authority(&e.admin);
        let did = shorten_did(&e.did);
        if show_names {
            let name = book.name_of(&e.did).unwrap_or_else(|| "\u{2014}".into());
            println!(
                "   {:<24} {:<44} {:<14} {:<12} {}",
                name,
                did,
                e.role.to_string(),
                expires,
                contexts
            );
        } else {
            println!(
                "   {:<44} {:<14} {:<12} {}",
                did,
                e.role.to_string(),
                expires,
                contexts
            );
        }
    }
    println!(
        "\n{} entr{}.",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" }
    );
    Ok(())
}

/// `vtc acl add` — create or overwrite the ACL entry for a DID.
pub struct AclAddArgs {
    pub config_path: Option<PathBuf>,
    pub did: String,
    pub role: String,
    pub label: Option<String>,
    /// Refused unless empty: a community holds no contexts (VTI-VTC-010).
    pub contexts: Vec<String>,
    /// `--admin-role`: the administrative role. Absent, the one the community
    /// role implies (`admin` → `community-admin`).
    pub admin_role: Option<String>,
    /// `--capability cap[@resource]`, repeatable: narrow the role's ceiling to
    /// these. Absent, the full ceiling.
    pub capabilities: Vec<String>,
    /// Expiry, in seconds from now. `None` → no expiry.
    pub expires: Option<u64>,
}

pub async fn run_acl_add(args: AclAddArgs) -> CliResult {
    // Parse everything first so a typo fails before we touch the store.
    let role = VtcRole::from_str(&args.role)?;
    if !args.contexts.is_empty() {
        return Err(format!(
            "a community holds no contexts (VTI-VTC-010), so --contexts {} cannot be held — \
             narrow administrative authority with --admin-role and --capability instead",
            args.contexts.join(",")
        )
        .into());
    }
    let admin = authority_from_args(&role, args.admin_role.as_deref(), &args.capabilities)?;

    let config = AppConfig::load(args.config_path)?;
    let store = crate::store::offline::open_offline(&config.store)?;
    let acl_ks = store.keyspace(keyspaces::ACL)?;

    let now = now_epoch();
    let existing = get_acl_entry(&acl_ks, &args.did).await?;
    let entry = VtcAclEntry {
        did: args.did.clone(),
        role,
        label: args.label,
        admin,
        // An operator-written entry derives from no granter's authority.
        delegated_by: None,
        // Preserve the original creation time on update.
        created_at: existing.as_ref().map(|e| e.created_at).unwrap_or(now),
        created_by: "cli:acl-add".into(),
        updated_at: None,
        updated_by: None,
        expires_at: args.expires.map(|ttl| now.saturating_add(ttl)),
    };
    store_acl_entry(&acl_ks, &entry).await?;
    // The break-glass bypasses the consent and attrition rules; the daemon
    // audits that it did on its next boot (VTI-APV-014).
    crate::install::record_offline_acl_write(
        &store,
        "vtc acl add",
        "grant",
        &entry.did,
        Some(&entry.role),
        &entry
            .admin
            .effective()
            .iter()
            .map(CapRef::display)
            .collect::<Vec<_>>(),
    )
    .await?;
    store.persist().await?;

    println!(
        "{} ACL entry for {} (role {}; {}).",
        if existing.is_some() {
            "Updated"
        } else {
            "Added"
        },
        args.did,
        entry.role,
        describe_authority(&entry.admin)
    );
    Ok(())
}

/// The administrative authority the offline CLI writes: `--admin-role` (or
/// what the community role implies) at its full ceiling, narrowed to
/// `--capability` grants when any are given. Checked against the role's
/// ceiling like any grant (VTI-ACL-031); the operator is not bounded by a
/// granter (`vtc-admin-roles.md` §2), but an entry that could never be held
/// is still refused.
pub fn authority_from_args(
    role: &VtcRole,
    admin_role: Option<&str>,
    capabilities: &[String],
) -> Result<AdminAuthority, Box<dyn std::error::Error>> {
    let admin_role = match admin_role {
        Some("none" | "member") => None,
        Some(r) => Some(r.parse::<AdminRole>()?),
        None => role.implied_admin_role(),
    };
    let mut admin = match admin_role {
        Some(r) => AdminAuthority::for_role(r),
        None => AdminAuthority::none(),
    };
    if !capabilities.is_empty() {
        let grants = capabilities
            .iter()
            .map(|c| c.parse::<CapRef>().map(CapabilityGrant::from))
            .collect::<Result<Vec<_>, _>>()?;
        admin.capabilities = CapabilityScope::listed(grants)?;
    }
    admin
        .validate_against_ceiling()
        .map_err(|e| e.to_string())?;
    Ok(admin)
}

/// One line saying what an entry may administer.
pub fn describe_authority(admin: &AdminAuthority) -> String {
    let Some(role) = admin.admin_role.as_ref() else {
        return "nothing (no administrative role)".into();
    };
    if !admin.act.is_all() {
        return format!("{role}: acts nowhere (approves only)");
    }
    if *role == AdminRole::CommunityAdmin && admin.capabilities == CapabilityScope::Ceiling {
        return format!("{role}: everything");
    }
    let caps: Vec<String> = admin.effective().iter().map(CapRef::display).collect();
    if caps.is_empty() {
        format!("{role}: nothing")
    } else {
        format!("{role}: {}", caps.join(", "))
    }
}

/// `vtc acl remove` — delete the ACL entry for a DID.
pub async fn run_acl_remove(config_path: Option<PathBuf>, did: String) -> CliResult {
    let config = AppConfig::load(config_path)?;
    let store = crate::store::offline::open_offline(&config.store)?;
    let acl_ks = store.keyspace(keyspaces::ACL)?;

    // A row that does not decode is still a row: removing it is the fix the
    // boot-time ACL migration names for one it cannot map.
    let present = match get_acl_entry(&acl_ks, &did).await {
        Ok(entry) => entry.is_some(),
        Err(_) => true,
    };
    if !present {
        println!("No ACL entry for {did} — nothing to remove.");
        return Ok(());
    }
    delete_acl_entry(&acl_ks, &did).await?;
    crate::install::record_offline_acl_write(&store, "vtc acl remove", "remove", &did, None, &[])
        .await?;
    store.persist().await?;
    println!("Removed ACL entry for {did}.");
    Ok(())
}
