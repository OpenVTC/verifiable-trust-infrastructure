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
//! (ACL plugin) or the REST `/v1/acl` surface.

use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::acl::{
    VtcAclEntry, VtcRole, delete_acl_entry, get_acl_entry, list_acl_entries, store_acl_entry,
};
use crate::config::AppConfig;
use crate::store::Store;

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
    let store = Store::open(&config.store)?;
    let acl_ks = store.keyspace("acl")?;

    let mut entries = list_acl_entries(&acl_ks).await?;
    if entries.is_empty() {
        println!("No ACL entries.");
        return Ok(());
    }
    entries.sort_by(|a, b| a.did.cmp(&b.did));

    let now = now_epoch();
    println!(
        "   {:<48} {:<14} {:<12} LABEL / CONTEXTS",
        "DID", "ROLE", "EXPIRES"
    );
    for e in &entries {
        let expires = match e.expires_at {
            None => "never".to_string(),
            Some(t) if t <= now => "EXPIRED".to_string(),
            Some(t) => format!("{}s", t - now),
        };
        let mut detail = e.label.clone().unwrap_or_default();
        if !e.allowed_contexts.is_empty() {
            if !detail.is_empty() {
                detail.push_str("  ");
            }
            detail.push_str(&format!("contexts=[{}]", e.allowed_contexts.join(",")));
        }
        println!(
            "   {:<48} {:<14} {:<12} {}",
            e.did,
            e.role.to_string(),
            expires,
            detail
        );
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
    pub contexts: Vec<String>,
    /// Expiry, in seconds from now. `None` → no expiry.
    pub expires: Option<u64>,
}

pub async fn run_acl_add(args: AclAddArgs) -> CliResult {
    // Parse the role first so a typo fails before we touch the store.
    let role = VtcRole::from_str(&args.role)?;

    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&config.store)?;
    let acl_ks = store.keyspace("acl")?;

    let now = now_epoch();
    let existing = get_acl_entry(&acl_ks, &args.did).await?;
    let entry = VtcAclEntry {
        did: args.did.clone(),
        role,
        label: args.label,
        allowed_contexts: args.contexts,
        // Preserve the original creation time on update.
        created_at: existing.as_ref().map(|e| e.created_at).unwrap_or(now),
        created_by: "cli:acl-add".into(),
        expires_at: args.expires.map(|ttl| now.saturating_add(ttl)),
    };
    store_acl_entry(&acl_ks, &entry).await?;
    store.persist().await?;

    println!(
        "{} ACL entry for {} (role {}).",
        if existing.is_some() {
            "Updated"
        } else {
            "Added"
        },
        args.did,
        entry.role
    );
    Ok(())
}

/// `vtc acl remove` — delete the ACL entry for a DID.
pub async fn run_acl_remove(config_path: Option<PathBuf>, did: String) -> CliResult {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let acl_ks = store.keyspace("acl")?;

    if get_acl_entry(&acl_ks, &did).await?.is_none() {
        println!("No ACL entry for {did} — nothing to remove.");
        return Ok(());
    }
    delete_acl_entry(&acl_ks, &did).await?;
    store.persist().await?;
    println!("Removed ACL entry for {did}.");
    Ok(())
}
