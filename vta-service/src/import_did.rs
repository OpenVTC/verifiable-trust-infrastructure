use std::path::PathBuf;

use dialoguer::{Confirm, Select};

use crate::acl::{AclEntry, Role, get_acl_entry, store_acl_entry};
use crate::config::AppConfig;
use crate::store::Store;

pub struct ImportDidArgs {
    pub config_path: Option<PathBuf>,
    pub did: String,
    pub role: Option<String>,
    pub label: Option<String>,
    pub context: Vec<String>,
}

pub async fn run_import_did(args: ImportDidArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&config.store)?;
    let acl_ks = store.keyspace("acl")?;

    // Validate DID format
    if !args.did.starts_with("did:") {
        return Err("invalid DID: must start with \"did:\"".into());
    }

    // Determine role
    let role = match args.role {
        Some(r) => Role::parse(&r)?,
        None => {
            let roles = ["admin", "initiator", "application", "reader"];
            let selection = Select::new()
                .with_prompt("Select role for this DID")
                .items(roles)
                .default(0)
                .interact()?;
            Role::parse(roles[selection])?
        }
    };

    // Check for existing entry
    if let Some(existing) = get_acl_entry(&acl_ks, &args.did).await? {
        eprintln!(
            "ACL entry already exists for {} (role: {})",
            args.did, existing.role
        );
        if !Confirm::new()
            .with_prompt("Overwrite?")
            .default(false)
            .interact()?
        {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    let entry = AclEntry::new(args.did.clone(), role.clone(), "cli:import-did")
        .with_label(args.label.clone())
        .with_contexts(args.context.clone());

    store_acl_entry(&acl_ks, &entry).await?;
    store.persist().await?;

    // Print summary
    eprintln!();
    eprintln!("DID imported: {}", args.did);
    eprintln!("Role: {role}");
    if args.context.is_empty() {
        eprintln!("Contexts: unrestricted");
    } else {
        eprintln!("Contexts: {}", args.context.join(", "));
    }
    if let Some(label) = &args.label {
        eprintln!("Label: {label}");
    }

    // Print connection info for the DID owner
    eprintln!();
    eprintln!("--- Connection info (share with DID owner) ---");
    if let Some(vta_did) = &config.vta_did {
        eprintln!("Community VTA DID: {vta_did}");
    } else {
        eprintln!("Community VTA DID: (not configured)");
    }
    if let Some(url) = &config.public_url {
        eprintln!("Community VTA URL: {url}");
    } else {
        eprintln!("Community VTA URL: (not configured)");
    }

    Ok(())
}
