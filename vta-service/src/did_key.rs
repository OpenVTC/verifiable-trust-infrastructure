use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use dialoguer::Input;

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::config::AppConfig;
use crate::contexts::{self, get_context};
use crate::keys;
use crate::keys::seed_store::create_seed_store;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::store::Store;

pub struct CreateDidKeyArgs {
    pub config_path: Option<PathBuf>,
    pub context: String,
    pub admin: bool,
    pub label: Option<String>,
}

pub async fn run_create_did_key(args: CreateDidKeyArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&config.store)?;
    let keys_ks = store.keyspace("keys")?;
    let contexts_ks = store.keyspace("contexts")?;

    // Load seed from configured backend using the active generation
    let seed_store = create_seed_store(&config)?;
    let active_seed_id = get_active_seed_id(&keys_ks).await?;
    let seed = load_seed_bytes(&keys_ks, &*seed_store, Some(active_seed_id)).await?;

    // Resolve context
    let ctx = match get_context(&contexts_ks, &args.context).await? {
        Some(ctx) => ctx,
        None => {
            eprintln!("Context '{}' does not exist.", args.context);
            let name: String = Input::new()
                .with_prompt("Create it with name")
                .default(args.context.clone())
                .interact_text()?;
            let ctx = contexts::create_context(&contexts_ks, &args.context, &name).await?;
            eprintln!("Created context: {} ({})", ctx.id, ctx.base_path);
            ctx
        }
    };

    let label = args.label.as_deref().unwrap_or("did:key");

    // Derive and store the did:key
    let (did, private_key_multibase) = keys::derive_and_store_did_key(
        &seed,
        &ctx.base_path,
        &ctx.id,
        label,
        &keys_ks,
        Some(active_seed_id),
    )
    .await?;

    // Optionally create ACL entry
    if args.admin {
        let acl_ks = store.keyspace("acl")?;
        let entry = AclEntry::new(did.clone(), Role::Admin, "cli:create-did-key")
            .with_label(args.label.clone())
            .with_contexts(vec![args.context.clone()]);
        store_acl_entry(&acl_ks, &entry).await?;
        eprintln!(
            "ACL entry created: {} (admin, context: {})",
            did, args.context
        );
    }

    // Persist all writes
    store.persist().await?;

    eprintln!("DID: {did}");

    // When --admin is set, print a credential bundle to stdout
    if args.admin {
        let vta_did = config.vta_did.unwrap_or_default();
        let mut bundle = serde_json::json!({
            "did": did,
            "privateKeyMultibase": private_key_multibase,
            "vtaDid": vta_did,
        });
        if let Some(url) = &config.public_url {
            bundle["vtaUrl"] = serde_json::json!(url);
        }
        let bundle_json = serde_json::to_string(&bundle)?;
        let credential = BASE64.encode(bundle_json.as_bytes());
        eprintln!();
        eprintln!("Credential:");
        println!("{credential}");
    }

    Ok(())
}
