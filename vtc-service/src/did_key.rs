use crate::store::keyspaces;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use crate::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use crate::auth::credentials::generate_did_key;
use crate::config::AppConfig;
use crate::store::Store;

pub struct CreateDidKeyArgs {
    pub config_path: Option<PathBuf>,
    pub admin: bool,
    pub label: Option<String>,
}

pub async fn run_create_did_key(args: CreateDidKeyArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&config.store)?;

    let (did, private_key_multibase) = generate_did_key();

    // Optionally create ACL entry
    if args.admin {
        let acl_ks = store.keyspace(keyspaces::ACL)?;
        let entry = VtcAclEntry {
            did: did.clone(),
            role: VtcRole::Admin,
            label: args.label.clone(),
            allowed_contexts: vec![],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            created_by: "cli:create-did-key".into(),
            expires_at: None,
        };
        store_acl_entry(&acl_ks, &entry).await?;
        eprintln!("ACL entry created: {} (admin)", did);
    }

    // Persist all writes
    store.persist().await?;

    eprintln!("DID: {did}");

    // When --admin is set, print a credential bundle to stdout
    if args.admin {
        let vtc_did = config.vtc_did.unwrap_or_default();
        let mut bundle = serde_json::json!({
            "did": did,
            "privateKeyMultibase": private_key_multibase,
            "vtaDid": vtc_did,
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
