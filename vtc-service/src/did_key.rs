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

    // When --admin is set, print a credential bundle to stdout.
    //
    // This is the canonical `vta_sdk::CredentialBundle` shape — the same
    // envelope a VTA emits — so the CLI importer parses VTC- and
    // VTA-issued admin credentials with one type. The bundle's
    // `vtaDid` / `vtaUrl` fields name the *issuing authority*; for a
    // VTC-issued credential that authority is this VTC, so we pass the
    // VTC's own DID / URL. (Not a copy-paste bug — building via the
    // typed bundle keeps it from drifting out of the shared contract,
    // whose `deny_unknown_fields` would reject a renamed key.)
    if args.admin {
        let vtc_did = config.vtc_did.unwrap_or_default();
        let mut bundle = vta_sdk::credentials::CredentialBundle::new(
            did.clone(),
            private_key_multibase,
            vtc_did,
        );
        if let Some(url) = &config.public_url {
            bundle = bundle.vta_url(url.clone());
        }
        let bundle_json = serde_json::to_string(&bundle)?;
        let credential = BASE64.encode(bundle_json.as_bytes());
        eprintln!();
        eprintln!("Credential:");
        println!("{credential}");
    }

    Ok(())
}
