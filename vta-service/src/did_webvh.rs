use std::path::PathBuf;
use std::sync::Arc;

use dialoguer::{Confirm, Input, Select};
use didwebvh_rs::url::WebVHURL;
use serde_json::json;
use url::Url;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};
use vta_sdk::protocols::did_management::create::WebvhPathMode;

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::config::AppConfig;
use crate::keys::seed_store::create_seed_store;
use crate::operations;
use crate::operations::did_webvh::CreateDidWebvhParams;
use crate::setup;
use crate::store::Store;
use crate::webvh_cli::cli_super_admin;

pub struct CreateDidWebvhArgs {
    pub config_path: Option<PathBuf>,
    pub context: String,
    pub label: Option<String>,
    /// Hosting URL. When `Some`, the command runs fully non-interactive.
    pub url: Option<String>,
    /// Emit the `DidSecretsBundle` JSON to stdout and skip interactive prompts.
    pub export_secrets: bool,
    /// Create an ACL admin entry for the new DID in the target context.
    pub admin: bool,
}

pub async fn run_create_did_webvh(
    args: CreateDidWebvhArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&config.store)?;
    let keys_ks = store.keyspace(crate::keyspaces::KEYS)?;
    let imported_ks = store.keyspace(crate::keyspaces::IMPORTED_SECRETS)?;
    let contexts_ks = store.keyspace(crate::keyspaces::CONTEXTS)?;
    let webvh_ks = store.keyspace(crate::keyspaces::WEBVH)?;
    let did_templates_ks = store.keyspace(crate::keyspaces::DID_TEMPLATES)?;

    // Resolve context
    let ctx = match crate::contexts::get_context(&contexts_ks, &args.context).await? {
        Some(ctx) => ctx,
        None => {
            eprintln!("Context '{}' does not exist.", args.context);
            let name: String = Input::new()
                .with_prompt("Create it with name")
                .default(args.context.clone())
                .interact_text()?;
            let ctx = crate::contexts::create_context(&contexts_ks, &args.context, &name).await?;
            eprintln!("Created context: {} ({})", ctx.id, ctx.base_path);
            ctx
        }
    };

    let label = args.label.as_deref().unwrap_or(&args.context);

    // `--url` selects fully non-interactive mode: no hosting-URL prompt, no
    // save-log prompt, no export-secrets confirm, and no DID-document
    // edit/portability/pre-rotation prompts. Without it, behave interactively
    // exactly as before.
    let interactive = args.url.is_none();

    // Resolve the hosting URL: from `--url` (non-interactive) or by prompting.
    let webvh_url = match &args.url {
        Some(raw) => {
            let parsed = Url::parse(raw).map_err(|e| format!("invalid --url `{raw}`: {e}"))?;
            WebVHURL::parse_url(&parsed)
                .map_err(|e| format!("invalid did:webvh hosting URL `{raw}`: {e}"))?
        }
        None => setup::prompt_webvh_url(label)?,
    };
    let url_str = webvh_url
        .get_http_url(None)
        .map_err(|e| format!("{e}"))?
        .to_string();

    // Build base DID document using shared helper (without services)
    let seed_store = create_seed_store(&config)?;
    let seed = crate::keys::seeds::load_seed_bytes(
        &keys_ks,
        &*seed_store,
        Some(
            crate::keys::seeds::get_active_seed_id(&keys_ks)
                .await
                .map_err(|e| format!("{e}"))?,
        ),
    )
    .await
    .map_err(|e| format!("{e}"))?;

    // Derive keys temporarily just to build a preview document
    let derived = crate::keys::derive_entity_keys(
        &seed,
        &ctx.base_path,
        &format!("{label} signing key"),
        &format!("{label} key-agreement key"),
        &keys_ks,
    )
    .await?;

    let mut did_document =
        operations::did_webvh::build_did_document(&derived, &config, false, &None);

    // Service endpoint selection. Interactive: prompt. Non-interactive:
    // advertise the DIDComm mediator endpoint when messaging is configured
    // (the same default as the interactive prompt).
    if let Some(ref msg) = config.messaging {
        let want_didcomm = if interactive {
            let service_options = &[
                "DIDComm endpoint (references mediator DID for routing)",
                "No service endpoints",
            ];
            Select::new()
                .with_prompt("Service endpoints")
                .items(service_options)
                .default(0)
                .interact()?
                == 0
        } else {
            true
        };

        if want_didcomm {
            did_document["service"] = json!([
                {
                    "id": "{DID}#vta-didcomm",
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": [{
                        "accept": ["didcomm/v2"],
                        "uri": msg.mediator_did
                    }]
                }
            ]);
        }
    }

    eprintln!();
    eprintln!(
        "\x1b[2mDID Document:\n{}\x1b[0m",
        serde_json::to_string_pretty(&did_document)?
    );
    eprintln!();

    // Offer to edit in $EDITOR (interactive only).
    if interactive
        && Confirm::new()
            .with_prompt("Edit DID document in your editor?")
            .default(false)
            .interact()?
    {
        did_document = edit_did_document(did_document)?;
    }

    // Portability (interactive prompt; non-interactive uses the prompt default).
    let portable = if interactive {
        Confirm::new()
            .with_prompt("Make this DID portable (can move to a different domain later)?")
            .default(true)
            .interact()?
    } else {
        true
    };

    // Pre-rotation count (interactive prompt; non-interactive uses the default).
    let pre_rotation_count: u32 = if interactive {
        Input::new()
            .with_prompt("Number of pre-rotation keys (0 = none, recommended: 1-3)")
            .default(1u32)
            .interact_text()?
    } else {
        1
    };

    // Build params and call the operations layer
    let auth = cli_super_admin();
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let no_bridge: Arc<crate::didcomm_bridge::DIDCommBridge> =
        Arc::new(crate::didcomm_bridge::DIDCommBridge::placeholder());

    let params = CreateDidWebvhParams {
        context_id: args.context.clone(),
        server_id: None,
        url: Some(url_str.clone()),
        // Serverless (`server_id: None`) ignores `path_mode`.
        path_mode: WebvhPathMode::default(),
        domain: None,
        label: Some(label.to_string()),
        portable,
        add_mediator_service: false, // handled via did_document template
        additional_services: None,
        pre_rotation_count,
        did_document: Some(did_document),
        did_log: None,
        set_primary: true,
        signing_key_id: None,
        ka_key_id: None,
        template: None,
        template_context: None,
        template_vars: std::collections::HashMap::new(),
        // `vta create-did-webvh` is the runtime integration-DID CLI — not
        // used to mint the VTA's own identity (that's setup wizard /
        // setup --from / TEE autogen).
        is_vta_identity: false,
    };

    let deps = operations::did_webvh::CreateDidWebvhDeps {
        keys_ks: &keys_ks,
        imported_ks: &imported_ks,
        contexts_ks: &contexts_ks,
        webvh_ks: &webvh_ks,
        did_templates_ks: &did_templates_ks,
        seed_store: &*seed_store,
        config: &config,
        did_resolver: &did_resolver,
        didcomm_bridge: &no_bridge,
    };
    let result = operations::did_webvh::create_did_webvh(&deps, &auth, params, "cli").await?;

    let final_did = &result.did;
    eprintln!("\x1b[1;32mCreated DID:\x1b[0m {final_did}");

    // Optionally grant the new DID admin in the target context. Mirrors
    // `create-did-key --admin` (`vta-service/src/did_key.rs`): same
    // `AclEntry::new(..).with_label(..).with_contexts(..)` +
    // `store_acl_entry` call, scoped to the target context.
    if args.admin {
        let acl_ks = store.keyspace(crate::keyspaces::ACL)?;
        let entry = AclEntry::new(final_did.clone(), Role::Admin, "cli:create-did-webvh")
            .with_label(args.label.clone())
            .with_contexts(vec![args.context.clone()]);
        store_acl_entry(&acl_ks, &entry).await?;
        eprintln!(
            "ACL entry created: {final_did} (admin, context: {})",
            args.context
        );
    }

    // Persist all writes (DID + optional ACL entry)
    store.persist().await?;

    // Save did.jsonl. Interactive: prompt for the filename. Non-interactive
    // (`--url`): no prompt — the operator wanted automation, and stdout is
    // reserved for the secrets bundle, so we only note the log on stderr.
    if let Some(ref log_entry) = result.log_entry {
        if interactive {
            let default_file = format!("{label}-did.jsonl");
            let did_file: String = Input::new()
                .with_prompt("Save DID log to file")
                .default(default_file)
                .interact_text()?;

            std::fs::write(&did_file, log_entry)?;
            eprintln!("  DID log saved to: {did_file}");
            eprintln!("  Context '{}' updated with DID: {final_did}", args.context);
            eprintln!();
            eprintln!("  \x1b[2mTo self-host this DID, upload {did_file} to:");
            eprintln!("  {url_str}\x1b[0m");
        } else {
            eprintln!("  Context '{}' updated with DID: {final_did}", args.context);
            eprintln!("  \x1b[2mDID log (did.jsonl) ready; self-host at: {url_str}\x1b[0m");
        }
    }

    // Optionally export secrets bundle. `--export-secrets` forces it
    // unconditionally (no confirm); interactively, prompt. Non-interactive
    // without the flag emits nothing on stdout.
    let want_export = if args.export_secrets {
        true
    } else if interactive {
        Confirm::new()
            .with_prompt("Export DID secrets bundle?")
            .default(false)
            .interact()?
    } else {
        false
    };
    if want_export {
        // Fetch key secrets via the operations layer
        let signing_secret = crate::operations::keys::get_key_secret(
            &keys_ks,
            &imported_ks,
            &Arc::from(seed_store),
            &store.keyspace(crate::keyspaces::AUDIT)?,
            &auth,
            &result.signing_key_id,
            "cli",
        )
        .await
        .map_err(|e| format!("failed to fetch signing key secret: {e}"))?;

        let mut secrets = vec![SecretEntry {
            key_id: result.signing_key_id.clone(),
            key_type: vta_sdk::keys::KeyType::Ed25519,
            private_key_multibase: signing_secret.private_key_multibase,
        }];

        if !result.ka_key_id.is_empty() {
            let ka_secret = crate::operations::keys::get_key_secret(
                &keys_ks,
                &imported_ks,
                &Arc::from(create_seed_store(&config)?),
                &store.keyspace(crate::keyspaces::AUDIT)?,
                &auth,
                &result.ka_key_id,
                "cli",
            )
            .await
            .map_err(|e| format!("failed to fetch KA key secret: {e}"))?;

            secrets.push(SecretEntry {
                key_id: result.ka_key_id.clone(),
                key_type: vta_sdk::keys::KeyType::X25519,
                private_key_multibase: ka_secret.private_key_multibase,
            });
        }

        let bundle = DidSecretsBundle {
            did: final_did.clone(),
            secrets,
        };
        // Local operator export to stdout: JSON, not base64. The base64
        // wrapper offered no integrity or confidentiality — the OS
        // filesystem (for redirected output) or terminal scrollback is the
        // only protection here. Pretty-printed JSON is easier to audit
        // and indexes cleanly into secure storage.
        let json = serde_json::to_string_pretty(&bundle)?;
        eprintln!();
        eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  WARNING: The secrets bundle contains private keys.      ║");
        eprintln!("║  Redirect to a file with restrictive permissions.        ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
        eprintln!();
        println!("{json}");
        eprintln!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::get_acl_entry;
    use crate::keys::seeds::{SeedRecord, save_seed_record, set_active_seed_id};
    use vti_common::acl::Role;

    /// `vta create-did-webvh --url <URL> --admin --export-secrets` must run
    /// fully non-interactive and, in one shot:
    ///   * mint a did:webvh with #key-0 (Ed25519 signing) + #key-1 (X25519
    ///     key-agreement),
    ///   * create an ACL **admin** entry for that DID, scoped to the context,
    ///   * (export-secrets emits the bundle to stdout — verified by the
    ///     vta-sdk `secrets_from_bundle` tests; here we assert the store-side
    ///     effects that prove the non-interactive + ACL wiring).
    ///
    /// Gated on `config-seed` so the seed store is the in-config backend (no
    /// OS keyring), making the test hermetic. Run with:
    /// `cargo test -p vta-service --bin vta --features config-seed`.
    #[cfg(feature = "config-seed")]
    #[tokio::test]
    async fn create_did_webvh_url_admin_export_is_noninteractive_and_grants_admin() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let config_path = dir.path().join("config.toml");

        // Minimal config: local store + a config-seed backend carrying a
        // fixed hex seed (dev/test only; selected ahead of keyring in the
        // factory). No messaging, so the DID gets no DIDComm service.
        let seed_hex = hex::encode([7u8; 64]);
        std::fs::write(
            &config_path,
            format!(
                "[store]\ndata_dir = \"{}\"\n\n[secrets]\nseed = \"{seed_hex}\"\n",
                data_dir.display()
            ),
        )
        .unwrap();

        // Bootstrap the seed generation record (the bytes live in the
        // config-seed backend); record generation 0 as active.
        let config = AppConfig::load(Some(config_path.clone())).expect("load config");
        let store = Store::open(&config.store).expect("open store");
        let keys_ks = store.keyspace(crate::keyspaces::KEYS).unwrap();
        let contexts_ks = store.keyspace(crate::keyspaces::CONTEXTS).unwrap();

        save_seed_record(
            &keys_ks,
            &SeedRecord {
                id: 0,
                seed_hex: None,
                seed_enc: None,
                created_at: chrono::Utc::now(),
                retired_at: None,
            },
        )
        .await
        .unwrap();
        set_active_seed_id(&keys_ks, 0).await.unwrap();

        // Create the target context up-front (so no "create context?" prompt).
        crate::contexts::create_context(&contexts_ks, "agents", "Agents")
            .await
            .unwrap();
        store.persist().await.unwrap();
        // Release the fjall lock fully before the command opens its own Store.
        drop(keys_ks);
        drop(contexts_ks);
        drop(store);

        // Run fully non-interactive: --url set, --admin, --export-secrets.
        let args = CreateDidWebvhArgs {
            config_path: Some(config_path.clone()),
            context: "agents".to_string(),
            label: Some("agent-1".to_string()),
            url: Some("https://example.com/agents/agent-1".to_string()),
            export_secrets: true,
            admin: true,
        };
        run_create_did_webvh(args).await.expect("create-did-webvh");

        // Reopen the store and assert the side effects.
        let store = Store::open(&config.store).expect("reopen store");
        let webvh_ks = store.keyspace(crate::keyspaces::WEBVH).unwrap();
        let acl_ks = store.keyspace(crate::keyspaces::ACL).unwrap();

        // Exactly one did:webvh was created, with #key-0 + #key-1 records.
        let dids = crate::webvh_store::list_dids(&webvh_ks).await.unwrap();
        assert_eq!(dids.len(), 1, "one did:webvh minted");
        let did = &dids[0].did;
        assert!(did.starts_with("did:webvh:"), "got {did}");

        let keys_ks2 = store.keyspace(crate::keyspaces::KEYS).unwrap();
        let key0: Option<crate::keys::KeyRecord> = keys_ks2
            .get(crate::keys::store_key(&format!("{did}#key-0")))
            .await
            .unwrap();
        let key1: Option<crate::keys::KeyRecord> = keys_ks2
            .get(crate::keys::store_key(&format!("{did}#key-1")))
            .await
            .unwrap();
        assert!(key0.is_some(), "#key-0 (signing) record present");
        assert!(key1.is_some(), "#key-1 (key-agreement) record present");
        assert_eq!(key1.unwrap().key_type, crate::keys::KeyType::X25519);

        // The ACL admin entry exists for the new DID, scoped to the context.
        let entry = get_acl_entry(&acl_ks, did)
            .await
            .unwrap()
            .expect("ACL entry created for the did:webvh");
        assert_eq!(entry.role, Role::Admin);
        assert_eq!(entry.allowed_contexts, vec!["agents".to_string()]);
    }
}

fn edit_did_document(
    doc: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::process::Command;

    let json = serde_json::to_string_pretty(&doc)?;

    // Write to a named temp file with .json extension for editor syntax highlighting
    let mut tmp = tempfile::Builder::new().suffix(".json").tempfile()?;
    tmp.write_all(json.as_bytes())?;
    tmp.flush()?;
    let path = tmp.path().to_path_buf();

    // Resolve editor: $VISUAL > $EDITOR > fallback
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());

    // Open editor and wait
    let status = Command::new(&editor)
        .arg(&path)
        .status()
        .map_err(|e| format!("failed to launch editor '{editor}': {e}"))?;

    if !status.success() {
        return Err(format!("editor exited with {status}").into());
    }

    // Read back and parse
    let edited = std::fs::read_to_string(&path)?;
    let new_doc: serde_json::Value =
        serde_json::from_str(&edited).map_err(|e| format!("invalid JSON from editor: {e}"))?;

    // Basic validation: must be an object with "id" field
    if !new_doc.is_object() || !new_doc.get("id").is_some_and(|v| v.is_string()) {
        return Err("DID document must be a JSON object with an \"id\" field".into());
    }

    // Show the updated document
    eprintln!(
        "\x1b[2mUpdated DID Document:\n{}\x1b[0m",
        serde_json::to_string_pretty(&new_doc)?
    );

    Ok(new_doc)
}
