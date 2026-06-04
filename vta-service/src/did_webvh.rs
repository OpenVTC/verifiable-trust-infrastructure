use std::path::PathBuf;
use std::sync::Arc;

use dialoguer::{Confirm, Input, Select};
use serde_json::json;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};
use vta_sdk::protocols::did_management::create::WebvhPathMode;

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
}

pub async fn run_create_did_webvh(
    args: CreateDidWebvhArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&config.store)?;
    let keys_ks = store.keyspace("keys")?;
    let imported_ks = store.keyspace("imported_secrets")?;
    let contexts_ks = store.keyspace("contexts")?;
    let webvh_ks = store.keyspace("webvh")?;
    let did_templates_ks = store.keyspace("did_templates")?;

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

    // Prompt for URL
    let webvh_url = setup::prompt_webvh_url(label)?;
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

    // Interactive service endpoint selection
    if let Some(ref msg) = config.messaging {
        let service_options = &[
            "DIDComm endpoint (references mediator DID for routing)",
            "No service endpoints",
        ];
        let service_choice = Select::new()
            .with_prompt("Service endpoints")
            .items(service_options)
            .default(0)
            .interact()?;

        if service_choice == 0 {
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

    // Offer to edit in $EDITOR
    if Confirm::new()
        .with_prompt("Edit DID document in your editor?")
        .default(false)
        .interact()?
    {
        did_document = edit_did_document(did_document)?;
    }

    // Portability
    let portable = Confirm::new()
        .with_prompt("Make this DID portable (can move to a different domain later)?")
        .default(true)
        .interact()?;

    // Pre-rotation count
    let pre_rotation_count: u32 = Input::new()
        .with_prompt("Number of pre-rotation keys (0 = none, recommended: 1-3)")
        .default(1u32)
        .interact_text()?;

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

    let result = operations::did_webvh::create_did_webvh(
        &keys_ks,
        &imported_ks,
        &contexts_ks,
        &webvh_ks,
        &did_templates_ks,
        &*seed_store,
        &config,
        &auth,
        params,
        &did_resolver,
        &no_bridge,
        "cli",
    )
    .await?;

    let final_did = &result.did;
    eprintln!("\x1b[1;32mCreated DID:\x1b[0m {final_did}");

    // Persist all writes
    store.persist().await?;

    // Save did.jsonl
    if let Some(ref log_entry) = result.log_entry {
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
    }

    // Optionally export secrets bundle
    if Confirm::new()
        .with_prompt("Export DID secrets bundle?")
        .default(false)
        .interact()?
    {
        // Fetch key secrets via the operations layer
        let signing_secret = crate::operations::keys::get_key_secret(
            &keys_ks,
            &imported_ks,
            &Arc::from(seed_store),
            &store.keyspace("audit")?,
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
                &store.keyspace("audit")?,
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
