//! Interactive setup wizard (`vta setup`).
//!
//! Prompts the operator for every configuration knob — config path, VTA
//! name, services, seed-store backend, mnemonic confirmation, DIDComm
//! mediator setup, VTA DID creation — then writes a `config.toml` and
//! exits. Uses `dialoguer` for prompts; the non-interactive counterpart
//! in [`super::from_toml`] mirrors every step without prompts.
//!
//! Module-private by design: only [`run_setup_wizard`] is pub. Everything
//! else is an implementation detail.

use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use bip39::Mnemonic;
use chrono::Utc;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use rand::Rng;
use serde_json::json;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

use crate::config::{
    AppConfig, AuditConfig, AuthConfig, LogConfig, LogFormat, MessagingConfig, SecretsConfig,
    ServerConfig, ServicesConfig, StoreConfig,
};
use crate::contexts::store_context;
use crate::keys::seed_store::create_seed_store;
use crate::keys::seeds::{SeedRecord, save_seed_record, set_active_seed_id};
use crate::operations;
use crate::operations::did_webvh::CreateDidWebvhParams;
use crate::store::{KeyspaceHandle, Store};
use crate::webvh_cli::cli_super_admin;

use super::{create_seed_context, generate_mnemonic_silent, prompt_webvh_url};

/// Prompt the user to select which services to enable.
///
/// Returns `(rest_enabled, didcomm_enabled)`. At least one must be selected.
fn prompt_services() -> Result<(bool, bool), Box<dyn std::error::Error>> {
    let items = vec!["REST API", "DIDComm Messaging"];
    loop {
        let selected = MultiSelect::new()
            .with_prompt("Services to enable (select at least one)")
            .items(&items)
            .defaults(&[true, true])
            .interact()?;

        if selected.is_empty() {
            eprintln!("\x1b[31mPlease select at least one service.\x1b[0m");
            continue;
        }

        let rest = selected.contains(&0);
        let didcomm = selected.contains(&1);
        return Ok((rest, didcomm));
    }
}

/// Prompt for seed store backend configuration based on compiled features.
///
/// Dynamically builds a list of available backends and lets the user choose
/// when more than one is compiled. Supported backends:
/// - **aws-secrets**: AWS Secrets Manager
/// - **gcp-secrets**: GCP Secret Manager
/// - **config-seed**: hex-encoded seed stored in config.toml
/// - **keyring**: OS keyring (the default)
async fn configure_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let mut labels: Vec<&str> = Vec::new();
    let mut tags: Vec<&str> = Vec::new();

    #[cfg(feature = "aws-secrets")]
    {
        labels.push("AWS Secrets Manager");
        tags.push("aws");
    }

    #[cfg(feature = "gcp-secrets")]
    {
        labels.push("GCP Secret Manager");
        tags.push("gcp");
    }

    #[cfg(feature = "azure-secrets")]
    {
        labels.push("Azure Key Vault");
        tags.push("azure");
    }

    #[cfg(feature = "vault-secrets")]
    {
        labels.push("HashiCorp Vault");
        tags.push("vault");
    }

    #[cfg(feature = "config-seed")]
    {
        labels.push("Config file (hex-encoded seed in config.toml)");
        tags.push("config");
    }

    #[cfg(feature = "keyring")]
    {
        labels.push("OS keyring");
        tags.push("keyring");
    }

    labels.push("Plaintext file (NOT recommended)");
    tags.push("plaintext");

    // If only one backend is compiled, use it without prompting
    let choice = if labels.len() == 1 {
        0
    } else {
        Select::new()
            .with_prompt("Seed storage backend")
            .items(&labels)
            .default(0)
            .interact()?
    };

    let tag = tags[choice];

    #[cfg(feature = "aws-secrets")]
    if tag == "aws" {
        return prompt_aws_secrets().await;
    }

    #[cfg(feature = "gcp-secrets")]
    if tag == "gcp" {
        return prompt_gcp_secrets().await;
    }

    #[cfg(feature = "azure-secrets")]
    if tag == "azure" {
        return prompt_azure_secrets().await;
    }

    #[cfg(feature = "vault-secrets")]
    if tag == "vault" {
        return prompt_vault_secrets();
    }

    #[cfg(feature = "config-seed")]
    if tag == "config" {
        // Marker: seed field will be populated with hex after mnemonic derivation
        return Ok(SecretsConfig {
            seed: Some(String::new()),
            ..Default::default()
        });
    }

    #[cfg(feature = "keyring")]
    if tag == "keyring" {
        return prompt_keyring_service(SecretsConfig::default());
    }

    if tag == "plaintext" {
        eprintln!();
        eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  WARNING: Plaintext storage is NOT secure.               ║");
        eprintln!("║  Seeds will be stored in a plaintext file on disk.       ║");
        eprintln!("║  Use only for development or testing.                    ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
        eprintln!();
        return Ok(SecretsConfig::default());
    }

    // All compiled backends are covered above; this is truly unreachable
    unreachable!("selected backend tag does not match any compiled feature")
}

/// Prompt for the OS keyring service name.
///
/// Each VTA instance needs a unique keyring service name to store its seed
/// separately. The default is "vta".
#[cfg(feature = "keyring")]
fn prompt_keyring_service(
    mut config: SecretsConfig,
) -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let service: String = Input::new()
        .with_prompt("Keyring service name (use a unique name per VTA instance)")
        .default("vta".into())
        .interact_text()?;
    config.keyring_service = service;
    Ok(config)
}

#[cfg(feature = "aws-secrets")]
async fn prompt_aws_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    // Prompt for region first so we can list secrets from that region
    let region: String = Input::new()
        .with_prompt("AWS region (leave empty for SDK default)")
        .allow_empty(true)
        .interact_text()?;
    let region = if region.is_empty() {
        None
    } else {
        Some(region)
    };

    // Try to list existing secrets
    let secret_name = match list_aws_secrets(region.as_deref()).await {
        Ok(names) if !names.is_empty() => {
            let mut items: Vec<String> = names;
            items.push("Create new secret".into());
            let choice = Select::new()
                .with_prompt("Select an existing secret or create a new one")
                .items(&items)
                .default(0)
                .interact()?;
            if choice == items.len() - 1 {
                Input::new()
                    .with_prompt("AWS Secrets Manager secret name")
                    .default("vta-master-seed".into())
                    .interact_text()?
            } else {
                items.swap_remove(choice)
            }
        }
        Ok(_) => {
            eprintln!("  No existing secrets found.");
            Input::new()
                .with_prompt("AWS Secrets Manager secret name")
                .default("vta-master-seed".into())
                .interact_text()?
        }
        Err(e) => {
            eprintln!("  Warning: could not list secrets: {e}");
            Input::new()
                .with_prompt("AWS Secrets Manager secret name")
                .default("vta-master-seed".into())
                .interact_text()?
        }
    };

    Ok(SecretsConfig {
        aws_secret_name: Some(secret_name),
        aws_region: region,
        ..Default::default()
    })
}

/// List all secret names from AWS Secrets Manager, paginating through
/// every page so the wizard sees the full set rather than just the
/// first 100 (the default page size). Caps at 10k secrets to bound
/// memory + the operator picker, which gets unusable past that anyway.
#[cfg(feature = "aws-secrets")]
async fn list_aws_secrets(region: Option<&str>) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    const MAX_SECRETS: usize = 10_000;

    let mut config_loader = aws_config::from_env();
    if let Some(region) = region {
        config_loader = config_loader.region(aws_config::Region::new(region.to_owned()));
    }
    let sdk_config = config_loader.load().await;
    let client = aws_sdk_secretsmanager::Client::new(&sdk_config);

    let mut names: Vec<String> = Vec::new();
    let mut next_token: Option<String> = None;
    loop {
        let mut req = client.list_secrets();
        if let Some(token) = next_token.as_ref() {
            req = req.next_token(token.clone());
        }
        let output = req.send().await?;
        names.extend(
            output
                .secret_list()
                .iter()
                .filter_map(|entry| entry.name().map(String::from)),
        );
        if names.len() >= MAX_SECRETS {
            names.truncate(MAX_SECRETS);
            break;
        }
        match output.next_token() {
            Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
            _ => break,
        }
    }
    Ok(names)
}

#[cfg(feature = "gcp-secrets")]
async fn prompt_gcp_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let project: String = Input::new().with_prompt("GCP project ID").interact_text()?;

    // Try to list existing secrets
    let secret_name = match list_gcp_secrets(&project).await {
        Ok(names) if !names.is_empty() => {
            let mut items: Vec<String> = names;
            items.push("Create new secret".into());
            let choice = Select::new()
                .with_prompt("Select an existing secret or create a new one")
                .items(&items)
                .default(0)
                .interact()?;
            if choice == items.len() - 1 {
                Input::new()
                    .with_prompt("GCP Secret Manager secret name")
                    .default("vta-master-seed".into())
                    .interact_text()?
            } else {
                items.swap_remove(choice)
            }
        }
        Ok(_) => {
            eprintln!("  No existing secrets found.");
            Input::new()
                .with_prompt("GCP Secret Manager secret name")
                .default("vta-master-seed".into())
                .interact_text()?
        }
        Err(e) => {
            eprintln!("  Warning: could not list secrets: {e}");
            Input::new()
                .with_prompt("GCP Secret Manager secret name")
                .default("vta-master-seed".into())
                .interact_text()?
        }
    };

    Ok(SecretsConfig {
        gcp_project: Some(project),
        gcp_secret_name: Some(secret_name),
        ..Default::default()
    })
}

/// List all secret names from GCP Secret Manager, paginating through
/// every page via the response's `next_page_token`. Capped at 10k for
/// the same reasons as `list_aws_secrets`.
#[cfg(feature = "gcp-secrets")]
async fn list_gcp_secrets(project: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    const MAX_SECRETS: usize = 10_000;

    let client = google_cloud_secretmanager_v1::client::SecretManagerService::builder()
        .build()
        .await?;
    let prefix = format!("projects/{project}/secrets/");

    let mut names: Vec<String> = Vec::new();
    let mut page_token: Option<String> = None;
    loop {
        let mut req = client
            .list_secrets()
            .set_parent(format!("projects/{project}"));
        if let Some(token) = page_token.as_ref() {
            req = req.set_page_token(token.clone());
        }
        let response = req.send().await?;
        names.extend(
            response
                .secrets
                .iter()
                .map(|s| s.name.strip_prefix(&prefix).unwrap_or(&s.name).to_owned()),
        );
        if names.len() >= MAX_SECRETS {
            names.truncate(MAX_SECRETS);
            break;
        }
        if response.next_page_token.is_empty() {
            break;
        }
        page_token = Some(response.next_page_token);
    }
    Ok(names)
}

#[cfg(feature = "azure-secrets")]
async fn prompt_azure_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let vault_url: String = Input::new()
        .with_prompt("Azure Key Vault URL (e.g. https://my-vault.vault.azure.net)")
        .interact_text()?;

    let secret_name: String = Input::new()
        .with_prompt("Azure Key Vault secret name")
        .default("vta-master-seed".into())
        .interact_text()?;

    Ok(SecretsConfig {
        azure_vault_url: Some(vault_url),
        azure_secret_name: Some(secret_name),
        ..Default::default()
    })
}

/// Prompt for HashiCorp Vault settings. Synchronous because everything
/// is local input — actual Vault auth happens at first seed-store call.
#[cfg(feature = "vault-secrets")]
fn prompt_vault_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let addr: String = Input::new()
        .with_prompt("Vault server URL (e.g. https://vault.example.com:8200)")
        .interact_text()?;

    let secret_path: String = Input::new()
        .with_prompt("KV v2 secret path (e.g. vta/master-seed)")
        .interact_text()?;

    let kv_mount: String = Input::new()
        .with_prompt("KV v2 mount path")
        .default("secret".into())
        .interact_text()?;

    let secret_key: String = Input::new()
        .with_prompt("Field name within the KV entry holding the hex seed")
        .default("seed".into())
        .interact_text()?;

    let namespace: String = Input::new()
        .with_prompt("Vault Enterprise namespace (leave empty if not using)")
        .allow_empty(true)
        .interact_text()?;
    let namespace = if namespace.is_empty() {
        None
    } else {
        Some(namespace)
    };

    let auth_methods = &["kubernetes", "token", "approle"];
    let auth_idx = Select::new()
        .with_prompt("Auth method")
        .items(auth_methods)
        .default(0)
        .interact()?;
    let auth_method = auth_methods[auth_idx].to_string();

    let mut config = SecretsConfig {
        vault_addr: Some(addr),
        vault_secret_path: Some(secret_path),
        vault_kv_mount: kv_mount,
        vault_secret_key: secret_key,
        vault_namespace: namespace,
        vault_auth_method: auth_method.clone(),
        ..Default::default()
    };

    match auth_method.as_str() {
        "kubernetes" => {
            let role: String = Input::new()
                .with_prompt("Kubernetes auth role name")
                .interact_text()?;
            config.vault_k8s_role = Some(role);
            // k8s_mount and jwt_path keep their defaults.
        }
        "token" => {
            eprintln!(
                "  \x1b[2mLeave empty to read from the VAULT_TOKEN env var at runtime.\x1b[0m"
            );
            let token: String = Input::new()
                .with_prompt("Vault token")
                .allow_empty(true)
                .interact_text()?;
            if !token.is_empty() {
                config.vault_token = Some(token);
            }
        }
        "approle" => {
            let role_id: String = Input::new()
                .with_prompt("AppRole role_id")
                .interact_text()?;
            let secret_id: String = Input::new()
                .with_prompt("AppRole secret_id")
                .interact_text()?;
            config.vault_approle_role_id = Some(role_id);
            config.vault_approle_secret_id = Some(secret_id);
        }
        _ => unreachable!("auth_method came from a fixed list"),
    }

    Ok(config)
}

pub async fn run_setup_wizard(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Welcome to the VTA setup wizard.\n");

    // 1. Config file path
    let default_path = config_path
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            std::env::var("VTA_CONFIG_PATH").unwrap_or_else(|_| "config.toml".into())
        });
    let config_path: String = Input::new()
        .with_prompt("Config file path")
        .default(default_path)
        .interact_text()?;
    let config_path = PathBuf::from(&config_path);

    if config_path.exists() {
        let overwrite = Confirm::new()
            .with_prompt(format!(
                "{} already exists. Overwrite?",
                config_path.display()
            ))
            .default(false)
            .interact()?;
        if !overwrite {
            eprintln!("Setup cancelled.");
            return Ok(());
        }
    }

    // 2. VTA name
    let vta_name: String = Input::new()
        .with_prompt("VTA name (leave empty to skip)")
        .allow_empty(true)
        .interact_text()?;
    let vta_name = if vta_name.is_empty() {
        None
    } else {
        Some(vta_name)
    };

    // 3. Services to enable
    let (enable_rest, enable_didcomm) = prompt_services()?;

    // 4. Server host + port + REST URL (only when REST is enabled).
    // The REST URL is asked AFTER host/port so the localhost default
    // can use the actual port the operator just chose.
    let (public_url, host, port) = if enable_rest {
        let host: String = Input::new()
            .with_prompt("Server host")
            .default("0.0.0.0".into())
            .interact_text()?;

        let port: u16 = Input::new()
            .with_prompt("Server port")
            .default(8100u16)
            .interact_text()?;

        eprintln!();
        eprintln!(
            "  REST is enabled — the VTA needs a public URL to publish as a service endpoint in its DID document. Other parties (CLI clients, other VTAs) resolve the DID and use this URL to reach the REST API."
        );
        eprintln!("  Examples:");
        eprintln!("    • Local development: http://localhost:{port}");
        eprintln!("    • Production:        https://vta.example.com");
        eprintln!();

        let default_url = format!("http://localhost:{port}");
        let public_url: String = Input::new()
            .with_prompt("VTA REST URL")
            .default(default_url)
            .validate_with(|input: &String| -> Result<(), String> {
                let s = input.trim();
                if s.is_empty() {
                    return Err("VTA REST URL is required when REST is enabled".into());
                }
                if !(s.starts_with("http://") || s.starts_with("https://")) {
                    return Err(
                        "URL must start with http:// or https:// (e.g. http://localhost:8100)"
                            .into(),
                    );
                }
                Ok(())
            })
            .interact_text()?;

        // Strip any trailing slash so consumers that append paths
        // (e.g. `<url>/auth/challenge`) don't end up with a double `//`.
        let public_url = public_url.trim().trim_end_matches('/').to_string();
        (Some(public_url), host, port)
    } else {
        (
            None,
            ServerConfig::default().host,
            ServerConfig::default().port,
        )
    };

    // 6. Log level
    let log_level: String = Input::new()
        .with_prompt("Log level")
        .default("info".into())
        .interact_text()?;

    // 7. Log format
    let log_format_items = &["text", "json"];
    let log_format_idx = Select::new()
        .with_prompt("Log format")
        .items(log_format_items)
        .default(0)
        .interact()?;
    let log_format = match log_format_idx {
        1 => LogFormat::Json,
        _ => LogFormat::Text,
    };

    // 7b. Optional remote DID resolver — only prompted on TEE / Nitro
    // builds. There the enclave cannot fetch did:web / did:webvh itself,
    // so resolution must be bridged to a parent-side
    // `affinidi-did-resolver-cache-server` over vsock and a ws:// URL is
    // required. Non-TEE builds always resolve in-process; an operator who
    // wants a shared resolver-cache there can set `resolver_url` directly
    // in config.toml — it doesn't warrant a wizard prompt for every
    // single-node deployment.
    #[cfg(feature = "tee")]
    let resolver_url = {
        println!();
        println!("DID resolution");
        println!("  The VTA resolves DIDs (did:web, did:webvh, did:key, did:peer) on every");
        println!("  authcrypt, every proof check, every authenticate. In a TEE the enclave");
        println!("  cannot reach the network directly, so resolution is dispatched to an");
        println!("  external `affinidi-did-resolver-cache-server` on the parent, bridged");
        println!("  over vsock.");
        println!();
        println!("  Example: ws://127.0.0.1:4445/did/v1/ws");
        println!();
        let entered: String = Input::new()
            .with_prompt("Remote DID resolver WebSocket URL")
            .allow_empty(true)
            .interact_text()?;
        if entered.is_empty() {
            None
        } else {
            Some(entered)
        }
    };
    #[cfg(not(feature = "tee"))]
    let resolver_url: Option<String> = None;

    // 7c. Audit-log retention. Default 28 days; compliance-driven
    // deployments often want 90 or 365.
    let audit_retention_days: u32 = Input::new()
        .with_prompt("Audit-log retention (days)")
        .default(AuditConfig::default().retention_days)
        .validate_with(|v: &u32| -> Result<(), String> {
            if *v == 0 {
                Err("retention must be > 0; the audit sweeper assumes a positive window".into())
            } else {
                Ok(())
            }
        })
        .interact_text()?;
    let audit = AuditConfig {
        retention_days: audit_retention_days,
    };

    // 8. Data directory
    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/vta".into())
        .interact_text()?;

    // 9. If data directory already exists, offer to delete and start fresh
    let data_path = PathBuf::from(&data_dir);
    if data_path.exists() {
        let delete = Confirm::new()
            .with_prompt(format!(
                "Data directory \"{}\" already exists. Delete and start fresh?",
                data_dir
            ))
            .default(false)
            .interact()?;
        if delete {
            std::fs::remove_dir_all(&data_path)?;
            eprintln!("  Deleted existing data directory.");
        } else {
            eprintln!("Setup cancelled.");
            return Ok(());
        }
    }

    // 10. Open the store so we can persist key records during DID creation
    let store = Store::open(&StoreConfig {
        data_dir: PathBuf::from(&data_dir),
    })?;
    let keys_ks = store.keyspace("keys")?;
    let imported_ks = store.keyspace("imported_secrets")?;
    let contexts_ks = store.keyspace("contexts")?;
    let webvh_ks = store.keyspace("webvh")?;
    let did_templates_ks = store.keyspace("did_templates")?;

    // Create seed application contexts
    let mut vta_ctx = create_seed_context(&contexts_ks, "vta", "Verifiable Trust Agent").await?;
    eprintln!("  Created application context: vta");

    // 10. BIP-39 mnemonic. Always generated — operator-supplied mnemonics
    // were removed because pasting one into a terminal exposes it to shell
    // history, scrollback, and clipboard. Use `vta keys rotate-seed
    // --mnemonic <phrase>` after setup if you need a specific seed.
    let mnemonic = generate_mnemonic_with_confirmation()?;

    // Prompt for seed store backend configuration
    let mut secrets_config = configure_secrets().await?;

    // Derive BIP-39 seed
    let seed = mnemonic.to_seed("");

    // Store seed via the configured backend
    if secrets_config.seed.is_some() {
        // config-seed backend: hex-encode seed into the config (persisted when config is saved)
        secrets_config.seed = Some(hex::encode(seed));
    } else {
        // All other backends: store via the seed store
        let seed_store = create_seed_store(&AppConfig {
            trusted_presentation_verifiers: Vec::new(),
            credential_holder_did: None,
            vta_did: None,
            vta_name: None,
            public_url: None,
            server: ServerConfig::default(),
            log: LogConfig::default(),
            store: StoreConfig {
                data_dir: PathBuf::from("data/vta"),
            },
            services: ServicesConfig::default(),
            messaging: None,
            auth: AuthConfig::default(),
            audit: Default::default(),
            secrets: secrets_config.clone(),
            #[cfg(feature = "tee")]
            tee: Default::default(),
            resolver_url: None,
            config_path: config_path.clone(),
        })
        .map_err(|e| format!("{e}"))?;
        seed_store.set(&seed).await.map_err(|e| format!("{e}"))?;
    }

    // Create initial seed record (generation 0)
    let initial_seed_record = SeedRecord {
        id: 0,
        seed_hex: None,
        created_at: Utc::now(),
        retired_at: None,
    };
    save_seed_record(&keys_ks, &initial_seed_record).await?;
    set_active_seed_id(&keys_ks, 0).await?;

    // 11. Generate random JWT signing key
    let mut jwt_key_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut jwt_key_bytes);
    let jwt_signing_key = BASE64.encode(jwt_key_bytes);

    // Create a temporary AppConfig for the seed store (config hasn't been saved yet)
    let mut wizard_config = AppConfig {
        trusted_presentation_verifiers: Vec::new(),
        credential_holder_did: None,
        vta_did: None,
        vta_name: None,
        public_url: public_url.clone(),
        server: ServerConfig {
            host: host.clone(),
            port,
            cors_origins: Vec::new(),
            trust_xff: false,
        },
        log: LogConfig::default(),
        store: StoreConfig {
            data_dir: PathBuf::from(&data_dir),
        },
        services: ServicesConfig::default(),
        messaging: None,
        auth: AuthConfig::default(),
        audit: Default::default(),
        secrets: secrets_config.clone(),
        #[cfg(feature = "tee")]
        tee: Default::default(),
        resolver_url: None,
        config_path: config_path.clone(),
    };
    let wizard_seed_store: Arc<dyn crate::keys::seed_store::SeedStore> =
        Arc::from(create_seed_store(&wizard_config).map_err(|e| format!("{e}"))?);

    // 12. DIDComm messaging
    let messaging = if enable_didcomm {
        configure_messaging(
            &keys_ks,
            &imported_ks,
            &contexts_ks,
            &webvh_ks,
            &did_templates_ks,
            &*wizard_seed_store,
            &wizard_config,
        )
        .await?
    } else {
        None
    };

    // Propagate the resolved mediator into the scratch config so the VTA DID
    // builder can embed `DIDCommMessaging` in the DID document. Without this,
    // `build_did_document_inner` sees `config.messaging == None` and silently
    // drops the service even when `add_mediator_service == true`.
    wizard_config.messaging = messaging.clone();

    // 13. VTA DID (after mediator so we can embed it as a service endpoint)
    let vta_did = create_vta_did(
        messaging.as_ref(),
        &public_url,
        &keys_ks,
        &imported_ks,
        &contexts_ks,
        &webvh_ks,
        &did_templates_ks,
        &*wizard_seed_store,
        &wizard_config,
    )
    .await?;

    // Update VTA context with the DID
    if let Some(ref did) = vta_did {
        vta_ctx.did = Some(did.clone());
        vta_ctx.updated_at = Utc::now();
        store_context(&contexts_ks, &vta_ctx)
            .await
            .map_err(|e| format!("{e}"))?;
    }

    // The VTA ACL starts empty. Admins add themselves via `pnm setup` (which
    // mints a temp did:key, asks the operator to grant it via `vta import-did`,
    // and auto-rotates on first connect). See the "What to do next" section
    // printed at the end of this wizard.
    let _ = &seed;

    // Flush all store writes to disk before exiting
    store.persist().await?;

    // 15. Save config
    let config = AppConfig {
        trusted_presentation_verifiers: Vec::new(),
        credential_holder_did: None,
        vta_did,
        vta_name,
        public_url: public_url.clone(),
        server: ServerConfig {
            host,
            port,
            cors_origins: Vec::new(),
            trust_xff: false,
        },
        log: LogConfig {
            level: log_level,
            format: log_format,
        },
        store: StoreConfig {
            data_dir: PathBuf::from(data_dir),
        },
        services: ServicesConfig {
            rest: enable_rest,
            didcomm: enable_didcomm,
            // WebAuthn-RP service defaults off at setup. The
            // operator enables it later via
            // `pnm services webauthn enable --url <portal-url>`
            // once they're ready to wire up a browser flow.
            webauthn: false,
        },
        messaging,
        auth: AuthConfig {
            jwt_signing_key: Some(jwt_signing_key),
            ..AuthConfig::default()
        },
        audit,
        secrets: secrets_config,
        #[cfg(feature = "tee")]
        tee: Default::default(),
        resolver_url,
        config_path: config_path.clone(),
    };
    config.save()?;

    // 16. Summary
    eprintln!();
    eprintln!("\x1b[1;32mSetup complete!\x1b[0m");
    eprintln!("  Config saved to: {}", config_path.display());
    eprintln!("  Seed stored in configured backend");
    // Print which seed backend was chosen
    {
        let mut _printed = false;
        #[cfg(feature = "aws-secrets")]
        if let Some(ref name) = config.secrets.aws_secret_name {
            let region = config
                .secrets
                .aws_region
                .as_deref()
                .unwrap_or("SDK default");
            eprintln!("  Seed backend: AWS Secrets Manager ({name} in {region})");
            _printed = true;
        }
        #[cfg(feature = "gcp-secrets")]
        if !_printed && let Some(ref name) = config.secrets.gcp_secret_name {
            let project = config.secrets.gcp_project.as_deref().unwrap_or("unknown");
            eprintln!("  Seed backend: GCP Secret Manager ({project}/{name})");
            _printed = true;
        }
        #[cfg(feature = "azure-secrets")]
        if !_printed && let Some(ref url) = config.secrets.azure_vault_url {
            let name = config
                .secrets
                .azure_secret_name
                .as_deref()
                .unwrap_or("vta-master-seed");
            eprintln!("  Seed backend: Azure Key Vault ({url}/{name})");
            _printed = true;
        }
        if !_printed && config.secrets.seed.is_some() {
            eprintln!("  Seed backend: config file (hex-encoded in config.toml)");
            _printed = true;
        }
        #[cfg(feature = "keyring")]
        if !_printed {
            eprintln!(
                "  Seed backend: OS keyring (service: \"{}\")",
                config.secrets.keyring_service
            );
        }
    }
    if let Some(name) = &config.vta_name {
        eprintln!("  VTA Name: {name}");
    }
    if let Some(url) = &config.public_url {
        eprintln!("  VTA REST URL: {url}");
    }
    if let Some(did) = &config.vta_did {
        eprintln!("  VTA DID: {did}");
    }
    let mut svc_list = Vec::new();
    if config.services.rest {
        svc_list.push("REST");
    }
    if config.services.didcomm {
        svc_list.push("DIDComm");
    }
    eprintln!("  Services: {}", svc_list.join(", "));
    eprintln!("  Server: {}:{}", config.server.host, config.server.port);
    if let Some(msg) = &config.messaging {
        eprintln!("  Mediator DID: {}", msg.mediator_did);
        if !msg.mediator_url.is_empty() {
            eprintln!("  Mediator URL: {}", msg.mediator_url);
        }
    }
    eprintln!("  Contexts: vta ({})", vta_ctx.base_path);
    eprintln!();
    eprintln!("\x1b[1;36m── What to do next ──\x1b[0m");
    eprintln!();
    eprintln!("  1. On your operator workstation (with the VTA still stopped),");
    eprintln!("     run `pnm setup` and choose \"Connect to an existing non-TEE");
    eprintln!("     VTA\". When it asks for the VTA DID, enter:");
    eprintln!();
    if let Some(did) = &config.vta_did {
        eprintln!("       \x1b[1m{did}\x1b[0m");
    } else {
        eprintln!("       (the VTA DID shown above)");
    }
    eprintln!();
    eprintln!("     `pnm setup` mints a temp did:key and prints an");
    eprintln!("     `vta import-did` command.");
    eprintln!();
    eprintln!("  2. Back on this host, run the `vta import-did` command pnm");
    eprintln!("     printed. This grants admin access to the temp did:key by");
    eprintln!("     writing to the local store — no network call, no running VTA");
    eprintln!("     required.");
    eprintln!();
    eprintln!("  3. Start the VTA:");
    eprintln!(
        "       \x1b[1mvta --config {}\x1b[0m",
        config_path.display()
    );
    eprintln!();
    eprintln!("     On the operator workstation's first authenticated command");
    eprintln!("     (e.g. `pnm health`), PNM rotates to a fresh long-lived");
    eprintln!("     did:key and removes the temp from the ACL.");
    eprintln!();
    eprintln!("  4. (Optional) To bootstrap additional admins, repeat steps 1–2");
    eprintln!("     on each operator's workstation before or after starting the");
    eprintln!("     VTA — `vta import-did` takes a store-level lock and must not");
    eprintln!("     run while the VTA process is holding the store open.");
    eprintln!();

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared DID creation helper
// ---------------------------------------------------------------------------

/// Interactive did:webvh creation using the operations layer.
///
/// Prompts for URL, offers simple/advanced mode, builds params, calls
/// `operations::create_did_webvh()`, and saves did.jsonl. Private keys stay
/// in the VTA's key store; consumers fetch them at runtime via
/// `GET /keys/{id}/secret`, not from a setup-time export.
///
/// `additional_services` lets callers inject custom services (e.g. mediator endpoints).
#[allow(clippy::too_many_arguments)]
async fn build_wizard_did(
    label: &str,
    context_id: &str,
    additional_services: Option<Vec<serde_json::Value>>,
    add_mediator_service: bool,
    template: Option<String>,
    template_vars: std::collections::HashMap<String, serde_json::Value>,
    is_vta_identity: bool,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    did_templates_ks: &KeyspaceHandle,
    seed_store: &dyn crate::keys::seed_store::SeedStore,
    config: &AppConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    // Prompt for URL
    let webvh_url = prompt_webvh_url(label)?;
    let url_str = webvh_url
        .get_http_url(None)
        .map_err(|e| format!("{e}"))?
        .to_string();

    // Simple vs advanced toggle
    let mode_options = &[
        "Simple — VTA creates keys and document (recommended)",
        "Advanced — provide your own document, keys, or pre-signed log",
    ];
    let mode_choice = Select::new()
        .with_prompt("DID creation mode")
        .items(mode_options)
        .default(0)
        .interact()?;

    let (did_document, did_log, signing_key_id, ka_key_id) = if mode_choice == 1 {
        // Advanced mode
        let adv_options = &[
            "Provide a DID Document template (VTA signs it)",
            "Import a pre-signed did.jsonl",
            "Use existing imported keys",
        ];
        let adv_choice = Select::new()
            .with_prompt("Advanced option")
            .items(adv_options)
            .default(0)
            .interact()?;

        match adv_choice {
            0 => {
                // Template mode
                let path: String = Input::new()
                    .with_prompt("Path to DID Document JSON file")
                    .interact_text()?;
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| format!("failed to read {path}: {e}"))?;
                let doc: serde_json::Value = serde_json::from_str(&content)
                    .map_err(|e| format!("invalid JSON in {path}: {e}"))?;
                (Some(doc), None, None, None)
            }
            1 => {
                // Final mode
                let path: String = Input::new()
                    .with_prompt("Path to did.jsonl file")
                    .interact_text()?;
                let log = std::fs::read_to_string(&path)
                    .map_err(|e| format!("failed to read {path}: {e}"))?;
                (None, Some(log), None, None)
            }
            _ => {
                // User-specified keys
                let signing: String = Input::new()
                    .with_prompt("Signing key ID (Ed25519)")
                    .interact_text()?;
                let ka: String = Input::new()
                    .with_prompt("Key-agreement key ID (X25519, leave empty to skip)")
                    .allow_empty(true)
                    .interact_text()?;
                let ka_id = if ka.is_empty() { None } else { Some(ka) };
                (None, None, Some(signing), ka_id)
            }
        }
    } else {
        (None, None, None, None)
    };

    // Portability (skip for final mode — document is already signed)
    let portable = if did_log.is_none() {
        Confirm::new()
            .with_prompt("Make this DID portable (can move to a different domain later)?")
            .default(true)
            .interact()?
    } else {
        true
    };

    // Pre-rotation count (skip for final mode)
    let pre_rotation_count = if did_log.is_none() {
        eprintln!();
        eprintln!("  \x1b[2mPre-rotation protects against key compromise by publishing hashes");
        eprintln!("  of future keys now. Recommended: 1-3 keys.\x1b[0m");
        Input::new()
            .with_prompt("Number of pre-rotation keys")
            .default(1u32)
            .interact_text()?
    } else {
        0
    };

    let auth = cli_super_admin();
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let no_bridge: Arc<crate::didcomm_bridge::DIDCommBridge> =
        Arc::new(crate::didcomm_bridge::DIDCommBridge::placeholder());

    let params = CreateDidWebvhParams {
        context_id: context_id.to_string(),
        server_id: None,
        url: Some(url_str.clone()),
        // Serverless (`server_id: None`) ignores `path_mode`.
        path_mode: vta_sdk::protocols::did_management::create::WebvhPathMode::default(),
        domain: None,
        label: Some(label.to_string()),
        portable,
        add_mediator_service,
        additional_services,
        pre_rotation_count,
        did_document,
        did_log,
        set_primary: true,
        signing_key_id,
        ka_key_id,
        template,
        template_context: None,
        template_vars,
        is_vta_identity,
    };

    let result = operations::did_webvh::create_did_webvh(
        keys_ks,
        imported_ks,
        contexts_ks,
        webvh_ks,
        did_templates_ks,
        seed_store,
        config,
        &auth,
        params,
        &did_resolver,
        &no_bridge,
        "setup",
    )
    .await
    .map_err(|e| format!("{e}"))?;

    let final_did = result.did.clone();
    eprintln!("\x1b[1;32mCreated DID:\x1b[0m {final_did}");

    // Save did.jsonl (serverless mode returns it in the response)
    if let Some(ref log_entry) = result.log_entry {
        let default_file = format!("{label}-did.jsonl");
        let did_file: String = Input::new()
            .with_prompt("Save DID log to file")
            .default(default_file)
            .interact_text()?;

        std::fs::write(&did_file, log_entry)?;
        eprintln!("  DID log saved to: {did_file}");
        eprintln!();
        eprintln!("  \x1b[2mTo self-host this DID, upload {did_file} to:");
        eprintln!("  {url_str}\x1b[0m");
    }

    // DID secrets live in the VTA's key store and are fetched by consumers
    // (applications, mediators, the VTA itself) via `GET /keys/{id}/secret`
    // or the DIDComm equivalent at runtime. No setup-time export — the
    // setup wizard's output is the DID itself, not its secrets.
    Ok(final_did)
}

// ---------------------------------------------------------------------------
// DID creation steps
// ---------------------------------------------------------------------------

/// Guide the user through creating (or entering) a did:webvh DID for the VTA.
///
/// Uses the operations layer via `build_wizard_did()` with simple/advanced toggle.
///
/// Returns `Some(did_string)` or `None` if skipped.
#[allow(clippy::too_many_arguments)]
async fn create_vta_did(
    messaging: Option<&MessagingConfig>,
    public_url: &Option<String>,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    did_templates_ks: &KeyspaceHandle,
    seed_store: &dyn crate::keys::seed_store::SeedStore,
    config: &AppConfig,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let did_options = &[
        "Create a new did:webvh DID (recommended for production)",
        "Create a new did:key (no external hosting; great for local dev)",
        "Enter an existing DID",
        "Skip (no VTA DID for now)",
    ];
    let choice = Select::new()
        .with_prompt("VTA DID")
        .items(did_options)
        .default(0)
        .interact()?;

    match choice {
        0 => {
            let add_mediator = messaging.is_some();
            let services =
                super::build_vta_additional_services(&config.services, public_url.as_deref());

            let did = build_wizard_did(
                "VTA",
                "vta",
                services,
                add_mediator,
                None,
                std::collections::HashMap::new(),
                true, // is_vta_identity — mint `#sealed-transfer-0` alongside `#key-0`
                keys_ks,
                imported_ks,
                contexts_ks,
                webvh_ks,
                did_templates_ks,
                seed_store,
                config,
            )
            .await?;
            Ok(Some(did))
        }
        1 => {
            let did = super::create_vta_did_key("vta", keys_ks, contexts_ks, seed_store).await?;
            Ok(Some(did))
        }
        2 => {
            let did: String = Input::new().with_prompt("VTA DID").interact_text()?;

            Ok(Some(did))
        }
        _ => Ok(None),
    }
}

/// Prompt for the optional `mediator_host` override. Used in TEE
/// network mode where the VTA dials the mediator via a vsock proxy
/// on the parent EC2 instance and that proxy needs the real upstream
/// hostname for SNI / TLS validation. Empty input means "not set",
/// returned as `None`.
fn prompt_optional_mediator_host() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let host: String = Input::new()
        .with_prompt("Mediator hostname for vsock-bridged TEE deployments (leave empty to skip)")
        .allow_empty(true)
        .interact_text()?;
    Ok(if host.is_empty() { None } else { Some(host) })
}

/// Prompt for an optional comma-separated list of routing-key DIDs
/// for the `didcomm-mediator` template's `ROUTING_KEYS` variable.
/// Used when this mediator forwards traffic through an upstream
/// mediator. Empty input means no routing keys.
fn prompt_routing_keys() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let raw: String = Input::new()
        .with_prompt(
            "Upstream routing-key DIDs for this mediator (comma-separated, leave empty to skip)",
        )
        .allow_empty(true)
        .interact_text()?;
    Ok(raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect())
}

/// Guide the user through DIDComm messaging configuration.
///
/// Offers three choices:
/// 1. Use an existing mediator DID (no URL needed — ATM resolves endpoints from the DID document)
/// 2. Create a new did:webvh mediator DID (creates a "mediator" context for key storage)
/// 3. Skip DIDComm messaging entirely
///
/// Returns `None` when the user chooses to skip.
#[allow(clippy::too_many_arguments)]
async fn configure_messaging(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    did_templates_ks: &KeyspaceHandle,
    seed_store: &dyn crate::keys::seed_store::SeedStore,
    config: &AppConfig,
) -> Result<Option<MessagingConfig>, Box<dyn std::error::Error>> {
    let options = &[
        "Use an existing mediator DID",
        "Create a new mediator DID (did:webvh)",
        "Do not use DIDComm messaging",
    ];
    let choice = Select::new()
        .with_prompt("DIDComm messaging")
        .items(options)
        .default(0)
        .interact()?;

    match choice {
        // Existing DID — no local keys or context needed
        0 => {
            let did: String = Input::new()
                .with_prompt("Mediator DID")
                .validate_with(|input: &String| -> Result<(), String> {
                    if input.starts_with("did:") {
                        Ok(())
                    } else {
                        Err("DID must start with 'did:' (e.g. did:webvh:... or did:key:...)".into())
                    }
                })
                .interact_text()?;

            let mediator_host = prompt_optional_mediator_host()?;

            Ok(Some(MessagingConfig {
                mediator_url: String::new(),
                mediator_did: did,
                mediator_host,
            }))
        }
        // Create new did:webvh — needs a mediator context
        1 => {
            // The mediator DID lives inside a trust context so its keys slot
            // into the normal context-scoped key hierarchy. Default id is
            // "mediator" but operators running more than one mediator on the
            // same VTA can differentiate (e.g. "mediator-eu", "mediator-us").
            let mediator_context: String = Input::new()
                .with_prompt("Trust context for the mediator DID")
                .default("mediator".to_string())
                .interact_text()?;
            let mediator_context = mediator_context.trim().to_string();
            if mediator_context.is_empty() {
                return Err("mediator context id cannot be empty".into());
            }

            let mediator_url: String = Input::new().with_prompt("Mediator URL").interact_text()?;

            let mediator_host = prompt_optional_mediator_host()?;

            // Optional ROUTING_KEYS escape hatch (mediator chains). The
            // didcomm-mediator template's other optional vars (ACCEPT,
            // WEBVH_SERVER) have correct defaults; operators who need to
            // tweak those should use `--from <toml>` and the
            // `[messaging.template_vars]` table.
            let routing_keys = prompt_routing_keys()?;

            // Create mediator context
            let _med_ctx =
                create_seed_context(contexts_ks, &mediator_context, "DIDComm Messaging Mediator")
                    .await?;

            // Use the built-in `didcomm-mediator` template — a single
            // source of truth for the mediator DID document shape. Operators
            // who need a different shape can fork it via
            // `pnm did-templates init mediator > custom.json`, edit, and
            // upload to global or context scope. Resolution order is
            // context → global → builtin, so a stored `didcomm-mediator`
            // override at either scope shadows this built-in automatically.
            let mut template_vars: std::collections::HashMap<String, serde_json::Value> =
                std::collections::HashMap::new();
            template_vars.insert("URL".into(), json!(mediator_url));
            if !routing_keys.is_empty() {
                template_vars.insert("ROUTING_KEYS".into(), json!(routing_keys));
            }

            let mediator_did = build_wizard_did(
                &mediator_context,
                &mediator_context,
                None,
                false,
                Some("didcomm-mediator".into()),
                template_vars,
                false, // mediator DID, not the VTA's own identity
                keys_ks,
                imported_ks,
                contexts_ks,
                webvh_ks,
                did_templates_ks,
                seed_store,
                config,
            )
            .await?;

            Ok(Some(MessagingConfig {
                mediator_url,
                mediator_did,
                mediator_host,
            }))
        }
        // Skip DIDComm
        _ => Ok(None),
    }
}

/// Generate a fresh 24-word BIP-39 mnemonic, display it, and require the
/// operator to confirm they have saved it before returning. Used by the
/// interactive wizard.
///
/// The non-interactive (`--from <file>`) path uses
/// [`super::generate_mnemonic_silent`] instead — no display, no confirm,
/// on the assumption that the operator will run `pnm backup export`
/// after the first admin connects to capture the seed in an encrypted
/// backup.
fn generate_mnemonic_with_confirmation() -> Result<Mnemonic, Box<dyn std::error::Error>> {
    let m = generate_mnemonic_silent()?;
    eprintln!();
    eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  WARNING: Write down your mnemonic phrase and store it   ║");
    eprintln!("║  securely. It is the ONLY way to recover your keys.      ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
    eprintln!();
    eprintln!("\x1b[1m{}\x1b[0m", m);
    eprintln!();

    let confirmed = Confirm::new()
        .with_prompt("I have saved my mnemonic phrase")
        .default(false)
        .interact()?;
    if !confirmed {
        return Err("Setup cancelled — please save your mnemonic before proceeding.".into());
    }
    Ok(m)
}
