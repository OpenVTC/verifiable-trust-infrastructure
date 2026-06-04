use std::path::PathBuf;
use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use vta_sdk::protocols::did_management::create::WebvhPathMode;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::keys::seed_store::create_seed_store;
use crate::operations;
use crate::store::Store;

/// Format a UTC `DateTime` as a readable local-timezone string with ISO offset.
///
/// The service stores timestamps in UTC internally (wire format, storage);
/// operator-facing CLI output converts to the local timezone for readability.
fn format_local_datetime(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M:%S %:z")
        .to_string()
}

/// Create a synthetic super-admin AuthClaims for CLI operations.
///
/// Thin wrapper over the workspace-level
/// [`AuthClaims::unsafe_local_cli_super_admin`] factory so the
/// trust-boundary documentation lives in one place. Callers should
/// prefer the factory directly in new code.
pub(crate) fn cli_super_admin() -> AuthClaims {
    AuthClaims::unsafe_local_cli_super_admin("webvh")
}

pub async fn run_add_server(
    config_path: Option<PathBuf>,
    id: String,
    did: String,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let webvh_ks = store.keyspace("webvh")?;
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;

    let auth = cli_super_admin();
    let result = operations::did_webvh::add_webvh_server(
        &webvh_ks,
        &auth,
        &id,
        &did,
        label,
        &did_resolver,
        "cli",
    )
    .await?;
    store.persist().await?;

    eprintln!("WebVH server added:");
    eprintln!("  ID:  {}", result.id);
    eprintln!("  DID: {}", result.did);
    if let Some(label) = &result.label {
        eprintln!("  Label: {label}");
    }
    Ok(())
}

pub async fn run_list_servers(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let webvh_ks = store.keyspace("webvh")?;

    let auth = cli_super_admin();
    let result = operations::did_webvh::list_webvh_servers(&webvh_ks, &auth, "cli").await?;

    if result.servers.is_empty() {
        eprintln!("No WebVH servers configured.");
        return Ok(());
    }

    eprintln!("{} WebVH server(s):\n", result.servers.len());
    for server in &result.servers {
        eprintln!("  ID:      {}", server.id);
        eprintln!("  DID:     {}", server.did);
        if let Some(label) = &server.label {
            eprintln!("  Label:   {label}");
        }
        eprintln!("  Created: {}", format_local_datetime(server.created_at));
        eprintln!();
    }
    Ok(())
}

pub async fn run_update_server(
    config_path: Option<PathBuf>,
    id: String,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let webvh_ks = store.keyspace("webvh")?;

    let auth = cli_super_admin();
    let result =
        operations::did_webvh::update_webvh_server(&webvh_ks, &auth, &id, label, "cli").await?;
    store.persist().await?;

    eprintln!("WebVH server updated:");
    eprintln!("  ID:  {}", result.id);
    eprintln!("  DID: {}", result.did);
    if let Some(label) = &result.label {
        eprintln!("  Label: {label}");
    }
    Ok(())
}

pub async fn run_remove_server(
    config_path: Option<PathBuf>,
    id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let webvh_ks = store.keyspace("webvh")?;

    let auth = cli_super_admin();
    operations::did_webvh::remove_webvh_server(&webvh_ks, &auth, &id, "cli").await?;
    store.persist().await?;

    eprintln!("WebVH server removed: {id}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_create_did(
    config_path: Option<PathBuf>,
    context_id: String,
    server_id: String,
    path: Option<String>,
    label: Option<String>,
    portable: bool,
    mediator_service: bool,
    services_json: Option<String>,
    pre_rotation: Option<u32>,
    print_mnemonic: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path.clone())?;
    let store = Store::open(&config.store)?;
    let keys_ks = store.keyspace("keys")?;
    let imported_ks = store.keyspace("imported_secrets")?;
    let contexts_ks = store.keyspace("contexts")?;
    let webvh_ks = store.keyspace("webvh")?;
    let did_templates_ks = store.keyspace("did_templates")?;
    let seed_store: Arc<dyn crate::keys::seed_store::SeedStore> =
        Arc::from(create_seed_store(&config)?);

    let additional_services: Option<Vec<serde_json::Value>> = match services_json {
        Some(json) => Some(serde_json::from_str(&json)?),
        None => None,
    };

    let auth = cli_super_admin();
    let params = operations::did_webvh::CreateDidWebvhParams {
        context_id: context_id.clone(),
        server_id: Some(server_id),
        url: None,
        // `--path <p>` → explicit; `--path .well-known` → root; absent
        // → server auto-assigns.
        path_mode: WebvhPathMode::from(path),
        // CLI-driven flow: no per-DID domain selection here. Wired
        // via `--domain` in pnm-cli's surface.
        domain: None,
        label,
        portable,
        add_mediator_service: mediator_service,
        additional_services,
        pre_rotation_count: pre_rotation.unwrap_or(0),
        did_document: None,
        did_log: None,
        set_primary: true,
        signing_key_id: None,
        ka_key_id: None,
        template: None,
        template_context: None,
        template_vars: std::collections::HashMap::new(),
        // `pnm did-webvh create` is a runtime integration-DID CLI; it
        // never mints the VTA's own identity (setup wizard does that).
        is_vta_identity: false,
    };

    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let no_bridge: Arc<DIDCommBridge> = Arc::new(DIDCommBridge::placeholder());
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
    store.persist().await?;

    eprintln!("\x1b[1;32mCreated DID:\x1b[0m {}", result.did);
    eprintln!("  Context:    {}", result.context_id);
    if let Some(ref server_id) = result.server_id {
        eprintln!("  Server:     {}", server_id);
    }
    eprintln!("  SCID:       {}", result.scid);
    if let Some(ref mnemonic) = result.mnemonic {
        if print_mnemonic {
            eprintln!("  Mnemonic:   {mnemonic}");
        } else {
            eprintln!(
                "  Mnemonic:   <redacted — re-run with `--print-mnemonic` if you really need it on stderr>"
            );
        }
    }
    eprintln!("  Portable:   {}", result.portable);
    eprintln!("  Signing:    {}", result.signing_key_id);
    eprintln!("  KA:         {}", result.ka_key_id);
    if result.pre_rotation_key_count > 0 {
        eprintln!("  Pre-rot:    {} keys", result.pre_rotation_key_count);
    }
    Ok(())
}

pub async fn run_list_dids(
    config_path: Option<PathBuf>,
    context_id: Option<String>,
    server_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let webvh_ks = store.keyspace("webvh")?;

    let auth = cli_super_admin();
    let result = operations::did_webvh::list_dids_webvh(
        &webvh_ks,
        &auth,
        context_id.as_deref(),
        server_id.as_deref(),
        "cli",
    )
    .await?;

    if result.dids.is_empty() {
        eprintln!("No WebVH DIDs found.");
        return Ok(());
    }

    eprintln!("{} WebVH DID(s):\n", result.dids.len());
    for d in &result.dids {
        eprintln!("  DID:      {}", d.did);
        eprintln!("  Context:  {}", d.context_id);
        eprintln!("  Server:   {}", d.server_id);
        eprintln!("  SCID:     {}", d.scid);
        eprintln!("  Portable: {}", d.portable);
        eprintln!("  Created:  {}", format_local_datetime(d.created_at));
        eprintln!();
    }
    Ok(())
}

pub async fn run_delete_did(
    config_path: Option<PathBuf>,
    did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let keys_ks = store.keyspace("keys")?;
    let imported_ks = store.keyspace("imported_secrets")?;
    let audit_ks = store.keyspace("audit")?;
    let webvh_ks = store.keyspace("webvh")?;
    let seed_store: Arc<dyn crate::keys::seed_store::SeedStore> =
        Arc::from(create_seed_store(&config)?);

    let auth = cli_super_admin();
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let no_bridge: Arc<DIDCommBridge> = Arc::new(DIDCommBridge::placeholder());
    let auth_locks = crate::operations::did_webvh::WebvhAuthLocks::new();
    operations::did_webvh::delete_did_webvh(
        &webvh_ks,
        &keys_ks,
        &imported_ks,
        &audit_ks,
        &*seed_store,
        &auth,
        &did,
        &did_resolver,
        &no_bridge,
        config.vta_did.as_deref(),
        &auth_locks,
        "cli",
    )
    .await?;
    store.persist().await?;

    eprintln!("WebVH DID deleted: {did}");
    Ok(())
}

/// `vta webvh did-log` — print the raw `did.jsonl` log for a DID the
/// VTA knows (provisioning-time snapshot).
pub async fn run_did_log(
    config_path: Option<PathBuf>,
    did: String,
    out: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let webvh_ks = store.keyspace("webvh")?;

    let log = crate::webvh_store::get_did_log(&webvh_ks, &did)
        .await?
        .ok_or_else(|| format!("webvh DID log not found: {did}"))?;

    match out {
        Some(path) => {
            std::fs::write(&path, log.as_bytes())
                .map_err(|e| format!("write {}: {e}", path.display()))?;
            eprintln!(
                "DID log written to {} ({} bytes)",
                path.display(),
                log.len()
            );
        }
        None => {
            // Raw to stdout so it can be piped to a webvh server or
            // saved to `.well-known/did.jsonl` directly.
            print!("{log}");
        }
    }
    Ok(())
}

/// Offline equivalent of `pnm webvh edit-did` — edit a WebVH
/// DID document and publish a new LogEntry. Operates directly on
/// the local fjall keystore. The VTA daemon must be stopped
/// (fjall holds an exclusive lock when the daemon is running).
///
/// Same flag surface as the online command:
/// - No flags → interactive mode (opens `$EDITOR`, asks about
///   webvh parameters, confirms).
/// - `--document <file>` / `--options-file <file>` plus per-field
///   flags → non-interactive mode.
#[allow(clippy::too_many_arguments)]
pub async fn run_edit_did(
    config_path: Option<PathBuf>,
    did: String,
    document: Option<PathBuf>,
    options_file: Option<PathBuf>,
    pre_rotation: Option<u32>,
    ttl: Option<u32>,
    watchers: Vec<String>,
    no_watchers: bool,
    label: Option<String>,
    no_confirm: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use vta_cli_common::commands::webvh_edit::{
        EditFlags, assert_did_id_unchanged, build_options_from_flags, confirm_publish,
        diff_summary, document_id, extract_current_document, launch_editor, prompt_webvh_params,
    };
    use vta_sdk::protocols::did_management::update::UpdateDidWebvhBody;

    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let webvh_ks = store.keyspace("webvh")?;
    let keys_ks = store.keyspace("keys")?;
    let imported_ks = store.keyspace("imported_secrets")?;
    let contexts_ks = store.keyspace("contexts")?;
    let audit_ks = store.keyspace("audit")?;
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let didcomm_bridge: Arc<DIDCommBridge> = Arc::new(DIDCommBridge::placeholder());
    let seed_store: Arc<dyn crate::keys::seed_store::SeedStore> =
        Arc::from(create_seed_store(&config)?);

    // Look up the DID record for scid (update_did_webvh keys off it).
    let record = crate::webvh_store::get_did(&webvh_ks, &did)
        .await?
        .ok_or_else(|| format!("DID `{did}` not found on this VTA"))?;
    let scid = record.scid.clone();

    let any_flag_set = document.is_some()
        || options_file.is_some()
        || pre_rotation.is_some()
        || ttl.is_some()
        || !watchers.is_empty()
        || no_watchers
        || label.is_some();

    let body: UpdateDidWebvhBody = if any_flag_set {
        let flags = EditFlags {
            document_file: document,
            options_file,
            pre_rotation,
            ttl,
            watchers,
            no_watchers,
            label,
        };
        let body = build_options_from_flags(&flags)?;
        if let Some(edited) = &body.document {
            let log = crate::webvh_store::get_did_log(&webvh_ks, &did)
                .await?
                .ok_or_else(|| format!("DID `{did}` has no log on disk"))?;
            let prior = extract_current_document(&log)?;
            assert_did_id_unchanged(&prior, edited)?;
        }
        body
    } else {
        let log = crate::webvh_store::get_did_log(&webvh_ks, &did)
            .await?
            .ok_or_else(|| format!("DID `{did}` has no log on disk"))?;
        let prior = extract_current_document(&log)?;
        let prior_id = document_id(&prior)?.to_string();
        let pre_rotation_status =
            vta_cli_common::commands::webvh_edit::extract_pre_rotation_status(&log);
        eprintln!("Editing DID document for {prior_id}.");
        eprintln!("Opening $EDITOR — save and exit to continue, or quit without saving to abort.");

        let edited = match launch_editor(&prior)? {
            Some(doc) => {
                let summary = diff_summary(&prior, &doc);
                eprintln!();
                eprintln!("Document diff:");
                for line in summary.lines() {
                    eprintln!("  {line}");
                }
                eprintln!();
                Some(doc)
            }
            None => {
                eprintln!("Editor cancelled. No changes will be published.");
                return Ok(());
            }
        };
        prompt_webvh_params(edited, Some(&pre_rotation_status))?
    };

    confirm_publish(&body, no_confirm)?;

    // Convert the wire body into the op-layer options shape. The
    // SDK type carries `witnesses` as opaque JSON to stay
    // didwebvh-rs-free; we deserialise into the typed enum at
    // intake (matching the REST handler's behaviour).
    let witnesses = match body.witnesses {
        Some(value) => Some(
            serde_json::from_value(value)
                .map_err(|e| format!("invalid witnesses JSON in options-file: {e}"))?,
        ),
        None => None,
    };
    let opts = crate::operations::did_webvh::UpdateDidWebvhOptions {
        document: body.document,
        pre_rotation_count: body.pre_rotation_count,
        witnesses,
        watchers: body.watchers,
        ttl: body.ttl,
        label: body.label,
        expected_version_id: body.expected_version_id,
    };

    let auth = cli_super_admin();
    let vta_did = config.vta_did.clone();
    let auth_locks = crate::operations::did_webvh::WebvhAuthLocks::new();
    let result = crate::operations::did_webvh::update_did_webvh(
        &keys_ks,
        &imported_ks,
        &contexts_ks,
        &webvh_ks,
        &audit_ks,
        &*seed_store,
        &auth,
        &scid,
        opts,
        &did_resolver,
        &didcomm_bridge,
        vta_did.as_deref(),
        &auth_locks,
        "vta-cli-offline",
    )
    .await?;
    store.persist().await?;

    eprintln!("WebVH DID updated.");
    eprintln!("  DID:             {}", result.did);
    eprintln!("  New version ID:  {}", result.new_version_id);
    eprintln!("  New SCID:        {}", result.new_scid);
    eprintln!("  Update keys:     {}", result.update_keys_count);
    eprintln!("  Pre-rotation:    {}", result.pre_rotation_key_count);
    Ok(())
}

/// Offline equivalent of `pnm webvh register-did` — promote a
/// serverless WebVH DID to a server-managed one. Operates directly
/// on the local fjall keystore. The VTA daemon must be stopped
/// (fjall holds an exclusive lock when the daemon is running).
pub async fn run_register_did(
    config_path: Option<PathBuf>,
    did: String,
    server: String,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let webvh_ks = store.keyspace("webvh")?;
    let keys_ks = store.keyspace("keys")?;
    let imported_ks = store.keyspace("imported_secrets")?;
    let audit_ks = store.keyspace("audit")?;
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let didcomm_bridge: Arc<DIDCommBridge> = Arc::new(DIDCommBridge::placeholder());
    let seed_store: Arc<dyn crate::keys::seed_store::SeedStore> =
        Arc::from(create_seed_store(&config)?);
    let auth_locks = crate::operations::did_webvh::WebvhAuthLocks::new();

    let auth = cli_super_admin();
    let result = operations::did_webvh::register_did_with_server(
        &webvh_ks,
        &keys_ks,
        &imported_ks,
        &audit_ks,
        &*seed_store,
        &auth,
        &did_resolver,
        &didcomm_bridge,
        operations::did_webvh::RegisterDidWithServerParams {
            did,
            server_id: server,
            force,
            domain: None,
        },
        config.vta_did.as_deref(),
        &auth_locks,
        "vta-cli-offline",
    )
    .await?;
    store.persist().await?;

    eprintln!("DID registered with WebVH server.");
    eprintln!("  DID:         {}", result.did);
    eprintln!("  Server:      {}", result.server_id);
    eprintln!("  Log entries: {}", result.log_entry_count);
    eprintln!();
    eprintln!(
        "Future `pnm services …` mutations will auto-publish to `{}`.",
        result.server_id
    );
    Ok(())
}
