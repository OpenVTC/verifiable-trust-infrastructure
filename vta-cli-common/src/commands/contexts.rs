use std::io::{self, Write};

use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Cell, Row, Table},
};
use vta_sdk::client::{ContextResponse, CreateDidWebvhRequest, UpdateContextRequest};
use vta_sdk::context_provision::{ContextProvisionBundle, ProvisionedDid};
use vta_sdk::prelude::*;
use vta_sdk::sealed_transfer::SealedPayloadV1;

use crate::render::{is_full_display, print_full_entry, print_full_list_title, print_widget};
use crate::sealed_producer::{SealedRecipient, seal_for_recipient};

pub struct ProvisionDidOptions {
    pub server_id: Option<String>,
    pub did_url: Option<String>,
    pub portable: bool,
    pub add_mediator_service: bool,
    pub pre_rotation_count: u32,
}

pub async fn cmd_context_bootstrap(
    client: &VtaClient,
    id: &str,
    name: &str,
    description: Option<String>,
    admin_label: Option<String>,
    recipient: SealedRecipient,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx_req = CreateContextRequest::new(id, name);
    if let Some(desc) = description {
        ctx_req = ctx_req.description(desc);
    }
    let ctx = client.create_context(ctx_req).await?;
    println!("Context created:");
    println!("  ID:        {}", ctx.id);
    println!("  Name:      {}", ctx.name);
    println!("  Base Path: {}", ctx.base_path);

    // Fetch VTA config so the minted CredentialBundle carries VTA DID/URL.
    let config = client.get_config().await?;
    let vta_did = config
        .community_vta_did
        .clone()
        .ok_or("VTA DID not configured — cannot mint admin credential")?;
    let vta_url = config.public_url.clone();

    // Mint admin did:key locally + register ACL. The VTA never sees the
    // private half; the full bundle reaches the recipient via sealed transfer.
    let (admin_bundle, admin_did) = crate::local_keygen::generate_admin_did_key(vta_did, vta_url);
    let mut acl_req =
        vta_sdk::client::CreateAclRequest::new(&admin_did, "admin").contexts(vec![id.to_string()]);
    if let Some(l) = admin_label {
        acl_req = acl_req.label(l);
    }
    client.create_acl(acl_req).await?;

    let sealed = seal_for_recipient(
        &recipient,
        &SealedPayloadV1::AdminCredential(Box::new(admin_bundle)),
    )
    .await?;
    println!();
    println!("Admin credential created:");
    println!("  DID:  {admin_did}");
    println!("  Role: admin");
    if let Some(ref label) = recipient.label {
        println!("  Recipient: {label}");
    }
    println!();

    crate::sealed_producer::emit_sealed_output(&sealed, None)?;
    Ok(())
}

/// Render a list of context records — table view by default, full
/// `key: value` blocks when `--full-display` is set.
///
/// Shared by the online (`pnm contexts list`, REST) and offline
/// (`vta contexts list`, keystore-direct) paths so both render
/// identically.
pub fn render_context_list(contexts: &[ContextResponse]) {
    if contexts.is_empty() {
        println!("No contexts found.");
        return;
    }

    if is_full_display() {
        print_full_list_title("Contexts", contexts.len());
        for ctx in contexts {
            let did = ctx.did.as_deref().unwrap_or("—");
            let created = ctx
                .created_at
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S %:z")
                .to_string();
            print_full_entry(&[
                ("ID", &ctx.id),
                ("Name", &ctx.name),
                ("DID", did),
                ("Base Path", &ctx.base_path),
                ("Created", &created),
            ]);
        }
        return;
    }

    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let header = Row::new(vec!["ID", "Name", "DID", "Base Path", "Created"])
        .style(header_style)
        .bottom_margin(1);

    let rows: Vec<Row> = contexts
        .iter()
        .map(|ctx| {
            let did = ctx.did.clone().unwrap_or_else(|| "\u{2014}".into());
            let created = ctx
                .created_at
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d")
                .to_string();

            Row::new(vec![
                Cell::from(ctx.id.clone()),
                Cell::from(ctx.name.clone()),
                Cell::from(did).style(Style::default().fg(Color::DarkGray)),
                Cell::from(ctx.base_path.clone()),
                Cell::from(created),
            ])
        })
        .collect();

    let title = format!(" Contexts ({}) ", contexts.len());

    // DID field carries full did:webvh / did:key values (40+ chars).
    // Use `Min` so it expands on wide terminals rather than truncating
    // at the former fixed 30-char width.
    let table = Table::new(
        rows,
        [
            Constraint::Min(16),    // ID
            Constraint::Min(20),    // Name
            Constraint::Min(40),    // DID
            Constraint::Length(16), // Base Path
            Constraint::Length(10), // Created
        ],
    )
    .header(header)
    .column_spacing(2)
    .block(
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    let height = contexts.len() as u16 + 4;
    print_widget(table, height);
}

/// Render a single context record's details, used by `get` and the
/// success path of `update`. Shared by online + offline call sites.
pub fn render_context_record(ctx: &ContextResponse) {
    println!("ID:          {}", ctx.id);
    println!("Name:        {}", ctx.name);
    println!("DID:         {}", ctx.did.as_deref().unwrap_or("(not set)"));
    println!(
        "Description: {}",
        ctx.description.as_deref().unwrap_or("(not set)")
    );
    println!("Base Path:   {}", ctx.base_path);
    println!(
        "Created At:  {}",
        crate::duration::format_local_datetime(ctx.created_at)
    );
    println!(
        "Updated At:  {}",
        crate::duration::format_local_datetime(ctx.updated_at)
    );
}

pub async fn cmd_context_list(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.list_contexts().await?;
    if crate::render::is_json_output() {
        crate::render::print_json(&resp.contexts)?;
        return Ok(());
    }
    render_context_list(&resp.contexts);
    Ok(())
}

pub async fn cmd_context_get(
    client: &VtaClient,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.get_context(id).await?;
    render_context_record(&resp);
    Ok(())
}

/// Options for optionally creating a context-scoped admin ACL entry as
/// part of `pnm contexts create`.
///
/// Omit the entire struct to create the context without touching the ACL —
/// the historical behaviour. Supply a [`AdminAclOptions::did`] to atomically
/// create an `admin`-role ACL entry scoped to the new context in the same
/// CLI invocation.
///
/// Setting [`AdminAclOptions::expires_at`] flips the entry from **permanent**
/// to a **setup ACL** that auto-expires (pruned by the VTA's ACL sweeper) if
/// the admin never authenticates and rotates to a fresh did:key.
#[derive(Debug, Default, Clone)]
pub struct AdminAclOptions {
    /// DID to grant admin access to. Must start with `did:`.
    pub did: Option<String>,
    /// Human-readable label stored on the ACL entry.
    pub label: Option<String>,
    /// Unix-epoch seconds at which the entry auto-expires. `None` = permanent.
    pub expires_at: Option<u64>,
    /// Raw `--admin-expires` input (e.g. `"1h"`). Preserved alongside the
    /// resolved `expires_at` so conflict hints can re-emit the operator's
    /// original duration verbatim instead of a drift-skewed seconds value.
    pub expires_duration: Option<String>,
}

impl AdminAclOptions {
    fn is_requested(&self) -> bool {
        self.did.is_some()
    }
}

pub async fn cmd_context_create(
    client: &VtaClient,
    id: &str,
    name: &str,
    description: Option<String>,
    parent: Option<String>,
    admin: AdminAclOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::render::{RESET, YELLOW};
    use vta_sdk::error::VtaError;

    // The full context path the server will assign (`<parent>/<id>` when nested)
    // — used for the conflict hint before `resp` exists.
    let effective_id = parent
        .as_ref()
        .map_or_else(|| id.to_string(), |p| format!("{p}/{id}"));
    let req = CreateContextRequest {
        id: id.to_string(),
        name: name.to_string(),
        description,
        parent,
    };
    let resp = match client.create_context(req).await {
        Ok(r) => r,
        // Friendly path when the operator's real intent was "grant this DID
        // admin access to this context": the context already exists, so the
        // scaffolding command is the wrong tool — point them at the ACL
        // command and exit cleanly so repeated provisioning scripts don't
        // choke on second runs.
        Err(VtaError::Conflict(_)) if admin.is_requested() => {
            let did = admin.did.as_deref().unwrap_or_default();
            let bin = crate::render::bin_name();
            eprintln!(
                "{YELLOW}\u{26a0}{RESET}  Context '{effective_id}' already exists — skipping context creation."
            );
            eprintln!();
            eprintln!("  The --admin-did was NOT added. To grant admin access to an existing");
            eprintln!("  context, use the ACL command directly:");
            eprintln!();
            let mut hint =
                format!("    {bin} acl create --did {did} --role admin --contexts {effective_id}");
            if let Some(label) = admin.label.as_deref() {
                hint.push_str(&format!(" --label '{label}'"));
            }
            match (admin.expires_duration.as_deref(), admin.expires_at) {
                // Prefer the raw duration the user typed — any latency between
                // --admin-expires being parsed and the conflict firing would
                // otherwise drift the re-rendered seconds (e.g. `1h` → `3599s`).
                (Some(raw), _) => hint.push_str(&format!(" --expires {raw}")),
                (None, Some(expires_at)) => {
                    let remaining = expires_at.saturating_sub(crate::duration::now_unix());
                    hint.push_str(&format!(" --expires {remaining}s"));
                }
                (None, None) => {}
            }
            eprintln!("{hint}");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    println!("Context created:");
    println!("  ID:        {}", resp.id);
    println!("  Name:      {}", resp.name);
    println!("  Base Path: {}", resp.base_path);

    if admin.is_requested() {
        let did = admin.did.as_deref().unwrap_or_default();
        if !did.starts_with("did:") {
            return Err(format!(
                "--admin-did must start with `did:` (got {did:?}) — context was created but no ACL entry was added"
            )
            .into());
        }
        // Scope the admin grant to the **full path** the server assigned
        // (`<parent>/<id>` for a sub-context), not the leaf.
        let mut acl_req =
            vta_sdk::client::CreateAclRequest::new(did, "admin").contexts(vec![resp.id.clone()]);
        if let Some(label) = admin.label.as_deref() {
            acl_req = acl_req.label(label);
        }
        if let Some(expires_at) = admin.expires_at {
            acl_req = acl_req.expires_at(expires_at);
        }
        let acl = client.create_acl(acl_req).await?;

        println!();
        println!("Admin ACL entry created:");
        println!("  DID:        {}", acl.did);
        println!("  Role:       {}", acl.role);
        println!("  Contexts:   {}", acl.allowed_contexts.join(", "));
        if let Some(ref label) = acl.label {
            println!("  Label:      {label}");
        }
        match acl.expires_at {
            Some(secs) => {
                println!(
                    "  Expires at: {} ({}) — setup ACL",
                    crate::duration::format_local_time(secs),
                    crate::duration::format_remaining(secs),
                );
                println!();
                println!("  The admin should authenticate before expiry. On first successful");
                println!("  connect PNM rotates to a fresh long-lived did:key and replaces this");
                println!("  temporary entry with a permanent one.");
            }
            None => println!("  Expires at: (permanent)"),
        }
    }

    Ok(())
}

pub async fn cmd_context_update(
    client: &VtaClient,
    id: &str,
    name: Option<String>,
    did: Option<String>,
    description: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = UpdateContextRequest {
        name,
        did,
        description,
    };
    let resp = client.update_context(id, req).await?;
    println!("Context updated:");
    render_context_record(&resp);
    Ok(())
}

pub async fn cmd_context_update_did(
    client: &VtaClient,
    id: &str,
    did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.update_context_did(id, did).await?;
    println!("Context DID updated:");
    println!("  ID:         {}", resp.id);
    println!(
        "  DID:        {}",
        resp.did.as_deref().unwrap_or("(not set)")
    );
    println!(
        "  Updated At: {}",
        crate::duration::format_local_datetime(resp.updated_at)
    );
    Ok(())
}

/// Print the human-readable resource preview shown before context
/// deletion. Returns `true` when the preview lists any resources
/// (i.e. the caller should prompt for confirmation unless `--force`).
///
/// Shared by online + offline delete paths so both warn about exactly
/// the same resource classes.
pub fn render_delete_context_preview(
    id: &str,
    preview: &vta_sdk::protocols::context_management::delete::DeleteContextPreviewResultBody,
) -> bool {
    let has_resources = !preview.keys.is_empty()
        || !preview.webvh_dids.is_empty()
        || !preview.acl_entries_removed.is_empty()
        || !preview.acl_entries_updated.is_empty();

    if !has_resources {
        return false;
    }

    println!(
        "Deleting context '{}' will remove the following resources:\n",
        id
    );

    if !preview.keys.is_empty() {
        println!("  Keys ({}):", preview.keys.len());
        for key in &preview.keys {
            println!("    - {key}");
        }
    }

    if !preview.webvh_dids.is_empty() {
        println!("  WebVH DIDs ({}):", preview.webvh_dids.len());
        for did in &preview.webvh_dids {
            println!("    - {did}");
        }
    }

    if !preview.acl_entries_removed.is_empty() {
        println!(
            "  ACL entries removed ({}):",
            preview.acl_entries_removed.len()
        );
        for did in &preview.acl_entries_removed {
            println!("    - {did}");
        }
    }

    if !preview.acl_entries_updated.is_empty() {
        println!(
            "  ACL entries updated (context removed from access list) ({}):",
            preview.acl_entries_updated.len()
        );
        for did in &preview.acl_entries_updated {
            println!("    - {did}");
        }
    }

    println!();
    true
}

/// Read a `[y/N]` reply from stdin. Returns `true` for `y` / `yes`,
/// `false` otherwise. Shared by the destructive shared commands so
/// the prompt wording stays consistent.
pub fn confirm_destructive(prompt: &str) -> Result<bool, Box<dyn std::error::Error>> {
    print!("{prompt} [y/N] ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();
    Ok(input == "y" || input == "yes")
}

pub async fn cmd_context_delete(
    client: &VtaClient,
    id: &str,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Fetch a preview of what will be removed
    let preview = client.preview_delete_context(id).await?;

    let has_resources = render_delete_context_preview(id, &preview);

    if has_resources && !force && !confirm_destructive("Proceed with deletion?")? {
        println!("Aborted.");
        return Ok(());
    }

    client.delete_context(id, true).await?;
    println!("Context deleted: {id}");
    Ok(())
}

pub async fn cmd_context_provision(
    client: &VtaClient,
    id: &str,
    name: &str,
    description: Option<String>,
    admin_label: Option<String>,
    did_opts: Option<ProvisionDidOptions>,
    recipient: SealedRecipient,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create the context
    eprintln!("Creating context '{id}'...");
    let mut ctx_req = CreateContextRequest::new(id, name);
    if let Some(desc) = description {
        ctx_req = ctx_req.description(desc);
    }
    client.create_context(ctx_req).await?;

    // 2. Fetch VTA config for URL/DID (needed to build the admin credential).
    let config = client.get_config().await?;
    let vta_did = config
        .community_vta_did
        .clone()
        .ok_or("VTA DID not configured — cannot mint admin credential")?;
    let vta_url = config.public_url.clone();

    // 3. Generate admin did:key locally (private key never crosses the wire)
    //    and register it with the VTA via POST /acl. This replaces the
    //    pre-5c6 `POST /auth/credentials` round-trip that returned a base64
    //    CredentialBundle in a plaintext JSON body.
    eprintln!("Minting local admin credential and registering ACL...");
    let (admin_credential, admin_did) =
        crate::local_keygen::generate_admin_did_key(vta_did, vta_url);
    let mut acl_req =
        vta_sdk::client::CreateAclRequest::new(&admin_did, "admin").contexts(vec![id.to_string()]);
    if let Some(l) = admin_label {
        acl_req = acl_req.label(l);
    }
    client.create_acl(acl_req).await?;

    // 4. Optionally create a DID and collect its secrets
    let provisioned_did = if let Some(opts) = did_opts {
        eprintln!("Creating WebVH DID...");
        let req = CreateDidWebvhRequest {
            context_id: id.to_string(),
            server_id: opts.server_id,
            url: opts.did_url,
            path: None,
            // No explicit path-mode override; the absent legacy `path`
            // resolves to auto-assign server-side.
            path_mode: None,
            // Context-bootstrap path: no per-DID domain override.
            // The server's caller-default → system-default resolves.
            domain: None,
            label: Some(id.to_string()),
            portable: opts.portable,
            add_mediator_service: opts.add_mediator_service,
            additional_services: None,
            pre_rotation_count: opts.pre_rotation_count,
            did_document: None,
            did_log: None,
            set_primary: true,
            signing_key_id: None,
            ka_key_id: None,
            template: None,
            template_context: None,
            template_vars: std::collections::HashMap::new(),
        };
        let did_result = client.create_did_webvh(req).await?;

        // Collect secrets for the DID keys
        eprintln!("Fetching DID key secrets...");
        let mut secrets: Vec<SecretEntry> = Vec::new();
        // Signing key
        secrets.push(
            client
                .get_key_secret(&did_result.signing_key_id)
                .await?
                .into(),
        );
        // Key-agreement key
        secrets.push(client.get_key_secret(&did_result.ka_key_id).await?.into());
        // Pre-rotation keys
        for i in 0..did_result.pre_rotation_key_count {
            let pre_rot_id = format!("{}#pre-rotation-{i}", did_result.did);
            secrets.push(client.get_key_secret(&pre_rot_id).await?.into());
        }

        Some(ProvisionedDid {
            id: did_result.did,
            did_document: did_result.did_document,
            log_entry: did_result.log_entry,
            secrets,
        })
    } else {
        None
    };

    // 5. Build the provision bundle
    let bundle = ContextProvisionBundle {
        context_id: id.to_string(),
        context_name: name.to_string(),
        vta_url: config.public_url,
        vta_did: config.community_vta_did,
        credential: admin_credential,
        admin_did,
        did: provisioned_did,
    };

    // 6. Seal and emit via the shared helper
    crate::sealed_producer::emit_context_provision_bundle(bundle, &recipient, None).await
}

/// Build a `CredentialBundle` from a VTA-stored key, deriving its `did:key`.
///
/// The REST fetch is transport-specific; the derivation is shared via
/// [`CredentialBundle::from_ed25519_seed_multibase`] with the offline
/// path in `vta-service::operations::export::credential_from_key_offline`
/// so the `did:key` encoding and bundle shape can't drift.
async fn credential_from_key(
    client: &VtaClient,
    key_id: &str,
    vta_did: &str,
    vta_url: Option<&str>,
) -> Result<(CredentialBundle, String), Box<dyn std::error::Error>> {
    let secret = client.get_key_secret(key_id).await?;
    CredentialBundle::from_ed25519_seed_multibase(&secret.private_key_multibase, vta_did, vta_url)
        .map_err(|e| format!("Cannot decode key secret: {e}").into())
}

pub async fn cmd_context_reprovision(
    client: &VtaClient,
    id: &str,
    key_id: Option<String>,
    admin_label: Option<String>,
    recipient: SealedRecipient,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Fetch the existing context
    eprintln!("Fetching context '{id}'...");
    let ctx = client.get_context(id).await?;

    // 2. Fetch VTA config for URL/DID
    let config = client.get_config().await?;
    let vta_did = config
        .community_vta_did
        .as_deref()
        .ok_or("VTA DID not configured")?;

    // 3. Resolve admin credential
    let (admin_credential, admin_did) = if let Some(ref kid) = key_id {
        // Direct key ID specified
        eprintln!("Using key '{kid}'...");
        credential_from_key(client, kid, vta_did, config.public_url.as_deref()).await?
    } else {
        // Interactive: list existing Ed25519 keys and let user choose
        let keys_resp = client.list_keys(0, 10000, Some("active"), Some(id)).await?;
        let ed25519_keys: Vec<_> = keys_resp
            .keys
            .iter()
            .filter(|k| k.key_type == KeyType::Ed25519)
            .collect();

        eprintln!();
        eprintln!("Select an admin credential key for context '{id}':");
        eprintln!();
        for (i, key) in ed25519_keys.iter().enumerate() {
            let label = key
                .label
                .as_deref()
                .map(|l| format!(" ({l})"))
                .unwrap_or_default();
            eprintln!("  [{}] {}{}", i + 1, key.key_id, label);
        }
        let new_option = ed25519_keys.len() + 1;
        eprintln!("  [{}] Create a new admin key", new_option);
        eprintln!();
        eprint!("Choice [{}]: ", new_option);
        io::stderr().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        // Default to creating a new key if empty
        let choice: usize = if input.is_empty() {
            new_option
        } else {
            input
                .parse()
                .map_err(|_| format!("Invalid choice: {input}"))?
        };

        if choice == new_option {
            // Create a new Ed25519 key in VTA scoped to this context
            eprintln!("Creating new admin key...");
            let key_resp = client
                .create_key(CreateKeyRequest {
                    key_type: KeyType::Ed25519,
                    derivation_path: None,
                    key_id: None,
                    mnemonic: None,
                    label: admin_label.or_else(|| Some("admin".to_string())),
                    context_id: Some(id.to_string()),
                })
                .await?;
            credential_from_key(
                client,
                &key_resp.key_id,
                vta_did,
                config.public_url.as_deref(),
            )
            .await?
        } else if choice >= 1 && choice <= ed25519_keys.len() {
            let selected = &ed25519_keys[choice - 1];
            eprintln!("Using key '{}'...", selected.key_id);
            credential_from_key(
                client,
                &selected.key_id,
                vta_did,
                config.public_url.as_deref(),
            )
            .await?
        } else {
            return Err(format!("Invalid choice: {choice}").into());
        }
    };

    // 4. Ensure an ACL entry exists for this admin DID
    if client.get_acl(&admin_did).await.is_err() {
        eprintln!("Creating ACL entry for {admin_did}...");
        client
            .create_acl(
                vta_sdk::client::CreateAclRequest::new(&admin_did, "admin")
                    .contexts(vec![id.to_string()]),
            )
            .await?;
    }

    // 5. Collect DID material (document, log, secrets) when the context has a DID
    let provisioned_did = if let Some(ref did_id) = ctx.did {
        eprintln!("Fetching DID material...");

        // Fetch the DID log and extract the DID document from it
        let log_resp = client.get_did_webvh_log(did_id).await?;
        let (did_document, log_entry) = if let Some(ref log_str) = log_resp.log {
            let parsed: serde_json::Value = serde_json::from_str(log_str)
                .map_err(|e| format!("failed to parse DID log: {e}"))?;
            let doc = parsed.get("state").cloned();
            (doc, Some(log_str.clone()))
        } else {
            (None, None)
        };

        // Fetch all active key secrets for this context
        let secrets_bundle = client.fetch_did_secrets_bundle(id).await?;

        Some(ProvisionedDid {
            id: did_id.clone(),
            did_document,
            log_entry,
            secrets: secrets_bundle.secrets,
        })
    } else {
        None
    };

    // 6. Build the provision bundle
    let bundle = ContextProvisionBundle {
        context_id: id.to_string(),
        context_name: ctx.name.clone(),
        vta_url: config.public_url,
        vta_did: config.community_vta_did,
        credential: admin_credential,
        admin_did,
        did: provisioned_did,
    };

    // 7. Seal and emit via the shared helper
    crate::sealed_producer::emit_context_provision_bundle(bundle, &recipient, None).await
}
