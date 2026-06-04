use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Cell, Row, Table},
};
use vta_sdk::client::{AddWebvhServerRequest, CreateDidWebvhRequest, UpdateWebvhServerRequest};
use vta_sdk::prelude::*;

use crate::render::{is_full_display, print_full_entry, print_full_list_title, print_widget};

pub async fn cmd_webvh_server_add(
    client: &VtaClient,
    id: String,
    did: String,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = AddWebvhServerRequest { id, did, label };
    let record = client.add_webvh_server(req).await?;
    println!("WebVH server added:");
    println!("  ID:  {}", record.id);
    println!("  DID: {}", record.did);
    if let Some(label) = &record.label {
        println!("  Label: {label}");
    }
    Ok(())
}

pub async fn cmd_webvh_server_list(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.list_webvh_servers().await?;

    if resp.servers.is_empty() {
        println!("No WebVH servers configured.");
        return Ok(());
    }

    if is_full_display() {
        print_full_list_title("WebVH Servers", resp.servers.len());
        for s in &resp.servers {
            let label = s.label.as_deref().unwrap_or("—");
            let created = s
                .created_at
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S %:z")
                .to_string();
            print_full_entry(&[
                ("ID", &s.id),
                ("DID", &s.did),
                ("Label", label),
                ("Created", &created),
            ]);
        }
        return Ok(());
    }

    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let header = Row::new(vec!["ID", "DID", "Label", "Created"])
        .style(header_style)
        .bottom_margin(1);

    let rows: Vec<Row> = resp
        .servers
        .iter()
        .map(|s| {
            let label = s.label.clone().unwrap_or_else(|| "\u{2014}".into());
            let created = s
                .created_at
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string();

            Row::new(vec![
                Cell::from(s.id.clone()),
                Cell::from(s.did.clone()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(label),
                Cell::from(created).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let title = format!(" WebVH Servers ({}) ", resp.servers.len());

    let table = Table::new(
        rows,
        [
            Constraint::Length(16), // ID
            Constraint::Min(40),    // DID
            Constraint::Min(16),    // Label
            Constraint::Length(18), // Created
        ],
    )
    .header(header)
    .column_spacing(2)
    .block(
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    let height = resp.servers.len() as u16 + 4;
    print_widget(table, height);

    Ok(())
}

pub async fn cmd_webvh_server_update(
    client: &VtaClient,
    id: &str,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = UpdateWebvhServerRequest { label };
    let record = client.update_webvh_server(id, req).await?;
    println!("WebVH server updated:");
    println!("  ID:  {}", record.id);
    println!("  DID: {}", record.did);
    if let Some(label) = &record.label {
        println!("  Label: {label}");
    }
    Ok(())
}

pub async fn cmd_webvh_server_remove(
    client: &VtaClient,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    client.remove_webvh_server(id).await?;
    println!("WebVH server removed: {id}");
    Ok(())
}

/// `pnm webvh register-did --did <did> --server <id> [--force]` —
/// promote a serverless WebVH DID to a server-managed one.
///
/// Pushes the local `did.jsonl` to the host atomically (single
/// batched write — no resolver gap) and flips the local record's
/// `server_id` so future `pnm services …` mutations auto-publish
/// there. Refused if the DID is already server-managed
/// (re-pointing a hosted DID is out of scope).
///
/// `--force` is honoured only when the VTA's DID authenticates to
/// the host as an admin replacing a slot owned by a different DID.
/// An owner re-registering their own slot is idempotent and always
/// succeeds without `--force`.
pub async fn cmd_webvh_did_register_server(
    client: &VtaClient,
    did: &str,
    server_id: &str,
    force: bool,
    domain: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client
        .register_did_with_server(did, server_id, force, domain.as_deref())
        .await?;
    println!("DID registered with WebVH server.");
    println!("  DID:        {}", result.did);
    println!("  Server:     {}", result.server_id);
    println!("  Log entries: {}", result.log_entry_count);
    println!();
    println!(
        "Future `pnm services …` mutations will auto-publish to `{}`.",
        result.server_id
    );
    Ok(())
}

/// `pnm webvh edit-did --did <did>` — interactive or
/// non-interactive update of an existing WebVH DID document.
///
/// **Interactive (no flags):** fetches the latest published DID
/// document, opens it in `$EDITOR`, asks whether to change any of
/// the webvh parameters (pre-rotation, watchers, TTL, label),
/// confirms, then publishes a new LogEntry.
///
/// **Non-interactive:** supply `--document <file>` (and optionally
/// the per-field flags) or `--options-file <file>` to skip prompts
/// entirely. Useful for scripted flows.
///
/// Refuses to publish if the operator changed the DID's top-level
/// `id` field — the WebVH method treats the DID id as a permanent
/// commitment from the first LogEntry.
pub async fn cmd_webvh_did_edit(
    client: &VtaClient,
    did: &str,
    flags: super::webvh_edit::EditFlags,
    no_confirm: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use super::webvh_edit::{
        build_options_from_flags, confirm_publish, diff_summary, document_id,
        extract_current_document, extract_latest_version_id, extract_pre_rotation_status,
        launch_editor, prompt_webvh_params,
    };

    // Fetch the DID record (for context_id + scid) — this also
    // surfaces a clean 404 if the DID isn't registered.
    let record = client.get_did_webvh(did).await?;
    let context_id = record.context_id.clone();
    let scid = record.scid.clone();

    // Decide between interactive and non-interactive paths. The
    // non-interactive heuristic: any flag set → skip the editor
    // and prompt chain. Interactive mode (no flags) opens $EDITOR
    // and asks the parameter questions.
    let any_flag_set = flags.document_file.is_some()
        || flags.options_file.is_some()
        || flags.pre_rotation.is_some()
        || flags.ttl.is_some()
        || !flags.watchers.is_empty()
        || flags.no_watchers
        || flags.label.is_some();

    let mut body = if any_flag_set {
        let body = build_options_from_flags(&flags)?;
        // Validate the supplied document doesn't change the DID id.
        if let Some(edited) = &body.document {
            let log = client.get_did_webvh_log(did).await?;
            let log_str = log.log.ok_or_else(|| -> Box<dyn std::error::Error> {
                "DID has no published log on the VTA — nothing to edit".into()
            })?;
            let prior = extract_current_document(&log_str)?;
            super::webvh_edit::assert_did_id_unchanged(&prior, edited)?;
        }
        body
    } else {
        // Interactive path: fetch the log, extract the latest doc,
        // open in $EDITOR, then walk the parameter prompts. Capture
        // the latest versionId so the save call can carry an
        // optimistic-concurrency precondition (lost-update guard).
        let log = client.get_did_webvh_log(did).await?;
        let log_str = log.log.ok_or_else(|| -> Box<dyn std::error::Error> {
            "DID has no published log on the VTA — nothing to edit".into()
        })?;
        let prior = extract_current_document(&log_str)?;
        let prior_id = document_id(&prior)?.to_string();
        let fetched_version_id = extract_latest_version_id(&log_str).ok();
        let pre_rotation_status = extract_pre_rotation_status(&log_str);
        eprintln!("Editing DID document for {prior_id}.");
        if let Some(ref v) = fetched_version_id {
            eprintln!("  Current versionId: {v}");
        }
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

        let mut body = prompt_webvh_params(edited, Some(&pre_rotation_status))?;
        // Stamp the precondition so the VTA refuses the save if the
        // DID was updated by another operator while we were editing.
        body.expected_version_id = fetched_version_id;
        body
    };
    // Suppress the unused_mut warning when the flag-driven branch
    // doesn't mutate `body` after construction.
    let _ = &mut body;

    confirm_publish(&body, no_confirm)?;

    let result = client.update_did_webvh(&context_id, &scid, body).await?;
    println!("WebVH DID updated.");
    println!("  DID:             {}", result.did);
    println!("  New version ID:  {}", result.new_version_id);
    println!("  New SCID:        {}", result.new_scid);
    println!("  Update keys:     {}", result.update_keys_count);
    println!("  Pre-rotation:    {}", result.pre_rotation_key_count);
    crate::commands::services::print_serverless_hint(result.serverless, &result.did);
    Ok(())
}

// ── DID commands ────────────────────────────────────────────────────

pub async fn cmd_webvh_did_create(
    client: &VtaClient,
    req: CreateDidWebvhRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.create_did_webvh(req).await?;
    println!("WebVH DID created:");
    println!("  DID:              {}", result.did);
    println!("  Context:          {}", result.context_id);
    if let Some(ref server_id) = result.server_id {
        println!("  Server:           {}", server_id);
    }
    if let Some(ref mnemonic) = result.mnemonic {
        println!("  Mnemonic:         {}", mnemonic);
    }
    println!("  SCID:             {}", result.scid);
    println!("  Portable:         {}", result.portable);
    println!("  Signing key:      {}", result.signing_key_id);
    println!("  KA key:           {}", result.ka_key_id);
    println!("  Pre-rotation keys: {}", result.pre_rotation_key_count);

    if let Some(ref did_document) = result.did_document {
        println!();
        println!("DID Document:");
        println!(
            "{}",
            serde_json::to_string_pretty(did_document)
                .unwrap_or_else(|_| format!("{did_document}"))
        );
    }
    if let Some(ref log_entry) = result.log_entry {
        println!();
        println!("Log Entry (did.jsonl):");
        println!("{}", log_entry);
        println!();
        println!("To self-host this DID, place the log entry in a file named `did.jsonl`");
        println!("at the URL path corresponding to your DID URL.");
    }

    Ok(())
}

/// Helper that reads optional file inputs before building a `CreateDidWebvhRequest`.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_webvh_did_create_with_files(
    client: &VtaClient,
    context_id: String,
    server_id: Option<String>,
    url: Option<String>,
    path: Option<String>,
    domain: Option<String>,
    label: Option<String>,
    portable: bool,
    add_mediator_service: bool,
    services: Option<String>,
    pre_rotation_count: u32,
    did_document_path: Option<String>,
    did_log_path: Option<String>,
    no_primary: bool,
    signing_key_id: Option<String>,
    ka_key_id: Option<String>,
    template: Option<String>,
    template_context: Option<String>,
    template_vars: Vec<(String, String)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let did_document = match did_document_path {
        Some(p) => {
            let content =
                std::fs::read_to_string(&p).map_err(|e| format!("failed to read {p}: {e}"))?;
            Some(
                serde_json::from_str::<serde_json::Value>(&content)
                    .map_err(|e| format!("invalid JSON in {p}: {e}"))?,
            )
        }
        None => None,
    };
    if template.is_some() && (did_document.is_some() || did_log_path.is_some()) {
        return Err("--template is mutually exclusive with --did-document and --did-log".into());
    }
    let did_log = match did_log_path {
        Some(p) => {
            Some(std::fs::read_to_string(&p).map_err(|e| format!("failed to read {p}: {e}"))?)
        }
        None => None,
    };
    let additional_services = services
        .map(|s| serde_json::from_str::<Vec<serde_json::Value>>(&s))
        .transpose()
        .map_err(|e| format!("invalid --services JSON: {e}"))?;

    let template_vars: std::collections::HashMap<String, serde_json::Value> = template_vars
        .into_iter()
        .map(|(k, v)| (k, serde_json::Value::String(v)))
        .collect();

    let req = CreateDidWebvhRequest {
        context_id,
        server_id,
        url,
        path,
        // The `--path` value travels in the legacy `path` field, which
        // resolves to the right mode server-side (absent → auto-assign,
        // `.well-known` → root, else explicit).
        path_mode: None,
        domain,
        label,
        portable,
        add_mediator_service,
        additional_services,
        pre_rotation_count,
        did_document,
        did_log,
        set_primary: !no_primary,
        signing_key_id,
        ka_key_id,
        template,
        template_context,
        template_vars,
    };
    cmd_webvh_did_create(client, req).await
}

pub async fn cmd_webvh_did_list(
    client: &VtaClient,
    context_id: Option<&str>,
    server_id: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.list_dids_webvh(context_id, server_id).await?;

    if resp.dids.is_empty() {
        println!("No WebVH DIDs found.");
        return Ok(());
    }

    if is_full_display() {
        print_full_list_title("WebVH DIDs", resp.dids.len());
        for d in &resp.dids {
            let created = d
                .created_at
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S %:z")
                .to_string();
            let portable = if d.portable { "yes" } else { "no" };
            print_full_entry(&[
                ("DID", &d.did),
                ("Context", &d.context_id),
                ("Server", &d.server_id),
                ("SCID", &d.scid),
                ("Portable", portable),
                ("Created", &created),
            ]);
        }
        return Ok(());
    }

    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let header = Row::new(vec!["DID", "Context", "Server", "Portable", "Created"])
        .style(header_style)
        .bottom_margin(1);

    let rows: Vec<Row> = resp
        .dids
        .iter()
        .map(|d| {
            let portable = if d.portable { "yes" } else { "no" };
            let created = d
                .created_at
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string();

            Row::new(vec![
                Cell::from(d.did.clone()),
                Cell::from(d.context_id.clone()),
                Cell::from(d.server_id.clone()),
                Cell::from(portable.to_string()),
                Cell::from(created).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let title = format!(" WebVH DIDs ({}) ", resp.dids.len());

    let table = Table::new(
        rows,
        [
            Constraint::Min(40),    // DID
            Constraint::Length(16), // Context
            Constraint::Length(16), // Server
            Constraint::Length(10), // Portable
            Constraint::Length(18), // Created
        ],
    )
    .header(header)
    .column_spacing(2)
    .block(
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    let height = resp.dids.len() as u16 + 4;
    print_widget(table, height);

    Ok(())
}

pub async fn cmd_webvh_did_get(
    client: &VtaClient,
    did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let record = client.get_did_webvh(did).await?;
    println!("WebVH DID:");
    println!("  DID:             {}", record.did);
    println!("  Context:         {}", record.context_id);
    println!("  Server:          {}", record.server_id);
    println!("  Mnemonic:        {}", record.mnemonic);
    println!("  SCID:            {}", record.scid);
    println!("  Portable:        {}", record.portable);
    println!("  Log entries:     {}", record.log_entry_count);
    println!(
        "  Created:         {}",
        crate::duration::format_local_datetime(record.created_at)
    );
    println!(
        "  Updated:         {}",
        crate::duration::format_local_datetime(record.updated_at)
    );
    Ok(())
}

pub async fn cmd_webvh_did_delete(
    client: &VtaClient,
    did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    client.delete_did_webvh(did).await?;
    println!("WebVH DID deleted: {did}");
    Ok(())
}

/// `pnm webvh did-log <did> [--out <path>]` — fetch the raw `did.jsonl`
/// log from the VTA's public `GET /did/{did}/log` endpoint.
///
/// Unauthenticated — matches webvh's world-readable log model. Reads
/// the VTA base URL off the caller's current session (no token needed
/// for this endpoint specifically).
pub async fn cmd_webvh_did_log(
    vta_base_url: &str,
    did: &str,
    out: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Cheap URL-path-segment escaping for DIDs. DIDs use `:` (reserved
    // but safe in a path segment) and possibly `#` / `?` — we only need
    // to handle `#` and `?` (both would terminate the path) and `%`
    // (escape char). Keep `:` as-is.
    let escaped_did = did
        .replace('%', "%25")
        .replace('#', "%23")
        .replace('?', "%3F");
    let url = format!("{vta_base_url}/did/{escaped_did}/log");
    let http = reqwest::Client::new();
    let resp = http.get(&url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("GET {url} failed ({status}): {body}").into());
    }
    let log = resp.text().await?;

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
            // Raw to stdout — pipe to a file, to `curl --data-binary`,
            // or to `.well-known/did.jsonl` directly.
            print!("{log}");
        }
    }
    Ok(())
}
