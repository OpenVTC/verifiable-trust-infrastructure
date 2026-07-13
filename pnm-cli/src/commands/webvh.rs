//! Dispatch for `pnm webvh …`.

use vta_cli_common::commands::webvh;
use vta_sdk::client::VtaClient;

use crate::cli::WebvhCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: WebvhCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        WebvhCommands::AddServer { id, did, label } => {
            webvh::cmd_webvh_server_add(client, id, did, label).await
        }
        WebvhCommands::ListServers => webvh::cmd_webvh_server_list(client).await,
        WebvhCommands::UpdateServer { id, label } => {
            webvh::cmd_webvh_server_update(client, &id, label).await
        }
        WebvhCommands::RemoveServer { id } => webvh::cmd_webvh_server_remove(client, &id).await,
        WebvhCommands::CreateDid {
            context,
            server,
            did_url,
            path,
            domain,
            label,
            portable,
            mediator_service,
            services,
            pre_rotation,
            did_document,
            did_log,
            no_primary,
            signing_key,
            ka_key,
            template,
            template_context,
            vars,
        } => {
            if server.is_none() && did_url.is_none() {
                Err("either --server or --did-url is required".into())
            } else if server.is_some() && did_url.is_some() {
                Err("--server and --did-url are mutually exclusive".into())
            } else {
                // Default template lookup to the DID's own context so
                // context-local overrides are found before the global
                // fallback.
                let template_context =
                    template_context.or_else(|| template.as_ref().map(|_| context.clone()));
                // Interactive domain prompt: when the caller picked a
                // hosting server but didn't supply `--domain`, list
                // the server's available domains and ask. Non-TTY
                // invocations skip the prompt — the VTA's own
                // resolver runs the caller-default → system-default
                // chain server-side, so an unselected domain is
                // harmless on a single-domain host.
                let domain = if let (Some(srv_id), None) = (server.as_deref(), domain.as_ref()) {
                    prompt_domain_if_interactive(client, srv_id).await?
                } else {
                    domain
                };
                webvh::cmd_webvh_did_create_with_files(
                    client,
                    context,
                    server,
                    did_url,
                    path,
                    domain,
                    label,
                    portable,
                    mediator_service,
                    services,
                    pre_rotation,
                    did_document,
                    did_log,
                    no_primary,
                    signing_key,
                    ka_key,
                    template,
                    template_context,
                    vars,
                )
                .await
            }
        }
        WebvhCommands::EditDid {
            did,
            document,
            options_file,
            pre_rotation,
            ttl,
            watchers,
            no_watchers,
            label,
            no_confirm,
        } => {
            let flags = vta_cli_common::commands::webvh_edit::EditFlags {
                document_file: document,
                options_file,
                pre_rotation,
                ttl,
                watchers,
                no_watchers,
                label,
            };
            webvh::cmd_webvh_did_edit(client, &did, flags, no_confirm).await
        }
        WebvhCommands::RegisterDid {
            did,
            server,
            force,
            domain,
        } => {
            let domain = match domain {
                Some(d) => Some(d),
                None => prompt_domain_if_interactive(client, &server).await?,
            };
            webvh::cmd_webvh_did_register_server(client, &did, &server, force, domain).await
        }
        WebvhCommands::ListDids { context, server } => {
            webvh::cmd_webvh_did_list(client, context.as_deref(), server.as_deref()).await
        }
        WebvhCommands::GetDid { did } => webvh::cmd_webvh_did_get(client, &did).await,
        WebvhCommands::DeleteDid { did } => webvh::cmd_webvh_did_delete(client, &did).await,
        WebvhCommands::DidLog { did, out } => webvh::cmd_webvh_did_log(client, &did, out).await,
        WebvhCommands::ListDomains { server } => cmd_list_domains(client, &server).await,
    }
}

/// Fetch the server's `/api/me/domains` view and print it as a
/// short table. Used by the dedicated `list-domains` subcommand.
async fn cmd_list_domains(
    client: &VtaClient,
    server_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let domains = client.list_webvh_server_domains(server_id).await?;
    if domains.domains.is_empty() {
        println!(
            "No hosting domains available to this VTA on `{server_id}`. \
             Ask the server's admin to grant your VTA's DID an ACL entry \
             scoped to the domain(s) you need."
        );
        return Ok(());
    }
    println!(
        "Hosting domains on `{server_id}`:{}",
        if let Some(d) = &domains.default {
            format!(" (system default: {d})")
        } else {
            String::new()
        }
    );
    for entry in &domains.domains {
        let default = if entry.default_domain {
            " (default)"
        } else {
            ""
        };
        let status = if entry.status == "disabled" {
            " [disabled]"
        } else {
            ""
        };
        let label = entry
            .label
            .as_ref()
            .map(|l| format!(" — {l}"))
            .unwrap_or_default();
        println!("  - {}{}{}{}", entry.name, default, status, label);
    }
    Ok(())
}

/// When the caller didn't pass `--domain` but is targeting a
/// specific hosting server, interactively prompt them to pick one of
/// the server's available domains. Returns `Ok(None)` when stdin is
/// not a TTY (CI / scripted use) so the call proceeds with the
/// server's own resolution chain. Network failures and empty domain
/// lists also fall back to `Ok(None)` rather than blocking the
/// operation — the server's `did-management:unknown_domain` error
/// surfaces any real misconfiguration downstream.
async fn prompt_domain_if_interactive(
    client: &VtaClient,
    server_id: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Ok(None);
    }
    let domains = match client.list_webvh_server_domains(server_id).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "warning: could not list hosting domains on `{server_id}` ({e}); \
                 falling back to the server's default domain."
            );
            return Ok(None);
        }
    };
    if domains.domains.is_empty() {
        return Ok(None);
    }
    if domains.domains.len() == 1 {
        // Single-domain host — no point prompting.
        return Ok(None);
    }
    println!("Available hosting domains on `{server_id}`:");
    for (i, entry) in domains.domains.iter().enumerate() {
        let default = if entry.default_domain {
            " (default)"
        } else {
            ""
        };
        let status = if entry.status == "disabled" {
            " [disabled]"
        } else {
            ""
        };
        println!("  [{}] {}{}{}", i + 1, entry.name, default, status);
    }
    println!("  [0] use server default");
    eprint!(
        "Pick a domain (1..={}, or 0 for default): ",
        domains.domains.len()
    );
    use std::io::Write;
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed == "0" {
        return Ok(None);
    }
    let idx: usize = trimmed
        .parse()
        .map_err(|_| "invalid selection — enter a number from the list".to_string())?;
    let entry = domains
        .domains
        .get(idx.saturating_sub(1))
        .ok_or_else(|| "selection out of range".to_string())?;
    Ok(Some(entry.name.clone()))
}
