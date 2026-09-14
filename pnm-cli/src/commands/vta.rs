//! Dispatch for `pnm vta …`.
//!
//! Most subcommands are pure config-store operations and run without
//! VTA connectivity ([`run_offline`] returns `true` when it handled
//! them). `Restart` needs an authenticated client and falls through
//! to [`run_restart`] in the post-auth main-loop pass.

use vta_sdk::client::VtaClient;

use vta_cli_common::commands::contexts;
use vta_cli_common::render::{GREEN, RED, RESET};

use crate::auth;
use crate::cli::VtaCommands;
use crate::config::{self, PnmConfig};

/// Handle the offline VTA subcommands. Returns `true` if the command
/// was handled (caller should `return`); `false` if it needs the
/// authenticated dispatch path (currently only `Restart`).
pub(crate) async fn run_offline(
    pnm_config: &mut PnmConfig,
    vta_override: Option<&str>,
    command: &VtaCommands,
) -> bool {
    match command {
        VtaCommands::List => {
            if pnm_config.vtas.is_empty() {
                println!("No VTAs configured.");
                println!("\nRun `pnm setup` to configure your first VTA.");
            } else {
                let default = pnm_config.default_vta.as_deref().unwrap_or("");
                for (slug, vta) in &pnm_config.vtas {
                    let marker = if slug == default { " (default)" } else { "" };
                    println!("  {slug}{marker}");
                    println!("    Name: {}", vta.name);
                    if let Some(ref did) = vta.vta_did {
                        println!("    DID:  {did}");
                    }
                    println!();
                }
            }
            true
        }
        VtaCommands::Use { slug } => {
            if !pnm_config.vtas.contains_key(slug) {
                eprintln!(
                    "Error: VTA '{slug}' not found.\n\nConfigured VTAs: {}",
                    pnm_config
                        .vtas
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                std::process::exit(1);
            }
            pnm_config.default_vta = Some(slug.clone());
            if let Err(e) = config::save_config(pnm_config) {
                eprintln!("Error saving config: {e}");
                std::process::exit(1);
            }
            println!("Default VTA set to '{slug}'.");
            true
        }
        VtaCommands::Remove { slug, force } => {
            let Some(vta) = pnm_config.vtas.get(slug) else {
                eprintln!("Error: VTA '{slug}' not found.");
                std::process::exit(1);
            };

            // Removal drops the stored connection *and* the cached
            // credential — it is not recoverable from the config file,
            // so show what goes and ask before doing it.
            if !force {
                println!("About to remove VTA '{slug}':");
                println!("  Name: {}", vta.name);
                if let Some(ref did) = vta.vta_did {
                    println!("  DID:  {did}");
                }
                println!("  The stored credential for this VTA will be deleted.");
                if pnm_config.default_vta.as_deref() == Some(slug.as_str()) {
                    println!("  This is the default VTA — the default will move.");
                }
                println!();
                let proceed = contexts::confirm_destructive("Proceed with removal?")
                    .unwrap_or_else(|e| {
                        eprintln!("Error reading confirmation: {e}");
                        std::process::exit(1);
                    });
                if !proceed {
                    println!("Aborted.");
                    return true;
                }
            }

            pnm_config.vtas.remove(slug);
            // Clear default if it was the removed VTA
            if pnm_config.default_vta.as_deref() == Some(slug.as_str()) {
                pnm_config.default_vta = pnm_config.vtas.keys().next().cloned();
            }
            // Clear the keyring entry
            let key = config::vta_keyring_key(slug);
            auth::logout(&key);
            if let Err(e) = config::save_config(pnm_config) {
                eprintln!("Error saving config: {e}");
                std::process::exit(1);
            }
            println!("VTA '{slug}' removed.");
            true
        }
        VtaCommands::Info => {
            match config::resolve_vta(vta_override, pnm_config) {
                Ok((slug, vta)) => {
                    println!("Active VTA: {slug}");
                    println!("  Name: {}", vta.name);
                    if let Some(ref did) = vta.vta_did {
                        println!("  DID:  {did}");
                        // REST endpoint isn't stored in PNM config —
                        // it lives in the VTA's DID document. Try to
                        // resolve and surface it for the operator.
                        if let Ok(url) = vta_sdk::session::resolve_vta_url(did).await {
                            println!("  URL:  {url} (from DID)");
                        }
                    }
                    let key = config::vta_keyring_key(&slug);
                    auth::status(&key);
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
            true
        }
        VtaCommands::Restart => false,
    }
}

/// `pnm vta restart` — soft restart the VTA service and poll health.
pub(crate) async fn run_restart(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    println!("Requesting VTA restart...");
    client.restart().await?;
    println!("{GREEN}✓{RESET} Restart initiated");

    // Wait briefly, then check health
    println!("Waiting for VTA to come back...");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    for attempt in 1..=5 {
        match client.health().await {
            Ok(resp) => {
                let ver = resp.version.as_deref().unwrap_or("?");
                println!("{GREEN}✓{RESET} VTA is back (v{ver})");
                return Ok(());
            }
            Err(_) if attempt < 5 => {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(e) => {
                println!("{RED}✗{RESET} VTA did not come back after restart: {e}");
                println!("  The VTA may still be restarting. Try `pnm health` in a few seconds.");
            }
        }
    }
    Ok(())
}
