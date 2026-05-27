//! Dispatch for `pnm config …`.

use vta_cli_common::commands::config as config_cmd;
use vta_sdk::client::VtaClient;

use crate::cli::ConfigCommands;
use crate::config::{PnmConfig, save_config};

pub(crate) async fn run(
    client: &VtaClient,
    command: ConfigCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        ConfigCommands::Get => config_cmd::cmd_config_get(client, "").await,
        ConfigCommands::Update {
            community_vta_did,
            community_vta_name,
            public_url,
        } => {
            config_cmd::cmd_config_update(
                client,
                "",
                community_vta_did,
                community_vta_name,
                public_url,
            )
            .await
        }
        ConfigCommands::ResolverUrl { .. } => {
            // Handled in the pre-auth dispatcher (see `main.rs`) — local
            // config mutation, no VTA round-trip. Reaching here means
            // `requires_auth` and the pre-auth match disagreed.
            unreachable!("`pnm config resolver-url` is handled pre-auth in main.rs");
        }
    }
}

/// Local handler for `pnm config resolver-url [url] [--unset]`. Mutates
/// `~/.config/pnm/config.toml`'s `resolver_url` field. No VTA round-trip.
///
/// Argument matrix:
/// - `(None, false)` — print the current value (or "(unset)" if absent).
/// - `(Some(url), false)` — set `resolver_url` to `url`.
/// - `(None, true)` — clear `resolver_url`.
/// - `(Some(_), true)` — rejected by clap's `conflicts_with`.
pub(crate) async fn run_resolver_url(
    config: &mut PnmConfig,
    url: Option<String>,
    unset: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if unset {
        if config.resolver_url.is_some() {
            config.resolver_url = None;
            save_config(config)?;
            eprintln!("Cleared resolver URL. PNM will now resolve DIDs in-process.");
        } else {
            eprintln!("No resolver URL was set — nothing to clear.");
        }
        return Ok(());
    }

    if let Some(url) = url {
        let url = url.trim().to_string();
        if !(url.starts_with("ws://") || url.starts_with("wss://")) {
            return Err(
                format!("resolver URL must start with ws:// or wss:// (got `{url}`)").into(),
            );
        }
        config.resolver_url = Some(url.clone());
        save_config(config)?;
        eprintln!("Set resolver URL: {url}");
        eprintln!("PNM will dispatch DID resolutions to this server on next invocation.");
        return Ok(());
    }

    // No url, no --unset: show current value.
    match &config.resolver_url {
        Some(u) => println!("{u}"),
        None => println!("(unset — PNM resolves DIDs in-process)"),
    }
    Ok(())
}
