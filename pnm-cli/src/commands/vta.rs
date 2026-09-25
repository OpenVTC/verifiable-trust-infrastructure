//! Dispatch for `pnm vta …`.
//!
//! Most subcommands are pure config-store operations and run without
//! VTA connectivity ([`run_offline`] returns `true` when it handled
//! them). `Restart` needs an authenticated client and falls through
//! to [`run_restart`] in the post-auth main-loop pass.

use vta_sdk::client::VtaClient;

use vta_cli_common::commands::contexts;
use vta_cli_common::render::{DIM, GREEN, RED, RESET, YELLOW};

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
            if vta_cli_common::render::is_json_output() {
                let default = pnm_config.default_vta.as_deref().unwrap_or("");
                let out: Vec<_> = pnm_config
                    .vtas
                    .iter()
                    .map(|(slug, vta)| {
                        serde_json::json!({
                            "slug": slug,
                            "name": vta.name,
                            "did": vta.vta_did,
                            "url": vta.url,
                            "mediatorDid": vta.mediator_did,
                            "default": slug == default,
                        })
                    })
                    .collect();
                if let Err(e) = vta_cli_common::render::print_json(&out) {
                    eprintln!("Error serializing VTA list: {e}");
                    std::process::exit(1);
                }
                return true;
            }
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
                std::process::exit(crate::exit::NOT_FOUND);
            }
            pnm_config.default_vta = Some(slug.clone());
            if let Err(e) = config::save_config(pnm_config) {
                eprintln!("Error saving config: {e}");
                std::process::exit(1);
            }
            println!("Default VTA set to '{slug}'.");
            true
        }
        VtaCommands::Delete { slug, yes } => {
            let Some(vta) = pnm_config.vtas.get(slug) else {
                eprintln!("Error: VTA '{slug}' not found.");
                std::process::exit(crate::exit::NOT_FOUND);
            };
            let key = config::vta_keyring_key(slug);
            // Read before the keyring entry goes: the notice names the DID
            // whose ACL entry survives on the VTA.
            let client_did = auth::loaded_session(&key).map(|s| s.client_did);

            // Deletion drops the stored connection *and* the cached
            // credential — it is not recoverable from the config file,
            // so show what goes and ask before doing it.
            if !yes {
                println!("About to delete VTA connection '{slug}':");
                println!("  Name: {}", vta.name);
                if let Some(ref did) = vta.vta_did {
                    println!("  DID:  {did}");
                }
                println!("  The stored credential for this VTA will be deleted.");
                if pnm_config.default_vta.as_deref() == Some(slug.as_str()) {
                    println!("  This is the default VTA — the default will move.");
                }
                println!();
                print_local_only_notice(slug, client_did.as_deref());
                println!();
                let proceed = contexts::confirm_destructive("Proceed with deletion?")
                    .unwrap_or_else(|e| {
                        eprintln!("Error reading confirmation: {e}");
                        std::process::exit(1);
                    });
                if !proceed {
                    println!("Aborted.");
                    return true;
                }
            }

            // Before the mutation, not after: once `auth::logout` has run the
            // credential is gone, and a notice about what was just destroyed
            // is of no use to someone who would have stopped.
            if *yes {
                print_local_only_notice(slug, client_did.as_deref());
            }

            pnm_config.vtas.remove(slug);
            // Clear default if it was the deleted VTA
            if pnm_config.default_vta.as_deref() == Some(slug.as_str()) {
                pnm_config.default_vta = pnm_config.vtas.keys().next().cloned();
            }
            // Clear the keyring entry
            auth::logout(&key);
            if let Err(e) = config::save_config(pnm_config) {
                eprintln!("Error saving config: {e}");
                std::process::exit(1);
            }
            println!("{GREEN}✓{RESET} VTA connection '{slug}' deleted.");
            true
        }
        VtaCommands::Info => {
            match config::resolve_vta(vta_override, pnm_config) {
                Ok((slug, vta)) => {
                    if vta_cli_common::render::is_json_output() {
                        let mut url = None;
                        if let Some(ref did) = vta.vta_did {
                            url = vta_sdk::session::resolve_vta_url(did).await.ok();
                        }
                        let key = config::vta_keyring_key(&slug);
                        let out = serde_json::json!({
                            "slug": slug,
                            "name": vta.name,
                            "did": vta.vta_did,
                            "url": url,
                            "mediatorDid": vta.mediator_did,
                            "session": auth::status_json(&key),
                        });
                        if let Err(e) = vta_cli_common::render::print_json(&out) {
                            eprintln!("Error serializing VTA info: {e}");
                            std::process::exit(1);
                        }
                        return true;
                    }
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
        VtaCommands::Qr { did, out } => {
            let (label, did) = match qr_subject(vta_override, pnm_config, did.as_deref()) {
                Ok(subject) => subject,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) = show_qr(label.as_deref(), &did, out.as_deref()) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
            true
        }
        VtaCommands::Restart => false,
    }
}

/// The DID `pnm vta qr` draws, and the label to print above it: the `--did`
/// given, else the active VTA's (`--vta`, then the default).
fn qr_subject(
    vta_override: Option<&str>,
    pnm_config: &PnmConfig,
    explicit: Option<&str>,
) -> Result<(Option<String>, String), Box<dyn std::error::Error>> {
    if let Some(did) = explicit {
        if !did.starts_with("did:") {
            return Err(format!("'{did}' is not a DID — it should start with `did:`").into());
        }
        return Ok((None, did.to_string()));
    }
    let (slug, vta) = config::resolve_vta(vta_override, pnm_config)?;
    let did = vta.vta_did.clone().ok_or_else(|| {
        format!(
            "no DID is stored for VTA '{slug}'.\n\n\
             Finish its setup with `pnm setup continue {slug}`, or pass --did <DID>."
        )
    })?;
    Ok((Some(format!("{slug} ({})", vta.name)), did))
}

/// `pnm vta qr` — print `did` as a terminal QR code, and write it as an SVG
/// when `out` is given.
fn show_qr(
    label: Option<&str>,
    did: &str,
    out: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let lines = vta_cli_common::qr::terminal_lines(did)?;
    if let Some(label) = label {
        println!("{DIM}VTA{RESET}  {label}");
    }
    println!();
    for line in &lines {
        // Indented so the code's white margin stands clear of the prompt.
        println!("  {line}");
    }
    println!();
    println!("{DIM}DID{RESET}  {did}");
    println!("{DIM}Scan with Keyring. The code holds only this public DID.{RESET}");

    if let Some(path) = out {
        std::fs::write(path, vta_cli_common::qr::svg(did)?)
            .map_err(|e| format!("could not write {}: {e}", path.display()))?;
        println!("{GREEN}✓{RESET} Wrote {}", path.display());
    }
    Ok(())
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

/// `pnm vta delete` is not a complete delete: it forgets the connection on
/// this machine, while the VTA keeps the ACL entry that authorises the
/// credential. Say so, and name the command that revokes it, because an
/// operator retiring a credential usually means both.
fn print_local_only_notice(slug: &str, client_did: Option<&str>) {
    eprintln!(
        "{YELLOW}⚠{RESET} This deletes only the local connection and credential for '{slug}'. \
         The VTA, and its ACL entry for this credential, are untouched."
    );
    match client_did {
        Some(did) => eprintln!(
            "  To revoke the credential on the VTA as well, run this from an admin \
             connection to it{DIM} (not if it is that VTA's only admin){RESET}:\n    \
             pnm acl delete {did}"
        ),
        None => eprintln!(
            "  To revoke a credential on the VTA as well, run `pnm acl delete <did>` from \
             an admin connection to it."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VtaConfig;

    fn config_with(vta_did: Option<&str>) -> PnmConfig {
        let mut config = PnmConfig::default();
        config.default_vta = Some("personal".into());
        config.vtas.insert(
            "personal".into(),
            VtaConfig {
                name: "Personal VTA".into(),
                vta_did: vta_did.map(str::to_string),
                url: None,
                mediator_did: None,
            },
        );
        config
    }

    #[test]
    fn qr_draws_the_default_vta_did() {
        let config = config_with(Some("did:webvh:QmScid:vta.example.com"));
        let (label, did) = qr_subject(None, &config, None).unwrap();
        assert_eq!(did, "did:webvh:QmScid:vta.example.com");
        assert_eq!(label.as_deref(), Some("personal (Personal VTA)"));
    }

    #[test]
    fn qr_did_flag_overrides_the_vta_and_needs_no_config() {
        let (label, did) = qr_subject(None, &PnmConfig::default(), Some("did:key:z6Mk")).unwrap();
        assert_eq!(did, "did:key:z6Mk");
        assert!(label.is_none());
    }

    #[test]
    fn qr_refuses_something_that_is_not_a_did() {
        let err = qr_subject(None, &PnmConfig::default(), Some("https://vta.example.com"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a DID"), "{err}");
    }

    #[test]
    fn qr_on_an_unknown_vta_names_the_list_command() {
        let config = config_with(Some("did:webvh:QmScid:vta.example.com"));
        let err = qr_subject(Some("missing"), &config, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("pnm vta list"), "{err}");
    }
}
