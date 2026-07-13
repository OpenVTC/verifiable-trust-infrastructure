//! `pnm` — Personal Network Manager CLI binary.
//!
//! This file is intentionally a thin dispatch table. Clap surface lives
//! in [`crate::cli`]; per-subcommand handlers live in
//! [`crate::commands`]. The flow:
//!
//!   1. Maybe-translate retired `pnm mediator …` invocations into a
//!      `pnm services …` cue and exit.
//!   2. Parse the CLI, install the force-exit watchdog + tracing
//!      subscriber, print the banner.
//!   3. Run the offline pre-auth dispatch (Setup, offline Bootstrap,
//!      offline DidTemplates, most VtaCommands). If any of these
//!      handle the command, return.
//!   4. Resolve the active VTA + (if needed) authenticate.
//!   5. Run the post-auth dispatch.

mod auth;
mod bootstrap;
mod cli;
mod commands;
mod config;
mod setup;

use vta_sdk::client::VtaClient;

use vta_cli_common::render::{DIM, RESET};

use crate::cli::{
    Cli, Commands, DidcommCommands, ServicesCommands, VtaCommands, install_force_exit_handler,
    is_online_template_cmd, print_banner, requires_auth, retired_mediator_redirect,
};
use clap::Parser;

#[tokio::main]
async fn main() {
    // Pin rustls to the aws-lc-rs backend before any TLS object is built;
    // see `vta_sdk::crypto_init`. Without this, rustls 0.23 panics on
    // backend auto-detection when both backends are compiled in.
    vta_sdk::crypto_init::install_default_crypto_provider();

    install_force_exit_handler();

    // Migration cue: the `pnm mediator …` subcommand surface was
    // retired in favour of `pnm services didcomm …`. Detect it
    // before clap rejects the args with a generic "unrecognised
    // subcommand" message and print a copy-pasteable redirect.
    if let Some(replacement) = retired_mediator_redirect(std::env::args()) {
        eprintln!("`pnm mediator …` was retired in this release.");
        eprintln!();
        eprintln!("Run instead:");
        eprintln!("  {replacement}");
        eprintln!();
        eprintln!("See `pnm services --help` for the full surface, or");
        eprintln!("docs/02-vta/runtime-service-management.md.");
        std::process::exit(2);
    }

    let cli = Cli::parse();

    // Propagate --full-display to the shared render module so any list
    // command — including ones reached via the shared vta-cli-common
    // handlers — picks up the setting without threading a bool through
    // every signature.
    vta_cli_common::render::set_full_display(cli.full_display);
    if cli.json {
        vta_cli_common::render::set_output_format(vta_cli_common::render::OutputFormat::Json);
    }
    vta_cli_common::render::set_bin_name("pnm");

    // Initialize tracing: --verbose sets pnm_cli=debug, or respect RUST_LOG
    let filter = if cli.verbose {
        tracing_subscriber::EnvFilter::new("pnm_cli=debug")
    } else {
        tracing_subscriber::EnvFilter::from_default_env()
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .with_writer(std::io::stderr)
        .init();

    #[cfg(feature = "keyring")]
    if let Err(e) = vta_sdk::keyring_init::install_default_store() {
        eprintln!("warning: OS keyring unavailable: {e}");
    }

    print_banner();

    // Load PNM config
    let mut pnm_config = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: could not load config: {e}");
            config::PnmConfig::default()
        }
    };

    // Propagate the optional remote DID-resolver URL to the SDK as an
    // env var. `vta_sdk::resolver::build_did_cache_config_from_env`
    // reads this at every DIDCacheClient construction site, so a single
    // config setting reaches the three SDK helpers PNM uses
    // (resolve_vta_endpoint / resolve_vta_url / resolve_mediator_did)
    // and the local `pnm health` resolver without surface-API churn.
    //
    // Respects any value the operator set in their environment — only
    // sets from config when the env var is absent (or empty).
    if let Some(url) = pnm_config.resolver_url.as_deref()
        && !url.is_empty()
        && std::env::var_os("PNM_RESOLVER_URL")
            .map(|v| v.is_empty())
            .unwrap_or(true)
    {
        // SAFETY: set on the main thread, before any worker / async
        // task that reads PNM_RESOLVER_URL has been spawned.
        unsafe {
            std::env::set_var("PNM_RESOLVER_URL", url);
        }
    }

    // Save overrides + move the parsed command into a local so the
    // pre-auth dispatch can consume the inner enums by value (no
    // borrow-vs-move dance against `cli.command`).
    let url_override = cli.url;
    let vta_override = cli.vta;
    let transport_override = cli.transport;
    let mut command = cli.command;

    // ── Pre-auth dispatch ─────────────────────────────────────────
    //
    // Handle commands that don't need VTA resolution. Each branch
    // either fully handles the command (and `return`s) or hands
    // `command` back to the post-auth dispatch below for the
    // authenticated path.
    let needs_auth = requires_auth(&command);
    match command {
        Commands::Setup {
            command: setup_cmd,
            name,
            overwrite,
        } => {
            let result = commands::setup::run(&mut pnm_config, setup_cmd, name, overwrite).await;
            if let Err(e) = result {
                vta_cli_common::render::print_cli_error(e.as_ref());
                std::process::exit(1);
            }
            return;
        }
        Commands::Bootstrap { command: bs_cmd } => {
            // run_offline returns None for the authed
            // ProvisionIntegration variant; hand `command` back so
            // the post-auth dispatch can run it.
            match commands::bootstrap::run_offline(&bs_cmd, &mut pnm_config).await {
                Some(Ok(())) => return,
                Some(Err(e)) => {
                    vta_cli_common::render::print_cli_error(e.as_ref());
                    std::process::exit(1);
                }
                None => {
                    command = Commands::Bootstrap { command: bs_cmd };
                }
            }
        }
        Commands::DidTemplates { command: dt_cmd } => {
            if is_online_template_cmd(&dt_cmd) {
                command = Commands::DidTemplates { command: dt_cmd };
            } else {
                if let Err(e) = commands::did_templates::run_offline(&dt_cmd) {
                    vta_cli_common::render::print_cli_error(e.as_ref());
                    std::process::exit(1);
                }
                return;
            }
        }
        Commands::Vta { command: vta_cmd } => {
            // Most VTA subcommands are pure config-store ops; only
            // Restart needs VTA connectivity. run_offline reports
            // back so we can fall through cleanly.
            if commands::vta::run_offline(&mut pnm_config, vta_override.as_deref(), &vta_cmd).await
            {
                return;
            }
            command = Commands::Vta { command: vta_cmd };
        }
        Commands::Config {
            command: cli::ConfigCommands::ResolverUrl { url, unset },
        } => {
            // Purely local — mutates the PNM config file at
            // `~/.config/pnm/config.toml`. No VTA round-trip.
            if let Err(e) = commands::config::run_resolver_url(&mut pnm_config, url, unset).await {
                vta_cli_common::render::print_cli_error(e.as_ref());
                std::process::exit(1);
            }
            return;
        }
        other => {
            command = other;
        }
    }

    // Resolve active VTA. Cloned so the immutable borrow of `pnm_config` ends
    // here — the post-dispatch mediator-hint reconciliation below writes back
    // into it.
    let (slug, vta_config) = match config::resolve_vta(vta_override.as_deref(), &pnm_config) {
        Ok((slug, cfg)) => (slug, cfg.clone()),
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };
    let keyring_key = config::vta_keyring_key(&slug);

    // Print VTA info banner
    eprintln!("  {DIM}VTA: {slug}{RESET}");
    if let Some(ref did) = vta_config.vta_did {
        eprintln!("  {DIM}DID: {did}{RESET}");
    }
    eprintln!();

    // Build client
    // For did:key VTAs, use the persisted URL as fallback (DID has no service endpoint).
    let effective_url_override = url_override.as_deref().or(vta_config.url.as_deref());
    let mediator_did_hint = vta_config.mediator_did.as_deref();

    let client = if needs_auth {
        match auth::connect(
            effective_url_override,
            mediator_did_hint,
            transport_override.into(),
            &keyring_key,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                vta_cli_common::render::print_cli_error(e.as_ref());
                std::process::exit(1);
            }
        }
    } else {
        // Non-auth commands (e.g. `pnm health`) build the client without
        // running the SessionStore::connect path. Honour an explicit
        // `--url` override only — never silently fall back to a URL
        // synthesized from the VTA DID. For DIDComm-only VTAs that
        // synthesized URL points at nothing, and downstream code (e.g.
        // `pnm health`) would then probe REST + try to authenticate
        // against an endpoint that does not exist. Commands that need
        // a URL and have none can decide for themselves how to react.
        let url = effective_url_override.unwrap_or_default().to_string();
        VtaClient::new(&url)
    };

    // A pinned `mediator_did` in the config is priority 1 of the connect path
    // and never re-reads the DID document — so after the operator turns DIDComm
    // off (or repoints it), a stale hint would keep dialling the old mediator
    // forever, and `--transport rest` would be needed on every subsequent
    // command. Work out the hint's fate before `command` is moved into dispatch.
    let mediator_hint_update = pending_mediator_hint(&command, &vta_config);

    // ── Post-auth dispatch ────────────────────────────────────────
    let result = match command {
        Commands::Setup { .. } => unreachable!("Setup handled in pre-auth dispatch"),
        Commands::Bootstrap { command } => commands::bootstrap::run_authed(&client, command).await,
        Commands::DidTemplates { command } => {
            commands::did_templates::run_online(&client, command).await
        }
        Commands::Vta {
            command: VtaCommands::Restart,
        } => commands::vta::run_restart(&client).await,
        Commands::Vta { .. } => unreachable!("VTA non-restart handled in pre-auth dispatch"),
        Commands::Health => commands::health::run(effective_url_override, &keyring_key).await,
        Commands::Auth { command } => commands::auth::run(&keyring_key, command).await,
        Commands::Config { command } => commands::config::run(&client, command).await,
        Commands::Services { command } => commands::services::run(&client, command).await,
        Commands::Contexts { command } => commands::contexts::run(&client, command).await,
        Commands::Acl { command } => commands::acl::run(&client, command).await,
        Commands::StepUp { command } => commands::step_up::run(&client, command).await,
        Commands::Device { command } => commands::device::run(&client, command).await,
        Commands::Vault { command } => commands::vault::run(&client, command).await,
        Commands::CredVault { command } => commands::cred_vault::run(&client, command).await,
        Commands::AuthCredential { command } => {
            commands::auth_credential::run(&client, command).await
        }
        Commands::DidMgmt { command } => commands::webvh::run(&client, command.into()).await,
        Commands::Audit { command } => commands::audit::run(&client, command).await,
        Commands::Backup { command } => commands::backup::run(&client, command).await,
        Commands::Keys { command } => commands::keys::run(&client, command).await,
    };

    client.shutdown().await;

    if result.is_ok()
        && let Some(new_hint) = mediator_hint_update
    {
        apply_mediator_hint(&mut pnm_config, &slug, new_hint);
    }

    if let Err(e) = result {
        vta_cli_common::render::print_cli_error(e.as_ref());
        std::process::exit(1);
    }
}

/// What the locally-pinned `mediator_did` should become once `command`
/// succeeds: `None` = leave it alone, `Some(None)` = clear it, `Some(Some(did))`
/// = repoint it.
///
/// Only VTAs that actually pin a mediator are affected — we never *introduce* a
/// hint for a VTA that was happily discovering its mediator from the DID doc.
fn pending_mediator_hint(
    command: &Commands,
    vta_config: &config::VtaConfig,
) -> Option<Option<String>> {
    vta_config.mediator_did.as_ref()?;

    match command {
        Commands::Services {
            command: ServicesCommands::Didcomm { command },
        } => match command {
            DidcommCommands::Disable { .. } => Some(None),
            DidcommCommands::Update {
                new_mediator_did, ..
            } => Some(Some(new_mediator_did.clone())),
            DidcommCommands::Enable { mediator_did, .. } => Some(Some(mediator_did.clone())),
            // Rollback lands on whichever mediator the snapshot held — the CLI
            // doesn't know which — and drain list/cancel change nothing. Leave
            // the pin; `--transport rest` remains the escape hatch.
            _ => None,
        },
        _ => None,
    }
}

/// Write the reconciled hint back to `~/.config/pnm/config.toml`.
///
/// Best-effort: the VTA-side change already succeeded, so a config-write
/// failure is a warning, not an error — but it has to be loud, because the
/// operator's next command would otherwise dial a mediator that is gone.
fn apply_mediator_hint(pnm_config: &mut config::PnmConfig, slug: &str, new_hint: Option<String>) {
    let Some(cfg) = pnm_config.vtas.get_mut(slug) else {
        return;
    };
    cfg.mediator_did = new_hint.clone();

    if let Err(e) = config::save_config(pnm_config) {
        eprintln!(
            "\n  Warning: could not update the pinned mediator DID for '{slug}': {e}\n  \
             Edit `mediator_did` under [vtas.{slug}] in the PNM config by hand, or \
             later commands will keep using the old mediator."
        );
        return;
    }

    match new_hint {
        Some(did) => eprintln!("  {DIM}Repointed pinned mediator DID for '{slug}' → {did}{RESET}"),
        None => eprintln!(
            "  {DIM}Cleared the pinned mediator DID for '{slug}' (DIDComm is no longer advertised){RESET}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{
        AclCommands, AuthCommands, ConfigCommands, ContextCommands, KeyCommands, SetupCommands,
    };

    // ── requires_auth ──────────────────────────────────────────────

    #[test]
    fn test_requires_auth_health_false() {
        assert!(!requires_auth(&Commands::Health));
    }

    #[test]
    fn test_requires_auth_auth_status_false() {
        let cmd = Commands::Auth {
            command: AuthCommands::Status,
        };
        assert!(!requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_setup_false() {
        let cmd = Commands::Setup {
            command: None,
            name: None,
            overwrite: false,
        };
        assert!(!requires_auth(&cmd));
    }

    // ── Setup clap parse shapes ───────────────────────────────────
    //
    // The spec requires all of these to parse unambiguously. If clap
    // surfaces a regression here (e.g. `--name continue` being absorbed
    // as a value for the subcommand), these tests pin the contract.

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("should parse")
    }

    #[test]
    fn setup_bare_parses_all_none() {
        let cli = parse(&["pnm", "setup"]);
        match cli.command {
            Commands::Setup {
                command,
                name,
                overwrite,
            } => {
                assert!(command.is_none());
                assert!(name.is_none());
                assert!(!overwrite);
            }
            _ => panic!("expected Setup"),
        }
    }

    #[test]
    fn setup_with_name_parses_as_non_interactive_phase1() {
        let cli = parse(&["pnm", "setup", "--name", "My VTA"]);
        match cli.command {
            Commands::Setup {
                command,
                name,
                overwrite,
            } => {
                assert!(command.is_none());
                assert_eq!(name.as_deref(), Some("My VTA"));
                assert!(!overwrite);
            }
            _ => panic!("expected Setup"),
        }
    }

    #[test]
    fn setup_with_name_and_overwrite_parses() {
        let cli = parse(&["pnm", "setup", "--name", "foo", "--overwrite"]);
        match cli.command {
            Commands::Setup {
                name, overwrite, ..
            } => {
                assert_eq!(name.as_deref(), Some("foo"));
                assert!(overwrite);
            }
            _ => panic!("expected Setup"),
        }
    }

    #[test]
    fn setup_continue_parses_interactive() {
        let cli = parse(&["pnm", "setup", "continue", "my-vta"]);
        match cli.command {
            Commands::Setup {
                command,
                name,
                overwrite,
            } => {
                assert!(matches!(
                    command,
                    Some(SetupCommands::Continue { vta_did: None, .. })
                ));
                assert!(name.is_none());
                assert!(!overwrite);
                if let Some(SetupCommands::Continue { slug, .. }) = command {
                    assert_eq!(slug, "my-vta");
                }
            }
            _ => panic!("expected Setup"),
        }
    }

    #[test]
    fn setup_continue_parses_non_interactive() {
        let cli = parse(&[
            "pnm",
            "setup",
            "continue",
            "my-vta",
            "--vta-did",
            "did:webvh:abc:vta.example.com:primary",
        ]);
        match cli.command {
            Commands::Setup {
                command: Some(SetupCommands::Continue { slug, vta_did, .. }),
                ..
            } => {
                assert_eq!(slug, "my-vta");
                assert_eq!(
                    vta_did.as_deref(),
                    Some("did:webvh:abc:vta.example.com:primary")
                );
            }
            _ => panic!("expected Setup+Continue"),
        }
    }

    #[test]
    fn setup_name_with_continue_subcommand_parses() {
        // Clap treats subcommand and parent args as orthogonal, so
        // `pnm setup --name foo continue bar` parses. The runtime
        // dispatch rejects this combination — enforced in commit 3
        // (setup logic + pending detection), covered by the
        // integration suite in commit 4. This test pins the parse
        // contract so a future clap upgrade doesn't silently change
        // it.
        let cli = parse(&["pnm", "setup", "--name", "foo", "continue", "bar"]);
        match cli.command {
            Commands::Setup { command, name, .. } => {
                assert_eq!(name.as_deref(), Some("foo"));
                assert!(matches!(command, Some(SetupCommands::Continue { .. })));
            }
            _ => panic!("expected Setup"),
        }
    }

    #[test]
    fn test_requires_auth_keys_true() {
        let cmd = Commands::Keys {
            command: KeyCommands::List {
                limit: 50,
                offset: 0,
                status: None,
                context: None,
            },
        };
        assert!(requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_config_true() {
        let cmd = Commands::Config {
            command: ConfigCommands::Get,
        };
        assert!(requires_auth(&cmd));
    }

    // ── Pinned mediator hint reconciliation ───────────────────────

    fn vta_config(mediator_did: Option<&str>) -> config::VtaConfig {
        config::VtaConfig {
            name: "test".into(),
            vta_did: Some("did:webvh:scid:vta.example.com".into()),
            url: None,
            mediator_did: mediator_did.map(str::to_string),
        }
    }

    fn didcomm(command: DidcommCommands) -> Commands {
        Commands::Services {
            command: ServicesCommands::Didcomm { command },
        }
    }

    #[test]
    fn disable_clears_a_pinned_mediator_hint() {
        let cmd = didcomm(DidcommCommands::Disable { drain_ttl: 0 });
        assert_eq!(
            pending_mediator_hint(&cmd, &vta_config(Some("did:web:old-mediator"))),
            Some(None)
        );
    }

    #[test]
    fn update_repoints_a_pinned_mediator_hint() {
        let cmd = didcomm(DidcommCommands::Update {
            new_mediator_did: "did:web:new-mediator".into(),
            drain_ttl: 86_400,
            force: false,
            handshake_timeout: None,
        });
        assert_eq!(
            pending_mediator_hint(&cmd, &vta_config(Some("did:web:old-mediator"))),
            Some(Some("did:web:new-mediator".into()))
        );
    }

    /// A VTA that discovers its mediator from the DID doc must not acquire a
    /// pin as a side effect of an unrelated `services didcomm` command.
    #[test]
    fn unpinned_vta_never_gains_a_hint() {
        let cmd = didcomm(DidcommCommands::Update {
            new_mediator_did: "did:web:new-mediator".into(),
            drain_ttl: 86_400,
            force: false,
            handshake_timeout: None,
        });
        assert_eq!(pending_mediator_hint(&cmd, &vta_config(None)), None);
    }

    #[test]
    fn enable_repoints_a_pinned_mediator_hint() {
        let cmd = didcomm(DidcommCommands::Enable {
            mediator_did: "did:web:new-mediator".into(),
            force: false,
            handshake_timeout: None,
        });
        assert_eq!(
            pending_mediator_hint(&cmd, &vta_config(Some("did:web:old-mediator"))),
            Some(Some("did:web:new-mediator".into()))
        );
    }

    #[test]
    fn read_only_commands_leave_the_hint_alone() {
        let cmd = Commands::Services {
            command: ServicesCommands::List,
        };
        assert_eq!(
            pending_mediator_hint(&cmd, &vta_config(Some("did:web:old-mediator"))),
            None
        );
    }

    #[test]
    fn test_requires_auth_acl_true() {
        let cmd = Commands::Acl {
            command: AclCommands::List { context: None },
        };
        assert!(requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_contexts_true() {
        let cmd = Commands::Contexts {
            command: ContextCommands::List,
        };
        assert!(requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_vta_false() {
        let cmd = Commands::Vta {
            command: VtaCommands::List,
        };
        assert!(!requires_auth(&cmd));
    }
}
