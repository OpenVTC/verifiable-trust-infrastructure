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
    Cli, Commands, VtaCommands, install_force_exit_handler, is_online_template_cmd, print_banner,
    requires_auth, retired_mediator_redirect,
};
use clap::Parser;

#[tokio::main]
async fn main() {
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

    // Resolve active VTA
    let (slug, vta_config) = match config::resolve_vta(vta_override.as_deref(), &pnm_config) {
        Ok(v) => v,
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

    let client = if needs_auth {
        match auth::connect(effective_url_override, &keyring_key).await {
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
        Commands::AuthCredential { command } => {
            commands::auth_credential::run(&client, command).await
        }
        Commands::DidMgmt { command } => commands::webvh::run(&client, command.into()).await,
        Commands::Webvh { command } => {
            eprintln!(
                "\x1b[1;33mwarning:\x1b[0m `pnm webvh …` has been renamed to \
                 `pnm did-mgmt {{servers,dids}} …`. The old name is accepted for \
                 one release and will be removed in the next minor. \
                 See `pnm did-mgmt --help`."
            );
            commands::webvh::run(&client, command).await
        }
        Commands::Audit { command } => commands::audit::run(&client, command).await,
        Commands::Backup { command } => commands::backup::run(&client, command).await,
        Commands::Keys { command } => commands::keys::run(&client, command).await,
    };

    client.shutdown().await;

    if let Err(e) = result {
        vta_cli_common::render::print_cli_error(e.as_ref());
        std::process::exit(1);
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
