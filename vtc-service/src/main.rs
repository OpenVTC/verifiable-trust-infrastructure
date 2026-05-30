// Module tree is declared in lib.rs (so integration tests under
// `tests/` can pull the same modules the binary uses). Re-import the
// pieces this binary needs at the top level.
use vtc_service::{acl_cli, config, did_key, keys, server, status, store};
#[cfg(feature = "setup")]
use vtc_service::{emergency, setup};

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use config::{AppConfig, LogFormat};
use keys::seed_store::create_secret_store;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "vtc", about = "Verifiable Trust Community", version)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the interactive setup wizard
    Setup,
    /// Show VTC status and statistics
    Status,
    /// Create a did:key (offline, no server required)
    CreateDidKey {
        /// Also create an ACL entry with Admin role for the new DID
        #[arg(long)]
        admin: bool,
        /// Human-readable label for the ACL entry
        #[arg(long)]
        label: Option<String>,
    },
    /// Operator-level recovery + administration (offline)
    Admin {
        #[command(subcommand)]
        command: AdminCommands,
    },
    /// Manage ACL entries (offline — run on a **stopped** daemon)
    Acl {
        #[command(subcommand)]
        command: AclCommands,
    },
}

#[derive(Subcommand)]
enum AclCommands {
    /// List every ACL entry.
    List,
    /// Add or update the ACL entry for a DID.
    Add {
        /// The subject DID the entry grants a role to.
        #[arg(long)]
        did: String,
        /// Role: admin | moderator | issuer | member | custom:<name>.
        #[arg(long, default_value = "member")]
        role: String,
        /// Human-readable label.
        #[arg(long)]
        label: Option<String>,
        /// Comma-separated context IDs to scope the entry to.
        #[arg(long, value_delimiter = ',')]
        contexts: Vec<String>,
        /// Expiry in seconds from now (omit for no expiry).
        #[arg(long)]
        expires: Option<u64>,
    },
    /// Remove the ACL entry for a DID.
    Remove {
        /// The subject DID whose entry to delete.
        #[arg(long)]
        did: String,
    },
}

#[derive(Subcommand)]
enum AdminCommands {
    /// Reset the install carve-out via the VTA's recovery path.
    ///
    /// Run on a **stopped** daemon. Authenticates against the VTA
    /// using a fresh ephemeral DID the operator authorizes at the
    /// VTA, then clears every admin ACL entry and admin sister
    /// record locally and mints a fresh install URL the operator
    /// can claim with a new passkey. The daemon's next boot emits
    /// a loud `EmergencyBootstrapInvoked` audit event.
    ///
    /// Replaces the BIP-39-mnemonic-based recovery from M0.10's
    /// initial implementation; see `tasks/vtc-mvp/vta-driven-keys.md`
    /// §4 for the design.
    EmergencyBootstrap {
        /// Skip the "are you sure?" confirmation prompt.
        #[arg(long)]
        yes: bool,
        /// VTA context the recovery DID should be authorized into.
        /// Defaults to the value persisted in `config.toml`.
        #[arg(long)]
        context: Option<String>,
    },
    /// Mint a fresh single-use install URL for `--did`.
    ///
    /// Run on a **stopped** daemon (fjall lock). Non-destructive
    /// to existing admins and passkeys, but DOES grant the
    /// supplied `--did` an admin ACL entry if one doesn't already
    /// exist — otherwise the new passkey would attach to a DID
    /// with no role and login would 403. Operators who want to
    /// invite an existing admin pass the same `--did` they already
    /// granted via `pnm acl create` (or the upgrade path); this is
    /// idempotent.
    ///
    /// Pairs with the install ceremony's separation of admin DID
    /// from passkey: operators can issue invites for any DID they
    /// want to grant admin access, without going through the
    /// destructive `emergency-bootstrap` path.
    Invite {
        /// Admin DID the install URL grants a passkey for.
        #[arg(long)]
        did: String,
        /// Token TTL in seconds (default: 900 = 15 min).
        #[arg(long, default_value_t = 900)]
        ttl: u64,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    #[cfg(feature = "keyring")]
    if let Err(e) = vta_sdk::keyring_init::install_default_store() {
        eprintln!("warning: OS keyring unavailable: {e}");
    }

    print_banner();

    match cli.command {
        Some(Commands::Setup) => {
            #[cfg(feature = "setup")]
            {
                if let Err(e) = setup::run_setup_wizard(cli.config).await {
                    eprintln!("Setup failed: {e}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(feature = "setup"))]
            {
                eprintln!("Setup wizard not available (compiled without 'setup' feature)");
                std::process::exit(1);
            }
        }
        Some(Commands::Status) => {
            if let Err(e) = status::run_status(cli.config).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::CreateDidKey { admin, label }) => {
            let args = did_key::CreateDidKeyArgs {
                config_path: cli.config,
                admin,
                label,
            };
            if let Err(e) = did_key::run_create_did_key(args).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Admin { command }) => {
            #[cfg(feature = "setup")]
            {
                match command {
                    AdminCommands::EmergencyBootstrap { yes, context } => {
                        if let Err(e) = run_emergency_bootstrap_cli(cli.config, yes, context).await
                        {
                            eprintln!("Emergency bootstrap failed: {e}");
                            std::process::exit(1);
                        }
                    }
                    AdminCommands::Invite { did, ttl } => {
                        if let Err(e) = run_invite_cli(cli.config, did, ttl).await {
                            eprintln!("Invite failed: {e}");
                            std::process::exit(1);
                        }
                    }
                }
            }
            #[cfg(not(feature = "setup"))]
            {
                let _ = command;
                eprintln!("admin subcommands are unavailable (compiled without 'setup')");
                std::process::exit(1);
            }
        }
        Some(Commands::Acl { command }) => {
            let result = match command {
                AclCommands::List => acl_cli::run_acl_list(cli.config).await,
                AclCommands::Add {
                    did,
                    role,
                    label,
                    contexts,
                    expires,
                } => {
                    acl_cli::run_acl_add(acl_cli::AclAddArgs {
                        config_path: cli.config,
                        did,
                        role,
                        label,
                        contexts,
                        expires,
                    })
                    .await
                }
                AclCommands::Remove { did } => acl_cli::run_acl_remove(cli.config, did).await,
            };
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        None => {
            let config = match AppConfig::load(cli.config) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Error: {e}");
                    eprintln!();
                    eprintln!("To set up a new VTC instance, run:");
                    eprintln!("  vtc setup");
                    eprintln!();
                    eprintln!("Or specify a config file:");
                    eprintln!("  vtc --config <path>");
                    std::process::exit(1);
                }
            };

            init_tracing(&config);

            let store = store::Store::open(&config.store).expect("failed to open store");
            let secret_store = create_secret_store(&config).expect("failed to create secret store");

            if let Err(e) = server::run(config, store, secret_store).await {
                tracing::error!("server error: {e}");
                std::process::exit(1);
            }
        }
    }
}

/// Interactive `vtc admin emergency-bootstrap` flow.
///
/// 1. Loud warning + confirmation (skippable with `--yes`).
/// 2. Operator authorizes a fresh ephemeral DID at the VTA via
///    `pnm acl create` (the wizard prints the exact command).
/// 3. The driver calls the VTA's `provision-integration` flow
///    (`VtaIntent::AdminRotated`) with that ephemeral DID. The
///    VTA's accept/reject IS the recovery authority — see
///    `tasks/vtc-mvp/vta-driven-keys.md` §4.
/// 4. On success: local admin ACL + sister records cleared, install
///    carve-out reopened, fresh install token minted.
#[cfg(feature = "setup")]
async fn run_emergency_bootstrap_cli(
    config_path: Option<std::path::PathBuf>,
    skip_confirm: bool,
    context: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use dialoguer::Confirm;

    eprintln!();
    eprintln!("⚠️  EMERGENCY BOOTSTRAP");
    eprintln!(
        "This clears every existing admin ACL entry and admin sister record, then\n\
         reopens the install carve-out so a new operator can claim a fresh install URL.\n\
         \n\
         The VTA accepts or rejects the recovery: if your PNM admin credential at the\n\
         VTA is still valid, the VTA will accept it; otherwise this command fails and\n\
         no local state is touched. The daemon's next boot emits a loud\n\
         `EmergencyBootstrapInvoked` audit event.\n"
    );

    if !skip_confirm {
        let ok = Confirm::new()
            .with_prompt("Proceed?")
            .default(false)
            .interact()?;
        if !ok {
            eprintln!("aborted.");
            return Ok(());
        }
    }

    let outcome = emergency::run_emergency_bootstrap(emergency::EmergencyBootstrapArgs {
        config_path,
        context,
    })
    .await?;

    eprintln!();
    eprintln!("✅ emergency bootstrap complete");
    eprintln!(
        "   admin ACL entries cleared:  {}",
        outcome.admin_entries_cleared
    );
    eprintln!(
        "   admin sister records:       {}",
        outcome.admin_records_cleared
    );
    eprintln!();
    eprintln!("Install URL (one-shot, 15 min TTL):");
    eprintln!("   {}", outcome.install_url);
    eprintln!();
    eprintln!("Claim code (required at claim time — keep separate from the URL):");
    eprintln!("   {}", outcome.claim_code);
    eprintln!();
    eprintln!(
        "Restart the daemon (`vtc`) so the `EmergencyBootstrapInvoked` audit event lands.\n\
         Then claim the install URL with a fresh passkey, supplying the claim code above."
    );
    Ok(())
}

/// `vtc admin invite --did <did>` — mint a fresh single-use install
/// URL for an admin DID. Runs on a stopped daemon (fjall lock) and
/// is non-destructive to existing admins and passkeys, but DOES
/// grant the supplied `--did` an Admin ACL entry if one doesn't
/// already exist — otherwise the new passkey would attach to a DID
/// with no role and the operator would 403 on their first login.
#[cfg(feature = "setup")]
async fn run_invite_cli(
    config_path: Option<std::path::PathBuf>,
    admin_did: String,
    ttl_seconds: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    use chrono::{Duration as ChronoDuration, Utc};
    use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
    use vtc_service::auth::session::now_epoch;
    use vtc_service::install::{InstallTokenSigner, InstallTokenStore, mint_install_token};
    use vtc_service::keys::seed_store::create_secret_store;
    use vtc_service::setup::VtcKeyBundle;
    use vti_common::store::Store as VtiStore;

    if !admin_did.starts_with("did:") {
        return Err(format!("--did must start with 'did:' (got '{admin_did}')").into());
    }

    let config = vtc_service::config::AppConfig::load(config_path)?;
    let vtc_did = config
        .vtc_did
        .clone()
        .ok_or("config has no vtc_did — has setup completed?")?;
    let base_url = config
        .public_url
        .clone()
        .ok_or("config has no public_url — operators cannot build a clickable install URL")?;

    let secret_store = create_secret_store(&config)?;
    let bundle_bytes = secret_store
        .get()
        .await?
        .ok_or("secret store has no VTC bundle — has setup completed?")?;
    let bundle = VtcKeyBundle::from_secret_store_bytes(&bundle_bytes)?;

    let ed25519 = bundle.ed25519_private_bytes()?;
    let signer = InstallTokenSigner::from_master_seed(&*ed25519)?;

    // Open the install + ACL keyspaces directly. The daemon must
    // be stopped — fjall does not allow concurrent processes on
    // the same data dir.
    let store = VtiStore::open(&config.store)?;
    let install_ks = store.keyspace("install")?;
    let install_store = InstallTokenStore::new(install_ks);
    let acl_ks = store.keyspace("acl")?;

    // Ensure the ACL entry exists with Admin role. The post-login
    // flow gates on `check_acl(acl_ks, &user.did)`, so a DID
    // without an entry yields a `forbidden` once the passkey
    // ceremony completes. Creating the entry up-front closes that
    // gap and makes `vtc admin invite` the operator's one-shot
    // way to onboard a new admin.
    let acl_already_present = get_acl_entry(&acl_ks, &admin_did).await?.is_some();
    if !acl_already_present {
        let entry = VtcAclEntry {
            did: admin_did.clone(),
            role: VtcRole::Admin,
            label: Some("vtc admin invite".into()),
            allowed_contexts: vec![],
            created_at: now_epoch(),
            created_by: format!("vtc-cli/{}", env!("CARGO_PKG_VERSION")),
            expires_at: None,
        };
        store_acl_entry(&acl_ks, &entry).await?;
    }

    let minted = mint_install_token(&signer, &vtc_did, &admin_did, ttl_seconds)?;
    let claim_code = vtc_service::install::claim_secret::generate();
    let claim_code_hash = vtc_service::install::claim_secret::hash(&claim_code)?;
    let exp = Utc::now() + ChronoDuration::seconds(ttl_seconds as i64);
    install_store
        .record_issued(
            &minted.jti,
            minted.cnonce_bytes,
            *minted.ephemeral_signing_key,
            exp,
            Some(claim_code_hash),
            Some(admin_did.clone()),
        )
        .await?;

    let install_url = format!(
        "{}/admin/install?token={}",
        base_url.trim_end_matches('/'),
        minted.jwt
    );

    eprintln!();
    eprintln!("✅ install URL minted");
    eprintln!("   Admin DID:   {admin_did}");
    eprintln!(
        "   ACL entry:   {}",
        if acl_already_present {
            "pre-existing (left untouched)"
        } else {
            "created (role=admin)"
        }
    );
    eprintln!("   TTL:         {ttl_seconds}s");
    eprintln!();
    eprintln!("Install URL (one-shot):");
    eprintln!("   {install_url}");
    eprintln!();
    eprintln!("Claim code (deliver via a SEPARATE channel — Signal/SMS/in person):");
    eprintln!("   {claim_code}");
    eprintln!();
    eprintln!("Both the URL and the claim code are required to claim the passkey.");
    eprintln!("A leaked URL alone is not enough — the daemon refuses claim without the code.");
    eprintln!();
    eprintln!("Restart the daemon (`vtc`) before claiming — the daemon must be running");
    eprintln!("for the browser to reach `/admin/install` and `/v1/install/claim/*`.");
    Ok(())
}

fn print_banner() {
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{cyan} ██╗   ██╗{magenta}████████╗{yellow} ██████╗{reset}
{cyan} ██║   ██║{magenta}╚══██╔══╝{yellow}██╔════╝{reset}
{cyan} ██║   ██║{magenta}   ██║   {yellow}██║     {reset}
{cyan} ╚██╗ ██╔╝{magenta}   ██║   {yellow}██║     {reset}
{cyan}  ╚████╔╝ {magenta}   ██║   {yellow}╚██████╗{reset}
{cyan}   ╚═══╝  {magenta}   ╚═╝   {yellow} ╚═════╝{reset}
{dim}  Verifiable Trust Community v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

fn init_tracing(config: &AppConfig) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log.level));

    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);

    match config.log.format {
        LogFormat::Json => subscriber.json().init(),
        LogFormat::Text => subscriber.init(),
    }
}
