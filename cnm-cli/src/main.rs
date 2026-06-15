mod auth;
mod backup;
mod config;
mod setup;

use clap::{Parser, Subcommand};
use config::{community_keyring_key, resolve_community};
use vta_sdk::client::VtaClient;

use vta_cli_common::commands::{
    acl, config as config_cmd, contexts, credentials, did_templates, keys,
};
use vta_cli_common::render::{CYAN, DIM, GREEN, RED, RESET, YELLOW, print_section};

#[derive(Parser)]
#[command(
    name = "cnm-cli",
    about = "CLI for VTC Verifiable Trust Agents (community-admin scope)",
    long_about = "Community Network Manager — community-admin-scoped CLI for the VTA.\n\
                  \n\
                  CNM is deliberately a reduced surface compared to `pnm`:\n\
                  - No `webvh` / `audit` / `keys import` — those are VTA-operator\n\
                    concerns, not community-admin concerns, and live on pnm.\n\
                  - `backup` IS here: it backs up the *community's* state (the VTC),\n\
                    a community-admin concern, distinct from pnm's VTA backup.\n\
                  - DID-template management is mirrored here because community admins\n\
                    own context-scoped templates.\n\
                  - Contexts + ACL + auth-credential generation are present because\n\
                    a community admin needs to provision application identities."
)]
struct Cli {
    /// Base URL of the VTA service (overrides config)
    #[arg(long, env = "VTA_URL")]
    url: Option<String>,

    /// Override the active community for this command
    #[arg(short = 'c', long, global = true)]
    community: Option<String>,

    /// Enable verbose debug output (can also set RUST_LOG=debug)
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Show full identifiers (DIDs, key ids, template names, …) in
    /// list output instead of the compact table view that may truncate
    /// long values. Useful when you need to copy a complete ID.
    #[arg(long, global = true)]
    full_display: bool,

    /// Emit list output as JSON instead of a human-readable table.
    /// Use this for automation: `cnm acl list --json | jq …`.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initial setup wizard
    Setup,

    /// Community management
    Community {
        #[command(subcommand)]
        command: CommunityCommands,
    },

    /// Check service health
    Health,

    /// Authentication management
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },

    /// Key management
    Keys {
        #[command(subcommand)]
        command: KeyCommands,
    },

    /// Application context management
    Contexts {
        #[command(subcommand)]
        command: ContextCommands,
    },

    /// Access control list management
    Acl {
        #[command(subcommand)]
        command: AclCommands,
    },

    /// Generate auth credentials for applications and services
    AuthCredential {
        #[command(subcommand)]
        command: AuthCredentialCommands,
    },

    /// Encrypted full-state backup / restore of the community.
    Backup {
        #[command(subcommand)]
        command: BackupCommands,
    },

    /// Sealed-transfer bootstrap (consumer side).
    Bootstrap {
        #[command(subcommand)]
        command: BootstrapCommands,
    },

    /// DID document template management.
    ///
    /// Phase 1 surface is offline-only: validate a template file, or scaffold
    /// a starter by forking a built-in. Later phases will add list/create/
    /// update/delete commands that hit the VTA.
    #[command(name = "did-templates")]
    DidTemplates {
        #[command(subcommand)]
        command: DidTemplateCommands,
    },
}

#[derive(Subcommand)]
enum DidTemplateCommands {
    /// Validate a DID template file against the v1 schema (offline).
    Validate {
        /// Path to a template JSON file to validate.
        file: std::path::PathBuf,
    },

    /// Scaffold a starter template by forking an embedded built-in (offline).
    Init {
        /// Built-in kind or alias to fork.
        kind: String,
    },

    /// List every built-in template shipped with this SDK (offline).
    #[command(name = "list-builtins")]
    ListBuiltins,

    /// List DID templates stored on the VTA.
    List {
        /// FILTER: scope the listing to one context. Omit for global scope.
        #[arg(long)]
        context: Option<String>,
    },

    /// Show a stored template by name. `--rendered` previews the DID document.
    Show {
        /// Template name.
        name: String,
        /// LOOKUP SCOPE: which scope to search for the named template.
        /// Omit for global scope.
        #[arg(long)]
        context: Option<String>,
        /// Render the template rather than showing its raw record.
        #[arg(long)]
        rendered: bool,
        /// `KEY=VALUE` — supply a template variable. Repeatable.
        #[arg(long = "var", value_parser = parse_key_value_cnm)]
        vars: Vec<(String, String)>,
    },

    /// Upload a new template. Global is super-admin-only; context scope is
    /// writable by context admins.
    Create {
        /// Path to a template JSON file.
        #[arg(long)]
        file: std::path::PathBuf,
        /// TARGET SCOPE: create in this context's scope instead of global.
        #[arg(long)]
        context: Option<String>,
    },

    /// Replace a stored template.
    Update {
        /// Template name.
        name: String,
        /// Path to the replacement JSON file.
        #[arg(long)]
        file: std::path::PathBuf,
        /// TARGET SCOPE: operate on this context's stored template.
        #[arg(long)]
        context: Option<String>,
    },

    /// Delete a stored template.
    Delete {
        /// Template name.
        name: String,
        /// TARGET SCOPE: operate on this context's stored template.
        #[arg(long)]
        context: Option<String>,
    },

    /// Export a stored template to stdout as a portable JSON file.
    Export {
        /// Template name.
        name: String,
        /// LOOKUP SCOPE: export from this context's scope instead of global.
        #[arg(long)]
        context: Option<String>,
    },

    /// Compare a local template file against the VTA-stored version.
    Diff {
        /// Template name.
        name: String,
        /// Path to the local template JSON file.
        #[arg(long)]
        file: std::path::PathBuf,
        /// LOOKUP SCOPE: fetch stored from this context's scope.
        #[arg(long)]
        context: Option<String>,
    },
}

fn parse_key_value_cnm(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("expected KEY=VALUE, got '{s}'"))?;
    Ok((k.to_string(), v.to_string()))
}

fn is_online_template_cmd(cmd: &DidTemplateCommands) -> bool {
    !matches!(
        cmd,
        DidTemplateCommands::Validate { .. }
            | DidTemplateCommands::Init { .. }
            | DidTemplateCommands::ListBuiltins
    )
}

#[derive(Subcommand)]
enum BackupCommands {
    /// Export the community's state to an encrypted backup file.
    Export {
        /// Include the audit log (can be large; off by default).
        #[arg(long)]
        include_audit: bool,
        /// Output file path (default: `vtc-backup-<slug>-<ts>.vtcbak`).
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
    /// Import the community's state from an encrypted backup file.
    Import {
        /// Path to the `.vtcbak` backup file.
        file: std::path::PathBuf,
        /// Preview only — show row counts without applying.
        #[arg(long)]
        preview: bool,
    },
}

#[derive(Subcommand)]
enum BootstrapCommands {
    /// Generate an ephemeral keypair and emit a BootstrapRequest for the producer.
    ///
    /// The X25519 secret is stored on disk under
    /// `~/.config/cnm/bootstrap-secrets/<bundle_id>.key` (mode 0600 on Unix).
    /// The emitted JSON file contains only the public key, a fresh nonce, and
    /// an optional label — no secrets cross the boundary.
    Request {
        /// Output path for the BootstrapRequest JSON.
        #[arg(long)]
        out: std::path::PathBuf,
        /// Optional human-readable label visible to the operator.
        #[arg(long)]
        label: Option<String>,
    },
    /// Open an armored sealed bundle returned by the producer.
    ///
    /// `--expect-digest <hex>` is required by default. Use `--no-verify-digest`
    /// to opt out (with a warning) — there is no silent TOFU.
    Open {
        /// Path to the armored bundle file.
        #[arg(long)]
        bundle: std::path::PathBuf,
        /// Expected SHA-256 digest, communicated out-of-band by the producer.
        #[arg(long)]
        expect_digest: Option<String>,
        /// Skip out-of-band digest verification (testing only — prints a warning).
        #[arg(long)]
        no_verify_digest: bool,
    },
}

#[derive(Subcommand)]
enum CommunityCommands {
    /// List configured communities
    List,
    /// Switch default community
    Use {
        /// Community slug to set as default
        name: String,
    },
    /// Add a new community
    Add,
    /// Remove a community
    Remove {
        /// Community slug to remove
        name: String,
    },
    /// Show current community info
    Status,
    /// Send a DIDComm trust-ping to the community VTA
    Ping,
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Import a credential from an armored sealed bundle and authenticate.
    ///
    /// Expects an armored `VTA SEALED BUNDLE` produced by the operator. The
    /// local secret must already exist under `~/.config/cnm/bootstrap-secrets/`
    /// — produce one with `cnm bootstrap request --out <request>.json`.
    Login {
        /// Path to the armored sealed bundle file.
        #[arg(long)]
        credential_bundle: std::path::PathBuf,
        /// Expected SHA-256 digest, communicated out-of-band by the producer.
        #[arg(long)]
        expect_digest: Option<String>,
        /// Skip out-of-band digest verification (testing only — prints a warning).
        #[arg(long)]
        no_verify_digest: bool,
    },
    /// Clear stored credentials and tokens
    Logout,
    /// Show current authentication status
    Status,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Get current configuration
    Get,
    /// Update configuration
    Update {
        /// VTA DID
        #[arg(long)]
        community_vta_did: Option<String>,
        /// VTA name
        #[arg(long)]
        community_vta_name: Option<String>,
        /// Public URL for this VTA
        #[arg(long)]
        public_url: Option<String>,
    },
}

#[derive(Subcommand)]
enum ContextCommands {
    /// List all application contexts
    List,
    /// Get a context by ID
    Get {
        /// Context ID (e.g. "vta")
        id: String,
    },
    /// Create a new application context
    Create {
        /// Context slug (lowercase alphanumeric + hyphens). When `--parent` is
        /// set this is the leaf segment; the full id becomes `<parent>/<id>`.
        #[arg(long)]
        id: String,
        /// Human-readable name
        #[arg(long)]
        name: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
        /// Parent context path to nest under (e.g. `acme/eng`). Creates a
        /// sub-context — requires admin of the parent. Omit for a top-level
        /// context (super-admin only).
        #[arg(long)]
        parent: Option<String>,
        /// DID to grant admin access to (must start with `did:`). When set,
        /// creates an ACL entry with role=admin scoped to this context.
        #[arg(long)]
        admin_did: Option<String>,
        /// Human-readable label for the admin ACL entry.
        #[arg(long)]
        admin_label: Option<String>,
        /// Setup-ACL expiry — accepts `N[s|m|h|d|w]` (e.g. `24h`, `7d`).
        /// When set, the admin entry auto-expires via the VTC's sweeper.
        /// Requires `--admin-did`.
        #[arg(long, requires = "admin_did")]
        admin_expires: Option<String>,
    },
    /// Update an existing context
    Update {
        /// Context ID
        id: String,
        /// New name
        #[arg(long)]
        name: Option<String>,
        /// Set the DID for this context
        #[arg(long)]
        did: Option<String>,
        /// New description
        #[arg(long)]
        description: Option<String>,
    },
    /// Update the DID for a context (context admin or super admin)
    UpdateDid {
        /// Context ID
        id: String,
        /// The new DID to assign
        did: String,
    },
    /// Delete an application context and all associated resources
    Delete {
        /// Context ID
        id: String,
        /// Skip confirmation and delete immediately
        #[arg(long, short)]
        force: bool,
    },
    /// Create a context and mint a sealed admin credential for its first admin.
    ///
    /// The admin did:key is generated locally and registered via `POST /acl`;
    /// the VTA never sees the private key. The minted credential is sealed to
    /// the `--recipient` and printed as an armored bundle.
    Bootstrap {
        /// Context slug (lowercase alphanumeric + hyphens)
        #[arg(long)]
        id: String,
        /// Human-readable name
        #[arg(long)]
        name: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
        /// Admin label
        #[arg(long)]
        admin_label: Option<String>,
        /// Path to a BootstrapRequest JSON file produced by `cnm bootstrap request`.
        #[arg(long, conflicts_with_all = ["recipient_did", "recipient_nonce"])]
        recipient: Option<std::path::PathBuf>,
        /// Recipient's `did:key` (Ed25519). The X25519 pubkey HPKE seals to
        /// is derived locally.
        #[arg(long, requires = "recipient_nonce", conflicts_with = "recipient")]
        recipient_did: Option<String>,
        /// Recipient's 16-byte nonce in hex.
        #[arg(long, requires = "recipient_did", conflicts_with = "recipient")]
        recipient_nonce: Option<String>,
    },
}

#[derive(Subcommand)]
enum AclCommands {
    /// List ACL entries
    List {
        /// FILTER: only show entries whose `allowed_contexts` include this
        /// context. Omit to see every entry visible to you.
        #[arg(long)]
        context: Option<String>,
    },
    /// Get an ACL entry by DID
    Get {
        /// DID to look up
        did: String,
    },
    /// Create an ACL entry
    Create {
        /// DID to grant access to
        #[arg(long)]
        did: String,
        /// Role: admin, initiator, application, or reader
        #[arg(long)]
        role: String,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Comma-separated context IDs (empty = unrestricted)
        #[arg(long, value_delimiter = ',')]
        contexts: Vec<String>,
        /// Optional expiry — accepts `N[s|m|h|d|w]` (e.g. `24h`, `7d`). When
        /// set, the server's ACL sweeper removes the entry after the deadline.
        /// Without this flag the entry is permanent.
        #[arg(long)]
        expires: Option<String>,
    },
    /// Update an ACL entry
    Update {
        /// DID of the entry to update
        did: String,
        /// New role
        #[arg(long)]
        role: Option<String>,
        /// New label
        #[arg(long)]
        label: Option<String>,
        /// New comma-separated context IDs
        #[arg(long, value_delimiter = ',')]
        contexts: Option<Vec<String>>,
    },
    /// Delete an ACL entry
    Delete {
        /// DID of the entry to delete
        did: String,
    },
}

#[derive(Subcommand)]
enum AuthCredentialCommands {
    /// Generate a new auth credential (did:key minted locally + ACL entry)
    /// and seal it to the given recipient.
    Create {
        /// Role: admin, initiator, application, or reader
        #[arg(long)]
        role: String,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Comma-separated context IDs (empty = unrestricted)
        #[arg(long, value_delimiter = ',')]
        contexts: Vec<String>,
        /// Path to a BootstrapRequest JSON file produced by `cnm bootstrap request`.
        #[arg(long, conflicts_with_all = ["recipient_did", "recipient_nonce"])]
        recipient: Option<std::path::PathBuf>,
        /// Recipient's `did:key` (Ed25519). The X25519 pubkey HPKE seals to
        /// is derived locally.
        #[arg(long, requires = "recipient_nonce", conflicts_with = "recipient")]
        recipient_did: Option<String>,
        /// Recipient's 16-byte nonce in hex.
        #[arg(long, requires = "recipient_did", conflicts_with = "recipient")]
        recipient_nonce: Option<String>,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Create a new key
    Create {
        /// Key type: ed25519, x25519, or p256
        #[arg(long)]
        key_type: String,
        /// BIP-32 derivation path (auto-derived from context if omitted)
        #[arg(long)]
        derivation_path: Option<String>,
        /// BIP-39 mnemonic phrase
        #[arg(long)]
        mnemonic: Option<String>,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Application context ID
        #[arg(long)]
        context_id: Option<String>,
    },
    /// Get a key by ID
    Get {
        /// Key ID
        key_id: String,
        /// Reveal private key material (multibase)
        #[arg(long)]
        secret: bool,
    },
    /// Revoke (invalidate) a key
    Revoke {
        /// Key ID
        key_id: String,
    },
    /// Rename a key
    Rename {
        /// Current key ID
        key_id: String,
        /// New key ID
        new_key_id: String,
    },
    /// List all keys
    List {
        /// Maximum number of keys to return
        #[arg(long, default_value = "50")]
        limit: u64,
        /// Number of keys to skip
        #[arg(long, default_value = "0")]
        offset: u64,
        /// FILTER: only keys with this status (`active` or `revoked`).
        #[arg(long)]
        status: Option<String>,
        /// FILTER: only keys belonging to this context.
        #[arg(long)]
        context: Option<String>,
    },
    /// Export secret key material for one or more keys
    Secrets {
        /// Key IDs to export (omit to export all active keys in --context)
        key_ids: Vec<String>,
        /// REFERENCE: export every active key in this context when no
        /// `key_ids` are supplied.
        #[arg(long)]
        context: Option<String>,
    },
    /// List seed generations
    Seeds,
    /// Rotate to a new seed generation
    RotateSeed {
        /// BIP-39 mnemonic phrase for the new seed (random if omitted)
        #[arg(long)]
        mnemonic: Option<String>,
    },
}

fn print_banner() {
    let green = "\x1b[32m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{green}  ██████╗ {magenta}███╗   ██╗ {yellow}███╗   ███╗{reset}
{green} ██╔════╝ {magenta}████╗  ██║ {yellow}████╗ ████║{reset}
{green} ██║      {magenta}██╔██╗ ██║ {yellow}██╔████╔██║{reset}
{green} ██║      {magenta}██║╚██╗██║ {yellow}██║╚██╔╝██║{reset}
{green} ╚██████╗ {magenta}██║ ╚████║ {yellow}██║ ╚═╝ ██║{reset}
{green}  ╚═════╝ {magenta}╚═╝  ╚═══╝ {yellow}╚═╝     ╚═╝{reset}
{dim}  Community Network Manager v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

/// Implementation of `cnm auth login --credential-bundle <file>`.
///
/// Opens an armored sealed bundle (matching a secret persisted earlier by
/// `cnm bootstrap request`), extracts the admin credential from the payload,
/// and installs it via `auth::login`.
async fn auth_login_sealed(
    client: &VtaClient,
    keyring_key: &str,
    credential_bundle: &std::path::Path,
    expect_digest: Option<&str>,
    no_verify_digest: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_dir =
        config::config_dir().map_err(|e| format!("could not resolve config dir: {e}"))?;
    if no_verify_digest {
        vta_cli_common::sealed_consumer::warn_no_verify_digest();
    }
    let opened = vta_cli_common::sealed_consumer::open_armored_bundle(
        credential_bundle,
        &config_dir,
        expect_digest,
        no_verify_digest,
    )?;
    eprintln!(
        "Sealed bundle opened ({} — digest {}).",
        opened.bundle_id_hex, opened.digest
    );
    let bundle = vta_cli_common::sealed_consumer::extract_admin_credential(opened.payload)?;
    auth::login(&bundle, client.base_url(), keyring_key).await
}

/// Resolve CLI `--recipient` / `--recipient-did` / `--recipient-nonce`
/// arguments into a [`vta_cli_common::sealed_producer::SealedRecipient`].
fn resolve_recipient(
    recipient: Option<&std::path::Path>,
    recipient_did: Option<&str>,
    recipient_nonce: Option<&str>,
) -> Result<vta_cli_common::sealed_producer::SealedRecipient, Box<dyn std::error::Error>> {
    use vta_cli_common::sealed_producer::SealedRecipient;
    if let Some(path) = recipient {
        SealedRecipient::from_file(path)
    } else if let (Some(did), Some(nonce)) = (recipient_did, recipient_nonce) {
        SealedRecipient::from_inline(did, nonce)
    } else {
        Err(
            "a recipient is required: pass --recipient <file> or both --recipient-did and --recipient-nonce"
                .into(),
        )
    }
}

/// Returns true if this command requires authentication.
fn requires_auth(cmd: &Commands) -> bool {
    if let Commands::DidTemplates { command } = cmd {
        return is_online_template_cmd(command);
    }
    !matches!(
        cmd,
        Commands::Health
            | Commands::Auth { .. }
            | Commands::Setup
            | Commands::Community { .. }
            | Commands::Bootstrap { .. }
    )
}

/// `cnm bootstrap request --out <PATH> [--label <NAME>]`
fn bootstrap_request(
    out: std::path::PathBuf,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_dir =
        config::config_dir().map_err(|e| format!("could not resolve config dir: {e}"))?;
    let created = vta_cli_common::sealed_consumer::create_bootstrap_request(&config_dir, label)?;
    let json = serde_json::to_string_pretty(&created.request)?;
    std::fs::write(&out, json.as_bytes())?;

    let client_did = created.request.client_did.clone();
    println!("Bootstrap request written to {}", out.display());
    println!();
    println!("  Bundle-Id:  {}", created.bundle_id_hex);
    println!("  Client DID: {client_did}");
    println!("  Seed saved: {}", created.secret_path.display());
    println!();
    println!("Hand the request to the operator. They return an armored sealed bundle.");
    println!("Verify the SHA-256 digest they print to you out-of-band, then run:");
    println!("  cnm auth login --credential-bundle <file> --expect-digest <hex>");
    Ok(())
}

/// `cnm bootstrap open --bundle <PATH> [--expect-digest <HEX>] [--no-verify-digest]`
fn bootstrap_open(
    bundle_path: &std::path::Path,
    expect_digest: Option<&str>,
    no_verify_digest: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if no_verify_digest {
        vta_cli_common::sealed_consumer::warn_no_verify_digest();
    }
    let config_dir =
        config::config_dir().map_err(|e| format!("could not resolve config dir: {e}"))?;
    let opened = vta_cli_common::sealed_consumer::open_armored_bundle(
        bundle_path,
        &config_dir,
        expect_digest,
        no_verify_digest,
    )?;
    println!("Sealed bundle opened.");
    println!();
    println!("  Bundle-Id:       {}", opened.bundle_id_hex);
    println!("  Digest (sha256): {}", opened.digest);
    println!("  Producer DID:    {}", opened.producer.producer_did);
    println!("  Producer proof:  {:?}", opened.producer.proof);
    println!();
    use vta_sdk::sealed_transfer::SealedPayloadV1;
    match &opened.payload {
        SealedPayloadV1::AdminCredential(c) => {
            println!("Payload: AdminCredential");
            println!("  DID:     {}", c.did);
            println!("  VTA DID: {}", c.vta_did);
            if let Some(ref u) = c.vta_url {
                println!("  VTA URL: {u}");
            }
            println!();
            println!("To install this credential, run:");
            println!(
                "  cnm auth login --credential-bundle <bundle> --expect-digest {}",
                opened.digest
            );
        }
        SealedPayloadV1::ContextProvision(p) => {
            println!("Payload: ContextProvision");
            println!("  Context:   {} ({})", p.context_id, p.context_name);
            println!("  Admin DID: {}", p.admin_did);
        }
        SealedPayloadV1::DidSecrets(s) => {
            println!("Payload: DidSecrets");
            println!("  DID:     {}", s.did);
            println!("  Secrets: {}", s.secrets.len());
        }
        other => {
            println!("Payload: {other:?}");
        }
    }
    Ok(())
}

/// Spawn a Ctrl-C / SIGTERM watcher that lets a second signal force the
/// process out. Operations like a stuck mediator handshake can hold the
/// async runtime for tens of seconds even though the runtime itself
/// observed the signal — without this, the operator has no escape.
fn install_force_exit_handler() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

    tokio::spawn(async {
        loop {
            if tokio::signal::ctrl_c().await.is_err() {
                return;
            }
            if SHUTDOWN_REQUESTED.swap(true, Ordering::SeqCst) {
                eprintln!("\nForcing exit.");
                std::process::exit(130);
            }
            eprintln!("\nShutting down — press Ctrl-C again to force exit.");
        }
    });
}

#[tokio::main]
async fn main() {
    install_force_exit_handler();

    let cli = Cli::parse();

    // Propagate --full-display to the shared render module so list
    // commands from vta-cli-common pick it up.
    vta_cli_common::render::set_full_display(cli.full_display);
    if cli.json {
        vta_cli_common::render::set_output_format(vta_cli_common::render::OutputFormat::Json);
    }
    vta_cli_common::render::set_bin_name("cnm");

    // Initialize tracing: --verbose sets cnm_cli=debug, or respect RUST_LOG
    let filter = if cli.verbose {
        tracing_subscriber::EnvFilter::new("cnm_cli=debug")
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

    // Load CNM config (multi-community)
    let cnm_config = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: could not load config: {e}");
            config::CnmConfig::default()
        }
    };

    // Legacy migration notice
    if cnm_config.communities.is_empty() && auth::has_legacy_session() {
        eprintln!(
            "{YELLOW}Detected legacy single-community session.\n\
             Legacy sessions are no longer used. Run `cnm setup` to configure a community.{RESET}\n"
        );
    }

    // Save the URL override before it's consumed by URL resolution
    let url_override = cli.url.clone();

    // Resolve community URL and keyring key for commands that need a VTA connection.
    // Setup and Community commands handle their own URL resolution.
    // For everything else, the URL is derived from the community VTA
    // DID at runtime — `--url` stays as an ephemeral per-command override.
    let (url, keyring_key): (String, String) =
        if requires_auth(&cli.command) || matches!(cli.command, Commands::Auth { .. }) {
            // Auth-required and Auth commands always need a community
            match resolve_community(cli.community.as_deref(), &cnm_config) {
                Ok((slug, community)) => {
                    let url = match cli.url.clone() {
                        Some(u) => u,
                        None => match community.vta_did.as_deref() {
                            Some(did) => vta_sdk::session::resolve_vta_url(did)
                                .await
                                .unwrap_or_default(),
                            None => String::new(),
                        },
                    };
                    let key = community_keyring_key(&slug);
                    (url, key)
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        } else if matches!(cli.command, Commands::Health) {
            // Health: use community if available, otherwise require --url
            match resolve_community(cli.community.as_deref(), &cnm_config) {
                Ok((slug, community)) => {
                    let url = match cli.url.clone() {
                        Some(u) => u,
                        None => match community.vta_did.as_deref() {
                            Some(did) => vta_sdk::session::resolve_vta_url(did)
                                .await
                                .unwrap_or_default(),
                            None => String::new(),
                        },
                    };
                    let key = community_keyring_key(&slug);
                    (url, key)
                }
                Err(_) => {
                    let url = match cli.url {
                        Some(url) => url,
                        None => {
                            eprintln!("Error: no community configured and no --url provided.\n");
                            eprintln!(
                                "Either configure a community with `cnm setup`, or provide a URL:"
                            );
                            // `--url` is a top-level flag (cli::Cli::url) so it must
                            // appear BEFORE the subcommand or clap rejects the parse.
                            eprintln!("  cnm --url http://localhost:8100 health");
                            std::process::exit(1);
                        }
                    };
                    (url, String::new())
                }
            }
        } else {
            // Setup/Community commands don't need a pre-resolved URL
            let url = cli
                .url
                .unwrap_or_else(|| "http://localhost:8100".to_string());
            (url, String::new())
        };

    // Build client: DIDComm-preferred for authenticated commands, REST for others
    let client = if requires_auth(&cli.command) {
        // Bootstrap session from personal VTA if needed
        if auth::loaded_session(&keyring_key).is_none()
            && let Ok((slug, community)) = resolve_community(cli.community.as_deref(), &cnm_config)
            && community.context_id.is_some()
            && let Some(personal_did) = cnm_config
                .personal_vta
                .as_ref()
                .and_then(|p| p.vta_did.as_deref())
            && let Ok(personal_url) = vta_sdk::session::resolve_vta_url(personal_did).await
            && let Err(e) =
                setup::bootstrap_community_session(&slug, community, &personal_url).await
        {
            eprintln!(
                "Error: could not bootstrap session from personal VTA: {e}\n\n\
                         To fix this, either:\n  \
                         1. Import a sealed credential bundle from your VTA admin:\n     \
                            cnm auth login --credential-bundle <bundle.armored> [--expect-digest <sha256>]\n  \
                         2. Re-run setup: cnm setup"
            );
            std::process::exit(1);
        }

        match auth::connect(url_override.as_deref(), &keyring_key).await {
            Ok(c) => c,
            Err(e) => {
                vta_cli_common::render::print_cli_error(e.as_ref());
                std::process::exit(1);
            }
        }
    } else {
        VtaClient::new(&url)
    };

    let result = match cli.command {
        Commands::Setup => setup::run_setup_wizard().await,
        Commands::Community { command } => cmd_community(command, &cnm_config).await,
        Commands::Health => cmd_health(&client, &keyring_key, &cnm_config).await,
        Commands::Auth { command } => match command {
            AuthCommands::Login {
                credential_bundle,
                expect_digest,
                no_verify_digest,
            } => {
                auth_login_sealed(
                    &client,
                    &keyring_key,
                    &credential_bundle,
                    expect_digest.as_deref(),
                    no_verify_digest,
                )
                .await
            }
            AuthCommands::Logout => {
                auth::logout(&keyring_key);
                Ok(())
            }
            AuthCommands::Status => {
                auth::status(&keyring_key);
                Ok(())
            }
        },
        Commands::Config { command } => match command {
            ConfigCommands::Get => config_cmd::cmd_config_get(&client, "Community ").await,
            ConfigCommands::Update {
                community_vta_did,
                community_vta_name,
                public_url,
            } => {
                config_cmd::cmd_config_update(
                    &client,
                    "Community ",
                    community_vta_did,
                    community_vta_name,
                    public_url,
                )
                .await
            }
        },
        Commands::Contexts { command } => match command {
            ContextCommands::List => contexts::cmd_context_list(&client).await,
            ContextCommands::Get { id } => contexts::cmd_context_get(&client, &id).await,
            ContextCommands::Create {
                id,
                name,
                description,
                parent,
                admin_did,
                admin_label,
                admin_expires,
            } => {
                let expires_at = match admin_expires.as_deref() {
                    Some(s) => match vta_cli_common::duration::duration_to_expires_at(s) {
                        Ok(v) => Some(v),
                        Err(e) => {
                            eprintln!("Error: --admin-expires: {e}");
                            std::process::exit(1);
                        }
                    },
                    None => None,
                };
                let admin = contexts::AdminAclOptions {
                    did: admin_did,
                    label: admin_label,
                    expires_at,
                    expires_duration: admin_expires.clone(),
                };
                contexts::cmd_context_create(&client, &id, &name, description, parent, admin).await
            }
            ContextCommands::Update {
                id,
                name,
                did,
                description,
            } => contexts::cmd_context_update(&client, &id, name, did, description).await,
            ContextCommands::UpdateDid { id, did } => {
                contexts::cmd_context_update_did(&client, &id, &did).await
            }
            ContextCommands::Delete { id, force } => {
                contexts::cmd_context_delete(&client, &id, force).await
            }
            ContextCommands::Bootstrap {
                id,
                name,
                description,
                admin_label,
                recipient,
                recipient_did,
                recipient_nonce,
            } => match resolve_recipient(
                recipient.as_deref(),
                recipient_did.as_deref(),
                recipient_nonce.as_deref(),
            ) {
                Ok(recipient) => {
                    contexts::cmd_context_bootstrap(
                        &client,
                        &id,
                        &name,
                        description,
                        admin_label,
                        recipient,
                    )
                    .await
                }
                Err(e) => Err(e),
            },
        },
        Commands::Acl { command } => match command {
            AclCommands::List { context } => acl::cmd_acl_list(&client, context.as_deref()).await,
            AclCommands::Get { did } => acl::cmd_acl_get(&client, &did).await,
            AclCommands::Create {
                did,
                role,
                label,
                contexts,
                expires,
            } => match expires
                .as_deref()
                .map(vta_cli_common::duration::duration_to_expires_at)
                .transpose()
            {
                Ok(expires_at) => {
                    // cnm does not expose the per-entry step-up flags.
                    acl::cmd_acl_create(&client, did, role, label, contexts, expires_at, None, None)
                        .await
                }
                Err(e) => Err(format!("--expires: {e}").into()),
            },
            AclCommands::Update {
                did,
                role,
                label,
                contexts,
            } => acl::cmd_acl_update(&client, &did, role, label, contexts, None, None).await,
            AclCommands::Delete { did } => acl::cmd_acl_delete(&client, &did).await,
        },
        Commands::AuthCredential { command } => match command {
            AuthCredentialCommands::Create {
                role,
                label,
                contexts,
                recipient,
                recipient_did,
                recipient_nonce,
            } => match resolve_recipient(
                recipient.as_deref(),
                recipient_did.as_deref(),
                recipient_nonce.as_deref(),
            ) {
                Ok(recipient) => {
                    credentials::cmd_auth_credential_create(
                        &client, role, label, contexts, recipient,
                    )
                    .await
                }
                Err(e) => Err(e),
            },
        },
        Commands::Backup { command } => match command {
            BackupCommands::Export {
                include_audit,
                output,
            } => backup::cmd_export(&client, &keyring_key, include_audit, output).await,
            BackupCommands::Import { file, preview } => {
                backup::cmd_import(&client, &keyring_key, file, preview).await
            }
        },
        Commands::Bootstrap { command } => match command {
            BootstrapCommands::Request { out, label } => bootstrap_request(out, label),
            BootstrapCommands::Open {
                bundle,
                expect_digest,
                no_verify_digest,
            } => bootstrap_open(&bundle, expect_digest.as_deref(), no_verify_digest),
        },
        Commands::DidTemplates { command } => match command {
            DidTemplateCommands::Validate { file } => did_templates::cmd_validate(file),
            DidTemplateCommands::Init { kind } => did_templates::cmd_init(kind),
            DidTemplateCommands::ListBuiltins => did_templates::cmd_list_builtins(),
            DidTemplateCommands::List { context } => {
                did_templates::cmd_list(&client, context.as_deref()).await
            }
            DidTemplateCommands::Show {
                name,
                context,
                rendered,
                vars,
            } => did_templates::cmd_show(&client, &name, context.as_deref(), rendered, vars).await,
            DidTemplateCommands::Create { file, context } => {
                did_templates::cmd_create(&client, context.as_deref(), file).await
            }
            DidTemplateCommands::Update {
                name,
                file,
                context,
            } => did_templates::cmd_update(&client, &name, context.as_deref(), file).await,
            DidTemplateCommands::Delete { name, context } => {
                did_templates::cmd_delete(&client, &name, context.as_deref()).await
            }
            DidTemplateCommands::Export { name, context } => {
                did_templates::cmd_export(&client, &name, context.as_deref()).await
            }
            DidTemplateCommands::Diff {
                name,
                file,
                context,
            } => did_templates::cmd_diff(&client, &name, context.as_deref(), file).await,
        },
        Commands::Keys { command } => match command {
            KeyCommands::Create {
                key_type,
                derivation_path,
                mnemonic,
                label,
                context_id,
            } => {
                keys::cmd_key_create(
                    &client,
                    &key_type,
                    derivation_path,
                    mnemonic,
                    label,
                    context_id,
                )
                .await
            }
            KeyCommands::Get { key_id, secret } => {
                keys::cmd_key_get(&client, &key_id, secret).await
            }
            KeyCommands::Revoke { key_id } => keys::cmd_key_revoke(&client, &key_id).await,
            KeyCommands::Rename { key_id, new_key_id } => {
                keys::cmd_key_rename(&client, &key_id, &new_key_id).await
            }
            KeyCommands::List {
                limit,
                offset,
                status,
                context,
            } => keys::cmd_key_list(&client, offset, limit, status, context).await,
            KeyCommands::Secrets { key_ids, context } => {
                keys::cmd_key_secrets(&client, key_ids, context).await
            }
            KeyCommands::Seeds => keys::cmd_seeds_list(&client).await,
            KeyCommands::RotateSeed { mnemonic } => keys::cmd_seeds_rotate(&client, mnemonic).await,
        },
    };

    client.shutdown().await;

    if let Err(e) = result {
        vta_cli_common::render::print_cli_error(e.as_ref());
        std::process::exit(1);
    }
}

async fn cmd_community(
    command: CommunityCommands,
    cnm_config: &config::CnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        CommunityCommands::List => {
            if cnm_config.communities.is_empty() {
                println!("No communities configured.");
                println!("\nRun `cnm setup` to configure your first community.");
                return Ok(());
            }
            let default = cnm_config.default_community.as_deref().unwrap_or("");
            for (slug, community) in &cnm_config.communities {
                let marker = if slug == default { " (default)" } else { "" };
                println!("  {slug}{marker}");
                println!("    Name: {}", community.name);
                if let Some(ref did) = community.vta_did {
                    println!("    DID:  {did}");
                }
                if let Some(ref ctx) = community.context_id {
                    println!("    Context: {ctx}");
                }
                println!();
            }
            Ok(())
        }
        CommunityCommands::Use { name } => {
            if !cnm_config.communities.contains_key(&name) {
                return Err(format!(
                    "community '{name}' not found.\n\nConfigured communities: {}",
                    cnm_config
                        .communities
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
                .into());
            }
            let mut config = config::load_config()?;
            config.default_community = Some(name.clone());
            config::save_config(&config)?;
            println!("Default community set to '{name}'.");
            Ok(())
        }
        CommunityCommands::Add => setup::add_community().await,
        CommunityCommands::Remove { name } => {
            let config = config::load_config()?;
            if !config.communities.contains_key(&name) {
                return Err(format!("community '{name}' not found.").into());
            }

            let confirm = dialoguer::Confirm::new()
                .with_prompt(format!(
                    "Remove community '{name}'? This will delete its stored credentials."
                ))
                .default(false)
                .interact()?;

            if !confirm {
                println!("Cancelled.");
                return Ok(());
            }

            let mut config = config;
            config.communities.remove(&name);
            // Clear default if it was the removed community
            if config.default_community.as_deref() == Some(&name) {
                config.default_community = config.communities.keys().next().cloned();
            }
            // Clear the keyring entry
            auth::logout(&community_keyring_key(&name));
            config::save_config(&config)?;
            println!("Community '{name}' removed.");
            Ok(())
        }
        CommunityCommands::Status => {
            match resolve_community(None, cnm_config) {
                Ok((slug, community)) => {
                    println!("Active community: {slug}");
                    println!("  Name: {}", community.name);
                    if let Some(ref did) = community.vta_did {
                        println!("  DID:  {did}");
                        // REST endpoint is derived from the DID document at
                        // runtime — show what was resolved so the operator
                        // can see the live URL.
                        if let Ok(url) = vta_sdk::session::resolve_vta_url(did).await {
                            println!("  URL:  {url} (from DID)");
                        }
                    }
                    if let Some(ref ctx) = community.context_id {
                        println!("  Context: {ctx}");
                    }
                    let key = community_keyring_key(&slug);
                    auth::status(&key);
                }
                Err(_) => {
                    println!("No community configured.");
                    println!("\nRun `cnm setup` to get started.");
                }
            }
            Ok(())
        }
        CommunityCommands::Ping => cmd_community_ping(cnm_config).await,
    }
}

async fn cmd_community_ping(
    cnm_config: &config::CnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let (slug, community) = resolve_community(None, cnm_config)?;
    println!("Community: {} ({slug})", community.name);

    // Need a session to get client DID + VTA DID
    let key = community_keyring_key(&slug);
    let session = match auth::loaded_session(&key) {
        Some(s) => s,
        None => {
            return Err("not authenticated — run `cnm auth login` first".into());
        }
    };

    let vta_did = session
        .vta_did
        .as_deref()
        .ok_or("community session is pending VTA binding — finish `cnm setup` first")?;
    let mediator_did = match vta_sdk::session::resolve_mediator_did(vta_did).await? {
        Some(did) => did,
        None => {
            println!("  This community is not using DIDComm Messaging.");
            return Ok(());
        }
    };

    println!("  {CYAN}{:<13}{RESET} {vta_did}", "VTA DID");
    println!("  {CYAN}{:<13}{RESET} {mediator_did}", "Mediator DID");

    let timeout = std::time::Duration::from_secs(10);
    match tokio::time::timeout(
        timeout,
        vta_sdk::session::send_trust_ping(
            &session.client_did,
            &session.private_key_multibase,
            &mediator_did,
            Some(vta_did),
        ),
    )
    .await
    {
        Ok(Ok(latency)) => println!(
            "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} pong ({latency}ms)",
            "Trust-ping"
        ),
        Ok(Err(e)) => println!(
            "  {CYAN}{:<13}{RESET} {RED}✗{RESET} failed: {e}",
            "Trust-ping"
        ),
        Err(_) => println!(
            "  {CYAN}{:<13}{RESET} {RED}✗{RESET} timed out",
            "Trust-ping"
        ),
    }
    Ok(())
}

async fn cmd_health(
    client: &VtaClient,
    keyring_key: &str,
    cnm_config: &config::CnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use std::time::Duration;

    let ping_timeout = Duration::from_secs(10);

    // ── Community VTA ──────────────────────────────────────────────
    print_section("Community VTA");

    match client.health().await {
        Ok(resp) => {
            let ver = resp
                .version
                .as_deref()
                .map(|v| format!(" (v{v})"))
                .unwrap_or_default();
            println!("  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} ok{ver}", "Service");
        }
        Err(e) => {
            println!(
                "  {CYAN}{:<13}{RESET} {RED}✗{RESET} unreachable ({e})",
                "Service"
            );
            // Continue to personal VTA section instead of returning error
            print_personal_vta_section(cnm_config, None, ping_timeout).await;
            return Ok(());
        }
    }
    println!("  {CYAN}{:<13}{RESET} {}", "URL", client.base_url());

    // Create a shared DID resolver for both sections
    let resolver = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(r) => Some(r),
        Err(e) => {
            println!("  {DIM}DID resolution skipped (resolver unavailable: {e}){RESET}");
            None
        }
    };

    // Community DID resolution + trust-ping
    let session = if keyring_key.is_empty() {
        None
    } else {
        auth::loaded_session(keyring_key)
    };
    if let Some(ref session) = session {
        if let Some(ref resolver) = resolver {
            print_did_resolution(resolver, "Client DID", &session.client_did, false).await;

            if let Some(vta_did) = session.vta_did.as_deref() {
                let mediator_did = print_did_resolution(resolver, "VTA DID", vta_did, true).await;

                if let Some(ref mediator_did) = mediator_did {
                    print_did_resolution(resolver, "Mediator DID", mediator_did, false).await;
                    match tokio::time::timeout(
                        ping_timeout,
                        vta_sdk::session::send_trust_ping(
                            &session.client_did,
                            &session.private_key_multibase,
                            mediator_did,
                            None,
                        ),
                    )
                    .await
                    {
                        Ok(Ok(latency)) => println!(
                            "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} pong ({latency}ms)",
                            "Trust-ping"
                        ),
                        Ok(Err(e)) => println!(
                            "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping failed: {e}",
                            "Trust-ping"
                        ),
                        Err(_) => println!(
                            "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping timed out",
                            "Trust-ping"
                        ),
                    }
                }
            } else {
                println!(
                    "  {DIM}(session pending VTA binding — finish `cnm setup` to enable DID resolution){RESET}"
                );
            }
        }
    } else {
        println!("  {DIM}(not authenticated — DID resolution skipped){RESET}");
    }

    // ── Personal VTA ───────────────────────────────────────────────
    print_personal_vta_section(cnm_config, resolver.as_ref(), ping_timeout).await;

    Ok(())
}

async fn print_personal_vta_section(
    cnm_config: &config::CnmConfig,
    resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    ping_timeout: std::time::Duration,
) {
    print_section("Personal VTA");

    let Some(ref personal) = cnm_config.personal_vta else {
        println!("  {DIM}Not configured.{RESET}");
        return;
    };
    let Some(personal_did) = personal.vta_did.as_deref() else {
        println!(
            "  {DIM}(personal VTA configured without a DID — finish `cnm setup` to enable health checks){RESET}"
        );
        return;
    };

    // REST endpoint is derived from the personal VTA's DID document on
    // every call. Surface what was resolved so the operator can see the
    // live URL.
    let personal_url = match vta_sdk::session::resolve_vta_url(personal_did).await {
        Ok(url) => url,
        Err(e) => {
            println!(
                "  {CYAN}{:<13}{RESET} {RED}✗{RESET} could not resolve REST endpoint from {personal_did}: {e}",
                "URL"
            );
            return;
        }
    };
    let personal_client = VtaClient::new(&personal_url);
    match personal_client.health().await {
        Ok(resp) => {
            let ver = resp
                .version
                .as_deref()
                .map(|v| format!(" (v{v})"))
                .unwrap_or_default();
            println!("  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} ok{ver}", "Service");
        }
        Err(e) => {
            println!(
                "  {CYAN}{:<13}{RESET} {RED}✗{RESET} unreachable ({e})",
                "Service"
            );
            return;
        }
    };
    println!(
        "  {CYAN}{:<13}{RESET} {personal_url} {DIM}(from DID){RESET}",
        "URL"
    );

    // Personal DID resolution + trust-ping
    let personal_session = auth::loaded_session(config::PERSONAL_KEYRING_KEY);
    if let Some(ref session) = personal_session {
        if let Some(resolver) = resolver {
            print_did_resolution(resolver, "Client DID", &session.client_did, false).await;

            if let Some(vta_did) = session.vta_did.as_deref() {
                let mediator_did = print_did_resolution(resolver, "VTA DID", vta_did, true).await;

                if let Some(ref mediator_did) = mediator_did {
                    print_did_resolution(resolver, "Mediator DID", mediator_did, false).await;
                    match tokio::time::timeout(
                        ping_timeout,
                        vta_sdk::session::send_trust_ping(
                            &session.client_did,
                            &session.private_key_multibase,
                            mediator_did,
                            None,
                        ),
                    )
                    .await
                    {
                        Ok(Ok(latency)) => println!(
                            "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} pong ({latency}ms)",
                            "Trust-ping"
                        ),
                        Ok(Err(e)) => println!(
                            "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping failed: {e}",
                            "Trust-ping"
                        ),
                        Err(_) => println!(
                            "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping timed out",
                            "Trust-ping"
                        ),
                    }
                }
            } else {
                println!(
                    "  {DIM}(personal session pending VTA binding — finish `pnm setup continue <slug>` to enable DID resolution){RESET}"
                );
            }
        }
    } else {
        println!("  {DIM}(not authenticated — DID resolution skipped){RESET}");
    }
}

/// Resolve a DID and print the result with colored ✓/✗.
///
/// Prints label + DID, then resolution status and detail lines.
/// When `find_mediator` is true, looks for a DIDCommMessaging service and
/// extracts the mediator DID from its endpoint URI (if the URI is a `did:`).
async fn print_did_resolution(
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    label: &str,
    did: &str,
    find_mediator: bool,
) -> Option<String> {
    let method = did
        .strip_prefix("did:")
        .and_then(|s| s.split(':').next())
        .unwrap_or("unknown");

    println!("  {CYAN}{:<13}{RESET} {did}", label);

    let resolved = match resolver.resolve(did).await {
        Ok(r) => r,
        Err(e) => {
            println!("                {RED}✗{RESET} resolution failed: {e}");
            return None;
        }
    };

    println!("                {GREEN}✓{RESET} resolves ({method})");

    for ka in &resolved.doc.key_agreement {
        println!("                {DIM}keyAgreement: {}{RESET}", ka.get_id());
    }

    let mut mediator_did: Option<String> = None;
    for svc in &resolved.doc.service {
        let types = svc.type_.join(", ");
        // Endpoint::get_uris() wraps Map-sourced values in JSON quotes; strip them.
        let uris: Vec<String> = svc
            .service_endpoint
            .get_uris()
            .into_iter()
            .map(|u| u.trim_matches('"').to_string())
            .collect();

        if uris.is_empty() {
            println!("                {DIM}service: {types}{RESET}");
        } else {
            for uri in &uris {
                println!("                {DIM}service: {types} -> {uri}{RESET}");
            }
        }

        if find_mediator
            && svc.type_.iter().any(|t| t == "DIDCommMessaging")
            && mediator_did.is_none()
        {
            mediator_did = uris.into_iter().find(|u| u.starts_with("did:"));
            if let Some(ref m) = mediator_did {
                println!("                mediator {GREEN}✓{RESET} {m}");
            } else {
                println!("                mediator {RED}✗{RESET} no DID found in service endpoint");
            }
        }
    }
    mediator_did
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── requires_auth ──────────────────────────────────────────────

    #[test]
    fn test_requires_auth_health_false() {
        assert!(!requires_auth(&Commands::Health));
    }

    #[test]
    fn test_requires_auth_auth_login_false() {
        let cmd = Commands::Auth {
            command: AuthCommands::Login {
                credential_bundle: std::path::PathBuf::from("/tmp/fake.armor"),
                expect_digest: None,
                no_verify_digest: false,
            },
        };
        assert!(!requires_auth(&cmd));
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
    fn test_requires_auth_setup_false() {
        assert!(!requires_auth(&Commands::Setup));
    }

    #[test]
    fn test_requires_auth_community_false() {
        let cmd = Commands::Community {
            command: CommunityCommands::List,
        };
        assert!(!requires_auth(&cmd));
    }
}
