//! Clap argument-parsing surface for the `pnm` CLI.
//!
//! Pure data definitions: every dispatcher lives in `crate::commands::*`.
//! Helpers in this module (auth-routing, the retired `pnm mediator …`
//! migration cue, the banner, the force-exit watchdog) are likewise
//! parser-adjacent — they decide *which* dispatcher to call, never *how*
//! the call is performed.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "pnm-cli",
    about = "CLI for managing a personal Verifiable Trust Agent"
)]
pub(crate) struct Cli {
    /// Base URL of the VTA service (overrides config)
    #[arg(long, env = "VTA_URL")]
    pub(crate) url: Option<String>,

    /// VTA slug to use (overrides default)
    #[arg(short, long, env = "PNM_VTA", global = true)]
    pub(crate) vta: Option<String>,

    /// Enable verbose debug output (can also set RUST_LOG=debug)
    #[arg(short = 'V', long, global = true)]
    pub(crate) verbose: bool,

    /// Show full identifiers (DIDs, key ids, template names, …) in
    /// list output instead of the compact table view that may truncate
    /// long values. Useful when you need to copy a complete ID.
    #[arg(long, global = true)]
    pub(crate) full_display: bool,

    /// Emit list output as JSON instead of a human-readable table.
    /// Use this for automation: `pnm acl list --json | jq …`.
    #[arg(long, global = true)]
    pub(crate) json: bool,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Configure VTA URL and credentials.
    ///
    /// Bare `pnm setup` runs the interactive wizard. Non-interactive
    /// phase-1 lives behind `--name`; phase-2 (supply a VTA DID for a
    /// pending slug) lives under the `continue` subcommand.
    ///
    ///   # Interactive:
    ///   pnm setup
    ///
    ///   # Non-interactive phase 1 (mint + park pending; JSON on stdout):
    ///   pnm setup --name "My VTA"
    ///   pnm setup --name "My VTA" --overwrite    # replace existing pending
    ///
    ///   # Phase 2 (interactive — prompts for VTA DID):
    ///   pnm setup continue my-vta
    ///
    ///   # Phase 2 (non-interactive — JSON on stdout):
    ///   pnm setup continue my-vta --vta-did did:webvh:...
    Setup {
        #[command(subcommand)]
        command: Option<SetupCommands>,

        /// Non-interactive phase 1: human-readable VTA name. Slugified
        /// the same way as the interactive wizard. Combining with the
        /// `continue` subcommand is an error, enforced at dispatch.
        #[arg(long)]
        name: Option<String>,

        /// Non-interactive phase 1: overwrite an existing *pending*
        /// setup for the same slug. Never overwrites a complete VTA —
        /// use `pnm vta remove <slug>` first.
        #[arg(long)]
        overwrite: bool,
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

    /// Manage the VTA's advertised transport services (REST + DIDComm).
    ///
    /// Spec: docs/05-design-notes/runtime-service-management.md §5.1.
    /// The previous `pnm mediator …` subcommand was retired in this
    /// release; its functionality moved under
    /// `pnm services didcomm {update,rollback,drain {list,cancel}}`.
    Services {
        #[command(subcommand)]
        command: ServicesCommands,
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

    /// Manage the controller's DIDs and the DID-hosting servers
    /// they live on.
    ///
    /// `pnm did-mgmt servers {add,list,update,remove}` manages the
    /// controller's view of registered DID-hosting servers (the
    /// daemons that publish `did:webvh:*` logs). `pnm did-mgmt
    /// dids {…}` operates on the DIDs themselves (create, edit,
    /// delete, list, get, get-log, register).
    ///
    /// Matches the `vta_sdk::protocols::did_management` SDK module,
    /// which is the umbrella for both lifecycle and server-
    /// registration operations on the controller side. (The
    /// daemon-side hosting trust-tasks live under
    /// `spec/did-hosting/*` and are a separate concern.)
    ///
    /// Replaces the earlier `pnm webvh …` surface. The retired
    /// command path is still accepted (hidden) for one release —
    /// operators get a stderr deprecation note on each invocation.
    /// The DID method itself remains `did:webvh`; only the operator
    /// UX category was renamed.
    DidMgmt {
        #[command(subcommand)]
        command: DidMgmtCommands,
    },

    /// DEPRECATED — renamed to `pnm did-mgmt <subcommand>`. Still
    /// dispatched for one release; switch your scripts before the
    /// alias is removed in the next minor.
    #[command(hide = true)]
    Webvh {
        #[command(subcommand)]
        command: WebvhCommands,
    },

    /// Audit log management
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },

    /// Backup and restore VTA data
    Backup {
        #[command(subcommand)]
        command: BackupCommands,
    },

    /// VTA connection management
    Vta {
        #[command(subcommand)]
        command: VtaCommands,
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
pub(crate) enum SetupCommands {
    /// Finish a pending VTA setup by supplying the VTA DID.
    ///
    /// Interactive when `--vta-did` is omitted; non-interactive with
    /// JSON stdout when supplied. The ephemeral `did:key` minted in
    /// phase 1 is preserved — this command only binds the VTA DID and
    /// flips the session to `PendingRotation`.
    Continue {
        /// Slug identifying the pending VTA (see `pnm vta list`).
        slug: String,

        /// VTA DID to bind (non-interactive). Must start with `did:`.
        #[arg(long)]
        vta_did: Option<String>,

        /// VTA REST URL (required for did:key DIDs that cannot advertise a service endpoint).
        #[arg(long)]
        vta_url: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum BootstrapCommands {
    /// Generate an ephemeral keypair and emit a BootstrapRequest for the producer.
    ///
    /// The X25519 secret is stored on disk under
    /// `~/.config/pnm/bootstrap-secrets/<bundle_id>.key` (mode 0600). The
    /// emitted JSON file contains only the public key, a fresh nonce, and an
    /// optional label — no secrets cross the boundary.
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
        /// Pin the VTA DID out-of-band. When supplied and the payload
        /// is `TemplateBootstrap`, the VC is verified end-to-end
        /// against this DID (pinned-DID check + issuer-pubkey
        /// extraction + Data Integrity verify + validity window).
        /// Without this flag, verification is digest-only.
        #[arg(long)]
        expect_vta_did: Option<String>,
    },

    /// One-command TEE first-boot bootstrap against a running VTA.
    ///
    /// Generates an ephemeral keypair, POSTs to `/bootstrap/request`,
    /// verifies the attestation quote, and installs the minted admin
    /// credential. Only works against a fresh TEE VTA that has not yet
    /// bootstrapped an admin — the carve-out closes permanently on first
    /// success.
    ///
    /// For non-TEE VTAs use `pnm setup` (temp did:key + ACL grant +
    /// auto-rotate on first connect).
    Connect {
        /// Base URL of the target VTA.
        #[arg(long)]
        vta_url: String,
        /// Out-of-band digest anchor. Compared against the server's
        /// reported digest and the locally computed one. Required unless
        /// `--no-verify-digest` is passed.
        #[arg(long)]
        expect_digest: Option<String>,
        /// Skip out-of-band digest verification (testing only — prints a warning).
        /// Required when `--expect-digest` is not provided; there is no silent TOFU.
        #[arg(long)]
        no_verify_digest: bool,
        /// Slug to register this VTA under in pnm config (default: tail of the
        /// VTA DID).
        #[arg(long)]
        slug: Option<String>,
    },

    /// Generate a VP-framed BootstrapRequest for the provision-integration
    /// flow (consumer side).
    ///
    /// Mints an ephemeral Ed25519 keypair, persists the seed under
    /// `~/.config/pnm/bootstrap-secrets/<bundle_id>.key`, and writes a
    /// signed VP naming the target DID template (e.g.
    /// `didcomm-mediator`, `did-hosting-control`, `did-hosting-daemon`, `did-hosting-server`) + variables. Hand the
    /// JSON to the VTA operator. Counterpart to `vta bootstrap
    /// provision-request` — same wire shape, same on-disk layout,
    /// different default seed directory.
    ///
    /// See `docs/02-vta/provision-integration.md` for the flow.
    ProvisionRequest {
        /// DID template name the VTA should render (e.g.
        /// `didcomm-mediator`, `did-hosting-control`, `did-hosting-daemon`, `did-hosting-server`, or an
        /// operator-uploaded custom template).
        #[arg(long)]
        template: String,
        /// Template variable, repeat for each binding. Format `KEY=VALUE`.
        /// Values are parsed as JSON when possible; otherwise treated as
        /// a string.
        #[arg(long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
        /// Hint the target VTA context.
        #[arg(long)]
        context_hint: Option<String>,
        /// Opt into long-term admin-DID rollover (typically
        /// `--admin-template vta-admin`).
        #[arg(long)]
        admin_template: Option<String>,
        /// Freshness window in hours for the VP's `validUntil`. Default
        /// 168 (7 days).
        #[arg(long, value_name = "HOURS", default_value_t = 168.0)]
        validity_hours: f64,
        /// Free-form human label echoed back in audit logs.
        #[arg(long)]
        label: Option<String>,
        /// Output path for the signed BootstrapRequest JSON.
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Bridge a VP-framed BootstrapRequest to `POST /bootstrap/provision-integration`
    /// on the configured VTA, writing the returned armored sealed bundle to disk.
    ///
    /// Mirrors the offline `vta bootstrap provision-integration` command;
    /// the difference is purely the transport — the VTA runs the same
    /// shared library function regardless of how the request arrived.
    ProvisionIntegration {
        /// Path to the VP-framed BootstrapRequest JSON (emitted by the
        /// integration's operator via `pnm bootstrap request`).
        #[arg(long)]
        request: std::path::PathBuf,
        /// VTA context to provision into. If the request carries a
        /// `contextHint`, this flag must either match it or be omitted.
        #[arg(long)]
        context: Option<String>,
        /// Producer assertion mode. `did-signed` (default) signs with
        /// the VTA's assertion key; `pinned-only` is a dev/test
        /// escape hatch.
        #[arg(long, default_value = "did-signed")]
        assertion: String,
        /// Override for the VC's `validUntil` window, in seconds.
        #[arg(long, value_name = "SECONDS")]
        vc_validity_seconds: Option<i64>,
        /// Output path for the armored bundle.
        #[arg(long)]
        out: std::path::PathBuf,
        /// Create the target context inline if it doesn't already
        /// exist on the VTA. Requires **super-admin** role; ordinary
        /// context-admin callers get `Forbidden` against a missing
        /// context. Idempotent — no-op when the context already
        /// exists. Mirrors `vta bootstrap provision-integration
        /// --create-context`.
        #[arg(long)]
        create_context: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum DidTemplateCommands {
    /// Validate a DID template file against the v1 schema.
    ///
    /// Runs offline — never talks to the VTA. Reports whether the file
    /// parses, its placeholders are all declared, and its reserved/required
    /// variables are well-formed.
    Validate {
        /// Path to a template JSON file to validate.
        file: std::path::PathBuf,
    },

    /// Scaffold a starter template by forking an embedded built-in.
    ///
    /// Emits JSON on stdout so it can be redirected to a file for editing.
    /// `kind` accepts either the full built-in name
    /// (`didcomm-mediator`, `did-hosting-control`, `did-hosting-daemon`, `did-hosting-server`) or a short alias
    /// (`mediator`, `control`, `did-hosting`, `hosting`, `daemon`, `witness`, `watcher`, `server`).
    /// Legacy `webvh-control` / `webvh-daemon` / `webvh-server` names are
    /// still accepted and resolve to the renamed templates for one release.
    Init {
        /// Built-in kind or alias to fork.
        kind: String,
    },

    /// List every built-in template shipped with this SDK.
    #[command(name = "list-builtins")]
    ListBuiltins,

    /// List DID templates stored on the VTA.
    ///
    /// Without `--context`, lists global-scope templates (visible across
    /// every context). With `--context X`, lists templates scoped to X.
    List {
        /// FILTER: scope the listing to one context. Omit for global scope.
        /// Does not merge in the other scope — use `list-builtins` for
        /// built-ins.
        #[arg(long)]
        context: Option<String>,
    },

    /// Show a stored template by name.
    ///
    /// Without `--rendered`, prints the raw record. With `--rendered`, the
    /// server renders the template using `--var KEY=VALUE` pairs.
    Show {
        /// Template name as stored on the VTA.
        name: String,
        /// LOOKUP SCOPE: which scope to search for the named template.
        /// Omit for global scope.
        #[arg(long)]
        context: Option<String>,
        /// Render the template rather than showing its raw record.
        #[arg(long)]
        rendered: bool,
        /// `KEY=VALUE` — supply a template variable. Repeatable.
        #[arg(long = "var", value_parser = parse_key_value)]
        vars: Vec<(String, String)>,
    },

    /// Upload a new template.
    ///
    /// Without `--context`: global scope (super admin only). With
    /// `--context X`: context scope (context admin or super admin).
    Create {
        /// Path to a template JSON file.
        #[arg(long)]
        file: std::path::PathBuf,
        /// TARGET SCOPE: create the template in this context's scope
        /// instead of global. Requires context-admin access to the context.
        #[arg(long)]
        context: Option<String>,
    },

    /// Replace a stored template.
    Update {
        /// Template name as stored on the VTA.
        name: String,
        /// Path to the replacement JSON file. Its `name` field must match.
        #[arg(long)]
        file: std::path::PathBuf,
        /// TARGET SCOPE: operate on this context's stored template instead
        /// of the global one.
        #[arg(long)]
        context: Option<String>,
    },

    /// Delete a stored template.
    Delete {
        /// Template name.
        name: String,
        /// TARGET SCOPE: operate on this context's stored template instead
        /// of the global one.
        #[arg(long)]
        context: Option<String>,
    },

    /// Export a stored template to stdout as a portable JSON file.
    ///
    /// Strips server provenance so the output can be edited and re-uploaded
    /// via `create --file`. Pipe into a file or `jq` for scripted workflows.
    Export {
        /// Template name.
        name: String,
        /// LOOKUP SCOPE: export from this context's scope instead of global.
        #[arg(long)]
        context: Option<String>,
    },

    /// Compare a local template file against the VTA-stored version.
    ///
    /// Shows every JSON path whose value differs, exits non-zero when the
    /// two diverge (so it plugs into drift-detection scripts).
    Diff {
        /// Template name.
        name: String,
        /// Path to the local template JSON file.
        #[arg(long)]
        file: std::path::PathBuf,
        /// LOOKUP SCOPE: fetch the stored template from this context's scope
        /// instead of global.
        #[arg(long)]
        context: Option<String>,
    },
}

pub(crate) fn parse_key_value(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("expected KEY=VALUE, got '{s}'"))?;
    Ok((k.to_string(), v.to_string()))
}

#[derive(Subcommand)]
pub(crate) enum BackupCommands {
    /// Export VTA state to an encrypted backup file
    Export {
        /// Include audit logs in the backup
        #[arg(long)]
        include_audit: bool,
        /// Output file path (default: `vta-backup-<timestamp>.vtabak`)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
        /// Use the new descriptor-pattern trust-task flow instead of
        /// the legacy inline `/backup/export` REST route. Off by
        /// default during the transition window; will flip to on by
        /// default in a future release. See
        /// `docs/05-design-notes/backup-descriptor-pattern.md`.
        #[arg(long)]
        use_trust_task: bool,
    },
    /// Import VTA state from an encrypted backup file
    Import {
        /// Path to the .vtabak backup file
        file: std::path::PathBuf,
        /// Preview only — show what would be imported without applying
        #[arg(long)]
        preview: bool,
        /// Use the new descriptor-pattern trust-task flow instead of
        /// the legacy inline `/backup/import` REST route. Off by
        /// default during the transition window.
        #[arg(long)]
        use_trust_task: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum VtaCommands {
    /// List configured VTAs
    List,
    /// Set the default VTA
    Use { slug: String },
    /// Remove a VTA connection
    Remove { slug: String },
    /// Show current VTA details
    Info,
    /// Restart the VTA service (soft restart — reloads config and reconnects)
    Restart,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum WebvhCommands {
    /// Add a WebVH server
    AddServer {
        /// Server identifier
        #[arg(long)]
        id: String,
        /// Server DID (must resolve to a DID document with a WebVHHostingService endpoint)
        #[arg(long)]
        did: String,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
    },
    /// List configured WebVH servers
    ListServers,
    /// Update a WebVH server
    UpdateServer {
        /// Server identifier to update
        id: String,
        /// New label (empty string to clear)
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a WebVH server
    RemoveServer {
        /// Server identifier to remove
        id: String,
    },
    /// Create a WebVH DID
    CreateDid {
        /// Application context ID
        #[arg(long)]
        context: String,
        /// WebVH server ID (mutually exclusive with --did-url)
        #[arg(long)]
        server: Option<String>,
        /// DID URL for serverless creation (mutually exclusive with --server)
        #[arg(long)]
        did_url: Option<String>,
        /// Optional path on the WebVH server
        #[arg(long)]
        path: Option<String>,
        /// Optional hosting domain on the target server. When the
        /// remote backplane serves multiple tenant domains, name the
        /// one this DID should live on; otherwise the server resolves
        /// via your ACL default → its system default. An unknown
        /// domain comes back as a `did-management:unknown_domain`
        /// error. Use `pnm did-mgmt list-domains --server <id>` to
        /// see what's configured. Ignored in serverless mode.
        #[arg(long)]
        domain: Option<String>,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Make the DID portable (default: true)
        #[arg(long, default_value = "true")]
        portable: bool,
        /// Add a mediator service endpoint
        #[arg(long)]
        mediator_service: bool,
        /// Additional service endpoints (JSON array)
        #[arg(long)]
        services: Option<String>,
        /// Number of pre-rotation keys to generate
        #[arg(long, default_value = "0")]
        pre_rotation: u32,
        /// Path to a JSON file containing a DID Document template (template mode)
        #[arg(long)]
        did_document: Option<String>,
        /// Path to a did.jsonl file containing a pre-signed log entry (final mode)
        #[arg(long)]
        did_log: Option<String>,
        /// Do not set this DID as the primary DID for the context
        #[arg(long)]
        no_primary: bool,
        /// Use an existing key ID as the signing verification method
        #[arg(long)]
        signing_key: Option<String>,
        /// Use an existing key ID as the key-agreement verification method
        #[arg(long)]
        ka_key: Option<String>,
        /// Name of a stored DID template to render into the DID document.
        /// Mutually exclusive with `--did-document` and `--did-log`.
        #[arg(long)]
        template: Option<String>,
        /// Look up the template in this context's scope first. Defaults to
        /// the DID's own `--context` so context-local templates shadow
        /// global ones naturally.
        #[arg(long)]
        template_context: Option<String>,
        /// `KEY=VALUE` — supply a template variable. Repeatable.
        #[arg(long = "var", value_parser = parse_key_value)]
        vars: Vec<(String, String)>,
    },
    /// Edit an existing WebVH DID document.
    ///
    /// **Interactive (default):** opens the latest DID document in
    /// `$EDITOR`, then walks a Confirm/Input chain for the webvh
    /// parameters (pre-rotation, watchers, TTL, audit label),
    /// confirms, and publishes a new LogEntry.
    ///
    /// **Non-interactive:** supply `--document <file>` (and
    /// optionally per-field flags) or `--options-file <file>` for
    /// scripted updates. Witness changes need `--options-file`
    /// because the multibase-id wire shape is awkward to express
    /// on the command line.
    ///
    /// The DID's top-level `id` is treated as a permanent
    /// commitment from the first LogEntry — changing it in the
    /// editor is rejected before publish.
    EditDid {
        /// The DID to edit.
        #[arg(long)]
        did: String,
        /// Path to a JSON file with the new DID document. Skips
        /// `$EDITOR`.
        #[arg(long)]
        document: Option<std::path::PathBuf>,
        /// Path to a JSON file with a full UpdateDidWebvhBody
        /// (document + every parameter). Mutually exclusive with
        /// the per-field flags below.
        #[arg(long)]
        options_file: Option<std::path::PathBuf>,
        /// Override the pre-rotation count (0 disables).
        #[arg(long)]
        pre_rotation: Option<u32>,
        /// New TTL in seconds.
        #[arg(long)]
        ttl: Option<u32>,
        /// Replace the watcher set with these URLs (repeatable).
        #[arg(long = "watcher")]
        watchers: Vec<String>,
        /// Disable watchers entirely (mutually exclusive with
        /// `--watcher`).
        #[arg(long)]
        no_watchers: bool,
        /// Audit label for this update.
        #[arg(long)]
        label: Option<String>,
        /// Skip the final "Publish?" confirmation prompt. Useful
        /// for scripted runs.
        #[arg(long)]
        no_confirm: bool,
    },
    /// Register an existing serverless WebVH DID with a webvh hosting server.
    ///
    /// Pushes the local `did.jsonl` to the host atomically (single
    /// batched write — no resolver gap) and flips the DID's
    /// `server_id` so future `pnm services …` mutations auto-publish
    /// there. Useful when the VTA was set up serverless and a host
    /// became available later.
    ///
    /// Refused if the DID is already server-managed.
    RegisterDid {
        /// The serverless WebVH DID to promote.
        #[arg(long)]
        did: String,
        /// Registered server id (from `pnm webvh add-server`).
        #[arg(long)]
        server: String,
        /// Take over a slot owned by a different DID. Honoured only
        /// when this VTA authenticates to the host as an admin. An
        /// owner re-registering their own slot is idempotent and
        /// always succeeds without `--force`.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Optional hosting domain on the target server. When the
        /// remote serves multiple tenant domains, name the one this
        /// DID should land on; otherwise the server resolves via the
        /// usual chain.
        #[arg(long)]
        domain: Option<String>,
    },
    /// List hosting domains a server makes available to this VTA.
    ///
    /// Walks the configured webvh server's `GET /api/me/domains`
    /// endpoint and prints the caller-scoped subset. Use this to
    /// discover legitimate `--domain` values for `pnm did-mgmt
    /// create-did` / `register-did` before the first call. The
    /// system default is flagged with `(default)`.
    ListDomains {
        /// Registered server id (from `pnm webvh add-server`).
        #[arg(long)]
        server: String,
    },
    /// List WebVH DIDs
    ListDids {
        /// FILTER: only show DIDs belonging to this context.
        #[arg(long)]
        context: Option<String>,
        /// FILTER: only show DIDs hosted by this WebVH server.
        #[arg(long)]
        server: Option<String>,
    },
    /// Get details of a WebVH DID
    GetDid {
        /// The DID to look up
        did: String,
    },
    /// Delete a WebVH DID
    DeleteDid {
        /// The DID to delete
        did: String,
    },
    /// Print the raw `did.jsonl` log for a webvh DID the VTA knows.
    ///
    /// Snapshot from provisioning time — not a live resolver. Use for
    /// audit, debugging, or republication fallback.
    ///
    /// The VTA's endpoint is public (webvh logs are world-readable by
    /// design), so this runs without a session token.
    DidLog {
        /// The DID to retrieve the log for.
        did: String,
        /// Optional output file; stdout if omitted.
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
}

// ── pnm did-mgmt {servers,dids} (new surface) ───────────────────────
//
// Restructured replacement for `pnm webvh …`. The variant fields are
// duplicated from `WebvhCommands` so the new structure can stand on
// its own, then `From<DidMgmtCommands> for WebvhCommands` converts
// into the legacy enum so the existing `commands::webvh::run` handler
// stays the single source of business logic. Drop the legacy enum +
// conversion in the next minor release.

/// Two-tier split: server-registration management vs DID lifecycle.
#[derive(Subcommand)]
pub(crate) enum DidMgmtCommands {
    /// Manage registered DID-hosting servers.
    Servers {
        #[command(subcommand)]
        command: DidMgmtServerCommands,
    },
    /// Manage DIDs hosted by a registered server or published serverlessly.
    Dids {
        #[command(subcommand)]
        command: DidMgmtDidCommands,
    },
}

/// `pnm did-mgmt servers {…}` — controller-side server registry.
#[derive(Subcommand)]
pub(crate) enum DidMgmtServerCommands {
    /// Add a DID-hosting server to the controller's registry.
    Add {
        /// Server identifier (operator-chosen, must be unique).
        #[arg(long)]
        id: String,
        /// Server DID (must resolve to a DID document with a
        /// WebVHHostingService endpoint).
        #[arg(long)]
        did: String,
        /// Human-readable label.
        #[arg(long)]
        label: Option<String>,
    },
    /// List registered DID-hosting servers.
    List,
    /// Update a registered DID-hosting server.
    Update {
        /// Server identifier to update.
        id: String,
        /// New label (empty string to clear).
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a registered DID-hosting server.
    Remove {
        /// Server identifier to remove.
        id: String,
    },
}

/// `pnm did-mgmt dids {…}` — DID lifecycle.
#[derive(Subcommand)]
pub(crate) enum DidMgmtDidCommands {
    /// Create a DID hosted on a registered server, or serverless via
    /// `--did-url`.
    Create {
        /// Application context ID
        #[arg(long)]
        context: String,
        /// DID-hosting server ID (mutually exclusive with --did-url)
        #[arg(long)]
        server: Option<String>,
        /// DID URL for serverless creation (mutually exclusive with --server)
        #[arg(long)]
        did_url: Option<String>,
        /// Optional path on the DID-hosting server
        #[arg(long)]
        path: Option<String>,
        /// Optional hosting domain on the target server. Discover
        /// available values with `pnm did-mgmt list-domains --server <id>`.
        /// Omit to use the server's caller-default → system-default
        /// resolution chain. Ignored in serverless mode.
        #[arg(long)]
        domain: Option<String>,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Make the DID portable (default: true)
        #[arg(long, default_value = "true")]
        portable: bool,
        /// Add a mediator service endpoint
        #[arg(long)]
        mediator_service: bool,
        /// Additional service endpoints (JSON array)
        #[arg(long)]
        services: Option<String>,
        /// Number of pre-rotation keys to generate
        #[arg(long, default_value = "0")]
        pre_rotation: u32,
        /// Path to a JSON file containing a DID Document template (template mode)
        #[arg(long)]
        did_document: Option<String>,
        /// Path to a did.jsonl file containing a pre-signed log entry (final mode)
        #[arg(long)]
        did_log: Option<String>,
        /// Do not set this DID as the primary DID for the context
        #[arg(long)]
        no_primary: bool,
        /// Use an existing key ID as the signing verification method
        #[arg(long)]
        signing_key: Option<String>,
        /// Use an existing key ID as the key-agreement verification method
        #[arg(long)]
        ka_key: Option<String>,
        /// Name of a stored DID template to render into the DID document.
        /// Mutually exclusive with `--did-document` and `--did-log`.
        #[arg(long)]
        template: Option<String>,
        /// Look up the template in this context's scope first. Defaults
        /// to the DID's own `--context` so context-local templates
        /// shadow global ones naturally.
        #[arg(long)]
        template_context: Option<String>,
        /// `KEY=VALUE` — supply a template variable. Repeatable.
        #[arg(long = "var", value_parser = parse_key_value)]
        vars: Vec<(String, String)>,
    },
    /// Edit an existing DID document.
    ///
    /// **Interactive (default):** opens the latest DID document in
    /// `$EDITOR`, then walks a Confirm/Input chain for the webvh
    /// parameters (pre-rotation, watchers, TTL, audit label),
    /// confirms, and publishes a new LogEntry.
    ///
    /// **Non-interactive:** supply `--document <file>` (and
    /// optionally per-field flags) or `--options-file <file>` for
    /// scripted updates. Witness changes need `--options-file`
    /// because the multibase-id wire shape is awkward to express
    /// on the command line.
    Edit {
        /// The DID to edit.
        #[arg(long)]
        did: String,
        /// Path to a JSON file with the new DID document. Skips
        /// `$EDITOR`.
        #[arg(long)]
        document: Option<std::path::PathBuf>,
        /// Path to a JSON file with a full UpdateDidWebvhBody
        /// (document + every parameter). Mutually exclusive with
        /// the per-field flags below.
        #[arg(long)]
        options_file: Option<std::path::PathBuf>,
        /// Override the pre-rotation count (0 disables).
        #[arg(long)]
        pre_rotation: Option<u32>,
        /// New TTL in seconds.
        #[arg(long)]
        ttl: Option<u32>,
        /// Replace the watcher set with these URLs (repeatable).
        #[arg(long = "watcher")]
        watchers: Vec<String>,
        /// Disable watchers entirely (mutually exclusive with
        /// `--watcher`).
        #[arg(long)]
        no_watchers: bool,
        /// Audit label for this update.
        #[arg(long)]
        label: Option<String>,
        /// Skip the final "Publish?" confirmation prompt.
        #[arg(long)]
        no_confirm: bool,
    },
    /// Register an existing serverless DID with a registered
    /// DID-hosting server.
    ///
    /// Pushes the local `did.jsonl` to the host atomically and flips
    /// the DID's `server_id` so future updates auto-publish there.
    /// Useful when the VTA was set up serverless and a host became
    /// available later. Refused if the DID is already server-managed.
    Register {
        /// The serverless DID to promote.
        #[arg(long)]
        did: String,
        /// Registered server id (from `pnm did-mgmt servers add`).
        #[arg(long)]
        server: String,
        /// Take over a slot owned by a different DID. Honoured only
        /// when this VTA authenticates to the host as an admin. An
        /// owner re-registering their own slot is idempotent and
        /// always succeeds without `--force`.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Optional hosting domain on the target server. Discover
        /// available values with `pnm did-mgmt list-domains --server <id>`.
        #[arg(long)]
        domain: Option<String>,
    },
    /// List DIDs.
    List {
        /// FILTER: only show DIDs belonging to this context.
        #[arg(long)]
        context: Option<String>,
        /// FILTER: only show DIDs hosted by this DID-hosting server.
        #[arg(long)]
        server: Option<String>,
    },
    /// Get details of a single DID.
    Get {
        /// The DID to look up.
        did: String,
    },
    /// Delete a DID.
    Delete {
        /// The DID to delete.
        did: String,
    },
    /// Print the raw `did.jsonl` log for a DID the VTA knows.
    ///
    /// Snapshot from provisioning time — not a live resolver. Use
    /// for audit, debugging, or republication fallback. The VTA's
    /// endpoint is public (webvh logs are world-readable by design),
    /// so this runs without a session token.
    GetLog {
        /// The DID to retrieve the log for.
        did: String,
        /// Optional output file; stdout if omitted.
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
    /// List the hosting domains a registered server makes available.
    ///
    /// Calls the server's `GET /api/me/domains` endpoint and prints
    /// the caller-scoped subset. Use this to discover legitimate
    /// `--domain` values for `pnm did-mgmt dids create` /
    /// `pnm did-mgmt dids register` before the first call. The
    /// system default is flagged with `(default)`.
    ListDomains {
        /// Registered server id (from `pnm did-mgmt servers add`).
        #[arg(long)]
        server: String,
    },
}

impl From<DidMgmtCommands> for WebvhCommands {
    /// Bridge the new structured surface into the legacy flat
    /// `WebvhCommands` so `commands::webvh::run` remains the single
    /// dispatch site. Drop together with the legacy enum in the next
    /// minor release.
    fn from(cmd: DidMgmtCommands) -> Self {
        match cmd {
            DidMgmtCommands::Servers { command } => match command {
                DidMgmtServerCommands::Add { id, did, label } => {
                    WebvhCommands::AddServer { id, did, label }
                }
                DidMgmtServerCommands::List => WebvhCommands::ListServers,
                DidMgmtServerCommands::Update { id, label } => {
                    WebvhCommands::UpdateServer { id, label }
                }
                DidMgmtServerCommands::Remove { id } => WebvhCommands::RemoveServer { id },
            },
            DidMgmtCommands::Dids { command } => match command {
                DidMgmtDidCommands::Create {
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
                } => WebvhCommands::CreateDid {
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
                },
                DidMgmtDidCommands::Edit {
                    did,
                    document,
                    options_file,
                    pre_rotation,
                    ttl,
                    watchers,
                    no_watchers,
                    label,
                    no_confirm,
                } => WebvhCommands::EditDid {
                    did,
                    document,
                    options_file,
                    pre_rotation,
                    ttl,
                    watchers,
                    no_watchers,
                    label,
                    no_confirm,
                },
                DidMgmtDidCommands::Register {
                    did,
                    server,
                    force,
                    domain,
                } => WebvhCommands::RegisterDid {
                    did,
                    server,
                    force,
                    domain,
                },
                DidMgmtDidCommands::List { context, server } => {
                    WebvhCommands::ListDids { context, server }
                }
                DidMgmtDidCommands::Get { did } => WebvhCommands::GetDid { did },
                DidMgmtDidCommands::Delete { did } => WebvhCommands::DeleteDid { did },
                DidMgmtDidCommands::GetLog { did, out } => WebvhCommands::DidLog { did, out },
                DidMgmtDidCommands::ListDomains { server } => WebvhCommands::ListDomains { server },
            },
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum AuthCommands {
    /// Clear stored credentials and tokens
    Logout,
    /// Show current authentication status
    Status,
    /// Sign an unseal challenge with this PNM's stored admin key.
    ///
    /// Pair with `vta unseal`: when the VTA prints a 64-character hex
    /// challenge, run `pnm auth sign-challenge <hex>` and paste the
    /// resulting signature back into the unseal prompt. The cold-start
    /// alternative — when PNM isn't usable yet — is `vta auth
    /// sign-challenge --did <did> --challenge <hex>`, which signs from
    /// the VTA's local fjall keystore (daemon must be stopped).
    SignChallenge {
        /// The 32-byte challenge in hex (exactly as printed by `vta
        /// unseal`).
        challenge: String,
    },
    /// Print the current access token (JWT) to stdout. Use only for
    /// debugging or for pasting into a tool that needs a bearer
    /// credential (e.g. the `examples/vta-auth-demo/` browser
    /// harness). The token is sensitive — don't share it.
    ///
    /// If no token is cached, performs a fresh authentication first.
    /// Fails if PNM hasn't been set up (`pnm setup`).
    ShowToken,
}

#[derive(Subcommand)]
pub(crate) enum ConfigCommands {
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
    /// Manage the remote DID-resolver cache URL stored in
    /// `~/.config/pnm/config.toml`. When set, PNM dispatches every DID
    /// resolution to that WebSocket endpoint (typically the same
    /// `affinidi-did-resolver-cache-server` the local VTA points at)
    /// instead of resolving in-process.
    ///
    /// Examples:
    ///   pnm config resolver-url                            # show current value
    ///   pnm config resolver-url ws://127.0.0.1:4445/did/v1/ws
    ///   pnm config resolver-url --unset                    # clear, resolve locally
    ResolverUrl {
        /// WebSocket URL of the resolver-cache server. Omit to print
        /// the current value.
        url: Option<String>,
        /// Clear the configured resolver URL. PNM will resolve DIDs
        /// in-process again.
        #[arg(long, conflicts_with = "url")]
        unset: bool,
    },
}

// ── Unified `pnm services …` surface (spec §5.1) ──────────────────
//
// Replaces the earlier `pnm services {enable,disable} didcomm` and
// `pnm mediator …` subcommands. The retired surfaces redirect via
// the `pnm mediator …` migration cue (handled by main()'s clap
// error path) so operators with stale scripts get a clear pointer.

#[derive(Subcommand)]
pub(crate) enum ServicesCommands {
    /// Show currently-advertised transport services.
    List,
    /// Manage REST advertisement.
    Rest {
        #[command(subcommand)]
        command: RestCommands,
    },
    /// Manage DIDComm advertisement.
    Didcomm {
        #[command(subcommand)]
        command: DidcommCommands,
    },
    /// Manage WebAuthn-RP advertisement (the browser-facing
    /// passkey-login surface advertised at `#vta-webauthn` on the
    /// VTA's DID document).
    Webauthn {
        #[command(subcommand)]
        command: WebauthnCommands,
    },
    /// Show inbound-message attribution by mediator and sender.
    /// (Replaces `pnm mediator report`.)
    Report {
        /// Lower bound (RFC 3339, e.g. 2026-04-29T15:00:00Z).
        #[arg(long)]
        since: Option<String>,
        /// Upper bound (RFC 3339).
        #[arg(long)]
        until: Option<String>,
        /// Output format: `json` (default) or `table`.
        #[arg(long, default_value = "json")]
        format: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum RestCommands {
    /// Add a `#vta-rest` service entry advertising `--url`.
    Enable {
        #[arg(long)]
        url: String,
    },
    /// Replace the URL on the existing `#vta-rest` entry.
    Update {
        #[arg(long)]
        url: String,
    },
    /// Remove the `#vta-rest` entry. Refused when DIDComm is also
    /// disabled (spec §3.2 — at least one transport must remain).
    Disable,
    /// Fail-forward the most recent REST mutation by re-applying
    /// the snapshotted prior state (spec §3.5a).
    Rollback,
}

#[derive(Subcommand)]
pub(crate) enum WebauthnCommands {
    /// Add a `#vta-webauthn` service entry advertising `--url`
    /// (typically the auth-portal URL, e.g.
    /// `https://vta.example.com/auth/portal`).
    Enable {
        #[arg(long)]
        url: String,
    },
    /// Replace the URL on the existing `#vta-webauthn` entry.
    Update {
        #[arg(long)]
        url: String,
    },
    /// Remove the `#vta-webauthn` entry AND strip every passkey
    /// verificationMethod from the DIDs this VTA controls. Operators
    /// must re-enrol passkeys after re-enabling. Refused when
    /// disabling WebAuthn would leave no transport advertised.
    Disable,
    /// Fail-forward the most recent WebAuthn mutation by re-applying
    /// the snapshotted prior state.
    Rollback,
}

#[derive(Subcommand)]
pub(crate) enum DidcommCommands {
    /// Enable DIDComm. Requires a mediator DID and super-admin auth.
    /// The VTA must currently be REST-only.
    Enable {
        #[arg(long)]
        mediator_did: String,
        /// Skip handshake steps 2-5 (DID resolution always runs).
        #[arg(long)]
        force: bool,
        /// Trust-ping round-trip timeout in seconds (default 10).
        #[arg(long)]
        handshake_timeout: Option<u64>,
    },
    /// Update which mediator the `#vta-didcomm` entry advertises.
    /// (Replaces `pnm mediator migrate`.) Runs the pre-promotion
    /// handshake; the prior mediator's listener stays up until
    /// `--drain-ttl` expires so in-flight messages can drain.
    Update {
        #[arg(long = "mediator-did", visible_alias = "to")]
        new_mediator_did: String,
        /// Drain window for the prior mediator (seconds).
        /// Default: 24h per spec §3.6.
        #[arg(long, default_value_t = 86_400)]
        drain_ttl: u64,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        handshake_timeout: Option<u64>,
    },
    /// Disable DIDComm. The current mediator's listener stays up
    /// for `--drain-ttl` seconds so in-flight messages drain.
    /// Default: 24h per spec §3.6.
    Disable {
        /// 0 = immediate teardown over REST transport. Server
        /// enforces a 1h minimum when invoked over DIDComm
        /// transport (spec §3.6).
        #[arg(long, default_value_t = 86_400)]
        drain_ttl: u64,
    },
    /// Fail-forward the most recent DIDComm mutation by re-applying
    /// the snapshotted prior state. (Replaces `pnm mediator
    /// rollback`.)
    Rollback {
        /// Drain window for the demoted mediator (seconds) when
        /// the rollback dispatches into update / disable. Default:
        /// 24h. Omitted = use server-side default.
        #[arg(long)]
        drain_ttl: Option<u64>,
    },
    /// Drain-set management.
    Drain {
        #[command(subcommand)]
        command: DrainCommands,
    },
}

#[derive(Subcommand)]
pub(crate) enum DrainCommands {
    /// Show currently-draining mediators.
    List,
    /// Cancel a drain entry. Drops the listener for that mediator
    /// immediately. Refuses if the named DID is the active mediator
    /// (use `services didcomm disable` instead).
    Cancel {
        #[arg(long)]
        mediator_did: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum ContextCommands {
    /// List all application contexts
    List,
    /// Get a context by ID
    Get {
        /// Context ID (e.g. "vta")
        id: String,
    },
    /// Create a new application context, optionally with an admin ACL entry.
    ///
    /// Without `--admin-did` the command just creates the context (historical
    /// behaviour). Supply `--admin-did` to atomically grant that DID admin
    /// access scoped to the new context.
    ///
    /// The admin ACL entry is **permanent** by default. Pass `--admin-expires`
    /// to make it a **setup ACL** that auto-expires if the admin never claims
    /// it — useful when the DID was minted on a fresh `pnm setup` and you
    /// want an automatic safety window.
    Create {
        /// Context slug (lowercase alphanumeric + hyphens)
        #[arg(long)]
        id: String,
        /// Human-readable name
        #[arg(long)]
        name: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
        /// DID to grant admin access to (must start with `did:`). When set,
        /// creates an ACL entry with role=admin scoped to this context.
        #[arg(long)]
        admin_did: Option<String>,
        /// Human-readable label for the admin ACL entry.
        #[arg(long)]
        admin_label: Option<String>,
        /// Setup-ACL expiry — accepts `N[s|m|h|d|w]` (e.g. `24h`, `7d`).
        /// When set, the admin ACL entry auto-expires via the server's ACL
        /// sweeper; the expectation is that the admin authenticates and
        /// rotates to a fresh did:key before expiry. Without this flag the
        /// entry is permanent. Requires `--admin-did`.
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
    /// The admin did:key is generated locally by the CLI and registered via
    /// `POST /acl`; the VTA never sees the private key. The minted credential
    /// is sealed to the `--recipient` and printed as an armored bundle.
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
        /// Path to a BootstrapRequest JSON file produced by `pnm bootstrap request`.
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
    /// Provision a new application context with a portable config bundle
    ///
    /// Creates a context, generates admin credentials, and optionally creates a
    /// WebVH DID. Emits an armored sealed bundle (`-----BEGIN VTA SEALED BUNDLE-----`)
    /// containing everything an application needs to connect, authenticate,
    /// and self-administer its context. Pass `--recipient <file>` with a
    /// `BootstrapRequest` JSON (produced by `pnm bootstrap request --out`) or
    /// `--recipient-pubkey` + `--recipient-nonce` inline.
    Provision {
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
        /// Create a DID using this WebVH server (mutually exclusive with --did-url)
        #[arg(long)]
        server: Option<String>,
        /// Create a DID at this URL for self-hosting (mutually exclusive with --server)
        #[arg(long)]
        did_url: Option<String>,
        /// Make the DID portable (default: true)
        #[arg(long, default_value = "true")]
        portable: bool,
        /// Add a mediator service endpoint to the DID
        #[arg(long)]
        mediator_service: bool,
        /// Number of pre-rotation keys to generate
        #[arg(long, default_value = "0")]
        pre_rotation: u32,
        /// Path to a BootstrapRequest JSON file produced by `pnm bootstrap request`.
        #[arg(long, conflicts_with_all = ["recipient_did", "recipient_nonce"])]
        recipient: Option<std::path::PathBuf>,
        /// Recipient's `did:key` (Ed25519). The X25519 pubkey HPKE seals to
        /// is derived locally.
        /// Requires --recipient-nonce. Mutually exclusive with --recipient.
        #[arg(long, requires = "recipient_nonce", conflicts_with = "recipient")]
        recipient_did: Option<String>,
        /// Recipient's 16-byte nonce in hex (32 chars).
        /// Requires --recipient-did. Mutually exclusive with --recipient.
        #[arg(long, requires = "recipient_did", conflicts_with = "recipient")]
        recipient_nonce: Option<String>,
    },
    /// Regenerate a provision bundle for an existing context.
    ///
    /// The DID's operational keys (signing, KA, any pre-rotation) are
    /// auto-included in the bundle. `--admin-key` separately picks which
    /// existing VTA-stored Ed25519 key's seed backs the admin credential
    /// — the `did:key` the mediator operator uses to authenticate back
    /// to the VTA for ACL-gated operations. Omit to interactively select
    /// from existing keys or create a new one.
    Reprovision {
        /// Context ID to reprovision
        #[arg(long)]
        id: String,
        /// Key ID of an existing VTA-stored Ed25519 key whose seed backs
        /// the exported admin credential. Kept as `--key` for backward
        /// compatibility.
        #[arg(long = "admin-key", alias = "key")]
        admin_key: Option<String>,
        /// Label for a newly created admin key (used when no
        /// `--admin-key` is provided and the interactive prompt selects
        /// "create new").
        #[arg(long)]
        admin_label: Option<String>,
        /// Path to a BootstrapRequest JSON file produced by `pnm bootstrap request`.
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
pub(crate) enum AclCommands {
    /// List ACL entries
    List {
        /// FILTER: only show ACL entries whose `allowed_contexts` include
        /// this context. Omit to see every entry visible to you.
        #[arg(long)]
        context: Option<String>,
    },
    /// Get an ACL entry by DID
    Get {
        /// DID to look up
        did: String,
    },
    /// Create an ACL entry.
    ///
    /// Not idempotent — errors with 409 Conflict if an entry already exists
    /// for the given DID. To change a role or context list on an existing
    /// entry use `pnm acl update`. To revoke access use `pnm acl delete`.
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
pub(crate) enum AuthCredentialCommands {
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
        /// Path to a BootstrapRequest JSON file produced by `pnm bootstrap request`.
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

#[derive(Subcommand, Debug)]
pub(crate) enum AuditCommands {
    /// List audit log entries with optional filtering
    List {
        /// Start time (unix epoch seconds)
        #[arg(long)]
        from: Option<u64>,
        /// End time (unix epoch seconds)
        #[arg(long)]
        to: Option<u64>,
        /// Filter by action (e.g. "auth.challenge", "key.create")
        #[arg(long)]
        action: Option<String>,
        /// Filter by actor DID
        #[arg(long)]
        actor: Option<String>,
        /// Filter by outcome (e.g. "success", "denied")
        #[arg(long)]
        outcome: Option<String>,
        /// Filter by context ID
        #[arg(long)]
        context_id: Option<String>,
        /// Page number (default 1)
        #[arg(long, default_value_t = 1)]
        page: u64,
        /// Page size (default 50, max 500)
        #[arg(long, default_value_t = 50)]
        page_size: u64,
    },
    /// Manage audit log retention
    Retention {
        #[command(subcommand)]
        command: RetentionCommands,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum RetentionCommands {
    /// Get the current retention period
    Get,
    /// Set the retention period (super-admin only)
    Set {
        /// Number of days to retain audit logs (1-365)
        #[arg(long)]
        days: u32,
    },
}

#[derive(Subcommand)]
pub(crate) enum KeyCommands {
    /// Create a new key.
    ///
    /// Not idempotent — every invocation mints a fresh key record (even with
    /// identical arguments). Use `pnm keys list` to discover existing keys
    /// in a context first if you're trying to avoid duplicates.
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
        /// TARGET SCOPE: store the new key under this context. Required
        /// unless you're a super admin creating a context-less key (rare).
        #[arg(long = "context", alias = "context-id", value_name = "ID")]
        context_id: Option<String>,
    },
    /// Import an externally-created private key
    Import {
        /// Key type: ed25519, x25519, or p256
        #[arg(long)]
        key_type: String,
        /// Multibase-encoded private key
        #[arg(long)]
        private_key: Option<String>,
        /// Path to private key file
        #[arg(long)]
        private_key_file: Option<std::path::PathBuf>,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// TARGET SCOPE: store the imported key under this context.
        #[arg(long = "context", alias = "context-id", value_name = "ID")]
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
    /// Export a portable DID secrets bundle for a context as an armored
    /// sealed bundle. The recipient runs `pnm bootstrap open` to decrypt.
    Bundle {
        /// Application context ID whose DID and keys to bundle
        context: String,
        /// Path to a BootstrapRequest JSON file produced by `pnm bootstrap request`.
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
    /// List seed generations
    Seeds,
    /// Rotate to a new seed generation
    RotateSeed {
        /// BIP-39 mnemonic phrase for the new seed (random if omitted)
        #[arg(long)]
        mnemonic: Option<String>,
    },
}

/// Returns true if this command requires authentication.
pub(crate) fn requires_auth(cmd: &Commands) -> bool {
    // VTA restart requires auth; other VTA subcommands don't
    if matches!(
        cmd,
        Commands::Vta {
            command: VtaCommands::Restart
        }
    ) {
        return true;
    }
    // did-templates has both offline (Validate/Init/ListBuiltins) and online
    // (List/Show/Create/Update/Delete) subcommands — the former run without
    // authentication, the latter need a VTA connection.
    if let Commands::DidTemplates { command } = cmd {
        return is_online_template_cmd(command);
    }
    // Bootstrap has mostly offline subcommands, but
    // ProvisionIntegration bridges to the authenticated endpoint.
    if let Commands::Bootstrap { command } = cmd {
        return matches!(command, BootstrapCommands::ProvisionIntegration { .. });
    }
    // `pnm config resolver-url …` is purely local — it mutates the
    // PNM config file at `~/.config/pnm/config.toml` and never talks
    // to the VTA. Other `pnm config` subcommands hit REST endpoints
    // and need auth.
    if let Commands::Config {
        command: ConfigCommands::ResolverUrl { .. },
    } = cmd
    {
        return false;
    }
    !matches!(
        cmd,
        Commands::Health
            | Commands::Auth { .. }
            | Commands::Setup { .. }
            | Commands::Vta { .. }
            | Commands::Bootstrap { .. }
    )
}

pub(crate) fn is_online_template_cmd(cmd: &DidTemplateCommands) -> bool {
    !matches!(
        cmd,
        DidTemplateCommands::Validate { .. }
            | DidTemplateCommands::Init { .. }
            | DidTemplateCommands::ListBuiltins
    )
}

/// Translate a retired `pnm mediator …` invocation into the
/// equivalent `pnm services didcomm …` command, or `None` if the
/// args don't match a retired shape. Operates on `args()` directly
/// so it runs before clap rejects the unknown subcommand.
pub(crate) fn retired_mediator_redirect<I, S>(args: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let argv: Vec<String> = args
        .into_iter()
        .map(|s| s.as_ref().to_string())
        .skip(1) // drop the binary name
        .filter(|a| !a.starts_with('-')) // ignore global flags like --json
        .collect();

    if argv.first().map(|s| s.as_str()) != Some("mediator") {
        return None;
    }

    Some(match argv.get(1).map(|s| s.as_str()) {
        Some("migrate") => "pnm services didcomm update --mediator-did <did>".to_string(),
        Some("rollback") => "pnm services didcomm rollback".to_string(),
        Some("report") => "pnm services report".to_string(),
        Some("drain") => match argv.get(2).map(|s| s.as_str()) {
            Some("cancel") => "pnm services didcomm drain cancel --mediator-did <did>".to_string(),
            Some("list") => "pnm services didcomm drain list".to_string(),
            _ => "pnm services didcomm drain {list|cancel}".to_string(),
        },
        _ => "pnm services --help".to_string(),
    })
}

pub(crate) fn print_banner() {
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{cyan} ██████╗  {magenta}███╗   ██╗ {yellow}███╗   ███╗{reset}
{cyan} ██╔══██╗ {magenta}████╗  ██║ {yellow}████╗ ████║{reset}
{cyan} ██████╔╝ {magenta}██╔██╗ ██║ {yellow}██╔████╔██║{reset}
{cyan} ██╔═══╝  {magenta}██║╚██╗██║ {yellow}██║╚██╔╝██║{reset}
{cyan} ██║      {magenta}██║ ╚████║ {yellow}██║ ╚═╝ ██║{reset}
{cyan} ╚═╝      {magenta}╚═╝  ╚═══╝ {yellow}╚═╝     ╚═╝{reset}
{dim}  Personal Network Manager v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

/// Spawn a Ctrl-C / SIGTERM watcher that lets a second signal force the
/// process out. Operations like a stuck mediator handshake can hold the
/// async runtime for tens of seconds even though the runtime itself
/// observed the signal — without this, the operator has no escape.
pub(crate) fn install_force_exit_handler() {
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
