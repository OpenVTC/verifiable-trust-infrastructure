// CLI-only modules (not part of the library)
mod acl_cli;
mod bootstrap_cli;
mod did_key;
#[cfg(feature = "setup")]
mod did_webvh;
mod import_did;
mod keys_cli;
mod services_cli;
#[cfg(feature = "setup")]
mod setup;
mod vault_cli;
#[cfg(feature = "webvh")]
mod webvh_cli;

// Re-export library modules for use by CLI commands
use vta_service::*;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use clap::{Parser, Subcommand};
use config::AppConfig;
use ed25519_dalek::SigningKey;
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use keys::seed_store::create_seed_store;
use keys::seeds::load_seed_bytes;
use multibase::Base;
use std::path::PathBuf;
use std::sync::Arc;

// There must be a valid mix of transports for the VTA Service
// The following checks if a valid set of features is enabled at compile time and produces a
// helpful error message if not.
#[cfg(not(any(feature = "rest", feature = "didcomm")))]
compile_error!("At least one of 'rest' or 'didcomm' must be enabled.");

#[derive(Parser)]
#[command(name = "vta", about = "Verifiable Trust Agent", version)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Boot the daemon even when the VTA has no usable signing identity
    /// (missing `vta_did` or JWT signing key). Without this flag the daemon
    /// refuses to start rather than come up in a state where every
    /// authenticated endpoint returns 401 (P0.9b). Use only to inspect or
    /// finish provisioning a half-set-up instance. Ignored by subcommands.
    #[arg(long)]
    allow_degraded: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the setup wizard.
    ///
    /// Without arguments, prompts interactively. With `--from <file>`, reads
    /// a TOML setup-inputs file and runs end-to-end without prompts —
    /// suitable for CI, immutable images, or any unattended provisioning.
    /// See `vta_service::setup::WizardInputs` for the schema.
    Setup {
        /// Path to a TOML setup-inputs file. When set, setup runs
        /// non-interactively. The file format mirrors the on-disk
        /// `config.toml` plus a few one-shot fields (`admin_did`,
        /// `data_dir_exists`, etc.) that the interactive wizard normally
        /// collects via prompts.
        #[arg(long)]
        from: Option<PathBuf>,
    },
    /// Bootstrap the first admin and seal the VTA against offline CLI modifications.
    ///
    /// This is a ONE-TIME operation. After sealing, all CLI commands that modify
    /// state (ACL, keys, import, export) are disabled. Management is only possible
    /// via the authenticated REST API or DIDComm.
    BootstrapAdmin {
        /// DID to grant super admin access (must be a DID you control)
        #[arg(long)]
        did: String,
        /// Human-readable label for the admin ACL entry
        #[arg(long)]
        label: Option<String>,
    },
    /// Unseal the VTA — re-enables offline CLI commands (emergency recovery).
    ///
    /// Requires proof of super admin key ownership via challenge-response:
    /// the VTA generates a random challenge, you sign it with your admin
    /// private key using either `pnm auth sign-challenge <hex>` (online,
    /// uses PNM's stored admin key) or `vta auth sign-challenge --did
    /// <did> --challenge <hex>` (offline cold-start, signs from the local
    /// keystore — daemon must be stopped). Paste the signature back into
    /// the prompt.
    Unseal,
    /// Authentication helpers (offline; safe to run while sealed).
    ///
    /// Today: only the `sign-challenge` subcommand, which signs the
    /// challenge from `vta unseal` using a key from the local fjall
    /// keystore. Useful for cold-start operators who can't reach PNM
    /// yet (no network, no PNM auth setup, etc.).
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    /// Export admin DID and credential (blocked when sealed)
    ExportAdmin,
    /// Show VTA status and statistics
    Status,
    /// Inspect the configuration file (offline, no server required).
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Manage the AAL2 step-up policy (offline; edits the config file).
    ///
    /// This is the local break-glass path: it reads and writes the config
    /// file directly, bypassing the wire step-up gate — so an operator can
    /// turn the policy off (or fix it) even when an over-strict policy has
    /// locked everyone out over REST/DIDComm. Changes take effect on the
    /// next daemon start.
    StepUp {
        #[command(subcommand)]
        command: StepUpCommands,
    },
    /// Create a did:key in a context (offline, no server required)
    CreateDidKey {
        /// Target context ID
        #[arg(long)]
        context: String,
        /// Also create an ACL entry with Admin role for the new DID
        #[arg(long)]
        admin: bool,
        /// Human-readable label for the key record and ACL entry
        #[arg(long)]
        label: Option<String>,
    },
    /// Create a did:webvh DID for a context (interactive wizard, no server required).
    ///
    /// Passing `--url` makes the command fully non-interactive (no prompts) so
    /// it can be scripted: combine with `--export-secrets` to emit the secrets
    /// bundle to stdout and `--admin` to grant the new DID admin in the context.
    CreateDidWebvh {
        /// Target context ID
        #[arg(long)]
        context: String,
        /// Human-readable label prefix for key records (default: context id)
        #[arg(long)]
        label: Option<String>,
        /// Hosting URL for the DID (e.g. https://example.com). When set, the
        /// command runs fully non-interactive — no hosting-URL, save-log, or
        /// export-secrets prompts.
        #[arg(long)]
        url: Option<String>,
        /// Emit the `DidSecretsBundle` JSON to stdout (the only thing on
        /// stdout; human text goes to stderr) and skip the save-log /
        /// export-secrets prompts.
        #[arg(long)]
        export_secrets: bool,
        /// Also create an ACL entry with Admin role for the new did:webvh in
        /// the target context (mirrors `create-did-key --admin`).
        #[arg(long)]
        admin: bool,
    },
    /// Import an external DID and create an ACL entry (offline, no server required)
    ImportDid {
        /// The DID to import
        #[arg(long)]
        did: String,
        /// Role to assign (admin, initiator, application, reader)
        #[arg(long)]
        role: Option<String>,
        /// Human-readable label for the ACL entry
        #[arg(long)]
        label: Option<String>,
        /// Restrict to specific context(s); omit for unrestricted access
        #[arg(long)]
        context: Vec<String>,
    },
    /// Manage Access Control List entries (offline, no server required)
    Acl {
        #[command(subcommand)]
        command: AclCommands,
    },
    /// Manage keys (offline, no server required)
    Keys {
        #[command(subcommand)]
        command: KeyCliCommands,
    },
    /// Manage application contexts (offline, no server required)
    ///
    /// Mirrors `pnm contexts` so cold-start / air-gapped operators
    /// have an identical CLI surface (list/get/create/update/delete)
    /// against the local keystore. The historical `vta context`
    /// (singular) form is retained as a hidden alias for scripts
    /// already in production.
    #[command(alias = "context")]
    Contexts {
        #[command(subcommand)]
        command: ContextCommands,
    },
    /// Manage the VTA's DIDs and the DID-hosting servers they live
    /// on. Offline equivalent of `pnm did-mgmt …` — operates
    /// directly on the local fjall keystore, so the daemon must be
    /// stopped.
    ///
    /// `vta did-mgmt servers {add,list,update,remove}` manages the
    /// controller's registered DID-hosting servers. `vta did-mgmt
    /// dids {…}` operates on the DIDs themselves.
    ///
    /// Replaces the earlier `vta webvh …` surface. The retired
    /// command path is still accepted (hidden) for one release —
    /// operators get a stderr deprecation note on each invocation.
    /// The DID method itself remains `did:webvh`; only the operator
    /// UX category was renamed.
    #[cfg(feature = "webvh")]
    DidMgmt {
        #[command(subcommand)]
        command: DidMgmtCommands,
    },

    /// DEPRECATED — renamed to `vta did-mgmt <subcommand>`. Still
    /// dispatched for one release; switch your scripts before the
    /// alias is removed in the next minor.
    #[cfg(feature = "webvh")]
    #[command(hide = true)]
    Webvh {
        #[command(subcommand)]
        command: WebvhCommands,
    },
    /// Sealed-transfer bootstrap — seal payloads for offline consumer
    /// provisioning (mediators, webvh servers, and other complex clients).
    Bootstrap {
        #[command(subcommand)]
        command: BootstrapCommands,
    },
    /// Dev-only vault operations (offline). M1 ships `seed` — populates the
    /// `vault:` keyspace from a JSON file or a built-in demo set so operators
    /// can exercise vault/list/0.1 against a running VTA. Daemon must be
    /// stopped (fjall exclusive lock); not available in TEE deployments
    /// (the enclave's vsock-store is the only writer there — use the
    /// upcoming `vault/upsert/0.1` Trust Task instead).
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
    /// Manage the VTA's advertised transport services offline.
    ///
    /// Mirrors the `pnm services …` surface but operates directly
    /// on the local fjall keystore — no HTTP, no auth ceremony,
    /// no running VTA required. Filesystem access to the data
    /// directory is the security boundary (same model as
    /// `vta acl …`, `vta keys …`, etc.).
    ///
    /// **Not for TEE deployments.** Inside a Nitro Enclave the VTA's
    /// fjall store lives behind a vsock proxy; the offline `vta`
    /// binary on the parent has no access. Use `pnm services …`
    /// against the running VTA instead.
    ///
    /// **Don't run while the VTA daemon is running.** fjall's file
    /// lock will reject the open if the daemon holds it, so
    /// concurrent corruption is impossible — but offline writes
    /// won't be picked up until the daemon restarts. Prefer
    /// `pnm services` against the live VTA when both are available.
    #[cfg(feature = "webvh")]
    Services {
        #[command(subcommand)]
        command: ServicesCommands,
    },
}

#[derive(Subcommand)]
enum VaultCommands {
    /// Populate the `vault:` keyspace with VaultEntry records.
    ///
    /// Reads entries from a JSON file (array of canonical VaultEntry shape,
    /// per `https://trusttasks.org/spec/vault/_shared/0.1/vault-entry`), or
    /// — when `--entries-file` is omitted and `--context` is supplied —
    /// seeds three built-in demo entries that exercise every field shown
    /// in the wallet popup's vault panel (web + iOS targets, password and
    /// passkey kinds, tags, a breach flag, a never-used entry).
    ///
    /// Refuses to overwrite an entry with an existing id unless `--force`
    /// is passed — vault entries with stable ids generally shouldn't be
    /// silently rewritten.
    ///
    /// Daemon must be stopped (fjall holds an exclusive lock); restart
    /// after seeding to make the entries visible via vault/list/0.1.
    Seed {
        /// Path to a JSON file containing an array of VaultEntry objects.
        /// Mutually exclusive with `--context` for the demo set.
        #[arg(long)]
        entries_file: Option<std::path::PathBuf>,
        /// Trust context id the demo entries land under. Required when
        /// `--entries-file` is omitted; ignored when entries supply their
        /// own `contextId`.
        #[arg(long)]
        context: Option<String>,
        /// Print the entries that would be seeded without writing.
        #[arg(long)]
        dry_run: bool,
        /// Overwrite an existing entry with the same id.
        #[arg(long)]
        force: bool,
    },
    /// Delete every row in the `vault:` keyspace.
    ///
    /// Use cases:
    /// - Clear out stale-format rows after a schema migration
    ///   (e.g. M1's bare `VaultEntry` rows became unreadable after
    ///   M2A introduced the `StoredVaultEntry { entry, secret }`
    ///   wrapper — a fresh wipe is faster than writing a one-shot
    ///   re-wrapper).
    /// - Reset the demo state between test runs.
    ///
    /// Refuses to run unless `--force` is supplied — this is
    /// irreversible against the local store and you'd lose any
    /// real entries the wallet has saved.
    ///
    /// Daemon must be stopped (fjall holds an exclusive lock); the
    /// `vault:` keyspace is the only one touched, so other VTA
    /// state (ACL, contexts, keys, audit) is preserved.
    Wipe {
        /// Required confirmation flag. Without it the command lists
        /// the row count and exits without writing.
        #[arg(long)]
        force: bool,
        /// Optional: only wipe rows whose `contextId` matches.
        /// Useful when the user wants to reset a single persona's
        /// vault without clearing the others. Omit to wipe every row.
        #[arg(long)]
        context: Option<String>,
    },
}

#[derive(Subcommand)]
enum BootstrapCommands {
    /// Generate a fresh BootstrapRequest (consumer side).
    ///
    /// Mints an ephemeral Ed25519 keypair, persists the seed under
    /// `<seed-dir>/bootstrap-secrets/<bundle_id>.key`, and writes the
    /// `BootstrapRequest` JSON. Hand the JSON to the VTA operator; they
    /// return an armored sealed bundle which `vta bootstrap open` decrypts
    /// using the persisted seed.
    ///
    /// Used in cold-start scenarios where `pnm bootstrap request` isn't
    /// available — same wire format, different binary.
    Request {
        /// Output path for the BootstrapRequest JSON.
        #[arg(long)]
        out: PathBuf,
        /// Optional human-readable label echoed back in the request.
        #[arg(long)]
        label: Option<String>,
        /// Override the default seed cache directory
        /// (`~/.config/vta/bootstrap-secrets/`). Useful in CI or sealed
        /// images where `$HOME` isn't writable.
        #[arg(long)]
        seed_dir: Option<PathBuf>,
    },
    /// Open an armored sealed bundle returned by the producer (consumer side).
    ///
    /// Looks up the seed by `bundle_id` under `<seed-dir>/bootstrap-secrets/`,
    /// derives the X25519 HPKE secret, decrypts, and prints the payload.
    /// Counterpart to `vta bootstrap request`.
    ///
    /// When `--expect-vta-did` is set and the payload is a
    /// `TemplateBootstrap`, the VTA-issued authorization VC is verified
    /// end-to-end: the pinned DID is cross-checked against the bundle's
    /// `vta_trust.vta_did` and against `credentialSubject.adminOf.vta`,
    /// the issuer's pubkey is extracted from the bundled DID document's
    /// verificationMethod array, and the Data Integrity proof is
    /// verified. The DidSigned producer assertion (when present) is
    /// verified against the same key. Without this flag the opener
    /// trusts only the OOB SHA-256 digest; the printed payload is
    /// labelled "unverified trust bundle" so it's obvious.
    Open {
        /// Path to the armored sealed bundle.
        #[arg(long)]
        bundle: PathBuf,
        /// Expected SHA-256 digest, communicated by the producer
        /// out-of-band. Required unless `--no-verify-digest` is set.
        #[arg(long)]
        expect_digest: Option<String>,
        /// Skip out-of-band digest verification. Prints a warning;
        /// intended for testing only.
        #[arg(long, default_value_t = false)]
        no_verify_digest: bool,
        /// Pin the VTA DID out-of-band. When supplied and the payload is
        /// a `TemplateBootstrap`, the VC + producer assertion are
        /// verified end-to-end against this DID; mismatches are
        /// rejected (no silent fallback). Without this flag,
        /// verification is digest-only.
        #[arg(long)]
        expect_vta_did: Option<String>,
        /// Override the default seed cache directory
        /// (`~/.config/vta/bootstrap-secrets/`). Must match the value
        /// passed to `vta bootstrap request`.
        #[arg(long)]
        seed_dir: Option<PathBuf>,
    },
    /// Seal a payload for a consumer's BootstrapRequest (offline / Mode C).
    ///
    /// Reads the consumer's request (containing their ephemeral X25519 pubkey
    /// and a nonce), seals the supplied payload to that pubkey using HPKE,
    /// and writes an armored bundle. Prints the canonical SHA-256 digest the
    /// operator must communicate to the consumer out-of-band so they can
    /// pass it to `vta bootstrap open --expect-digest` (or
    /// `pnm bootstrap open` if the consumer has pnm installed).
    ///
    /// Producer authenticity in this mode is `PinnedOnly`: the consumer
    /// trusts the producer pubkey embedded in the bundle because they
    /// pinned it out-of-band.
    Seal {
        /// Path to the consumer's BootstrapRequest JSON.
        #[arg(long)]
        request: PathBuf,
        /// Path to a JSON file containing a SealedPayloadV1.
        #[arg(long)]
        payload: PathBuf,
        /// Output path for the armored bundle.
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate a VP-framed BootstrapRequest for the provision-integration
    /// flow (consumer side).
    ///
    /// Mints an ephemeral Ed25519 keypair, persists the seed under
    /// `<seed-dir>/bootstrap-secrets/<bundle_id>.key`, and writes a signed
    /// VP (VC Data Model 2.0 `VerifiablePresentation` + `BootstrapRequest`
    /// types) carrying a `TemplateBootstrap` ask naming the target
    /// template and variables. Hand the JSON to the VTA operator; they
    /// return an armored sealed bundle which `vta bootstrap open`
    /// decrypts using the persisted seed.
    ///
    /// Used by integration operators (mediator, did-hosting-control, did-hosting-daemon,
    /// did-hosting-server, etc.) to request enrollment from a VTA that may not
    /// yet be network-reachable. See
    /// `docs/02-vta/provision-integration.md` for the end-to-end
    /// flow.
    ProvisionRequest {
        /// DID template name the VTA should render (e.g.
        /// `didcomm-mediator`, `did-hosting-control`, `did-hosting-daemon`,
        /// `did-hosting-server`, or an operator-uploaded custom template).
        #[arg(long)]
        template: String,
        /// Template variable, repeat for each binding. Format `KEY=VALUE`.
        /// Values are parsed as JSON when the value starts with `{`, `[`,
        /// `"`, digit, `true`, `false`, or `null`; otherwise treated as a
        /// string.
        #[arg(long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
        /// Hint the target VTA context. The VTA operator may override
        /// but if they do and the hint disagrees, the request is
        /// rejected rather than silently normalised.
        #[arg(long)]
        context_hint: Option<String>,
        /// Opt into long-term admin-DID rollover: the VTA mints a
        /// fresh admin DID under its own key custody (default template
        /// `vta-admin`) and binds authorization to that DID instead
        /// of the ephemeral `client_did`. Recommended for any
        /// integration that stays up long-term.
        #[arg(long)]
        admin_template: Option<String>,
        /// Freshness window in hours for the VP's `validUntil`.
        /// Default 168 (7 days) — setup-file shuffling between hosts
        /// is slow.
        #[arg(long, value_name = "HOURS", default_value_t = 168.0)]
        validity_hours: f64,
        /// Free-form human label echoed back in audit logs.
        #[arg(long)]
        label: Option<String>,
        /// Override the default seed cache directory
        /// (`~/.config/vta/bootstrap-secrets/`). Must match the
        /// `--seed-dir` passed to `vta bootstrap open` on the same host.
        #[arg(long)]
        seed_dir: Option<PathBuf>,
        /// Output path for the signed BootstrapRequest JSON.
        #[arg(long)]
        out: PathBuf,
    },
    /// Provision a template-driven integration (mediator, webvh-host,
    /// future kinds) for a consumer's VP-framed BootstrapRequest.
    ///
    /// Mints integration key material, renders the named DID template,
    /// creates an admin ACL entry for the consumer's `client_did`,
    /// issues a VTA-signed authorization VC, and seals everything to
    /// the consumer's X25519 pubkey (derived from `client_did`).
    ///
    /// See `docs/02-vta/provision-integration.md` for the full flow.
    #[cfg(feature = "webvh")]
    ProvisionIntegration {
        /// Path to the consumer's VP-framed BootstrapRequest JSON
        /// (`pnm bootstrap request --out …`).
        #[arg(long)]
        request: PathBuf,
        /// VTA context the integration will live in. Must be an
        /// existing context the operator is admin of (or pass
        /// `--create-context` to create it inline). If the request
        /// carries a `contextHint`, this flag must either match it or
        /// be omitted.
        #[arg(long)]
        context: Option<String>,
        /// Create the target context if it does not already exist.
        /// Idempotent — silently succeeds if the context exists. The
        /// context is created with `name = <id>`; rename later via the
        /// REST API if needed. Without this flag, a missing context
        /// fails with operator-remediation guidance.
        #[arg(long)]
        create_context: bool,
        /// Producer assertion mode on the returned sealed bundle.
        /// `did-signed` (default) signs with the VTA's `{vta_did}#key-0`.
        /// `pinned-only` is a dev/test escape hatch — no in-band
        /// signature, digest-pinning only.
        #[arg(long, default_value = "did-signed")]
        assertion: crate::bootstrap_cli::AssertionModeFlag,
        /// Override for the VC's `validUntil` window, in hours. Default
        /// is 1h. Fractional hours accepted (e.g. `0.25` for 15min).
        #[arg(long, value_name = "HOURS")]
        vc_validity_hours: Option<f64>,
        /// Output path for the armored bundle.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeyCliCommands {
    /// List keys
    List {
        /// Filter by context ID
        #[arg(long)]
        context: Option<String>,
        /// Filter by status (active or revoked)
        #[arg(long)]
        status: Option<String>,
    },
    /// Export secret key material for one or more keys
    Secrets {
        /// Key IDs to export (omit to export all active keys in --context)
        key_ids: Vec<String>,
        /// Export all active keys in this context
        #[arg(long)]
        context: Option<String>,
    },
    /// List seed generations and their status
    Seeds,
    /// Rotate to a new master seed (retires the current seed)
    RotateSeed {
        /// BIP-39 mnemonic for the new seed (generates random if omitted)
        #[arg(long)]
        mnemonic: Option<String>,
    },
    /// Export all active keys in a context as a sealed DidSecrets bundle.
    ///
    /// Reads the local keystore directly — no running VTA or network
    /// required. Mirrors `pnm keys bundle` but works in cold-start /
    /// air-gapped environments where PNM cannot reach the VTA.
    Bundle {
        /// Context ID whose active keys should be exported.
        #[arg(long)]
        context: String,
        /// Path to the consumer's BootstrapRequest JSON (v1). Mutually
        /// exclusive with `--recipient-did` / `--recipient-nonce`.
        #[arg(long, conflicts_with_all = ["recipient_did", "recipient_nonce"])]
        recipient: Option<PathBuf>,
        /// Inline consumer DID (`did:key:z6Mk...`). Requires `--recipient-nonce`.
        #[arg(long, requires = "recipient_nonce")]
        recipient_did: Option<String>,
        /// Inline consumer nonce (32 hex chars == 16 bytes). Requires
        /// `--recipient-did`.
        #[arg(long, requires = "recipient_did")]
        recipient_nonce: Option<String>,
        /// Output path for the armored sealed bundle. If omitted, the
        /// armor is written to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ContextCommands {
    /// List all application contexts.
    List,
    /// Get a context by ID.
    Get {
        /// Context ID.
        id: String,
    },
    /// Create an application context (offline, no running VTA required).
    ///
    /// Allocates the next BIP-32 context index and writes the context
    /// record. Mirrors the online `POST /contexts` endpoint (and
    /// `pnm contexts create`) for cold-start / air-gapped operators
    /// who need to provision a context before standing the service up.
    ///
    /// Without `--admin-did` no keys, ACL entries, or DID are minted —
    /// pair with `vta bootstrap provision-integration` (or run it with
    /// `--create-context`) to populate the context. Supplying
    /// `--admin-did` writes an admin ACL entry scoped to the new
    /// context atomically with the context record, mirroring the
    /// `pnm contexts create --admin-did` shorthand.
    Create {
        /// Context ID (slug). Lowercase alphanumeric + hyphens, ≤64
        /// chars, no leading/trailing hyphen.
        #[arg(long)]
        id: String,
        /// Human-readable name. Defaults to the id when omitted.
        #[arg(long)]
        name: Option<String>,
        /// Free-form description.
        #[arg(long)]
        description: Option<String>,
        /// Parent context path to nest under (e.g. `acme/eng`). Creates a
        /// sub-context; omit for a top-level context.
        #[arg(long)]
        parent: Option<String>,
        /// DID to grant admin access to (must start with `did:`). When
        /// set, atomically creates an ACL entry with role=admin scoped
        /// to this context.
        #[arg(long)]
        admin_did: Option<String>,
        /// Human-readable label for the admin ACL entry.
        #[arg(long)]
        admin_label: Option<String>,
        /// Setup-ACL expiry — accepts `N[s|m|h|d|w]` (e.g. `24h`, `7d`).
        /// When set, the admin ACL entry auto-expires via the server's
        /// ACL sweeper. Without this flag the entry is permanent.
        /// Requires `--admin-did`.
        #[arg(long, requires = "admin_did")]
        admin_expires: Option<String>,
    },
    /// Update an existing context.
    Update {
        /// Context ID.
        id: String,
        /// New name.
        #[arg(long)]
        name: Option<String>,
        /// Set the DID for this context.
        #[arg(long)]
        did: Option<String>,
        /// New description.
        #[arg(long)]
        description: Option<String>,
    },
    /// Delete a context and all associated resources (keys, ACL
    /// entries, DID records, scoped templates).
    Delete {
        /// Context ID.
        id: String,
        /// Skip confirmation and delete immediately.
        #[arg(long, short)]
        force: bool,
    },
    /// Export an existing context — its admin credential + all DID
    /// keys (signing + KA + any pre-rotation) + DID document + log —
    /// as a sealed ContextProvision bundle for a new/backup admin to
    /// import.
    ///
    /// Reads the local keystore directly — no running VTA or network
    /// required. Mirrors `pnm context reprovision` but works in
    /// cold-start / air-gapped environments where PNM cannot reach the
    /// VTA.
    ///
    /// The bundle always contains every key tied to the context's DID
    /// document (operational keys are auto-included). `--admin-key`
    /// separately names the existing Ed25519 seed that becomes the
    /// **admin credential** — the `did:key` the mediator operator uses
    /// to authenticate back to the VTA for ACL-gated operations.
    /// When omitted, a fresh admin key is minted in the context and
    /// the derived `did:key` is granted admin access automatically.
    Reprovision {
        /// Context ID to export.
        #[arg(long)]
        id: String,
        /// Existing Ed25519 key whose seed backs the exported admin
        /// credential. When omitted, a fresh admin key is minted in
        /// the context. Kept as `--key` for backward compatibility.
        #[arg(long = "admin-key", alias = "key")]
        admin_key: Option<String>,
        /// Label applied to the freshly-minted admin key when
        /// `--admin-key` is omitted. Defaults to
        /// `"admin-reprovision"`.
        #[arg(long)]
        admin_label: Option<String>,
        /// Path to the consumer's BootstrapRequest JSON (v1). Mutually
        /// exclusive with `--recipient-did` / `--recipient-nonce`.
        #[arg(long, conflicts_with_all = ["recipient_did", "recipient_nonce"])]
        recipient: Option<PathBuf>,
        /// Inline consumer DID (`did:key:z6Mk...`). Requires `--recipient-nonce`.
        #[arg(long, requires = "recipient_nonce")]
        recipient_did: Option<String>,
        /// Inline consumer nonce (32 hex chars == 16 bytes). Requires
        /// `--recipient-did`.
        #[arg(long, requires = "recipient_did")]
        recipient_nonce: Option<String>,
        /// Output path for the armored sealed bundle. If omitted, the
        /// armor is written to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[cfg(feature = "webvh")]
#[derive(Subcommand)]
enum WebvhCommands {
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
    /// Create a did:webvh DID and publish to a WebVH server
    CreateDid {
        /// Target context ID
        #[arg(long)]
        context: String,
        /// WebVH server ID
        #[arg(long)]
        server: String,
        /// Optional path on the server (server allocates if omitted)
        #[arg(long)]
        path: Option<String>,
        /// Human-readable label for the DID and key records
        #[arg(long)]
        label: Option<String>,
        /// Make the DID portable (default: true)
        #[arg(long, default_value_t = true)]
        portable: bool,
        /// Add mediator DIDComm service endpoint
        #[arg(long)]
        mediator_service: bool,
        /// Additional services as JSON array
        #[arg(long)]
        services: Option<String>,
        /// Number of pre-rotation keys to generate
        #[arg(long)]
        pre_rotation: Option<u32>,
        /// Print the generated mnemonic to stderr. **Off by default** —
        /// printing puts the master seed in shell history, terminal
        /// scrollback, CI log collectors, and tmux/screen buffers. The
        /// mnemonic is also persisted via the configured seed-store; if
        /// you need it for paper backup, run `vta export-mnemonic`
        /// instead so it goes through the time-bounded export guard.
        #[arg(long)]
        print_mnemonic: bool,
    },
    /// List WebVH DIDs
    ListDids {
        /// Filter by context ID
        #[arg(long)]
        context: Option<String>,
        /// Filter by server ID
        #[arg(long)]
        server: Option<String>,
    },
    /// Delete a WebVH DID
    DeleteDid {
        /// The DID to delete
        did: String,
    },
    /// Print the raw `did.jsonl` log for a webvh DID the VTA knows.
    ///
    /// Snapshot from provisioning time — use this for audit or
    /// republication fallback, not as a live resolver (the integration
    /// itself becomes the live source once it publishes).
    DidLog {
        /// The DID to retrieve the log for.
        did: String,
        /// Optional output file. Stdout if omitted.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Edit an existing WebVH DID document. Offline equivalent of
    /// `pnm webvh edit-did`. Operates directly on the local fjall
    /// keystore — VTA daemon must be stopped (fjall lock).
    ///
    /// Interactive mode opens the latest DID document in `$EDITOR`,
    /// then asks about webvh parameters. Non-interactive mode takes
    /// `--document` / `--options-file` and per-field flags.
    EditDid {
        /// The DID to edit.
        #[arg(long)]
        did: String,
        /// Path to a JSON file with the new DID document. Skips
        /// `$EDITOR`.
        #[arg(long)]
        document: Option<PathBuf>,
        /// Path to a JSON file with a full UpdateDidWebvhBody.
        /// Mutually exclusive with the per-field flags below.
        #[arg(long)]
        options_file: Option<PathBuf>,
        #[arg(long)]
        pre_rotation: Option<u32>,
        #[arg(long)]
        ttl: Option<u32>,
        #[arg(long = "watcher")]
        watchers: Vec<String>,
        #[arg(long)]
        no_watchers: bool,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        no_confirm: bool,
    },
    /// Register an existing serverless WebVH DID with a registered
    /// hosting server. Pushes the local `did.jsonl` to the host and
    /// flips the DID's `server_id` so future updates auto-publish.
    ///
    /// Offline equivalent of `pnm webvh register-did`. Operates
    /// directly on the local fjall keystore — VTA daemon must be
    /// stopped (fjall holds an exclusive lock when the daemon is
    /// running).
    RegisterDid {
        /// The serverless WebVH DID to promote.
        #[arg(long)]
        did: String,
        /// Registered server id (from `vta webvh add-server`).
        #[arg(long)]
        server: String,
        /// Take over a slot owned by a different DID. Honoured only
        /// when this VTA's DID authenticates to the host as an admin.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

// ── vta did-mgmt {servers,dids} (new surface) ──────────────────────
//
// Restructured replacement for `vta webvh …`. Variant fields are
// duplicated from `WebvhCommands` so the new structure can stand on
// its own; `From<DidMgmtCommands> for WebvhCommands` converts into
// the legacy enum so the existing dispatch handler stays the single
// source of business logic. Drop the legacy enum + conversion in
// the next minor release.

/// Two-tier split: server-registration management vs DID lifecycle.
#[cfg(feature = "webvh")]
#[derive(Subcommand)]
enum DidMgmtCommands {
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

/// `vta did-mgmt servers {…}` — local server registry.
#[cfg(feature = "webvh")]
#[derive(Subcommand)]
enum DidMgmtServerCommands {
    /// Add a DID-hosting server to the local registry.
    Add {
        /// Server identifier.
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
    /// List configured DID-hosting servers.
    List,
    /// Update a DID-hosting server.
    Update {
        /// Server identifier to update.
        id: String,
        /// New label (empty string to clear).
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a DID-hosting server.
    Remove {
        /// Server identifier to remove.
        id: String,
    },
}

/// `vta did-mgmt dids {…}` — DID lifecycle (offline).
#[cfg(feature = "webvh")]
#[derive(Subcommand)]
enum DidMgmtDidCommands {
    /// Create a did:webvh DID and publish to a registered server.
    Create {
        /// Target context ID.
        #[arg(long)]
        context: String,
        /// DID-hosting server ID.
        #[arg(long)]
        server: String,
        /// Optional path on the server (server allocates if omitted).
        #[arg(long)]
        path: Option<String>,
        /// Human-readable label for the DID and key records.
        #[arg(long)]
        label: Option<String>,
        /// Make the DID portable (default: true).
        #[arg(long, default_value_t = true)]
        portable: bool,
        /// Add mediator DIDComm service endpoint.
        #[arg(long)]
        mediator_service: bool,
        /// Additional services as JSON array.
        #[arg(long)]
        services: Option<String>,
        /// Number of pre-rotation keys to generate.
        #[arg(long)]
        pre_rotation: Option<u32>,
        /// Print the generated mnemonic to stderr. **Off by default** —
        /// printing puts the master seed in shell history, terminal
        /// scrollback, CI log collectors, and tmux/screen buffers. The
        /// mnemonic is also persisted via the configured seed-store;
        /// if you need it for paper backup, run `vta export-mnemonic`
        /// instead so it goes through the time-bounded export guard.
        #[arg(long)]
        print_mnemonic: bool,
    },
    /// Edit an existing DID document. Offline equivalent of
    /// `pnm did-mgmt dids edit`. Operates directly on the local
    /// fjall keystore — VTA daemon must be stopped.
    Edit {
        /// The DID to edit.
        #[arg(long)]
        did: String,
        /// Path to a JSON file with the new DID document. Skips
        /// `$EDITOR`.
        #[arg(long)]
        document: Option<PathBuf>,
        /// Path to a JSON file with a full UpdateDidWebvhBody.
        /// Mutually exclusive with the per-field flags below.
        #[arg(long)]
        options_file: Option<PathBuf>,
        #[arg(long)]
        pre_rotation: Option<u32>,
        #[arg(long)]
        ttl: Option<u32>,
        #[arg(long = "watcher")]
        watchers: Vec<String>,
        #[arg(long)]
        no_watchers: bool,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        no_confirm: bool,
    },
    /// Register an existing serverless DID with a registered
    /// hosting server. Pushes the local `did.jsonl` to the host and
    /// flips the DID's `server_id` so future updates auto-publish.
    /// Offline equivalent of `pnm did-mgmt dids register`.
    Register {
        /// The serverless DID to promote.
        #[arg(long)]
        did: String,
        /// Registered server id (from `vta did-mgmt servers add`).
        #[arg(long)]
        server: String,
        /// Take over a slot owned by a different DID. Honoured only
        /// when this VTA's DID authenticates to the host as an admin.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// List DIDs.
    List {
        /// Filter by context ID.
        #[arg(long)]
        context: Option<String>,
        /// Filter by server ID.
        #[arg(long)]
        server: Option<String>,
    },
    /// Delete a DID.
    Delete {
        /// The DID to delete.
        did: String,
    },
    /// Print the raw `did.jsonl` log for a DID the VTA knows.
    ///
    /// Snapshot from provisioning time — use this for audit or
    /// republication fallback, not as a live resolver (the
    /// integration itself becomes the live source once it
    /// publishes).
    GetLog {
        /// The DID to retrieve the log for.
        did: String,
        /// Optional output file. Stdout if omitted.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[cfg(feature = "webvh")]
impl From<DidMgmtCommands> for WebvhCommands {
    /// Bridge the new structured surface into the legacy flat
    /// `WebvhCommands` so the existing dispatch handler remains the
    /// single source of business logic. Drop together with the
    /// legacy enum in the next minor release.
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
                    path,
                    label,
                    portable,
                    mediator_service,
                    services,
                    pre_rotation,
                    print_mnemonic,
                } => WebvhCommands::CreateDid {
                    context,
                    server,
                    path,
                    label,
                    portable,
                    mediator_service,
                    services,
                    pre_rotation,
                    print_mnemonic,
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
                DidMgmtDidCommands::Register { did, server, force } => {
                    WebvhCommands::RegisterDid { did, server, force }
                }
                DidMgmtDidCommands::List { context, server } => {
                    WebvhCommands::ListDids { context, server }
                }
                DidMgmtDidCommands::Delete { did } => WebvhCommands::DeleteDid { did },
                DidMgmtDidCommands::GetLog { did, out } => WebvhCommands::DidLog { did, out },
            },
        }
    }
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Print the VTA's identity and service settings.
    ///
    /// Output matches what `pnm setup` asks for (VTA DID, public URL,
    /// mediator) plus the config/data paths. No network calls; the data
    /// store is not opened, so this works while the VTA is running.
    Show,
}

#[derive(Subcommand)]
enum StepUpCommands {
    /// Print the current step-up policy (enabled flag + per-op floors).
    Show,
    /// Enable step-up enforcement. Floors with a non-`none` mode then gate
    /// their operations; configure them with `set-floor` first.
    Enable,
    /// Disable step-up enforcement — every operation proceeds at AAL1. The
    /// break-glass switch when an enabled policy has locked you out.
    Disable,
    /// Add or replace a per-operation-class floor.
    SetFloor {
        /// Operation-class: `acl/grant`, `acl/change-role`, `acl/revoke`,
        /// `acl/swap-key`, `context/delete`, `key/revoke`, or `*` for the
        /// catch-all default.
        operation: String,
        /// Minimum mode: `none`, `self`, `delegated`, or `delegated-any`.
        mode: String,
        /// Admit a non-escalating self-service request (e.g. `acl/swap-key`)
        /// at AAL1 even when the mode requires AAL2 — the rotation carve-out.
        #[arg(long)]
        allow_aal1_if_non_escalating: bool,
    },
    /// Remove the floor for an operation-class.
    RemoveFloor {
        /// Operation-class to clear.
        operation: String,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Sign an unseal challenge using a key from the local fjall keystore.
    ///
    /// The cold-start companion to `pnm auth sign-challenge`. When
    /// `vta unseal` prints a challenge, run this in a *second* terminal
    /// (the daemon must be stopped — fjall takes an exclusive lock per
    /// data dir) to produce the Ed25519 signature, then paste it back
    /// into the unseal prompt.
    ///
    /// Only supports `did:key:` admin DIDs; for other DID methods the
    /// unseal flow itself rejects via the verifier in `seal::
    /// verify_challenge_signature`.
    SignChallenge {
        /// The admin DID to sign as. Must match a key record in the
        /// local keystore — typically the super-admin's `did:key:zXxx`
        /// from `vta bootstrap-admin`.
        #[arg(long)]
        did: String,
        /// The 32-byte challenge in hex (exactly as printed by
        /// `vta unseal`).
        #[arg(long)]
        challenge: String,
    },
}

#[derive(Subcommand)]
enum AclCommands {
    /// List all ACL entries
    List {
        /// Filter by context
        #[arg(long)]
        context: Option<String>,
        /// Filter by role (admin, initiator, application, reader)
        #[arg(long)]
        role: Option<String>,
    },
    /// Show details of a single ACL entry
    Get {
        /// The DID to look up
        did: String,
    },
    /// Update an existing ACL entry
    Update {
        /// The DID to update
        did: String,
        /// New role (admin, initiator, application, reader)
        #[arg(long)]
        role: Option<String>,
        /// New label (empty string to clear)
        #[arg(long)]
        label: Option<String>,
        /// New context list (comma-separated; omit flag to keep unchanged)
        #[arg(long, value_delimiter = ',')]
        contexts: Option<Vec<String>>,
        /// Set the delegated step-up approver VID (`stepUp.approver`). Empty
        /// string clears it; omit to keep unchanged. Break-glass: direct store
        /// write, no wire auth.
        #[arg(long)]
        step_up_approver: Option<String>,
        /// Set the per-entry step-up override (`self` | `delegated`;
        /// `stepUp.require`). Empty string clears it; omit to keep unchanged.
        #[arg(long)]
        step_up_require: Option<String>,
    },
    /// Delete an ACL entry
    Delete {
        /// The DID to delete
        did: String,
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
}

// ── `vta services …` offline subcommand surface (mirrors `pnm
//    services …` from spec §5.1) ────────────────────────────────

#[cfg(feature = "webvh")]
#[derive(Subcommand)]
enum ServicesCommands {
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
    /// Show inbound-message attribution by mediator and sender.
    /// Note: the offline binary's telemetry sink is fresh per
    /// invocation, so the report is empty by design — for the
    /// running VTA's full record use `pnm services report`.
    Report {
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value = "json")]
        format: String,
    },
}

#[cfg(feature = "webvh")]
#[derive(Subcommand)]
enum RestCommands {
    Enable {
        #[arg(long)]
        url: String,
    },
    Update {
        #[arg(long)]
        url: String,
    },
    Disable,
    Rollback,
}

#[cfg(feature = "webvh")]
#[derive(Subcommand)]
enum DidcommCommands {
    Enable {
        #[arg(long)]
        mediator_did: String,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        handshake_timeout: Option<u64>,
    },
    Update {
        #[arg(long = "mediator-did", visible_alias = "to")]
        new_mediator_did: String,
        #[arg(long, default_value_t = 86_400)]
        drain_ttl: u64,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        handshake_timeout: Option<u64>,
    },
    Disable {
        #[arg(long, default_value_t = 86_400)]
        drain_ttl: u64,
    },
    Rollback {
        #[arg(long)]
        drain_ttl: Option<u64>,
    },
    Drain {
        #[command(subcommand)]
        command: DrainCommands,
    },
}

#[cfg(feature = "webvh")]
#[derive(Subcommand)]
enum DrainCommands {
    List,
    Cancel {
        #[arg(long)]
        mediator_did: String,
    },
}

#[tokio::main]
async fn main() {
    // Pin rustls to the aws-lc-rs backend before any TLS object is built;
    // see `vta_sdk::crypto_init`. Without this, rustls 0.23 panics on
    // backend auto-detection when both backends are compiled in.
    vta_sdk::crypto_init::install_default_crypto_provider();

    let cli = Cli::parse();

    #[cfg(feature = "keyring")]
    if let Err(e) = vta_sdk::keyring_init::install_default_store() {
        eprintln!("warning: OS keyring unavailable: {e}");
    }

    print_banner();

    match cli.command {
        Some(Commands::Setup { from }) => {
            #[cfg(feature = "setup")]
            {
                let result = match from {
                    Some(path) => setup::run_setup_from_file(path).await,
                    None => setup::run_setup_wizard(cli.config).await,
                };
                if let Err(e) = result {
                    eprintln!("Setup failed: {e}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(feature = "setup"))]
            {
                let _ = from;
                eprintln!("Setup wizard not available (compiled without 'setup' feature)");
                std::process::exit(1);
            }
        }
        Some(Commands::BootstrapAdmin { did, label }) => {
            if let Err(e) = run_bootstrap_admin(cli.config, did, label).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Unseal) => {
            let config = match AppConfig::load(cli.config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            // run_unseal_challenge opens and drops the store twice on
            // purpose so the fjall lock is not held while the operator
            // is pasting a signature — see the doc comment on that
            // function. Pass the config, not an already-opened Store.
            if let Err(e) = seal::run_unseal_challenge(&config.store).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Auth { command }) => {
            // `auth` subcommands are intentionally not gated on the seal —
            // sign-challenge produces an Ed25519 signature offline; it
            // never mutates state and is the cold-start companion to
            // `vta unseal` itself. Gating it on `check_seal` would be a
            // chicken-and-egg paradox.
            let config = match AppConfig::load(cli.config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            let result = match command {
                AuthCommands::SignChallenge { did, challenge } => {
                    auth_sign_challenge(&config, &did, &challenge).await
                }
            };
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::ExportAdmin) => {
            // SEALED CHECK: export-admin leaks private keys
            check_seal(&cli.config).await;
            if let Err(e) = export_admin(cli.config).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Status) => {
            if let Ok(config) = AppConfig::load(cli.config.clone()) {
                init_tracing(&config);
            }
            if let Err(e) = status::run_status(cli.config).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Config { command }) => {
            let result = match command {
                ConfigCommands::Show => run_config_show(cli.config),
            };
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::StepUp { command }) => {
            let result = run_step_up(cli.config, command);
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::CreateDidKey {
            context,
            admin,
            label,
        }) => {
            // SEALED CHECK: creates keys and optionally admin ACL entries
            check_seal(&cli.config).await;
            let args = did_key::CreateDidKeyArgs {
                config_path: cli.config,
                context,
                admin,
                label,
            };
            if let Err(e) = did_key::run_create_did_key(args).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::CreateDidWebvh {
            context,
            label,
            url,
            export_secrets,
            admin,
        }) => {
            // SEALED CHECK: creates keys and DIDs
            check_seal(&cli.config).await;
            #[cfg(feature = "setup")]
            {
                let args = did_webvh::CreateDidWebvhArgs {
                    config_path: cli.config,
                    context,
                    label,
                    url,
                    export_secrets,
                    admin,
                };
                if let Err(e) = did_webvh::run_create_did_webvh(args).await {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(feature = "setup"))]
            {
                let _ = (context, label, url, export_secrets, admin);
                eprintln!("create-did-webvh is not available (compiled without 'setup' feature)");
                std::process::exit(1);
            }
        }
        Some(Commands::ImportDid {
            did,
            role,
            label,
            context,
        }) => {
            // SEALED CHECK: imports DIDs with arbitrary roles
            check_seal(&cli.config).await;
            let args = import_did::ImportDidArgs {
                config_path: cli.config,
                did,
                role,
                label,
                context,
            };
            if let Err(e) = import_did::run_import_did(args).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Vault { command }) => match command {
            VaultCommands::Seed {
                entries_file,
                context,
                dry_run,
                force,
            } => {
                let args = vault_cli::VaultSeedArgs {
                    config_path: cli.config,
                    entries_file,
                    context,
                    dry_run,
                    force,
                };
                if let Err(e) = vault_cli::run_vault_seed(args).await {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
            VaultCommands::Wipe { force, context } => {
                let args = vault_cli::VaultWipeArgs {
                    config_path: cli.config,
                    force,
                    context,
                };
                if let Err(e) = vault_cli::run_vault_wipe(args).await {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        },
        Some(Commands::Keys { command }) => {
            // SEALED CHECK: secrets export and seed rotation
            match &command {
                KeyCliCommands::List { .. } | KeyCliCommands::Seeds => {}
                KeyCliCommands::Secrets { .. }
                | KeyCliCommands::RotateSeed { .. }
                | KeyCliCommands::Bundle { .. } => {
                    check_seal(&cli.config).await;
                }
            }
            let result = match command {
                KeyCliCommands::List { context, status } => {
                    keys_cli::run_keys_list(cli.config, context, status).await
                }
                KeyCliCommands::Secrets { key_ids, context } => {
                    keys_cli::run_keys_secrets(cli.config, key_ids, context).await
                }
                KeyCliCommands::Seeds => keys_cli::run_keys_seeds_list(cli.config).await,
                KeyCliCommands::RotateSeed { mnemonic } => {
                    keys_cli::run_rotate_seed(cli.config, mnemonic).await
                }
                KeyCliCommands::Bundle {
                    context,
                    recipient,
                    recipient_did,
                    recipient_nonce,
                    out,
                } => {
                    bootstrap_cli::run_keys_bundle(
                        cli.config,
                        context,
                        recipient,
                        recipient_did,
                        recipient_nonce,
                        out,
                    )
                    .await
                }
            };
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Contexts { command }) => {
            // SEALED CHECK: only commands that mutate state need the
            // unsealed-store guard. List/Get are read-only.
            match &command {
                ContextCommands::List | ContextCommands::Get { .. } => {}
                ContextCommands::Create { .. }
                | ContextCommands::Update { .. }
                | ContextCommands::Delete { .. }
                | ContextCommands::Reprovision { .. } => {
                    check_seal(&cli.config).await;
                }
            }
            let result = match command {
                ContextCommands::List => bootstrap_cli::run_context_list(cli.config).await,
                ContextCommands::Get { id } => bootstrap_cli::run_context_get(cli.config, id).await,
                ContextCommands::Create {
                    id,
                    name,
                    description,
                    parent,
                    admin_did,
                    admin_label,
                    admin_expires,
                } => {
                    bootstrap_cli::run_context_create(
                        cli.config,
                        id,
                        name,
                        description,
                        parent,
                        admin_did,
                        admin_label,
                        admin_expires,
                    )
                    .await
                }
                ContextCommands::Update {
                    id,
                    name,
                    did,
                    description,
                } => {
                    bootstrap_cli::run_context_update(cli.config, id, name, did, description).await
                }
                ContextCommands::Delete { id, force } => {
                    bootstrap_cli::run_context_delete(cli.config, id, force).await
                }
                ContextCommands::Reprovision {
                    id,
                    admin_key,
                    admin_label,
                    recipient,
                    recipient_did,
                    recipient_nonce,
                    out,
                } => {
                    bootstrap_cli::run_context_reprovision(
                        cli.config,
                        id,
                        admin_key,
                        admin_label,
                        recipient,
                        recipient_did,
                        recipient_nonce,
                        out,
                    )
                    .await
                }
            };
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Acl { command }) => {
            // SEALED CHECK: update and delete modify ACL
            match &command {
                AclCommands::List { .. } | AclCommands::Get { .. } => {}
                AclCommands::Update { .. } | AclCommands::Delete { .. } => {
                    check_seal(&cli.config).await;
                }
            }
            let result = match command {
                AclCommands::List { context, role } => {
                    acl_cli::run_acl_list(cli.config, context, role).await
                }
                AclCommands::Get { did } => acl_cli::run_acl_get(cli.config, did).await,
                AclCommands::Update {
                    did,
                    role,
                    label,
                    contexts,
                    step_up_approver,
                    step_up_require,
                } => {
                    acl_cli::run_acl_update(
                        cli.config,
                        did,
                        role,
                        label,
                        contexts,
                        step_up_approver,
                        step_up_require,
                    )
                    .await
                }
                AclCommands::Delete { did, yes } => {
                    acl_cli::run_acl_delete(cli.config, did, yes).await
                }
            };
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        #[cfg(feature = "webvh")]
        Some(Commands::DidMgmt { command }) => {
            // Funnel the new structure through the legacy enum so the
            // existing dispatch / seal-check / handler chain stays the
            // single source of business logic. Drop together with the
            // legacy `Webvh` variant in the next minor release.
            run_webvh_dispatch(cli.config.clone(), command.into()).await;
        }
        #[cfg(feature = "webvh")]
        Some(Commands::Webvh { command }) => {
            eprintln!(
                "\x1b[1;33mwarning:\x1b[0m `vta webvh …` has been renamed to \
                 `vta did-mgmt {{servers,dids}} …`. The old name is accepted \
                 for one release and will be removed in the next minor. \
                 See `vta did-mgmt --help`."
            );
            run_webvh_dispatch(cli.config.clone(), command).await;
        }
        Some(Commands::Bootstrap { command }) => {
            let result = match command {
                BootstrapCommands::Seal {
                    request,
                    payload,
                    out,
                } => bootstrap_cli::run_seal(cli.config.clone(), request, payload, out).await,
                BootstrapCommands::Request {
                    out,
                    label,
                    seed_dir,
                } => bootstrap_cli::run_request(out, label, seed_dir).await,
                BootstrapCommands::Open {
                    bundle,
                    expect_digest,
                    no_verify_digest,
                    expect_vta_did,
                    seed_dir,
                } => {
                    bootstrap_cli::run_open(
                        bundle,
                        expect_digest,
                        no_verify_digest,
                        expect_vta_did,
                        seed_dir,
                    )
                    .await
                }
                BootstrapCommands::ProvisionRequest {
                    template,
                    vars,
                    context_hint,
                    admin_template,
                    validity_hours,
                    label,
                    seed_dir,
                    out,
                } => {
                    bootstrap_cli::run_provision_request(
                        template,
                        vars,
                        context_hint,
                        admin_template,
                        validity_hours,
                        label,
                        seed_dir,
                        out,
                    )
                    .await
                }
                #[cfg(feature = "webvh")]
                BootstrapCommands::ProvisionIntegration {
                    request,
                    context,
                    create_context,
                    assertion,
                    vc_validity_hours,
                    out,
                } => {
                    bootstrap_cli::run_provision_integration(
                        cli.config.clone(),
                        request,
                        context,
                        create_context,
                        assertion,
                        vc_validity_hours,
                        out,
                    )
                    .await
                }
            };
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        #[cfg(feature = "webvh")]
        Some(Commands::Services { command }) => {
            // SEALED CHECK: every service mutation modifies the
            // VTA's state on disk + publishes a new LogEntry.
            // List/report/drain-list are read-only and skip the
            // check.
            match &command {
                ServicesCommands::List
                | ServicesCommands::Report { .. }
                | ServicesCommands::Didcomm {
                    command:
                        DidcommCommands::Drain {
                            command: DrainCommands::List,
                        },
                } => {}
                _ => check_seal(&cli.config).await,
            }
            let result = match command {
                ServicesCommands::List => services_cli::run_services_list(cli.config).await,
                ServicesCommands::Rest { command } => match command {
                    RestCommands::Enable { url } => {
                        services_cli::run_services_rest_enable(cli.config, url).await
                    }
                    RestCommands::Update { url } => {
                        services_cli::run_services_rest_update(cli.config, url).await
                    }
                    RestCommands::Disable => {
                        services_cli::run_services_rest_disable(cli.config).await
                    }
                    RestCommands::Rollback => {
                        services_cli::run_services_rest_rollback(cli.config).await
                    }
                },
                ServicesCommands::Didcomm { command } => match command {
                    DidcommCommands::Enable {
                        mediator_did,
                        force,
                        handshake_timeout,
                    } => {
                        services_cli::run_services_didcomm_enable(
                            cli.config,
                            mediator_did,
                            force,
                            handshake_timeout,
                        )
                        .await
                    }
                    DidcommCommands::Update {
                        new_mediator_did,
                        drain_ttl,
                        force,
                        handshake_timeout,
                    } => {
                        services_cli::run_services_didcomm_update(
                            cli.config,
                            new_mediator_did,
                            drain_ttl,
                            force,
                            handshake_timeout,
                        )
                        .await
                    }
                    DidcommCommands::Disable { drain_ttl } => {
                        services_cli::run_services_didcomm_disable(cli.config, drain_ttl).await
                    }
                    DidcommCommands::Rollback { drain_ttl } => {
                        services_cli::run_services_didcomm_rollback(cli.config, drain_ttl).await
                    }
                    DidcommCommands::Drain { command } => match command {
                        DrainCommands::List => {
                            services_cli::run_services_didcomm_drain_list(cli.config).await
                        }
                        DrainCommands::Cancel { mediator_did } => {
                            services_cli::run_services_didcomm_drain_cancel(
                                cli.config,
                                mediator_did,
                            )
                            .await
                        }
                    },
                },
                ServicesCommands::Report {
                    since,
                    until,
                    format,
                } => services_cli::run_services_report(cli.config, since, until, format).await,
            };
            if let Err(e) = result {
                // services_cli already prints typed VtaError via
                // print_cli_error and surfaces a SilentExit so we
                // don't double-print. Other error kinds get a
                // simple format here.
                let s = e.to_string();
                if !s.is_empty() {
                    eprintln!("Error: {s}");
                }
                std::process::exit(1);
            }
        }
        None => {
            let config = match AppConfig::load(cli.config) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Error: {e}");
                    eprintln!();
                    eprintln!("To set up a new VTA instance, run:");
                    eprintln!("  vta setup");
                    eprintln!();
                    eprintln!("Or specify a config file:");
                    eprintln!("  vta --config <path>");
                    std::process::exit(1);
                }
            };

            init_tracing(&config);

            let store = store::Store::open(&config.store).expect("failed to open store");
            let seed_store: Arc<dyn keys::seed_store::SeedStore> =
                Arc::from(create_seed_store(&config).expect("failed to create seed store"));

            if let Err(e) = server::run(
                config,
                store,
                seed_store,
                None, // no storage encryption (non-TEE mode)
                None, // no TEE context (use vta-enclave for TEE mode)
                cli.allow_degraded,
            )
            .await
            {
                tracing::error!("server error: {e}");
                std::process::exit(1);
            }
        }
    }
}

/// Dispatch a legacy `WebvhCommands` value through `webvh_cli`. Used
/// by both the new `vta did-mgmt …` surface (after `From<DidMgmtCommands>`
/// conversion) and the legacy `vta webvh …` shim. Drop together with
/// the legacy `Webvh` enum in the next minor release.
#[cfg(feature = "webvh")]
async fn run_webvh_dispatch(config_path: Option<PathBuf>, command: WebvhCommands) {
    // Read-only commands skip the seal check; everything else writes.
    match &command {
        WebvhCommands::ListServers
        | WebvhCommands::ListDids { .. }
        | WebvhCommands::DidLog { .. } => {}
        _ => check_seal(&config_path).await,
    }
    let result = match command {
        WebvhCommands::AddServer { id, did, label } => {
            webvh_cli::run_add_server(config_path, id, did, label).await
        }
        WebvhCommands::ListServers => webvh_cli::run_list_servers(config_path).await,
        WebvhCommands::UpdateServer { id, label } => {
            webvh_cli::run_update_server(config_path, id, label).await
        }
        WebvhCommands::RemoveServer { id } => webvh_cli::run_remove_server(config_path, id).await,
        WebvhCommands::CreateDid {
            context,
            server,
            path,
            label,
            portable,
            mediator_service,
            services,
            pre_rotation,
            print_mnemonic,
        } => {
            webvh_cli::run_create_did(
                config_path,
                context,
                server,
                path,
                label,
                portable,
                mediator_service,
                services,
                pre_rotation,
                print_mnemonic,
            )
            .await
        }
        WebvhCommands::ListDids { context, server } => {
            webvh_cli::run_list_dids(config_path, context, server).await
        }
        WebvhCommands::DeleteDid { did } => webvh_cli::run_delete_did(config_path, did).await,
        WebvhCommands::DidLog { did, out } => webvh_cli::run_did_log(config_path, did, out).await,
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
            webvh_cli::run_edit_did(
                config_path,
                did,
                document,
                options_file,
                pre_rotation,
                ttl,
                watchers,
                no_watchers,
                label,
                no_confirm,
            )
            .await
        }
        WebvhCommands::RegisterDid { did, server, force } => {
            webvh_cli::run_register_did(config_path, did, server, force).await
        }
    };
    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn print_banner() {
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{cyan} ██╗   ██╗{magenta}████████╗{yellow} █████╗{reset}
{cyan} ██║   ██║{magenta}╚══██╔══╝{yellow}██╔══██╗{reset}
{cyan} ██║   ██║{magenta}   ██║   {yellow}███████║{reset}
{cyan} ╚██╗ ██╔╝{magenta}   ██║   {yellow}██╔══██║{reset}
{cyan}  ╚████╔╝ {magenta}   ██║   {yellow}██║  ██║{reset}
{cyan}   ╚═══╝  {magenta}   ╚═╝   {yellow}╚═╝  ╚═╝{reset}
{dim}  Verifiable Trust Agent v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

/// Check if the VTA is sealed; exit with an error if so.
/// Called before any CLI command that modifies state.
async fn check_seal(config_path: &Option<PathBuf>) {
    let config = match AppConfig::load(config_path.clone()) {
        Ok(c) => c,
        Err(_) => return, // Config not loadable — let the actual command handle it
    };
    let store = match store::Store::open(&config.store) {
        Ok(s) => s,
        Err(_) => return, // Store not openable — let the actual command handle it
    };
    if let Err(e) = seal::require_unsealed(&store).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

/// Bootstrap the first super admin and seal the VTA.
async fn run_bootstrap_admin(
    config_path: Option<PathBuf>,
    did: String,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = store::Store::open(&config.store)?;
    let acl_ks = store.keyspace(crate::keyspaces::ACL)?;

    // Check if already sealed
    if let Some(existing) = seal::get_seal(&acl_ks).await? {
        eprintln!(
            "VTA is already sealed (by {} on {}).",
            existing.sealed_by,
            existing
                .sealed_at
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S %:z")
        );
        eprintln!("Cannot bootstrap again. Manage admins via the REST API or DIDComm.");
        std::process::exit(1);
    }

    // Check no existing super admins
    let entries = acl::list_acl_entries(&acl_ks).await?;
    let existing_super_admins: Vec<_> = entries
        .iter()
        .filter(|e| e.role == acl::Role::Admin && e.allowed_contexts.is_empty())
        .collect();

    if !existing_super_admins.is_empty() {
        eprintln!(
            "WARNING: {} existing super admin(s) found:",
            existing_super_admins.len()
        );
        for admin in &existing_super_admins {
            eprintln!(
                "  - {} ({})",
                admin.did,
                admin.label.as_deref().unwrap_or("no label")
            );
        }
        eprintln!();
        eprintln!("Proceeding will add another super admin and seal the VTA.");
        eprintln!("Press Ctrl+C to cancel, or Enter to continue...");
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf)?;
    }

    // Create the super admin ACL entry
    // Empty contexts = super admin
    let entry =
        acl::AclEntry::new(did.clone(), acl::Role::Admin, "cli:bootstrap-admin").with_label(label);
    acl::store_acl_entry(&acl_ks, &entry).await?;

    // Seal the VTA
    let seal_record = seal::seal(&acl_ks, &did).await?;

    store.persist().await?;

    eprintln!();
    eprintln!("=== VTA Bootstrapped and Sealed ===");
    eprintln!();
    eprintln!("  Admin DID: {}", did);
    eprintln!(
        "  Sealed at: {}",
        seal_record
            .sealed_at
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S %:z")
    );
    eprintln!();
    eprintln!("  The VTA is now sealed. Offline CLI commands that modify state are disabled.");
    eprintln!("  All management must go through the authenticated REST API or DIDComm.");
    eprintln!();
    eprintln!("  To start the VTA server:");
    eprintln!("    vta --config config.toml");
    eprintln!();

    Ok(())
}

// init_tracing is now in vta_service::init_tracing (lib.rs)

/// Print the VTA's identity and service settings from `config.toml`.
///
/// Explicitly does NOT open the data store, so it works while the VTA
/// process is running. Also doesn't resolve DIDs or touch the network —
/// this is the quick, safe "what did setup write?" command.
/// `vta step-up` — inspect and edit the AAL2 step-up policy in the config
/// file (offline break-glass; changes take effect on the next daemon start).
fn run_step_up(
    config_path: Option<PathBuf>,
    command: StepUpCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    use vti_common::auth::step_up::{StepUpFloor, StepUpMode};

    fn parse_mode(s: &str) -> Result<StepUpMode, Box<dyn std::error::Error>> {
        Ok(match s {
            "none" => StepUpMode::None,
            "self" => StepUpMode::SelfApprove,
            "delegated" => StepUpMode::Delegated,
            "delegated-any" => StepUpMode::DelegatedAny,
            other => {
                return Err(format!(
                    "unknown mode '{other}' (expected none|self|delegated|delegated-any)"
                )
                .into());
            }
        })
    }
    fn mode_token(m: StepUpMode) -> &'static str {
        match m {
            StepUpMode::None => "none",
            StepUpMode::SelfApprove => "self",
            StepUpMode::Delegated => "delegated",
            StepUpMode::DelegatedAny => "delegated-any",
        }
    }

    match command {
        StepUpCommands::Show => {
            let config = AppConfig::load(config_path)?;
            let p = &config.auth.step_up;
            println!();
            println!(
                "Step-up policy: {}",
                if p.enabled {
                    "ENABLED"
                } else {
                    "NOT ENFORCED (AAL1 everywhere)"
                }
            );
            if p.floors.is_empty() {
                println!("  (no floors configured)");
            } else {
                for f in &p.floors {
                    let carve = if f.allow_aal1_if_non_escalating {
                        "  [allow-aal1-if-non-escalating]"
                    } else {
                        ""
                    };
                    println!("  {:<18} {}{}", f.operation, mode_token(f.mode), carve);
                }
            }
            println!();
        }
        StepUpCommands::Enable => {
            let mut config = AppConfig::load(config_path)?;
            config.auth.step_up.enabled = true;
            let nothing_gated = config
                .auth
                .step_up
                .floors
                .iter()
                .all(|f| !f.mode.requires_aal2());
            config.save()?;
            println!("Step-up enforcement ENABLED. Restart the daemon to apply.");
            if nothing_gated {
                println!("Note: no floor requires AAL2 yet, so nothing is gated. Use `set-floor`.");
            }
        }
        StepUpCommands::Disable => {
            let mut config = AppConfig::load(config_path)?;
            config.auth.step_up.enabled = false;
            config.save()?;
            println!(
                "Step-up enforcement DISABLED — AAL1 everywhere. Restart the daemon to apply."
            );
        }
        StepUpCommands::SetFloor {
            operation,
            mode,
            allow_aal1_if_non_escalating,
        } => {
            let parsed = parse_mode(&mode)?;
            let mut config = AppConfig::load(config_path)?;
            let floors = &mut config.auth.step_up.floors;
            floors.retain(|f| f.operation != operation);
            floors.push(StepUpFloor {
                operation: operation.clone(),
                mode: parsed,
                allow_aal1_if_non_escalating,
            });
            let enabled = config.auth.step_up.enabled;
            config.save()?;
            println!(
                "Floor set: {operation} -> {mode}{}.",
                if allow_aal1_if_non_escalating {
                    " (allow-aal1-if-non-escalating)"
                } else {
                    ""
                }
            );
            if !enabled {
                println!("Note: step-up is not enabled; run `vta step-up enable` to enforce.");
            }
        }
        StepUpCommands::RemoveFloor { operation } => {
            let mut config = AppConfig::load(config_path)?;
            let before = config.auth.step_up.floors.len();
            config
                .auth
                .step_up
                .floors
                .retain(|f| f.operation != operation);
            if config.auth.step_up.floors.len() == before {
                println!("No floor for '{operation}' — nothing to remove.");
            } else {
                config.save()?;
                println!("Removed floor for '{operation}'.");
            }
        }
    }
    Ok(())
}

fn run_config_show(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;

    const BOLD: &str = "\x1b[1m";
    const CYAN: &str = "\x1b[36m";
    const DIM: &str = "\x1b[2m";
    const RESET: &str = "\x1b[0m";

    fn line(label: &str, value: Option<&str>) {
        match value {
            Some(v) if !v.is_empty() => {
                println!("  {CYAN}{:<13}{RESET} {v}", label);
            }
            _ => {
                println!("  {CYAN}{:<13}{RESET} {DIM}(not set){RESET}", label);
            }
        }
    }

    println!();
    println!("{BOLD}VTA configuration{RESET}");
    println!();
    line("Name", config.vta_name.as_deref());
    line("VTA DID", config.vta_did.as_deref());
    line("Public URL", config.public_url.as_deref());

    let mut svc_list = Vec::new();
    if config.services.rest {
        svc_list.push("REST");
    }
    if config.services.didcomm {
        svc_list.push("DIDComm");
    }
    let svc_display = if svc_list.is_empty() {
        "(none)".to_string()
    } else {
        svc_list.join(", ")
    };
    line("Services", Some(&svc_display));
    line(
        "Listen",
        Some(&format!("{}:{}", config.server.host, config.server.port)),
    );

    if let Some(msg) = &config.messaging {
        line("Mediator DID", Some(&msg.mediator_did));
        if !msg.mediator_url.is_empty() {
            line("Mediator URL", Some(&msg.mediator_url));
        }
    } else {
        line("Mediator DID", None);
    }

    line(
        "Config file",
        Some(&config.config_path.display().to_string()),
    );
    line(
        "Data store",
        Some(&config.store.data_dir.display().to_string()),
    );
    println!();
    Ok(())
}

/// `vta auth sign-challenge` — sign the 32-byte challenge from `vta unseal`
/// using the admin's Ed25519 private key, loaded from the local fjall
/// keystore. The cold-start companion to `pnm auth sign-challenge` for
/// operators who can't reach PNM yet (no network, no PNM auth setup).
///
/// Daemon must be stopped — fjall holds an exclusive lock per data dir.
/// Only `did:key:` admin DIDs are supported (matches the verifier in
/// `seal::verify_challenge_signature`).
async fn auth_sign_challenge(
    config: &AppConfig,
    did: &str,
    challenge_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use ed25519_dalek::Signer;
    use keys::{KeyRecord, KeyType};

    if !did.starts_with("did:key:") {
        return Err(format!(
            "vta auth sign-challenge only supports did:key admin DIDs (got: {did}). \
             For other DID methods, unseal via the REST API with a running VTA."
        )
        .into());
    }

    // 32-byte challenge from `vta unseal`.
    let challenge_bytes: [u8; 32] = hex::decode(challenge_hex.trim())
        .map_err(|e| format!("challenge is not valid hex: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("challenge must be 32 bytes (got {} bytes)", v.len()))?;

    // For `did:key:zXxx` the key_id is `did:key:zXxx#zXxx` (the
    // verifying key's multibase IS the DID-suffix). Construct
    // directly rather than scanning the keyspace.
    let multibase = did.strip_prefix("did:key:").unwrap();
    let key_id = format!("{did}#{multibase}");

    let store = store::Store::open(&config.store)?;
    let keys_ks = store.keyspace(crate::keyspaces::KEYS)?;
    let record: KeyRecord = keys_ks
        .get(keys::store_key(&key_id))
        .await?
        .ok_or_else(|| {
            format!(
                "no key record found for `{did}` in this VTA's keystore. \
                 If the admin DID was minted on a different host, run \
                 `pnm auth sign-challenge {challenge_hex}` from that host instead."
            )
        })?;

    if record.key_type != KeyType::Ed25519 {
        return Err(format!(
            "key for `{did}` is not Ed25519 (found: {:?}); cannot sign unseal challenge",
            record.key_type
        )
        .into());
    }

    let seed_store = create_seed_store(config).map_err(|e| e.to_string())?;
    let seed = load_seed_bytes(&keys_ks, &*seed_store, record.seed_id).await?;

    let bip32 = ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| format!("BIP-32 root key derivation failed: {e}"))?;
    let derivation_path: DerivationPath = record
        .derivation_path
        .parse()
        .map_err(|e| format!("invalid stored derivation path: {e}"))?;
    let derived = bip32
        .derive(&derivation_path)
        .map_err(|e| format!("key derivation failed: {e}"))?;

    let signing_key = SigningKey::from_bytes(derived.signing_key.as_bytes());
    let signature = signing_key.sign(&challenge_bytes);

    eprintln!();
    eprintln!("  Signature (hex):");
    println!("{}", hex::encode(signature.to_bytes()));
    eprintln!();
    eprintln!("  Paste the signature above into the `vta unseal` prompt.");
    eprintln!();

    Ok(())
}

async fn export_admin(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = store::Store::open(&config.store)?;
    let acl_ks = store.keyspace(crate::keyspaces::ACL)?;
    let keys_ks = store.keyspace(crate::keyspaces::KEYS)?;
    let seed_store = create_seed_store(&config)?;

    let vta_did = config.vta_did.as_deref().unwrap_or("(not set)");

    // Find admin ACL entries
    let entries = acl::list_acl_entries(&acl_ks).await?;
    let admins: Vec<_> = entries
        .iter()
        .filter(|e| e.role == acl::Role::Admin)
        .collect();

    if admins.is_empty() {
        eprintln!("No admin entries found in ACL.");
        return Ok(());
    }

    eprintln!("VTA DID: {vta_did}");
    if let Some(msg) = &config.messaging {
        eprintln!("Mediator DID: {}", msg.mediator_did);
    }
    eprintln!();

    for admin in &admins {
        eprintln!("Admin DID: {}", admin.did);
        if let Some(label) = &admin.label {
            eprintln!("  Label: {label}");
        }

        // For did:key admins, reconstruct the credential
        if admin.did.starts_with("did:key:") {
            match reconstruct_credential(&*seed_store, &admin.did, vta_did, &keys_ks).await {
                Ok(credential) => {
                    eprintln!();
                    eprintln!("  Credential:");
                    eprintln!("  {credential}");
                }
                Err(e) => {
                    eprintln!("  Could not reconstruct credential: {e}");
                }
            }
        }
        eprintln!();
    }

    Ok(())
}

/// Re-derive the admin private key from BIP-32 seed and build the credential bundle.
async fn reconstruct_credential(
    seed_store: &dyn keys::seed_store::SeedStore,
    admin_did: &str,
    vta_did: &str,
    keys_ks: &store::KeyspaceHandle,
) -> Result<String, Box<dyn std::error::Error>> {
    // The did:key fragment is {did}#{multibase_pubkey}
    let multibase_pubkey = admin_did.strip_prefix("did:key:").unwrap();
    let key_id = format!("{admin_did}#{multibase_pubkey}");

    // Look up the key record to get the derivation path
    let record: keys::KeyRecord = keys_ks
        .get(keys::store_key(&key_id))
        .await?
        .ok_or("admin key record not found in store")?;

    // Load seed for this key's generation
    let seed = load_seed_bytes(keys_ks, seed_store, record.seed_id).await?;

    // Re-derive the private key
    let root = ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| format!("failed to create BIP-32 root key: {e}"))?;
    let derivation_path: DerivationPath = record
        .derivation_path
        .parse()
        .map_err(|e| format!("invalid derivation path: {e}"))?;
    let derived = root
        .derive(&derivation_path)
        .map_err(|e| format!("key derivation failed: {e}"))?;

    let signing_key = SigningKey::from_bytes(derived.signing_key.as_bytes());
    let private_key_multibase = multibase::encode(Base::Base58Btc, signing_key.as_bytes());

    let bundle = serde_json::json!({
        "did": admin_did,
        "privateKeyMultibase": private_key_multibase,
        "vtaDid": vta_did,
    });
    let bundle_json = serde_json::to_string(&bundle)?;
    Ok(BASE64.encode(bundle_json.as_bytes()))
}
