//! Non-interactive setup (`vta setup --from <file>`).
//!
//! [`WizardInputs`] is the canonical TOML schema. Field-level doc
//! comments are the source of truth for the schema — there is no
//! separate spec doc, by design. [`run_setup_from_file`] reads a TOML
//! file into `WizardInputs` and hands off to [`apply_inputs`], which
//! mirrors [`super::interactive::run_setup_wizard`] step-for-step but
//! with no prompts and no display of generated key material.
//!
//! Design choices (stable; change with care):
//! - Mnemonic input is intentionally absent. Setup always generates
//!   fresh. Operators who need a known seed should run
//!   `vta keys rotate-seed --mnemonic <phrase>` post-setup.
//! - VTA DID and mediator DID creation only support "simple mode"
//!   (operations layer with VTA-managed keys). The interactive
//!   wizard's advanced options (template-from-file, pre-signed log
//!   import, user-specified key IDs) are out of scope here —
//!   operators who need those should use interactive setup.
//! - `admin_did`, when set, runs the same logic as `vta
//!   bootstrap-admin` at the end of apply: writes a super-admin ACL
//!   row and seals the VTA atomically with the rest of setup.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use chrono::Utc;
use didwebvh_rs::url::WebVHURL;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

use crate::config::{
    AppConfig, AuditConfig, AuthConfig, LogConfig, MessagingConfig, SecretsConfig, ServerConfig,
    ServicesConfig, StoreConfig,
};
use crate::contexts::store_context;
use crate::keys::seed_store::{SeedStore, create_seed_store};
use crate::keys::seeds::{SeedRecord, save_seed_record, set_active_seed_id};
use crate::operations;
use crate::operations::did_webvh::CreateDidWebvhParams;
use crate::store::{KeyspaceHandle, Store};
use crate::webvh_cli::cli_super_admin;

use super::{SetupUi, SilentUi, create_seed_context, generate_mnemonic_silent};

/// TOML schema for `vta setup --from <file>`.
///
/// `Serialize` is derived (alongside `Deserialize`) so the interactive wizard's
/// golden test can assert that prompt-gathered inputs and the equivalent TOML
/// deserialize to structurally-identical `WizardInputs` (compared via
/// `serde_json::to_value`). Production never serializes this type.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WizardInputs {
    /// Output path for the generated `config.toml`. The setup wizard refuses
    /// to overwrite an existing file; delete it first if you want to re-run.
    pub config_path: PathBuf,

    /// Optional human-readable name for this VTA. Surfaced in `vta config
    /// show` and `pnm setup`.
    #[serde(default)]
    pub vta_name: Option<String>,

    /// Public URL the VTA will advertise (e.g. `https://trust.example.com`).
    /// Used as the `VTARest` service endpoint when minting the VTA's DID.
    /// Optional — omit if this VTA is DIDComm-only or behind a private
    /// network.
    #[serde(default)]
    pub public_url: Option<String>,

    /// Where the on-disk fjall store lives.
    pub data_dir: PathBuf,

    /// What to do if `data_dir` already exists. Defaults to `error` (fail
    /// fast); set to `delete` for CI re-run patterns.
    #[serde(default)]
    pub data_dir_exists: ExistingDataDirPolicy,

    /// Which services to enable. Defaults to both REST and DIDComm.
    #[serde(default = "default_services")]
    pub services: ServicesConfig,

    /// HTTP server bind. Defaults to `0.0.0.0:8100`.
    #[serde(default)]
    pub server: ServerConfig,

    /// Logging. Defaults to text format at info level.
    #[serde(default)]
    pub log: LogConfig,

    /// Seed-store backend. Required — there is no implicit default because
    /// the choice is security-sensitive (each backend has different threat
    /// model and durability guarantees).
    pub secrets: SecretsBackendInput,

    /// DIDComm mediator configuration. Defaults to `skip`. Only meaningful
    /// when `services.didcomm = true`.
    #[serde(default)]
    pub messaging: MessagingInput,

    /// VTA DID configuration. Defaults to `skip`. A VTA without a DID can
    /// still serve REST traffic but cannot participate in DIDComm or sign
    /// VCs.
    #[serde(default)]
    pub vta_did: VtaDidInput,

    /// If set, after base setup completes the wizard runs the equivalent of
    /// `vta bootstrap-admin --did <X>` — writes a super-admin ACL row and
    /// seals the VTA atomically. Failure here aborts setup before declaring
    /// success.
    #[serde(default)]
    pub admin_did: Option<String>,

    /// Optional label attached to the seeded admin's ACL row.
    #[serde(default)]
    pub admin_label: Option<String>,

    /// WebSocket URL of a remote DID resolver (e.g.
    /// `ws://resolver.example.com/did/v1/ws`). When set, the VTA uses
    /// the remote resolver instead of resolving DIDs locally. Required
    /// for TEE network mode where DID resolution is bridged to a parent-
    /// side `affinidi-did-resolver-cache-server` over vsock; useful for
    /// any deployment that wants to share a resolver-cache across VTAs.
    #[serde(default)]
    pub resolver_url: Option<String>,

    /// Audit-log retention. Defaults to 28 days; compliance-driven
    /// deployments often want 90 or 365.
    #[serde(default)]
    pub audit: AuditConfig,

    /// Enterprise staff provisioning. For each entry the wizard creates a
    /// context, applies its initial `ContextPolicy`, and seeds a
    /// context-scoped ACL row — the VTA *user*, bounded by the policy. The
    /// *owner* is the super-admin `admin_did` above. Empty by default (a
    /// personal VTA where owner and user are the same DID).
    #[serde(default)]
    pub staff: Vec<StaffProvision>,
}

/// One enterprise staff member to provision at setup: a context, its initial
/// policy, and a context-scoped ACL entry scoped to it (separation of duty —
/// the owner sets the guardrail, the staff member works within it).
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StaffProvision {
    /// The staff member's DID (the VTA *user*) — gets a context-scoped ACL row.
    pub did: String,
    /// Context to create and scope the staff member to (a kebab-case slug,
    /// e.g. `staff` or `sales`).
    pub context: String,
    /// Human label for the context and the ACL row.
    #[serde(default)]
    pub label: Option<String>,
    /// Role for the staff entry (admin / initiator / application / reader /
    /// monitor). Defaults to `application` — use keys, present, and vault
    /// within the context, but never manage it.
    #[serde(default)]
    pub role: Option<String>,
    /// Initial `ContextPolicy` guardrail for the context (trusted verifiers,
    /// presentable types, signable keys, export, quotas). Omit for an
    /// unrestricted context the owner tightens later.
    #[serde(default)]
    pub context_policy: Option<vta_sdk::context_policy::ContextPolicy>,
}

fn default_services() -> ServicesConfig {
    ServicesConfig {
        rest: true,
        didcomm: true,
        // WebAuthn defaults off — operators flip this on via
        // `services webauthn enable`, and the existing `services.rest`
        // continues to be the discoverable HTTP surface until they do.
        webauthn: false,
        // TSP defaults off — operators enable it via `services tsp enable`
        // (or the setup wizard once it learns TSP). DIDComm stays default.
        tsp: false,
    }
}

#[derive(Debug, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExistingDataDirPolicy {
    /// Refuse to proceed if `data_dir` already exists.
    #[default]
    Error,
    /// Recursively delete `data_dir` before initializing the store.
    Delete,
}

/// Per-backend seed-store config. The `backend` discriminator selects the
/// variant; required fields per variant are validated at deserialization
/// time via `serde(deny_unknown_fields)`.
///
/// `large_enum_variant` is suppressed deliberately: the `Vault` arm
/// carries ~14 KV-v2 + auth-method fields, which dominates the
/// stack size of an `Option<SecretsBackendInput>`. The enum is
/// parsed exactly once at setup time from a TOML file and never
/// stored on a hot path, so the per-variant size footprint isn't
/// load-bearing — boxing just to mollify the lint would add
/// indirection for no operational benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretsBackendInput {
    /// OS keyring (libsecret / Keychain / Credential Vault). The
    /// `service` field defaults to `"vta"` but should be unique per VTA
    /// instance running on the same host.
    Keyring {
        #[serde(default = "default_keyring_service")]
        service: String,
    },
    /// Hex-encoded seed embedded in `config.toml`. **Not recommended** —
    /// the config file becomes a secret. Compiled in only when the
    /// `config-seed` feature is enabled.
    ConfigSeed,
    /// AWS Secrets Manager. `region` defaults to the SDK's default
    /// resolution chain.
    Aws {
        #[serde(default)]
        region: Option<String>,
        secret_name: String,
    },
    /// GCP Secret Manager.
    Gcp {
        project: String,
        secret_name: String,
    },
    /// Azure Key Vault.
    Azure {
        vault_url: String,
        secret_name: String,
    },
    /// HashiCorp Vault (KV v2). Authenticates via Kubernetes (default),
    /// AppRole, or a static token. The seed is stored at
    /// `<kv_mount>/<secret_path>` in the configured field (default
    /// `seed`). See `docs/02-vta/secret-backends.md` for the
    /// auth-method matrix.
    Vault {
        /// Vault server URL (e.g. `https://vault.example.com:8200`).
        addr: String,
        /// KV v2 secret path under the mount, e.g. `vta/master-seed`.
        secret_path: String,
        /// KV v2 mount path. Defaults to `secret`.
        #[serde(default = "default_vault_kv_mount")]
        kv_mount: String,
        /// Field name within the KV v2 secret holding the hex-encoded
        /// seed. Defaults to `seed`.
        #[serde(default = "default_vault_secret_key")]
        secret_key: String,
        /// Vault Enterprise namespace, if any.
        #[serde(default)]
        namespace: Option<String>,
        /// Auth method: `kubernetes` (default), `token`, or `approle`.
        #[serde(default = "default_vault_auth_method")]
        auth_method: String,
        /// Kubernetes auth role name (when `auth_method = "kubernetes"`).
        #[serde(default)]
        k8s_role: Option<String>,
        /// Kubernetes auth mount path. Defaults to `kubernetes`.
        #[serde(default = "default_vault_k8s_mount")]
        k8s_mount: String,
        /// File holding the ServiceAccount JWT presented to Vault.
        /// Defaults to the kubelet-mounted projected volume path.
        #[serde(default = "default_vault_k8s_jwt_path")]
        k8s_jwt_path: String,
        /// Static token (when `auth_method = "token"`). Prefer the
        /// `VAULT_TOKEN` env var over hard-coding here.
        #[serde(default)]
        token: Option<String>,
        /// AppRole role_id (when `auth_method = "approle"`).
        #[serde(default)]
        approle_role_id: Option<String>,
        /// AppRole secret_id (when `auth_method = "approle"`).
        #[serde(default)]
        approle_secret_id: Option<String>,
        /// AppRole mount path. Defaults to `approle`.
        #[serde(default = "default_vault_approle_mount")]
        approle_mount: String,
        /// Skip TLS certificate verification — dev/test only.
        #[serde(default)]
        skip_verify: bool,
    },
    /// Kubernetes `Secret`. The seed is stored hex-encoded under
    /// `secret_key` (default `seed`) in a namespaced `Secret`.
    /// Credentials come from the in-cluster ServiceAccount or a local
    /// kubeconfig. Compiled in only when the `k8s-secrets` feature is
    /// enabled.
    Kubernetes {
        /// Name of the `Secret` resource.
        secret_name: String,
        /// Namespace the `Secret` lives in. When omitted, the
        /// in-cluster ServiceAccount namespace (or kubeconfig context
        /// namespace) is used, falling back to `default`.
        #[serde(default)]
        namespace: Option<String>,
        /// Key within the `Secret`'s `data` map. Defaults to `seed`.
        #[serde(default = "default_k8s_secret_key")]
        secret_key: String,
    },
    /// Plaintext file under `data_dir`. **Not recommended** — for dev only.
    Plaintext,
}

fn default_keyring_service() -> String {
    "vta".into()
}

pub(crate) fn default_vault_kv_mount() -> String {
    "secret".into()
}

pub(crate) fn default_vault_secret_key() -> String {
    "seed".into()
}

pub(crate) fn default_vault_auth_method() -> String {
    "kubernetes".into()
}

pub(crate) fn default_vault_k8s_mount() -> String {
    "kubernetes".into()
}

pub(crate) fn default_vault_k8s_jwt_path() -> String {
    "/var/run/secrets/kubernetes.io/serviceaccount/token".into()
}

pub(crate) fn default_k8s_secret_key() -> String {
    "seed".into()
}

pub(crate) fn default_vault_approle_mount() -> String {
    "approle".into()
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MessagingInput {
    /// No DIDComm mediator. The VTA will not participate in DIDComm flows.
    #[default]
    Skip,
    /// Point at a mediator DID that already exists. ATM resolves the
    /// endpoint from the DID document.
    ///
    /// `mediator_host` is the *external* hostname the VTA should resolve
    /// to when dialling the mediator's DIDComm endpoint. Used in TEE
    /// network mode where outbound traffic is bridged via a vsock proxy
    /// on the parent EC2 instance and the proxy needs the real upstream
    /// hostname for SNI / TLS validation. Leave unset for the standard
    /// case where the URL in the resolved DID document is reachable
    /// directly.
    Existing {
        did: String,
        #[serde(default)]
        mediator_host: Option<String>,
        /// Automatically provision a per-DID allow-all ACL on the mediator
        /// after the DIDComm connection is established. Defaults to `false`.
        #[serde(default)]
        setup_acl: bool,
    },
    /// Mint a new mediator DID using the built-in `didcomm-mediator`
    /// template. The mediator gets its own trust context (default name
    /// `"mediator"`).
    ///
    /// `url` is the DIDComm service endpoint — what clients dial to send
    /// messages. It becomes the `URL` template var and lands in the
    /// rendered DID document's `serviceEndpoint.uri`.
    ///
    /// `webvh_url` is where the mediator's `did.jsonl` is published; it
    /// determines the `did:webvh:<scid>:host:path` identifier itself.
    /// Optional — defaults to `url` for the common case where DIDComm
    /// traffic and DID hosting share a host. Specify it explicitly when
    /// the mediator endpoint and the DID document live on different
    /// hosts (e.g. DIDComm at `https://mediator.example.com`, DID doc
    /// at `https://trust.example.com/dids/mediator`).
    ///
    /// `mediator_host` — see `Existing::mediator_host`.
    ///
    /// `ws_url` — the mediator's WebSocket endpoint, advertised in the
    /// `didcomm-mediator` template's `#service` block alongside the HTTP
    /// DIDComm endpoint. Optional: when omitted the wizard derives it
    /// from `url` (`http`→`ws` / `https`→`wss`, trailing slash trimmed,
    /// `/ws` appended) — the canonical mediator convention. Set it
    /// explicitly only when your reverse proxy routes the WS upgrade to a
    /// different host or path; an explicit value is used verbatim. This
    /// mirrors the interactive wizard's overridable WS prompt.
    ///
    /// `template_vars` is an escape hatch for overriding optional
    /// `didcomm-mediator` template variables (`ROUTING_KEYS`, `ACCEPT`,
    /// `WEBVH_SERVER`). The `URL` var is always set by the wizard from
    /// `url` and cannot be overridden here; `WS_URL` comes from the
    /// `ws_url` field above (or its `url`-derived default), so setting
    /// `WS_URL` in `template_vars` has no effect.
    ///
    /// `setup_acl` — when `true`, the VTA automatically provisions a
    /// per-DID allow-all ACL on the mediator after connecting. Required
    /// when the mediator uses `ExplicitAllow` mode. Defaults to `false`.
    CreateMediator {
        #[serde(default = "default_mediator_context")]
        context: String,
        url: String,
        #[serde(default)]
        ws_url: Option<String>,
        #[serde(default)]
        webvh_url: Option<String>,
        #[serde(default)]
        mediator_host: Option<String>,
        #[serde(default)]
        template_vars: HashMap<String, serde_json::Value>,
        #[serde(default)]
        setup_acl: bool,
    },
}

fn default_mediator_context() -> String {
    "mediator".into()
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VtaDidInput {
    /// No VTA DID. REST works; DIDComm and VC issuance do not.
    #[default]
    Skip,
    /// Use a DID that already exists.
    Existing { did: String },
    /// Mint a new `did:key` for the VTA. Uses BIP-32-derived Ed25519
    /// keys from the active seed — same derivation scheme as `did:webvh`
    /// but no external hosting needed. Ideal for local development and
    /// deployments that don't need webvh's portability/rotation.
    CreateDidKey,
    /// Mint a new `did:webvh` for the VTA. Defaults to the operations
    /// layer's "simple mode" (VTA generates keys + document); the optional
    /// `did_document_file` / `did_log_file` / `signing_key_id` fields select
    /// the advanced modes the interactive wizard exposes (see their docs).
    CreateWebvh {
        /// Hosting URL for the DID document, e.g.
        /// `https://trust.example.com/dids/vta`.
        url: String,
        /// Whether the DID is portable (can move to a different domain
        /// later). Default true. Ignored when `did_log_file` is set (the
        /// pre-signed log already fixes portability).
        #[serde(default = "default_true")]
        portable: bool,
        /// Number of pre-rotation keys to publish (defence against key
        /// compromise). Default 1; recommended 1–3. Ignored when
        /// `did_log_file` is set.
        #[serde(default = "default_pre_rotation_count")]
        pre_rotation_count: u32,
        /// Advanced: path to a DID-document JSON template file. The VTA still
        /// mints the keys and fills the document's key material; this only
        /// supplies the document *shape*. Mutually exclusive with
        /// `did_log_file` and `signing_key_id`.
        #[serde(default)]
        did_document_file: Option<PathBuf>,
        /// Advanced: path to a complete, pre-signed `did.jsonl` log to import
        /// verbatim. Mutually exclusive with `did_document_file` and
        /// `signing_key_id`; `portable` / `pre_rotation_count` are ignored.
        #[serde(default)]
        did_log_file: Option<PathBuf>,
        /// Advanced: id of an existing imported key to use as the signing
        /// verification method instead of minting a fresh one. Mutually
        /// exclusive with `did_document_file` and `did_log_file`.
        #[serde(default)]
        signing_key_id: Option<String>,
        /// Advanced: id of an existing imported key to use as the
        /// key-agreement verification method. Requires `signing_key_id`.
        #[serde(default)]
        ka_key_id: Option<String>,
    },
}

/// The interactive wizard's advanced webvh-DID options, lifted into the
/// shared engine. All-`None` (`Default`) is the common "simple mode" where the
/// VTA mints keys and renders the document itself — the only mode the mediator
/// DID path uses. The `CreateDidWebvhParams` layer enforces that
/// `did_document` / `did_log` / `template` are mutually exclusive; setup
/// validation (`validate_inputs`) rejects conflicting combinations up front.
#[derive(Default)]
struct AdvancedWebvhOptions {
    /// Caller-supplied DID-document template (parsed from `did_document_file`).
    did_document: Option<serde_json::Value>,
    /// Pre-signed did.jsonl log (read from `did_log_file`).
    did_log: Option<String>,
    /// Existing signing-key id to reuse.
    signing_key_id: Option<String>,
    /// Existing key-agreement-key id to reuse.
    ka_key_id: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_pre_rotation_count() -> u32 {
    1
}

/// Entry point for `vta setup --from <file>`.
pub async fn run_setup_from_file(file_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(&file_path)
        .map_err(|e| format!("read setup file {}: {e}", file_path.display()))?;
    let inputs: WizardInputs = toml::from_str(&raw)
        .map_err(|e| format!("parse setup file {}: {e}", file_path.display()))?;

    eprintln!(
        "Running non-interactive setup from {} ...",
        file_path.display()
    );
    apply_inputs(inputs, &SilentUi).await
}

/// Run the setup wizard from a [`WizardInputs`] (the canonical schema for
/// both `vta setup` and `vta setup --from <file>`).
///
/// This is the single setup engine: it owns all the work (store init, seed
/// persistence, mnemonic generation, mediator + VTA DID minting, config write,
/// optional admin seal). The two operator-input points the TOML schema can't
/// carry — confirming the displayed mnemonic and choosing where to write a
/// DID's `did.jsonl` — are delegated to `ui` ([`SetupUi`]). The non-interactive
/// path passes [`SilentUi`] (no display, canonical log path); the interactive
/// wizard passes an impl that prompts.
pub async fn apply_inputs(
    inputs: WizardInputs,
    ui: &dyn SetupUi,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Refuse to overwrite an existing config — same stance as the
    //    interactive wizard. Operators who want a re-run can delete the
    //    file first.
    if inputs.config_path.exists() {
        return Err(format!(
            "config file {} already exists — delete it first to re-run setup",
            inputs.config_path.display()
        )
        .into());
    }

    // 2. Validate cross-field constraints. `messaging.create_mediator`
    //    needs `services.didcomm = true`, and so on.
    validate_inputs(&inputs)?;

    // 3. Handle data_dir conflict per policy.
    if inputs.data_dir.exists() {
        match inputs.data_dir_exists {
            ExistingDataDirPolicy::Error => {
                return Err(format!(
                    "data directory {} already exists — set data_dir_exists = \"delete\" to wipe and re-init",
                    inputs.data_dir.display()
                )
                .into());
            }
            ExistingDataDirPolicy::Delete => {
                std::fs::remove_dir_all(&inputs.data_dir)
                    .map_err(|e| format!("delete {}: {e}", inputs.data_dir.display()))?;
                eprintln!("  Deleted existing data directory.");
            }
        }
    }

    // 4. Open store + seed contexts.
    let store = Store::open(&StoreConfig {
        data_dir: inputs.data_dir.clone(),
    })?;
    let keys_ks = store.keyspace(crate::keyspaces::KEYS)?;
    let imported_ks = store.keyspace(crate::keyspaces::IMPORTED_SECRETS)?;
    let contexts_ks = store.keyspace(crate::keyspaces::CONTEXTS)?;
    let webvh_ks = store.keyspace(crate::keyspaces::WEBVH)?;
    let audit_ks = store.keyspace(crate::keyspaces::AUDIT)?;
    let did_templates_ks = store.keyspace(crate::keyspaces::DID_TEMPLATES)?;

    let mut vta_ctx = create_seed_context(&contexts_ks, "vta", "Verifiable Trust Agent").await?;
    eprintln!("  Created application context: vta");

    // 5. Mnemonic — generate, then hand to the UI. `--from` (SilentUi) never
    //    displays it (operator captures via `pnm backup export` after the
    //    first admin connects); the interactive wizard shows it and requires
    //    the operator to confirm they've recorded it before continuing.
    let mnemonic = generate_mnemonic_silent()?;
    ui.confirm_mnemonic(&mnemonic)?;
    let seed = mnemonic.to_seed("");

    // 6. Translate the typed backend choice into a SecretsConfig the
    //    seed-store factory can consume.
    let mut secrets_config = secrets_config_from_input(&inputs.secrets)?;

    // 7. Persist seed via the chosen backend.
    if matches!(inputs.secrets, SecretsBackendInput::ConfigSeed) {
        // config-seed backend: hex-encode seed into the config struct so
        // it gets written to config.toml at save time.
        secrets_config.seed = Some(hex::encode(seed));
    } else {
        let scratch_config = scratch_config_for_seed_store(
            inputs.data_dir.clone(),
            secrets_config.clone(),
            inputs.config_path.clone(),
        );
        let seed_store = create_seed_store(&scratch_config).map_err(|e| format!("{e}"))?;
        seed_store.set(&seed).await.map_err(|e| format!("{e}"))?;
    }

    // 8. Initial seed record + JWT signing key.
    let initial_seed_record = SeedRecord {
        id: 0,
        seed_hex: None,
        seed_enc: None,
        created_at: Utc::now(),
        retired_at: None,
    };
    save_seed_record(&keys_ks, &initial_seed_record).await?;
    set_active_seed_id(&keys_ks, 0).await?;

    let mut jwt_key_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut jwt_key_bytes);
    let jwt_signing_key = BASE64.encode(jwt_key_bytes);

    // 9. Build a scratch AppConfig the messaging/DID builders can use to
    //    open the seed store. The real AppConfig is constructed at the end
    //    once we have the VTA DID.
    let mut wizard_config = scratch_config_for_seed_store(
        inputs.data_dir.clone(),
        secrets_config.clone(),
        inputs.config_path.clone(),
    );
    let wizard_seed_store: Arc<dyn SeedStore> =
        Arc::from(create_seed_store(&wizard_config).map_err(|e| format!("{e}"))?);

    // 10. Messaging.
    let messaging = match &inputs.messaging {
        MessagingInput::Skip => None,
        MessagingInput::Existing {
            did,
            mediator_host,
            setup_acl,
        } => Some(MessagingConfig {
            mediator_url: String::new(),
            mediator_did: did.clone(),
            mediator_host: mediator_host.clone(),
            setup_acl: *setup_acl,
            drain_inbox_on_start: false,
        }),
        MessagingInput::CreateMediator {
            context,
            url,
            ws_url,
            webvh_url,
            mediator_host,
            template_vars,
            setup_acl,
        } => {
            let _med_ctx =
                create_seed_context(&contexts_ks, context, "DIDComm Messaging Mediator").await?;
            // Operator-supplied vars first; then `URL` and `WS_URL` so the
            // wizard's notion of the endpoint always wins even if an
            // operator typo'd it under template_vars. Both are required by
            // the `didcomm-mediator` template since it started advertising
            // HTTP + WSS in a single `#service` block.
            let mut effective_vars: HashMap<String, serde_json::Value> = template_vars.clone();
            effective_vars.insert("URL".into(), json!(url));
            // `WS_URL`: an explicit `ws_url` is used verbatim (for reverse
            // proxies that route the WS upgrade elsewhere); otherwise derive
            // it from `url` via the shared helper — same `{base}/ws`
            // convention the interactive wizard offers as its prompt
            // default, so the two paths agree. Shape of an explicit value is
            // already checked in `validate_inputs`.
            let ws_url = match ws_url {
                Some(explicit) => explicit.trim().to_string(),
                None => super::derive_ws_url(url).ok_or_else(|| {
                    format!(
                        "messaging.url '{url}' must start with http:// or https:// so the \
                         wizard can derive WS_URL (or set messaging.ws_url explicitly)"
                    )
                })?,
            };
            effective_vars.insert("WS_URL".into(), json!(ws_url));

            // `url` is the DIDComm endpoint; `webvh_url` is the DID-document
            // hosting URL. They are usually the same host but are semantically
            // distinct, so we let operators specify them separately. Default to
            // the DIDComm endpoint when no explicit hosting URL is set.
            let did_hosting_url = webvh_url.as_deref().unwrap_or(url);

            let mediator_did = create_simple_webvh_did(
                context,
                context,
                did_hosting_url,
                /* portable */ true,
                /* pre_rotation_count */ 1,
                /* additional_services */ None,
                /* add_mediator_service */ false,
                /* template */ Some("didcomm-mediator".into()),
                effective_vars,
                /* is_vta_identity */ false,
                AdvancedWebvhOptions::default(),
                ui,
                &keys_ks,
                &imported_ks,
                &contexts_ks,
                &webvh_ks,
                &audit_ks,
                &did_templates_ks,
                &*wizard_seed_store,
                &wizard_config,
            )
            .await?;

            Some(MessagingConfig {
                mediator_url: url.clone(),
                mediator_did,
                mediator_host: mediator_host.clone(),
                setup_acl: *setup_acl,
                drain_inbox_on_start: false,
            })
        }
    };

    // Propagate the resolved mediator into the scratch config so the VTA DID
    // builder can embed `DIDCommMessaging` in the DID document. Without this,
    // `build_did_document_inner` sees `config.messaging == None` and silently
    // drops the service even when `add_mediator_service == true`.
    wizard_config.messaging = messaging.clone();

    // 11. VTA DID.
    let vta_did = match &inputs.vta_did {
        VtaDidInput::Skip => None,
        VtaDidInput::Existing { did } => Some(did.clone()),
        VtaDidInput::CreateDidKey => {
            let did =
                create_vta_did_key("vta", &keys_ks, &contexts_ks, &*wizard_seed_store).await?;
            Some(did)
        }
        VtaDidInput::CreateWebvh {
            url,
            portable,
            pre_rotation_count,
            did_document_file,
            did_log_file,
            signing_key_id,
            ka_key_id,
        } => {
            // Resolve the advanced-mode inputs (validated mutually exclusive in
            // `validate_inputs`): a DID-document template file is parsed as
            // JSON, a pre-signed log file is read verbatim.
            let did_document = match did_document_file {
                Some(path) => {
                    let raw = std::fs::read_to_string(path).map_err(|e| {
                        format!("read vta_did.did_document_file {}: {e}", path.display())
                    })?;
                    Some(
                        serde_json::from_str::<serde_json::Value>(&raw).map_err(|e| {
                            format!("parse vta_did.did_document_file {}: {e}", path.display())
                        })?,
                    )
                }
                None => None,
            };
            let did_log =
                match did_log_file {
                    Some(path) => Some(std::fs::read_to_string(path).map_err(|e| {
                        format!("read vta_did.did_log_file {}: {e}", path.display())
                    })?),
                    None => None,
                };
            let advanced = AdvancedWebvhOptions {
                did_document,
                did_log,
                signing_key_id: signing_key_id.clone(),
                ka_key_id: ka_key_id.clone(),
            };
            let services = super::build_vta_additional_services(
                &inputs.services,
                inputs.public_url.as_deref(),
            );
            let did = create_simple_webvh_did(
                "VTA",
                "vta",
                url,
                *portable,
                *pre_rotation_count,
                services,
                /* add_mediator_service */ messaging.is_some(),
                /* template */ None,
                HashMap::new(),
                /* is_vta_identity */ true,
                advanced,
                ui,
                &keys_ks,
                &imported_ks,
                &contexts_ks,
                &webvh_ks,
                &audit_ks,
                &did_templates_ks,
                &*wizard_seed_store,
                &wizard_config,
            )
            .await?;
            Some(did)
        }
    };

    if let Some(ref did) = vta_did {
        vta_ctx.did = Some(did.clone());
        vta_ctx.updated_at = Utc::now();
        store_context(&contexts_ks, &vta_ctx)
            .await
            .map_err(|e| format!("{e}"))?;
    }

    // 12. Flush store and release the directory lock before any later step
    //     that re-opens it. fjall holds an exclusive lock per data dir, so
    //     the admin-seeding step (which reopens the store) would deadlock
    //     if these handles were still alive.
    store.persist().await?;
    drop(wizard_seed_store);
    drop(keys_ks);
    drop(imported_ks);
    drop(contexts_ks);
    drop(webvh_ks);
    drop(audit_ks);
    drop(did_templates_ks);
    drop(store);

    // 13. Save AppConfig.
    let config = AppConfig {
        trusted_presentation_verifiers: Vec::new(),
        credential_holder_did: None,
        vta_did: vta_did.clone(),
        vta_name: inputs.vta_name.clone(),
        public_url: inputs.public_url.clone(),
        server: inputs.server.clone(),
        log: inputs.log.clone(),
        store: StoreConfig {
            data_dir: inputs.data_dir.clone(),
        },
        services: inputs.services.clone(),
        messaging: messaging.clone(),
        auth: AuthConfig {
            jwt_signing_key: Some(jwt_signing_key),
            ..AuthConfig::default()
        },
        audit: inputs.audit.clone(),
        vault: Default::default(),
        policy: Default::default(),
        secrets: secrets_config,
        #[cfg(feature = "tee")]
        tee: Default::default(),
        resolver_url: inputs.resolver_url.clone(),
        config_path: inputs.config_path.clone(),
        unknown_keys: Vec::new(),
    };
    config.save()?;

    // 14. Optional admin seeding + seal. Atomic from the operator's
    //    perspective — if seeding fails, setup as a whole fails (config is
    //    on disk but the VTA is not declared "ready").
    if let Some(ref admin_did) = inputs.admin_did {
        seed_initial_admin(&inputs.data_dir, admin_did, inputs.admin_label.clone()).await?;
    }

    // 14b. Enterprise staff provisioning (context + policy + scoped ACL row).
    //     Runs after the owner is seeded; no-op for a personal VTA.
    seed_staff(&inputs.data_dir, &inputs.staff).await?;

    // 15. Summary.
    eprintln!();
    eprintln!("\x1b[1;32mSetup complete.\x1b[0m");
    eprintln!("  Config:   {}", config.config_path.display());
    eprintln!("  Data dir: {}", config.store.data_dir.display());
    if let Some(ref name) = config.vta_name {
        eprintln!("  Name:     {name}");
    }
    if let Some(ref url) = config.public_url {
        eprintln!("  URL:      {url}");
    }
    if let Some(ref did) = config.vta_did {
        eprintln!("  VTA DID:  {did}");
    }
    if let Some(ref msg) = config.messaging {
        eprintln!("  Mediator: {}", msg.mediator_did);
    }
    if let Some(admin) = &inputs.admin_did {
        eprintln!("  Admin:    {admin} (sealed)");
    } else {
        eprintln!();
        eprintln!("  ACL is empty. Seed the first admin:");
        eprintln!();
        eprintln!("    Option A (recommended, reversible) — grant admin access to an");
        eprintln!("    existing DID without sealing the VTA. Lets you add more admins");
        eprintln!("    later and re-run offline CLI commands:");
        eprintln!("      vta import-did --did <did:...> --role admin [--label <name>]");
        eprintln!();
        eprintln!("    Option B (one-time, seals the VTA) — for immutable-image");
        eprintln!("    deployments that should refuse any further offline CLI writes");
        eprintln!("    after first admin. Disables `acl`, `keys`, `import-did`,");
        eprintln!("    `export-admin` until you run `vta unseal`:");
        eprintln!("      vta bootstrap-admin --did <did:...> [--label <name>]");
    }
    eprintln!();
    eprintln!("  Mnemonic was generated and stored in the configured backend.");
    eprintln!("  Capture an encrypted backup after the first admin connects:");
    eprintln!("    pnm backup export --output vta-backup.vtabak");
    eprintln!();

    Ok(())
}

fn validate_inputs(inputs: &WizardInputs) -> Result<(), Box<dyn std::error::Error>> {
    let mut errors: Vec<String> = Vec::new();

    if matches!(inputs.messaging, MessagingInput::CreateMediator { .. }) && !inputs.services.didcomm
    {
        errors.push("messaging.kind = \"create_mediator\" requires services.didcomm = true".into());
    }
    if matches!(inputs.messaging, MessagingInput::Existing { .. }) && !inputs.services.didcomm {
        errors.push("messaging.kind = \"existing\" requires services.didcomm = true".into());
    }
    // REST requires a public URL — without it the VTA DID document
    // ends up with no `VTARest` service entry, leaving downstream
    // resolvers no way to reach the REST API. The interactive wizard
    // blocks this at prompt time; this rule does the same for the
    // `--from <toml>` path.
    if inputs.services.rest && inputs.public_url.as_deref().is_none_or(str::is_empty) {
        errors.push(
            "services.rest = true requires `public_url` to be set (e.g. \
             `public_url = \"https://vta.example.com\"`); without it the VTA DID \
             document has no REST service endpoint to publish"
                .into(),
        );
    }
    // TSP advertises the **same** mediator as DIDComm (one dual-protocol
    // mediator — tsp-enablement.md D8), so `services.tsp = true` without
    // DIDComm would point the `#tsp` service at a mediator the VTA never
    // configured. Require DIDComm when TSP is on. (TSP is usually enabled
    // post-setup via `services tsp enable` once it's been verified; this rule
    // guards the declarative `--from <toml>` path.)
    if inputs.services.tsp && !inputs.services.didcomm {
        errors.push(
            "services.tsp = true requires services.didcomm = true — TSP advertises \
             the same mediator as DIDComm. Set services.didcomm = true (and \
             configure messaging), or leave TSP off here and enable it later with \
             `services tsp enable`"
                .into(),
        );
    }
    if let MessagingInput::CreateMediator {
        context,
        webvh_url,
        ws_url,
        ..
    } = &inputs.messaging
    {
        if context.trim().is_empty() {
            errors.push("messaging.context cannot be empty".into());
        }
        if webvh_url.as_deref().is_some_and(str::is_empty) {
            errors.push(
                "messaging.webvh_url is set to an empty string; either remove the key to default \
                 to messaging.url, or provide a hosting URL"
                    .into(),
            );
        }
        // An explicit `ws_url` is used verbatim (reverse proxies that
        // route the WS upgrade elsewhere); validate its shape here so the
        // failure surfaces at parse time, alongside `webvh_url`, rather
        // than mid-`apply_inputs`. An absent `ws_url` is derived from
        // `url` and validated there.
        if let Some(ws) = ws_url {
            let trimmed = ws.trim();
            if trimmed.is_empty() {
                errors.push(
                    "messaging.ws_url is set to an empty string; either remove the key to \
                     derive it from messaging.url, or provide a ws:// or wss:// endpoint"
                        .into(),
                );
            } else if !(trimmed.starts_with("ws://") || trimmed.starts_with("wss://")) {
                errors.push(format!(
                    "messaging.ws_url '{trimmed}' must start with ws:// or wss://"
                ));
            }
        }
    }
    if let VtaDidInput::CreateWebvh {
        pre_rotation_count,
        did_document_file,
        did_log_file,
        signing_key_id,
        ka_key_id,
        ..
    } = &inputs.vta_did
    {
        if *pre_rotation_count > 32 {
            errors.push(format!(
                "vta_did.pre_rotation_count = {pre_rotation_count} is unreasonably large (max 32)"
            ));
        }
        // The advanced modes are mutually exclusive — each selects a different
        // way of supplying the DID document / keys, and the operations layer
        // rejects more than one of `did_document` / `did_log` / existing-key
        // anyway. Surface the conflict at parse time with a clear message.
        let advanced_modes = usize::from(did_document_file.is_some())
            + usize::from(did_log_file.is_some())
            + usize::from(signing_key_id.is_some());
        if advanced_modes > 1 {
            errors.push(
                "vta_did: at most one of `did_document_file`, `did_log_file`, `signing_key_id` \
                 may be set — they select mutually-exclusive advanced DID-creation modes"
                    .into(),
            );
        }
        if ka_key_id.is_some() && signing_key_id.is_none() {
            errors.push(
                "vta_did.ka_key_id requires vta_did.signing_key_id (the key-agreement key pairs \
                 with an existing signing key)"
                    .into(),
            );
        }
    }
    if let Some(did) = &inputs.admin_did
        && !did.starts_with("did:")
    {
        errors.push(format!(
            "admin_did = {did:?} must be a DID (starts with `did:`)"
        ));
    }
    for s in &inputs.staff {
        if !s.did.starts_with("did:") {
            errors.push(format!(
                "staff.did = {:?} must be a DID (starts with `did:`)",
                s.did
            ));
        }
        if s.context.trim().is_empty() {
            errors.push("staff.context must be a non-empty context id".into());
        }
        if let Some(role) = &s.role
            && crate::acl::Role::parse(role).is_err()
        {
            errors.push(format!(
                "staff.role = {role:?} is not a valid role \
                 (admin/initiator/application/reader/monitor)"
            ));
        }
    }
    if inputs.resolver_url.as_deref().is_some_and(str::is_empty) {
        errors.push(
            "resolver_url is set to an empty string; either remove the key or provide a \
             WebSocket URL (e.g. `ws://resolver.example.com/did/v1/ws`)"
                .into(),
        );
    }
    // `retention_days = 0` would silently disable retention. Reject it
    // so an operator who meant "keep forever" has to think about it
    // explicitly (we don't currently support unbounded retention; the
    // sweeper assumes a positive window).
    if inputs.audit.retention_days == 0 {
        errors.push("audit.retention_days must be > 0 (default is 28)".into());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "setup file has {} validation error(s):\n  - {}",
            errors.len(),
            errors.join("\n  - ")
        )
        .into())
    }
}

fn secrets_config_from_input(
    input: &SecretsBackendInput,
) -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    Ok(match input {
        SecretsBackendInput::Keyring { service } => {
            #[cfg(not(feature = "keyring"))]
            {
                let _ = service;
                return Err(
                    "keyring backend requested but vta-service was built without the `keyring` feature"
                        .into(),
                );
            }
            #[cfg(feature = "keyring")]
            {
                SecretsConfig {
                    keyring_service: service.clone(),
                    ..SecretsConfig::default()
                }
            }
        }
        SecretsBackendInput::ConfigSeed => {
            #[cfg(not(feature = "config-seed"))]
            {
                return Err(
                    "config_seed backend requested but vta-service was built without the `config-seed` feature"
                        .into(),
                );
            }
            #[cfg(feature = "config-seed")]
            {
                SecretsConfig {
                    seed: Some(String::new()), // populated with hex(seed) by caller
                    ..Default::default()
                }
            }
        }
        SecretsBackendInput::Aws {
            region,
            secret_name,
        } => {
            #[cfg(not(feature = "aws-secrets"))]
            {
                let _ = (region, secret_name);
                return Err(
                    "aws backend requested but vta-service was built without the `aws-secrets` feature"
                        .into(),
                );
            }
            #[cfg(feature = "aws-secrets")]
            {
                SecretsConfig {
                    aws_secret_name: Some(secret_name.clone()),
                    aws_region: region.clone(),
                    ..Default::default()
                }
            }
        }
        SecretsBackendInput::Gcp {
            project,
            secret_name,
        } => {
            #[cfg(not(feature = "gcp-secrets"))]
            {
                let _ = (project, secret_name);
                return Err(
                    "gcp backend requested but vta-service was built without the `gcp-secrets` feature"
                        .into(),
                );
            }
            #[cfg(feature = "gcp-secrets")]
            {
                SecretsConfig {
                    gcp_project: Some(project.clone()),
                    gcp_secret_name: Some(secret_name.clone()),
                    ..Default::default()
                }
            }
        }
        SecretsBackendInput::Azure {
            vault_url,
            secret_name,
        } => {
            #[cfg(not(feature = "azure-secrets"))]
            {
                let _ = (vault_url, secret_name);
                return Err(
                    "azure backend requested but vta-service was built without the `azure-secrets` feature"
                        .into(),
                );
            }
            #[cfg(feature = "azure-secrets")]
            {
                SecretsConfig {
                    azure_vault_url: Some(vault_url.clone()),
                    azure_secret_name: Some(secret_name.clone()),
                    ..Default::default()
                }
            }
        }
        SecretsBackendInput::Vault {
            addr,
            secret_path,
            kv_mount,
            secret_key,
            namespace,
            auth_method,
            k8s_role,
            k8s_mount,
            k8s_jwt_path,
            token,
            approle_role_id,
            approle_secret_id,
            approle_mount,
            skip_verify,
        } => {
            #[cfg(not(feature = "vault-secrets"))]
            {
                let _ = (
                    addr,
                    secret_path,
                    kv_mount,
                    secret_key,
                    namespace,
                    auth_method,
                    k8s_role,
                    k8s_mount,
                    k8s_jwt_path,
                    token,
                    approle_role_id,
                    approle_secret_id,
                    approle_mount,
                    skip_verify,
                );
                return Err(
                    "vault backend requested but vta-service was built without the `vault-secrets` feature"
                        .into(),
                );
            }
            #[cfg(feature = "vault-secrets")]
            {
                SecretsConfig {
                    vault_addr: Some(addr.clone()),
                    vault_secret_path: Some(secret_path.clone()),
                    vault_kv_mount: kv_mount.clone(),
                    vault_secret_key: secret_key.clone(),
                    vault_namespace: namespace.clone(),
                    vault_auth_method: auth_method.clone(),
                    vault_k8s_role: k8s_role.clone(),
                    vault_k8s_mount: k8s_mount.clone(),
                    vault_k8s_jwt_path: k8s_jwt_path.clone(),
                    vault_token: token.clone(),
                    vault_approle_role_id: approle_role_id.clone(),
                    vault_approle_secret_id: approle_secret_id.clone(),
                    vault_approle_mount: approle_mount.clone(),
                    vault_skip_verify: *skip_verify,
                    ..SecretsConfig::default()
                }
            }
        }
        SecretsBackendInput::Kubernetes {
            secret_name,
            namespace,
            secret_key,
        } => {
            #[cfg(not(feature = "k8s-secrets"))]
            {
                let _ = (secret_name, namespace, secret_key);
                return Err(
                    "kubernetes backend requested but vta-service was built without the `k8s-secrets` feature"
                        .into(),
                );
            }
            #[cfg(feature = "k8s-secrets")]
            {
                SecretsConfig {
                    k8s_secret_name: Some(secret_name.clone()),
                    k8s_namespace: namespace.clone(),
                    k8s_secret_key: secret_key.clone(),
                    ..SecretsConfig::default()
                }
            }
        }
        SecretsBackendInput::Plaintext => {
            eprintln!();
            eprintln!(
                "\x1b[1;33mWARNING: plaintext seed storage selected. NOT for production.\x1b[0m"
            );
            eprintln!();
            // The plaintext fallback in `create_seed_store` is an explicit
            // opt-in (P0.9) — without `allow_plaintext = true` it errors
            // rather than silently writing the master seed in clear. Since
            // the operator deliberately chose plaintext here, set the flag so
            // the seed store can be created during setup *and* the booted VTA
            // can re-open it. The flag is serialized into `[secrets]` in the
            // generated config.toml, so plaintext deployments stay runnable.
            SecretsConfig {
                allow_plaintext: true,
                ..SecretsConfig::default()
            }
        }
    })
}

fn scratch_config_for_seed_store(
    data_dir: PathBuf,
    secrets: SecretsConfig,
    config_path: PathBuf,
) -> AppConfig {
    AppConfig {
        trusted_presentation_verifiers: Vec::new(),
        credential_holder_did: None,
        vta_did: None,
        vta_name: None,
        public_url: None,
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: StoreConfig { data_dir },
        services: ServicesConfig::default(),
        messaging: None,
        auth: AuthConfig::default(),
        audit: Default::default(),
        vault: Default::default(),
        policy: Default::default(),
        secrets,
        #[cfg(feature = "tee")]
        tee: Default::default(),
        resolver_url: None,
        config_path,
        unknown_keys: Vec::new(),
    }
}

/// Mint a `did:key` for the VTA identity using a BIP-32-derived Ed25519
/// key from the active seed. Stores only the Ed25519 signing record at
/// `{did}#key-0`; the X25519 key-agreement secret is curve-converted
/// from Ed25519 at runtime (per the `did:key` spec) so a separate
/// `#key-1` record would be a misleading second source of truth. No
/// external hosting needed — `did:key` is self-resolving.
pub(crate) async fn create_vta_did_key(
    context_id: &str,
    keys_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
) -> Result<String, Box<dyn std::error::Error>> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};

    use crate::keys;
    use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
    use vta_sdk::keys::KeyType as SdkKeyType;

    let active_seed_id = get_active_seed_id(keys_ks).await?;
    let seed = load_seed_bytes(keys_ks, seed_store, Some(active_seed_id)).await?;

    // Load context to get base derivation path
    let ctx = crate::contexts::get_context(contexts_ks, context_id)
        .await
        .map_err(|e| format!("{e}"))?
        .ok_or_else(|| format!("context '{context_id}' not found"))?;

    // Allocate a single BIP-32 path for the Ed25519 signing key. Unlike
    // did:webvh we do NOT allocate a second path for X25519 — it is
    // derived from the Ed25519 key at runtime.
    let signing_path = keys::paths::allocate_path(keys_ks, &ctx.base_path)
        .await
        .map_err(|e| format!("{e}"))?;

    let root = ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| format!("Failed to create BIP-32 root key: {e}"))?;
    let derivation_path: DerivationPath = signing_path
        .parse()
        .map_err(|e| format!("Invalid derivation path: {e}"))?;
    let derived = root
        .derive(&derivation_path)
        .map_err(|e| format!("Key derivation failed: {e}"))?;

    let signing_secret = Secret::generate_ed25519(None, Some(derived.signing_key.as_bytes()));
    let signing_pub = signing_secret
        .get_public_keymultibase()
        .map_err(|e| format!("{e}"))?;

    let did = format!("did:key:{signing_pub}");

    keys::save_key_record(
        keys_ks,
        &format!("{did}#key-0"),
        &signing_path,
        SdkKeyType::Ed25519,
        &signing_pub,
        "VTA signing key",
        Some(context_id),
        Some(active_seed_id),
    )
    .await?;

    // Derive and store sealed-transfer key for bootstrap assertions
    let st = keys::derive_sealed_transfer_key(
        &seed,
        &ctx.base_path,
        "VTA sealed-transfer producer-assertion key",
        keys_ks,
    )
    .await?;
    keys::save_sealed_transfer_key_record(
        &did,
        &st,
        keys_ks,
        Some(context_id),
        Some(active_seed_id),
    )
    .await?;

    eprintln!("  Created DID: {did}");

    Ok(did)
}

/// Mint a `did:webvh` via the operations layer with no interactive
/// prompts. Equivalent to the interactive `build_wizard_did` in "simple
/// mode" with all advanced options off.
#[allow(clippy::too_many_arguments)]
async fn create_simple_webvh_did(
    label: &str,
    context_id: &str,
    url: &str,
    portable: bool,
    pre_rotation_count: u32,
    additional_services: Option<Vec<serde_json::Value>>,
    add_mediator_service: bool,
    template: Option<String>,
    template_vars: HashMap<String, serde_json::Value>,
    is_vta_identity: bool,
    advanced: AdvancedWebvhOptions,
    ui: &dyn SetupUi,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    did_templates_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    config: &AppConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    let parsed = Url::parse(url).map_err(|e| format!("invalid DID URL {url:?}: {e}"))?;
    let webvh_url =
        WebVHURL::parse_url(&parsed).map_err(|e| format!("invalid webvh URL {url:?}: {e}"))?;
    let url_str = webvh_url
        .get_http_url(None)
        .map_err(|e| format!("{e}"))?
        .to_string();

    let auth = cli_super_admin();
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let no_bridge: Arc<crate::didcomm_bridge::DIDCommBridge> =
        Arc::new(crate::didcomm_bridge::DIDCommBridge::placeholder());

    let params = CreateDidWebvhParams {
        context_id: context_id.to_string(),
        server_id: None,
        url: Some(url_str),
        // Serverless (`server_id: None`) ignores `path_mode`.
        path_mode: vta_sdk::protocols::did_management::create::WebvhPathMode::default(),
        domain: None,
        label: Some(label.to_string()),
        portable,
        add_mediator_service,
        additional_services,
        pre_rotation_count,
        did_document: advanced.did_document,
        did_log: advanced.did_log,
        set_primary: true,
        signing_key_id: advanced.signing_key_id,
        ka_key_id: advanced.ka_key_id,
        template,
        template_context: None,
        template_vars,
        is_vta_identity,
    };

    // Setup wizard: no shared AppState, so create a local per-server
    // auth-lock registry. This path is serverless (mints from a URL),
    // so it won't authenticate to a hosting server, but the deps bundle
    // requires the field.
    let auth_locks = operations::did_webvh::WebvhAuthLocks::new();
    let deps = operations::did_webvh::CreateDidWebvhDeps {
        keys_ks,
        imported_ks,
        contexts_ks,
        webvh_ks,
        did_templates_ks,
        audit_ks,
        seed_store,
        config,
        did_resolver: &did_resolver,
        didcomm_bridge: &no_bridge,
        auth_locks: &auth_locks,
    };
    let result = operations::did_webvh::create_did_webvh(&deps, &auth, params, "setup")
        .await
        .map_err(|e| format!("{e}"))?;

    let final_did = result.did.clone();
    eprintln!("  Created DID: {final_did}");

    // Persist the did.jsonl so operators can re-publish or audit later. The UI
    // picks the destination: `--from` (SilentUi) writes the canonical in-store
    // location (`<data_dir>/did-logs/<label>-did.jsonl`); the interactive
    // wizard prompts. `None` skips the write entirely.
    if let Some(ref log_entry) = result.log_entry {
        let canonical = config
            .store
            .data_dir
            .join("did-logs")
            .join(format!("{label}-did.jsonl"));
        if let Some(log_path) = ui.did_log_path(label, &canonical) {
            if let Some(parent) = log_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&log_path, log_entry)?;
            eprintln!("  DID log:     {}", log_path.display());
        }
    }

    Ok(final_did)
}

/// Seed the first super-admin and seal the VTA. Library counterpart to
/// `vta bootstrap-admin --did <X>`.
///
/// Refuses to proceed if a seal or any super-admin already exists — for the
/// non-interactive setup flow this should never trip (we just initialised
/// the store), and tripping it indicates a bug or a corrupt re-run.
async fn seed_initial_admin(
    data_dir: &Path,
    did: &str,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::{acl, seal};

    let store = Store::open(&StoreConfig {
        data_dir: data_dir.to_path_buf(),
    })?;
    let acl_ks = store.keyspace(crate::keyspaces::ACL)?;

    if let Some(existing) = seal::get_seal(&acl_ks).await? {
        return Err(format!(
            "VTA is already sealed (by {} on {}); cannot seed admin during setup",
            existing.sealed_by, existing.sealed_at
        )
        .into());
    }

    let entries = acl::list_acl_entries(&acl_ks).await?;
    let existing_super_admins: Vec<_> = entries
        .iter()
        .filter(|e| e.role == acl::Role::Admin && e.allowed_contexts.is_empty())
        .collect();
    if !existing_super_admins.is_empty() {
        return Err(format!(
            "found {} existing super admin(s); refusing to seed another during setup",
            existing_super_admins.len()
        )
        .into());
    }

    let entry = acl::AclEntry::new(did, acl::Role::Admin, "cli:setup-from-file").with_label(label);
    acl::store_acl_entry(&acl_ks, &entry).await?;
    let _seal_record = seal::seal(&acl_ks, did).await?;
    store.persist().await?;
    Ok(())
}

/// Provision enterprise staff: for each entry, create its context (+ initial
/// `ContextPolicy`) and seed a context-scoped ACL row. Separation of duty — the
/// owner (super-admin) sets the guardrail; the staff entry is bounded by it.
/// No-op when no staff are configured. Setup runs once on a fresh store, so this
/// does not attempt idempotency: a duplicate context id surfaces as an error.
async fn seed_staff(
    data_dir: &Path,
    staff: &[StaffProvision],
) -> Result<(), Box<dyn std::error::Error>> {
    if staff.is_empty() {
        return Ok(());
    }
    use crate::acl;

    let store = Store::open(&StoreConfig {
        data_dir: data_dir.to_path_buf(),
    })?;
    let contexts_ks = store.keyspace(crate::keyspaces::CONTEXTS)?;
    let acl_ks = store.keyspace(crate::keyspaces::ACL)?;

    for s in staff {
        let name = s.label.clone().unwrap_or_else(|| s.context.clone());
        let mut record = crate::contexts::create_context(&contexts_ks, &s.context, &name).await?;
        if let Some(policy) = &s.context_policy {
            record.context_policy = Some(policy.clone());
            crate::contexts::store_context(&contexts_ks, &record).await?;
        }

        let role = match s.role.as_deref() {
            Some(r) => acl::Role::parse(r)?,
            None => acl::Role::Application,
        };
        eprintln!("  Staff:    {} → context `{}` ({role:?})", s.did, s.context);
        let entry = acl::AclEntry::new(&s.did, role, "cli:setup-from-file")
            .with_contexts(vec![s.context.clone()])
            .with_label(s.label.clone());
        acl::store_acl_entry(&acl_ks, &entry).await?;
    }
    store.persist().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_str: &str) -> Result<WizardInputs, Box<dyn std::error::Error>> {
        Ok(toml::from_str::<WizardInputs>(toml_str)?)
    }

    #[test]
    fn staff_section_parses_with_inline_context_policy() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"

            [secrets]
            backend = "keyring"

            [[staff]]
            did     = "did:key:z6MkStaff"
            context = "sales"
            label   = "Sales"
            role    = "application"

            [staff.context_policy]
            export_allowed    = false
            trusted_verifiers = ["did:web:partner.example"]
        "#;
        let inputs = parse(raw).expect("parse staff");
        assert_eq!(inputs.staff.len(), 1);
        let s = &inputs.staff[0];
        assert_eq!(s.did, "did:key:z6MkStaff");
        assert_eq!(s.context, "sales");
        assert_eq!(s.role.as_deref(), Some("application"));
        let pol = s.context_policy.as_ref().unwrap();
        assert!(!pol.allows_export());
        assert!(pol.allows_verifier("did:web:partner.example"));
        assert!(!pol.allows_verifier("did:web:other"));
    }

    #[tokio::test]
    async fn seed_staff_creates_context_policy_and_scoped_entry() {
        let dir = tempfile::tempdir().unwrap();
        let staff = vec![StaffProvision {
            did: "did:key:z6MkStaff".into(),
            context: "sales".into(),
            label: Some("Sales".into()),
            role: Some("application".into()),
            context_policy: Some(vta_sdk::context_policy::ContextPolicy {
                export_allowed: false,
                ..vta_sdk::context_policy::ContextPolicy::unrestricted()
            }),
        }];
        seed_staff(dir.path(), &staff).await.expect("seed_staff");

        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let contexts_ks = store.keyspace(crate::keyspaces::CONTEXTS).unwrap();
        let acl_ks = store.keyspace(crate::keyspaces::ACL).unwrap();

        // The context exists and carries the initial policy (export disabled).
        let ctx = crate::contexts::get_context(&contexts_ks, "sales")
            .await
            .unwrap()
            .unwrap();
        assert!(!ctx.context_policy.unwrap().allows_export());

        // The staff member has a context-scoped Application entry — not a
        // super-admin (allowed_contexts is non-empty).
        let entries = crate::acl::list_acl_entries(&acl_ks).await.unwrap();
        let e = entries
            .iter()
            .find(|e| e.did == "did:key:z6MkStaff")
            .expect("staff entry seeded");
        assert_eq!(e.role, crate::acl::Role::Application);
        assert_eq!(e.allowed_contexts, vec!["sales".to_string()]);
        assert!(!e.allowed_contexts.is_empty(), "staff must be scoped");
    }

    #[test]
    fn minimal_keyring_inputs_round_trip() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("minimal inputs should parse");
        assert!(matches!(
            inputs.secrets,
            SecretsBackendInput::Keyring { .. }
        ));
        assert!(matches!(inputs.messaging, MessagingInput::Skip));
        assert!(matches!(inputs.vta_did, VtaDidInput::Skip));
        assert!(inputs.admin_did.is_none());
    }

    #[test]
    fn plaintext_backend_sets_allow_plaintext() {
        // Selecting the plaintext backend must opt in to the plaintext
        // seed-store fallback (P0.9). Otherwise `create_seed_store` errors
        // during setup and the booted VTA can't re-open the seed. The flag
        // is serialized into `[secrets]` in the generated config.toml.
        let secrets = secrets_config_from_input(&SecretsBackendInput::Plaintext)
            .expect("plaintext backend should convert");
        assert!(
            secrets.allow_plaintext,
            "plaintext backend must set allow_plaintext = true"
        );

        // And it round-trips into the written config as `allow_plaintext = true`.
        let toml_out = toml::to_string(&secrets).expect("secrets config serializes");
        assert!(
            toml_out.contains("allow_plaintext = true"),
            "generated config must carry the flag, got:\n{toml_out}"
        );
    }

    #[test]
    fn unknown_field_rejected() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            bogus_field = "no"

            [secrets]
            backend = "keyring"
        "#;
        let err = parse(raw).expect_err("unknown top-level field should fail");
        assert!(err.to_string().contains("bogus_field"), "got: {err}");
    }

    #[test]
    fn create_mediator_webvh_url_optional_defaults_to_none() {
        // Back-compat: TOML without `webvh_url` parses; the runtime falls
        // back to `url` when none is set.
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [messaging]
            kind = "create_mediator"
            url  = "https://mediator.example.com"
        "#;
        let inputs = parse(raw).expect("parses");
        match &inputs.messaging {
            MessagingInput::CreateMediator { webvh_url, .. } => assert!(webvh_url.is_none()),
            other => panic!("expected CreateMediator, got {other:?}"),
        }
        validate_inputs(&inputs).expect("absent webvh_url should validate");
    }

    #[test]
    fn create_mediator_webvh_url_can_be_set() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [messaging]
            kind      = "create_mediator"
            url       = "https://mediator.example.com"
            webvh_url = "https://trust.example.com/dids/mediator"
        "#;
        let inputs = parse(raw).expect("parses");
        match &inputs.messaging {
            MessagingInput::CreateMediator { webvh_url, .. } => {
                assert_eq!(
                    webvh_url.as_deref(),
                    Some("https://trust.example.com/dids/mediator")
                );
            }
            other => panic!("expected CreateMediator, got {other:?}"),
        }
        validate_inputs(&inputs).expect("explicit webvh_url should validate");
    }

    #[test]
    fn create_mediator_empty_webvh_url_rejected() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [messaging]
            kind      = "create_mediator"
            url       = "https://mediator.example.com"
            webvh_url = ""
        "#;
        let inputs = parse(raw).expect("parses");
        let err = validate_inputs(&inputs).expect_err("empty webvh_url must be rejected");
        assert!(
            err.to_string().contains("messaging.webvh_url"),
            "got: {err}"
        );
    }

    #[test]
    fn create_mediator_ws_url_optional_defaults_to_none() {
        // Back-compat: TOML without `ws_url` parses; `apply_inputs`
        // derives `WS_URL` from `url`.
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [messaging]
            kind = "create_mediator"
            url  = "https://mediator.example.com"
        "#;
        let inputs = parse(raw).expect("parses");
        match &inputs.messaging {
            MessagingInput::CreateMediator { ws_url, .. } => assert!(ws_url.is_none()),
            other => panic!("expected CreateMediator, got {other:?}"),
        }
        validate_inputs(&inputs).expect("absent ws_url should validate");
    }

    #[test]
    fn create_mediator_explicit_ws_url_round_trips() {
        // An operator whose reverse proxy routes WS to a different host
        // can express it; the value is taken verbatim, not derived.
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [messaging]
            kind   = "create_mediator"
            url    = "https://mediator.example.com"
            ws_url = "wss://ws.example.com/mediator/socket"
        "#;
        let inputs = parse(raw).expect("parses");
        match &inputs.messaging {
            MessagingInput::CreateMediator { ws_url, .. } => {
                assert_eq!(
                    ws_url.as_deref(),
                    Some("wss://ws.example.com/mediator/socket")
                );
            }
            other => panic!("expected CreateMediator, got {other:?}"),
        }
        validate_inputs(&inputs).expect("explicit ws:// ws_url should validate");
    }

    #[test]
    fn create_mediator_empty_ws_url_rejected() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [messaging]
            kind   = "create_mediator"
            url    = "https://mediator.example.com"
            ws_url = ""
        "#;
        let inputs = parse(raw).expect("parses");
        let err = validate_inputs(&inputs).expect_err("empty ws_url must be rejected");
        assert!(err.to_string().contains("messaging.ws_url"), "got: {err}");
    }

    #[test]
    fn create_mediator_non_ws_scheme_ws_url_rejected() {
        // A `ws_url` that isn't a ws(s) URL (e.g. an https typo) must be
        // rejected — the template advertises it as a WebSocket endpoint.
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [messaging]
            kind   = "create_mediator"
            url    = "https://mediator.example.com"
            ws_url = "https://mediator.example.com/ws"
        "#;
        let inputs = parse(raw).expect("parses");
        let err = validate_inputs(&inputs).expect_err("non-ws scheme must be rejected");
        assert!(err.to_string().contains("ws:// or wss://"), "got: {err}");
    }

    #[test]
    fn create_mediator_mediator_host_round_trips() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [messaging]
            kind          = "create_mediator"
            url           = "https://mediator.example.com"
            mediator_host = "mediator.example.com"
        "#;
        let inputs = parse(raw).expect("parses");
        match &inputs.messaging {
            MessagingInput::CreateMediator { mediator_host, .. } => {
                assert_eq!(mediator_host.as_deref(), Some("mediator.example.com"));
            }
            other => panic!("expected CreateMediator, got {other:?}"),
        }
        validate_inputs(&inputs).expect("mediator_host should validate");
    }

    #[test]
    fn existing_mediator_mediator_host_round_trips() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [messaging]
            kind          = "existing"
            did           = "did:webvh:scid:mediator.example.com:mediator"
            mediator_host = "mediator.example.com"
        "#;
        let inputs = parse(raw).expect("parses");
        match &inputs.messaging {
            MessagingInput::Existing { mediator_host, .. } => {
                assert_eq!(mediator_host.as_deref(), Some("mediator.example.com"));
            }
            other => panic!("expected Existing, got {other:?}"),
        }
        validate_inputs(&inputs).expect("Existing+mediator_host should validate");
    }

    /// `setup_acl` is optional and defaults to `false` when absent — back-compat
    /// for existing configs that predate the field.
    #[test]
    fn setup_acl_defaults_to_false() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [messaging]
            kind = "create_mediator"
            url  = "https://mediator.example.com"
        "#;
        let inputs = parse(raw).expect("parses");
        match &inputs.messaging {
            MessagingInput::CreateMediator { setup_acl, .. } => {
                assert!(!setup_acl, "setup_acl must default to false");
            }
            other => panic!("expected CreateMediator, got {other:?}"),
        }
        validate_inputs(&inputs).expect("absent setup_acl should validate");
    }

    /// `setup_acl = true` is preserved through parsing and carried into
    /// `MessagingConfig` — the value in TOML must appear in the final config.
    #[test]
    fn setup_acl_true_is_preserved_and_propagates() {
        use crate::config::MessagingConfig;

        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [messaging]
            kind      = "existing"
            did       = "did:webvh:scid:mediator.example.com:mediator"
            setup_acl = true
        "#;
        let inputs = parse(raw).expect("parses");
        let (did, mediator_host, setup_acl) = match &inputs.messaging {
            MessagingInput::Existing {
                did,
                mediator_host,
                setup_acl,
            } => (did.clone(), mediator_host.clone(), *setup_acl),
            other => panic!("expected Existing, got {other:?}"),
        };
        assert!(setup_acl, "setup_acl must be true after parsing");
        validate_inputs(&inputs).expect("setup_acl = true should validate");

        let cfg = MessagingConfig {
            mediator_url: String::new(),
            mediator_did: did,
            mediator_host,
            setup_acl,
            drain_inbox_on_start: false,
        };
        assert!(
            cfg.setup_acl,
            "setup_acl must propagate into MessagingConfig"
        );
    }

    #[test]
    fn create_mediator_template_vars_round_trip() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [messaging]
            kind = "create_mediator"
            url  = "https://mediator.example.com"

            [messaging.template_vars]
            ROUTING_KEYS = ["did:key:zUpstream"]
            ACCEPT       = ["didcomm/v2"]
        "#;
        let inputs = parse(raw).expect("parses");
        match &inputs.messaging {
            MessagingInput::CreateMediator { template_vars, .. } => {
                assert!(template_vars.contains_key("ROUTING_KEYS"));
                assert!(template_vars.contains_key("ACCEPT"));
            }
            other => panic!("expected CreateMediator, got {other:?}"),
        }
    }

    #[test]
    fn resolver_url_round_trips() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"
            resolver_url = "ws://resolver.example.com/did/v1/ws"

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("parses");
        assert_eq!(
            inputs.resolver_url.as_deref(),
            Some("ws://resolver.example.com/did/v1/ws")
        );
        validate_inputs(&inputs).expect("resolver_url should validate");
    }

    #[test]
    fn empty_resolver_url_rejected() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"
            resolver_url = ""

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("parses");
        let err = validate_inputs(&inputs).expect_err("empty resolver_url must be rejected");
        assert!(err.to_string().contains("resolver_url"), "got: {err}");
    }

    #[test]
    fn audit_retention_days_round_trips() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [audit]
            retention_days = 365
        "#;
        let inputs = parse(raw).expect("parses");
        assert_eq!(inputs.audit.retention_days, 365);
        validate_inputs(&inputs).expect("retention_days = 365 should validate");
    }

    #[test]
    fn audit_retention_days_zero_rejected() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [audit]
            retention_days = 0
        "#;
        let inputs = parse(raw).expect("parses");
        let err = validate_inputs(&inputs).expect_err("retention_days = 0 must be rejected");
        assert!(
            err.to_string().contains("audit.retention_days"),
            "got: {err}"
        );
    }

    #[test]
    fn vault_backend_round_trips() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend     = "vault"
            addr        = "https://vault.example.com:8200"
            secret_path = "vta/master-seed"
            auth_method = "kubernetes"
            k8s_role    = "vta"
        "#;
        let inputs = parse(raw).expect("parses");
        match &inputs.secrets {
            SecretsBackendInput::Vault {
                addr,
                secret_path,
                auth_method,
                k8s_role,
                kv_mount,
                secret_key,
                ..
            } => {
                assert_eq!(addr, "https://vault.example.com:8200");
                assert_eq!(secret_path, "vta/master-seed");
                assert_eq!(auth_method, "kubernetes");
                assert_eq!(k8s_role.as_deref(), Some("vta"));
                // Defaults applied.
                assert_eq!(kv_mount, "secret");
                assert_eq!(secret_key, "seed");
            }
            other => panic!("expected Vault, got {other:?}"),
        }
        validate_inputs(&inputs).expect("vault backend should validate");
    }

    #[test]
    fn create_mediator_without_didcomm_rejected() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"

            [services]
            rest    = true
            didcomm = false

            [secrets]
            backend = "keyring"

            [messaging]
            kind = "create_mediator"
            url  = "http://localhost:8000"
        "#;
        let inputs = parse(raw).expect("parses");
        let err = validate_inputs(&inputs).expect_err("validation should fail");
        assert!(
            err.to_string().contains("services.didcomm = true"),
            "got: {err}"
        );
    }

    #[test]
    fn services_rest_without_public_url_rejected() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"

            [services]
            rest    = true
            didcomm = false

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("parses");
        let err = validate_inputs(&inputs).expect_err("validation should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("services.rest = true requires `public_url`"),
            "got: {err}"
        );
    }

    #[test]
    fn services_rest_with_empty_public_url_rejected() {
        // Operators sometimes leave the value as an empty string rather
        // than removing the key entirely; treat that as not-set.
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = ""

            [services]
            rest    = true
            didcomm = false

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("parses");
        let err = validate_inputs(&inputs).expect_err("empty public_url must be rejected");
        assert!(
            err.to_string()
                .contains("services.rest = true requires `public_url`"),
            "got: {err}"
        );
    }

    #[test]
    fn services_rest_with_public_url_passes() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://vta.example.com"

            [services]
            rest    = true
            didcomm = false

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("parses");
        validate_inputs(&inputs).expect("rest + public_url should pass");
    }

    #[test]
    fn services_rest_disabled_does_not_require_public_url() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"

            [services]
            rest    = false
            didcomm = true

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("parses");
        validate_inputs(&inputs).expect("rest disabled means public_url is optional");
    }

    #[test]
    fn services_tsp_without_didcomm_is_rejected() {
        // TSP shares the DIDComm mediator, so it can't be advertised without
        // DIDComm — the `--from <toml>` path must reject the combination.
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"

            [services]
            rest    = false
            didcomm = false
            tsp     = true

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("parses");
        let err = validate_inputs(&inputs).expect_err("tsp without didcomm must be rejected");
        assert!(
            err.to_string()
                .contains("services.tsp = true requires services.didcomm = true"),
            "got: {err}"
        );
    }

    #[test]
    fn services_tsp_with_didcomm_passes_and_carries_through() {
        // The declarative TSP path: `[services] tsp = true` (with DIDComm)
        // parses, validates, and the flag is carried on `WizardInputs.services`
        // (which `apply` writes verbatim to `config.services`).
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"

            [services]
            rest    = false
            didcomm = true
            tsp     = true

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("parses");
        validate_inputs(&inputs).expect("tsp + didcomm should validate");
        assert!(inputs.services.tsp, "tsp flag must be carried through");
    }

    #[test]
    fn admin_did_validation_rejects_non_did() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            admin_did   = "not-a-did"

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("parses");
        let err = validate_inputs(&inputs).expect_err("validation should fail");
        assert!(err.to_string().contains("admin_did"), "got: {err}");
    }

    /// Catch drift between `WizardInputs` and the operator-facing example
    /// file at `docs/02-vta/examples/vta-setup.example.toml`. If you
    /// change the schema and forget to update the example, this test fails.
    #[test]
    fn shipped_example_parses() {
        let raw = include_str!("../../../docs/02-vta/examples/vta-setup.example.toml");
        let inputs = parse(raw).expect(
            "docs/02-vta/examples/vta-setup.example.toml must be valid against WizardInputs",
        );
        validate_inputs(&inputs)
            .expect("docs/02-vta/examples/vta-setup.example.toml must pass cross-field validation");
    }

    #[test]
    fn full_inputs_parse() {
        let raw = r#"
            config_path = "/srv/vta/config.toml"
            data_dir    = "/srv/vta/data"
            vta_name    = "trust-prod-1"
            public_url  = "https://trust.example.com"
            admin_did   = "did:key:z6MkABC"
            admin_label = "ops-bootstrap"

            [services]
            rest    = true
            didcomm = true

            [server]
            host = "0.0.0.0"
            port = 7080

            [log]
            level  = "info"
            format = "json"

            [secrets]
            backend     = "aws"
            region      = "us-east-1"
            secret_name = "vta/prod/seed"

            [messaging]
            kind    = "create_mediator"
            context = "mediator"
            url     = "https://mediator.example.com"

            [vta_did]
            kind               = "create_webvh"
            url                = "https://trust.example.com/dids/vta"
            portable           = true
            pre_rotation_count = 2
        "#;
        let inputs = parse(raw).expect("full inputs should parse");
        assert_eq!(inputs.vta_name.as_deref(), Some("trust-prod-1"));
        assert!(matches!(inputs.secrets, SecretsBackendInput::Aws { .. }));
        validate_inputs(&inputs).expect("full inputs should validate");
    }

    // ── Advanced webvh-DID options (P1.2a) ──────────────────────────────

    /// Back-compat: a `create_webvh` block without any advanced field parses
    /// with all advanced options absent (plain simple-mode).
    #[test]
    fn create_webvh_advanced_fields_default_absent() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [vta_did]
            kind = "create_webvh"
            url  = "https://trust.example.com/dids/vta"
        "#;
        let inputs = parse(raw).expect("simple create_webvh should parse");
        match &inputs.vta_did {
            VtaDidInput::CreateWebvh {
                did_document_file,
                did_log_file,
                signing_key_id,
                ka_key_id,
                portable,
                pre_rotation_count,
                ..
            } => {
                assert!(did_document_file.is_none());
                assert!(did_log_file.is_none());
                assert!(signing_key_id.is_none());
                assert!(ka_key_id.is_none());
                assert!(*portable, "portable defaults true");
                assert_eq!(*pre_rotation_count, 1, "pre_rotation_count defaults 1");
            }
            other => panic!("expected CreateWebvh, got {other:?}"),
        }
        validate_inputs(&inputs).expect("simple create_webvh should validate");
    }

    /// Each advanced mode parses and, on its own, validates.
    #[test]
    fn create_webvh_single_advanced_mode_validates() {
        for (field, value) in [
            ("did_document_file", "\"/tmp/doc.json\""),
            ("did_log_file", "\"/tmp/did.jsonl\""),
            ("signing_key_id", "\"did:key:z6MkSigner#key-0\""),
        ] {
            let raw = format!(
                r#"
                config_path = "/tmp/vta-test/config.toml"
                data_dir    = "/tmp/vta-test/data"
                public_url  = "https://trust.example.com"

                [secrets]
                backend = "keyring"

                [vta_did]
                kind = "create_webvh"
                url  = "https://trust.example.com/dids/vta"
                {field} = {value}
            "#
            );
            let inputs = parse(&raw).unwrap_or_else(|e| panic!("{field} should parse: {e}"));
            validate_inputs(&inputs)
                .unwrap_or_else(|e| panic!("{field} alone should validate: {e}"));
        }
    }

    /// Two advanced modes at once is rejected (they're mutually exclusive).
    #[test]
    fn create_webvh_conflicting_advanced_modes_rejected() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [vta_did]
            kind              = "create_webvh"
            url               = "https://trust.example.com/dids/vta"
            did_document_file = "/tmp/doc.json"
            signing_key_id    = "did:key:z6MkSigner#key-0"
        "#;
        let inputs = parse(raw).expect("conflicting advanced modes should still parse");
        let err =
            validate_inputs(&inputs).expect_err("conflicting advanced modes must be rejected");
        assert!(err.to_string().contains("mutually-exclusive"), "got: {err}");
    }

    /// `ka_key_id` without `signing_key_id` is rejected.
    #[test]
    fn create_webvh_ka_key_without_signing_key_rejected() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://trust.example.com"

            [secrets]
            backend = "keyring"

            [vta_did]
            kind      = "create_webvh"
            url       = "https://trust.example.com/dids/vta"
            ka_key_id = "did:key:z6MkKA#key-1"
        "#;
        let inputs = parse(raw).expect("ka_key_id alone should parse");
        let err = validate_inputs(&inputs)
            .expect_err("ka_key_id without signing_key_id must be rejected");
        assert!(err.to_string().contains("ka_key_id requires"), "got: {err}");
    }

    /// SilentUi preserves the `--from` behaviour: never display the mnemonic,
    /// always write the canonical did.jsonl path.
    #[test]
    fn silent_ui_behaviour() {
        let ui = super::super::SilentUi;
        let mnemonic = super::super::generate_mnemonic_silent().expect("mnemonic");
        ui.confirm_mnemonic(&mnemonic)
            .expect("SilentUi must never block on mnemonic confirmation");
        let canonical = std::path::Path::new("/data/did-logs/vta-did.jsonl");
        assert_eq!(
            ui.did_log_path("vta", canonical),
            Some(canonical.to_path_buf()),
            "SilentUi must echo the canonical did.jsonl path"
        );
    }
}
