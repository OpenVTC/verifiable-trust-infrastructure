use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Re-export shared config types
pub use vti_common::config::{
    AuditConfig, AuthConfig, LogConfig, LogFormat, MessagingConfig, StoreConfig,
};
// The `[secrets]` config shape + its seed-store backends live in the shared
// `vti-secrets` crate (issue #501). Re-exported here so `AppConfig.secrets`
// and every `crate::config::SecretsConfig` reference are unchanged.
pub use vti_secrets::SecretsConfig;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub vta_did: Option<String>,
    #[serde(alias = "community_name")]
    pub vta_name: Option<String>,
    pub public_url: Option<String>,
    /// WebSocket URL of a remote DID resolver (network mode).
    /// When set, the VTA uses the remote resolver instead of resolving locally.
    /// Format: `ws://host:port/did/v1/ws`
    /// In TEE mode, this points to the affinidi-did-resolver-cache-server
    /// sidecar on the parent, bridged via vsock.
    #[serde(default)]
    pub resolver_url: Option<String>,
    #[serde(default = "default_server_config")]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default = "default_store_config")]
    pub store: StoreConfig,
    pub messaging: Option<MessagingConfig>,
    #[serde(default)]
    pub services: ServicesConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
    /// Verifier DIDs the holder **auto-consents** to when answering a
    /// `credential-exchange/query` (`present_or_defer`'s `ConsentPolicy`). Any
    /// verifier not listed **defers** to an out-of-band approval. Default empty
    /// (defer everything) — a safe default; operators trust specific verifiers.
    #[serde(default)]
    pub trusted_presentation_verifiers: Vec<String>,
    /// The VTA-managed holder identity (a registered derived `subject_did`) the
    /// VTA **auto-accepts** offered credentials for: when set, an inbound
    /// `credential-exchange/offer` is answered with a `request` binding the new
    /// credential to this DID. Default unset — the VTA does **not** accept
    /// unsolicited offers (a safe default; opt in by naming the holder identity).
    #[serde(default)]
    pub credential_holder_did: Option<String>,
    #[cfg(feature = "tee")]
    #[serde(default)]
    pub tee: TeeConfig,
    #[serde(skip)]
    pub config_path: PathBuf,
    /// Dotted paths of keys present in the parsed `config.toml` that no
    /// field of `AppConfig` claims — typos, removed/renamed settings, or
    /// keys meant for a different section. Collected by `load()` (via
    /// `serde_ignored`) and surfaced as advisory warnings in `validate()`.
    /// `#[serde(skip)]` so it never round-trips through the file itself.
    /// We *warn* rather than reject (no `deny_unknown_fields`): an existing
    /// deployment may legitimately carry a legacy/extra key, and a config
    /// that boots fine today must keep booting (P0.9b).
    #[serde(skip)]
    pub unknown_keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServicesConfig {
    #[serde(default = "default_true")]
    pub rest: bool,
    #[serde(default = "default_true")]
    pub didcomm: bool,
    /// WebAuthn-RP service — the dedicated `/auth/portal` +
    /// `/auth/passkey-login/*` + `/did/verification-methods/passkey/*`
    /// surface. Distinct from `rest` so an operator can run a
    /// REST-less, browser-facing-only VTA (e.g. one that only
    /// publishes WebAuthn flows for end-users plus DIDComm for
    /// programmatic peers). Defaults to `false` because legacy
    /// installs don't have this surface enabled; new installs that
    /// want browser-side passkey login flip this on explicitly.
    #[serde(default)]
    pub webauthn: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ServicesConfig {
    fn default() -> Self {
        Self {
            rest: true,
            didcomm: true,
            webauthn: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Origins permitted to make cross-origin requests against the
    /// VTA's REST surface. Empty (default) disables the CORS layer
    /// entirely — a fresh-install VTA refuses cross-origin requests
    /// the way the legacy behaviour did. Production deployments
    /// typically leave this empty (programmatic clients send the
    /// bearer token directly and don't need browser-side CORS); the
    /// demo at `examples/vta-auth-demo/` sets it to
    /// `["http://localhost:8000"]` so an operator can drive the
    /// auth flow from a browser running on a different localhost
    /// port.
    ///
    /// Each entry is matched exactly against the request's `Origin`
    /// header. Wildcards are not accepted — bearer credentials must
    /// not flow to arbitrary origins.
    #[serde(default)]
    pub cors_origins: Vec<String>,
    /// Whether to trust `X-Forwarded-For` / `Forwarded` headers
    /// for client-IP attribution in the per-IP rate limiter.
    ///
    /// Default `false` — the rate limiter keys on the socket
    /// peer-IP (`PeerIpKeyExtractor`). This is the safe default
    /// for direct-binding deployments where an attacker can spoof
    /// `X-Forwarded-For` to evade rate limiting.
    ///
    /// Set `true` only when the VTA runs behind a trust-boundary
    /// reverse proxy (Nginx, Envoy, ALB) that overwrites or
    /// strips these headers from external requests — the rate
    /// limiter switches to `SmartIpKeyExtractor` and walks the
    /// `X-Forwarded-For` chain. Misconfiguring this (`trust_xff =
    /// true` with no proxy, or a misconfigured proxy that doesn't
    /// strip the header) is a silent rate-limit bypass.
    ///
    /// Closes L2 from the May 2026 security review.
    #[serde(default)]
    pub trust_xff: bool,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8100
}

fn default_server_config() -> ServerConfig {
    ServerConfig::default()
}

fn default_store_config() -> StoreConfig {
    StoreConfig {
        data_dir: PathBuf::from("data/vta"),
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            cors_origins: Vec::new(),
            trust_xff: false,
        }
    }
}

/// TEE attestation configuration.
#[cfg(feature = "tee")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TeeConfig {
    /// Enforcement mode: required, optional, disabled, simulated.
    #[serde(default)]
    pub mode: TeeMode,
    /// Whether to embed attestation info as a DID document service.
    #[serde(default)]
    pub embed_in_did: bool,
    /// Attestation report cache TTL in seconds (generation is expensive).
    #[serde(default = "default_attestation_cache_ttl")]
    pub attestation_cache_ttl: u64,
    /// KMS-based secret bootstrap configuration (for Nitro Enclaves).
    #[serde(default)]
    pub kms: Option<TeeKmsConfig>,
    /// Storage encryption salt (change to invalidate all stored data).
    /// WARNING: Changing this value invalidates all encrypted storage.
    #[serde(default = "default_storage_key_salt")]
    pub storage_key_salt: String,
    /// Restrict which DID methods are accepted for ACL entries and authentication.
    /// When set, only DIDs matching these prefixes are allowed (e.g., `["did:key", "did:webvh"]`).
    /// When `None`, all DID methods are accepted (less secure with parent-side resolver).
    #[serde(default)]
    pub allowed_did_methods: Option<Vec<String>>,
}

/// KMS configuration for TEE secret bootstrap.
#[cfg(feature = "tee")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TeeKmsConfig {
    /// AWS region for KMS calls.
    pub region: String,
    /// KMS key ARN used to encrypt/decrypt VTA secrets.
    pub key_arn: String,
    /// Template for auto-generating a did:webvh identity on first boot.
    ///
    /// Use `{SCID}` as a placeholder for the self-certifying identifier:
    ///   `did:webvh:{SCID}:example.com:vta`
    ///
    /// On first boot, the VTA derives keys from the bootstrapped seed,
    /// creates the DID, and persists it in the encrypted store.
    ///
    /// Ignored if `vta_did` is already set in config or the store.
    #[serde(default)]
    pub vta_did_template: Option<String>,
    /// Context ID used for the auto-bootstrapped admin (default: "default").
    ///
    /// On first boot, the VTA auto-creates this context and grants the
    /// admin_did super-admin access.
    #[serde(default = "default_admin_context_id")]
    pub admin_context_id: String,
    /// DID to grant super-admin access on first boot.
    ///
    /// The operator generates a `did:key` locally (e.g., via `pnm setup`),
    /// sets it here before building the EIF, and connects to the VTA using
    /// the corresponding private key after boot. The private key never
    /// touches the TEE or the parent instance.
    ///
    /// If not set, the VTA auto-generates a random `did:key` and stores
    /// the credential in the bootstrap keyspace (retrievable via REST).
    #[serde(default)]
    pub admin_did: Option<String>,
    /// Allow falling back to non-attested KMS calls when the attested path
    /// fails on real Nitro hardware (`/dev/nsm` present).
    ///
    /// **Default: false.** On production hardware a failure to use the
    /// Nitro `Recipient` parameter must be terminal — otherwise a transient
    /// NSM hiccup silently downgrades to an IAM-only KMS call, bypassing
    /// the key policy's PCR conditions (PCR0/PCR8). The fallback path stays
    /// available for simulated mode (no `/dev/nsm`), which uses the direct
    /// KMS call regardless of this flag.
    ///
    /// Set to `true` only as a break-glass measure during incident response,
    /// understanding that decrypts will then only require the enclave's IAM
    /// role, not an attested PCR match.
    #[serde(default)]
    pub allow_unattested_fallback: bool,
    /// Allow initializing the JWT key fingerprint when none is stored.
    ///
    /// **Default: false.** A missing fingerprint on a subsequent boot is
    /// suspicious — the only legitimate cause is first boot after upgrading
    /// from a pre-fingerprint VTA version. Left unguarded, an attacker with
    /// write access to the bootstrap keyspace (parent-host / vsock proxy
    /// compromise) could delete the fingerprint and then substitute a
    /// rogue key that the enclave would accept as canonical on the next
    /// restart.
    ///
    /// Operators migrating from a pre-fingerprint VTA: set `true`, boot
    /// once to store the fingerprint, then set back to `false`.
    #[serde(default)]
    pub allow_fingerprint_init: bool,
    /// Allow auto-clearing existing bootstrap ciphertexts when a KMS
    /// decrypt **other than ACCESS_DENIED** fails on a subsequent boot.
    ///
    /// **Default: false.** ACCESS_DENIED is the legitimate post-rebuild
    /// signal (PCR mismatch — the enclave's measurements changed and KMS
    /// won't decrypt the old data key); the bootstrap keyspace is
    /// auto-cleared without this flag in that case. Any other class
    /// of decrypt failure (transient KMS error, network glitch,
    /// ciphertext corruption, attacker-induced byte flip) is *not*
    /// auto-cleared, because doing so would silently delete the VTA's
    /// identity. Set to `true` only when you have diagnosed the cause
    /// and intend to reset the VTA to a fresh first-boot state.
    #[serde(default)]
    pub allow_kms_reinit: bool,
    /// Allow establishing the TEE integrity-manifest baseline when none is
    /// stored (P0.2a anti-rollback anchor).
    ///
    /// **Default: false.** The integrity manifest is the MAC'd snapshot of the
    /// rollback-protected singletons (carve-out sentinel, ACL root, JWT
    /// fingerprint, key counters). A missing manifest on a configured VTA is
    /// indistinguishable from a parent-deleted one, so the enclave refuses to
    /// boot rather than silently baseline whatever (possibly rolled-back) state
    /// the parent presents.
    ///
    /// Operators on first boot, or migrating from a pre-manifest VTA: set
    /// `true`, boot once to establish the baseline, then set back to `false`.
    /// Mirrors [`Self::allow_fingerprint_init`].
    #[serde(default)]
    pub allow_anchor_init: bool,
    /// External anti-rollback counter (P0.2b). When set, the integrity manifest
    /// version is pinned to a DynamoDB single-item counter the parent can't roll
    /// back, upgrading detection from "deletion / inconsistent tamper" (P0.2a)
    /// to "consistent storage rollback". Absent → manifest-only (P0.2a).
    #[serde(default)]
    pub anchor: Option<TeeAnchorConfig>,
    /// Break-glass: boot even when the external anchor counter can't be reached
    /// or disagrees with the local manifest (P0.2b).
    ///
    /// **Default: false.** If the parent denies egress to the counter the
    /// enclave fails closed (a DoS, not an integrity breach). Setting this true
    /// lets it boot manifest-only when the counter is unreachable, or re-anchor
    /// the counter to the MAC-trusted local manifest when they diverge — for
    /// incident recovery only. Safe to expose as config because TEE config is
    /// baked into the measured EIF, so the parent can't flip it at runtime.
    #[serde(default)]
    pub allow_unanchored: bool,
}

/// External anti-rollback anchor configuration (P0.2b counter + P0.2c writer).
#[cfg(feature = "tee")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TeeAnchorConfig {
    /// DynamoDB table holding the single-item monotonic version counter (one
    /// item per VTA DID). The region is reused from [`TeeKmsConfig::region`].
    pub table_name: String,
    /// KMS-attestation-gated writer credential (P0.2c — root-on-parent
    /// resistance). Base64 of the `vta-anchor-writer` IAM credentials
    /// (`{"access_key_id","secret_access_key"}`) sealed under the PCR-gated KMS
    /// key ([`TeeKmsConfig::key_arn`]): only the genuine enclave image can
    /// `kms:Decrypt` it, so a root-on-parent attacker — who holds the
    /// *instance-role* credentials but cannot produce a valid attestation —
    /// cannot obtain the only principal allowed to write the counter (the
    /// instance role is explicitly denied on the table; see the operator
    /// runbook). Unset → P0.2b: the counter is written with the instance role
    /// (resists storage/backup rollback, **not** root-on-parent).
    #[serde(default)]
    pub writer_credential_ciphertext: Option<String>,
}

// KMS ciphertexts (seed, JWT key, fingerprint) are stored as K/V entries
// in the "bootstrap" keyspace — no file paths needed.

#[cfg(feature = "tee")]
fn default_admin_context_id() -> String {
    "default".to_string()
}

#[cfg(feature = "tee")]
fn default_attestation_cache_ttl() -> u64 {
    300
}

#[cfg(feature = "tee")]
fn default_storage_key_salt() -> String {
    "vta-tee-storage-v1".to_string()
}

#[cfg(feature = "tee")]
impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            mode: TeeMode::default(),
            embed_in_did: false,
            attestation_cache_ttl: default_attestation_cache_ttl(),
            kms: None,
            storage_key_salt: default_storage_key_salt(),
            allowed_did_methods: None,
        }
    }
}

/// TEE enforcement mode.
#[cfg(feature = "tee")]
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TeeMode {
    /// TEE hardware required — VTA refuses to start without it.
    Required,
    /// TEE used if available, continues without it.
    #[default]
    Optional,
    /// Simulated TEE for development/testing (NOT for production).
    Simulated,
}

impl AppConfig {
    pub fn load(config_path: Option<PathBuf>) -> Result<Self, AppError> {
        let path = config_path
            .or_else(|| std::env::var("VTA_CONFIG_PATH").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("config.toml"));

        if !path.exists() {
            return Err(AppError::Config(format!(
                "configuration file not found: {}",
                path.display()
            )));
        }

        let contents = std::fs::read_to_string(&path).map_err(AppError::Io)?;

        // Deserialize through `serde_ignored` so we can *record* every key the
        // schema doesn't recognise (typo'd / legacy / mis-sectioned) instead of
        // silently dropping it. We don't reject — `validate()` warns. (P0.9b)
        let de = toml::Deserializer::parse(&contents)
            .map_err(|e| AppError::Config(format!("failed to parse {}: {e}", path.display())))?;
        let mut unknown_keys: Vec<String> = Vec::new();
        let mut config: AppConfig = serde_ignored::deserialize(de, |key_path| {
            unknown_keys.push(key_path.to_string());
        })
        .map_err(|e| AppError::Config(format!("failed to parse {}: {e}", path.display())))?;

        config.config_path = path.clone();
        config.unknown_keys = unknown_keys;

        // =====================================================================
        // SECURITY: When KMS bootstrap is configured (TEE mode), the config
        // baked into the EIF is authoritative. ALL env var overrides are blocked
        // except VTA_LOG_LEVEL and VTA_LOG_FORMAT (operational, no security impact).
        //
        // This prevents an attacker with server access from overriding identity
        // (VTA_DID), endpoints (VTA_PUBLIC_URL, VTA_MESSAGING_*), secrets
        // (VTA_SECRETS_*, VTA_AUTH_JWT_SIGNING_KEY), or security settings
        // (VTA_TEE_MODE) via environment variables.
        //
        // In Nitro Enclaves, env var injection is already blocked by the enclave
        // model (no --env flag on nitro-cli run-enclave). This gate provides
        // defense in depth for non-Nitro TEE deployments (e.g., SEV-SNP).
        // =====================================================================
        #[cfg(feature = "tee")]
        let kms_locked = config.tee.kms.is_some();
        #[cfg(not(feature = "tee"))]
        let kms_locked = false;

        if kms_locked {
            // In KMS mode, only allow log settings
            if let Ok(level) = std::env::var("VTA_LOG_LEVEL") {
                config.log.level = level;
            }
            if let Ok(format) = std::env::var("VTA_LOG_FORMAT") {
                config.log.format = match format.to_lowercase().as_str() {
                    "json" => LogFormat::Json,
                    "text" => LogFormat::Text,
                    other => {
                        return Err(AppError::Config(format!(
                            "invalid VTA_LOG_FORMAT '{other}', expected 'text' or 'json'"
                        )));
                    }
                };
            }

            // Log warnings for any env vars that would have been applied
            let blocked_vars = [
                "VTA_DID",
                "VTA_SERVER_HOST",
                "VTA_SERVER_PORT",
                "VTA_PUBLIC_URL",
                "VTA_STORE_DATA_DIR",
                "VTA_MESSAGING_MEDIATOR_URL",
                "VTA_MESSAGING_MEDIATOR_DID",
                "VTA_SECRETS_SEED",
                "VTA_SECRETS_AWS_SECRET_NAME",
                "VTA_SECRETS_AWS_REGION",
                "VTA_SECRETS_GCP_PROJECT",
                "VTA_SECRETS_GCP_SECRET_NAME",
                "VTA_SECRETS_AZURE_VAULT_URL",
                "VTA_SECRETS_AZURE_SECRET_NAME",
                "VTA_SECRETS_KEYRING_SERVICE",
                "VTA_SECRETS_K8S_SECRET_NAME",
                "VTA_SECRETS_K8S_NAMESPACE",
                "VTA_SECRETS_K8S_SECRET_KEY",
                "VTA_AUTH_ACCESS_EXPIRY",
                "VTA_AUTH_REFRESH_EXPIRY",
                "VTA_AUTH_CHALLENGE_TTL",
                "VTA_AUTH_SESSION_CLEANUP_INTERVAL",
                "VTA_AUTH_JWT_SIGNING_KEY",
                "VTA_TEE_MODE",
                "VTA_TEE_EMBED_IN_DID",
                "VTA_TEE_ATTESTATION_CACHE_TTL",
            ];
            for var in &blocked_vars {
                if std::env::var(var).is_ok() {
                    tracing::warn!(
                        "SECURITY: {var} env var ignored — config is locked when KMS bootstrap is active"
                    );
                }
            }
        } else {
            // Non-KMS mode: apply all env var overrides (existing behavior)
            Self::apply_env_overrides(&mut config)?;
        }

        Ok(config)
    }

    /// Apply environment variable overrides to the config.
    ///
    /// Only called in non-KMS mode. When KMS bootstrap is active,
    /// the baked-in config is authoritative and env overrides are blocked.
    fn apply_env_overrides(config: &mut AppConfig) -> Result<(), AppError> {
        if let Ok(vta_did) = std::env::var("VTA_DID") {
            config.vta_did = Some(vta_did);
        }
        if let Ok(host) = std::env::var("VTA_SERVER_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = std::env::var("VTA_SERVER_PORT") {
            config.server.port = port
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTA_SERVER_PORT: {e}")))?;
        }
        if let Ok(level) = std::env::var("VTA_LOG_LEVEL") {
            config.log.level = level;
        }
        if let Ok(format) = std::env::var("VTA_LOG_FORMAT") {
            config.log.format = match format.to_lowercase().as_str() {
                "json" => LogFormat::Json,
                "text" => LogFormat::Text,
                other => {
                    return Err(AppError::Config(format!(
                        "invalid VTA_LOG_FORMAT '{other}', expected 'text' or 'json'"
                    )));
                }
            };
        }
        if let Ok(public_url) = std::env::var("VTA_PUBLIC_URL") {
            config.public_url = Some(public_url);
        }
        if let Ok(data_dir) = std::env::var("VTA_STORE_DATA_DIR") {
            config.store.data_dir = PathBuf::from(data_dir);
        }

        // Messaging
        match (
            std::env::var("VTA_MESSAGING_MEDIATOR_URL"),
            std::env::var("VTA_MESSAGING_MEDIATOR_DID"),
        ) {
            (Ok(url), Ok(did)) => {
                config.messaging = Some(MessagingConfig {
                    mediator_url: url,
                    mediator_did: did,
                    mediator_host: None,
                });
            }
            (Ok(url), Err(_)) => {
                let messaging = config.messaging.get_or_insert(MessagingConfig {
                    mediator_url: String::new(),
                    mediator_did: String::new(),
                    mediator_host: None,
                });
                messaging.mediator_url = url;
            }
            (Err(_), Ok(did)) => {
                let messaging = config.messaging.get_or_insert(MessagingConfig {
                    mediator_url: String::new(),
                    mediator_did: String::new(),
                    mediator_host: None,
                });
                messaging.mediator_did = did;
            }
            (Err(_), Err(_)) => {}
        }

        // Secrets
        if let Ok(seed) = std::env::var("VTA_SECRETS_SEED") {
            config.secrets.seed = Some(seed);
        }
        if let Ok(name) = std::env::var("VTA_SECRETS_AWS_SECRET_NAME") {
            config.secrets.aws_secret_name = Some(name);
        }
        if let Ok(region) = std::env::var("VTA_SECRETS_AWS_REGION") {
            config.secrets.aws_region = Some(region);
        }
        if let Ok(project) = std::env::var("VTA_SECRETS_GCP_PROJECT") {
            config.secrets.gcp_project = Some(project);
        }
        if let Ok(name) = std::env::var("VTA_SECRETS_GCP_SECRET_NAME") {
            config.secrets.gcp_secret_name = Some(name);
        }
        if let Ok(url) = std::env::var("VTA_SECRETS_AZURE_VAULT_URL") {
            config.secrets.azure_vault_url = Some(url);
        }
        if let Ok(name) = std::env::var("VTA_SECRETS_AZURE_SECRET_NAME") {
            config.secrets.azure_secret_name = Some(name);
        }
        if let Ok(service) = std::env::var("VTA_SECRETS_KEYRING_SERVICE") {
            config.secrets.keyring_service = service;
        }

        // Vault. K8s deployments commonly inject these via Secret /
        // ConfigMap so envs override file-config. `VAULT_ADDR` /
        // `VAULT_NAMESPACE` / `VAULT_TOKEN` are the canonical names
        // Vault itself uses; we accept those alongside the
        // VTA_SECRETS_* prefix for symmetry.
        if let Ok(addr) =
            std::env::var("VAULT_ADDR").or_else(|_| std::env::var("VTA_SECRETS_VAULT_ADDR"))
        {
            config.secrets.vault_addr = Some(addr);
        }
        if let Ok(ns) = std::env::var("VAULT_NAMESPACE")
            .or_else(|_| std::env::var("VTA_SECRETS_VAULT_NAMESPACE"))
        {
            config.secrets.vault_namespace = Some(ns);
        }
        if let Ok(path) = std::env::var("VTA_SECRETS_VAULT_SECRET_PATH") {
            config.secrets.vault_secret_path = Some(path);
        }
        if let Ok(key) = std::env::var("VTA_SECRETS_VAULT_SECRET_KEY") {
            config.secrets.vault_secret_key = key;
        }
        if let Ok(mount) = std::env::var("VTA_SECRETS_VAULT_KV_MOUNT") {
            config.secrets.vault_kv_mount = mount;
        }
        if let Ok(method) = std::env::var("VTA_SECRETS_VAULT_AUTH_METHOD") {
            config.secrets.vault_auth_method = method;
        }
        if let Ok(role) = std::env::var("VTA_SECRETS_VAULT_K8S_ROLE") {
            config.secrets.vault_k8s_role = Some(role);
        }
        if let Ok(mount) = std::env::var("VTA_SECRETS_VAULT_K8S_MOUNT") {
            config.secrets.vault_k8s_mount = mount;
        }
        if let Ok(jwt) = std::env::var("VTA_SECRETS_VAULT_K8S_JWT_PATH") {
            config.secrets.vault_k8s_jwt_path = jwt;
        }
        if let Ok(token) = std::env::var("VAULT_TOKEN") {
            config.secrets.vault_token = Some(token);
        }
        if let Ok(rid) = std::env::var("VTA_SECRETS_VAULT_APPROLE_ROLE_ID") {
            config.secrets.vault_approle_role_id = Some(rid);
        }
        if let Ok(sid) = std::env::var("VTA_SECRETS_VAULT_APPROLE_SECRET_ID") {
            config.secrets.vault_approle_secret_id = Some(sid);
        }
        if let Ok(mount) = std::env::var("VTA_SECRETS_VAULT_APPROLE_MOUNT") {
            config.secrets.vault_approle_mount = mount;
        }
        if let Ok(skip) = std::env::var("VAULT_SKIP_VERIFY")
            .or_else(|_| std::env::var("VTA_SECRETS_VAULT_SKIP_VERIFY"))
        {
            config.secrets.vault_skip_verify =
                matches!(skip.to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        }

        // Kubernetes Secret backend. K8s deployments commonly inject the
        // namespace from the pod's own metadata via the Downward API, so an
        // env override is the natural way to set it.
        if let Ok(name) = std::env::var("VTA_SECRETS_K8S_SECRET_NAME") {
            config.secrets.k8s_secret_name = Some(name);
        }
        if let Ok(ns) = std::env::var("VTA_SECRETS_K8S_NAMESPACE") {
            config.secrets.k8s_namespace = Some(ns);
        }
        if let Ok(key) = std::env::var("VTA_SECRETS_K8S_SECRET_KEY") {
            config.secrets.k8s_secret_key = key;
        }

        // Auth
        if let Ok(expiry) = std::env::var("VTA_AUTH_ACCESS_EXPIRY") {
            config.auth.access_token_expiry = expiry
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTA_AUTH_ACCESS_EXPIRY: {e}")))?;
        }
        if let Ok(expiry) = std::env::var("VTA_AUTH_REFRESH_EXPIRY") {
            config.auth.refresh_token_expiry = expiry
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTA_AUTH_REFRESH_EXPIRY: {e}")))?;
        }
        if let Ok(ttl) = std::env::var("VTA_AUTH_CHALLENGE_TTL") {
            config.auth.challenge_ttl = ttl
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTA_AUTH_CHALLENGE_TTL: {e}")))?;
        }
        if let Ok(interval) = std::env::var("VTA_AUTH_SESSION_CLEANUP_INTERVAL") {
            config.auth.session_cleanup_interval = interval.parse().map_err(|e| {
                AppError::Config(format!("invalid VTA_AUTH_SESSION_CLEANUP_INTERVAL: {e}"))
            })?;
        }
        if let Ok(key) = std::env::var("VTA_AUTH_JWT_SIGNING_KEY") {
            config.auth.jwt_signing_key = Some(key);
        }

        // Audit
        if let Ok(val) = std::env::var("VTA_AUDIT_RETENTION_DAYS")
            && let Ok(days) = val.parse::<u32>()
        {
            config.audit.retention_days = days;
        }

        // TEE (non-KMS mode — all overrides allowed)
        #[cfg(feature = "tee")]
        {
            if let Ok(mode) = std::env::var("VTA_TEE_MODE") {
                config.tee.mode = match mode.to_lowercase().as_str() {
                    "required" => TeeMode::Required,
                    "optional" => TeeMode::Optional,
                    "simulated" => TeeMode::Simulated,
                    "disabled" => {
                        tracing::warn!(
                            "VTA_TEE_MODE=disabled is deprecated — use 'optional' instead"
                        );
                        TeeMode::Optional
                    }
                    other => {
                        return Err(AppError::Config(format!(
                            "invalid VTA_TEE_MODE '{other}', expected 'required', 'optional', or 'simulated'"
                        )));
                    }
                };
            }
            if let Ok(val) = std::env::var("VTA_TEE_EMBED_IN_DID") {
                config.tee.embed_in_did = val
                    .parse()
                    .map_err(|e| AppError::Config(format!("invalid VTA_TEE_EMBED_IN_DID: {e}")))?;
            }
            if let Ok(val) = std::env::var("VTA_TEE_ATTESTATION_CACHE_TTL") {
                config.tee.attestation_cache_ttl = val.parse().map_err(|e| {
                    AppError::Config(format!("invalid VTA_TEE_ATTESTATION_CACHE_TTL: {e}"))
                })?;
            }
        }

        Ok(())
    }

    /// Validate the loaded runtime config, called at daemon boot
    /// (`server::run`). Catches misconfigurations that would otherwise
    /// produce a half-started or misbehaving service — the setup wizard
    /// validates its *inputs*, but a hand-edited `config.toml` never went
    /// through that gate.
    ///
    /// Conservative by design: it hard-errors only on values that are
    /// unambiguously broken (a present-but-empty URL, a zero retention
    /// window the sweeper can't honour) and *warns* — never blocks — on
    /// cross-field advisories that a working deployment might legitimately
    /// have, so it can't reject a config that boots fine today.
    pub fn validate(&self) -> Result<(), AppError> {
        // Advisory (non-blocking): keys the schema doesn't recognise. Emitted
        // here rather than in `load()` because `load()` runs before the tracing
        // subscriber is installed, so a warn there would be dropped. A typo'd
        // key means the operator's intended setting silently took its default —
        // worth flagging, but never a reason to refuse a config that otherwise
        // boots (P0.9b — softer than `deny_unknown_fields`).
        for key in &self.unknown_keys {
            tracing::warn!(
                "unknown configuration key `{key}` in {} — ignored. Check for a typo, \
                 a removed/renamed setting, or a key placed in the wrong [section].",
                self.config_path.display()
            );
        }

        let mut errors: Vec<String> = Vec::new();

        // A present-but-empty URL is always a mistake (the operator set the
        // key and left it blank); an *absent* key is fine (the default /
        // serverless path).
        if self
            .public_url
            .as_deref()
            .is_some_and(|u| u.trim().is_empty())
        {
            errors.push(
                "public_url is set to an empty string — remove the key for a \
                 serverless VTA, or give it a value (e.g. https://vta.example.com)"
                    .into(),
            );
        }
        if self
            .resolver_url
            .as_deref()
            .is_some_and(|u| u.trim().is_empty())
        {
            errors.push(
                "resolver_url is set to an empty string — remove the key to resolve \
                 DIDs locally, or give it a ws:// or wss:// URL"
                    .into(),
            );
        }
        // retention_days = 0 would silently disable audit retention; the
        // sweeper assumes a positive window. (Mirrors the setup-time rule.)
        if self.audit.retention_days == 0 {
            errors.push("audit.retention_days must be > 0 (default is 28)".into());
        }

        if !errors.is_empty() {
            return Err(AppError::Config(format!(
                "invalid configuration in {}:\n  - {}",
                self.config_path.display(),
                errors.join("\n  - ")
            )));
        }

        // Advisory (non-blocking): a REST-advertising VTA with no public_url
        // publishes a DID document with no reachable REST endpoint. We don't
        // hard-fail — a dev VTA legitimately runs REST without publishing —
        // but the operator should see it.
        if self.services.rest && self.public_url.is_none() {
            tracing::warn!(
                "services.rest = true but public_url is unset — the VTA DID document \
                 will advertise no reachable REST endpoint"
            );
        }

        Ok(())
    }

    pub fn save(&self) -> Result<(), AppError> {
        let contents = toml::to_string_pretty(self)
            .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;
        std::fs::write(&self.config_path, contents).map_err(AppError::Io)?;
        Ok(())
    }
}

#[cfg(test)]
mod validate_tests {
    use super::*;

    /// Parse a (possibly empty) TOML snippet into an `AppConfig`. An empty
    /// document is valid — every field defaults (Options to None, server /
    /// store / audit to their default fns).
    fn cfg(toml_str: &str) -> AppConfig {
        toml::from_str::<AppConfig>(toml_str).expect("parse test config")
    }

    #[test]
    fn default_config_validates() {
        cfg("")
            .validate()
            .expect("a fully-defaulted config must validate");
    }

    #[test]
    fn zero_retention_days_is_rejected() {
        let err = cfg("[audit]\nretention_days = 0\n")
            .validate()
            .expect_err("retention_days = 0 must be rejected");
        assert!(format!("{err:?}").contains("retention_days"), "{err:?}");
    }

    #[test]
    fn present_but_empty_public_url_is_rejected() {
        let err = cfg("public_url = \"\"\n")
            .validate()
            .expect_err("empty public_url must be rejected");
        assert!(format!("{err:?}").contains("public_url"), "{err:?}");
    }

    #[test]
    fn present_but_empty_resolver_url_is_rejected() {
        let err = cfg("resolver_url = \"   \"\n")
            .validate()
            .expect_err("whitespace-only resolver_url must be rejected");
        assert!(format!("{err:?}").contains("resolver_url"), "{err:?}");
    }

    #[test]
    fn rest_without_public_url_only_warns_does_not_fail() {
        // services.rest defaults to true and public_url is absent — this is
        // an advisory (a dev VTA legitimately runs REST without publishing),
        // so validate must NOT hard-fail.
        cfg("")
            .validate()
            .expect("rest-without-public_url is advisory, not an error");
    }

    /// Write `contents` to a `config.toml` in a fresh tempdir and run it
    /// through the real `AppConfig::load` path (the only path that populates
    /// `unknown_keys` — `toml::from_str` doesn't). Returns the loaded config;
    /// the `TempDir` is returned too so the file outlives the call.
    fn load(contents: &str) -> (AppConfig, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, contents).expect("write config");
        let config = AppConfig::load(Some(path)).expect("load config");
        (config, dir)
    }

    #[test]
    fn unknown_keys_are_collected_not_rejected() {
        // A typo'd top-level key and a typo inside a nested table. `load`
        // must succeed (no rejection) and record both as dotted paths.
        let (config, _dir) = load(
            "vta_naem = \"oops\"\n\
             [secrets]\nkyring_service = \"vta-2\"\n",
        );
        assert!(
            config.unknown_keys.iter().any(|k| k == "vta_naem"),
            "top-level typo should be flagged: {:?}",
            config.unknown_keys
        );
        assert!(
            config
                .unknown_keys
                .iter()
                .any(|k| k == "secrets.kyring_service"),
            "nested typo should be flagged with a dotted path: {:?}",
            config.unknown_keys
        );
        // Advisory only — a config with unknown keys still validates.
        config
            .validate()
            .expect("unknown keys are advisory, not a hard error");
    }

    #[test]
    fn known_keys_and_aliases_are_not_flagged() {
        // `community_name` is a serde alias for `vta_name`; a real nested
        // key must not be reported. Nothing should land in `unknown_keys`.
        let (config, _dir) = load(
            "community_name = \"acme\"\n\
             [server]\nport = 9000\n",
        );
        assert!(
            config.unknown_keys.is_empty(),
            "known keys + aliases must not be flagged: {:?}",
            config.unknown_keys
        );
        assert_eq!(config.vta_name.as_deref(), Some("acme"));
        assert_eq!(config.server.port, 9000);
    }
}
