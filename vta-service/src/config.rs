use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Re-export shared config types
pub use vti_common::config::{
    AuditConfig, AuthConfig, LogConfig, LogFormat, MessagingConfig, StoreConfig,
};

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
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretsConfig {
    /// Hex-encoded BIP-32 seed (config-seed feature)
    pub seed: Option<String>,
    /// AWS Secrets Manager secret name (aws-secrets feature)
    pub aws_secret_name: Option<String>,
    /// AWS region override (aws-secrets feature)
    pub aws_region: Option<String>,
    /// GCP project ID (gcp-secrets feature)
    pub gcp_project: Option<String>,
    /// GCP secret name (gcp-secrets feature)
    pub gcp_secret_name: Option<String>,
    /// Azure Key Vault URL (azure-secrets feature)
    pub azure_vault_url: Option<String>,
    /// Azure Key Vault secret name (azure-secrets feature)
    pub azure_secret_name: Option<String>,
    /// OS keyring service name (keyring feature).
    /// Change this to run multiple VTA instances on the same machine.
    #[serde(default = "default_keyring_service")]
    pub keyring_service: String,
    /// HashiCorp Vault server URL (vault-secrets feature). Setting this
    /// activates the Vault backend.
    pub vault_addr: Option<String>,
    /// KV v2 mount path (vault-secrets feature). Default `secret`.
    #[serde(default = "default_vault_kv_mount")]
    pub vault_kv_mount: String,
    /// KV v2 secret path under the mount, e.g. `vta/master-seed`
    /// (vault-secrets feature).
    pub vault_secret_path: Option<String>,
    /// Field name within the KV v2 secret that holds the hex-encoded
    /// seed (vault-secrets feature). Default `seed`.
    #[serde(default = "default_vault_secret_key")]
    pub vault_secret_key: String,
    /// Vault Enterprise namespace, if any (vault-secrets feature).
    pub vault_namespace: Option<String>,
    /// Auth method: `kubernetes` (default), `token`, or `approle`
    /// (vault-secrets feature).
    #[serde(default = "default_vault_auth_method")]
    pub vault_auth_method: String,
    /// Kubernetes auth role name (vault-secrets feature, kubernetes
    /// auth method).
    pub vault_k8s_role: Option<String>,
    /// Kubernetes auth mount path (vault-secrets feature). Default
    /// `kubernetes`.
    #[serde(default = "default_vault_k8s_mount")]
    pub vault_k8s_mount: String,
    /// File holding the ServiceAccount JWT presented to Vault
    /// (vault-secrets feature, kubernetes auth method). Default is the
    /// kubelet-mounted projected volume path.
    #[serde(default = "default_vault_k8s_jwt_path")]
    pub vault_k8s_jwt_path: String,
    /// Static token (vault-secrets feature, token auth method). Prefer
    /// the `VAULT_TOKEN` env var over hard-coding here.
    pub vault_token: Option<String>,
    /// AppRole role_id (vault-secrets feature, approle auth method).
    pub vault_approle_role_id: Option<String>,
    /// AppRole secret_id (vault-secrets feature, approle auth method).
    pub vault_approle_secret_id: Option<String>,
    /// AppRole mount path (vault-secrets feature). Default `approle`.
    #[serde(default = "default_vault_approle_mount")]
    pub vault_approle_mount: String,
    /// Skip TLS certificate verification — dev/test only
    /// (vault-secrets feature).
    #[serde(default)]
    pub vault_skip_verify: bool,
    /// Opt in to the **plaintext file** seed-store fallback. Off by
    /// default: when no secure backend (keyring / cloud / Vault /
    /// config-seed) is compiled-in *and* configured, `create_seed_store`
    /// errors rather than silently writing the BIP-32 master seed to a
    /// file in clear. Set `true` only for dev/test where that is
    /// acceptable. (P0.9 — closes the "one wrong TOML key → master seed
    /// on disk in cleartext" footgun.)
    #[serde(default)]
    pub allow_plaintext: bool,
}

fn default_keyring_service() -> String {
    "vta".to_string()
}

fn default_vault_kv_mount() -> String {
    "secret".to_string()
}

fn default_vault_secret_key() -> String {
    "seed".to_string()
}

fn default_vault_auth_method() -> String {
    "kubernetes".to_string()
}

fn default_vault_k8s_mount() -> String {
    "kubernetes".to_string()
}

fn default_vault_k8s_jwt_path() -> String {
    "/var/run/secrets/kubernetes.io/serviceaccount/token".to_string()
}

fn default_vault_approle_mount() -> String {
    "approle".to_string()
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            seed: None,
            aws_secret_name: None,
            aws_region: None,
            gcp_project: None,
            gcp_secret_name: None,
            azure_vault_url: None,
            azure_secret_name: None,
            keyring_service: default_keyring_service(),
            vault_addr: None,
            vault_kv_mount: default_vault_kv_mount(),
            vault_secret_path: None,
            vault_secret_key: default_vault_secret_key(),
            vault_namespace: None,
            vault_auth_method: default_vault_auth_method(),
            vault_k8s_role: None,
            vault_k8s_mount: default_vault_k8s_mount(),
            vault_k8s_jwt_path: default_vault_k8s_jwt_path(),
            vault_token: None,
            vault_approle_role_id: None,
            vault_approle_secret_id: None,
            vault_approle_mount: default_vault_approle_mount(),
            vault_skip_verify: false,
            allow_plaintext: false,
        }
    }
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
        let mut config = toml::from_str::<AppConfig>(&contents)
            .map_err(|e| AppError::Config(format!("failed to parse {}: {e}", path.display())))?;

        config.config_path = path.clone();

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
}
