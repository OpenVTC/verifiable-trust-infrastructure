use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Re-export shared config types
pub use vti_common::config::{AuthConfig, LogConfig, LogFormat, MessagingConfig, StoreConfig};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub vtc_did: Option<String>,
    pub vta_did: Option<String>,
    #[serde(alias = "community_name")]
    pub vtc_name: Option<String>,
    #[serde(alias = "community_description")]
    pub vtc_description: Option<String>,
    pub public_url: Option<String>,
    #[serde(default = "default_server_config")]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default = "default_store_config")]
    pub store: StoreConfig,
    pub messaging: Option<MessagingConfig>,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub cors: CorsConfig,
    /// Trust-registry settings (Phase 3 M3.2). When `url` is
    /// unset, registry features no-op and `registry_status`
    /// reports `"degraded"`. Otherwise the daemon health-pings
    /// the registry at boot and on a periodic interval.
    #[serde(default)]
    pub registry: RegistryConfig,
    /// Renewal-path settings (Phase 4 M4.2.2). Currently
    /// gates the renewal-time behaviour when `personhood.rego`
    /// flips a previously-asserted member's flag to `false`.
    #[serde(default)]
    pub renewal: RenewalConfig,
    /// Retention sweeper settings (§5.5). Controls the window after which
    /// terminal join requests (and expired credential-exchange / Failed
    /// sync-job rows) are purged, plus the sweep cadence. Defaults to a
    /// 30-day window swept hourly.
    #[serde(default)]
    pub join_requests: crate::join::retention::JoinRequestsConfig,
    /// Public community website settings (Phase 5 M5.4). When
    /// `root_dir` is unset the website handler 503s — the
    /// feature is opt-in by operator configuration, even though
    /// the cargo feature is default-on.
    #[serde(default)]
    pub website: WebsiteConfig,
    /// Admin UX settings (Phase 5 M5.7). When `mode = "external"`,
    /// the embedded SPA is skipped and `/admin/*` returns 404; the
    /// configured `external_origin` is added to
    /// `cors.allowed_origins` so an external SPA hosted on that
    /// origin can drive the API.
    #[serde(default)]
    pub admin_ui: AdminUiConfig,
    #[serde(skip)]
    pub config_path: PathBuf,
}

/// Admin UX configuration (§12.2, Phase 5 M5.7).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct AdminUiConfig {
    /// `"embedded"` (default): serve the baked admin SPA at
    /// `routing.admin_ui.mount`. `"external"`: skip embedding;
    /// the operator hosts the SPA elsewhere and the daemon
    /// merely allowlists their origin.
    #[serde(default = "default_admin_ui_mode")]
    pub mode: String,
    /// Origin the external SPA serves from. Required when
    /// `mode = "external"`; ignored otherwise.
    #[serde(default)]
    pub external_origin: Option<String>,
    /// WebAuthn RP-ID override. When `None`, derived from the
    /// routing mode (path-mode → base host; subdomain-mode →
    /// base domain).
    #[serde(default)]
    pub rp_id: Option<String>,
    /// Directory the daemon scans for third-party plugins. Each
    /// subdirectory is one plugin: `<plugin_dir>/<id>/manifest.json`
    /// declares the manifest; the daemon serves the directory's
    /// static files under `/admin/plugins/<id>/`. `None` (default)
    /// → only built-in plugins, no third-party scan.
    ///
    /// Plugin IDs must match `^[a-z][a-z0-9-]*$` — anything else
    /// is dropped from the manifest endpoint with a `warn!`.
    #[serde(default)]
    pub plugin_dir: Option<std::path::PathBuf>,
}

impl Default for AdminUiConfig {
    fn default() -> Self {
        Self {
            mode: default_admin_ui_mode(),
            external_origin: None,
            rp_id: None,
            plugin_dir: None,
        }
    }
}

fn default_admin_ui_mode() -> String {
    "embedded".into()
}

/// Public community website (§12.1, Phase 5 M5.4.1). Filesystem-
/// backed static hosting under [`Self::root_dir`].
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct WebsiteConfig {
    /// Directory served as the site root. `None` disables the
    /// handler entirely (it 503s with a clear error). No default
    /// — operators opt in by setting this to a real path.
    #[serde(default)]
    pub root_dir: Option<PathBuf>,
    /// Deploy mode: `"live"` (default) or `"managed"`. See
    /// [`crate::website::WebsiteRoot`].
    #[serde(default = "default_deploy_mode")]
    pub deploy_mode: String,
    /// Cache TTL for the live-mode FD cache, in seconds.
    /// Defaults to 5 — short enough that `scp` / `rsync` edits
    /// surface quickly, long enough to amortise repeat hits.
    #[serde(default = "default_live_cache_ttl_seconds")]
    pub live_cache_ttl_seconds: u64,
    /// Managed mode: retain this many old generations beyond
    /// the active one. Default 5.
    #[serde(default = "default_managed_generations_keep")]
    pub managed_generations_keep: u32,
    /// `Cache-Control` header on every successful response.
    /// Defaults to `"public, max-age=300"` — five minutes for a
    /// CDN to cache.
    #[serde(default = "default_cache_control")]
    pub cache_control: String,
    /// Extensions refused unconditionally. Default
    /// `[".cgi", ".php", ".exe"]`. Lowercased + dot-prefixed.
    #[serde(default = "default_executable_blocklist")]
    pub executable_blocklist: Vec<String>,
    /// Maximum bundle size for `POST /v1/website/deploy` (M5.5).
    /// Tested at the management API; informational here.
    #[serde(default = "default_max_bundle_size_mb")]
    pub max_bundle_size_mb: u64,
    /// Maximum size for a single `PUT /v1/website/files/...`
    /// upload (M5.5). Tested at the management API; informational
    /// here.
    #[serde(default = "default_max_file_size_mb")]
    pub max_file_size_mb: u64,
    /// Per-site override file (relative to `root_dir`). Currently
    /// supports a single key, `csp = "..."`, that replaces the
    /// default CSP for this site. Default `".vtc-website.toml"`.
    #[serde(default = "default_csp_override_file")]
    pub csp_override_file: String,
}

impl Default for WebsiteConfig {
    fn default() -> Self {
        Self {
            root_dir: None,
            deploy_mode: default_deploy_mode(),
            live_cache_ttl_seconds: default_live_cache_ttl_seconds(),
            managed_generations_keep: default_managed_generations_keep(),
            cache_control: default_cache_control(),
            executable_blocklist: default_executable_blocklist(),
            max_bundle_size_mb: default_max_bundle_size_mb(),
            max_file_size_mb: default_max_file_size_mb(),
            csp_override_file: default_csp_override_file(),
        }
    }
}

fn default_deploy_mode() -> String {
    "live".into()
}
fn default_live_cache_ttl_seconds() -> u64 {
    5
}
fn default_managed_generations_keep() -> u32 {
    5
}
fn default_cache_control() -> String {
    "public, max-age=300".into()
}
fn default_executable_blocklist() -> Vec<String> {
    vec![".cgi".into(), ".php".into(), ".exe".into()]
}
fn default_max_bundle_size_mb() -> u64 {
    50
}
fn default_max_file_size_mb() -> u64 {
    10
}
fn default_csp_override_file() -> String {
    ".vtc-website.toml".into()
}

/// Renewal-path settings. Phase 4 M4.2.2.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub struct RenewalConfig {
    /// What to do when the active `personhood.rego` returns
    /// `false` for a member whose current `personhood` flag
    /// is `true` (spec §6.3 step 3 + Phase 4 plan D5 review).
    ///
    /// - [`PersonhoodFailMode::Downgrade`] (default): flip the
    ///   Member row's flag to `false`, re-mint the VMC with
    ///   `personhood: false`, audit a `PersonhoodRevoked
    ///   { reason: "renewal-policy" }` envelope, **succeed**.
    ///   Preserves §3-B "ACL is authoritative" — membership
    ///   lifecycle is decoupled from personhood lifecycle.
    /// - [`PersonhoodFailMode::Refuse`]: return `422
    ///   Unprocessable Entity` with stable reason
    ///   `personhood-renewal-refused`. Member row stays
    ///   `true`; no VMC re-mint; no audit envelope. Caller
    ///   re-asserts via the assert endpoint before retrying.
    #[serde(default)]
    pub on_personhood_fail: PersonhoodFailMode,
}

/// What renewal does when `personhood.rego` drops a previously-
/// asserted member's flag to `false`. See [`RenewalConfig`].
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PersonhoodFailMode {
    /// Re-mint with `personhood: false`. Default. Recommended
    /// for most deployments.
    #[default]
    Downgrade,
    /// Return `422`. Stricter privacy posture.
    Refuse,
}

/// Trust-registry runtime settings.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct RegistryConfig {
    /// Base URL of the upstream TRQP-compliant registry
    /// (e.g. `https://registry.example.com`). When `None`,
    /// registry features no-op — `registry_status` reads
    /// `"degraded"`, sync is skipped.
    #[serde(default)]
    pub url: Option<String>,
    /// Period (seconds) between background health probes.
    /// `0` disables the periodic probe (only boot-time probe
    /// runs). Default: 60s.
    #[serde(default = "default_health_probe_interval")]
    pub health_probe_interval_seconds: u64,
    /// Per-call HTTP timeout for registry operations (seconds).
    /// Default: 5s.
    #[serde(default = "default_registry_http_timeout")]
    pub http_timeout_seconds: u64,
    /// RTBF-batch coalescing window (hours) — spec §8.2 +
    /// M3.7. When the syncer's walker fires an RTBF override,
    /// the resulting `DeleteMember` job is parked for at
    /// least this many hours before the registry call goes
    /// out. The window de-correlates the override audit
    /// envelope's timestamp from the registry record's
    /// disappearance so an external observer can't time-align
    /// the two and re-identify the RTBF requester. Set to `0`
    /// to disable batching (RTBF jobs dispatch immediately —
    /// useful in tests; **not recommended in production**).
    /// Default: 24h.
    #[serde(default = "default_rtbf_batch_window_hours")]
    pub rtbf_batch_window_hours: u64,
}

fn default_health_probe_interval() -> u64 {
    60
}

fn default_registry_http_timeout() -> u64 {
    5
}

fn default_rtbf_batch_window_hours() -> u64 {
    24
}

impl Default for RegistryConfig {
    fn default() -> Self {
        // Production defaults — match the serde-default
        // values. Deriving Default would zero every numeric
        // field, silently disabling the periodic probe + the
        // RTBF batch protection. Keep the two in sync by
        // construction.
        Self {
            url: None,
            health_probe_interval_seconds: default_health_probe_interval(),
            http_timeout_seconds: default_registry_http_timeout(),
            rtbf_batch_window_hours: default_rtbf_batch_window_hours(),
        }
    }
}

/// Per-surface mount config (spec §9.2). Phase-0 surfaces:
///
/// - `api` — the JSON REST + DIDComm management surface. **Always
///   mounted**; this is the daemon's reason to exist.
/// - `admin_ui` — the (eventual) admin SPA. Phase 0 leaves the
///   mount declared but doesn't serve anything; the slot reserves
///   the path so cookie scopes don't collide later.
/// - `website` — public community site (Phase 5+). Same story —
///   the mount is reserved, the route table is empty.
///
/// **Mode**: per the spec, each surface can be path-prefixed
/// (`mount`) or host-routed (`host`). Phase 0 exercises only the
/// path-prefix default. Subdomain mode is accepted by the config
/// parser but not driven by any code path until later phases.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct RoutingConfig {
    #[serde(default = "default_api_mount")]
    pub api: MountConfig,
    #[serde(default = "default_admin_ui_mount")]
    pub admin_ui: MountConfig,
    #[serde(default = "default_website_mount")]
    pub website: MountConfig,
    /// Subdomain-mode strictness (Phase 5 M5.1.2). When at least one
    /// surface has `host` set:
    ///
    /// - `true` (default): a request whose `Host` header doesn't match
    ///   any configured surface returns 404 `HostNotRecognised`.
    /// - `false`: unknown hosts fall back to path-mode prefix
    ///   matching against the parent router. Debug aid only — not
    ///   recommended for production.
    ///
    /// No effect when every surface has `host = None` (pure path
    /// mode).
    #[serde(default = "default_subdomain_mode_strict")]
    pub subdomain_mode_strict: bool,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            api: default_api_mount(),
            admin_ui: default_admin_ui_mount(),
            website: default_website_mount(),
            subdomain_mode_strict: default_subdomain_mode_strict(),
        }
    }
}

fn default_subdomain_mode_strict() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct MountConfig {
    /// Path prefix the surface attaches under (e.g. `/v1`,
    /// `/admin`, `/`). Path mode is the Phase-0 default.
    pub mount: String,
    /// Optional host header for subdomain mode. Accepted by the
    /// config parser; not exercised by Phase-0 routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

fn default_api_mount() -> MountConfig {
    MountConfig {
        mount: "/v1".into(),
        host: None,
    }
}

fn default_admin_ui_mount() -> MountConfig {
    MountConfig {
        mount: "/admin".into(),
        host: None,
    }
}

fn default_website_mount() -> MountConfig {
    MountConfig {
        mount: "/".into(),
        host: None,
    }
}

/// CORS allowlist (spec §9.3). Wildcards (`*`) are refused at
/// config-load — the spec demands an explicit allowlist so the
/// admin UX origin (and only that origin) can mutate the daemon.
///
/// When the list is empty, **CORS is disabled** — every cross-
/// origin request gets the default browser rejection. Path-mode
/// deployments serving the admin UX same-origin don't need any
/// entries.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct CorsConfig {
    /// Exact-match origin allowlist. Each entry is a full origin
    /// (`https://host:port` — no path). Wildcards rejected.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Whether to trust `X-Forwarded-For` / `Forwarded` headers
    /// for client-IP attribution in the per-IP rate limiter
    /// (`build_unauth_routes`).
    ///
    /// Default `false` — the rate limiter keys on the socket
    /// peer-IP. Safe for direct-binding deployments; not
    /// bypassable by header spoofing.
    ///
    /// Set `true` only when the VTC runs behind a trust-boundary
    /// reverse proxy that overwrites or strips these headers
    /// from external requests. Misconfiguring this is a silent
    /// rate-limit bypass.
    ///
    /// Closes L2 from the May 2026 security review.
    #[serde(default)]
    pub trust_xff: bool,
}

// `deny_unknown_fields` so a typo'd backend selector (`aws_secretname`,
// `gcp_secrets_name`, …) is a loud parse error rather than a silently-dropped
// key that lets the factory fall through to the keyring/plaintext default
// (P0.8). Safe here — `SecretsConfig` carries no serde aliases; the
// alias-bearing fields live on the parent `AppConfig`, which is intentionally
// left lenient until the alias audit in the plan.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    /// Hex-encoded VTC key material (config-secret feature)
    pub secret: Option<String>,
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
    /// Change this to run multiple VTC instances on the same machine.
    #[serde(default = "default_keyring_service")]
    pub keyring_service: String,
}

fn default_keyring_service() -> String {
    "vtc".to_string()
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            secret: None,
            aws_secret_name: None,
            aws_region: None,
            gcp_project: None,
            gcp_secret_name: None,
            azure_vault_url: None,
            azure_secret_name: None,
            keyring_service: default_keyring_service(),
        }
    }
}

fn default_host() -> String {
    default_host_value()
}

fn default_port() -> u16 {
    default_port_value()
}

/// Compiled-in default for `server.host`. Exposed crate-wide so the
/// three-layer overlay in `config_store` can attribute the layer
/// source correctly (a TOML value equal to this is treated as
/// `Default`, not `Toml`).
pub(crate) fn default_host_value() -> String {
    "0.0.0.0".to_string()
}

/// Compiled-in default for `server.port`. See [`default_host_value`].
pub(crate) fn default_port_value() -> u16 {
    8200
}

fn default_server_config() -> ServerConfig {
    ServerConfig::default()
}

/// Refuse a config that would break the spec's routing
/// invariants. Phase-0 enforcement:
///
/// - **Path-mode mounts must be unique.** Two surfaces sharing the
///   same prefix would race for routes; reject at load.
/// - **`admin_ui.mount` must not be `/` in path mode.** Spec §9.3:
///   "refuses to start if cookie scopes would overlap (e.g., admin
///   mounted at / is rejected)". With admin at root, the future
///   admin session cookie's `Path=/admin` constraint collapses to
///   "any path", letting public-website JS read admin cookies.
/// - **Path-mode mounts start with `/`.** A bare `admin` mount is
///   almost certainly a typo; bail loud.
/// - **`api.mount` cannot equal `admin_ui.mount`.** Same family
///   of routes; cookie-scope rationale doesn't apply but the
///   ambiguity does.
fn validate_routing(routing: &RoutingConfig) -> Result<(), AppError> {
    for (name, m) in [
        ("api", &routing.api),
        ("admin_ui", &routing.admin_ui),
        ("website", &routing.website),
    ] {
        if !m.mount.starts_with('/') {
            return Err(AppError::Config(format!(
                "routing.{name}.mount must start with '/': got '{}'",
                m.mount
            )));
        }
    }

    // Cookie-scope guard. Only fires in path mode for the admin_ui
    // surface — subdomain mode (host set) carries its own scope.
    if routing.admin_ui.host.is_none() && routing.admin_ui.mount == "/" {
        return Err(AppError::Config(
            "routing.admin_ui.mount = '/' would collapse the admin cookie scope; \
             pick a non-root prefix (default: '/admin') or enable subdomain mode via \
             routing.admin_ui.host"
                .into(),
        ));
    }

    // Mount uniqueness (path mode only — subdomain mode disambiguates
    // by host). The `website` catch-all is allowed to share `/` with
    // a non-mounted slot, but pairwise duplicates between api +
    // admin_ui + website are rejected.
    let path_mounts: Vec<(&str, &str)> = [
        (
            "api",
            routing.api.host.as_deref(),
            routing.api.mount.as_str(),
        ),
        (
            "admin_ui",
            routing.admin_ui.host.as_deref(),
            routing.admin_ui.mount.as_str(),
        ),
        (
            "website",
            routing.website.host.as_deref(),
            routing.website.mount.as_str(),
        ),
    ]
    .into_iter()
    .filter_map(|(name, host, mount)| host.is_none().then_some((name, mount)))
    .collect();

    for i in 0..path_mounts.len() {
        for j in (i + 1)..path_mounts.len() {
            let (a, am) = path_mounts[i];
            let (b, bm) = path_mounts[j];
            if am == bm {
                return Err(AppError::Config(format!(
                    "routing.{a}.mount and routing.{b}.mount both = '{am}'; \
                     path-mode mounts must be unique",
                )));
            }
        }
    }
    Ok(())
}

/// Refuse a CORS allowlist that includes `*` or empty / whitespace
/// entries. Spec §9.3: "wildcards refused". An empty
/// `allowed_origins` is valid — that's "no cross-origin requests
/// permitted" (same-origin path-mode default).
fn validate_cors(cors: &CorsConfig) -> Result<(), AppError> {
    for origin in &cors.allowed_origins {
        let trimmed = origin.trim();
        if trimmed.is_empty() {
            return Err(AppError::Config(
                "cors.allowed_origins contains an empty / whitespace entry".into(),
            ));
        }
        if trimmed == "*" || trimmed.contains('*') {
            return Err(AppError::Config(format!(
                "cors.allowed_origins entry '{trimmed}' uses a wildcard; \
                 spec §9.3 demands an exact-match allowlist"
            )));
        }
        if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
            return Err(AppError::Config(format!(
                "cors.allowed_origins entry '{trimmed}' must be a full origin \
                 (e.g., 'https://admin.example.com')"
            )));
        }
    }
    Ok(())
}

fn default_store_config() -> StoreConfig {
    StoreConfig {
        data_dir: PathBuf::from("data/vtc"),
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            trust_xff: false,
        }
    }
}

impl AppConfig {
    pub fn load(config_path: Option<PathBuf>) -> Result<Self, AppError> {
        let path = config_path
            .or_else(|| std::env::var("VTC_CONFIG_PATH").ok().map(PathBuf::from))
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

        // Apply env var overrides
        if let Ok(vtc_did) = std::env::var("VTC_DID") {
            config.vtc_did = Some(vtc_did);
        }
        if let Ok(vta_did) = std::env::var("VTC_VTA_DID") {
            config.vta_did = Some(vta_did);
        }
        if let Ok(host) = std::env::var("VTC_SERVER_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = std::env::var("VTC_SERVER_PORT") {
            config.server.port = port
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTC_SERVER_PORT: {e}")))?;
        }
        if let Ok(level) = std::env::var("VTC_LOG_LEVEL") {
            config.log.level = level;
        }
        if let Ok(format) = std::env::var("VTC_LOG_FORMAT") {
            config.log.format = match format.to_lowercase().as_str() {
                "json" => LogFormat::Json,
                "text" => LogFormat::Text,
                other => {
                    return Err(AppError::Config(format!(
                        "invalid VTC_LOG_FORMAT '{other}', expected 'text' or 'json'"
                    )));
                }
            };
        }
        if let Ok(public_url) = std::env::var("VTC_PUBLIC_URL") {
            config.public_url = Some(public_url);
        }
        if let Ok(data_dir) = std::env::var("VTC_STORE_DATA_DIR") {
            config.store.data_dir = PathBuf::from(data_dir);
        }

        // Messaging env var overrides
        match (
            std::env::var("VTC_MESSAGING_MEDIATOR_URL"),
            std::env::var("VTC_MESSAGING_MEDIATOR_DID"),
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

        // Secrets env var overrides
        if let Ok(secret) = std::env::var("VTC_SECRETS_SECRET") {
            config.secrets.secret = Some(secret);
        }
        if let Ok(name) = std::env::var("VTC_SECRETS_AWS_SECRET_NAME") {
            config.secrets.aws_secret_name = Some(name);
        }
        if let Ok(region) = std::env::var("VTC_SECRETS_AWS_REGION") {
            config.secrets.aws_region = Some(region);
        }
        if let Ok(project) = std::env::var("VTC_SECRETS_GCP_PROJECT") {
            config.secrets.gcp_project = Some(project);
        }
        if let Ok(name) = std::env::var("VTC_SECRETS_GCP_SECRET_NAME") {
            config.secrets.gcp_secret_name = Some(name);
        }
        if let Ok(url) = std::env::var("VTC_SECRETS_AZURE_VAULT_URL") {
            config.secrets.azure_vault_url = Some(url);
        }
        if let Ok(name) = std::env::var("VTC_SECRETS_AZURE_SECRET_NAME") {
            config.secrets.azure_secret_name = Some(name);
        }
        if let Ok(service) = std::env::var("VTC_SECRETS_KEYRING_SERVICE") {
            config.secrets.keyring_service = service;
        }

        // Auth env var overrides
        if let Ok(expiry) = std::env::var("VTC_AUTH_ACCESS_EXPIRY") {
            config.auth.access_token_expiry = expiry
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTC_AUTH_ACCESS_EXPIRY: {e}")))?;
        }
        if let Ok(expiry) = std::env::var("VTC_AUTH_REFRESH_EXPIRY") {
            config.auth.refresh_token_expiry = expiry
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTC_AUTH_REFRESH_EXPIRY: {e}")))?;
        }
        if let Ok(ttl) = std::env::var("VTC_AUTH_CHALLENGE_TTL") {
            config.auth.challenge_ttl = ttl
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTC_AUTH_CHALLENGE_TTL: {e}")))?;
        }
        if let Ok(interval) = std::env::var("VTC_AUTH_SESSION_CLEANUP_INTERVAL") {
            config.auth.session_cleanup_interval = interval.parse().map_err(|e| {
                AppError::Config(format!("invalid VTC_AUTH_SESSION_CLEANUP_INTERVAL: {e}"))
            })?;
        }
        if let Ok(key) = std::env::var("VTC_AUTH_JWT_SIGNING_KEY") {
            config.auth.jwt_signing_key = Some(key);
        }

        config.validate_routing_and_cors()?;
        Ok(config)
    }

    /// Validate the routing + CORS sections per spec §9.2 / §9.3.
    /// Called at the tail of [`Self::load`]; surfaced as a
    /// public helper so tests can drive it directly without
    /// touching the filesystem.
    pub fn validate_routing_and_cors(&self) -> Result<(), AppError> {
        validate_routing(&self.routing)?;
        validate_cors(&self.cors)?;
        Ok(())
    }

    pub fn save(&self) -> Result<(), AppError> {
        self.validate_routing_and_cors()?;
        let contents = toml::to_string_pretty(self)
            .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;
        std::fs::write(&self.config_path, contents).map_err(AppError::Io)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Parse contract ──────────────────────────────────────────────
    //
    // These tests guard the on-disk config shape. A rename or a
    // missing #[serde(default)] here breaks every operator's
    // config.toml on upgrade.

    #[test]
    fn empty_toml_parses_with_all_defaults() {
        let config: AppConfig = toml::from_str("").expect("empty TOML must parse");
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8200, "VTC default port is 8200");
        assert!(config.vtc_did.is_none());
        assert!(config.vta_did.is_none());
        assert!(config.messaging.is_none());
    }

    #[test]
    fn minimal_toml_parses() {
        let toml_src = r#"
            vtc_did = "did:key:zVTC"
            vta_did = "did:key:zVTA"
        "#;
        let config: AppConfig = toml::from_str(toml_src).expect("minimal TOML must parse");
        assert_eq!(config.vtc_did.as_deref(), Some("did:key:zVTC"));
        assert_eq!(config.vta_did.as_deref(), Some("did:key:zVTA"));
    }

    #[test]
    fn community_name_alias_is_accepted() {
        // Backward-compat: older configs used `community_name` before
        // the rename to `vtc_name`. The serde alias preserves their
        // configs. Breaking this breaks existing operators.
        let toml_src = r#"
            community_name = "Alpha Community"
            community_description = "First VTC"
        "#;
        let config: AppConfig = toml::from_str(toml_src).expect("alias must parse");
        assert_eq!(config.vtc_name.as_deref(), Some("Alpha Community"));
        assert_eq!(config.vtc_description.as_deref(), Some("First VTC"));
    }

    #[test]
    fn vtc_name_canonical_field_is_accepted() {
        let toml_src = r#"
            vtc_name = "Alpha"
            vtc_description = "Canonical"
        "#;
        let config: AppConfig = toml::from_str(toml_src).expect("canonical name parses");
        assert_eq!(config.vtc_name.as_deref(), Some("Alpha"));
    }

    #[test]
    fn invalid_toml_produces_config_error() {
        let err = toml::from_str::<AppConfig>("server.port = \"not-a-number\"")
            .expect_err("invalid port type must fail parse");
        let msg = format!("{err}");
        assert!(msg.contains("port"), "error must name the field: {msg}");
    }

    #[test]
    fn server_port_bounds() {
        // u16 range enforced by serde — 70000 must fail.
        let toml_src = r#"
            [server]
            port = 70000
        "#;
        let err =
            toml::from_str::<AppConfig>(toml_src).expect_err("out-of-range port must not parse");
        assert!(format!("{err}").contains("port"), "got {err}");
    }

    #[test]
    fn secrets_config_keyring_service_defaults_to_vtc() {
        // Keyring service name is per-service — VTC uses "vtc" so it
        // doesn't collide with a VTA running on the same host.
        let empty: AppConfig = toml::from_str("").unwrap();
        assert_eq!(empty.secrets.keyring_service, "vtc");
    }

    #[test]
    fn secrets_unknown_key_is_a_named_parse_error() {
        // P0.8: a typo'd backend selector must be a loud parse error, not a
        // silently-dropped key that lets the factory fall through to the
        // default backend with an empty store.
        let toml_src = r#"
            [secrets]
            aws_secretname = "prod/vtc"
        "#;
        let err = toml::from_str::<AppConfig>(toml_src)
            .expect_err("unknown [secrets] key must not parse");
        let msg = format!("{err}");
        assert!(
            msg.contains("aws_secretname"),
            "error must name the offending key: {msg}"
        );
    }

    #[test]
    fn secrets_known_keys_still_parse() {
        // deny_unknown_fields must not reject the legitimate fields.
        let toml_src = r#"
            [secrets]
            keyring_service = "vtc-test"
            aws_secret_name = "prod/vtc"
            aws_region = "us-east-1"
        "#;
        let config: AppConfig = toml::from_str(toml_src).expect("known keys parse");
        assert_eq!(config.secrets.keyring_service, "vtc-test");
        assert_eq!(config.secrets.aws_secret_name.as_deref(), Some("prod/vtc"));
    }

    #[test]
    fn config_round_trip_preserves_fields() {
        // Serialize then parse — catches field additions that break
        // serialization symmetry (e.g. a serialize-only field that
        // can't parse back).
        let original: AppConfig = toml::from_str(
            r#"
            vtc_did = "did:key:zVTC"
            vta_did = "did:key:zVTA"
            vtc_name = "Round Trip"
            public_url = "https://vtc.example.com"
        "#,
        )
        .unwrap();

        let serialized = toml::to_string_pretty(&original).expect("serialize ok");
        let parsed: AppConfig = toml::from_str(&serialized).expect("re-parse ok");
        assert_eq!(parsed.vtc_did, original.vtc_did);
        assert_eq!(parsed.vta_did, original.vta_did);
        assert_eq!(parsed.vtc_name, original.vtc_name);
        assert_eq!(parsed.public_url, original.public_url);
    }
}
