use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    /// Port number. No default — each service must provide its own via
    /// `#[serde(default = "...")]` or by composing this struct.
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StoreConfig {
    /// Data directory. No default — each service provides its own
    /// (e.g., "data/vta" vs "data/vtc").
    pub data_dir: PathBuf,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    #[serde(default = "default_access_token_expiry")]
    pub access_token_expiry: u64,
    #[serde(default = "default_refresh_token_expiry")]
    pub refresh_token_expiry: u64,
    #[serde(default = "default_challenge_ttl")]
    pub challenge_ttl: u64,
    #[serde(default = "default_session_cleanup_interval")]
    pub session_cleanup_interval: u64,
    /// Base64url-no-pad encoded 32-byte Ed25519 private key for JWT signing.
    pub jwt_signing_key: Option<String>,
    /// AAL2 step-up policy. Defaults to disabled (AAL1 everywhere) — a fresh
    /// VTA has no approver registered, so step-up is opt-in once one exists.
    /// See `auth/step-up/policy/0.1`.
    #[serde(default)]
    pub step_up: crate::auth::step_up::StepUpPolicy,
}

// Manual Debug so a `tracing::debug!(?config, ...)`, panic-with-debug,
// or `format!("{:?}", app_config)` in a downstream crate cannot dump
// the JWT signing key into logs (which in enclave mode are forwarded
// over vsock to the host). Non-secret fields stay visible for
// diagnostics; `Serialize` is intentionally untouched since these
// structs round-trip to the on-disk config file.
impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("access_token_expiry", &self.access_token_expiry)
            .field("refresh_token_expiry", &self.refresh_token_expiry)
            .field("challenge_ttl", &self.challenge_ttl)
            .field("session_cleanup_interval", &self.session_cleanup_interval)
            .field(
                "jwt_signing_key",
                &self.jwt_signing_key.as_ref().map(|_| "<redacted>"),
            )
            .field("step_up", &self.step_up)
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MessagingConfig {
    /// Mediator URL. Optional — the TDK resolves the endpoint from mediator_did.
    /// Kept for display/status purposes and backward compatibility.
    #[serde(default)]
    pub mediator_url: String,
    pub mediator_did: String,
    /// Real external hostname of the mediator (e.g., "mediator.example.com").
    /// Used by the parent proxy to establish the TLS connection.
    /// Not used by the VTA itself (which connects via the local vsock proxy).
    #[serde(default)]
    pub mediator_host: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SecretsConfig {
    /// Hex-encoded key material (seed for VTA, secret for VTC).
    /// Uses serde aliases so both `seed` and `secret` are accepted in config files.
    #[serde(alias = "seed", alias = "secret")]
    pub inline_secret: Option<String>,
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
    /// No default — each service provides its own ("vta" or "vtc").
    pub keyring_service: String,
}

// Manual Debug — see `AuthConfig` impl for rationale. `inline_secret`
// is the master seed (VTA) or HMAC secret (VTC); leaking it via a
// stray `{:?}` would compromise every key derived from it.
impl std::fmt::Debug for SecretsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretsConfig")
            .field(
                "inline_secret",
                &self.inline_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("aws_secret_name", &self.aws_secret_name)
            .field("aws_region", &self.aws_region)
            .field("gcp_project", &self.gcp_project)
            .field("gcp_secret_name", &self.gcp_secret_name)
            .field("azure_vault_url", &self.azure_vault_url)
            .field("azure_secret_name", &self.azure_secret_name)
            .field("keyring_service", &self.keyring_service)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Number of days to retain audit logs (default 28).
    #[serde(default = "default_audit_retention_days")]
    pub retention_days: u32,
}

fn default_audit_retention_days() -> u32 {
    28
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            retention_days: default_audit_retention_days(),
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_access_token_expiry() -> u64 {
    900
}

fn default_refresh_token_expiry() -> u64 {
    86400
}

fn default_challenge_ttl() -> u64 {
    300
}

fn default_session_cleanup_interval() -> u64 {
    600
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            access_token_expiry: default_access_token_expiry(),
            refresh_token_expiry: default_refresh_token_expiry(),
            challenge_ttl: default_challenge_ttl(),
            session_cleanup_interval: default_session_cleanup_interval(),
            jwt_signing_key: None,
            step_up: crate::auth::step_up::StepUpPolicy::default(),
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `AuthConfig`'s Debug impl MUST NOT print the JWT signing key —
    /// it's the Ed25519 private key used to sign every access token. A
    /// stray `tracing::debug!(?config, ...)` or panic-with-debug
    /// formatter would otherwise dump it into logs.
    #[test]
    fn auth_config_debug_redacts_jwt_signing_key() {
        let cfg = AuthConfig {
            access_token_expiry: 900,
            refresh_token_expiry: 86400,
            challenge_ttl: 300,
            session_cleanup_interval: 600,
            jwt_signing_key: Some("SUPER_SECRET_KEY_MATERIAL_MUST_NOT_LEAK".into()),
            step_up: Default::default(),
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("SUPER_SECRET_KEY_MATERIAL"),
            "AuthConfig Debug leaked jwt_signing_key contents: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "expected redaction marker in Debug, got: {dbg}"
        );
        // Non-secret fields must remain visible for diagnostics.
        assert!(
            dbg.contains("900"),
            "access_token_expiry must still be visible: {dbg}"
        );
    }

    #[test]
    fn auth_config_debug_none_signing_key_renders_none() {
        let cfg = AuthConfig::default();
        let dbg = format!("{cfg:?}");
        // `Option<&str>` Debug prints `None` for the absent case.
        assert!(dbg.contains("jwt_signing_key: None"), "got: {dbg}");
    }

    /// `SecretsConfig.inline_secret` is the master seed (VTA) or HMAC
    /// secret (VTC). Same redaction discipline as `AuthConfig`.
    #[test]
    fn secrets_config_debug_redacts_inline_secret() {
        let cfg = SecretsConfig {
            inline_secret: Some("MASTER_SEED_HEX_MUST_NOT_LEAK".into()),
            aws_secret_name: None,
            aws_region: None,
            gcp_project: None,
            gcp_secret_name: None,
            azure_vault_url: None,
            azure_secret_name: None,
            keyring_service: "vta".into(),
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("MASTER_SEED_HEX"),
            "SecretsConfig Debug leaked inline_secret contents: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "expected redaction marker in Debug, got: {dbg}"
        );
        // Non-secret routing fields stay visible so the operator can
        // tell which backend is configured.
        assert!(
            dbg.contains("vta"),
            "keyring_service must be visible: {dbg}"
        );
    }

    /// Serialize must remain unaffected — these structs round-trip to
    /// the config file, and redacting them on serialize would break
    /// persistence. Use JSON here since serde_json is already a
    /// dev-dep; the wire format (TOML on disk) shares the same serde
    /// derive so this is sufficient to prove non-redaction.
    #[test]
    fn auth_config_serialize_still_carries_jwt_signing_key() {
        let cfg = AuthConfig {
            access_token_expiry: 900,
            refresh_token_expiry: 86400,
            challenge_ttl: 300,
            session_cleanup_interval: 600,
            jwt_signing_key: Some("key-material".into()),
            step_up: Default::default(),
        };
        let json = serde_json::to_string(&cfg).expect("serialize");
        assert!(
            json.contains("key-material"),
            "Serialize must not redact — config persistence relies on round-trip: {json}"
        );
    }
}
