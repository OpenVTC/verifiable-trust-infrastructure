//! Secret-store configuration.
//!
//! `SecretsConfig` selects which [`SeedStore`](crate::SeedStore) backend
//! [`create_seed_store`](crate::create_seed_store) builds, plus the
//! per-backend connection parameters. It is deserialised from the
//! `[secrets]` table of a service's config file; `vta-service` re-exports
//! this type so its `AppConfig` keeps a `secrets: SecretsConfig` field.

use serde::{Deserialize, Serialize};

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
    /// Kubernetes `Secret` name holding the hex-encoded seed
    /// (k8s-secrets feature). Setting this activates the Kubernetes
    /// backend.
    pub k8s_secret_name: Option<String>,
    /// Kubernetes namespace the `Secret` lives in (k8s-secrets feature).
    /// When unset, the in-cluster ServiceAccount namespace (or the
    /// kubeconfig context namespace) is used, falling back to `default`.
    pub k8s_namespace: Option<String>,
    /// Key within the `Secret`'s `data` map that holds the hex-encoded
    /// seed (k8s-secrets feature). Default `seed`.
    #[serde(default = "default_k8s_secret_key")]
    pub k8s_secret_key: String,
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

fn default_k8s_secret_key() -> String {
    "seed".to_string()
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
            k8s_secret_name: None,
            k8s_namespace: None,
            k8s_secret_key: default_k8s_secret_key(),
            allow_plaintext: false,
        }
    }
}
