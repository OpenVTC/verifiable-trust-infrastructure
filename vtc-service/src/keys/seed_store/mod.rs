//! VTC secret-store facade.
//!
//! The concrete backend implementations are shared with the VTA: they live in
//! the `vti-secrets` crate (issue #504 — dedup of the per-service copies that
//! had drifted). This module re-exports them under the VTC's `*SecretStore`
//! names and keeps the VTC-specific `create_secret_store` factory, which
//! preserves the VTC's own storage locations and fail-closed semantics:
//!
//! - keyring item name `vtc_secret` (not the VTA's `master_seed`);
//! - plaintext file `secret.plaintext` (not the VTA's `seed.plaintext`);
//! - Azure default secret name `vtc-secret`;
//! - `config-secret` / `secrets.secret` naming (not the VTA's `config-seed` /
//!   `secrets.seed`);
//! - a *set-but-not-compiled* backend selector is a hard `Config` error (P0.8),
//!   never a silent fall-through to keyring/plaintext;
//! - the plaintext fallback is the unconditional last resort with a warning
//!   (the VTA additionally gates it behind `allow_plaintext`).
//!
//! Reusing the implementations means a backend fix / new backend lands once and
//! both services benefit; keeping the factory here means the VTC's on-disk /
//! in-keyring locations are byte-for-byte unchanged for existing deployments.

use crate::config::AppConfig;
use crate::error::AppError;

// Backend implementations, shared with the VTA via `vti-secrets`, re-exported
// under the VTC's historical `*SecretStore` names.
#[cfg(feature = "aws-secrets")]
pub use vti_secrets::seed_store::AwsSeedStore as AwsSecretStore;
#[cfg(feature = "azure-secrets")]
pub use vti_secrets::seed_store::AzureSeedStore as AzureSecretStore;
#[cfg(feature = "config-secret")]
pub use vti_secrets::seed_store::ConfigSeedStore as ConfigSecretStore;
#[cfg(feature = "gcp-secrets")]
pub use vti_secrets::seed_store::GcpSeedStore as GcpSecretStore;
#[cfg(feature = "k8s-secrets")]
pub use vti_secrets::seed_store::K8sSeedStore as K8sSecretStore;
#[cfg(feature = "keyring")]
pub use vti_secrets::seed_store::KeyringSeedStore as KeyringSecretStore;
pub use vti_secrets::seed_store::PlaintextSeedStore as PlaintextSecretStore;

/// Store for VTC key material (64 bytes: 32 Ed25519 + 32 X25519).
/// Re-exports the shared SeedStore trait as SecretStore for VTC naming.
pub use vti_common::seed_store::SeedStore as SecretStore;

/// Filename the VTC plaintext backend uses under the data dir. Distinct from
/// the VTA's `seed.plaintext` so the two never collide and so existing VTC
/// deployments keep finding their secret.
const VTC_PLAINTEXT_FILENAME: &str = "secret.plaintext";

/// Create a secret store backend based on compiled features and configuration.
///
/// **Selection.** If `secrets.backend` is set it wins outright — the named
/// backend is used and its required field(s) are validated (a mismatch is a
/// hard `Config` error, never a silent pick of a different backend). If it is
/// unset (`None`), resolution falls back to the legacy implicit priority chain
/// below, keyed on which selector field is set:
///
/// 1. AWS Secrets Manager (if `aws-secrets` compiled + `secrets.aws_secret_name` set)
/// 2. GCP Secret Manager (if `gcp-secrets` compiled + `secrets.gcp_secret_name` set)
/// 3. Azure Key Vault (if `azure-secrets` compiled + `secrets.azure_vault_url` set)
/// 4. HashiCorp Vault (if `vault-secrets` compiled + `secrets.vault_addr` set)
/// 5. Kubernetes Secret (if `k8s-secrets` compiled + `secrets.k8s_secret_name` set)
/// 6. Config file secret (if `config-secret` compiled + `secrets.secret` set)
/// 7. OS keyring (if `keyring` compiled — the default)
/// 8. Plaintext file (always available — NOT secure)
///
/// Either way, a backend requested on a binary built without its feature is a
/// hard `Config` error — never a silent fall-through to keyring/plaintext
/// (P0.8): pre-P0.8 the arm was `#[cfg]`'d away, so a prod config pointing at
/// AWS on a keyring-only binary booted with an empty store and a mere `warn!`.
#[allow(unused_variables)]
pub fn create_secret_store(config: &AppConfig) -> Result<Box<dyn SecretStore>, AppError> {
    use crate::config::SecretBackend;
    let explicit = config.secrets.backend;

    // Is backend `b` the one to build? An explicit selector wins outright;
    // otherwise fall back to "its selector field is set" implicit resolution.
    // Used only for the cloud/config backends (keyring/plaintext are the tail
    // fallbacks, handled separately below).
    let wants = |b: SecretBackend, field_set: bool| match explicit {
        Some(sel) => sel == b,
        None => field_set,
    };

    #[cfg(feature = "aws-secrets")]
    if wants(SecretBackend::Aws, config.secrets.aws_secret_name.is_some()) {
        let name = config.secrets.aws_secret_name.clone().ok_or_else(|| {
            AppError::Config("secrets.backend = aws requires secrets.aws_secret_name".into())
        })?;
        let store = AwsSecretStore::new(name, config.secrets.aws_region.clone());
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "aws-secrets"))]
    if wants(SecretBackend::Aws, config.secrets.aws_secret_name.is_some()) {
        return Err(AppError::Config(
            "secrets backend 'aws' selected but this binary was built without the \
             'aws-secrets' feature"
                .into(),
        ));
    }

    #[cfg(feature = "gcp-secrets")]
    if wants(SecretBackend::Gcp, config.secrets.gcp_secret_name.is_some()) {
        let name = config.secrets.gcp_secret_name.clone().ok_or_else(|| {
            AppError::Config("secrets.backend = gcp requires secrets.gcp_secret_name".into())
        })?;
        let project = config.secrets.gcp_project.clone().ok_or_else(|| {
            AppError::Config(
                "secrets.gcp_project is required when secrets.gcp_secret_name is set".into(),
            )
        })?;
        let store = GcpSecretStore::new(project, name);
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "gcp-secrets"))]
    if wants(SecretBackend::Gcp, config.secrets.gcp_secret_name.is_some()) {
        return Err(AppError::Config(
            "secrets backend 'gcp' selected but this binary was built without the \
             'gcp-secrets' feature"
                .into(),
        ));
    }

    #[cfg(feature = "azure-secrets")]
    if wants(
        SecretBackend::Azure,
        config.secrets.azure_vault_url.is_some(),
    ) {
        let vault_url = config.secrets.azure_vault_url.clone().ok_or_else(|| {
            AppError::Config("secrets.backend = azure requires secrets.azure_vault_url".into())
        })?;
        let secret_name = config
            .secrets
            .azure_secret_name
            .clone()
            .unwrap_or_else(|| "vtc-secret".to_string());
        let store = AzureSecretStore::new(vault_url, secret_name);
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "azure-secrets"))]
    if wants(
        SecretBackend::Azure,
        config.secrets.azure_vault_url.is_some(),
    ) {
        return Err(AppError::Config(
            "secrets backend 'azure' selected but this binary was built without the \
             'azure-secrets' feature"
                .into(),
        ));
    }

    // HashiCorp Vault — reuses the shared `vti-secrets` Vault builder. The
    // VTC's `vault_*` config fields mirror the VTA's, so the auth-method
    // parsing is not duplicated here.
    #[cfg(feature = "vault-secrets")]
    if wants(SecretBackend::Vault, config.secrets.vault_addr.is_some()) {
        let s = &config.secrets;
        if s.vault_addr.is_none() {
            return Err(AppError::Config(
                "secrets.backend = vault requires secrets.vault_addr".into(),
            ));
        }
        let store =
            vti_secrets::seed_store::vault_from_params(&vti_secrets::seed_store::VaultParams {
                addr: s.vault_addr.as_deref(),
                namespace: s.vault_namespace.as_deref(),
                skip_verify: s.vault_skip_verify,
                secret_path: s.vault_secret_path.as_deref(),
                secret_key: &s.vault_secret_key,
                kv_mount: &s.vault_kv_mount,
                auth_method: &s.vault_auth_method,
                k8s_role: s.vault_k8s_role.as_deref(),
                k8s_mount: &s.vault_k8s_mount,
                k8s_jwt_path: &s.vault_k8s_jwt_path,
                token: s.vault_token.as_deref(),
                approle_role_id: s.vault_approle_role_id.as_deref(),
                approle_secret_id: s.vault_approle_secret_id.as_deref(),
                approle_mount: &s.vault_approle_mount,
            })?;
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "vault-secrets"))]
    if wants(SecretBackend::Vault, config.secrets.vault_addr.is_some()) {
        return Err(AppError::Config(
            "secrets backend 'vault' selected but this binary was built without the \
             'vault-secrets' feature"
                .into(),
        ));
    }

    #[cfg(feature = "k8s-secrets")]
    if wants(SecretBackend::K8s, config.secrets.k8s_secret_name.is_some()) {
        let name = config.secrets.k8s_secret_name.clone().ok_or_else(|| {
            AppError::Config("secrets.backend = k8s requires secrets.k8s_secret_name".into())
        })?;
        let store = K8sSecretStore::new(
            name,
            config.secrets.k8s_namespace.clone(),
            config.secrets.k8s_secret_key.clone(),
        );
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "k8s-secrets"))]
    if wants(SecretBackend::K8s, config.secrets.k8s_secret_name.is_some()) {
        return Err(AppError::Config(
            "secrets backend 'k8s' selected but this binary was built without the \
             'k8s-secrets' feature"
                .into(),
        ));
    }

    #[cfg(feature = "config-secret")]
    if wants(SecretBackend::Config, config.secrets.secret.is_some()) {
        let secret = config.secrets.secret.clone().ok_or_else(|| {
            AppError::Config("secrets.backend = config requires secrets.secret".into())
        })?;
        let store = ConfigSecretStore::new(secret);
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "config-secret"))]
    if wants(SecretBackend::Config, config.secrets.secret.is_some()) {
        return Err(AppError::Config(
            "secrets backend 'config' selected but this binary was built without the \
             'config-secret' feature"
                .into(),
        ));
    }

    // Keyring — the implicit default when nothing is selected, or an explicit
    // `backend = "keyring"`. An explicit keyring selection on a binary built
    // without the feature is a hard error (mirrors the cloud arms); the
    // implicit path just falls through to plaintext when keyring isn't compiled.
    #[cfg(not(feature = "keyring"))]
    if matches!(explicit, Some(SecretBackend::Keyring)) {
        return Err(AppError::Config(
            "secrets backend 'keyring' selected but this binary was built without the \
             'keyring' feature"
                .into(),
        ));
    }
    #[cfg(feature = "keyring")]
    if explicit.is_none() || matches!(explicit, Some(SecretBackend::Keyring)) {
        let store = KeyringSecretStore::new(&config.secrets.keyring_service, "vtc_secret");
        return Ok(Box::new(store));
    }

    // Plaintext — explicit `backend = "plaintext"`, or the unconditional last
    // resort when no keyring is compiled and nothing else matched.
    #[allow(unreachable_code)]
    {
        if !matches!(explicit, Some(SecretBackend::Plaintext)) {
            tracing::warn!(
                "no secure secret store backend available — falling back to plaintext file storage"
            );
        }
        let store =
            PlaintextSecretStore::with_filename(&config.store.data_dir, VTC_PLAINTEXT_FILENAME);
        Ok(Box::new(store))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> AppConfig {
        // Every `AppConfig` field is optional or has a serde default, so an
        // empty document yields an all-default config we can poke at.
        toml::from_str("").expect("empty config parses")
    }

    // The default test build compiles only `keyring` (see Cargo.toml
    // `default`), so the cloud/config backends are all "not compiled" here —
    // exactly the set-but-uncompiled case P0.8 must fail closed on.

    // `Box<dyn SecretStore>` is not `Debug`, so `expect_err` won't compile;
    // pattern-match the result instead.
    fn assert_config_err_mentions(config: &AppConfig, needle: &str) {
        match create_secret_store(config) {
            Err(AppError::Config(msg)) => {
                assert!(
                    msg.contains(needle),
                    "error should mention {needle:?}: {msg}"
                )
            }
            Err(other) => panic!("expected Config error, got {other:?}"),
            Ok(_) => panic!("expected a Config error, got a store (did the feature leak on?)"),
        }
    }

    #[test]
    fn aws_set_without_feature_is_config_error() {
        let mut config = base_config();
        config.secrets.aws_secret_name = Some("prod/vtc-secret".into());
        assert_config_err_mentions(&config, "aws-secrets");
    }

    #[test]
    fn gcp_set_without_feature_is_config_error() {
        let mut config = base_config();
        config.secrets.gcp_secret_name = Some("vtc-secret".into());
        assert_config_err_mentions(&config, "gcp-secrets");
    }

    #[test]
    fn azure_set_without_feature_is_config_error() {
        let mut config = base_config();
        config.secrets.azure_vault_url = Some("https://v.vault.azure.net".into());
        assert_config_err_mentions(&config, "azure-secrets");
    }

    #[test]
    fn config_secret_set_without_feature_is_config_error() {
        let mut config = base_config();
        config.secrets.secret = Some("ab".repeat(32));
        assert_config_err_mentions(&config, "config-secret");
    }

    #[test]
    fn k8s_set_without_feature_is_config_error() {
        let mut config = base_config();
        config.secrets.k8s_secret_name = Some("vtc-master-seed".into());
        assert_config_err_mentions(&config, "k8s-secrets");
    }

    #[test]
    fn vault_set_without_feature_is_config_error() {
        let mut config = base_config();
        config.secrets.vault_addr = Some("https://vault.internal:8200".into());
        assert_config_err_mentions(&config, "vault-secrets");
    }

    #[test]
    fn no_backend_set_falls_through_to_the_default() {
        // No selector field set → the compiled default (keyring) is chosen,
        // not an error. Guards must only fire when a backend is *requested*.
        let config = base_config();
        assert!(create_secret_store(&config).is_ok());
    }

    // ---- explicit `secrets.backend` selector ------------------------------

    use crate::config::SecretBackend;

    #[test]
    fn explicit_backend_uncompiled_is_config_error() {
        // `backend = "vault"` on the keyring-only default test build fails
        // closed (vault-secrets not compiled), same as the implicit path.
        let mut config = base_config();
        config.secrets.backend = Some(SecretBackend::Vault);
        assert_config_err_mentions(&config, "vault-secrets");
    }

    #[test]
    fn explicit_aws_uncompiled_is_config_error() {
        let mut config = base_config();
        config.secrets.backend = Some(SecretBackend::Aws);
        assert_config_err_mentions(&config, "aws-secrets");
    }

    #[test]
    fn explicit_keyring_selects_keyring() {
        let mut config = base_config();
        config.secrets.backend = Some(SecretBackend::Keyring);
        assert!(create_secret_store(&config).is_ok());
    }

    #[test]
    fn explicit_plaintext_selects_plaintext() {
        // Explicit plaintext is honoured even though keyring is compiled —
        // the keyring arm is skipped when an explicit non-keyring backend is
        // named.
        let mut config = base_config();
        config.secrets.backend = Some(SecretBackend::Plaintext);
        assert!(create_secret_store(&config).is_ok());
    }

    #[test]
    fn explicit_backend_overrides_a_stray_implicit_field() {
        // A leftover `vault_addr` would make the implicit path error (vault
        // not compiled here), but an explicit `backend = "keyring"` wins
        // outright and ignores it — no error, keyring selected.
        let mut config = base_config();
        config.secrets.vault_addr = Some("https://vault.internal:8200".into());
        config.secrets.backend = Some(SecretBackend::Keyring);
        assert!(
            create_secret_store(&config).is_ok(),
            "explicit backend must override a stray selector field"
        );
    }

    // Only meaningful when the feature is actually compiled: an explicit
    // backend whose required field is missing is a clear "requires" error
    // rather than a silent fall-through.
    #[cfg(feature = "vault-secrets")]
    #[test]
    fn explicit_vault_without_addr_reports_required_field() {
        let mut config = base_config();
        config.secrets.backend = Some(SecretBackend::Vault);
        // vault_addr deliberately left None.
        assert_config_err_mentions(&config, "requires secrets.vault_addr");
    }
}
