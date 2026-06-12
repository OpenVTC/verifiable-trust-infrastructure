#[cfg(feature = "aws-secrets")]
mod aws;
#[cfg(feature = "azure-secrets")]
mod azure;
#[cfg(feature = "config-secret")]
mod config;
#[cfg(feature = "gcp-secrets")]
mod gcp;
#[cfg(feature = "keyring")]
mod keyring;
mod plaintext;

#[cfg(feature = "aws-secrets")]
pub use aws::AwsSecretStore;
#[cfg(feature = "azure-secrets")]
pub use azure::AzureSecretStore;
#[cfg(feature = "config-secret")]
pub use config::ConfigSecretStore;
#[cfg(feature = "gcp-secrets")]
pub use gcp::GcpSecretStore;
#[cfg(feature = "keyring")]
pub use keyring::KeyringSecretStore;
pub use plaintext::PlaintextSecretStore;

use crate::config::AppConfig;
use crate::error::AppError;

/// Store for VTC key material (64 bytes: 32 Ed25519 + 32 X25519).
/// Re-exports the shared SeedStore trait as SecretStore for VTC naming.
pub use vti_common::seed_store::SeedStore as SecretStore;

/// Create a secret store backend based on compiled features and configuration.
///
/// Priority:
/// 1. AWS Secrets Manager (if `aws-secrets` compiled + `secrets.aws_secret_name` set)
/// 2. GCP Secret Manager (if `gcp-secrets` compiled + `secrets.gcp_secret_name` set)
/// 3. Azure Key Vault (if `azure-secrets` compiled + `secrets.azure_vault_url` set)
/// 4. Config file secret (if `config-secret` compiled + `secrets.secret` set)
/// 5. OS keyring (if `keyring` compiled — the default)
/// 6. Plaintext file (always available — NOT secure)
#[allow(unused_variables)]
pub fn create_secret_store(config: &AppConfig) -> Result<Box<dyn SecretStore>, AppError> {
    // For every cloud/config backend, a set selector field on a binary that
    // wasn't compiled with the matching feature is a hard error — never a
    // silent fall-through to the keyring/plaintext default. Pre-P0.8 the arm
    // was simply `#[cfg]`'d away, so a production config pointing at AWS on a
    // keyring-only binary booted with an empty store and a mere `warn!`
    // (every auth/issue/install call then 503s). Fail closed instead.
    #[cfg(feature = "aws-secrets")]
    if config.secrets.aws_secret_name.is_some() {
        let store = AwsSecretStore::new(
            config.secrets.aws_secret_name.clone().unwrap(),
            config.secrets.aws_region.clone(),
        );
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "aws-secrets"))]
    if config.secrets.aws_secret_name.is_some() {
        return Err(AppError::Config(
            "secrets.aws_secret_name is set but this binary was built without the \
             'aws-secrets' feature"
                .into(),
        ));
    }

    #[cfg(feature = "gcp-secrets")]
    if config.secrets.gcp_secret_name.is_some() {
        let project = config.secrets.gcp_project.clone().ok_or_else(|| {
            AppError::Config(
                "secrets.gcp_project is required when secrets.gcp_secret_name is set".into(),
            )
        })?;
        let store = GcpSecretStore::new(project, config.secrets.gcp_secret_name.clone().unwrap());
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "gcp-secrets"))]
    if config.secrets.gcp_secret_name.is_some() {
        return Err(AppError::Config(
            "secrets.gcp_secret_name is set but this binary was built without the \
             'gcp-secrets' feature"
                .into(),
        ));
    }

    #[cfg(feature = "azure-secrets")]
    if config.secrets.azure_vault_url.is_some() {
        let vault_url = config.secrets.azure_vault_url.clone().unwrap();
        let secret_name = config
            .secrets
            .azure_secret_name
            .clone()
            .unwrap_or_else(|| "vtc-secret".to_string());
        let store = AzureSecretStore::new(vault_url, secret_name);
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "azure-secrets"))]
    if config.secrets.azure_vault_url.is_some() {
        return Err(AppError::Config(
            "secrets.azure_vault_url is set but this binary was built without the \
             'azure-secrets' feature"
                .into(),
        ));
    }

    #[cfg(feature = "config-secret")]
    if config.secrets.secret.is_some() {
        let store = ConfigSecretStore::new(config.secrets.secret.clone().unwrap());
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "config-secret"))]
    if config.secrets.secret.is_some() {
        return Err(AppError::Config(
            "secrets.secret is set but this binary was built without the \
             'config-secret' feature"
                .into(),
        ));
    }

    #[cfg(feature = "keyring")]
    {
        let store = KeyringSecretStore::new(&config.secrets.keyring_service, "vtc_secret");
        return Ok(Box::new(store));
    }

    #[allow(unreachable_code)]
    {
        tracing::warn!(
            "no secure secret store backend available — falling back to plaintext file storage"
        );
        let store = PlaintextSecretStore::new(&config.store.data_dir);
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
    fn no_backend_set_falls_through_to_the_default() {
        // No selector field set → the compiled default (keyring) is chosen,
        // not an error. Guards must only fire when a backend is *requested*.
        let config = base_config();
        assert!(create_secret_store(&config).is_ok());
    }
}
