#[cfg(feature = "aws-secrets")]
mod aws;
#[cfg(feature = "azure-secrets")]
mod azure;
#[cfg(feature = "config-seed")]
mod config;
#[cfg(feature = "gcp-secrets")]
mod gcp;
#[cfg(feature = "k8s-secrets")]
mod k8s;
#[cfg(feature = "keyring")]
mod keyring;
#[cfg(feature = "tee")]
pub mod kms_tee;
mod plaintext;
#[cfg(feature = "vault-secrets")]
mod vault;

#[cfg(feature = "aws-secrets")]
pub use aws::AwsSeedStore;
#[cfg(feature = "azure-secrets")]
pub use azure::AzureSeedStore;
#[cfg(feature = "config-seed")]
pub use config::ConfigSeedStore;
#[cfg(feature = "gcp-secrets")]
pub use gcp::GcpSeedStore;
#[cfg(feature = "k8s-secrets")]
pub use k8s::{K8sSeedStore, from_config as k8s_from_config};
#[cfg(feature = "keyring")]
pub use keyring::KeyringSeedStore;
#[cfg(feature = "tee")]
pub use kms_tee::KmsTeeSeedStore;
pub use plaintext::PlaintextSeedStore;
#[cfg(feature = "vault-secrets")]
pub use vault::{VaultSeedStore, from_config as vault_from_config};

#[cfg(feature = "tee")]
use std::future::Future;
#[cfg(feature = "tee")]
use std::pin::Pin;

use std::path::Path;

use crate::config::SecretsConfig;
use vti_common::error::AppError;

pub use vti_common::seed_store::SeedStore;

/// Local boxed-future alias mirroring `vti_common::seed_store::BoxFuture`,
/// used by the in-crate `kms_tee` backend's trait impl. Only compiled when
/// the `tee` feature pulls in that backend.
#[cfg(feature = "tee")]
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Create a seed store backend based on compiled features and configuration.
///
/// `secrets` is the resolved [`SecretsConfig`] (which backend + its
/// connection parameters); `data_dir` is only consulted by the plaintext
/// fallback for the `seed.plaintext` location.
///
/// Priority:
/// 1. AWS Secrets Manager (if `aws-secrets` compiled + `aws_secret_name` set)
/// 2. GCP Secret Manager (if `gcp-secrets` compiled + `gcp_secret_name` set)
/// 3. Azure Key Vault (if `azure-secrets` compiled + `azure_vault_url` set)
/// 4. HashiCorp Vault (if `vault-secrets` compiled + `vault_addr` set)
/// 5. Kubernetes Secret (if `k8s-secrets` compiled + `k8s_secret_name` set)
/// 6. Config file seed (if `config-seed` compiled + `seed` set)
/// 7. OS keyring (if `keyring` compiled — the default)
/// 8. Plaintext file (always available — NOT secure)
///
/// `unused_variables` allowed: `secrets` / `data_dir` are only read under
/// specific feature flags; a build with none of the cloud/keyring/config-seed
/// features compiled leaves them unused, which is fine — we fall through
/// to the plaintext backend. rustc's dead-code lint can't see through
/// the cfg-gated early returns.
#[allow(unused_variables)]
pub fn create_seed_store(
    secrets: &SecretsConfig,
    data_dir: &Path,
) -> Result<Box<dyn SeedStore>, AppError> {
    #[cfg(feature = "aws-secrets")]
    if secrets.aws_secret_name.is_some() {
        let store = AwsSeedStore::new(
            secrets.aws_secret_name.clone().unwrap(),
            secrets.aws_region.clone(),
        );
        return Ok(Box::new(store));
    }

    #[cfg(feature = "gcp-secrets")]
    if secrets.gcp_secret_name.is_some() {
        let project = secrets.gcp_project.clone().ok_or_else(|| {
            AppError::Config(
                "secrets.gcp_project is required when secrets.gcp_secret_name is set".into(),
            )
        })?;
        let store = GcpSeedStore::new(project, secrets.gcp_secret_name.clone().unwrap());
        return Ok(Box::new(store));
    }

    #[cfg(feature = "azure-secrets")]
    if secrets.azure_vault_url.is_some() {
        let vault_url = secrets.azure_vault_url.clone().unwrap();
        let secret_name = secrets
            .azure_secret_name
            .clone()
            .unwrap_or_else(|| "vta-master-seed".to_string());
        let store = AzureSeedStore::new(vault_url, secret_name);
        return Ok(Box::new(store));
    }

    #[cfg(feature = "vault-secrets")]
    if secrets.vault_addr.is_some() {
        let store = vault::from_config(secrets)?;
        return Ok(Box::new(store));
    }

    #[cfg(feature = "k8s-secrets")]
    if secrets.k8s_secret_name.is_some() {
        let store = k8s::from_config(secrets)?;
        return Ok(Box::new(store));
    }

    #[cfg(feature = "config-seed")]
    if secrets.seed.is_some() {
        let store = ConfigSeedStore::new(secrets.seed.clone().unwrap());
        return Ok(Box::new(store));
    }

    #[cfg(feature = "keyring")]
    {
        let store = KeyringSeedStore::new(&secrets.keyring_service, "master_seed");
        return Ok(Box::new(store));
    }

    // `unreachable_code` allowed: each of the `return Ok(...)` branches above
    // is `cfg(feature = ...)`-gated, so with every secure-backend feature
    // enabled (or none of them), this tail is or isn't actually reached.
    // Rustc can't resolve the combined cfg math — the allow is load-bearing
    // only when `keyring` is the selected feature.
    #[allow(unreachable_code)]
    {
        // No secure backend was compiled-in AND configured. Writing the
        // BIP-32 master seed to a plaintext file is a real footgun (one
        // wrong/missing TOML key would silently do it), so require an
        // explicit opt-in rather than falling through silently (P0.9).
        if !secrets.allow_plaintext {
            return Err(AppError::Config(
                "no secure seed-store backend is available (keyring/cloud/Vault/config-seed \
                 not compiled-in or not configured), and the plaintext file fallback is \
                 disabled. Configure a secure backend, or set `secrets.allow_plaintext = true` \
                 to explicitly accept storing the master seed in a cleartext file (dev/test only)."
                    .into(),
            ));
        }
        tracing::warn!(
            "secrets.allow_plaintext = true — storing the BIP-32 master seed in a PLAINTEXT \
             file. This is NOT secure; use a keyring or cloud/Vault backend in production."
        );
        let store = PlaintextSeedStore::new(data_dir);
        Ok(Box::new(store))
    }
}
