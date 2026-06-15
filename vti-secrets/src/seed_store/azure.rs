use std::future::Future;
use std::pin::Pin;

use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_secrets::SecretClient;
use tracing::debug;

use vti_common::error::AppError;

/// Seed store backed by Azure Key Vault.
///
/// The seed is stored as a hex-encoded string in the named secret.
/// Azure credentials are resolved via `DeveloperToolsCredential` (Azure CLI,
/// Developer CLI, etc.) for development, or other credential types in production.
pub struct AzureSeedStore {
    vault_url: String,
    secret_name: String,
}

impl AzureSeedStore {
    pub fn new(vault_url: String, secret_name: String) -> Self {
        Self {
            vault_url,
            secret_name,
        }
    }

    fn client(&self) -> Result<SecretClient, AppError> {
        let credential = DeveloperToolsCredential::new(None)
            .map_err(|e| AppError::SecretStore(format!("Azure credential error: {e}")))?;
        SecretClient::new(&self.vault_url, credential, None)
            .map_err(|e| AppError::SecretStore(format!("Azure Key Vault client error: {e}")))
    }
}

impl super::SeedStore for AzureSeedStore {
    fn get(&self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client()?;
            let result = client.get_secret(&self.secret_name, None).await;

            match result {
                Ok(response) => {
                    let secret = response
                        .into_model()
                        .map_err(|e| AppError::SecretStore(format!("Azure response error: {e}")))?;
                    let hex_seed = secret.value.ok_or_else(|| {
                        AppError::SecretStore("Azure secret exists but has no value".into())
                    })?;
                    let bytes = hex::decode(&hex_seed).map_err(|e| {
                        AppError::SecretStore(format!("failed to decode hex seed from Azure: {e}"))
                    })?;
                    debug!(secret_name = %self.secret_name, "seed loaded from Azure Key Vault");
                    Ok(Some(bytes))
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("SecretNotFound") || msg.contains("404") {
                        debug!(secret_name = %self.secret_name, "secret not found in Azure Key Vault");
                        Ok(None)
                    } else {
                        Err(AppError::SecretStore(format!("Azure Key Vault error: {e}")))
                    }
                }
            }
        })
    }

    fn set(&self, seed: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let hex_seed = hex::encode(seed);
        Box::pin(async move {
            let client = self.client()?;

            // Azure Key Vault set_secret creates-or-updates automatically
            let params = azure_security_keyvault_secrets::models::SetSecretParameters {
                value: Some(hex_seed),
                ..Default::default()
            };
            let body = params
                .try_into()
                .map_err(|e| AppError::SecretStore(format!("Azure request error: {e}")))?;
            client
                .set_secret(&self.secret_name, body, None)
                .await
                .map_err(|e| {
                    AppError::SecretStore(format!("failed to store seed in Azure Key Vault: {e}"))
                })?;

            debug!(secret_name = %self.secret_name, "seed stored in Azure Key Vault");
            Ok(())
        })
    }
}
