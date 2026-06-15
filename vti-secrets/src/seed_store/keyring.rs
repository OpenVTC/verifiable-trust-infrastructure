use std::future::Future;
use std::pin::Pin;

use tracing::debug;
use vti_common::error::AppError;

pub struct KeyringSeedStore {
    service: String,
    user: String,
}

impl KeyringSeedStore {
    pub fn new(service: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            user: user.into(),
        }
    }
}

impl super::SeedStore for KeyringSeedStore {
    fn get(&self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>> {
        let service = self.service.clone();
        let user = self.user.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let entry = keyring_core::Entry::new(&service, &user).map_err(|e| {
                    AppError::SecretStore(format!("failed to create keyring entry: {e}"))
                })?;
                match entry.get_password() {
                    Ok(hex_seed) => {
                        let bytes = hex::decode(&hex_seed).map_err(|e| {
                            AppError::SecretStore(format!("failed to decode seed: {e}"))
                        })?;
                        debug!("seed loaded from keyring");
                        Ok(Some(bytes))
                    }
                    Err(keyring_core::Error::NoEntry) => {
                        debug!("no seed found in keyring");
                        Ok(None)
                    }
                    Err(e) => Err(AppError::SecretStore(format!("failed to read seed: {e}"))),
                }
            })
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
        })
    }

    fn set(&self, seed: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let service = self.service.clone();
        let user = self.user.clone();
        let hex_seed = hex::encode(seed);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let entry = keyring_core::Entry::new(&service, &user).map_err(|e| {
                    AppError::SecretStore(format!("failed to create keyring entry: {e}"))
                })?;
                entry
                    .set_password(&hex_seed)
                    .map_err(|e| AppError::SecretStore(format!("failed to store seed: {e}")))?;
                debug!("seed stored in keyring");
                Ok(())
            })
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
        })
    }
}
