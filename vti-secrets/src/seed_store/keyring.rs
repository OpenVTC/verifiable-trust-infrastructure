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

/// Explain an `Entry::new` failure in terms of the store, not the entry.
///
/// The dominant cause is that the platform store was never installed — the
/// process started on a host with no Secret Service, or with a locked keychain
/// — and `keyring-core` reports that as an entry-construction error. An
/// operator reading "failed to create keyring entry" has no way to tell that
/// apart from a bad service name, so name the likely cause and the choice.
fn entry_error(e: impl std::fmt::Display) -> AppError {
    AppError::SecretStore(format!(
        "the OS credential store is unavailable, so the master seed cannot be \
         reached: {e}. This is the `keyring` secrets backend; if this host has no \
         credential store, set `[secrets] backend` to one it does have (aws, gcp, \
         azure, vault, k8s). Refusing rather than treating the seed as absent."
    ))
}

impl super::SeedStore for KeyringSeedStore {
    fn get(&self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>> {
        let service = self.service.clone();
        let user = self.user.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let entry = keyring_core::Entry::new(&service, &user).map_err(entry_error)?;
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
                let entry = keyring_core::Entry::new(&service, &user).map_err(entry_error)?;
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
