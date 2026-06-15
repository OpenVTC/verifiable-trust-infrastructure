use std::future::Future;
use std::pin::Pin;

use tracing::debug;
use vti_common::error::AppError;

/// Seed store that reads a hex-encoded seed from the config.
///
/// Initialized from `[secrets] seed` in the config file. The seed is
/// read-only at runtime — to change it, update the config and restart.
pub struct ConfigSeedStore {
    hex_seed: String,
}

impl ConfigSeedStore {
    pub fn new(hex_seed: String) -> Self {
        Self { hex_seed }
    }
}

impl super::SeedStore for ConfigSeedStore {
    fn get(&self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>> {
        Box::pin(async {
            let bytes = hex::decode(&self.hex_seed).map_err(|e| {
                AppError::SecretStore(format!("failed to decode hex seed from config: {e}"))
            })?;
            debug!("seed loaded from config");
            Ok(Some(bytes))
        })
    }

    fn set(&self, _seed: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        Box::pin(async {
            Err(AppError::SecretStore(
                "config-seed backend is read-only at runtime; update [secrets] seed in config.toml"
                    .into(),
            ))
        })
    }
}
