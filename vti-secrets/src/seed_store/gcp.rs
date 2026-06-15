use std::future::Future;
use std::pin::Pin;

use tracing::debug;
use vti_common::error::AppError;

/// Seed store backed by GCP Secret Manager.
///
/// The seed is stored as a hex-encoded string in the named secret.
/// GCP auth is resolved from the environment (service account, workload
/// identity, application default credentials, etc.).
pub struct GcpSeedStore {
    project: String,
    secret_name: String,
}

impl GcpSeedStore {
    pub fn new(project: String, secret_name: String) -> Self {
        Self {
            project,
            secret_name,
        }
    }

    fn secret_path(&self) -> String {
        format!("projects/{}/secrets/{}", self.project, self.secret_name)
    }

    fn latest_version_path(&self) -> String {
        format!("{}/versions/latest", self.secret_path())
    }

    async fn client(
        &self,
    ) -> Result<google_cloud_secretmanager_v1::client::SecretManagerService, AppError> {
        google_cloud_secretmanager_v1::client::SecretManagerService::builder()
            .build()
            .await
            .map_err(|e| AppError::SecretStore(format!("GCP Secret Manager client error: {e}")))
    }
}

impl super::SeedStore for GcpSeedStore {
    fn get(&self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client().await?;
            let result = client
                .access_secret_version()
                .set_name(self.latest_version_path())
                .send()
                .await;

            match result {
                Ok(response) => {
                    let payload = response.payload.ok_or_else(|| {
                        AppError::SecretStore("GCP secret version has no payload".into())
                    })?;
                    let hex_seed = String::from_utf8(payload.data.to_vec()).map_err(|e| {
                        AppError::SecretStore(format!("GCP secret payload is not valid UTF-8: {e}"))
                    })?;
                    let bytes = hex::decode(hex_seed.trim()).map_err(|e| {
                        AppError::SecretStore(format!("failed to decode hex seed from GCP: {e}"))
                    })?;
                    debug!(secret = %self.secret_name, "seed loaded from GCP Secret Manager");
                    Ok(Some(bytes))
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("NOT_FOUND") {
                        debug!(secret = %self.secret_name, "secret not found in GCP Secret Manager");
                        Ok(None)
                    } else {
                        Err(AppError::SecretStore(format!(
                            "GCP Secret Manager error: {e}"
                        )))
                    }
                }
            }
        })
    }

    fn set(&self, seed: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let hex_seed = hex::encode(seed);
        Box::pin(async move {
            let client = self.client().await?;

            // Try to add a new version to the existing secret
            let payload = google_cloud_secretmanager_v1::model::SecretPayload::new()
                .set_data(bytes::Bytes::from(hex_seed.clone()));
            let result = client
                .add_secret_version()
                .set_parent(self.secret_path())
                .set_payload(payload.clone())
                .send()
                .await;

            match result {
                Ok(_) => {
                    debug!(secret = %self.secret_name, "seed stored in GCP Secret Manager");
                    Ok(())
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("NOT_FOUND") {
                        // Create the secret first
                        let secret = google_cloud_secretmanager_v1::model::Secret::new()
                            .set_replication(
                                google_cloud_secretmanager_v1::model::Replication::new()
                                    .set_automatic(
                                        google_cloud_secretmanager_v1::model::replication::Automatic::default(),
                                    ),
                            );
                        client
                            .create_secret()
                            .set_parent(format!("projects/{}", self.project))
                            .set_secret_id(&self.secret_name)
                            .set_secret(secret)
                            .send()
                            .await
                            .map_err(|e| {
                                AppError::SecretStore(format!("failed to create GCP secret: {e}"))
                            })?;

                        // Now add the version
                        client
                            .add_secret_version()
                            .set_parent(self.secret_path())
                            .set_payload(payload)
                            .send()
                            .await
                            .map_err(|e| {
                                AppError::SecretStore(format!(
                                    "failed to add secret version in GCP: {e}"
                                ))
                            })?;

                        debug!(secret = %self.secret_name, "seed created in GCP Secret Manager");
                        Ok(())
                    } else {
                        Err(AppError::SecretStore(format!(
                            "failed to store seed in GCP: {e}"
                        )))
                    }
                }
            }
        })
    }
}
