use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, PostParams};
use kube::{Client, ResourceExt};
use tracing::debug;

use crate::config::SecretsConfig;
use crate::error::AppError;

/// Format a `kube` error with its full source chain for troubleshooting —
/// the top-level `Display` is usually a terse "ApiError"/"HyperError" that
/// hides the actual cause (RBAC denial, DNS, TLS, …).
fn format_kube_error(context: &str, err: kube::Error) -> AppError {
    let mut msg = format!("{context}: {err}");
    let mut source = std::error::Error::source(&err);
    while let Some(cause) = source {
        msg.push_str(&format!("\n  caused by: {cause}"));
        source = cause.source();
    }
    AppError::SecretStore(msg)
}

/// Secret store backed by a Kubernetes `Secret`.
///
/// The VTC key material is stored as a hex-encoded string under `secret_key`
/// inside a namespaced `Secret` resource. Authentication is resolved by
/// [`Client::try_default`]: the in-cluster ServiceAccount when running inside
/// a pod, or the local kubeconfig (`~/.kube/config` / `$KUBECONFIG`) otherwise.
///
/// `namespace` is resolved at call time: the explicit config value if set,
/// otherwise the client's default namespace (the ServiceAccount's namespace
/// in-cluster, or the kubeconfig context's namespace), falling back to
/// `"default"` — all handled by `Client::default_namespace`.
pub struct K8sSecretStore {
    secret_name: String,
    namespace: Option<String>,
    secret_key: String,
}

impl K8sSecretStore {
    pub fn new(secret_name: String, namespace: Option<String>, secret_key: String) -> Self {
        Self {
            secret_name,
            namespace,
            secret_key,
        }
    }

    /// Build a namespaced `Secret` API handle, resolving the namespace and
    /// loading credentials from the in-cluster SA or local kubeconfig.
    async fn api(&self) -> Result<Api<Secret>, AppError> {
        let client = Client::try_default()
            .await
            .map_err(|e| format_kube_error("failed to initialise Kubernetes client", e))?;
        let namespace = self
            .namespace
            .clone()
            .unwrap_or_else(|| client.default_namespace().to_string());
        Ok(Api::namespaced(client, &namespace))
    }
}

/// Build the `k8s-secrets` backend from config. `k8s_secret_name` activates
/// the backend (checked by the caller); the namespace + data key fall back to
/// sensible defaults when unset.
pub fn from_config(secrets: &SecretsConfig) -> Result<K8sSecretStore, AppError> {
    let secret_name = secrets.k8s_secret_name.clone().ok_or_else(|| {
        AppError::Config("secrets.k8s_secret_name is required for the Kubernetes backend".into())
    })?;
    Ok(K8sSecretStore::new(
        secret_name,
        secrets.k8s_namespace.clone(),
        secrets.k8s_secret_key.clone(),
    ))
}

impl super::SecretStore for K8sSecretStore {
    fn get(&self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>> {
        Box::pin(async {
            let api = self.api().await?;
            // `get_opt` maps a 404 to `Ok(None)` for us — a missing Secret is
            // the legitimate first-boot case, not an error.
            let secret = api
                .get_opt(&self.secret_name)
                .await
                .map_err(|e| format_kube_error("failed to read Kubernetes Secret", e))?;

            let Some(secret) = secret else {
                debug!(secret = %self.secret_name, "Kubernetes Secret not found");
                return Ok(None);
            };

            let data = secret.data.unwrap_or_default();
            let Some(ByteString(raw)) = data.get(&self.secret_key) else {
                // The Secret exists but lacks our key. Returning `None` here
                // would make the caller think it is first-boot and re-bootstrap
                // the VTC identity, clobbering whatever the Secret holds. Fail
                // loudly instead.
                return Err(AppError::SecretStore(format!(
                    "Kubernetes Secret '{}' exists but has no '{}' key",
                    self.secret_name, self.secret_key
                )));
            };

            let hex_val = std::str::from_utf8(raw).map_err(|e| {
                AppError::SecretStore(format!("Kubernetes Secret value is not valid UTF-8: {e}"))
            })?;
            let bytes = hex::decode(hex_val.trim()).map_err(|e| {
                AppError::SecretStore(format!(
                    "failed to decode hex key material from Kubernetes: {e}"
                ))
            })?;
            debug!(secret = %self.secret_name, "VTC key material loaded from Kubernetes Secret");
            Ok(Some(bytes))
        })
    }

    fn set(&self, value: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let hex_val = hex::encode(value);
        Box::pin(async move {
            let api = self.api().await?;

            match api
                .get_opt(&self.secret_name)
                .await
                .map_err(|e| format_kube_error("failed to read Kubernetes Secret", e))?
            {
                Some(mut existing) => {
                    // Preserve any other keys on the Secret (and its
                    // resourceVersion, for optimistic concurrency); only touch
                    // our own data key. `string_data` is write-only and never
                    // round-trips on GET, so clear it before replacing.
                    let mut data = existing.data.take().unwrap_or_default();
                    data.insert(self.secret_key.clone(), ByteString(hex_val.into_bytes()));
                    existing.data = Some(data);
                    existing.string_data = None;
                    api.replace(&self.secret_name, &PostParams::default(), &existing)
                        .await
                        .map_err(|e| format_kube_error("failed to update Kubernetes Secret", e))?;
                    debug!(secret = %self.secret_name, "VTC key material stored in existing Kubernetes Secret");
                    Ok(())
                }
                None => {
                    let mut data = BTreeMap::new();
                    data.insert(self.secret_key.clone(), ByteString(hex_val.into_bytes()));
                    let secret = Secret {
                        metadata: ObjectMeta {
                            name: Some(self.secret_name.clone()),
                            ..Default::default()
                        },
                        data: Some(data),
                        type_: Some("Opaque".to_string()),
                        ..Default::default()
                    };
                    let created = api
                        .create(&PostParams::default(), &secret)
                        .await
                        .map_err(|e| format_kube_error("failed to create Kubernetes Secret", e))?;
                    debug!(secret = %created.name_any(), "VTC key material created in Kubernetes Secret");
                    Ok(())
                }
            }
        })
    }
}
