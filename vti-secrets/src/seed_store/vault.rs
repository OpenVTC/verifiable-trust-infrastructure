use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OnceCell, RwLock};
use tracing::{debug, error, info, warn};
use vaultrs::auth::approle;
use vaultrs::auth::kubernetes;
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;
use vaultrs::kv2;

use vti_common::error::AppError;

/// Vault recommends renewing well before expiry; renewing at half the
/// lease keeps the token comfortably within its window even if a single
/// renewal request fails. The 10s floor stops very short test TTLs from
/// busy-looping.
const RENEW_FACTOR: u32 = 2;
const RENEW_MIN_INTERVAL: Duration = Duration::from_secs(10);
/// Backoff after a re-auth failure. Long enough that flapping doesn't
/// spam Vault; short enough that the VTA recovers quickly once it's back.
const RENEW_RETRY_INTERVAL: Duration = Duration::from_secs(30);
/// Polling cadence when Vault returned a non-renewable token (e.g.
/// static token auth). Picks up manual rotations without forcing the
/// renewal task to no-op forever.
const NON_RENEWABLE_POLL_INTERVAL: Duration = Duration::from_secs(300);

/// Authentication method for Vault. Each variant carries everything the
/// renewal task needs to re-authenticate from scratch when a lease can
/// no longer be renewed.
#[derive(Clone)]
enum VaultAuth {
    Kubernetes {
        mount: String,
        role: String,
        jwt_path: String,
    },
    Token {
        token: String,
    },
    AppRole {
        mount: String,
        role_id: String,
        secret_id: String,
    },
}

impl VaultAuth {
    /// Authenticate against Vault and return `(token, lease_secs, renewable)`.
    async fn login(&self, client: &VaultClient) -> Result<(String, u64, bool), ClientError> {
        match self {
            VaultAuth::Kubernetes {
                mount,
                role,
                jwt_path,
            } => {
                // SA JWTs are short-lived (kubelet rotates them ~1h by
                // default) so we re-read the file every time we authenticate.
                let jwt = std::fs::read_to_string(jwt_path).map_err(|e| {
                    ClientError::FileNotFoundError {
                        path: format!("{jwt_path}: {e}"),
                    }
                })?;
                let info = kubernetes::login(client, mount, role, jwt.trim()).await?;
                Ok((info.client_token, info.lease_duration, info.renewable))
            }
            VaultAuth::Token { token } => {
                // Static tokens have no auth-time lease; treat as
                // non-renewable. The renewal task will still poll
                // periodically in case the operator rotates the token.
                Ok((token.clone(), 0, false))
            }
            VaultAuth::AppRole {
                mount,
                role_id,
                secret_id,
            } => {
                let info = approle::login(client, mount, role_id, secret_id).await?;
                Ok((info.client_token, info.lease_duration, info.renewable))
            }
        }
    }
}

/// Connection parameters captured at construction time. The actual
/// `VaultClient` is built lazily on first use so `create_seed_store`
/// can stay synchronous (matching AWS/GCP/Azure).
struct ConnectParams {
    addr: String,
    namespace: Option<String>,
    skip_verify: bool,
    auth: VaultAuth,
}

/// A live Vault connection plus its background token-renewal task.
struct ConnectedState {
    client: Arc<RwLock<VaultClient>>,
    /// Held so we can abort the renewal task on `Drop`.
    renewal_task: tokio::task::JoinHandle<()>,
}

impl Drop for ConnectedState {
    fn drop(&mut self) {
        self.renewal_task.abort();
    }
}

/// Seed store backed by HashiCorp Vault's KV v2 engine.
///
/// Authenticates via Kubernetes ServiceAccount JWT (default), a static
/// token, or AppRole. The Vault token is auto-renewed in a background
/// task; if a renewal fails (max-TTL reached, lease expired) the task
/// re-authenticates from scratch using the configured method.
///
/// The seed is stored as a hex-encoded string under
/// `secret_path` -> `secret_key` (default `seed`).
pub struct VaultSeedStore {
    /// Lazily initialised on first `get` / `set` / `delete` call.
    state: OnceCell<ConnectedState>,
    params: ConnectParams,
    secret_path: String,
    secret_key: String,
    kv_mount: String,
}

impl VaultSeedStore {
    fn new(
        addr: String,
        namespace: Option<String>,
        skip_verify: bool,
        secret_path: String,
        secret_key: String,
        kv_mount: String,
        auth: VaultAuth,
    ) -> Self {
        Self {
            state: OnceCell::new(),
            params: ConnectParams {
                addr,
                namespace,
                skip_verify,
                auth,
            },
            secret_path,
            secret_key,
            kv_mount,
        }
    }

    /// Lazily build the Vault client, authenticate, and spawn the
    /// renewal task. Subsequent calls reuse the same connection.
    async fn connect(&self) -> Result<&Arc<RwLock<VaultClient>>, AppError> {
        let state = self
            .state
            .get_or_try_init(|| async {
                let mut builder = VaultClientSettingsBuilder::default();
                builder
                    .address(self.params.addr.as_str())
                    .verify(!self.params.skip_verify);
                if let Some(ref ns) = self.params.namespace {
                    builder.namespace(Some(ns.clone()));
                }
                let settings = builder
                    .build()
                    .map_err(|e| AppError::Config(format!("invalid Vault settings: {e}")))?;
                let mut client = VaultClient::new(settings).map_err(|e| {
                    AppError::SecretStore(format!("failed to build Vault client: {e}"))
                })?;

                let (token, lease, renewable) =
                    self.params.auth.login(&client).await.map_err(|e| {
                        AppError::SecretStore(format!("Vault authentication failed: {e}"))
                    })?;
                client.set_token(&token);
                info!(
                    addr = %self.params.addr,
                    renewable,
                    lease_secs = lease,
                    "authenticated to Vault"
                );

                let client = Arc::new(RwLock::new(client));
                let renewal_task = spawn_renewal_task(
                    Arc::clone(&client),
                    self.params.auth.clone(),
                    lease,
                    renewable,
                );
                Ok::<_, AppError>(ConnectedState {
                    client,
                    renewal_task,
                })
            })
            .await?;
        Ok(&state.client)
    }
}

/// Spawn the background task that renews the Vault token before its
/// lease expires, falling back to full re-auth when the lease can no
/// longer be extended.
fn spawn_renewal_task(
    client: Arc<RwLock<VaultClient>>,
    auth: VaultAuth,
    initial_lease: u64,
    renewable: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut current_lease = initial_lease;
        let mut current_renewable = renewable;
        loop {
            let sleep = if current_lease == 0 {
                NON_RENEWABLE_POLL_INTERVAL
            } else {
                Duration::from_secs((current_lease / RENEW_FACTOR as u64).max(1))
                    .max(RENEW_MIN_INTERVAL)
            };
            debug!(?sleep, current_lease, "vault renewal task sleeping");
            tokio::time::sleep(sleep).await;

            if current_renewable {
                let renew_result = {
                    let c = client.read().await;
                    c.renew(None).await
                };
                match renew_result {
                    Ok(info) => {
                        current_lease = info.lease_duration;
                        current_renewable = info.renewable;
                        debug!(lease_secs = current_lease, "vault token renewed");
                        continue;
                    }
                    Err(e) => {
                        warn!("vault token renewal failed: {e} — re-authenticating");
                    }
                }
            }

            // Re-auth from scratch (covers max-TTL exhaustion and the
            // non-renewable poll path).
            let login_result = {
                let c = client.read().await;
                auth.login(&c).await
            };
            match login_result {
                Ok((token, lease, renewable)) => {
                    let mut c = client.write().await;
                    c.set_token(&token);
                    current_lease = lease;
                    current_renewable = renewable;
                    info!(lease_secs = lease, renewable, "vault re-authenticated");
                }
                Err(e) => {
                    error!(
                        "vault re-authentication failed: {e} — retrying in {}s",
                        RENEW_RETRY_INTERVAL.as_secs()
                    );
                    tokio::time::sleep(RENEW_RETRY_INTERVAL).await;
                }
            }
        }
    })
}

impl super::SeedStore for VaultSeedStore {
    fn get(&self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.connect().await?;
            let client = client.read().await;
            let result: Result<HashMap<String, String>, ClientError> =
                kv2::read(&*client, &self.kv_mount, &self.secret_path).await;
            match result {
                Ok(map) => {
                    let hex_seed = map.get(&self.secret_key).ok_or_else(|| {
                        AppError::SecretStore(format!(
                            "Vault secret at {}/{} has no field '{}'",
                            self.kv_mount, self.secret_path, self.secret_key
                        ))
                    })?;
                    let bytes = hex::decode(hex_seed.trim()).map_err(|e| {
                        AppError::SecretStore(format!("failed to decode hex seed from Vault: {e}"))
                    })?;
                    debug!(path = %self.secret_path, "seed loaded from Vault");
                    Ok(Some(bytes))
                }
                Err(ClientError::APIError { code: 404, .. }) => {
                    debug!(path = %self.secret_path, "secret not found in Vault");
                    Ok(None)
                }
                Err(e) => Err(AppError::SecretStore(format!(
                    "failed to read seed from Vault: {e}"
                ))),
            }
        })
    }

    fn set(&self, seed: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let hex_seed = hex::encode(seed);
        Box::pin(async move {
            let client = self.connect().await?;
            let client = client.read().await;
            let mut payload = HashMap::new();
            payload.insert(self.secret_key.clone(), hex_seed);
            kv2::set(&*client, &self.kv_mount, &self.secret_path, &payload)
                .await
                .map_err(|e| {
                    AppError::SecretStore(format!("failed to store seed in Vault: {e}"))
                })?;
            debug!(path = %self.secret_path, "seed stored in Vault");
            Ok(())
        })
    }

    fn delete(&self) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.connect().await?;
            let client = client.read().await;
            kv2::delete_latest(&*client, &self.kv_mount, &self.secret_path)
                .await
                .map_err(|e| {
                    AppError::SecretStore(format!("failed to delete seed from Vault: {e}"))
                })?;
            debug!(path = %self.secret_path, "seed deleted in Vault (latest version)");
            Ok(())
        })
    }
}

/// Build a [`VaultSeedStore`] from the workspace [`SecretsConfig`].
/// Validates the auth-method-specific fields and surfaces actionable
/// errors when something required is missing.
pub fn from_config(secrets: &crate::config::SecretsConfig) -> Result<VaultSeedStore, AppError> {
    let addr = secrets
        .vault_addr
        .clone()
        .ok_or_else(|| AppError::Config("secrets.vault_addr is required".into()))?;
    let path = secrets.vault_secret_path.clone().ok_or_else(|| {
        AppError::Config(
            "secrets.vault_secret_path is required when secrets.vault_addr is set".into(),
        )
    })?;

    let auth = match secrets.vault_auth_method.as_str() {
        "kubernetes" => {
            let role = secrets.vault_k8s_role.clone().ok_or_else(|| {
                AppError::Config(
                    "secrets.vault_k8s_role is required for kubernetes auth method".into(),
                )
            })?;
            VaultAuth::Kubernetes {
                mount: secrets.vault_k8s_mount.clone(),
                role,
                jwt_path: secrets.vault_k8s_jwt_path.clone(),
            }
        }
        "token" => {
            let token = secrets
                .vault_token
                .clone()
                .or_else(|| std::env::var("VAULT_TOKEN").ok())
                .ok_or_else(|| {
                    AppError::Config(
                        "token auth requires secrets.vault_token or the VAULT_TOKEN env var".into(),
                    )
                })?;
            VaultAuth::Token { token }
        }
        "approle" => {
            let role_id = secrets.vault_approle_role_id.clone().ok_or_else(|| {
                AppError::Config("secrets.vault_approle_role_id is required for approle".into())
            })?;
            let secret_id = secrets.vault_approle_secret_id.clone().ok_or_else(|| {
                AppError::Config("secrets.vault_approle_secret_id is required for approle".into())
            })?;
            VaultAuth::AppRole {
                mount: secrets.vault_approle_mount.clone(),
                role_id,
                secret_id,
            }
        }
        other => {
            return Err(AppError::Config(format!(
                "unknown secrets.vault_auth_method '{other}', expected kubernetes|token|approle"
            )));
        }
    };

    Ok(VaultSeedStore::new(
        addr,
        secrets.vault_namespace.clone(),
        secrets.vault_skip_verify,
        path,
        secrets.vault_secret_key.clone(),
        secrets.vault_kv_mount.clone(),
        auth,
    ))
}
