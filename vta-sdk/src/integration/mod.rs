//! Unified VTA integration for service startup.
//!
//! Provides a single startup pattern for any service that manages its DID and
//! secrets through a VTA:
//!
//! 1. Authenticate to the VTA. Tier order is determined by
//!    [`TransportPreference`]: DIDComm first when a mediator is available
//!    (identity-native, no separate auth round-trip), with lightweight REST
//!    + session-REST as fallbacks.
//! 2. Fetch the latest [`DidSecretsBundle`] from the VTA context.
//! 3. Cache the bundle locally for offline resilience.
//! 4. If the VTA is unreachable, load the last cached bundle.
//!
//! # Usage
//!
//! ```ignore
//! use vta_sdk::integration::{startup, VtaServiceConfig, SecretCache};
//!
//! // Implement SecretCache for your storage backend (keyring, AWS, etc.)
//! struct MyCache { /* ... */ }
//! impl SecretCache for MyCache { /* ... */ }
//!
//! // Quick path — defaults everywhere:
//! let config = VtaServiceConfig::new(loaded_credential_bundle, "my-service");
//!
//! // Or build explicitly when you need to tweak specific fields:
//! // let config = VtaServiceConfig {
//! //     auth: VtaAuthConfig { credential, url_override: None, timeout: None },
//! //     context: VtaContextConfig {
//! //         id: "my-service".into(),
//! //         mediator_did: None,        // auto-resolve from VTA DID doc
//! //         transport_preference: Default::default(), // Auto
//! //         did_resolver: None,        // SDK makes a one-shot on demand
//! //     },
//! // };
//!
//! let cache = MyCache::new();
//!
//! let result = startup(&config, &cache).await?;
//! // result.did — the service's DID
//! // result.bundle.secrets — Vec<SecretEntry> for DIDComm/signing
//! // result.source — whether secrets came from VTA or cache
//! ```

pub mod auth;
pub mod cache;

pub use auth::authenticate;
pub use cache::SecretCache;

use crate::did_secrets::DidSecretsBundle;
use crate::error::VtaError;
use std::time::Duration;

/// Default timeout for the entire VTA startup flow (auth + secret fetch).
const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// "Who am I talking to" — credential + REST endpoint + overall
/// timeout. Shape every integration needs regardless of whether it
/// operates in a single context or many.
#[derive(Clone, Debug)]
pub struct VtaAuthConfig {
    /// VTA credential bundle (identity + signing key + VTA DID/URL).
    pub credential: crate::credentials::CredentialBundle,
    /// Optional REST URL override. When set, bypasses the URL embedded
    /// in the credential (useful for VTARest service discovery or
    /// dev/testing).
    pub url_override: Option<String>,
    /// Timeout for the VTA startup flow (auth + secret fetch).
    /// Defaults to 30 seconds if `None`.
    pub timeout: Option<Duration>,
}

impl VtaAuthConfig {
    /// Minimal constructor — just a credential, everything else left
    /// as defaults.
    pub fn new(credential: crate::credentials::CredentialBundle) -> Self {
        Self {
            credential,
            url_override: None,
            timeout: None,
        }
    }
}

/// "Where in that VTA am I operating" — context id + transport
/// preferences + DID-lookup resolver. Mediator-flavoured defaults are
/// fine for the common single-tenant integration; operators who host
/// multiple tenants carry multiple `VtaContextConfig` values and
/// share a `VtaAuthConfig`.
#[derive(Clone)]
pub struct VtaContextConfig {
    /// VTA context ID that holds this service's DID and keys. The
    /// field is named `id` (not `context`) so the combined
    /// [`VtaServiceConfig`] doesn't force callers to read
    /// `config.context.context`.
    pub id: String,
    /// Mediator DID to route DIDComm traffic through, when the DIDComm
    /// transport tier is selected.
    ///
    /// When set, explicit config wins over auto-resolution. When unset,
    /// the integration layer attempts to auto-resolve the mediator DID
    /// from the VTA's DID document (walking `service[].type ==
    /// "DIDCommMessaging"`) using [`Self::did_resolver`] if supplied,
    /// or a one-shot default resolver otherwise. When no mediator DID
    /// is ultimately available (unset + auto-resolve returned `None`
    /// or failed), the tier sequence falls through to REST — unless
    /// [`TransportPreference::DidCommOnly`] forces an error.
    #[cfg(feature = "session")]
    pub mediator_did: Option<String>,
    /// Which transport the integration layer should try first, and
    /// whether it may fall back. Default is
    /// [`TransportPreference::Auto`].
    #[cfg(feature = "session")]
    pub transport_preference: TransportPreference,
    /// Optional shared DID resolver for mediator auto-resolution and
    /// other DID-lookup paths. When `None`, the integration layer
    /// creates a one-shot [`DIDCacheClient`] on demand — fine for
    /// first-run use but wasteful if the host already has a resolver.
    ///
    /// [`DIDCacheClient`]: affinidi_did_resolver_cache_sdk::DIDCacheClient
    #[cfg(feature = "session")]
    pub did_resolver: Option<std::sync::Arc<affinidi_did_resolver_cache_sdk::DIDCacheClient>>,
}

impl VtaContextConfig {
    /// Minimal constructor — just a context id, everything else left
    /// as defaults (auto transport, no pinned mediator, no shared
    /// resolver).
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            #[cfg(feature = "session")]
            mediator_did: None,
            #[cfg(feature = "session")]
            transport_preference: TransportPreference::Auto,
            #[cfg(feature = "session")]
            did_resolver: None,
        }
    }
}

impl std::fmt::Debug for VtaContextConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg = f.debug_struct("VtaContextConfig");
        dbg.field("id", &self.id);
        #[cfg(feature = "session")]
        {
            dbg.field("mediator_did", &self.mediator_did)
                .field("transport_preference", &self.transport_preference)
                .field(
                    "did_resolver",
                    &self.did_resolver.as_ref().map(|_| "Arc<DIDCacheClient>"),
                );
        }
        dbg.finish()
    }
}

/// Full configuration for [`startup`] — composition of an
/// [`VtaAuthConfig`] (who to talk to) and a [`VtaContextConfig`]
/// (where to operate). Kept as a combined struct so the common
/// single-tenant case stays a one-struct-literal affair; multi-tenant
/// integrations hold `VtaAuthConfig` once and rebuild `VtaContextConfig`
/// per tenant.
///
/// The `credential` field holds the already-decoded [`CredentialBundle`].
/// How the credential is obtained (opened from a sealed bundle, read
/// from a keyring, loaded from AWS Secrets Manager, etc.) is left to
/// the calling service.
#[derive(Clone, Debug)]
pub struct VtaServiceConfig {
    pub auth: VtaAuthConfig,
    pub context: VtaContextConfig,
}

impl VtaServiceConfig {
    /// Convenience constructor for the single-tenant happy path:
    /// credential + context id, everything else defaults.
    pub fn new(
        credential: crate::credentials::CredentialBundle,
        context: impl Into<String>,
    ) -> Self {
        Self {
            auth: VtaAuthConfig::new(credential),
            context: VtaContextConfig::new(context),
        }
    }
}

/// Transport selection policy for [`authenticate`].
///
/// The actual tier sequence is derived from this preference plus whether
/// [`VtaServiceConfig::mediator_did`] is set — see
/// [`decide_transport`](auth::decide_transport) for the matrix.
#[cfg(feature = "session")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TransportPreference {
    /// Try DIDComm first when a `mediator_did` is configured; fall back to
    /// REST on DIDComm failure. When `mediator_did` is unset, go straight
    /// to REST. The sensible default for integrations that already speak
    /// DIDComm for their primary workload (mediators) while keeping REST
    /// as a safety net for pure-consumer deployments.
    #[default]
    Auto,
    /// Skip DIDComm entirely; use REST. For integrations whose workload
    /// is occasional / boot-time and who don't want the cost of a
    /// persistent DIDComm channel.
    PreferRest,
    /// Require DIDComm. Error when `mediator_did` is unset or the DIDComm
    /// channel fails — do **not** fall back to REST. For environments
    /// that intentionally don't expose the REST endpoint publicly.
    DidCommOnly,
}

/// Whether secrets were loaded live from the VTA or from the local cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSource {
    /// Fresh secrets fetched from the VTA.
    Vta,
    /// Stale secrets loaded from the local cache (VTA was unreachable).
    Cache,
}

/// Why [`startup`] fell back to the local cache instead of loading fresh
/// secrets from the VTA. Present only when [`SecretSource::Cache`].
///
/// Callers use this to log the right severity and take the right action:
/// [`AuthDenied`](Self::AuthDenied) is an authorization problem the
/// operator must fix (the VTA rejected an otherwise-reachable request),
/// whereas [`Unreachable`](Self::Unreachable)/[`Timeout`](Self::Timeout)
/// are transient connectivity that a later refresh clears on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackReason {
    /// The VTA answered but **rejected** the request — HTTP 401/403 or the
    /// DIDComm `unauthorized`/`forbidden` problem-report. The credential or
    /// its authorization (e.g. an expired ACL entry) needs attention;
    /// re-fetching won't self-heal until that's resolved.
    AuthDenied,
    /// The VTA could not be reached (network/transport error, DIDComm
    /// session failure, non-auth VTA error). Typically transient.
    Unreachable,
    /// The startup round-trip exceeded the configured timeout.
    Timeout,
}

impl FallbackReason {
    /// Classify a [`VtaError`] surfaced by a failed VTA round-trip into the
    /// reason `startup` fell back to cache. `Auth` (401 / `unauthorized`)
    /// and `Forbidden` (403 / `forbidden`) are authorization denials;
    /// everything else is treated as unreachable.
    fn from_vta_error(err: &VtaIntegrationError) -> Self {
        match err {
            VtaIntegrationError::Vta(e) if e.is_auth() => FallbackReason::AuthDenied,
            _ => FallbackReason::Unreachable,
        }
    }
}

/// Successful result from [`startup`].
pub struct StartupResult {
    /// The service's DID, as recorded in the VTA context.
    pub did: String,
    /// The full secrets bundle (DID + all private keys).
    pub bundle: DidSecretsBundle,
    /// Where the secrets came from.
    pub source: SecretSource,
    /// The authenticated VTA client, if secrets were fetched live.
    /// `None` when secrets came from the local cache.
    ///
    /// Its live DIDComm mediator session (if any) has **already been shut
    /// down** by [`startup`] — the client is retained only for
    /// REST-backed follow-up calls such as [`health`](crate::client::VtaClient::health),
    /// which never touch the live session. Do **not** rely on it for
    /// further DIDComm round-trips; open a fresh scoped client
    /// ([`with_didcomm`](crate::client::VtaClient::with_didcomm)) for those.
    pub client: Option<crate::client::VtaClient>,
    /// Why a VTA round-trip *failed* and forced the cached bundle. `Some`
    /// only with [`SecretSource::Cache`], distinguishing an authorization
    /// denial ([`FallbackReason::AuthDenied`]) from transient
    /// unreachability so callers can log/alert appropriately. `None` when
    /// secrets are fresh from the VTA ([`SecretSource::Vta`]) **or** when a
    /// caller loaded the cache without attempting the VTA at all (no
    /// failure to report).
    pub fallback: Option<FallbackReason>,
}

/// Errors from the VTA integration startup flow.
#[derive(Debug)]
pub enum VtaIntegrationError {
    /// VTA is unreachable and no locally cached secrets exist.
    /// This typically means the service has never successfully contacted the VTA.
    NoCachedSecrets,
    /// The VTA context returned zero secrets. This is a configuration error —
    /// the context must have at least one key (signing or key agreement) provisioned.
    EmptySecretsBundle(String),
    /// The local secret cache could not be read or written.
    CacheError(String),
    /// An error from the VTA SDK (authentication or secret fetch).
    Vta(VtaError),
}

impl std::fmt::Display for VtaIntegrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCachedSecrets => write!(
                f,
                "VTA is unreachable and no cached secrets exist. \
                 Run the setup wizard or ensure the VTA is accessible for the first startup."
            ),
            Self::EmptySecretsBundle(ctx) => write!(
                f,
                "VTA context '{ctx}' returned zero secrets. \
                 Provision keys via the setup wizard or VTA admin tools."
            ),
            Self::CacheError(e) => write!(f, "secret cache error: {e}"),
            Self::Vta(e) => write!(f, "VTA error: {e}"),
        }
    }
}

impl std::error::Error for VtaIntegrationError {}

impl From<VtaError> for VtaIntegrationError {
    fn from(e: VtaError) -> Self {
        Self::Vta(e)
    }
}

/// Main entry point for VTA-integrated service startup.
///
/// Attempts to fetch fresh secrets from the VTA and cache them locally.
/// If the VTA is unreachable, falls back to the last cached bundle.
///
/// Returns a [`StartupResult`] containing the service DID, secrets bundle,
/// and whether the secrets are fresh or cached.
///
/// The DIDComm session used to fetch the bundle is **transient**: it is
/// shut down before this function returns, so no auto-reconnecting
/// mediator socket outlives the call. See [`StartupResult::client`].
pub async fn startup(
    config: &VtaServiceConfig,
    cache: &(impl SecretCache + ?Sized),
) -> Result<StartupResult, VtaIntegrationError> {
    let timeout = config.auth.timeout.unwrap_or(DEFAULT_STARTUP_TIMEOUT);
    let context_id = &config.context.id;

    let vta_result = tokio::time::timeout(timeout, async {
        let client = authenticate(config).await?;
        let bundle = client
            .fetch_did_secrets_bundle(context_id)
            .await
            .map_err(VtaIntegrationError::from)?;
        Ok::<_, VtaIntegrationError>((client, bundle))
    })
    .await;

    match vta_result {
        Ok(Ok((client, bundle))) => {
            if bundle.secrets.is_empty() {
                // Tear the transient session down before bailing — the
                // early return would otherwise drop `client` without
                // `shutdown()`, leaking a live session (see below).
                client.shutdown().await;
                return Err(VtaIntegrationError::EmptySecretsBundle(context_id.clone()));
            }
            if let Err(e) = cache.store(&bundle).await {
                tracing::warn!("Failed to cache VTA secrets locally: {e}");
            }
            tracing::info!(
                context = context_id,
                secrets = bundle.secrets.len(),
                "Loaded fresh secrets from VTA",
            );
            // The bundle fetch is the only thing that needs the live
            // DIDComm session. Shut it down here, at the source, so the
            // auto-reconnecting mediator socket a DIDComm `VtaClient` owns
            // can never outlive this call — regardless of whether the
            // caller remembers to `shutdown()`. Callers (mediator boot +
            // hourly `vta_refresh`) that drop `StartupResult.client`
            // without shutting it down were leaking one live session per
            // `startup()`; two live sessions for the same DID displace
            // each other forever at the mediator's one-socket-per-DID
            // gate, producing an endless duplicate-WebSocket churn storm.
            // `shutdown()` is a no-op for REST and idempotent, so the
            // returned client stays usable for REST-backed follow-ups
            // (e.g. `health()`, which never uses the live session).
            client.shutdown().await;
            Ok(StartupResult {
                did: bundle.did.clone(),
                bundle,
                source: SecretSource::Vta,
                client: Some(client),
                fallback: None,
            })
        }
        Ok(Err(e)) => {
            let reason = FallbackReason::from_vta_error(&e);
            tracing::warn!(
                context = context_id,
                error = %e,
                reason = ?reason,
                "VTA call failed; attempting fallback to last-known cached bundle",
            );
            load_from_cache(cache, context_id, reason).await
        }
        Err(_elapsed) => {
            tracing::warn!(
                context = context_id,
                timeout_secs = timeout.as_secs(),
                "VTA startup timed out; attempting fallback to last-known cached bundle",
            );
            load_from_cache(cache, context_id, FallbackReason::Timeout).await
        }
    }
}

async fn load_from_cache(
    cache: &(impl SecretCache + ?Sized),
    context: &str,
    reason: FallbackReason,
) -> Result<StartupResult, VtaIntegrationError> {
    match cache.load().await {
        Ok(Some(bundle)) => {
            if bundle.secrets.is_empty() {
                return Err(VtaIntegrationError::EmptySecretsBundle(context.to_string()));
            }
            tracing::warn!(
                context = context,
                secrets = bundle.secrets.len(),
                "Booted from last-known cached bundle; keys may be stale. \
                 Will refresh on next successful VTA contact",
            );
            Ok(StartupResult {
                did: bundle.did.clone(),
                bundle,
                source: SecretSource::Cache,
                client: None,
                fallback: Some(reason),
            })
        }
        Ok(None) => {
            tracing::warn!(
                context = context,
                "No cached bundle found in local cache; returning NoCachedSecrets",
            );
            Err(VtaIntegrationError::NoCachedSecrets)
        }
        Err(e) => {
            tracing::error!(
                context = context,
                error = %e,
                "Failed to read cached bundle from local cache",
            );
            Err(VtaIntegrationError::CacheError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did_secrets::{DidSecretsBundle, SecretEntry};
    use crate::keys::KeyType;
    use std::sync::Mutex;

    /// In-memory `SecretCache` for tests. Records the last-stored bundle
    /// and lets the test script arbitrary `load()` / `store()`
    /// behaviours via pre-seeded slots. Intentionally unassuming — no
    /// tracking of store-count, no clear() semantics — each test
    /// constructs a fresh instance.
    struct MockSecretCache {
        load_result: Mutex<Option<LoadOutcome>>,
        last_stored: Mutex<Option<DidSecretsBundle>>,
    }

    enum LoadOutcome {
        Some(DidSecretsBundle),
        None,
        Err(String),
    }

    impl MockSecretCache {
        fn with_cached(bundle: DidSecretsBundle) -> Self {
            Self {
                load_result: Mutex::new(Some(LoadOutcome::Some(bundle))),
                last_stored: Mutex::new(None),
            }
        }
        fn empty() -> Self {
            Self {
                load_result: Mutex::new(Some(LoadOutcome::None)),
                last_stored: Mutex::new(None),
            }
        }
        fn failing(msg: &str) -> Self {
            Self {
                load_result: Mutex::new(Some(LoadOutcome::Err(msg.into()))),
                last_stored: Mutex::new(None),
            }
        }
    }

    impl SecretCache for MockSecretCache {
        fn store(
            &self,
            bundle: &DidSecretsBundle,
        ) -> impl std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send
        {
            let mut slot = self.last_stored.lock().unwrap();
            *slot = Some(bundle.clone());
            async { Ok(()) }
        }
        fn load(
            &self,
        ) -> impl std::future::Future<
            Output = Result<Option<DidSecretsBundle>, Box<dyn std::error::Error + Send + Sync>>,
        > + Send {
            let taken = self.load_result.lock().unwrap().take();
            async move {
                match taken {
                    Some(LoadOutcome::Some(b)) => Ok(Some(b)),
                    Some(LoadOutcome::None) => Ok(None),
                    Some(LoadOutcome::Err(m)) => Err(m.into()),
                    None => Ok(None),
                }
            }
        }
    }

    fn sample_bundle() -> DidSecretsBundle {
        DidSecretsBundle {
            did: "did:key:z6MkSampleIntegration".into(),
            secrets: vec![SecretEntry {
                key_id: "did:key:z6MkSampleIntegration#z6MkSampleIntegration".into(),
                key_type: KeyType::Ed25519,
                private_key_multibase: "z3weSampleSecret".into(),
            }],
        }
    }

    #[tokio::test]
    async fn load_from_cache_returns_fresh_bundle_when_present() {
        let cache = MockSecretCache::with_cached(sample_bundle());
        let result = load_from_cache(&cache, "prod-mediator", FallbackReason::AuthDenied)
            .await
            .expect("cache hit returns StartupResult");
        assert_eq!(result.source, SecretSource::Cache);
        assert_eq!(result.did, "did:key:z6MkSampleIntegration");
        assert_eq!(result.bundle.secrets.len(), 1);
        assert_eq!(
            result.fallback,
            Some(FallbackReason::AuthDenied),
            "cache fallback carries the reason it was triggered",
        );
        assert!(
            result.client.is_none(),
            "Cache-source startup never carries a live VtaClient",
        );
    }

    #[test]
    fn fallback_reason_classifies_auth_errors() {
        use crate::error::VtaError;
        // 401 / 403 → the VTA rejected the request: an authorization problem.
        assert_eq!(
            FallbackReason::from_vta_error(&VtaIntegrationError::Vta(VtaError::Forbidden(
                "acl expired".into()
            ))),
            FallbackReason::AuthDenied,
        );
        assert_eq!(
            FallbackReason::from_vta_error(&VtaIntegrationError::Vta(VtaError::Auth(
                "token rejected".into()
            ))),
            FallbackReason::AuthDenied,
        );
        // Anything else is treated as (transient) unreachability.
        assert_eq!(
            FallbackReason::from_vta_error(&VtaIntegrationError::Vta(VtaError::NotFound(
                "no context".into()
            ))),
            FallbackReason::Unreachable,
        );
        assert_eq!(
            FallbackReason::from_vta_error(&VtaIntegrationError::NoCachedSecrets),
            FallbackReason::Unreachable,
        );
    }

    #[tokio::test]
    async fn load_from_cache_empty_returns_no_cached_secrets() {
        let cache = MockSecretCache::empty();
        let result = load_from_cache(&cache, "prod-mediator", FallbackReason::Unreachable).await;
        match result {
            Err(VtaIntegrationError::NoCachedSecrets) => {}
            Err(other) => panic!("expected NoCachedSecrets, got {other:?}"),
            Ok(_) => panic!("empty cache must be an error"),
        }
    }

    #[tokio::test]
    async fn load_from_cache_io_error_becomes_cache_error() {
        let cache = MockSecretCache::failing("keyring unavailable");
        let result = load_from_cache(&cache, "prod-mediator", FallbackReason::Unreachable).await;
        match result {
            Err(VtaIntegrationError::CacheError(msg)) => {
                assert!(msg.contains("keyring unavailable"), "got: {msg}")
            }
            Err(other) => panic!("expected CacheError, got {other:?}"),
            Ok(_) => panic!("cache read error must propagate"),
        }
    }

    #[tokio::test]
    async fn load_from_cache_rejects_empty_bundle() {
        // A cached bundle with no secrets is structurally-valid on the
        // wire but useless at boot — reject loudly rather than silently
        // return an unusable StartupResult.
        let cache = MockSecretCache::with_cached(DidSecretsBundle {
            did: "did:key:zEmpty".into(),
            secrets: vec![],
        });
        let result = load_from_cache(&cache, "prod-mediator", FallbackReason::Timeout).await;
        match result {
            Err(VtaIntegrationError::EmptySecretsBundle(ctx)) => {
                assert_eq!(ctx, "prod-mediator")
            }
            Err(other) => panic!("expected EmptySecretsBundle, got {other:?}"),
            Ok(_) => panic!("empty-secrets bundle must be rejected"),
        }
    }
}
