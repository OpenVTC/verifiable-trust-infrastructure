use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use ed25519_dalek_bip32::ExtendedSigningKey;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use crate::auth::AuthState;
use crate::auth::jwt::JwtKeys;
use crate::auth::session::cleanup_expired_sessions;
use crate::config::{AppConfig, AuthConfig};
#[cfg(feature = "didcomm")]
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::keys::KeyRecord;
use crate::keys::derivation::Bip32Extension;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::load_seed_bytes;
#[cfg(feature = "didcomm")]
use crate::messaging;
#[cfg(feature = "rest")]
use crate::routes;
use crate::store::{KeyspaceHandle, Store};
use tokio::sync::{RwLock, watch};
#[cfg(feature = "rest")]
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;
use tracing::{debug, error, info, warn};

#[cfg(feature = "didcomm")]
use affinidi_messaging_didcomm_service::{
    DIDCommService, DIDCommServiceConfig, ListenerConfig, RestartPolicy, RetryConfig,
};
#[cfg(feature = "didcomm")]
use affinidi_tdk_common::profiles::TDKProfile;
#[cfg(feature = "didcomm")]
use tokio_util::sync::CancellationToken;

/// TEE context passed by the caller (main.rs or vta-enclave).
/// None when running outside a TEE.
///
/// When the `tee` feature is not compiled in, this is a unit struct
/// that is never constructed — callers pass `None::<TeeContext>`.
#[derive(Clone)]
#[cfg(feature = "tee")]
pub struct TeeContext {
    pub state: crate::tee::TeeState,
    pub mnemonic_guard: Option<Arc<crate::tee::mnemonic_guard::MnemonicExportGuard>>,
}

/// Stub type when TEE is not compiled in. Never constructed.
#[derive(Clone)]
#[cfg(not(feature = "tee"))]
pub struct TeeContext(());

/// Trigger a soft restart after a short delay, allowing the current
/// response to be sent before threads shut down.
pub fn trigger_restart(restart_tx: &watch::Sender<bool>) {
    let tx = restart_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let _ = tx.send(true);
    });
}

#[derive(Clone)]
pub struct AppState {
    pub keys_ks: KeyspaceHandle,
    pub sessions_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub contexts_ks: KeyspaceHandle,
    pub did_templates_ks: KeyspaceHandle,
    pub audit_ks: KeyspaceHandle,
    pub imported_ks: KeyspaceHandle,
    pub cache_ks: KeyspaceHandle,
    /// Vault — third-party credentials the holder has stored on this VTA.
    /// M1 reads only; upsert/delete/sync/release land in M2+. Encrypted at
    /// rest like every other secret-bearing keyspace.
    pub vault_ks: KeyspaceHandle,
    /// Persistent runtime state for service enable/disable
    /// (`operations::protocol::runtime_state`). Replaces the legacy
    /// `[services]` block in `config.toml` as the source of truth for whether
    /// REST / DIDComm are currently active.
    pub service_state_ks: KeyspaceHandle,
    /// Anti-replay log for sealed-bootstrap `bundle_id`s. One row per seal;
    /// `PersistentNonceStore` refuses duplicates.
    pub sealed_nonces_ks: KeyspaceHandle,
    /// In-flight backup-bundle records for the descriptor-pattern
    /// export/import slice (see
    /// `docs/05-design-notes/backup-descriptor-pattern.md`). Holds
    /// only the control-plane state — `.vtabak` bytes live on disk
    /// under [`Self::backup_blob_dir`]. Encrypted at rest (records
    /// include hashed bearer tokens; nothing useful leaks if the
    /// keyspace is read, but encrypting it keeps storage-layer
    /// invariants uniform across slices).
    pub backup_bundles_ks: KeyspaceHandle,
    /// Filesystem directory under which `.vtabak` byte blobs are
    /// staged for in-flight backup bundles. Created lazily at first
    /// `initiate-*` call. Permissions: 0700 (owner-only). Each
    /// blob is at `{backup_blob_dir}/{bundle_id}.vtabak` with mode
    /// 0600. The sweeper deletes both the file and the record
    /// when a bundle ages out.
    pub backup_blob_dir: std::path::PathBuf,
    #[cfg(feature = "webvh")]
    pub webvh_ks: KeyspaceHandle,
    /// In-flight WebAuthn registration state for the
    /// passkey-as-verificationMethod enrolment ceremony. Holds
    /// `PasskeyRegistration` keyed by ceremony id; consumed (taken)
    /// at finish.
    #[cfg(feature = "webvh")]
    pub passkey_vms_ks: KeyspaceHandle,
    /// Persisted drain set for the protocol-management feature
    /// (`docs/05-design-notes/didcomm-protocol-management.md`).
    /// Keyed by mediator DID; replayed at boot.
    #[cfg(feature = "webvh")]
    pub drains_ks: KeyspaceHandle,
    /// Per-kind previous-config snapshot store for fail-forward
    /// rollback (spec §3.5a). Populated alongside `drains_ks`.
    #[cfg(feature = "webvh")]
    pub snapshot_ks: KeyspaceHandle,
    /// In-process registry of active + draining mediator listeners.
    /// Owns the per-listener bounded outbound buffer and the
    /// active/drain state machine.
    #[cfg(feature = "webvh")]
    pub mediator_registry: Arc<crate::messaging::registry::MediatorListenerRegistry>,
    /// Per-webvh-server async mutex registry for serializing
    /// daemon-REST auth-cache read-modify-writes. Two concurrent
    /// operations against the same server can't both refresh and
    /// last-writer-wins; locks are keyed by server id so unrelated
    /// servers don't contend.
    #[cfg(feature = "webvh")]
    pub webvh_auth_locks: crate::operations::did_webvh::WebvhAuthLocks,
    /// Per-mediator TTL sweeper. Arms a `tokio::time::sleep_until`
    /// task per drain entry; on expiry, calls
    /// `record_expiries_persisted` and signals upstream listener
    /// teardown via the teardown channel.
    #[cfg(feature = "webvh")]
    pub drain_sweeper: Arc<crate::messaging::drain_sweeper::DrainSweeper>,
    /// Pluggable telemetry sink for mediator-attribution events.
    /// Default impl is the in-memory ring buffer; alternative
    /// backends plug in via the `TelemetrySink` trait.
    pub telemetry: vti_common::telemetry::SharedTelemetrySink,
    pub wrapping_cache: crate::keys::wrapping::WrappingKeyCache,
    pub config: Arc<RwLock<AppConfig>>,
    pub seed_store: Arc<dyn SeedStore>,
    pub did_resolver: Option<DIDCacheClient>,
    /// Live status-list resolver for the present path: when set, the holder
    /// **re-resolves** a credential's revocation status at present time rather
    /// than trusting the stored tag (§14.5). `None` falls back to the stored
    /// status (the pre-live behaviour).
    pub status_list_resolver: Option<Arc<dyn crate::vault::status::StatusListResolver>>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    /// Verification-method id for the VTA's signing key (e.g.
    /// `{did}#key-0`). Populated by `init_auth`. Needed by the
    /// live mediator-handshake prover to fetch the corresponding
    /// secret out of [`Self::secrets_resolver`].
    #[cfg(feature = "didcomm")]
    pub signing_vm_id: Option<String>,
    /// Verification-method id for the VTA's key-agreement key
    /// (e.g. `{did}#key-1`). Populated by `init_auth`.
    #[cfg(feature = "didcomm")]
    pub ka_vm_id: Option<String>,
    #[cfg(feature = "didcomm")]
    pub didcomm_bridge: Arc<DIDCommBridge>,
    pub jwt_keys: Option<Arc<JwtKeys>>,
    pub atm: Option<ATM>,
    pub tee: Option<TeeContext>,
    /// Send `true` to trigger a soft restart (threads shut down and re-initialize).
    pub restart_tx: watch::Sender<bool>,
    /// Prometheus metrics handle for rendering `/metrics` endpoint.
    #[cfg(feature = "rest")]
    pub metrics_handle: Option<crate::metrics::PrometheusHandle>,
}

impl AuthState for AppState {
    fn jwt_keys(&self) -> Option<&Arc<JwtKeys>> {
        self.jwt_keys.as_ref()
    }
    fn sessions_ks(&self) -> &KeyspaceHandle {
        &self.sessions_ks
    }
}

/// Build the shared application state from config, store, and TEE context.
///
/// Use this to construct `AppState` without the full thread orchestration
/// of `run()`. Useful for non-axum front-ends (e.g., Lambda handlers)
/// that need the state but manage their own request loop.
pub async fn build_app_state(
    config: AppConfig,
    store: &Store,
    seed_store: Arc<dyn SeedStore>,
    storage_encryption_key: Option<[u8; 32]>,
    tee_context: Option<TeeContext>,
    restart_tx: watch::Sender<bool>,
) -> Result<AppState, AppError> {
    let apply_encryption = |ks: KeyspaceHandle| -> KeyspaceHandle {
        if let Some(key) = storage_encryption_key {
            ks.with_encryption(key)
        } else {
            ks
        }
    };

    let keys_ks = apply_encryption(store.keyspace("keys")?);
    let sessions_ks = apply_encryption(store.keyspace("sessions")?);
    let acl_ks = apply_encryption(store.keyspace("acl")?);
    let contexts_ks = apply_encryption(store.keyspace("contexts")?);
    let did_templates_ks = apply_encryption(store.keyspace("did_templates")?);
    let audit_ks = apply_encryption(store.keyspace("audit")?);
    let imported_ks = apply_encryption(store.keyspace("imported_secrets")?);
    let cache_ks = store.keyspace("cache")?;
    let vault_ks = apply_encryption(store.keyspace("vault")?);
    // Persistent runtime state for service enable/disable. Encrypted because
    // a couple of bool records are cheap and the keyspace may grow.
    let service_state_ks = apply_encryption(store.keyspace("service_state")?);
    // Sealed-transfer anti-replay store. Bundle_ids are not secret and the
    // row is a one-byte sentinel, so the keyspace is intentionally
    // unencrypted — saves a decrypt hop on every request.
    let sealed_nonces_ks = store.keyspace("sealed_nonces")?;
    let backup_bundles_ks = apply_encryption(store.keyspace("backup_bundles")?);
    // Stage `.vtabak` blobs under `{data_dir}/backups`. Created lazily
    // by the op layer at first `initiate-*` call (so a VTA that never
    // does backups doesn't get an empty directory). See
    // `docs/05-design-notes/backup-descriptor-pattern.md` §"State
    // machine" for the file-system layout.
    let backup_blob_dir = config.store.data_dir.join("backups");
    #[cfg(feature = "webvh")]
    let webvh_ks = apply_encryption(store.keyspace("webvh")?);
    #[cfg(feature = "webvh")]
    let passkey_vms_ks = apply_encryption(store.keyspace("passkey_vms")?);
    #[cfg(feature = "webvh")]
    let drains_ks = apply_encryption(store.keyspace("drains")?);
    #[cfg(feature = "webvh")]
    let snapshot_ks =
        apply_encryption(store.keyspace(crate::operations::protocol::snapshot::KEYSPACE_NAME)?);

    let auth = init_auth(&config, &*seed_store, &keys_ks).await;

    let telemetry: vti_common::telemetry::SharedTelemetrySink =
        Arc::new(vti_common::telemetry::RingBufferTelemetry::new());
    #[cfg(feature = "webvh")]
    let mediator_registry = Arc::new(crate::messaging::registry::MediatorListenerRegistry::new(
        Arc::clone(&telemetry),
    ));
    // `build_app_state` is called from non-axum front-ends (e.g.
    // Lambda) that don't run a teardown consumer — give them a
    // sweeper whose channel sender goes nowhere so signals
    // become no-ops. The full `run()` path replaces this with a
    // sweeper whose receiver is consumed by a real task that
    // calls `DIDCommService::remove_listener`.
    #[cfg(feature = "webvh")]
    let drain_sweeper = {
        let (tx, _rx) = crate::messaging::drain_sweeper::teardown_channel(
            crate::messaging::drain_sweeper::DEFAULT_TEARDOWN_CHANNEL_CAPACITY,
        );
        Arc::new(crate::messaging::drain_sweeper::DrainSweeper::new(
            Arc::clone(&mediator_registry),
            drains_ks.clone(),
            tx,
        ))
    };

    Ok(AppState {
        keys_ks,
        sessions_ks,
        acl_ks,
        contexts_ks,
        did_templates_ks,
        audit_ks,
        imported_ks,
        cache_ks,
        vault_ks,
        service_state_ks,
        sealed_nonces_ks,
        backup_bundles_ks,
        backup_blob_dir,
        #[cfg(feature = "webvh")]
        webvh_ks,
        #[cfg(feature = "webvh")]
        passkey_vms_ks,
        #[cfg(feature = "webvh")]
        drains_ks,
        #[cfg(feature = "webvh")]
        snapshot_ks,
        #[cfg(feature = "webvh")]
        mediator_registry,
        #[cfg(feature = "webvh")]
        drain_sweeper,
        #[cfg(feature = "webvh")]
        webvh_auth_locks: crate::operations::did_webvh::WebvhAuthLocks::new(),
        telemetry,
        wrapping_cache: crate::keys::wrapping::WrappingKeyCache::new(),
        config: Arc::new(RwLock::new(config)),
        seed_store,
        did_resolver: auth.did_resolver,
        status_list_resolver: crate::vault::status::default_status_resolver(),
        secrets_resolver: auth.secrets_resolver,
        #[cfg(feature = "didcomm")]
        signing_vm_id: auth.signing_vm_id,
        #[cfg(feature = "didcomm")]
        ka_vm_id: auth.ka_vm_id,
        #[cfg(feature = "didcomm")]
        didcomm_bridge: Arc::new(DIDCommBridge::placeholder()),

        jwt_keys: auth.jwt_keys,
        atm: auth.atm,
        tee: tee_context,
        restart_tx,
        #[cfg(feature = "rest")]
        metrics_handle: None,
    })
}

// `config` is only mutated when the `webvh` feature is on (mirror of
// runtime-state into the in-memory `config.services`). Allow the lint
// in other feature combos so `cargo check -D warnings` stays clean.
#[cfg_attr(not(feature = "webvh"), allow(unused_mut))]
pub async fn run(
    mut config: AppConfig,
    store: Store,
    seed_store: Arc<dyn SeedStore>,
    storage_encryption_key: Option<[u8; 32]>,
    tee_context: Option<TeeContext>,
) -> Result<(), AppError> {
    // Open the runtime-state keyspace once up front so the boot decisions
    // below can read it (and the migration can seed it from the legacy
    // `[services]` block on first boot post-upgrade). Same encryption policy
    // as the rest of the keyspaces.
    let boot_service_state_ks = {
        let ks = store.keyspace("service_state")?;
        match storage_encryption_key {
            Some(key) => ks.with_encryption(key),
            None => ks,
        }
    };
    // Runtime-state-to-fjall migration + read-back lives in
    // `operations::protocol`, which is `#[cfg(feature = "webvh")]`-
    // gated (the protocol-management surface that owns service
    // toggles only exists in webvh builds). Without webvh the
    // boot path falls back to reading `config.services.*` directly
    // from `config.toml` — the legacy behaviour, still useful for
    // headless / secrets-only builds in the CI feature-combos
    // matrix.
    #[cfg(feature = "webvh")]
    {
        crate::operations::protocol::runtime_state::migrate_from_config(
            &boot_service_state_ks,
            &config,
        )
        .await?;

        // Runtime state in fjall is authoritative; mirror it into the in-memory
        // `config.services` so the existing readers across the codebase keep
        // working unchanged. The on-disk `config.toml` [services] block is now
        // legacy (consumed only by the first-boot migration above).
        config.services.rest =
            crate::operations::protocol::runtime_state::is_rest_enabled(&boot_service_state_ks)
                .await?;
        config.services.didcomm =
            crate::operations::protocol::runtime_state::is_didcomm_enabled(&boot_service_state_ks)
                .await?;
    }
    #[cfg(not(feature = "webvh"))]
    {
        let _ = &boot_service_state_ks;
    }

    // Determine which services will actually start (feature flag AND
    // persisted runtime state, the latter set by `pnm services {kind}
    // {enable,disable}`).
    let rest_enabled = cfg!(feature = "rest") && config.services.rest;
    let didcomm_enabled = cfg!(feature = "didcomm") && config.services.didcomm;

    if !rest_enabled && !didcomm_enabled {
        return Err(AppError::Config(
            "no services enabled — enable at least one of REST or DIDComm \
             (compile-time feature flags + `pnm services {kind} enable`)"
                .into(),
        ));
    }

    // Bind TCP listener once (persists across soft restarts)
    #[cfg(feature = "rest")]
    let std_listener = if rest_enabled {
        let addr = format!("{}:{}", config.server.host, config.server.port);
        let listener = std::net::TcpListener::bind(&addr).map_err(AppError::Io)?;
        listener.set_nonblocking(true).map_err(AppError::Io)?;
        info!("server listening addr={addr}");
        Some(listener)
    } else {
        None
    };

    // ── Restart loop ──────────────────────────────────────────────
    // Each iteration starts all service threads, waits for shutdown
    // or restart signal, tears everything down, then either exits
    // or loops back to re-initialize with updated state.
    loop {
        // Open cached keyspace handles with optional encryption.
        let apply_encryption = |ks: KeyspaceHandle| -> KeyspaceHandle {
            match storage_encryption_key {
                Some(key) => {
                    info!("storage encryption enabled for keyspace");
                    ks.with_encryption(key)
                }
                None => ks,
            }
        };

        let keys_ks = apply_encryption(store.keyspace("keys")?);
        let sessions_ks = apply_encryption(store.keyspace("sessions")?);
        let acl_ks = apply_encryption(store.keyspace("acl")?);
        let contexts_ks = apply_encryption(store.keyspace("contexts")?);
        let did_templates_ks = apply_encryption(store.keyspace("did_templates")?);
        let audit_ks = apply_encryption(store.keyspace("audit")?);
        let imported_ks = apply_encryption(store.keyspace("imported_secrets")?);
        let cache_ks = store.keyspace("cache")?;
        let vault_ks = apply_encryption(store.keyspace("vault")?);
        let service_state_ks = apply_encryption(store.keyspace("service_state")?);
        let sealed_nonces_ks = store.keyspace("sealed_nonces")?;
        let backup_bundles_ks = apply_encryption(store.keyspace("backup_bundles")?);
        let backup_blob_dir = config.store.data_dir.join("backups");
        #[cfg(feature = "webvh")]
        let webvh_ks = apply_encryption(store.keyspace("webvh")?);
        #[cfg(feature = "webvh")]
        let passkey_vms_ks = apply_encryption(store.keyspace("passkey_vms")?);
        #[cfg(feature = "webvh")]
        let drains_ks = apply_encryption(store.keyspace("drains")?);
        #[cfg(feature = "webvh")]
        let snapshot_ks =
            apply_encryption(store.keyspace(crate::operations::protocol::snapshot::KEYSPACE_NAME)?);

        // Initialize auth infrastructure
        let auth = init_auth(&config, &*seed_store, &keys_ks).await;

        // Pluggable telemetry sink + multi-mediator listener registry.
        // The registry holds active/drain state and the per-mediator
        // bounded outbound buffer; spec
        // `docs/05-design-notes/didcomm-protocol-management.md`.
        let telemetry: vti_common::telemetry::SharedTelemetrySink =
            Arc::new(vti_common::telemetry::RingBufferTelemetry::new());
        #[cfg(feature = "webvh")]
        let mediator_registry = Arc::new(
            crate::messaging::registry::MediatorListenerRegistry::new(Arc::clone(&telemetry)),
        );
        // Drain sweeper: TTL-keyed `tokio::time::sleep_until` per
        // drain entry. On expiry, the sweeper signals the
        // teardown channel; the consumer task spawned below
        // translates each signal into a
        // `DIDCommService::remove_listener` call.
        #[cfg(feature = "webvh")]
        let (teardown_tx, teardown_rx) = crate::messaging::drain_sweeper::teardown_channel(
            crate::messaging::drain_sweeper::DEFAULT_TEARDOWN_CHANNEL_CAPACITY,
        );
        #[cfg(feature = "webvh")]
        let drain_sweeper = Arc::new(crate::messaging::drain_sweeper::DrainSweeper::new(
            Arc::clone(&mediator_registry),
            drains_ks.clone(),
            teardown_tx,
        ));
        // Boot replay: load any drains persisted from a previous
        // run, drop already-expired entries, register the live
        // ones with the registry, and arm the sweeper for each.
        #[cfg(feature = "webvh")]
        match mediator_registry.replay_drains(&drains_ks).await {
            Ok(live) => {
                if !live.is_empty() {
                    info!(count = live.len(), "drain set replayed from keyspace");
                }
                drain_sweeper.arm_all(&live).await;
            }
            Err(e) => {
                warn!(error = %e, "drain replay failed — starting with empty drain set");
            }
        }

        // In TEE required mode, warn if auth isn't initialized.
        #[cfg(feature = "tee")]
        if config.tee.mode == crate::config::TeeMode::Required && auth.jwt_keys.is_none() {
            warn!(
                "TEE mode is 'required' but authentication is not initialized \
                 (vta_did not configured). The VTA will start but authenticated \
                 endpoints will return 401."
            );
        }

        // Shutdown + restart coordination
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (restart_tx, mut restart_rx) = watch::channel(false);

        #[cfg(feature = "didcomm")]
        let didcomm_shutdown = CancellationToken::new();

        // Spawn signal handler. First signal triggers cooperative shutdown;
        // a second signal forces an immediate exit so an operator can always
        // bail out if cleanup hangs (e.g., a mediator handshake that won't
        // complete before its timeout fires).
        tokio::spawn({
            let shutdown_tx = shutdown_tx.clone();
            #[cfg(feature = "didcomm")]
            let didcomm_shutdown = didcomm_shutdown.clone();
            async move {
                shutdown_signal().await;
                info!("shutting down — press Ctrl-C again to force exit");
                let _ = shutdown_tx.send(true);
                #[cfg(feature = "didcomm")]
                didcomm_shutdown.cancel();

                shutdown_signal().await;
                eprintln!("\nForcing exit.");
                std::process::exit(130);
            }
        });

        // Gather storage thread inputs
        let storage_store = store.clone();
        let storage_sessions_ks = sessions_ks.clone();
        let storage_audit_ks = audit_ks.clone();
        let storage_acl_ks = acl_ks.clone();
        let storage_backup_bundles_ks = backup_bundles_ks.clone();
        let storage_backup_blob_dir = backup_blob_dir.clone();
        let storage_audit_config = config.audit.clone();
        let storage_auth_config = config.auth.clone();
        let has_auth = auth.jwt_keys.is_some();

        // Shared DIDComm bridge for outbound request-response messaging.
        // The service reference is set after DIDCommService::start().
        #[cfg(feature = "didcomm")]
        let didcomm_bridge: Arc<DIDCommBridge> = Arc::new(DIDCommBridge::new("vta-main"));

        // Build VtaState for the DIDComm service router
        #[cfg(feature = "didcomm")]
        let vta_state = if config.services.didcomm {
            Some(Arc::new(messaging::router::VtaState {
                keys_ks: keys_ks.clone(),
                acl_ks: acl_ks.clone(),
                contexts_ks: contexts_ks.clone(),
                did_templates_ks: did_templates_ks.clone(),
                audit_ks: audit_ks.clone(),
                imported_ks: imported_ks.clone(),
                service_state_ks: service_state_ks.clone(),
                #[cfg(feature = "webvh")]
                webvh_ks: webvh_ks.clone(),
                sealed_nonces_ks: sealed_nonces_ks.clone(),
                #[cfg(feature = "webvh")]
                drains_ks: drains_ks.clone(),
                #[cfg(feature = "webvh")]
                snapshot_ks: snapshot_ks.clone(),
                #[cfg(feature = "webvh")]
                mediator_registry: Arc::clone(&mediator_registry),
                #[cfg(feature = "webvh")]
                drain_sweeper: Arc::clone(&drain_sweeper),
                #[cfg(feature = "webvh")]
                webvh_auth_locks: crate::operations::did_webvh::WebvhAuthLocks::new(),
                telemetry: Arc::clone(&telemetry),
                seed_store: seed_store.clone(),
                config: Arc::new(RwLock::new(config.clone())),
                did_resolver: auth.did_resolver.clone(),
                didcomm_bridge: didcomm_bridge.clone(),
                secrets_resolver: auth.secrets_resolver.clone(),
                signing_vm_id: auth.signing_vm_id.clone(),
                ka_vm_id: auth.ka_vm_id.clone(),
                #[cfg(feature = "tee")]
                tee_state: tee_context.as_ref().map(|tc| tc.state.clone()),
                restart_tx: restart_tx.clone(),
            }))
        } else {
            None
        };

        // Build the shared `AppState` once, before the REST thread spawn.
        // Both the REST front-end and the DIDComm → trust-task dispatch
        // bridge need it; constructing it here (rather than inside the
        // REST block) keeps a single owned copy in scope that each
        // consumer clones. `AppState` is `Clone`.
        #[cfg(any(feature = "rest", feature = "didcomm"))]
        let wrapping_cache = crate::keys::wrapping::WrappingKeyCache::new();
        #[cfg(any(feature = "rest", feature = "didcomm"))]
        wrapping_cache.clone().spawn_reaper();

        #[cfg(any(feature = "rest", feature = "didcomm"))]
        let app_state = AppState {
            keys_ks,
            sessions_ks,
            acl_ks,
            contexts_ks,
            did_templates_ks,
            audit_ks,
            imported_ks,
            cache_ks,
            vault_ks,
            service_state_ks: service_state_ks.clone(),
            sealed_nonces_ks,
            backup_bundles_ks,
            backup_blob_dir,
            #[cfg(feature = "webvh")]
            webvh_ks,
            #[cfg(feature = "webvh")]
            passkey_vms_ks,
            #[cfg(feature = "webvh")]
            drains_ks,
            #[cfg(feature = "webvh")]
            snapshot_ks,
            #[cfg(feature = "webvh")]
            mediator_registry: Arc::clone(&mediator_registry),
            #[cfg(feature = "webvh")]
            drain_sweeper: Arc::clone(&drain_sweeper),
            #[cfg(feature = "webvh")]
            webvh_auth_locks: crate::operations::did_webvh::WebvhAuthLocks::new(),
            telemetry: Arc::clone(&telemetry),
            wrapping_cache,
            config: Arc::new(RwLock::new(config.clone())),
            seed_store: seed_store.clone(),
            did_resolver: auth.did_resolver,
            status_list_resolver: crate::vault::status::default_status_resolver(),
            secrets_resolver: auth.secrets_resolver.clone(),
            #[cfg(feature = "didcomm")]
            signing_vm_id: auth.signing_vm_id.clone(),
            #[cfg(feature = "didcomm")]
            ka_vm_id: auth.ka_vm_id.clone(),
            #[cfg(feature = "didcomm")]
            didcomm_bridge: didcomm_bridge.clone(),
            jwt_keys: auth.jwt_keys,
            atm: auth.atm,
            tee: tee_context.clone(),
            restart_tx: restart_tx.clone(),
            #[cfg(feature = "rest")]
            metrics_handle: None, // Set in REST thread after install
        };

        // Spawn REST thread (conditional)
        #[cfg(feature = "rest")]
        let rest_handle = if let Some(ref listener_ref) = std_listener {
            let listener = listener_ref.try_clone().map_err(AppError::Io)?;
            let state = app_state.clone();
            let mut rest_shutdown_rx = shutdown_rx.clone();
            Some(
                std::thread::Builder::new()
                    .name("vta-rest".into())
                    .spawn(move || run_rest_thread(listener, state, &mut rest_shutdown_rx))
                    .map_err(|e| AppError::Internal(format!("failed to spawn REST thread: {e}")))?,
            )
        } else {
            None
        };
        #[cfg(not(feature = "rest"))]
        let rest_handle: Option<std::thread::JoinHandle<()>> = None;

        // Start DIDComm service (conditional)
        #[cfg(feature = "didcomm")]
        let didcomm_service: Option<DIDCommService> = if let Some(ref vta_state) = vta_state {
            match (&auth.secrets_resolver, &config.vta_did, &config.messaging) {
                (Some(sr), Some(vta_did), Some(messaging_config)) => {
                    // Collect secrets using the VM IDs from init_auth (correct for both
                    // did:key and did:webvh — avoids hardcoding #key-0/#key-1 fragments).
                    let mut secrets = Vec::new();
                    if let Some(ref signing_id) = auth.signing_vm_id
                        && let Some(s) = sr.get_secret(signing_id).await
                    {
                        secrets.push(s);
                    }
                    if let Some(ref ka_id) = auth.ka_vm_id
                        && let Some(s) = sr.get_secret(ka_id).await
                    {
                        secrets.push(s);
                    }

                    let profile = TDKProfile::new(
                        "VTA",
                        vta_did,
                        Some(&messaging_config.mediator_did),
                        secrets,
                    );

                    // Build a TDKConfig for the DIDComm listener so it uses the
                    // same resolver mode as the VTA (network-mode in TEE enclaves).
                    let listener_tdk_config = {
                        let mut builder = affinidi_tdk::common::config::TDKConfig::builder()
                            .with_load_environment(false);
                        if let Some(ref url) = config.resolver_url {
                            let resolver_config = DIDCacheConfigBuilder::default()
                                .with_network_mode(url)
                                .build();
                            builder = builder.with_did_resolver_config(resolver_config);
                        }
                        builder.build().ok()
                    };

                    let service_config = DIDCommServiceConfig {
                        listeners: vec![ListenerConfig {
                            id: "vta-main".into(),
                            profile,
                            restart_policy: RestartPolicy::Always {
                                backoff: RetryConfig {
                                    initial_delay_secs: 5,
                                    max_delay_secs: 60,
                                },
                            },
                            tdk_config: listener_tdk_config,
                            ..Default::default()
                        }],
                    };

                    let handler = messaging::router::build_handler(
                        Arc::clone(vta_state),
                        app_state.clone(),
                        didcomm_bridge.clone(),
                    )
                    .map_err(|e| {
                        AppError::Internal(format!("failed to build DIDComm handler: {e}"))
                    })?;

                    match DIDCommService::start(service_config, handler, didcomm_shutdown.clone())
                        .await
                    {
                        Ok(service) => {
                            // Wait for the mediator connection before accepting traffic.
                            // Race the wait against shutdown so a Ctrl-C while the
                            // mediator is unreachable doesn't park us here for the full
                            // 30s — `wait_connected` is itself signal-deaf upstream.
                            tokio::select! {
                                res = service.wait_connected(
                                    "vta-main",
                                    Duration::from_secs(30),
                                ) => {
                                    if let Err(e) = res {
                                        warn!("DIDComm listener not connected after 30s: {e}");
                                    }
                                }
                                _ = didcomm_shutdown.cancelled() => {
                                    info!("shutdown received before mediator connected");
                                }
                            }
                            didcomm_bridge.set_service(service.clone());
                            spawn_event_logger(service.clone());
                            info!("DIDComm service started");
                            Some(service)
                        }
                        Err(e) => {
                            warn!("failed to start DIDComm service: {e}");
                            None
                        }
                    }
                }
                _ => {
                    info!("DIDComm not configured — service not started");
                    None
                }
            }
        } else {
            None
        };
        #[cfg(not(feature = "didcomm"))]
        let didcomm_service: Option<()> = None;

        // Spawn the teardown channel consumer. The drain sweeper
        // sends mediator DIDs over `teardown_rx` whenever a TTL
        // fires; this task translates each signal into a
        // `DIDCommService::remove_listener` call. If DIDComm
        // isn't running, the loop still runs but every recv is a
        // no-op — drains still get cleaned up at the registry +
        // keyspace level by the sweeper.
        #[cfg(all(feature = "webvh", feature = "didcomm"))]
        let _teardown_handle = {
            let didcomm_service_ref = didcomm_service.clone();
            let mut teardown_rx = teardown_rx;
            let mut shutdown_rx_for_teardown = shutdown_rx.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown_rx_for_teardown.changed() => {
                            if *shutdown_rx_for_teardown.borrow() {
                                break;
                            }
                        }
                        msg = teardown_rx.recv() => {
                            match msg {
                                None => break,
                                Some(mediator_did) => {
                                    if let Some(ref svc) = didcomm_service_ref {
                                        if let Err(e) = svc.remove_listener(&mediator_did).await {
                                            warn!(
                                                mediator = %mediator_did,
                                                error = %e,
                                                "drain teardown: remove_listener failed"
                                            );
                                        } else {
                                            info!(
                                                mediator = %mediator_did,
                                                "drain teardown: listener removed"
                                            );
                                        }
                                    } else {
                                        debug!(
                                            mediator = %mediator_did,
                                            "drain teardown: DIDComm not running, skipping remove_listener"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                debug!("teardown consumer task exiting");
            })
        };
        #[cfg(not(all(feature = "webvh", feature = "didcomm")))]
        let _teardown_handle: Option<tokio::task::JoinHandle<()>> = None;

        // Storage thread always runs
        let mut storage_shutdown_rx = shutdown_rx.clone();
        let storage_handle = std::thread::Builder::new()
            .name("vta-storage".into())
            .spawn(move || {
                run_storage_thread(
                    storage_store,
                    storage_sessions_ks,
                    storage_audit_ks,
                    storage_acl_ks,
                    storage_backup_bundles_ks,
                    storage_backup_blob_dir,
                    storage_audit_config,
                    storage_auth_config,
                    has_auth,
                    &mut storage_shutdown_rx,
                )
            })
            .map_err(|e| AppError::Internal(format!("failed to spawn storage thread: {e}")))?;

        // ── Wait for shutdown or restart ──────────────────────────
        let mut any_panic = false;
        let is_restart;

        if let Some(handle) = rest_handle {
            // REST thread blocks — wait for it, or for restart signal
            tokio::select! {
                result = tokio::task::spawn_blocking(move || handle.join()) => {
                    match result {
                        Ok(Ok(())) => info!("REST thread stopped"),
                        Ok(Err(_panic)) => { error!("REST thread panicked"); any_panic = true; }
                        Err(e) => { error!("failed to join REST thread: {e}"); any_panic = true; }
                    }
                    is_restart = false;
                }
                _ = restart_rx.changed() => {
                    info!("soft restart requested — shutting down services");
                    let _ = shutdown_tx.send(true);
                    is_restart = true;
                }
            }
        } else {
            // No REST thread — wait for shutdown or restart
            tokio::select! {
                _ = async {
                    let mut wait_rx = shutdown_rx.clone();
                    let _ = wait_rx.changed().await;
                } => {
                    is_restart = false;
                }
                _ = restart_rx.changed() => {
                    info!("soft restart requested — shutting down services");
                    let _ = shutdown_tx.send(true);
                    is_restart = true;
                }
            }
        }

        // Gracefully shut down the DIDComm service and wait for listeners
        // to disconnect from the mediator.
        #[cfg(feature = "didcomm")]
        if let Some(ref service) = didcomm_service {
            service.shutdown().await;
            info!("DIDComm service stopped");
        }
        #[cfg(not(feature = "didcomm"))]
        let _ = didcomm_service;

        if any_panic {
            let _ = shutdown_tx.send(true);
        }

        // Join storage last — guarantees all writes flushed before database closes
        match storage_handle.join() {
            Ok(()) => info!("storage thread stopped"),
            Err(_panic) => {
                error!("storage thread panicked");
                any_panic = true;
            }
        }

        if any_panic {
            return Err(AppError::Internal("one or more threads panicked".into()));
        }

        if !is_restart {
            info!("server shut down");
            return Ok(());
        }

        // ── Soft restart: reload config and re-derive keys ───────
        info!("soft restart: re-initializing services");

        // Config and seed are updated in-memory by the import handler.
        // The restart loop re-initializes auth and keyspace handles from
        // the current config and seed_store on the next iteration.
    }
}

/// Storage thread: runs session cleanup loop and persists the store on shutdown.
#[allow(clippy::too_many_arguments)]
fn run_storage_thread(
    store: Store,
    sessions_ks: KeyspaceHandle,
    audit_ks: KeyspaceHandle,
    acl_ks: KeyspaceHandle,
    backup_bundles_ks_storage: KeyspaceHandle,
    backup_blob_dir_storage: std::path::PathBuf,
    audit_config: crate::config::AuditConfig,
    auth_config: AuthConfig,
    has_auth: bool,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build storage runtime");

    rt.block_on(async {
        info!("storage thread started");

        if has_auth {
            let interval = Duration::from_secs(auth_config.session_cleanup_interval);
            let mut timer = tokio::time::interval(interval);
            // First tick completes immediately; skip it so cleanup doesn't run at startup
            timer.tick().await;

            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        if let Err(e) = cleanup_expired_sessions(&sessions_ks, auth_config.challenge_ttl).await {
                            warn!("session cleanup error: {e}");
                        }
                        // Also clean up expired audit logs
                        let audit_retention = audit_config.retention_days;
                        if let Err(e) = crate::audit::cleanup_expired_logs(&audit_ks, audit_retention).await {
                            warn!("audit cleanup error: {e}");
                        }
                        // Prune expired AclEntry rows and PendingBootstrap rows.
                        // `audit_ks` threaded in so each deletion produces
                        // an `acl.expire` audit entry — without it, the
                        // sweeper's removals leave no trail and operators
                        // can't distinguish "entry was never created" from
                        // "entry was created then expired and pruned".
                        if let Err(e) =
                            crate::acl_sweeper::sweep_expired(&acl_ks, &audit_ks).await
                        {
                            warn!("acl sweeper error: {e}");
                        }
                        // Expire & retention-prune in-flight backup
                        // bundles (descriptor-pattern slice). TTL
                        // pass transitions stale non-terminal records
                        // to Expired; retention pass deletes terminal
                        // records older than the 24h audit window.
                        if let Err(e) = crate::backup_bundle_sweeper::sweep_bundles(
                            &backup_bundles_ks_storage,
                            &backup_blob_dir_storage,
                        )
                        .await
                        {
                            warn!("backup bundle sweeper error: {e}");
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        info!("storage thread shutting down");
                        break;
                    }
                }
            }
        } else {
            // No auth — just wait for shutdown
            let _ = shutdown_rx.changed().await;
            info!("storage thread shutting down");
        }

        // Persist store before closing
        if let Err(e) = store.persist().await {
            error!("failed to persist store on shutdown: {e}");
        } else {
            info!("store persisted");
        }
    });
}

/// REST thread: serves the Axum HTTP server.
#[cfg(feature = "rest")]
fn run_rest_thread(
    std_listener: std::net::TcpListener,
    mut state: AppState,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build REST runtime");

    rt.block_on(async {
        info!("REST thread started");

        // Install Prometheus metrics recorder (once per process)
        let metrics_handle = crate::metrics::install();
        state.metrics_handle = Some(metrics_handle);

        let listener = tokio::net::TcpListener::from_std(std_listener)
            .expect("failed to convert std TcpListener to tokio TcpListener");

        // Snapshot the CORS origins for the router build. The config
        // is reloadable, but a router rebuild requires a full
        // service restart (which the operator triggers via
        // /vta/restart after editing the file), so reading the
        // current values here is correct.
        let (cors_origins, trust_xff) = {
            let cfg = state.config.read().await;
            (cfg.server.cors_origins.clone(), cfg.server.trust_xff)
        };
        let traced_routes = routes::router_with_cors(&cors_origins, trust_xff)
            .with_state(state.clone())
            .layer(axum::middleware::from_fn(crate::metrics::track_metrics))
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                    .on_request(DefaultOnRequest::new().level(Level::INFO))
                    .on_response(DefaultOnResponse::new().level(Level::INFO)),
            );

        // `/health` stays out of the trace + metrics layers (it's a
        // high-frequency probe), but still needs the API's CORS policy
        // so browser tools can run their cross-origin connectivity
        // check against it.
        let app =
            traced_routes.merge(routes::health_router_with_cors(&cors_origins).with_state(state));

        let shutdown_rx = shutdown_rx.clone();
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let mut rx = shutdown_rx;
            let _ = rx.changed().await;
        })
        .await
        .expect("axum serve failed");

        info!("REST thread shutting down");
    });
}

/// Initialize DID resolver, secrets resolver, and JWT keys for authentication.
///
/// Returns `None` values if the VTA DID is not configured (server still starts
/// so the setup wizard can be run first).
/// Result of auth initialization, bundling all outputs including the
/// verification-method IDs that were inserted into the secrets resolver.
struct AuthInit {
    did_resolver: Option<DIDCacheClient>,
    secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    jwt_keys: Option<Arc<JwtKeys>>,
    atm: Option<ATM>,
    /// Signing verification method ID (e.g. `{did}#key-0` or `{did}#{ed_pub_mb}`).
    /// Consumed only by the DIDComm secret-collection path; cfg-gated to
    /// keep non-didcomm builds warning-free.
    #[cfg_attr(not(feature = "didcomm"), allow(dead_code))]
    signing_vm_id: Option<String>,
    /// Key-agreement verification method ID (e.g. `{did}#key-1` or `{did}#{x_pub_mb}`).
    #[cfg_attr(not(feature = "didcomm"), allow(dead_code))]
    ka_vm_id: Option<String>,
}

impl AuthInit {
    fn empty() -> Self {
        Self {
            did_resolver: None,
            secrets_resolver: None,
            jwt_keys: None,
            atm: None,
            signing_vm_id: None,
            ka_vm_id: None,
        }
    }
}

async fn init_auth(
    config: &AppConfig,
    seed_store: &dyn SeedStore,
    keys_ks: &KeyspaceHandle,
) -> AuthInit {
    let vta_did = match &config.vta_did {
        Some(did) => did.clone(),
        None => {
            warn!("vta_did not configured — auth endpoints will not work (run setup first)");
            return AuthInit::empty();
        }
    };

    // Look up VTA key paths from stored key records
    let (signing_path, ka_path, vta_seed_id) = match find_vta_key_paths(&vta_did, keys_ks).await {
        Ok(paths) => paths,
        Err(e) => {
            warn!(
                "failed to find VTA key records: {e} — auth endpoints will not work (run setup first)"
            );
            return AuthInit::empty();
        }
    };

    // Load seed for VTA keys (uses the seed generation from the key record)
    let seed = match load_seed_bytes(keys_ks, seed_store, vta_seed_id).await {
        Ok(s) => s,
        Err(e) => {
            warn!("failed to load seed: {e} — auth endpoints will not work");
            return AuthInit::empty();
        }
    };

    let root = match ExtendedSigningKey::from_seed(&seed) {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to create BIP-32 root key: {e} — auth endpoints will not work");
            return AuthInit::empty();
        }
    };

    // 1. DID resolver (network mode if resolver_url is set, local mode otherwise)
    let resolver_config = {
        let mut builder = DIDCacheConfigBuilder::default();
        if let Some(ref url) = config.resolver_url {
            info!(url = %url, "DID resolver using network mode (remote resolver)");
            builder = builder.with_network_mode(url);
        } else {
            info!("DID resolver using local mode");
        }
        builder.build()
    };
    let did_resolver = match DIDCacheClient::new(resolver_config).await {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to create DID resolver: {e} — auth endpoints will not work");
            return AuthInit::empty();
        }
    };

    // 2. Secrets resolver with VTA's Ed25519 + X25519 secrets
    let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;

    // Track verification-method IDs so DIDComm consumers use the right fragment.
    let mut signing_vm_id: Option<String> = None;
    let mut ka_vm_id: Option<String> = None;

    if vta_did.starts_with("did:key:") {
        // did:key uses fragment IDs like {did}#{ed_pub_mb} and {did}#{x_pub_mb},
        // and the X25519 key is derived FROM the Ed25519 key (not independently).
        // Use the SDK helper which handles both correctly.
        let dp: ed25519_dalek_bip32::DerivationPath = match signing_path.parse() {
            Ok(p) => p,
            Err(e) => {
                warn!("invalid signing derivation path: {e}");
                return AuthInit {
                    did_resolver: Some(did_resolver),
                    ..AuthInit::empty()
                };
            }
        };
        match root.derive(&dp) {
            Ok(derived) => {
                let seed_bytes: &[u8; 32] = derived.signing_key.as_bytes();
                match vta_sdk::did_key::secrets_from_did_key(&vta_did, seed_bytes) {
                    Ok(secrets) => {
                        signing_vm_id = Some(secrets.signing.id.clone());
                        ka_vm_id = Some(secrets.key_agreement.id.clone());
                        info!(signing_id = %secrets.signing.id, ka_id = %secrets.key_agreement.id, "did:key secrets loaded");
                        secrets_resolver.insert(secrets.signing).await;
                        secrets_resolver.insert(secrets.key_agreement).await;
                    }
                    Err(e) => {
                        warn!("failed to build did:key secrets: {e} — auth will not work");
                        return AuthInit {
                            did_resolver: Some(did_resolver),
                            ..AuthInit::empty()
                        };
                    }
                }
            }
            Err(e) => warn!("failed to derive VTA signing key: {e}"),
        }
    } else {
        // did:webvh / other methods: use #key-0 / #key-1 fragment convention
        // with independently derived Ed25519 + X25519 keys.
        let ka_path = match ka_path {
            Some(p) => p,
            None => {
                warn!(
                    "VTA key-agreement record missing — auth endpoints will not work (run setup first)"
                );
                return AuthInit {
                    did_resolver: Some(did_resolver),
                    ..AuthInit::empty()
                };
            }
        };

        signing_vm_id = Some(format!("{vta_did}#key-0"));
        ka_vm_id = Some(format!("{vta_did}#key-1"));

        // Load stored key records for validation
        let stored_signing: Option<KeyRecord> = keys_ks
            .get(crate::keys::store_key(&format!("{vta_did}#key-0")))
            .await
            .ok()
            .flatten();
        let stored_ka: Option<KeyRecord> = keys_ks
            .get(crate::keys::store_key(&format!("{vta_did}#key-1")))
            .await
            .ok()
            .flatten();

        // Derive and insert VTA signing secret (Ed25519)
        match root.derive_ed25519(&signing_path) {
            Ok(mut signing_secret) => {
                if let Some(ref record) = stored_signing {
                    match signing_secret.get_public_keymultibase() {
                        Ok(runtime_pub) if runtime_pub != record.public_key => {
                            error!(
                                key_id = %format!("{vta_did}#key-0"),
                                stored = %record.public_key,
                                runtime = %runtime_pub,
                                "SIGNING KEY MISMATCH: runtime-derived Ed25519 public key does not match \
                                 the key stored in the key record (and published in the DID document). \
                                 DIDComm message signing/verification will fail. \
                                 This likely means the DID was created with different code or seed."
                            );
                        }
                        Ok(runtime_pub) => {
                            info!(key_id = %format!("{vta_did}#key-0"), pub_key = %runtime_pub, "signing key validated");
                        }
                        Err(e) => warn!("could not extract signing public key for validation: {e}"),
                    }
                }
                signing_secret.id = format!("{vta_did}#key-0");
                secrets_resolver.insert(signing_secret).await;
            }
            Err(e) => warn!("failed to derive VTA signing key: {e}"),
        }

        // Derive and insert VTA key-agreement secret (X25519)
        match root.derive_x25519(&ka_path) {
            Ok(mut ka_secret) => {
                if let Some(ref record) = stored_ka {
                    match ka_secret.get_public_keymultibase() {
                        Ok(runtime_pub) if runtime_pub != record.public_key => {
                            error!(
                                key_id = %format!("{vta_did}#key-1"),
                                stored = %record.public_key,
                                runtime = %runtime_pub,
                                "KEY-AGREEMENT KEY MISMATCH: runtime-derived X25519 public key does not match \
                                 the key stored in the key record (and published in the DID document). \
                                 DIDComm encryption/decryption will fail. Others will encrypt to the DID \
                                 document key but this VTA holds a different private key. \
                                 The DID document must be updated or the VTA identity must be regenerated."
                            );
                        }
                        Ok(runtime_pub) => {
                            info!(key_id = %format!("{vta_did}#key-1"), pub_key = %runtime_pub, "key-agreement key validated");
                        }
                        Err(e) => warn!("could not extract KA public key for validation: {e}"),
                    }
                }
                ka_secret.id = format!("{vta_did}#key-1");
                secrets_resolver.insert(ka_secret).await;
            }
            Err(e) => warn!("failed to derive VTA key-agreement key: {e}"),
        }
    }

    // 3. JWT signing key from config (random key, not BIP-32 derived)
    let jwt_keys = match &config.auth.jwt_signing_key {
        Some(b64) => match decode_jwt_key(b64) {
            Ok(k) => k,
            Err(e) => {
                warn!("failed to load JWT signing key: {e} — auth endpoints will not work");
                return AuthInit {
                    did_resolver: Some(did_resolver),
                    secrets_resolver: Some(Arc::new(secrets_resolver)),
                    signing_vm_id,
                    ka_vm_id,
                    ..AuthInit::empty()
                };
            }
        },
        None => {
            warn!(
                "auth.jwt_signing_key not configured — auth endpoints will not work (run setup first)"
            );
            return AuthInit {
                did_resolver: Some(did_resolver),
                secrets_resolver: Some(Arc::new(secrets_resolver)),
                signing_vm_id,
                ka_vm_id,
                ..AuthInit::empty()
            };
        }
    };

    // 4. Build ATM for DIDComm message unpacking (used by auth endpoints)
    let secrets_resolver = Arc::new(secrets_resolver);
    let atm = {
        let tdk_config = TDKConfig::builder()
            .with_did_resolver(did_resolver.clone())
            .with_secrets_resolver((*secrets_resolver).clone())
            .with_load_environment(false)
            .build();
        match tdk_config {
            Ok(cfg) => match TDKSharedState::new(cfg).await {
                Ok(tdk) => {
                    match ATM::new(ATMConfig::builder().build().unwrap(), Arc::new(tdk)).await {
                        Ok(a) => Some(a),
                        Err(e) => {
                            warn!("failed to create ATM for auth unpack: {e}");
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!("failed to create TDK shared state: {e}");
                    None
                }
            },
            Err(e) => {
                warn!("failed to build TDK config: {e}");
                None
            }
        }
    };

    info!("auth initialized for DID {vta_did}");

    AuthInit {
        did_resolver: Some(did_resolver),
        secrets_resolver: Some(secrets_resolver),
        jwt_keys: Some(Arc::new(jwt_keys)),
        atm,
        signing_vm_id,
        ka_vm_id,
    }
}

/// Look up VTA signing and key-agreement derivation paths from stored key records.
///
/// `did:webvh` (and other methods with independently-derived X25519) stores
/// records at both `#key-0` and `#key-1`. `did:key` stores only `#key-0`
/// because its X25519 key is curve-converted from Ed25519 at runtime, not
/// independently derived — there is no separate path to record.
///
/// Returns `(signing_path, ka_path, seed_id)` where `ka_path` is `None` for
/// `did:key` and `seed_id` comes from the signing key record.
async fn find_vta_key_paths(
    vta_did: &str,
    keys_ks: &KeyspaceHandle,
) -> Result<(String, Option<String>, Option<u32>), AppError> {
    let signing_key_id = format!("{vta_did}#key-0");

    let signing: KeyRecord = keys_ks
        .get(crate::keys::store_key(&signing_key_id))
        .await?
        .ok_or_else(|| AppError::NotFound("VTA signing key not found".into()))?;

    let ka_path = if vta_did.starts_with("did:key:") {
        None
    } else {
        let ka_key_id = format!("{vta_did}#key-1");
        let ka: KeyRecord = keys_ks
            .get(crate::keys::store_key(&ka_key_id))
            .await?
            .ok_or_else(|| AppError::NotFound("VTA key-agreement key not found".into()))?;
        Some(ka.derivation_path)
    };

    debug!(signing_path = %signing.derivation_path, ka_path = ?ka_path, "VTA key paths resolved");
    Ok((signing.derivation_path, ka_path, signing.seed_id))
}

/// Decode a base64url-no-pad JWT signing key and construct `JwtKeys`.
fn decode_jwt_key(b64: &str) -> Result<JwtKeys, AppError> {
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| AppError::Config(format!("invalid jwt_signing_key base64: {e}")))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::Config("jwt_signing_key must be exactly 32 bytes".into()))?;
    let keys = JwtKeys::from_ed25519_bytes(&key_bytes, "VTA")?;
    debug!("JWT signing key decoded successfully");
    Ok(keys)
}

/// Spawn a background task that logs DIDComm listener lifecycle events.
#[cfg(feature = "didcomm")]
fn spawn_event_logger(service: DIDCommService) {
    use affinidi_messaging_didcomm_service::ListenerEvent;

    let mut rx = service.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(ListenerEvent::Connected { listener_id }) => {
                    info!(listener = %listener_id, "DIDComm listener connected to mediator");
                }
                Ok(ListenerEvent::Disconnected { listener_id, error }) => {
                    warn!(
                        listener = %listener_id,
                        error = error.as_deref().unwrap_or("none"),
                        "DIDComm listener disconnected from mediator"
                    );
                }
                Ok(ListenerEvent::Restarting {
                    listener_id,
                    attempt,
                    delay,
                }) => {
                    info!(
                        listener = %listener_id,
                        attempt,
                        delay_secs = delay.as_secs(),
                        "DIDComm listener restarting"
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!(skipped = n, "DIDComm event logger lagged");
                }
            }
        }
    });
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => info!("received SIGINT"),
        () = terminate => info!("received SIGTERM"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyType, save_key_record};
    use crate::store::Store;
    use vti_common::config::StoreConfig;

    fn temp_keys_ks() -> (Store, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store open");
        let keys_ks = store.keyspace("keys").expect("keys keyspace");
        (store, keys_ks, dir)
    }

    /// `did:key` VTAs only store the Ed25519 signing record at `#key-0`;
    /// the X25519 key-agreement secret is curve-converted from Ed25519 at
    /// runtime, so a `#key-1` record is intentionally absent.
    /// `find_vta_key_paths` must succeed without it.
    #[tokio::test]
    async fn find_vta_key_paths_returns_none_ka_for_did_key() {
        let (_store, keys_ks, _dir) = temp_keys_ks();
        let did = "did:key:z6MkTestKey";

        save_key_record(
            &keys_ks,
            &format!("{did}#key-0"),
            "m/44'/0'/0'",
            KeyType::Ed25519,
            "z6MkSigningPub",
            "VTA signing key",
            Some("vta"),
            Some(0),
        )
        .await
        .unwrap();

        let (signing_path, ka_path, seed_id) =
            find_vta_key_paths(did, &keys_ks).await.expect("paths");

        assert_eq!(signing_path, "m/44'/0'/0'");
        assert!(ka_path.is_none(), "did:key must not require #key-1 lookup");
        assert_eq!(seed_id, Some(0));
    }

    /// `did:webvh` (and any non-`did:key` method) keeps the
    /// independently-derived X25519 record at `#key-1`, and
    /// `find_vta_key_paths` must surface it.
    #[tokio::test]
    async fn find_vta_key_paths_loads_ka_for_did_webvh() {
        let (_store, keys_ks, _dir) = temp_keys_ks();
        let did = "did:webvh:abc:example.com:vta";

        save_key_record(
            &keys_ks,
            &format!("{did}#key-0"),
            "m/44'/0'/0'",
            KeyType::Ed25519,
            "z6MkSigningPub",
            "VTA signing key",
            Some("vta"),
            Some(0),
        )
        .await
        .unwrap();
        save_key_record(
            &keys_ks,
            &format!("{did}#key-1"),
            "m/44'/0'/1'",
            KeyType::X25519,
            "z6LSKaPub",
            "VTA key-agreement key",
            Some("vta"),
            Some(0),
        )
        .await
        .unwrap();

        let (signing_path, ka_path, _seed_id) =
            find_vta_key_paths(did, &keys_ks).await.expect("paths");

        assert_eq!(signing_path, "m/44'/0'/0'");
        assert_eq!(ka_path.as_deref(), Some("m/44'/0'/1'"));
    }

    /// A `did:webvh` setup that is missing its `#key-1` record is broken —
    /// `find_vta_key_paths` must return `NotFound` rather than silently
    /// degrading to a `None` ka_path. (The `did:key` short-circuit is
    /// keyed off the DID prefix, not off record presence, so a missing
    /// record for non-`did:key` is genuinely an error.)
    #[tokio::test]
    async fn find_vta_key_paths_errors_when_did_webvh_missing_ka() {
        let (_store, keys_ks, _dir) = temp_keys_ks();
        let did = "did:webvh:abc:example.com:vta";

        save_key_record(
            &keys_ks,
            &format!("{did}#key-0"),
            "m/44'/0'/0'",
            KeyType::Ed25519,
            "z6MkSigningPub",
            "VTA signing key",
            Some("vta"),
            Some(0),
        )
        .await
        .unwrap();

        let result = find_vta_key_paths(did, &keys_ks).await;
        assert!(
            matches!(result, Err(AppError::NotFound(_))),
            "expected NotFound for did:webvh missing #key-1, got {result:?}"
        );
    }
}
