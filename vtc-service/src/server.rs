use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver, secrets::Secret};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::auth::AuthState;
use crate::auth::jwt::JwtKeys;
use crate::auth::session::cleanup_expired_sessions;
use crate::config::{AppConfig, AuthConfig};
use crate::error::AppError;
use crate::install::{InstallTokenSigner, InstallTokenStore};
use crate::keys::seed_store::SecretStore;
use crate::messaging;
use crate::routes;
use crate::store::{KeyspaceHandle, Store};
use crate::supervisor::{SupervisorKind, detect_supervisor};
use tokio::sync::{RwLock, watch};
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn};
use vti_common::audit::{AuditKeyStore, AuditWriter};
use vti_common::auth::passkey::{PasskeyState, build_webauthn};
use webauthn_rs::Webauthn;

/// Default enrolment-invite TTL surfaced by `PasskeyState::enrollment_ttl`.
/// Admin-invite enrolment lands in M0.6; until then this constant is the
/// canonical "how long is an admin invite redeemable" value. An hour
/// is the same default `webvh-common`'s passkey routes use.
const DEFAULT_ENROLLMENT_TTL_SECS: u64 = 60 * 60;

/// Whole-request timeout for the REST surface (P0.10). A wedged handler — a
/// registry call without its own timeout, a slow downstream — must not hold
/// its connection (and a runtime worker) open forever. `tower_http`'s
/// `TimeoutLayer` returns `408 Request Timeout` when exceeded.
const REST_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone)]
#[allow(dead_code)]
pub struct AppState {
    pub sessions_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub community_ks: KeyspaceHandle,
    pub config_ks: KeyspaceHandle,
    pub passkey_ks: KeyspaceHandle,
    pub install_ks: KeyspaceHandle,
    pub members_ks: KeyspaceHandle,
    pub join_requests_ks: KeyspaceHandle,
    /// Uploaded Rego policies (M2.2). Holds every revision; the
    /// active pointer for each purpose lives in
    /// [`Self::active_policies_ks`].
    pub policies_ks: KeyspaceHandle,
    /// Per-purpose pointer to the currently-active policy id. One
    /// row per [`crate::policy::PolicyPurpose`] variant. M2.3's
    /// activate endpoint flips this; M2.6 / M2.7 / M2.13 read it.
    pub active_policies_ks: KeyspaceHandle,
    /// BitstringStatusList state (M2.10). One row per
    /// [`affinidi_status_list::StatusPurpose`] variant. M2.11's
    /// public route reads from it; M2.14's flip-on-removal path
    /// writes.
    pub status_lists_ks: KeyspaceHandle,
    /// Local mirror of trust-registry records (Phase 3 M3.1).
    /// Updated when a `SyncJob` completes successfully so the
    /// daemon can detect drift at boot.
    pub registry_records_ks: KeyspaceHandle,
    /// Pending / in-flight / failed trust-registry sync jobs
    /// (Phase 3 M3.1). Drained by `MembershipSyncer` (M3.4).
    pub sync_queue_ks: KeyspaceHandle,
    /// Singleton row tracking the audit-log tail's last-seen
    /// timestamp for boot-time replay (Phase 3 M3.3).
    pub sync_cursor_ks: KeyspaceHandle,
    /// VRC trust-edge rows (Phase 4 M4.5). Primary keyspace.
    pub relationships_ks: KeyspaceHandle,
    /// VRC per-DID secondary index (Phase 4 M4.5). Keyed by
    /// `<did>:<vrc-id>` so per-DID list queries are O(matched
    /// rows). CAS-paired with `relationships_ks`.
    pub relationships_by_did_ks: KeyspaceHandle,
    /// Operator-uploaded endorsement type registry (Phase 4
    /// M4.8.0). Only registered types are issuable.
    pub endorsement_types_ks: KeyspaceHandle,
    /// Credential-type schema store (Phase 2 task 2.2): the Issues / Accepts
    /// registry binding each type to a DTG catalog type + JSON Schema.
    pub schemas_ks: KeyspaceHandle,
    /// Issued custom endorsement rows (Phase 4 M4.7).
    /// Tracked here for list + revoke surfaces; the VEC body
    /// itself is signed + returned at issuance time.
    pub endorsements_ks: KeyspaceHandle,
    pub audit_ks: KeyspaceHandle,
    pub audit_key_ks: KeyspaceHandle,
    /// Trust-registry client (Phase 3 M3.2). `None` when
    /// `config.registry.url` is unset — the daemon runs in
    /// "no-registry" mode and `registry_health.status()` stays
    /// `Degraded`.
    pub registry_client: Option<Arc<dyn crate::registry::TrustRegistryClient>>,
    /// Live trust-registry reachability + last-success /
    /// last-failure surface (Phase 3 M3.2). The community-
    /// profile + diagnostics handlers read this; the
    /// boot/probe paths write it.
    pub registry_health: crate::registry::RegistryHealth,
    pub config: Arc<RwLock<AppConfig>>,
    pub did_resolver: Option<DIDCacheClient>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    pub jwt_keys: Option<Arc<JwtKeys>>,
    pub atm: Option<ATM>,
    /// WebAuthn relying-party handle. `None` when `config.public_url`
    /// is unset at startup — the install + admin-passkey routes 503
    /// in that case (per `PasskeyState` contract).
    pub webauthn: Option<Arc<Webauthn>>,
    /// Cached `public_url` snapshot for `PasskeyState::public_url`.
    /// Held alongside the `Webauthn` so the trait impl doesn't need
    /// to take an async read-lock on the config every request.
    pub public_url: Option<String>,
    /// EdDSA signer that verifies install tokens and mints setup-session
    /// tokens at the end of the claim ceremony. `None` until the secret
    /// store yields key material — install routes 503 in that case.
    pub install_signer: Option<Arc<InstallTokenSigner>>,
    /// Ed25519 signer that mints VMC, VEC, and BitstringStatusList
    /// credentials (M2.9). Wraps the same `#key-0` secret the
    /// `secrets_resolver` holds. `None` until the secret store
    /// yields key material — credential routes 503 in that case.
    pub credential_signer: Option<Arc<crate::credentials::LocalSigner>>,
    /// Wraps `install_ks` with the claim-window state machine. Cheap
    /// to clone; always present once `install_ks` is open.
    pub install_store: InstallTokenStore,
    /// HMAC-actor-hashing audit envelope writer. `None` until the
    /// secret store yields key material (the audit key is HKDF-
    /// derived from the master seed). Endpoints that emit audit
    /// events 503 in that case.
    pub audit_writer: Option<AuditWriter>,
    /// Sender half of the shared graceful-shutdown channel.
    /// `POST /v1/admin/config/restart` flips this to `true` to
    /// trigger the same drain path SIGINT/SIGTERM use.
    pub shutdown_tx: watch::Sender<bool>,
    /// Cached supervisor probe (M0.8.3). Computed once at startup
    /// — process supervisors don't change during the daemon's
    /// lifetime, and a cached value lets tests inject
    /// `Some(Manual)` / `None` without racing other tests on the
    /// shared `std::env`.
    pub supervisor: Option<SupervisorKind>,
}

impl AuthState for AppState {
    fn jwt_keys(&self) -> Option<&Arc<JwtKeys>> {
        self.jwt_keys.as_ref()
    }
    fn sessions_ks(&self) -> &KeyspaceHandle {
        &self.sessions_ks
    }
}

impl PasskeyState for AppState {
    fn webauthn(&self) -> Option<&Arc<Webauthn>> {
        self.webauthn.as_ref()
    }

    fn acl_ks(&self) -> &KeyspaceHandle {
        &self.acl_ks
    }

    fn access_token_expiry(&self) -> u64 {
        // `config` is wrapped in an `Arc<RwLock<…>>`; the trait method
        // is sync. `try_read` returns immediately — if a writer is
        // mid-update we fall through to the workspace default so the
        // auth layer never blocks. The default values match the
        // compiled-in `AuthConfig::default()` and the runtime tax of
        // missing a recently-updated value is bounded by the JWT TTL
        // anyway.
        self.config
            .try_read()
            .map(|c| c.auth.access_token_expiry)
            .unwrap_or(AuthConfig::default().access_token_expiry)
    }

    fn refresh_token_expiry(&self) -> u64 {
        self.config
            .try_read()
            .map(|c| c.auth.refresh_token_expiry)
            .unwrap_or(AuthConfig::default().refresh_token_expiry)
    }

    fn public_url(&self) -> Option<&str> {
        self.public_url.as_deref()
    }

    fn enrollment_ttl(&self) -> u64 {
        DEFAULT_ENROLLMENT_TTL_SECS
    }
}

pub async fn run(
    config: AppConfig,
    store: Store,
    secret_store: Box<dyn SecretStore>,
) -> Result<(), AppError> {
    // Open cached keyspace handles
    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;
    let community_ks = store.keyspace("community")?;
    let config_ks = store.keyspace("config")?;
    let passkey_ks = store.keyspace("passkey")?;
    let install_ks = store.keyspace("install")?;
    // `install_store` is built later (after `init_auth` yields the storage
    // key) so it wraps the encrypted `install` handle — see P0.7 below.
    let members_ks = store.keyspace("members")?;
    let join_requests_ks = store.keyspace("join_requests")?;
    let policies_ks = store.keyspace("policies")?;
    let active_policies_ks = store.keyspace("active_policies")?;
    let status_lists_ks = store.keyspace("status_lists")?;
    let registry_records_ks = store.keyspace("registry_records")?;
    let sync_queue_ks = store.keyspace("sync_queue")?;
    let sync_cursor_ks = store.keyspace("sync_cursor")?;
    let relationships_ks = store.keyspace("relationships")?;
    let relationships_by_did_ks = store.keyspace("relationships_by_did")?;
    let endorsement_types_ks = store.keyspace("endorsement_types")?;
    let schemas_ks = store.keyspace("schemas")?;
    // Seed the schema store with the built-in catalog Issues types (idempotent;
    // never overwrites operator edits) so the registry reflects what the VTC
    // mints out of the box.
    crate::schemas::seed_default_issues(&schemas_ks).await?;
    let endorsements_ks = store.keyspace("endorsements")?;
    let audit_ks = store.keyspace("audit")?;
    let audit_key_ks = store.keyspace("audit_key")?;

    // M2.5: install the workspace-shipped default policies for any
    // PolicyPurpose that lacks an active row. Idempotent — operator
    // uploads are preserved verbatim. A failure here is non-fatal:
    // policies are only evaluated by handlers that ship in M2.6+,
    // and those handlers default-deny when the active pointer is
    // missing, so a partial install still produces a safe daemon.
    match crate::policy::default::install_defaults(&policies_ks, &active_policies_ks).await {
        Ok(0) => debug!("default policies: every purpose already has an active row"),
        Ok(n) => info!("installed {n} default policy(ies) at boot"),
        Err(e) => warn!("failed to install default policies: {e}"),
    }

    // Self-heal a binary-upgrade-over-old-data state: a ceremony purpose
    // whose active policy predates the decision-pipeline migration
    // (defines `allow`, not `decision`) is non-functional — the routes
    // evaluate `data.<pkg>.decision`. Replace those with the shipped
    // decision-shaped defaults; operator decision-policies are untouched.
    match crate::policy::default::upgrade_legacy_ceremony_defaults(
        &policies_ks,
        &active_policies_ks,
    )
    .await
    {
        Ok(0) => {}
        Ok(n) => info!("upgraded {n} legacy ceremony policy(ies) to decision-shaped defaults"),
        Err(e) => warn!("failed to upgrade legacy ceremony policies: {e}"),
    }

    // M2.10 + M2.11: provision the two BitstringStatusLists.
    // Idempotent — only seeds decoys when the row is brand new.
    // Skipped when `public_url` is unset (pre-setup deployment) —
    // the status-list `list_credential_id` is baked into every
    // VMC's `credentialStatus.statusListCredential`, so we can't
    // mint the row until we know the canonical URL.
    if let Some(public_url) = config.public_url.as_deref() {
        for purpose in [
            affinidi_status_list::StatusPurpose::Revocation,
            affinidi_status_list::StatusPurpose::Suspension,
        ] {
            let url = format!("{public_url}/v1/status-lists/{purpose}");
            match crate::status_list::ensure_initial(&status_lists_ks, purpose, url).await {
                Ok(_) => debug!(?purpose, "status list initialised"),
                Err(e) => warn!(?purpose, "failed to initialise status list: {e}"),
            }
        }
    } else {
        warn!(
            "public_url not configured — status lists deferred; \
             VMC issuance + GET /v1/status-lists/* return 503 until set"
        );
    }

    // M3.2: build the trust-registry client + run the boot
    // health probe. When `registry.url` is unset, the client
    // is `None` and `registry_health` stays Degraded. The
    // periodic probe task is spawned later, after the audit
    // writer is available.
    let registry_health = crate::registry::RegistryHealth::new();
    let registry_client: Option<Arc<dyn crate::registry::TrustRegistryClient>> = match config
        .registry
        .url
        .as_deref()
    {
        Some(url) => {
            let cfg = crate::registry::upstream::UpstreamConfig {
                base_url: url.to_string(),
                http_timeout: std::time::Duration::from_secs(config.registry.http_timeout_seconds),
                authority_did: config.vtc_did.clone(),
            };
            match crate::registry::UpstreamRegistryClient::new(cfg) {
                Ok(c) => Some(Arc::new(c) as Arc<dyn crate::registry::TrustRegistryClient>),
                Err(e) => {
                    warn!(error = ?e, "failed to construct trust-registry client; running with registry features disabled");
                    None
                }
            }
        }
        None => {
            debug!(
                "trust-registry url not configured — registry features disabled; \
                     registry_status reads 'degraded'"
            );
            None
        }
    };

    // Initialize auth infrastructure. Pass the audit keyspaces in so
    // `init_auth` can derive the HMAC audit key from the same secret
    // store contents it uses for the install signer.
    let (
        did_resolver,
        secrets_resolver,
        jwt_keys,
        atm,
        install_signer,
        audit_writer,
        credential_signer,
        storage_key,
    ) = init_auth(
        &config,
        &*secret_store,
        audit_ks.clone(),
        audit_key_ks.clone(),
    )
    .await?;

    // P0.7: `install` (ephemeral install-token signing key) and `passkey`
    // (WebAuthn state) also hold secrets in the clear. `init_auth` already
    // migrated + wrapped `audit_key`; do the same for these two here, where
    // the derived storage key is in scope. Migration is idempotent and
    // crash-safe; a failure aborts boot rather than serving a store with a
    // half-encrypted secret keyspace. `install_store` is (re)built on the
    // wrapped handle so issued tokens are encrypted on disk.
    let (install_ks, passkey_ks, audit_key_ks) = match storage_key {
        Some(key) => {
            let n_install = install_ks.migrate_to_encrypted(key).await?;
            let n_passkey = passkey_ks.migrate_to_encrypted(key).await?;
            if n_install > 0 || n_passkey > 0 {
                info!(
                    "encrypted {n_install} legacy install + {n_passkey} legacy passkey row(s) at rest"
                );
            }
            // `audit_key`'s on-disk rows were already migrated inside
            // `init_auth`; wrap the `AppState`-bound handle too so the
            // field is consistent with what the `AuditKeyStore` uses.
            (
                install_ks.with_encryption(key),
                passkey_ks.with_encryption(key),
                audit_key_ks.with_encryption(key),
            )
        }
        None => (install_ks, passkey_ks, audit_key_ks),
    };
    let install_store = InstallTokenStore::new(install_ks.clone());

    // Build WebAuthn relying party handle from `public_url`. Optional —
    // a serverless / pre-setup deployment has no public URL yet and
    // the install + admin-passkey routes will 503 until one is set.
    let public_url = config.public_url.clone();
    let webauthn = match &public_url {
        Some(url) => match build_webauthn(url) {
            Ok(w) => Some(Arc::new(w)),
            Err(e) => {
                warn!(
                    "failed to build WebAuthn relying party from public_url '{url}': {e} — passkey routes disabled"
                );
                None
            }
        },
        None => {
            debug!("public_url not configured — WebAuthn / passkey routes disabled");
            None
        }
    };

    // Bind TCP listener on the main thread for early port validation
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let std_listener = std::net::TcpListener::bind(&addr).map_err(AppError::Io)?;
    std_listener.set_nonblocking(true).map_err(AppError::Io)?;
    info!("server listening addr={addr}");

    // Shutdown coordination
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn signal handler on the main tokio runtime
    tokio::spawn({
        let shutdown_tx = shutdown_tx.clone();
        async move {
            shutdown_signal().await;
            let _ = shutdown_tx.send(true);
        }
    });

    // Gather DIDComm thread inputs
    let didcomm_config = config.clone();
    let didcomm_secrets = secrets_resolver.clone();
    let didcomm_vtc_did = config.vtc_did.clone();

    // Gather storage thread inputs
    let storage_sessions_ks = sessions_ks.clone();
    let storage_auth_config = config.auth.clone();
    let has_auth = jwt_keys.is_some();

    // Build AppState for the REST thread
    let state = AppState {
        sessions_ks,
        acl_ks,
        community_ks,
        config_ks,
        passkey_ks,
        install_ks,
        members_ks,
        join_requests_ks,
        policies_ks,
        active_policies_ks,
        status_lists_ks: status_lists_ks.clone(),
        registry_records_ks,
        sync_queue_ks,
        sync_cursor_ks,
        relationships_ks,
        relationships_by_did_ks,
        endorsement_types_ks,
        schemas_ks,
        endorsements_ks,
        audit_ks,
        audit_key_ks,
        registry_client: registry_client.clone(),
        registry_health: registry_health.clone(),
        config: Arc::new(RwLock::new(config)),
        did_resolver,
        secrets_resolver,
        jwt_keys,
        atm,
        webauthn,
        public_url,
        install_signer,
        credential_signer: credential_signer.clone(),
        install_store,
        audit_writer,
        shutdown_tx: shutdown_tx.clone(),
        supervisor: detect_supervisor(),
    };

    // Heal missing AdminEntries: any DID with an Admin ACL grant +
    // a PasskeyUser but no AdminEntry gets the AdminEntry synthesised
    // from the PasskeyUser's credentials. Covers daemons where
    // `vtc admin invite` ran before `claim_finish` started writing
    // the AdminEntry — without this, `GET /v1/admin/passkeys` 404s
    // permanently because list reads AdminEntry, not PasskeyUser.
    if let Err(e) = heal_missing_admin_entries(&state).await {
        warn!(error = %e, "admin-entry heal scan failed");
    }

    // One-shot heal for daemons bootstrapped before the install
    // ceremony initialised the community profile. New installs land
    // here as a no-op because `POST /v1/admin/bootstrap` now writes
    // the profile up front; legacy daemons get a one-time create so
    // `GET /v1/community/profile` stops 404'ing in the admin UI.
    // `community_did` is immutable per spec §5.1, so we only heal
    // when `vtc_did` is actually configured.
    //
    // Snapshot the config once for the remainder of the boot path.
    // The earlier `state.config.read().await` repeated six times
    // through the boot section made it ambiguous which copy was
    // canonical and added an awkward "did I drop the guard before
    // the next await?" question to every change. One clone, read
    // many times.
    let boot_cfg = state.config.read().await.clone();
    if let Some(vtc_did) = boot_cfg.vtc_did.clone()
        && crate::community::load_profile(&state.community_ks)
            .await
            .ok()
            .flatten()
            .is_none()
    {
        let profile = crate::community::CommunityProfile::new(&vtc_did, "");
        match crate::community::store_profile(&state.community_ks, &profile).await {
            Ok(()) => info!(
                %vtc_did,
                "initialised default community profile at boot (heal)",
            ),
            Err(e) => warn!(error = %e, "failed to initialise default community profile at boot"),
        }
    }

    // M3.2: boot-time health probe. Best-effort — daemon
    // proceeds regardless. Subsequent periodic probes track
    // the live state.
    if let (Some(client), Some(vtc_did)) =
        (state.registry_client.as_ref(), boot_cfg.vtc_did.clone())
    {
        match client.health().await {
            Ok(()) => {
                state
                    .registry_health
                    .record_success(state.audit_writer.as_ref(), &vtc_did)
                    .await;
                info!("trust-registry health probe passed at boot");
            }
            Err(e) => {
                state
                    .registry_health
                    .record_failure(format!("{e}"), state.audit_writer.as_ref(), &vtc_did)
                    .await;
                warn!(error = %e, "trust-registry health probe failed at boot — running with registry_status=degraded");
            }
        }
    }

    // M3.2: periodic health probe. Each tick re-runs `health()`
    // + updates `registry_health`. Configurable via
    // `registry.health_probe_interval_seconds`; `0` disables.
    let probe_interval_secs = boot_cfg.registry.health_probe_interval_seconds;
    // Skip the periodic probe entirely when `vtc_did` isn't yet set
    // (pre-setup). The previous `unwrap_or("did:key:vtc-unknown")`
    // fallback poisoned every health-probe audit envelope with a
    // sentinel actor — operators couldn't tell a real "boot before
    // setup" event from a misconfigured production daemon. The probe
    // has nothing useful to do until setup completes anyway.
    let probe_did_opt = boot_cfg.vtc_did.clone();
    if registry_client.is_some() && probe_interval_secs > 0 && probe_did_opt.is_some() {
        let probe_client = registry_client.clone().expect("checked is_some");
        let probe_health = registry_health.clone();
        let probe_audit = state.audit_writer.clone();
        let probe_did = probe_did_opt.clone().expect("checked is_some");
        let mut probe_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_secs(probe_interval_secs));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // First tick fires immediately — skip so the
            // periodic probe doesn't overlap the boot probe.
            timer.tick().await;
            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        match probe_client.health().await {
                            Ok(()) => {
                                probe_health
                                    .record_success(probe_audit.as_ref(), &probe_did)
                                    .await;
                            }
                            Err(e) => {
                                probe_health
                                    .record_failure(
                                        format!("{e}"),
                                        probe_audit.as_ref(),
                                        &probe_did,
                                    )
                                    .await;
                            }
                        }
                    }
                    _ = probe_shutdown.changed() => {
                        debug!("trust-registry health probe task shutting down");
                        return;
                    }
                }
            }
        });
    }

    // M3.4: spawn the MembershipSyncer task. Drains the
    // sync_queue against the trust-registry client with
    // exponential backoff + boot-time InFlight recovery.
    // Only runs when a registry is configured — without
    // one, the queue grows visibly via /v1/health/diagnostics
    // but no dispatch happens.
    // Same discipline as the probe above — without a `vtc_did` the
    // syncer's audit envelopes would carry the `vtc-unknown` sentinel
    // and the queue can't usefully dispatch (no identity to sign
    // outbound TRQP calls with).
    let syncer_actor_did_opt = boot_cfg.vtc_did.clone();
    if let (Some(client), Some(actor_did)) =
        (state.registry_client.clone(), syncer_actor_did_opt.clone())
    {
        let rtbf_batch_window_hours = boot_cfg.registry.rtbf_batch_window_hours;
        let syncer = crate::registry::MembershipSyncer::new(
            state.audit_ks.clone(),
            state.sync_queue_ks.clone(),
            state.sync_cursor_ks.clone(),
            state.registry_records_ks.clone(),
            state.policies_ks.clone(),
            state.active_policies_ks.clone(),
            client,
            state.registry_health.clone(),
            state.audit_writer.clone(),
            actor_did,
        )
        .with_rtbf_batch_window_hours(rtbf_batch_window_hours);
        let syncer_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            syncer.run(syncer_shutdown).await;
        });
    }

    // P0.6: spawn the retention sweeper. It was defined but never spawned, so
    // terminal join requests (PII in the submitted VP), expired
    // present-challenge / credx-pending rows, and `Failed` registry sync jobs
    // accumulated forever. Unconditional — unlike the registry syncer, it has
    // no external dependency. Runs on its own task until shutdown.
    crate::join::retention::RetentionSweeper::spawn(
        state.join_requests_ks.clone(),
        state.sync_queue_ks.clone(),
        boot_cfg.join_requests.clone(),
        shutdown_rx.clone(),
    );

    // M0.10: consume + audit any pending emergency-bootstrap marker
    // left behind by `vtc admin emergency-bootstrap`. The marker is
    // **one-shot**: `take_pending_emergency` deletes it as part of
    // reading, so a restart loop emits the loud event exactly once.
    if let (Some(pending), Some(writer)) = (
        state
            .install_store
            .take_pending_emergency()
            .await
            .ok()
            .flatten(),
        state.audit_writer.as_ref(),
    ) {
        warn!(
            operator_hostname = %pending.operator_hostname,
            invoked_at = %pending.invoked_at,
            "EMERGENCY BOOTSTRAP was invoked since the daemon last ran — auditing now",
        );
        if let Err(e) = writer
            .write(
                "did:key:vtc-emergency",
                None,
                vti_common::audit::AuditEvent::EmergencyBootstrapInvoked(
                    vti_common::audit::EmergencyBootstrapData {
                        operator_hostname: pending.operator_hostname,
                        invoked_at: pending.invoked_at,
                    },
                ),
            )
            .await
        {
            error!(error = %e, "failed to emit EmergencyBootstrapInvoked envelope");
        }
    }

    // Snapshot the CORS allowlist + routing config before the
    // AppState `move` into the REST thread. Both layers are fixed
    // at start-up; a future `POST /v1/admin/config/reload` can
    // swap them if operators demand live updates.
    let rest_cors = boot_cfg.cors.clone();
    let rest_routing = boot_cfg.routing.clone();

    // Phase 5 M5.7.2 — emit `AdminUiServed` audit envelope exactly
    // once at boot, after the audit writer is online. Captures the
    // SHA-256 of the baked admin SPA's `index.html` so an operator
    // who suspects a compromise can pin the running build.
    #[cfg(feature = "admin-ui")]
    if let Some(writer) = state.audit_writer.as_ref() {
        let mode = boot_cfg.admin_ui.mode.clone();
        let info = crate::admin_ui::AdminUiInfo::from_embedded(&mode);
        let _ = writer
            .write(
                "daemon",
                None,
                vti_common::audit::AuditEvent::AdminUiServed(
                    vti_common::audit::AdminUiServedData {
                        index_sha256: (*info.index_sha256).clone(),
                        file_count: info.file_count,
                        mode: (*info.mode).clone(),
                    },
                ),
            )
            .await;
    }

    // Spawn three named OS threads
    let mut rest_shutdown_rx = shutdown_rx.clone();
    let rest_state = state.clone();
    let rest_handle = std::thread::Builder::new()
        .name("vtc-rest".into())
        .spawn(move || {
            run_rest_thread(
                std_listener,
                rest_state,
                rest_cors,
                rest_routing,
                &mut rest_shutdown_rx,
            )
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn REST thread: {e}")))?;

    let mut didcomm_shutdown_rx = shutdown_rx.clone();
    let didcomm_state = state.clone();
    let didcomm_handle = std::thread::Builder::new()
        .name("vtc-didcomm".into())
        .spawn(move || {
            run_didcomm_thread(
                didcomm_config,
                didcomm_secrets,
                didcomm_vtc_did,
                didcomm_state,
                &mut didcomm_shutdown_rx,
            )
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn DIDComm thread: {e}")))?;

    let mut storage_shutdown_rx = shutdown_rx.clone();
    let storage_handle = std::thread::Builder::new()
        .name("vtc-storage".into())
        .spawn(move || {
            run_storage_thread(
                store,
                storage_sessions_ks,
                storage_auth_config,
                has_auth,
                &mut storage_shutdown_rx,
            )
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn storage thread: {e}")))?;

    // Join REST + DIDComm in parallel, then storage last
    let (rest_result, didcomm_result) = tokio::join!(
        tokio::task::spawn_blocking(move || rest_handle.join()),
        tokio::task::spawn_blocking(move || didcomm_handle.join()),
    );

    // If either thread panicked, trigger shutdown for the remaining threads
    let mut any_panic = false;

    match rest_result {
        Ok(Ok(())) => info!("REST thread stopped"),
        Ok(Err(_panic)) => {
            error!("REST thread panicked");
            any_panic = true;
        }
        Err(e) => {
            error!("failed to join REST thread: {e}");
            any_panic = true;
        }
    }

    match didcomm_result {
        Ok(Ok(())) => info!("DIDComm thread stopped"),
        Ok(Err(_panic)) => {
            error!("DIDComm thread panicked");
            any_panic = true;
        }
        Err(e) => {
            error!("failed to join DIDComm thread: {e}");
            any_panic = true;
        }
    }

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

    info!("server shut down");
    Ok(())
}

/// Walk the ACL keyspace for `Admin` entries; for each, if a
/// `PasskeyUser` exists for the DID but no `AdminEntry` does,
/// synthesise the `AdminEntry` from the user's registered
/// credentials. Idempotent — no-op once every Admin DID has its
/// entry. Used to repair daemons where the AdminEntry was never
/// written (pre-fix `vtc admin invite` + claim flow, or a partial
/// bootstrap that crashed between PasskeyUser and AdminEntry).
async fn heal_missing_admin_entries(state: &AppState) -> Result<(), AppError> {
    use chrono::Utc;
    use vti_common::auth::passkey::store::get_passkey_user_by_did;

    use crate::acl::admin::{AdminEntry, RegisteredPasskey, get_admin_entry, store_admin_entry};
    // Use the VTC's own ACL type (`VtcRole`), not `vti_common`'s `Role`. The
    // VTC stores `VtcAclEntry`, whose role set includes `Member` (written by a
    // join admit); deserializing those rows via `vti_common::acl` fails with
    // "unknown variant `member`" once any member exists.
    use crate::acl::{VtcRole, list_acl_entries};

    let admins = list_acl_entries(&state.acl_ks).await?;
    let mut healed = 0usize;
    for acl_entry in admins {
        if acl_entry.role != VtcRole::Admin {
            continue;
        }
        if get_admin_entry(&state.passkey_ks, &acl_entry.did)
            .await?
            .is_some()
        {
            continue;
        }
        let Some(pk_user) = get_passkey_user_by_did(&state.passkey_ks, &acl_entry.did).await?
        else {
            // Admin DID with no passkey yet — login is impossible
            // anyway. Leave alone; nothing to heal from.
            continue;
        };
        let now = Utc::now();
        let passkeys: Vec<RegisteredPasskey> = pk_user
            .credentials
            .iter()
            .map(|cred| {
                let cred_id_hex = hex::encode(<_ as AsRef<[u8]>>::as_ref(cred.cred_id()));
                RegisteredPasskey {
                    credential_id: cred_id_hex,
                    label: "install".into(),
                    transports: Vec::new(),
                    registered_at: now,
                    last_used_at: None,
                }
            })
            .collect();
        if passkeys.is_empty() {
            continue;
        }
        let entry = AdminEntry {
            did: acl_entry.did.clone(),
            passkeys,
            extensions: serde_json::Value::Null,
            created_at: now,
        };
        store_admin_entry(&state.passkey_ks, &entry).await?;
        info!(did = %acl_entry.did, "synthesised missing AdminEntry from PasskeyUser (heal)");
        healed += 1;
    }
    if healed > 0 {
        info!(count = healed, "admin-entry heal scan completed");
    }
    Ok(())
}

/// Storage thread: runs session cleanup loop and persists the store on shutdown.
fn run_storage_thread(
    store: Store,
    sessions_ks: KeyspaceHandle,
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

/// Build the [`CorsLayer`] applied to every REST response. Honours
/// the spec §9.3 allowlist:
///
/// - Empty `allowed_origins` → CORS is disabled (no cross-origin
///   responses set the headers); same-origin path-mode deployments
///   never need an entry.
/// - Each origin is reflected verbatim by the `Origin` header
///   match; wildcards are refused at config-load (see
///   `crate::config::validate_cors`), so by the time we get here
///   every entry is a literal `http(s)://host[:port]`.
///
/// `Access-Control-Allow-Headers` is fixed at the workspace's
/// "common" header set (Authorization, Content-Type, Trust-Task,
/// Idempotency-Key). `Access-Control-Allow-Credentials` is `true`
/// so the admin SPA can carry the future cookie session over the
/// allowlist edge; an empty allowlist disables CORS entirely so
/// `credentials: true` is harmless there.
fn build_cors_layer(cors: &crate::config::CorsConfig) -> CorsLayer {
    use axum::http::Method;
    use axum::http::header::{
        ACCESS_CONTROL_ALLOW_HEADERS, AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue,
    };

    if cors.allowed_origins.is_empty() {
        // No origins → same-origin only.
        return CorsLayer::new();
    }

    let allowed_origins: Vec<HeaderValue> = cors
        .allowed_origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();

    let allowed_methods = vec![
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
    ];

    let allowed_headers: Vec<HeaderName> = vec![
        AUTHORIZATION,
        CONTENT_TYPE,
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderName::from_static("trust-task"),
        HeaderName::from_static("idempotency-key"),
    ];

    CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods(allowed_methods)
        .allow_headers(allowed_headers)
        .allow_credentials(true)
}

/// REST thread: serves the Axum HTTP server.
fn run_rest_thread(
    std_listener: std::net::TcpListener,
    state: AppState,
    cors: crate::config::CorsConfig,
    routing: crate::config::RoutingConfig,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    // P0.10: the REST surface must not run CPU-bound work (Argon2id verify on
    // the unauth claim-start, Rego eval, VC signing) on a single executor — a
    // few distinct source IPs hitting claim-start would otherwise saturate the
    // lone thread (the 5 rps governor is per-IP, so it doesn't help). A small
    // worker pool lets concurrent requests progress while one is mid-Argon2id;
    // the heavy calls themselves are also moved off-runtime via `spawn_blocking`.
    let worker_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .clamp(2, 8);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .expect("failed to build REST runtime");

    rt.block_on(async {
        info!(worker_threads, "REST thread started");

        let listener = tokio::net::TcpListener::from_std(std_listener)
            .expect("failed to convert std TcpListener to tokio TcpListener");

        let cors_layer = build_cors_layer(&cors);

        // Subdomain-mode host-dispatch (Phase 5 M5.1.2). The
        // middleware is a no-op when every routing surface has
        // `host = None` (pure path mode), so configuring it
        // unconditionally is cheap.
        let host_map = crate::routing::host_dispatch::HostMap::from_routing(&routing);
        let host_layer =
            axum::middleware::from_fn_with_state(host_map, crate::routing::host_dispatch::enforce);

        // CSRF double-submit + Sec-Fetch-Site check (Phase 5
        // M5.2.2). Bootstrapping flows + the public form-post
        // target are path-exempt — see `routing::csrf` for the
        // exemption list.
        let csrf_layer = axum::middleware::from_fn(crate::routing::csrf::enforce);

        // Public-website state (Phase 5 M5.4). `None` when the
        // operator hasn't set `website.root_dir` — the website
        // sub-router keeps the 503 placeholder in that case.
        #[cfg(feature = "website")]
        let website_state = build_website_state(&state.config).await;

        let trust_xff = state.config.read().await.server.trust_xff;
        // `TimeoutLayer` is the outermost layer so the whole-request budget
        // (P0.10) covers every inner middleware + the handler.
        #[cfg(feature = "website")]
        let app = routes::router_with_xff(&routing, website_state, trust_xff)
            .with_state(state)
            .layer(csrf_layer)
            .layer(host_layer)
            .layer(cors_layer)
            .layer(TraceLayer::new_for_http())
            .layer(TimeoutLayer::new(REST_REQUEST_TIMEOUT));
        #[cfg(not(feature = "website"))]
        let app = routes::router_with_xff(&routing, trust_xff)
            .with_state(state)
            .layer(csrf_layer)
            .layer(host_layer)
            .layer(cors_layer)
            .layer(TraceLayer::new_for_http())
            .layer(TimeoutLayer::new(REST_REQUEST_TIMEOUT));

        let shutdown_rx = shutdown_rx.clone();
        // `into_make_service_with_connect_info` is required for the
        // tower-governor `SmartIpKeyExtractor` to fall back to the
        // peer socket address when `X-Forwarded-For` / `X-Real-IP`
        // headers are absent (Phase 5 M5.1.5).
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

/// DIDComm thread: runs the DIDComm service until shutdown.
fn run_didcomm_thread(
    config: AppConfig,
    secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    vtc_did: Option<String>,
    state: AppState,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build DIDComm runtime");

    rt.block_on(async {
        info!("DIDComm thread started");

        let (sr, did) = match (&secrets_resolver, &vtc_did) {
            (Some(sr), Some(did)) => (sr, did.as_str()),
            _ => {
                info!("DIDComm not configured — thread idle");
                let _ = shutdown_rx.changed().await;
                info!("DIDComm thread shutting down (idle)");
                return;
            }
        };

        messaging::run_didcomm_service(&config, sr, did, state, shutdown_rx).await;

        info!("DIDComm thread shutting down");
    });
}

/// Initialize DID resolver, secrets resolver, and JWT keys for authentication.
///
/// Returns `None` values if the VTC DID is not configured (server still starts
/// so the setup wizard can be run first).
///
/// Loads a serialized [`crate::setup::VtcKeyBundle`] from the secret
/// store. The bundle is what the VTA's `provision-integration` flow
/// produced at setup time; it carries the integration DID + the
/// Ed25519 + X25519 keys that back `vtc_did#key-0` / `#key-1`.
/// Install-token signing key + audit key are HKDF-derived from the
/// Ed25519 private bytes (32 B IKM) with `/v2` info strings — see
/// `tasks/vtc-mvp/vta-driven-keys.md` §5.2.
async fn init_auth(
    config: &AppConfig,
    secret_store: &dyn SecretStore,
    audit_ks: KeyspaceHandle,
    audit_key_ks: KeyspaceHandle,
) -> Result<
    (
        Option<DIDCacheClient>,
        Option<Arc<ThreadedSecretsResolver>>,
        Option<Arc<JwtKeys>>,
        Option<ATM>,
        Option<Arc<InstallTokenSigner>>,
        Option<AuditWriter>,
        Option<Arc<crate::credentials::LocalSigner>>,
        // P0.7: at-rest storage-encryption key (HKDF of the bundle Ed25519
        // seed). `None` only when no key material is configured yet (pre-setup)
        // or derivation fails — the caller then leaves keyspaces unencrypted.
        // The `audit_key` keyspace is already migrated + wrapped with this key
        // before return; the caller re-wraps `install` + `passkey`.
        Option<[u8; 32]>,
    ),
    AppError,
> {
    // P0.9: a daemon with no `vtc_did` is legitimately pre-setup — it boots
    // degraded (auth/issue/install routes 503) so the operator can run
    // `vtc setup`. But once `vtc_did` IS configured, an empty / erroring /
    // mismatched secret store is a *broken* identity (lost keyring entry,
    // wrong backend, wrong service name). Those used to return all-`None`
    // too, so the daemon served a healthy listener while every auth call
    // 503'd and the only signal was a log line. Fail the boot hard instead so
    // monitoring sees a non-zero exit, not a zombie.
    let vtc_did = match &config.vtc_did {
        Some(did) => did.clone(),
        None => {
            warn!("vtc_did not configured — auth endpoints will not work (run setup first)");
            return Ok((None, None, None, None, None, None, None, None));
        }
    };

    // Load the VtcKeyBundle from the secret store. Backwards-compat
    // window: tests + the legacy bootstrap flow still feed 64 raw
    // bytes (`[Ed25519:32 || X25519:32]`) directly; we accept that
    // shape too and synthesize an in-memory bundle. Production
    // setup writes the JSON shape via `inline_secret_for_bundle`.
    let stored = match secret_store.get().await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err(AppError::Config(format!(
                "vtc_did is configured ({vtc_did}) but the secret store is empty — key \
                 material is missing (lost keyring entry, wrong secrets backend, or a \
                 different keyring_service?). Run `vtc setup` or restore the secret; \
                 refusing to boot into an auth-dead state"
            )));
        }
        Err(e) => {
            return Err(AppError::Config(format!(
                "vtc_did is configured ({vtc_did}) but the secret store failed to load: {e} \
                 — check the backend's availability and permissions; refusing to boot into \
                 an auth-dead state"
            )));
        }
    };

    let (ed25519_bytes, x25519_bytes) =
        match crate::setup::bundle::decode_secret_store_value(&vtc_did, &stored) {
            Ok(pair) => pair,
            Err(msg) => {
                return Err(AppError::Config(format!(
                    "vtc_did is configured ({vtc_did}) but the stored key material does not \
                     match it: {msg}. This usually means the secret store holds a different \
                     identity's bundle; refusing to boot into an auth-dead state"
                )));
            }
        };

    // P0.7: derive the at-rest storage-encryption key from the same 32-byte
    // Ed25519 seed (HKDF-SHA256, info `vtc-storage-key/v1`). Domain-separated
    // from the install-token (`vtc-install-jwt-key/v2`) and audit
    // (`vtc-audit-key/v2`) derivations by its info string, so the same IKM
    // yields three independent keys. `None` only on the (practically
    // impossible) HKDF-expand failure, in which case keyspaces stay
    // plaintext rather than the daemon refusing to boot.
    let storage_key: Option<[u8; 32]> = derive_storage_key(&*ed25519_bytes);

    // M2.9 credential signer — wraps the same 32-byte Ed25519
    // seed in a [`LocalSigner`] handle so VMC / VEC / status-list
    // credential builders can sign without round-tripping through
    // the secret store on every call.
    let credential_signer = Some(Arc::new(
        crate::credentials::LocalSigner::from_ed25519_seed(vtc_did.clone(), &ed25519_bytes),
    ));

    // Derive the install-token signer from the 32-byte Ed25519
    // private. HKDF info is `vtc-install-jwt-key/v2` — bumped from
    // /v1 alongside the VTA-driven-keys rework so any pre-rework
    // deployment that still feeds a BIP-39-derived 64-byte seed
    // derives a different signing key and fails token verification
    // loudly instead of silently accepting tokens minted under the
    // old derivation. See `tasks/vtc-mvp/vta-driven-keys.md` §5.2.
    let install_signer = match InstallTokenSigner::from_master_seed(&*ed25519_bytes) {
        Ok(s) => Some(Arc::new(s)),
        Err(e) => {
            warn!("failed to derive install token signer: {e} — install routes disabled");
            None
        }
    };

    // P0.7: the `audit_key` keyspace holds the HMAC audit key in the clear.
    // Migrate any pre-encryption plaintext row in place, then wrap the
    // handle so the key is encrypted at rest going forward. A migration
    // failure leaves the keyspace bare (still readable) and is logged — we
    // only build the encrypted handle once the legacy rows are converted,
    // so an encrypted read can never hit a stale plaintext row.
    let audit_key_ks = match storage_key {
        Some(key) => match audit_key_ks.migrate_to_encrypted(key).await {
            Ok(n) => {
                if n > 0 {
                    info!("encrypted {n} legacy audit_key row(s) at rest");
                }
                audit_key_ks.with_encryption(key)
            }
            Err(e) => {
                warn!(
                    "audit_key encryption-at-rest migration failed: {e} — \
                     keyspace left unencrypted"
                );
                audit_key_ks
            }
        },
        None => audit_key_ks,
    };

    // Derive the HMAC audit key from the same 32 bytes. The
    // `AuditKeyStore` info string is also bumped to /v2 in
    // vti-common — see the rework note there.
    let audit_writer = {
        let key_store = AuditKeyStore::new(audit_key_ks);
        match key_store.ensure_initial(&*ed25519_bytes).await {
            Ok(_) => Some(AuditWriter::new(audit_ks, key_store)),
            Err(e) => {
                warn!("failed to derive initial audit key: {e} — audit-emitting routes disabled");
                None
            }
        }
    };

    // 1. DID resolver (local mode)
    let did_resolver = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to create DID resolver: {e} — auth endpoints will not work");
            return Ok((
                None,
                None,
                None,
                None,
                install_signer,
                audit_writer,
                credential_signer,
                storage_key,
            ));
        }
    };

    // 2. Secrets resolver with VTC's Ed25519 + X25519 secrets
    let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;

    let mut signing_secret = Secret::generate_ed25519(None, Some(&*ed25519_bytes));
    signing_secret.id = format!("{vtc_did}#key-0");
    secrets_resolver.insert(signing_secret).await;

    match Secret::generate_x25519(None, Some(&*x25519_bytes)) {
        Ok(mut ka_secret) => {
            ka_secret.id = format!("{vtc_did}#key-1");
            secrets_resolver.insert(ka_secret).await;
        }
        Err(e) => warn!("failed to create VTC key-agreement secret: {e}"),
    }

    // 3. JWT signing key from config (random key, not derived from VTC keys)
    let jwt_keys = match &config.auth.jwt_signing_key {
        Some(b64) => match decode_jwt_key(b64) {
            Ok(k) => k,
            Err(e) => {
                warn!("failed to load JWT signing key: {e} — auth endpoints will not work");
                return Ok((
                    Some(did_resolver),
                    Some(Arc::new(secrets_resolver)),
                    None,
                    None,
                    install_signer,
                    audit_writer,
                    credential_signer,
                    storage_key,
                ));
            }
        },
        None => {
            warn!(
                "auth.jwt_signing_key not configured — auth endpoints will not work (run setup first)"
            );
            return Ok((
                Some(did_resolver),
                Some(Arc::new(secrets_resolver)),
                None,
                None,
                install_signer,
                audit_writer,
                credential_signer,
                storage_key,
            ));
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
                Ok(tdk) => match ATMConfig::builder().build() {
                    Ok(atm_cfg) => match ATM::new(atm_cfg, Arc::new(tdk)).await {
                        Ok(a) => Some(a),
                        Err(e) => {
                            warn!("failed to create ATM for auth unpack: {e}");
                            None
                        }
                    },
                    Err(e) => {
                        // Every other init branch in this block falls
                        // back to `None` and lets the daemon boot
                        // without DIDComm auth. The earlier `.unwrap()`
                        // here would crash the entire process on what
                        // is structurally an optional feature.
                        warn!("failed to build ATMConfig: {e}");
                        None
                    }
                },
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

    info!("auth initialized for DID {vtc_did}");

    Ok((
        Some(did_resolver),
        Some(secrets_resolver),
        Some(Arc::new(jwt_keys)),
        atm,
        install_signer,
        audit_writer,
        credential_signer,
        storage_key,
    ))
}

/// Derive the at-rest storage-encryption key (P0.7).
///
/// `HKDF-SHA256(IKM = bundle Ed25519 seed, info = b"vtc-storage-key/v1")`.
/// The info string domain-separates this key from the install-token signer
/// (`vtc-install-jwt-key/v2`) and audit HMAC key (`vtc-audit-key/v2`) that
/// share the same IKM. Returns `None` only if HKDF expand fails (it cannot
/// for a 32-byte output), in which case the caller leaves keyspaces
/// unencrypted rather than refusing to boot.
fn derive_storage_key(ed25519_seed: &[u8]) -> Option<[u8; 32]> {
    let mut key = [0u8; 32];
    match Hkdf::<Sha256>::new(None, ed25519_seed).expand(b"vtc-storage-key/v1", &mut key) {
        Ok(()) => Some(key),
        Err(e) => {
            warn!("failed to derive storage-encryption key: {e} — keyspaces left unencrypted");
            None
        }
    }
}

/// Decode a base64url-no-pad JWT signing key and construct `JwtKeys`.
fn decode_jwt_key(b64: &str) -> Result<JwtKeys, AppError> {
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| AppError::Config(format!("invalid jwt_signing_key base64: {e}")))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::Config("jwt_signing_key must be exactly 32 bytes".into()))?;
    let keys = JwtKeys::from_ed25519_bytes(&key_bytes, "VTC")?;
    debug!("JWT signing key decoded successfully");
    Ok(keys)
}

/// Construct the public-website state from operator config (Phase 5
/// M5.4). Returns `None` when:
///
/// - `website.root_dir` is unset (operator opt-out); the handler
///   stays as the 503 placeholder.
/// - The configured `deploy_mode` value isn't recognised; a
///   warning is logged and the daemon falls back to the
///   placeholder so a misconfiguration can't bring down the API
///   surface.
///
/// On success, the returned [`crate::website::WebsiteState`] is
/// passed to [`crate::routes::router_with`] which mounts the
/// static handler at `routing.website.mount`.
#[cfg(feature = "website")]
async fn build_website_state(
    config: &Arc<RwLock<crate::config::AppConfig>>,
) -> Option<crate::website::WebsiteState> {
    let cfg = config.read().await;
    let root_dir = cfg.website.root_dir.as_ref()?;

    let root = match crate::website::WebsiteRoot::new(root_dir, &cfg.website.deploy_mode) {
        Ok(r) => r,
        Err(e) => {
            warn!("website.deploy_mode invalid ({e}); falling back to 503 placeholder");
            return None;
        }
    };

    let cache = crate::website::cache::WebsiteCache::new(cfg.website.live_cache_ttl_seconds);

    info!(
        root = %root_dir.display(),
        mode = %cfg.website.deploy_mode,
        "public-website handler enabled",
    );

    Some(crate::website::WebsiteState {
        root,
        cache,
        executable_blocklist: cfg.website.executable_blocklist.clone(),
        cache_control: cfg.website.cache_control.clone(),
        csp_override_file: cfg.website.csp_override_file.clone(),
    })
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
mod p0_10_timeout_tests {
    //! P0.10: the REST `TimeoutLayer` bounds each request so a wedged handler
    //! can't hold a connection (and a worker) forever, and a concurrent fast
    //! request is unaffected.
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    #[tokio::test]
    async fn timeout_layer_408s_a_slow_handler_but_not_a_fast_one() {
        async fn slow() -> &'static str {
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            "done"
        }
        async fn fast() -> &'static str {
            "ok"
        }

        let app = axum::Router::new()
            .route("/slow", get(slow))
            .route("/fast", get(fast))
            .layer(TimeoutLayer::new(std::time::Duration::from_millis(50)));

        let slow_res = app
            .clone()
            .oneshot(Request::builder().uri("/slow").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            slow_res.status(),
            StatusCode::REQUEST_TIMEOUT,
            "a handler exceeding the budget must 408"
        );

        let fast_res = app
            .oneshot(Request::builder().uri("/fast").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            fast_res.status(),
            StatusCode::OK,
            "a fast request must be unaffected by the timeout"
        );
    }
}

#[cfg(test)]
mod p0_9_init_auth_tests {
    //! P0.9: a configured-but-broken identity must fail the boot hard, while
    //! a daemon with no `vtc_did` still boots degraded for first-run setup.
    use super::*;
    use crate::keys::seed_store::PlaintextSecretStore;
    use std::future::Future;
    use std::pin::Pin;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        (store, dir)
    }

    fn config_with_did(did: Option<&str>) -> AppConfig {
        let mut c: AppConfig = toml::from_str("").unwrap();
        c.vtc_did = did.map(str::to_string);
        c
    }

    /// SecretStore whose `get` always errors — models a broken backend
    /// (keyring locked, cloud perms revoked).
    struct ErroringStore;
    impl SecretStore for ErroringStore {
        fn get(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>> {
            Box::pin(async { Err(AppError::SecretStore("backend unreachable".into())) })
        }
        fn set(
            &self,
            _secret: &[u8],
        ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
            Box::pin(async { Ok(()) })
        }
    }

    // The Ok tuple isn't `Debug`, so `expect_err` won't compile — match instead.
    async fn assert_hard_fails(config: &AppConfig, secret: &dyn SecretStore, store: &Store) {
        let audit = store.keyspace("audit").unwrap();
        let audit_key = store.keyspace("audit_key").unwrap();
        match init_auth(config, secret, audit, audit_key).await {
            Err(AppError::Config(_)) => {}
            Err(other) => panic!("expected Config error, got {other:?}"),
            Ok(_) => panic!("expected a hard boot failure, but init_auth booted"),
        }
    }

    #[tokio::test]
    async fn boots_degraded_when_vtc_did_unset() {
        let (store, _d) = temp_store();
        let audit = store.keyspace("audit").unwrap();
        let audit_key = store.keyspace("audit_key").unwrap();
        // Secret store is never consulted when there's no vtc_did.
        let result = init_auth(&config_with_did(None), &ErroringStore, audit, audit_key).await;
        let tuple = result.expect("no vtc_did must boot degraded, not error");
        assert!(
            tuple.0.is_none() && tuple.2.is_none(),
            "degraded boot yields no resolver / jwt keys"
        );
    }

    #[tokio::test]
    async fn hard_fails_when_vtc_did_set_but_store_empty() {
        let (store, dir) = temp_store();
        // Empty plaintext store → get() yields Ok(None).
        let secret = PlaintextSecretStore::new(dir.path());
        assert_hard_fails(&config_with_did(Some("did:key:zVtc")), &secret, &store).await;
    }

    #[tokio::test]
    async fn hard_fails_when_store_errors() {
        let (store, _d) = temp_store();
        assert_hard_fails(
            &config_with_did(Some("did:key:zVtc")),
            &ErroringStore,
            &store,
        )
        .await;
    }
}
