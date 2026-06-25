//! `vta services …` — offline service-management commands.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §5.1.
//!
//! Mirrors the `pnm services …` surface (twelve commands total) but
//! operates **directly on the local fjall keystore** with no HTTP,
//! no operator authentication, and no running VTA required.
//! Anyone with filesystem access to the VTA's data directory can
//! run these commands — that's the same security model as
//! `vta acl …`, `vta keys …`, etc.
//!
//! ## Not for TEE deployments
//!
//! Inside a Nitro Enclave deployment, the VTA's fjall store lives
//! behind a vsock proxy and the offline `vta` binary on the parent
//! host has no access to it. Same constraint applies to every
//! other `vta` offline command (acl, keys, contexts, webvh).
//! Operators running TEE use `pnm services …` against the VTA's
//! HTTPS endpoint instead — that's the only path that reaches the
//! in-enclave operation layer through the auth + ACL gates.
//!
//! ## Don't run while the VTA is up
//!
//! Modifying service state offline while the VTA daemon is running
//! is risky: the running VTA caches `AppConfig` and holds the
//! mediator registry / drain sweeper in memory; offline writes to
//! the keystore won't be picked up until restart. fjall's
//! file-level lock prevents concurrent process access (the offline
//! `vta` will fail to open the store if the daemon holds it), so
//! we get free protection against split-brain on disk. Operators
//! should still prefer `pnm services` against the running VTA.

use std::path::PathBuf;
use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use tokio::sync::RwLock;

use vta_cli_common::commands::services::print_serverless_hint;
use vta_cli_common::render::print_cli_error;
use vti_common::config::StoreConfig as VtiStoreConfig;
use vti_common::telemetry::{RingBufferTelemetry, SharedTelemetrySink};

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::keys::seed_store::{SeedStore, create_seed_store};
use crate::messaging::drain_sweeper::{DrainSweeper, teardown_channel};
use crate::messaging::handshake::AlwaysOkProver;
use crate::messaging::registry::MediatorListenerRegistry;
use crate::operations::protocol::OpContext;
use crate::operations::protocol::ServiceOpDeps;
use crate::operations::protocol::disable_didcomm::{
    DisableDidcommParams, DisableTransport, disable_didcomm,
};
use crate::operations::protocol::disable_rest::{DisableRestParams, disable_rest};
use crate::operations::protocol::disable_tsp::{DisableTspParams, disable_tsp};
use crate::operations::protocol::drain_cancel::{DrainCancelParams, drain_cancel};
use crate::operations::protocol::enable_didcomm::{EnableDidcommParams, enable_didcomm};
use crate::operations::protocol::enable_rest::{EnableRestParams, enable_rest};
use crate::operations::protocol::enable_tsp::{EnableTspParams, enable_tsp};
use crate::operations::protocol::list::list_services;
use crate::operations::protocol::list_drain::list_drain;
use crate::operations::protocol::rollback_didcomm::{RollbackDidcommParams, rollback_didcomm};
use crate::operations::protocol::rollback_rest::{RollbackRestParams, rollback_rest};
use crate::operations::protocol::rollback_tsp::{RollbackTspParams, rollback_tsp};
use crate::operations::protocol::snapshot;
use crate::operations::protocol::update_didcomm::{
    MigrateAuditKind, UpdateDidcommParams, update_didcomm,
};
use crate::operations::protocol::update_rest::{UpdateRestParams, update_rest};
use crate::operations::protocol::update_tsp::{UpdateTspParams, update_tsp};
use crate::store::{KeyspaceHandle, Store};

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// Bundle of dependencies that every service-management op needs.
/// Owns the `Store` so all derived keyspaces stay valid for the
/// command's lifetime.
struct OfflineDeps {
    config: Arc<RwLock<AppConfig>>,
    _store: Store,
    keys_ks: KeyspaceHandle,
    imported_ks: KeyspaceHandle,
    contexts_ks: KeyspaceHandle,
    webvh_ks: KeyspaceHandle,
    audit_ks: KeyspaceHandle,
    drains_ks: KeyspaceHandle,
    snapshot_ks: KeyspaceHandle,
    service_state_ks: KeyspaceHandle,
    seed_store: Box<dyn SeedStore>,
    did_resolver: DIDCacheClient,
    didcomm_bridge: Arc<DIDCommBridge>,
    telemetry: SharedTelemetrySink,
    registry: Arc<MediatorListenerRegistry>,
    sweeper: Arc<DrainSweeper>,
    auth: AuthClaims,
    /// Fresh per-invocation auth-locks. The offline CLI is a
    /// single short-lived process; concurrent webvh ops aren't
    /// possible here because the fjall store requires exclusive
    /// access. A throwaway map suffices.
    webvh_auth_locks: crate::operations::did_webvh::WebvhAuthLocks,
}

impl OfflineDeps {
    /// Borrow the full service-op dependency bundle. The offline CLI owns its
    /// `did_resolver` (always present, unlike `AppState`'s `Option`), so this is
    /// infallible — the same shape `ServiceOpDeps::from_app_state` produces for
    /// the online path (REST/WebAuthn + DIDComm).
    fn service_op_deps(&self) -> ServiceOpDeps<'_> {
        ServiceOpDeps {
            config: &self.config,
            keys_ks: &self.keys_ks,
            imported_ks: &self.imported_ks,
            contexts_ks: &self.contexts_ks,
            webvh_ks: &self.webvh_ks,
            audit_ks: &self.audit_ks,
            snapshot_ks: &self.snapshot_ks,
            service_state_ks: &self.service_state_ks,
            drains_ks: &self.drains_ks,
            seed_store: &*self.seed_store,
            did_resolver: &self.did_resolver,
            didcomm_bridge: &self.didcomm_bridge,
            telemetry: &self.telemetry,
            webvh_auth_locks: &self.webvh_auth_locks,
            registry: &self.registry,
            sweeper: &self.sweeper,
        }
    }
}

/// Open the local VTA state for offline service-management.
///
/// Loads `AppConfig` via the standard search path (or the
/// caller-supplied `config_path`), opens the fjall store at the
/// configured `data_dir`, and constructs the dependency bundle
/// every operation needs. Returns an error if the data dir is
/// locked (running VTA) or doesn't exist.
async fn build_offline_deps(
    config_path: Option<PathBuf>,
) -> Result<OfflineDeps, Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let data_dir = config.store.data_dir.clone();
    let store = Store::open(&VtiStoreConfig {
        data_dir: data_dir.clone(),
    })
    .map_err(|e| {
        format!(
            "open store at {}: {e}\n\nIs the VTA daemon running? \
             Offline `vta services` commands require exclusive access. \
             Use `pnm services` against the running VTA instead.",
            data_dir.display()
        )
    })?;

    let keys_ks = store.keyspace(crate::keyspaces::KEYS)?;
    let imported_ks = store.keyspace(crate::keyspaces::IMPORTED_SECRETS)?;
    let contexts_ks = store.keyspace(crate::keyspaces::CONTEXTS)?;
    let audit_ks = store.keyspace(crate::keyspaces::AUDIT)?;
    let webvh_ks = store.keyspace(crate::keyspaces::WEBVH)?;
    let drains_ks = store.keyspace(crate::keyspaces::DRAINS)?;
    let snapshot_ks = store.keyspace(snapshot::KEYSPACE_NAME)?;
    let service_state_ks = store.keyspace(crate::keyspaces::SERVICE_STATE)?;
    // Sync the in-memory config from fjall (authoritative) so the readers
    // throughout the codebase see the current runtime state, not the legacy
    // (possibly stale) [services] block on disk.
    crate::operations::protocol::runtime_state::migrate_from_config(&service_state_ks, &config)
        .await?;
    let mut config = config;
    config.services.rest =
        crate::operations::protocol::runtime_state::is_rest_enabled(&service_state_ks).await?;
    config.services.didcomm =
        crate::operations::protocol::runtime_state::is_didcomm_enabled(&service_state_ks).await?;

    // Build the seed store from the configured `[secrets]` backend
    // (keyring / AWS / GCP / Vault / plaintext / …) exactly as the
    // daemon and every other offline command (`keys`, `contexts`,
    // `create-did-key`, `webvh`) do. WebVH-mutating service ops
    // (enable/disable/update DIDComm) re-sign the DID log and need
    // the master seed; hardcoding `PlaintextSeedStore(data_dir)`
    // meant any non-plaintext backend failed with
    // "no seed found in external store" (#564).
    let seed_store = create_seed_store(&config)?;
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let didcomm_bridge = Arc::new(DIDCommBridge::placeholder());
    let telemetry: SharedTelemetrySink = Arc::new(RingBufferTelemetry::new());
    let registry = Arc::new(MediatorListenerRegistry::new(Arc::clone(&telemetry)));
    let (tx, _rx) = teardown_channel(8);
    let sweeper = Arc::new(DrainSweeper::new(
        Arc::clone(&registry),
        drains_ks.clone(),
        tx,
    ));
    // Embed the calling process's pid (and uid on Unix) into the
    // audit channel string so a forensic investigator can map a
    // logged super-admin synthesis back to the shell session that
    // ran the command. Best-effort: missing pid/uid degrades to
    // the bare channel name rather than blocking the operation.
    let auth = AuthClaims::unsafe_local_cli_super_admin(&offline_audit_channel());

    Ok(OfflineDeps {
        config: Arc::new(RwLock::new(config)),
        _store: store,
        keys_ks,
        imported_ks,
        contexts_ks,
        webvh_ks,
        audit_ks,
        drains_ks,
        snapshot_ks,
        service_state_ks,
        seed_store,
        did_resolver,
        didcomm_bridge,
        telemetry,
        registry,
        sweeper,
        auth,
        webvh_auth_locks: crate::operations::did_webvh::WebvhAuthLocks::new(),
    })
}

/// Build the audit-channel string the offline `vta services …`
/// CLI uses when synthesising a super-admin claim. Includes the
/// calling process's pid so audit-log greps can distinguish
/// concurrent local invocations on the same host. (uid is not
/// recorded because pulling it in would force a `libc` /
/// `rustix` dependency on this code path; the pid plus the
/// per-invocation timestamp on the audit record is sufficient
/// to disambiguate in practice.)
fn offline_audit_channel() -> String {
    format!("vta-services-offline:pid={}", std::process::id())
}

/// Print a `VtaError`-bearing error using the workspace's shared
/// CLI renderer (which surfaces `suggested_fix()` strings per
/// CLAUDE.md).
fn report_op_error<E: std::error::Error + 'static>(e: E) -> Box<dyn std::error::Error> {
    print_cli_error(&e);
    // Return a minimal error so the caller propagates a non-zero
    // exit code without re-printing the same message.
    Box::new(SilentExit)
}

#[derive(Debug)]
struct SilentExit;
impl std::fmt::Display for SilentExit {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}
impl std::error::Error for SilentExit {}

// ── services list ─────────────────────────────────────────────────

pub async fn run_services_list(config_path: Option<PathBuf>) -> CliResult {
    let d = build_offline_deps(config_path).await?;
    let response = list_services(&d.config, &d.webvh_ks, &d.auth)
        .await
        .map_err(report_op_error)?;
    println!("Services advertised on this VTA's DID document:");
    println!();
    for state in &response.services {
        match state {
            vta_sdk::protocol::services::ServiceState::Tsp {
                enabled,
                mediator_did,
            } => {
                println!("  TSP:      {}", if *enabled { "on" } else { "off" });
                if let Some(m) = mediator_did {
                    println!("    Mediator:     {m}");
                }
            }
            vta_sdk::protocol::services::ServiceState::Didcomm {
                enabled,
                mediator_did,
                routing_keys,
            } => {
                println!("  DIDComm:  {}", if *enabled { "on" } else { "off" });
                if let Some(m) = mediator_did {
                    println!("    Mediator:     {m}");
                }
                if !routing_keys.is_empty() {
                    println!("    Routing keys: {}", routing_keys.join(", "));
                }
            }
            vta_sdk::protocol::services::ServiceState::Rest { enabled, url } => {
                println!("  REST:     {}", if *enabled { "on" } else { "off" });
                if let Some(u) = url {
                    println!("    URL:          {u}");
                }
            }
            vta_sdk::protocol::services::ServiceState::Webauthn { enabled, url } => {
                println!("  WebAuthn: {}", if *enabled { "on" } else { "off" });
                if let Some(u) = url {
                    println!("    URL:          {u}");
                }
            }
        }
    }
    Ok(())
}

// ── services rest {enable, update, disable, rollback} ─────────────

pub async fn run_services_rest_enable(config_path: Option<PathBuf>, url: String) -> CliResult {
    let d = build_offline_deps(config_path).await?;
    let deps = d.service_op_deps();
    let result = enable_rest(
        &deps,
        &d.auth,
        EnableRestParams { url },
        OpContext::Direct,
        "vta-cli-offline",
    )
    .await
    .map_err(report_op_error)?;
    println!("REST enabled.");
    println!("  New version ID: {}", result.new_version_id);
    println!("  URL:            {}", result.url);
    print_serverless_hint(result.serverless, &result.vta_did);
    Ok(())
}

pub async fn run_services_rest_update(config_path: Option<PathBuf>, url: String) -> CliResult {
    let d = build_offline_deps(config_path).await?;
    let deps = d.service_op_deps();
    let result = update_rest(
        &deps,
        &d.auth,
        UpdateRestParams { url },
        OpContext::Direct,
        "vta-cli-offline",
    )
    .await
    .map_err(report_op_error)?;
    println!("REST URL updated.");
    println!("  Prior URL:      {}", result.prior_url);
    println!("  New URL:        {}", result.url);
    println!("  New version ID: {}", result.new_version_id);
    print_serverless_hint(result.serverless, &result.vta_did);
    Ok(())
}

pub async fn run_services_rest_disable(config_path: Option<PathBuf>) -> CliResult {
    let d = build_offline_deps(config_path).await?;
    let deps = d.service_op_deps();
    let result = disable_rest(
        &deps,
        &d.auth,
        DisableRestParams,
        OpContext::Direct,
        "vta-cli-offline",
    )
    .await
    .map_err(report_op_error)?;
    println!("REST disabled.");
    println!("  Prior URL:      {}", result.prior_url);
    println!("  New version ID: {}", result.new_version_id);
    print_serverless_hint(result.serverless, &result.vta_did);
    Ok(())
}

pub async fn run_services_rest_rollback(config_path: Option<PathBuf>) -> CliResult {
    let d = build_offline_deps(config_path).await?;
    let deps = d.service_op_deps();
    let result = rollback_rest(&deps, &d.auth, RollbackRestParams, "vta-cli-offline")
        .await
        .map_err(report_op_error)?;
    if matches!(
        result.kind,
        crate::operations::protocol::rollback_rest::RollbackKind::NoOp
    ) {
        println!("REST rollback: no change required (snapshot ≡ current state).");
    } else {
        println!("REST rolled back.");
        if let Some(version) = result.new_version_id {
            println!("  New version ID: {version}");
        }
        print_serverless_hint(result.serverless, &result.vta_did);
    }
    Ok(())
}

// ── services tsp {enable, update, disable, rollback} ──────────────
//
// TSP advertises a **mediator DID** (the VTA's TSP VID), not a URL —
// so these mirror the REST offline ops with `mediator_did` in place
// of `url`. Direct op calls, no auth ceremony (offline binary).

pub async fn run_services_tsp_enable(
    config_path: Option<PathBuf>,
    mediator_did: String,
) -> CliResult {
    let d = build_offline_deps(config_path).await?;
    let deps = d.service_op_deps();
    let result = enable_tsp(
        &deps,
        &d.auth,
        EnableTspParams { mediator_did },
        OpContext::Direct,
        "vta-cli-offline",
    )
    .await
    .map_err(report_op_error)?;
    println!("TSP enabled.");
    println!("  New version ID: {}", result.new_version_id);
    println!("  Mediator DID:   {}", result.mediator_did);
    print_serverless_hint(result.serverless, &result.vta_did);
    Ok(())
}

pub async fn run_services_tsp_update(
    config_path: Option<PathBuf>,
    mediator_did: String,
) -> CliResult {
    let d = build_offline_deps(config_path).await?;
    let deps = d.service_op_deps();
    let result = update_tsp(
        &deps,
        &d.auth,
        UpdateTspParams { mediator_did },
        OpContext::Direct,
        "vta-cli-offline",
    )
    .await
    .map_err(report_op_error)?;
    println!("TSP mediator DID updated.");
    println!("  Prior mediator: {}", result.prior_mediator_did);
    println!("  New mediator:   {}", result.mediator_did);
    println!("  New version ID: {}", result.new_version_id);
    print_serverless_hint(result.serverless, &result.vta_did);
    Ok(())
}

pub async fn run_services_tsp_disable(config_path: Option<PathBuf>) -> CliResult {
    let d = build_offline_deps(config_path).await?;
    let deps = d.service_op_deps();
    let result = disable_tsp(
        &deps,
        &d.auth,
        DisableTspParams,
        OpContext::Direct,
        "vta-cli-offline",
    )
    .await
    .map_err(report_op_error)?;
    println!("TSP disabled.");
    println!("  Prior mediator: {}", result.prior_mediator_did);
    println!("  New version ID: {}", result.new_version_id);
    print_serverless_hint(result.serverless, &result.vta_did);
    Ok(())
}

pub async fn run_services_tsp_rollback(config_path: Option<PathBuf>) -> CliResult {
    let d = build_offline_deps(config_path).await?;
    let deps = d.service_op_deps();
    let result = rollback_tsp(&deps, &d.auth, RollbackTspParams, "vta-cli-offline")
        .await
        .map_err(report_op_error)?;
    if matches!(
        result.kind,
        crate::operations::protocol::rollback_tsp::RollbackKind::NoOp
    ) {
        println!("TSP rollback: no change required (snapshot ≡ current state).");
    } else {
        println!("TSP rolled back.");
        if let Some(version) = result.new_version_id {
            println!("  New version ID: {version}");
        }
        print_serverless_hint(result.serverless, &result.vta_did);
    }
    Ok(())
}

// ── services didcomm {enable, update, disable, rollback} ──────────

pub async fn run_services_didcomm_enable(
    config_path: Option<PathBuf>,
    mediator_did: String,
    force: bool,
    handshake_timeout_secs: Option<u64>,
) -> CliResult {
    let d = build_offline_deps(config_path).await?;
    let prover = AlwaysOkProver;
    let timeout = std::time::Duration::from_secs(handshake_timeout_secs.unwrap_or(10));
    let deps = d.service_op_deps();
    let result = enable_didcomm(
        &deps,
        &prover,
        &d.auth,
        EnableDidcommParams {
            mediator_did,
            force,
            handshake_timeout: timeout,
        },
        OpContext::Direct,
        "vta-cli-offline",
    )
    .await
    .map_err(report_op_error)?;
    println!("DIDComm enabled.");
    println!("  Mediator DID:   {}", result.mediator_did);
    if !result.mediator_endpoint.is_empty() {
        println!("  Mediator URL:   {}", result.mediator_endpoint);
    }
    println!("  New version ID: {}", result.new_version_id);
    print_serverless_hint(result.serverless, &result.vta_did);
    Ok(())
}

pub async fn run_services_didcomm_update(
    config_path: Option<PathBuf>,
    new_mediator_did: String,
    drain_ttl_secs: u64,
    force: bool,
    handshake_timeout_secs: Option<u64>,
) -> CliResult {
    let d = build_offline_deps(config_path).await?;
    let prover = AlwaysOkProver;
    let deps = d.service_op_deps();
    let result = update_didcomm(
        &deps,
        &prover,
        &d.auth,
        UpdateDidcommParams {
            new_mediator_did,
            drain_ttl: std::time::Duration::from_secs(drain_ttl_secs),
            force,
            handshake_timeout: std::time::Duration::from_secs(handshake_timeout_secs.unwrap_or(10)),
            audit_kind: MigrateAuditKind::Forward,
            transport: crate::operations::protocol::disable_didcomm::DisableTransport::Rest,
        },
        OpContext::Direct,
        "vta-cli-offline",
    )
    .await
    .map_err(report_op_error)?;
    println!("DIDComm mediator updated.");
    println!("  Prior mediator:  {}", result.prior_mediator_did);
    println!("  Active mediator: {}", result.active_mediator_did);
    println!("  New version ID:  {}", result.new_version_id);
    println!("  Drain deadline:  {}", result.drains_until);
    print_serverless_hint(result.serverless, &result.vta_did);
    Ok(())
}

pub async fn run_services_didcomm_disable(
    config_path: Option<PathBuf>,
    drain_ttl_secs: u64,
) -> CliResult {
    let d = build_offline_deps(config_path).await?;
    let deps = d.service_op_deps();
    let result = disable_didcomm(
        &deps,
        &d.auth,
        DisableDidcommParams {
            drain_ttl: std::time::Duration::from_secs(drain_ttl_secs),
            // Offline binary acts like the REST transport — no
            // 1h floor since there's no DIDComm channel to
            // protect.
            transport: DisableTransport::Rest,
        },
        OpContext::Direct,
        "vta-cli-offline",
    )
    .await
    .map_err(report_op_error)?;
    println!("DIDComm disabled.");
    println!("  Prior mediator: {}", result.prior_mediator_did);
    println!("  New version ID: {}", result.new_version_id);
    if let Some(deadline) = result.drains_until {
        println!("  Drain deadline: {deadline}");
    } else {
        println!("  Listener torn down immediately (drain TTL 0).");
    }
    print_serverless_hint(result.serverless, &result.vta_did);
    Ok(())
}

pub async fn run_services_didcomm_rollback(
    config_path: Option<PathBuf>,
    drain_ttl_secs: Option<u64>,
) -> CliResult {
    let d = build_offline_deps(config_path).await?;
    // Offline path: there's no running DIDComm service to assemble a
    // live prover against, so the dispatcher's re-promotion
    // handshake degrades to a config-shape check via
    // `AlwaysOkProver`. A subsequent `pnm services didcomm update`
    // against a running VTA exercises the live prover.
    let prover = AlwaysOkProver;
    let deps = d.service_op_deps();
    let result = rollback_didcomm(
        &deps,
        &prover,
        &d.auth,
        RollbackDidcommParams {
            drain_ttl: std::time::Duration::from_secs(drain_ttl_secs.unwrap_or(86_400)),
            transport: DisableTransport::Rest,
        },
        "vta-cli-offline",
    )
    .await
    .map_err(report_op_error)?;
    if matches!(
        result.kind,
        crate::operations::protocol::rollback_didcomm::RollbackKind::NoOp
    ) {
        println!("DIDComm rollback: no change required (snapshot ≡ current state).");
    } else {
        println!("DIDComm rolled back.");
        if let Some(version) = result.new_version_id {
            println!("  New version ID: {version}");
        }
        if let Some(draining) = result.draining_mediator {
            println!("  Draining:       {draining}");
        }
        print_serverless_hint(result.serverless, &result.vta_did);
    }
    Ok(())
}

// ── services didcomm drain {list, cancel} ─────────────────────────

pub async fn run_services_didcomm_drain_list(config_path: Option<PathBuf>) -> CliResult {
    let d = build_offline_deps(config_path).await?;
    let response = list_drain(&d.config, &d.drains_ks, &d.auth)
        .await
        .map_err(report_op_error)?;
    if response.entries.is_empty() {
        println!("No mediators currently in drain.");
        return Ok(());
    }
    println!("Drain set ({} mediator(s)):", response.entries.len());
    println!();
    let header_did = "MEDIATOR DID";
    let header_until = "DRAIN UNTIL";
    println!("  {header_did:<60}  {header_until}");
    for e in &response.entries {
        println!("  {:<60}  {}", &e.mediator_did, e.drains_until);
    }
    Ok(())
}

pub async fn run_services_didcomm_drain_cancel(
    config_path: Option<PathBuf>,
    mediator_did: String,
) -> CliResult {
    let d = build_offline_deps(config_path).await?;
    let result = drain_cancel(
        &d.config,
        &d.drains_ks,
        &d.registry,
        &d.telemetry,
        &d.auth,
        DrainCancelParams {
            mediator_did: mediator_did.clone(),
        },
        "vta-cli-offline",
    )
    .await
    .map_err(report_op_error)?;
    println!("Drain cancelled for {}.", result.mediator_did);
    Ok(())
}

// ── services report ───────────────────────────────────────────────

pub async fn run_services_report(
    config_path: Option<PathBuf>,
    since: Option<String>,
    until: Option<String>,
    format: String,
) -> CliResult {
    use crate::operations::protocol::report::{ReportParams, mediator_report};
    use chrono::DateTime;
    let d = build_offline_deps(config_path).await?;

    let parse_ts = |s: Option<String>| -> Result<Option<chrono::DateTime<chrono::Utc>>, String> {
        match s {
            None => Ok(None),
            Some(s) => DateTime::parse_from_rfc3339(&s)
                .map(|dt| Some(dt.with_timezone(&chrono::Utc)))
                .map_err(|e| format!("invalid RFC 3339 timestamp `{s}`: {e}")),
        }
    };

    let since = parse_ts(since)?;
    let until = parse_ts(until)?;
    let report = mediator_report(&d.telemetry, &d.auth, ReportParams { since, until })
        .await
        .map_err(report_op_error)?;

    match format.as_str() {
        "json" => println!("{}", serde_json::to_string_pretty(&report)?),
        "table" => {
            println!("Service-management report");
            if let Some(ref s) = report.since {
                println!("  Window: {s} → {}", report.until);
            } else {
                println!("  Window: (all time) → {}", report.until);
            }
            println!();
            // The offline binary's telemetry sink is fresh per
            // invocation (RingBufferTelemetry::new()) so the
            // report is empty by design — tells the operator
            // that real telemetry lives on the running VTA.
            if report.mediators.is_empty() {
                println!("  No telemetry recorded in this offline session.");
                println!(
                    "  Run `pnm services report` against the running VTA for the full record."
                );
            } else {
                for m in &report.mediators {
                    println!(
                        "    {}  {:>10}  {}",
                        &m.mediator_did, m.inbound_count, m.last_seen
                    );
                }
            }
        }
        other => return Err(format!("unknown format `{other}` — use `json` or `table`").into()),
    }
    Ok(())
}
