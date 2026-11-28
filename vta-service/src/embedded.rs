//! A VTA run inside another application's process.
//!
//! An application that gives its user a personal VTA (openvtc's quick start)
//! sets one up with [`crate::setup::apply_inputs`] and runs it with
//! [`EmbeddedVta::start`]. The VTA is the same service the `vta` binary runs —
//! the same store, setup, Trust Task spine and transports — hosted differently:
//!
//! - It runs on a thread of its own, with its own tokio runtime, so a stall in
//!   the host's runtime (a TUI's event loop) never stalls the VTA, and the
//!   VTA's blocking storage work never stalls the host.
//! - REST listens on a loopback port the host learns before the service
//!   starts ([`EmbeddedVta::rest_url`]).
//! - The host stops it ([`EmbeddedVta::shutdown`]); nothing in the VTA installs
//!   a signal handler or ends the process (see [`RunOptions::shutdown`]).
//!
//! What this does **not** do is apply a restore by re-executing the process:
//! the `vta` binary re-execs after a committed restore, which would restart
//! the host application. A committed restore stops the embedded VTA, and the
//! host starts it again ([`EmbeddedVta::start`] applies a staged restore first,
//! exactly as the binary's boot does).

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread::JoinHandle;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use tokio_util::sync::CancellationToken;

use crate::config::AppConfig;
use crate::error::AppError;
use crate::keys::seed_store::{SeedStore, create_seed_store};
use crate::server::{RunOptions, run_with};
use crate::store::Store;

/// A running in-process VTA. Dropping it without [`shutdown`](Self::shutdown)
/// cancels the service but does not wait for the store to flush.
pub struct EmbeddedVta {
    rest_addr: SocketAddr,
    shutdown: CancellationToken,
    thread: Option<JoinHandle<Result<(), AppError>>>,
}

impl EmbeddedVta {
    /// Boot the VTA described by `config` (as written by setup) and return once
    /// its REST listener is bound.
    ///
    /// `seed_store` overrides the `[secrets]` backend in `config`, for a host
    /// that keeps the seed in its own protected storage; `None` builds the
    /// backend `config` names.
    ///
    /// The REST listener binds `127.0.0.1:0` — the configured
    /// `server.host:port` is ignored, because an embedded VTA must never listen
    /// beyond the machine it runs on.
    pub async fn start(
        config: AppConfig,
        seed_store: Option<Arc<dyn SeedStore>>,
    ) -> Result<Self, AppError> {
        Self::start_on(config, seed_store, 0).await
    }

    /// [`start`](Self::start) on a loopback port of the caller's choosing.
    ///
    /// For a host application that hands the VTA's URL to other local
    /// processes (a git signing proxy that connects on its own), so the URL has
    /// to survive a restart: it binds the port it bound last time. `0` picks a
    /// free one. A port that is taken is an error, not a silent move to
    /// another — whatever holds it would be answering for this VTA.
    pub async fn start_on(
        mut config: AppConfig,
        seed_store: Option<Arc<dyn SeedStore>>,
        port: u16,
    ) -> Result<Self, AppError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).map_err(AppError::Io)?;
        let rest_addr = listener.local_addr().map_err(AppError::Io)?;

        let store = Store::open_with(&config.store, &config.fjall)?;
        let seed_store: Arc<dyn SeedStore> = match seed_store {
            Some(s) => s,
            None => Arc::from(create_seed_store(&config)?),
        };

        let storage_encryption_key = prepare_boot(&mut config, &store, &*seed_store).await?;

        let shutdown = CancellationToken::new();
        let options = RunOptions {
            shutdown: Some(shutdown.clone()),
            rest_listener: Some(listener),
            ..RunOptions::default()
        };

        let thread = std::thread::Builder::new()
            .name("embedded-vta".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .thread_name("embedded-vta-rt")
                    .build()
                    .map_err(AppError::Io)?;
                runtime.block_on(run_with(
                    config,
                    store,
                    seed_store,
                    storage_encryption_key,
                    None,
                    options,
                ))
            })
            .map_err(AppError::Io)?;

        Ok(Self {
            rest_addr,
            shutdown,
            thread: Some(thread),
        })
    }

    /// The loopback port REST listens on.
    pub fn rest_port(&self) -> u16 {
        self.rest_addr.port()
    }

    /// The loopback REST base URL, e.g. `http://127.0.0.1:53817`.
    pub fn rest_url(&self) -> String {
        format!("http://{}", self.rest_addr)
    }

    /// Whether the service has stopped on its own (a fatal error, or a
    /// committed restore waiting for [`start`](Self::start) to apply it).
    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(|t| t.is_finished())
    }

    /// Stop the service and wait until every thread is joined and the store is
    /// flushed. Returns the service's own error if it had already failed.
    pub async fn shutdown(mut self) -> Result<(), AppError> {
        self.shutdown.cancel();
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        tokio::task::spawn_blocking(move || thread.join())
            .await
            .map_err(|e| AppError::Internal(format!("joining the embedded VTA: {e}")))?
            .map_err(|_| AppError::Internal("the embedded VTA thread panicked".into()))?
    }
}

impl Drop for EmbeddedVta {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// The binary's pre-`run` boot, minus its process-level side effects: apply a
/// staged restore, then derive the storage-encryption and JWT keys for a
/// hardened store. Returns the storage-encryption key (`None` for a plain
/// store).
async fn prepare_boot(
    config: &mut AppConfig,
    store: &Store,
    seed_store: &dyn SeedStore,
) -> Result<Option<[u8; 32]>, AppError> {
    let seed = seed_store
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("loading the VTA seed: {e}")))?;
    if let Some(seed) = seed {
        let storage_key = config.hardened.enabled.then(|| {
            *crate::hardened_bootstrap::derive_storage_key(&seed, &config.hardened.storage_key_salt)
        });
        #[cfg(feature = "rest")]
        crate::restore::apply_pending_restore(
            store,
            storage_key,
            crate::restore::environment_of(storage_key, false),
            &seed,
            config,
        )
        .await
        .map_err(|e| AppError::Internal(format!("applying the staged restore: {e}")))?;
        #[cfg(not(feature = "rest"))]
        let _ = storage_key;
    }

    if !config.hardened.enabled {
        return Ok(None);
    }
    let boot = crate::hardened_bootstrap::load_boot_secrets(config, seed_store, store)
        .await
        .map_err(|e| AppError::Internal(format!("hardened boot: {e}")))?;
    store.persist().await?;
    config.auth.jwt_signing_key = Some(BASE64.encode(boot.jwt_key));
    Ok(Some(boot.storage_key))
}
