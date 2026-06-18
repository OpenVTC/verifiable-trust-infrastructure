//! VTA (Verifiable Trust Agent) service library.
//!
//! This is the shared business logic used by both the `vta` binary
//! (local/dev/cloud) and the `vta-enclave` binary (Nitro Enclave).
//!
//! Front-end binaries import this library and call `server::run()`
//! with the appropriate store backend and TEE context.

// Re-exported so front-end binaries (e.g. `vta-enclave`, which only depends
// on this crate) can install the rustls aws-lc-rs CryptoProvider at startup
// without taking a direct `vta-sdk` dependency.
pub use vta_sdk::crypto_init;

pub mod acl;
pub mod acl_sweeper;
pub mod audit;
pub mod auth;
pub mod backup_bundle_store;
pub mod backup_bundle_sweeper;
pub mod config;
pub mod consent_sweeper;
pub mod contexts;
pub mod did_templates;
pub mod didcomm_bridge;
pub mod error;
pub mod keys;
pub mod keyspaces;
#[cfg(feature = "didcomm")]
pub mod messaging;
#[cfg(feature = "rest")]
pub mod metrics;
pub mod operations;
#[cfg(feature = "rest")]
pub mod routes;
pub mod seal;
pub mod sealed_nonce_store;
pub mod server;
pub mod status;
pub mod store;
#[cfg(feature = "tee")]
pub mod tee;
/// Transport-neutral Trust-Task dispatch subsystem. Both the REST route
/// (`routes::trust_tasks`-mounted `dispatch_trust_task`) and the DIDComm
/// `handle_trust_task` handler dispatch through `dispatch_trust_task_core`
/// here, so it lives at the crate root rather than under `routes::` (P2.4).
pub mod trust_tasks;
pub mod vault;
pub mod vault_sweeper;
#[cfg(feature = "webvh")]
pub mod webvh_auth;
#[cfg(feature = "webvh")]
pub mod webvh_client;
#[cfg(feature = "webvh")]
pub mod webvh_didcomm;
#[cfg(feature = "webvh")]
pub mod webvh_store;

// `test_support` is gated internally on `any(test, feature = "test-support")`.
// `#[cfg(...)]` here would hide the module from the test builds that
// don't pass `--features test-support` explicitly; the module header
// handles that itself.
pub mod test_support;

/// Initialize tracing/logging from config. Call once at startup before any
/// log output. Shared by all VTA front-end binaries.
pub fn init_tracing(config: &config::AppConfig) {
    init_tracing_with_writer(config, std::io::stderr);
}

/// Initialize tracing with a custom `MakeWriter`.
///
/// The enclave binary uses this to tee log output to both stderr and a
/// vsock connection for forwarding to the parent EC2 instance.
pub fn init_tracing_with_writer<W>(config: &config::AppConfig, writer: W)
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log.level));

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer);

    match config.log.format {
        config::LogFormat::Json => subscriber.json().init(),
        config::LogFormat::Text => subscriber.init(),
    }
}
