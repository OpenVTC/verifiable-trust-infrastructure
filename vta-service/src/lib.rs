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
/// Structured audit logging (the `audit!` tracing macro + audit-keyspace
/// persistence helpers), extracted to the `vta-audit` crate and re-exported so
/// every `crate::audit::{record,record_consent,…}` path and `audit!(…)` call
/// site is unchanged. The macro is `#[macro_export]`ed from `vta-audit`, so
/// `use crate::audit::{self, audit}` resolves the same as before.
pub use vta_audit as audit;
/// Background TTL sweepers (ACL grant expiry, pending-consent expiry,
/// soft-deleted-vault purge), extracted to the `vta-sweepers` crate and
/// re-exported so every `crate::{acl_sweeper,consent_sweeper,vault_sweeper}::…`
/// path (the storage-thread sweep loop, provision-integration) is unchanged.
pub use vta_sweepers::{acl_sweeper, consent_sweeper, vault_sweeper};
pub mod auth;
/// Backup/restore subsystem, extracted to the `vta-backup` crate. The sealed
/// backup-bundle store + its TTL sweeper are re-exported so every
/// `crate::{backup_bundle_store,backup_bundle_sweeper}::…` path is unchanged;
/// the export/import operations are re-exported as `crate::operations::backup`
/// (see `operations/mod.rs`).
pub use vta_backup::{backup_bundle_store, backup_bundle_sweeper};
/// VTA configuration types, extracted to the `vta-config` crate. Re-exported as
/// `crate::config` so every `crate::config::…` path stays unchanged, and so
/// `vta_service::config` keeps resolving for `vta-enclave`. The `tee` cargo
/// feature gates the same `TeeConfig` / `TeeMode` items, wired to
/// `vta-config/tee` in `Cargo.toml`.
pub use vta_config as config;
/// Shared mid-layer services (trust-context store, sealed-transfer seal
/// helper, anti-replay nonce store), extracted to the `vta-support` crate and
/// re-exported so every `crate::{contexts,seal,sealed_nonce_store}::…` path is
/// unchanged.
pub use vta_support::contexts;
pub mod deprecation;
/// DID-template storage (the `tpl:` keyspace), extracted to the `vta-support`
/// crate and re-exported so every `crate::did_templates::…` path is unchanged.
pub use vta_support::did_templates;
pub mod didcomm_bridge;
pub mod error;
/// Key management (master seed, BIP-32 derivation, wrapping, seed-store
/// backends), extracted to the `vta-keys` crate. Re-exported as `crate::keys`
/// so every `crate::keys::…` path stays unchanged and `vta_service::keys` keeps
/// resolving for `vta-enclave`. The seed-store backend features
/// (`aws-secrets` … `keyring`, `tee`) are wired to the matching `vta-keys/*`
/// features in `Cargo.toml`.
pub use vta_keys as keys;
pub mod keyspaces;
#[cfg(feature = "didcomm")]
pub mod messaging;
#[cfg(feature = "rest")]
pub mod metrics;
pub mod operations;
/// Policy subsystem (regorus engine, default policy bundle, consent model,
/// decision evaluators), extracted to the `vta-policy` crate and re-exported so
/// every `crate::policy::…` path is unchanged.
pub use vta_policy as policy;
#[cfg(feature = "rest")]
pub mod routes;
pub use vta_support::seal;
pub use vta_support::sealed_nonce_store;
pub mod server;
pub mod status;
pub mod store;
/// TEE bootstrap subsystem (attestation providers, KMS attest/decrypt, the
/// anchor MAC, first-boot DID autogen), extracted to the `vta-tee` crate and
/// re-exported as `crate::tee` so `vta_service::tee::…` keeps resolving for
/// `vta-enclave` and every existing call site.
#[cfg(feature = "tee")]
pub use vta_tee as tee;
/// Transport-neutral Trust-Task dispatch subsystem. Both the REST route
/// (`routes::trust_tasks`-mounted `dispatch_trust_task`) and the DIDComm
/// `handle_trust_task` handler dispatch through `dispatch_trust_task_core`
/// here, so it lives at the crate root rather than under `routes::` (P2.4).
pub mod trust_tasks;
/// The holder credential vault, extracted to the `vta-vault` crate. Re-exported
/// as `crate::vault` so every `crate::vault::…` path (dispatch handlers, the
/// sweeper, `credential_exchange`) keeps resolving unchanged. The `bbs` /
/// `webvh` cargo features gate the same code they did before, wired through to
/// `vta-vault/bbs` and `vta-vault/webvh` in `Cargo.toml`.
pub use vta_vault as vault;
/// WebVH hosting infrastructure (DID-record store, hosting-server HTTP client,
/// and its DID-auth handshake), extracted to the `vta-webvh` crate and
/// re-exported so every `crate::{webvh_store,webvh_client,webvh_auth}::…` path
/// is unchanged. `webvh_didcomm` stays here — it depends on `didcomm_bridge`.
#[cfg(feature = "webvh")]
pub use vta_webvh::{webvh_auth, webvh_client, webvh_store};
#[cfg(feature = "webvh")]
pub mod webvh_didcomm;

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
