//! VTA binary for AWS Nitro Enclaves (TEE mode).
//!
//! This binary handles TEE-specific bootstrapping:
//! - VsockStore connection to parent's persistent storage proxy
//! - KMS secret bootstrap (seed + JWT key generation/decryption)
//! - TEE provider initialization (Nitro/SEV-SNP/Simulated)
//! - Mnemonic export guard
//! - Automatic did:webvh identity generation
//!
//! After bootstrapping, it calls vta_service::server::run() with
//! the TeeContext — the same server code as the local VTA binary.

#[cfg(feature = "vsock-log")]
mod vsock_log;

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use clap::Parser;
use tracing::info;

use vta_service::config::AppConfig;
use vta_service::keys::seed_store::{KmsTeeSeedStore, SeedStore};
use vta_service::server::TeeContext;
use vta_service::store;
use vta_service::tee;

#[cfg(not(any(feature = "rest", feature = "didcomm")))]
compile_error!("At least one of 'rest' or 'didcomm' must be enabled.");

#[derive(Parser)]
#[command(name = "vta", about = "Verifiable Trust Agent (TEE Enclave mode)")]
struct Cli {
    /// Path to config file
    #[arg(long, short)]
    config: Option<std::path::PathBuf>,
}

/// Connect to the parent instance's vsock storage proxy, retrying with bounded
/// backoff so a boot-ordering race isn't an outage.
///
/// On a cold boot the enclave and the parent-side storage proxy start
/// concurrently; if the enclave's connect races ahead of the proxy binding its
/// vsock port, a single attempt would `exit(1)` — and Nitro does **not** restart
/// the enclave, so a benign ordering race becomes an outage on every unattended
/// host reboot. Wait for the dependency instead, giving up only after the proxy
/// is clearly not coming up (~80s total).
#[cfg(feature = "vsock-store")]
async fn connect_vsock_with_retry() -> Result<store::VsockStore, String> {
    use std::time::Duration;
    const MAX_ATTEMPTS: u32 = 30;
    const BASE_DELAY: Duration = Duration::from_millis(250);
    const MAX_DELAY: Duration = Duration::from_secs(3);

    let mut delay = BASE_DELAY;
    for attempt in 1..=MAX_ATTEMPTS {
        match store::VsockStore::connect(None).await {
            Ok(vs) => {
                if attempt > 1 {
                    tracing::info!("connected to vsock storage proxy on attempt {attempt}");
                }
                return Ok(vs);
            }
            Err(e) if attempt < MAX_ATTEMPTS => {
                tracing::warn!(
                    "vsock storage proxy not ready (attempt {attempt}/{MAX_ATTEMPTS}): {e}; \
                     retrying in {delay:?}"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(MAX_DELAY);
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    unreachable!("the loop returns on the final attempt")
}

#[tokio::main]
async fn main() {
    // Pin rustls to the aws-lc-rs backend before any TLS object is built;
    // see `vta_sdk::crypto_init` (re-exported by vta-service). Without this,
    // rustls 0.23 panics on backend auto-detection when both backends are
    // compiled in.
    vta_service::crypto_init::install_default_crypto_provider();

    eprintln!("VTA enclave binary starting...");

    let cli = Cli::parse();

    // Load config — resolve the path first so we can print diagnostics on failure
    let config_path = cli
        .config
        .clone()
        .or_else(|| {
            std::env::var("VTA_CONFIG_PATH")
                .ok()
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(|| std::path::PathBuf::from("config.toml"));
    eprintln!("Loading config from: {}", config_path.display());
    if config_path.exists() {
        eprintln!(
            "Config file exists ({} bytes)",
            std::fs::metadata(&config_path)
                .map(|m| m.len())
                .unwrap_or(0)
        );
    } else {
        eprintln!("Config file NOT FOUND at {}", config_path.display());
    }
    let config = match AppConfig::load(cli.config) {
        Ok(c) => {
            eprintln!("Config loaded successfully");
            c
        }
        Err(e) => {
            eprintln!("FATAL: failed to load config: {e}");
            // Print the raw config file for debugging
            if let Ok(raw) = std::fs::read_to_string(&config_path) {
                eprintln!("--- config file contents ---\n{raw}\n--- end config ---");
            }
            std::process::exit(1);
        }
    };

    eprintln!("Config loaded. Initializing tracing...");

    // Initialize tracing. When vsock-log is enabled, logs are tee'd to both
    // stderr (visible in debug mode) and a vsock channel on port 5700 (visible
    // via enclave-proxy in production mode). The initial connection is awaited
    // (with a 2s timeout) so early boot logs are forwarded before bootstrap.
    #[cfg(feature = "vsock-log")]
    {
        eprintln!("vsock-log feature enabled, starting vsock writer...");
        let vsock_writer = vsock_log::start().await;
        eprintln!("vsock writer started, initializing tracing...");
        vta_service::init_tracing_with_writer(&config, vsock_writer);
    }
    #[cfg(not(feature = "vsock-log"))]
    {
        eprintln!("vsock-log feature NOT enabled, using stderr tracing");
        vta_service::init_tracing(&config);
    }
    eprintln!("Tracing initialized.");
    print_banner();

    // ── Open store (vsock-proxied or local) ──
    #[cfg(feature = "vsock-store")]
    let store = if config.tee.kms.is_some() {
        match connect_vsock_with_retry().await {
            Ok(vs) => store::Store::Vsock(vs),
            Err(e) => {
                tracing::error!("failed to connect to vsock storage proxy after retries: {e}");
                std::process::exit(1);
            }
        }
    } else {
        match store::Store::open(&config.store) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("failed to open store: {e}");
                std::process::exit(1);
            }
        }
    };
    #[cfg(not(feature = "vsock-store"))]
    let store = match store::Store::open(&config.store) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("failed to open store: {e}");
            std::process::exit(1);
        }
    };

    // ── KMS secret bootstrap (uses the store for ciphertext K/V storage) ──
    let tee_bootstrap = if let Some(ref kms_config) = config.tee.kms {
        match tee::kms_bootstrap::bootstrap_secrets(
            kms_config,
            &config.tee.storage_key_salt,
            &store,
        )
        .await
        {
            Ok(secrets) => Some(secrets),
            Err(e) => {
                tracing::error!("TEE KMS bootstrap failed: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // ── Seed store ──
    let seed_store: Arc<dyn SeedStore> = if let Some(ref bootstrap) = tee_bootstrap {
        let kms_config = match config.tee.kms.as_ref() {
            Some(c) => c,
            None => {
                tracing::error!("KMS config missing after successful bootstrap");
                std::process::exit(1);
            }
        };
        Arc::new(KmsTeeSeedStore::new(
            bootstrap.seed.clone(),
            kms_config.key_arn.clone(),
            kms_config.region.clone(),
        ))
    } else {
        match vta_service::keys::seed_store::create_seed_store(&config) {
            Ok(store) => Arc::from(store),
            Err(e) => {
                tracing::error!("failed to create seed store: {e}");
                std::process::exit(1);
            }
        }
    };

    // ── JWT signing key + storage encryption key from bootstrap ──
    let (mut config, storage_encryption_key) = if let Some(ref bootstrap) = tee_bootstrap {
        let mut config = config;
        let jwt_b64 = BASE64.encode(bootstrap.jwt_signing_key);
        config.auth.jwt_signing_key = Some(jwt_b64);
        (config, Some(bootstrap.storage_key))
    } else {
        (config, None)
    };

    // ── Mnemonic export guard ──
    let mnemonic_guard = {
        let export_window: Option<u64> = std::env::var("VTA_MNEMONIC_EXPORT_WINDOW")
            .ok()
            .and_then(|v| v.parse().ok());

        if let Some(ref bootstrap) = tee_bootstrap {
            if let (Some(entropy), Some(window_secs)) = (bootstrap.entropy, export_window) {
                Some(Arc::new(tee::mnemonic_guard::MnemonicExportGuard::new(
                    entropy,
                    window_secs,
                )))
            } else if bootstrap.entropy.is_some() && export_window.is_none() {
                info!(
                    "first boot but VTA_MNEMONIC_EXPORT_WINDOW not set — mnemonic export disabled"
                );
                Some(Arc::new(tee::mnemonic_guard::MnemonicExportGuard::empty()))
            } else {
                Some(Arc::new(tee::mnemonic_guard::MnemonicExportGuard::empty()))
            }
        } else {
            None
        }
    };

    // ── Auto-generate DID identity on first boot ──
    if let Err(e) = tee::did_autogen::maybe_generate_vta_did(
        &mut config,
        &*seed_store,
        &store,
        storage_encryption_key,
    )
    .await
    {
        tracing::warn!("VTA DID auto-generation failed: {e}");
    }

    // ── Auto-bootstrap super-admin credential on first boot ──
    if let Err(e) =
        tee::admin_bootstrap::maybe_bootstrap_admin(&config, &store, storage_encryption_key).await
    {
        tracing::warn!("admin credential bootstrap failed: {e}");
    }

    // ── Initialize TEE provider + build context ──
    let tee_context = {
        let tee_state = match tee::init_tee(&config.tee) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("TEE initialization failed: {e}");
                std::process::exit(1);
            }
        };
        tee_state.map(|state| TeeContext {
            state,
            mnemonic_guard,
        })
    };

    // ── Start the server ──
    // `allow_degraded = true`: in a TEE the signing identity is established
    // earlier in this boot by KMS autogen (`maybe_generate_vta_did`) +
    // admin-bootstrap, and a degraded first boot is an existing, documented
    // state (see the TEE-required warning in `server::run`). The
    // missing-identity hard-fail (P0.9b) is a guard for the local `vta`
    // daemon, which exposes the `--allow-degraded` opt-out on its CLI; the
    // enclave has no such CLI surface.
    if let Err(e) = vta_service::server::run(
        config,
        store,
        seed_store,
        storage_encryption_key,
        tee_context,
        true,
    )
    .await
    {
        tracing::error!("server error: {e}");
        std::process::exit(1);
    }
}

// init_tracing is in vta_service::init_tracing (shared with all front-ends)

fn print_banner() {
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let red = "\x1b[31m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{cyan} ██╗   ██╗{magenta}████████╗{yellow} █████╗{reset}
{cyan} ██║   ██║{magenta}╚══██╔══╝{yellow}██╔══██╗{reset}
{cyan} ██║   ██║{magenta}   ██║   {yellow}███████║{reset}
{cyan} ╚██╗ ██╔╝{magenta}   ██║   {yellow}██╔══██║{reset}
{cyan}  ╚████╔╝ {magenta}   ██║   {yellow}██║  ██║{reset}
{cyan}   ╚═══╝  {magenta}   ╚═╝   {yellow}╚═╝  ╚═╝{reset}
{dim}  Verifiable Trust Agent v{version}{reset}  {red}[TEE ENCLAVE]{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}
