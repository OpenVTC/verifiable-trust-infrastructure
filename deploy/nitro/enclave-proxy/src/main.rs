mod bridge;
mod channels;
mod config;
mod detect;
#[allow(dead_code)] // Protocol functions used by vsock client (different crate)
mod protocol;
mod resolve;
mod storage;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use config::ProxyConfig;

#[derive(Parser)]
#[command(
    name = "enclave-proxy",
    about = "VTA Nitro Enclave parent-instance proxy",
    long_about = "Bridges networking between a Nitro Enclave and the outside world.\n\
                  Reads mediator config from the VTA's config.toml automatically.\n\
                  Resolves mediator DID locally using the embedded Affinidi DID resolver.\n\
                  Run on the parent EC2 instance (not inside the enclave)."
)]
pub struct Cli {
    /// Path to the VTA config.toml (auto-reads mediator, KMS region, etc.)
    #[arg(short, long, default_value = "deploy/nitro/config.toml")]
    config: PathBuf,

    /// Enclave CID (auto-detected from nitro-cli, or 16 if no enclave running yet)
    #[arg(long, default_value_t = 0)]
    enclave_cid: u32,

    /// External REST API listen port
    #[arg(long, default_value_t = 8443)]
    listen_port: u16,

    /// Vsock port for inbound REST (enclave-side)
    #[arg(long, default_value_t = 5100)]
    vsock_inbound: u32,

    /// Vsock port for outbound mediator (enclave-side)
    #[arg(long, default_value_t = 5200)]
    vsock_mediator: u32,

    /// Vsock port for outbound HTTPS (enclave-side)
    #[arg(long, default_value_t = 5300)]
    vsock_https: u32,

    /// Vsock port for IMDS credential proxy (enclave-side)
    #[arg(long, default_value_t = 5400)]
    vsock_imds: u32,

    /// Vsock port for persistent storage proxy (enclave-side)
    #[arg(long, default_value_t = 5500)]
    vsock_storage: u32,

    /// Vsock port for DID resolver bridge (enclave → resolver sidecar)
    #[arg(long, default_value_t = 5600)]
    vsock_resolver: u32,

    /// Vsock port for enclave log forwarding (enclave → parent stdout)
    #[arg(long, default_value_t = 5700)]
    vsock_logs: u32,

    /// Vsock port for serving the un-baked config envelope (parent → enclave)
    #[arg(long, default_value_t = 5800)]
    vsock_config: u32,

    /// Path to the config envelope JSON served over --vsock-config. When set and
    /// the file exists, the enclave fetches its tenant config here at boot
    /// instead of using a baked/mounted config (un-baked image; see docs).
    #[arg(long)]
    config_envelope: Option<PathBuf>,

    /// Local port where affinidi-did-resolver-cache-server sidecar listens
    #[arg(long, default_value_t = 8080)]
    resolver_port: u16,

    /// Directory for persistent key-value store (on parent EBS)
    #[arg(long, default_value = "/mnt/vta-data/store")]
    storage_data_dir: PathBuf,

    /// Additional hosts to allowlist for HTTPS proxy (host:port)
    #[arg(trailing_var_arg = true)]
    allowlist: Vec<String>,
}

#[tokio::main]
async fn main() {
    // Install the ring crypto provider for rustls before any TLS is used.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // Initialize tracing
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    let mut cli = Cli::parse();

    // Auto-detect enclave CID if not provided.
    // Default to CID 16 if no enclave is running yet — the proxy must start
    // before the enclave so the vsock listeners are ready for boot-time
    // connections (KMS, IMDS).
    const DEFAULT_ENCLAVE_CID: u32 = 16;
    if cli.enclave_cid == 0 {
        cli.enclave_cid = match detect::detect_enclave_cid() {
            Some(cid) => cid,
            None => {
                warn!(
                    "no running enclave found — using default CID {DEFAULT_ENCLAVE_CID}. \
                     Start the enclave with: nitro-cli run-enclave --enclave-cid {DEFAULT_ENCLAVE_CID} ..."
                );
                DEFAULT_ENCLAVE_CID
            }
        };
    }

    // Load proxy config from VTA config.toml
    let config = ProxyConfig::load(&cli.config, &cli);
    let allowlist = config.build_allowlist();

    // Initialize the embedded DID resolver (used for mediator DID resolution)
    let resolver = if config.mediator_did.is_some() && config.mediator_host_override.is_none() {
        match resolve::DIDResolver::new().await {
            Ok(r) => Some(Arc::new(r)),
            Err(e) => {
                error!("failed to initialize DID resolver: {e}");
                error!("mediator DID resolution will not work — set MEDIATOR_HOST as a fallback");
                None
            }
        }
    } else {
        None
    };

    // Print banner
    eprintln!();
    eprintln!("=========================================");
    eprintln!("  VTA Enclave Proxy");
    eprintln!("=========================================");
    eprintln!();
    eprintln!("  Config:      {}", cli.config.display());
    eprintln!("  Enclave CID: {}", config.enclave_cid);
    eprintln!("  Resolver:    {}", if resolver.is_some() { "embedded (Affinidi)" } else { "none" });
    eprintln!();
    eprintln!("  [1] Inbound  REST:     0.0.0.0:{} → vsock:{}", config.listen_port, config.vsock_inbound_port);
    if let Some(ref host) = config.mediator_host_override {
        eprintln!("  [2] Outbound Mediator: vsock:{} → {}:{} (manual override)", config.vsock_mediator_port, host, config.mediator_port_override.unwrap_or(443));
    } else if let Some(ref did) = config.mediator_did {
        eprintln!("  [2] Outbound Mediator: vsock:{} → resolve {did}", config.vsock_mediator_port);
    } else {
        eprintln!("  [2] Outbound Mediator: DISABLED (no mediator_did configured)");
    }
    eprintln!("  [3] Outbound HTTPS:    vsock:{} → {} hosts allowlisted", config.vsock_https_port, allowlist.len());
    for (host, port) in &allowlist {
        eprintln!("       - {host}:{port}");
    }
    eprintln!("  [4] Outbound IMDS:     vsock:{} → 169.254.169.254:80", config.vsock_imds_port);
    eprintln!("  [5] Storage:           vsock:{} → {} (fjall)", config.vsock_storage_port, config.storage_data_dir.display());
    eprintln!("  [6] DID Resolver:      vsock:{} → localhost:{} (sidecar)", cli.vsock_resolver, cli.resolver_port);
    eprintln!("  [7] Enclave Logs:      vsock:{} → stdout (prefixed [vta])", cli.vsock_logs);
    match cli.config_envelope {
        Some(ref p) => eprintln!("  [0] Config:            vsock:{} → {} (un-baked config envelope)", cli.vsock_config, p.display()),
        None => eprintln!("  [0] Config:            DISABLED (no --config-envelope; enclave uses baked/mounted config)"),
    }
    eprintln!();
    eprintln!("  Test:");
    eprintln!("    curl http://localhost:{}/health", config.listen_port);
    eprintln!("    curl http://localhost:{}/attestation/status", config.listen_port);
    eprintln!();

    // Spawn all proxy channels as concurrent tasks
    let inbound = tokio::spawn(channels::run_inbound(
        config.listen_port,
        config.enclave_cid,
        config.vsock_inbound_port,
    ));

    let has_mediator = config.mediator_did.is_some() || config.mediator_host_override.is_some();
    let mediator = if has_mediator {
        let mediator_config = channels::MediatorConfig {
            did: config.mediator_did.clone(),
            host_override: config.mediator_host_override.clone(),
            port_override: config.mediator_port_override,
            resolver: resolver.clone(),
        };
        Some(tokio::spawn(channels::run_mediator(
            config.vsock_mediator_port,
            mediator_config,
        )))
    } else {
        None
    };

    let https = tokio::spawn(channels::run_https_proxy(
        config.vsock_https_port,
        allowlist,
    ));

    let imds = tokio::spawn(channels::run_imds(
        config.vsock_imds_port,
    ));

    let storage = tokio::spawn(storage::run_storage(
        config.vsock_storage_port,
        config.storage_data_dir.clone(),
    ));

    let resolver_bridge = tokio::spawn(channels::run_resolver(
        cli.vsock_resolver,
        cli.resolver_port,
    ));

    let log_receiver = tokio::spawn(channels::run_log_receiver(cli.vsock_logs));

    // [0] Config server (un-baked config): serve the envelope over vsock when a
    // path is supplied and the file exists. Absent → the enclave uses a
    // baked/mounted config (backward compatible).
    let config_server = match cli.config_envelope.clone() {
        Some(path) if path.exists() => {
            Some(tokio::spawn(channels::run_config_server(cli.vsock_config, path)))
        }
        Some(path) => {
            warn!("--config-envelope {} does not exist — not serving config over vsock:{}", path.display(), cli.vsock_config);
            None
        }
        None => None,
    };

    info!("all proxy channels started — press Ctrl+C to stop");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await.ok();
    info!("shutting down");

    // Cancel all tasks
    inbound.abort();
    if let Some(m) = mediator {
        m.abort();
    }
    https.abort();
    imds.abort();
    storage.abort();
    resolver_bridge.abort();
    log_receiver.abort();
    if let Some(c) = config_server {
        c.abort();
    }
}
