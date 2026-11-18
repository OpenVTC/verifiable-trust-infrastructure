//! `vti-witness` — the witness host service binary.

// jemalloc as the global allocator (the `jemalloc` feature, on by default).
// glibc malloc keeps freed pages in its arenas rather than returning them, so
// RSS ratchets to the high-water mark and never falls back — indistinguishable
// from a leak on a memory graph. jemalloc purges freed pages back to the OS.
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// jemalloc tuning, read by jemalloc itself at startup via this well-known symbol.
///
/// `background_thread:true` runs the purger on its own thread, so freed pages
/// are returned even while the process is idle (without it, purging only
/// happens as a side effect of later allocator calls). `dirty_decay_ms` /
/// `muzzy_decay_ms` are how long freed pages linger before being returned;
/// 5s (default 10s) keeps RSS close to the live heap at negligible cost for an
/// I/O-bound service.
///
/// The name is `_rjem_malloc_conf`, not `malloc_conf`: `tikv-jemalloc-sys`
/// builds jemalloc with the `_rjem_` symbol prefix, so an unprefixed
/// `malloc_conf` would be silently ignored.
///
/// SAFETY: exporting a symbol is unsafe because it could clash with another
/// definition of the same name. This is the name jemalloc documents for
/// exactly this, it is defined once (in the binary, never the library), and
/// the value is the NUL-terminated static string jemalloc expects. The type is a
/// reference to a fixed-size array, a thin pointer matching jemalloc's
/// `const char *malloc_conf`; a `&[u8]` slice reference would be two words.
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[allow(unsafe_code)]
#[unsafe(export_name = "_rjem_malloc_conf")]
pub static MALLOC_CONF: &[u8; 63] =
    b"background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000\0";

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "vti-witness",
    version,
    about = "Witness host service: witness identities provisioned from a VTA, served over TSP and DIDComm"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Provision witness identities from the operator's VTA (two phases).
    Setup(SetupArgs),
    /// Serve every enabled witness identity until SIGINT or SIGTERM.
    Run {
        /// The configuration `setup` wrote.
        #[arg(long, short, default_value = "config.toml")]
        config: PathBuf,
    },
}

#[derive(Args)]
struct SetupArgs {
    /// Phase 1: mint an ephemeral setup key, store it here (0600) and print
    /// the `pnm` grant to run at the VTA.
    #[arg(long, conflicts_with = "from")]
    setup_key_out: Option<PathBuf>,
    /// The VTA context the phase-1 grant names (phase 1 only).
    #[arg(long, default_value = vti_witness::setup::DEFAULT_CONTEXT)]
    context: String,
    /// Phase 2: provision from this setup file, once the grant is in place.
    #[arg(long)]
    from: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    // rustls cannot pick a provider on its own with two compiled in.
    vta_sdk::crypto_init::install_default_crypto_provider();
    #[cfg(feature = "keyring")]
    vta_sdk::keyring_init::warn_store_unavailable("vti-witness");

    let cli = Cli::parse();
    let result = match cli.command {
        Command::Setup(args) => match (args.setup_key_out, args.from) {
            (Some(out), None) => vti_witness::setup::run_phase1(&out, &args.context).await,
            (None, Some(from)) => vti_witness::setup::run_from_file(&from).await,
            _ => Err(anyhow::anyhow!(
                "give --setup-key-out <path> (phase 1) or --from <setup.toml> (phase 2)"
            )),
        },
        Command::Run { config } => vti_witness::run::run(&config).await,
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
