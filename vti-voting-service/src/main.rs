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

use clap::{Parser, Subcommand};
use vti_voting_service::{config::VotingConfig, run, setup};

/// The voting service: a ballot box and board for community elections.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Provision the service's identity from the operator's VTA (two phases).
    Setup {
        /// Phase 1: mint the setup key into this file and print the grant to run at the VTA.
        #[arg(long, conflicts_with = "from")]
        setup_key_out: Option<PathBuf>,
        /// The VTA context to provision into (phase 1).
        #[arg(long, default_value = setup::DEFAULT_CONTEXT)]
        context: String,
        /// Phase 2: provision from this setup file.
        #[arg(long)]
        from: Option<PathBuf>,
    },
    /// Serve the ballot box.
    Run {
        /// The configuration `setup` wrote.
        #[arg(long, conflicts_with_all = ["data_dir", "listen"])]
        config: Option<PathBuf>,
        /// Without --config: serve as a did:key minted into this directory, over HTTPS only
        /// (for tests).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Without --config: the address to serve the HTTPS binding on.
        #[arg(long)]
        listen: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vti_voting_service=info,vti_common=info".into()),
        )
        .init();
    match Args::parse().command {
        Command::Setup {
            setup_key_out: Some(out),
            context,
            ..
        } => setup::run_phase1(&out, &context).await,
        Command::Setup {
            from: Some(path), ..
        } => setup::run_from_file(&path).await,
        Command::Setup { .. } => {
            anyhow::bail!("name --setup-key-out <path> (phase 1) or --from <setup.toml> (phase 2)")
        }
        Command::Run {
            config: Some(path), ..
        } => run::run(VotingConfig::load(&path)?).await,
        Command::Run {
            data_dir, listen, ..
        } => {
            let mut config = VotingConfig::from_toml_str("data_dir = \"./voting-data\"\n")?;
            if let Some(dir) = data_dir {
                config.data_dir = dir;
            }
            if let Some(listen) = listen {
                config.listen = listen;
            }
            run::run(config).await
        }
    }
}
