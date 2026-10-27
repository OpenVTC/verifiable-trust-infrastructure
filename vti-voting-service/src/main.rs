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
