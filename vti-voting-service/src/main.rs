use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use clap::Parser;
use vti_voting::service::BallotBox;
use vti_voting_service::{AppState, identity::Identity, journal::FileJournal, router};

/// The voting service: a ballot box and board for community elections.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Where the service keeps its identity and its journal.
    #[arg(long, default_value = "./voting-data")]
    data_dir: PathBuf,
    /// The address to serve the HTTPS Trust Task binding on (terminate TLS in front of it).
    #[arg(long, default_value = "127.0.0.1:8740")]
    listen: String,
    /// Verify only did:key signers, resolving nothing over the network. Every cast is signed
    /// by a did:key; a community on did:webvh then cannot register, so this is for tests.
    #[arg(long)]
    did_key_only: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vti_voting_service=info".into()),
        )
        .init();
    let args = Args::parse();

    let identity = Identity::load_or_mint(&args.data_dir)?;
    // Printed, not only logged: it is what a community names as `ballotBox`.
    println!("ballot box DID: {}", identity.did);

    let journal = Arc::new(FileJournal::open(&args.data_dir.join("journal"))?);
    let restored = journal.load()?;
    let elections = restored.len();
    let ballot_box = BallotBox::restore(&identity.did, journal, restored)
        .map_err(|f| anyhow::anyhow!("restoring the journal: {} ({})", f.reason, f.local))?;

    let resolver = if !args.did_key_only {
        use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
        let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
        vti_common::auth::TrustTaskVmResolver::new(client)
    } else {
        vti_common::auth::TrustTaskVmResolver::did_key_only()
    };

    let state = Arc::new(AppState {
        ballot_box: Mutex::new(ballot_box),
        identity,
        resolver,
    });
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!(
        listen = %args.listen,
        data_dir = %args.data_dir.display(),
        elections,
        "voting service ready — holding ballots it cannot attribute"
    );
    axum::serve(listener, router(state)).await?;
    Ok(())
}
