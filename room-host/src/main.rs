//! The `room-host` binary: parse the flags, open the store, serve.
//!
//! Everything else is in the library beside this, so the same router can be driven from a
//! test or the `data_room` example without a socket.

use clap::Parser;
use room_host::{open_state_with_resolver, router};

#[derive(Parser, Debug)]
#[command(name = "room-host", about = "Store and serve data-room records")]
struct Args {
    /// Where the record store lives.
    #[arg(long, default_value = "./room-host-data")]
    data_dir: std::path::PathBuf,
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8300")]
    listen: String,
    /// Resolve credential issuers over the network as well as locally.
    ///
    /// Off by default. A room's credentials are normally issued by a `did:webvh` room, so a
    /// host without this serves almost nothing — but turning network resolution on means an
    /// unauthenticated request can make this host fetch, so it is a decision an operator
    /// makes rather than a default they inherit.
    #[arg(long)]
    resolve_dids: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "room_host=info".into()),
        )
        .init();

    let args = Args::parse();
    let resolver = if args.resolve_dids {
        use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
        let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
        vti_common::auth::TrustTaskVmResolver::new(client)
    } else {
        vti_common::auth::TrustTaskVmResolver::did_key_only()
    };
    let state = open_state_with_resolver(&args.data_dir, resolver)?;

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!(
        listen = %args.listen,
        data_dir = %args.data_dir.display(),
        network_resolution = args.resolve_dids,
        "room host ready — storing records for rooms it does not govern"
    );
    axum::serve(listener, router(state)).await?;
    Ok(())
}
