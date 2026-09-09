//! The `room-host` binary: parse the flags, open the store, serve.
//!
//! Everything else is in the library beside this, so the same router can be driven from a
//! test or the `data_room` example without a socket.

use clap::Parser;
use room_host::{open_state_with_resolver, router_with_origins};

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
    /// Origins allowed to reach this host from a browser. Repeatable.
    ///
    /// Off by default, and explicit origins only — no wildcard. A room's member may be a
    /// web page, and without this a browser cannot reach this host at all: the response is
    /// discarded before any script sees it, so the failure reads as a network error with
    /// nothing in it about origins. Which sites may ask is an operator's decision; what the
    /// answer is remains the credentials'.
    #[arg(long = "allow-origin")]
    allow_origin: Vec<String>,
    /// Rooms this host **mirrors**: a JSON file naming each room's write-primary
    /// and the read credentials this mirror presents to it.
    ///
    /// A mirrored room serves reads from the copy and refuses every write,
    /// naming its primary. The file holds a private key, so it is hardened to
    /// owner-only on load.
    #[arg(long)]
    mirror_config: Option<std::path::PathBuf>,
    /// Be reachable at this mediator, as well as at `--listen`.
    ///
    /// The host connects as its own `did:peer:2` — minted into the data directory on first
    /// use and stable thereafter, because a member's saved address names it — and serves the
    /// same Trust Tasks over DIDComm and TSP that it serves over HTTP. What authorizes a
    /// request does not change: the presenter is the document's own proof either way.
    ///
    /// Off by default. A host that is not asked to be reachable opens no socket and mints no
    /// identity, which is the same posture `--resolve-dids` and `--allow-origin` take: a
    /// capability is a decision an operator makes rather than one they inherit.
    #[cfg(feature = "didcomm")]
    #[arg(long)]
    mediator_did: Option<String>,

    /// Seconds between mirror pulls.
    ///
    /// A mirror is not latency-critical — it serves a copy, and a client that
    /// needs the newest record reads the primary — so the default is unhurried.
    /// Shorter intervals cost the primary a listing per room per pass.
    #[arg(long, default_value_t = 300)]
    mirror_interval_secs: u64,
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

    // Mirrors start before the listener: a host that is going to serve a copy
    // should begin catching up before it starts answering reads from it, and a
    // config that does not parse is a startup failure rather than a warning
    // discovered later.
    if let Some(path) = &args.mirror_config {
        let config = room_host::mirror::MirrorConfig::load(path)?;
        tracing::info!(
            rooms = config.rooms.len(),
            interval_secs = args.mirror_interval_secs,
            "mirroring rooms from their write-primaries"
        );
        tokio::spawn(room_host::mirror::run(
            state.clone(),
            config,
            args.mirror_interval_secs,
        ));
    }

    // Before the listener, for the same reason mirrors start first: a host that is going to
    // be reachable at a mediator should be reachable *by the time* it starts answering, and
    // an identity that will not load is a startup failure rather than something discovered
    // by the first member who cannot reach it.
    #[cfg(feature = "didcomm")]
    if let Some(mediator_did) = args.mediator_did.clone() {
        let identity =
            room_host::didcomm::HostIdentity::load_or_mint(&args.data_dir, &mediator_did)?;
        // Printed, not only logged. It is this host's *address* — the thing a member puts
        // after `?at=` — and an operator has to be able to copy it out of a terminal.
        println!("host DID: {}", identity.did);
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = room_host::didcomm::serve(state, identity, mediator_did).await {
                tracing::error!(error = %e, "the mediator connection ended");
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!(
        listen = %args.listen,
        data_dir = %args.data_dir.display(),
        network_resolution = args.resolve_dids,
        "room host ready — storing records for rooms it does not govern"
    );
    axum::serve(listener, router_with_origins(state, &args.allow_origin)).await?;
    Ok(())
}
