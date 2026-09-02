//! The `room-host` binary: parse the flags, open the store, serve.
//!
//! Everything else is in the library beside this, so the same router can be driven from a
//! test or the `data_room` example without a socket.

use clap::Parser;
use room_host::{open_state, router};

#[derive(Parser, Debug)]
#[command(name = "room-host", about = "Store and serve data-room records")]
struct Args {
    /// Where the record store lives.
    #[arg(long, default_value = "./room-host-data")]
    data_dir: std::path::PathBuf,
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8300")]
    listen: String,
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
    let state = open_state(&args.data_dir)?;

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!(
        listen = %args.listen,
        data_dir = %args.data_dir.display(),
        "room host ready — storing records for rooms it does not govern"
    );
    axum::serve(listener, router(state)).await?;
    Ok(())
}
