//! `vta-mcp` — a Model Context Protocol server exposing a Verifiable Trust
//! Agent's capabilities as MCP tools, so any MCP-speaking agent host can use
//! the VTA (signing oracle, secrets vault, device check-in, discovery) without
//! custom integration code.
//!
//! Transport: stdio (the standard local-agent transport — Claude Desktop and
//! most hosts spawn the server and speak JSON-RPC over stdin/stdout). All
//! logging therefore goes to **stderr**; stdout is the protocol channel.
//!
//! Auth (two modes):
//! - **Session** (default): reuse an existing `pnm`/`cnm` login —
//!   `--vta <slug>` selects the stored keyring session; the client
//!   auto-refreshes its token. This is the "log in with pnm, then run vta-mcp"
//!   path.
//! - **Token**: set `VTA_URL` + `VTA_TOKEN` for a REST client with a bearer
//!   token (simple, for testing / short-lived use; no auto-refresh).

mod server;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use vta_sdk::agent_session::{AgentConfig, AgentSession};
use vta_sdk::client::VtaClient;
use vta_sdk::session::SessionStore;

use server::VtaMcp;

#[derive(Parser, Debug)]
#[command(
    name = "vta-mcp",
    about = "MCP server exposing a VTA's agent capabilities as tools"
)]
struct Args {
    /// Keyring session key / VTA slug of an existing `pnm` login to reuse
    /// (session mode). Omit only when using `VTA_URL` + `VTA_TOKEN`.
    #[arg(long, env = "VTA_MCP_VTA")]
    vta: Option<String>,

    /// Service name the session was stored under.
    #[arg(long, env = "VTA_MCP_SERVICE", default_value = "pnm-cli")]
    service_name: String,

    /// Directory holding stored sessions (default: ~/.config/pnm).
    #[arg(long, env = "VTA_MCP_SESSIONS_DIR")]
    sessions_dir: Option<PathBuf>,

    /// Override the VTA REST URL (otherwise resolved from the session/DID,
    /// or required in token mode).
    #[arg(long, env = "VTA_URL")]
    url: Option<String>,

    /// Register this bridge as an `ai-agent` device at startup, so it appears in
    /// `pnm device list` and can be revoked with `pnm device {disable,wipe}`.
    /// Only use this when vta-mcp runs as a *dedicated* agent identity — it
    /// attaches a device binding to the authenticated DID's ACL entry. Idempotent.
    #[arg(long, env = "VTA_MCP_ENROLL")]
    enroll: bool,

    /// Display name for the device binding when `--enroll` is set.
    #[arg(long, env = "VTA_MCP_DEVICE_NAME", default_value = "vta-mcp")]
    device_name: String,

    /// Holder DID for the `issue_vp` tool (the agent's own presentation
    /// identity). Together with `--holder-key`, enables VP issuance.
    #[arg(long, env = "VTA_MCP_HOLDER_DID")]
    holder_did: Option<String>,

    /// Holder Ed25519 signing key (multibase) for `issue_vp`. Stays in this
    /// process; never sent over MCP.
    #[arg(long, env = "VTA_MCP_HOLDER_KEY")]
    holder_key: Option<String>,

    /// Verification-method fragment of the holder DID used as the VP proof's
    /// `verificationMethod` (`{holder_did}#{fragment}`).
    #[arg(long, env = "VTA_MCP_HOLDER_VM_FRAGMENT", default_value = "key-0")]
    holder_vm_fragment: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Pin rustls to the aws-lc-rs backend before any TLS object is built;
    // see `vta_sdk::crypto_init`. Without this, rustls 0.23 panics on
    // backend auto-detection when both backends are compiled in.
    vta_sdk::crypto_init::install_default_crypto_provider();

    // stdout is the MCP JSON-RPC channel — logs MUST go to stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let client = build_client(&args).await?;

    // Wrap the connected client in an AgentSession — the unified handle the MCP
    // tools route through. Optionally enroll as a managed device first (one-shot,
    // before serving — never concurrently with tool RPCs on a DIDComm session).
    let agent = AgentSession::from_client(client, AgentConfig::for_attach(&args.device_name));
    if args.enroll {
        agent.ensure_enrolled().await?;
        tracing::info!(device = %args.device_name, "vta-mcp enrolled as a managed device");
    }
    // Optional holder identity for the `issue_vp` tool (signs presentations
    // locally; the key never crosses MCP).
    let holder = match (&args.holder_did, &args.holder_key) {
        (Some(did), Some(key)) => {
            tracing::info!(%did, "issue_vp enabled with configured holder identity");
            Some(Arc::new(server::HolderIdentity {
                did: did.clone(),
                vm_fragment: args.holder_vm_fragment.clone(),
                key_multibase: key.clone(),
            }))
        }
        _ => None,
    };

    tracing::info!("vta-mcp connected to VTA; serving MCP over stdio");

    let service = VtaMcp::new(Arc::new(agent), holder).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

/// Build an authenticated [`VtaClient`] from the args/env (see module docs).
async fn build_client(args: &Args) -> anyhow::Result<VtaClient> {
    // Token mode: explicit URL + bearer token.
    if let (Some(url), Ok(token)) = (args.url.as_deref(), std::env::var("VTA_TOKEN"))
        && !token.is_empty()
    {
        let client = VtaClient::new(url);
        client.set_token_async(token).await;
        tracing::info!(%url, "using token-mode REST client");
        return Ok(client);
    }

    // Session mode: reuse an existing pnm/cnm login (auto-refreshing).
    let key = args.vta.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "no session selected: pass --vta <slug> (an existing `pnm` login) \
             or set VTA_URL + VTA_TOKEN"
        )
    })?;
    let sessions_dir = match &args.sessions_dir {
        Some(d) => d.clone(),
        None => default_sessions_dir()?,
    };
    tracing::info!(
        key,
        service = args.service_name,
        "using session-mode client"
    );
    SessionStore::new(&args.service_name, sessions_dir)
        .connect(key, args.url.as_deref(), None)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to VTA: {e}"))
}

fn default_sessions_dir() -> anyhow::Result<PathBuf> {
    let home =
        std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME not set; pass --sessions-dir"))?;
    Ok(PathBuf::from(home).join(".config").join("pnm"))
}
