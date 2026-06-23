//! `vta-mcp` — a Model Context Protocol server exposing a Verifiable Trust
//! Agent's capabilities as MCP tools, so any MCP-speaking agent host can use
//! the VTA (signing oracle, secrets vault, device check-in, discovery) without
//! custom integration code.
//!
//! Transport: stdio (the standard local-agent transport — Claude Desktop and
//! most hosts spawn the server and speak JSON-RPC over stdin/stdout). All
//! logging therefore goes to **stderr**; stdout is the protocol channel.
//!
//! Auth (three modes):
//! - **did:key DIDComm** (`--agent-did` + `--agent-key` + `--vta-did` +
//!   `--mediator-did`): authenticate a scoped agent `did:key` directly over
//!   DIDComm via a mediator. The canonical path — it works against any VTA,
//!   including DIDComm-only VTAs that expose no REST endpoint. Use this to run a
//!   dedicated, context-scoped vta-mcp (the agent's ACL bounds it to its
//!   context). Takes precedence when fully configured.
//! - **Session**: reuse an existing `pnm`/`cnm` login — `--vta <slug>` selects
//!   the stored keyring session; the client auto-refreshes its token. This is
//!   the "log in with pnm, then run vta-mcp" path.
//! - **Token**: set `VTA_URL` + `VTA_TOKEN` for a REST client with a bearer
//!   token (simple, for testing / short-lived use; no auto-refresh; REST only).

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
    /// or required in token mode). Optional in did:key DIDComm mode (REST is a
    /// fallback there).
    #[arg(long, env = "VTA_URL")]
    url: Option<String>,

    /// Agent `did:key` to authenticate as, directly over DIDComm (did:key
    /// DIDComm mode). Requires `--agent-key`, `--vta-did`, `--mediator-did`.
    /// Lets a consumer run a dedicated, context-scoped vta-mcp against any VTA —
    /// including DIDComm-only VTAs with no REST endpoint.
    #[arg(long, env = "VTA_MCP_AGENT_DID")]
    agent_did: Option<String>,

    /// Agent Ed25519 signing key (multibase) for did:key DIDComm mode. Stays in
    /// this process; never sent over MCP.
    #[arg(long, env = "VTA_MCP_AGENT_KEY")]
    agent_key: Option<String>,

    /// The VTA's DID (did:key DIDComm mode) — the recipient of the DIDComm
    /// messages.
    #[arg(long, env = "VTA_MCP_VTA_DID")]
    vta_did: Option<String>,

    /// The mediator's DID to route DIDComm through (did:key DIDComm mode).
    #[arg(long, env = "VTA_MCP_MEDIATOR_DID")]
    mediator_did: Option<String>,

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

    // Keep a handle so the client's DIDComm session can be closed cleanly once
    // serving ends — however it ends. A DIDComm `VtaClient` owns a live,
    // auto-reconnecting mediator socket that `Drop` can't close; leaking it
    // trips a debug-assert and duels the mediator on reconnect. We run serve +
    // wait, then `shutdown()` unconditionally (idempotent, a no-op for
    // REST/token clients) *before* propagating any error — a bare `?` on
    // `waiting()` would skip the cleanup on the common EOF/disconnect path.
    let agent = Arc::new(agent);
    let served = async {
        let service = VtaMcp::new(agent.clone(), holder).serve(stdio()).await?;
        service.waiting().await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    agent.shutdown().await;
    served
}

/// Resolve the four did:key DIDComm-mode params. Returns `Some(..)` when all
/// four are set, `None` when none are, and an error when only some are — so a
/// half-configured invocation fails fast instead of silently falling through to
/// another auth mode.
fn didkey_didcomm_params(
    agent_did: Option<String>,
    agent_key: Option<String>,
    vta_did: Option<String>,
    mediator_did: Option<String>,
) -> anyhow::Result<Option<(String, String, String, String)>> {
    match (agent_did, agent_key, vta_did, mediator_did) {
        (Some(a), Some(k), Some(v), Some(m)) => Ok(Some((a, k, v, m))),
        (None, None, None, None) => Ok(None),
        _ => anyhow::bail!(
            "did:key DIDComm mode needs all of --agent-did, --agent-key, \
             --vta-did, --mediator-did (or none of them)"
        ),
    }
}

/// Build an authenticated [`VtaClient`] from the args/env (see module docs).
async fn build_client(args: &Args) -> anyhow::Result<VtaClient> {
    // did:key DIDComm mode: authenticate a scoped agent did:key directly over
    // DIDComm (the canonical transport — works against DIDComm-only VTAs that
    // expose no REST endpoint). Takes precedence when fully configured.
    if let Some((agent_did, agent_key, vta_did, mediator_did)) = didkey_didcomm_params(
        args.agent_did.clone(),
        args.agent_key.clone(),
        args.vta_did.clone(),
        args.mediator_did.clone(),
    )? {
        tracing::info!(%agent_did, %mediator_did, "using did:key DIDComm mode");
        return VtaClient::connect_didcomm(
            &agent_did,
            &agent_key,
            &vta_did,
            &mediator_did,
            args.url.clone(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("connecting to VTA over DIDComm: {e}"));
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn didkey_didcomm_params_all_set_returns_some() {
        let got = didkey_didcomm_params(
            Some("did:key:zAgent".into()),
            Some("zKey".into()),
            Some("did:key:zVta".into()),
            Some("did:key:zMed".into()),
        )
        .unwrap();
        assert_eq!(
            got,
            Some((
                "did:key:zAgent".into(),
                "zKey".into(),
                "did:key:zVta".into(),
                "did:key:zMed".into(),
            ))
        );
    }

    #[test]
    fn didkey_didcomm_params_none_set_returns_none() {
        assert_eq!(didkey_didcomm_params(None, None, None, None).unwrap(), None);
    }

    #[test]
    fn didkey_didcomm_params_partial_is_error() {
        let err = didkey_didcomm_params(
            Some("did:key:zAgent".into()),
            None,
            Some("did:key:zVta".into()),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("all of"));
    }
}
