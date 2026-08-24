//! `vta-mcp` — a Model Context Protocol server exposing a Verifiable Trust
//! Agent's capabilities as MCP tools, so any MCP-speaking agent host can use
//! the VTA (signing oracle, secrets vault, device check-in, discovery) without
//! custom integration code.
//!
//! Transport: stdio (the standard local-agent transport — Claude Desktop and
//! most hosts spawn the server and speak JSON-RPC over stdin/stdout). All
//! logging therefore goes to **stderr**; stdout is the protocol channel.
//!
//! Auth (modes):
//! - **DIDComm** — authenticate a scoped agent directly over DIDComm via a
//!   mediator (`--vta-did` + `--mediator-did` required). The canonical path —
//!   it works against any VTA, including DIDComm-only VTAs that expose no REST
//!   endpoint. Two mutually-exclusive ways to supply the agent identity:
//!   - **did:webvh bundle** (`--agent-secrets <PATH|JSON>`): a hosted DID whose
//!     `#key-0` (Ed25519 signing) + `#key-1` (X25519 key-agreement) keys are
//!     exported as a `DidSecretsBundle` (e.g. by `vta create-did-webvh
//!     --export-secrets`). The agent's `client_did` is the bundle's `did`.
//!   - **did:key** (`--agent-did` + `--agent-key`): authenticate a scoped agent
//!     `did:key` directly. Both keys are derived from the one Ed25519 seed.
//!     Either runs a dedicated, context-scoped vta-mcp (the agent's ACL bounds
//!     it to its context). Takes precedence when fully configured.
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
use vta_sdk::agent_connect::{AgentConnect, pnm_session_key};
use vta_sdk::agent_session::{AgentConfig, AgentSession};
use vta_sdk::client::VtaClient;
use vta_sdk::session::TransportChoice;

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
    /// or required in token mode). Optional in DIDComm mode (REST is a
    /// fallback there).
    #[arg(long, env = "VTA_URL")]
    url: Option<String>,

    /// did:webvh agent secrets bundle (DIDComm mode) — a path to a JSON
    /// `DidSecretsBundle` file, or the inline JSON itself. The agent's
    /// `client_did` is the bundle's `did`; its `#key-0` (Ed25519) +
    /// `#key-1` (X25519) keys authenticate + decrypt. Requires `--vta-did`
    /// and `--mediator-did`. Mutually exclusive with `--agent-did`/`--agent-key`.
    /// Stays in this process; never sent over MCP.
    #[arg(long, env = "VTA_MCP_AGENT_SECRETS")]
    agent_secrets: Option<String>,

    /// Agent `did:key` to authenticate as, directly over DIDComm (did:key
    /// DIDComm mode). Requires `--agent-key`, `--vta-did`, `--mediator-did`.
    /// Lets a consumer run a dedicated, context-scoped vta-mcp against any VTA —
    /// including DIDComm-only VTAs with no REST endpoint. Mutually exclusive
    /// with `--agent-secrets`.
    #[arg(long, env = "VTA_MCP_AGENT_DID")]
    agent_did: Option<String>,

    /// Agent Ed25519 signing key (multibase) for did:key DIDComm mode. Stays in
    /// this process; never sent over MCP.
    #[arg(long, env = "VTA_MCP_AGENT_KEY")]
    agent_key: Option<String>,

    /// The VTA's DID (DIDComm mode) — the recipient of the DIDComm messages.
    #[arg(long, env = "VTA_MCP_VTA_DID")]
    vta_did: Option<String>,

    /// The mediator's DID to route DIDComm through (DIDComm mode).
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

/// Translate the CLI/env args into the SDK's connect ladder. Keeping this a
/// pure mapping (no I/O) is what lets the test below assert the *mode* a set of
/// flags selects without a VTA to connect to.
fn agent_connect_from(args: &Args) -> AgentConnect {
    AgentConnect {
        agent_secrets: args.agent_secrets.clone(),
        agent_did: args.agent_did.clone(),
        agent_key: args.agent_key.clone(),
        vta_did: args.vta_did.clone(),
        mediator_did: args.mediator_did.clone(),
        url: args.url.clone(),
        token: std::env::var("VTA_TOKEN").ok(),
        // `pnm` stores sessions as `vta:<slug>`; the bare slug an operator
        // types finds nothing. See `pnm_session_key`.
        session_key: args.vta.as_deref().map(pnm_session_key),
        service_name: Some(args.service_name.clone()),
        sessions_dir: args.sessions_dir.clone(),
        transport: TransportChoice::Auto,
    }
}

/// Build an authenticated [`VtaClient`] from the args/env (see module docs).
///
/// The four-rung ladder itself lives in `vta_sdk::agent_connect` — every
/// agent-side bridge needs the same one, and a second copy is how they drift.
async fn build_client(args: &Args) -> anyhow::Result<VtaClient> {
    let connect = agent_connect_from(args);
    let mode = connect.mode()?;
    tracing::info!(mode = mode.label(), "connecting to VTA");
    connect
        .connect()
        .await
        .map_err(|e| anyhow::anyhow!("connecting to VTA ({}): {e}", mode.label()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::agent_connect::ConnectMode;

    /// Args with everything unset — the base every case below varies from.
    fn args() -> Args {
        Args::parse_from(["vta-mcp"])
    }

    #[test]
    fn didkey_flags_select_didkey_didcomm_mode() {
        let mut a = args();
        a.agent_did = Some("did:key:zAgent".into());
        a.agent_key = Some("zKey".into());
        a.vta_did = Some("did:key:zVta".into());
        a.mediator_did = Some("did:key:zMed".into());
        assert_eq!(
            agent_connect_from(&a).mode().unwrap(),
            ConnectMode::DidKey {
                agent_did: "did:key:zAgent".into(),
                mediator_did: "did:key:zMed".into(),
            }
        );
    }

    #[test]
    fn agent_secrets_flag_selects_the_bundle_mode() {
        let mut a = args();
        a.agent_secrets = Some(r#"{"did":"did:webvh:abc:example.com:a","secrets":[]}"#.into());
        a.vta_did = Some("did:key:zVta".into());
        a.mediator_did = Some("did:key:zMed".into());
        assert_eq!(
            agent_connect_from(&a).mode().unwrap(),
            ConnectMode::DidWebvhBundle {
                agent_did: "did:webvh:abc:example.com:a".into(),
                mediator_did: "did:key:zMed".into(),
            }
        );
    }

    #[test]
    fn a_half_configured_agent_identity_fails_rather_than_using_the_session() {
        let mut a = args();
        a.agent_did = Some("did:key:zAgent".into());
        a.vta = Some("my-vta".into());
        let err = agent_connect_from(&a).mode().unwrap_err();
        assert!(err.to_string().contains("agent_key"), "{err}");
    }

    #[test]
    fn the_vta_slug_alone_selects_session_mode() {
        let mut a = args();
        a.vta = Some("my-vta".into());
        // Guard against a `VTA_TOKEN` in the developer's own environment
        // silently turning this into the token rung.
        let mut connect = agent_connect_from(&a);
        connect.token = None;
        assert_eq!(
            connect.mode().unwrap(),
            ConnectMode::Session {
                // Not "my-vta": `pnm` stores it as `vta:my-vta`, and passing
                // the bare slug found no session at all.
                key: "vta:my-vta".into()
            }
        );
    }
}
