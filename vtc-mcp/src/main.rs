//! `vtc-mcp` — a Verifiable Trust Community as MCP tools, over stdio.
//!
//! The bridge is a native Trust Task client: every tool call is one signed
//! document `vtc-client` sends in-process, over the transport the community's
//! DID document advertises — TSP, else DIDComm, else signed documents over
//! HTTPS (`docs/05-design-notes/vtc-mcp.md`, D0). It never runs `cnm` or
//! `pnm`, and never takes a CLI's stored login as its identity.
//!
//! ## The identity ladder
//!
//! Exactly one identity, chosen by what is configured, never by falling
//! through:
//!
//! 1. `--agent-secrets` — a `did:webvh` secrets bundle: a member's own
//!    persona, as a VTA minted it. **The member's** standing.
//! 2. `--agent-did` + `--agent-key` — an Ed25519 `did:key` an administrator
//!    enrolled as a dedicated agent entry with a role ceiling or listed
//!    capabilities. **That entry's** standing.
//!
//! Both need `--vtc-did`. Both given is an error; half of rung 2 is an error
//! naming the missing field; neither serves in degraded mode so `vtc_status`
//! can say what is wrong. There is no rung that replays an operator's login.

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use vta_sdk::did_secrets::DidSecretsBundle;
use vta_sdk::session::TransportChoice;
use vtc_client::{SessionIdentity, VtcClient};
use vti_mcp_common::guard::{ConfirmLevel, Guard};
use vti_mcp_common::observability::{self, LogFormat, Recorder};

mod server;

use server::{BridgeIdentity, VtcMcp};

#[derive(Parser)]
#[command(
    name = "vtc-mcp",
    about = "MCP server exposing a Verifiable Trust Community as tools"
)]
struct Args {
    /// The community's DID. The audience every document is signed for, and
    /// where its transports are read from: never taken from a server.
    #[arg(long, env = "VTC_MCP_VTC_DID")]
    vtc_did: Option<String>,

    /// The community's HTTPS API base (`https://vtc.example.com/v1`). Only
    /// needed when the DID document advertises no `VTCRest` service, or to
    /// override the one it does.
    #[arg(long, env = "VTC_URL")]
    vtc_url: Option<String>,

    /// Rung 1: a `did:webvh` secrets bundle — a path to a JSON
    /// `DidSecretsBundle` file, or the inline JSON. The bridge speaks as the
    /// bundle's `did`: a member's persona. Stays in this process; never sent
    /// over MCP. Mutually exclusive with `--agent-did`/`--agent-key`.
    #[arg(long, env = "VTC_MCP_AGENT_SECRETS")]
    agent_secrets: Option<String>,

    /// Rung 2: the dedicated agent `did:key` an administrator enrolled.
    /// Requires `--agent-key`. Mutually exclusive with `--agent-secrets`.
    #[arg(long, env = "VTC_MCP_AGENT_DID")]
    agent_did: Option<String>,

    /// Rung 2: the agent's Ed25519 signing key (multibase). Stays in this
    /// process; never sent over MCP. Prefer the environment variable — a
    /// command-line argument is readable by every process on the machine.
    #[arg(long, env = "VTC_MCP_AGENT_KEY")]
    agent_key: Option<String>,

    /// Which transport to use. `auto` (default): TSP when the community
    /// advertises it, else DIDComm, else signed documents over HTTPS; a
    /// session the community advertises is never silently replaced by HTTPS.
    /// `tsp` / `didcomm` pin one; `rest` posts signed documents over HTTPS
    /// regardless, for a diagnosis.
    #[arg(long, env = "VTC_MCP_TRANSPORT", default_value = "auto")]
    transport: TransportOpt,

    /// Refuse every operation that is not read-only.
    #[arg(long, env = "VTC_MCP_READ_ONLY")]
    read_only: bool,

    /// Only permit operations matching these slug globs (`vtc/groups/*`, or an
    /// exact slug). Repeatable; comma-separated in the environment variable.
    #[arg(long, env = "VTC_MCP_ALLOW", value_delimiter = ',')]
    allow: Vec<String>,

    /// Always refuse operations matching these slug globs. Checked before
    /// `--allow`.
    #[arg(long, env = "VTC_MCP_DENY", value_delimiter = ',')]
    deny: Vec<String>,

    /// Which operations need a human to approve them, via MCP elicitation:
    /// `never`, `destructive` (default), `sensitive` (also authority-moving
    /// and disclosing ones) or `always`.
    #[arg(long, env = "VTC_MCP_CONFIRM", default_value = "destructive")]
    confirm: String,

    /// stderr log level for this crate. `RUST_LOG`, when set, wins.
    #[arg(long, env = "VTC_MCP_LOG_LEVEL", default_value = "info")]
    log_level: String,

    /// stderr log format: `text` or `json`.
    #[arg(long, env = "VTC_MCP_LOG_FORMAT", default_value = "text")]
    log_format: String,

    /// Append a redacted JSONL record of every call to this file (0600).
    #[arg(long, env = "VTC_MCP_AUDIT_LOG")]
    audit_log: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
enum TransportOpt {
    #[default]
    Auto,
    Tsp,
    Didcomm,
    Rest,
}

impl From<TransportOpt> for TransportChoice {
    fn from(opt: TransportOpt) -> Self {
        match opt {
            TransportOpt::Auto => Self::Auto,
            TransportOpt::Tsp => Self::Tsp,
            TransportOpt::Didcomm => Self::Didcomm,
            TransportOpt::Rest => Self::Rest,
        }
    }
}

impl TransportOpt {
    fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Tsp => "tsp",
            Self::Didcomm => "didcomm",
            Self::Rest => "rest",
        }
    }
}

/// The identity rung the arguments select, with its label — or `None` when
/// nothing is configured, or an error for a half-configured or
/// doubly-configured one.
fn ladder(args: &Args) -> Result<Option<(SessionIdentity, &'static str)>, String> {
    let has_didkey = args.agent_did.is_some() || args.agent_key.is_some();
    if args.agent_secrets.is_some() && has_didkey {
        return Err(
            "--agent-secrets (a did:webvh bundle) and --agent-did/--agent-key (a \
                    did:key) are mutually exclusive — supply one identity, not both"
                .into(),
        );
    }
    if let Some(raw) = args.agent_secrets.as_deref() {
        let bundle = load_bundle(raw)?;
        return Ok(Some((SessionIdentity::Bundle(bundle), "did:webvh-bundle")));
    }
    match (args.agent_did.as_deref(), args.agent_key.as_deref()) {
        (Some(did), Some(key)) => Ok(Some((
            SessionIdentity::DidKey {
                did: did.to_string(),
                private_key_multibase: key.to_string(),
            },
            "did:key",
        ))),
        (None, None) => Ok(None),
        (Some(_), None) => Err("did:key mode needs --agent-key beside --agent-did".into()),
        (None, Some(_)) => Err("did:key mode needs --agent-did beside --agent-key".into()),
    }
}

/// Load a secrets bundle from a path or inline JSON.
fn load_bundle(raw: &str) -> Result<DidSecretsBundle, String> {
    let json = if std::path::Path::new(raw).exists() {
        std::fs::read_to_string(raw)
            .map_err(|e| format!("reading the agent secrets bundle from `{raw}`: {e}"))?
    } else {
        raw.to_string()
    };
    serde_json::from_str(&json)
        .map_err(|e| format!("parsing the agent secrets bundle (path or inline JSON): {e}"))
}

/// A key on the command line is readable by every process on the machine;
/// say so once, at startup, rather than silently.
fn warn_about_argv_secrets() {
    let argv: Vec<String> = std::env::args().collect();
    if argv
        .iter()
        .any(|a| a == "--agent-key" || a.starts_with("--agent-key="))
    {
        tracing::warn!(
            "--agent-key was passed on the command line, where other processes can read it; \
             prefer VTC_MCP_AGENT_KEY in the environment"
        );
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // stdout is the MCP JSON-RPC channel — logs go to stderr, and on by default.
    let log_format = LogFormat::parse(&args.log_format).map_err(|e| anyhow::anyhow!(e))?;
    observability::init_tracing("vtc_mcp", &args.log_level, log_format);

    // Policy failures are fatal; connectivity failures serve degraded. See
    // `vta-mcp` for why: running under a policy the operator did not ask for
    // is the one outcome worse than not starting, while an exited MCP server
    // is invisible to the model.
    let guard = Guard {
        read_only: args.read_only,
        allow: args.allow.clone(),
        deny: args.deny.clone(),
        confirm: ConfirmLevel::parse(&args.confirm).map_err(|e| anyhow::anyhow!(e))?,
        node: "VTC",
    };
    let recorder = match &args.audit_log {
        Some(path) => Arc::new(
            Recorder::with_file(path)
                .map_err(|e| anyhow::anyhow!("opening --audit-log {}: {e}", path.display()))?,
        ),
        None => Arc::new(Recorder::default()),
    };
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        policy = %guard.summary(),
        audit_log = recorder
            .audit_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "-".into()),
        "vtc-mcp starting"
    );
    warn_about_argv_secrets();

    let mut identity = BridgeIdentity {
        mode: "unconfigured".into(),
        agent_did: None,
        vtc_did: args.vtc_did.clone(),
        transport_choice: args.transport.label().into(),
    };
    let rung = match ladder(&args) {
        Ok(Some(rung)) => rung,
        Ok(None) => {
            let message = "no identity configured: supply --agent-secrets (a did:webvh bundle) \
                           or --agent-did + --agent-key (a dedicated did:key), and --vtc-did"
                .to_string();
            tracing::error!(error = %message, "serving in degraded mode — tools will report this");
            return serve(VtcMcp::degraded(message, identity, guard, recorder), None).await;
        }
        Err(e) => {
            let message = format!("no usable identity: {e}");
            tracing::error!(error = %message, "serving in degraded mode — tools will report this");
            return serve(VtcMcp::degraded(message, identity, guard, recorder), None).await;
        }
    };
    let (session_identity, mode) = rung;
    identity.mode = mode.into();
    identity.agent_did = Some(session_identity.did().to_string());

    let Some(vtc_did) = args
        .vtc_did
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
    else {
        let message = "no community configured: --vtc-did names the community, and its DID \
                       document says how to reach it"
            .to_string();
        tracing::error!(error = %message, "serving in degraded mode — tools will report this");
        return serve(VtcMcp::degraded(message, identity, guard, recorder), None).await;
    };

    tracing::info!(
        mode,
        agent_did = identity.agent_did.as_deref().unwrap_or("-"),
        vtc_did,
        transport = args.transport.label(),
        "connecting to the community"
    );
    let connected = VtcClient::connect_resolved(
        session_identity,
        vtc_did,
        args.vtc_url.as_deref(),
        args.transport.into(),
    )
    .await;
    match connected {
        Ok(client) => {
            let client = Arc::new(client);
            tracing::info!(
                transport = client
                    .transport()
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "-".into()),
                "connected to the community; serving MCP over stdio"
            );
            let bridge = VtcMcp::new(client.clone(), identity, guard, recorder);
            bridge.learn_served().await;
            serve(bridge, Some(client)).await
        }
        Err(e) => {
            let message = format!("connecting to the community ({mode}): {e}");
            tracing::error!(error = %message, "serving in degraded mode — tools will report this");
            serve(VtcMcp::degraded(message, identity, guard, recorder), None).await
        }
    }
}

/// Serve MCP over stdio until the host disconnects, then close the session.
/// A session client holds a live, auto-reconnecting mediator socket that
/// `Drop` cannot close, so `shutdown` runs on every path out.
async fn serve(bridge: VtcMcp, client: Option<Arc<VtcClient>>) -> anyhow::Result<()> {
    let served = async {
        let service = bridge.serve(stdio()).await?;
        service.waiting().await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Some(client) = client {
        client.shutdown().await;
    }
    served
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> Args {
        let mut argv = vec!["vtc-mcp"];
        argv.extend_from_slice(extra);
        Args::try_parse_from(argv).unwrap()
    }

    #[test]
    fn nothing_configured_is_no_rung_not_an_error() {
        assert!(ladder(&args(&[])).unwrap().is_none());
    }

    #[test]
    fn a_did_key_needs_both_halves() {
        let err = ladder(&args(&["--agent-did", "did:key:zA"])).unwrap_err();
        assert!(err.contains("--agent-key"), "{err}");
        let err = ladder(&args(&["--agent-key", "zSecret"])).unwrap_err();
        assert!(err.contains("--agent-did"), "{err}");
        let (identity, mode) = ladder(&args(&[
            "--agent-did",
            "did:key:zA",
            "--agent-key",
            "zSecret",
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(mode, "did:key");
        assert_eq!(identity.did(), "did:key:zA");
    }

    #[test]
    fn two_identities_are_refused_rather_than_ranked() {
        let bundle = r#"{"did":"did:webvh:abc:example.com:p","secrets":[]}"#;
        let err = ladder(&args(&[
            "--agent-secrets",
            bundle,
            "--agent-did",
            "did:key:zA",
            "--agent-key",
            "zSecret",
        ]))
        .unwrap_err();
        assert!(err.contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn an_inline_bundle_is_the_persona_rung() {
        let bundle = r#"{"did":"did:webvh:abc:example.com:p","secrets":[]}"#;
        let (identity, mode) = ladder(&args(&["--agent-secrets", bundle]))
            .unwrap()
            .unwrap();
        assert_eq!(mode, "did:webvh-bundle");
        assert_eq!(identity.did(), "did:webvh:abc:example.com:p");
        assert!(load_bundle("not json and not a path").is_err());
    }

    #[test]
    fn the_default_policy_is_confirm_destructive_and_auto_transport() {
        let a = args(&[]);
        assert_eq!(
            ConfirmLevel::parse(&a.confirm).unwrap(),
            ConfirmLevel::Destructive
        );
        assert_eq!(a.transport, TransportOpt::Auto);
        assert!(!a.read_only);
        let a = args(&[
            "--transport",
            "rest",
            "--allow",
            "vtc/groups/*,vtc/boards/*",
        ]);
        assert_eq!(TransportChoice::from(a.transport), TransportChoice::Rest);
        assert_eq!(a.allow, vec!["vtc/groups/*", "vtc/boards/*"]);
    }
}
