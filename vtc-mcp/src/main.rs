//! `vtc-mcp` — a Verifiable Trust Community as MCP tools, over stdio, or with
//! `--listen` over loopback HTTP to every MCP host on the machine at once
//! (`listen`).
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
//!
//! ## Several communities
//!
//! `--communities <file>` with `--listen` bridges each community the file
//! names from one process, at `/mcp/<name>`, each as its own identity under
//! its own policy (`communities`). The ladder holds per community.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing::Instrument;
use vta_sdk::did_secrets::DidSecretsBundle;
use vta_sdk::session::TransportChoice;
use vtc_client::{SessionIdentity, VtcClient};
use vti_mcp_common::guard::{ConfirmLevel, Guard};
use vti_mcp_common::listen::{Serving, mcp_path_for};
use vti_mcp_common::observability::{self, LogFormat, Recorder};

mod communities;
mod guides;
mod health;
mod key_reuse;
mod listen;
mod server;
mod signin;
mod workflows;

use server::{BridgeIdentity, VtcMcp};

#[derive(Parser)]
#[command(
    name = "vtc-mcp",
    version,
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

    /// Mint a fresh Ed25519 `did:key` for a dedicated agent entry and print
    /// it as JSON (`did`, `privateKeyMultibase`) on stdout, then exit. Give
    /// the DID to an administrator to enrol (`cnm access grant`), keep the key
    /// for `VTC_MCP_AGENT_KEY`. Serves no MCP.
    #[arg(long, exclusive = true)]
    mint_did_key: bool,

    /// Do not keep or read the local note of which community each agent key
    /// was used with, and so do not warn when one key is pointed at a second
    /// community (`docs/03-vtc/vtc-mcp.md` §2.7).
    #[arg(long, env = "VTC_MCP_NO_KEY_REUSE_CHECK")]
    no_key_reuse_check: bool,

    /// Serve MCP over HTTP at `http://<addr>/mcp` instead of stdio, so every
    /// MCP host on this machine shares one bridge — one key, one mediator
    /// socket. Loopback addresses only (`127.0.0.1:7465`). Every request needs
    /// `Authorization: Bearer <token>`: `VTC_MCP_LISTEN_TOKEN`, else the
    /// owner-only `listen-token` file in the state directory, created on
    /// first use.
    #[arg(long, env = "VTC_MCP_LISTEN")]
    listen: Option<SocketAddr>,

    /// Bridge every community this TOML file names from one `--listen`
    /// process, each at `http://<addr>/mcp/<name>` as its own identity, with
    /// its own policy, audit log and sign-in (`docs/03-vtc/vtc-mcp.md` §7.2).
    /// Replaces `--vtc-did`, `--vtc-url`, the identity flags and
    /// `--audit-log`; the policy flags beside it are every community's
    /// default.
    #[arg(long, env = "VTC_MCP_COMMUNITIES")]
    communities: Option<PathBuf>,
}

/// A fresh Ed25519 `did:key` and its private key, multibase-encoded as the
/// rest of the workspace encodes one (the raw 32-byte seed, base58btc).
fn mint_did_key() -> anyhow::Result<serde_json::Value> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("CSPRNG failed: {e}"))?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&signing.verifying_key().to_bytes())
    );
    let private_key_multibase = multibase::encode(multibase::Base::Base58Btc, seed);
    Ok(serde_json::json!({
        "did": did,
        "privateKeyMultibase": private_key_multibase,
        "next": "give `did` to an administrator to enrol (cnm access grant <did> --admin-role …); \
                 keep `privateKeyMultibase` as VTC_MCP_AGENT_KEY, never on the command line",
    }))
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum TransportOpt {
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

/// Whether this agent key was used with another community before, recorded
/// as used with this one (`key_reuse`). A warning, logged and reported by
/// `vtc_whoami`/`vtc_status`; never a refusal. A note that cannot be kept is
/// logged and otherwise ignored, since it only ever warns.
fn reuse_warning(agent_did: Option<&str>, vtc_did: &str) -> Option<String> {
    let agent_did = agent_did?;
    let Some(path) = key_reuse::default_path() else {
        tracing::debug!("no state directory: the agent-key reuse note is not kept");
        return None;
    };
    match key_reuse::check_and_record(&path, agent_did, vtc_did) {
        Ok(others) if others.is_empty() => None,
        Ok(others) => {
            let warning = key_reuse::warning(agent_did, &others);
            tracing::warn!("{warning}");
            Some(warning)
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "could not keep the agent-key reuse note");
            None
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.mint_did_key {
        // The one thing this binary writes to stdout other than MCP: it is
        // not serving, so the channel is free.
        println!("{}", serde_json::to_string_pretty(&mint_did_key()?)?);
        return Ok(());
    }

    // stdout is the MCP JSON-RPC channel — logs go to stderr, and on by default.
    let log_format = LogFormat::parse(&args.log_format).map_err(|e| anyhow::anyhow!(e))?;
    observability::init_tracing("vtc_mcp", &args.log_level, log_format);

    if let Some(path) = args.communities.clone() {
        return run_communities(&args, &path).await;
    }

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
    let recorder = open_recorder(args.audit_log.as_deref())?;
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
    // Settled before anything connects: a listen address or token that cannot
    // be used is a policy failure, and policy failures are fatal.
    let serving =
        Serving::from_listen(&listen::BRIDGE, args.listen).map_err(|e| anyhow::anyhow!(e))?;

    let community = Community {
        name: None,
        vtc_did: args.vtc_did.clone(),
        vtc_url: args.vtc_url.clone(),
        rung: ladder(&args),
        transport: args.transport,
        guard,
        recorder,
        serving: serving.label(),
        reuse_check: !args.no_key_reuse_check,
    };
    let (bridge, client) = open(community).await;
    serve(bridge, client, serving).await
}

/// One community to bridge, resolved from the flags or from one section of
/// the communities file.
struct Community {
    /// Its name with `--communities`; `None` for a bridge to one community.
    name: Option<String>,
    vtc_did: Option<String>,
    vtc_url: Option<String>,
    rung: Result<Option<(SessionIdentity, &'static str)>, String>,
    transport: TransportOpt,
    guard: Guard,
    recorder: Arc<Recorder>,
    /// How hosts reach it: `stdio`, or its URL.
    serving: String,
    reuse_check: bool,
}

/// Connect to one community and build its bridge — degraded, with the
/// reason, when there is no usable identity, no community, or no connection,
/// so its `vtc_status` can say what is wrong.
async fn open(c: Community) -> (VtcMcp, Option<Arc<VtcClient>>) {
    let mut identity = BridgeIdentity {
        community: c.name.clone(),
        mode: "unconfigured".into(),
        agent_did: None,
        vtc_did: c.vtc_did.clone(),
        transport_choice: c.transport.label().into(),
        reuse_warning: None,
        serving: c.serving,
    };
    let degraded = |message: String, identity, guard, recorder| {
        tracing::error!(error = %message, "serving in degraded mode — tools will report this");
        (VtcMcp::degraded(message, identity, guard, recorder), None)
    };
    let (session_identity, mode) = match c.rung {
        Ok(Some(rung)) => rung,
        Ok(None) => {
            let message = "no identity configured: supply --agent-secrets (a did:webvh bundle) \
                           or --agent-did + --agent-key (a dedicated did:key), and --vtc-did"
                .to_string();
            return degraded(message, identity, c.guard, c.recorder);
        }
        Err(e) => {
            let message = format!("no usable identity: {e}");
            return degraded(message, identity, c.guard, c.recorder);
        }
    };
    identity.mode = mode.into();
    identity.agent_did = Some(session_identity.did().to_string());

    let Some(vtc_did) = c
        .vtc_did
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
    else {
        let message = "no community configured: --vtc-did names the community, and its DID \
                       document says how to reach it"
            .to_string();
        return degraded(message, identity, c.guard, c.recorder);
    };

    if c.reuse_check {
        identity.reuse_warning = reuse_warning(identity.agent_did.as_deref(), vtc_did);
    }

    tracing::info!(
        mode,
        agent_did = identity.agent_did.as_deref().unwrap_or("-"),
        vtc_did,
        transport = c.transport.label(),
        "connecting to the community"
    );
    let connected = VtcClient::connect_resolved(
        session_identity,
        vtc_did,
        c.vtc_url.as_deref(),
        c.transport.into(),
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
                serving = %identity.serving,
                "connected to the community; serving MCP"
            );
            let bridge = VtcMcp::new(client.clone(), identity, c.guard, c.recorder);
            bridge.learn_served().await;
            bridge.learn_delegation().await;
            (bridge, Some(client))
        }
        Err(e) => {
            let message = format!("connecting to the community ({mode}): {e}");
            degraded(message, identity, c.guard, c.recorder)
        }
    }
}

fn open_recorder(path: Option<&std::path::Path>) -> anyhow::Result<Arc<Recorder>> {
    Ok(match path {
        Some(path) => Arc::new(
            Recorder::with_file(path)
                .map_err(|e| anyhow::anyhow!("opening audit log {}: {e}", path.display()))?,
        ),
        None => Arc::new(Recorder::default()),
    })
}

/// The flags `--communities` replaces: each community names its own, and a
/// process-wide one would be ambiguous.
fn communities_conflicts(args: &Args) -> Vec<&'static str> {
    [
        ("--vtc-did", args.vtc_did.is_some()),
        ("--vtc-url", args.vtc_url.is_some()),
        ("--agent-secrets", args.agent_secrets.is_some()),
        ("--agent-did", args.agent_did.is_some()),
        ("--agent-key", args.agent_key.is_some()),
        ("--audit-log", args.audit_log.is_some()),
    ]
    .into_iter()
    .filter_map(|(flag, given)| given.then_some(flag))
    .collect()
}

/// `--communities`: bridge every community the file names from one process,
/// each at `/mcp/<name>`. Everything that is the operator's policy — the
/// file, the flags beside it, every audit log, the listen address and token —
/// is settled before anything connects, and fatal when wrong.
async fn run_communities(args: &Args, path: &std::path::Path) -> anyhow::Result<()> {
    let conflicts = communities_conflicts(args);
    if !conflicts.is_empty() {
        anyhow::bail!(
            "--communities names each community's DID, identity and audit log in its own \
             section; remove {} (or their VTC_MCP_* variables)",
            conflicts.join(", ")
        );
    }
    let Some(addr) = args.listen else {
        anyhow::bail!(
            "--communities serves each community at its own path, so it needs --listen \
             (127.0.0.1:7465); a stdio host reaches one community, with --vtc-did"
        );
    };
    // Checked here rather than per community: a bad default is as fatal as a
    // bad section.
    ConfirmLevel::parse(&args.confirm).map_err(|e| anyhow::anyhow!(e))?;
    let defaults = communities::Defaults {
        transport: args.transport,
        read_only: args.read_only,
        allow: args.allow.clone(),
        deny: args.deny.clone(),
        confirm: args.confirm.clone(),
    };
    let resolved = communities::load(path, &defaults).map_err(|e| anyhow::anyhow!(e))?;
    let Serving::Http { addr, token } =
        Serving::from_listen(&listen::BRIDGE, Some(addr)).map_err(|e| anyhow::anyhow!(e))?
    else {
        unreachable!("a listen address always serves HTTP")
    };
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        communities = resolved.len(),
        file = %path.display(),
        "vtc-mcp starting"
    );

    let mut pending = Vec::with_capacity(resolved.len());
    for c in resolved {
        let recorder = open_recorder(c.audit_log.as_deref())?;
        tracing::info!(
            community = %c.name,
            policy = %c.guard.summary(),
            audit_log = recorder
                .audit_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".into()),
            "community configured"
        );
        let name = c.name.clone();
        let community = Community {
            serving: format!("http://{addr}{}", mcp_path_for(&c.name)),
            name: Some(c.name),
            vtc_did: Some(c.vtc_did),
            vtc_url: c.vtc_url,
            rung: c.rung.map(Some),
            transport: c.transport,
            guard: c.guard,
            recorder,
            reuse_check: !args.no_key_reuse_check,
        };
        let span = tracing::info_span!("community", name = %name);
        pending.push(async move { (name, open(community).await) }.instrument(span));
    }
    // Each community connects on its own: one that is slow or unreachable
    // delays none of the others' connects, and serves degraded on its own.
    let opened = futures_util::future::join_all(pending).await;

    let mut services = Vec::with_capacity(opened.len());
    let mut clients = Vec::new();
    for (name, (bridge, client)) in opened {
        services.push((name, bridge));
        clients.extend(client);
    }
    let served = vti_mcp_common::listen::serve_many(&listen::BRIDGE, services, addr, token)
        .await
        .map_err(anyhow::Error::from);
    for client in clients {
        client.shutdown().await;
    }
    served
}

/// Serve MCP until the host disconnects (stdio) or the process is told to stop
/// (`--listen`), then close the session. A session client holds a live,
/// auto-reconnecting mediator socket that `Drop` cannot close, so `shutdown`
/// runs on every path out.
async fn serve(
    bridge: VtcMcp,
    client: Option<Arc<VtcClient>>,
    serving: Serving,
) -> anyhow::Result<()> {
    let served = match serving {
        Serving::Stdio => {
            async {
                let service = bridge.serve(stdio()).await?;
                service.waiting().await?;
                Ok::<(), anyhow::Error>(())
            }
            .await
        }
        Serving::Http { addr, token } => {
            vti_mcp_common::listen::serve(&listen::BRIDGE, bridge, addr, token)
                .await
                .map_err(anyhow::Error::from)
        }
    };
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
    fn a_minted_did_key_signs_as_itself() {
        let minted = mint_did_key().unwrap();
        let did = minted["did"].as_str().unwrap();
        let key = minted["privateKeyMultibase"].as_str().unwrap();
        assert!(did.starts_with("did:key:z6Mk"), "{did}");
        // The key the bridge would run with reconstructs the same DID.
        let seed = vta_sdk::did_key::decode_private_key_multibase(key).unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(
            did,
            format!(
                "did:key:{}",
                vta_sdk::did_key::ed25519_multibase_pubkey(&signing.verifying_key().to_bytes())
            )
        );
        assert_ne!(mint_did_key().unwrap()["did"], minted["did"]);
        assert!(args(&["--mint-did-key"]).mint_did_key);
    }

    #[test]
    fn communities_replaces_the_single_community_flags() {
        assert!(communities_conflicts(&args(&["--communities", "c.toml"])).is_empty());
        let a = args(&[
            "--communities",
            "c.toml",
            "--vtc-did",
            "did:webvh:x",
            "--audit-log",
            "a.jsonl",
            "--confirm",
            "sensitive",
        ]);
        assert_eq!(communities_conflicts(&a), vec!["--vtc-did", "--audit-log"]);
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
