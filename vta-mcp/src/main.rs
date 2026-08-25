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
//!
//! Security posture: the VTA is the authority — every call is gated there on
//! the bridge identity's role, ACL and context scope. On top of that this
//! process applies a **local** policy ([`guard`]), because an MCP host approves
//! a *tool* and `vta_call` is one tool that reaches the entire management
//! surface. See `docs/02-vta/vta-mcp.md`.

mod guard;
mod observability;
mod server;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use vta_sdk::agent_connect::{AgentConnect, ConnectMode, pnm_session_key};
use vta_sdk::agent_session::{AgentConfig, AgentSession};
use vta_sdk::client::VtaClient;
use vta_sdk::session::TransportChoice;

use guard::{ConfirmLevel, Guard};
use observability::{LogFormat, Recorder};
use server::{BridgeIdentity, VtaMcp};

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
    /// this process; never sent over MCP. Prefer the environment variable — a
    /// command-line argument is readable by every process on the machine.
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
    /// Refused in session mode — it would attach a device binding to the
    /// *operator's* ACL entry. Idempotent.
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
    /// process; never sent over MCP. Prefer the environment variable.
    #[arg(long, env = "VTA_MCP_HOLDER_KEY")]
    holder_key: Option<String>,

    /// Verification-method fragment of the holder DID used as the VP proof's
    /// `verificationMethod` (`{holder_did}#{fragment}`).
    #[arg(long, env = "VTA_MCP_HOLDER_VM_FRAGMENT", default_value = "key-0")]
    holder_vm_fragment: String,

    /// Refuse every operation that is not read-only. The strongest single
    /// setting: the bridge can inspect the VTA and nothing else, whatever its
    /// ACL would permit.
    #[arg(long, env = "VTA_MCP_READ_ONLY")]
    read_only: bool,

    /// Only permit operations matching these slug globs (`acl/*`,
    /// `vta/memory/*`, or an exact slug). Repeatable; comma-separated in the
    /// environment variable. When set, everything else is refused.
    #[arg(long, env = "VTA_MCP_ALLOW", value_delimiter = ',')]
    allow: Vec<String>,

    /// Always refuse operations matching these slug globs. Checked before
    /// `--allow`, so a deny cannot be undone by an allow.
    #[arg(long, env = "VTA_MCP_DENY", value_delimiter = ',')]
    deny: Vec<String>,

    /// Which operations need a human to approve them, via MCP elicitation:
    /// `never`, `destructive` (default), `sensitive` (also signing, secret
    /// release, ACL changes) or `always`.
    #[arg(long, env = "VTA_MCP_CONFIRM", default_value = "destructive")]
    confirm: String,

    /// stderr log level for this crate (`error`, `warn`, `info`, `debug`,
    /// `trace`). `RUST_LOG`, when set, wins.
    #[arg(long, env = "VTA_MCP_LOG_LEVEL", default_value = "info")]
    log_level: String,

    /// stderr log format: `text` (default) or `json`.
    #[arg(long, env = "VTA_MCP_LOG_FORMAT", default_value = "text")]
    log_format: String,

    /// Append a redacted JSON record of every call to this file (created
    /// owner-only). Independent of the stderr log, and the only record that
    /// outlives the process.
    #[arg(long, env = "VTA_MCP_AUDIT_LOG")]
    audit_log: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Pin rustls to the aws-lc-rs backend before any TLS object is built;
    // see `vta_sdk::crypto_init`. Without this, rustls 0.23 panics on
    // backend auto-detection when both backends are compiled in.
    vta_sdk::crypto_init::install_default_crypto_provider();
    // Register the platform keyring store before any session is read. The
    // `keyring` feature compiles a backend in; this is what gives it somewhere
    // to look. Exits with a diagnostic if no store is usable, matching `pnm`
    // and `cnm` — a session read from a store that will not open returns
    // `None`, which is indistinguishable from "never logged in": the bridge
    // would not fall back, it would forget.
    #[cfg(feature = "keyring")]
    vta_sdk::keyring_init::install_default_store_or_exit("vta-mcp");

    let args = Args::parse();

    // stdout is the MCP JSON-RPC channel — logs MUST go to stderr. Installed
    // before anything else can want to log, and *on* by default: a bridge that
    // says nothing unless RUST_LOG happens to be set is one nobody can debug.
    let log_format = LogFormat::parse(&args.log_format).map_err(|e| anyhow::anyhow!(e))?;
    observability::init_tracing(&args.log_level, log_format);

    // Two kinds of startup failure, handled differently on purpose:
    //
    // - **Policy** (an unparseable `--confirm`, an audit log that will not
    //   open) is fatal. Degrading here would run the bridge under a policy the
    //   operator did not ask for, which is the one outcome worse than not
    //   starting.
    // - **Connectivity** (no auth configured, mediator unreachable, expired
    //   session) serves in degraded mode below, because those are the field
    //   failures and an exited server is invisible to the model.
    let guard = Guard {
        read_only: args.read_only,
        allow: args.allow.clone(),
        deny: args.deny.clone(),
        confirm: ConfirmLevel::parse(&args.confirm).map_err(|e| anyhow::anyhow!(e))?,
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
        "vta-mcp starting"
    );
    warn_about_argv_secrets();
    let connect = agent_connect_from(&args);
    let holder = holder_identity(&args);

    // A misconfigured rung — nothing set at all, a typo'd env var, three of the
    // four did:key fields — is the single most common way this bridge fails,
    // and it fails before any network call. Serve it degraded like any other
    // connection failure so the operator can *ask* what went wrong.
    let mode = match connect.mode() {
        Ok(mode) => mode,
        Err(e) => {
            let message = format!("no usable VTA credentials: {e}");
            tracing::error!(error = %message, "serving in degraded mode — tools will report this");
            let identity = BridgeIdentity {
                // Not the empty string a `Default` would leave: `vta_status`
                // renders this, and a blank mode reads as a bug in the bridge
                // rather than as the operator having configured nothing.
                mode: "unconfigured".to_string(),
                ..BridgeIdentity::default()
            };
            return serve(
                VtaMcp::degraded(message, holder, identity, guard, recorder),
                None,
            )
            .await;
        }
    };
    let identity = identity_of(&args, &mode);

    if args.enroll && !mode.is_dedicated_agent() {
        // Enrolment attaches a device binding to the *authenticated* DID's ACL
        // entry. In session mode that DID is the operator's, so `--enroll`
        // would silently bind this bridge to an operator credential — and the
        // binding is awkward to undo. Refuse rather than do the wrong thing.
        anyhow::bail!(
            "--enroll needs a dedicated agent identity, but this bridge is running in {} mode. \
             Run it with --agent-did/--agent-key (or --agent-secrets) so the device binding \
             attaches to the agent's own ACL entry, or drop --enroll.",
            mode.label()
        );
    }

    tracing::info!(
        mode = mode.label(),
        dedicated_agent = mode.is_dedicated_agent(),
        agent_did = identity.agent_did.as_deref().unwrap_or("-"),
        vta_did = identity.vta_did.as_deref().unwrap_or("-"),
        "connecting to VTA"
    );
    if !mode.is_dedicated_agent() {
        // Worth saying out loud every boot: in session mode the model on the
        // other end of the pipe holds whatever the operator holds, which for a
        // `pnm` admin login is everything.
        tracing::warn!(
            mode = mode.label(),
            "this bridge holds an operator credential, not a scoped agent identity — every tool \
             runs with the operator's role and ACL. See docs/02-vta/vta-mcp.md for the \
             least-privilege setup."
        );
    }

    // Connect, but never let a failed connect stop the server from serving.
    // An MCP server that exits before speaking the protocol shows up in the
    // host as *no tools at all*, so the operator gets an empty tool list and no
    // explanation. Degraded mode keeps `vta_status` answering.
    let attached = match connect.connect().await {
        Ok(client) => attach(client, &args).await,
        Err(e) => Err(format!("connecting to VTA ({}): {e}", mode.label())),
    };
    let (bridge, session) = match attached {
        Ok(agent) => {
            tracing::info!("connected to VTA; serving MCP over stdio");
            (
                VtaMcp::new(agent.clone(), holder, identity, guard, recorder),
                Some(agent),
            )
        }
        Err(message) => {
            tracing::error!(error = %message, "serving in degraded mode — tools will report this");
            (
                VtaMcp::degraded(message, holder, identity, guard, recorder),
                None,
            )
        }
    };
    serve(bridge, session).await
}

/// Serve MCP over stdio until the host disconnects, then tear the DIDComm
/// session down.
///
/// The teardown is why `session` is passed separately: a DIDComm `VtaClient`
/// owns a live, auto-reconnecting mediator socket that `Drop` cannot close, so
/// leaking it trips a debug-assert and duels the mediator on reconnect. Serve
/// and wait, then `shutdown()` unconditionally (idempotent, a no-op for
/// REST/token clients) *before* propagating any error — a bare `?` on
/// `waiting()` would skip the cleanup on the common EOF/disconnect path.
async fn serve(bridge: VtaMcp, session: Option<Arc<AgentSession>>) -> anyhow::Result<()> {
    let served = async {
        let service = bridge.serve(stdio()).await?;
        service.waiting().await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Some(agent) = session {
        agent.shutdown().await;
    }
    served
}

/// Wrap the connected client in an `AgentSession` — the unified handle the MCP
/// tools route through. Optionally enroll as a managed device first (one-shot,
/// before serving — never concurrently with tool RPCs on a DIDComm session).
///
/// A failed enrolment is returned, not logged and shrugged off. The operator
/// asked for the bridge to be revocable through `pnm device disable`; serving
/// anyway would hand them a bridge that quietly is not.
async fn attach(client: VtaClient, args: &Args) -> Result<Arc<AgentSession>, String> {
    let agent = AgentSession::from_client(client, AgentConfig::for_attach(&args.device_name));
    if args.enroll
        && let Err(e) = agent.ensure_enrolled().await
    {
        // Tear the session down before returning. The degraded path drops this
        // `AgentSession`, and a dropped DIDComm client leaves a live,
        // auto-reconnecting mediator socket behind — one duelling socket per
        // start, holding the mediator's one-per-DID slot.
        agent.shutdown().await;
        return Err(format!(
            "enrolling as device '{}': {e}. The bridge asked to be revocable via \
             `pnm device disable`, so it will not serve without that binding — fix the \
             enrolment or drop --enroll.",
            args.device_name
        ));
    }
    if args.enroll {
        tracing::info!(device = %args.device_name, "vta-mcp enrolled as a managed device");
    }
    Ok(Arc::new(agent))
}

/// Optional holder identity for the `issue_vp` tool (signs presentations
/// locally; the key never crosses MCP).
fn holder_identity(args: &Args) -> Option<Arc<server::HolderIdentity>> {
    match (&args.holder_did, &args.holder_key) {
        (Some(did), Some(key)) => {
            tracing::info!(%did, "issue_vp enabled with configured holder identity");
            Some(Arc::new(server::HolderIdentity {
                did: did.clone(),
                vm_fragment: args.holder_vm_fragment.clone(),
                key_multibase: key.clone(),
            }))
        }
        _ => None,
    }
}

/// What the bridge will report about itself, resolved before connecting so it
/// is available even when the connect fails.
fn identity_of(args: &Args, mode: &ConnectMode) -> BridgeIdentity {
    let (agent_did, mediator_did) = match mode {
        ConnectMode::DidWebvhBundle {
            agent_did,
            mediator_did,
        }
        | ConnectMode::DidKey {
            agent_did,
            mediator_did,
        } => (Some(agent_did.clone()), Some(mediator_did.clone())),
        _ => (None, args.mediator_did.clone()),
    };
    BridgeIdentity {
        mode: mode.label().to_string(),
        agent_did,
        vta_did: args.vta_did.clone(),
        mediator_did,
        dedicated_agent: mode.is_dedicated_agent(),
    }
}

/// Warn when key material arrived as a command-line argument.
///
/// `/proc/<pid>/cmdline` and `ps` are readable by other processes on the same
/// machine; the environment is not, on any platform this runs on. The flags
/// stay supported — an operator scripting a one-off should not have to export
/// variables — but they should know.
fn warn_about_argv_secrets() {
    const SECRET_FLAGS: &[&str] = &["--agent-key", "--holder-key", "--agent-secrets"];
    let args: Vec<String> = std::env::args().collect();
    for flag in SECRET_FLAGS {
        if args
            .iter()
            .any(|a| a == flag || a.starts_with(&format!("{flag}=")))
        {
            tracing::warn!(
                flag,
                "key material passed as a command-line argument is visible to every process on \
                 this machine (ps / /proc/<pid>/cmdline) — prefer the matching VTA_MCP_* \
                 environment variable, or a file path for --agent-secrets"
            );
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn the_default_policy_is_confirm_destructive_and_nothing_else() {
        let a = args();
        assert!(!a.read_only);
        assert!(a.allow.is_empty());
        assert!(a.deny.is_empty());
        assert_eq!(
            ConfirmLevel::parse(&a.confirm).unwrap(),
            ConfirmLevel::Destructive
        );
    }

    #[test]
    fn allow_and_deny_accept_repeated_and_comma_separated_values() {
        let a = Args::parse_from([
            "vta-mcp",
            "--allow",
            "vta/memory/*",
            "--allow",
            "acl/list",
            "--deny",
            "vta/seeds/*,vta/backup/*",
        ]);
        assert_eq!(a.allow, ["vta/memory/*", "acl/list"]);
        assert_eq!(a.deny, ["vta/seeds/*", "vta/backup/*"]);
    }

    #[test]
    fn identity_carries_the_agent_did_in_didcomm_modes() {
        let mut a = args();
        a.agent_did = Some("did:key:zAgent".into());
        a.agent_key = Some("zKey".into());
        a.vta_did = Some("did:webvh:example.com:vta".into());
        a.mediator_did = Some("did:key:zMed".into());
        let mode = agent_connect_from(&a).mode().unwrap();
        let identity = identity_of(&a, &mode);
        assert_eq!(identity.agent_did.as_deref(), Some("did:key:zAgent"));
        assert_eq!(
            identity.vta_did.as_deref(),
            Some("did:webvh:example.com:vta")
        );
        assert!(identity.dedicated_agent);
    }

    #[test]
    fn session_mode_is_not_a_dedicated_agent() {
        let mut a = args();
        a.vta = Some("my-vta".into());
        let mut connect = agent_connect_from(&a);
        connect.token = None;
        let mode = connect.mode().unwrap();
        // The fact `--enroll` is refused on, and the startup warning fires on.
        assert!(!identity_of(&a, &mode).dedicated_agent);
    }
}
