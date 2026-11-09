//! `--listen`: one bridge process serving every MCP host on the machine over
//! loopback HTTP (MCP's streamable HTTP transport), in place of a stdio bridge
//! per host.
//!
//! ## Why
//!
//! A bridge holds a mediator session as its identity, and the mediator permits
//! one websocket per DID. Two stdio bridges on one key — two assistant
//! sessions — evict each other's socket on every reconnect, and a reply the
//! mediator flushes onto the other process's socket is deleted once written,
//! so the call that was waiting for it never gets it. One process holding one
//! session serves them all instead; each MCP session gets its own clone of the
//! bridge, so an approval (elicitation) goes back to the host that made the
//! call.
//!
//! ## What guards it
//!
//! The endpoint speaks with the bridge's identity — possibly an
//! administrator's delegation, or an operator's login — so it is served to
//! this machine's own user and nobody else. None of these can be turned off:
//!
//! - **Loopback only.** [`check_loopback`] refuses any other address before
//!   anything binds.
//! - **A bearer token on every request**, compared in constant time
//!   ([`require_bearer`]). From the bridge's `*_LISTEN_TOKEN` variable, or the
//!   owner-only file `listen-token` in its state directory, created on first
//!   use and refused if anyone but its owner can read it ([`load_token`]).
//!   Another local user can reach a loopback port; they cannot read that file.
//! - **No browsers.** A request carrying an `Origin` header is refused and the
//!   `Host` header must name a loopback host, so a web page cannot reach the
//!   endpoint by DNS rebinding (rmcp's own checks, both enforced here).
//!
//! A bridge served this way must also hold its hosts to a protocol version
//! that can ask the human ([`supported_protocol_versions`]).

use std::borrow::Cow;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rmcp::ServerHandler;
use rmcp::model::ProtocolVersion;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;

/// The token file's name, in the bridge's state directory.
pub const TOKEN_FILE: &str = "listen-token";

/// The shortest token accepted: 32 characters. A generated one is 64 hex
/// characters (256 bits).
pub const MIN_TOKEN_LEN: usize = 32;

/// The path MCP is served at.
pub const MCP_PATH: &str = "/mcp";

/// Which bridge is listening: its name (in messages and the 401 body) and the
/// environment variables it reads.
#[derive(Debug, Clone, Copy)]
pub struct Bridge {
    /// `vtc-mcp`, `vta-mcp`.
    pub name: &'static str,
    /// The variable a token can be supplied in: `VTC_MCP_LISTEN_TOKEN`.
    pub token_env: &'static str,
    /// The variable that overrides the state directory: `VTC_MCP_STATE_DIR`.
    pub state_dir_env: &'static str,
}

impl Bridge {
    /// The bridge's local state directory: its `*_STATE_DIR`, else
    /// `$XDG_STATE_HOME/<name>`, else `~/.local/state/<name>`. `None` when none
    /// of them is set.
    pub fn state_dir(&self) -> Option<PathBuf> {
        let env = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        env(self.state_dir_env)
            .or_else(|| env("XDG_STATE_HOME").map(|d| d.join(self.name)))
            .or_else(|| env("HOME").map(|h| h.join(".local/state").join(self.name)))
    }
}

/// How a bridge serves MCP: to the one host that started it, or with
/// `--listen` to every host on the machine.
pub enum Serving {
    Stdio,
    Http { addr: SocketAddr, token: String },
}

impl Serving {
    /// From the bridge's `--listen` value, settled before anything connects: a
    /// listen address or token that cannot be used is a policy failure, and a
    /// bridge does not start under a policy the operator did not ask for.
    pub fn from_listen(bridge: &Bridge, listen: Option<SocketAddr>) -> Result<Self, String> {
        let Some(addr) = listen else {
            return Ok(Self::Stdio);
        };
        check_loopback(addr)?;
        let state_dir = bridge.state_dir();
        let (token, source) = load_token(
            bridge,
            std::env::var(bridge.token_env).ok(),
            state_dir.as_deref(),
        )?;
        tracing::info!(token = %source, "listen token loaded");
        Ok(Self::Http { addr, token })
    }

    /// `stdio`, or the URL the hosts connect to.
    pub fn label(&self) -> String {
        match self {
            Self::Stdio => "stdio".into(),
            Self::Http { addr, .. } => format!("http://{addr}{MCP_PATH}"),
        }
    }
}

/// The MCP protocol versions a bridge that asks the human may serve: up to
/// `2025-11-25`, never `2026-07-28`.
///
/// A bridge's confirmation (`--confirm`) is a server-to-client elicitation
/// request, which `2026-07-28` forbids: rmcp serves a host that negotiates it
/// statelessly, with no client capabilities, so every confirmation would be
/// refused as "this host cannot ask you". Refused with this list instead, the
/// host falls back to `initialize` and keeps elicitation — observed with
/// Claude Code, which probes with `2026-07-28` and then initializes at
/// `2025-11-25`. Return this from `ServerHandler::supported_protocol_versions`.
/// Lift it only once confirmation is answered with an `InputRequiredResult`
/// that the hosts in use are known to handle.
pub fn supported_protocol_versions() -> Cow<'static, [ProtocolVersion]> {
    Cow::Borrowed(ProtocolVersion::known_up_to(&ProtocolVersion::V_2025_11_25))
}

/// Refuse any address that is not loopback. The endpoint carries the bridge's
/// standing, so it is never offered to the network.
pub fn check_loopback(addr: SocketAddr) -> Result<(), String> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(format!(
            "--listen {addr}: only a loopback address is served (127.0.0.1 or ::1) — the \
             endpoint speaks with this bridge's identity, so it is never offered to the network"
        ))
    }
}

/// Where the token came from, for the startup log (never the token itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSource {
    /// The bridge's `*_LISTEN_TOKEN` variable.
    Env(&'static str),
    File(PathBuf),
    Generated(PathBuf),
}

impl std::fmt::Display for TokenSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Env(var) => write!(f, "${var}"),
            Self::File(p) => write!(f, "{}", p.display()),
            Self::Generated(p) => write!(f, "{} (generated)", p.display()),
        }
    }
}

/// The bearer token every request must carry: `env` (the value of the
/// bridge's token variable) when set, else the token file in `state_dir`,
/// generated and written owner-only when absent.
pub fn load_token(
    bridge: &Bridge,
    env: Option<String>,
    state_dir: Option<&Path>,
) -> Result<(String, TokenSource), String> {
    if let Some(token) = env.map(|t| t.trim().to_string()).filter(|t| !t.is_empty()) {
        check_token(&token, &format!("${}", bridge.token_env))?;
        return Ok((token, TokenSource::Env(bridge.token_env)));
    }
    let dir = state_dir.ok_or_else(|| {
        format!(
            "--listen needs a bearer token: set {}, or {} (or HOME) so the bridge can keep one \
             in its state directory",
            bridge.token_env, bridge.state_dir_env
        )
    })?;
    let path = dir.join(TOKEN_FILE);
    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            check_owner_only(&path)?;
            let token = contents.trim().to_string();
            check_token(&token, &path.display().to_string())?;
            Ok((token, TokenSource::File(path)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let token = generate_token()?;
            write_owner_only(&path, format!("{token}\n").as_bytes())
                .map_err(|e| format!("writing the listen token to {}: {e}", path.display()))?;
            Ok((token, TokenSource::Generated(path)))
        }
        Err(e) => Err(format!("reading the listen token {}: {e}", path.display())),
    }
}

fn check_token(token: &str, source: &str) -> Result<(), String> {
    if token.len() < MIN_TOKEN_LEN {
        return Err(format!(
            "the listen token from {source} is {} characters; at least {MIN_TOKEN_LEN} are needed",
            token.len()
        ));
    }
    if !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "the listen token from {source} must be printable ASCII with no spaces, as it is \
             sent in an HTTP header"
        ));
    }
    Ok(())
}

/// A token file anyone but its owner can read is a token other users hold.
#[cfg(unix)]
fn check_owner_only(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(|e| format!("reading {}: {e}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "the listen token {} is readable by others (mode {:o}); run `chmod 600` on it, or \
             delete it and a new one is generated",
            path.display(),
            mode & 0o777
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owner_only(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn generate_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("CSPRNG failed: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Write `bytes` to `path` readable by its owner only, through a temporary
/// file beside it so a reader never sees half a file.
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

/// The HTTP application: MCP at [`MCP_PATH`], every request behind the token.
/// Each MCP session the hosts open is served by its own clone of `service`,
/// which shares whatever the bridge keeps behind `Arc`s — its node session,
/// guard and recorder.
pub fn router<S>(
    bridge: &Bridge,
    service: S,
    token: Arc<str>,
    cancel: CancellationToken,
) -> axum::Router
where
    S: ServerHandler + Clone + Send + Sync + 'static,
{
    // Loopback hosts only (rmcp's default list), and no `Origin` at all: an
    // MCP host sends none, a browser always does.
    let config = StreamableHttpServerConfig::default()
        .with_cancellation_token(cancel)
        .enforce_origin_validation();
    let http = StreamableHttpService::new(
        move || Ok(service.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let gate = Gate {
        token,
        refusal: format!(
            "{}: a bearer token is required (Authorization: Bearer <token>)",
            bridge.name
        )
        .into(),
    };
    axum::Router::new()
        .nest_service(MCP_PATH, http)
        .layer(axum::middleware::from_fn_with_state(gate, require_bearer))
}

#[derive(Clone)]
struct Gate {
    token: Arc<str>,
    refusal: Arc<str>,
}

/// Admit a request only with `Authorization: Bearer <token>`.
async fn require_bearer(State(gate): State<Gate>, request: Request, next: Next) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    let admitted = presented.is_some_and(|p| bool::from(p.as_bytes().ct_eq(gate.token.as_bytes())));
    if admitted {
        return next.run(request).await;
    }
    let mut response = (StatusCode::UNAUTHORIZED, gate.refusal.to_string()).into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// Serve `service` at `http://<addr>/mcp` until SIGINT or SIGTERM, then close
/// every MCP session and return; the caller closes its node session after.
pub async fn serve<S>(
    bridge: &Bridge,
    service: S,
    addr: SocketAddr,
    token: String,
) -> std::io::Result<()>
where
    S: ServerHandler + Clone + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| std::io::Error::new(e.kind(), format!("binding --listen {addr}: {e}")))?;
    let bound = listener.local_addr()?;
    tracing::info!(url = %format!("http://{bound}{MCP_PATH}"), "serving MCP over loopback HTTP");
    let cancel = CancellationToken::new();
    let app = router(bridge, service, Arc::from(token), cancel.clone());
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            tracing::info!("shutting down: closing every MCP session");
            cancel.cancel();
        })
        .await
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        ) {
            Ok(term) => term,
            Err(e) => {
                tracing::warn!(error = %e, "cannot watch SIGTERM; only Ctrl-C stops the bridge");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BRIDGE: Bridge = Bridge {
        name: "test-mcp",
        token_env: "TEST_MCP_LISTEN_TOKEN",
        state_dir_env: "TEST_MCP_STATE_DIR",
    };

    #[test]
    fn only_loopback_is_served() {
        assert!(check_loopback("127.0.0.1:7465".parse().unwrap()).is_ok());
        assert!(check_loopback("[::1]:7465".parse().unwrap()).is_ok());
        for addr in ["0.0.0.0:7465", "192.168.1.10:7465", "[::]:7465"] {
            let err = check_loopback(addr.parse().unwrap()).unwrap_err();
            assert!(err.contains("only a loopback address"), "{addr}: {err}");
        }
    }

    #[test]
    fn a_token_is_generated_owner_only_and_then_reused() {
        let dir = tempfile::tempdir().unwrap();
        let (first, source) = load_token(&BRIDGE, None, Some(dir.path())).unwrap();
        assert_eq!(source, TokenSource::Generated(dir.path().join(TOKEN_FILE)));
        assert_eq!(first.len(), 64);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(TOKEN_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let (again, source) = load_token(&BRIDGE, None, Some(dir.path())).unwrap();
        assert_eq!(again, first);
        assert_eq!(source, TokenSource::File(dir.path().join(TOKEN_FILE)));
    }

    #[cfg(unix)]
    #[test]
    fn a_token_file_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        load_token(&BRIDGE, None, Some(dir.path())).unwrap();
        let path = dir.path().join(TOKEN_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_token(&BRIDGE, None, Some(dir.path())).unwrap_err();
        assert!(err.contains("readable by others"), "{err}");
    }

    #[test]
    fn the_environment_wins_and_a_short_token_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let long = "x".repeat(40);
        let (token, source) = load_token(&BRIDGE, Some(long.clone()), Some(dir.path())).unwrap();
        assert_eq!((token, source), (long, TokenSource::Env(BRIDGE.token_env)));
        assert!(
            !dir.path().join(TOKEN_FILE).exists(),
            "no file when the env supplies one"
        );
        let err = load_token(&BRIDGE, Some("short".into()), Some(dir.path())).unwrap_err();
        assert!(err.contains("at least 32"), "{err}");
        let err = load_token(&BRIDGE, None, None).unwrap_err();
        assert!(
            err.contains(BRIDGE.token_env) && err.contains(BRIDGE.state_dir_env),
            "{err}"
        );
    }

    #[test]
    fn the_served_versions_stop_before_2026_07_28() {
        let versions = supported_protocol_versions();
        assert!(versions.contains(&ProtocolVersion::V_2025_11_25));
        assert!(!versions.contains(&ProtocolVersion::V_2026_07_28));
    }

    /// The HTTP surface end to end, as an MCP host drives it, against the
    /// smallest server that holds its hosts to [`supported_protocol_versions`].
    mod http {
        use super::*;
        use rmcp::model::{ServerCapabilities, ServerConfig};
        use serde_json::{Value, json};

        const TOKEN: &str = "0123456789abcdef0123456789abcdef-test";

        #[derive(Clone)]
        struct Minimal;

        impl ServerHandler for Minimal {
            fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
                super::supported_protocol_versions()
            }
            fn get_info(&self) -> ServerConfig {
                ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            }
        }

        async fn spawn() -> (String, CancellationToken) {
            let cancel = CancellationToken::new();
            let app = router(&BRIDGE, Minimal, Arc::from(TOKEN), cancel.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}{MCP_PATH}", listener.local_addr().unwrap());
            let stop = cancel.clone();
            tokio::spawn(async move {
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move { stop.cancelled().await })
                    .await
                    .unwrap();
            });
            (url, cancel)
        }

        fn post(url: &str, body: &Value) -> reqwest::RequestBuilder {
            reqwest::Client::new()
                .post(url)
                .header("accept", "application/json, text/event-stream")
                .json(body)
        }

        fn initialize(version: &str) -> Value {
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": version,
                    "capabilities": { "elicitation": {} },
                    "clientInfo": { "name": "listen-test", "version": "0" }
                }
            })
        }

        /// The JSON-RPC message in a response, sent as JSON or as an SSE event
        /// (a stream opens with an empty priming event).
        async fn message(response: reqwest::Response) -> Value {
            let text = response.text().await.unwrap();
            let json = text
                .lines()
                .filter_map(|l| l.strip_prefix("data:"))
                .map(str::trim)
                .find(|d| !d.is_empty())
                .unwrap_or(&text);
            serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}: {text}"))
        }

        #[tokio::test]
        async fn a_request_without_the_token_is_refused() {
            let (url, cancel) = spawn().await;
            let init = initialize("2025-11-25");
            let none = post(&url, &init).send().await.unwrap();
            assert_eq!(none.status(), 401);
            assert_eq!(none.headers()["www-authenticate"], "Bearer");
            assert!(none.text().await.unwrap().starts_with("test-mcp:"));
            let wrong = post(&url, &init)
                .bearer_auth("0123456789abcdef0123456789abcdef-nope")
                .send()
                .await
                .unwrap();
            assert_eq!(wrong.status(), 401);
            let basic = post(&url, &init)
                .basic_auth("user", Some(TOKEN))
                .send()
                .await
                .unwrap();
            assert_eq!(basic.status(), 401);
            cancel.cancel();
        }

        #[tokio::test]
        async fn a_browser_request_is_refused_even_with_the_token() {
            let (url, cancel) = spawn().await;
            let response = post(&url, &initialize("2025-11-25"))
                .bearer_auth(TOKEN)
                .header("origin", "https://evil.example")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 403);
            cancel.cancel();
        }

        #[tokio::test]
        async fn several_hosts_get_their_own_sessions() {
            let (url, cancel) = spawn().await;
            let mut sessions = Vec::new();
            for _ in 0..2 {
                let response = post(&url, &initialize("2025-11-25"))
                    .bearer_auth(TOKEN)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), 200);
                sessions.push(
                    response.headers()["mcp-session-id"]
                        .to_str()
                        .unwrap()
                        .to_string(),
                );
                let init = message(response).await;
                assert_eq!(init["result"]["protocolVersion"], "2025-11-25", "{init}");
            }
            assert_ne!(sessions[0], sessions[1]);
            cancel.cancel();
        }

        /// A host speaking `2026-07-28` — no `initialize`, the version in each
        /// request's `_meta` — is refused with the versions served, so it
        /// falls back to `initialize` and keeps elicitation.
        #[tokio::test]
        async fn a_host_speaking_2026_07_28_is_sent_back_to_a_version_that_can_ask() {
            let (url, cancel) = spawn().await;
            let stateless = json!({
                "jsonrpc": "2.0", "id": 7, "method": "tools/list",
                "params": { "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": { "elicitation": {} },
                    "io.modelcontextprotocol/clientInfo": { "name": "host", "version": "0" }
                } }
            });
            let response = post(&url, &stateless)
                .bearer_auth(TOKEN)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/list")
                .send()
                .await
                .unwrap();
            let refusal = message(response).await;
            assert_eq!(
                refusal["error"]["message"], "Unsupported protocol version",
                "{refusal}"
            );
            let supported = refusal["error"]["data"]["supported"].to_string();
            assert!(supported.contains("2025-11-25"), "{supported}");
            assert!(!supported.contains("2026-07-28"), "{supported}");
            cancel.cancel();
        }
    }
}
