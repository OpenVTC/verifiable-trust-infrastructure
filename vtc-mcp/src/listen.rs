//! `--listen`: one bridge serving every MCP host on the machine, over loopback
//! HTTP (MCP's streamable HTTP transport), in place of one stdio bridge per host.
//!
//! ## Why
//!
//! The mediator permits one websocket per DID. Two stdio bridges started with
//! the same agent key — two assistant sessions — evict each other's socket on
//! every reconnect, and a reply the mediator flushes onto the other process's
//! socket is deleted once written, so the call that was waiting for it never
//! gets it. One process holding one session serves them all instead: the
//! session already routes each reply to the request waiting for it, however
//! many are in flight, and each MCP session gets its own clone of the bridge,
//! so an approval (elicitation) goes back to the host that made the call.
//!
//! ## What guards it
//!
//! The endpoint speaks with this bridge's identity — for an administrator's
//! delegation, the administrator's standing — so it is served to this machine's
//! own user and nobody else:
//!
//! - **Loopback only.** [`check_loopback`] refuses any other address before
//!   anything binds; there is no flag to widen it.
//! - **A bearer token on every request**, compared in constant time
//!   ([`require_bearer`]). From `VTC_MCP_LISTEN_TOKEN`, or the owner-only file
//!   `listen-token` in the state directory, created on first use and refused if
//!   anyone but its owner can read it ([`load_token`]). Another local user can
//!   reach a loopback port; they cannot read that file.
//! - **No browsers.** A request carrying an `Origin` header is refused, and the
//!   `Host` header must name a loopback host, so a web page cannot reach the
//!   endpoint by DNS rebinding (rmcp's own checks, both enforced here).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;

use crate::server::VtcMcp;

/// The environment variable a token can be supplied in, in place of the file.
pub const TOKEN_ENV: &str = "VTC_MCP_LISTEN_TOKEN";

/// The token file's name, in the state directory.
const TOKEN_FILE: &str = "listen-token";

/// The shortest token accepted: 32 characters. A generated one is 64 hex
/// characters (256 bits).
const MIN_TOKEN_LEN: usize = 32;

/// The path MCP is served at.
pub const MCP_PATH: &str = "/mcp";

/// Refuse any address that is not loopback. The endpoint carries this bridge's
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
    Env,
    File(PathBuf),
    Generated(PathBuf),
}

impl std::fmt::Display for TokenSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Env => write!(f, "${TOKEN_ENV}"),
            Self::File(p) => write!(f, "{}", p.display()),
            Self::Generated(p) => write!(f, "{} (generated)", p.display()),
        }
    }
}

/// The bearer token every request must carry: `env` when set, else the token
/// file in `state_dir`, generated and written owner-only when absent.
pub fn load_token(
    env: Option<String>,
    state_dir: Option<&Path>,
) -> Result<(String, TokenSource), String> {
    if let Some(token) = env.map(|t| t.trim().to_string()).filter(|t| !t.is_empty()) {
        check_token(&token, &format!("${TOKEN_ENV}"))?;
        return Ok((token, TokenSource::Env));
    }
    let dir = state_dir.ok_or_else(|| {
        format!(
            "--listen needs a bearer token: set {TOKEN_ENV}, or VTC_MCP_STATE_DIR (or HOME) so \
             the bridge can keep one in its state directory"
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
            crate::key_reuse::write_owner_only(&path, format!("{token}\n").as_bytes())
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

/// The HTTP application: MCP at [`MCP_PATH`], every request behind the token.
/// Each MCP session the hosts open is served by its own clone of `bridge`;
/// the clones share the community session, guard, recorder and sign-in state.
pub fn router(bridge: VtcMcp, token: Arc<str>, cancel: CancellationToken) -> axum::Router {
    // Loopback hosts only (rmcp's default list), and no `Origin` at all: an
    // MCP host sends none, a browser always does.
    let config = StreamableHttpServerConfig::default()
        .with_cancellation_token(cancel)
        .enforce_origin_validation();
    let service = StreamableHttpService::new(
        move || Ok(bridge.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    axum::Router::new()
        .nest_service(MCP_PATH, service)
        .layer(axum::middleware::from_fn_with_state(token, require_bearer))
}

/// Admit a request only with `Authorization: Bearer <token>`.
async fn require_bearer(State(token): State<Arc<str>>, request: Request, next: Next) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    let admitted = presented.is_some_and(|p| bool::from(p.as_bytes().ct_eq(token.as_bytes())));
    if admitted {
        return next.run(request).await;
    }
    let mut response = (
        StatusCode::UNAUTHORIZED,
        "vtc-mcp: a bearer token is required (Authorization: Bearer <token>)",
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// Serve `bridge` at `http://<addr>/mcp` until SIGINT or SIGTERM.
pub async fn serve(bridge: VtcMcp, addr: SocketAddr, token: String) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("binding --listen {addr}: {e}"))?;
    let bound = listener.local_addr()?;
    tracing::info!(url = %format!("http://{bound}{MCP_PATH}"), "serving MCP over loopback HTTP");
    let cancel = CancellationToken::new();
    let app = router(bridge, Arc::from(token), cancel.clone());
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            tracing::info!("shutting down: closing every MCP session");
            cancel.cancel();
        })
        .await?;
    Ok(())
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
        let (first, source) = load_token(None, Some(dir.path())).unwrap();
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
        let (again, source) = load_token(None, Some(dir.path())).unwrap();
        assert_eq!(again, first);
        assert_eq!(source, TokenSource::File(dir.path().join(TOKEN_FILE)));
    }

    #[cfg(unix)]
    #[test]
    fn a_token_file_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        load_token(None, Some(dir.path())).unwrap();
        let path = dir.path().join(TOKEN_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_token(None, Some(dir.path())).unwrap_err();
        assert!(err.contains("readable by others"), "{err}");
    }

    #[test]
    fn the_environment_wins_and_a_short_token_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let long = "x".repeat(40);
        let (token, source) = load_token(Some(long.clone()), Some(dir.path())).unwrap();
        assert_eq!((token, source), (long, TokenSource::Env));
        assert!(
            !dir.path().join(TOKEN_FILE).exists(),
            "no file when the env supplies one"
        );
        let err = load_token(Some("short".into()), Some(dir.path())).unwrap_err();
        assert!(err.contains("at least 32"), "{err}");
        assert!(load_token(None, None).unwrap_err().contains(TOKEN_ENV));
    }

    /// The HTTP surface end to end, as an MCP host drives it: the token gate,
    /// the browser gate, and several MCP sessions on one bridge. The bridge is
    /// degraded (no community), which is enough — what is under test is who
    /// reaches it and how many at once, not what it says.
    mod http {
        use super::*;
        use crate::server::BridgeIdentity;
        use serde_json::{Value, json};
        use vti_mcp_common::guard::{ConfirmLevel, Guard};
        use vti_mcp_common::observability::Recorder;

        const TOKEN: &str = "0123456789abcdef0123456789abcdef-test";

        async fn spawn() -> (String, CancellationToken) {
            let bridge = VtcMcp::degraded(
                "no community in this test".into(),
                BridgeIdentity {
                    mode: "unconfigured".into(),
                    agent_did: None,
                    vtc_did: None,
                    transport_choice: "auto".into(),
                    reuse_warning: None,
                },
                Guard {
                    read_only: true,
                    allow: vec![],
                    deny: vec![],
                    confirm: ConfirmLevel::parse("destructive").unwrap(),
                    node: "VTC",
                },
                Arc::new(Recorder::default()),
            );
            let cancel = CancellationToken::new();
            let app = router(bridge, Arc::from(TOKEN), cancel.clone());
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

        fn initialize() -> Value {
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "listen-test", "version": "0" }
                }
            })
        }

        /// The JSON-RPC message in a response, whether sent as JSON or as one
        /// server-sent event.
        async fn message(response: reqwest::Response) -> Value {
            let text = response.text().await.unwrap();
            // A stream opens with an empty priming event; the message is the
            // first event that carries data.
            let json = text
                .lines()
                .filter_map(|l| l.strip_prefix("data:"))
                .map(str::trim)
                .find(|d| !d.is_empty())
                .unwrap_or(&text);
            serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}: {text}"))
        }

        /// Open one MCP session and return its id.
        async fn open_session(url: &str) -> String {
            let response = post(url, &initialize())
                .bearer_auth(TOKEN)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            let session = response.headers()["mcp-session-id"]
                .to_str()
                .unwrap()
                .to_string();
            let init = message(response).await;
            assert_eq!(init["result"]["serverInfo"]["name"], "vtc-mcp", "{init}");
            let ack = post(
                url,
                &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            )
            .bearer_auth(TOKEN)
            .header("mcp-session-id", &session)
            .send()
            .await
            .unwrap();
            assert!(ack.status().is_success(), "{}", ack.status());
            session
        }

        #[tokio::test]
        async fn a_request_without_the_token_is_refused() {
            let (url, cancel) = spawn().await;
            let none = post(&url, &initialize()).send().await.unwrap();
            assert_eq!(none.status(), 401);
            assert_eq!(none.headers()["www-authenticate"], "Bearer");
            let wrong = post(&url, &initialize())
                .bearer_auth("0123456789abcdef0123456789abcdef-nope")
                .send()
                .await
                .unwrap();
            assert_eq!(wrong.status(), 401);
            let basic = post(&url, &initialize())
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
            let response = post(&url, &initialize())
                .bearer_auth(TOKEN)
                .header("origin", "https://evil.example")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 403);
            cancel.cancel();
        }

        #[tokio::test]
        async fn several_hosts_share_one_bridge_each_in_its_own_session() {
            let (url, cancel) = spawn().await;
            let first = open_session(&url).await;
            let second = open_session(&url).await;
            assert_ne!(first, second, "each host gets its own MCP session");
            for session in [&first, &second] {
                let listed = post(
                    &url,
                    &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
                )
                .bearer_auth(TOKEN)
                .header("mcp-session-id", session)
                .send()
                .await
                .unwrap();
                assert_eq!(listed.status(), 200);
                let tools = message(listed).await;
                let names: Vec<&str> = tools["result"]["tools"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{tools}"))
                    .iter()
                    .filter_map(|t| t["name"].as_str())
                    .collect();
                assert!(names.contains(&"vtc_call"), "{names:?}");
            }
            cancel.cancel();
        }
    }
}
