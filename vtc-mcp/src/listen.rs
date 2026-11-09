//! `--listen` for this bridge: the shared listener in `vti_mcp_common::listen`
//! (loopback only, a bearer token, no browsers, the protocol versions a bridge
//! that asks the human may serve), named for `vtc-mcp`.
//!
//! The mediator holds one websocket per DID, so two stdio bridges on one agent
//! key fight over it; one `--listen` bridge serves every host on the machine
//! instead (design note D7).

use vti_mcp_common::listen::Bridge;

/// This bridge, as the shared listener names it.
pub const BRIDGE: Bridge = Bridge {
    name: "vtc-mcp",
    token_env_name: "VTC_MCP_LISTEN_TOKEN",
    state_dir_env: "VTC_MCP_STATE_DIR",
};

#[cfg(test)]
mod tests {
    use crate::server::VtcMcp;

    /// The bridge itself behind the shared listener: several hosts on one
    /// `VtcMcp`, and its hosts held to a version that can ask (the
    /// listener's own guarantees are tested in `vti-mcp-common`).
    mod http {
        use super::*;
        use crate::server::BridgeIdentity;
        use serde_json::{Value, json};
        use std::sync::Arc;
        use tokio_util::sync::CancellationToken;
        use vti_mcp_common::guard::{ConfirmLevel, Guard};
        use vti_mcp_common::listen::{self, MCP_PATH};
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
                    serving: "stdio".into(),
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
            let app = listen::router(
                &crate::listen::BRIDGE,
                bridge,
                Arc::from(TOKEN),
                cancel.clone(),
            );
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

            // The fallback: `initialize` at the newest version offered.
            let mut offer = initialize();
            offer["params"]["protocolVersion"] = json!("2025-11-25");
            let response = post(&url, &offer).bearer_auth(TOKEN).send().await.unwrap();
            assert!(
                response.headers().contains_key("mcp-session-id"),
                "a session, not stateless"
            );
            let init = message(response).await;
            assert_eq!(init["result"]["protocolVersion"], "2025-11-25", "{init}");
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
