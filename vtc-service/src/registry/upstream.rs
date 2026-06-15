//! `UpstreamRegistryClient` — production implementation of
//! [`TrustRegistryClient`] talking to a real upstream
//! `affinidi-trust-registry-rs` server.
//!
//! ## Transport split
//!
//! The upstream's HTTP surface exposes only TRQP queries
//! (`POST /recognition`, `POST /authorization`,
//! `GET /.well-known/did.json`). Record mutations go over
//! DIDComm against the upstream's `tr-admin/1.0/*` protocol
//! family.
//!
//! As-shipped status:
//!
//! - `health()` — live (HTTP probe against
//!   `GET /.well-known/did.json`); drives `registry_status`
//!   on the community profile (M3.2).
//! - `recognise()` — live (`POST /recognition` with the
//!   pinned TRQP v2.0 4-tuple); drives the cross-community
//!   session-mint path's recognition gate (M3.10 + the wire-
//!   shape pin follow-up).
//! - `publish_member()` / `delete_member()` / `read_member()`
//!   — scaffolded as "not yet wired"; return
//!   `RegistryError::Permanent` so consumers (the syncer task
//!   in M3.4) fail closed until the DIDComm transport lands.
//!
//! ## Why the write methods land as "not wired" first
//!
//! M3.2's load-bearing scope is the *registry_status*
//! surface — that needs only `health()`. The syncer (M3.4)
//! is the first real consumer of `publish_member` /
//! `delete_member`; the DIDComm send-and-wait plumbing lands
//! in the same PR so its failure paths are visible alongside
//! the call sites.

use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::messaging::ATM;
use async_trait::async_trait;
use reqwest::Client;
use tracing::{debug, warn};

use super::client::{RegistryError, TrustRegistryClient};
use super::model::RegistryRecord;

/// Configuration for the upstream HTTP transport.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Base URL of the upstream registry — e.g.
    /// `https://registry.example.com`. No trailing slash.
    pub base_url: String,
    /// Per-call HTTP timeout. Mirrors
    /// `RegistryConfig::http_timeout_seconds`.
    pub http_timeout: Duration,
    /// Local VTC's DID — used as the TRQP `authority_id` in
    /// recognition queries (we're the authority asking "do *I*
    /// recognise this peer?"). Sourced from `config.vtc_did`
    /// at boot. `None` when the VTC hasn't completed setup —
    /// recognition queries refuse with a clear error in that
    /// state rather than sending a malformed payload.
    pub authority_did: Option<String>,
}

/// Reqwest-backed client. Lazy field: the ATM handle is only
/// needed for the DIDComm write path. `None` until M3.4 wires
/// it in — at which point `publish_member` / `delete_member`
/// will dispatch real DIDComm messages.
pub struct UpstreamRegistryClient {
    http: Client,
    base_url: String,
    authority_did: Option<String>,
    /// ATM handle for DIDComm sends. `None` in M3.2; lands in
    /// M3.4 when the syncer needs the write path.
    #[allow(dead_code)]
    atm: Option<Arc<ATM>>,
}

impl std::fmt::Debug for UpstreamRegistryClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamRegistryClient")
            .field("base_url", &self.base_url)
            .field("atm_set", &self.atm.is_some())
            .finish()
    }
}

impl UpstreamRegistryClient {
    /// Build the client from config. Returns an `Err` if
    /// reqwest fails to construct (typically a misconfigured
    /// TLS backend on this platform).
    pub fn new(cfg: UpstreamConfig) -> Result<Self, RegistryError> {
        // Recognition answers are trusted; served over cleartext they're
        // spoofable by an on-path attacker. Require https for any real
        // (non-loopback) registry. Loopback http stays allowed for local
        // dev / tests, where there's no on-path attacker — the same
        // "localhost is a secure context" carve-out browsers make.
        validate_registry_scheme(&cfg.base_url)?;
        let http = Client::builder()
            .timeout(cfg.http_timeout)
            // No retry middleware here — the syncer's
            // exponential backoff handles retries at the
            // job-row level, which gives us restart
            // resilience for free. A retry-middleware here
            // would mask connection-pool failures.
            .build()
            .map_err(|e| RegistryError::Permanent(format!("reqwest client init: {e}")))?;
        Ok(Self {
            http,
            base_url: cfg.base_url.trim_end_matches('/').to_string(),
            authority_did: cfg.authority_did,
            atm: None,
        })
    }

    /// Inject the ATM handle for DIDComm writes. M3.4 calls
    /// this at boot once `init_auth` has produced the ATM.
    #[allow(dead_code)]
    pub fn with_atm(mut self, atm: Arc<ATM>) -> Self {
        self.atm = Some(atm);
        self
    }

    /// Classify a reqwest error into the workspace's error
    /// taxonomy. Connect / timeout / DNS errors are
    /// `Unreachable`; 5xx are `Transient`; 4xx are
    /// `Permanent`.
    fn classify_http_error(e: reqwest::Error) -> RegistryError {
        if e.is_timeout() {
            RegistryError::Unreachable(format!("timeout: {e}"))
        } else if e.is_connect() {
            RegistryError::Unreachable(format!("connect: {e}"))
        } else if let Some(s) = e.status() {
            if s.is_server_error() {
                RegistryError::Transient(format!("{s}: {e}"))
            } else {
                RegistryError::Permanent(format!("{s}: {e}"))
            }
        } else {
            RegistryError::Transient(format!("http: {e}"))
        }
    }
}

/// Reject a registry `base_url` that isn't `https://`, except a
/// loopback `http://` (local dev / tests). See [`UpstreamRegistryClient::new`].
fn validate_registry_scheme(base_url: &str) -> Result<(), RegistryError> {
    if base_url.starts_with("https://") {
        return Ok(());
    }
    if let Some(rest) = base_url.strip_prefix("http://") {
        // Host is the authority up to the first `/`, `:`, or `?`.
        let host = rest.split(['/', ':', '?']).next().unwrap_or("");
        if host == "localhost" || host == "127.0.0.1" || rest.starts_with("[::1]") {
            return Ok(());
        }
    }
    Err(RegistryError::Permanent(format!(
        "registry base_url must be https:// (got '{base_url}'); cleartext recognition is \
         spoofable by an on-path attacker. http:// is allowed only to loopback for local dev."
    )))
}

#[async_trait]
impl TrustRegistryClient for UpstreamRegistryClient {
    async fn publish_member(&self, _record: &RegistryRecord) -> Result<(), RegistryError> {
        // DIDComm transport lands in M3.4. Until then, the
        // syncer should not be dispatching against this
        // client — but if it does, fail closed loudly.
        warn!(
            "UpstreamRegistryClient.publish_member called before M3.4's DIDComm transport landed"
        );
        Err(RegistryError::Permanent(
            "publish_member is not yet implemented in M3.2 — DIDComm transport lands in M3.4"
                .into(),
        ))
    }

    async fn delete_member(&self, _member_did: &str) -> Result<(), RegistryError> {
        warn!("UpstreamRegistryClient.delete_member called before M3.4's DIDComm transport landed");
        Err(RegistryError::Permanent(
            "delete_member is not yet implemented in M3.2 — DIDComm transport lands in M3.4".into(),
        ))
    }

    async fn read_member(
        &self,
        _member_did: &str,
    ) -> Result<Option<RegistryRecord>, RegistryError> {
        // The upstream's TRQP recognition query takes a
        // 4-tuple (authority_id, entity_id, action, resource)
        // and the VTC needs to construct the right key shape
        // — that mapping lands in M3.10 alongside the
        // cross-community session-mint path.
        warn!("UpstreamRegistryClient.read_member called before M3.10's TRQP mapping landed");
        Err(RegistryError::Permanent(
            "read_member is not yet implemented in M3.2 — TRQP query mapping lands in M3.10".into(),
        ))
    }

    async fn recognise(&self, foreign_issuer_did: &str) -> Result<bool, RegistryError> {
        // TRQP `POST /recognition` per
        // `affinidi/affinidi-trust-registry-rs`:
        //
        // - Path: `/recognition` at server root (no API prefix).
        // - Body: `{ entity_id, authority_id, action, resource,
        //   context? }`, all snake_case strings; `context`
        //   optional/omitted.
        // - 200 → body carries `recognized: bool` (single
        //   tuple lookup — not an array). A `recognized: true`
        //   means the upstream confirms recognition.
        // - 404 → no record matches the 4-tuple. We map this
        //   to `Ok(false)` — that's the *clean* "not
        //   recognised" path, semantically identical to a
        //   stored record with `recognized: false`. Surfacing
        //   it as an error would force every caller to handle
        //   the same case twice.
        // - 400 → operator-side input is malformed. Maps to
        //   `Permanent` so the syncer flips the job to
        //   `Failed` immediately rather than retrying.
        // - 5xx / connect / DNS errors → `classify_http_error`
        //   (Transient / Unreachable).
        //
        // The recognition trust model:
        //   entity_id    = the peer community being checked
        //                  (`foreign_issuer_did`).
        //   authority_id = our own VTC's DID (we're the
        //                  authority who recognises peers).
        //   action       = `"recognise"`.
        //   resource     = `"trust-graph"` — the scope we're
        //                  asking about. Fixed string for
        //                  Phase 3; future PRs can promote to
        //                  a config knob if operators need
        //                  per-deployment scopes.
        let authority = self.authority_did.as_deref().ok_or_else(|| {
            RegistryError::Permanent(
                "authority_did not configured — cannot issue recognise query (set vtc_did in config)".into(),
            )
        })?;

        #[derive(serde::Serialize)]
        struct RecognitionRequest<'a> {
            entity_id: &'a str,
            authority_id: &'a str,
            action: &'static str,
            resource: &'static str,
        }
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct RecognitionResponse {
            recognized: bool,
            // The upstream response carries a handful of
            // additional fields (`entity_id`, `authority_id`,
            // `record_type`, `time_requested`, `time_evaluated`,
            // `message`, merged `context`). We deserialize only
            // `recognized` so any wire additions don't break
            // us. `#[serde(deny_unknown_fields)]` would be the
            // wrong call here — let the upstream evolve.
        }

        let url = format!("{}/recognition", self.base_url);
        let body = RecognitionRequest {
            entity_id: foreign_issuer_did,
            authority_id: authority,
            action: "recognise",
            resource: "trust-graph",
        };
        debug!(%url, entity = %foreign_issuer_did, authority = %authority, "trust-registry recognise");
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(Self::classify_http_error)?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if status.is_client_error() {
            // 400 / 401 / 403 — payload malformed or auth
            // surface changed. Operator intervention; don't
            // retry.
            return Err(RegistryError::Permanent(format!(
                "registry returned {status} for recognise"
            )));
        }
        if status.is_server_error() {
            return Err(RegistryError::Transient(format!(
                "registry returned {status} for recognise"
            )));
        }
        if !status.is_success() {
            return Err(RegistryError::Transient(format!(
                "unexpected status {status} for recognise"
            )));
        }
        let body: RecognitionResponse = resp
            .json()
            .await
            .map_err(|e| RegistryError::Transient(format!("parse recognise response: {e}")))?;
        Ok(body.recognized)
    }

    async fn health(&self) -> Result<(), RegistryError> {
        // `GET /.well-known/did.json` is the cheapest live
        // probe the upstream exposes. A 2xx confirms the
        // service is responding to requests; a 4xx still
        // counts as "reachable" (the upstream is up; the
        // resource is just missing — that's still a green
        // signal for connectivity).
        let url = format!("{}/.well-known/did.json", self.base_url);
        debug!(%url, "trust-registry health probe");
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(Self::classify_http_error)?;
        let status = resp.status();
        if status.is_success() || status.is_client_error() {
            // 2xx = OK. 4xx = upstream is up but the URL
            // isn't where we expected — still proves reachability.
            Ok(())
        } else if status.is_server_error() {
            Err(RegistryError::Transient(format!(
                "registry returned {status}"
            )))
        } else {
            Err(RegistryError::Transient(format!(
                "unexpected status {status}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    //! In-test axum servers stand in for a real
    //! `affinidi-trust-registry-rs` upstream. We bind to
    //! `127.0.0.1:0`, capture the port, and point the client
    //! at the resulting URL. No mocking dependencies — keeps
    //! the test surface honest about the wire format because
    //! reqwest serialises through the same codepath as
    //! production.

    use super::*;
    use axum::Json;
    use axum::Router;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::post;
    use serde_json::Value as JsonValue;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    /// Captured-payload type so tests can assert on the
    /// exact wire shape the client sent.
    #[derive(Debug, Clone, serde::Deserialize)]
    struct CapturedRequest {
        entity_id: String,
        authority_id: String,
        action: String,
        resource: String,
    }

    #[derive(Clone)]
    struct ServerState {
        captured: Arc<tokio::sync::Mutex<Option<CapturedRequest>>>,
        response: Arc<tokio::sync::Mutex<TestResponse>>,
    }

    #[derive(Clone, Debug)]
    enum TestResponse {
        Recognized(bool),
        NotFound,
        BadRequest,
        ServerError,
    }

    async fn recognition_handler(
        State(state): State<ServerState>,
        Json(body): Json<CapturedRequest>,
    ) -> (StatusCode, Json<JsonValue>) {
        *state.captured.lock().await = Some(body);
        match state.response.lock().await.clone() {
            TestResponse::Recognized(b) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "entity_id": "did:webvh:peer.example",
                    "authority_id": "did:webvh:vtc.example",
                    "action": "recognise",
                    "resource": "trust-graph",
                    "recognized": b,
                    "context": {},
                    "record_type": "recognition",
                    "time_requested": "2026-05-13T10:00:00Z",
                    "time_evaluated": "2026-05-13T10:00:00Z",
                    "message": "mock"
                })),
            ),
            TestResponse::NotFound => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "title": "not_found",
                    "type": "about:blank",
                    "code": 404
                })),
            ),
            TestResponse::BadRequest => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "title": "bad_request",
                    "type": "about:blank",
                    "code": 400
                })),
            ),
            TestResponse::ServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "title": "internal_error",
                    "type": "about:blank",
                    "code": 500
                })),
            ),
        }
    }

    /// Spin up the in-test server. Returns (base_url,
    /// captured-request handle, response-mode handle,
    /// shutdown-trigger).
    ///
    /// Shutdown trigger fires the oneshot to tear down the
    /// server cleanly at end-of-test — avoids leaking the
    /// background task across tests sharing a tokio runtime.
    async fn spawn_server(
        initial: TestResponse,
    ) -> (
        String,
        Arc<tokio::sync::Mutex<Option<CapturedRequest>>>,
        Arc<tokio::sync::Mutex<TestResponse>>,
        oneshot::Sender<()>,
    ) {
        let captured = Arc::new(tokio::sync::Mutex::new(None));
        let response = Arc::new(tokio::sync::Mutex::new(initial));
        let state = ServerState {
            captured: captured.clone(),
            response: response.clone(),
        };
        let app = Router::new()
            .route("/recognition", post(recognition_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        (format!("http://{addr}"), captured, response, shutdown_tx)
    }

    fn config_for(base_url: &str) -> UpstreamConfig {
        UpstreamConfig {
            base_url: base_url.to_string(),
            http_timeout: Duration::from_secs(2),
            authority_did: Some("did:webvh:vtc.example".into()),
        }
    }

    // ──────────────────────────────────────────────────────

    #[test]
    fn config_trims_trailing_slash() {
        let cfg = UpstreamConfig {
            base_url: "https://registry.example.com/".into(),
            http_timeout: Duration::from_secs(5),
            authority_did: Some("did:webvh:vtc.example".into()),
        };
        let c = UpstreamRegistryClient::new(cfg).unwrap();
        assert_eq!(c.base_url, "https://registry.example.com");
    }

    #[test]
    fn rejects_cleartext_registry_url() {
        // A public http:// registry is spoofable on-path — refuse at
        // construction.
        let err = UpstreamRegistryClient::new(config_for("http://registry.example.com"))
            .expect_err("cleartext public registry must be rejected");
        assert!(matches!(err, RegistryError::Permanent(_)), "got {err:?}");
        // https is fine.
        assert!(UpstreamRegistryClient::new(config_for("https://registry.example.com")).is_ok());
        // Loopback http stays allowed for local dev.
        assert!(UpstreamRegistryClient::new(config_for("http://127.0.0.1:8080")).is_ok());
        assert!(UpstreamRegistryClient::new(config_for("http://localhost:8080")).is_ok());
        assert!(UpstreamRegistryClient::new(config_for("http://[::1]:8080")).is_ok());
        // A host that merely starts with "localhost" is not loopback.
        assert!(UpstreamRegistryClient::new(config_for("http://localhost.evil.com")).is_err());
    }

    #[tokio::test]
    async fn health_against_unreachable_host_is_unreachable() {
        let cfg = UpstreamConfig {
            base_url: "http://127.0.0.1:1".into(),
            http_timeout: Duration::from_millis(200),
            authority_did: None,
        };
        let c = UpstreamRegistryClient::new(cfg).unwrap();
        let err = c.health().await.expect_err("should fail");
        assert!(
            err.is_retriable(),
            "connection refused is retriable: {err:?}"
        );
    }

    #[tokio::test]
    async fn publish_member_returns_permanent_until_m3_4() {
        let cfg = UpstreamConfig {
            base_url: "http://localhost:9999".into(),
            http_timeout: Duration::from_secs(1),
            authority_did: None,
        };
        let c = UpstreamRegistryClient::new(cfg).unwrap();
        let record = RegistryRecord::fresh_active("did:key:zMember");
        let err = c
            .publish_member(&record)
            .await
            .expect_err("M3.2 doesn't implement writes");
        assert!(matches!(err, RegistryError::Permanent(_)));
        assert!(!err.is_retriable());
    }

    #[tokio::test]
    async fn recognise_sends_canonical_four_tuple() {
        let (url, captured, _resp, shutdown) = spawn_server(TestResponse::Recognized(true)).await;
        let c = UpstreamRegistryClient::new(config_for(&url)).unwrap();
        let ok = c.recognise("did:webvh:peer.example").await.unwrap();
        assert!(ok);
        let body = captured.lock().await.clone().expect("server saw request");
        assert_eq!(body.entity_id, "did:webvh:peer.example");
        assert_eq!(body.authority_id, "did:webvh:vtc.example");
        assert_eq!(body.action, "recognise");
        assert_eq!(body.resource, "trust-graph");
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn recognise_returns_false_when_response_recognized_is_false() {
        let (url, _captured, _resp, shutdown) = spawn_server(TestResponse::Recognized(false)).await;
        let c = UpstreamRegistryClient::new(config_for(&url)).unwrap();
        let ok = c.recognise("did:webvh:peer.example").await.unwrap();
        assert!(!ok);
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn recognise_maps_404_to_clean_not_recognised() {
        let (url, _captured, _resp, shutdown) = spawn_server(TestResponse::NotFound).await;
        let c = UpstreamRegistryClient::new(config_for(&url)).unwrap();
        // 404 = no record matches the 4-tuple. The client
        // surfaces this as Ok(false) — semantically the same
        // as a stored record with `recognized: false`.
        let ok = c.recognise("did:webvh:stranger.example").await.unwrap();
        assert!(!ok);
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn recognise_maps_400_to_permanent() {
        let (url, _captured, _resp, shutdown) = spawn_server(TestResponse::BadRequest).await;
        let c = UpstreamRegistryClient::new(config_for(&url)).unwrap();
        let err = c.recognise("did:webvh:peer.example").await.unwrap_err();
        assert!(matches!(err, RegistryError::Permanent(_)));
        assert!(!err.is_retriable());
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn recognise_maps_500_to_transient() {
        let (url, _captured, _resp, shutdown) = spawn_server(TestResponse::ServerError).await;
        let c = UpstreamRegistryClient::new(config_for(&url)).unwrap();
        let err = c.recognise("did:webvh:peer.example").await.unwrap_err();
        assert!(matches!(err, RegistryError::Transient(_)));
        assert!(err.is_retriable());
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn recognise_connection_refused_is_unreachable() {
        // Nothing listens on 127.0.0.1:1 — connection refused.
        let cfg = UpstreamConfig {
            base_url: "http://127.0.0.1:1".into(),
            http_timeout: Duration::from_millis(300),
            authority_did: Some("did:webvh:vtc.example".into()),
        };
        let c = UpstreamRegistryClient::new(cfg).unwrap();
        let err = c.recognise("did:webvh:peer.example").await.unwrap_err();
        assert!(
            err.is_retriable(),
            "connection refused must be retriable: {err:?}"
        );
    }

    #[tokio::test]
    async fn recognise_refuses_when_authority_did_missing() {
        // Daemons that boot without `vtc_did` configured can't
        // produce a valid recognition payload — refuse with a
        // clear Permanent rather than send half a 4-tuple.
        let cfg = UpstreamConfig {
            base_url: "http://127.0.0.1:1".into(),
            http_timeout: Duration::from_secs(1),
            authority_did: None,
        };
        let c = UpstreamRegistryClient::new(cfg).unwrap();
        let err = c.recognise("did:webvh:peer.example").await.unwrap_err();
        assert!(matches!(err, RegistryError::Permanent(_)));
        assert!(
            err.to_string().contains("authority_did"),
            "error should mention authority_did: {err}"
        );
    }
}
