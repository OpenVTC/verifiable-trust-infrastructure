//! VTA REST + DIDComm client.
//!
//! The public surface is the [`VtaClient`] struct and its methods.
//! Methods are split into per-domain `impl` blocks across sibling
//! files (`auth.rs`, `keys.rs`, `acl.rs`, `contexts.rs`, `webvh.rs`,
//! `audit.rs`, `did_templates.rs`, `bootstrap.rs`, `backup.rs`,
//! `vta_management.rs`, `secrets.rs`). This file holds the struct
//! definition, transport plumbing, the constructor / connection
//! surface, and the shared `rpc` / `rpc_void` dispatch helpers used
//! by every per-domain method.

use crate::error::VtaError;
use reqwest::{Client, RequestBuilder};

// ── Internal transport ──────────────────────────────────────────────

/// Stored credential for automatic token refresh.
pub(super) struct AuthCredential {
    pub(super) did: String,
    pub(super) private_key_multibase: String,
    pub(super) vta_did: String,
}

/// Mutable auth state protected by a mutex for auto-refresh.
pub(super) struct RestAuth {
    pub(super) token: Option<String>,
    pub(super) expires_at: Option<u64>,
    pub(super) refresh_token: Option<String>,
    pub(super) refresh_expires_at: Option<u64>,
    pub(super) credential: Option<AuthCredential>,
}

/// Cloneable transport layer.
///
/// Auth state is wrapped in `Arc<Mutex>` so cloned clients share tokens
/// and avoid redundant authentication round-trips.
#[derive(Clone)]
pub(super) enum Transport {
    Rest {
        client: Client,
        base_url: String,
        auth: std::sync::Arc<tokio::sync::Mutex<RestAuth>>,
    },
    #[cfg(feature = "session")]
    DIDComm {
        session: crate::didcomm_session::DIDCommSession,
        rest_client: Option<Client>,
        rest_url: Option<String>,
    },
}

/// HTTP/DIDComm client for the VTA service API.
///
/// **Requires the `client` feature.** Without it the struct and all
/// methods below are absent — enable in `Cargo.toml`:
/// ```toml
/// vta-sdk = { version = "…", features = ["client"] }
/// ```
///
/// Cloning a `VtaClient` is cheap — clones share the underlying HTTP
/// connection pool and authentication state.
#[derive(Clone)]
pub struct VtaClient {
    pub(super) transport: Transport,
}

// ── Protocol response aliases ──────────────────────────────────────
//
// Response types that live in the `protocols::` layer are re-exported
// here with `*Response` naming so callers can import everything they
// need from `vta_sdk::client::*` (or `vta_sdk::prelude::*`) without
// reaching into the protocol path. The original `*ResultBody` names
// stay exported from `protocols/` for DIDComm-layer consumers.

pub use crate::protocols::context_management::delete::{
    DeleteContextPreviewResultBody as DeleteContextPreviewResponse,
    DeleteContextResultBody as DeleteContextResponse,
};

pub use crate::protocols::did_management::create::CreateDidWebvhResultBody as CreateDidWebvhResponse;
pub use crate::protocols::did_management::list::ListDidsWebvhResultBody as ListDidsWebvhResponse;
pub use crate::protocols::did_management::servers::ListWebvhServersResultBody as ListWebvhServersResponse;

// DID-template response shape (Phase 2+).
pub use crate::did_templates::{
    BUILTIN_NAMES as DID_TEMPLATE_BUILTINS, DidTemplate, DidTemplateRecord,
    Scope as DidTemplateScope, TemplateError as DidTemplateError, TemplateVars,
};

// ── Request / Response types ────────────────────────────────────────
//
// All request/response DTOs live in `types.rs`; re-exported here so
// callers can continue to use `vta_sdk::client::*` without reaching
// into the submodule path.
mod types;
pub use types::*;

// ── Per-domain impl blocks ─────────────────────────────────────────

mod acl;
mod agent_devices;
#[cfg(feature = "session")]
mod auto_connect;
mod backup;
mod backup_descriptors;
mod bootstrap;
mod contexts;
mod did_templates;
mod keys;
mod secrets;
mod vault;
mod vta_management;
mod webvh;

#[cfg(feature = "client")]
mod audit;

#[cfg(feature = "session")]
pub use crate::session::TokenResult;
#[cfg(feature = "session")]
pub use auto_connect::{AutoConnect, ConnectedVta};

/// Percent-encode characters that are unsafe inside a URL path segment.
///
/// `%` must be escaped first — re-ordering would double-escape any
/// already-percent-encoded character.
pub(super) fn encode_path_segment(s: &str) -> String {
    s.replace('%', "%25")
        .replace('#', "%23")
        .replace('?', "%3F")
        .replace('/', "%2F")
}

// ── REST helpers ────────────────────────────────────────────────────

impl VtaClient {
    /// Attach Bearer token to a request if one is set.
    pub(super) fn with_auth_token(req: RequestBuilder, token: &Option<String>) -> RequestBuilder {
        match token {
            Some(token) => req.bearer_auth(token),
            None => req,
        }
    }

    pub(super) async fn handle_response<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
    ) -> Result<T, VtaError> {
        if resp.status().is_success() {
            Ok(resp.json::<T>().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            // For 409 Conflict, preserve the full JSON body so callers can
            // extract structured details (e.g. EnableDidcommConflictBody).
            // Other error codes only need the `error` field string.
            if status == reqwest::StatusCode::CONFLICT {
                return Err(VtaError::Conflict(text));
            }
            let body = Self::extract_error_message(&text);
            Err(VtaError::from_http(status, body))
        }
    }

    pub(super) async fn handle_delete_response(resp: reqwest::Response) -> Result<(), VtaError> {
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            if status == reqwest::StatusCode::CONFLICT {
                return Err(VtaError::Conflict(text));
            }
            let body = Self::extract_error_message(&text);
            Err(VtaError::from_http(status, body))
        }
    }

    /// Extract the `error` field from a JSON response body, or fall back to
    /// "unknown error" with the raw text appended for diagnostics. The raw text
    /// is truncated so a large non-JSON body (e.g. a 1 MB proxy error page)
    /// can't bloat the error string that propagates into CLI output and logs.
    fn extract_error_message(text: &str) -> String {
        /// Max characters of raw body to surface in the fallback message.
        const MAX_RAW_LEN: usize = 256;
        serde_json::from_str::<ErrorResponse>(text)
            .map(|e| e.error)
            .unwrap_or_else(|_| {
                if text.is_empty() {
                    "unknown error".to_string()
                } else {
                    let truncated: String = text.chars().take(MAX_RAW_LEN).collect();
                    let ellipsis = if truncated.len() < text.len() {
                        "…"
                    } else {
                        ""
                    };
                    format!("unknown error: {truncated}{ellipsis}")
                }
            })
    }
}

// ── Constructor + transport surface ────────────────────────────────

impl VtaClient {
    /// Create a new REST-only client.
    pub fn new(base_url: &str) -> Self {
        Self {
            transport: Transport::Rest {
                client: Client::new(),
                base_url: base_url.trim_end_matches('/').to_string(),
                auth: std::sync::Arc::new(tokio::sync::Mutex::new(RestAuth {
                    token: None,
                    expires_at: None,
                    refresh_token: None,
                    refresh_expires_at: None,
                    credential: None,
                })),
            },
        }
    }

    /// Create a client from a credential bundle.
    ///
    /// Performs lightweight challenge-response auth (no ATM/TDK initialization)
    /// and stores the credential for automatic token refresh.
    pub async fn from_credential(
        credential: &crate::credentials::CredentialBundle,
        url_override: Option<&str>,
    ) -> Result<Self, VtaError> {
        let (result, cred, http) =
            crate::auth_light::authenticate_with_credential(credential, url_override).await?;
        let base_url = url_override
            .or(cred.vta_url.as_deref())
            .ok_or_else(|| VtaError::Validation("no VTA URL".into()))?
            .trim_end_matches('/')
            .to_string();

        Ok(Self {
            transport: Transport::Rest {
                client: http,
                base_url,
                auth: std::sync::Arc::new(tokio::sync::Mutex::new(RestAuth {
                    token: Some(result.access_token),
                    expires_at: Some(result.access_expires_at),
                    refresh_token: result.refresh_token,
                    refresh_expires_at: result.refresh_expires_at,
                    credential: Some(AuthCredential {
                        did: cred.did,
                        private_key_multibase: cred.private_key_multibase,
                        vta_did: cred.vta_did,
                    }),
                })),
            },
        })
    }

    /// Returns the token expiry timestamp, if known.
    pub async fn token_expires_at(&self) -> Option<u64> {
        match &self.transport {
            Transport::Rest { auth, .. } => auth.lock().await.expires_at,
            #[cfg(feature = "session")]
            Transport::DIDComm { .. } => None,
        }
    }

    /// Connect via DIDComm through a mediator.
    ///
    /// `rest_url` is an optional fallback for REST-only operations like `health()`.
    ///
    /// # You MUST call [`shutdown`](Self::shutdown) when done
    ///
    /// This opens a **persistent, auto-reconnecting** session. [`Drop`] cannot
    /// close it (shutdown is `async`), so dropping a DIDComm `VtaClient` without
    /// `shutdown()` **leaks a live session that keeps reconnecting** — and two
    /// live sessions for the same DID fight on the mediator, so round-trips time
    /// out. Always:
    ///
    /// ```ignore
    /// let client = VtaClient::connect_didcomm(client_did, key, vta_did, mediator, rest).await?;
    /// // ...use client...
    /// client.shutdown().await;   // REQUIRED — not optional cleanup
    /// ```
    ///
    /// Prefer [`with_didcomm`](Self::with_didcomm), which guarantees `shutdown()`
    /// on scope exit (including the error path). Dropping a leaked client logs a
    /// `WARN` (and trips a `debug_assert!` in debug builds).
    #[cfg(feature = "session")]
    pub async fn connect_didcomm(
        client_did: &str,
        private_key_multibase: &str,
        vta_did: &str,
        mediator_did: &str,
        rest_url: Option<String>,
    ) -> Result<Self, VtaError> {
        let session = crate::didcomm_session::DIDCommSession::connect(
            client_did,
            private_key_multibase,
            vta_did,
            mediator_did,
        )
        .await
        .map_err(|e| VtaError::DidcommTransport(e.to_string()))?;

        let rest_client = rest_url.as_ref().map(|_| Client::new());

        Ok(Self {
            transport: Transport::DIDComm {
                session,
                rest_client,
                rest_url: rest_url.map(|u| u.trim_end_matches('/').to_string()),
            },
        })
    }

    /// Set the Bearer token for authenticated requests (REST only, no-op for DIDComm).
    ///
    /// Can be called from sync or async contexts. For async contexts, use
    /// [`set_token_async`](Self::set_token_async) to avoid potential blocking.
    pub fn set_token(&self, token: String) {
        match &self.transport {
            Transport::Rest { auth, .. } => {
                // try_lock avoids blocking the current thread if called from async
                if let Ok(mut guard) = auth.try_lock() {
                    guard.token = Some(token);
                }
            }
            #[cfg(feature = "session")]
            Transport::DIDComm { .. } => {}
        }
    }

    /// Set the Bearer token (async version).
    pub async fn set_token_async(&self, token: String) {
        match &self.transport {
            Transport::Rest { auth, .. } => {
                auth.lock().await.token = Some(token);
            }
            #[cfg(feature = "session")]
            Transport::DIDComm { .. } => {}
        }
    }

    /// Returns the base URL (REST) or VTA DID (DIDComm).
    pub fn base_url(&self) -> &str {
        match &self.transport {
            Transport::Rest { base_url, .. } => base_url,
            #[cfg(feature = "session")]
            Transport::DIDComm { session, .. } => &session.vta_did,
        }
    }

    /// Gracefully shut down the client.
    ///
    /// **Required for every DIDComm client** (no-op for REST). A DIDComm
    /// `VtaClient` owns a live, auto-reconnecting mediator session that [`Drop`]
    /// cannot close; failing to call this leaks the session and causes
    /// duplicate-WebSocket mediator duels + round-trip timeouts. Idempotent and
    /// safe to call on any clone. Prefer [`with_didcomm`](Self::with_didcomm) so
    /// you can't forget.
    pub async fn shutdown(&self) {
        #[cfg(feature = "session")]
        if let Transport::DIDComm { session, .. } = &self.transport {
            session.shutdown().await;
        }
    }

    /// Run `f` with a DIDComm client that is **guaranteed to be shut down** on
    /// the way out — the scoped, leak-proof alternative to
    /// [`connect_didcomm`](Self::connect_didcomm) + a manual `shutdown()`.
    ///
    /// Connects, hands the client to `f`, then calls `shutdown().await`
    /// **whether `f` returns `Ok` or `Err`** (the common forgotten-cleanup
    /// path), and returns `f`'s result. The session can't outlive the scope, so
    /// there's no duplicate-WebSocket duel between sequential uses.
    ///
    /// ```ignore
    /// let dids = VtaClient::with_didcomm(client_did, key, vta_did, mediator, rest, |client| async move {
    ///     client.list_webvh_dids().await   // ...use client...
    /// })
    /// .await?;   // shutdown() already ran
    /// ```
    ///
    /// (If `f`'s future *panics*, the async `shutdown()` cannot run from the
    /// unwinding drop, but the leak guard still logs a `WARN`.)
    #[cfg(feature = "session")]
    pub async fn with_didcomm<F, Fut, T>(
        client_did: &str,
        private_key_multibase: &str,
        vta_did: &str,
        mediator_did: &str,
        rest_url: Option<String>,
        f: F,
    ) -> Result<T, VtaError>
    where
        F: FnOnce(VtaClient) -> Fut,
        Fut: std::future::Future<Output = Result<T, VtaError>>,
    {
        let client = Self::connect_didcomm(
            client_did,
            private_key_multibase,
            vta_did,
            mediator_did,
            rest_url,
        )
        .await?;
        // Run the body, then shut down regardless of Ok/Err before returning.
        let result = f(client.clone()).await;
        client.shutdown().await;
        result
    }

    // ── RPC helpers ─────────────────────────────────────────────────

    /// Ensure the REST auth token is valid, refreshing if needed.
    pub(super) async fn ensure_token_valid(
        client: &Client,
        base_url: &str,
        auth: &tokio::sync::Mutex<RestAuth>,
    ) -> Result<(), VtaError> {
        let mut guard = auth.lock().await;

        // Check if token is still valid (>30s remaining)
        if let Some(expires_at) = guard.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now + 30 < expires_at {
                return Ok(()); // Token still valid
            }
        } else if guard.token.is_some() {
            // Token without expiry — assume valid
            return Ok(());
        }

        // No credential stored — can't auto-refresh
        let Some(ref cred) = guard.credential else {
            return Ok(());
        };

        // Try refresh token first (cheaper than full re-auth)
        if let Some(ref refresh_tok) = guard.refresh_token
            && let Some(refresh_exp) = guard.refresh_expires_at
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now < refresh_exp
                && let Ok(result) = crate::auth_light::refresh_token_light(
                    client,
                    base_url,
                    &cred.did,
                    &cred.vta_did,
                    refresh_tok,
                )
                .await
            {
                guard.token = Some(result.access_token);
                guard.expires_at = Some(result.access_expires_at);
                if let Some(new_refresh) = result.refresh_token {
                    guard.refresh_token = Some(new_refresh);
                }
                guard.refresh_expires_at = result.refresh_expires_at;
                return Ok(());
            }
            // Refresh failed or expired — fall through to full re-auth
        }

        // Full re-authentication
        let did = cred.did.clone();
        let pk = cred.private_key_multibase.clone();
        let vta = cred.vta_did.clone();
        drop(guard); // Release lock before async call

        let result =
            crate::auth_light::challenge_response_light(client, base_url, &did, &pk, &vta).await?;

        let mut guard = auth.lock().await;
        guard.token = Some(result.access_token);
        guard.expires_at = Some(result.access_expires_at);
        guard.refresh_token = result.refresh_token;
        guard.refresh_expires_at = result.refresh_expires_at;
        Ok(())
    }

    /// Dispatch an RPC call via REST (using `build_rest`) or DIDComm (using
    /// `msg_type`/`body`/`result_type`), returning a deserialized response.
    #[allow(unused_variables)]
    pub(crate) async fn rpc<T: serde::de::DeserializeOwned>(
        &self,
        msg_type: &str,
        body: serde_json::Value,
        result_type: &str,
        timeout: u64,
        build_rest: impl FnOnce(&Client, &str) -> RequestBuilder,
    ) -> Result<T, VtaError> {
        match &self.transport {
            Transport::Rest {
                client,
                base_url,
                auth,
            } => {
                Self::ensure_token_valid(client, base_url, auth).await?;
                let token = auth.lock().await.token.clone();
                let req = build_rest(client, base_url);
                let resp = Self::with_auth_token(req, &token).send().await?;
                Self::handle_response(resp).await
            }
            #[cfg(feature = "session")]
            Transport::DIDComm { session, .. } => {
                session
                    .send_and_wait(msg_type, body, result_type, timeout)
                    .await
            }
        }
    }

    /// Like [`rpc`](Self::rpc) but for operations that return `()` (e.g. DELETE).
    #[allow(unused_variables)]
    pub(super) async fn rpc_void(
        &self,
        msg_type: &str,
        body: serde_json::Value,
        result_type: &str,
        timeout: u64,
        build_rest: impl FnOnce(&Client, &str) -> RequestBuilder,
    ) -> Result<(), VtaError> {
        match &self.transport {
            Transport::Rest {
                client,
                base_url,
                auth,
            } => {
                Self::ensure_token_valid(client, base_url, auth).await?;
                let token = auth.lock().await.token.clone();
                let req = build_rest(client, base_url);
                let resp = Self::with_auth_token(req, &token).send().await?;
                Self::handle_delete_response(resp).await
            }
            #[cfg(feature = "session")]
            Transport::DIDComm { session, .. } => {
                let _: serde_json::Value = session
                    .send_and_wait(msg_type, body, result_type, timeout)
                    .await?;
                Ok(())
            }
        }
    }

    // ── Trust-task dispatch (device/vault slices) ──────────────────────

    /// Dispatch a Trust Task over whichever transport this client uses and
    /// return the success response's `payload`.
    ///
    /// The wire envelope is identical on both transports — `{ id, type,
    /// payload }`:
    /// - **REST** → `POST /api/trust-tasks` with the envelope; the HTTP status
    ///   signals success/failure and the response body's `payload` is returned.
    /// - **DIDComm** → a message of type [`TRUST_TASK_ENVELOPE_TYPE`] carrying
    ///   the envelope as its body; the reply is itself a trust-task document
    ///   (HTTP status is dropped on the wire), so a missing `payload` is treated
    ///   as a rejection and surfaced as an error.
    ///
    /// Used by the `device/*` and `vault/*` client methods, which have no
    /// dedicated REST route and are reachable only through the dispatcher.
    #[cfg_attr(not(feature = "session"), allow(unused_variables))]
    pub(crate) async fn dispatch_trust_task(
        &self,
        type_uri: &str,
        payload: serde_json::Value,
        timeout: u64,
    ) -> Result<serde_json::Value, VtaError> {
        let doc = serde_json::json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": type_uri,
            "payload": payload,
        });
        match &self.transport {
            Transport::Rest {
                client,
                base_url,
                auth,
            } => {
                Self::ensure_token_valid(client, base_url, auth).await?;
                let token = auth.lock().await.token.clone();
                let req = client
                    .post(format!("{base_url}/api/trust-tasks"))
                    .json(&doc);
                let resp = Self::with_auth_token(req, &token).send().await?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(VtaError::from_http(status, body));
                }
                let response_doc: serde_json::Value = resp.json().await?;
                Self::extract_trust_task_payload(response_doc)
            }
            #[cfg(feature = "session")]
            Transport::DIDComm { session, .. } => {
                const TRUST_TASK_ENVELOPE_TYPE: &str =
                    "https://trusttasks.org/binding/didcomm/0.1/envelope";
                let response_doc: serde_json::Value = session
                    .send_and_wait(
                        TRUST_TASK_ENVELOPE_TYPE,
                        doc,
                        TRUST_TASK_ENVELOPE_TYPE,
                        timeout,
                    )
                    .await?;
                Self::extract_trust_task_payload(response_doc)
            }
        }
    }

    /// Pull `payload` out of a framework trust-task response document. A success
    /// document carries `payload`; a rejection does not — surface its
    /// `reason`/`comment` (or the whole document) as a protocol error so the
    /// DIDComm path (which drops the HTTP status) still fails loudly.
    fn extract_trust_task_payload(doc: serde_json::Value) -> Result<serde_json::Value, VtaError> {
        if let Some(payload) = doc.get("payload") {
            return Ok(payload.clone());
        }
        let reason = doc
            .get("reason")
            .or_else(|| doc.get("comment"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| doc.to_string());
        Err(VtaError::Protocol(format!("trust task rejected: {reason}")))
    }

    /// Seal a cleartext `VaultSecret` JSON for `vault/upsert`'s `sealedSecret`
    /// field. Requires the DIDComm transport — the seal is a `didcomm-authcrypt`
    /// JWE produced with this client's own keys, so a REST-only client (no key
    /// material) cannot produce it and gets a clear `UnsupportedTransport`
    /// error.
    #[cfg_attr(not(feature = "session"), allow(unused_variables))]
    pub async fn seal_vault_secret(&self, secret: serde_json::Value) -> Result<String, VtaError> {
        match &self.transport {
            #[cfg(feature = "session")]
            Transport::DIDComm { session, .. } => session.seal_to_vta(secret).await,
            Transport::Rest { .. } => Err(VtaError::UnsupportedTransport(
                "sealing a vault secret requires the DIDComm transport \
                 (REST clients hold no key material to authcrypt with)"
                    .into(),
            )),
        }
    }

    /// Open a `didcomm-authcrypt` JWE the VTA sealed to this client (the
    /// `sealedSecret` returned by `vault/release` / `vault/get`). DIDComm-only,
    /// for the same reason as [`Self::seal_vault_secret`].
    #[cfg_attr(not(feature = "session"), allow(unused_variables))]
    pub async fn open_sealed_secret(&self, jwe: &str) -> Result<serde_json::Value, VtaError> {
        match &self.transport {
            #[cfg(feature = "session")]
            Transport::DIDComm { session, .. } => session.open_from_vta(jwe).await,
            Transport::Rest { .. } => Err(VtaError::UnsupportedTransport(
                "opening a sealed vault secret requires the DIDComm transport".into(),
            )),
        }
    }

    /// Wait up to `timeout_secs` for the next **unsolicited** inbound DIDComm
    /// message (e.g. a VTA-pushed wake / step-up request), returning the
    /// serialized DIDComm `Message` JSON. `Ok(None)` on timeout with nothing
    /// received. DIDComm-only — the inbound live stream needs the session.
    ///
    /// This is the receive half of an agent's event loop (see
    /// `agent_session::AgentSession`).
    #[cfg_attr(not(feature = "session"), allow(unused_variables))]
    pub async fn receive_next(&self, timeout_secs: u64) -> Result<Option<String>, VtaError> {
        match &self.transport {
            #[cfg(feature = "session")]
            Transport::DIDComm { session, .. } => session.receive_next(timeout_secs).await,
            Transport::Rest { .. } => Err(VtaError::UnsupportedTransport(
                "receiving inbound messages requires the DIDComm transport".into(),
            )),
        }
    }

    // ── Health ───────────────────────────────────────────────────────

    /// GET /health (always REST, unauthenticated)
    pub async fn health(&self) -> Result<HealthResponse, VtaError> {
        match &self.transport {
            Transport::Rest {
                client, base_url, ..
            } => {
                let resp = client.get(format!("{base_url}/health")).send().await?;
                Self::handle_response(resp).await
            }
            #[cfg(feature = "session")]
            Transport::DIDComm {
                rest_client,
                rest_url,
                ..
            } => match (rest_client, rest_url) {
                (Some(client), Some(url)) => {
                    let resp = client.get(format!("{url}/health")).send().await?;
                    Self::handle_response(resp).await
                }
                _ => Err(VtaError::UnsupportedTransport(
                    "health check not available via DIDComm (no REST URL)".into(),
                )),
            },
        }
    }

    // ── Step-up policy ──────────────────────────────────────────────

    /// `GET /step-up/policy` — read the maintainer's current effective step-up
    /// policy (the `0.2` shape: `{ enabled, floors }`). REST-only in the SDK;
    /// over DIDComm send the `auth/step-up/policy/0.2` trust-task instead.
    pub async fn get_step_up_policy(&self) -> Result<serde_json::Value, VtaError> {
        match &self.transport {
            Transport::Rest {
                client,
                base_url,
                auth,
            } => {
                Self::ensure_token_valid(client, base_url, auth).await?;
                let token = auth.lock().await.token.clone();
                let req = client.get(format!("{base_url}/step-up/policy"));
                let resp = Self::with_auth_token(req, &token).send().await?;
                Self::handle_response(resp).await
            }
            #[cfg(feature = "session")]
            Transport::DIDComm { .. } => Err(VtaError::UnsupportedTransport(
                "step-up policy read is REST-only in the SDK".into(),
            )),
        }
    }

    /// `PUT /step-up/policy` — set the step-up policy (super-admin). `policy` is
    /// the `0.2` payload (`{ enabled, floors }`); returns the effective
    /// (canonicalized) policy. REST-only; over DIDComm send the
    /// `auth/step-up/policy/0.2` trust-task instead.
    pub async fn set_step_up_policy(
        &self,
        policy: serde_json::Value,
    ) -> Result<serde_json::Value, VtaError> {
        match &self.transport {
            Transport::Rest {
                client,
                base_url,
                auth,
            } => {
                Self::ensure_token_valid(client, base_url, auth).await?;
                let token = auth.lock().await.token.clone();
                let req = client
                    .put(format!("{base_url}/step-up/policy"))
                    .json(&policy);
                let resp = Self::with_auth_token(req, &token).send().await?;
                Self::handle_response(resp).await
            }
            #[cfg(feature = "session")]
            Transport::DIDComm { .. } => Err(VtaError::UnsupportedTransport(
                "step-up policy set is REST-only in the SDK; send the \
                 auth/step-up/policy/0.2 trust-task over DIDComm instead"
                    .into(),
            )),
        }
    }

    // ── Discovery ──────────────────────────────────────────────────

    /// Discover VTA capabilities: enabled features, services, WebVH servers,
    /// and supported DID creation modes.
    ///
    /// Requires authentication — any role (including Reader) can access.
    #[cfg(feature = "client")]
    pub async fn capabilities(
        &self,
    ) -> Result<crate::protocols::discovery::CapabilitiesResponse, VtaError> {
        use crate::protocols::discovery;
        self.rpc(
            discovery::DISCOVER_CAPABILITIES,
            serde_json::json!({}),
            discovery::DISCOVER_CAPABILITIES_RESULT,
            30,
            |c, url| c.get(format!("{url}/capabilities")),
        )
        .await
    }

    /// Check whether the current auth token is valid by calling an authenticated endpoint.
    ///
    /// Returns `true` if authenticated, `false` if the token is invalid/expired.
    /// Returns an error only on network failures.
    #[cfg(feature = "client")]
    pub async fn check_auth(&self) -> Result<bool, VtaError> {
        match &self.transport {
            Transport::Rest {
                client,
                base_url,
                auth,
            } => {
                let token = auth.lock().await.token.clone();
                let req = client.get(format!("{base_url}/health/details"));
                let resp = Self::with_auth_token(req, &token).send().await?;
                Ok(resp.status().is_success())
            }
            #[cfg(feature = "session")]
            Transport::DIDComm { .. } => {
                // DIDComm sessions are always authenticated
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyType;

    // ── encode_path_segment ─────────────────────────────────────────

    #[test]
    fn test_encode_hash_in_did_fragment() {
        assert_eq!(
            encode_path_segment("did:key:z6Mk123#z6Mk123"),
            "did:key:z6Mk123%23z6Mk123"
        );
    }

    #[test]
    fn test_encode_question_mark() {
        assert_eq!(encode_path_segment("foo?bar"), "foo%3Fbar");
    }

    #[test]
    fn test_encode_percent_is_escaped_first() {
        assert_eq!(encode_path_segment("100%#done"), "100%25%23done");
    }

    #[test]
    fn test_encode_colon_preserved() {
        assert_eq!(encode_path_segment("did:key:z6Mk"), "did:key:z6Mk");
    }

    #[test]
    fn test_encode_plain_string_unchanged() {
        assert_eq!(encode_path_segment("simple-id"), "simple-id");
    }

    #[test]
    fn test_encode_multiple_hashes() {
        assert_eq!(encode_path_segment("a#b#c"), "a%23b%23c");
    }

    #[test]
    fn test_encode_slash_in_derivation_path() {
        assert_eq!(
            encode_path_segment("m/44'/0'/0'/0"),
            "m%2F44'%2F0'%2F0'%2F0"
        );
    }

    // ── VtaClient::new ──────────────────────────────────────────────

    #[test]
    fn test_new_strips_trailing_slash() {
        let client = VtaClient::new("http://localhost:3000/");
        assert_eq!(client.base_url(), "http://localhost:3000");
    }

    #[test]
    fn test_new_strips_multiple_trailing_slashes() {
        let client = VtaClient::new("http://localhost:3000///");
        assert_eq!(client.base_url(), "http://localhost:3000");
    }

    #[test]
    fn test_new_no_trailing_slash_unchanged() {
        let client = VtaClient::new("http://localhost:3000");
        assert_eq!(client.base_url(), "http://localhost:3000");
    }

    #[tokio::test]
    async fn test_new_token_initially_none() {
        let client = VtaClient::new("http://example.com");
        match &client.transport {
            Transport::Rest { auth, .. } => assert!(auth.lock().await.token.is_none()),
            #[cfg(feature = "session")]
            _ => panic!("expected REST transport"),
        }
    }

    #[tokio::test]
    async fn test_set_token() {
        let client = VtaClient::new("http://example.com");
        client.set_token("my-jwt".to_string());
        match &client.transport {
            Transport::Rest { auth, .. } => {
                assert_eq!(auth.lock().await.token.as_deref(), Some("my-jwt"));
            }
            #[cfg(feature = "session")]
            _ => panic!("expected REST transport"),
        }
    }

    // ── Request/Response serialization ──────────────────────────────

    #[test]
    fn test_update_config_skips_none_fields() {
        let req = UpdateConfigRequest {
            vta_did: None,
            vta_name: Some("Test".into()),
            public_url: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(!json.as_object().unwrap().contains_key("vta_did"));
        assert_eq!(json["vta_name"], "Test");
        assert!(!json.as_object().unwrap().contains_key("public_url"));
    }

    #[test]
    fn test_create_key_request_serialization() {
        let req = CreateKeyRequest {
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("test key".into()),
            context_id: Some("vta".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(!json.as_object().unwrap().contains_key("derivation_path"));
        assert!(!json.as_object().unwrap().contains_key("key_id"));
        assert!(!json.as_object().unwrap().contains_key("mnemonic"));
        assert_eq!(json["label"], "test key");
        assert_eq!(json["context_id"], "vta");
    }

    #[test]
    fn test_create_acl_request_serialization() {
        let req = CreateAclRequest {
            did: "did:key:z6Mk123".into(),
            role: "admin".into(),
            label: None,
            allowed_contexts: vec!["vta".into()],
            expires_at: None,
            step_up_approver: None,
            step_up_require: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["did"], "did:key:z6Mk123");
        assert_eq!(json["role"], "admin");
        // Omitted approver must not appear on the wire.
        assert!(json.get("step_up_approver").is_none());
        assert!(!json.as_object().unwrap().contains_key("label"));
        assert_eq!(json["allowed_contexts"], serde_json::json!(["vta"]));
    }

    #[test]
    fn test_update_acl_request_all_none() {
        let req = UpdateAclRequest {
            role: None,
            label: None,
            allowed_contexts: None,
            step_up_approver: None,
            step_up_require: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.is_empty(), "all-None request should serialize to {{}}");
    }

    #[test]
    fn test_health_response_deserialization() {
        let json = r#"{"status":"ok","version":"0.1.0"}"#;
        let resp: HealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.version.as_deref(), Some("0.1.0"));
    }

    #[test]
    fn test_health_response_minimal() {
        let json = r#"{"status":"ok"}"#;
        let resp: HealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.version, None);
    }

    #[test]
    fn test_error_response_deserialization() {
        let json = r#"{"error":"not found"}"#;
        let resp: ErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.error, "not found");
    }

    #[test]
    fn test_list_keys_response_deserialization() {
        let json = r#"{"keys":[],"total":0}"#;
        let resp: ListKeysResponse = serde_json::from_str(json).unwrap();
        assert!(resp.keys.is_empty());
        assert_eq!(resp.total, 0);
    }

    #[test]
    fn test_acl_list_response_deserialization() {
        let json = r#"{"entries":[{"did":"did:key:z6Mk1","role":"admin","label":null,"allowed_contexts":[],"created_at":1700000000,"created_by":"setup"}]}"#;
        let resp: AclListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.entries.len(), 1);
        assert_eq!(resp.entries[0].did, "did:key:z6Mk1");
        assert_eq!(resp.entries[0].role, "admin");
        assert!(resp.entries[0].allowed_contexts.is_empty());
    }

    #[test]
    fn test_context_response_deserialization() {
        let json = r#"{"id":"vta","name":"Verified Trust Agent","did":null,"description":null,"base_path":"m/26'/2'/0'","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}"#;
        let resp: ContextResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "vta");
        assert_eq!(resp.name, "Verified Trust Agent");
        assert!(resp.did.is_none());
        assert_eq!(resp.base_path, "m/26'/2'/0'");
    }

    // ── extract_trust_task_payload (device/vault dispatch) ───────────

    #[test]
    fn trust_task_payload_extracted_from_success_doc() {
        // A framework success document carries `payload`; dispatch returns it.
        let doc = serde_json::json!({
            "id": "urn:uuid:abc",
            "type": "https://trusttasks.org/spec/device/list/0.1#response",
            "payload": { "devices": [], "truncated": false }
        });
        let out = VtaClient::extract_trust_task_payload(doc).unwrap();
        assert_eq!(
            out,
            serde_json::json!({ "devices": [], "truncated": false })
        );
    }

    #[test]
    fn trust_task_reject_doc_surfaces_reason_as_error() {
        // A reject document has no `payload`; over DIDComm the HTTP status is
        // dropped, so a missing payload must become a loud error carrying the
        // reject reason rather than a silent empty success.
        let doc = serde_json::json!({
            "id": "urn:uuid:def",
            "type": "https://trusttasks.org/spec/vault/get/0.1#reject",
            "reason": "vault/get:not_found — no such entry"
        });
        let err = VtaClient::extract_trust_task_payload(doc).unwrap_err();
        match err {
            VtaError::Protocol(msg) => assert!(msg.contains("not_found"), "got: {msg}"),
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }
}
