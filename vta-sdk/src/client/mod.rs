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
#[derive(Clone)]
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
mod consent;
mod contexts;
mod credentials;
mod did_templates;
mod keys;
mod memory;
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

    /// Connect via DIDComm through a mediator using a hosted-DID secrets
    /// bundle (`did:webvh` and any DID whose signing + key-agreement keys are
    /// independent, exported as a [`DidSecretsBundle`]).
    ///
    /// The DIDComm `client_did` is taken from `bundle.did`; the secrets are
    /// reconstructed from the bundle's entries via
    /// [`crate::did_key::secrets_from_bundle`] (signing/key-agreement order
    /// preserved). This is the bundle counterpart to
    /// [`connect_didcomm`](Self::connect_didcomm), which derives both keys from
    /// a single `did:key` seed.
    ///
    /// `rest_url` is an optional fallback for REST-only operations like
    /// `health()`.
    ///
    /// # You MUST call [`shutdown`](Self::shutdown) when done
    ///
    /// See [`connect_didcomm`](Self::connect_didcomm) — the same live-session
    /// leak contract applies. Prefer [`with_didcomm`](Self::with_didcomm).
    ///
    /// [`DidSecretsBundle`]: crate::did_secrets::DidSecretsBundle
    #[cfg(feature = "session")]
    pub async fn connect_didcomm_bundle(
        bundle: &crate::did_secrets::DidSecretsBundle,
        vta_did: &str,
        mediator_did: &str,
        rest_url: Option<String>,
    ) -> Result<Self, VtaError> {
        let secrets = crate::did_key::secrets_from_bundle(bundle)
            .map_err(|e| VtaError::DidcommTransport(e.to_string()))?;

        let session = crate::didcomm_session::DIDCommSession::connect_with_secrets(
            &bundle.did,
            secrets,
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

    /// The VTA's HTTP base URL, or `None` if this client has none.
    ///
    /// **This is the only accessor you may build an HTTP request from.**
    /// `Some` on the REST transport. On DIDComm it yields the optional
    /// REST side-channel (`None` unless the client was constructed with
    /// one) — a DIDComm client is not guaranteed to know an HTTP URL at
    /// all, so callers must handle `None` rather than assume one exists.
    ///
    /// Replaces the former `base_url()`, which returned the VTA *DID* on
    /// DIDComm and so silently produced `did:…/some/path` when
    /// interpolated into a URL.
    pub fn rest_url(&self) -> Option<&str> {
        match &self.transport {
            Transport::Rest { base_url, .. } => Some(base_url),
            #[cfg(feature = "session")]
            Transport::DIDComm { rest_url, .. } => rest_url.as_deref(),
        }
    }

    /// The VTA's DID, or `None` if this client doesn't know it.
    ///
    /// `Some` on the DIDComm transport (the session is established
    /// against it). `None` on REST — a REST client is never told the
    /// VTA's DID.
    pub fn vta_did(&self) -> Option<&str> {
        match &self.transport {
            Transport::Rest { .. } => None,
            #[cfg(feature = "session")]
            Transport::DIDComm { session, .. } => Some(&session.vta_did),
        }
    }

    /// Human-readable identifier for the VTA this client talks to — the
    /// REST URL, or the VTA DID on a DIDComm client with no REST URL.
    ///
    /// **Display and diagnostics only.** The value is a URL on one
    /// transport and a DID on the other, so never interpolate it into a
    /// request — use [`rest_url`](Self::rest_url) for that.
    pub fn endpoint_label(&self) -> &str {
        match &self.transport {
            Transport::Rest { base_url, .. } => base_url,
            #[cfg(feature = "session")]
            Transport::DIDComm {
                session, rest_url, ..
            } => rest_url.as_deref().unwrap_or(&session.vta_did),
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

    /// Force a **full** re-authentication (challenge-response), discarding
    /// the cached access token *and* the refresh token. Unlike
    /// [`ensure_token_valid`](Self::ensure_token_valid) — which trusts the
    /// locally stored expiry — this is the reaction to the VTA actually
    /// rejecting a request (401/403): the token the local clock believed
    /// valid is stale server-side (clock skew, a VTA restart, or a
    /// refresh-rotation desync), so both cached tokens are cleared before
    /// re-authenticating from the stored credential.
    ///
    /// Returns `Ok(true)` if a re-auth ran, `Ok(false)` if no credential is
    /// stored (nothing to retry with — e.g. a client given only a bare
    /// token via [`set_token`](Self::set_token)).
    pub(super) async fn force_reauth(
        client: &Client,
        base_url: &str,
        auth: &tokio::sync::Mutex<RestAuth>,
    ) -> Result<bool, VtaError> {
        let cred = {
            let mut guard = auth.lock().await;
            let Some(cred) = guard.credential.clone() else {
                return Ok(false);
            };
            // Invalidate every cached token up front so a racing
            // `ensure_token_valid` can't hand back the just-rejected token.
            guard.token = None;
            guard.expires_at = None;
            guard.refresh_token = None;
            guard.refresh_expires_at = None;
            cred
        };

        let result = crate::auth_light::challenge_response_light(
            client,
            base_url,
            &cred.did,
            &cred.private_key_multibase,
            &cred.vta_did,
        )
        .await?;

        let mut guard = auth.lock().await;
        guard.token = Some(result.access_token);
        guard.expires_at = Some(result.access_expires_at);
        guard.refresh_token = result.refresh_token;
        guard.refresh_expires_at = result.refresh_expires_at;
        Ok(true)
    }

    /// Send an authenticated REST request, with a single reactive
    /// re-auth-and-retry on a 401/403.
    ///
    /// Proactive refresh ([`ensure_token_valid`](Self::ensure_token_valid))
    /// only reacts to the *local* clock; it can't catch a token the VTA
    /// invalidated out-of-band. So if the response is `401`/`403`, we
    /// [`force_reauth`](Self::force_reauth) once and replay the request,
    /// turning a transient auth rejection into a self-heal instead of a
    /// propagated error. The retry needs a cloneable request body
    /// ([`RequestBuilder::try_clone`]); JSON bodies clone fine, streaming
    /// bodies don't and simply skip the retry. A persistent denial (e.g. an
    /// expired ACL entry) still surfaces — the replay is rejected too.
    ///
    /// `req` must be the request **before** the bearer token is attached;
    /// this helper attaches it (and re-attaches the fresh one on retry).
    pub(super) async fn send_authed(
        client: &Client,
        base_url: &str,
        auth: &tokio::sync::Mutex<RestAuth>,
        req: RequestBuilder,
    ) -> Result<reqwest::Response, VtaError> {
        Self::ensure_token_valid(client, base_url, auth).await?;
        let retry_req = req.try_clone();
        let token = auth.lock().await.token.clone();
        let resp = Self::with_auth_token(req, &token).send().await?;

        let status = resp.status();
        if matches!(
            status,
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        ) && let Some(retry_req) = retry_req
        {
            match Self::force_reauth(client, base_url, auth).await {
                Ok(true) => {
                    let token = auth.lock().await.token.clone();
                    return Ok(Self::with_auth_token(retry_req, &token).send().await?);
                }
                // No credential to re-auth with — surface the original 401/403.
                Ok(false) => {}
                // Re-auth itself failed — keep the original response rather
                // than masking the server's verdict with a transport error.
                Err(e) => {
                    tracing::debug!(
                        %status,
                        error = %e,
                        "re-auth after auth rejection failed; surfacing original response"
                    );
                }
            }
        }
        Ok(resp)
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
                let req = build_rest(client, base_url);
                let resp = Self::send_authed(client, base_url, auth, req).await?;
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
                let req = build_rest(client, base_url);
                let resp = Self::send_authed(client, base_url, auth, req).await?;
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

    /// Like [`rpc`](Self::rpc), but the **DIDComm leg dispatches a Trust Task**
    /// (binding envelope, `tt_uri`) instead of a raw protocol message, while the
    /// **REST leg keeps using the dedicated route** built by `build_rest`.
    ///
    /// This is the bridge for surfaces (e.g. DID templates) that expose
    /// dedicated REST endpoints but are only reachable over DIDComm through the
    /// VTA's Trust-Task dispatcher (`trusttasks.org/spec/...`). The DIDComm
    /// reply is a trust-task document whose `payload` is the result body.
    #[cfg_attr(not(feature = "session"), allow(unused_variables))]
    pub(crate) async fn rpc_tt<T: serde::de::DeserializeOwned>(
        &self,
        tt_uri: &str,
        payload: serde_json::Value,
        timeout: u64,
        build_rest: impl FnOnce(&Client, &str) -> RequestBuilder,
    ) -> Result<T, VtaError> {
        match &self.transport {
            Transport::Rest {
                client,
                base_url,
                auth,
            } => {
                let req = build_rest(client, base_url);
                let resp = Self::send_authed(client, base_url, auth, req).await?;
                Self::handle_response(resp).await
            }
            #[cfg(feature = "session")]
            Transport::DIDComm { .. } => {
                let payload = self.dispatch_trust_task(tt_uri, payload, timeout).await?;
                serde_json::from_value(payload)
                    .map_err(|e| VtaError::Protocol(format!("trust-task response decode: {e}")))
            }
        }
    }

    /// [`rpc_tt`](Self::rpc_tt) for operations that return `()` (e.g. DELETE).
    /// The DIDComm leg still requires a non-rejection trust-task reply.
    #[cfg_attr(not(feature = "session"), allow(unused_variables))]
    pub(crate) async fn rpc_tt_void(
        &self,
        tt_uri: &str,
        payload: serde_json::Value,
        timeout: u64,
        build_rest: impl FnOnce(&Client, &str) -> RequestBuilder,
    ) -> Result<(), VtaError> {
        match &self.transport {
            Transport::Rest {
                client,
                base_url,
                auth,
            } => {
                let req = build_rest(client, base_url);
                let resp = Self::send_authed(client, base_url, auth, req).await?;
                Self::handle_delete_response(resp).await
            }
            #[cfg(feature = "session")]
            Transport::DIDComm { .. } => {
                let _ = self.dispatch_trust_task(tt_uri, payload, timeout).await?;
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
    /// dedicated REST route and are reachable only through the dispatcher; also
    /// the generic escape hatch for invoking *any* of the VTA's trust-task
    /// operations by URI (see `vta_sdk::trust_tasks::ALL_URIS` for the catalog).
    #[cfg_attr(not(feature = "session"), allow(unused_variables))]
    pub async fn dispatch_trust_task(
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
                let req = client
                    .post(format!("{base_url}/api/trust-tasks"))
                    .json(&doc);
                let resp = Self::send_authed(client, base_url, auth, req).await?;
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

    /// Send a one-way (fire-and-forget) DIDComm message of `msg_type` to
    /// `recipient_did` and return as soon as the mediator accepts it — no
    /// response is awaited and the body is **not** wrapped in a trust-task
    /// envelope.
    ///
    /// This is the send-side counterpart to [`Self::receive_next`], for
    /// asynchronous peer-to-peer data planes (e.g. `vti-message-bridge`'s
    /// agent ⇄ bridge chat messages) where the traffic is one-way, not RPC.
    /// The message is authcrypt-packed with this client's own keys, so the
    /// recipient unpacks a cryptographically-authenticated sender DID. Safe to
    /// call concurrently with a `receive_next` loop — it never touches the
    /// inbound live stream. See issue #502.
    ///
    /// DIDComm-only — a REST client holds no key material to authcrypt with and
    /// gets a clear [`VtaError::UnsupportedTransport`].
    #[cfg_attr(not(feature = "session"), allow(unused_variables))]
    pub async fn send_message(
        &self,
        recipient_did: &str,
        msg_type: &str,
        body: serde_json::Value,
    ) -> Result<(), VtaError> {
        match &self.transport {
            #[cfg(feature = "session")]
            Transport::DIDComm { session, .. } => {
                session.send_one_way(recipient_did, msg_type, body).await
            }
            Transport::Rest { .. } => Err(VtaError::UnsupportedTransport(
                "one-way DIDComm send requires the DIDComm transport \
                 (REST clients hold no key material to authcrypt with)"
                    .into(),
            )),
        }
    }

    /// Resolve an **arbitrary** DID to its DID document JSON, via the shared
    /// DID-resolver cache (`affinidi-did-resolver-cache-sdk`). Independent of
    /// this client's auth/transport — pure resolution. Requires the `didcomm`
    /// feature (which pulls the resolver).
    #[cfg(feature = "didcomm")]
    pub async fn resolve_did(&self, did: &str) -> Result<serde_json::Value, VtaError> {
        use affinidi_did_resolver_cache_sdk::DIDCacheClient;
        let resolver = DIDCacheClient::new(crate::resolver::build_did_cache_config_from_env())
            .await
            .map_err(|e| VtaError::Protocol(format!("resolver init: {e}")))?;
        let resolved = resolver
            .resolve(did)
            .await
            .map_err(|e| VtaError::Protocol(format!("resolve {did}: {e}")))?;
        serde_json::to_value(resolved.doc).map_err(VtaError::from)
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
        assert_eq!(client.rest_url(), Some("http://localhost:3000"));
    }

    #[test]
    fn test_new_strips_multiple_trailing_slashes() {
        let client = VtaClient::new("http://localhost:3000///");
        assert_eq!(client.rest_url(), Some("http://localhost:3000"));
    }

    #[test]
    fn test_new_no_trailing_slash_unchanged() {
        let client = VtaClient::new("http://localhost:3000");
        assert_eq!(client.rest_url(), Some("http://localhost:3000"));
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
