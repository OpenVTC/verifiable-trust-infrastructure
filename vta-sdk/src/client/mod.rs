//! VTA REST + DIDComm client.
//!
//! The public surface is the [`VtaClient`] struct and its methods.
//! Methods are split into per-domain `impl` blocks across sibling
//! files (`auth.rs`, `keys.rs`, `acl.rs`, `contexts.rs`, `webvh.rs`,
//! `audit.rs`, `did_templates.rs`, `bootstrap.rs`, `backup.rs`,
//! `vta_management.rs`, `secrets.rs`). This file holds the struct
//! definition, transport plumbing, the constructor / connection
//! surface, and the shared `rpc` / `rpc_tt` dispatch helpers used
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
        /// The **Trust-Task surface**'s transport, when it has been moved to
        /// TSP by [`VtaClient::enable_tsp_trust_tasks`]. `None` means every
        /// surface uses DIDComm.
        ///
        /// TSP is selected *per surface*, not per client: it carries Trust
        /// Tasks, and the older DIDComm protocol-message surface
        /// ([`VtaClient::rpc`]) has no TSP dispatcher behind it. So a client
        /// that wants both keeps its DIDComm leg and adds this one, rather than
        /// choosing between them.
        #[cfg(feature = "tsp")]
        tsp: Option<TspLeg>,
    },
    /// TSP — the workspace's highest-preference transport.
    ///
    /// Carries the **Trust-Task** surface only ([`VtaClient::rpc_tt`]). The
    /// VTA's TSP inbound dispatcher hands each unpacked payload straight to
    /// `dispatch_trust_task_core`, so a trust task routes over TSP unchanged —
    /// but the older DIDComm *protocol-message* surface ([`VtaClient::rpc`],
    /// e.g. `key-management/1.0/sign-request`) has no TSP dispatcher behind it
    /// and reports `UnsupportedTransport` naming DIDComm.
    #[cfg(feature = "tsp")]
    Tsp {
        session: std::sync::Arc<crate::session::TspSession>,
        vta_did: String,
        mediator_did: String,
        rest_client: Option<Client>,
        rest_url: Option<String>,
    },
}

/// How a DIDComm client reaches TSP for the Trust-Task surface.
///
/// The distinction exists because **the mediator permits one websocket per
/// DID**. Which arm applies is decided by comparing the VTA's advertised `#tsp`
/// endpoint against the mediator the DIDComm session is already on — see
/// [`tsp_leg_for`].
#[cfg(all(feature = "session", feature = "tsp"))]
#[derive(Clone)]
pub(super) enum TspLeg {
    /// The VTA advertises the **same** mediator for `#tsp` and
    /// `#vta-didcomm` — the reference topology. TSP rides the DIDComm session's
    /// existing socket (`DIDCommSession::request_tsp`). No second connection, so
    /// nothing to fail and nothing to shut down.
    Multiplexed,
    /// The VTA advertises a **different** TSP mediator. There is no
    /// one-socket-per-DID conflict across two mediators, so this leg owns its
    /// own [`TspSession`](crate::session::TspSession) — and, being ours, must be
    /// shut down with the client.
    Separate {
        session: std::sync::Arc<crate::session::TspSession>,
        mediator_did: String,
    },
}

/// Which TSP leg a DIDComm session on `didcomm_mediator_did` should use to reach
/// a VTA advertising `tsp_mediator_did`.
///
/// Pure so the rule is testable without a mediator: `None` here would mean
/// silently keeping trust tasks on DIDComm, and `Separate` on the reference
/// deployment would mean a second socket for one DID — `duplicate-channel` plus
/// duelling reconnect loops (#803). Both failure modes are decided entirely by
/// this comparison, so it is worth pinning on its own.
#[cfg(all(feature = "session", feature = "tsp"))]
pub(super) fn tsp_leg_kind(didcomm_mediator_did: &str, tsp_mediator_did: &str) -> TspLegKind {
    if didcomm_mediator_did == tsp_mediator_did {
        TspLegKind::Multiplexed
    } else {
        TspLegKind::Separate
    }
}

/// The decision [`tsp_leg_kind`] makes, before any connecting happens.
#[cfg(all(feature = "session", feature = "tsp"))]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum TspLegKind {
    Multiplexed,
    Separate,
}

/// Which transport carries a given surface on this client.
///
/// A `VtaClient` no longer has *one* transport. TSP carries the Trust-Task
/// surface only, so a client can legitimately be on DIDComm for protocol
/// messages and TSP for trust tasks at the same time — an operator-facing
/// display that renders a single value is therefore wrong by construction. Read
/// both [`VtaClient::trust_task_transport`] and
/// [`VtaClient::protocol_message_transport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceTransport {
    /// REST/HTTPS with a bearer token.
    Rest,
    /// DIDComm authcrypt via a mediator.
    Didcomm,
    /// TSP via a mediator.
    Tsp,
}

impl std::fmt::Display for SurfaceTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rest => write!(f, "REST"),
            Self::Didcomm => write!(f, "DIDComm"),
            Self::Tsp => write!(f, "TSP"),
        }
    }
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

/// The error for a legacy DIDComm *protocol message* attempted over TSP.
///
/// TSP carries Trust Tasks; the VTA's TSP inbound dispatcher feeds every
/// unpacked payload to `dispatch_trust_task_core` and has no handler for the
/// older `key-management/1.0/*`-style protocol messages. Refusing here — rather
/// than sending a frame the VTA would answer with an error, or silently doing
/// nothing — names the transport that does serve the operation.
#[cfg(feature = "tsp")]
fn unsupported_over_tsp(msg_type: &str) -> VtaError {
    VtaError::UnsupportedTransport(format!(
        "'{msg_type}' is a DIDComm protocol message, which TSP does not carry \
         (TSP carries Trust Tasks). Reach this operation over DIDComm:\n  \
         <cli> --transport didcomm <command>"
    ))
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
                client: crate::http::rest_client(),
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
            // No token to expire: TSP authenticates by proven sender VID.
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => None,
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

        Ok(Self::didcomm_transport(session, rest_url))
    }

    /// Wrap a connected [`DIDCommSession`](crate::didcomm_session::DIDCommSession)
    /// in a client. One place to build the transport, so a new `connect_*_on`
    /// variant cannot forget the REST fallback or the TSP-leg default.
    #[cfg(feature = "session")]
    fn didcomm_transport(
        session: crate::didcomm_session::DIDCommSession,
        rest_url: Option<String>,
    ) -> Self {
        let rest_client = rest_url.as_ref().map(|_| crate::http::rest_client());
        Self {
            transport: Transport::DIDComm {
                session,
                rest_client,
                rest_url: rest_url.map(|u| u.trim_end_matches('/').to_string()),
                #[cfg(feature = "tsp")]
                tsp: None,
            },
        }
    }

    /// Connect via DIDComm as one identity **on a shared
    /// [`SessionHub`](crate::session_hub::SessionHub)** — the multi-identity
    /// counterpart to [`connect_didcomm`](Self::connect_didcomm).
    ///
    /// This is the constructor for a front door that terminates requests for N
    /// tenants and has to *act as* each of them: build one hub, then one client
    /// per tenant DID on it. Each client still gets its own profile and its own
    /// mediator websocket (the mediator's ceiling is one socket per DID); what
    /// they share is the TDK, the ATM, the secrets resolver, and the background
    /// tasks — the N-of-everything this replaces (#830).
    ///
    /// # You MUST still call [`shutdown`](Self::shutdown)
    ///
    /// Same contract as [`connect_didcomm`](Self::connect_didcomm), with one
    /// difference: `shutdown()` detaches **this** identity and leaves the hub —
    /// and every sibling client on it — running. Shut the hub down yourself once
    /// the last client on it is done.
    ///
    /// ```ignore
    /// let hub = SessionHub::new().await?;
    /// let finance = VtaClient::connect_didcomm_on(&hub, fin_did, key, vta, med, rest).await?;
    /// let legal   = VtaClient::connect_didcomm_on(&hub, leg_did, key, vta, med, rest).await?;
    /// // ...
    /// finance.shutdown().await;
    /// legal.shutdown().await;
    /// hub.shutdown().await;
    /// ```
    #[cfg(feature = "session")]
    pub async fn connect_didcomm_on(
        hub: &std::sync::Arc<crate::session_hub::SessionHub>,
        client_did: &str,
        private_key_multibase: &str,
        vta_did: &str,
        mediator_did: &str,
        rest_url: Option<String>,
    ) -> Result<Self, VtaError> {
        let session = crate::didcomm_session::DIDCommSession::connect_on(
            hub,
            client_did,
            private_key_multibase,
            vta_did,
            mediator_did,
        )
        .await
        .map_err(|e| VtaError::DidcommTransport(e.to_string()))?;

        Ok(Self::didcomm_transport(session, rest_url))
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

        Ok(Self::didcomm_transport(session, rest_url))
    }

    /// Connect from a hosted-DID secrets bundle as one identity **on a shared
    /// [`SessionHub`](crate::session_hub::SessionHub)** — the bundle
    /// counterpart to [`connect_didcomm_on`](Self::connect_didcomm_on).
    ///
    /// The same hub / per-identity split and the same `shutdown()` contract
    /// apply; see [`connect_didcomm_on`](Self::connect_didcomm_on).
    #[cfg(feature = "session")]
    pub async fn connect_didcomm_bundle_on(
        hub: &std::sync::Arc<crate::session_hub::SessionHub>,
        bundle: &crate::did_secrets::DidSecretsBundle,
        vta_did: &str,
        mediator_did: &str,
        rest_url: Option<String>,
    ) -> Result<Self, VtaError> {
        let secrets = crate::did_key::secrets_from_bundle(bundle)
            .map_err(|e| VtaError::DidcommTransport(e.to_string()))?;

        let session = crate::didcomm_session::DIDCommSession::connect_with_secrets_on(
            hub,
            &bundle.did,
            secrets,
            vta_did,
            mediator_did,
        )
        .await
        .map_err(|e| VtaError::DidcommTransport(e.to_string()))?;

        Ok(Self::didcomm_transport(session, rest_url))
    }

    /// Connect via **TSP** through a mediator — the transport-agnostic
    /// counterpart to [`connect_didcomm`](Self::connect_didcomm), so consumers
    /// switch transport by construction rather than by rewriting call sites.
    ///
    /// `mediator_did` is the VTA's `#tsp` (`TSPTransport`) service endpoint —
    /// the mediator the VTA is a local account on. Get it from
    /// [`resolve_vta_endpoint`](crate::session::resolve_vta_endpoint), which
    /// reads it from that entry rather than assuming it matches the DIDComm
    /// mediator.
    ///
    /// `rest_url` is an optional fallback for the REST-only operations
    /// (`health()`, the descriptor uploads) exactly as on the DIDComm client.
    ///
    /// # What routes over TSP
    ///
    /// The **Trust-Task surface** — the VTA's TSP inbound dispatcher feeds each
    /// unpacked payload to the same `dispatch_trust_task_core` spine REST and
    /// DIDComm use, so those operations are byte-identical across transports.
    /// The older DIDComm protocol-message surface (`key-management/1.0/*` and
    /// friends) has no TSP dispatcher behind it and reports
    /// [`VtaError::UnsupportedTransport`] naming DIDComm — deliberately, rather
    /// than sending a frame the VTA would answer with an error.
    ///
    /// # Authentication
    ///
    /// None to perform. TSP `unpack` yields a cryptographically **proven**
    /// sender VID, which the VTA resolves straight to its ACL grant — the same
    /// intrinsic-sender model as DIDComm authcrypt. There is no challenge, no
    /// bearer token, and no holder proof inside the document; the REST token
    /// dance has no TSP analogue. [`set_token`](Self::set_token) is a no-op
    /// here for that reason.
    ///
    /// # You MUST call [`shutdown`](Self::shutdown) when done
    ///
    /// The same live-session leak contract as
    /// [`connect_didcomm`](Self::connect_didcomm): the mediator permits one
    /// websocket per DID, so a leaked session makes the next connect for this
    /// DID fight the old one.
    #[cfg(feature = "tsp")]
    pub async fn connect_tsp(
        client_did: &str,
        private_key_multibase: &str,
        vta_did: &str,
        mediator_did: &str,
        rest_url: Option<String>,
    ) -> Result<Self, VtaError> {
        let session =
            crate::session::TspSession::connect(client_did, private_key_multibase, mediator_did)
                .await
                .map_err(|e| VtaError::TspTransport(e.to_string()))?;

        Ok(Self::tsp_transport(
            session,
            vta_did,
            mediator_did,
            rest_url,
        ))
    }

    /// Connect via **TSP** as one identity **on a shared
    /// [`SessionHub`](crate::session_hub::SessionHub)** — the multi-identity
    /// counterpart to [`connect_tsp`](Self::connect_tsp).
    ///
    /// Each identity still opens its own TSP websocket to the mediator; the hub
    /// shares everything above the socket. The same `shutdown()` contract as
    /// [`connect_didcomm_on`](Self::connect_didcomm_on) applies — the client
    /// detaches its identity and the hub keeps running for its siblings.
    #[cfg(all(feature = "session", feature = "tsp"))]
    pub async fn connect_tsp_on(
        hub: &std::sync::Arc<crate::session_hub::SessionHub>,
        client_did: &str,
        private_key_multibase: &str,
        vta_did: &str,
        mediator_did: &str,
        rest_url: Option<String>,
    ) -> Result<Self, VtaError> {
        let session = crate::session::TspSession::connect_on(
            hub,
            client_did,
            private_key_multibase,
            mediator_did,
        )
        .await
        .map_err(|e| VtaError::TspTransport(e.to_string()))?;

        Ok(Self::tsp_transport(
            session,
            vta_did,
            mediator_did,
            rest_url,
        ))
    }

    /// Wrap a connected [`TspSession`](crate::session::TspSession) in a client —
    /// the TSP counterpart of
    /// [`didcomm_transport`](Self::didcomm_transport).
    #[cfg(all(feature = "session", feature = "tsp"))]
    fn tsp_transport(
        session: crate::session::TspSession,
        vta_did: &str,
        mediator_did: &str,
        rest_url: Option<String>,
    ) -> Self {
        let rest_client = rest_url.as_ref().map(|_| crate::http::rest_client());
        Self {
            transport: Transport::Tsp {
                session: std::sync::Arc::new(session),
                vta_did: vta_did.to_string(),
                mediator_did: mediator_did.to_string(),
                rest_client,
                rest_url: rest_url.map(|u| u.trim_end_matches('/').to_string()),
            },
        }
    }

    /// Move the **Trust-Task surface** of this DIDComm client onto TSP, keeping
    /// the DIDComm leg for everything TSP does not carry.
    ///
    /// This is the seam for a consumer that already holds a DIDComm session and
    /// wants TSP too (#803). Before it existed, the only way to a TSP-capable
    /// client was [`connect_tsp`](Self::connect_tsp), which opens its **own**
    /// websocket — and since the mediator permits one websocket per DID, and the
    /// reference deployment advertises the *same* mediator for `#tsp` and
    /// `#vta-didcomm`, that second socket is rejected with `duplicate-channel`
    /// and the two reconnect loops duel.
    ///
    /// # What moves, and what does not
    ///
    /// - [`dispatch_trust_task`](Self::dispatch_trust_task) and everything built
    ///   on it (`rpc_tt`, the `device/*` and `vault/*` methods, the generic
    ///   trust-task escape hatch) routes over TSP.
    /// - [`rpc`](Self::rpc) — the older DIDComm protocol-message surface
    ///   (`import_key`, `update_webvh_server`, the legacy `backup/*` pair, …)
    ///   — stays on DIDComm **unconditionally**. It has no TSP dispatcher behind
    ///   it, so moving it would break it; that is why TSP is a per-surface
    ///   choice and not a client-wide one.
    ///
    /// # Cost
    ///
    /// **No I/O, and it cannot fail on the transport.** TSP send is an HTTP post
    /// to the mediator and TSP receive already arrives on the existing socket,
    /// so there is nothing to connect.
    ///
    /// Get `tsp_mediator_did` from
    /// [`resolve_vta_endpoint`](crate::session::resolve_vta_endpoint) — it reads
    /// the `#tsp` (`TSPTransport`) service entry, which is **not** assumed to
    /// match the DIDComm mediator. When it doesn't match, this refuses and names
    /// [`attach_tsp_leg`](Self::attach_tsp_leg): a different mediator genuinely
    /// needs its own session, and that one needs key material a `DIDCommSession`
    /// deliberately does not keep.
    ///
    /// Errors with [`VtaError::Validation`] on a non-DIDComm client: a REST
    /// client has no session to ride, and a [`connect_tsp`](Self::connect_tsp)
    /// client is already entirely on TSP.
    #[cfg(all(feature = "session", feature = "tsp"))]
    pub fn enable_tsp_trust_tasks(&mut self, tsp_mediator_did: &str) -> Result<(), VtaError> {
        let Transport::DIDComm { session, tsp, .. } = &mut self.transport else {
            return Err(VtaError::Validation(
                "enable_tsp_trust_tasks needs a DIDComm client — TSP rides its mediator \
                 session. Connect with `connect_didcomm` first, or use `connect_tsp` for a \
                 TSP-only client."
                    .into(),
            ));
        };

        match tsp_leg_kind(session.mediator_did(), tsp_mediator_did) {
            TspLegKind::Multiplexed => {
                *tsp = Some(TspLeg::Multiplexed);
                Ok(())
            }
            TspLegKind::Separate => Err(VtaError::Validation(format!(
                "this VTA advertises its TSP mediator ({tsp_mediator_did}) separately from \
                 its DIDComm mediator ({}), so TSP cannot ride the DIDComm session — build \
                 a TspSession against the TSP mediator and pass it to `attach_tsp_leg`, or \
                 use `connect_didcomm_with_tsp`, which does both.",
                session.mediator_did()
            ))),
        }
    }

    /// Attach a **separately-connected** TSP session as this DIDComm client's
    /// Trust-Task leg, for the split-mediator topology where the VTA's `#tsp`
    /// endpoint names a different mediator from its `#vta-didcomm` one.
    ///
    /// The client takes ownership: [`shutdown`](Self::shutdown) closes this
    /// session along with the DIDComm one.
    ///
    /// **Refuses when the two mediators are the same.** A second socket for one
    /// DID on one mediator is `duplicate-channel` and duelling reconnect loops
    /// (#803) — the very defect this whole surface exists to prevent — so that
    /// case is not merely discouraged here, it is unrepresentable. Use
    /// [`enable_tsp_trust_tasks`](Self::enable_tsp_trust_tasks), which is free.
    #[cfg(all(feature = "session", feature = "tsp"))]
    pub fn attach_tsp_leg(
        &mut self,
        tsp_session: std::sync::Arc<crate::session::TspSession>,
        tsp_mediator_did: &str,
    ) -> Result<(), VtaError> {
        let Transport::DIDComm { session, tsp, .. } = &mut self.transport else {
            return Err(VtaError::Validation(
                "attach_tsp_leg needs a DIDComm client — the TSP leg is the Trust-Task half \
                 of a two-transport client. Use `connect_tsp` for a TSP-only client."
                    .into(),
            ));
        };
        if tsp_leg_kind(session.mediator_did(), tsp_mediator_did) == TspLegKind::Multiplexed {
            return Err(VtaError::Validation(format!(
                "refusing to attach a second session for {} on mediator {tsp_mediator_did}: \
                 the mediator permits one websocket per DID, so this would be evicted as \
                 `duplicate-channel`. This VTA advertises the same mediator for TSP and \
                 DIDComm — call `enable_tsp_trust_tasks` instead (no second socket needed).",
                session.client_did()
            )));
        }
        *tsp = Some(TspLeg::Separate {
            session: tsp_session,
            mediator_did: tsp_mediator_did.to_string(),
        });
        Ok(())
    }

    /// Connect via DIDComm and put the Trust-Task surface on TSP in one call,
    /// picking the right leg for the VTA's topology: the DIDComm session's own
    /// socket when both services name the same mediator, otherwise a TSP session
    /// against the separate one.
    ///
    /// The same [`shutdown`](Self::shutdown) contract applies — and it closes
    /// both legs.
    #[cfg(all(feature = "session", feature = "tsp"))]
    pub async fn connect_didcomm_with_tsp(
        client_did: &str,
        private_key_multibase: &str,
        vta_did: &str,
        mediator_did: &str,
        tsp_mediator_did: &str,
        rest_url: Option<String>,
    ) -> Result<Self, VtaError> {
        let mut client = Self::connect_didcomm(
            client_did,
            private_key_multibase,
            vta_did,
            mediator_did,
            rest_url,
        )
        .await?;

        let attached = match tsp_leg_kind(mediator_did, tsp_mediator_did) {
            TspLegKind::Multiplexed => client.enable_tsp_trust_tasks(tsp_mediator_did),
            TspLegKind::Separate => {
                tracing::debug!(
                    didcomm_mediator = %mediator_did,
                    tsp_mediator = %tsp_mediator_did,
                    "VTA advertises a separate TSP mediator; connecting a TSP session for it"
                );
                match crate::session::TspSession::connect(
                    client_did,
                    private_key_multibase,
                    tsp_mediator_did,
                )
                .await
                {
                    Ok(s) => client.attach_tsp_leg(std::sync::Arc::new(s), tsp_mediator_did),
                    Err(e) => Err(VtaError::TspTransport(e.to_string())),
                }
            }
        };

        // Shut the DIDComm session down rather than leaking it if the TSP leg
        // can't be established — this constructor either returns a whole client
        // or nothing.
        if let Err(e) = attached {
            client.shutdown().await;
            return Err(e);
        }
        Ok(client)
    }

    /// Which transport carries the **Trust-Task** surface
    /// ([`dispatch_trust_task`](Self::dispatch_trust_task), `rpc_tt`, the
    /// `device/*` and `vault/*` methods).
    ///
    /// Pairs with [`protocol_message_transport`](Self::protocol_message_transport):
    /// a client can be on TSP for one and DIDComm for the other, so rendering a
    /// single "transport" for a `VtaClient` is wrong.
    pub fn trust_task_transport(&self) -> SurfaceTransport {
        match &self.transport {
            Transport::Rest { .. } => SurfaceTransport::Rest,
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => SurfaceTransport::Tsp,
            #[cfg(feature = "session")]
            Transport::DIDComm {
                #[cfg(feature = "tsp")]
                tsp,
                ..
            } => {
                #[cfg(feature = "tsp")]
                if tsp.is_some() {
                    return SurfaceTransport::Tsp;
                }
                SurfaceTransport::Didcomm
            }
        }
    }

    /// Which transport carries the older DIDComm **protocol-message** surface
    /// ([`rpc`](Self::rpc) — `import_key`, `update_webvh_server`, the legacy
    /// `backup/*` pair, …).
    ///
    /// Never TSP: the VTA has no TSP dispatcher for these, so they report
    /// [`VtaError::UnsupportedTransport`] on a TSP-only client rather than being
    /// silently routed somewhere that cannot serve them.
    pub fn protocol_message_transport(&self) -> SurfaceTransport {
        match &self.transport {
            Transport::Rest { .. } => SurfaceTransport::Rest,
            #[cfg(feature = "session")]
            Transport::DIDComm { .. } => SurfaceTransport::Didcomm,
            // A TSP-only client cannot serve this surface at all; naming DIDComm
            // here would claim a leg it does not have, so report TSP and let the
            // call itself fail with the message that names the fix.
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => SurfaceTransport::Tsp,
        }
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
            // Intrinsic-sender auth — there is no bearer token on this path.
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => {}
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
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => {}
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
            #[cfg(feature = "tsp")]
            Transport::Tsp { rest_url, .. } => rest_url.as_deref(),
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
            #[cfg(feature = "tsp")]
            Transport::Tsp { vta_did, .. } => Some(vta_did),
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
            #[cfg(feature = "tsp")]
            Transport::Tsp {
                vta_did, rest_url, ..
            } => rest_url.as_deref().unwrap_or(vta_did),
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
        // A `Separate` TSP leg owns its own socket, so it leaks exactly like a
        // DIDComm session would if nothing closed it. `Multiplexed` has nothing
        // of its own — the DIDComm shutdown above already took its socket down.
        #[cfg(all(feature = "session", feature = "tsp"))]
        if let Transport::DIDComm {
            tsp: Some(TspLeg::Separate { session, .. }),
            ..
        } = &self.transport
        {
            session.shutdown().await;
        }
        // Same one-websocket-per-DID contract as DIDComm: a leaked TSP session
        // makes the next connect for this DID fight the old one.
        #[cfg(feature = "tsp")]
        if let Transport::Tsp { session, .. } = &self.transport {
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
    /// The DID this client sends as, when the transport has one.
    ///
    /// `None` over REST: a REST client authenticates with a bearer token, and
    /// the token's subject is the VTA's business, not something to be inferred
    /// here. Callers that need the DID on REST take it from the operator.
    pub fn caller_did(&self) -> Option<&str> {
        match &self.transport {
            Transport::Rest { .. } => None,
            #[cfg(feature = "session")]
            Transport::DIDComm { session, .. } => Some(session.client_did()),
            #[cfg(feature = "tsp")]
            Transport::Tsp { session, .. } => Some(session.client_did()),
        }
    }

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
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => Err(unsupported_over_tsp(msg_type)),
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
            // Same trust-task path as DIDComm — `dispatch_trust_task` picks the
            // transport, so this surface needed no per-operation work to reach
            // TSP.
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => {
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
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => {
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
            // The whole typed VTA surface over TSP. The VTA's inbound
            // dispatcher hands the unpacked payload straight to
            // `dispatch_trust_task_core` — the same spine REST and DIDComm use
            // — so the request and reply documents are byte-identical across
            // all three transports. No envelope wrapper: TSP carries the
            // Trust-Task bytes directly.
            #[cfg(feature = "tsp")]
            Transport::Tsp {
                session,
                vta_did,
                mediator_did,
                ..
            } => {
                let body = Self::address_trust_task(doc, session.client_did(), vta_did)?;
                let reply = session
                    .request(
                        vta_did,
                        mediator_did,
                        &body,
                        std::time::Duration::from_secs(timeout),
                    )
                    .await
                    .map_err(|e| VtaError::TspTransport(e.to_string()))?;
                Self::extract_trust_task_payload(Self::decode_trust_task_reply(&reply)?)
            }
            #[cfg(feature = "session")]
            Transport::DIDComm {
                session,
                #[cfg(feature = "tsp")]
                tsp,
                ..
            } => {
                // Per-surface routing: with a TSP leg attached, trust tasks go
                // over TSP while `rpc` keeps using this same session's DIDComm
                // leg. The document is byte-identical either way — the VTA's TSP
                // inbound dispatcher and its DIDComm envelope handler both feed
                // `dispatch_trust_task_core`.
                #[cfg(feature = "tsp")]
                if let Some(leg) = tsp {
                    let body =
                        Self::address_trust_task(doc, session.client_did(), &session.vta_did)?;
                    let timeout = std::time::Duration::from_secs(timeout);
                    let reply = match leg {
                        // Rides the DIDComm session's own socket — no second
                        // websocket for this DID (#803).
                        TspLeg::Multiplexed => {
                            session
                                .request_tsp(&session.vta_did, &body, timeout)
                                .await?
                        }
                        TspLeg::Separate {
                            session: tsp_session,
                            mediator_did,
                        } => tsp_session
                            .request(&session.vta_did, mediator_did, &body, timeout)
                            .await
                            .map_err(|e| VtaError::TspTransport(e.to_string()))?,
                    };
                    return Self::extract_trust_task_payload(Self::decode_trust_task_reply(
                        &reply,
                    )?);
                }

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

    /// Address a trust-task document for a **mediator** transport and serialize
    /// it.
    ///
    /// `issuer`/`recipient` are set here rather than at document construction
    /// because only a mediator transport knows both DIDs — the REST leg posts to
    /// an already-addressed endpoint. Shared by every TSP path so the wire shape
    /// cannot drift between them.
    #[cfg(feature = "tsp")]
    fn address_trust_task(
        mut doc: serde_json::Value,
        issuer: &str,
        recipient: &str,
    ) -> Result<Vec<u8>, VtaError> {
        doc["issuer"] = serde_json::Value::String(issuer.to_string());
        doc["recipient"] = serde_json::Value::String(recipient.to_string());
        serde_json::to_vec(&doc).map_err(|e| VtaError::Protocol(format!("trust-task encode: {e}")))
    }

    /// Parse a TSP reply frame back into a trust-task response document.
    #[cfg(feature = "tsp")]
    fn decode_trust_task_reply(reply: &str) -> Result<serde_json::Value, VtaError> {
        serde_json::from_str(reply)
            .map_err(|e| VtaError::Protocol(format!("trust-task reply decode: {e}")))
    }

    /// Pull `payload` out of a framework trust-task response document. A success
    /// document carries `payload`; a rejection does not — surface its
    /// `reason`/`comment` (or the whole document) as a protocol error so the
    /// DIDComm path (which drops the HTTP status) still fails loudly.
    fn extract_trust_task_payload(doc: serde_json::Value) -> Result<serde_json::Value, VtaError> {
        if let Some(payload) = doc.get("payload") {
            // A failed task still carries a `payload` — the error envelope goes
            // *inside* it (`{ code, message, retryable }`). Treating "a payload
            // is present" as success therefore hands the caller an error object
            // to deserialise as a result, and the caller reports whatever field
            // its result type happened to be missing. The real message — which
            // may be as specific as "not supported over the DIDComm transport" —
            // is discarded, and the failure reads like a schema mismatch.
            //
            // Keyed on `code` + `message`, mirroring the service's own denial
            // check (`vta-service`'s trust-task `denial_code`, which reads
            // `payload.code`).
            if let Some(err) = Self::trust_task_error(payload) {
                return Err(err);
            }
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

    /// Recognise a trust-task error envelope carried inside `payload`.
    ///
    /// Requires **both** `code` and `message` to be strings: `code` alone is a
    /// plausible field on a legitimate result body, so demanding the pair keeps
    /// a successful response from being mistaken for a failure.
    fn trust_task_error(payload: &serde_json::Value) -> Option<VtaError> {
        let code = payload.get("code")?.as_str()?;
        let message = payload.get("message")?.as_str()?;

        // A consent refusal is not a dead end — it is a question the caller can
        // answer — so it gets a variant carrying what answering requires. The
        // gate puts the machine-readable reason in `details.reason` precisely
        // so a consumer keys on a stable field rather than the top-level `code`
        // (`taskFailed` for every gated task) or the free-text message.
        if let Some(details) = payload.get("details")
            && details.get("reason").and_then(|r| r.as_str()) == Some("auth:consent_required")
        {
            let s = |k: &str| {
                details
                    .get(k)
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string()
            };
            return Some(VtaError::ConsentRequired {
                payload_digest: s("payloadDigest"),
                challenge: s("challenge"),
                approver_set: s("approverSet"),
                min_approvals: details
                    .get("minApprovals")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(1) as u32,
                // Absent on a server older than the field. `true` is the
                // conservative read: it tells the caller to wait for another
                // device rather than to offer a self-approval that the gate
                // would refuse with `denied:requester_excluded`.
                exclude_requester: details
                    .get("excludeRequester")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true),
            });
        }

        Some(VtaError::Protocol(format!(
            "trust task failed [{code}]: {message}"
        )))
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
            // A TSP client *has* key material, but the seal is specifically a
            // `didcomm-authcrypt` JWE — a wire format tied to the DIDComm
            // stack, not to holding keys. Producing one here would need the
            // DIDComm packer this transport deliberately does not carry.
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => Err(VtaError::UnsupportedTransport(
                "sealing a vault secret produces a didcomm-authcrypt JWE, which \
                 requires the DIDComm transport:\n  <cli> --transport didcomm <command>"
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
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => Err(VtaError::UnsupportedTransport(
                "opening a sealed vault secret unwraps a didcomm-authcrypt JWE, which \
                 requires the DIDComm transport:\n  <cli> --transport didcomm <command>"
                    .into(),
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
            // TSP has a real receive path: `TspSession::receive_next` hands
            // back frames that matched no in-flight `request` — i.e. exactly
            // the unsolicited pushes this method is for.
            #[cfg(feature = "tsp")]
            Transport::Tsp { session, .. } => session
                .receive_next(timeout_secs)
                .await
                .map_err(|e| VtaError::TspTransport(e.to_string())),
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
            // Named for the DIDComm wire format it emits. TSP's own
            // fire-and-forget send is `TspSession::send_document`.
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => Err(VtaError::UnsupportedTransport(
                "one-way DIDComm send requires the DIDComm transport:\n  \
                 <cli> --transport didcomm <command>"
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
            #[cfg(feature = "tsp")]
            Transport::Tsp {
                rest_client,
                rest_url,
                ..
            } => match (rest_client, rest_url) {
                (Some(client), Some(url)) => {
                    let resp = client.get(format!("{url}/health")).send().await?;
                    Self::handle_response(resp).await
                }
                _ => Err(VtaError::UnsupportedTransport(
                    "health check not available via TSP (no REST URL)".into(),
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
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => Err(VtaError::UnsupportedTransport(
                "step-up policy read is REST-only in the SDK; over TSP send the \
                 `auth/step-up/policy/0.2` trust task instead"
                    .into(),
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
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => Err(VtaError::UnsupportedTransport(
                "step-up policy set is REST-only in the SDK; send the \
                 auth/step-up/policy/0.2 trust-task over TSP instead"
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
        self.rpc_tt(
            crate::trust_tasks::TASK_DISCOVERY_CAPABILITIES_1_0,
            serde_json::json!({}),
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
            // Same reasoning: the sender VID is proven by the TSP unpack, so
            // there is no token that could be invalid or expired.
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => Ok(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyType;

    // ── consent refusals ────────────────────────────────────────────

    /// A `requireConsent` refusal must arrive as something a caller can act
    /// on, not a flat string.
    ///
    /// The fixture is the gate's real shape: `code` is `taskFailed` for every
    /// gated task and the message is free text, so the machine-readable answer
    /// lives in `details.reason` — keying on anything else would match the
    /// wrong rejections or none. Folded into `Protocol(String)`, the digest and
    /// challenge were discarded, and a CLI could only print the refusal and
    /// exit; that is why a consent-gated task was unreachable from `pnm`.
    #[test]
    fn a_consent_refusal_carries_what_answering_it_needs() {
        let payload = serde_json::json!({
            "code": "taskFailed",
            "message": "task failed: auth:consent_required",
            "details": {
                "reason": "auth:consent_required",
                "payloadDigest": "A1B2C3",
                "challenge": "chal-xyz",
                "approverSet": "webvh-approvers",
                "minApprovals": 1,
                "excludeRequester": true,
                "consentRequests": [],
            }
        });

        match VtaClient::trust_task_error(&payload) {
            Some(VtaError::ConsentRequired {
                payload_digest,
                challenge,
                approver_set,
                min_approvals,
                exclude_requester,
            }) => {
                assert_eq!(payload_digest, "A1B2C3");
                assert_eq!(challenge, "chal-xyz");
                assert_eq!(approver_set, "webvh-approvers");
                assert_eq!(min_approvals, 1);
                assert!(exclude_requester, "the two-device posture must be reported");
            }
            other => panic!("expected ConsentRequired, got {other:?}"),
        }
    }

    /// Against a server that predates `excludeRequester`, assume the
    /// restrictive answer. Guessing `false` would have the CLI offer a
    /// self-approval the gate then refuses with `denied:requester_excluded`;
    /// guessing `true` only tells the operator to use another device, which is
    /// correct whenever a second device exists.
    #[test]
    fn an_absent_exclude_requester_defaults_to_the_restrictive_reading() {
        let payload = serde_json::json!({
            "code": "taskFailed",
            "message": "task failed: auth:consent_required",
            "details": { "reason": "auth:consent_required", "challenge": "c" }
        });
        match VtaClient::trust_task_error(&payload) {
            Some(VtaError::ConsentRequired {
                exclude_requester, ..
            }) => assert!(exclude_requester),
            other => panic!("expected ConsentRequired, got {other:?}"),
        }
    }

    /// Every other failure keeps its existing shape — the new variant must not
    /// swallow unrelated rejections that merely carry a `details` object.
    #[test]
    fn a_non_consent_failure_is_still_a_protocol_error() {
        let payload = serde_json::json!({
            "code": "malformedRequest",
            "message": "payload does not conform",
            "details": { "reason": "schema:invalid" }
        });
        assert!(matches!(
            VtaClient::trust_task_error(&payload),
            Some(VtaError::Protocol(_))
        ));
    }

    // ── extract_trust_task_payload ──────────────────────────────────

    /// A successful task returns its payload untouched.
    #[test]
    fn extract_returns_a_success_payload() {
        let doc = serde_json::json!({
            "id": "urn:uuid:1", "type": "spec/vta/x/1.0",
            "payload": { "did": "did:webvh:QmScid:example.com", "names": [] },
        });
        let got = VtaClient::extract_trust_task_payload(doc).expect("should succeed");
        assert_eq!(got["did"], "did:webvh:QmScid:example.com");
    }

    /// The regression: a *failed* task also carries a `payload`, holding the
    /// error envelope. Returning it as success made callers deserialise an error
    /// object as a result and report a missing field, hiding the real cause.
    ///
    /// Shaped after a rejected `set_agent_name`, where the actionable detail
    /// lives only in the message — the caller cannot act on `internalError`
    /// alone, but "that name is taken" tells them exactly what to do next.
    #[test]
    fn extract_surfaces_an_error_envelope_inside_the_payload() {
        let doc = serde_json::json!({
            "id": "urn:uuid:1", "type": "spec/vta/webvh/agent-name/set/1.0",
            "payload": {
                "code": "internalError",
                "message": "set_agent_name: name_taken: `ops` is already bound on \
                            webvh.storm.ws",
                "retryable": false,
            },
        });
        let err = VtaClient::extract_trust_task_payload(doc).expect_err("must be an error");
        let msg = err.to_string();
        assert!(msg.contains("internalError"), "{msg}");
        assert!(
            msg.contains("name_taken"),
            "the actionable part of the message must survive: {msg}"
        );
    }

    /// `code` without `message` is not treated as an error — a result body may
    /// legitimately carry a `code`, so both are required before failing.
    #[test]
    fn extract_does_not_mistake_a_code_field_for_an_error() {
        let doc = serde_json::json!({
            "payload": { "code": "GB", "country": "United Kingdom" },
        });
        let got = VtaClient::extract_trust_task_payload(doc).expect("code alone is not an error");
        assert_eq!(got["code"], "GB");
    }

    /// A rejection with no payload at all still reports its reason.
    #[test]
    fn extract_reports_a_rejection_without_a_payload() {
        let doc = serde_json::json!({ "id": "urn:uuid:1", "reason": "not authorized" });
        let err = VtaClient::extract_trust_task_payload(doc).expect_err("must be an error");
        assert!(err.to_string().contains("not authorized"), "{err}");
    }

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

    /// The patch carries only the keys the caller named — it is a map, so an
    /// unmentioned key is simply absent rather than an explicit null that a
    /// consumer might read as "clear this".
    #[test]
    fn test_update_config_sends_only_named_keys() {
        use crate::protocols::vta_management::update_config::UpdateConfigBody;
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("vta_name".to_string(), serde_json::json!("Test"));
        let req = UpdateConfigRequest {
            patch: UpdateConfigBody { overrides },
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["overrides"]["vta_name"], "Test");
        assert!(
            !json["overrides"]
                .as_object()
                .unwrap()
                .contains_key("public_url")
        );
        assert!(
            !json["overrides"]
                .as_object()
                .unwrap()
                .contains_key("vta_did")
        );
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
            approve_all_contexts: false,
            approve_contexts: vec![],
            allowed_keys: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        // The builder API is unchanged; only what it serialises moved. The wire
        // is canonical `acl/grant/0.1`: the entry is nested and uses `subject`
        // and `scopes`.
        assert_eq!(json["entry"]["subject"], "did:key:z6Mk123");
        assert_eq!(json["entry"]["role"], "admin");
        assert_eq!(json["entry"]["scopes"][0], "vta");
        assert!(
            json.get("did").is_none(),
            "pre-fold flat shape is gone: {json}"
        );
        // An omitted approver must not appear at all — an empty `stepUp` object
        // would read as a configured-but-blank override rather than absence.
        assert!(json["entry"].get("stepUp").is_none());
        assert!(json["entry"].get("approve").is_none());
        // An unset label is omitted rather than emitted as null.
        assert!(!json["entry"].as_object().unwrap().contains_key("label"));
        assert_eq!(json["entry"]["scopes"], serde_json::json!(["vta"]));
        // And the pre-fold member name is not emitted alongside the new one.
        assert!(json["entry"].get("allowedContexts").is_none(), "{json}");
    }

    #[test]
    fn test_update_acl_request_all_none() {
        let req = UpdateAclRequest {
            label: None,
            allowed_contexts: None,
            step_up_approver: None,
            step_up_require: None,
            approve_scope: None,
            allowed_keys: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.is_empty(), "all-None request should serialize to {{}}");
    }

    /// The `allowedKeys` member of the update request keeps the three-way
    /// distinction on the wire (#818): leave-alone emits nothing, clear emits
    /// an explicit `null`, and the empty list — "no keys at all" — emits `[]`.
    #[test]
    fn test_update_acl_request_allowed_keys_three_intentions() {
        let base = || UpdateAclRequest {
            label: None,
            allowed_contexts: None,
            step_up_approver: None,
            step_up_require: None,
            approve_scope: None,
            allowed_keys: None,
        };

        let set = UpdateAclRequest {
            allowed_keys: Some(Some(vec!["key-1".into()])),
            ..base()
        };
        let json = serde_json::to_value(&set).unwrap();
        assert_eq!(json["allowedKeys"], serde_json::json!(["key-1"]));

        let clear = UpdateAclRequest {
            allowed_keys: Some(None),
            ..base()
        };
        let json = serde_json::to_value(&clear).unwrap();
        assert!(
            json["allowedKeys"].is_null(),
            "clear is explicit null: {json}"
        );

        let none_at_all = UpdateAclRequest {
            allowed_keys: Some(Some(vec![])),
            ..base()
        };
        let json = serde_json::to_value(&none_at_all).unwrap();
        assert_eq!(
            json["allowedKeys"],
            serde_json::json!([]),
            "the empty list must be emitted, not skipped: {json}"
        );
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
        // Canonical wire: `subject`/`scopes`, RFC 3339 timestamps. The Rust
        // field names stay historical so the CLI and the VTC's ACL routes did
        // not have to move in the same change.
        let json = r#"{"entries":[{"subject":"did:key:z6Mk1","role":"admin","label":null,"scopes":[],"createdAt":"2023-11-14T22:13:20Z","createdBy":"setup"}],"truncated":false}"#;
        let resp: AclListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.entries.len(), 1);
        assert_eq!(resp.entries[0].did, "did:key:z6Mk1");
        assert_eq!(resp.entries[0].role, "admin");
        assert!(resp.entries[0].allowed_contexts.is_empty());
        assert_eq!(resp.entries[0].created_at, 1_700_000_000);
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

    // ── TSP leg selection (#803) ────────────────────────────────────

    /// The reference topology: a VTA advertising the **same** mediator for
    /// `#tsp` and `#vta-didcomm`. TSP must ride the DIDComm session's existing
    /// socket — the mediator permits one websocket per DID, so a second one for
    /// this DID is `duplicate-channel` and duelling reconnect loops.
    #[cfg(all(feature = "session", feature = "tsp"))]
    #[test]
    fn same_mediator_multiplexes_rather_than_opening_a_second_socket() {
        let mediator = "did:webvh:QmTS3a:webvh.storm.ws:mediator";
        assert_eq!(tsp_leg_kind(mediator, mediator), TspLegKind::Multiplexed);
    }

    /// Split-mediator deployments are legitimate — `Transport::Tsp` explicitly
    /// does not assume the two are equal — and there a second socket is fine,
    /// because the one-websocket-per-DID rule is per mediator.
    #[cfg(all(feature = "session", feature = "tsp"))]
    #[test]
    fn a_separate_tsp_mediator_gets_its_own_session() {
        assert_eq!(
            tsp_leg_kind(
                "did:webvh:QmTS3a:webvh.storm.ws:mediator",
                "did:web:tsp-mediator.example.com",
            ),
            TspLegKind::Separate
        );
    }

    // ── Per-surface transport reporting ─────────────────────────────

    /// A REST client is on REST for everything — no per-surface split to make.
    #[test]
    fn a_rest_client_reports_rest_for_both_surfaces() {
        let client = VtaClient::new("https://vta.example.com");
        assert_eq!(client.trust_task_transport(), SurfaceTransport::Rest);
        assert_eq!(client.protocol_message_transport(), SurfaceTransport::Rest);
    }

    #[test]
    fn surface_transport_renders_the_operator_facing_name() {
        assert_eq!(SurfaceTransport::Tsp.to_string(), "TSP");
        assert_eq!(SurfaceTransport::Didcomm.to_string(), "DIDComm");
        assert_eq!(SurfaceTransport::Rest.to_string(), "REST");
    }
}
