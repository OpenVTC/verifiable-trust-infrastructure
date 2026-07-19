use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use serde::{Deserialize, Serialize};
use serde_json;
use tracing::debug;

use crate::credentials::CredentialBundle;
use crate::protocols::auth::{AuthenticateResponse, ChallengeRequest, ChallengeResponse};

/// Test-support types (public `SessionBackend` mock for consumers'
/// integration tests). Compiled for unit tests and whenever the
/// `test-support` feature is enabled by downstream crates.
#[cfg(any(test, feature = "test-support"))]
pub mod testing;

// ── Session (internal) ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Session {
    client_did: String,
    private_key: String,
    /// `None` in the `PendingVtaBinding` state — the client DID has been
    /// minted locally but the operator has not yet supplied the VTA DID
    /// to bind to. `Some` in both `PendingRotation` (combined with
    /// `needs_rotation = true`) and `Direct` (no rotation) states. See
    /// `SessionStore::store_pending_vta_binding` + `bind_vta_did`.
    #[serde(default)]
    vta_did: Option<String>,
    access_token: Option<String>,
    access_expires_at: Option<u64>,
    /// Marks a session whose `client_did` was minted locally with no live
    /// VTA to register it against — the user has been told to ask their
    /// admin to run `vta acl create --did <did>`. On the first successful
    /// authentication we atomically rotate to a fresh did:key and drop
    /// the original from the ACL, so the DID the user initially exposed
    /// (maybe over chat/email) does not remain long-lived.
    #[serde(default)]
    needs_rotation: bool,
}

/// Pull the VTA DID out of a session or error with the deferred-setup
/// hint. Used at every authenticated-operation entry point so a
/// `PendingVtaBinding` session surfaces as a clean error rather than a
/// panic when downstream code tries to unwrap.
///
/// This is the SDK-side defensive backstop. The CLI should gate on
/// [`SessionStore::has_pending_vta_binding`] before reaching these
/// functions; if it does, operators never see this string.
fn require_vta_did(session: &Session) -> Result<&str, Box<dyn std::error::Error>> {
    session.vta_did.as_deref().ok_or_else(|| {
        "session is pending VTA binding — run `pnm setup continue <slug>` to supply the VTA DID"
            .into()
    })
}

// ── Public types ────────────────────────────────────────────────────

/// Loaded session info exposed for health/diagnostics.
///
/// `vta_did` is `None` when the session is in the `PendingVtaBinding`
/// state — the client DID was minted but the operator has not yet
/// supplied the VTA DID.
///
/// The `private_key_multibase` is included so diagnostics can render
/// the public half (via `did:key` derivation) without re-loading the
/// session. `Debug` is hand-implemented to redact it.
#[derive(Clone)]
pub struct SessionInfo {
    pub client_did: String,
    pub vta_did: Option<String>,
    pub private_key_multibase: String,
}

impl std::fmt::Debug for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionInfo")
            .field("client_did", &self.client_did)
            .field("vta_did", &self.vta_did)
            .field("private_key_multibase", &"<redacted>")
            .finish()
    }
}

/// Status of a stored session.
///
/// See [`SessionInfo`] for the `vta_did` semantics. The VTA's REST URL
/// is not part of session state — callers resolve it from the VTA DID
/// document at runtime via [`resolve_vta_url`] or
/// [`resolve_vta_endpoint`].
#[derive(Debug, Clone)]
pub struct SessionStatus {
    pub client_did: String,
    pub vta_did: Option<String>,
    pub token_status: TokenStatus,
}

/// Current state of a cached access token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenStatus {
    Valid { expires_in_secs: u64 },
    Expired,
    None,
}

/// Result of a successful login.
///
/// `vta_did` is always `Some` here — you cannot log in without one.
/// Kept as `Option<String>` to match the cascaded field shape across
/// the session types; callers can `.expect("login succeeded")` if they
/// truly need the unwrapped value.
#[derive(Debug, Clone)]
pub struct LoginResult {
    pub client_did: String,
    pub vta_did: Option<String>,
}

/// Result of an authentication exchange. `Debug` is hand-implemented to
/// redact the access token — bearer-equivalent material that should not
/// land in `tracing::debug!("{result:?}")` or panic backtraces.
#[derive(Clone)]
pub struct TokenResult {
    pub access_token: String,
    pub access_expires_at: u64,
}

impl std::fmt::Debug for TokenResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResult")
            .field("access_token", &"<redacted>")
            .field("access_expires_at", &self.access_expires_at)
            .finish()
    }
}

// ── SessionBackend trait ────────────────────────────────────────────

/// Pluggable storage backend for VTA session credentials.
///
/// Implement this trait to store VTA sessions in a custom backend
/// (e.g., the same secrets store your application already uses).
///
/// The `key` parameter identifies the session (e.g., "default", "setup").
/// The `value` is a JSON-serialized session blob containing credentials
/// and cached tokens.
pub trait SessionBackend: Send + Sync {
    /// Load a session by key. Returns `None` if not found.
    fn load(&self, key: &str) -> Option<String>;
    /// Store a session. The value is JSON-serialized session data.
    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>>;
    /// Remove a session by key.
    fn clear(&self, key: &str);
}

// ── Built-in backends ───────────────────────────────────────────────
//
// Each backend lives in `session/backends/<name>.rs`; the module
// selects among them via `default_backend` based on compiled features.

mod backends;

use backends::default_backend;

// ── SessionStore ────────────────────────────────────────────────────

/// Reusable session storage for VTA authentication.
///
/// Uses a pluggable [`SessionBackend`] for credential persistence.
/// By default, the backend is selected based on compiled features
/// (keyring → azure → config-file → plaintext). Consumers can
/// provide their own backend via [`SessionStore::with_backend`].
pub struct SessionStore {
    backend: Box<dyn SessionBackend>,
}

impl SessionStore {
    /// Create a new session store with the default backend.
    ///
    /// The backend is selected based on compiled features:
    /// - `keyring` → OS keyring (uses `service_name`)
    /// - `azure-secrets` → Azure Key Vault (uses `service_name` as prefix)
    /// - `config-session` → local JSON file (uses `sessions_dir`)
    /// - fallback → plaintext JSON file with warning
    pub fn new(service_name: &str, sessions_dir: PathBuf) -> Self {
        Self {
            backend: default_backend(service_name, sessions_dir),
        }
    }

    /// Create a session store with a custom backend.
    ///
    /// Use this to integrate with your application's existing secrets
    /// storage (e.g., AWS Secrets Manager, GCP Secret Manager, etc.).
    pub fn with_backend(backend: Box<dyn SessionBackend>) -> Self {
        Self { backend }
    }

    // ── Internal session serialization ───────────────────────────────

    fn load_session(&self, key: &str) -> Option<Session> {
        let json = self.backend.load(key)?;
        serde_json::from_str(&json).ok()
    }

    fn save_session(&self, key: &str, session: &Session) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(session)?;
        self.backend.save(key, &json)
    }

    fn clear_session(&self, key: &str) {
        self.backend.clear(key);
    }

    // ── Public API ──────────────────────────────────────────────────

    /// Returns true if a session exists for the given key.
    pub fn has_session(&self, key: &str) -> bool {
        self.load_session(key).is_some()
    }

    /// Store a credential bundle and authenticate.
    ///
    /// Returns `LoginResult` on success (no printing).
    pub async fn login(
        &self,
        bundle: &CredentialBundle,
        base_url: &str,
        key: &str,
    ) -> Result<LoginResult, Box<dyn std::error::Error>> {
        debug!(
            client_did = %bundle.did,
            vta_did = %bundle.vta_did,
            "login with credential bundle"
        );

        let mut session = Session {
            client_did: bundle.did.clone(),
            private_key: bundle.private_key_multibase.clone(),
            vta_did: Some(bundle.vta_did.clone()),
            access_token: None,
            access_expires_at: None,
            needs_rotation: false,
        };
        self.save_session(key, &session)?;
        debug!(keyring_key = key, "session saved");

        // Perform authentication
        let token = challenge_response(
            base_url,
            &bundle.did,
            &bundle.private_key_multibase,
            &bundle.vta_did,
        )
        .await?;

        session.access_token = Some(token.access_token);
        session.access_expires_at = Some(token.access_expires_at);
        self.save_session(key, &session)?;

        Ok(LoginResult {
            client_did: bundle.did.clone(),
            vta_did: Some(bundle.vta_did.clone()),
        })
    }

    /// Store a session directly (without performing authentication).
    ///
    /// The VTA's REST endpoint is resolved at runtime from the VTA DID
    /// document on every command (see [`resolve_vta_url`] /
    /// [`resolve_vta_endpoint`]); it is no longer persisted in session
    /// state. Per-command CLI overrides (e.g. `--url`) remain ephemeral.
    pub fn store_direct(
        &self,
        key: &str,
        did: &str,
        private_key: &str,
        vta_did: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let session = Session {
            client_did: did.to_string(),
            private_key: private_key.to_string(),
            vta_did: Some(vta_did.to_string()),
            access_token: None,
            access_expires_at: None,
            needs_rotation: false,
        };
        self.save_session(key, &session)
    }

    /// Store a session marked for rotation on first successful authentication.
    ///
    /// Use this when the client has generated a did:key locally and handed
    /// it to a human to add to the VTA's ACL. Once the VTA is reachable and
    /// the ACL entry exists, `ensure_authenticated()` will atomically rotate
    /// to a fresh did:key and drop the temp one, so the DID that may have
    /// been copy-pasted through a low-trust channel does not remain live.
    pub fn store_pending_rotation(
        &self,
        key: &str,
        did: &str,
        private_key: &str,
        vta_did: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let session = Session {
            client_did: did.to_string(),
            private_key: private_key.to_string(),
            vta_did: Some(vta_did.to_string()),
            access_token: None,
            access_expires_at: None,
            needs_rotation: true,
        };
        self.save_session(key, &session)
    }

    /// Store an ephemeral did:key with no VTA DID bound yet.
    ///
    /// This is the `PendingVtaBinding` state used by the deferred-VTA-DID
    /// `pnm setup` flow: phase 1 mints the DID and parks it in the keyring;
    /// phase 2 lifts the entry into a `PendingRotation` session via
    /// [`Self::bind_vta_did`] once the operator supplies the VTA DID.
    ///
    /// A session in this state is **not** usable for authentication. Callers
    /// should gate authenticated operations on
    /// [`Self::has_pending_vta_binding`] and route operators to
    /// `pnm setup continue <slug>` before attempting to authenticate.
    pub fn store_pending_vta_binding(
        &self,
        key: &str,
        did: &str,
        private_key: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if key.trim().is_empty() {
            return Err("keyring key must be non-empty".into());
        }
        if !did.starts_with("did:key:") {
            return Err(
                "pending ephemeral DID must be a did:key (minted locally by the SDK)".into(),
            );
        }
        if private_key.trim().is_empty() {
            return Err("private key multibase must be non-empty".into());
        }
        let session = Session {
            client_did: did.to_string(),
            private_key: private_key.to_string(),
            vta_did: None,
            access_token: None,
            access_expires_at: None,
            needs_rotation: false,
        };
        self.save_session(key, &session)
    }

    /// Lift a `PendingVtaBinding` session into a `PendingRotation` session
    /// by supplying the VTA DID.
    ///
    /// Preserves the ephemeral did:key + private key from phase 1 and sets
    /// `needs_rotation = true`, so the first successful authenticate triggers
    /// the same auto-rotate-off-the-temp-DID flow as
    /// [`Self::store_pending_rotation`].
    ///
    /// Errors if:
    /// - the entry is missing at `key`;
    /// - the entry already has a VTA DID bound (re-binding is not allowed —
    ///   use `logout` + re-provision instead);
    /// - `vta_did` is empty after trim, or does not start with `did:`.
    pub fn bind_vta_did(&self, key: &str, vta_did: &str) -> Result<(), Box<dyn std::error::Error>> {
        let vta_did = vta_did.trim();
        if vta_did.is_empty() {
            return Err("VTA DID must be non-empty".into());
        }
        if !vta_did.starts_with("did:") {
            return Err(
                "VTA DID must start with `did:` (e.g. did:webvh:..., did:web:..., did:key:...)"
                    .into(),
            );
        }
        let mut session = self
            .load_session(key)
            .ok_or("no session found — cannot bind VTA DID to a non-existent entry")?;
        if session.vta_did.is_some() {
            return Err("session already has a VTA DID bound".into());
        }
        session.vta_did = Some(vta_did.to_string());
        session.needs_rotation = true;
        self.save_session(key, &session)
    }

    /// Report whether the entry at `key` is a `PendingVtaBinding` session
    /// (exists, parses, and has `vta_did: None`). Total — no errors.
    pub fn has_pending_vta_binding(&self, key: &str) -> bool {
        match self.load_session(key) {
            Some(session) => session.vta_did.is_none(),
            None => false,
        }
    }

    /// Clear stored credentials and cached tokens.
    pub fn logout(&self, key: &str) {
        self.clear_session(key);
    }

    /// Load the stored session for diagnostics (DID resolution, etc.).
    pub fn loaded_session(&self, key: &str) -> Option<SessionInfo> {
        self.load_session(key).map(|s| SessionInfo {
            client_did: s.client_did,
            vta_did: s.vta_did,
            private_key_multibase: s.private_key,
        })
    }

    /// Get the status of a stored session.
    pub fn session_status(&self, key: &str) -> Option<SessionStatus> {
        let session = self.load_session(key)?;
        let token_status = match (session.access_token, session.access_expires_at) {
            (Some(_), Some(exp)) => {
                let now = now_epoch();
                if exp > now {
                    TokenStatus::Valid {
                        expires_in_secs: exp - now,
                    }
                } else {
                    TokenStatus::Expired
                }
            }
            _ => TokenStatus::None,
        };
        Some(SessionStatus {
            client_did: session.client_did,
            vta_did: session.vta_did,
            token_status,
        })
    }

    /// Ensure we have a valid access token. Returns the token string.
    ///
    /// If no credentials are stored, returns an error.
    /// If a cached token is still valid (>30s remaining), returns it.
    /// Otherwise, performs a full challenge-response authentication.
    ///
    /// When the loaded session is flagged `needs_rotation`, the first
    /// successful challenge-response triggers an automatic key roll:
    /// a fresh did:key is minted, the VTA ACL entry for the temp DID is
    /// mirrored onto the new DID, the temp DID is removed from the ACL,
    /// and the session is updated in place. See `rotate_key`.
    pub async fn ensure_authenticated(
        &self,
        base_url: &str,
        key: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        debug!(base_url, keyring_key = key, "ensuring authentication");

        let mut session = self.load_session(key).ok_or(
            "Not authenticated.\n\nRun `pnm setup` (or the equivalent) to provision an admin identity.",
        )?;

        let session_vta_did = require_vta_did(&session)?.to_string();

        debug!(
            client_did = %session.client_did,
            vta_did = %session_vta_did,
            needs_rotation = session.needs_rotation,
            "session loaded"
        );

        // Check cached token — but only if we're not pending rotation.
        // A cached token on a pending-rotation session means we rotated in
        // a previous call already, which `rotate_key` handled atomically.
        if !session.needs_rotation
            && let (Some(token), Some(expires_at)) =
                (&session.access_token, session.access_expires_at)
            && now_epoch() + 30 < expires_at
        {
            debug!(expires_in = expires_at - now_epoch(), "using cached token");
            return Ok(token.clone());
        }

        debug!("cached token expired or missing, performing challenge-response");

        // Full challenge-response with the current (possibly temp) identity.
        let result = challenge_response(
            base_url,
            &session.client_did,
            &session.private_key,
            &session_vta_did,
        )
        .await?;

        // If the session was provisioned as a temp did:key, rotate now —
        // before we return the token to the caller or persist the temp
        // token in the session.
        if session.needs_rotation {
            debug!("session is pending rotation, swapping to fresh did:key");
            let (new_session, new_token_result) =
                rotate_key(base_url, session, &result.access_token).await?;
            session = new_session;
            session.access_token = Some(new_token_result.access_token.clone());
            session.access_expires_at = Some(new_token_result.access_expires_at);
            self.save_session(key, &session)?;
            return Ok(new_token_result.access_token);
        }

        let token = result.access_token.clone();
        session.access_token = Some(result.access_token);
        session.access_expires_at = Some(result.access_expires_at);
        self.save_session(key, &session)?;
        debug!("new token cached");

        Ok(token)
    }

    /// Authenticate to a VTA over DIDComm and return a connected
    /// [`crate::client::VtaClient`].
    ///
    /// DIDComm-preferred peer of [`Self::ensure_authenticated`]. Where
    /// the REST path issues a JWT via challenge-response, this path
    /// uses DIDComm authcrypt as the auth: every outbound message is
    /// encrypted to the VTA's recipient key, the VTA decrypts and
    /// reads `from` as the authenticated sender DID, then ACL-checks
    /// it (see `vta-service/src/messaging/auth.rs::auth_from_message`).
    /// No JWT changes hands; no token to expire.
    ///
    /// Pending-rotation parity with the REST path: when the loaded
    /// session is flagged `needs_rotation`, the first successful
    /// connection triggers a key roll over the same DIDComm transport
    /// — read the temp DID's ACL entry, mint a fresh did:key, create
    /// a new ACL entry mirroring the role + contexts, probe the new
    /// DID by opening a second DIDComm session, then drop the temp
    /// DID. The new session is persisted in place; the returned
    /// client is connected as the new DID.
    ///
    /// Errors with a clear message if the VTA's DID document does not
    /// advertise a DIDComm service endpoint — caller should fall back
    /// to [`Self::ensure_authenticated`] for REST.
    #[cfg(feature = "session")]
    pub async fn ensure_authenticated_didcomm(
        &self,
        key: &str,
    ) -> Result<crate::client::VtaClient, Box<dyn std::error::Error>> {
        let session = self.load_session(key).ok_or(
            "Not authenticated.\n\nRun `pnm setup` (or the equivalent) to provision an admin identity.",
        )?;

        let session_vta_did = require_vta_did(&session)?.to_string();

        debug!(
            client_did = %session.client_did,
            vta_did = %session_vta_did,
            needs_rotation = session.needs_rotation,
            "ensure_authenticated_didcomm: session loaded"
        );

        let (vta_did, mediator_did, rest_url) = match resolve_vta_endpoint(&session_vta_did).await?
        {
            VtaEndpoint::DIDComm {
                vta_did,
                mediator_did,
                rest_url,
            } => (vta_did, mediator_did, rest_url),
            VtaEndpoint::Rest { .. } => {
                return Err(format!(
                    "VTA '{session_vta_did}' does not advertise a DIDComm service endpoint. \
                     Use SessionStore::ensure_authenticated for REST, or \
                     SessionStore::connect to auto-select."
                )
                .into());
            }
        };

        // Open the DIDComm session as the (possibly temp) DID.
        let client = crate::client::VtaClient::connect_didcomm(
            &session.client_did,
            &session.private_key,
            &vta_did,
            &mediator_did,
            rest_url.clone(),
        )
        .await?;

        if !session.needs_rotation {
            return Ok(client);
        }

        debug!("session is pending rotation, swapping to fresh did:key over DIDComm");
        let rotated =
            rotate_key_didcomm(&client, &session, &vta_did, &mediator_did, rest_url.clone())
                .await?;
        // Drop the temp client; the new client below is the
        // authoritative connection going forward.
        client.shutdown().await;
        self.save_session(key, &rotated)?;

        let new_client = crate::client::VtaClient::connect_didcomm(
            &rotated.client_did,
            &rotated.private_key,
            &vta_did,
            &mediator_did,
            rest_url,
        )
        .await?;
        Ok(new_client)
    }

    /// Connect to a VTA using the preferred transport (DIDComm or REST).
    ///
    /// Transport selection priority:
    /// 1. If `mediator_did_hint` is provided → DIDComm (pinned, no discovery).
    /// 2. If VTA DID doc has DIDCommMessaging service → DIDComm (resolved).
    /// 3. If `url_override` is provided → authenticate over REST, then ask the
    ///    VTA's status endpoint whether DIDComm is live and prefer it if so.
    /// 4. REST-only (from DID doc or url_override).
    ///
    /// Note `url_override` is a *fallback hint*, not a force-REST switch: a VTA
    /// DID that resolves to a DIDComm endpoint (priority 2) still uses DIDComm
    /// even when `--url` is supplied. The override only takes effect when DID
    /// resolution yields nothing usable (e.g. `did:key`). To force REST
    /// regardless of what the DID document advertises, use
    /// [`connect_with_transport`](Self::connect_with_transport) with
    /// [`TransportChoice::Rest`].
    pub async fn connect(
        &self,
        key: &str,
        url_override: Option<&str>,
        mediator_did_hint: Option<&str>,
    ) -> Result<crate::client::VtaClient, Box<dyn std::error::Error>> {
        self.connect_with_transport(key, url_override, mediator_did_hint, TransportChoice::Auto)
            .await
    }

    /// Like [`connect`](Self::connect) but with an explicit transport choice.
    ///
    /// [`TransportChoice::Auto`] keeps the priority order documented on
    /// [`connect`]. Its DIDComm connects are bounded (see
    /// [`DIDCOMM_CONNECT_TIMEOUT_DEFAULT`]): an unreachable mediator errors out
    /// pointing at `--transport rest` rather than hanging.
    ///
    /// [`TransportChoice::Rest`] forces REST — ignoring the mediator hint and
    /// any advertised DIDComm — using `url_override`, else the `#vta-rest`
    /// service on the VTA's DID document. Errors if the VTA advertises neither
    /// and no `url_override` was given; unlike the auto path it will *not* fall
    /// back to a URL synthesized from the DID's domain, which for a hosted
    /// `did:webvh` points at the DID host rather than the VTA.
    ///
    /// This is the recovery path for an unreachable mediator.
    pub async fn connect_with_transport(
        &self,
        key: &str,
        url_override: Option<&str>,
        mediator_did_hint: Option<&str>,
        transport: TransportChoice,
    ) -> Result<crate::client::VtaClient, Box<dyn std::error::Error>> {
        let session = self.load_session(key).ok_or(
            "Not authenticated.\n\nTo authenticate, import a credential:\n  <cli> auth login <credential-string>",
        )?;

        let session_vta_did = require_vta_did(&session)?.to_string();

        // Forced REST: skip DIDComm (priorities 1 & 2). Resolve the REST
        // endpoint (`--url`, else the DID doc's `#vta-rest`) and auth over HTTP.
        if transport == TransportChoice::Rest {
            let url = match url_override {
                Some(u) => u.to_string(),
                // Deliberately *not* `resolve_vta_url` — that falls back to a
                // URL synthesized from the DID's own domain, which for a
                // `did:webvh` is the DID *host*, not the VTA. Authenticating
                // against the wrong origin fails in a way no operator can
                // diagnose, so demand a real advertisement or an explicit
                // `--url`.
                None => rest_url_from_did_doc(&session_vta_did)
                    .await
                    .ok_or_else(|| no_rest_endpoint_error(&session_vta_did))?,
            };
            debug!(url = %url, "connecting via REST (forced --transport rest)");
            let token = self.ensure_authenticated(&url, key).await?;
            let client = crate::client::VtaClient::new(&url);
            client.set_token(token);
            return Ok(client);
        }

        // Priority 1: Explicit mediator DID from config → DIDComm directly
        if let Some(mediator_did) = mediator_did_hint {
            debug!(mediator_did, "connecting via DIDComm (config mediator_did)");
            let client = connect_didcomm_bounded(
                &session.client_did,
                &session.private_key,
                &session_vta_did,
                mediator_did,
                url_override.map(|s| s.to_string()),
            )
            .await?;
            return Ok(client);
        }

        // Priority 2: Resolve VTA DID for transport selection
        match resolve_vta_endpoint(&session_vta_did).await {
            Ok(VtaEndpoint::DIDComm {
                vta_did,
                mediator_did,
                rest_url,
            }) => {
                debug!("connecting via DIDComm");
                let client = connect_didcomm_bounded(
                    &session.client_did,
                    &session.private_key,
                    &vta_did,
                    &mediator_did,
                    rest_url,
                )
                .await?;
                return Ok(client);
            }
            Ok(VtaEndpoint::Rest { url }) => {
                debug!(url = %url, "connecting via REST (from DID doc)");
                let token = self.ensure_authenticated(&url, key).await?;
                let client = crate::client::VtaClient::new(&url);
                client.set_token(token);
                return Ok(client);
            }
            Err(e) => {
                debug!(error = %e, "DID resolution failed, trying URL-based fallback");
            }
        }

        // Priority 3 & 4: URL override. Authenticate over REST first (needed for
        // either outcome), then ask the *authenticated* status endpoint whether
        // DIDComm is live. `GET /services/didcomm` is super-admin-gated, so an
        // unauthenticated probe can never succeed — discovery must reuse the
        // token we just obtained. Prefer DIDComm if available, otherwise keep
        // the REST client we already built.
        if let Some(url) = url_override {
            let token = self.ensure_authenticated(url, key).await?;
            let rest_client = crate::client::VtaClient::new(url);
            rest_client.set_token(token);

            // Priority 3: DIDComm discovery via the authenticated status endpoint.
            if let Some(mediator_did) = discover_mediator_via_status(&rest_client).await {
                debug!(mediator_did = %mediator_did, "connecting via DIDComm (REST discovery)");
                let client = connect_didcomm_bounded(
                    &session.client_did,
                    &session.private_key,
                    &session_vta_did,
                    &mediator_did,
                    Some(url.to_string()),
                )
                .await?;
                return Ok(client);
            }

            // Priority 4: REST-only fallback.
            debug!(url, "connecting via REST (URL override)");
            return Ok(rest_client);
        }

        Err(format!("Could not determine transport for VTA DID: {session_vta_did}").into())
    }
}

// ── Temp-key rotation ───────────────────────────────────────────────

/// DIDComm-transport peer of [`rotate_key`]. Drives the same
/// read-ACL → mint → create-ACL → probe → delete-temp-ACL sequence,
/// but every server interaction is an authcrypt'd DIDComm message
/// rather than a REST call.
///
/// Probe semantics matches the REST path: opening a fresh DIDComm
/// session as the new DID *is* the auth check. If the new ACL row is
/// not yet visible to the listener, `connect_didcomm` will fail and
/// we bail before touching the temp ACL — so the temp DID still works
/// and the caller can retry.
#[cfg(feature = "session")]
async fn rotate_key_didcomm(
    client: &crate::client::VtaClient,
    session: &Session,
    vta_did: &str,
    mediator_did: &str,
    rest_url: Option<String>,
) -> Result<Session, Box<dyn std::error::Error>> {
    // 1. Read the ACL entry the admin granted to the temp DID.
    debug!(temp_did = %session.client_did, "fetching ACL entry for temp DID over DIDComm");
    let acl_entry = client.get_acl(&session.client_did).await.map_err(|e| {
        format!(
            "rotate (DIDComm): cannot read temp DID's ACL entry: {e} — \
             has your admin run `vta import-did --did {} --role admin` yet?",
            session.client_did
        )
    })?;
    let role = acl_entry.role.clone();
    let contexts = acl_entry.allowed_contexts.clone();
    let label = acl_entry.label.clone();

    // 2. Mint a new did:key. (The DIDComm rotation path still uses the
    //    create-then-delete shape; migrating it onto `acl/swap-key` is a
    //    follow-up — see the REST `rotate_key`.)
    let (new_did, new_private_key, _new_signing) = generate_did_key()?;
    debug!(%new_did, %role, "minted rotation DID, creating ACL entry over DIDComm");

    // 3. Create an ACL entry for the new DID via DIDComm.
    let mut create_req = crate::client::CreateAclRequest::new(&new_did, role).contexts(contexts);
    if let Some(l) = label {
        create_req = create_req.label(l);
    }
    client
        .create_acl(create_req)
        .await
        .map_err(|e| format!("rotate (DIDComm): failed to create ACL entry for new DID: {e}"))?;

    // 4. Probe — open a fresh DIDComm session as the new DID. Fails
    //    *before* we delete the temp DID, so a probe-failure leaves
    //    the temp authoritative and the caller can retry.
    let probe = crate::client::VtaClient::connect_didcomm(
        &new_did,
        &new_private_key,
        vta_did,
        mediator_did,
        rest_url,
    )
    .await
    .map_err(|e| {
        format!(
            "rotate (DIDComm): new DID failed authcrypt probe (ACL entry present \
             but DIDComm session refused): {e}"
        )
    })?;

    // 5. Drop the temp DID from the ACL using the new DID's session.
    //    Best-effort — if it fails, the new DID is already live, so
    //    we log and continue rather than leave the caller unauthenticated.
    match probe.delete_acl(&session.client_did).await {
        Ok(_) => {
            debug!(temp_did = %session.client_did, "temp DID removed from ACL over DIDComm");
        }
        Err(e) => {
            tracing::warn!(
                temp_did = %session.client_did,
                error = %e,
                "could not delete temp DID from ACL after rotation (DIDComm) — \
                 manual cleanup may be required"
            );
        }
    }
    probe.shutdown().await;

    let Session { vta_did, .. } = session.clone();
    Ok(Session {
        client_did: new_did,
        private_key: new_private_key,
        vta_did,
        access_token: None,
        access_expires_at: None,
        needs_rotation: false,
    })
}

/// Generate a fresh Ed25519 did:key. Returns
/// `(did, private_key_multibase, signing_key)`.
///
/// The seed is sourced from `getrandom` (the OS CSPRNG). `private_key_multibase`
/// is the raw 32-byte seed base58btc-encoded, matching the format used by the
/// rest of the workspace (see `decode_private_key_multibase`). The
/// `signing_key` is returned so callers can sign over the new DID (e.g. the
/// `acl/swap-key` presentation) without re-deriving it from the multibase.
fn generate_did_key()
-> Result<(String, String, ed25519_dalek::SigningKey), Box<dyn std::error::Error>> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|e| format!("CSPRNG failed while minting rotated did:key: {e}"))?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pubkey = signing.verifying_key().to_bytes();
    let did = format!(
        "did:key:{}",
        crate::did_key::ed25519_multibase_pubkey(&pubkey)
    );
    let private_key_multibase = multibase::encode(multibase::Base::Base58Btc, seed);
    Ok((did, private_key_multibase, signing))
}

/// Swap a `needs_rotation=true` session's temp did:key for a fresh one via the
/// atomic `acl/swap-key` operation.
///
/// Precondition: `temp_token` is a valid bearer token authenticating as
/// `session.client_did` (the temp DID). Returned `Session` carries the new
/// did:key and `needs_rotation=false`; caller is responsible for persisting it
/// alongside the returned `TokenResult` (an auth under the new DID, confirming
/// the swap actually lived).
///
/// Flow:
/// 1. Mint a fresh did:key.
/// 2. `POST /acl/swap` with a VP-JWT proving control of the new DID. The VTA
///    atomically moves the temp DID's ACL entry (same role + contexts) onto the
///    new DID and removes the temp — no create-then-delete over-privilege
///    window. Because swap-key is structurally non-escalating, an enabled
///    step-up policy carrying the rotation carve-out still admits it at AAL1.
/// 3. Run challenge-response as the new DID to obtain a token under it (and
///    confirm the swap landed).
async fn rotate_key(
    base_url: &str,
    session: Session,
    temp_token: &str,
) -> Result<(Session, TokenResult), Box<dyn std::error::Error>> {
    use crate::protocols::acl_management::swap::{SwapAclBody, build_swap_presentation};

    let http = crate::http::rest_client();

    // `ensure_authenticated` has already gated `vta_did.is_some()` via
    // `require_vta_did`; safe to unwrap here.
    let session_vta_did = session
        .vta_did
        .as_deref()
        .expect("ensure_authenticated gates vta_did.is_some() before calling rotate_key")
        .to_string();

    // 1. Mint a fresh did:key.
    let (new_did, new_private_key, new_signing) = generate_did_key()?;
    debug!(%new_did, "minted rotation DID; swapping via acl/swap-key");

    // 2. Prove control of the new DID and atomically swap the temp entry onto
    //    it. The VP-JWT is audience-bound to this VTA and short-lived.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let presentation =
        build_swap_presentation(&new_signing, &new_did, &session_vta_did, now, 300, None);
    let swap_url = format!("{}/acl/swap", base_url.trim_end_matches('/'));
    let swap_resp = http
        .post(&swap_url)
        .bearer_auth(temp_token)
        .json(&SwapAclBody { presentation })
        .send()
        .await
        .map_err(|e| format!("POST {swap_url}: {e}"))?;
    if !swap_resp.status().is_success() {
        let status = swap_resp.status();
        let body = swap_resp.text().await.unwrap_or_default();
        return Err(format!(
            "rotate: acl/swap-key failed ({status}): {body} — has your admin run \
             `vta import-did --did {} --role admin` yet?",
            session.client_did
        )
        .into());
    }

    // 3. Authenticate as the new DID to obtain a token under it (and confirm
    //    the swap landed). The temp entry is already gone server-side.
    let new_token_result =
        challenge_response(base_url, &new_did, &new_private_key, &session_vta_did)
            .await
            .map_err(|e| format!("rotate: new DID failed challenge-response after swap: {e}"))?;

    let Session { vta_did, .. } = session;
    let rotated = Session {
        client_did: new_did,
        private_key: new_private_key,
        vta_did,
        access_token: None,
        access_expires_at: None,
        needs_rotation: false,
    };
    Ok((rotated, new_token_result))
}

// ── Challenge-response auth ─────────────────────────────────────────

/// Perform DIDComm challenge-response authentication against a VTA.
pub async fn challenge_response(
    base_url: &str,
    client_did: &str,
    private_key_multibase: &str,
    vta_did: &str,
) -> Result<TokenResult, Box<dyn std::error::Error>> {
    debug!(
        base_url,
        client_did, vta_did, "starting challenge-response auth"
    );
    let http = crate::http::rest_client();

    // Step 1: Request challenge
    let challenge_url = format!("{base_url}/auth/challenge");
    debug!(url = %challenge_url, did = client_did, "requesting challenge");
    let challenge_resp = http
        .post(&challenge_url)
        .json(&ChallengeRequest {
            did: client_did.to_string(),
        })
        .send()
        .await
        .map_err(|e| format!("could not connect to VTA at {challenge_url}: {e}"))?;

    if !challenge_resp.status().is_success() {
        let status = challenge_resp.status();
        let body = challenge_resp.text().await.unwrap_or_default();
        return Err(format!("challenge request failed ({status}): {body}").into());
    }

    let challenge_text = challenge_resp
        .text()
        .await
        .map_err(|e| format!("failed to read challenge response from VTA: {e}"))?;
    let challenge: ChallengeResponse = serde_json::from_str(&challenge_text).map_err(|e| {
        format!("unexpected response from VTA at {challenge_url} (is this a VTA server?): {e}")
    })?;
    debug!(
        session_id = %challenge.session_id,
        challenge = %challenge.challenge,
        "challenge received"
    );

    // Step 2: Build DIDComm message
    debug!("initializing DID resolver and ATM for message packing");

    use affinidi_tdk::common::TDKSharedState;
    use affinidi_tdk::common::config::TDKConfig;
    use affinidi_tdk::messaging::ATM;
    use affinidi_tdk::messaging::config::ATMConfig;
    use std::sync::Arc;

    let tdk = TDKSharedState::new(
        TDKConfig::builder()
            .build()
            .map_err(|e| format!("TDK config build failed: {e}"))?,
    )
    .await
    .map_err(|e| format!("TDK init failed: {e}"))?;

    // Build DIDComm secrets from the private key
    let seed = crate::did_key::decode_private_key_multibase(private_key_multibase)?;
    let secrets = crate::did_key::secrets_from_did_key(client_did, &seed)?;
    debug!(signing_id = %secrets.signing.id, ka_id = %secrets.key_agreement.id, "inserting DIDComm secrets");
    tdk.secrets_resolver().insert(secrets.signing).await;
    tdk.secrets_resolver().insert(secrets.key_agreement).await;

    let atm = ATM::new(
        ATMConfig::builder()
            .build()
            .map_err(|e| format!("ATM config build failed: {e}"))?,
        Arc::new(tdk),
    )
    .await
    .map_err(|e| format!("ATM init failed: {e}"))?;

    // Build the authenticate message
    debug!(
        from = client_did,
        to = vta_did,
        "building DIDComm authenticate message"
    );
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        crate::trust_tasks::TASK_AUTH_AUTHENTICATE_0_1.to_string(),
        serde_json::json!({
            "challenge": challenge.challenge,
            "session_id": challenge.session_id,
        }),
    )
    .from(client_did.to_string())
    .to(vta_did.to_string())
    .finalize();

    // Pack the message (encrypted)
    let (packed, _metadata) = atm
        .pack_encrypted(&msg, vta_did, Some(client_did), None)
        .await
        .map_err(|e| format!("DIDComm pack failed: {e}"))?;

    debug!(packed_len = packed.len(), "message packed");

    // Step 3: Authenticate
    let auth_url = format!("{base_url}/auth/");
    debug!(url = %auth_url, "sending packed message");
    let auth_resp = http
        .post(&auth_url)
        .header("content-type", "text/plain")
        .body(packed)
        .send()
        .await
        .map_err(|e| format!("could not connect to VTA at {auth_url}: {e}"))?;

    let status = auth_resp.status();
    debug!(status = %status, "auth response received");

    if !status.is_success() {
        let body = auth_resp.text().await.unwrap_or_default();
        return Err(format!("authentication failed ({status}): {body}").into());
    }

    let auth_text = auth_resp
        .text()
        .await
        .map_err(|e| format!("failed to read auth response from VTA: {e}"))?;
    let auth_data: AuthenticateResponse = serde_json::from_str(&auth_text).map_err(|e| {
        format!("unexpected response from VTA at {auth_url} (is this a VTA server?): {e}")
    })?;
    let access_expires_at = auth_data.access_expires_at_epoch().ok_or_else(|| {
        format!(
            "VTA returned unparseable session.issuedAt: '{}'",
            auth_data.session.issued_at
        )
    })?;
    debug!(expires_at = access_expires_at, "authentication successful");

    Ok(TokenResult {
        access_token: auth_data.tokens.access_token,
        access_expires_at,
    })
}

// ── DIDComm-preferred connection ─────────────────────────────────────

/// Result of resolving a VTA DID's service endpoints.
pub enum VtaEndpoint {
    /// REST-only (no DIDCommMessaging service found).
    Rest { url: String },
    /// DIDComm preferred, with optional REST fallback.
    DIDComm {
        vta_did: String,
        mediator_did: String,
        rest_url: Option<String>,
    },
}

/// Operator transport selection for
/// [`SessionStore::connect_with_transport`] (the `pnm`/`cnm` connect path).
///
/// `#[non_exhaustive]`: TSP is the workspace's preferred transport
/// (TSP > DIDComm > REST) and will land here as a variant, as may an
/// explicit `Didcomm`. Match with a `_` arm.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportChoice {
    /// Prefer DIDComm when advertised, else REST. The default.
    #[default]
    Auto,
    /// Force REST, ignoring any advertised DIDComm. Recovery path when a VTA's
    /// mediator is unreachable (auto would pick DIDComm and hang).
    Rest,
}

/// How long an auto-selected DIDComm connect may take before we give up and
/// tell the operator how to reach the VTA over REST instead.
///
/// The mediator client owns a reconnect/backoff loop, so a DIDComm connect
/// against an unreachable mediator does not fail — it retries, and the CLI
/// hangs with no output. `pnm health` already caps its DIDComm probes for this
/// reason; the connect path needs the same ceiling, otherwise
/// [`TransportChoice::Rest`] is a recovery flag nobody ever gets told about.
///
/// Override with `VTA_DIDCOMM_CONNECT_TIMEOUT_SECS` for links slower than the
/// 30s default.
const DIDCOMM_CONNECT_TIMEOUT_DEFAULT: Duration = Duration::from_secs(30);

fn didcomm_connect_timeout() -> Duration {
    parse_connect_timeout(std::env::var("VTA_DIDCOMM_CONNECT_TIMEOUT_SECS").ok())
}

/// Env-var parsing for [`didcomm_connect_timeout`], split out so it is
/// testable without touching process environment. Garbage and `0` fall back to
/// the default — a zero deadline would fail every connect instantly, which is
/// worse than the hang it replaces.
fn parse_connect_timeout(raw: Option<String>) -> Duration {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or(DIDCOMM_CONNECT_TIMEOUT_DEFAULT)
}

/// [`crate::client::VtaClient::connect_didcomm`] under a deadline.
///
/// Every auto-transport DIDComm connect goes through here so an unreachable
/// mediator surfaces as an error naming the recovery flag rather than as an
/// indefinite hang. See [`DIDCOMM_CONNECT_TIMEOUT_DEFAULT`].
async fn connect_didcomm_bounded(
    client_did: &str,
    private_key: &str,
    vta_did: &str,
    mediator_did: &str,
    rest_url: Option<String>,
) -> Result<crate::client::VtaClient, Box<dyn std::error::Error>> {
    let timeout = didcomm_connect_timeout();
    match tokio::time::timeout(
        timeout,
        crate::client::VtaClient::connect_didcomm(
            client_did,
            private_key,
            vta_did,
            mediator_did,
            rest_url,
        ),
    )
    .await
    {
        Ok(result) => Ok(result?),
        Err(_) => Err(mediator_unreachable_error(mediator_did, timeout).into()),
    }
}

/// The message an operator sees when their VTA's mediator is down.
///
/// Names the recovery command verbatim, per the workspace's "operator errors
/// should suggest the fix" rule.
fn mediator_unreachable_error(mediator_did: &str, timeout: Duration) -> String {
    format!(
        "Timed out after {}s connecting to the VTA's mediator:\n  {mediator_did}\n\n\
         The VTA advertises DIDComm, but its mediator did not answer. Reach the VTA \
         over REST instead:\n  \
         <cli> --transport rest <command>\n\n\
         If the mediator is gone for good, stop advertising it:\n  \
         pnm --transport rest services didcomm disable",
        timeout.as_secs()
    )
}

/// The message an operator sees when `--transport rest` has no REST endpoint
/// to force.
fn no_rest_endpoint_error(vta_did: &str) -> Box<dyn std::error::Error> {
    format!(
        "--transport rest: VTA '{vta_did}' does not advertise a REST service \
         (`#vta-rest`) in its DID document, so there is no REST endpoint to \
         force.\n\nPass the VTA's base URL explicitly:\n  \
         <cli> --transport rest --url https://vta.example.com <command>"
    )
    .into()
}

/// Resolve a VTA DID to discover available transport endpoints.
///
/// Performs a single DID resolution and extracts:
/// - `DIDCommMessaging` service → mediator DID (preferred transport)
/// - `#vta-rest` service → REST URL (fallback)
///
/// Returns `VtaEndpoint::DIDComm` if a mediator is found, otherwise `VtaEndpoint::Rest`.
pub async fn resolve_vta_endpoint(
    vta_did: &str,
) -> Result<VtaEndpoint, Box<dyn std::error::Error>> {
    debug!(vta_did, "resolving VTA DID for transport selection");

    let did_resolver = DIDCacheClient::new(crate::resolver::build_did_cache_config_from_env())
        .await
        .map_err(|e| format!("DID resolver init failed: {e}"))?;

    let resolved = match did_resolver.resolve(vta_did).await {
        Ok(r) => r,
        Err(e) => {
            debug!(error = %e, "DID resolution failed, falling back to URL parsing");
            let url = url_from_did(vta_did)
                .ok_or_else(|| format!("Could not determine VTA URL from DID: {vta_did}"))?;
            return Ok(VtaEndpoint::Rest { url });
        }
    };

    // Look for #vta-rest service endpoint
    let rest_url = resolved
        .doc
        .find_service("vta-rest")
        .and_then(|svc| svc.service_endpoint.get_uri())
        .map(|u| u.trim_matches('"').trim_end_matches('/').to_string());

    // Look for DIDCommMessaging service with a DID-based endpoint (mediator)
    let mediator_did = resolved
        .doc
        .service
        .iter()
        .filter(|svc| svc.type_.iter().any(|t| t == "DIDCommMessaging"))
        .flat_map(|svc| svc.service_endpoint.get_uris())
        .map(|u| u.trim_matches('"').to_string())
        .find(|u| u.starts_with("did:"));

    if let Some(mediator_did) = mediator_did {
        debug!(mediator_did = %mediator_did, rest_url = ?rest_url, "DIDComm endpoint found");
        Ok(VtaEndpoint::DIDComm {
            vta_did: vta_did.to_string(),
            mediator_did,
            rest_url,
        })
    } else if let Some(url) = rest_url {
        debug!(url = %url, "REST-only endpoint found");
        Ok(VtaEndpoint::Rest { url })
    } else {
        // Last resort: parse URL from DID string
        let url = url_from_did(vta_did)
            .ok_or_else(|| format!("Could not determine VTA URL from DID: {vta_did}"))?;
        debug!(url = %url, "falling back to URL from DID string");
        Ok(VtaEndpoint::Rest { url })
    }
}

/// Best-effort: ask an already-authenticated VTA whether DIDComm is enabled
/// and, if so, return its mediator DID.
///
/// Used as a fallback for DID methods with no resolvable service block (e.g.
/// `did:key`), where the only way to learn the mediator is to ask the running
/// VTA over REST. `GET /services/didcomm` is super-admin-gated, so this *must*
/// run on a client that already carries a valid token — an unauthenticated
/// probe always 401s. Returns `None` if DIDComm is disabled, the caller lacks
/// permission, or the endpoint errs; every one of those simply means "fall
/// back to REST".
async fn discover_mediator_via_status(client: &crate::client::VtaClient) -> Option<String> {
    match client.didcomm_status().await {
        Ok(status) if status.enabled => status.mediator_did,
        Ok(_) => {
            debug!("DIDComm not enabled on VTA (status discovery)");
            None
        }
        Err(e) => {
            debug!(error = %e, "DIDComm status discovery failed; falling back to REST");
            None
        }
    }
}

/// The `#vta-rest` service endpoint from the VTA's DID document, if it
/// advertises one. `None` covers both "resolution failed" and "no REST service"
/// — neither yields a REST URL we can stand behind.
///
/// Strict counterpart of [`resolve_vta_url`], which additionally guesses a URL
/// from the DID's own domain. That guess is right for a self-hosted `did:web`
/// VTA and wrong for a `did:webvh` whose DID lives on a hosting server, so the
/// force-REST path uses this instead.
async fn rest_url_from_did_doc(vta_did: &str) -> Option<String> {
    let did_resolver = DIDCacheClient::new(crate::resolver::build_did_cache_config_from_env())
        .await
        .inspect_err(|e| debug!(error = %e, "DID resolver init failed"))
        .ok()?;

    let resolved = did_resolver
        .resolve(vta_did)
        .await
        .inspect_err(|e| debug!(error = %e, "DID resolution failed"))
        .ok()?;

    let url = resolved
        .doc
        .find_service("vta-rest")?
        .service_endpoint
        .get_uri()?
        .trim_matches('"')
        .trim_end_matches('/')
        .to_string();

    debug!(url = %url, "found VTA URL from #vta-rest service endpoint");
    Some(url)
}

/// Resolve a VTA DID to discover its service URL.
///
/// Resolves the DID document and looks for the `#vta-rest` service endpoint.
/// Falls back to parsing the domain from `did:web:` or `did:webvh:` DID strings.
pub async fn resolve_vta_url(vta_did: &str) -> Result<String, Box<dyn std::error::Error>> {
    debug!(vta_did, "resolving VTA DID to discover service URL");

    if let Some(url) = rest_url_from_did_doc(vta_did).await {
        return Ok(url);
    }
    debug!("no #vta-rest service resolved, falling back to DID parsing");

    // Fallback: parse domain from did:web or did:webvh DID strings
    url_from_did(vta_did)
        .ok_or_else(|| format!("Could not determine VTA URL from DID: {vta_did}").into())
}

/// Extract the base URL from a `did:web:` or `did:webvh:` DID string.
fn url_from_did(did: &str) -> Option<String> {
    let domain = if let Some(rest) = did.strip_prefix("did:web:") {
        // did:web:domain.com or did:web:domain.com%3A8100
        rest.split(':').next()
    } else if let Some(rest) = did.strip_prefix("did:webvh:") {
        // did:webvh:SCID:domain.com or did:webvh:SCID:domain.com%3A8100
        rest.split(':').nth(1)
    } else {
        None
    }?;

    let decoded = domain.replace("%3A", ":").replace("%3a", ":");
    Some(format!("https://{decoded}"))
}

/// Send a DIDComm trust-ping to the mediator using the client's `did:key`
/// credentials, and return latency in milliseconds.
pub async fn send_trust_ping(
    client_did: &str,
    private_key_multibase: &str,
    mediator_did: &str,
    target_did: Option<&str>,
) -> Result<u128, Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::Instant;

    use affinidi_tdk::common::TDKSharedState;
    use affinidi_tdk::common::config::TDKConfig;
    use affinidi_tdk::messaging::ATM;
    use affinidi_tdk::messaging::config::ATMConfig;
    use affinidi_tdk::messaging::profiles::ATMProfile;
    use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;

    let seed = crate::did_key::decode_private_key_multibase(private_key_multibase)?;
    let secrets = crate::did_key::secrets_from_did_key(client_did, &seed)?;

    let tdk = TDKSharedState::new(TDKConfig::builder().build()?).await?;
    tdk.secrets_resolver().insert(secrets.signing).await;
    tdk.secrets_resolver().insert(secrets.key_agreement).await;

    let atm = ATM::new(ATMConfig::builder().build()?, Arc::new(tdk)).await?;

    let profile = ATMProfile::new(
        &atm,
        None,
        client_did.to_string(),
        Some(mediator_did.to_string()),
    )
    .await?;
    let profile = Arc::new(profile);

    atm.profile_enable_websocket(&profile).await?;

    let start = Instant::now();
    TrustPing::default()
        .send_ping(
            &atm,
            &profile,
            target_did.unwrap_or(mediator_did),
            true,
            true,
            true,
        )
        .await?;
    let elapsed = start.elapsed().as_millis();

    atm.graceful_shutdown().await;
    Ok(elapsed)
}

/// Resolve the VTA DID document and extract the mediator DID from the
/// `DIDCommMessaging` service endpoint.
pub async fn resolve_mediator_did(
    vta_did: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let did_resolver = DIDCacheClient::new(crate::resolver::build_did_cache_config_from_env())
        .await
        .map_err(|e| format!("DID resolver init failed: {e}"))?;
    resolve_mediator_did_with_resolver(vta_did, &did_resolver).await
}

/// Resolve the mediator DID using an existing resolver (avoids re-creating one).
pub async fn resolve_mediator_did_with_resolver(
    vta_did: &str,
    resolver: &DIDCacheClient,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let resolved = resolver
        .resolve(vta_did)
        .await
        .map_err(|e| format!("DID resolution failed: {e}"))?;

    for svc in &resolved.doc.service {
        if svc.type_.iter().any(|t| t == "DIDCommMessaging")
            && let Some(did) = svc
                .service_endpoint
                .get_uris()
                .into_iter()
                .map(|u| u.trim_matches('"').to_string())
                .find(|u| u.starts_with("did:"))
        {
            return Ok(Some(did));
        }
    }

    Ok(None)
}

/// A reusable DIDComm session for sending multiple trust-pings through
/// the same ATM + WebSocket connection.
///
/// Eliminates per-ping overhead of TDK init, ATM creation, profile setup,
/// and WebSocket handshake (~4 seconds saved per additional ping).
pub struct TrustPingSession {
    atm: affinidi_tdk::messaging::ATM,
    profile: std::sync::Arc<affinidi_tdk::messaging::profiles::ATMProfile>,
    mediator_did: String,
}

impl TrustPingSession {
    /// Create a new session connected to the mediator via WebSocket.
    pub async fn new(
        client_did: &str,
        private_key_multibase: &str,
        mediator_did: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        use affinidi_tdk::common::TDKSharedState;
        use affinidi_tdk::common::config::TDKConfig;
        use affinidi_tdk::messaging::ATM;
        use affinidi_tdk::messaging::config::ATMConfig;
        use affinidi_tdk::messaging::profiles::ATMProfile;
        use std::sync::Arc;

        let seed = crate::did_key::decode_private_key_multibase(private_key_multibase)?;
        let secrets = crate::did_key::secrets_from_did_key(client_did, &seed)?;

        let tdk = TDKSharedState::new(TDKConfig::builder().build()?).await?;
        tdk.secrets_resolver().insert(secrets.signing).await;
        tdk.secrets_resolver().insert(secrets.key_agreement).await;

        let atm = ATM::new(ATMConfig::builder().build()?, Arc::new(tdk)).await?;

        let profile = ATMProfile::new(
            &atm,
            None,
            client_did.to_string(),
            Some(mediator_did.to_string()),
        )
        .await?;
        let profile = Arc::new(profile);

        atm.profile_enable_websocket(&profile).await?;

        Ok(Self {
            atm,
            profile,
            mediator_did: mediator_did.to_string(),
        })
    }

    /// Send a trust-ping to a target (or the mediator if `target_did` is None).
    /// Returns latency in milliseconds.
    pub async fn ping(&self, target_did: Option<&str>) -> Result<u128, Box<dyn std::error::Error>> {
        use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;
        use std::time::Instant;

        let target = target_did.unwrap_or(&self.mediator_did);
        let start = Instant::now();
        TrustPing::default()
            .send_ping(&self.atm, &self.profile, target, true, true, true)
            .await?;
        Ok(start.elapsed().as_millis())
    }

    /// Gracefully shut down the ATM connection.
    pub async fn shutdown(self) {
        self.atm.graceful_shutdown().await;
    }
}

/// A client-side TSP connectivity probe — the TSP analogue of
/// [`TrustPingSession`].
///
/// Opens the client's **single** TSP websocket to the shared mediator, sends a
/// Trust Task to the VTA's VID over TSP (routed through the mediator), and
/// awaits the VTA's response envelope — proving the whole TSP round-trip:
/// client seal → mediator route → VTA unpack → auth → `dispatch_trust_task_core`
/// → reply → route back → client receive. This is the receive-capable
/// counterpart to the outbound-only `atm.tsp().send_*`; the VTA replies via the
/// symmetric `TspHandler` (`affinidi-messaging-didcomm-service` ≥ 0.3.14).
///
/// TSP-only client: no DIDComm listener shares this DID's socket, so
/// `connect_websocket` is safe here (the one-socket-per-DID rule only bites a
/// *dual* node — ADR 0005). Callers running a DIDComm [`TrustPingSession`] on
/// the same client DID must shut it down before opening this.
#[cfg(feature = "tsp")]
pub struct TspPingSession {
    atm: affinidi_tdk::messaging::ATM,
    profile: std::sync::Arc<affinidi_tdk::messaging::profiles::ATMProfile>,
    ws: affinidi_tdk::messaging::TspWebSocket,
    client_did: String,
    mediator_did: String,
}

#[cfg(feature = "tsp")]
impl TspPingSession {
    /// Connect the client's TSP websocket to `mediator_did` (the VTA's `#tsp`
    /// service endpoint — the same mediator the VTA is a local account on).
    pub async fn new(
        client_did: &str,
        private_key_multibase: &str,
        mediator_did: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        use affinidi_tdk::common::TDKSharedState;
        use affinidi_tdk::common::config::TDKConfig;
        use affinidi_tdk::messaging::ATM;
        use affinidi_tdk::messaging::config::ATMConfig;
        use affinidi_tdk::messaging::profiles::ATMProfile;
        use std::sync::Arc;

        let seed = crate::did_key::decode_private_key_multibase(private_key_multibase)?;
        let secrets = crate::did_key::secrets_from_did_key(client_did, &seed)?;

        let tdk = TDKSharedState::new(TDKConfig::builder().build()?).await?;
        tdk.secrets_resolver().insert(secrets.signing).await;
        tdk.secrets_resolver().insert(secrets.key_agreement).await;

        let atm = ATM::new(ATMConfig::builder().build()?, Arc::new(tdk)).await?;

        let profile = ATMProfile::new(
            &atm,
            None,
            client_did.to_string(),
            Some(mediator_did.to_string()),
        )
        .await?;
        let profile = Arc::new(profile);

        let ws = atm.tsp().connect_websocket(&profile).await?;

        Ok(Self {
            atm,
            profile,
            ws,
            client_did: client_did.to_string(),
            mediator_did: mediator_did.to_string(),
        })
    }

    /// Send a Trust Task to `vta_did` over TSP and await the response envelope.
    /// Returns latency in milliseconds.
    ///
    /// The probe sends a `messaging/ping/0.1` Trust Task — the canonical,
    /// session-less liveness + capability probe (ToIP Trust Tasks). It's
    /// authenticated intrinsically by the TSP unpack's proven sender VID (no
    /// holder proof needed on TSP, like DIDComm authcrypt) and requires no
    /// capability beyond reachability, so it returns a clean `#response` (not a
    /// 422 like a session-bound task would). A correlation `nonce` is included;
    /// the round-trip latency is measured to the response frame.
    pub async fn ping(
        &mut self,
        vta_did: &str,
        timeout: std::time::Duration,
    ) -> Result<u128, Box<dyn std::error::Error>> {
        use std::time::Instant;
        use trust_tasks_rs::TrustTask;

        let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
        let nonce = uuid::Uuid::new_v4().to_string();
        let type_uri = crate::trust_tasks::TASK_MESSAGING_PING_0_1
            .parse()
            .map_err(|e| format!("messaging/ping type URI parse: {e}"))?;
        let mut doc: TrustTask<serde_json::Value> =
            TrustTask::new(id, type_uri, serde_json::json!({ "nonce": nonce }));
        doc.issuer = Some(self.client_did.clone());
        doc.recipient = Some(vta_did.to_string());
        let body = serde_json::to_vec(&doc)?;

        let start = Instant::now();
        // Route through our mediator to the VTA (a local account on it):
        // inner sealed end-to-end to the VTA, outer sealed to the mediator.
        self.atm
            .tsp()
            .send_routed(
                &self.profile,
                &[self.mediator_did.clone(), vta_did.to_string()],
                &body,
            )
            .await?;

        loop {
            let remaining = timeout
                .checked_sub(start.elapsed())
                .ok_or("TSP ping timed out waiting for reply")?;
            let frame = match tokio::time::timeout(remaining, self.ws.recv()).await {
                Ok(Ok(Some(bytes))) => bytes,
                Ok(Ok(None)) => return Err("TSP websocket closed before reply".into()),
                Ok(Err(e)) => return Err(Box::new(e)),
                Err(_) => return Err("TSP ping timed out waiting for reply".into()),
            };
            // The VTA's reply is sealed to us; a frame we can unpack and parse
            // as a JSON trust-task envelope is the pong. (Our ephemeral-ish
            // client DID has no other TSP traffic, so the first such frame is
            // our reply.) Frames that don't unpack are skipped.
            if let Ok((payload, _sender)) = self.atm.tsp().unpack_bytes(&self.profile, &frame).await
                && serde_json::from_slice::<serde_json::Value>(&payload).is_ok()
            {
                return Ok(start.elapsed().as_millis());
            }
        }
    }

    /// Close the TSP websocket and shut down the ATM connection.
    pub async fn shutdown(self) {
        let _ = self.ws.close().await;
        self.atm.graceful_shutdown().await;
    }
}

/// A live, receive-oriented TSP session to a mediator, scoped to one client
/// identity — the TSP analogue of [`crate::didcomm_session::DIDCommSession`].
/// Connects the client's TSP websocket to the mediator and yields inbound
/// Trust-Task frames already unpacked under the client key. This is the receive
/// primitive the mobile approver uses to collect a VTA-pushed
/// `task-consent/request` over TSP.
///
/// Unlike [`TspPingSession`] (a one-shot send-then-await liveness probe), this
/// session is long-lived: [`receive_next`](Self::receive_next) can be polled
/// repeatedly. The websocket lives behind a mutex so the receive/shutdown
/// methods take `&self` — the session is shared as an `Arc` across the FFI
/// boundary, mirroring `DIDCommSession::receive_next`.
#[cfg(feature = "tsp")]
pub struct TspSession {
    atm: affinidi_tdk::messaging::ATM,
    profile: std::sync::Arc<affinidi_tdk::messaging::profiles::ATMProfile>,
    // `Option` so `shutdown` can `take()` the socket out to `close()` it —
    // `TspWebSocket::close` consumes `self`, which a `MutexGuard` can't yield.
    // `None` means already shut down; receive then no-ops.
    ws: tokio::sync::Mutex<Option<affinidi_tdk::messaging::TspWebSocket>>,
    /// This client's DID — the `issuer` on an [`announce`](Self::announce) frame.
    client_did: String,
}

#[cfg(feature = "tsp")]
impl TspSession {
    /// Connect the client's TSP websocket to `mediator_did` (the VTA's `#tsp`
    /// endpoint — the mediator the VTA is a local account on) as `client_did`.
    /// Same connect path as [`TspPingSession::new`]; the difference is lifetime
    /// and direction (this one stays open to receive).
    pub async fn connect(
        client_did: &str,
        private_key_multibase: &str,
        mediator_did: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        use affinidi_tdk::common::TDKSharedState;
        use affinidi_tdk::common::config::TDKConfig;
        use affinidi_tdk::messaging::ATM;
        use affinidi_tdk::messaging::config::ATMConfig;
        use affinidi_tdk::messaging::profiles::ATMProfile;
        use std::sync::Arc;

        let seed = crate::did_key::decode_private_key_multibase(private_key_multibase)?;
        let secrets = crate::did_key::secrets_from_did_key(client_did, &seed)?;

        let tdk = TDKSharedState::new(TDKConfig::builder().build()?).await?;
        tdk.secrets_resolver().insert(secrets.signing).await;
        tdk.secrets_resolver().insert(secrets.key_agreement).await;

        let atm = ATM::new(ATMConfig::builder().build()?, Arc::new(tdk)).await?;

        let profile = ATMProfile::new(
            &atm,
            None,
            client_did.to_string(),
            Some(mediator_did.to_string()),
        )
        .await?;
        let profile = Arc::new(profile);

        let ws = atm.tsp().connect_websocket(&profile).await?;

        Ok(Self {
            atm,
            profile,
            ws: tokio::sync::Mutex::new(Some(ws)),
            client_did: client_did.to_string(),
        })
    }

    /// Announce this client's TSP reachability to `vta_did` by sending a
    /// session-less `messaging/ping/0.1` frame (routed through `mediator_did`).
    /// The point is not the pong — it's that the VTA's inbound dispatcher records
    /// our **proven** `sender_vid` as TSP-reachable (learn-from-inbound), so its
    /// device-push prefers TSP for us. The VTA's pong arrives on
    /// [`receive_next`](Self::receive_next) like any other frame and is ignored
    /// by the Trust-Task classifier (it's neither a step-up nor a task-consent).
    ///
    /// Send-only: unlike a socket read it needs no `ws` lock — `send_routed`
    /// goes out through the ATM's TSP transport, so it can run concurrently with
    /// a blocked `receive_next`. Call it on connect (and periodically) to keep
    /// the VTA's reachability record fresh.
    pub async fn announce(
        &self,
        vta_did: &str,
        mediator_did: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use trust_tasks_rs::TrustTask;

        let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
        let nonce = uuid::Uuid::new_v4().to_string();
        let type_uri = crate::trust_tasks::TASK_MESSAGING_PING_0_1
            .parse()
            .map_err(|e| format!("messaging/ping type URI parse: {e}"))?;
        let mut doc: TrustTask<serde_json::Value> =
            TrustTask::new(id, type_uri, serde_json::json!({ "nonce": nonce }));
        doc.issuer = Some(self.client_did.clone());
        doc.recipient = Some(vta_did.to_string());
        let body = serde_json::to_vec(&doc)?;

        self.atm
            .tsp()
            .send_routed(
                &self.profile,
                &[mediator_did.to_string(), vta_did.to_string()],
                &body,
            )
            .await?;
        Ok(())
    }

    /// Wait up to `timeout_secs` for the next inbound TSP frame that unpacks to a
    /// Trust-Task payload, and return that payload as a JSON string — the
    /// unpacked inner document (e.g. a `task-consent/request`). Returns `None`
    /// if nothing arrived within the timeout or the websocket closed. TSP
    /// control frames (which don't unpack to an application payload) are skipped
    /// within the remaining budget rather than surfaced. Call again to poll on.
    ///
    /// The plaintext is the *inner* document the sender packed, not a DIDComm
    /// envelope: TSP carries the Trust-Task bytes directly, so callers parse the
    /// returned JSON as the document itself (its own `type`/`issuer` fields),
    /// not as `{ body: … }`.
    pub async fn receive_next(
        &self,
        timeout_secs: u64,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        use std::time::{Duration, Instant};

        let mut guard = self.ws.lock().await;
        let ws = match guard.as_mut() {
            Some(w) => w,
            None => return Ok(None), // already shut down
        };
        let budget = Duration::from_secs(timeout_secs);
        let start = Instant::now();
        loop {
            let remaining = match budget.checked_sub(start.elapsed()) {
                Some(r) => r,
                None => return Ok(None),
            };
            let frame = match tokio::time::timeout(remaining, ws.recv()).await {
                Ok(Ok(Some(bytes))) => bytes,
                Ok(Ok(None)) => return Ok(None), // websocket closed
                Ok(Err(e)) => return Err(Box::new(e)),
                Err(_) => return Ok(None), // timed out with nothing to hand back
            };
            // A frame sealed to us that unpacks to a UTF-8 body is an application
            // message; hand its plaintext to the caller. Frames that don't unpack
            // are TSP control/relationship traffic — skip and keep waiting.
            match self.atm.tsp().unpack_bytes(&self.profile, &frame).await {
                Ok((payload, _sender)) => {
                    let json = String::from_utf8(payload)
                        .map_err(|e| format!("TSP payload was not UTF-8: {e}"))?;
                    return Ok(Some(json));
                }
                Err(_) => continue,
            }
        }
    }

    /// Close the TSP websocket and shut down the ATM connection. Takes `&self`
    /// (the session is shared across the FFI boundary).
    pub async fn shutdown(&self) {
        if let Some(ws) = self.ws.lock().await.take() {
            let _ = ws.close().await;
        }
        self.atm.graceful_shutdown().await;
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_round_trip() {
        let session = Session {
            client_did: "did:key:z6Mk1".into(),
            private_key: "z_seed".into(),
            vta_did: Some("did:key:z6MkVTA".into()),
            access_token: Some("tok123".into()),
            access_expires_at: Some(1700000000),
            needs_rotation: false,
        };
        let json = serde_json::to_string(&session).unwrap();
        let restored: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.client_did, session.client_did);
        assert_eq!(restored.private_key, session.private_key);
        assert_eq!(restored.vta_did, session.vta_did);
        assert_eq!(restored.access_token, session.access_token);
        assert_eq!(restored.access_expires_at, session.access_expires_at);
    }

    /// Older session blobs include a `vta_url` field. Serde silently drops
    /// unknown fields on deserialise so they keep loading; the field
    /// disappears on next save.
    #[test]
    fn test_session_legacy_vta_url_field_silently_dropped() {
        let json = r#"{
            "client_did": "did:key:z6Mk1",
            "private_key": "z_seed",
            "vta_did": "did:key:z6MkVTA",
            "vta_url": "https://stale.example.com",
            "access_token": null,
            "access_expires_at": null
        }"#;
        let session: Session = serde_json::from_str(json).unwrap();
        assert_eq!(session.vta_did.as_deref(), Some("did:key:z6MkVTA"));
        // Field is gone — re-serializing produces no `vta_url` key.
        let reserialised = serde_json::to_string(&session).unwrap();
        assert!(!reserialised.contains("vta_url"));
    }

    #[test]
    fn test_session_vta_did_defaults_to_none_when_missing() {
        // A PendingVtaBinding session persists with `vta_did` absent.
        let json = r#"{
            "client_did": "did:key:z6MkPending",
            "private_key": "z_seed",
            "access_token": null,
            "access_expires_at": null
        }"#;
        let session: Session = serde_json::from_str(json).unwrap();
        assert!(session.vta_did.is_none());
    }

    #[test]
    fn test_session_vta_did_round_trips_null() {
        let session = Session {
            client_did: "did:key:z6MkPending".into(),
            private_key: "z_seed".into(),
            vta_did: None,
            access_token: None,
            access_expires_at: None,
            needs_rotation: false,
        };
        let json = serde_json::to_string(&session).unwrap();
        let restored: Session = serde_json::from_str(&json).unwrap();
        assert!(restored.vta_did.is_none());
    }

    #[test]
    fn test_now_epoch_is_recent() {
        let epoch = now_epoch();
        assert!(epoch > 1704067200, "epoch {epoch} should be after 2024");
        assert!(epoch < 4102444800, "epoch {epoch} should be before 2100");
    }

    #[test]
    fn test_url_from_did_web() {
        assert_eq!(
            url_from_did("did:web:vta.example.com"),
            Some("https://vta.example.com".to_string())
        );
    }

    #[test]
    fn test_url_from_did_web_with_port() {
        assert_eq!(
            url_from_did("did:web:localhost%3A8100"),
            Some("https://localhost:8100".to_string())
        );
    }

    #[test]
    fn test_url_from_did_webvh() {
        assert_eq!(
            url_from_did("did:webvh:QmSCID123:vta.example.com"),
            Some("https://vta.example.com".to_string())
        );
    }

    #[test]
    fn test_url_from_did_webvh_with_port() {
        assert_eq!(
            url_from_did("did:webvh:QmSCID123:localhost%3A8100"),
            Some("https://localhost:8100".to_string())
        );
    }

    #[test]
    fn test_url_from_did_key_returns_none() {
        assert_eq!(url_from_did("did:key:z6MkTest"), None);
    }

    fn test_store() -> SessionStore {
        SessionStore::with_backend(Box::new(testing::InMemorySessionBackend::new()))
    }

    #[test]
    fn test_in_memory_backend() {
        let store = test_store();

        assert!(!store.has_session("test"));

        store
            .store_direct("test", "did:key:z6Mk1", "zSeed", "did:key:zVTA")
            .unwrap();
        assert!(store.has_session("test"));

        let info = store.loaded_session("test").unwrap();
        assert_eq!(info.client_did, "did:key:z6Mk1");
        assert_eq!(info.vta_did.as_deref(), Some("did:key:zVTA"));

        store.logout("test");
        assert!(!store.has_session("test"));
    }

    #[test]
    fn store_pending_vta_binding_round_trips() {
        let store = test_store();
        store
            .store_pending_vta_binding("slug", "did:key:z6MkPending", "zSeed123")
            .unwrap();

        assert!(store.has_pending_vta_binding("slug"));

        let info = store.loaded_session("slug").unwrap();
        assert_eq!(info.client_did, "did:key:z6MkPending");
        assert!(info.vta_did.is_none());
    }

    #[test]
    fn store_pending_vta_binding_rejects_non_did_key() {
        let store = test_store();
        let err = store
            .store_pending_vta_binding("slug", "did:web:something", "zSeed")
            .unwrap_err();
        assert!(err.to_string().contains("did:key"));
    }

    #[test]
    fn store_pending_vta_binding_rejects_empty_inputs() {
        let store = test_store();
        assert!(
            store
                .store_pending_vta_binding("   ", "did:key:z6Mk", "zSeed")
                .is_err()
        );
        assert!(
            store
                .store_pending_vta_binding("slug", "did:key:z6Mk", "")
                .is_err()
        );
    }

    #[test]
    fn bind_vta_did_promotes_pending_to_rotation() {
        let store = test_store();
        store
            .store_pending_vta_binding("slug", "did:key:z6MkPending", "zSeed")
            .unwrap();

        store
            .bind_vta_did("slug", "did:webvh:abc:vta.example.com:primary")
            .unwrap();

        assert!(!store.has_pending_vta_binding("slug"));
        let info = store.loaded_session("slug").unwrap();
        assert_eq!(info.client_did, "did:key:z6MkPending");
        assert_eq!(
            info.vta_did.as_deref(),
            Some("did:webvh:abc:vta.example.com:primary")
        );
    }

    #[test]
    fn bind_vta_did_accepts_did_key_vta() {
        // did:key VTAs are documented in docs/02-vta/cold-start.md — keep
        // the validation loose.
        let store = test_store();
        store
            .store_pending_vta_binding("slug", "did:key:z6MkPending", "zSeed")
            .unwrap();

        store.bind_vta_did("slug", "did:key:z6MkVTA").unwrap();
    }

    #[test]
    fn bind_vta_did_rejects_rebind() {
        let store = test_store();
        store
            .store_direct("slug", "did:key:z6Mk", "zSeed", "did:web:vta.example.com")
            .unwrap();
        let err = store
            .bind_vta_did("slug", "did:web:other.example.com")
            .unwrap_err();
        assert!(err.to_string().contains("already has a VTA DID bound"));
    }

    #[test]
    fn bind_vta_did_rejects_missing_session() {
        let store = test_store();
        let err = store
            .bind_vta_did("no-such-slug", "did:web:vta.example.com")
            .unwrap_err();
        assert!(err.to_string().contains("no session found"));
    }

    #[test]
    fn bind_vta_did_rejects_malformed_input() {
        let store = test_store();
        store
            .store_pending_vta_binding("slug", "did:key:z6Mk", "zSeed")
            .unwrap();

        assert!(store.bind_vta_did("slug", "   ").is_err());
        assert!(store.bind_vta_did("slug", "not-a-did").is_err());
    }

    #[test]
    fn has_pending_vta_binding_false_for_direct_session() {
        let store = test_store();
        store
            .store_direct("slug", "did:key:z6Mk", "zSeed", "did:web:vta.example.com")
            .unwrap();
        assert!(!store.has_pending_vta_binding("slug"));
    }

    #[test]
    fn has_pending_vta_binding_false_for_missing_entry() {
        let store = test_store();
        assert!(!store.has_pending_vta_binding("nope"));
    }

    #[test]
    fn require_vta_did_errors_on_pending() {
        let pending = Session {
            client_did: "did:key:z6MkPending".into(),
            private_key: "zSeed".into(),
            vta_did: None,
            access_token: None,
            access_expires_at: None,
            needs_rotation: false,
        };
        let err = require_vta_did(&pending).unwrap_err();
        assert!(err.to_string().contains("pnm setup continue"));
    }

    // ── Transport selection ───────────────────────────────────────

    #[test]
    fn transport_choice_defaults_to_auto() {
        assert_eq!(TransportChoice::default(), TransportChoice::Auto);
    }

    #[test]
    fn connect_timeout_defaults_when_unset_or_junk() {
        assert_eq!(parse_connect_timeout(None), DIDCOMM_CONNECT_TIMEOUT_DEFAULT);
        assert_eq!(
            parse_connect_timeout(Some("not-a-number".into())),
            DIDCOMM_CONNECT_TIMEOUT_DEFAULT
        );
        // Zero would fail every connect instantly — worse than the hang.
        assert_eq!(
            parse_connect_timeout(Some("0".into())),
            DIDCOMM_CONNECT_TIMEOUT_DEFAULT
        );
    }

    #[test]
    fn connect_timeout_honours_env_override() {
        assert_eq!(
            parse_connect_timeout(Some(" 90 ".into())),
            Duration::from_secs(90)
        );
    }

    /// The whole point of bounding the connect is that the operator learns the
    /// recovery flag exists. If this message stops naming it, the timeout is
    /// just a faster dead end.
    #[test]
    fn mediator_timeout_error_names_the_recovery_flag() {
        let msg =
            mediator_unreachable_error("did:web:mediator.example.com", Duration::from_secs(30));
        assert!(msg.contains("--transport rest"));
        assert!(msg.contains("services didcomm disable"));
        assert!(msg.contains("did:web:mediator.example.com"));
        assert!(msg.contains("30s"));
    }

    #[test]
    fn no_rest_endpoint_error_tells_operator_to_pass_url() {
        let msg = no_rest_endpoint_error("did:webvh:scid:host.example.com").to_string();
        assert!(msg.contains("--url"));
        assert!(msg.contains("did:webvh:scid:host.example.com"));
    }
}
