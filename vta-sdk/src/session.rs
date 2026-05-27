use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

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
    /// 1. Loads session from store (client DID, private key, VTA DID).
    /// 2. If `url_override` is provided, uses REST directly.
    /// 3. Otherwise resolves the VTA DID to discover DIDComm or REST endpoints.
    /// 4. For DIDComm: encryption provides auth (no JWT needed).
    /// 5. For REST: performs challenge-response to obtain a JWT.
    pub async fn connect(
        &self,
        key: &str,
        url_override: Option<&str>,
    ) -> Result<crate::client::VtaClient, Box<dyn std::error::Error>> {
        let session = self.load_session(key).ok_or(
            "Not authenticated.\n\nTo authenticate, import a credential:\n  <cli> auth login <credential-string>",
        )?;

        // URL override: always use REST
        if let Some(url) = url_override {
            debug!(url, "using REST transport (URL override)");
            let token = self.ensure_authenticated(url, key).await?;
            let client = crate::client::VtaClient::new(url);
            client.set_token(token);
            return Ok(client);
        }

        let session_vta_did = require_vta_did(&session)?.to_string();

        // Resolve VTA DID for transport selection
        match resolve_vta_endpoint(&session_vta_did).await? {
            VtaEndpoint::DIDComm {
                vta_did,
                mediator_did,
                rest_url,
            } => {
                debug!("connecting via DIDComm");
                let client = crate::client::VtaClient::connect_didcomm(
                    &session.client_did,
                    &session.private_key,
                    &vta_did,
                    &mediator_did,
                    rest_url,
                )
                .await?;
                Ok(client)
            }
            VtaEndpoint::Rest { url } => {
                debug!(url = %url, "connecting via REST");
                let token = self.ensure_authenticated(&url, key).await?;
                let client = crate::client::VtaClient::new(&url);
                client.set_token(token);
                Ok(client)
            }
        }
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

    // 2. Mint a new did:key.
    let (new_did, new_private_key) = generate_did_key()?;
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

/// Generate a fresh Ed25519 did:key. Returns `(did, private_key_multibase)`.
///
/// The seed is sourced from `getrandom` (the OS CSPRNG). `private_key_multibase`
/// is the raw 32-byte seed base58btc-encoded, matching the format used by the
/// rest of the workspace (see `decode_private_key_multibase`).
fn generate_did_key() -> Result<(String, String), Box<dyn std::error::Error>> {
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
    Ok((did, private_key_multibase))
}

/// Swap a `needs_rotation=true` session's temp did:key for a fresh one.
///
/// Precondition: `temp_token` is a valid bearer token authenticating as
/// `session.client_did` (the temp DID). Returned `Session` carries the new
/// did:key and `needs_rotation=false`; caller is responsible for persisting
/// it alongside the returned `TokenResult` (which is an auth under the new
/// DID, confirming the ACL swap actually lived).
///
/// Flow:
/// 1. `GET /acl/{temp_did}` — read role + allowed_contexts the admin granted.
/// 2. `POST /acl` — create an entry for the new DID with the same scope.
/// 3. Run challenge-response as the new DID to confirm the new entry is
///    live. If that fails, we bail *before* deleting the temp — so the
///    temp still works and the caller can retry.
/// 4. `DELETE /acl/{temp_did}` — best-effort; warn on failure.
async fn rotate_key(
    base_url: &str,
    session: Session,
    temp_token: &str,
) -> Result<(Session, TokenResult), Box<dyn std::error::Error>> {
    let http = reqwest::Client::new();

    // 1. Read the ACL entry the admin granted to the temp DID.
    let acl_url = format!(
        "{}/acl/{}",
        base_url.trim_end_matches('/'),
        &session.client_did
    );
    debug!(url = %acl_url, "fetching ACL entry for temp DID");
    let acl_resp = http
        .get(&acl_url)
        .bearer_auth(temp_token)
        .send()
        .await
        .map_err(|e| format!("GET {acl_url}: {e}"))?;
    if !acl_resp.status().is_success() {
        let status = acl_resp.status();
        let body = acl_resp.text().await.unwrap_or_default();
        return Err(format!(
            "rotate: cannot read temp DID's ACL entry ({status}): {body} — has your admin run `vta import-did --did {} --role admin` yet?",
            session.client_did
        )
        .into());
    }
    let acl_entry: crate::client::AclEntryResponse = acl_resp
        .json()
        .await
        .map_err(|e| format!("parse ACL entry: {e}"))?;
    let role = acl_entry.role.clone();
    let contexts = acl_entry.allowed_contexts.clone();
    let label = acl_entry.label.clone();

    // 2. Mint a new did:key and register it.
    let (new_did, new_private_key) = generate_did_key()?;
    debug!(%new_did, %role, "minted rotation DID, creating ACL entry");
    let mut create_req = crate::client::CreateAclRequest::new(&new_did, role).contexts(contexts);
    if let Some(l) = label {
        create_req = create_req.label(l);
    }
    let acl_post = format!("{}/acl", base_url.trim_end_matches('/'));
    let create_resp = http
        .post(&acl_post)
        .bearer_auth(temp_token)
        .json(&create_req)
        .send()
        .await
        .map_err(|e| format!("POST {acl_post}: {e}"))?;
    if !create_resp.status().is_success() {
        let status = create_resp.status();
        let body = create_resp.text().await.unwrap_or_default();
        return Err(
            format!("rotate: failed to create ACL entry for new DID ({status}): {body}").into(),
        );
    }

    // 3. Verify the new DID can actually authenticate. Fail *before* we
    //    delete the temp — if this errors, the temp still works.
    //
    // `ensure_authenticated` has already gated `vta_did.is_some()` via
    // `require_vta_did`; we're safe to unwrap here.
    let session_vta_did = session
        .vta_did
        .as_deref()
        .expect("ensure_authenticated gates vta_did.is_some() before calling rotate_key");
    let new_token_result = challenge_response(
        base_url,
        &new_did,
        &new_private_key,
        session_vta_did,
    )
    .await
    .map_err(|e| {
        format!(
            "rotate: new DID failed challenge-response (ACL entry present but login failed): {e}"
        )
    })?;

    // 4. Drop the temp DID from the ACL. Best-effort — if this fails, the
    //    new DID is already live, so we log and continue rather than leave
    //    the caller unauthenticated.
    let del_url = format!(
        "{}/acl/{}",
        base_url.trim_end_matches('/'),
        &session.client_did
    );
    match http
        .delete(&del_url)
        .bearer_auth(&new_token_result.access_token)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            debug!(temp_did = %session.client_did, "temp DID removed from ACL");
        }
        Ok(resp) => {
            tracing::warn!(
                temp_did = %session.client_did,
                status = %resp.status(),
                "could not delete temp DID from ACL after rotation — manual cleanup may be required",
            );
        }
        Err(e) => {
            tracing::warn!(
                temp_did = %session.client_did,
                error = %e,
                "could not delete temp DID from ACL after rotation — manual cleanup may be required",
            );
        }
    }

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
    let http = reqwest::Client::new();

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
        "https://affinidi.com/atm/1.0/authenticate".to_string(),
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

/// Resolve a VTA DID to discover its service URL.
///
/// Resolves the DID document and looks for the `#vta-rest` service endpoint.
/// Falls back to parsing the domain from `did:web:` or `did:webvh:` DID strings.
pub async fn resolve_vta_url(vta_did: &str) -> Result<String, Box<dyn std::error::Error>> {
    debug!(vta_did, "resolving VTA DID to discover service URL");

    let did_resolver = DIDCacheClient::new(crate::resolver::build_did_cache_config_from_env())
        .await
        .map_err(|e| format!("DID resolver init failed: {e}"))?;

    match did_resolver.resolve(vta_did).await {
        Ok(resolved) => {
            if let Some(svc) = resolved.doc.find_service("vta-rest")
                && let Some(url) = svc.service_endpoint.get_uri()
            {
                let url = url.trim_matches('"').trim_end_matches('/').to_string();
                debug!(url = %url, "found VTA URL from #vta-rest service endpoint");
                return Ok(url);
            }
            debug!("no #vta-rest service found in DID document, falling back to DID parsing");
        }
        Err(e) => {
            debug!(error = %e, "DID resolution failed, falling back to DID parsing");
        }
    }

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
}
