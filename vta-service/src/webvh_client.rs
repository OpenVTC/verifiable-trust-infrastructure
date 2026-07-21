use serde::Deserialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Total-request timeout for a call to a webvh hosting daemon (auth, publish,
/// delete, register). Generous enough for a DID-log publish, bounded so a
/// wedged daemon can't hang the operation — or the per-server auth mutex.
const WEBVH_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// TCP/TLS connect timeout for a webvh hosting daemon.
const WEBVH_HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
use tracing::{debug, info, warn};
use url::{Host, Url};

use crate::error::AppError;
use crate::webvh_auth::{
    ChallengeContext, VtaSigningIdentity, build_authenticate_message, build_refresh_message,
};

pub struct WebvhClient {
    http: reqwest::Client,
    server_url: String,
    /// The daemon's DID. Bound at construction so the auth flow can
    /// populate the DIDComm `to:` field for audience-binding, and so
    /// the operator-facing error messages can name *which* daemon
    /// the failure came from.
    server_did: String,
    access_token: Option<String>,
}

/// Decide whether a host is a loopback address we're willing to dial
/// over plaintext `http://` in dev. We accept:
///
/// - the literal domain `localhost` (and only that — `localhost.evil`
///   resolves to attacker-controlled IPs),
/// - any IPv4 in `127.0.0.0/8` (covers `127.0.0.1` and dev shims like
///   `127.0.0.2`),
/// - the IPv6 loopback `::1` (and only that — `::ffff:8.8.8.8` IPv4-
///   mapped IPv6 is *not* a loopback even though it sometimes parses
///   as one in laxer stacks).
///
/// We deliberately exclude `0.0.0.0` (a listen-on-all-interfaces
/// sentinel an operator should rarely *dial*) and
/// `host.docker.internal` (resolution depends on the container
/// runtime). Operators who need plain HTTP from outside loopback
/// should terminate TLS at a reverse proxy and advertise its
/// `https://` URL in the daemon DID's service entry.
fn is_loopback_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(d) => *d == "localhost",
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => ip.is_loopback(),
    }
}

/// Reject schemes other than `https://` (always) or `http://` to a
/// loopback host (dev only). Bearer tokens, the VTA-signed
/// authenticate JWS, and refresh tokens must never travel over
/// plaintext. The check happens at client construction so every
/// REST entrypoint inherits it — there is no "skip the check"
/// path for individual requests.
fn enforce_transport_security(parsed: &Url, raw: &str) -> Result<(), AppError> {
    let scheme = parsed.scheme();
    if scheme == "https" {
        return Ok(());
    }
    if scheme == "http" {
        if parsed.host().map(|h| is_loopback_host(&h)).unwrap_or(false) {
            return Ok(());
        }
        return Err(AppError::Validation(format!(
            "refusing to dial webvh-server `{raw}` over plaintext `http://`: \
             bearer tokens and the VTA's signed authenticate payload must not be sent \
             over plaintext. Only `http://` to a loopback host \
             (localhost, 127/8, ::1) is permitted; advertise an `https://` endpoint in \
             the server DID's service entry instead.",
        )));
    }
    Err(AppError::Validation(format!(
        "webvh-server URL `{raw}` uses unsupported scheme `{scheme}://`; \
         only `https://` (recommended) or `http://` to a loopback host are accepted.",
    )))
}

/// Wire shape of `POST /api/dids` (and `/api/dids/register`) responses.
/// The daemon (`did-hosting-common::RequestUriResponse`) serializes camelCase,
/// so `did_url` arrives as `didUrl` — match it or the body fails to decode.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestUriResponse {
    pub did_url: String,
    pub mnemonic: String,
}

#[derive(Debug, Deserialize)]
pub struct CheckPathResponse {
    pub available: bool,
}

/// One entry of the host's `agentNames` array on `GET /api/dids/{mnemonic}`.
/// Deserialize-only: the VTA reads this registry, the host owns it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentNameEntryWire {
    pub name: String,
    /// `false` = parked: still reserved to this DID, just not resolving.
    pub enabled: bool,
    pub created_at: u64,
}

/// Wire shape of `POST /api/agent-names/check`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentNameAvailabilityWire {
    pub name: String,
    pub domain: String,
    pub available: bool,
    pub reserved: bool,
}

/// The VTA's **internal** token representation — the value
/// `authenticate()` / `refresh()` return and `auth_cache::persist_tokens`
/// writes to `WebvhServerAuthRecord`. Not a wire type: it is built from
/// [`TokenResponseWire`] via [`TokenResponseWire::into_token_data`], which
/// converts the daemon's **relative** `expiresIn` / `refreshExpiresIn`
/// (seconds-from-now) into the **absolute** Unix-second expiries this
/// type (and the cached record) store. The daemon **always rotates the
/// refresh token** on use, so a `TokenData` returned from `refresh()`
/// carries a different `refresh_token` from the one supplied as input —
/// callers must persist the new value.
///
/// Hygiene:
/// - `ZeroizeOnDrop` overwrites the token bytes when the instance
///   falls out of scope.
/// - `Debug` is manually implemented to redact the token strings —
///   accidental `tracing::error!(?tokens, ...)` then logs
///   `<redacted>` instead of the secret.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct TokenData {
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: String,
    pub refresh_expires_at: u64,
}

impl std::fmt::Debug for TokenData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenData")
            .field("access_token", &"<redacted>")
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_token", &"<redacted>")
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish()
    }
}

/// Wire shape of `/api/auth/` and `/api/auth/refresh` responses. The
/// daemon emits a **flat** body — `{ session, tokens }` — matching its
/// `did_hosting_common::AuthenticateResponse` / `RefreshResponse`
/// (both `spec/auth/authenticate/0.1#response`, the `{ session, tokens }`
/// canonical shape). `session` is accepted for shape-completeness but the
/// client doesn't need it. `tokens` carries **relative** OAuth2-style
/// expiries (`expiresIn` seconds from issuance), converted to absolute in
/// [`Self::into_token_data`].
#[derive(Debug, Deserialize)]
struct TokenResponseWire {
    #[allow(dead_code)] // accepted for shape match; client doesn't need the value
    session: serde::de::IgnoredAny,
    tokens: TokenBundleWire,
}

/// Wire shape of the daemon's `TokenBundle` (`spec/auth/_shared/0.1/
/// tokens.schema.json`, camelCase). Expiries are **relative** — seconds
/// from issuance (RFC 6749 §5.1) — not absolute timestamps. `refresh_token`
/// / `refresh_expires_in` are optional on the canonical shape, but the VTA
/// flow relies on rotation, so [`TokenResponseWire::into_token_data`]
/// rejects a bundle that omits them.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenBundleWire {
    access_token: String,
    expires_in: u64,
    refresh_token: Option<String>,
    refresh_expires_in: Option<u64>,
}

impl TokenResponseWire {
    /// Convert the daemon's relative-expiry wire bundle into the VTA's
    /// internal absolute-expiry [`TokenData`]. `now_secs` is the current
    /// Unix time captured at the call site (via `unix_now_secs()`); the
    /// absolute expiry is `now_secs + expires_in`, saturating so an
    /// implausibly large `expires_in` can't wrap.
    fn into_token_data(self, now_secs: u64) -> Result<TokenData, AppError> {
        let refresh_token = self.tokens.refresh_token.ok_or_else(|| {
            AppError::Internal(
                "webvh-server auth response omitted `refreshToken`; the VTA requires a \
                 refresh token to keep the hosting session alive"
                    .to_string(),
            )
        })?;
        let refresh_expires_in = self.tokens.refresh_expires_in.ok_or_else(|| {
            AppError::Internal(
                "webvh-server auth response omitted `refreshExpiresIn`; cannot compute \
                 the refresh-token expiry"
                    .to_string(),
            )
        })?;
        Ok(TokenData {
            access_token: self.tokens.access_token,
            access_expires_at: now_secs.saturating_add(self.tokens.expires_in),
            refresh_token,
            refresh_expires_at: now_secs.saturating_add(refresh_expires_in),
        })
    }
}

/// Wire shape of `/api/auth/challenge` response. The daemon emits a
/// **flat** body — `{ challenge, sessionId, expiresAt }` — matching
/// its `did_hosting_common::ChallengeResponse`
/// (`spec/auth/challenge/0.1#response`), which dropped the `data: {}`
/// envelope. `#[serde(rename_all = "camelCase")]` deserialises
/// `sessionId`; the `alias` keeps older daemon builds that emitted
/// snake_case working through one upgrade cycle. `expiresAt` is
/// ignored — the client redeems the challenge immediately and the
/// daemon enforces its own TTL.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponseWire {
    challenge: String,
    #[serde(alias = "session_id")]
    session_id: String,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl WebvhClient {
    /// Construct a client for a daemon REST URL. Rejects URLs whose
    /// scheme would send the bearer token / authenticate JWS over
    /// plaintext to a non-loopback host. See
    /// [`enforce_transport_security`] for the policy.
    ///
    /// `server_did` is the daemon's DID. The auth flow uses it for
    /// the DIDComm `to:` field (audience binding) and operator-facing
    /// error messages name it explicitly.
    pub fn new(server_url: &str, server_did: &str) -> Result<Self, AppError> {
        let parsed = Url::parse(server_url).map_err(|e| {
            AppError::Validation(format!("invalid webvh-server URL `{server_url}`: {e}"))
        })?;
        enforce_transport_security(&parsed, server_url)?;
        Ok(Self {
            // Finite timeouts: reqwest has none by default. A wedged hosting
            // daemon (accepts TCP, never answers) must surface as a timeout
            // error, not an unbounded hang — which also bounds how long the
            // per-server auth mutex (`auth_cache::ensure_fresh_access_token`)
            // is held across `authenticate`/`refresh`, so one dead daemon can't
            // freeze all publishing for that server.
            http: reqwest::Client::builder()
                .timeout(WEBVH_HTTP_TIMEOUT)
                .connect_timeout(WEBVH_HTTP_CONNECT_TIMEOUT)
                .build()
                .expect("reqwest client with timeouts (TLS backend init)"),
            server_url: server_url.trim_end_matches('/').to_string(),
            server_did: server_did.to_string(),
            access_token: None,
        })
    }

    pub fn set_access_token(&mut self, token: String) {
        self.access_token = Some(token);
    }

    /// Run the full challenge → JWS-authenticate flow against the
    /// daemon, returning a fresh token pair. Does not mutate
    /// `self.access_token`; the caller chooses what to do with the
    /// returned tokens (typically persist via `webvh_store`).
    ///
    /// Errors map to typed `AppError` variants so the route /
    /// operation layer can surface the right hint to the operator:
    ///
    /// - daemon 401 → `Authentication` (signature / session /
    ///   challenge invalid; likely clock skew or kid mismatch),
    /// - daemon 403 → `Forbidden` (signature valid, VTA DID not in
    ///   daemon ACL — corrective action is daemon-side),
    /// - daemon 4xx other → `Validation`,
    /// - daemon 5xx → `Internal`,
    /// - network/parse failures → `Internal`.
    pub async fn authenticate(
        &self,
        identity: &VtaSigningIdentity<'_>,
    ) -> Result<TokenData, AppError> {
        let challenge = self.fetch_challenge(identity.vta_did).await?;

        let jws = build_authenticate_message(
            identity,
            &ChallengeContext {
                session_id: &challenge.session_id,
                challenge: &challenge.challenge,
                server_did: &self.server_did,
            },
            unix_now_secs(),
        )?;

        let url = format!("{}/api/auth/", self.server_url);
        info!(method = "POST", %url, "webvh: authenticating");
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .body(jws)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("webvh authenticate request failed: {e}")))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(self.map_auth_failure(status, &body, identity.vta_did));
        }
        let parsed: TokenResponseWire = serde_json::from_str(&body).map_err(|e| {
            AppError::Internal(format!(
                "webvh authenticate response parse error: {e} (body: {body})"
            ))
        })?;
        parsed.into_token_data(unix_now_secs())
    }

    /// Redeem a refresh token against the daemon. Returns the rotated
    /// token pair. The daemon always rotates refresh tokens on use, so
    /// the returned `refresh_token` differs from the input — callers
    /// must persist the new one immediately.
    pub async fn refresh(
        &self,
        identity: &VtaSigningIdentity<'_>,
        refresh_token: &str,
    ) -> Result<TokenData, AppError> {
        let jws =
            build_refresh_message(identity, &self.server_did, refresh_token, unix_now_secs())?;
        let url = format!("{}/api/auth/refresh", self.server_url);
        info!(method = "POST", %url, "webvh: refreshing token");
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .body(jws)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("webvh refresh request failed: {e}")))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            // Refresh failure is normal at end-of-lifetime — return
            // a typed `Authentication` so the caller can fall back to
            // a full re-authenticate instead of bubbling a 500.
            warn!(
                status = %status,
                vta_did = %identity.vta_did,
                "webvh refresh rejected by daemon",
            );
            return Err(AppError::Authentication(format!(
                "webvh-server {} rejected refresh token (status {status}): {body}",
                self.server_did,
            )));
        }
        let parsed: TokenResponseWire = serde_json::from_str(&body).map_err(|e| {
            AppError::Internal(format!(
                "webvh refresh response parse error: {e} (body: {body})"
            ))
        })?;
        parsed.into_token_data(unix_now_secs())
    }

    async fn fetch_challenge(&self, vta_did: &str) -> Result<ChallengeResponseWire, AppError> {
        let url = format!("{}/api/auth/challenge", self.server_url);
        debug!(method = "POST", %url, "webvh: fetching challenge");
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "did": vta_did }))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("webvh challenge request failed: {e}")))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(AppError::Internal(format!(
                "webvh-server {} POST /api/auth/challenge failed (status {status}): {body}",
                self.server_did,
            )));
        }
        serde_json::from_str(&body).map_err(|e| {
            AppError::Internal(format!(
                "webvh challenge response parse error: {e} (body: {body})"
            ))
        })
    }

    /// Map a non-2xx response from `/api/auth/` to a typed `AppError`.
    ///
    /// The daemon distinguishes:
    ///
    /// - **401 Unauthorized** — signature / session / challenge
    ///   verification failed. Common causes: clock skew between VTA
    ///   and daemon (daemon accepts a ±5min window), the challenge
    ///   expired before redemption, or the signing-key fragment on
    ///   the VTA doesn't match a verification method in its DID
    ///   document.
    /// - **403 Forbidden** — signature was valid, but the VTA's
    ///   DID is not in the daemon's ACL. Corrective action is on
    ///   the daemon side.
    ///
    /// Two distinct hints so the CLI can guide the operator to the
    /// *actually* broken thing. (Earlier on this branch the ACL hint
    /// was attached to the 401 arm — caught by the audit.)
    fn map_auth_failure(&self, status: reqwest::StatusCode, body: &str, vta_did: &str) -> AppError {
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return AppError::Authentication(format!(
                "webvh-server {server_did} rejected authentication signature for VTA DID `{vta_did}`. \
                 Likely causes: clock skew between VTA and daemon (daemon accepts a ±5min window), \
                 expired challenge, or a signing-key fragment that doesn't match a verification method \
                 in the VTA's DID document. Daemon response: {body}",
                server_did = self.server_did,
            ));
        }
        if status == reqwest::StatusCode::FORBIDDEN {
            return AppError::Forbidden(format!(
                "webvh-server {server_did} accepted the signature for VTA DID `{vta_did}` but the \
                 DID is not in the daemon's ACL. The corrective action is daemon-side: grant the \
                 VTA's DID access on the daemon. Daemon response: {body}",
                server_did = self.server_did,
            ));
        }
        if status.is_client_error() {
            return AppError::Validation(format!(
                "webvh-server {} rejected authentication (status {status}): {body}",
                self.server_did,
            ));
        }
        AppError::Internal(format!(
            "webvh-server {} authentication failed (status {status}): {body}",
            self.server_did,
        ))
    }

    /// Apply authorization header (if set) to a request builder.
    fn with_auth(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(ref token) = self.access_token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        req
    }

    /// Send a request and map non-2xx HTTP statuses to typed
    /// `AppError` variants so the operation layer can switch on them:
    ///
    /// - 401 → `Unauthorized` (token rejected; caller should
    ///   invalidate cache and re-authenticate),
    /// - 403 → `Forbidden` (daemon ACL miss),
    /// - 4xx other → `Validation` (request-shape rejection),
    /// - 5xx → `Internal` (daemon-side fault),
    /// - network failure → `Internal`.
    ///
    /// The error message names the daemon DID so operator-facing
    /// errors don't need to thread the server identity separately.
    async fn send(
        &self,
        req: reqwest::RequestBuilder,
        context: &str,
    ) -> Result<reqwest::Response, AppError> {
        let resp = req
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server request failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            let msg = format!(
                "webvh-server {server} {context} failed ({status}): {text}",
                server = self.server_did,
            );
            return Err(match status {
                reqwest::StatusCode::UNAUTHORIZED => AppError::Unauthorized(msg),
                reqwest::StatusCode::FORBIDDEN => AppError::Forbidden(msg),
                // A taken path (e.g. `POST /api/dids` on an already-reserved
                // slot) is a clean conflict, not a malformed request — keep
                // it a 409 to the caller rather than collapsing to a 400.
                reqwest::StatusCode::CONFLICT => AppError::Conflict(msg),
                s if s.is_client_error() => AppError::Validation(msg),
                _ => AppError::Internal(msg),
            });
        }
        debug!(
            status = status.as_u16(),
            context, "webvh: received via rest"
        );
        Ok(resp)
    }

    /// POST /api/dids — reserve a path on the remote.
    ///
    /// `domain` is the optional hosting domain to target. When the
    /// remote serves multiple tenant domains, the operator (via pnm
    /// CLI `--domain`) supplies the target; otherwise the remote
    /// resolves through caller's ACL default → system default. An
    /// unknown domain on the remote is rejected as
    /// `did-management:unknown_domain`.
    pub async fn request_uri(
        &self,
        path: Option<&str>,
        domain: Option<&str>,
    ) -> Result<RequestUriResponse, AppError> {
        let url = format!("{}/api/dids", self.server_url);
        info!(method = "POST", %url, "webvh: sending via rest");
        let mut body = serde_json::Map::new();
        if let Some(p) = path {
            body.insert("path".to_string(), serde_json::Value::String(p.to_string()));
        }
        if let Some(d) = domain {
            body.insert(
                "domain".to_string(),
                serde_json::Value::String(d.to_string()),
            );
        }
        let req = self
            .with_auth(self.http.post(&url))
            .json(&serde_json::Value::Object(body));
        let resp = self.send(req, "POST /api/dids").await?;
        resp.json()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server response parse error: {e}")))
    }

    /// POST /api/dids/register — atomic claim-and-publish.
    ///
    /// Single round-trip equivalent to `request_uri(path)` +
    /// `publish_did(mnemonic, log_content)` but committed in one fjall
    /// batch on the server, so resolvers never see the slot empty
    /// between allocation and content upload. The relevant flow for
    /// promoting an existing serverless DID to a host without a
    /// resolvability gap.
    ///
    /// `force` is honoured only when the caller is an admin replacing a
    /// slot owned by a different DID. The owner re-registering their
    /// own slot is idempotent and needs no force.
    ///
    /// `domain` follows the same resolution chain as `request_uri`.
    pub async fn register_did_atomic(
        &self,
        path: &str,
        did_log: &str,
        force: bool,
        domain: Option<&str>,
    ) -> Result<RequestUriResponse, AppError> {
        let url = format!("{}/api/dids/register", self.server_url);
        info!(method = "POST", %url, "webvh: sending via rest");
        let mut body = serde_json::Map::new();
        body.insert(
            "path".to_string(),
            serde_json::Value::String(path.to_string()),
        );
        // Send the canonical `didData` + `method` shape introduced by
        // the v0.1 did-management spec. The remote accepts the legacy
        // `did_log` shape too (T26 normalisation), but emitting the
        // canonical form keeps this client off the deprecation path.
        body.insert(
            "method".to_string(),
            serde_json::Value::String("webvh".to_string()),
        );
        body.insert(
            "didData".to_string(),
            serde_json::Value::String(did_log.to_string()),
        );
        body.insert("force".to_string(), serde_json::Value::Bool(force));
        if let Some(d) = domain {
            body.insert(
                "domain".to_string(),
                serde_json::Value::String(d.to_string()),
            );
        }
        let req = self
            .with_auth(self.http.post(&url))
            .json(&serde_json::Value::Object(body));
        let resp = self.send(req, "POST /api/dids/register").await?;
        resp.json()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server response parse error: {e}")))
    }

    /// PUT /api/dids/{mnemonic} — publish DID log.
    ///
    /// The `domain` argument is accepted for disambiguation on hosts
    /// that run per-domain mnemonic namespaces. Hosts with a flat
    /// namespace ignore it on lookup; a mismatched explicit domain is
    /// surfaced as `did-management:unknown_domain`.
    pub async fn publish_did(
        &self,
        mnemonic: &str,
        log_content: &str,
        domain: Option<&str>,
    ) -> Result<(), AppError> {
        let url = if let Some(d) = domain {
            format!(
                "{}/api/dids/{mnemonic}?domain={}",
                self.server_url,
                url::form_urlencoded::byte_serialize(d.as_bytes()).collect::<String>()
            )
        } else {
            format!("{}/api/dids/{mnemonic}", self.server_url)
        };
        info!(method = "PUT", %url, "webvh: sending via rest");
        let req = self
            .with_auth(self.http.put(&url))
            .header("Content-Type", "application/jsonl")
            .body(log_content.to_string());
        self.send(req, &format!("PUT /api/dids/{mnemonic}")).await?;
        Ok(())
    }

    /// POST /api/agent-names/{op} — bind (`set`), release (`remove`), park
    /// (`disable`) or resume (`enable`) an agent name via a signed new DID
    /// version.
    ///
    /// `did_log` is the full new signed `did.jsonl` whose `alsoKnownAs` claims
    /// (`set`/`enable`) or no longer claims (`remove`/`disable`) the name; the
    /// host verifies that direction matches the verb, republishes the log as a
    /// new version, and applies the registry change in one commit.
    ///
    /// One generic call rather than four wrappers: the request body is
    /// identical for every verb, so the only thing a wrapper would add is a
    /// place for the endpoint and the document direction to disagree.
    pub async fn agent_name_op(
        &self,
        op: &str,
        mnemonic: &str,
        name: &str,
        did_log: &str,
        domain: Option<&str>,
    ) -> Result<(), AppError> {
        let url = format!("{}/api/agent-names/{op}", self.server_url);
        info!(method = "POST", %url, "webvh: sending via rest");
        let mut body = serde_json::Map::new();
        body.insert(
            "mnemonic".to_string(),
            serde_json::Value::String(mnemonic.to_string()),
        );
        body.insert(
            "name".to_string(),
            serde_json::Value::String(name.to_string()),
        );
        body.insert(
            "didLog".to_string(),
            serde_json::Value::String(did_log.to_string()),
        );
        if let Some(d) = domain {
            body.insert(
                "domain".to_string(),
                serde_json::Value::String(d.to_string()),
            );
        }
        let req = self
            .with_auth(self.http.post(&url))
            .json(&serde_json::Value::Object(body));
        self.send(req, &format!("POST /api/agent-names/{op}"))
            .await?;
        Ok(())
    }

    /// GET /api/dids/{mnemonic} — the DID's agent-name registry.
    ///
    /// Returns the record's `agentNames`, **parked entries included**. That is
    /// the whole point: parking works by dropping the name from `alsoKnownAs`,
    /// so a caller that only resolves the DID document cannot see a parked
    /// name at all and has nothing to offer "resume" on.
    ///
    /// A host that predates the registry omits the field; that is an empty
    /// list, not an error.
    pub async fn list_agent_names(
        &self,
        mnemonic: &str,
        domain: Option<&str>,
    ) -> Result<Vec<AgentNameEntryWire>, AppError> {
        let url = if let Some(d) = domain {
            format!(
                "{}/api/dids/{mnemonic}?domain={}",
                self.server_url,
                url::form_urlencoded::byte_serialize(d.as_bytes()).collect::<String>()
            )
        } else {
            format!("{}/api/dids/{mnemonic}", self.server_url)
        };
        info!(method = "GET", %url, "webvh: sending via rest");
        let req = self.with_auth(self.http.get(&url));
        let body = self
            .send(req, &format!("GET /api/dids/{mnemonic}"))
            .await?
            .json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server response parse error: {e}")))?;
        let Some(names) = body.get("agentNames") else {
            return Ok(Vec::new());
        };
        serde_json::from_value(names.clone())
            .map_err(|e| AppError::Internal(format!("webvh-server agentNames parse error: {e}")))
    }

    /// POST /api/agent-names/check — is this name free on `domain`?
    ///
    /// `reserved` is reported separately from `available` so a caller can say
    /// *why* a name is unavailable. A malformed name is an error, not an
    /// unavailable answer.
    pub async fn check_agent_name(
        &self,
        name: &str,
        domain: Option<&str>,
    ) -> Result<AgentNameAvailabilityWire, AppError> {
        let url = format!("{}/api/agent-names/check", self.server_url);
        info!(method = "POST", %url, "webvh: sending via rest");
        let mut body = serde_json::Map::new();
        body.insert(
            "name".to_string(),
            serde_json::Value::String(name.to_string()),
        );
        if let Some(d) = domain {
            body.insert(
                "domain".to_string(),
                serde_json::Value::String(d.to_string()),
            );
        }
        let req = self
            .with_auth(self.http.post(&url))
            .json(&serde_json::Value::Object(body));
        self.send(req, "POST /api/agent-names/check")
            .await?
            .json::<AgentNameAvailabilityWire>()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server response parse error: {e}")))
    }

    /// DELETE /api/dids/{mnemonic}.
    pub async fn delete_did(&self, mnemonic: &str, domain: Option<&str>) -> Result<(), AppError> {
        let url = if let Some(d) = domain {
            format!(
                "{}/api/dids/{mnemonic}?domain={}",
                self.server_url,
                url::form_urlencoded::byte_serialize(d.as_bytes()).collect::<String>()
            )
        } else {
            format!("{}/api/dids/{mnemonic}", self.server_url)
        };
        info!(method = "DELETE", %url, "webvh: sending via rest");
        let req = self.with_auth(self.http.delete(&url));
        self.send(req, &format!("DELETE /api/dids/{mnemonic}"))
            .await?;
        Ok(())
    }

    /// POST /api/dids/check — check whether a path is available, with
    /// optional atomic reservation (v0.1 `did-management/did/check-name/0.1`
    /// `reserve` flag).
    pub async fn check_path(
        &self,
        path: &str,
        reserve: bool,
        domain: Option<&str>,
    ) -> Result<CheckPathResponse, AppError> {
        let url = format!("{}/api/dids/check", self.server_url);
        let mut body = serde_json::Map::new();
        body.insert(
            "path".to_string(),
            serde_json::Value::String(path.to_string()),
        );
        if reserve {
            body.insert("reserve".to_string(), serde_json::Value::Bool(true));
        }
        if let Some(d) = domain {
            body.insert(
                "domain".to_string(),
                serde_json::Value::String(d.to_string()),
            );
        }
        let req = self
            .with_auth(self.http.post(&url))
            .json(&serde_json::Value::Object(body));
        let resp = self.send(req, "POST /api/dids/check").await?;
        resp.json()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server response parse error: {e}")))
    }

    /// GET /api/me/domains — list the hosting domains the caller's
    /// ACL scope permits on this server. Read-only; used by the pnm
    /// CLI to discover legitimate `--domain` values before creating
    /// a DID.
    pub async fn list_my_domains(&self) -> Result<MyDomainsResponse, AppError> {
        let url = format!("{}/api/me/domains", self.server_url);
        info!(method = "GET", %url, "webvh: sending via rest");
        let req = self.with_auth(self.http.get(&url));
        let resp = self.send(req, "GET /api/me/domains").await?;
        resp.json()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server response parse error: {e}")))
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MyDomainsResponse {
    pub domains: Vec<MyDomainEntry>,
    pub default: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MyDomainEntry {
    pub name: String,
    #[serde(default)]
    pub default_domain: bool,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_validation_err(result: Result<WebvhClient, AppError>, needle: &str) {
        match result {
            Err(AppError::Validation(msg)) => assert!(
                msg.contains(needle),
                "expected validation error to contain `{needle}`, got: {msg}"
            ),
            Err(other) => panic!("expected Validation error, got {other:?}"),
            Ok(_) => panic!("expected Validation error, got Ok"),
        }
    }

    #[test]
    fn https_url_is_accepted() {
        // Standard production case — DID advertises an https endpoint.
        let c = WebvhClient::new("https://daemon.example", "did:web:daemon.example")
            .expect("https must be accepted");
        assert_eq!(c.server_url, "https://daemon.example");
    }

    #[test]
    fn https_url_trailing_slash_is_normalised() {
        // Match the existing trim_end_matches('/') behaviour so callers
        // can format paths with a leading slash without producing `//`.
        let c = WebvhClient::new("https://daemon.example/", "did:web:daemon.example").unwrap();
        assert_eq!(c.server_url, "https://daemon.example");
    }

    #[test]
    fn http_to_non_loopback_is_rejected() {
        // The core invariant: bearer tokens and the signed JWS must
        // not be sent over plaintext to a network-reachable host.
        assert_validation_err(
            WebvhClient::new("http://daemon.example", "did:web:daemon.example"),
            "refusing to dial webvh-server",
        );
    }

    #[test]
    fn http_to_localhost_is_accepted_for_dev() {
        // Local-dev escape hatch — operator's daemon on the same host.
        let c = WebvhClient::new("http://localhost:8530", "did:web:daemon.example").unwrap();
        assert_eq!(c.server_url, "http://localhost:8530");
    }

    #[test]
    fn http_to_127_0_0_1_is_accepted() {
        let c = WebvhClient::new("http://127.0.0.1:8530", "did:web:daemon.example").unwrap();
        assert_eq!(c.server_url, "http://127.0.0.1:8530");
    }

    #[test]
    fn http_to_127_0_0_x_subnet_is_accepted() {
        // We use the IPv4 `is_loopback()` predicate, which covers all
        // of `127.0.0.0/8` — including dev shims like 127.0.0.2 that
        // operators use to bind multiple local services.
        let c = WebvhClient::new("http://127.0.0.5:8530", "did:web:daemon.example").unwrap();
        assert_eq!(c.server_url, "http://127.0.0.5:8530");
    }

    #[test]
    fn http_to_ipv6_loopback_is_accepted() {
        let c = WebvhClient::new("http://[::1]:8530", "did:web:daemon.example").unwrap();
        // The url crate normalises bracketed IPv6 in display form.
        assert!(c.server_url.contains("::1"));
    }

    #[test]
    fn http_to_0_0_0_0_is_rejected() {
        // 0.0.0.0 is a listen-on-all address. An operator dialing it
        // from the VTA host is technically loopback-equivalent, but
        // it's also the kind of typo that a misconfigured daemon DID
        // can introduce — fail loud rather than silently allow it.
        assert_validation_err(
            WebvhClient::new("http://0.0.0.0:8530", "did:web:daemon.example"),
            "refusing to dial webvh-server",
        );
    }

    #[test]
    fn ftp_scheme_is_rejected() {
        assert_validation_err(
            WebvhClient::new("ftp://daemon.example/", "did:web:daemon.example"),
            "unsupported scheme",
        );
    }

    #[test]
    fn ws_scheme_is_rejected() {
        // WebSocket isn't a wire we serve daemon REST over —
        // a daemon DID advertising ws:// is a misconfiguration.
        assert_validation_err(
            WebvhClient::new("ws://daemon.example/", "did:web:daemon.example"),
            "unsupported scheme",
        );
    }

    #[test]
    fn malformed_url_is_rejected() {
        assert_validation_err(
            WebvhClient::new("not-a-url", "did:web:daemon.example"),
            "invalid webvh-server URL",
        );
    }

    #[test]
    fn empty_url_is_rejected() {
        assert_validation_err(
            WebvhClient::new("", "did:web:daemon.example"),
            "invalid webvh-server URL",
        );
    }

    #[test]
    fn https_to_loopback_is_also_accepted() {
        // Operators running a TLS-terminating proxy locally
        // (mkcert + nginx, mitmproxy) should still work.
        let c = WebvhClient::new("https://localhost:8443", "did:web:daemon.example").unwrap();
        assert_eq!(c.server_url, "https://localhost:8443");
    }

    #[test]
    fn http_to_hostname_resembling_localhost_is_rejected() {
        // `localhost.evil.com` resolves wherever the attacker wants —
        // accept only the literal `localhost`, not anything ending in it.
        assert_validation_err(
            WebvhClient::new("http://localhost.evil.example", "did:web:daemon.example"),
            "refusing to dial webvh-server",
        );
    }

    // ── HTTP-flow tests against a wiremock daemon ──────────────────
    //
    // wiremock spins up a real local server bound to 127.0.0.1:<random>;
    // our HTTPS policy admits loopback HTTP so no insecure-test knob is
    // needed. Each test scopes its `MockServer` so the port is freed
    // between tests.

    use crate::webvh_auth::VtaSigningIdentity;
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn signing_identity() -> ([u8; 32], String, String) {
        let seed = [9u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vta_did = "did:webvh:test:vta".to_string();
        let kid = format!("{vta_did}#key-0");
        (sk.to_bytes(), vta_did, kid)
    }

    fn token_response_json() -> serde_json::Value {
        // Daemon's flat `AuthenticateResponse` wire shape (camelCase):
        // `{ session, tokens }`, with OAuth2-style *relative* expiries
        // (`expiresIn` seconds from issuance), no `data` envelope.
        json!({
            "session": {
                "id": "auth-session-1",
                "subject": "did:webvh:test:vta",
                "issuedAt": "2026-01-01T00:00:00Z",
                "expiresAt": "2026-01-02T00:00:00Z",
            },
            "tokens": {
                "accessToken": "access-token-A",
                "refreshToken": "refresh-token-A",
                "tokenType": "Bearer",
                "expiresIn": 900u64,
                "refreshExpiresIn": 86_400u64,
                "scope": ["did:hosting"],
            }
        })
    }

    fn challenge_response_json() -> serde_json::Value {
        // Daemon's `ChallengeResponse` wire shape — flat
        // `{ challenge, sessionId, expiresAt }`, no `data` envelope.
        json!({
            "challenge": "deadbeef",
            "sessionId": "chal-session-1",
            "expiresAt": "2026-01-01T00:00:00Z",
        })
    }

    #[tokio::test]
    async fn authenticate_round_trips_against_mock_daemon() {
        // Happy path: challenge → JWS authenticate → tokens.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(challenge_response_json()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/auth/"))
            .and(header("Content-Type", "application/json"))
            // The JWS payload is base64url-encoded; we can't match on
            // its inner content here. The wire-shape correctness of
            // the JWS is verified by the unit tests in `webvh_auth`.
            .respond_with(ResponseTemplate::new(200).set_body_json(token_response_json()))
            .expect(1)
            .mount(&server)
            .await;

        let (private, vta_did, kid) = signing_identity();
        let client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };

        let before = unix_now_secs();
        let tokens = client
            .authenticate(&identity)
            .await
            .expect("authenticate must succeed");
        let after = unix_now_secs();
        assert_eq!(tokens.access_token, "access-token-A");
        assert_eq!(tokens.refresh_token, "refresh-token-A");
        // The daemon returns *relative* `expiresIn: 900`; the client
        // converts to an *absolute* expiry `now + 900`. Bracket by the
        // pre/post-call clock reads so we don't depend on exact timing.
        assert!(
            (before + 900..=after + 900).contains(&tokens.access_expires_at),
            "access_expires_at {} not within now+900 window [{}, {}]",
            tokens.access_expires_at,
            before + 900,
            after + 900,
        );
        assert!(
            (before + 86_400..=after + 86_400).contains(&tokens.refresh_expires_at),
            "refresh_expires_at {} not within now+86400 window",
            tokens.refresh_expires_at,
        );
    }

    #[tokio::test]
    async fn authenticate_401_surfaces_signature_freshness_hint() {
        // 401 from the daemon means signature/session/challenge
        // verification failed — typically clock skew, expired
        // challenge, or a kid that doesn't match a verification
        // method. The hint must NOT misdirect the operator toward
        // ACL edits (that's the 403 case below).
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(challenge_response_json()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/auth/"))
            .respond_with(ResponseTemplate::new(401).set_body_string("invalid signature"))
            .mount(&server)
            .await;

        let (private, vta_did, kid) = signing_identity();
        let client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };

        let err = client.authenticate(&identity).await.unwrap_err();
        match err {
            AppError::Authentication(msg) => {
                assert!(
                    msg.contains("clock skew") || msg.contains("expired challenge"),
                    "401 must hint at signature/freshness failures, not ACL: {msg}"
                );
                assert!(
                    !msg.contains("not in the daemon's ACL"),
                    "401 must NOT suggest ACL change (that's the 403 case): {msg}"
                );
            }
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authenticate_403_surfaces_acl_hint() {
        // 403 from the daemon means signature was valid but the VTA
        // DID is not in the ACL. The CLI must direct the operator
        // toward the daemon-side fix (grant ACL access), not toward
        // re-checking signatures.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(challenge_response_json()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/auth/"))
            .respond_with(ResponseTemplate::new(403).set_body_string("DID not in ACL"))
            .mount(&server)
            .await;

        let (private, vta_did, kid) = signing_identity();
        let client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };

        let err = client.authenticate(&identity).await.unwrap_err();
        match err {
            AppError::Forbidden(msg) => {
                assert!(
                    msg.contains("not in the daemon's ACL"),
                    "403 must surface the ACL hint: {msg}"
                );
                assert!(msg.contains(&vta_did), "should name the VTA DID: {msg}");
                assert!(
                    msg.contains("daemon-side"),
                    "should point at the daemon as the fix location: {msg}"
                );
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authenticate_500_yields_internal_not_auth_error() {
        // A 5xx is a daemon-side problem, not an auth problem — must
        // not look like "ACL needs updating."
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(challenge_response_json()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/auth/"))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
            .mount(&server)
            .await;

        let (private, vta_did, kid) = signing_identity();
        let client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };

        let err = client.authenticate(&identity).await.unwrap_err();
        assert!(
            matches!(err, AppError::Internal(_)),
            "5xx should map to Internal, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn refresh_returns_rotated_tokens() {
        // The daemon rotates the refresh token on use. The returned
        // refresh_token must be the daemon's new value, not echoed
        // from the input.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/refresh"))
            .and(header("Content-Type", "application/json"))
            // The old refresh token rides inside the JWS body; we
            // can't match on encoded contents from a wiremock matcher.
            // Flat `{ session, tokens }`, relative expiries.
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "session": {
                    "id": "refreshed-session",
                    "subject": "did:webvh:test:vta",
                    "issuedAt": "2026-01-01T00:00:00Z",
                    "expiresAt": "2026-01-02T00:00:00Z",
                },
                "tokens": {
                    "accessToken": "new-access",
                    "refreshToken": "rotated-refresh",
                    "tokenType": "Bearer",
                    "expiresIn": 900u64,
                    "refreshExpiresIn": 86_400u64,
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let (private, vta_did, kid) = signing_identity();
        let client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };

        let before = unix_now_secs();
        let tokens = client
            .refresh(&identity, "old-refresh")
            .await
            .expect("refresh must succeed");
        let after = unix_now_secs();
        assert_eq!(tokens.access_token, "new-access");
        assert_eq!(
            tokens.refresh_token, "rotated-refresh",
            "refresh must return rotated token, not echo input"
        );
        assert!(
            (before + 900..=after + 900).contains(&tokens.access_expires_at),
            "refreshed access_expires_at must be now+900 (relative→absolute)"
        );
    }

    #[tokio::test]
    async fn refresh_failure_yields_typed_authentication_error() {
        // End-of-lifetime case: refresh token expired or replayed.
        // Callers fall back to full re-auth; the typed variant tells
        // them to.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/refresh"))
            .respond_with(ResponseTemplate::new(401).set_body_string("invalid refresh token"))
            .mount(&server)
            .await;

        let (private, vta_did, kid) = signing_identity();
        let client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };
        let err = client
            .refresh(&identity, "stale-refresh")
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::Authentication(_)),
            "expired refresh must map to Authentication, got: {err:?}"
        );
    }

    #[test]
    fn token_data_debug_redacts_secret_fields() {
        // Same protection as `WebvhServerAuthRecord` — accidental
        // `tracing::error!(?tokens)` must not log the access or
        // refresh token bytes. Expiry timestamps stay visible (not
        // secret, useful for freshness diagnostics).
        let td = TokenData {
            access_token: "should-not-appear-XXXX".into(),
            access_expires_at: 1234,
            refresh_token: "also-secret-YYYY".into(),
            refresh_expires_at: 5678,
        };
        let dbg = format!("{td:?}");
        assert!(!dbg.contains("XXXX"), "access_token must not leak: {dbg}");
        assert!(!dbg.contains("YYYY"), "refresh_token must not leak: {dbg}");
        assert!(dbg.contains("<redacted>"));
        assert!(dbg.contains("1234"));
        assert!(dbg.contains("5678"));
    }

    #[tokio::test]
    async fn authenticate_uses_camelcase_sessionid_from_daemon() {
        // The daemon's `ChallengeResponse` has
        // `#[serde(rename_all = "camelCase")]` so the wire field is
        // `sessionId`. Regression guard: a future tweak that switched
        // our deserializer to snake_case-only would silently break
        // the auth handshake.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/challenge"))
            // Note: explicit camelCase `sessionId`, not snake_case,
            // and the flat daemon body (no `data` envelope).
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "challenge": "cafebabe",
                "sessionId": "camel-id",
                "expiresAt": "2026-01-01T00:00:00Z"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/auth/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_response_json()))
            .mount(&server)
            .await;

        let (private, vta_did, kid) = signing_identity();
        let client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };
        let _ = client
            .authenticate(&identity)
            .await
            .expect("must accept camelCase sessionId");
    }

    #[test]
    fn challenge_response_deserializes_flat_daemon_body() {
        // The daemon emits `spec/auth/challenge/0.1#response` flat:
        // `{ challenge, sessionId, expiresAt }`, with no `data`
        // envelope. Regression guard for the wire-format bug where we
        // modelled the response as data-wrapped and serde failed with
        // "missing field `data`". `expiresAt` is present on the wire
        // but intentionally ignored by the parser.
        let body = r#"{"challenge":"abc","sessionId":"sess-1","expiresAt":"2026-01-01T00:00:00Z"}"#;
        let parsed: ChallengeResponseWire =
            serde_json::from_str(body).expect("flat daemon challenge body must deserialize");
        assert_eq!(parsed.challenge, "abc");
        assert_eq!(parsed.session_id, "sess-1");
    }

    #[test]
    fn request_uri_response_deserializes_camelcase_daemon_body() {
        // The daemon's `POST /api/dids` (+ `/api/dids/register`) response
        // (did-hosting-common::RequestUriResponse) is camelCase, so `did_url`
        // arrives as `didUrl`. Regression guard for the wire-format bug where
        // the mirror lacked `#[serde(rename_all = "camelCase")]` and the body
        // failed to decode on the publish path.
        let body = r#"{"mnemonic":"apple-banana-cherry","didUrl":"did:webvh:Qm...:host%3A8534"}"#;
        let parsed: RequestUriResponse =
            serde_json::from_str(body).expect("camelCase daemon request-uri body must deserialize");
        assert_eq!(parsed.mnemonic, "apple-banana-cherry");
        assert_eq!(parsed.did_url, "did:webvh:Qm...:host%3A8534");
    }

    #[test]
    fn challenge_response_accepts_snake_case_session_id_alias() {
        // Older daemon builds emitted snake_case `session_id` before
        // the `#[serde(rename_all = "camelCase")]` annotation landed;
        // the `#[serde(alias = "session_id")]` keeps them working
        // through one upgrade cycle.
        let body =
            r#"{"challenge":"abc","session_id":"sess-1","expiresAt":"2026-01-01T00:00:00Z"}"#;
        let parsed: ChallengeResponseWire =
            serde_json::from_str(body).expect("snake_case session_id alias must deserialize");
        assert_eq!(parsed.challenge, "abc");
        assert_eq!(parsed.session_id, "sess-1");
    }

    #[test]
    fn auth_response_deserializes_flat_daemon_body_and_maps_relative_expiries() {
        // The daemon emits `spec/auth/authenticate/0.1#response` flat:
        // `{ session, tokens }`, with OAuth2-style *relative* expiries
        // (`expiresIn` / `refreshExpiresIn` seconds from issuance).
        // Regression guard for the wire-format bug where we modelled
        // this as `{ session_id, data }`; and proof that the client
        // converts relative → absolute (`now + expiresIn`).
        let body = r#"{
            "session": {
                "id": "sess-1",
                "subject": "did:webvh:test:vta",
                "issuedAt": "2026-01-01T00:00:00Z",
                "expiresAt": "2026-01-02T00:00:00Z"
            },
            "tokens": {
                "accessToken": "a",
                "refreshToken": "r",
                "tokenType": "Bearer",
                "expiresIn": 900,
                "refreshExpiresIn": 86400,
                "scope": ["did:hosting"]
            }
        }"#;
        let parsed: TokenResponseWire =
            serde_json::from_str(body).expect("flat daemon auth body must deserialize");

        // Use a fixed `now` so the absolute expiry is deterministic.
        let now = 1_800_000_000u64;
        let tokens = parsed
            .into_token_data(now)
            .expect("mapping must succeed with both tokens present");
        assert_eq!(tokens.access_token, "a");
        assert_eq!(tokens.refresh_token, "r");
        assert_eq!(
            tokens.access_expires_at,
            now + 900,
            "access expiry must be now + expiresIn"
        );
        assert_eq!(
            tokens.refresh_expires_at,
            now + 86_400,
            "refresh expiry must be now + refreshExpiresIn"
        );
    }

    #[test]
    fn auth_response_without_refresh_token_is_rejected() {
        // The canonical `TokenBundle` marks `refreshToken` optional,
        // but the VTA's hosting-session lifecycle depends on rotation.
        // A bundle without one must surface a typed error rather than
        // silently persisting an empty refresh token.
        let body = r#"{
            "session": { "id": "s", "subject": "did:x", "issuedAt": "t", "expiresAt": "t" },
            "tokens": { "accessToken": "a", "tokenType": "Bearer", "expiresIn": 900 }
        }"#;
        let parsed: TokenResponseWire =
            serde_json::from_str(body).expect("body without refresh token still deserializes");
        let err = parsed.into_token_data(0).unwrap_err();
        assert!(
            matches!(err, AppError::Internal(msg) if msg.contains("refreshToken")),
            "missing refreshToken must be a typed Internal error"
        );
    }

    #[tokio::test]
    async fn agent_name_disable_posts_bearer_authed_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/agent-names/disable"))
            .and(header("Authorization", "Bearer tok-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "record": {} })))
            .expect(1)
            .mount(&server)
            .await;

        let mut client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        client.set_access_token("tok-1".to_string());
        client
            .agent_name_op("disable", "alice", "alice", "<jsonl>", Some("example.com"))
            .await
            .expect("disable should POST and succeed");
    }

    #[tokio::test]
    async fn agent_name_enable_maps_403_to_forbidden() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/agent-names/enable"))
            .respond_with(ResponseTemplate::new(403).set_body_string("not the owner"))
            .expect(1)
            .mount(&server)
            .await;

        let mut client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        client.set_access_token("tok-1".to_string());
        let err = client
            .agent_name_op("enable", "alice", "alice", "<jsonl>", None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "a 403 from the host maps to Forbidden, got {err:?}"
        );
    }

    /// Every verb hits its own endpoint and carries the same body. The name
    /// is what the caller passes, not a fixed `alice` — a wrapper that
    /// transposed arguments would still pass a same-value test.
    #[tokio::test]
    async fn agent_name_op_routes_each_verb_to_its_endpoint() {
        for verb in ["set", "remove", "enable", "disable"] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(format!("/api/agent-names/{verb}")))
                .and(header("Authorization", "Bearer tok-1"))
                .and(body_json(json!({
                    "mnemonic": "slot-one",
                    "name": "bob",
                    "didLog": "<jsonl>",
                    "domain": "example.com",
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "record": {} })))
                .expect(1)
                .mount(&server)
                .await;

            let mut client =
                WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
            client.set_access_token("tok-1".to_string());
            client
                .agent_name_op(verb, "slot-one", "bob", "<jsonl>", Some("example.com"))
                .await
                .unwrap_or_else(|e| panic!("{verb} should POST and succeed: {e:?}"));
        }
    }

    /// The registry read must surface **parked** entries — they are the only
    /// reason this call exists, since a parked name is absent from the DID
    /// document by design and cannot be recovered from it.
    #[tokio::test]
    async fn list_agent_names_returns_parked_entries() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/dids/slot-one"))
            .and(header("Authorization", "Bearer tok-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "mnemonic": "slot-one",
                "agentNames": [
                    { "name": "alice", "enabled": true,  "createdAt": 1 },
                    { "name": "bob",   "enabled": false, "createdAt": 2 },
                ],
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        client.set_access_token("tok-1".to_string());
        let names = client
            .list_agent_names("slot-one", None)
            .await
            .expect("list should succeed");
        assert_eq!(names.len(), 2);
        assert!(names.iter().any(|n| n.name == "bob" && !n.enabled));
    }

    /// A host predating the registry omits the field entirely. That is an
    /// empty list, not a parse error — otherwise every read against an older
    /// host fails.
    #[tokio::test]
    async fn list_agent_names_tolerates_a_host_without_the_field() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/dids/slot-one"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "mnemonic": "slot-one"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        client.set_access_token("tok-1".to_string());
        assert!(
            client
                .list_agent_names("slot-one", None)
                .await
                .expect("absent agentNames must not be an error")
                .is_empty()
        );
    }

    /// `reserved` has to survive as its own signal — "unavailable because it
    /// is `@admin`" needs different UI from "unavailable because someone has
    /// it".
    #[tokio::test]
    async fn check_agent_name_reports_reserved_separately() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/agent-names/check"))
            .and(body_json(
                json!({ "name": "admin", "domain": "example.com" }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": "admin",
                "domain": "example.com",
                "available": false,
                "reserved": true,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        client.set_access_token("tok-1".to_string());
        let a = client
            .check_agent_name("admin", Some("example.com"))
            .await
            .expect("check should succeed");
        assert!(!a.available);
        assert!(a.reserved);
    }

    /// A name already held by another DID comes back as a distinguishable
    /// error, not a generic failure — the client has to render "pick another
    /// name" differently from "you don't control this DID".
    #[tokio::test]
    async fn agent_name_set_surfaces_a_taken_name() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/agent-names/set"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "code": "did-management:name_taken",
                "message": "agent name is already taken",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        client.set_access_token("tok-1".to_string());
        let err = client
            .agent_name_op("set", "slot-one", "alice", "<jsonl>", None)
            .await
            .unwrap_err();
        let rendered = format!("{err:?}");
        assert!(
            rendered.contains("name_taken") || rendered.contains("already taken"),
            "the host's reason must survive into the error, got {rendered}"
        );
    }
}
