use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use tracing::warn;

use crate::acl::{ActScope, Role, act_scope_for};
use crate::auth::jwt::JwtKeys;
use crate::auth::session::{Session, SessionState, get_session, now_epoch};
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Trait that each service's `AppState` implements to provide the data
/// needed by the auth extractors.
pub trait AuthState: Clone + Send + Sync + 'static {
    fn jwt_keys(&self) -> Option<&Arc<JwtKeys>>;
    fn sessions_ks(&self) -> &KeyspaceHandle;
}

/// Extracted from a valid JWT Bearer token on protected routes.
///
/// Add this as a handler parameter to require authentication:
/// ```ignore
/// async fn handler(_auth: AuthClaims, ...) { }
/// ```
#[derive(Debug, Default, Clone)]
pub struct AuthClaims {
    pub did: String,
    pub role: Role,
    pub allowed_contexts: Vec<String>,
    /// JWT `session_id` claim. Carried through so handlers can do
    /// session-targeted operations (sign-out, refresh-token
    /// rotation) without re-decoding the JWT.
    pub session_id: String,
    /// JWT `exp` claim — Unix-second expiry. Surfaced so
    /// `whoami`-style endpoints can return the access-token
    /// lifetime without re-decoding.
    pub access_expires_at: u64,
    /// JWT `iat` claim — Unix-second issue time.
    ///
    /// Carried for the same reason as `access_expires_at`: the canonical
    /// `Session` component makes `issuedAt` **required**, and a `whoami` that
    /// cannot say when the session began describes a session only half way.
    /// The value was always in the token; it simply was not surfaced.
    pub issued_at: u64,
    /// Authentication Methods References per [RFC 8176]. Mirrors
    /// `Claims.amr` from the bearer JWT. Handlers gating sensitive
    /// operations check this to decide whether a step-up is needed.
    pub amr: Vec<String>,
    /// Authentication Context Class Reference per OIDC Core §2.
    /// Typical values: `"aal1"` / `"aal2"` / `"aal3"`. Handlers gating
    /// step-up read this directly.
    pub acr: String,
}

/// Name of the admin UX session cookie set by the VTC's
/// `POST /v1/auth/admin-session` + `POST /v1/auth/passkey-login/finish`
/// flows. When the `Authorization: Bearer` header is absent,
/// [`AuthClaims`] falls back to reading a JWT out of this cookie.
/// The cookie is set with `Path=/; SameSite=Strict; Secure; HttpOnly`
/// so the browser sends it on `/v1/*` API calls; `HttpOnly` keeps
/// JS on any path from reading it, and `SameSite=Strict` blocks
/// cross-site CSRF.
pub const ADMIN_SESSION_COOKIE: &str = "vtc_admin_session";

impl<S: AuthState> FromRequestParts<S> for AuthClaims {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(authenticate(parts, state).await?.0)
    }
}

/// Lets a handler accept `Option<AuthClaims>` — "authenticate the caller if
/// they presented a credential, otherwise carry on anonymously".
///
/// Needed by the endpoints that serve two audiences on one route: passkey
/// *login* is unauthenticated by nature (the ceremony is the authentication),
/// while passkey *step-up* on the very same task elevates a session the caller
/// must already hold. Splitting them into two routes would fork a canonical
/// Trust Task in two.
///
/// This is **not** a way to make authentication optional on a protected route:
/// a caller who presents a credential still has it fully verified, and a bad
/// one is rejected rather than silently downgraded to anonymous.
impl<S: AuthState> axum::extract::OptionalFromRequestParts<S> for AuthClaims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let Some(token) = presented_token(parts, state).await else {
            return Ok(None);
        };
        Ok(Some(authenticate_token(&token, state).await?.0))
    }
}

/// The shared body of [`AuthClaims::from_request_parts`], additionally handing
/// back the [`Session`] row it had to load anyway (for the `jti` pin).
///
/// [`StepUpAuth`] needs session state the JWT does not carry — how long ago the
/// second factor was actually confirmed — and re-reading the row per request
/// would double the store hit on every stepped-up call. Every extractor in this
/// module funnels through here, so there is exactly one place that decides what
/// "authenticated" means.
async fn authenticate<S: AuthState>(
    parts: &mut Parts,
    state: &S,
) -> Result<(AuthClaims, Session), AppError> {
    let Some(token) = presented_token(parts, state).await else {
        warn!("auth rejected: no Authorization header and no {ADMIN_SESSION_COOKIE} cookie");
        return Err(AppError::Unauthorized(
            "missing or invalid Authorization header".into(),
        ));
    };
    authenticate_token(&token, state).await
}

/// Pull the caller's JWT off the request, whichever way they presented it.
///
/// `Authorization: Bearer <jwt>` first — programmatic clients (cnm-cli, DIDComm
/// bridges, the `/v1/auth/` flow) all use this. Falls back to the admin session
/// cookie (Phase 5 M5.2.3) set by `POST /v1/auth/admin-session`, which carries
/// the same JWT.
///
/// `None` means the caller presented **no** credential at all — distinct from
/// presenting a bad one, which is what lets
/// [`OptionalFromRequestParts`](axum::extract::OptionalFromRequestParts) treat
/// an anonymous request as "not authenticated" while still rejecting a forged
/// or expired token outright.
async fn presented_token<S: AuthState>(parts: &mut Parts, state: &S) -> Option<String> {
    let bearer = TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
        .await
        .ok()
        .map(|TypedHeader(auth)| auth.token().to_string());
    bearer.or_else(|| cookie_token(parts, ADMIN_SESSION_COOKIE))
}

async fn authenticate_token<S: AuthState>(
    token: &str,
    state: &S,
) -> Result<(AuthClaims, Session), AppError> {
    {
        // Decode and validate JWT
        let jwt_keys = state
            .jwt_keys()
            .ok_or_else(|| AppError::Unauthorized("auth not configured".into()))?;

        let claims = jwt_keys.decode(token)?;

        // Verify session exists and is authenticated
        let session = get_session(state.sessions_ks(), &claims.session_id)
            .await?
            .ok_or_else(|| {
                warn!(session_id = %claims.session_id, "auth rejected: session not found");
                AppError::Unauthorized("session not found".into())
            })?;

        if session.state != SessionState::Authenticated {
            warn!(session_id = %claims.session_id, "auth rejected: session not in authenticated state");
            return Err(AppError::Unauthorized("session not authenticated".into()));
        }

        // jti pin: when the session records a `token_id`, only the token whose
        // `jti` matches it authenticates. Minting a fresh token (login, refresh,
        // step-up) rotates `token_id`, so every previously-issued access token
        // for this session is superseded immediately — the mechanism that keeps
        // a non-rotating session_id revocable. Skipped when `token_id` is unset
        // (sessions written before this field, or intrinsic-sender sessions that
        // carry no JWT), preserving their existing behaviour.
        if let Some(ref pinned) = session.token_id
            && claims.jti != *pinned
        {
            warn!(session_id = %claims.session_id, "auth rejected: token superseded (jti mismatch)");
            return Err(AppError::Unauthorized("token superseded".into()));
        }

        let role = Role::parse(&claims.role)?;

        Ok((
            AuthClaims {
                did: claims.sub,
                role,
                allowed_contexts: claims.contexts,
                session_id: claims.session_id,
                access_expires_at: claims.exp,
                issued_at: claims.iat,
                amr: claims.amr,
                acr: claims.acr,
            },
            session,
        ))
    }
}

impl AuthClaims {
    /// **UNSAFE**: Synthesize a super-admin claim with no wire-level
    /// verification. Only for **on-host offline CLI** invocations — the
    /// trust boundary is the OS process, not the network.
    ///
    /// Feature-gated behind `cli-synthesis` so this function is physically
    /// absent from enclave and server-only builds. Any caller compiles
    /// iff the feature is on; calling this from a route handler is a bug
    /// that the type system can't catch (the resulting `AuthClaims` is
    /// indistinguishable from a legitimate one), so the name loudly marks
    /// the footgun.
    ///
    /// The trust model: a process that can execute the VTA binary AND
    /// read the keystore + seed store is already trusted by the OS to
    /// act as the VTA itself. Offline CLIs that mutate state (mint keys,
    /// seal bundles, export admin credentials) pre-date any over-the-
    /// wire authentication, so wire-level claims can't gate them. The
    /// caller-supplied `channel` is recorded in the audit log so misuse
    /// can be traced back to the specific CLI path.
    ///
    /// Downstream hardening (tracked as review item 9 follow-up):
    /// - Require an operator-side credential (env var / local config
    ///   pointing at a key in the ACL) before synthesizing.
    /// - Audit-log process identity (`uid`, `pid`, `cwd`) alongside
    ///   `channel` so a forensic investigator can distinguish
    ///   operator-intentional runs from lateral-movement abuse.
    ///
    /// The sentinel DID format `"cli:<channel>"` (not `did:*`) is
    /// deliberate — it doesn't round-trip through DID resolution and
    /// can't be confused with a real caller DID in log correlation.
    #[cfg(feature = "cli-synthesis")]
    pub fn unsafe_local_cli_super_admin(channel: &str) -> Self {
        Self {
            did: format!("cli:{channel}"),
            role: Role::Admin,
            allowed_contexts: Vec::new(),
            // CLI synthesis bypasses the session store entirely.
            // The sentinel session_id matches the DID format and
            // `access_expires_at: 0` makes the synthesized claim
            // visibly "no real expiry" to any log scraper, and
            // `issued_at: 0` follows the same convention — there is
            // no JWT here, so there is no `iat` to carry.
            session_id: format!("cli:{channel}"),
            access_expires_at: 0,
            issued_at: 0,
            // CLI synthesis is a process-local trust boundary; the auth
            // method is the OS user, not a wire factor. Surface `"cli"`
            // in amr so a downstream auditor distinguishes synthesized
            // claims from real authenticated sessions.
            amr: vec!["cli".to_string()],
            acr: String::new(),
        }
    }

    /// This caller's authority to **act**, decoded from `(role,
    /// allowed_contexts)`.
    ///
    /// Use this — or [`has_context_access`](Self::has_context_access), which is
    /// built on it — rather than inspecting `allowed_contexts` directly. An
    /// empty list means *unrestricted* for [`Role::Admin`] and *nothing at all*
    /// for every other role; a call site that tests `is_empty()` without the
    /// role gets one of those two cases backwards. See [`ActScope`].
    pub fn act_scope(&self) -> ActScope {
        act_scope_for(&self.role, &self.allowed_contexts)
    }

    /// Returns `true` if the caller is an admin whose [`ActScope`] is
    /// unrestricted.
    pub fn is_super_admin(&self) -> bool {
        self.role == Role::Admin && self.act_scope().is_unrestricted()
    }

    /// Returns `true` if the caller may act in the given context — because
    /// their [`ActScope`] is unrestricted, or because it names `context_id`
    /// itself **or an ancestor of it** (folder-level authority: admin of a
    /// parent context covers the whole subtree).
    ///
    /// Ancestry is the segment-aware
    /// [`is_ancestor_or_self`](crate::context_path::is_ancestor_or_self) — a
    /// pure, store-free check over the verified JWT's contexts. For today's flat
    /// (single-segment, childless) contexts this is identical to the previous
    /// exact match.
    pub fn has_context_access(&self, context_id: &str) -> bool {
        self.act_scope().covers(context_id)
    }

    /// Clone these claims with `extra` contexts merged into `allowed_contexts`.
    ///
    /// This is how a **consented per-task delegation** is realized: an approver
    /// who holds admin in a context authorizes one specific task, and the
    /// executor runs *that one dispatch* under the requester's identity widened
    /// to include the delegated context. The widening lives only for the single
    /// consented, payload-bound, single-use execution — it is never persisted
    /// onto the session or the JWT, so the agent accrues no standing authority.
    ///
    /// Never *widens* a super-admin (empty `allowed_contexts` already means "all
    /// contexts", so there is nothing to add and replacing the empty list would
    /// wrongly *narrow* it) and is a no-op when `extra` is empty. Duplicates are
    /// dropped so repeated delegation can't bloat the list.
    pub fn with_delegated_contexts(&self, extra: &[String]) -> Self {
        let mut claims = self.clone();
        if extra.is_empty() || claims.is_super_admin() {
            return claims;
        }
        for ctx in extra {
            if !claims.allowed_contexts.iter().any(|c| c == ctx) {
                claims.allowed_contexts.push(ctx.clone());
            }
        }
        claims
    }

    /// Realize a **consented grant** for a single dispatch: the approval conferred
    /// full authority over `extra`, so the requester need hold **no standing
    /// admin at all**.
    ///
    /// Unlike [`with_delegated_contexts`] — which widens context but keeps the
    /// requester's role — this also lifts the role to [`Role::Admin`], because
    /// the grant authorizes the exact bound task in full. That is what lets a
    /// purely unprivileged agent (a Reader that can act nowhere) execute a task an
    /// approver blessed: the approval *is* the authority. Ephemeral in exactly the
    /// same way as the context widening — built for one dispatch, never persisted
    /// to the session, JWT, or ACL — so the agent accrues no standing power.
    ///
    /// A no-op when `extra` is empty (nothing was delegated — an ordinary
    /// same-context, already-authorized execution) and for a super-admin (already
    /// unrestricted; adding to the empty list would wrongly narrow it).
    pub fn with_delegated_authority(&self, extra: &[String]) -> Self {
        let mut claims = self.clone();
        if extra.is_empty() || claims.is_super_admin() {
            return claims;
        }
        claims.role = Role::Admin;
        for ctx in extra {
            if !claims.allowed_contexts.iter().any(|c| c == ctx) {
                claims.allowed_contexts.push(ctx.clone());
            }
        }
        claims
    }

    /// Check that the caller has access to the given context.
    ///
    /// Admins with an empty `allowed_contexts` list have unrestricted access.
    pub fn require_context(&self, context_id: &str) -> Result<(), AppError> {
        if self.has_context_access(context_id) {
            return Ok(());
        }
        Err(AppError::Forbidden(format!(
            "no access to context: {context_id}"
        )))
    }

    /// If the caller has exactly one allowed context, return it.
    pub fn default_context(&self) -> Option<&str> {
        if self.allowed_contexts.len() == 1 {
            Some(&self.allowed_contexts[0])
        } else {
            None
        }
    }

    /// Require at least Reader role (all roles except Monitor).
    ///
    /// Use for read-only endpoints that access business data (keys, contexts, DIDs).
    /// Monitor can only see metrics and health.
    pub fn require_read(&self) -> Result<(), AppError> {
        if self.role == Role::Monitor {
            return Err(AppError::Forbidden("reader role or higher required".into()));
        }
        Ok(())
    }

    /// Require at least Application role (Admin, Initiator, or Application).
    ///
    /// Use for write operations: signing, cache writes, and other actions that
    /// produce artifacts or modify state.
    pub fn require_write(&self) -> Result<(), AppError> {
        if matches!(self.role, Role::Admin | Role::Initiator | Role::Application) {
            return Ok(());
        }
        Err(AppError::Forbidden(
            "application role or higher required".into(),
        ))
    }

    /// Require the caller to have Admin role.
    pub fn require_admin(&self) -> Result<(), AppError> {
        if self.role == Role::Admin {
            return Ok(());
        }
        Err(AppError::Forbidden("admin role required".into()))
    }

    /// Require the caller to have Admin or Initiator role.
    pub fn require_manage(&self) -> Result<(), AppError> {
        if self.role == Role::Admin || self.role == Role::Initiator {
            return Ok(());
        }
        Err(AppError::Forbidden(
            "admin or initiator role required".into(),
        ))
    }

    /// Require this caller's session to carry a **live** step-up elevation —
    /// the same rule [`StepUpAuth`] enforces, for routes where only *some*
    /// requests need it.
    ///
    /// A whole-route extractor can't express "this PATCH needs a fresh second
    /// factor only when it promotes someone to admin". Both paths run
    /// `check_fresh_step_up`, so the in-handler gate can't drift from the
    /// extractor's; the only difference is that this one re-reads the session
    /// (the extractor already had it in hand).
    ///
    /// A missing session is a refusal, not a pass.
    pub async fn require_fresh_step_up(&self, sessions: &KeyspaceHandle) -> Result<(), AppError> {
        let session = get_session(sessions, &self.session_id)
            .await?
            .ok_or_else(|| {
                warn!(session_id = %self.session_id, "step-up rejected: session not found");
                AppError::StepUpRequired("operation requires a recent step-up".into())
            })?;
        check_fresh_step_up(self, &session)
    }

    /// Require the caller to be a super admin (Admin + unrestricted).
    pub fn require_super_admin(&self) -> Result<(), AppError> {
        if self.is_super_admin() {
            return Ok(());
        }
        Err(AppError::Forbidden("super admin required".into()))
    }
}

/// Extractor that requires the caller to have Admin or Initiator role.
///
/// Use on endpoints that manage ACL entries and other management tasks:
/// ```ignore
/// async fn handler(auth: ManageAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct ManageAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for ManageAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        match claims.role {
            Role::Admin | Role::Initiator => Ok(ManageAuth(claims)),
            _ => {
                warn!(did = %claims.did, role = %claims.role, "auth rejected: admin or initiator role required");
                Err(AppError::Forbidden(
                    "admin or initiator role required".into(),
                ))
            }
        }
    }
}

/// Extractor that requires the caller to have Admin role.
///
/// Use on endpoints that modify configuration, create/delete keys, etc.:
/// ```ignore
/// async fn handler(auth: AdminAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct AdminAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for AdminAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        match claims.role {
            Role::Admin => Ok(AdminAuth(claims)),
            _ => {
                warn!(did = %claims.did, role = %claims.role, "auth rejected: admin role required");
                Err(AppError::Forbidden("admin role required".into()))
            }
        }
    }
}

/// Extractor that requires a **freshly** stepped-up session: `acr == "aal2"`
/// *and* a step-up elevation whose window is still open.
///
/// Use on routes that demand a second factor confirmed **for this operation** —
/// ACL edits, role promotion, key rotation, backup export; anything that lets
/// an attacker holding a live session pivot to a long-lived foothold.
///
/// ```ignore
/// async fn rotate_keys(auth: StepUpAuth, ...) { /* fresh aal2 enforced */ }
/// ```
///
/// A request that fails either half is rejected with
/// [`AppError::StepUpRequired`] (403 + body
/// `{ "error": "step_up_required", "requiredAcr": "aal2" }`). The
/// wallet uses that signal to trigger a passkey-login or
/// VTA-approval ceremony — distinct from a generic `forbidden`
/// it would get from a role gate.
///
/// **Why `acr` alone is not enough.** `acr` records the assurance level the
/// session *reached*, and it stays there for the session's whole life: a
/// passkey sign-in mints `aal2` up front and the canonical refresh handler
/// preserves it across every rotation. Gating on `acr` alone would therefore
/// accept a sign-in from an hour ago and lose the property these routes exist
/// for — that a stolen session cannot, by itself, authorise the next
/// promotion. Freshness lives in
/// [`Session::acr_expires_at`](crate::auth::session::Session::acr_expires_at),
/// which a step-up ceremony sets to a bounded deadline, so this gate reads the
/// session row rather than the token.
///
/// **Fail closed.** An absent deadline is refused, not waved through: it means
/// no step-up ceremony ever ran for this session (or the row pre-dates the
/// field). An unknown elevation time must never read as a recent one.
#[derive(Debug, Clone)]
pub struct StepUpAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for StepUpAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let (claims, session) = authenticate(parts, state).await?;
        check_fresh_step_up(&claims, &session)?;
        Ok(StepUpAuth(claims))
    }
}

/// The step-up rule itself, so the extractor and the in-handler check below
/// can never drift apart.
fn check_fresh_step_up(claims: &AuthClaims, session: &Session) -> Result<(), AppError> {
    if claims.acr != "aal2" {
        warn!(
            did = %claims.did,
            acr = %claims.acr,
            "auth rejected: step-up (aal2) required",
        );
        return Err(AppError::StepUpRequired(
            "operation requires a stepped-up (aal2) session".into(),
        ));
    }
    if !session.elevation_active(now_epoch()) {
        warn!(
            did = %claims.did,
            acr_expires_at = ?session.acr_expires_at,
            "auth rejected: step-up elevation absent or lapsed",
        );
        return Err(AppError::StepUpRequired(
            "operation requires a recent step-up; re-run the step-up ceremony".into(),
        ));
    }
    Ok(())
}

/// Extractor that requires the caller to be a super admin (Admin role with
/// empty `allowed_contexts`).
///
/// Use on endpoints that only unrestricted administrators should access,
/// such as creating/deleting contexts or modifying global configuration:
/// ```ignore
/// async fn handler(auth: SuperAdminAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct SuperAdminAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for SuperAdminAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        if !claims.is_super_admin() {
            warn!(did = %claims.did, "auth rejected: super admin required");
            return Err(AppError::Forbidden("super admin required".into()));
        }

        Ok(SuperAdminAuth(claims))
    }
}

/// Extractor that requires the caller to have at least Application role
/// (Admin, Initiator, or Application).
///
/// Use on endpoints that perform write operations — signing, cache writes,
/// and other actions that produce artifacts or modify state:
/// ```ignore
/// async fn handler(auth: WriteAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct WriteAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for WriteAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        match claims.role {
            Role::Admin | Role::Initiator | Role::Application => Ok(WriteAuth(claims)),
            _ => {
                warn!(did = %claims.did, role = %claims.role, "auth rejected: application role or higher required");
                Err(AppError::Forbidden(
                    "application role or higher required".into(),
                ))
            }
        }
    }
}

/// Pull a named cookie value off the request `Cookie` headers.
/// Returns `None` when the cookie isn't present. Does **not**
/// percent-decode — cookie values minted by the VTC's admin-session
/// flow are JWTs (base64url + dots), which are ASCII-safe.
fn cookie_token(parts: &Parts, name: &str) -> Option<String> {
    parts
        .headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(|s| s.trim())
        .find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == name).then(|| v.to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::Claims;
    use crate::auth::session::{now_epoch, store_session};
    use crate::config::StoreConfig;
    use crate::store::Store;

    /// Minimal [`AuthState`] so the extractors can be driven end-to-end
    /// (real JWT, real session row) instead of asserting on their parts.
    #[derive(Clone)]
    struct TestState {
        keys: Arc<JwtKeys>,
        sessions: KeyspaceHandle,
    }

    impl AuthState for TestState {
        fn jwt_keys(&self) -> Option<&Arc<JwtKeys>> {
            Some(&self.keys)
        }
        fn sessions_ks(&self) -> &KeyspaceHandle {
            &self.sessions
        }
    }

    fn test_state() -> (TestState, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let state = TestState {
            keys: Arc::new(JwtKeys::from_ed25519_bytes(&[7u8; 32], "VTA").expect("build jwt keys")),
            sessions: store.keyspace("sessions").expect("keyspace"),
        };
        (state, dir)
    }

    /// Authenticate `did` at `acr`, with the step-up window set to
    /// `acr_expires_at`, and return request parts carrying the bearer token.
    async fn authed_parts(
        state: &TestState,
        acr: &str,
        acr_expires_at: Option<u64>,
    ) -> axum::http::request::Parts {
        let did = "did:key:zStepUp";
        let claims: Claims = state
            .keys
            .new_claims(
                did.to_string(),
                did.to_string(),
                "admin".to_string(),
                Vec::new(),
                900,
                false,
            )
            .with_aal(vec!["passkey".to_string()], acr);
        let token = state.keys.encode(&claims).expect("encode jwt");

        let session = Session {
            session_id: did.to_string(),
            did: did.to_string(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: now_epoch(),
            last_seen: now_epoch(),
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: vec!["passkey".to_string()],
            acr: acr.to_string(),
            acr_expires_at,
            token_id: None,
            session_pubkey_b58btc: None,
        };
        store_session(&state.sessions, &session)
            .await
            .expect("store session");

        let (parts, _) = axum::http::Request::builder()
            .uri("/anything")
            .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .body(())
            .expect("build request")
            .into_parts();
        parts
    }

    #[tokio::test]
    async fn step_up_accepts_a_live_elevation() {
        let (state, _dir) = test_state();
        let mut parts = authed_parts(&state, "aal2", Some(now_epoch() + 900)).await;
        let auth = StepUpAuth::from_request_parts(&mut parts, &state)
            .await
            .expect("a live step-up window must satisfy the gate");
        assert_eq!(auth.0.acr, "aal2");
    }

    #[tokio::test]
    async fn step_up_refuses_an_aal2_session_that_was_never_stepped_up() {
        // The load-bearing case: a passkey sign-in is `aal2` from its first
        // request and carries no elevation window. Gating on `acr` alone would
        // accept it hours later — exactly the "a stolen session cannot persist"
        // property these routes exist to keep.
        let (state, _dir) = test_state();
        let mut parts = authed_parts(&state, "aal2", None).await;
        let err = StepUpAuth::from_request_parts(&mut parts, &state)
            .await
            .expect_err("an absent elevation window must fail closed");
        assert!(
            matches!(err, AppError::StepUpRequired(_)),
            "expected StepUpRequired, got {err:?}"
        );
    }

    #[tokio::test]
    async fn step_up_refuses_a_lapsed_elevation() {
        let (state, _dir) = test_state();
        let mut parts = authed_parts(&state, "aal2", Some(now_epoch().saturating_sub(1))).await;
        let err = StepUpAuth::from_request_parts(&mut parts, &state)
            .await
            .expect_err("a lapsed step-up window must be refused");
        assert!(
            matches!(err, AppError::StepUpRequired(_)),
            "expected StepUpRequired, got {err:?}"
        );
    }

    #[tokio::test]
    async fn step_up_refuses_aal1_even_with_a_live_window() {
        // Both halves are required: a live window on a session that never
        // reached aal2 is not a second factor.
        let (state, _dir) = test_state();
        let mut parts = authed_parts(&state, "aal1", Some(now_epoch() + 900)).await;
        let err = StepUpAuth::from_request_parts(&mut parts, &state)
            .await
            .expect_err("aal1 must be refused regardless of the window");
        assert!(
            matches!(err, AppError::StepUpRequired(_)),
            "expected StepUpRequired, got {err:?}"
        );
    }

    #[tokio::test]
    async fn ordinary_auth_is_unaffected_by_the_freshness_rule() {
        // `AuthClaims` (and every role gate built on it) must keep accepting a
        // session with no elevation window — the gate is opt-in per route.
        let (state, _dir) = test_state();
        let mut parts = authed_parts(&state, "aal2", None).await;
        let claims = AuthClaims::from_request_parts(&mut parts, &state)
            .await
            .expect("plain authentication must not require a step-up");
        assert_eq!(claims.did, "did:key:zStepUp");
        assert_eq!(claims.acr, "aal2");
    }

    #[test]
    fn has_context_access_grants_the_subtree_to_a_parent_admin() {
        // A context admin scoped to `acme/eng` (not super-admin — the list is
        // non-empty), so ancestry applies.
        let claims = AuthClaims {
            role: Role::Admin,
            allowed_contexts: vec!["acme/eng".into()],
            ..Default::default()
        };
        assert!(!claims.is_super_admin());

        // Self + every descendant.
        assert!(claims.has_context_access("acme/eng"));
        assert!(claims.has_context_access("acme/eng/team-a"));
        assert!(claims.has_context_access("acme/eng/team-a/squad-1"));

        // NOT the parent, a sibling, or a prefix-confusion look-alike.
        assert!(!claims.has_context_access("acme"));
        assert!(!claims.has_context_access("acme/ops"));
        assert!(!claims.has_context_access("acme/engineering"));

        assert!(claims.require_context("acme/eng/team-a").is_ok());
        assert!(claims.require_context("acme/ops").is_err());
    }

    #[test]
    fn with_delegated_contexts_widens_a_scoped_admin_for_one_call() {
        let base = AuthClaims {
            role: Role::Admin,
            allowed_contexts: vec!["ctx-a".into()],
            ..Default::default()
        };
        // Before: no access to the delegated context.
        assert!(base.require_context("openvtc").is_err());

        let widened = base.with_delegated_contexts(&["openvtc".into()]);
        assert!(widened.require_context("openvtc").is_ok());
        assert!(
            widened.require_context("ctx-a").is_ok(),
            "keeps its own context"
        );
        // The delegation is a fresh value — the caller's own claims are untouched.
        assert!(base.require_context("openvtc").is_err());
    }

    #[test]
    fn with_delegated_contexts_is_a_noop_for_empty_or_super_admin() {
        let scoped = AuthClaims {
            role: Role::Admin,
            allowed_contexts: vec!["ctx-a".into()],
            ..Default::default()
        };
        // Empty delegation changes nothing.
        assert_eq!(
            scoped.with_delegated_contexts(&[]).allowed_contexts,
            scoped.allowed_contexts
        );
        // A super-admin (empty list = all contexts) must never be narrowed to a
        // scoped list by a delegation.
        let sa = AuthClaims {
            role: Role::Admin,
            ..Default::default()
        };
        assert!(sa.is_super_admin());
        let after = sa.with_delegated_contexts(&["openvtc".into()]);
        assert!(after.is_super_admin(), "super-admin stays unrestricted");
        assert!(after.allowed_contexts.is_empty());
    }

    #[test]
    fn with_delegated_authority_lifts_a_non_admin_for_one_dispatch() {
        // Fix 2: a purely unprivileged agent (Reader, acts nowhere) executes a
        // task an approver blessed — the grant confers both admin and context.
        let reader = AuthClaims {
            role: Role::Reader,
            allowed_contexts: vec![],
            ..Default::default()
        };
        assert!(reader.require_admin().is_err());
        assert!(!reader.has_context_access("openvtc"));

        let widened = reader.with_delegated_authority(&["openvtc".into()]);
        assert!(widened.require_admin().is_ok(), "grant confers admin");
        assert!(
            widened.has_context_access("openvtc"),
            "grant confers the context"
        );

        // The original is untouched — no standing elevation persists.
        assert!(reader.require_admin().is_err());
        assert!(!reader.has_context_access("openvtc"));
    }

    #[test]
    fn with_delegated_authority_is_a_noop_for_empty_or_super_admin() {
        let reader = AuthClaims {
            role: Role::Reader,
            allowed_contexts: vec![],
            ..Default::default()
        };
        // Empty delegation changes nothing (an ordinary self-authorized execution).
        let after = reader.with_delegated_authority(&[]);
        assert_eq!(after.role, Role::Reader);
        assert!(after.allowed_contexts.is_empty());

        // A super-admin is already unrestricted; never narrow it to a scoped list.
        let sa = AuthClaims {
            role: Role::Admin,
            ..Default::default()
        };
        assert!(sa.is_super_admin());
        let after = sa.with_delegated_authority(&["openvtc".into()]);
        assert!(after.is_super_admin(), "super-admin stays unrestricted");
    }

    #[test]
    fn with_delegated_contexts_dedups() {
        let base = AuthClaims {
            role: Role::Admin,
            allowed_contexts: vec!["ctx-a".into()],
            ..Default::default()
        };
        let widened = base.with_delegated_contexts(&["ctx-a".into(), "openvtc".into()]);
        assert_eq!(widened.allowed_contexts, vec!["ctx-a", "openvtc"]);
    }

    #[test]
    fn flat_context_grant_is_exact_match_only() {
        // A single-segment grant with no sub-contexts behaves exactly as before.
        let claims = AuthClaims {
            role: Role::Reader,
            allowed_contexts: vec!["prod-mediator".into()],
            ..Default::default()
        };
        assert!(claims.has_context_access("prod-mediator"));
        assert!(!claims.has_context_access("prod-mediator-2"));
        assert!(!claims.has_context_access("other"));
    }

    #[cfg(feature = "cli-synthesis")]
    #[test]
    fn local_cli_synthesizes_super_admin_with_channel_sentinel() {
        let claims = AuthClaims::unsafe_local_cli_super_admin("provision-integration");
        assert_eq!(claims.did, "cli:provision-integration");
        assert_eq!(claims.role, Role::Admin);
        assert!(claims.allowed_contexts.is_empty());
        assert!(claims.is_super_admin());
    }

    #[cfg(feature = "cli-synthesis")]
    #[test]
    fn local_cli_grants_any_context_access() {
        let claims = AuthClaims::unsafe_local_cli_super_admin("keys-bundle");
        // Super-admin has access to every context — enforced elsewhere
        // but assert it explicitly here so a future refactor that
        // breaks the invariant gets caught.
        assert!(claims.has_context_access("any-context"));
        assert!(claims.has_context_access("another"));
        claims
            .require_context("prod-mediator")
            .expect("super-admin passes require_context");
    }

    #[cfg(feature = "cli-synthesis")]
    #[test]
    fn local_cli_did_sentinel_cannot_be_confused_with_real_did() {
        // The `cli:<channel>` format must not round-trip as a
        // `did:*` URI — otherwise audit-log correlation would muddle
        // CLI-synthesized claims with real caller identities.
        let claims = AuthClaims::unsafe_local_cli_super_admin("context-reprovision");
        assert!(!claims.did.starts_with("did:"));
        assert!(claims.did.starts_with("cli:"));
    }

    #[cfg(feature = "cli-synthesis")]
    #[test]
    fn local_cli_channel_embedded_in_did() {
        // Audit-log grep'ability: each synthesis records its `channel`
        // distinctly so forensic investigation can attribute CLI
        // actions to the specific code path that ran them.
        let a = AuthClaims::unsafe_local_cli_super_admin("provision-integration");
        let b = AuthClaims::unsafe_local_cli_super_admin("keys-bundle");
        assert_ne!(a.did, b.did);
    }
}
