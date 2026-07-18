use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use tracing::warn;

use crate::acl::Role;
use crate::auth::jwt::JwtKeys;
use crate::auth::session::{SessionState, get_session};
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
/// `POST /v1/auth/admin-login` + `POST /v1/auth/passkey-login/finish`
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
        // Try `Authorization: Bearer <jwt>` first. Programmatic
        // clients (cnm-cli, DIDComm bridges, the existing
        // `/v1/auth/` flow) all use this path.
        let bearer_token = TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
            .await
            .ok()
            .map(|TypedHeader(auth)| auth.token().to_string());

        // Fall back to the admin session cookie (Phase 5 M5.2.3).
        // Set by `POST /v1/auth/admin-login`; carries the same JWT
        // as the bearer path.
        let token: String = match bearer_token {
            Some(t) => t,
            None => match cookie_token(parts, ADMIN_SESSION_COOKIE) {
                Some(t) => t,
                None => {
                    warn!(
                        "auth rejected: no Authorization header and no {ADMIN_SESSION_COOKIE} cookie"
                    );
                    return Err(AppError::Unauthorized(
                        "missing or invalid Authorization header".into(),
                    ));
                }
            },
        };
        let token = token.as_str();

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

        Ok(AuthClaims {
            did: claims.sub,
            role,
            allowed_contexts: claims.contexts,
            session_id: claims.session_id,
            access_expires_at: claims.exp,
            amr: claims.amr,
            acr: claims.acr,
        })
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
            // visibly "no real expiry" to any log scraper.
            session_id: format!("cli:{channel}"),
            access_expires_at: 0,
            // CLI synthesis is a process-local trust boundary; the auth
            // method is the OS user, not a wire factor. Surface `"cli"`
            // in amr so a downstream auditor distinguishes synthesized
            // claims from real authenticated sessions.
            amr: vec!["cli".to_string()],
            acr: String::new(),
        }
    }

    /// Returns `true` if the caller is an admin with unrestricted access
    /// (empty `allowed_contexts`).
    pub fn is_super_admin(&self) -> bool {
        self.role == Role::Admin && self.allowed_contexts.is_empty()
    }

    /// Returns `true` if the caller has access to the given context — as a super
    /// admin, or because one of their `allowed_contexts` is `context_id` itself
    /// **or an ancestor of it** (folder-level authority: admin of a parent
    /// context covers the whole subtree).
    ///
    /// Ancestry is the segment-aware
    /// [`is_ancestor_or_self`](crate::context_path::is_ancestor_or_self) — a
    /// pure, store-free check over the verified JWT's contexts. For today's flat
    /// (single-segment, childless) contexts this is identical to the previous
    /// exact match.
    pub fn has_context_access(&self, context_id: &str) -> bool {
        self.is_super_admin()
            || self
                .allowed_contexts
                .iter()
                .any(|allowed| crate::context_path::is_ancestor_or_self(allowed, context_id))
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

/// Extractor that requires a **stepped-up** session (JWT `acr == "aal2"`).
///
/// Use on routes that demand a second factor beyond the base DID
/// challenge-response (`aal1`) — typical examples: ACL edits,
/// key rotation, backup export, anything that lets an attacker
/// with a leaked `aal1` token pivot to a long-lived foothold.
///
/// ```ignore
/// async fn rotate_keys(auth: StepUpAuth, ...) { /* aal2 enforced */ }
/// ```
///
/// A request with a lower `acr` is rejected with
/// [`AppError::StepUpRequired`] (403 + body
/// `{ "error": "step_up_required", "requiredAcr": "aal2" }`). The
/// wallet uses that signal to trigger a passkey-login or
/// VTA-approval ceremony — distinct from a generic `forbidden`
/// it would get from a role gate.
///
/// **Trust model**: the gate reads `acr` from the JWT claims the
/// `AuthClaims` extractor already verified (signature, expiry,
/// session existence). Step-up tokens are stateless during their
/// access-window; the canonical refresh handler preserves `acr`
/// across rotation. If a step-up access-token leaks, the only
/// brake is the short access-token TTL (or [`M2`] — shorter TTL
/// when `acr=aal2`).
#[derive(Debug, Clone)]
pub struct StepUpAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for StepUpAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        if claims.acr == "aal2" {
            Ok(StepUpAuth(claims))
        } else {
            warn!(
                did = %claims.did,
                acr = %claims.acr,
                "auth rejected: step-up (aal2) required",
            );
            Err(AppError::StepUpRequired(
                "operation requires a stepped-up (aal2) session".into(),
            ))
        }
    }
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
/// percent-decode — cookie values minted by the VTC's admin-login
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
