//! Canonical auth-flow backend trait.
//!
//! Five callers (VTA, VTC, did-hosting-control, did-hosting-server,
//! did-hosting-witness) all run the same shape of `/auth/challenge`,
//! `/auth/authenticate`, `/auth/refresh` flow with minor policy
//! differences (TEE attestation, DID-method allowlist, per-DID
//! rate limit) and different storage / error / role types.
//!
//! [`AuthBackend`] is the boundary that lets the canonical handlers
//! in [`crate::auth::handlers`] run unchanged across all five
//! services. Each service implements `AuthBackend` once; the
//! per-route boilerplate collapses to "build the input, call the
//! handler, map the response."
//!
//! ## Trait shape
//!
//! - Associated [`Store`](AuthBackend::Store) — the session storage
//!   primitives the handler needs. Implementors typically wrap their
//!   keyspace handle in a thin adapter that implements
//!   [`SessionStore`].
//! - Associated [`Error`](AuthBackend::Error) — the backend's own
//!   error type. Must convert from [`AuthError`] so the canonical
//!   handler can raise the auth-specific failures and the route
//!   layer surfaces them via its existing `IntoResponse` plumbing.
//! - Associated [`Role`](AuthBackend::Role) — the backend's role
//!   enum (vti-common's `Role`, did-hosting's `Role`, etc.). The
//!   handler treats it opaquely; it appears in the JWT minter
//!   contract and the audit log only.
//! - Default-method policy hooks — [`validate_did`], [`attest_challenge`],
//!   [`max_pending_challenges_per_did`], [`audit`] — backends override
//!   only when they need non-default behaviour. Most backends override
//!   one or two; the rest inherit safe defaults.
//!
//! ## What stays out of the trait
//!
//! - Transport (REST vs. DIDComm) — the canonical handler takes a
//!   pre-extracted [`AuthInput`] struct; transport-specific unpacking
//!   stays in the route handler.
//! - JWT structure — `JwtKeys` is the same across all callers; the
//!   handler holds a `&JwtKeys` reference and mints directly.
//! - Wire-shape serialisation — canonical request / response types
//!   live in `vta_sdk::protocols::auth` and are shared with clients.

use async_trait::async_trait;
use serde::Serialize;
use std::fmt::Debug;

use crate::auth::session::Session;

// ---------------------------------------------------------------------------
// Canonical auth-flow errors
// ---------------------------------------------------------------------------

/// Auth-specific failures the canonical handlers can raise.
///
/// Each backend's `Error` associated type must implement
/// `From<AuthError>` so the handler can return these variants and
/// the route layer surfaces them via its existing `IntoResponse`
/// plumbing (e.g. vti-common's `AppError::Unauthorized(_)` arm).
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// DID is not in the backend's ACL, or the ACL entry is expired.
    /// Returned as 403 Forbidden to avoid revealing whether the DID
    /// exists in the ACL system at all (timing-side-channel
    /// mitigation; the ACL check happens before any other gate).
    #[error("forbidden")]
    Forbidden,

    /// The DID's method (e.g. `did:foo:...`) is not in the backend's
    /// allowlist. Distinct from `Forbidden` so audit logs can
    /// distinguish "wrong method" from "not in ACL". Surfaced to
    /// callers as a generic 403 to avoid leaking the allowlist
    /// contents.
    #[error("did method rejected")]
    DidMethodRejected,

    /// Too many concurrent `ChallengeSent` sessions for this DID;
    /// the per-DID rate limit (default 10) is exhausted. Returned
    /// as 429 Too Many Requests so clients can back off.
    #[error("too many pending challenges")]
    PendingChallengeLimitReached,

    /// The session referenced by the request does not exist or has
    /// expired (TTL swept it). Returned as 401 Unauthorized; the
    /// holder must restart the challenge flow.
    #[error("session not found")]
    SessionNotFound,

    /// The session exists but was already authenticated (replay) or
    /// is otherwise not in the state the request expected. Returned
    /// as 401 Unauthorized; the holder must restart.
    #[error("session replay or state mismatch")]
    SessionStateMismatch,

    /// The presented challenge does not match what was issued for
    /// this session. Constant-time compared. Returned as 401
    /// Unauthorized.
    #[error("challenge mismatch")]
    ChallengeMismatch,

    /// The challenge is older than the backend's configured TTL.
    /// Returned as 401 Unauthorized; the holder must request a
    /// fresh challenge.
    #[error("challenge expired")]
    ChallengeExpired,

    /// The signer DID extracted from the transport (DIDComm `from`,
    /// SIOPv2 `iss`) does not match the DID the session was issued
    /// to. Critical binding — without this check, any leaked
    /// challenge could be redeemed by any signer. Returned as 401
    /// Unauthorized.
    #[error("signer DID does not match session DID")]
    SignerMismatch,

    /// The DIDComm envelope's `created_time` is outside the freshness
    /// window. Replay defense for the DIDComm transport. Returned as
    /// 401 Unauthorized.
    #[error("message created_time outside freshness window")]
    StaleMessage,

    /// The refresh token was not found or already consumed. Atomic
    /// claim semantics: at most one caller succeeds per token.
    /// Returned as 401 Unauthorized; the holder must re-authenticate.
    #[error("refresh token not found or consumed")]
    RefreshTokenInvalid,

    /// The refresh token's absolute expiry has passed. Returned as
    /// 401 Unauthorized; the holder must re-authenticate.
    #[error("refresh token expired")]
    RefreshTokenExpired,

    /// TEE attestation failed in a `TeeMode::Required` deployment.
    /// Returned as 503 Service Unavailable (the operator's TEE is
    /// broken; the caller did nothing wrong).
    #[error("tee attestation failed: {0}")]
    AttestationFailed(String),

    /// Surface for any wrapped error from the backend's policy or
    /// storage layer that doesn't fit the variants above. The
    /// canonical handler does not introspect this; it surfaces
    /// unchanged via the backend's `Error::from(AuthError::Internal)`.
    #[error("internal: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// SessionStore — the storage primitives the canonical handlers need
// ---------------------------------------------------------------------------

/// Storage operations the canonical handlers invoke.
///
/// Each backend wraps its own keyspace handle (vti-common's
/// `KeyspaceHandle` enum, did-hosting's `KeyspaceHandle` struct,
/// future cloud-store backends) in an adapter implementing this
/// trait. The handler holds a `&S` and never touches the concrete
/// storage type directly.
///
/// ## Why this trait, not a single `KeyspaceHandle` type
///
/// did-hosting and vti-common evolved separate keyspace
/// abstractions before the auth-architecture consolidation. Merging
/// them is out of scope for the auth work; the trait boundary
/// keeps them independent while still sharing the auth-flow code.
#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    /// Wrapped error type. Conversion to `AuthError::Internal` is
    /// the handler's responsibility (via `?` and the backend's
    /// `From<AuthError>` impl).
    type Error: Debug + Send + Sync + 'static;

    /// Persist a session under its `session_id`.
    async fn store_session(&self, session: &Session) -> Result<(), Self::Error>;

    /// Load a session by `session_id`. `Ok(None)` if missing or expired-and-swept.
    async fn get_session(&self, session_id: &str) -> Result<Option<Session>, Self::Error>;

    /// Delete a session and its refresh-token reverse-index.
    async fn delete_session(&self, session_id: &str) -> Result<(), Self::Error>;

    /// Persist the `refresh_token → session_id` reverse-index.
    /// Implementors choose whether to hash the key (recommended;
    /// vti-common does, did-hosting historically does not) — the
    /// handler treats the token as an opaque bearer.
    async fn store_refresh_index(
        &self,
        refresh_token: &str,
        session_id: &str,
    ) -> Result<(), Self::Error>;

    /// Atomically claim-and-delete the `refresh_token → session_id`
    /// reverse-index. Cross-replica safe (Redis GETDEL / DynamoDB
    /// DeleteItem ReturnValues=ALL_OLD / fjall mutex). Exactly one
    /// concurrent caller observes `Some` for any given token.
    /// Used by `/auth/refresh` to close the rotation TOCTOU.
    async fn take_session_id_by_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<Option<String>, Self::Error>;

    /// Count `ChallengeSent` sessions for `did`. Backends with an
    /// O(1) per-DID tracker (did-hosting) override the default
    /// O(N) prefix-scan implementation by re-implementing this
    /// method.
    ///
    /// Default implementation provided for backends that haven't
    /// yet built a tracker — correct but slow under load. Override
    /// before relying on per-DID rate limiting in production.
    async fn count_pending_challenges(&self, did: &str) -> Result<usize, Self::Error>;
}

// ---------------------------------------------------------------------------
// AuthBackend — per-service policy + glue
// ---------------------------------------------------------------------------

/// Pluggable backend for the canonical `/auth/*` handlers.
///
/// One implementation per service. Most methods have safe defaults;
/// implementors override only the policy hooks their service
/// actually exercises (TEE attestation, DID-method allowlist, etc.).
#[async_trait]
pub trait AuthBackend: Send + Sync + 'static {
    /// Session storage adapter.
    type Store: SessionStore;

    /// Backend-local error type. Must convert from [`AuthError`]
    /// so the canonical handler can raise auth-specific failures.
    /// Must implement `IntoResponse` at the route boundary; the
    /// trait does not bound that here (would force an axum
    /// dependency on every backend), but the canonical handler
    /// surfaces the error verbatim and the route layer renders
    /// it via its existing path.
    type Error: From<AuthError> + Debug + Send + Sync + 'static;

    /// Backend's role type. The handler holds it opaquely between
    /// ACL lookup and JWT minting.
    ///
    /// - `Display` so the handler can render it into the JWT
    ///   `role` claim (which is a plain string per the canonical
    ///   spec).
    /// - `Serialize` so the audit hook can include it in
    ///   structured logs.
    type Role: std::fmt::Display + Serialize + Clone + Send + Sync + 'static;

    // -------- Plumbing --------

    /// Session store handle. The handler invokes the
    /// [`SessionStore`] methods through this.
    fn sessions(&self) -> &Self::Store;

    /// Mint an access token JWT for an authenticated session.
    ///
    /// The trait abstracts over the concrete JWT minter — VTA + VTC
    /// use `vti_common::auth::jwt::JwtKeys`; did-hosting has its own
    /// minter type with the same shape but a separate `AppError`
    /// surface. Each backend implements this method using whatever
    /// minter it holds; the canonical handler treats the return
    /// value as an opaque base64url-encoded JWS.
    #[allow(clippy::too_many_arguments)]
    async fn mint_access_token(
        &self,
        subject: &str,
        session_id: &str,
        role: &Self::Role,
        contexts: &[String],
        amr: &[String],
        acr: &str,
        tee_attested: bool,
        ttl_secs: u64,
        // Per-issue `jti` nonce; embedded in the token and pinned to the
        // session's `token_id` so a freshly-minted token supersedes the prior.
        jti: &str,
    ) -> Result<String, Self::Error>;

    // -------- Policy hooks --------

    /// Resolve a DID to a role + context scope. Returning an error
    /// (typically [`AuthError::Forbidden`]) rejects the request
    /// before any other gate fires.
    async fn check_acl(&self, did: &str) -> Result<RoleResolution<Self::Role>, Self::Error>;

    /// Optional DID-method validation gate. Default: accept any
    /// method (backends with no allowlist). VTA overrides in TEE
    /// mode to enforce `allowed_did_methods`.
    async fn validate_did(&self, _did: &str) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Optional TEE attestation hook. Returns the attestation
    /// report (if produced) and whether attestation succeeded.
    /// Default: no attestation (None, false). VTA overrides in
    /// TEE mode; in `TeeMode::Required` a failure here must be
    /// raised as [`AuthError::AttestationFailed`].
    async fn attest_challenge(
        &self,
        _challenge_bytes: &[u8; 32],
    ) -> Result<AttestationOutcome, Self::Error> {
        Ok(AttestationOutcome::not_attested())
    }

    /// Cap on concurrent `ChallengeSent` sessions per DID. Default
    /// 10. Setting to 0 disables per-DID rate limiting (still
    /// IP-rate-limited at the tower-governor layer). Backends with
    /// low-trust callers may want this higher; backends with
    /// admin-only callers can keep it at 10.
    fn max_pending_challenges_per_did(&self) -> usize {
        10
    }

    /// Audit hook fired at the end of each handler. Default impl
    /// emits via `tracing::info!(audit=true)`; backends with
    /// structured audit pipelines (e.g. VTC's audit log with HMAC
    /// actor hashing) can override.
    fn audit(&self, event: AuthAuditEvent<'_>) {
        match event {
            AuthAuditEvent::ChallengeIssued { did, session_id } => {
                tracing::info!(audit = true, %did, %session_id, "auth challenge issued");
            }
            AuthAuditEvent::Authenticated {
                did, session_id, ..
            } => {
                tracing::info!(audit = true, %did, %session_id, "auth successful");
            }
            AuthAuditEvent::Refreshed {
                did,
                old_session_id,
                new_session_id,
                ..
            } => {
                tracing::info!(
                    audit = true,
                    %did,
                    %old_session_id,
                    %new_session_id,
                    "token refreshed",
                );
            }
        }
    }

    // -------- Timings --------

    /// Challenge TTL in seconds. Typical: 60.
    fn challenge_ttl(&self) -> u64;

    /// Access-token TTL in seconds. Typical: 900 (15 min).
    fn access_token_ttl(&self) -> u64;

    /// Access-token TTL in seconds for a stepped-up
    /// (`acr=aal2`) session. Default: 1/3 of [`Self::access_token_ttl`]
    /// floored to a minimum of 60 seconds — closes M2 from the
    /// May 2026 security review, which observed that a leaked
    /// `aal2` token has the same 15-minute window as a `aal1`
    /// token despite the elevated privileges it grants.
    ///
    /// Backends can override to set their own ratio or to
    /// disable the elevation (return `access_token_ttl()` for a
    /// uniform TTL).
    fn access_token_ttl_for_aal2(&self) -> u64 {
        let base = self.access_token_ttl();
        std::cmp::max(60, base / 3)
    }

    /// Refresh-token TTL in seconds. Typical: 86400 (24 h).
    fn refresh_token_ttl(&self) -> u64;

    /// DIDComm `created_time` freshness window in seconds. The
    /// canonical handler rejects messages older than this against
    /// `session.created_at` to bound replay risk. Default 60s.
    fn didcomm_freshness_window(&self) -> u64 {
        60
    }
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// Result of an ACL lookup. The handler propagates this opaquely
/// into the JWT minter and audit event.
#[derive(Debug, Clone)]
pub struct RoleResolution<R> {
    pub role: R,
    /// Context-scoped backends (VTA) populate this. Backends with
    /// flat ACL (did-hosting) leave it empty.
    pub contexts: Vec<String>,
}

impl<R> RoleResolution<R> {
    pub fn new(role: R) -> Self {
        Self {
            role,
            contexts: Vec::new(),
        }
    }

    pub fn with_contexts(role: R, contexts: Vec<String>) -> Self {
        Self { role, contexts }
    }
}

/// Outcome of the optional TEE attestation hook.
#[derive(Debug, Clone)]
pub struct AttestationOutcome {
    /// JSON-serialised attestation report, if produced. Echoed
    /// back to the client in the challenge response under
    /// `tee_attestation`. `None` for backends with no TEE.
    pub report: Option<serde_json::Value>,
    /// Whether attestation succeeded for *this* challenge. The
    /// JWT's `tee_attested` claim is sourced from this bit; a TEE
    /// binary in `TeeMode::Optional` that fails attestation must
    /// set this to `false`.
    pub attested: bool,
}

impl AttestationOutcome {
    pub fn not_attested() -> Self {
        Self {
            report: None,
            attested: false,
        }
    }

    pub fn attested(report: serde_json::Value) -> Self {
        Self {
            report: Some(report),
            attested: true,
        }
    }
}

/// Events the canonical handlers emit to the backend's audit
/// sink. The default `AuthBackend::audit` impl forwards each
/// variant to `tracing::info!(audit=true)` so backends without
/// a structured audit log get useful output for free.
#[derive(Debug)]
pub enum AuthAuditEvent<'a> {
    /// Fired after a successful `/auth/challenge`. The session
    /// is in `ChallengeSent` state.
    ChallengeIssued { did: &'a str, session_id: &'a str },
    /// Fired after a successful `/auth/authenticate`. The
    /// session is now in `Authenticated` state with `amr`/`acr`
    /// populated.
    Authenticated {
        did: &'a str,
        session_id: &'a str,
        amr: &'a [String],
        acr: &'a str,
    },
    /// Fired after a successful `/auth/refresh`. The old
    /// session has been deleted; the new one is `Authenticated`
    /// at the *preserved* `amr`/`acr` from the old session.
    Refreshed {
        did: &'a str,
        old_session_id: &'a str,
        new_session_id: &'a str,
        amr: &'a [String],
        acr: &'a str,
    },
}

// ---------------------------------------------------------------------------
// Pre-extracted inputs the canonical handlers take
// ---------------------------------------------------------------------------

/// Inputs to `/auth/challenge`.
#[derive(Debug, Clone)]
pub struct ChallengeInput {
    /// Caller's DID. ACL-gated.
    pub did: String,
    /// Optional ephemeral session pubkey (Ed25519 multikey
    /// base58btc with `z` prefix) for Data-Integrity-proof
    /// binding on subsequent trust-task envelopes. `None` for
    /// callers that sign with their DID's own key.
    pub session_pubkey_b58btc: Option<String>,
}

/// Inputs to `/auth/authenticate` after the transport layer has
/// verified the signer.
///
/// The transport layer (DIDComm `unpack_signed`, SIOPv2 JWS
/// verification, etc.) extracts the signer and produces this
/// struct; the canonical handler then validates against the
/// session and mints tokens.
#[derive(Debug, Clone)]
pub struct AuthenticateInput {
    pub session_id: String,
    pub challenge: String,
    /// Verified signer DID. The transport layer must produce
    /// this from a cryptographic check (DIDComm authcrypt,
    /// JWS signature, etc.) — *never* echo it from the request
    /// body unchecked.
    pub signer_did: String,
    /// Optional message `created_time` for DIDComm freshness
    /// checking. `None` for REST transports.
    pub created_time: Option<u64>,
    /// Optional ephemeral session pubkey to register against
    /// this session at the auth transition. SIOPv2 callers
    /// (did-hosting-control) carry one to support
    /// Data-Integrity-proof binding on subsequent
    /// trust-task envelopes; DIDComm transports normally leave
    /// this `None`. The route layer is responsible for any
    /// shape-validation (e.g. `z6Mk…` Ed25519 multikey prefix)
    /// before passing it in.
    pub session_pubkey_b58btc: Option<String>,
}

/// Inputs to `/auth/refresh` after the transport layer has
/// verified the signer.
#[derive(Debug, Clone)]
pub struct RefreshInput {
    pub refresh_token: String,
    /// Verified signer DID (DIDComm transports). REST transports
    /// can leave this `None`; the canonical handler treats `None`
    /// as "skip signer-DID-matches-session-DID check" — only safe
    /// when the transport offers no signer assertion (i.e. plain
    /// REST refresh, where the token itself is the only credential).
    pub signer_did: Option<String>,
}
