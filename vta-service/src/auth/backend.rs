//! VTA-side [`AuthBackend`] implementation.
//!
//! Wires the canonical `/auth/*` handlers in `vti_common::auth::handlers`
//! to VTA's storage (`sessions_ks`, `acl_ks`), JWT minter, TEE
//! attestation provider, and DID-method allowlist.
//!
//! The route handlers in [`crate::routes::auth`] build a
//! [`VtaAuthBackend`] from [`crate::server::AppState`] per request
//! and dispatch to the canonical handler — they own the
//! transport-specific concerns (REST JSON parse, DIDComm
//! `unpack_signed`) and surface the response to axum.

use async_trait::async_trait;
use std::sync::Arc;

// `AuthError` is only constructed inside `#[cfg(feature = "tee")]`
// branches; gate the import alongside to avoid an "unused import" lint
// in non-TEE feature combos (`-D warnings` in CI).
#[cfg(feature = "tee")]
use vti_common::auth::backend::AuthError;
use vti_common::auth::backend::{AttestationOutcome, AuthBackend, RoleResolution};
use vti_common::auth::handlers::KeyspaceSessionStore;
use vti_common::auth::jwt::JwtKeys;

use crate::acl::Role;
use crate::error::AppError;
use crate::server::AppState;

/// VTA `AuthBackend`. Holds an `Arc<AppState>` clone (cheap —
/// every member is already `Clone` and most are `Arc`'d) plus a
/// snapshot of the TTL knobs read once at construction so the
/// trait's sync TTL methods don't have to take the config lock.
pub struct VtaAuthBackend {
    state: Arc<AppState>,
    sessions: KeyspaceSessionStore,
    jwt_keys: Arc<JwtKeys>,
    challenge_ttl: u64,
    access_token_ttl: u64,
    refresh_token_ttl: u64,
}

impl VtaAuthBackend {
    /// Build a backend from the request's `State<AppState>`.
    /// Async because it snapshots the config TTLs under the
    /// `tokio::sync::RwLock`. Errors only when JWT minting isn't
    /// configured — auth routes are effectively unmounted in that
    /// case anyway, but we surface a clear error.
    pub async fn from_state(state: &AppState) -> Result<Self, AppError> {
        let jwt_keys = state
            .jwt_keys
            .clone()
            .ok_or_else(|| AppError::Internal("JWT keys not configured".to_string()))?;
        let sessions = KeyspaceSessionStore::new(state.sessions_ks.clone());

        let (challenge_ttl, access_token_ttl, refresh_token_ttl) = {
            let cfg = state.config.read().await;
            (
                cfg.auth.challenge_ttl,
                cfg.auth.access_token_expiry,
                cfg.auth.refresh_token_expiry,
            )
        };

        Ok(Self {
            state: Arc::new(state.clone()),
            sessions,
            jwt_keys,
            challenge_ttl,
            access_token_ttl,
            refresh_token_ttl,
        })
    }
}

#[async_trait]
impl AuthBackend for VtaAuthBackend {
    type Store = KeyspaceSessionStore;
    type Error = AppError;
    type Role = Role;

    fn sessions(&self) -> &Self::Store {
        &self.sessions
    }

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
    ) -> Result<String, Self::Error> {
        let claims = self
            .jwt_keys
            .new_claims(
                subject.to_string(),
                session_id.to_string(),
                role.to_string(),
                contexts.to_vec(),
                ttl_secs,
                tee_attested,
            )
            .with_aal(amr.to_vec(), acr.to_string());
        self.jwt_keys
            .encode(&claims)
            .map_err(|e| AppError::Internal(format!("jwt encode failed: {e:?}")))
    }

    async fn check_acl(&self, did: &str) -> Result<RoleResolution<Self::Role>, Self::Error> {
        let (role, allowed_contexts) =
            vti_common::acl::check_acl_full(&self.state.acl_ks, did).await?;
        Ok(RoleResolution::with_contexts(role, allowed_contexts))
    }

    /// Enforces VTA's `allowed_did_methods` allowlist in TEE
    /// deployments. Generic `Forbidden` on rejection — the
    /// configured list is operator-private, never echoed to the
    /// caller.
    async fn validate_did(&self, did: &str) -> Result<(), Self::Error> {
        #[cfg(feature = "tee")]
        {
            let config = self.state.config.read().await;
            if let Some(ref allowed) = config.tee.allowed_did_methods {
                let did_ok = allowed.iter().any(|prefix| did.starts_with(prefix));
                if !did_ok {
                    tracing::warn!(%did, "auth rejected: DID method not in allowed_did_methods");
                    return Err(AuthError::DidMethodRejected.into());
                }
            }
        }
        let _ = did;
        Ok(())
    }

    /// VTA-specific TEE attestation. Outside TEE builds returns
    /// not-attested; inside TEE builds with `TeeMode::Optional`
    /// returns not-attested + a warning on provider failure;
    /// inside `TeeMode::Required` raises [`AuthError::AttestationFailed`]
    /// so the canonical handler surfaces a 503-equivalent.
    async fn attest_challenge(
        &self,
        _challenge_bytes: &[u8; 32],
    ) -> Result<AttestationOutcome, Self::Error> {
        #[cfg(feature = "tee")]
        {
            let Some(ref tee) = self.state.tee else {
                return Ok(AttestationOutcome::not_attested());
            };

            let config = self.state.config.read().await;
            let vta_did = config.vta_did.clone();
            let tee_mode = config.tee.mode.clone();
            drop(config);

            let user_data = vta_did.as_deref().unwrap_or("").as_bytes();
            let nonce_bytes = &_challenge_bytes[..];

            match tee.state.provider.attest(user_data, nonce_bytes) {
                Ok(mut report) => {
                    report.vta_did = vta_did;
                    let value = serde_json::to_value(&report).map_err(|e| {
                        AppError::Internal(format!("failed to serialize attestation report: {e}"))
                    })?;
                    Ok(AttestationOutcome::attested(value))
                }
                Err(e) => {
                    if matches!(tee_mode, crate::config::TeeMode::Required) {
                        tracing::error!(
                            "TEE attestation failed in required mode — refusing challenge: {e}"
                        );
                        return Err(AuthError::AttestationFailed(e.to_string()).into());
                    }
                    tracing::warn!(
                        "TEE attestation failed (mode=optional) — challenge served without attestation: {e}"
                    );
                    Ok(AttestationOutcome::not_attested())
                }
            }
        }
        #[cfg(not(feature = "tee"))]
        {
            Ok(AttestationOutcome::not_attested())
        }
    }

    fn challenge_ttl(&self) -> u64 {
        self.challenge_ttl
    }

    fn access_token_ttl(&self) -> u64 {
        self.access_token_ttl
    }

    fn refresh_token_ttl(&self) -> u64 {
        self.refresh_token_ttl
    }
}
