//! The member portal's [`AuthBackend`]: the shared `/auth/*` handlers, pointed
//! at the member session keyspace, admitting active members only, minting for
//! the member audience.

use std::sync::Arc;

use async_trait::async_trait;
use vti_common::auth::backend::{AuthBackend, RoleResolution};
use vti_common::auth::handlers::KeyspaceSessionStore;
use vti_common::auth::jwt::JwtKeys;

use super::{member_jwt_keys, require_active_member};
use crate::acl::Role;
use crate::error::AppError;
use crate::server::AppState;

/// Member-portal backend. Same TTLs and idle timeout as the console's
/// ([`crate::auth::VtcAuthBackend`]); different keyspace, audience and gate.
pub struct MemberAuthBackend {
    state: Arc<AppState>,
    sessions: KeyspaceSessionStore,
    jwt_keys: JwtKeys,
    challenge_ttl: u64,
    access_token_ttl: u64,
    refresh_token_ttl: u64,
    refresh_reuse_grace: u64,
    idle_timeout: u64,
}

impl MemberAuthBackend {
    pub async fn from_state(state: &AppState) -> Result<Self, AppError> {
        let jwt_keys = member_jwt_keys(state)?;
        let cfg = state.config.read().await;
        Ok(Self {
            state: Arc::new(state.clone()),
            sessions: KeyspaceSessionStore::new(state.member_sessions_ks.clone()),
            jwt_keys,
            challenge_ttl: cfg.auth.challenge_ttl,
            access_token_ttl: cfg.auth.access_token_expiry,
            refresh_token_ttl: cfg.auth.refresh_token_expiry,
            refresh_reuse_grace: cfg.auth.refresh_reuse_grace,
            idle_timeout: cfg.auth.admin_idle_timeout,
        })
    }
}

#[async_trait]
impl AuthBackend for MemberAuthBackend {
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
        jti: &str,
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
            .with_aal(amr.to_vec(), acr.to_string())
            .with_jti(jti);
        self.jwt_keys
            .encode(&claims)
            .map_err(|e| AppError::Internal(format!("jwt encode failed: {e:?}")))
    }

    /// Active members only, read live at challenge, authentication and every
    /// refresh. The role claim is `reader` — it carries no authority (nothing
    /// that reads this audience consults it), and is the least-privileged
    /// value the shared taxonomy has should a token ever be misrouted.
    async fn check_acl(&self, did: &str) -> Result<RoleResolution<Self::Role>, Self::Error> {
        require_active_member(&self.state, did).await?;
        Ok(RoleResolution::with_contexts(Role::Reader, Vec::new()))
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

    fn refresh_reuse_grace(&self) -> u64 {
        self.refresh_reuse_grace
    }

    fn idle_timeout(&self) -> Option<u64> {
        Some(self.idle_timeout)
    }
}
