//! Shared session-token minting.
//!
//! The single place that computes the acr-dependent access-token TTL,
//! mints the access + refresh token pair, and fires the
//! `Authenticated` audit hook. Both the canonical `/auth/` handler
//! ([`super::handle_authenticate_with_aal`]) and out-of-band step-up
//! mints (e.g. VTC passkey-login-finish) call this so the AAL2
//! short-TTL hardening (M2 — bound a leaked elevated token) and the
//! audit hook can't drift between paths.

use uuid::Uuid;

use crate::auth::backend::{AuthAuditEvent, AuthBackend};
use crate::auth::session::now_epoch;

/// Tokens minted for an authenticated session, plus the timing the
/// caller needs to build its wire response and persist the session.
pub struct MintedTokens {
    pub access_token: String,
    pub refresh_token: String,
    /// Access-token TTL actually applied (acr-dependent).
    pub access_ttl: u64,
    /// Absolute epoch-second expiry of the access token.
    pub access_expires_at: u64,
    /// Absolute epoch-second expiry of the refresh token.
    pub refresh_expires_at: u64,
    /// Epoch second the tokens were minted at.
    pub issued_at: u64,
}

/// Mint an access + refresh token pair for an already-authenticated
/// subject and fire the `Authenticated` audit hook.
///
/// The access TTL is **acr-dependent**: a stepped-up (`aal2`) session
/// gets [`AuthBackend::access_token_ttl_for_aal2`] (M2 — bounds the
/// blast radius of a leaked elevated token), everything else gets
/// [`AuthBackend::access_token_ttl`]. Centralising this is the point
/// of the helper: callers that hand-rolled the mint (VTC
/// passkey-login-finish) previously issued `aal2` tokens with the
/// full `aal1` TTL, so the one token class the hardening protects got
/// the longest exposure — and emitted no `Authenticated` audit event.
///
/// Does **not** persist the session or refresh index — the caller
/// owns the session lifecycle (the canonical handler transitions a
/// `ChallengeSent` row to `Authenticated`; the passkey path creates a
/// fresh `Authenticated` row).
#[allow(clippy::too_many_arguments)]
pub async fn mint_session_tokens<B: AuthBackend>(
    backend: &B,
    did: &str,
    session_id: &str,
    role: &B::Role,
    contexts: &[String],
    amr: &[String],
    acr: &str,
    tee_attested: bool,
) -> Result<MintedTokens, B::Error> {
    let now = now_epoch();
    let access_ttl = if acr == "aal2" {
        backend.access_token_ttl_for_aal2()
    } else {
        backend.access_token_ttl()
    };
    let refresh_token = Uuid::new_v4().to_string();
    let refresh_expires_at = now.saturating_add(backend.refresh_token_ttl());
    let access_expires_at = now.saturating_add(access_ttl);

    let access_token = backend
        .mint_access_token(
            did,
            session_id,
            role,
            contexts,
            amr,
            acr,
            tee_attested,
            access_ttl,
        )
        .await?;

    backend.audit(AuthAuditEvent::Authenticated {
        did,
        session_id,
        amr,
        acr,
    });

    Ok(MintedTokens {
        access_token,
        refresh_token,
        access_ttl,
        access_expires_at,
        refresh_expires_at,
        issued_at: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::backend::{RoleResolution, SessionStore};
    use crate::auth::session::Session;
    use crate::error::AppError;
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// `mint_session_tokens` never touches the session store, so every
    /// method is `unreachable!()`.
    struct DummyStore;

    #[async_trait]
    impl SessionStore for DummyStore {
        type Error = AppError;
        async fn store_session(&self, _: &Session) -> Result<(), AppError> {
            unreachable!()
        }
        async fn get_session(&self, _: &str) -> Result<Option<Session>, AppError> {
            unreachable!()
        }
        async fn delete_session(&self, _: &str) -> Result<(), AppError> {
            unreachable!()
        }
        async fn store_refresh_index(&self, _: &str, _: &str) -> Result<(), AppError> {
            unreachable!()
        }
        async fn take_session_id_by_refresh(&self, _: &str) -> Result<Option<String>, AppError> {
            unreachable!()
        }
        async fn count_pending_challenges(&self, _: &str) -> Result<usize, AppError> {
            unreachable!()
        }
    }

    struct MockBackend {
        store: DummyStore,
        authenticated_fired: Arc<AtomicBool>,
    }

    #[async_trait]
    impl AuthBackend for MockBackend {
        type Store = DummyStore;
        type Error = AppError;
        type Role = String;

        fn sessions(&self) -> &DummyStore {
            &self.store
        }

        #[allow(clippy::too_many_arguments)]
        async fn mint_access_token(
            &self,
            _subject: &str,
            _session_id: &str,
            _role: &String,
            _contexts: &[String],
            _amr: &[String],
            _acr: &str,
            _tee_attested: bool,
            ttl_secs: u64,
        ) -> Result<String, AppError> {
            // Echo the applied TTL so the test can confirm which one was used.
            Ok(format!("token-ttl-{ttl_secs}"))
        }

        async fn check_acl(&self, _did: &str) -> Result<RoleResolution<String>, AppError> {
            unreachable!()
        }

        fn challenge_ttl(&self) -> u64 {
            60
        }
        fn access_token_ttl(&self) -> u64 {
            900
        }
        fn refresh_token_ttl(&self) -> u64 {
            86_400
        }

        fn audit(&self, event: AuthAuditEvent<'_>) {
            if matches!(event, AuthAuditEvent::Authenticated { .. }) {
                self.authenticated_fired.store(true, Ordering::SeqCst);
            }
        }
    }

    fn backend() -> (MockBackend, Arc<AtomicBool>) {
        let fired = Arc::new(AtomicBool::new(false));
        (
            MockBackend {
                store: DummyStore,
                authenticated_fired: fired.clone(),
            },
            fired,
        )
    }

    #[tokio::test]
    async fn aal2_mint_uses_short_ttl_and_fires_authenticated_audit() {
        let (backend, fired) = backend();
        let minted = mint_session_tokens(
            &backend,
            "did:key:zA",
            "sess-1",
            &"admin".to_string(),
            &[],
            &["passkey".to_string()],
            "aal2",
            false,
        )
        .await
        .unwrap();

        // aal2 → access_token_ttl_for_aal2() = max(60, 900/3) = 300.
        // This is the M2 hardening the passkey path previously bypassed.
        assert_eq!(minted.access_ttl, backend.access_token_ttl_for_aal2());
        assert_eq!(minted.access_ttl, 300);
        assert_eq!(minted.access_token, "token-ttl-300");
        assert_eq!(minted.access_expires_at, minted.issued_at + 300);
        assert_eq!(minted.refresh_expires_at, minted.issued_at + 86_400);
        assert!(
            fired.load(Ordering::SeqCst),
            "Authenticated audit hook must fire"
        );
    }

    #[tokio::test]
    async fn aal1_mint_uses_full_ttl() {
        let (backend, fired) = backend();
        let minted = mint_session_tokens(
            &backend,
            "did:key:zA",
            "sess-1",
            &"member".to_string(),
            &[],
            &["did".to_string()],
            "aal1",
            false,
        )
        .await
        .unwrap();

        assert_eq!(minted.access_ttl, backend.access_token_ttl());
        assert_eq!(minted.access_ttl, 900);
        assert_eq!(minted.access_token, "token-ttl-900");
        assert!(fired.load(Ordering::SeqCst));
    }
}
