//! [`SessionStore`] impl for vti-common's [`KeyspaceHandle`].
//!
//! VTA + VTC use this directly: their `AuthBackend::Store` is
//! `KeyspaceSessionStore` and the trait methods delegate to the
//! free-standing helpers in [`crate::auth::session`].
//!
//! did-hosting writes its own `SessionStore` impl wrapping
//! [`did_hosting_common::server::store::KeyspaceHandle`] —
//! different concrete keyspace type, same trait surface.

use async_trait::async_trait;

use crate::auth::backend::SessionStore;
use crate::auth::session::{self, Session};
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Thin newtype around [`KeyspaceHandle`] that implements
/// [`SessionStore`].
///
/// Newtype rather than blanket-impl-on-`KeyspaceHandle` so the
/// trait surface stays decoupled from the storage type (orphan
/// rule + future-proofing — a different store would implement
/// `SessionStore` on a different newtype).
#[derive(Clone)]
pub struct KeyspaceSessionStore {
    inner: KeyspaceHandle,
}

impl KeyspaceSessionStore {
    pub fn new(inner: KeyspaceHandle) -> Self {
        Self { inner }
    }

    pub fn handle(&self) -> &KeyspaceHandle {
        &self.inner
    }
}

#[async_trait]
impl SessionStore for KeyspaceSessionStore {
    type Error = AppError;

    async fn store_session(&self, s: &Session) -> Result<(), Self::Error> {
        session::store_session(&self.inner, s).await
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<Session>, Self::Error> {
        session::get_session(&self.inner, session_id).await
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), Self::Error> {
        session::delete_session(&self.inner, session_id).await
    }

    async fn store_refresh_index(
        &self,
        refresh_token: &str,
        session_id: &str,
    ) -> Result<(), Self::Error> {
        session::store_refresh_index(&self.inner, refresh_token, session_id).await
    }

    async fn take_session_id_by_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<Option<String>, Self::Error> {
        session::take_session_id_by_refresh(&self.inner, refresh_token).await
    }

    /// Overrides the trait's no-op default so VTA and VTC get refresh
    /// reuse detection. Paired with [`Self::get_refresh_tombstone`] —
    /// either both are implemented or neither does anything.
    async fn store_refresh_tombstone(
        &self,
        rotated_token: &str,
        session_id: &str,
        successor_token: &str,
        rotated_at: u64,
        ttl: u64,
    ) -> Result<(), Self::Error> {
        session::store_refresh_tombstone(
            &self.inner,
            rotated_token,
            session_id,
            successor_token,
            rotated_at,
            ttl,
        )
        .await
    }

    async fn get_refresh_tombstone(
        &self,
        refresh_token: &str,
    ) -> Result<Option<session::RefreshTombstone>, Self::Error> {
        session::get_refresh_tombstone(&self.inner, refresh_token).await
    }

    async fn count_pending_challenges(&self, did: &str) -> Result<usize, Self::Error> {
        session::count_pending_challenges(&self.inner, did).await
    }

    /// Overrides the trait's read-modify-write default to share one
    /// implementation with the extractor's per-request touch — both go
    /// through [`session::touch_last_seen`], so the granularity throttle
    /// is applied in exactly one place.
    async fn touch_session(&self, session_id: &str, at: u64) -> Result<(), Self::Error> {
        let Some(row) = session::get_session(&self.inner, session_id).await? else {
            return Ok(());
        };
        session::touch_last_seen(&self.inner, &row, at)
            .await
            .map(|_| ())
    }
}
