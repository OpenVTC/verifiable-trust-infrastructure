//! `TrustRegistryClient` trait + in-memory mock.
//!
//! The trait covers both transports the upstream
//! `affinidi-trust-registry-rs` exposes:
//!
//! - **Reads** — TRQP v2.0 queries (`recognise`, `authorize`) go
//!   over HTTP. Used by M3.10's cross-community session-mint
//!   path.
//! - **Writes** — admin operations (publish / update / delete
//!   member record) go over DIDComm against the upstream's
//!   `tr-admin/1.0/*` message types. Used by M3.4's
//!   `MembershipSyncer`.
//!
//! M3.1 lands the **trait shape + `MockRegistryClient`** for
//! tests; the live HTTP / DIDComm wiring lands alongside its
//! consumers (M3.2 + M3.4 for writes, M3.10 for reads).
//!
//! ## Why one trait, two transports
//!
//! The transports are opaque to consumers — the syncer never
//! asks "should this go over HTTP or DIDComm?", it just calls
//! `publish_member()`. Keeping that abstraction means future
//! upstream changes (e.g. an HTTP admin API materialising)
//! land in one place, not at every call site.

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::Mutex;

use super::model::RegistryRecord;

/// Errors the trust-registry client surfaces. Mapped to
/// [`vti_common::error::AppError::Internal`] at the call site
/// — the registry is a downstream dependency, never operator
/// input.
#[derive(Debug, Clone, Error)]
pub enum RegistryError {
    /// Transient — the next retry will likely succeed. The
    /// syncer's backoff schedule kicks in.
    #[error("transient registry failure: {0}")]
    Transient(String),
    /// Permanent — the registry rejected the request shape.
    /// Manual operator intervention required; the syncer flips
    /// the job to `Failed` immediately rather than retrying.
    #[error("permanent registry failure: {0}")]
    Permanent(String),
    /// The registry is unreachable. Caller's circuit breaker
    /// should open after enough of these in a row.
    #[error("registry unreachable: {0}")]
    Unreachable(String),
}

impl RegistryError {
    /// `true` when the error is worth retrying. Used by the
    /// syncer to distinguish "back off + retry" from "give up
    /// immediately".
    pub fn is_retriable(&self) -> bool {
        matches!(self, Self::Transient(_) | Self::Unreachable(_))
    }
}

impl From<RegistryError> for vti_common::error::AppError {
    /// Preserve the retriable/permanent semantics at the HTTP
    /// boundary instead of collapsing every registry failure into an
    /// opaque 500 (house rule on typed errors). A reachable-but-flaky
    /// or unreachable registry is **503** (try again later); a
    /// registry that rejected the request shape is an upstream fault
    /// surfaced as **502**.
    fn from(e: RegistryError) -> Self {
        use axum::http::StatusCode;
        match e {
            RegistryError::Transient(msg) | RegistryError::Unreachable(msg) => {
                vti_common::error::AppError::ServiceError {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    message: format!("trust registry unavailable: {msg}"),
                }
            }
            RegistryError::Permanent(msg) => vti_common::error::AppError::ServiceError {
                status: StatusCode::BAD_GATEWAY,
                message: format!("trust registry rejected request: {msg}"),
            },
        }
    }
}

/// Abstraction over the upstream trust-registry transport.
/// Production binds [`UpstreamTrustRegistryClient`] (lands in
/// M3.2 + M3.10); tests bind [`MockRegistryClient`].
#[async_trait]
pub trait TrustRegistryClient: Send + Sync {
    /// Publish (or republish) a member record. Maps onto the
    /// upstream's `tr-admin/1.0/create-record` (M3.4) or
    /// `update-record` DIDComm message — the trait doesn't
    /// distinguish; the implementation chooses based on
    /// whether the record already exists. Phase-3 sentry:
    /// every call is idempotent.
    async fn publish_member(&self, record: &RegistryRecord) -> Result<(), RegistryError>;

    /// Delete a member record (RTBF / Purge disposition).
    /// Maps onto `tr-admin/1.0/delete-record`.
    async fn delete_member(&self, member_did: &str) -> Result<(), RegistryError>;

    /// Read a member's current record. `Ok(None)` when the
    /// registry has no row for this DID. Used by the syncer
    /// at boot to reconcile drift, and by M3.10 to check that
    /// a foreign issuer is recognised.
    async fn read_member(&self, member_did: &str) -> Result<Option<RegistryRecord>, RegistryError>;

    /// Connectivity probe. Returns `Ok(())` iff the registry
    /// is reachable. Drives the `registry_status` flip on
    /// `GET /v1/community/profile` (M3.2).
    async fn health(&self) -> Result<(), RegistryError>;

    /// TRQP `recognise` query (M3.9 + M3.10): "is this foreign
    /// community's issuer DID present in the recognition
    /// graph?". Returns `Ok(true)` when the registry confirms
    /// the issuer is recognised, `Ok(false)` for a clean
    /// not-found, and `Err` for transport / parse failures.
    ///
    /// **Called per-mint, never cached** (spec §8.4 + plan
    /// D5): a peer community removed from the recognition
    /// graph mid-session loses access on the next mint /
    /// refresh, not when a TTL elapses.
    async fn recognise(&self, foreign_issuer_did: &str) -> Result<bool, RegistryError>;
}

// ---------------------------------------------------------------------------
// MockRegistryClient — in-memory test double
// ---------------------------------------------------------------------------

/// In-memory `TrustRegistryClient` for tests. Tracks per-call
/// counts so tests can assert against the upstream surface
/// without needing a docker-backed registry.
///
/// Cheap to clone — the inner state is an `Arc<Mutex<...>>`.
#[derive(Debug, Clone, Default)]
pub struct MockRegistryClient {
    inner: Arc<Mutex<MockState>>,
}

#[derive(Debug, Default)]
struct MockState {
    pub records: std::collections::HashMap<String, RegistryRecord>,
    /// Set of foreign-issuer DIDs the mock will return
    /// `Ok(true)` for on `recognise`. Tests seed this directly
    /// via [`MockRegistryClient::set_recognised`].
    pub recognised_issuers: std::collections::HashSet<String>,
    pub publish_calls: usize,
    pub delete_calls: usize,
    pub read_calls: usize,
    pub health_calls: usize,
    pub recognise_calls: usize,
    /// When set, the next call of the matching kind returns
    /// the queued error instead of succeeding. Tests inject
    /// these to exercise the failure branches.
    pub next_publish_error: Option<RegistryError>,
    pub next_delete_error: Option<RegistryError>,
    pub next_read_error: Option<RegistryError>,
    pub next_health_error: Option<RegistryError>,
    pub next_recognise_error: Option<RegistryError>,
}

impl MockRegistryClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the call counts. Useful for `assert_eq!` in
    /// tests without cloning the full state.
    pub async fn call_counts(&self) -> MockCallCounts {
        let s = self.inner.lock().await;
        MockCallCounts {
            publish: s.publish_calls,
            delete: s.delete_calls,
            read: s.read_calls,
            health: s.health_calls,
            recognise: s.recognise_calls,
        }
    }

    /// Queue an error for the next `publish_member` call.
    pub async fn fail_next_publish(&self, err: RegistryError) {
        self.inner.lock().await.next_publish_error = Some(err);
    }

    /// Queue an error for the next `delete_member` call.
    pub async fn fail_next_delete(&self, err: RegistryError) {
        self.inner.lock().await.next_delete_error = Some(err);
    }

    /// Queue an error for the next `read_member` call.
    pub async fn fail_next_read(&self, err: RegistryError) {
        self.inner.lock().await.next_read_error = Some(err);
    }

    /// Queue an error for the next `health` call.
    pub async fn fail_next_health(&self, err: RegistryError) {
        self.inner.lock().await.next_health_error = Some(err);
    }

    /// Mark `foreign_issuer_did` as recognised — the next
    /// `recognise` call returns `Ok(true)` for it.
    pub async fn set_recognised(&self, foreign_issuer_did: impl Into<String>) {
        self.inner
            .lock()
            .await
            .recognised_issuers
            .insert(foreign_issuer_did.into());
    }

    /// Queue an error for the next `recognise` call.
    pub async fn fail_next_recognise(&self, err: RegistryError) {
        self.inner.lock().await.next_recognise_error = Some(err);
    }

    /// Read the upstream state directly. Tests assert against
    /// this to confirm a call landed.
    pub async fn snapshot(&self) -> std::collections::HashMap<String, RegistryRecord> {
        self.inner.lock().await.records.clone()
    }
}

/// Per-call counters surfaced by [`MockRegistryClient::call_counts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MockCallCounts {
    pub publish: usize,
    pub delete: usize,
    pub read: usize,
    pub health: usize,
    pub recognise: usize,
}

#[async_trait]
impl TrustRegistryClient for MockRegistryClient {
    async fn publish_member(&self, record: &RegistryRecord) -> Result<(), RegistryError> {
        let mut s = self.inner.lock().await;
        s.publish_calls += 1;
        if let Some(err) = s.next_publish_error.take() {
            return Err(err);
        }
        s.records.insert(record.member_did.clone(), record.clone());
        Ok(())
    }

    async fn delete_member(&self, member_did: &str) -> Result<(), RegistryError> {
        let mut s = self.inner.lock().await;
        s.delete_calls += 1;
        if let Some(err) = s.next_delete_error.take() {
            return Err(err);
        }
        s.records.remove(member_did);
        Ok(())
    }

    async fn read_member(&self, member_did: &str) -> Result<Option<RegistryRecord>, RegistryError> {
        let mut s = self.inner.lock().await;
        s.read_calls += 1;
        if let Some(err) = s.next_read_error.take() {
            return Err(err);
        }
        Ok(s.records.get(member_did).cloned())
    }

    async fn health(&self) -> Result<(), RegistryError> {
        let mut s = self.inner.lock().await;
        s.health_calls += 1;
        if let Some(err) = s.next_health_error.take() {
            return Err(err);
        }
        Ok(())
    }

    async fn recognise(&self, foreign_issuer_did: &str) -> Result<bool, RegistryError> {
        let mut s = self.inner.lock().await;
        s.recognise_calls += 1;
        if let Some(err) = s.next_recognise_error.take() {
            return Err(err);
        }
        Ok(s.recognised_issuers.contains(foreign_issuer_did))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::model::RegistryStatus;
    use chrono::Utc;

    fn fresh_record(did: &str) -> RegistryRecord {
        RegistryRecord {
            member_did: did.into(),
            status: RegistryStatus::Active,
            active_from: Utc::now(),
            active_to: None,
            last_synced_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn mock_tracks_call_counts() {
        let m = MockRegistryClient::new();
        m.publish_member(&fresh_record("did:key:zA")).await.unwrap();
        m.publish_member(&fresh_record("did:key:zB")).await.unwrap();
        m.read_member("did:key:zA").await.unwrap();
        m.delete_member("did:key:zB").await.unwrap();
        m.health().await.unwrap();

        let counts = m.call_counts().await;
        assert_eq!(counts.publish, 2);
        assert_eq!(counts.read, 1);
        assert_eq!(counts.delete, 1);
        assert_eq!(counts.health, 1);
    }

    #[tokio::test]
    async fn mock_persists_published_records() {
        let m = MockRegistryClient::new();
        m.publish_member(&fresh_record("did:key:zX")).await.unwrap();
        let got = m.read_member("did:key:zX").await.unwrap().expect("present");
        assert_eq!(got.member_did, "did:key:zX");
        // Absent DID returns None.
        let none = m.read_member("did:key:zMissing").await.unwrap();
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn fail_next_publish_consumes_a_single_call() {
        let m = MockRegistryClient::new();
        m.fail_next_publish(RegistryError::Transient("flaky".into()))
            .await;
        let err = m
            .publish_member(&fresh_record("did:key:zA"))
            .await
            .expect_err("queued error must surface");
        assert!(err.is_retriable());
        // Second call succeeds — error queue is one-shot.
        m.publish_member(&fresh_record("did:key:zA")).await.unwrap();
    }

    #[tokio::test]
    async fn delete_removes_from_snapshot() {
        let m = MockRegistryClient::new();
        m.publish_member(&fresh_record("did:key:zKeep"))
            .await
            .unwrap();
        m.publish_member(&fresh_record("did:key:zDrop"))
            .await
            .unwrap();
        m.delete_member("did:key:zDrop").await.unwrap();
        let snap = m.snapshot().await;
        assert!(snap.contains_key("did:key:zKeep"));
        assert!(!snap.contains_key("did:key:zDrop"));
    }

    #[tokio::test]
    async fn recognise_returns_true_for_seeded_issuer() {
        let m = MockRegistryClient::new();
        m.set_recognised("did:webvh:peer.example.com:abc").await;
        assert!(m.recognise("did:webvh:peer.example.com:abc").await.unwrap());
        // Unseeded DID returns false (clean not-found).
        assert!(!m.recognise("did:webvh:stranger.example").await.unwrap());
        assert_eq!(m.call_counts().await.recognise, 2);
    }

    #[tokio::test]
    async fn recognise_propagates_transport_errors() {
        let m = MockRegistryClient::new();
        m.fail_next_recognise(RegistryError::Unreachable("dns".into()))
            .await;
        let err = m
            .recognise("did:webvh:peer.example")
            .await
            .expect_err("queued error must surface");
        assert!(err.is_retriable());
    }

    #[test]
    fn registry_error_retriable_classification() {
        assert!(RegistryError::Transient("x".into()).is_retriable());
        assert!(RegistryError::Unreachable("x".into()).is_retriable());
        assert!(!RegistryError::Permanent("x".into()).is_retriable());
    }

    #[test]
    fn registry_error_maps_to_typed_http_status() {
        use axum::http::StatusCode;
        use vti_common::error::AppError;

        let status = |e: RegistryError| match AppError::from(e) {
            AppError::ServiceError { status, .. } => status,
            other => panic!("expected ServiceError, got {other:?}"),
        };
        // Retriable failures → 503 (try again later), never an opaque 500.
        assert_eq!(
            status(RegistryError::Transient("x".into())),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status(RegistryError::Unreachable("x".into())),
            StatusCode::SERVICE_UNAVAILABLE
        );
        // A registry that rejected the request shape → 502 (upstream fault).
        assert_eq!(
            status(RegistryError::Permanent("x".into())),
            StatusCode::BAD_GATEWAY
        );
    }
}
