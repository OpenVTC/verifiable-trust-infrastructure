//! Persistent idempotency cache: `(principal, key) → CacheEntry`.

use std::net::IpAddr;

use axum::extract::ConnectInfo;
use axum::http::request::Parts;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::class::IdempotencyClass;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Identifier scoping the idempotency cache. **Never plaintext on
/// disk** — the principal bytes are hashed and the hash becomes part
/// of the storage key. Different principals therefore inhabit
/// disjoint namespaces.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Principal {
    /// Authenticated request — principal is the bearer credential
    /// itself (hashed at storage time, never persisted in the clear).
    /// Different tokens are different principals; token rotation
    /// resets the cache namespace (conservatively).
    AuthToken(Vec<u8>),
    /// Unauthenticated request scoped to the source IP. Phase-0
    /// unauth surfaces are `/v1/join-requests` and `/v1/install/*`;
    /// the IP-scoping prevents one IP's idempotent retry returning
    /// another IP's cached response.
    Ip(IpAddr),
    /// Authenticated request scoped to the caller's **DID**.
    ///
    /// Preferred over [`Principal::AuthToken`] wherever the DID is known,
    /// for two reasons. It survives token rotation, so a retry that
    /// straddles a refresh still lands in the same namespace — with the
    /// token as the principal, rotating mid-retry silently starts a fresh
    /// cache and re-runs the operation, which is the failure the cache
    /// exists to prevent. And it is the *only* identity the DIDComm and
    /// TSP transports have: neither carries a bearer token, so a
    /// Trust-Task caller on either transport would otherwise collapse to
    /// [`Principal::Anonymous`] and share a namespace with every other
    /// caller.
    Did(String),
    /// Fallback when neither Authorization nor `ConnectInfo` is
    /// available (e.g. unit tests). Cache is effectively shared
    /// across anonymous callers — acceptable because no Phase-0
    /// production path lacks both signals.
    Anonymous,
}

impl Principal {
    /// 32-byte hash of the principal — the actual cache namespace.
    /// Stable across calls; equal `Principal`s hash to equal bytes.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        match self {
            Principal::AuthToken(bytes) => {
                hasher.update(b"auth-token:");
                hasher.update(bytes);
            }
            Principal::Did(did) => {
                hasher.update(b"did:");
                hasher.update(did.as_bytes());
            }
            Principal::Ip(ip) => {
                hasher.update(b"ip:");
                hasher.update(ip.to_string().as_bytes());
            }
            Principal::Anonymous => {
                hasher.update(b"anonymous");
            }
        }
        hasher.finalize().into()
    }
}

/// Derive a [`Principal`] from request parts.
///
/// Prefers the Authorization header (hashed) when present, falls
/// back to `ConnectInfo<SocketAddr>` (which Axum populates from
/// `into_make_service_with_connect_info`), and finally to
/// [`Principal::Anonymous`].
///
/// Public so a service can inspect / log the principal without
/// re-implementing the precedence.
pub fn principal_from_request(parts: &Parts) -> Principal {
    if let Some(auth) = parts.headers.get(axum::http::header::AUTHORIZATION) {
        return Principal::AuthToken(auth.as_bytes().to_vec());
    }
    if let Some(ConnectInfo(addr)) = parts.extensions.get::<ConnectInfo<std::net::SocketAddr>>() {
        return Principal::Ip(addr.ip());
    }
    Principal::Anonymous
}

// ---------------------------------------------------------------------------
// Cache entry
// ---------------------------------------------------------------------------

/// What stage of its life a [`CacheEntry`] is in.
///
/// The HTTP middleware only ever writes [`EntryState::Completed`], which is
/// why that is the serde default: a record written before this enum existed
/// reads back as a completed one, unchanged.
///
/// The other two variants exist for callers that claim a key *before* running
/// the operation — see [`IdempotencyStore::claim`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EntryState {
    /// Claimed, but the outcome is not known yet — the first attempt is still
    /// running. A concurrent attempt seeing this must wait, not proceed.
    InFlight,
    /// Finished. The response fields hold the original response verbatim.
    #[default]
    Completed,
    /// Finished, and the response deliberately **not** retained — because it
    /// carried secret material, or exceeded the caller's size cap. The effect
    /// is still deduplicated; only the replay is unavailable, and a caller
    /// seeing this should say so rather than answer with an empty body.
    CompletedNotRetained,
}

/// Persisted cache record. The response is held in full so a retry
/// reproduces every header + body byte the original delivered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    /// Which stage this record is in. Defaults to [`EntryState::Completed`]
    /// so records written by the HTTP middleware — which has no in-flight
    /// stage — deserialize unchanged.
    #[serde(default)]
    pub state: EntryState,
    pub idempotency_key: String,
    /// SHA-256 over the request body. Differing hashes for the same
    /// `(principal, key)` cause [`AppError::IdempotencyKeyConflict`].
    pub request_hash: [u8; 32],
    pub response_status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Vec<u8>,
    pub class: IdempotencyClass,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl CacheEntry {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    /// Whether the outcome is still unknown.
    pub fn is_in_flight(&self) -> bool {
        self.state == EntryState::InFlight
    }

    /// Whether [`Self::response_body`] holds the original response.
    ///
    /// False for an in-flight claim (no outcome yet) and for a deliberately
    /// unretained one — in both cases the body field is empty, and answering
    /// a retry with it would be answering with a lie.
    pub fn has_replayable_response(&self) -> bool {
        self.state == EntryState::Completed
    }
}

// ---------------------------------------------------------------------------
// IdempotencyStore
// ---------------------------------------------------------------------------

/// Wraps an `idempotency` keyspace. Cheap to clone — the underlying
/// keyspace handle is `Arc`-shared.
#[derive(Clone)]
pub struct IdempotencyStore {
    ks: KeyspaceHandle,
}

impl IdempotencyStore {
    pub fn new(ks: KeyspaceHandle) -> Self {
        Self { ks }
    }

    /// Look up an existing entry. **Expired entries are treated as
    /// absent** so a long-stale cached response is never served, even
    /// if a background sweeper hasn't yet reclaimed the disk space.
    pub async fn get(
        &self,
        principal_hash: &[u8; 32],
        key: &str,
    ) -> Result<Option<CacheEntry>, AppError> {
        let storage_key = storage_key(principal_hash, key);
        let entry: Option<CacheEntry> = self.ks.get(storage_key).await?;
        let now = Utc::now();
        Ok(entry.filter(|e| !e.is_expired(now)))
    }

    /// Insert or replace a cache entry. Caller is responsible for
    /// setting `expires_at = created_at + class.ttl_seconds()`.
    pub async fn put(&self, principal_hash: &[u8; 32], entry: &CacheEntry) -> Result<(), AppError> {
        let storage_key = storage_key(principal_hash, &entry.idempotency_key);
        self.ks.insert(storage_key, entry).await
    }

    /// Claim `(principal, key)` **before** running the operation.
    ///
    /// This is the difference between deduplicating a *finished* request and
    /// deduplicating a request at all. [`Self::get`] followed by
    /// [`Self::put`] leaves a window: two concurrent attempts both read
    /// `None`, both run, and both produce the effect the cache exists to
    /// prevent. Claiming closes it — the write is `insert_if_absent`, so
    /// exactly one attempt wins and the other is told to wait.
    ///
    /// It also survives a crash. An attempt that dies between claiming and
    /// completing leaves an [`EntryState::InFlight`] record, which
    /// [`ClaimOutcome`] reports as stale once `in_flight_grace` has passed so
    /// the retry can reclaim it rather than being blocked forever.
    ///
    /// The caller must finish with [`Self::complete`] or [`Self::release`];
    /// a claim left dangling blocks retries until it goes stale.
    pub async fn claim(
        &self,
        principal_hash: &[u8; 32],
        key: &str,
        request_hash: [u8; 32],
        class: IdempotencyClass,
        in_flight_grace: chrono::Duration,
    ) -> Result<ClaimOutcome, AppError> {
        let now = Utc::now();
        let pending = CacheEntry {
            state: EntryState::InFlight,
            idempotency_key: key.to_string(),
            request_hash,
            response_status: 0,
            response_headers: Vec::new(),
            response_body: Vec::new(),
            class,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(class.ttl_seconds() as i64),
        };
        let sk = storage_key(principal_hash, key);

        if self.ks.insert_if_absent(sk.clone(), &pending).await? {
            return Ok(ClaimOutcome::Claimed);
        }

        let Some(existing): Option<CacheEntry> = self.ks.get(sk.clone()).await? else {
            // Raced the sweeper, or another attempt completing and being
            // reclaimed. Nothing holds the key now.
            self.ks.insert(sk, &pending).await?;
            return Ok(ClaimOutcome::Claimed);
        };

        if existing.is_expired(now) {
            self.ks.insert(sk, &pending).await?;
            return Ok(ClaimOutcome::Claimed);
        }

        // Checked before the in-flight branch: a mismatched body is a caller
        // error whichever stage the first attempt is in, and reporting "wait
        // and try again" to a request that will never be accepted would send
        // the caller round a loop it cannot exit.
        if existing.request_hash != request_hash {
            return Ok(ClaimOutcome::Conflict);
        }

        if existing.is_in_flight() {
            if now - existing.created_at > in_flight_grace {
                // The claiming attempt cannot still be running; it died.
                self.ks.insert(sk, &pending).await?;
                return Ok(ClaimOutcome::Claimed);
            }
            return Ok(ClaimOutcome::InFlight);
        }

        Ok(ClaimOutcome::Completed(Box::new(existing)))
    }

    /// Record the outcome of a claimed key.
    ///
    /// `response` is `None` when the body must not be retained — a
    /// secret-bearing or oversized response. The record still marks the
    /// operation done, so the duplicate effect is still prevented; only the
    /// replay is given up, and [`EntryState::CompletedNotRetained`] says so
    /// explicitly rather than leaving an empty body to be misread as one.
    pub async fn complete(
        &self,
        principal_hash: &[u8; 32],
        key: &str,
        response: Option<CompletedResponse>,
    ) -> Result<(), AppError> {
        let sk = storage_key(principal_hash, key);
        let Some(mut entry): Option<CacheEntry> = self.ks.get(sk.clone()).await? else {
            // The claim went away underneath us. Nothing to complete, and
            // writing a fresh record here would resurrect a key the sweeper
            // (or a reclaim) deliberately dropped.
            return Ok(());
        };
        match response {
            Some(r) => {
                entry.state = EntryState::Completed;
                entry.response_status = r.status;
                entry.response_headers = r.headers;
                entry.response_body = r.body;
            }
            None => {
                entry.state = EntryState::CompletedNotRetained;
                entry.response_status = 0;
                entry.response_headers = Vec::new();
                entry.response_body = Vec::new();
            }
        }
        self.ks.insert(sk, &entry).await
    }

    /// Drop a claim without recording an outcome.
    ///
    /// For the case where the operation *failed*: the effect never happened,
    /// so a retry should be allowed to actually run rather than be answered
    /// with the failure. Caching failures would turn one transient error into
    /// a sticky one for the lifetime of the record.
    pub async fn release(&self, principal_hash: &[u8; 32], key: &str) -> Result<(), AppError> {
        self.ks.remove(storage_key(principal_hash, key)).await
    }
}

/// The response fields to record against a completed claim.
#[derive(Debug, Clone)]
pub struct CompletedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// What [`IdempotencyStore::claim`] found.
#[derive(Debug)]
pub enum ClaimOutcome {
    /// The key is ours. Run the operation, then `complete` or `release`.
    Claimed,
    /// An attempt with the same request is still running. Answer "try again"
    /// — not "duplicate", because at this instant nobody knows the outcome.
    InFlight,
    /// The request already ran. Replay it if
    /// [`CacheEntry::has_replayable_response`], otherwise say it happened and
    /// the result is not retained.
    Completed(Box<CacheEntry>),
    /// This key was already used for a *different* request. Answering it with
    /// the first request's result would be answering the wrong question.
    Conflict,
}

fn storage_key(principal_hash: &[u8; 32], key: &str) -> Vec<u8> {
    // Hex-encode the principal hash so the resulting fjall key stays
    // ASCII for grepping during debugging. Newlines / NUL bytes are
    // rejected upstream by the idempotency middleware's header
    // validation, so the unencoded `key` part is safe to embed
    // directly.
    let mut out = Vec::with_capacity(64 + key.len() + 5);
    out.extend_from_slice(b"idem:");
    out.extend_from_slice(hex::encode(principal_hash).as_bytes());
    out.push(b':');
    out.extend_from_slice(key.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;
    use chrono::Duration;

    fn temp_store() -> (IdempotencyStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&cfg).expect("store");
        let ks = store.keyspace("idempotency-test").expect("ks");
        (IdempotencyStore::new(ks), dir)
    }

    fn sample_entry() -> CacheEntry {
        let now = Utc::now();
        CacheEntry {
            state: EntryState::Completed,
            idempotency_key: "key-1".into(),
            request_hash: [0xAB; 32],
            response_status: 201,
            response_headers: vec![("content-type".into(), "application/json".into())],
            response_body: br#"{"ok":true}"#.to_vec(),
            class: IdempotencyClass::NonDestructive,
            created_at: now,
            expires_at: now
                + Duration::seconds(IdempotencyClass::NonDestructive.ttl_seconds() as i64),
        }
    }

    #[test]
    fn principal_hash_is_stable_and_distinct_across_kinds() {
        let a = Principal::AuthToken(b"Bearer abc".to_vec());
        let a_again = Principal::AuthToken(b"Bearer abc".to_vec());
        let b = Principal::AuthToken(b"Bearer xyz".to_vec());
        let ip = Principal::Ip(IpAddr::V4("127.0.0.1".parse().unwrap()));
        let anon = Principal::Anonymous;

        assert_eq!(a.hash(), a_again.hash());
        assert_ne!(a.hash(), b.hash());
        assert_ne!(a.hash(), ip.hash());
        assert_ne!(a.hash(), anon.hash());
        assert_ne!(ip.hash(), anon.hash());
    }

    #[tokio::test]
    async fn put_then_get_returns_entry() {
        let (store, _dir) = temp_store();
        let principal = Principal::AuthToken(b"Bearer t".to_vec()).hash();
        let entry = sample_entry();

        store.put(&principal, &entry).await.unwrap();
        let got = store.get(&principal, &entry.idempotency_key).await.unwrap();
        assert_eq!(got.as_ref(), Some(&entry));
    }

    #[tokio::test]
    async fn entries_are_scoped_by_principal() {
        let (store, _dir) = temp_store();
        let a = Principal::AuthToken(b"alice".to_vec()).hash();
        let b = Principal::AuthToken(b"bob".to_vec()).hash();
        let entry = sample_entry();

        store.put(&a, &entry).await.unwrap();
        let got_a = store.get(&a, &entry.idempotency_key).await.unwrap();
        let got_b = store.get(&b, &entry.idempotency_key).await.unwrap();
        assert!(got_a.is_some());
        assert!(got_b.is_none(), "principal scoping leaked");
    }

    const GRACE: chrono::Duration = chrono::Duration::minutes(10);

    /// The property `get` + `put` cannot provide: two concurrent attempts, one
    /// winner. Without this, both read `None` and both run the operation.
    #[tokio::test]
    async fn a_second_claim_on_the_same_request_does_not_also_win() {
        let (store, _d) = temp_store();
        let p = Principal::Did("did:web:alice".into()).hash();

        let first = store
            .claim(&p, "k", [1u8; 32], IdempotencyClass::NonDestructive, GRACE)
            .await
            .expect("claim");
        assert!(matches!(first, ClaimOutcome::Claimed));

        let second = store
            .claim(&p, "k", [1u8; 32], IdempotencyClass::NonDestructive, GRACE)
            .await
            .expect("claim");
        assert!(
            matches!(second, ClaimOutcome::InFlight),
            "a concurrent attempt must be told to wait, got {second:?}"
        );
    }

    #[tokio::test]
    async fn a_completed_claim_replays_its_response() {
        let (store, _d) = temp_store();
        let p = Principal::Did("did:web:alice".into()).hash();
        store
            .claim(&p, "k", [1u8; 32], IdempotencyClass::NonDestructive, GRACE)
            .await
            .expect("claim");
        store
            .complete(
                &p,
                "k",
                Some(CompletedResponse {
                    status: 201,
                    headers: vec![],
                    body: b"body".to_vec(),
                }),
            )
            .await
            .expect("complete");

        match store
            .claim(&p, "k", [1u8; 32], IdempotencyClass::NonDestructive, GRACE)
            .await
            .expect("claim")
        {
            ClaimOutcome::Completed(e) => {
                assert!(e.has_replayable_response());
                assert_eq!(e.response_status, 201);
                assert_eq!(e.response_body, b"body".to_vec());
            }
            other => panic!("expected a completed replay, got {other:?}"),
        }
    }

    /// The secret-bearing case: the effect is still deduplicated, but the
    /// record must not be mistaken for a real empty response.
    #[tokio::test]
    async fn an_unretained_completion_dedups_without_offering_a_body() {
        let (store, _d) = temp_store();
        let p = Principal::Did("did:web:alice".into()).hash();
        store
            .claim(&p, "k", [1u8; 32], IdempotencyClass::NonDestructive, GRACE)
            .await
            .expect("claim");
        store.complete(&p, "k", None).await.expect("complete");

        match store
            .claim(&p, "k", [1u8; 32], IdempotencyClass::NonDestructive, GRACE)
            .await
            .expect("claim")
        {
            ClaimOutcome::Completed(e) => {
                assert_eq!(e.state, EntryState::CompletedNotRetained);
                assert!(!e.has_replayable_response());
                assert!(e.response_body.is_empty());
            }
            other => panic!("expected a completed record, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_same_key_with_a_different_request_conflicts() {
        let (store, _d) = temp_store();
        let p = Principal::Did("did:web:alice".into()).hash();
        store
            .claim(&p, "k", [1u8; 32], IdempotencyClass::NonDestructive, GRACE)
            .await
            .expect("claim");
        let other = store
            .claim(&p, "k", [2u8; 32], IdempotencyClass::NonDestructive, GRACE)
            .await
            .expect("claim");
        assert!(
            matches!(other, ClaimOutcome::Conflict),
            "a different body under the same key must conflict, got {other:?}"
        );
    }

    /// A mismatched body conflicts even while the first attempt is still
    /// running — telling that caller to "try again" would loop it forever on a
    /// request that can never be accepted.
    #[tokio::test]
    async fn conflict_is_reported_ahead_of_in_flight() {
        let (store, _d) = temp_store();
        let p = Principal::Did("did:web:alice".into()).hash();
        store
            .claim(&p, "k", [1u8; 32], IdempotencyClass::NonDestructive, GRACE)
            .await
            .expect("claim");
        // First attempt deliberately left in flight.
        let other = store
            .claim(&p, "k", [9u8; 32], IdempotencyClass::NonDestructive, GRACE)
            .await
            .expect("claim");
        assert!(matches!(other, ClaimOutcome::Conflict), "got {other:?}");
    }

    /// A process that dies between claiming and completing must not block the
    /// retry that would recover it.
    #[tokio::test]
    async fn a_stale_in_flight_claim_is_reclaimed() {
        let (store, _d) = temp_store();
        let p = Principal::Did("did:web:alice".into()).hash();
        store
            .claim(&p, "k", [1u8; 32], IdempotencyClass::NonDestructive, GRACE)
            .await
            .expect("claim");
        // Zero grace: any in-flight claim is already stale.
        let again = store
            .claim(
                &p,
                "k",
                [1u8; 32],
                IdempotencyClass::NonDestructive,
                chrono::Duration::zero(),
            )
            .await
            .expect("claim");
        assert!(matches!(again, ClaimOutcome::Claimed), "got {again:?}");
    }

    /// A failed operation releases its key, so the retry actually runs rather
    /// than being answered with a cached failure.
    #[tokio::test]
    async fn releasing_a_claim_frees_the_key() {
        let (store, _d) = temp_store();
        let p = Principal::Did("did:web:alice".into()).hash();
        store
            .claim(&p, "k", [1u8; 32], IdempotencyClass::NonDestructive, GRACE)
            .await
            .expect("claim");
        store.release(&p, "k").await.expect("release");
        let again = store
            .claim(&p, "k", [1u8; 32], IdempotencyClass::NonDestructive, GRACE)
            .await
            .expect("claim");
        assert!(matches!(again, ClaimOutcome::Claimed), "got {again:?}");
    }

    #[tokio::test]
    async fn claims_are_scoped_by_principal() {
        let (store, _d) = temp_store();
        let alice = Principal::Did("did:web:alice".into()).hash();
        let bob = Principal::Did("did:web:bob".into()).hash();
        store
            .claim(
                &alice,
                "k",
                [1u8; 32],
                IdempotencyClass::NonDestructive,
                GRACE,
            )
            .await
            .expect("claim");
        let bobs = store
            .claim(
                &bob,
                "k",
                [1u8; 32],
                IdempotencyClass::NonDestructive,
                GRACE,
            )
            .await
            .expect("claim");
        assert!(
            matches!(bobs, ClaimOutcome::Claimed),
            "one caller's key must not block another's, got {bobs:?}"
        );
    }

    /// A DID principal is stable across token rotation — the reason it exists.
    #[test]
    fn did_principals_are_distinct_and_stable() {
        let a = Principal::Did("did:web:alice".into());
        assert_eq!(a.hash(), Principal::Did("did:web:alice".into()).hash());
        assert_ne!(a.hash(), Principal::Did("did:web:bob".into()).hash());
        assert_ne!(
            a.hash(),
            Principal::AuthToken(b"did:web:alice".to_vec()).hash()
        );
    }

    /// Records written before `state` existed must still read as completed.
    #[test]
    fn a_record_without_a_state_member_reads_as_completed() {
        let json = serde_json::json!({
            "idempotency_key": "k",
            "request_hash": vec![0u8; 32],
            "response_status": 200,
            "response_headers": [],
            "response_body": [],
            "class": "NonDestructive",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2036-01-01T00:00:00Z",
        });
        let e: CacheEntry = serde_json::from_value(json).expect("legacy record decodes");
        assert_eq!(e.state, EntryState::Completed);
        assert!(e.has_replayable_response());
    }

    #[tokio::test]
    async fn expired_entries_are_filtered_at_read_time() {
        let (store, _dir) = temp_store();
        let principal = Principal::AuthToken(b"Bearer t".to_vec()).hash();
        let mut entry = sample_entry();
        entry.expires_at = Utc::now() - Duration::seconds(1);
        store.put(&principal, &entry).await.unwrap();

        let got = store.get(&principal, &entry.idempotency_key).await.unwrap();
        assert!(got.is_none(), "stale entry served");
    }

    #[tokio::test]
    async fn put_overwrites_existing_entry_under_same_key() {
        let (store, _dir) = temp_store();
        let principal = Principal::AuthToken(b"Bearer t".to_vec()).hash();
        let first = sample_entry();
        store.put(&principal, &first).await.unwrap();

        let mut second = first.clone();
        second.response_status = 204;
        second.response_body = b"updated".to_vec();
        store.put(&principal, &second).await.unwrap();

        let got = store.get(&principal, &first.idempotency_key).await.unwrap();
        assert_eq!(got.unwrap().response_status, 204);
    }
}
