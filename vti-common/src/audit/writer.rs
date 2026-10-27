//! [`AuditWriter`] — writes [`AuditEnvelope`]s using the active
//! audit_key for actor/target hashing, plus a `verify_actor` helper
//! that walks key history to confirm a candidate DID matches an
//! envelope's hash.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::sync::Mutex;
use uuid::Uuid;

use super::envelope::{AuditEnvelope, EVENT_VERSION, GENESIS_HASH, SCHEMA_VERSION};
use super::event::AuditEvent;
use super::key_store::AuditKeyStore;
use crate::error::AppError;
use crate::store::{KeyspaceHandle, RawKvPair, ScanOpts};

type HmacSha256 = Hmac<Sha256>;

/// How many of the newest rows chain-head recovery reads before falling back
/// to the deep scan below.
///
/// **The number is not load-bearing.** On a running log the newest row is
/// already an envelope, so one row would usually do; the window is slack for
/// the few non-envelope rows that can sort above it — a VTC's keyspace holds
/// rows whose keys outrank an RFC 3339 timestamp, and a VTA mid-migration has
/// pre-chain rows about. Because the deep scan stands behind it, choosing this
/// too small costs an extra page, never a wrong answer, which is why 20 rather
/// than the 8 first proposed is not a decision anyone needs to defend. Keep it
/// small enough that the read stays trivial on every restart.
const HEAD_LOOKBACK: usize = 20;

/// How long a failed recovery is answered from the cached failure before one
/// more attempt is made.
///
/// Long enough that a busy node does not re-read storage per audited
/// operation while it is broken, short enough that fixing the cause (a
/// restarted storage proxy) takes effect without restarting the node.
const HEAD_RECOVERY_RETRY_BACKOFF: Duration = Duration::from_secs(60);

/// Page size for the deep-scan fallback below — bounded per request so a
/// single page still respects the vsock frame cap, same as `HEAD_LOOKBACK`.
///
/// The deep scan has a page size but no row cap. It walks until it finds an
/// envelope or reaches the end of the prefix, because every answer short of
/// the end is wrong: stopping and anchoring at genesis forks the chain if an
/// envelope lies further back, and stopping and failing closed refuses every
/// audit write to the prefix with nothing that could ever clear it (no write
/// succeeds, so the next attempt walks the same rows). A legacy log larger
/// than a fixed cap is ordinary — one row per audited operation over the
/// retention window — so the cap would turn an upgrade into a lost audit
/// trail. The walk's cost is bounded by the prefix and paid once: the
/// envelope it lets the next write anchor is found by every later restart's
/// `HEAD_LOOKBACK` read.
const DEEP_SCAN_PAGE: usize = 500;

/// Counter incremented once per failed chain-head recovery.
///
/// Recovery fails only when the scan itself fails — storage unreachable, a
/// response too large for one frame, a value that would not decrypt — and by
/// the time this fires every audit write to that prefix is failing closed.
/// Nothing else makes that visible from outside the log itself.
pub const AUDIT_CHAIN_RECOVERY_FAILURES: &str = "audit_chain_recovery_failures_total";

#[derive(Clone)]
enum ChainHeadState {
    Unknown,
    Known([u8; 32]),
    /// Recovery failed at `since`; `cause` is the failure rendered whole
    /// (`store error: …`), quoted by the refusals during the backoff.
    Failed {
        since: Instant,
        cause: String,
    },
}

/// Computes the envelope key (`<rfc3339-timestamp>:<event_id>`) so a
/// prefix-iter scan walks rows in time order. Visible to other
/// modules for migration helpers.
pub fn envelope_storage_key(env: &AuditEnvelope) -> Vec<u8> {
    format!("{}:{}", env.timestamp.to_rfc3339(), env.event_id).into_bytes()
}

/// Persistent writer that combines an `audit` keyspace with the
/// matching [`AuditKeyStore`]. Cheap to clone — every field is
/// reference-counted internally.
///
/// Production constructs exactly one writer (held in `AppState` and
/// cloned), so the shared `chain_head` below serialises every audit
/// write process-wide: each envelope's `prev_hash` is the
/// immediately-preceding envelope's `entry_hash`, forming the
/// tamper-evidence chain verified by
/// [`super::envelope::verify_chain`].
#[derive(Clone)]
pub struct AuditWriter {
    audit_ks: KeyspaceHandle,
    key_store: AuditKeyStore,
    /// How an envelope is keyed in the audit keyspace.
    ///
    /// Configurable because a keyspace that already holds rows has an
    /// ordering, and a writer that ignores it produces a log whose newest
    /// entry is not the last one — which breaks both chain-head recovery and
    /// every reader that pages in key order. A VTA's audit keyspace is such a
    /// keyspace: it holds `log:<zero-padded-epoch>:<uuid>` rows written before
    /// chaining existed, and those sort after an RFC 3339 timestamp.
    ///
    /// [`envelope_storage_key`] is the default and the only one a fresh
    /// keyspace needs.
    storage_key: Arc<dyn Fn(&AuditEnvelope) -> Vec<u8> + Send + Sync>,
    /// Restricts chain-head recovery to the rows written by this writer.
    /// Empty keeps the default whole-keyspace behavior used by VTC.
    key_prefix: Vec<u8>,
    /// Page size for the deep-scan fallback. See [`DEEP_SCAN_PAGE`] for the
    /// production default and `AuditWriter::with_deep_scan_page` for why
    /// tests override it.
    deep_scan_page: usize,
    /// Cached `entry_hash` of the last-written envelope (the chain
    /// head). `None` until the first write loads it from storage
    /// (restart recovery). Guarded by an async mutex so the
    /// read-head → stamp → insert → update-head sequence is atomic
    /// across concurrent writers.
    chain_head: Arc<Mutex<ChainHeadState>>,
}

impl AuditWriter {
    pub fn new(audit_ks: KeyspaceHandle, key_store: AuditKeyStore) -> Self {
        Self {
            audit_ks,
            key_store,
            storage_key: Arc::new(envelope_storage_key),
            key_prefix: Vec::new(),
            deep_scan_page: DEEP_SCAN_PAGE,
            chain_head: Arc::new(Mutex::new(ChainHeadState::Unknown)),
        }
    }

    /// Key envelopes with `f` rather than [`envelope_storage_key`].
    ///
    /// The function must order envelopes by write time, because chain-head
    /// recovery reads the last key in ascending order and expects the most
    /// recent envelope. A key that does not sort by time silently anchors new
    /// writes to the wrong predecessor.
    #[must_use]
    pub fn with_storage_key(
        mut self,
        f: impl Fn(&AuditEnvelope) -> Vec<u8> + Send + Sync + 'static,
    ) -> Self {
        self.storage_key = Arc::new(f);
        self
    }

    /// Restrict chain-head recovery to keys beginning with `prefix`.
    ///
    /// **The prefix must match what [`Self::with_storage_key`] emits**, and
    /// the two are checked against each other nowhere. A prefix no envelope
    /// key begins with makes recovery scan an empty range, find nothing,
    /// conclude the prefix holds no chain, and anchor the next write at
    /// [`GENESIS_HASH`] — forking the chain as quietly as a storage key that
    /// does not sort by time does. Same failure, same silence; set them
    /// together.
    ///
    /// The default is empty, meaning the whole keyspace, which is what a
    /// keyspace holding nothing but envelopes wants. A VTA passes `log:`
    /// because its audit keyspace also holds `prune:watermark`, which sorts
    /// after every envelope and would otherwise be read as the newest row.
    #[must_use]
    pub fn with_key_prefix(mut self, prefix: impl Into<Vec<u8>>) -> Self {
        self.key_prefix = prefix.into();
        self
    }

    /// Override the deep-scan page size used by [`Self::load_chain_head`].
    ///
    /// Test-only: a small page lets a test walk many pages (or prove a page
    /// shorter than requested means the prefix has ended) without writing
    /// hundreds of rows per page.
    #[cfg(test)]
    #[must_use]
    fn with_deep_scan_page(mut self, page: usize) -> Self {
        self.deep_scan_page = page;
        self
    }

    /// Return the currently-active audit key. Callers that need to
    /// sign a pagination cursor (or run any other HMAC operation
    /// tied to the per-community audit epoch) use this rather than
    /// reaching into the key store directly.
    pub async fn active_key(&self) -> Result<crate::audit::AuditKey, AppError> {
        self.key_store.active().await
    }

    /// Write an audit event. Hashes `actor_did` (mandatory) and
    /// `target_did` (optional) under the currently-active key,
    /// returns the persisted envelope so callers can echo the
    /// `event_id` back to their handlers.
    ///
    /// The `actor_did` is stored both as its HMAC hash and as
    /// plaintext (for normal queries); RTBF code paths null the
    /// plaintext separately, leaving the hash + envelope in place.
    pub async fn write(
        &self,
        actor_did: &str,
        target_did: Option<&str>,
        event: AuditEvent,
    ) -> Result<AuditEnvelope, AppError> {
        let key = self.key_store.active().await?;

        let actor_did_hash = hmac_did(&key.key, actor_did);
        let target_did_hash = target_did.map(|d| hmac_did(&key.key, d));

        // Hold the chain lock across the whole read-head → stamp →
        // insert → update-head sequence so concurrent writers can't
        // fork the chain (two envelopes sharing one `prev_hash`).
        //
        // A deliberate exception to "no lock across an await": releasing it to
        // recover would let two writers recover and anchor concurrently, which
        // is the fork this lock exists to prevent. The cost is that a first
        // write needing the deep scan holds it for one storage round trip per
        // `DEEP_SCAN_PAGE` legacy rows, blocking every other audit write
        // meanwhile. Once per process, and only during the legacy-to-chained
        // migration window — the steady state is one bounded read, and
        // thereafter a cache hit.
        let mut head = self.chain_head.lock().await;
        let current_state = head.clone();
        let prev_hash = match current_state {
            ChainHeadState::Known(hash) => hash,
            ChainHeadState::Unknown => self.recover_chain_head(&mut head).await?,
            ChainHeadState::Failed { since, cause } => {
                if since.elapsed() < HEAD_RECOVERY_RETRY_BACKOFF {
                    return Err(AppError::Internal(format!(
                        "audit chain head unavailable: {cause}"
                    )));
                }
                self.recover_chain_head(&mut head).await?
            }
        };

        let mut envelope = AuditEnvelope {
            event_id: Uuid::new_v4(),
            event_version: EVENT_VERSION,
            schema_version: SCHEMA_VERSION,
            timestamp: Utc::now(),
            audit_key_id: key.key_id,
            actor_did_hash,
            actor_did_plain: Some(actor_did.to_string()),
            target_did_hash,
            target_did_plain: target_did.map(str::to_string),
            prev_hash,
            entry_hash: GENESIS_HASH, // placeholder; stamped next
            event,
        };
        envelope.entry_hash = envelope.chain_digest();

        self.audit_ks
            .insert((self.storage_key)(&envelope), &envelope)
            .await?;
        *head = ChainHeadState::Known(envelope.entry_hash);
        Ok(envelope)
    }

    async fn recover_chain_head(&self, state: &mut ChainHeadState) -> Result<[u8; 32], AppError> {
        match self.load_chain_head().await {
            Ok(hash) => {
                *state = ChainHeadState::Known(hash);
                Ok(hash)
            }
            Err(error) => {
                // The one place a recovery failure is counted, so none can be
                // missed and none double-counted: every path out of
                // `load_chain_head` arrives here exactly once.
                metrics::counter!(AUDIT_CHAIN_RECOVERY_FAILURES).increment(1);
                let cause = error.to_string();
                tracing::error!(
                    target: "audit.chain_recovery",
                    error = %error,
                    retry_after_secs = HEAD_RECOVERY_RETRY_BACKOFF.as_secs(),
                    "audit chain head recovery failed"
                );
                *state = ChainHeadState::Failed {
                    since: Instant::now(),
                    cause,
                };
                Err(error)
            }
        }
    }

    /// Recover the chain head from storage on the first write after a
    /// (re)start. The last pair in ascending key order is the most recently
    /// written envelope; its `entry_hash` is the head. The VTA supplies the
    /// `log:` prefix, which includes both pre-v2 `log:<seconds>:<uuid>` rows
    /// and chained `log:<seconds>:<nanos>:<uuid>` rows; VTC keeps the empty
    /// prefix for its default `<rfc3339-timestamp>:<event_id>` keys. An empty
    /// (or pre-v2) log anchors at [`GENESIS_HASH`].
    ///
    /// The fast path scans only the newest `HEAD_LOOKBACK` rows, which is all
    /// a prefix that has ever anchored a chain needs: that first envelope is
    /// permanent, so it is always within the lookback window of every later
    /// restart. A prefix that has *not* anchored yet — a legacy log mid
    /// migration — can have an arbitrary number of pre-chain rows newer than
    /// the window, and wrongly reading that as "nothing here, anchor at
    /// genesis" risks forking the chain if an envelope does exist further
    /// back; wrongly reading it as "fail closed" bricks every future write to
    /// this prefix forever, because no write ever succeeds to clear the
    /// condition. So when the fast path is inconclusive, page further back
    /// (bounded per request, to respect the vsock frame cap, but not in
    /// total — see [`DEEP_SCAN_PAGE`]) until either an envelope turns up or
    /// the prefix ends. This deep scan only runs during that one-time
    /// migration window: the envelope the next write anchors is found by
    /// every later restart's fast path in O(`HEAD_LOOKBACK`).
    ///
    /// The only failure is a failed read.
    async fn load_chain_head(&self) -> Result<[u8; 32], AppError> {
        let pairs = self
            .audit_ks
            .scan_raw(ScanOpts::newest_first(
                self.key_prefix.clone(),
                HEAD_LOOKBACK,
            ))
            .await?;

        if let Some(hash) = newest_envelope_hash(&pairs) {
            return Ok(hash);
        }

        if pairs.len() < HEAD_LOOKBACK {
            // Fewer rows than the fast-path window: there is nothing older
            // left to find, so this prefix is empty or entirely legacy.
            return Ok(GENESIS_HASH);
        }

        // `Box::pin` rather than a bare `.await`: this fallback is only ever
        // taken during the one-time legacy-migration window (see the doc
        // comment above), but the compiler still has to size *this* function's
        // state machine for the largest future it can await, branch taken or
        // not. Inlining `deep_scan_for_chain_head`'s loop (with its page
        // buffers and cursor) into every `load_chain_head` call — which is to
        // say every first `write()` after a restart, on the hot context/task
        // dispatch spine — blew the pinned 512 KiB worker-stack budget
        // (`vti_08_context_create_fits_half_a_default_worker_stack`). Boxing
        // puts the large, rarely-used half on the heap and leaves a
        // pointer-sized slot in the common-path state machine instead.
        Box::pin(self.deep_scan_for_chain_head(pairs)).await
    }

    /// Fallback for [`Self::load_chain_head`] when the fast-path window is
    /// entirely non-envelope rows but the prefix holds more rows below it.
    /// Pages backward until an envelope is found or the prefix runs out.
    async fn deep_scan_for_chain_head(
        &self,
        fast_path: Vec<RawKvPair>,
    ) -> Result<[u8; 32], AppError> {
        let mut cursor = fast_path.into_iter().next_back().map(|(key, _)| key);

        loop {
            let Some(after) = cursor.take() else {
                // No resume key: the fast-path window was itself the whole
                // prefix (shouldn't happen, since that implies
                // `pairs.len() < HEAD_LOOKBACK` above, but fail safe).
                return Ok(GENESIS_HASH);
            };

            let page = self
                .audit_ks
                .scan_raw(
                    ScanOpts::newest_first(self.key_prefix.clone(), self.deep_scan_page)
                        .after(after),
                )
                .await?;

            if let Some(hash) = newest_envelope_hash(&page) {
                return Ok(hash);
            }

            if page.len() < self.deep_scan_page {
                // Fewer rows than requested: this was the prefix's last page.
                return Ok(GENESIS_HASH);
            }
            cursor = page.into_iter().next_back().map(|(key, _)| key);
        }
    }

    /// Verify that `candidate_did` matches the actor recorded on
    /// `envelope`, even after the active key has rotated. Walks the
    /// `audit_key` history to find the key referenced by
    /// `envelope.audit_key_id`; an unknown id returns
    /// `Ok(false)` (the corresponding key was garbage-collected or
    /// the envelope is corrupt — either way the candidate does
    /// not match).
    pub async fn verify_actor(
        &self,
        envelope: &AuditEnvelope,
        candidate_did: &str,
    ) -> Result<bool, AppError> {
        let key = match self.key_store.fetch(&envelope.audit_key_id).await? {
            Some(k) => k,
            None => return Ok(false),
        };
        let recomputed = hmac_did(&key.key, candidate_did);
        Ok(constant_time_eq(&recomputed, &envelope.actor_did_hash))
    }

    /// Symmetric helper for the optional target DID.
    pub async fn verify_target(
        &self,
        envelope: &AuditEnvelope,
        candidate_did: &str,
    ) -> Result<bool, AppError> {
        let expected = match envelope.target_did_hash {
            Some(h) => h,
            None => return Ok(false),
        };
        let key = match self.key_store.fetch(&envelope.audit_key_id).await? {
            Some(k) => k,
            None => return Ok(false),
        };
        let recomputed = hmac_did(&key.key, candidate_did);
        Ok(constant_time_eq(&recomputed, &expected))
    }
}

/// Returns the `entry_hash` of the newest pair in `pairs` that deserializes
/// as an [`AuditEnvelope`], scanning in the slice's own (newest-first) order.
/// A value either is an envelope or is not — the key format belongs to the
/// caller, so deserialization is the test rather than the key.
fn newest_envelope_hash(pairs: &[RawKvPair]) -> Option<[u8; 32]> {
    pairs
        .iter()
        .find_map(|(_, raw)| serde_json::from_slice::<AuditEnvelope>(raw).ok())
        .map(|env| env.entry_hash)
}

fn hmac_did(key: &[u8; 32], did: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("32-byte HMAC key");
    mac.update(did.as_bytes());
    mac.finalize().into_bytes().into()
}

/// Constant-time comparison so a side-channel observer can't learn
/// match progress from response timing. `[u8; 32]` only.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::key_store::RotationReason;
    use crate::audit::verify_chain;
    use crate::config::StoreConfig;
    use crate::store::Store;

    struct Fixture {
        writer: AuditWriter,
        key_store: AuditKeyStore,
        _dir: tempfile::TempDir,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&cfg).expect("store");
        let audit_ks = store.keyspace("audit").expect("audit ks");
        let key_ks = store.keyspace("audit_key").expect("audit_key ks");
        let key_store = AuditKeyStore::new(key_ks);
        let writer = AuditWriter::new(audit_ks, key_store.clone());
        Fixture {
            writer,
            key_store,
            _dir: dir,
        }
    }

    fn sample_event() -> AuditEvent {
        AuditEvent::CommunityProfileUpdated(crate::audit::event::CommunityProfileUpdatedData {
            fields_changed: vec!["name".into()],
            ..Default::default()
        })
    }

    /// The VTA's audit keyspace holds rows written before this log was
    /// chained. Chain-head recovery reads the last key in ascending order, and
    /// those rows sort *after* an RFC 3339 timestamp, so the first chained
    /// write would otherwise try to read a pre-chain row as an envelope.
    #[tokio::test]
    async fn a_pre_chain_row_does_not_break_the_first_write() {
        let f = fixture();
        f.key_store.ensure_initial(&[0x01; 32]).await.unwrap();

        // A row in the shape a VTA wrote before chaining existed, keyed the
        // way a VTA keys them — which sorts after any RFC 3339 timestamp.
        f.writer
            .audit_ks
            .insert(
                b"log:00000000001700000000:11111111-1111-1111-1111-111111111111".to_vec(),
                &serde_json::json!({
                    "id": "11111111-1111-1111-1111-111111111111",
                    "timestamp": 1_700_000_000u64,
                    "action": "auth.challenge",
                    "actor": "did:key:z6MkLegacy",
                    "outcome": "success",
                }),
            )
            .await
            .expect("seed a pre-chain row");

        let env = f
            .writer
            .write("did:key:z6Mk", None, sample_event())
            .await
            .expect("a pre-chain row must not stop the first chained write");

        assert_eq!(
            env.prev_hash, GENESIS_HASH,
            "the first chained entry anchors at genesis, not at a row that predates the chain"
        );
    }

    #[tokio::test]
    async fn prefixed_recovery_ignores_rows_outside_the_log_prefix() {
        let f = fixture();
        f.key_store.ensure_initial(&[0x0a; 32]).await.unwrap();
        f.writer
            .audit_ks
            .insert(
                b"log:00000000001700000000:legacy".to_vec(),
                &serde_json::json!({
                    "id": "legacy",
                    "timestamp": 1_700_000_000u64,
                    "action": "auth.challenge",
                    "actor": "did:key:z6MkLegacy",
                    "outcome": "success",
                }),
            )
            .await
            .unwrap();
        f.writer
            .audit_ks
            .insert(
                b"prune:watermark".to_vec(),
                &serde_json::json!({
                    "head": "00",
                    "prunedEntries": 1,
                    "prunedAt": "2026-10-13T00:00:00Z",
                }),
            )
            .await
            .unwrap();

        let env = f
            .writer
            .clone()
            .with_key_prefix("log:")
            .write("did:key:z6Mk", None, sample_event())
            .await
            .unwrap();

        assert_eq!(env.prev_hash, GENESIS_HASH);
    }

    /// Run `body` with a metrics recorder installed on this thread, and
    /// return the total [`AUDIT_CHAIN_RECOVERY_FAILURES`] count it emitted.
    ///
    /// Thread-local rather than a global recorder, so tests running in
    /// parallel cannot see each other's counters. The runtime is built inside
    /// the closure for the same reason: `with_local_recorder`'s guard is tied
    /// to this thread, and a current-thread runtime keeps the whole future on
    /// it.
    #[cfg(feature = "encryption")]
    fn recovery_failures_during<F>(body: F) -> u64
    where
        F: std::future::Future<Output = ()>,
    {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(body);
        });

        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .filter(|(key, _, _, _)| key.key().name() == AUDIT_CHAIN_RECOVERY_FAILURES)
            .map(|(_, _, _, value)| match value {
                DebugValue::Counter(count) => count,
                other => panic!("{AUDIT_CHAIN_RECOVERY_FAILURES} is not a counter: {other:?}"),
            })
            .sum()
    }

    /// Seed `count` non-envelope rows under `log:`, the shape a pre-chain VTA
    /// log has.
    async fn seed_legacy_rows(writer: &AuditWriter, count: usize) {
        for index in 0..count {
            writer
                .audit_ks
                .insert(
                    format!("log:{index:020}:legacy"),
                    &serde_json::json!({
                        "id": format!("legacy-{index}"),
                        "timestamp": 1_700_000_000u64 + index as u64,
                        "action": "auth.challenge",
                        "actor": "did:key:z6MkLegacy",
                        "outcome": "success",
                    }),
                )
                .await
                .unwrap();
        }
    }

    /// A writer whose recovery read storage refuses: rows written in the
    /// clear, read back through a handle that insists on decrypting. The
    /// scan reaches storage and is refused by it, which is the shape of the
    /// real failures (an unreachable proxy, an oversized frame, a value that
    /// will not decrypt).
    #[cfg(feature = "encryption")]
    async fn writer_whose_recovery_read_fails() -> (AuditWriter, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        let plain_ks = store.keyspace("audit").expect("audit ks");
        let key_store = AuditKeyStore::new(store.keyspace("audit_key").expect("key ks"));
        key_store.ensure_initial(&[0x1b; 32]).await.unwrap();

        let seeding_writer = AuditWriter::new(plain_ks.clone(), key_store.clone());
        seed_legacy_rows(&seeding_writer, 3).await;

        let encrypted_ks = plain_ks.with_encryption([0x1c; 32]);
        let writer = AuditWriter::new(encrypted_ks, key_store).with_key_prefix("log:");
        (writer, dir)
    }

    /// A recovery that fails because the scan failed is counted once.
    #[cfg(feature = "encryption")]
    #[test]
    fn a_storage_failure_during_recovery_is_counted_once() {
        let count = recovery_failures_during(async {
            let (writer, _dir) = writer_whose_recovery_read_fails().await;
            writer
                .write("did:key:z6Mk", None, sample_event())
                .await
                .expect_err("a scan that storage refuses must fail closed");
        });

        assert_eq!(count, 1);
    }

    /// Writes refused during the backoff window do not re-count the failure.
    ///
    /// The counter has to stay a count of *recoveries attempted and failed*,
    /// not of audit writes refused: the backoff deliberately answers without
    /// touching storage, so counting there would turn one broken log into a
    /// rate that tracks traffic and tells an operator nothing about severity.
    #[cfg(feature = "encryption")]
    #[test]
    fn writes_refused_during_the_backoff_do_not_re_count() {
        let count = recovery_failures_during(async {
            let (writer, _dir) = writer_whose_recovery_read_fails().await;
            for _ in 0..3 {
                writer
                    .write("did:key:z6Mk", None, sample_event())
                    .await
                    .expect_err("every write fails while the head is unknown");
            }
        });

        assert_eq!(
            count, 1,
            "three refused writes, one recovery attempt, one count"
        );
    }

    /// A legacy log far longer than one deep-scan page, with no envelope
    /// anywhere, is walked to its end and anchors at genesis — never refused.
    /// A fixed cap here once turned an ordinary pre-chain log (one row per
    /// audited operation over the retention window) into every audit write
    /// failing closed, with nothing that could clear it.
    #[tokio::test]
    async fn a_legacy_log_spanning_many_deep_scan_pages_anchors_at_genesis() {
        let f = fixture();
        f.key_store.ensure_initial(&[0x0b; 32]).await.unwrap();
        seed_legacy_rows(&f.writer, HEAD_LOOKBACK + 10 * 7 + 3).await;

        let env = f
            .writer
            .with_key_prefix("log:")
            .with_deep_scan_page(10)
            .write("did:key:z6Mk", None, sample_event())
            .await
            .expect("a long legacy log must anchor, not fail closed");

        assert_eq!(env.prev_hash, GENESIS_HASH);
    }

    /// A keyspace with *more* non-envelope rows than `HEAD_LOOKBACK` and no
    /// envelope anywhere: a lookback-only scan would have failed closed
    /// forever. Recovery must keep walking until it proves the prefix empty
    /// of envelopes, then anchor at genesis.
    #[tokio::test]
    async fn legacy_log_longer_than_head_lookback_without_envelope_still_anchors_at_genesis() {
        let f = fixture();
        f.key_store.ensure_initial(&[0x0e; 32]).await.unwrap();
        // More than HEAD_LOOKBACK: the fast path alone cannot decide.
        let total_rows = HEAD_LOOKBACK + 10;
        for index in 0..total_rows {
            f.writer
                .audit_ks
                .insert(
                    format!("log:{index:020}:legacy"),
                    &serde_json::json!({
                        "id": format!("legacy-{index}"),
                        "timestamp": 1_700_000_000u64 + index as u64,
                        "action": "auth.challenge",
                        "actor": "did:key:z6MkLegacy",
                        "outcome": "success",
                    }),
                )
                .await
                .unwrap();
        }

        let env = f
            .writer
            .with_key_prefix("log:")
            .write("did:key:z6Mk", None, sample_event())
            .await
            .expect(
                "a legacy log longer than HEAD_LOOKBACK but with no envelope must still anchor, \
                 not fail closed",
            );

        assert_eq!(
            env.prev_hash, GENESIS_HASH,
            "the deep scan must prove the prefix envelope-free before anchoring at genesis"
        );
    }

    /// The other half of the same regression: a chain that *did* anchor once
    /// (its envelope key sorts older than a pile of more-recent legacy
    /// rows written beneath it) must still be found by the deep-scan
    /// fallback, not mistaken for an unanchored prefix.
    #[tokio::test]
    async fn deep_scan_finds_an_envelope_further_back_than_head_lookback() {
        let f = fixture();
        f.key_store.ensure_initial(&[0x0f; 32]).await.unwrap();

        let anchor = f
            .writer
            .write("did:key:z6Mk", None, sample_event())
            .await
            .expect("seed the anchor envelope");

        // Pile on more non-envelope rows than HEAD_LOOKBACK, sorted after
        // the anchor's RFC 3339 storage key.
        for index in 0..(HEAD_LOOKBACK + 5) {
            f.writer
                .audit_ks
                .insert(
                    format!("zzz-legacy-{index:020}"),
                    &serde_json::json!({
                        "id": format!("legacy-{index}"),
                        "timestamp": 1_700_000_000u64 + index as u64,
                        "action": "auth.challenge",
                        "actor": "did:key:z6MkLegacy",
                        "outcome": "success",
                    }),
                )
                .await
                .unwrap();
        }

        // A fresh writer over the same storage simulates a restart: the
        // in-process chain-head cache from the `write` above must not be
        // reused, so this exercises storage recovery, not the cache.
        let restarted = AuditWriter::new(f.writer.audit_ks.clone(), f.key_store.clone());
        let next = restarted
            .write("did:key:z6Mk", None, sample_event())
            .await
            .expect("an envelope below the fast-path window must still be found");

        assert_eq!(
            next.prev_hash, anchor.entry_hash,
            "the deep-scan fallback must anchor on the buried envelope, not genesis"
        );
    }

    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn failed_head_recovery_is_cached_during_backoff() {
        let (writer, _dir) = writer_whose_recovery_read_fails().await;

        let first = writer
            .write("did:key:z6Mk", None, sample_event())
            .await
            .expect_err("first head recovery must fail");
        let second = writer
            .write("did:key:z6Mk", None, sample_event())
            .await
            .expect_err("backoff must keep failing without a storage retry");

        // The refusal quotes the original failure whole, so it keeps the kind
        // that tells an operator which thing broke.
        assert_eq!(
            second.to_string(),
            format!("internal error: audit chain head unavailable: {first}")
        );
    }

    /// A caller whose keyspace has an existing ordering supplies its own key
    /// function, so that the newest envelope is still the last key — which is
    /// what chain-head recovery depends on.
    #[tokio::test]
    async fn a_custom_storage_key_still_recovers_the_head() {
        let f = fixture();
        f.key_store.ensure_initial(&[0x01; 32]).await.unwrap();

        let writer = f.writer.clone().with_storage_key(|env| {
            format!(
                "log:{:020}:{}",
                env.timestamp.timestamp().max(0),
                env.event_id
            )
            .into_bytes()
        });

        let first = writer
            .write("did:key:z6MkA", None, sample_event())
            .await
            .unwrap();

        // A fresh writer over the same keyspace has no cached head, so it
        // recovers one from storage — the path a restart takes.
        let restarted = AuditWriter::new(f.writer.audit_ks.clone(), f.key_store.clone())
            .with_storage_key(|env| {
                format!(
                    "log:{:020}:{}",
                    env.timestamp.timestamp().max(0),
                    env.event_id
                )
                .into_bytes()
            });
        let second = restarted
            .write("did:key:z6MkB", None, sample_event())
            .await
            .unwrap();

        assert_eq!(
            second.prev_hash, first.entry_hash,
            "the second entry chains to the first across a restart"
        );
        assert!(
            verify_chain(&[first, second]).is_ok(),
            "the pair verifies as a chain"
        );
    }

    #[tokio::test]
    async fn write_persists_envelope_and_hashes_actor() {
        let f = fixture();
        f.key_store.ensure_initial(&[0x01; 32]).await.unwrap();

        let env = f
            .writer
            .write("did:key:z6Mk", None, sample_event())
            .await
            .unwrap();

        assert_eq!(env.event_version, EVENT_VERSION);
        assert_eq!(env.schema_version, SCHEMA_VERSION);
        assert_eq!(env.actor_did_plain.as_deref(), Some("did:key:z6Mk"));
        assert!(env.target_did_hash.is_none());

        // The hash is not the SHA-256 of the DID — it's HMAC-keyed.
        // Concretely, it must differ from a plain SHA-256.
        use sha2::Digest;
        let plain_sha: [u8; 32] = sha2::Sha256::digest(b"did:key:z6Mk").into();
        assert_ne!(env.actor_did_hash, plain_sha);
    }

    #[tokio::test]
    async fn same_actor_same_key_yields_same_hash() {
        let f = fixture();
        f.key_store.ensure_initial(&[0x02; 32]).await.unwrap();

        let a = f
            .writer
            .write("did:key:abc", None, sample_event())
            .await
            .unwrap();
        let b = f
            .writer
            .write("did:key:abc", None, sample_event())
            .await
            .unwrap();
        assert_eq!(a.actor_did_hash, b.actor_did_hash);
        assert_eq!(a.audit_key_id, b.audit_key_id);
    }

    #[tokio::test]
    async fn different_actors_yield_different_hashes() {
        let f = fixture();
        f.key_store.ensure_initial(&[0x03; 32]).await.unwrap();
        let a = f
            .writer
            .write("did:key:alice", None, sample_event())
            .await
            .unwrap();
        let b = f
            .writer
            .write("did:key:bob", None, sample_event())
            .await
            .unwrap();
        assert_ne!(a.actor_did_hash, b.actor_did_hash);
    }

    #[tokio::test]
    async fn rotation_changes_subsequent_hashes() {
        let f = fixture();
        f.key_store.ensure_initial(&[0x04; 32]).await.unwrap();
        let before = f
            .writer
            .write("did:key:alice", None, sample_event())
            .await
            .unwrap();
        f.key_store.rotate(RotationReason::Manual).await.unwrap();
        let after = f
            .writer
            .write("did:key:alice", None, sample_event())
            .await
            .unwrap();
        assert_ne!(before.actor_did_hash, after.actor_did_hash);
        assert_ne!(before.audit_key_id, after.audit_key_id);
    }

    #[tokio::test]
    async fn verify_actor_walks_history_across_rotation() {
        let f = fixture();
        f.key_store.ensure_initial(&[0x05; 32]).await.unwrap();

        let pre = f
            .writer
            .write("did:key:alice", None, sample_event())
            .await
            .unwrap();
        f.key_store.rotate(RotationReason::Routine).await.unwrap();
        let post = f
            .writer
            .write("did:key:bob", None, sample_event())
            .await
            .unwrap();

        // Pre-rotation envelope still verifies against alice via the
        // retained prior key.
        assert!(f.writer.verify_actor(&pre, "did:key:alice").await.unwrap());
        assert!(!f.writer.verify_actor(&pre, "did:key:bob").await.unwrap());

        // Post-rotation envelope verifies against bob via the new key.
        assert!(f.writer.verify_actor(&post, "did:key:bob").await.unwrap());
        assert!(!f.writer.verify_actor(&post, "did:key:alice").await.unwrap());
    }

    /// Read every envelope back in ascending storage-key order.
    async fn read_chain(ks: &KeyspaceHandle) -> Vec<AuditEnvelope> {
        let mut pairs = ks.prefix_iter_raw(Vec::new()).await.unwrap();
        pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
        pairs
            .iter()
            .map(|(_, v)| serde_json::from_slice(v).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn writes_form_a_verifiable_chain() {
        use crate::audit::envelope::{GENESIS_HASH, verify_chain};
        let f = fixture();
        f.key_store.ensure_initial(&[0x07; 32]).await.unwrap();

        for i in 0..5u8 {
            f.writer
                .write(&format!("did:key:actor{i}"), None, sample_event())
                .await
                .unwrap();
        }

        let chain = read_chain(&f.writer.audit_ks).await;
        assert_eq!(chain.len(), 5);
        assert_eq!(chain[0].prev_hash, GENESIS_HASH);
        // Each link points at its predecessor.
        for w in chain.windows(2) {
            assert_eq!(w[1].prev_hash, w[0].entry_hash);
        }
        verify_chain(&chain).expect("chain must verify");
    }

    #[tokio::test]
    async fn tamper_after_write_is_detected() {
        use crate::audit::envelope::{ChainBreak, verify_chain};
        let f = fixture();
        f.key_store.ensure_initial(&[0x08; 32]).await.unwrap();
        for i in 0..3u8 {
            f.writer
                .write(&format!("did:key:a{i}"), None, sample_event())
                .await
                .unwrap();
        }

        let mut chain = read_chain(&f.writer.audit_ks).await;
        // Forge a different event on the middle row without restamping.
        chain[1].event =
            AuditEvent::CommunityProfileUpdated(crate::audit::event::CommunityProfileUpdatedData {
                fields_changed: vec!["forged".into()],
                ..Default::default()
            });
        assert!(matches!(
            verify_chain(&chain),
            Err(ChainBreak::TamperedEntry { index: 1, .. })
        ));
    }

    #[tokio::test]
    async fn chain_head_recovers_after_restart() {
        use crate::audit::envelope::verify_chain;
        let f = fixture();
        f.key_store.ensure_initial(&[0x09; 32]).await.unwrap();
        f.writer
            .write("did:key:before", None, sample_event())
            .await
            .unwrap();

        // Simulate a restart: a fresh writer over the same keyspace
        // with an empty in-memory head. Its first write must link to
        // the persisted head, not restart at genesis.
        let restarted = AuditWriter::new(f.writer.audit_ks.clone(), f.key_store.clone());
        restarted
            .write("did:key:after", None, sample_event())
            .await
            .unwrap();

        let chain = read_chain(&f.writer.audit_ks).await;
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].prev_hash, chain[0].entry_hash);
        verify_chain(&chain).expect("chain survives restart");
    }

    #[tokio::test]
    async fn target_hash_set_when_target_supplied() {
        let f = fixture();
        f.key_store.ensure_initial(&[0x06; 32]).await.unwrap();
        let env = f
            .writer
            .write("did:key:admin", Some("did:key:member"), sample_event())
            .await
            .unwrap();
        assert!(env.target_did_hash.is_some());
        assert!(
            f.writer
                .verify_target(&env, "did:key:member")
                .await
                .unwrap()
        );
        assert!(
            !f.writer
                .verify_target(&env, "did:key:somebody-else")
                .await
                .unwrap()
        );
    }
}
