//! Where audit entries go.
//!
//! The audit log records what happened; it cannot prove it. `AuditLogEntry` is
//! `{id, timestamp, action, actor, resource, outcome, channel, contextId,
//! detail}` — no signature, no hash chain — so a compromised VTA can rewrite
//! its own history. The canonical `AuditEnvelope` in
//! `vta_sdk::protocols::audit_management` already names the members that would
//! change that (`prevHash`, `entryHash`, `schemaVersion`) and says why this
//! maintainer omits them: its log is flat and unchained.
//!
//! This module does **not** add tamper-evidence, and that is deliberate (#1031).
//! It adds the seam. An operator who needs a stronger guarantee implements
//! [`AuditSink`] — an append-only file, a transparency log, a blockchain anchor,
//! a hash chain populating those three members — and installs it, without the
//! VTA committing to any particular scheme. The crypto decision moves out of the
//! protocol and becomes a deployment choice.
//!
//! Same shape as `vti_common::telemetry::TelemetrySink`, whose own docs already
//! name "append-only log, blockchain anchor" as the backends it exists to admit.
//! The two stay separate for the reason recorded there: telemetry is
//! high-volume and query-oriented, audit is security-relevant and durable.
//!
//! ## What is, and is not, behind the seam
//!
//! Writes go through the sink. **Reads and retention do not** —
//! [`crate::cleanup_expired_logs`] and the audit-list query still address the
//! fjall keyspace directly, and take a `KeyspaceHandle` rather than a sink.
//! That is not an oversight. A sink is free to be write-only and remote, and
//! for an append-only or anchored backend "delete rows older than N days" is
//! not an operation it can offer — the immutability is the point. So retention
//! stays a property of the local keyspace, which is also what the retention API
//! is documented to govern.
//!
//! A deployment that installs a remote sink therefore keeps writing locally too
//! if it wants the query API to work — compose the two with [`FanOutAuditSink`]
//! rather than replacing the keyspace sink outright.

use std::sync::Arc;

use async_trait::async_trait;
use vta_sdk::protocols::audit_management::list::AuditLogEntry;
use vti_common::audit::event::{AuditEvent, VtaOperationData};
use vti_common::audit::key_store::AuditKeyStore;
use vti_common::audit::writer::AuditWriter;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// A destination for audit entries.
///
/// One method, taking the whole entry. The entry is the unit of meaning; how it
/// is keyed, framed, chained, or shipped is the implementation's business —
/// which is why the storage key format lives in [`KeyspaceAuditSink`] and not
/// in the caller.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Durably record `entry`.
    ///
    /// Returning `Err` propagates to the caller. Callers differ in what they do
    /// with it — the vault dispatch tail and the DTTE ceremony log and swallow,
    /// because a missing audit row must not change an operation's outcome,
    /// while other call sites propagate. An implementation should not assume
    /// either; it should assume only that returning `Err` is honest and
    /// swallowing internally is not.
    async fn record(&self, entry: &AuditLogEntry) -> Result<(), AppError>;
}

/// The shared handle every call site holds.
pub type SharedAuditSink = Arc<dyn AuditSink>;

/// The default sink: the `audit` fjall keyspace, exactly as before this trait
/// existed.
///
/// Owns the storage key format — `log:{timestamp:020}:{uuid}` — because that
/// format is a property of *this* backend. Zero-padding gives lexicographic
/// time ordering, which is what makes the retention sweep's early `break` and
/// the audit-list time-range scan prefix operations rather than full scans.
#[derive(Clone)]
pub struct KeyspaceAuditSink {
    keyspace: KeyspaceHandle,
}

impl KeyspaceAuditSink {
    pub fn new(keyspace: KeyspaceHandle) -> Self {
        Self { keyspace }
    }

    /// The keyspace behind this sink, for the read and retention paths that
    /// deliberately are not routed through [`AuditSink`] (see the module docs).
    pub fn keyspace(&self) -> &KeyspaceHandle {
        &self.keyspace
    }

    /// The storage key for `entry`. Public so a test — or an alternative
    /// keyspace-backed sink — can agree with the reader rather than restate the
    /// format and drift from it.
    pub fn storage_key(entry: &AuditLogEntry) -> String {
        format!("log:{:020}:{}", entry.timestamp, entry.id)
    }
}

#[async_trait]
impl AuditSink for KeyspaceAuditSink {
    async fn record(&self, entry: &AuditLogEntry) -> Result<(), AppError> {
        self.keyspace.insert(Self::storage_key(entry), entry).await
    }
}

/// The actor recorded for events the node performs on its own behalf, where
/// there is no caller to name.
pub const SYSTEM_ACTOR: &str = "urn:vti:vta:system";

/// The action recorded for the entry that opens a chain.
pub const AUDIT_KEY_CREATED: &str = "audit.key.created";

/// The `audit` keyspace, written as a hash chain.
///
/// Same keyspace and same storage-key format as [`KeyspaceAuditSink`], so the
/// read and retention paths keep working and rows written before this existed
/// keep their place in time order. What changes is the value: an envelope that
/// commits to its predecessor, and that commits to the actor under a keyed
/// hash so an erasure can remove the plaintext without breaking the chain.
///
/// # The first entry
///
/// A chain has to start somewhere, and the honest place is the creation of the
/// key that chains it. The key is established on the first write — there is
/// nothing to audit before a node can act, and a node cannot act before it has
/// somewhere to record what it did — so the first entry this sink writes is
/// the record of that key coming into existence, committing to its id. A
/// verifier reading from the start learns which key the following entries are
/// hashed under, from an entry hashed under that same key.
#[derive(Clone)]
pub struct ChainedKeyspaceAuditSink {
    keyspace: KeyspaceHandle,
    key_store: AuditKeyStore,
    writer: AuditWriter,
    /// Runs the establish-key-then-open-the-chain sequence once per process,
    /// so concurrent first writes cannot both open it.
    opened: Arc<tokio::sync::OnceCell<()>>,
}

impl ChainedKeyspaceAuditSink {
    pub fn new(keyspace: KeyspaceHandle, key_keyspace: KeyspaceHandle) -> Self {
        let key_store = AuditKeyStore::new(key_keyspace);
        let writer = AuditWriter::new(keyspace.clone(), key_store.clone())
            // The keyspace already has an ordering and rows that use it, so
            // the seconds stay the leading field: the retention sweep compares
            // keys against `log:{cutoff:020}:` and stops at the first row past
            // it, and a different leading field would make every chained row
            // sort past every cutoff and never expire.
            //
            // The nanoseconds are the tiebreaker, and they are not optional.
            // Whole seconds put two entries written in the same second in
            // uuid order, so a verifier reading the log in key order sees them
            // out of chain order and reports a break in a chain that is
            // intact. That is the worst kind of false alarm: it looks exactly
            // like the thing it exists to detect.
            .with_storage_key(|env| {
                format!(
                    "log:{:020}:{:09}:{}",
                    env.timestamp.timestamp().max(0),
                    env.timestamp.timestamp_subsec_nanos(),
                    env.event_id
                )
                .into_bytes()
            });
        Self {
            keyspace,
            key_store,
            writer,
            opened: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// The keyspace behind this sink, for the read and retention paths.
    pub fn keyspace(&self) -> &KeyspaceHandle {
        &self.keyspace
    }

    /// Establish the key if there is none, and open the chain with the record
    /// of its creation. Idempotent within a process and across restarts: a key
    /// that already exists was already recorded when it was created.
    async fn ensure_open(&self) -> Result<(), AppError> {
        let already_established = self.key_store.try_active().await?.is_some();
        if already_established {
            return Ok(());
        }

        let key = self.key_store.ensure_initial_random().await?;
        self.writer
            .write(
                SYSTEM_ACTOR,
                None,
                AuditEvent::VtaOperation(VtaOperationData {
                    action: AUDIT_KEY_CREATED.to_string(),
                    resource: Some(key.key_id.as_uuid().to_string()),
                    outcome: "success".to_string(),
                    channel: None,
                    context_id: None,
                    detail: None,
                }),
            )
            .await?;
        Ok(())
    }
}

#[async_trait]
impl AuditSink for ChainedKeyspaceAuditSink {
    async fn record(&self, entry: &AuditLogEntry) -> Result<(), AppError> {
        self.opened
            .get_or_try_init(|| self.ensure_open())
            .await
            .map(|_| ())?;

        // A resource that is a DID travels in the envelope's hashed members,
        // where an erasure can reach it. Anything else — a key id, a session
        // id, a context path — is not personal data and stays in the event.
        let (target, resource) = match entry.resource.as_deref() {
            Some(r) if r.starts_with("did:") => (Some(r), None),
            other => (None, other),
        };

        self.writer
            .write(
                &entry.actor,
                target,
                AuditEvent::VtaOperation(VtaOperationData {
                    action: entry.action.clone(),
                    resource: resource.map(str::to_string),
                    outcome: entry.outcome.clone(),
                    channel: entry.channel.clone(),
                    context_id: entry.context_id.clone(),
                    detail: entry.detail.clone(),
                }),
            )
            .await
            .map(|_| ())
    }
}

/// Build the shared sink every caller should use.
///
/// One construction point, so that changing what a VTA's audit writes is one
/// edit rather than a search. Before this existed the workspace built the same
/// sink over the same keyspace in thirty-one places — including three times
/// inside a single function — and each was a place a later change would have
/// to find.
///
/// A server takes its sink from `AppState`; this is for the callers that have
/// no `AppState` to take it from — offline CLI commands, setup, sweepers and
/// tests.
#[must_use]
pub fn shared_keyspace_sink(keyspace: KeyspaceHandle) -> SharedAuditSink {
    Arc::new(KeyspaceAuditSink::new(keyspace))
}

/// Build the shared sink for a caller that can reach the audit-key keyspace —
/// which is every caller that has the store open, and therefore every caller
/// that should be using this one.
///
/// [`shared_keyspace_sink`] remains for the paths that genuinely cannot: a
/// test that has only the one keyspace, and any caller holding a handle rather
/// than a store. What it writes is unchained, and a chain that resumes after
/// it treats those rows the way it treats rows written before chaining
/// existed.
#[must_use]
pub fn shared_chained_sink(
    keyspace: KeyspaceHandle,
    key_keyspace: KeyspaceHandle,
) -> SharedAuditSink {
    Arc::new(ChainedKeyspaceAuditSink::new(keyspace, key_keyspace))
}

/// Write every entry to several sinks.
///
/// The composition an operator adding tamper-evidence actually needs: keep the
/// keyspace sink so the query and retention APIs go on working, and add the
/// append-only or anchored one beside it. Without this, installing a remote
/// sink would silently take `GET /audit/logs` with it.
///
/// **Every** sink is attempted, and the first error is returned after all of
/// them have run. Short-circuiting would make a failing sink hide the entry
/// from the ones after it in the list, which for an audit log is the failure
/// mode that matters: the row you cannot see is the one you needed.
pub struct FanOutAuditSink {
    sinks: Vec<SharedAuditSink>,
}

impl FanOutAuditSink {
    pub fn new(sinks: Vec<SharedAuditSink>) -> Self {
        Self { sinks }
    }
}

#[async_trait]
impl AuditSink for FanOutAuditSink {
    async fn record(&self, entry: &AuditLogEntry) -> Result<(), AppError> {
        let mut first_err = None;
        for sink in &self.sinks {
            if let Err(e) = sink.record(entry).await {
                tracing::warn!(
                    action = %entry.action,
                    actor = %entry.actor,
                    error = %e,
                    "an audit sink rejected an entry; continuing with the rest"
                );
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn entry(action: &str) -> AuditLogEntry {
        AuditLogEntry {
            id: "11111111-1111-4111-8111-111111111111".into(),
            timestamp: 1_700_000_000,
            action: action.into(),
            actor: "did:key:zTest".into(),
            resource: None,
            outcome: "success".into(),
            channel: None,
            context_id: None,
            detail: None,
        }
    }

    #[derive(Default)]
    struct Recording {
        seen: Mutex<Vec<String>>,
        fail: bool,
    }

    #[async_trait]
    impl AuditSink for Recording {
        async fn record(&self, entry: &AuditLogEntry) -> Result<(), AppError> {
            self.seen.lock().unwrap().push(entry.action.clone());
            if self.fail {
                return Err(AppError::Internal("sink refused".into()));
            }
            Ok(())
        }
    }

    #[test]
    fn the_storage_key_sorts_lexicographically_by_time() {
        // The retention sweep stops at the first key past the cutoff, and the
        // list query is a prefix scan. Both are only correct while the key
        // sorts by time as a *string* — which is what the zero-padding buys.
        let mut early = entry("a");
        early.timestamp = 9;
        let mut late = entry("b");
        late.timestamp = 100;

        assert!(
            KeyspaceAuditSink::storage_key(&early) < KeyspaceAuditSink::storage_key(&late),
            "an earlier entry must sort first as a string, or the sweep's early \
             `break` skips live rows"
        );
    }

    #[tokio::test]
    async fn fan_out_reaches_every_sink_even_when_one_fails() {
        // The point of the composition is that a failing sink cannot hide an
        // entry from the sinks after it.
        let failing = Arc::new(Recording {
            fail: true,
            ..Default::default()
        });
        let healthy = Arc::new(Recording::default());
        let fan = FanOutAuditSink::new(vec![
            Arc::clone(&failing) as SharedAuditSink,
            Arc::clone(&healthy) as SharedAuditSink,
        ]);

        let result = fan.record(&entry("keys.create")).await;

        assert!(result.is_err(), "the failure must still be reported");
        assert_eq!(
            healthy.seen.lock().unwrap().as_slice(),
            ["keys.create"],
            "the sink after the failing one must still have received the entry"
        );
    }

    #[tokio::test]
    async fn fan_out_is_ok_when_every_sink_accepts() {
        let a = Arc::new(Recording::default());
        let b = Arc::new(Recording::default());
        let fan = FanOutAuditSink::new(vec![
            Arc::clone(&a) as SharedAuditSink,
            Arc::clone(&b) as SharedAuditSink,
        ]);

        assert!(fan.record(&entry("acl.grant")).await.is_ok());
        assert_eq!(a.seen.lock().unwrap().len(), 1);
        assert_eq!(b.seen.lock().unwrap().len(), 1);
    }
}

#[cfg(test)]
mod chained_sink_tests {
    use super::*;
    use vti_common::audit::verify_chain;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn keyspaces() -> (KeyspaceHandle, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        (
            store.keyspace("audit").expect("audit"),
            store.keyspace("audit_key").expect("audit_key"),
            dir,
        )
    }

    fn entry(action: &str, actor: &str, resource: Option<&str>) -> AuditLogEntry {
        AuditLogEntry {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: 1_700_000_000,
            action: action.to_string(),
            actor: actor.to_string(),
            resource: resource.map(str::to_string),
            outcome: "success".to_string(),
            channel: Some("rest".to_string()),
            context_id: Some("acme/eng".to_string()),
            detail: None,
        }
    }

    async fn envelopes(ks: &KeyspaceHandle) -> Vec<vti_common::audit::AuditEnvelope> {
        let pairs = ks.prefix_iter_raw("log:").await.expect("scan");
        pairs
            .iter()
            .filter_map(|(_, v)| serde_json::from_slice(v).ok())
            .collect()
    }

    /// The first entry is the creation of the key that chains it, so a
    /// verifier reading from the start learns which key the entries after it
    /// are hashed under.
    #[tokio::test]
    async fn the_chain_opens_with_the_creation_of_its_own_key() {
        let (audit_ks, key_ks, _dir) = keyspaces();
        let sink = ChainedKeyspaceAuditSink::new(audit_ks.clone(), key_ks);

        sink.record(&entry("auth.challenge", "did:key:z6MkA", None))
            .await
            .expect("record");

        let found = envelopes(&audit_ks).await;
        assert_eq!(
            found.len(),
            2,
            "the key's creation, then the caller's event"
        );

        let opening = &found[0];
        match &opening.event {
            vti_common::audit::event::AuditEvent::VtaOperation(op) => {
                assert_eq!(op.action, AUDIT_KEY_CREATED);
                assert_eq!(
                    op.resource.as_deref(),
                    Some(opening.audit_key_id.as_uuid().to_string().as_str()),
                    "the opening entry names the key it is hashed under"
                );
            }
            other => panic!("unexpected opening event: {other:?}"),
        }
        assert_eq!(opening.actor_did_plain.as_deref(), Some(SYSTEM_ACTOR));
    }

    #[tokio::test]
    async fn writes_chain_to_one_another() {
        let (audit_ks, key_ks, _dir) = keyspaces();
        let sink = ChainedKeyspaceAuditSink::new(audit_ks.clone(), key_ks);

        for action in ["auth.challenge", "acl.create", "keys.sign"] {
            sink.record(&entry(action, "did:key:z6MkA", None))
                .await
                .expect("record");
        }

        let found = envelopes(&audit_ks).await;
        assert_eq!(found.len(), 4, "three events plus the opening entry");
        verify_chain(&found).expect("the log verifies as a chain");
    }

    /// The key is established once. A restart does not open a second chain.
    #[tokio::test]
    async fn a_second_sink_over_the_same_keyspace_continues_the_chain() {
        let (audit_ks, key_ks, _dir) = keyspaces();

        ChainedKeyspaceAuditSink::new(audit_ks.clone(), key_ks.clone())
            .record(&entry("auth.challenge", "did:key:z6MkA", None))
            .await
            .expect("first sink");

        ChainedKeyspaceAuditSink::new(audit_ks.clone(), key_ks)
            .record(&entry("acl.create", "did:key:z6MkB", None))
            .await
            .expect("second sink");

        let found = envelopes(&audit_ks).await;
        assert_eq!(found.len(), 3, "one opening entry, not two");
        verify_chain(&found).expect("the chain survives the restart");
    }

    /// A DID-shaped resource travels in the hashed members, where an erasure
    /// can reach it. Anything else is not personal data and stays put.
    #[tokio::test]
    async fn a_did_resource_becomes_a_hashed_target() {
        let (audit_ks, key_ks, _dir) = keyspaces();
        let sink = ChainedKeyspaceAuditSink::new(audit_ks.clone(), key_ks);

        sink.record(&entry(
            "acl.create",
            "did:key:zAdmin",
            Some("did:key:zSubject"),
        ))
        .await
        .expect("did resource");
        sink.record(&entry("keys.sign", "did:key:zAdmin", Some("key-3f2a")))
            .await
            .expect("opaque resource");

        let found = envelopes(&audit_ks).await;
        let did_row = &found[1];
        assert_eq!(
            did_row.target_did_plain.as_deref(),
            Some("did:key:zSubject")
        );
        assert!(did_row.target_did_hash.is_some());

        let key_row = &found[2];
        assert!(
            key_row.target_did_plain.is_none(),
            "a key id is not an identifier to commit to"
        );
        match &key_row.event {
            vti_common::audit::event::AuditEvent::VtaOperation(op) => {
                assert_eq!(op.resource.as_deref(), Some("key-3f2a"));
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
}

#[cfg(test)]
mod verify_support_tests {
    //! The sink's half of what verification depends on. The verifier itself
    //! lives in `vta-service`, where the keyspace read path is.
    use super::*;
    use vti_common::audit::{AuditEnvelope, verify_chain};
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn keyspaces() -> (KeyspaceHandle, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        (
            store.keyspace("audit").expect("audit"),
            store.keyspace("audit_key").expect("audit_key"),
            dir,
        )
    }

    fn entry(action: &str) -> AuditLogEntry {
        AuditLogEntry {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: 1_700_000_000,
            action: action.to_string(),
            actor: "did:key:z6MkA".to_string(),
            resource: None,
            outcome: "success".to_string(),
            channel: None,
            context_id: None,
            detail: None,
        }
    }

    /// Entries written inside one second must still verify. Whole-second keys
    /// order same-second writes by uuid, so a verifier reading in key order
    /// sees them out of chain order and reports a break in an intact chain —
    /// which is why the storage key carries nanoseconds.
    #[tokio::test]
    async fn writes_within_one_second_verify_in_key_order() {
        let (audit_ks, key_ks, _dir) = keyspaces();
        let sink = ChainedKeyspaceAuditSink::new(audit_ks.clone(), key_ks);

        for i in 0..25 {
            sink.record(&entry(&format!("op.{i}")))
                .await
                .expect("record");
        }

        let mut pairs = audit_ks.prefix_iter_raw("log:").await.expect("scan");
        pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
        let envelopes: Vec<AuditEnvelope> = pairs
            .iter()
            .filter_map(|(_, v)| serde_json::from_slice(v).ok())
            .collect();

        assert_eq!(envelopes.len(), 26, "25 events plus the opening entry");
        verify_chain(&envelopes)
            .expect("key order is write order, so the chain verifies as written");
    }

    /// Tampering is what the chain exists to detect, so assert it is detected
    /// rather than assuming.
    #[tokio::test]
    async fn an_altered_entry_breaks_verification() {
        let (audit_ks, key_ks, _dir) = keyspaces();
        let sink = ChainedKeyspaceAuditSink::new(audit_ks.clone(), key_ks);

        for i in 0..3 {
            sink.record(&entry(&format!("op.{i}")))
                .await
                .expect("record");
        }

        let mut pairs = audit_ks.prefix_iter_raw("log:").await.expect("scan");
        pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
        let mut envelopes: Vec<AuditEnvelope> = pairs
            .iter()
            .filter_map(|(_, v)| serde_json::from_slice(v).ok())
            .collect();

        verify_chain(&envelopes).expect("intact before tampering");

        // Rewrite what an entry says happened, leaving its hashes alone —
        // the edit an operator covering their tracks would make.
        if let vti_common::audit::event::AuditEvent::VtaOperation(op) = &mut envelopes[2].event {
            op.outcome = "failure".to_string();
        }
        assert!(
            verify_chain(&envelopes).is_err(),
            "an altered entry must not verify"
        );
    }
}
