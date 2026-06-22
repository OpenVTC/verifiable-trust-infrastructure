//! [`AuditWriter`] — writes [`AuditEnvelope`]s using the active
//! audit_key for actor/target hashing, plus a `verify_actor` helper
//! that walks key history to confirm a candidate DID matches an
//! envelope's hash.

use std::sync::Arc;

use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::sync::Mutex;
use uuid::Uuid;

use super::envelope::{AuditEnvelope, EVENT_VERSION, GENESIS_HASH, SCHEMA_VERSION};
use super::event::AuditEvent;
use super::key_store::AuditKeyStore;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

type HmacSha256 = Hmac<Sha256>;

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
    /// Cached `entry_hash` of the last-written envelope (the chain
    /// head). `None` until the first write loads it from storage
    /// (restart recovery). Guarded by an async mutex so the
    /// read-head → stamp → insert → update-head sequence is atomic
    /// across concurrent writers.
    chain_head: Arc<Mutex<Option<[u8; 32]>>>,
}

impl AuditWriter {
    pub fn new(audit_ks: KeyspaceHandle, key_store: AuditKeyStore) -> Self {
        Self {
            audit_ks,
            key_store,
            chain_head: Arc::new(Mutex::new(None)),
        }
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
        let mut head = self.chain_head.lock().await;
        let prev_hash = match *head {
            Some(h) => h,
            None => self.load_chain_head().await?,
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
            .insert(envelope_storage_key(&envelope), &envelope)
            .await?;
        *head = Some(envelope.entry_hash);
        Ok(envelope)
    }

    /// Recover the chain head from storage on the first write after a
    /// (re)start. The audit keyspace is keyed by
    /// `<rfc3339-timestamp>:<event_id>`, so the last pair in ascending
    /// key order is the most recently written envelope; its
    /// `entry_hash` is the head. An empty (or pre-v2) log anchors at
    /// [`GENESIS_HASH`].
    async fn load_chain_head(&self) -> Result<[u8; 32], AppError> {
        let pairs = self.audit_ks.prefix_iter_raw(Vec::new()).await?;
        match pairs.last() {
            Some((_, raw)) => {
                let env: AuditEnvelope = serde_json::from_slice(raw)?;
                Ok(env.entry_hash)
            }
            None => Ok(GENESIS_HASH),
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
