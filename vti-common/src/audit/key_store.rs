//! `audit_key` lifecycle — HKDF-derived initial key, fresh-random
//! rotations, indefinite retention.
//!
//! See plan **D3 + D10** in `tasks/vtc-mvp/plan.md` for the full
//! rationale. Highlights:
//!
//! - **Algorithm**: HMAC-SHA256 over UTF-8 DID bytes.
//! - **Initial key**: deterministic
//!   `HKDF-SHA256(master_seed, info: "vtc-audit-key/v2")` — so a
//!   backup+restore on the same master seed reproduces it.
//! - **Subsequent rotations**: 32 fresh random bytes via `rand::fill`
//!   (the workspace pattern; backed by the OS RNG). Deterministic
//!   rotations would defeat the point of RTBF — a rotated key's
//!   predecessor needs to be genuinely unrecoverable from the seed
//!   alone.
//! - **Retention**: every prior key stays in the keyspace under its
//!   own `audit_key:<key_id>` entry. 32 bytes × one rotation/year ×
//!   100 years = 3.2 KB. Lookups walk newest-first; the active key
//!   answers the typical case and pre-rotation hashes only need
//!   older keys during compliance investigations.
//!
//! ## Storage layout
//!
//! Two key spaces under the `audit_key` keyspace:
//!
//! - `audit_key:<key_id>` → [`AuditKey`] (JSON-encoded, encrypted via
//!   the standard [`crate::store::KeyspaceHandle`] encryption layer
//!   if the consumer enables it).
//! - `audit_key:active` → `<key_id>` as bytes — the marker for the
//!   currently-issuing key. Updated atomically on rotation.

use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Stable identifier for an audit_key. Wrapper around [`Uuid`] so
/// public APIs stay typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub Uuid);

impl KeyId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn nil() -> Self {
        Self(Uuid::nil())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for KeyId {
    fn default() -> Self {
        Self::nil()
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Why an [`AuditKey`] was rotated. Recorded on the **successor** key
/// so an investigator can tell why a particular epoch ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationReason {
    /// Initial key derived from the master seed via HKDF. Always
    /// present as the first row.
    Initial,
    /// Routine age-triggered rotation (the audit background task fired).
    Routine,
    /// Operator invoked the rotate CLI / endpoint.
    Manual,
    /// Right-to-be-forgotten override — the rotation closes the
    /// previous epoch and makes its hashes opaque.
    Rtbf,
}

/// A persisted audit_key. Stored under `audit_key:<key_id>`. Manual
/// [`std::fmt::Debug`] redacts the key material so a stray
/// `tracing::debug!(?key, …)` never leaks it.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuditKey {
    pub key_id: KeyId,
    /// 32-byte HMAC-SHA256 key. Serialised as a JSON array of bytes;
    /// in production the surrounding keyspace handle should be
    /// configured with the workspace's standard encryption-at-rest
    /// layer so the value never touches disk in the clear.
    pub key: [u8; 32],
    pub valid_from: DateTime<Utc>,
    /// `None` for the currently-active key; populated on rotation.
    pub valid_until: Option<DateTime<Utc>>,
    pub rotation_reason: RotationReason,
}

impl std::fmt::Debug for AuditKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditKey")
            .field("key_id", &self.key_id)
            .field("key", &"<redacted>")
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .field("rotation_reason", &self.rotation_reason)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

const ACTIVE_MARKER_KEY: &[u8] = b"audit_key:active";

fn key_storage_key(key_id: &KeyId) -> Vec<u8> {
    format!("audit_key:{}", key_id.0).into_bytes()
}

// ---------------------------------------------------------------------------
// AuditKeyStore
// ---------------------------------------------------------------------------

/// Manager for the audit_key history under a single keyspace.
///
/// All methods are async because the underlying keyspace I/O is
/// async. Concurrent rotations on the same store are *not*
/// serialised in this layer — the caller (services) owns the
/// invariant that rotation happens from a single coordinator path.
///
/// ## The active-key cache
///
/// Every audited operation asks for the active key, which is two reads
/// (the marker, then the key it names). [`Self::active`] and
/// [`Self::try_active`] keep the last answer under the keyspace's
/// [cache ticket](KeyspaceHandle::cache_ticket) and reuse it while that
/// ticket is current: no write to `audit_key` has begun, ended or been
/// abandoned since, through *any* handle or instance.
///
/// That makes it coherent and fail-closed without this type seeing the
/// writes:
///
/// - a rotation through another `AuditKeyStore`, or the marker deleted
///   through a bare keyspace handle (VTI-APV-022's outage test), retires the
///   ticket, so the next call re-reads and fails exactly as it did before the
///   cache existed;
/// - nothing read while a write is in flight, or while a write's outcome is
///   unknown (cancelled after its request may have reached the vsock
///   parent), is cached — so a rotation the parent applies after its caller
///   gave up cannot leave the old key cached;
/// - a read error is never cached;
/// - and whatever the tickets say, no value is served once it is
///   [`MAX_CACHE_AGE`] old.
///
/// The cached value is per instance (shared by clones); the write tracking
/// is per keyspace. Sharing the *value* across every handle for the name
/// would also share it between an encrypted and a bare handle, handing a
/// decrypted key to an instance whose own read would fail.
#[derive(Clone)]
pub struct AuditKeyStore {
    ks: KeyspaceHandle,
    cached: std::sync::Arc<std::sync::Mutex<Option<CachedKey>>>,
    max_age: std::time::Duration,
}

/// How long a cached active key may be served, whatever the write tracking
/// says.
///
/// The tracking is the correctness argument; this bounds the cost of any
/// case it does not foresee (a write applied out of order behind a later
/// one, a store change the process cannot observe) to half a minute of
/// hashing under the previous key — which stays retained and verifiable, so
/// the worst outcome is a row attributed to the epoch that just closed. At
/// the rates where the cache matters (hundreds of audited operations a
/// second) one re-read every 30 s costs nothing measurable; much shorter and
/// the bound would start to show in latency, much longer and a rotation that
/// RTBF depends on could be ignored for minutes.
pub const MAX_CACHE_AGE: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone)]
struct CachedKey {
    ticket: u64,
    read_at: std::time::Instant,
    key: AuditKey,
}

/// HKDF info string for a VTC's audit key. The `/v2` is the rework recorded
/// in this module's history and is part of the derivation — changing it
/// derives a different key and orphans every existing hash.
pub const VTC_AUDIT_KEY_INFO: &[u8] = b"vtc-audit-key/v2";

/// HKDF info string for a VTA's audit key. Separate from
/// [`VTC_AUDIT_KEY_INFO`] so that a VTC provisioned on a VTA does not share
/// its HMAC key with the VTA underneath it.
pub const VTA_AUDIT_KEY_INFO: &[u8] = b"vta-audit-key/v1";

impl AuditKeyStore {
    /// Wrap a keyspace handle. The caller is responsible for
    /// configuring encryption-at-rest if desired.
    pub fn new(ks: KeyspaceHandle) -> Self {
        Self {
            ks,
            cached: Default::default(),
            max_age: MAX_CACHE_AGE,
        }
    }

    /// Test-only: a shorter [`MAX_CACHE_AGE`].
    #[cfg(test)]
    pub(crate) fn with_max_age(mut self, max_age: std::time::Duration) -> Self {
        self.max_age = max_age;
        self
    }

    /// Read the currently active key. Returns
    /// [`AppError::NotFound`] if no initial key has been derived yet
    /// — callers should invoke [`Self::ensure_initial`] on boot.
    ///
    /// Served from the cache while `audit_key` is unchanged (see the type
    /// docs); otherwise read, exactly as before the cache.
    pub async fn active(&self) -> Result<AuditKey, AppError> {
        let ticket = self.ks.cache_ticket();
        if let Some(key) = self.cached_at(ticket) {
            return Ok(key);
        }
        let id_bytes = self
            .ks
            .get_raw(ACTIVE_MARKER_KEY.to_vec())
            .await?
            .ok_or_else(|| {
                AppError::NotFound(
                    "no active audit_key; call ensure_initial(master_seed) first".into(),
                )
            })?;
        let id_str = String::from_utf8(id_bytes)
            .map_err(|e| AppError::Internal(format!("invalid audit_key id encoding: {e}")))?;
        let key_id = KeyId(
            Uuid::parse_str(&id_str)
                .map_err(|e| AppError::Internal(format!("invalid audit_key uuid: {e}")))?,
        );
        let key = self.fetch(&key_id).await?.ok_or_else(|| {
            AppError::Internal(format!(
                "active marker points at unknown audit_key {key_id}"
            ))
        })?;
        self.remember(ticket, &key);
        Ok(key)
    }

    /// The cached active key, if it was cached under `ticket` (taken just
    /// now, so nothing has been written since) and is younger than the
    /// maximum age. No ticket — a write in flight or of unknown outcome —
    /// means no hit.
    fn cached_at(&self, ticket: Option<u64>) -> Option<AuditKey> {
        let ticket = ticket?;
        let cached = self
            .cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*cached {
            Some(c) if c.ticket == ticket && c.read_at.elapsed() < self.max_age => {
                Some(c.key.clone())
            }
            _ => None,
        }
    }

    /// Cache `key`, read after taking `ticket`, if that ticket is still
    /// current: no write began, ended or was abandoned during the reads.
    /// Otherwise the value may predate a write, and is not kept.
    fn remember(&self, ticket: Option<u64>, key: &AuditKey) {
        let Some(ticket) = ticket else { return };
        // `read_at` before the check, so the age is never understated.
        let read_at = std::time::Instant::now();
        if !self.ks.ticket_is_current(ticket) {
            return;
        }
        *self
            .cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(CachedKey {
            ticket,
            read_at,
            key: key.clone(),
        });
    }

    /// Fetch a specific key by id. Used by verifiers walking history
    /// to find the key that produced a given hash.
    pub async fn fetch(&self, key_id: &KeyId) -> Result<Option<AuditKey>, AppError> {
        self.ks.get(key_storage_key(key_id)).await
    }

    /// List every key in the store, newest first. Used by
    /// `verify_actor`-style helpers in [`super::writer::AuditWriter`]
    /// to walk history when the envelope's `audit_key_id` is
    /// unavailable (defensive — every envelope written here has one).
    pub async fn history(&self) -> Result<Vec<AuditKey>, AppError> {
        let pairs = self.ks.prefix_iter_raw(b"audit_key:".to_vec()).await?;
        let mut keys: Vec<AuditKey> = pairs
            .into_iter()
            .filter(|(k, _)| k.as_slice() != ACTIVE_MARKER_KEY)
            .filter_map(|(_, v)| serde_json::from_slice::<AuditKey>(&v).ok())
            .collect();
        keys.sort_by_key(|k| std::cmp::Reverse(k.valid_from));
        Ok(keys)
    }

    /// Derive the initial audit_key from `master_seed` and persist it.
    /// Idempotent: if an initial key already exists, returns it
    /// unchanged. Safe to call on every daemon start.
    ///
    /// The derivation is deterministic
    /// (`HKDF-SHA256(master_seed, info: "vtc-audit-key/v2")`) so a
    /// backup+restore on the same seed reproduces the initial key
    /// and pre-rotation hashes stay verifiable.
    ///
    /// Info string bumped from `/v1` to `/v2` alongside the
    /// VTA-driven-keys rework (`tasks/vtc-mvp/vta-driven-keys.md`
    /// §5.2) — the IKM is now a 32-byte Ed25519 private from the
    /// VTA bundle, not a 64-byte BIP-39 seed.
    pub async fn ensure_initial(&self, master_seed: &[u8]) -> Result<AuditKey, AppError> {
        self.ensure_initial_with_info(master_seed, VTC_AUDIT_KEY_INFO)
            .await
    }

    /// As [`Self::ensure_initial`], deriving under an explicit HKDF info
    /// string.
    ///
    /// The info string is what separates one node's audit key from another's
    /// when both derive from the same seed — which is not hypothetical: a VTC
    /// is provisioned on top of a VTA and can reach the same master seed, so
    /// deriving both logs' keys under one label would give two different logs
    /// one HMAC key. An actor hash would then correlate across them, which is
    /// precisely the correlation the hash exists to contain.
    ///
    /// Use [`VTC_AUDIT_KEY_INFO`] or [`VTA_AUDIT_KEY_INFO`]; a new node type
    /// adds a constant beside them rather than passing a literal, so the set
    /// of labels in use is greppable.
    pub async fn ensure_initial_with_info(
        &self,
        master_seed: &[u8],
        info: &[u8],
    ) -> Result<AuditKey, AppError> {
        if let Some(existing) = self.try_active().await? {
            return Ok(existing);
        }

        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(None, master_seed)
            .expand(info, &mut key)
            .map_err(|e| AppError::Internal(format!("HKDF expand failed: {e}")))?;

        let initial = AuditKey {
            key_id: KeyId::new(),
            key,
            valid_from: Utc::now(),
            valid_until: None,
            rotation_reason: RotationReason::Initial,
        };
        self.persist(&initial).await?;
        self.set_active(&initial.key_id).await?;
        Ok(initial)
    }

    /// Establish an initial key from the OS random source rather than from a
    /// seed. Idempotent, like [`Self::ensure_initial`].
    ///
    /// # Why a node would prefer this
    ///
    /// The key's job is to be a stable handle for actor and target
    /// identifiers: it has to exist before the first write, stay retrievable
    /// while any envelope references it, and be rotatable. Nothing about that
    /// requires it to be derivable.
    ///
    /// What derivation adds is a second copy of the key wherever the seed is.
    /// A node whose recovery story is a mnemonic therefore has an audit key
    /// that anyone holding the mnemonic can recompute — and since the
    /// commitment exists so that an erasure can null the plaintext while the
    /// row stays correlatable, that makes the erasure reversible by brute
    /// force over the identifiers the node has seen. Generating the key
    /// instead confines that to whoever holds the key material.
    ///
    /// The cost is that the key is not regenerable: if the keyspace holding it
    /// is lost and envelopes survive elsewhere, their actor hashes can no
    /// longer be checked against a candidate. Keep this keyspace in the backup
    /// set.
    pub async fn ensure_initial_random(&self) -> Result<AuditKey, AppError> {
        if let Some(existing) = self.try_active().await? {
            return Ok(existing);
        }

        let mut key = [0u8; 32];
        rand::fill(&mut key);

        let initial = AuditKey {
            key_id: KeyId::new(),
            key,
            valid_from: Utc::now(),
            valid_until: None,
            rotation_reason: RotationReason::Initial,
        };
        self.persist(&initial).await?;
        self.set_active(&initial.key_id).await?;
        Ok(initial)
    }

    /// Rotate the active key. The previous key gets `valid_until: now`
    /// and a fresh-random successor is generated + activated.
    /// Returns the new active key.
    ///
    /// Concurrent rotations are **not** safe at this layer — the
    /// caller must hold a logical exclusivity lock.
    pub async fn rotate(&self, reason: RotationReason) -> Result<AuditKey, AppError> {
        let now = Utc::now();
        let mut prev = self.active().await?;
        prev.valid_until = Some(now);
        self.persist(&prev).await?;

        let key = random_32_bytes();
        let successor = AuditKey {
            key_id: KeyId::new(),
            key,
            valid_from: now,
            valid_until: None,
            rotation_reason: reason,
        };
        self.persist(&successor).await?;
        self.set_active(&successor.key_id).await?;
        Ok(successor)
    }

    /// Look up the active marker without raising if it's absent.
    /// Public so a caller can ask whether a key has been established without
    /// establishing one — the question a sink asks before deciding whether
    /// this write is the one that opens the chain.
    pub async fn try_active(&self) -> Result<Option<AuditKey>, AppError> {
        let ticket = self.ks.cache_ticket();
        if let Some(key) = self.cached_at(ticket) {
            return Ok(Some(key));
        }
        let id_bytes = match self.ks.get_raw(ACTIVE_MARKER_KEY.to_vec()).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        let id_str = String::from_utf8(id_bytes)
            .map_err(|e| AppError::Internal(format!("invalid audit_key id encoding: {e}")))?;
        let key_id = KeyId(
            Uuid::parse_str(&id_str)
                .map_err(|e| AppError::Internal(format!("invalid audit_key uuid: {e}")))?,
        );
        let key = self.fetch(&key_id).await?;
        if let Some(key) = &key {
            self.remember(ticket, key);
        }
        Ok(key)
    }

    async fn persist(&self, key: &AuditKey) -> Result<(), AppError> {
        self.ks.insert(key_storage_key(&key.key_id), key).await
    }

    async fn set_active(&self, key_id: &KeyId) -> Result<(), AppError> {
        self.ks
            .insert_raw(
                ACTIVE_MARKER_KEY.to_vec(),
                key_id.0.to_string().into_bytes(),
            )
            .await
    }
}

fn random_32_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    rand::fill(&mut out);
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

    pub(super) fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&cfg).expect("store");
        let ks = store.keyspace("audit_key-test").expect("keyspace");
        (ks, dir)
    }

    #[tokio::test]
    async fn ensure_initial_is_deterministic() {
        let (ks_a, _a) = temp_ks();
        let (ks_b, _b) = temp_ks();
        let seed = [0xAB; 32];

        let store_a = AuditKeyStore::new(ks_a);
        let store_b = AuditKeyStore::new(ks_b);

        let a = store_a.ensure_initial(&seed).await.unwrap();
        let b = store_b.ensure_initial(&seed).await.unwrap();

        // Same seed → same HKDF output, even though the key_id /
        // valid_from differ. The 32-byte key bytes are the load-bearing
        // determinism.
        assert_eq!(a.key, b.key);
    }

    #[tokio::test]
    async fn ensure_initial_is_idempotent() {
        let (ks, _dir) = temp_ks();
        let store = AuditKeyStore::new(ks);

        let first = store.ensure_initial(&[0x01; 32]).await.unwrap();
        let second = store.ensure_initial(&[0x99; 32]).await.unwrap();

        // The seed argument is *ignored* on the second call — once an
        // initial key exists, ensure_initial returns it unchanged.
        assert_eq!(first.key_id, second.key_id);
        assert_eq!(first.key, second.key);
    }

    #[tokio::test]
    async fn rotate_generates_fresh_random_and_closes_prior() {
        let (ks, _dir) = temp_ks();
        let store = AuditKeyStore::new(ks);

        let initial = store.ensure_initial(&[0x33; 32]).await.unwrap();
        assert_eq!(initial.rotation_reason, RotationReason::Initial);
        assert!(initial.valid_until.is_none());

        let rotated = store.rotate(RotationReason::Rtbf).await.unwrap();
        assert_eq!(rotated.rotation_reason, RotationReason::Rtbf);
        assert_ne!(rotated.key_id, initial.key_id);
        assert_ne!(rotated.key, initial.key);
        assert!(rotated.valid_until.is_none());

        // Initial now has a `valid_until` populated.
        let prior = store.fetch(&initial.key_id).await.unwrap().expect("prior");
        assert!(prior.valid_until.is_some());

        // Active reads return the successor.
        let active = store.active().await.unwrap();
        assert_eq!(active.key_id, rotated.key_id);
    }

    #[tokio::test]
    async fn history_lists_newest_first() {
        let (ks, _dir) = temp_ks();
        let store = AuditKeyStore::new(ks);

        let k1 = store.ensure_initial(&[0x33; 32]).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let k2 = store.rotate(RotationReason::Routine).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let k3 = store.rotate(RotationReason::Manual).await.unwrap();

        let history = store.history().await.unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].key_id, k3.key_id);
        assert_eq!(history[1].key_id, k2.key_id);
        assert_eq!(history[2].key_id, k1.key_id);
    }

    #[tokio::test]
    async fn active_is_not_found_before_initial() {
        let (ks, _dir) = temp_ks();
        let store = AuditKeyStore::new(ks);
        let err = store.active().await.expect_err("no active key yet");
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[test]
    fn debug_redacts_key_material() {
        let k = AuditKey {
            key_id: KeyId::new(),
            key: [0xAB; 32],
            valid_from: Utc::now(),
            valid_until: None,
            rotation_reason: RotationReason::Initial,
        };
        let s = format!("{k:?}");
        assert!(!s.contains("AB"), "key bytes leaked: {s}");
        assert!(s.contains("<redacted>"), "missing redaction marker: {s}");
    }
}

#[cfg(test)]
mod domain_separation_tests {
    use super::tests::temp_ks;
    use super::*;

    fn store() -> (AuditKeyStore, tempfile::TempDir) {
        let (ks, dir) = temp_ks();
        (AuditKeyStore::new(ks), dir)
    }

    /// The reason `ensure_initial_with_info` exists: a VTC is provisioned on
    /// top of a VTA and can reach the same master seed. Deriving both logs'
    /// keys under one label would give two different audit logs one HMAC key,
    /// so an actor hash would correlate across them — the correlation the
    /// hash exists to contain.
    #[tokio::test]
    async fn one_seed_derives_different_keys_per_node_type() {
        let seed = [7u8; 32];

        let (vtc, _vtc_dir) = store();
        let (vta, _vta_dir) = store();

        let vtc_key = vtc
            .ensure_initial_with_info(&seed, VTC_AUDIT_KEY_INFO)
            .await
            .expect("derive vtc audit key");
        let vta_key = vta
            .ensure_initial_with_info(&seed, VTA_AUDIT_KEY_INFO)
            .await
            .expect("derive vta audit key");

        assert_ne!(
            vtc_key.key, vta_key.key,
            "a VTC and the VTA beneath it must not share an audit key"
        );
    }

    /// A generated key is idempotent the same way a derived one is: it is
    /// established once and returned unchanged after that, so a node can call
    /// it on every start.
    #[tokio::test]
    async fn a_generated_key_is_established_once() {
        let (ks, _dir) = store();

        let first = ks.ensure_initial_random().await.expect("first");
        let second = ks.ensure_initial_random().await.expect("second");

        assert_eq!(first.key_id, second.key_id);
        assert_eq!(first.key, second.key);
    }

    /// The property that makes a generated key worth preferring: nothing
    /// outside the key store reproduces it. Two nodes that share a seed —
    /// a VTC and the VTA beneath it — still get unrelated keys.
    #[tokio::test]
    async fn a_generated_key_is_not_reproducible_from_the_seed() {
        let seed = [7u8; 32];

        let (generated_ks, _a) = store();
        let (derived_ks, _b) = store();

        let generated = generated_ks.ensure_initial_random().await.unwrap();
        let derived = derived_ks
            .ensure_initial_with_info(&seed, VTA_AUDIT_KEY_INFO)
            .await
            .unwrap();

        assert_ne!(generated.key, derived.key);

        let (other_ks, _c) = store();
        let other = other_ks.ensure_initial_random().await.unwrap();
        assert_ne!(
            generated.key, other.key,
            "two generated keys are unrelated to each other as well"
        );
    }

    /// The plain constructor keeps deriving what it always derived, so an
    /// existing community's hashes stay verifiable.
    #[tokio::test]
    async fn the_default_derivation_is_unchanged() {
        let seed = [7u8; 32];

        let (implicit, _a) = store();
        let (explicit, _b) = store();

        let a = implicit.ensure_initial(&seed).await.expect("implicit");
        let b = explicit
            .ensure_initial_with_info(&seed, VTC_AUDIT_KEY_INFO)
            .await
            .expect("explicit");

        assert_eq!(a.key, b.key);
    }

    /// Derivation happens once. A second call returns the stored key rather
    /// than re-deriving, which is what makes it safe to call on every boot.
    #[tokio::test]
    async fn deriving_twice_returns_the_same_key() {
        let seed = [7u8; 32];
        let (ks, _dir) = store();

        let first = ks
            .ensure_initial_with_info(&seed, VTA_AUDIT_KEY_INFO)
            .await
            .expect("first");
        let second = ks
            .ensure_initial_with_info(&seed, VTA_AUDIT_KEY_INFO)
            .await
            .expect("second");

        assert_eq!(first.key_id, second.key_id);
        assert_eq!(first.key, second.key);
    }
}

/// The active-key cache: coherent across instances, fail-closed, and a hit
/// reads nothing.
#[cfg(test)]
mod cache_tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    /// A store and two independently obtained handles on one keyspace — how
    /// the VTC holds several `AuditKeyStore`s over `audit_key`.
    fn shared_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        (Store::open(&cfg).expect("store"), dir)
    }

    /// A rotation through one instance is seen by another that had the old
    /// key cached: the rotation's writes moved the shared generation.
    #[tokio::test]
    async fn a_rotation_through_another_instance_is_seen() {
        let (store, _dir) = shared_store();
        let reader = AuditKeyStore::new(store.keyspace("audit_key").unwrap());
        let rotator = AuditKeyStore::new(store.keyspace("audit_key").unwrap());

        let initial = reader.ensure_initial(&[0x11; 32]).await.unwrap();
        assert_eq!(reader.active().await.unwrap().key_id, initial.key_id);

        let successor = rotator.rotate(RotationReason::Manual).await.unwrap();
        assert_eq!(reader.active().await.unwrap().key_id, successor.key_id);
        assert_eq!(
            reader.try_active().await.unwrap().unwrap().key_id,
            successor.key_id
        );
    }

    /// VTI-APV-022's outage, at this layer: the marker deleted through a bare
    /// handle, after the key was cached, fails the next read exactly as an
    /// uncached store would.
    #[tokio::test]
    async fn deleting_the_marker_through_any_handle_fails_closed() {
        let (store, _dir) = shared_store();
        let keys = AuditKeyStore::new(store.keyspace("audit_key").unwrap());
        keys.ensure_initial(&[0x22; 32]).await.unwrap();
        keys.active().await.unwrap();

        store
            .keyspace("audit_key")
            .unwrap()
            .remove(ACTIVE_MARKER_KEY.to_vec())
            .await
            .unwrap();

        let err = keys.active().await.expect_err("no active key any more");
        assert!(matches!(err, AppError::NotFound(_)), "{err:?}");
        assert!(keys.try_active().await.unwrap().is_none());
    }

    /// A hit reads nothing: with the marker removed *behind the generation's
    /// back* the cached key is still served, which only a call that never
    /// touched storage could do. The next real write ends it.
    #[tokio::test]
    async fn a_cache_hit_reads_nothing_and_any_write_ends_it() {
        let (store, _dir) = shared_store();
        let ks = store.keyspace("audit_key").unwrap();
        let keys = AuditKeyStore::new(ks.clone());
        let initial = keys.ensure_initial(&[0x33; 32]).await.unwrap();
        keys.active().await.unwrap();

        ks.remove_untracked(ACTIVE_MARKER_KEY.to_vec())
            .await
            .unwrap();
        assert_eq!(keys.active().await.unwrap().key_id, initial.key_id);

        // Any write to the keyspace, of any row, invalidates.
        ks.insert_raw(b"unrelated".to_vec(), b"x".to_vec())
            .await
            .unwrap();
        assert!(keys.active().await.is_err());
    }

    /// A failed read is not cached: once the key exists, the next call finds
    /// it.
    #[tokio::test]
    async fn a_failed_read_is_not_remembered() {
        let (store, _dir) = shared_store();
        let keys = AuditKeyStore::new(store.keyspace("audit_key").unwrap());
        assert!(keys.active().await.is_err());
        assert!(keys.try_active().await.unwrap().is_none());

        let initial = keys.ensure_initial(&[0x44; 32]).await.unwrap();
        assert_eq!(keys.active().await.unwrap().key_id, initial.key_id);
    }

    /// The age bound holds whatever the write tracking says: with the marker
    /// removed behind the tracking's back, the cached key is served until it
    /// is `max_age` old, and the next call after that re-reads (and fails).
    #[tokio::test]
    async fn max_age_forces_a_re_read() {
        let (store, _dir) = shared_store();
        let ks = store.keyspace("audit_key").unwrap();
        let keys =
            AuditKeyStore::new(ks.clone()).with_max_age(std::time::Duration::from_millis(200));
        let initial = keys.ensure_initial(&[0x55; 32]).await.unwrap();
        keys.active().await.unwrap();

        ks.remove_untracked(ACTIVE_MARKER_KEY.to_vec())
            .await
            .unwrap();
        assert_eq!(
            keys.active().await.unwrap().key_id,
            initial.key_id,
            "young: a hit"
        );

        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        assert!(keys.active().await.is_err(), "old: re-read, and fail");
    }

    /// While a local write is running (its blocking closure holds the
    /// keyspace's write lock here), reads go through and are not cached.
    #[tokio::test]
    async fn a_local_write_in_flight_suppresses_caching() {
        let (store, _dir) = shared_store();
        let ks = store.keyspace("audit_key").unwrap();
        let keys = AuditKeyStore::new(ks.clone());
        keys.ensure_initial(&[0x66; 32]).await.unwrap();

        let write = ks.begin_local_write_for_test();
        assert!(ks.cache_ticket().is_none(), "in flight: no ticket");
        keys.active().await.unwrap();
        ks.remove_untracked(ACTIVE_MARKER_KEY.to_vec())
            .await
            .unwrap();
        assert!(
            keys.active().await.is_err(),
            "the read during the write was not cached"
        );
        drop(write);
    }
}
