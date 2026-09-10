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
#[derive(Clone)]
pub struct AuditKeyStore {
    ks: KeyspaceHandle,
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
        Self { ks }
    }

    /// Read the currently active key. Returns
    /// [`AppError::NotFound`] if no initial key has been derived yet
    /// — callers should invoke [`Self::ensure_initial`] on boot.
    pub async fn active(&self) -> Result<AuditKey, AppError> {
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
        self.fetch(&key_id).await?.ok_or_else(|| {
            AppError::Internal(format!(
                "active marker points at unknown audit_key {key_id}"
            ))
        })
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
    async fn try_active(&self) -> Result<Option<AuditKey>, AppError> {
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
        self.fetch(&key_id).await
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
