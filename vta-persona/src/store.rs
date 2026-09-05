//! The attribute pool: read, write, delete, and the indexes that keep the
//! correlation guard and the referential checks answerable.
//!
//! # Why a lock and not a compare-and-swap
//!
//! Read-modify-write is serialised by a process-local lock per store, not by a
//! CAS in the storage layer. That mirrors the conclusion `app-state` reached and
//! for the same reason: there is no reachable multi-writer topology. The local
//! backend takes an exclusive file lock on its directory, so two processes
//! cannot open one store at all; the vsock backend proxies to a single store,
//! and its `swap`/`insert_if_absent` are already *non-atomic* get+insert
//! fallbacks. A CAS added here would be atomic exactly where the lock already
//! suffices, and would still be non-atomic on the proxy that needs it.
//!
//! # Versions
//!
//! One monotonic counter for the store. A record's version is the counter value
//! its most recent write took, which makes the same number serve as both the
//! optimistic-concurrency token and the change-feed watermark. Per-record
//! counters could do the first but not the second, because two records'
//! counters are not comparable to each other.
//!
//! The counter is **reserved before the write it belongs to**. A crash between
//! reserving and writing leaks a number, which is harmless — versions are
//! opaque and monotonic, never an edit count. A crash between writing and
//! reserving would reuse one, which is not.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::correlation;
use crate::model::{Attribute, Provenance, Ulid, ValueType, Version};
use crate::storage;

/// A stored attribute, or the tombstone left where one was.
///
/// Tombstones are what make incremental sync converge. Without them a peer
/// pulling from a watermark learns about every create and update and never
/// learns about a delete, so deleted records resurrect on the next full rebuild
/// and disagree with peers that saw the delete live.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Slot {
    Live(Attribute),
    Tombstone {
        attribute_id: Ulid,
        version: Version,
        deleted_at: String,
        /// The blinded key this attribute occupied, so the correlation index
        /// can be cleaned up without decrypting anything.
        value_blind: String,
    },
}

/// Outcome of a write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Written {
    pub version: Version,
    pub created: bool,
}

/// Outcome of a delete. `existed` distinguishes a removal from a no-op.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deleted {
    pub existed: bool,
    /// Profiles whose entries referred to the attribute.
    pub referring_profiles: Vec<Ulid>,
}

/// The persona store over one keyspace handle.
///
/// The handle carries the at-rest encryption when the deployment provides a
/// key, exactly as the credential vault's does — this layer never encrypts by
/// hand, so there is one at-rest implementation in the workspace rather than
/// two.
pub struct PersonaStore {
    ks: KeyspaceHandle,
    /// Per-agent key for the correlation index's keyed hash.
    correlation_key: [u8; 32],
    /// Serialises read-modify-write. One lock for the agent-scoped pool, which
    /// is the only scope this module writes.
    write_lock: Arc<Mutex<()>>,
    /// Cached counter, guarded by `write_lock` and re-read from the store on
    /// first use so a restart never reuses a number.
    counter: Arc<Mutex<Option<Version>>>,
}

impl PersonaStore {
    #[must_use]
    pub fn new(ks: KeyspaceHandle, correlation_key: [u8; 32]) -> Self {
        Self {
            ks,
            correlation_key,
            write_lock: Arc::new(Mutex::new(())),
            counter: Arc::new(Mutex::new(None)),
        }
    }

    /// Reserve the next version. Caller must hold `write_lock`.
    async fn next_version(&self) -> Result<Version, AppError> {
        let mut cached = self.counter.lock().await;
        let current = match *cached {
            Some(v) => v,
            None => self
                .ks
                .get::<Version>(storage::VERSION_COUNTER_KEY)
                .await?
                .unwrap_or(0),
        };
        let next = current + 1;
        // Persisted before it is handed out. A crash here leaks a number, which
        // is harmless; the opposite order would reuse one, which is not.
        self.ks.insert(storage::VERSION_COUNTER_KEY, &next).await?;
        *cached = Some(next);
        Ok(next)
    }

    /// Read one attribute. `None` for absent or tombstoned — a caller that needs
    /// to tell those apart reads the slot.
    pub async fn get(&self, attribute_id: &str) -> Result<Option<Attribute>, AppError> {
        Ok(match self.slot(attribute_id).await? {
            Some(Slot::Live(a)) => Some(a),
            _ => None,
        })
    }

    pub(crate) async fn slot(&self, attribute_id: &str) -> Result<Option<Slot>, AppError> {
        self.ks
            .get::<Slot>(storage::attribute_key(attribute_id))
            .await
    }

    /// Create or replace one attribute.
    ///
    /// `expected_version` is the optimistic-concurrency precondition: `Some(0)`
    /// means create-only, `Some(n)` requires the record to be at exactly `n`,
    /// `None` is last-writer-wins.
    ///
    /// A failed precondition returns [`AppError::Conflict`] carrying the current
    /// version. A bare rejection would oblige the caller to re-read, and between
    /// the rejection and the re-read the record can change again — the pattern
    /// has no fixed point under contention.
    pub async fn put(
        &self,
        mut attribute: Attribute,
        expected_version: Option<Version>,
    ) -> Result<Written, AppError> {
        if !attribute
            .value
            .as_ref()
            .is_some_and(|v| attribute.value_type.accepts(v))
        {
            return Err(AppError::Validation(format!(
                "value does not agree with declared valueType {:?}",
                attribute.value_type
            )));
        }

        let _guard = self.write_lock.lock().await;
        let existing = self.slot(&attribute.attribute_id).await?;

        let current_version = match &existing {
            Some(Slot::Live(a)) => Some(a.version),
            // A tombstone is not a live record, so create-only succeeds over
            // one. The new record takes the next counter value, necessarily
            // greater than the tombstone's, so a watcher still sees it move
            // forward.
            Some(Slot::Tombstone { .. }) | None => None,
        };
        check_precondition(expected_version, current_version)?;

        let version = self.next_version().await?;
        let created = current_version.is_none();
        attribute.version = version;

        // Index maintenance before the record, so a crash leaves an index entry
        // with no record — which reads as a false positive in the correlation
        // guard — rather than a record with no index entry, which reads as a
        // false ALL-CLEAR. Over-warning is recoverable; under-warning is the
        // failure this guard exists to prevent.
        if let Some(v) = &attribute.value {
            let blind = correlation::blind(&self.correlation_key, v);
            self.index_value(&blind, &attribute.attribute_id).await?;
        }
        if let Some(Slot::Live(old)) = &existing
            && let Some(old_value) = &old.value
        {
            let old_blind = correlation::blind(&self.correlation_key, old_value);
            let new_blind = attribute
                .value
                .as_ref()
                .map(|v| correlation::blind(&self.correlation_key, v));
            if Some(&old_blind) != new_blind.as_ref() {
                self.unindex_value(&old_blind, &attribute.attribute_id)
                    .await?;
            }
        }

        self.ks
            .insert(
                storage::attribute_key(&attribute.attribute_id),
                &Slot::Live(attribute),
            )
            .await?;

        Ok(Written { version, created })
    }

    /// Remove one attribute, leaving a tombstone.
    ///
    /// Refuses while a profile refers to it unless `cascade`. Profiles reference
    /// rather than copy, so removing a fact changes what every referring profile
    /// presents — and doing that silently is the surprise this store exists to
    /// prevent.
    ///
    /// A repeat delete converges: `existed: false`, and deliberately **no new
    /// version**. Had it taken one, every consumer watching the store would see
    /// a change that did not happen, and delete could not be safely retried.
    pub async fn delete(&self, attribute_id: &str, cascade: bool) -> Result<Deleted, AppError> {
        let _guard = self.write_lock.lock().await;

        let referring = self.referring_profiles(attribute_id).await?;
        if !referring.is_empty() && !cascade {
            return Err(AppError::Conflict(format!(
                "attribute {attribute_id} is referenced by {} profile(s); \
                 pass cascade to remove those entries too",
                referring.len()
            )));
        }

        let Some(Slot::Live(existing)) = self.slot(attribute_id).await? else {
            return Ok(Deleted {
                existed: false,
                referring_profiles: Vec::new(),
            });
        };

        let version = self.next_version().await?;
        let value_blind = existing
            .value
            .as_ref()
            .map(|v| correlation::blind(&self.correlation_key, v))
            .unwrap_or_default();

        if !value_blind.is_empty() {
            self.unindex_value(&value_blind, attribute_id).await?;
        }
        for profile_id in &referring {
            self.ks
                .remove(storage::reverse_index_key(attribute_id, profile_id))
                .await?;
        }

        self.ks
            .insert(
                storage::attribute_key(attribute_id),
                &Slot::Tombstone {
                    attribute_id: attribute_id.to_string(),
                    version,
                    deleted_at: now_rfc3339(),
                    value_blind,
                },
            )
            .await?;

        Ok(Deleted {
            existed: true,
            referring_profiles: referring,
        })
    }

    /// Profiles whose entries refer to this attribute, from the reverse index —
    /// so a delete can name them without scanning every profile.
    pub async fn referring_profiles(&self, attribute_id: &str) -> Result<Vec<Ulid>, AppError> {
        let prefix = storage::reverse_index_prefix(attribute_id);
        let keys = self.ks.prefix_keys(prefix.clone().into_bytes()).await?;
        Ok(keys
            .into_iter()
            .filter_map(|k| {
                String::from_utf8(k)
                    .ok()?
                    .strip_prefix(&prefix)
                    .map(str::to_string)
            })
            .collect())
    }

    /// How many *other* attributes share this exact value.
    ///
    /// A count, not identifiers. Returning identifiers on a write would disclose
    /// the holder's other compositions to whatever tool made it; the analyze
    /// task is holder-authorized and is where identifiers belong.
    pub async fn correlation_count(
        &self,
        value: &serde_json::Value,
        excluding: &str,
    ) -> Result<usize, AppError> {
        let blind = correlation::blind(&self.correlation_key, value);
        let ids = self.indexed_ids(&blind).await?;
        Ok(ids.iter().filter(|id| *id != excluding).count())
    }

    async fn indexed_ids(&self, blind: &str) -> Result<Vec<Ulid>, AppError> {
        Ok(self
            .ks
            .get::<Vec<Ulid>>(storage::correlation_key(blind))
            .await?
            .unwrap_or_default())
    }

    async fn index_value(&self, blind: &str, attribute_id: &str) -> Result<(), AppError> {
        let mut ids = self.indexed_ids(blind).await?;
        if !ids.iter().any(|i| i == attribute_id) {
            ids.push(attribute_id.to_string());
            self.ks
                .insert(storage::correlation_key(blind), &ids)
                .await?;
        }
        Ok(())
    }

    async fn unindex_value(&self, blind: &str, attribute_id: &str) -> Result<(), AppError> {
        let mut ids = self.indexed_ids(blind).await?;
        ids.retain(|i| i != attribute_id);
        if ids.is_empty() {
            self.ks.remove(storage::correlation_key(blind)).await?;
        } else {
            self.ks
                .insert(storage::correlation_key(blind), &ids)
                .await?;
        }
        Ok(())
    }
}

/// Apply the optimistic-concurrency precondition.
fn check_precondition(expected: Option<Version>, current: Option<Version>) -> Result<(), AppError> {
    match (expected, current) {
        (None, _) => Ok(()),
        // Create-only.
        (Some(0), None) => Ok(()),
        (Some(0), Some(v)) => Err(AppError::Conflict(format!(
            "expectedVersion 0 means create-only, but a live record exists at version {v}"
        ))),
        (Some(n), Some(v)) if n == v => Ok(()),
        (Some(n), Some(v)) => Err(AppError::Conflict(format!(
            "expectedVersion {n} does not match current version {v}"
        ))),
        (Some(n), None) => Err(AppError::Conflict(format!(
            "expectedVersion {n} but no live record exists"
        ))),
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Build an attribute with server-assigned identity and timestamps.
#[must_use]
pub fn new_attribute(
    r#type: impl Into<String>,
    value_type: ValueType,
    value: serde_json::Value,
    provenance: Provenance,
) -> Attribute {
    let now = now_rfc3339();
    Attribute {
        attribute_id: ulid::Ulid::new().to_string(),
        r#type: r#type.into(),
        value_type,
        value: Some(value),
        label: None,
        provenance,
        stale: None,
        stale_reason: None,
        version: 0,
        created_at: now.clone(),
        updated_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    const KEY: [u8; 32] = [3u8; 32];

    async fn fresh(encrypted: bool) -> (tempfile::TempDir, PersonaStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open");
        let ks = store.keyspace(vta_keyspaces::PERSONA).expect("keyspace");
        let ks = if encrypted {
            ks.with_encryption(KEY)
        } else {
            ks
        };
        (dir, PersonaStore::new(ks, KEY))
    }

    fn sample(value: &str) -> Attribute {
        new_attribute(
            "phone.mobile",
            ValueType::String,
            serde_json::json!(value),
            Provenance::SelfAsserted,
        )
    }

    #[tokio::test]
    async fn value_must_agree_with_its_declared_type() {
        let (_d, s) = fresh(false).await;
        let mut a = sample("+61 4");
        a.value_type = ValueType::Number;
        let err = s.put(a, None).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn versions_advance_and_never_repeat_across_records() {
        let (_d, s) = fresh(false).await;
        let a = s.put(sample("one"), None).await.unwrap();
        let b = s.put(sample("two"), None).await.unwrap();
        assert!(b.version > a.version, "counter is monotonic across records");
        assert!(a.created && b.created);
    }

    #[tokio::test]
    async fn create_only_is_refused_over_a_live_record_and_allowed_over_a_tombstone() {
        let (_d, s) = fresh(false).await;
        let mut a = sample("x");
        s.put(a.clone(), Some(0)).await.expect("first create");

        // Second create-only at the same id must fail: this is what makes lease
        // acquisition safe.
        let err = s.put(a.clone(), Some(0)).await.unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)));

        // A tombstone is not a live record, so create-only succeeds over one.
        s.delete(&a.attribute_id, false).await.expect("delete");
        a.value = Some(serde_json::json!("y"));
        s.put(a, Some(0)).await.expect("create over tombstone");
    }

    #[tokio::test]
    async fn a_repeat_delete_converges_and_takes_no_new_version() {
        let (_d, s) = fresh(false).await;
        let a = sample("x");
        s.put(a.clone(), None).await.unwrap();

        let first = s.delete(&a.attribute_id, false).await.unwrap();
        assert!(first.existed);

        // The second finds a tombstone. If it took a version, every consumer
        // watching the store would see a change that did not happen — and
        // delete could not be safely retried.
        let before = s.put(sample("probe"), None).await.unwrap().version;
        let second = s.delete(&a.attribute_id, false).await.unwrap();
        assert!(!second.existed);
        let after = s.put(sample("probe2"), None).await.unwrap().version;
        assert_eq!(after, before + 1, "the no-op delete consumed no version");
    }

    #[tokio::test]
    async fn correlation_sees_reuse_and_forgets_it_on_delete() {
        let (_d, s) = fresh(false).await;
        let a = sample("+61 4xx");
        let b = sample("+61 4xx"); // same value, different attribute
        s.put(a.clone(), None).await.unwrap();
        s.put(b.clone(), None).await.unwrap();

        let v = serde_json::json!("+61 4xx");
        assert_eq!(s.correlation_count(&v, &a.attribute_id).await.unwrap(), 1);

        s.delete(&b.attribute_id, false).await.unwrap();
        assert_eq!(
            s.correlation_count(&v, &a.attribute_id).await.unwrap(),
            0,
            "a deleted attribute must stop counting as reuse"
        );
    }

    #[tokio::test]
    async fn editing_a_value_moves_its_index_entry() {
        let (_d, s) = fresh(false).await;
        let mut a = sample("old");
        s.put(a.clone(), None).await.unwrap();

        a.value = Some(serde_json::json!("new"));
        s.put(a.clone(), None).await.unwrap();

        // The old value must no longer count as reuse, or the guard reports a
        // link the holder already removed.
        assert_eq!(
            s.correlation_count(&serde_json::json!("old"), "other")
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            s.correlation_count(&serde_json::json!("new"), "other")
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn the_value_is_encrypted_at_rest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open");
        let enc = store
            .keyspace(vta_keyspaces::PERSONA)
            .unwrap()
            .with_encryption(KEY);
        let s = PersonaStore::new(enc, KEY);

        let a = sample("+61 4xx xxx 001");
        s.put(a.clone(), None).await.unwrap();

        // A second, PLAIN handle on the same keyspace reads the on-disk bytes.
        let plain = store.keyspace(vta_keyspaces::PERSONA).unwrap();
        let raw = plain
            .get_raw(storage::attribute_key(&a.attribute_id))
            .await
            .unwrap()
            .expect("row present");
        let as_text = String::from_utf8_lossy(&raw);
        assert!(
            !as_text.contains("+61 4xx xxx 001"),
            "the value must not be readable without the at-rest key"
        );
    }
}
