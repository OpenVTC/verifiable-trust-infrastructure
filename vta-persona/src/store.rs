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

use crate::claim_types::{self, Sensitivity};
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

/// How much of a listing's plaintext the caller asked for.
///
/// Three states rather than two booleans, because the fourth combination —
/// sensitive values without values — is not a request. `persona/attribute/list`
/// says `includeSensitive` "widens `includeValues`, and can never be the
/// thing that introduces plaintext on its own"; a pair of booleans lets a call
/// site express the combination anyway and obliges every reader to remember
/// that it means nothing. [`ValueVisibility::from_flags`] performs that
/// collapse once, where the wire members arrive.
///
/// Ordered least revealing first, so a variant added in the wrong place reads
/// wrong rather than merely being wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueVisibility {
    /// Metadata only. The default, and what a picker needs.
    Metadata,
    /// Values, except those resolving to [`Sensitivity::High`].
    Ordinary,
    /// Every value, sensitive ones included.
    All,
}

impl ValueVisibility {
    /// Collapse the two wire members into the three states they can express.
    #[must_use]
    pub fn from_flags(include_values: bool, include_sensitive: bool) -> Self {
        match (include_values, include_sensitive) {
            (false, _) => Self::Metadata,
            (true, false) => Self::Ordinary,
            (true, true) => Self::All,
        }
    }
}

/// The attributes a listing returned, and what it withheld to return them.
///
/// The count travels with the rows because the alternative is deriving it at
/// the call site from an absent `value` — which cannot tell a value withheld
/// for sensitivity from one that was never asked for or one whose credential
/// went stale. Three causes, one symptom; only the store knows which applied.
#[derive(Clone, Debug)]
pub struct Listing {
    pub attributes: Vec<Attribute>,
    /// How many values [`ValueVisibility::Ordinary`] held back. Zero for every
    /// other visibility, including [`ValueVisibility::Metadata`], which
    /// withholds everything for a different reason.
    pub withheld_sensitive: usize,
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
    pub(crate) ks: KeyspaceHandle,
    /// Per-agent key for the correlation index's keyed hash.
    pub(crate) correlation_key: [u8; 32],
    /// Serialises read-modify-write across every scope this store writes. One
    /// lock rather than one per scope: the scopes share a keyspace and the
    /// reverse index spans them, so two locks would have to be taken in a fixed
    /// order by every writer — a rule nothing enforces and a deadlock the first
    /// time somebody forgets.
    pub(crate) write_lock: Arc<Mutex<()>>,
    /// Cached counter, guarded by `write_lock` and re-read from the store on
    /// first use so a restart never reuses a number.
    pub(crate) counter: Arc<Mutex<Option<Version>>>,
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
    pub(crate) async fn next_version(&self) -> Result<Version, AppError> {
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

        let attribute_id = attribute.attribute_id.clone();
        self.ks
            .insert(
                storage::attribute_key(&attribute_id),
                &Slot::Live(attribute),
            )
            .await?;

        // Edit once, everywhere — and it happens HERE, inside the write, not at
        // the call site.
        //
        // A context holds a materialised copy and may never read the pool, so
        // the copy only changes if a write above the boundary pushes it. Leaving
        // that to handlers is the same decision taken once per call site, and
        // forgetting it is silent: the pool shows the new value, the console
        // shows the pool, and the verifier is handed the old one. That is
        // exactly what shipped — nothing called `rematerialise` at all.
        //
        // On a create this is a no-op: nothing references a brand-new attribute
        // yet, so the reverse index is empty and the scan does not run.
        self.push_attribute_locked(&attribute_id).await?;

        Ok(Written { version, created })
    }

    /// Remove one attribute, leaving a tombstone.
    ///
    /// Refuses while a profile refers to it unless `cascade`. Profiles reference
    /// rather than copy, so removing an attribute changes what every referring profile
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

        // A cascade leaves the profile's `ref` in place and the attribute
        // tombstoned, so resolution reports the claim stale rather than
        // dropping it — which is the honest answer, and one the bound contexts
        // must be given too. Without this push they would go on presenting the
        // deleted value as though it were current.
        for profile_id in &referring {
            self.push_profile_locked(profile_id).await?;
        }

        Ok(Deleted {
            existed: true,
            referring_profiles: referring,
        })
    }

    /// Every live attribute, optionally narrowed by vocabulary prefix.
    ///
    /// [`ValueVisibility`] is opt-in because the common case — rendering a
    /// picker so a holder can choose what to compose with — needs type and
    /// label, not plaintext. Making the sensitive path the one a caller has to
    /// ask for means it is never the one they get by forgetting.
    ///
    /// A value withheld for sensitivity leaves its **row** in place: type,
    /// label, provenance, version and staleness all come back. This is
    /// withholding a value, not hiding an attribute — a holder listing their pool
    /// must still see that the card is there, or the control teaches them their
    /// own store has lost something.
    ///
    /// Stale credential-backed attributes are returned carrying their reason
    /// rather than omitted: a pool that looks smaller than it is would leave
    /// the holder unaware that a claim has stopped being presentable.
    pub async fn list_attributes(
        &self,
        type_prefix: Option<&str>,
        values: ValueVisibility,
    ) -> Result<Listing, AppError> {
        let rows = self
            .ks
            .prefix_iter_raw(storage::ATTRIBUTE_PREFIX.as_bytes().to_vec())
            .await?;

        let mut withheld_sensitive = 0usize;
        let attributes = rows
            .into_iter()
            .filter_map(|(_k, v)| match serde_json::from_slice::<Slot>(&v) {
                Ok(Slot::Live(a)) => Some(a),
                _ => None,
            })
            .filter(|a| type_prefix.is_none_or(|p| a.r#type.starts_with(p)))
            .map(|mut a| {
                match values {
                    ValueVisibility::Metadata => a.value = None,
                    ValueVisibility::Ordinary
                        if a.value.is_some()
                            && claim_types::sensitivity_of(&a) == Sensitivity::High =>
                    {
                        // Counted only here, so the count means "the
                        // sensitivity control did this" rather than "no value
                        // came back". A metadata-only listing withholds every
                        // value and none of them for this reason.
                        withheld_sensitive += 1;
                        a.value = None;
                    }
                    ValueVisibility::Ordinary | ValueVisibility::All => {}
                }
                a
            })
            .collect();

        Ok(Listing {
            attributes,
            withheld_sensitive,
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

    /// The attribute ids occupying one blinded index slot — every attribute
    /// holding this exact value.
    ///
    /// `pub(crate)` rather than private because `correlation::analyze` needs
    /// the identifiers themselves, not the count [`Self::correlation_count`]
    /// derives from them. Deliberately not `pub`: outside this crate the only
    /// supported way to ask about a value's reach is the holder-authorized
    /// analyze task, which decides what it is safe to say.
    pub(crate) async fn indexed_ids(&self, blind: &str) -> Result<Vec<Ulid>, AppError> {
        Ok(self
            .ks
            .get::<Vec<Ulid>>(storage::correlation_key(blind))
            .await?
            .unwrap_or_default())
    }

    pub(crate) async fn index_value(
        &self,
        blind: &str,
        attribute_id: &str,
    ) -> Result<(), AppError> {
        let mut ids = self.indexed_ids(blind).await?;
        if !ids.iter().any(|i| i == attribute_id) {
            ids.push(attribute_id.to_string());
            self.ks
                .insert(storage::correlation_key(blind), &ids)
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn unindex_value(
        &self,
        blind: &str,
        attribute_id: &str,
    ) -> Result<(), AppError> {
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
pub(crate) fn check_precondition(
    expected: Option<Version>,
    current: Option<Version>,
) -> Result<(), AppError> {
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

pub(crate) fn now_rfc3339() -> String {
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
        attribute_id: ulid::Ulid::generate().to_string(),
        r#type: r#type.into(),
        value_type,
        value: Some(value),
        label: None,
        provenance,
        stale: None,
        stale_reason: None,
        // Unset, not `normal`: a new attribute records no holder decision, so
        // its sensitivity resolves from the registry every time it is read.
        sensitivity: None,
        // Same, for the same reason.
        release: None,
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

#[cfg(test)]
mod list_tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn fresh_store() -> (tempfile::TempDir, PersonaStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(vta_keyspaces::PERSONA).unwrap();
        (dir, PersonaStore::new(ks, [1u8; 32]))
    }

    async fn store_one(s: &PersonaStore, claim_type: &str, value: &str) -> Attribute {
        let a = new_attribute(
            claim_type,
            ValueType::String,
            serde_json::json!(value),
            Provenance::SelfAsserted,
        );
        s.put(a.clone(), None).await.unwrap();
        a
    }

    /// Find one attribute in a listing by claim type.
    fn of_type<'a>(listing: &'a Listing, claim_type: &str) -> &'a Attribute {
        listing
            .attributes
            .iter()
            .find(|a| a.r#type == claim_type)
            .unwrap_or_else(|| panic!("{claim_type} is missing from the listing"))
    }

    #[tokio::test]
    async fn listing_withholds_values_unless_asked() {
        let (_d, s) = fresh_store().await;
        // `account.handle` resolves to `normal`, so this test is about
        // `includeValues` alone and cannot pass by accident on sensitivity.
        store_one(&s, "account.handle", "ada").await;

        let quiet = s
            .list_attributes(None, ValueVisibility::Metadata)
            .await
            .unwrap();
        assert_eq!(quiet.attributes.len(), 1);
        assert!(
            quiet.attributes[0].value.is_none(),
            "the default must not move plaintext"
        );
        assert_eq!(
            quiet.withheld_sensitive, 0,
            "a metadata listing withholds everything, but not for sensitivity"
        );

        let loud = s
            .list_attributes(None, ValueVisibility::Ordinary)
            .await
            .unwrap();
        assert!(loud.attributes[0].value.is_some());
    }

    #[tokio::test]
    async fn a_prefix_selects_a_vocabulary_family_and_a_tombstone_is_not_listed() {
        let (_d, s) = fresh_store().await;

        let a = store_one(&s, "phone.work", "1").await;
        store_one(&s, "name.legal", "n").await;

        for (prefix, expected) in [(Some("phone"), 1), (Some("name"), 1), (None, 2)] {
            assert_eq!(
                s.list_attributes(prefix, ValueVisibility::Metadata)
                    .await
                    .unwrap()
                    .attributes
                    .len(),
                expected
            );
        }

        s.delete(&a.attribute_id, false).await.unwrap();
        assert_eq!(
            s.list_attributes(Some("phone"), ValueVisibility::Metadata)
                .await
                .unwrap()
                .attributes
                .len(),
            0,
            "a tombstone is not a live attribute"
        );
    }

    /// The control this whole path exists for: a listing that asked for values
    /// still does not carry a sensitive one.
    ///
    /// Paired with its success case below, deliberately. A refusal test alone
    /// passes against an implementation that withholds everything, which is a
    /// picker that shows the holder nothing.
    #[tokio::test]
    async fn a_sensitive_value_is_withheld_from_a_listing_that_asked_only_for_values() {
        let (_d, s) = fresh_store().await;
        store_one(&s, "payment.card", "4242424242424242").await;
        store_one(&s, "name.given", "Ada").await;

        let listing = s
            .list_attributes(None, ValueVisibility::Ordinary)
            .await
            .unwrap();

        assert!(
            of_type(&listing, "payment.card").value.is_none(),
            "a card number left the store on a listing that never asked for \
             sensitive values — masking it afterwards defends a screen and not \
             a log, a crash dump, or this process's memory"
        );
        assert_eq!(
            of_type(&listing, "name.given").value,
            Some(serde_json::json!("Ada")),
            "an ordinary value was withheld too, which is a picker that shows \
             the holder nothing"
        );
        assert_eq!(listing.withheld_sensitive, 1);
    }

    #[tokio::test]
    async fn a_sensitive_value_is_returned_when_the_listing_asked_for_sensitive_values() {
        let (_d, s) = fresh_store().await;
        store_one(&s, "payment.card", "4242424242424242").await;

        let listing = s.list_attributes(None, ValueVisibility::All).await.unwrap();
        assert_eq!(
            of_type(&listing, "payment.card").value,
            Some(serde_json::json!("4242424242424242")),
            "the holder could not read their own card back by asking for it"
        );
        assert_eq!(
            listing.withheld_sensitive, 0,
            "nothing was withheld, so nothing should be counted"
        );
    }

    /// Withholding a value is not hiding an attribute. The row and everything about
    /// it still come back, or a holder listing their own pool would conclude
    /// the store had lost the card.
    #[tokio::test]
    async fn a_withheld_attribute_keeps_its_metadata() {
        let (_d, s) = fresh_store().await;
        let mut card = new_attribute(
            "payment.card",
            ValueType::String,
            serde_json::json!("4242424242424242"),
            Provenance::SelfAsserted,
        );
        card.label = Some("the blue one".into());
        s.put(card.clone(), None).await.unwrap();

        let listing = s
            .list_attributes(None, ValueVisibility::Ordinary)
            .await
            .unwrap();
        let row = of_type(&listing, "payment.card");
        assert_eq!(row.attribute_id, card.attribute_id);
        assert_eq!(row.label.as_deref(), Some("the blue one"));
        assert_eq!(row.value_type, ValueType::String);
        assert!(row.version > 0);
        assert!(row.value.is_none());
    }

    /// `includeSensitive` widens `includeValues`; it is never the member that
    /// introduces plaintext.
    #[tokio::test]
    async fn asking_for_sensitive_values_without_values_asks_for_no_plaintext() {
        assert_eq!(
            ValueVisibility::from_flags(false, true),
            ValueVisibility::Metadata
        );
        assert_eq!(
            ValueVisibility::from_flags(false, false),
            ValueVisibility::Metadata
        );
        assert_eq!(
            ValueVisibility::from_flags(true, false),
            ValueVisibility::Ordinary
        );
        assert_eq!(
            ValueVisibility::from_flags(true, true),
            ValueVisibility::All
        );

        let (_d, s) = fresh_store().await;
        store_one(&s, "payment.card", "4242424242424242").await;
        let listing = s
            .list_attributes(None, ValueVisibility::from_flags(false, true))
            .await
            .unwrap();
        assert!(
            listing.attributes[0].value.is_none(),
            "`includeSensitive` alone introduced plaintext"
        );
    }

    /// The registry decides, and the holder overrules it — both directions, on
    /// the read path rather than only in the classifier's own tests.
    #[tokio::test]
    async fn the_holders_own_sensitivity_decides_what_a_listing_carries() {
        let (_d, s) = fresh_store().await;

        // A type the registry calls ordinary, which the holder does not.
        let mut handle = new_attribute(
            "account.handle",
            ValueType::String,
            serde_json::json!("ada"),
            Provenance::SelfAsserted,
        );
        handle.sensitivity = Some(Sensitivity::High);
        s.put(handle, None).await.unwrap();

        // A type the registry calls sensitive, which the holder does not.
        let mut card = new_attribute(
            "payment.card",
            ValueType::String,
            serde_json::json!("4242424242424242"),
            Provenance::SelfAsserted,
        );
        card.sensitivity = Some(Sensitivity::Normal);
        s.put(card, None).await.unwrap();

        let listing = s
            .list_attributes(None, ValueVisibility::Ordinary)
            .await
            .unwrap();
        assert!(
            of_type(&listing, "account.handle").value.is_none(),
            "the holder marked this sensitive and the listing carried it anyway"
        );
        assert!(
            of_type(&listing, "payment.card").value.is_some(),
            "the holder's own decision about their own pool was overruled"
        );
        assert_eq!(listing.withheld_sensitive, 1);
    }

    /// An unregistered token is withheld, and that is the conservative answer
    /// working rather than a bug. `x:` borrows nothing from the registry.
    #[tokio::test]
    async fn an_unregistered_token_is_withheld_by_default() {
        let (_d, s) = fresh_store().await;
        store_one(&s, "x:loyaltyNumber", "9911").await;
        store_one(&s, "name.somethingNew", "Ada").await;

        let listing = s
            .list_attributes(None, ValueVisibility::Ordinary)
            .await
            .unwrap();
        assert!(of_type(&listing, "x:loyaltyNumber").value.is_none());
        assert!(
            of_type(&listing, "name.somethingNew").value.is_none(),
            "an invented token inherited `name`'s permissiveness — a family \
             entry can only ever tighten"
        );
        assert_eq!(listing.withheld_sensitive, 2);
    }
}
