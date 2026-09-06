//! Application-state store (operations layer) — versioned, namespaced,
//! per-context JSON an application owns and the VTA does not interpret.
//!
//! Backs the `vta/app-state/{get,put,list,delete,get-many,put-many}/1.0` Trust
//! Tasks (`crate::trust_tasks::app_state`). The transport/auth ceremony (the
//! context-ACL gate, audit) stays in the trust-task handler; this module owns
//! the store operations and the invariants below.
//!
//! ## Layout
//!
//! Everything lives in the [`APP_STATE`](crate::keyspaces::APP_STATE) keyspace,
//! four record families distinguished by prefix. Context ids are
//! `[A-Za-z0-9._-]` plus `/` and namespaces are `[a-z0-9-]`, so neither can
//! contain the `:` delimiter and every prefix below is unambiguous.
//!
//! | Key | Value |
//! |---|---|
//! | `app:<ctx>:<ns>:<key>` | [`StoredRecord`] — the record, live or tombstoned |
//! | `appv:<ctx>:<ns>:<version:020>` | the record key that version belongs to |
//! | `appc:<ctx>:<ns>` | the namespace's write counter |
//! | `appt:<ctx>:<ns>` | highest version whose tombstones have been reaped |
//!
//! ## The version counter, and why it is per namespace
//!
//! One counter per `(contextId, namespace)`. Every write takes its next value,
//! and a record's `version` is the value its most recent write took.
//!
//! This is the design's load-bearing choice. A *per-record* counter would serve
//! `expectedVersion` perfectly well, but could not serve `sinceVersion` at all:
//! two records' per-record counters are not comparable to each other, so no
//! single number could mean "everything changed after this point", and
//! incremental sync would need a second sequence anyway. One counter answers
//! both questions. The cost is that a record's version jumps by however many
//! values its neighbours consumed — which is why the wire contract states that
//! versions are opaque and monotonic, never an edit count.
//!
//! ## The version index, and why a scan-and-sort will not do
//!
//! `appv:` maps counter values to record keys, exactly one entry per record
//! (its *current* version), tombstones included. A change feed is therefore a
//! range scan from `sinceVersion + 1`, already in version order.
//!
//! Deriving the same answer by scanning `app:` and sorting would be correct but
//! unpaginatable: [`vti_common::pagination`] cursors carry a *storage key* and
//! resume strictly after it, so the ordering has to exist in the store rather
//! than in a sort applied afterwards. Maintaining the index costs one extra
//! delete+insert per write, under the same lock.
//!
//! ## Atomicity
//!
//! Read-modify-write sequences (check the precondition, take a counter value,
//! rewrite the index) are guarded by [`NamespaceLocks`], one lock per
//! `(contextId, namespace)`. The store's own write lock serialises *individual*
//! operations, not sequences of them, and there is no transaction primitive to
//! reach for — so the lock lives here, in the one process that writes.
//!
//! That is sound for the VTA's deployment shape: a single service owns its
//! fjall store, and the enclave build proxies to one store over vsock from one
//! writer. It would **not** be sound for two VTA processes sharing a store,
//! which nothing does today; making it so needs a compare-and-swap in the store
//! layer, not a bigger lock here.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use vta_sdk::protocols::app_state::{
    AppStateRecord, AppStateWrite, PutManyMode, WriteOutcome, WriteResult,
};
use vti_common::pagination::{Cursor, CursorKey, MAX_LIMIT, paginate};

use crate::error::AppError;
use crate::store::KeyspaceHandle;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Per-record value cap, in bytes of the value's compact JSON encoding.
///
/// The published specification RECOMMENDS this number and requires only that a
/// maintainer enforce a *documented* cap and refuse loudly. 64 KiB is chosen to
/// sit far enough under the 1 MB request-body ceiling that a full 64-write
/// batch is still expressible, while being generous for what the store is for
/// — labels, relationships, contacts, join history.
///
/// The requirement that matters is the loudness, not the number: a limit that
/// drops a write silently has already cost a real deployment a lost join.
pub const MAX_VALUE_BYTES: u64 = 65_536;

/// Maximum keys in one `get-many`. Matches the published schema's `maxItems`.
pub const MAX_GET_MANY_KEYS: usize = 256;

/// Maximum writes in one `put-many`. Matches the published schema's `maxItems`.
pub const MAX_PUT_MANY_WRITES: usize = 64;

/// Response budget for `get-many`, in bytes of returned value.
///
/// [`MAX_VALUE_BYTES`] × [`MAX_GET_MANY_KEYS`] is 16 MiB, far past any sane
/// response ceiling, so a maintainer must be able to return a partial batch.
/// Keys past this budget come back as `deferred` rather than as an error: the
/// alternative — refusing the whole batch — makes a caller bisect for a
/// workable size, which it cannot compute without knowing the values' sizes.
pub const GET_MANY_RESPONSE_BUDGET_BYTES: u64 = 512 * 1024;

/// Aggregate request budget for `put-many`, in bytes of submitted value.
pub const PUT_MANY_REQUEST_BUDGET_BYTES: u64 = 768 * 1024;

/// Default tombstone retention, in seconds (30 days).
///
/// The operative value is `config.app_state.tombstone_retention_days`; this is
/// only the fallback for call sites with no config to hand (tests, offline
/// tooling). Matches the vault's grace window, which the specification calls a
/// starting point to revisit on evidence.
pub const DEFAULT_TOMBSTONE_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Namespace grammar, matching the published schema's `pattern`.
fn namespace_is_valid(ns: &str) -> bool {
    if ns.is_empty() || ns.len() > 64 {
        return false;
    }
    let bytes = ns.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut prev_hyphen = false;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'a'..=b'z' | b'0'..=b'9' => prev_hyphen = false,
            b'-' => {
                // No leading, trailing, or consecutive hyphens.
                if prev_hyphen || i + 1 == bytes.len() {
                    return false;
                }
                prev_hyphen = true;
            }
            _ => return false,
        }
    }
    true
}

/// Key grammar: 1–512 bytes, no NUL. Otherwise opaque — the store never
/// parses, normalises, or case-folds a key, and `/` is a convention between an
/// application and itself.
fn key_is_valid(key: &str) -> bool {
    !key.is_empty() && key.len() <= 512 && !key.contains('\0')
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an `expectedVersion` precondition failed. Mirrors the published
/// `detailsSchema` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ConflictReason {
    /// A positive `expectedVersion` did not match the live record's version.
    VersionMismatch,
    /// `expectedVersion: 0` ("create only") but a live record exists.
    RecordExists,
    /// A positive `expectedVersion` but no live record exists.
    RecordAbsent,
    /// `expectedVersion: 0` on a delete — never satisfiable, never intended.
    CreateOnlyNotApplicable,
}

/// Why a `list` request's members cannot be answered together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FilterConflict {
    /// `sinceVersion` without `namespace`: the counter is per namespace, so a
    /// watermark spanning namespaces names no single point in time.
    SinceVersionRequiresNamespace,
    /// `sinceVersion` with `includeDeleted: false`: a change feed that omits
    /// deletions cannot converge, so this is a contradiction, not a preference.
    ChangeFeedCannotExcludeDeleted,
}

/// Failures the application-state operations raise, mapped by the trust-task
/// handler onto the published error taxonomy.
#[derive(Debug)]
pub enum AppStateError {
    /// No record at the address (`get`), or a `mergePatch` with nothing to
    /// apply to (`put`).
    NotFound,
    /// An `expectedVersion` precondition failed. Carries the VTA's current
    /// version **and value** so the caller resolves without a re-read — a bare
    /// rejection has no fixed point under contention.
    VersionConflict {
        reason: ConflictReason,
        current_version: Option<u64>,
        current_value: Option<Value>,
        current_deleted: Option<bool>,
    },
    /// The value exceeded [`MAX_VALUE_BYTES`].
    ValueTooLarge { limit_bytes: u64, actual_bytes: u64 },
    /// The `list` filters cannot be answered together.
    FilterConflict(FilterConflict),
    /// `sinceVersion` predates the oldest retained tombstone, so a feed from it
    /// would omit deletions. The consumer must rebuild from a snapshot.
    WatermarkTooOld {
        oldest_retained_version: u64,
        high_watermark: u64,
    },
    /// A batch named the same key twice.
    DuplicateKey(Vec<String>),
    /// An atomic batch did not apply. Carries the per-record outcomes so the
    /// caller learns which write blocked it, and which were merely skipped.
    AtomicBatchRejected(Vec<WriteResult>),
    /// The batch's aggregate size exceeds what one request may carry.
    BatchTooLarge { limit_bytes: u64, actual_bytes: u64 },
    /// A malformed request the schema did not catch (bad namespace, bad key,
    /// both/neither of `value` and `mergePatch`, too many items).
    Validation(String),
    /// A store or encoding failure.
    Internal(String),
}

impl std::fmt::Display for AppStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no record at that address"),
            Self::VersionConflict {
                reason,
                current_version,
                ..
            } => match (reason, current_version) {
                (ConflictReason::VersionMismatch, Some(v)) => {
                    write!(
                        f,
                        "record is at version {v}; the supplied expectedVersion did not match"
                    )
                }
                (ConflictReason::RecordExists, Some(v)) => {
                    write!(
                        f,
                        "expectedVersion 0 requires no live record, but one exists at version {v}"
                    )
                }
                (ConflictReason::RecordAbsent, _) => {
                    write!(f, "expectedVersion was supplied but no live record exists")
                }
                (ConflictReason::CreateOnlyNotApplicable, _) => write!(
                    f,
                    "expectedVersion 0 is not applicable to a delete: a create-only \
                     precondition on a removal can never be satisfied"
                ),
                (ConflictReason::VersionMismatch | ConflictReason::RecordExists, None) => {
                    write!(f, "the supplied expectedVersion did not match")
                }
            },
            Self::ValueTooLarge {
                limit_bytes,
                actual_bytes,
            } => write!(
                f,
                "value is {actual_bytes} bytes; this VTA's per-record cap is {limit_bytes}"
            ),
            Self::FilterConflict(FilterConflict::SinceVersionRequiresNamespace) => write!(
                f,
                "sinceVersion requires namespace: the version counter is per (contextId, \
                 namespace), so a watermark spanning namespaces names no single point in time"
            ),
            Self::FilterConflict(FilterConflict::ChangeFeedCannotExcludeDeleted) => write!(
                f,
                "a change feed cannot exclude tombstones: without them a consumer never \
                 learns of a deletion and its copy cannot converge"
            ),
            Self::WatermarkTooOld {
                oldest_retained_version,
                ..
            } => write!(
                f,
                "tombstones before version {oldest_retained_version} have been reaped; \
                 resume from a snapshot rather than this watermark"
            ),
            Self::DuplicateKey(keys) => {
                write!(f, "duplicate keys in one batch: {}", keys.join(", "))
            }
            Self::AtomicBatchRejected(_) => {
                write!(f, "atomic batch not applied; nothing was written")
            }
            Self::BatchTooLarge {
                limit_bytes,
                actual_bytes,
            } => write!(
                f,
                "batch is {actual_bytes} bytes; this VTA accepts {limit_bytes} per request"
            ),
            Self::Validation(m) => write!(f, "{m}"),
            Self::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl From<AppError> for AppStateError {
    fn from(e: AppError) -> Self {
        match e {
            AppError::InvalidCursor => {
                Self::Validation("cursor is not valid for this query".into())
            }
            other => Self::Internal(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-namespace serialisation
// ---------------------------------------------------------------------------

/// One async lock per `(contextId, namespace)`, guarding the read-modify-write
/// sequences the store cannot make atomic on its own. See the module docs for
/// why this lives here and what it does not cover.
#[derive(Clone, Default)]
pub struct NamespaceLocks {
    inner: Arc<StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
}

impl NamespaceLocks {
    /// Acquire the lock for one namespace, creating it on first use.
    pub async fn acquire(&self, context_id: &str, namespace: &str) -> OwnedMutexGuard<()> {
        let name = format!("{context_id}\u{0}{namespace}");
        let lock = {
            let mut map = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(map.entry(name).or_default())
        };
        lock.lock_owned().await
    }
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

fn record_key(context_id: &str, namespace: &str, key: &str) -> String {
    format!("app:{context_id}:{namespace}:{key}")
}

fn namespace_prefix(context_id: &str, namespace: &str) -> String {
    format!("app:{context_id}:{namespace}:")
}

fn context_prefix(context_id: &str) -> String {
    format!("app:{context_id}:")
}

/// Version-index key. Zero-padded to 20 digits so lexicographic order over the
/// storage key is numeric order over the version — `u64::MAX` is 20 digits.
fn index_key(context_id: &str, namespace: &str, version: u64) -> String {
    format!("appv:{context_id}:{namespace}:{version:020}")
}

fn index_prefix(context_id: &str, namespace: &str) -> String {
    format!("appv:{context_id}:{namespace}:")
}

fn counter_key(context_id: &str, namespace: &str) -> String {
    format!("appc:{context_id}:{namespace}")
}

fn reaped_key(context_id: &str, namespace: &str) -> String {
    format!("appt:{context_id}:{namespace}")
}

// ---------------------------------------------------------------------------
// Stored shape
// ---------------------------------------------------------------------------

/// The stored value for one record.
///
/// The address is held verbatim rather than parsed back out of the storage key.
/// Context ids may contain `/` and keys may contain `:`, so splitting a storage
/// key is ambiguous in general — the memory store learned the same lesson.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRecord {
    context_id: String,
    namespace: String,
    key: String,
    version: u64,
    deleted: bool,
    /// The stored value, **always present**.
    ///
    /// Deliberately not `Option<Value>`: serde deserializes a present `null`
    /// into `None`, so an application that legitimately stores the JSON literal
    /// null would read it back as an absent value — exactly the conflation the
    /// wire contract forbids. `deleted` is the only thing that distinguishes a
    /// tombstone, and a tombstone simply carries `Null` here and never emits a
    /// value on the wire.
    #[serde(default)]
    value: Value,
    value_bytes: u64,
    created_at: String,
    updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deleted_at: Option<String>,
}

impl StoredRecord {
    /// Project to the wire shape. `with_value` false yields the metadata view;
    /// a tombstone never carries a value regardless.
    fn to_wire(&self, with_value: bool) -> AppStateRecord {
        AppStateRecord {
            context_id: self.context_id.clone(),
            namespace: self.namespace.clone(),
            key: self.key.clone(),
            version: self.version,
            deleted: self.deleted,
            value: (with_value && !self.deleted).then(|| self.value.clone()),
            value_bytes: (!self.deleted).then_some(self.value_bytes),
            created_at: Some(self.created_at.clone()),
            updated_at: self.updated_at.clone(),
            deleted_at: self.deleted_at.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

async fn read_record(
    ks: &KeyspaceHandle,
    context_id: &str,
    namespace: &str,
    key: &str,
) -> Result<Option<StoredRecord>, AppStateError> {
    let raw = ks.get_raw(record_key(context_id, namespace, key)).await?;
    match raw {
        None => Ok(None),
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| AppStateError::Internal(format!("decode app-state record: {e}"))),
    }
}

async fn read_counter(
    ks: &KeyspaceHandle,
    context_id: &str,
    namespace: &str,
) -> Result<u64, AppStateError> {
    read_u64(ks, counter_key(context_id, namespace)).await
}

async fn read_reaped_through(
    ks: &KeyspaceHandle,
    context_id: &str,
    namespace: &str,
) -> Result<u64, AppStateError> {
    read_u64(ks, reaped_key(context_id, namespace)).await
}

async fn read_u64(ks: &KeyspaceHandle, key: String) -> Result<u64, AppStateError> {
    match ks.get_raw(key).await? {
        None => Ok(0),
        Some(bytes) => {
            let text = std::str::from_utf8(&bytes)
                .map_err(|e| AppStateError::Internal(format!("counter is not UTF-8: {e}")))?;
            text.parse()
                .map_err(|e| AppStateError::Internal(format!("counter is not a u64: {e}")))
        }
    }
}

async fn write_u64(ks: &KeyspaceHandle, key: String, value: u64) -> Result<(), AppStateError> {
    ks.insert_raw(key, value.to_string().into_bytes()).await?;
    Ok(())
}

/// Reserve `count` consecutive version numbers for a namespace, returning the
/// first. The caller holds the namespace lock.
///
/// **The reservation is fsynced before it is returned**, and this is the whole
/// point of the function rather than an aside. `vti_common::store::counter`
/// makes the argument for BIP-32 path counters and it transfers exactly: a
/// counter that survives only in the journal buffer can be re-derived after a
/// crash, handing out an already-used value. Here an already-used *version*
/// means two records land on one `appv:` index key — so one of them vanishes
/// from the change feed, and every consumer syncing incrementally misses that
/// change permanently, with nothing to signal it happened. A wasted version is
/// a harmless gap; a reused one is silent data loss.
///
/// Re-sealing the TEE integrity manifest is the same argument against rollback
/// rather than against a crash: a snapshot restored behind the live counter
/// would hand out used versions on purpose. No-op outside a TEE.
///
/// Reserving a **block** exists so a batch pays one fsync instead of N, which
/// mirrors `counter::allocate_u32_block` and is why `put_many` can afford to be
/// durable. Writes that then fail leave their reserved versions unused, which
/// is safe for the reason above.
async fn reserve_versions(
    ks: &KeyspaceHandle,
    context_id: &str,
    namespace: &str,
    count: u64,
) -> Result<u64, AppStateError> {
    let current = read_counter(ks, context_id, namespace).await?;
    let first = current + 1;
    write_u64(ks, counter_key(context_id, namespace), current + count).await?;
    ks.persist().await?;
    vti_common::integrity::reseal_if_active()
        .await
        .map_err(|e| AppStateError::Internal(format!("reseal after version reservation: {e}")))?;
    Ok(first)
}

/// Compact-JSON byte length of a value, which is what the per-record cap is
/// measured over.
fn value_size(value: &Value) -> u64 {
    serde_json::to_vec(value)
        .map(|v| v.len() as u64)
        .unwrap_or(0)
}

/// RFC 7386 JSON Merge Patch.
///
/// Implemented here rather than pulled in as a dependency: the algorithm is
/// fifteen lines and fully specified, and the workspace's dependency policy
/// does not spend a supply-chain edge on that.
///
/// The rule that surprises people is the third arm — a member whose patch value
/// is `null` is **removed**, which is also why a patch cannot set a member to
/// the JSON literal null.
fn merge_patch(target: &mut Value, patch: &Value) {
    match patch {
        Value::Object(patch_map) => {
            if !target.is_object() {
                *target = Value::Object(serde_json::Map::new());
            }
            let target_map = target.as_object_mut().expect("just made it an object");
            for (k, v) in patch_map {
                if v.is_null() {
                    target_map.remove(k);
                } else {
                    let entry = target_map.entry(k.clone()).or_insert(Value::Null);
                    merge_patch(entry, v);
                }
            }
        }
        // A non-object patch replaces the target wholesale.
        other => *target = other.clone(),
    }
}

fn validate_address(namespace: &str, key: &str) -> Result<(), AppStateError> {
    if !namespace_is_valid(namespace) {
        return Err(AppStateError::Validation(format!(
            "namespace `{namespace}` is not a valid partition name \
             (lowercase alphanumeric with single interior hyphens, 1-64 bytes)"
        )));
    }
    if !key_is_valid(key) {
        return Err(AppStateError::Validation(
            "key must be 1-512 bytes and must not contain NUL".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// get
// ---------------------------------------------------------------------------

/// Read one record. Returns [`AppStateError::NotFound`] when the address holds
/// nothing, and when it holds a tombstone that `include_deleted` did not ask
/// for.
pub async fn get(
    ks: &KeyspaceHandle,
    context_id: &str,
    namespace: &str,
    key: &str,
    include_deleted: bool,
) -> Result<AppStateRecord, AppStateError> {
    validate_address(namespace, key)?;
    match read_record(ks, context_id, namespace, key).await? {
        Some(r) if !r.deleted || include_deleted => Ok(r.to_wire(true)),
        _ => Err(AppStateError::NotFound),
    }
}

/// Read many records in one pass, accounting for every requested key.
///
/// Returns `(records, missing, deferred)`. `deferred` names keys not evaluated
/// because [`GET_MANY_RESPONSE_BUDGET_BYTES`] was reached; keys are evaluated
/// in request order so that a caller re-requesting `deferred` makes forward
/// progress rather than receiving an arbitrary subset each time.
pub async fn get_many(
    ks: &KeyspaceHandle,
    context_id: &str,
    namespace: &str,
    keys: &[String],
    include_deleted: bool,
) -> Result<(Vec<AppStateRecord>, Vec<String>, Vec<String>), AppStateError> {
    if keys.is_empty() || keys.len() > MAX_GET_MANY_KEYS {
        return Err(AppStateError::Validation(format!(
            "keys must hold between 1 and {MAX_GET_MANY_KEYS} entries"
        )));
    }
    let mut seen = HashSet::with_capacity(keys.len());
    let mut dupes = Vec::new();
    for k in keys {
        if !seen.insert(k.as_str()) {
            dupes.push(k.clone());
        }
    }
    if !dupes.is_empty() {
        dupes.sort();
        dupes.dedup();
        return Err(AppStateError::DuplicateKey(dupes));
    }
    for k in keys {
        validate_address(namespace, k)?;
    }

    let mut records = Vec::new();
    let mut missing = Vec::new();
    let mut deferred = Vec::new();
    let mut budget = GET_MANY_RESPONSE_BUDGET_BYTES;

    for key in keys {
        if !deferred.is_empty() {
            // Once the budget is spent, everything after it defers — evaluating
            // a later small record out of order would break the forward-progress
            // guarantee a caller relies on when it re-requests.
            deferred.push(key.clone());
            continue;
        }
        match read_record(ks, context_id, namespace, key).await? {
            Some(r) if !r.deleted || include_deleted => {
                if r.value_bytes > budget && !records.is_empty() {
                    deferred.push(key.clone());
                    continue;
                }
                budget = budget.saturating_sub(r.value_bytes);
                records.push(r.to_wire(true));
            }
            _ => missing.push(key.clone()),
        }
    }
    Ok((records, missing, deferred))
}

// ---------------------------------------------------------------------------
// put
// ---------------------------------------------------------------------------

/// What one applied write produced.
#[derive(Debug, Clone)]
pub struct PutOutcome {
    pub version: u64,
    pub created: bool,
    pub updated_at: String,
    pub value_bytes: u64,
}

/// Write one record at an already-reserved `version`.
///
/// Caller **must** hold the namespace lock ([`NamespaceLocks::acquire`]) and
/// must have reserved `version` via [`reserve_versions`]. Neither is done here,
/// so that [`put_many`] can hold the lock across a whole batch and pay a single
/// fsync for the whole block of versions it reserves.
///
/// A failure after reservation leaves `version` unused. That is deliberate and
/// safe — see [`reserve_versions`] for why a gap costs nothing and a reuse
/// costs a change off the feed.
#[allow(clippy::too_many_arguments)]
async fn put_locked(
    ks: &KeyspaceHandle,
    context_id: &str,
    namespace: &str,
    key: &str,
    value: Option<&Value>,
    patch: Option<&Value>,
    expected_version: Option<u64>,
    version: u64,
    now: &str,
) -> Result<PutOutcome, AppStateError> {
    validate_address(namespace, key)?;

    let existing = read_record(ks, context_id, namespace, key).await?;
    let live = existing.as_ref().filter(|r| !r.deleted);

    // Precondition. A tombstone is not a live record: `expectedVersion: 0`
    // succeeds over one, and the new record takes a counter value necessarily
    // greater than the tombstone's.
    match expected_version {
        None => {}
        Some(0) => {
            if let Some(cur) = live {
                return Err(AppStateError::VersionConflict {
                    reason: ConflictReason::RecordExists,
                    current_version: Some(cur.version),
                    current_value: Some(cur.value.clone()),
                    current_deleted: None,
                });
            }
        }
        Some(want) => match live {
            None => {
                return Err(AppStateError::VersionConflict {
                    reason: ConflictReason::RecordAbsent,
                    current_version: existing.as_ref().map(|r| r.version),
                    current_value: None,
                    current_deleted: existing.as_ref().map(|r| r.deleted),
                });
            }
            Some(cur) if cur.version != want => {
                return Err(AppStateError::VersionConflict {
                    reason: ConflictReason::VersionMismatch,
                    current_version: Some(cur.version),
                    current_value: Some(cur.value.clone()),
                    current_deleted: None,
                });
            }
            Some(_) => {}
        },
    }

    // Resolve the new value.
    let new_value = match (value, patch) {
        (Some(v), None) => v.clone(),
        (None, Some(p)) => {
            let Some(cur) = live else {
                // A patch has nothing to apply to. Refused rather than treated
                // as a create: RFC 7386 against a null target would silently
                // invent a record from the patch minus its nulls.
                return Err(AppStateError::NotFound);
            };
            let mut base = cur.value.clone();
            merge_patch(&mut base, p);
            base
        }
        _ => {
            return Err(AppStateError::Validation(
                "exactly one of `value` or `mergePatch` must be supplied".into(),
            ));
        }
    };

    let size = value_size(&new_value);
    if size > MAX_VALUE_BYTES {
        return Err(AppStateError::ValueTooLarge {
            limit_bytes: MAX_VALUE_BYTES,
            actual_bytes: size,
        });
    }

    let next = version;
    let created = live.is_none();
    let created_at = existing
        .as_ref()
        .map(|r| r.created_at.clone())
        .filter(|_| !created)
        .unwrap_or_else(|| now.to_string());

    let record = StoredRecord {
        context_id: context_id.to_string(),
        namespace: namespace.to_string(),
        key: key.to_string(),
        version: next,
        deleted: false,
        value: new_value,
        value_bytes: size,
        created_at,
        updated_at: now.to_string(),
        deleted_at: None,
    };

    // The counter was already advanced and fsynced by `reserve_versions`
    // before this function was called, so `next` cannot be handed out twice
    // even across a crash here. What remains is index-then-record: a crash
    // between them leaves an index entry pointing at a record still holding
    // its previous version, which the change feed resolves to a real record
    // and may therefore deliver twice. At-least-once is the failure this
    // design accepts throughout; losing a change is the one it does not.
    if let Some(prev) = existing.as_ref() {
        ks.remove(index_key(context_id, namespace, prev.version))
            .await?;
    }
    ks.insert_raw(
        index_key(context_id, namespace, next),
        key.as_bytes().to_vec(),
    )
    .await?;
    ks.insert(record_key(context_id, namespace, key), &record)
        .await?;

    Ok(PutOutcome {
        version: next,
        created,
        updated_at: now.to_string(),
        value_bytes: size,
    })
}

/// Write one record, taking the namespace lock.
pub async fn put(
    ks: &KeyspaceHandle,
    locks: &NamespaceLocks,
    context_id: &str,
    namespace: &str,
    key: &str,
    value: Option<&Value>,
    patch: Option<&Value>,
    expected_version: Option<u64>,
) -> Result<PutOutcome, AppStateError> {
    // Validate before reserving. A reservation is a durable write, so a
    // malformed namespace would otherwise leave an `appc:` counter behind for
    // an address that can never hold a record.
    validate_address(namespace, key)?;

    let _guard = locks.acquire(context_id, namespace).await;
    let now = Utc::now().to_rfc3339();
    let version = reserve_versions(ks, context_id, namespace, 1).await?;
    put_locked(
        ks,
        context_id,
        namespace,
        key,
        value,
        patch,
        expected_version,
        version,
        &now,
    )
    .await
}

// ---------------------------------------------------------------------------
// put-many
// ---------------------------------------------------------------------------

/// Apply a batch of writes.
///
/// In [`PutManyMode::Independent`] every write applies on its own merits and
/// the per-record outcomes are the answer. In [`PutManyMode::Atomic`] the batch
/// is **dry-run first** — every precondition and size check evaluated against
/// the store before anything is written — and applied only if all pass;
/// otherwise nothing is written and [`AppStateError::AtomicBatchRejected`]
/// carries the outcomes, `Skipped` for the writes never attempted.
///
/// The dry run is what makes "all or none" real without a store transaction:
/// nothing else touches the namespace while the lock is held, so a check that
/// passes in the dry run still passes in the apply.
pub async fn put_many(
    ks: &KeyspaceHandle,
    locks: &NamespaceLocks,
    context_id: &str,
    namespace: &str,
    writes: &[AppStateWrite],
    mode: PutManyMode,
) -> Result<(Vec<WriteResult>, u64), AppStateError> {
    if writes.is_empty() || writes.len() > MAX_PUT_MANY_WRITES {
        return Err(AppStateError::Validation(format!(
            "writes must hold between 1 and {MAX_PUT_MANY_WRITES} entries"
        )));
    }
    let mut seen = HashSet::with_capacity(writes.len());
    let mut dupes = Vec::new();
    for w in writes {
        if !seen.insert(w.key.as_str()) {
            dupes.push(w.key.clone());
        }
    }
    if !dupes.is_empty() {
        dupes.sort();
        dupes.dedup();
        return Err(AppStateError::DuplicateKey(dupes));
    }

    for w in writes {
        validate_address(namespace, &w.key)?;
    }

    let submitted: u64 = writes
        .iter()
        .map(|w| {
            w.value
                .as_ref()
                .or(w.merge_patch.as_ref())
                .map(value_size)
                .unwrap_or(0)
        })
        .sum();
    if submitted > PUT_MANY_REQUEST_BUDGET_BYTES {
        return Err(AppStateError::BatchTooLarge {
            limit_bytes: PUT_MANY_REQUEST_BUDGET_BYTES,
            actual_bytes: submitted,
        });
    }

    let _guard = locks.acquire(context_id, namespace).await;
    let now = Utc::now().to_rfc3339();

    if mode == PutManyMode::Atomic {
        // Dry run: find the first write that would fail, and report every
        // other write as `Skipped` so the caller can see that a retry does not
        // need its create-only preconditions rewritten.
        if let Some(failed_at) = dry_run_atomic(ks, context_id, namespace, writes).await? {
            let results = writes
                .iter()
                .enumerate()
                .map(|(i, w)| {
                    if i == failed_at.index {
                        failed_at.result.clone()
                    } else {
                        WriteResult {
                            key: w.key.clone(),
                            outcome: WriteOutcome::Skipped,
                            version: None,
                            created: None,
                            current_version: None,
                            current_value: None,
                            current_deleted: None,
                            limit_bytes: None,
                            actual_bytes: None,
                        }
                    }
                })
                .collect();
            return Err(AppStateError::AtomicBatchRejected(results));
        }
    }

    // One reservation, one fsync, for the whole batch — the reason
    // `reserve_versions` takes a count. Writes that then conflict leave their
    // reserved versions unused, which is a gap and therefore safe.
    let first = reserve_versions(ks, context_id, namespace, writes.len() as u64).await?;

    let mut results = Vec::with_capacity(writes.len());
    for (i, w) in writes.iter().enumerate() {
        let outcome = put_locked(
            ks,
            context_id,
            namespace,
            &w.key,
            w.value.as_ref(),
            w.merge_patch.as_ref(),
            w.expected_version,
            first + i as u64,
            &now,
        )
        .await;
        results.push(write_result(&w.key, outcome)?);
    }
    let high = read_counter(ks, context_id, namespace).await?;
    Ok((results, high))
}

/// One write's dry-run failure.
struct DryRunFailure {
    index: usize,
    result: WriteResult,
}

/// Evaluate every write's precondition and size against the store without
/// writing. Returns the first failure, or `None` when the whole batch would
/// apply.
///
/// Preconditions are evaluated against the *stored* state, not against the
/// batch's own intermediate states. Two writes in one atomic batch therefore
/// cannot chain (`expectedVersion` on the second naming the version the first
/// would produce) — the keys are distinct so no write in a batch can observe
/// another, which is what makes evaluating them all up-front sound.
async fn dry_run_atomic(
    ks: &KeyspaceHandle,
    context_id: &str,
    namespace: &str,
    writes: &[AppStateWrite],
) -> Result<Option<DryRunFailure>, AppStateError> {
    for (index, w) in writes.iter().enumerate() {
        validate_address(namespace, &w.key)?;
        let existing = read_record(ks, context_id, namespace, &w.key).await?;
        let live = existing.as_ref().filter(|r| !r.deleted);

        let conflict = match w.expected_version {
            None => None,
            Some(0) => live.map(|cur| (ConflictReason::RecordExists, Some(cur))),
            Some(want) => match live {
                None => Some((ConflictReason::RecordAbsent, None)),
                Some(cur) if cur.version != want => {
                    Some((ConflictReason::VersionMismatch, Some(cur)))
                }
                Some(_) => None,
            },
        };
        if let Some((_reason, cur)) = conflict {
            return Ok(Some(DryRunFailure {
                index,
                result: WriteResult {
                    key: w.key.clone(),
                    outcome: WriteOutcome::Conflict,
                    version: None,
                    created: None,
                    current_version: cur
                        .map(|c| c.version)
                        .or(existing.as_ref().map(|r| r.version)),
                    current_value: cur.map(|c| c.value.clone()),
                    current_deleted: existing.as_ref().map(|r| r.deleted).filter(|d| *d),
                    limit_bytes: None,
                    actual_bytes: None,
                },
            }));
        }

        // A patch needs a live record; a whole value does not.
        if w.merge_patch.is_some() && live.is_none() {
            return Ok(Some(DryRunFailure {
                index,
                result: WriteResult {
                    key: w.key.clone(),
                    outcome: WriteOutcome::NotFound,
                    version: None,
                    created: None,
                    current_version: None,
                    current_value: None,
                    current_deleted: None,
                    limit_bytes: None,
                    actual_bytes: None,
                },
            }));
        }

        let projected = match (&w.value, &w.merge_patch) {
            (Some(v), None) => v.clone(),
            (None, Some(p)) => {
                let mut base = live.map(|c| c.value.clone()).unwrap_or(Value::Null);
                merge_patch(&mut base, p);
                base
            }
            _ => {
                return Err(AppStateError::Validation(format!(
                    "write for key `{}`: exactly one of `value` or `mergePatch` must be supplied",
                    w.key
                )));
            }
        };
        let size = value_size(&projected);
        if size > MAX_VALUE_BYTES {
            return Ok(Some(DryRunFailure {
                index,
                result: WriteResult {
                    key: w.key.clone(),
                    outcome: WriteOutcome::TooLarge,
                    version: None,
                    created: None,
                    current_version: None,
                    current_value: None,
                    current_deleted: None,
                    limit_bytes: Some(MAX_VALUE_BYTES),
                    actual_bytes: Some(size),
                },
            }));
        }
    }
    Ok(None)
}

/// Fold one write's `Result` into its per-record [`WriteResult`]. Genuine
/// faults (validation, store) propagate — they are not per-record outcomes and
/// reporting them as such would tell a caller to retry a malformed batch.
fn write_result(
    key: &str,
    outcome: Result<PutOutcome, AppStateError>,
) -> Result<WriteResult, AppStateError> {
    let base = |o: WriteOutcome| WriteResult {
        key: key.to_string(),
        outcome: o,
        version: None,
        created: None,
        current_version: None,
        current_value: None,
        current_deleted: None,
        limit_bytes: None,
        actual_bytes: None,
    };
    match outcome {
        Ok(o) => Ok(WriteResult {
            version: Some(o.version),
            created: Some(o.created),
            ..base(WriteOutcome::Written)
        }),
        Err(AppStateError::VersionConflict {
            current_version,
            current_value,
            current_deleted,
            ..
        }) => Ok(WriteResult {
            current_version,
            current_value,
            current_deleted,
            ..base(WriteOutcome::Conflict)
        }),
        Err(AppStateError::ValueTooLarge {
            limit_bytes,
            actual_bytes,
        }) => Ok(WriteResult {
            limit_bytes: Some(limit_bytes),
            actual_bytes: Some(actual_bytes),
            ..base(WriteOutcome::TooLarge)
        }),
        Err(AppStateError::NotFound) => Ok(base(WriteOutcome::NotFound)),
        Err(other) => Err(other),
    }
}

// ---------------------------------------------------------------------------
// delete
// ---------------------------------------------------------------------------

/// What a delete produced.
#[derive(Debug, Clone)]
pub struct DeleteOutcome {
    pub existed: bool,
    pub version: Option<u64>,
    pub deleted_at: Option<String>,
}

/// Delete one record, leaving a versioned tombstone.
///
/// Three cases, all successes:
///
/// - a live record → replaced by a tombstone taking the next counter value,
///   `existed: true`;
/// - an existing tombstone → unchanged, `existed: false`, and deliberately
///   **no** new counter value, because taking one would present a change to
///   every watching consumer where none occurred;
/// - nothing at all → `existed: false` and **no** tombstone written. Nothing
///   ever existed there for a consumer to have learned about, so there is
///   nothing to converge.
pub async fn delete(
    ks: &KeyspaceHandle,
    locks: &NamespaceLocks,
    context_id: &str,
    namespace: &str,
    key: &str,
    expected_version: Option<u64>,
) -> Result<DeleteOutcome, AppStateError> {
    validate_address(namespace, key)?;
    if expected_version == Some(0) {
        return Err(AppStateError::VersionConflict {
            reason: ConflictReason::CreateOnlyNotApplicable,
            current_version: None,
            current_value: None,
            current_deleted: None,
        });
    }

    let _guard = locks.acquire(context_id, namespace).await;
    let existing = read_record(ks, context_id, namespace, key).await?;
    let live = existing.as_ref().filter(|r| !r.deleted);

    if let Some(want) = expected_version {
        match live {
            None => {
                return Err(AppStateError::VersionConflict {
                    reason: ConflictReason::RecordAbsent,
                    current_version: existing.as_ref().map(|r| r.version),
                    current_value: None,
                    current_deleted: existing.as_ref().map(|r| r.deleted),
                });
            }
            Some(cur) if cur.version != want => {
                return Err(AppStateError::VersionConflict {
                    reason: ConflictReason::VersionMismatch,
                    current_version: Some(cur.version),
                    current_value: Some(cur.value.clone()),
                    current_deleted: None,
                });
            }
            Some(_) => {}
        }
    }

    let Some(prev) = existing else {
        return Ok(DeleteOutcome {
            existed: false,
            version: None,
            deleted_at: None,
        });
    };
    if prev.deleted {
        return Ok(DeleteOutcome {
            existed: false,
            version: Some(prev.version),
            deleted_at: prev.deleted_at,
        });
    }

    let now = Utc::now().to_rfc3339();
    // Reserved only once a tombstone is actually going to be written — the
    // no-op paths above return before this, so a repeated delete consumes
    // nothing and presents no change to a watching consumer.
    let next = reserve_versions(ks, context_id, namespace, 1).await?;
    let tombstone = StoredRecord {
        context_id: context_id.to_string(),
        namespace: namespace.to_string(),
        key: key.to_string(),
        version: next,
        deleted: true,
        value: Value::Null,
        value_bytes: 0,
        created_at: prev.created_at,
        updated_at: now.clone(),
        deleted_at: Some(now.clone()),
    };

    ks.remove(index_key(context_id, namespace, prev.version))
        .await?;
    ks.insert_raw(
        index_key(context_id, namespace, next),
        key.as_bytes().to_vec(),
    )
    .await?;
    ks.insert(record_key(context_id, namespace, key), &tombstone)
        .await?;

    Ok(DeleteOutcome {
        existed: true,
        version: Some(next),
        deleted_at: Some(now),
    })
}

/// Reap tombstones at or below `through`, and record that the namespace's feed
/// is no longer complete from before that point.
///
/// **Nothing schedules this yet.** It exists so the watermark check in
/// [`list`] is live rather than dead code, and so that adding a sweeper is a
/// pure addition rather than a change to the read path. A VTA that never calls
/// it retains tombstones forever and never emits `watermarkTooOld`, which the
/// published specification explicitly permits.
///
/// Recording `appt:` **before** removing anything is the safe order: a crash
/// mid-reap leaves the watermark claiming more was reaped than actually was,
/// which refuses a resumable sync (recoverable), where the opposite order would
/// serve an incomplete feed as if it were whole (not recoverable).
pub async fn reap_tombstones_through(
    ks: &KeyspaceHandle,
    locks: &NamespaceLocks,
    context_id: &str,
    namespace: &str,
    through: u64,
) -> Result<usize, AppStateError> {
    let _guard = locks.acquire(context_id, namespace).await;
    write_u64(ks, reaped_key(context_id, namespace), through).await?;

    let mut reaped = 0;
    for (_ik, key_bytes) in ks
        .prefix_iter_raw(index_prefix(context_id, namespace))
        .await?
    {
        let Ok(key) = std::str::from_utf8(&key_bytes) else {
            continue;
        };
        let Some(rec) = read_record(ks, context_id, namespace, key).await? else {
            continue;
        };
        if rec.deleted && rec.version <= through {
            ks.remove(index_key(context_id, namespace, rec.version))
                .await?;
            ks.remove(record_key(context_id, namespace, key)).await?;
            reaped += 1;
        }
    }
    Ok(reaped)
}

/// Reap every tombstone whose retention window has elapsed, across every
/// context and namespace in the keyspace.
///
/// Run from the storage thread's interval loop alongside the ACL / consent /
/// vault sweepers. Lives here rather than in `vta-sweepers` for the same reason
/// the backup-bundle sweeper stays in `vta-service`: it is coupled to this
/// module's key layout and record shape, and a second copy of those in a lower
/// crate is a second thing to keep in step.
///
/// ## Why it reaps a *prefix*, not a set
///
/// The obvious implementation removes each expired tombstone individually. That
/// is wrong here. `sinceVersion` resumption is only sound while the maintainer
/// can promise that a consumer's watermark is at or above everything it has
/// discarded — that promise is exactly what `appt:` records and what
/// `watermarkTooOld` enforces. Reaping version 7 while leaving version 4 makes
/// the promise unstateable: no single watermark describes what survives.
///
/// So each namespace advances through its tombstones in version order and stops
/// at the first one still inside the window. Everything below that point is
/// reaped and the watermark moves with it. A tombstone that is expired but sits
/// behind a younger one simply waits for the next sweep — a bounded delay, in
/// exchange for a watermark that always means what it says.
///
/// Walking in version order rather than filtering on time also makes the sweep
/// robust to a clock that has moved backwards: a stale `deletedAt` on a *later*
/// version stops the walk instead of licensing the removal of everything under
/// it.
///
/// `retention_seconds` is a pure cutoff — `now - retention_seconds` — so `0`
/// here means "everything already written is expired", not "disabled".
/// Disabling lives at the **call site**: the storage thread skips the sweep
/// entirely when `tombstone_retention_days` is 0. Keeping the two apart means
/// this function has one unambiguous meaning and the operator-facing knob has
/// the safer one, rather than overloading a single number with both.
///
/// Returns the number of tombstones removed.
pub async fn sweep_expired_tombstones(
    ks: &KeyspaceHandle,
    locks: &NamespaceLocks,
    audit: &vta_audit::SharedAuditSink,
    retention_seconds: u64,
) -> Result<usize, AppStateError> {
    let cutoff = Utc::now() - chrono::Duration::seconds(retention_seconds as i64);

    // Collect (contextId, namespace) -> tombstones, reading the address from
    // the record rather than parsing the storage key: a context id may contain
    // `/` and a key may contain `:`, so splitting the key is ambiguous.
    let mut by_namespace: HashMap<(String, String), Vec<(u64, Option<String>)>> = HashMap::new();
    for (_sk, bytes) in ks.prefix_iter_raw("app:").await? {
        let rec: StoredRecord = match serde_json::from_slice(&bytes) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "app-state sweeper: skipping unreadable row");
                continue;
            }
        };
        if !rec.deleted {
            continue;
        }
        by_namespace
            .entry((rec.context_id.clone(), rec.namespace.clone()))
            .or_default()
            .push((rec.version, rec.deleted_at.clone()));
    }

    let mut total = 0usize;
    for ((context_id, namespace), mut tombstones) in by_namespace {
        tombstones.sort_by_key(|(v, _)| *v);

        let mut through = 0u64;
        for (version, deleted_at) in &tombstones {
            let expired = deleted_at
                .as_deref()
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .is_some_and(|t| t.with_timezone(&Utc) < cutoff);
            if !expired {
                break;
            }
            through = *version;
        }
        if through == 0 {
            continue;
        }

        let reaped = reap_tombstones_through(ks, locks, &context_id, &namespace, through).await?;
        if reaped == 0 {
            continue;
        }
        total += reaped;
        tracing::info!(
            context_id = %context_id,
            namespace = %namespace,
            reaped,
            through,
            "app-state sweeper: reaped expired tombstones"
        );
        // Audited per namespace, not per record: what an operator needs to
        // reconstruct later is that the namespace's feed is no longer complete
        // from before `through`, which is one fact per namespace. The resource
        // carries that boundary so an incident review can tell whether a given
        // consumer's watermark was still valid.
        if let Err(e) = vta_audit::record(
            audit,
            "app_state.tombstone.purge",
            "system:sweeper",
            Some(&format!("{namespace}@{through}")),
            "success:retention-expired",
            None,
            Some(&context_id),
        )
        .await
        {
            tracing::warn!(
                error = %e,
                "app-state sweeper: purge succeeded but audit::record failed"
            );
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

/// One page of a list, plus what an incremental consumer needs to resume.
#[derive(Debug)]
pub struct ListPage {
    pub records: Vec<AppStateRecord>,
    pub truncated: bool,
    pub cursor: Option<String>,
    pub high_watermark: Option<u64>,
    pub tombstone_retention_seconds: Option<u64>,
}

/// Enumerate records.
///
/// Snapshot mode (`since_version` absent) scans records by key. Change-feed
/// mode scans the version index, so the page is already in version order and
/// its cursor is a real storage key.
#[allow(clippy::too_many_arguments)]
pub async fn list(
    ks: &KeyspaceHandle,
    context_id: &str,
    namespace: Option<&str>,
    prefix: Option<&str>,
    since_version: Option<u64>,
    include_values: bool,
    include_deleted: Option<bool>,
    page_size: Option<usize>,
    cursor: Option<&str>,
    // Retention this VTA is configured for, reported to change-feed callers so
    // they can schedule inside it. `None` when reaping is disabled — the feed
    // then omits the member rather than advertising a window that will never
    // expire anything, because a consumer reading a number would reasonably
    // infer it must sync more often than that.
    tombstone_retention_seconds: Option<u64>,
) -> Result<ListPage, AppStateError> {
    if let Some(ns) = namespace
        && !namespace_is_valid(ns)
    {
        return Err(AppStateError::Validation(format!(
            "namespace `{ns}` is not a valid partition name"
        )));
    }

    // Mode conflicts, refused rather than reconciled.
    if since_version.is_some() {
        if namespace.is_none() {
            return Err(AppStateError::FilterConflict(
                FilterConflict::SinceVersionRequiresNamespace,
            ));
        }
        if include_deleted == Some(false) {
            return Err(AppStateError::FilterConflict(
                FilterConflict::ChangeFeedCannotExcludeDeleted,
            ));
        }
    }

    let cursor_key = CursorKey::new(ks.clone()).get().await?;
    // Bind the query shape into the cursor's MAC so a cursor cannot be replayed
    // against a different filter set and silently skip records.
    let binding = format!(
        "app-state|{context_id}|{}|{}|{}",
        namespace.unwrap_or(""),
        prefix.unwrap_or(""),
        since_version.map(|v| v.to_string()).unwrap_or_default()
    );
    let decoded = match cursor {
        None => None,
        Some(raw) => Some(
            Cursor::decode_bound(raw, &cursor_key, binding.as_bytes())
                .map_err(|_| AppStateError::from(AppError::InvalidCursor))?,
        ),
    };
    let limit = page_size.unwrap_or(50).clamp(1, MAX_LIMIT);
    let snapshot = Utc::now().timestamp().max(0) as u64;

    // **Read the watermark BEFORE scanning**, and do not reorder these. No lock
    // is held across a read, so a write can land in between, and the two orders
    // differ in which way that failure goes:
    //
    // - Counter first (here): a write landing between the read and the scan may
    //   appear in `records` while `highWatermark` still sits below it. The
    //   consumer re-receives that change on its next pull — at-least-once,
    //   which is safe because applying a versioned record twice reaches the
    //   same state.
    // - Scan first: the same write appears in neither `records` nor the
    //   consumer's next query, because the watermark it stores already covers
    //   it. Silent loss, and nothing downstream can detect it.
    //
    // Duplicate delivery is the acceptable failure here; a missed change is not.
    let high_watermark = match namespace {
        Some(ns) => Some(read_counter(ks, context_id, ns).await?),
        None => None,
    };

    let pairs = match since_version {
        // ── Change feed ────────────────────────────────────────────────
        Some(since) => {
            let ns = namespace.expect("checked above");
            let reaped_through = read_reaped_through(ks, context_id, ns).await?;
            if since < reaped_through {
                return Err(AppStateError::WatermarkTooOld {
                    oldest_retained_version: reaped_through + 1,
                    high_watermark: high_watermark.unwrap_or(0),
                });
            }
            // The index is ordered by zero-padded version, so a range scan from
            // `since + 1` is the feed. Resolve each index entry to its record.
            let mut out = Vec::new();
            for (ik, key_bytes) in ks.prefix_iter_raw(index_prefix(context_id, ns)).await? {
                let Some(version) = version_from_index_key(&ik) else {
                    continue;
                };
                if version <= since {
                    continue;
                }
                let Ok(key) = std::str::from_utf8(&key_bytes) else {
                    continue;
                };
                if let Some(p) = prefix
                    && !key.starts_with(p)
                {
                    continue;
                }
                let Some(rec) = read_record(ks, context_id, ns, key).await? else {
                    continue;
                };
                out.push((ik, serde_json::to_vec(&rec).map_err(encode_err)?));
            }
            out
        }
        // ── Snapshot ───────────────────────────────────────────────────
        None => {
            let scan_prefix = match namespace {
                Some(ns) => namespace_prefix(context_id, ns),
                None => context_prefix(context_id),
            };
            let want_deleted = include_deleted.unwrap_or(false);
            let mut out = Vec::new();
            for (sk, bytes) in ks.prefix_iter_raw(scan_prefix).await? {
                let rec: StoredRecord = serde_json::from_slice(&bytes).map_err(decode_err)?;
                if rec.deleted && !want_deleted {
                    continue;
                }
                if let Some(p) = prefix
                    && !rec.key.starts_with(p)
                {
                    continue;
                }
                out.push((sk, bytes));
            }
            out
        }
    };

    let page = paginate(pairs, decoded.as_ref(), limit, &cursor_key, snapshot, |v| {
        let rec: StoredRecord = serde_json::from_slice(v).map_err(decode_err_app)?;
        Ok(rec.to_wire(include_values))
    })?;

    // `paginate` signs its cursor unbound; re-sign under the query binding so a
    // cursor cannot be carried to a different filter set.
    let cursor = page
        .next_cursor
        .as_deref()
        .map(|raw| rebind_cursor(raw, &cursor_key, binding.as_bytes(), snapshot))
        .transpose()?;

    Ok(ListPage {
        truncated: cursor.is_some(),
        records: page.items,
        cursor,
        high_watermark,
        tombstone_retention_seconds: since_version
            .is_some()
            .then_some(tombstone_retention_seconds)
            .flatten(),
    })
}

/// Re-encode a cursor minted by [`paginate`] under the query binding.
fn rebind_cursor(
    raw: &str,
    cursor_key: &[u8; 32],
    binding: &[u8],
    snapshot: u64,
) -> Result<String, AppStateError> {
    let decoded = Cursor::decode(raw, cursor_key)
        .map_err(|e| AppStateError::Internal(format!("re-decode own cursor: {e}")))?;
    Ok(Cursor::new(decoded.last_key, snapshot).encode_bound(cursor_key, binding))
}

/// Parse the version out of an `appv:<ctx>:<ns>:<version:020>` storage key.
fn version_from_index_key(index_key: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(index_key).ok()?;
    text.rsplit_once(':')?.1.parse().ok()
}

fn encode_err(e: serde_json::Error) -> AppStateError {
    AppStateError::Internal(format!("encode app-state record: {e}"))
}

fn decode_err(e: serde_json::Error) -> AppStateError {
    AppStateError::Internal(format!("decode app-state record: {e}"))
}

fn decode_err_app(e: serde_json::Error) -> AppError {
    AppError::Internal(format!("decode app-state record: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn open() -> (tempfile::TempDir, KeyspaceHandle, NamespaceLocks) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::APP_STATE).unwrap();
        (dir, ks, NamespaceLocks::default())
    }

    async fn put_value(
        ks: &KeyspaceHandle,
        locks: &NamespaceLocks,
        ctx: &str,
        ns: &str,
        key: &str,
        v: Value,
    ) -> PutOutcome {
        put(ks, locks, ctx, ns, key, Some(&v), None, None)
            .await
            .expect("put")
    }

    // ── The version counter ────────────────────────────────────────────

    #[tokio::test]
    async fn version_counter_is_shared_across_the_namespace() {
        // The property the whole design rests on: a record's version is a value
        // of the NAMESPACE counter, so writing a neighbour advances what the
        // next write to this record will take.
        let (_d, ks, locks) = open().await;
        let a1 = put_value(&ks, &locks, "ctx", "openvtc", "a", json!(1)).await;
        let b1 = put_value(&ks, &locks, "ctx", "openvtc", "b", json!(1)).await;
        let a2 = put_value(&ks, &locks, "ctx", "openvtc", "a", json!(2)).await;
        assert_eq!(a1.version, 1);
        assert_eq!(b1.version, 2);
        assert_eq!(
            a2.version, 3,
            "a's second write takes the namespace's next value, not its own"
        );
    }

    #[tokio::test]
    async fn namespaces_have_independent_counters() {
        let (_d, ks, locks) = open().await;
        let a = put_value(&ks, &locks, "ctx", "openvtc", "k", json!(1)).await;
        let b = put_value(&ks, &locks, "ctx", "cnm", "k", json!(1)).await;
        assert_eq!(a.version, 1);
        assert_eq!(b.version, 1, "a second namespace starts its own counter");
    }

    // ── Preconditions ──────────────────────────────────────────────────

    #[tokio::test]
    async fn expected_version_zero_creates_only_once() {
        // Lease acquisition: exactly one winner, and the loser is told who won.
        let (_d, ks, locks) = open().await;
        let first = put(
            &ks,
            &locks,
            "ctx",
            "openvtc",
            "lease",
            Some(&json!({"holder": "a"})),
            None,
            Some(0),
        )
        .await
        .expect("first create-only wins");
        assert!(first.created);

        let second = put(
            &ks,
            &locks,
            "ctx",
            "openvtc",
            "lease",
            Some(&json!({"holder": "b"})),
            None,
            Some(0),
        )
        .await;
        match second {
            Err(AppStateError::VersionConflict {
                reason,
                current_version,
                current_value,
                ..
            }) => {
                assert_eq!(reason, ConflictReason::RecordExists);
                assert_eq!(current_version, Some(first.version));
                assert_eq!(
                    current_value,
                    Some(json!({"holder": "a"})),
                    "the loser must be handed the winner's value, not just a rejection"
                );
            }
            other => panic!("expected a create-only conflict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn conflict_carries_the_current_version_and_value() {
        let (_d, ks, locks) = open().await;
        let first = put_value(
            &ks,
            &locks,
            "ctx",
            "openvtc",
            "k",
            json!({"role": "member"}),
        )
        .await;
        put_value(&ks, &locks, "ctx", "openvtc", "k", json!({"role": "owner"})).await;

        let stale = put(
            &ks,
            &locks,
            "ctx",
            "openvtc",
            "k",
            Some(&json!({"role": "admin"})),
            None,
            Some(first.version),
        )
        .await;
        match stale {
            Err(AppStateError::VersionConflict {
                reason,
                current_value,
                ..
            }) => {
                assert_eq!(reason, ConflictReason::VersionMismatch);
                assert_eq!(
                    current_value,
                    Some(json!({"role": "owner"})),
                    "returning the winner's view is what removes the re-read race"
                );
            }
            other => panic!("expected a version conflict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_only_succeeds_over_a_tombstone() {
        // A tombstone is not a live record, and the replacement must take a
        // version above the tombstone's so the change feed stays ordered.
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "k", json!(1)).await;
        let del = delete(&ks, &locks, "ctx", "openvtc", "k", None)
            .await
            .unwrap();
        let recreated = put(
            &ks,
            &locks,
            "ctx",
            "openvtc",
            "k",
            Some(&json!(2)),
            None,
            Some(0),
        )
        .await
        .expect("create-only applies over a tombstone");
        assert!(recreated.created);
        assert!(recreated.version > del.version.unwrap());
    }

    // ── Merge patch ────────────────────────────────────────────────────

    #[tokio::test]
    async fn merge_patch_edits_one_member_and_null_removes() {
        let (_d, ks, locks) = open().await;
        put_value(
            &ks,
            &locks,
            "ctx",
            "openvtc",
            "k",
            json!({"label": "Acme", "role": "member", "joinedAt": "2026-07-02"}),
        )
        .await;
        put(
            &ks,
            &locks,
            "ctx",
            "openvtc",
            "k",
            None,
            Some(&json!({"label": "Acme EMEA", "role": null})),
            None,
        )
        .await
        .expect("patch applies");

        let rec = get(&ks, "ctx", "openvtc", "k", false).await.unwrap();
        assert_eq!(
            rec.value,
            Some(json!({"label": "Acme EMEA", "joinedAt": "2026-07-02"})),
            "RFC 7386: a null member is removed, untouched members survive"
        );
    }

    #[tokio::test]
    async fn merge_patch_on_absent_record_is_not_found() {
        // Refused rather than treated as a create: RFC 7386 against a null
        // target would silently invent a record from the patch minus its nulls.
        let (_d, ks, locks) = open().await;
        let err = put(
            &ks,
            &locks,
            "ctx",
            "openvtc",
            "nope",
            None,
            Some(&json!({"a": 1})),
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppStateError::NotFound), "{err:?}");
    }

    #[tokio::test]
    async fn merge_patch_replaces_wholesale_when_not_an_object() {
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "k", json!({"a": 1})).await;
        put(
            &ks,
            &locks,
            "ctx",
            "openvtc",
            "k",
            None,
            Some(&json!("scalar")),
            None,
        )
        .await
        .unwrap();
        let rec = get(&ks, "ctx", "openvtc", "k", false).await.unwrap();
        assert_eq!(rec.value, Some(json!("scalar")));
    }

    // ── Tombstones and convergence ─────────────────────────────────────

    #[tokio::test]
    async fn delete_leaves_a_tombstone_the_change_feed_reports() {
        // The property the store exists for: a consumer syncing from a
        // watermark must LEARN about the deletion, not merely stop seeing the
        // record.
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "gone", json!(1)).await;
        let watermark = put_value(&ks, &locks, "ctx", "openvtc", "stays", json!(1))
            .await
            .version;
        delete(&ks, &locks, "ctx", "openvtc", "gone", None)
            .await
            .unwrap();

        let feed = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            Some(watermark),
            true,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(feed.records.len(), 1);
        assert_eq!(feed.records[0].key, "gone");
        assert!(
            feed.records[0].deleted,
            "the deletion must reach the consumer as a tombstone"
        );
        assert!(feed.records[0].value.is_none());
    }

    #[tokio::test]
    async fn snapshot_hides_tombstones_unless_asked() {
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "gone", json!(1)).await;
        put_value(&ks, &locks, "ctx", "openvtc", "stays", json!(1)).await;
        delete(&ks, &locks, "ctx", "openvtc", "gone", None)
            .await
            .unwrap();

        let plain = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            None,
            false,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(plain.records.len(), 1);
        assert_eq!(plain.records[0].key, "stays");

        let with_tombs = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            None,
            false,
            Some(true),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(with_tombs.records.len(), 2);
    }

    #[tokio::test]
    async fn repeated_delete_takes_no_new_version() {
        // A second delete must present NO change to a watching consumer.
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "k", json!(1)).await;
        let first = delete(&ks, &locks, "ctx", "openvtc", "k", None)
            .await
            .unwrap();
        assert!(first.existed);
        let second = delete(&ks, &locks, "ctx", "openvtc", "k", None)
            .await
            .unwrap();
        assert!(
            !second.existed,
            "a repeat delete is a success, not an error"
        );
        assert_eq!(
            second.version, first.version,
            "a repeat delete must not advance the counter"
        );
    }

    #[tokio::test]
    async fn delete_of_never_written_address_writes_no_tombstone() {
        let (_d, ks, locks) = open().await;
        let out = delete(&ks, &locks, "ctx", "openvtc", "never", None)
            .await
            .unwrap();
        assert!(!out.existed);
        assert!(
            out.version.is_none(),
            "nothing existed to converge, so no tombstone is written"
        );
        assert_eq!(read_counter(&ks, "ctx", "openvtc").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn delete_with_expected_version_zero_is_refused() {
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "k", json!(1)).await;
        let err = delete(&ks, &locks, "ctx", "openvtc", "k", Some(0))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                AppStateError::VersionConflict {
                    reason: ConflictReason::CreateOnlyNotApplicable,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    // ── The change feed ────────────────────────────────────────────────

    #[tokio::test]
    async fn change_feed_is_in_version_order() {
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "zebra", json!(1)).await;
        put_value(&ks, &locks, "ctx", "openvtc", "alpha", json!(1)).await;
        let feed = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            Some(0),
            false,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let keys: Vec<_> = feed.records.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(
            keys,
            vec!["zebra", "alpha"],
            "change feed orders by version, not by key"
        );
    }

    #[tokio::test]
    async fn high_watermark_is_the_counter_not_the_max_returned_version() {
        // The distinction that makes prefix-filtered sync correct: a change
        // outside the prefix still advances the counter, and a consumer that
        // stored max(version) would replay it forever.
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "community/a", json!(1)).await;
        put_value(&ks, &locks, "ctx", "openvtc", "other/b", json!(1)).await;

        let feed = list(
            &ks,
            "ctx",
            Some("openvtc"),
            Some("community/"),
            Some(0),
            false,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(feed.records.len(), 1);
        assert_eq!(feed.records[0].version, 1);
        assert_eq!(
            feed.high_watermark,
            Some(2),
            "the watermark is the namespace counter, past the filtered-out change"
        );
    }

    #[tokio::test]
    async fn a_gap_in_the_version_sequence_does_not_break_the_change_feed() {
        // Writes reserve their counter value BEFORE writing the record, so a
        // crash in between consumes a version that no record ever occupies.
        // That trade is only sound if a gap is harmless to a consumer — this
        // pins that half. (The other half, that a REUSED version silently drops
        // a change from the feed, is what the ordering exists to prevent and
        // cannot be provoked without crash injection.)
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "before", json!(1)).await;

        // Simulate the crash: burn counter values with no record behind them.
        write_u64(&ks, counter_key("ctx", "openvtc"), 40)
            .await
            .unwrap();

        let after = put_value(&ks, &locks, "ctx", "openvtc", "after", json!(1)).await;
        assert_eq!(after.version, 41, "the next write resumes above the gap");

        let feed = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            Some(0),
            false,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let keys: Vec<_> = feed.records.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, vec!["before", "after"], "the gap is simply absent");
        assert_eq!(feed.high_watermark, Some(41));

        // And resuming from the watermark yields nothing further.
        let resumed = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            Some(41),
            false,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(resumed.records.is_empty());
    }

    #[tokio::test]
    async fn change_feed_requires_a_namespace() {
        let (_d, ks, _l) = open().await;
        let err = list(
            &ks,
            "ctx",
            None,
            None,
            Some(0),
            false,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                AppStateError::FilterConflict(FilterConflict::SinceVersionRequiresNamespace)
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn change_feed_cannot_be_asked_to_exclude_tombstones() {
        let (_d, ks, _l) = open().await;
        let err = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            Some(0),
            false,
            Some(false),
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                AppStateError::FilterConflict(FilterConflict::ChangeFeedCannotExcludeDeleted)
            ),
            "{err:?}"
        );
    }

    /// A real sink over a scratch keyspace — the sweeper audits each reap, and
    /// a sink that swallowed the call would leave that path untested.
    fn test_audit_sink(ks: &KeyspaceHandle) -> vta_audit::SharedAuditSink {
        std::sync::Arc::new(vta_audit::KeyspaceAuditSink::new(ks.clone()))
    }

    #[tokio::test]
    async fn sweeper_reaps_expired_tombstones_and_leaves_live_records() {
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "keep", json!(1)).await;
        put_value(&ks, &locks, "ctx", "openvtc", "gone", json!(1)).await;
        let del = delete(&ks, &locks, "ctx", "openvtc", "gone", None)
            .await
            .unwrap();

        // retention 0 → everything already written is past its window.
        let reaped = sweep_expired_tombstones(&ks, &locks, &test_audit_sink(&ks), 0)
            .await
            .unwrap();
        assert_eq!(reaped, 1, "only the tombstone is reaped");

        // The live record survives.
        assert!(get(&ks, "ctx", "openvtc", "keep", false).await.is_ok());
        // The tombstone is gone even to a caller asking for it.
        assert!(
            matches!(
                get(&ks, "ctx", "openvtc", "gone", true).await,
                Err(AppStateError::NotFound)
            ),
            "a reaped tombstone leaves nothing behind"
        );

        // And the watermark moved with it, so a consumer that was behind is
        // told to rebuild rather than served a feed missing that deletion.
        let err = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            Some(0),
            false,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
        match err {
            AppStateError::WatermarkTooOld {
                oldest_retained_version,
                ..
            } => assert_eq!(oldest_retained_version, del.version.unwrap() + 1),
            other => panic!("expected WatermarkTooOld, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sweeper_leaves_tombstones_inside_the_retention_window() {
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "gone", json!(1)).await;
        delete(&ks, &locks, "ctx", "openvtc", "gone", None)
            .await
            .unwrap();

        let reaped = sweep_expired_tombstones(&ks, &locks, &test_audit_sink(&ks), 3600)
            .await
            .unwrap();
        assert_eq!(reaped, 0, "a fresh tombstone is inside the window");

        // Still reported to an incremental consumer, which is the point of
        // keeping it.
        let feed = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            Some(0),
            false,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(feed.records.iter().any(|r| r.deleted));
    }

    #[tokio::test]
    async fn sweeper_stops_at_the_first_unexpired_tombstone() {
        // The walk is a prefix, not a filter: reaping a later tombstone while
        // leaving an earlier one would make `appt:` unstateable, because no
        // single watermark would describe what survives. Here the *earlier*
        // tombstone is expired and the later one is not, so nothing below the
        // later one may be reaped past it.
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "old", json!(1)).await;
        put_value(&ks, &locks, "ctx", "openvtc", "new", json!(1)).await;
        delete(&ks, &locks, "ctx", "openvtc", "old", None)
            .await
            .unwrap();
        let newer = delete(&ks, &locks, "ctx", "openvtc", "new", None)
            .await
            .unwrap();

        // Backdate only the first tombstone, leaving the second inside the
        // window, then sweep with a window that expires the backdated one.
        let mut rec = read_record(&ks, "ctx", "openvtc", "old")
            .await
            .unwrap()
            .expect("tombstone");
        rec.deleted_at = Some((Utc::now() - chrono::Duration::days(90)).to_rfc3339());
        ks.insert(record_key("ctx", "openvtc", "old"), &rec)
            .await
            .unwrap();

        let reaped =
            sweep_expired_tombstones(&ks, &locks, &test_audit_sink(&ks), 30 * 24 * 60 * 60)
                .await
                .unwrap();
        assert_eq!(reaped, 1, "only the backdated tombstone goes");

        // The younger tombstone is untouched and still reachable.
        let still = read_record(&ks, "ctx", "openvtc", "new").await.unwrap();
        assert!(still.is_some_and(|r| r.deleted));
        // And the watermark stops below it, so a consumer at that version can
        // still resume.
        assert!(
            list(
                &ks,
                "ctx",
                Some("openvtc"),
                None,
                Some(newer.version.unwrap() - 1),
                false,
                None,
                None,
                None,
                None,
            )
            .await
            .is_ok(),
            "a watermark above the reap point must still resume"
        );
    }

    #[tokio::test]
    async fn change_feed_reports_the_configured_retention_and_omits_it_when_disabled() {
        // A consumer schedules its syncs against this number, so it has to be
        // the window the operator actually configured. When reaping is off the
        // member is omitted rather than set to something: any number would tell
        // the consumer it must sync more often than that, which is false.
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "k", json!(1)).await;

        let configured = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            Some(0),
            false,
            None,
            None,
            None,
            Some(604_800),
        )
        .await
        .unwrap();
        assert_eq!(configured.tombstone_retention_seconds, Some(604_800));

        let disabled = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            Some(0),
            false,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(disabled.tombstone_retention_seconds, None);

        // A snapshot never reports it — the window only bears on resumption.
        let snapshot = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            None,
            false,
            None,
            None,
            None,
            Some(604_800),
        )
        .await
        .unwrap();
        assert_eq!(snapshot.tombstone_retention_seconds, None);
    }

    #[tokio::test]
    async fn sweeper_is_namespace_scoped() {
        let (_d, ks, locks) = open().await;
        for ns in ["openvtc", "cnm"] {
            put_value(&ks, &locks, "ctx", ns, "gone", json!(1)).await;
            delete(&ks, &locks, "ctx", ns, "gone", None).await.unwrap();
        }
        let reaped = sweep_expired_tombstones(&ks, &locks, &test_audit_sink(&ks), 0)
            .await
            .unwrap();
        assert_eq!(reaped, 2, "each namespace is swept on its own counter");
        for ns in ["openvtc", "cnm"] {
            assert!(read_record(&ks, "ctx", ns, "gone").await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn reaped_tombstones_make_an_old_watermark_refuse_rather_than_lie() {
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "gone", json!(1)).await;
        let del = delete(&ks, &locks, "ctx", "openvtc", "gone", None)
            .await
            .unwrap();
        put_value(&ks, &locks, "ctx", "openvtc", "later", json!(1)).await;

        let reaped = reap_tombstones_through(&ks, &locks, "ctx", "openvtc", del.version.unwrap())
            .await
            .unwrap();
        assert_eq!(reaped, 1);

        // A watermark from before the reap point can no longer converge.
        let err = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            Some(0),
            false,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppStateError::WatermarkTooOld { .. }),
            "{err:?}"
        );

        // One at or after it still resumes.
        assert!(
            list(
                &ks,
                "ctx",
                Some("openvtc"),
                None,
                Some(del.version.unwrap()),
                false,
                None,
                None,
                None,
                None,
            )
            .await
            .is_ok()
        );
    }

    // ── Isolation and limits ───────────────────────────────────────────

    #[tokio::test]
    async fn namespaces_do_not_bleed_into_each_other() {
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "k", json!("openvtc")).await;
        put_value(&ks, &locks, "ctx", "cnm", "k", json!("cnm")).await;
        let listed = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            None,
            true,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(listed.records.len(), 1);
        assert_eq!(listed.records[0].value, Some(json!("openvtc")));
    }

    #[tokio::test]
    async fn contexts_do_not_bleed_into_each_other() {
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx-a", "openvtc", "k", json!("a")).await;
        put_value(&ks, &locks, "ctx-b", "openvtc", "k", json!("b")).await;
        let a = list(&ks, "ctx-a", None, None, None, true, None, None, None, None)
            .await
            .unwrap();
        assert_eq!(a.records.len(), 1);
        assert_eq!(a.records[0].value, Some(json!("a")));
    }

    #[tokio::test]
    async fn metadata_view_omits_the_value_but_keeps_its_size() {
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "k", json!({"a": "bb"})).await;
        let listed = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            None,
            false,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(listed.records[0].value.is_none());
        assert_eq!(listed.records[0].value_bytes, Some(10));
    }

    #[tokio::test]
    async fn oversized_value_is_refused_loudly_with_both_numbers() {
        let (_d, ks, locks) = open().await;
        let big = json!("x".repeat(MAX_VALUE_BYTES as usize + 10));
        let err = put(&ks, &locks, "ctx", "openvtc", "k", Some(&big), None, None)
            .await
            .unwrap_err();
        match err {
            AppStateError::ValueTooLarge {
                limit_bytes,
                actual_bytes,
            } => {
                assert_eq!(limit_bytes, MAX_VALUE_BYTES);
                assert!(actual_bytes > limit_bytes);
            }
            other => panic!("expected ValueTooLarge, got {other:?}"),
        }
        // Nothing was written. The reserved version is simply unused — a gap,
        // which `a_gap_in_the_version_sequence_does_not_break_the_change_feed`
        // covers. Reserving before validating is what lets a batch pay one
        // fsync instead of N, and a gap is the price.
        assert!(
            matches!(
                get(&ks, "ctx", "openvtc", "k", false).await,
                Err(AppStateError::NotFound)
            ),
            "a refused write must leave no record behind"
        );
    }

    #[tokio::test]
    async fn a_null_value_is_stored_and_is_not_an_absent_value() {
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "k", Value::Null).await;
        let rec = get(&ks, "ctx", "openvtc", "k", false).await.unwrap();
        assert_eq!(rec.value, Some(Value::Null));
        assert!(!rec.deleted);
    }

    #[tokio::test]
    async fn invalid_namespace_is_refused() {
        let (_d, ks, locks) = open().await;
        for bad in ["OpenVTC", "open_vtc", "-lead", "trail-", "a--b", ""] {
            let err = put(&ks, &locks, "ctx", bad, "k", Some(&json!(1)), None, None)
                .await
                .unwrap_err();
            assert!(
                matches!(err, AppStateError::Validation(_)),
                "namespace `{bad}` should be refused, got {err:?}"
            );
        }
    }

    // ── Batches ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn independent_batch_applies_the_writes_that_pass() {
        let (_d, ks, locks) = open().await;
        let a = put_value(&ks, &locks, "ctx", "openvtc", "a", json!(1)).await;
        put_value(&ks, &locks, "ctx", "openvtc", "b", json!(1)).await;

        let writes = vec![
            {
                let mut w = AppStateWrite::new("a".into());
                w.value = Some(json!(2));
                w.expected_version = Some(a.version);
                w
            },
            {
                let mut w = AppStateWrite::new("b".into());
                w.value = Some(json!(2));
                // Stale on purpose.
                w.expected_version = Some(999);
                w
            },
            {
                let mut w = AppStateWrite::new("c".into());
                w.value = Some(json!(1));
                w.expected_version = Some(0);
                w
            },
        ];
        let (results, high) = put_many(
            &ks,
            &locks,
            "ctx",
            "openvtc",
            &writes,
            PutManyMode::Independent,
        )
        .await
        .expect("an independent batch with a conflict is still a success");

        assert_eq!(results[0].outcome, WriteOutcome::Written);
        assert_eq!(results[1].outcome, WriteOutcome::Conflict);
        assert_eq!(
            results[1].current_value,
            Some(json!(1)),
            "a conflicted write in a batch carries the same current-value payload as a single put"
        );
        assert_eq!(results[2].outcome, WriteOutcome::Written);
        assert!(high >= results[2].version.unwrap());

        // The conflicted record is untouched; the others landed.
        assert_eq!(
            get(&ks, "ctx", "openvtc", "b", false).await.unwrap().value,
            Some(json!(1))
        );
    }

    #[tokio::test]
    async fn atomic_batch_writes_nothing_when_one_write_fails() {
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "index", json!({"ids": []})).await;
        let counter_before = read_counter(&ks, "ctx", "openvtc").await.unwrap();

        let writes = vec![
            {
                let mut w = AppStateWrite::new("member".into());
                w.value = Some(json!({"label": "Cyprus"}));
                w.expected_version = Some(0);
                w
            },
            {
                let mut w = AppStateWrite::new("index".into());
                w.value = Some(json!({"ids": ["cyprus"]}));
                w.expected_version = Some(999); // stale
                w
            },
        ];
        let err = put_many(&ks, &locks, "ctx", "openvtc", &writes, PutManyMode::Atomic)
            .await
            .unwrap_err();

        match err {
            AppStateError::AtomicBatchRejected(results) => {
                assert_eq!(
                    results[0].outcome,
                    WriteOutcome::Skipped,
                    "the write that was never attempted must say so, so a retry \
                     does not rewrite its create-only precondition"
                );
                assert_eq!(results[1].outcome, WriteOutcome::Conflict);
            }
            other => panic!("expected AtomicBatchRejected, got {other:?}"),
        }

        assert!(
            get(&ks, "ctx", "openvtc", "member", false).await.is_err(),
            "an atomic batch that did not apply must have written nothing"
        );
        assert_eq!(
            read_counter(&ks, "ctx", "openvtc").await.unwrap(),
            counter_before,
            "a rejected atomic batch must not consume counter values"
        );
    }

    #[tokio::test]
    async fn atomic_batch_applies_when_every_write_passes() {
        let (_d, ks, locks) = open().await;
        let idx = put_value(&ks, &locks, "ctx", "openvtc", "index", json!({"ids": []})).await;
        let writes = vec![
            {
                let mut w = AppStateWrite::new("member".into());
                w.value = Some(json!({"label": "Cyprus"}));
                w.expected_version = Some(0);
                w
            },
            {
                let mut w = AppStateWrite::new("index".into());
                w.value = Some(json!({"ids": ["cyprus"]}));
                w.expected_version = Some(idx.version);
                w
            },
        ];
        let (results, _) = put_many(&ks, &locks, "ctx", "openvtc", &writes, PutManyMode::Atomic)
            .await
            .unwrap();
        assert!(results.iter().all(|r| r.outcome == WriteOutcome::Written));
    }

    #[tokio::test]
    async fn duplicate_keys_in_a_batch_are_refused() {
        let (_d, ks, locks) = open().await;
        let writes = vec![
            {
                let mut w = AppStateWrite::new("k".into());
                w.value = Some(json!(1));
                w
            },
            {
                let mut w = AppStateWrite::new("k".into());
                w.value = Some(json!(2));
                w
            },
        ];
        let err = put_many(
            &ks,
            &locks,
            "ctx",
            "openvtc",
            &writes,
            PutManyMode::Independent,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppStateError::DuplicateKey(_)), "{err:?}");
    }

    #[tokio::test]
    async fn get_many_accounts_for_every_requested_key() {
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "a", json!(1)).await;
        put_value(&ks, &locks, "ctx", "openvtc", "gone", json!(1)).await;
        delete(&ks, &locks, "ctx", "openvtc", "gone", None)
            .await
            .unwrap();

        let keys = vec!["a".to_string(), "gone".to_string(), "never".to_string()];
        let (records, missing, deferred) =
            get_many(&ks, "ctx", "openvtc", &keys, false).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(missing, vec!["gone", "never"]);
        assert!(deferred.is_empty());

        let total = records.len() + missing.len() + deferred.len();
        assert_eq!(
            total,
            keys.len(),
            "every requested key must be accounted for"
        );
    }

    #[tokio::test]
    async fn get_many_defers_past_the_budget_and_still_accounts_for_every_key() {
        // The published spec makes the three-way accounting a MUST: every
        // requested key lands in exactly one of records / missing / deferred.
        // The deferral branch is the one that can silently drop a key, so it
        // needs its own test rather than riding on the happy path.
        let (_d, ks, locks) = open().await;
        let big = json!("x".repeat(65_000)); // just under the per-record cap
        let keys: Vec<String> = (0..10).map(|i| format!("k{i}")).collect();
        for k in &keys {
            put_value(&ks, &locks, "ctx", "openvtc", k, big.clone()).await;
        }

        let (records, missing, deferred) =
            get_many(&ks, "ctx", "openvtc", &keys, false).await.unwrap();

        assert!(
            !deferred.is_empty(),
            "10 x ~64KiB must exceed the {GET_MANY_RESPONSE_BUDGET_BYTES}-byte budget"
        );
        assert!(!records.is_empty(), "the batch must make forward progress");
        assert_eq!(
            records.len() + missing.len() + deferred.len(),
            keys.len(),
            "every requested key must be accounted for exactly once"
        );

        // Deferral is in request order, so re-requesting `deferred` progresses
        // rather than returning an arbitrary subset again.
        let returned: Vec<&str> = records.iter().map(|r| r.key.as_str()).collect();
        let expected_prefix: Vec<&str> = keys
            .iter()
            .take(records.len())
            .map(String::as_str)
            .collect();
        assert_eq!(returned, expected_prefix);

        let (r2, _m2, d2) = get_many(&ks, "ctx", "openvtc", &deferred, false)
            .await
            .unwrap();
        assert!(
            !r2.is_empty(),
            "the re-request must return the deferred keys"
        );
        assert!(d2.len() < deferred.len(), "and must shrink the remainder");
    }

    #[tokio::test]
    async fn get_many_include_deleted_returns_the_tombstone() {
        let (_d, ks, locks) = open().await;
        put_value(&ks, &locks, "ctx", "openvtc", "gone", json!(1)).await;
        delete(&ks, &locks, "ctx", "openvtc", "gone", None)
            .await
            .unwrap();
        let keys = vec!["gone".to_string()];
        let (records, missing, _) = get_many(&ks, "ctx", "openvtc", &keys, true).await.unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].deleted);
        assert!(missing.is_empty());
    }

    #[tokio::test]
    async fn get_many_refuses_duplicates() {
        let (_d, ks, _l) = open().await;
        let keys = vec!["a".to_string(), "a".to_string()];
        let err = get_many(&ks, "ctx", "openvtc", &keys, false)
            .await
            .unwrap_err();
        assert!(matches!(err, AppStateError::DuplicateKey(_)), "{err:?}");
    }

    // ── Pagination ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn snapshot_paginates_and_the_cursor_resumes() {
        let (_d, ks, locks) = open().await;
        for i in 0..5 {
            put_value(&ks, &locks, "ctx", "openvtc", &format!("k{i}"), json!(i)).await;
        }
        let first = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            None,
            false,
            None,
            Some(2),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(first.records.len(), 2);
        assert!(first.truncated);

        let second = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None,
            None,
            false,
            None,
            Some(2),
            first.cursor.as_deref(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(second.records.len(), 2);
        assert_ne!(first.records[0].key, second.records[0].key);
    }

    #[tokio::test]
    async fn a_cursor_cannot_be_replayed_against_a_different_filter() {
        // Otherwise a consumer could resume a `community/` scan inside an
        // `other/` one and silently skip everything in between.
        let (_d, ks, locks) = open().await;
        for i in 0..5 {
            put_value(
                &ks,
                &locks,
                "ctx",
                "openvtc",
                &format!("community/{i}"),
                json!(i),
            )
            .await;
        }
        let page = list(
            &ks,
            "ctx",
            Some("openvtc"),
            Some("community/"),
            None,
            false,
            None,
            Some(2),
            None,
            None,
        )
        .await
        .unwrap();
        let err = list(
            &ks,
            "ctx",
            Some("openvtc"),
            None, // different filter set
            None,
            false,
            None,
            Some(2),
            page.cursor.as_deref(),
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppStateError::Validation(_)), "{err:?}");
    }
}
