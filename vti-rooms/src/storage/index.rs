//! The indexes kept beside a room's records, so a read costs what it returns (#2595).
//!
//! # Rows
//!
//! ```text
//! room_leaf/v1:<len>:<roomId>:<key>            -> version (u64, big-endian) ‖ leaf hash (32 bytes)
//! room_by_version/v1:<len>:<roomId>:<version>  -> the record key at that version (20 digits)
//! room_head/v1:<len>:<roomId>                  -> HeadRow (JSON)
//! ```
//!
//! All three live in the **records keyspace**, beside the records, so every change to a
//! record and to its index rows is one atomic [`Batch`]: there is no moment at which a
//! reader can see a record whose leaf, or whose place in the version order, is another
//! version's.
//!
//! # What each buys
//!
//! - The **leaf rows** hold each record's leaf hash, computed once when the record is
//!   written. The data commitment is a tree over leaves ordered by key, so its root and
//!   any trace come from a scan of 40-byte rows — no record is read, decoded,
//!   canonicalised or hashed on a read. The tree's shape is fixed by its leaf count
//!   ([`crate::merkle::root_of`]), and a new key lands among the others, so a write moves
//!   the position of every later leaf: no incremental frontier reproduces this
//!   commitment, and a root is `O(n)` 64-byte node hashes. That is the cheap part; the
//!   per-record JCS and SHA-256 over whole records was the expensive one.
//! - The **version rows** order the room by version, so `since_version` and a cursor
//!   seek (`ScanOpts::after`) instead of reading and sorting every record.
//! - The **head row** caches the room's [`TreeHead`]. Every write replaces it with
//!   `stale` and a fresh nonce in the same batch; a reader that finds it stale computes
//!   the head from the leaf rows and caches it only if the row is still the stale marker
//!   it read (`require_unchanged`). A writer's marker is never equal to an earlier one,
//!   so a head computed before a write can never be cached after it — a stale root is
//!   worse than a slow one (`merkle` docs), and this is how it is never served.
//!
//! # Rooms written before these rows existed
//!
//! No migration step. **A room is indexed exactly when its head row exists**: every
//! read and write first calls [`ensure`], which builds the index from the records when
//! the head row is absent — leaves and version rows first, the head row last, so an
//! interrupted build is finished by the next caller. The build writes only what the
//! records say, so two concurrent builds converge on the same rows.
//!
//! The commitment is unchanged: the same leaves, in the same order, through the same
//! [`crate::merkle::root_of`] and [`crate::merkle::inclusion_proof`]. A test holds it
//! against [`crate::merkle::tree_head`] over the records.

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;
use vti_common::store::{Batch, BatchOutcome, KeyspaceHandle, ScanOpts};

use super::{RecordOrder, room_scope};
use crate::Record;
use crate::merkle::{self, Hash, InclusionProof, TreeHead};

const LEAVES_PREFIX: &str = "room_leaf/v1:";
const BY_VERSION_PREFIX: &str = "room_by_version/v1:";
const HEAD_PREFIX: &str = "room_head/v1:";

/// Rows per batch when a room's index is built.
const BUILD_CHUNK: usize = 256;

fn leaf_prefix(room_id: &str) -> String {
    room_scope(LEAVES_PREFIX, room_id)
}

fn leaf_key(room_id: &str, key: &str) -> String {
    format!("{}{key}", leaf_prefix(room_id))
}

fn by_version_prefix(room_id: &str) -> String {
    room_scope(BY_VERSION_PREFIX, room_id)
}

/// Twenty digits: `u64::MAX` is twenty, so the version order is the key order.
fn by_version_key(room_id: &str, version: u64) -> String {
    format!("{}{version:020}", by_version_prefix(room_id))
}

pub(super) fn head_key(room_id: &str) -> String {
    room_scope(HEAD_PREFIX, room_id)
}

/// Every index row of one room, for [`super::purge_room_rows`].
pub(super) fn prefixes(room_id: &str) -> [String; 2] {
    [leaf_prefix(room_id), by_version_prefix(room_id)]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum HeadRow {
    /// A write landed since the head was last computed.
    Stale { nonce: String },
    /// The head over the leaf rows as they stand.
    Fresh {
        root: String,
        record_count: u64,
        head_version: u64,
    },
}

impl HeadRow {
    fn stale() -> Self {
        Self::Stale {
            nonce: uuid::Uuid::new_v4().to_string(),
        }
    }

    fn fresh(head: &TreeHead) -> Self {
        Self::Fresh {
            root: merkle::to_multibase(&head.root),
            record_count: head.record_count,
            head_version: head.head_version,
        }
    }
}

fn internal(room_id: &str, what: impl std::fmt::Display) -> AppError {
    AppError::Internal(format!("record index of `{room_id}`: {what}"))
}

fn leaf_of(room_id: &str, record: &Record) -> Result<Hash, AppError> {
    merkle::leaf_hash(&record.committed()).map_err(|e| internal(room_id, e))
}

fn encode_leaf(version: u64, hash: &Hash) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(hash);
    out
}

fn decode_leaf(raw: &[u8]) -> Option<(u64, Hash)> {
    let (version, hash) = raw.split_first_chunk::<8>()?;
    Some((u64::from_be_bytes(*version), hash.try_into().ok()?))
}

/// Add to `batch` the index rows for record `old` becoming `new` at the same key —
/// `None` for "not there". The caller puts the record row itself in the same batch.
///
/// The room must be indexed ([`ensure`]) before the batch is built.
pub(super) fn stage(
    batch: &mut Batch,
    room_id: &str,
    old: Option<&Record>,
    new: Option<&Record>,
) -> Result<(), AppError> {
    // A batch writes each key once, so a row that would be removed and rewritten is only
    // rewritten.
    if let Some(old) = old
        && new.is_none_or(|n| n.version != old.version)
    {
        batch.remove(by_version_key(room_id, old.version));
    }
    match (old, new) {
        (_, Some(new)) => {
            batch
                .insert_raw(
                    leaf_key(room_id, &new.key),
                    encode_leaf(new.version, &leaf_of(room_id, new)?),
                )
                .insert_raw(
                    by_version_key(room_id, new.version),
                    new.key.as_bytes().to_vec(),
                );
        }
        (Some(old), None) => {
            batch.remove(leaf_key(room_id, &old.key));
        }
        (None, None) => {}
    }
    batch.insert(head_key(room_id), &HeadRow::stale())?;
    Ok(())
}

/// Apply a batch that carries no preconditions.
pub(super) async fn apply(records: &KeyspaceHandle, batch: Batch) -> Result<(), AppError> {
    match records.apply_batch(batch).await? {
        BatchOutcome::Applied => Ok(()),
        BatchOutcome::Refused { check } => Err(AppError::Internal(format!(
            "a record write without preconditions was refused at check {check}"
        ))),
    }
}

/// Index the room if it is not yet (module docs). Cheap when it is: one row read.
pub(super) async fn ensure(records: &KeyspaceHandle, room_id: &str) -> Result<(), AppError> {
    if records.get_raw(head_key(room_id)).await?.is_some() {
        return Ok(());
    }
    build(records, room_id).await
}

/// Drop the room's head row, so the next caller rebuilds the whole index from the
/// records. For a host that rewrote a record row directly ([`super::record_storage_key`]).
pub(super) async fn forget(records: &KeyspaceHandle, room_id: &str) -> Result<(), AppError> {
    records.remove(head_key(room_id)).await
}

/// Build the room's index from its records: upsert every leaf and version row, remove
/// any the records do not account for, then write the head — last, so its presence
/// means the rest is in place.
async fn build(records: &KeyspaceHandle, room_id: &str) -> Result<(), AppError> {
    let all = super::list_records(records, room_id, None, None).await?;
    let room = room_id.to_string();
    // Canonicalising and hashing every record is the one expensive step, done once per
    // room, off the async executor.
    let mut rows = tokio::task::spawn_blocking(move || {
        all.into_iter()
            .map(|r| {
                let hash = leaf_of(&room, &r)?;
                Ok((r.key, r.version, hash))
            })
            .collect::<Result<Vec<_>, AppError>>()
    })
    .await
    .map_err(|e| internal(room_id, e))??;
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    let wanted_leaves: std::collections::HashSet<Vec<u8>> = rows
        .iter()
        .map(|(k, _, _)| leaf_key(room_id, k).into_bytes())
        .collect();
    let wanted_versions: std::collections::HashSet<Vec<u8>> = rows
        .iter()
        .map(|(_, v, _)| by_version_key(room_id, *v).into_bytes())
        .collect();
    let mut stray = Vec::new();
    for k in records.prefix_keys(leaf_prefix(room_id)).await? {
        if !wanted_leaves.contains(&k) {
            stray.push(k);
        }
    }
    for k in records.prefix_keys(by_version_prefix(room_id)).await? {
        if !wanted_versions.contains(&k) {
            stray.push(k);
        }
    }
    for chunk in stray.chunks(BUILD_CHUNK) {
        let mut batch = Batch::new();
        for k in chunk {
            batch.remove(k.clone());
        }
        apply(records, batch).await?;
    }
    for chunk in rows.chunks(BUILD_CHUNK) {
        let mut batch = Batch::new();
        for (key, version, hash) in chunk {
            batch
                .insert_raw(leaf_key(room_id, key), encode_leaf(*version, hash))
                .insert_raw(by_version_key(room_id, *version), key.as_bytes().to_vec());
        }
        apply(records, batch).await?;
    }

    let leaves = rows
        .into_iter()
        .map(|(k, v, h)| Leaf {
            key: k,
            version: v,
            hash: h,
        })
        .collect::<Vec<_>>();
    let (head, _) = compute(leaves, None).await?;
    let mut batch = Batch::new();
    batch
        .require_absent(head_key(room_id))
        .insert(head_key(room_id), &HeadRow::fresh(&head))?;
    // Refused: another caller built it first, from the same records.
    records.apply_batch(batch).await?;
    Ok(())
}

struct Leaf {
    key: String,
    version: u64,
    hash: Hash,
}

/// Every leaf row of the room, ordered by key — the commitment's order.
async fn load_leaves(records: &KeyspaceHandle, room_id: &str) -> Result<Vec<Leaf>, AppError> {
    let prefix = leaf_prefix(room_id);
    let mut out = Vec::new();
    for (k, v) in records.prefix_iter_raw(prefix.clone()).await? {
        let key = k
            .strip_prefix(prefix.as_bytes())
            .and_then(|k| std::str::from_utf8(k).ok())
            .ok_or_else(|| internal(room_id, "a leaf row's key is not a record key"))?
            .to_string();
        let (version, hash) =
            decode_leaf(&v).ok_or_else(|| internal(room_id, "a leaf row is not 40 bytes"))?;
        out.push(Leaf { key, version, hash });
    }
    // The store yields key order already; the commitment's order is not left to it.
    out.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(out)
}

/// The head over `leaves`, and the trace for `key` if it is one of them — computed off
/// the async executor, since a large room is a lot of node hashes.
async fn compute(
    leaves: Vec<Leaf>,
    key: Option<String>,
) -> Result<(TreeHead, Option<InclusionProof>), AppError> {
    tokio::task::spawn_blocking(move || {
        let hashes: Vec<Hash> = leaves.iter().map(|l| l.hash).collect();
        let head = TreeHead {
            root: merkle::root_of(&hashes),
            record_count: hashes.len() as u64,
            head_version: leaves.iter().map(|l| l.version).max().unwrap_or(0),
        };
        let trace = key
            .and_then(|k| leaves.binary_search_by(|l| l.key.as_str().cmp(&k)).ok())
            .and_then(|index| merkle::inclusion_proof(&hashes, index));
        (head, trace)
    })
    .await
    .map_err(|e| AppError::Internal(format!("commit a room's records: {e}")))
}

/// The room's head and, when `key` is given, that record's trace — from one scan of the
/// leaf rows. A fresh cached head answers a head-only read without the scan.
pub(super) async fn head(
    records: &KeyspaceHandle,
    room_id: &str,
    key: Option<&str>,
) -> Result<(TreeHead, Option<InclusionProof>), AppError> {
    ensure(records, room_id).await?;
    let raw = records
        .get_raw(head_key(room_id))
        .await?
        .ok_or_else(|| internal(room_id, "the head row went while it was read"))?;
    let row: HeadRow = serde_json::from_slice(&raw).map_err(|e| internal(room_id, e))?;
    if key.is_none()
        && let HeadRow::Fresh {
            root,
            record_count,
            head_version,
        } = &row
    {
        let root = merkle::from_multibase(root).map_err(|e| internal(room_id, e))?;
        return Ok((
            TreeHead {
                root,
                record_count: *record_count,
                head_version: *head_version,
            },
            None,
        ));
    }
    let leaves = load_leaves(records, room_id).await?;
    let (head, trace) = compute(leaves, key.map(str::to_string)).await?;
    if matches!(row, HeadRow::Stale { .. }) {
        // Cached only over the marker this read saw: a write since has replaced it, and
        // this head is then already old.
        let mut batch = Batch::new();
        batch
            .require_unchanged(head_key(room_id), raw)
            .insert(head_key(room_id), &HeadRow::fresh(&head))?;
        records.apply_batch(batch).await?;
    }
    Ok((head, trace))
}

/// Up to `want` of the room's records in `order`, by the version rows: versions above
/// `above` and below `below` (both exclusive, either absent), keys starting with
/// `key_prefix`. Reads only the version rows it walks and the records it returns.
pub(super) async fn page(
    records: &KeyspaceHandle,
    room_id: &str,
    key_prefix: Option<&str>,
    above: Option<u64>,
    below: Option<u64>,
    order: RecordOrder,
    want: usize,
) -> Result<Vec<Record>, AppError> {
    ensure(records, room_id).await?;
    let prefix = by_version_prefix(room_id);
    // A prefix filter may skip rows, so read ahead of the page — bounded per read.
    let batch = want.clamp(16, 1024);
    let opts = match order {
        RecordOrder::OldestFirst => {
            let opts = ScanOpts::new(prefix.clone(), batch);
            match above {
                Some(v) => opts.after(by_version_key(room_id, v)),
                None => opts,
            }
        }
        RecordOrder::NewestFirst => {
            let opts = ScanOpts::newest_first(prefix.clone(), batch);
            match below {
                Some(v) => opts.after(by_version_key(room_id, v)),
                None => opts,
            }
        }
    };
    let mut pager = records.scan_pager(opts);
    let mut out = Vec::with_capacity(want.min(1024));
    'walk: loop {
        let rows = pager.next_page().await?;
        if rows.is_empty() {
            break;
        }
        for (k, v) in rows {
            let version = k
                .strip_prefix(prefix.as_bytes())
                .and_then(|d| std::str::from_utf8(d).ok())
                .and_then(|d| d.parse::<u64>().ok())
                .ok_or_else(|| internal(room_id, "a version row's key is not a version"))?;
            match order {
                RecordOrder::OldestFirst if below.is_some_and(|b| version >= b) => break 'walk,
                RecordOrder::NewestFirst if above.is_some_and(|a| version <= a) => break 'walk,
                _ => {}
            }
            let key = String::from_utf8(v)
                .map_err(|_| internal(room_id, "a version row does not name a key"))?;
            if key_prefix.is_some_and(|p| !key.starts_with(p)) {
                continue;
            }
            let record = match super::get_record(records, room_id, &key).await {
                Ok(r) => r,
                Err(AppError::NotFound(_)) => continue,
                Err(e) => return Err(e),
            };
            // Written in one batch with the record, so this holds; a row that does not
            // is not served under a version it no longer has.
            if record.version != version {
                continue;
            }
            out.push(record);
            if out.len() >= want {
                break 'walk;
            }
        }
    }
    Ok(out)
}

/// Remove every index row of the room, head first: an interrupted removal leaves the
/// room unindexed rather than indexed wrongly.
pub(super) async fn purge(records: &KeyspaceHandle, room_id: &str) -> Result<(), AppError> {
    forget(records, room_id).await?;
    for prefix in prefixes(room_id) {
        for k in records.prefix_keys(prefix).await? {
            records.remove(k).await?;
        }
    }
    Ok(())
}
