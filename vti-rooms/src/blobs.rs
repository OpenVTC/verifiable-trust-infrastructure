//! Room files on the host side: the blob index, uploads and downloads, limits,
//! usage, reference counts and collection.
//!
//! A file is a record plus a blob (`docs/05-design-notes/data-rooms-files.md`).
//! The record is an ordinary room record, sealed as any other; this module keeps
//! everything about the **blob** — the file's ciphertext — that a host needs and
//! may know: its size, its manifest, which store holds it, how many records name
//! it, and whom it is charged to. It never sees a key or a byte of plaintext.
//!
//! Shared by every host for the same reason [`crate::storage`] is: a standalone
//! room host and a community serve the same tasks, and two implementations of
//! "does this upload fit" would come to two answers. The hosts parse the wire
//! (`rooms/blobs/*`, `rooms/records/put` 0.2, `rooms/info`) with the generated
//! types and call in here with what they verified.
//!
//! # What the host is told, and by whom
//!
//! Every entry point takes the **opener** — the party the host authenticated
//! for the request, from its proof — and, where usage is charged, the
//! **member** the chain descends from ([`crate::authz::AuthorizedAction::member`]).
//! Authorization by the room's chain happens before any call here; this module
//! decides only what the host's own limits and records allow.
//!
//! # Concurrency and crash-safety
//!
//! One async lock serialises every change to reservations, usage and reference
//! counts, so the check-then-reserve of an upload is atomic and two uploads
//! cannot both fit under a limit only one of them fits. The store has no
//! multi-key transactions: a crash between two of a step's writes can leave a
//! counter off by one blob, which the next collection pass does not repair.
//! That is a known limit of this first cut, written down rather than hidden.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vti_common::backup_transfer::bundle_store::{self, BundleState};
use vti_common::backup_transfer::chunked::{
    self, ChunkRateLimiter, ChunkWrite, ChunkedError, TransferTerms,
};
use vti_common::backup_transfer::{self, MAX_OPEN_BUNDLES_PER_DID};
use vti_common::blob_store::{self, BackendRef, BlobKey, BlobStore, Deletion, MAX_BLOB_BYTES};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::{Room, Visibility};

/// The blob index, upload and download records, record references and usage
/// counters. Part of the storage contract, like [`crate::ROOMS_KEYSPACE`].
pub const ROOM_BLOBS_KEYSPACE: &str = "room_blobs";

/// The chunked-transfer slots uploads stage through
/// ([`vti_common::backup_transfer`]). Its own keyspace, so the transfer sweeper
/// and the open-slot cap see only room uploads.
pub const ROOM_BLOB_TRANSFERS_KEYSPACE: &str = "room_blob_transfers";

/// How long an orphaned blob is kept before collection: long enough that a
/// retraction can be undone by rewriting the record, short enough that storage
/// is given back in days.
pub const DEFAULT_ORPHAN_GRACE_SECS: u64 = 7 * 24 * 60 * 60;

/// A download handle's idle lifetime; fetching chunks slides it forward, never
/// past [`DOWNLOAD_LIFETIME_SECS`] from opening. The same floors an upload slot
/// has, so a slow link that can upload a file can download it too.
const DOWNLOAD_TTL_SECS: i64 = 15 * 60;
const DOWNLOAD_LIFETIME_SECS: i64 = 24 * 60 * 60;

/// How long an upload that `begin` answered `alreadyCommitted` stays committable.
const ALREADY_COMMITTED_TTL_SECS: u64 = 15 * 60;

/// How long a finished upload's record is kept, so a repeated commit or abort is
/// answered with what happened rather than `notFound`.
const FINISHED_UPLOAD_RETENTION_SECS: u64 = 24 * 60 * 60;

/// Limits at one scope. An absent measure sets no limit of that kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_files: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_file_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
}

impl ScopeLimits {
    /// These limits with every byte measure capped at `ceiling`, which is what a
    /// host may report: a limit it would not enforce is not a limit.
    pub fn capped(self, ceiling: u64) -> Self {
        Self {
            max_files: self.max_files,
            max_file_bytes: Some(self.max_file_bytes.map_or(ceiling, |m| m.min(ceiling))),
            max_bytes: self.max_bytes,
        }
    }
}

/// What a host is willing to store, for every room it serves.
///
/// One set for the host, from its configuration: a standalone host has one
/// storage config and no per-room overrides. Per-room and per-member overrides
/// (`vtc/rooms/limits/set`) are a community's, and come with its integration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLimits {
    /// False refuses every upload. Reads of stored blobs continue.
    pub files_enabled: bool,
    /// Limits on each room as a whole.
    pub room: ScopeLimits,
    /// Limits on each member's own uploads in a room. Not applied on a
    /// `private` room, where the host cannot tell members apart.
    pub member: ScopeLimits,
    /// The host-wide ceiling on one blob; never above [`MAX_BLOB_BYTES`].
    pub max_file_bytes: u64,
    /// The storage's capacity, across every room on it.
    pub storage_capacity_bytes: Option<u64>,
    /// How long an orphaned blob waits before collection.
    pub orphan_grace_secs: u64,
}

impl Default for HostLimits {
    /// The shipped defaults of design note §6.2.
    fn default() -> Self {
        const MIB: u64 = 1024 * 1024;
        Self {
            files_enabled: true,
            room: ScopeLimits {
                max_files: Some(10_000),
                max_file_bytes: Some(100 * MIB),
                max_bytes: Some(5 * 1024 * MIB),
            },
            member: ScopeLimits {
                max_files: Some(2_000),
                max_file_bytes: Some(100 * MIB),
                max_bytes: Some(1024 * MIB),
            },
            max_file_bytes: MAX_BLOB_BYTES,
            storage_capacity_bytes: None,
            orphan_grace_secs: DEFAULT_ORPHAN_GRACE_SECS,
        }
    }
}

/// What one scope holds now, in ciphertext bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    /// Committed blobs that are not orphaned.
    pub files: u64,
    /// Their total size.
    pub bytes: u64,
    /// Bytes reserved by uploads begun and not yet finished.
    pub reserved_bytes: u64,
    /// Uploads begun and not yet finished.
    pub reserved_files: u64,
}

/// Which scope a refusing limit belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitScope {
    Member,
    Room,
    Storage,
    Host,
}

impl LimitScope {
    /// The `LimitScope` wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Room => "room",
            Self::Storage => "storage",
            Self::Host => "host",
        }
    }
}

/// The one limit that refused an upload, and its numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitExceeded {
    pub scope: LimitScope,
    /// `maxFiles`, `maxFileBytes` or `maxBytes`.
    pub measure: &'static str,
    pub limit: u64,
    /// Current use, reservations included; 0 for `maxFileBytes`.
    pub used: u64,
    /// What the upload would add.
    pub requested: u64,
}

impl LimitExceeded {
    /// The `LimitExceeded` `details` object.
    pub fn details(&self) -> Value {
        serde_json::json!({
            "scope": self.scope.as_str(),
            "measure": self.measure,
            "limit": self.limit,
            "used": self.used,
            "requested": self.requested,
        })
    }
}

/// Why a blob operation refused. Most arms are a task's declared error code,
/// which the host puts on the wire under that task's slug.
#[derive(Debug)]
pub enum BlobError {
    FilesDisabled,
    InvalidManifest(String),
    /// The opener already holds as many open uploads as the host allows one
    /// party. Retryable once one finishes.
    TooManyUploads {
        max_open: usize,
    },
    LimitExceeded(LimitExceeded),
    /// No such upload, download or blob for this caller, in this room.
    /// Deliberately conflates absent, finished, expired and somebody else's.
    NotFound,
    ChunkOutOfRange {
        index: u64,
        chunk_count: u64,
    },
    ChunkMismatch(String),
    Incomplete {
        remaining_count: u64,
    },
    DigestMismatch,
    RateLimited {
        retry_after_secs: u64,
    },
    App(AppError),
}

impl From<AppError> for BlobError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

impl std::fmt::Display for BlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FilesDisabled => write!(f, "this host stores no files for this room"),
            Self::InvalidManifest(why) => write!(f, "invalid manifest: {why}"),
            Self::TooManyUploads { max_open } => write!(
                f,
                "you already hold {max_open} open uploads; commit, abort or let one lapse"
            ),
            Self::LimitExceeded(l) => write!(
                f,
                "the upload would exceed the {} {} limit: {} of {} used, {} more requested",
                l.scope.as_str(),
                l.measure,
                l.used,
                l.limit,
                l.requested
            ),
            Self::NotFound => write!(f, "not found"),
            Self::ChunkOutOfRange { index, chunk_count } => {
                write!(
                    f,
                    "chunk {index} is not below the chunk count {chunk_count}"
                )
            }
            Self::ChunkMismatch(why) => write!(f, "{why}"),
            Self::Incomplete { remaining_count } => {
                write!(f, "{remaining_count} chunk(s) have not been sent")
            }
            Self::DigestMismatch => write!(
                f,
                "the reassembled ciphertext is not the manifest's digest; the upload is discarded"
            ),
            Self::RateLimited { retry_after_secs } => {
                write!(f, "too many chunk requests; retry in {retry_after_secs}s")
            }
            Self::App(e) => write!(f, "{e}"),
        }
    }
}

/// A received `BlobManifest`, checked for internal consistency.
#[derive(Debug, Clone)]
pub struct Manifest {
    /// The manifest exactly as received, returned to readers as committed.
    pub raw: Value,
    pub size: u64,
    pub chunk_size: u64,
    pub chunk_count: u64,
    pub chunk_digests: Vec<String>,
    /// The whole ciphertext's digest.
    pub digest: String,
    /// The digest of `raw`'s JCS form: the blob's name.
    pub blob_ref: String,
}

impl Manifest {
    /// Read and check a manifest the caller has already validated against the
    /// `BlobManifest` schema.
    ///
    /// Refuses what the schema cannot state: a chunk count that does not follow
    /// from the size and chunk size, a digest list of the wrong length, and any
    /// digest that is not sha2-256, the one hash this host implements.
    pub fn parse(raw: &Value) -> Result<Self, BlobError> {
        let bad = |why: &str| BlobError::InvalidManifest(why.to_string());
        let size = raw["size"]
            .as_u64()
            .ok_or_else(|| bad("`size` is missing"))?;
        let chunk_size = raw["chunks"]["chunkSize"]
            .as_u64()
            .ok_or_else(|| bad("`chunks.chunkSize` is missing"))?;
        let declared = raw["chunks"]["chunkCount"]
            .as_u64()
            .ok_or_else(|| bad("`chunks.chunkCount` is missing"))?;
        let chunk_digests: Vec<String> = raw["chunks"]["chunkDigests"]
            .as_array()
            .ok_or_else(|| bad("`chunks.chunkDigests` is missing"))?
            .iter()
            .map(|d| d.as_str().map(str::to_string))
            .collect::<Option<_>>()
            .ok_or_else(|| bad("a chunk digest is not a string"))?;
        let digest = raw["digest"]
            .as_str()
            .ok_or_else(|| bad("`digest` is missing"))?
            .to_string();

        let count = transfer_chunk_count(size, chunk_size).ok_or_else(|| {
            BlobError::InvalidManifest(format!(
                "{size} bytes do not divide into at most 4096 chunks of {chunk_size}"
            ))
        })?;
        if count != declared {
            return Err(BlobError::InvalidManifest(format!(
                "chunkCount is {declared}; {size} bytes at {chunk_size} is {count}"
            )));
        }
        if chunk_digests.len() as u64 != count {
            return Err(BlobError::InvalidManifest(format!(
                "chunkDigests has {} entries; the manifest has {count} chunks",
                chunk_digests.len()
            )));
        }
        if let Some(i) = chunk_digests
            .iter()
            .position(|d| blob_store::sha256_from_digest_multibase(d).is_none())
        {
            return Err(BlobError::InvalidManifest(format!(
                "chunkDigests[{i}] is not a sha2-256 multihash, the hash this host implements"
            )));
        }
        if blob_store::sha256_from_digest_multibase(&digest).is_none() {
            return Err(bad("`digest` is not a sha2-256 multihash"));
        }
        let blob_ref = blob_store::blob_ref_of_manifest(raw)?;
        Ok(Self {
            raw: raw.clone(),
            size,
            chunk_size,
            chunk_count: count,
            chunk_digests,
            digest,
            blob_ref,
        })
    }

    fn sha256_hex(&self) -> String {
        let bytes =
            blob_store::sha256_from_digest_multibase(&self.digest).expect("checked at parse");
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

fn transfer_chunk_count(size: u64, chunk_size: u64) -> Option<u64> {
    // The transfer's own formula and bounds, so a manifest this accepts is one
    // the chunked transfer below accepts too.
    const MIN: u64 = 16_384;
    const MAX: u64 = 262_144;
    if !(MIN..=MAX).contains(&chunk_size) || size == 0 {
        return None;
    }
    let count = size.div_ceil(chunk_size);
    (count <= 4_096).then_some(count)
}

/// Where a blob stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BlobState {
    /// Stored, and counted against its room and member.
    Committed,
    /// No record names it any more. Counted against the storage only, until
    /// collected.
    Orphaned,
}

/// One committed blob of one room.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobEntry {
    pub room_id: String,
    pub blob_ref: String,
    pub size: u64,
    /// The manifest exactly as committed.
    pub manifest: Value,
    /// The storage config it was written to.
    pub config_id: String,
    pub backend_ref: BackendRef,
    pub state: BlobState,
    /// How many records name it.
    pub refs: u64,
    /// The member its size is charged to; `None` on a `private` room.
    pub charged_to: Option<String>,
    pub committed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orphaned_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum UploadPhase {
    Open,
    Committed,
    Aborted,
    /// Expired or discarded: its reservation has been given back.
    Released,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadRecord {
    upload_id: Uuid,
    room_id: String,
    opener: String,
    charged_to: Option<String>,
    blob_ref: String,
    size: u64,
    manifest: Value,
    phase: UploadPhase,
    created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    finished_at: Option<u64>,
    /// Begun on a blob already committed in the room: no slot, no chunks, no
    /// reservation, and a commit that answers with the existing blob.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    already_committed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DownloadRecord {
    download_id: Uuid,
    room_id: String,
    opener: String,
    blob_ref: String,
    expires_at: DateTime<Utc>,
    ceiling: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StorageUsage {
    files: u64,
    bytes: u64,
    reserved_bytes: u64,
}

/// What `begin` answers.
#[derive(Debug, Clone)]
pub struct Begun {
    pub upload_id: Uuid,
    pub missing: Vec<u64>,
    pub expires_at: DateTime<Utc>,
    /// The BlobRef is already committed in this room; commit answers with it.
    pub already_committed: bool,
}

/// What a stored chunk answers.
#[derive(Debug, Clone, Copy)]
pub struct ChunkStored {
    pub stored: bool,
    pub remaining_count: u64,
    pub expires_at: DateTime<Utc>,
}

/// What `commit` answers.
#[derive(Debug, Clone)]
pub struct Committed {
    pub blob_ref: String,
    pub size: u64,
}

/// What `get` answers.
#[derive(Debug, Clone)]
pub struct Download {
    pub download_id: Uuid,
    pub manifest: Value,
    pub expires_at: DateTime<Utc>,
}

/// One served chunk.
#[derive(Debug, Clone)]
pub struct ServedChunk {
    pub data: Vec<u8>,
    pub digest_multibase: String,
}

/// What one collection pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepStats {
    /// Orphaned or never-referenced blobs deleted from the store.
    pub collected: usize,
    /// Uploads whose reservation was given back because they expired.
    pub released: usize,
    /// Finished upload and expired download records dropped.
    pub forgotten: usize,
}

/// A room's limits as a host reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveLimits {
    pub files_enabled: bool,
    pub room: ScopeLimits,
    pub member: ScopeLimits,
}

/// Everything a host needs to store room files.
pub struct BlobHost {
    blobs: KeyspaceHandle,
    transfers: KeyspaceHandle,
    staging_dir: PathBuf,
    store: Arc<dyn BlobStore>,
    config_id: String,
    limits: HostLimits,
    lock: tokio::sync::Mutex<()>,
}

fn room_hash(room_id: &str) -> String {
    // `rooms/<32 hex>/` → `<32 hex>`.
    blob_store::room_prefix(room_id)
        .trim_start_matches("rooms/")
        .trim_end_matches('/')
        .to_string()
}

fn short_hash(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0u8]);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn blob_key(room_id: &str, blob_ref: &str) -> String {
    format!("blob:{}:{blob_ref}", room_hash(room_id))
}
fn refs_key(room_id: &str, record_key: &str) -> String {
    format!("refs:{}:{record_key}", room_hash(room_id))
}
fn upload_key(id: &Uuid) -> String {
    format!("upload:{id}")
}
fn upload_index_key(opener: &str, room_id: &str, blob_ref: &str) -> String {
    format!("upload-by:{}", short_hash(&[opener, room_id, blob_ref]))
}
fn download_key(id: &Uuid) -> String {
    format!("download:{id}")
}
fn room_usage_key(room_id: &str) -> String {
    format!("usage:room:{}", room_hash(room_id))
}
fn member_usage_key(room_id: &str, member: &str) -> String {
    format!(
        "usage:member:{}:{}",
        room_hash(room_id),
        short_hash(&[member])
    )
}
const STORAGE_USAGE_KEY: &str = "usage:storage";

/// When an `alreadyCommitted` upload stops being committable.
fn already_expiry(rec: &UploadRecord) -> DateTime<Utc> {
    DateTime::from_timestamp((rec.created_at + ALREADY_COMMITTED_TTL_SECS) as i64, 0)
        .unwrap_or_else(Utc::now)
}

fn now_secs() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

fn checked_sub(a: u64, b: u64, what: &str) -> u64 {
    a.checked_sub(b).unwrap_or_else(|| {
        tracing::warn!(what, "usage counter would go below zero; clamped");
        0
    })
}

impl BlobHost {
    /// A host over `blobs` and `transfers` (opened as [`ROOM_BLOBS_KEYSPACE`] and
    /// [`ROOM_BLOB_TRANSFERS_KEYSPACE`]), staging uploads under `staging_dir` and
    /// storing committed blobs in `store`, recorded as config `config_id`.
    pub fn new(
        blobs: KeyspaceHandle,
        transfers: KeyspaceHandle,
        staging_dir: PathBuf,
        store: Arc<dyn BlobStore>,
        config_id: impl Into<String>,
        mut limits: HostLimits,
    ) -> Self {
        limits.max_file_bytes = limits.max_file_bytes.min(MAX_BLOB_BYTES);
        Self {
            blobs,
            transfers,
            staging_dir,
            store,
            config_id: config_id.into(),
            limits,
            lock: tokio::sync::Mutex::new(()),
        }
    }

    /// The limits this host applies to `room`, as it reports them.
    pub fn effective_limits(&self, _room: &Room) -> EffectiveLimits {
        EffectiveLimits {
            files_enabled: self.limits.files_enabled,
            room: self.limits.room.capped(self.limits.max_file_bytes),
            member: self
                .limits
                .member
                .capped(self.limits.max_file_bytes)
                // A member's largest file is never more than the room's.
                .min_file(self.limits.room.max_file_bytes),
        }
    }

    /// The room's usage, reservations included.
    pub async fn room_usage(&self, room_id: &str) -> Result<Usage, AppError> {
        Ok(self
            .blobs
            .get(room_usage_key(room_id))
            .await?
            .unwrap_or_default())
    }

    /// One member's usage in a room.
    pub async fn member_usage(&self, room_id: &str, member: &str) -> Result<Usage, AppError> {
        Ok(self
            .blobs
            .get(member_usage_key(room_id, member))
            .await?
            .unwrap_or_default())
    }

    /// The committed blob `blob_ref` of `room_id`, if there is one.
    pub async fn blob(&self, room_id: &str, blob_ref: &str) -> Result<Option<BlobEntry>, AppError> {
        self.blobs.get(blob_key(room_id, blob_ref)).await
    }

    // ─── upload ──────────────────────────────────────────────────────────

    /// `rooms/blobs/upload/begin`: check the upload against every limit,
    /// reserve, and open a staging slot — or answer the open slot this opener
    /// already has for this manifest in this room.
    ///
    /// `member` is the subject at the root of the opener's chain, `None` on a
    /// `private` room.
    pub async fn begin(
        &self,
        room: &Room,
        opener: &str,
        member: Option<&str>,
        manifest: Manifest,
    ) -> Result<Begun, BlobError> {
        if !self.limits.files_enabled {
            return Err(BlobError::FilesDisabled);
        }
        let member = match room.visibility {
            Visibility::Private => None,
            _ => member,
        };
        let _guard = self.lock.lock().await;

        // Resume: the same opener, room and manifest, while its slot is open.
        let index = upload_index_key(opener, &room.room_id, &manifest.blob_ref);
        if let Some(id) = self.blobs.get::<Uuid>(index.clone()).await?
            && let Some(mut rec) = self.blobs.get::<UploadRecord>(upload_key(&id)).await?
            && rec.phase == UploadPhase::Open
        {
            if rec.already_committed {
                if rec.created_at + ALREADY_COMMITTED_TTL_SECS > now_secs()
                    && self.blob(&room.room_id, &rec.blob_ref).await?.is_some()
                {
                    return Ok(Begun {
                        upload_id: id,
                        missing: Vec::new(),
                        expires_at: already_expiry(&rec),
                        already_committed: true,
                    });
                }
            } else if let Some(slot) = self.live_slot(&id).await? {
                let plan = chunked::get_plan(&self.transfers, &id)
                    .await?
                    .ok_or(BlobError::NotFound)?;
                let missing = plan
                    .done
                    .iter()
                    .enumerate()
                    .filter(|(_, d)| !**d)
                    .map(|(i, _)| i as u64)
                    .collect();
                return Ok(Begun {
                    upload_id: id,
                    missing,
                    expires_at: slot.expires_at,
                    already_committed: false,
                });
            }
            // Its slot lapsed: give its reservation back and open a new one.
            if !rec.already_committed {
                self.release_reservation(&rec).await?;
            }
            rec.phase = UploadPhase::Released;
            rec.finished_at = Some(now_secs());
            self.blobs.insert(upload_key(&id), &rec).await?;
        }

        // Already committed in this room: nothing to send, nothing to reserve.
        // A BlobRef in another room is never reported; it is stored again here.
        if self
            .blob(&room.room_id, &manifest.blob_ref)
            .await?
            .is_some()
        {
            let rec = UploadRecord {
                upload_id: Uuid::new_v4(),
                room_id: room.room_id.clone(),
                opener: opener.to_string(),
                charged_to: member.map(str::to_string),
                blob_ref: manifest.blob_ref.clone(),
                size: manifest.size,
                manifest: manifest.raw.clone(),
                phase: UploadPhase::Open,
                created_at: now_secs(),
                finished_at: None,
                already_committed: true,
            };
            self.blobs.insert(upload_key(&rec.upload_id), &rec).await?;
            self.blobs.insert(index, &rec.upload_id).await?;
            return Ok(Begun {
                upload_id: rec.upload_id,
                missing: Vec::new(),
                expires_at: already_expiry(&rec),
                already_committed: true,
            });
        }

        self.check_limits(&room.room_id, member, manifest.size)
            .await?;

        let slot = match chunked::initiate_import_with(
            &self.transfers,
            opener,
            &manifest.sha256_hex(),
            manifest.size,
            manifest.chunk_size,
            manifest.chunk_count,
            manifest.chunk_digests.clone(),
            TransferTerms::room_file(),
        )
        .await
        {
            Ok(s) => s,
            Err(ChunkedError::InvalidManifest(why)) => return Err(BlobError::InvalidManifest(why)),
            Err(ChunkedError::App(AppError::Conflict(_))) => {
                // The per-opener cap on open slots. Not a limit of the room's,
                // and retryable once a slot finishes.
                return Err(BlobError::TooManyUploads {
                    max_open: MAX_OPEN_BUNDLES_PER_DID,
                });
            }
            Err(e) => return Err(chunked_error(e)),
        };

        let rec = UploadRecord {
            upload_id: slot.bundle_id,
            room_id: room.room_id.clone(),
            opener: opener.to_string(),
            charged_to: member.map(str::to_string),
            blob_ref: manifest.blob_ref.clone(),
            size: manifest.size,
            manifest: manifest.raw.clone(),
            phase: UploadPhase::Open,
            created_at: now_secs(),
            finished_at: None,
            already_committed: false,
        };
        self.reserve(&rec).await?;
        self.blobs.insert(upload_key(&rec.upload_id), &rec).await?;
        self.blobs.insert(index, &rec.upload_id).await?;
        Ok(Begun {
            upload_id: slot.bundle_id,
            missing: (0..slot.chunk_count).collect(),
            expires_at: slot.expires_at,
            already_committed: false,
        })
    }

    /// `rooms/blobs/upload/chunk`.
    pub async fn put_chunk(
        &self,
        opener: &str,
        upload_id: &str,
        index: u64,
        digest_multibase: &str,
        data: &[u8],
    ) -> Result<ChunkStored, BlobError> {
        let rec = self.owned_open_upload(opener, upload_id).await?;
        let result = chunked::put_chunk_for(
            &self.transfers,
            &self.staging_dir,
            ChunkRateLimiter::global(),
            opener,
            ChunkWrite {
                bundle_id: &rec.upload_id.to_string(),
                index,
                digest_multibase,
                data,
            },
        )
        .await;
        match result {
            Ok(o) => Ok(ChunkStored {
                stored: o.stored,
                remaining_count: o.remaining_count,
                expires_at: o.expires_at,
            }),
            Err(e) => Err(chunked_error(e)),
        }
    }

    /// `rooms/blobs/upload/commit`.
    pub async fn commit(&self, opener: &str, upload_id: &str) -> Result<Committed, BlobError> {
        let Ok(id) = Uuid::parse_str(upload_id) else {
            return Err(BlobError::NotFound);
        };
        let _guard = self.lock.lock().await;
        let mut rec = match self.blobs.get::<UploadRecord>(upload_key(&id)).await? {
            Some(r) if r.opener == opener => r,
            _ => return Err(BlobError::NotFound),
        };
        match rec.phase {
            UploadPhase::Open => {}
            // Answered again, storing and charging nothing a second time.
            UploadPhase::Committed => {
                return Ok(Committed {
                    blob_ref: rec.blob_ref,
                    size: rec.size,
                });
            }
            UploadPhase::Aborted | UploadPhase::Released => return Err(BlobError::NotFound),
        }

        // Begun on a blob this room already holds: answer with it, charging
        // nothing. Gone since (collected), the upload is gone with it.
        if rec.already_committed {
            let Some(entry) = self.blob(&rec.room_id, &rec.blob_ref).await? else {
                return Err(BlobError::NotFound);
            };
            rec.phase = UploadPhase::Committed;
            rec.finished_at = Some(now_secs());
            self.blobs.insert(upload_key(&id), &rec).await?;
            return Ok(Committed {
                blob_ref: entry.blob_ref,
                size: entry.size,
            });
        }

        match chunked::finalize_precheck_for(&self.transfers, opener, upload_id).await {
            Ok(()) => {}
            Err(ChunkedError::IncompleteUpload { missing_count, .. }) => {
                return Err(BlobError::Incomplete {
                    remaining_count: missing_count,
                });
            }
            Err(ChunkedError::BundleDigestMismatch) => {
                let _ = backup_transfer::abort(&self.transfers, opener, &id).await;
                self.release_reservation(&rec).await?;
                rec.phase = UploadPhase::Released;
                rec.finished_at = Some(now_secs());
                self.blobs.insert(upload_key(&id), &rec).await?;
                return Err(BlobError::DigestMismatch);
            }
            Err(e) => return Err(chunked_error(e)),
        }

        // Already in this room: store and charge nothing twice.
        if self.blob(&rec.room_id, &rec.blob_ref).await?.is_some() {
            self.release_reservation(&rec).await?;
            self.close_slot(&id).await?;
            rec.phase = UploadPhase::Committed;
            rec.finished_at = Some(now_secs());
            self.blobs.insert(upload_key(&id), &rec).await?;
            return Ok(Committed {
                blob_ref: rec.blob_ref,
                size: rec.size,
            });
        }

        let slot = bundle_store::get_bundle(&self.transfers, &id)
            .await?
            .ok_or(BlobError::NotFound)?;
        let staged = slot.blob_path.clone().ok_or(BlobError::NotFound)?;
        let key = BlobKey::for_room(&rec.room_id, &rec.blob_ref)?;
        // Durable in the store before anything says it is committed.
        let backend_ref = self.store.put(&key, &staged, rec.size).await?;

        let entry = BlobEntry {
            room_id: rec.room_id.clone(),
            blob_ref: rec.blob_ref.clone(),
            size: rec.size,
            manifest: rec.manifest.clone(),
            config_id: self.config_id.clone(),
            backend_ref,
            state: BlobState::Committed,
            refs: 0,
            charged_to: rec.charged_to.clone(),
            committed_at: now_secs(),
            orphaned_at: None,
        };
        self.blobs
            .insert(blob_key(&entry.room_id, &entry.blob_ref), &entry)
            .await?;
        self.convert_reservation(&rec).await?;
        rec.phase = UploadPhase::Committed;
        rec.finished_at = Some(now_secs());
        self.blobs.insert(upload_key(&id), &rec).await?;
        self.close_slot(&id).await?;
        Ok(Committed {
            blob_ref: entry.blob_ref,
            size: entry.size,
        })
    }

    /// `rooms/blobs/upload/abort`. `Ok(true)` when this call aborted it,
    /// `Ok(false)` when it already was.
    pub async fn abort(&self, opener: &str, upload_id: &str) -> Result<bool, BlobError> {
        let Ok(id) = Uuid::parse_str(upload_id) else {
            return Err(BlobError::NotFound);
        };
        let _guard = self.lock.lock().await;
        let mut rec = match self.blobs.get::<UploadRecord>(upload_key(&id)).await? {
            Some(r) if r.opener == opener => r,
            _ => return Err(BlobError::NotFound),
        };
        match rec.phase {
            UploadPhase::Open => {}
            UploadPhase::Aborted => return Ok(false),
            // A committed blob goes by dropping it from every record, never by
            // aborting; an expired upload is not one this caller can abort.
            UploadPhase::Committed | UploadPhase::Released => return Err(BlobError::NotFound),
        }
        if !rec.already_committed {
            if let Err(e) = backup_transfer::abort(&self.transfers, opener, &id).await
                && !matches!(e, AppError::NotFound(_))
            {
                return Err(e.into());
            }
            self.release_reservation(&rec).await?;
        }
        rec.phase = UploadPhase::Aborted;
        rec.finished_at = Some(now_secs());
        self.blobs.insert(upload_key(&id), &rec).await?;
        Ok(true)
    }

    // ─── download ────────────────────────────────────────────────────────

    /// `rooms/blobs/get`: the manifest as committed, and a download handle
    /// bound to the opener.
    ///
    /// An orphaned blob not yet collected is still served: a member may hold a
    /// record version that names it.
    pub async fn open_download(
        &self,
        room_id: &str,
        opener: &str,
        blob_ref: &str,
    ) -> Result<Download, BlobError> {
        let entry = self
            .blob(room_id, blob_ref)
            .await?
            .ok_or(BlobError::NotFound)?;
        let now = Utc::now();
        let rec = DownloadRecord {
            download_id: Uuid::new_v4(),
            room_id: room_id.to_string(),
            opener: opener.to_string(),
            blob_ref: blob_ref.to_string(),
            expires_at: now + Duration::seconds(DOWNLOAD_TTL_SECS),
            ceiling: now + Duration::seconds(DOWNLOAD_LIFETIME_SECS),
        };
        self.blobs
            .insert(download_key(&rec.download_id), &rec)
            .await?;
        Ok(Download {
            download_id: rec.download_id,
            manifest: entry.manifest,
            expires_at: rec.expires_at,
        })
    }

    /// `rooms/blobs/chunk`: chunk `index` of an open download, checked against
    /// its committed digest before it is served.
    pub async fn read_chunk(
        &self,
        opener: &str,
        download_id: &str,
        index: u64,
    ) -> Result<ServedChunk, BlobError> {
        if let Err(ChunkedError::RateLimited { retry_after_secs }) =
            ChunkRateLimiter::global().check(opener)
        {
            return Err(BlobError::RateLimited { retry_after_secs });
        }
        let Ok(id) = Uuid::parse_str(download_id) else {
            return Err(BlobError::NotFound);
        };
        let now = Utc::now();
        let mut rec = match self.blobs.get::<DownloadRecord>(download_key(&id)).await? {
            Some(r) if r.opener == opener && r.expires_at > now => r,
            _ => return Err(BlobError::NotFound),
        };
        let entry = self
            .blob(&rec.room_id, &rec.blob_ref)
            .await?
            .ok_or(BlobError::NotFound)?;
        let manifest = Manifest::parse(&entry.manifest).map_err(|e| {
            BlobError::App(AppError::Internal(format!(
                "stored manifest of `{}` no longer parses: {e}",
                entry.blob_ref
            )))
        })?;
        if index >= manifest.chunk_count {
            return Err(BlobError::ChunkOutOfRange {
                index,
                chunk_count: manifest.chunk_count,
            });
        }
        let start = index * manifest.chunk_size;
        let end = (start + manifest.chunk_size).min(manifest.size);
        let data = self.store.get_range(&entry.backend_ref, start, end).await?;
        let digest = &manifest.chunk_digests[index as usize];
        // Storage corruption is the host's fault, never the reader's, and
        // serving it would hand them a chunk their own check refuses.
        if blob_store::sha256_from_digest_multibase(digest) != Some(Sha256::digest(&data).into()) {
            return Err(BlobError::App(AppError::Internal(format!(
                "stored chunk {index} of `{}` does not match its committed digest",
                entry.blob_ref
            ))));
        }
        rec.expires_at = (now + Duration::seconds(DOWNLOAD_TTL_SECS)).min(rec.ceiling);
        self.blobs.insert(download_key(&id), &rec).await?;
        Ok(ServedChunk {
            data,
            digest_multibase: digest.clone(),
        })
    }

    // ─── records ─────────────────────────────────────────────────────────

    /// The blobs the current version of record `record_key` names.
    pub async fn record_blobs(
        &self,
        room_id: &str,
        record_key: &str,
    ) -> Result<Vec<String>, AppError> {
        Ok(self
            .blobs
            .get(refs_key(room_id, record_key))
            .await?
            .unwrap_or_default())
    }

    /// Prepare a record write that will name exactly `blobs`, holding the lock
    /// until it is applied or dropped.
    ///
    /// Refuses with [`BlobError::NotFound`] unless every blob is committed in
    /// `room_id` — the same refusal whether one was never uploaded, is still
    /// uploading, belongs to another room or was collected. A blob that is
    /// orphaned and not yet collected is re-referenced: it is charged again, to
    /// `member` (the writer's, `None` on a `private` room), and refused with
    /// [`BlobError::LimitExceeded`] if the member's or the room's counts and
    /// totals would not hold it.
    ///
    /// The caller writes the record while it holds the returned value, then
    /// calls [`RecordBlobs::apply`]; a write that fails drops it and changes
    /// nothing.
    pub async fn prepare_record(
        &self,
        room: &Room,
        member: Option<&str>,
        record_key: &str,
        blobs: &[String],
    ) -> Result<RecordBlobs<'_>, BlobError> {
        let guard = self.lock.lock().await;
        let member = match room.visibility {
            Visibility::Private => None,
            _ => member,
        };
        let previous = self.record_blobs(&room.room_id, record_key).await?;
        let (mut files, mut bytes) = (0u64, 0u64);
        for b in blobs {
            if blob_store::validate_blob_ref(b).is_err() {
                return Err(BlobError::NotFound);
            }
            let entry = self
                .blob(&room.room_id, b)
                .await?
                .ok_or(BlobError::NotFound)?;
            if entry.state == BlobState::Orphaned && !previous.contains(b) {
                files += 1;
                bytes += entry.size;
            }
        }
        if files > 0 {
            self.check_totals(&room.room_id, member, files, bytes, false)
                .await?;
        }
        Ok(RecordBlobs {
            host: self,
            _guard: guard,
            room_id: room.room_id.clone(),
            record_key: record_key.to_string(),
            blobs: blobs.to_vec(),
            previous,
            member: member.map(str::to_string),
        })
    }

    /// Release every blob record `record_key` names, as a retraction does.
    pub async fn release_record(&self, room_id: &str, record_key: &str) -> Result<(), AppError> {
        let _guard = self.lock.lock().await;
        let previous = self.record_blobs(room_id, record_key).await?;
        self.apply_refs(room_id, record_key, &previous, &[], None)
            .await
    }

    async fn apply_refs(
        &self,
        room_id: &str,
        record_key: &str,
        previous: &[String],
        blobs: &[String],
        member: Option<&str>,
    ) -> Result<(), AppError> {
        if previous.is_empty() && blobs.is_empty() {
            return Ok(());
        }
        for b in blobs.iter().filter(|b| !previous.contains(b)) {
            self.adjust_refs(room_id, b, 1, member).await?;
        }
        for b in previous.iter().filter(|b| !blobs.contains(b)) {
            self.adjust_refs(room_id, b, -1, member).await?;
        }
        let key = refs_key(room_id, record_key);
        if blobs.is_empty() {
            self.blobs.remove(key).await
        } else {
            self.blobs.insert(key, &blobs.to_vec()).await
        }
    }

    async fn adjust_refs(
        &self,
        room_id: &str,
        blob_ref: &str,
        delta: i64,
        member: Option<&str>,
    ) -> Result<(), AppError> {
        let key = blob_key(room_id, blob_ref);
        let Some(mut entry) = self.blobs.get::<BlobEntry>(key.clone()).await? else {
            // Collected between the check and the write. The record names a
            // blob this host no longer has; say so rather than invent one.
            tracing::error!(
                room = room_id,
                blob = blob_ref,
                "a record names a collected blob"
            );
            return Ok(());
        };
        if delta > 0 {
            entry.refs += 1;
            if entry.state == BlobState::Orphaned {
                // Charged again, as a new upload of it would be: to the member
                // whose record now names it.
                entry.state = BlobState::Committed;
                entry.orphaned_at = None;
                entry.charged_to = member.map(str::to_string);
                self.charge(&entry, true).await?;
            }
        } else {
            entry.refs = entry.refs.saturating_sub(1);
            if entry.refs == 0 && entry.state == BlobState::Committed {
                entry.state = BlobState::Orphaned;
                entry.orphaned_at = Some(now_secs());
                // Members expect a delete to make room, so the room and member
                // are credited now; the storage keeps counting until collected.
                self.charge(&entry, false).await?;
            }
        }
        self.blobs.insert(key, &entry).await
    }

    // ─── collection ──────────────────────────────────────────────────────

    /// One collection pass: delete orphaned and never-referenced blobs past the
    /// grace window, give back the reservations of uploads that expired, and
    /// forget finished uploads and expired downloads.
    pub async fn sweep(&self) -> Result<SweepStats, AppError> {
        let mut stats = SweepStats::default();
        backup_transfer::sweeper::sweep_bundles(&self.transfers, &self.staging_dir).await?;
        let now = now_secs();
        let grace = self.limits.orphan_grace_secs;

        for (key, raw) in self.blobs.prefix_iter_raw(b"blob:".to_vec()).await? {
            let Ok(entry) = serde_json::from_slice::<BlobEntry>(&raw) else {
                continue;
            };
            let due = match entry.state {
                BlobState::Orphaned => entry.orphaned_at.unwrap_or(0) + grace <= now,
                // Committed and never named by a record: the uploader abandoned it.
                BlobState::Committed => entry.refs == 0 && entry.committed_at + grace <= now,
            };
            if !due {
                continue;
            }
            let _guard = self.lock.lock().await;
            // Re-read under the lock: a record may have named it since.
            let Some(entry) = self.blobs.get::<BlobEntry>(key.clone()).await? else {
                continue;
            };
            if entry.refs > 0 {
                continue;
            }
            match self.store.delete(&entry.backend_ref).await {
                Ok(Deletion::Deleted) | Ok(Deletion::Lapses { .. }) => {}
                Ok(Deletion::Unsupported) => {
                    tracing::warn!(blob = %entry.blob_ref, "store cannot delete; forgetting the blob");
                }
                Err(e) => {
                    tracing::warn!(blob = %entry.blob_ref, error = %e, "collection failed; retry next pass");
                    continue;
                }
            }
            if entry.state == BlobState::Committed {
                self.charge(&entry, false).await?;
            }
            let mut storage = self.storage_usage().await?;
            storage.files = checked_sub(storage.files, 1, "storage files");
            storage.bytes = checked_sub(storage.bytes, entry.size, "storage bytes");
            self.blobs.insert(STORAGE_USAGE_KEY, &storage).await?;
            self.blobs.remove(key).await?;
            stats.collected += 1;
        }

        let uploads = self.blobs.prefix_iter_raw(b"upload:".to_vec()).await?;
        for (key, raw) in uploads {
            let Ok(mut rec) = serde_json::from_slice::<UploadRecord>(&raw) else {
                continue;
            };
            match rec.phase {
                UploadPhase::Open => {
                    let _guard = self.lock.lock().await;
                    let lapsed = if rec.already_committed {
                        rec.created_at + ALREADY_COMMITTED_TTL_SECS <= now
                    } else {
                        self.live_slot(&rec.upload_id).await?.is_none()
                    };
                    if lapsed {
                        if !rec.already_committed {
                            self.release_reservation(&rec).await?;
                        }
                        rec.phase = UploadPhase::Released;
                        rec.finished_at = Some(now);
                        self.blobs.insert(key, &rec).await?;
                        stats.released += 1;
                    }
                }
                _ if rec.finished_at.unwrap_or(rec.created_at) + FINISHED_UPLOAD_RETENTION_SECS
                    <= now =>
                {
                    self.blobs.remove(key).await?;
                    let index = upload_index_key(&rec.opener, &rec.room_id, &rec.blob_ref);
                    if self.blobs.get::<Uuid>(index.clone()).await? == Some(rec.upload_id) {
                        self.blobs.remove(index).await?;
                    }
                    stats.forgotten += 1;
                }
                _ => {}
            }
        }

        let utc_now = Utc::now();
        for (key, raw) in self.blobs.prefix_iter_raw(b"download:".to_vec()).await? {
            if let Ok(rec) = serde_json::from_slice::<DownloadRecord>(&raw)
                && rec.expires_at <= utc_now
            {
                self.blobs.remove(key).await?;
                stats.forgotten += 1;
            }
        }
        Ok(stats)
    }

    // ─── internals ───────────────────────────────────────────────────────

    async fn owned_open_upload(
        &self,
        opener: &str,
        upload_id: &str,
    ) -> Result<UploadRecord, BlobError> {
        let Ok(id) = Uuid::parse_str(upload_id) else {
            return Err(BlobError::NotFound);
        };
        match self.blobs.get::<UploadRecord>(upload_key(&id)).await? {
            Some(r) if r.opener == opener && r.phase == UploadPhase::Open => Ok(r),
            _ => Err(BlobError::NotFound),
        }
    }

    /// The slot behind an upload while it can still take chunks.
    async fn live_slot(&self, id: &Uuid) -> Result<Option<bundle_store::BundleRecord>, AppError> {
        Ok(bundle_store::get_bundle(&self.transfers, id)
            .await?
            .filter(|b| !b.state.is_terminal() && b.expires_at > Utc::now()))
    }

    /// Finish a committed upload's slot: its staged bytes go, and it is
    /// terminal.
    async fn close_slot(&self, id: &Uuid) -> Result<(), AppError> {
        if let Some(mut b) = bundle_store::get_bundle(&self.transfers, id).await? {
            if let Some(path) = b.blob_path.take() {
                let _ = tokio::fs::remove_file(&path).await;
            }
            b.state = BundleState::ImportCommitted;
            bundle_store::store_bundle(&self.transfers, &b).await?;
        }
        chunked::delete_plan(&self.transfers, id).await
    }

    async fn storage_usage(&self) -> Result<StorageUsage, AppError> {
        Ok(self.blobs.get(STORAGE_USAGE_KEY).await?.unwrap_or_default())
    }

    /// Every limit an upload of `size` must fit. Called under the lock,
    /// immediately before [`Self::reserve`].
    ///
    /// For `maxFileBytes` the refusal names the scope the smallest applicable
    /// limit was set at, and of two scopes setting the same value the narrower;
    /// for a count or a total, the narrowest scope that would be exceeded.
    async fn check_limits(
        &self,
        room_id: &str,
        member: Option<&str>,
        size: u64,
    ) -> Result<(), BlobError> {
        let mut smallest: Option<(LimitScope, u64)> = None;
        let candidates = [
            (
                LimitScope::Member,
                member.and(self.limits.member.max_file_bytes),
            ),
            (LimitScope::Room, self.limits.room.max_file_bytes),
            (LimitScope::Host, Some(self.limits.max_file_bytes)),
        ];
        // Narrowest first, replaced only by a strictly smaller limit, so a tie
        // keeps the narrower scope.
        for (scope, limit) in candidates {
            if let Some(limit) = limit
                && smallest.is_none_or(|(_, s)| limit < s)
            {
                smallest = Some((scope, limit));
            }
        }
        if let Some((scope, limit)) = smallest
            && size > limit
        {
            return Err(BlobError::LimitExceeded(LimitExceeded {
                scope,
                measure: "maxFileBytes",
                limit,
                used: 0,
                requested: size,
            }));
        }
        self.check_totals(room_id, member, 1, size, true).await
    }

    /// Whether adding `files` blobs of `bytes` in total fits the member's and
    /// the room's counts and totals (reservations included), and, when
    /// `storage`, the storage's capacity. Narrowest scope first.
    async fn check_totals(
        &self,
        room_id: &str,
        member: Option<&str>,
        files: u64,
        bytes: u64,
        storage: bool,
    ) -> Result<(), BlobError> {
        let fits = |scope: LimitScope, limits: &ScopeLimits, usage: &Usage| {
            let used_files = usage.files + usage.reserved_files;
            if let Some(max) = limits.max_files
                && used_files + files > max
            {
                return Err(BlobError::LimitExceeded(LimitExceeded {
                    scope,
                    measure: "maxFiles",
                    limit: max,
                    used: used_files,
                    requested: files,
                }));
            }
            let used_bytes = usage.bytes + usage.reserved_bytes;
            if let Some(max) = limits.max_bytes
                && used_bytes + bytes > max
            {
                return Err(BlobError::LimitExceeded(LimitExceeded {
                    scope,
                    measure: "maxBytes",
                    limit: max,
                    used: used_bytes,
                    requested: bytes,
                }));
            }
            Ok(())
        };
        if let Some(member) = member {
            let usage = self.member_usage(room_id, member).await?;
            fits(LimitScope::Member, &self.limits.member, &usage)?;
        }
        let usage = self.room_usage(room_id).await?;
        fits(LimitScope::Room, &self.limits.room, &usage)?;
        if storage && let Some(capacity) = self.limits.storage_capacity_bytes {
            let s = self.storage_usage().await?;
            let used = s.bytes + s.reserved_bytes;
            if used + bytes > capacity {
                return Err(BlobError::LimitExceeded(LimitExceeded {
                    scope: LimitScope::Storage,
                    measure: "maxBytes",
                    limit: capacity,
                    used,
                    requested: bytes,
                }));
            }
        }
        Ok(())
    }

    async fn update_usage(&self, key: String, f: impl FnOnce(&mut Usage)) -> Result<(), AppError> {
        let mut usage: Usage = self.blobs.get(key.clone()).await?.unwrap_or_default();
        f(&mut usage);
        self.blobs.insert(key, &usage).await
    }

    async fn reserve(&self, rec: &UploadRecord) -> Result<(), AppError> {
        let size = rec.size;
        let add = move |u: &mut Usage| {
            u.reserved_bytes += size;
            u.reserved_files += 1;
        };
        self.update_usage(room_usage_key(&rec.room_id), add).await?;
        if let Some(m) = &rec.charged_to {
            self.update_usage(member_usage_key(&rec.room_id, m), add)
                .await?;
        }
        let mut storage = self.storage_usage().await?;
        storage.reserved_bytes += size;
        self.blobs.insert(STORAGE_USAGE_KEY, &storage).await
    }

    async fn release_reservation(&self, rec: &UploadRecord) -> Result<(), AppError> {
        let size = rec.size;
        let sub = move |u: &mut Usage| {
            u.reserved_bytes = checked_sub(u.reserved_bytes, size, "reserved bytes");
            u.reserved_files = checked_sub(u.reserved_files, 1, "reserved files");
        };
        self.update_usage(room_usage_key(&rec.room_id), sub).await?;
        if let Some(m) = &rec.charged_to {
            self.update_usage(member_usage_key(&rec.room_id, m), sub)
                .await?;
        }
        let mut storage = self.storage_usage().await?;
        storage.reserved_bytes = checked_sub(storage.reserved_bytes, size, "storage reserved");
        self.blobs.insert(STORAGE_USAGE_KEY, &storage).await
    }

    async fn convert_reservation(&self, rec: &UploadRecord) -> Result<(), AppError> {
        let size = rec.size;
        let convert = move |u: &mut Usage| {
            u.reserved_bytes = checked_sub(u.reserved_bytes, size, "reserved bytes");
            u.reserved_files = checked_sub(u.reserved_files, 1, "reserved files");
            u.bytes += size;
            u.files += 1;
        };
        self.update_usage(room_usage_key(&rec.room_id), convert)
            .await?;
        if let Some(m) = &rec.charged_to {
            self.update_usage(member_usage_key(&rec.room_id, m), convert)
                .await?;
        }
        let mut storage = self.storage_usage().await?;
        storage.reserved_bytes = checked_sub(storage.reserved_bytes, size, "storage reserved");
        storage.bytes += size;
        storage.files += 1;
        self.blobs.insert(STORAGE_USAGE_KEY, &storage).await
    }

    /// Charge (`true`) or credit (`false`) a committed blob to its room and
    /// member. The storage is not touched: it holds the bytes until collected.
    async fn charge(&self, entry: &BlobEntry, add: bool) -> Result<(), AppError> {
        let size = entry.size;
        let apply = move |u: &mut Usage| {
            if add {
                u.bytes += size;
                u.files += 1;
            } else {
                u.bytes = checked_sub(u.bytes, size, "bytes");
                u.files = checked_sub(u.files, 1, "files");
            }
        };
        self.update_usage(room_usage_key(&entry.room_id), apply)
            .await?;
        if let Some(m) = &entry.charged_to {
            self.update_usage(member_usage_key(&entry.room_id, m), apply)
                .await?;
        }
        Ok(())
    }
}

/// A record write's blob references, prepared and waiting for the write.
///
/// Holds the host's lock, so nothing about these blobs changes between the
/// check and [`RecordBlobs::apply`].
pub struct RecordBlobs<'a> {
    host: &'a BlobHost,
    _guard: tokio::sync::MutexGuard<'a, ()>,
    room_id: String,
    record_key: String,
    blobs: Vec<String>,
    previous: Vec<String>,
    member: Option<String>,
}

impl RecordBlobs<'_> {
    /// The record is written: reference what it gained, release what it
    /// dropped. A blob whose last reference goes is orphaned, and stops
    /// counting against its room and member at once.
    pub async fn apply(self) -> Result<(), AppError> {
        self.host
            .apply_refs(
                &self.room_id,
                &self.record_key,
                &self.previous,
                &self.blobs,
                self.member.as_deref(),
            )
            .await
    }
}

impl ScopeLimits {
    fn min_file(self, other: Option<u64>) -> Self {
        Self {
            max_file_bytes: match (self.max_file_bytes, other) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
            ..self
        }
    }
}

fn chunked_error(e: ChunkedError) -> BlobError {
    match e {
        ChunkedError::NotFound | ChunkedError::TerminalState(_) => BlobError::NotFound,
        ChunkedError::ChunkOutOfRange { index, chunk_count } => {
            BlobError::ChunkOutOfRange { index, chunk_count }
        }
        e @ (ChunkedError::DigestMismatch { .. } | ChunkedError::ChunkSizeMismatch { .. }) => {
            BlobError::ChunkMismatch(e.to_string())
        }
        ChunkedError::RateLimited { retry_after_secs } => {
            BlobError::RateLimited { retry_after_secs }
        }
        ChunkedError::InvalidManifest(why) => BlobError::InvalidManifest(why),
        ChunkedError::IncompleteUpload { missing_count, .. } => BlobError::Incomplete {
            remaining_count: missing_count,
        },
        ChunkedError::BundleDigestMismatch => BlobError::DigestMismatch,
        ChunkedError::BundleTooLarge { size_bytes } => {
            BlobError::InvalidManifest(format!("{size_bytes} bytes exceed the transfer ceiling"))
        }
        ChunkedError::App(e) => BlobError::App(e),
    }
}
