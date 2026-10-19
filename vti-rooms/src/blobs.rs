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
use vti_common::blob_store::{
    self, BackendRef, BlobKey, BlobStore, Deletion, DirectFinish, DirectPart, MAX_BLOB_BYTES,
    MIN_MULTIPART_PART_BYTES, PresignedRequest,
};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::revocation::Presented;
use crate::{Room, Visibility};

mod usage;
pub use usage::{
    Activity, DailyUsage, LimitTarget, MemberUsage, OverrideChange, OverrideError, RETENTION_DAYS,
    RoomBlobsSummary,
};

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
/// One set for the host, from its configuration. These are the defaults: a
/// room may carry overrides of its own, at the room, per-member-default and
/// per-member scopes ([`BlobHost::set_limit_override`], which a community sets
/// through `vtc/rooms/limits/set`), and the ceiling bounds every one.
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
#[non_exhaustive]
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
    /// `0.2`: the producer offered no mode this host will use for this upload.
    /// `modes` names those it would.
    NoTransferMode {
        modes: Vec<TransferMode>,
    },
    /// `0.2`: the part plan is inconsistent with the manifest.
    InvalidParts(String),
    /// `0.2`: the upload key is already bound to another open upload.
    UploadKeyInUse,
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
            Self::NoTransferMode { modes } => write!(
                f,
                "no transfer mode is open to both sides; this host would use: {}",
                modes
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::InvalidParts(why) => write!(f, "invalid part plan: {why}"),
            Self::UploadKeyInUse => write!(
                f,
                "the upload key is already bound to another open upload; generate a fresh one"
            ),
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
    /// The storage config chosen at begin, which the commit writes to and whose
    /// capacity the reservation counts against. Absent on an upload begun before
    /// configs existed: it reserved nothing on any config, and commits to the
    /// room's config then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config_id: Option<String>,
    /// The version of the transfer tasks it was opened, or last resumed, under. A
    /// `0.1` chunk, commit or abort never reaches a `0.2` upload, nor the reverse
    /// (`rooms/blobs/upload/begin/0.2`, "What changed from 0.1"). Absent on an
    /// upload begun before `0.2` existed, which is `0.1`.
    #[serde(default)]
    protocol: TransferProtocol,
    /// `0.2`, proxied: the single-use `did:key` that alone sends this upload's
    /// chunk, commit and abort documents. Never the owner, never recorded as one,
    /// never charged or reported (`begin/0.2` items 14–15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upload_key_did: Option<String>,
    /// `0.2`, direct: where the parts go and what they must be. Absent on every
    /// proxied upload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    direct: Option<DirectState>,
    /// The credentials the begin that opened — or last resumed — this upload presented,
    /// so its chunks and its commit, which present nothing, are held to a revocation list
    /// accepted after it began (`rooms/revocations/put`, *Enforcement* item 3). Absent on
    /// an upload begun before this was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    presented: Option<Presented>,
}

/// A direct upload's state: the object this host chose, storage's multipart upload
/// id, the part plan every part is bound to, and when the slot lapses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DirectState {
    object_key: BlobKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    storage_upload_id: Option<String>,
    part_size: u64,
    /// Each part's sha2-256, as `DigestMultibase`, in order.
    part_digests: Vec<String>,
    expires_at: DateTime<Utc>,
}

impl DirectState {
    /// The plan as storage operations take it: 1-based numbers, lengths, digests.
    fn parts(&self, size: u64) -> Vec<DirectPart> {
        self.part_digests
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let start = i as u64 * self.part_size;
                DirectPart {
                    number: i as u32 + 1,
                    len: (size - start).min(self.part_size),
                    sha256: blob_store::sha256_from_digest_multibase(d).unwrap_or([0; 32]),
                }
            })
            .collect()
    }
}

/// How long a direct upload's slot lives after the begin that last resumed it
/// (begin/0.2 item 11: no sooner than 15 minutes), up to [`DIRECT_LIFETIME`].
const DIRECT_IDLE: Duration = Duration::minutes(30);
/// The longest a direct upload's slot lives in all (item 11: at least 24 hours).
const DIRECT_LIFETIME: Duration = Duration::hours(24);
/// The most part targets one begin answers with (`targets`: at most 128). Below it,
/// because one answer is one presign issuance, and a sealed set of more does not
/// fit the custodian's answer.
pub const MAX_TARGETS: usize = 64;

/// Which version of the `rooms/blobs/upload/*` tasks an upload belongs to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum TransferProtocol {
    /// Every document signed by the party that began it.
    #[default]
    V1,
    /// Begun by the member; a proxied transfer's documents signed by its upload key.
    V2,
}

/// How a blob's bytes move (`TransferMode` of `rooms/_shared/0.1/blobs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TransferMode {
    /// Straight between the member and the room's storage, over time-limited
    /// URLs this host issues for one object and one method each.
    Direct,
    /// Through this host, as chunk documents.
    Proxied,
}

impl TransferMode {
    /// The mode as the wire names it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Proxied => "proxied",
        }
    }
}

/// Which rooms this host may answer with a direct transfer, where the room's
/// storage can issue one (`rooms/blobs/get/0.2` item 6, `upload/begin/0.2` item 16).
///
/// Direct transfer shows the member's network address, and which object they
/// read or wrote, to the storage provider. On a `private` room that is exactly
/// the link the tier exists to deny anyone, so the specifications say a host
/// SHOULD NOT offer it there unless its policy explicitly allows it — and this
/// is that policy: the default leaves `private` rooms proxied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectTransfer {
    /// Never: every transfer goes through this host.
    Off,
    /// `open` and `attributed` rooms; `private` rooms stay proxied.
    #[default]
    NotPrivate,
    /// Every room, `private` included: the operator accepts that the storage
    /// provider sees which network address reads and writes a private room's
    /// objects.
    All,
}

impl DirectTransfer {
    /// Whether a room of `visibility` may be answered directly.
    pub fn allows(self, visibility: Visibility) -> bool {
        match self {
            Self::Off => false,
            Self::NotPrivate => visibility != Visibility::Private,
            Self::All => true,
        }
    }
}

/// What the producer of a `rooms/blobs/upload/begin/0.2` accepts.
#[derive(Debug, Clone, Default)]
pub struct UploadOffer {
    /// The single-use `did:key` for a proxied transfer; absent, it accepts only
    /// direct transfer.
    pub upload_key_did: Option<String>,
    /// How it will cut the blob for a direct transfer; absent, it accepts only
    /// proxied transfer.
    pub direct_parts: Option<PartPlan>,
}

/// A `PartPlan`: how the producer will cut a blob for a direct transfer.
#[derive(Debug, Clone)]
pub struct PartPlan {
    pub part_size: u64,
    pub part_count: u64,
    /// Each part's sha2-256 digest, as `DigestMultibase`.
    pub part_digests: Vec<String>,
}

impl PartPlan {
    /// Whether S3-class storage takes this plan: one part (a single write), or parts
    /// of at least 5 MiB but the last, at most 1024 of them.
    fn suits_storage(&self) -> bool {
        self.part_count == 1
            || (self.part_size >= MIN_MULTIPART_PART_BYTES && self.part_count <= 1024)
    }

    /// Refuse a plan inconsistent with `manifest` (`invalidParts`): a part count
    /// that does not follow from the size, a digest list of the wrong length, or
    /// a digest that is not sha2-256 — what storage itself checks a part against.
    fn check(&self, manifest: &Manifest) -> Result<(), BlobError> {
        let bad = |why: String| Err(BlobError::InvalidParts(why));
        if self.part_size == 0 {
            return bad("partSize is 0".into());
        }
        let count = manifest.size.div_ceil(self.part_size);
        if count != self.part_count {
            return bad(format!(
                "partCount is {}; {} bytes at {} is {count}",
                self.part_count, manifest.size, self.part_size
            ));
        }
        if self.part_digests.len() as u64 != count {
            return bad(format!(
                "partDigests has {} entries; the plan has {count} parts",
                self.part_digests.len()
            ));
        }
        if let Some(i) = self
            .part_digests
            .iter()
            .position(|d| blob_store::sha256_from_digest_multibase(d).is_none())
        {
            return bad(format!("partDigests[{i}] is not a sha2-256 multihash"));
        }
        Ok(())
    }
}

/// Who sent an upload's chunk, commit or abort document, and in which version.
#[derive(Debug, Clone, Copy)]
pub enum UploadCaller<'a> {
    /// A `0.1` document: authenticated as the party that began the upload.
    V1(&'a str),
    /// A `0.2` document, authenticated as this party: for a proxied upload, its
    /// upload key and nobody else — not its owner (`chunk/0.2` item 2).
    V2(&'a str),
}

impl UploadCaller<'_> {
    /// Whether this caller may act on `rec`. Anything else is `notFound`, which
    /// conflates an unknown id with somebody else's upload.
    fn admits(&self, rec: &UploadRecord) -> bool {
        match *self {
            Self::V1(opener) => rec.protocol == TransferProtocol::V1 && rec.opener == opener,
            // Proxied: the upload key and nobody else. Direct: the owner, since no
            // byte passes through a document (commit/0.2 and abort/0.2 item 1).
            Self::V2(signer) => {
                rec.protocol == TransferProtocol::V2
                    && match &rec.direct {
                        Some(_) => rec.opener == signer,
                        None => rec.upload_key_did.as_deref() == Some(signer),
                    }
            }
        }
    }
}

/// What `rooms/blobs/get/0.2` answers.
#[derive(Debug, Clone)]
pub enum DownloadV2 {
    /// Fetch the chunks through this host under a download handle.
    Proxied(Download),
    /// Fetch the object straight from storage.
    Direct {
        manifest: Value,
        /// A `GET` of the one object: a bearer credential, never logged.
        target: PresignedRequest,
    },
}

/// The longest a direct target may live (`TransferTarget`: never more than 5
/// minutes), with a few seconds for the clocks of this host and the party that
/// presigned it to disagree.
const MAX_TARGET_LIFETIME: Duration = Duration::seconds(5 * 60 + 10);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DownloadRecord {
    download_id: Uuid,
    room_id: String,
    opener: String,
    blob_ref: String,
    expires_at: DateTime<Utc>,
    ceiling: DateTime<Utc>,
    /// The member the reader's chain descends from, whose activity the chunks
    /// served count under; `None` on a `private` room.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    member: Option<String>,
    /// The credentials the request that opened it presented, as for an upload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    presented: Option<Presented>,
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
    /// How the bytes move. Always [`TransferMode::Proxied`] for a `0.1` upload.
    pub mode: TransferMode,
    /// Direct mode: a bound `PUT` for some or all of the `missing` parts, each with
    /// the 0-based part index it writes. Bearer credentials: never logged.
    pub targets: Vec<(u64, PresignedRequest)>,
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

/// A room's limits as a host enforces them, and where each scope's came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EffectiveLimits {
    pub files_enabled: bool,
    pub room: ScopeLimits,
    /// The per-member default: what a member without an override of their own
    /// is held to.
    pub member: ScopeLimits,
    pub room_source: LimitSource,
    pub member_source: LimitSource,
    /// The host-wide ceiling on one blob, which bounds every scope.
    pub host_ceiling_bytes: u64,
}

/// Where a scope's limits came from (`vtc/rooms/get`'s `roomSource` /
/// `memberSource`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LimitSource {
    /// The host's configured defaults.
    Default,
    /// Set for this room by `vtc/rooms/limits/set`.
    Override,
}

/// The limits one member of one room is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemberLimits {
    pub limits: ScopeLimits,
    /// Set for this member by name, rather than the room's per-member default.
    pub overridden: bool,
}

/// Where a room's new uploads go: a storage config, and its capacity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadTarget {
    /// The config the blob is written to, and recorded under.
    pub config_id: String,
    /// The config's capacity across every room on it; `None` sets none.
    pub capacity_bytes: Option<u64>,
}

/// The stores a host keeps committed blobs in, one per storage config
/// (`docs/05-design-notes/data-rooms-files.md` §7).
///
/// Every blob remembers the config it was written to ([`BlobEntry::config_id`]),
/// so a room reassigned to another config keeps reading its existing files from
/// the old one. Both questions name the room: a store may be scoped to one
/// room's prefix, with credentials that reach nothing else.
#[async_trait::async_trait]
pub trait BlobStores: Send + Sync {
    /// The config an upload begun now in `room_id` is written to. An error when
    /// the room's config cannot take uploads.
    async fn upload_target(&self, room_id: &str) -> Result<UploadTarget, AppError>;

    /// The store holding the blobs of `room_id` recorded under `config_id`, to
    /// write, read or delete them.
    async fn store_for(
        &self,
        config_id: &str,
        room_id: &str,
    ) -> Result<Arc<dyn BlobStore>, AppError>;
}

/// One store under one config for every room: a standalone host, set from its
/// command line.
pub struct FixedStore {
    config_id: String,
    store: Arc<dyn BlobStore>,
}

impl FixedStore {
    pub fn new(config_id: impl Into<String>, store: Arc<dyn BlobStore>) -> Self {
        Self {
            config_id: config_id.into(),
            store,
        }
    }
}

#[async_trait::async_trait]
impl BlobStores for FixedStore {
    async fn upload_target(&self, _room_id: &str) -> Result<UploadTarget, AppError> {
        Ok(UploadTarget {
            config_id: self.config_id.clone(),
            capacity_bytes: None,
        })
    }

    async fn store_for(
        &self,
        config_id: &str,
        _room_id: &str,
    ) -> Result<Arc<dyn BlobStore>, AppError> {
        if config_id != self.config_id {
            return Err(AppError::Internal(format!(
                "a blob is recorded under storage config `{config_id}`, which this host does not have"
            )));
        }
        Ok(self.store.clone())
    }
}

/// What one storage config holds, from the blob index at the time of the read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConfigHoldings {
    /// Blobs not yet deleted, whichever room they are in now.
    pub files: u64,
    /// Their total ciphertext bytes.
    pub bytes: u64,
    /// Bytes of orphaned blobs waiting for collection.
    pub pending_delete_bytes: u64,
}

/// Everything a host needs to store room files.
pub struct BlobHost {
    blobs: KeyspaceHandle,
    transfers: KeyspaceHandle,
    staging_dir: PathBuf,
    stores: Arc<dyn BlobStores>,
    limits: HostLimits,
    lock: tokio::sync::Mutex<()>,
    /// Serialises the activity counters and daily rows, apart from `lock`: a
    /// chunk served must not wait behind a commit writing to a store.
    activity: tokio::sync::Mutex<()>,
    /// Which rooms may be answered with a direct transfer.
    direct: DirectTransfer,
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
fn upload_key_record(id: &Uuid) -> String {
    format!("upload:{id}")
}
fn upload_index_key(opener: &str, room_id: &str, blob_ref: &str) -> String {
    format!("upload-by:{}", short_hash(&[opener, room_id, blob_ref]))
}
/// The open `0.2` upload an upload key is bound to.
fn signer_index_key(upload_key_did: &str) -> String {
    format!("upload-signer:{}", short_hash(&[upload_key_did]))
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
fn config_usage_key(config_id: &str) -> String {
    format!("usage:config:{config_id}")
}

/// When an `alreadyCommitted` upload stops being committable.
fn already_expiry(rec: &UploadRecord) -> DateTime<Utc> {
    DateTime::from_timestamp((rec.created_at + ALREADY_COMMITTED_TTL_SECS) as i64, 0)
        .unwrap_or_else(Utc::now)
}

/// The storage-wide counter, and the config's when the upload names one.
fn storage_keys(config_id: Option<&str>) -> Vec<String> {
    let mut keys = vec![STORAGE_USAGE_KEY.to_string()];
    if let Some(c) = config_id {
        keys.push(config_usage_key(c));
    }
    keys
}

/// Whether a read target may be handed to a reader: one `GET`, over HTTPS,
/// unexpired and expiring within [`MAX_TARGET_LIFETIME`].
fn fit_read_target(t: &PresignedRequest) -> bool {
    let now = Utc::now();
    t.method.eq_ignore_ascii_case("GET")
        && t.url.starts_with("https://")
        && t.expires_at > now
        && t.expires_at <= now + MAX_TARGET_LIFETIME
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
    /// storing committed blobs in the configs `stores` resolves.
    pub fn new(
        blobs: KeyspaceHandle,
        transfers: KeyspaceHandle,
        staging_dir: PathBuf,
        stores: Arc<dyn BlobStores>,
        mut limits: HostLimits,
    ) -> Self {
        limits.max_file_bytes = limits.max_file_bytes.min(MAX_BLOB_BYTES);
        Self {
            blobs,
            transfers,
            staging_dir,
            stores,
            limits,
            lock: tokio::sync::Mutex::new(()),
            activity: tokio::sync::Mutex::new(()),
            direct: DirectTransfer::default(),
        }
    }

    /// This host with `direct` as its policy on direct transfer. The default
    /// ([`DirectTransfer::NotPrivate`]) answers `open` and `attributed` rooms
    /// directly where their storage can, and keeps `private` rooms proxied.
    pub fn with_direct_transfer(mut self, direct: DirectTransfer) -> Self {
        self.direct = direct;
        self
    }

    /// What each storage config holds now, from the blob index. A scan of every
    /// blob, for an administrator's read; never on an upload's path.
    pub async fn config_holdings(
        &self,
    ) -> Result<std::collections::HashMap<String, ConfigHoldings>, AppError> {
        let mut out = std::collections::HashMap::<String, ConfigHoldings>::new();
        for (_, raw) in self.blobs.prefix_iter_raw(b"blob:".to_vec()).await? {
            let Ok(entry) = serde_json::from_slice::<BlobEntry>(&raw) else {
                continue;
            };
            let h = out.entry(entry.config_id).or_default();
            h.files += 1;
            h.bytes += entry.size;
            if entry.state == BlobState::Orphaned {
                h.pending_delete_bytes += entry.size;
            }
        }
        Ok(out)
    }

    /// How many of `room_id`'s blobs are recorded under a config other than
    /// `config_id`.
    pub async fn room_blobs_elsewhere(
        &self,
        room_id: &str,
        config_id: &str,
    ) -> Result<u64, AppError> {
        let prefix = format!("blob:{}:", room_hash(room_id));
        let mut n = 0;
        for (_, raw) in self.blobs.prefix_iter_raw(prefix.into_bytes()).await? {
            if let Ok(entry) = serde_json::from_slice::<BlobEntry>(&raw)
                && entry.config_id != config_id
            {
                n += 1;
            }
        }
        Ok(n)
    }

    /// The blob index ([`ROOM_BLOBS_KEYSPACE`]), for a host that backs it up. Its rows are
    /// written only through this type; a backup reads them and a restore puts them back
    /// before anything is served.
    pub fn index_keyspace(&self) -> &KeyspaceHandle {
        &self.blobs
    }

    /// The limits this host applies to every room it serves, from its configuration:
    /// the defaults a room's own overrides replace, and the host-wide ceiling.
    pub fn host_limits(&self) -> &HostLimits {
        &self.limits
    }

    /// Whether this host accepts uploads at all.
    pub fn files_enabled(&self) -> bool {
        self.limits.files_enabled
    }

    /// Whether `opener` holds an upload here that is open and unexpired.
    ///
    /// What a host can check about a document's claimed issuer before verifying anything,
    /// for a chunk document larger than its default size: the raised size is for the party
    /// uploading, and an upload is opened only after a verified chain. A scan of this
    /// host's transfers, which hold at most a few open slots per party, each for minutes.
    /// A failed read counts as no.
    pub async fn holds_open_upload(&self, opener: &str) -> bool {
        let now = chrono::Utc::now();
        match bundle_store::list_bundles(&self.transfers).await {
            Ok(all) => all.iter().any(|b| {
                b.created_by == opener
                    && b.kind == bundle_store::BundleKind::Import
                    && !b.state.is_terminal()
                    && b.expires_at > now
            }),
            Err(_) => false,
        }
    }

    /// The room of the open upload (`rooms/blobs/upload/chunk`) or unexpired download
    /// (`rooms/blobs/chunk`) `transfer_id` names, when `opener` is the party that opened
    /// it. `None` for anyone else's transfer, a closed one, or an id that names nothing.
    ///
    /// Whether `signer` is the upload key of a `0.2` upload that is open and
    /// unexpired: the standing of a `rooms/blobs/upload/chunk/0.2` document, which
    /// that key signs and which owns no slot of its own. The upload exists only
    /// because a verified chain opened it and named the key (`begin/0.2` item 12).
    /// A failed read counts as no.
    pub async fn holds_open_upload_key(&self, signer: &str) -> bool {
        match self.blobs.get::<Uuid>(signer_index_key(signer)).await {
            Ok(Some(id)) => matches!(self.open_upload_for_key(&id, signer).await, Ok(Some(_))),
            _ => false,
        }
    }

    /// What a host needs to charge a chunk to the room and party it belongs to before
    /// doing the work: the same ownership check [`Self::put_chunk`] and
    /// [`Self::read_chunk`] make, without the work. A failed read answers `None`.
    pub async fn transfer_room(&self, opener: &str, transfer_id: &str) -> Option<String> {
        if let Ok(rec) = self
            .owned_open_upload(UploadCaller::V1(opener), transfer_id)
            .await
        {
            return Some(rec.room_id);
        }
        let id = Uuid::parse_str(transfer_id).ok()?;
        match self.blobs.get::<DownloadRecord>(download_key(&id)).await {
            Ok(Some(r)) if r.opener == opener && r.expires_at > Utc::now() => Some(r.room_id),
            _ => None,
        }
    }

    /// As [`Self::transfer_room`], for an upload's `0.2` chunk, commit or abort from
    /// `caller`: the room and the upload's **owner**, so a host charges the document
    /// to the member's budget in that room — an upload key is minted per upload, and
    /// a budget of its own would be a fresh one for every file. `None` when `caller`
    /// may not act on it.
    pub async fn upload_owner_room(
        &self,
        caller: UploadCaller<'_>,
        upload_id: &str,
    ) -> Option<(String, String)> {
        let id = Uuid::parse_str(upload_id).ok()?;
        match self.blobs.get::<UploadRecord>(upload_key_record(&id)).await {
            Ok(Some(rec)) if caller.admits(&rec) => Some((rec.room_id, rec.opener)),
            _ => None,
        }
    }

    /// Test hook: let every open direct upload's slot lapse now, as the clock would,
    /// so a test can run the sweep that reclaims it.
    #[cfg(feature = "test-support")]
    pub async fn lapse_direct_uploads(&self) -> Result<(), AppError> {
        for (key, raw) in self.blobs.prefix_iter_raw(b"upload:".to_vec()).await? {
            if let Ok(mut rec) = serde_json::from_slice::<UploadRecord>(&raw)
                && let Some(d) = rec.direct.as_mut()
            {
                d.expires_at = Utc::now() - Duration::seconds(1);
                self.blobs.insert(key, &rec).await?;
            }
        }
        Ok(())
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

    /// `rooms/blobs/upload/begin/0.1`: check the upload against every limit,
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
        self.begin_with(room, opener, member, None, manifest, None)
            .await
    }

    /// `rooms/blobs/upload/begin/0.2`: as [`Self::begin`], and then the transfer
    /// mode, from what the producer `offer`s, what the room's storage can do and
    /// this host's [`DirectTransfer`] policy (item 16).
    ///
    /// In direct mode the host chooses the object (unique to the upload), starts
    /// the multipart upload at storage for a plan of several parts, and answers with
    /// bound `PUT` targets for up to [`MAX_TARGETS`] missing parts; the producer
    /// begins again, with the same manifest and plan, for the rest and for any that
    /// lapsed.
    pub async fn begin_v2(
        &self,
        room: &Room,
        opener: &str,
        member: Option<&str>,
        manifest: Manifest,
        offer: UploadOffer,
    ) -> Result<Begun, BlobError> {
        self.begin_with(room, opener, member, None, manifest, Some(offer))
            .await
    }

    /// [`Self::begin`] (`offer` absent) or [`Self::begin_v2`], recording the credentials
    /// the begin presented so the steps that present nothing are held to a revocation
    /// list accepted later (`rooms/revocations/put`, *Enforcement* item 3).
    pub async fn begin_presented(
        &self,
        room: &Room,
        opener: &str,
        member: Option<&str>,
        presented: &Presented,
        manifest: Manifest,
        offer: Option<UploadOffer>,
    ) -> Result<Begun, BlobError> {
        self.begin_with(room, opener, member, Some(presented), manifest, offer)
            .await
    }

    /// The room a transfer belongs to and the credentials that opened it, whoever asks —
    /// for a host to hold the transfer's next step to the room's revocation list before
    /// the step's own ownership check runs. `None` for a transfer this host does not hold.
    pub async fn transfer_presented(
        &self,
        transfer_id: &str,
    ) -> Option<(String, Option<Presented>)> {
        let id = Uuid::parse_str(transfer_id).ok()?;
        if let Ok(Some(rec)) = self.blobs.get::<UploadRecord>(upload_key_record(&id)).await {
            return Some((rec.room_id, rec.presented));
        }
        match self.blobs.get::<DownloadRecord>(download_key(&id)).await {
            Ok(Some(r)) => Some((r.room_id, r.presented)),
            _ => None,
        }
    }

    /// The mode a `0.2` begin is answered in, or why none (item 16). `None` is a
    /// `0.1` begin, which is always proxied.
    ///
    /// Direct when the producer offered a part plan, this host's policy allows
    /// it for the room's tier, the room's storage can take a direct upload — issue
    /// writes bound to each part's length and SHA-256, and verify the object before
    /// it is recorded — and the plan suits it. Otherwise proxied, when the producer
    /// named an upload key; otherwise no mode is open to both sides.
    async fn choose_mode(
        &self,
        room: &Room,
        offer: Option<&UploadOffer>,
    ) -> Result<TransferMode, BlobError> {
        let Some(o) = offer else {
            return Ok(TransferMode::Proxied);
        };
        let can_direct =
            self.direct.allows(room.visibility) && self.direct_store(&room.room_id).await.is_some();
        if can_direct && o.direct_parts.as_ref().is_some_and(PartPlan::suits_storage) {
            return Ok(TransferMode::Direct);
        }
        if o.upload_key_did.is_some() {
            return Ok(TransferMode::Proxied);
        }
        let mut modes = Vec::new();
        if can_direct {
            modes.push(TransferMode::Direct);
        }
        modes.push(TransferMode::Proxied);
        Err(BlobError::NoTransferMode { modes })
    }

    /// The store a new upload in `room_id` goes to, when it takes direct uploads.
    async fn direct_store(&self, room_id: &str) -> Option<(UploadTarget, Arc<dyn BlobStore>)> {
        let target = self.stores.upload_target(room_id).await.ok()?;
        let store = self
            .stores
            .store_for(&target.config_id, room_id)
            .await
            .ok()?;
        store.direct_uploads().then_some((target, store))
    }

    /// The offer a direct upload is bound with: version `0.2`, and any upload key
    /// the producer also sent ignored (begin/0.2 item 15).
    fn without_key(offer: Option<&UploadOffer>) -> UploadOffer {
        UploadOffer {
            upload_key_did: None,
            direct_parts: offer.and_then(|o| o.direct_parts.clone()),
        }
    }

    /// Bound `PUT`s for the first [`MAX_TARGETS`] of `missing` (0-based part indices).
    async fn targets_for(
        &self,
        rec: &UploadRecord,
        missing: &[u64],
    ) -> Result<Vec<(u64, PresignedRequest)>, BlobError> {
        let Some(d) = &rec.direct else {
            return Ok(Vec::new());
        };
        let config = rec.config_id.clone().unwrap_or_default();
        let store = self.stores.store_for(&config, &rec.room_id).await?;
        let plan = d.parts(rec.size);
        let wanted: Vec<DirectPart> = missing
            .iter()
            .take(MAX_TARGETS)
            .filter_map(|i| plan.get(*i as usize).copied())
            .collect();
        if wanted.is_empty() {
            return Ok(Vec::new());
        }
        let reqs = store
            .direct_targets(&d.object_key, d.storage_upload_id.as_deref(), &wanted)
            .await?;
        Ok(wanted
            .iter()
            .zip(reqs)
            .map(|(p, r)| (u64::from(p.number) - 1, r))
            .collect())
    }

    /// Abort a direct upload at storage and delete what it holds there.
    async fn abort_direct(&self, rec: &UploadRecord) -> Result<(), AppError> {
        let Some(d) = &rec.direct else {
            return Ok(());
        };
        let config = rec.config_id.clone().unwrap_or_default();
        let store = self.stores.store_for(&config, &rec.room_id).await?;
        store
            .direct_abort(&d.object_key, d.storage_upload_id.as_deref())
            .await
    }

    /// How many direct uploads `opener` holds open, for the per-party cap proxied
    /// uploads take from their slots.
    async fn open_direct_uploads(&self, opener: &str) -> Result<usize, AppError> {
        let now = Utc::now();
        let mut n = 0;
        for (_, raw) in self.blobs.prefix_iter_raw(b"upload:".to_vec()).await? {
            if let Ok(rec) = serde_json::from_slice::<UploadRecord>(&raw)
                && rec.phase == UploadPhase::Open
                && rec.opener == opener
                && rec.direct.as_ref().is_some_and(|d| d.expires_at > now)
            {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Bind `rec` to the version and upload key of the begin that opened or
    /// resumed it, keeping the key's index in step. A key bound to another open
    /// upload is refused (item 14); the key this one held before is dropped, so it
    /// is refused from now on (item 8).
    async fn bind(
        &self,
        rec: &mut UploadRecord,
        offer: Option<&UploadOffer>,
    ) -> Result<(), BlobError> {
        let key = offer.and_then(|o| o.upload_key_did.clone());
        if let Some(k) = &key
            && self.key_bound_elsewhere(k, rec.upload_id).await?
        {
            return Err(BlobError::UploadKeyInUse);
        }
        if let Some(old) = rec.upload_key_did.take()
            && Some(&old) != key.as_ref()
        {
            let index = signer_index_key(&old);
            if self.blobs.get::<Uuid>(index.clone()).await? == Some(rec.upload_id) {
                self.blobs.remove(index).await?;
            }
        }
        rec.protocol = match offer {
            None => TransferProtocol::V1,
            Some(_) => TransferProtocol::V2,
        };
        if let Some(k) = &key {
            self.blobs
                .insert(signer_index_key(k), &rec.upload_id)
                .await?;
        }
        rec.upload_key_did = key;
        Ok(())
    }

    /// Whether `upload_key` is bound to an open upload other than `this`.
    async fn key_bound_elsewhere(
        &self,
        upload_key_did: &str,
        this: Uuid,
    ) -> Result<bool, AppError> {
        let Some(id) = self
            .blobs
            .get::<Uuid>(signer_index_key(upload_key_did))
            .await?
        else {
            return Ok(false);
        };
        if id == this {
            return Ok(false);
        }
        self.open_upload_for_key(&id, upload_key_did)
            .await
            .map(|r| r.is_some())
    }

    /// The upload `id`, while it is open, unexpired and bound to `upload_key`.
    async fn open_upload_for_key(
        &self,
        id: &Uuid,
        upload_key_did: &str,
    ) -> Result<Option<UploadRecord>, AppError> {
        let Some(rec) = self
            .blobs
            .get::<UploadRecord>(upload_key_record(id))
            .await?
        else {
            return Ok(None);
        };
        if rec.phase != UploadPhase::Open || rec.upload_key_did.as_deref() != Some(upload_key_did) {
            return Ok(None);
        }
        let live = if rec.already_committed {
            rec.created_at + ALREADY_COMMITTED_TTL_SECS > now_secs()
        } else {
            self.live_slot(id).await?.is_some()
        };
        Ok(live.then_some(rec))
    }

    async fn begin_with(
        &self,
        room: &Room,
        opener: &str,
        member: Option<&str>,
        presented: Option<&Presented>,
        manifest: Manifest,
        offer: Option<UploadOffer>,
    ) -> Result<Begun, BlobError> {
        if !self.limits.files_enabled {
            return Err(BlobError::FilesDisabled);
        }
        if let Some(plan) = offer.as_ref().and_then(|o| o.direct_parts.as_ref()) {
            plan.check(&manifest)?;
        }
        let member = match room.visibility {
            Visibility::Private => None,
            _ => member,
        };
        let _guard = self.lock.lock().await;
        // Read under the lock, so an override set before this begin is the one
        // it is checked against (`vtc/rooms/limits/set` item 5).
        let limits = self.limits_for(&room.room_id, member).await?;
        if !limits.files_enabled {
            return Err(BlobError::FilesDisabled);
        }
        // Chosen now and refused only where the specification places it: after
        // every check that applies to this begin, before anything is reserved.
        let mode = self.choose_mode(room, offer.as_ref()).await;

        // Resume: the same opener, room and manifest, while its slot is open.
        let index = upload_index_key(opener, &room.room_id, &manifest.blob_ref);
        if let Some(id) = self.blobs.get::<Uuid>(index.clone()).await?
            && let Some(mut rec) = self
                .blobs
                .get::<UploadRecord>(upload_key_record(&id))
                .await?
            && rec.phase == UploadPhase::Open
        {
            // Resumed under this begin's presentation, which is what its later steps
            // are held to from now on.
            rec.presented = presented.cloned();
            if rec.already_committed {
                if rec.created_at + ALREADY_COMMITTED_TTL_SECS > now_secs()
                    && self.blob(&room.room_id, &rec.blob_ref).await?.is_some()
                {
                    let mode = mode?;
                    let bound = match mode {
                        TransferMode::Direct => Some(Self::without_key(offer.as_ref())),
                        TransferMode::Proxied => offer.clone(),
                    };
                    self.bind(&mut rec, bound.as_ref()).await?;
                    self.blobs.insert(upload_key_record(&id), &rec).await?;
                    return Ok(Begun {
                        upload_id: id,
                        missing: Vec::new(),
                        expires_at: already_expiry(&rec),
                        already_committed: true,
                        mode,
                        targets: Vec::new(),
                    });
                }
            } else if let Some(d) = rec.direct.clone() {
                // A direct upload resumes while its slot is open and the producer
                // still takes direct transfer: fresh targets for the parts storage
                // does not yet hold, and the slot extended.
                if d.expires_at > Utc::now() && matches!(mode, Ok(TransferMode::Direct)) {
                    let config = rec.config_id.clone().unwrap_or_default();
                    let store = self.stores.store_for(&config, &rec.room_id).await?;
                    let held = store
                        .direct_held(
                            &d.object_key,
                            d.storage_upload_id.as_deref(),
                            &d.parts(rec.size),
                        )
                        .await?;
                    let missing: Vec<u64> = (0..d.part_digests.len() as u64)
                        .filter(|i| !held.contains(&(*i as u32 + 1)))
                        .collect();
                    let ceiling = DateTime::from_timestamp(rec.created_at as i64, 0)
                        .unwrap_or_else(Utc::now)
                        + DIRECT_LIFETIME;
                    let expires_at = (Utc::now() + DIRECT_IDLE).min(ceiling);
                    if let Some(state) = rec.direct.as_mut() {
                        state.expires_at = expires_at;
                    }
                    self.bind(&mut rec, Some(&Self::without_key(offer.as_ref())))
                        .await?;
                    self.blobs.insert(upload_key_record(&id), &rec).await?;
                    let targets = self.targets_for(&rec, &missing).await?;
                    return Ok(Begun {
                        upload_id: id,
                        missing,
                        expires_at,
                        already_committed: false,
                        mode: TransferMode::Direct,
                        targets,
                    });
                }
                // Lapsed, or the producer no longer takes direct transfer: what
                // storage holds for it goes, and the begin starts afresh.
                if let Err(e) = self.abort_direct(&rec).await {
                    tracing::warn!(error = %e, "a superseded direct upload was not aborted at storage; the sweep retries");
                }
            } else if offer.as_ref().is_none_or(|o| o.upload_key_did.is_some())
                && let Some(slot) = self.live_slot(&id).await?
            {
                // A proxied slot resumes as proxied: its chunks are staged here.
                let mode = mode.map(|_| TransferMode::Proxied)?;
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
                // Rebound to this begin's key, so a client that lost its upload
                // key can resume; the key it held is refused from now on.
                self.bind(&mut rec, offer.as_ref()).await?;
                self.blobs.insert(upload_key_record(&id), &rec).await?;
                return Ok(Begun {
                    upload_id: id,
                    missing,
                    expires_at: slot.expires_at,
                    already_committed: false,
                    mode,
                    targets: Vec::new(),
                });
            }
            // Its slot lapsed: give its reservation back and open a new one.
            if !rec.already_committed {
                self.release_reservation(&rec).await?;
            }
            rec.phase = UploadPhase::Released;
            rec.finished_at = Some(now_secs());
            self.blobs.insert(upload_key_record(&id), &rec).await?;
        }

        // Already committed in this room: nothing to send, nothing to reserve.
        // A BlobRef in another room is never reported; it is stored again here.
        if self
            .blob(&room.room_id, &manifest.blob_ref)
            .await?
            .is_some()
        {
            let mode = mode?;
            let mut rec = UploadRecord {
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
                config_id: None,
                protocol: TransferProtocol::V1,
                upload_key_did: None,
                direct: None,
                presented: presented.cloned(),
            };
            self.bind(&mut rec, offer.as_ref()).await?;
            self.blobs
                .insert(upload_key_record(&rec.upload_id), &rec)
                .await?;
            self.blobs.insert(index, &rec.upload_id).await?;
            return Ok(Begun {
                upload_id: rec.upload_id,
                missing: Vec::new(),
                expires_at: already_expiry(&rec),
                already_committed: true,
                mode,
                targets: Vec::new(),
            });
        }

        let target = self.stores.upload_target(&room.room_id).await?;
        self.check_limits(&room.room_id, member, manifest.size, &target, &limits)
            .await?;
        let mode = mode?;
        if mode == TransferMode::Direct {
            let plan = offer
                .as_ref()
                .and_then(|o| o.direct_parts.clone())
                .ok_or_else(|| AppError::Internal("direct mode with no part plan".into()))?;
            if self.open_direct_uploads(opener).await? >= MAX_OPEN_BUNDLES_PER_DID {
                return Err(BlobError::TooManyUploads {
                    max_open: MAX_OPEN_BUNDLES_PER_DID,
                });
            }
            let store = self
                .stores
                .store_for(&target.config_id, &room.room_id)
                .await?;
            // The object is the host's choice, never the producer's (item 17), and
            // unique to this upload, so no other upload of the blob shares it.
            let upload_id = Uuid::new_v4();
            let object_key = BlobKey::for_upload(&room.room_id, &manifest.blob_ref, &upload_id)?;
            let storage_upload_id = store.direct_begin(&object_key, plan.part_count > 1).await?;
            let expires_at = Utc::now() + DIRECT_IDLE;
            let mut rec = UploadRecord {
                upload_id,
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
                config_id: Some(target.config_id),
                protocol: TransferProtocol::V1,
                upload_key_did: None,
                direct: Some(DirectState {
                    object_key,
                    storage_upload_id,
                    part_size: plan.part_size,
                    part_digests: plan.part_digests.clone(),
                    expires_at,
                }),
                presented: presented.cloned(),
            };
            self.reserve(&rec).await?;
            self.bind(&mut rec, Some(&Self::without_key(offer.as_ref())))
                .await?;
            self.blobs
                .insert(upload_key_record(&rec.upload_id), &rec)
                .await?;
            self.blobs.insert(index, &rec.upload_id).await?;
            let missing: Vec<u64> = (0..plan.part_count).collect();
            // A failure here leaves the upload open: the producer begins again for
            // its targets.
            let targets = self.targets_for(&rec, &missing).await?;
            return Ok(Begun {
                upload_id,
                missing,
                expires_at,
                already_committed: false,
                mode,
                targets,
            });
        }
        if let Some(k) = offer.as_ref().and_then(|o| o.upload_key_did.as_deref())
            && self.key_bound_elsewhere(k, Uuid::nil()).await?
        {
            return Err(BlobError::UploadKeyInUse);
        }

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

        let mut rec = UploadRecord {
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
            config_id: Some(target.config_id),
            protocol: TransferProtocol::V1,
            upload_key_did: None,
            direct: None,
            presented: presented.cloned(),
        };
        self.reserve(&rec).await?;
        self.bind(&mut rec, offer.as_ref()).await?;
        self.blobs
            .insert(upload_key_record(&rec.upload_id), &rec)
            .await?;
        self.blobs.insert(index, &rec.upload_id).await?;
        Ok(Begun {
            upload_id: slot.bundle_id,
            missing: (0..slot.chunk_count).collect(),
            expires_at: slot.expires_at,
            already_committed: false,
            mode,
            targets: Vec::new(),
        })
    }

    /// `rooms/blobs/upload/chunk/0.1`, from the party that began the upload.
    pub async fn put_chunk(
        &self,
        opener: &str,
        upload_id: &str,
        index: u64,
        digest_multibase: &str,
        data: &[u8],
    ) -> Result<ChunkStored, BlobError> {
        self.put_chunk_as(
            UploadCaller::V1(opener),
            upload_id,
            index,
            digest_multibase,
            data,
        )
        .await
    }

    /// `rooms/blobs/upload/chunk`, from `caller`. The slot belongs to the upload's
    /// owner whoever sends its chunks, so the per-party chunk rate is the owner's:
    /// minting upload keys does not buy a member more of it.
    pub async fn put_chunk_as(
        &self,
        caller: UploadCaller<'_>,
        upload_id: &str,
        index: u64,
        digest_multibase: &str,
        data: &[u8],
    ) -> Result<ChunkStored, BlobError> {
        let rec = self.owned_open_upload(caller, upload_id).await?;
        let result = chunked::put_chunk_for(
            &self.transfers,
            &self.staging_dir,
            ChunkRateLimiter::global(),
            &rec.opener,
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

    /// `rooms/blobs/upload/commit/0.1`, from the party that began the upload.
    pub async fn commit(&self, opener: &str, upload_id: &str) -> Result<Committed, BlobError> {
        self.commit_as(UploadCaller::V1(opener), upload_id).await
    }

    /// `rooms/blobs/upload/commit`, from `caller`. Whoever commits, the blob is
    /// recorded and charged as the owner's — never the upload key's (`commit/0.2`
    /// item 5).
    pub async fn commit_as(
        &self,
        caller: UploadCaller<'_>,
        upload_id: &str,
    ) -> Result<Committed, BlobError> {
        let Ok(id) = Uuid::parse_str(upload_id) else {
            return Err(BlobError::NotFound);
        };
        let _guard = self.lock.lock().await;
        let mut rec = match self
            .blobs
            .get::<UploadRecord>(upload_key_record(&id))
            .await?
        {
            Some(r) if caller.admits(&r) => r,
            _ => return Err(BlobError::NotFound),
        };
        // The slot is the owner's, whoever signed this document.
        let owner = rec.opener.clone();
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
            self.blobs.insert(upload_key_record(&id), &rec).await?;
            return Ok(Committed {
                blob_ref: entry.blob_ref,
                size: entry.size,
            });
        }

        if let Some(d) = rec.direct.clone() {
            return self.commit_direct(rec, d).await;
        }

        match chunked::finalize_precheck_for(&self.transfers, &owner, upload_id).await {
            Ok(()) => {}
            Err(ChunkedError::IncompleteUpload { missing_count, .. }) => {
                return Err(BlobError::Incomplete {
                    remaining_count: missing_count,
                });
            }
            Err(ChunkedError::BundleDigestMismatch) => {
                let _ = backup_transfer::abort(&self.transfers, &owner, &id).await;
                self.release_reservation(&rec).await?;
                rec.phase = UploadPhase::Released;
                rec.finished_at = Some(now_secs());
                self.blobs.insert(upload_key_record(&id), &rec).await?;
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
            self.blobs.insert(upload_key_record(&id), &rec).await?;
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
        let config_id = match &rec.config_id {
            Some(c) => c.clone(),
            None => self.stores.upload_target(&rec.room_id).await?.config_id,
        };
        let store = self.stores.store_for(&config_id, &rec.room_id).await?;
        // Durable in the store before anything says it is committed.
        let backend_ref = store.put(&key, &staged, rec.size).await?;

        let entry = BlobEntry {
            room_id: rec.room_id.clone(),
            blob_ref: rec.blob_ref.clone(),
            size: rec.size,
            manifest: rec.manifest.clone(),
            config_id: config_id.clone(),
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
        self.convert_reservation(&rec, &config_id).await?;
        self.record_upload(&rec.room_id, rec.charged_to.as_deref())
            .await?;
        rec.phase = UploadPhase::Committed;
        rec.finished_at = Some(now_secs());
        self.blobs.insert(upload_key_record(&id), &rec).await?;
        self.close_slot(&id).await?;
        Ok(Committed {
            blob_ref: entry.blob_ref,
            size: entry.size,
        })
    }

    /// A direct upload's commit (`commit/0.2` items 2, 3, 5–8): verify the object at
    /// storage before recording anything — each part's length and checksum, the
    /// completion bound to the planned size, the assembled object's length and
    /// checksum — and, on any disagreement, delete what storage holds, release the
    /// reservation and refuse `digestMismatch`. Called under the lock.
    async fn commit_direct(
        &self,
        mut rec: UploadRecord,
        d: DirectState,
    ) -> Result<Committed, BlobError> {
        let id = rec.upload_id;
        if d.expires_at <= Utc::now() {
            return Err(BlobError::NotFound);
        }
        let config_id = rec.config_id.clone().unwrap_or_default();
        let store = self.stores.store_for(&config_id, &rec.room_id).await?;
        let finished = store
            .direct_finish(
                &d.object_key,
                d.storage_upload_id.as_deref(),
                &d.parts(rec.size),
            )
            .await?;
        let backend_ref = match finished {
            DirectFinish::Missing(n) => {
                return Err(BlobError::Incomplete { remaining_count: n });
            }
            DirectFinish::Mismatch(why) => {
                tracing::warn!(upload = %id, why = %why, "a direct upload's object is not its plan; deleted");
                self.release_reservation(&rec).await?;
                rec.phase = UploadPhase::Released;
                rec.finished_at = Some(now_secs());
                self.blobs.insert(upload_key_record(&id), &rec).await?;
                return Err(BlobError::DigestMismatch);
            }
            DirectFinish::Stored(at) => at,
        };
        // Already in this room (another upload of the blob committed first): this
        // object goes, and nothing is charged twice.
        if let Some(existing) = self.blob(&rec.room_id, &rec.blob_ref).await? {
            if let Err(e) = store.delete(&backend_ref).await {
                tracing::warn!(upload = %id, error = %e, "a duplicate direct upload's object was not deleted");
            }
            self.release_reservation(&rec).await?;
            rec.phase = UploadPhase::Committed;
            rec.finished_at = Some(now_secs());
            self.blobs.insert(upload_key_record(&id), &rec).await?;
            return Ok(Committed {
                blob_ref: existing.blob_ref,
                size: existing.size,
            });
        }
        let entry = BlobEntry {
            room_id: rec.room_id.clone(),
            blob_ref: rec.blob_ref.clone(),
            size: rec.size,
            manifest: rec.manifest.clone(),
            config_id: config_id.clone(),
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
        self.convert_reservation(&rec, &config_id).await?;
        self.record_upload(&rec.room_id, rec.charged_to.as_deref())
            .await?;
        rec.phase = UploadPhase::Committed;
        rec.finished_at = Some(now_secs());
        self.blobs.insert(upload_key_record(&id), &rec).await?;
        Ok(Committed {
            blob_ref: entry.blob_ref,
            size: entry.size,
        })
    }

    /// `rooms/blobs/upload/abort/0.1`. `Ok(true)` when this call aborted it,
    /// `Ok(false)` when it already was.
    pub async fn abort(&self, opener: &str, upload_id: &str) -> Result<bool, BlobError> {
        self.abort_as(UploadCaller::V1(opener), upload_id).await
    }

    /// `rooms/blobs/upload/abort`, from `caller`.
    pub async fn abort_as(
        &self,
        caller: UploadCaller<'_>,
        upload_id: &str,
    ) -> Result<bool, BlobError> {
        let Ok(id) = Uuid::parse_str(upload_id) else {
            return Err(BlobError::NotFound);
        };
        let _guard = self.lock.lock().await;
        let mut rec = match self
            .blobs
            .get::<UploadRecord>(upload_key_record(&id))
            .await?
        {
            Some(r) if caller.admits(&r) => r,
            _ => return Err(BlobError::NotFound),
        };
        // The slot is the owner's, whoever signed this document.
        let owner = rec.opener.clone();
        match rec.phase {
            UploadPhase::Open => {}
            UploadPhase::Aborted => return Ok(false),
            // A committed blob goes by dropping it from every record, never by
            // aborting; an expired upload is not one this caller can abort.
            UploadPhase::Committed | UploadPhase::Released => return Err(BlobError::NotFound),
        }
        if rec.direct.is_some() {
            // Abort the write at storage and delete what it holds (abort/0.2 item 2).
            self.abort_direct(&rec).await?;
            self.release_reservation(&rec).await?;
        } else if !rec.already_committed {
            if let Err(e) = backup_transfer::abort(&self.transfers, &owner, &id).await
                && !matches!(e, AppError::NotFound(_))
            {
                return Err(e.into());
            }
            self.release_reservation(&rec).await?;
        }
        rec.phase = UploadPhase::Aborted;
        rec.finished_at = Some(now_secs());
        self.blobs.insert(upload_key_record(&id), &rec).await?;
        Ok(true)
    }

    // ─── download ────────────────────────────────────────────────────────

    /// `rooms/blobs/get`: the manifest as committed, and a download handle
    /// bound to the opener.
    ///
    /// An orphaned blob not yet collected is still served: a member may hold a
    /// record version that names it.
    ///
    /// `member` is the subject at the root of the reader's chain, `None` on a
    /// `private` room; the download counts under it.
    pub async fn open_download(
        &self,
        room: &Room,
        opener: &str,
        member: Option<&str>,
        blob_ref: &str,
    ) -> Result<Download, BlobError> {
        self.open_download_presented(room, opener, member, None, blob_ref)
            .await
    }

    /// [`Self::open_download`], recording the credentials the request presented, so the
    /// download's chunks — which present nothing — are held to a revocation list accepted
    /// after it opened (`rooms/revocations/put`, *Enforcement* item 4: a host serving from
    /// storage it controls SHOULD refuse those too).
    pub async fn open_download_presented(
        &self,
        room: &Room,
        opener: &str,
        member: Option<&str>,
        presented: Option<&Presented>,
        blob_ref: &str,
    ) -> Result<Download, BlobError> {
        let room_id = room.room_id.as_str();
        let member = match room.visibility {
            Visibility::Private => None,
            _ => member,
        };
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
            member: member.map(str::to_string),
            presented: presented.cloned(),
        };
        self.blobs
            .insert(download_key(&rec.download_id), &rec)
            .await?;
        self.record_activity(room_id, member, usage::Activity::download())
            .await?;
        Ok(Download {
            download_id: rec.download_id,
            manifest: entry.manifest,
            expires_at: rec.expires_at,
        })
    }

    /// `rooms/blobs/get/0.2`: the manifest as committed, and either a storage
    /// target for the one object (`want_direct`, where this host's policy allows
    /// it for the room's tier and the blob's store can issue one) or, as
    /// [`Self::open_download`], a download handle.
    ///
    /// A target is checked before it is handed out: a `GET`, over HTTPS, expiring
    /// within five minutes (`TransferTarget`). One that is not, or a store that
    /// fails to issue one, answers proxied instead — the mode is the host's
    /// choice, and the reader is told which it got. The target is never logged.
    ///
    /// A direct download is counted when the target is issued, as a download and
    /// the blob's size served, since its bytes never pass through this host.
    pub async fn open_download_v2(
        &self,
        room: &Room,
        opener: &str,
        member: Option<&str>,
        presented: Option<&Presented>,
        blob_ref: &str,
        want_direct: bool,
    ) -> Result<DownloadV2, BlobError> {
        if want_direct && self.direct.allows(room.visibility) {
            let entry = self
                .blob(&room.room_id, blob_ref)
                .await?
                .ok_or(BlobError::NotFound)?;
            let issued = match self
                .stores
                .store_for(&entry.config_id, &entry.room_id)
                .await
            {
                Ok(store) => store.read_target(&entry.backend_ref).await,
                Err(e) => Err(e),
            };
            match issued {
                Ok(Some(target)) if fit_read_target(&target) => {
                    let member = match room.visibility {
                        Visibility::Private => None,
                        _ => member,
                    };
                    self.record_activity(
                        &room.room_id,
                        member,
                        usage::Activity::direct_download(entry.size),
                    )
                    .await?;
                    return Ok(DownloadV2::Direct {
                        manifest: entry.manifest,
                        target,
                    });
                }
                Ok(Some(_)) => tracing::warn!(
                    blob = %entry.blob_ref,
                    "storage issued a read target that is not an HTTPS GET within five minutes; \
                     serving through this host"
                ),
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    blob = %entry.blob_ref,
                    error = %e,
                    "storage could not issue a read target; serving through this host"
                ),
            }
        }
        self.open_download_presented(room, opener, member, presented, blob_ref)
            .await
            .map(DownloadV2::Proxied)
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
        let store = self
            .stores
            .store_for(&entry.config_id, &entry.room_id)
            .await?;
        let data = store.get_range(&entry.backend_ref, start, end).await?;
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
        // Every chunk served counts, a repeated one included: egress is what
        // left the store, which is what a cloud bills.
        self.record_activity(
            &rec.room_id,
            rec.member.as_deref(),
            usage::Activity::egress(data.len() as u64),
        )
        .await?;
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
            let limits = self.limits_for(&room.room_id, member).await?;
            self.check_totals(&room.room_id, member, files, bytes, false, &limits)
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

    /// Prepare to release every blob record `record_key` names, as a
    /// retraction does. Holds the lock like [`Self::prepare_record`]: the
    /// caller curates the record while holding it, and applies only if the
    /// curation retracted it.
    pub async fn prepare_release(
        &self,
        room_id: &str,
        record_key: &str,
    ) -> Result<RecordBlobs<'_>, AppError> {
        let guard = self.lock.lock().await;
        let previous = self.record_blobs(room_id, record_key).await?;
        Ok(RecordBlobs {
            host: self,
            _guard: guard,
            room_id: room_id.to_string(),
            record_key: record_key.to_string(),
            blobs: Vec::new(),
            previous,
            member: None,
        })
    }

    /// Hold the lock every record write holds, so a read of a record and of
    /// the blobs it names sees one version of both. A record write and its blob
    /// references change together under this lock; reading both inside it is
    /// what keeps a 0.2 read from pairing one version's record with another's
    /// `blobs`.
    pub async fn read_snapshot(&self) -> ReadSnapshot<'_> {
        ReadSnapshot {
            host: self,
            _guard: self.lock.lock().await,
        }
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
            let deleted = match self
                .stores
                .store_for(&entry.config_id, &entry.room_id)
                .await
            {
                Ok(store) => store.delete(&entry.backend_ref).await,
                Err(e) => Err(e),
            };
            match deleted {
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
            for usage_key in [
                STORAGE_USAGE_KEY.to_string(),
                config_usage_key(&entry.config_id),
            ] {
                let mut storage = self.counter(&usage_key).await?;
                storage.files = checked_sub(storage.files, 1, "storage files");
                storage.bytes = checked_sub(storage.bytes, entry.size, "storage bytes");
                self.blobs.insert(usage_key, &storage).await?;
            }
            self.blobs.remove(key).await?;
            // A storage config's holdings moved (`crate::observe`).
            crate::observe::changed();
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
                    } else if let Some(d) = &rec.direct {
                        d.expires_at <= Utc::now()
                    } else {
                        self.live_slot(&rec.upload_id).await?.is_none()
                    };
                    // A lapsed direct upload's parts, or an object it wrote and never
                    // committed, are reclaimed at storage before its reservation is
                    // given back; a failure is retried on the next pass.
                    if lapsed
                        && rec.direct.is_some()
                        && let Err(e) = self.abort_direct(&rec).await
                    {
                        tracing::warn!(upload = %rec.upload_id, error = %e, "a lapsed direct upload was not reclaimed; retry next pass");
                        continue;
                    }
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
                    if let Some(k) = &rec.upload_key_did {
                        let index = signer_index_key(k);
                        if self.blobs.get::<Uuid>(index.clone()).await? == Some(rec.upload_id) {
                            self.blobs.remove(index).await?;
                        }
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
        self.roll_days().await?;
        Ok(stats)
    }

    // ─── internals ───────────────────────────────────────────────────────

    async fn owned_open_upload(
        &self,
        caller: UploadCaller<'_>,
        upload_id: &str,
    ) -> Result<UploadRecord, BlobError> {
        let Ok(id) = Uuid::parse_str(upload_id) else {
            return Err(BlobError::NotFound);
        };
        match self
            .blobs
            .get::<UploadRecord>(upload_key_record(&id))
            .await?
        {
            Some(r) if caller.admits(&r) && r.phase == UploadPhase::Open => Ok(r),
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
        self.counter(STORAGE_USAGE_KEY).await
    }

    async fn counter(&self, key: &str) -> Result<StorageUsage, AppError> {
        Ok(self.blobs.get(key.to_string()).await?.unwrap_or_default())
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
        target: &UploadTarget,
        limits: &usage::Applied,
    ) -> Result<(), BlobError> {
        let mut smallest: Option<(LimitScope, u64)> = None;
        let candidates = [
            (LimitScope::Member, member.and(limits.member.max_file_bytes)),
            (LimitScope::Room, limits.room.max_file_bytes),
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
        self.check_totals(room_id, member, 1, size, true, limits)
            .await?;
        // The config's own capacity, across every room assigned to it.
        if let Some(capacity) = target.capacity_bytes {
            let s = self.counter(&config_usage_key(&target.config_id)).await?;
            let used = s.bytes + s.reserved_bytes;
            if used + size > capacity {
                return Err(BlobError::LimitExceeded(LimitExceeded {
                    scope: LimitScope::Storage,
                    measure: "maxBytes",
                    limit: capacity,
                    used,
                    requested: size,
                }));
            }
        }
        Ok(())
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
        limits: &usage::Applied,
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
            fits(LimitScope::Member, &limits.member, &usage)?;
        }
        let usage = self.room_usage(room_id).await?;
        fits(LimitScope::Room, &limits.room, &usage)?;
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
        self.blobs.insert(key, &usage).await?;
        // Holdings moved, perhaps across a band (`crate::observe`).
        crate::observe::changed();
        Ok(())
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
        for key in storage_keys(rec.config_id.as_deref()) {
            let mut storage = self.counter(&key).await?;
            storage.reserved_bytes += size;
            self.blobs.insert(key, &storage).await?;
        }
        crate::observe::changed();
        Ok(())
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
        for key in storage_keys(rec.config_id.as_deref()) {
            let mut storage = self.counter(&key).await?;
            storage.reserved_bytes = checked_sub(storage.reserved_bytes, size, "storage reserved");
            self.blobs.insert(key, &storage).await?;
        }
        crate::observe::changed();
        Ok(())
    }

    /// The upload is stored on `config_id`: its reservation becomes usage. An
    /// upload begun before configs existed reserved nothing on one, so its
    /// config is charged the bytes alone.
    async fn convert_reservation(
        &self,
        rec: &UploadRecord,
        config_id: &str,
    ) -> Result<(), AppError> {
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
        for key in [STORAGE_USAGE_KEY.to_string(), config_usage_key(config_id)] {
            let reserved = key == STORAGE_USAGE_KEY || rec.config_id.is_some();
            let mut storage = self.counter(&key).await?;
            if reserved {
                storage.reserved_bytes =
                    checked_sub(storage.reserved_bytes, size, "storage reserved");
            }
            storage.bytes += size;
            storage.files += 1;
            self.blobs.insert(key, &storage).await?;
        }
        crate::observe::changed();
        Ok(())
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
        self.record_activity(
            &entry.room_id,
            entry.charged_to.as_deref(),
            usage::Activity::default(),
        )
        .await
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

/// A read under the record-write lock ([`BlobHost::read_snapshot`]).
pub struct ReadSnapshot<'a> {
    host: &'a BlobHost,
    _guard: tokio::sync::MutexGuard<'a, ()>,
}

impl ReadSnapshot<'_> {
    /// The blobs the current version of record `record_key` names.
    pub async fn record_blobs(
        &self,
        room_id: &str,
        record_key: &str,
    ) -> Result<Vec<String>, AppError> {
        self.host.record_blobs(room_id, record_key).await
    }
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
        // `ChunkedError` is `#[non_exhaustive]`: a refusal this mapping does not
        // know yet is an internal error, never silently a success.
        other => BlobError::App(AppError::Internal(other.to_string())),
    }
}

#[cfg(test)]
mod direct_tests {
    use super::*;

    /// A `private` room is proxied unless the host's policy explicitly says otherwise
    /// (`rooms/blobs/get/0.2` item 6, `upload/begin/0.2` item 16).
    #[test]
    fn private_rooms_are_proxied_by_default() {
        let d = DirectTransfer::default();
        assert!(d.allows(Visibility::Open));
        assert!(d.allows(Visibility::Attributed));
        assert!(!d.allows(Visibility::Private));
        assert!(DirectTransfer::All.allows(Visibility::Private));
        assert!(!DirectTransfer::Off.allows(Visibility::Open));
    }

    /// S3-class storage takes one part, or parts of at least 5 MiB but the last.
    #[test]
    fn a_plan_suits_storage_by_its_part_size() {
        let plan = |size: u64, count: u64| PartPlan {
            part_size: size,
            part_count: count,
            part_digests: vec![],
        };
        assert!(plan(300_000, 1).suits_storage());
        assert!(plan(MIN_MULTIPART_PART_BYTES, 3).suits_storage());
        assert!(!plan(MIN_MULTIPART_PART_BYTES - 1, 3).suits_storage());
        assert!(!plan(MIN_MULTIPART_PART_BYTES, 1025).suits_storage());
    }

    #[test]
    fn a_part_plan_must_follow_from_the_manifest() {
        let d = blob_store::sha256_digest_multibase(&[1; 32]);
        let manifest = Manifest::parse(&serde_json::json!({
            "size": 40_000,
            "chunks": { "chunkSize": 16_384, "chunkCount": 3, "chunkDigests": [d, d, d] },
            "digest": d,
        }))
        .unwrap();
        let plan = |size, count, n: usize| PartPlan {
            part_size: size,
            part_count: count,
            part_digests: vec![d.clone(); n],
        };
        plan(40_000, 1, 1).check(&manifest).unwrap();
        plan(20_000, 2, 2).check(&manifest).unwrap();
        assert!(plan(20_000, 3, 3).check(&manifest).is_err());
        assert!(plan(20_000, 2, 1).check(&manifest).is_err());
        let mut not_sha = plan(40_000, 1, 1);
        not_sha.part_digests = vec!["zNotAHash".into()];
        assert!(not_sha.check(&manifest).is_err());
    }
}
