//! Op-layer for the `chunkedTrustTask` backup transfer algorithm.
//!
//! The `stream` algorithm moves a bundle over the VTA's HTTPS blob endpoint,
//! which a VTA reachable only over DIDComm or TSP does not have. This one moves
//! it as a sequence of Trust Tasks over whatever transport carries the control
//! plane: `vta/backup/get-chunk/1.0` pulls an export chunk by index, and
//! `vta/backup/put-chunk/1.0` writes an import chunk checked against a manifest
//! the operator committed before any chunk moved. The normative account is
//! `vta/backup/initiate-export/1.1` § Chunked transfer
//! (trustoverip/dtgwg-trust-tasks-tf#474).
//!
//! It reuses the descriptor pattern's [`BundleRecord`] state machine and staging
//! directory unchanged, and keeps what is new — the manifest and which indices
//! have moved — in a [`ChunkPlan`] beside the record, under its own key prefix,
//! so the record's shape (and every reader of it) is untouched.
//!
//! Four properties the specification makes normative, and where each is held:
//!
//! - **Pulled, not pushed.** Nothing here sends; every chunk is an answer to a
//!   request, so a chunk lost in transit is one the client knows it lacks.
//! - **Non-consuming reads.** [`get_chunk`] serves by offset from the staged
//!   file and never deletes it; the bundle goes on `complete-export`, `abort` or
//!   expiry.
//! - **Idempotent writes.** [`put_chunk`] checks every chunk against the
//!   pre-committed digest, so the only bytes an index can ever hold are the
//!   committed ones; a repeat is `stored: false`.
//! - **Bounded expiry.** Activity slides `expires_at` forward, never past a
//!   ceiling fixed when the bundle was minted.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tracing::info;
use uuid::Uuid;

use vta_sdk::protocols::backup_management::chunked::{
    ALGORITHM_CHUNKED, MAX_CHUNK_SIZE, chunk_count, chunk_range, sha256_digest_multibase,
    sha256_from_digest_multibase,
};

use super::descriptors::{
    DescriptorDeps, MAX_BUNDLE_TTL_SECS, bundle_ttl, enforce_kind, enforce_open_bundle_cap,
    parse_bundle_id, require_owned, sha256_hex,
};
use crate::backup_bundle_store::{self, BundleKind, BundleRecord, BundleState, mint_token};
use vti_common::auth::AuthClaims;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Largest `missingIndices` list an `incompleteUpload` refusal carries
/// (`vta/backup/finalize-import/1.1` bounds it).
pub const MAX_REPORTED_MISSING: usize = 256;

/// Chunk requests one DID may make per second, sustained.
///
/// The per-IP limiter in front of the REST routes never sees these: over DIDComm
/// or TSP every request arrives through a mediator, and one mediator can carry
/// every operator's traffic from a single address. So the bound is per
/// authenticated sender. At this rate the largest bundle the algorithm permits
/// (4096 chunks) moves in under two minutes.
pub const CHUNK_REQUESTS_PER_SECOND: f64 = 50.0;

/// Burst above [`CHUNK_REQUESTS_PER_SECOND`] a DID may spend at once.
pub const CHUNK_REQUEST_BURST: f64 = 100.0;

/// Why a chunked operation refused. Kept apart from [`AppError`] because most
/// arms are a specification error code the handler must put on the wire as
/// `<task-slug>:<code>`, and several carry the `details` that code declares.
#[derive(Debug)]
pub enum ChunkedError {
    /// A general failure (authorization, I/O, storage) with no task-specific
    /// code of its own.
    App(AppError),
    /// No live chunked bundle of the right kind that this caller owns.
    /// Deliberately conflates absent, wrong kind, wrong algorithm and not yours.
    NotFound,
    /// The bundle was completed, finalized, aborted, or has expired.
    TerminalState(String),
    /// `index` is not below the manifest's chunk count.
    ChunkOutOfRange { index: u64, chunk_count: u64 },
    /// The chunk's bytes, or the digest the request restated, do not match the
    /// manifest entry for the index.
    DigestMismatch { expected_digest_multibase: String },
    /// The chunk decodes to the wrong length for its index.
    ChunkSizeMismatch { expected: u64, actual: u64 },
    /// A chunked import is missing chunks; `missing_indices` is the first
    /// [`MAX_REPORTED_MISSING`] of them.
    IncompleteUpload {
        missing_count: u64,
        missing_indices: Vec<u64>,
    },
    /// Every chunk verified but the assembled bytes do not match the committed
    /// whole-bundle digest or size.
    BundleDigestMismatch,
    /// The serialized state does not fit in the chunk-count bound at the chunk
    /// size this request allows.
    BundleTooLarge { size_bytes: u64 },
    /// An import manifest that is internally inconsistent or names a digest this
    /// build cannot verify.
    InvalidManifest(String),
    /// The caller exceeded its per-DID chunk request budget.
    RateLimited { retry_after_secs: u64 },
}

impl From<AppError> for ChunkedError {
    fn from(e: AppError) -> Self {
        // Ownership and kind checks shared with the stream ops report absence as
        // `NotFound`; keep that meaning rather than wrapping it as a general
        // failure.
        match e {
            AppError::NotFound(_) => Self::NotFound,
            other => Self::App(other),
        }
    }
}

impl std::fmt::Display for ChunkedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::App(e) => write!(f, "{e}"),
            Self::NotFound => write!(f, "no chunked backup bundle with that identifier"),
            Self::TerminalState(s) => write!(f, "bundle is {s}; nothing more moves under it"),
            Self::ChunkOutOfRange { index, chunk_count } => {
                write!(
                    f,
                    "chunk index {index} is not below the chunk count {chunk_count}"
                )
            }
            Self::DigestMismatch { .. } => {
                write!(f, "chunk does not match the manifest digest for its index")
            }
            Self::ChunkSizeMismatch { expected, actual } => write!(
                f,
                "chunk is {actual} bytes; the manifest requires {expected} at this index"
            ),
            Self::IncompleteUpload { missing_count, .. } => {
                write!(f, "{missing_count} chunk(s) have not been uploaded")
            }
            Self::BundleDigestMismatch => write!(
                f,
                "the assembled bundle does not match the committed digest; abort and upload again"
            ),
            Self::BundleTooLarge { size_bytes } => write!(
                f,
                "a {size_bytes}-byte bundle does not fit in 4096 chunks at the permitted chunk size"
            ),
            Self::InvalidManifest(why) => write!(f, "invalid chunk manifest: {why}"),
            Self::RateLimited { retry_after_secs } => {
                write!(f, "too many chunk requests; retry in {retry_after_secs}s")
            }
        }
    }
}

/// The manifest and progress of one chunked bundle, stored at
/// `chunks:{bundle_id}` in the bundles keyspace beside its [`BundleRecord`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPlan {
    pub bundle_id: Uuid,
    pub chunk_size: u64,
    pub chunk_count: u64,
    /// `DigestMultibase` of each chunk's raw bytes, in index order.
    pub digests: Vec<String>,
    /// Export: which indices have been served at least once. Import: which have
    /// been durably written.
    pub done: Vec<bool>,
    /// The latest `expires_at` activity may extend the bundle to.
    pub expiry_ceiling: DateTime<Utc>,
}

impl ChunkPlan {
    fn missing(&self) -> impl Iterator<Item = u64> + '_ {
        self.done
            .iter()
            .enumerate()
            .filter(|(_, d)| !**d)
            .map(|(i, _)| i as u64)
    }

    fn remaining(&self) -> u64 {
        self.done.iter().filter(|d| !**d).count() as u64
    }
}

fn plan_key(id: &Uuid) -> String {
    format!("chunks:{id}")
}

/// Fetch the chunk plan for a bundle, if it has one.
pub async fn get_plan(ks: &KeyspaceHandle, id: &Uuid) -> Result<Option<ChunkPlan>, AppError> {
    ks.get(plan_key(id)).await
}

async fn store_plan(ks: &KeyspaceHandle, plan: &ChunkPlan) -> Result<(), AppError> {
    ks.insert(plan_key(&plan.bundle_id), plan).await
}

/// Remove a bundle's chunk plan. Called when the bundle ends and by the
/// sweeper's retention pass; absent is not an error.
pub async fn delete_plan(ks: &KeyspaceHandle, id: &Uuid) -> Result<(), AppError> {
    ks.remove(plan_key(id)).await
}

/// Serializes the read-modify-write of a plan's progress bitmap. Chunk requests
/// for one bundle may arrive concurrently, and two writers each reading the
/// bitmap before either stored it would lose one index's progress. One lock for
/// all bundles is enough: the critical section is a small record write, or one
/// chunk-sized read or write, and the per-DID limiter bounds how many wait.
fn chunk_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

// ─── Per-DID rate limit ──────────────────────────────────────────────────

/// Token bucket per authenticated DID for chunk requests.
///
/// In-process and deliberately simple: the quantity it protects (disk reads,
/// hashing, bitmap writes on this VTA) is per-process too.
pub struct ChunkRateLimiter {
    per_second: f64,
    burst: f64,
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl ChunkRateLimiter {
    pub fn new(per_second: f64, burst: f64) -> Self {
        Self {
            per_second,
            burst,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// The process-wide limiter the Trust Task handlers use.
    pub fn global() -> &'static Self {
        static GLOBAL: OnceLock<ChunkRateLimiter> = OnceLock::new();
        GLOBAL.get_or_init(|| Self::new(CHUNK_REQUESTS_PER_SECOND, CHUNK_REQUEST_BURST))
    }

    /// Spend one request for `did`, or say how long until one is available.
    pub fn check(&self, did: &str) -> Result<(), ChunkedError> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        // Forget callers idle long enough to have refilled completely, so the
        // map does not grow with every DID that ever asked.
        let full_after = self.burst / self.per_second;
        buckets.retain(|_, (_, last)| now.duration_since(*last).as_secs_f64() < full_after * 4.0);
        let (tokens, last) = buckets.entry(did.to_string()).or_insert((self.burst, now));
        let refilled =
            (*tokens + now.duration_since(*last).as_secs_f64() * self.per_second).min(self.burst);
        *last = now;
        if refilled >= 1.0 {
            *tokens = refilled - 1.0;
            Ok(())
        } else {
            *tokens = refilled;
            let wait = ((1.0 - refilled) / self.per_second).ceil().max(1.0);
            Err(ChunkedError::RateLimited {
                retry_after_secs: wait as u64,
            })
        }
    }
}

// ─── Export ──────────────────────────────────────────────────────────────

/// What a chunked `initiate-export` hands back: the manifest and the terms.
#[derive(Debug, Clone)]
pub struct ChunkedBundle {
    pub bundle_id: Uuid,
    pub chunk_size: u64,
    pub chunk_count: u64,
    pub digests: Vec<String>,
    pub expected_sha256: String,
    pub expected_size_bytes: u64,
    pub expires_at: DateTime<Utc>,
}

/// Mint a `chunkedTrustTask` export bundle.
///
/// Serializes and encrypts the agent's state exactly as the `stream` op does,
/// then stages it for retrieval by index instead of by URL. Needs no
/// `public_url`: the chunks travel over the transport this request arrived on.
///
/// `max_chunk_size` is the producer's `maxChunkSize`; the chunk size used is the
/// normative ceiling or that, whichever is smaller.
pub async fn initiate_export(
    deps: &DescriptorDeps<'_>,
    auth: &AuthClaims,
    password: &str,
    include_audit: bool,
    max_chunk_size: Option<u64>,
) -> Result<ChunkedBundle, ChunkedError> {
    auth.require_super_admin()?;
    enforce_open_bundle_cap(deps.bundles_ks, &auth.did).await?;

    let envelope = {
        let config_guard = deps.config.read().await;
        super::export_backup(
            &deps.keyspaces,
            deps.seed_store.as_ref(),
            &config_guard,
            auth,
            password,
            include_audit,
        )
        .await?
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|e| AppError::Internal(format!("serialize backup envelope: {e}")))?;
    stage_export(
        deps.bundles_ks,
        deps.blob_dir,
        &auth.did,
        &bytes,
        max_chunk_size,
    )
    .await
}

/// Stage already-encrypted export bytes as a chunked bundle. Split from
/// [`initiate_export`] so the staging and serving logic can be exercised without
/// a full agent to serialize.
pub async fn stage_export(
    bundles_ks: &KeyspaceHandle,
    blob_dir: &Path,
    owner_did: &str,
    bytes: &[u8],
    max_chunk_size: Option<u64>,
) -> Result<ChunkedBundle, ChunkedError> {
    let chunk_size = max_chunk_size.unwrap_or(MAX_CHUNK_SIZE).min(MAX_CHUNK_SIZE);
    let size = bytes.len() as u64;
    let count =
        chunk_count(size, chunk_size).ok_or(ChunkedError::BundleTooLarge { size_bytes: size })?;

    let digests: Vec<String> = bytes
        .chunks(chunk_size as usize)
        .map(|c| sha256_digest_multibase(&Sha256::digest(c).into()))
        .collect();
    debug_assert_eq!(digests.len() as u64, count);

    let bundle_id = Uuid::new_v4();
    let blob_path = prepare_blob_path(blob_dir, &bundle_id).await?;
    tokio::fs::write(&blob_path, bytes)
        .await
        .map_err(AppError::Io)?;
    #[cfg(unix)]
    super::descriptors::set_file_mode_600(&blob_path).await?;

    let now = Utc::now();
    // The record's `token_hash` is required by its shape and never presented:
    // a chunked bundle is admitted by the authenticated sender, not a token. A
    // fresh random hash that no token was ever issued for keeps the blob
    // endpoint refusing this bundle whatever is sent to it.
    let (_unused_token, token_hash) = mint_token()?;
    let record = BundleRecord {
        bundle_id,
        kind: BundleKind::Export,
        state: BundleState::ExportReady,
        created_at: now,
        expires_at: now + bundle_ttl(),
        created_by: owner_did.to_string(),
        algorithm: ALGORITHM_CHUNKED.into(),
        expected_sha256: sha256_hex(bytes),
        expected_size_bytes: size,
        token_hash,
        blob_path: Some(blob_path),
    };
    let plan = ChunkPlan {
        bundle_id,
        chunk_size,
        chunk_count: count,
        digests: digests.clone(),
        done: vec![false; count as usize],
        expiry_ceiling: now + Duration::seconds(MAX_BUNDLE_TTL_SECS as i64),
    };
    // Plan first: a record without its plan would be a chunked bundle nothing
    // can serve, where a plan without its record is inert.
    store_plan(bundles_ks, &plan).await?;
    backup_bundle_store::store_bundle(bundles_ks, &record).await?;

    info!(bundle_id = %bundle_id, size, chunks = count, "initiate-export (chunked): bundle ready");
    Ok(ChunkedBundle {
        bundle_id,
        chunk_size,
        chunk_count: count,
        digests,
        expected_sha256: record.expected_sha256,
        expected_size_bytes: size,
        expires_at: record.expires_at,
    })
}

/// One served chunk.
#[derive(Debug, Clone)]
pub struct ServedChunk {
    pub bundle_id: Uuid,
    pub index: u64,
    pub digest_multibase: String,
    pub data: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

/// Serve chunk `index` of a chunked export bundle.
///
/// Reads only that chunk's byte range from the staged file, never the whole
/// bundle. Non-consuming: repeated requests return the same bytes while the
/// bundle is live. Records the index as served and slides the expiry within its
/// ceiling.
pub async fn get_chunk(
    bundles_ks: &KeyspaceHandle,
    limiter: &ChunkRateLimiter,
    auth: &AuthClaims,
    bundle_id: &str,
    index: u64,
) -> Result<ServedChunk, ChunkedError> {
    auth.require_super_admin()?;
    limiter.check(&auth.did)?;
    let id = parse_bundle_id(bundle_id)?;

    let _guard = chunk_lock().lock().await;
    let (mut record, mut plan) =
        load_chunked(bundles_ks, &id, &auth.did, BundleKind::Export).await?;
    match record.state {
        BundleState::ExportReady => {}
        BundleState::ExportAcked => return Err(ChunkedError::TerminalState("completed".into())),
        BundleState::Aborted => return Err(ChunkedError::TerminalState("aborted".into())),
        _ => return Err(ChunkedError::TerminalState("expired".into())),
    }
    let now = Utc::now();
    if record.expires_at <= now {
        return Err(ChunkedError::TerminalState("expired".into()));
    }
    let (start, end) = chunk_range(record.expected_size_bytes, plan.chunk_size, index).ok_or(
        ChunkedError::ChunkOutOfRange {
            index,
            chunk_count: plan.chunk_count,
        },
    )?;

    let path = record
        .blob_path
        .clone()
        .ok_or_else(|| ChunkedError::TerminalState("expired".into()))?;
    let data = read_range(&path, start, end).await?;

    // The bytes on disk must still be the ones the manifest committed to. A
    // mismatch is storage corruption, never the caller's fault, and serving it
    // would hand the client a chunk its own check will reject.
    let expected = &plan.digests[index as usize];
    if sha256_from_digest_multibase(expected) != Some(Sha256::digest(&data).into()) {
        return Err(ChunkedError::App(AppError::Internal(format!(
            "staged bytes for chunk {index} of bundle {id} no longer match the manifest"
        ))));
    }

    plan.done[index as usize] = true;
    extend_expiry(&mut record, &plan, now);
    store_plan(bundles_ks, &plan).await?;
    backup_bundle_store::store_bundle(bundles_ks, &record).await?;

    Ok(ServedChunk {
        bundle_id: id,
        index,
        digest_multibase: expected.clone(),
        data,
        expires_at: record.expires_at,
    })
}

/// Whether every chunk of a chunked export has been served at least once — the
/// meaning `complete-export`'s `downloaded` takes for such a bundle. `None` for
/// a bundle with no chunk plan (a `stream` bundle).
pub async fn all_served(ks: &KeyspaceHandle, id: &Uuid) -> Result<Option<bool>, AppError> {
    Ok(get_plan(ks, id).await?.map(|p| p.remaining() == 0))
}

// ─── Import ──────────────────────────────────────────────────────────────

/// Open a chunked import slot for a manifest the producer has pre-committed.
///
/// Refuses an inconsistent manifest — a chunk count that does not follow from
/// the size and chunk size, a digest list of the wrong length, or a digest this
/// build cannot verify — before any slot exists.
pub async fn initiate_import(
    bundles_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    expected_sha256: &str,
    expected_size_bytes: u64,
    chunk_size: u64,
    declared_chunk_count: u64,
    digests: Vec<String>,
) -> Result<ChunkedBundle, ChunkedError> {
    auth.require_super_admin()?;
    enforce_open_bundle_cap(bundles_ks, &auth.did).await?;

    if expected_sha256.len() != 64
        || !expected_sha256
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(ChunkedError::InvalidManifest(
            "expectedSha256 must be 64 lowercase hex characters".into(),
        ));
    }
    let count = chunk_count(expected_size_bytes, chunk_size).ok_or_else(|| {
        ChunkedError::InvalidManifest(format!(
            "{expected_size_bytes} bytes cannot be divided into at most 4096 chunks of {chunk_size}"
        ))
    })?;
    if count != declared_chunk_count {
        return Err(ChunkedError::InvalidManifest(format!(
            "chunkCount is {declared_chunk_count}; {expected_size_bytes} bytes at {chunk_size} is {count}"
        )));
    }
    if digests.len() as u64 != count {
        return Err(ChunkedError::InvalidManifest(format!(
            "chunkDigests has {} entries; the manifest has {count} chunks",
            digests.len()
        )));
    }
    if let Some(bad) = digests
        .iter()
        .position(|d| sha256_from_digest_multibase(d).is_none())
    {
        return Err(ChunkedError::InvalidManifest(format!(
            "chunkDigests[{bad}] is not a sha2-256 multihash this agent can verify"
        )));
    }

    let bundle_id = Uuid::new_v4();
    let now = Utc::now();
    let (_unused_token, token_hash) = mint_token()?;
    let record = BundleRecord {
        bundle_id,
        kind: BundleKind::Import,
        state: BundleState::ImportPending,
        created_at: now,
        expires_at: now + bundle_ttl(),
        created_by: auth.did.clone(),
        algorithm: ALGORITHM_CHUNKED.into(),
        expected_sha256: expected_sha256.to_string(),
        expected_size_bytes,
        token_hash,
        // Set by the first accepted chunk, which creates the staging file.
        blob_path: None,
    };
    let plan = ChunkPlan {
        bundle_id,
        chunk_size,
        chunk_count: count,
        digests: digests.clone(),
        done: vec![false; count as usize],
        expiry_ceiling: now + Duration::seconds(MAX_BUNDLE_TTL_SECS as i64),
    };
    store_plan(bundles_ks, &plan).await?;
    backup_bundle_store::store_bundle(bundles_ks, &record).await?;

    info!(bundle_id = %bundle_id, chunks = count, "initiate-import (chunked): slot ready");
    Ok(ChunkedBundle {
        bundle_id,
        chunk_size,
        chunk_count: count,
        digests,
        expected_sha256: record.expected_sha256,
        expected_size_bytes,
        expires_at: record.expires_at,
    })
}

/// What one accepted write reports back.
#[derive(Debug, Clone, Copy)]
pub struct PutOutcome {
    pub stored: bool,
    pub remaining_count: u64,
    pub expires_at: DateTime<Utc>,
}

/// One `put-chunk` request, as the op reads it.
#[derive(Debug, Clone, Copy)]
pub struct ChunkWrite<'a> {
    pub bundle_id: &'a str,
    pub index: u64,
    /// The digest the request restates for this index.
    pub digest_multibase: &'a str,
    /// The chunk's raw bytes, already decoded from base64url.
    pub data: &'a [u8],
}

/// Write chunk `index` of a chunked import.
///
/// The chunk is checked against the manifest committed at `initiate-import`
/// before anything is written, and the write is synced before `stored: true` is
/// answered — the client may discard its copy on that answer. A chunk already
/// held is never rewritten; since it passed the same check it is identical, and
/// the answer is `stored: false`.
pub async fn put_chunk(
    bundles_ks: &KeyspaceHandle,
    blob_dir: &Path,
    limiter: &ChunkRateLimiter,
    auth: &AuthClaims,
    write: ChunkWrite<'_>,
) -> Result<PutOutcome, ChunkedError> {
    let ChunkWrite {
        bundle_id,
        index,
        digest_multibase,
        data,
    } = write;
    auth.require_super_admin()?;
    limiter.check(&auth.did)?;
    let id = parse_bundle_id(bundle_id)?;

    let _guard = chunk_lock().lock().await;
    let (mut record, mut plan) =
        load_chunked(bundles_ks, &id, &auth.did, BundleKind::Import).await?;
    match record.state {
        BundleState::ImportPending => {}
        // Assembled and verified: every index is held, so this is a repeat of a
        // write that already landed, and it is answered as one below — but only
        // while the bundle is still open.
        BundleState::ImportReceived | BundleState::ImportPreviewed => {}
        BundleState::ImportCommitted => {
            return Err(ChunkedError::TerminalState("committed".into()));
        }
        BundleState::Aborted => return Err(ChunkedError::TerminalState("aborted".into())),
        _ => return Err(ChunkedError::TerminalState("expired".into())),
    }
    let now = Utc::now();
    if record.expires_at <= now {
        return Err(ChunkedError::TerminalState("expired".into()));
    }
    let (start, end) = chunk_range(record.expected_size_bytes, plan.chunk_size, index).ok_or(
        ChunkedError::ChunkOutOfRange {
            index,
            chunk_count: plan.chunk_count,
        },
    )?;
    if data.len() as u64 != end - start {
        return Err(ChunkedError::ChunkSizeMismatch {
            expected: end - start,
            actual: data.len() as u64,
        });
    }
    let expected = plan.digests[index as usize].clone();
    let committed = sha256_from_digest_multibase(&expected);
    let restated = sha256_from_digest_multibase(digest_multibase);
    let actual: [u8; 32] = Sha256::digest(data).into();
    if committed.is_none() || restated != committed || committed != Some(actual) {
        return Err(ChunkedError::DigestMismatch {
            expected_digest_multibase: expected,
        });
    }

    let stored = if plan.done[index as usize] {
        false
    } else {
        let path = match record.blob_path.clone() {
            Some(p) => p,
            None => {
                let p = prepare_blob_path(blob_dir, &id).await?;
                record.blob_path = Some(p.clone());
                p
            }
        };
        write_range(&path, record.expected_size_bytes, start, data).await?;
        plan.done[index as usize] = true;
        true
    };

    extend_expiry(&mut record, &plan, now);
    store_plan(bundles_ks, &plan).await?;
    backup_bundle_store::store_bundle(bundles_ks, &record).await?;

    Ok(PutOutcome {
        stored,
        remaining_count: plan.remaining(),
        expires_at: record.expires_at,
    })
}

/// The checks `finalize-import` must make of a chunked bundle before the
/// password is used: every chunk present, and the assembled bytes equal to the
/// committed whole-bundle digest and size. On success the bundle moves to
/// `ImportReceived`, which is the state the finalize op accepts.
///
/// A no-op for a `stream` bundle, whose bytes were verified on upload, and for a
/// chunked bundle already verified. Makes no change on refusal, so a producer may
/// write the missing chunks and ask again.
pub async fn finalize_precheck(
    bundles_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    bundle_id: &str,
) -> Result<(), ChunkedError> {
    auth.require_super_admin()?;
    let id = parse_bundle_id(bundle_id)?;
    let _guard = chunk_lock().lock().await;
    let record = require_owned(bundles_ks, &id, &auth.did).await?;
    enforce_kind(&record, BundleKind::Import)?;
    if record.algorithm != ALGORITHM_CHUNKED || record.state != BundleState::ImportPending {
        return Ok(());
    }
    let plan = get_plan(bundles_ks, &id)
        .await?
        .ok_or(ChunkedError::NotFound)?;

    let missing_count = plan.remaining();
    if missing_count > 0 {
        return Err(ChunkedError::IncompleteUpload {
            missing_count,
            missing_indices: plan.missing().take(MAX_REPORTED_MISSING).collect(),
        });
    }

    let path = record
        .blob_path
        .clone()
        .ok_or_else(|| AppError::Internal(format!("chunked bundle {id} has no staging file")))?;
    if !assembled_matches(&path, &record).await? {
        return Err(ChunkedError::BundleDigestMismatch);
    }

    let mut record = record;
    record.state = BundleState::ImportReceived;
    backup_bundle_store::store_bundle(bundles_ks, &record).await?;
    info!(bundle_id = %id, "finalize-import (chunked): upload assembled and verified");
    Ok(())
}

// ─── Internals ───────────────────────────────────────────────────────────

/// Load a bundle and its plan, requiring the caller to own a chunked bundle of
/// `kind`. Every other case is `NotFound`, so a handle never becomes an oracle
/// over another operator's bundles or a stream bundle's existence.
///
/// A terminal bundle is reported as such *before* its plan is looked up: the
/// plan goes when the bundle is completed or aborted, and the creator is owed
/// `terminalState` for it, not a `notFound` that reads as a bad handle.
async fn load_chunked(
    ks: &KeyspaceHandle,
    id: &Uuid,
    caller: &str,
    kind: BundleKind,
) -> Result<(BundleRecord, ChunkPlan), ChunkedError> {
    let record = require_owned(ks, id, caller).await?;
    enforce_kind(&record, kind)?;
    if record.algorithm != ALGORITHM_CHUNKED {
        return Err(ChunkedError::NotFound);
    }
    match record.state {
        BundleState::ExportAcked => return Err(ChunkedError::TerminalState("completed".into())),
        BundleState::ImportCommitted => {
            return Err(ChunkedError::TerminalState("committed".into()));
        }
        BundleState::Aborted => return Err(ChunkedError::TerminalState("aborted".into())),
        BundleState::Expired | BundleState::ExportDownloaded => {
            return Err(ChunkedError::TerminalState("expired".into()));
        }
        _ => {}
    }
    let plan = get_plan(ks, id).await?.ok_or(ChunkedError::NotFound)?;
    Ok((record, plan))
}

/// Slide the bundle's expiry to one TTL from now, never past the ceiling and
/// never backwards.
fn extend_expiry(record: &mut BundleRecord, plan: &ChunkPlan, now: DateTime<Utc>) {
    let proposed = (now + bundle_ttl()).min(plan.expiry_ceiling);
    if proposed > record.expires_at {
        record.expires_at = proposed;
    }
}

async fn prepare_blob_path(blob_dir: &Path, id: &Uuid) -> Result<PathBuf, AppError> {
    tokio::fs::create_dir_all(blob_dir)
        .await
        .map_err(AppError::Io)?;
    #[cfg(unix)]
    super::descriptors::set_dir_mode_700(blob_dir).await?;
    Ok(blob_dir.join(format!("{id}.vtabak")))
}

async fn read_range(path: &Path, start: u64, end: u64) -> Result<Vec<u8>, ChunkedError> {
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ChunkedError::TerminalState("expired".into()));
        }
        Err(e) => return Err(AppError::Io(e).into()),
    };
    file.seek(SeekFrom::Start(start))
        .await
        .map_err(AppError::Io)?;
    let mut data = vec![0u8; (end - start) as usize];
    file.read_exact(&mut data).await.map_err(AppError::Io)?;
    Ok(data)
}

/// Write `data` at `offset` in the staging file, creating it at the bundle's
/// full size on first use, and sync before returning.
async fn write_range(
    path: &Path,
    total_size: u64,
    offset: u64,
    data: &[u8],
) -> Result<(), AppError> {
    let existed = tokio::fs::try_exists(path).await.map_err(AppError::Io)?;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .await
        .map_err(AppError::Io)?;
    if !existed {
        #[cfg(unix)]
        super::descriptors::set_file_mode_600(path).await?;
        file.set_len(total_size).await.map_err(AppError::Io)?;
    }
    file.seek(SeekFrom::Start(offset))
        .await
        .map_err(AppError::Io)?;
    file.write_all(data).await.map_err(AppError::Io)?;
    file.sync_data().await.map_err(AppError::Io)?;
    Ok(())
}

/// Hash the assembled staging file in bounded reads and compare it with the
/// committed digest and size.
async fn assembled_matches(path: &Path, record: &BundleRecord) -> Result<bool, AppError> {
    let mut file = tokio::fs::File::open(path).await.map_err(AppError::Io)?;
    let len = file.metadata().await.map_err(AppError::Io)?.len();
    if len != record.expected_size_bytes {
        return Ok(false);
    }
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; MAX_CHUNK_SIZE as usize];
    loop {
        let n = file.read(&mut buf).await.map_err(AppError::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    Ok(hex == record.expected_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::acl::Role;
    use vti_common::config::StoreConfig as VtiStoreConfig;
    use vti_common::store::Store;

    const OWNER: &str = "did:key:z6MkChunkOwner";
    const MIN: u64 = vta_sdk::protocols::backup_management::chunked::MIN_CHUNK_SIZE;

    fn admin(did: &str) -> AuthClaims {
        AuthClaims {
            did: did.into(),
            role: Role::Admin,
            allowed_contexts: Vec::new(),
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    struct Env {
        _dir: tempfile::TempDir,
        ks: KeyspaceHandle,
        blob_dir: PathBuf,
    }

    fn env() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().join("store"),
        })
        .unwrap();
        let ks = store.keyspace(crate::BACKUP_BUNDLES_TEST).unwrap();
        let blob_dir = dir.path().join("backups");
        Env {
            _dir: dir,
            ks,
            blob_dir,
        }
    }

    fn unlimited() -> ChunkRateLimiter {
        ChunkRateLimiter::new(1.0e9, 1.0e9)
    }

    /// Three chunks at the minimum chunk size, the last a short remainder, with
    /// distinct contents so a misordered read cannot pass.
    fn bundle_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(std::iter::repeat_n(1u8, MIN as usize));
        v.extend(std::iter::repeat_n(2u8, MIN as usize));
        v.extend_from_slice(b"backup-tail!");
        v
    }

    fn digest(bytes: &[u8]) -> String {
        sha256_digest_multibase(&Sha256::digest(bytes).into())
    }

    #[tokio::test]
    async fn export_round_trips_chunk_by_chunk_and_is_non_consuming() {
        let e = env();
        let auth = admin(OWNER);
        let bytes = bundle_bytes();
        let bundle = stage_export(&e.ks, &e.blob_dir, OWNER, &bytes, Some(MIN))
            .await
            .unwrap();
        assert_eq!(bundle.chunk_count, 3);

        let mut assembled = Vec::new();
        for i in 0..bundle.chunk_count {
            let c = get_chunk(&e.ks, &unlimited(), &auth, &bundle.bundle_id.to_string(), i)
                .await
                .unwrap();
            assert_eq!(c.digest_multibase, bundle.digests[i as usize]);
            assert_eq!(digest(&c.data), bundle.digests[i as usize]);
            assembled.extend(c.data);
        }
        assert_eq!(assembled, bytes);
        assert_eq!(sha256_hex(&assembled), bundle.expected_sha256);

        // Reading again returns the same bytes: nothing was consumed.
        let again = get_chunk(&e.ks, &unlimited(), &auth, &bundle.bundle_id.to_string(), 2)
            .await
            .unwrap();
        assert_eq!(again.data, b"backup-tail!");
        assert_eq!(
            all_served(&e.ks, &bundle.bundle_id).await.unwrap(),
            Some(true)
        );
    }

    #[tokio::test]
    async fn an_index_past_the_last_chunk_is_out_of_range() {
        let e = env();
        let bundle = stage_export(&e.ks, &e.blob_dir, OWNER, &bundle_bytes(), Some(MIN))
            .await
            .unwrap();
        let err = get_chunk(
            &e.ks,
            &unlimited(),
            &admin(OWNER),
            &bundle.bundle_id.to_string(),
            3,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                ChunkedError::ChunkOutOfRange {
                    index: 3,
                    chunk_count: 3
                }
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn another_operators_bundle_is_not_found() {
        let e = env();
        let bundle = stage_export(&e.ks, &e.blob_dir, OWNER, &bundle_bytes(), Some(MIN))
            .await
            .unwrap();
        let err = get_chunk(
            &e.ks,
            &unlimited(),
            &admin("did:key:z6MkSomeoneElse"),
            &bundle.bundle_id.to_string(),
            0,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChunkedError::NotFound), "{err:?}");
    }

    #[tokio::test]
    async fn serving_a_chunk_slides_the_expiry_but_never_past_the_ceiling() {
        let e = env();
        let auth = admin(OWNER);
        let bundle = stage_export(&e.ks, &e.blob_dir, OWNER, &bundle_bytes(), Some(MIN))
            .await
            .unwrap();
        let id = bundle.bundle_id;

        // Age the bundle: it expires in 10 seconds, with its ceiling 20 seconds
        // out. One chunk request must move the expiry to the ceiling, not a full
        // TTL beyond it.
        let now = Utc::now();
        let mut record = backup_bundle_store::get_bundle(&e.ks, &id)
            .await
            .unwrap()
            .unwrap();
        record.expires_at = now + Duration::seconds(10);
        backup_bundle_store::store_bundle(&e.ks, &record)
            .await
            .unwrap();
        let mut plan = get_plan(&e.ks, &id).await.unwrap().unwrap();
        plan.expiry_ceiling = now + Duration::seconds(20);
        store_plan(&e.ks, &plan).await.unwrap();

        let served = get_chunk(&e.ks, &unlimited(), &auth, &id.to_string(), 0)
            .await
            .unwrap();
        assert_eq!(served.expires_at, plan.expiry_ceiling);

        // With the ceiling well ahead, activity extends by one TTL from now.
        let mut plan = get_plan(&e.ks, &id).await.unwrap().unwrap();
        plan.expiry_ceiling = now + Duration::hours(1);
        store_plan(&e.ks, &plan).await.unwrap();
        let served = get_chunk(&e.ks, &unlimited(), &auth, &id.to_string(), 1)
            .await
            .unwrap();
        assert!(served.expires_at > now + Duration::seconds(20));
        assert!(served.expires_at <= plan.expiry_ceiling);
    }

    #[tokio::test]
    async fn an_expired_bundle_serves_nothing() {
        let e = env();
        let bundle = stage_export(&e.ks, &e.blob_dir, OWNER, &bundle_bytes(), Some(MIN))
            .await
            .unwrap();
        let mut record = backup_bundle_store::get_bundle(&e.ks, &bundle.bundle_id)
            .await
            .unwrap()
            .unwrap();
        record.expires_at = Utc::now() - Duration::seconds(1);
        backup_bundle_store::store_bundle(&e.ks, &record)
            .await
            .unwrap();
        let err = get_chunk(
            &e.ks,
            &unlimited(),
            &admin(OWNER),
            &bundle.bundle_id.to_string(),
            0,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChunkedError::TerminalState(_)), "{err:?}");
    }

    #[tokio::test]
    async fn a_bundle_too_large_for_the_chunk_bound_is_refused() {
        let e = env();
        // 4097 minimum-size chunks' worth cannot be staged at the minimum size.
        let bytes = vec![0u8; (MIN * 4096 + 1) as usize];
        let err = stage_export(&e.ks, &e.blob_dir, OWNER, &bytes, Some(MIN))
            .await
            .unwrap_err();
        assert!(
            matches!(err, ChunkedError::BundleTooLarge { .. }),
            "{err:?}"
        );
    }

    async fn open_import(e: &Env, bytes: &[u8]) -> ChunkedBundle {
        let digests: Vec<String> = bytes.chunks(MIN as usize).map(digest).collect();
        initiate_import(
            &e.ks,
            &admin(OWNER),
            &sha256_hex(bytes),
            bytes.len() as u64,
            MIN,
            digests.len() as u64,
            digests,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn import_resumes_after_a_missing_chunk_and_assembles() {
        let e = env();
        let auth = admin(OWNER);
        let bytes = bundle_bytes();
        let slot = open_import(&e, &bytes).await;
        let id = slot.bundle_id.to_string();
        let chunks: Vec<&[u8]> = bytes.chunks(MIN as usize).collect();

        // Write 0 and 2; chunk 1 is "lost".
        for i in [0usize, 2] {
            let out = put_chunk(
                &e.ks,
                &e.blob_dir,
                &unlimited(),
                &auth,
                ChunkWrite {
                    bundle_id: &id,
                    index: i as u64,
                    digest_multibase: &slot.digests[i],
                    data: chunks[i],
                },
            )
            .await
            .unwrap();
            assert!(out.stored);
        }

        // Finalize refuses, names exactly the missing index, and changes nothing.
        let err = finalize_precheck(&e.ks, &auth, &id).await.unwrap_err();
        match err {
            ChunkedError::IncompleteUpload {
                missing_count,
                missing_indices,
            } => {
                assert_eq!(missing_count, 1);
                assert_eq!(missing_indices, vec![1]);
            }
            other => panic!("expected IncompleteUpload, got {other:?}"),
        }

        // Resume: write only the missing index.
        let out = put_chunk(
            &e.ks,
            &e.blob_dir,
            &unlimited(),
            &auth,
            ChunkWrite {
                bundle_id: &id,
                index: 1,
                digest_multibase: &slot.digests[1],
                data: chunks[1],
            },
        )
        .await
        .unwrap();
        assert!(out.stored);
        assert_eq!(out.remaining_count, 0);

        finalize_precheck(&e.ks, &auth, &id).await.unwrap();
        let record = backup_bundle_store::get_bundle(&e.ks, &slot.bundle_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.state, BundleState::ImportReceived);
        let staged = tokio::fs::read(record.blob_path.unwrap()).await.unwrap();
        assert_eq!(staged, bytes);
    }

    #[tokio::test]
    async fn an_identical_re_put_is_stored_false_and_a_mismatched_one_is_refused() {
        let e = env();
        let auth = admin(OWNER);
        let bytes = bundle_bytes();
        let slot = open_import(&e, &bytes).await;
        let id = slot.bundle_id.to_string();
        let chunk0 = &bytes[..MIN as usize];

        let first = put_chunk(
            &e.ks,
            &e.blob_dir,
            &unlimited(),
            &auth,
            ChunkWrite {
                bundle_id: &id,
                index: 0,
                digest_multibase: &slot.digests[0],
                data: chunk0,
            },
        )
        .await
        .unwrap();
        assert!(first.stored);
        let repeat = put_chunk(
            &e.ks,
            &e.blob_dir,
            &unlimited(),
            &auth,
            ChunkWrite {
                bundle_id: &id,
                index: 0,
                digest_multibase: &slot.digests[0],
                data: chunk0,
            },
        )
        .await
        .unwrap();
        assert!(!repeat.stored, "an identical re-put stores nothing new");

        // Same length, different bytes: refused, and chunk 0 on disk is untouched.
        let tampered = vec![9u8; MIN as usize];
        let err = put_chunk(
            &e.ks,
            &e.blob_dir,
            &unlimited(),
            &auth,
            ChunkWrite {
                bundle_id: &id,
                index: 0,
                digest_multibase: &digest(&tampered),
                data: &tampered,
            },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ChunkedError::DigestMismatch { .. }),
            "{err:?}"
        );

        // The committed digest restated with the wrong bytes is refused too.
        let err = put_chunk(
            &e.ks,
            &e.blob_dir,
            &unlimited(),
            &auth,
            ChunkWrite {
                bundle_id: &id,
                index: 1,
                digest_multibase: &slot.digests[1],
                data: &tampered,
            },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ChunkedError::DigestMismatch { .. }),
            "{err:?}"
        );

        let record = backup_bundle_store::get_bundle(&e.ks, &slot.bundle_id)
            .await
            .unwrap()
            .unwrap();
        let staged = tokio::fs::read(record.blob_path.unwrap()).await.unwrap();
        assert_eq!(&staged[..MIN as usize], chunk0);
    }

    #[tokio::test]
    async fn a_wrong_length_chunk_is_refused() {
        let e = env();
        let bytes = bundle_bytes();
        let slot = open_import(&e, &bytes).await;
        let short = &bytes[..10];
        let err = put_chunk(
            &e.ks,
            &e.blob_dir,
            &unlimited(),
            &admin(OWNER),
            ChunkWrite {
                bundle_id: &slot.bundle_id.to_string(),
                index: 0,
                digest_multibase: &digest(short),
                data: short,
            },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ChunkedError::ChunkSizeMismatch { expected, actual: 10 } if expected == MIN),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn a_manifest_whose_count_does_not_follow_is_refused() {
        let e = env();
        let bytes = bundle_bytes();
        let digests: Vec<String> = bytes.chunks(MIN as usize).map(digest).collect();
        let err = initiate_import(
            &e.ks,
            &admin(OWNER),
            &sha256_hex(&bytes),
            bytes.len() as u64,
            MIN,
            2,
            digests,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChunkedError::InvalidManifest(_)), "{err:?}");
    }

    #[tokio::test]
    async fn chunks_that_verify_but_do_not_assemble_to_the_bundle_are_caught() {
        let e = env();
        let auth = admin(OWNER);
        let bytes = bundle_bytes();
        // A manifest whose per-chunk digests are right but whose whole-bundle
        // digest names different bytes.
        let digests: Vec<String> = bytes.chunks(MIN as usize).map(digest).collect();
        let slot = initiate_import(
            &e.ks,
            &auth,
            &sha256_hex(b"something else"),
            bytes.len() as u64,
            MIN,
            3,
            digests,
        )
        .await
        .unwrap();
        let id = slot.bundle_id.to_string();
        for (i, c) in bytes.chunks(MIN as usize).enumerate() {
            put_chunk(
                &e.ks,
                &e.blob_dir,
                &unlimited(),
                &auth,
                ChunkWrite {
                    bundle_id: &id,
                    index: i as u64,
                    digest_multibase: &slot.digests[i],
                    data: c,
                },
            )
            .await
            .unwrap();
        }
        let err = finalize_precheck(&e.ks, &auth, &id).await.unwrap_err();
        assert!(matches!(err, ChunkedError::BundleDigestMismatch), "{err:?}");
    }

    #[test]
    fn the_limiter_refuses_past_the_burst_and_names_a_wait() {
        let limiter = ChunkRateLimiter::new(1.0, 2.0);
        limiter.check(OWNER).unwrap();
        limiter.check(OWNER).unwrap();
        match limiter.check(OWNER) {
            Err(ChunkedError::RateLimited { retry_after_secs }) => assert!(retry_after_secs >= 1),
            other => panic!("expected RateLimited, got {other:?}"),
        }
        // Budgets are per DID.
        limiter.check("did:key:z6MkAnotherOperator").unwrap();
    }
}
