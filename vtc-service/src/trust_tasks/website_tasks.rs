//! The community website's content on the signed-document spine: a chunked
//! upload (`vtc/website/upload/{begin,chunk,commit,abort}/0.1`), publishing a
//! staged bundle (`vtc/website/deploy/0.1`), and ranged reads
//! (`vtc/website/files/show/0.1`). These replace the raw-byte routes
//! `GET`/`PUT /v1/website/files/{path}` and `POST /v1/website/deploy`.
//!
//! Every task is an administrator's (the old routes' `AdminAuth`), read from
//! the signer's ACL row ([`super::admin_signer`]), and an upload belongs to the
//! identity that began it: another's `uploadId` is `notFound`.
//!
//! # The transfer
//!
//! `begin` commits everything before a byte moves: the target (a file at a
//! path, with an optional `ifMatch`, or a whole-site bundle), the total size,
//! the whole-content SHA-256 and every chunk's digest. Each `chunk` is checked
//! against that manifest on arrival, and `commit` checks the reassembled bytes
//! against the committed SHA-256 before anything is written — then writes a
//! file target atomically, or stages a bundle for `deploy`.
//!
//! The staging, the manifest checks and the expiry are
//! [`vti_common::backup_transfer::chunked`], the machinery the backup family
//! uses: an upload's slot lives five minutes from its last chunk, never more
//! than an hour, is collected by the same sweeper, and an identity holds at
//! most [`vti_common::backup_transfer::MAX_OPEN_BUNDLES_PER_DID`] open at once.
//! What is the website's own — the target — sits beside the slot under
//! `website-upload:<id>`.
//!
//! A chunk is at most [`MAX_CHUNK_SIZE`] (256 KiB); `begin`, `chunk` and the
//! `files/show` response declare their `maxDocumentBytes`, which the spine
//! admits for a signer with standing ([`super::size`]).

use base64::Engine as _;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trust_tasks_rs::specs::vtc::website::{
    deploy::v0_1 as deploy,
    files::{delete::v0_1 as files_delete, list::v0_1 as files_list, show::v0_1 as files_show},
    generations::list::v0_1 as generations_list,
    rollback::v0_1 as rollback,
    upload::{
        abort::v0_1 as upload_abort, begin::v0_1 as upload_begin, chunk::v0_1 as upload_chunk,
        commit::v0_1 as upload_commit,
    },
};
use trust_tasks_rs::{Payload, RejectReason, TrustTask};
use uuid::Uuid;
use vti_common::backup_transfer::bundle_store::{self, BundleState};
use vti_common::backup_transfer::chunked::{self, ChunkRateLimiter, ChunkWrite, ChunkedError};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response,
};
use super::{JoinAuthCtx, parse_spec_payload};
use crate::error::AppError;
use crate::server::AppState;
use crate::website::paths::{PathError, canonical_within_root, canonical_within_root_for_create};

pub(crate) const BEGIN_TYPE: &str = <upload_begin::Payload as Payload>::TYPE_URI;
pub(crate) const CHUNK_TYPE: &str = <upload_chunk::Payload as Payload>::TYPE_URI;
pub(crate) const COMMIT_TYPE: &str = <upload_commit::Payload as Payload>::TYPE_URI;
pub(crate) const ABORT_TYPE: &str = <upload_abort::Payload as Payload>::TYPE_URI;
pub(crate) const DEPLOY_TYPE: &str = <deploy::Payload as Payload>::TYPE_URI;
pub(crate) const FILES_SHOW_TYPE: &str = <files_show::Payload as Payload>::TYPE_URI;
pub(crate) const FILES_LIST_TYPE: &str = <files_list::Payload as Payload>::TYPE_URI;
pub(crate) const FILES_DELETE_TYPE: &str = <files_delete::Payload as Payload>::TYPE_URI;
pub(crate) const GENERATIONS_LIST_TYPE: &str = <generations_list::Payload as Payload>::TYPE_URI;
pub(crate) const ROLLBACK_TYPE: &str = <rollback::Payload as Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[
    BEGIN_TYPE,
    CHUNK_TYPE,
    COMMIT_TYPE,
    ABORT_TYPE,
    DEPLOY_TYPE,
    FILES_SHOW_TYPE,
    FILES_LIST_TYPE,
    FILES_DELETE_TYPE,
    GENERATIONS_LIST_TYPE,
    ROLLBACK_TYPE,
];

/// The largest chunk an upload may use, and the largest range a read returns.
pub(crate) const MAX_CHUNK_SIZE: u64 = 256 * 1024;

// ─── the codes these tasks declare ───────────────────────────────────────

pub(crate) const BEGIN_ERR_NOT_CONFIGURED: &str = upload_begin::error_codes::NOT_CONFIGURED.code;
pub(crate) const BEGIN_ERR_TOO_LARGE: &str = upload_begin::error_codes::TOO_LARGE.code;
pub(crate) const BEGIN_ERR_PATH_REFUSED: &str = upload_begin::error_codes::PATH_REFUSED.code;
pub(crate) const BEGIN_ERR_SINGLE_FILE_WRITES_DISABLED: &str =
    upload_begin::error_codes::SINGLE_FILE_WRITES_DISABLED.code;
pub(crate) const BEGIN_ERR_INVALID_MANIFEST: &str =
    upload_begin::error_codes::INVALID_MANIFEST.code;
pub(crate) const CHUNK_ERR_NOT_FOUND: &str = upload_chunk::error_codes::NOT_FOUND.code;
pub(crate) const CHUNK_ERR_CHUNK_OUT_OF_RANGE: &str =
    upload_chunk::error_codes::CHUNK_OUT_OF_RANGE.code;
pub(crate) const CHUNK_ERR_CHUNK_MISMATCH: &str = upload_chunk::error_codes::CHUNK_MISMATCH.code;
pub(crate) const COMMIT_ERR_NOT_FOUND: &str = upload_commit::error_codes::NOT_FOUND.code;
pub(crate) const COMMIT_ERR_INCOMPLETE: &str = upload_commit::error_codes::INCOMPLETE.code;
pub(crate) const COMMIT_ERR_DIGEST_MISMATCH: &str =
    upload_commit::error_codes::DIGEST_MISMATCH.code;
pub(crate) const COMMIT_ERR_PRECONDITION_FAILED: &str =
    upload_commit::error_codes::PRECONDITION_FAILED.code;
pub(crate) const COMMIT_ERR_PATH_REFUSED: &str = upload_commit::error_codes::PATH_REFUSED.code;
pub(crate) const COMMIT_ERR_SINGLE_FILE_WRITES_DISABLED: &str =
    upload_commit::error_codes::SINGLE_FILE_WRITES_DISABLED.code;
pub(crate) const ABORT_ERR_NOT_FOUND: &str = upload_abort::error_codes::NOT_FOUND.code;
pub(crate) const DEPLOY_ERR_NOT_FOUND: &str = deploy::error_codes::NOT_FOUND.code;
pub(crate) const DEPLOY_ERR_BUNDLE_REFUSED: &str = deploy::error_codes::BUNDLE_REFUSED.code;
pub(crate) const SHOW_ERR_NOT_FOUND: &str = files_show::error_codes::NOT_FOUND.code;
pub(crate) const SHOW_ERR_PATH_REFUSED: &str = files_show::error_codes::PATH_REFUSED.code;
pub(crate) const SHOW_ERR_CHANGED: &str = files_show::error_codes::CHANGED.code;
pub(crate) const SHOW_ERR_RANGE_OUT_OF_BOUNDS: &str =
    files_show::error_codes::RANGE_OUT_OF_BOUNDS.code;
// `files/delete`'s, `generations/list`'s and `rollback`'s declared codes are
// used where they are raised — inside `routes::website::{files::delete,
// generations::{list,rollback}}` — and not read again here, so they stay
// `pub const` there rather than growing a second binding this module never
// reads.

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    // The website is part of the community's public surface
    // (`vtc.surface.admin`, vtc-admin-roles.md §4).
    let actor =
        match super::capable_signer(state, ctx, &doc, crate::acl::Capability::SurfaceAdmin, None)
            .await
        {
            Ok(a) => a.did,
            Err(reject) => return Some(reject),
        };
    Some(match type_uri {
        BEGIN_TYPE => handle_begin(state, &actor, doc).await,
        CHUNK_TYPE => handle_chunk(state, &actor, doc).await,
        COMMIT_TYPE => handle_commit(state, &actor, doc).await,
        ABORT_TYPE => handle_abort(state, &actor, doc).await,
        DEPLOY_TYPE => handle_deploy(state, &actor, doc).await,
        FILES_SHOW_TYPE => handle_files_show(state, doc).await,
        FILES_LIST_TYPE => handle_files_list(state, doc).await,
        FILES_DELETE_TYPE => handle_files_delete(state, &actor, doc).await,
        GENERATIONS_LIST_TYPE => handle_generations_list(state, doc).await,
        ROLLBACK_TYPE => handle_rollback(state, &actor, doc).await,
        _ => return None,
    })
}

// ─── the upload's own record ─────────────────────────────────────────────

/// What an upload is for, recorded at `begin` beside its transfer slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadRecord {
    upload_id: Uuid,
    owner: String,
    target: Target,
    phase: Phase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum Target {
    File {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        if_match: Option<String>,
    },
    Bundle,
}

impl Target {
    fn wire(&self) -> Value {
        match self {
            Self::File { path, if_match } => {
                let mut v = json!({ "kind": "file", "path": path });
                if let Some(m) = if_match {
                    v["ifMatch"] = json!(m);
                }
                v
            }
            Self::Bundle => json!({ "kind": "bundle" }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Phase {
    /// Chunks are being sent.
    Open,
    /// A bundle, verified and waiting for `deploy`.
    Staged,
    /// Written or deployed: nothing more moves under it.
    Done,
    Aborted,
}

fn record_key(id: &Uuid) -> String {
    format!("website-upload:{id}")
}

async fn store_record(state: &AppState, r: &UploadRecord) -> Result<(), AppError> {
    state
        .backup_bundles_ks
        .insert(record_key(&r.upload_id), r)
        .await
}

/// The upload `raw` names, if it is one `owner` began. Everything else —
/// malformed, unknown, another identity's — is `None`, so a handle is never
/// an oracle for somebody else's upload.
async fn owned(state: &AppState, owner: &str, raw: &str) -> Result<Option<UploadRecord>, AppError> {
    let Ok(id) = Uuid::parse_str(raw) else {
        return Ok(None);
    };
    Ok(state
        .backup_bundles_ks
        .get::<UploadRecord>(record_key(&id))
        .await?
        .filter(|r| r.owner == owner))
}

/// Drop the records of uploads whose transfer slot is gone or finished — the
/// slot's sweeper collects the bytes, and this keeps the records it leaves
/// behind from accumulating.
async fn collect_records(state: &AppState) -> Result<(), AppError> {
    let rows = state
        .backup_bundles_ks
        .prefix_iter_raw(b"website-upload:".to_vec())
        .await?;
    let now = Utc::now();
    for (key, raw) in rows {
        let Ok(r) = serde_json::from_slice::<UploadRecord>(&raw) else {
            continue;
        };
        let live = match bundle_store::get_bundle(&state.backup_bundles_ks, &r.upload_id).await? {
            Some(b) => !b.state.is_terminal() && b.expires_at > now,
            None => false,
        };
        if !live {
            state.backup_bundles_ks.remove(key).await?;
        }
    }
    Ok(())
}

fn staging_dir(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("website-uploads")
}

/// Finish an upload's transfer slot: its staged bytes go, and it is terminal.
async fn close_slot(state: &AppState, id: &Uuid) -> Result<(), AppError> {
    if let Some(mut b) = bundle_store::get_bundle(&state.backup_bundles_ks, id).await? {
        if let Some(path) = b.blob_path.take() {
            let _ = tokio::fs::remove_file(&path).await;
        }
        b.state = BundleState::ImportCommitted;
        bundle_store::store_bundle(&state.backup_bundles_ks, &b).await?;
    }
    Ok(())
}

// ─── shared ──────────────────────────────────────────────────────────────

fn declared(doc: &TrustTask<Value>, code: &str, message: impl Into<String>) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, None)
}

/// The website settings a task reads, or `notConfigured`.
struct Site {
    root_dir: std::path::PathBuf,
    data_dir: std::path::PathBuf,
    blocklist: Vec<String>,
    managed: bool,
    max_file: u64,
    max_bundle: u64,
}

async fn site(state: &AppState) -> Option<Site> {
    let cfg = state.config.read().await;
    Some(Site {
        root_dir: cfg.website.root_dir.clone()?,
        data_dir: cfg.store.data_dir.clone(),
        blocklist: cfg.website.executable_blocklist.clone(),
        managed: cfg.website.deploy_mode == "managed",
        max_file: cfg.website.max_file_size_mb.saturating_mul(1024 * 1024),
        max_bundle: cfg.website.max_bundle_size_mb.saturating_mul(1024 * 1024),
    })
}

impl Site {
    /// The directory the public read handler serves.
    fn serve_root(&self) -> std::path::PathBuf {
        if self.managed {
            self.root_dir.join("current")
        } else {
            self.root_dir.clone()
        }
    }
}

fn chunked_reject(doc: &TrustTask<Value>, err: ChunkedError, not_found: &str) -> TrustTaskOutcome {
    match err {
        ChunkedError::NotFound | ChunkedError::TerminalState(_) => {
            declared(doc, not_found, "no open upload with that id")
        }
        ChunkedError::RateLimited { retry_after_secs } => reject_with(
            doc,
            RejectReason::Unavailable {
                retry_after: Some(Utc::now() + chrono::Duration::seconds(retry_after_secs as i64)),
            },
        ),
        ChunkedError::App(e) => app_error_to_reject(doc, &e),
        other => reject_with(
            doc,
            RejectReason::MalformedRequest {
                reason: other.to_string(),
            },
        ),
    }
}

// ─── begin ───────────────────────────────────────────────────────────────

async fn handle_begin(state: &AppState, actor: &str, doc: TrustTask<Value>) -> TrustTaskOutcome {
    if let Err(reject) = parse_spec_payload::<upload_begin::Payload>(&doc) {
        return reject;
    }
    let p = &doc.payload;
    let Some(site) = site(state).await else {
        return declared(
            &doc,
            BEGIN_ERR_NOT_CONFIGURED,
            "this community serves no website",
        );
    };
    let target = match (
        p["target"]["kind"].as_str(),
        p["target"]["path"].as_str(),
        p["target"]["ifMatch"].as_str(),
    ) {
        (Some("file"), Some(path), if_match) => Target::File {
            path: path.to_string(),
            if_match: if_match.map(str::to_string),
        },
        (Some("bundle"), None, None) => Target::Bundle,
        _ => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: "a `file` target names a `path`; a `bundle` target names neither \
                             `path` nor `ifMatch`"
                        .into(),
                },
            );
        }
    };
    let size = p["expectedSizeBytes"].as_u64().unwrap_or(0);
    let max = match target {
        Target::File { .. } => site.max_file,
        Target::Bundle => site.max_bundle,
    };
    if size > max {
        return declared(
            &doc,
            BEGIN_ERR_TOO_LARGE,
            format!("{size} bytes is more than this community accepts ({max})"),
        );
    }
    if let Target::File { path, .. } = &target {
        if site.managed {
            return declared(
                &doc,
                BEGIN_ERR_SINGLE_FILE_WRITES_DISABLED,
                "this site is in managed deploy mode; upload a bundle and deploy it",
            );
        }
        if canonical_within_root_for_create(
            &site.root_dir,
            &format!("/{}", path.trim_start_matches('/')),
            &site.blocklist,
        )
        .is_err()
        {
            return declared(
                &doc,
                BEGIN_ERR_PATH_REFUSED,
                format!("the site would not serve `{path}`"),
            );
        }
    }
    let chunk_size = p["chunks"]["chunkSize"].as_u64().unwrap_or(0);
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return declared(
            &doc,
            BEGIN_ERR_INVALID_MANIFEST,
            format!("chunkSize must be between 1 and {MAX_CHUNK_SIZE} bytes"),
        );
    }
    let digests: Vec<String> = p["chunks"]["chunkDigests"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|d| d.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    if let Err(e) = collect_records(state).await {
        return app_error_to_reject(&doc, &e);
    }
    let slot = match chunked::initiate_import_for(
        &state.backup_bundles_ks,
        actor,
        p["expectedSha256"].as_str().unwrap_or_default(),
        size,
        chunk_size,
        p["chunks"]["chunkCount"].as_u64().unwrap_or(0),
        digests,
    )
    .await
    {
        Ok(s) => s,
        Err(ChunkedError::InvalidManifest(why)) => {
            return declared(&doc, BEGIN_ERR_INVALID_MANIFEST, why);
        }
        Err(e) => return chunked_reject(&doc, e, BEGIN_ERR_INVALID_MANIFEST),
    };
    let record = UploadRecord {
        upload_id: slot.bundle_id,
        owner: actor.to_string(),
        target,
        phase: Phase::Open,
    };
    if let Err(e) = store_record(state, &record).await {
        return app_error_to_reject(&doc, &e);
    }
    success_response(
        &doc,
        json!({ "uploadId": slot.bundle_id, "expiresAt": slot.expires_at }),
    )
}

// ─── chunk ───────────────────────────────────────────────────────────────

async fn handle_chunk(state: &AppState, actor: &str, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let req: upload_chunk::Payload = match parse_spec_payload(&doc) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let upload_id = req.upload_id.to_string();
    match owned(state, actor, &upload_id).await {
        Ok(Some(r)) if r.phase == Phase::Open => {}
        Ok(_) => return declared(&doc, CHUNK_ERR_NOT_FOUND, "no open upload with that id"),
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    let Some(site) = site(state).await else {
        return declared(&doc, CHUNK_ERR_NOT_FOUND, "no open upload with that id");
    };
    let data = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(req.data.as_str()) {
        Ok(d) => d,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("`data` is not base64url: {e}"),
                },
            );
        }
    };
    let index = req.index.0.max(0) as u64;
    match chunked::put_chunk_for(
        &state.backup_bundles_ks,
        &staging_dir(&site.data_dir),
        ChunkRateLimiter::global(),
        actor,
        ChunkWrite {
            bundle_id: &upload_id,
            index,
            digest_multibase: req.digest_multibase.as_str(),
            data: &data,
        },
    )
    .await
    {
        Ok(o) => success_response(
            &doc,
            json!({
                "uploadId": upload_id,
                "index": index,
                "stored": o.stored,
                "remainingCount": o.remaining_count,
                "expiresAt": o.expires_at,
            }),
        ),
        Err(ChunkedError::ChunkOutOfRange { index, chunk_count }) => declared(
            &doc,
            CHUNK_ERR_CHUNK_OUT_OF_RANGE,
            format!("chunk {index} is not below the chunk count {chunk_count}"),
        ),
        Err(e @ (ChunkedError::DigestMismatch { .. } | ChunkedError::ChunkSizeMismatch { .. })) => {
            declared(&doc, CHUNK_ERR_CHUNK_MISMATCH, e.to_string())
        }
        Err(e) => chunked_reject(&doc, e, CHUNK_ERR_NOT_FOUND),
    }
}

// ─── commit ──────────────────────────────────────────────────────────────

async fn handle_commit(state: &AppState, actor: &str, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let req: upload_commit::Payload = match parse_spec_payload(&doc) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let upload_id = req.upload_id.to_string();
    let mut record = match owned(state, actor, &upload_id).await {
        Ok(Some(r)) if r.phase == Phase::Open => r,
        Ok(_) => return declared(&doc, COMMIT_ERR_NOT_FOUND, "no open upload with that id"),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    match chunked::finalize_precheck_for(&state.backup_bundles_ks, actor, &upload_id).await {
        Ok(()) => {}
        Err(ChunkedError::IncompleteUpload {
            missing_count,
            missing_indices,
        }) => {
            return reject_with_code(
                &doc,
                extended_code(COMMIT_ERR_INCOMPLETE),
                format!("{missing_count} chunk(s) have not been sent"),
                Some(json!({ "missingCount": missing_count, "missingIndices": missing_indices })),
            );
        }
        Err(ChunkedError::BundleDigestMismatch) => {
            // The committed hash is what the content was promised to be; the
            // upload is discarded rather than left to be completed differently.
            let _ = vti_common::backup_transfer::abort(
                &state.backup_bundles_ks,
                actor,
                &record.upload_id,
            )
            .await;
            record.phase = Phase::Aborted;
            let _ = store_record(state, &record).await;
            return declared(
                &doc,
                COMMIT_ERR_DIGEST_MISMATCH,
                "the reassembled content is not the committed SHA-256; the upload is discarded",
            );
        }
        Err(e) => return chunked_reject(&doc, e, COMMIT_ERR_NOT_FOUND),
    }
    let slot = match bundle_store::get_bundle(&state.backup_bundles_ks, &record.upload_id).await {
        Ok(Some(b)) => b,
        Ok(None) => return declared(&doc, COMMIT_ERR_NOT_FOUND, "no open upload with that id"),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let base = json!({
        "uploadId": upload_id,
        "target": record.target.wire(),
        "sha256": slot.expected_sha256,
        "sizeBytes": slot.expected_size_bytes,
    });

    match record.target.clone() {
        Target::Bundle => {
            record.phase = Phase::Staged;
            if let Err(e) = store_record(state, &record).await {
                return app_error_to_reject(&doc, &e);
            }
            let mut body = base;
            body["stagedUntil"] = json!(slot.expires_at);
            success_response(&doc, body)
        }
        Target::File { path, if_match } => {
            let Some(site) = site(state).await else {
                return declared(&doc, COMMIT_ERR_NOT_FOUND, "no open upload with that id");
            };
            if site.managed {
                return declared(
                    &doc,
                    COMMIT_ERR_SINGLE_FILE_WRITES_DISABLED,
                    "this site is in managed deploy mode; upload a bundle and deploy it",
                );
            }
            let Some(blob) = slot.blob_path.clone() else {
                return declared(&doc, COMMIT_ERR_NOT_FOUND, "no open upload with that id");
            };
            let bytes = match tokio::fs::read(&blob).await {
                Ok(b) => b,
                Err(e) => return app_error_to_reject(&doc, &AppError::Io(e)),
            };
            match crate::routes::website::files::write_file(
                state,
                actor,
                &path,
                if_match.as_deref(),
                &bytes,
            )
            .await
            {
                Ok(written) => {
                    record.phase = Phase::Done;
                    if let Err(e) = store_record(state, &record).await {
                        return app_error_to_reject(&doc, &e);
                    }
                    if let Err(e) = close_slot(state, &record.upload_id).await {
                        return app_error_to_reject(&doc, &e);
                    }
                    let mut body = base;
                    body["file"] = json!({
                        "path": written.path,
                        "etag": written.etag.trim_matches('"'),
                        "sizeBytes": written.size_bytes,
                    });
                    success_response(&doc, body)
                }
                Err(crate::routes::website::files::WriteError::Precondition(m)) => {
                    declared(&doc, COMMIT_ERR_PRECONDITION_FAILED, m)
                }
                Err(crate::routes::website::files::WriteError::Path(m)) => {
                    declared(&doc, COMMIT_ERR_PATH_REFUSED, m)
                }
                Err(crate::routes::website::files::WriteError::App(e)) => {
                    app_error_to_reject(&doc, &e)
                }
            }
        }
    }
}

// ─── abort ───────────────────────────────────────────────────────────────

async fn handle_abort(state: &AppState, actor: &str, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let req: upload_abort::Payload = match parse_spec_payload(&doc) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let upload_id = req.upload_id.to_string();
    let mut record = match owned(state, actor, &upload_id).await {
        Ok(Some(r)) if r.phase != Phase::Done => r,
        Ok(_) => return declared(&doc, ABORT_ERR_NOT_FOUND, "no upload with that id"),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if record.phase == Phase::Aborted {
        return success_response(&doc, json!({ "uploadId": upload_id, "aborted": false }));
    }
    if let Err(e) =
        vti_common::backup_transfer::abort(&state.backup_bundles_ks, actor, &record.upload_id).await
        && !matches!(e, AppError::NotFound(_))
    {
        return app_error_to_reject(&doc, &e);
    }
    record.phase = Phase::Aborted;
    if let Err(e) = store_record(state, &record).await {
        return app_error_to_reject(&doc, &e);
    }
    success_response(&doc, json!({ "uploadId": upload_id, "aborted": true }))
}

// ─── deploy ──────────────────────────────────────────────────────────────

async fn handle_deploy(state: &AppState, actor: &str, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let req: deploy::Payload = match parse_spec_payload(&doc) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let upload_id = req.upload_id.to_string();
    let not_found = |doc: &TrustTask<Value>| {
        declared(
            doc,
            DEPLOY_ERR_NOT_FOUND,
            "no staged bundle upload with that id",
        )
    };
    let mut record = match owned(state, actor, &upload_id).await {
        Ok(Some(r)) if r.phase == Phase::Staged && matches!(r.target, Target::Bundle) => r,
        Ok(_) => return not_found(&doc),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let slot = match bundle_store::get_bundle(&state.backup_bundles_ks, &record.upload_id).await {
        Ok(Some(b)) if !b.state.is_terminal() && b.expires_at > Utc::now() => b,
        Ok(_) => return not_found(&doc),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let Some(blob) = slot.blob_path.clone() else {
        return not_found(&doc);
    };
    let bytes = match tokio::fs::read(&blob).await {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(&doc, &AppError::Io(e)),
    };
    // Checked once more: the staged file is this service's own, but it is
    // what the whole-content hash promised only if nothing touched it since.
    if hex::encode(Sha256::digest(&bytes)) != slot.expected_sha256 {
        return declared(
            &doc,
            DEPLOY_ERR_BUNDLE_REFUSED,
            "the staged bundle no longer matches its committed SHA-256",
        );
    }
    match crate::routes::website::deploy::deploy_inner(state, actor, &bytes).await {
        Ok(response) => {
            record.phase = Phase::Done;
            if let Err(e) = store_record(state, &record).await {
                return app_error_to_reject(&doc, &e);
            }
            if let Err(e) = close_slot(state, &record.upload_id).await {
                return app_error_to_reject(&doc, &e);
            }
            success_response(&doc, response)
        }
        Err(AppError::Validation(m)) => declared(&doc, DEPLOY_ERR_BUNDLE_REFUSED, m),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── files/show ──────────────────────────────────────────────────────────

async fn handle_files_show(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    if let Err(reject) = parse_spec_payload::<files_show::Payload>(&doc) {
        return reject;
    }
    let p = &doc.payload;
    let path = p["path"].as_str().unwrap_or_default().to_string();
    let Some(site) = site(state).await else {
        return declared(&doc, SHOW_ERR_NOT_FOUND, format!("no such file: {path}"));
    };
    let resolved = match canonical_within_root(
        &site.serve_root(),
        &format!("/{}", path.trim_start_matches('/')),
        &site.blocklist,
    ) {
        Ok(r) => r,
        Err(PathError::NotFound) => {
            return declared(&doc, SHOW_ERR_NOT_FOUND, format!("no such file: {path}"));
        }
        Err(_) => {
            return declared(
                &doc,
                SHOW_ERR_PATH_REFUSED,
                format!("the site would not serve `{path}`"),
            );
        }
    };
    let bytes = match tokio::fs::read(&resolved).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return declared(&doc, SHOW_ERR_NOT_FOUND, format!("no such file: {path}"));
        }
        Err(e) => return app_error_to_reject(&doc, &AppError::Io(e)),
    };
    let etag = hex::encode(Sha256::digest(&bytes));
    if let Some(m) = p["ifMatch"].as_str()
        && m != etag
    {
        return declared(
            &doc,
            SHOW_ERR_CHANGED,
            format!("`{path}` has changed since {m}"),
        );
    }
    let size = bytes.len() as u64;
    let offset = p["offset"].as_u64().unwrap_or(0);
    if offset > size {
        return declared(
            &doc,
            SHOW_ERR_RANGE_OUT_OF_BOUNDS,
            format!("offset {offset} is past the file's {size} bytes"),
        );
    }
    let length = p["length"]
        .as_u64()
        .unwrap_or(MAX_CHUNK_SIZE)
        .min(MAX_CHUNK_SIZE);
    let end = offset.saturating_add(length).min(size);
    let range = &bytes[offset as usize..end as usize];
    let content_type = mime_guess::from_path(&resolved)
        .first_or_octet_stream()
        .to_string();
    success_response(
        &doc,
        json!({
            "path": path,
            "etag": etag,
            "sizeBytes": size,
            "contentType": content_type,
            "offset": offset,
            "data": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(range),
            "complete": end == size,
        }),
    )
}

// ─── files/list, files/delete, generations/list, rollback ───────────────

/// `vtc/website/files/list/0.1` — the paginated listing
/// `GET /v1/website/files` used to serve.
async fn handle_files_list(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let payload: files_list::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let cursor = payload.cursor.map(|c| c.to_string());
    let limit = payload.limit.map(|n| n.get() as u32);
    match crate::routes::website::files::list(state, cursor, limit).await {
        Ok(resp) => success_response(&doc, resp),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/website/files/delete/0.1` — the delete `DELETE /v1/website/files/
/// {*path}` used to serve.
async fn handle_files_delete(
    state: &AppState,
    actor: &str,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let payload: files_delete::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let path = payload.path.to_string();
    match crate::routes::website::files::delete(state, actor, path).await {
        Ok(resp) => success_response(&doc, resp),
        Err(e) => super::helpers::task_error_to_reject(&doc, &e),
    }
}

/// `vtc/website/generations/list/0.1` — the managed-mode generation history
/// `GET /v1/website/generations` used to serve.
async fn handle_generations_list(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    if let Err(reject) = parse_spec_payload::<generations_list::Payload>(&doc) {
        return reject;
    }
    match crate::routes::website::generations::list(state).await {
        Ok(resp) => success_response(&doc, resp),
        Err(e) => super::helpers::task_error_to_reject(&doc, &e),
    }
}

/// `vtc/website/rollback/0.1` — the managed-mode rollback
/// `POST /v1/website/rollback/{gen_num}` used to serve. `generation` is a
/// decimal string, matching the wire convention `routes::website::
/// generations` already established (not `gen-N`, the directory name).
async fn handle_rollback(state: &AppState, actor: &str, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let payload: rollback::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let Ok(gen_num) = payload.generation.parse::<u32>() else {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: format!(
                    "`{}` is not a generation number",
                    payload.generation.as_str()
                ),
            },
        );
    };
    match crate::routes::website::generations::rollback(state, actor, gen_num).await {
        Ok(resp) => success_response(&doc, resp),
        Err(e) => super::helpers::task_error_to_reject(&doc, &e),
    }
}
