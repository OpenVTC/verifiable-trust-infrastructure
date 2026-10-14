//! Room files on this community's host: the `rooms/blobs/*` tasks, `rooms/info` and
//! `rooms/records/{put,get,list}` 0.2 (`docs/05-design-notes/data-rooms-files.md` §5–§6).
//!
//! What each task does is [`vti_rooms::blob_tasks`], shared with `room-host` so the two
//! hosts cannot answer one task two ways. What stays here is this service's side of it:
//! dispatch on the generated payload type, the chain verified with this service's verifier,
//! and the reply rendered the way every other task here renders one.
//!
//! The VTC holds ciphertext only. A file's key is derived in the member's VTA and never
//! reaches a host, and nothing here could use one.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;
use trust_tasks_rs::specs::rooms::blobs::chunk::v0_1 as download_chunk;
use trust_tasks_rs::specs::rooms::blobs::get::v0_1 as blob_get;
use trust_tasks_rs::specs::rooms::blobs::upload::{
    abort::v0_1 as upload_abort, begin::v0_1 as upload_begin, chunk::v0_1 as upload_chunk,
    commit::v0_1 as upload_commit,
};
use trust_tasks_rs::specs::rooms::info::v0_1 as rooms_info;
use trust_tasks_rs::specs::rooms::records::{
    get::v0_2 as get_v2, list::v0_2 as list_v2, put::v0_2 as put_v2,
};
use trust_tasks_rs::specs::rooms::usage::v0_1 as rooms_usage;
use trust_tasks_rs::{RejectReason, TrustTask};
use vti_common::error::AppError;
use vti_common::store::Store;
use vti_rooms::authz::{self, Action, AuthorizedAction};
use vti_rooms::blob_tasks::{self, Refusal, TaskResult};
use vti_rooms::blobs::BlobHost;
use vti_rooms::wire::{AuthorityPresentation, GetRecordBody, ListRecordsBody, PutRecordBody};
use vti_rooms::{Room, storage};

use super::handlers::{RoomCtx, now, presenter_and_verifier};
use super::storage_configs::RoomStorage;
use crate::config::RoomFilesConfig;
use crate::store::keyspaces;
use crate::trust_tasks::helpers::{
    TrustTaskOutcome, app_error_to_reject, declared_code, reject_with, reject_with_code,
    success_response,
};

/// Open this community's storage configs (`[rooms.files]`, §7): the `local` config is
/// seeded from `blob_dir` (default `<data_dir>/room-blobs`) on first start, and a
/// `local` root may be placed only beneath `local_storage_bases` (default
/// `<data_dir>/room-storage`).
pub async fn open_room_storage(
    store: &Store,
    data_dir: &Path,
    config: &RoomFilesConfig,
    community_did: Option<&str>,
) -> Result<Arc<RoomStorage>, AppError> {
    // A storage config's `root` is absolute (`vtc/_shared/0.1/room-storage`), and a
    // relative `[store] data_dir` is ordinary, so a root derived from it, or a
    // `blob_dir` given relative, is resolved against the directory the store itself
    // was opened from. Left relative, the seeded config fails its own schema check
    // and the community does not start.
    let cwd = std::env::current_dir().map_err(AppError::Io)?;
    let seed_root = absolute_dir(
        config
            .blob_dir
            .clone()
            .unwrap_or_else(|| data_dir.join("room-blobs")),
        &cwd,
    )
    .await?;
    // Explicit bases stay as given: they must be absolute, and are refused otherwise.
    let bases = if config.local_storage_bases.is_empty() {
        vec![absolute_dir(data_dir.join("room-storage"), &cwd).await?]
    } else {
        config.local_storage_bases.clone()
    };
    RoomStorage::open(
        store.keyspace(keyspaces::STORAGE_CONFIGS)?,
        &store.keyspace(keyspaces::ROOMS)?,
        seed_root,
        bases,
        community_did,
    )
    .await
}

/// `path` as an absolute directory: unchanged when it already is one, and otherwise
/// created beneath `cwd` and resolved, so it carries no `.` or `..`.
async fn absolute_dir(path: PathBuf, cwd: &Path) -> Result<PathBuf, AppError> {
    if path.is_absolute() {
        return Ok(path);
    }
    let joined = cwd.join(path);
    tokio::fs::create_dir_all(&joined)
        .await
        .map_err(AppError::Io)?;
    std::fs::canonicalize(&joined).map_err(AppError::Io)
}

/// Open the room-file host over this service's store, from `[rooms.files]`, storing
/// committed blobs in the configs `storage` holds. Staging sits under the data directory.
pub fn open_blob_host(
    store: &Store,
    data_dir: &Path,
    config: &RoomFilesConfig,
    storage: Arc<RoomStorage>,
) -> Result<BlobHost, AppError> {
    Ok(BlobHost::new(
        store.keyspace(keyspaces::ROOM_BLOBS)?,
        store.keyspace(keyspaces::ROOM_BLOB_TRANSFERS)?,
        data_dir.join("room-blob-staging"),
        storage,
        config.limits(),
    ))
}

/// Collect deleted, orphaned-past-grace and abandoned files every `interval_secs`, and
/// retire each `draining` storage config once its last blob is gone.
pub(crate) fn spawn_sweeper(
    files: Arc<BlobHost>,
    storage: Arc<RoomStorage>,
    interval_secs: u64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let interval = std::time::Duration::from_secs(interval_secs.max(1));
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(interval) => {}
            }
            match files.sweep().await {
                Ok(stats) if stats.collected + stats.released + stats.forgotten > 0 => {
                    tracing::info!(
                        collected = stats.collected,
                        released = stats.released,
                        forgotten = stats.forgotten,
                        "room files swept"
                    );
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "room file sweep failed"),
            }
            let settled = match files.config_holdings().await {
                Ok(holdings) => storage.settle_draining(&holdings).await,
                Err(e) => Err(e),
            };
            if let Err(e) = settled {
                tracing::warn!(error = %e, "draining storage configs not settled");
            }
        }
    });
}

/// Render a shared refusal as this service's reply.
pub(super) fn refused<P>(doc: &TrustTask<P>, refusal: Refusal) -> TrustTaskOutcome {
    match refusal {
        Refusal::Declared {
            code,
            message,
            details,
        } => reject_with_code(doc, declared_code(code.code), message, details),
        Refusal::Malformed(reason) => reject_with(doc, RejectReason::MalformedRequest { reason }),
        Refusal::Unavailable { retry_after_secs } => reject_with(
            doc,
            RejectReason::Unavailable {
                retry_after: Some(
                    chrono::Utc::now() + chrono::Duration::seconds(retry_after_secs as i64),
                ),
            },
        ),
        Refusal::TaskFailed(reason) => reject_with(
            doc,
            RejectReason::TaskFailed {
                reason,
                details: None,
            },
        ),
        Refusal::App(e) => app_error_to_reject(doc, &e),
        Refusal::Internal(reason) => reject_with(doc, RejectReason::InternalError { reason }),
    }
}

/// Render a shared task's answer as this service's reply.
pub(super) fn render<P>(doc: &TrustTask<P>, result: TaskResult) -> TrustTaskOutcome {
    match result {
        Ok(body) => success_response(doc, body),
        Err(r) => refused(doc, r),
    }
}

/// The payload as JSON, for the shared layer, which reads it member by member.
fn payload_json<P: serde::Serialize>(doc: &TrustTask<P>) -> Result<Value, TrustTaskOutcome> {
    serde_json::to_value(&doc.payload)
        .map_err(|e| app_error_to_reject(doc, &AppError::Serialization(e)))
}

/// Read the presentation and room, verify the chain for `action`, and return the room and
/// the authorization.
///
/// A chain that does not confer `action` is the framework's standard `permissionDenied`, as
/// for every `rooms/*` task: the family declares no task-specific code that would shadow it.
async fn authorize<P>(
    doc: &TrustTask<P>,
    ctx: &RoomCtx,
    payload: &Value,
    action: Action,
) -> Result<(Room, AuthorizedAction), TrustTaskOutcome> {
    let presentation: AuthorityPresentation =
        serde_json::from_value(payload["presentation"].clone()).map_err(|e| {
            reject_with(
                doc,
                RejectReason::MalformedRequest {
                    reason: format!("presentation: {e}"),
                },
            )
        })?;
    let room_id = payload["roomId"].as_str().unwrap_or_default();
    let room = storage::get_room(&ctx.state.rooms_ks, room_id)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    let (presenter, verifier) = presenter_and_verifier(&ctx.state, &ctx.presenter);
    let authorized = authz::authorize(&room, &presentation, action, &presenter, now(), &verifier)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    Ok((room, authorized))
}

/// The 0.1 request a 0.2 one carries, read as the 0.1 body type.
fn as_v0_1<P, B: serde::de::DeserializeOwned>(
    doc: &TrustTask<P>,
    payload: Value,
) -> Result<B, TrustTaskOutcome> {
    serde_json::from_value(blob_tasks::as_v0_1(payload)).map_err(|e| {
        reject_with(
            doc,
            RejectReason::MalformedRequest {
                reason: e.to_string(),
            },
        )
    })
}

/// `rooms/records/put/0.2`: a record that may name blobs committed in its room.
pub(crate) async fn handle_put_record_v2(
    doc: TrustTask<put_v2::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let blobs = match blob_tasks::put_v2_blobs(&payload) {
        Ok(b) => b,
        Err(r) => return refused(&doc, r),
    };
    let req: PutRecordBody = match as_v0_1(&doc, payload) {
        Ok(r) => r,
        Err(o) => return o,
    };
    super::handlers::put_record(&doc, &ctx, req, blobs).await
}

/// `rooms/records/get/0.2`: the 0.1 read, whose answer also names the record's blobs.
pub(crate) async fn handle_get_record_v2(
    doc: TrustTask<get_v2::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let req: GetRecordBody = match payload_json(&doc).and_then(|p| as_v0_1(&doc, p)) {
        Ok(r) => r,
        Err(o) => return o,
    };
    super::handlers::get_record(&doc, &ctx, req, true).await
}

/// `rooms/records/list/0.2`: the 0.1 listing, each row naming its blobs.
pub(crate) async fn handle_list_records_v2(
    doc: TrustTask<list_v2::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let req: ListRecordsBody = match payload_json(&doc).and_then(|p| as_v0_1(&doc, p)) {
        Ok(r) => r,
        Err(o) => return o,
    };
    super::handlers::list_records(&doc, &ctx, req, true).await
}

/// `rooms/blobs/upload/begin/0.1`. Needs `write`.
pub(crate) async fn handle_upload_begin(
    doc: TrustTask<upload_begin::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let (room, authorized) = match authorize(&doc, &ctx, &payload, Action::Write).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    render(
        &doc,
        blob_tasks::begin(
            &ctx.state.room_files,
            &room,
            &ctx.presenter,
            &authorized,
            &payload,
        )
        .await,
    )
}

/// `rooms/blobs/upload/chunk/0.1`. Authorized by owning the upload.
pub(crate) async fn handle_upload_chunk(
    doc: TrustTask<upload_chunk::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    match payload_json(&doc) {
        Ok(p) => render(
            &doc,
            blob_tasks::upload_chunk(&ctx.state.room_files, &ctx.presenter, &p).await,
        ),
        Err(o) => o,
    }
}

/// `rooms/blobs/upload/commit/0.1`. Authorized by owning the upload.
pub(crate) async fn handle_upload_commit(
    doc: TrustTask<upload_commit::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    match payload_json(&doc) {
        Ok(p) => render(
            &doc,
            blob_tasks::commit(&ctx.state.room_files, &ctx.presenter, &p).await,
        ),
        Err(o) => o,
    }
}

/// `rooms/blobs/upload/abort/0.1`. Authorized by owning the upload.
pub(crate) async fn handle_upload_abort(
    doc: TrustTask<upload_abort::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    match payload_json(&doc) {
        Ok(p) => render(
            &doc,
            blob_tasks::abort(&ctx.state.room_files, &ctx.presenter, &p).await,
        ),
        Err(o) => o,
    }
}

/// `rooms/blobs/get/0.1`. Needs `read`.
pub(crate) async fn handle_blob_get(
    doc: TrustTask<blob_get::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let (room, authorized) = match authorize(&doc, &ctx, &payload, Action::Read).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    render(
        &doc,
        blob_tasks::get(
            &ctx.state.room_files,
            &room,
            &ctx.presenter,
            &authorized,
            &payload,
        )
        .await,
    )
}

/// `rooms/blobs/chunk/0.1`. Authorized by owning the download.
pub(crate) async fn handle_download_chunk(
    doc: TrustTask<download_chunk::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    match payload_json(&doc) {
        Ok(p) => render(
            &doc,
            blob_tasks::download_chunk(&ctx.state.room_files, &ctx.presenter, &p).await,
        ),
        Err(o) => o,
    }
}

/// `rooms/usage/0.1`. Needs `admin`: who is using the room's space is the owner's
/// question, not a member's.
pub(crate) async fn handle_usage(
    doc: TrustTask<rooms_usage::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let (room, authorized) = match authorize(&doc, &ctx, &payload, Action::Admin).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    render(
        &doc,
        blob_tasks::usage(&ctx.state.room_files, &room, &authorized, &payload).await,
    )
}

/// `rooms/info/0.1`. Needs `read`.
pub(crate) async fn handle_info(
    doc: TrustTask<rooms_info::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let (room, authorized) = match authorize(&doc, &ctx, &payload, Action::Read).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    render(
        &doc,
        blob_tasks::info(&ctx.state.room_files, &room, &authorized, &payload).await,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A relative `[store] data_dir` is ordinary; the `local` config seeded from it
    /// must still carry the absolute `root` the specification requires.
    #[tokio::test]
    async fn a_relative_blob_dir_is_resolved_against_the_working_directory() {
        let cwd = tempfile::tempdir().unwrap();
        let resolved = absolute_dir(PathBuf::from("data/vtc/room-blobs"), cwd.path())
            .await
            .unwrap();
        assert!(resolved.is_absolute(), "{}", resolved.display());
        assert_eq!(
            resolved,
            std::fs::canonicalize(cwd.path())
                .unwrap()
                .join("data/vtc/room-blobs")
        );
        assert!(resolved.is_dir());

        let with_dots = absolute_dir(PathBuf::from("data/../data/./x"), cwd.path())
            .await
            .unwrap();
        assert!(
            !with_dots.components().any(|c| matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )),
            "{}",
            with_dots.display()
        );
    }

    #[tokio::test]
    async fn an_absolute_blob_dir_is_kept_as_given() {
        let p = PathBuf::from("/srv/vtc/room-blobs");
        assert_eq!(
            absolute_dir(p.clone(), Path::new("/elsewhere"))
                .await
                .unwrap(),
            p
        );
    }

    /// End to end: storage opened over a relative data directory seeds a config
    /// that conforms, rather than refusing to start.
    #[tokio::test]
    async fn storage_opens_over_a_relative_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().join("store"),
        })
        .unwrap();
        // Relative to the test process's working directory, as an operator's
        // `data_dir = "data"` is relative to theirs. Unique, and removed after.
        let rel = PathBuf::from(format!("target/relative-data-{}", uuid::Uuid::new_v4()));
        let storage = open_room_storage(
            &store,
            &rel,
            &RoomFilesConfig::default(),
            Some("did:key:zCommunity"),
        )
        .await;
        let _ = std::fs::remove_dir_all(&rel);
        let storage = storage.expect("a relative data directory opens");
        let local = storage
            .config(super::super::storage_configs::SEED_CONFIG_ID)
            .await
            .unwrap()
            .unwrap();
        assert!(
            local["settings"]["root"].as_str().unwrap().starts_with('/'),
            "{local}"
        );
    }
}
