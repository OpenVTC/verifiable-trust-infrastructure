//! The room-file Trust Tasks, host-neutral: what each task does with a [`BlobHost`], its
//! response, and its declared refusals.
//!
//! Both hosts serve these tasks: `room-host` and the VTC. Each one keeps its own transport,
//! document handling and chain verification, and calls in here once it knows the room, the
//! authenticated presenter and, where the task carries a presentation, what the chain
//! authorized. What comes back is either a response body that already deserializes as the
//! task's **generated** response type, or a [`Refusal`] the host renders in its own reply
//! type. Keeping the mapping here is what stops the two hosts answering one task two ways.
//!
//! The transfer tasks that carry no presentation (`upload/chunk`, `commit`, `abort`, the
//! download `chunk`) are authorized by owning the transfer a verified chain opened, which
//! [`BlobHost`] checks against the presenter, and answer `notFound` to anybody else.

use base64::Engine as _;
use serde_json::{Value, json};
use trust_tasks_rs::DeclaredErrorCode;
use trust_tasks_rs::specs::rooms::blobs::chunk::v0_1 as download_chunk_spec;
use trust_tasks_rs::specs::rooms::blobs::get::v0_1 as blob_get;
use trust_tasks_rs::specs::rooms::blobs::upload::abort::v0_1 as upload_abort;
use trust_tasks_rs::specs::rooms::blobs::upload::begin::v0_1 as upload_begin;
use trust_tasks_rs::specs::rooms::blobs::upload::chunk::v0_1 as upload_chunk_spec;
use trust_tasks_rs::specs::rooms::blobs::upload::commit::v0_1 as upload_commit;
use trust_tasks_rs::specs::rooms::info::v0_1 as rooms_info;
use trust_tasks_rs::specs::rooms::records::get::v0_2 as get_v2;
use trust_tasks_rs::specs::rooms::records::list::v0_2 as list_v2;
use trust_tasks_rs::specs::rooms::records::put::v0_2 as put_v2;
use vti_common::error::AppError;

use crate::authz::AuthorizedAction;
use crate::blobs::{BlobError, BlobHost, Manifest, ReadSnapshot};
use crate::{Room, Visibility};

/// The URIs these tasks are dispatched under, from [`crate::wire`].
pub use crate::wire::{
    ROOMS_BLOBS_CHUNK_TYPE as DOWNLOAD_CHUNK_TYPE, ROOMS_BLOBS_GET_TYPE as BLOB_GET_TYPE,
    ROOMS_BLOBS_UPLOAD_ABORT_TYPE as UPLOAD_ABORT_TYPE,
    ROOMS_BLOBS_UPLOAD_BEGIN_TYPE as UPLOAD_BEGIN_TYPE,
    ROOMS_BLOBS_UPLOAD_CHUNK_TYPE as UPLOAD_CHUNK_TYPE,
    ROOMS_BLOBS_UPLOAD_COMMIT_TYPE as UPLOAD_COMMIT_TYPE, ROOMS_INFO_TYPE as INFO_TYPE,
    ROOMS_RECORDS_GET_V2_TYPE as GET_V2_TYPE, ROOMS_RECORDS_LIST_V2_TYPE as LIST_V2_TYPE,
    ROOMS_RECORDS_PUT_V2_TYPE as PUT_V2_TYPE,
};

/// Why a room-file task was refused, for the host to render as its reply.
#[derive(Debug)]
pub enum Refusal {
    /// A code the task's specification declares.
    Declared {
        code: DeclaredErrorCode,
        message: String,
        details: Option<Value>,
    },
    /// The request is not the task's payload (`malformedRequest`).
    Malformed(String),
    /// Rate-limited: retry after this many seconds (`unavailable`).
    Unavailable { retry_after_secs: u64 },
    /// A resource is exhausted (`taskFailed`).
    TaskFailed(String),
    /// A storage or domain error, rendered by the host as it renders any other.
    App(AppError),
    /// Something this host cannot explain (`internalError`).
    Internal(String),
}

/// A task's answer: a response body for its generated response type, or why not.
pub type TaskResult = Result<Value, Refusal>;

fn declared(
    code: DeclaredErrorCode,
    message: impl Into<String>,
    details: Option<Value>,
) -> Refusal {
    Refusal::Declared {
        code,
        message: message.into(),
        details,
    }
}

/// Parse `payload` as the generated type `P`, or refuse it as malformed.
pub fn parse<P: serde::de::DeserializeOwned>(payload: &Value) -> Result<P, Refusal> {
    serde_json::from_value(payload.clone()).map_err(|e| Refusal::Malformed(e.to_string()))
}

/// `body`, once it reads as the generated response type `R`: the check that what a host
/// sends is the specification's response, not a near miss.
fn checked<R: serde::de::DeserializeOwned>(body: Value) -> TaskResult {
    match serde_json::from_value::<R>(body.clone()) {
        Ok(_) => Ok(body),
        Err(e) => Err(Refusal::Internal(format!(
            "this host built a response its specification refuses: {e}"
        ))),
    }
}

/// What every blob operation can refuse with and no task declares.
fn general(e: BlobError) -> Refusal {
    match e {
        BlobError::RateLimited { retry_after_secs } => Refusal::Unavailable { retry_after_secs },
        BlobError::App(AppError::ResourceExhausted(reason)) => Refusal::TaskFailed(reason),
        BlobError::App(e) => Refusal::App(e),
        other => Refusal::Internal(other.to_string()),
    }
}

/// `rooms/blobs/upload/begin/0.1`, once the chain has been verified for `write`.
pub async fn begin(
    files: &BlobHost,
    room: &Room,
    presenter: &str,
    authorized: &AuthorizedAction,
    payload: &Value,
) -> TaskResult {
    use upload_begin::error_codes as codes;
    parse::<upload_begin::Payload>(payload)?;
    let manifest = Manifest::parse(&payload["manifest"])
        .map_err(|e| declared(codes::INVALID_MANIFEST, e.to_string(), None))?;
    match files
        .begin(room, presenter, authorized.member(), manifest)
        .await
    {
        Ok(b) => {
            let mut body = json!({
                "uploadId": b.upload_id.to_string(),
                "missing": b.missing,
                "expiresAt": b.expires_at,
            });
            if b.already_committed {
                body["alreadyCommitted"] = json!(true);
            }
            checked::<upload_begin::Response>(body)
        }
        Err(e @ BlobError::TooManyUploads { max_open }) => Err(declared(
            codes::TOO_MANY_UPLOADS,
            e.to_string(),
            Some(json!({ "maxOpen": max_open })),
        )),
        Err(BlobError::FilesDisabled) => Err(declared(
            codes::FILES_DISABLED,
            BlobError::FilesDisabled.to_string(),
            None,
        )),
        Err(BlobError::InvalidManifest(why)) => Err(declared(codes::INVALID_MANIFEST, why, None)),
        Err(BlobError::LimitExceeded(l)) => Err(declared(
            codes::LIMIT_EXCEEDED,
            BlobError::LimitExceeded(l.clone()).to_string(),
            Some(l.details()),
        )),
        Err(e) => Err(general(e)),
    }
}

/// `rooms/blobs/upload/chunk/0.1`, from the authenticated `presenter`.
pub async fn upload_chunk(files: &BlobHost, presenter: &str, payload: &Value) -> TaskResult {
    use upload_chunk_spec::error_codes as codes;
    let req: upload_chunk_spec::Payload = parse(payload)?;
    let data = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(req.data.as_str())
        .map_err(|e| Refusal::Malformed(format!("`data` is not base64url: {e}")))?;
    let index = (*req.index).max(0) as u64;
    match files
        .put_chunk(
            presenter,
            req.upload_id.as_str(),
            index,
            req.digest_multibase.as_str(),
            &data,
        )
        .await
    {
        Ok(o) => checked::<upload_chunk_spec::Response>(json!({
            "uploadId": req.upload_id.as_str(),
            "index": index,
            "stored": o.stored,
            "remainingCount": o.remaining_count,
            "expiresAt": o.expires_at,
        })),
        Err(BlobError::NotFound) => Err(declared(
            codes::NOT_FOUND,
            "no open upload with that id",
            None,
        )),
        Err(e @ BlobError::ChunkOutOfRange { .. }) => {
            Err(declared(codes::CHUNK_OUT_OF_RANGE, e.to_string(), None))
        }
        Err(BlobError::ChunkMismatch(why)) => Err(declared(codes::CHUNK_MISMATCH, why, None)),
        Err(e) => Err(general(e)),
    }
}

/// `rooms/blobs/upload/commit/0.1`, from the authenticated `presenter`.
pub async fn commit(files: &BlobHost, presenter: &str, payload: &Value) -> TaskResult {
    use upload_commit::error_codes as codes;
    let req: upload_commit::Payload = parse(payload)?;
    match files.commit(presenter, req.upload_id.as_str()).await {
        Ok(c) => {
            checked::<upload_commit::Response>(json!({ "blobRef": c.blob_ref, "size": c.size }))
        }
        Err(BlobError::NotFound) => Err(declared(codes::NOT_FOUND, "no upload with that id", None)),
        Err(BlobError::Incomplete { remaining_count }) => Err(declared(
            codes::INCOMPLETE,
            format!("{remaining_count} chunk(s) have not been sent"),
            Some(json!({ "remainingCount": remaining_count })),
        )),
        Err(e @ BlobError::DigestMismatch) => {
            Err(declared(codes::DIGEST_MISMATCH, e.to_string(), None))
        }
        Err(e) => Err(general(e)),
    }
}

/// `rooms/blobs/upload/abort/0.1`, from the authenticated `presenter`.
pub async fn abort(files: &BlobHost, presenter: &str, payload: &Value) -> TaskResult {
    use upload_abort::error_codes as codes;
    let req: upload_abort::Payload = parse(payload)?;
    match files.abort(presenter, req.upload_id.as_str()).await {
        Ok(aborted) => checked::<upload_abort::Response>(
            json!({ "uploadId": req.upload_id.as_str(), "aborted": aborted }),
        ),
        Err(BlobError::NotFound) => Err(declared(codes::NOT_FOUND, "no upload with that id", None)),
        Err(e) => Err(general(e)),
    }
}

/// `rooms/blobs/get/0.1`, once the chain has been verified for `read`.
pub async fn get(files: &BlobHost, room: &Room, presenter: &str, payload: &Value) -> TaskResult {
    use blob_get::error_codes as codes;
    let req: blob_get::Payload = parse(payload)?;
    match files
        .open_download(&room.room_id, presenter, req.blob_ref.as_str())
        .await
    {
        Ok(d) => checked::<blob_get::Response>(json!({
            "manifest": d.manifest,
            "downloadId": d.download_id.to_string(),
            "expiresAt": d.expires_at,
        })),
        Err(BlobError::NotFound) => Err(declared(
            codes::NOT_FOUND,
            "no blob with that BlobRef is committed in this room",
            None,
        )),
        Err(e) => Err(general(e)),
    }
}

/// `rooms/blobs/chunk/0.1`, from the authenticated `presenter`.
pub async fn download_chunk(files: &BlobHost, presenter: &str, payload: &Value) -> TaskResult {
    use download_chunk_spec::error_codes as codes;
    let req: download_chunk_spec::Payload = parse(payload)?;
    let index = (*req.index).max(0) as u64;
    match files
        .read_chunk(presenter, req.download_id.as_str(), index)
        .await
    {
        Ok(c) => checked::<download_chunk_spec::Response>(json!({
            "index": index,
            "data": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&c.data),
            "digestMultibase": c.digest_multibase,
        })),
        Err(BlobError::NotFound) => Err(declared(
            codes::NOT_FOUND,
            "no open download with that id",
            None,
        )),
        Err(e @ BlobError::ChunkOutOfRange { .. }) => {
            Err(declared(codes::CHUNK_OUT_OF_RANGE, e.to_string(), None))
        }
        Err(e) => Err(general(e)),
    }
}

/// `rooms/info/0.1`, once the chain has been verified for `read`.
pub async fn info(
    files: &BlobHost,
    room: &Room,
    authorized: &AuthorizedAction,
    payload: &Value,
) -> TaskResult {
    parse::<rooms_info::Payload>(payload)?;
    let limits = files.effective_limits(room);
    let room_usage = files
        .room_usage(&room.room_id)
        .await
        .map_err(Refusal::App)?;
    let mut usage = json!({ "room": room_usage });
    // The presenter's own figures, charged to the member the chain descends
    // from. Never on a `private` room, where the host does not know who asks.
    if room.visibility != Visibility::Private
        && let Some(member) = authorized.member()
    {
        let u = files
            .member_usage(&room.room_id, member)
            .await
            .map_err(Refusal::App)?;
        usage["member"] = json!({ "usage": u, "limits": limits.member });
    }
    checked::<rooms_info::Response>(json!({
        "roomId": room.room_id,
        "visibility": room.visibility,
        "retentionPolicy": room.retention_policy,
        "epoch": room.epoch,
        "limits": {
            "filesEnabled": limits.files_enabled,
            "room": limits.room,
            "member": limits.member,
        },
        "usage": usage,
    }))
}

/// The `blobs` a `rooms/records/put/0.2` names, after checking the payload is that task's.
pub fn put_v2_blobs(payload: &Value) -> Result<Vec<String>, Refusal> {
    let req: put_v2::Payload = parse(payload)?;
    Ok(req
        .blobs
        .unwrap_or_default()
        .iter()
        .map(|b| b.as_str().to_string())
        .collect())
}

/// The members a 0.1 request shares with its 0.2 successor: everything but `blobs` and
/// `ext`, which the 0.1 bodies do not take.
pub fn as_v0_1(mut payload: Value) -> Value {
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("blobs");
        obj.remove("ext");
    }
    payload
}

/// Why `rooms/records/put` 0.2 refused a record's `blobs`, as that task's declared codes.
pub fn record_blobs_refused(e: BlobError) -> Refusal {
    match e {
        BlobError::NotFound => declared(
            put_v2::error_codes::BLOB_NOT_FOUND,
            "a `blobs` entry names no blob committed in this room",
            None,
        ),
        BlobError::LimitExceeded(l) => declared(
            put_v2::error_codes::LIMIT_EXCEEDED,
            BlobError::LimitExceeded(l.clone()).to_string(),
            Some(l.details()),
        ),
        other => general(other),
    }
}

/// A 0.1 get response with `blobs` added, as `rooms/records/get/0.2` answers.
///
/// `blobs` is exactly what the stored version names: absent when it names none, which
/// includes a retraction (which released them) and a 0.1 write.
pub async fn get_v2_response(
    snapshot: &ReadSnapshot<'_>,
    room_id: &str,
    key: &str,
    response: impl serde::Serialize,
) -> TaskResult {
    let mut body =
        serde_json::to_value(response).map_err(|e| Refusal::App(AppError::Serialization(e)))?;
    let blobs = snapshot
        .record_blobs(room_id, key)
        .await
        .map_err(Refusal::App)?;
    if !blobs.is_empty() {
        body["blobs"] = json!(blobs);
    }
    checked::<get_v2::Response>(body)
}

/// A 0.1 listing with each row's `blobs` added, as `rooms/records/list/0.2` answers.
pub async fn list_v2_response(
    snapshot: &ReadSnapshot<'_>,
    room_id: &str,
    response: impl serde::Serialize,
) -> TaskResult {
    let mut body =
        serde_json::to_value(response).map_err(|e| Refusal::App(AppError::Serialization(e)))?;
    if let Some(rows) = body["records"].as_array_mut() {
        for row in rows {
            let Some(key) = row["key"].as_str().map(str::to_string) else {
                continue;
            };
            let blobs = snapshot
                .record_blobs(room_id, &key)
                .await
                .map_err(Refusal::App)?;
            if !blobs.is_empty() {
                row["blobs"] = json!(blobs);
            }
        }
    }
    checked::<list_v2::Response>(body)
}

/// Whether a task is one of these, which a host routes here.
pub fn is_file_task(type_uri: &str) -> bool {
    [
        UPLOAD_BEGIN_TYPE,
        UPLOAD_CHUNK_TYPE,
        UPLOAD_COMMIT_TYPE,
        UPLOAD_ABORT_TYPE,
        BLOB_GET_TYPE,
        DOWNLOAD_CHUNK_TYPE,
        INFO_TYPE,
    ]
    .contains(&type_uri)
}
