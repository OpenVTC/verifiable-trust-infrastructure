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
use vti_common::error::AppError;
use vti_specs_rooms::rooms::blobs::chunk::v0_1 as download_chunk_spec;
use vti_specs_rooms::rooms::blobs::get::v0_2 as blob_get_v2;
use vti_specs_rooms::rooms::blobs::upload::abort::v0_2 as upload_abort_v2;
use vti_specs_rooms::rooms::blobs::upload::begin::v0_2 as upload_begin_v2;
use vti_specs_rooms::rooms::blobs::upload::chunk::v0_2 as upload_chunk_v2;
use vti_specs_rooms::rooms::blobs::upload::commit::v0_2 as upload_commit_v2;
use vti_specs_rooms::rooms::records::get::v0_2 as get_v2;
use vti_specs_rooms::rooms::records::put::v0_3 as put_v3;
use vti_specs_rooms::rooms::records::put::v0_4 as put_v4;
use vti_specs_rooms::rooms::usage::v0_1 as rooms_usage;

use crate::authz::{Action, AuthorizedAction};
use crate::blobs::{
    BlobError, BlobHost, DownloadV2, Manifest, PartPlan, ReadSnapshot, TransferMode, UploadCaller,
    UploadOffer,
};
use crate::{Room, Visibility};

/// The URIs these tasks are dispatched under, from [`crate::wire`].
pub use crate::wire::{
    ROOMS_BLOBS_CHUNK_TYPE as DOWNLOAD_CHUNK_TYPE, ROOMS_RECORDS_GET_V2_TYPE as GET_V2_TYPE,
    ROOMS_RECORDS_PUT_V3_TYPE as PUT_V3_TYPE, ROOMS_RECORDS_PUT_V4_TYPE as PUT_V4_TYPE,
    ROOMS_USAGE_TYPE as USAGE_TYPE,
};
pub use crate::wire::{
    ROOMS_BLOBS_GET_V2_TYPE as BLOB_GET_V2_TYPE,
    ROOMS_BLOBS_UPLOAD_ABORT_V2_TYPE as UPLOAD_ABORT_V2_TYPE,
    ROOMS_BLOBS_UPLOAD_BEGIN_V2_TYPE as UPLOAD_BEGIN_V2_TYPE,
    ROOMS_BLOBS_UPLOAD_CHUNK_V2_TYPE as UPLOAD_CHUNK_V2_TYPE,
    ROOMS_BLOBS_UPLOAD_COMMIT_V2_TYPE as UPLOAD_COMMIT_V2_TYPE,
};

/// A `rooms/usage` page when the caller names no `limit`, and the most one holds.
const USAGE_PAGE: usize = 100;
/// A `rooms/usage` cursor names the last member returned, after this prefix.
const USAGE_CURSOR_PREFIX: &str = "rooms-usage:";

/// Why a room-file task was refused, for the host to render as its reply.
#[derive(Debug)]
#[non_exhaustive]
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

pub(crate) fn declared(
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
pub(crate) fn checked<R: serde::de::DeserializeOwned>(body: Value) -> TaskResult {
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

// ─── 0.2: direct-to-storage transfer, and the single-use upload key ─────────
//
// The member begins and (in direct mode) commits and aborts; a proxied transfer's
// chunk, commit and abort documents are signed by the `uploadKey` the begin named,
// so the member's key holder never signs over a file's bytes. The host records,
// charges and reports the member — the begin's authenticated presenter — and
// never the upload key (`rooms/blobs/upload/begin/0.2` items 14–15).

/// `rooms/blobs/upload/begin/0.2`, once the chain has been verified for `write`.
pub async fn begin_v2(
    files: &BlobHost,
    room: &Room,
    presenter: &str,
    authorized: &AuthorizedAction,
    payload: &Value,
) -> TaskResult {
    use upload_begin_v2::error_codes as codes;
    let req: upload_begin_v2::Payload = parse(payload)?;
    let manifest = Manifest::parse(&payload["manifest"])
        .map_err(|e| declared(codes::INVALID_MANIFEST, e.to_string(), None))?;
    let offer = UploadOffer {
        upload_key_did: req.upload_key.as_ref().map(|k| k.to_string()),
        direct_parts: req.direct_parts.as_ref().map(|p| PartPlan {
            part_size: p.part_size.get(),
            part_count: p.part_count.get(),
            part_digests: p.part_digests.iter().map(|d| d.to_string()).collect(),
        }),
    };
    match files
        .begin_presented(
            room,
            presenter,
            authorized.member(),
            authorized.presented(),
            manifest,
            Some(offer),
        )
        .await
    {
        Ok(b) => {
            let mut body = json!({
                "uploadId": b.upload_id.to_string(),
                "mode": b.mode.as_str(),
                "missing": b.missing,
                "expiresAt": b.expires_at,
            });
            if b.already_committed {
                body["alreadyCommitted"] = json!(true);
            }
            if b.mode == TransferMode::Direct && !b.targets.is_empty() {
                let targets: Vec<Value> = b
                    .targets
                    .iter()
                    .map(|(index, t)| {
                        let mut v = json!({
                            "index": index,
                            "method": "PUT",
                            "url": t.url,
                            "expiresAt": t.expires_at,
                        });
                        if !t.headers.is_empty() {
                            v["headers"] = json!(t.headers);
                        }
                        v
                    })
                    .collect();
                body["targets"] = json!(targets);
            }
            checked::<upload_begin_v2::Response>(body)
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
        Err(e @ BlobError::NoTransferMode { .. }) => {
            let BlobError::NoTransferMode { modes } = &e else {
                unreachable!()
            };
            let modes: Vec<&str> = modes.iter().map(|m| m.as_str()).collect();
            Err(declared(
                codes::NO_TRANSFER_MODE,
                e.to_string(),
                Some(json!({ "modes": modes })),
            ))
        }
        Err(BlobError::InvalidParts(why)) => Err(declared(codes::INVALID_PARTS, why, None)),
        Err(e @ BlobError::UploadKeyInUse) => {
            Err(declared(codes::UPLOAD_KEY_IN_USE, e.to_string(), None))
        }
        Err(e) => Err(general(e)),
    }
}

/// `rooms/blobs/upload/chunk/0.2`, from the authenticated `signer`: the upload's key,
/// or `notFound` to anybody else — its owner included.
pub async fn upload_chunk_v2(files: &BlobHost, signer: &str, payload: &Value) -> TaskResult {
    use upload_chunk_v2::error_codes as codes;
    let req: upload_chunk_v2::Payload = parse(payload)?;
    let data = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(req.data.as_str())
        .map_err(|e| Refusal::Malformed(format!("`data` is not base64url: {e}")))?;
    let index = (*req.index).max(0) as u64;
    match files
        .put_chunk_as(
            UploadCaller::V2(signer),
            req.upload_id.as_str(),
            index,
            req.digest_multibase.as_str(),
            &data,
        )
        .await
    {
        Ok(o) => checked::<upload_chunk_v2::Response>(json!({
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

/// `rooms/blobs/upload/commit/0.2`, from the authenticated `signer`.
pub async fn commit_v2(files: &BlobHost, signer: &str, payload: &Value) -> TaskResult {
    use upload_commit_v2::error_codes as codes;
    let req: upload_commit_v2::Payload = parse(payload)?;
    match files
        .commit_as(UploadCaller::V2(signer), req.upload_id.as_str())
        .await
    {
        Ok(c) => {
            checked::<upload_commit_v2::Response>(json!({ "blobRef": c.blob_ref, "size": c.size }))
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

/// `rooms/blobs/upload/abort/0.2`, from the authenticated `signer`.
pub async fn abort_v2(files: &BlobHost, signer: &str, payload: &Value) -> TaskResult {
    use upload_abort_v2::error_codes as codes;
    let req: upload_abort_v2::Payload = parse(payload)?;
    match files
        .abort_as(UploadCaller::V2(signer), req.upload_id.as_str())
        .await
    {
        Ok(aborted) => checked::<upload_abort_v2::Response>(
            json!({ "uploadId": req.upload_id.as_str(), "aborted": aborted }),
        ),
        Err(BlobError::NotFound) => Err(declared(codes::NOT_FOUND, "no upload with that id", None)),
        Err(e) => Err(general(e)),
    }
}

/// `rooms/blobs/get/0.2`, once the chain has been verified for `read`. Direct when the
/// reader asks for it and the host can and may answer so; proxied otherwise.
pub async fn get_v2(
    files: &BlobHost,
    room: &Room,
    presenter: &str,
    authorized: &AuthorizedAction,
    payload: &Value,
) -> TaskResult {
    use blob_get_v2::error_codes as codes;
    let req: blob_get_v2::Payload = parse(payload)?;
    match files
        .open_download_v2(
            room,
            presenter,
            authorized.member(),
            Some(authorized.presented()),
            req.blob_ref.as_str(),
            req.direct == Some(true),
        )
        .await
    {
        Ok(DownloadV2::Proxied(d)) => checked::<blob_get_v2::Response>(json!({
            "mode": TransferMode::Proxied.as_str(),
            "manifest": d.manifest,
            "downloadId": d.download_id.to_string(),
            "expiresAt": d.expires_at,
        })),
        Ok(DownloadV2::Direct { manifest, target }) => {
            let mut t = json!({
                "index": 0,
                "method": "GET",
                "url": target.url,
                "expiresAt": target.expires_at,
            });
            if !target.headers.is_empty() {
                t["headers"] = json!(target.headers);
            }
            checked::<blob_get_v2::Response>(json!({
                "mode": TransferMode::Direct.as_str(),
                "manifest": manifest,
                "target": t,
                "expiresAt": target.expires_at,
            }))
        }
        Err(BlobError::NotFound) => Err(declared(
            codes::NOT_FOUND,
            "no blob with that BlobRef is committed in this room",
            None,
        )),
        Err(e) => Err(general(e)),
    }
}

/// The room, its limits and its usage — what every `rooms/info` answers, before its schema
/// check; [`crate::record_tasks::info_v3`] adds the record retention and the latest prune.
pub(crate) async fn info_body(
    files: &BlobHost,
    room: &Room,
    authorized: &AuthorizedAction,
) -> Result<Value, Refusal> {
    let limits = files.effective_limits(room).await.map_err(Refusal::App)?;
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
        // Their own limits: an override set for them by name, else the default.
        let own = files
            .member_limits(room, member)
            .await
            .map_err(Refusal::App)?;
        usage["member"] = json!({ "usage": u, "limits": own.limits });
    }
    Ok(json!({
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

/// `rooms/usage/0.1`, once the chain has been verified for `admin` — the room's owner
/// asking who is using the space. One entry per member holding or reserving storage, or
/// holding an override; never a roster, never a file.
pub async fn usage(
    files: &BlobHost,
    room: &Room,
    authorized: &AuthorizedAction,
    payload: &Value,
) -> TaskResult {
    use rooms_usage::error_codes as codes;
    let req: rooms_usage::Payload = parse(payload)?;
    // Item 1: `read`, `write` and `curate` do not suffice. The host verified the chain
    // for the action it was asked to; this is the check that it was asked for `admin`.
    if authorized.action() != Action::Admin {
        return Err(Refusal::Internal(
            "rooms/usage was dispatched without an admin chain".into(),
        ));
    }
    // Item 2: nothing is attributed on a private room, and nothing is approximated.
    if room.visibility == Visibility::Private {
        return Err(declared(
            codes::NOT_AVAILABLE,
            "a private room's uploads are not attributed to members, by design",
            None,
        ));
    }
    let after = match req.cursor.as_ref() {
        None => None,
        Some(c) => Some(
            c.as_str()
                .strip_prefix(USAGE_CURSOR_PREFIX)
                .and_then(|b| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(b)
                        .ok()
                })
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or_else(|| Refusal::Malformed("`cursor` is not one this host issued".into()))?,
        ),
    };
    let limit = req
        .limit
        .map_or(USAGE_PAGE, |l| (l.get() as usize).min(USAGE_PAGE));
    // Ordered by member DID, which is what makes the cursor stable.
    let all = files.members_with_usage(room).await.map_err(Refusal::App)?;
    let mut rest = all
        .into_iter()
        .filter(|m| after.as_deref().is_none_or(|a| m.member.as_str() > a))
        .peekable();
    let mut members = Vec::new();
    while members.len() < limit {
        let Some(m) = rest.next() else { break };
        let mut entry = json!({
            "member": m.member,
            "usage": m.usage,
            "limits": m.limits,
        });
        if m.overridden {
            entry["overridden"] = json!(true);
        }
        if let Some(at) = m
            .last_upload_at
            .and_then(|s| chrono::DateTime::from_timestamp(s as i64, 0))
        {
            entry["lastUploadAt"] = json!(at);
        }
        members.push(entry);
    }
    let mut body = json!({ "roomId": room.room_id, "members": members });
    if rest.peek().is_some()
        && let Some(last) = members.last().and_then(|m| m["member"].as_str())
    {
        body["nextCursor"] = json!(format!(
            "{USAGE_CURSOR_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(last)
        ));
    }
    checked::<rooms_usage::Response>(body)
}

/// What a `rooms/records/put/0.3` carries beyond the 0.1 body, after checking the payload
/// is that task's: the `blobs` it names, and on an `open` room its `cleartext` **exactly as
/// received** — provenance and `validUntil` included (consumer item 11: stored and served as
/// received, never acted on).
///
/// The cleartext is read from the JSON, never from the generated type: some generated
/// constructors normalise what they parse (a `validUntil` comes back in another spelling),
/// and a host that rewrote a member would be serving the writer something they did not write.
#[allow(deprecated)] // superseded by 0.4, and still served: rooms/keys/act/0.8 completes put only to 0.3
pub fn put_v3_parts(payload: &Value) -> Result<(Vec<String>, Option<Value>), Refusal> {
    parse::<put_v3::Payload>(payload)?;
    put_parts(payload)
}

/// [`put_v3_parts`] for `rooms/records/put/0.4`, whose open-room `cleartext` may also carry
/// a `file`. The host checks that file against the record's `blobs` once it knows the room
/// ([`open_file_refused`]).
pub fn put_v4_parts(payload: &Value) -> Result<(Vec<String>, Option<Value>), Refusal> {
    parse::<put_v4::Payload>(payload)?;
    put_parts(payload)
}

/// The `blobs` and the `cleartext` as received, of a payload already checked against its
/// generated type.
fn put_parts(payload: &Value) -> Result<(Vec<String>, Option<Value>), Refusal> {
    // The bounds the generated type does not carry (`confidence` in [0, 1], a set of
    // purposes), against the schema itself.
    if let Some(cleartext) = payload.get("cleartext").and_then(Value::as_object) {
        crate::provenance::check(cleartext).map_err(Refusal::Malformed)?;
    }
    let blobs = payload
        .get("blobs")
        .and_then(Value::as_array)
        .map(|b| {
            b.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok((blobs, payload.get("cleartext").cloned()))
}

/// The members `rooms/records/put/0.3` adds to an `open` room's `cleartext` — a record's
/// provenance and its expiry (`rooms/_shared/0.1` `SealedRecordBody`, *Provenance*).
pub const PROVENANCE_MEMBERS: [&str; 5] =
    ["basis", "confidence", "evidence", "validFor", "validUntil"];

/// A 0.3 put read as the 0.1 body: [`as_v0_1`], and the provenance members taken out of
/// `cleartext`, which the 0.1 body does not take. The host stores the cleartext
/// [`put_v3_parts`] returned, not this one.
pub fn put_v3_as_v0_1(payload: Value) -> Value {
    let mut payload = as_v0_1(payload);
    if let Some(cleartext) = payload.get_mut("cleartext").and_then(Value::as_object_mut) {
        for member in PROVENANCE_MEMBERS {
            cleartext.remove(member);
        }
    }
    payload
}

/// A 0.4 put read as the 0.1 body: [`put_v3_as_v0_1`], and an open record's `file` taken
/// out of `cleartext` too. The host stores the cleartext [`put_v4_parts`] returned.
pub fn put_v4_as_v0_1(payload: Value) -> Value {
    let mut payload = put_v3_as_v0_1(payload);
    if let Some(cleartext) = payload.get_mut("cleartext").and_then(Value::as_object_mut) {
        cleartext.remove("file");
    }
    payload
}

/// `rooms/records/put/0.4` Host item 12: on an `open` room, which can read the record, a
/// `blobs` that is not exactly the blob `cleartext.file` describes, or a file with no
/// `fileKey`, is refused as malformed — before `blobNotFound`, and before anything changes.
/// `None` on a sealed room, whose body the host cannot see, and for a record that passes.
///
/// A blob the record does not describe would be kept alive by a record no reader can
/// connect it to; a file with no key is one no reader can open, since on this tier there is
/// no room key to derive it from.
pub fn open_file_refused(
    room: &Room,
    blobs: &[String],
    cleartext: Option<&Value>,
) -> Option<Refusal> {
    if !room.visibility.stores_cleartext() {
        return None;
    }
    let reason = match cleartext.and_then(|c| c.get("file")) {
        None if blobs.is_empty() => return None,
        None => {
            "`blobs` names a blob but `cleartext.file` describes none: an open room's record \
             names only the file it describes"
        }
        Some(file) if file.get("fileKey").is_none() => {
            "`cleartext.file` has no `fileKey`: an open room's file is sealed under a random \
             key its record carries"
        }
        Some(file) => {
            let described = file.get("blobRef").and_then(Value::as_str);
            if matches!((blobs, described), ([named], Some(r)) if named == r) {
                return None;
            }
            "`blobs` must be exactly `[cleartext.file.blobRef]`"
        }
    };
    Some(Refusal::Malformed(reason.to_string()))
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

/// Why `rooms/records/put/0.3` refused a record's `blobs`, as that task's declared codes.
pub fn record_blobs_refused(e: BlobError) -> Refusal {
    match e {
        BlobError::NotFound => declared(
            put_v3::error_codes::BLOB_NOT_FOUND,
            "a `blobs` entry names no blob committed in this room",
            None,
        ),
        BlobError::LimitExceeded(l) => declared(
            put_v3::error_codes::LIMIT_EXCEEDED,
            BlobError::LimitExceeded(l.clone()).to_string(),
            Some(l.details()),
        ),
        other => general(other),
    }
}

/// `rooms/records/put/0.3` refusing a sealed record whose epoch is not the room's
/// current one, as the task's declared `epochMismatch` — or `None` when the epoch is not the
/// reason to refuse it.
///
/// The usual cause is a writer whose key holder missed the commit that moved the room on
/// (a renewal, a removal); the remedy is to apply it and write again. Declared so the writer
/// can say that from the code, never from this message. The store re-checks the epoch
/// under its own read of the room
/// ([`crate::storage::put_record`]), which is the backstop for a room that moves between
/// this check and the write.
pub fn record_epoch_refused(room: &Room, sealed_epoch: Option<u32>) -> Option<Refusal> {
    if room.visibility.stores_cleartext() {
        return None;
    }
    let sealed = sealed_epoch?;
    (sealed != room.epoch).then(|| {
        declared(
            put_v3::error_codes::EPOCH_MISMATCH,
            format!(
                "record is sealed under epoch {sealed}, room `{}` is at {}",
                room.room_id, room.epoch
            ),
            None,
        )
    })
}

/// `rooms/epoch/prune/0.2`'s floor: a `beforeEpoch` at or above the room's current epoch
/// is refused with the declared `notAhead`, `details.epoch` naming the current one.
///
/// Pruning to the current epoch would drop every rung, leaving a member who restarts unable
/// to derive anything below the epoch they are handed next — a plausible typo
/// (`beforeEpoch: currentEpoch` reads like "keep from here") with a consequence nobody would
/// choose, so the specification refuses it, and declares a code so a client can say which
/// floor would work without reading this message.
pub fn prune_floor_refused(room: &Room, before_epoch: u32) -> Option<Refusal> {
    (before_epoch >= room.epoch).then(|| {
        declared(
            vti_specs_rooms::rooms::epoch::prune::v0_2::error_codes::NOT_AHEAD,
            format!(
                "`beforeEpoch` {before_epoch} is at or above the current epoch {} of `{}`; \
                 pruning there would drop the whole chain, not shorten it",
                room.epoch, room.room_id
            ),
            Some(json!({ "epoch": room.epoch })),
        )
    })
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

/// A listing with each row's `blobs`, before its schema check: 0.5 adds to it
/// ([`crate::record_tasks::list_v5_response`]).
pub(crate) async fn list_v2_body(
    snapshot: &ReadSnapshot<'_>,
    room_id: &str,
    response: impl serde::Serialize,
) -> Result<Value, Refusal> {
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
    Ok(body)
}

/// Whether a task is one of these, which a host routes here.
pub fn is_file_task(type_uri: &str) -> bool {
    [
        DOWNLOAD_CHUNK_TYPE,
        USAGE_TYPE,
        UPLOAD_BEGIN_V2_TYPE,
        UPLOAD_CHUNK_V2_TYPE,
        UPLOAD_COMMIT_V2_TYPE,
        UPLOAD_ABORT_V2_TYPE,
        BLOB_GET_V2_TYPE,
    ]
    .contains(&type_uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn room(visibility: Visibility) -> Room {
        Room {
            room_id: "did:key:zRoom".into(),
            owner_did: "did:key:zOwner".into(),
            visibility,
            retention_policy: crate::RetentionPolicy::Chained,
            anchor_cadence: Default::default(),
            epoch: 1,
            next_version: 1,
            retention_days: 90,
            epoch_expires_at: None,
            created_at: 0,
            updated_at: 0,
            mirror_of: None,
            record_retention: None,
            last_prune: None,
            epoch_floor: None,
        }
    }

    /// `rooms/records/put/0.4` Host item 12 is the open tier's: a sealed room's host cannot
    /// see the body, so it checks nothing of the kind — even a `blobs` with no cleartext.
    #[test]
    fn open_file_rules_do_not_reach_a_sealed_room() {
        let blobs = vec!["zBlob".to_string()];
        for visibility in [Visibility::Attributed, Visibility::Private] {
            assert!(open_file_refused(&room(visibility), &blobs, None).is_none());
        }
    }

    /// On an open room: a record with neither file nor blob passes, as does one naming
    /// exactly the blob its keyed file describes; anything else is malformed.
    #[test]
    fn open_file_rules_on_an_open_room() {
        let open = room(Visibility::Open);
        let file = json!({ "blobRef": "zBlob", "fileKey": "k" });
        let named = |b: &[&str]| b.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        assert!(open_file_refused(&open, &[], Some(&json!({ "body": "x" }))).is_none());
        assert!(open_file_refused(&open, &[], None).is_none());
        assert!(
            open_file_refused(&open, &named(&["zBlob"]), Some(&json!({ "file": file }))).is_none()
        );

        for (why, blobs, cleartext) in [
            ("blob, no file", named(&["zBlob"]), json!({ "body": "x" })),
            ("file, no blob", named(&[]), json!({ "file": file })),
            ("another blob", named(&["zOther"]), json!({ "file": file })),
            (
                "extra blob",
                named(&["zBlob", "zOther"]),
                json!({ "file": file }),
            ),
            (
                "no fileKey",
                named(&["zBlob"]),
                json!({ "file": { "blobRef": "zBlob" } }),
            ),
        ] {
            assert!(
                matches!(
                    open_file_refused(&open, &blobs, Some(&cleartext)),
                    Some(Refusal::Malformed(_))
                ),
                "{why}"
            );
        }
    }
}
