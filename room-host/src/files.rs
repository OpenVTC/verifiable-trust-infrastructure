//! Room files: the `rooms/blobs/*` tasks, `rooms/records/put` 0.2 and
//! `rooms/info`, over [`vti_rooms::blobs`].
//!
//! Every request is parsed with the **generated** payload type for its task, so
//! what this host accepts is what the specification says, member for member.
//! Authorization is the room's chain, exactly as for a record; the transfer
//! tasks that carry no presentation (`upload/chunk`, `commit`, `abort`, the
//! download `chunk`) are authorized by owning the transfer a verified chain
//! opened, and answer `notFound` to anybody else.

use std::sync::Arc;

use base64::Engine as _;
use serde_json::{Value, json};
use trust_tasks_rs::specs::rooms::blobs::chunk::v0_1 as download_chunk;
use trust_tasks_rs::specs::rooms::blobs::get::v0_1 as blob_get;
use trust_tasks_rs::specs::rooms::blobs::upload::abort::v0_1 as upload_abort;
use trust_tasks_rs::specs::rooms::blobs::upload::begin::v0_1 as upload_begin;
use trust_tasks_rs::specs::rooms::blobs::upload::chunk::v0_1 as upload_chunk;
use trust_tasks_rs::specs::rooms::blobs::upload::commit::v0_1 as upload_commit;
use trust_tasks_rs::specs::rooms::info::v0_1 as rooms_info;
use trust_tasks_rs::specs::rooms::records::put::v0_2 as put_v2;
use trust_tasks_rs::{DeclaredErrorCode, ErrorPayload, RejectReason, TrustTask, TrustTaskCode};
use uuid::Uuid;
use vti_common::error::AppError;
use vti_rooms::authz::{self, Action, AuthorizedAction};
use vti_rooms::blobs::{BlobError, Manifest};
use vti_rooms::storage;
use vti_rooms::wire::AuthorityPresentation;
use vti_rooms::{Room, Visibility};

use super::{Answer, HostState, from_app_error, now, reject, respond};

/// `rooms/blobs/upload/begin/0.1`.
pub(crate) const UPLOAD_BEGIN_TYPE: &str =
    <upload_begin::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `rooms/blobs/upload/chunk/0.1`.
pub(crate) const UPLOAD_CHUNK_TYPE: &str =
    <upload_chunk::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `rooms/blobs/upload/commit/0.1`.
pub(crate) const UPLOAD_COMMIT_TYPE: &str =
    <upload_commit::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `rooms/blobs/upload/abort/0.1`.
pub(crate) const UPLOAD_ABORT_TYPE: &str =
    <upload_abort::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `rooms/blobs/get/0.1`.
pub(crate) const BLOB_GET_TYPE: &str = <blob_get::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `rooms/blobs/chunk/0.1`.
pub(crate) const DOWNLOAD_CHUNK_TYPE: &str =
    <download_chunk::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `rooms/info/0.1`.
pub(crate) const INFO_TYPE: &str = <rooms_info::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `rooms/records/put/0.2`.
pub(crate) const PUT_V2_TYPE: &str = <put_v2::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Parse `payload` as the generated type `P`, or refuse it as malformed.
fn parse<P: serde::de::DeserializeOwned>(
    doc: &TrustTask<Value>,
    payload: &Value,
) -> Result<P, Answer> {
    serde_json::from_value(payload.clone()).map_err(|e| {
        reject(
            doc,
            RejectReason::MalformedRequest {
                reason: e.to_string(),
            },
        )
    })
}

/// Refuse with a code the task's specification declares.
fn coded(
    doc: &TrustTask<Value>,
    code: DeclaredErrorCode,
    message: impl Into<String>,
    details: Option<Value>,
) -> Answer {
    let (slug, local) = code
        .code
        .rsplit_once(':')
        .expect("a declared code is <slug>:<local>");
    let mut payload = ErrorPayload::new(TrustTaskCode::Extended {
        slug: slug.to_string(),
        local: local.to_string(),
    })
    .with_message(message)
    .with_retryable(code.retryable);
    if let Some(d) = details {
        payload = payload.with_details(d);
    }
    let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), payload);
    Answer {
        status: trust_tasks_https::status_for_code(&routed.payload.code),
        document: serde_json::to_value(&routed).unwrap_or(Value::Null),
    }
}

/// Answer with the generated response type `R`, built from `body`.
///
/// Going through `R` is the check that what this host sends is the
/// specification's response, not a near miss.
fn answer<R: serde::de::DeserializeOwned + serde::Serialize>(
    doc: &TrustTask<Value>,
    body: Value,
) -> Answer {
    match serde_json::from_value::<R>(body) {
        Ok(r) => respond(doc, r),
        Err(e) => reject(
            doc,
            RejectReason::InternalError {
                reason: format!("this host built a response its specification refuses: {e}"),
            },
        ),
    }
}

/// Map what every blob operation can refuse with and no task declares.
fn general(doc: &TrustTask<Value>, e: BlobError) -> Answer {
    match e {
        BlobError::RateLimited { retry_after_secs } => reject(
            doc,
            RejectReason::Unavailable {
                retry_after: Some(
                    chrono::Utc::now() + chrono::Duration::seconds(retry_after_secs as i64),
                ),
            },
        ),
        BlobError::App(AppError::ResourceExhausted(reason)) => reject(
            doc,
            RejectReason::TaskFailed {
                reason,
                details: None,
            },
        ),
        BlobError::App(e) => from_app_error(doc, &e),
        other => reject(
            doc,
            RejectReason::InternalError {
                reason: other.to_string(),
            },
        ),
    }
}

/// Read the presentation and room, verify the chain for `action`, and return
/// the room, the authenticated presenter and the authorization.
///
/// A chain that does not confer `action` is answered with `not_authorized`, the
/// code the task declares for it.
async fn authorize(
    state: &HostState,
    doc: &TrustTask<Value>,
    payload: &Value,
    action: Action,
    not_authorized: DeclaredErrorCode,
) -> Result<(Room, String, AuthorizedAction), Answer> {
    let presentation: AuthorityPresentation =
        serde_json::from_value(payload["presentation"].clone()).map_err(|e| {
            reject(
                doc,
                RejectReason::MalformedRequest {
                    reason: format!("presentation: {e}"),
                },
            )
        })?;
    let room_id = payload["roomId"].as_str().unwrap_or_default();
    let room = storage::get_room(&state.rooms, room_id)
        .await
        .map_err(|e| from_app_error(doc, &e))?;
    let (presenter, verifier) = state
        .presenter_and_verifier(doc)
        .await
        .map_err(|e| from_app_error(doc, &e))?;
    let authorized = authz::authorize(&room, &presentation, action, &presenter, now(), &verifier)
        .await
        .map_err(|e| match e {
            AppError::Forbidden(reason) => coded(doc, not_authorized, reason, None),
            other => from_app_error(doc, &other),
        })?;
    Ok((room, presenter, authorized))
}

pub(crate) async fn begin(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    use upload_begin::error_codes as codes;
    if let Err(a) = parse::<upload_begin::Payload>(doc, &payload) {
        return a;
    }
    let (room, presenter, authorized) =
        match authorize(state, doc, &payload, Action::Write, codes::NOT_AUTHORIZED).await {
            Ok(r) => r,
            Err(a) => return a,
        };
    let manifest = match Manifest::parse(&payload["manifest"]) {
        Ok(m) => m,
        Err(e) => return coded(doc, codes::INVALID_MANIFEST, e.to_string(), None),
    };
    match state
        .files
        .begin(&room, &presenter, authorized.member(), manifest)
        .await
    {
        Ok(b) => answer::<upload_begin::Response>(
            doc,
            json!({
                "uploadId": b.upload_id.to_string(),
                "missing": b.missing,
                "expiresAt": b.expires_at,
            }),
        ),
        Err(BlobError::FilesDisabled) => coded(
            doc,
            codes::FILES_DISABLED,
            BlobError::FilesDisabled.to_string(),
            None,
        ),
        Err(BlobError::InvalidManifest(why)) => coded(doc, codes::INVALID_MANIFEST, why, None),
        Err(BlobError::LimitExceeded(l)) => coded(
            doc,
            codes::LIMIT_EXCEEDED,
            BlobError::LimitExceeded(l.clone()).to_string(),
            Some(l.details()),
        ),
        Err(e) => general(doc, e),
    }
}

pub(crate) async fn upload_chunk(
    state: &HostState,
    doc: &TrustTask<Value>,
    payload: Value,
) -> Answer {
    use upload_chunk::error_codes as codes;
    let req: upload_chunk::Payload = match parse(doc, &payload) {
        Ok(p) => p,
        Err(a) => return a,
    };
    let presenter = match state.presenter(doc).await {
        Ok(p) => p,
        Err(e) => return from_app_error(doc, &e),
    };
    let data = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(req.data.as_str()) {
        Ok(d) => d,
        Err(e) => {
            return reject(
                doc,
                RejectReason::MalformedRequest {
                    reason: format!("`data` is not base64url: {e}"),
                },
            );
        }
    };
    let index = (*req.index).max(0) as u64;
    match state
        .files
        .put_chunk(
            &presenter,
            req.upload_id.as_str(),
            index,
            req.digest_multibase.as_str(),
            &data,
        )
        .await
    {
        Ok(o) => answer::<upload_chunk::Response>(
            doc,
            json!({
                "uploadId": req.upload_id.as_str(),
                "index": index,
                "stored": o.stored,
                "remainingCount": o.remaining_count,
                "expiresAt": o.expires_at,
            }),
        ),
        Err(BlobError::NotFound) => {
            coded(doc, codes::NOT_FOUND, "no open upload with that id", None)
        }
        Err(e @ BlobError::ChunkOutOfRange { .. }) => {
            coded(doc, codes::CHUNK_OUT_OF_RANGE, e.to_string(), None)
        }
        Err(BlobError::ChunkMismatch(why)) => coded(doc, codes::CHUNK_MISMATCH, why, None),
        Err(e) => general(doc, e),
    }
}

pub(crate) async fn commit(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    use upload_commit::error_codes as codes;
    let req: upload_commit::Payload = match parse(doc, &payload) {
        Ok(p) => p,
        Err(a) => return a,
    };
    let presenter = match state.presenter(doc).await {
        Ok(p) => p,
        Err(e) => return from_app_error(doc, &e),
    };
    match state.files.commit(&presenter, req.upload_id.as_str()).await {
        Ok(c) => {
            answer::<upload_commit::Response>(doc, json!({ "blobRef": c.blob_ref, "size": c.size }))
        }
        Err(BlobError::NotFound) => coded(doc, codes::NOT_FOUND, "no upload with that id", None),
        Err(BlobError::Incomplete { remaining_count }) => coded(
            doc,
            codes::INCOMPLETE,
            format!("{remaining_count} chunk(s) have not been sent"),
            Some(json!({ "remainingCount": remaining_count })),
        ),
        Err(e @ BlobError::DigestMismatch) => {
            coded(doc, codes::DIGEST_MISMATCH, e.to_string(), None)
        }
        Err(e) => general(doc, e),
    }
}

pub(crate) async fn abort(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    use upload_abort::error_codes as codes;
    let req: upload_abort::Payload = match parse(doc, &payload) {
        Ok(p) => p,
        Err(a) => return a,
    };
    let presenter = match state.presenter(doc).await {
        Ok(p) => p,
        Err(e) => return from_app_error(doc, &e),
    };
    match state.files.abort(&presenter, req.upload_id.as_str()).await {
        Ok(aborted) => answer::<upload_abort::Response>(
            doc,
            json!({ "uploadId": req.upload_id.as_str(), "aborted": aborted }),
        ),
        Err(BlobError::NotFound) => coded(doc, codes::NOT_FOUND, "no upload with that id", None),
        Err(e) => general(doc, e),
    }
}

pub(crate) async fn get(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    use blob_get::error_codes as codes;
    let req: blob_get::Payload = match parse(doc, &payload) {
        Ok(p) => p,
        Err(a) => return a,
    };
    let (room, presenter, _authorized) =
        match authorize(state, doc, &payload, Action::Read, codes::NOT_AUTHORIZED).await {
            Ok(r) => r,
            Err(a) => return a,
        };
    match state
        .files
        .open_download(&room.room_id, &presenter, req.blob_ref.as_str())
        .await
    {
        Ok(d) => answer::<blob_get::Response>(
            doc,
            json!({
                "manifest": d.manifest,
                "downloadId": d.download_id.to_string(),
                "expiresAt": d.expires_at,
            }),
        ),
        Err(BlobError::NotFound) => coded(
            doc,
            codes::NOT_FOUND,
            "no blob with that BlobRef is committed in this room",
            None,
        ),
        Err(e) => general(doc, e),
    }
}

pub(crate) async fn download_chunk(
    state: &HostState,
    doc: &TrustTask<Value>,
    payload: Value,
) -> Answer {
    use download_chunk::error_codes as codes;
    let req: download_chunk::Payload = match parse(doc, &payload) {
        Ok(p) => p,
        Err(a) => return a,
    };
    let presenter = match state.presenter(doc).await {
        Ok(p) => p,
        Err(e) => return from_app_error(doc, &e),
    };
    let index = (*req.index).max(0) as u64;
    match state
        .files
        .read_chunk(&presenter, req.download_id.as_str(), index)
        .await
    {
        Ok(c) => answer::<download_chunk::Response>(
            doc,
            json!({
                "index": index,
                "data": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&c.data),
                "digestMultibase": c.digest_multibase,
            }),
        ),
        Err(BlobError::NotFound) => {
            coded(doc, codes::NOT_FOUND, "no open download with that id", None)
        }
        Err(e @ BlobError::ChunkOutOfRange { .. }) => {
            coded(doc, codes::CHUNK_OUT_OF_RANGE, e.to_string(), None)
        }
        Err(e) => general(doc, e),
    }
}

pub(crate) async fn info(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    use rooms_info::error_codes as codes;
    if let Err(a) = parse::<rooms_info::Payload>(doc, &payload) {
        return a;
    }
    let (room, _presenter, authorized) =
        match authorize(state, doc, &payload, Action::Read, codes::NOT_AUTHORIZED).await {
            Ok(r) => r,
            Err(a) => return a,
        };
    let limits = state.files.effective_limits(&room);
    let room_usage = match state.files.room_usage(&room.room_id).await {
        Ok(u) => u,
        Err(e) => return from_app_error(doc, &e),
    };
    let mut usage = json!({ "room": room_usage });
    // The presenter's own figures, charged to the member the chain descends
    // from. Never on a `private` room, where the host does not know who asks.
    if room.visibility != Visibility::Private
        && let Some(member) = authorized.member()
    {
        match state.files.member_usage(&room.room_id, member).await {
            Ok(u) => usage["member"] = json!({ "usage": u, "limits": limits.member }),
            Err(e) => return from_app_error(doc, &e),
        }
    }
    answer::<rooms_info::Response>(
        doc,
        json!({
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
        }),
    )
}

/// `rooms/records/put/0.2`: a record that may name committed blobs.
///
/// Parsed with the generated type, then handed to the same write path 0.1
/// takes, with its `blobs`.
pub(crate) async fn put_v2(
    state: &Arc<HostState>,
    doc: &TrustTask<Value>,
    payload: Value,
) -> Answer {
    let req: put_v2::Payload = match parse(doc, &payload) {
        Ok(p) => p,
        Err(a) => return a,
    };
    let blobs: Vec<String> = req
        .blobs
        .unwrap_or_default()
        .iter()
        .map(|b| b.as_str().to_string())
        .collect();
    let mut body = payload;
    if let Some(obj) = body.as_object_mut() {
        obj.remove("blobs");
        obj.remove("ext");
    }
    super::put_with_blobs(state, doc, body, Some(blobs)).await
}

/// The `blobNotFound` refusal `rooms/records/put` 0.2 declares.
pub(crate) fn blob_not_found(doc: &TrustTask<Value>) -> Answer {
    coded(
        doc,
        put_v2::error_codes::BLOB_NOT_FOUND,
        "a `blobs` entry names no blob committed in this room",
        None,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    use vti_common::blob_store::{blob_ref_of_manifest, sha256_digest_multibase};
    use vti_rooms::Visibility;
    use vti_rooms::blobs::{HostLimits, ScopeLimits};
    use vti_rooms_dtg::test_support::{Party, RoomFixture};

    use super::*;
    use crate::{FilesConfig, HostState, open_state_with_files, router};

    const CHUNK: usize = 16_384;

    struct Host {
        _dir: tempfile::TempDir,
        state: Arc<HostState>,
        app: Router,
    }

    fn host(limits: HostLimits) -> Host {
        let dir = tempfile::tempdir().unwrap();
        let state = open_state_with_files(
            dir.path(),
            vti_common::auth::TrustTaskVmResolver::did_key_only(),
            FilesConfig {
                limits,
                ..Default::default()
            },
        )
        .unwrap();
        let app = router(state.clone());
        Host {
            _dir: dir,
            state,
            app,
        }
    }

    /// No grace, so a collection pass collects at once.
    fn eager() -> HostLimits {
        HostLimits {
            orphan_grace_secs: 0,
            ..Default::default()
        }
    }

    async fn call(
        app: &Router,
        type_uri: &str,
        payload: Value,
        signer: &Party,
    ) -> (StatusCode, Value) {
        let doc = vta_sdk::trust_task_sign::build_signed(
            type_uri,
            payload,
            &signer.did,
            &signer.secret_multibase,
            "did:key:zHost",
        )
        .await
        .expect("sign the request");
        let resp = app
            .clone()
            .oneshot(
                Request::post("/trust-tasks")
                    .header("content-type", "application/json")
                    .body(Body::from(doc))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, doc["payload"].clone())
    }

    async fn room(h: &Host) -> RoomFixture {
        let f = RoomFixture::new(Visibility::Open).await;
        let (status, body) = call(
            &h.app,
            vti_rooms::wire::ROOMS_CREATE_TYPE,
            json!({ "roomId": f.room.room_id, "ownerDid": f.room.owner_did, "visibility": "open" }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        f
    }

    /// A file's ciphertext as an uploader would hold it: the bytes, its
    /// manifest and the BlobRef the host will name it by.
    struct Blob {
        bytes: Vec<u8>,
        manifest: Value,
        blob_ref: String,
    }

    fn blob(len: usize, seed: u8) -> Blob {
        let bytes: Vec<u8> = (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect();
        let digests: Vec<String> = bytes
            .chunks(CHUNK)
            .map(|c| sha256_digest_multibase(&Sha256::digest(c).into()))
            .collect();
        let manifest = json!({
            "size": len,
            "chunks": { "chunkSize": CHUNK, "chunkCount": digests.len(), "chunkDigests": digests },
            "digest": sha256_digest_multibase(&Sha256::digest(&bytes).into()),
        });
        let blob_ref = blob_ref_of_manifest(&manifest).unwrap();
        Blob {
            bytes,
            manifest,
            blob_ref,
        }
    }

    fn chunk_doc(upload_id: &str, b: &Blob, index: usize) -> Value {
        let data = &b.bytes[index * CHUNK..((index + 1) * CHUNK).min(b.bytes.len())];
        json!({
            "uploadId": upload_id,
            "index": index,
            "digestMultibase": sha256_digest_multibase(&Sha256::digest(data).into()),
            "data": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data),
        })
    }

    async fn begin(h: &Host, f: &RoomFixture, b: &Blob) -> (StatusCode, Value) {
        call(
            &h.app,
            UPLOAD_BEGIN_TYPE,
            json!({ "roomId": f.room.room_id, "presentation": f.as_owner(), "manifest": b.manifest }),
            &f.owner,
        )
        .await
    }

    /// Begin, send every chunk, commit. Returns the BlobRef.
    async fn upload(h: &Host, f: &RoomFixture, b: &Blob) -> String {
        let (status, begun) = begin(h, f, b).await;
        assert_eq!(status, StatusCode::OK, "{begun}");
        let id = begun["uploadId"].as_str().unwrap().to_string();
        for i in 0..b.bytes.len().div_ceil(CHUNK) {
            let (status, out) =
                call(&h.app, UPLOAD_CHUNK_TYPE, chunk_doc(&id, b, i), &f.owner).await;
            assert_eq!(status, StatusCode::OK, "{out}");
        }
        let (status, out) = call(
            &h.app,
            UPLOAD_COMMIT_TYPE,
            json!({ "uploadId": id }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        out["blobRef"].as_str().unwrap().to_string()
    }

    async fn put_record(
        h: &Host,
        f: &RoomFixture,
        key: &str,
        blobs: &[&str],
    ) -> (StatusCode, Value) {
        call(
            &h.app,
            PUT_V2_TYPE,
            json!({
                "roomId": f.room.room_id,
                "key": key,
                "presentation": f.as_owner(),
                "cleartext": { "body": "a file" },
                "blobs": blobs,
            }),
            &f.owner,
        )
        .await
    }

    async fn info(h: &Host, f: &RoomFixture) -> Value {
        let (status, out) = call(
            &h.app,
            INFO_TYPE,
            json!({ "roomId": f.room.room_id, "presentation": f.as_owner() }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        out
    }

    fn code(out: &Value) -> String {
        out["code"].as_str().unwrap_or_default().to_string()
    }

    /// The whole life of a file: an interrupted upload resumed, committed,
    /// downloaded byte-identical, named by a record, retracted, and collected.
    #[tokio::test]
    async fn a_file_from_upload_to_collection() {
        let h = host(eager());
        let f = room(&h).await;
        let b = blob(3 * CHUNK + 100, 1);

        let (_, begun) = begin(&h, &f, &b).await;
        let id = begun["uploadId"].as_str().unwrap().to_string();
        assert_eq!(begun["missing"], json!([0, 1, 2, 3]));
        call(&h.app, UPLOAD_CHUNK_TYPE, chunk_doc(&id, &b, 0), &f.owner).await;

        // Resumed: the same slot, only what is left, and no second reservation.
        let (_, again) = begin(&h, &f, &b).await;
        assert_eq!(again["uploadId"], json!(id));
        assert_eq!(again["missing"], json!([1, 2, 3]));
        assert_eq!(
            info(&h, &f).await["usage"]["room"]["reservedFiles"],
            json!(1)
        );

        // An identical re-send is a success that stores nothing.
        let (status, out) = call(&h.app, UPLOAD_CHUNK_TYPE, chunk_doc(&id, &b, 0), &f.owner).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(out["stored"], json!(false));

        // Not committable until complete.
        let (_, out) = call(
            &h.app,
            UPLOAD_COMMIT_TYPE,
            json!({ "uploadId": id }),
            &f.owner,
        )
        .await;
        assert_eq!(code(&out), "rooms/blobs/upload/commit:incomplete");
        assert_eq!(out["details"]["remainingCount"], json!(3));
        for i in 1..4 {
            call(&h.app, UPLOAD_CHUNK_TYPE, chunk_doc(&id, &b, i), &f.owner).await;
        }
        let (status, out) = call(
            &h.app,
            UPLOAD_COMMIT_TYPE,
            json!({ "uploadId": id }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(
            out["blobRef"],
            json!(b.blob_ref),
            "the host names it by the manifest's digest"
        );
        assert_eq!(out["size"], json!(b.bytes.len()));

        // A repeated commit answers the same, charging nothing twice.
        let (_, again) = call(
            &h.app,
            UPLOAD_COMMIT_TYPE,
            json!({ "uploadId": id }),
            &f.owner,
        )
        .await;
        assert_eq!(again, out);
        let usage = info(&h, &f).await["usage"].clone();
        assert_eq!(usage["room"]["files"], json!(1));
        assert_eq!(usage["room"]["bytes"], json!(b.bytes.len()));
        assert_eq!(usage["room"]["reservedBytes"], json!(0));
        assert_eq!(
            usage["member"]["usage"]["files"],
            json!(1),
            "charged to the member"
        );

        // Downloaded, byte for byte.
        let (status, got) = call(
            &h.app,
            BLOB_GET_TYPE,
            json!({ "roomId": f.room.room_id, "presentation": f.as_owner(), "blobRef": b.blob_ref }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{got}");
        assert_eq!(
            got["manifest"], b.manifest,
            "the manifest exactly as committed"
        );
        assert_eq!(blob_ref_of_manifest(&got["manifest"]).unwrap(), b.blob_ref);
        let download = got["downloadId"].as_str().unwrap();
        let mut fetched = Vec::new();
        for i in 0..4 {
            let (status, c) = call(
                &h.app,
                DOWNLOAD_CHUNK_TYPE,
                json!({ "downloadId": download, "index": i }),
                &f.owner,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{c}");
            fetched.extend(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(c["data"].as_str().unwrap())
                    .unwrap(),
            );
        }
        assert_eq!(fetched, b.bytes);
        let (_, c) = call(
            &h.app,
            DOWNLOAD_CHUNK_TYPE,
            json!({ "downloadId": download, "index": 4 }),
            &f.owner,
        )
        .await;
        assert_eq!(code(&c), "rooms/blobs/chunk:chunkOutOfRange");

        // Named by a record, then retracted: the room has the space back at once.
        let (status, out) = put_record(&h, &f, "files/term-sheet", &[&b.blob_ref]).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        let (status, out) = call(
            &h.app,
            vti_rooms::wire::ROOMS_RECORDS_CURATE_TYPE,
            json!({
                "roomId": f.room.room_id,
                "key": "files/term-sheet",
                "presentation": f.as_owner(),
                "status": "retracted",
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        let usage = info(&h, &f).await["usage"].clone();
        assert_eq!(
            usage["room"]["files"],
            json!(0),
            "orphaned: no longer counted"
        );
        assert_eq!(usage["member"]["usage"]["bytes"], json!(0));

        // Collected: gone from the store, and no longer downloadable.
        let stats = h.state.files().sweep().await.unwrap();
        assert_eq!(stats.collected, 1);
        let (_, got) = call(
            &h.app,
            BLOB_GET_TYPE,
            json!({ "roomId": f.room.room_id, "presentation": f.as_owner(), "blobRef": b.blob_ref }),
            &f.owner,
        )
        .await;
        assert_eq!(code(&got), "rooms/blobs/get:notFound");
        let (_, out) = put_record(&h, &f, "files/again", &[&b.blob_ref]).await;
        assert_eq!(code(&out), "rooms/records/put:blobNotFound");
    }

    /// Rewriting a record without its file releases the file; rewriting it
    /// with the file again, before collection, takes it back.
    #[tokio::test]
    async fn a_rewrite_releases_and_restores_a_file() {
        let h = host(HostLimits::default());
        let f = room(&h).await;
        let b = blob(CHUNK, 2);
        let blob_ref = upload(&h, &f, &b).await;
        put_record(&h, &f, "doc", &[&blob_ref]).await;

        // A 0.1 write names no blobs.
        let (status, out) = call(
            &h.app,
            vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE,
            json!({
                "roomId": f.room.room_id,
                "key": "doc",
                "presentation": f.as_owner(),
                "cleartext": { "body": "no file now" },
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(info(&h, &f).await["usage"]["room"]["files"], json!(0));

        let (status, out) = put_record(&h, &f, "doc", &[&blob_ref]).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(info(&h, &f).await["usage"]["room"]["files"], json!(1));

        // Two records may share a blob; it is orphaned only when the last lets go.
        put_record(&h, &f, "copy", &[&blob_ref]).await;
        put_record(&h, &f, "doc", &[]).await;
        assert_eq!(info(&h, &f).await["usage"]["room"]["files"], json!(1));
    }

    /// Uploading the same file twice stores and charges it once.
    #[tokio::test]
    async fn a_second_upload_of_a_committed_blob_is_not_stored_twice() {
        let h = host(HostLimits::default());
        let f = room(&h).await;
        let b = blob(CHUNK + 1, 3);
        upload(&h, &f, &b).await;
        let again = upload(&h, &f, &b).await;
        assert_eq!(again, b.blob_ref);
        let usage = info(&h, &f).await["usage"]["room"].clone();
        assert_eq!(usage["files"], json!(1));
        assert_eq!(usage["reservedFiles"], json!(0));
    }

    #[tokio::test]
    async fn limits_refuse_at_the_narrowest_scope_with_their_numbers() {
        // Member: one file each.
        let h = host(HostLimits {
            member: ScopeLimits {
                max_files: Some(1),
                ..Default::default()
            },
            ..Default::default()
        });
        let f = room(&h).await;
        upload(&h, &f, &blob(CHUNK, 4)).await;
        let (_, out) = begin(&h, &f, &blob(CHUNK, 5)).await;
        assert_eq!(code(&out), "rooms/blobs/upload/begin:limitExceeded");
        assert_eq!(
            out["details"],
            json!({ "scope": "member", "measure": "maxFiles", "limit": 1, "used": 1, "requested": 1 })
        );

        // Room: bytes.
        let h = host(HostLimits {
            room: ScopeLimits {
                max_bytes: Some(CHUNK as u64 * 2),
                ..Default::default()
            },
            ..Default::default()
        });
        let f = room(&h).await;
        let (_, out) = begin(&h, &f, &blob(CHUNK * 2 + 1, 6)).await;
        assert_eq!(out["details"]["scope"], json!("room"));
        assert_eq!(out["details"]["measure"], json!("maxBytes"));

        // The host's ceiling on one file.
        let h = host(HostLimits {
            max_file_bytes: CHUNK as u64,
            ..Default::default()
        });
        let f = room(&h).await;
        let (_, out) = begin(&h, &f, &blob(CHUNK + 1, 7)).await;
        assert_eq!(out["details"]["scope"], json!("host"));
        assert_eq!(out["details"]["measure"], json!("maxFileBytes"));

        // The storage's capacity.
        let h = host(HostLimits {
            storage_capacity_bytes: Some(CHUNK as u64),
            ..Default::default()
        });
        let f = room(&h).await;
        let (_, out) = begin(&h, &f, &blob(CHUNK + 1, 8)).await;
        assert_eq!(out["details"]["scope"], json!("storage"));

        // Files off.
        let h = host(HostLimits {
            files_enabled: false,
            ..Default::default()
        });
        let f = room(&h).await;
        let (_, out) = begin(&h, &f, &blob(CHUNK, 9)).await;
        assert_eq!(code(&out), "rooms/blobs/upload/begin:filesDisabled");
    }

    /// Two uploads racing for room under a limit only one of them fits: one is
    /// reserved, the other refused — never both.
    #[tokio::test]
    async fn concurrent_uploads_cannot_both_squeeze_under_a_limit() {
        let h = host(HostLimits {
            room: ScopeLimits {
                max_bytes: Some(CHUNK as u64 * 3),
                ..Default::default()
            },
            ..Default::default()
        });
        let f = room(&h).await;
        let (a, b) = (blob(CHUNK * 2, 10), blob(CHUNK * 2, 11));
        let ((sa, _), (sb, _)) = tokio::join!(begin(&h, &f, &a), begin(&h, &f, &b));
        let oks = [sa, sb].iter().filter(|s| **s == StatusCode::OK).count();
        assert_eq!(oks, 1, "exactly one reservation fits");
        assert_eq!(
            info(&h, &f).await["usage"]["room"]["reservedBytes"],
            json!(CHUNK * 2)
        );
    }

    /// A transfer belongs to whoever opened it: another member, with a valid
    /// chain of their own, cannot write to it, commit it, abort it, or read
    /// through somebody else's download.
    #[tokio::test]
    async fn a_transfer_answers_only_its_opener() {
        let h = host(HostLimits::default());
        let f = room(&h).await;
        let b = blob(CHUNK * 2, 12);
        let (_, begun) = begin(&h, &f, &b).await;
        let id = begun["uploadId"].as_str().unwrap().to_string();

        let (_, out) = call(
            &h.app,
            UPLOAD_CHUNK_TYPE,
            chunk_doc(&id, &b, 0),
            &f.successor,
        )
        .await;
        assert_eq!(code(&out), "rooms/blobs/upload/chunk:notFound");
        let (_, out) = call(
            &h.app,
            UPLOAD_COMMIT_TYPE,
            json!({ "uploadId": id }),
            &f.successor,
        )
        .await;
        assert_eq!(code(&out), "rooms/blobs/upload/commit:notFound");
        let (_, out) = call(
            &h.app,
            UPLOAD_ABORT_TYPE,
            json!({ "uploadId": id }),
            &f.successor,
        )
        .await;
        assert_eq!(code(&out), "rooms/blobs/upload/abort:notFound");

        // The successor holds `read` only, so it cannot begin at all.
        let (_, out) = call(
            &h.app,
            UPLOAD_BEGIN_TYPE,
            json!({ "roomId": f.room.room_id, "presentation": f.as_successor(), "manifest": b.manifest }),
            &f.successor,
        )
        .await;
        assert_eq!(code(&out), "rooms/blobs/upload/begin:notAuthorized");

        for i in 0..2 {
            call(&h.app, UPLOAD_CHUNK_TYPE, chunk_doc(&id, &b, i), &f.owner).await;
        }
        call(
            &h.app,
            UPLOAD_COMMIT_TYPE,
            json!({ "uploadId": id }),
            &f.owner,
        )
        .await;
        let (_, got) = call(
            &h.app,
            BLOB_GET_TYPE,
            json!({ "roomId": f.room.room_id, "presentation": f.as_owner(), "blobRef": b.blob_ref }),
            &f.owner,
        )
        .await;
        let (_, out) = call(
            &h.app,
            DOWNLOAD_CHUNK_TYPE,
            json!({ "downloadId": got["downloadId"], "index": 0 }),
            &f.successor,
        )
        .await;
        assert_eq!(code(&out), "rooms/blobs/chunk:notFound");
    }

    #[tokio::test]
    async fn a_chunk_that_is_not_the_committed_one_is_refused() {
        let h = host(HostLimits::default());
        let f = room(&h).await;
        let b = blob(CHUNK * 2, 13);
        let (_, begun) = begin(&h, &f, &b).await;
        let id = begun["uploadId"].as_str().unwrap();
        let mut doc = chunk_doc(id, &b, 0);
        doc["data"] =
            json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0u8; CHUNK]));
        let (_, out) = call(&h.app, UPLOAD_CHUNK_TYPE, doc, &f.owner).await;
        assert_eq!(code(&out), "rooms/blobs/upload/chunk:chunkMismatch");
        let mut doc = chunk_doc(id, &b, 0);
        doc["index"] = json!(5);
        let (_, out) = call(&h.app, UPLOAD_CHUNK_TYPE, doc, &f.owner).await;
        assert_eq!(code(&out), "rooms/blobs/upload/chunk:chunkOutOfRange");
    }

    /// Every chunk right, the commitment wrong: discarded, reservation back.
    #[tokio::test]
    async fn a_wrong_whole_digest_discards_the_upload() {
        let h = host(HostLimits::default());
        let f = room(&h).await;
        let mut b = blob(CHUNK * 2, 14);
        b.manifest["digest"] = json!(sha256_digest_multibase(&[0u8; 32]));
        let (_, begun) = begin(&h, &f, &b).await;
        let id = begun["uploadId"].as_str().unwrap().to_string();
        for i in 0..2 {
            call(&h.app, UPLOAD_CHUNK_TYPE, chunk_doc(&id, &b, i), &f.owner).await;
        }
        let (_, out) = call(
            &h.app,
            UPLOAD_COMMIT_TYPE,
            json!({ "uploadId": id }),
            &f.owner,
        )
        .await;
        assert_eq!(code(&out), "rooms/blobs/upload/commit:digestMismatch");
        assert_eq!(
            info(&h, &f).await["usage"]["room"]["reservedBytes"],
            json!(0)
        );
    }

    #[tokio::test]
    async fn an_abort_gives_the_reservation_back_once() {
        let h = host(HostLimits::default());
        let f = room(&h).await;
        let b = blob(CHUNK, 15);
        let (_, begun) = begin(&h, &f, &b).await;
        let id = begun["uploadId"].as_str().unwrap();
        let (_, out) = call(
            &h.app,
            UPLOAD_ABORT_TYPE,
            json!({ "uploadId": id }),
            &f.owner,
        )
        .await;
        assert_eq!(out["aborted"], json!(true));
        let (_, out) = call(
            &h.app,
            UPLOAD_ABORT_TYPE,
            json!({ "uploadId": id }),
            &f.owner,
        )
        .await;
        assert_eq!(out["aborted"], json!(false));
        let (_, out) = call(
            &h.app,
            UPLOAD_COMMIT_TYPE,
            json!({ "uploadId": id }),
            &f.owner,
        )
        .await;
        assert_eq!(code(&out), "rooms/blobs/upload/commit:notFound");
        assert_eq!(
            info(&h, &f).await["usage"]["room"]["reservedFiles"],
            json!(0)
        );
    }

    /// A blob committed in one room is never another room's.
    #[tokio::test]
    async fn a_blob_from_another_room_is_not_found() {
        let h = host(HostLimits::default());
        let a = room(&h).await;
        let other = room(&h).await;
        let b = blob(CHUNK, 16);
        upload(&h, &a, &b).await;

        let (_, out) = put_record(&h, &other, "stolen", &[&b.blob_ref]).await;
        assert_eq!(code(&out), "rooms/records/put:blobNotFound");
        let (_, out) = call(
            &h.app,
            BLOB_GET_TYPE,
            json!({ "roomId": other.room.room_id, "presentation": other.as_owner(), "blobRef": b.blob_ref }),
            &other.owner,
        )
        .await;
        assert_eq!(code(&out), "rooms/blobs/get:notFound");
    }

    /// Committed and never named by a record: collected after the grace window.
    #[tokio::test]
    async fn an_abandoned_commit_is_collected() {
        let h = host(eager());
        let f = room(&h).await;
        upload(&h, &f, &blob(CHUNK, 17)).await;
        assert_eq!(h.state.files().sweep().await.unwrap().collected, 1);
        assert_eq!(info(&h, &f).await["usage"]["room"]["files"], json!(0));
    }
}
