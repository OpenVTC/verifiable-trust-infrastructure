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

use serde_json::Value;
use trust_tasks_rs::specs::rooms::records::get::v0_2 as get_v2_spec;
use trust_tasks_rs::specs::rooms::records::list::v0_2 as list_v2_spec;
use trust_tasks_rs::{DeclaredErrorCode, ErrorPayload, RejectReason, TrustTask, TrustTaskCode};
use uuid::Uuid;
use vti_rooms::Room;
use vti_rooms::authz::{self, Action, AuthorizedAction};
use vti_rooms::blob_tasks::{self, Refusal, TaskResult};
use vti_rooms::blobs::BlobError;
use vti_rooms::storage;
use vti_rooms::wire::AuthorityPresentation;

use super::{Answer, HostState, from_app_error, now, reject, respond};

pub(crate) use vti_rooms::blob_tasks::{
    BLOB_GET_TYPE, BLOB_GET_V2_TYPE, DOWNLOAD_CHUNK_TYPE, GET_V2_TYPE, INFO_TYPE, LIST_V2_TYPE,
    PUT_V2_TYPE, UPLOAD_ABORT_TYPE, UPLOAD_ABORT_V2_TYPE, UPLOAD_BEGIN_TYPE, UPLOAD_BEGIN_V2_TYPE,
    UPLOAD_CHUNK_TYPE, UPLOAD_CHUNK_V2_TYPE, UPLOAD_COMMIT_TYPE, UPLOAD_COMMIT_V2_TYPE, USAGE_TYPE,
};

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

/// Render a shared refusal as this host's reply.
fn refused(doc: &TrustTask<Value>, refusal: Refusal) -> Answer {
    match refusal {
        Refusal::Declared {
            code,
            message,
            details,
        } => coded(doc, code, message, details),
        Refusal::Malformed(reason) => reject(doc, RejectReason::MalformedRequest { reason }),
        Refusal::Unavailable { retry_after_secs } => reject(
            doc,
            RejectReason::Unavailable {
                retry_after: Some(
                    chrono::Utc::now() + chrono::Duration::seconds(retry_after_secs as i64),
                ),
            },
        ),
        Refusal::TaskFailed(reason) => reject(
            doc,
            RejectReason::TaskFailed {
                reason,
                details: None,
            },
        ),
        Refusal::App(e) => from_app_error(doc, &e),
        Refusal::Internal(reason) => reject(doc, RejectReason::InternalError { reason }),
    }
}

/// Render a shared task's answer as this host's reply.
fn render(doc: &TrustTask<Value>, result: TaskResult) -> Answer {
    match result {
        Ok(body) => respond(doc, body),
        Err(r) => refused(doc, r),
    }
}

/// Read the presentation and room, verify the chain for `action`, and return
/// the room, the authenticated presenter and the authorization.
///
/// A chain that does not confer `action` is the framework's standard
/// `permissionDenied`, as for every `rooms/*` task: the family declares no
/// task-specific code that would shadow it.
async fn authorize(
    state: &HostState,
    doc: &TrustTask<Value>,
    payload: &Value,
    action: Action,
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
        .map_err(|e| from_app_error(doc, &e))?;
    Ok((room, presenter, authorized))
}

/// The authenticated presenter of a transfer task, which carries no presentation.
async fn presenter(state: &HostState, doc: &TrustTask<Value>) -> Result<String, Answer> {
    state
        .presenter(doc)
        .await
        .map_err(|e| from_app_error(doc, &e))
}

pub(crate) async fn begin(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    // The payload is checked before the chain, so a malformed request costs no
    // verification.
    if let Err(r) = blob_tasks::parse::<
        trust_tasks_rs::specs::rooms::blobs::upload::begin::v0_1::Payload,
    >(&payload)
    {
        return refused(doc, r);
    }
    let (room, presenter, authorized) = match authorize(state, doc, &payload, Action::Write).await {
        Ok(r) => r,
        Err(a) => return a,
    };
    render(
        doc,
        blob_tasks::begin(&state.files, &room, &presenter, &authorized, &payload).await,
    )
}

pub(crate) async fn upload_chunk(
    state: &HostState,
    doc: &TrustTask<Value>,
    payload: Value,
) -> Answer {
    match presenter(state, doc).await {
        Ok(p) => render(
            doc,
            blob_tasks::upload_chunk(&state.files, &p, &payload).await,
        ),
        Err(a) => a,
    }
}

pub(crate) async fn commit(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    match presenter(state, doc).await {
        Ok(p) => render(doc, blob_tasks::commit(&state.files, &p, &payload).await),
        Err(a) => a,
    }
}

pub(crate) async fn abort(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    match presenter(state, doc).await {
        Ok(p) => render(doc, blob_tasks::abort(&state.files, &p, &payload).await),
        Err(a) => a,
    }
}

pub(crate) async fn get(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    if let Err(r) =
        blob_tasks::parse::<trust_tasks_rs::specs::rooms::blobs::get::v0_1::Payload>(&payload)
    {
        return refused(doc, r);
    }
    let (room, presenter, authorized) = match authorize(state, doc, &payload, Action::Read).await {
        Ok(r) => r,
        Err(a) => return a,
    };
    render(
        doc,
        blob_tasks::get(&state.files, &room, &presenter, &authorized, &payload).await,
    )
}

pub(crate) async fn download_chunk(
    state: &HostState,
    doc: &TrustTask<Value>,
    payload: Value,
) -> Answer {
    match presenter(state, doc).await {
        Ok(p) => render(
            doc,
            blob_tasks::download_chunk(&state.files, &p, &payload).await,
        ),
        Err(a) => a,
    }
}

/// `rooms/blobs/upload/begin/0.2`. This host stores blobs in a local directory, which
/// cannot issue storage URLs, so every upload is proxied: a producer offering only
/// `directParts` is refused `noTransferMode`.
pub(crate) async fn begin_v2(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    if let Err(r) = blob_tasks::parse::<
        trust_tasks_rs::specs::rooms::blobs::upload::begin::v0_2::Payload,
    >(&payload)
    {
        return refused(doc, r);
    }
    let (room, presenter, authorized) = match authorize(state, doc, &payload, Action::Write).await {
        Ok(r) => r,
        Err(a) => return a,
    };
    render(
        doc,
        blob_tasks::begin_v2(&state.files, &room, &presenter, &authorized, &payload).await,
    )
}

/// `rooms/blobs/upload/chunk/0.2`, signed by the upload's key.
pub(crate) async fn upload_chunk_v2(
    state: &HostState,
    doc: &TrustTask<Value>,
    payload: Value,
) -> Answer {
    match presenter(state, doc).await {
        Ok(p) => render(
            doc,
            blob_tasks::upload_chunk_v2(&state.files, &p, &payload).await,
        ),
        Err(a) => a,
    }
}

/// `rooms/blobs/upload/commit/0.2`, signed by the upload's key.
pub(crate) async fn commit_v2(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    match presenter(state, doc).await {
        Ok(p) => render(doc, blob_tasks::commit_v2(&state.files, &p, &payload).await),
        Err(a) => a,
    }
}

/// `rooms/blobs/upload/abort/0.2`, signed by the upload's key.
pub(crate) async fn abort_v2(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    match presenter(state, doc).await {
        Ok(p) => render(doc, blob_tasks::abort_v2(&state.files, &p, &payload).await),
        Err(a) => a,
    }
}

/// `rooms/blobs/get/0.2`. Always proxied here: local storage issues no URLs.
pub(crate) async fn get_blob_v2(
    state: &HostState,
    doc: &TrustTask<Value>,
    payload: Value,
) -> Answer {
    if let Err(r) =
        blob_tasks::parse::<trust_tasks_rs::specs::rooms::blobs::get::v0_2::Payload>(&payload)
    {
        return refused(doc, r);
    }
    let (room, presenter, authorized) = match authorize(state, doc, &payload, Action::Read).await {
        Ok(r) => r,
        Err(a) => return a,
    };
    render(
        doc,
        blob_tasks::get_v2(&state.files, &room, &presenter, &authorized, &payload).await,
    )
}

pub(crate) async fn info(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    if let Err(r) = blob_tasks::parse::<trust_tasks_rs::specs::rooms::info::v0_1::Payload>(&payload)
    {
        return refused(doc, r);
    }
    let (room, _presenter, authorized) = match authorize(state, doc, &payload, Action::Read).await {
        Ok(r) => r,
        Err(a) => return a,
    };
    render(
        doc,
        blob_tasks::info(&state.files, &room, &authorized, &payload).await,
    )
}

/// `rooms/usage/0.1`: who is using the room's space, for its owner. Needs `admin`.
pub(crate) async fn usage(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    if let Err(r) =
        blob_tasks::parse::<trust_tasks_rs::specs::rooms::usage::v0_1::Payload>(&payload)
    {
        return refused(doc, r);
    }
    let (room, _presenter, authorized) = match authorize(state, doc, &payload, Action::Admin).await
    {
        Ok(r) => r,
        Err(a) => return a,
    };
    render(
        doc,
        blob_tasks::usage(&state.files, &room, &authorized, &payload).await,
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
    let blobs = match blob_tasks::put_v2_blobs(&payload) {
        Ok(b) => b,
        Err(r) => return refused(doc, r),
    };
    super::put_with_blobs(state, doc, blob_tasks::as_v0_1(payload), Some(blobs)).await
}

/// `rooms/records/get/0.2`: the 0.1 read, whose answer also names the
/// record's blobs.
pub(crate) async fn get_v2(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    if let Err(r) = blob_tasks::parse::<get_v2_spec::Payload>(&payload) {
        return refused(doc, r);
    }
    super::get_versioned(state, doc, blob_tasks::as_v0_1(payload), true).await
}

/// `rooms/records/list/0.2`: the 0.1 listing, each row naming its blobs.
pub(crate) async fn list_v2(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    if let Err(r) = blob_tasks::parse::<list_v2_spec::Payload>(&payload) {
        return refused(doc, r);
    }
    super::list_versioned(state, doc, blob_tasks::as_v0_1(payload), true).await
}

/// A 0.1 get response with `blobs` added, answered as 0.2.
pub(crate) async fn get_v2_response(
    snapshot: &vti_rooms::blobs::ReadSnapshot<'_>,
    doc: &TrustTask<Value>,
    room_id: &str,
    key: &str,
    response: impl serde::Serialize,
) -> Answer {
    render(
        doc,
        blob_tasks::get_v2_response(snapshot, room_id, key, response).await,
    )
}

/// A 0.1 listing with each row's `blobs` added, answered as 0.2.
pub(crate) async fn list_v2_response(
    snapshot: &vti_rooms::blobs::ReadSnapshot<'_>,
    doc: &TrustTask<Value>,
    room_id: &str,
    response: impl serde::Serialize,
) -> Answer {
    render(
        doc,
        blob_tasks::list_v2_response(snapshot, room_id, response).await,
    )
}

/// Why `rooms/records/put` 0.2 refused a record's `blobs`, as that task's
/// declared codes.
pub(crate) fn record_blobs_refused(doc: &TrustTask<Value>, e: BlobError) -> Answer {
    refused(doc, blob_tasks::record_blobs_refused(e))
}

/// Render a `rooms/records/put` refusal the shared tasks produced.
pub(crate) fn record_refused(doc: &TrustTask<Value>, refusal: blob_tasks::Refusal) -> Answer {
    refused(doc, refusal)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
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
        for i in begun["missing"].as_array().unwrap() {
            let i = i.as_u64().unwrap() as usize;
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

    // ─── 0.2: the single-use upload key, and direct reads ──────────────────

    fn begin_v2_doc(f: &RoomFixture, b: &Blob, upload_key_did: Option<&str>) -> Value {
        let mut p = json!({
            "roomId": f.room.room_id,
            "presentation": f.as_owner(),
            "manifest": b.manifest,
        });
        if let Some(k) = upload_key_did {
            p["uploadKey"] = json!(k);
        }
        p
    }

    fn whole_part_plan(b: &Blob) -> Value {
        json!({
            "partSize": b.bytes.len(),
            "partCount": 1,
            "partDigests": [b.manifest["digest"]],
        })
    }

    /// A proxied 0.2 upload: the member begins, naming a single-use key; only that key
    /// sends the chunks and commits. The member signing as itself is `notFound`, a 0.1
    /// document never reaches the upload, and the blob is the member's — the upload key
    /// is charged, recorded and reported nowhere (begin/0.2 items 14–15).
    #[tokio::test]
    async fn a_proxied_upload_is_sent_by_its_upload_key_and_charged_to_the_member() {
        let h = host(Default::default());
        let f = room(&h).await;
        let b = blob(CHUNK + 100, 1);
        let key = Party::new();
        let (status, begun) = call(
            &h.app,
            UPLOAD_BEGIN_V2_TYPE,
            begin_v2_doc(&f, &b, Some(&key.did)),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{begun}");
        assert_eq!(begun["mode"], "proxied");
        assert!(begun.get("targets").is_none());
        let id = begun["uploadId"].as_str().unwrap().to_string();

        // The owner does not send the transfer it named a key for, in either version.
        let (_, out) = call(
            &h.app,
            UPLOAD_CHUNK_V2_TYPE,
            chunk_doc(&id, &b, 0),
            &f.owner,
        )
        .await;
        assert_eq!(code(&out), "rooms/blobs/upload/chunk:notFound");
        let (_, out) = call(&h.app, UPLOAD_CHUNK_TYPE, chunk_doc(&id, &b, 0), &f.owner).await;
        assert_eq!(code(&out), "rooms/blobs/upload/chunk:notFound");
        // Nor does the key send a 0.1 document.
        let (_, out) = call(&h.app, UPLOAD_CHUNK_TYPE, chunk_doc(&id, &b, 0), &key).await;
        assert_eq!(code(&out), "rooms/blobs/upload/chunk:notFound");

        for i in 0..2 {
            let (status, out) =
                call(&h.app, UPLOAD_CHUNK_V2_TYPE, chunk_doc(&id, &b, i), &key).await;
            assert_eq!(status, StatusCode::OK, "{out}");
        }
        let (_, out) = call(
            &h.app,
            UPLOAD_COMMIT_V2_TYPE,
            json!({ "uploadId": id }),
            &f.owner,
        )
        .await;
        assert_eq!(code(&out), "rooms/blobs/upload/commit:notFound");
        let (status, out) = call(
            &h.app,
            UPLOAD_COMMIT_V2_TYPE,
            json!({ "uploadId": id }),
            &key,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(out["blobRef"], b.blob_ref);
        // An idempotent repeat of the commit that ended it is the only thing the key
        // may still do.
        let (status, again) = call(
            &h.app,
            UPLOAD_COMMIT_V2_TYPE,
            json!({ "uploadId": id }),
            &key,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        let (_, out) = call(&h.app, UPLOAD_CHUNK_V2_TYPE, chunk_doc(&id, &b, 0), &key).await;
        assert_eq!(code(&out), "rooms/blobs/upload/chunk:notFound");

        let entry = h
            .state
            .files
            .blob(&f.room.room_id, &b.blob_ref)
            .await
            .unwrap()
            .expect("committed");
        assert_eq!(entry.charged_to.as_deref(), Some(f.room.owner_did.as_str()));
        let member = h
            .state
            .files
            .member_usage(&f.room.room_id, &f.room.owner_did)
            .await
            .unwrap();
        assert_eq!(member.files, 1);
        let key_usage = h
            .state
            .files
            .member_usage(&f.room.room_id, &key.did)
            .await
            .unwrap();
        assert_eq!(key_usage.files + key_usage.reserved_files, 0);
        let raw = serde_json::to_string(&entry).unwrap();
        assert!(
            !raw.contains(&key.did),
            "the upload key is recorded nowhere"
        );
    }

    /// Resume rebinds the slot to the key the new begin names, so a client that lost its
    /// key can finish; the old key is refused from then on, and the reservation is not
    /// taken twice (begin/0.2 item 8). A key bound to another open upload is refused.
    #[tokio::test]
    async fn resume_rebinds_the_upload_key_and_refuses_the_old_one() {
        let h = host(Default::default());
        let f = room(&h).await;
        let b = blob(CHUNK * 2, 2);
        let (old, new) = (Party::new(), Party::new());
        let (_, first) = call(
            &h.app,
            UPLOAD_BEGIN_V2_TYPE,
            begin_v2_doc(&f, &b, Some(&old.did)),
            &f.owner,
        )
        .await;
        let id = first["uploadId"].as_str().unwrap().to_string();
        let (status, _) = call(&h.app, UPLOAD_CHUNK_V2_TYPE, chunk_doc(&id, &b, 0), &old).await;
        assert_eq!(status, StatusCode::OK);
        let reserved = info(&h, &f).await["usage"]["room"]["reservedBytes"].clone();

        // Another upload may not take a key that is bound to an open one.
        let other = blob(CHUNK, 3);
        let (_, out) = call(
            &h.app,
            UPLOAD_BEGIN_V2_TYPE,
            begin_v2_doc(&f, &other, Some(&old.did)),
            &f.owner,
        )
        .await;
        assert_eq!(code(&out), "rooms/blobs/upload/begin:uploadKeyInUse");

        let (status, resumed) = call(
            &h.app,
            UPLOAD_BEGIN_V2_TYPE,
            begin_v2_doc(&f, &b, Some(&new.did)),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{resumed}");
        assert_eq!(resumed["uploadId"], id.as_str());
        assert_eq!(resumed["missing"], json!([1]));
        assert_eq!(
            info(&h, &f).await["usage"]["room"]["reservedBytes"],
            reserved
        );

        let (_, out) = call(&h.app, UPLOAD_CHUNK_V2_TYPE, chunk_doc(&id, &b, 1), &old).await;
        assert_eq!(code(&out), "rooms/blobs/upload/chunk:notFound");
        let (status, _) = call(&h.app, UPLOAD_CHUNK_V2_TYPE, chunk_doc(&id, &b, 1), &new).await;
        assert_eq!(status, StatusCode::OK);
        let (_, out) = call(
            &h.app,
            UPLOAD_ABORT_V2_TYPE,
            json!({ "uploadId": id }),
            &old,
        )
        .await;
        assert_eq!(code(&out), "rooms/blobs/upload/abort:notFound");
        let (status, out) = call(
            &h.app,
            UPLOAD_ABORT_V2_TYPE,
            json!({ "uploadId": id }),
            &new,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(out["aborted"], true);
        assert_eq!(info(&h, &f).await["usage"]["room"]["reservedBytes"], 0);
    }

    /// Local storage issues no URLs, so a producer that offers only a part plan has no
    /// mode in common with this host; an inconsistent plan is refused as such.
    #[tokio::test]
    async fn direct_only_is_no_transfer_mode_on_storage_that_cannot_presign() {
        let h = host(Default::default());
        let f = room(&h).await;
        let b = blob(CHUNK, 4);
        let mut p = begin_v2_doc(&f, &b, None);
        p["directParts"] = whole_part_plan(&b);
        let (_, out) = call(&h.app, UPLOAD_BEGIN_V2_TYPE, p.clone(), &f.owner).await;
        assert_eq!(
            code(&out),
            "rooms/blobs/upload/begin:noTransferMode",
            "{out}"
        );
        assert_eq!(out["details"]["modes"], json!(["proxied"]));
        assert_eq!(info(&h, &f).await["usage"]["room"]["reservedBytes"], 0);

        // Offering a key as well, it is proxied.
        let key = Party::new();
        p["uploadKey"] = json!(key.did);
        let (status, begun) = call(&h.app, UPLOAD_BEGIN_V2_TYPE, p.clone(), &f.owner).await;
        assert_eq!(status, StatusCode::OK, "{begun}");
        assert_eq!(begun["mode"], "proxied");

        p["directParts"]["partCount"] = json!(2);
        p["directParts"]["partDigests"] = json!([b.manifest["digest"], b.manifest["digest"]]);
        let (_, out) = call(&h.app, UPLOAD_BEGIN_V2_TYPE, p, &f.owner).await;
        assert_eq!(code(&out), "rooms/blobs/upload/begin:invalidParts", "{out}");
    }

    /// Local storage, wrapped so it presigns reads: what a store reached through
    /// presigned requests answers [`BlobStore::read_target`] with.
    struct Presigning {
        inner: vti_common::blob_store::local::LocalDirStore,
        lifetime: chrono::Duration,
    }

    #[async_trait::async_trait]
    impl vti_common::blob_store::BlobStore for Presigning {
        fn kind(&self) -> &'static str {
            self.inner.kind()
        }
        async fn put(
            &self,
            key: &vti_common::blob_store::BlobKey,
            staged: &std::path::Path,
            size: u64,
        ) -> Result<vti_common::blob_store::BackendRef, vti_common::error::AppError> {
            self.inner.put(key, staged, size).await
        }
        async fn get_range(
            &self,
            at: &vti_common::blob_store::BackendRef,
            start: u64,
            end: u64,
        ) -> Result<Vec<u8>, vti_common::error::AppError> {
            self.inner.get_range(at, start, end).await
        }
        async fn delete(
            &self,
            at: &vti_common::blob_store::BackendRef,
        ) -> Result<vti_common::blob_store::Deletion, vti_common::error::AppError> {
            self.inner.delete(at).await
        }
        async fn health(&self) -> vti_common::blob_store::Health {
            self.inner.health().await
        }
        async fn read_target(
            &self,
            at: &vti_common::blob_store::BackendRef,
        ) -> Result<Option<vti_common::blob_store::PresignedRequest>, vti_common::error::AppError>
        {
            Ok(Some(vti_common::blob_store::PresignedRequest {
                method: "GET".into(),
                url: format!(
                    "https://bucket.example/{}?X-Amz-Signature=secret",
                    at.key.as_str()
                ),
                headers: Default::default(),
                expires_at: chrono::Utc::now() + self.lifetime,
            }))
        }
    }

    fn presigning_host(lifetime: chrono::Duration) -> Host {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Presigning {
            inner: vti_common::blob_store::local::LocalDirStore::new(dir.path().join("b")),
            lifetime,
        });
        let state = open_state_with_files(
            dir.path(),
            vti_common::auth::TrustTaskVmResolver::did_key_only(),
            FilesConfig {
                store: Some(store),
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

    async fn get_v2(h: &Host, f: &RoomFixture, blob_ref: &str, direct: bool) -> Value {
        let (status, out) = call(
            &h.app,
            BLOB_GET_V2_TYPE,
            json!({
                "roomId": f.room.room_id,
                "presentation": f.as_owner(),
                "blobRef": blob_ref,
                "direct": direct,
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        out
    }

    /// A reader who accepts a storage URL, on storage that issues one, gets a GET for
    /// the one object, expiring within five minutes; the download is counted when it is
    /// issued, at the blob's size, since its bytes never pass through the host.
    #[tokio::test]
    async fn get_v2_is_direct_where_storage_presigns_and_counts_the_download() {
        let h = presigning_host(chrono::Duration::minutes(5));
        let f = room(&h).await;
        let b = blob(CHUNK + 7, 5);
        let blob_ref = upload(&h, &f, &b).await;

        let out = get_v2(&h, &f, &blob_ref, true).await;
        assert_eq!(out["mode"], "direct", "{out}");
        assert_eq!(out["manifest"], b.manifest);
        assert!(out.get("downloadId").is_none());
        assert_eq!(out["target"]["method"], "GET");
        assert_eq!(out["target"]["index"], 0);
        assert!(
            out["target"]["url"]
                .as_str()
                .unwrap()
                .starts_with("https://")
        );
        let expires: chrono::DateTime<chrono::Utc> =
            serde_json::from_value(out["expiresAt"].clone()).unwrap();
        assert!(expires <= chrono::Utc::now() + chrono::Duration::seconds(301));
        assert_eq!(out["expiresAt"], out["target"]["expiresAt"]);

        let today = chrono::Utc::now().date_naive();
        let a = h
            .state
            .files
            .room_activity(&f.room.room_id, today, today)
            .await
            .unwrap();
        assert_eq!(a.downloads, 1);
        assert_eq!(a.egress_bytes, b.bytes.len() as u64);

        // Not asked for: proxied, with a download handle.
        let out = get_v2(&h, &f, &blob_ref, false).await;
        assert_eq!(out["mode"], "proxied");
        assert!(out["downloadId"].is_string() && out.get("target").is_none());
    }

    /// A target that would outlive five minutes is never handed out: the host answers
    /// through itself instead.
    #[tokio::test]
    async fn a_long_lived_read_target_is_never_issued() {
        let h = presigning_host(chrono::Duration::hours(1));
        let f = room(&h).await;
        let b = blob(CHUNK, 6);
        let blob_ref = upload(&h, &f, &b).await;
        let out = get_v2(&h, &f, &blob_ref, true).await;
        assert_eq!(out["mode"], "proxied", "{out}");
    }

    /// Local storage issues no URLs: a 0.2 read there is proxied and its chunks come
    /// through the host as for 0.1.
    #[tokio::test]
    async fn get_v2_on_local_storage_is_proxied() {
        let h = host(Default::default());
        let f = room(&h).await;
        let b = blob(CHUNK, 7);
        let blob_ref = upload(&h, &f, &b).await;
        let out = get_v2(&h, &f, &blob_ref, true).await;
        assert_eq!(out["mode"], "proxied");
        let (status, c) = call(
            &h.app,
            DOWNLOAD_CHUNK_TYPE,
            json!({ "downloadId": out["downloadId"], "index": 0 }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{c}");
    }

    /// The client's 0.2 path: the member begins and reads, a fresh upload key sends and
    /// commits, and the bytes come back through the host where storage cannot presign.
    #[tokio::test]
    async fn a_file_round_trips_through_the_client_at_0_2() {
        use vtc_client::VtcClient;
        use vtc_client::rooms::RoomSession;
        use vti_rooms::files::{self, FileBinding, Padding};

        let h = host(eager());
        let f = room(&h).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = h.app.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = VtcClient::anonymous(&url, "did:key:zHost");
        let owner = f.as_owner();
        let session =
            RoomSession::new(&f.room.room_id, &owner.membership, owner.authority.clone()).unwrap();
        let (did, secret) = (f.owner.did.as_str(), f.owner.secret_multibase.as_str());
        let plaintext: Vec<u8> = (0..30_000u32).map(|i| (i % 249) as u8).collect();
        let sealed = files::seal_file(
            &[3u8; 32],
            FileBinding {
                room_id: f.room.room_id.clone(),
                file_id: files::new_file_id(),
                epoch: 1,
                segment_size: 16_384 - files::TAG_LEN,
            },
            "notes.txt",
            None,
            &plaintext,
            Padding::None,
        )
        .unwrap();

        let key = Party::new();
        let begun = client
            .begin_upload_v2::<_, Value>(&session, &sealed.blob, Some(&key.did), None, did, secret)
            .await
            .expect("begin");
        assert_eq!(begun.mode.to_string(), "proxied");
        let upload_id = begun.upload_id.to_string();
        for index in &begun.missing {
            let i = index.0 as usize;
            client
                .upload_chunk_v2(
                    &upload_id,
                    i as u64,
                    &sealed.chunks[i],
                    &key.did,
                    &key.secret_multibase,
                )
                .await
                .expect("chunk, signed by the upload key");
        }
        let committed = client
            .commit_upload_v2(&upload_id, &key.did, &key.secret_multibase)
            .await
            .expect("commit, signed by the upload key");
        let blob_ref = committed.blob_ref.to_string();
        assert!(files::same_digest(&blob_ref, &sealed.file.blob_ref));

        let got = client
            .get_blob_v2(&session, &blob_ref, true, did, secret)
            .await
            .expect("get");
        assert_eq!(got.mode.to_string(), "proxied");
        let download_id = got.download_id.expect("a handle").to_string();
        for i in 0..sealed.chunks.len() {
            let chunk = client
                .download_chunk(&download_id, i as u64, did, secret)
                .await
                .unwrap();
            assert_eq!(chunk, sealed.chunks[i]);
        }
    }

    // ─── 0.2 direct uploads, against an S3-shaped store ────────────────────

    const PART: usize = vti_common::blob_store::MIN_MULTIPART_PART_BYTES as usize;

    fn direct_host(s3: &vti_common::blob_store::mock_s3::MockS3) -> Host {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::blob_store::presigned::PresignedBlobs::new(
            "s3",
            s3.presigner(),
            Some("community/"),
        )
        .unwrap()
        .with_plain_http();
        let state = open_state_with_files(
            dir.path(),
            vti_common::auth::TrustTaskVmResolver::did_key_only(),
            FilesConfig {
                store: Some(Arc::new(store)),
                config_id: Some("s3".into()),
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

    fn part_plan(b: &Blob, part: usize) -> Value {
        let digests: Vec<String> = b
            .bytes
            .chunks(part)
            .map(|c| sha256_digest_multibase(&Sha256::digest(c).into()))
            .collect();
        json!({ "partSize": part, "partCount": digests.len(), "partDigests": digests })
    }

    async fn begin_direct(h: &Host, f: &RoomFixture, b: &Blob, part: usize) -> (StatusCode, Value) {
        call(
            &h.app,
            UPLOAD_BEGIN_V2_TYPE,
            json!({
                "roomId": f.room.room_id,
                "presentation": f.as_owner(),
                "manifest": b.manifest,
                "directParts": part_plan(b, part),
            }),
            &f.owner,
        )
        .await
    }

    /// What a member's client does with a target: exactly its method and headers.
    async fn put_target(target: &Value, bytes: &[u8]) -> reqwest::StatusCode {
        let url = target["url"]
            .as_str()
            .unwrap()
            .replacen("https://", "http://", 1);
        let mut req = reqwest::Client::new().put(url);
        for (k, v) in target["headers"].as_object().unwrap() {
            req = req.header(k, v.as_str().unwrap());
        }
        req.body(bytes.to_vec()).send().await.unwrap().status()
    }

    /// Begin → write each part to its bound target → commit (verified at storage)
    /// → a record names the blob → read it back direct. Charged to the member at
    /// commit; no byte passed through the host.
    #[tokio::test]
    async fn a_direct_upload_is_verified_at_storage_before_it_is_recorded() {
        let s3 = vti_common::blob_store::mock_s3::MockS3::start(true).await;
        let h = direct_host(&s3);
        let f = room(&h).await;
        let b = blob(PART + 300_000, 11);
        let (status, begun) = begin_direct(&h, &f, &b, PART).await;
        assert_eq!(status, StatusCode::OK, "{begun}");
        assert_eq!(begun["mode"], "direct");
        assert_eq!(begun["missing"], json!([0, 1]));
        let targets = begun["targets"].as_array().unwrap().clone();
        assert_eq!(targets.len(), 2);
        for t in &targets {
            assert_eq!(t["method"], "PUT");
            assert!(t["url"].as_str().unwrap().starts_with("https://"));
            assert!(t["headers"]["x-amz-checksum-sha256"].is_string());
            assert!(t["headers"]["Content-Length"].is_string());
            let exp: chrono::DateTime<chrono::Utc> =
                serde_json::from_value(t["expiresAt"].clone()).unwrap();
            assert!(exp <= chrono::Utc::now() + chrono::Duration::seconds(301));
        }
        let id = begun["uploadId"].as_str().unwrap().to_string();
        // Storage refuses bytes other than the part's.
        assert_eq!(
            put_target(&targets[0], &b.bytes[1..PART + 1]).await,
            reqwest::StatusCode::BAD_REQUEST
        );
        assert!(put_target(&targets[0], &b.bytes[..PART]).await.is_success());

        // One part is missing: `incomplete`, and a re-begin answers only it.
        let (_, out) = call(
            &h.app,
            UPLOAD_COMMIT_V2_TYPE,
            json!({ "uploadId": id }),
            &f.owner,
        )
        .await;
        assert_eq!(code(&out), "rooms/blobs/upload/commit:incomplete", "{out}");
        let (_, again) = begin_direct(&h, &f, &b, PART).await;
        assert_eq!(again["uploadId"], id.as_str());
        assert_eq!(again["missing"], json!([1]));
        assert!(
            put_target(&again["targets"][0], &b.bytes[PART..])
                .await
                .is_success()
        );

        // Only the owner commits a direct upload.
        let (_, out) = call(
            &h.app,
            UPLOAD_COMMIT_V2_TYPE,
            json!({ "uploadId": id }),
            &Party::new(),
        )
        .await;
        assert_eq!(code(&out), "rooms/blobs/upload/commit:notFound");
        let (status, out) = call(
            &h.app,
            UPLOAD_COMMIT_V2_TYPE,
            json!({ "uploadId": id }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(out["blobRef"], b.blob_ref);
        assert_eq!(s3.open_uploads(), 0);
        assert_eq!(info(&h, &f).await["usage"]["room"]["files"], 1);
        assert_eq!(info(&h, &f).await["usage"]["room"]["reservedBytes"], 0);

        let (status, out) = put_record(&h, &f, "giXFLTGBdnnQJRoIsktuIg", &[&b.blob_ref]).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        let got = get_v2(&h, &f, &b.blob_ref, false).await;
        assert_eq!(got["mode"], "proxied");
        let (status, c) = call(
            &h.app,
            DOWNLOAD_CHUNK_TYPE,
            json!({ "downloadId": got["downloadId"], "index": 0 }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{c}");
    }

    /// Storage that does not enforce the signed checksum accepts other bytes; the
    /// commit catches them at storage, deletes what is there and refuses.
    #[tokio::test]
    async fn a_tampered_direct_upload_is_refused_and_deleted() {
        let s3 = vti_common::blob_store::mock_s3::MockS3::start(false).await;
        let h = direct_host(&s3);
        let f = room(&h).await;
        let b = blob(PART + 1000, 12);
        let (_, begun) = begin_direct(&h, &f, &b, PART).await;
        let id = begun["uploadId"].as_str().unwrap().to_string();
        let mut forged = b.bytes[..PART].to_vec();
        forged[7] ^= 0xff;
        assert!(put_target(&begun["targets"][0], &forged).await.is_success());
        assert!(
            put_target(&begun["targets"][1], &b.bytes[PART..])
                .await
                .is_success()
        );
        let (_, out) = call(
            &h.app,
            UPLOAD_COMMIT_V2_TYPE,
            json!({ "uploadId": id }),
            &f.owner,
        )
        .await;
        assert_eq!(
            code(&out),
            "rooms/blobs/upload/commit:digestMismatch",
            "{out}"
        );
        assert_eq!(s3.open_uploads(), 0);
        assert!(s3.objects().is_empty());
        assert_eq!(info(&h, &f).await["usage"]["room"]["reservedBytes"], 0);
        assert!(
            h.state
                .files
                .blob(&f.room.room_id, &b.blob_ref)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Abort takes the parts storage holds, and a lapsed upload's are taken by the
    /// sweep; either way the reservation comes back.
    #[tokio::test]
    async fn abort_and_the_sweep_reclaim_a_direct_upload_at_storage() {
        let s3 = vti_common::blob_store::mock_s3::MockS3::start(true).await;
        let h = direct_host(&s3);
        let f = room(&h).await;
        let b = blob(PART + 10, 13);
        let (_, begun) = begin_direct(&h, &f, &b, PART).await;
        let id = begun["uploadId"].as_str().unwrap().to_string();
        assert!(
            put_target(&begun["targets"][0], &b.bytes[..PART])
                .await
                .is_success()
        );
        let (status, out) = call(
            &h.app,
            UPLOAD_ABORT_V2_TYPE,
            json!({ "uploadId": id }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(out["aborted"], true);
        assert_eq!(s3.open_uploads(), 0);
        assert_eq!(info(&h, &f).await["usage"]["room"]["reservedBytes"], 0);

        let other = blob(PART + 20, 14);
        let (_, begun) = begin_direct(&h, &f, &other, PART).await;
        assert!(
            put_target(&begun["targets"][0], &other.bytes[..PART])
                .await
                .is_success()
        );
        assert_eq!(s3.open_uploads(), 1);
        h.state.files.lapse_direct_uploads().await.unwrap();
        let stats = h.state.files.sweep().await.unwrap();
        assert_eq!(stats.released, 1);
        assert_eq!(
            s3.open_uploads(),
            0,
            "the sweep aborts the multipart upload"
        );
        assert_eq!(info(&h, &f).await["usage"]["room"]["reservedBytes"], 0);
    }

    /// One part is one bound PUT; a plan whose parts storage could not take, from a
    /// producer with no upload key, is no mode at all — naming both the host has.
    #[tokio::test]
    async fn a_single_part_plan_is_one_put_and_an_unsuitable_plan_has_no_mode() {
        let s3 = vti_common::blob_store::mock_s3::MockS3::start(true).await;
        let h = direct_host(&s3);
        let f = room(&h).await;
        let b = blob(40_000, 15);
        let (_, begun) = begin_direct(&h, &f, &b, b.bytes.len()).await;
        assert_eq!(begun["mode"], "direct", "{begun}");
        assert!(
            put_target(&begun["targets"][0], &b.bytes)
                .await
                .is_success()
        );
        let (status, out) = call(
            &h.app,
            UPLOAD_COMMIT_V2_TYPE,
            json!({ "uploadId": begun["uploadId"] }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");

        let small = blob(40_000, 16);
        let (_, out) = begin_direct(&h, &f, &small, 16_384).await;
        assert_eq!(
            code(&out),
            "rooms/blobs/upload/begin:noTransferMode",
            "{out}"
        );
        assert_eq!(out["details"]["modes"], json!(["direct", "proxied"]));
    }

    /// The owner's read of who is using the room: one entry per member who has
    /// stored something, under the member at the root of their chain.
    #[tokio::test]
    async fn the_owner_sees_usage_by_member() {
        let h = host(HostLimits::default());
        let f = room(&h).await;
        let b = blob(1000, 1);
        upload(&h, &f, &b).await;
        let (status, out) = call(
            &h.app,
            USAGE_TYPE,
            json!({ "roomId": f.room.room_id, "presentation": f.as_owner() }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        let members = out["members"].as_array().expect("members");
        assert_eq!(members.len(), 1, "{out}");
        assert_eq!(members[0]["usage"]["files"], 1);
        assert_eq!(members[0]["usage"]["bytes"], 1000);
        assert!(members[0]["lastUploadAt"].is_string(), "{out}");
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

    /// Uploading the same file twice stores and charges it once: begin says
    /// it is already there, reserves nothing, and commit answers with it.
    #[tokio::test]
    async fn a_second_upload_of_a_committed_blob_is_not_stored_twice() {
        let h = host(HostLimits::default());
        let f = room(&h).await;
        let b = blob(CHUNK + 1, 3);
        upload(&h, &f, &b).await;
        let (status, begun) = begin(&h, &f, &b).await;
        assert_eq!(status, StatusCode::OK, "{begun}");
        assert_eq!(begun["alreadyCommitted"], json!(true));
        assert_eq!(begun["missing"], json!([]));
        assert_eq!(
            info(&h, &f).await["usage"]["room"]["reservedFiles"],
            json!(0)
        );
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
        assert_eq!(
            code(&out),
            "permissionDenied",
            "the standard code, not a shadow"
        );

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

    /// In another room, the same BlobRef is uploaded again: another room's
    /// copy is never reported.
    #[tokio::test]
    async fn another_rooms_copy_is_never_reported() {
        let h = host(HostLimits::default());
        let (a, other) = (room(&h).await, room(&h).await);
        let b = blob(CHUNK, 20);
        upload(&h, &a, &b).await;
        let (_, begun) = begin(&h, &other, &b).await;
        assert!(begun.get("alreadyCommitted").is_none(), "{begun}");
        assert_eq!(begun["missing"], json!([0]));
    }

    #[tokio::test]
    async fn too_many_open_uploads_is_its_own_retryable_refusal() {
        let h = host(HostLimits::default());
        let f = room(&h).await;
        for seed in 0..3 {
            let (status, out) = begin(&h, &f, &blob(CHUNK, 30 + seed)).await;
            assert_eq!(status, StatusCode::OK, "{out}");
        }
        let (_, out) = begin(&h, &f, &blob(CHUNK, 40)).await;
        assert_eq!(code(&out), "rooms/blobs/upload/begin:tooManyUploads");
        assert_eq!(out["retryable"], json!(true));
        assert_eq!(out["details"]["maxOpen"], json!(3));
    }

    /// For `maxFileBytes` the refusal names where the smallest limit was set,
    /// not merely the narrowest scope that has one.
    #[tokio::test]
    async fn the_smallest_file_limit_is_the_one_named() {
        let h = host(HostLimits {
            member: ScopeLimits {
                max_file_bytes: Some(CHUNK as u64 * 4),
                ..Default::default()
            },
            room: ScopeLimits {
                max_file_bytes: Some(CHUNK as u64),
                ..Default::default()
            },
            ..Default::default()
        });
        let f = room(&h).await;
        let (_, out) = begin(&h, &f, &blob(CHUNK * 5, 41)).await;
        assert_eq!(out["details"]["scope"], json!("room"));
        assert_eq!(out["details"]["limit"], json!(CHUNK));
    }

    /// Reviving an orphan charges it again and is checked against limits.
    #[tokio::test]
    async fn re_referencing_an_orphan_is_charged_and_checked() {
        let h = host(HostLimits {
            member: ScopeLimits {
                max_files: Some(1),
                ..Default::default()
            },
            ..Default::default()
        });
        let f = room(&h).await;
        let (a, b) = (blob(CHUNK, 50), blob(CHUNK, 51));
        let ra = upload(&h, &f, &a).await;
        put_record(&h, &f, "a", &[&ra]).await;
        put_record(&h, &f, "a", &[]).await; // orphaned: the member has room again
        let rb = upload(&h, &f, &b).await;
        put_record(&h, &f, "b", &[&rb]).await;

        let (_, out) = put_record(&h, &f, "a", &[&ra]).await;
        assert_eq!(code(&out), "rooms/records/put:limitExceeded", "{out}");
        assert_eq!(out["details"]["scope"], json!("member"));
        assert_eq!(
            info(&h, &f).await["usage"]["member"]["usage"]["files"],
            json!(1)
        );

        // Room made: the revival is charged.
        put_record(&h, &f, "b", &[]).await;
        let (status, out) = put_record(&h, &f, "a", &[&ra]).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(
            info(&h, &f).await["usage"]["member"]["usage"]["files"],
            json!(1)
        );
    }

    /// get and list 0.2 name the blobs a record keeps alive; 0.1 cannot.
    #[tokio::test]
    async fn reads_at_0_2_name_the_records_blobs() {
        let h = host(HostLimits::default());
        let f = room(&h).await;
        let b = blob(CHUNK, 60);
        let r = upload(&h, &f, &b).await;
        put_record(&h, &f, "with-file", &[&r]).await;
        put_record(&h, &f, "without", &[]).await;

        let (status, got) = call(
            &h.app,
            GET_V2_TYPE,
            json!({ "roomId": f.room.room_id, "key": "with-file", "presentation": f.as_owner() }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{got}");
        assert_eq!(got["blobs"], json!([r]));

        let (status, listed) = call(
            &h.app,
            LIST_V2_TYPE,
            json!({ "roomId": f.room.room_id, "presentation": f.as_owner() }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        let rows = listed["records"].as_array().unwrap();
        let row = |k: &str| rows.iter().find(|r| r["key"] == json!(k)).unwrap().clone();
        assert_eq!(row("with-file")["blobs"], json!([r]));
        assert!(row("without").get("blobs").is_none());

        let (_, old) = call(
            &h.app,
            vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
            json!({ "roomId": f.room.room_id, "key": "with-file", "presentation": f.as_owner() }),
            &f.owner,
        )
        .await;
        assert!(old.get("blobs").is_none(), "0.1 has no such member: {old}");
    }

    /// A document larger than its specification bounds is refused before it
    /// is acted on.
    #[tokio::test]
    async fn an_oversized_document_is_refused_at_its_bound() {
        let h = host(HostLimits::default());
        let f = room(&h).await;
        let (_, out) = call(
            &h.app,
            UPLOAD_BEGIN_TYPE,
            json!({
                "roomId": f.room.room_id,
                "presentation": f.as_owner(),
                "manifest": blob(CHUNK, 70).manifest,
                "padding": "x".repeat(340_000),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(code(&out), "malformedRequest");
        assert!(out["message"].as_str().unwrap().contains("327680"), "{out}");
    }

    /// A 0.2 read never pairs one version's record with another's `blobs`:
    /// writes flip a record between two files while reads run beside them,
    /// and every read must see a title and a blob from the same write.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reads_at_0_2_never_mix_versions_under_concurrent_writes() {
        let h = Arc::new(host(HostLimits::default()));
        let f = Arc::new(room(&h).await);
        let ra = upload(&h, &f, &blob(CHUNK, 80)).await;
        let rb = upload(&h, &f, &blob(CHUNK, 81)).await;
        let expected = |title: &str| if title == "A" { ra.clone() } else { rb.clone() };

        let writer = {
            let (h, f, ra, rb) = (h.clone(), f.clone(), ra.clone(), rb.clone());
            tokio::spawn(async move {
                for i in 0..40 {
                    let (title, b) = if i % 2 == 0 { ("A", &ra) } else { ("B", &rb) };
                    let (status, out) = call(
                        &h.app,
                        PUT_V2_TYPE,
                        json!({
                            "roomId": f.room.room_id,
                            "key": "flip",
                            "presentation": f.as_owner(),
                            "cleartext": { "title": title, "body": title },
                            "blobs": [b],
                        }),
                        &f.owner,
                    )
                    .await;
                    assert_eq!(status, StatusCode::OK, "{out}");
                }
            })
        };
        let mut reads = 0;
        while !writer.is_finished() {
            let (status, got) = call(
                &h.app,
                GET_V2_TYPE,
                json!({ "roomId": f.room.room_id, "key": "flip", "presentation": f.as_owner() }),
                &f.owner,
            )
            .await;
            if status == StatusCode::OK {
                let title = got["record"]["cleartext"]["title"]
                    .as_str()
                    .or_else(|| got["cleartext"]["title"].as_str())
                    .unwrap_or_default()
                    .to_string();
                assert_eq!(
                    got["blobs"],
                    json!([expected(&title)]),
                    "get mixed versions: {got}"
                );
                reads += 1;
            }
            let (status, listed) = call(
                &h.app,
                LIST_V2_TYPE,
                json!({ "roomId": f.room.room_id, "prefix": "flip", "presentation": f.as_owner() }),
                &f.owner,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{listed}");
            if let Some(row) = listed["records"].as_array().and_then(|r| r.first()) {
                let title = row["title"].as_str().unwrap_or_default().to_string();
                assert_eq!(
                    row["blobs"],
                    json!([expected(&title)]),
                    "list mixed versions: {row}"
                );
            }
        }
        writer.await.unwrap();
        assert!(reads > 0, "the reads ran beside the writes");
    }

    /// A member's whole file path through the real client, against this host served on a
    /// socket: seal a file, upload its ciphertext, write a record whose signed body names
    /// it, then read the record, verify the body, download and check every chunk, and open
    /// the file. Only the VTA is absent: the file key and the record's seal are local here,
    /// which the host cannot tell apart, since it never holds either.
    #[tokio::test]
    async fn a_file_round_trips_through_the_client_with_a_signed_body() {
        use vtc_client::VtcClient;
        use vtc_client::rooms::RoomSession;
        use vtc_client::rooms::SealedContent;
        use vtc_client::rooms::body::{RecordLocation, SealedRecordBody, verify_record_body};
        use vti_rooms::files::{self, BlobManifest, FileBinding, Padding};

        let h = host(eager());
        let f = RoomFixture::new(Visibility::Attributed).await;
        let (status, body) = call(
            &h.app,
            vti_rooms::wire::ROOMS_CREATE_TYPE,
            json!({ "roomId": f.room.room_id, "ownerDid": f.room.owner_did, "visibility": "attributed" }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = h.app.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = VtcClient::anonymous(&url, "did:key:zHost");
        let owner = f.as_owner();
        let session =
            RoomSession::new(&f.room.room_id, &owner.membership, owner.authority.clone()).unwrap();
        let (did, secret) = (f.owner.did.as_str(), f.owner.secret_multibase.as_str());
        let room_id = f.room.room_id.as_str();

        // Seal: three segments' worth, so the chunks are checked in order.
        let plaintext: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let key = [7u8; 32];
        let sealed = files::seal_file(
            &key,
            FileBinding {
                room_id: room_id.to_string(),
                file_id: files::new_file_id(),
                epoch: 1,
                segment_size: 16_384 - files::TAG_LEN,
            },
            "term sheet.pdf",
            Some("application/pdf"),
            &plaintext,
            Padding::None,
        )
        .unwrap();

        // Upload.
        let begun = client
            .begin_upload(&session, &sealed.blob, did, secret)
            .await
            .expect("begin");
        assert_eq!(
            begun.missing.len(),
            sealed.chunks.len(),
            "a new upload needs every chunk"
        );
        let upload_id = serde_json::to_value(&begun.upload_id).unwrap();
        let upload_id = upload_id.as_str().unwrap();
        for index in &begun.missing {
            let i = index.0 as usize;
            client
                .upload_chunk(upload_id, i as u64, &sealed.chunks[i], did, secret)
                .await
                .expect("chunk");
        }
        let committed = client
            .commit_upload(upload_id, did, secret)
            .await
            .expect("commit");
        let blob_ref = serde_json::to_value(&committed.blob_ref)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        assert!(files::same_digest(&blob_ref, &sealed.file.blob_ref));

        // Write the record: a signed body naming the file, sealed (here, only encoded: the
        // host cannot tell), naming the blob in the clear.
        let record_key = "giXFLTGBdnnQJRoIsktuIg";
        let holder = vta_sdk::trust_task_sign::HolderKey::from_did_key(did, secret).unwrap();
        let mut content = SealedRecordBody::new(
            RecordLocation {
                room_id,
                key: record_key,
                version: 1,
            },
            did,
        );
        content.title = Some("Term sheet v3".into());
        content.file = Some(sealed.file.clone());
        let signed = content.sign(&holder).await.unwrap();
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let put = client
            .put_sealed_record_with_blobs(
                &session,
                record_key,
                SealedContent {
                    ciphertext: b64(&signed),
                    nonce: b64(&[0u8; 12]),
                    epoch: 1,
                },
                std::slice::from_ref(&blob_ref),
                Some(0),
                did,
                secret,
            )
            .await
            .expect("put");
        assert_eq!(
            put.version.get(),
            1,
            "the first record in a room takes version 1"
        );

        // Read it back and verify the body against where it was read.
        let record = client
            .get_record_v2(&session, record_key, did, secret)
            .await
            .expect("get");
        let names: Vec<String> = record
            .blobs
            .iter()
            .flatten()
            .map(|b| {
                serde_json::to_value(b)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(names, vec![blob_ref.clone()], "the record names its blob");
        let opened = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&record.sealed.as_ref().unwrap().ciphertext)
            .unwrap();
        let verified = verify_record_body(
            &opened,
            RecordLocation {
                room_id,
                key: record_key,
                version: record.version.get(),
            },
            record.author.as_deref(),
            &vta_sdk::trust_task_proof::TrustTaskVmResolver::did_key_only(),
        )
        .await
        .expect("the body verifies where it was read, for the author the host recorded");
        let file = verified.body().file.clone().unwrap();

        // Download, check, open.
        let started = client
            .get_blob(&session, &file.blob_ref, did, secret)
            .await
            .expect("get blob");
        let blob: BlobManifest =
            serde_json::from_value(serde_json::to_value(&started.manifest).unwrap()).unwrap();
        file.check_blob(&blob)
            .expect("the host's manifest is the author's blob");
        let download_id = serde_json::to_value(&started.download_id).unwrap();
        let mut chunks = Vec::new();
        for (i, expected) in blob.chunks.chunk_digests.iter().enumerate() {
            let chunk = client
                .download_chunk(download_id.as_str().unwrap(), i as u64, did, secret)
                .await
                .expect("chunk");
            assert!(files::same_digest(
                &files::digest_multibase(&chunk),
                expected
            ));
            chunks.push(chunk);
        }
        let back = files::open_file(&key, room_id, &file, &blob, &chunks).expect("opens");
        assert_eq!(back, plaintext);

        // The room's info says what tier this is, which is how a client decides to seal.
        let info = client.room_info(&session, did, secret).await.expect("info");
        assert_eq!(serde_json::to_value(info.visibility).unwrap(), "attributed");
    }
}
