//! Moving a room file's ciphertext: `rooms/blobs/upload/*`, `rooms/blobs/{get,chunk}` and
//! the record put that names a blob (`rooms/records/put/0.2`).
//!
//! What goes over these calls is ciphertext and its manifest, never a key and never a file
//! name: a file is sealed before [`VtcClient::begin_upload`] and opened after
//! [`VtcClient::download_chunk`], by a party holding that one file's key (`vti_rooms::files`).
//!
//! The payloads and responses are the generated `trust_tasks_rs::specs::rooms` types. Each
//! payload is built through its generated type, so a value the schema refuses is refused
//! here rather than by the host.

use serde::Serialize;
use serde::de::DeserializeOwned;
use trust_tasks_rs::Payload as _;
use trust_tasks_rs::specs::rooms::blobs::chunk::v0_1 as download_chunk;
use trust_tasks_rs::specs::rooms::blobs::get::v0_1 as blob_get;
use trust_tasks_rs::specs::rooms::blobs::upload::{
    abort::v0_1 as upload_abort, begin::v0_1 as upload_begin, chunk::v0_1 as upload_chunk,
    commit::v0_1 as upload_commit,
};
use trust_tasks_rs::specs::rooms::info::v0_1 as room_info;
use trust_tasks_rs::specs::rooms::records::get::v0_2 as get_v2;
use trust_tasks_rs::specs::rooms::records::put::v0_2 as put_v2;

use super::{RoomSession, SealedContent};
use crate::{VtcClient, VtcError};

pub use blob_get::Response as BlobGetResponse;
pub use download_chunk::Response as DownloadChunkResponse;
pub use get_v2::Response as GetRecordV2Response;
pub use put_v2::Response as PutRecordV2Response;
pub use room_info::Response as RoomInfoResponse;
pub use upload_begin::Response as BeginUploadResponse;
pub use upload_chunk::Response as UploadChunkResponse;
pub use upload_commit::Response as CommitUploadResponse;

/// Build a payload through its generated type: the schema's checks run here.
fn payload<P: DeserializeOwned + Serialize>(
    value: serde_json::Value,
) -> Result<serde_json::Value, VtcError> {
    let typed: P = serde_json::from_value(value)
        .map_err(|e| VtcError::Url(format!("payload refused by its schema: {e}")))?;
    serde_json::to_value(typed).map_err(|e| VtcError::Url(e.to_string()))
}

/// Read a response as its generated type.
fn response<R: DeserializeOwned>(type_uri: &str, value: serde_json::Value) -> Result<R, VtcError> {
    serde_json::from_value(value).map_err(|e| VtcError::Http {
        status: 200,
        body: format!("{type_uri} response does not match its schema: {e}"),
    })
}

fn b64url(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

impl VtcClient {
    /// `rooms/blobs/upload/begin/0.1`: offer a blob's manifest to the room.
    ///
    /// `manifest` is the ciphertext manifest (`vti_rooms::files::BlobManifest`); its digest
    /// is the `blobRef` the blob will have. The answer lists the chunks the host still needs,
    /// so a resumed upload sends only those, and says when the blob is already committed.
    pub async fn begin_upload<M: Serialize>(
        &self,
        session: &RoomSession,
        manifest: &M,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<BeginUploadResponse, VtcError> {
        let p = payload::<upload_begin::Payload>(serde_json::json!({
            "roomId": session.room_id,
            "manifest": manifest,
            "presentation": session.presentation,
        }))?;
        let uri = upload_begin::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        response(uri, v)
    }

    /// `rooms/blobs/upload/chunk/0.1`: one sealed chunk, which the host checks against the
    /// manifest before storing.
    pub async fn upload_chunk(
        &self,
        upload_id: &str,
        index: u64,
        chunk: &[u8],
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<UploadChunkResponse, VtcError> {
        let p = payload::<upload_chunk::Payload>(serde_json::json!({
            "uploadId": upload_id,
            "index": index,
            "data": b64url(chunk),
            "digestMultibase": vti_rooms::files::digest_multibase(chunk),
        }))?;
        let uri = upload_chunk::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        response(uri, v)
    }

    /// `rooms/blobs/upload/commit/0.1`: finish an upload whose every chunk is held.
    pub async fn commit_upload(
        &self,
        upload_id: &str,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<CommitUploadResponse, VtcError> {
        let p = payload::<upload_commit::Payload>(serde_json::json!({ "uploadId": upload_id }))?;
        let uri = upload_commit::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        response(uri, v)
    }

    /// `rooms/blobs/upload/abort/0.1`: give up an upload, releasing what it reserved.
    pub async fn abort_upload(
        &self,
        upload_id: &str,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<bool, VtcError> {
        let p = payload::<upload_abort::Payload>(serde_json::json!({ "uploadId": upload_id }))?;
        let uri = upload_abort::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        let r: upload_abort::Response = response(uri, v)?;
        Ok(r.aborted)
    }

    /// `rooms/blobs/get/0.1`: start a download, returning the manifest committed at upload.
    ///
    /// The manifest comes from the host. A reader checks it against the `blobRef` and the
    /// author's `FileManifest` before trusting a chunk, which `vti_rooms::files` does.
    pub async fn get_blob(
        &self,
        session: &RoomSession,
        blob_ref: &str,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<BlobGetResponse, VtcError> {
        let p = payload::<blob_get::Payload>(serde_json::json!({
            "roomId": session.room_id,
            "blobRef": blob_ref,
            "presentation": session.presentation,
        }))?;
        let uri = blob_get::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        response(uri, v)
    }

    /// `rooms/blobs/chunk/0.1`: one chunk of a started download, decoded.
    ///
    /// The bytes are returned unchecked against the manifest; the caller checks each against
    /// its digest there, since the digest the host sends beside the chunk proves nothing.
    pub async fn download_chunk(
        &self,
        download_id: &str,
        index: u64,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<Vec<u8>, VtcError> {
        let p = payload::<download_chunk::Payload>(serde_json::json!({
            "downloadId": download_id,
            "index": index,
        }))?;
        let uri = download_chunk::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        let r: DownloadChunkResponse = response(uri, v)?;
        base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            r.data.as_str(),
        )
        .map_err(|e| VtcError::Http {
            status: 200,
            body: format!("chunk {index} is not base64url: {e}"),
        })
    }

    /// `rooms/info/0.1`: the room's visibility, epoch, limits and usage.
    pub async fn room_info(
        &self,
        session: &RoomSession,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<RoomInfoResponse, VtcError> {
        let p = payload::<room_info::Payload>(serde_json::json!({
            "roomId": session.room_id,
            "presentation": session.presentation,
        }))?;
        let uri = room_info::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        response(uri, v)
    }

    /// `rooms/records/get/0.2`: one record, with the blobs it names.
    ///
    /// On a sealed tier the body is still ciphertext; open it through the member's VTA and
    /// check it with [`super::body::verify_record_body`] before using anything in it.
    pub async fn get_record_v2(
        &self,
        session: &RoomSession,
        key: &str,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<GetRecordV2Response, VtcError> {
        let p = payload::<get_v2::Payload>(serde_json::json!({
            "roomId": session.room_id,
            "key": key,
            "presentation": session.presentation,
        }))?;
        let uri = get_v2::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        response(uri, v)
    }

    /// `rooms/records/put/0.2`: write a sealed record that names its blobs.
    ///
    /// Each blob must be committed in this room first, and the record's sealed body must
    /// describe it; the host can check the first and never the second.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_sealed_record_with_blobs(
        &self,
        session: &RoomSession,
        key: &str,
        sealed: SealedContent,
        blobs: &[String],
        expected_version: Option<u64>,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<PutRecordV2Response, VtcError> {
        let mut value = serde_json::json!({
            "roomId": session.room_id,
            "key": key,
            "presentation": session.presentation,
            "sealed": sealed,
        });
        if !blobs.is_empty() {
            value["blobs"] = serde_json::json!(blobs);
        }
        if let Some(v) = expected_version {
            value["expectedVersion"] = serde_json::json!(v);
        }
        let p = payload::<put_v2::Payload>(value)?;
        let uri = put_v2::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        response(uri, v)
    }
}
