//! Moving a room file's ciphertext: `rooms/blobs/upload/*`, `rooms/blobs/{get,chunk}` and
//! the record put that names a blob (`rooms/records/put/0.3`).
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
use trust_tasks_rs::specs::rooms::blobs::get::v0_2 as blob_get_v2;
use trust_tasks_rs::specs::rooms::blobs::upload::{
    abort::v0_2 as upload_abort_v2, begin::v0_2 as upload_begin_v2, chunk::v0_2 as upload_chunk_v2,
    commit::v0_2 as upload_commit_v2,
};
use trust_tasks_rs::specs::rooms::info::v0_1 as room_info;
use trust_tasks_rs::specs::rooms::info::v0_2 as room_info_v2;
use trust_tasks_rs::specs::rooms::records::get::v0_2 as get_v2;
use trust_tasks_rs::specs::rooms::records::prune::v0_1 as records_prune;
use trust_tasks_rs::specs::rooms::records::put::v0_3 as put_v3;
use trust_tasks_rs::specs::rooms::records::retention::set::v0_1 as retention_set;

use super::{RoomSession, SealedContent};
use crate::{VtcClient, VtcError};

pub use blob_get_v2::Response as BlobGetV2Response;
pub use blob_get_v2::TransferTarget as ReadTarget;
pub use download_chunk::Response as DownloadChunkResponse;
pub use get_v2::Response as GetRecordV2Response;
pub use put_v3::Response as PutRecordV3Response;
pub use records_prune::Response as PruneRecordsResponse;
pub use retention_set::Response as RetentionSetResponse;
pub use room_info::Response as RoomInfoResponse;
pub use room_info_v2::Response as RoomInfoV2Response;
pub use upload_begin_v2::{Response as BeginUploadV2Response, TransferTarget as WriteTarget};
pub use upload_chunk_v2::Response as UploadChunkResponse;
pub use upload_commit_v2::Response as CommitUploadResponse;

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

/// The client for requests straight to a room's storage (direct mode): finite timeouts
/// (R1.2), and no redirect followed — a target is for one object, and a redirect would
/// be a request to wherever it points, with the member's bytes.
fn storage_client() -> Result<&'static reqwest::Client, VtcError> {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    if let Some(c) = CLIENT.get() {
        return Ok(c);
    }
    let c = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .read_timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| VtcError::Url(format!("storage client: {e}")))?;
    Ok(CLIENT.get_or_init(|| c))
}

/// A storage failure, without the URL: it carries the target's signature, which is a
/// bearer credential and never goes in an error or a log line.
fn storage_error(op: &str, e: reqwest::Error) -> VtcError {
    VtcError::Http {
        status: e.status().map_or(0, |s| s.as_u16()),
        body: format!("storage {op} failed: {}", e.without_url()),
    }
}

/// Refuse a target that is not what the transfer needs before sending a byte: HTTPS,
/// the expected method, and (for a write) the index asked for.
fn check_target(url: &str, got: &str, method: &str) -> Result<(), VtcError> {
    if !url.starts_with("https://") {
        return Err(VtcError::Url("a storage target must be HTTPS".into()));
    }
    if got != method {
        return Err(VtcError::Url(format!(
            "a storage target for {got} where {method} was needed"
        )));
    }
    Ok(())
}

/// Write one part of a direct upload to its target, with exactly the headers the target
/// names (for S3, the part's `Content-Length` and `x-amz-checksum-sha256`, which its
/// signature covers, so storage refuses any other bytes). The URL is never logged.
pub async fn put_part(target: &WriteTarget, part: &[u8]) -> Result<(), VtcError> {
    check_target(&target.url, &target.method.to_string(), "PUT")?;
    let mut req = storage_client()?.put(&target.url);
    for (name, value) in &target.headers {
        req = req.header(name.as_str(), value.as_str());
    }
    let res = req
        .body(part.to_vec())
        .send()
        .await
        .map_err(|e| storage_error("write", e))?;
    if !res.status().is_success() {
        return Err(VtcError::Http {
            status: res.status().as_u16(),
            body: "storage refused the part".into(),
        });
    }
    Ok(())
}

/// Read `range` (`start..end`, end exclusive) of a blob from its direct-read target. The
/// bytes are unchecked here: the reader cuts them at the manifest's chunk boundaries and
/// checks each chunk's digest, since storage proves nothing about what it returns.
pub async fn get_range(
    target: &ReadTarget,
    range: std::ops::Range<u64>,
) -> Result<Vec<u8>, VtcError> {
    check_target(&target.url, &target.method.to_string(), "GET")?;
    if range.end <= range.start {
        return Ok(Vec::new());
    }
    let mut req = storage_client()?.get(&target.url);
    for (name, value) in &target.headers {
        req = req.header(name.as_str(), value.as_str());
    }
    let res = req
        .header(
            reqwest::header::RANGE,
            format!("bytes={}-{}", range.start, range.end - 1),
        )
        .send()
        .await
        .map_err(|e| storage_error("read", e))?;
    let status = res.status();
    if !status.is_success() {
        return Err(VtcError::Http {
            status: status.as_u16(),
            body: "storage refused the read".into(),
        });
    }
    let body = res.bytes().await.map_err(|e| storage_error("read", e))?;
    // A store that ignored the range sent the whole object.
    let bytes = if status == reqwest::StatusCode::OK {
        let (s, e) = (range.start as usize, range.end as usize);
        body.get(s..e).map(<[u8]>::to_vec).unwrap_or_default()
    } else {
        body.to_vec()
    };
    if bytes.len() as u64 != range.end - range.start {
        return Err(VtcError::Http {
            status: status.as_u16(),
            body: format!(
                "storage returned {} bytes for a range of {}",
                bytes.len(),
                range.end - range.start
            ),
        });
    }
    Ok(bytes)
}

fn b64url(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

impl VtcClient {
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

    /// `rooms/blobs/upload/begin/0.2`, signed by the member (`signer_did`): offer a blob's
    /// manifest and the modes this producer accepts — `upload_key` (a `did:key` generated
    /// for this one upload, from no key held for anything else) for a proxied transfer,
    /// `direct_parts` (a `PartPlan`) for a direct one. The answer's `mode` says which the
    /// host chose; in direct mode write each part with [`put_part`] and commit as the
    /// member, in proxied mode send [`Self::upload_chunk_v2`] and commit with the key.
    ///
    /// Resume is this call again with the same manifest: the host answers the same
    /// `uploadId` and what is missing, rebound to the key this call names.
    #[allow(clippy::too_many_arguments)]
    pub async fn begin_upload_v2<M: Serialize, P: Serialize>(
        &self,
        session: &RoomSession,
        manifest: &M,
        upload_key: Option<&str>,
        direct_parts: Option<&P>,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<BeginUploadV2Response, VtcError> {
        let mut value = serde_json::json!({
            "roomId": session.room_id,
            "manifest": manifest,
            "presentation": session.presentation,
        });
        if let Some(k) = upload_key {
            value["uploadKey"] = serde_json::json!(k);
        }
        if let Some(p) = direct_parts {
            value["directParts"] = serde_json::json!(p);
        }
        let p = payload::<upload_begin_v2::Payload>(value)?;
        let uri = upload_begin_v2::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        response(uri, v)
    }

    /// `rooms/blobs/upload/chunk/0.2`: one sealed chunk of a proxied upload, signed by the
    /// upload key the begin named — never by the member.
    pub async fn upload_chunk_v2(
        &self,
        upload_id: &str,
        index: u64,
        chunk: &[u8],
        upload_key_did: &str,
        upload_key_multibase: &str,
    ) -> Result<UploadChunkResponse, VtcError> {
        let p = payload::<upload_chunk_v2::Payload>(serde_json::json!({
            "uploadId": upload_id,
            "index": index,
            "data": b64url(chunk),
            "digestMultibase": vti_rooms::files::digest_multibase(chunk),
        }))?;
        let uri = upload_chunk_v2::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, upload_key_did, upload_key_multibase)
            .await?;
        response(uri, v)
    }

    /// `rooms/blobs/upload/commit/0.2`: signed by the upload key (proxied) or the member
    /// (direct).
    pub async fn commit_upload_v2(
        &self,
        upload_id: &str,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<CommitUploadResponse, VtcError> {
        let p = payload::<upload_commit_v2::Payload>(serde_json::json!({ "uploadId": upload_id }))?;
        let uri = upload_commit_v2::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        response(uri, v)
    }

    /// `rooms/blobs/upload/abort/0.2`: signed by the upload key (proxied) or the member
    /// (direct).
    pub async fn abort_upload_v2(
        &self,
        upload_id: &str,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<bool, VtcError> {
        let p = payload::<upload_abort_v2::Payload>(serde_json::json!({ "uploadId": upload_id }))?;
        let uri = upload_abort_v2::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        let r: upload_abort_v2::Response = response(uri, v)?;
        Ok(r.aborted)
    }

    /// `rooms/blobs/get/0.2`: start a download, accepting a storage URL when `direct`. The
    /// answer's `mode` says which the host chose: `direct` — read the object with
    /// [`get_range`] over `target`; `proxied` — fetch chunks with
    /// [`Self::download_chunk`] under `downloadId`. Either way check the manifest against
    /// the `blobRef`, and every chunk against the manifest, before trusting a byte.
    pub async fn get_blob_v2(
        &self,
        session: &RoomSession,
        blob_ref: &str,
        direct: bool,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<BlobGetV2Response, VtcError> {
        let p = payload::<blob_get_v2::Payload>(serde_json::json!({
            "roomId": session.room_id,
            "blobRef": blob_ref,
            "presentation": session.presentation,
            "direct": direct,
        }))?;
        let uri = blob_get_v2::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        response(uri, v)
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

    /// `rooms/records/put/0.3`: write a sealed record that names its blobs.
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
    ) -> Result<PutRecordV3Response, VtcError> {
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
        let p = payload::<put_v3::Payload>(value)?;
        let uri = put_v3::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        response(uri, v)
    }

    /// `rooms/info/0.2`: 0.1's answer, the room's record retention in force (absent when it
    /// states none) and its latest record prune.
    pub async fn room_info_v2(
        &self,
        session: &RoomSession,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<RoomInfoV2Response, VtcError> {
        let p = payload::<room_info_v2::Payload>(serde_json::json!({
            "roomId": session.room_id,
            "presentation": session.presentation,
        }))?;
        let uri = room_info_v2::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        response(uri, v)
    }

    /// `rooms/records/prune/0.1`: remove the records the room's record retention makes
    /// eligible — `retracted` tombstones, `aged` records, or both. Needs `admin`.
    ///
    /// **Irreversible, for every member**: what is removed is removed outright, tombstones
    /// included, and the room keeps only a mark that records went. `dry_run` reports what
    /// would go and changes nothing — ask it first. `removed: 0` is a success. Refused
    /// `noRetention` when the room states no rule for any kind asked.
    ///
    /// Never retried here: eligibility is a function of time, so a second prune is not a
    /// repeat of the first.
    pub async fn prune_records(
        &self,
        session: &RoomSession,
        kinds: &[&str],
        reason: &str,
        dry_run: bool,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<PruneRecordsResponse, VtcError> {
        let mut value = serde_json::json!({
            "roomId": session.room_id,
            "presentation": session.presentation,
            "kinds": kinds,
            "reason": reason,
        });
        if dry_run {
            value["dryRun"] = serde_json::json!(true);
        }
        let p = payload::<records_prune::Payload>(value)?;
        let uri = records_prune::Payload::TYPE_URI;
        let v = self
            .room_task(uri, p, signer_did, private_key_multibase)
            .await?;
        response(uri, v)
    }

    /// `rooms/records/retention/set/0.1`: replace the room's record retention whole
    /// (`{}` clears it). `expected` is the retention the caller believes is in force — the
    /// host refuses `retentionConflict` otherwise, so two administrators do not overwrite
    /// each other unseen. Needs `admin`. Removes nothing; the next prune applies it.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_record_retention(
        &self,
        session: &RoomSession,
        retention: serde_json::Value,
        expected: Option<serde_json::Value>,
        reason: &str,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<RetentionSetResponse, VtcError> {
        let mut value = serde_json::json!({
            "roomId": session.room_id,
            "presentation": session.presentation,
            "recordRetention": retention,
            "reason": reason,
        });
        if let Some(e) = expected {
            value["expectedRetention"] = e;
        }
        serde_json::from_value::<retention_set::Payload>(value.clone())
            .map_err(|e| VtcError::Url(format!("payload refused by its schema: {e}")))?;
        let uri = retention_set::Payload::TYPE_URI;
        let v = self
            .room_task(uri, value, signer_did, private_key_multibase)
            .await?;
        response(uri, v)
    }

    /// `rooms/records/put/0.3`: write an `open` room's record whose `cleartext` may carry
    /// its provenance (`basis`, `confidence`, `evidence`, `validFor`) and `validUntil`.
    ///
    /// On this tier nothing is signed by the author: every member is the writer's claim as
    /// the host stores it, and the host stores and serves it as received and never acts on
    /// it. A sealed room carries the same members inside the signed body instead
    /// ([`super::body::SealedRecordBody`]) and writes with 0.2.
    ///
    /// The payload is checked against the generated type but sent **as given**, so a
    /// `validUntil` reaches the host in the spelling the writer chose.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_cleartext_record_v3(
        &self,
        session: &RoomSession,
        key: &str,
        cleartext: serde_json::Value,
        blobs: &[String],
        expected_version: Option<u64>,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<PutRecordV3Response, VtcError> {
        let mut value = serde_json::json!({
            "roomId": session.room_id,
            "key": key,
            "presentation": session.presentation,
            "cleartext": cleartext,
        });
        if !blobs.is_empty() {
            value["blobs"] = serde_json::json!(blobs);
        }
        if let Some(v) = expected_version {
            value["expectedVersion"] = serde_json::json!(v);
        }
        serde_json::from_value::<put_v3::Payload>(value.clone())
            .map_err(|e| VtcError::Url(format!("payload refused by its schema: {e}")))?;
        let uri = put_v3::Payload::TYPE_URI;
        let v = self
            .room_task(uri, value, signer_did, private_key_multibase)
            .await?;
        response(uri, v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_target(url: &str, method: &str) -> ReadTarget {
        serde_json::from_value(serde_json::json!({
            "index": 0,
            "method": method,
            "url": url,
            "expiresAt": "2030-01-01T00:00:00Z",
        }))
        .unwrap()
    }

    /// A target is refused before a byte is sent when it is not HTTPS or not the
    /// method the transfer needs, and a failure never carries the URL's signature.
    #[tokio::test]
    async fn a_target_is_checked_before_anything_is_sent() {
        let get = read_target("https://bucket.example/o?X-Amz-Signature=secret", "GET");
        let put: WriteTarget = serde_json::from_value(serde_json::json!({
            "index": 0,
            "method": "GET",
            "url": "https://bucket.example/o?X-Amz-Signature=secret",
            "expiresAt": "2030-01-01T00:00:00Z",
        }))
        .unwrap();
        let err = put_part(&put, b"x").await.unwrap_err().to_string();
        assert!(err.contains("where PUT was needed"), "{err}");
        assert!(!err.contains("secret"));
        assert!(get_range(&get, 5..5).await.unwrap().is_empty());
        assert!(check_target("http://bucket.example/o", "GET", "GET").is_err());
    }
}
