//! Client side of the `chunkedTrustTask` backup transfer algorithm.
//!
//! The descriptor flow's `stream` algorithm moves a bundle over the VTA's HTTPS
//! blob endpoint. A client whose Trust-Task surface is DIDComm or TSP — because
//! that is what the VTA's DID document advertises and this client selected — has
//! no such endpoint to use, so it moves the bundle in chunks over the same
//! transport as the control plane (`vta/backup/initiate-export/1.1` § Chunked
//! transfer, trustoverip/dtgwg-trust-tasks-tf#474).
//!
//! Two properties the specification makes the client's job:
//!
//! - **Pull, one index at a time.** [`ChunkedDownload::fetch_missing`] asks for
//!   each chunk it lacks, sequentially. A reply lost in transit is a chunk still
//!   missing, never a silent gap, because nothing was pushed.
//! - **Verify before trusting.** Each chunk is checked against the manifest's
//!   digest on arrival, and the assembled bundle against the whole-bundle digest
//!   and size, before the bytes are returned to be written anywhere.
//!
//! Retries belong to [`VtaClient::idempotent`] alone: every chunk request goes
//! through it, and nothing here loops. Resuming after a failure that outlasted
//! those retries is calling [`ChunkedDownload::fetch_missing`] (or
//! [`ChunkedUpload::put_missing`]) again on the same value, which asks only for
//! what is still missing.

use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::VtaClient;
use crate::error::VtaError;
use crate::protocols::backup_management::chunked::{
    ALGORITHM_CHUNKED, MAX_CHUNK_SIZE, chunk_count, chunk_range, get_chunk, initiate_export_1_1,
    initiate_import_1_1, put_chunk, sha256_digest_multibase, sha256_from_digest_multibase,
};
use crate::trust_tasks::{
    TASK_BACKUP_GET_CHUNK_1_0, TASK_BACKUP_INITIATE_EXPORT_1_1, TASK_BACKUP_INITIATE_IMPORT_1_1,
    TASK_BACKUP_PUT_CHUNK_1_0,
};

/// How far a chunked transfer has got. Reported after each chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferProgress {
    /// Chunks transferred so far.
    pub chunks_done: u64,
    /// Chunks in the bundle.
    pub chunks_total: u64,
    /// Bytes transferred so far.
    pub bytes_done: u64,
    /// Bytes in the bundle.
    pub bytes_total: u64,
}

/// An export bundle being pulled chunk by chunk.
///
/// Built from the manifest an `initiate-export/1.1` descriptor returned. Holds
/// the chunks received so far, so a failed [`Self::fetch_missing`] can be
/// resumed by calling it again.
#[derive(Debug)]
pub struct ChunkedDownload {
    bundle_id: String,
    chunk_size: u64,
    size: u64,
    expected_sha256: String,
    digests: Vec<[u8; 32]>,
    chunks: Vec<Option<Vec<u8>>>,
}

impl ChunkedDownload {
    /// Validate a chunked descriptor's manifest and prepare to pull it.
    ///
    /// Refuses a manifest whose chunk count does not follow from its size and
    /// chunk size, whose digest list is the wrong length, or that names a digest
    /// this build cannot verify — the specification requires a party receiving
    /// such a manifest to refuse it rather than proceed on trust.
    pub fn new(descriptor: &initiate_export_1_1::ChunkedDescriptor) -> Result<Self, VtaError> {
        let size = descriptor.expected_size_bytes.0.get();
        let chunk_size = u64::try_from(descriptor.chunks.chunk_size.0)
            .map_err(|_| VtaError::Protocol("manifest chunkSize is negative".into()))?;
        let digests = verified_manifest(
            size,
            chunk_size,
            descriptor.chunks.chunk_count.0.get(),
            descriptor.chunks.chunk_digests.iter().map(|d| d.as_str()),
        )?;
        Ok(Self {
            bundle_id: descriptor.bundle_id.as_str().to_string(),
            chunk_size,
            size,
            expected_sha256: descriptor.expected_sha256.as_str().to_string(),
            chunks: vec![None; digests.len()],
            digests,
        })
    }

    /// The bundle this download belongs to.
    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    /// Indices not yet received and verified.
    pub fn missing(&self) -> Vec<u64> {
        self.chunks
            .iter()
            .enumerate()
            .filter(|(_, c)| c.is_none())
            .map(|(i, _)| i as u64)
            .collect()
    }

    fn progress(&self) -> TransferProgress {
        let held: Vec<&Vec<u8>> = self.chunks.iter().flatten().collect();
        TransferProgress {
            chunks_done: held.len() as u64,
            chunks_total: self.chunks.len() as u64,
            bytes_done: held.iter().map(|c| c.len() as u64).sum(),
            bytes_total: self.size,
        }
    }

    /// Accept one `get-chunk` response, verifying it against the manifest.
    ///
    /// A chunk that fails is not stored, so it stays missing and a later
    /// [`Self::fetch_missing`] asks for it again.
    pub fn accept(&mut self, response: &get_chunk::Response) -> Result<(), VtaError> {
        if response.bundle_id.as_str() != self.bundle_id {
            return Err(VtaError::Protocol(format!(
                "get-chunk answered for bundle {} while fetching {}",
                response.bundle_id.as_str(),
                self.bundle_id
            )));
        }
        let index = u64::try_from(response.index.0)
            .map_err(|_| VtaError::Protocol("get-chunk answered a negative index".into()))?;
        let (start, end) = chunk_range(self.size, self.chunk_size, index).ok_or_else(|| {
            VtaError::Protocol(format!(
                "get-chunk answered index {index}, outside the manifest"
            ))
        })?;
        let data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(response.data.as_str())
            .map_err(|e| VtaError::Protocol(format!("chunk {index} is not base64url: {e}")))?;
        if data.len() as u64 != end - start {
            return Err(VtaError::Protocol(format!(
                "chunk {index} is {} bytes; the manifest requires {}",
                data.len(),
                end - start
            )));
        }
        let actual: [u8; 32] = Sha256::digest(&data).into();
        if actual != self.digests[index as usize] {
            return Err(VtaError::Protocol(format!(
                "chunk {index} does not match the manifest digest"
            )));
        }
        self.chunks[index as usize] = Some(data);
        Ok(())
    }

    /// Pull every chunk not yet held, in index order, reporting progress after
    /// each. Each request goes through [`VtaClient::idempotent`]; the first
    /// failure that outlasts it stops the pass and is returned, leaving what was
    /// received in place for a later call to resume from.
    pub async fn fetch_missing(
        &mut self,
        client: &VtaClient,
        progress: &mut (dyn FnMut(TransferProgress) + Send),
    ) -> Result<(), VtaError> {
        for index in self.missing() {
            let request = json!({ "bundleId": self.bundle_id, "index": index });
            let response: get_chunk::Response = client
                .idempotent(|| client.post_trust_task(TASK_BACKUP_GET_CHUNK_1_0, request.clone()))
                .await?;
            if u64::try_from(response.index.0).ok() != Some(index) {
                return Err(VtaError::Protocol(format!(
                    "asked for chunk {index}, received chunk {}",
                    response.index.0
                )));
            }
            self.accept(&response)?;
            progress(self.progress());
        }
        Ok(())
    }

    /// Assemble the bundle once every chunk is held, verifying the result
    /// against the whole-bundle digest and size.
    pub fn assemble(&self) -> Result<Vec<u8>, VtaError> {
        let missing = self.missing();
        if !missing.is_empty() {
            return Err(VtaError::Protocol(format!(
                "{} chunk(s) not yet received",
                missing.len()
            )));
        }
        let mut bytes = Vec::with_capacity(self.size as usize);
        for chunk in self.chunks.iter().flatten() {
            bytes.extend_from_slice(chunk);
        }
        if bytes.len() as u64 != self.size || sha256_hex(&bytes) != self.expected_sha256 {
            return Err(VtaError::Protocol(
                "assembled backup does not match the manifest's whole-bundle digest".into(),
            ));
        }
        Ok(bytes)
    }
}

/// An import bundle being written chunk by chunk.
#[derive(Debug)]
pub struct ChunkedUpload<'a> {
    bundle_id: String,
    chunk_size: u64,
    bytes: &'a [u8],
    digests: Vec<String>,
    done: Vec<bool>,
}

impl<'a> ChunkedUpload<'a> {
    /// The bundle this upload writes to.
    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    /// Indices whose write has not been acknowledged.
    pub fn missing(&self) -> Vec<u64> {
        self.done
            .iter()
            .enumerate()
            .filter(|(_, d)| !**d)
            .map(|(i, _)| i as u64)
            .collect()
    }

    /// Write every chunk not yet acknowledged, in index order. A chunk counts as
    /// written only once the VTA's `put-chunk` response says it holds it — a
    /// send the transport accepted is not that.
    pub async fn put_missing(
        &mut self,
        client: &VtaClient,
        progress: &mut (dyn FnMut(TransferProgress) + Send),
    ) -> Result<(), VtaError> {
        let size = self.bytes.len() as u64;
        for index in self.missing() {
            let (start, end) = chunk_range(size, self.chunk_size, index)
                .expect("an index below the manifest's count has a range");
            let request = json!({
                "bundleId": self.bundle_id,
                "index": index,
                "digestMultibase": self.digests[index as usize],
                "data": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(&self.bytes[start as usize..end as usize]),
            });
            let response: put_chunk::Response = client
                .idempotent(|| client.post_trust_task(TASK_BACKUP_PUT_CHUNK_1_0, request.clone()))
                .await?;
            if response.bundle_id.as_str() != self.bundle_id
                || u64::try_from(response.index.0).ok() != Some(index)
            {
                return Err(VtaError::Protocol(format!(
                    "put-chunk for chunk {index} was answered for another write"
                )));
            }
            self.done[index as usize] = true;
            let chunks_done = self.done.iter().filter(|d| **d).count() as u64;
            progress(TransferProgress {
                chunks_done,
                chunks_total: self.done.len() as u64,
                bytes_done: (chunks_done * self.chunk_size).min(size),
                bytes_total: size,
            });
        }
        Ok(())
    }
}

impl VtaClient {
    /// Mint a `chunkedTrustTask` export bundle and pull it.
    ///
    /// Returns the verified bundle bytes. On any failure the bundle is aborted
    /// best-effort, so a half-retrieved copy of the agent does not stay
    /// retrievable until its expiry.
    pub(super) async fn backup_export_chunked(
        &self,
        password: &str,
        include_audit: bool,
        progress: &mut (dyn FnMut(TransferProgress) + Send),
    ) -> Result<(Vec<u8>, String), VtaError> {
        let response: initiate_export_1_1::Response = self
            .post_trust_task(
                TASK_BACKUP_INITIATE_EXPORT_1_1,
                json!({
                    "password": password,
                    "includeAudit": include_audit,
                    "algorithm": ALGORITHM_CHUNKED,
                }),
            )
            .await?;
        let initiate_export_1_1::BundleDescriptor::ChunkedDescriptor(descriptor) =
            response.descriptor
        else {
            // The spec forbids answering a chunked request with another
            // algorithm; accepting one would mean fetching from an address this
            // client did not choose to use.
            return Err(VtaError::Protocol(
                "the VTA answered a chunkedTrustTask export with a different algorithm".into(),
            ));
        };
        let mut download = ChunkedDownload::new(&descriptor)?;
        let bundle_id = download.bundle_id().to_string();
        let result = async {
            download.fetch_missing(self, progress).await?;
            download.assemble()
        }
        .await;
        match result {
            Ok(bytes) => Ok((bytes, bundle_id)),
            Err(e) => {
                let _ = self.backup_abort_bundle(&bundle_id).await;
                Err(e)
            }
        }
    }

    /// Open a `chunkedTrustTask` import slot for `bytes` and write it.
    ///
    /// Returns the bundle id, ready for `finalize-import`. On failure the slot is
    /// aborted best-effort.
    pub(super) async fn backup_import_chunked(
        &self,
        bytes: &[u8],
        progress: &mut (dyn FnMut(TransferProgress) + Send),
    ) -> Result<String, VtaError> {
        let size = bytes.len() as u64;
        let count = chunk_count(size, MAX_CHUNK_SIZE).ok_or_else(|| {
            VtaError::Validation(format!(
                "a {size}-byte backup cannot be sent in chunks: the algorithm caps a bundle \
                 at 4096 chunks of 256 KiB (1 GiB)"
            ))
        })?;
        let digests: Vec<String> = bytes
            .chunks(MAX_CHUNK_SIZE as usize)
            .map(|c| sha256_digest_multibase(&Sha256::digest(c).into()))
            .collect();
        let response: initiate_import_1_1::Response = self
            .post_trust_task(
                TASK_BACKUP_INITIATE_IMPORT_1_1,
                json!({
                    "expectedSha256": sha256_hex(bytes),
                    "expectedSizeBytes": size,
                    "algorithm": ALGORITHM_CHUNKED,
                    "chunks": {
                        "chunkSize": MAX_CHUNK_SIZE,
                        "chunkCount": count,
                        "chunkDigests": digests,
                    },
                }),
            )
            .await?;
        let initiate_import_1_1::BundleDescriptor::ChunkedDescriptor(descriptor) =
            response.descriptor
        else {
            return Err(VtaError::Protocol(
                "the VTA answered a chunkedTrustTask import with a different algorithm".into(),
            ));
        };
        // The descriptor echoes the manifest; a VTA that altered it would be
        // checking chunks against terms this client never committed to.
        let echoed: Vec<&str> = descriptor
            .chunks
            .chunk_digests
            .iter()
            .map(|d| d.as_str())
            .collect();
        if echoed != digests.iter().map(String::as_str).collect::<Vec<_>>()
            || descriptor.chunks.chunk_size.0 != MAX_CHUNK_SIZE as i64
        {
            let _ = self
                .backup_abort_bundle(descriptor.bundle_id.as_str())
                .await;
            return Err(VtaError::Protocol(
                "the VTA's import descriptor does not echo the committed manifest".into(),
            ));
        }
        let mut upload = ChunkedUpload {
            bundle_id: descriptor.bundle_id.as_str().to_string(),
            chunk_size: MAX_CHUNK_SIZE,
            bytes,
            digests,
            done: vec![false; count as usize],
        };
        if let Err(e) = upload.put_missing(self, progress).await {
            let _ = self.backup_abort_bundle(upload.bundle_id()).await;
            return Err(e);
        }
        Ok(upload.bundle_id)
    }
}

/// Check a manifest's internal consistency and decode its digests.
fn verified_manifest<'a>(
    size: u64,
    chunk_size: u64,
    declared_count: u64,
    digests: impl Iterator<Item = &'a str>,
) -> Result<Vec<[u8; 32]>, VtaError> {
    let count = chunk_count(size, chunk_size).ok_or_else(|| {
        VtaError::Protocol(format!(
            "manifest describes {size} bytes in chunks of {chunk_size}, outside the algorithm's bounds"
        ))
    })?;
    if count != declared_count {
        return Err(VtaError::Protocol(format!(
            "manifest declares {declared_count} chunks; {size} bytes at {chunk_size} is {count}"
        )));
    }
    let decoded: Vec<[u8; 32]> = digests
        .map(|d| {
            sha256_from_digest_multibase(d).ok_or_else(|| {
                VtaError::Protocol("manifest names a chunk digest this client cannot verify".into())
            })
        })
        .collect::<Result<_, _>>()?;
    if decoded.len() as u64 != count {
        return Err(VtaError::Protocol(format!(
            "manifest has {} digests for {count} chunks",
            decoded.len()
        )));
    }
    Ok(decoded)
}

fn sha256_hex(bytes: &[u8]) -> String {
    crate::hex::lower(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: usize = crate::protocols::backup_management::chunked::MIN_CHUNK_SIZE as usize;

    fn bundle() -> Vec<u8> {
        let mut v = vec![1u8; MIN];
        v.extend(vec![2u8; MIN]);
        v.extend_from_slice(b"backup-tail!");
        v
    }

    fn descriptor(bytes: &[u8]) -> initiate_export_1_1::ChunkedDescriptor {
        let digests: Vec<String> = bytes
            .chunks(MIN)
            .map(|c| sha256_digest_multibase(&Sha256::digest(c).into()))
            .collect();
        serde_json::from_value(json!({
            "bundleId": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
            "algorithm": "chunkedTrustTask",
            "chunks": { "chunkSize": MIN, "chunkCount": digests.len(), "chunkDigests": digests },
            "expectedSha256": sha256_hex(bytes),
            "expectedSizeBytes": bytes.len(),
            "expiresAt": "2026-01-01T00:05:01Z",
        }))
        .unwrap()
    }

    fn response(index: usize, data: &[u8]) -> get_chunk::Response {
        serde_json::from_value(json!({
            "bundleId": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
            "index": index,
            "digestMultibase": sha256_digest_multibase(&Sha256::digest(data).into()),
            "data": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data),
            "expiresAt": "2026-01-01T00:05:01Z",
        }))
        .unwrap()
    }

    #[test]
    fn chunks_in_any_order_assemble_to_the_verified_bundle() {
        let bytes = bundle();
        let mut dl = ChunkedDownload::new(&descriptor(&bytes)).unwrap();
        for i in [2usize, 0, 1] {
            let (s, e) = chunk_range(bytes.len() as u64, MIN as u64, i as u64).unwrap();
            dl.accept(&response(i, &bytes[s as usize..e as usize]))
                .unwrap();
        }
        assert_eq!(dl.assemble().unwrap(), bytes);
    }

    #[test]
    fn a_chunk_that_does_not_match_its_digest_stays_missing() {
        let bytes = bundle();
        let mut dl = ChunkedDownload::new(&descriptor(&bytes)).unwrap();
        // Right length, wrong bytes — and the response even carries a digest of
        // the wrong bytes, which must not be what the check trusts.
        let err = dl.accept(&response(0, &vec![9u8; MIN])).unwrap_err();
        assert!(matches!(err, VtaError::Protocol(_)), "{err:?}");
        assert_eq!(dl.missing(), vec![0, 1, 2]);
    }

    #[test]
    fn resuming_asks_only_for_what_is_still_missing() {
        let bytes = bundle();
        let mut dl = ChunkedDownload::new(&descriptor(&bytes)).unwrap();
        dl.accept(&response(0, &bytes[..MIN])).unwrap();
        // Chunk 1 was lost to a failure; chunk 2 arrived.
        dl.accept(&response(2, &bytes[2 * MIN..])).unwrap();
        assert_eq!(dl.missing(), vec![1]);
        assert!(
            dl.assemble().is_err(),
            "an incomplete bundle must not assemble"
        );
        dl.accept(&response(1, &bytes[MIN..2 * MIN])).unwrap();
        assert_eq!(dl.assemble().unwrap(), bytes);
    }

    #[test]
    fn an_out_of_range_index_is_refused() {
        let bytes = bundle();
        let mut dl = ChunkedDownload::new(&descriptor(&bytes)).unwrap();
        let err = dl.accept(&response(3, b"x")).unwrap_err();
        assert!(matches!(err, VtaError::Protocol(_)), "{err:?}");
    }

    #[test]
    fn a_manifest_whose_count_does_not_follow_is_refused() {
        let bytes = bundle();
        let mut d = serde_json::to_value(descriptor(&bytes)).unwrap();
        d["chunks"]["chunkCount"] = json!(2);
        d["chunks"]["chunkDigests"].as_array_mut().unwrap().pop();
        let d: initiate_export_1_1::ChunkedDescriptor = serde_json::from_value(d).unwrap();
        assert!(ChunkedDownload::new(&d).is_err());
    }

    #[test]
    fn an_assembled_bundle_is_checked_against_the_whole_digest() {
        let bytes = bundle();
        let mut d = serde_json::to_value(descriptor(&bytes)).unwrap();
        d["expectedSha256"] = json!(sha256_hex(b"other bytes"));
        let d: initiate_export_1_1::ChunkedDescriptor = serde_json::from_value(d).unwrap();
        let mut dl = ChunkedDownload::new(&d).unwrap();
        for i in 0..3 {
            let (s, e) = chunk_range(bytes.len() as u64, MIN as u64, i).unwrap();
            dl.accept(&response(i as usize, &bytes[s as usize..e as usize]))
                .unwrap();
        }
        assert!(dl.assemble().is_err());
    }
}
