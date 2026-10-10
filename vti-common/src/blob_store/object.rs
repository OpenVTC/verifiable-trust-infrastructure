//! Blobs in S3-compatible object storage or Google Cloud Storage.
//!
//! Through the `object_store` crate: one implementation for both, and a later
//! Azure backend costs configuration rather than code. Credentials are what the
//! crate's builders read from the environment (or the host's ambient identity).
//! The VTA-issued, room-scoped credentials of `data-rooms-files.md` §7.4 replace
//! that through `object_store`'s credential-provider hook, in a later phase.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use tokio::io::AsyncReadExt;

use super::{BackendRef, BlobKey, BlobStore, Deletion, Health, check_kind};
use crate::error::AppError;

/// Bytes per part when a blob is uploaded in parts. Above S3's 5 MiB minimum
/// part size, and small enough that a 1 GiB blob is 128 parts.
const PART_BYTES: usize = 8 * 1024 * 1024;

/// A blob store over any `object_store` backend.
#[derive(Debug, Clone)]
pub struct ObjectStoreBlobs {
    kind: &'static str,
    inner: Arc<dyn ObjectStore>,
    /// Prepended to every key, so a store can share a bucket with other data.
    prefix: String,
}

impl ObjectStoreBlobs {
    /// Wrap an already-built store. `kind` is what [`BackendRef`]s record.
    pub fn new(kind: &'static str, inner: Arc<dyn ObjectStore>, prefix: Option<&str>) -> Self {
        let prefix = prefix
            .map(|p| p.trim_matches('/'))
            .filter(|p| !p.is_empty())
            .map(|p| format!("{p}/"))
            .unwrap_or_default();
        Self {
            kind,
            inner,
            prefix,
        }
    }

    /// An S3-compatible bucket, credentials from the environment.
    ///
    /// `endpoint` is for stores other than AWS (R2, MinIO, B2); `path_style` for
    /// those, like MinIO, that do not do virtual-hosted buckets.
    #[cfg(feature = "blob-s3")]
    pub fn s3(
        bucket: &str,
        region: &str,
        endpoint: Option<&str>,
        path_style: bool,
        prefix: Option<&str>,
    ) -> Result<Self, AppError> {
        let mut builder = object_store::aws::AmazonS3Builder::from_env()
            .with_bucket_name(bucket)
            .with_region(region)
            .with_virtual_hosted_style_request(!path_style);
        if let Some(endpoint) = endpoint {
            builder = builder.with_endpoint(endpoint);
        }
        let store = builder
            .build()
            .map_err(|e| AppError::Config(format!("S3 blob store: {e}")))?;
        Ok(Self::new("s3", Arc::new(store), prefix))
    }

    /// A Google Cloud Storage bucket, credentials from the environment.
    #[cfg(feature = "blob-gcs")]
    pub fn gcs(bucket: &str, prefix: Option<&str>) -> Result<Self, AppError> {
        let store = object_store::gcp::GoogleCloudStorageBuilder::from_env()
            .with_bucket_name(bucket)
            .build()
            .map_err(|e| AppError::Config(format!("GCS blob store: {e}")))?;
        Ok(Self::new("gcs", Arc::new(store), prefix))
    }

    fn location(&self, key: &BlobKey) -> ObjectPath {
        ObjectPath::from(format!("{}{}", self.prefix, key.as_str()))
    }
}

fn store_error(e: object_store::Error) -> AppError {
    match e {
        object_store::Error::NotFound { path, .. } => AppError::NotFound(format!("blob `{path}`")),
        other => AppError::Internal(format!("object store: {other}")),
    }
}

#[async_trait]
impl BlobStore for ObjectStoreBlobs {
    fn kind(&self) -> &'static str {
        self.kind
    }

    async fn put(&self, key: &BlobKey, staged: &Path, size: u64) -> Result<BackendRef, AppError> {
        let location = self.location(key);
        let at = BackendRef {
            kind: self.kind.into(),
            key: key.clone(),
        };
        // Idempotent on the key: a content address that is already there holds
        // these bytes.
        if let Ok(meta) = self.inner.head(&location).await
            && meta.size == size
        {
            return Ok(at);
        }
        let mut file = tokio::fs::File::open(staged).await.map_err(AppError::Io)?;
        if size as usize <= PART_BYTES {
            let mut bytes = Vec::with_capacity(size as usize);
            file.read_to_end(&mut bytes).await.map_err(AppError::Io)?;
            if bytes.len() as u64 != size {
                return Err(AppError::Internal(format!(
                    "staged blob is {} bytes, expected {size}",
                    bytes.len()
                )));
            }
            self.inner
                .put(&location, PutPayload::from(bytes))
                .await
                .map_err(store_error)?;
            return Ok(at);
        }

        let mut upload = self
            .inner
            .put_multipart(&location)
            .await
            .map_err(store_error)?;
        let mut sent = 0u64;
        let outcome: Result<(), AppError> = async {
            loop {
                let mut part = vec![0u8; PART_BYTES];
                let mut filled = 0;
                while filled < PART_BYTES {
                    let n = file.read(&mut part[filled..]).await.map_err(AppError::Io)?;
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                if filled == 0 {
                    break;
                }
                part.truncate(filled);
                sent += filled as u64;
                upload
                    .put_part(PutPayload::from(part))
                    .await
                    .map_err(store_error)?;
            }
            if sent != size {
                return Err(AppError::Internal(format!(
                    "staged blob is {sent} bytes, expected {size}"
                )));
            }
            upload.complete().await.map_err(store_error)?;
            Ok(())
        }
        .await;
        if let Err(e) = outcome {
            let _ = upload.abort().await;
            return Err(e);
        }
        Ok(at)
    }

    async fn get_range(&self, at: &BackendRef, start: u64, end: u64) -> Result<Vec<u8>, AppError> {
        check_kind(self, at)?;
        let bytes = self
            .inner
            .get_range(&self.location(&at.key), start..end)
            .await
            .map_err(store_error)?;
        if bytes.len() as u64 != end - start {
            return Err(AppError::Internal(format!(
                "blob `{}` returned {} bytes for a {}-byte range",
                at.key.as_str(),
                bytes.len(),
                end - start
            )));
        }
        Ok(bytes.to_vec())
    }

    async fn delete(&self, at: &BackendRef) -> Result<Deletion, AppError> {
        check_kind(self, at)?;
        match self.inner.delete(&self.location(&at.key)).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(Deletion::Deleted),
            Err(e) => Err(store_error(e)),
        }
    }

    async fn health(&self) -> Health {
        // A read of a key that should not exist: reachable and authorized is a
        // `NotFound`, anything else is the store's own complaint, verbatim.
        let probe = ObjectPath::from(format!("{}rooms/.health", self.prefix));
        match self.inner.head(&probe).await {
            Ok(_) | Err(object_store::Error::NotFound { .. }) => Health {
                ok: true,
                detail: None,
            },
            Err(e) => Health {
                ok: false,
                detail: Some(e.to_string()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The in-memory backend stands in for a bucket: the suite exercises this
    /// adapter, which is the code in question, and a real bucket would test the
    /// network.
    #[tokio::test]
    async fn passes_the_conformance_suite() {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStoreBlobs::new(
            "memory",
            Arc::new(object_store::memory::InMemory::new()),
            Some("tenant-a"),
        );
        super::super::conformance::run(&store, dir.path()).await;
    }

    #[tokio::test]
    async fn a_blob_larger_than_one_part_goes_up_in_parts() {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStoreBlobs::new(
            "memory",
            Arc::new(object_store::memory::InMemory::new()),
            None,
        );
        let bytes: Vec<u8> = (0..(PART_BYTES as u32 + 1000))
            .map(|i| (i % 253) as u8)
            .collect();
        let staged = dir.path().join("big");
        tokio::fs::write(&staged, &bytes).await.unwrap();
        let key = BlobKey::for_room(
            "did:key:zRoom",
            &super::super::sha256_digest_multibase(&[9; 32]),
        )
        .unwrap();
        let at = store.put(&key, &staged, bytes.len() as u64).await.unwrap();
        let tail = store
            .get_range(&at, PART_BYTES as u64 - 10, bytes.len() as u64)
            .await
            .unwrap();
        assert_eq!(tail, bytes[PART_BYTES - 10..]);
    }
}
