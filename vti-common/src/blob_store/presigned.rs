//! Blobs in an S3-compatible bucket, reached only through presigned requests.
//!
//! The store holds no credential. Every operation asks a [`Presigner`] for one
//! request — one method, on one object, for minutes — and performs it. In a
//! community the presigner is its VTA's `s3-static-presign` external account
//! (`data-rooms-files.md` §7.4): the access key never leaves the VTA, and what
//! reaches this process is a URL good for exactly the object it names. A URL
//! lifted from memory while one room's file is served reads, writes or deletes
//! that one object, and nothing else, until it expires.
//!
//! # What is checked of a presigned request
//!
//! It came from the presigner, which the caller trusts; it is still checked
//! before use, because a mistake there would otherwise send a room's bytes
//! somewhere unexpected:
//!
//! - it is HTTPS, so the bytes and the signature are never in clear;
//! - its method is the operation asked for;
//! - its path ends with the object asked for, so a presigner configured for a
//!   different layout fails loudly instead of writing elsewhere.
//!
//! No redirect is followed: a presigned request answered with a redirect is a
//! failure, never a second request to wherever it points.
//!
//! # Reads reuse a request
//!
//! A download is many ranges of one blob, so a `GET` request is kept until
//! shortly before it expires and reused for every range. Writes and deletes are
//! asked for each time: each happens once per blob.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use reqwest::StatusCode;

use super::{
    BackendRef, BlobKey, BlobStore, Deletion, DirectFinish, DirectPart, Health, PROBE_PREFIX,
    StorageOp, check_kind,
};
use crate::error::AppError;

/// How long before its expiry a cached `GET` request stops being reused.
const REUSE_MARGIN: chrono::Duration = chrono::Duration::seconds(30);
/// At most this many `GET` requests are kept; more, and the expired go first,
/// then the lot.
const MAX_CACHED: usize = 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Between bytes, not for the whole transfer: a large blob takes as long as it
/// takes, a stalled one does not.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// The one object operation a presigned request performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PresignAction {
    Put,
    Get,
    Delete,
}

impl PresignAction {
    /// The action as `external/credentials/issue` names it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Put => "put",
            Self::Get => "get",
            Self::Delete => "delete",
        }
    }

    fn method(self) -> &'static str {
        match self {
            Self::Put => "PUT",
            Self::Get => "GET",
            Self::Delete => "DELETE",
        }
    }
}

pub use super::PresignedRequest;

/// Where presigned requests come from.
///
/// `prefix` ends in `/` and `object_key` is one path segment; the object is
/// `prefix + object_key`. Both are built here from validated keys, never taken
/// from a caller.
#[async_trait]
pub trait Presigner: Send + Sync {
    async fn presign(
        &self,
        action: PresignAction,
        prefix: &str,
        object_key: &str,
    ) -> Result<PresignedRequest, AppError>;

    /// Whether [`presign_ops`](Self::presign_ops) works: writes bound to their
    /// length and checksum, multipart, head (`external/credentials/issue/0.2`+).
    fn presigns_ops(&self) -> bool {
        false
    }

    /// Presign `ops` on the one object `prefix + object_key` (and at most one
    /// multipart upload of it), answered in order. At most [`MAX_OPS`] at once.
    async fn presign_ops(
        &self,
        prefix: &str,
        object_key: &str,
        upload_id: Option<&str>,
        ops: &[StorageOp],
    ) -> Result<Vec<PresignedRequest>, AppError> {
        let _ = (prefix, object_key, upload_id, ops);
        Err(AppError::Internal(
            "this presigner presigns one put, get or delete at a time".into(),
        ))
    }
}

/// The most operations asked of a presigner at once: `external/credentials/issue/0.3`'s
/// batch bound. A presigner whose answer for that many would not fit splits the
/// batch itself (the VTA refuses it `responseTooLarge`), so a caller never sees
/// fewer requests than it asked for.
pub const MAX_OPS: usize = 64;

/// The method each [`StorageOp`] is presigned for.
fn op_method(op: &StorageOp) -> &'static str {
    match op {
        StorageOp::Put { .. } | StorageOp::UploadPart { .. } => "PUT",
        StorageOp::Get | StorageOp::ListParts { .. } => "GET",
        StorageOp::Head => "HEAD",
        StorageOp::Delete | StorageOp::AbortMultipart => "DELETE",
        StorageOp::CreateMultipart | StorageOp::CompleteMultipart { .. } => "POST",
    }
}

/// Standard, padded base64 of a SHA-256: how S3 carries `x-amz-checksum-sha256`.
pub fn checksum_b64(sha256: &[u8; 32]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(sha256)
}

/// What S3 reports as a multipart object's SHA-256: the SHA-256 of its parts'
/// digests concatenated, then `-<part count>`.
pub fn composite_checksum(parts: &[DirectPart]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.sha256);
    }
    format!("{}-{}", checksum_b64(&h.finalize().into()), parts.len())
}

/// One part as storage lists it.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListedPart {
    part_number: u32,
    size: u64,
    #[serde(rename = "ETag")]
    etag: String,
    #[serde(rename = "ChecksumSHA256", default)]
    checksum_sha256: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListPartsResult {
    #[serde(rename = "Part", default)]
    parts: Vec<ListedPart>,
    #[serde(default)]
    is_truncated: bool,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct InitiateMultipartUploadResult {
    upload_id: String,
}

/// A blob store over presigned requests.
pub struct PresignedBlobs {
    kind: &'static str,
    presigner: Arc<dyn Presigner>,
    /// Prepended to every key, ending in `/` when not empty.
    prefix: String,
    http: reqwest::Client,
    reads: Mutex<HashMap<String, PresignedRequest>>,
    plain_http: bool,
}

impl std::fmt::Debug for PresignedBlobs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresignedBlobs")
            .field("kind", &self.kind)
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl PresignedBlobs {
    /// A store whose objects live under `prefix` (a bucket-relative prefix ending
    /// in `/`, or none), presigned by `presigner`. `kind` is what its
    /// [`BackendRef`]s record.
    pub fn new(
        kind: &'static str,
        presigner: Arc<dyn Presigner>,
        prefix: Option<&str>,
    ) -> Result<Self, AppError> {
        let prefix = prefix
            .map(|p| p.trim_start_matches('/'))
            .filter(|p| !p.is_empty())
            .map(|p| {
                if p.ends_with('/') {
                    p.to_string()
                } else {
                    format!("{p}/")
                }
            })
            .unwrap_or_default();
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .build()
            .map_err(|e| AppError::Internal(format!("presigned blob store client: {e}")))?;
        Ok(Self {
            kind,
            presigner,
            prefix,
            http,
            reads: Mutex::new(HashMap::new()),
            plain_http: false,
        })
    }

    /// Accept `http://` requests, for a test server on the loopback. Never in a
    /// deployment: the requests carry their signatures and the room's bytes.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_plain_http(mut self) -> Self {
        self.plain_http = true;
        self
    }

    /// `(prefix, object key)` of `key` in the bucket.
    fn split<'a>(&self, key: &'a BlobKey) -> Result<(String, &'a str), AppError> {
        let (dir, object) = key.as_str().rsplit_once('/').ok_or_else(|| {
            AppError::Internal(format!("blob key `{}` has no prefix", key.as_str()))
        })?;
        Ok((format!("{}{dir}/", self.prefix), object))
    }

    async fn request(
        &self,
        action: PresignAction,
        key: &BlobKey,
    ) -> Result<PresignedRequest, AppError> {
        let (prefix, object) = self.split(key)?;
        let full = format!("{prefix}{object}");
        if action == PresignAction::Get
            && let Some(cached) = self.cached(&full)
        {
            return Ok(cached);
        }
        let req = self.presigner.presign(action, &prefix, object).await?;
        self.check(&req, action, &full)?;
        if action == PresignAction::Get {
            self.remember(full, req.clone());
        }
        Ok(req)
    }

    fn check(
        &self,
        req: &PresignedRequest,
        action: PresignAction,
        full_key: &str,
    ) -> Result<(), AppError> {
        let refuse = |why: &str| {
            Err(AppError::Internal(format!(
                "the presigned request for `{full_key}` was refused: {why}"
            )))
        };
        let url = match reqwest::Url::parse(&req.url) {
            Ok(u) => u,
            Err(_) => return refuse("its URL does not parse"),
        };
        let scheme_ok = url.scheme() == "https" || (self.plain_http && url.scheme() == "http");
        if !scheme_ok {
            return refuse("it is not HTTPS");
        }
        if !req.method.eq_ignore_ascii_case(action.method()) {
            return refuse("its method is not the operation asked for");
        }
        if !url.path().ends_with(&format!("/{full_key}")) {
            return refuse("it names a different object");
        }
        Ok(())
    }

    fn cached(&self, full_key: &str) -> Option<PresignedRequest> {
        let reads = self.reads.lock().unwrap_or_else(|p| p.into_inner());
        reads
            .get(full_key)
            .filter(|r| r.expires_at - REUSE_MARGIN > Utc::now())
            .cloned()
    }

    fn remember(&self, full_key: String, req: PresignedRequest) {
        let mut reads = self.reads.lock().unwrap_or_else(|p| p.into_inner());
        if reads.len() >= MAX_CACHED {
            let now = Utc::now();
            reads.retain(|_, r| r.expires_at - REUSE_MARGIN > now);
            if reads.len() >= MAX_CACHED {
                reads.clear();
            }
        }
        reads.insert(full_key, req);
    }

    fn forget(&self, key: &BlobKey) {
        if let Ok((prefix, object)) = self.split(key) {
            let mut reads = self.reads.lock().unwrap_or_else(|p| p.into_inner());
            reads.remove(&format!("{prefix}{object}"));
        }
    }

    /// Presign `ops` on `key`, each checked as [`Self::check`] checks a single one:
    /// HTTPS, the operation's method, the object asked for.
    async fn ops(
        &self,
        key: &BlobKey,
        upload_id: Option<&str>,
        ops: &[StorageOp],
    ) -> Result<Vec<PresignedRequest>, AppError> {
        let (prefix, object) = self.split(key)?;
        let full = format!("{prefix}{object}");
        let mut out = Vec::with_capacity(ops.len());
        for chunk in ops.chunks(MAX_OPS) {
            let reqs = self
                .presigner
                .presign_ops(&prefix, object, upload_id, chunk)
                .await?;
            if reqs.len() != chunk.len() {
                return Err(AppError::Internal(format!(
                    "the presigner answered {} requests for {} operations",
                    reqs.len(),
                    chunk.len()
                )));
            }
            for (req, op) in reqs.iter().zip(chunk) {
                self.check_method(req, op_method(op), &full)?;
            }
            out.extend(reqs);
        }
        Ok(out)
    }

    fn check_method(
        &self,
        req: &PresignedRequest,
        method: &str,
        full_key: &str,
    ) -> Result<(), AppError> {
        let refuse = |why: &str| {
            Err(AppError::Internal(format!(
                "the presigned request for `{full_key}` was refused: {why}"
            )))
        };
        let Ok(url) = reqwest::Url::parse(&req.url) else {
            return refuse("its URL does not parse");
        };
        if !(url.scheme() == "https" || (self.plain_http && url.scheme() == "http")) {
            return refuse("it is not HTTPS");
        }
        if !req.method.eq_ignore_ascii_case(method) {
            return refuse("its method is not the operation asked for");
        }
        if !url.path().ends_with(&format!("/{full_key}")) {
            return refuse("it names a different object");
        }
        Ok(())
    }

    /// Send `req` with `body`, refusing a non-success answer.
    async fn send(
        &self,
        op: &str,
        req: &PresignedRequest,
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response, AppError> {
        let mut b = self.builder(req)?;
        if let Some(body) = body {
            b = b.body(body);
        }
        let res = b.send().await.map_err(|e| transport(op, e))?;
        if !res.status().is_success() {
            return Err(refused(op, res.status()));
        }
        Ok(res)
    }

    /// Every part storage lists for `upload_id`, from the `list` requests in order
    /// until one is not truncated.
    async fn listed(&self, list: &[PresignedRequest]) -> Result<Vec<ListedPart>, AppError> {
        let mut parts = Vec::new();
        for req in list {
            let res = self.send("part listing", req, None).await?;
            let text = res.text().await.map_err(|e| transport("part listing", e))?;
            let page: ListPartsResult = quick_xml::de::from_str(&text).map_err(|e| {
                AppError::Internal(format!("storage's part listing does not parse: {e}"))
            })?;
            parts.extend(page.parts);
            if !page.is_truncated {
                return Ok(parts);
            }
        }
        Err(AppError::Internal(
            "storage lists more parts than the plan has".into(),
        ))
    }

    /// The planned parts the listing shows with their planned length and checksum,
    /// and whether it shows anything else (a part outside the plan, or one whose
    /// length or checksum differs).
    fn compare(plan: &[DirectPart], listed: &[ListedPart]) -> (Vec<u32>, Option<String>) {
        let mut held = Vec::new();
        for l in listed {
            let Some(p) = plan.iter().find(|p| p.number == l.part_number) else {
                return (
                    held,
                    Some(format!(
                        "storage holds part {}, which the plan does not",
                        l.part_number
                    )),
                );
            };
            if l.size != p.len {
                return (
                    held,
                    Some(format!(
                        "part {} is {} bytes, not {}",
                        p.number, l.size, p.len
                    )),
                );
            }
            if l.checksum_sha256.as_deref() != Some(checksum_b64(&p.sha256).as_str()) {
                return (
                    held,
                    Some(format!("part {}'s checksum is not the plan's", p.number)),
                );
            }
            held.push(p.number);
        }
        (held, None)
    }

    /// The list requests a plan of `parts` needs: one per 1000 parts.
    fn list_ops(parts: usize) -> Vec<StorageOp> {
        (0..parts.div_ceil(1000).max(1))
            .map(|page| StorageOp::ListParts {
                marker: (page > 0).then_some(page as u32 * 1000),
            })
            .collect()
    }

    /// HEAD with checksum mode: the object's length and SHA-256 as storage reports
    /// them, or `None` when it holds no object.
    async fn head(
        &self,
        req: &PresignedRequest,
    ) -> Result<Option<(u64, Option<String>)>, AppError> {
        let res = self
            .builder(req)?
            .send()
            .await
            .map_err(|e| transport("check", e))?;
        if res.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !res.status().is_success() {
            return Err(refused("check", res.status()));
        }
        let len = res
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(u64::MAX);
        let sum = res
            .headers()
            .get("x-amz-checksum-sha256")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        Ok(Some((len, sum)))
    }

    fn builder(&self, req: &PresignedRequest) -> Result<reqwest::RequestBuilder, AppError> {
        let method = reqwest::Method::from_bytes(req.method.to_ascii_uppercase().as_bytes())
            .map_err(|_| AppError::Internal("presigned request has no valid method".into()))?;
        // A test store on the loopback: the presigner names it `https` (as a target
        // handed to a member must be), and it answers plain `http`.
        let url = if self.plain_http && req.url.starts_with("https://127.0.0.1") {
            req.url.replacen("https://", "http://", 1)
        } else {
            req.url.clone()
        };
        let mut b = self.http.request(method, &url);
        for (name, value) in &req.headers {
            b = b.header(name, value);
        }
        Ok(b)
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// A transport failure, without the URL: reqwest's error names it, signature
/// included.
fn transport(op: &str, e: reqwest::Error) -> AppError {
    AppError::ServiceError {
        status: axum::http::StatusCode::BAD_GATEWAY,
        message: format!("storage {op} failed: {}", e.without_url()),
    }
}

fn refused(op: &str, status: StatusCode) -> AppError {
    AppError::ServiceError {
        status: axum::http::StatusCode::BAD_GATEWAY,
        message: format!("storage refused the {op}: HTTP {}", status.as_u16()),
    }
}

#[async_trait]
impl BlobStore for PresignedBlobs {
    fn kind(&self) -> &'static str {
        self.kind
    }

    async fn put(&self, key: &BlobKey, staged: &Path, size: u64) -> Result<BackendRef, AppError> {
        let req = self.request(PresignAction::Put, key).await?;
        let file = tokio::fs::File::open(staged).await.map_err(AppError::Io)?;
        let res = self
            .builder(&req)?
            .header(reqwest::header::CONTENT_LENGTH, size)
            .body(reqwest::Body::from(file))
            .send()
            .await
            .map_err(|e| transport("upload", e))?;
        if !res.status().is_success() {
            return Err(refused("upload", res.status()));
        }
        Ok(BackendRef {
            kind: self.kind.to_string(),
            key: key.clone(),
        })
    }

    async fn get_range(&self, at: &BackendRef, start: u64, end: u64) -> Result<Vec<u8>, AppError> {
        check_kind(self, at)?;
        if end <= start {
            return Ok(Vec::new());
        }
        let req = self.request(PresignAction::Get, &at.key).await?;
        let res = self
            .builder(&req)?
            .header(reqwest::header::RANGE, format!("bytes={start}-{}", end - 1))
            .send()
            .await
            .map_err(|e| transport("read", e))?;
        match res.status() {
            StatusCode::PARTIAL_CONTENT | StatusCode::OK => {}
            StatusCode::NOT_FOUND => {
                return Err(AppError::NotFound(format!(
                    "blob `{}` is not in storage",
                    at.key.as_str()
                )));
            }
            StatusCode::RANGE_NOT_SATISFIABLE => {
                return Err(AppError::Validation(format!(
                    "bytes {start}..{end} are past the end of blob `{}`",
                    at.key.as_str()
                )));
            }
            // A request the store no longer accepts (expired, or the key was
            // rotated): drop it, so the next read asks again.
            StatusCode::FORBIDDEN => {
                self.forget(&at.key);
                return Err(refused("read", StatusCode::FORBIDDEN));
            }
            other => return Err(refused("read", other)),
        }
        let whole = res.status() == StatusCode::OK;
        let body = res.bytes().await.map_err(|e| transport("read", e))?;
        // A store that ignored the range sent the whole object; take the slice.
        let bytes = if whole {
            let (s, e) = (start as usize, end as usize);
            if e > body.len() {
                Vec::new()
            } else {
                body[s..e].to_vec()
            }
        } else {
            body.to_vec()
        };
        if bytes.len() as u64 != end - start {
            return Err(AppError::Validation(format!(
                "bytes {start}..{end} are past the end of blob `{}`",
                at.key.as_str()
            )));
        }
        Ok(bytes)
    }

    async fn delete(&self, at: &BackendRef) -> Result<Deletion, AppError> {
        check_kind(self, at)?;
        self.forget(&at.key);
        let req = self.request(PresignAction::Delete, &at.key).await?;
        let res = self
            .builder(&req)?
            .send()
            .await
            .map_err(|e| transport("delete", e))?;
        if res.status().is_success() || res.status() == StatusCode::NOT_FOUND {
            Ok(Deletion::Deleted)
        } else {
            Err(refused("delete", res.status()))
        }
    }

    /// A fresh `GET` for a reader, presigned for this one blob — never the request
    /// this store keeps for its own reads, so the reader gets the request's whole
    /// lifetime and the store's cached one is never handed out.
    async fn read_target(&self, at: &BackendRef) -> Result<Option<PresignedRequest>, AppError> {
        check_kind(self, at)?;
        let (prefix, object) = self.split(&at.key)?;
        let req = self
            .presigner
            .presign(PresignAction::Get, &prefix, object)
            .await?;
        self.check(&req, PresignAction::Get, &format!("{prefix}{object}"))?;
        Ok(Some(req))
    }

    fn direct_uploads(&self) -> bool {
        self.presigner.presigns_ops()
    }

    async fn direct_begin(
        &self,
        key: &BlobKey,
        multipart: bool,
    ) -> Result<Option<String>, AppError> {
        if !multipart {
            return Ok(None);
        }
        let reqs = self.ops(key, None, &[StorageOp::CreateMultipart]).await?;
        let res = self.send("multipart start", &reqs[0], None).await?;
        let text = res
            .text()
            .await
            .map_err(|e| transport("multipart start", e))?;
        let started: InitiateMultipartUploadResult =
            quick_xml::de::from_str(&text).map_err(|e| {
                AppError::Internal(format!("storage's multipart start does not parse: {e}"))
            })?;
        Ok(Some(started.upload_id))
    }

    async fn direct_targets(
        &self,
        key: &BlobKey,
        upload_id: Option<&str>,
        parts: &[DirectPart],
    ) -> Result<Vec<PresignedRequest>, AppError> {
        let ops: Vec<StorageOp> = parts
            .iter()
            .map(|p| match upload_id {
                Some(_) => StorageOp::UploadPart {
                    part: p.number,
                    len: p.len,
                    sha256: p.sha256,
                },
                None => StorageOp::Put {
                    len: p.len,
                    sha256: p.sha256,
                },
            })
            .collect();
        self.ops(key, upload_id, &ops).await
    }

    async fn direct_held(
        &self,
        key: &BlobKey,
        upload_id: Option<&str>,
        plan: &[DirectPart],
    ) -> Result<Vec<u32>, AppError> {
        match upload_id {
            Some(id) => {
                let list = self.ops(key, Some(id), &Self::list_ops(plan.len())).await?;
                let listed = self.listed(&list).await?;
                Ok(Self::compare(plan, &listed).0)
            }
            None => {
                let head = self.ops(key, None, &[StorageOp::Head]).await?;
                let p = plan.first().copied();
                Ok(match (self.head(&head[0]).await?, p) {
                    (Some((len, Some(sum))), Some(p))
                        if len == p.len && sum == checksum_b64(&p.sha256) =>
                    {
                        vec![p.number]
                    }
                    _ => Vec::new(),
                })
            }
        }
    }

    /// `rooms/blobs/upload/commit/0.2` item 3, at storage: every part's length and
    /// checksum (listed), the completion bound to the planned size, and the
    /// assembled object's length and checksum (head) — all asked for in one
    /// issuance with the abort and delete a disagreement needs. On any disagreement
    /// what storage holds for the upload is deleted.
    async fn direct_finish(
        &self,
        key: &BlobKey,
        upload_id: Option<&str>,
        plan: &[DirectPart],
    ) -> Result<DirectFinish, AppError> {
        let total: u64 = plan.iter().map(|p| p.len).sum();
        let Some(id) = upload_id else {
            let reqs = self
                .ops(key, None, &[StorageOp::Head, StorageOp::Delete])
                .await?;
            let Some(p) = plan.first() else {
                return Err(AppError::Internal("a direct upload with no parts".into()));
            };
            return match self.head(&reqs[0]).await? {
                None => Ok(DirectFinish::Missing(1)),
                Some((len, sum))
                    if len == p.len && sum.as_deref() == Some(checksum_b64(&p.sha256).as_str()) =>
                {
                    Ok(DirectFinish::Stored(BackendRef {
                        kind: self.kind.to_string(),
                        key: key.clone(),
                    }))
                }
                Some((len, _)) => {
                    self.send("delete", &reqs[1], None).await?;
                    Ok(DirectFinish::Mismatch(format!(
                        "storage holds {len} bytes, or a checksum, other than the plan's"
                    )))
                }
            };
        };
        let mut ops = Self::list_ops(plan.len());
        let lists = ops.len();
        ops.extend([
            StorageOp::CompleteMultipart { len: total },
            StorageOp::Head,
            StorageOp::AbortMultipart,
            StorageOp::Delete,
        ]);
        let reqs = self.ops(key, Some(id), &ops).await?;
        let (list, rest) = reqs.split_at(lists);
        let (complete, head, abort, delete) = (&rest[0], &rest[1], &rest[2], &rest[3]);
        let discard = |why: String| async move {
            let _ = self.send("abort", abort, None).await;
            let _ = self.send("delete", delete, None).await;
            Ok(DirectFinish::Mismatch(why))
        };

        let listed = self.listed(list).await?;
        let (held, wrong) = Self::compare(plan, &listed);
        if let Some(why) = wrong {
            return discard(why).await;
        }
        if held.len() < plan.len() {
            return Ok(DirectFinish::Missing((plan.len() - held.len()) as u64));
        }
        let mut body = String::from("<CompleteMultipartUpload>");
        for p in plan {
            let l = listed
                .iter()
                .find(|l| l.part_number == p.number)
                .expect("compared above");
            body.push_str(&format!(
                "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag><ChecksumSHA256>{}</ChecksumSHA256></Part>",
                p.number,
                xml_escape(&l.etag),
                checksum_b64(&p.sha256)
            ));
        }
        body.push_str("</CompleteMultipartUpload>");
        let completed = self
            .builder(complete)?
            .body(body)
            .send()
            .await
            .map_err(|e| transport("completion", e))?;
        let status = completed.status();
        // S3 can answer 200 with an error document in the body.
        let text = completed.text().await.unwrap_or_default();
        if !status.is_success() || text.contains("<Error>") {
            return discard(format!(
                "storage refused to assemble the parts (HTTP {})",
                status.as_u16()
            ))
            .await;
        }
        match self.head(head).await? {
            Some((len, Some(sum))) if len == total && sum == composite_checksum(plan) => {
                Ok(DirectFinish::Stored(BackendRef {
                    kind: self.kind.to_string(),
                    key: key.clone(),
                }))
            }
            Some((len, sum)) => {
                discard(format!(
                    "the assembled object is {len} bytes with checksum {}, not the plan's",
                    sum.as_deref().unwrap_or("(none reported)")
                ))
                .await
            }
            None => discard("the assembled object is not in storage".into()).await,
        }
    }

    async fn direct_abort(&self, key: &BlobKey, upload_id: Option<&str>) -> Result<(), AppError> {
        let ops: Vec<StorageOp> = match upload_id {
            Some(_) => vec![StorageOp::AbortMultipart, StorageOp::Delete],
            None => vec![StorageOp::Delete],
        };
        for req in self.ops(key, upload_id, &ops).await? {
            let res = self
                .builder(&req)?
                .send()
                .await
                .map_err(|e| transport("abort", e))?;
            // Gone already is aborted.
            if !(res.status().is_success() || res.status() == StatusCode::NOT_FOUND) {
                return Err(refused("abort", res.status()));
            }
        }
        Ok(())
    }

    /// Whether a request can be presigned now: the presigner answers, and for
    /// an object in this store's layout. The store itself is exercised by a
    /// probe, which writes, reads and deletes.
    async fn health(&self) -> Health {
        let mut nonce = [0u8; 16];
        rand::fill(&mut nonce);
        let object: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let prefix = format!("{}{PROBE_PREFIX}", self.prefix);
        let full = format!("{prefix}{object}");
        match self
            .presigner
            .presign(PresignAction::Get, &prefix, &object)
            .await
            .and_then(|req| self.check(&req, PresignAction::Get, &full))
        {
            Ok(()) => Health {
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
    use axum::Router;
    use axum::body::Bytes;
    use axum::extract::{Path as AxPath, State};
    use axum::http::{HeaderMap, StatusCode as Ax};
    use axum::routing::put;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type Objects = Arc<Mutex<HashMap<String, Vec<u8>>>>;

    /// An S3-shaped server on the loopback: PUT, ranged GET, DELETE.
    async fn bucket() -> (String, Objects) {
        let objects: Objects = Arc::default();
        async fn put_obj(State(o): State<Objects>, AxPath(k): AxPath<String>, body: Bytes) -> Ax {
            o.lock().unwrap().insert(k, body.to_vec());
            Ax::OK
        }
        async fn get_obj(
            State(o): State<Objects>,
            AxPath(k): AxPath<String>,
            headers: HeaderMap,
        ) -> (Ax, Vec<u8>) {
            let Some(v) = o.lock().unwrap().get(&k).cloned() else {
                return (Ax::NOT_FOUND, Vec::new());
            };
            let range = headers
                .get("range")
                .and_then(|r| r.to_str().ok())
                .and_then(|r| r.strip_prefix("bytes="))
                .and_then(|r| r.split_once('-'))
                .and_then(|(a, b)| Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?)));
            match range {
                Some((a, _)) if a >= v.len() => (Ax::RANGE_NOT_SATISFIABLE, Vec::new()),
                // S3 answers a range that runs past the end with what there is.
                Some((a, b)) => (Ax::PARTIAL_CONTENT, v[a..(b + 1).min(v.len())].to_vec()),
                None => (Ax::OK, v),
            }
        }
        async fn del_obj(State(o): State<Objects>, AxPath(k): AxPath<String>) -> Ax {
            o.lock().unwrap().remove(&k);
            Ax::NO_CONTENT
        }
        let app = Router::new()
            .route("/bucket/{*key}", put(put_obj).get(get_obj).delete(del_obj))
            .with_state(objects.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}/bucket/"), objects)
    }

    struct Fake {
        base: String,
        calls: AtomicUsize,
        /// Sign this object instead of the one asked for.
        swap: Option<String>,
    }

    #[async_trait]
    impl Presigner for Fake {
        async fn presign(
            &self,
            action: PresignAction,
            prefix: &str,
            object_key: &str,
        ) -> Result<PresignedRequest, AppError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let object = self
                .swap
                .clone()
                .unwrap_or_else(|| format!("{prefix}{object_key}"));
            Ok(PresignedRequest {
                method: action.method().into(),
                url: format!("{}{object}?X-Amz-Signature=secret", self.base),
                headers: BTreeMap::new(),
                expires_at: Utc::now() + chrono::Duration::minutes(5),
            })
        }
    }

    fn store(base: &str, swap: Option<String>) -> (PresignedBlobs, Arc<Fake>) {
        let fake = Arc::new(Fake {
            base: base.into(),
            calls: AtomicUsize::new(0),
            swap,
        });
        let s = PresignedBlobs::new("s3", fake.clone(), Some("community/"))
            .unwrap()
            .with_plain_http();
        (s, fake)
    }

    #[tokio::test]
    async fn conforms() {
        let (base, objects) = bucket().await;
        let (s, _) = store(&base, None);
        let scratch = tempfile::tempdir().unwrap();
        super::super::conformance::run(&s, scratch.path()).await;
        assert!(
            objects.lock().unwrap().is_empty(),
            "the suite leaves nothing behind"
        );
    }

    #[tokio::test]
    async fn objects_live_under_the_config_prefix_and_the_room_prefix() {
        let (base, objects) = bucket().await;
        let (s, _) = store(&base, None);
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("b");
        tokio::fs::write(&staged, b"hello").await.unwrap();
        let key = BlobKey::for_room(
            "did:key:zRoom",
            &super::super::sha256_digest_multibase(&[1; 32]),
        )
        .unwrap();
        s.put(&key, &staged, 5).await.unwrap();
        let stored: Vec<String> = objects.lock().unwrap().keys().cloned().collect();
        assert_eq!(stored, vec![format!("community/{}", key.as_str())]);
    }

    #[tokio::test]
    async fn ranges_of_one_blob_reuse_one_read_request() {
        let (base, _) = bucket().await;
        let (s, fake) = store(&base, None);
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("b");
        tokio::fs::write(&staged, vec![7u8; 100]).await.unwrap();
        let key = BlobKey::for_room(
            "did:key:zRoom",
            &super::super::sha256_digest_multibase(&[2; 32]),
        )
        .unwrap();
        let at = s.put(&key, &staged, 100).await.unwrap();
        let before = fake.calls.load(Ordering::SeqCst);
        for i in 0..5 {
            s.get_range(&at, i * 10, i * 10 + 10).await.unwrap();
        }
        assert_eq!(fake.calls.load(Ordering::SeqCst) - before, 1);
    }

    #[tokio::test]
    async fn a_request_for_another_object_is_refused_before_it_is_sent() {
        let (base, objects) = bucket().await;
        let (s, _) = store(&base, Some("elsewhere/x".into()));
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("b");
        tokio::fs::write(&staged, b"x").await.unwrap();
        let key = BlobKey::for_room(
            "did:key:zRoom",
            &super::super::sha256_digest_multibase(&[3; 32]),
        )
        .unwrap();
        let err = s.put(&key, &staged, 1).await.unwrap_err().to_string();
        assert!(err.contains("different object"), "{err}");
        assert!(objects.lock().unwrap().is_empty());
        assert!(!s.health().await.ok);
    }

    /// A reader's target is presigned for it alone: a fresh `GET` of the one blob, never
    /// the request this store keeps for its own ranged reads.
    #[tokio::test]
    async fn a_read_target_is_a_fresh_get_of_the_one_blob() {
        let (base, _) = bucket().await;
        let (s, fake) = store(&base, None);
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("b");
        tokio::fs::write(&staged, vec![9u8; 40]).await.unwrap();
        let key = BlobKey::for_room(
            "did:key:zRoom",
            &super::super::sha256_digest_multibase(&[4; 32]),
        )
        .unwrap();
        let at = s.put(&key, &staged, 40).await.unwrap();
        s.get_range(&at, 0, 10).await.unwrap();
        let before = fake.calls.load(Ordering::SeqCst);
        let target = s
            .read_target(&at)
            .await
            .unwrap()
            .expect("a presigned store issues one");
        assert_eq!(
            fake.calls.load(Ordering::SeqCst) - before,
            1,
            "presigned afresh"
        );
        assert_eq!(target.method, "GET");
        assert!(target.url.contains(&format!("community/{}", key.as_str())));

        let (other, _) = store(&base, Some("elsewhere/x".into()));
        assert!(
            other.read_target(&at).await.is_err(),
            "another object is refused"
        );
    }

    #[tokio::test]
    async fn plain_http_is_refused_outside_tests() {
        let (base, _) = bucket().await;
        let fake = Arc::new(Fake {
            base,
            calls: AtomicUsize::new(0),
            swap: None,
        });
        let s = PresignedBlobs::new("s3", fake, None).unwrap();
        let health = s.health().await;
        assert!(!health.ok);
        assert!(health.detail.unwrap().contains("not HTTPS"));
    }

    #[test]
    fn a_presigned_request_never_prints_its_url() {
        let r = PresignedRequest {
            method: "GET".into(),
            url: "https://b/k?X-Amz-Signature=secret".into(),
            headers: BTreeMap::new(),
            expires_at: Utc::now(),
        };
        assert!(!format!("{r:?}").contains("secret"));
    }
}

#[cfg(test)]
mod direct_tests {
    use super::super::mock_s3::MockS3;
    use super::*;
    use sha2::{Digest, Sha256};

    const PART: usize = super::super::MIN_MULTIPART_PART_BYTES as usize;

    fn store(s3: &MockS3) -> PresignedBlobs {
        PresignedBlobs::new("s3", s3.presigner(), Some("community/"))
            .unwrap()
            .with_plain_http()
    }

    fn plan(bytes: &[u8], part: usize) -> Vec<DirectPart> {
        bytes
            .chunks(part)
            .enumerate()
            .map(|(i, c)| DirectPart {
                number: i as u32 + 1,
                len: c.len() as u64,
                sha256: Sha256::digest(c).into(),
            })
            .collect()
    }

    fn key(n: u8) -> BlobKey {
        BlobKey::for_upload(
            "did:key:zRoom",
            &super::super::sha256_digest_multibase(&[n; 32]),
            &uuid::Uuid::new_v4(),
        )
        .unwrap()
    }

    /// What a member's client does with a target: send exactly its method and
    /// headers, and the bytes.
    async fn put(target: &PresignedRequest, bytes: &[u8]) -> reqwest::StatusCode {
        let mut b = reqwest::Client::new().put(target.url.replacen("https://", "http://", 1));
        for (k, v) in &target.headers {
            b = b.header(k, v);
        }
        b.body(bytes.to_vec()).send().await.unwrap().status()
    }

    /// A multipart direct upload end to end: create, write each part to its
    /// bound target, verify at storage (listing, completion bound to the size,
    /// head with the composite checksum), and the object is there.
    #[tokio::test]
    async fn a_multipart_upload_is_verified_at_storage_and_completed() {
        let s3 = MockS3::start(true).await;
        let s = store(&s3);
        assert!(s.direct_uploads());
        let bytes: Vec<u8> = (0..PART * 2 + 1000).map(|i| (i % 251) as u8).collect();
        let plan = plan(&bytes, PART);
        let k = key(1);
        let id = s
            .direct_begin(&k, true)
            .await
            .unwrap()
            .expect("an upload id");
        let targets = s.direct_targets(&k, Some(&id), &plan).await.unwrap();
        assert_eq!(targets.len(), 3);
        assert_eq!(
            s.direct_finish(&k, Some(&id), &plan).await.unwrap(),
            DirectFinish::Missing(3)
        );
        for (t, c) in targets.iter().zip(bytes.chunks(PART)).take(2) {
            assert!(put(t, c).await.is_success());
        }
        assert_eq!(
            s.direct_held(&k, Some(&id), &plan).await.unwrap(),
            vec![1, 2]
        );
        assert!(put(&targets[2], &bytes[PART * 2..]).await.is_success());
        match s.direct_finish(&k, Some(&id), &plan).await.unwrap() {
            DirectFinish::Stored(at) => assert_eq!(
                s.get_range(&at, 0, bytes.len() as u64).await.unwrap(),
                bytes
            ),
            other => panic!("{other:?}"),
        }
        assert_eq!(s3.open_uploads(), 0);
    }

    /// Storage itself refuses bytes other than the signed checksum; a store that
    /// does not is caught at commit, which deletes what it holds.
    #[tokio::test]
    async fn other_bytes_are_refused_by_storage_or_caught_at_commit() {
        let s3 = MockS3::start(true).await;
        let s = store(&s3);
        let bytes = vec![7u8; PART + 10];
        let plan = plan(&bytes, PART);
        let k = key(2);
        let id = s.direct_begin(&k, true).await.unwrap().unwrap();
        let targets = s.direct_targets(&k, Some(&id), &plan).await.unwrap();
        let mut forged = bytes[..PART].to_vec();
        forged[0] ^= 1;
        assert_eq!(
            put(&targets[0], &forged).await,
            reqwest::StatusCode::BAD_REQUEST
        );

        let lax = MockS3::start(false).await;
        let s = store(&lax);
        let k = key(3);
        let id = s.direct_begin(&k, true).await.unwrap().unwrap();
        let targets = s.direct_targets(&k, Some(&id), &plan).await.unwrap();
        assert!(put(&targets[0], &forged).await.is_success());
        assert!(put(&targets[1], &bytes[PART..]).await.is_success());
        assert!(matches!(
            s.direct_finish(&k, Some(&id), &plan).await.unwrap(),
            DirectFinish::Mismatch(_)
        ));
        assert_eq!(lax.open_uploads(), 0, "the upload is aborted");
        assert!(lax.objects().is_empty(), "nothing is left");
    }

    #[tokio::test]
    async fn a_single_part_upload_is_one_bound_put_checked_by_head() {
        let s3 = MockS3::start(false).await;
        let s = store(&s3);
        let bytes = vec![3u8; 1000];
        let plan = plan(&bytes, 1000);
        let k = key(4);
        assert_eq!(s.direct_begin(&k, false).await.unwrap(), None);
        let t = s.direct_targets(&k, None, &plan).await.unwrap();
        assert_eq!(t[0].headers["Content-Length"], "1000");
        assert_eq!(
            s.direct_finish(&k, None, &plan).await.unwrap(),
            DirectFinish::Missing(1)
        );
        assert!(put(&t[0], &vec![4u8; 1000]).await.is_success());
        assert!(matches!(
            s.direct_finish(&k, None, &plan).await.unwrap(),
            DirectFinish::Mismatch(_)
        ));
        assert!(s3.objects().is_empty(), "the wrong object is deleted");
        assert!(put(&t[0], &bytes).await.is_success());
        assert!(matches!(
            s.direct_finish(&k, None, &plan).await.unwrap(),
            DirectFinish::Stored(_)
        ));
    }

    #[tokio::test]
    async fn abort_reclaims_parts_and_the_object() {
        let s3 = MockS3::start(true).await;
        let s = store(&s3);
        let bytes = vec![5u8; PART + 1];
        let plan = plan(&bytes, PART);
        let k = key(5);
        let id = s.direct_begin(&k, true).await.unwrap().unwrap();
        let targets = s.direct_targets(&k, Some(&id), &plan).await.unwrap();
        assert!(put(&targets[0], &bytes[..PART]).await.is_success());
        s.direct_abort(&k, Some(&id)).await.unwrap();
        assert_eq!(s3.open_uploads(), 0);
        // Again: already gone is aborted.
        s.direct_abort(&k, Some(&id)).await.unwrap();
    }
}
