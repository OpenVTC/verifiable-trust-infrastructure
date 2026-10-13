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

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::StatusCode;

use super::{BackendRef, BlobKey, BlobStore, Deletion, Health, PROBE_PREFIX, check_kind};
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

/// One presigned request, as a presigner hands it over.
#[derive(Clone)]
pub struct PresignedRequest {
    pub method: String,
    pub url: String,
    /// Headers the request must carry for its signature to verify.
    pub headers: BTreeMap<String, String>,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for PresignedRequest {
    // The URL carries its signature: never in a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresignedRequest")
            .field("method", &self.method)
            .field("url", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

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

    fn builder(&self, req: &PresignedRequest) -> Result<reqwest::RequestBuilder, AppError> {
        let method = reqwest::Method::from_bytes(req.method.to_ascii_uppercase().as_bytes())
            .map_err(|_| AppError::Internal("presigned request has no valid method".into()))?;
        let mut b = self.http.request(method, &req.url);
        for (name, value) in &req.headers {
            b = b.header(name, value);
        }
        Ok(b)
    }
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
