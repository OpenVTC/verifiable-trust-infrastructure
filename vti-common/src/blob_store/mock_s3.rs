//! An S3-shaped store on the loopback, for tests of direct transfer: objects,
//! ranged reads, multipart uploads (create, upload part, list parts, complete,
//! abort) and head with checksum mode — and a [`MockPresigner`] for it.
//!
//! In **enforcing** mode it does what S3 does with the headers a presigned write
//! carries: a body whose SHA-256 is not `x-amz-checksum-sha256` is refused, a part
//! of an upload created with `x-amz-checksum-algorithm: SHA256` must carry one, and
//! a completion whose `x-amz-mp-object-size` is not the assembled size is refused.
//! In **lax** mode it accepts any bytes, as an S3-compatible store that ignores
//! those headers would — but it always *reports* the truth (each part's real
//! checksum in a listing, the object's real checksum on head), which is what a
//! host's verification at commit relies on.
//!
//! The presigner signs nothing: a URL is the object's path and the operation's
//! query, scheme `https` (as a target must be), which a store built
//! [`with_plain_http`](super::presigned::PresignedBlobs::with_plain_http) and a
//! test client rewrite to the loopback's `http`.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use chrono::Utc;
use sha2::{Digest, Sha256};

use super::StorageOp;
use super::presigned::{PresignAction, PresignedRequest, Presigner, checksum_b64};
use crate::error::AppError;

#[derive(Default)]
struct Upload {
    key: String,
    checksum_required: bool,
    parts: BTreeMap<u32, (Vec<u8>, [u8; 32])>,
}

#[derive(Default)]
struct Inner {
    objects: HashMap<String, (Vec<u8>, String)>,
    uploads: HashMap<String, Upload>,
    next: u64,
}

/// The store. Clone it freely: every clone is the same bucket.
#[derive(Clone)]
pub struct MockS3 {
    /// `http://127.0.0.1:<port>/bucket/`.
    pub base: String,
    enforce: bool,
    inner: Arc<Mutex<Inner>>,
}

fn etag(bytes: &[u8]) -> String {
    format!("\"{}\"", hex::encode(&Sha256::digest(bytes)[..16]))
}

fn xml(status: StatusCode, body: String) -> Response {
    (status, [("content-type", "application/xml")], body).into_response()
}

impl MockS3 {
    /// Start one on the loopback; `enforce` as the module describes.
    pub async fn start(enforce: bool) -> Self {
        let s = Self {
            base: String::new(),
            enforce,
            inner: Arc::default(),
        };
        let app = Router::new()
            .route("/bucket/{*key}", any(handle))
            .layer(axum::extract::DefaultBodyLimit::disable())
            .with_state(s.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            base: format!("http://{addr}/bucket/"),
            ..s
        }
    }

    /// The keys of the objects stored.
    pub fn objects(&self) -> Vec<String> {
        let mut v: Vec<String> = self.inner.lock().unwrap().objects.keys().cloned().collect();
        v.sort();
        v
    }

    /// The bytes of one object.
    pub fn object(&self, key: &str) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .unwrap()
            .objects
            .get(key)
            .map(|o| o.0.clone())
    }

    /// How many multipart uploads are open.
    pub fn open_uploads(&self) -> usize {
        self.inner.lock().unwrap().uploads.len()
    }

    /// A presigner for this store, presigning ops and single requests alike.
    pub fn presigner(&self) -> Arc<MockPresigner> {
        Arc::new(MockPresigner {
            base: self.base.replacen("http://", "https://", 1),
        })
    }
}

async fn handle(
    State(s): State<MockS3>,
    method: Method,
    Path(key): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let h = |n: &str| {
        headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let mut inner = s.inner.lock().unwrap();
    match (method.as_str(), q.get("uploadId"), q.get("partNumber")) {
        ("POST", None, None) if q.contains_key("uploads") => {
            inner.next += 1;
            let id = format!("up-{}", inner.next);
            let required = h("x-amz-checksum-algorithm").as_deref() == Some("SHA256");
            inner.uploads.insert(
                id.clone(),
                Upload {
                    key: key.clone(),
                    checksum_required: required,
                    parts: BTreeMap::new(),
                },
            );
            xml(
                StatusCode::OK,
                format!(
                    "<InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>{key}</Key>\
                     <UploadId>{id}</UploadId></InitiateMultipartUploadResult>"
                ),
            )
        }
        ("PUT", Some(id), Some(n)) => {
            let enforce = s.enforce;
            let Some(up) = inner.uploads.get_mut(id).filter(|u| u.key == key) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let sum: [u8; 32] = Sha256::digest(&body).into();
            match h("x-amz-checksum-sha256") {
                Some(c) if enforce && c != checksum_b64(&sum) => {
                    return xml(
                        StatusCode::BAD_REQUEST,
                        "<Error><Code>BadDigest</Code></Error>".into(),
                    );
                }
                None if enforce && up.checksum_required => {
                    return xml(
                        StatusCode::BAD_REQUEST,
                        "<Error><Code>InvalidRequest</Code></Error>".into(),
                    );
                }
                _ => {}
            }
            let n: u32 = n.parse().unwrap_or(0);
            up.parts.insert(n, (body.to_vec(), sum));
            ([("etag", etag(&body))], StatusCode::OK).into_response()
        }
        ("GET", Some(id), None) => {
            let Some(up) = inner.uploads.get(id).filter(|u| u.key == key) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let max: usize = q
                .get("max-parts")
                .and_then(|m| m.parse().ok())
                .unwrap_or(1000);
            let marker: u32 = q
                .get("part-number-marker")
                .and_then(|m| m.parse().ok())
                .unwrap_or(0);
            let after: Vec<_> = up.parts.iter().filter(|(n, _)| **n > marker).collect();
            let mut out = String::from("<ListPartsResult>");
            for (n, (bytes, sum)) in after.iter().take(max) {
                out.push_str(&format!(
                    "<Part><PartNumber>{n}</PartNumber><Size>{}</Size><ETag>{}</ETag>\
                     <ChecksumSHA256>{}</ChecksumSHA256></Part>",
                    bytes.len(),
                    etag(bytes).replace('"', "&quot;"),
                    checksum_b64(sum)
                ));
            }
            out.push_str(&format!(
                "<IsTruncated>{}</IsTruncated></ListPartsResult>",
                after.len() > max
            ));
            xml(StatusCode::OK, out)
        }
        ("POST", Some(id), None) => {
            let text = String::from_utf8_lossy(&body).to_string();
            let Some(up) = inner.uploads.get(id).filter(|u| u.key == key) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let mut assembled = Vec::new();
            let mut sums = Vec::new();
            let mut count = 0;
            for chunk in text.split("<Part>").skip(1) {
                let field = |tag: &str| {
                    chunk
                        .split(&format!("<{tag}>"))
                        .nth(1)
                        .and_then(|r| r.split(&format!("</{tag}>")).next())
                        .map(|v| v.replace("&quot;", "\""))
                };
                let n: u32 = field("PartNumber")
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(0);
                let Some((bytes, sum)) = up.parts.get(&n) else {
                    return xml(
                        StatusCode::BAD_REQUEST,
                        "<Error><Code>InvalidPart</Code></Error>".into(),
                    );
                };
                if field("ETag").as_deref() != Some(etag(bytes).as_str()) {
                    return xml(
                        StatusCode::BAD_REQUEST,
                        "<Error><Code>InvalidPart</Code></Error>".into(),
                    );
                }
                assembled.extend_from_slice(bytes);
                sums.extend_from_slice(sum);
                count += 1;
            }
            if s.enforce
                && let Some(size) = h("x-amz-mp-object-size")
                && size.parse::<usize>().ok() != Some(assembled.len())
            {
                return xml(
                    StatusCode::BAD_REQUEST,
                    "<Error><Code>InvalidRequest</Code></Error>".into(),
                );
            }
            let composite = format!("{}-{count}", checksum_b64(&Sha256::digest(&sums).into()));
            inner.uploads.remove(id);
            inner.objects.insert(key.clone(), (assembled, composite));
            xml(
                StatusCode::OK,
                format!(
                    "<CompleteMultipartUploadResult><Key>{key}</Key></CompleteMultipartUploadResult>"
                ),
            )
        }
        ("DELETE", Some(id), None) => match inner.uploads.remove(id) {
            Some(_) => StatusCode::NO_CONTENT.into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
        ("PUT", None, None) => {
            let sum: [u8; 32] = Sha256::digest(&body).into();
            if s.enforce
                && let Some(c) = h("x-amz-checksum-sha256")
                && c != checksum_b64(&sum)
            {
                return xml(
                    StatusCode::BAD_REQUEST,
                    "<Error><Code>BadDigest</Code></Error>".into(),
                );
            }
            inner
                .objects
                .insert(key, (body.to_vec(), checksum_b64(&sum)));
            StatusCode::OK.into_response()
        }
        ("HEAD", None, None) => match inner.objects.get(&key) {
            None => StatusCode::NOT_FOUND.into_response(),
            Some((bytes, sum)) => {
                let mut r = StatusCode::OK.into_response();
                r.headers_mut()
                    .insert("content-length", bytes.len().to_string().parse().unwrap());
                if h("x-amz-checksum-mode").as_deref() == Some("ENABLED") {
                    r.headers_mut()
                        .insert("x-amz-checksum-sha256", sum.parse().unwrap());
                }
                r
            }
        },
        ("GET", None, None) => {
            let Some((v, _)) = inner.objects.get(&key) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let range = h("range")
                .and_then(|r| r.strip_prefix("bytes=").map(str::to_string))
                .and_then(|r| {
                    let (a, b) = r.split_once('-')?;
                    Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?))
                });
            match range {
                Some((a, _)) if a >= v.len() => StatusCode::RANGE_NOT_SATISFIABLE.into_response(),
                Some((a, b)) => (
                    StatusCode::PARTIAL_CONTENT,
                    v[a..(b + 1).min(v.len())].to_vec(),
                )
                    .into_response(),
                None => (StatusCode::OK, v.clone()).into_response(),
            }
        }
        ("DELETE", None, None) => {
            inner.objects.remove(&key);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

/// Presigns for a [`MockS3`]: each request names the object, the operation's query
/// and the headers S3 would have signed. Signs nothing.
pub struct MockPresigner {
    base: String,
}

impl MockPresigner {
    fn url(&self, prefix: &str, object: &str, query: &[(&str, String)]) -> String {
        let mut q: Vec<String> = query
            .iter()
            .map(|(k, v)| format!("{k}={}", urlencode(v)))
            .collect();
        q.push("X-Amz-Signature=fake".into());
        format!("{}{prefix}{object}?{}", self.base, q.join("&"))
    }
}

fn urlencode(v: &str) -> String {
    v.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[async_trait]
impl Presigner for MockPresigner {
    async fn presign(
        &self,
        action: PresignAction,
        prefix: &str,
        object_key: &str,
    ) -> Result<PresignedRequest, AppError> {
        let method = match action {
            PresignAction::Put => "PUT",
            PresignAction::Get => "GET",
            PresignAction::Delete => "DELETE",
        };
        Ok(PresignedRequest {
            method: method.into(),
            url: self.url(prefix, object_key, &[]),
            headers: BTreeMap::new(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        })
    }

    fn presigns_ops(&self) -> bool {
        true
    }

    async fn presign_ops(
        &self,
        prefix: &str,
        object_key: &str,
        upload_id: Option<&str>,
        ops: &[StorageOp],
    ) -> Result<Vec<PresignedRequest>, AppError> {
        let id = upload_id.unwrap_or_default().to_string();
        Ok(ops
            .iter()
            .map(|op| {
                let (method, query, headers): (&str, Vec<(&str, String)>, Vec<(&str, String)>) =
                    match *op {
                        StorageOp::Put { len, sha256 } => (
                            "PUT",
                            vec![],
                            vec![
                                ("Content-Length", len.to_string()),
                                ("x-amz-checksum-sha256", checksum_b64(&sha256)),
                            ],
                        ),
                        StorageOp::Get => ("GET", vec![], vec![]),
                        StorageOp::Head => (
                            "HEAD",
                            vec![],
                            vec![("x-amz-checksum-mode", "ENABLED".into())],
                        ),
                        StorageOp::Delete => ("DELETE", vec![], vec![]),
                        StorageOp::CreateMultipart => (
                            "POST",
                            vec![("uploads", String::new())],
                            vec![("x-amz-checksum-algorithm", "SHA256".into())],
                        ),
                        StorageOp::UploadPart { part, len, sha256 } => (
                            "PUT",
                            vec![("partNumber", part.to_string()), ("uploadId", id.clone())],
                            vec![
                                ("Content-Length", len.to_string()),
                                ("x-amz-checksum-sha256", checksum_b64(&sha256)),
                            ],
                        ),
                        StorageOp::ListParts { marker } => {
                            let mut q =
                                vec![("uploadId", id.clone()), ("max-parts", "1000".into())];
                            if let Some(m) = marker {
                                q.push(("part-number-marker", m.to_string()));
                            }
                            ("GET", q, vec![])
                        }
                        StorageOp::CompleteMultipart { len } => (
                            "POST",
                            vec![("uploadId", id.clone())],
                            vec![("x-amz-mp-object-size", len.to_string())],
                        ),
                        StorageOp::AbortMultipart => {
                            ("DELETE", vec![("uploadId", id.clone())], vec![])
                        }
                    };
                PresignedRequest {
                    method: method.into(),
                    url: self.url(prefix, object_key, &query),
                    headers: headers
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v))
                        .collect(),
                    expires_at: Utc::now() + chrono::Duration::minutes(5),
                }
            })
            .collect())
    }
}
