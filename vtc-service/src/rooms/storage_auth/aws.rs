//! `s3` configs on `ambient` or `sealed` authentication: every object request is a
//! SigV4 presigned request made here with a credential scoped to one room's prefix
//! (`vtc/storage/configs/create/0.2`, "Room-scoped credentials", rules 3 and 5, and
//! the paragraph on `sealed`).
//!
//! - **`ambient`**: STS `AssumeRole` of the config's `roleArn` (else the host's
//!   `[rooms.files.auth] aws_role_arn`, else the ambient identity's own role) with an
//!   inline session policy, `DurationSeconds` 900, a `RoleSessionName` naming the
//!   community and the room prefix's hash.
//! - **`sealed` on AWS S3** (no `endpoint`): STS `GetFederationToken` with the same
//!   session policy, signed by the stored key.
//! - **`sealed` elsewhere** — an S3-compatible store with no STS (R2, B2, MinIO), or a
//!   temporary pair STS refuses to federate — the stored key only presigns requests
//!   for single objects under the room's prefix, expiring within 15 minutes, as the
//!   VTA's `s3-static-presign` does.
//!
//! Whichever it is, the store is [`PresignedBlobs`]: the same code that serves
//! `vta-account` configs, direct transfers included.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use aws_credential_types::Credentials;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;
use vti_common::blob_store::presigned::{
    PresignAction, PresignedBlobs, PresignedRequest, Presigner, checksum_b64,
};
use vti_common::blob_store::{BlobStore, StorageOp};
use vti_common::error::AppError;

use super::{Access, CredentialCache, Held, REQUESTED_LIFETIME_SECS, Scope, scrub_provider_error};

/// Whether `arn` is an IAM role ARN, as `AwsRoleArn` of
/// `vtc/_shared/0.2/room-storage` states it:
/// `^arn:aws(-[a-z]+)*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`.
pub fn is_role_arn(arn: &str) -> bool {
    if arn.len() < 20 || arn.len() > 2048 {
        return false;
    }
    let Some(rest) = arn.strip_prefix("arn:aws") else {
        return false;
    };
    let Some((partition_tail, rest)) = rest.split_once(":iam::") else {
        return false;
    };
    // `(-[a-z]+)*`
    if !partition_tail.is_empty() {
        let Some(t) = partition_tail.strip_prefix('-') else {
            return false;
        };
        if !t
            .split('-')
            .all(|seg| !seg.is_empty() && seg.chars().all(|c| c.is_ascii_lowercase()))
        {
            return false;
        }
    }
    let Some((account, name)) = rest.split_once(":role/") else {
        return false;
    };
    account.len() == 12
        && account.chars().all(|c| c.is_ascii_digit())
        && (1..=512).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+=,.@_/-".contains(c))
}

/// The partition a role ARN names (`aws`, `aws-cn`, `aws-us-gov`): where the session
/// policy's resources live.
pub fn partition_of(role_arn: &str) -> Option<&str> {
    role_arn
        .strip_prefix("arn:")
        .and_then(|r| r.split(':').next())
        .filter(|p| p.starts_with("aws"))
}

/// The partition of an AWS region, for a credential that names no role (federation).
pub fn partition_of_region(region: &str) -> &'static str {
    if region.starts_with("cn-") {
        "aws-cn"
    } else if region.starts_with("us-gov-") {
        "aws-us-gov"
    } else {
        "aws"
    }
}

/// The S3 actions of one [`Access`] — never more than rule 2 allows: create, read and
/// delete an object, and the two multipart actions an upload in parts needs.
pub fn actions(access: Access) -> &'static [&'static str] {
    match access {
        Access::Read => &["s3:GetObject"],
        Access::Write => &[
            "s3:PutObject",
            "s3:AbortMultipartUpload",
            "s3:ListMultipartUploadParts",
        ],
        Access::Delete => &["s3:DeleteObject"],
    }
}

/// The inline session policy for one scope and access (rules 2, 3 and 5): built by a
/// JSON encoder from validated values — the bucket and prefix the schema validates for
/// exactly this, the partition read off a validated ARN — never by interpolating into
/// a policy template.
pub fn session_policy(
    partition: &str,
    bucket: &str,
    object_prefix: &str,
    access: Access,
    source_ip: Option<&str>,
) -> String {
    let mut statement = json!({
        "Effect": "Allow",
        "Action": actions(access),
        "Resource": [format!("arn:{partition}:s3:::{bucket}/{object_prefix}*")],
    });
    if let Some(ip) = source_ip {
        statement["Condition"] = json!({ "IpAddress": { "aws:SourceIp": ip } });
    }
    serde_json::to_string(&json!({ "Version": "2012-10-17", "Statement": [statement] }))
        .expect("a JSON value serialises")
}

/// What an issuer is asked for: a policy and the session's name.
#[derive(Debug, Clone)]
pub struct SessionRequest {
    pub policy: String,
    pub session_name: String,
    /// The partition the policy's resources were written for.
    pub partition: String,
}

/// A scoped session credential and what the provider said of it.
pub struct Issued {
    pub credentials: Credentials,
    pub expiry: Option<DateTime<Utc>>,
    pub request_id: Option<String>,
}

/// Where scoped sessions come from: STS in a deployment, a stand-in in tests.
#[async_trait]
pub trait SessionIssuer: Send + Sync {
    /// The partition this issuer's sessions live in (from the role ARN, or the region).
    async fn partition(&self) -> Result<String, String>;
    async fn issue(&self, req: &SessionRequest) -> Result<Issued, String>;
}

fn smithy_time(t: &aws_smithy_types::DateTime) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(t.secs(), t.subsec_nanos())
}

fn sts_credentials(c: &aws_sdk_sts::types::Credentials) -> (Credentials, Option<DateTime<Utc>>) {
    let expiry = smithy_time(c.expiration());
    (
        Credentials::new(
            c.access_key_id(),
            c.secret_access_key(),
            Some(c.session_token().to_string()),
            expiry.map(SystemTime::from),
            "vtc-room-scoped",
        ),
        expiry,
    )
}

fn sts_error<E: std::fmt::Display>(e: E) -> String {
    scrub_provider_error(&format!("{e}"))
}

/// `ambient`: STS `AssumeRole`, with the machine's own identity (rule 3).
pub struct AssumeRoleIssuer {
    region: String,
    /// The config's `roleArn`, else the host's.
    role_arn: Option<String>,
    sts: OnceCell<aws_sdk_sts::Client>,
    resolved: OnceCell<String>,
}

impl AssumeRoleIssuer {
    pub fn new(region: &str, role_arn: Option<String>) -> Self {
        Self {
            region: region.to_string(),
            role_arn,
            sts: OnceCell::new(),
            resolved: OnceCell::new(),
        }
    }

    async fn client(&self) -> &aws_sdk_sts::Client {
        self.sts
            .get_or_init(|| async {
                let conf = aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(aws_config::Region::new(self.region.clone()))
                    .load()
                    .await;
                aws_sdk_sts::Client::new(&conf)
            })
            .await
    }

    /// The role to assume: the one named, else the ambient identity's own — read off
    /// `GetCallerIdentity`'s assumed-role ARN. A role with a path cannot be recovered
    /// that way, and must be named.
    async fn role(&self) -> Result<&str, String> {
        self.resolved
            .get_or_try_init(|| async {
                if let Some(r) = &self.role_arn {
                    return Ok(r.clone());
                }
                let me = self
                    .client()
                    .await
                    .get_caller_identity()
                    .send()
                    .await
                    .map_err(sts_error)?;
                let arn = me.arn().unwrap_or_default();
                own_role(arn).ok_or_else(|| {
                    "the ambient identity is not an assumed role; name the role to assume in \
                     the config's `roleArn` or the host's `[rooms.files.auth] aws_role_arn`"
                        .to_string()
                })
            })
            .await
            .map(String::as_str)
    }
}

/// `arn:<p>:sts::<acct>:assumed-role/<name>/<session>` → `arn:<p>:iam::<acct>:role/<name>`.
fn own_role(assumed: &str) -> Option<String> {
    let mut parts = assumed.splitn(6, ':');
    let (_, partition, service, _, account, resource) = (
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
    );
    if service != "sts" {
        return None;
    }
    let name = resource.strip_prefix("assumed-role/")?.split('/').next()?;
    let arn = format!("arn:{partition}:iam::{account}:role/{name}");
    is_role_arn(&arn).then_some(arn)
}

#[async_trait]
impl SessionIssuer for AssumeRoleIssuer {
    async fn partition(&self) -> Result<String, String> {
        let role = self.role().await?;
        partition_of(role)
            .map(str::to_string)
            .ok_or_else(|| "the role ARN names no partition".into())
    }

    async fn issue(&self, req: &SessionRequest) -> Result<Issued, String> {
        let role = self.role().await?.to_string();
        let out = self
            .client()
            .await
            .assume_role()
            .role_arn(role)
            .role_session_name(&req.session_name)
            .policy(&req.policy)
            .duration_seconds(REQUESTED_LIFETIME_SECS)
            .send()
            .await
            .map_err(sts_error)?;
        let c = out
            .credentials()
            .ok_or("STS answered AssumeRole with no credentials")?;
        let (credentials, expiry) = sts_credentials(c);
        Ok(Issued {
            credentials,
            expiry,
            request_id: aws_types_request_id(&out),
        })
    }
}

fn aws_types_request_id<T: aws_sdk_sts::operation::RequestId>(out: &T) -> Option<String> {
    out.request_id().map(str::to_string)
}

/// `sealed` on AWS S3: STS `GetFederationToken`, signed by the stored key.
pub struct FederationIssuer {
    region: String,
    sts: aws_sdk_sts::Client,
}

impl FederationIssuer {
    pub fn new(region: &str, key: Credentials) -> Self {
        let conf = aws_sdk_sts::Config::builder()
            .behavior_version(aws_sdk_sts::config::BehaviorVersion::latest())
            .region(aws_sdk_sts::config::Region::new(region.to_string()))
            .credentials_provider(key)
            .build();
        Self {
            region: region.to_string(),
            sts: aws_sdk_sts::Client::from_conf(conf),
        }
    }
}

#[async_trait]
impl SessionIssuer for FederationIssuer {
    async fn partition(&self) -> Result<String, String> {
        Ok(partition_of_region(&self.region).to_string())
    }

    async fn issue(&self, req: &SessionRequest) -> Result<Issued, String> {
        let out = self
            .sts
            .get_federation_token()
            .name(&req.session_name)
            .policy(&req.policy)
            .duration_seconds(REQUESTED_LIFETIME_SECS)
            .send()
            .await
            .map_err(sts_error)?;
        let c = out
            .credentials()
            .ok_or("STS answered GetFederationToken with no credentials")?;
        let (credentials, expiry) = sts_credentials(c);
        Ok(Issued {
            credentials,
            expiry,
            request_id: aws_types_request_id(&out),
        })
    }
}

/// Where a config's objects are addressed.
#[derive(Debug, Clone)]
pub struct S3Target {
    pub config_id: String,
    pub bucket: String,
    pub region: String,
    /// The store's origin (`https://host[:port]`), for one other than AWS.
    pub endpoint: Option<url::Url>,
    pub path_style: bool,
    /// The config's own prefix, `""` or ending `/`.
    pub prefix: String,
}

impl S3Target {
    /// The target `settings` describe (`S3Settings`, already validated).
    pub fn from_settings(config_id: &str, settings: &Value) -> Result<Self, String> {
        let bucket = settings["bucket"].as_str().ok_or("no bucket")?.to_string();
        let region = settings["region"].as_str().ok_or("no region")?.to_string();
        let endpoint = match settings["endpoint"].as_str() {
            Some(e) => Some(url::Url::parse(e).map_err(|e| format!("endpoint: {e}"))?),
            None => None,
        };
        Ok(Self {
            config_id: config_id.to_string(),
            bucket,
            region,
            endpoint,
            path_style: settings["pathStyle"].as_bool().unwrap_or(false),
            prefix: settings["prefix"].as_str().unwrap_or_default().to_string(),
        })
    }

    /// `(origin, path prefix)` objects are addressed under: virtual-hosted unless the
    /// config asks for path style.
    fn base(&self) -> (String, String) {
        let (scheme, host, port) = match &self.endpoint {
            Some(u) => (
                u.scheme().to_string(),
                u.host_str().unwrap_or_default().to_string(),
                u.port(),
            ),
            None => {
                let domain = if self.region.starts_with("cn-") {
                    "amazonaws.com.cn"
                } else {
                    "amazonaws.com"
                };
                (
                    "https".to_string(),
                    format!("s3.{}.{domain}", self.region),
                    None,
                )
            }
        };
        let host = if self.path_style {
            host
        } else {
            format!("{}.{host}", self.bucket)
        };
        let origin = match port {
            Some(p) => format!("{scheme}://{host}:{p}"),
            None => format!("{scheme}://{host}"),
        };
        let path = if self.path_style {
            format!("/{}/", self.bucket)
        } else {
            "/".to_string()
        };
        (origin, path)
    }
}

/// How an `s3` config on `ambient` or `sealed` obtains what it signs with.
pub enum S3Authority {
    /// A credential scoped per (scope, access) by STS.
    Scoped(Arc<dyn SessionIssuer>),
    /// A key that cannot be downscoped here: it only presigns single objects under the
    /// scope's prefix, for at most 15 minutes.
    PresignOnly(Credentials),
}

/// One `s3` config's backend: its target, how it is authorized, the room-scoped
/// credentials it holds now and a store per scope.
pub struct S3Backend {
    target: S3Target,
    authority: S3Authority,
    /// `aws:SourceIp`, when the host has a stable egress.
    source_ip: Option<String>,
    /// A short tag naming this community in session names.
    community_tag: String,
    cache: CredentialCache<Credentials>,
    stores: Mutex<HashMap<Scope, Arc<dyn BlobStore>>>,
    #[cfg(feature = "test-support")]
    plain_http: bool,
}

/// At most this many per-scope stores are kept; more, and the lot are dropped.
const MAX_STORES: usize = 4096;

impl S3Backend {
    pub fn new(
        target: S3Target,
        authority: S3Authority,
        source_ip: Option<String>,
        community_did: &str,
    ) -> Self {
        let digest = Sha256::digest(community_did.as_bytes());
        let community_tag: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
        Self {
            target,
            authority,
            source_ip,
            community_tag,
            cache: CredentialCache::default(),
            stores: Mutex::new(HashMap::new()),
            #[cfg(feature = "test-support")]
            plain_http: false,
        }
    }

    /// Accept a loopback store answering plain `http`, for tests.
    #[cfg(feature = "test-support")]
    pub fn with_plain_http(mut self) -> Self {
        self.plain_http = true;
        self
    }

    /// How many rooms hold a live credential now.
    pub fn rooms_holding(&self) -> usize {
        self.cache.rooms_holding(Utc::now())
    }

    /// The store for `scope`: every request it makes is presigned for that scope
    /// alone.
    pub fn store(self: &Arc<Self>, scope: Scope) -> Result<Arc<dyn BlobStore>, AppError> {
        let mut stores = self.stores.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(s) = stores.get(&scope) {
            return Ok(s.clone());
        }
        let presigner = Arc::new(ScopedPresigner {
            backend: self.clone(),
            scope: scope.clone(),
        });
        let prefix = (!self.target.prefix.is_empty()).then_some(self.target.prefix.as_str());
        #[allow(unused_mut)]
        let mut store = PresignedBlobs::new("s3", presigner, prefix)?;
        #[cfg(feature = "test-support")]
        if self.plain_http {
            store = store.with_plain_http();
        }
        let store: Arc<dyn BlobStore> = Arc::new(store);
        if stores.len() >= MAX_STORES {
            stores.clear();
        }
        stores.insert(scope, store.clone());
        Ok(store)
    }

    /// The session name for `scope` and `access`: the community and the room prefix's
    /// hash, so the provider's audit trail joins the community's (rule 3). At most 32
    /// characters, which both `RoleSessionName` and federation's `Name` accept.
    fn session_name(&self, scope: &Scope, access: Access) -> String {
        let tag: String = scope.tag().chars().take(16).collect();
        format!("vtc{}-{tag}-{}", self.community_tag, access.letter())
    }

    /// A credential for `(scope, access)`, minted when none is held (rules 1, 3, 6).
    /// Never the unscoped authority in its place (rule 8).
    async fn credential(
        &self,
        scope: &Scope,
        access: Access,
    ) -> Result<Held<Credentials>, AppError> {
        let issuer = match &self.authority {
            S3Authority::PresignOnly(key) => {
                return Ok(Held {
                    credential: key.clone(),
                    stop_at: Utc::now()
                        + chrono::Duration::from_std(super::MAX_LIFETIME).expect("fits"),
                });
            }
            S3Authority::Scoped(issuer) => issuer,
        };
        let now = Utc::now();
        if let Some(held) = self.cache.get(scope, access, now) {
            return Ok(held);
        }
        let unavailable = |why: String| AppError::ServiceError {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            message: format!(
                "storage config `{}` could not obtain a room-scoped credential: {why}",
                self.target.config_id
            ),
        };
        let partition = issuer.partition().await.map_err(unavailable)?;
        let object_prefix = scope.object_prefix(&self.target.prefix);
        let req = SessionRequest {
            policy: session_policy(
                &partition,
                &self.target.bucket,
                &object_prefix,
                access,
                self.source_ip.as_deref(),
            ),
            session_name: self.session_name(scope, access),
            partition,
        };
        let issued = issuer.issue(&req).await.map_err(unavailable)?;
        let held = Held {
            credential: issued.credentials,
            stop_at: super::stop_at(now, issued.expiry),
        };
        // What the provider's trail can be joined on — never the credential.
        tracing::info!(
            config = %self.target.config_id,
            scope = scope.tag(),
            access = ?access,
            expires = %held.stop_at,
            request_id = issued.request_id.as_deref().unwrap_or("-"),
            "room-scoped storage credential issued"
        );
        self.cache.put(scope.clone(), access, held.clone());
        Ok(held)
    }

    /// Presign `method` on `full_key` (bucket-relative) with `query` and `headers`
    /// signed, with `cred`, until no later than its stop time and 15 minutes.
    fn presign_with(
        &self,
        cred: &Held<Credentials>,
        method: &str,
        full_key: &str,
        query: &[(&str, String)],
        headers: &[(&str, String)],
    ) -> Result<PresignedRequest, AppError> {
        use aws_sigv4::http_request::{
            PercentEncodingMode, SignableBody, SignableRequest, SignatureLocation, SigningSettings,
            UriPathNormalizationMode, sign,
        };
        let now = Utc::now();
        let lifetime = (cred.stop_at - now)
            .to_std()
            .unwrap_or_default()
            .min(super::MAX_LIFETIME);
        if lifetime < Duration::from_secs(1) {
            return Err(AppError::Internal(
                "the room-scoped credential stopped before it could sign".into(),
            ));
        }
        let (origin, base_path) = self.target.base();
        let mut url = url::Url::parse(&format!("{origin}{base_path}{full_key}"))
            .map_err(|e| AppError::Internal(format!("storage URL: {e}")))?;
        for (k, v) in query {
            url.query_pairs_mut().append_pair(k, v);
        }
        if url.query() == Some("") {
            url.set_query(None);
        }

        let mut settings = SigningSettings::default();
        settings.signature_location = SignatureLocation::QueryParams;
        settings.expires_in = Some(lifetime);
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        let identity = cred.credential.clone().into();
        let params = aws_sigv4::sign::v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.target.region)
            .name("s3")
            .time(SystemTime::from(now))
            .settings(settings)
            .build()
            .map_err(|e| AppError::Internal(format!("signing parameters: {e}")))?
            .into();
        let signable = SignableRequest::new(
            method,
            url.as_str(),
            headers.iter().map(|(k, v)| (*k, v.as_str())),
            SignableBody::UnsignedPayload,
        )
        .map_err(|e| AppError::Internal(format!("signable request: {e}")))?;
        let (instructions, _signature) = sign(signable, &params)
            .map_err(|e| AppError::Internal(format!("signing: {e}")))?
            .into_parts();
        {
            let mut pairs = url.query_pairs_mut();
            for (k, v) in instructions.params() {
                pairs.append_pair(k, v);
            }
        }
        Ok(PresignedRequest {
            method: method.to_string(),
            url: url.into(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
            expires_at: now + chrono::Duration::from_std(lifetime).expect("fits"),
        })
    }
}

/// The access an operation needs (rule 2).
fn op_access(op: &StorageOp) -> Access {
    match op {
        StorageOp::Get | StorageOp::Head => Access::Read,
        StorageOp::Delete => Access::Delete,
        StorageOp::Put { .. }
        | StorageOp::CreateMultipart
        | StorageOp::UploadPart { .. }
        | StorageOp::ListParts { .. }
        | StorageOp::CompleteMultipart { .. }
        | StorageOp::AbortMultipart => Access::Write,
    }
}

type Signed = Vec<(&'static str, String)>;

/// Method, signed query and signed headers of one operation — the table of
/// `external/credentials/issue/0.2` item 10, which [`PresignedBlobs`] sends.
fn op_parts(op: &StorageOp, upload_id: Option<&str>) -> (&'static str, Signed, Signed) {
    let id = || upload_id.unwrap_or_default().to_string();
    match *op {
        StorageOp::Put { len, sha256 } => (
            "PUT",
            vec![],
            vec![
                ("content-length", len.to_string()),
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
            vec![("partNumber", part.to_string()), ("uploadId", id())],
            vec![
                ("content-length", len.to_string()),
                ("x-amz-checksum-sha256", checksum_b64(&sha256)),
            ],
        ),
        StorageOp::ListParts { marker } => {
            let mut q = vec![("uploadId", id()), ("max-parts", "1000".into())];
            if let Some(m) = marker {
                q.push(("part-number-marker", m.to_string()));
            }
            ("GET", q, vec![])
        }
        StorageOp::CompleteMultipart { len } => (
            "POST",
            vec![("uploadId", id())],
            vec![("x-amz-mp-object-size", len.to_string())],
        ),
        StorageOp::AbortMultipart => ("DELETE", vec![("uploadId", id())], vec![]),
    }
}

/// The presigner of one scope: refuses any object outside it (rule 1), and signs each
/// request with the credential for its access.
struct ScopedPresigner {
    backend: Arc<S3Backend>,
    scope: Scope,
}

impl ScopedPresigner {
    /// `prefix + object_key`, once it is known to lie inside this scope.
    fn object(&self, prefix: &str, object_key: &str) -> Result<String, AppError> {
        let allowed = self.scope.object_prefix(&self.backend.target.prefix);
        if !prefix.starts_with(&allowed) || object_key.contains('/') || object_key.is_empty() {
            return Err(AppError::Internal(format!(
                "a request for `{prefix}{object_key}` lies outside the credential's scope"
            )));
        }
        Ok(format!("{prefix}{object_key}"))
    }
}

#[async_trait]
impl Presigner for ScopedPresigner {
    async fn presign(
        &self,
        action: PresignAction,
        prefix: &str,
        object_key: &str,
    ) -> Result<PresignedRequest, AppError> {
        let full = self.object(prefix, object_key)?;
        let (method, access) = match action {
            PresignAction::Put => ("PUT", Access::Write),
            PresignAction::Get => ("GET", Access::Read),
            PresignAction::Delete => ("DELETE", Access::Delete),
        };
        let cred = self.backend.credential(&self.scope, access).await?;
        self.backend.presign_with(&cred, method, &full, &[], &[])
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
        let full = self.object(prefix, object_key)?;
        let mut out = Vec::with_capacity(ops.len());
        for op in ops {
            let (method, query, headers) = op_parts(op, upload_id);
            let cred = self.backend.credential(&self.scope, op_access(op)).await?;
            out.push(
                self.backend
                    .presign_with(&cred, method, &full, &query, &headers)?,
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn a_role_arn_is_checked_as_the_schema_states_it() {
        for ok in [
            "arn:aws:iam::123456789012:role/northwind-rooms-writer",
            "arn:aws-cn:iam::123456789012:role/a",
            "arn:aws-us-gov:iam::123456789012:role/path/to/r",
        ] {
            assert!(is_role_arn(ok), "{ok}");
        }
        for bad in [
            "arn:aws:iam::12345678901:role/x",
            "arn:aws:iam::123456789012:user/x",
            "arn:aws:s3:::bucket",
            "arn:aws-:iam::123456789012:role/x",
            "arn:aws:iam::123456789012:role/x\"}],\"Effect\"",
            "arn:aws:iam::123456789012:role/",
        ] {
            assert!(!is_role_arn(bad), "{bad}");
        }
        assert_eq!(
            partition_of("arn:aws-cn:iam::123456789012:role/a"),
            Some("aws-cn")
        );
        assert_eq!(
            own_role("arn:aws:sts::123456789012:assumed-role/vtc-host/i-0abc").as_deref(),
            Some("arn:aws:iam::123456789012:role/vtc-host")
        );
        assert_eq!(own_role("arn:aws:iam::123456789012:user/bob"), None);
    }

    /// The session policy is a JSON document an encoder wrote: one statement, the
    /// actions of one access and nothing else, one resource under the room's prefix.
    #[test]
    fn the_session_policy_names_one_prefix_and_only_object_actions() {
        let p = session_policy(
            "aws",
            "northwind-rooms-eu",
            "tenant-a/rooms/0123456789abcdef0123456789abcdef/",
            Access::Write,
            Some("203.0.113.7/32"),
        );
        let v: Value = serde_json::from_str(&p).unwrap();
        let st = &v["Statement"];
        assert_eq!(st.as_array().unwrap().len(), 1);
        assert_eq!(
            st[0]["Resource"],
            json!([
                "arn:aws:s3:::northwind-rooms-eu/tenant-a/rooms/0123456789abcdef0123456789abcdef/*"
            ])
        );
        assert_eq!(
            st[0]["Action"],
            json!([
                "s3:PutObject",
                "s3:AbortMultipartUpload",
                "s3:ListMultipartUploadParts"
            ])
        );
        assert_eq!(
            st[0]["Condition"]["IpAddress"]["aws:SourceIp"],
            "203.0.113.7/32"
        );
        for access in [Access::Read, Access::Write, Access::Delete] {
            for a in actions(access) {
                assert!(a.starts_with("s3:") && !a.contains('*'), "{a}");
                assert!(!a.contains("List") || *a == "s3:ListMultipartUploadParts");
                assert!(!a.contains("Bucket") && !a.contains("Acl") && !a.contains("Policy"));
            }
        }
    }

    /// A stand-in for STS: records what it was asked, issues a distinct key each time.
    #[derive(Default)]
    struct Recording {
        asked: Mutex<Vec<SessionRequest>>,
        issued: AtomicUsize,
        refuse: bool,
    }

    #[async_trait]
    impl SessionIssuer for Recording {
        async fn partition(&self) -> Result<String, String> {
            Ok("aws".into())
        }
        async fn issue(&self, req: &SessionRequest) -> Result<Issued, String> {
            if self.refuse {
                return Err("AccessDenied".into());
            }
            self.asked.lock().unwrap().push(req.clone());
            let n = self.issued.fetch_add(1, Ordering::SeqCst);
            Ok(Issued {
                credentials: Credentials::new(
                    format!("ASIA{n}"),
                    "secret",
                    Some("token".into()),
                    None,
                    "test",
                ),
                expiry: Some(Utc::now() + chrono::Duration::hours(1)),
                request_id: Some("req-1".into()),
            })
        }
    }

    fn target() -> S3Target {
        S3Target::from_settings(
            "eu",
            &json!({"kind": "s3", "region": "eu-west-1", "bucket": "northwind-rooms-eu", "prefix": "tenant-a/"}),
        )
        .unwrap()
    }

    fn backend(issuer: Arc<Recording>) -> Arc<S3Backend> {
        Arc::new(S3Backend::new(
            target(),
            S3Authority::Scoped(issuer),
            None,
            "did:web:community.example",
        ))
    }

    /// One credential per (room, access): reused within a room, never across rooms;
    /// a request for another room's object is refused before anything is signed.
    #[tokio::test]
    async fn each_room_gets_its_own_credential_and_never_anothers() {
        let issuer = Arc::new(Recording::default());
        let b = backend(issuer.clone());
        let room_a = Scope::room("did:key:zRoomA");
        let room_b = Scope::room("did:key:zRoomB");
        let pa = ScopedPresigner {
            backend: b.clone(),
            scope: room_a.clone(),
        };
        let prefix_a = room_a.object_prefix("tenant-a/");
        let prefix_b = room_b.object_prefix("tenant-a/");

        let r1 = pa
            .presign(PresignAction::Get, &prefix_a, "zObj1")
            .await
            .unwrap();
        let r2 = pa
            .presign(PresignAction::Get, &prefix_a, "zObj2")
            .await
            .unwrap();
        assert_eq!(
            issuer.issued.load(Ordering::SeqCst),
            1,
            "reused for the room"
        );
        assert!(r1.url.contains("X-Amz-Credential=ASIA0"), "{}", r1.url);
        assert!(r2.url.contains("X-Amz-Security-Token=token"));
        assert!(
            r1.url.starts_with(
                "https://northwind-rooms-eu.s3.eu-west-1.amazonaws.com/tenant-a/rooms/"
            )
        );
        // At most 15 minutes, whatever STS granted.
        assert!(r1.expires_at <= Utc::now() + chrono::Duration::minutes(15));
        let expires: i64 = url::Url::parse(&r1.url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "X-Amz-Expires")
            .unwrap()
            .1
            .parse()
            .unwrap();
        assert!(expires <= 900, "{expires}");

        // A write is another credential, whose policy names only write actions.
        pa.presign(PresignAction::Put, &prefix_a, "zObj1")
            .await
            .unwrap();
        assert_eq!(issuer.issued.load(Ordering::SeqCst), 2);

        assert!(
            pa.presign(PresignAction::Get, &prefix_b, "zObj1")
                .await
                .is_err(),
            "another room's object"
        );
        assert!(
            pa.presign(PresignAction::Get, "tenant-a/", "zObj1")
                .await
                .is_err(),
            "the bucket as a whole"
        );
        let asked = issuer.asked.lock().unwrap();
        assert_eq!(asked.len(), 2);
        for req in asked.iter() {
            let v: Value = serde_json::from_str(&req.policy).unwrap();
            let resource = v["Statement"][0]["Resource"][0].as_str().unwrap();
            assert_eq!(
                resource,
                format!("arn:aws:s3:::northwind-rooms-eu/{prefix_a}*")
            );
            assert!(req.session_name.len() <= 32, "{}", req.session_name);
            assert!(req.session_name.contains(&room_a.tag()[..16]));
        }
        assert_eq!(b.rooms_holding(), 1);
    }

    /// No room-scoped credential, no operation: never the unscoped authority (rule 8).
    #[tokio::test]
    async fn without_a_scoped_credential_the_operation_fails() {
        let issuer = Arc::new(Recording {
            refuse: true,
            ..Default::default()
        });
        let b = backend(issuer);
        let scope = Scope::room("did:key:zRoomA");
        let p = ScopedPresigner {
            backend: b,
            scope: scope.clone(),
        };
        let err = p
            .presign(
                PresignAction::Get,
                &scope.object_prefix("tenant-a/"),
                "zObj",
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("room-scoped credential"), "{err}");
    }

    /// Writes are signed with their length and checksum, so storage refuses other bytes.
    #[tokio::test]
    async fn a_write_is_bound_to_its_length_and_checksum() {
        let b = backend(Arc::new(Recording::default()));
        let scope = Scope::room("did:key:zRoomA");
        let p = ScopedPresigner {
            backend: b,
            scope: scope.clone(),
        };
        let reqs = p
            .presign_ops(
                &scope.object_prefix("tenant-a/"),
                "zObj",
                None,
                &[StorageOp::Put {
                    len: 5,
                    sha256: [1; 32],
                }],
            )
            .await
            .unwrap();
        let signed = url::Url::parse(&reqs[0].url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "X-Amz-SignedHeaders")
            .unwrap()
            .1
            .into_owned();
        assert!(signed.contains("content-length"), "{signed}");
        assert!(signed.contains("x-amz-checksum-sha256"), "{signed}");
        assert_eq!(reqs[0].headers["content-length"], "5");
    }

    /// End to end against an S3-shaped store: a room's blob is written, read in a range
    /// and deleted through requests this backend presigned for that room alone.
    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn a_room_store_round_trips_a_blob_through_its_own_presigned_requests() {
        let bucket = vti_common::blob_store::mock_s3::MockS3::start(true).await;
        let origin = bucket
            .base
            .trim_end_matches("/bucket/")
            .replacen("http://", "https://", 1);
        let target = S3Target {
            config_id: "eu".into(),
            bucket: "bucket".into(),
            region: "eu-west-1".into(),
            endpoint: Some(url::Url::parse(&origin).unwrap()),
            path_style: true,
            prefix: "tenant-a/".into(),
        };
        let issuer = Arc::new(Recording::default());
        let b = Arc::new(
            S3Backend::new(
                target,
                S3Authority::Scoped(issuer.clone()),
                None,
                "did:web:community.example",
            )
            .with_plain_http(),
        );
        let store = b.store(Scope::room("did:key:zRoomA")).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("blob");
        std::fs::write(&staged, b"ciphertext").unwrap();
        let blob = vti_common::blob_store::sha256_digest_multibase(&[5; 32]);
        let key = vti_common::blob_store::BlobKey::for_room("did:key:zRoomA", &blob).unwrap();
        let at = store.put(&key, &staged, 10).await.unwrap();
        assert_eq!(store.get_range(&at, 0, 6).await.unwrap(), b"cipher");
        assert!(
            bucket
                .objects()
                .iter()
                .all(|o| o.starts_with("tenant-a/rooms/")),
            "{:?}",
            bucket.objects()
        );
        store.delete(&at).await.unwrap();
        assert!(bucket.objects().is_empty());
        // Another room's key never goes through this room's store.
        let theirs = vti_common::blob_store::BlobKey::for_room("did:key:zRoomB", &blob).unwrap();
        assert!(store.put(&theirs, &staged, 10).await.is_err());
        // Read, write and delete: one credential each, all for this room.
        assert!(issuer.issued.load(Ordering::SeqCst) <= 3);
        for req in issuer.asked.lock().unwrap().iter() {
            assert!(
                req.policy
                    .contains(&Scope::room("did:key:zRoomA").object_prefix("tenant-a/"))
            );
        }
    }

    /// A key that cannot be downscoped presigns only within the scope, and for at most
    /// 15 minutes.
    #[tokio::test]
    async fn a_presign_only_key_is_still_held_to_the_rooms_prefix() {
        let mut t = target();
        t.endpoint = Some(url::Url::parse("https://account.r2.example").unwrap());
        t.path_style = true;
        let b = Arc::new(S3Backend::new(
            t,
            S3Authority::PresignOnly(Credentials::new("AKID", "secret", None, None, "test")),
            None,
            "did:web:community.example",
        ));
        let scope = Scope::room("did:key:zRoomA");
        let p = ScopedPresigner {
            backend: b,
            scope: scope.clone(),
        };
        let r = p
            .presign(
                PresignAction::Get,
                &scope.object_prefix("tenant-a/"),
                "zObj",
            )
            .await
            .unwrap();
        assert!(
            r.url
                .starts_with("https://account.r2.example/northwind-rooms-eu/tenant-a/rooms/"),
            "{}",
            r.url
        );
        assert!(!r.url.contains("secret"));
        assert!(
            p.presign(
                PresignAction::Get,
                &Scope::room("did:key:zRoomB").object_prefix("tenant-a/"),
                "zObj"
            )
            .await
            .is_err()
        );
    }
}
