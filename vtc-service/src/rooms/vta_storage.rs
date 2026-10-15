//! Storage through the community's VTA: a config with `auth: vta-account`
//! (`data-rooms-files.md` §7.4).
//!
//! The community holds no storage credential. For each object operation it asks
//! its VTA, over the messaging channel it already keeps, for one presigned
//! request (`external/credentials/issue/0.1` against an `s3-static-presign`
//! account): one method on one object, for minutes, every issuance checked
//! against the community's binding and audited at the VTA. A direct upload's
//! requests come in batches (`issue/0.3`, 0.2 from a VTA that does not serve
//! it), each write bound to its length and checksum; a batch whose sealed answer
//! would not fit is refused `responseTooLarge` and asked for again in parts. The VTA seals the
//! request to this community's key-agreement key, inside a `#response` whose
//! proof the inbound demux has verified as the VTA's before it reaches here.
//!
//! The scope asked for is always one room's prefix and one object, built from
//! the blob key, so what the VTA signs reaches one blob of one room.
//!
//! # What the community needs at its VTA
//!
//! An entry for this community's DID holding `external-auth-use` in the account's
//! context, and a binding on the account naming this DID, with a ceiling covering
//! `<prefix>rooms/` and `<prefix>probe/` for the actions `put`, `get` and
//! `delete`, and a `maxTtlSeconds` of at least [`TTL_SECONDS`]. A config names the
//! account by its context and identifier, as the VTA names it.

use std::sync::Arc;
use std::time::Duration;

use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use async_trait::async_trait;
use axum::http::StatusCode;
use serde_json::{Value, json};
use trust_tasks_rs::specs::external::credentials::issue::v0_1 as issue;
use trust_tasks_rs::specs::external::credentials::issue::v0_2 as issue_v2;
use trust_tasks_rs::specs::external::credentials::issue::v0_3 as issue_v3;
use vta_sdk::sealed_transfer::ExternalCredentialPayload;
use vti_common::blob_store::StorageOp;
use vti_common::blob_store::presigned::{PresignAction, PresignedRequest, Presigner, checksum_b64};
use vti_common::error::AppError;
use zeroize::Zeroizing;

pub use crate::outbound::PeerError;
use crate::vta_link::VtaLink;

/// How long a presigned request is asked to live. A write or delete uses it at
/// once; a read is reused across a download's ranges until shortly before it
/// expires.
pub const TTL_SECONDS: i64 = 300;

/// How long to wait for the VTA's answer before an operation fails.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

const ISSUE: &str = <issue::Payload as trust_tasks_rs::Payload>::TYPE_URI;
const ISSUE_V2: &str = <issue_v2::Payload as trust_tasks_rs::Payload>::TYPE_URI;
const ISSUE_V3: &str = <issue_v3::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The VTA's refusal of an issuance: its code, message and `details`.
struct Refusal {
    code: String,
    message: String,
    details: Option<Value>,
}

/// How a Trust Task reaches the VTA and its signed reply comes back: the
/// community's [`VtaLink`] in a running community, a stand-in in tests.
#[async_trait]
pub trait VtaChannel: Send + Sync {
    async fn exchange(
        &self,
        type_uri: &str,
        payload: &Value,
        timeout: Duration,
    ) -> Result<trust_tasks_rs::TrustTask<Value>, PeerError>;
}

#[async_trait]
impl VtaChannel for VtaLink {
    async fn exchange(
        &self,
        type_uri: &str,
        payload: &Value,
        timeout: Duration,
    ) -> Result<trust_tasks_rs::TrustTask<Value>, PeerError> {
        VtaLink::exchange(self, type_uri, payload, timeout).await
    }
}

/// Storage credentials from this community's VTA, over its link to it.
pub struct VtaStorage {
    vta: Arc<dyn VtaChannel>,
    community_did: String,
    secrets: Arc<ThreadedSecretsResolver>,
}

impl VtaStorage {
    pub fn new(
        vta: Arc<dyn VtaChannel>,
        community_did: String,
        secrets: Arc<ThreadedSecretsResolver>,
    ) -> Self {
        Self {
            vta,
            community_did,
            secrets,
        }
    }

    /// A presigner for objects of `account` in `context`, whose requests must
    /// address the config's `bucket` (at `endpoint`, when the config names one).
    pub fn presigner(
        self: &Arc<Self>,
        context: &str,
        account: &str,
        bucket: &str,
        endpoint: Option<&str>,
    ) -> Arc<dyn Presigner> {
        Arc::new(AccountPresigner {
            link: self.clone(),
            context: context.to_string(),
            account: account.to_string(),
            bucket: bucket.to_string(),
            endpoint_host: endpoint
                .and_then(|e| reqwest::Url::parse(e).ok())
                .and_then(|u| u.host_str().map(str::to_ascii_lowercase)),
        })
    }

    /// Ask for one presigned request; the VTA's refusal as `Ok(Err((code, message)))`.
    async fn issue(&self, asked: &Value) -> Result<Result<String, (String, String)>, AppError> {
        Ok(self
            .issue_at(ISSUE, asked)
            .await?
            .map_err(|r| (r.code, r.message)))
    }

    /// Ask at `type_uri` (`issue/0.1`, `0.2` or `0.3`); the sealed answer, or the
    /// VTA's refusal.
    async fn issue_at(
        &self,
        type_uri: &str,
        asked: &Value,
    ) -> Result<Result<String, Refusal>, AppError> {
        let reply = self
            .vta
            .exchange(type_uri, asked, REPLY_TIMEOUT)
            .await
            .map_err(|e| match e {
                PeerError::Transient(m) => {
                    unavailable(format!("the community's VTA could not be reached: {m}"))
                }
                PeerError::NoMatchingProtocol(m) => unavailable(format!(
                    "the community's VTA shares no transport with this community: {m}"
                )),
            })?;
        if reply.type_uri.slug() == "trust-task-error" {
            return Ok(Err(Refusal {
                code: reply.payload["code"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
                message: reply.payload["message"].as_str().unwrap_or("").to_string(),
                details: reply.payload.get("details").cloned(),
            }));
        }
        if type_uri == ISSUE {
            read_answer(&reply, asked).map(Ok)
        } else {
            read_batch_answer(type_uri, &reply, asked).map(Ok)
        }
    }

    /// What the VTA says of `account` in `context` for objects under `prefix`
    /// (`vtc/storage/configs/create` item 5): asked as one read of a canary under
    /// `<prefix>probe/`, which is issued only to a bound consumer and touches
    /// nothing.
    pub async fn check_account(&self, context: &str, account: &str, prefix: &str) -> AccountCheck {
        let mut nonce = [0u8; 16];
        rand::fill(&mut nonce);
        let object: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let probe = format!("{prefix}{}", vti_common::blob_store::PROBE_PREFIX);
        let asked = request(account, context, PresignAction::Get, &probe, &object);
        match self.issue(&asked).await {
            Ok(Ok(_)) => AccountCheck::Usable,
            Ok(Err((code, message))) => AccountCheck::from_refusal(&code, message),
            Err(e) => AccountCheck::Unconfirmed(e.to_string()),
        }
    }

    /// This community's X25519 key-agreement secret: what the VTA sealed to.
    async fn key_agreement_secret(&self) -> Result<Zeroizing<[u8; 32]>, AppError> {
        let id = format!("{}#key-1", self.community_did);
        let secret = self.secrets.get_secret(&id).await.ok_or_else(|| {
            AppError::Internal("this community has no key-agreement secret loaded".into())
        })?;
        let bytes: [u8; 32] = secret.get_private_bytes().try_into().map_err(|_| {
            AppError::Internal("this community's key-agreement secret is not 32 bytes".into())
        })?;
        Ok(Zeroizing::new(bytes))
    }
}

struct AccountPresigner {
    link: Arc<VtaStorage>,
    context: String,
    account: String,
    bucket: String,
    endpoint_host: Option<String>,
}

impl AccountPresigner {
    /// Open one sealed `PresignedRequestSet` answering `count` operations, every
    /// request in order and addressing this config's bucket.
    async fn open_set(
        &self,
        armored: &str,
        count: usize,
    ) -> Result<Vec<PresignedRequest>, AppError> {
        let secret = self.link.key_agreement_secret().await?;
        let credential = vta_sdk::client::open_external_credential(armored, &secret)
            .map_err(|e| unavailable(format!("the storage requests did not open: {e}")))?;
        let ExternalCredentialPayload::PresignedRequests { requests, .. } = &credential else {
            return Err(unavailable(format!(
                "external account `{}` answered a presign batch with something else",
                self.account
            )));
        };
        if requests.len() != count {
            return Err(unavailable(format!(
                "the VTA presigned {} requests for {count} operations",
                requests.len()
            )));
        }
        let mut out = Vec::with_capacity(requests.len());
        for (i, r) in requests.iter().enumerate() {
            if r.index as usize != i {
                return Err(unavailable(
                    "the VTA's presigned requests are out of order".into(),
                ));
            }
            if !self.addresses(&r.url) {
                return Err(unavailable(format!(
                    "external account `{}` presigns for a different bucket or endpoint than this \
                     config's `{}`",
                    self.account, self.bucket
                )));
            }
            let expires_at = chrono::DateTime::parse_from_rfc3339(&r.expires_at)
                .map(|t| t.with_timezone(&chrono::Utc))
                .map_err(|_| unavailable("a presigned request has no readable expiry".into()))?;
            out.push(PresignedRequest {
                method: r.method.clone(),
                url: r.url.clone(),
                headers: r.headers.clone(),
                expires_at,
            });
        }
        Ok(out)
    }

    /// Whether `url` addresses this config's bucket — virtual-hosted or in the
    /// path — at its endpoint. An account at the VTA set up for another bucket
    /// then fails loudly, rather than this config's rooms being written there.
    fn addresses(&self, url: &str) -> bool {
        let Ok(url) = reqwest::Url::parse(url) else {
            return false;
        };
        let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
            return false;
        };
        let virtual_hosted = host.strip_prefix(&format!("{}.", self.bucket));
        let path_style = url.path().starts_with(&format!("/{}/", self.bucket));
        match &self.endpoint_host {
            Some(endpoint) => {
                virtual_hosted == Some(endpoint.as_str()) || (path_style && host == *endpoint)
            }
            None => virtual_hosted.is_some() || path_style,
        }
    }
}

/// What the VTA said of an account, when a config naming it was proposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountCheck {
    /// It issued: the account exists and this community may use it here.
    Usable,
    /// It exists and this community is bound, but it cannot issue now (not
    /// active, setup incomplete, rate, provider): the config may still be made,
    /// and its probe says when it works.
    NotReady(String),
    /// No such account for this community: unknown, unbound, or no
    /// `external-auth-use` — `unknownAccount`.
    Unknown(String),
    /// Bound, but for something the config cannot do — `invalidSettings` naming
    /// the member.
    Unfit {
        member: &'static str,
        problem: String,
    },
    /// The VTA did not answer; nothing was learned.
    Unconfirmed(String),
}

impl AccountCheck {
    fn from_refusal(code: &str, message: String) -> Self {
        let name = code.rsplit(':').next().unwrap_or(code);
        match name {
            "notFound" | "notBound" | "permissionDenied" => Self::Unknown(message),
            "scopeOutsideCeiling" => Self::Unfit {
                member: "settings.prefix",
                problem: format!(
                    "the community's binding at its VTA does not cover this config's prefix: \
                     {message}"
                ),
            },
            "ttlTooLong" => Self::Unfit {
                member: "auth.account",
                problem: format!(
                    "the community's binding allows credentials shorter than the {TTL_SECONDS}s \
                     this community asks for: {message}"
                ),
            },
            "notBrokered" => Self::Unfit {
                member: "auth.account",
                problem: "the account does not issue credentials (it is not an \
                          `s3-static-presign` account)"
                    .into(),
            },
            _ => Self::NotReady(format!("{code}: {message}")),
        }
    }
}

fn unavailable(message: String) -> AppError {
    AppError::ServiceError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        message,
    }
}

/// The issue request for one object operation.
fn request(
    account: &str,
    context: &str,
    action: PresignAction,
    prefix: &str,
    object: &str,
) -> Value {
    json!({
        "account": account,
        "context": context,
        "scope": { "prefix": prefix, "actions": [action.as_str()], "objectKey": object },
        "ttlSeconds": TTL_SECONDS,
    })
}

/// The `issue/0.2`/`0.3` request (one payload shape) presigning `ops` on one object of one room.
fn batch_request(
    account: &str,
    context: &str,
    prefix: &str,
    object: &str,
    upload_id: Option<&str>,
    ops: &[StorageOp],
) -> Value {
    let requests: Vec<Value> = ops
        .iter()
        .map(|op| match *op {
            StorageOp::Put { len, sha256 } => json!({
                "operation": "put", "contentLength": len, "checksumSha256": checksum_b64(&sha256),
            }),
            StorageOp::Get => json!({ "operation": "get" }),
            StorageOp::Head => json!({ "operation": "head" }),
            StorageOp::Delete => json!({ "operation": "delete" }),
            StorageOp::CreateMultipart => json!({ "operation": "create-multipart" }),
            StorageOp::UploadPart { part, len, sha256 } => json!({
                "operation": "upload-part", "partNumber": part, "contentLength": len,
                "checksumSha256": checksum_b64(&sha256),
            }),
            StorageOp::ListParts { marker: Some(m) } => {
                json!({ "operation": "list-parts", "partNumberMarker": m })
            }
            StorageOp::ListParts { marker: None } => json!({ "operation": "list-parts" }),
            StorageOp::CompleteMultipart { len } => {
                json!({ "operation": "complete-multipart", "contentLength": len })
            }
            StorageOp::AbortMultipart => json!({ "operation": "abort-multipart" }),
        })
        .collect();
    let mut presign = json!({ "prefix": prefix, "objectKey": object, "requests": requests });
    if let Some(id) = upload_id {
        presign["uploadId"] = json!(id);
    }
    json!({ "account": account, "context": context, "presign": presign, "ttlSeconds": TTL_SECONDS })
}

/// Read an `issue/0.2` or `0.3` answer (`type_uri` is the version asked) as the
/// sealed set, after checking it is that task's answer, for exactly the batch
/// asked.
fn read_batch_answer(
    type_uri: &str,
    reply: &trust_tasks_rs::TrustTask<Value>,
    asked: &Value,
) -> Result<String, AppError> {
    if reply.type_uri.to_string() != format!("{type_uri}#response") {
        return Err(unavailable(
            "the community's VTA answered a storage request with something else".into(),
        ));
    }
    let malformed = |e: serde_json::Error| {
        unavailable(format!(
            "the community's VTA answered with a malformed credential: {e}"
        ))
    };
    let presigned = if type_uri == ISSUE_V3 {
        match serde_json::from_value(reply.payload.clone()).map_err(malformed)? {
            issue_v3::Response::Variant1 {
                presign,
                sealed_credential,
                ..
            } => Some((
                serde_json::to_value(&presign).unwrap_or(Value::Null),
                sealed_credential.to_string(),
            )),
            _ => None,
        }
    } else {
        match serde_json::from_value(reply.payload.clone()).map_err(malformed)? {
            issue_v2::Response::Variant1 {
                presign,
                sealed_credential,
                ..
            } => Some((
                serde_json::to_value(&presign).unwrap_or(Value::Null),
                sealed_credential.to_string(),
            )),
            _ => None,
        }
    };
    let Some((presign, sealed)) = presigned else {
        return Err(unavailable(
            "the community's VTA answered a presign batch with a scope".into(),
        ));
    };
    if presign != asked["presign"] {
        return Err(unavailable(
            "the community's VTA presigned a different batch than asked".into(),
        ));
    }
    Ok(sealed)
}

/// Read the VTA's answer as the sealed credential, after checking it is the
/// issue task's answer, for exactly the scope asked.
fn read_answer(
    reply: &trust_tasks_rs::TrustTask<Value>,
    asked: &Value,
) -> Result<String, AppError> {
    if reply.type_uri.to_string() != format!("{ISSUE}#response") {
        return Err(unavailable(
            "the community's VTA answered a storage credential request with something else".into(),
        ));
    }
    let answer: issue::Response = serde_json::from_value(reply.payload.clone()).map_err(|e| {
        unavailable(format!(
            "the community's VTA answered with a malformed credential: {e}"
        ))
    })?;
    let echoed = serde_json::to_value(&answer.scope).unwrap_or(Value::Null);
    if echoed != asked["scope"] {
        return Err(unavailable(
            "the community's VTA issued a credential for a different scope than asked".into(),
        ));
    }
    Ok(answer.sealed_credential.to_string())
}

#[async_trait]
impl Presigner for AccountPresigner {
    fn presigns_ops(&self) -> bool {
        true
    }

    /// The requests for one object, in order, each write bound to its length and
    /// checksum: one `external/credentials/issue/0.3` batch, one issuance against
    /// the binding's rate whatever its size.
    ///
    /// A batch whose sealed answer would not fit is refused `responseTooLarge`,
    /// which spends none of the rate, and asked for again in parts (`issue/0.3`
    /// consumer item 5): the first `details.maxOperations` operations when the
    /// VTA names it, else the first half, then the rest. Each part is a new,
    /// smaller request, so this is a split, not a retry; it ends when every
    /// operation is answered or one alone does not fit. A VTA that does not
    /// serve 0.3 (`unsupportedType` / `unsupportedVersion`, as the SDK and the
    /// git bridge read it) is asked at 0.2, which takes the same batch.
    async fn presign_ops(
        &self,
        prefix: &str,
        object_key: &str,
        upload_id: Option<&str>,
        ops: &[StorageOp],
    ) -> Result<Vec<PresignedRequest>, AppError> {
        let too_large = issue_v3::error_codes::RESPONSE_TOO_LARGE.code;
        let mut out = Vec::with_capacity(ops.len());
        let mut rest = ops;
        let mut take = rest.len();
        let mut type_uri = ISSUE_V3;
        while !rest.is_empty() {
            let n = take.min(rest.len());
            let part = &rest[..n];
            let asked = batch_request(
                &self.account,
                &self.context,
                prefix,
                object_key,
                upload_id,
                part,
            );
            match self.link.issue_at(type_uri, &asked).await? {
                Ok(armored) => {
                    out.extend(self.open_set(&armored, part.len()).await?);
                    rest = &rest[n..];
                    take = n;
                }
                Err(r)
                    if type_uri == ISSUE_V3
                        && matches!(r.code.as_str(), "unsupportedType" | "unsupportedVersion") =>
                {
                    type_uri = ISSUE_V2;
                }
                Err(r) if r.code == too_large => {
                    match vta_sdk::client::presign_split_at(n, r.details.as_ref()) {
                        Some(k) => take = k,
                        None => {
                            return Err(unavailable(format!(
                                "the community's VTA cannot seal even one storage request for \
                                 this object ({}): {}",
                                r.code, r.message
                            )));
                        }
                    }
                }
                Err(r) => {
                    return Err(unavailable(format!(
                        "the community's VTA refused a storage request ({}): {}",
                        r.code, r.message
                    )));
                }
            }
        }
        Ok(out)
    }

    async fn presign(
        &self,
        action: PresignAction,
        prefix: &str,
        object_key: &str,
    ) -> Result<PresignedRequest, AppError> {
        let link = &self.link;
        let asked = request(&self.account, &self.context, action, prefix, object_key);
        let armored = link.issue(&asked).await?.map_err(|(code, message)| {
            unavailable(format!(
                "the community's VTA refused a storage credential ({code}): {message}"
            ))
        })?;
        let secret = link.key_agreement_secret().await?;
        let credential = vta_sdk::client::open_external_credential(&armored, &secret)
            .map_err(|e| unavailable(format!("the storage credential did not open: {e}")))?;
        let ExternalCredentialPayload::PresignedRequest {
            method,
            url,
            headers,
            expires_at,
            ..
        } = &credential
        else {
            return Err(unavailable(format!(
                "external account `{}` does not issue presigned requests (this community uses \
                 `s3-static-presign` accounts)",
                self.account
            )));
        };
        if !self.addresses(url) {
            return Err(unavailable(format!(
                "external account `{}` presigns for a different bucket or endpoint than this \
                 config's `{}`",
                self.account, self.bucket
            )));
        }
        let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at)
            .map(|t| t.with_timezone(&chrono::Utc))
            .map_err(|_| unavailable("the storage credential has no readable expiry".into()))?;
        Ok(PresignedRequest {
            method: method.clone(),
            url: url.clone(),
            headers: headers.clone(),
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::TrustTask;

    fn doc(type_uri: &str, payload: Value) -> TrustTask<Value> {
        TrustTask::new("urn:uuid:r", type_uri.parse().unwrap(), payload)
    }

    fn asked() -> Value {
        request(
            "eu-r2",
            "community",
            PresignAction::Get,
            "rooms/0123456789abcdef0123456789abcdef/",
            "zObject",
        )
    }

    #[test]
    fn refusals_say_what_the_config_should_be_told() {
        for code in ["external:notFound", "external:notBound", "permissionDenied"] {
            assert!(matches!(
                AccountCheck::from_refusal(code, String::new()),
                AccountCheck::Unknown(_)
            ));
        }
        assert!(matches!(
            AccountCheck::from_refusal(
                "external/credentials/issue:scopeOutsideCeiling",
                String::new()
            ),
            AccountCheck::Unfit {
                member: "settings.prefix",
                ..
            }
        ));
        assert!(matches!(
            AccountCheck::from_refusal("external:providerSetupRequired", String::new()),
            AccountCheck::NotReady(_)
        ));
    }

    /// A VTA never reached: these tests look only at the request's address.
    struct NoVta;

    #[async_trait]
    impl VtaChannel for NoVta {
        async fn exchange(
            &self,
            _: &str,
            _: &Value,
            _: Duration,
        ) -> Result<trust_tasks_rs::TrustTask<Value>, PeerError> {
            Err(PeerError::Transient("no VTA in this test".into()))
        }
    }

    async fn presigner(bucket: &str, endpoint: Option<&str>) -> AccountPresigner {
        let (resolver, _h) = ThreadedSecretsResolver::new(None).await;
        AccountPresigner {
            link: Arc::new(VtaStorage::new(
                Arc::new(NoVta),
                "did:key:zVtc".into(),
                Arc::new(resolver),
            )),
            context: "community".into(),
            account: "a".into(),
            bucket: bucket.into(),
            endpoint_host: endpoint
                .and_then(|e| reqwest::Url::parse(e).ok())
                .and_then(|u| u.host_str().map(str::to_string)),
        }
    }

    #[tokio::test]
    async fn a_request_must_address_the_configs_bucket() {
        let aws = presigner("rooms-eu", None).await;
        assert!(aws.addresses("https://rooms-eu.s3.eu-west-1.amazonaws.com/rooms/x/z"));
        assert!(aws.addresses("https://s3.eu-west-1.amazonaws.com/rooms-eu/rooms/x/z"));
        assert!(!aws.addresses("https://other.s3.eu-west-1.amazonaws.com/rooms/x/z"));
        assert!(!aws.addresses("https://s3.eu-west-1.amazonaws.com/other/rooms-eu/z"));

        let minio = presigner("rooms", Some("https://minio.example.com")).await;
        assert!(minio.addresses("https://minio.example.com/rooms/rooms/x/z"));
        assert!(minio.addresses("https://rooms.minio.example.com/rooms/x/z"));
        assert!(!minio.addresses("https://minio.elsewhere.com/rooms/rooms/x/z"));
    }

    #[test]
    fn an_answer_for_another_scope_is_refused() {
        let mut scope = asked()["scope"].clone();
        scope["objectKey"] = json!("zOther");
        let reply = doc(
            &format!("{ISSUE}#response"),
            json!({
                "sealedCredential": format!(
                    "-----BEGIN VTA SEALED BUNDLE-----\n{}\n-----END VTA SEALED BUNDLE-----\n",
                    "x".repeat(64)
                ),
                "expiresAt": "2030-01-01T00:00:00Z",
                "scope": scope,
            }),
        );
        let err = read_answer(&reply, &asked()).unwrap_err().to_string();
        assert!(err.contains("different scope"), "{err}");
    }

    #[test]
    fn another_task_is_not_an_answer() {
        let reply = doc(
            "https://trusttasks.org/spec/external/accounts/get/0.1#response",
            json!({}),
        );
        assert!(read_answer(&reply, &asked()).is_err());
    }

    /// A direct upload's batch is the specification's payload, each write carrying
    /// its length and checksum; an answer presigning another batch is refused.
    #[test]
    fn a_batch_request_conforms_and_its_answer_must_echo_it() {
        let ops = [
            StorageOp::UploadPart {
                part: 2,
                len: 5_242_880,
                sha256: [9; 32],
            },
            StorageOp::ListParts { marker: None },
            StorageOp::CompleteMultipart { len: 10_485_760 },
        ];
        let v = batch_request(
            "eu-r2",
            "community",
            "rooms/0123/",
            "zBlob-u1",
            Some("UP"),
            &ops,
        );
        assert_eq!(
            v["presign"]["requests"][0]["checksumSha256"],
            checksum_b64(&[9; 32])
        );
        assert_eq!(v["ttlSeconds"], TTL_SECONDS);
        serde_json::from_value::<issue_v2::Payload>(v.clone()).expect("conforms to issue 0.2");
        serde_json::from_value::<issue_v3::Payload>(v.clone()).expect("conforms to issue 0.3");

        let mut other = v["presign"].clone();
        other["objectKey"] = json!("zOther");
        let reply = doc(
            &format!("{ISSUE_V2}#response"),
            json!({
                "sealedCredential": format!(
                    "-----BEGIN VTA SEALED BUNDLE-----\n{}\n-----END VTA SEALED BUNDLE-----\n",
                    "x".repeat(64)
                ),
                "expiresAt": "2030-01-01T00:00:00Z",
                "presign": other,
            }),
        );
        let err = read_batch_answer(ISSUE_V2, &reply, &v)
            .unwrap_err()
            .to_string();
        assert!(err.contains("different batch"), "{err}");
    }

    /// A stand-in VTA answering presign batches. At 0.3 it refuses a batch of
    /// more than `fits` operations `responseTooLarge` (naming `fits` when
    /// `names_max`), or every 0.3 request `unsupportedType` when `serves_0_3` is
    /// off. It records each request's version and size.
    struct BatchVta {
        community_x25519: [u8; 32],
        fits: usize,
        names_max: bool,
        serves_0_3: bool,
        asked: std::sync::Mutex<Vec<(String, usize)>>,
    }

    #[async_trait]
    impl VtaChannel for BatchVta {
        async fn exchange(
            &self,
            type_uri: &str,
            payload: &Value,
            _: Duration,
        ) -> Result<trust_tasks_rs::TrustTask<Value>, PeerError> {
            use vta_sdk::sealed_transfer::{
                AssertionProof, InMemoryNonceStore, PresignedEntry, ProducerAssertion,
                SealedPayloadV1, armor, seal_payload,
            };
            let ops = payload["presign"]["requests"].as_array().unwrap().clone();
            self.asked
                .lock()
                .unwrap()
                .push((type_uri.to_string(), ops.len()));
            let error = |code: &str, details: Value| {
                Ok(doc(
                    "https://trusttasks.org/spec/trust-task-error/0.5",
                    json!({ "code": code, "message": "no", "retryable": false, "details": details }),
                ))
            };
            if type_uri == ISSUE_V3 && !self.serves_0_3 {
                return error("unsupportedType", json!({}));
            }
            if type_uri == ISSUE_V3 && ops.len() > self.fits {
                let details = if self.names_max {
                    json!({ "maxOperations": self.fits })
                } else {
                    json!({})
                };
                return error("external/credentials/issue:responseTooLarge", details);
            }
            let expires = "2030-01-01T00:00:00Z".to_string();
            let requests = ops
                .iter()
                .enumerate()
                .map(|(i, op)| PresignedEntry {
                    index: i as u32,
                    operation: op["operation"].as_str().unwrap().into(),
                    method: "PUT".into(),
                    url: format!(
                        "https://rooms.invalid/rooms/o?partNumber={}",
                        op["partNumber"]
                    ),
                    headers: Default::default(),
                    expires_at: expires.clone(),
                })
                .collect();
            let set = SealedPayloadV1::ExternalCredential(Box::new(
                ExternalCredentialPayload::PresignedRequests {
                    requests,
                    expires_at: expires.clone(),
                },
            ));
            let mut id = [0u8; 16];
            rand::fill(&mut id);
            let bundle = seal_payload(
                &self.community_x25519,
                id,
                ProducerAssertion {
                    producer_did: "did:key:zVta".into(),
                    proof: AssertionProof::PinnedOnly,
                },
                &set,
                &InMemoryNonceStore::new(),
            )
            .await
            .unwrap();
            Ok(doc(
                &format!("{type_uri}#response"),
                json!({
                    "sealedCredential": armor::encode(&bundle),
                    "expiresAt": expires,
                    "presign": payload["presign"],
                }),
            ))
        }
    }

    async fn batch_presigner(vta: Arc<BatchVta>, secret_bytes: [u8; 32]) -> AccountPresigner {
        use affinidi_secrets_resolver::secrets::Secret;
        let mut secret = Secret::generate_x25519(None, Some(&secret_bytes)).unwrap();
        secret.id = "did:key:zVtc#key-1".into();
        let (resolver, _h) = ThreadedSecretsResolver::new(None).await;
        resolver.insert(secret).await;
        AccountPresigner {
            link: Arc::new(VtaStorage::new(
                vta,
                "did:key:zVtc".into(),
                Arc::new(resolver),
            )),
            context: "community".into(),
            account: "a".into(),
            bucket: "rooms".into(),
            endpoint_host: Some("rooms.invalid".into()),
        }
    }

    fn parts(n: u32) -> Vec<StorageOp> {
        (1..=n)
            .map(|part| StorageOp::UploadPart {
                part,
                len: 5_242_880,
                sha256: [1; 32],
            })
            .collect()
    }

    /// `issue/0.3` consumer item 5: a batch refused `responseTooLarge` is asked
    /// for again in parts — of `maxOperations` when given, else halves — and
    /// every operation is answered, in order. A VTA serving only 0.2 is asked at
    /// 0.2.
    #[tokio::test]
    async fn a_batch_too_large_to_seal_is_split_and_an_old_vta_is_asked_at_0_2() {
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        let public = {
            use affinidi_secrets_resolver::secrets::Secret;
            let s = Secret::generate_x25519(None, Some(&bytes)).unwrap();
            let p: [u8; 32] = s.get_public_bytes().try_into().unwrap();
            p
        };
        let vta = |fits, names_max, serves_0_3| {
            Arc::new(BatchVta {
                community_x25519: public,
                fits,
                names_max,
                serves_0_3,
                asked: Default::default(),
            })
        };
        let urls = |reqs: &[PresignedRequest]| -> Vec<String> {
            reqs.iter().map(|r| r.url.clone()).collect()
        };
        let expected: Vec<String> = (1..=64)
            .map(|p| format!("https://rooms.invalid/rooms/o?partNumber={p}"))
            .collect();

        // Named: 64 → 10, 10, …, 4 after one refusal.
        let named = vta(10, true, true);
        let p = batch_presigner(named.clone(), bytes).await;
        let out = p
            .presign_ops("rooms/", "o", Some("U"), &parts(64))
            .await
            .unwrap();
        assert_eq!(urls(&out), expected);
        let asked = named.asked.lock().unwrap().clone();
        assert!(asked.iter().all(|(uri, _)| uri == ISSUE_V3));
        let sizes: Vec<usize> = asked.iter().map(|(_, n)| *n).collect();
        assert_eq!(sizes, [64, 10, 10, 10, 10, 10, 10, 4]);

        // Unnamed: halves — 64, 32, 16, then 16-wide parts.
        let halves = vta(20, false, true);
        let p = batch_presigner(halves.clone(), bytes).await;
        let out = p
            .presign_ops("rooms/", "o", Some("U"), &parts(64))
            .await
            .unwrap();
        assert_eq!(urls(&out), expected);
        let sizes: Vec<usize> = halves
            .asked
            .lock()
            .unwrap()
            .iter()
            .map(|(_, n)| *n)
            .collect();
        assert_eq!(sizes, [64, 32, 16, 16, 16, 16]);

        // One operation alone that does not fit is an error, not a loop.
        let none = vta(0, false, true);
        let p = batch_presigner(none.clone(), bytes).await;
        assert!(
            p.presign_ops("rooms/", "o", Some("U"), &parts(4))
                .await
                .is_err()
        );
        assert_eq!(none.asked.lock().unwrap().len(), 3, "4, 2, 1");

        // A VTA that does not serve 0.3 is asked the same batch at 0.2.
        let old = vta(64, true, false);
        let p = batch_presigner(old.clone(), bytes).await;
        let out = p
            .presign_ops("rooms/", "o", Some("U"), &parts(64))
            .await
            .unwrap();
        assert_eq!(urls(&out), expected);
        let asked = old.asked.lock().unwrap().clone();
        assert_eq!(
            asked,
            [(ISSUE_V3.to_string(), 64), (ISSUE_V2.to_string(), 64)]
        );
    }

    #[test]
    fn the_request_is_one_room_one_object_one_action() {
        let v = asked();
        assert_eq!(v["scope"]["actions"], json!(["get"]));
        assert_eq!(v["ttlSeconds"], TTL_SECONDS);
        serde_json::from_value::<issue::Payload>(v).expect("conforms to the issue payload");
    }
}
