//! Storage through the community's VTA: a config with `auth: vta-account`
//! (`data-rooms-files.md` §7.4).
//!
//! The community holds no storage credential. For each object operation it asks
//! its VTA, over the messaging channel it already keeps, for one presigned
//! request (`external/credentials/issue/0.1` against an `s3-static-presign`
//! account): one method on one object, for minutes, every issuance checked
//! against the community's binding and audited at the VTA. The VTA seals the
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
use vta_sdk::sealed_transfer::ExternalCredentialPayload;
use vti_common::blob_store::presigned::{PresignAction, PresignedRequest, Presigner};
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
        let reply = self
            .vta
            .exchange(ISSUE, asked, REPLY_TIMEOUT)
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
            return Ok(Err((
                reply.payload["code"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
                reply.payload["message"].as_str().unwrap_or("").to_string(),
            )));
        }
        read_answer(&reply, asked).map(Ok)
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

    #[test]
    fn the_request_is_one_room_one_object_one_action() {
        let v = asked();
        assert_eq!(v["scope"]["actions"], json!(["get"]));
        assert_eq!(v["ttlSeconds"], TTL_SECONDS);
        serde_json::from_value::<issue::Payload>(v).expect("conforms to the issue payload");
    }
}
