//! The community's link to its VTA at runtime: Trust Tasks this VTC sends the
//! VTA as an integration holding an ACL entry there, and the replies it awaits.
//!
//! Two uses share it:
//!
//! - an OpenID4VP verifier identity whose key the VTA keeps signs each request
//!   object through `keys/sign-jws/0.1` (#1988, custody B), so the VTC never
//!   holds the key. The VTC's DID needs an entry at the VTA in the key's
//!   context carrying `sign-jws`;
//! - room files in a `vta-account` storage config are read and written with
//!   presigned requests the VTA issues one object at a time
//!   (`external/credentials/issue/0.1`, [`crate::rooms::vta_storage`]).
//!
//! In both the VTA decides, as for any other caller.
//!
//! # Transport
//!
//! [`PeerTasks`]: TSP > DIDComm, by the service types the VTA's DID document
//! advertises, on the VTC's existing mediator socket — the mediator permits one
//! per DID, and a TSP send is an HTTP post on the same profile. There is no
//! REST arm: the VTA answers HTTPS Trust Tasks only to a session, and a link
//! that fell back to one would need a credential this VTC does not keep. Nor
//! does the VTA need an address of its own that this VTC could reach. A VTA
//! that advertises neither is refused by name, never downgraded past.
//!
//! Each document is signed with the VTC's operational key, and a reply is
//! accepted only when its own proof verifies as the VTA ([`PendingReplies`]).
//! One request, one attempt: the caller owns the retry, so a lost reply is an
//! error, not a resend.

use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde_json::{Map, Value, json};
use tokio::sync::OnceCell;
use trust_tasks_rs::TrustTask;
use vti_common::error::AppError;

use crate::credentials::LocalSigner;
use crate::hooks::PendingReplies;
use crate::messaging::VtcMessaging;
use crate::outbound::{PeerError, PeerTasks};

/// How long a VTA has to answer one `keys/sign-jws`. A wallet is waiting on it.
const REPLY_TIMEOUT: Duration = Duration::from_secs(20);

/// A Trust-Task link from this VTC to its VTA.
pub struct VtaLink {
    vta_did: String,
    peers: PeerTasks,
    reply_timeout: Duration,
}

impl VtaLink {
    pub fn new(
        vta_did: String,
        messaging: Arc<OnceCell<Arc<VtcMessaging>>>,
        signer: Arc<LocalSigner>,
        replies: PendingReplies,
        resolver: DIDCacheClient,
    ) -> Self {
        Self {
            vta_did,
            peers: PeerTasks {
                didcomm: messaging,
                signer: Some(signer),
                replies,
                resolver: Some(resolver),
            },
            reply_timeout: REPLY_TIMEOUT,
        }
    }

    /// The VTA this link reaches.
    pub fn vta_did(&self) -> &str {
        &self.vta_did
    }

    /// Sign one document of `type_uri` to the VTA, send it over the best
    /// transport both sides advertise, and await the VTA's signed reply for up
    /// to `timeout`.
    pub async fn exchange(
        &self,
        type_uri: &str,
        payload: &Value,
        timeout: Duration,
    ) -> Result<TrustTask<Value>, PeerError> {
        self.peers
            .exchange(&self.vta_did, type_uri, payload, timeout)
            .await
    }

    /// [`Self::exchange`] for a caller that reports in [`AppError`].
    async fn round_trip(
        &self,
        type_uri: &str,
        payload: Value,
    ) -> Result<TrustTask<Value>, AppError> {
        self.exchange(type_uri, &payload, self.reply_timeout)
            .await
            .map_err(|e| match e {
                PeerError::Transient(m) => AppError::Internal(format!("the VTA link: {m}")),
                PeerError::NoMatchingProtocol(m) => AppError::Internal(format!(
                    "no transport to the VTA: {m} (this VTC speaks TSP or DIDComm once its \
                     messaging is up)"
                )),
            })
    }
}

/// The JWS out of a `keys/sign-jws` reply, or the VTA's refusal named.
fn sign_jws_answer(reply: &TrustTask<Value>, key_id: &str) -> Result<String, AppError> {
    if reply.type_uri.slug() == "trust-task-error" {
        let code = reply
            .payload
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let message = reply
            .payload
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("");
        let hint = if code == "permissionDenied" {
            " — grant this VTC's DID `sign-jws` in the key's context at the VTA"
        } else {
            ""
        };
        return Err(AppError::Internal(format!(
            "the VTA refused keys/sign-jws for key {key_id}: {code} {message}{hint}"
        )));
    }
    if !reply.type_uri.is_response() || reply.type_uri.slug() != "keys/sign-jws" {
        return Err(AppError::Internal(format!(
            "expected a keys/sign-jws response from the VTA, got `{}`",
            reply.type_uri
        )));
    }
    reply
        .payload
        .get("jws")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| AppError::Internal("the VTA's keys/sign-jws response has no jws".into()))
}

#[async_trait::async_trait]
impl crate::oid4vp::VtaJwsSigner for VtaLink {
    async fn sign_jws(
        &self,
        key_id: &str,
        header: Map<String, Value>,
        claims: Map<String, Value>,
    ) -> Result<String, AppError> {
        let mut payload = json!({ "keyId": key_id, "payload": claims });
        if !header.is_empty() {
            payload["header"] = Value::Object(header);
        }
        let reply = self
            .round_trip(vta_sdk::trust_tasks::TASK_KEYS_SIGN_JWS_0_1, payload)
            .await?;
        sign_jws_answer(&reply, key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(type_uri: &str, payload: Value) -> TrustTask<Value> {
        serde_json::from_value(json!({
            "id": "urn:uuid:7f0e1a52-3c4b-4d5e-8f60-718293a4b5c6",
            "type": type_uri,
            "threadId": "urn:uuid:00000000-0000-4000-8000-000000000001",
            "issuer": "did:example:vta",
            "recipient": "did:example:vtc",
            "issuedAt": "2026-10-13T09:00:00Z",
            "payload": payload,
        }))
        .unwrap()
    }

    /// The JWS comes out of a `keys/sign-jws` response; a refusal is named,
    /// with the grant that fixes a `permissionDenied`; anything else is not a
    /// JWS.
    #[test]
    fn the_answer_is_the_jws_or_the_refusal_named() {
        let ok = reply(
            "https://trusttasks.org/spec/keys/sign-jws/0.1#response",
            json!({ "keyId": "k", "alg": "ES256", "jws": "a.b.c" }),
        );
        assert_eq!(sign_jws_answer(&ok, "k").unwrap(), "a.b.c");

        let denied = reply(
            "https://trusttasks.org/spec/trust-task-error/0.5",
            json!({ "code": "permissionDenied", "message": "no sign-jws" }),
        );
        let err = sign_jws_answer(&denied, "k").unwrap_err().to_string();
        assert!(
            err.contains("permissionDenied") && err.contains("grant this VTC"),
            "{err}"
        );

        let other = reply(
            "https://trusttasks.org/spec/keys/sign/0.1#response",
            json!({ "keyId": "k", "signature": "x" }),
        );
        assert!(sign_jws_answer(&other, "k").is_err());
    }
}
