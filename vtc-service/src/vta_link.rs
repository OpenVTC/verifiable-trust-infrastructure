//! The community's link to its VTA at runtime: Trust Tasks this VTC sends the
//! VTA as an integration holding an ACL entry there, and the replies it awaits.
//!
//! First use: an OpenID4VP verifier identity whose key the VTA keeps signs each
//! request object through `keys/sign-jws/0.1` (#1988, custody B), so the VTC
//! never holds the key. The VTC's DID needs an entry at the VTA in the key's
//! context carrying `sign-jws`; the VTA decides, as for any other caller.
//!
//! # Transport
//!
//! TSP > DIDComm, by the service types the VTA's DID document advertises, on
//! the VTC's existing mediator socket — the mediator permits one per DID, and
//! a TSP send is an HTTP post on the same profile. There is no REST arm: the
//! VTA answers HTTPS Trust Tasks only to a session, and a link that fell back
//! to one would need a credential this VTC does not keep. A VTA that
//! advertises neither is refused by name, never downgraded past.
//!
//! Each document is signed with the VTC's operational key, and a reply is
//! accepted only when its own proof verifies as the VTA ([`PendingReplies`]).
//! One request, one attempt: the caller (a wallet session start) owns the
//! retry, so a lost reply is an error, not a resend.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde_json::{Map, Value, json};
use tokio::sync::OnceCell;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocol::matching::{Protocol, ServiceCapabilities, select_protocol};
use vti_common::capability_client::build_document;
use vti_common::error::AppError;

use crate::credentials::LocalSigner;
use crate::hooks::PendingReplies;
use crate::messaging::VtcMessaging;

/// How long a VTA has to answer one task. A wallet is waiting on it.
const REPLY_TIMEOUT: Duration = Duration::from_secs(20);

/// A Trust-Task link from this VTC to its VTA.
pub struct VtaLink {
    vta_did: String,
    vtc_did: String,
    messaging: Arc<OnceCell<Arc<VtcMessaging>>>,
    signer: Arc<LocalSigner>,
    replies: PendingReplies,
    resolver: DIDCacheClient,
    reply_timeout: Duration,
    /// The VTA's TSP mediator, from the last selection: a send routes through
    /// it when it is not ours (`vti_common::tsp_route`). No await is held
    /// across the lock (R1.3).
    tsp_mediator: RwLock<Option<String>>,
}

impl VtaLink {
    pub fn new(
        vta_did: String,
        vtc_did: String,
        messaging: Arc<OnceCell<Arc<VtcMessaging>>>,
        signer: Arc<LocalSigner>,
        replies: PendingReplies,
        resolver: DIDCacheClient,
    ) -> Self {
        Self {
            vta_did,
            vtc_did,
            messaging,
            signer,
            replies,
            resolver,
            reply_timeout: REPLY_TIMEOUT,
            tsp_mediator: RwLock::new(None),
        }
    }

    /// The transport to the VTA this call: the best both sides advertise.
    async fn select(&self) -> Result<Protocol, AppError> {
        let resolved = self.resolver.resolve(&self.vta_did).await.map_err(|e| {
            AppError::Internal(format!(
                "could not resolve the VTA's DID {}: {e}",
                self.vta_did
            ))
        })?;
        let doc = serde_json::to_value(&resolved.doc)
            .map_err(|e| AppError::Internal(format!("the VTA's DID document: {e}")))?;
        let theirs = ServiceCapabilities::from_did_document(&doc);
        if let Ok(mut slot) = self.tsp_mediator.write() {
            slot.clone_from(&theirs.tsp);
        }
        let messaging_up = self.messaging.get().is_some();
        let ours = ServiceCapabilities {
            tsp: (messaging_up && cfg!(feature = "tsp")).then(|| self.vta_did.clone()),
            didcomm: messaging_up.then(|| self.vta_did.clone()),
            rest: None,
        };
        let matched = select_protocol(&ours, &theirs, &self.vta_did).map_err(|e| {
            AppError::Internal(format!(
                "no transport to the VTA: {e} (the VTA advertises {:?}; this VTC speaks TSP or \
                 DIDComm once its messaging is up)",
                theirs.advertised()
            ))
        })?;
        Ok(matched.protocol)
    }

    /// Build, sign, send one task to the VTA, and await its signed reply.
    async fn round_trip(
        &self,
        type_uri: &str,
        payload: Value,
    ) -> Result<TrustTask<Value>, AppError> {
        let protocol = self.select().await?;
        let messaging = self
            .messaging
            .get()
            .ok_or_else(|| AppError::Internal("VTC messaging is not running yet".into()))?;

        let doc = build_document(&self.vtc_did, &self.vta_did, type_uri, payload);
        let mut value = serde_json::to_value(&doc)
            .map_err(|e| AppError::Internal(format!("serialise document: {e}")))?;
        self.signer.sign_operational_doc(&mut value).await?;
        let doc: TrustTask<Value> = serde_json::from_value(value)
            .map_err(|e| AppError::Internal(format!("reparse signed document: {e}")))?;

        // Registered before sending: a reply can land while the send returns.
        let receiver = self.replies.register(&doc.id, &self.vta_did);
        let sent = match protocol {
            Protocol::Tsp => self.send_tsp(messaging, &doc).await,
            Protocol::Didcomm => {
                crate::outbound::send_trust_task_didcomm(messaging, &self.vta_did, &doc)
                    .await
                    .map_err(|e| AppError::Internal(format!("DIDComm send to the VTA: {e}")))
            }
            Protocol::Rest => Err(AppError::Internal("the VTA link has no REST arm".into())),
        };
        if let Err(e) = sent {
            self.replies.abandon(&doc.id);
            return Err(e);
        }
        match tokio::time::timeout(self.reply_timeout, receiver).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => {
                self.replies.abandon(&doc.id);
                Err(AppError::Internal("the reply channel closed".into()))
            }
            Err(_) => {
                self.replies.abandon(&doc.id);
                Err(AppError::Internal(format!(
                    "no reply from the VTA within {}s",
                    self.reply_timeout.as_secs()
                )))
            }
        }
    }

    #[cfg(feature = "tsp")]
    async fn send_tsp(
        &self,
        messaging: &VtcMessaging,
        doc: &TrustTask<Value>,
    ) -> Result<(), AppError> {
        let body = crate::outbound::seal_trust_task_tsp(doc)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let mediator = self.tsp_mediator.read().ok().and_then(|m| m.clone());
        vti_common::tsp_route::send_reestablishing(
            &messaging.atm,
            &messaging.profile,
            &messaging.mediator_did,
            &self.vta_did,
            mediator.as_deref(),
            &body,
        )
        .await
        .map_err(|e| AppError::Internal(format!("TSP send to the VTA: {e}")))
    }

    #[cfg(not(feature = "tsp"))]
    async fn send_tsp(&self, _: &VtcMessaging, _: &TrustTask<Value>) -> Result<(), AppError> {
        // Never selected: `select` offers TSP only with the feature.
        Err(AppError::Internal(
            "this build has no `tsp` feature and cannot send TSP frames".into(),
        ))
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
