//! The production [`CapabilityWriter`]: signs a `git-trust/grant|revoke`
//! document with the VTC's assertion key and sends it to the community's
//! trust registry over DIDComm, correlating the reply by `threadId`.
//!
//! Durability lives in the hook queue, not here: this send is `BestEffort`
//! and a job is complete only when a correlated reply classifies as success —
//! no reply within the window is a [`HookWriteError::Transient`], which the
//! relay retries (R1.1: an `Ok` from a send is never treated as delivery).

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_delivery::Delivery;
use affinidi_messaging_didcomm::Message;
use async_trait::async_trait;
use tokio::sync::OnceCell;
use uuid::Uuid;
use vti_common::capability_client::{
    self, TRUST_TASK_ENVELOPE_TYPE, WriteOutcome, build_git_trust_grant, build_git_trust_revoke,
};

use crate::credentials::LocalSigner;
use crate::messaging::VtcMessaging;

use super::reply::PendingReplies;
use super::{CapabilityWriter, HookJob, HookOp, HookWriteError};

/// Default wait for the registry's reply before a write is deemed transient.
pub const DEFAULT_REPLY_TIMEOUT_SECONDS: u64 = 60;

/// Signs and sends capability writes to the trust registry over the VTC's
/// DIDComm messaging, awaiting the correlated reply.
pub struct DidcommCapabilityWriter {
    /// The VTC messaging handle (`None` until the listener is up — a not-yet-
    /// running messaging is a transient condition, not a permanent failure).
    didcomm: Arc<OnceCell<Arc<VtcMessaging>>>,
    /// The VTC's assertion signer (`{vtc_did}#key-0`) — the same identity
    /// that mints VMC/VEC. The community is the authority its grants are
    /// issued under, so this is exactly the right key.
    signer: Arc<LocalSigner>,
    /// DID of the community's trust registry (the write recipient).
    registry_did: String,
    replies: PendingReplies,
    reply_timeout: Duration,
}

impl DidcommCapabilityWriter {
    pub fn new(
        didcomm: Arc<OnceCell<Arc<VtcMessaging>>>,
        signer: Arc<LocalSigner>,
        registry_did: String,
        replies: PendingReplies,
    ) -> Self {
        Self {
            didcomm,
            signer,
            registry_did,
            replies,
            reply_timeout: Duration::from_secs(DEFAULT_REPLY_TIMEOUT_SECONDS),
        }
    }

    #[cfg(test)]
    pub fn with_reply_timeout(mut self, timeout: Duration) -> Self {
        self.reply_timeout = timeout;
        self
    }
}

#[async_trait]
impl CapabilityWriter for DidcommCapabilityWriter {
    async fn write(&self, job: &HookJob) -> Result<WriteOutcome, HookWriteError> {
        let messaging = self.didcomm.get().ok_or_else(|| {
            HookWriteError::Transient("VTC messaging not running yet".to_string())
        })?;
        let issuer = messaging.vtc_did.clone();
        let doc = self.build_signed_document(&issuer, job).await?;

        // Register the waiter before sending so a fast reply cannot be lost.
        let receiver = self.replies.register(&doc.id);

        if let Err(e) = self.send_envelope(messaging, &doc).await {
            self.replies.abandon(&doc.id);
            return Err(e);
        }

        match tokio::time::timeout(self.reply_timeout, receiver).await {
            Ok(Ok(reply)) => capability_client::classify_git_trust_reply(&reply).ok_or_else(|| {
                // A reply we correlated but can't classify is a contract bug on
                // the registry side; retrying can't fix it, but treating it as
                // permanent would strand the job — surface transient + loud.
                HookWriteError::Transient(format!(
                    "uninterpretable reply type `{}`",
                    reply.type_uri
                ))
            }),
            Ok(Err(_closed)) => {
                self.replies.abandon(&doc.id);
                Err(HookWriteError::Transient(
                    "reply channel closed".to_string(),
                ))
            }
            Err(_elapsed) => {
                self.replies.abandon(&doc.id);
                Err(HookWriteError::Transient(format!(
                    "no reply within {}s",
                    self.reply_timeout.as_secs()
                )))
            }
        }
    }
}

impl DidcommCapabilityWriter {
    /// Build the `git-trust/grant|revoke` document for `job` (issued by
    /// `issuer`, the VTC) and attach the VTC's Data-Integrity proof. Signing
    /// reuses the VTC's credential signer, whose canonical form (remove
    /// `proof`, eddsa-jcs-2022, reinsert) matches the registry verifier's
    /// exactly — so a document built here verifies at the registry.
    async fn build_signed_document(
        &self,
        issuer: &str,
        job: &HookJob,
    ) -> Result<trust_tasks_rs::TrustTask<serde_json::Value>, HookWriteError> {
        let doc = match job.op {
            HookOp::Grant => {
                build_git_trust_grant(issuer, &self.registry_did, &job.subject_did, &job.resource)
            }
            HookOp::Revoke => build_git_trust_revoke(
                issuer,
                &self.registry_did,
                &job.subject_did,
                &job.resource,
                job.reason.as_deref(),
            ),
        }
        .map_err(|e| HookWriteError::Transient(format!("build capability document: {e}")))?;

        let mut doc_value = serde_json::to_value(&doc)
            .map_err(|e| HookWriteError::Transient(format!("serialise document: {e}")))?;
        self.signer
            .sign_doc(&mut doc_value)
            .await
            .map_err(|e| HookWriteError::Transient(format!("sign document: {e}")))?;
        serde_json::from_value(doc_value)
            .map_err(|e| HookWriteError::Transient(format!("reparse signed document: {e}")))
    }

    /// Pack the signed document in the trust-task envelope and hand it to the
    /// delivery layer (`BestEffort` — the hook queue owns durability).
    async fn send_envelope(
        &self,
        messaging: &VtcMessaging,
        doc: &trust_tasks_rs::TrustTask<serde_json::Value>,
    ) -> Result<(), HookWriteError> {
        let body = serde_json::to_value(doc)
            .map_err(|e| HookWriteError::Transient(format!("serialise envelope body: {e}")))?;
        let envelope = Message::build(
            format!("urn:uuid:{}", Uuid::new_v4()),
            TRUST_TASK_ENVELOPE_TYPE.to_string(),
            body,
        )
        .from(messaging.vtc_did.clone())
        .to(self.registry_did.clone())
        .thid(doc.id.clone())
        .finalize();

        let (packed, _) = messaging
            .atm
            .pack_encrypted(
                &envelope,
                &self.registry_did,
                Some(&messaging.vtc_did),
                Some(&messaging.vtc_did),
            )
            .await
            .map_err(|e| HookWriteError::Unreachable(format!("pack failed: {e}")))?;

        messaging
            .service
            .send(
                &self.registry_did,
                packed.into_bytes(),
                Delivery::BestEffort,
            )
            .await
            .map_err(|e| HookWriteError::Unreachable(format!("send failed: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::hooks::reply::PendingReplies;
    use std::time::Duration;
    use trust_tasks_rs::TrustTask;

    const VTC: &str = "did:webvh:vtc.example";
    const REGISTRY: &str = "did:webvh:registry.example";

    fn writer() -> DidcommCapabilityWriter {
        DidcommCapabilityWriter::new(
            Arc::new(OnceCell::new()),
            Arc::new(LocalSigner::from_ed25519_seed(VTC.into(), &[0x11; 32])),
            REGISTRY.into(),
            PendingReplies::new(),
        )
        .with_reply_timeout(Duration::from_millis(50))
    }

    fn grant_job() -> HookJob {
        HookJob::new(
            "seq".into(),
            HookOp::Grant,
            "did:example:signer".into(),
            "openvtc".into(),
            None,
            chrono::Utc::now(),
        )
    }

    #[tokio::test]
    async fn signed_document_verifies_against_the_vtc_key() {
        let w = writer();
        let doc = w.build_signed_document(VTC, &grant_job()).await.unwrap();
        assert_eq!(doc.type_uri.slug(), "git-trust/grant");
        assert_eq!(doc.issuer.as_deref(), Some(VTC));
        assert_eq!(doc.recipient.as_deref(), Some(REGISTRY));

        // The proof verifies over the canonical form (doc minus proof) with
        // the VTC's public key — the same check the registry runs.
        let proof = doc.proof.clone().expect("document is signed");
        let mut value = serde_json::to_value(&doc).unwrap();
        value.as_object_mut().unwrap().remove("proof");
        let di_proof: affinidi_data_integrity::DataIntegrityProof =
            serde_json::from_value(serde_json::to_value(&proof).unwrap()).unwrap();
        let signer = LocalSigner::from_ed25519_seed(VTC.into(), &[0x11; 32]);
        di_proof
            .verify_with_public_key(
                &value,
                signer.public_bytes(),
                affinidi_data_integrity::VerifyOptions::new(),
            )
            .expect("proof verifies with the VTC key");
    }

    #[tokio::test]
    async fn write_is_transient_when_messaging_is_not_up() {
        let w = writer();
        // Empty OnceCell = listener not yet running.
        let err = w.write(&grant_job()).await.unwrap_err();
        assert!(matches!(err, HookWriteError::Transient(_)), "got {err}");
    }

    #[tokio::test]
    async fn pending_replies_correlate_by_thread_id() {
        let replies = PendingReplies::new();
        let rx = replies.register("urn:uuid:req");

        // A reply with the wrong threadId completes nobody.
        let mut wrong: TrustTask<serde_json::Value> = TrustTask::new(
            "urn:uuid:x".to_string(),
            "https://trusttasks.org/spec/git-trust/grant/0.1#response"
                .parse()
                .unwrap(),
            serde_json::json!({}),
        );
        wrong.thread_id = Some("urn:uuid:other".into());
        assert!(!replies.complete(wrong));

        // The matching reply resolves the waiter.
        let mut right: TrustTask<serde_json::Value> = TrustTask::new(
            "urn:uuid:y".to_string(),
            "https://trusttasks.org/spec/git-trust/grant/0.1#response"
                .parse()
                .unwrap(),
            serde_json::json!({}),
        );
        right.thread_id = Some("urn:uuid:req".into());
        assert!(replies.complete(right));
        assert!(rx.await.is_ok());
    }
}
