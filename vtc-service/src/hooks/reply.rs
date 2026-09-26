//! Reply correlation for capability writes.
//!
//! A capability write is sent as a DIDComm envelope and its reply arrives
//! asynchronously on the shared inbound stream. The [`CapabilityWriter`] and
//! the inbound demux (`messaging::dispatch`) share one [`PendingReplies`]: the
//! writer registers a waiter keyed by the request document id before sending;
//! the demux completes it when a reply whose `threadId` matches arrives.
//!
//! [`CapabilityWriter`]: super::CapabilityWriter

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tokio::sync::oneshot;
use trust_tasks_rs::TrustTask;

/// Shared map of in-flight capability writes awaiting their reply, keyed by
/// request document id (== the reply's `threadId`).
#[derive(Clone, Default)]
pub struct PendingReplies {
    inner: Arc<Mutex<HashMap<String, Waiter>>>,
}

/// One outstanding request: the peer it went to, and the waiter for its reply.
struct Waiter {
    /// Base DID of the party the request was sent to. Only a reply whose
    /// verified signer is this DID releases the waiter.
    peer: String,
    tx: oneshot::Sender<TrustTask<Value>>,
}

fn base_did(did: &str) -> &str {
    did.split('#').next().unwrap_or(did)
}

impl PendingReplies {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a waiter for `request_id` before the request is sent, so a
    /// fast reply cannot race the registration. `peer` is the DID the request
    /// goes to: only a reply that party verifiably signed releases the waiter.
    pub fn register(&self, request_id: &str, peer: &str) -> oneshot::Receiver<TrustTask<Value>> {
        let (tx, rx) = oneshot::channel();
        self.lock().insert(
            request_id.to_string(),
            Waiter {
                peer: base_did(peer).to_string(),
                tx,
            },
        );
        rx
    }

    /// Drop the waiter for `request_id` (send failure or timeout).
    pub fn abandon(&self, request_id: &str) {
        self.lock().remove(request_id);
    }

    /// Complete the waiter registered under `document`'s `threadId` — only when
    /// `verified_signer` (the DID the document's own proof verifies as, bound to
    /// its `issuer`) is the peer the request went to. Returns `true` if a waiter
    /// received it (i.e. this was one of our replies). A document on the thread
    /// that the peer did not sign leaves the waiter for the genuine reply.
    pub fn complete(&self, document: TrustTask<Value>, verified_signer: Option<&str>) -> bool {
        let Some(thread_id) = document.thread_id.clone() else {
            return false;
        };
        let Some(signer) = verified_signer.map(base_did) else {
            return false;
        };
        let waiter = {
            let mut map = self.lock();
            match map.get(&thread_id) {
                Some(w) if w.peer == signer => map.remove(&thread_id),
                _ => None,
            }
        };
        match waiter {
            Some(w) => w.tx.send(document).is_ok(),
            None => false,
        }
    }

    /// [`Self::complete`], verifying `document`'s proof first: the signer must
    /// be the document's `issuer`.
    pub async fn complete_verified(
        &self,
        document: TrustTask<Value>,
        resolver: &vti_common::auth::TrustTaskVmResolver,
    ) -> bool {
        let signer = match document.proof.as_ref() {
            Some(_) => vti_common::auth::verify_trust_task_proof_with(&document, resolver)
                .await
                .ok()
                .map(|s| base_did(&s).to_string())
                .filter(|s| document.issuer.as_deref() == Some(s.as_str())),
            None => None,
        };
        self.complete(document, signer.as_deref())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Waiter>> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}
