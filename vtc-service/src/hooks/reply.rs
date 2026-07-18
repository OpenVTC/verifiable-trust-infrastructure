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
    inner: Arc<Mutex<HashMap<String, oneshot::Sender<TrustTask<Value>>>>>,
}

impl PendingReplies {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a waiter for `request_id` before the request is sent, so a
    /// fast reply cannot race the registration.
    pub fn register(&self, request_id: &str) -> oneshot::Receiver<TrustTask<Value>> {
        let (tx, rx) = oneshot::channel();
        self.lock().insert(request_id.to_string(), tx);
        rx
    }

    /// Drop the waiter for `request_id` (send failure or timeout).
    pub fn abandon(&self, request_id: &str) {
        self.lock().remove(request_id);
    }

    /// Complete the waiter registered under `document`'s `threadId`. Returns
    /// `true` if a waiter received it (i.e. this was one of our replies).
    pub fn complete(&self, document: TrustTask<Value>) -> bool {
        let Some(thread_id) = document.thread_id.clone() else {
            return false;
        };
        let waiter = self.lock().remove(&thread_id);
        match waiter {
            Some(tx) => tx.send(document).is_ok(),
            None => false,
        }
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, oneshot::Sender<TrustTask<Value>>>> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}
