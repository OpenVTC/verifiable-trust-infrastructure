//! One mediator session per witness identity: `vti_common::host_session`, with
//! this service's dispatch core as the responder.
//!
//! The session, its supervisor and the TSP / DIDComm carriage are shared with
//! every host service; what is the witness's own is [`WitnessResponder`] —
//! [`dispatch::answer`] for one identity, verifying proofs through the
//! process's one resolver.

use std::sync::Arc;

use serde_json::Value;
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
pub use vti_common::host_session::{IdentitySession, Shared, supervise};

use crate::dispatch::{self, IdentityContext, Outcome};

/// A witness identity as a [`vti_common::host_session::Responder`].
#[derive(Debug)]
pub struct WitnessResponder {
    identity: IdentityContext,
    vm_resolver: TrustTaskVmResolver,
}

impl WitnessResponder {
    /// `identity`, verifying proofs through `vm_resolver`.
    pub fn new(identity: IdentityContext, vm_resolver: TrustTaskVmResolver) -> Arc<Self> {
        Arc::new(Self {
            identity,
            vm_resolver,
        })
    }
}

#[async_trait::async_trait]
impl vti_common::host_session::Responder for WitnessResponder {
    fn name(&self) -> &str {
        self.identity.name()
    }

    fn did(&self) -> &str {
        self.identity.did()
    }

    async fn answer(&self, sender: &str, document: &[u8]) -> Option<Value> {
        match dispatch::answer(
            &self.identity,
            sender,
            document,
            &self.vm_resolver,
            chrono::Utc::now(),
        )
        .await
        {
            Outcome::Reply(reply) => Some(reply),
            Outcome::Drop(reason) => {
                tracing::debug!(identity = %self.identity.name(), %sender, ?reason, "dropped unanswered");
                None
            }
        }
    }
}
