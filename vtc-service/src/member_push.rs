//! Pushing a Trust Task to a member, over whichever transport the member
//! speaks — TSP, then DIDComm, then REST — durably, with escalation.
//!
//! The engine is node-neutral and lives in [`vti_common::trust_task_push`],
//! which documents the selection, the evidence classes and the escalation
//! (VTI-TRN-030, -040, -041, -042). This module lends it what is the VTC's
//! own: the encrypted `member_pushes` keyspace, the outbox, the resolver and
//! the messaging handle.

use std::time::Duration;

use serde_json::Value;
use vta_sdk::protocol::matching::Protocol;
use vti_common::error::AppError;
use vti_common::trust_task_push::{self, PushContext, PushMessaging, PushReissuer};

#[cfg(feature = "tsp")]
pub use vti_common::trust_task_push::TspPushTransport;
pub use vti_common::trust_task_push::{
    ATTEMPT_WINDOW, REST_TRANSPORT_ID, RestPushTransport, TSP_TRANSPORT_ID,
};

use crate::server::AppState;

fn context(state: &AppState) -> PushContext<'_> {
    PushContext {
        records: &state.member_pushes_ks,
        outbox: &state.outbox_ks,
        resolver: state.did_resolver.as_ref(),
        messaging: state.didcomm.get().map(|m| PushMessaging {
            service: &m.service,
            atm: &m.atm,
            own_did: &m.vtc_did,
        }),
        tsp: cfg!(feature = "tsp"),
        learned_tsp: Some(&state.tsp_reach),
        reissuer: Some(state),
    }
}

/// The VTC signs a new attempt at a push as it signed the original. Its push
/// sites sign two ways — a request under the operational key with `proofPurpose:
/// authentication` (`sign_operational_doc`), and the granted notice with the
/// signer's default purpose (`sign_doc`) — so the original's own proof says
/// which.
#[async_trait::async_trait]
impl PushReissuer for AppState {
    async fn sign_new_attempt(&self, previous: &Value, next: &mut Value) -> Result<(), AppError> {
        let signer = self
            .credential_signer
            .as_ref()
            .ok_or_else(|| AppError::Internal("credential signer not configured".into()))?;
        let purpose = previous
            .get("proof")
            .and_then(|p| p.get("proofPurpose"))
            .and_then(Value::as_str);
        if purpose == Some("authentication") {
            signer.sign_operational_doc(next).await
        } else {
            signer.sign_doc(next).await
        }
    }
}

/// Push a **signed** Trust Task document to `recipient`. `Ok` means the first
/// attempt is durably queued (VTI-TRN-030), not that it was delivered — see
/// [`trust_task_push::push_trust_task`].
pub async fn push_trust_task(
    state: &AppState,
    recipient: &str,
    document: Value,
    deliver_by: Duration,
) -> Result<String, AppError> {
    trust_task_push::push_trust_task(&context(state), recipient, document, deliver_by).await
}

/// How a push ended, once it has: `(delivered, via, evidence)`.
pub async fn outcome(
    state: &AppState,
    id: &str,
) -> Result<Option<(bool, Protocol, String)>, AppError> {
    trust_task_push::outcome(&state.member_pushes_ks, id).await
}

/// One pass over every push: settle, escalate, and expire.
pub async fn sweep(state: &AppState) -> Result<(), AppError> {
    trust_task_push::sweep(&context(state)).await
}
