//! Pushing a signed Trust Task to a peer — an approver's device, a requester —
//! over whichever transport it speaks, durably, with escalation.
//!
//! The engine is node-neutral and lives in [`vti_common::trust_task_push`],
//! which documents the selection, the evidence and the escalation
//! (VTI-TRN-030, -040, -041, -042). This module lends it what is the VTA's own:
//! the encrypted `trust_task_pushes` keyspace, the outbox, the resolver, the
//! current session's messaging, and what the VTA has learned about which peers
//! are listening on TSP.
//!
//! The session is read from [`crate::didcomm_bridge::DIDCommBridge::push_wiring`]
//! on every call rather than held, because the VTA republishes its messaging on
//! each mediator reconnect.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_core::MessageTransport;
use affinidi_messaging_delivery::{MessagingService, OutboxStore};
use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use serde_json::Value;
use tracing::warn;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use vti_common::trust_task_push::{self, PushContext, PushMessaging};

use crate::server::AppState;

/// How long the durable-push sweep waits between passes.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// How often a named push transport's drain loop looks for due entries.
const DRAIN_INTERVAL: Duration = Duration::from_secs(2);

/// Every `(recipient, document)` handed to [`push_trust_task`], in order — the
/// unit tests' view of what a push site sent. Recorded before the engine runs,
/// so it holds even where a test has no live messaging session to queue on.
#[cfg(test)]
pub(crate) type PushLog = Arc<std::sync::Mutex<Vec<(String, Value)>>>;

/// One document a push site handed to delivery (unit tests).
#[cfg(test)]
pub(crate) struct Pushed {
    pub recipient_did: String,
    pub body: Value,
}

/// Drain what the push sites of `state` have handed to delivery so far.
#[cfg(test)]
pub(crate) fn take_pushes(state: &AppState) -> Vec<Pushed> {
    std::mem::take(&mut *state.push_log.lock().expect("push log"))
        .into_iter()
        .map(|(recipient_did, body)| Pushed {
            recipient_did,
            body,
        })
        .collect()
}

/// Push a **signed** Trust Task document to `recipient`, durably. `Ok` means
/// the first attempt is queued (VTI-TRN-030), not that it was delivered — see
/// [`trust_task_push::push_trust_task`].
pub async fn push_trust_task(
    state: &AppState,
    recipient: &str,
    document: Value,
    deliver_by: Duration,
) -> Result<String, AppError> {
    #[cfg(test)]
    state
        .push_log
        .lock()
        .expect("push log")
        .push((recipient.to_string(), document.clone()));
    let wiring = state.didcomm_bridge.push_wiring();
    trust_task_push::push_trust_task(&context(state, &wiring), recipient, document, deliver_by)
        .await
}

/// One pass over every push: settle, escalate, and expire.
pub async fn sweep(state: &AppState) -> Result<(), AppError> {
    let wiring = state.didcomm_bridge.push_wiring();
    trust_task_push::sweep(&context(state, &wiring)).await
}

/// Run [`sweep`] every [`SWEEP_INTERVAL`], for the life of the process. Spawn
/// once at startup, not per session: each pass reads the current session.
pub async fn sweep_loop(state: AppState) {
    let mut tick = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        tick.tick().await;
        if let Err(e) = sweep(&state).await {
            warn!(error = %e, "trust-task push sweep failed; retrying next tick");
        }
    }
}

fn context<'a>(
    state: &'a AppState,
    wiring: &'a Option<(Arc<MessagingService>, ATM, String)>,
) -> PushContext<'a> {
    PushContext {
        records: &state.trust_task_pushes_ks,
        outbox: &state.outbox_ks,
        resolver: state.did_resolver.as_ref(),
        messaging: wiring
            .as_ref()
            .map(|(service, atm, own_did)| PushMessaging {
                service,
                atm,
                own_did,
            }),
        tsp: cfg!(feature = "tsp"),
        #[cfg(feature = "tsp")]
        learned_tsp: Some(&state.tsp_reach),
        #[cfg(not(feature = "tsp"))]
        learned_tsp: None,
    }
}

/// Add the push engine's named TSP and REST transports to one session's
/// service, each with its own drain loop. Called from
/// [`crate::messaging::service::build_messaging`] for every new session, since
/// a named transport belongs to the service it was added to.
pub(crate) fn register_transports(
    service: &MessagingService,
    outbox: Arc<dyn OutboxStore>,
    pushes: KeyspaceHandle,
    #[cfg_attr(not(feature = "tsp"), allow(unused))] atm: &Arc<ATM>,
    #[cfg_attr(not(feature = "tsp"), allow(unused))] profile: &Arc<ATMProfile>,
    #[cfg_attr(not(feature = "tsp"), allow(unused))] mediator_did: &str,
) {
    #[cfg(feature = "tsp")]
    if let Some(primary) = service.primary_transport() {
        let tsp: Arc<dyn MessageTransport> = Arc::new(trust_task_push::TspPushTransport {
            atm: atm.clone(),
            profile: profile.clone(),
            mediator_did: mediator_did.to_string(),
            pushes: pushes.clone(),
            conn: primary.connection_state(),
        });
        service.add_transport(trust_task_push::TSP_TRANSPORT_ID.into(), tsp.clone());
        tokio::spawn(affinidi_messaging_delivery::drain_loop_via(
            outbox.clone(),
            trust_task_push::TSP_TRANSPORT_ID.into(),
            tsp,
            DRAIN_INTERVAL,
        ));
    }
    let rest: Arc<dyn MessageTransport> = Arc::new(trust_task_push::RestPushTransport::new(
        pushes,
        vta_sdk::http::foreign_fetch_client(),
    ));
    service.add_transport(trust_task_push::REST_TRANSPORT_ID.into(), rest.clone());
    tokio::spawn(affinidi_messaging_delivery::drain_loop_via(
        outbox,
        trust_task_push::REST_TRANSPORT_ID.into(),
        rest,
        DRAIN_INTERVAL,
    ));
}
