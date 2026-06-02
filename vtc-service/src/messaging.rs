use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommService, DIDCommServiceConfig, DIDCommServiceError, Extension,
    HandlerContext, ListenerConfig, ListenerEvent, MESSAGE_PICKUP_STATUS_TYPE, RestartPolicy,
    RetryConfig, Router, TRUST_PING_TYPE, handler_fn, ignore_handler, trust_ping_handler,
};
use affinidi_tdk::common::profiles::TDKProfile;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_SUBMIT_RECEIPT_TYPE, JOIN_REQUEST_SUBMIT_TYPE, JoinRequestSubmitBody,
    JoinRequestSubmitReceiptBody, MEMBER_SELF_REMOVE_RECEIPT_TYPE, MEMBER_SELF_REMOVE_TYPE,
    SelfRemoveBody, SelfRemoveReceiptBody,
};

use crate::config::AppConfig;
use crate::join::JoinTransport;
use crate::members::Disposition;
use crate::routes::join_requests::submit::submit_inner;
use crate::routes::members::remove::remove_inner;
use crate::server::AppState;

/// Start the DIDComm service and block until shutdown.
///
/// Uses `DIDCommService` for automatic mediator connection management,
/// reconnection with backoff, and typed message routing.
///
/// `state` is needed because the join-request handler writes
/// rows into the keyspaces + audit log — same shared
/// `AppState` the REST surface holds. Passed as a `Router`
/// extension so handlers extract it via `Extension<AppState>`.
pub async fn run_didcomm_service(
    config: &AppConfig,
    secrets_resolver: &Arc<ThreadedSecretsResolver>,
    vtc_did: &str,
    state: AppState,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let mediator_did = match &config.messaging {
        Some(m) => &m.mediator_did,
        None => {
            warn!("messaging not configured — inbound message handling disabled");
            let _ = shutdown_rx.changed().await;
            return;
        }
    };

    // Collect secrets for the TDKProfile
    let signing_id = format!("{vtc_did}#key-0");
    let ka_id = format!("{vtc_did}#key-1");
    let mut secrets = Vec::new();
    if let Some(s) = secrets_resolver.get_secret(&signing_id).await {
        secrets.push(s);
    } else {
        warn!("VTC signing secret not found — messaging disabled");
        let _ = shutdown_rx.changed().await;
        return;
    }
    if let Some(s) = secrets_resolver.get_secret(&ka_id).await {
        secrets.push(s);
    }

    let profile = TDKProfile::new("VTC", vtc_did, Some(mediator_did), secrets);

    let service_config = DIDCommServiceConfig {
        listeners: vec![ListenerConfig {
            id: "vtc-main".into(),
            profile,
            restart_policy: RestartPolicy::Always {
                backoff: RetryConfig {
                    initial_delay_secs: 5,
                    max_delay_secs: 60,
                },
            },
            ..Default::default()
        }],
    };

    // Build the router: trust-ping + ignore-pickup-status + the
    // VTC's protocol surface. `Extension<AppState>` is how the
    // join-request handler reaches the keyspaces / audit writer.
    let router = match Router::new()
        .extension(state)
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))
        .and_then(|r| r.route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler)))
        .and_then(|r| {
            r.route(
                JOIN_REQUEST_SUBMIT_TYPE,
                handler_fn(join_request_submit_handler),
            )
        })
        .and_then(|r| {
            r.route(
                MEMBER_SELF_REMOVE_TYPE,
                handler_fn(member_self_remove_handler),
            )
        }) {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to build DIDComm router: {e}");
            let _ = shutdown_rx.changed().await;
            return;
        }
    };

    let shutdown_token = CancellationToken::new();
    let service = match DIDCommService::start(service_config, router, shutdown_token.clone()).await
    {
        Ok(s) => s,
        Err(e) => {
            warn!("failed to start DIDComm service: {e}");
            let _ = shutdown_rx.changed().await;
            return;
        }
    };

    // Wait for the mediator connection
    if let Err(e) = service
        .wait_connected("vtc-main", Duration::from_secs(30))
        .await
    {
        warn!("DIDComm listener not connected after 30s: {e}");
    }

    // Log lifecycle events in background
    let mut event_rx = service.subscribe();
    let event_task = tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(ListenerEvent::Connected { listener_id }) => {
                    info!(listener = %listener_id, "DIDComm listener connected");
                }
                Ok(ListenerEvent::Disconnected { listener_id, error }) => {
                    warn!(
                        listener = %listener_id,
                        error = error.as_deref().unwrap_or("none"),
                        "DIDComm listener disconnected"
                    );
                }
                Ok(ListenerEvent::Restarting {
                    listener_id,
                    attempt,
                    delay,
                }) => {
                    info!(
                        listener = %listener_id,
                        attempt,
                        delay_secs = delay.as_secs(),
                        "DIDComm listener restarting"
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!(skipped = n, "DIDComm event logger lagged");
                }
            }
        }
    });

    info!("DIDComm service started");

    // Block until shutdown
    let _ = shutdown_rx.changed().await;

    // Graceful shutdown
    service.shutdown().await;
    event_task.abort();
    info!("DIDComm service stopped");
}

/// `join-requests/submit/1.0` over DIDComm (M1.8.2).
///
/// The applicant DID is the DIDComm `from` field — the
/// authcrypt sender. No separate holder-binding signature
/// needed (the envelope IS the proof). Calls into the same
/// `submit_inner` the REST endpoint uses.
async fn join_request_submit_handler(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let applicant_did = ctx.sender_did.clone().ok_or_else(|| {
        DIDCommServiceError::Internal("join-request submit has no DIDComm sender".into())
    })?;
    let body: JoinRequestSubmitBody = serde_json::from_value(message.body.clone())
        .map_err(|e| DIDCommServiceError::Internal(format!("malformed join-request body: {e}")))?;

    let request = submit_inner(
        &state,
        applicant_did,
        body.vp,
        body.registry_consent,
        body.extensions,
        None,
        JoinTransport::DIDComm,
    )
    .await
    .map_err(|e| DIDCommServiceError::Internal(format!("submit failed: {e}")))?;

    let receipt = JoinRequestSubmitReceiptBody {
        request_id: request.id,
        status: request.status.to_string(),
    };
    let body = serde_json::to_value(&receipt)
        .map_err(|e| DIDCommServiceError::Internal(format!("receipt serialise: {e}")))?;
    Ok(Some(
        DIDCommResponse::new(JOIN_REQUEST_SUBMIT_RECEIPT_TYPE, body).thid(message.id),
    ))
}

/// `members/self-remove/1.0` over DIDComm (M1.11.1 twin).
///
/// Caller's DID = the DIDComm `from` field. Body optionally
/// carries the disposition; defaults match REST (Member's
/// stored `departure_preference`, then PolicyDefault→Tombstone).
async fn member_self_remove_handler(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let caller_did = ctx
        .sender_did
        .clone()
        .ok_or_else(|| DIDCommServiceError::Internal("self-remove has no DIDComm sender".into()))?;

    let body: SelfRemoveBody = serde_json::from_value(message.body.clone())
        .map_err(|e| DIDCommServiceError::Internal(format!("malformed self-remove body: {e}")))?;

    let disposition = body
        .disposition
        .as_deref()
        .map(parse_disposition)
        .transpose()
        .map_err(DIDCommServiceError::Internal)?;

    // DIDComm self-leave — actor == subject. The leave decision policy
    // allows self-leave unconditionally (spec §10.2); the no-last-admin
    // invariant still applies in the effect stage.
    let outcome = remove_inner(&state, &caller_did, &caller_did, disposition, String::new())
        .await
        .map_err(|e| DIDCommServiceError::Internal(format!("self-remove: {e}")))?;

    let receipt = SelfRemoveReceiptBody {
        did: outcome.did,
        disposition: outcome.disposition,
        removed: outcome.removed,
    };
    let body = serde_json::to_value(&receipt)
        .map_err(|e| DIDCommServiceError::Internal(format!("receipt serialise: {e}")))?;
    Ok(Some(
        DIDCommResponse::new(MEMBER_SELF_REMOVE_RECEIPT_TYPE, body).thid(message.id),
    ))
}

fn parse_disposition(s: &str) -> Result<Disposition, String> {
    match s.to_ascii_lowercase().as_str() {
        "purge" => Ok(Disposition::Purge),
        "tombstone" => Ok(Disposition::Tombstone),
        "historical" => Ok(Disposition::Historical),
        "policydefault" => Ok(Disposition::PolicyDefault),
        other => Err(format!(
            "unknown disposition '{other}' (expected purge|tombstone|historical|policydefault)"
        )),
    }
}
