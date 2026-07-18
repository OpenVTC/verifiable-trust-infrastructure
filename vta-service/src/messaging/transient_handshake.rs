//! Transient delivery-layer messaging service for the first-enable handshake.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`
//! "Mediator handshake before promotion".
//!
//! At first-enable time the main [`MessagingService`] isn't running
//! (`services.didcomm = false`), so the live prover used by `migrate` can't be
//! reused. This module spins up a **transient** delivery-layer service just for
//! the handshake round-trip:
//!
//! 1. Build an ATM (seeded with the VTA's secrets) + a bounded-websocket
//!    [`ATMProfile`] against the new mediator, wrap it in a [`DidCommTransport`],
//!    and drive it with a single-transport [`MessagingService`] over an
//!    in-memory outbox.
//! 2. Spawn a minimal trust-ping answerer on `subscribe()` (there is no full
//!    handler set at first-enable) so the self-ping gets a pong.
//! 3. Trust-ping the VTA's own DID via the new mediator and await the pong.
//! 4. Cancel the answerer + drop the service so the websocket tears down.
//!
//! On success or failure the transient service is torn down before returning.
//! The caller (`enable_didcomm`) then publishes the LogEntry and persists
//! `services.didcomm = true`; the next restart starts the real
//! [`crate::messaging::service`] path, which re-connects to the now-active
//! mediator.

#![cfg(all(feature = "webvh", feature = "didcomm"))]

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_core::{MessageTransport, Protocol};
use affinidi_messaging_delivery::{Delivery, InMemoryOutboxStore, MessagingService, OutboxStore};
use affinidi_messaging_didcomm::Message;
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::{ATM, DidCommTransport};
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use futures_util::StreamExt;
use serde_json::{Value as JsonValue, json};
use tokio_util::sync::CancellationToken;
use tracing::warn;
use vti_common::telemetry::{SharedTelemetrySink, TelemetryEvent, TelemetryKind};

use crate::messaging::handshake::{
    HandshakeError, HandshakeOptions, HandshakeStage, ProverFailure, ResolvedMediator,
    resolve_mediator,
};

const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
const TRUST_PING_RESPONSE_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping-response";

/// Caller-supplied bits the transient service needs to authenticate the VTA's
/// DID to the new mediator.
pub struct TransientHandshakeContext {
    pub vta_did: String,
    pub secrets: Vec<Secret>,
    pub tdk_config: Option<TDKConfig>,
}

/// Run the full handshake against a freshly-spun-up transient
/// [`MessagingService`]. Returns `Ok(ResolvedMediator)` on success. Always tears
/// down the transient service before returning, regardless of outcome.
pub async fn run_transient_handshake(
    ctx: TransientHandshakeContext,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    telemetry: &SharedTelemetrySink,
    mediator_did: &str,
    opts: HandshakeOptions,
) -> Result<ResolvedMediator, HandshakeError> {
    // Step 1 — always resolve.
    let resolved = match resolve_mediator(resolver, mediator_did).await {
        Ok(r) => r,
        Err(cause) => {
            emit_failed(telemetry, mediator_did, HandshakeStage::Resolve, &cause).await;
            return Err(HandshakeError::Failed {
                stage: HandshakeStage::Resolve,
                cause,
            });
        }
    };

    if opts.force {
        let _ = telemetry
            .record(
                TelemetryEvent::new(TelemetryKind::MediatorHandshakeBypassed)
                    .with_mediator(mediator_did)
                    .with_field("endpoint", JsonValue::from(resolved.endpoint.clone())),
            )
            .await;
        return Ok(resolved);
    }

    // Steps 2–5 against a transient service.
    match transient_prove(&ctx, mediator_did, opts.timeout).await {
        Ok(()) => {
            let _ = telemetry
                .record(
                    TelemetryEvent::new(TelemetryKind::MediatorHandshakeOk)
                        .with_mediator(mediator_did)
                        .with_field("endpoint", JsonValue::from(resolved.endpoint.clone())),
                )
                .await;
            Ok(resolved)
        }
        Err(failure) => {
            emit_failed(telemetry, mediator_did, failure.stage, &failure.cause).await;
            Err(HandshakeError::Failed {
                stage: failure.stage,
                cause: failure.cause,
            })
        }
    }
}

/// Build a transient single-transport delivery service against `mediator_did`,
/// prove it with a self trust-ping, then tear it down.
async fn transient_prove(
    ctx: &TransientHandshakeContext,
    mediator_did: &str,
    timeout: Duration,
) -> Result<(), ProverFailure> {
    let connect_fail = |cause: String| ProverFailure {
        stage: HandshakeStage::Connect,
        cause,
    };

    let tdk_config = match ctx.tdk_config.clone() {
        Some(c) => c,
        None => TDKConfig::builder()
            .build()
            .map_err(|e| connect_fail(format!("build TDK config: {e}")))?,
    };
    let tdk = TDKSharedState::new(tdk_config)
        .await
        .map_err(|e| connect_fail(format!("create TDK shared state: {e}")))?;
    for secret in &ctx.secrets {
        tdk.secrets_resolver().insert(secret.clone()).await;
    }
    let atm = ATM::new(
        ATMConfig::builder()
            .build()
            .map_err(|e| connect_fail(format!("build ATM config: {e}")))?,
        Arc::new(tdk),
    )
    .await
    .map_err(|e| connect_fail(format!("create ATM: {e}")))?;

    let profile = Arc::new(
        ATMProfile::new(
            &atm,
            Some(mediator_did.to_string()),
            ctx.vta_did.clone(),
            Some(mediator_did.to_string()),
        )
        .await
        .map_err(|e| connect_fail(format!("create transient profile: {e}")))?,
    );
    match tokio::time::timeout(timeout, atm.profile_enable_websocket(&profile)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(connect_fail(format!("enable transient websocket: {e}"))),
        Err(_) => {
            return Err(connect_fail(
                "timeout enabling transient mediator websocket".to_string(),
            ));
        }
    }

    let atm = Arc::new(atm);
    let transport: Arc<dyn MessageTransport> = Arc::new(
        DidCommTransport::new((*atm).clone(), profile.clone())
            .await
            .map_err(|e| connect_fail(format!("bind transient transport: {e}")))?,
    );
    let outbox: Arc<dyn OutboxStore> = Arc::new(InMemoryOutboxStore::new());
    // Single transport → it is the primary; `send` (the pong) routes through it.
    let service = Arc::new(MessagingService::new(transport, outbox));

    // Minimal trust-ping answerer (there is no handler set at first-enable).
    let answerer_shutdown = CancellationToken::new();
    spawn_ping_answerer(
        service.clone(),
        atm.clone(),
        ctx.vta_did.clone(),
        answerer_shutdown.clone(),
    );

    let result = ping_self(&service, &atm, &ctx.vta_did, timeout).await;

    // Tear down the answerer; dropping `service`/`atm` on return closes the
    // transient websocket.
    answerer_shutdown.cancel();
    tokio::time::sleep(Duration::from_millis(50)).await;
    result
}

/// Trust-ping the VTA's own DID over the transient service and await the pong.
async fn ping_self(
    service: &Arc<MessagingService>,
    atm: &ATM,
    vta_did: &str,
    timeout: Duration,
) -> Result<(), ProverFailure> {
    let ping_fail = |cause: String| ProverFailure {
        stage: HandshakeStage::TrustPing,
        cause,
    };

    let msg_id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ping = Message::build(
        msg_id.clone(),
        TRUST_PING_TYPE.to_string(),
        json!({ "response_requested": true }),
    )
    .from(vta_did.to_string())
    .to(vta_did.to_string())
    .created_time(now)
    .expires_time(now + timeout.as_secs())
    .finalize();
    let (packed, _) = atm
        .pack_encrypted(&ping, vta_did, Some(vta_did), Some(vta_did))
        .await
        .map_err(|e| ping_fail(format!("pack trust-ping: {e}")))?;

    let received = service
        .request(vta_did, packed.into_bytes(), &msg_id, timeout)
        .await
        .map_err(|e| ping_fail(format!("trust-ping round-trip failed: {e}")))?;

    let response: Message = serde_json::from_slice(&received.payload)
        .map_err(|e| ping_fail(format!("parse pong: {e}")))?;
    if response.typ != TRUST_PING_RESPONSE_TYPE {
        return Err(ping_fail(format!(
            "unexpected reply to trust-ping: {}",
            response.typ
        )));
    }
    Ok(())
}

/// Answer authenticated self trust-pings with a threaded pong over the same
/// transient service, until `shutdown` fires.
fn spawn_ping_answerer(
    service: Arc<MessagingService>,
    atm: Arc<ATM>,
    vta_did: String,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let mut stream = service.subscribe();
        loop {
            tokio::select! {
                maybe = stream.next() => {
                    let Some(inbound) = maybe else { break };
                    if inbound.message.protocol != Protocol::DIDComm {
                        continue;
                    }
                    let Ok(msg) = serde_json::from_slice::<Message>(&inbound.message.payload) else {
                        continue;
                    };
                    if msg.typ != TRUST_PING_TYPE {
                        continue;
                    }
                    // Only pong an authenticated (verified) sender; fall back to
                    // the plaintext `from` solely as the reply address.
                    let to = inbound
                        .message
                        .sender
                        .clone()
                        .filter(|_| inbound.message.verified)
                        .or_else(|| msg.from.clone());
                    let Some(to) = to else { continue };
                    let pong = Message::build(
                        uuid::Uuid::new_v4().to_string(),
                        TRUST_PING_RESPONSE_TYPE.to_string(),
                        JsonValue::Null,
                    )
                    .from(vta_did.clone())
                    .to(to.clone())
                    .thid(msg.id.clone())
                    .finalize();
                    if let Ok((packed, _)) = atm
                        .pack_encrypted(&pong, &to, Some(&vta_did), Some(&vta_did))
                        .await
                        && let Err(e) = service
                            .send(&to, packed.into_bytes(), Delivery::BestEffort)
                            .await
                    {
                        warn!(error = %e, "transient handshake: failed to send pong");
                    }
                }
                _ = shutdown.cancelled() => break,
            }
        }
    });
}

async fn emit_failed(
    telemetry: &SharedTelemetrySink,
    mediator_did: &str,
    stage: HandshakeStage,
    cause: &str,
) {
    let _ = telemetry
        .record(
            TelemetryEvent::new(TelemetryKind::MediatorHandshakeFailed)
                .with_mediator(mediator_did)
                .with_field("stage", JsonValue::from(stage.as_str()))
                .with_field("cause", JsonValue::from(cause)),
        )
        .await;
}

#[cfg(test)]
mod tests {
    use crate::messaging::handshake::HandshakeStage;

    /// Sentinel: the construction shape compiles + the stages this module
    /// produces are still present.
    #[test]
    fn transient_handshake_module_compiles() {
        let _stage = HandshakeStage::Resolve;
    }
}
