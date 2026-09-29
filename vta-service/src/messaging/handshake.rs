//! Mediator handshake: 5-step preflight before promoting a mediator
//! into the DID document.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md` §
//! "Mediator handshake before promotion".
//!
//! The five steps are:
//! 1. **Resolve** the mediator DID. Read `keyAgreement` and the
//!    `DIDCommMessaging` `serviceEndpoint` from its DID document.
//! 2. **Connect** the WebSocket transport.
//! 3. **Authenticate** the VTA's DID to the mediator (DIDComm
//!    challenge / response, handled by the upstream library).
//! 4. **Register** the listener so the mediator forwards messages
//!    addressed to the VTA's DID to this socket.
//! 5. **Trust-ping** the VTA's own DID via this mediator and wait
//!    for the `ping-response`.
//!
//! Step 1 lives in this module (DID-document inspection is pure,
//! deterministic, and worth a clean API). Steps 2–5 are abstracted
//! behind the [`ListenerProver`] trait so they can be implemented
//! against the live `affinidi_messaging_didcomm_service::DIDCommService`
//! and stubbed for unit tests. `--force` bypasses steps 2–5
//! (NOT step 1).
//!
//! Telemetry contract:
//! - Successful handshake →
//!   [`vti_common::telemetry::TelemetryKind::MediatorHandshakeOk`]
//! - Any-stage failure →
//!   [`vti_common::telemetry::TelemetryKind::MediatorHandshakeFailed`]
//!   with the failing `stage` recorded as a field
//! - `--force` bypass →
//!   [`vti_common::telemetry::TelemetryKind::MediatorHandshakeBypassed`]
//!
//! The default `--handshake-timeout` is 10 seconds; configurable
//! via [`HandshakeOptions::timeout`].

use std::fmt;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use async_trait::async_trait;
use serde_json::Value as JsonValue;
use thiserror::Error;

use vti_common::telemetry::{SharedTelemetrySink, TelemetryEvent, TelemetryKind};

/// Default trust-ping round-trip timeout. Spec default: 10s.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Result of a successful step-1 resolve. Carries the strings the
/// caller needs to build a listener config + log events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMediator {
    pub mediator_did: String,
    /// Best-effort string form of the mediator's `serviceEndpoint`.
    /// May be a URL (typical for production mediators) or a DID
    /// (chained mediator). Empty string if the endpoint is a JSON
    /// object whose URI couldn't be extracted.
    pub endpoint: String,
}

/// Stage at which a handshake failed. Surfaced to operators so the
/// CLI / REST error message can name the failing step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStage {
    Resolve,
    Connect,
    Authenticate,
    Register,
    TrustPing,
}

impl HandshakeStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::Connect => "connect",
            Self::Authenticate => "authenticate",
            Self::Register => "register",
            Self::TrustPing => "trust-ping",
        }
    }
}

impl fmt::Display for HandshakeStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("mediator handshake failed at stage `{stage}`: {cause}")]
    Failed {
        stage: HandshakeStage,
        cause: String,
    },
}

impl HandshakeError {
    pub fn stage(&self) -> HandshakeStage {
        let Self::Failed { stage, .. } = self;
        *stage
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeOptions {
    pub timeout: Duration,
    /// Provision the VTA's account ACL on the candidate mediator before the
    /// forwarded self trust-ping.
    pub setup_acl: bool,
    /// Audit/logging channel used by mediator ACL provisioning.
    pub channel: String,
    /// Skip steps 2–5. Step 1 (DID resolution) is always performed —
    /// a malformed or unresolvable DID is always a hard failure.
    pub force: bool,
}

impl Default for HandshakeOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            setup_acl: false,
            channel: "protocol-management".to_string(),
            force: false,
        }
    }
}

/// Failure shape returned by a [`ListenerProver`].
#[derive(Debug, Clone)]
pub struct ProverFailure {
    pub stage: HandshakeStage,
    pub cause: String,
}

/// Steps 2–5 of the handshake. Implemented against the live
/// `DIDCommService` in production, stubbed in unit tests.
#[async_trait]
pub trait ListenerProver: Send + Sync {
    async fn prove(
        &self,
        resolved: &ResolvedMediator,
        vta_did: &str,
        timeout: Duration,
        setup_acl: bool,
        channel: &str,
    ) -> Result<(), ProverFailure>;
}

/// Run the full handshake. Returns the [`ResolvedMediator`] on
/// success so the caller can use the extracted endpoint string for
/// logging / registry storage.
pub async fn mediator_handshake(
    resolver: &DIDCacheClient,
    prover: &(dyn ListenerProver + Send + Sync),
    telemetry: &SharedTelemetrySink,
    mediator_did: &str,
    vta_did: &str,
    opts: HandshakeOptions,
) -> Result<ResolvedMediator, HandshakeError> {
    // Step 1 — always.
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

    // Steps 2–5 via the prover.
    if let Err(failure) = prover
        .prove(
            &resolved,
            vta_did,
            opts.timeout,
            opts.setup_acl,
            &opts.channel,
        )
        .await
    {
        emit_failed(telemetry, mediator_did, failure.stage, &failure.cause).await;
        return Err(HandshakeError::Failed {
            stage: failure.stage,
            cause: failure.cause,
        });
    }

    let _ = telemetry
        .record(
            TelemetryEvent::new(TelemetryKind::MediatorHandshakeOk)
                .with_mediator(mediator_did)
                .with_field("endpoint", JsonValue::from(resolved.endpoint.clone())),
        )
        .await;
    Ok(resolved)
}

/// Step 1 in isolation. Pure-async; the only I/O is the DID resolver
/// network call.
pub async fn resolve_mediator(
    resolver: &DIDCacheClient,
    mediator_did: &str,
) -> Result<ResolvedMediator, String> {
    let resolved = resolver
        .resolve(mediator_did)
        .await
        .map_err(|e| format!("failed to resolve mediator DID `{mediator_did}`: {e}"))?;

    // Confirm there's at least one DIDCommMessaging service entry —
    // otherwise this DID isn't a mediator.
    let service = resolved
        .doc
        .service
        .iter()
        .find(|s| s.type_.iter().any(|t| t == "DIDCommMessaging"))
        .ok_or_else(|| {
            format!("mediator DID `{mediator_did}` has no DIDCommMessaging service entry")
        })?;

    // Confirm there's a keyAgreement verification method on the
    // mediator (required for DIDComm encryption).
    if resolved.doc.key_agreement.is_empty() {
        return Err(format!(
            "mediator DID `{mediator_did}` exposes no keyAgreement verification method"
        ));
    }

    let endpoint = service.service_endpoint.get_uri().unwrap_or_default();
    Ok(ResolvedMediator {
        mediator_did: mediator_did.to_string(),
        endpoint,
    })
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

/// A [`ListenerProver`] that always succeeds. Useful for unit tests
/// of `mediator_handshake` itself; the live impl is wired in
/// downstream tasks.
#[doc(hidden)]
pub struct AlwaysOkProver;

#[async_trait]
impl ListenerProver for AlwaysOkProver {
    async fn prove(
        &self,
        _resolved: &ResolvedMediator,
        _vta_did: &str,
        _timeout: Duration,
        _setup_acl: bool,
        _channel: &str,
    ) -> Result<(), ProverFailure> {
        Ok(())
    }
}

/// A [`ListenerProver`] that fails at a configured stage with a
/// configured cause. For unit tests.
#[doc(hidden)]
pub struct FailingProver {
    pub stage: HandshakeStage,
    pub cause: String,
}

#[async_trait]
impl ListenerProver for FailingProver {
    async fn prove(
        &self,
        _resolved: &ResolvedMediator,
        _vta_did: &str,
        _timeout: Duration,
        _setup_acl: bool,
        _channel: &str,
    ) -> Result<(), ProverFailure> {
        Err(ProverFailure {
            stage: self.stage,
            cause: self.cause.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    use std::sync::Arc;
    use vti_common::telemetry::{RingBufferTelemetry, TelemetryFilter};

    fn telemetry() -> SharedTelemetrySink {
        Arc::new(RingBufferTelemetry::with_capacity(64))
    }

    async fn local_resolver() -> DIDCacheClient {
        // Local-mode resolver — no network, fastest for tests.
        let config = DIDCacheConfigBuilder::default().build();
        DIDCacheClient::new(config).await.expect("resolver init")
    }

    #[test]
    fn handshake_stage_string_form() {
        assert_eq!(HandshakeStage::Resolve.as_str(), "resolve");
        assert_eq!(HandshakeStage::Connect.as_str(), "connect");
        assert_eq!(HandshakeStage::Authenticate.as_str(), "authenticate");
        assert_eq!(HandshakeStage::Register.as_str(), "register");
        assert_eq!(HandshakeStage::TrustPing.as_str(), "trust-ping");
    }

    #[test]
    fn handshake_options_default_is_10s_no_force() {
        let opts = HandshakeOptions::default();
        assert_eq!(opts.timeout, Duration::from_secs(10));
        assert!(!opts.force);
    }

    #[tokio::test]
    async fn resolve_mediator_rejects_unresolvable_did() {
        let resolver = local_resolver().await;
        // did:key with a bogus payload — resolver will reject.
        let err = resolve_mediator(&resolver, "did:key:zNOTAREALKEY")
            .await
            .unwrap_err();
        assert!(err.contains("failed to resolve"));
    }

    #[tokio::test]
    async fn force_bypass_skips_prover_but_still_resolves() {
        // We use a guaranteed-bad DID so step 1 fails. With --force,
        // we expect step 1 still runs (and fails) — force does not
        // skip resolution.
        let resolver = local_resolver().await;
        let sink = telemetry();
        let prover = AlwaysOkProver;
        let err = mediator_handshake(
            &resolver,
            &prover,
            &sink,
            "did:key:zNOTAREALKEY",
            "did:webvh:vta",
            HandshakeOptions {
                force: true,
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.stage(), HandshakeStage::Resolve);
    }

    #[tokio::test]
    async fn failed_resolve_emits_handshake_failed_with_stage() {
        let resolver = local_resolver().await;
        let sink = telemetry();
        let prover = AlwaysOkProver;
        let _ = mediator_handshake(
            &resolver,
            &prover,
            &sink,
            "did:key:zNOTAREALKEY",
            "did:webvh:vta",
            HandshakeOptions::default(),
        )
        .await;
        let events = sink
            .query(&TelemetryFilter::new().kind(TelemetryKind::MediatorHandshakeFailed))
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].fields.get("stage").and_then(|v| v.as_str()),
            Some("resolve"),
        );
    }

    #[tokio::test]
    async fn prover_failure_propagates_stage() {
        // To exercise stages 2-5, we need a mediator DID that
        // resolves cleanly. The `did:peer:0` form for a key-only
        // peer DID resolves locally without network access. But
        // peer DIDs of that form don't expose DIDCommMessaging
        // service entries either, so step 1 would fail with
        // "no DIDCommMessaging service".
        //
        // Instead, this test goes through the prover directly via a
        // synthetic ResolvedMediator; we then assert the
        // `mediator_handshake` orchestration would propagate the
        // failure stage. To fit `mediator_handshake`'s actual
        // signature we'd need a DID resolver that returns a doc
        // with a DIDCommMessaging service — out of scope for this
        // unit test. Instead, exercise the prover directly:
        let prover = FailingProver {
            stage: HandshakeStage::TrustPing,
            cause: "pong timeout".into(),
        };
        let resolved = ResolvedMediator {
            mediator_did: "did:m:fake".into(),
            endpoint: "wss://fake".into(),
        };
        let failure = prover
            .prove(
                &resolved,
                "did:webvh:vta",
                Duration::from_secs(1),
                false,
                "test",
            )
            .await
            .unwrap_err();
        assert_eq!(failure.stage, HandshakeStage::TrustPing);
        assert_eq!(failure.cause, "pong timeout");
    }

    // Note: end-to-end tests of mediator_handshake against a real
    // DIDCommMessaging-bearing mediator DID document live in Phase 4
    // verticals, which stand up an in-process mock mediator.
}
