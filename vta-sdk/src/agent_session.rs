//! High-level personal-AI-agent runtime helper.
//!
//! `AgentSession` collapses the enroll → heartbeat → wake-loop → vault-access
//! boilerplate an agent runtime (open-claw / nano-claw / hermes) would otherwise
//! hand-wire, into a few calls on top of the DIDComm [`VtaClient`]:
//!
//! ```no_run
//! # async fn run() -> Result<(), vta_sdk::error::VtaError> {
//! # let (client_did, private_key_mb, vta_did, mediator_did) = ("", "", "", "");
//! use vta_sdk::agent_session::{AgentConfig, AgentSession, AgentControl};
//!
//! let cfg = AgentConfig::new(client_did, private_key_mb, vta_did, mediator_did)
//!     .display_name("nano-claw")
//!     .platform("linux");
//! let agent = AgentSession::enroll(cfg).await?;
//!
//! // Use the VTA directly when you need to (sign, vault, …):
//! let _keys = agent.client().list_keys(0, 50, None, None).await?;
//!
//! // Or run the event loop: heartbeat + handle inbound wake/step-up messages.
//! agent.run(|msg| async move {
//!     println!("inbound {}: {}", msg.typ, msg.body);
//!     AgentControl::Continue
//! }).await?;
//! # Ok(()) }
//! ```
//!
//! Requires the `session` feature (DIDComm transport — the agent receives wakes
//! via its mediator).

use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{debug, info, warn};

use crate::client::VtaClient;
use crate::error::VtaError;

/// How long each inbound-poll window waits before the loop checks the heartbeat
/// timer again. Bounded so a pending heartbeat can't be starved by a quiet
/// inbound stream.
const INBOUND_POLL_SECS: u64 = 20;

/// Default heartbeat cadence (seconds) when the caller doesn't set one.
const DEFAULT_HEARTBEAT_SECS: u64 = 300;

/// Connection + enrolment parameters for an [`AgentSession`].
///
/// Build with [`AgentConfig::new`] (fills sensible defaults) then chain the
/// `with`-style setters.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// The agent's own DID (its long-term key, already in the VTA's ACL).
    pub client_did: String,
    /// The agent's Ed25519 private key, multibase-encoded.
    pub private_key_multibase: String,
    /// The VTA's DID.
    pub vta_did: String,
    /// The mediator DID the agent receives through.
    pub mediator_did: String,
    /// Optional VTA REST URL (for the REST-fallback surfaces; DIDComm is primary).
    pub rest_url: Option<String>,
    /// Human-readable device/agent name.
    pub display_name: String,
    /// `consumerKind.serviceKind` for the device binding.
    pub service_kind: String,
    /// Platform string (e.g. `linux`, `macos`).
    pub platform: Option<String>,
    /// Optional HPKE public key (multibase) for sealed delivery.
    pub hpke_public_key: Option<String>,
    /// Heartbeat cadence in seconds.
    pub heartbeat_secs: u64,
}

impl AgentConfig {
    /// New config with defaults: `service_kind = "ai-agent"`,
    /// `display_name = "agent"`, `heartbeat_secs = 300`.
    pub fn new(
        client_did: impl Into<String>,
        private_key_multibase: impl Into<String>,
        vta_did: impl Into<String>,
        mediator_did: impl Into<String>,
    ) -> Self {
        Self {
            client_did: client_did.into(),
            private_key_multibase: private_key_multibase.into(),
            vta_did: vta_did.into(),
            mediator_did: mediator_did.into(),
            rest_url: None,
            display_name: "agent".to_string(),
            service_kind: "ai-agent".to_string(),
            platform: None,
            hpke_public_key: None,
            heartbeat_secs: DEFAULT_HEARTBEAT_SECS,
        }
    }

    /// Set the display name.
    pub fn display_name(mut self, v: impl Into<String>) -> Self {
        self.display_name = v.into();
        self
    }

    /// Override the Service kind (defaults to `ai-agent`).
    pub fn service_kind(mut self, v: impl Into<String>) -> Self {
        self.service_kind = v.into();
        self
    }

    /// Set the platform string.
    pub fn platform(mut self, v: impl Into<String>) -> Self {
        self.platform = Some(v.into());
        self
    }

    /// Set the REST URL.
    pub fn rest_url(mut self, v: impl Into<String>) -> Self {
        self.rest_url = Some(v.into());
        self
    }

    /// Set the HPKE public key (multibase).
    pub fn hpke_public_key(mut self, v: impl Into<String>) -> Self {
        self.hpke_public_key = Some(v.into());
        self
    }

    /// Set the heartbeat cadence (seconds). Clamped to ≥ 1.
    pub fn heartbeat_secs(mut self, secs: u64) -> Self {
        self.heartbeat_secs = secs.max(1);
        self
    }

    /// Config for wrapping an **already-connected** client via
    /// [`AgentSession::from_client`]. The connection fields (DID, key, mediator)
    /// are left empty — they're unused once a client exists; only the enrolment
    /// fields (`display_name`, `service_kind`, `platform`, `heartbeat_secs`)
    /// apply. Chain the setters to customise.
    pub fn for_attach(display_name: impl Into<String>) -> Self {
        Self::new("", "", "", "").display_name(display_name)
    }
}

/// Whether the agent event loop should keep running after a handler call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentControl {
    /// Keep running.
    Continue,
    /// Stop the loop and shut the session down cleanly.
    Stop,
}

/// A decoded inbound DIDComm message (a VTA-pushed wake, step-up request, …).
#[derive(Debug, Clone)]
pub struct InboundMessage {
    /// The message id.
    pub id: String,
    /// The message `type` URI (use this to route).
    pub typ: String,
    /// The authenticated sender DID, if present.
    pub from: Option<String>,
    /// The message body.
    pub body: Value,
}

impl InboundMessage {
    /// Parse the serialized DIDComm message JSON yielded by
    /// [`VtaClient::receive_next`]. Lenient: missing fields default rather than
    /// failing, so an unusual envelope still routes on whatever it carries.
    pub fn parse(json: &str) -> Result<Self, VtaError> {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default)]
            id: String,
            #[serde(rename = "type", default)]
            typ: String,
            #[serde(default)]
            from: Option<String>,
            #[serde(default)]
            body: Value,
        }
        let w: Wire = serde_json::from_str(json)?;
        Ok(Self {
            id: w.id,
            typ: w.typ,
            from: w.from,
            body: w.body,
        })
    }
}

/// A connected, enrolled personal-AI-agent session.
pub struct AgentSession {
    client: VtaClient,
    config: AgentConfig,
}

impl AgentSession {
    /// Connect over DIDComm and ensure the agent is enrolled as a device.
    ///
    /// Idempotent on enrolment: if the device is already registered the existing
    /// binding is reused (re-registration would otherwise conflict). On any
    /// other failure the half-open session is shut down before returning.
    pub async fn enroll(config: AgentConfig) -> Result<Self, VtaError> {
        let client = VtaClient::connect_didcomm(
            &config.client_did,
            &config.private_key_multibase,
            &config.vta_did,
            &config.mediator_did,
            config.rest_url.clone(),
        )
        .await?;

        let session = Self::from_client(client, config);
        if let Err(e) = session.ensure_enrolled().await {
            session.client.shutdown().await;
            return Err(e);
        }
        Ok(session)
    }

    /// Wrap an **already-connected** [`VtaClient`] (built however the caller
    /// likes — `connect_didcomm`, a stored session, a bearer token) as an agent
    /// session, without enrolling. Use this when the connection is established
    /// elsewhere (e.g. a bridge that reuses an operator login) and you only want
    /// the unified `client()` accessor + optional [`Self::ensure_enrolled`] /
    /// [`Self::run`]. Pair with [`AgentConfig::for_attach`].
    pub fn from_client(client: VtaClient, config: AgentConfig) -> Self {
        Self { client, config }
    }

    /// Register this identity as a device, idempotently (an already-registered
    /// device reuses its binding). Safe to call once at startup; do **not** call
    /// it concurrently with in-flight RPCs on a DIDComm session.
    pub async fn ensure_enrolled(&self) -> Result<(), VtaError> {
        let consumer_kind = json!({ "kind": "service", "serviceKind": self.config.service_kind });
        match self
            .client
            .device_register(
                consumer_kind,
                &self.config.display_name,
                self.config.platform.as_deref(),
                self.config.hpke_public_key.as_deref(),
            )
            .await
        {
            Ok(_) => info!(name = %self.config.display_name, "agent device registered"),
            Err(e) if is_already_registered(&e) => {
                debug!(name = %self.config.display_name, "agent already registered; reusing binding");
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// The underlying authenticated client — use it for vault, signing, and any
    /// other VTA operation the agent needs.
    pub fn client(&self) -> &VtaClient {
        &self.client
    }

    /// Run the agent event loop until `handler` returns [`AgentControl::Stop`] or
    /// the inbound stream errors: heartbeats on the configured cadence and
    /// dispatches each inbound DIDComm message to `handler`. Always shuts the
    /// session down before returning.
    ///
    /// Heartbeat failures are logged and retried on the next tick (transient
    /// mediator hiccups shouldn't kill the loop); an inbound-stream error is
    /// terminal.
    pub async fn run<H, Fut>(&self, mut handler: H) -> Result<(), VtaError>
    where
        H: FnMut(InboundMessage) -> Fut,
        Fut: std::future::Future<Output = AgentControl>,
    {
        let mut ticker = tokio::time::interval(Duration::from_secs(self.config.heartbeat_secs));
        // The first tick fires immediately; consume it so we don't heartbeat
        // before the loop has even polled for inbound work.
        ticker.tick().await;

        let result = loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.client.device_heartbeat(self.config.platform.as_deref()).await {
                        warn!(error = %e, "agent heartbeat failed; retrying next tick");
                    }
                }
                inbound = self.client.receive_next(INBOUND_POLL_SECS) => {
                    match inbound {
                        Ok(Some(json)) => match InboundMessage::parse(&json) {
                            Ok(msg) => {
                                if handler(msg).await == AgentControl::Stop {
                                    break Ok(());
                                }
                            }
                            Err(e) => warn!(error = %e, "dropping unparseable inbound message"),
                        },
                        Ok(None) => {} // poll window elapsed with nothing — loop
                        Err(e) => break Err(e),
                    }
                }
            }
        };

        self.client.shutdown().await;
        result
    }

    /// Shut the DIDComm session down cleanly. Call this if you used the session
    /// without [`Self::run`] (which shuts down on its own).
    pub async fn shutdown(&self) {
        self.client.shutdown().await;
    }
}

/// Treat a `device/register` conflict as "already enrolled". The reject surfaces
/// differently per transport (a `Conflict` over REST, a `Protocol` reject
/// carrying `already_registered` over DIDComm), so match on both.
fn is_already_registered(e: &VtaError) -> bool {
    matches!(e, VtaError::Conflict(_)) || e.to_string().contains("already_registered")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_then_builders() {
        let cfg = AgentConfig::new("did:key:zA", "zKey", "did:key:zVta", "did:key:zMed")
            .display_name("nano-claw")
            .platform("linux")
            .heartbeat_secs(0); // clamps to 1
        assert_eq!(cfg.service_kind, "ai-agent");
        assert_eq!(cfg.display_name, "nano-claw");
        assert_eq!(cfg.platform.as_deref(), Some("linux"));
        assert_eq!(cfg.heartbeat_secs, 1, "heartbeat clamps to >= 1");
    }

    #[test]
    fn inbound_message_parses_didcomm_envelope() {
        let json = r#"{
            "id": "urn:uuid:abc",
            "type": "https://trusttasks.org/spec/push/wake/0.1",
            "from": "did:key:zVta",
            "body": { "reason": "work-available" }
        }"#;
        let msg = InboundMessage::parse(json).unwrap();
        assert_eq!(msg.id, "urn:uuid:abc");
        assert_eq!(msg.typ, "https://trusttasks.org/spec/push/wake/0.1");
        assert_eq!(msg.from.as_deref(), Some("did:key:zVta"));
        assert_eq!(msg.body["reason"], "work-available");
    }

    #[test]
    fn inbound_message_is_lenient_about_missing_fields() {
        // A sparse envelope still parses; absent fields default.
        let msg = InboundMessage::parse(r#"{"type":"x/1.0"}"#).unwrap();
        assert_eq!(msg.typ, "x/1.0");
        assert!(msg.id.is_empty());
        assert!(msg.from.is_none());
        assert!(msg.body.is_null());
    }

    #[test]
    fn from_client_wraps_without_enrolling() {
        // `from_client` is pure wiring — no network — so a REST client built
        // offline is enough to exercise it.
        let client = VtaClient::new("http://localhost:9999");
        let session = AgentSession::from_client(
            client,
            AgentConfig::for_attach("vta-mcp").service_kind("ai-agent"),
        );
        assert_eq!(session.config.display_name, "vta-mcp");
        assert_eq!(session.config.service_kind, "ai-agent");
        // The unified accessor is available for callers that only need the client.
        let _ = session.client();
    }

    #[test]
    fn already_registered_is_detected_across_transports() {
        assert!(is_already_registered(&VtaError::Conflict("dup".into())));
        assert!(is_already_registered(&VtaError::Protocol(
            "trust task rejected: device/register:already_registered — ...".into()
        )));
        assert!(!is_already_registered(&VtaError::Protocol(
            "something else".into()
        )));
    }
}
