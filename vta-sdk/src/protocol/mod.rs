//! Client surface for DIDComm protocol management.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`.
//!
//! Phase 3 lands `enable_didcomm` (REST-only by nature — DIDComm is
//! not yet running at first-enable time). The disable / migrate /
//! drain-cancel / report calls — and their DIDComm transport
//! handlers — arrive in Phase 4 verticals.
//!
//! Runtime REST service-management wire types (the symmetric
//! REST-side of the spec §4 surface — `EnableRestRequest`,
//! `UpdateRestRequest`, `DisableRestRequest`, `RollbackRestRequest`,
//! `ServiceMutationResponse`) live in [`services`].

pub mod matching;
pub mod services;

use serde::{Deserialize, Serialize};

#[cfg(feature = "client")]
use crate::client::VtaClient;
#[cfg(feature = "client")]
use crate::error::VtaError;
#[cfg(feature = "client")]
use crate::protocols::protocol_management;

/// Request body for `POST /services/didcomm/enable`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct EnableDidcommRequest {
    pub mediator_did: String,
    /// Skip handshake steps 2-5 (DID resolution always runs).
    /// Emits a `MediatorHandshakeBypassed` telemetry event when set.
    #[serde(default)]
    pub force: bool,
    /// Trust-ping round-trip timeout (default: 10 seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_timeout_secs: Option<u64>,
}

impl EnableDidcommRequest {
    pub fn new(mediator_did: impl Into<String>) -> Self {
        Self {
            mediator_did: mediator_did.into(),
            force: false,
            handshake_timeout_secs: None,
        }
    }

    pub fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub fn handshake_timeout_secs(mut self, secs: u64) -> Self {
        self.handshake_timeout_secs = Some(secs);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnableDidcommResponse {
    pub new_version_id: String,
    pub mediator_did: String,
    pub mediator_endpoint: String,
    /// The VTA's own DID — subject of the LogEntry this enable
    /// wrote. Carried so the CLI can print follow-up commands like
    /// `pnm webvh did-log <vta_did>` for serverless deployments.
    /// `#[serde(default)]` + elide-when-empty keeps the wire form
    /// back-compat with older servers.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted (`server_id =
    /// "serverless"`). The new LogEntry is local only — operators
    /// must fetch the updated `did.jsonl` and redeploy.
    /// `#[serde(default)]` for back-compat.
    #[serde(default)]
    pub serverless: bool,
}

/// Response body for `GET /services/didcomm`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DidcommStatusResponse {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mediator_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub websocket_status: Option<String>,
}

/// Body returned by the server on `409 Conflict` from
/// `POST /services/didcomm/enable` when DIDComm is already active.
#[derive(Debug, Clone, Deserialize)]
pub struct EnableDidcommConflictBody {
    pub error: String,
    #[serde(default)]
    pub mediator_did: Option<String>,
}

/// Request body for `POST /services/didcomm/disable`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisableDidcommRequest {
    /// Drain TTL in seconds. 0 = immediate teardown (REST only;
    /// over DIDComm transport, minimum 1h is enforced server-side).
    pub drain_ttl_secs: u64,
}

impl DisableDidcommRequest {
    pub fn new(drain_ttl_secs: u64) -> Self {
        Self { drain_ttl_secs }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisableDidcommResponse {
    pub new_version_id: String,
    pub prior_mediator_did: String,
    /// `Some(rfc3339)` when the listener entered drain state;
    /// `None` when it was torn down immediately.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drains_until: Option<String>,
    /// The VTA's own DID. See [`EnableDidcommResponse::vta_did`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted. See
    /// [`EnableDidcommResponse::serverless`].
    #[serde(default)]
    pub serverless: bool,
}

#[cfg(feature = "client")]
impl VtaClient {
    /// Enable DIDComm on a REST-only VTA. Spec: success criterion #1.
    ///
    /// The VTA must be configured with a vta_did, must currently
    /// have `services.didcomm = false`, and the caller must have
    /// super-admin role. On success, the VTA publishes a new WebVH
    /// LogEntry advertising the mediator and registers it as
    /// active.
    ///
    /// **First-enable handshake:** the route runs a transient
    /// `DIDCommService` round-trip against the candidate mediator
    /// before publishing — see
    /// `vta_service::messaging::transient_handshake`. The operation
    /// itself uses [`AlwaysOkProver`] because the steady-state
    /// `DIDCommService` doesn't exist yet at first-enable. The
    /// live-prover path through `update_didcomm` covers the
    /// steady-state case.
    pub async fn enable_didcomm(
        &self,
        req: EnableDidcommRequest,
    ) -> Result<EnableDidcommResponse, VtaError> {
        match &self.transport {
            crate::client::Transport::Rest {
                client,
                base_url,
                auth,
            } => {
                Self::ensure_token_valid(client, base_url, auth).await?;
                let token = auth.lock().await.token.clone();
                let req = client
                    .post(format!("{base_url}/services/didcomm/enable"))
                    .json(&req);
                let resp = Self::with_auth_token(req, &token).send().await?;
                Self::handle_response(resp).await
            }
            #[cfg(feature = "session")]
            crate::client::Transport::DIDComm { .. } => Err(VtaError::UnsupportedTransport(
                "enable_didcomm is REST-only".into(),
            )),
        }
    }

    /// Read the current DIDComm runtime status. Auth: super-admin (parity with
    /// `GET /services` / `list_services`, which exposes the same `mediator_did`).
    pub async fn didcomm_status(&self) -> Result<DidcommStatusResponse, VtaError> {
        match &self.transport {
            crate::client::Transport::Rest {
                client,
                base_url,
                auth,
            } => {
                crate::client::VtaClient::ensure_token_valid(client, base_url, auth).await?;
                let token = auth.lock().await.token.clone();
                let req = client.get(format!("{base_url}/services/didcomm"));
                let resp = crate::client::VtaClient::with_auth_token(req, &token)
                    .send()
                    .await?;
                crate::client::VtaClient::handle_response(resp).await
            }
            #[cfg(feature = "session")]
            crate::client::Transport::DIDComm { .. } => Err(VtaError::UnsupportedTransport(
                "didcomm status is REST-only in the SDK".into(),
            )),
        }
    }

    /// Disable DIDComm. Refuses if REST is also disabled
    /// (`NoProtocolRemaining`). Drain TTL semantics:
    /// - `0` = immediate teardown (REST transport only).
    /// - `>= 3600` = drain window over DIDComm transport (server
    ///   enforces 1h minimum).
    pub async fn disable_didcomm(
        &self,
        req: DisableDidcommRequest,
    ) -> Result<DisableDidcommResponse, VtaError> {
        self.rpc(
            protocol_management::DISABLE_DIDCOMM,
            serde_json::to_value(&req)?,
            protocol_management::DISABLE_DIDCOMM_RESULT,
            30,
            |c, url| c.post(format!("{url}/services/didcomm/disable")).json(&req),
        )
        .await
    }

    /// Update which DIDComm mediator the VTA's `#vta-didcomm`
    /// service entry advertises. Runs the pre-promotion handshake
    /// against the new mediator and places the prior mediator in
    /// drain state for the requested TTL.
    ///
    /// (T2.3 rename — was `migrate_mediator`. Operation is the
    /// same; the naming aligns with the unified `services
    /// {kind} {verb}` surface.)
    pub async fn update_didcomm(
        &self,
        req: UpdateDidcommRequest,
    ) -> Result<UpdateDidcommResponse, VtaError> {
        self.rpc(
            protocol_management::UPDATE_DIDCOMM,
            serde_json::to_value(&req)?,
            protocol_management::UPDATE_DIDCOMM_RESULT,
            120,
            |c, url| c.post(format!("{url}/services/didcomm/update")).json(&req),
        )
        .await
    }

    // ── REST service-management client methods (P1 wire types,
    //    P5 client surface) ──────────────────────────────────────────

    /// Enable REST advertisement on the VTA's DID document by
    /// publishing a `#vta-rest` service entry. Spec §3.4.
    pub async fn enable_rest(
        &self,
        req: services::EnableRestRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        self.rpc(
            protocol_management::ENABLE_REST,
            serde_json::to_value(&req)?,
            protocol_management::ENABLE_REST_RESULT,
            30,
            |c, url| c.post(format!("{url}/services/rest/enable")).json(&req),
        )
        .await
    }

    /// Update the URL on the existing `#vta-rest` service entry.
    pub async fn update_rest(
        &self,
        req: services::UpdateRestRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        self.rpc(
            protocol_management::UPDATE_REST,
            serde_json::to_value(&req)?,
            protocol_management::UPDATE_REST_RESULT,
            30,
            |c, url| c.post(format!("{url}/services/rest/update")).json(&req),
        )
        .await
    }

    /// Remove the `#vta-rest` entry from the VTA's DID document.
    /// Refused with `LastServiceRefused` when DIDComm is also off.
    pub async fn disable_rest(
        &self,
        req: services::DisableRestRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        self.rpc(
            protocol_management::DISABLE_REST,
            serde_json::to_value(&req)?,
            protocol_management::DISABLE_REST_RESULT,
            30,
            |c, url| c.post(format!("{url}/services/rest/disable")).json(&req),
        )
        .await
    }

    // ── Fail-forward rollback client methods (P3 server, P5
    //    client surface) ──────────────────────────────────────────

    /// Fail-forward the most recent REST mutation by re-applying
    /// the snapshotted prior state. Spec §3.5a.
    pub async fn rollback_rest(
        &self,
        req: services::RollbackRestRequest,
    ) -> Result<services::RollbackResponse, VtaError> {
        self.rpc(
            protocol_management::ROLLBACK_REST,
            serde_json::to_value(&req)?,
            protocol_management::ROLLBACK_REST_RESULT,
            60,
            |c, url| c.post(format!("{url}/services/rest/rollback")).json(&req),
        )
        .await
    }

    // ── TSP service-management client methods ──────────────────────
    //
    // TSP advertises a **mediator DID** (the VTA's TSP VID), not a
    // URL — so these mirror the REST methods exactly except for the
    // request types carrying `mediator_did` and the `/services/tsp/…`
    // paths. All four go through `self.rpc(…)` (reachable over both
    // REST and DIDComm); `enable_tsp` is NOT REST-only the way
    // `enable_didcomm` is.

    /// Enable TSP advertisement on the VTA's DID document by
    /// publishing a `#tsp` service entry pointing at the mediator
    /// DID. Spec §3.4.
    pub async fn enable_tsp(
        &self,
        req: services::EnableTspRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        self.rpc(
            protocol_management::ENABLE_TSP,
            serde_json::to_value(&req)?,
            protocol_management::ENABLE_TSP_RESULT,
            30,
            |c, url| c.post(format!("{url}/services/tsp/enable")).json(&req),
        )
        .await
    }

    /// Update the mediator DID on the existing `#tsp` service entry.
    pub async fn update_tsp(
        &self,
        req: services::UpdateTspRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        self.rpc(
            protocol_management::UPDATE_TSP,
            serde_json::to_value(&req)?,
            protocol_management::UPDATE_TSP_RESULT,
            30,
            |c, url| c.post(format!("{url}/services/tsp/update")).json(&req),
        )
        .await
    }

    /// Remove the `#tsp` entry from the VTA's DID document.
    /// Refused with `LastServiceRefused` when TSP is the only
    /// advertised transport.
    pub async fn disable_tsp(
        &self,
        req: services::DisableTspRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        self.rpc(
            protocol_management::DISABLE_TSP,
            serde_json::to_value(&req)?,
            protocol_management::DISABLE_TSP_RESULT,
            30,
            |c, url| c.post(format!("{url}/services/tsp/disable")).json(&req),
        )
        .await
    }

    /// Fail-forward the most recent TSP mutation by re-applying the
    /// snapshotted prior state. Spec §3.5a.
    pub async fn rollback_tsp(
        &self,
        req: services::RollbackTspRequest,
    ) -> Result<services::RollbackResponse, VtaError> {
        self.rpc(
            protocol_management::ROLLBACK_TSP,
            serde_json::to_value(&req)?,
            protocol_management::ROLLBACK_TSP_RESULT,
            60,
            |c, url| c.post(format!("{url}/services/tsp/rollback")).json(&req),
        )
        .await
    }

    // ── WebAuthn service-management client methods ─────────────────

    /// Enable WebAuthn-RP advertisement on the VTA's DID document by
    /// publishing a `#vta-webauthn` service entry.
    pub async fn enable_webauthn(
        &self,
        req: services::EnableWebauthnRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        self.rpc(
            protocol_management::ENABLE_WEBAUTHN,
            serde_json::to_value(&req)?,
            protocol_management::ENABLE_WEBAUTHN_RESULT,
            30,
            |c, url| c.post(format!("{url}/services/webauthn/enable")).json(&req),
        )
        .await
    }

    /// Update the URL on the existing `#vta-webauthn` entry.
    pub async fn update_webauthn(
        &self,
        req: services::UpdateWebauthnRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        self.rpc(
            protocol_management::UPDATE_WEBAUTHN,
            serde_json::to_value(&req)?,
            protocol_management::UPDATE_WEBAUTHN_RESULT,
            30,
            |c, url| c.post(format!("{url}/services/webauthn/update")).json(&req),
        )
        .await
    }

    /// Remove the `#vta-webauthn` entry AND strip passkey VMs from
    /// every DID this VTA controls (hard-disable semantics).
    /// Refused with `LastServiceRefused` when removing WebAuthn
    /// would leave no transport advertised.
    pub async fn disable_webauthn(
        &self,
        req: services::DisableWebauthnRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        // Longer timeout than REST/DIDComm disable because the
        // passkey-VM cleanup iterates every DID this VTA controls
        // and publishes a WebVH update per affected DID.
        self.rpc(
            protocol_management::DISABLE_WEBAUTHN,
            serde_json::to_value(&req)?,
            protocol_management::DISABLE_WEBAUTHN_RESULT,
            300,
            |c, url| {
                c.post(format!("{url}/services/webauthn/disable"))
                    .json(&req)
            },
        )
        .await
    }

    /// Fail-forward the most recent WebAuthn mutation by re-applying
    /// the snapshotted prior state.
    pub async fn rollback_webauthn(
        &self,
        req: services::RollbackWebauthnRequest,
    ) -> Result<services::RollbackResponse, VtaError> {
        self.rpc(
            protocol_management::ROLLBACK_WEBAUTHN,
            serde_json::to_value(&req)?,
            protocol_management::ROLLBACK_WEBAUTHN_RESULT,
            300,
            |c, url| {
                c.post(format!("{url}/services/webauthn/rollback"))
                    .json(&req)
            },
        )
        .await
    }

    /// Fail-forward the most recent DIDComm mutation. Threads
    /// `drain_ttl_secs` through to the dispatched forward op for
    /// the disable / update arms.
    pub async fn rollback_didcomm(
        &self,
        req: services::RollbackDidcommRequest,
    ) -> Result<services::RollbackResponse, VtaError> {
        self.rpc(
            protocol_management::ROLLBACK_DIDCOMM,
            serde_json::to_value(&req)?,
            protocol_management::ROLLBACK_DIDCOMM_RESULT,
            120,
            |c, url| {
                c.post(format!("{url}/services/didcomm/rollback"))
                    .json(&req)
            },
        )
        .await
    }

    // ── Read-only inspection (P4 server, P5 client surface) ──────

    /// Inspect the VTA's currently-advertised transport services.
    /// Returns one entry per kind in canonical DIDComm-then-REST
    /// order.
    pub async fn list_services(&self) -> Result<services::ServicesListResponse, VtaError> {
        self.rpc(
            protocol_management::LIST_SERVICES,
            serde_json::Value::Null,
            protocol_management::LIST_SERVICES_RESULT,
            30,
            |c, url| c.get(format!("{url}/services")),
        )
        .await
    }

    /// List currently-draining mediators. Empty list is normal.
    pub async fn list_drain(&self) -> Result<services::DrainListResponse, VtaError> {
        self.rpc(
            protocol_management::LIST_DRAIN,
            serde_json::Value::Null,
            protocol_management::LIST_DRAIN_RESULT,
            30,
            |c, url| c.get(format!("{url}/services/didcomm/drain")),
        )
        .await
    }
}

/// Request body for `POST /services/didcomm/update`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct UpdateDidcommRequest {
    pub new_mediator_did: String,
    pub drain_ttl_secs: u64,
    #[serde(default)]
    pub force: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_timeout_secs: Option<u64>,
    /// Tag the operation as a rollback in telemetry.
    #[serde(default)]
    pub rollback: bool,
}

impl UpdateDidcommRequest {
    pub fn new(new_mediator_did: impl Into<String>, drain_ttl_secs: u64) -> Self {
        Self {
            new_mediator_did: new_mediator_did.into(),
            drain_ttl_secs,
            force: false,
            handshake_timeout_secs: None,
            rollback: false,
        }
    }

    pub fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub fn rollback(mut self, rollback: bool) -> Self {
        self.rollback = rollback;
        self
    }

    pub fn handshake_timeout_secs(mut self, secs: u64) -> Self {
        self.handshake_timeout_secs = Some(secs);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDidcommResponse {
    pub new_version_id: String,
    pub prior_mediator_did: String,
    pub active_mediator_did: String,
    pub active_mediator_endpoint: String,
    pub drains_until: String,
    /// The VTA's own DID. See [`EnableDidcommResponse::vta_did`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted. See
    /// [`EnableDidcommResponse::serverless`].
    #[serde(default)]
    pub serverless: bool,
}

/// Request body for `POST /mediators/drain/cancel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrainCancelRequest {
    pub mediator_did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrainCancelResponse {
    pub mediator_did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediatorStats {
    pub mediator_did: String,
    pub inbound_count: u64,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderLastSeen {
    pub sender_did: String,
    pub last_seen_mediator: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediatorReport {
    #[serde(default)]
    pub since: Option<String>,
    pub until: String,
    pub mediators: Vec<MediatorStats>,
    pub senders: Vec<SenderLastSeen>,
}

#[cfg(feature = "client")]
impl VtaClient {
    /// Cancel a drain entry early, dropping the listener for that
    /// mediator immediately. Refuses if the named DID is the
    /// active mediator (use `services disable didcomm` instead) or
    /// not registered at all.
    pub async fn drain_cancel(
        &self,
        req: DrainCancelRequest,
    ) -> Result<DrainCancelResponse, VtaError> {
        self.rpc(
            protocol_management::DRAIN_CANCEL,
            serde_json::to_value(&req)?,
            protocol_management::DRAIN_CANCEL_RESULT,
            30,
            |c, url| c.post(format!("{url}/mediators/drain/cancel")).json(&req),
        )
        .await
    }

    /// Query the mediator-attribution report. `since`/`until` are
    /// optional RFC 3339 timestamps. Returns per-mediator inbound
    /// counts and per-sender last-seen mediator (so operators can
    /// spot senders still using the prior mediator after a
    /// migrate).
    pub async fn mediator_report(
        &self,
        since: Option<&str>,
        until: Option<&str>,
    ) -> Result<MediatorReport, VtaError> {
        let since_owned = since.map(str::to_string);
        let until_owned = until.map(str::to_string);
        let qs = build_report_query(since_owned.as_deref(), until_owned.as_deref());
        self.rpc(
            protocol_management::MEDIATOR_REPORT,
            serde_json::json!({
                "since": since_owned,
                "until": until_owned,
            }),
            protocol_management::MEDIATOR_REPORT_RESULT,
            30,
            move |c, url| {
                let url = if qs.is_empty() {
                    format!("{url}/mediators/report")
                } else {
                    format!("{url}/mediators/report?{qs}")
                };
                c.get(url)
            },
        )
        .await
    }
}

#[cfg(feature = "client")]
fn build_report_query(since: Option<&str>, until: Option<&str>) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(s) = since {
        parts.push(format!("since={}", url_encode(s)));
    }
    if let Some(u) = until {
        parts.push(format!("until={}", url_encode(u)));
    }
    parts.join("&")
}

#[cfg(feature = "client")]
fn url_encode(s: &str) -> String {
    // RFC 3339 timestamps contain `:` and `+`; the latter is the
    // form-urlencoded representation of a space and would mangle
    // the timestamp on the server side. Encode the unsafe chars
    // explicitly.
    s.chars()
        .flat_map(|c| match c {
            ':' => "%3A".chars().collect::<Vec<_>>(),
            '+' => "%2B".chars().collect::<Vec<_>>(),
            _ => vec![c],
        })
        .collect()
}
