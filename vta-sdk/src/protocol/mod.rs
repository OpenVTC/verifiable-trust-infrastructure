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
mod via_trust_tasks {
    //! The `vta/services/*` Trust Tasks behind the typed SDK methods.
    //!
    //! Every method here used to be a bespoke REST route (`/services/…`,
    //! `/mediators/…`) reached through `rpc`, whose DIDComm and TSP arms
    //! answered `UnsupportedTransport` — so `pnm services …` worked only over
    //! REST. They go through `rpc_tt` now: one signed Trust Task, over whichever
    //! transport the client holds. The methods keep their signatures and return
    //! types; this module builds the spec payload and maps the generated
    //! response back to them.

    use chrono::{DateTime, SecondsFormat, Utc};
    use serde_json::{Value, json};
    use trust_tasks_rs::specs::vta::services as spec;

    use super::services::{
        DrainEntry, DrainListResponse, RollbackResponse, ServiceMutationResponse, ServiceState,
        ServicesListResponse,
    };
    use super::{MediatorReport, MediatorStats, SenderLastSeen};
    use crate::client::VtaClient;
    use crate::error::VtaError;
    use crate::trust_tasks as uri;

    pub(super) fn ts(t: DateTime<Utc>) -> String {
        t.to_rfc3339_opts(SecondsFormat::Secs, true)
    }

    /// The service kind as the registry spells it.
    #[derive(Clone, Copy)]
    pub(super) enum Kind {
        Rest,
        Didcomm,
        Tsp,
        Webauthn,
    }

    impl Kind {
        fn wire(self) -> &'static str {
            match self {
                Kind::Rest => "rest",
                Kind::Didcomm => "didcomm",
                Kind::Tsp => "tsp",
                Kind::Webauthn => "webauthn",
            }
        }
    }

    /// The members of a `config` object: exactly the ones the named service
    /// takes, since the spec refuses a member that does not apply.
    pub(super) enum Config {
        Url(String),
        Mediator {
            mediator_did: String,
            force: Option<bool>,
            handshake_timeout_secs: Option<u64>,
        },
    }

    impl Config {
        fn to_json(&self) -> Value {
            match self {
                Config::Url(url) => json!({ "url": url }),
                Config::Mediator {
                    mediator_did,
                    force,
                    handshake_timeout_secs,
                } => {
                    let mut c = json!({ "mediatorDid": mediator_did });
                    if let Some(f) = force {
                        c["force"] = json!(f);
                    }
                    if let Some(t) = handshake_timeout_secs {
                        c["handshakeTimeoutSecs"] = json!(t);
                    }
                    c
                }
            }
        }
    }

    /// A mutation's result, in the shape every verb shares.
    pub(super) struct Mutation {
        pub log_entry_version_id: String,
        pub effective_at: String,
        pub drain_until: Option<String>,
        pub draining_mediator: Option<String>,
        pub vta_did: String,
        pub serverless: bool,
    }

    impl From<spec::enable::v1_0::ServiceMutationResult> for Mutation {
        fn from(r: spec::enable::v1_0::ServiceMutationResult) -> Self {
            Self {
                log_entry_version_id: r.log_entry_version_id.to_string(),
                effective_at: ts(r.effective_at),
                drain_until: r.drain_until.map(ts),
                draining_mediator: r.draining_mediator,
                vta_did: r.vta_did.unwrap_or_default(),
                serverless: r.serverless,
            }
        }
    }

    impl From<Mutation> for ServiceMutationResponse {
        fn from(m: Mutation) -> Self {
            Self {
                log_entry_version_id: m.log_entry_version_id,
                effective_at: m.effective_at,
                drain_until: m.drain_until,
                vta_did: m.vta_did,
                serverless: m.serverless,
            }
        }
    }

    // `enable`, `update` and `disable` each have their own generated
    // `ServiceMutationResult`, identical in shape; the response is decoded as
    // `enable`'s, which the JSON of all three satisfies by construction.
    type MutationResponse = spec::enable::v1_0::Response;

    impl VtaClient {
        pub(super) async fn services_enable(
            &self,
            kind: Kind,
            config: Config,
            timeout: u64,
        ) -> Result<Mutation, VtaError> {
            let payload = json!({ "service": kind.wire(), "config": config.to_json() });
            let r: MutationResponse = self
                .rpc_tt(uri::TASK_SERVICES_ENABLE_1_0, payload, timeout)
                .await?;
            Ok(r.result.into())
        }

        pub(super) async fn services_update(
            &self,
            kind: Kind,
            config: Config,
            drain_ttl_secs: Option<u64>,
            timeout: u64,
        ) -> Result<Mutation, VtaError> {
            let mut payload = json!({ "service": kind.wire(), "config": config.to_json() });
            if let Some(ttl) = drain_ttl_secs {
                payload["drainTtlSecs"] = json!(ttl);
            }
            let r: MutationResponse = self
                .rpc_tt(uri::TASK_SERVICES_UPDATE_1_1, payload, timeout)
                .await?;
            Ok(r.result.into())
        }

        pub(super) async fn services_disable(
            &self,
            kind: Kind,
            drain_ttl_secs: Option<u64>,
            timeout: u64,
        ) -> Result<Mutation, VtaError> {
            let mut payload = json!({ "service": kind.wire() });
            if let Some(ttl) = drain_ttl_secs {
                payload["drainTtlSecs"] = json!(ttl);
            }
            let r: MutationResponse = self
                .rpc_tt(uri::TASK_SERVICES_DISABLE_1_0, payload, timeout)
                .await?;
            Ok(r.result.into())
        }

        pub(super) async fn services_rollback(
            &self,
            kind: Kind,
            timeout: u64,
        ) -> Result<RollbackResponse, VtaError> {
            let r: spec::rollback::v1_0::Response = self
                .rpc_tt(
                    uri::TASK_SERVICES_ROLLBACK_1_0,
                    json!({ "service": kind.wire() }),
                    timeout,
                )
                .await?;
            let r = r.result;
            Ok(RollbackResponse {
                log_entry_version_id: r.log_entry_version_id.unwrap_or_default(),
                effective_at: r.effective_at.map(ts).unwrap_or_default(),
                kind: serde_json::to_value(r.kind)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default(),
                drain_until: r.drain_until.map(ts),
                draining_mediator: r.draining_mediator,
                vta_did: r.vta_did.unwrap_or_default(),
                serverless: r.serverless,
            })
        }

        pub(super) async fn services_list(&self) -> Result<ServicesListResponse, VtaError> {
            let r: spec::list::v1_0::Response = self
                .rpc_tt(uri::TASK_SERVICES_LIST_1_0, json!({}), 30)
                .await?;
            Ok(ServicesListResponse {
                services: r.services.into_iter().filter_map(state).collect(),
            })
        }

        /// `Ok(None)` when the transport has never been configured — `get`
        /// answers that as not-found, distinct from configured-and-disabled.
        pub(super) async fn services_get(
            &self,
            kind: Kind,
        ) -> Result<Option<ServiceState>, VtaError> {
            let r: Result<spec::get::v1_0::Response, VtaError> = self
                .rpc_tt(
                    uri::TASK_SERVICES_GET_1_0,
                    json!({ "service": kind.wire() }),
                    30,
                )
                .await;
            match r {
                Ok(r) => Ok(serde_json::to_value(r.state)
                    .ok()
                    .and_then(|v| serde_json::from_value::<spec::list::v1_0::ServiceState>(v).ok())
                    .and_then(state)),
                Err(VtaError::NotFound(_)) => Ok(None),
                Err(e) => Err(e),
            }
        }

        pub(super) async fn services_drain_list(&self) -> Result<DrainListResponse, VtaError> {
            let r: spec::drain::list::v1_0::Response = self
                .rpc_tt(uri::TASK_SERVICES_DRAIN_LIST_1_0, json!({}), 30)
                .await?;
            Ok(DrainListResponse {
                entries: r
                    .entries
                    .into_iter()
                    .map(|e| DrainEntry {
                        mediator_did: e.mediator_did.to_string(),
                        endpoint: e.endpoint,
                        drains_until: ts(e.drains_until),
                    })
                    .collect(),
            })
        }

        pub(super) async fn services_drain_cancel(
            &self,
            mediator_did: &str,
        ) -> Result<String, VtaError> {
            let r: spec::drain::cancel::v1_0::Response = self
                .rpc_tt(
                    uri::TASK_SERVICES_DRAIN_CANCEL_1_0,
                    json!({ "mediatorDid": mediator_did }),
                    30,
                )
                .await?;
            Ok(r.mediator_did.to_string())
        }

        pub(super) async fn services_report(
            &self,
            since: Option<&str>,
            until: Option<&str>,
        ) -> Result<MediatorReport, VtaError> {
            let mut payload = json!({});
            if let Some(s) = since {
                payload["since"] = json!(s);
            }
            if let Some(u) = until {
                payload["until"] = json!(u);
            }
            let r: spec::report::v0_1::Response = self
                .rpc_tt(uri::TASK_SERVICES_REPORT_0_1, payload, 30)
                .await?;
            Ok(MediatorReport {
                since: r.since.map(ts),
                until: ts(r.until),
                mediators: r
                    .mediators
                    .into_iter()
                    .map(|m| MediatorStats {
                        mediator_did: m.mediator_did.to_string(),
                        inbound_count: m.inbound_count,
                        first_seen: ts(m.first_seen),
                        last_seen: ts(m.last_seen),
                    })
                    .collect(),
                senders: r
                    .senders
                    .into_iter()
                    .map(|s| SenderLastSeen {
                        sender_did: s.sender_did.to_string(),
                        last_seen_mediator: s.last_seen_mediator.to_string(),
                        last_seen_at: ts(s.last_seen_at),
                    })
                    .collect(),
            })
        }
    }

    /// The published flat state as the SDK's tagged enum. A kind this build
    /// does not know (the generated enum is `#[non_exhaustive]`) is dropped
    /// rather than guessed at.
    fn state(s: spec::list::v1_0::ServiceState) -> Option<ServiceState> {
        use spec::list::v1_0::ServiceKind as K;
        Some(match s.kind {
            K::Rest => ServiceState::Rest {
                enabled: s.enabled,
                url: s.url,
            },
            K::Didcomm => ServiceState::Didcomm {
                enabled: s.enabled,
                mediator_did: s.mediator_did,
                routing_keys: Vec::new(),
            },
            K::Tsp => ServiceState::Tsp {
                enabled: s.enabled,
                mediator_did: s.mediator_did,
            },
            K::Webauthn => ServiceState::Webauthn {
                enabled: s.enabled,
                url: s.url,
            },
            _ => return None,
        })
    }
}

#[cfg(feature = "client")]
use via_trust_tasks::{Config, Kind};

#[cfg(feature = "client")]
impl VtaClient {
    /// Enable DIDComm on a VTA that does not advertise it yet
    /// (`vta/services/enable`, `service: didcomm`).
    ///
    /// The VTA must be configured with a vta_did and have `services.didcomm =
    /// false`, and the caller must be super-admin. On success it publishes a
    /// new WebVH LogEntry advertising the mediator and registers it as active,
    /// after a transient handshake against the candidate mediator. Reachable
    /// over any transport the client holds — HTTPS on a REST-only VTA.
    pub async fn enable_didcomm(
        &self,
        req: EnableDidcommRequest,
    ) -> Result<EnableDidcommResponse, VtaError> {
        let m = self
            .services_enable(
                Kind::Didcomm,
                Config::Mediator {
                    mediator_did: req.mediator_did.clone(),
                    force: req.force.then_some(true),
                    handshake_timeout_secs: req.handshake_timeout_secs,
                },
                60,
            )
            .await?;
        Ok(EnableDidcommResponse {
            new_version_id: m.log_entry_version_id,
            mediator_did: req.mediator_did,
            // Not in the Trust Task's result: the endpoint is the mediator's
            // own DID document's to say, and the CLI prints it only when set.
            mediator_endpoint: String::new(),
            vta_did: m.vta_did,
            serverless: m.serverless,
        })
    }

    /// Whether DIDComm is advertised, and through which mediator
    /// (`vta/services/get`, `service: didcomm`). Auth: super-admin.
    ///
    /// `websocket_status` is not part of the published state and is always
    /// `None`; a live connection check is `GET /health/details`.
    pub async fn didcomm_status(&self) -> Result<DidcommStatusResponse, VtaError> {
        Ok(match self.services_get(Kind::Didcomm).await? {
            Some(services::ServiceState::Didcomm {
                enabled,
                mediator_did,
                ..
            }) => DidcommStatusResponse {
                enabled,
                mediator_did,
                websocket_status: None,
            },
            _ => DidcommStatusResponse {
                enabled: false,
                mediator_did: None,
                websocket_status: None,
            },
        })
    }

    /// Disable DIDComm. Refuses if it is the last advertised transport
    /// (`NoProtocolRemaining`). Drain TTL semantics:
    /// - `0` = immediate teardown, honoured only when the request did not
    ///   arrive through the mediator being torn down.
    /// - otherwise a drain window; over a DIDComm- or TSP-carried request the
    ///   server enforces a 1h floor.
    pub async fn disable_didcomm(
        &self,
        req: DisableDidcommRequest,
    ) -> Result<DisableDidcommResponse, VtaError> {
        let m = self
            .services_disable(Kind::Didcomm, Some(req.drain_ttl_secs), 30)
            .await?;
        Ok(DisableDidcommResponse {
            new_version_id: m.log_entry_version_id,
            prior_mediator_did: m.draining_mediator.unwrap_or_default(),
            drains_until: m.drain_until,
            vta_did: m.vta_did,
            serverless: m.serverless,
        })
    }

    /// Replace the DIDComm mediator the VTA advertises
    /// (`vta/services/update/1.1`). Runs the pre-promotion handshake against the
    /// new mediator and places the prior one in drain for the requested TTL —
    /// one drain covering every mediated transport it carried.
    pub async fn update_didcomm(
        &self,
        req: UpdateDidcommRequest,
    ) -> Result<UpdateDidcommResponse, VtaError> {
        let m = self
            .services_update(
                Kind::Didcomm,
                Config::Mediator {
                    mediator_did: req.new_mediator_did.clone(),
                    force: req.force.then_some(true),
                    handshake_timeout_secs: req.handshake_timeout_secs,
                },
                Some(req.drain_ttl_secs),
                120,
            )
            .await?;
        Ok(UpdateDidcommResponse {
            new_version_id: m.log_entry_version_id,
            prior_mediator_did: m.draining_mediator.unwrap_or_default(),
            active_mediator_did: req.new_mediator_did,
            active_mediator_endpoint: String::new(),
            drains_until: m.drain_until.unwrap_or_default(),
            vta_did: m.vta_did,
            serverless: m.serverless,
        })
    }

    /// Enable REST advertisement (`#vta-rest`). Spec §3.4.
    pub async fn enable_rest(
        &self,
        req: services::EnableRestRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        Ok(self
            .services_enable(Kind::Rest, Config::Url(req.url), 30)
            .await?
            .into())
    }

    /// Update the URL on the existing `#vta-rest` service entry.
    pub async fn update_rest(
        &self,
        req: services::UpdateRestRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        Ok(self
            .services_update(Kind::Rest, Config::Url(req.url), None, 30)
            .await?
            .into())
    }

    /// Remove the `#vta-rest` entry. Refused with `LastServiceRefused` when it
    /// is the last advertised transport.
    pub async fn disable_rest(
        &self,
        _req: services::DisableRestRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        Ok(self.services_disable(Kind::Rest, None, 30).await?.into())
    }

    /// Fail-forward the most recent REST mutation. Spec §3.5a.
    pub async fn rollback_rest(
        &self,
        _req: services::RollbackRestRequest,
    ) -> Result<services::RollbackResponse, VtaError> {
        self.services_rollback(Kind::Rest, 60).await
    }

    /// Enable TSP advertisement (`#tsp` → the mediator DID). Spec §3.4.
    pub async fn enable_tsp(
        &self,
        req: services::EnableTspRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        Ok(self
            .services_enable(
                Kind::Tsp,
                Config::Mediator {
                    mediator_did: req.mediator_did,
                    force: None,
                    handshake_timeout_secs: None,
                },
                30,
            )
            .await?
            .into())
    }

    /// Update the mediator DID on the existing `#tsp` service entry.
    pub async fn update_tsp(
        &self,
        req: services::UpdateTspRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        Ok(self
            .services_update(
                Kind::Tsp,
                Config::Mediator {
                    mediator_did: req.mediator_did,
                    force: None,
                    handshake_timeout_secs: None,
                },
                None,
                30,
            )
            .await?
            .into())
    }

    /// Remove the `#tsp` entry. Refused with `LastServiceRefused` when it is
    /// the last advertised transport.
    pub async fn disable_tsp(
        &self,
        _req: services::DisableTspRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        Ok(self.services_disable(Kind::Tsp, None, 30).await?.into())
    }

    /// Fail-forward the most recent TSP mutation. Spec §3.5a.
    pub async fn rollback_tsp(
        &self,
        _req: services::RollbackTspRequest,
    ) -> Result<services::RollbackResponse, VtaError> {
        self.services_rollback(Kind::Tsp, 60).await
    }

    /// Enable WebAuthn-RP advertisement (`#vta-webauthn`).
    pub async fn enable_webauthn(
        &self,
        req: services::EnableWebauthnRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        Ok(self
            .services_enable(Kind::Webauthn, Config::Url(req.url), 30)
            .await?
            .into())
    }

    /// Update the URL on the existing `#vta-webauthn` entry.
    pub async fn update_webauthn(
        &self,
        req: services::UpdateWebauthnRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        Ok(self
            .services_update(Kind::Webauthn, Config::Url(req.url), None, 30)
            .await?
            .into())
    }

    /// Remove the `#vta-webauthn` entry AND strip passkey VMs from every DID
    /// this VTA controls. Longer timeout: the cleanup publishes a WebVH update
    /// per affected DID.
    pub async fn disable_webauthn(
        &self,
        _req: services::DisableWebauthnRequest,
    ) -> Result<services::ServiceMutationResponse, VtaError> {
        Ok(self
            .services_disable(Kind::Webauthn, None, 300)
            .await?
            .into())
    }

    /// Fail-forward the most recent WebAuthn mutation.
    pub async fn rollback_webauthn(
        &self,
        _req: services::RollbackWebauthnRequest,
    ) -> Result<services::RollbackResponse, VtaError> {
        self.services_rollback(Kind::Webauthn, 300).await
    }

    /// Fail-forward the most recent DIDComm mutation.
    ///
    /// `drain_ttl_secs` is not carried: `vta/services/rollback/1.0` has no
    /// drain member, so a rollback that lands on a drain transition takes the
    /// agent's default window.
    pub async fn rollback_didcomm(
        &self,
        _req: services::RollbackDidcommRequest,
    ) -> Result<services::RollbackResponse, VtaError> {
        self.services_rollback(Kind::Didcomm, 120).await
    }

    /// The VTA's currently-advertised transport services, in canonical order.
    pub async fn list_services(&self) -> Result<services::ServicesListResponse, VtaError> {
        self.services_list().await
    }

    /// Mediators still draining. Empty is normal.
    pub async fn list_drain(&self) -> Result<services::DrainListResponse, VtaError> {
        self.services_drain_list().await
    }

    /// End a drain early, dropping the listener for that mediator at once.
    /// Refused for the active mediator, or one that is not registered.
    pub async fn drain_cancel(
        &self,
        req: DrainCancelRequest,
    ) -> Result<DrainCancelResponse, VtaError> {
        Ok(DrainCancelResponse {
            mediator_did: self.services_drain_cancel(&req.mediator_did).await?,
        })
    }

    /// The mediator-attribution report (`vta/services/report`): per-mediator
    /// inbound counts and each sender's last-seen mediator, across every
    /// mediated transport, so an operator can spot senders still on the prior
    /// mediator before ending a drain. `since`/`until` are optional RFC 3339.
    pub async fn mediator_report(
        &self,
        since: Option<&str>,
        until: Option<&str>,
    ) -> Result<MediatorReport, VtaError> {
        self.services_report(since, until).await
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
