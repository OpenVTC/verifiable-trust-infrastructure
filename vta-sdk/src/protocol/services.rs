//! Wire types for the runtime REST service-management surface.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §4.
//!
//! These cover the four REST operations exposed under
//! `pnm services rest {enable,update,disable,rollback}` plus the
//! shared response shape (`ServiceMutationResponse`) used by every
//! mutation across both REST and DIDComm kinds.
//!
//! DIDComm-side wire types live in [`super`] — `EnableDidcommRequest`,
//! `DisableDidcommRequest`, and (renamed in T2.3) `UpdateDidcommRequest`.
//! Keep the two surfaces in sync as they evolve.
//!
//! ## URL field convention
//!
//! `url: String` is intentional — the field stays a string here so
//! the SDK matches the existing protocol-management types
//! (`mediator_did: String`, etc.) and the operation layer applies a
//! single validation pass via [`crate::protocol::validate_service_url`]
//! (T1.2). Operators see one consistent error shape regardless of
//! whether validation runs client-side, server-side, or both.

use serde::{Deserialize, Serialize};

use crate::error::VtaError;

/// Validate a service-endpoint URL.
///
/// Spec §3.4: must be `https://`, parsable by `url::Url`, no
/// fragment, no userinfo. Returns the parsed [`url::Url`] on
/// success so callers don't re-parse, or [`VtaError::Validation`]
/// with a specific message on failure.
///
/// Centralized so both REST handlers and DIDComm transport
/// handlers (and any client-side pre-flight) use the same rule.
/// The CLI surfaces the rejection through `VtaError`'s
/// `suggested_fix` path; reasons are kept short and operator-
/// readable rather than full stack-trace text.
///
/// `localhost` and IP literals are accepted — the operator may
/// genuinely want to advertise a private deployment. TLS is still
/// required there (operator can run a private CA / mkcert); the
/// invariant is that clients see a TLS-protected URL in the DID
/// document, not that the cert chains to a public root.
pub fn validate_service_url(url: &str) -> Result<url::Url, VtaError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(VtaError::Validation("service URL is empty".into()));
    }

    let parsed = url::Url::parse(trimmed)
        .map_err(|e| VtaError::Validation(format!("service URL is unparseable: {e}")))?;

    if parsed.scheme() != "https" {
        return Err(VtaError::Validation(format!(
            "service URL must use https:// (got {})",
            parsed.scheme()
        )));
    }

    if parsed.fragment().is_some() {
        return Err(VtaError::Validation(
            "service URL must not contain a `#fragment`".into(),
        ));
    }

    // userinfo = the `user:password@` part. `url::Url` exposes
    // username() (always returns "" when absent) and password()
    // (Option<&str>). A non-empty username OR a password being
    // present means userinfo is set.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(VtaError::Validation(
            "service URL must not contain userinfo (user:password@)".into(),
        ));
    }

    if parsed.host().is_none() {
        return Err(VtaError::Validation("service URL must have a host".into()));
    }

    Ok(parsed)
}

/// Request body for `POST /services/rest/enable`.
///
/// Adds a `#vta-rest` service entry to the VTA's DID document
/// pointing at `url`. Refused with `ServiceAlreadyEnabled` if REST
/// is already advertised. The wire shape rendered into the DID
/// document — `id: "{DID}#vta-rest"`, `type: "VTARest"` — is
/// preserved by the operation layer (P1.3) for SDK-resolution
/// compatibility (`vta-sdk/src/session.rs:1100`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[must_use]
pub struct EnableRestRequest {
    pub url: String,
}

impl EnableRestRequest {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

/// Request body for `POST /services/rest/update`.
///
/// Replaces the URL on the existing `#vta-rest` entry. Refused
/// with `ServiceNotPresent` if REST is not currently advertised.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[must_use]
pub struct UpdateRestRequest {
    pub url: String,
}

impl UpdateRestRequest {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

/// Request body for `POST /services/rest/disable`.
///
/// Removes the `#vta-rest` entry. Refused with
/// `LastServiceRefused` when DIDComm is also disabled (spec §3.2)
/// and with `ServiceNotPresent` if REST isn't currently advertised.
///
/// No fields today — the body exists so the wire surface stays
/// uniform (every mutation is a `POST` with a JSON body) and so
/// the type can grow optional fields later without a breaking
/// change. Serializes as `{}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[must_use]
pub struct DisableRestRequest {}

/// Request body for `POST /services/rest/rollback`.
///
/// Fail-forwards the most recent REST mutation (spec §3.5a) by
/// reading the snapshot store and dispatching to the equivalent
/// forward operation. Refused with `NoPriorMutation` when no
/// snapshot is recorded, and with `LastServiceRefused` if the
/// rollback would brick the VTA. Like [`DisableRestRequest`],
/// no fields today — serializes as `{}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[must_use]
pub struct RollbackRestRequest {}

// ── TSP service-management request types ──────────────────────────
//
// TSP advertises a **mediator DID** (the VTA's TSP VID), not a URL —
// so where the REST types carry `url: String`, these carry
// `mediator_did: String`. TSP reuses the shared
// [`ServiceMutationResponse`] / [`RollbackResponse`] shapes; there
// are no TSP-specific response types. TSP has no drain and no
// handshake, so the disable / rollback bodies stay field-free.

/// Request body for `POST /services/tsp/enable`.
///
/// Adds a `#tsp` service entry (`type: "TSPTransport"`) to the VTA's
/// DID document advertising `mediator_did` — the VTA's TSP VID.
/// Refused with `ServiceAlreadyEnabled` if TSP is already advertised.
/// Unlike DIDComm enable, TSP enable is reachable over both REST and
/// DIDComm (DIDComm is always running when REST is, per the §3.2
/// at-least-one-service invariant).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[must_use]
pub struct EnableTspRequest {
    pub mediator_did: String,
}

impl EnableTspRequest {
    pub fn new(mediator_did: impl Into<String>) -> Self {
        Self {
            mediator_did: mediator_did.into(),
        }
    }
}

/// Request body for `POST /services/tsp/update`.
///
/// Replaces the mediator DID on the existing `#tsp` entry. Refused
/// with `ServiceNotPresent` if TSP is not currently advertised.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[must_use]
pub struct UpdateTspRequest {
    pub mediator_did: String,
}

impl UpdateTspRequest {
    pub fn new(mediator_did: impl Into<String>) -> Self {
        Self {
            mediator_did: mediator_did.into(),
        }
    }
}

/// Request body for `POST /services/tsp/disable`.
///
/// Removes the `#tsp` entry. Refused with `LastServiceRefused` when
/// TSP is the only advertised transport (spec §3.2) and with
/// `ServiceNotPresent` if TSP isn't currently advertised.
///
/// No fields today — like [`DisableRestRequest`] the body exists so
/// the wire surface stays uniform. Serializes as `{}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[must_use]
pub struct DisableTspRequest {}

/// Request body for `POST /services/tsp/rollback`.
///
/// Fail-forwards the most recent TSP mutation (spec §3.5a) by reading
/// the snapshot store and dispatching to the equivalent forward
/// operation. Refused with `NoPriorMutation` when no snapshot is
/// recorded, and with `LastServiceRefused` if the rollback would
/// brick the VTA. Like [`RollbackRestRequest`], no fields today —
/// serializes as `{}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[must_use]
pub struct RollbackTspRequest {}

/// Request body for `POST /services/webauthn/enable`.
///
/// Adds a `#vta-webauthn` service entry to the VTA's DID document
/// pointing at `url`. Refused with `ServiceAlreadyEnabled` if the
/// WebAuthn-RP surface is already advertised. The wire shape
/// rendered into the DID document — `id: "{DID}#vta-webauthn"`,
/// `type: "WebAuthnRP"` — is preserved by the operation layer.
///
/// Distinct from `EnableRestRequest` because the WebAuthn-RP
/// surface has different availability semantics: it can be
/// toggled independently of the general REST API and is the entry
/// point browsers discover for the auth portal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[must_use]
pub struct EnableWebauthnRequest {
    pub url: String,
}

impl EnableWebauthnRequest {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

/// Request body for `POST /services/webauthn/update`.
///
/// Replaces the URL on the existing `#vta-webauthn` entry. Refused
/// with `ServiceNotPresent` if the WebAuthn surface is not currently
/// advertised.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[must_use]
pub struct UpdateWebauthnRequest {
    pub url: String,
}

impl UpdateWebauthnRequest {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

/// Request body for `POST /services/webauthn/disable`.
///
/// Removes the `#vta-webauthn` entry **and** any passkey
/// verificationMethods published on the VTA's DID document — the
/// operator chose hard-disable semantics so a disabled WebAuthn-RP
/// surface doesn't leave dangling VMs claiming to authenticate
/// against an unreachable RP.
///
/// Refused with `LastServiceRefused` when removing WebAuthn would
/// leave no transport advertised at all (spec §3.2; WebAuthn counts
/// as a transport for this invariant).
///
/// No fields today — serializes as `{}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[must_use]
pub struct DisableWebauthnRequest {}

/// Request body for `POST /services/webauthn/rollback`. Symmetric
/// with [`RollbackRestRequest`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[must_use]
pub struct RollbackWebauthnRequest {}

/// Request body for `POST /services/didcomm/rollback`.
///
/// Threads `drain_ttl_secs` through to the dispatched forward op
/// for the disable / update arms. Server applies the spec §3.6
/// default (24h) when omitted.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[must_use]
pub struct RollbackDidcommRequest {
    /// Drain window for the previously-active mediator (seconds).
    /// Server default is 24h when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_ttl_secs: Option<u64>,
}

impl RollbackDidcommRequest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn drain_ttl_secs(mut self, secs: u64) -> Self {
        self.drain_ttl_secs = Some(secs);
        self
    }
}

/// Response body for `GET /services/didcomm/drain` — the list of
/// mediators currently in drain state. Empty list is normal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DrainListResponse {
    pub entries: Vec<DrainEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DrainEntry {
    pub mediator_did: String,
    pub endpoint: String,
    /// Drain deadline (RFC 3339).
    pub drains_until: String,
}

/// Response body for the rollback handlers. Wider than
/// [`ServiceMutationResponse`] — adds `kind` and
/// `draining_mediator` fields that downstream consumers need to
/// distinguish the dispatched arm.
///
/// `log_entry_version_id` is the empty string when the rollback
/// was a no-op (snapshot ≡ current state).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RollbackResponse {
    pub log_entry_version_id: String,
    pub effective_at: String,
    /// One of: `disabled`, `enabled`, `updated`, `no_op`.
    pub kind: String,
    /// `Some(rfc3339)` when the rollback scheduled a drain.
    /// `None` for REST and DIDComm enable / no-op arms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_until: Option<String>,
    /// Mediator DID currently being drained by this rollback.
    /// `None` for REST and DIDComm enable / no-op arms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draining_mediator: Option<String>,
    /// The VTA's own DID — the subject of the LogEntry this
    /// rollback wrote. Carried so the CLI can print follow-up
    /// commands like `pnm webvh did-log <vta_did>` for serverless
    /// deployments without forcing the operator to look it up.
    /// Empty string in `no_op` responses where no LogEntry was
    /// written. Serialized as `vta_did` on the wire; elided when
    /// empty for compactness.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted (`server_id =
    /// "serverless"`). The rollback's new LogEntry is persisted
    /// locally but NOT pushed to any webvh host — the operator
    /// must fetch the updated `did.jsonl` and redeploy.
    /// `#[serde(default)]` for back-compat — older servers don't
    /// emit the field and old clients treat absent → false.
    #[serde(default)]
    pub serverless: bool,
}

/// Response body for `GET /services` — the operator-facing read
/// surface for inspecting the VTA's current advertised transport
/// services. Spec §10 (resolved): minimal shape — one entry per
/// kind, `enabled` flag, kind-specific config when enabled.
///
/// Order is canonical: DIDComm before REST when both are
/// advertised, matching the spec §3.3 ordering invariant
/// enforced in `protocol::document::sort_services_canonical`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ServicesListResponse {
    pub services: Vec<ServiceState>,
}

/// State of a single transport kind. The `kind` discriminator is
/// `"tsp"`, `"rest"`, `"didcomm"`, or `"webauthn"` on the wire (kebab-case
/// to align with the rest of the runtime service-management surface).
/// When `enabled` is `false`, the kind-specific config fields are
/// absent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ServiceState {
    Tsp {
        enabled: bool,
        /// Mediator DID the `#tsp` service advertises (the VTA's TSP
        /// VID) — TSP uses the same mediator indirection as DIDComm, so
        /// this is typically the same value as the DIDComm `mediator_did`
        /// (one dual-protocol mediator). `None` when TSP is disabled.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mediator_did: Option<String>,
    },
    Rest {
        enabled: bool,
        /// Currently-published REST URL. `None` when REST is
        /// disabled.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
    },
    Didcomm {
        enabled: bool,
        /// Currently-active mediator DID. `None` when DIDComm is
        /// disabled.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mediator_did: Option<String>,
        /// Routing keys for the active mediator. Empty when
        /// DIDComm is disabled or when the mediator entry doesn't
        /// carry routing-keys today (the workspace's `#vta-didcomm`
        /// service entry currently doesn't).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        routing_keys: Vec<String>,
    },
    Webauthn {
        enabled: bool,
        /// Currently-published WebAuthn-RP URL — typically the
        /// operator-facing auth portal. `None` when the WebAuthn
        /// service is disabled.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
    },
}

/// Shared response body for every successful service-mutation
/// operation (REST + DIDComm enable/update/disable/rollback).
///
/// `drain_until` is `Some(rfc3339)` only for DIDComm operations
/// that scheduled a drain (`update_didcomm`, `disable_didcomm`,
/// or a `rollback_didcomm` whose fail-forward target was a drain
/// transition). REST mutations always set it to `None`.
///
/// All timestamps are RFC 3339 strings to match the existing wire
/// convention from `DisableDidcommResponse::drains_until`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ServiceMutationResponse {
    /// Version-id of the new WebVH LogEntry produced by the
    /// mutation. Joins telemetry events to chain history.
    pub log_entry_version_id: String,
    /// RFC 3339 timestamp when the mutation took effect — the
    /// same instant stamped on the new LogEntry.
    pub effective_at: String,
    /// `Some(rfc3339)` when the mutation scheduled a DIDComm
    /// drain; `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_until: Option<String>,
    /// The VTA's own DID — subject of the LogEntry this mutation
    /// wrote. Carried so the CLI can print follow-up commands like
    /// `pnm webvh did-log <vta_did>` for serverless deployments
    /// without forcing the operator to look it up.
    /// `#[serde(default)]` + `skip_serializing_if = "String::is_empty"`
    /// keep the wire compact and back-compat with older servers.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted (`server_id =
    /// "serverless"`). The new LogEntry is persisted locally but
    /// NOT pushed to any webvh host — the operator must fetch the
    /// updated `did.jsonl` and redeploy. `#[serde(default)]` for
    /// back-compat — older servers don't emit the field; old
    /// clients treat absent → false (no spurious hint).
    #[serde(default)]
    pub serverless: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip every request type — both directions, across the
    /// wire forms used by REST handlers (raw JSON body) and DIDComm
    /// transport (JSON-tagged in the message attachment).
    #[test]
    fn rest_request_types_round_trip_through_json() {
        let req = EnableRestRequest::new("https://vta.example.com");
        let json = serde_json::to_string(&req).unwrap();
        let restored: EnableRestRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, req);

        let req = UpdateRestRequest::new("https://vta-new.example.com");
        let json = serde_json::to_string(&req).unwrap();
        let restored: UpdateRestRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, req);

        let req = DisableRestRequest::default();
        let json = serde_json::to_string(&req).unwrap();
        let restored: DisableRestRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, req);

        let req = RollbackRestRequest::default();
        let json = serde_json::to_string(&req).unwrap();
        let restored: RollbackRestRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, req);
    }

    /// TSP request types round-trip — `mediator_did` (a DID) where
    /// REST uses `url`. Mirror of `rest_request_types_round_trip…`.
    #[test]
    fn tsp_request_types_round_trip_through_json() {
        let req = EnableTspRequest::new("did:peer:2.Mediator");
        let json = serde_json::to_string(&req).unwrap();
        let restored: EnableTspRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, req);

        let req = UpdateTspRequest::new("did:peer:2.NewMediator");
        let json = serde_json::to_string(&req).unwrap();
        let restored: UpdateTspRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, req);

        let req = DisableTspRequest::default();
        let json = serde_json::to_string(&req).unwrap();
        let restored: DisableTspRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, req);

        let req = RollbackTspRequest::default();
        let json = serde_json::to_string(&req).unwrap();
        let restored: RollbackTspRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, req);
    }

    /// TSP's enable/update field must stay literal `mediator_did` on
    /// the wire (a DID, not a URL). Pin via JSON shape.
    #[test]
    fn tsp_mediator_did_field_is_literal_on_wire() {
        let json = serde_json::to_value(EnableTspRequest::new("did:peer:2.M")).unwrap();
        assert_eq!(json["mediator_did"], "did:peer:2.M");
        assert!(json.get("url").is_none(), "TSP must not carry a url field");

        let json = serde_json::to_value(UpdateTspRequest::new("did:peer:2.N")).unwrap();
        assert_eq!(json["mediator_did"], "did:peer:2.N");
    }

    /// TSP's empty bodies serialize as `{}` (mirror of the REST pin).
    #[test]
    fn tsp_empty_request_bodies_serialize_as_empty_object() {
        assert_eq!(
            serde_json::to_string(&DisableTspRequest::default()).unwrap(),
            "{}"
        );
        assert_eq!(
            serde_json::to_string(&RollbackTspRequest::default()).unwrap(),
            "{}"
        );
        let _: DisableTspRequest = serde_json::from_str("{}").unwrap();
        let _: RollbackTspRequest = serde_json::from_str("{}").unwrap();
    }

    /// The empty request bodies must serialize as `{}`, not `null`,
    /// `[]`, or a string. REST clients that send `null` would
    /// fail strict-deserialize servers; pin the wire form.
    #[test]
    fn empty_request_bodies_serialize_as_empty_object() {
        assert_eq!(
            serde_json::to_string(&DisableRestRequest::default()).unwrap(),
            "{}"
        );
        assert_eq!(
            serde_json::to_string(&RollbackRestRequest::default()).unwrap(),
            "{}"
        );
    }

    /// The empty request bodies must also accept an empty object
    /// `{}` (and `null`, via `Default`) on the deserialize side, so
    /// callers that send no body don't trip up the server.
    #[test]
    fn empty_request_bodies_accept_empty_object() {
        let _: DisableRestRequest = serde_json::from_str("{}").unwrap();
        let _: RollbackRestRequest = serde_json::from_str("{}").unwrap();
    }

    /// `url` field name must stay literal `url` on the wire —
    /// renaming it would break every caller. Pin via JSON shape
    /// rather than relying solely on the `#[derive(Serialize)]`
    /// default.
    #[test]
    fn rest_url_field_is_literal_url_on_wire() {
        let json = serde_json::to_value(EnableRestRequest::new("https://x.example")).unwrap();
        assert_eq!(json["url"], "https://x.example");
        assert!(json.get("uri").is_none(), "must not rename url to uri");

        let json = serde_json::to_value(UpdateRestRequest::new("https://y.example")).unwrap();
        assert_eq!(json["url"], "https://y.example");
    }

    /// `ServiceMutationResponse` round-trips with and without
    /// `drain_until`. The `None` case omits the field on the wire
    /// (per `skip_serializing_if`); the `Some` case includes the
    /// RFC 3339 timestamp.
    #[test]
    fn service_mutation_response_round_trips_both_drain_states() {
        let rest_response = ServiceMutationResponse {
            log_entry_version_id: "1-zQm...A".into(),
            effective_at: "2026-05-06T13:00:00Z".into(),
            drain_until: None,
            vta_did: "did:webvh:scid:host:vta".into(),
            serverless: false,
        };
        let json = serde_json::to_value(&rest_response).unwrap();
        assert_eq!(json["log_entry_version_id"], "1-zQm...A");
        assert_eq!(json["effective_at"], "2026-05-06T13:00:00Z");
        assert!(
            json.get("drain_until").is_none(),
            "drain_until must be omitted when None — wire bandwidth + reader convention",
        );
        let restored: ServiceMutationResponse = serde_json::from_value(json).unwrap();
        assert_eq!(restored, rest_response);

        let didcomm_response = ServiceMutationResponse {
            log_entry_version_id: "2-zQm...B".into(),
            effective_at: "2026-05-06T13:00:00Z".into(),
            drain_until: Some("2026-05-07T13:00:00Z".into()),
            vta_did: "did:webvh:scid:host:vta".into(),
            serverless: true,
        };
        let json = serde_json::to_value(&didcomm_response).unwrap();
        assert_eq!(json["drain_until"], "2026-05-07T13:00:00Z");
        assert_eq!(json["vta_did"], "did:webvh:scid:host:vta");
        assert_eq!(json["serverless"], true);
        let restored: ServiceMutationResponse = serde_json::from_value(json).unwrap();
        assert_eq!(restored, didcomm_response);
    }

    /// Back-compat: older servers don't emit `vta_did` /
    /// `serverless`. Absent on the wire → string default ("") +
    /// bool default (false). Pins what `#[serde(default)]` buys.
    #[test]
    fn service_mutation_response_decodes_legacy_payload() {
        let legacy = r#"{
            "log_entry_version_id": "1-zQm...A",
            "effective_at": "2026-05-06T13:00:00Z"
        }"#;
        let r: ServiceMutationResponse = serde_json::from_str(legacy).unwrap();
        assert_eq!(r.vta_did, "");
        assert!(!r.serverless);
    }

    // ── validate_service_url ──────────────────────────────────────

    #[test]
    fn validate_service_url_accepts_https() {
        assert!(validate_service_url("https://vta.example.com").is_ok());
        assert!(validate_service_url("https://vta.example.com/").is_ok());
        assert!(validate_service_url("https://vta.example.com:8443").is_ok());
        assert!(validate_service_url("https://vta.example.com/path/sub").is_ok());
    }

    #[test]
    fn validate_service_url_accepts_localhost_and_ip_literals() {
        // Private/dev deployments are valid — operators may run
        // mkcert or a private CA; TLS-protected is what matters,
        // not whether the cert chains to a public root.
        assert!(validate_service_url("https://localhost:8443").is_ok());
        assert!(validate_service_url("https://127.0.0.1:8443").is_ok());
        assert!(validate_service_url("https://[::1]:8443").is_ok());
    }

    #[test]
    fn validate_service_url_rejects_http() {
        let err = validate_service_url("http://vta.example.com").unwrap_err();
        match err {
            VtaError::Validation(msg) => assert!(
                msg.contains("https"),
                "expected scheme-related rejection, got: {msg}",
            ),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validate_service_url_rejects_other_schemes() {
        for bad in [
            "ws://vta.example.com",
            "ftp://x.example",
            "file:///etc/passwd",
        ] {
            assert!(
                matches!(validate_service_url(bad), Err(VtaError::Validation(_))),
                "expected rejection for {bad}",
            );
        }
    }

    #[test]
    fn validate_service_url_rejects_fragment() {
        let err = validate_service_url("https://vta.example.com/api#section").unwrap_err();
        match err {
            VtaError::Validation(msg) => {
                assert!(
                    msg.contains("fragment"),
                    "expected fragment rejection, got: {msg}"
                )
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validate_service_url_rejects_userinfo() {
        for bad in [
            "https://user@vta.example.com",
            "https://user:pass@vta.example.com",
            "https://:pass@vta.example.com",
        ] {
            let err = validate_service_url(bad).unwrap_err();
            match err {
                VtaError::Validation(msg) => assert!(
                    msg.contains("userinfo"),
                    "expected userinfo rejection for {bad}, got: {msg}",
                ),
                other => panic!("expected Validation for {bad}, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_service_url_rejects_unparseable() {
        for bad in ["not a url at all", "://no-scheme", "https://", "🦀"] {
            assert!(
                matches!(validate_service_url(bad), Err(VtaError::Validation(_))),
                "expected rejection for {bad:?}",
            );
        }
    }

    #[test]
    fn validate_service_url_rejects_empty_and_whitespace() {
        for bad in ["", "   ", "\t\n"] {
            let err = validate_service_url(bad).unwrap_err();
            match err {
                VtaError::Validation(msg) => assert!(
                    msg.contains("empty"),
                    "expected empty-URL rejection for {bad:?}, got: {msg}",
                ),
                other => panic!("expected Validation for {bad:?}, got {other:?}"),
            }
        }
    }

    /// On success, the parsed `url::Url` is returned so callers
    /// don't re-parse. Spot-check a couple of properties.
    #[test]
    fn validate_service_url_returns_parsed_url() {
        let parsed = validate_service_url("https://vta.example.com:8443/api").unwrap();
        assert_eq!(parsed.scheme(), "https");
        assert_eq!(parsed.host_str(), Some("vta.example.com"));
        assert_eq!(parsed.port(), Some(8443));
        assert_eq!(parsed.path(), "/api");
    }

    // ── ServicesListResponse / ServiceState wire shape ──────────

    #[test]
    fn services_list_response_round_trips_both_kinds() {
        let response = ServicesListResponse {
            services: vec![
                ServiceState::Didcomm {
                    enabled: true,
                    mediator_did: Some("did:peer:2.M".into()),
                    routing_keys: vec!["did:peer:2.K".into()],
                },
                ServiceState::Rest {
                    enabled: true,
                    url: Some("https://vta.example.com".into()),
                },
            ],
        };
        let json = serde_json::to_string(&response).unwrap();
        let restored: ServicesListResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, response);
    }

    /// Disabled state on either kind has the kind-specific config
    /// fields elided from the wire form (per `skip_serializing_if`).
    #[test]
    fn service_state_disabled_omits_config_fields() {
        let rest_off = ServiceState::Rest {
            enabled: false,
            url: None,
        };
        let json = serde_json::to_value(&rest_off).unwrap();
        assert_eq!(json["kind"], "rest");
        assert_eq!(json["enabled"], false);
        assert!(
            json.get("url").is_none(),
            "url must be elided when None to keep the wire form clean",
        );

        let didcomm_off = ServiceState::Didcomm {
            enabled: false,
            mediator_did: None,
            routing_keys: vec![],
        };
        let json = serde_json::to_value(&didcomm_off).unwrap();
        assert_eq!(json["kind"], "didcomm");
        assert_eq!(json["enabled"], false);
        assert!(json.get("mediator_did").is_none());
        assert!(json.get("routing_keys").is_none());
    }

    /// Discriminator field is literal `kind` with kebab-case
    /// (`rest` / `didcomm`) values — pin the wire contract so a
    /// `serde(rename)` tweak fails loudly.
    #[test]
    fn service_state_discriminator_is_literal_kind() {
        let json = serde_json::to_value(ServiceState::Rest {
            enabled: true,
            url: Some("https://x.example".into()),
        })
        .unwrap();
        assert_eq!(json["kind"], "rest");

        let json = serde_json::to_value(ServiceState::Didcomm {
            enabled: true,
            mediator_did: Some("did:peer:2.M".into()),
            routing_keys: vec![],
        })
        .unwrap();
        assert_eq!(json["kind"], "didcomm");
    }

    /// `ServiceMutationResponse` deserializes both forms — explicit
    /// `null` for drain_until (some encoders emit it) and the
    /// elided form (preferred).
    #[test]
    fn service_mutation_response_accepts_explicit_null_drain_until() {
        let with_null = r#"{
            "log_entry_version_id": "1-zQm...A",
            "effective_at": "2026-05-06T13:00:00Z",
            "drain_until": null
        }"#;
        let r: ServiceMutationResponse = serde_json::from_str(with_null).unwrap();
        assert_eq!(r.drain_until, None);

        let elided = r#"{
            "log_entry_version_id": "1-zQm...A",
            "effective_at": "2026-05-06T13:00:00Z"
        }"#;
        let r: ServiceMutationResponse = serde_json::from_str(elided).unwrap();
        assert_eq!(r.drain_until, None);
    }
}
