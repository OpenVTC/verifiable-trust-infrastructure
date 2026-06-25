//! Bidirectional transport-protocol matching from advertised DID-document
//! services.
//!
//! When two parties communicate, the protocol used is the highest-preference
//! one **both** advertise in their DID documents — **TSP > DIDComm > REST**
//! (`docs/05-design-notes/tsp-enablement.md` §3, §11). Services are matched on
//! their `type` (`TSPTransport` / `DIDCommMessaging` / `VTARest`), **never** on
//! the `#id` fragment, which is an arbitrary label (D9 — the OWF reference TSP
//! impl names its id `#tsp-transport`, Affinidi names it `#tsp`; same type). If
//! the advertised sets don't intersect, [`select_protocol`] returns
//! [`VtaError::NoMatchingProtocol`] carrying both sides' advertised sets.
//!
//! This is pure, side-effect-free logic over an already-resolved DID document
//! `serde_json::Value`. DID resolution itself is the caller's job; so is the
//! second hop for TSP/DIDComm (resolving the returned mediator DID to its
//! transport URL).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::VtaError;

/// DID-document service `type` for a TSP transport endpoint. `TSPTransport`
/// is the OpenWallet-Foundation-Labs reference-implementation convention
/// (`affinidi_tsp`'s DID-backed VID resolver matches on it); the ToIP TSP
/// spec names no DID-document service type. Kept in sync with
/// `vta_service::operations::protocol::document::TSP_SERVICE_TYPE`.
pub const TSP_SERVICE_TYPE: &str = "TSPTransport";

/// DID-document service `type` for a DIDComm v2 mediator endpoint (W3C).
pub const DIDCOMM_SERVICE_TYPE: &str = "DIDCommMessaging";

/// DID-document service `type` for the VTA REST endpoint. Kept in sync with
/// `vta_service::operations::protocol::document::REST_SERVICE_TYPE`.
pub const REST_SERVICE_TYPE: &str = "VTARest";

/// A transport protocol, in workspace preference order: TSP, then DIDComm,
/// then REST. `Ord` follows that order — `Tsp` is the smallest (most
/// preferred) — so [`Protocol::PREFERENCE_ORDER`] is ascending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tsp,
    Didcomm,
    Rest,
}

impl Protocol {
    /// Every protocol in descending preference order (most preferred first).
    pub const PREFERENCE_ORDER: [Protocol; 3] = [Protocol::Tsp, Protocol::Didcomm, Protocol::Rest];

    /// Lowercase wire/display name (`"tsp"` / `"didcomm"` / `"rest"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tsp => "tsp",
            Protocol::Didcomm => "didcomm",
            Protocol::Rest => "rest",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The transport services a party advertises in its DID document, parsed by
/// service `type`. Each field holds the endpoint the SDK would route to for
/// that protocol:
///
/// - `tsp` / `didcomm`: the party's **mediator DID** (its VID / mediator),
///   not a transport URL — TSP and DIDComm both use mediator indirection (the
///   transport URL lives in the mediator's own DID document).
/// - `rest`: the party's REST base URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceCapabilities {
    pub tsp: Option<String>,
    pub didcomm: Option<String>,
    pub rest: Option<String>,
}

impl ServiceCapabilities {
    /// Parse the advertised transports from a resolved DID document.
    ///
    /// Walks the `service` array and selects entries by their `type` (D9 —
    /// never by `#id`). The `type` may be a string or an array of strings
    /// (DID-Core permits both). The first non-empty endpoint of each type
    /// wins; later duplicates are ignored. A document with no `service`
    /// array yields an all-`None` capability set.
    #[must_use]
    pub fn from_did_document(doc: &Value) -> Self {
        let mut caps = ServiceCapabilities::default();
        let Some(services) = doc.get("service").and_then(Value::as_array) else {
            return caps;
        };
        for svc in services {
            let Some(uri) = svc.get("serviceEndpoint").and_then(endpoint_uri) else {
                continue;
            };
            if uri.is_empty() {
                continue;
            }
            if service_has_type(svc, TSP_SERVICE_TYPE) {
                caps.tsp.get_or_insert(uri);
            } else if service_has_type(svc, DIDCOMM_SERVICE_TYPE) {
                caps.didcomm.get_or_insert(uri);
            } else if service_has_type(svc, REST_SERVICE_TYPE) {
                caps.rest.get_or_insert(uri);
            }
        }
        caps
    }

    /// The endpoint advertised for `protocol`, if any (mediator DID for
    /// TSP/DIDComm, URL for REST).
    #[must_use]
    pub fn endpoint(&self, protocol: Protocol) -> Option<&str> {
        match protocol {
            Protocol::Tsp => self.tsp.as_deref(),
            Protocol::Didcomm => self.didcomm.as_deref(),
            Protocol::Rest => self.rest.as_deref(),
        }
    }

    /// Every protocol this party advertises, in preference order.
    #[must_use]
    pub fn advertised(&self) -> Vec<Protocol> {
        Protocol::PREFERENCE_ORDER
            .into_iter()
            .filter(|p| self.endpoint(*p).is_some())
            .collect()
    }
}

/// The chosen protocol and the counterparty endpoint to route to for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolMatch {
    /// The selected transport.
    pub protocol: Protocol,
    /// The counterparty endpoint for `protocol`: the peer's **mediator DID**
    /// for TSP/DIDComm (resolve it onward for the transport URL), the peer's
    /// **URL** for REST.
    pub peer_endpoint: String,
}

/// Pick the protocol to use with a counterparty: the highest-preference one
/// (TSP > DIDComm > REST) present in **both** `ours` and `theirs`.
///
/// Returns [`VtaError::NoMatchingProtocol`] — carrying both advertised sets —
/// when the intersection is empty, so the CLI can show the operator what each
/// side offers and which transport to enable. Never silently downgrades past
/// what a peer advertises.
pub fn select_protocol(
    ours: &ServiceCapabilities,
    theirs: &ServiceCapabilities,
    counterparty_did: &str,
) -> Result<ProtocolMatch, VtaError> {
    for protocol in Protocol::PREFERENCE_ORDER {
        if ours.endpoint(protocol).is_some()
            && let Some(peer) = theirs.endpoint(protocol)
        {
            return Ok(ProtocolMatch {
                protocol,
                peer_endpoint: peer.to_string(),
            });
        }
    }
    Err(VtaError::NoMatchingProtocol {
        counterparty_did: counterparty_did.to_string(),
        ours: ours.advertised(),
        theirs: theirs.advertised(),
    })
}

/// Whether a service entry advertises `type_`. DID-Core permits `type` to be
/// a single string or an array of strings.
fn service_has_type(svc: &Value, type_: &str) -> bool {
    match svc.get("type") {
        Some(Value::String(s)) => s == type_,
        Some(Value::Array(arr)) => arr.iter().any(|t| t.as_str() == Some(type_)),
        _ => false,
    }
}

/// Resolve a `serviceEndpoint` value to its URI, tolerating the three shapes
/// a DID document may carry it in: a plain string (TSP/REST current
/// convention), an object with a `uri` field (DIDComm v2), or a
/// single-element array of either. Mirrors
/// `vta_service::operations::protocol::document::extract_mediator_did`.
fn endpoint_uri(endpoint: &Value) -> Option<String> {
    match endpoint {
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => map.get("uri")?.as_str().map(str::to_string),
        Value::Array(arr) => arr.iter().find_map(endpoint_uri),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc(services: Value) -> Value {
        json!({ "id": "did:webvh:peer", "service": services })
    }

    #[test]
    fn protocol_preference_order_is_tsp_didcomm_rest() {
        assert_eq!(
            Protocol::PREFERENCE_ORDER,
            [Protocol::Tsp, Protocol::Didcomm, Protocol::Rest]
        );
        // Ord agrees: Tsp is the most preferred (smallest).
        assert!(Protocol::Tsp < Protocol::Didcomm);
        assert!(Protocol::Didcomm < Protocol::Rest);
    }

    #[test]
    fn parses_each_type_and_endpoint_shape() {
        let caps = ServiceCapabilities::from_did_document(&doc(json!([
            // TSP: plain-string mediator DID.
            { "id": "did:webvh:peer#tsp", "type": "TSPTransport",
              "serviceEndpoint": "did:webvh:med-tsp" },
            // DIDComm: array-of-object {uri} mediator DID.
            { "id": "did:webvh:peer#vta-didcomm", "type": "DIDCommMessaging",
              "serviceEndpoint": [{ "accept": ["didcomm/v2"], "uri": "did:webvh:med-dc" }] },
            // REST: plain-string URL.
            { "id": "did:webvh:peer#vta-rest", "type": "VTARest",
              "serviceEndpoint": "https://peer.example/" },
        ])));
        assert_eq!(caps.tsp.as_deref(), Some("did:webvh:med-tsp"));
        assert_eq!(caps.didcomm.as_deref(), Some("did:webvh:med-dc"));
        assert_eq!(caps.rest.as_deref(), Some("https://peer.example/"));
        assert_eq!(
            caps.advertised(),
            vec![Protocol::Tsp, Protocol::Didcomm, Protocol::Rest]
        );
    }

    #[test]
    fn matches_by_type_not_id() {
        // A TSPTransport service whose id is a non-canonical label is still
        // discovered (match is on `type`). And a service whose id *looks*
        // like `#tsp` but has a different type is NOT treated as TSP.
        let caps = ServiceCapabilities::from_did_document(&doc(json!([
            { "id": "did:webvh:peer#tsp-transport", "type": "TSPTransport",
              "serviceEndpoint": "did:webvh:med" },
            { "id": "did:webvh:peer#tsp", "type": "SomethingElse",
              "serviceEndpoint": "https://decoy.example/" },
        ])));
        assert_eq!(caps.tsp.as_deref(), Some("did:webvh:med"));
        assert_eq!(caps.rest, None);
        assert_eq!(caps.didcomm, None);
    }

    #[test]
    fn type_may_be_an_array() {
        let caps = ServiceCapabilities::from_did_document(&doc(json!([
            { "id": "x", "type": ["DIDCommMessaging", "OtherThing"],
              "serviceEndpoint": { "uri": "did:webvh:med" } },
        ])));
        assert_eq!(caps.didcomm.as_deref(), Some("did:webvh:med"));
    }

    #[test]
    fn empty_or_missing_service_array_is_no_capabilities() {
        assert_eq!(
            ServiceCapabilities::from_did_document(&json!({ "id": "did:x" })),
            ServiceCapabilities::default()
        );
        assert!(
            ServiceCapabilities::from_did_document(&doc(json!([])))
                .advertised()
                .is_empty()
        );
    }

    fn caps(tsp: Option<&str>, didcomm: Option<&str>, rest: Option<&str>) -> ServiceCapabilities {
        ServiceCapabilities {
            tsp: tsp.map(str::to_string),
            didcomm: didcomm.map(str::to_string),
            rest: rest.map(str::to_string),
        }
    }

    #[test]
    fn select_prefers_tsp_when_both_advertise_it() {
        let ours = caps(
            Some("did:m:ours"),
            Some("did:dc:ours"),
            Some("https://ours"),
        );
        let theirs = caps(
            Some("did:m:theirs"),
            Some("did:dc:theirs"),
            Some("https://theirs"),
        );
        let m = select_protocol(&ours, &theirs, "did:webvh:peer").unwrap();
        assert_eq!(m.protocol, Protocol::Tsp);
        // Endpoint returned is the *counterparty's* TSP mediator DID.
        assert_eq!(m.peer_endpoint, "did:m:theirs");
    }

    #[test]
    fn select_falls_through_to_didcomm_then_rest() {
        // We don't speak TSP; peer does — fall to the next shared protocol.
        let ours = caps(None, Some("did:dc:ours"), Some("https://ours"));
        let theirs = caps(Some("did:m:theirs"), Some("did:dc:theirs"), None);
        let m = select_protocol(&ours, &theirs, "did:webvh:peer").unwrap();
        assert_eq!(m.protocol, Protocol::Didcomm);
        assert_eq!(m.peer_endpoint, "did:dc:theirs");

        // Only REST in common.
        let ours = caps(Some("did:m:ours"), None, Some("https://ours"));
        let theirs = caps(None, Some("did:dc:theirs"), Some("https://theirs"));
        let m = select_protocol(&ours, &theirs, "did:webvh:peer").unwrap();
        assert_eq!(m.protocol, Protocol::Rest);
        assert_eq!(m.peer_endpoint, "https://theirs");
    }

    #[test]
    fn select_requires_both_sides_to_advertise() {
        // We only speak TSP; peer only speaks REST — no overlap.
        let ours = caps(Some("did:m:ours"), None, None);
        let theirs = caps(None, None, Some("https://theirs"));
        let err = select_protocol(&ours, &theirs, "did:webvh:peer").unwrap_err();
        match err {
            VtaError::NoMatchingProtocol {
                counterparty_did,
                ours,
                theirs,
            } => {
                assert_eq!(counterparty_did, "did:webvh:peer");
                assert_eq!(ours, vec![Protocol::Tsp]);
                assert_eq!(theirs, vec![Protocol::Rest]);
            }
            other => panic!("expected NoMatchingProtocol, got {other:?}"),
        }
    }
}
