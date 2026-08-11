//! The messaging-transport entries a community publishes in its DID document.
//!
//! A DID document is how a party says *how to reach it*. Until now the
//! `vtc-host` template published none: a VTC connected outbound to a mediator
//! and its document told nobody, so a conforming client resolving the community
//! found no messaging transport at all and DIDComm only worked when the sender
//! had been handed the mediator out of band.
//!
//! ## Why this has to happen at mint
//!
//! A VTC serves a **write-once** `did.jsonl` and cannot re-sign its own log, so
//! adding a service afterwards means a VTA-side `dids edit` plus redelivering
//! the log by hand. That is exactly how the reference deployment acquired its
//! `#tsp` entry at DID log version 3 — out of band, long after mint, and with
//! nothing checking that the binary could serve it. Provisioning is the only
//! moment the community's own setup gets to decide this, so the decision is
//! taken there and rendered into the document it is minting.
//!
//! ## Both entries name the mediator, not a URL
//!
//! TSP and DIDComm use the same indirection: the `serviceEndpoint` is the
//! **mediator's DID**, and the transport URL lives in the mediator's own
//! document. They also bind the *same* mediator — one dual-protocol mediator
//! serves both (`docs/05-design-notes/tsp-enablement.md` §14 Q2), so a
//! community advertising both publishes one mediator DID twice under two
//! service types.
//!
//! ## Advertising is a promise about the mediator, too
//!
//! Managing a mediator's own service entries belongs to the mediator's
//! controller (§14 Q3), so nothing here can confirm the named mediator
//! actually routes the protocol being advertised. Advertising `#tsp` against a
//! mediator that does not route TSP produces a service entry clients will
//! choose and cannot use — the same shape of failure as advertising a
//! transport the binary cannot serve. The operator makes that call at setup;
//! `vtc-service` warns at the prompt.

use serde_json::{Value, json};

use crate::protocol::matching::{DIDCOMM_SERVICE_TYPE, TSP_SERVICE_TYPE};

use super::TemplateError;

/// Template variable carrying the whole `DIDCommMessaging` entry.
///
/// Declared in `vtc-host`'s `optionalVars` with a `null` default and placed as
/// a bare array member, so a community provisioned without DIDComm has the
/// element pruned. That null-pruning slot is the only conditional the template
/// format has, which is why the entry is built here in Rust rather than spelled
/// out in the template JSON.
pub const DIDCOMM_SERVICE_VAR: &str = "SERVICE_DIDCOMM";

/// Template variable carrying the whole `TSPTransport` entry. Same
/// null-pruning mechanism as [`DIDCOMM_SERVICE_VAR`].
pub const TSP_SERVICE_VAR: &str = "SERVICE_TSP";

/// Emitted service-id fragment for the DIDComm entry.
///
/// The workspace convention is the bare protocol name — `#didcomm`, not
/// `#vta-didcomm`. Discovery matches on service `type`, never on the fragment,
/// which is an arbitrary label (CLAUDE.md D9); the fragment only has to be
/// stable and readable.
const DIDCOMM_FRAGMENT: &str = "#didcomm";

/// Emitted service-id fragment for the TSP entry. The OWF reference impl uses
/// `#tsp-transport` for the same `type`; both resolve, because nothing matches
/// on the fragment.
const TSP_FRAGMENT: &str = "#tsp";

/// Build the `DIDCommMessaging` entry routing through `mediator_did`.
///
/// Pass the result as [`DIDCOMM_SERVICE_VAR`] in a template's vars map. The
/// `id` carries the literal `{DID}` sentinel: caller-supplied variable values
/// are not re-substituted by the renderer, but `didwebvh-rs` resolves `{DID}`
/// across every leaf string once the SCID is computed, so the entry lands with
/// the community's minted DID.
///
/// # Errors
///
/// [`TemplateError::Invalid`] if `mediator_did` is not a DID. A URL here would
/// render an entry claiming this community hosts a DIDComm endpoint directly,
/// which it does not — the sender's routing layer reads this value as the first
/// hop to resolve, so a URL simply fails to route.
pub fn didcomm_service(mediator_did: &str) -> Result<Value, TemplateError> {
    transport_service(
        mediator_did,
        DIDCOMM_SERVICE_TYPE,
        DIDCOMM_FRAGMENT,
        "DIDComm",
    )
}

/// Build the `TSPTransport` entry routing through `mediator_did`.
///
/// Same shape and the same mediator as [`didcomm_service`] — see the module
/// docs for why both name a DID rather than a URL.
///
/// # Errors
///
/// [`TemplateError::Invalid`] if `mediator_did` is not a DID.
pub fn tsp_service(mediator_did: &str) -> Result<Value, TemplateError> {
    transport_service(mediator_did, TSP_SERVICE_TYPE, TSP_FRAGMENT, "TSP")
}

/// Build the `TSPTransport` entry a **mediator** publishes for *itself*.
///
/// This is the other end of the indirection [`tsp_service`] builds, and it is
/// the inverse shape. A consumer's `#tsp` names its mediator's DID; a
/// mediator's own `#tsp` names the **URL** its TSP transport is served at,
/// because the chain has to terminate somewhere. `forward_tsp_remote` on the
/// sending mediator URL-parses exactly this value for the mediator→mediator
/// hop, so a DID here is unroutable in the same way a URL is unroutable in a
/// consumer's entry.
///
/// Pass the result as [`TSP_SERVICE_VAR`] when rendering `didcomm-mediator`.
/// Without it the template's null-pruning slot drops the entry and the mediator
/// advertises DIDComm only.
///
/// # Errors
///
/// [`TemplateError::Invalid`] if `url` is not an `http(s)` URL — including when
/// it is a DID, which is the confusion this pair of helpers exists to prevent.
pub fn tsp_transport_service(url: &str) -> Result<Value, TemplateError> {
    let url = url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(TemplateError::Invalid(format!(
            "a mediator's own TSP service must name the URL it serves TSP at, got '{url}'. \
             The mediator is the endpoint — a DID here would point at another node to \
             resolve onward, which is the consumer-side shape (see `tsp_service`)."
        )));
    }
    Ok(json!({
        "id": format!("{{DID}}{TSP_FRAGMENT}"),
        "type": TSP_SERVICE_TYPE,
        "serviceEndpoint": url,
    }))
}

fn transport_service(
    mediator_did: &str,
    type_: &str,
    fragment: &str,
    label: &str,
) -> Result<Value, TemplateError> {
    let mediator_did = mediator_did.trim();
    if !mediator_did.starts_with("did:") {
        return Err(TemplateError::Invalid(format!(
            "{label} service must name the mediator by DID, got '{mediator_did}'. The \
             serviceEndpoint is the mediator's DID — the transport URL lives in the \
             mediator's own document — so a URL here renders an entry no sender can route."
        )));
    }
    Ok(json!({
        "id": format!("{{DID}}{fragment}"),
        "type": type_,
        "serviceEndpoint": mediator_did,
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const MEDIATOR: &str = "did:webvh:QmTS3:webvh.example.com:mediator";

    #[test]
    fn didcomm_entry_names_the_mediator_by_did() {
        let e = didcomm_service(MEDIATOR).unwrap();
        assert_eq!(e["id"], "{DID}#didcomm");
        assert_eq!(e["type"], DIDCOMM_SERVICE_TYPE);
        assert_eq!(e["serviceEndpoint"], MEDIATOR);
    }

    #[test]
    fn tsp_entry_names_the_mediator_by_did() {
        let e = tsp_service(MEDIATOR).unwrap();
        assert_eq!(e["id"], "{DID}#tsp");
        assert_eq!(e["type"], TSP_SERVICE_TYPE);
        assert_eq!(e["serviceEndpoint"], MEDIATOR);
    }

    /// Both transports bind the *same* mediator (§14 Q2) — one dual-protocol
    /// mediator, advertised twice under two types. A change that started
    /// deriving one endpoint from the other would break that.
    #[test]
    fn both_transports_bind_the_same_mediator() {
        assert_eq!(
            didcomm_service(MEDIATOR).unwrap()["serviceEndpoint"],
            tsp_service(MEDIATOR).unwrap()["serviceEndpoint"]
        );
    }

    /// A URL is refused for both. The endpoint is read by the sender's routing
    /// layer as `route[0]` — a DID to resolve onward — so a URL is not a
    /// degraded entry, it is an unroutable one.
    #[test]
    fn a_url_endpoint_is_refused() {
        for build in [
            didcomm_service as fn(&str) -> Result<Value, TemplateError>,
            tsp_service,
        ] {
            let err = build("https://mediator.example.com").unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("by DID"), "must say what is wrong: {msg}");
        }
    }

    #[test]
    fn surrounding_whitespace_does_not_defeat_the_did_check() {
        let e = tsp_service(&format!("  {MEDIATOR}  ")).unwrap();
        assert_eq!(e["serviceEndpoint"], MEDIATOR);
    }

    #[test]
    fn an_empty_mediator_is_refused() {
        assert!(didcomm_service("").is_err());
        assert!(tsp_service("   ").is_err());
    }

    /// A mediator's own entry is the inverse shape: the URL it serves TSP at,
    /// because the mediator is where the indirection terminates.
    #[test]
    fn a_mediators_own_tsp_entry_names_its_url() {
        let e = tsp_transport_service("https://mediator.example.com").unwrap();
        assert_eq!(e["id"], "{DID}#tsp");
        assert_eq!(e["type"], TSP_SERVICE_TYPE);
        assert_eq!(e["serviceEndpoint"], "https://mediator.example.com");

        // Same `{DID}` late-substitution contract as the consumer entry.
        assert!(e["id"].as_str().unwrap().starts_with("{DID}"));
        // And the same whitespace tolerance.
        assert_eq!(
            tsp_transport_service("  https://mediator.example.com  ").unwrap()["serviceEndpoint"],
            "https://mediator.example.com"
        );
    }

    /// The two helpers refuse each other's argument. Handing a mediator DID to
    /// the mediator-side builder is the likelier slip — it is the value in
    /// scope at every call site — and it would publish a mediator that points
    /// at itself for onward resolution.
    #[test]
    fn the_two_tsp_shapes_refuse_each_others_input() {
        let err = tsp_transport_service(MEDIATOR).unwrap_err().to_string();
        assert!(err.contains("URL it serves TSP at"), "got: {err}");
        assert!(
            err.contains("tsp_service"),
            "must point at the other helper: {err}"
        );

        let err = tsp_service("https://mediator.example.com")
            .unwrap_err()
            .to_string();
        assert!(err.contains("by DID"), "got: {err}");
    }

    #[test]
    fn a_mediator_tsp_entry_refuses_empty_and_non_http() {
        assert!(tsp_transport_service("").is_err());
        assert!(tsp_transport_service("   ").is_err());
        assert!(tsp_transport_service("wss://mediator.example.com/ws").is_err());
        assert!(tsp_transport_service("mediator.example.com").is_err());
    }

    /// The `{DID}` sentinel must survive verbatim into the rendered entry —
    /// `didwebvh-rs` resolves it after the SCID exists. A helper that
    /// interpolated a real DID here would emit an id that cannot match the
    /// document it lands in.
    #[test]
    fn the_id_carries_the_did_sentinel_for_late_substitution() {
        assert!(
            tsp_service(MEDIATOR).unwrap()["id"]
                .as_str()
                .unwrap()
                .starts_with("{DID}")
        );
    }
}
