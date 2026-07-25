//! Thin wrapper over [`crate::session::resolve_vta_endpoint`] that presents
//! a flat result type and distinguishes "TSP" / "DIDComm" / "REST" / several
//! at once, for downstream consumers.

use crate::session::{VtaEndpoint, resolve_vta_endpoint};

use super::error::ProvisionError;

/// Everything a VTA's DID document advertises, flattened.
///
/// Deliberately **not** "the transport we chose": every field is independently
/// populated, so a *probe* can report what a VTA offers without that being what
/// it connected over. A UI panel needs exactly this split — conflating the two
/// is what made a TSP-enabled VTA render as "DIDComm · only transport offered".
#[derive(Clone, Debug, Default)]
pub struct ResolvedVta {
    pub vta_did: String,
    /// TSP mediator DID advertised via the `#tsp` (`TSPTransport`) service, if
    /// any. Read from that entry — *not* assumed to equal `mediator_did`, even
    /// though a dual-transport VTA usually points both at one mediator.
    pub tsp_mediator_did: Option<String>,
    /// DIDComm mediator DID advertised in the VTA document, if any.
    pub mediator_did: Option<String>,
    /// REST URL advertised via the `#vta-rest` service, if any.
    pub rest_url: Option<String>,
}

impl ResolvedVta {
    /// Every transport this VTA advertises, in preference order — what a probe
    /// prints as "transports offered".
    #[must_use]
    pub fn advertised(&self) -> Vec<crate::protocol::matching::Protocol> {
        use crate::protocol::matching::Protocol;
        let mut out = Vec::with_capacity(3);
        if self.tsp_mediator_did.is_some() {
            out.push(Protocol::Tsp);
        }
        if self.mediator_did.is_some() {
            out.push(Protocol::Didcomm);
        }
        if self.rest_url.is_some() {
            out.push(Protocol::Rest);
        }
        out
    }
}

/// Resolve a VTA DID and extract its transport endpoints.
///
/// Returns an error if the DID cannot be resolved and no fallback URL can
/// be inferred from the DID string.
pub async fn resolve_vta(vta_did: &str) -> Result<ResolvedVta, ProvisionError> {
    match resolve_vta_endpoint(vta_did)
        .await
        .map_err(|e| ProvisionError::Resolve {
            vta_did: vta_did.to_string(),
            message: e.to_string(),
        })? {
        VtaEndpoint::Tsp {
            vta_did,
            mediator_did,
            didcomm_mediator_did,
            rest_url,
        } => Ok(ResolvedVta {
            vta_did,
            tsp_mediator_did: Some(mediator_did),
            mediator_did: didcomm_mediator_did,
            rest_url,
        }),
        VtaEndpoint::DIDComm {
            vta_did,
            mediator_did,
            rest_url,
        } => Ok(ResolvedVta {
            vta_did,
            tsp_mediator_did: None,
            mediator_did: Some(mediator_did),
            rest_url,
        }),
        VtaEndpoint::Rest { url } => Ok(ResolvedVta {
            vta_did: vta_did.to_string(),
            tsp_mediator_did: None,
            mediator_did: None,
            rest_url: Some(url),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::matching::Protocol;

    fn resolved(tsp: Option<&str>, didcomm: Option<&str>, rest: Option<&str>) -> ResolvedVta {
        ResolvedVta {
            vta_did: "did:webvh:scid:vta.example".into(),
            tsp_mediator_did: tsp.map(str::to_string),
            mediator_did: didcomm.map(str::to_string),
            rest_url: rest.map(str::to_string),
        }
    }

    /// The split this type exists for: a probe reports *everything* a VTA
    /// advertises, independently of which transport it would connect over.
    /// Conflating the two is what rendered a TSP-enabled VTA as
    /// "DIDComm · only transport offered".
    #[test]
    fn a_dual_transport_vta_reports_every_transport_it_offers() {
        let r = resolved(
            Some("did:webvh:scid:mediator.example"),
            Some("did:webvh:scid:mediator.example"),
            Some("https://vta.example"),
        );
        assert_eq!(
            r.advertised(),
            vec![Protocol::Tsp, Protocol::Didcomm, Protocol::Rest]
        );
    }

    /// TSP is reported even when it is the *only* transport — the shape that
    /// previously resolved to a REST URL guessed from the DID's own domain.
    #[test]
    fn a_tsp_only_vta_reports_tsp() {
        let r = resolved(Some("did:webvh:scid:mediator.example"), None, None);
        assert_eq!(r.advertised(), vec![Protocol::Tsp]);
    }

    #[test]
    fn advertised_is_in_preference_order() {
        let r = resolved(None, Some("did:webvh:scid:m"), Some("https://vta.example"));
        assert_eq!(r.advertised(), vec![Protocol::Didcomm, Protocol::Rest]);
    }

    #[test]
    fn a_vta_advertising_nothing_reports_nothing() {
        assert!(resolved(None, None, None).advertised().is_empty());
    }
}
