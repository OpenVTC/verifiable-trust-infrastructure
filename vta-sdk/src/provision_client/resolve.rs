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
    flatten(
        vta_did,
        resolve_vta_endpoint(vta_did)
            .await
            .map_err(|e| ProvisionError::Resolve {
                vta_did: vta_did.to_string(),
                message: e.to_string(),
            })?,
    )
}

/// [`resolve_vta`] over an **existing** resolver.
///
/// The probing counterpart of
/// [`resolve_vta_endpoint_with_resolver`](crate::session::resolve_vta_endpoint_with_resolver):
/// same flattened `ResolvedVta`, but discovery runs against a resolver the
/// caller supplies. A consumer testing "does the panel report `#tsp` when the
/// VTA advertises it" seeds a document and calls this; against the
/// env-configured entry point that assertion needs a live deployment.
pub async fn resolve_vta_with_resolver(
    vta_did: &str,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
) -> Result<ResolvedVta, ProvisionError> {
    flatten(
        vta_did,
        crate::session::resolve_vta_endpoint_with_resolver(vta_did, resolver)
            .await
            .map_err(|e| ProvisionError::Resolve {
                vta_did: vta_did.to_string(),
                message: e.to_string(),
            })?,
    )
}

/// Flatten a [`VtaEndpoint`] into the independently-populated [`ResolvedVta`].
///
/// Shared so the two entry points cannot disagree about what a given endpoint
/// shape means — the split that keeps "what is advertised" separate from "what
/// we connected over".
fn flatten(vta_did: &str, endpoint: VtaEndpoint) -> Result<ResolvedVta, ProvisionError> {
    match endpoint {
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
    /// Both discovery entry points must be exported from `provision_client`
    /// itself, not just from this module.
    ///
    /// #813 added `resolve_vta_with_resolver` to this file but not to
    /// `provision_client`'s curated `pub use` list, so it was reachable only via
    /// `provision_client::resolve::`. This import fails to compile if that
    /// happens again — which is exactly how it was introduced.
    ///
    /// Deliberately a unit test rather than a `tests/` file: an integration test
    /// is a separate binary, and in a workspace this size each one links hundreds
    /// of rlibs. The first version of this guard was a `tests/reexport_check.rs`
    /// and the CI Test job ran the runner out of disk.
    #[allow(unused_imports)]
    use crate::provision_client::{resolve_vta, resolve_vta_with_resolver};

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

/// Discovery against a **seeded** resolver — the assertions that were previously
/// only provable against a live deployment.
///
/// `resolve_vta` builds its resolver from the environment, so before
/// [`resolve_vta_with_resolver`] a consumer could not point discovery at a
/// fixture: seeding a document into its own cache did nothing, because the
/// function never saw that cache. These run in-process with no network.
#[cfg(test)]
mod seeded_discovery_tests {
    use super::*;
    use crate::protocol::matching::Protocol;
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use serde_json::json;

    const VTA: &str = "did:web:vta.example";
    const MEDIATOR: &str = "did:web:mediator.example";
    const REST: &str = "https://vta.example/api";

    /// A resolver holding exactly `doc` for [`VTA`], resolving offline.
    async fn resolver_serving(doc: serde_json::Value) -> DIDCacheClient {
        let mut client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("local DID cache");
        client
            .add_did_document(
                VTA,
                serde_json::from_value(doc).expect("fixture document deserializes"),
            )
            .await;
        client
    }

    fn document(services: serde_json::Value) -> serde_json::Value {
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": VTA,
            "service": services,
        })
    }

    /// The shape the reference deployment actually has: `#tsp` and
    /// `#vta-didcomm` pointing at the **same** mediator. This is what a consumer
    /// needs to be able to assert without a live VTA.
    #[tokio::test]
    async fn a_tsp_advertising_vta_is_discovered_as_tsp() {
        let resolver = resolver_serving(document(json!([
            { "id": format!("{VTA}#tsp"), "type": "TSPTransport", "serviceEndpoint": MEDIATOR },
            { "id": format!("{VTA}#vta-didcomm"), "type": "DIDCommMessaging", "serviceEndpoint": MEDIATOR },
        ])))
        .await;

        let resolved = resolve_vta_with_resolver(VTA, &resolver)
            .await
            .expect("the seeded document resolves");

        assert_eq!(resolved.tsp_mediator_did.as_deref(), Some(MEDIATOR));
        assert_eq!(resolved.mediator_did.as_deref(), Some(MEDIATOR));
        assert_eq!(
            resolved.advertised(),
            vec![Protocol::Tsp, Protocol::Didcomm],
            "both transports are reported, in preference order"
        );
    }

    /// A VTA advertising no `#tsp` must not report one — the other direction,
    /// and the one a panel would misreport if discovery guessed.
    #[tokio::test]
    async fn a_didcomm_only_vta_advertises_no_tsp() {
        let resolver = resolver_serving(document(json!([
            { "id": format!("{VTA}#vta-didcomm"), "type": "DIDCommMessaging", "serviceEndpoint": MEDIATOR },
            { "id": format!("{VTA}#vta-rest"), "type": "VTARest", "serviceEndpoint": REST },
        ])))
        .await;

        let resolved = resolve_vta_with_resolver(VTA, &resolver)
            .await
            .expect("the seeded document resolves");

        assert_eq!(resolved.tsp_mediator_did, None);
        assert_eq!(
            resolved.advertised(),
            vec![Protocol::Didcomm, Protocol::Rest]
        );
    }

    /// A TSP-only node — the shape this crate ships `did-host-tsp` templates for.
    /// It must not fall through to a REST URL synthesized from the DID's domain,
    /// which is the bug the endpoint doc calls out.
    #[tokio::test]
    async fn a_tsp_only_vta_does_not_fall_back_to_a_guessed_rest_url() {
        let resolver = resolver_serving(document(json!([
            { "id": format!("{VTA}#tsp"), "type": "TSPTransport", "serviceEndpoint": MEDIATOR },
        ])))
        .await;

        let resolved = resolve_vta_with_resolver(VTA, &resolver)
            .await
            .expect("the seeded document resolves");

        assert_eq!(resolved.tsp_mediator_did.as_deref(), Some(MEDIATOR));
        assert_eq!(resolved.rest_url, None, "no URL was invented");
        assert_eq!(resolved.advertised(), vec![Protocol::Tsp]);
    }

    /// A `#tsp` entry whose endpoint is a URL rather than a mediator DID is a
    /// misconfiguration, not a routable TSP endpoint, and must be ignored rather
    /// than handed onward.
    #[tokio::test]
    async fn a_non_did_tsp_endpoint_is_not_treated_as_a_mediator() {
        let resolver = resolver_serving(document(json!([
            { "id": format!("{VTA}#tsp"), "type": "TSPTransport", "serviceEndpoint": "https://not-a-did.example" },
            { "id": format!("{VTA}#vta-didcomm"), "type": "DIDCommMessaging", "serviceEndpoint": MEDIATOR },
        ])))
        .await;

        let resolved = resolve_vta_with_resolver(VTA, &resolver)
            .await
            .expect("the seeded document resolves");

        assert_eq!(resolved.tsp_mediator_did, None);
        assert_eq!(resolved.mediator_did.as_deref(), Some(MEDIATOR));
    }
}
