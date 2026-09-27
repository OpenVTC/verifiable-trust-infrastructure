//! How this VTA reaches a DID hosting service, read from the service's DID
//! document. Pure (no resolver, no async, no I/O) so it can be unit-tested
//! with stub service entries.
//!
//! ## Every call is a Trust Task
//!
//! The hosting service serves its whole DID-management surface as Trust Tasks
//! over TSP, DIDComm and HTTPS (affinidi-webvh-service #217, #218), so there
//! is one client and the transport is `operations::outbound`'s choice, in the
//! workspace order TSP > DIDComm > HTTPS. This module answers two narrower
//! questions:
//!
//! 1. **Can the seam reach the host at all?** Yes when it advertises
//!    `TSPTransport`, `DIDCommMessaging`, `TrustTaskHTTPS` or `WebVHHosting`.
//! 2. **Where is its HTTPS binding when it does not advertise one?** The
//!    hosting service serves `POST /api/trust-tasks` at the origin its
//!    `WebVHHosting` service names, so the Trust-Task HTTPS base is
//!    `{uri}/api`. An advertised `TrustTaskHTTPS` endpoint wins over this;
//!    the seam only uses it to fill the empty slot
//!    (`Outbound::with_https_base`). The origin must be `https://`; plain
//!    `http://` is accepted only to a loopback host (localhost, 127/8, ::1),
//!    as the retired REST client required, so a signed request never
//!    crosses a network in the clear.
//!
//! Replies are required to carry the host's proof whichever transport carried
//! them (`ReplyTrust::SignedByRecipient`), so reaching the host over HTTPS,
//! where TLS authenticates a hostname rather than a DID, claims no more than
//! the sealing transports do.
//!
//! ## `hostingPath` is not the base
//!
//! The `did-host-http*` templates used to stamp a `hostingPath` beside `uri`
//! in the `WebVHHosting` endpoint. No server ever read it back, and the
//! hosting service nests its whole API at `/api` off the origin root, so the
//! base is `serviceEndpoint.uri` alone (#756, #759).

/// `TSPTransport`, from the module the seam reads.
pub(crate) const SVC_TSP: &str = vta_sdk::protocol::matching::TSP_SERVICE_TYPE;

/// `DIDCommMessaging`, from the module the seam reads.
pub(crate) const SVC_DIDCOMM: &str = vta_sdk::protocol::matching::DIDCOMM_SERVICE_TYPE;

/// `TrustTaskHTTPS`, from the module the seam reads.
pub(crate) const SVC_TRUST_TASK_HTTPS: &str =
    vta_sdk::protocol::matching::TRUST_TASK_HTTPS_SERVICE_TYPE;

/// The service type the hosting service publishes for the origin it serves
/// DID documents and its API from.
pub(crate) const SVC_WEBVH_HOSTING: &str = "WebVHHosting";

/// Where the hosting service mounts its Trust-Task HTTPS binding under the
/// `WebVHHosting` origin: requests go to `{origin}/api/trust-tasks`.
const HOSTING_TRUST_TASK_BASE_PATH: &str = "/api";

/// Minimal abstraction over a DID-document service entry, sufficient for
/// reachability. Implemented for `affinidi_did_common::Service` below; tests
/// construct stub values.
pub(crate) trait ServiceEntry {
    fn types(&self) -> &[String];
    fn endpoint_uri(&self) -> Option<String>;
}

/// How the seam reaches a hosting service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostReach {
    /// The Trust-Task HTTPS base derived from `WebVHHosting`, used only when
    /// the host advertises no `TrustTaskHTTPS` endpoint.
    pub https_base: Option<String>,
}

/// Walk `services` and decide whether, and how, the seam can reach this host.
///
/// `None` when it advertises nothing the seam can carry a Trust Task over; the
/// caller surfaces an `AppError::Validation` naming the server DID.
///
/// A `WebVHHosting` URI is stripped of surrounding double quotes (some JSON-LD
/// serialisers emit them) and one trailing `/` before the base path is added.
pub(crate) fn resolve_host_reach<S: ServiceEntry>(services: &[S]) -> Option<HostReach> {
    let https_base = services
        .iter()
        .filter(|s| s.types().iter().any(|t| t == SVC_WEBVH_HOSTING))
        .filter_map(|s| s.endpoint_uri())
        .map(|raw| raw.trim_matches('"').trim_end_matches('/').to_string())
        .find(|origin| origin_is_secure(origin))
        .map(|origin| format!("{origin}{HOSTING_TRUST_TASK_BASE_PATH}"));
    let seam = services.iter().any(|s| {
        s.types()
            .iter()
            .any(|t| t == SVC_TSP || t == SVC_DIDCOMM || t == SVC_TRUST_TASK_HTTPS)
    });
    (seam || https_base.is_some()).then_some(HostReach { https_base })
}

/// `https://`, or `http://` to a loopback host.
fn origin_is_secure(origin: &str) -> bool {
    let Ok(url) = url::Url::parse(origin) else {
        return false;
    };
    match url.scheme() {
        "https" => url.host().is_some(),
        "http" => match url.host() {
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        },
        _ => false,
    }
}

/// Human-readable description of the accepted service types, for the
/// refusal an operator sees when a server advertises none of them.
pub(crate) const SUPPORTED_TYPES_HUMAN: &str =
    "TSPTransport, DIDCommMessaging, TrustTaskHTTPS, or WebVHHosting at an https:// origin";

impl ServiceEntry for affinidi_tdk::did_common::service::Service {
    fn types(&self) -> &[String] {
        &self.type_
    }
    fn endpoint_uri(&self) -> Option<String> {
        self.service_endpoint.get_uri()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestService {
        types: Vec<String>,
        uri: Option<String>,
    }
    impl TestService {
        fn new(types: &[&str], uri: Option<&str>) -> Self {
            Self {
                types: types.iter().map(|s| s.to_string()).collect(),
                uri: uri.map(String::from),
            }
        }
    }
    impl ServiceEntry for TestService {
        fn types(&self) -> &[String] {
            &self.types
        }
        fn endpoint_uri(&self) -> Option<String> {
            self.uri.clone()
        }
    }

    fn reach(services: &[TestService]) -> Option<HostReach> {
        resolve_host_reach(services)
    }

    fn base(url: &str) -> Option<HostReach> {
        Some(HostReach {
            https_base: Some(url.to_string()),
        })
    }

    /// The verbatim `WebVHHosting` entry `webvh.storm.ws` publishes: the base
    /// is the origin plus `/api`, and `hostingPath` is ignored (#756/#759).
    #[test]
    fn the_live_hosting_entry_yields_the_origin_api_base() {
        let svc: affinidi_tdk::did_common::service::Service = serde_json::from_str(
            r#"{
                "id": "did:webvh:QmUcyd...:webvh.storm.ws#webvh-hosting",
                "type": "WebVHHosting",
                "serviceEndpoint": { "hostingPath": "/webvh", "uri": "https://webvh.storm.ws" }
            }"#,
        )
        .expect("the live WebVHHosting entry parses");
        assert_eq!(
            resolve_host_reach(std::slice::from_ref(&svc)),
            base("https://webvh.storm.ws/api")
        );
    }

    #[test]
    fn the_service_types_are_the_sdk_ones() {
        assert_eq!(SVC_TSP, "TSPTransport");
        assert_eq!(SVC_DIDCOMM, "DIDCommMessaging");
        assert_eq!(SVC_TRUST_TASK_HTTPS, "TrustTaskHTTPS");
    }

    #[test]
    fn nothing_the_seam_can_use_is_unreachable() {
        assert_eq!(reach(&[]), None);
        assert_eq!(
            reach(&[TestService::new(&["LinkedDomains"], Some("https://x"))]),
            None
        );
        // The retired alias names nothing any more: test deployments are
        // recreated, not migrated.
        assert_eq!(
            reach(&[TestService::new(
                &["WebVHHostingService"],
                Some("https://x")
            )]),
            None
        );
    }

    #[test]
    fn a_sealing_transport_alone_reaches_the_host_with_no_https_base() {
        for t in [SVC_TSP, SVC_DIDCOMM, SVC_TRUST_TASK_HTTPS] {
            assert_eq!(
                reach(&[TestService::new(&[t], Some("did:example:mediator"))]),
                Some(HostReach { https_base: None }),
                "{t}"
            );
        }
    }

    /// The hosting service advertises TSP, DIDComm and `WebVHHosting`: the
    /// seam picks TSP; the HTTPS base is carried for when it cannot.
    #[test]
    fn the_hosting_service_shape_carries_its_https_base() {
        let services = vec![
            TestService::new(&[SVC_TSP], Some("did:example:mediator")),
            TestService::new(&[SVC_DIDCOMM], Some("did:example:mediator")),
            TestService::new(&[SVC_WEBVH_HOSTING], Some("https://host.example")),
        ];
        assert_eq!(reach(&services), base("https://host.example/api"));
    }

    #[test]
    fn the_hosting_origin_is_normalised() {
        for raw in [
            "https://host.example",
            "https://host.example/",
            "\"https://host.example\"",
            "\"https://host.example/\"",
        ] {
            assert_eq!(
                reach(&[TestService::new(&[SVC_WEBVH_HOSTING], Some(raw))]),
                base("https://host.example/api"),
                "{raw}"
            );
        }
    }

    #[test]
    fn a_hosting_entry_without_a_usable_uri_is_skipped() {
        assert_eq!(reach(&[TestService::new(&[SVC_WEBVH_HOSTING], None)]), None);
        assert_eq!(
            reach(&[
                TestService::new(&[SVC_WEBVH_HOSTING], Some("\"\"")),
                TestService::new(&[SVC_WEBVH_HOSTING], Some("https://second.example")),
            ]),
            base("https://second.example/api")
        );
    }

    /// A signed request never crosses a network in the clear: plain `http://`
    /// is refused except to a loopback host, and so is any other scheme.
    #[test]
    fn a_plaintext_hosting_origin_is_refused_off_loopback() {
        for raw in [
            "http://host.example",
            "http://10.0.0.5:8080",
            "ftp://host.example",
            "not a url",
        ] {
            assert_eq!(
                reach(&[TestService::new(&[SVC_WEBVH_HOSTING], Some(raw))]),
                None,
                "{raw}"
            );
        }
        for (raw, expected) in [
            ("http://127.0.0.1:8530", "http://127.0.0.1:8530/api"),
            ("http://localhost:8530", "http://localhost:8530/api"),
            ("http://[::1]:8530", "http://[::1]:8530/api"),
        ] {
            assert_eq!(
                reach(&[TestService::new(&[SVC_WEBVH_HOSTING], Some(raw))]),
                base(expected),
                "{raw}"
            );
        }
        // A plaintext origin beside a sealing transport: the host is still
        // reachable, just not over HTTPS.
        assert_eq!(
            reach(&[
                TestService::new(&[SVC_DIDCOMM], Some("did:example:mediator")),
                TestService::new(&[SVC_WEBVH_HOSTING], Some("http://host.example")),
            ]),
            Some(HostReach { https_base: None })
        );
    }

    #[test]
    fn a_multi_typed_entry_matches_any_type() {
        assert_eq!(
            reach(&[TestService::new(
                &["LinkedDomains", SVC_WEBVH_HOSTING],
                Some("https://host.example")
            )]),
            base("https://host.example/api")
        );
    }
}
