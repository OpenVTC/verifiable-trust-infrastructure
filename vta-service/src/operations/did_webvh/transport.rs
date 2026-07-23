//! Pure transport-resolution logic for WebVH hosting servers.
//!
//! Walks a server DID's service array and decides whether the VTA
//! should talk to it via DIDComm or REST, and — for REST — which URL
//! to dial. Kept pure (no resolver, no async, no I/O) so it can be
//! unit-tested with stub service entries instead of a live
//! `DIDCacheClient`.
//!
//! ## Accepted service types
//!
//! - `DIDCommMessaging` — preferred when present, regardless of
//!   position in the service array.
//! - `WebVHHosting` — the canonical type emitted by current
//!   `did-hosting-daemon` / `did-hosting-server` builds.
//! - `WebVHHostingService` — legacy alias accepted on **read only**.
//!   We never emit it; existing daemon DIDs stamped before the
//!   unification keep working.
//!
//! ## DIDComm precedence
//!
//! Workspace-wide invariant: when a DID advertises both transports,
//! Service[] is canonically ordered DIDComm-first (see
//! `protocol::document::sort_services_canonical`). We don't rely on
//! that ordering for *reading* foreign DIDs though — any DIDComm
//! entry, wherever it sits, wins over every REST entry. This keeps
//! third-party DIDs that emit non-canonical orderings working
//! without surprising the operator.

/// Service-type string emitted on DIDComm endpoints (per DIDComm v2).
pub(crate) const SVC_DIDCOMM: &str = "DIDCommMessaging";

/// Service-type string emitted on current WebVH-host endpoints.
pub(crate) const SVC_WEBVH_HOSTING: &str = "WebVHHosting";

/// Legacy alias for [`SVC_WEBVH_HOSTING`]. Accepted on read; never
/// emitted by this workspace.
pub(crate) const SVC_WEBVH_HOSTING_LEGACY: &str = "WebVHHostingService";

/// Minimal abstraction over a DID-document service entry, sufficient
/// for transport resolution. Implemented for
/// `affinidi_did_common::Service` in `mod.rs`; tests construct stub
/// values.
pub(crate) trait ServiceEntry {
    fn types(&self) -> &[String];
    fn endpoint_uri(&self) -> Option<String>;
}

/// Outcome of walking a server's service array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolvedTransport {
    DIDComm,
    Rest { url: String },
}

/// Walk `services` and decide how the VTA should talk to this server.
///
/// Returns `None` if no usable service is advertised; the caller
/// surfaces an `AppError::Validation` so the operator sees the
/// specific server DID.
///
/// REST URLs returned here are stripped of:
/// - surrounding double-quotes — some JSON-LD serialisers emit
///   `"https://host"` (quotes included) for `serviceEndpoint`,
/// - one trailing `/` — to keep the per-route `format!("{base}/api/…")`
///   helpers from producing double slashes.
pub(crate) fn resolve_server_transport<S: ServiceEntry>(
    services: &[S],
) -> Option<ResolvedTransport> {
    if services.iter().any(|s| s.types().iter().any(is_didcomm)) {
        return Some(ResolvedTransport::DIDComm);
    }
    for svc in services {
        if svc.types().iter().any(is_webvh_rest)
            && let Some(raw) = svc.endpoint_uri()
        {
            let url = raw.trim_matches('"').trim_end_matches('/').to_string();
            if url.is_empty() {
                continue;
            }
            return Some(ResolvedTransport::Rest { url });
        }
    }
    None
}

/// The REST endpoint a server advertises, if any — **regardless** of whether it
/// also advertises DIDComm.
///
/// [`resolve_server_transport`] returns as soon as it sees a DIDComm service,
/// which is right for the operations both transports implement. Agent-name
/// operations are not among them: the hosting server's transport-agnostic
/// DIDComm dispatch table carries no agent-name verbs, so they exist over REST
/// alone.
///
/// A deployed hosting server normally advertises `WebVHHosting` *and*
/// `DIDCommMessaging` together. Without this, the DIDComm preference hides the
/// REST endpoint sitting in the same document, and an agent-name call fails on
/// a server that is perfectly able to serve it.
pub(crate) fn resolve_rest_endpoint<S: ServiceEntry>(services: &[S]) -> Option<String> {
    services.iter().find_map(|svc| {
        if !svc.types().iter().any(is_webvh_rest) {
            return None;
        }
        let url = svc
            .endpoint_uri()?
            .trim_matches('"')
            .trim_end_matches('/')
            .to_string();
        (!url.is_empty()).then_some(url)
    })
}

#[inline]
fn is_didcomm(t: &String) -> bool {
    t == SVC_DIDCOMM
}

#[inline]
fn is_webvh_rest(t: &String) -> bool {
    t == SVC_WEBVH_HOSTING || t == SVC_WEBVH_HOSTING_LEGACY
}

/// Human-readable description of accepted service types. Used in
/// the `validate_server_did` failure message so operators see the
/// full accepted set at the point of rejection.
pub(crate) const SUPPORTED_TYPES_HUMAN: &str =
    "DIDCommMessaging, WebVHHosting, or WebVHHostingService (legacy)";

// ── ServiceEntry impl for the resolver's concrete Service type ─────
//
// Lets `resolve_server_transport(&doc.service)` work without an
// adaptor at the call site. We reach the type through the
// `affinidi_tdk` umbrella — that's the path the workspace already
// uses for adjacent resolver types, and it spares us from adding
// `affinidi-did-common` as a direct dependency just for this impl.
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

    // ── resolve_rest_endpoint ───────────────────────────────────────

    /// The case that motivated this: a server advertising BOTH transports.
    /// `resolve_server_transport` picks DIDComm, and the REST endpoint must
    /// still be discoverable — agent-name operations exist only over REST.
    #[test]
    fn rest_endpoint_is_found_even_when_didcomm_is_advertised() {
        let services = vec![
            TestService::new(&["WebVHHosting"], Some("https://host.example/")),
            TestService::new(&["DIDCommMessaging"], Some("did:webvh:QmMED:med.example")),
        ];
        // DIDComm still wins for transport selection...
        assert!(matches!(
            resolve_server_transport(&services),
            Some(ResolvedTransport::DIDComm)
        ));
        // ...but the REST endpoint is not hidden by that preference.
        assert_eq!(
            resolve_rest_endpoint(&services).as_deref(),
            Some("https://host.example")
        );
    }

    /// Order must not matter — the DIDComm entry may come first.
    #[test]
    fn rest_endpoint_is_order_independent() {
        let services = vec![
            TestService::new(&["DIDCommMessaging"], Some("did:webvh:QmMED:med.example")),
            TestService::new(&["WebVHHosting"], Some("https://host.example")),
        ];
        assert_eq!(
            resolve_rest_endpoint(&services).as_deref(),
            Some("https://host.example")
        );
    }

    /// The legacy service type is accepted here too, matching
    /// `resolve_server_transport`.
    #[test]
    fn rest_endpoint_accepts_the_legacy_type() {
        let services = vec![TestService::new(
            &["WebVHHostingService"],
            Some("https://legacy.example"),
        )];
        assert_eq!(
            resolve_rest_endpoint(&services).as_deref(),
            Some("https://legacy.example")
        );
    }

    /// A DIDComm-only server genuinely has nowhere to send an agent-name call,
    /// and must report that rather than inventing an endpoint.
    #[test]
    fn rest_endpoint_is_none_for_a_didcomm_only_server() {
        let services = vec![TestService::new(
            &["DIDCommMessaging"],
            Some("did:webvh:QmMED:med.example"),
        )];
        assert_eq!(resolve_rest_endpoint(&services), None);
    }

    /// An advertised-but-empty URI is not an endpoint.
    #[test]
    fn rest_endpoint_ignores_an_empty_uri() {
        let services = vec![TestService::new(&["WebVHHosting"], Some(""))];
        assert_eq!(resolve_rest_endpoint(&services), None);
    }

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

    #[test]
    fn empty_service_list_yields_none() {
        let services: Vec<TestService> = vec![];
        assert_eq!(resolve_server_transport(&services), None);
    }

    #[test]
    fn unsupported_service_type_yields_none() {
        // A DID with services but none we can talk to — operator
        // sees a "no supported service" error upstream.
        let services = vec![TestService::new(&["LinkedDomains"], Some("https://x"))];
        assert_eq!(resolve_server_transport(&services), None);
    }

    #[test]
    fn didcomm_only_resolves_to_didcomm() {
        let services = vec![TestService::new(&[SVC_DIDCOMM], None)];
        assert_eq!(
            resolve_server_transport(&services),
            Some(ResolvedTransport::DIDComm)
        );
    }

    #[test]
    fn webvh_hosting_canonical_resolves_to_rest() {
        // The canonical type emitted by current daemon builds.
        let services = vec![TestService::new(
            &[SVC_WEBVH_HOSTING],
            Some("https://daemon.example"),
        )];
        assert_eq!(
            resolve_server_transport(&services),
            Some(ResolvedTransport::Rest {
                url: "https://daemon.example".into()
            })
        );
    }

    #[test]
    fn webvh_hosting_service_legacy_alias_accepted() {
        // Older daemon deployments emit WebVHHostingService. We
        // never emit it ourselves but tolerate it on read so
        // pre-unification DIDs keep working.
        let services = vec![TestService::new(
            &[SVC_WEBVH_HOSTING_LEGACY],
            Some("https://legacy.example"),
        )];
        assert_eq!(
            resolve_server_transport(&services),
            Some(ResolvedTransport::Rest {
                url: "https://legacy.example".into()
            })
        );
    }

    #[test]
    fn didcomm_wins_when_listed_first() {
        let services = vec![
            TestService::new(&[SVC_DIDCOMM], None),
            TestService::new(&[SVC_WEBVH_HOSTING], Some("https://x")),
        ];
        assert_eq!(
            resolve_server_transport(&services),
            Some(ResolvedTransport::DIDComm)
        );
    }

    #[test]
    fn didcomm_wins_when_listed_after_rest() {
        // The canonical ordering puts DIDComm first, but third-party
        // DIDs may not honour that. Walk the array twice rather than
        // trust the order.
        let services = vec![
            TestService::new(&[SVC_WEBVH_HOSTING], Some("https://x")),
            TestService::new(&[SVC_DIDCOMM], None),
        ];
        assert_eq!(
            resolve_server_transport(&services),
            Some(ResolvedTransport::DIDComm)
        );
    }

    #[test]
    fn rest_url_strips_surrounding_quotes() {
        let services = vec![TestService::new(
            &[SVC_WEBVH_HOSTING],
            Some("\"https://daemon.example\""),
        )];
        assert_eq!(
            resolve_server_transport(&services),
            Some(ResolvedTransport::Rest {
                url: "https://daemon.example".into()
            })
        );
    }

    #[test]
    fn rest_url_strips_trailing_slash() {
        let services = vec![TestService::new(
            &[SVC_WEBVH_HOSTING],
            Some("https://daemon.example/"),
        )];
        assert_eq!(
            resolve_server_transport(&services),
            Some(ResolvedTransport::Rest {
                url: "https://daemon.example".into()
            })
        );
    }

    #[test]
    fn rest_url_strips_quotes_and_trailing_slash_together() {
        let services = vec![TestService::new(
            &[SVC_WEBVH_HOSTING],
            Some("\"https://daemon.example/\""),
        )];
        assert_eq!(
            resolve_server_transport(&services),
            Some(ResolvedTransport::Rest {
                url: "https://daemon.example".into()
            })
        );
    }

    #[test]
    fn rest_entry_without_endpoint_falls_through() {
        // A WebVHHosting entry with no URI shouldn't short-circuit —
        // a later valid entry should still win.
        let services = vec![
            TestService::new(&[SVC_WEBVH_HOSTING], None),
            TestService::new(&[SVC_WEBVH_HOSTING], Some("https://second.example")),
        ];
        assert_eq!(
            resolve_server_transport(&services),
            Some(ResolvedTransport::Rest {
                url: "https://second.example".into()
            })
        );
    }

    #[test]
    fn rest_entry_with_empty_uri_after_trim_is_skipped() {
        // "/" → trims to empty → not usable. Caller should treat as
        // no REST service, fall through to a later entry or None.
        let services = vec![TestService::new(&[SVC_WEBVH_HOSTING], Some("/"))];
        assert_eq!(resolve_server_transport(&services), None);
    }

    #[test]
    fn multi_typed_service_entry_matches_any_type() {
        // A service entry can carry multiple types in `type` (rare
        // but valid per DID-Core). Match if any one of them is a
        // supported type.
        let services = vec![TestService::new(
            &["LinkedDomains", SVC_WEBVH_HOSTING],
            Some("https://multi.example"),
        )];
        assert_eq!(
            resolve_server_transport(&services),
            Some(ResolvedTransport::Rest {
                url: "https://multi.example".into()
            })
        );
    }
}
