//! Does this binary serve the transports its DID document advertises?
//!
//! A DID document is a contract. The workspace rule is *prefer TSP, then
//! DIDComm, then REST* (CLAUDE.md), so a conforming client reads the VTC's
//! document, picks the highest-preference transport it finds, and commits to
//! it. If the VTC advertises a transport its binary cannot serve, every
//! conforming client picks the one path that cannot work — and the more
//! correct the client, the more certainly it fails.
//!
//! That is not hypothetical. A VTC deployed advertising `#tsp`
//! (`TSPTransport`) and no `DIDCommMessaging` at all, built without
//! `--features tsp`, silently dropped every join. The frame never reached the
//! VTC's router: `affinidi-messaging-sdk`'s websocket transport classifies TSP
//! frames only under its own `tsp` feature
//!
//! ```text
//! #[cfg(feature = "tsp")]      let force_packed = atm.tsp().is_tsp(&message);
//! #[cfg(not(feature = "tsp"))] let force_packed = false;
//! ```
//!
//! so without it the CESR frame fell through to the DIDComm unpacker. CESR
//! qb64 streams begin with `-`, which `serde_json` reads as the start of a
//! number, and the operator got
//!
//! ```text
//! Error unpacking message: DidcommError("Cannot parse message as JSON",
//! "invalid number at line 1 column 2")
//! ```
//!
//! — a JSON parse error naming neither TSP nor a missing feature, from a layer
//! *below* [`crate::messaging`]'s own well-written "the `tsp` feature is
//! disabled" warning, which therefore could never fire. Meanwhile the client
//! saw a successful send (R1.1: a DIDComm send `Ok` means "accepted locally").
//!
//! This module makes that state unreachable rather than merely unlikely.
//! [`tsp`](../index.html) is now a default feature of `vtc-service`, so the
//! shipped binary always serves what it may advertise; this check is what
//! holds the invariant for a `--no-default-features` build, and — more
//! importantly — for a document edited *after* mint. The deployed VTC's `#tsp`
//! arrived at DID log version 3, published long after the `vtc-host` template
//! minted versions 1 and 2. No mint-time gate could have caught it, because
//! the VTC never minted it: `vtc-host` emits `#vtc-rest` and
//! `#vtc-status-list` only, and the VTC has no service-management surface of
//! its own. The check therefore runs against the document as it *is*, at
//! startup, not against the document as it was rendered.
//!
//! Per R6.4 the error names the actual failure class — which transport, why it
//! is unservable, and both ways to fix it — so an operator can tell a
//! capability mismatch from a network or auth failure.

use vta_sdk::protocol::matching::{Protocol, ServiceCapabilities};

/// The transports a build with the `tsp` feature serves inbound.
///
/// REST is deliberately absent from both sets: it is not a messaging
/// transport, it is served unconditionally by the axum router, and a `VTCRest`
/// service entry is therefore never a capability claim this check can falsify.
pub const TSP_BUILD: &[Protocol] = &[Protocol::Tsp, Protocol::Didcomm];

/// The transports a build without the `tsp` feature serves inbound.
///
/// DIDComm only — [`crate::messaging`] always compiles its DIDComm dispatch
/// arm, and nothing gates it.
pub const NON_TSP_BUILD: &[Protocol] = &[Protocol::Didcomm];

/// The messaging transports *this* build can serve inbound.
///
/// The one `cfg`-dependent value in this module. Everything else takes the
/// served set as a parameter, which is what lets the tests exercise both
/// builds' behaviour from either build — see the note on
/// [`unservable_against`].
#[must_use]
pub fn served_transports() -> &'static [Protocol] {
    if cfg!(feature = "tsp") {
        TSP_BUILD
    } else {
        NON_TSP_BUILD
    }
}

/// A transport the DID document advertises that this build cannot serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnservableTransport {
    /// The advertised-but-unservable protocol.
    pub protocol: Protocol,
    /// The endpoint the document advertises for it (a mediator DID for
    /// TSP/DIDComm) — quoted back so the operator can find the service entry.
    pub endpoint: String,
}

impl UnservableTransport {
    /// Why this build cannot serve it, and the two ways to fix it.
    ///
    /// R6.4: an operator reading this must be able to tell it apart from a
    /// network failure and from an auth rejection. It names the transport, the
    /// missing build feature, the consequence, and both remediations.
    #[must_use]
    pub fn remediation(&self) -> String {
        match self.protocol {
            Protocol::Tsp => format!(
                "this VTC's DID document advertises a TSP transport (`TSPTransport` -> {}), but \
                 this binary was built without the `tsp` feature and cannot receive TSP frames. \
                 Because the workspace prefers TSP over DIDComm over REST, every conforming \
                 client will choose TSP and every one of its messages will be dropped \
                 undecodable in the messaging SDK's websocket transport, before this service \
                 sees it. Fix by rebuilding with `--features tsp` (it is on by default; a \
                 `--no-default-features` build must add it back), or by removing the \
                 `TSPTransport` service entry from the DID document so clients fall back to a \
                 transport this binary serves.",
                self.endpoint
            ),
            // Not reachable today — DIDComm is unconditional — but stated
            // rather than `unreachable!()`: this runs at startup, and a future
            // feature-gating of the DIDComm arm must produce a diagnosis, not
            // a panic.
            Protocol::Didcomm => format!(
                "this VTC's DID document advertises a DIDComm mediator (`DIDCommMessaging` -> \
                 {}), but this binary cannot serve DIDComm. Rebuild with DIDComm support, or \
                 remove the `DIDCommMessaging` service entry from the DID document.",
                self.endpoint
            ),
            Protocol::Rest => format!(
                "this VTC's DID document advertises a REST endpoint ({}) that this binary does \
                 not serve.",
                self.endpoint
            ),
        }
    }
}

impl std::fmt::Display for UnservableTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.remediation())
    }
}

/// Every advertised messaging transport that `served` does not cover, in
/// preference order.
///
/// Takes the served set as a parameter rather than reading
/// [`served_transports`], and that is not incidental. `vtc-service` carries a
/// `[dev-dependencies]` self-dep (`vtc-service = { path = ".", features =
/// [...] }`) with `default-features` left on, so Cargo unifies the default
/// features into *every* test build of this crate. A `#[cfg(not(feature =
/// "tsp"))]` unit test here would therefore never compile in, never run, and
/// never fail — a vacuous assertion dressed as coverage, which is precisely
/// the failure class this whole module exists to close. Parameterising instead
/// means both builds' behaviour is exercised from either build, and no CI
/// feature combination has to be remembered for the coverage to exist.
///
/// Empty means the document and the build agree. Reads capabilities by service
/// `type` via [`ServiceCapabilities`] — never by `#id`, which is an arbitrary
/// label (CLAUDE.md D9).
#[must_use]
pub fn unservable_against(
    served: &[Protocol],
    caps: &ServiceCapabilities,
) -> Vec<UnservableTransport> {
    caps.advertised()
        .into_iter()
        // REST is served unconditionally; it is the axum router, not a
        // messaging listener, and never a claim this check can falsify.
        .filter(|p| *p != Protocol::Rest)
        .filter(|p| !served.contains(p))
        .map(|protocol| UnservableTransport {
            endpoint: caps.endpoint(protocol).unwrap_or_default().to_string(),
            protocol,
        })
        .collect()
}

/// [`unservable_against`] for the transports this build actually serves.
#[must_use]
pub fn unservable_advertised(caps: &ServiceCapabilities) -> Vec<UnservableTransport> {
    unservable_against(served_transports(), caps)
}

/// Whether any advertised messaging transport is one `served` covers.
///
/// `false` is the deployed failure exactly: a document offering TSP alone to a
/// binary without the feature, leaving a conforming client no reachable path
/// in. Distinct from "advertises nothing" — a document with no messaging
/// service at all is a REST-only community, which is a coherent (if
/// fallback-less) configuration rather than a contradiction.
#[must_use]
pub fn has_servable_messaging_against(served: &[Protocol], caps: &ServiceCapabilities) -> bool {
    caps.advertised()
        .into_iter()
        .filter(|p| *p != Protocol::Rest)
        .any(|p| served.contains(&p))
}

/// [`has_servable_messaging_against`] for the transports this build serves.
#[must_use]
pub fn has_servable_messaging(caps: &ServiceCapabilities) -> bool {
    has_servable_messaging_against(served_transports(), caps)
}

/// Whether the document advertises any messaging transport at all.
///
/// A VTC advertising none is reachable only over REST. That is legal, and the
/// `vtc-host` template's documented default ("DIDComm is not advertised here
/// by default"), so it is reported rather than refused.
#[must_use]
pub fn advertises_messaging(caps: &ServiceCapabilities) -> bool {
    caps.advertised().iter().any(|p| *p != Protocol::Rest)
}

/// The DID-document state from the VTC's own on-disk `did.jsonl`, if it has
/// one.
///
/// This is the log the VTC serves at `GET /.well-known/did.jsonl` — a document
/// it publishes itself, so a transport advertised here is a promise this
/// binary is making directly. Read from disk rather than resolved so the boot
/// gate below adds no network dependency to the startup path (CLAUDE.md's
/// mediator-connection invariant: nothing may block `server::run` from
/// reaching its shutdown select).
///
/// `None` for a VTC that hasn't been set up, isn't a `did:webvh`, or whose log
/// is hosted elsewhere and not mirrored locally — all legitimate, and all
/// cases where there is simply nothing to check here. A malformed or
/// unreadable log is also `None`: `routes::did_log` already owns reporting
/// that, and this function must not turn a serving problem into a boot
/// failure.
pub async fn local_did_document(config: &crate::config::AppConfig) -> Option<serde_json::Value> {
    let label = crate::routes::did_log::did_log_label(config.vtc_did.as_deref()?)?;
    let path = config
        .store
        .data_dir
        .join("did")
        .join(format!("{label}.jsonl"));
    let body = tokio::fs::read_to_string(&path).await.ok()?;
    // did:webvh log: one JSON entry per line, newest last. The current
    // document is the last entry's `state`.
    let last = body.lines().rev().find(|l| !l.trim().is_empty())?;
    let entry: serde_json::Value = serde_json::from_str(last).ok()?;
    entry.get("state").cloned()
}

/// Refuse to boot when the document this VTC publishes advertises a messaging
/// transport this binary cannot serve.
///
/// Fail-closed, but only on a *positive* determination: no local log, an
/// unreadable one, or a pre-setup VTC all pass, because none of them
/// establishes that a contradiction exists. Deny-on-known-bad rather than
/// deny-on-unknown — the alternative makes a missing file or a stale mirror
/// into an outage.
///
/// Serving REST while silently dropping every join is a worse failure than not
/// starting: it is invisible from the outside, the client sees success, and
/// the community accumulates applicants who will never be admitted. The
/// existing half-applied-backup gate in [`crate::server::run`] refuses to boot
/// for the same reason — better a loud stop than quiet partial service.
pub async fn enforce_at_boot(
    config: &crate::config::AppConfig,
) -> Result<(), crate::error::AppError> {
    let Some(doc) = local_did_document(config).await else {
        return Ok(());
    };
    let caps = ServiceCapabilities::from_did_document(&doc);
    let unservable = unservable_advertised(&caps);
    if unservable.is_empty() {
        return Ok(());
    }
    let detail = unservable
        .iter()
        .map(UnservableTransport::remediation)
        .collect::<Vec<_>>()
        .join(" ");
    Err(crate::error::AppError::Config(format!(
        "this VTC's published DID document advertises a transport this build cannot serve, so \
         conforming clients would choose a path that silently drops their messages. {detail}"
    )))
}

/// The transports the VTC's DID document advertises **as published**, resolved
/// over the network.
///
/// This is the authoritative advertisement, and it is not the same thing as
/// [`local_did_document`]. The reference VTC's `#tsp` entry was published at
/// log version 3, after the `vtc-host` template minted versions 1 and 2 — a
/// document can gain a service long after the VTC last wrote its own mirror,
/// and did. Any check that only reads local state would have passed the exact
/// deployment that failed.
///
/// `None` when there is no resolver or resolution fails: unknown is not the
/// same as bad, and [`crate::messaging`] must not refuse to start over a
/// resolver blip.
pub async fn resolved_capabilities(
    did_resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    vtc_did: &str,
) -> Option<ServiceCapabilities> {
    let resolved = did_resolver?.resolve(vtc_did).await.ok()?;
    let doc = serde_json::to_value(&resolved.doc).ok()?;
    Some(ServiceCapabilities::from_did_document(&doc))
}

/// What the messaging listener should do about the published document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessagingVerdict {
    /// Every advertised messaging transport is one this build serves.
    Ok,
    /// Some advertised transport is unservable, but at least one servable
    /// transport remains — start, and say loudly what will be dropped.
    Degraded(Vec<UnservableTransport>),
    /// Nothing advertised can be served. A conforming client has no reachable
    /// path in, so starting the listener would only mean dropping every frame
    /// somewhere quieter.
    Unreachable(Vec<UnservableTransport>),
}

/// Classify the published document for the messaging listener.
///
/// Deliberately three-valued rather than a boolean. Refusing to start on *any*
/// mismatch would take down a working DIDComm surface because TSP was
/// advertised and unbuilt, which trades one silent failure for a louder but
/// larger one; ignoring it would restore the original defect. Only the case
/// where nothing is reachable stops the listener.
#[must_use]
pub fn classify_against(served: &[Protocol], caps: &ServiceCapabilities) -> MessagingVerdict {
    let unservable = unservable_against(served, caps);
    if unservable.is_empty() {
        return MessagingVerdict::Ok;
    }
    if has_servable_messaging_against(served, caps) {
        MessagingVerdict::Degraded(unservable)
    } else {
        MessagingVerdict::Unreachable(unservable)
    }
}

/// [`classify_against`] for the transports this build serves.
#[must_use]
pub fn classify_for_messaging(caps: &ServiceCapabilities) -> MessagingVerdict {
    classify_against(served_transports(), caps)
}

/// Whether the document offers TSP with no DIDComm to fall back to.
///
/// Legal, and *served* correctly by a `tsp` build — but worth saying out loud,
/// because it is one build flag away from being unreachable and it strands any
/// peer that does not speak TSP. The `vtc-host` template advertises **no**
/// messaging transport out of the box (its description: "DIDComm is not
/// advertised here by default; communities that need a mediator add it later
/// via the runtime-service-management flow"), so a TSP-only document is not
/// something the mint produces — it is what an operator gets by adding `#tsp`
/// after mint and never adding `#didcomm`. That is exactly how the reference
/// deployment ended up here.
///
/// §12 Phase A of `docs/05-design-notes/tsp-enablement.md` is "advertise TSP
/// **+** DIDComm; prefer TSP when both peers speak it". Dropping DIDComm is
/// Phase D, and gated on telemetry showing no DIDComm-only peers remain.
#[must_use]
pub fn lacks_didcomm_fallback(caps: &ServiceCapabilities) -> bool {
    caps.tsp.is_some() && caps.didcomm.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The shape the deployed VTC actually had, verbatim from
    /// `https://webvh.storm.ws/first-vtc/did.jsonl` at log version 3:
    /// REST + status-list + TSP, and **no** `DIDCommMessaging`.
    fn deployed_shape() -> ServiceCapabilities {
        ServiceCapabilities::from_did_document(&json!({
            "service": [
                { "id": "did:webvh:x:h:first-vtc#vtc-rest",
                  "type": "VTCRest",
                  "serviceEndpoint": "https://first.openvtc.net" },
                { "id": "did:webvh:x:h:first-vtc#vtc-status-list",
                  "type": "VTCStatusList",
                  "serviceEndpoint": "https://first.openvtc.net/v1/status-lists" },
                { "id": "did:webvh:x:h:first-vtc#tsp",
                  "type": "TSPTransport",
                  "serviceEndpoint": "did:webvh:y:h:mediator" },
            ]
        }))
    }

    /// TSP *and* DIDComm — what §12 Phase A says a document should advertise,
    /// and what the deployed one was missing.
    fn tsp_and_didcomm() -> ServiceCapabilities {
        ServiceCapabilities::from_did_document(&json!({
            "service": [
                { "id": "did:webvh:x:h:first-vtc#tsp",
                  "type": "TSPTransport",
                  "serviceEndpoint": "did:webvh:y:h:mediator" },
                { "id": "did:webvh:x:h:first-vtc#didcomm",
                  "type": "DIDCommMessaging",
                  "serviceEndpoint": "did:webvh:y:h:mediator" },
            ]
        }))
    }

    fn didcomm_only() -> ServiceCapabilities {
        ServiceCapabilities::from_did_document(&json!({
            "service": [
                { "id": "did:webvh:x:h:first-vtc#didcomm",
                  "type": "DIDCommMessaging",
                  "serviceEndpoint": "did:webvh:y:h:mediator" },
            ]
        }))
    }

    /// REST only — the `vtc-host` template's out-of-the-box shape.
    fn rest_only() -> ServiceCapabilities {
        ServiceCapabilities::from_did_document(&json!({
            "service": [
                { "id": "did:webvh:x:h:first-vtc#vtc-rest",
                  "type": "VTCRest",
                  "serviceEndpoint": "https://first.openvtc.net" },
            ]
        }))
    }

    /// The invariant, stated against the build that *cannot* serve TSP — and
    /// asserted from whichever build is running the test, which is the point.
    /// It fails if anyone widens [`NON_TSP_BUILD`] without adding the code
    /// behind it.
    #[test]
    fn non_tsp_build_reports_the_tsp_it_cannot_serve() {
        let found = unservable_against(NON_TSP_BUILD, &deployed_shape());
        assert_eq!(found.len(), 1, "expected exactly the TSP entry: {found:?}");
        assert_eq!(found[0].protocol, Protocol::Tsp);
        assert_eq!(found[0].endpoint, "did:webvh:y:h:mediator");
    }

    /// R6.4: the operator-facing text must name the transport, why it is
    /// unservable, and the remediation — not a generic parse or network error.
    /// The observed failure was `Cannot parse message as JSON`, which names
    /// none of the three.
    #[test]
    fn the_error_names_transport_reason_and_fix() {
        let found = unservable_against(NON_TSP_BUILD, &deployed_shape());
        let text = found[0].remediation();
        assert!(text.contains("TSP"), "must name the transport: {text}");
        assert!(text.contains("`tsp` feature"), "must name why: {text}");
        assert!(text.contains("--features tsp"), "must name the fix: {text}");
        assert!(
            text.contains("TSPTransport") && text.contains("DID document"),
            "must name the other fix — editing the document: {text}"
        );
    }

    /// The same document is honest in a build that serves TSP. Both directions
    /// matter: a check that flagged everything would be as useless as one that
    /// flagged nothing.
    #[test]
    fn tsp_build_serves_the_tsp_it_advertises() {
        assert_eq!(unservable_against(TSP_BUILD, &deployed_shape()), vec![]);
        assert!(has_servable_messaging_against(TSP_BUILD, &deployed_shape()));
        assert_eq!(
            classify_against(TSP_BUILD, &deployed_shape()),
            MessagingVerdict::Ok
        );
    }

    /// The deployed configuration, classified: TSP alone, in a build without
    /// it, leaves a conforming client no reachable path in. This is the verdict
    /// that stops the messaging listener rather than letting it drop frames.
    #[test]
    fn tsp_only_document_is_unreachable_to_a_non_tsp_build() {
        assert!(!has_servable_messaging_against(
            NON_TSP_BUILD,
            &deployed_shape()
        ));
        // ...but it *is* advertising messaging, so this is a contradiction
        // rather than a REST-only community.
        assert!(advertises_messaging(&deployed_shape()));
        assert!(matches!(
            classify_against(NON_TSP_BUILD, &deployed_shape()),
            MessagingVerdict::Unreachable(u) if u.len() == 1
        ));
    }

    /// Advertising both is what keeps a peer from being stranded: a non-`tsp`
    /// build still has DIDComm to answer on, so it starts — degraded, and
    /// loudly, but it does not take a working transport down over an
    /// unservable one.
    #[test]
    fn tsp_plus_didcomm_degrades_rather_than_stopping() {
        assert!(has_servable_messaging_against(
            NON_TSP_BUILD,
            &tsp_and_didcomm()
        ));
        assert!(matches!(
            classify_against(NON_TSP_BUILD, &tsp_and_didcomm()),
            MessagingVerdict::Degraded(u) if u.len() == 1 && u[0].protocol == Protocol::Tsp
        ));
        // And fully served by a `tsp` build.
        assert_eq!(
            classify_against(TSP_BUILD, &tsp_and_didcomm()),
            MessagingVerdict::Ok
        );
    }

    /// DIDComm is unconditional, so it is servable in every build. Guards
    /// against a refactor that accidentally feature-gates the dispatch arm.
    #[test]
    fn didcomm_is_servable_in_every_build() {
        for served in [TSP_BUILD, NON_TSP_BUILD] {
            assert_eq!(unservable_against(served, &didcomm_only()), vec![]);
            assert!(has_servable_messaging_against(served, &didcomm_only()));
        }
    }

    /// A REST-only community is coherent, not a mismatch: nothing to report,
    /// and no messaging advertised for the caller to complain about. It must
    /// not be mistaken for the TSP-only case above — that one is a
    /// contradiction, this one is a configuration.
    #[test]
    fn rest_only_is_not_a_mismatch() {
        for served in [TSP_BUILD, NON_TSP_BUILD] {
            assert_eq!(unservable_against(served, &rest_only()), vec![]);
            assert_eq!(classify_against(served, &rest_only()), MessagingVerdict::Ok);
            assert!(!has_servable_messaging_against(served, &rest_only()));
        }
        assert!(!advertises_messaging(&rest_only()));
    }

    /// Discovery is by `type`, never by `#id` (CLAUDE.md D9). A `TSPTransport`
    /// under the OWF reference impl's `#tsp-transport` label must be found just
    /// the same — otherwise the check silently passes a document it should have
    /// caught, which is the same class of miss as the original defect.
    #[test]
    fn matches_tsp_by_type_not_by_id_fragment() {
        let caps = ServiceCapabilities::from_did_document(&json!({
            "service": [
                { "id": "did:webvh:x:h:first-vtc#tsp-transport",
                  "type": "TSPTransport",
                  "serviceEndpoint": "did:webvh:y:h:mediator" },
            ]
        }));
        let found = unservable_against(NON_TSP_BUILD, &caps);
        assert_eq!(found.len(), 1, "id fragment must not gate discovery");
        assert_eq!(found[0].protocol, Protocol::Tsp);
    }

    /// The `cfg` wiring itself: `served_transports()` must agree with the
    /// feature actually compiled in. Everything above is parameterised, so this
    /// one assertion is what ties the parameterised logic to reality — without
    /// it, a broken `cfg!` would leave every other test still passing.
    #[test]
    fn served_transports_tracks_the_compiled_feature() {
        if cfg!(feature = "tsp") {
            assert_eq!(served_transports(), TSP_BUILD);
            assert!(served_transports().contains(&Protocol::Tsp));
        } else {
            assert_eq!(served_transports(), NON_TSP_BUILD);
            assert!(!served_transports().contains(&Protocol::Tsp));
        }
    }

    /// `tsp` is a *default* feature, so an ordinary `cargo build` — the one
    /// that produces a release binary — serves it.
    ///
    /// Always meaningful despite the `cfg!`: the `[dev-dependencies]` self-dep
    /// keeps default features on for every test build of this crate, so this
    /// assertion cannot be skipped by a flag. It fails exactly when someone
    /// removes `tsp` from `default`, which is the change that would let a
    /// deployed VTC silently drop every TSP join again.
    #[test]
    // The constant is the assertion. `cfg!` folds to a literal at compile time,
    // which is precisely what makes this a build-configuration guard rather
    // than a runtime check — clippy's usual "this proves nothing" reasoning is
    // inverted here.
    #[allow(clippy::assertions_on_constants)]
    fn the_default_build_serves_tsp() {
        assert!(
            cfg!(feature = "tsp"),
            "`tsp` must stay a default feature of vtc-service: the shipped binary has to serve \
             the TSP its DID document may advertise."
        );
    }
}
