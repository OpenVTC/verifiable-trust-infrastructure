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

use serde::Serialize;
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

/// The messaging transports this build serves that the document does **not**
/// advertise.
///
/// Purely informational: a binary that can serve more than it promises strands
/// nobody, and this is the normal shape of a staged rollout — ship the capable
/// binary first, add the service entry once it is deployed everywhere. Reported
/// so an operator mid-rollout can see the second half is still outstanding,
/// never as a fault.
#[must_use]
pub fn served_not_advertised(served: &[Protocol], caps: &ServiceCapabilities) -> Vec<Protocol> {
    let advertised = caps.advertised();
    served
        .iter()
        .copied()
        .filter(|p| !advertised.contains(p))
        .collect()
}

/// How loudly a [`Finding`] should be reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The document promises something this build cannot deliver. Clients that
    /// obey the document will fail.
    Error,
    /// Reachable, but a peer can be stranded — no fallback, or no messaging at
    /// all.
    Warn,
    /// Nothing wrong; stated so a rollout is legible.
    Info,
}

/// One observation about the document-versus-binary relationship.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

/// Every observation about `caps` from the standpoint of a build serving
/// `served`, most severe first.
///
/// One function so the boot gate, the messaging listener, and `vtc status` say
/// the *same* thing about the same document — an operator who runs `vtc status`
/// to explain a boot refusal must not be told a different story by the tool
/// they reached for second.
#[must_use]
pub fn findings_against(served: &[Protocol], caps: &ServiceCapabilities) -> Vec<Finding> {
    let mut out = Vec::new();

    // 1. Promised but not deliverable. The failure this module exists for.
    for u in unservable_against(served, caps) {
        out.push(Finding {
            severity: Severity::Error,
            message: u.remediation(),
        });
    }

    // 2. No messaging at all. Legal — the `vtc-host` template mints exactly
    //    this — but it means no join, no credential delivery, no member
    //    messaging can reach the VTC by any route a DID-driven client would
    //    find. An operator who thinks they configured a mediator should learn
    //    that the document does not say so.
    if !advertises_messaging(caps) {
        out.push(Finding {
            severity: Severity::Warn,
            message: "this VTC's DID document advertises no messaging transport at all (no \
                      `TSPTransport`, no `DIDCommMessaging`) — a client resolving it can reach \
                      this community over REST only, and nothing can be delivered to it over \
                      the mediator. If that is not deliberate, add a service entry via the \
                      runtime-service-management flow."
                .to_string(),
        });
    }

    // 3. TSP with nothing behind it.
    if lacks_didcomm_fallback(caps) {
        out.push(Finding {
            severity: Severity::Warn,
            message: "this VTC advertises TSP but no DIDComm mediator, so a peer that does not \
                      speak TSP has no messaging transport to fall back to, and a build without \
                      the `tsp` feature would have none at all. tsp-enablement.md §12 Phase A \
                      is to advertise both; add a `DIDCommMessaging` service unless dropping \
                      DIDComm is deliberate."
                .to_string(),
        });
    }

    // 4. Capable of more than it claims. A staged rollout, not a fault.
    for p in served_not_advertised(served, caps) {
        out.push(Finding {
            severity: Severity::Info,
            message: format!(
                "this build serves {p} but the DID document does not advertise it, so no client \
                 will choose it. Normal mid-rollout (ship the capable binary, then add the \
                 service); add the service entry to start receiving {p} traffic."
            ),
        });
    }

    out
}

/// [`findings_against`] for the transports this build serves.
#[must_use]
pub fn findings_for_build(caps: &ServiceCapabilities) -> Vec<Finding> {
    findings_against(served_transports(), caps)
}

/// One transport's public connectivity status, as reported on the
/// unauthenticated community profile.
///
/// The two flags answer different questions and both are needed:
///
/// - `advertised` — will a client resolving this community's DID *find* this
///   transport? Read from the DID document, which is the authority (CLAUDE.md).
/// - `serviceable` — if reached on it, can this VTC actually answer? Build
///   capability plus live messaging connectivity.
///
/// A transport is genuinely reachable only when **both** are true. Splitting
/// them is the point: the failure that motivated all of this was `advertised`
/// without `serviceable`, and a single boolean would have hidden it exactly the
/// way the original defect did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TransportStatus {
    /// `"tsp"` / `"didcomm"` / `"rest"`.
    pub protocol: String,
    /// Present in the community's DID document, so a resolving client will
    /// find it.
    pub advertised: bool,
    /// This VTC can answer on it right now. For the messaging transports that
    /// means the build supports the protocol *and* the mediator connection is
    /// live — a re-falsifiable signal, never a boot-time latch (R6.2).
    pub serviceable: bool,
    /// The advertised endpoint: the mediator DID for TSP/DIDComm, the base URL
    /// for REST. `None` when not advertised — there is no endpoint to give.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// The public transport view: every protocol, whether the document advertises
/// it, and whether this VTC can serve it.
///
/// Deliberately reports **all three** protocols rather than only the advertised
/// ones, so the response shape is stable and a client can tell "not advertised"
/// from "absent from an older response". A `serviceable` transport that is not
/// `advertised` is the staged-rollout state — the binary is ready, the DID
/// document has not caught up.
///
/// Discloses nothing that isn't already public or externally observable:
/// `advertised` and `endpoint` are read straight out of the DID document, which
/// anyone can resolve, and `serviceable` is discoverable by simply attempting
/// the transport. Deliberately **excluded**: build feature flags, version
/// strings, and the operator-facing remediation text from [`Finding`] — those
/// are for `vtc status` and the daemon log, not a public page.
///
/// `messaging_connected` is the live mediator-connection signal; REST is always
/// serviceable, since serving this response proves it.
#[must_use]
pub fn public_transport_view(
    served: &[Protocol],
    caps: &ServiceCapabilities,
    messaging_connected: bool,
) -> Vec<TransportStatus> {
    Protocol::PREFERENCE_ORDER
        .into_iter()
        .map(|protocol| {
            let endpoint = caps.endpoint(protocol).map(str::to_string);
            let serviceable = match protocol {
                // Answering this request is the proof.
                Protocol::Rest => true,
                // A messaging transport needs both halves: compiled in, and a
                // live socket to the mediator.
                _ => served.contains(&protocol) && messaging_connected,
            };
            TransportStatus {
                protocol: protocol.as_str().to_string(),
                advertised: endpoint.is_some(),
                serviceable,
                endpoint,
            }
        })
        .collect()
}

/// [`public_transport_view`] for the transports this build serves.
#[must_use]
pub fn public_transport_view_for_build(
    caps: &ServiceCapabilities,
    messaging_connected: bool,
) -> Vec<TransportStatus> {
    public_transport_view(served_transports(), caps, messaging_connected)
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

    // ─── the public transport view ───────────────────────────────────────

    fn status<'a>(view: &'a [TransportStatus], protocol: &str) -> &'a TransportStatus {
        view.iter()
            .find(|t| t.protocol == protocol)
            .unwrap_or_else(|| panic!("{protocol} missing from the view: {view:?}"))
    }

    /// The shape is stable: all three protocols, always, in preference order.
    /// A consumer must be able to tell "not advertised" from "this response is
    /// from an older build that omitted the field".
    #[test]
    fn every_protocol_is_reported_in_preference_order() {
        let view = public_transport_view(TSP_BUILD, &deployed_shape(), true);
        assert_eq!(
            view.iter().map(|t| t.protocol.as_str()).collect::<Vec<_>>(),
            vec!["tsp", "didcomm", "rest"]
        );
    }

    /// The deployed community, served by a build that can answer: TSP is
    /// advertised and serviceable, and carries the mediator DID a client needs.
    #[test]
    fn an_advertised_and_servable_transport_reports_both() {
        let view = public_transport_view(TSP_BUILD, &deployed_shape(), true);
        let tsp = status(&view, "tsp");
        assert!(tsp.advertised && tsp.serviceable);
        assert_eq!(tsp.endpoint.as_deref(), Some("did:webvh:y:h:mediator"));
    }

    /// The failure this whole line of work exists for, as a visitor would see
    /// it: advertised, but not serviceable. A single "reachable" boolean would
    /// have collapsed these two and hidden it — the same way the original
    /// defect was hidden.
    #[test]
    fn advertised_but_unservable_is_visible_as_two_separate_facts() {
        let view = public_transport_view(NON_TSP_BUILD, &deployed_shape(), true);
        let tsp = status(&view, "tsp");
        assert!(tsp.advertised, "the document offers it");
        assert!(!tsp.serviceable, "this build cannot answer on it");
    }

    /// The staged-rollout state: the binary is ready, the document has not
    /// caught up. Serviceable, not advertised, and no endpoint to give.
    #[test]
    fn servable_but_unadvertised_reports_no_endpoint() {
        let view = public_transport_view(TSP_BUILD, &didcomm_only(), true);
        let tsp = status(&view, "tsp");
        assert!(!tsp.advertised);
        assert!(tsp.serviceable);
        assert_eq!(tsp.endpoint, None, "nothing to publish when unadvertised");
    }

    /// A dropped mediator connection makes every messaging transport
    /// unserviceable — and must, or the published flag is a latch (R6.2).
    /// REST stays serviceable: answering the request proves it.
    #[test]
    fn losing_the_mediator_makes_messaging_unserviceable_but_not_rest() {
        let view = public_transport_view(TSP_BUILD, &tsp_and_didcomm(), false);
        assert!(!status(&view, "tsp").serviceable);
        assert!(!status(&view, "didcomm").serviceable);
        assert!(
            status(&view, "rest").serviceable,
            "serving this response is the proof REST works"
        );
    }

    /// Nothing in the public view leaks build configuration or operator
    /// remediation. `Finding`'s text names feature flags and rebuild commands
    /// on purpose — for `vtc status` and the daemon log. It must not ride out
    /// on an unauthenticated endpoint.
    #[test]
    fn the_public_view_leaks_no_build_detail() {
        let view = public_transport_view(NON_TSP_BUILD, &deployed_shape(), true);
        let json = serde_json::to_string(&view).expect("serialises");
        for leak in ["feature", "--features", "rebuild", "cargo", "version"] {
            assert!(
                !json.contains(leak),
                "public transport view must not mention {leak:?}: {json}"
            );
        }
    }

    /// Wire casing is camelCase (R3.1), and the two flags are named
    /// distinctly enough that a consumer cannot confuse them.
    #[test]
    fn wire_shape_is_camel_case() {
        let view = public_transport_view(TSP_BUILD, &deployed_shape(), true);
        let json = serde_json::to_value(&view).expect("serialises");
        let first = &json[0];
        assert!(first.get("protocol").is_some());
        assert!(first.get("advertised").is_some());
        assert!(first.get("serviceable").is_some());
        assert!(first.get("endpoint").is_some());
        // Not snake_case, and no stray fields.
        assert_eq!(
            first.as_object().unwrap().len(),
            4,
            "unexpected fields on the public wire type: {first}"
        );
    }

    // ─── findings: the four document-vs-binary relationships ─────────────

    fn messages(findings: &[Finding], want: Severity) -> Vec<&str> {
        findings
            .iter()
            .filter(|f| f.severity == want)
            .map(|f| f.message.as_str())
            .collect()
    }

    /// The deployed failure, as an operator-facing finding: one `Error` naming
    /// TSP. Also carries the no-fallback warning, since that document had no
    /// DIDComm either.
    #[test]
    fn unservable_advertised_transport_is_an_error_finding() {
        let f = findings_against(NON_TSP_BUILD, &deployed_shape());
        let errors = messages(&f, Severity::Error);
        assert_eq!(errors.len(), 1, "expected one error finding: {f:?}");
        assert!(errors[0].contains("TSP") && errors[0].contains("--features tsp"));
    }

    /// A document advertising no messaging transport at all: nothing can be
    /// delivered to this VTC over a mediator by any route a DID-driven client
    /// would find. Not an error — the `vtc-host` template mints exactly this —
    /// but the operator should be told.
    #[test]
    fn a_document_with_no_messaging_service_is_warned_about() {
        for served in [TSP_BUILD, NON_TSP_BUILD] {
            let f = findings_against(served, &rest_only());
            assert!(
                messages(&f, Severity::Error).is_empty(),
                "REST-only is legal, not an error: {f:?}"
            );
            assert!(
                messages(&f, Severity::Warn)
                    .iter()
                    .any(|m| m.contains("no messaging transport at all")),
                "expected the no-messaging warning: {f:?}"
            );
        }
    }

    /// Built with TSP, document silent about it — a valid staged rollout
    /// (capable binary first, service entry second). Informational only: it
    /// must never be an error, or the rollout order itself becomes unshippable.
    #[test]
    fn serving_more_than_the_document_advertises_is_informational() {
        let f = findings_against(TSP_BUILD, &didcomm_only());
        assert!(
            messages(&f, Severity::Error).is_empty(),
            "a capable binary that under-advertises strands nobody: {f:?}"
        );
        assert!(
            messages(&f, Severity::Info)
                .iter()
                .any(|m| m.contains("tsp") && m.contains("does not advertise it")),
            "expected the staged-rollout note for TSP: {f:?}"
        );
        assert_eq!(
            served_not_advertised(TSP_BUILD, &didcomm_only()),
            vec![Protocol::Tsp]
        );
    }

    /// The healthy shape produces nothing at all — otherwise every correct
    /// deployment prints noise and operators learn to skip the section.
    #[test]
    fn a_document_that_matches_the_build_has_no_findings() {
        assert_eq!(findings_against(TSP_BUILD, &tsp_and_didcomm()), vec![]);
    }

    /// The severities are what the three call sites switch on — boot refuses on
    /// `Error`, `vtc status` colours by it. Pin the mapping so a reordering of
    /// `findings_against` cannot quietly downgrade the failure that motivated
    /// this module.
    #[test]
    fn errors_sort_before_warnings_and_info() {
        let f = findings_against(NON_TSP_BUILD, &deployed_shape());
        assert_eq!(
            f.first().map(|f| f.severity),
            Some(Severity::Error),
            "the unservable-transport error must lead: {f:?}"
        );
    }
}
