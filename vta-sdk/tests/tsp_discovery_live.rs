//! Live discovery check against a **deployed** TSP-enabled VTA (#765, R3.6).
//!
//! Issue #765 asked for the `#tsp` extraction to be verified against a real
//! deployed DID document rather than against the template fixtures alone, and
//! that verification was never done — the unit tests in `protocol::matching`
//! and `provision_client::resolve` all run over hand-written JSON. This closes
//! that gap.
//!
//! **`#[ignore]`d**: it resolves a `did:webvh` over the network, so it must not
//! run in the ordinary suite. Run it deliberately:
//!
//! ```sh
//! cargo test -p vta-sdk --features session,provision-client,tsp \
//!     --test tsp_discovery_live -- --ignored --nocapture
//! ```
//!
//! Point it at a different deployment with `VTA_LIVE_TSP_DID`.
//!
//! ## What a real document exercises that a fixture does not
//!
//! The deployed VTA advertises its two transports in **different JSON shapes**,
//! which is the whole reason a live check earns its keep:
//!
//! ```jsonc
//! { "id": "…#tsp",          "type": "TSPTransport",
//!   "serviceEndpoint": "did:webvh:…:mediator" },                 // bare string
//! { "id": "…#vta-didcomm",  "type": "DIDCommMessaging",
//!   "serviceEndpoint": [ { "accept": ["didcomm/v2"],
//!                          "uri": "did:webvh:…:mediator" } ] }   // array of objects
//! ```
//!
//! It also advertises **no `#vta-rest`**, which is precisely the shape that
//! used to fall through both extractions in `resolve_vta_endpoint` and return a
//! REST URL synthesized from the DID's own domain — an endpoint that need not
//! exist. Asserting `rest_url == None` here pins the #765 defect against a real
//! document.
//!
//! ## What this does NOT cover
//!
//! The correlated round-trip (`connect_tsp` → `TspSession::request` → reply).
//! That needs a client DID with an ACL grant on the target VTA, which is
//! provisioning this test cannot do. Discovery is the half that is verifiable
//! without credentials; the transacting half still wants a live exercise.

#![cfg(all(feature = "session", feature = "provision-client"))]

use vta_sdk::session::{VtaEndpoint, resolve_vta_endpoint};

/// The deployment named in #765. Overridable so this does not rot into a test
/// that only ever proves one host was up.
fn target_did() -> String {
    std::env::var("VTA_LIVE_TSP_DID").unwrap_or_else(|_| {
        "did:webvh:QmWoJD2kpP6AJknNtj7UFERUstEen258ywj3ruHoh1ZAqr:webvh.storm.ws:glenn-vta"
            .to_string()
    })
}

#[tokio::test]
#[ignore = "resolves a did:webvh over the network; run explicitly with --ignored"]
async fn deployed_vta_resolves_as_tsp_with_no_guessed_rest_url() {
    let did = target_did();
    let endpoint = resolve_vta_endpoint(&did)
        .await
        .expect("the deployed VTA's DID document should resolve");

    let VtaEndpoint::Tsp {
        vta_did,
        mediator_did,
        didcomm_mediator_did,
        rest_url,
    } = endpoint
    else {
        panic!(
            "a VTA advertising #tsp must resolve as VtaEndpoint::Tsp — this is the \
             #765 defect: before the fix it resolved as Rest, via a URL guessed \
             from the DID's own domain"
        );
    };

    assert_eq!(vta_did, did);

    // Read from the `#tsp` entry, whose serviceEndpoint is a BARE STRING.
    assert!(
        mediator_did.starts_with("did:"),
        "the #tsp endpoint is the mediator's DID, not a transport URL — got {mediator_did:?}"
    );

    // Read from the `#vta-didcomm` entry, whose serviceEndpoint is an ARRAY OF
    // OBJECTS. Both shapes going through one matcher is what a fixture-only
    // test cannot prove.
    let didcomm =
        didcomm_mediator_did.expect("this deployment advertises DIDCommMessaging alongside TSP");
    assert!(didcomm.starts_with("did:"), "got {didcomm:?}");

    // This deployment happens to point both transports at one mediator. Assert
    // it as an observation, NOT as a rule the resolver may rely on: #765 is
    // explicit that the TSP mediator must be read from the `#tsp` entry rather
    // than assumed equal to the DIDComm one.
    assert_eq!(
        mediator_did, didcomm,
        "informational: this deployment shares one mediator between transports"
    );

    // The defect this issue was filed for. No `#vta-rest` is advertised, so
    // there must be no REST URL — not one invented from the DID's domain.
    assert_eq!(
        rest_url, None,
        "a VTA advertising no #vta-rest must yield no REST URL; a synthesized \
         one points at the DID host rather than the VTA"
    );

    println!("  vta_did      {vta_did}");
    println!("  tsp mediator {mediator_did}");
    println!("  didcomm      {didcomm}");
    println!("  rest_url     {rest_url:?}");
}

/// A probe must be able to report *everything* a VTA advertises, independently
/// of what it would connect over. Conflating the two is what rendered a
/// TSP-enabled VTA as "DIDComm (in use) · only transport offered".
#[tokio::test]
#[ignore = "resolves a did:webvh over the network; run explicitly with --ignored"]
async fn deployed_vta_advertises_both_transports_to_a_probe() {
    use vta_sdk::protocol::matching::Protocol;

    let did = target_did();
    let resolved = vta_sdk::provision_client::resolve_vta(&did)
        .await
        .expect("the deployed VTA's DID document should resolve");

    assert_eq!(
        resolved.advertised(),
        vec![Protocol::Tsp, Protocol::Didcomm],
        "a probe must see TSP *and* DIDComm, in preference order"
    );
    assert!(
        resolved.tsp_mediator_did.is_some(),
        "tsp_mediator_did is what lets a probe say 'this VTA advertises TSP' \
         without that being the transport it connected over"
    );

    println!("  advertised   {:?}", resolved.advertised());
}
