//! Reaching a TSP peer on another mediator — shared by every node that starts
//! a TSP exchange (the VTA's outbound, the VTC's registry and git-ns bridge
//! clients).
//!
//! # Why this exists (VTI-56)
//!
//! A mediator delivers a Direct TSP message only to an account it hosts, and
//! refuses one for anybody else (`e.p.direct_delivery.denied`). So everything a
//! node sends to a peer on *another* mediator has to be routed through that
//! mediator:
//!
//! - **The relationship invite.** The SDK routes it, from 0.31.1
//!   (affinidi-tdk-rs #913): with no mediator learned for the peer, it uses the
//!   one the peer's DID document names in its `TSPTransport` service. Before
//!   that, a node starting a relationship sent its invite to its own mediator,
//!   which refused it on every attempt, and nothing reached the other mediator.
//!   That was the field report. The workspace floor is 0.31.1 for this reason.
//! - **The payload.** The SDK's `send_reestablishing` sends it along the route
//!   it is given. `[our_mediator, peer]` ends at a mediator that does not host
//!   the peer, so it has to go `[our_mediator, peer_mediator]`, nested, and
//!   [`send_reestablishing`] here does that.
//!
//! The peer's mediator is the `#tsp` (`TSPTransport`) endpoint of its DID
//! document, which every caller already read to choose TSP.
//! `vti_56_a_cold_relationship_with_a_cross_mediator_peer_forms` (vta-service)
//! holds both halves.

use std::sync::Arc;

use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_sdk::protocols::tsp::{SendReadiness, invite_refusal_is_benign};
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;

/// `peer_mediator` when it is a mediator other than `own_mediator` — the case
/// that needs routing through it.
#[must_use]
pub fn cross_mediator<'a>(own_mediator: &str, peer_mediator: Option<&'a str>) -> Option<&'a str> {
    peer_mediator.filter(|m| *m != own_mediator)
}

/// The recovery-aware send (Rev 3 §7.2.2) to `peer`, wherever it lives: invite
/// first when no relationship is on record, then `body` behind it (§3.6).
///
/// Same mediator, or `peer_mediator` unknown: the SDK's own
/// `send_reestablishing`, routed `[own_mediator, peer]`. Another mediator: the
/// same steps, with `body` nested `[own_mediator, peer_mediator]` and the SDK's
/// benign-refusal re-read for the case where the peer re-formed the
/// relationship first.
pub async fn send_reestablishing(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    own_mediator: &str,
    peer: &str,
    peer_mediator: Option<&str>,
    body: &[u8],
) -> Result<(), ATMError> {
    let tsp = atm.tsp();
    let Some(peer_mediator) = cross_mediator(own_mediator, peer_mediator) else {
        return tsp
            .send_reestablishing(
                profile,
                peer,
                &[own_mediator.to_string(), peer.to_string()],
                body,
            )
            .await;
    };
    if tsp.send_readiness(profile, peer).await? == SendReadiness::Reestablish
        && let Err(e) = tsp.form_relationship_routed(profile, peer).await
        && !invite_refusal_is_benign(tsp.send_readiness(profile, peer).await?)
    {
        return Err(e);
    }
    tsp.send_nested_routed(
        profile,
        &[own_mediator.to_string(), peer_mediator.to_string()],
        peer,
        body,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::cross_mediator;

    #[test]
    fn only_another_mediator_is_cross() {
        assert_eq!(cross_mediator("did:m:a", Some("did:m:b")), Some("did:m:b"));
        assert_eq!(cross_mediator("did:m:a", Some("did:m:a")), None);
        assert_eq!(cross_mediator("did:m:a", None), None);
    }
}
