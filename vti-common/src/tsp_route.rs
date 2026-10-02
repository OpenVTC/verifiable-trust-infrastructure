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
//! - **The reply.** A node answering a peer that wrote to it — a Trust-Task
//!   reply, a join-request status — routed `[our_mediator, peer]` too, and so
//!   never reached a peer on another mediator. The request arrived; the answer
//!   was refused at our mediator. [`send_reply`] looks the peer's mediator up
//!   and routes the same way the payload above does.
//!
//! The peer's mediator is the `#tsp` (`TSPTransport`) endpoint of its DID
//! document, which every caller already read to choose TSP. A reply has not
//! read it, so [`send_reply`] asks the SDK, which prefers a mediator learned
//! from the peer's routed invite and falls back to that document.
//! `vti_56_a_cold_relationship_with_a_cross_mediator_peer_forms` (vta-service)
//! holds both halves.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_sdk::protocols::tsp::{SendReadiness, invite_refusal_is_benign};
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use tracing::warn;

/// How long [`send_reply`] waits to learn the peer's mediator. The lookup can
/// resolve a DID document over the network; a hung resolver must cost a reply
/// this long and then fall back, not hold the inbound loop (R1.2).
pub const PEER_MEDIATOR_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Send `body` to `peer` over an existing relationship, wherever `peer` lives:
/// routed `[own_mediator, peer]` when it shares our mediator (or its mediator
/// is unknown), nested `[own_mediator, peer_mediator]` when it is on another.
///
/// No invite: the caller already holds a relationship with `peer` — it is
/// answering a frame `peer` just sent, or has formed one already.
pub async fn send_routed_to(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    own_mediator: &str,
    peer: &str,
    peer_mediator: Option<&str>,
    body: &[u8],
) -> Result<(), ATMError> {
    let tsp = atm.tsp();
    match cross_mediator(own_mediator, peer_mediator) {
        Some(peer_mediator) => {
            tsp.send_nested_routed(
                profile,
                &[own_mediator.to_string(), peer_mediator.to_string()],
                peer,
                body,
            )
            .await
        }
        None => {
            tsp.send_routed(profile, &[own_mediator.to_string(), peer.to_string()], body)
                .await
        }
    }
}

/// Answer `peer`, which just sent us a verified frame, wherever it lives.
///
/// The peer's mediator comes from the SDK ([`TspOps::peer_mediator`]): one
/// learned from its routed invite first, else its DID document's `#tsp`
/// service. A lookup that fails or outlasts [`PEER_MEDIATOR_LOOKUP_TIMEOUT`]
/// falls back to our own mediator — the only route there was before, and the
/// right one for a peer that shares it — with a warning, because for a peer
/// on another mediator that reply will be refused.
///
/// [`TspOps::peer_mediator`]: affinidi_messaging_sdk::protocols::tsp::TspOps::peer_mediator
pub async fn send_reply(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    own_mediator: &str,
    peer: &str,
    body: &[u8],
) -> Result<(), ATMError> {
    let peer_mediator = match tokio::time::timeout(
        PEER_MEDIATOR_LOOKUP_TIMEOUT,
        atm.tsp().peer_mediator(profile, peer),
    )
    .await
    {
        Ok(Ok(found)) => found,
        Ok(Err(e)) => {
            warn!(peer, error = %e, "could not look up the peer's TSP mediator; replying through ours");
            None
        }
        Err(_) => {
            warn!(
                peer,
                timeout_secs = PEER_MEDIATOR_LOOKUP_TIMEOUT.as_secs(),
                "timed out looking up the peer's TSP mediator; replying through ours"
            );
            None
        }
    };
    send_routed_to(
        atm,
        profile,
        own_mediator,
        peer,
        peer_mediator.as_deref(),
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
