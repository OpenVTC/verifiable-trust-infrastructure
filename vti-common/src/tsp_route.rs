//! Reaching a TSP peer on another mediator — shared by every node that starts
//! a TSP exchange (the VTA's outbound, the push engine, the VTC's registry and
//! git-ns bridge clients).
//!
//! # Why this exists (VTI-56)
//!
//! A mediator delivers a Direct TSP message only to an account it hosts, and
//! refuses one for anybody else (`e.p.direct_delivery.denied`). So everything a
//! node sends to a peer on *another* mediator has to be routed through that
//! mediator:
//!
//! - **The relationship invite.** The SDK's `send_control` routes it across
//!   mediators only when it already knows the peer's mediator — learned from a
//!   routed invite *from* the peer, or recorded with `set_peer_mediator`. A node
//!   that starts the relationship has neither, so its invite went to its own
//!   mediator, was refused, and every attempt failed the same way. Nothing
//!   reached the other mediator, which is what the field report saw.
//! - **The payload.** `[our_mediator, peer]` ends at a mediator that does not
//!   host the peer. It has to go `[our_mediator, peer_mediator]`, nested.
//!
//! The peer's mediator is the `#tsp` (`TSPTransport`) endpoint of its DID
//! document, which every caller already read to choose TSP. The DID document is
//! authoritative for where a party is reached; this module only hands what it
//! says to the SDK.
//!
//! The proper home for the first half is the SDK itself (fall back to the
//! peer's DID document when no mediator was learned); until it does, this is
//! where it is done. `vti_56_a_cold_relationship_with_a_cross_mediator_peer_forms`
//! (vta-service) pins the SDK behaviour, so it says when this can go.

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

/// Record `peer`'s mediator with the SDK when it is not `own_mediator`, so the
/// relationship control messages it sends (invite, accept, cancel) route
/// through it. Returns the cross mediator, if there is one.
pub async fn note_peer_mediator<'a>(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    own_mediator: &str,
    peer: &str,
    peer_mediator: Option<&'a str>,
) -> Result<Option<&'a str>, ATMError> {
    let Some(m) = cross_mediator(own_mediator, peer_mediator) else {
        return Ok(None);
    };
    atm.tsp()
        .set_peer_mediator(profile, peer, Some(m.to_string()))
        .await?;
    Ok(Some(m))
}

/// The recovery-aware send (Rev 3 §7.2.2) to `peer`, wherever it lives: invite
/// first when no relationship is on record, then `body` behind it (§3.6).
///
/// Same mediator, or `peer_mediator` unknown: the SDK's own
/// `send_reestablishing`, routed `[own_mediator, peer]`. Another mediator: the
/// invite routed through it (see [`note_peer_mediator`]) and `body` nested
/// `[own_mediator, peer_mediator]`, with the SDK's benign-refusal re-read for
/// the case where the peer re-formed the relationship first.
pub async fn send_reestablishing(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    own_mediator: &str,
    peer: &str,
    peer_mediator: Option<&str>,
    body: &[u8],
) -> Result<(), ATMError> {
    let tsp = atm.tsp();
    let Some(peer_mediator) =
        note_peer_mediator(atm, profile, own_mediator, peer, peer_mediator).await?
    else {
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
