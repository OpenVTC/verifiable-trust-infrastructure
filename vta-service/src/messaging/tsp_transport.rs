//! The one way this VTA puts a TSP frame on the wire.
//!
//! # Why this is one type
//!
//! A TSP operation needs an `ATM`, the `ATMProfile` registered on it, and this
//! VTA's own mediator — and the three are not independent. The profile is
//! registered on that ATM and nowhere else; the mediator is a property *of the
//! profile*, which is why [`ATMProfile::dids`] returns it. Passing them as three
//! arguments made all three of those facts something a call site had to know,
//! and four call sites each knew a different amount:
//!
//! - `messaging::service::handle_tsp` took `mediator_did` down a parameter chain
//!   from `run_inbound_loop`, past a DIDComm arm that discards it, to rebuild a
//!   route the profile could have answered.
//! - `operations::outbound::TspSender` read it from `AppConfig` instead — a
//!   second source for one fact, and no check that the two agreed.
//! - `trust_tasks::step_up::try_push_over_tsp` took it as an argument from a
//!   caller that had computed it for the *DIDComm* fallback.
//! - `trust_tasks::vault` passed an ATM and a profile that came from different
//!   places, which is how it came to hold a pair that could not work.
//!
//! # The invariant this type holds
//!
//! **A profile with no mediator is not a receive-only profile; it is a
//! non-functional one.** Every TSP entry point in the messaging SDK resolves the
//! mediator off the profile handed to it: `TspOps::pack` and `unpack_bytes` call
//! [`ATMProfile::dids`], and `send_raw` calls it alongside
//! `get_mediator_rest_endpoint`. All three answer
//! `ConfigError("No Mediator is configured for this Profile")` without one —
//! before any I/O, so the failure reads like a logic error rather than missing
//! wiring.
//!
//! That is not a hypothetical. `init_auth` built exactly such a profile for
//! unsealing, on the reasoning that the decryption key comes from the ATM's
//! secrets resolver and so no route is needed; it could not unseal either, and
//! when the outbound seam later reached for the nearest profile-shaped thing in
//! `AppState`, every TSP send this VTA attempted died inside the SDK.
//!
//! So [`TspTransport::new`] *checks*, and returns `None` when the profile cannot
//! route. There is no way to hold one of these and still be unable to send.

use std::sync::Arc;

use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;

/// An ATM, the profile registered on it, and the mediator that profile routes
/// through — the three things a TSP send, seal or unseal needs, which only work
/// together.
///
/// Cheap to clone (an `ATM` handle and two `Arc`-ish fields), and cloned rather
/// than borrowed because the live pair is republished on every mediator
/// reconnect: it lives behind the bridge's lock, not in a field with
/// `AppState`'s lifetime. Holding a clone also pins the session an operation was
/// selected against, so a reconnect mid-flight cannot swap the socket out from
/// under a half-sent frame.
#[derive(Clone)]
pub struct TspTransport {
    atm: ATM,
    profile: Arc<ATMProfile>,
    /// Read once from the profile at construction, so there is no second source
    /// for it and nothing to keep in step. Storing it also means `mediator_did`
    /// is infallible at every call site, which is the reason the check lives in
    /// the constructor.
    mediator_did: String,
}

impl TspTransport {
    /// Pair an ATM with a profile registered on it, or `None` if that profile
    /// carries no mediator.
    ///
    /// `None` is the honest answer rather than a transport that errors on first
    /// use: see the module docs for what the SDK does with a mediator-less
    /// profile, which is refuse every operation including the ones that look
    /// like they need no route.
    pub fn new(atm: ATM, profile: Arc<ATMProfile>) -> Option<Self> {
        let mediator_did = profile.dids().ok()?.1.to_string();
        Some(Self {
            atm,
            profile,
            mediator_did,
        })
    }

    /// The live transport for this VTA, or `None` when it has no mediator
    /// session.
    ///
    /// Reads the pair published on [`DIDCommBridge`](crate::didcomm_bridge::DIDCommBridge)
    /// by `server::MessagingConnect` — the same pair the inbound loop seals its
    /// replies with, so this VTA answers and initiates on one profile rather
    /// than on two that differ in whether they work.
    ///
    /// `None` is a real answer, not a gap: before the first connect, and between
    /// a dropped session and its reconnect, this VTA genuinely cannot put a
    /// frame on a TSP wire. Callers that *select* a transport
    /// ([`operations::outbound`](crate::operations::outbound)) use that to drop
    /// TSP from selection and reach the peer over its next-preferred protocol,
    /// rather than choosing TSP and then failing to send on it.
    pub fn from_app_state(state: &crate::server::AppState) -> Option<Self> {
        Self::new(state.didcomm_bridge.atm()?, state.didcomm_bridge.profile()?)
    }

    /// This VTA's own mediator — the first hop of every route below, and the
    /// `/inbound` the SDK posts to.
    pub fn mediator_did(&self) -> &str {
        &self.mediator_did
    }

    /// The ATM the profile is registered on. For the unseal path, which needs
    /// the SDK's `tsp()` ops directly rather than a send.
    pub fn atm(&self) -> &ATM {
        &self.atm
    }

    /// The mediator-registered profile. Pairs with [`atm`](Self::atm); handing
    /// this profile to a different ATM's `tsp()` is not a combination that
    /// works, which is why the two are only ever taken from one of these.
    pub fn profile(&self) -> &Arc<ATMProfile> {
        &self.profile
    }

    /// Seal `body` end-to-end to `recipient` and route it through this VTA's
    /// mediator.
    ///
    /// The inner layer is sealed to the recipient and the outer to the mediator
    /// — the routed shape both directions already use. `body` is expected to be
    /// framed by [`vta_sdk::tsp_binding`] where it carries a Trust Task; this
    /// function is the carriage and does not frame, so the one place framing is
    /// decided stays the caller that knows what the payload is.
    pub async fn send_to(
        &self,
        recipient: &str,
        body: &[u8],
    ) -> Result<(), affinidi_messaging_sdk::errors::ATMError> {
        self.atm
            .tsp()
            .send_routed(
                &self.profile,
                &[self.mediator_did.clone(), recipient.to_string()],
                body,
            )
            .await
    }

    /// Route `body` to `recipient` with **metadata privacy** when the topology
    /// allows it, and by the plain routed send when it does not.
    ///
    /// TSP's privacy is against the intermediaries a message crosses *before* the
    /// recipient's own mediator: with a nested send, each hop sees only the next
    /// hop, never the final recipient. That is worth something only when the peer
    /// is on a *different* mediator — so:
    ///
    /// - `peer_mediator` differs from ours → nest: seal the inner message
    ///   end-to-end to `recipient`, wrap it in a Nested envelope sealed to
    ///   `peer_mediator`, and route `[our_mediator, peer_mediator]`. The peer is
    ///   carried inside the sealed envelope, not as a visible route hop, so our
    ///   mediator (the only intermediary before the peer's) never learns it.
    /// - same mediator, or `peer_mediator` unknown (`None`) → the direct routed
    ///   [`send_to`](Self::send_to). A shared mediator is the sole intermediary
    ///   and already terminates the route, so there is no one to hide the
    ///   recipient from; nesting there would only add per-hop overhead. This is
    ///   the reference single-mediator topology, and its behaviour is unchanged.
    ///
    /// `peer_mediator` is the recipient's `#tsp` (`TSPTransport`) service endpoint
    /// — its mediator DID — which the caller already has from selecting TSP for
    /// this peer, so nothing is resolved again here. Mirrors the SDK's own
    /// `ATM::send_to` gate (nest iff the peer's mediator differs from ours).
    pub async fn send_metadata_private(
        &self,
        recipient: &str,
        peer_mediator: Option<&str>,
        body: &[u8],
    ) -> Result<(), affinidi_messaging_sdk::errors::ATMError> {
        match peer_mediator {
            Some(peer_mediator) if peer_mediator != self.mediator_did => {
                self.atm
                    .tsp()
                    .send_nested_routed(
                        &self.profile,
                        &[self.mediator_did.clone(), peer_mediator.to_string()],
                        recipient,
                        body,
                    )
                    .await
            }
            _ => self.send_to(recipient, body).await,
        }
    }

    /// This VTA's own VID — the first of the profile's `dids()`. Keys the D6
    /// recovery coordinator's per-peer single-flight state. `None` only if the
    /// profile somehow lost its mediator between construction and here.
    pub fn our_vid(&self) -> Option<String> {
        self.profile.dids().ok().map(|(ours, _)| ours.to_string())
    }

    /// Force our local half of the relationship with `recipient` back to `None`,
    /// clearing thread digests — the D4 "stale local half" reset for use on a
    /// reply-timeout that may be a §7.2.2 silent drop. Safe against a false
    /// positive: if the peer kept the relationship, the fresh invite that
    /// follows reconciles (D2) rather than errors.
    pub async fn reset_relationship(
        &self,
        recipient: &str,
    ) -> Result<(), affinidi_messaging_sdk::errors::ATMError> {
        self.atm
            .tsp()
            .reset_relationship(&self.profile, recipient)
            .await
    }

    /// Re-invite `recipient` if our half is `None`/stale, then send `body` — the
    /// readiness-gated re-establishing send. Pair with [`reset_relationship`](Self::reset_relationship)
    /// first so a stale `Bidirectional` local half actually re-invites rather
    /// than sending straight into the drop again.
    ///
    /// # Why this is spelled out rather than `TspOps::send_reestablishing`
    ///
    /// The SDK's version is the same three steps — read the readiness, invite if
    /// it says `Reestablish`, send the payload — but its readiness read and the
    /// FSM's `SendInvite` transition are two separate awaits on the relationship
    /// store, and **the peer can move our half between them**. `SendInvite` is
    /// legal only from `None`, so an inbound invite from that same peer landing
    /// in the window makes the invite fail with
    ///
    /// ```text
    /// invalid transition: SendInvite in state InviteReceived
    /// ```
    ///
    /// and the payload is never sent. That is not a failed recovery — it is the
    /// *successful* one, arrived at from the other side: a relationship is on
    /// record again, and §3.6 admits an application message over any state but
    /// `None`. Failing there loses the resend, and the loss is worst exactly
    /// when it matters most, because two endpoints repairing the same broken
    /// relationship at once (a mediator restart, a VTA redeploy) is precisely
    /// the case that produces the collision.
    ///
    /// So a refused invite is answered by **re-reading the store**, not by
    /// trusting the error's text — [`invite_refusal_is_benign`] is the decision,
    /// separated so it can be read and tested without a mediator. The payload is
    /// still sent exactly once either way.
    pub async fn send_reestablishing(
        &self,
        recipient: &str,
        body: &[u8],
    ) -> Result<(), affinidi_messaging_sdk::errors::ATMError> {
        use affinidi_messaging_sdk::SendReadiness;

        let tsp = self.atm.tsp();
        if tsp.send_readiness(&self.profile, recipient).await? == SendReadiness::Reestablish
            && let Err(e) = tsp.form_relationship_routed(&self.profile, recipient).await
        {
            let after = tsp.send_readiness(&self.profile, recipient).await?;
            if !invite_refusal_is_benign(after) {
                return Err(e);
            }
        }
        self.send_to(recipient, body).await
    }

    /// Re-invite `recipient` **without** sending a payload — heal the
    /// relationship for a later send. Used on the recovery path for a task that
    /// is not safe to blind-resend, where re-forming the relationship (so the
    /// caller's retry lands) is right but re-sending the Trust Task could
    /// double-execute. Valid only from `None`, so callers reset first.
    pub async fn relate(
        &self,
        recipient: &str,
    ) -> Result<(), affinidi_messaging_sdk::errors::ATMError> {
        self.atm
            .tsp()
            .form_relationship_routed(&self.profile, recipient)
            .await
            .map(|_| ())
    }
}

/// May a refused `SendInvite` be carried on from, given the readiness read
/// **after** the refusal?
///
/// The question only arises on the re-establishing send
/// ([`TspTransport::send_reestablishing`]), and it is decided on the *store*
/// rather than on the error's text: an `ATMError` string is not a contract, and
/// the state is.
///
/// - Anything but `Reestablish` means a relationship is on record again — the
///   peer invited us while we were preparing to invite it. That is the outcome
///   the invite existed to produce, reached from the other side, and §3.6 admits
///   the payload over any state but `None`. Carry on.
/// - `Reestablish` means our half is still `None`: the invite failed for its own
///   reasons (no route, no key, the mediator refused it), nothing has changed,
///   and sending the payload would send it into the §7.2.2 drop. Surface the
///   error.
///
/// A pure function, and deliberately so: the race it answers cannot be staged
/// in a test — it lives between two awaits inside the SDK — so the decision is
/// what gets pinned. Same reason `tsp_inbound::decide_control` is separate from
/// the sends it drives.
#[must_use]
fn invite_refusal_is_benign(after: affinidi_messaging_sdk::SendReadiness) -> bool {
    !matches!(after, affinidi_messaging_sdk::SendReadiness::Reestablish)
}

#[cfg(test)]
mod tests {
    use super::invite_refusal_is_benign;
    use affinidi_messaging_sdk::SendReadiness;

    /// The collision this exists for: the peer's invite landed between our
    /// readiness read and our `SendInvite`, leaving our half `InviteReceived`.
    /// A relationship is on record, so the payload goes.
    #[test]
    fn a_peer_invite_landing_mid_reestablish_is_carried_on_from() {
        assert!(invite_refusal_is_benign(SendReadiness::HandshakeInFlight));
    }

    /// The peer went further and the handshake completed under us. Still on
    /// record, still sendable — more so.
    #[test]
    fn a_completed_relationship_is_carried_on_from() {
        assert!(invite_refusal_is_benign(SendReadiness::Ready));
    }

    /// Nothing on record after the refusal, so the invite genuinely failed.
    /// Sending the payload here would feed it to the peer's §7.2.2 drop and
    /// report success; the error has to stand.
    #[test]
    fn a_half_still_absent_means_the_invite_really_failed() {
        assert!(!invite_refusal_is_benign(SendReadiness::Reestablish));
    }
}
