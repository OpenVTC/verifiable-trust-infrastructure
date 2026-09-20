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
    /// Delegates, and that is a decision with history. #1582 spelled the three
    /// steps out here — readiness, invite, payload — because the SDK's readiness
    /// read and its `SendInvite` are two separate awaits on the relationship
    /// store, and the peer can move our half between them: its own invite
    /// arrives, `None` + `ReceiveInvite` leaves us `InviteReceived`, and
    /// `SendInvite` is legal only from `None`. The refused invite took the
    /// payload down with it, which the D6 recovery then reported as a peer that
    /// "did not answer" a request it had never been sent.
    ///
    /// The SDK does that re-read itself from **0.26.12** (affinidi-tdk-rs #838),
    /// so the local copy is gone: one owner for the decision, and `vtc-service`'s
    /// registry client — which calls the SDK's form directly — is covered by the
    /// same bump rather than needing its own copy. The floor in `Cargo.toml` is
    /// `0.26.12` and not `0.26` precisely because of this: on `^0.26` a lockfile
    /// resolving 0.26.11 would put the race back with nothing here to catch it.
    pub async fn send_reestablishing(
        &self,
        recipient: &str,
        body: &[u8],
    ) -> Result<(), affinidi_messaging_sdk::errors::ATMError> {
        self.atm
            .tsp()
            .send_reestablishing(
                &self.profile,
                recipient,
                &[self.mediator_did.clone(), recipient.to_string()],
                body,
            )
            .await
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
