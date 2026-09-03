//! Authorizing an operation on a room.
//!
//! # The invariant this file exists to hold
//!
//! **Nothing here reads this service's ACL, member roster, or session state.** A room
//! operation is authorized by an authority chain the *room* issued, verified against the
//! room's own identifier. That is invariant I5 of the design note, and it is what makes a
//! room portable: the moment a host's own state participates in a room decision, the room
//! cannot move to another host and this service has joined its membership.
//!
//! It is also the easiest invariant in the design to lose by accident — one convenience
//! lookup against `members_ks` "just to check", and the property is gone with every test
//! still passing. [`AuthorizedAction`] is deliberately constructible only by
//! [`authorize`], so a handler cannot skip the check and cannot substitute a different one.
//!
//! # Two halves, and why they are separated
//!
//! Authorizing a room operation has two parts, and only one of them belongs in a crate that
//! anything can depend on:
//!
//! - **Shape.** Is there a chain at all, is it within the depth bound, is there a membership
//!   credential, does a private room carry its subject binding? These need no credential
//!   library, no DID resolution and no network. They live here.
//! - **Cryptography.** Does each credential's proof verify, does the chain reach a root the
//!   room issued, and does it confer the action being asked for? That needs a credential
//!   library and a resolver, and it is reached through [`ChainVerifier`].
//!
//! The split is not squeamishness about dependencies. `verify_chain` and proof verification
//! need `dtg-credentials`, which needs a DID resolver, which is a different thing on a VTC
//! than on a standalone room host. Pinning either choice into this crate would make the
//! storage layer un-reusable for the other. The trait is what lets **one** decision about
//! what is safe to serve be shared by hosts that resolve DIDs differently.
//!
//! It also means a host that has configured no verifier cannot accidentally serve a sealed
//! room: [`RefusesEverything`] is the only thing it has, and it refuses.
//!
//! # The shape checks run first, always
//!
//! [`authorize`] runs every shape check before it calls the verifier, and the order is
//! load-bearing: depth is the cheapest check and the one that bounds the cost of
//! verification, which is linear in chain length and runs on every operation.

use vti_common::error::AppError;

use crate::wire::AuthorityPresentation;
use crate::{Room, Visibility};

/// Maximum links in an authority chain, including the root.
///
/// Verification is linear in chain length and runs on every operation, so an unbounded
/// chain is a denial-of-service surface. The known uses need far less: a person attenuating
/// to an agent is depth 2, that agent to a sub-agent is depth 3. A chain near this ceiling
/// is a signal that authority is being re-delegated further than intended.
pub const MAX_CHAIN_DEPTH: usize = 8;

/// An action on a room.
///
/// Compared exactly and case-sensitively as wire strings, and **no action implies another**:
/// `Admin` does not grant `Write` unless the credential lists both. Implication is how a
/// permission model quietly widens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Read,
    Write,
    Curate,
    Admin,
}

impl Action {
    /// The wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Write => "write",
            Action::Curate => "curate",
            Action::Admin => "admin",
        }
    }
}

/// What a verifier concludes about a presentation.
///
/// Deliberately narrow: the caller gets the subject and the actions the chain confers, and
/// nothing that would tempt it to re-derive a decision the verifier already made.
#[derive(Debug, Clone)]
pub struct VerifiedChain {
    /// The party the leaf grants to — who may act.
    pub subject: String,
    /// The actions the chain confers, already narrowed by every link above the leaf.
    pub actions: Vec<String>,
}

/// Cryptographic verification of a presentation.
///
/// One implementation per host, because the resolver differs; one *decision*, because both
/// implementations answer the same question and [`authorize`] is the only caller.
///
/// # Contract
///
/// An implementation MUST verify, at minimum:
///
/// 1. every credential in the chain carries a valid proof;
/// 2. the chain's root was issued by the room — a chain reaching any other party confers
///    nothing here, however well-formed;
/// 3. no link widens the actions or scope of its parent;
/// 4. every link is within its validity window, and any audience is honoured;
/// 5. the membership credential and the chain describe the same subject;
/// 6. the chain's leaf grants to `presenter` — the party the *transport* authenticated,
///    not one named in the payload.
///
/// (5) is the pooling defence, and it is the verifier's because it needs both credentials
/// parsed. On a `private` room it is proved in zero knowledge from the subject binding; on
/// the disclosing tiers it is a comparison.
///
/// (6) is what stops a captured presentation being replayed. A presentation is a bearer
/// object — it names what may be done, not who is doing it — so without binding it to the
/// authenticated sender, anyone who observes one inherits it. `presenter` is therefore the
/// DID a proof established, never a field a caller filled in.
///
/// Returning `Ok` for a chain that fails any of these is a privilege escalation, not a
/// leniency: anyone can mint a well-formed VAC naming any scope and any action.
/// Verification may need to resolve a DID, so this is async. Keeping it sync would force
/// every implementation to either block a runtime thread or pre-resolve keys it cannot know
/// it will need — and pre-resolution is how a verifier ends up trusting a cache instead of a
/// signature. Same shape as `vti_common::auth::backend`, for the same reason.
#[async_trait::async_trait]
pub trait ChainVerifier: Send + Sync {
    /// Verify `presentation` against `room` for `action`.
    async fn verify(
        &self,
        room: &Room,
        presentation: &AuthorityPresentation,
        action: Action,
        presenter: &str,
    ) -> Result<VerifiedChain, AppError>;
}

/// The verifier a host has before it configures one.
///
/// A host with no credential library cannot check a chain, and a chain nobody checked
/// authorizes nothing — so this refuses, rather than defaulting to permissive and relying on
/// an operator to notice. It is the only safe default a fail-open seam can have.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefusesEverything;

#[async_trait::async_trait]
impl ChainVerifier for RefusesEverything {
    async fn verify(
        &self,
        room: &Room,
        _presentation: &AuthorityPresentation,
        _action: Action,
        _presenter: &str,
    ) -> Result<VerifiedChain, AppError> {
        Err(AppError::Forbidden(format!(
            "room `{}` has no chain verifier configured on this host, and a chain nobody \
             verified authorizes nothing",
            room.room_id
        )))
    }
}

/// Proof that [`authorize`] ran and allowed this operation.
///
/// Handlers take this rather than a presentation, so an operation that forgot to authorize
/// does not compile — the same typestate discipline the workspace uses for verified wire
/// forms. There is no public constructor.
#[derive(Debug)]
pub struct AuthorizedAction {
    action: Action,
    room_id: String,
    verified: VerifiedChain,
}

impl AuthorizedAction {
    /// The action that was authorized.
    pub fn action(&self) -> Action {
        self.action
    }
    /// The room it was authorized against.
    pub fn room_id(&self) -> &str {
        &self.room_id
    }
    /// Who the chain says may act.
    ///
    /// This is the subject the *verifier* established, never one a caller supplied — which
    /// is why a handler recording an author reads it from here.
    pub fn subject(&self) -> &str {
        &self.verified.subject
    }
    /// Everything the chain confers, which is at least the action asked for.
    pub fn conferred(&self) -> &[String] {
        &self.verified.actions
    }
}

/// Authorize `action` on `room` from `presentation`.
///
/// Returns [`AuthorizedAction`] on success. Every failure is [`AppError::Forbidden`], which
/// the dispatch layer maps to the framework's `permission_denied` — the reason text
/// distinguishes the cases for an operator reading logs, without telling a caller which
/// part of their chain to adjust.
pub async fn authorize(
    room: &Room,
    presentation: &AuthorityPresentation,
    action: Action,
    presenter: &str,
    now: u64,
    verifier: &dyn ChainVerifier,
) -> Result<AuthorizedAction, AppError> {
    // Depth first: it is the cheapest check and the one that bounds the cost of every
    // check after it — verification is linear in chain length and runs on every operation.
    if presentation.authority.is_empty() {
        return Err(AppError::Forbidden(
            "no authority chain presented; a room operation is authorized by the chain, \
             never by this service's own records"
                .into(),
        ));
    }
    if presentation.authority.len() > MAX_CHAIN_DEPTH {
        return Err(AppError::Forbidden(format!(
            "authority chain is {} deep, exceeding the maximum of {MAX_CHAIN_DEPTH}",
            presentation.authority.len()
        )));
    }

    if presentation.membership.trim().is_empty() {
        return Err(AppError::Forbidden(
            "no membership credential presented".into(),
        ));
    }

    // The pooling defence. On a tier that withholds the subject, a presentation without a
    // same-subject proof lets two parties combine one's membership with the other's
    // authority and verify as a single party holding both. Checked here because its
    // *absence* is a shape problem; whether a present one actually proves same-subject is
    // the verifier's job.
    if matches!(room.visibility, Visibility::Private) && presentation.subject_binding.is_none() {
        return Err(AppError::Forbidden(
            "a private room requires a subject binding proving the membership credential and \
             the authority chain describe the same subject; without it two parties can pool \
             credentials"
                .into(),
        ));
    }

    // A presentation names what may be done, not who is doing it, so an unbound one is a
    // bearer token: whoever observes it inherits it. The presenter is the DID the request's
    // own proof established.
    if presenter.trim().is_empty() {
        return Err(AppError::Forbidden(
            "no authenticated presenter; a presentation not bound to the party that signed \
             the request is replayable by anyone who observes it"
                .into(),
        ));
    }

    // A room whose epoch has expired is read-only until somebody renews it (§9). Nothing
    // is destroyed, nothing is hidden, and reads keep working in every state — a lapse is a
    // condition a member can notice and fix, not a punishment.
    //
    // `Admin` is exempt, and the exemption is what makes the state machine have an exit:
    // minting an epoch *is* the renewal, so a gate that refused it would leave a lapsed
    // room lapsed forever. It is checked before verification for the same reason depth is —
    // no point verifying a chain for an operation the room cannot accept.
    let lifecycle = room.lifecycle(now);
    if !matches!(action, Action::Admin) && !lifecycle.accepts_writes() && action != Action::Read {
        return Err(AppError::Forbidden(format!(
            "room `{}` is {} and accepts no writes until its epoch is renewed; reads and \
             export still work, and a single `rooms/epoch/mint` restores it",
            room.room_id,
            lifecycle.as_str()
        )));
    }

    // Everything above is shape. This is the decision.
    let verified = verifier
        .verify(room, presentation, action, presenter)
        .await?;

    // The verifier answers "what does this chain confer"; this asserts the answer covers
    // what was asked. Two steps rather than one because a verifier that also decided
    // sufficiency could quietly widen it — and because no action implies another, this is
    // an exact membership test, not a comparison.
    if !verified.actions.iter().any(|a| a == action.as_str()) {
        return Err(AppError::Forbidden(format!(
            "the chain confers {:?}, which does not include `{}`",
            verified.actions,
            action.as_str()
        )));
    }

    // The verifier is contracted to bind the leaf to `presenter`, and this re-states it
    // where the seam can see it. A verifier that returned some other subject would be
    // authorizing one party's chain for another's request; catching that here means the
    // property does not depend on every implementation remembering it.
    if verified.subject != presenter {
        return Err(AppError::Forbidden(format!(
            "the chain grants to `{}`, not to the party that signed this request",
            verified.subject
        )));
    }

    Ok(AuthorizedAction {
        action,
        room_id: room.room_id.clone(),
        verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn room(visibility: Visibility) -> Room {
        Room {
            room_id: "did:key:zRoom".into(),
            owner_did: "did:key:zOwner".into(),
            visibility,
            epoch: 1,
            next_version: 1,
            retention_days: 90,
            epoch_expires_at: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    /// The DID the request's own proof established.
    const PRESENTER: &str = "did:key:zAgent";
    /// Any time at all: the fixtures below have no epoch expiry, so they never lapse.
    const NOW: u64 = 1_800_000_000;

    fn presentation(depth: usize, binding: bool) -> AuthorityPresentation {
        AuthorityPresentation {
            membership: "vmc".into(),
            authority: (0..depth).map(|i| format!("vac-{i}")).collect(),
            subject_binding: binding.then(|| "binding".to_string()),
        }
    }

    /// A verifier that vouches for whatever it is handed.
    ///
    /// Stands in for the cryptographic half so the shape half can be tested on its own. It
    /// is `#[cfg(test)]` on purpose — a permissive verifier is a privilege escalation, and
    /// the only one shipped is [`RefusesEverything`].
    struct Vouches(Vec<String>);

    impl Vouches {
        fn for_all() -> Self {
            Self(
                ["read", "write", "curate", "admin"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            )
        }
        fn read_only() -> Self {
            Self(vec!["read".into()])
        }
    }

    #[async_trait::async_trait]
    impl ChainVerifier for Vouches {
        async fn verify(
            &self,
            _room: &Room,
            _presentation: &AuthorityPresentation,
            _action: Action,
            presenter: &str,
        ) -> Result<VerifiedChain, AppError> {
            Ok(VerifiedChain {
                subject: presenter.to_string(),
                actions: self.0.clone(),
            })
        }
    }

    /// A verifier that vouches for a chain granting to somebody else.
    struct VouchesForSomeoneElse;

    #[async_trait::async_trait]
    impl ChainVerifier for VouchesForSomeoneElse {
        async fn verify(
            &self,
            _room: &Room,
            _presentation: &AuthorityPresentation,
            _action: Action,
            _presenter: &str,
        ) -> Result<VerifiedChain, AppError> {
            Ok(VerifiedChain {
                subject: "did:key:zSomeoneElse".into(),
                actions: vec!["read".into()],
            })
        }
    }

    #[tokio::test]
    async fn a_verified_presentation_authorizes_what_the_chain_confers() {
        let ok = authorize(
            &room(Visibility::Open),
            &presentation(2, false),
            Action::Write,
            PRESENTER,
            NOW,
            &Vouches::for_all(),
        )
        .await
        .expect("should authorize");
        assert_eq!(ok.action(), Action::Write);
        assert_eq!(ok.room_id(), "did:key:zRoom");
        assert_eq!(
            ok.subject(),
            PRESENTER,
            "the subject is the verifier's finding, never the caller's claim"
        );
    }

    /// The whole point of the agent story: a chain conferring `read` writes nothing, and
    /// the refusal comes from `authorize` rather than from any handler remembering to check.
    #[tokio::test]
    async fn a_read_only_chain_cannot_write() {
        let err = authorize(
            &room(Visibility::Open),
            &presentation(2, false),
            Action::Write,
            PRESENTER,
            NOW,
            &Vouches::read_only(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err}").contains("does not include `write`"),
            "{err}"
        );

        authorize(
            &room(Visibility::Open),
            &presentation(2, false),
            Action::Read,
            PRESENTER,
            NOW,
            &Vouches::read_only(),
        )
        .await
        .expect("but it reads");
    }

    /// `admin` does not follow from `write`. Implication is how a permission model widens.
    #[tokio::test]
    async fn no_action_implies_another() {
        let err = authorize(
            &room(Visibility::Open),
            &presentation(1, false),
            Action::Admin,
            PRESENTER,
            NOW,
            &Vouches(vec!["read".into(), "write".into(), "curate".into()]),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err}").contains("does not include `admin`"),
            "{err}"
        );
    }

    /// The chain is the authorization. Nothing else is.
    #[tokio::test]
    async fn an_empty_chain_authorizes_nothing() {
        let err = authorize(
            &room(Visibility::Open),
            &presentation(0, false),
            Action::Read,
            PRESENTER,
            NOW,
            &Vouches::for_all(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err}").contains("no authority chain"), "{err}");
    }

    #[tokio::test]
    async fn a_chain_past_the_ceiling_is_refused() {
        let err = authorize(
            &room(Visibility::Open),
            &presentation(MAX_CHAIN_DEPTH + 1, false),
            Action::Read,
            PRESENTER,
            NOW,
            &Vouches::for_all(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err}").contains("exceeding the maximum"), "{err}");
    }

    /// Depth is checked before the verifier runs, so an over-deep chain costs nothing to
    /// refuse — which is the reason it is first.
    #[tokio::test]
    async fn the_shape_checks_run_before_the_verifier() {
        struct Panics;
        #[async_trait::async_trait]
        impl ChainVerifier for Panics {
            async fn verify(
                &self,
                _: &Room,
                _: &AuthorityPresentation,
                _: Action,
                _: &str,
            ) -> Result<VerifiedChain, AppError> {
                panic!("the verifier must not be reached for a malformed presentation");
            }
        }

        for p in [
            presentation(0, false),
            presentation(MAX_CHAIN_DEPTH + 1, false),
        ] {
            assert!(
                authorize(
                    &room(Visibility::Open),
                    &p,
                    Action::Read,
                    PRESENTER,
                    NOW,
                    &Panics
                )
                .await
                .is_err()
            );
        }
    }

    /// Without this, two parties pool credentials and verify as one.
    #[tokio::test]
    async fn a_private_room_refuses_a_presentation_with_no_subject_binding() {
        let err = authorize(
            &room(Visibility::Private),
            &presentation(2, false),
            Action::Read,
            PRESENTER,
            NOW,
            &Vouches::for_all(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err}").contains("subject binding"), "{err}");
    }

    /// A host that has configured no verifier serves nothing — on any tier, not just the
    /// sealed ones. Fail-closed is the only safe default for a seam like this.
    #[tokio::test]
    async fn a_host_with_no_verifier_authorizes_nothing() {
        for v in [
            Visibility::Open,
            Visibility::Attributed,
            Visibility::Private,
        ] {
            let err = authorize(
                &room(v),
                &presentation(2, true),
                Action::Read,
                PRESENTER,
                NOW,
                &RefusesEverything,
            )
            .await
            .unwrap_err();
            assert!(
                format!("{err}").contains("no chain verifier configured"),
                "{v:?}: {err}"
            );
        }
    }

    /// A presentation is a bearer object. Without binding it to the signer, anyone who
    /// observes one inherits it.
    #[tokio::test]
    async fn an_unbound_presentation_is_refused() {
        let err = authorize(
            &room(Visibility::Open),
            &presentation(2, false),
            Action::Read,
            "   ",
            NOW,
            &Vouches::for_all(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err}").contains("no authenticated presenter"),
            "{err}"
        );
    }

    /// The seam re-states the binding rather than trusting each verifier to remember it.
    #[tokio::test]
    async fn a_chain_granting_to_someone_else_is_refused() {
        let err = authorize(
            &room(Visibility::Open),
            &presentation(2, false),
            Action::Read,
            PRESENTER,
            NOW,
            &VouchesForSomeoneElse,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err}").contains("not to the party that signed this request"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_missing_membership_credential_is_refused() {
        let mut p = presentation(2, false);
        p.membership = "  ".into();
        let err = authorize(
            &room(Visibility::Open),
            &p,
            Action::Read,
            PRESENTER,
            NOW,
            &Vouches::for_all(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err}").contains("no membership credential"),
            "{err}"
        );
    }

    /// A lapsed room is read-only, and the refusal says how to fix it.
    #[tokio::test]
    async fn a_lapsed_room_refuses_writes_and_keeps_serving_reads() {
        let mut r = room(Visibility::Open);
        r.epoch_expires_at = Some(NOW - 1);

        let err = authorize(
            &r,
            &presentation(2, false),
            Action::Write,
            PRESENTER,
            NOW,
            &Vouches::for_all(),
        )
        .await
        .unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("accepts no writes"), "{text}");
        assert!(
            text.contains("rooms/epoch/mint"),
            "the refusal must say how to fix it: {text}"
        );

        authorize(
            &r,
            &presentation(2, false),
            Action::Read,
            PRESENTER,
            NOW,
            &Vouches::for_all(),
        )
        .await
        .expect("a lapse hides nothing — reads keep working");
    }

    /// The exemption that gives the state machine an exit. Minting an epoch *is* the
    /// renewal, so a gate that refused it would leave a lapsed room lapsed forever — and
    /// that holds all the way to `Reclaimable`, because until the bytes are deleted the
    /// members' choice is renew or export.
    #[tokio::test]
    async fn every_lapsed_state_still_accepts_the_operation_that_renews_it() {
        let mut r = room(Visibility::Open);
        r.retention_days = 90;

        for (days_past_expiry, state) in [(1, "lapsed"), (31, "dormant"), (91, "reclaimable")] {
            r.epoch_expires_at = Some(NOW - days_past_expiry * 24 * 60 * 60);
            assert_eq!(
                r.lifecycle(NOW).as_str(),
                state,
                "fixture should be {state}"
            );

            authorize(
                &r,
                &presentation(2, false),
                Action::Admin,
                PRESENTER,
                NOW,
                &Vouches::for_all(),
            )
            .await
            .unwrap_or_else(|e| panic!("a {state} room must still accept a renewal: {e}"));

            let err = authorize(
                &r,
                &presentation(2, false),
                Action::Write,
                PRESENTER,
                NOW,
                &Vouches::for_all(),
            )
            .await
            .unwrap_err();
            assert!(
                format!("{err}").contains("accepts no writes"),
                "a {state} room must refuse ordinary writes: {err}"
            );
        }
    }

    /// Curation is a write. A room nobody has renewed should not be quietly reorganised.
    #[tokio::test]
    async fn a_lapsed_room_refuses_curation() {
        let mut r = room(Visibility::Open);
        r.epoch_expires_at = Some(NOW - 1);
        let err = authorize(
            &r,
            &presentation(2, false),
            Action::Curate,
            PRESENTER,
            NOW,
            &Vouches::for_all(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err}").contains("accepts no writes"), "{err}");
    }

    /// No action implies another — the property that keeps a permission model from
    /// widening quietly.
    #[test]
    fn actions_are_distinct_wire_strings() {
        assert_eq!(Action::Read.as_str(), "read");
        assert_eq!(Action::Admin.as_str(), "admin");
        assert_ne!(Action::Admin.as_str(), Action::Write.as_str());
    }
}
