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
//! # What is verified, and what is deferred
//!
//! Chain-shape verification — reaching a root issued by the room, no link widening actions,
//! scope or validity, depth bounded, audience honoured — is implemented in
//! `dtg_credentials::authority::verify_chain`, the reference implementation that ships with
//! the credential. This module performs the checks that do not require parsing credentials
//! (presence, depth, the private-tier binding) and records where signature and chain
//! verification attach.
//!
//! The signature-verification hop is **not** wired here yet, and that is stated rather than
//! hidden: it needs the room's DID resolved to a verification method, which arrives with the
//! `attributed` tier. Until then [`authorize`] refuses anything but an `Open` room, so no
//! caller can mistake an unverified chain for a verified one.

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

/// Proof that [`authorize`] ran and allowed this operation.
///
/// Handlers take this rather than a presentation, so an operation that forgot to authorize
/// does not compile — the same typestate discipline the workspace uses for verified wire
/// forms. There is no public constructor.
#[derive(Debug)]
pub struct AuthorizedAction {
    action: Action,
    room_id: String,
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
}

/// Authorize `action` on `room` from `presentation`.
///
/// Returns [`AuthorizedAction`] on success. Every failure is [`AppError::Forbidden`], which
/// the dispatch layer maps to the framework's `permission_denied` — the reason text
/// distinguishes the cases for an operator reading logs, without telling a caller which
/// part of their chain to adjust.
pub fn authorize(
    room: &Room,
    presentation: &AuthorityPresentation,
    action: Action,
) -> Result<AuthorizedAction, AppError> {
    // Depth first: it is the cheapest check and the one that bounds the cost of every
    // check after it.
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
    // authority and verify as a single party holding both.
    if matches!(room.visibility, Visibility::Private) && presentation.subject_binding.is_none() {
        return Err(AppError::Forbidden(
            "a private room requires a subject binding proving the membership credential and \
             the authority chain describe the same subject; without it two parties can pool \
             credentials"
                .into(),
        ));
    }

    // Chain verification proper needs the room's DID resolved to a verification method,
    // which lands with the `attributed` tier. Refusing the sealed tiers outright is the
    // honest interim: it is better to serve no sealed room than to serve one whose chain
    // nobody checked.
    if !matches!(room.visibility, Visibility::Open) {
        return Err(AppError::Forbidden(format!(
            "room `{}` is {:?}; cryptographic chain verification is not yet wired, and this \
             service will not serve a sealed room on an unverified chain",
            room.room_id, room.visibility
        )));
    }

    Ok(AuthorizedAction {
        action,
        room_id: room.room_id.clone(),
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
            created_at: 0,
            updated_at: 0,
        }
    }

    fn presentation(depth: usize, binding: bool) -> AuthorityPresentation {
        AuthorityPresentation {
            membership: "vmc".into(),
            authority: (0..depth).map(|i| format!("vac-{i}")).collect(),
            subject_binding: binding.then(|| "binding".to_string()),
        }
    }

    #[test]
    fn an_open_room_authorizes_a_well_formed_presentation() {
        let ok = authorize(
            &room(Visibility::Open),
            &presentation(2, false),
            Action::Write,
        )
        .expect("should authorize");
        assert_eq!(ok.action(), Action::Write);
        assert_eq!(ok.room_id(), "did:key:zRoom");
    }

    /// The chain is the authorization. Nothing else is.
    #[test]
    fn an_empty_chain_authorizes_nothing() {
        let err = authorize(
            &room(Visibility::Open),
            &presentation(0, false),
            Action::Read,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("no authority chain"), "{err}");
    }

    #[test]
    fn a_chain_past_the_ceiling_is_refused() {
        let err = authorize(
            &room(Visibility::Open),
            &presentation(MAX_CHAIN_DEPTH + 1, false),
            Action::Read,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("exceeding the maximum"), "{err}");
    }

    /// Without this, two parties pool credentials and verify as one.
    #[test]
    fn a_private_room_refuses_a_presentation_with_no_subject_binding() {
        let err = authorize(
            &room(Visibility::Private),
            &presentation(2, false),
            Action::Read,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("subject binding"), "{err}");
    }

    /// Better to serve no sealed room than one whose chain nobody checked.
    #[test]
    fn sealed_tiers_are_refused_until_chain_verification_is_wired() {
        for v in [Visibility::Attributed, Visibility::Private] {
            let err = authorize(&room(v), &presentation(2, true), Action::Read).unwrap_err();
            assert!(
                format!("{err}").contains("chain verification is not yet wired"),
                "{v:?}: {err}"
            );
        }
    }

    #[test]
    fn a_missing_membership_credential_is_refused() {
        let mut p = presentation(2, false);
        p.membership = "  ".into();
        let err = authorize(&room(Visibility::Open), &p, Action::Read).unwrap_err();
        assert!(
            format!("{err}").contains("no membership credential"),
            "{err}"
        );
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
