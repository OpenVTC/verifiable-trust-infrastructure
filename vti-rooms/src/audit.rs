//! What a host may record about a room operation — §8 of the design note.
//!
//! # The trap this module exists to close
//!
//! Every host has audit machinery and every one of them wants to write the acting party's
//! DID into it. On a `private` room that single line destroys the tier: the host was built
//! never to learn the membership, and an audit log naming every actor *is* the membership,
//! assembled one entry at a time by the component least able to notice it is doing so.
//!
//! It is a quiet failure, too. Nothing breaks, no test goes red, and the log looks exactly
//! like the log of an `attributed` room. So the decision is a function here rather than a
//! judgement at each of the two hosts' call sites, and [`AuditActor`] has no constructor
//! that takes a DID unconditionally.
//!
//! # What each tier records
//!
//! | | `Open` | `Attributed` | `Private` |
//! |---|---|---|---|
//! | Who acted | the DID | the DID | **that a member did** |
//! | Which room | yes | yes | yes |
//! | Which record | the key | the opaque key | the opaque key |
//!
//! On `private`, who-did-what exists only *inside* the room, as in-body signatures the
//! members reconstruct client-side. That view covers writes. Reads leave no trace anyone
//! can reconstruct, including the owner — which is the design's position, not an omission.
//!
//! # Reads are audited, and that is the point
//!
//! §8: "reads are the interesting event on shared material". A write log tells you what a
//! room contains; a read log tells you who has seen it, which on shared material is the
//! question an incident review actually asks. It is also why the read log is itself a
//! privacy artifact — on a VTC the actor hash is operator-reversible — and why the
//! `private` tier's actorless recording is not a nicety.
//!
//! Read-volume anomaly detection is a dead end on every tier: agents read constantly, and a
//! design whose whole point is agents reading a room cannot treat reading a lot as a signal.

use crate::Visibility;
use crate::authz::{Action, AuthorizedAction};

/// The actor a host may record for one room operation.
///
/// Constructed only by [`for_operation`], so a host cannot reach for the DID on a tier that
/// withholds it — the one mistake this module exists to make unavailable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditActor {
    /// The tier discloses the actor: record this DID.
    Did(String),
    /// The tier withholds it: record that *a member* acted, and nothing more.
    ///
    /// Not "unknown" and not an empty DID. The host knows a verified member acted — it
    /// verified the chain — and recording that is both true and the most it may say.
    Member,
}

impl AuditActor {
    /// The DID, where the tier discloses one.
    pub fn did(&self) -> Option<&str> {
        match self {
            AuditActor::Did(d) => Some(d),
            AuditActor::Member => None,
        }
    }

    /// A stable string for a log line or a `tracing` field.
    pub fn as_str(&self) -> &str {
        match self {
            AuditActor::Did(d) => d,
            AuditActor::Member => "member",
        }
    }
}

/// What a host records about one authorized operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomAudit {
    /// Who acted, as much as the tier permits saying.
    pub actor: AuditActor,
    /// The room.
    pub room_id: String,
    /// The action, as its wire string.
    pub action: &'static str,
    /// The record, where the operation named one.
    ///
    /// Safe on every tier: on the sealed tiers a key is required to be opaque, so it
    /// identifies a record without describing it. A host that logged a *descriptive* key
    /// would be logging content, which is why the schema requires opacity there.
    pub record_key: Option<String>,
}

/// Decide what may be recorded about `authorized` on `visibility`.
///
/// The only way to build a [`RoomAudit`]. Takes the [`AuthorizedAction`] rather than a
/// presenter string so the subject recorded is the one the *verifier* established — a host
/// cannot record an actor for an operation it did not authorize, and cannot record a
/// different actor from the one it authorized.
pub fn for_operation(
    visibility: Visibility,
    authorized: &AuthorizedAction,
    record_key: Option<&str>,
) -> RoomAudit {
    RoomAudit {
        actor: if visibility.discloses_actor() {
            AuditActor::Did(authorized.subject().to_string())
        } else {
            AuditActor::Member
        },
        room_id: authorized.room_id().to_string(),
        action: authorized.action().as_str(),
        record_key: record_key.map(str::to_string),
    }
}

/// The `room.*` audit action name for an operation.
///
/// Named per the design's `room.*` vocabulary rather than reusing the authority action, so
/// a log distinguishes "read a record" from "listed the room" — both are `read` on the
/// authority axis and different events to anyone reading a log.
pub fn action_name(action: Action, listed: bool) -> &'static str {
    match (action, listed) {
        (Action::Read, true) => "room.records.list",
        (Action::Read, false) => "room.records.get",
        (Action::Write, _) => "room.records.put",
        (Action::Curate, _) => "room.records.curate",
        (Action::Admin, _) => "room.epoch.mint",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Room;
    use crate::authz::{ChainVerifier, VerifiedChain, authorize};
    use crate::wire::AuthorityPresentation;
    use vti_common::error::AppError;

    const PRESENTER: &str = "did:key:zAgent";
    const NOW: u64 = 1_800_000_000;

    struct Vouches;

    #[async_trait::async_trait]
    impl ChainVerifier for Vouches {
        async fn verify(
            &self,
            _: &Room,
            _: &AuthorityPresentation,
            _: Action,
            presenter: &str,
        ) -> Result<VerifiedChain, AppError> {
            Ok(VerifiedChain {
                subject: presenter.to_string(),
                actions: vec!["read".into(), "write".into()],
            })
        }
    }

    async fn authorized(visibility: Visibility) -> AuthorizedAction {
        let room = Room {
            room_id: "did:key:zRoom".into(),
            owner_did: "did:key:zOwner".into(),
            visibility,
            epoch: 1,
            next_version: 1,
            retention_days: 90,
            epoch_expires_at: None,
            created_at: 0,
            updated_at: 0,
        };
        let presentation = AuthorityPresentation {
            membership: "vmc".into(),
            authority: vec!["vac".into()],
            subject_binding: Some("binding".into()),
        };
        authorize(&room, &presentation, Action::Read, PRESENTER, NOW, &Vouches)
            .await
            .expect("authorized")
    }

    #[tokio::test]
    async fn a_disclosing_tier_records_the_actor() {
        for v in [Visibility::Open, Visibility::Attributed] {
            let a = authorized(v).await;
            let entry = for_operation(v, &a, Some("k1"));
            assert_eq!(entry.actor, AuditActor::Did(PRESENTER.into()), "{v:?}");
            assert_eq!(entry.actor.did(), Some(PRESENTER));
        }
    }

    /// The whole reason this module exists. An audit log naming every actor on a private
    /// room *is* the membership the host was built never to learn.
    #[tokio::test]
    async fn a_private_room_records_that_a_member_acted_and_never_who() {
        let a = authorized(Visibility::Private).await;
        let entry = for_operation(Visibility::Private, &a, Some("opaque-key"));

        assert_eq!(entry.actor, AuditActor::Member);
        assert_eq!(
            entry.actor.did(),
            None,
            "there must be no way to get a DID back out"
        );
        assert!(
            !format!("{entry:?}").contains(PRESENTER),
            "the presenter must not survive anywhere in the entry: {entry:?}"
        );
    }

    /// The room and the record are recorded on every tier — an opaque key identifies a
    /// record without describing it, which is why the sealed tiers require opacity.
    #[tokio::test]
    async fn the_room_and_record_are_recorded_on_every_tier() {
        for v in [
            Visibility::Open,
            Visibility::Attributed,
            Visibility::Private,
        ] {
            let a = authorized(v).await;
            let entry = for_operation(v, &a, Some("k1"));
            assert_eq!(entry.room_id, "did:key:zRoom");
            assert_eq!(entry.record_key.as_deref(), Some("k1"));
            assert_eq!(entry.action, "read");
        }
    }

    /// Listing and fetching are both `read` on the authority axis and different events to
    /// anyone reading a log.
    #[test]
    fn listing_and_fetching_are_distinct_actions_in_the_log() {
        assert_eq!(action_name(Action::Read, true), "room.records.list");
        assert_eq!(action_name(Action::Read, false), "room.records.get");
        assert_ne!(
            action_name(Action::Read, true),
            action_name(Action::Read, false)
        );
        assert_eq!(action_name(Action::Admin, false), "room.epoch.mint");
    }
}
