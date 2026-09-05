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

/// A room operation, as an audit log names it.
///
/// The authority action is not enough to name an operation, and the gap is not cosmetic.
/// Three distinct operations gate on `admin` — minting an epoch, handing the room to
/// someone, and a successor taking it — and an audit trail that recorded all three as
/// `room.epoch.mint` would be at its least informative at exactly the moment someone reads
/// it, which is after an ownership change they did not expect.
///
/// So the handler names the operation and the required action is *derived* from it
/// ([`RoomOperation::required_action`]). That direction matters: it is the one that cannot
/// drift. A handler cannot gate on `read` while logging a transfer, because it does not get
/// to choose both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomOperation {
    /// Read one record.
    GetRecord,
    /// Enumerate the room's records. Distinct from a read on the same authority: both are
    /// `read`, and "read one document" and "took an inventory of the room" are different
    /// events to anyone reading a log.
    ListRecords,
    /// Write a record.
    PutRecord,
    /// Change a record's standing.
    CurateRecord,
    /// Advance the epoch — which is also what renews the room.
    MintEpoch,
    /// The owner hands the room to another member.
    TransferOwner,
    /// A nominated successor takes a dormant room.
    ClaimOwner,
}

impl RoomOperation {
    /// The `room.*` audit action name, per the design's vocabulary.
    pub fn action_name(self) -> &'static str {
        match self {
            RoomOperation::GetRecord => "room.records.get",
            RoomOperation::ListRecords => "room.records.list",
            RoomOperation::PutRecord => "room.records.put",
            RoomOperation::CurateRecord => "room.records.curate",
            RoomOperation::MintEpoch => "room.epoch.mint",
            RoomOperation::TransferOwner => "room.owner.transfer",
            RoomOperation::ClaimOwner => "room.owner.claim",
        }
    }

    /// The authority action a party must hold to perform it.
    ///
    /// `ClaimOwner` is `Read`, and that is not a weaker gate by accident. A successor is
    /// being checked for *membership* — the room's own statement that they are a member and
    /// so could renew what they are claiming — not for authority they were never given. What
    /// authorizes the claim is the nomination, which is verified separately and is the only
    /// thing that makes the operation possible at all.
    pub fn required_action(self) -> Action {
        match self {
            RoomOperation::GetRecord | RoomOperation::ListRecords | RoomOperation::ClaimOwner => {
                Action::Read
            }
            RoomOperation::PutRecord => Action::Write,
            RoomOperation::CurateRecord => Action::Curate,
            RoomOperation::MintEpoch | RoomOperation::TransferOwner => Action::Admin,
        }
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
        assert_eq!(
            RoomOperation::ListRecords.action_name(),
            "room.records.list"
        );
        assert_eq!(RoomOperation::GetRecord.action_name(), "room.records.get");
        assert_eq!(
            RoomOperation::ListRecords.required_action(),
            RoomOperation::GetRecord.required_action(),
            "the same authority, and that is exactly why the action name has to differ"
        );
    }

    /// The defect this enum exists to prevent: three operations gate on `admin`, and a log
    /// that called all three `room.epoch.mint` would be least useful precisely when someone
    /// is trying to find out who took the room.
    #[test]
    fn every_operation_has_its_own_name() {
        let all = [
            RoomOperation::GetRecord,
            RoomOperation::ListRecords,
            RoomOperation::PutRecord,
            RoomOperation::CurateRecord,
            RoomOperation::MintEpoch,
            RoomOperation::TransferOwner,
            RoomOperation::ClaimOwner,
        ];
        let mut names: Vec<_> = all.iter().map(|o| o.action_name()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "two operations share an audit name");

        for op in all {
            assert!(
                op.action_name().starts_with("room."),
                "{op:?} is outside the room.* vocabulary"
            );
        }
    }

    /// A claim is gated on membership, not on authority the successor was never given —
    /// what authorizes it is the nomination, checked elsewhere.
    #[test]
    fn a_claim_asks_for_membership_not_admin() {
        assert_eq!(RoomOperation::ClaimOwner.required_action(), Action::Read);
        assert_eq!(
            RoomOperation::TransferOwner.required_action(),
            Action::Admin,
            "an owner handing the room away is the most consequential thing they do"
        );
    }
}
