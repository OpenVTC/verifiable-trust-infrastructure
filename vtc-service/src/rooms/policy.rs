//! Who may create a room **on this community** — §7.4 of the data-rooms design.
//!
//! # Why this is not a violation of invariant I5
//!
//! Every *operation* on a room is authorized by credentials the room itself
//! issued, and [`super::handlers`] never consults this service's roster to
//! decide one. That is I5, and it is what makes a room portable.
//!
//! Creation is the exception the design names, and it is not the same question.
//! A host that refuses to store a room is not deciding who belongs to it — the
//! room does not exist yet and has issued nothing. It is deciding whether to
//! lend its disk, which is the one thing a host is unambiguously entitled to
//! decide: *"A VTC governs what its members may create on it"*. Nothing here
//! reaches an existing room, and a room created elsewhere is unaffected.
//!
//! # What a policy can see, and what it cannot
//!
//! The design sketches an input contract carrying `didControlledBy` and
//! `contentStoredAt` — which of the two hosting axes the creator is asking for.
//! **The published `rooms/create/0.1` schema carries neither**, so a host cannot
//! know them and this input does not pretend to: it offers the creator (with
//! their community standing), and the room's identifier, visibility and owner.
//! Inventing the missing members locally would put this service's rooms out of
//! conformance with the schema every other host reads.
//!
//! # The verification gate
//!
//! [`VerifiedRoomCreation`] has no public constructor: it is reachable only
//! through [`VerifiedRoomCreation::assemble`], which takes the DID a *proof*
//! established. The convention `ceremony::verify` sets — policy input is always
//! the output of a verification gate, never a caller's payload — holds here for
//! the same reason: a policy that branched on an unproven actor would be
//! deciding about somebody who had not been shown to be there.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::policy::engine::{CompiledPolicy, evaluate};
use vti_common::error::AppError;
use vti_rooms::Visibility;

/// The `input` document a `rooms` policy evaluates over.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoomCreationFacts {
    /// Evaluation timestamp, so a policy compares against this rather than
    /// reading a wall clock — the same reason the ceremony facts carry one.
    pub now: DateTime<Utc>,
    pub actor: Actor,
    pub room: RoomRequest,
}

/// The party asking to create the room.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Actor {
    /// The DID the request's own proof established — never a payload field.
    pub did: String,
    /// Their community role, when this service holds a member row for them.
    /// `None` for a stranger, which is the case the default policy denies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Whether this service holds a member row for the actor at all. Surfaced
    /// separately from `role` so a policy can say "any member" without
    /// enumerating roles, and so an absent role is unambiguous.
    pub member: bool,
}

/// The room being asked for.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoomRequest {
    /// The room's own identifier, which the creator minted.
    pub room_id: String,
    /// `open` | `attributed` | `private`.
    pub visibility: Visibility,
    /// The accountable party. Equal to `actor.did` — a registration is signed
    /// by the owner it names — and carried anyway so a policy reads what it
    /// governs rather than inferring it.
    pub owner_did: String,
    /// How long the host is asked to hold the room after it lapses. A policy
    /// may cap it; nothing here does by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u32>,
}

/// Facts that passed the verification gate.
///
/// No public constructor and no public fields: the only way to obtain one is
/// [`Self::assemble`], so a policy can never be evaluated over an actor nobody
/// authenticated.
#[derive(Debug, Clone)]
pub struct VerifiedRoomCreation(RoomCreationFacts);

impl VerifiedRoomCreation {
    /// Seal the facts for evaluation.
    ///
    /// `presenter` is the DID the request document's own `eddsa-jcs-2022` proof
    /// established. Everything else describes the room being asked for.
    pub fn assemble(facts: RoomCreationFacts) -> Result<Self, AppError> {
        if facts.actor.did.trim().is_empty() {
            // Belt and braces: the caller reaches this with a proof-verified
            // DID, and an empty one would mean the proof layer returned
            // something impossible. Denying beats evaluating a policy about
            // nobody.
            return Err(AppError::Forbidden(
                "a room registration must name the party that signed it".into(),
            ));
        }
        Ok(Self(facts))
    }

    /// The JSON `input` the policy sees.
    pub fn to_input(&self) -> Result<JsonValue, AppError> {
        serde_json::to_value(&self.0).map_err(AppError::from)
    }

    /// The facts, for the audit trail and the refusal message.
    pub fn facts(&self) -> &RoomCreationFacts {
        &self.0
    }
}

/// The decision shape a `rooms` policy returns — the same `{effect, with}`
/// object every other purpose in this service uses, so one authoring style
/// serves them all.
#[derive(Debug, Clone, Deserialize)]
struct Decision {
    effect: String,
    #[serde(default)]
    with: DecisionWith,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct DecisionWith {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// Query the default bundle answers.
const DECISION_QUERY: &str = "data.vtc.rooms.decision";

/// Decide whether this creation may proceed.
///
/// `Ok(())` is an allow. Everything else is [`AppError::Forbidden`] carrying the
/// policy's own code, so an operator reading a refusal sees which rule produced
/// it rather than a bare 403.
///
/// **A policy that answers nothing is a deny.** Rego is permissive about a
/// missing rule — an empty result set is not an error — and reading that as
/// "no objection" would turn a typo in a policy name into an open host. The
/// default bundle is total (it carries a `default decision`), and this treats a
/// non-total operator policy the same way it treats an explicit deny.
pub fn decide_room_creation(
    verified: &VerifiedRoomCreation,
    policy: &CompiledPolicy,
) -> Result<(), AppError> {
    let results = evaluate(policy, DECISION_QUERY, verified.to_input()?)?;

    // regorus returns `{"result": [{"expressions": [{"value": …}]}]}`.
    let value = results
        .get("result")
        .and_then(|r| r.as_array())
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("expressions"))
        .and_then(|e| e.as_array())
        .and_then(|exprs| exprs.first())
        .and_then(|expr| expr.get("value"));

    let Some(value) = value else {
        tracing::warn!(
            room = %verified.facts().room.room_id,
            "the active rooms policy produced no decision; refusing the registration"
        );
        return Err(AppError::Forbidden(
            "room creation denied (no-decision): the active rooms policy answered nothing, \
             which is refused rather than read as consent"
                .into(),
        ));
    };

    let decision: Decision = serde_json::from_value(value.clone()).map_err(|e| {
        AppError::Internal(format!(
            "the active rooms policy returned a decision this service cannot read: {e}"
        ))
    })?;

    match decision.effect.as_str() {
        "allow" => Ok(()),
        "deny" => {
            let code = decision.with.code.unwrap_or_else(|| "denied".to_string());
            let reason = decision
                .with
                .reason
                .map(|r| format!(": {r}"))
                .unwrap_or_default();
            Err(AppError::Forbidden(format!(
                "room creation denied ({code}){reason}"
            )))
        }
        // `refer` and `request-more` are the threaded ceremony verdicts. A
        // registration is one synchronous call with no thread to resume, so a
        // policy returning one is misconfigured — and the safe reading of a
        // verdict this surface cannot honour is refusal.
        other => {
            tracing::warn!(
                effect = other,
                room = %verified.facts().room.room_id,
                "the active rooms policy returned a verdict room creation cannot honour"
            );
            Err(AppError::Forbidden(format!(
                "room creation denied (unsupported-verdict): the active rooms policy \
                 answered `{other}`, which this synchronous surface cannot carry out"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::default::default_source;
    use crate::policy::engine::compile;
    use crate::policy::model::PolicyPurpose;

    fn facts(role: Option<&str>, member: bool, visibility: Visibility) -> VerifiedRoomCreation {
        VerifiedRoomCreation::assemble(RoomCreationFacts {
            now: "2026-09-07T12:00:00Z".parse().unwrap(),
            actor: Actor {
                did: "did:key:zCreator".into(),
                role: role.map(str::to_string),
                member,
            },
            room: RoomRequest {
                room_id: "did:webvh:room.example".into(),
                visibility,
                owner_did: "did:key:zCreator".into(),
                retention_days: Some(90),
            },
        })
        .expect("a signed registration assembles")
    }

    fn default_policy() -> CompiledPolicy {
        compile(default_source(PolicyPurpose::Rooms), uuid::Uuid::nil())
            .expect("the bundled rooms policy compiles")
    }

    #[test]
    fn a_member_may_create_an_open_room() {
        decide_room_creation(
            &facts(Some("member"), true, Visibility::Open),
            &default_policy(),
        )
        .expect("the shipped default permits open rooms for members");
    }

    #[test]
    fn a_member_may_create_an_attributed_room() {
        decide_room_creation(
            &facts(Some("member"), true, Visibility::Attributed),
            &default_policy(),
        )
        .expect("attributed is permitted by default too — the host cannot read it either way");
    }

    /// §7.4's default posture: `private` is denied until an operator enables it.
    /// Not because it is dangerous, but because a community that has not decided
    /// should not discover it is hosting rooms whose membership it cannot see.
    #[test]
    fn private_is_denied_until_an_operator_enables_it() {
        let err = decide_room_creation(
            &facts(Some("member"), true, Visibility::Private),
            &default_policy(),
        )
        .expect_err("the shipped default denies private");
        assert!(
            matches!(err, AppError::Forbidden(ref m) if m.contains("private")),
            "the refusal must name the tier it refused: {err:?}"
        );
    }

    /// The gap this whole change closes: before it, anyone who could reach the
    /// endpoint could register a room in their own name on somebody else's host.
    #[test]
    fn a_stranger_may_not_create_a_room_here() {
        let err = decide_room_creation(&facts(None, false, Visibility::Open), &default_policy())
            .expect_err("a non-member is refused by the shipped default");
        assert!(
            matches!(err, AppError::Forbidden(ref m) if m.contains("not-a-member")),
            "the refusal must carry the policy's own code: {err:?}"
        );
    }

    /// A policy naming no `decision` rule answers with an empty set, which Rego
    /// does not treat as an error. Reading that as consent would turn a typo
    /// into an open host.
    #[test]
    fn a_policy_that_decides_nothing_refuses() {
        let silent = compile(
            "package vtc.rooms\n\nimport rego.v1\n\nunrelated := true\n",
            uuid::Uuid::nil(),
        )
        .expect("a policy with no decision rule still compiles");

        let err = decide_room_creation(&facts(Some("member"), true, Visibility::Open), &silent)
            .expect_err("no decision is a refusal");
        assert!(
            matches!(err, AppError::Forbidden(ref m) if m.contains("no-decision")),
            "got {err:?}"
        );
    }

    /// A verdict the synchronous surface cannot carry out is refused rather
    /// than approximated.
    #[test]
    fn a_threaded_verdict_is_refused() {
        let refers = compile(
            "package vtc.rooms\n\nimport rego.v1\n\n\
             decision := {\"effect\": \"refer\", \"with\": {\"code\": \"ask-an-admin\"}}\n",
            uuid::Uuid::nil(),
        )
        .expect("compiles");

        let err = decide_room_creation(&facts(Some("member"), true, Visibility::Open), &refers)
            .expect_err("refer cannot be honoured here");
        assert!(
            matches!(err, AppError::Forbidden(ref m) if m.contains("unsupported-verdict")),
            "got {err:?}"
        );
    }

    #[test]
    fn an_unsigned_registration_never_reaches_a_policy() {
        let err = VerifiedRoomCreation::assemble(RoomCreationFacts {
            now: Utc::now(),
            actor: Actor {
                did: "  ".into(),
                role: None,
                member: false,
            },
            room: RoomRequest {
                room_id: "did:webvh:room.example".into(),
                visibility: Visibility::Open,
                owner_did: "did:key:zCreator".into(),
                retention_days: None,
            },
        })
        .expect_err("an empty actor is refused at the gate");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }
}
