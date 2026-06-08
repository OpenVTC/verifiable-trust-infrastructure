//! The Facts contract — the purpose-agnostic policy `input` every
//! ceremony shares (ceremony-pipeline design §3).
//!
//! One typed shape feeds every `<purpose>.rego` module. It is the
//! greenfield replacement for the MVP's lossy
//! [`crate::policy::extract::extract_vp_claims`] projection: instead
//! of handing the policy a flattened `vp_claims` blob, the host hands
//! it **structured, pre-verified facts** — `actor` / `subject` /
//! `context` / `evidence` / `state`. Crypto (signatures,
//! holder-binding, revocation, issuer-trust) is resolved by the host
//! *before* a [`Facts`] is ever assembled (see
//! [`crate::ceremony::verify`]); the policy therefore reasons only
//! over booleans + claims, never over a signature.
//!
//! ## Wire shape is load-bearing
//!
//! These structs serialize to the exact JSON the Rule-IR-compiled
//! Rego reads — `snake_case` keys, `evidence.presentation.
//! credentials[].issuer_trusted`, `state.subject_member`, and so on.
//! The runnable policies under
//! `docs/05-design-notes/examples/*.rego` are the ground truth for
//! field names; the round-trip tests at the bottom of this module
//! lock the serialized shape against those examples. Renaming a field
//! here silently breaks every compiled policy that reads it, so the
//! `#[serde(rename = …)]` / `rename_all` attributes are part of the
//! contract, not cosmetic.
//!
//! ## Optionality convention
//!
//! - Evidence slots a ceremony doesn't use are **absent**
//!   (`skip_serializing_if`), not `null` — `directory` facts carry
//!   only `evidence.request`. Rego treats absent + `null` identically
//!   (both `undefined`), so the compiled helpers (`cred_trusted`,
//!   `has_valid_invitation`, …) defend against both.
//! - `state.subject_member` is the one slot serialized as explicit
//!   `null` when empty (an unknown DID joining has no member row) —
//!   the design example shows it present-but-null, and policies read
//!   `input.state.subject_member` directly.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Which ceremony this evaluation is deciding.
///
/// This is the **pipeline** vocabulary (`docs/05-design-notes/
/// vtc-ceremony-catalog.md`), deliberately distinct from the MVP's
/// nine-variant [`crate::policy::model::PolicyPurpose`]: the
/// greenfield pipeline replaces "nine bespoke per-purpose flows" with
/// one pipeline parameterized by this enum (pipeline §10). The
/// variants here are the four ceremonies that have worked examples +
/// compiled policies under `docs/05-design-notes/examples/`; more
/// land as ceremonies are ported onto the pipeline.
///
/// Naming reconciliation with `PolicyPurpose` is an open migration
/// item (pipeline §12, decisions 7): the MVP calls the destructive
/// ceremony `removal`; the pipeline calls it `leave`. The wire
/// strings here follow the catalog (`kebab-case`: `role-change`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    /// A DID joining the community (constructive; actor usually ==
    /// subject; threaded — supports `request_more` / `refer`).
    Join,
    /// A member departing or being removed (destructive; actor may
    /// differ from subject; no-last-admin invariant applies).
    Leave,
    /// A member's role being changed in place (mutating; the one
    /// ceremony whose `allow` may grant `admin`, gated by step-up).
    RoleChange,
    /// A read-only directory query (synchronous, unthreaded; `allow`
    /// returns a field projection rather than a state mutation).
    Directory,
}

impl Purpose {
    /// Stable wire string (matches the serde representation and the
    /// `purpose` field of the example facts files).
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Join => "join",
            Purpose::Leave => "leave",
            Purpose::RoleChange => "role-change",
            Purpose::Directory => "directory",
        }
    }

    /// The Rego package whose `decision` rule decides this ceremony.
    /// Identifiers can't carry hyphens, so `role-change` →
    /// `vtc.role_change`.
    ///
    /// Note the [`Purpose::Leave`] → `vtc.removal` mapping: the
    /// pipeline's friendly name for the destructive ceremony is
    /// "leave", but it reuses the MVP's `removal` policy purpose
    /// ([`crate::policy::model::PolicyPurpose::Removal`]) and package
    /// rather than introducing a parallel `leave` purpose — settling
    /// the leave/removal naming drift (pipeline §12) in favour of the
    /// established runtime name. Facts still serialize `purpose:
    /// "leave"`; only the policy package is `vtc.removal`.
    pub fn rego_package(self) -> &'static str {
        match self {
            Purpose::Join => "vtc.join",
            Purpose::Leave => "vtc.removal",
            Purpose::RoleChange => "vtc.role_change",
            Purpose::Directory => "vtc.directory",
        }
    }

    /// The full query the evaluate stage runs against a compiled
    /// policy for this purpose — the `decision` rule in the purpose's
    /// package. Every ceremony policy exposes a single `decision`
    /// object (pipeline §4), so this is the one query the host needs.
    pub fn decision_query(self) -> String {
        format!("data.{}.decision", self.rego_package())
    }
}

/// The purpose-agnostic policy input. Assembled by the host after
/// verification; consumed by `<purpose>.rego`.
///
/// Construct a [`Facts`] directly only at the host boundary that has
/// just finished verifying evidence — downstream code should take a
/// [`crate::ceremony::verify::VerifiedFacts`], which can only be
/// produced by running [`Facts`] through the verification gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Facts {
    /// Which ceremony is being decided. Selects the policy module
    /// and the effect handler.
    pub purpose: Purpose,
    /// Evaluation timestamp. Policies compare credential
    /// `valid_until` / member `joined_at` against this rather than
    /// reading a wall-clock, so a simulation can pin "now".
    pub now: DateTime<Utc>,
    /// Who initiated the transition.
    pub actor: Actor,
    /// Who the transition is *about*. May equal [`Actor::did`]
    /// (self-join, self-leave) or differ (admin removing a member).
    pub subject: Subject,
    /// Ambient community facts the policy may branch on.
    pub context: Context,
    /// What the actor presented. Ceremonies populate only the slots
    /// they use.
    pub evidence: Evidence,
    /// Authoritative current state relevant to the decision, read
    /// from the ACL / member keyspaces.
    pub state: State,
}

/// The authenticated initiator of the ceremony.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Actor {
    /// The actor's DID (the proven signer at the route layer).
    pub did: String,
    /// The actor's community role from the ACL, when they are a
    /// member. Absent for an unknown DID (e.g. an applicant joining).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Whether the route layer authenticated this actor. The host
    /// rejects truly anonymous triggers before assembling facts; the
    /// flag is surfaced so policies can branch (e.g. an open-join
    /// route that tolerates an unauthenticated applicant).
    pub authenticated: bool,
}

/// The DID the transition concerns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subject {
    pub did: String,
}

/// Ambient community context.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Context {
    /// The community this ceremony runs against.
    pub community_did: String,
    /// Transport the trigger arrived over (`"rest"` / `"didcomm"`).
    pub channel: String,
    /// Current member count — feeds size-sensitive policy (e.g. a
    /// quorum threshold or a first-member bootstrap branch).
    pub member_count: u64,
}

/// Everything the actor presented, grouped by kind. Each slot is
/// independently optional; a ceremony populates the slots it needs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// A community invitation credential (VIC), when the actor
    /// presented one. Absent for open-join / directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation: Option<Invitation>,
    /// A verifiable presentation's verified projection, when the
    /// actor presented credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation: Option<Presentation>,
    /// Ceremony-specific request parameters (e.g. `agreements` for
    /// join, `disposition` / `reason` for leave, `fields_requested`
    /// for directory, `target_role` for role-change). Free-form in
    /// Phase 1; tightened to per-purpose typed requests later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<JsonValue>,
}

/// A verified invitation credential (VIC). All fields are
/// post-verification facts — `verified` is the host's verdict on the
/// invitation's signature + binding, not a self-asserted flag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Invitation {
    /// Host verdict: did the invitation's signature + binding check
    /// out. Policy reads this; it never sees the signature.
    pub verified: bool,
    /// DID that issued the invitation (community DID or a delegating
    /// member).
    pub issuer: String,
    /// The issuer's community role at issue time, when known —
    /// distinguishes a community-issued invite from a member
    /// delegation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_role: Option<String>,
    /// Scopes the invitation authorizes (e.g. role bounds,
    /// single-context).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Whether this single-use invitation has already been consumed —
    /// the host tracks consumption like the bootstrap carve-out, and
    /// the compiled `has_valid_invitation` helper rejects a consumed
    /// invite.
    pub consumed: bool,
}

/// The verified projection of a presented VP.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Presentation {
    /// Host verdict: did the VP proof + holder-binding check out.
    pub verified: bool,
    /// The proven holder DID.
    pub holder: String,
    /// The credentials inside the VP, each already verified.
    #[serde(default)]
    pub credentials: Vec<Credential>,
}

/// One verified credential from a presentation. Crypto is already
/// resolved — `issuer_trusted` is the host's TRQP/governance verdict
/// and `status` is the resolved status-list state, both computed
/// before the policy runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    /// The credential `type` (e.g. `WitnessCredential`). Serialized
    /// as `type` to match the compiled helpers (`cred_trusted(t)`
    /// matches on `c.type`).
    #[serde(rename = "type")]
    pub credential_type: String,
    /// Issuer DID.
    pub issuer: String,
    /// Host verdict: is the issuer trusted for this credential type
    /// under the community's governance (resolved via TRQP, not
    /// hardcoded).
    pub issuer_trusted: bool,
    /// Resolved revocation/suspension state from the status list.
    pub status: CredentialStatus,
    /// Host verdict: did the presenter **cryptographically prove control of
    /// the holder key** (so the presenter *is* the subject), versus mere
    /// possession of the credential? True for SD-JWT-VC (`kb-jwt`), DI VP
    /// (holder proof), and holder-bound **bbs-2023 pseudonym** proofs; false
    /// for a basic, possession-based bbs-2023 derived proof. A policy can
    /// `require` this for sensitive communities (low-assurance flows may accept
    /// possession-based holdership).
    #[serde(default)]
    pub holder_bound: bool,
    /// The credential's subject claims, verbatim. Free-form; policies
    /// read specific claim paths.
    #[serde(default)]
    pub claims: JsonValue,
    /// Expiry, when the credential carries one. Policies compare
    /// against [`Facts::now`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
}

/// Resolved credential status. The host computes this from the
/// status-list lookup before evaluation, so the policy branches on a
/// settled state rather than performing a revocation check itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialStatus {
    /// Active and not revoked or suspended.
    Valid,
    /// Permanently revoked.
    Revoked,
    /// Temporarily suspended.
    Suspended,
    /// Status could not be resolved (e.g. status list unreachable).
    /// Surfaced rather than guessed so a policy can choose to refuse.
    Unknown,
}

/// Authoritative current state relevant to the decision.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct State {
    /// The subject's current member row, or `null` if the subject is
    /// not (yet) a member. Serialized as explicit `null` when empty
    /// so policies can read `input.state.subject_member` directly.
    pub subject_member: Option<MemberState>,
}

/// The subject's current membership, when they are a member.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemberState {
    /// Current community role.
    pub role: String,
    /// Membership status (e.g. `"active"`).
    pub status: String,
    /// When the subject joined — feeds tenure-sensitive policy.
    pub joined_at: DateTime<Utc>,
    /// Personhood assertion state, when established. Free-form in
    /// Phase 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub personhood: Option<JsonValue>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A join applicant with a trusted witness credential — mirrors
    /// `docs/05-design-notes/examples/facts.join.json` exactly. This
    /// is the contract test: if the serialized shape drifts from the
    /// example the compiled `join.rego` reads, this fails.
    #[test]
    fn join_facts_match_design_example() {
        let facts = Facts {
            purpose: Purpose::Join,
            now: "2026-05-30T12:00:00Z".parse().unwrap(),
            actor: Actor {
                did: "did:key:z6MkHuman".into(),
                role: None,
                authenticated: true,
            },
            subject: Subject {
                did: "did:key:z6MkHuman".into(),
            },
            context: Context {
                community_did: "did:webvh:acme.example".into(),
                channel: "rest".into(),
                member_count: 1421,
            },
            evidence: Evidence {
                invitation: None,
                presentation: Some(Presentation {
                    verified: true,
                    holder: "did:key:z6MkHuman".into(),
                    credentials: vec![Credential {
                        credential_type: "WitnessCredential".into(),
                        issuer: "did:webvh:notary.example".into(),
                        issuer_trusted: true,
                        status: CredentialStatus::Valid,
                        holder_bound: true,
                        claims: json!({ "kind": "proximity" }),
                        valid_until: None,
                    }],
                }),
                request: Some(json!({ "agreements": {} })),
            },
            state: State {
                subject_member: None,
            },
        };

        let expected = json!({
            "purpose": "join",
            "now": "2026-05-30T12:00:00Z",
            "actor": { "did": "did:key:z6MkHuman", "authenticated": true },
            "subject": { "did": "did:key:z6MkHuman" },
            "context": { "community_did": "did:webvh:acme.example", "channel": "rest", "member_count": 1421 },
            "evidence": {
                "presentation": {
                    "verified": true,
                    "holder": "did:key:z6MkHuman",
                    "credentials": [
                        { "type": "WitnessCredential", "issuer": "did:webvh:notary.example", "issuer_trusted": true, "status": "valid", "holder_bound": true, "claims": { "kind": "proximity" } }
                    ]
                },
                "request": { "agreements": {} }
            },
            "state": { "subject_member": null }
        });

        assert_eq!(serde_json::to_value(&facts).unwrap(), expected);
        // And it round-trips back from the wire shape.
        let parsed: Facts = serde_json::from_value(expected).unwrap();
        assert_eq!(parsed, facts);
    }

    /// Directory facts carry `actor.role` + a populated
    /// `subject_member` and omit the unused evidence slots — mirrors
    /// `facts.directory.json`.
    #[test]
    fn directory_facts_omit_unused_evidence_slots() {
        let facts = Facts {
            purpose: Purpose::Directory,
            now: "2026-05-30T12:00:00Z".parse().unwrap(),
            actor: Actor {
                did: "did:key:z6MkViewer".into(),
                role: Some("member".into()),
                authenticated: true,
            },
            subject: Subject {
                did: "did:key:z6MkTarget".into(),
            },
            context: Context {
                community_did: "did:webvh:acme.example".into(),
                channel: "rest".into(),
                member_count: 1421,
            },
            evidence: Evidence {
                invitation: None,
                presentation: None,
                request: Some(json!({ "fields_requested": ["did", "role", "joined_at"] })),
            },
            state: State {
                subject_member: Some(MemberState {
                    role: "member".into(),
                    status: "active".into(),
                    joined_at: "2026-03-03T00:00:00Z".parse().unwrap(),
                    personhood: None,
                }),
            },
        };

        let wire = serde_json::to_value(&facts).unwrap();
        // Unused evidence slots are absent, not null.
        assert!(wire["evidence"].get("invitation").is_none());
        assert!(wire["evidence"].get("presentation").is_none());
        assert_eq!(wire["actor"]["role"], "member");
        assert_eq!(wire["state"]["subject_member"]["role"], "member");
        assert_eq!(
            wire["evidence"]["request"]["fields_requested"],
            json!(["did", "role", "joined_at"])
        );
    }

    #[test]
    fn purpose_wire_strings_match_catalog() {
        for (purpose, wire) in [
            (Purpose::Join, "join"),
            (Purpose::Leave, "leave"),
            (Purpose::RoleChange, "role-change"),
            (Purpose::Directory, "directory"),
        ] {
            assert_eq!(serde_json::to_value(purpose).unwrap(), json!(wire));
            assert_eq!(purpose.as_str(), wire);
            let parsed: Purpose = serde_json::from_value(json!(wire)).unwrap();
            assert_eq!(parsed, purpose);
        }
    }

    #[test]
    fn credential_status_is_lowercase() {
        assert_eq!(
            serde_json::to_value(CredentialStatus::Valid).unwrap(),
            json!("valid")
        );
        assert_eq!(
            serde_json::to_value(CredentialStatus::Revoked).unwrap(),
            json!("revoked")
        );
        let parsed: CredentialStatus = serde_json::from_value(json!("unknown")).unwrap();
        assert_eq!(parsed, CredentialStatus::Unknown);
    }
}
