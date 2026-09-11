//! Wire types for peer identity vetting — how an applicant is vetted by
//! existing members before joining a Verifiable Trust Community.
//!
//! Design: OpenVTC `docs/design/vetting-process.md`. Four Trust Tasks carry
//! the exchange:
//!
//! | Type URI | From → to | Payload |
//! |---|---|---|
//! | `spec/vetting/request/0.1` | applicant → vetter | [`VettingRequestBody`] → [`VettingRequestAcceptedBody`] |
//! | `spec/vetting/session/0.1` | vetter → applicant | [`VettingSessionBody`] → [`VettingSessionResponseBody`] |
//! | `spec/vetting/decline/0.1` | vetter → applicant | [`VettingDeclineBody`] |
//! | `spec/vtc/vetting/revoke-statement/0.1` | vetter → community | [`RevokeStatementBody`] → [`RevokeStatementResponseBody`] |
//! | `spec/vtc/vetting/vetters/grant/0.1` | community admin → community | [`VetterGrantBody`] → [`VetterGrantResponseBody`] |
//!
//! A vetter is named by a **vetter role credential**: a DTG
//! `EndorsementCredential` the community issues to the member, with endorsement
//! `{ type: "CommunityRole", role: "vetter", communityDid }` and a
//! `credentialStatus` so it can be revoked. The community counts a statement
//! only from a vetter whose grant it recorded; the vetter presents the same
//! credential to an applicant (`crate::vetting::eligibility`).
//!
//! The Vetting Statement itself travels over the existing
//! `credential-exchange/issue/0.1`. It is a DTG `EndorsementCredential` whose
//! `endorsement` is an [`IdentityVettingEndorsement`] — no new credential type.
//!
//! What a community requires rides its join manifest as a
//! [`VettingRequirements`] on each criterion. **Every number in it is the
//! community's policy**: this crate supplies no default statement count,
//! method floor or age limit, and nothing here should grow one.
//!
//! This module is serde only, so any consumer can read the shapes. Building,
//! signing and verifying the card and the statement live in
//! `crate::vetting` (feature `vetting`).
//!
//! ## Refusals are errors, not responses
//!
//! A vetter that will not take a request answers with a framework
//! `trust-task-error` carrying one of the `VETTING_REQUEST_ERR_*` codes, never
//! a `#response` with an "outcome" field. One exception is deliberate: a request
//! whose **short ticket code** is wrong gets no answer at all, so a guesser
//! learns nothing from the reply (design §8.3).

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Type URIs
// ---------------------------------------------------------------------------

/// Applicant → vetter: ask to be vetted for one community.
pub const VETTING_REQUEST_TYPE: &str = "https://trusttasks.org/spec/vetting/request/0.1";
/// `#response` variant of [`VETTING_REQUEST_TYPE`] — the vetter accepted.
pub const VETTING_REQUEST_RESPONSE_TYPE: &str =
    "https://trusttasks.org/spec/vetting/request/0.1#response";

/// Vetter → applicant: open the session. The response carries the signed card.
pub const VETTING_SESSION_TYPE: &str = "https://trusttasks.org/spec/vetting/session/0.1";
/// `#response` variant of [`VETTING_SESSION_TYPE`].
pub const VETTING_SESSION_RESPONSE_TYPE: &str =
    "https://trusttasks.org/spec/vetting/session/0.1#response";

/// Vetter → applicant: the vetter will not issue a statement.
pub const VETTING_DECLINE_TYPE: &str = "https://trusttasks.org/spec/vetting/decline/0.1";

/// Vetter → community: withdraw a statement the vetter issued.
pub const VETTING_REVOKE_STATEMENT_TYPE: &str =
    "https://trusttasks.org/spec/vtc/vetting/revoke-statement/0.1";
/// `#response` variant of [`VETTING_REVOKE_STATEMENT_TYPE`].
pub const VETTING_REVOKE_STATEMENT_RESPONSE_TYPE: &str =
    "https://trusttasks.org/spec/vtc/vetting/revoke-statement/0.1#response";
/// Community admin → community: name a member as a vetter by issuing them a
/// revocable vetter role credential.
pub const VETTING_VETTER_GRANT_TYPE: &str =
    "https://trusttasks.org/spec/vtc/vetting/vetters/grant/0.1";
/// `#response` variant of [`VETTING_VETTER_GRANT_TYPE`].
pub const VETTING_VETTER_GRANT_RESPONSE_TYPE: &str =
    "https://trusttasks.org/spec/vtc/vetting/vetters/grant/0.1#response";

/// `credentialSubject.endorsement.type` of a community role credential — the
/// role VEC a community issues to a member.
pub const COMMUNITY_ROLE_ENDORSEMENT_TYPE: &str = "CommunityRole";
/// The role a vetter role credential names, and the conventional
/// `eligibleVetters.role`.
pub const VETTER_ROLE: &str = "vetter";

/// Does a held role name satisfy a required one?
///
/// `vetter` and `custom:vetter` are the same role in either direction: the
/// requirements name it bare, while a VTC's ACL spells a custom role with the
/// prefix. Every other role must match exactly.
#[must_use]
pub fn role_matches(held: &str, required: &str) -> bool {
    fn bare(role: &str) -> &str {
        role.strip_prefix("custom:").unwrap_or(role)
    }
    held == required || (bare(held) == VETTER_ROLE && bare(required) == VETTER_ROLE)
}

/// `endorsement.type` of a Vetting Statement.
pub const IDENTITY_VETTING_ENDORSEMENT_TYPE: &str =
    "https://firstperson.network/endorsements/identity-vetting/0.1";

/// The `type` members a Vetting Card carries, in order. It is a profile of the
/// r-card, which is itself a Verifiable Data Structure.
pub const VETTING_CARD_TYPES: [&str; 3] =
    ["VerifiableDataStructure", "RelationshipCard", "VettingCard"];

/// Vault `purpose` a holder files received statements under.
pub const VETTING_VAULT_PURPOSE: &str = "vetting";

/// `vetting/request` refusal: a scanned ticket's secret did not match. Never
/// sent for a short code — see the module docs.
pub const VETTING_REQUEST_ERR_INVALID_TICKET: &str = "vetting/request:invalidTicket";
/// `vetting/request` refusal: the vetter has no capacity.
pub const VETTING_REQUEST_ERR_CAPACITY: &str = "vetting/request:capacity";
/// `vetting/request` refusal: the addressee is not currently a vetter for the
/// named community.
pub const VETTING_REQUEST_ERR_NOT_ELIGIBLE: &str = "vetting/request:notEligible";
/// `vetting/request` refusal: the vetter declines, without a reason.
pub const VETTING_REQUEST_ERR_DECLINED: &str = "vetting/request:declined";
/// `vetting/request` refusal: the vetter does not offer the requested method.
pub const VETTING_REQUEST_ERR_METHOD_UNAVAILABLE: &str = "vetting/request:methodUnavailable";

// ---------------------------------------------------------------------------
// Shared vocabulary
// ---------------------------------------------------------------------------

/// How a vetter established who the applicant is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum VettingMethod {
    /// Both people in the same place.
    InPerson,
    /// A live video call.
    Video,
    /// The vetter already knows the applicant — the Linux kernel's own written
    /// standard ("worked with you for some period of time").
    PriorAcquaintance,
}

impl VettingMethod {
    /// The wire form, as used in `needs` strings.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InPerson => "inPerson",
            Self::Video => "video",
            Self::PriorAcquaintance => "priorAcquaintance",
        }
    }

    /// Inverse of [`Self::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "inPerson" => Some(Self::InPerson),
            "video" => Some(Self::Video),
            "priorAcquaintance" => Some(Self::PriorAcquaintance),
            _ => None,
        }
    }
}

/// The vetter's declared relationship to the applicant. Independence rules in
/// [`Independence`] cap how many counted statements may carry each value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum DeclaredRelationship {
    /// No prior relationship.
    None,
    /// Worked together in the community.
    CommunityColleague,
    /// Same employer.
    SameEmployer,
    /// Family.
    Family,
    /// Some other personal relationship.
    OtherPersonal,
}

/// Well-known documentation values. Documentation is **each vetter's choice**
/// (design D16), so the wire type is an open string; these are the names
/// clients should use for the common cases.
pub mod documentation {
    /// A passport.
    pub const PASSPORT: &str = "passport";
    /// A national identity card.
    pub const NATIONAL_ID: &str = "nationalId";
    /// A driver licence.
    pub const DRIVER_LICENCE: &str = "driverLicence";
    /// No document: the vetter knows the person (`priorAcquaintance`).
    pub const NONE: &str = "none";
}

// ---------------------------------------------------------------------------
// Requirements (manifest 0.2)
// ---------------------------------------------------------------------------

/// What a criterion in a community's join manifest requires of vetting.
///
/// Deliberately **not** `deny_unknown_fields`: this is a shape a client reads
/// from a community, and a newer community adding a member must not make an
/// older client unable to read the rest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VettingRequirements {
    /// Version of this requirements object's shape (`"0.1"`).
    pub version: String,
    /// The endorsement `type` a counted statement carries — normally
    /// [`IDENTITY_VETTING_ENDORSEMENT_TYPE`].
    pub statement_type: String,
    /// Distinct eligible vetters required, counted by member, not by DID.
    pub min_statements: u32,
    /// Per-method floors, e.g. at least one `inPerson`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub min_by_method: BTreeMap<VettingMethod, u32>,
    /// Methods that count at all.
    pub accepted_methods: Vec<VettingMethod>,
    /// Optional documentation floor. **Absent by default**: each vetter decides
    /// what documentation they accept (D16).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_document_classes: Option<Vec<String>>,
    /// Claim types a counted statement must mark verified, and which the
    /// identity commitment is computed over.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_claims: Vec<String>,
    /// Claim types an applicant may add to the card.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub optional_claims: Vec<String>,
    /// ISO 8601 duration; a statement older than this at decision time does
    /// not count. Absent: no age limit beyond the statement's own `validUntil`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_statement_age: Option<String>,
    /// How a vetter's eligibility is proven.
    pub eligible_vetters: EligibleVetters,
    /// Independence caps.
    #[serde(default)]
    pub independence: Independence,
    /// Whether an invitation credential must accompany the statements. Absent:
    /// the criterion's `presentationDefinition` alone decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation: Option<InvitationRequirement>,
    /// ISO 8601 duration the community commits to deciding a referred
    /// application within. Clients use it in place of a fixed pending expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_sla: Option<String>,
    /// ISO 8601 duration an application started under an older
    /// `requirementsDigest` is still evaluated under that version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirements_grace: Option<String>,
    /// Where the governance framework (and the vetter attestation text) lives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_framework_url: Option<String>,
}

/// How vetter eligibility is proven.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EligibleVetters {
    /// The community role a vetter must hold (normally `"vetter"`), evidenced
    /// by the community-issued role VEC.
    pub role: String,
}

/// Independence rules over the counted statements.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Independence {
    /// At most this many counted statements may declare each relationship.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub max_by_declared_relationship: BTreeMap<DeclaredRelationship, u32>,
    /// Every statement must carry the same identity commitment.
    #[serde(default)]
    pub require_consistent_identity_commitment: bool,
}

/// Whether a VIC must accompany the vetting statements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum InvitationRequirement {
    /// A VIC is required.
    Required,
    /// A VIC may be presented.
    Optional,
    /// No VIC is expected.
    None,
}

/// A [`VettingRequirements`] that cannot be evaluated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid vetting requirements: {0}")]
pub struct InvalidRequirements(pub String);

impl VettingRequirements {
    /// Check the requirements can be evaluated as written. A community should
    /// refuse to publish requirements that fail this, and a client should treat
    /// a criterion that fails it as unsatisfiable rather than guess.
    ///
    /// # Errors
    ///
    /// [`InvalidRequirements`] naming the first problem found.
    pub fn validate(&self) -> Result<(), InvalidRequirements> {
        let (major, minor) = self.version.split_once('.').unwrap_or_default();
        if major.is_empty()
            || minor.is_empty()
            || !major
                .bytes()
                .chain(minor.bytes())
                .all(|b| b.is_ascii_digit())
        {
            return Err(InvalidRequirements(format!(
                "version `{}` is not MAJOR.MINOR",
                self.version
            )));
        }
        if self.statement_type.is_empty() || self.statement_type.chars().count() > 512 {
            return Err(InvalidRequirements(
                "statementType is empty or longer than 512 characters".into(),
            ));
        }
        if self.min_statements == 0 {
            return Err(InvalidRequirements(
                "minStatements must be at least 1 — a criterion that needs no statements has no vetting object".into(),
            ));
        }
        if self.accepted_methods.is_empty() {
            return Err(InvalidRequirements("acceptedMethods is empty".into()));
        }
        for method in self.min_by_method.keys() {
            if !self.accepted_methods.contains(method) {
                return Err(InvalidRequirements(format!(
                    "minByMethod names `{}`, which acceptedMethods does not accept",
                    method.as_str()
                )));
            }
        }
        shape::role("eligibleVetters.role", &self.eligible_vetters.role)
            .map_err(|e| InvalidRequirements(e.to_string()))?;
        if let Some(classes) = &self.accepted_document_classes {
            shape::tokens("acceptedDocumentClasses", classes)
                .map_err(|e| InvalidRequirements(e.to_string()))?;
        }
        if let Some(url) = &self.governance_framework_url
            && (!url.starts_with("https://") || url.chars().count() > 2048)
        {
            return Err(InvalidRequirements(
                "governanceFrameworkUrl must be an https URL of at most 2048 characters".into(),
            ));
        }
        for (name, value) in [
            ("maxStatementAge", &self.max_statement_age),
            ("decisionSla", &self.decision_sla),
            ("requirementsGrace", &self.requirements_grace),
        ] {
            if let Some(v) = value
                && (v.len() > 32 || parse_iso8601_duration(v).is_none())
            {
                return Err(InvalidRequirements(format!(
                    "{name} `{v}` is not a supported ISO 8601 duration (weeks, days, hours, minutes, seconds)"
                )));
            }
        }
        Ok(())
    }

    /// [`Self::max_statement_age`] as a duration. `None` when absent **or
    /// unparseable** — call [`Self::validate`] first to tell the two apart.
    #[must_use]
    pub fn max_statement_age(&self) -> Option<Duration> {
        self.max_statement_age
            .as_deref()
            .and_then(parse_iso8601_duration)
    }
}

/// Parse the subset of ISO 8601 durations these requirements use: `P[n]W`,
/// `P[n]D` and a `T` part with `H`, `M`, `S`, in any combination
/// (`P1DT12H`). Years and months are refused — their length depends on the
/// calendar, and an age limit that means different things on different days is
/// not a limit.
#[must_use]
pub fn parse_iso8601_duration(s: &str) -> Option<Duration> {
    /// Units in the order ISO 8601 writes them. Each may appear at most once,
    /// and only after the ones before it — `P1D2W` is not a duration.
    fn accumulate(part: &str, units: &[(char, i64)]) -> Option<(i64, bool)> {
        let mut seconds: i64 = 0;
        let mut digits = String::new();
        let mut next_unit = 0;
        let mut any = false;
        for c in part.chars() {
            if c.is_ascii_digit() {
                digits.push(c);
                continue;
            }
            let offset = units[next_unit..].iter().position(|(unit, _)| *unit == c)?;
            let (_, multiplier) = units[next_unit + offset];
            next_unit += offset + 1;
            let n: i64 = digits.parse().ok()?;
            digits.clear();
            seconds = seconds.checked_add(n.checked_mul(multiplier)?)?;
            any = true;
        }
        if !digits.is_empty() {
            return None;
        }
        Some((seconds, any))
    }

    let rest = s.strip_prefix('P')?;
    let (date, time) = match rest.split_once('T') {
        Some((date, time)) => (date, Some(time)),
        None => (rest, None),
    };
    let (date_seconds, date_any) = accumulate(date, &[('W', 604_800), ('D', 86_400)])?;
    let (time_seconds, time_any) = match time {
        Some(time) => {
            let (seconds, any) = accumulate(time, &[('H', 3_600), ('M', 60), ('S', 1)])?;
            // `PT` with nothing after it is not a duration.
            if !any {
                return None;
            }
            (seconds, any)
        }
        None => (0, false),
    };
    if !date_any && !time_any {
        return None;
    }
    Duration::try_seconds(date_seconds.checked_add(time_seconds)?)
}

// ---------------------------------------------------------------------------
// vetting/request/0.1
// ---------------------------------------------------------------------------

/// A Vetting Ticket as presented by the applicant: either the short code the
/// vetter read out, or the full ticket scanned from their QR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TicketPresentation {
    /// The QR form: full-entropy secret, not subject to guess limits.
    Scanned {
        #[serde(rename = "ticketId")]
        ticket_id: String,
        /// base64url, 32 bytes.
        secret: String,
    },
    /// The spoken form: `XXXX-XXXX`, 40 bits.
    Code {
        /// Crockford base32, `XXXX-XXXX`.
        code: String,
    },
}

/// `vetting/request/0.1` payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VettingRequestBody {
    /// The community the applicant wants to be vetted for.
    pub community: String,
    /// `requirementsDigest` of the criterion the applicant is gathering for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirements_digest: Option<String>,
    /// The DID the applicant will join with. MUST equal the document `issuer`.
    pub join_did: String,
    /// The vetter's ticket. Mutually exclusive with `introduction`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<TicketPresentation>,
    /// A VIC for this community naming `joinDid`, used as a member
    /// introduction. Mutually exclusive with `ticket`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduction: Option<Value>,
    /// The method the applicant would prefer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_method: Option<VettingMethod>,
    /// BCP 47 language tags the applicant can be vetted in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub languages: Vec<String>,
    /// A short note to the vetter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Free-text availability, for scheduling out of band.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// Why a payload breaks a rule its Trust Task schema states.
///
/// Serde checks member names and types. The bounds and patterns the schemas
/// also set — lengths, the ticket-code alphabet, BCP 47 tags — are checked by
/// each type's `check_shape`, which a receiver runs before acting on the
/// payload and a sender before signing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ShapeError {
    /// Both a ticket and an introduction were supplied.
    #[error("a request carries a ticket or an introduction, not both")]
    TicketAndIntroduction,
    /// `joinDid` differs from the document issuer.
    #[error("joinDid must be the document issuer")]
    JoinDidNotIssuer,
    /// A member breaks its schema bound or pattern.
    #[error("`{field}` {rule}")]
    Field {
        /// The member, spelled as on the wire.
        field: &'static str,
        /// What it has to be.
        rule: &'static str,
    },
}

impl VettingRequestBody {
    /// Check the rules serde cannot: the schema's bounds and patterns, a ticket
    /// or an introduction but not both, and `joinDid` = the document issuer.
    ///
    /// # Errors
    ///
    /// [`ShapeError`] for the first rule broken.
    pub fn check_shape(&self, document_issuer: &str) -> Result<(), ShapeError> {
        if self.ticket.is_some() && self.introduction.is_some() {
            return Err(ShapeError::TicketAndIntroduction);
        }
        if self.join_did != document_issuer {
            return Err(ShapeError::JoinDidNotIssuer);
        }
        shape::did("community", &self.community)?;
        shape::did("joinDid", &self.join_did)?;
        match &self.ticket {
            Some(TicketPresentation::Scanned { ticket_id, secret }) => {
                shape::ticket_id("ticket.ticketId", ticket_id)?;
                shape::base64url_32("ticket.secret", secret)?;
            }
            Some(TicketPresentation::Code { code }) => shape::ticket_code("ticket.code", code)?,
            None => {}
        }
        shape::languages("languages", &self.languages)?;
        shape::optional_length("message", self.message.as_deref(), 1000)?;
        shape::optional_length("availability", self.availability.as_deref(), 256)
    }
}

/// `vetting/request/0.1#response` payload — the vetter accepted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VettingRequestAcceptedBody {
    /// The vetter's handle for this request; every later task names it.
    pub request_id: String,
    /// A VP of the vetter's community-issued VMC and `vetter` role VEC, with the
    /// `vetting/request` document's `id` as its challenge — a value the
    /// applicant chose, so the proof is fresh — letting the applicant confirm
    /// eligibility before investing in a session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eligibility_vp: Option<Value>,
    /// The documentation this vetter accepts (their own choice, D16).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepts_documentation: Vec<String>,
    /// Free text: how the vetter proposes to meet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_hint: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

// ---------------------------------------------------------------------------
// vetting/session/0.1
// ---------------------------------------------------------------------------

/// `vetting/session/0.1` payload. The vetter sends it when both people are
/// together. The document's `id` is the session's name: both clients derive
/// the match code from it, and the statement carries it as `taskContext`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VettingSessionBody {
    /// The accepted request this session belongs to.
    pub request_id: String,
    /// Single-use challenge the card must carry. base64url, 32 bytes.
    pub challenge: String,
    /// Binding domain the card must carry — the community DID.
    pub domain: String,
    /// The method this session uses.
    pub method: VettingMethod,
    /// Claim types the card must carry.
    pub required_claims: Vec<String>,
    /// Claim types the card may carry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub optional_claims: Vec<String>,
    /// After this the applicant's client refuses to present.
    pub expires_at: DateTime<Utc>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `vetting/session/0.1#response` payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VettingSessionResponseBody {
    /// The signed Vetting Card, exactly as signed.
    pub card: Value,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

// ---------------------------------------------------------------------------
// The Vetting Card (a VDS)
// ---------------------------------------------------------------------------

/// One claim on a Vetting Card.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CardClaim {
    /// Claim type from the claim-type registry, e.g. `name.legal`.
    #[serde(rename = "type")]
    pub claim_type: String,
    /// The claim value.
    pub value: Value,
    /// Where the value came from — `selfAsserted` in V0.
    pub provenance: String,
}

/// A Vetting Card: an r-card profile, signed by the applicant's join DID and
/// bound to one vetter and one session. Carries no document numbers, images or
/// portraits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VettingCard {
    /// [`VETTING_CARD_TYPES`].
    #[serde(rename = "type")]
    pub types: Vec<String>,
    /// `urn:uuid:…`.
    pub id: String,
    /// The applicant's join DID — the signer.
    pub publisher: String,
    /// r-card version.
    pub card_version: u32,
    /// The one vetter this card is for.
    pub audience: String,
    /// The community the vetting is for.
    pub community: String,
    /// From the session.
    pub challenge: String,
    /// From the session.
    pub domain: String,
    /// When the card was made.
    pub issued_at: DateTime<Utc>,
    /// When it stops being presentable.
    pub expires_at: DateTime<Utc>,
    /// The claims shown to the vetter.
    pub claims: Vec<CardClaim>,
    /// Salted digest over the identity claims; equal on every card of one
    /// application.
    pub identity_commitment: String,
    /// The per-application salt — disclosed to vetters, never to the community.
    pub commitment_salt: String,
    /// Data Integrity proof by `publisher`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,
}

// ---------------------------------------------------------------------------
// The Vetting Statement's endorsement body
// ---------------------------------------------------------------------------

/// `credentialSubject.endorsement` of a Vetting Statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityVettingEndorsement {
    /// [`IDENTITY_VETTING_ENDORSEMENT_TYPE`].
    #[serde(rename = "type")]
    pub endorsement_type: String,
    /// The one community this statement counts for. Not transitive.
    pub community: String,
    /// How the vetter established identity.
    pub method: VettingMethod,
    /// What the vetter relied on, from their own accepted list; empty with
    /// `priorAcquaintance`.
    #[serde(default)]
    pub document_classes: Vec<String>,
    /// Claim types the vetter verified.
    pub claims_verified: Vec<String>,
    /// The match code was confirmed with the person present.
    pub liveness_confirmed: bool,
    /// Copied from the card.
    pub identity_commitment: String,
    /// `digestMultibase` of the card the vetter checked.
    pub card_digest_multibase: String,
    /// The vetter's declared relationship to the applicant.
    pub declared_relationship: DeclaredRelationship,
    /// `digestMultibase` of the attestation text the vetter was shown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_text_digest: Option<String>,
}

// ---------------------------------------------------------------------------
// vetting/decline/0.1
// ---------------------------------------------------------------------------

/// Why a vetter declined. Optional — a vetter never has to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum DeclineCode {
    /// The vetter could not establish identity.
    CouldNotVerify,
    /// The documentation did not match the card.
    DocumentMismatch,
    /// The match code could not be confirmed with the person.
    LivenessFailed,
    /// The vetter is not comfortable attesting.
    NotComfortable,
    /// Something else.
    Other,
}

/// `vetting/decline/0.1` payload. Declines are never sent to the community.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VettingDeclineBody {
    /// The request being declined.
    pub request_id: String,
    /// Optional reason code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<DeclineCode>,
    /// Optional note to the applicant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

// ---------------------------------------------------------------------------
// vtc/vetting/revoke-statement/0.1
// ---------------------------------------------------------------------------

/// Why a vetter withdrew a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum RevocationReason {
    /// The vetter made a mistake.
    Mistake,
    /// The vetter learned something new.
    NewInformation,
    /// The vetter's signing key was compromised.
    KeyCompromise,
    /// Something else.
    Other,
}

/// `vtc/vetting/revoke-statement/0.1` payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeStatementBody {
    /// The statement's `id`.
    pub statement_id: String,
    /// `digestMultibase` of the statement, so a notice cannot be aimed at a
    /// different credential that reused the id.
    pub statement_digest_multibase: String,
    /// Optional reason; shared with the applicant only if the vetter chooses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<RevocationReason>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `vtc/vetting/revoke-statement/0.1#response` payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeStatementResponseBody {
    /// When the community recorded the notice. Repeating a notice returns the
    /// original time: revocation converges.
    pub recorded_at: DateTime<Utc>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

// ---------------------------------------------------------------------------
// vtc/vetting/vetters/grant/0.1
// ---------------------------------------------------------------------------

/// Shortest vetter grant a community may issue: one day.
pub const MIN_VETTER_GRANT_VALIDITY_SECONDS: u64 = 86_400;
/// Longest vetter grant a community may issue: two years.
pub const MAX_VETTER_GRANT_VALIDITY_SECONDS: u64 = 2 * 365 * 86_400;
/// A grant's validity when the request names none: one year.
pub const DEFAULT_VETTER_GRANT_VALIDITY_SECONDS: u64 = 365 * 86_400;

/// `vtc/vetting/vetters/grant/0.1` payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VetterGrantBody {
    /// The member to name as a vetter.
    pub member_did: String,
    /// How long the grant is valid, from one day to two years; one year when
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity_seconds: Option<u64>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `vtc/vetting/vetters/grant/0.1#response` payload.
///
/// Granting converges: while a grant is live and unexpired, asking again
/// returns it rather than issuing a second.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VetterGrantResponseBody {
    /// The community's record of the grant — the id its revocation names.
    pub endorsement_id: String,
    /// The vetter role credential's `id`.
    pub credential_id: String,
    /// The credential's `validFrom`.
    pub valid_from: DateTime<Utc>,
    /// The credential's `validUntil`.
    pub valid_until: DateTime<Utc>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

// ---------------------------------------------------------------------------
// Shape checks for the remaining payloads
// ---------------------------------------------------------------------------

/// The claim type a card, session or statement must never name: portraits are
/// not carried (design D17).
pub const PORTRAIT_CLAIM_TYPE: &str = "person.portrait";

impl VettingRequestAcceptedBody {
    /// Check the schema's bounds and patterns.
    ///
    /// # Errors
    ///
    /// [`ShapeError`] for the first rule broken.
    pub fn check_shape(&self) -> Result<(), ShapeError> {
        shape::length("requestId", &self.request_id, 128)?;
        shape::tokens("acceptsDocumentation", &self.accepts_documentation)?;
        shape::optional_length("sessionHint", self.session_hint.as_deref(), 500)
    }
}

impl VettingSessionBody {
    /// Check the schema's bounds and patterns.
    ///
    /// # Errors
    ///
    /// [`ShapeError`] for the first rule broken.
    pub fn check_shape(&self) -> Result<(), ShapeError> {
        shape::length("requestId", &self.request_id, 128)?;
        shape::base64url_32("challenge", &self.challenge)?;
        shape::did("domain", &self.domain)?;
        shape::no_portrait(
            "requiredClaims",
            self.required_claims.iter().map(String::as_str),
        )?;
        shape::no_portrait(
            "optionalClaims",
            self.optional_claims.iter().map(String::as_str),
        )
    }
}

impl VettingCard {
    /// Check the schema's bounds and patterns. The proof is not checked here:
    /// a card is shaped before it is signed, and verification checks the proof.
    ///
    /// # Errors
    ///
    /// [`ShapeError`] for the first rule broken.
    pub fn check_shape(&self) -> Result<(), ShapeError> {
        if self.types.len() != VETTING_CARD_TYPES.len()
            || !VETTING_CARD_TYPES
                .iter()
                .all(|t| self.types.iter().any(|s| s == t))
        {
            return Err(ShapeError::Field {
                field: "type",
                rule: "must be exactly VerifiableDataStructure, RelationshipCard and VettingCard",
            });
        }
        shape::did("publisher", &self.publisher)?;
        shape::did("audience", &self.audience)?;
        shape::did("community", &self.community)?;
        shape::did("domain", &self.domain)?;
        shape::base64url_32("challenge", &self.challenge)?;
        shape::base64url_32("commitmentSalt", &self.commitment_salt)?;
        if self.claims.is_empty() {
            return Err(ShapeError::Field {
                field: "claims",
                rule: "must carry at least one claim",
            });
        }
        for claim in &self.claims {
            shape::token("claims.provenance", &claim.provenance)?;
        }
        shape::no_portrait(
            "claims.type",
            self.claims.iter().map(|c| c.claim_type.as_str()),
        )
    }
}

impl IdentityVettingEndorsement {
    /// Check the schema's bounds and patterns.
    ///
    /// # Errors
    ///
    /// [`ShapeError`] for the first rule broken.
    pub fn check_shape(&self) -> Result<(), ShapeError> {
        shape::did("community", &self.community)?;
        shape::tokens("documentClasses", &self.document_classes)?;
        shape::no_portrait(
            "claimsVerified",
            self.claims_verified.iter().map(String::as_str),
        )
    }
}

impl VettingDeclineBody {
    /// Check the schema's bounds and patterns.
    ///
    /// # Errors
    ///
    /// [`ShapeError`] for the first rule broken.
    pub fn check_shape(&self) -> Result<(), ShapeError> {
        shape::length("requestId", &self.request_id, 128)?;
        shape::optional_length("message", self.message.as_deref(), 500)
    }
}

impl RevokeStatementBody {
    /// Check the schema's bounds and patterns.
    ///
    /// # Errors
    ///
    /// [`ShapeError`] for the first rule broken.
    pub fn check_shape(&self) -> Result<(), ShapeError> {
        shape::statement_id("statementId", &self.statement_id)
    }
}

impl VetterGrantBody {
    /// Check the schema's bounds and patterns.
    ///
    /// # Errors
    ///
    /// [`ShapeError`] for the first rule broken.
    pub fn check_shape(&self) -> Result<(), ShapeError> {
        shape::did("memberDid", &self.member_did)?;
        match self.validity_seconds {
            Some(s)
                if !(MIN_VETTER_GRANT_VALIDITY_SECONDS..=MAX_VETTER_GRANT_VALIDITY_SECONDS)
                    .contains(&s) =>
            {
                Err(ShapeError::Field {
                    field: "validitySeconds",
                    rule: "must be between one day and two years",
                })
            }
            _ => Ok(()),
        }
    }
}

/// The bounds and patterns the vetting schemas set, written out rather than
/// compiled from regular expressions so the crate takes no regex dependency.
/// Each function names the schema pattern it implements.
mod shape {
    use super::{PORTRAIT_CLAIM_TYPE, ShapeError};

    /// Crockford base32: no `I`, `L`, `O` or `U` (`[0-9A-HJKMNP-TV-Z]`).
    const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    fn fail(field: &'static str, rule: &'static str) -> Result<(), ShapeError> {
        Err(ShapeError::Field { field, rule })
    }

    /// `minLength: 1`, `maxLength: max`, counted in characters as JSON Schema
    /// counts them.
    pub(super) fn length(field: &'static str, value: &str, max: usize) -> Result<(), ShapeError> {
        let n = value.chars().count();
        if n == 0 || n > max {
            return fail(field, "is empty or longer than its schema allows");
        }
        Ok(())
    }

    pub(super) fn optional_length(
        field: &'static str,
        value: Option<&str>,
        max: usize,
    ) -> Result<(), ShapeError> {
        value.map_or(Ok(()), |v| length(field, v, max))
    }

    /// `^did:`.
    pub(super) fn did(field: &'static str, value: &str) -> Result<(), ShapeError> {
        if value.len() > "did:".len() && value.starts_with("did:") {
            return Ok(());
        }
        fail(field, "must be a DID")
    }

    /// `^[A-Za-z0-9_-]{43}$` — 32 bytes, base64url without padding.
    pub(super) fn base64url_32(field: &'static str, value: &str) -> Result<(), ShapeError> {
        if value.len() == 43
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Ok(());
        }
        fail(field, "must be 32 bytes, base64url without padding")
    }

    /// `^[a-z][a-zA-Z0-9]*$`, at most 64 characters — documentation classes
    /// and provenance values.
    pub(super) fn token(field: &'static str, value: &str) -> Result<(), ShapeError> {
        let mut chars = value.chars();
        if value.len() <= 64
            && chars.next().is_some_and(|c| c.is_ascii_lowercase())
            && chars.all(|c| c.is_ascii_alphanumeric())
        {
            return Ok(());
        }
        fail(
            field,
            "must be a lowerCamelCase token of at most 64 characters",
        )
    }

    pub(super) fn tokens(field: &'static str, values: &[String]) -> Result<(), ShapeError> {
        values.iter().try_for_each(|v| token(field, v))
    }

    /// `maxItems: 16`, `uniqueItems`, each item at most 35 characters of
    /// `^[A-Za-z]{2,3}(-[A-Za-z0-9]{1,8})*$`.
    pub(super) fn languages(field: &'static str, tags: &[String]) -> Result<(), ShapeError> {
        if tags.len() > 16 {
            return fail(field, "lists more than 16 languages");
        }
        for (i, tag) in tags.iter().enumerate() {
            if !language_tag(tag) {
                return fail(field, "must hold BCP 47 language tags");
            }
            if tags[..i].contains(tag) {
                return fail(field, "repeats a language");
            }
        }
        Ok(())
    }

    fn language_tag(tag: &str) -> bool {
        let mut parts = tag.split('-');
        tag.len() <= 35
            && parts.next().is_some_and(|primary| {
                (2..=3).contains(&primary.len()) && primary.bytes().all(|b| b.is_ascii_alphabetic())
            })
            && parts.all(|sub| {
                (1..=8).contains(&sub.len()) && sub.bytes().all(|b| b.is_ascii_alphanumeric())
            })
    }

    /// `^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$`.
    pub(super) fn ticket_code(field: &'static str, code: &str) -> Result<(), ShapeError> {
        if code.len() == 9
            && code.bytes().enumerate().all(|(i, b)| {
                if i == 4 {
                    b == b'-'
                } else {
                    CROCKFORD.contains(&b)
                }
            })
        {
            return Ok(());
        }
        fail(field, "must be XXXX-XXXX in Crockford base32")
    }

    /// `^[A-Za-z0-9._:-]+$`, at most 128 characters.
    pub(super) fn ticket_id(field: &'static str, id: &str) -> Result<(), ShapeError> {
        if (1..=128).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
        {
            return Ok(());
        }
        fail(
            field,
            "must be 1–128 characters of A–Z, a–z, 0–9, `.`, `_`, `:`, `-`",
        )
    }

    /// `^[a-zA-Z][a-zA-Z0-9+.-]*:\S+$`, at most 512 characters — a URI with a
    /// scheme, such as `urn:uuid:…`. The scheme cannot contain `:`, so the
    /// first `:` is where it ends.
    pub(super) fn statement_id(field: &'static str, id: &str) -> Result<(), ShapeError> {
        let well_formed = id.split_once(':').is_some_and(|(scheme, rest)| {
            let mut scheme = scheme.chars();
            scheme.next().is_some_and(|c| c.is_ascii_alphabetic())
                && scheme.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
                && !rest.is_empty()
                && !rest.chars().any(char::is_whitespace)
        });
        if well_formed && id.chars().count() <= 512 {
            return Ok(());
        }
        fail(field, "must be a URI of at most 512 characters")
    }

    /// `^[a-zA-Z][a-zA-Z0-9_-]*$`, at most 128 characters.
    pub(super) fn role(field: &'static str, role: &str) -> Result<(), ShapeError> {
        let mut chars = role.chars();
        if role.len() <= 128
            && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Ok(());
        }
        fail(field, "must be a role name of at most 128 characters")
    }

    /// Portraits are not carried (D17).
    pub(super) fn no_portrait<'a>(
        field: &'static str,
        mut claim_types: impl Iterator<Item = &'a str>,
    ) -> Result<(), ShapeError> {
        if claim_types.any(|t| t == PORTRAIT_CLAIM_TYPE) {
            return fail(field, "must not name person.portrait");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_vetter_role_matches_in_both_spellings_and_nothing_else_does() {
        assert!(role_matches("vetter", "vetter"));
        assert!(role_matches("custom:vetter", "vetter"));
        assert!(role_matches("vetter", "custom:vetter"));
        assert!(role_matches("custom:vetter", "custom:vetter"));
        assert!(role_matches("moderator", "moderator"));
        assert!(!role_matches("custom:moderator", "moderator"));
        assert!(!role_matches("member", "vetter"));
        assert!(!role_matches("vetters", "vetter"));
    }

    #[test]
    fn a_vetter_grant_is_camel_case_and_closed() {
        let body: VetterGrantBody = serde_json::from_value(json!({
            "memberDid": "did:key:zCarol",
            "validitySeconds": 86_400
        }))
        .unwrap();
        body.check_shape().unwrap();
        assert!(
            serde_json::from_value::<VetterGrantBody>(json!({
                "memberDid": "did:key:zCarol",
                "role": "admin"
            }))
            .is_err(),
            "the grant names no role: it only ever names a vetter"
        );

        let response = VetterGrantResponseBody {
            endorsement_id: "e".into(),
            credential_id: "urn:uuid:e".into(),
            valid_from: Utc::now(),
            valid_until: Utc::now(),
            ext: None,
        };
        let v = serde_json::to_value(&response).unwrap();
        assert!(v["endorsementId"].is_string() && v["validUntil"].is_string());
    }

    #[test]
    fn a_vetter_grant_is_bounded() {
        let grant = |did: &str, validity: Option<u64>| VetterGrantBody {
            member_did: did.into(),
            validity_seconds: validity,
            ext: None,
        };
        assert!(grant("did:key:zCarol", None).check_shape().is_ok());
        assert!(grant("carol", None).check_shape().is_err());
        assert!(
            grant(
                "did:key:zCarol",
                Some(MIN_VETTER_GRANT_VALIDITY_SECONDS - 1)
            )
            .check_shape()
            .is_err()
        );
        assert!(
            grant("did:key:zCarol", Some(MAX_VETTER_GRANT_VALIDITY_SECONDS))
                .check_shape()
                .is_ok()
        );
        assert!(
            grant(
                "did:key:zCarol",
                Some(MAX_VETTER_GRANT_VALIDITY_SECONDS + 1)
            )
            .check_shape()
            .is_err()
        );
    }

    fn requirements() -> VettingRequirements {
        serde_json::from_value(json!({
            "version": "0.1",
            "statementType": IDENTITY_VETTING_ENDORSEMENT_TYPE,
            "minStatements": 2,
            "minByMethod": { "inPerson": 1 },
            "acceptedMethods": ["inPerson", "video", "priorAcquaintance"],
            "requiredClaims": ["name.legal"],
            "maxStatementAge": "P120D",
            "eligibleVetters": { "role": "vetter" },
            "independence": { "maxByDeclaredRelationship": { "family": 0 } }
        }))
        .unwrap()
    }

    #[test]
    fn requirements_round_trip_with_camel_case_members_and_values() {
        let req = requirements();
        assert_eq!(req.min_by_method.get(&VettingMethod::InPerson), Some(&1));
        assert_eq!(
            req.independence
                .max_by_declared_relationship
                .get(&DeclaredRelationship::Family),
            Some(&0)
        );
        let back = serde_json::to_value(&req).unwrap();
        assert_eq!(back["minByMethod"]["inPerson"], 1);
        assert_eq!(back["acceptedMethods"][2], "priorAcquaintance");
        // Documentation is the vetter's choice unless a community sets a floor.
        assert!(back.get("acceptedDocumentClasses").is_none());
        req.validate().unwrap();
    }

    #[test]
    fn requirements_tolerate_members_a_newer_community_adds() {
        let mut v = serde_json::to_value(requirements()).unwrap();
        v["vetterDirectory"] = json!(true);
        let req: VettingRequirements = serde_json::from_value(v).unwrap();
        req.validate().unwrap();
    }

    #[test]
    fn validate_refuses_what_cannot_be_evaluated() {
        let mut req = requirements();
        req.min_statements = 0;
        assert!(req.validate().is_err());

        let mut req = requirements();
        req.accepted_methods = vec![VettingMethod::Video];
        assert!(
            req.validate().unwrap_err().0.contains("inPerson"),
            "a floor on a method that never counts is unsatisfiable"
        );

        let mut req = requirements();
        req.max_statement_age = Some("P4M".into());
        assert!(req.validate().is_err(), "months are calendar-dependent");
    }

    #[test]
    fn durations_parse_the_supported_subset_only() {
        assert_eq!(parse_iso8601_duration("P120D"), Duration::try_days(120));
        assert_eq!(parse_iso8601_duration("P2W"), Duration::try_days(14));
        assert_eq!(parse_iso8601_duration("P1DT12H"), Duration::try_hours(36));
        assert_eq!(parse_iso8601_duration("PT15M"), Duration::try_minutes(15));
        for bad in [
            "", "P", "PT", "120D", "P1Y", "P3M", "P1D2", "PTX", "P-1D", "P1D2W", "PT1M1H", "P1D1D",
        ] {
            assert_eq!(parse_iso8601_duration(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn request_shape_rules() {
        let mut body: VettingRequestBody = serde_json::from_value(json!({
            "community": "did:web:vtc.example",
            "joinDid": "did:key:zApplicant",
            "ticket": { "code": "K7QF-2M9X" }
        }))
        .unwrap();
        assert!(matches!(body.ticket, Some(TicketPresentation::Code { .. })));
        body.check_shape("did:key:zApplicant").unwrap();
        assert_eq!(
            body.check_shape("did:key:zSomeoneElse"),
            Err(ShapeError::JoinDidNotIssuer)
        );
        body.introduction = Some(json!({}));
        assert_eq!(
            body.check_shape("did:key:zApplicant"),
            Err(ShapeError::TicketAndIntroduction)
        );
    }

    fn field_of(result: Result<(), ShapeError>) -> &'static str {
        match result {
            Err(ShapeError::Field { field, .. }) => field,
            other => panic!("expected a field error, got {other:?}"),
        }
    }

    #[test]
    fn request_bounds_follow_the_schema() {
        let base = || -> VettingRequestBody {
            serde_json::from_value(json!({
                "community": "did:web:vtc.example",
                "joinDid": "did:key:zApplicant",
                "ticket": { "code": "K7QF-2M9X" },
                "languages": ["en", "pt-BR", "zh-Hant-TW"],
                "message": "Hello"
            }))
            .unwrap()
        };
        let issuer = "did:key:zApplicant";
        base().check_shape(issuer).unwrap();

        // I, L, O and U are not Crockford characters.
        let mut b = base();
        b.ticket = Some(TicketPresentation::Code {
            code: "K7QF-2M9O".into(),
        });
        assert_eq!(field_of(b.check_shape(issuer)), "ticket.code");

        let mut b = base();
        b.ticket = Some(TicketPresentation::Scanned {
            ticket_id: "t-1".into(),
            secret: "too-short".into(),
        });
        assert_eq!(field_of(b.check_shape(issuer)), "ticket.secret");

        let mut b = base();
        b.ticket = Some(TicketPresentation::Scanned {
            ticket_id: "t 1".into(),
            secret: "A".repeat(43),
        });
        assert_eq!(field_of(b.check_shape(issuer)), "ticket.ticketId");

        let mut b = base();
        b.languages = vec!["en".into(), "en".into()];
        assert_eq!(field_of(b.check_shape(issuer)), "languages");
        b.languages = vec!["english".into()];
        assert_eq!(field_of(b.check_shape(issuer)), "languages");
        b.languages = (0..17).map(|i| format!("en-x{i}")).collect();
        assert_eq!(field_of(b.check_shape(issuer)), "languages");

        let mut b = base();
        b.message = Some("x".repeat(1001));
        assert_eq!(field_of(b.check_shape(issuer)), "message");
        b.message = Some(String::new());
        assert_eq!(field_of(b.check_shape(issuer)), "message");

        let mut b = base();
        b.availability = Some("x".repeat(257));
        assert_eq!(field_of(b.check_shape(issuer)), "availability");

        let mut b = base();
        b.community = "vtc.example".into();
        assert_eq!(field_of(b.check_shape(issuer)), "community");
    }

    #[test]
    fn reply_and_notice_bounds_follow_the_schema() {
        let accepted = VettingRequestAcceptedBody {
            request_id: "r1".into(),
            eligibility_vp: None,
            accepts_documentation: vec!["passport".into(), "nationalId".into()],
            session_hint: Some("Hallway, 3pm".into()),
            ext: None,
        };
        accepted.check_shape().unwrap();
        let mut a = accepted.clone();
        a.accepts_documentation = vec!["national-id".into()];
        assert_eq!(field_of(a.check_shape()), "acceptsDocumentation");
        let mut a = accepted;
        a.request_id = "r".repeat(129);
        assert_eq!(field_of(a.check_shape()), "requestId");

        let session = VettingSessionBody {
            request_id: "r1".into(),
            challenge: "A".repeat(43),
            domain: "did:web:vtc.example".into(),
            method: VettingMethod::Video,
            required_claims: vec!["name.legal".into()],
            optional_claims: vec![],
            expires_at: Utc::now(),
            ext: None,
        };
        session.check_shape().unwrap();
        let mut s = session.clone();
        s.optional_claims = vec![PORTRAIT_CLAIM_TYPE.into()];
        assert_eq!(field_of(s.check_shape()), "optionalClaims");
        let mut s = session;
        s.challenge = "A".repeat(44);
        assert_eq!(field_of(s.check_shape()), "challenge");

        let decline = VettingDeclineBody {
            request_id: "r1".into(),
            code: Some(DeclineCode::NotComfortable),
            message: Some("x".repeat(501)),
            ext: None,
        };
        assert_eq!(field_of(decline.check_shape()), "message");

        for (id, ok) in [
            ("urn:uuid:5b0e1c2a-7d4f-4a51-9c6e-2f1b8d3a9e70", true),
            ("https://vetter.example/statements/1", true),
            ("statement-1", false),
            ("urn:uuid:has space", false),
            ("1urn:x", false),
            ("urn:", false),
        ] {
            let notice = RevokeStatementBody {
                statement_id: id.into(),
                statement_digest_multibase: "zDigest".into(),
                reason: None,
                ext: None,
            };
            assert_eq!(notice.check_shape().is_ok(), ok, "{id}");
        }
    }

    #[test]
    fn requirements_bounds_follow_the_schema() {
        let mut req = requirements();
        req.version = "1".into();
        assert!(req.validate().is_err(), "version is MAJOR.MINOR");

        let mut req = requirements();
        req.eligible_vetters.role = "vet ter".into();
        assert!(req.validate().is_err());

        let mut req = requirements();
        req.accepted_document_classes = Some(vec!["national-id".into()]);
        assert!(req.validate().is_err(), "documentation is lowerCamelCase");
        req.accepted_document_classes = Some(vec![documentation::NATIONAL_ID.into()]);
        req.validate().unwrap();

        let mut req = requirements();
        req.governance_framework_url = Some("http://gov.example".into());
        assert!(
            req.validate().is_err(),
            "governance text is served over https"
        );

        let mut req = requirements();
        req.decision_sla = Some(format!("PT{}S", "1".repeat(30)));
        assert!(
            req.validate().is_err(),
            "durations are at most 32 characters"
        );
    }

    #[test]
    fn scanned_tickets_parse_as_scanned_not_code() {
        let t: TicketPresentation =
            serde_json::from_value(json!({ "ticketId": "t1", "secret": "abc" })).unwrap();
        assert!(matches!(t, TicketPresentation::Scanned { .. }));
    }

    #[test]
    fn request_body_refuses_unknown_members() {
        let err = serde_json::from_value::<VettingRequestBody>(json!({
            "community": "did:web:vtc.example",
            "joinDid": "did:key:zApplicant",
            "tikcet": { "code": "K7QF-2M9X" }
        }));
        assert!(err.is_err(), "a typo must be refused, not ignored");
    }

    #[test]
    fn method_strings_round_trip() {
        for m in [
            VettingMethod::InPerson,
            VettingMethod::Video,
            VettingMethod::PriorAcquaintance,
        ] {
            assert_eq!(VettingMethod::parse(m.as_str()), Some(m));
            assert_eq!(serde_json::to_value(m).unwrap(), json!(m.as_str()));
        }
    }
}
