//! Peer identity vetting — how an applicant is vetted by existing members before
//! joining a Verifiable Trust Community.
//!
//! Design: OpenVTC `docs/design/vetting-process.md`.
//!
//! ## The wire types are the published specifications'
//!
//! Every Trust Task payload and response in this family is the type
//! `trust-tasks-codegen` generates from its specification, re-exported here from
//! `trust_tasks_rs::specs`. This crate does not restate any of them: a change to
//! a vetting wire shape lands in dtgwg-trust-tasks-tf and arrives here with a
//! `trust-tasks-rs` release.
//!
//! | Type URI | From → to | Generated module |
//! |---|---|---|
//! | `spec/vetting/request/0.1` | applicant → vetter | [`request::v0_1`] |
//! | `spec/vetting/session/0.1` | vetter → applicant | [`session::v0_1`] — its `Response` carries the signed [`session::v0_1::VettingCard`] |
//! | `spec/vetting/decline/0.1` | vetter → applicant | [`decline::v0_1`] |
//! | `spec/vtc/vetting/revoke-statement/0.1` | vetter → community | [`revoke_statement::v0_1`] |
//! | `spec/vtc/vetting/vetters/grant/0.1` | community admin → community | [`vetters::grant::v0_1`] |
//! | `spec/vtc/vetting/vetters/profile/0.1` | vetter → community | [`vetters::profile::v0_1`] |
//! | `spec/vtc/vetting/vetters/list/0.1` | member or applicant → community | [`vetters::list::v0_1`] |
//! | `spec/vtc/vetting/vetters/resend/0.1` | vetter → community | [`vetters::resend::v0_1`] |
//!
//! Each module holds the task's `Payload` and, where it has one, its `Response`.
//! The modules are versioned: a new specification version arrives beside the old
//! one instead of changing what an existing path means.
//!
//! What a community requires rides its join manifest
//! (`vtc/join-requests/manifest/0.2`) as a [`VettingRequirements`] on each
//! criterion. Its vocabulary — [`VettingMethod`], [`VettingRelationship`],
//! [`VettingDocumentation`], [`ClaimType`] — is the one statements are counted
//! in, so it is re-exported here from that specification's module. **Every number
//! in the requirements is the community's policy**: this crate supplies no
//! default statement count, method floor or age limit, and nothing here should
//! grow one.
//!
//! ## Working with generated types
//!
//! Generated structs are `#[non_exhaustive]`: build one with its `builder()` (or
//! by deserializing), then read or set its public fields. A constrained string
//! is a newtype that checks the schema's `pattern` and length when it is made
//! (`TryFrom<&str>`, `FromStr`) and dereferences to `String`. Unset optional
//! members are omitted rather than sent as `null`, and unknown members are
//! refused.
//!
//! What a constructor cannot check — array bounds and uniqueness, `oneOf`,
//! dependent members — the embedded schema does. [`CheckShape`] validates a value
//! against it and adds the few rules no JSON Schema can state, such as an event's
//! `endDate` against its `startDate`.
//!
//! **A receiver reads with [`read_checked`]**, not with `serde_json` and
//! [`CheckShape`]: some constructors normalise what they parse (a date written
//! `2026-1-05` parses and re-serialises as `2026-01-05`), so only the JSON as
//! received shows whether it met the schema. [`read_checked`] validates that JSON
//! first, then parses it, then applies the rules above.
//!
//! **Signatures and digests cover the JSON as received.** A generated type keeps
//! only the members its schema names, so re-serialising a parsed card, proof or
//! presentation can drop members the signer covered. Verify and digest the JSON
//! you received, as `crate::vetting` does.
//!
//! ## What is written by hand
//!
//! Only what no generated module carries:
//!
//! - [`IdentityVettingEndorsement`], the `endorsement` body of a Vetting
//!   Statement. It is a credential body (`vetting/_shared/0.1/identity-vetting`),
//!   not a Trust Task, and the codegen generates no type for shared definitions;
//!   its members use the generated vocabulary;
//! - the rules [`CheckShape`] and [`check_request`] add beyond the schemas;
//! - the extended error codes the specifications declare in their front matter;
//! - the community admin REST bodies that are not Trust Tasks: the grant listing
//!   ([`VetterGrantListResponse`]) and the automatic-grant configuration
//!   ([`AutoGrantConfig`], [`AutoGrantStatus`]).
//!
//! A vetter is named by a **vetter role credential**: a DTG
//! `EndorsementCredential` the community issues to the member, with endorsement
//! `{ type: "CommunityRole", role: "vetter", communityDid }` and a
//! `credentialStatus` so it can be revoked. The community counts a statement only
//! from a vetter whose grant it recorded; the vetter presents the same credential
//! to an applicant (`crate::vetting::eligibility`). The Vetting Statement itself
//! travels over `credential-exchange/issue/0.1`.
//!
//! Building, signing and verifying the card and the statement, and counting
//! statements against requirements, live in `crate::vetting` (feature
//! `vetting`).
//!
//! ## Refusals are errors, not responses
//!
//! A vetter that will not take a request answers with a framework
//! `trust-task-error` carrying one of the `VETTING_REQUEST_ERR_*` codes, never a
//! `#response` with an "outcome" field. One exception is deliberate: a request
//! whose **short ticket code** is wrong gets no answer at all, so a guesser
//! learns nothing from the reply (design §8.3).

use chrono::{DateTime, Duration, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use trust_tasks_rs::specs::vetting::{decline, request, session};
pub use trust_tasks_rs::specs::vtc::join_requests::manifest::v0_2::{
    ClaimType, VettingDocumentation, VettingMethod, VettingRelationship, VettingRequirements,
    VettingRequirementsEligibleVetters, VettingRequirementsIndependence,
    VettingRequirementsInvitation,
};
pub use trust_tasks_rs::specs::vtc::vetting::{revoke_statement, vetters};

use trust_tasks_rs::specs::vtc::join_requests::manifest::v0_2 as manifest;

// ---------------------------------------------------------------------------
// Type URIs — the generated types' own, so the URI a handler answers on is the
// one the specification publishes.
// ---------------------------------------------------------------------------

/// Applicant → vetter: ask to be vetted for one community.
pub const VETTING_REQUEST_TYPE: &str =
    <request::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `#response` variant of [`VETTING_REQUEST_TYPE`] — the vetter accepted.
pub const VETTING_REQUEST_RESPONSE_TYPE: &str =
    <request::v0_1::Response as trust_tasks_rs::Payload>::TYPE_URI;

/// Vetter → applicant: open the session. The response carries the signed card.
pub const VETTING_SESSION_TYPE: &str =
    <session::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `#response` variant of [`VETTING_SESSION_TYPE`].
pub const VETTING_SESSION_RESPONSE_TYPE: &str =
    <session::v0_1::Response as trust_tasks_rs::Payload>::TYPE_URI;

/// Vetter → applicant: the vetter will not issue a statement.
pub const VETTING_DECLINE_TYPE: &str =
    <decline::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Vetter → community: withdraw a statement the vetter issued.
pub const VETTING_REVOKE_STATEMENT_TYPE: &str =
    <revoke_statement::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `#response` variant of [`VETTING_REVOKE_STATEMENT_TYPE`].
pub const VETTING_REVOKE_STATEMENT_RESPONSE_TYPE: &str =
    <revoke_statement::v0_1::Response as trust_tasks_rs::Payload>::TYPE_URI;

/// Community admin → community: name a member as a vetter by issuing them a
/// revocable vetter role credential.
pub const VETTING_VETTER_GRANT_TYPE: &str =
    <vetters::grant::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `#response` variant of [`VETTING_VETTER_GRANT_TYPE`].
pub const VETTING_VETTER_GRANT_RESPONSE_TYPE: &str =
    <vetters::grant::v0_1::Response as trust_tasks_rs::Payload>::TYPE_URI;

/// Vetter → community: publish (or replace) the sender's vetter profile.
pub const VETTING_VETTER_PROFILE_TYPE: &str =
    <vetters::profile::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `#response` variant of [`VETTING_VETTER_PROFILE_TYPE`].
pub const VETTING_VETTER_PROFILE_RESPONSE_TYPE: &str =
    <vetters::profile::v0_1::Response as trust_tasks_rs::Payload>::TYPE_URI;

/// Member or applicant → community: find vetters by language, place, method or
/// event.
pub const VETTING_VETTER_LIST_TYPE: &str =
    <vetters::list::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `#response` variant of [`VETTING_VETTER_LIST_TYPE`].
pub const VETTING_VETTER_LIST_RESPONSE_TYPE: &str =
    <vetters::list::v0_1::Response as trust_tasks_rs::Payload>::TYPE_URI;

/// Vetter → community: deliver the sender's live vetter grant credential again.
pub const VETTING_VETTER_RESEND_TYPE: &str =
    <vetters::resend::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `#response` variant of [`VETTING_VETTER_RESEND_TYPE`].
pub const VETTING_VETTER_RESEND_RESPONSE_TYPE: &str =
    <vetters::resend::v0_1::Response as trust_tasks_rs::Payload>::TYPE_URI;

// ---------------------------------------------------------------------------
// Extended error codes, as each specification's front matter declares them.
// The codegen carries no error codes, so these are the one place they are
// spelled.
// ---------------------------------------------------------------------------

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
/// `vtc/vetting/vetters/profile` refusal: the sender is not an active member
/// holding a live vetter grant.
pub const VETTING_VETTER_PROFILE_ERR_NOT_ELIGIBLE: &str = "vtc/vetting/vetters/profile:notEligible";
/// `vtc/vetting/vetters/resend` refusal: the sender holds no live vetter grant.
pub const VETTING_VETTER_RESEND_ERR_NOT_GRANTED: &str = "vtc/vetting/vetters/resend:notGranted";

// ---------------------------------------------------------------------------
// Shared vocabulary that no schema carries
// ---------------------------------------------------------------------------

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

/// The `type` members a Vetting Card carries. It is a profile of the r-card,
/// which is itself a Verifiable Data Structure.
pub const VETTING_CARD_TYPES: [session::v0_1::VettingCardTypeItem; 3] = [
    session::v0_1::VettingCardTypeItem::VerifiableDataStructure,
    session::v0_1::VettingCardTypeItem::RelationshipCard,
    session::v0_1::VettingCardTypeItem::VettingCard,
];

/// Vault `purpose` a holder files received statements under.
pub const VETTING_VAULT_PURPOSE: &str = "vetting";

/// The claim type a card, session or statement never names: portraits are not
/// carried (design D17).
pub const PORTRAIT_CLAIM_TYPE: &str = "person.portrait";

/// Well-known documentation values. Documentation is **each vetter's choice**
/// (design D16), so the wire type ([`VettingDocumentation`]) is an open token;
/// these are the names clients should use for the common cases.
pub mod documentation {
    /// A passport.
    pub const PASSPORT: &str = "passport";
    /// A national identity card.
    pub const NATIONAL_ID: &str = "nationalId";
    /// A driver licence.
    pub const DRIVER_LICENCE: &str = "driverLicence";
    /// No document: the vetter knows the person (`priorAcquaintance`). A policy
    /// value only — a statement records "no document" as an empty list.
    pub const NONE: &str = "none";
}

/// Shortest vetter grant a community may issue: one day. The `minimum`
/// `vtc/vetting/vetters/grant/0.1` sets on `validitySeconds`; a test pins the
/// two together.
pub const MIN_VETTER_GRANT_VALIDITY_SECONDS: u64 = 86_400;
/// Longest vetter grant a community may issue: two years. The schema's
/// `maximum` on `validitySeconds`.
pub const MAX_VETTER_GRANT_VALIDITY_SECONDS: u64 = 2 * 365 * 86_400;
/// A grant's validity when the request names none: one year
/// (`vtc/vetting/vetters/grant/0.1`).
pub const DEFAULT_VETTER_GRANT_VALIDITY_SECONDS: u64 = 365 * 86_400;

/// A listing page when the request names no `limit`
/// (`vtc/vetting/vetters/list/0.1`).
pub const DEFAULT_VETTER_LIST_LIMIT: u64 = 50;

/// Longest span of one vetter event, `endDate − startDate`, in days. The
/// profile schema states this in prose, because JSON Schema cannot compare two
/// members.
pub const MAX_VETTER_EVENT_SPAN_DAYS: i64 = 31;

// ---------------------------------------------------------------------------
// Durations
// ---------------------------------------------------------------------------

/// Parse the subset of ISO 8601 durations the requirements use: `P[n]W`,
/// `P[n]D` and a `T` part with `H`, `M`, `S`, in any combination (`P1DT12H`).
/// Years and months are refused — their length depends on the calendar, and an
/// age limit that means different things on different days is not a limit.
///
/// The manifest schema's `Duration` pattern admits exactly this subset, so a
/// duration read from [`VettingRequirements`] fails here only when its number
/// does not fit.
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

/// The requirements' `maxStatementAge` as a duration. `None` when absent **or
/// too large to represent** — a caller that must tell the two apart checks
/// whether the member is set.
#[must_use]
pub fn max_statement_age(requirements: &VettingRequirements) -> Option<Duration> {
    requirements
        .max_statement_age
        .as_deref()
        .and_then(|d| parse_iso8601_duration(d))
}

// ---------------------------------------------------------------------------
// Validation beyond the constructors
// ---------------------------------------------------------------------------

/// Why a value breaks its specification.
///
/// A generated type's constructors check member names, types, patterns and
/// lengths. [`ShapeError::Schema`] is everything else the published schema
/// states; the other variants are the rules a schema cannot state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ShapeError {
    /// The value does not satisfy its published JSON Schema. Carries the
    /// validator's messages.
    #[error("breaks its published schema: {0}")]
    Schema(String),
    /// `joinDid` differs from the document issuer.
    #[error("joinDid must be the document issuer")]
    JoinDidNotIssuer,
    /// A member breaks a rule its specification states in prose.
    #[error("`{field}` {rule}")]
    Field {
        /// The member, spelled as on the wire.
        field: &'static str,
        /// What it has to be.
        rule: &'static str,
    },
}

/// Check a value against its specification: the schema the generated type
/// embeds, plus the rules no JSON Schema can state. A receiver runs it before
/// acting on a value, and a sender before signing one.
pub trait CheckShape {
    /// # Errors
    ///
    /// [`ShapeError`] for the first rule broken.
    fn check_shape(&self) -> Result<(), ShapeError>;
}

fn schema_error(e: trust_tasks_rs::validate::ValidationError) -> ShapeError {
    ShapeError::Schema(e.messages().join("; "))
}

/// Validate a generated payload or response against the schema its type embeds.
fn against_own_schema<P: trust_tasks_rs::Payload + Serialize>(value: &P) -> Result<(), ShapeError> {
    use trust_tasks_rs::validate::ValidatedPayload;
    let json = serde_json::to_value(value).map_err(|e| ShapeError::Schema(e.to_string()))?;
    P::validate_value(&json).map_err(schema_error)
}

/// Validate `json` against the definition `name` in the schema `P` embeds — for
/// a value that travels inside a payload rather than as one: a card inside a
/// session response, requirements inside a manifest.
pub(crate) fn against_definition<P: trust_tasks_rs::Payload>(
    name: &str,
    json: &Value,
) -> Result<(), ShapeError> {
    let unavailable = |why: &str| ShapeError::Schema(format!("{}: {why}", P::TYPE_URI));
    let embedded = P::PAYLOAD_SCHEMA.ok_or_else(|| unavailable("embeds no schema"))?;
    let parsed: Value = serde_json::from_str(embedded).map_err(|e| unavailable(&e.to_string()))?;
    let defs = parsed
        .get("$defs")
        .filter(|defs| defs.get(name).is_some())
        .ok_or_else(|| unavailable(&format!("defines no `{name}`")))?;
    let schema = serde_json::json!({
        "$defs": defs,
        "$ref": format!("#/$defs/{name}"),
    });
    trust_tasks_rs::validate::against_schema(&schema.to_string(), json).map_err(schema_error)
}

fn against_own_definition<P: trust_tasks_rs::Payload>(
    name: &str,
    value: &impl Serialize,
) -> Result<(), ShapeError> {
    let json = serde_json::to_value(value).map_err(|e| ShapeError::Schema(e.to_string()))?;
    against_definition::<P>(name, &json)
}

/// Read a payload or response as received, and check it.
///
/// Validates `json` against the published schema **before** parsing it — some
/// generated constructors normalise what they parse, so a value that has been
/// through one no longer shows what was sent — then parses it and applies
/// [`CheckShape`].
///
/// # Errors
///
/// [`ShapeError::Schema`] for JSON the schema refuses or that does not parse;
/// otherwise the first rule [`CheckShape`] finds broken.
pub fn read_checked<P>(json: &Value) -> Result<P, ShapeError>
where
    P: trust_tasks_rs::Payload + DeserializeOwned + CheckShape,
{
    use trust_tasks_rs::validate::ValidatedPayload;
    P::validate_value(json).map_err(schema_error)?;
    let parsed: P =
        serde_json::from_value(json.clone()).map_err(|e| ShapeError::Schema(e.to_string()))?;
    parsed.check_shape()?;
    Ok(parsed)
}

/// Read a type defined inside another task's schema as received: validate
/// `json` against the definition `name` of `C`'s schema, parse it, then apply
/// [`CheckShape`].
fn read_checked_definition<C, T>(name: &str, json: &Value) -> Result<T, ShapeError>
where
    C: trust_tasks_rs::Payload,
    T: DeserializeOwned + CheckShape,
{
    against_definition::<C>(name, json)?;
    let parsed: T =
        serde_json::from_value(json.clone()).map_err(|e| ShapeError::Schema(e.to_string()))?;
    parsed.check_shape()?;
    Ok(parsed)
}

/// [`read_checked`] for a community's [`VettingRequirements`], as the join
/// manifest 0.2 schema defines them.
///
/// # Errors
///
/// As [`read_checked`].
pub fn read_requirements(json: &Value) -> Result<VettingRequirements, ShapeError> {
    read_checked_definition::<manifest::Response, _>("VettingRequirements", json)
}

/// [`read_checked`] for a community's branding, as the join manifest 0.2
/// schema defines it.
///
/// # Errors
///
/// As [`read_checked`].
pub fn read_branding(json: &Value) -> Result<manifest::CommunityBranding, ShapeError> {
    read_checked_definition::<manifest::Response, _>("CommunityBranding", json)
}

/// [`read_checked`] for a `vetting/request/0.1` payload, which also binds
/// `joinDid` to the document issuer ([`check_request`]).
///
/// # Errors
///
/// As [`read_checked`], or [`ShapeError::JoinDidNotIssuer`].
pub fn read_request(
    json: &Value,
    document_issuer: &str,
) -> Result<request::v0_1::Payload, ShapeError> {
    use trust_tasks_rs::validate::ValidatedPayload;
    request::v0_1::Payload::validate_value(json).map_err(schema_error)?;
    let parsed: request::v0_1::Payload =
        serde_json::from_value(json.clone()).map_err(|e| ShapeError::Schema(e.to_string()))?;
    check_request(&parsed, document_issuer)?;
    Ok(parsed)
}

/// Tasks whose schema is the whole rule.
macro_rules! checked_by_schema {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl CheckShape for $ty {
                fn check_shape(&self) -> Result<(), ShapeError> {
                    against_own_schema(self)
                }
            }
        )+
    };
}

checked_by_schema!(
    request::v0_1::Response,
    session::v0_1::Payload,
    session::v0_1::Response,
    decline::v0_1::Payload,
    revoke_statement::v0_1::Payload,
    revoke_statement::v0_1::Response,
    vetters::grant::v0_1::Payload,
    vetters::grant::v0_1::Response,
    vetters::profile::v0_1::Response,
    vetters::resend::v0_1::Payload,
    vetters::resend::v0_1::Response,
);

/// Check a `vetting/request/0.1` payload: its schema — a ticket or an
/// introduction but not both, the ticket's patterns, the bounds — and that
/// `joinDid` is the document issuer, which no schema can see.
///
/// # Errors
///
/// [`ShapeError`] for the first rule broken.
pub fn check_request(
    payload: &request::v0_1::Payload,
    document_issuer: &str,
) -> Result<(), ShapeError> {
    against_own_schema(payload)?;
    if payload.join_did.as_str() != document_issuer {
        return Err(ShapeError::JoinDidNotIssuer);
    }
    Ok(())
}

impl CheckShape for session::v0_1::VettingCard {
    /// The card definition the session response carries. The proof is shaped
    /// here, not verified: `crate::vetting::card` verifies it.
    fn check_shape(&self) -> Result<(), ShapeError> {
        against_own_definition::<session::v0_1::Response>("VettingCard", self)
    }
}

impl CheckShape for vetters::profile::v0_1::Payload {
    fn check_shape(&self) -> Result<(), ShapeError> {
        against_own_schema(self)?;
        // `VetterEvent`: "`endDate` is on or after `startDate` and no more than
        // 31 days after it; JSON Schema cannot compare two members, so the
        // community checks both". Its `url` is a `format: uri` the validator
        // does not assert.
        for event in &self.events {
            if let Some(url) = &event.url {
                shape::https_uri("events.url", url)?;
            }
            let (start, end) = (event.start_date.0, event.end_date.0);
            if end < start {
                return Err(ShapeError::Field {
                    field: "events.endDate",
                    rule: "must not be before startDate",
                });
            }
            if (end - start).num_days() > MAX_VETTER_EVENT_SPAN_DAYS {
                return Err(ShapeError::Field {
                    field: "events.endDate",
                    rule: "must be at most 31 days after startDate",
                });
            }
        }
        Ok(())
    }
}

impl CheckShape for vetters::list::v0_1::Payload {
    fn check_shape(&self) -> Result<(), ShapeError> {
        against_own_schema(self)?;
        // Conformance 1: a request whose `eventFrom` is after its `eventTo` is
        // refused with `malformedRequest`.
        if let (Some(from), Some(to)) = (&self.event_from, &self.event_to)
            && to.0 < from.0
        {
            return Err(ShapeError::Field {
                field: "eventTo",
                rule: "must not be before eventFrom",
            });
        }
        Ok(())
    }
}

impl CheckShape for vetters::list::v0_1::Response {
    /// The schema, and each listed event's `url` as an absolute https URI,
    /// which the validator does not assert.
    fn check_shape(&self) -> Result<(), ShapeError> {
        against_own_schema(self)?;
        for event in self.vetters.iter().flat_map(|vetter| &vetter.events) {
            if let Some(url) = &event.url {
                shape::https_uri("vetters.events.url", url)?;
            }
        }
        Ok(())
    }
}

impl CheckShape for VettingRequirements {
    /// A community refuses to publish requirements that fail this, and a client
    /// treats a criterion that fails it as unsatisfiable rather than guess
    /// (`vtc/join-requests/manifest/0.2`, Conformance 3).
    fn check_shape(&self) -> Result<(), ShapeError> {
        against_own_definition::<manifest::Response>("VettingRequirements", self)?;
        if let Some(url) = &self.governance_framework_url {
            shape::https_uri("governanceFrameworkUrl", url)?;
        }
        if self
            .min_by_method
            .keys()
            .any(|method| !self.accepted_methods.contains(method))
        {
            return Err(ShapeError::Field {
                field: "minByMethod",
                rule: "names a method acceptedMethods does not accept",
            });
        }
        Ok(())
    }
}

impl CheckShape for manifest::CommunityBranding {
    /// The manifest's definition, and `logoUrl` as an absolute https URI, which
    /// the validator does not assert. A client fetches the logo from it.
    fn check_shape(&self) -> Result<(), ShapeError> {
        against_own_definition::<manifest::Response>("CommunityBranding", self)?;
        if let Some(url) = &self.logo_url {
            shape::https_uri("logoUrl", url)?;
        }
        Ok(())
    }
}

/// Is `vetters::list::v0_1::Payload` filtering on events at all: a date bound
/// or a name?
#[must_use]
pub fn has_event_filter(body: &vetters::list::v0_1::Payload) -> bool {
    body.event_from.is_some() || body.event_to.is_some() || body.event_name.is_some()
}

// ---------------------------------------------------------------------------
// The Vetting Statement's endorsement body
// ---------------------------------------------------------------------------

/// `credentialSubject.endorsement` of a Vetting Statement —
/// `vetting/_shared/0.1/identity-vetting`.
///
/// Written here because nothing generates it: it is a credential body, not a
/// Trust Task, and the codegen skips shared definitions. Its members take the
/// generated vocabulary, so a statement and the requirements it is counted
/// against compare value for value.
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
    /// `priorAcquaintance`. Never `none`: no document is the empty list.
    #[serde(default)]
    pub document_classes: Vec<VettingDocumentation>,
    /// Claim types the vetter verified.
    pub claims_verified: Vec<ClaimType>,
    /// The match code was confirmed with the person present.
    pub liveness_confirmed: bool,
    /// Copied from the card.
    pub identity_commitment: String,
    /// `digestMultibase` of the card the vetter checked.
    pub card_digest_multibase: String,
    /// The vetter's declared relationship to the applicant.
    pub declared_relationship: VettingRelationship,
    /// `digestMultibase` of the attestation text the vetter was shown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_text_digest: Option<String>,
}

impl CheckShape for IdentityVettingEndorsement {
    /// The shared definition's rules beyond what the member types enforce. No
    /// schema for it is embedded anywhere, so they are checked here.
    fn check_shape(&self) -> Result<(), ShapeError> {
        if self.endorsement_type.is_empty() || self.endorsement_type.chars().count() > 512 {
            return Err(ShapeError::Field {
                field: "type",
                rule: "is empty or longer than 512 characters",
            });
        }
        shape::did("community", &self.community)?;
        if shape::repeats(&self.document_classes) {
            return Err(ShapeError::Field {
                field: "documentClasses",
                rule: "repeats a documentation class",
            });
        }
        if self
            .document_classes
            .iter()
            .any(|d| d.as_str() == documentation::NONE)
        {
            return Err(ShapeError::Field {
                field: "documentClasses",
                rule: "never lists `none`: no document is the empty list",
            });
        }
        if shape::repeats(&self.claims_verified) {
            return Err(ShapeError::Field {
                field: "claimsVerified",
                rule: "repeats a claim type",
            });
        }
        shape::no_portrait(
            "claimsVerified",
            self.claims_verified.iter().map(|c| c.as_str()),
        )
    }
}

// ---------------------------------------------------------------------------
// VTC admin REST: vetter grants and automatic grants. Not Trust Tasks.
// ---------------------------------------------------------------------------

/// Who issued a vetter grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub enum GrantOrigin {
    /// The automatic-grant sweep, on the `vetter_eligibility` policy's
    /// `allow`. Only these does the sweep revoke.
    Auto,
    /// An admin.
    Manual,
}

/// What an admin sees of a vetter's published profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct VetterProfileSummary {
    /// Whether the profile appears in listings.
    pub listed: bool,
    /// The profile's `displayName`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// The profile's `location.country`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// The profile's `languages`.
    #[serde(default)]
    pub languages: Vec<String>,
    /// The profile's `methods`.
    #[serde(default)]
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Vec<crate::openapi::VetterProfile01VettingMethod>)
    )]
    pub methods: Vec<vetters::profile::v0_1::VettingMethod>,
    /// How many events the profile lists, ended or not.
    pub event_count: u32,
    /// When the profile was last published.
    pub updated_at: DateTime<Utc>,
}

/// One vetter grant, as `GET /v1/vetting/vetters` reports it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct VetterGrantRow {
    /// The grant's record — what `DELETE /v1/credentials/endorsements/{id}`
    /// revokes.
    pub endorsement_id: String,
    /// The member named a vetter.
    pub member_did: String,
    /// The vetter role credential's `id`.
    pub credential_id: String,
    /// The credential's `validFrom`.
    pub valid_from: DateTime<Utc>,
    /// The credential's `validUntil`; absent on a row that did not record it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    /// The grant has been revoked.
    pub revoked: bool,
    /// When it was revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    /// Unrevoked, unexpired, and held by a current member.
    pub live: bool,
    /// Issued by the automatic sweep or by an admin.
    pub origin: GrantOrigin,
    /// The member's published profile, when they have one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<VetterProfileSummary>,
}

/// `GET /v1/vetting/vetters` response: every grant, newest first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct VetterGrantListResponse {
    /// The grants.
    pub vetters: Vec<VetterGrantRow>,
}

/// How often the automatic-grant sweep runs when unconfigured, in minutes.
pub const DEFAULT_AUTO_GRANT_SWEEP_MINUTES: u32 = 60;
/// The most often the sweep may run, in minutes.
pub const MIN_AUTO_GRANT_SWEEP_MINUTES: u32 = 5;
/// The least often the sweep may run, in minutes (a day).
pub const MAX_AUTO_GRANT_SWEEP_MINUTES: u32 = 1440;

/// `PUT /v1/vetting/auto-grant` body. An absent member takes its default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutoGrantConfig {
    /// Whether the sweep runs. Off unless an admin turns it on.
    pub enabled: bool,
    /// Minutes between sweeps, 5–1440; 60 when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sweep_minutes: Option<u32>,
    /// Validity of a grant the sweep issues, within the grant bounds (one day
    /// to two years); one year when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity_seconds: Option<u64>,
}

impl CheckShape for AutoGrantConfig {
    fn check_shape(&self) -> Result<(), ShapeError> {
        if self.sweep_minutes.is_some_and(|m| {
            !(MIN_AUTO_GRANT_SWEEP_MINUTES..=MAX_AUTO_GRANT_SWEEP_MINUTES).contains(&m)
        }) {
            return Err(ShapeError::Field {
                field: "sweepMinutes",
                rule: "must be between 5 and 1440",
            });
        }
        if self.validity_seconds.is_some_and(|s| {
            !(MIN_VETTER_GRANT_VALIDITY_SECONDS..=MAX_VETTER_GRANT_VALIDITY_SECONDS).contains(&s)
        }) {
            return Err(ShapeError::Field {
                field: "validitySeconds",
                rule: "must be between one day and two years",
            });
        }
        Ok(())
    }
}

/// What one automatic-grant sweep did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AutoGrantSweep {
    /// When the sweep finished.
    pub ran_at: DateTime<Utc>,
    /// Grants issued.
    pub granted: u32,
    /// Automatic grants revoked.
    pub revoked: u32,
    /// Members the sweep could not decide or act on.
    pub errors: u32,
}

/// `GET /v1/vetting/auto-grant` response, and the answer to a `PUT`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AutoGrantStatus {
    /// Whether the sweep runs.
    pub enabled: bool,
    /// Minutes between sweeps.
    pub sweep_minutes: u32,
    /// Validity of a grant the sweep issues.
    pub validity_seconds: u64,
    /// The last sweep, when one has run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sweep: Option<AutoGrantSweep>,
}

/// The rules a schema does not carry for the values checked by hand here.
/// Crate-visible so `crate::vetting::ticket_uri` checks a decoded ticket's
/// vetter with the same rule.
pub(crate) mod shape {
    use super::{PORTRAIT_CLAIM_TYPE, ShapeError};

    /// `^did:` — the pattern every vetting schema gives a DID.
    pub(crate) fn did(field: &'static str, value: &str) -> Result<(), ShapeError> {
        if value.starts_with("did:") {
            return Ok(());
        }
        Err(ShapeError::Field {
            field,
            rule: "must be a DID",
        })
    }

    /// `uniqueItems` for a list no embedded schema covers.
    pub(crate) fn repeats<T: PartialEq>(values: &[T]) -> bool {
        values
            .iter()
            .enumerate()
            .any(|(i, v)| values[..i].contains(v))
    }

    /// Longest value a vetting schema gives `format: uri`.
    const MAX_URI_CHARS: usize = 2048;

    /// A member the vetting schemas give `format: uri`, `pattern: ^https://`
    /// and `maxLength: 2048` — an event's `url`, branding's `logoUrl`, the
    /// requirements' `governanceFrameworkUrl` — is an absolute https URI
    /// (RFC 3986) with a host. The schema validator treats `format` as an
    /// annotation and does not assert it, and the pattern alone lets
    /// `https://a b` through, so the URI rule is checked here.
    pub(crate) fn https_uri(field: &'static str, value: &str) -> Result<(), ShapeError> {
        let fail = |rule: &'static str| -> Result<(), ShapeError> {
            Err(ShapeError::Field { field, rule })
        };
        if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return fail("must not contain whitespace or control characters");
        }
        if value.chars().count() > MAX_URI_CHARS {
            return fail("must be at most 2048 characters");
        }
        let Some(rest) = value.strip_prefix("https://") else {
            return fail("must be an absolute https URI");
        };
        let uri_character =
            |b: u8| b.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=%".contains(&b);
        let escapes_are_well_formed = value.bytes().enumerate().all(|(i, b)| {
            b != b'%'
                || value
                    .as_bytes()
                    .get(i + 1..i + 3)
                    .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
        });
        let has_authority = !rest.is_empty() && !rest.starts_with(['/', '?', '#']);
        let parses = url::Url::parse(value)
            .is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some_and(|h| !h.is_empty()));
        if value.bytes().all(uri_character) && escapes_are_well_formed && has_authority && parses {
            return Ok(());
        }
        fail("must be an absolute https URI")
    }

    /// Portraits are not carried (D17).
    pub(crate) fn no_portrait<'a>(
        field: &'static str,
        mut claim_types: impl Iterator<Item = &'a str>,
    ) -> Result<(), ShapeError> {
        if claim_types.any(|t| t == PORTRAIT_CLAIM_TYPE) {
            return Err(ShapeError::Field {
                field,
                rule: "must not name person.portrait",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use serde_json::json;

    /// Refused as a receiver reads it: by the schema, by the parse, or by
    /// [`CheckShape`].
    fn refused<T: trust_tasks_rs::Payload + DeserializeOwned + CheckShape>(value: Value) -> bool {
        read_checked::<T>(&value).is_err()
    }

    fn profile_json() -> Value {
        json!({
            "listed": true,
            "displayName": "Carol",
            "languages": ["en", "de-AT"],
            "location": { "country": "CZ", "city": "Prague" },
            "methods": ["inPerson", "video"],
            "acceptsDocumentation": ["passport", "none"],
            "availability": "Weekday evenings",
            "contactHint": "Ask on the kernel list",
            "events": [{
                "name": "Kernel Maintainer Summit",
                "startDate": "2026-10-05",
                "endDate": "2026-10-08",
                "location": { "country": "CZ", "city": "Prague" },
                "url": "https://events.example.org/kms"
            }]
        })
    }

    #[test]
    fn a_vetter_profile_round_trips_as_published_and_is_closed() {
        let p: vetters::profile::v0_1::Payload = serde_json::from_value(profile_json()).unwrap();
        p.check_shape().unwrap();
        assert_eq!(serde_json::to_value(&p).unwrap(), profile_json());

        let minimal_json = json!({
            "listed": false, "languages": [], "methods": ["video"],
            "acceptsDocumentation": [], "events": []
        });
        let minimal: vetters::profile::v0_1::Payload =
            serde_json::from_value(minimal_json.clone()).unwrap();
        minimal.check_shape().unwrap();
        assert_eq!(
            serde_json::to_value(&minimal).unwrap(),
            minimal_json,
            "the empty arrays are written, optionals are absent"
        );

        for required in ["languages", "methods", "acceptsDocumentation", "events"] {
            let mut missing = minimal_json.clone();
            missing.as_object_mut().unwrap().remove(required);
            assert!(
                serde_json::from_value::<vetters::profile::v0_1::Payload>(missing).is_err(),
                "{required} is required"
            );
        }
        for (member, value) in [
            ("email", json!("c@example.com")),
            ("location", json!({ "country": "CZ", "street": "x" })),
        ] {
            let mut extra = minimal_json.clone();
            extra[member] = value;
            assert!(serde_json::from_value::<vetters::profile::v0_1::Payload>(extra).is_err());
        }
        assert!(
            serde_json::from_value::<vetters::profile::v0_1::Response>(json!({
                "listed": true, "updatedAt": "2026-09-15T08:30:01Z", "ext": {}
            }))
            .is_err(),
            "the response has no ext"
        );
    }

    #[test]
    fn a_vetter_profile_is_bounded_by_its_schema_and_its_event_rule() {
        type Profile = vetters::profile::v0_1::Payload;
        let broken = |f: &dyn Fn(&mut Value)| {
            let mut p = profile_json();
            f(&mut p);
            refused::<Profile>(p)
        };
        assert!(!broken(&|_| {}));
        assert!(broken(&|p| p["displayName"] = json!("")));
        assert!(broken(&|p| p["displayName"] = json!("x".repeat(129))));
        assert!(!broken(&|p| p["displayName"] = json!("é".repeat(128))));
        assert!(broken(&|p| p["languages"] = json!(["x"])));
        assert!(broken(&|p| p["languages"] = json!(["en", "en"])));
        assert!(broken(&|p| {
            p["languages"] = json!((0..17).map(|i| format!("en-{i}")).collect::<Vec<_>>());
        }));
        assert!(broken(&|p| p["methods"] = json!([])));
        assert!(broken(&|p| p["methods"] = json!(["video", "video"])));
        assert!(broken(&|p| p["acceptsDocumentation"] = json!(["Passport"])));
        assert!(broken(
            &|p| p["acceptsDocumentation"] = json!(["none", "none"])
        ));
        assert!(broken(&|p| {
            p["acceptsDocumentation"] =
                json!((0..17).map(|i| format!("doc{i}")).collect::<Vec<_>>());
        }));
        assert!(broken(&|p| p["availability"] = json!("x".repeat(501))));
        assert!(broken(&|p| p["contactHint"] = json!("x".repeat(301))));
        assert!(broken(&|p| p["location"]["country"] = json!("cz")));
        assert!(broken(&|p| p["location"]["country"] = json!("CZE")));
        assert!(broken(&|p| p["location"]["region"] = json!("")));
        assert!(broken(&|p| {
            let event = p["events"][0].clone();
            p["events"] = json!(vec![event; 33]);
        }));
        assert!(broken(&|p| p["events"][0]["name"] = json!("x".repeat(201))));
        assert!(broken(
            &|p| p["events"][0]["url"] = json!("http://events.example.org")
        ));
        assert!(broken(
            &|p| p["events"][0]["url"] = json!("https://events.example.org/kernel meetup")
        ));
        assert!(broken(
            &|p| p["events"][0]["url"] = json!("https://events.example.org/\u{7}")
        ));
        assert!(broken(&|p| p["events"][0]["endDate"] = json!("2026-10-04")));
        assert!(broken(&|p| p["events"][0]["endDate"] = json!("2026-11-06")));
        assert!(!broken(&|p| p["events"][0]["endDate"] = json!("2026-11-05")));
    }

    #[test]
    fn event_dates_are_exactly_year_month_day() {
        for bad in [
            "2026-1-05",
            "26-10-05",
            "2026-10-05T00:00:00Z",
            "+2026-10-05",
            "2026-13-01",
            "2026-02-30",
            "",
        ] {
            let mut p = profile_json();
            p["events"][0]["startDate"] = json!(bad);
            assert!(
                refused::<vetters::profile::v0_1::Payload>(p),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn a_listing_request_is_closed_and_bounded() {
        type List = vetters::list::v0_1::Payload;
        let body = json!({
            "language": "de", "country": "AT", "region": "Wien", "city": "Wien",
            "method": "inPerson", "eventFrom": "2026-10-01", "eventTo": "2026-10-31",
            "eventName": "summit", "limit": 100, "cursor": "abc"
        });
        let parsed: List = serde_json::from_value(body.clone()).unwrap();
        parsed.check_shape().unwrap();
        assert!(has_event_filter(&parsed));
        assert!(!has_event_filter(&List::default()));
        List::default().check_shape().unwrap();
        assert_eq!(
            serde_json::to_value(List::default()).unwrap(),
            json!({}),
            "every filter is absent, never null"
        );
        assert!(refused::<List>(json!({ "memberDid": "did:key:z" })));

        for (member, value) in [
            ("language", json!("deutsch-")),
            ("country", json!("at")),
            ("limit", json!(0)),
            ("limit", json!(101)),
            ("cursor", json!("x".repeat(513))),
            ("eventName", json!("x".repeat(201))),
        ] {
            let mut b = body.clone();
            b[member] = value;
            assert!(refused::<List>(b), "{member}");
        }
        let mut backwards = body;
        backwards["eventTo"] = json!("2026-09-30");
        let backwards: List = serde_json::from_value(backwards).unwrap();
        assert_eq!(
            backwards.check_shape(),
            Err(ShapeError::Field {
                field: "eventTo",
                rule: "must not be before eventFrom"
            })
        );
    }

    #[test]
    fn a_resend_carries_nothing_and_answers_with_the_credential() {
        serde_json::from_value::<vetters::resend::v0_1::Payload>(json!({})).unwrap();
        assert!(
            serde_json::from_value::<vetters::resend::v0_1::Payload>(
                json!({ "memberDid": "did:key:z" })
            )
            .is_err()
        );
        let r: vetters::resend::v0_1::Response = vetters::resend::v0_1::Response::builder()
            .credential_id("urn:uuid:5b0e1c2a-7d4f-4a51-9c6e-2f1b8d3a9e70")
            .valid_until(Utc::now())
            .try_into()
            .unwrap();
        r.check_shape().unwrap();
        let v = serde_json::to_value(&r).unwrap();
        assert!(v["credentialId"].is_string() && v["validUntil"].is_string());
        assert!(v.get("ext").is_none());
    }

    #[test]
    fn the_auto_grant_config_is_bounded() {
        let config = |sweep: Option<u32>, validity: Option<u64>| AutoGrantConfig {
            enabled: true,
            sweep_minutes: sweep,
            validity_seconds: validity,
        };
        assert!(config(None, None).check_shape().is_ok());
        assert!(
            config(Some(5), Some(MIN_VETTER_GRANT_VALIDITY_SECONDS))
                .check_shape()
                .is_ok()
        );
        assert!(
            config(Some(1440), Some(MAX_VETTER_GRANT_VALIDITY_SECONDS))
                .check_shape()
                .is_ok()
        );
        assert!(config(Some(4), None).check_shape().is_err());
        assert!(config(Some(1441), None).check_shape().is_err());
        assert!(
            config(None, Some(MIN_VETTER_GRANT_VALIDITY_SECONDS - 1))
                .check_shape()
                .is_err()
        );
        assert!(
            serde_json::from_value::<AutoGrantConfig>(json!({ "enabled": true, "x": 1 })).is_err()
        );
        let status = AutoGrantStatus {
            enabled: false,
            sweep_minutes: DEFAULT_AUTO_GRANT_SWEEP_MINUTES,
            validity_seconds: DEFAULT_VETTER_GRANT_VALIDITY_SECONDS,
            last_sweep: None,
        };
        let v = serde_json::to_value(status).unwrap();
        assert_eq!(v["sweepMinutes"], 60);
        assert!(v.get("lastSweep").is_none());
        assert_eq!(serde_json::to_value(GrantOrigin::Auto).unwrap(), "auto");
    }

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
    fn a_vetter_grant_is_closed_and_bounded_by_its_schema() {
        type Grant = vetters::grant::v0_1::Payload;
        let body: Grant = serde_json::from_value(json!({
            "memberDid": "did:key:zCarol",
            "validitySeconds": 86_400
        }))
        .unwrap();
        body.check_shape().unwrap();
        assert!(
            refused::<Grant>(json!({ "memberDid": "did:key:zCarol", "role": "admin" })),
            "the grant names no role: it only ever names a vetter"
        );
        assert!(refused::<Grant>(json!({ "memberDid": "carol" })));
        for (validity, ok) in [
            (MIN_VETTER_GRANT_VALIDITY_SECONDS - 1, false),
            (MIN_VETTER_GRANT_VALIDITY_SECONDS, true),
            (MAX_VETTER_GRANT_VALIDITY_SECONDS, true),
            (MAX_VETTER_GRANT_VALIDITY_SECONDS + 1, false),
        ] {
            assert_eq!(
                !refused::<Grant>(
                    json!({ "memberDid": "did:key:zCarol", "validitySeconds": validity })
                ),
                ok,
                "{validity}"
            );
        }
    }

    /// The grant bounds are also enforced on the admin's automatic-grant
    /// configuration, which no schema covers — so the constants must say what
    /// the grant schema says.
    #[test]
    fn the_grant_bounds_are_the_grant_schemas() {
        let schema: Value = serde_json::from_str(
            <vetters::grant::v0_1::Payload as trust_tasks_rs::Payload>::PAYLOAD_SCHEMA.unwrap(),
        )
        .unwrap();
        let validity = &schema["properties"]["validitySeconds"];
        assert_eq!(validity["minimum"], MIN_VETTER_GRANT_VALIDITY_SECONDS);
        assert_eq!(validity["maximum"], MAX_VETTER_GRANT_VALIDITY_SECONDS);
    }

    fn requirements_json() -> Value {
        json!({
            "version": "0.1",
            "statementType": IDENTITY_VETTING_ENDORSEMENT_TYPE,
            "minStatements": 2,
            "minByMethod": { "inPerson": 1 },
            "acceptedMethods": ["inPerson", "video", "priorAcquaintance"],
            "requiredClaims": ["name.legal"],
            "maxStatementAge": "P120D",
            "eligibleVetters": { "role": "vetter" },
            "independence": { "maxByDeclaredRelationship": { "family": 0 } }
        })
    }

    #[test]
    fn requirements_round_trip_as_published() {
        let req: VettingRequirements = serde_json::from_value(requirements_json()).unwrap();
        assert_eq!(req.min_by_method.get(&VettingMethod::InPerson), Some(&1));
        assert_eq!(
            req.independence
                .as_ref()
                .unwrap()
                .max_by_declared_relationship
                .get(&VettingRelationship::Family),
            Some(&0)
        );
        let back = serde_json::to_value(&req).unwrap();
        assert_eq!(back, requirements_json());
        // Documentation is the vetter's choice unless a community sets a floor.
        assert!(back.get("acceptedDocumentClasses").is_none());
        req.check_shape().unwrap();
        assert_eq!(max_statement_age(&req), Duration::try_days(120));
    }

    #[test]
    fn requirements_tolerate_members_a_newer_community_adds() {
        let mut v = requirements_json();
        v["vetterDirectory"] = json!(true);
        let req: VettingRequirements = serde_json::from_value(v).unwrap();
        req.check_shape().unwrap();
    }

    #[test]
    fn requirements_that_cannot_be_evaluated_are_refused() {
        let with = |member: &str, value: Value| {
            let mut v = requirements_json();
            v[member] = value;
            read_requirements(&v).is_err()
        };
        assert!(with("minStatements", json!(0)));
        assert!(with("acceptedMethods", json!([])));
        assert!(with("acceptedMethods", json!(["video", "video"])));
        assert!(
            with("maxStatementAge", json!("P4M")),
            "months are calendar-dependent"
        );
        assert!(with("version", json!("1")), "version is MAJOR.MINOR");
        assert!(with("eligibleVetters", json!({ "role": "vet ter" })));
        assert!(with("acceptedDocumentClasses", json!(["national-id"])));
        assert!(!with(
            "acceptedDocumentClasses",
            json!([documentation::NATIONAL_ID])
        ));
        assert!(
            with("governanceFrameworkUrl", json!("http://gov.example")),
            "governance text is served over https"
        );
        assert!(with(
            "governanceFrameworkUrl",
            json!("https://gov.example/frame work")
        ));
        assert!(with(
            "governanceFrameworkUrl",
            json!("https://gov.example/\u{1b}")
        ));
        assert!(
            with("decisionSla", json!(format!("PT{}S", "1".repeat(30)))),
            "durations are at most 32 characters"
        );

        let mut floor_unaccepted = requirements_json();
        floor_unaccepted["acceptedMethods"] = json!(["video"]);
        let req: VettingRequirements = serde_json::from_value(floor_unaccepted).unwrap();
        assert_eq!(
            req.check_shape(),
            Err(ShapeError::Field {
                field: "minByMethod",
                rule: "names a method acceptedMethods does not accept"
            }),
            "a floor on a method that never counts is unsatisfiable"
        );
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

    fn request_json() -> Value {
        json!({
            "community": "did:web:vtc.example",
            "joinDid": "did:key:zApplicant",
            "ticket": { "code": "K7QF-2M9X" },
            "languages": ["en", "pt-BR", "zh-Hant-TW"],
            "message": "Hello"
        })
    }

    fn request_refused(value: Value) -> bool {
        read_request(&value, "did:key:zApplicant").is_err()
    }

    #[test]
    fn a_request_is_checked_against_its_schema_and_its_issuer() {
        let body: request::v0_1::Payload = serde_json::from_value(request_json()).unwrap();
        assert!(matches!(
            body.ticket,
            Some(request::v0_1::Ticket::ShortCodeTicket(_))
        ));
        check_request(&body, "did:key:zApplicant").unwrap();
        assert_eq!(
            check_request(&body, "did:key:zSomeoneElse"),
            Err(ShapeError::JoinDidNotIssuer)
        );

        let mut both = request_json();
        both["introduction"] = json!({ "type": ["VerifiableCredential"] });
        assert!(
            matches!(
                read_request(&both, "did:key:zApplicant"),
                Err(ShapeError::Schema(_))
            ),
            "a ticket or an introduction, not both"
        );
        // An empty introduction is still an introduction on the wire, even
        // though the parsed payload cannot tell it from none.
        let mut empty_introduction = request_json();
        empty_introduction["introduction"] = json!({});
        assert!(read_request(&empty_introduction, "did:key:zApplicant").is_err());
    }

    #[test]
    fn request_bounds_follow_the_schema() {
        assert!(!request_refused(request_json()));
        for (member, value) in [
            // I, L, O and U are not Crockford characters.
            ("ticket", json!({ "code": "K7QF-2M9O" })),
            (
                "ticket",
                json!({ "ticketId": "t-1", "secret": "too-short" }),
            ),
            (
                "ticket",
                json!({ "ticketId": "t 1", "secret": "A".repeat(43) }),
            ),
            (
                "ticket",
                json!({ "code": "K7QF-2M9X", "secret": "A".repeat(43) }),
            ),
            ("languages", json!(["en", "en"])),
            ("languages", json!(["english"])),
            (
                "languages",
                json!((0..17).map(|i| format!("en-x{i}")).collect::<Vec<_>>()),
            ),
            ("message", json!("x".repeat(1001))),
            ("message", json!("")),
            ("availability", json!("x".repeat(257))),
            ("community", json!("vtc.example")),
            ("tikcet", json!({ "code": "K7QF-2M9X" })),
        ] {
            let mut b = request_json();
            b[member] = value.clone();
            assert!(request_refused(b), "{member}: {value}");
        }
        let scanned: request::v0_1::Ticket =
            serde_json::from_value(json!({ "ticketId": "t1", "secret": "A".repeat(43) })).unwrap();
        assert!(matches!(scanned, request::v0_1::Ticket::QrTicket(_)));
    }

    #[test]
    fn reply_and_notice_bounds_follow_the_schema() {
        let accepted = json!({
            "requestId": "r1",
            "acceptsDocumentation": ["passport", "nationalId"],
            "sessionHint": "Hallway, 3pm"
        });
        assert!(!refused::<request::v0_1::Response>(accepted.clone()));
        let mut a = accepted.clone();
        a["acceptsDocumentation"] = json!(["national-id"]);
        assert!(refused::<request::v0_1::Response>(a));
        let mut a = accepted;
        a["requestId"] = json!("r".repeat(129));
        assert!(refused::<request::v0_1::Response>(a));

        let session = json!({
            "requestId": "r1",
            "challenge": "A".repeat(43),
            "domain": "did:web:vtc.example",
            "method": "video",
            "requiredClaims": ["name.legal"],
            "expiresAt": "2026-09-17T15:17:00Z"
        });
        assert!(!refused::<session::v0_1::Payload>(session.clone()));
        let mut s = session.clone();
        s["optionalClaims"] = json!([PORTRAIT_CLAIM_TYPE]);
        assert!(refused::<session::v0_1::Payload>(s));
        let mut s = session;
        s["challenge"] = json!("A".repeat(44));
        assert!(refused::<session::v0_1::Payload>(s));

        assert!(refused::<decline::v0_1::Payload>(json!({
            "requestId": "r1", "code": "notComfortable", "message": "x".repeat(501)
        })));

        for (id, ok) in [
            ("urn:uuid:5b0e1c2a-7d4f-4a51-9c6e-2f1b8d3a9e70", true),
            ("https://vetter.example/statements/1", true),
            ("statement-1", false),
            ("urn:uuid:has space", false),
            ("1urn:x", false),
            ("urn:", false),
        ] {
            let notice = json!({
                "statementId": id,
                "statementDigestMultibase": "zQmYimQAvAKzznkjph8xTTpuLhf21jAiUPMy7qdBp7qsU7Z"
            });
            assert_eq!(
                !refused::<revoke_statement::v0_1::Payload>(notice),
                ok,
                "{id}"
            );
        }
    }

    #[test]
    fn branding_is_bounded_by_the_manifest_schema() {
        assert!(read_branding(&json!({})).is_ok());
        assert!(
            read_branding(&json!({
                "displayName": "Linux Kernel", "accentColor": "#1A2b3c",
                "logoUrl": "https://kernel.example.org/logo.svg"
            }))
            .is_ok()
        );
        for bad in [
            json!({ "accentColor": "red" }),
            json!({ "accentColor": "#12345g" }),
            json!({ "logoUrl": "http://kernel.example.org/logo.svg" }),
            json!({ "logoUrl": "https://kernel.example.org/my logo.svg" }),
            json!({ "logoUrl": "https://kernel.example.org/logo\u{0}.svg" }),
            json!({ "displayName": "x".repeat(129) }),
            json!({ "displayName": "" }),
            json!({ "tagline": "x" }),
        ] {
            assert!(read_branding(&bad).is_err(), "{bad}");
        }
        // A branding built in code, as the community stores it, is held to the
        // same rule.
        let spaced: manifest::CommunityBranding =
            serde_json::from_value(json!({ "logoUrl": "https://kernel.example.org/my logo.svg" }))
                .unwrap();
        assert!(spaced.check_shape().is_err());
    }

    #[test]
    fn a_format_uri_member_is_an_absolute_https_uri() {
        // The schema validator does not assert `format: uri`, and the
        // `^https://` pattern alone admits every one of these refusals.
        for good in [
            "https://events.example.org",
            "https://events.example.org/kms?day=1#hall-b",
            "https://example.org/caf%C3%A9",
            "https://[2001:db8::1]:8443/logo.svg",
        ] {
            assert_eq!(shape::https_uri("url", good), Ok(()), "{good}");
        }
        let whitespace = "must not contain whitespace or control characters";
        let not_a_uri = "must be an absolute https URI";
        let too_long = format!("https://example.org/{}", "a".repeat(2048));
        for (bad, rule) in [
            ("https://events.example.org/kernel meetup", whitespace),
            ("https://events.example.org/\u{7}", whitespace),
            ("https://events.example.org/\tx", whitespace),
            ("https://events.example.org/\u{85}", whitespace),
            ("http://events.example.org", not_a_uri),
            ("events.example.org", not_a_uri),
            ("https://", not_a_uri),
            ("https:///path", not_a_uri),
            ("https://?q=1", not_a_uri),
            ("https://example.org/%zz", not_a_uri),
            ("https://example.org/%4", not_a_uri),
            ("https://example.org/café", not_a_uri),
            ("https://example.org/<logo>", not_a_uri),
            (too_long.as_str(), "must be at most 2048 characters"),
        ] {
            assert_eq!(
                shape::https_uri("url", bad),
                Err(ShapeError::Field { field: "url", rule }),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_listed_event_url_is_an_absolute_https_uri() {
        // A listing is the stored profiles as the community lists them: without
        // `listed`, with the vetter's DID and the grant and update times.
        let listing = |url: &str| {
            let mut vetter = profile_json();
            vetter["events"][0]["url"] = json!(url);
            let members = vetter.as_object_mut().unwrap();
            members.remove("listed");
            members.insert("vetterDid".into(), json!("did:key:zVetter"));
            members.insert("grantValidUntil".into(), json!("2027-01-01T00:00:00Z"));
            members.insert("updatedAt".into(), json!("2026-09-01T00:00:00Z"));
            json!({ "vetters": [vetter] })
        };
        type Listing = vetters::list::v0_1::Response;
        assert!(!refused::<Listing>(listing(
            "https://events.example.org/kms"
        )));
        for bad in [
            "https://events.example.org/kernel meetup",
            "https://events.example.org/\u{7}",
            "http://events.example.org",
        ] {
            assert!(refused::<Listing>(listing(bad)), "{bad:?}");
        }
    }

    fn endorsement() -> IdentityVettingEndorsement {
        serde_json::from_value(json!({
            "type": IDENTITY_VETTING_ENDORSEMENT_TYPE,
            "community": "did:web:vtc.example",
            "method": "video",
            "documentClasses": ["passport"],
            "claimsVerified": ["name.legal"],
            "livenessConfirmed": true,
            "identityCommitment": "zCommitment",
            "cardDigestMultibase": "zCard",
            "declaredRelationship": "none"
        }))
        .unwrap()
    }

    #[test]
    fn an_endorsement_follows_its_shared_definition() {
        endorsement().check_shape().unwrap();
        let broken = |f: &dyn Fn(&mut IdentityVettingEndorsement)| {
            let mut e = endorsement();
            f(&mut e);
            e.check_shape().is_err()
        };
        assert!(broken(&|e| e.community = "vtc.example".into()));
        assert!(broken(&|e| e.endorsement_type = String::new()));
        assert!(broken(&|e| {
            e.document_classes
                .push(documentation::PASSPORT.try_into().unwrap());
        }));
        assert!(broken(&|e| {
            e.document_classes = vec![documentation::NONE.try_into().unwrap()];
        }));
        assert!(broken(&|e| {
            e.claims_verified
                .push(PORTRAIT_CLAIM_TYPE.try_into().unwrap());
        }));
        assert!(!broken(&|e| e.document_classes.clear()));
        assert!(
            serde_json::from_value::<IdentityVettingEndorsement>(json!({
                "type": IDENTITY_VETTING_ENDORSEMENT_TYPE,
                "community": "did:web:vtc.example",
                "method": "video",
                "documentClasses": ["national-id"],
                "claimsVerified": ["name.legal"],
                "livenessConfirmed": true,
                "identityCommitment": "zC",
                "cardDigestMultibase": "zD",
                "declaredRelationship": "none"
            }))
            .is_err(),
            "documentation is a lowerCamelCase token"
        );
    }

    #[test]
    fn method_strings_round_trip() {
        for m in [
            VettingMethod::InPerson,
            VettingMethod::Video,
            VettingMethod::PriorAcquaintance,
        ] {
            assert_eq!(m.to_string().parse::<VettingMethod>().unwrap(), m);
            assert_eq!(serde_json::to_value(m).unwrap(), json!(m.to_string()));
        }
    }
}
