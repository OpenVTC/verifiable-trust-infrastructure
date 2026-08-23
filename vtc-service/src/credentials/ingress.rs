//! The one place a DTG credential arriving from outside is checked for being
//! a DTG credential at all.
//!
//! DTG Credentials §Common Structure is normative for every subtype:
//!
//! - `@context` MUST include both the W3C VC v2 context and the DTG context
//! - `type` MUST include `VerifiableCredential`, `DTGCredential`, and exactly
//!   one concrete subtype
//!
//! The VTC asserted all of that on everything it *mints* — `credentials::dtg`
//! builds through the `dtg-credentials` catalog behind the `catalog_wire_shape`
//! guard — and, until this module, on almost nothing it *accepted*. Each
//! ingress point compared string literals of its own. Every literal that
//! drifted, drifted silently: the recognition path spent its whole life
//! matching `"VerifiableEndorsementCredential"`, a type nothing has ever
//! issued, rejecting every real presentation (#1062), and the VRC publish path
//! never looked at `type` at all, so any signed JSON with an `issuer` and a
//! `credentialSubject.id` became an edge in the community trust graph.
//!
//! Classification here goes through `dtg_credentials::DTGCredentialType` — the
//! same catalog the issuing side mints from — so the two cannot drift apart
//! without the round-trip tests below failing.
//!
//! ## Validity windows
//!
//! [`check_validity_window`] is the one implementation of the temporal check,
//! for the same reason: it was enforced on the VIC path and the recognition
//! path and on nothing else, so an expired VRC became a permanent graph edge
//! (#1069). It is a free function rather than part of [`classify_dtg`] because
//! `classify_dtg` is also used as a *filter*: `routes/recognise.rs:329` walks a
//! presentation's `verifiableCredential` array and skips entries that are not
//! DTG credentials, since a VP may legitimately carry others. Folding the
//! window check into it would turn an expired VEC into a silently skipped
//! entry, and the caller would report "presentation has no
//! EndorsementCredential" instead of `recognition::verify`'s "VEC validUntil …
//! is in the past".
//!
//! For the same reason the VIC and recognition paths are **left alone**. Both
//! already implement `validFrom <= now < validUntil` with the same boundary
//! this module uses, and each carries semantics the shared check does not:
//! recognition also *clamps* the minted session TTL to the earliest
//! `validUntil` across the pair (`routes/recognise.rs:408-417`), and both
//! require `validUntil` to be present at all. Routing them through here would
//! either duplicate their checks or weaken them. Three implementations was the
//! problem; replacing two working ones with one weaker one is not the fix.

use chrono::{DateTime, Utc};
use dtg_credentials::DTGCredentialType;
use serde_json::Value as JsonValue;
use vti_common::error::AppError;

/// The two `@context` entries every DTG credential MUST carry.
pub const DTG_CONTEXTS: [&str; 2] = [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1",
];

/// The base `type` entries every DTG credential MUST carry, alongside exactly
/// one concrete subtype.
pub const DTG_BASE_TYPES: [&str; 2] = ["VerifiableCredential", "DTGCredential"];

/// Check the DTG common structure and return the concrete subtype.
///
/// Says nothing about signatures, validity windows or revocation. This answers
/// only "is this a DTG credential, and which one" — deliberately, so it stays
/// usable as a filter over a presentation that may carry non-DTG credentials
/// (`routes/recognise.rs:329`). For the window check see
/// [`check_validity_window`]; a caller that wants both wants
/// [`require_dtg_type`].
pub fn classify_dtg(doc: &JsonValue) -> Result<DTGCredentialType, AppError> {
    let ctx: Vec<String> = doc
        .get("@context")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| {
            AppError::Validation("credential `@context` missing or not an array".into())
        })?;
    for required in DTG_CONTEXTS {
        if !ctx.iter().any(|c| c == required) {
            return Err(AppError::Validation(format!(
                "credential `@context` must include `{required}`"
            )));
        }
    }

    let types: Vec<String> = doc
        .get("type")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| AppError::Validation("credential `type` missing or not an array".into()))?;
    for required in DTG_BASE_TYPES {
        if !types.iter().any(|t| t == required) {
            return Err(AppError::Validation(format!(
                "credential `type` must include `{required}`"
            )));
        }
    }

    DTGCredentialType::try_from(types.as_slice()).map_err(|_| {
        AppError::Validation("credential `type` names no DTG credential subtype".into())
    })
}

/// Check the common structure, require one specific subtype, and require the
/// credential to be inside its validity window at `now`.
///
/// `context` names the endpoint in the rejection, so an operator reading a 400
/// learns which surface refused what — "this endpoint publishes relationship
/// edges; got a MembershipCredential" rather than a bare type mismatch.
///
/// `now` is passed in rather than read here so a caller's several checks all
/// evaluate at one instant, and so tests can pick the instant. Same shape as
/// `credentials::invitation_verify::verify`.
pub fn require_dtg_type(
    doc: &JsonValue,
    expected: DTGCredentialType,
    now: DateTime<Utc>,
    context: &str,
) -> Result<(), AppError> {
    let got = classify_dtg(doc)?;
    if std::mem::discriminant(&got) != std::mem::discriminant(&expected) {
        return Err(AppError::Validation(format!("{context}; got a {got}")));
    }
    // Type before window: a VMC sent to a VRC endpoint is the wrong credential
    // whatever its dates say, and that is the more useful thing to be told.
    check_validity_window(doc, now, &got.to_string())
}

/// Reject a credential outside its `validFrom` / `validUntil` window.
///
/// DTG Credentials §Security Considerations 2 asks a verifier to reject
/// credentials outside their window and to check revocation via the governing
/// trust registry. That section is marked *informative*, so this is a
/// conformance expectation rather than a normative MUST — but a VRC is the
/// longest-lived credential in the graph and `routes/relationships.rs` read
/// neither field before this, so an expired one became a permanent edge
/// (#1069).
///
/// On the revocation half: VRCs deliberately carry no `credentialStatus`.
/// Planning-review D7 makes VRC revocation a row deletion, not a status-list
/// bit flip — see the module doc of `routes/relationships.rs`. A reader
/// comparing this file against the specification should read that as a
/// deliberate divergence, not a second gap. Where a credential *does* carry a
/// status block, the path that consumes it checks it
/// (`recognition::verify::check_status_list`).
///
/// **Window semantics: `validFrom <= now < validUntil`.** Half-open, matching
/// `credentials::invitation_verify` (`invitation_verify.rs:361-373`) and
/// `recognition::verify` (`verify.rs:198-228`). A credential whose `validUntil`
/// is exactly `now` is expired.
///
/// **Absent bounds are not enforced.** Both properties are optional in W3C VC
/// 2.0, and this checks only the bounds a credential actually states. VIC and
/// recognition each additionally *require* `validUntil` — a bearer invitation
/// and a foreign session both need a fixed expiry to be safe at all — but that
/// is their own rule, not a property of being a DTG credential, and imposing it
/// here would reject open-ended VRCs that nothing has ever said are invalid.
/// Whether an edge may be open-ended is a community policy question, and
/// `relationships.rego` is where it belongs.
///
/// **No clock-skew tolerance.** The windows on these credentials are days to
/// years, so a grace period of any plausible size changes nothing operationally
/// while making "expired" a fuzzy predicate that disagreed with the two paths
/// this is meant to align with — both compare exactly. Contrast
/// `PUBLISH_AUTHORIZATION_MAX_AGE_SECS` in `routes/relationships.rs`, which
/// does allow skew: that bounds a five-minute freshness window, where skew is a
/// real fraction of the budget.
///
/// `label` is the credential's own name (`"RelationshipCredential"`), not the
/// endpoint's — the fact being reported is about the credential.
pub fn check_validity_window(
    doc: &JsonValue,
    now: DateTime<Utc>,
    label: &str,
) -> Result<(), AppError> {
    if let Some((key, valid_from)) = read_time(doc, VALID_FROM_NAMES, label)?
        && valid_from > now
    {
        return Err(AppError::Validation(format!(
            "{label} `{key}` {valid_from} is in the future"
        )));
    }
    if let Some((_, valid_until)) = read_time(doc, VALID_UNTIL_NAMES, label)?
        && valid_until <= now
    {
        return Err(AppError::Validation(format!(
            "{label} expired at {valid_until}"
        )));
    }
    Ok(())
}

/// `(v2.0 name, v1.1 name)` for the start of the window.
const VALID_FROM_NAMES: (&str, &str) = ("validFrom", "issuanceDate");
/// `(v2.0 name, v1.1 name)` for the end of the window.
const VALID_UNTIL_NAMES: (&str, &str) = ("validUntil", "expirationDate");

/// Read one window bound, accepting either the VC 2.0 or the VC 1.1 spelling.
///
/// Both spellings are read because the catalog's own deserializer accepts
/// both: `DTGCommon` declares `#[serde(alias = "issuanceDate")]` /
/// `#[serde(alias = "expirationDate")]`. Nothing in this stack *emits* the 1.1
/// names — the catalog always serializes the 2.0 ones — but a credential
/// arriving from a foreign issuer may use them and would still parse, so
/// reading only `validUntil` would leave a 1.1-named credential unchecked
/// while every other layer accepted it. (`policy/extract.rs:104` likewise
/// surfaces `issuanceDate` to operator policies, so 1.1-named credentials do
/// reach this stack.)
///
/// Carrying *both* spellings is rejected rather than resolved: they are two
/// names for one property, a document stating both is ambiguous, and serde
/// treats an alias as the same field, so the catalog parser rejects such a
/// document as a duplicate field. Picking one here would let a document
/// through ingress that the catalog cannot parse.
///
/// Returns the key that was actually present alongside the value, so the
/// rejection names the field the sender wrote.
fn read_time(
    doc: &JsonValue,
    names: (&'static str, &'static str),
    label: &str,
) -> Result<Option<(&'static str, DateTime<Utc>)>, AppError> {
    // `Some(Null)` is treated as absent, matching serde's `Option` + `default`
    // handling — an explicit `"validUntil": null` states no bound.
    let present = |name: &str| doc.get(name).filter(|v| !v.is_null());
    let (v2, v11) = names;
    let (key, raw) = match (present(v2), present(v11)) {
        (Some(_), Some(_)) => {
            return Err(AppError::Validation(format!(
                "{label} carries both `{v2}` and `{v11}`; they are two names for \
                 one property and stating both is ambiguous"
            )));
        }
        (Some(v), None) => (v2, v),
        (None, Some(v)) => (v11, v),
        (None, None) => return Ok(None),
    };
    let s = raw
        .as_str()
        .ok_or_else(|| AppError::Validation(format!("{label} `{key}` is not a string")))?;
    let t = DateTime::parse_from_rfc3339(s).map_err(|e| {
        AppError::Validation(format!("{label} `{key}` is not an RFC 3339 timestamp: {e}"))
    })?;
    Ok(Some((key, t.with_timezone(&Utc))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::dtg_json;
    use chrono::{Duration, Utc};
    use dtg_credentials::DTGCredential;

    fn vrc() -> JsonValue {
        dtg_json(&DTGCredential::new_vrc(
            "did:peer:2.zR1".into(),
            "did:peer:2.zR2".into(),
            Utc::now(),
            None,
        ))
    }

    /// A catalog-minted VRC with an explicit window.
    fn vrc_valid(from: DateTime<Utc>, until: Option<DateTime<Utc>>) -> JsonValue {
        dtg_json(&DTGCredential::new_vrc(
            "did:peer:2.zR1".into(),
            "did:peer:2.zR2".into(),
            from,
            until,
        ))
    }

    fn vmc() -> JsonValue {
        dtg_json(&DTGCredential::new_vmc(
            "did:web:community.example".into(),
            "did:key:zMember".into(),
            Utc::now(),
            None,
            false,
        ))
    }

    fn vec_cred() -> JsonValue {
        dtg_json(&DTGCredential::new_vec(
            "did:web:issuer.example".into(),
            "did:key:zSubject".into(),
            Utc::now(),
            None,
            serde_json::json!({ "role": "moderator" }),
        ))
    }

    /// The guard that makes this module worth having: every subtype the
    /// catalog can mint is classified as itself, asserted against **catalog
    /// output** rather than literals.
    ///
    /// A literal here could agree with a literal in the validator while both
    /// disagreed with what clients send — the failure mode behind #1062, where
    /// handler and test agreed on a type nothing issues.
    #[test]
    fn classifies_every_subtype_the_catalog_mints() {
        for (doc, expected, label) in [
            (vrc(), DTGCredentialType::Relationship, "VRC"),
            (vmc(), DTGCredentialType::Membership, "VMC"),
            (vec_cred(), DTGCredentialType::Endorsement, "VEC"),
        ] {
            let got = classify_dtg(&doc)
                .unwrap_or_else(|e| panic!("catalog-minted {label} must classify: {e:?}"));
            assert_eq!(
                std::mem::discriminant(&got),
                std::mem::discriminant(&expected),
                "{label} classified as {got}"
            );
        }
    }

    #[test]
    fn requires_the_expected_subtype() {
        let now = Utc::now();
        require_dtg_type(
            &vrc(),
            DTGCredentialType::Relationship,
            now,
            "this endpoint publishes relationship edges",
        )
        .expect("a VRC satisfies a VRC requirement");

        let err = require_dtg_type(
            &vmc(),
            DTGCredentialType::Relationship,
            now,
            "this endpoint publishes relationship edges",
        )
        .expect_err("a VMC must not satisfy a VRC requirement");
        assert!(format!("{err:?}").contains("relationship edges"));
    }

    /// The gap #1069 is about: before this, an expired credential reached the
    /// graph because nothing on the VRC path read `validUntil`.
    #[test]
    fn rejects_a_credential_whose_window_has_passed() {
        let now = Utc::now();
        let expired = vrc_valid(now - Duration::days(30), Some(now - Duration::days(1)));

        let err = check_validity_window(&expired, now, "RelationshipCredential")
            .expect_err("an expired credential must be rejected");
        assert!(
            format!("{err:?}").contains("expired at"),
            "rejection should say when it expired: {err:?}"
        );

        // And through the full ingress gate, which is what the routes call.
        assert!(
            require_dtg_type(
                &expired,
                DTGCredentialType::Relationship,
                now,
                "this endpoint publishes relationship edges",
            )
            .is_err(),
            "the shape check must not admit an expired credential"
        );
    }

    #[test]
    fn rejects_a_credential_not_yet_valid() {
        let now = Utc::now();
        let future = vrc_valid(now + Duration::days(1), Some(now + Duration::days(30)));
        let err = check_validity_window(&future, now, "RelationshipCredential")
            .expect_err("a credential whose validFrom is in the future must be rejected");
        assert!(format!("{err:?}").contains("in the future"), "{err:?}");
    }

    /// Half-open, matching `invitation_verify` and `recognition::verify`:
    /// `validFrom == now` is inside the window, `validUntil == now` is not.
    #[test]
    fn window_boundaries_are_valid_from_inclusive_and_valid_until_exclusive() {
        let now = Utc::now();

        let starts_now = vrc_valid(now, Some(now + Duration::days(1)));
        check_validity_window(&starts_now, now, "RelationshipCredential")
            .expect("validFrom == now is inside the window");

        let ends_now = vrc_valid(now - Duration::days(1), Some(now));
        assert!(
            check_validity_window(&ends_now, now, "RelationshipCredential").is_err(),
            "validUntil == now is outside the window"
        );
    }

    /// Absent bounds state no bound. A VRC minted with `valid_until: None` —
    /// which the catalog allows, and which most of this repo's fixtures use —
    /// must still publish. Whether an open-ended edge is acceptable is a
    /// community policy question, not a temporal one.
    #[test]
    fn a_credential_with_no_valid_until_is_not_expired() {
        let now = Utc::now();
        let open_ended = vrc_valid(now - Duration::days(365), None);
        assert!(
            open_ended.get("validUntil").is_none(),
            "the catalog omits validUntil when it is None; this test is about that shape"
        );
        check_validity_window(&open_ended, now, "RelationshipCredential")
            .expect("an open-ended credential has no upper bound to be outside of");
    }

    /// VC 1.1 named these `issuanceDate` / `expirationDate`. The catalog still
    /// accepts them as deserialization aliases, so ingress must too — reading
    /// only the 2.0 names would leave a 1.1-named credential unchecked while
    /// every other layer accepted it.
    #[test]
    fn enforces_the_window_under_the_vc_1_1_property_names() {
        let now = Utc::now();
        let mut expired = vrc_valid(now - Duration::days(30), Some(now - Duration::days(1)));
        let from = expired["validFrom"].take();
        let until = expired["validUntil"].take();
        let obj = expired
            .as_object_mut()
            .expect("credential is a JSON object");
        obj.remove("validFrom");
        obj.remove("validUntil");
        obj.insert("issuanceDate".into(), from);
        obj.insert("expirationDate".into(), until);

        let err = check_validity_window(&expired, now, "RelationshipCredential")
            .expect_err("a 1.1-named expired credential must be rejected too");
        assert!(format!("{err:?}").contains("expired at"), "{err:?}");

        // It is genuinely the alias doing the work: the catalog parses it.
        serde_json::from_value::<DTGCredential>(expired)
            .expect("the catalog accepts issuanceDate/expirationDate as aliases");
    }

    /// Two names for one property, both stated, is ambiguous — and the catalog
    /// parser rejects it outright (serde treats an alias as the same field, so
    /// stating both is a duplicate field). Ingress must not admit a document
    /// the catalog cannot parse.
    #[test]
    fn rejects_a_credential_stating_both_spellings_of_one_bound() {
        let now = Utc::now();
        let mut doc = vrc_valid(now - Duration::days(1), Some(now + Duration::days(1)));
        doc["expirationDate"] = doc["validUntil"].clone();

        assert!(
            check_validity_window(&doc, now, "RelationshipCredential").is_err(),
            "validUntil + expirationDate together are ambiguous"
        );
        assert!(
            serde_json::from_value::<DTGCredential>(doc).is_err(),
            "the catalog parser rejects the same document; ingress must agree"
        );
    }

    /// A bound that is not an RFC 3339 timestamp is a rejection, not a silently
    /// skipped check. This is the failure mode that makes a guard useless:
    /// treating an unparseable date as "no bound stated".
    #[test]
    fn rejects_an_unparseable_bound() {
        let now = Utc::now();
        let mut doc = vrc_valid(now - Duration::days(1), Some(now + Duration::days(1)));
        doc["validUntil"] = serde_json::json!("whenever");
        assert!(check_validity_window(&doc, now, "RelationshipCredential").is_err());

        doc["validUntil"] = serde_json::json!(1_700_000_000);
        assert!(check_validity_window(&doc, now, "RelationshipCredential").is_err());
    }

    #[test]
    fn rejects_a_credential_missing_either_half_of_the_common_structure() {
        let mut no_ctx = vrc();
        no_ctx["@context"] = serde_json::json!(["https://www.w3.org/ns/credentials/v2"]);
        assert!(classify_dtg(&no_ctx).is_err(), "missing DTG context");

        let mut no_base = vrc();
        no_base["type"] = serde_json::json!(["VerifiableCredential", "RelationshipCredential"]);
        assert!(classify_dtg(&no_base).is_err(), "missing DTGCredential");

        let mut no_subtype = vrc();
        no_subtype["type"] = serde_json::json!(["VerifiableCredential", "DTGCredential"]);
        assert!(classify_dtg(&no_subtype).is_err(), "no concrete subtype");
    }

    /// `VerifiableRecognitionCredential` and the `Verifiable`-prefixed
    /// membership/endorsement tags were never DTG types. Nothing here may
    /// re-admit them.
    #[test]
    fn refuses_types_the_specification_does_not_define() {
        for fiction in [
            "VerifiableRecognitionCredential",
            "VerifiableMembershipCredential",
            "VerifiableEndorsementCredential",
        ] {
            let mut doc = vrc();
            doc["type"] = serde_json::json!(["VerifiableCredential", "DTGCredential", fiction]);
            assert!(
                classify_dtg(&doc).is_err(),
                "`{fiction}` is not a DTG credential type"
            );
        }
    }
}
