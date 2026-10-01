//! The one place a DTG credential arriving from outside is checked for being
//! a DTG credential at all.
//!
//! DTG Credentials §Common Structure is normative for every subtype:
//!
//! - `@context` MUST be the W3C VC v2 context followed by the DTG v1 context
//!   (`https://registry.trustoverip.org/dtg/context/v1`); further contexts may
//!   follow. The retired `firstperson.network` context is refused, with no
//!   alias.
//! - `type` MUST include `VerifiableCredential`, `DTGCredential`, and exactly
//!   one concrete subtype
//! - `issuerScope` MUST be present: `pairwise`, `directed` or `public`
//!
//! The VTC asserted all of that on everything it *mints* — `credentials::dtg`
//! builds through the `dtg-credentials` catalog behind the `catalog_wire_shape`
//! guard — and, until this module, on almost nothing it *accepted*. Each
//! ingress point compared string literals of its own. Every literal that
//! drifted, drifted silently: the recognition path spent its whole life
//! matching a `Verifiable`-prefixed type nothing has ever issued, rejecting
//! every real presentation (#1062), and the VRC publish path
//! never looked at `type` at all, so any signed JSON with an `issuer` and a
//! `credentialSubject.id` became an edge in the community trust graph.
//!
//! Classification here goes through `dtg_credentials` — the same catalog the
//! issuing side mints from: its `type` rule (`DTGCredentialType::try_from`,
//! which names a retired type such as the old endorsement or witness type
//! rather than treating it as unknown), its `IssuerScope` parse, and, for a
//! statement, its full parse including the predicate profile — so the two
//! cannot drift apart without the round-trip tests below failing.
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
//! window check into it would turn an expired role VAC into a silently skipped
//! entry, and the caller would report "presentation has no AuthorityCredential"
//! instead of `recognition::verify`'s "VAC validUntil … is in the past".
//!
//! ## Trust Task Context Binding
//!
//! [`classify_dtg`] also refuses a statement whose predicate profile requires
//! `taskContext` — a `witnessed/1` VWC, a `vetted/1` vetting statement — and
//! that carries none (or no `taskDigestMultibase`). That *is* classification,
//! not validity: the profile marks the properties REQUIRED, and the catalog's
//! own parse rejects such a statement at exactly this point. So it belongs
//! inside the filter rather than beside it — a document that cannot be built
//! as a VWC is not a VWC being skipped for the wrong reason. Without
//! it, a witness made in one exchange reads identically to one made in the
//! exchange it is presented in (Security Considerations 5, context collapse);
//! see [`crate::credentials::task_context`].
//!
//! For the same reason the VIC and recognition paths are **left alone**. Both
//! already implement `validFrom <= now < validUntil` with the same boundary
//! this module uses, and each carries semantics the shared check does not:
//! recognition also *clamps* the minted session TTL to the earliest
//! `validUntil` across the pair (`routes/recognise.rs:408-417`), and both
//! require `validUntil` to be present at all. Routing them through here would
//! either duplicate their checks or weaken them. Three implementations was the
//! problem; replacing two working ones with one weaker one is not the fix.
//!
//! ## Ingress is only half the question
//!
//! A window check at ingress establishes that an artifact was in date when it
//! arrived, and nothing more. It cannot answer whether the artifact is in
//! force *now*, because the artifact may have been suspended, superseded or
//! withdrawn since, and because a stored row whose window has closed is not
//! re-checked on the way out. That was exactly the reach of #1075, and #1079
//! is the general form of it.
//!
//! [`crate::credentials::lifecycle`] owns the other half: it takes the window
//! [`validity_window`] reads and the events recorded against the artifact, and
//! resolves the two under one precedence rule. Read paths call that; ingress
//! points call [`require_dtg_type`]. Both get their bounds from the same
//! parser here, so admission and interpretation cannot disagree about where a
//! window's edges are.

use chrono::{DateTime, Utc};
use dtg_credentials::{DTGCredentialError, DTGCredentialType, IssuerScope};
use serde_json::Value as JsonValue;
use vti_common::error::AppError;

/// The two `@context` entries every DTG credential MUST carry, first and
/// second, in this order.
pub const DTG_CONTEXTS: [&str; 2] = [
    dtg_credentials::W3C_VC_V2_CONTEXT,
    dtg_credentials::DTG_CONTEXT_V1,
];

/// The base `type` entries every DTG credential MUST carry, alongside exactly
/// one concrete subtype.
pub const DTG_BASE_TYPES: [&str; 2] = ["VerifiableCredential", "DTGCredential"];

/// The member of a credential's `type` array that says what it is: the first
/// entry that is neither the W3C base type, the DTG base type, nor the
/// non-authoritative `PersonhoodCredential` hint. For a DTG credential that is
/// its concrete subtype; for any other VC, its own type. `None` for a document
/// with no such entry.
///
/// Reading "the first entry that is not `VerifiableCredential`", as the
/// presentation paths did, names every DTG credential `DTGCredential`.
pub fn concrete_type(doc: &JsonValue) -> Option<String> {
    match doc.get("type")? {
        JsonValue::Array(types) => types
            .iter()
            .filter_map(JsonValue::as_str)
            .find(|t| {
                !matches!(
                    *t,
                    "VerifiableCredential" | "DTGCredential" | "PersonhoodCredential"
                )
            })
            .map(str::to_string),
        JsonValue::String(t) => Some(t.clone()),
        _ => None,
    }
}

/// `credentialSubject.predicate` of a DTG statement — or `predicate` of an
/// already-unwrapped subject (the DI / SD-JWT presentation projections keep
/// only the subject). `None` for anything that is not a statement.
pub fn statement_predicate(claims: &JsonValue) -> Option<String> {
    let subject = match claims.get("credentialSubject") {
        Some(subject) if subject.is_object() => subject,
        _ => claims,
    };
    subject
        .get("predicate")
        .and_then(JsonValue::as_str)
        .map(str::to_string)
}

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
    // Exact positions, as the catalog's own parse compares them: the W3C
    // context first, the DTG v1 context second, further contexts after.
    for (position, required) in DTG_CONTEXTS.iter().enumerate() {
        if ctx.get(position).map(String::as_str) != Some(*required) {
            return Err(AppError::Validation(format!(
                "credential `@context` must carry `{required}` at position {position}"
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

    let subtype = DTGCredentialType::try_from(types.as_slice())
        .map_err(|e| AppError::Validation(format!("credential `type`: {e}")))?;

    // `issuerScope` is REQUIRED on every DTG credential, and its value is one
    // of three exact lowercase strings.
    let scope = doc
        .get("issuerScope")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| AppError::Validation("credential `issuerScope` missing".into()))?;
    scope
        .parse::<IssuerScope>()
        .map_err(|e| AppError::Validation(format!("credential `issuerScope`: {e}")))?;

    // A statement is held to its predicate profile — the catalog's full parse,
    // which is where `taskContext` / `taskDigestMultibase` being REQUIRED under
    // `witnessed/1` and `vetted/1` is enforced. Classification, not validity:
    // the missing binding is what lets a witness from one exchange be read as
    // evidence in another (Security Considerations 5).
    if matches!(subtype, DTGCredentialType::Statement) {
        // Shape only; a proof set would fail the catalog's one-proof model
        // (VTI-57), and the proofs are verified on their own.
        match vta_sdk::vetting::dtg_shape(doc) {
            Ok(_) => {}
            Err(DTGCredentialError::MissingTaskContext) => {
                return Err(crate::credentials::task_context::missing());
            }
            Err(e) => {
                return Err(AppError::Validation(format!("statement credential: {e}")));
            }
        }
    }
    Ok(subtype)
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

/// Read a credential's stated window as a value, for a caller that has to
/// *resolve* a state rather than accept-or-reject at ingress.
///
/// [`check_validity_window`] answers "may this document enter", which is the
/// only question an ingress point has. It is the wrong shape for the graph
/// read: an edge already in the store is not being admitted, it is being
/// interpreted, and interpreting it means combining the window with whatever
/// has been recorded against the artifact since — see
/// [`crate::credentials::lifecycle`]. Returning the bounds lets that
/// combination happen in one place instead of every reader re-deriving
/// "expired" from a boolean rejection it cannot see inside.
///
/// Shares `read_time` with the ingress check rather than parsing again, so
/// the two cannot disagree about what a bound *is*: both spellings are
/// accepted, a document stating both is refused as ambiguous, and an
/// unparseable bound is an error rather than a silent "no bound stated".
pub fn validity_window(
    doc: &JsonValue,
    label: &str,
) -> Result<crate::credentials::lifecycle::ValidityWindow, AppError> {
    Ok(crate::credentials::lifecycle::ValidityWindow {
        valid_from: read_time(doc, VALID_FROM_NAMES, label)?.map(|(_, t)| t),
        valid_until: read_time(doc, VALID_UNTIL_NAMES, label)?.map(|(_, t)| t),
    })
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
    use dtg_credentials::{DTGCredential, IssuerScope};

    fn vrc() -> JsonValue {
        vrc_valid(Utc::now(), None)
    }

    /// A catalog-minted VRC with an explicit window.
    fn vrc_valid(from: DateTime<Utc>, until: Option<DateTime<Utc>>) -> JsonValue {
        dtg_json(&DTGCredential::new_vrc(
            "did:peer:2.zR1".into(),
            IssuerScope::Pairwise,
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

    fn vsc() -> JsonValue {
        dtg_json(
            &DTGCredential::new_endorses_vsc(
                "did:web:issuer.example".into(),
                IssuerScope::Public,
                "did:key:zSubject".into(),
                serde_json::json!({ "skill": "moderation" }),
                Utc::now(),
                None,
            )
            .unwrap(),
        )
    }

    fn vac() -> JsonValue {
        dtg_json(
            &DTGCredential::new_community_role_vac(
                "did:web:community.example".into(),
                "did:key:zMember".into(),
                "moderator",
                Utc::now(),
                Utc::now() + Duration::days(30),
            )
            .unwrap(),
        )
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
            (vsc(), DTGCredentialType::Statement, "VSC"),
            (vac(), DTGCredentialType::Authority, "VAC"),
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

    /// A VWC the catalog itself would refuse to build must not classify as one
    /// here either. `taskContext` is REQUIRED under `witnessed/1`, and a witness
    /// without it is the credential that cannot be tied to any exchange — the
    /// one the context-collapse attack needs.
    #[test]
    fn refuses_a_witness_statement_with_no_task_context() {
        let mut witness = vsc();
        witness["issuerScope"] = serde_json::json!("directed");
        witness["credentialSubject"]["predicate"] =
            serde_json::json!(dtg_credentials::WITNESSED_V1);
        witness["credentialSubject"]["object"] = serde_json::json!({ "digestMultibase": dtg_credential_digest_multibase(&vrc()).unwrap() });

        let err = classify_dtg(&witness).expect_err("a VWC without taskContext must be refused");
        assert!(format!("{err:?}").contains("taskContext"), "{err:?}");

        // Both halves of the citation present, it classifies normally, so the
        // refusal is about the missing property and not about the subtype.
        witness["taskContext"] = serde_json::json!("urn:uuid:some-exchange");
        witness["taskDigestMultibase"] =
            serde_json::json!(digest_multibase(&serde_json::json!({ "id": "x" })).unwrap());
        assert_eq!(
            std::mem::discriminant(&classify_dtg(&witness).expect("a bound VWC classifies")),
            std::mem::discriminant(&DTGCredentialType::Statement)
        );
    }

    /// `issuerScope` is REQUIRED on every DTG credential, as one of three
    /// exact lowercase strings.
    #[test]
    fn refuses_a_credential_without_a_valid_issuer_scope() {
        let mut doc = vrc();
        doc.as_object_mut().unwrap().remove("issuerScope");
        assert!(classify_dtg(&doc).is_err(), "missing issuerScope");
        doc["issuerScope"] = serde_json::json!("Public");
        assert!(classify_dtg(&doc).is_err(), "case-sensitive");
    }

    /// The retired DTG context is refused, with no alias, and the v1 context
    /// must be second — not merely present.
    #[test]
    fn refuses_the_retired_context_and_a_misplaced_v1_context() {
        let mut doc = vrc();
        doc["@context"] = serde_json::json!([
            dtg_credentials::W3C_VC_V2_CONTEXT,
            "https://example.org/some-older-dtg-context"
        ]);
        assert!(classify_dtg(&doc).is_err());
        doc["@context"] = serde_json::json!([
            dtg_credentials::DTG_CONTEXT_V1,
            dtg_credentials::W3C_VC_V2_CONTEXT
        ]);
        assert!(classify_dtg(&doc).is_err(), "order matters");
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

    /// `Verifiable`-prefixed tags were never DTG types, and the types earlier
    /// drafts defined are retired. Nothing here may re-admit them.
    #[test]
    fn refuses_types_the_specification_does_not_define() {
        for fiction in [
            "VerifiableRecognitionCredential",
            "VerifiableMembershipCredential",
            "VerifiableStatementCredential",
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

/// Digest of a JSON document in the form DTG Credentials specifies: SHA-256
/// over the RFC 8785 (JCS) canonicalization, wrapped as a multihash
/// (`sha2-256`, header `0x12`, length `0x20`) and multibase-encoded base58btc.
///
/// Computed over the document **as submitted**, not over a re-serialisation of
/// a parsed model. A credential may carry members the local model does not
/// know, and digesting the model would silently drop them — leaving this
/// service and its peer computing different digests for the same credential
/// and neither able to see why.
///
/// This is the **Trust Task framework** digest — what
/// `_framework/0.3#/$defs/DigestMultibase` describes, used to bind a publish
/// authorization to the credential it authorizes. It is not the digest a DTG
/// credential carries in `digestMultibase`; that one is
/// [`dtg_credential_digest_multibase`], and the two differ in coverage.
pub fn digest_multibase(doc: &JsonValue) -> Result<String, AppError> {
    use sha2::{Digest, Sha256};
    let canonical = serde_json_canonicalizer::to_vec(doc)
        .map_err(|e| AppError::Validation(format!("credential is not canonicalizable: {e}")))?;
    let mut multihash = Vec::with_capacity(34);
    multihash.extend_from_slice(&[0x12, 0x20]);
    multihash.extend_from_slice(&Sha256::digest(&canonical));
    Ok(multibase::encode(multibase::Base::Base58Btc, multihash))
}

/// Digest of a credential in the form DTG Core Credentials **now** specifies for
/// `credentialSubject.digestMultibase`: SHA-256 over the JCS canonicalization of the
/// document with its top-level `proof` removed, as a base58btc multibase multihash.
///
/// Delegated to `dtg-credentials` rather than written here, and that is the point. This
/// module already carries two digest functions that differ in encoding *and* coverage, and
/// the acknowledgement binding used to be a third — a hand-rolled copy of a definition the
/// counterparty computes with the library. Working Draft 02 changed the encoding and the
/// copy did not follow, so the two sides stopped agreeing; the tests in
/// `members::inbound_vmc` caught it, being written for exactly that
/// ("two implementations, one definition — this is the assertion that catches either side
/// drifting").
///
/// One definition, one implementation, and it belongs to the party that publishes the
/// specification.
///
/// **Not [`digest_multibase`]**, which is the same encoding over *different* coverage — it
/// digests the document whole, `proof` included. Substituting one for the other compiles
/// and produces a plausible string that matches nothing.
pub fn dtg_credential_digest_multibase(doc: &JsonValue) -> Result<String, AppError> {
    dtg_credentials::digest_multibase_json(doc)
        .map_err(|e| AppError::Validation(format!("credential is not canonicalizable: {e}")))
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    /// The digest is over the canonical form, so member order in the submitted
    /// JSON cannot change it — which is the whole point of naming RFC 8785
    /// rather than "SHA-256 of the credential".
    #[test]
    fn member_order_does_not_change_the_digest() {
        let a = serde_json::json!({ "b": 1, "a": { "y": 2, "x": 3 } });
        let b = serde_json::json!({ "a": { "x": 3, "y": 2 }, "b": 1 });
        assert_eq!(digest_multibase(&a).unwrap(), digest_multibase(&b).unwrap());
    }

    /// base58btc multibase, so the value always leads with `z`.
    #[test]
    fn is_base58btc_multibase() {
        let d = digest_multibase(&serde_json::json!({ "a": 1 })).unwrap();
        assert!(
            d.starts_with('z'),
            "expected a base58btc multibase, got {d}"
        );
    }

    /// The DTG digest is an interoperability surface: the member computes it
    /// and this service recomputes it, in two codebases. It excludes the
    /// top-level `proof`, so signing the grant must not change it, or the
    /// community could never re-sign a credential without silently
    /// invalidating every acknowledgement already made against it.
    #[test]
    fn dtg_credential_digest_ignores_the_proof() {
        let unsigned = serde_json::json!({
            "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
            "issuer": "did:example:community",
            "credentialSubject": { "id": "did:example:member" }
        });
        let mut signed = unsigned.clone();
        signed["proof"] = serde_json::json!({
            "type": "DataIntegrityProof",
            "proofValue": "z3FXQ..."
        });

        assert_eq!(
            dtg_credential_digest_multibase(&unsigned).unwrap(),
            dtg_credential_digest_multibase(&signed).unwrap()
        );
    }

    /// The two digests answer different questions and must never be swapped:
    /// the framework one binds a publish authorization, the DTG one binds a
    /// credential to the credential it references.
    #[test]
    fn the_two_digests_are_not_interchangeable() {
        let doc = serde_json::json!({ "a": 1, "proof": { "proofValue": "zSig" } });
        assert_ne!(
            digest_multibase(&doc).unwrap(),
            dtg_credential_digest_multibase(&doc).unwrap()
        );
    }

    #[test]
    fn different_documents_digest_differently() {
        let a = digest_multibase(&serde_json::json!({ "a": 1 })).unwrap();
        let b = digest_multibase(&serde_json::json!({ "a": 2 })).unwrap();
        assert_ne!(a, b);
    }
}
