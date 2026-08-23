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
/// Says nothing about signatures, validity windows or revocation — those are
/// the caller's, and are checked on their own paths. This answers only "is
/// this a DTG credential, and which one".
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

/// Check the common structure and require one specific subtype.
///
/// `context` names the endpoint in the rejection, so an operator reading a 400
/// learns which surface refused what — "this endpoint publishes relationship
/// edges; got a MembershipCredential" rather than a bare type mismatch.
pub fn require_dtg_type(
    doc: &JsonValue,
    expected: DTGCredentialType,
    context: &str,
) -> Result<(), AppError> {
    let got = classify_dtg(doc)?;
    if std::mem::discriminant(&got) == std::mem::discriminant(&expected) {
        Ok(())
    } else {
        Err(AppError::Validation(format!("{context}; got a {got}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::dtg_json;
    use chrono::Utc;
    use dtg_credentials::DTGCredential;

    fn vrc() -> JsonValue {
        dtg_json(&DTGCredential::new_vrc(
            "did:peer:2.zR1".into(),
            "did:peer:2.zR2".into(),
            Utc::now(),
            None,
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
        require_dtg_type(
            &vrc(),
            DTGCredentialType::Relationship,
            "this endpoint publishes relationship edges",
        )
        .expect("a VRC satisfies a VRC requirement");

        let err = require_dtg_type(
            &vmc(),
            DTGCredentialType::Relationship,
            "this endpoint publishes relationship edges",
        )
        .expect_err("a VMC must not satisfy a VRC requirement");
        assert!(format!("{err:?}").contains("relationship edges"));
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
