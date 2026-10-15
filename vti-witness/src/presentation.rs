//! Verifying what a party submits: the presentation, the relationship
//! credential in it, and the membership evidence (design note §3.3–§3.4).
//!
//! Runs only after the binding check — the session, its opener, and the VP's
//! `nonce`/`domain` against the session's challenge and domain — has passed, so
//! everything refused here is `witness/session/submit:presentationInvalid`.
//!
//! # The chain
//!
//! 1. **The presentation.** A `VerifiablePresentation` whose `holder` is the
//!    submitter, and whose Data Integrity proof (every proof, if a set)
//!    verifies for `authentication` under the submitter's own key.
//! 2. **Every credential in it** carries an issuer proof that verifies for
//!    `assertionMethod` under a key of its `issuer`, and is in its validity
//!    window. A presented credential that does not verify is refused, not
//!    skipped: a presentation is checked whole.
//! 3. **The relationship credential.** Exactly one `RelationshipCredential`
//!    issued by the submitter, whose subject is the session's other party —
//!    the edge the session names, in the direction the submitter issued it.
//!    This is the credential the VWC's digest will name.
//! 4. **Membership** (unless the identity witnesses anyone): a community-issued
//!    `MembershipCredential` from one of the identity's `communities`, naming
//!    the submitter as its subject.
//! 5. **Independence at submit** (§3.2): no credential in the presentation is
//!    issued by an excluded DID, and neither party is one.
//!
//! Proofs are verified through `vta_sdk::trust_task_proof::verify_proof_set`,
//! the one proof-set verifier the vault, the vetting client and the VTC share;
//! credentials are classified with `dtg_credentials::DTGCredential`. Nothing
//! here is written or logged: the presentation is dropped when the caller
//! returns (the spec's Retention section).

use chrono::{DateTime, Utc};
use dtg_credentials::{DTGCredential, DTGCredentialType};
use serde_json::Value;
use vta_sdk::trust_task_proof::{ProofPurpose, TrustTaskVmResolver, verify_proof_set};

use crate::witness::WitnessPolicy;

/// What a verified presentation yields: the relationship credential the
/// witness observed, in the wire form it arrived in (its digest is taken over
/// exactly this).
pub struct VerifiedPresentation {
    /// The submitter's relationship credential, verbatim.
    pub relationship_credential: Value,
}

/// The parties a presentation is checked against.
pub struct Expected<'a> {
    /// The party submitting — the session's opener.
    pub submitter: &'a str,
    /// The session's other party.
    pub counterparty: &'a str,
}

/// Verify `vp` (see the module docs). The error is a short reason for the
/// `presentationInvalid` message; it never echoes the presentation.
pub async fn verify(
    vp: &Value,
    expected: &Expected<'_>,
    policy: &WitnessPolicy,
    resolver: &TrustTaskVmResolver,
    now: DateTime<Utc>,
) -> Result<VerifiedPresentation, String> {
    let submitter = expected.submitter;

    // Independence again, against the configuration in force now.
    if policy.is_excluded(submitter) || policy.is_excluded(expected.counterparty) {
        return Err("this witness does not witness this exchange".into());
    }

    // 1. The presentation and its holder binding.
    if !has_type(vp, "VerifiablePresentation") {
        return Err("`vp` is not a VerifiablePresentation".into());
    }
    if vp.get("holder").and_then(Value::as_str) != Some(submitter) {
        return Err("the presentation's `holder` is not the submitting party".into());
    }
    let holder = verify_proof_set(vp, ProofPurpose::Authentication, resolver)
        .await
        .map_err(|e| format!("the presentation's proof did not verify: {e}"))?;
    if holder.signer() != submitter {
        return Err("the presentation is not signed by the submitting party".into());
    }

    // 2. Every credential.
    let credentials: Vec<&Value> = match vp.get("verifiableCredential") {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(one @ Value::Object(_)) => vec![one],
        _ => Vec::new(),
    };
    if credentials.is_empty() {
        return Err("the presentation carries no credential".into());
    }

    let mut relationship: Option<&Value> = None;
    let mut member_of_a_community = false;
    for (index, vc) in credentials.into_iter().enumerate() {
        let issuer = issuer_of(vc).ok_or_else(|| format!("credential {index} has no `issuer`"))?;
        if policy.is_excluded(issuer) {
            return Err(format!(
                "credential {index} is issued by a party this witness does not witness"
            ));
        }
        let signed = verify_proof_set(vc, ProofPurpose::AssertionMethod, resolver)
            .await
            .map_err(|e| format!("credential {index}'s issuer proof did not verify: {e}"))?;
        if signed.signer() != issuer {
            return Err(format!("credential {index} is not signed by its `issuer`"));
        }

        // Only DTG credentials mean anything here; anything else the party
        // chose to present has been verified and is otherwise ignored.
        let Ok(dtg) = DTGCredential::try_from(vc.clone()) else {
            continue;
        };
        if !in_window(&dtg, now) {
            return Err(format!("credential {index} is not valid now"));
        }
        match dtg.type_() {
            DTGCredentialType::Relationship if dtg.issuer() == submitter => {
                if relationship.is_some() {
                    return Err(
                        "the presentation carries more than one relationship credential issued \
                         by the submitting party, so which one was witnessed is ambiguous"
                            .into(),
                    );
                }
                if dtg.subject() != expected.counterparty {
                    return Err(
                        "the relationship credential's subject is not the session's other party"
                            .into(),
                    );
                }
                relationship = Some(vc);
            }
            DTGCredentialType::Membership
                if policy.accepts_community(dtg.issuer())
                    && dtg.subject() == submitter
                    // A community-issued grant; an acknowledgement (member →
                    // community) carries a digest and names the community.
                    && dtg.subject_digest().is_none() =>
            {
                member_of_a_community = true;
            }
            _ => {}
        }
    }

    // 3. The relationship credential.
    let relationship = relationship.ok_or_else(|| {
        "the presentation carries no relationship credential issued by the submitting party"
            .to_string()
    })?;

    // 4. Membership.
    if !policy.witnesses_anyone() && !member_of_a_community {
        return Err(
            "the presentation carries no valid membership credential from a community this \
             witness serves, naming the submitting party"
                .into(),
        );
    }

    Ok(VerifiedPresentation {
        relationship_credential: relationship.clone(),
    })
}

fn has_type(doc: &Value, wanted: &str) -> bool {
    match doc.get("type") {
        Some(Value::String(t)) => t == wanted,
        Some(Value::Array(ts)) => ts.iter().any(|t| t.as_str() == Some(wanted)),
        _ => false,
    }
}

/// A credential's `issuer`: a string, or an object's `id`.
fn issuer_of(vc: &Value) -> Option<&str> {
    match vc.get("issuer")? {
        Value::String(s) => Some(s),
        Value::Object(o) => o.get("id").and_then(Value::as_str),
        _ => None,
    }
}

fn in_window(vc: &DTGCredential, now: DateTime<Utc>) -> bool {
    vc.valid_from() <= now && vc.valid_until().is_none_or(|until| now < until)
}
