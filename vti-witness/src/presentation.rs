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
//! # The member link
//!
//! A party submits from its pairwise relationship DID, but a community's
//! membership credential names the member's own DID, so step 4 cannot be met
//! from the relationship presentation alone. `witness/session/submit/0.2`
//! carries the bridge in its own payload member, **`memberPresentation`**
//! (*The member presentation*, rules 1–4):
//!
//! 1. a `VerifiablePresentation` whose `holder` is the member DID, signed for
//!    `authentication` by that DID;
//! 2. bound to the **same session** — its `nonce` (or `challenge`) is the
//!    session's challenge and its `domain` the session's domain — which only the
//!    party that opened the session was told, so the member key signed for this
//!    one session and nothing else;
//! 3. carrying a membership credential from one of the identity's communities
//!    naming the member DID, every credential in it checked as in step 2;
//! 4. the member DID is neither of the session's parties and not the witness
//!    (nor an excluded DID): the counterparty's membership does not make the
//!    submitter eligible, and a membership credential naming the submitter's
//!    relationship DID belongs in `vp`.
//!
//! The witness **relies** on it only when its policy asks for membership
//! evidence, and then verifies it whole: any failure is `presentationInvalid`.
//! An identity that witnesses anyone (`communities = ["*"]`) ignores it, and
//! nothing in it counts for any other check. The link proves that whoever holds the relationship key also holds a member key
//! **in this session**; it cannot prove they are one person, so a member who
//! signs for somebody else lends them their eligibility. The witness learns the
//! member DID, keeps it nowhere, and logs it nowhere. Design note §3.3a has the
//! risks and the options left for later.
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

/// The parties and session a presentation is checked against.
pub struct Expected<'a> {
    /// The party submitting — the session's opener.
    pub submitter: &'a str,
    /// The session's other party.
    pub counterparty: &'a str,
    /// The witness identity answering, which a member DID may not be.
    pub witness: &'a str,
    /// The session's challenge, which a member presentation binds to.
    pub challenge: &'a str,
    /// The session's domain, which a member presentation binds to.
    pub domain: &'a str,
}

/// Verify `vp` (see the module docs). The error is a short reason for the
/// `presentationInvalid` message; it never echoes the presentation.
pub async fn verify(
    vp: &Value,
    member_presentation: Option<&Value>,
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
    let mut relationship: Option<&Value> = None;
    let mut member_of_a_community = false;
    for (vc, dtg) in verified_credentials(vp, policy, resolver, now).await? {
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
            _ if grants_membership(&dtg, submitter, policy) => member_of_a_community = true,
            _ => {}
        }
    }

    // The member link: relied on — and so verified whole — only where this
    // identity asks for membership evidence. One that witnesses anyone ignores
    // it, and it never stands in for any other check.
    if let Some(member_vp) = member_presentation
        && !policy.witnesses_anyone()
    {
        verify_member_link(member_vp, expected, policy, resolver, now).await?;
        member_of_a_community = true;
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
             witness serves, naming the submitting party, and no member presentation"
                .into(),
        );
    }

    Ok(VerifiedPresentation {
        relationship_credential: relationship.clone(),
    })
}

/// Every credential in `presentation`, each issuer proof verified for
/// `assertionMethod` under its `issuer`, none issued by an excluded DID, every
/// DTG credential in its validity window. The DTG ones are returned; anything
/// else is verified and otherwise ignored.
async fn verified_credentials<'v>(
    presentation: &'v Value,
    policy: &WitnessPolicy,
    resolver: &TrustTaskVmResolver,
    now: DateTime<Utc>,
) -> Result<Vec<(&'v Value, DTGCredential)>, String> {
    let credentials: Vec<&Value> = match presentation.get("verifiableCredential") {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(one @ Value::Object(_)) => vec![one],
        _ => Vec::new(),
    };
    if credentials.is_empty() {
        return Err("the presentation carries no credential".into());
    }
    let mut out = Vec::new();
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
        // Only DTG credentials mean anything here.
        let Ok(dtg) = DTGCredential::try_from(vc.clone()) else {
            continue;
        };
        if !in_window(&dtg, now) {
            return Err(format!("credential {index} is not valid now"));
        }
        out.push((vc, dtg));
    }
    Ok(out)
}

/// A community-issued membership grant from an accepted community naming
/// `member`. An acknowledgement (member → community) carries a digest and
/// names the community, so it never counts.
fn grants_membership(dtg: &DTGCredential, member: &str, policy: &WitnessPolicy) -> bool {
    matches!(dtg.type_(), DTGCredentialType::Membership)
        && policy.accepts_community(dtg.issuer())
        && dtg.subject() == member
        && dtg.subject_digest().is_none()
}

/// The member link (module docs): a presentation by a member DID, bound to
/// this session, carrying that DID's membership of an accepted community.
async fn verify_member_link(
    member_vp: &Value,
    expected: &Expected<'_>,
    policy: &WitnessPolicy,
    resolver: &TrustTaskVmResolver,
    now: DateTime<Utc>,
) -> Result<(), String> {
    if !has_type(member_vp, "VerifiablePresentation") {
        return Err("the member presentation is not a VerifiablePresentation".into());
    }
    let member = member_vp
        .get("holder")
        .and_then(Value::as_str)
        .filter(|h| h.starts_with("did:"))
        .ok_or("the member presentation names no `holder` DID")?;
    if member == expected.submitter {
        return Err(
            "the member presentation is the submitting party's own: a membership credential \
             naming the relationship DID belongs in `vp`"
                .into(),
        );
    }
    if member == expected.witness {
        return Err("the member presentation's holder is this witness".into());
    }
    if member == expected.counterparty {
        return Err(
            "the member presentation is the other party's: its membership does not make the \
             submitting party eligible"
                .into(),
        );
    }
    if policy.is_excluded(member) {
        return Err("this witness does not witness this exchange".into());
    }

    // Bound to this session, as the relationship presentation is.
    let carried: Vec<&str> = ["nonce", "challenge"]
        .iter()
        .filter_map(|m| member_vp.get(*m).and_then(Value::as_str))
        .collect();
    if carried.is_empty() || carried.iter().any(|c| *c != expected.challenge) {
        return Err("the member presentation is not bound to this session's challenge".into());
    }
    if member_vp.get("domain").and_then(Value::as_str) != Some(expected.domain) {
        return Err("the member presentation is not bound to this session's domain".into());
    }

    let holder = verify_proof_set(member_vp, ProofPurpose::Authentication, resolver)
        .await
        .map_err(|e| format!("the member presentation's proof did not verify: {e}"))?;
    if holder.signer() != member {
        return Err("the member presentation is not signed by its `holder`".into());
    }

    let credentials = verified_credentials(member_vp, policy, resolver, now)
        .await
        .map_err(|e| format!("member presentation: {e}"))?;
    if credentials
        .iter()
        .any(|(_, dtg)| grants_membership(dtg, member, policy))
    {
        Ok(())
    } else {
        Err(
            "the member presentation carries no valid membership credential from a community \
             this witness serves, naming its holder"
                .into(),
        )
    }
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
