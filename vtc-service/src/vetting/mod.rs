//! Peer identity vetting, community side: turning the vetting statements a join
//! presentation carries into the facts `join.rego` decides on.
//!
//! Design: OpenVTC `docs/design/vetting-process.md` §10.
//!
//! ## What the host establishes, and what policy decides
//!
//! The raw submit path verifies the presentation's holder binding and none of
//! the credentials inside it (see `join::orchestrate::presentation_from_vp`), so
//! nothing here trusts a statement because it arrived. For each identity-vetting
//! `EndorsementCredential` in the VP this module:
//!
//! 1. verifies it (`vta_sdk::vetting::statement::verify_statement` — proof by
//!    the issuer, type, bounded window, strict endorsement body);
//! 2. binds it to the applicant (`credentialSubject.id` = the proven holder);
//! 3. asks whether the issuer is an **eligible vetter** of this community —
//!    a current member, who had already joined when they issued the statement,
//!    holding a vetter role grant ([`vetters`]) in the role the requirements
//!    name that was recorded by then, unexpired then, and is not revoked now;
//! 4. counts the survivors with `vta_sdk::vetting::requirements::evaluate`, the
//!    same rule the applicant's client uses for its checklist.
//!
//! The result is [`VettingFacts`]. Policy reads `satisfied`,
//! `commitments_consistent`, `independence_ok` and `needs` and decides; the
//! host never admits on vetting by itself.
//!
//! Independence is established from evidence, not from statements merely being
//! separately signed (VTI-CMP-070): distinct vetters are distinct *members*.

pub mod auto_grant;
pub mod profiles;
pub mod revocation;
pub mod vetters;

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::warn;

use vta_sdk::protocols::join_requests::manifest::v0_2::Criterion as ManifestCriterion;
use vta_sdk::protocols::vetting::{
    COMMUNITY_ROLE_ENDORSEMENT_TYPE, IDENTITY_VETTING_ENDORSEMENT_TYPE, VettingRequirements,
    VettingRequirementsInvitation,
};
use vta_sdk::vetting::requirements::{REQUIREMENTS_DIGEST_MEMBER, StatementFacts, evaluate};
use vta_sdk::vetting::statement::verify_statement;
use vti_common::error::AppError;

use crate::endorsements::endorsements_for_subject;
use crate::members::storage::get_member;
use crate::routes::join_requests::manifest::manifest_criterion;
use crate::schemas::accepts::list_accepts;
use crate::server::AppState;

/// The generic need a policy returns when vetting is incomplete. The host
/// expands it into the precise shortfall ([`expand_needs`]), which a visually
/// authored policy cannot express because its `with` is static.
pub const NEED_VETTING: &str = "vetting";

/// The need returned when the requirements demand an invitation and none was
/// presented.
pub const NEED_INVITATION: &str = "vetting:invitation";

/// What the host established about the vetting evidence of one join request.
/// Every member is a host verdict; policy reads it and decides.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VettingFacts {
    /// The criterion whose requirements were applied.
    pub criterion_id: String,
    /// That criterion's current `requirementsDigest`.
    pub requirements_digest: String,
    /// The applicant named this digest in its submission — it gathered its
    /// statements against the requirements as they stand now.
    pub applicant_digest_matches: bool,
    /// Every identity-vetting statement the presentation carried.
    pub statements: Vec<VettingStatementFact>,
    /// Distinct eligible vetters counted.
    pub distinct_counted_vetters: u32,
    /// Counted statements by method (`inPerson`, `video`, …).
    pub by_method: BTreeMap<String, u32>,
    /// All counted-eligible statements carry one identity commitment.
    pub commitments_consistent: bool,
    /// No declared-relationship cap is exceeded.
    pub independence_ok: bool,
    /// The requirements demand an invitation credential alongside.
    pub invitation_required: bool,
    /// Count, method floors, commitment consistency and independence all hold.
    pub satisfied: bool,
    /// What is still missing, in the `vetting:*` wire grammar.
    pub needs: Vec<String>,
}

/// One presented statement, as the host saw it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VettingStatementFact {
    /// The statement `id`, when it could be read.
    pub id: Option<String>,
    /// The issuer DID, when it could be read.
    pub issuer: Option<String>,
    /// Proof, type, window and body all verified.
    pub verified: bool,
    /// The issuer is an eligible vetter of this community.
    pub eligible: bool,
    /// The issuer has withdrawn the statement.
    pub revoked: bool,
    /// `inPerson` / `video` / `priorAcquaintance`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The vetter's declared relationship to the applicant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_relationship: Option<String>,
    /// It counted toward the requirements.
    pub counted: bool,
    /// Why it did not count (stable codes).
    #[serde(default)]
    pub failures: Vec<String>,
}

/// Build the vetting facts for a join presentation, or `None` when no
/// criterion this community publishes requires vetting.
///
/// `extensions` is the submission's `extensions` object; an applicant names the
/// `requirementsDigest` it gathered against there.
pub async fn vetting_facts(
    state: &AppState,
    applicant_did: &str,
    vp: &JsonValue,
    extensions: &JsonValue,
    now: DateTime<Utc>,
) -> Result<Option<VettingFacts>, AppError> {
    let mut projected = Vec::new();
    for stored in list_accepts(&state.schemas_ks).await? {
        if stored.vetting.is_some() {
            projected.push(manifest_criterion(stored)?);
        }
    }
    let applicant_digest = extensions
        .get(REQUIREMENTS_DIGEST_MEMBER)
        .and_then(JsonValue::as_str);
    let Some(selected) = select_criterion(projected, applicant_digest) else {
        return Ok(None);
    };
    let requirements = &selected.requirements;

    let community_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_default();
    let resolver = state.trust_task_vm_resolver();

    let mut to_count = Vec::new();
    let mut statements = Vec::new();
    for vc in vetting_credentials(vp) {
        let id = vc.get("id").and_then(JsonValue::as_str).map(str::to_string);
        let issuer = issuer_of(vc);
        let verified = match verify_statement(vc, now, &resolver).await {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    applicant = %applicant_did,
                    statement = id.as_deref().unwrap_or("<no id>"),
                    error = %e,
                    cause = e.cause().unwrap_or(""),
                    "vetting statement did not verify — not counted"
                );
                statements.push(VettingStatementFact {
                    id,
                    issuer,
                    verified: false,
                    eligible: false,
                    revoked: false,
                    method: None,
                    declared_relationship: None,
                    counted: false,
                    failures: vec!["unverified".into()],
                });
                continue;
            }
        };

        let endorsement = verified.endorsement();
        let mut failures = Vec::new();
        if verified.subject() != applicant_did {
            failures.push("subject-not-applicant".to_string());
        }
        if endorsement.endorsement_type != requirements.statement_type {
            failures.push("wrong-statement-type".to_string());
        }
        let eligible = vetter_eligible(
            state,
            verified.issuer(),
            &requirements.eligible_vetters.role,
            verified.valid_from(),
        )
        .await?;
        // A withdrawal notice counts only against a statement with the notice's
        // own issuer, id and digest, so nobody can withdraw a statement they did
        // not sign.
        let revoked = revocation::is_revoked(
            &state.vetting_revocations_ks,
            verified.issuer(),
            verified.id(),
            verified.digest_multibase(),
        )
        .await?;

        let fact = VettingStatementFact {
            id: Some(verified.id().to_string()),
            issuer: Some(verified.issuer().to_string()),
            verified: true,
            eligible,
            revoked,
            method: Some(endorsement.method.to_string()),
            declared_relationship: Some(endorsement.declared_relationship.to_string()),
            counted: false,
            failures,
        };
        // A statement about someone else, or of a type this criterion does not
        // count, is not evidence about this applicant at all — keep it out of the
        // count *and* out of the commitment-consistency check.
        if fact.failures.is_empty() {
            to_count.push(StatementFacts {
                statement_id: verified.id().to_string(),
                vetter: verified.issuer().to_string(),
                method: endorsement.method,
                claims_verified: endorsement
                    .claims_verified
                    .iter()
                    .map(|c| c.as_str().to_owned())
                    .collect(),
                document_classes: endorsement
                    .document_classes
                    .iter()
                    .map(|d| d.as_str().to_owned())
                    .collect(),
                declared_relationship: endorsement.declared_relationship,
                identity_commitment: endorsement.identity_commitment.clone(),
                valid_from: verified.valid_from(),
                community_matches: endorsement.community == community_did,
                eligible,
                revoked,
            });
        }
        statements.push(fact);
    }

    let evaluation = evaluate(requirements, &to_count, now);
    for fact in &mut statements {
        let Some(id) = fact.id.as_deref() else {
            continue;
        };
        if evaluation.counted.iter().any(|c| c == id) {
            fact.counted = true;
        } else if let Some((_, reasons)) = evaluation.not_counted.iter().find(|(nc, _)| nc == id) {
            fact.failures
                .extend(reasons.iter().map(|r| r.code().to_string()));
        }
    }

    Ok(Some(VettingFacts {
        criterion_id: selected.criterion_id,
        requirements_digest: selected.digest,
        applicant_digest_matches: selected.applicant_digest_matches,
        statements,
        distinct_counted_vetters: u32::try_from(evaluation.distinct_vetters()).unwrap_or(u32::MAX),
        by_method: evaluation
            .by_method
            .iter()
            .map(|(m, n)| (m.to_string(), *n))
            .collect(),
        commitments_consistent: evaluation.commitments_consistent,
        independence_ok: evaluation.independence_ok,
        invitation_required: matches!(
            requirements.invitation,
            Some(VettingRequirementsInvitation::Required)
        ),
        satisfied: evaluation.satisfied(),
        needs: evaluation.needs.iter().map(|n| n.to_wire()).collect(),
    }))
}

/// Replace a policy's generic [`NEED_VETTING`] with the precise shortfall the
/// facts record. A policy authored in the visual editor can only return a
/// static `needs` list; this is where it becomes something an applicant can act
/// on. Leaves `needs` untouched when there are no vetting facts, or when the
/// facts record no specific shortfall (e.g. only an independence concern).
pub fn expand_needs(needs: &mut Vec<String>, facts: Option<&VettingFacts>) {
    let Some(facts) = facts else {
        return;
    };
    if facts.needs.is_empty() {
        return;
    }
    if let Some(pos) = needs.iter().position(|n| n == NEED_VETTING) {
        needs.splice(pos..=pos, facts.needs.iter().cloned());
    }
}

/// The criterion a submission is evaluated under.
#[derive(Debug, Clone)]
struct Selected {
    criterion_id: String,
    requirements: VettingRequirements,
    digest: String,
    applicant_digest_matches: bool,
}

/// Pick the criterion: the one whose current digest the applicant named, else
/// the first vetting criterion (criteria are listed in id order). A community
/// with more than one vetting criterion should expect applicants to name one.
fn select_criterion(
    projected: Vec<ManifestCriterion>,
    applicant_digest: Option<&str>,
) -> Option<Selected> {
    let named = applicant_digest.and_then(|d| {
        projected
            .iter()
            .position(|c| c.requirements_digest.as_ref().map(|r| r.as_str()) == Some(d))
    });
    let (index, matches) = match named {
        Some(i) => (i, true),
        None => (0, false),
    };
    let chosen = projected.into_iter().nth(index)?;
    Some(Selected {
        criterion_id: chosen.id.as_str().to_owned(),
        requirements: chosen.vetting?,
        digest: chosen
            .requirements_digest
            .map(String::from)
            .unwrap_or_default(),
        applicant_digest_matches: matches,
    })
}

/// Identity-vetting endorsement credentials in a VP's `verifiableCredential`.
fn vetting_credentials(vp: &JsonValue) -> impl Iterator<Item = &JsonValue> {
    vp.get("verifiableCredential")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter(|vc| {
            vc.pointer("/credentialSubject/endorsement/type")
                .and_then(JsonValue::as_str)
                == Some(IDENTITY_VETTING_ENDORSEMENT_TYPE)
        })
}

fn issuer_of(vc: &JsonValue) -> Option<String> {
    match vc.get("issuer")? {
        JsonValue::String(s) => Some(s.clone()),
        JsonValue::Object(o) => o.get("id")?.as_str().map(str::to_string),
        _ => None,
    }
}

/// Is `issuer` an eligible vetter: a current member, whose membership predates
/// the statement, holding a role grant the community recorded for `role` —
/// issued during this membership and by the statement's `validFrom`, unexpired
/// then, and not revoked since ([`vetters::grant_covers`]).
///
/// Revocation is read as it stands now, not as it stood at issuance: a grant
/// withdrawn after a statement was signed stops that statement counting. That
/// errs toward not admitting, and it is what an operator withdrawing a vetter
/// they no longer trust means.
async fn vetter_eligible(
    state: &AppState,
    issuer: &str,
    role: &str,
    issued_at: DateTime<Utc>,
) -> Result<bool, AppError> {
    let Some(member) = get_member(&state.members_ks, issuer).await? else {
        return Ok(false);
    };
    // `issued_at` and a grant's `created_at` are second-precision credential
    // timestamps; compare them with the second the member joined.
    if member.removed_at.is_some() || vetters::joined_at_second(&member) > issued_at {
        return Ok(false);
    }
    let grants = endorsements_for_subject(
        &state.endorsements_ks,
        issuer,
        COMMUNITY_ROLE_ENDORSEMENT_TYPE,
    )
    .await?;
    Ok(grants.iter().any(|g| {
        vetters::recorded_during_membership(g, &member) && vetters::grant_covers(g, role, issued_at)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A digest-shaped value per criterion id.
    fn digest(id: &str) -> String {
        format!("zQm{}", id.repeat(20))
    }

    fn criterion(id: &str, min: u32) -> ManifestCriterion {
        serde_json::from_value(json!({
            "id": id,
            "presentationDefinition": {},
            "vetting": {
                "version": "0.1",
                "statementType": IDENTITY_VETTING_ENDORSEMENT_TYPE,
                "minStatements": min,
                "acceptedMethods": ["inPerson"],
                "eligibleVetters": { "role": "vetter" }
            },
            "requirementsDigest": digest(id),
        }))
        .unwrap()
    }

    #[test]
    fn the_criterion_the_applicant_named_is_the_one_applied() {
        let s = select_criterion(
            vec![criterion("a", 1), criterion("b", 2)],
            Some(&digest("b")),
        )
        .unwrap();
        assert_eq!(s.criterion_id, "b");
        assert!(s.applicant_digest_matches);
        assert_eq!(s.requirements.min_statements.get(), 2);
    }

    #[test]
    fn an_unknown_or_absent_digest_falls_back_to_the_first_and_says_so() {
        let s = select_criterion(
            vec![criterion("a", 1), criterion("b", 2)],
            Some(&digest("c")),
        )
        .unwrap();
        assert_eq!(s.criterion_id, "a");
        assert!(!s.applicant_digest_matches);
        assert!(select_criterion(vec![], Some(&digest("a"))).is_none());
    }

    fn facts_with_needs(needs: &[&str]) -> VettingFacts {
        VettingFacts {
            criterion_id: "a".into(),
            requirements_digest: "za".into(),
            applicant_digest_matches: true,
            statements: vec![],
            distinct_counted_vetters: 1,
            by_method: BTreeMap::new(),
            commitments_consistent: true,
            independence_ok: true,
            invitation_required: false,
            satisfied: false,
            needs: needs.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn a_generic_vetting_need_becomes_the_precise_shortfall() {
        let mut needs = vec!["agreed:code-of-conduct".into(), NEED_VETTING.into()];
        let f = facts_with_needs(&["vetting:statements:1", "vetting:method:inPerson:1"]);
        expand_needs(&mut needs, Some(&f));
        assert_eq!(
            needs,
            vec![
                "agreed:code-of-conduct",
                "vetting:statements:1",
                "vetting:method:inPerson:1"
            ]
        );
    }

    #[test]
    fn needs_are_left_alone_without_facts_or_a_specific_shortfall() {
        let mut needs = vec![NEED_VETTING.to_string()];
        expand_needs(&mut needs, None);
        assert_eq!(needs, vec![NEED_VETTING]);
        expand_needs(&mut needs, Some(&facts_with_needs(&[])));
        assert_eq!(needs, vec![NEED_VETTING]);
    }

    #[test]
    fn only_identity_vetting_endorsements_are_picked_out_of_a_presentation() {
        let vp = json!({
            "verifiableCredential": [
                { "credentialSubject": { "endorsement": { "type": IDENTITY_VETTING_ENDORSEMENT_TYPE } } },
                { "credentialSubject": { "endorsement": { "type": "SkillEndorsement" } } },
                { "type": ["VerifiableCredential", "InvitationCredential"] },
                "eyJhbGciOi.jwt.vc"
            ]
        });
        assert_eq!(vetting_credentials(&vp).count(), 1);
    }
}
