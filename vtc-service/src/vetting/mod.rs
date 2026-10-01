//! Peer identity vetting, community side: turning the vetting statements a join
//! presentation carries into the facts `join.rego` decides on.
//!
//! Design: OpenVTC `docs/design/vetting-process.md` §10.
//!
//! ## What the host establishes, and what policy decides
//!
//! The raw submit path verifies the presentation's holder binding and none of
//! the credentials inside it (see `join::orchestrate::presentation_from_vp`), so
//! nothing here trusts a statement because it arrived. For each Vetting
//! Statement in the VP — a DTG `StatementCredential` whose
//! `credentialSubject.predicate` is the criterion's `statementType`
//! (`https://registry.trustoverip.org/dtg/vsc/vetted/1`) — this module:
//!
//! 1. verifies it (`vta_sdk::vetting::statement::verify_statement` — proof by
//!    the issuer, v1 context and type, the `vetted/1` profile: `taskContext`,
//!    `taskDigestMultibase`, `issuerScope` at least `directed` — bounded
//!    window, strict `object.value`);
//! 2. accepts its predicate through the community's fail-closed accept list
//!    (`crate::endorsement_types::accept_list`) — a predicate the community
//!    has not registered never counts;
//! 3. binds it to the applicant (`credentialSubject.id` = the proven holder);
//! 4. asks whether the issuer is an **eligible vetter** of this community —
//!    a current member, who had already joined when they issued the statement,
//!    holding a vetter role grant ([`vetters`]; the community-issued VAC
//!    conferring `role:<eligibleVetters.role>` at the community's DID) that was
//!    recorded by then, unexpired then, and is not revoked now;
//! 5. counts the survivors with `vta_sdk::vetting::requirements::evaluate`, the
//!    same rule the applicant's client uses for its checklist.
//!
//! The result is [`VettingFacts`]. Policy reads `satisfied`,
//! `commitments_consistent`, `independence_ok` and `needs` and decides; the
//! host never admits on vetting by itself.
//!
//! Independence is established from evidence, not from statements merely being
//! separately signed (VTI-CMP-070): distinct vetters are distinct *members*.

pub mod auto_grant;
/// The member of a join submission's `extensions` a hidden-vetting proof rides in.
///
/// Spelled here rather than imported so that [`redact_hidden_submission`] runs whether or not
/// this build implements the suite: a community that never verifies one still has no reason to
/// keep it. `vetting::pcs`'s tests pin it against the crate's own constant.
pub const HIDDEN_VETTING_MEMBER: &str = "hiddenVetting";

/// Replace a hidden-vetting proof with a digest of itself, once it has been decided.
///
/// A proof is evidence for exactly one decision, and after that it is a liability: it carries
/// the tags, and a tag is one discrete log from the vetter who made it (`docs/design/
/// vetting-hidden-vetters-pcs.md` §18). The facts row is what every reader downstream actually
/// uses; the submission is not read again.
///
/// What stays is enough to answer "was this decided on the evidence we think" — the suite, the
/// size, and a SHA-256 of the canonical bytes — and nothing that links a vetter to anything.
///
/// Returns true when there was a proof to redact.
pub fn redact_hidden_submission(extensions: &mut JsonValue) -> bool {
    let Some(obj) = extensions.as_object_mut() else {
        return false;
    };
    let Some(proof) = obj.get(HIDDEN_VETTING_MEMBER) else {
        return false;
    };
    let bytes = serde_json::to_vec(proof).unwrap_or_default();
    let suite = proof
        .get("suite")
        .and_then(JsonValue::as_str)
        .unwrap_or("unknown")
        .to_string();
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes));
    obj.insert(
        HIDDEN_VETTING_MEMBER.to_string(),
        serde_json::json!({
            "redacted": true,
            "suite": suite,
            "bytes": bytes.len(),
            "sha256": digest,
        }),
    );
    true
}

/// Hidden-vetter admission (ZKP), development branch `zkp-pcs`.
#[cfg(feature = "vetting-pcs")]
pub mod pcs;
/// The VTC-issued challenge a hidden submission is bound to.
#[cfg(feature = "vetting-pcs")]
pub mod pcs_challenge;
/// Event mode: the exception to the constant drip, and the gate that keeps it survivable.
#[cfg(feature = "vetting-pcs")]
pub mod pcs_event;
/// The community's minting half: vetter enrolment and the token drip.
#[cfg(feature = "vetting-pcs")]
pub mod pcs_issue;
/// The Trust Tasks that carry the community half.
#[cfg(feature = "vetting-pcs")]
pub mod pcs_tasks;
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
    VETTED_PREDICATE, VettingRequirements, VettingRequirementsInvitation,
};
use vta_sdk::vetting::requirements::{REQUIREMENTS_DIGEST_MEMBER, StatementFacts, evaluate};
use vta_sdk::vetting::statement::verify_statement;
use vti_common::error::AppError;

use crate::endorsements::{VETTER_GRANT_ROW_TYPE, endorsements_for_subject};
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
            projected.push(manifest_criterion(stored)?.criterion);
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

    // Hidden-vetter admission (development branch `zkp-pcs`): when the criterion publishes
    // anonymity parameters AND this submission carries a proof, the facts come from the proof
    // instead of from named statements. Everything downstream — `evaluate`, the needs
    // expansion, `join.rego` — is the same, because the facts are the same shape with each
    // vetter's tag where their DID would be.
    #[cfg(feature = "vetting-pcs")]
    if let Some(facts) = hidden_facts(
        state,
        &community_did,
        applicant_did,
        &selected,
        requirements,
        extensions,
        now,
    )
    .await?
    {
        return Ok(Some(facts));
    }
    let resolver = state.trust_task_vm_resolver();
    // Fail closed: a statement counts only under a predicate this community
    // registered (vtc/endorsement-types/register/0.1).
    let accepted = crate::endorsement_types::accept_list(&state.endorsement_types_ks).await?;

    let mut to_count = Vec::new();
    let mut statements = Vec::new();
    for vc in vetting_credentials(vp, &requirements.statement_type) {
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

        let vetted = verified.value();
        let mut failures = Vec::new();
        if verified.subject() != applicant_did {
            failures.push("subject-not-applicant".to_string());
        }
        // `verify_statement` holds the statement to `vetted/1`; a criterion
        // counting another predicate counts none of these.
        if requirements.statement_type != VETTED_PREDICATE {
            failures.push("wrong-statement-type".to_string());
        }
        // A vetter's statement carries the vetter-only members
        // (`identityCommitment`, `cardDigestMultibase`, `declaredRelationship`).
        // One without them is a statement the community issued for itself
        // (registry `vetted/1`): evidence for personhood, never a vetter's
        // statement to count toward admission.
        let vetter = vetted.vetter_members();
        if vetter.is_none() {
            failures.push("not-a-vetter-statement".to_string());
        }
        let predicate_accepted =
            vta_sdk::vetting::dtg_shape(vc).is_ok_and(|parsed| accepted.accept(&parsed).is_ok());
        if !predicate_accepted {
            failures.push("predicate-not-accepted".to_string());
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
            method: Some(vetted.method.to_string()),
            declared_relationship: vetted.declared_relationship.map(|r| r.to_string()),
            counted: false,
            failures,
        };
        // A statement about someone else, or of a type this criterion does not
        // count, is not evidence about this applicant at all — keep it out of the
        // count *and* out of the commitment-consistency check.
        if let (true, Some(vetter)) = (fact.failures.is_empty(), vetter) {
            to_count.push(StatementFacts {
                statement_id: verified.id().to_string(),
                vetter: verified.issuer().to_string(),
                method: vetted.method,
                claims_verified: vetted
                    .claims_verified
                    .iter()
                    .map(|c| c.as_str().to_owned())
                    .collect(),
                document_classes: vetted
                    .document_classes
                    .iter()
                    .map(|d| d.as_str().to_owned())
                    .collect(),
                declared_relationship: vetter.declared_relationship,
                identity_commitment: vetter.identity_commitment.to_owned(),
                valid_from: verified.valid_from(),
                community_matches: vetted.community == community_did,
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

/// The hidden-vetter path (development branch `zkp-pcs`).
///
/// `Ok(None)` when this criterion publishes no anonymity parameters, or when the submission
/// carries no proof — which is every named-path submission, including one to a community that
/// runs both.
#[cfg(feature = "vetting-pcs")]
async fn hidden_facts(
    state: &AppState,
    community_did: &str,
    applicant_did: &str,
    selected: &Selected,
    requirements: &VettingRequirements,
    extensions: &JsonValue,
    now: DateTime<Utc>,
) -> Result<Option<VettingFacts>, AppError> {
    let Some(stored) =
        crate::schemas::accepts::get_accepts(&state.schemas_ks, &selected.criterion_id).await?
    else {
        return Ok(None);
    };
    let Some(raw) = stored.hidden_vetting else {
        return Ok(None);
    };
    let config: crate::vetting::pcs::HiddenVettingConfig = serde_json::from_value(raw)
        .map_err(|e| AppError::Validation(format!("hidden-vetting parameters: {e}")))?;
    let decision = crate::vetting::pcs::decide(
        state,
        community_did,
        applicant_did,
        requirements,
        &selected.digest,
        &config,
        extensions,
        now,
    )
    .await
    .map_err(|e| AppError::Validation(format!("hidden vetting: {e}")))?;
    let Some(decision) = decision else {
        return Ok(None);
    };
    let evaluation = &decision.evaluation;
    Ok(Some(VettingFacts {
        criterion_id: selected.criterion_id.clone(),
        requirements_digest: selected.digest.clone(),
        applicant_digest_matches: selected.applicant_digest_matches,
        statements: decision
            .statements
            .iter()
            .map(|s| VettingStatementFact {
                id: Some(s.id.clone()),
                // The tag, not a DID: distinct tags are distinct vetters (design §2), and
                // that is all the community learns.
                issuer: Some(s.issuer.clone()),
                verified: s.verified,
                eligible: s.eligible,
                revoked: s.revoked,
                method: Some(s.method.to_string()),
                declared_relationship: Some(s.declared_relationship.to_string()),
                counted: s.counted,
                failures: s.failures.clone(),
            })
            .collect(),
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

/// Vetting Statements in a VP's `verifiableCredential`: statements whose
/// `credentialSubject.predicate` is the criterion's `statement_type` or the
/// registry's `vetted/1`, compared byte for byte. Picked by predicate, never by
/// a type string; everything else in the presentation is left to the other
/// facts.
fn vetting_credentials<'a>(
    vp: &'a JsonValue,
    statement_type: &'a str,
) -> impl Iterator<Item = &'a JsonValue> {
    vp.get("verifiableCredential")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter(move |vc| {
            let predicate = vc
                .pointer("/credentialSubject/predicate")
                .and_then(JsonValue::as_str);
            predicate == Some(statement_type) || predicate == Some(VETTED_PREDICATE)
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
pub(crate) async fn vetter_eligible(
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
    let grants =
        endorsements_for_subject(&state.endorsements_ks, issuer, VETTER_GRANT_ROW_TYPE).await?;
    Ok(grants.iter().any(|g| {
        vetters::recorded_during_membership(g, &member) && vetters::grant_covers(g, role, issued_at)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A decided proof is replaced by a digest of itself: enough to say what was decided on,
    /// nothing that links a vetter.
    #[test]
    fn a_decided_hidden_proof_is_redacted_to_a_digest() {
        let mut extensions = json!({
            "requirementsDigest": "zQmDigest",
            HIDDEN_VETTING_MEMBER: {
                "suite": "ps-ddh-bls12381",
                "id": "z7Applicant",
                "proof": "zTheWholeProofWithTagsInside",
                "statements": [{ "meta": {}, "token": {} }],
            },
        });
        assert!(redact_hidden_submission(&mut extensions));

        let left = &extensions[HIDDEN_VETTING_MEMBER];
        assert_eq!(left["redacted"], json!(true));
        assert_eq!(left["suite"], json!("ps-ddh-bls12381"));
        assert!(left["bytes"].as_u64().unwrap() > 0);
        assert_eq!(left["sha256"].as_str().unwrap().len(), 64);
        // Nothing of the proof survives.
        let text = serde_json::to_string(&extensions).unwrap();
        assert!(!text.contains("zTheWholeProofWithTagsInside"), "{text}");
        assert!(!text.contains("z7Applicant"), "{text}");
        // Everything beside it does.
        assert_eq!(extensions["requirementsDigest"], json!("zQmDigest"));
    }

    /// A named-path submission has nothing to redact, and is left exactly as it was.
    #[test]
    fn redaction_leaves_a_named_submission_alone() {
        let before = json!({ "requirementsDigest": "zQmDigest" });
        let mut after = before.clone();
        assert!(!redact_hidden_submission(&mut after));
        assert_eq!(before, after);
        // And a submission that is not an object at all is not a panic.
        let mut odd = json!("not an object");
        assert!(!redact_hidden_submission(&mut odd));
    }

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
                "statementType": VETTED_PREDICATE,
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
    fn only_vetting_statements_are_picked_out_of_a_presentation() {
        let vp = json!({
            "verifiableCredential": [
                { "credentialSubject": { "predicate": VETTED_PREDICATE } },
                { "credentialSubject": { "predicate": dtg_credentials::ENDORSES_V1 } },
                { "credentialSubject": { "predicate": "dtg:vetted" } },
                { "type": ["VerifiableCredential", "InvitationCredential"] },
                "eyJhbGciOi.jwt.vc"
            ]
        });
        assert_eq!(vetting_credentials(&vp, VETTED_PREDICATE).count(), 1);
    }
}
