//! Evaluating vetting statements against a community's requirements.
//!
//! One counting rule, used by both sides:
//!
//! - the **applicant's client** feeds it what it can verify itself and shows
//!   the result as a checklist. It is advisory — "meets the published
//!   requirements", never "approved";
//! - the **community** feeds it what only it knows (current eligibility,
//!   revocation notices) and passes the result to its policy as facts. The
//!   policy decides; this only counts.
//!
//! Keeping the counting in one place means the checklist and the verdict cannot
//! drift apart on what "two distinct vetters" means.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::{VettingError, digest};
use crate::protocols::vetting::{DeclaredRelationship, VettingMethod, VettingRequirements};

/// The member a criterion's `requirementsDigest` sits in, excluded from its own
/// digest.
pub const REQUIREMENTS_DIGEST_MEMBER: &str = "requirementsDigest";

/// `digestMultibase` over a manifest criterion without its own
/// `requirementsDigest`. An applicant records it when it starts gathering; a
/// changed digest means the requirements changed.
///
/// # Errors
///
/// [`VettingError::Digest`] if the criterion cannot be canonicalised.
pub fn requirements_digest(criterion: &Value) -> Result<String, VettingError> {
    let mut criterion = criterion.clone();
    if let Some(map) = criterion.as_object_mut() {
        map.remove(REQUIREMENTS_DIGEST_MEMBER);
    }
    digest(&criterion)
}

/// One statement, reduced to what counting needs.
#[derive(Debug, Clone)]
pub struct StatementFacts {
    /// The statement `id`.
    pub statement_id: String,
    /// Who the vetter **is**, not which DID they used: the community passes its
    /// member id, a client passes the issuer DID. Two statements with the same
    /// value are one vetter (design D14).
    pub vetter: String,
    /// Method.
    pub method: VettingMethod,
    /// Claims the vetter verified.
    pub claims_verified: Vec<String>,
    /// Documentation the vetter relied on.
    pub document_classes: Vec<String>,
    /// Declared relationship.
    pub declared_relationship: DeclaredRelationship,
    /// Identity commitment.
    pub identity_commitment: String,
    /// `validFrom`.
    pub valid_from: DateTime<Utc>,
    /// The statement's community is the one evaluating.
    pub community_matches: bool,
    /// The vetter is eligible (held the role at issuance and still does, as
    /// far as the evaluator can tell).
    pub eligible: bool,
    /// A revocation notice exists.
    pub revoked: bool,
}

/// Why a statement did not count.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotCounted {
    /// The vetter is not an eligible vetter.
    NotEligible,
    /// The vetter withdrew it.
    Revoked,
    /// Issued for a different community.
    WrongCommunity,
    /// The method is not one the community accepts.
    MethodNotAccepted,
    /// The documentation is outside a floor the community set.
    DocumentationNotAccepted,
    /// A required claim was not verified.
    ClaimNotVerified(String),
    /// Older than `maxStatementAge`.
    TooOld,
    /// This vetter already has a statement that counts.
    SameVetter,
}

impl NotCounted {
    /// Stable code for facts and logs.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotEligible => "issuer-not-vetter",
            Self::Revoked => "revoked",
            Self::WrongCommunity => "wrong-community",
            Self::MethodNotAccepted => "method-not-accepted",
            Self::DocumentationNotAccepted => "documentation-not-accepted",
            Self::ClaimNotVerified(_) => "claim-not-verified",
            Self::TooOld => "too-old",
            Self::SameVetter => "same-vetter",
        }
    }
}

/// Something still missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Need {
    /// This many more statements from distinct eligible vetters.
    Statements(u32),
    /// This many more counted statements by `method`.
    Method(VettingMethod, u32),
}

impl Need {
    /// The `needs` string a verdict carries: `vetting:statements:<n>` or
    /// `vetting:method:<method>:<n>`. Verdict `needs` are strings on the wire,
    /// so this is their grammar.
    #[must_use]
    pub fn to_wire(self) -> String {
        match self {
            Self::Statements(n) => format!("vetting:statements:{n}"),
            Self::Method(method, n) => format!("vetting:method:{}:{n}", method.as_str()),
        }
    }

    /// Parse a `needs` string. `None` for strings that are not vetting needs,
    /// which a client shows verbatim.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.strip_prefix("vetting:")?;
        if let Some(n) = rest.strip_prefix("statements:") {
            return n.parse().ok().map(Self::Statements);
        }
        let (method, n) = rest.strip_prefix("method:")?.rsplit_once(':')?;
        Some(Self::Method(VettingMethod::parse(method)?, n.parse().ok()?))
    }
}

/// The outcome of counting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// Statement ids that count, one per vetter.
    pub counted: Vec<String>,
    /// Statement ids that do not, with every reason.
    pub not_counted: Vec<(String, Vec<NotCounted>)>,
    /// Counted statements by method.
    pub by_method: BTreeMap<VettingMethod, u32>,
    /// Counted statements by declared relationship.
    pub by_relationship: BTreeMap<DeclaredRelationship, u32>,
    /// All presented statements carry one identity commitment (or the
    /// requirements do not ask for consistency).
    pub commitments_consistent: bool,
    /// No relationship cap is exceeded.
    pub independence_ok: bool,
    /// What is still missing. Empty when the count and method floors are met.
    pub needs: Vec<Need>,
}

impl Evaluation {
    /// Distinct vetters counted.
    #[must_use]
    pub fn distinct_vetters(&self) -> usize {
        self.counted.len()
    }

    /// The count, method floors, commitment consistency and independence are
    /// all satisfied. For a community this is an input to policy, not the
    /// verdict.
    #[must_use]
    pub fn satisfied(&self) -> bool {
        self.needs.is_empty() && self.commitments_consistent && self.independence_ok
    }
}

/// Count `statements` against `requirements` at `now`.
///
/// Statements from the same vetter count once; the most recent eligible one is
/// the one kept. Requirements are assumed valid
/// ([`VettingRequirements::validate`]); an unparseable `maxStatementAge` is
/// read as the most restrictive interpretation, so nothing counts as young
/// enough.
#[must_use]
pub fn evaluate(
    requirements: &VettingRequirements,
    statements: &[StatementFacts],
    now: DateTime<Utc>,
) -> Evaluation {
    let max_age_declared = requirements.max_statement_age.is_some();
    let max_age = requirements.max_statement_age();

    let mut ordered: Vec<&StatementFacts> = statements.iter().collect();
    ordered.sort_by_key(|s| std::cmp::Reverse(s.valid_from));

    let mut counted = Vec::new();
    let mut not_counted = Vec::new();
    let mut vetters = BTreeSet::new();
    let mut by_method: BTreeMap<VettingMethod, u32> = BTreeMap::new();
    let mut by_relationship: BTreeMap<DeclaredRelationship, u32> = BTreeMap::new();

    for s in ordered {
        let mut reasons = Vec::new();
        if !s.eligible {
            reasons.push(NotCounted::NotEligible);
        }
        if s.revoked {
            reasons.push(NotCounted::Revoked);
        }
        if !s.community_matches {
            reasons.push(NotCounted::WrongCommunity);
        }
        if !requirements.accepted_methods.contains(&s.method) {
            reasons.push(NotCounted::MethodNotAccepted);
        }
        if let Some(floor) = &requirements.accepted_document_classes {
            let documented = s.document_classes.iter().any(|d| floor.contains(d));
            let exempt =
                s.method == VettingMethod::PriorAcquaintance && s.document_classes.is_empty();
            if !documented && !exempt {
                reasons.push(NotCounted::DocumentationNotAccepted);
            }
        }
        for claim in &requirements.required_claims {
            if !s.claims_verified.contains(claim) {
                reasons.push(NotCounted::ClaimNotVerified(claim.clone()));
            }
        }
        let too_old = match max_age {
            Some(age) => now - s.valid_from > age,
            None => max_age_declared,
        };
        if too_old {
            reasons.push(NotCounted::TooOld);
        }
        if reasons.is_empty() && vetters.contains(&s.vetter) {
            reasons.push(NotCounted::SameVetter);
        }

        if reasons.is_empty() {
            vetters.insert(s.vetter.clone());
            *by_method.entry(s.method).or_default() += 1;
            *by_relationship.entry(s.declared_relationship).or_default() += 1;
            counted.push(s.statement_id.clone());
        } else {
            not_counted.push((s.statement_id.clone(), reasons));
        }
    }

    let commitments_consistent = !requirements
        .independence
        .require_consistent_identity_commitment
        || statements
            .iter()
            .map(|s| s.identity_commitment.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            <= 1;

    let independence_ok = requirements
        .independence
        .max_by_declared_relationship
        .iter()
        .all(|(rel, max)| by_relationship.get(rel).copied().unwrap_or(0) <= *max);

    let mut needs = Vec::new();
    let have = u32::try_from(counted.len()).unwrap_or(u32::MAX);
    if have < requirements.min_statements {
        needs.push(Need::Statements(requirements.min_statements - have));
    }
    for (method, floor) in &requirements.min_by_method {
        let got = by_method.get(method).copied().unwrap_or(0);
        if got < *floor {
            needs.push(Need::Method(*method, floor - got));
        }
    }

    Evaluation {
        counted,
        not_counted,
        by_method,
        by_relationship,
        commitments_consistent,
        independence_ok,
        needs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::vetting::IDENTITY_VETTING_ENDORSEMENT_TYPE;
    use chrono::Duration;
    use serde_json::json;

    fn requirements() -> VettingRequirements {
        serde_json::from_value(json!({
            "version": "0.1",
            "statementType": IDENTITY_VETTING_ENDORSEMENT_TYPE,
            "minStatements": 2,
            "minByMethod": { "in-person": 1 },
            "acceptedMethods": ["in-person", "video", "prior-acquaintance"],
            "requiredClaims": ["name.legal"],
            "maxStatementAge": "P120D",
            "eligibleVetters": { "role": "vetter" },
            "independence": {
                "maxByDeclaredRelationship": { "family": 0, "same-employer": 1 },
                "requireConsistentIdentityCommitment": true
            }
        }))
        .unwrap()
    }

    fn fact(id: &str, vetter: &str, method: VettingMethod, age_days: i64) -> StatementFacts {
        StatementFacts {
            statement_id: id.into(),
            vetter: vetter.into(),
            method,
            claims_verified: vec!["name.legal".into()],
            document_classes: vec!["passport".into()],
            declared_relationship: DeclaredRelationship::None,
            identity_commitment: "zSame".into(),
            valid_from: Utc::now() - Duration::days(age_days),
            community_matches: true,
            eligible: true,
            revoked: false,
        }
    }

    #[test]
    fn two_distinct_vetters_with_one_in_person_satisfy() {
        let e = evaluate(
            &requirements(),
            &[
                fact("s1", "carol", VettingMethod::Video, 10),
                fact("s2", "dave", VettingMethod::InPerson, 3),
            ],
            Utc::now(),
        );
        assert_eq!(e.distinct_vetters(), 2);
        assert!(e.satisfied(), "{e:?}");
    }

    #[test]
    fn one_vetter_with_two_statements_counts_once() {
        let e = evaluate(
            &requirements(),
            &[
                fact("old", "carol", VettingMethod::InPerson, 30),
                fact("new", "carol", VettingMethod::InPerson, 1),
            ],
            Utc::now(),
        );
        assert_eq!(
            e.counted,
            vec!["new".to_string()],
            "the most recent is kept"
        );
        assert_eq!(e.not_counted[0].1, vec![NotCounted::SameVetter]);
        assert_eq!(e.needs, vec![Need::Statements(1)]);
    }

    #[test]
    fn a_method_floor_is_a_need_of_its_own() {
        let e = evaluate(
            &requirements(),
            &[
                fact("s1", "carol", VettingMethod::Video, 1),
                fact("s2", "dave", VettingMethod::Video, 1),
            ],
            Utc::now(),
        );
        assert_eq!(e.needs, vec![Need::Method(VettingMethod::InPerson, 1)]);
        assert_eq!(e.needs[0].to_wire(), "vetting:method:in-person:1");
    }

    #[test]
    fn ineligible_revoked_stale_and_foreign_statements_do_not_count() {
        let mut ineligible = fact("s1", "a", VettingMethod::InPerson, 1);
        ineligible.eligible = false;
        let mut revoked = fact("s2", "b", VettingMethod::InPerson, 1);
        revoked.revoked = true;
        let stale = fact("s3", "c", VettingMethod::InPerson, 200);
        let mut foreign = fact("s4", "d", VettingMethod::InPerson, 1);
        foreign.community_matches = false;
        let mut unverified = fact("s5", "e", VettingMethod::InPerson, 1);
        unverified.claims_verified.clear();

        let e = evaluate(
            &requirements(),
            &[ineligible, revoked, stale, foreign, unverified],
            Utc::now(),
        );
        assert!(e.counted.is_empty());
        let codes: BTreeSet<&str> = e
            .not_counted
            .iter()
            .flat_map(|(_, r)| r.iter().map(NotCounted::code))
            .collect();
        for code in [
            "issuer-not-vetter",
            "revoked",
            "too-old",
            "wrong-community",
            "claim-not-verified",
        ] {
            assert!(codes.contains(code), "missing {code} in {codes:?}");
        }
    }

    #[test]
    fn relationship_caps_are_independence_not_count() {
        let mut family = fact("s2", "dave", VettingMethod::InPerson, 1);
        family.declared_relationship = DeclaredRelationship::Family;
        let e = evaluate(
            &requirements(),
            &[fact("s1", "carol", VettingMethod::Video, 1), family],
            Utc::now(),
        );
        assert!(e.needs.is_empty());
        assert!(!e.independence_ok);
        assert!(!e.satisfied());
    }

    #[test]
    fn different_commitments_mean_different_identities() {
        let mut other = fact("s2", "dave", VettingMethod::InPerson, 1);
        other.identity_commitment = "zDifferent".into();
        let e = evaluate(
            &requirements(),
            &[fact("s1", "carol", VettingMethod::Video, 1), other],
            Utc::now(),
        );
        assert!(!e.commitments_consistent);
        assert!(!e.satisfied());
    }

    #[test]
    fn documentation_is_unconstrained_unless_the_community_sets_a_floor() {
        let mut known = fact("s1", "carol", VettingMethod::PriorAcquaintance, 1);
        known.document_classes.clear();
        let mut odd = fact("s2", "dave", VettingMethod::InPerson, 1);
        odd.document_classes = vec!["library-card".into()];

        let e = evaluate(&requirements(), &[known.clone(), odd.clone()], Utc::now());
        assert!(e.satisfied(), "each vetter decides (D16): {e:?}");

        let mut floored = requirements();
        floored.accepted_document_classes = Some(vec!["passport".into()]);
        let e = evaluate(&floored, &[known, odd], Utc::now());
        assert_eq!(
            e.counted,
            vec!["s1".to_string()],
            "prior acquaintance is exempt"
        );
    }

    #[test]
    fn an_unparseable_age_limit_counts_nothing() {
        let mut req = requirements();
        req.max_statement_age = Some("P1Y".into());
        let e = evaluate(
            &req,
            &[fact("s1", "carol", VettingMethod::InPerson, 0)],
            Utc::now(),
        );
        assert!(e.counted.is_empty());
    }

    #[test]
    fn needs_round_trip_through_their_wire_strings() {
        for need in [
            Need::Statements(3),
            Need::Method(VettingMethod::PriorAcquaintance, 1),
        ] {
            assert_eq!(Need::parse(&need.to_wire()), Some(need));
        }
        assert_eq!(Need::parse("vc:Endorsement"), None);
        assert_eq!(Need::parse("vetting:method:telepathy:1"), None);
    }

    #[test]
    fn the_digest_ignores_itself_and_tracks_everything_else() {
        let criterion = json!({ "id": "kernel", "vetting": { "minStatements": 2 } });
        let d = requirements_digest(&criterion).unwrap();
        let mut with_digest = criterion.clone();
        with_digest[REQUIREMENTS_DIGEST_MEMBER] = json!(d);
        assert_eq!(requirements_digest(&with_digest).unwrap(), d);

        let mut changed = criterion;
        changed["vetting"]["minStatements"] = json!(3);
        assert_ne!(requirements_digest(&changed).unwrap(), d);
    }
}
