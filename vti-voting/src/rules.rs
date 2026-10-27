//! What a manifest must say and what a ballot may answer: the rules JSON Schema cannot state,
//! as checks over the generated wire types.
//!
//! The schema already holds every shape; these hold the relations between fields — that a
//! manifest's times are in order, that a choice's bounds fit its options, that a ballot answers
//! each question exactly once and only as its question admits. A ballot box runs
//! [`check_manifest`] at registration and [`check_ballot`] before the pairing check of every
//! cast (VTI-VOT-045); a VTA runs [`check_ballot`] before it builds a cast (VTI-VOT-032).
//!
//! Received JSON is read against the schema before it is parsed into these types; the
//! cross-field rules here assume a document that already passed it.

use std::collections::HashSet;

use sha2::{Digest, Sha256};
use trust_tasks_rs::specs::voting::{
    ballot::cast::v0_1::{Answer, Ballot},
    election::register::v0_1::{Manifest, Question, RollRuleRule, SecrecyLevel},
};

/// A broken rule. Each variant is one error local part of the voting families.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RuleError {
    /// `invalidManifest`.
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    /// `unsupportedSecrecy`: version 0.1 serves open elections only.
    #[error("secrecy level {0} is not served by this version")]
    UnsupportedSecrecy(String),
    /// `manifestMismatch`.
    #[error("the ballot names another election or manifest")]
    ManifestMismatch,
    /// `ballotInvalid`.
    #[error("invalid ballot: {0}")]
    BallotInvalid(String),
    #[error("serialization: {0}")]
    Serialization(String),
}

/// SHA-256 of the manifest's RFC 8785 (JCS) canonicalization, over the JSON as received.
///
/// # Errors
/// [`RuleError::Serialization`] if the value cannot be canonicalized.
pub fn manifest_digest(manifest: &serde_json::Value) -> Result<[u8; 32], RuleError> {
    let jcs = serde_json_canonicalizer::to_vec(manifest)
        .map_err(|e| RuleError::Serialization(e.to_string()))?;
    Ok(Sha256::digest(jcs).into())
}

/// A SHA-256 digest as the wire carries it: a multihash (`0x12 0x20 ‖ digest`), multibase
/// base58btc.
pub fn digest_multibase(digest: &[u8; 32]) -> String {
    let mut mh = Vec::with_capacity(34);
    mh.extend([0x12, 0x20]);
    mh.extend(digest);
    multibase::encode(multibase::Base::Base58Btc, mh)
}

/// The raw digest of a [`digest_multibase`] value, if it is one.
pub fn digest_from_multibase(text: &str) -> Option<[u8; 32]> {
    let (_, bytes) = multibase::decode(text).ok()?;
    match bytes.as_slice() {
        [0x12, 0x20, rest @ ..] => rest.try_into().ok(),
        _ => None,
    }
}

/// The question's key, or `None` for a question type this version does not know: the
/// generated enum grows with the specification, and an unknown type is refused, never guessed.
pub(crate) fn key(q: &Question) -> Option<&str> {
    match q {
        Question::Choice { key, .. }
        | Question::Ranking { key, .. }
        | Question::Score { key, .. }
        | Question::Text { key, .. } => Some(key.as_str()),
        _ => None,
    }
}

fn optional(q: &Question) -> bool {
    match q {
        Question::Choice { optional, .. }
        | Question::Ranking { optional, .. }
        | Question::Score { optional, .. }
        | Question::Text { optional, .. } => *optional,
        _ => false,
    }
}

pub(crate) fn option_keys(q: &Question) -> Vec<&str> {
    match q {
        Question::Choice { options, .. }
        | Question::Ranking { options, .. }
        | Question::Score { options, .. } => options.iter().map(|o| o.key.as_str()).collect(),
        _ => Vec::new(),
    }
}

fn bad_manifest(why: impl Into<String>) -> RuleError {
    RuleError::InvalidManifest(why.into())
}

/// The most trustees an election may have (`TrusteeIndex` runs 1..=64).
pub const MAX_TRUSTEES: usize = 64;

/// The trustee rules of a sealed or tallied-encrypted manifest (VTI-VOT-060 – 064): trustees
/// named, `2 <= threshold <= n <= 64`, neither the community nor the ballot box among them, no
/// running totals, and — tallied-encrypted — choice questions only.
fn check_trustees(m: &Manifest) -> Result<(), RuleError> {
    let Some(t) = &m.trustees else {
        return Err(bad_manifest(
            "a sealed or tallied-encrypted election names its trustees",
        ));
    };
    let n = t.dids.len();
    if n > MAX_TRUSTEES {
        return Err(bad_manifest(format!(
            "at most {MAX_TRUSTEES} trustees, not {n}"
        )));
    }
    if t.threshold < 2 || t.threshold > n as i64 {
        return Err(bad_manifest(
            "the trustees' threshold must satisfy 2 <= threshold <= trustees",
        ));
    }
    if t.dids
        .iter()
        .map(|d| d.as_str())
        .collect::<HashSet<_>>()
        .len()
        != n
    {
        return Err(bad_manifest("a trustee is named twice"));
    }
    if t.dids
        .iter()
        .any(|d| d.as_str() == m.community.as_str() || d.as_str() == m.ballot_box.as_str())
    {
        return Err(bad_manifest(
            "neither the community nor the ballot box is a trustee",
        ));
    }
    if m.results_before_close {
        return Err(bad_manifest(
            "running totals are an open election's alone (VTI-VOT-061)",
        ));
    }
    if m.secrecy == SecrecyLevel::TalliedEncrypted
        && m.questions
            .iter()
            .any(|q| !matches!(q, Question::Choice { .. }))
    {
        return Err(bad_manifest(
            "a tallied-encrypted election asks choice questions only (VTI-VOT-064)",
        ));
    }
    Ok(())
}

/// The secrecy levels served: all three. The encrypted levels are served end to end — the
/// trustees' ceremony and encrypted casts at the ballot box ([`crate::service`]), their
/// certification ([`crate::audit`]) — so a ballot box registers them and a VTC creates them.
/// `unsupportedSecrecy` remains for a level a service built from this crate would not serve.
pub const SERVED_LEVELS: &[SecrecyLevel] = &[
    SecrecyLevel::Open,
    SecrecyLevel::Sealed,
    SecrecyLevel::TalliedEncrypted,
];

/// A manifest's cross-field rules (VTI-VOT-010), as a ballot box checks it at registration and
/// a VTC at creation. `ballot_box` is the checking service's own DID, when it is one.
///
/// # Errors
/// [`RuleError::UnsupportedSecrecy`] for a level not in [`SERVED_LEVELS`]; otherwise
/// [`RuleError::InvalidManifest`] naming the first rule broken.
pub fn check_manifest(m: &Manifest, ballot_box: Option<&str>) -> Result<(), RuleError> {
    check_manifest_serving(m, ballot_box, SERVED_LEVELS)
}

/// [`check_manifest`] for a service serving `served`.
///
/// # Errors
/// As [`check_manifest`].
pub fn check_manifest_serving(
    m: &Manifest,
    ballot_box: Option<&str>,
    served: &[SecrecyLevel],
) -> Result<(), RuleError> {
    if !served.contains(&m.secrecy) {
        return Err(RuleError::UnsupportedSecrecy(m.secrecy.to_string()));
    }
    if m.secrecy == SecrecyLevel::Open {
        if m.trustees.is_some() {
            return Err(bad_manifest("an open election has no trustees"));
        }
    } else {
        check_trustees(m)?;
    }
    if !(m.registration_opens <= m.voting_opens && m.voting_opens < m.voting_closes) {
        return Err(bad_manifest(
            "the times must satisfy registrationOpens <= votingOpens < votingCloses",
        ));
    }
    if let Some(own) = ballot_box
        && m.ballot_box.as_str() != own
    {
        return Err(bad_manifest("ballotBox names another service"));
    }
    if m.text_release_threshold < 10 {
        return Err(bad_manifest("textReleaseThreshold must be at least 10"));
    }
    let listed = m.roll.listed.as_ref().map_or(0, Vec::len);
    match m.roll.rule {
        RollRuleRule::Listed | RollRuleRule::MembersAndListed if listed == 0 => {
            return Err(bad_manifest(
                "a roll that lists parties must list at least one",
            ));
        }
        RollRuleRule::Members if listed != 0 => {
            return Err(bad_manifest("a members-only roll lists nobody"));
        }
        _ => {}
    }
    if m.board
        .auditors
        .iter()
        .any(|a| a.as_str() == m.community.as_str() || a.as_str() == m.ballot_box.as_str())
    {
        return Err(bad_manifest(
            "neither the community nor the ballot box audits its own election",
        ));
    }
    let mut seen = HashSet::new();
    for q in &m.questions {
        let Some(k) = key(q) else {
            return Err(bad_manifest(
                "a question of a type this version does not serve",
            ));
        };
        if !seen.insert(k) {
            return Err(bad_manifest(format!("question key {k} repeats")));
        }
        let opts = option_keys(q);
        if opts.iter().collect::<HashSet<_>>().len() != opts.len() {
            return Err(bad_manifest(format!("question {k} repeats an option key")));
        }
        match q {
            Question::Choice {
                min_selections,
                max_selections,
                options,
                ..
            } => {
                let max = max_selections.get();
                if *min_selections > max || max > options.len() as u64 {
                    return Err(bad_manifest(format!(
                        "question {k}: minSelections <= maxSelections <= options"
                    )));
                }
            }
            Question::Score { min, max, .. } if min >= max => {
                return Err(bad_manifest(format!("question {k}: min < max")));
            }
            _ => {}
        }
    }
    Ok(())
}

fn bad_ballot(why: impl Into<String>) -> RuleError {
    RuleError::BallotInvalid(why.into())
}

/// How many answer members an answer carries. Exactly one is admitted; the schema states it as
/// `minProperties`/`maxProperties`, which the generated type cannot.
fn members(a: &Answer) -> usize {
    usize::from(a.choice.is_some())
        + usize::from(a.ranking.is_some())
        + usize::from(!a.scores.is_empty())
        + usize::from(a.text.is_some())
        + usize::from(a.abstain.is_some())
}

/// A ballot against the manifest it was cast under (VTI-VOT-032, VTI-VOT-045).
/// `manifest_digest` is the registered manifest's.
///
/// # Errors
/// [`RuleError::ManifestMismatch`] if the ballot names another election or manifest;
/// [`RuleError::BallotInvalid`] naming the first rule broken.
pub fn check_ballot(m: &Manifest, manifest_digest: &[u8; 32], b: &Ballot) -> Result<(), RuleError> {
    if b.election_id.as_str() != m.election_id.as_str()
        || digest_from_multibase(b.manifest_digest.as_str()).as_ref() != Some(manifest_digest)
    {
        return Err(RuleError::ManifestMismatch);
    }
    let mut answered = HashSet::new();
    for a in &b.answers {
        let qkey = a.question.as_str();
        let Some(q) = m.questions.iter().find(|q| key(q) == Some(qkey)) else {
            return Err(bad_ballot(format!("no question {qkey}")));
        };
        if !answered.insert(qkey) {
            return Err(bad_ballot(format!("question {qkey} answered twice")));
        }
        if members(a) != 1 {
            return Err(bad_ballot(format!(
                "question {qkey}: exactly one answer member"
            )));
        }
        if a.abstain.is_some() {
            if a.abstain != Some(serde_json::Value::Bool(true)) {
                return Err(bad_ballot(format!("question {qkey}: abstain is true")));
            }
            if !optional(q) {
                return Err(bad_ballot(format!(
                    "question {qkey} may not be left unanswered"
                )));
            }
            continue;
        }
        let opts: HashSet<&str> = option_keys(q).into_iter().collect();
        match q {
            Question::Choice {
                min_selections,
                max_selections,
                ..
            } => {
                let Some(choice) = &a.choice else {
                    return Err(bad_ballot(format!("question {qkey} takes a choice")));
                };
                let n = choice.len() as u64;
                if n < *min_selections || n > max_selections.get() {
                    return Err(bad_ballot(format!("question {qkey}: selection count")));
                }
                if choice.iter().collect::<HashSet<_>>().len() != choice.len()
                    || choice.iter().any(|k| !opts.contains(k.as_str()))
                {
                    return Err(bad_ballot(format!(
                        "question {qkey}: unknown or repeated option"
                    )));
                }
            }
            Question::Ranking { partial, .. } => {
                let Some(ranking) = &a.ranking else {
                    return Err(bad_ballot(format!("question {qkey} takes a ranking")));
                };
                let distinct = ranking.iter().collect::<HashSet<_>>().len() == ranking.len();
                let known = ranking.iter().all(|k| opts.contains(k.as_str()));
                let complete = if *partial {
                    !ranking.is_empty()
                } else {
                    ranking.len() == opts.len()
                };
                if !(distinct && known && complete) {
                    return Err(bad_ballot(format!("question {qkey}: ranking")));
                }
            }
            Question::Score { min, max, .. } => {
                let scored: HashSet<&str> = a.scores.keys().map(|k| k.as_str()).collect();
                if scored != opts {
                    return Err(bad_ballot(format!("question {qkey}: score every option")));
                }
                if a.scores.values().any(|v| v < min || v > max) {
                    return Err(bad_ballot(format!("question {qkey}: score out of bounds")));
                }
            }
            Question::Text { max_length, .. } => {
                let Some(text) = &a.text else {
                    return Err(bad_ballot(format!("question {qkey} takes text")));
                };
                if text.as_str().chars().count() as u64 > max_length.get() {
                    return Err(bad_ballot(format!("question {qkey}: text too long")));
                }
            }
            _ => return Err(bad_ballot(format!("question {qkey}: unsupported type"))),
        }
    }
    if let Some(q) = m
        .questions
        .iter()
        .find(|q| key(q).is_none_or(|k| !answered.contains(k)))
    {
        return Err(bad_ballot(format!(
            "question {} unanswered (an optional question is answered with abstain)",
            key(q).unwrap_or("?")
        )));
    }
    Ok(())
}
