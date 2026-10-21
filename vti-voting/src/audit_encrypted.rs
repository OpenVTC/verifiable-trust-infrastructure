//! Checks 3 – 5 of [`super::audit`] for a sealed or tallied-encrypted board (CONVENTIONS §9):
//! re-run the trustees' ceremony from their signed steps, re-admit every encrypted cast — attestation
//! over the encrypted form, and a tallied ballot's proofs — re-verify every partial decryption,
//! and recount from what they decrypt. Nothing the ballot box computed is taken on trust: each
//! `unsealed` and `spoiled` entry must be what the partials give.

use std::collections::{BTreeMap, HashMap};

use serde_json::Value;
use trust_tasks_rs::specs::voting::{
    ballot::cast::v0_1 as cast,
    election::register::v0_1::{Manifest, Question, SecrecyLevel},
};

use super::{AuditFailure, canonical};
use crate::{
    ballot_box::{BallotBox, MemoryNullifiers, Revote as BoxRevote},
    ceremony::{Ceremony, Decryption, Phase},
    rules,
    steps::{self, ProvenRequests},
    tally,
    trustees::{
        EncryptedQuestion, Sealed, Threshold, admitted_counts, open_with, question_ctx,
        tally as read_total, total, verify_vote,
    },
    voter::Cast,
    wire::{self, Target},
};

enum Form {
    Sealed(Box<Sealed>),
    Tallied(Vec<EncryptedQuestion>),
}

fn bad_step(index: u64, e: impl std::fmt::Display) -> AuditFailure {
    AuditFailure::CeremonyInvalid {
        index,
        reason: e.to_string(),
    }
}

fn idx(v: &Value, index: u64) -> Result<u32, AuditFailure> {
    v.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| bad_step(index, "a trustee index"))
}

/// What the ceremony's steps are read against.
pub(super) struct Steps<'a> {
    pub community: &'a str,
    pub ctx: Vec<u8>,
    pub proven: &'a ProvenRequests,
}

/// A ceremony replayed from the board's entries, one at a time.
struct Replay<'a> {
    ceremony: Ceremony,
    community: &'a str,
    election_id: &'a str,
    trustees: Vec<&'a str>,
    proven: &'a ProvenRequests,
}

impl<'a> Replay<'a> {
    fn new(manifest: &'a Manifest, s: &Steps<'a>) -> Result<Self, AuditFailure> {
        let trustees = manifest
            .trustees
            .as_ref()
            .ok_or_else(|| AuditFailure::Unreadable("no trustees".into()))?;
        let th = Threshold::new(
            u32::try_from(trustees.threshold).unwrap_or(0),
            u32::try_from(trustees.dids.len()).unwrap_or(0),
        )
        .map_err(|e| AuditFailure::Unreadable(e.to_string()))?;
        Ok(Self {
            ceremony: Ceremony::new(th, s.ctx.clone()),
            community: s.community,
            election_id: manifest.election_id.as_str(),
            trustees: trustees.dids.iter().map(|d| d.as_str()).collect(),
            proven: s.proven,
        })
    }

    /// Take `entry` if it is the ceremony's; whether it was.
    fn take(&mut self, index: u64, entry: &Value) -> Result<bool, AuditFailure> {
        match entry["kind"].as_str() {
            Some(steps::KIND) => {
                let request = &entry["request"];
                let signer = self
                    .proven
                    .signer(request)
                    .ok_or_else(|| bad_step(index, steps::StepError::Unproven))?;
                let election = steps::Election {
                    community: self.community,
                    election_id: self.election_id,
                    trustees: &self.trustees,
                };
                steps::read(request, election, signer)
                    .map_err(|e| bad_step(index, e))?
                    .apply(&mut self.ceremony)
                    .map_err(|e| bad_step(index, e))?;
            }
            Some(k) if steps::RETIRED_KINDS.contains(&k) => {
                return Err(bad_step(
                    index,
                    "a retired entry kind, which carries no proof",
                ));
            }
            Some("electionKey") => {
                if self.ceremony.phase() != Phase::Keyed {
                    self.ceremony.deadline();
                }
                if self.ceremony.key().map(wire::election_key_value).as_ref()
                    != Some(&entry["electionKey"])
                {
                    return Err(bad_step(index, "not the key the board's ceremony forms"));
                }
            }
            Some("opened") => {
                self.ceremony.deadline();
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

/// The key the board's ceremony formed, through its `electionKey` entry; `None` before it.
pub(super) fn formed_key(
    manifest: &Manifest,
    steps: Steps<'_>,
    entries: &[Value],
) -> Result<Option<Value>, AuditFailure> {
    let mut replay = Replay::new(manifest, &steps)?;
    for (i, entry) in entries.iter().enumerate() {
        replay.take(i as u64, entry)?;
        if entry["kind"] == "electionKey" {
            return Ok(Some(entry["electionKey"].clone()));
        }
    }
    Ok(None)
}

/// The counted ballots and their totals, from the board alone.
///
/// # Errors
/// The first entry that does not hold.
pub(super) fn recount<'a>(
    manifest: &Manifest,
    digest: &[u8; 32],
    steps: Steps<'_>,
    verifier: &BallotBox<MemoryNullifiers>,
    revote: BoxRevote,
    entries: &'a [Value],
) -> Result<(u64, Value, Option<&'a Value>), AuditFailure> {
    let ctx = steps.ctx.clone();
    let mut replay = Replay::new(manifest, &steps)?;
    let mut round: Option<Decryption<Target>> = None;
    let mut counted: HashMap<String, (u64, Form)> = HashMap::new();
    let mut owed: Option<(String, u64, u64)> = None;
    let mut opened: BTreeMap<u64, Option<Value>> = BTreeMap::new();
    let mut result_entry = None;

    for (i, entry) in entries.iter().enumerate() {
        let index = i as u64;
        if replay.take(index, entry)? {
            continue;
        }
        let ceremony = &replay.ceremony;
        match entry["kind"].as_str() {
            Some("encryptedCast") => {
                if let Some((_, _, by)) = owed {
                    return Err(AuditFailure::ReplacementInvalid {
                        index: by,
                        reason:
                            "a later cast under a counted tag is not followed by its replacement"
                                .into(),
                    });
                }
                let invalid = |reason: String| AuditFailure::CastInvalid { index, reason };
                let key = ceremony
                    .key()
                    .ok_or_else(|| invalid("cast before the election key formed".into()))?;
                let c = &entry["cast"];
                let (bound, form) = match (manifest.secrecy, c.get("sealed"), c.get("encrypted")) {
                    (SecrecyLevel::Sealed, Some(s), None) => (
                        s,
                        Form::Sealed(Box::new(
                            wire::sealed(s).map_err(|e| invalid(e.to_string()))?,
                        )),
                    ),
                    (SecrecyLevel::TalliedEncrypted, None, Some(enc)) => {
                        let qs =
                            check_tallied(manifest, digest, &ctx, key, enc).map_err(invalid)?;
                        (enc, Form::Tallied(qs))
                    }
                    _ => return Err(invalid("not this election's form of cast".into())),
                };
                let attestation =
                    vti_vetting_pcs::scheme::dec(c["attestation"].as_str().unwrap_or_default())
                        .map_err(|err| invalid(format!("attestation: {err}")))?;
                let tag = verifier
                    .verify(&Cast { attestation }, &canonical(bound)?)
                    .map_err(|err| invalid(err.to_string()))?;
                if c["tag"].as_str() != Some(tag.as_str()) {
                    return Err(invalid("the tag is not the attestation's".into()));
                }
                match counted.get(&tag) {
                    None => {
                        counted.insert(tag, (index, form));
                    }
                    Some(_) if revote == BoxRevote::Refuse => {
                        return Err(AuditFailure::TagRepeated { index });
                    }
                    Some((earlier, _)) => {
                        owed = Some((tag.clone(), *earlier, index));
                        counted.insert(tag, (index, form));
                    }
                }
            }
            Some("replaced") => {
                let bad = |reason: &str| AuditFailure::ReplacementInvalid {
                    index,
                    reason: reason.into(),
                };
                let Some((tag, earlier, by)) = owed.take() else {
                    return Err(bad("no cast is waiting to be replaced"));
                };
                if entry["tag"].as_str() != Some(tag.as_str())
                    || entry["replaces"].as_u64() != Some(earlier)
                    || entry["by"].as_u64() != Some(by)
                {
                    return Err(bad("it names other casts than the two under its tag"));
                }
            }
            Some("closed" | "closedEarly") => {
                if let Some(key) = ceremony.key().cloned() {
                    round = Some(Decryption::new(
                        key,
                        ctx.clone(),
                        targets(manifest, &counted),
                    ));
                }
            }
            Some("partials") => {
                let trustee = idx(&entry["trustee"], index)?;
                let parts = entry["partials"]
                    .as_array()
                    .ok_or_else(|| bad_step(index, "partials"))?
                    .iter()
                    .map(|p| wire::partial(p, trustee))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| bad_step(index, e))?;
                round
                    .as_mut()
                    .ok_or_else(|| bad_step(index, "partials before close"))?
                    .accept(trustee, parts)
                    .map_err(|e| bad_step(index, e))?;
            }
            Some("unsealed") => {
                opened.insert(
                    entry["leafIndex"].as_u64().unwrap_or(u64::MAX),
                    Some(entry["ballot"].clone()),
                );
            }
            Some("spoiled") => {
                opened.insert(entry["leafIndex"].as_u64().unwrap_or(u64::MAX), None);
            }
            Some("result") => result_entry = Some(entry),
            _ => {}
        }
    }
    if let Some((_, _, by)) = owed {
        return Err(AuditFailure::ReplacementInvalid {
            index: by,
            reason: "a later cast under a counted tag is not followed by its replacement".into(),
        });
    }

    let Some(round) = round.filter(|r| r.complete() || r.targets().is_empty()) else {
        return Err(AuditFailure::ResultMismatch(
            "the board holds no complete decryption".into(),
        ));
    };
    let plaintexts = if round.targets().is_empty() {
        Vec::new()
    } else {
        round
            .plaintexts()
            .map_err(|e| AuditFailure::ResultMismatch(e.to_string()))?
    };
    let n = counted.len() as u64;
    if manifest.secrecy == SecrecyLevel::Sealed {
        let by_leaf: HashMap<u64, &Sealed> = counted
            .values()
            .filter_map(|(i, f)| match f {
                Form::Sealed(s) => Some((*i, s.as_ref())),
                Form::Tallied(_) => None,
            })
            .collect();
        let mut ballots = Vec::new();
        for (t, r_elem) in plaintexts {
            let Target::Leaf(leaf) = t else { continue };
            let valid = open_with(&r_elem, by_leaf[&leaf], &ctx)
                .ok()
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                .and_then(|v| {
                    let b: cast::Ballot = serde_json::from_value(v.clone()).ok()?;
                    rules::check_ballot(manifest, digest, &b).ok()?;
                    Some((v, b))
                });
            match (valid, opened.get(&leaf)) {
                (Some((v, b)), Some(Some(said))) if *said == v => ballots.push(b),
                (None, Some(None)) => {}
                _ => {
                    return Err(AuditFailure::ResultMismatch(format!(
                        "the board's opening of the cast at {leaf} is not what its partials give"
                    )));
                }
            }
        }
        let (counted_n, rows) = tally::tally(manifest, ballots.iter(), false)
            .map_err(|e| AuditFailure::Unreadable(e.to_string()))?;
        let rows =
            serde_json::to_value(rows).map_err(|e| AuditFailure::Unreadable(e.to_string()))?;
        return Ok((counted_n, rows, result_entry));
    }
    let mut totals: HashMap<(String, String), u64> = HashMap::new();
    for (t, m) in &plaintexts {
        if let Target::Option { question, option } = t {
            let c = read_total(m, n).map_err(|e| AuditFailure::ResultMismatch(e.to_string()))?;
            totals.insert((question.clone(), option.clone()), c);
        }
    }
    let rows = tally::tallied_rows(
        manifest,
        |q, o| {
            totals
                .get(&(q.to_string(), o.to_string()))
                .copied()
                .or((n == 0).then_some(0))
        },
        n,
    )
    .map_err(|e| AuditFailure::Unreadable(e.to_string()))?;
    Ok((n, Value::Array(rows), result_entry))
}

/// The decryption targets once voting closes, as the ballot box fixes them (CONVENTIONS §9.7).
fn targets(
    manifest: &Manifest,
    counted: &HashMap<String, (u64, Form)>,
) -> Vec<(Target, crate::trustees::Ciphertext)> {
    // No casts, nothing to decrypt: every total is zero (and the identity, which no wire form
    // carries).
    if counted.is_empty() {
        return Vec::new();
    }
    let mut by_leaf: Vec<&(u64, Form)> = counted.values().collect();
    by_leaf.sort_by_key(|(i, _)| *i);
    let mut out = Vec::new();
    if manifest.secrecy == SecrecyLevel::Sealed {
        for (i, f) in by_leaf {
            if let Form::Sealed(s) = f {
                out.push((Target::Leaf(*i), s.kem));
            }
        }
        return out;
    }
    for (qi, q) in manifest.questions.iter().enumerate() {
        let Some(qkey) = rules::key(q) else { continue };
        for (oi, okey) in rules::option_keys(q).iter().enumerate() {
            let sum = total(by_leaf.iter().filter_map(|(_, f)| match f {
                Form::Tallied(qs) => qs.get(qi).and_then(|q| q.options.get(oi)).map(|o| o.0),
                Form::Sealed(_) => None,
            }));
            out.push((
                Target::Option {
                    question: qkey.to_string(),
                    option: (*okey).to_string(),
                },
                sum,
            ));
        }
    }
    out
}

/// CONVENTIONS §9.5, as the ballot box checks it.
fn check_tallied(
    manifest: &Manifest,
    digest: &[u8; 32],
    ctx: &[u8],
    key: &crate::trustees::ElectionKey,
    enc: &Value,
) -> Result<Vec<EncryptedQuestion>, String> {
    if enc["electionId"].as_str() != Some(manifest.election_id.as_str())
        || rules::digest_from_multibase(enc["manifestDigest"].as_str().unwrap_or_default())
            != Some(*digest)
    {
        return Err("another election's ballot".into());
    }
    let given = enc["questions"].as_array().map_or(&[][..], Vec::as_slice);
    if given.len() != manifest.questions.len() {
        return Err("not one encrypted question per manifest question".into());
    }
    let mut out = Vec::with_capacity(given.len());
    for (q, v) in manifest.questions.iter().zip(given) {
        let Question::Choice {
            min_selections,
            max_selections,
            optional,
            options,
            ..
        } = q
        else {
            return Err("a tallied-encrypted election asks choices only".into());
        };
        let qkey = rules::key(q).unwrap_or_default();
        let (named, eq) = wire::encrypted_question(v).map_err(|e| e.to_string())?;
        if named != qkey {
            return Err(format!("question {named} is not {qkey}"));
        }
        let counts = admitted_counts(
            options.len(),
            *min_selections,
            max_selections.get(),
            *optional,
        )
        .map_err(|e| e.to_string())?;
        verify_vote(key, &eq, options.len(), &counts, &question_ctx(ctx, qkey))
            .map_err(|e| e.to_string())?;
        out.push(eq);
    }
    Ok(out)
}
