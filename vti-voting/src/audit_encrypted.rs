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
    board::Board,
    ceremony::{Ceremony, Decryption, Phase},
    rules,
    steps::{self, ProvenRequests},
    tally,
    trustees::{
        EncryptedQuestion, Sealed, Threshold, admitted_counts, cast_ctx, open_with, question_ctx,
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

/// The decryption a closed board calls for: the closing entry, and the targets the counted casts
/// give (CONVENTIONS §9.7) — what a community authorizes.
#[derive(Debug, Clone)]
pub struct Closing {
    /// The closing entry's index on the board.
    pub index: u64,
    /// Its `at`, as the board carries it.
    pub at: String,
    /// The targets, in the order CONVENTIONS §9.7 fixes.
    pub targets: Vec<(Target, crate::trustees::Ciphertext)>,
}

impl Closing {
    /// The targets as the wire carries them (`DecryptionTarget`), in order.
    pub fn target_values(&self) -> Vec<Value> {
        self.targets
            .iter()
            .map(|(t, ct)| wire::target_value(t, ct))
            .collect()
    }
}

/// SHA-256 over the JCS of a target list, as a multihash: what an authorization pins.
///
/// # Errors
/// [`AuditFailure::Unreadable`] if it cannot be canonicalized.
pub fn targets_digest(targets: &[Value]) -> Result<String, AuditFailure> {
    use sha2::{Digest, Sha256};
    Ok(rules::digest_multibase(
        &Sha256::digest(canonical(&Value::Array(targets.to_vec()))?).into(),
    ))
}

/// One pass over an encrypted board: the ceremony, the casts, and — once closed — the
/// decryption, each entry held to everything before it.
struct Recount<'a> {
    manifest: &'a Manifest,
    digest: &'a [u8; 32],
    ctx: Vec<u8>,
    verifier: &'a BallotBox<MemoryNullifiers>,
    revote: BoxRevote,
    replay: Replay<'a>,
    /// Tag → (index of the counted cast, its form, the digest of its JCS form).
    counted: HashMap<String, (u64, Form, [u8; 32])>,
    /// A later cast under a counted tag, still owed its `replaced` entry.
    owed: Option<(String, u64, u64)>,
    /// Every ciphertext's compressed `a`, with the tag it was cast under.
    seen: HashMap<[u8; 32], String>,
    closing: Option<Closing>,
    authorized: bool,
    round: Option<Decryption<Target>>,
    opened: BTreeMap<u64, Option<Value>>,
}

fn cast_failure(index: u64) -> impl Fn(String) -> AuditFailure {
    move |reason| AuditFailure::CastInvalid { index, reason }
}

impl<'a> Recount<'a> {
    fn new(
        manifest: &'a Manifest,
        digest: &'a [u8; 32],
        steps: &Steps<'a>,
        verifier: &'a BallotBox<MemoryNullifiers>,
        revote: BoxRevote,
    ) -> Result<Self, AuditFailure> {
        Ok(Self {
            manifest,
            digest,
            ctx: steps.ctx.clone(),
            verifier,
            revote,
            replay: Replay::new(manifest, steps)?,
            counted: HashMap::new(),
            owed: None,
            seen: HashMap::new(),
            closing: None,
            authorized: false,
            round: None,
            opened: BTreeMap::new(),
        })
    }

    fn owed_failure(by: u64) -> AuditFailure {
        AuditFailure::ReplacementInvalid {
            index: by,
            reason: "a later cast under a counted tag is not followed by its replacement".into(),
        }
    }

    /// Take one entry; `board` is the board's tree, for an authorization's head.
    fn take(&mut self, index: u64, entry: &Value, board: &Board) -> Result<(), AuditFailure> {
        if self.replay.take(index, entry)? {
            return Ok(());
        }
        match entry["kind"].as_str() {
            Some("encryptedCast") => self.cast(index, &entry["cast"])?,
            Some("replaced") => {
                let bad = |reason: &str| AuditFailure::ReplacementInvalid {
                    index,
                    reason: reason.into(),
                };
                let Some((tag, earlier, by)) = self.owed.take() else {
                    return Err(bad("no cast is waiting to be replaced"));
                };
                if entry["tag"].as_str() != Some(tag.as_str())
                    || entry["replaces"].as_u64() != Some(earlier)
                    || entry["by"].as_u64() != Some(by)
                {
                    return Err(bad("it names other casts than the two under its tag"));
                }
            }
            Some(kind @ ("closed" | "closedEarly")) => {
                if let Some((_, _, by)) = self.owed {
                    return Err(Self::owed_failure(by));
                }
                let _ = kind;
                let targets = targets(self.manifest, &self.counted);
                if let Some(key) = self.replay.ceremony.key().cloned() {
                    self.round = Some(Decryption::new(key, self.ctx.clone(), targets.clone()));
                }
                self.closing = Some(Closing {
                    index,
                    at: entry["at"].as_str().unwrap_or_default().to_string(),
                    targets,
                });
            }
            Some("decryptionAuthorized") => self.authorization(index, &entry["request"], board)?,
            Some("partials") => {
                if !self.authorized {
                    return Err(bad_step(
                        index,
                        "partials before the community authorized the decryption",
                    ));
                }
                let trustee = idx(&entry["trustee"], index)?;
                let parts = entry["partials"]
                    .as_array()
                    .ok_or_else(|| bad_step(index, "partials"))?
                    .iter()
                    .map(|p| wire::partial(p, trustee))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| bad_step(index, e))?;
                self.round
                    .as_mut()
                    .ok_or_else(|| bad_step(index, "partials before close"))?
                    .accept(trustee, parts)
                    .map_err(|e| bad_step(index, e))?;
            }
            Some("unsealed") => {
                self.opened.insert(
                    entry["leafIndex"].as_u64().unwrap_or(u64::MAX),
                    Some(entry["ballot"].clone()),
                );
            }
            Some("spoiled") => {
                self.opened
                    .insert(entry["leafIndex"].as_u64().unwrap_or(u64::MAX), None);
            }
            _ => {}
        }
        Ok(())
    }

    /// An encrypted cast, re-admitted as the ballot box must have admitted it.
    fn cast(&mut self, index: u64, c: &Value) -> Result<(), AuditFailure> {
        let invalid = cast_failure(index);
        if let Some((_, _, by)) = self.owed {
            return Err(Self::owed_failure(by));
        }
        if self.closing.is_some() {
            return Err(invalid("cast after voting closed".into()));
        }
        let key = self
            .replay
            .ceremony
            .key()
            .cloned()
            .ok_or_else(|| invalid("cast before the election key formed".into()))?;
        let bound = match (self.manifest.secrecy, c.get("sealed"), c.get("encrypted")) {
            (SecrecyLevel::Sealed, Some(s), None) => s,
            (SecrecyLevel::TalliedEncrypted, None, Some(enc)) => enc,
            _ => return Err(invalid("not this election's form of cast".into())),
        };
        let bound_bytes = canonical(bound)?;
        let attestation =
            vti_vetting_pcs::scheme::dec(c["attestation"].as_str().unwrap_or_default())
                .map_err(|err| invalid(format!("attestation: {err}")))?;
        let tag = self
            .verifier
            .verify(&Cast { attestation }, &bound_bytes)
            .map_err(|err| invalid(err.to_string()))?;
        if c["tag"].as_str() != Some(tag.as_str()) {
            return Err(invalid("the tag is not the attestation's".into()));
        }
        // The form is bound to this cast's tag (CONVENTIONS §9.3, §9.4).
        let form = match self.manifest.secrecy {
            SecrecyLevel::Sealed => Form::Sealed(Box::new(
                wire::sealed(bound).map_err(|e| invalid(e.to_string()))?,
            )),
            _ => Form::Tallied(
                check_tallied(
                    self.manifest,
                    self.digest,
                    &cast_ctx(&self.ctx, &tag),
                    &key,
                    bound,
                )
                .map_err(&invalid)?,
            ),
        };
        let keys = ciphertext_keys(&form);
        if keys
            .iter()
            .any(|a| self.seen.get(a).is_some_and(|t| *t != tag))
        {
            return Err(invalid(
                "its ciphertexts are another cast's: a copied ballot".into(),
            ));
        }
        for a in keys {
            self.seen.insert(a, tag.clone());
        }
        use sha2::{Digest, Sha256};
        let form_digest: [u8; 32] = Sha256::digest(&bound_bytes).into();
        match self.counted.get(&tag) {
            None => {
                self.counted.insert(tag, (index, form, form_digest));
            }
            Some(_) if self.revote == BoxRevote::Refuse => {
                return Err(AuditFailure::TagRepeated { index });
            }
            Some((earlier, _, held)) => {
                if *held == form_digest {
                    return Err(AuditFailure::ReplacementInvalid {
                        index,
                        reason: "a replacement must carry another ballot".into(),
                    });
                }
                self.owed = Some((tag.clone(), *earlier, index));
                self.counted.insert(tag, (index, form, form_digest));
            }
        }
        Ok(())
    }

    /// The community's `decryptionAuthorized` entry (CONVENTIONS §9.7): its own, for this
    /// election, after the close, pinning exactly the targets the board gives under the board
    /// through the closing entry.
    fn authorization(
        &mut self,
        index: u64,
        request: &Value,
        board: &Board,
    ) -> Result<(), AuditFailure> {
        let bad = |why: &str| bad_step(index, format!("decryption authorization: {why}"));
        let community = self.manifest.community.as_str();
        if self.replay.proven.signer(request) != Some(community)
            || request["issuer"].as_str() != Some(community)
        {
            return Err(bad("not the community's"));
        }
        let Some(closing) = &self.closing else {
            return Err(bad("before voting closed"));
        };
        let p = &request["payload"];
        let size = closing.index + 1;
        let root = board
            .root(usize::try_from(size).unwrap_or(usize::MAX))
            .ok()
            .map(|r| rules::digest_multibase(&r));
        let values = closing.target_values();
        let holds = p["community"].as_str() == Some(community)
            && p["electionId"].as_str() == Some(self.manifest.election_id.as_str())
            && p["manifestDigest"].as_str() == Some(rules::digest_multibase(self.digest).as_str())
            && p["head"]["treeSize"].as_u64() == Some(size)
            && p["head"]["rootHash"].as_str() == root.as_deref()
            && p["closedAt"].as_str() == Some(closing.at.as_str())
            && p["targetCount"].as_u64() == Some(values.len() as u64)
            && p["targetsDigest"].as_str() == Some(targets_digest(&values)?.as_str());
        if !holds {
            return Err(bad("it does not pin the targets the closed board gives"));
        }
        if self.authorized {
            return Err(bad("a second authorization"));
        }
        self.authorized = true;
        Ok(())
    }
}

/// The closed board's decryption, for the community to authorize (CONVENTIONS §9.7): every entry
/// through the closing one held as certification holds it, and the targets the counted casts
/// give. `None` while the board has not closed.
///
/// # Errors
/// The first entry that does not hold.
pub(super) fn closing(
    manifest: &Manifest,
    digest: &[u8; 32],
    steps: Steps<'_>,
    verifier: &BallotBox<MemoryNullifiers>,
    revote: BoxRevote,
    entries: &[Value],
    board: &Board,
) -> Result<Option<Closing>, AuditFailure> {
    let mut r = Recount::new(manifest, digest, &steps, verifier, revote)?;
    for (i, entry) in entries.iter().enumerate() {
        r.take(i as u64, entry, board)?;
        if r.closing.is_some() {
            return Ok(r.closing);
        }
    }
    Ok(None)
}

/// The counted ballots and their totals, from the board alone.
///
/// # Errors
/// The first entry that does not hold.
pub(super) fn recount(
    manifest: &Manifest,
    digest: &[u8; 32],
    steps: Steps<'_>,
    verifier: &BallotBox<MemoryNullifiers>,
    revote: BoxRevote,
    entries: &[Value],
    board: &Board,
) -> Result<(u64, Value), AuditFailure> {
    let mut r = Recount::new(manifest, digest, &steps, verifier, revote)?;
    for (i, entry) in entries.iter().enumerate() {
        r.take(i as u64, entry, board)?;
    }
    if let Some((_, _, by)) = r.owed {
        return Err(Recount::owed_failure(by));
    }
    let ctx = r.ctx.clone();
    let Some(round) = r.round.filter(|d| d.complete() || d.targets().is_empty()) else {
        return Err(AuditFailure::ResultMismatch(
            "the board holds no complete decryption".into(),
        ));
    };
    if !round.targets().is_empty() && !r.authorized {
        return Err(AuditFailure::ResultMismatch(
            "the community never authorized the decryption".into(),
        ));
    }
    let plaintexts = if round.targets().is_empty() {
        Vec::new()
    } else {
        round
            .plaintexts()
            .map_err(|e| AuditFailure::ResultMismatch(e.to_string()))?
    };
    let counted = r.counted;
    let opened = r.opened;
    let n = counted.len() as u64;
    if manifest.secrecy == SecrecyLevel::Sealed {
        // Each sealed form opens under the tag it was cast under (CONVENTIONS §9.4).
        let by_leaf: HashMap<u64, (&Sealed, &str)> = counted
            .iter()
            .filter_map(|(tag, (i, f, _))| match f {
                Form::Sealed(s) => Some((*i, (s.as_ref(), tag.as_str()))),
                Form::Tallied(_) => None,
            })
            .collect();
        let mut ballots = Vec::new();
        for (t, r_elem) in plaintexts {
            let Target::Leaf(leaf) = t else { continue };
            let (s, tag) = by_leaf.get(&leaf).ok_or_else(|| {
                AuditFailure::ResultMismatch(format!("no counted cast at {leaf}"))
            })?;
            let valid = open_with(&r_elem, s, &cast_ctx(&ctx, tag))
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
        return Ok((counted_n, rows));
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
    Ok((n, Value::Array(rows)))
}

/// The compressed `a` of every ciphertext in a form.
fn ciphertext_keys(form: &Form) -> Vec<[u8; 32]> {
    match form {
        Form::Sealed(s) => vec![s.kem.a.compress().to_bytes()],
        Form::Tallied(qs) => qs
            .iter()
            .flat_map(|q| q.options.iter().map(|o| o.0.a.compress().to_bytes()))
            .collect(),
    }
}

/// The decryption targets once voting closes, as the ballot box fixes them (CONVENTIONS §9.7).
fn targets(
    manifest: &Manifest,
    counted: &HashMap<String, (u64, Form, [u8; 32])>,
) -> Vec<(Target, crate::trustees::Ciphertext)> {
    // No casts, nothing to decrypt: every total is zero (and the identity, which no wire form
    // carries).
    if counted.is_empty() {
        return Vec::new();
    }
    let mut by_leaf: Vec<&(u64, Form, [u8; 32])> = counted.values().collect();
    by_leaf.sort_by_key(|(i, _, _)| *i);
    let mut out = Vec::new();
    if manifest.secrecy == SecrecyLevel::Sealed {
        for (i, f, _) in by_leaf {
            if let Form::Sealed(s) = f {
                out.push((Target::Leaf(*i), s.kem));
            }
        }
        return out;
    }
    for (qi, q) in manifest.questions.iter().enumerate() {
        let Some(qkey) = rules::key(q) else { continue };
        for (oi, okey) in rules::option_keys(q).iter().enumerate() {
            let sum = total(by_leaf.iter().filter_map(|(_, f, _)| match f {
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

/// CONVENTIONS §9.5, as the ballot box checks it, under `ctx` — the cast's (§9.3).
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
