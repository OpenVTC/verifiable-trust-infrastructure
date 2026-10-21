//! Re-verify a whole board, as a community certifying its result or any auditor would
//! (VTI-VOT-070 – 073): no secret, only the community's published voting key, the manifest and
//! the board's entries as the ballot box served them.
//!
//! In order, each failure naming where it was found:
//!
//! 1. The entries hash to the head's root at its size (RFC 9162).
//! 2. The board is consistent with every checkpoint kept while it was open: the root of its
//!    first `treeSize` entries is the checkpoint's. Having every entry, this is the root itself
//!    rather than a consistency proof, which is the stronger check.
//! 3. Every cast would have been admitted: its ballot names this election and manifest and
//!    answers as the manifest admits, its attestation is of this election's class, and it
//!    verifies for this election's point with the ballot bound in. On an encrypted board, every
//!    step of the trustees' ceremony before it is the named trustee's signed request, its proof
//!    vouched for by the caller ([`ProvenRequests`], CONVENTIONS §9.6), and the key a cast is
//!    checked under is the one those steps form.
//! 4. Every tag counts once: under `refuse`, no tag twice; under `replace`, a later cast under a
//!    tag is followed by a `replaced` entry naming the two, and only the last counts.
//! 5. The result is the board's: recomputed from the counted ballots, it equals the published
//!    one, whose head is a prefix of the verified board.
//! 6. No more ballots than tickets (VTI-VOT-072).

use std::collections::HashMap;

use serde_json::Value;
use sha2::{Digest, Sha256};
use trust_tasks_rs::specs::voting::{
    ballot::cast::v0_1 as cast,
    election::register::v0_1::{Manifest, Revote},
};

use crate::{
    ballot_box::{BallotBox, MemoryNullifiers, Revote as BoxRevote},
    board::{Board, Hash},
    election::{Election, ElectionId},
    rules::{self, digest_from_multibase},
    scheme::VotingParams,
    steps::ProvenRequests,
    tally,
    voter::Cast,
};

/// What a certification found wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuditFailure {
    /// The entries do not hash to the head's root.
    #[error("the entries do not hash to the head's root")]
    RootMismatch,
    /// The board is not an extension of a checkpoint kept earlier.
    #[error("the board is not consistent with the checkpoint at tree size {tree_size}")]
    CheckpointInconsistent { tree_size: u64 },
    /// A cast would not have been admitted.
    #[error("the cast at index {index} would not have been admitted: {reason}")]
    CastInvalid { index: u64, reason: String },
    /// A tag counted twice where the manifest refuses a revote.
    #[error("the tag at index {index} is already on the board")]
    TagRepeated { index: u64 },
    /// A replacement that does not follow the manifest's revote rule.
    #[error("the replacement at index {index} is not valid: {reason}")]
    ReplacementInvalid { index: u64, reason: String },
    /// The published result is not the one the counted ballots give.
    #[error("the published result is not the board's: {0}")]
    ResultMismatch(String),
    /// More ballots counted than tickets issued.
    #[error("{counted} ballots counted, but only {issued} tickets were issued")]
    CountExceedsTickets { counted: u64, issued: u64 },
    /// The manifest, the parameters or an entry could not be read.
    #[error("{0}")]
    Unreadable(String),
    /// A trustee step on an encrypted board does not hold (CONVENTIONS §9.6 – 9.7).
    #[error("the trustee entry at index {index} does not hold: {reason}")]
    CeremonyInvalid { index: u64, reason: String },
    /// The board is not the election's lifecycle in order (CONVENTIONS §3.9).
    #[error("the entry at index {index} is out of the election's order: {reason}")]
    OrderInvalid { index: u64, reason: String },
}

/// A board head: its size and root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadRef {
    pub tree_size: u64,
    pub root: Hash,
}

impl HeadRef {
    /// From a `BoardHead` as the wire carries it.
    ///
    /// # Errors
    /// [`AuditFailure::Unreadable`] for a head without a size or a decodable root.
    pub fn from_wire(head: &Value) -> Result<Self, AuditFailure> {
        let tree_size = head["treeSize"]
            .as_u64()
            .ok_or_else(|| AuditFailure::Unreadable("a head without treeSize".into()))?;
        let root = head["rootHash"]
            .as_str()
            .and_then(digest_from_multibase)
            .ok_or_else(|| AuditFailure::Unreadable("a head without a rootHash".into()))?;
        Ok(Self { tree_size, root })
    }
}

/// Everything a certification checks, as received.
#[derive(Debug, Clone, Copy)]
pub struct Evidence<'a> {
    /// The manifest as registered.
    pub manifest: &'a Value,
    /// The community's published voting parameters.
    pub params: &'a VotingParams,
    /// Every entry under the head, in board order.
    pub entries: &'a [Value],
    /// The head the entries are read under.
    pub head: HeadRef,
    /// The heads kept while the board was open.
    pub checkpoints: &'a [HeadRef],
    /// The published result (`ElectionResult`).
    pub result: &'a Value,
    /// How many tickets the community issued.
    pub tickets_issued: u64,
    /// The signers of the trustees' requests on the board, as the caller verified them. Empty
    /// for an open election.
    pub proven: &'a ProvenRequests,
}

/// What a board that verified holds: the counted ballots and the result recomputed from them.
#[derive(Debug, Clone)]
pub struct Verified {
    pub ballots_counted: u64,
    pub questions: Value,
}

#[path = "audit_encrypted.rs"]
mod encrypted;

fn canonical(v: &Value) -> Result<Vec<u8>, AuditFailure> {
    serde_json_canonicalizer::to_vec(v)
        .map_err(|e| AuditFailure::Unreadable(format!("canonicalize: {e}")))
}

/// Run every check, in the order the module lists.
///
/// # Errors
/// The first check that fails.
pub fn audit(e: Evidence<'_>) -> Result<Verified, AuditFailure> {
    let manifest: Manifest = serde_json::from_value(e.manifest.clone())
        .map_err(|err| AuditFailure::Unreadable(format!("manifest: {err}")))?;
    let digest = rules::manifest_digest(e.manifest)
        .map_err(|err| AuditFailure::Unreadable(err.to_string()))?;
    let election = Election::new(
        e.params.community(),
        ElectionId::new(manifest.election_id.as_str())
            .map_err(|err| AuditFailure::Unreadable(err.to_string()))?,
        digest,
    )
    .map_err(|err| AuditFailure::Unreadable(err.to_string()))?;

    // 1.
    let mut board = Board::new();
    let mut leaves_bytes = Vec::with_capacity(e.entries.len());
    for entry in e.entries {
        let bytes = canonical(entry)?;
        board.append(&bytes);
        leaves_bytes.push(bytes);
    }
    if board.len() as u64 != e.head.tree_size || board.root(board.len()).ok() != Some(e.head.root) {
        return Err(AuditFailure::RootMismatch);
    }
    // 2.
    for c in e.checkpoints {
        let size = usize::try_from(c.tree_size).unwrap_or(usize::MAX);
        if board.root(size).ok() != Some(c.root) {
            return Err(AuditFailure::CheckpointInconsistent {
                tree_size: c.tree_size,
            });
        }
    }

    // The election's order (CONVENTIONS §3.9), and where its one result is.
    let result_index = check_order(&manifest, e.entries)?;
    let result_entry = Some(&e.entries[result_index]);

    // 3 – 4.
    let revote = if manifest.revote == Revote::Replace {
        BoxRevote::Replace
    } else {
        BoxRevote::Refuse
    };
    if manifest.trustees.is_some() {
        let ctx = election.trustee_context();
        let verifier = BallotBox::new(e.params, election, revote, MemoryNullifiers::default())
            .map_err(|err| AuditFailure::Unreadable(err.to_string()))?;
        let (n, questions) = encrypted::recount(
            &manifest,
            &digest,
            encrypted::Steps {
                community: e.params.community(),
                ctx,
                proven: e.proven,
            },
            &verifier,
            revote,
            e.entries,
            &board,
        )?;
        return finish(e, &board, &digest, n, questions, result_entry, result_index);
    }
    let verifier = BallotBox::new(e.params, election, revote, MemoryNullifiers::default())
        .map_err(|err| AuditFailure::Unreadable(err.to_string()))?;
    // Tag → (index of the counted cast, its ballot).
    let mut counted: HashMap<String, (u64, cast::Ballot)> = HashMap::new();
    // A later cast under a counted tag, still owed its `replaced` entry.
    let mut owed: Option<(String, u64, u64)> = None;
    for (i, entry) in e.entries.iter().enumerate() {
        let index = i as u64;
        match entry["kind"].as_str() {
            Some("cast") => {
                if let Some((_, _, by)) = owed {
                    return Err(AuditFailure::ReplacementInvalid {
                        index: by,
                        reason:
                            "a later cast under a counted tag is not followed by its replacement"
                                .into(),
                    });
                }
                let invalid = |reason: String| AuditFailure::CastInvalid { index, reason };
                let wire: cast::Cast = serde_json::from_value(entry["cast"].clone())
                    .map_err(|err| invalid(format!("unreadable: {err}")))?;
                rules::check_ballot(&manifest, &digest, &wire.ballot)
                    .map_err(|err| invalid(err.to_string()))?;
                let attestation = vti_vetting_pcs::scheme::dec(wire.attestation.as_str())
                    .map_err(|err| invalid(format!("attestation: {err}")))?;
                let ballot = canonical(&entry["cast"]["ballot"])?;
                let tag = verifier
                    .verify(&Cast { attestation }, &ballot)
                    .map_err(|err| invalid(err.to_string()))?;
                if tag != wire.tag.as_str() {
                    return Err(invalid("the tag is not the attestation's".into()));
                }
                match counted.get(&tag) {
                    None => {
                        counted.insert(tag, (index, wire.ballot));
                    }
                    Some(_) if revote == BoxRevote::Refuse => {
                        return Err(AuditFailure::TagRepeated { index });
                    }
                    Some((earlier, held)) => {
                        if canonical(&serde_json::to_value(held).unwrap_or_default())?
                            == canonical(&entry["cast"]["ballot"])?
                        {
                            return Err(AuditFailure::ReplacementInvalid {
                                index,
                                reason: "a replacement must carry another ballot".into(),
                            });
                        }
                        owed = Some((tag.clone(), *earlier, index));
                        counted.insert(tag, (index, wire.ballot));
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
            _ => {}
        }
    }
    if let Some((_, _, by)) = owed {
        return Err(AuditFailure::ReplacementInvalid {
            index: by,
            reason: "a later cast under a counted tag is not followed by its replacement".into(),
        });
    }

    // 5.
    let ballots: Vec<&cast::Ballot> = counted.values().map(|(_, b)| b).collect();
    let (n, questions) = tally::tally(&manifest, ballots, false)
        .map_err(|err| AuditFailure::Unreadable(err.to_string()))?;
    let questions = serde_json::to_value(&questions)
        .map_err(|err| AuditFailure::Unreadable(err.to_string()))?;
    finish(e, &board, &digest, n, questions, result_entry, result_index)
}

/// CONVENTIONS §3.9: the board is the election's lifecycle in order. Returns the index of its one
/// `result` entry.
fn check_order(manifest: &Manifest, entries: &[Value]) -> Result<usize, AuditFailure> {
    let at = |e: &Value| {
        e["at"]
            .as_str()
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.with_timezone(&chrono::Utc))
    };
    let mut opened = false;
    let mut key = false;
    let mut closing = false;
    let mut authorized = false;
    let mut result: Option<usize> = None;
    for (i, e) in entries.iter().enumerate() {
        let bad = |reason: &str| AuditFailure::OrderInvalid {
            index: i as u64,
            reason: reason.into(),
        };
        if result.is_some() {
            return Err(bad("an entry after the result"));
        }
        match e["kind"].as_str() {
            Some(crate::steps::KIND) if key => {
                return Err(bad("a trustee step after the election key"));
            }
            Some("electionKey") => {
                if key || opened {
                    return Err(bad("the election key after voting opened, or twice"));
                }
                key = true;
            }
            Some("opened") => {
                if opened || closing {
                    return Err(bad("voting opened twice, or after it ended"));
                }
                if at(e).is_none_or(|t| t < manifest.voting_opens) {
                    return Err(bad("voting opened before votingOpens"));
                }
                opened = true;
            }
            Some("cast" | "encryptedCast") => {
                if !opened || closing {
                    return Err(bad("a cast outside the voting window"));
                }
            }
            Some(kind @ ("closed" | "closedEarly" | "cancelled")) => {
                if closing {
                    return Err(bad("the election ended twice"));
                }
                if kind == "closedEarly" && !manifest.allow_early_close {
                    return Err(bad("closed early where the manifest allows no early close"));
                }
                if kind == "closed" && at(e).is_none_or(|t| t < manifest.voting_closes) {
                    return Err(bad("closed before votingCloses"));
                }
                if kind != "cancelled" && !opened {
                    return Err(bad("closed before it opened"));
                }
                closing = true;
            }
            Some("decryptionAuthorized") => {
                if !closing || authorized {
                    return Err(bad("a decryption authorized before the close, or twice"));
                }
                authorized = true;
            }
            Some("partials" | "unsealed" | "spoiled") => {
                if !authorized {
                    return Err(bad("a decryption the community did not authorize"));
                }
            }
            Some("result") => {
                if !closing {
                    return Err(bad("a result before the close"));
                }
                result = Some(i);
            }
            _ => {}
        }
    }
    result.ok_or_else(|| AuditFailure::ResultMismatch("the board records no result".into()))
}

/// The decryption a closed sealed or tallied-encrypted board calls for — the targets its counted
/// casts give, and the closing entry — for the community to authorize (CONVENTIONS §9.7): every
/// entry through the closing one held as certification holds it (the ceremony from its signed
/// steps, every cast re-admitted). `None` while the board has not closed.
///
/// # Errors
/// The first entry that does not hold.
pub fn decryption(
    manifest_value: &Value,
    params: &VotingParams,
    entries: &[Value],
    proven: &ProvenRequests,
) -> Result<Option<encrypted::Closing>, AuditFailure> {
    let manifest: Manifest = serde_json::from_value(manifest_value.clone())
        .map_err(|err| AuditFailure::Unreadable(format!("manifest: {err}")))?;
    let digest = rules::manifest_digest(manifest_value)
        .map_err(|err| AuditFailure::Unreadable(err.to_string()))?;
    let election = Election::new(
        params.community(),
        ElectionId::new(manifest.election_id.as_str())
            .map_err(|err| AuditFailure::Unreadable(err.to_string()))?,
        digest,
    )
    .map_err(|err| AuditFailure::Unreadable(err.to_string()))?;
    let revote = if manifest.revote == Revote::Replace {
        BoxRevote::Replace
    } else {
        BoxRevote::Refuse
    };
    let mut board = Board::new();
    for entry in entries {
        board.append(&canonical(entry)?);
    }
    let ctx = election.trustee_context();
    let verifier = BallotBox::new(params, election, revote, MemoryNullifiers::default())
        .map_err(|err| AuditFailure::Unreadable(err.to_string()))?;
    encrypted::closing(
        &manifest,
        &digest,
        encrypted::Steps {
            community: params.community(),
            ctx,
            proven,
        },
        &verifier,
        revote,
        entries,
        &board,
    )
}

pub use encrypted::{Closing, targets_digest};

/// The election key a sealed or tallied-encrypted board's ceremony formed, once its `electionKey`
/// entry is on the board: replayed from the trustees' steps alone, each the named trustee's
/// request with a proof `proven` vouches for (CONVENTIONS §9.6), and returned only when the entry
/// states the very key that replay forms. `None` while no key has formed.
///
/// This is what a community shows its voters (`vtc/elections/show` item 6): whatever else a
/// ballot box serves, a key formed only from trustees' own dealings is one it does not hold.
///
/// # Errors
/// [`AuditFailure::CeremonyInvalid`] at the first step or key entry that does not hold, and
/// [`AuditFailure::Unreadable`] for a manifest without trustees.
pub fn election_key(
    manifest: &Value,
    community: &str,
    entries: &[Value],
    proven: &ProvenRequests,
) -> Result<Option<Value>, AuditFailure> {
    let typed: Manifest = serde_json::from_value(manifest.clone())
        .map_err(|err| AuditFailure::Unreadable(format!("manifest: {err}")))?;
    let digest = rules::manifest_digest(manifest)
        .map_err(|err| AuditFailure::Unreadable(err.to_string()))?;
    let ctx = Election::new(
        community,
        ElectionId::new(typed.election_id.as_str())
            .map_err(|err| AuditFailure::Unreadable(err.to_string()))?,
        digest,
    )
    .map_err(|err| AuditFailure::Unreadable(err.to_string()))?
    .trustee_context();
    encrypted::formed_key(
        &typed,
        encrypted::Steps {
            community,
            ctx,
            proven,
        },
        entries,
    )
}

/// Checks 5 and 6, on the totals the board gives.
fn finish(
    e: Evidence<'_>,
    board: &Board,
    digest: &[u8; 32],
    n: u64,
    questions: Value,
    result_entry: Option<&Value>,
    result_index: usize,
) -> Result<Verified, AuditFailure> {
    let digest = *digest;
    let published = e.result;
    if published["ballotsCounted"].as_u64() != Some(n) {
        return Err(AuditFailure::ResultMismatch(format!(
            "it counts {}, the board {n}",
            published["ballotsCounted"]
        )));
    }
    if !same_questions(&published["questions"], &questions) {
        return Err(AuditFailure::ResultMismatch(
            "the totals differ from the counted ballots'".into(),
        ));
    }
    if published["manifestDigest"]
        .as_str()
        .and_then(digest_from_multibase)
        != Some(digest)
    {
        return Err(AuditFailure::ResultMismatch(
            "it names another manifest".into(),
        ));
    }
    // The result's head is the board just before its `result` entry (CONVENTIONS §3.9 item 5).
    let at = HeadRef::from_wire(&published["head"])?;
    if at.tree_size != result_index as u64 || board.root(result_index).ok() != Some(at.root) {
        return Err(AuditFailure::ResultMismatch(
            "its head is not the board the result was published on".into(),
        ));
    }
    if let Some(entry) = result_entry
        && !same_result(&entry["result"], published)
    {
        return Err(AuditFailure::ResultMismatch(
            "it is not the result the board records".into(),
        ));
    }
    // 6.
    if n > e.tickets_issued {
        return Err(AuditFailure::CountExceedsTickets {
            counted: n,
            issued: e.tickets_issued,
        });
    }
    Ok(Verified {
        ballots_counted: n,
        questions,
    })
}

/// Totals compared as values, question by question, in any order.
fn same_questions(a: &Value, b: &Value) -> bool {
    let index = |v: &Value| -> Option<HashMap<String, Value>> {
        v.as_array()?
            .iter()
            .map(|q| Some((q["question"].as_str()?.to_string(), q.clone())))
            .collect()
    };
    let rows = |v: &Value| v.as_array().map_or(0, Vec::len);
    if rows(a) != rows(b) {
        return false;
    }
    match (index(a), index(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// The same result, whatever the time its head was read at.
fn same_result(a: &Value, b: &Value) -> bool {
    let strip = |v: &Value| {
        let mut v = v.clone();
        if let Some(h) = v.get_mut("head").and_then(Value::as_object_mut) {
            h.remove("issuedAt");
        }
        v
    };
    strip(a) == strip(b)
}

/// A digest of a result, multibase, for the audit row.
///
/// # Errors
/// [`AuditFailure::Unreadable`] if it cannot be canonicalized.
pub fn result_digest(result: &Value) -> Result<String, AuditFailure> {
    Ok(rules::digest_multibase(
        &Sha256::digest(canonical(result)?).into(),
    ))
}
