//! The ballot box: every `voting/*` task, as a state machine over the elections it holds.
//!
//! Transport, document signing and storage are the host's. A handler takes the request's
//! payload exactly as received, the proven signer (if the binding proved one) and the time, and
//! answers with the response payload or a [`Failure`] carrying the task's error local part. The
//! host signs the answer as the ballot box — every answer that carries a head must be signed
//! (conventions §4, VTI-VOT-050), and the cast's answer is the voter's receipt (VTI-VOT-043).
//!
//! Time is an input: each election advances on its own clock — `opened` at
//! `votingOpens`, `closed` and the result at `votingCloses` — and every handler advances first,
//! so an election never answers from a state its clock has left.
//!
//! What the ballot box never holds is the point: no roster, no member DID, no issuance record
//! (VTI-VOT-002, VTI-VOT-044). It admits a cast on the registration and its own tag record.
//!
//! # Durability
//!
//! A [`Journal`] receives, before any answer is sent, the three things that cannot be
//! recomputed: each registration (manifest and parameters as received), each board entry, and
//! each receipt token. Everything else — the state, the tag record, the counted ballots, the
//! result, the roots — is rebuilt by replaying the board ([`BallotBox::restore`]), so there is
//! one record of what happened and no second copy to disagree with it. A receipt token is
//! journalled before its cast's entry; a token without an entry is never answered.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trust_tasks_rs::specs::voting::{
    ballot::cast::v0_1 as cast, board::consistency::v0_1 as consistency, board::head::v0_1 as head,
    board::inclusion::v0_1 as inclusion, board::read::v0_1 as read,
    election::cancel::v0_1 as cancel, election::close::v0_1 as close,
    election::register::v0_1 as register, election::show::v0_1 as show,
    result::show::v0_1 as result,
};

mod encrypted;

use encrypted::Encrypted;

use crate::{
    ballot_box::{BallotBox as Verifier, MemoryNullifiers, Revote as BoxRevote},
    board::{Board, Hash},
    ceremony::{Ceremony, Decryption},
    election::{Election, ElectionId},
    rules::{self, RuleError, digest_multibase},
    scheme::{Hvk, VotingParams},
    tally,
    trustees::Threshold,
    voter::Cast,
    wire::Target,
};

/// A refusal: the task's error local part and a reason for the operator's log. The host turns
/// it into a `trust-task-error` with code `<task slug>:<local>`, or the framework's standard
/// code where `standard` is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub local: &'static str,
    pub standard: bool,
    pub reason: String,
}

impl Failure {
    fn task(local: &'static str, reason: impl Into<String>) -> Self {
        Self {
            local,
            standard: false,
            reason: reason.into(),
        }
    }
    fn standard(local: &'static str, reason: impl Into<String>) -> Self {
        Self {
            local,
            standard: true,
            reason: reason.into(),
        }
    }
    fn malformed(reason: impl Into<String>) -> Self {
        Self::standard("malformedRequest", reason)
    }
    fn denied() -> Self {
        Self::standard("permissionDenied", "the signer may not do this")
    }
    fn unknown() -> Self {
        Self::task(
            "electionUnknown",
            "no such election, or not visible to the caller",
        )
    }
}

impl From<RuleError> for Failure {
    fn from(e: RuleError) -> Self {
        let reason = e.to_string();
        match e {
            RuleError::InvalidManifest(_) => Self::task("invalidManifest", reason),
            RuleError::UnsupportedSecrecy(_) => Self::task("unsupportedSecrecy", reason),
            RuleError::ManifestMismatch => Self::task("manifestMismatch", reason),
            RuleError::BallotInvalid(_) => Self::task("ballotInvalid", reason),
            _ => Self::malformed(reason),
        }
    }
}

/// Who asked. A read of a public board needs nobody; everything else is decided on the DID the
/// binding proved.
#[derive(Debug, Clone, Copy)]
pub enum Caller<'a> {
    Anonymous,
    Did(&'a str),
}

impl Caller<'_> {
    fn did(&self) -> Option<&str> {
        match self {
            Caller::Anonymous => None,
            Caller::Did(d) => Some(d),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum State {
    Registered,
    Registration,
    Voting,
    Closed,
    Tallied,
    Cancelled,
}

impl State {
    fn wire(self) -> &'static str {
        match self {
            State::Registered => "registered",
            State::Registration => "registration",
            State::Voting => "voting",
            State::Closed => "closed",
            State::Tallied => "tallied",
            State::Cancelled => "cancelled",
        }
    }
}

/// A registration as received: everything a restored election is rebuilt from, beside its
/// board.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredElection {
    pub manifest: Value,
    pub parameters: Value,
}

/// One election as a journal returns it for [`BallotBox::restore`].
#[derive(Debug, Clone, Default)]
pub struct Restored {
    pub election: Option<StoredElection>,
    /// Board entries in order, as their JCS bytes.
    pub entries: Vec<Vec<u8>>,
    /// Receipt tokens by leaf index.
    pub receipts: HashMap<u64, String>,
}

/// Where the ballot box makes what it accepted durable. Each call completes before the answer
/// that depends on it is sent; an error refuses the request.
pub trait Journal: Send + Sync {
    /// A new registration.
    ///
    /// # Errors
    /// The store's reason.
    fn election(
        &self,
        community: &str,
        election_id: &str,
        e: &StoredElection,
    ) -> Result<(), String>;
    /// Board entry `index` of an election.
    ///
    /// # Errors
    /// The store's reason.
    fn entry(
        &self,
        community: &str,
        election_id: &str,
        index: u64,
        bytes: &[u8],
    ) -> Result<(), String>;
    /// The receipt token of the cast at `leaf`.
    ///
    /// # Errors
    /// The store's reason.
    fn receipt(
        &self,
        community: &str,
        election_id: &str,
        leaf: u64,
        token: &str,
    ) -> Result<(), String>;
}

/// Keeps nothing: a ballot box that forgets on restart.
#[derive(Debug, Default)]
pub struct NoJournal;

impl Journal for NoJournal {
    fn election(&self, _: &str, _: &str, _: &StoredElection) -> Result<(), String> {
        Ok(())
    }
    fn entry(&self, _: &str, _: &str, _: u64, _: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn receipt(&self, _: &str, _: &str, _: u64, _: &str) -> Result<(), String> {
        Ok(())
    }
}

/// An in-memory journal, for tests and for checking that a restore reproduces the original.
#[derive(Debug, Default)]
pub struct MemoryJournal(Mutex<HashMap<(String, String), Restored>>);

impl MemoryJournal {
    /// What a restart would read back.
    pub fn contents(&self) -> Vec<Restored> {
        self.0
            .lock()
            .expect("journal lock")
            .values()
            .cloned()
            .collect()
    }
}

impl Journal for MemoryJournal {
    fn election(&self, c: &str, id: &str, e: &StoredElection) -> Result<(), String> {
        let mut m = self.0.lock().map_err(|e| e.to_string())?;
        m.entry((c.into(), id.into())).or_default().election = Some(e.clone());
        Ok(())
    }
    fn entry(&self, c: &str, id: &str, index: u64, bytes: &[u8]) -> Result<(), String> {
        let mut m = self.0.lock().map_err(|e| e.to_string())?;
        let r = m.entry((c.into(), id.into())).or_default();
        if r.entries.len() as u64 != index {
            return Err(format!("entry {index} out of order"));
        }
        r.entries.push(bytes.to_vec());
        Ok(())
    }
    fn receipt(&self, c: &str, id: &str, leaf: u64, token: &str) -> Result<(), String> {
        let mut m = self.0.lock().map_err(|e| e.to_string())?;
        m.entry((c.into(), id.into()))
            .or_default()
            .receipts
            .insert(leaf, token.to_string());
        Ok(())
    }
}

fn journal_failure(reason: String) -> Failure {
    Failure::standard("internalError", format!("journal: {reason}"))
}

/// One cast as admitted: what its receipt names and what makes a resend recognisable.
#[derive(Clone)]
struct Admitted {
    leaf: u64,
    ballot_digest: [u8; 32],
    /// A bearer credential: on a private board it alone admits a read of this leaf.
    receipt_token: String,
}

/// Written by hand so the receipt token never reaches a log.
impl std::fmt::Debug for Admitted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admitted")
            .field("leaf", &self.leaf)
            .field("receipt_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

struct ElectionRecord {
    community: String,
    journal: Arc<dyn Journal>,
    manifest: register::Manifest,
    manifest_value: Value,
    digest: [u8; 32],
    parameters: Value,
    verifier: Verifier<MemoryNullifiers>,
    state: State,
    board: Board,
    entries: Vec<Vec<u8>>,
    /// Exact casts already on the board, by the digest of the cast's JCS form.
    exact: HashMap<[u8; 32], Admitted>,
    /// The counted cast under each tag.
    counted: HashMap<String, (Admitted, cast::Ballot)>,
    /// The counted encrypted cast under each tag, at the sealed and tallied-encrypted levels.
    encrypted: HashMap<String, (Admitted, Encrypted)>,
    /// `ctx` of the encrypted levels (CONVENTIONS §9.2).
    ctx: Vec<u8>,
    /// The trustees' key ceremony, at the encrypted levels.
    ceremony: Option<Ceremony>,
    /// The decryption round, once an encrypted election has closed with its key formed.
    decryption: Option<Decryption<Target>>,
    result: Option<Value>,
}

/// The ballot box: its own DID, its journal and the elections it holds.
pub struct BallotBox {
    did: String,
    journal: Arc<dyn Journal>,
    elections: HashMap<(String, String), ElectionRecord>,
}

impl std::fmt::Debug for BallotBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BallotBox")
            .field("did", &self.did)
            .field("elections", &self.elections.len())
            .finish()
    }
}

fn parse<T: DeserializeOwned>(v: &Value) -> Result<T, Failure> {
    serde_json::from_value(v.clone()).map_err(|e| Failure::malformed(e.to_string()))
}

/// Build a response through its generated type, so nothing leaves that the schema forbids.
fn respond<T: DeserializeOwned + Serialize>(v: Value) -> Result<Value, Failure> {
    let typed: T = serde_json::from_value(v)
        .map_err(|e| Failure::standard("internalError", format!("response shape: {e}")))?;
    serde_json::to_value(typed)
        .map_err(|e| Failure::standard("internalError", format!("response encoding: {e}")))
}

fn jcs(v: &Value) -> Result<Vec<u8>, Failure> {
    serde_json_canonicalizer::to_vec(v).map_err(|e| Failure::malformed(e.to_string()))
}

fn hash_text(h: &Hash) -> String {
    digest_multibase(h)
}

fn time(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Constant-time equality, for receipt tokens.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

impl ElectionRecord {
    fn id(&self) -> &str {
        self.manifest.election_id.as_str()
    }

    fn head(&self, size: usize, now: DateTime<Utc>) -> Value {
        json!({
            "electionId": self.id(),
            "treeSize": size,
            "rootHash": hash_text(&self.board.root(size).expect("size within the board")),
            "issuedAt": time(now),
        })
    }

    fn append(&mut self, entry: &Value) -> Result<u64, Failure> {
        let bytes = jcs(entry)?;
        let index = self.board.len() as u64;
        self.journal
            .entry(
                &self.community,
                self.manifest.election_id.as_str(),
                index,
                &bytes,
            )
            .map_err(journal_failure)?;
        self.board.append(&bytes);
        self.entries.push(bytes);
        Ok(index)
    }

    /// Rebuild state from entries already journalled, journalling nothing.
    fn replay(
        &mut self,
        entries: Vec<Vec<u8>>,
        receipts: &HashMap<u64, String>,
    ) -> Result<(), Failure> {
        for bytes in entries {
            let leaf = self.board.append(&bytes) as u64;
            let entry: Value = serde_json::from_slice(&bytes)
                .map_err(|e| journal_failure(format!("entry {leaf}: {e}")))?;
            if self.replay_encrypted(&entry, leaf, receipts)? {
                self.entries.push(bytes);
                continue;
            }
            match entry["kind"].as_str() {
                Some("opened") => {
                    if let Some(c) = &mut self.ceremony {
                        c.deadline();
                    }
                    self.state = State::Voting;
                }
                Some("cast") => {
                    let cast_value = &entry["cast"];
                    let cast_digest: [u8; 32] = Sha256::digest(jcs(cast_value)?).into();
                    let ballot_digest: [u8; 32] =
                        Sha256::digest(jcs(&cast_value["ballot"])?).into();
                    let typed: cast::Cast = parse(cast_value)?;
                    let admitted = Admitted {
                        leaf,
                        ballot_digest,
                        receipt_token: receipts.get(&leaf).cloned().unwrap_or_default(),
                    };
                    self.exact.insert(cast_digest, admitted.clone());
                    self.counted
                        .insert(typed.tag.as_str().to_string(), (admitted, typed.ballot));
                }
                Some("closed" | "closedEarly") => {
                    self.state = State::Closed;
                    self.start_decryption();
                }
                Some("result") => {
                    self.result = Some(entry["result"].clone());
                    self.state = State::Tallied;
                }
                Some("cancelled") => self.state = State::Cancelled,
                _ => {}
            }
            self.entries.push(bytes);
        }
        Ok(())
    }

    fn summary(&self, now: DateTime<Utc>) -> Value {
        json!({
            "electionId": self.id(),
            "community": self.manifest.community.as_str(),
            "manifestDigest": digest_multibase(&self.digest),
            "state": self.state.wire(),
            "ballotsAdmitted": self.counted.len() + self.encrypted.len(),
            "head": self.head(self.board.len(), now),
        })
    }

    /// May `caller` read this election's board (conventions §4)?
    fn readable_by(&self, caller: Caller<'_>) -> bool {
        if self.manifest.board.visibility == register::BoardVisibility::Public {
            return true;
        }
        caller.did().is_some_and(|d| {
            d == self.manifest.community.as_str()
                || self.manifest.board.auditors.iter().any(|a| a.as_str() == d)
        })
    }

    fn tally_now(&self, provisional: bool, now: DateTime<Utc>) -> Result<Value, Failure> {
        let ballots: Vec<&cast::Ballot> = self.counted.values().map(|(_, b)| b).collect();
        let (n, questions) = tally::tally(&self.manifest, ballots, provisional)?;
        Ok(json!({
            "electionId": self.id(),
            "manifestDigest": digest_multibase(&self.digest),
            "ballotsCounted": n,
            "questions": questions,
            "head": self.head(self.board.len(), now),
        }))
    }

    /// Close at `at` and publish the result on the board — at the encrypted levels, once the
    /// trustees have decrypted it.
    fn close(&mut self, kind: &str, at: DateTime<Utc>) -> Result<(), Failure> {
        self.append(&json!({ "kind": kind, "at": time(at) }))?;
        if self.ceremony.is_some() {
            self.state = State::Closed;
            self.start_decryption();
            return self.finish_if_decrypted(at);
        }
        self.state = State::Closed;
        let result = self.tally_now(false, at)?;
        self.append(&json!({ "kind": "result", "result": result }))?;
        self.result = Some(result);
        self.state = State::Tallied;
        Ok(())
    }

    /// Run the election's clock up to `now`.
    fn advance(&mut self, now: DateTime<Utc>) -> Result<(), Failure> {
        if self.state == State::Registered && now >= self.manifest.registration_opens {
            self.state = State::Registration;
        }
        if self.state <= State::Registration && now >= self.manifest.voting_opens {
            let at = self.manifest.voting_opens;
            self.ceremony_deadline()?;
            self.append(&json!({ "kind": "opened", "at": time(at) }))?;
            self.state = State::Voting;
        }
        if self.state == State::Voting && now >= self.manifest.voting_closes {
            self.close("closed", self.manifest.voting_closes)?;
        }
        Ok(())
    }
}

impl BallotBox {
    /// A ballot box that keeps nothing across a restart.
    pub fn new(did: &str) -> Self {
        Self::with_journal(did, Arc::new(NoJournal))
    }

    /// A ballot box that makes what it accepts durable in `journal`.
    pub fn with_journal(did: &str, journal: Arc<dyn Journal>) -> Self {
        Self {
            did: did.to_string(),
            journal,
            elections: HashMap::new(),
        }
    }

    /// Rebuild a ballot box from what its journal holds. Each election is re-registered from its
    /// manifest and parameters as received and its board replayed; nothing is journalled again.
    ///
    /// # Errors
    /// A failure naming the election that cannot be rebuilt: a journal that no longer parses is
    /// an operator's problem, never a silently shorter board.
    pub fn restore(
        did: &str,
        journal: Arc<dyn Journal>,
        restored: Vec<Restored>,
    ) -> Result<Self, Failure> {
        let mut bb = Self::with_journal(did, journal);
        for r in restored {
            let Some(stored) = r.election else {
                continue;
            };
            let mut record = bb.build_record(stored.manifest, stored.parameters)?;
            record.replay(r.entries, &r.receipts)?;
            let key = (record.community.clone(), record.id().to_string());
            bb.elections.insert(key, record);
        }
        Ok(bb)
    }

    fn build_record(
        &self,
        manifest_value: Value,
        parameters: Value,
    ) -> Result<ElectionRecord, Failure> {
        let manifest: register::Manifest = parse(&manifest_value)?;
        let voting: register::VotingParameters = parse(&parameters)?;
        let community = manifest.community.as_str().to_string();
        let digest = rules::manifest_digest(&manifest_value)?;
        let hvk: Hvk = vti_vetting_pcs::scheme::dec(voting.voting_key.as_str())
            .map_err(|e| Failure::malformed(format!("votingKey: {e}")))?;
        let params =
            VotingParams::new(&community, hvk).map_err(|e| Failure::malformed(e.to_string()))?;
        let election = Election::new(
            &community,
            ElectionId::new(manifest.election_id.as_str())
                .map_err(|e| Failure::malformed(e.to_string()))?,
            digest,
        )
        .map_err(|e| Failure::malformed(e.to_string()))?;
        let ctx = election.trustee_context();
        let ceremony = match &manifest.trustees {
            Some(t) => Some(Ceremony::new(
                Threshold::new(
                    u32::try_from(t.threshold).unwrap_or(0),
                    u32::try_from(t.dids.len()).unwrap_or(0),
                )
                .map_err(|e| Failure::malformed(e.to_string()))?,
                ctx.clone(),
            )),
            None => None,
        };
        let revote = match manifest.revote {
            register::Revote::Replace => BoxRevote::Replace,
            _ => BoxRevote::Refuse,
        };
        let verifier = Verifier::new(&params, election, revote, MemoryNullifiers::default())
            .map_err(|e| Failure::malformed(e.to_string()))?;
        Ok(ElectionRecord {
            community,
            journal: Arc::clone(&self.journal),
            manifest,
            manifest_value,
            digest,
            parameters,
            verifier,
            state: State::Registered,
            board: Board::new(),
            entries: Vec::new(),
            exact: HashMap::new(),
            counted: HashMap::new(),
            encrypted: HashMap::new(),
            ctx,
            ceremony,
            decryption: None,
            result: None,
        })
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    fn election(
        &mut self,
        community: &str,
        election_id: &str,
        now: DateTime<Utc>,
    ) -> Result<&mut ElectionRecord, Failure> {
        let e = self
            .elections
            .get_mut(&(community.to_string(), election_id.to_string()))
            .ok_or_else(Failure::unknown)?;
        e.advance(now)?;
        Ok(e)
    }

    /// `voting/election/register` (VTI-VOT-012, VTI-VOT-013).
    ///
    /// # Errors
    /// `permissionDenied` unless the signer is the community; `manifestMismatch`,
    /// `invalidManifest`, `unsupportedSecrecy`; `conflict` for the identifier with another
    /// manifest or key.
    pub fn register(
        &mut self,
        signer: &str,
        payload: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let p: register::Payload = parse(payload)?;
        let community = p.community.as_str().to_string();
        if signer != community || p.manifest.community.as_str() != community {
            return Err(Failure::denied());
        }
        let manifest_value = payload["manifest"].clone();
        let digest = rules::manifest_digest(&manifest_value)?;
        if rules::digest_from_multibase(p.manifest_digest.as_str()) != Some(digest) {
            return Err(RuleError::ManifestMismatch.into());
        }
        rules::check_manifest(&p.manifest, Some(&self.did))?;
        let parameters = payload["parameters"].clone();
        let key = (
            community.clone(),
            p.manifest.election_id.as_str().to_string(),
        );
        if let Some(existing) = self.elections.get_mut(&key) {
            if existing.digest == digest && existing.parameters == parameters {
                existing.advance(now)?;
                return respond::<register::Response>(json!({ "election": existing.summary(now) }));
            }
            return Err(Failure::task(
                "alreadyRegistered",
                "this election is registered with another manifest or key (VTI-VOT-013)",
            ));
        }
        let mut record = self.build_record(manifest_value.clone(), parameters.clone())?;
        self.journal
            .election(
                &community,
                &key.1,
                &StoredElection {
                    manifest: manifest_value,
                    parameters,
                },
            )
            .map_err(journal_failure)?;
        record.advance(now)?;
        let answer = respond::<register::Response>(json!({ "election": record.summary(now) }));
        self.elections.insert(key, record);
        answer
    }

    /// `voting/election/show`.
    ///
    /// # Errors
    /// `electionUnknown` for an election the caller may not see.
    pub fn show(
        &mut self,
        caller: Caller<'_>,
        payload: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let p: show::Payload = parse(payload)?;
        let e = self.election(p.community.as_str(), p.election_id.as_str(), now)?;
        // A trustee reads the election it takes part in on any board: its tasks take the
        // manifest, and its decryption the time voting closed (CONVENTIONS §4, §9.6).
        if !(e.readable_by(caller) || e.is_trustee(caller)) {
            return Err(Failure::unknown());
        }
        respond::<show::Response>(json!({
            "election": e.summary(now),
            "manifest": e.manifest_value,
        }))
    }

    /// `voting/election/close` — early close, where the manifest allows it.
    ///
    /// # Errors
    /// `permissionDenied`, `electionUnknown`, `notOpen`, `earlyCloseNotAllowed`.
    pub fn close(
        &mut self,
        signer: &str,
        payload: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let p: close::Payload = parse(payload)?;
        if signer != p.community.as_str() {
            return Err(Failure::denied());
        }
        let e = self.election(p.community.as_str(), p.election_id.as_str(), now)?;
        if e.state != State::Voting {
            return Err(Failure::task("notOpen", "voting is not open"));
        }
        if !e.manifest.allow_early_close {
            return Err(Failure::task(
                "earlyCloseNotAllowed",
                "the manifest does not allow closing early",
            ));
        }
        e.close("closedEarly", now)?;
        respond::<close::Response>(json!({ "election": e.summary(now) }))
    }

    /// `voting/election/cancel` — before the election closes.
    ///
    /// # Errors
    /// `permissionDenied`, `electionUnknown`, `notOpen`.
    pub fn cancel(
        &mut self,
        signer: &str,
        payload: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let p: cancel::Payload = parse(payload)?;
        if signer != p.community.as_str() {
            return Err(Failure::denied());
        }
        let e = self.election(p.community.as_str(), p.election_id.as_str(), now)?;
        if e.state >= State::Closed {
            return Err(Failure::task(
                "notOpen",
                "the election has closed or was cancelled",
            ));
        }
        e.append(&json!({ "kind": "cancelled", "at": time(now) }))?;
        e.state = State::Cancelled;
        respond::<cancel::Response>(json!({ "election": e.summary(now) }))
    }

    /// `voting/ballot/cast` (VTI-VOT-040 – 045). The signer is a one-time key and plays no part.
    ///
    /// # Errors
    /// `electionUnknown`, `notOpen`, `manifestMismatch`, `ballotInvalid`, `classMismatch`,
    /// `alreadyVoted`, `castInvalid`.
    pub fn cast(&mut self, payload: &Value, now: DateTime<Utc>) -> Result<Value, Failure> {
        let p: cast::Payload = parse(payload)?;
        let e = self.election(p.community.as_str(), p.election_id.as_str(), now)?;
        if e.ceremony.is_some() {
            return Err(Failure::malformed(
                "a sealed or tallied-encrypted election is cast with voting/ballot/cast-encrypted",
            ));
        }
        // Cheapest first (VTI-VOT-045): state, then form, then class and tag, then the pairing.
        if e.state != State::Voting {
            return Err(Failure::task("notOpen", "voting is not open"));
        }
        rules::check_ballot(&e.manifest, &e.digest, &p.cast.ballot)?;
        let cast_value = &payload["cast"];
        let cast_jcs = jcs(cast_value)?;
        let cast_digest: [u8; 32] = Sha256::digest(&cast_jcs).into();
        let ballot_jcs = jcs(&cast_value["ballot"])?;
        let ballot_digest: [u8; 32] = Sha256::digest(&ballot_jcs).into();
        let tag = p.cast.tag.as_str().to_string();

        // A resend of a cast already on the board: its first receipt, unverified again
        // (VTI-VOT-042). Replaying an old cast never undoes a revote.
        if let Some(a) = e.exact.get(&cast_digest).cloned() {
            return receipt(e, &a, "alreadyCounted", now);
        }
        let held = e.counted.get(&tag).map(|(a, _)| a.clone());
        if e.manifest.revote != register::Revote::Replace
            && held
                .as_ref()
                .is_some_and(|a| a.ballot_digest != ballot_digest)
        {
            return Err(Failure::task(
                "alreadyVoted",
                "a different ballot is counted",
            ));
        }

        let attestation = vti_vetting_pcs::scheme::dec(p.cast.attestation.as_str())
            .map_err(|_| Failure::task("castInvalid", "the attestation cannot be decoded"))?;
        let parsed = Cast { attestation };
        if parsed
            .tag()
            .map_err(|e| Failure::malformed(e.to_string()))?
            != tag
        {
            return Err(Failure::task(
                "castInvalid",
                "tag differs from the attestation's",
            ));
        }
        e.verifier
            .verify(&parsed, &ballot_jcs)
            .map_err(|err| match err {
                crate::VotingError::WrongClass => Failure::task("classMismatch", err.to_string()),
                _ => Failure::task("castInvalid", err.to_string()),
            })?;

        if let Some(a) = held.as_ref().filter(|a| a.ballot_digest == ballot_digest) {
            return receipt(e, a, "alreadyCounted", now);
        }
        let mut token = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token);
        let receipt_token = multibase::encode(multibase::Base::Base58Btc, token);
        e.journal
            .receipt(
                &e.community,
                e.manifest.election_id.as_str(),
                e.board.len() as u64,
                &receipt_token,
            )
            .map_err(journal_failure)?;
        let leaf = e.append(&json!({ "kind": "cast", "cast": cast_value }))?;
        let admitted = Admitted {
            leaf,
            ballot_digest,
            receipt_token,
        };
        let outcome = match held {
            Some(prev) => {
                e.append(&json!({
                    "kind": "replaced",
                    "tag": tag,
                    "replaces": prev.leaf,
                    "by": leaf,
                }))?;
                "replaced"
            }
            None => "counted",
        };
        e.exact.insert(cast_digest, admitted.clone());
        e.counted.insert(tag, (admitted.clone(), p.cast.ballot));
        receipt(e, &admitted, outcome, now)
    }

    /// `voting/board/head`.
    ///
    /// # Errors
    /// `electionUnknown`.
    pub fn board_head(
        &mut self,
        caller: Caller<'_>,
        payload: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let p: head::Payload = parse(payload)?;
        let e = self.election(p.community.as_str(), p.election_id.as_str(), now)?;
        if !e.readable_by(caller) {
            return Err(Failure::unknown());
        }
        respond::<head::Response>(json!({ "head": e.head(e.board.len(), now) }))
    }

    /// `voting/board/read`.
    ///
    /// # Errors
    /// `electionUnknown`, `outOfRange`.
    pub fn board_read(
        &mut self,
        caller: Caller<'_>,
        payload: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let p: read::Payload = parse(payload)?;
        let e = self.election(p.community.as_str(), p.election_id.as_str(), now)?;
        if !e.readable_by(caller) {
            return Err(Failure::unknown());
        }
        let size = p.tree_size.unwrap_or(e.board.len() as u64);
        if size > e.board.len() as u64 || p.from > size {
            return Err(Failure::task("outOfRange", "beyond the board"));
        }
        let end = size.min(p.from.saturating_add(p.limit.get()));
        let entries = (p.from..end)
            .map(|i| {
                let entry: Value = serde_json::from_slice(&e.entries[i as usize])
                    .expect("entries are stored as JSON");
                json!({ "index": i, "entry": entry })
            })
            .collect::<Vec<_>>();
        let mut answer = json!({ "treeSize": size, "entries": entries });
        if end < size {
            answer["next"] = json!(end);
        }
        respond::<read::Response>(answer)
    }

    /// `voting/board/inclusion`. On a private board, the receipt token admits exactly its leaf.
    ///
    /// # Errors
    /// `electionUnknown`, `outOfRange`.
    pub fn board_inclusion(
        &mut self,
        caller: Caller<'_>,
        payload: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let p: inclusion::Payload = parse(payload)?;
        let e = self.election(p.community.as_str(), p.election_id.as_str(), now)?;
        let by_receipt = p.receipt_token.as_ref().is_some_and(|t| {
            e.exact
                .values()
                .any(|a| a.leaf == p.leaf_index && same(&a.receipt_token, t.as_str()))
        });
        if !(e.readable_by(caller) || by_receipt) {
            return Err(Failure::unknown());
        }
        let (index, size) = (p.leaf_index as usize, p.tree_size.get() as usize);
        let path = e
            .board
            .inclusion_proof(index, size)
            .map_err(|err| Failure::task("outOfRange", err.to_string()))?;
        respond::<inclusion::Response>(json!({
            "leafIndex": p.leaf_index,
            "treeSize": p.tree_size.get(),
            "entryHash": hash_text(e.board.leaf(index).expect("index checked")),
            "path": path.iter().map(hash_text).collect::<Vec<_>>(),
        }))
    }

    /// `voting/board/consistency`.
    ///
    /// # Errors
    /// `electionUnknown`, `outOfRange`.
    pub fn board_consistency(
        &mut self,
        caller: Caller<'_>,
        payload: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let p: consistency::Payload = parse(payload)?;
        let e = self.election(p.community.as_str(), p.election_id.as_str(), now)?;
        if !e.readable_by(caller) {
            return Err(Failure::unknown());
        }
        let path = e
            .board
            .consistency_proof(p.first_size.get() as usize, p.second_size.get() as usize)
            .map_err(|err| Failure::task("outOfRange", err.to_string()))?;
        respond::<consistency::Response>(json!({
            "firstSize": p.first_size.get(),
            "secondSize": p.second_size.get(),
            "path": path.iter().map(hash_text).collect::<Vec<_>>(),
        }))
    }

    /// `voting/result/show`: the result once tallied, or running totals for an open election
    /// whose manifest allows them (VTI-VOT-061).
    ///
    /// # Errors
    /// `electionUnknown`, `notTallied`.
    pub fn result(
        &mut self,
        caller: Caller<'_>,
        payload: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let p: result::Payload = parse(payload)?;
        let e = self.election(p.community.as_str(), p.election_id.as_str(), now)?;
        if !e.readable_by(caller) {
            return Err(Failure::unknown());
        }
        let (result, provisional) = match (&e.result, e.state) {
            (Some(r), State::Tallied) => (r.clone(), false),
            (_, State::Voting) if e.manifest.results_before_close => {
                (e.tally_now(true, now)?, true)
            }
            _ => return Err(Failure::task("notTallied", "no result yet")),
        };
        respond::<result::Response>(json!({
            "result": result,
            "provisional": provisional,
            "state": e.state.wire(),
        }))
    }
}

fn receipt(
    e: &ElectionRecord,
    a: &Admitted,
    outcome: &str,
    now: DateTime<Utc>,
) -> Result<Value, Failure> {
    respond::<cast::Response>(json!({
        "electionId": e.id(),
        "outcome": outcome,
        "leafIndex": a.leaf,
        "entryHash": hash_text(e.board.leaf(a.leaf as usize).expect("admitted leaves exist")),
        "head": e.head(e.board.len(), now),
        "receiptToken": a.receipt_token,
    }))
}
