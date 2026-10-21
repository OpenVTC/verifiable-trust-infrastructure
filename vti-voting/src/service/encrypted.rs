//! The sealed and tallied-encrypted levels (CONVENTIONS §9): the trustees' tasks, the encrypted
//! cast, and the decryption that ends in the result.
//!
//! Every step a trustee takes is a board entry — its signed request, as received (`trusteeStep`,
//! [`crate::steps`]) — and replaying the board re-runs it through the same [`Ceremony`], so the
//! ceremony is rebuilt the way the open levels' tag record is.

use std::collections::{BTreeMap, BTreeSet};

use trust_tasks_rs::specs::voting::{
    ballot::cast_encrypted::v0_1 as cast_encrypted,
    trustees::{
        confirm::v0_1 as confirm, deal::v0_1 as deal, decrypt::v0_1 as decrypt,
        enrol::v0_1 as enrol, justify::v0_1 as justify, status::v0_1 as status,
    },
};

use super::*;
use crate::{
    ceremony::{CeremonyError, Phase, Step},
    steps,
    trustees::{
        EncryptedQuestion, Sealed, admitted_counts, open_with, question_ctx, tally as read_total,
        total, verify_vote,
    },
    wire,
};

/// A counted encrypted cast's ballot, as the board holds it.
#[derive(Debug, Clone)]
pub(super) enum Encrypted {
    Sealed(Box<Sealed>),
    /// One encrypted question per manifest question, in its order.
    Tallied(Vec<EncryptedQuestion>),
}

impl From<CeremonyError> for Failure {
    fn from(e: CeremonyError) -> Self {
        let reason = e.to_string();
        let local = match e {
            CeremonyError::NotEnrolling => "notEnrolling",
            CeremonyError::AlreadyEnrolled => "alreadyEnrolled",
            CeremonyError::TransportKeyInvalid => "transportKeyInvalid",
            CeremonyError::NotDealing => "notDealing",
            CeremonyError::AlreadyDealt => "alreadyDealt",
            CeremonyError::DealingInvalid(_) => "dealingInvalid",
            CeremonyError::NotConfirming => "notConfirming",
            CeremonyError::AlreadyConfirmed => "alreadyConfirmed",
            CeremonyError::NoComplaint => "noComplaint",
            CeremonyError::ShareInvalid => "shareInvalid",
            CeremonyError::NotDecrypting => "notDecrypting",
            CeremonyError::PartialInvalid(_) => "partialInvalid",
            _ => return Self::malformed(reason),
        };
        Self::task(local, reason)
    }
}

fn wire_failure(e: crate::trustees::TrusteeError) -> Failure {
    Failure::malformed(e.to_string())
}

fn index(v: &Value) -> Result<u32, Failure> {
    v.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| Failure::malformed("a trustee index"))
}

impl ElectionRecord {
    /// VTI-VOT-062: only the trustee the manifest names at `index` acts as it.
    fn require_trustee(&self, signer: &str, index: u32) -> Result<(), Failure> {
        let named = self
            .manifest
            .trustees
            .as_ref()
            .and_then(|t| t.dids.get(index.checked_sub(1)? as usize));
        if named.is_some_and(|d| d.as_str() == signer) {
            Ok(())
        } else {
            Err(Failure::denied())
        }
    }

    /// Whether the proven caller is one of the manifest's trustees.
    pub(super) fn is_trustee(&self, caller: Caller<'_>) -> bool {
        let Caller::Did(did) = caller else {
            return false;
        };
        self.manifest
            .trustees
            .as_ref()
            .is_some_and(|t| t.dids.iter().any(|d| d.as_str() == did))
    }

    fn trustee_dids(&self) -> Vec<String> {
        self.manifest
            .trustees
            .as_ref()
            .map(|t| t.dids.iter().map(|d| d.to_string()).collect())
            .unwrap_or_default()
    }

    fn step_election<'a>(&'a self, trustees: &'a [&'a str]) -> steps::Election<'a> {
        steps::Election {
            community: &self.community,
            election_id: self.id(),
            trustees,
        }
    }

    fn ceremony_or(&mut self, not_now: &'static str) -> Result<&mut Ceremony, Failure> {
        self.ceremony
            .as_mut()
            .ok_or_else(|| Failure::task(not_now, "an open election has no trustees"))
    }

    /// Append the election key once a step has formed it.
    fn key_entry_if_formed(&mut self, was: Phase) -> Result<(), Failure> {
        let Some(c) = &self.ceremony else {
            return Ok(());
        };
        if was != Phase::Keyed
            && let Some(k) = c.key()
        {
            let entry =
                json!({ "kind": "electionKey", "electionKey": wire::election_key_value(k) });
            self.append(&entry)?;
        }
        Ok(())
    }

    /// `votingOpens`: the ceremony forms its key from whoever qualifies, or fails.
    pub(super) fn ceremony_deadline(&mut self) -> Result<(), Failure> {
        let Some(c) = &mut self.ceremony else {
            return Ok(());
        };
        let was = c.phase();
        c.deadline();
        self.key_entry_if_formed(was)
    }

    /// Set up the decryption round on close, if the key formed. No board entry: the targets are
    /// a function of the board.
    pub(super) fn start_decryption(&mut self) {
        let Some(key) = self.ceremony.as_ref().and_then(|c| c.key()).cloned() else {
            return;
        };
        let mut by_leaf: Vec<&(Admitted, Encrypted)> = self.encrypted.values().collect();
        by_leaf.sort_by_key(|(a, _)| a.leaf);
        let mut targets = Vec::new();
        if by_leaf.is_empty() {
            // No casts, nothing to decrypt: every total is zero (and the identity, which no wire
            // form carries).
        } else if self.manifest.secrecy == register::SecrecyLevel::Sealed {
            for (a, e) in &by_leaf {
                if let Encrypted::Sealed(s) = e {
                    targets.push((Target::Leaf(a.leaf), s.kem));
                }
            }
        } else {
            for (qi, q) in self.manifest.questions.iter().enumerate() {
                let (Some(qkey), opts) = (rules::key(q), rules::option_keys(q)) else {
                    continue;
                };
                for (oi, okey) in opts.iter().enumerate() {
                    let sum = total(by_leaf.iter().filter_map(|(_, e)| match e {
                        Encrypted::Tallied(qs) => {
                            qs.get(qi).and_then(|q| q.options.get(oi)).map(|o| o.0)
                        }
                        Encrypted::Sealed(_) => None,
                    }));
                    targets.push((
                        Target::Option {
                            question: qkey.to_string(),
                            option: (*okey).to_string(),
                        },
                        sum,
                    ));
                }
            }
        }
        self.decryption = Some(Decryption::new(key, self.ctx.clone(), targets));
    }

    /// Once `t` trustees have decrypted every target: open or read, append, tally.
    pub(super) fn finish_if_decrypted(&mut self, now: DateTime<Utc>) -> Result<(), Failure> {
        let Some(d) = &self.decryption else {
            return Ok(());
        };
        if self.state != State::Closed || !(d.complete() || d.targets().is_empty()) {
            return Ok(());
        }
        let plaintexts = if d.targets().is_empty() {
            Vec::new()
        } else {
            d.plaintexts()?
        };
        let n = self.encrypted.len() as u64;
        let questions = if self.manifest.secrecy == register::SecrecyLevel::Sealed {
            let sealed: BTreeMap<u64, Sealed> = self
                .encrypted
                .values()
                .filter_map(|(a, e)| match e {
                    Encrypted::Sealed(s) => Some((a.leaf, (**s).clone())),
                    Encrypted::Tallied(_) => None,
                })
                .collect();
            let mut ballots = Vec::new();
            for (t, r_elem) in plaintexts {
                let Target::Leaf(leaf) = t else { continue };
                let opened = open_with(&r_elem, &sealed[&leaf], &self.ctx)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                    .and_then(|v| {
                        let b: cast::Ballot = serde_json::from_value(v.clone()).ok()?;
                        rules::check_ballot(&self.manifest, &self.digest, &b).ok()?;
                        Some((v, b))
                    });
                match opened {
                    Some((v, b)) => {
                        self.append(
                            &json!({ "kind": "unsealed", "leafIndex": leaf, "ballot": v }),
                        )?;
                        ballots.push(b);
                    }
                    None => {
                        self.append(&json!({ "kind": "spoiled", "leafIndex": leaf }))?;
                    }
                }
            }
            let (counted, questions) = tally::tally(&self.manifest, ballots.iter(), false)?;
            return self.publish(
                counted,
                serde_json::to_value(questions)
                    .map_err(|e| Failure::standard("internalError", e.to_string()))?,
                now,
            );
        } else {
            let mut totals: HashMap<(String, String), u64> = HashMap::new();
            for (t, m) in &plaintexts {
                if let Target::Option { question, option } = t {
                    let c = read_total(m, n).map_err(|e| {
                        Failure::standard("internalError", format!("{question}/{option}: {e}"))
                    })?;
                    totals.insert((question.clone(), option.clone()), c);
                }
            }
            // With no casts there were no targets, and every total is zero.
            let rows = tally::tallied_rows(
                &self.manifest,
                |q, o| {
                    totals
                        .get(&(q.to_string(), o.to_string()))
                        .copied()
                        .or((n == 0).then_some(0))
                },
                n,
            )?;
            Value::Array(rows)
        };
        self.publish(n, questions, now)
    }

    fn publish(
        &mut self,
        counted: u64,
        questions: Value,
        now: DateTime<Utc>,
    ) -> Result<(), Failure> {
        let result = json!({
            "electionId": self.id(),
            "manifestDigest": digest_multibase(&self.digest),
            "ballotsCounted": counted,
            "questions": questions,
            "head": self.head(self.board.len(), now),
        });
        self.append(&json!({ "kind": "result", "result": result }))?;
        self.result = Some(result);
        self.state = State::Tallied;
        Ok(())
    }

    /// The `TrusteePhase` on the wire.
    fn trustee_phase(&self) -> &'static str {
        match (&self.ceremony, self.state) {
            (None, _) => Phase::Failed.wire(),
            (Some(c), _) if c.phase() != Phase::Keyed => c.phase().wire(),
            (Some(_), State::Closed) => "decrypting",
            (Some(_), State::Tallied) => "done",
            (Some(c), _) => c.phase().wire(),
        }
    }

    /// The board's encrypted-level entries, re-run through the ceremony and the round. Returns
    /// whether `entry` was one.
    pub(super) fn replay_encrypted(
        &mut self,
        entry: &Value,
        leaf: u64,
        receipts: &HashMap<u64, String>,
    ) -> Result<bool, Failure> {
        let fail = |what: &str, e: String| journal_failure(format!("entry {leaf} ({what}): {e}"));
        match entry["kind"].as_str() {
            Some(steps::KIND) => {
                // The box verified the proof when the request arrived; its own journal is not
                // re-verified, only re-read as that trustee's step.
                let request = &entry["request"];
                let signer = request["issuer"].as_str().unwrap_or_default();
                let dids = self.trustee_dids();
                let trustees: Vec<&str> = dids.iter().map(String::as_str).collect();
                let step = steps::read(request, self.step_election(&trustees), signer)
                    .map_err(|e| fail("trusteeStep", e.to_string()))?;
                step.apply(self.ceremony_or("notEnrolling")?)
                    .map_err(|e| fail("trusteeStep", e.to_string()))?;
            }
            Some(k) if steps::RETIRED_KINDS.contains(&k) => {
                return Err(fail(k, "a retired entry kind".into()));
            }
            Some("electionKey") => {
                let c = self.ceremony_or("notConfirming")?;
                if c.phase() != Phase::Keyed {
                    c.deadline();
                }
                if c.key().map(wire::election_key_value).as_ref() != Some(&entry["electionKey"]) {
                    return Err(fail(
                        "electionKey",
                        "not the key the board's ceremony forms".into(),
                    ));
                }
            }
            Some("encryptedCast") => {
                let cast_value = &entry["cast"];
                let (tag, ballot_digest, form) = self.read_encrypted(cast_value)?;
                let admitted = Admitted {
                    leaf,
                    ballot_digest,
                    receipt_token: receipts.get(&leaf).cloned().unwrap_or_default(),
                };
                let cast_digest: [u8; 32] = Sha256::digest(jcs(cast_value)?).into();
                self.exact.insert(cast_digest, admitted.clone());
                self.encrypted.insert(tag, (admitted, form));
            }
            Some("partials") => {
                let trustee = index(&entry["trustee"])?;
                let parts = entry["partials"]
                    .as_array()
                    .ok_or_else(|| fail("partials", "not a list".into()))?
                    .iter()
                    .map(|p| wire::partial(p, trustee))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| fail("partials", e.to_string()))?;
                if let Some(d) = &mut self.decryption {
                    d.accept(trustee, parts)
                        .map_err(|e| fail("partials", e.to_string()))?;
                }
            }
            Some("unsealed" | "spoiled") => {}
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// An `EncryptedCast` as received: its tag, the digest of the form its attestation binds,
    /// and the form.
    fn read_encrypted(&self, cast_value: &Value) -> Result<(String, [u8; 32], Encrypted), Failure> {
        let tag = cast_value["tag"].as_str().unwrap_or_default().to_string();
        if let Some(s) = cast_value.get("sealed") {
            let form = wire::sealed(s).map_err(wire_failure)?;
            return Ok((
                tag,
                Sha256::digest(jcs(s)?).into(),
                Encrypted::Sealed(Box::new(form)),
            ));
        }
        let enc = &cast_value["encrypted"];
        let questions = enc["questions"]
            .as_array()
            .ok_or_else(|| Failure::malformed("questions"))?
            .iter()
            .map(|q| wire::encrypted_question(q).map(|(_, q)| q))
            .collect::<Result<_, _>>()
            .map_err(wire_failure)?;
        Ok((
            tag,
            Sha256::digest(jcs(enc)?).into(),
            Encrypted::Tallied(questions),
        ))
    }

    /// CONVENTIONS §9.5: the election and manifest are this one's, the questions are the
    /// manifest's in order, one ciphertext per option, and every proof verifies.
    fn check_encrypted_ballot(&self, enc: &Value) -> Result<(), Failure> {
        let invalid = |why: String| Failure::task("ballotInvalid", why);
        if enc["electionId"].as_str() != Some(self.id())
            || rules::digest_from_multibase(enc["manifestDigest"].as_str().unwrap_or_default())
                != Some(self.digest)
        {
            return Err(invalid("another election's ballot".into()));
        }
        let key = self
            .ceremony
            .as_ref()
            .and_then(|c| c.key())
            .ok_or_else(|| Failure::task("notOpen", "the election key is not formed"))?;
        let given = enc["questions"].as_array().map_or(&[][..], Vec::as_slice);
        if given.len() != self.manifest.questions.len() {
            return Err(invalid(
                "not one encrypted question per manifest question".into(),
            ));
        }
        for (q, v) in self.manifest.questions.iter().zip(given) {
            let register::Question::Choice {
                min_selections,
                max_selections,
                optional,
                options,
                ..
            } = q
            else {
                return Err(invalid(
                    "a tallied-encrypted election asks choices only".into(),
                ));
            };
            let qkey = rules::key(q).unwrap_or_default();
            let (named, eq) = wire::encrypted_question(v).map_err(|e| invalid(e.to_string()))?;
            if named != qkey {
                return Err(invalid(format!("question {named} is not {qkey}")));
            }
            let counts = admitted_counts(
                options.len(),
                *min_selections,
                max_selections.get(),
                *optional,
            )
            .map_err(|e| invalid(e.to_string()))?;
            verify_vote(
                key,
                &eq,
                options.len(),
                &counts,
                &question_ctx(&self.ctx, qkey),
            )
            .map_err(|e| invalid(e.to_string()))?;
        }
        Ok(())
    }
}

impl BallotBox {
    fn trustee_election(
        &mut self,
        signer: &str,
        payload: &Value,
        index_field: &str,
        now: DateTime<Utc>,
    ) -> Result<(&mut ElectionRecord, u32), Failure> {
        let community = payload["community"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let id = payload["electionId"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let index = index(payload.pointer(index_field).unwrap_or(&Value::Null))?;
        let e = self.election(&community, &id, now)?;
        e.require_trustee(signer, index)?;
        Ok((e, index))
    }

    fn trustee_answer(e: &ElectionRecord, now: DateTime<Utc>) -> Value {
        json!({ "election": e.summary(now), "phase": e.trustee_phase() })
    }

    /// `voting/trustees/enrol`.
    ///
    /// # Errors
    /// `permissionDenied`, `electionUnknown`, `notEnrolling`, `alreadyEnrolled`,
    /// `transportKeyInvalid`.
    pub fn trustees_enrol(
        &mut self,
        signer: &str,
        request: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let payload = &request["payload"];
        let _: enrol::Payload = parse(payload)?;
        let (e, _) = self.trustee_election(signer, payload, "/transportKey/trustee", now)?;
        let tk = wire::transport_key(&payload["transportKey"]).map_err(|_| {
            Failure::task("transportKeyInvalid", "the transport key does not decode")
        })?;
        if e.ceremony_or("notEnrolling")?.enrol(tk)? == Step::Accepted {
            e.append(&steps::entry(request))?;
        }
        respond::<enrol::Response>(Self::trustee_answer(e, now))
    }

    /// `voting/trustees/deal`.
    ///
    /// # Errors
    /// `permissionDenied`, `electionUnknown`, `notDealing`, `alreadyDealt`, `dealingInvalid`.
    pub fn trustees_deal(
        &mut self,
        signer: &str,
        request: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let payload = &request["payload"];
        let _: deal::Payload = parse(payload)?;
        let (e, _) = self.trustee_election(signer, payload, "/dealing/dealer", now)?;
        let d = wire::dealing(&payload["dealing"])
            .map_err(|err| Failure::task("dealingInvalid", err.to_string()))?;
        if e.ceremony_or("notDealing")?.deal(d)? == Step::Accepted {
            e.append(&steps::entry(request))?;
        }
        respond::<deal::Response>(Self::trustee_answer(e, now))
    }

    /// `voting/trustees/confirm`.
    ///
    /// # Errors
    /// `permissionDenied`, `electionUnknown`, `notConfirming`, `alreadyConfirmed`.
    pub fn trustees_confirm(
        &mut self,
        signer: &str,
        request: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let payload = &request["payload"];
        let _: confirm::Payload = parse(payload)?;
        let (e, trustee) = self.trustee_election(signer, payload, "/trustee", now)?;
        let complaints: BTreeSet<u32> = payload["complaints"]
            .as_array()
            .map_or(Ok(BTreeSet::new()), |a| a.iter().map(index).collect())?;
        let c = e.ceremony_or("notConfirming")?;
        let was = c.phase();
        if c.confirm(trustee, complaints)? == Step::Accepted {
            e.append(&steps::entry(request))?;
            e.key_entry_if_formed(was)?;
        }
        respond::<confirm::Response>(Self::trustee_answer(e, now))
    }

    /// `voting/trustees/justify`.
    ///
    /// # Errors
    /// `permissionDenied`, `electionUnknown`, `notConfirming`, `noComplaint`, `shareInvalid`.
    pub fn trustees_justify(
        &mut self,
        signer: &str,
        request: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let payload = &request["payload"];
        let _: justify::Payload = parse(payload)?;
        let (e, dealer) = self.trustee_election(signer, payload, "/dealer", now)?;
        let recipient = index(&payload["recipient"])?;
        let share =
            crate::trustees::scalar_from_text(payload["share"].as_str().unwrap_or_default())
                .map_err(|_| Failure::task("shareInvalid", "the share does not decode"))?;
        let c = e.ceremony_or("notConfirming")?;
        let was = c.phase();
        if c.justify(dealer, recipient, share)? == Step::Accepted {
            e.append(&steps::entry(request))?;
            e.key_entry_if_formed(was)?;
        }
        respond::<justify::Response>(Self::trustee_answer(e, now))
    }

    /// `voting/trustees/decrypt` (VTI-VOT-063).
    ///
    /// # Errors
    /// `permissionDenied`, `electionUnknown`, `notDecrypting`, `partialInvalid`.
    pub fn trustees_decrypt(
        &mut self,
        signer: &str,
        request: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let payload = &request["payload"];
        let _: decrypt::Payload = parse(payload)?;
        let (e, trustee) = self.trustee_election(signer, payload, "/trustee", now)?;
        let parts = payload["partials"]
            .as_array()
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .map(|p| wire::partial(p, trustee))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| Failure::task("partialInvalid", err.to_string()))?;
        if e.state != State::Closed {
            return Err(Failure::task(
                "notDecrypting",
                "voting has not closed, or the result is out",
            ));
        }
        let round = e
            .decryption
            .as_mut()
            .ok_or_else(|| Failure::task("notDecrypting", "the election key never formed"))?;
        let entry = json!({
            "kind": "partials",
            "trustee": trustee,
            "partials": parts.iter().map(|(t, ct, p)| wire::partial_value(t, ct, p)).collect::<Vec<_>>(),
        });
        if round.accept(trustee, parts)? == Step::Accepted {
            e.append(&entry)?;
            e.finish_if_decrypted(now)?;
        }
        respond::<decrypt::Response>(Self::trustee_answer(e, now))
    }

    /// `voting/trustees/status`. A trustee the manifest names reads it on any board: it cannot
    /// take its next step without it, and nothing here is secret (CONVENTIONS §4, §9.6).
    ///
    /// # Errors
    /// `electionUnknown`, for an election the caller may not read and is no trustee of.
    pub fn trustees_status(
        &mut self,
        caller: Caller<'_>,
        payload: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let p: status::Payload = parse(payload)?;
        let e = self.election(p.community.as_str(), p.election_id.as_str(), now)?;
        if !(e.readable_by(caller) || e.is_trustee(caller)) {
            return Err(Failure::unknown());
        }
        let Some(c) = &e.ceremony else {
            return Err(Failure::unknown());
        };
        let complaints: Vec<Value> = c
            .complaints()
            .iter()
            .map(|k| {
                let mut v = json!({ "dealer": k.dealer, "recipient": k.recipient, "justified": k.justified.is_some() });
                if let Some(s) = &k.justified {
                    v["share"] = json!(crate::trustees::scalar_text(s));
                }
                v
            })
            .collect();
        let (targets, decrypted): (Vec<Value>, Vec<u32>) = match (&e.decryption, e.state) {
            (Some(d), State::Closed) => (
                d.targets()
                    .iter()
                    .map(|(t, ct)| wire::target_value(t, ct))
                    .collect(),
                d.decrypted().collect(),
            ),
            (Some(d), _) => (Vec::new(), d.decrypted().collect()),
            (None, _) => (Vec::new(), Vec::new()),
        };
        let mut answer = json!({
            "phase": e.trustee_phase(),
            "threshold": c.threshold().t,
            "transportKeys": c.transport_keys().map(wire::transport_key_value).collect::<Vec<_>>(),
            "dealings": c.dealings().map(wire::dealing_value).collect::<Vec<_>>(),
            "complaints": complaints,
            "confirmed": c.confirmed().collect::<Vec<_>>(),
            "targets": targets,
            "decrypted": decrypted,
        });
        if let Some(k) = c.key() {
            answer["electionKey"] = wire::election_key_value(k);
        }
        respond::<status::Response>(answer)
    }

    /// `voting/ballot/cast-encrypted` (VTI-VOT-040 – 045, 064). Admission is the open cast's,
    /// with the attestation over the encrypted form's JCS bytes.
    ///
    /// # Errors
    /// `electionUnknown`, `wrongLevel`, `notOpen`, `ballotInvalid`, `alreadyVoted`, `castInvalid`.
    pub fn cast_encrypted(
        &mut self,
        payload: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value, Failure> {
        let p: cast_encrypted::Payload = parse(payload)?;
        let e = self.election(p.community.as_str(), p.election_id.as_str(), now)?;
        let cast_value = &payload["cast"];
        let sealed_level = e.manifest.secrecy == register::SecrecyLevel::Sealed;
        let tallied_level = e.manifest.secrecy == register::SecrecyLevel::TalliedEncrypted;
        if !((sealed_level && cast_value.get("sealed").is_some())
            || (tallied_level && cast_value.get("encrypted").is_some()))
        {
            return Err(Failure::task(
                "wrongLevel",
                "not this election's form of cast",
            ));
        }
        if e.state != State::Voting || e.ceremony.as_ref().and_then(|c| c.key()).is_none() {
            return Err(Failure::task(
                "notOpen",
                "voting is not open, or the election key is not formed",
            ));
        }
        if tallied_level {
            e.check_encrypted_ballot(&cast_value["encrypted"])?;
        }
        let cast_digest: [u8; 32] = Sha256::digest(jcs(cast_value)?).into();
        if let Some(a) = e.exact.get(&cast_digest).cloned() {
            return encrypted_receipt(e, &a, "alreadyCounted", now);
        }
        let (tag, ballot_digest, form) = e.read_encrypted(cast_value)?;
        let held = e.encrypted.get(&tag).map(|(a, _)| a.clone());
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
        let bound = jcs(cast_value.get("sealed").unwrap_or(&cast_value["encrypted"]))?;
        let attestation =
            vti_vetting_pcs::scheme::dec(cast_value["attestation"].as_str().unwrap_or_default())
                .map_err(|_| Failure::task("castInvalid", "the attestation cannot be decoded"))?;
        let parsed = Cast { attestation };
        if parsed
            .tag()
            .map_err(|err| Failure::malformed(err.to_string()))?
            != tag
        {
            return Err(Failure::task(
                "castInvalid",
                "tag differs from the attestation's",
            ));
        }
        e.verifier
            .verify(&parsed, &bound)
            .map_err(|err| Failure::task("castInvalid", err.to_string()))?;
        if let Some(a) = held.as_ref().filter(|a| a.ballot_digest == ballot_digest) {
            return encrypted_receipt(e, a, "alreadyCounted", now);
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
        let leaf = e.append(&json!({ "kind": "encryptedCast", "cast": cast_value }))?;
        let admitted = Admitted {
            leaf,
            ballot_digest,
            receipt_token,
        };
        let outcome = match held {
            Some(prev) => {
                e.append(
                    &json!({ "kind": "replaced", "tag": tag, "replaces": prev.leaf, "by": leaf }),
                )?;
                "replaced"
            }
            None => "counted",
        };
        e.exact.insert(cast_digest, admitted.clone());
        e.encrypted.insert(tag, (admitted.clone(), form));
        encrypted_receipt(e, &admitted, outcome, now)
    }
}

fn encrypted_receipt(
    e: &ElectionRecord,
    a: &Admitted,
    outcome: &str,
    now: DateTime<Utc>,
) -> Result<Value, Failure> {
    respond::<cast_encrypted::Response>(json!({
        "electionId": e.id(),
        "leafIndex": a.leaf,
        "entryHash": hash_text(e.board.leaf(a.leaf as usize).expect("admitted leaves exist")),
        "outcome": outcome,
        "receiptToken": a.receipt_token,
        "head": e.head(e.board.len(), now),
    }))
}
