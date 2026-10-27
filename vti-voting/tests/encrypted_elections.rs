//! Sealed and tallied-encrypted elections end to end (CONVENTIONS §9): the trustees generate the
//! key through the ballot box, voters cast encrypted ballots, two of three trustees decrypt after
//! close, and the box publishes the result — and a restored box rebuilds every step.

use std::{collections::BTreeSet, sync::Arc};

use chrono::{DateTime, Utc};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::{Value, json};
use trust_tasks_rs::specs::voting::{
    election::register::v0_1::Manifest,
    trustees::{
        authorize::v0_1 as authorize, confirm::v0_1 as confirm, deal::v0_1 as deal_task,
        decrypt::v0_1 as decrypt, enrol::v0_1 as enrol,
    },
};
use vti_voting::{
    audit::{AuditFailure, Evidence, HeadRef, audit},
    election::{Election, ElectionId},
    registrar::Registrar,
    rules::{digest_multibase, manifest_digest},
    service::{BallotBox, Caller, MemoryJournal, NoJournal},
    steps::ProvenRequests,
    trustees::{
        Dealing, Share, Threshold, TransportSecret, TrusteeKey, deal, open_share, partial_decrypt,
        seal_share, verify_share,
    },
    voter::{EncryptedForm, Voter, encrypted_form},
    wire,
};

const COMMUNITY: &str = "did:webvh:QmCommunity:vtc.example.org";
const BOX: &str = "did:webvh:QmVote:vote.example.net";
const TRUSTEES: [&str; 3] = [
    "did:webvh:QmT1:t1.example",
    "did:webvh:QmT2:t2.example",
    "did:webvh:QmT3:t3.example",
];

fn t(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

/// A trustee's request as the ballot box receives it. The box's host verifies the proof before
/// the box sees it; here the signer is simply the issuer.
fn request<P: trust_tasks_rs::Payload>(issuer: &str, payload: Value) -> Value {
    json!({
        "id": format!("urn:uuid:{}", payload.to_string().len()),
        "type": P::TYPE_URI.to_string(),
        "issuer": issuer,
        "recipient": BOX,
        "payload": payload,
        "proof": { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022" },
    })
}

/// A future that is ready at once (every verifier here is), without a runtime.
fn ready<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match f.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => v,
        std::task::Poll::Pending => unreachable!("every verifier here is ready at once"),
    }
}

/// The signers a verifier vouches for: each request's issuer, unless `refuse` says its proof
/// does not verify.
fn proven(entries: &[Value], refuse: impl Fn(&Value) -> bool) -> ProvenRequests {
    ready(ProvenRequests::prove(entries, |r: Value| {
        std::future::ready((!refuse(&r)).then(|| r["issuer"].as_str().unwrap().to_string()))
    }))
}

fn manifest(secrecy: &str, visibility: &str) -> Value {
    json!({
        "electionId": "board-2027",
        "community": COMMUNITY,
        "questions": [
            { "key": "chair", "type": "choice",
              "options": [{ "key": "ana" }, { "key": "ben" }, { "key": "cai" }],
              "minSelections": 1, "maxSelections": 1, "optional": true },
            { "key": "projects", "type": "choice",
              "options": [{ "key": "kiln" }, { "key": "laser" }],
              "minSelections": 0, "maxSelections": 2, "optional": false }
        ],
        "secrecy": secrecy,
        "trustees": { "dids": TRUSTEES, "threshold": 2 },
        "roll": { "rule": "members" },
        "registrationOpens": "2026-11-01T00:00:00Z",
        "votingOpens": "2026-11-03T00:00:00Z",
        "votingCloses": "2026-11-07T18:00:00Z",
        "revote": "replace",
        "board": { "visibility": visibility, "auditors": [] },
        "ballotBox": BOX,
        "binding": false,
        "allowEarlyClose": false,
        "resultsBeforeClose": false,
        "textReleaseThreshold": 10
    })
}

struct Trustee {
    transport: TransportSecret,
    shares: Vec<Share>,
    key: Option<TrusteeKey>,
}

struct Run {
    reg: Registrar,
    bb: BallotBox,
    journal: Arc<MemoryJournal>,
    manifest: Value,
    digest: [u8; 32],
    trustees: Vec<Trustee>,
    rng: StdRng,
}

const BEFORE: &str = "2026-11-02T00:00:00Z";
const DURING: &str = "2026-11-04T00:00:00Z";
const AFTER: &str = "2026-11-08T00:00:00Z";

impl Run {
    fn new(secrecy: &str) -> Self {
        Self::on_board(secrecy, "public")
    }

    fn on_board(secrecy: &str, visibility: &str) -> Self {
        let mut rng = StdRng::seed_from_u64(7);
        let reg = Registrar::generate(COMMUNITY, &mut rng).unwrap();
        let manifest = manifest(secrecy, visibility);
        let digest = manifest_digest(&manifest).unwrap();
        let journal = Arc::new(MemoryJournal::default());
        let mut bb = BallotBox::with_journal(BOX, journal.clone());
        bb.register(
            COMMUNITY,
            &json!({
                "community": COMMUNITY,
                "manifest": manifest,
                "manifestDigest": digest_multibase(&digest),
                "parameters": { "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() },
            }),
            t("2026-10-30T00:00:00Z"),
        )
        .unwrap();
        let trustees = (1..=3)
            .map(|j| Trustee {
                transport: TransportSecret::generate(j, &mut rng),
                shares: Vec::new(),
                key: None,
            })
            .collect();
        Self {
            reg,
            bb,
            journal,
            manifest,
            digest,
            trustees,
            rng,
        }
    }

    fn election(&self) -> Election {
        Election::new(
            COMMUNITY,
            ElectionId::new("board-2027").unwrap(),
            self.digest,
        )
        .unwrap()
    }

    fn sel(&self) -> Value {
        json!({ "community": COMMUNITY, "electionId": "board-2027" })
    }

    fn with(&self, extra: Value) -> Value {
        let mut v = self.sel();
        v.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        v
    }

    fn status(&mut self, now: &str) -> Value {
        let sel = self.sel();
        self.bb
            .trustees_status(Caller::Did(TRUSTEES[0]), &sel, t(now))
            .unwrap()
    }

    /// The whole key ceremony, each step as its trustee would send it.
    fn ceremony(&mut self) {
        let ctx = self.election().trustee_context();
        for j in 0..3 {
            let tk = self.trustees[j].transport.publish(&ctx, &mut self.rng);
            let p = request::<enrol::Payload>(
                TRUSTEES[j],
                self.with(json!({ "transportKey": wire::transport_key_value(&tk) })),
            );
            let a = self.bb.trustees_enrol(TRUSTEES[j], &p, t(BEFORE)).unwrap();
            // A repeat is the same answer, and nobody else may enrol as this trustee.
            assert_eq!(
                self.bb.trustees_enrol(TRUSTEES[j], &p, t(BEFORE)).unwrap(),
                a
            );
            let other = TRUSTEES[(j + 1) % 3];
            assert_eq!(
                self.bb
                    .trustees_enrol(other, &p, t(BEFORE))
                    .unwrap_err()
                    .local,
                "permissionDenied"
            );
        }
        assert_eq!(self.status(BEFORE)["phase"], "dealing");

        let tks: Vec<_> = self.status(BEFORE)["transportKeys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| wire::transport_key(v).unwrap())
            .collect();
        let th = Threshold::new(2, 3).unwrap();
        for i in 1..=3u32 {
            let (dealing, shares) = deal(i, th, &ctx, &mut self.rng).unwrap();
            let sealed = shares
                .iter()
                .map(|s| {
                    (
                        s.recipient,
                        seal_share(s, &tks[s.recipient as usize - 1], &ctx, &mut self.rng).unwrap(),
                    )
                })
                .collect();
            let sd = vti_voting::ceremony::SealedDealing {
                dealing,
                shares: sealed,
            };
            let p = request::<deal_task::Payload>(
                TRUSTEES[i as usize - 1],
                self.with(json!({ "dealing": wire::dealing_value(&sd) })),
            );
            self.bb
                .trustees_deal(TRUSTEES[i as usize - 1], &p, t(BEFORE))
                .unwrap();
        }
        let status = self.status(BEFORE);
        assert_eq!(status["phase"], "confirming");

        // Each trustee opens what the board holds for it and confirms.
        let dealings: Vec<_> = status["dealings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| wire::dealing(v).unwrap())
            .collect();
        for (j, did) in TRUSTEES.iter().enumerate() {
            let mut complaints = BTreeSet::new();
            let tr = &mut self.trustees[j];
            for sd in &dealings {
                let me = tr.transport.trustee;
                match open_share(&tr.transport, sd.dealing.dealer, &sd.shares[&me], &ctx)
                    .and_then(|s| verify_share(&sd.dealing, &s).map(|()| s))
                {
                    Ok(s) => tr.shares.push(s),
                    Err(_) => {
                        complaints.insert(sd.dealing.dealer);
                    }
                }
            }
            let p = request::<confirm::Payload>(
                did,
                self.with(json!({ "trustee": j + 1, "complaints": complaints })),
            );
            self.bb.trustees_confirm(did, &p, t(BEFORE)).unwrap();
        }
        let status = self.status(BEFORE);
        assert_eq!(status["phase"], "keyed");
        let ek = wire::election_key(&status["electionKey"], th).unwrap();
        let plain: Vec<Dealing> = dealings.iter().map(|d| d.dealing.clone()).collect();
        for tr in &mut self.trustees {
            tr.key = Some(
                TrusteeKey::from_shares(tr.transport.trustee, &tr.shares, &plain, &ek).unwrap(),
            );
        }
    }

    fn cast(&mut self, seed: u64, ballot: Value) -> Value {
        let params = self.reg.params();
        let mut r = StdRng::seed_from_u64(seed);
        let v = Voter::generate(&params, &mut r).unwrap();
        let e = self.election();
        let (req, st) = v.ticket_request(&params, &e, &mut r).unwrap();
        let pre = self.reg.issue_ticket(&e, v.id(), &req, &mut r).unwrap();
        let ticket = v.accept_ticket(&params, &e, &pre, &st).unwrap();
        let status = self.status(DURING);
        let ek = wire::election_key(&status["electionKey"], Threshold::new(2, 3).unwrap()).unwrap();
        let m: Manifest = serde_json::from_value(self.manifest.clone()).unwrap();
        let tag = v.tag_for(&params, &ticket, &mut r).unwrap();
        let form = encrypted_form(&m, &e, &ek, &ballot, &tag, &mut r).unwrap();
        let cast = v
            .cast_encrypted_wire(&params, &ticket, &form, &mut r)
            .unwrap();
        self.with(json!({ "cast": cast }))
    }

    /// Another ticket holder's cast of `form` — someone else's encrypted form, copied verbatim —
    /// under its own ticket and tag.
    fn recast(&mut self, seed: u64, form: EncryptedForm) -> Value {
        let params = self.reg.params();
        let mut r = StdRng::seed_from_u64(seed);
        let v = Voter::generate(&params, &mut r).unwrap();
        let e = self.election();
        let (req, st) = v.ticket_request(&params, &e, &mut r).unwrap();
        let pre = self.reg.issue_ticket(&e, v.id(), &req, &mut r).unwrap();
        let ticket = v.accept_ticket(&params, &e, &pre, &st).unwrap();
        let cast = v
            .cast_encrypted_wire(&params, &ticket, &form, &mut r)
            .unwrap();
        self.with(json!({ "cast": cast }))
    }

    fn ballot(&self, chair: Option<&str>, projects: &[&str]) -> Value {
        json!({
            "electionId": "board-2027",
            "manifestDigest": digest_multibase(&self.digest),
            "answers": [
                match chair {
                    Some(c) => json!({ "question": "chair", "choice": [c] }),
                    None => json!({ "question": "chair", "abstain": true }),
                },
                { "question": "projects", "choice": projects }
            ],
        })
    }

    /// Trustee `j` (0-based) decrypts every target the board lists.
    /// The community authorizes the decryption (CONVENTIONS §9.7): it reads the closed board,
    /// computes the targets itself, and pins their digest under the board through the close.
    fn authorize(&mut self) -> Value {
        let entries = self.entries();
        let params = self.reg.params();
        let closing = vti_voting::audit::decryption(
            &self.manifest,
            &params,
            &entries,
            &proven(&entries, |_| false),
        )
        .unwrap()
        .expect("the board has closed");
        let size = closing.index as usize + 1;
        let mut b = vti_voting::board::Board::new();
        for e in &entries[..size] {
            b.append(&serde_json_canonicalizer::to_vec(e).unwrap());
        }
        let values = closing.target_values();
        let payload = self.with(json!({
            "manifestDigest": digest_multibase(&self.digest),
            "head": { "electionId": "board-2027", "treeSize": size,
                      "rootHash": digest_multibase(&b.root(size).unwrap()),
                      "issuedAt": AFTER },
            "closedAt": closing.at,
            "targetCount": values.len(),
            "targetsDigest": vti_voting::audit::targets_digest(&values).unwrap(),
        }));
        let doc = request::<authorize::Payload>(COMMUNITY, payload);
        self.bb
            .trustees_authorize(COMMUNITY, &doc, t(AFTER))
            .unwrap()
    }

    fn decrypt(&mut self, j: usize) -> Value {
        let ctx = self.election().trustee_context();
        if self.status(AFTER).get("authorization").is_none() {
            self.authorize();
        }
        let status = self.status(AFTER);
        assert_eq!(status["phase"], "decrypting");
        let key = self.trustees[j].key.clone().unwrap();
        let partials: Vec<Value> = status["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tv| {
                let (target, ct) = wire::target(tv).unwrap();
                let p = partial_decrypt(&key, &ct, &ctx, &mut self.rng);
                wire::partial_value(&target, &ct, &p)
            })
            .collect();
        let p = request::<decrypt::Payload>(
            TRUSTEES[j],
            self.with(json!({ "trustee": j + 1, "partials": partials })),
        );
        self.bb.trustees_decrypt(TRUSTEES[j], &p, t(AFTER)).unwrap()
    }
}

impl Run {
    /// Certify the board as the community would (VTI-VOT-070 – 073): every entry, the head, the
    /// published result.
    fn certify(&mut self, tamper: impl Fn(&mut Vec<Value>)) -> Result<u64, AuditFailure> {
        self.certify_proving(tamper, |_| false)
    }

    /// The board's entries, as anyone it admits reads them.
    fn entries(&mut self) -> Vec<Value> {
        let board = self
            .bb
            .board_read(
                Caller::Did(COMMUNITY),
                &self.with(json!({ "from": 0, "limit": 1000 })),
                t(AFTER),
            )
            .unwrap();
        board["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["entry"].clone())
            .collect()
    }

    /// [`Self::certify`], with a verifier that does not vouch for the requests `refuse` names.
    fn certify_proving(
        &mut self,
        tamper: impl Fn(&mut Vec<Value>),
        refuse: impl Fn(&Value) -> bool,
    ) -> Result<u64, AuditFailure> {
        let sel = self.sel();
        let mut entries = self.entries();
        tamper(&mut entries);
        let proven = proven(&entries, refuse);
        let head = self
            .bb
            .board_head(Caller::Anonymous, &sel, t(AFTER))
            .unwrap();
        let result = self.bb.result(Caller::Anonymous, &sel, t(AFTER)).unwrap();
        let params = self.reg.params();
        // Tampered entries no longer hash to the head: certify against their own root, so the
        // check that fails is the recount's.
        let mut b = vti_voting::board::Board::new();
        for e in &entries {
            b.append(&serde_json_canonicalizer::to_vec(e).unwrap());
        }
        let head = if entries.len() as u64 == head["head"]["treeSize"].as_u64().unwrap() {
            HeadRef {
                tree_size: entries.len() as u64,
                root: b.root(entries.len()).unwrap(),
            }
        } else {
            HeadRef::from_wire(&head["head"]).unwrap()
        };
        audit(Evidence {
            manifest: &self.manifest,
            params: &params,
            entries: &entries,
            head,
            checkpoints: &[],
            result: &result["result"],
            tickets_issued: 10,
            proven: &proven,
        })
        .map(|v| v.ballots_counted)
    }
}

#[test]
fn vot_070_an_encrypted_board_certifies_and_a_doctored_opening_does_not() {
    let mut run = Run::new("sealed");
    run.ceremony();
    let p = run.cast(300, run.ballot(Some("ana"), &["kiln"]));
    run.bb.cast_encrypted(&p, t(DURING)).unwrap();
    let p = run.cast(301, run.ballot(Some("ben"), &[]));
    run.bb.cast_encrypted(&p, t(DURING)).unwrap();
    run.decrypt(0);
    run.decrypt(1);
    assert_eq!(run.certify(|_| {}), Ok(2));
    // An `unsealed` entry that says something other than what the partials open is caught.
    let err = run
        .certify(|entries| {
            let e = entries
                .iter_mut()
                .find(|e| e["kind"] == "unsealed")
                .unwrap();
            e["ballot"]["answers"][0]["choice"] = json!(["cai"]);
        })
        .unwrap_err();
    assert!(matches!(err, AuditFailure::ResultMismatch(_)), "{err:?}");

    let mut run = Run::new("talliedEncrypted");
    run.ceremony();
    let p = run.cast(310, run.ballot(Some("cai"), &["laser"]));
    run.bb.cast_encrypted(&p, t(DURING)).unwrap();
    run.decrypt(2);
    run.decrypt(1);
    assert_eq!(run.certify(|_| {}), Ok(1));
}

/// On a private board the trustees still read their ceremony, as themselves (CONVENTIONS §4,
/// §9.6): the election runs to its result. Anybody else is answered as if it did not exist.
#[test]
fn vot_062_a_private_board_runs_its_ceremony_for_its_trustees_alone() {
    let mut run = Run::on_board("sealed", "private");
    let sel = run.sel();
    assert_eq!(
        run.bb
            .trustees_status(Caller::Anonymous, &sel, t(BEFORE))
            .unwrap_err()
            .local,
        "electionUnknown"
    );
    assert_eq!(
        run.bb
            .trustees_status(Caller::Did("did:key:z6MkNotATrustee"), &sel, t(BEFORE))
            .unwrap_err()
            .local,
        "electionUnknown"
    );
    // A trustee reads the election itself — the manifest its tasks take, and later when voting
    // closed — and an outsider still learns nothing.
    let shown = run
        .bb
        .show(Caller::Did(TRUSTEES[2]), &sel, t(BEFORE))
        .unwrap();
    assert_eq!(shown["manifest"], run.manifest);
    assert_eq!(
        run.bb
            .show(Caller::Did("did:key:z6MkNotATrustee"), &sel, t(BEFORE))
            .unwrap_err()
            .local,
        "electionUnknown"
    );
    run.ceremony();
    let p = run.cast(400, run.ballot(Some("ben"), &[]));
    run.bb.cast_encrypted(&p, t(DURING)).unwrap();
    run.decrypt(1);
    assert_eq!(run.decrypt(2)["phase"], "done");
    // The result is the community's to read on a private board, not a trustee's.
    let result = run
        .bb
        .result(Caller::Did(COMMUNITY), &sel, t(AFTER))
        .unwrap();
    assert_eq!(
        result["result"]["questions"][0]["choice"],
        json!({ "ana": 0, "ben": 1, "cai": 0 })
    );
    assert!(
        run.bb
            .result(Caller::Did(TRUSTEES[0]), &sel, t(AFTER))
            .is_err()
    );
}

#[test]
fn vot_064_a_tallied_election_with_no_casts_tallies_to_zero() {
    let mut run = Run::new("talliedEncrypted");
    run.ceremony();
    let sel = run.sel();
    let result = run.bb.result(Caller::Anonymous, &sel, t(AFTER)).unwrap();
    assert_eq!(result["result"]["ballotsCounted"], 0);
    assert_eq!(
        result["result"]["questions"][0]["choice"],
        json!({ "ana": 0, "ben": 0, "cai": 0 })
    );
    assert_eq!(run.certify(|_| {}), Ok(0));
}

#[test]
fn vot_060_064_a_tallied_encrypted_election_reveals_only_totals() {
    let mut run = Run::new("talliedEncrypted");
    run.ceremony();
    let votes = [
        (Some("ana"), vec!["kiln"]),
        (Some("ben"), vec!["kiln", "laser"]),
        (Some("ana"), vec![]),
        (None, vec!["laser"]),
    ];
    let mut receipts = Vec::new();
    for (i, (chair, projects)) in votes.iter().enumerate() {
        let ballot = run.ballot(*chair, projects);
        let p = run.cast(100 + i as u64, ballot);
        let r = run.bb.cast_encrypted(&p, t(DURING)).unwrap();
        assert_eq!(r["outcome"], "counted");
        // A resend is the first receipt (VTI-VOT-042).
        let again = run.bb.cast_encrypted(&p, t(DURING)).unwrap();
        assert_eq!(again["outcome"], "alreadyCounted");
        assert_eq!(again["receiptToken"], r["receiptToken"]);
        assert_eq!(again["leafIndex"], r["leafIndex"]);
        receipts.push(r);
    }
    // The open cast task does not take an encrypted election's ballots.
    let open_cast = json!({ "community": COMMUNITY, "electionId": "board-2027", "cast": {} });
    assert!(run.bb.cast(&open_cast, t(DURING)).is_err());
    // Neither before close nor by one trustee alone is anything decrypted.
    let sel = run.sel();
    assert_eq!(
        run.bb
            .result(Caller::Anonymous, &sel, t(DURING))
            .unwrap_err()
            .local,
        "notTallied"
    );
    let a = run.decrypt(0);
    assert_eq!(a["phase"], "decrypting");
    let b = run.decrypt(2);
    assert_eq!(b["phase"], "done");
    let result = run.bb.result(Caller::Anonymous, &sel, t(AFTER)).unwrap();
    let q = &result["result"]["questions"];
    assert_eq!(result["result"]["ballotsCounted"], 4);
    assert_eq!(q[0]["choice"], json!({ "ana": 2, "ben": 1, "cai": 0 }));
    assert_eq!(q[0]["abstained"], 1, "single selection: derived");
    assert_eq!(q[1]["choice"], json!({ "kiln": 2, "laser": 2 }));
    assert_eq!(q[1]["abstained"], 0, "multiple selections: not derivable");

    // A restored box rebuilds the ceremony, the casts, the partials and the result.
    let mut restored =
        BallotBox::restore(BOX, Arc::new(NoJournal), run.journal.contents()).unwrap();
    assert_eq!(
        restored.result(Caller::Anonymous, &sel, t(AFTER)).unwrap(),
        result
    );
    assert_eq!(
        restored
            .trustees_status(Caller::Anonymous, &sel, t(AFTER))
            .unwrap(),
        run.status(AFTER)
    );
}

#[test]
fn vot_063_a_sealed_election_opens_each_ballot_after_close() {
    let mut run = Run::new("sealed");
    // Before the key is formed nobody can cast.
    run.ceremony();
    let ballot = run.ballot(Some("cai"), &["laser"]);
    let p = run.cast(200, ballot.clone());
    let r = run.bb.cast_encrypted(&p, t(DURING)).unwrap();
    let p2 = run.cast(201, run.ballot(Some("ana"), &[]));
    run.bb.cast_encrypted(&p2, t(DURING)).unwrap();
    run.decrypt(1);
    let done = run.decrypt(0);
    assert_eq!(done["phase"], "done");
    let sel = run.sel();
    let result = run.bb.result(Caller::Anonymous, &sel, t(AFTER)).unwrap();
    assert_eq!(result["result"]["ballotsCounted"], 2);
    assert_eq!(
        result["result"]["questions"][0]["choice"],
        json!({ "ana": 1, "ben": 0, "cai": 1 })
    );
    // The board holds the opened ballot at the cast's leaf.
    let board = run
        .bb
        .board_read(
            Caller::Anonymous,
            &run.with(json!({ "from": 0, "limit": 100 })),
            t(AFTER),
        )
        .unwrap();
    let unsealed: Vec<&Value> = board["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["entry"]["kind"] == "unsealed")
        .collect();
    assert_eq!(unsealed.len(), 2);
    assert!(
        unsealed
            .iter()
            .any(|e| e["entry"]["leafIndex"] == r["leafIndex"] && e["entry"]["ballot"] == ballot)
    );
}

#[test]
fn vot_062_casts_need_a_formed_key_and_the_elections_own_form() {
    let mut run = Run::new("sealed");
    // The ceremony never completes: at votingOpens it fails, and no cast is admitted.
    let ctx = run.election().trustee_context();
    let tk = run.trustees[0].transport.publish(&ctx, &mut run.rng);
    let p = request::<enrol::Payload>(
        TRUSTEES[0],
        run.with(json!({ "transportKey": wire::transport_key_value(&tk) })),
    );
    run.bb.trustees_enrol(TRUSTEES[0], &p, t(BEFORE)).unwrap();
    assert_eq!(run.status(DURING)["phase"], "failed");
    let fake = run.with(json!({ "cast": {
        "sealed": { "kem": { "a": "z11", "b": "z11" }, "body": "z11" },
        "tag": "z11", "attestation": "z11" } }));
    let err = run.bb.cast_encrypted(&fake, t(DURING)).unwrap_err();
    assert_eq!(err.local, "notOpen");
    // A trustee step after the ceremony failed is refused.
    let tk2 = run.trustees[1].transport.publish(&ctx, &mut run.rng);
    let p2 = request::<enrol::Payload>(
        TRUSTEES[1],
        run.with(json!({ "transportKey": wire::transport_key_value(&tk2) })),
    );
    assert_eq!(
        run.bb
            .trustees_enrol(TRUSTEES[1], &p2, t(DURING))
            .unwrap_err()
            .local,
        "notEnrolling"
    );

    // A well-formed encrypted form the election does not take — a tallied one at a sealed
    // election — is wrongLevel.
    let mut tallied = Run::new("talliedEncrypted");
    tallied.ceremony();
    let wrong = tallied.cast(900, tallied.ballot(Some("ana"), &[]));
    let mut run = Run::new("sealed");
    run.ceremony();
    assert_eq!(
        run.bb.cast_encrypted(&wrong, t(DURING)).unwrap_err().local,
        "wrongLevel"
    );
}

/// Every step of the ceremony is on the board as its trustee's own signed request (CONVENTIONS
/// §9.6), so a ballot box cannot take a trustee's place: a step whose proof nobody vouches for,
/// or that names another trustee than its signer, or a payload-only entry of the retired kinds,
/// is not the election's ceremony — and nothing formed from it is the election key.
#[test]
fn vot_062_a_trustee_step_counts_only_as_its_trustees_signed_request() {
    let mut run = Run::new("sealed");
    run.ceremony();
    let p = run.cast(500, run.ballot(Some("ana"), &[]));
    run.bb.cast_encrypted(&p, t(DURING)).unwrap();
    run.decrypt(0);
    run.decrypt(1);
    assert_eq!(run.certify(|_| {}), Ok(1));

    let steps: Vec<Value> = run
        .entries()
        .into_iter()
        .filter(|e| e["kind"].is_string())
        .collect();
    assert!(
        steps
            .iter()
            .all(|e| !vti_voting::steps::RETIRED_KINDS.contains(&e["kind"].as_str().unwrap())),
        "no payload-only trustee entry is appended"
    );
    let step = |e: &Value| e["kind"] == "trusteeStep";
    assert_eq!(
        steps.iter().filter(|e| step(e)).count(),
        9,
        "3 enrol, 3 deal, 3 confirm"
    );

    let ceremony = |f: AuditFailure| matches!(f, AuditFailure::CeremonyInvalid { .. });
    // A dealing the verifier does not vouch for — as a box-made dealing in trustee 2's name
    // would be — fails, before anything is decrypted.
    let is_deal_2 = |r: &Value| {
        r["issuer"] == TRUSTEES[1] && r["type"].as_str().unwrap().contains("/trustees/deal/")
    };
    let err = run.certify_proving(|_| {}, is_deal_2).unwrap_err();
    assert!(ceremony(err.clone()), "{err:?}");
    // A step proven for one trustee, at another trustee's index.
    let err = run
        .certify(|entries| {
            let e = entries
                .iter_mut()
                .find(|e| e["kind"] == "trusteeStep" && e["request"]["issuer"] == TRUSTEES[1])
                .unwrap();
            e["request"]["issuer"] = json!(TRUSTEES[0]);
        })
        .unwrap_err();
    assert!(ceremony(err.clone()), "{err:?}");
    // The retired payload-only form carries no proof, and is refused outright.
    let err = run
        .certify(|entries| {
            let e = entries
                .iter_mut()
                .find(|e| e["kind"] == "trusteeStep")
                .unwrap();
            *e = json!({ "kind": "transportKey",
                         "transportKey": e["request"]["payload"]["transportKey"].clone() });
        })
        .unwrap_err();
    assert!(ceremony(err.clone()), "{err:?}");

    // The key a community shows its voters is formed from the proven steps alone.
    let entries = run.entries();
    let status = run.status(AFTER);
    let key = vti_voting::audit::election_key(
        &run.manifest,
        COMMUNITY,
        &entries,
        &proven(&entries, |_| false),
    )
    .unwrap();
    assert_eq!(key.as_ref(), Some(&status["electionKey"]));
    assert!(
        vti_voting::audit::election_key(
            &run.manifest,
            COMMUNITY,
            &entries,
            &proven(&entries, is_deal_2)
        )
        .is_err()
    );
    // Before the key forms there is none to show.
    let before: Vec<Value> = entries
        .iter()
        .take_while(|e| e["kind"] != "electionKey")
        .cloned()
        .collect();
    assert_eq!(
        vti_voting::audit::election_key(
            &run.manifest,
            COMMUNITY,
            &before,
            &proven(&before, |_| false)
        ),
        Ok(None)
    );
}

/// A ballot copied into another cast is not a vote (CONVENTIONS §9.3 – 9.5): its ciphertexts are
/// already on the board under another tag, and its proofs, or its seal, hold only under the tag it
/// was made for. Without this a voter could re-cast a target's encrypted ballot verbatim and read
/// the target's vote off the totals (Cortier–Smyth).
#[test]
fn vot_064_a_copied_ballot_is_not_a_vote() {
    for (level, field) in [("talliedEncrypted", "encrypted"), ("sealed", "sealed")] {
        let mut run = Run::new(level);
        run.ceremony();
        let victim = run.cast(600, run.ballot(Some("ana"), &["kiln"]));
        run.bb.cast_encrypted(&victim, t(DURING)).unwrap();
        let form = victim["cast"][field].clone();
        let form = if field == "sealed" {
            EncryptedForm::Sealed(form)
        } else {
            EncryptedForm::Encrypted(form)
        };
        let copied = run.recast(601, form);
        assert_eq!(
            run.bb.cast_encrypted(&copied, t(DURING)).unwrap_err().local,
            "ballotInvalid",
            "{level}"
        );
    }
}

/// A board is the election's lifecycle in order (CONVENTIONS §3.9): a cast moved after the close
/// does not certify, however well every entry verifies on its own.
#[test]
fn vot_071_a_board_out_of_the_elections_order_does_not_certify() {
    let mut run = Run::new("sealed");
    run.ceremony();
    let p = run.cast(700, run.ballot(Some("ben"), &[]));
    run.bb.cast_encrypted(&p, t(DURING)).unwrap();
    run.decrypt(0);
    run.decrypt(1);
    assert_eq!(run.certify(|_| {}), Ok(1));
    let err = run
        .certify(|entries| {
            let cast = entries
                .iter()
                .position(|e| e["kind"] == "encryptedCast")
                .unwrap();
            let closed = entries.iter().position(|e| e["kind"] == "closed").unwrap();
            let moved = entries.remove(cast);
            entries.insert(closed, moved);
        })
        .unwrap_err();
    assert!(matches!(err, AuditFailure::OrderInvalid { .. }), "{err:?}");
}

/// A ballot box that stopped between the last partial and the result finishes the decryption when
/// it restarts, as the step cut short would have — never stuck closed without a result.
#[test]
fn vot_063_a_restart_finishes_a_decryption_cut_short() {
    let mut run = Run::new("sealed");
    run.ceremony();
    let p = run.cast(800, run.ballot(Some("cai"), &["laser"]));
    run.bb.cast_encrypted(&p, t(DURING)).unwrap();
    run.decrypt(0);
    run.decrypt(1);
    let sel = run.sel();
    let result = run.bb.result(Caller::Anonymous, &sel, t(AFTER)).unwrap();
    let mut contents = run.journal.contents();
    for r in &mut contents {
        while let Some(last) = r.entries.last() {
            let v: Value = serde_json::from_slice(last).unwrap();
            if v["kind"] == "partials" {
                break;
            }
            r.entries.pop();
        }
    }
    let mut restored = BallotBox::restore(BOX, Arc::new(NoJournal), contents).unwrap();
    let again = restored.result(Caller::Anonymous, &sel, t(AFTER)).unwrap();
    assert_eq!(again["result"]["questions"], result["result"]["questions"]);
    assert_eq!(again["result"]["ballotsCounted"], 1);
}
