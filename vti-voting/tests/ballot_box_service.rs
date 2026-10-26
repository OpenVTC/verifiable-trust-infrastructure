//! The ballot box end to end: register, tickets, casts, revotes, the board, the result.

use chrono::{DateTime, Duration, Utc};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::{Value, json};
use vti_voting::{
    board::{Hash, verify_consistency, verify_inclusion},
    election::{Election, ElectionId},
    registrar::Registrar,
    rules::{digest_from_multibase, digest_multibase, manifest_digest},
    service::{BallotBox, Caller},
    voter::{Ticket, Voter},
};

#[test]
fn a_restored_ballot_box_answers_as_the_original() {
    use std::sync::Arc;
    use vti_voting::service::{MemoryJournal, NoJournal};

    let s = setup("public", "replace", false);
    let journal = Arc::new(MemoryJournal::default());
    let mut bb = BallotBox::with_journal(BOX, journal.clone());
    let reg_payload = json!({
        "community": COMMUNITY,
        "manifest": s.manifest,
        "manifestDigest": digest_multibase(&s.digest),
        "parameters": { "suite": "ps-ddh-bls12381", "votingKey": s.reg.public_text().unwrap() },
    });
    bb.register(COMMUNITY, &reg_payload, t("2026-10-30T00:00:00Z"))
        .unwrap();
    let now = t("2026-11-04T00:00:00Z");
    let (v, ticket) = s.voter(10);
    let first = s.cast_payload(&v, &ticket, &s.ballot("yes", None), 11);
    let receipt = bb.cast(&first, now).unwrap();
    let second = s.cast_payload(&v, &ticket, &s.ballot("no", None), 12);
    bb.cast(&second, now).unwrap();
    let (w, wticket) = s.voter(20);
    bb.cast(
        &s.cast_payload(&w, &wticket, &s.ballot("yes", None), 21),
        now,
    )
    .unwrap();
    let head = bb.board_head(Caller::Anonymous, &s.sel(), now).unwrap();

    // One box per journal: the restored box writes to its own.
    let mut restored = BallotBox::restore(BOX, Arc::new(NoJournal), journal.contents()).unwrap();
    assert_eq!(
        restored
            .board_head(Caller::Anonymous, &s.sel(), now)
            .unwrap(),
        head
    );
    // A resend after the restart is the first receipt, token included.
    let again = restored.cast(&first, now).unwrap();
    assert_eq!(again["outcome"], "alreadyCounted");
    assert_eq!(again["receiptToken"], receipt["receiptToken"]);
    // And the count after close is the same as the original's.
    let after = t("2026-11-08T00:00:00Z");
    let a = bb.result(Caller::Anonymous, &s.sel(), after).unwrap();
    let b = restored.result(Caller::Anonymous, &s.sel(), after).unwrap();
    assert_eq!(a["result"]["questions"], b["result"]["questions"]);
    assert_eq!(
        b["result"]["questions"][0]["choice"],
        json!({ "yes": 1, "no": 1 })
    );
}

const COMMUNITY: &str = "did:webvh:QmCommunity:vtc.example.org";
const BOX: &str = "did:webvh:QmVote:vote.example.net";
const AUDITOR: &str = "did:webvh:QmAudit:audit.example.com";

fn t(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

fn manifest(visibility: &str, revote: &str, early: bool) -> Value {
    json!({
        "electionId": "agm-2027",
        "community": COMMUNITY,
        "questions": [
            { "key": "budget", "type": "choice",
              "options": [{ "key": "yes" }, { "key": "no" }],
              "minSelections": 1, "maxSelections": 1, "optional": false },
            { "key": "improve", "type": "text", "maxLength": 200, "optional": true }
        ],
        "secrecy": "open",
        "roll": { "rule": "members" },
        "registrationOpens": "2026-11-01T00:00:00Z",
        "votingOpens": "2026-11-03T00:00:00Z",
        "votingCloses": "2026-11-07T18:00:00Z",
        "revote": revote,
        "board": { "visibility": visibility, "auditors": [AUDITOR] },
        "ballotBox": BOX,
        "binding": false,
        "allowEarlyClose": early,
        "resultsBeforeClose": false,
        "textReleaseThreshold": 10
    })
}

struct Setup {
    reg: Registrar,
    bb: BallotBox,
    manifest: Value,
    digest: [u8; 32],
}

fn setup(visibility: &str, revote: &str, early: bool) -> Setup {
    let reg = Registrar::generate(COMMUNITY, &mut StdRng::seed_from_u64(1)).unwrap();
    let manifest = manifest(visibility, revote, early);
    let digest = manifest_digest(&manifest).unwrap();
    let mut bb = BallotBox::new(BOX);
    let payload = json!({
        "community": COMMUNITY,
        "manifest": manifest,
        "manifestDigest": digest_multibase(&digest),
        "parameters": { "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() },
    });
    let answer = bb
        .register(COMMUNITY, &payload, t("2026-10-30T00:00:00Z"))
        .unwrap();
    assert_eq!(answer["election"]["state"], "registered");
    // Registering the same thing again is the same answer (conventions §8.2).
    assert!(
        bb.register(COMMUNITY, &payload, t("2026-10-30T00:00:00Z"))
            .is_ok()
    );
    Setup {
        reg,
        bb,
        manifest,
        digest,
    }
}

impl Setup {
    fn election(&self) -> Election {
        Election::new(COMMUNITY, ElectionId::new("agm-2027").unwrap(), self.digest).unwrap()
    }

    fn voter(&self, seed: u64) -> (Voter, Ticket) {
        let params = self.reg.params();
        let mut r = StdRng::seed_from_u64(seed);
        let v = Voter::generate(&params, &mut r).unwrap();
        let e = self.election();
        let (req, st) = v.ticket_request(&params, &e, &mut r).unwrap();
        let pre = self.reg.issue_ticket(&e, v.id(), &req, &mut r).unwrap();
        let ticket = v.accept_ticket(&params, &e, &pre, &st).unwrap();
        (v, ticket)
    }

    fn ballot(&self, choice: &str, text: Option<&str>) -> Value {
        json!({
            "electionId": "agm-2027",
            "manifestDigest": digest_multibase(&self.digest),
            "answers": [
                { "question": "budget", "choice": [choice] },
                match text {
                    Some(t) => json!({ "question": "improve", "text": t }),
                    None => json!({ "question": "improve", "abstain": true }),
                }
            ],
        })
    }

    fn cast_payload(&self, v: &Voter, ticket: &Ticket, ballot: &Value, seed: u64) -> Value {
        let cast = v
            .cast_wire(
                &self.reg.params(),
                ticket,
                ballot,
                &mut StdRng::seed_from_u64(seed),
            )
            .unwrap();
        json!({ "community": COMMUNITY, "electionId": "agm-2027", "cast": cast })
    }

    fn sel(&self) -> Value {
        json!({ "community": COMMUNITY, "electionId": "agm-2027" })
    }
}

fn hash(text: &Value) -> Hash {
    digest_from_multibase(text.as_str().unwrap()).unwrap()
}

#[test]
fn vot_040_casts_are_refused_until_voting_opens() {
    let mut s = setup("public", "replace", false);
    let (v, ticket) = s.voter(10);
    let p = s.cast_payload(&v, &ticket, &s.ballot("yes", None), 11);
    let err = s.bb.cast(&p, t("2026-11-02T00:00:00Z")).unwrap_err();
    assert_eq!(err.local, "notOpen");
    assert!(s.bb.cast(&p, t("2026-11-03T00:00:01Z")).is_ok());
}

#[test]
fn vot_041_042_revote_resend_and_refusal() {
    let mut s = setup("public", "replace", false);
    let now = t("2026-11-04T00:00:00Z");
    let (v, ticket) = s.voter(10);
    let first = s.cast_payload(&v, &ticket, &s.ballot("yes", None), 11);
    let a = s.bb.cast(&first, now).unwrap();
    assert_eq!(a["outcome"], "counted");
    // A resend is the first receipt, counted once (VTI-VOT-042).
    let again = s.bb.cast(&first, now).unwrap();
    assert_eq!(again["outcome"], "alreadyCounted");
    assert_eq!(again["receiptToken"], a["receiptToken"]);
    // A different ballot under the same ticket replaces the first (VTI-VOT-041).
    let second = s.cast_payload(&v, &ticket, &s.ballot("no", None), 12);
    let b = s.bb.cast(&second, now).unwrap();
    assert_eq!(b["outcome"], "replaced");
    // Replaying the old cast does not undo the revote.
    assert_eq!(s.bb.cast(&first, now).unwrap()["outcome"], "alreadyCounted");

    let mut r = setup("public", "refuse", false);
    let (v, ticket) = r.voter(10);
    r.bb.cast(
        &r.cast_payload(&v, &ticket, &r.ballot("yes", None), 11),
        now,
    )
    .unwrap();
    let err =
        r.bb.cast(&r.cast_payload(&v, &ticket, &r.ballot("no", None), 12), now)
            .unwrap_err();
    assert_eq!(err.local, "alreadyVoted");
}

#[test]
fn vot_040_a_tampered_cast_is_refused() {
    let mut s = setup("public", "replace", false);
    let now = t("2026-11-04T00:00:00Z");
    let (v, ticket) = s.voter(10);
    let mut p = s.cast_payload(&v, &ticket, &s.ballot("yes", None), 11);
    p["cast"]["ballot"]["answers"][0]["choice"] = json!(["no"]);
    assert_eq!(s.bb.cast(&p, now).unwrap_err().local, "castInvalid");
    let mut p = s.cast_payload(&v, &ticket, &s.ballot("yes", None), 11);
    p["cast"]["ballot"]["answers"][0]["choice"] = json!(["maybe"]);
    assert_eq!(s.bb.cast(&p, now).unwrap_err().local, "ballotInvalid");
}

/// VTI-VOT-045 without the lock: the costly checks run on a [`CastCheck`] apart from the box,
/// and what they prove admits that one cast — never another sent with it.
#[test]
fn a_cast_checked_apart_from_the_box_is_admitted_and_nothing_else_is() {
    let mut s = setup("public", "replace", false);
    let now = t("2026-11-04T00:00:00Z");
    let (v, ticket) = s.voter(10);
    let first = s.cast_payload(&v, &ticket, &s.ballot("yes", None), 11);

    let verified =
        s.bb.cast_check(&first, now)
            .unwrap()
            .expect("a new cast needs its checks")
            .run()
            .unwrap();
    let receipt = s.bb.cast_verified(&first, &verified, now).unwrap();
    assert_eq!(receipt["outcome"], "counted");
    // A resend needs no costly check: the box answers it with the first receipt.
    assert!(s.bb.cast_check(&first, now).unwrap().is_none());
    assert_eq!(
        s.bb.cast_verified(&first, &verified, now).unwrap()["receiptToken"],
        receipt["receiptToken"]
    );

    // What proved one cast does not admit a tampered one: the box checks it in full.
    let mut tampered = s.cast_payload(&v, &ticket, &s.ballot("yes", None), 12);
    tampered["cast"]["ballot"]["answers"][0]["choice"] = json!(["no"]);
    assert_eq!(
        s.bb.cast_verified(&tampered, &verified, now)
            .unwrap_err()
            .local,
        "castInvalid"
    );
    // And a tampered cast's own check fails apart from the box as it would inside.
    let check = s.bb.cast_check(&tampered, now).unwrap().unwrap();
    assert_eq!(check.run().unwrap_err().local, "castInvalid");

    // A refusal the cheap checks find needs no costly one.
    let mut early = setup("public", "replace", false);
    assert_eq!(
        early
            .bb
            .cast_check(&first, t("2026-11-02T00:00:00Z"))
            .unwrap_err()
            .local,
        "notOpen"
    );
}

/// What a registration quota counts: elections registered here and not yet finished.
#[test]
fn the_box_counts_a_communitys_unfinished_elections() {
    let mut s = setup("public", "replace", false);
    assert!(s.bb.holds(COMMUNITY, "agm-2027"));
    assert!(!s.bb.holds(COMMUNITY, "another"));
    assert_eq!(s.bb.unfinished(COMMUNITY), 1);
    assert_eq!(s.bb.unfinished("did:webvh:QmOther:other.example.org"), 0);
    s.bb.cancel(
        COMMUNITY,
        &json!({ "community": COMMUNITY, "electionId": "agm-2027", "reason": "test" }),
        t("2026-11-04T00:00:00Z"),
    )
    .unwrap();
    assert_eq!(s.bb.unfinished(COMMUNITY), 0);
}

#[test]
fn vot_050_receipts_prove_inclusion_and_heads_stay_consistent() {
    let mut s = setup("public", "replace", false);
    let now = t("2026-11-04T00:00:00Z");
    let mut receipts = Vec::new();
    for i in 0..5 {
        let (v, ticket) = s.voter(100 + i);
        let p = s.cast_payload(&v, &ticket, &s.ballot("yes", None), 200 + i);
        receipts.push(s.bb.cast(&p, now).unwrap());
    }
    let early = s.bb.board_head(Caller::Anonymous, &s.sel(), now).unwrap()["head"].clone();
    let (v, ticket) = s.voter(999);
    s.bb.cast(
        &s.cast_payload(&v, &ticket, &s.ballot("no", None), 1000),
        now,
    )
    .unwrap();
    let late = s.bb.board_head(Caller::Anonymous, &s.sel(), now).unwrap()["head"].clone();

    let r = &receipts[2];
    let size = late["treeSize"].as_u64().unwrap();
    let mut q = s.sel();
    q["leafIndex"] = r["leafIndex"].clone();
    q["treeSize"] = json!(size);
    let proof = s.bb.board_inclusion(Caller::Anonymous, &q, now).unwrap();
    let path: Vec<Hash> = proof["path"].as_array().unwrap().iter().map(hash).collect();
    assert!(verify_inclusion(
        r["leafIndex"].as_u64().unwrap() as usize,
        size as usize,
        &hash(&r["entryHash"]),
        &path,
        &hash(&late["rootHash"]),
    ));

    let (first, second) = (early["treeSize"].as_u64().unwrap(), size);
    let mut q = s.sel();
    q["firstSize"] = json!(first);
    q["secondSize"] = json!(second);
    let c = s.bb.board_consistency(Caller::Anonymous, &q, now).unwrap();
    let path: Vec<Hash> = c["path"].as_array().unwrap().iter().map(hash).collect();
    assert!(verify_consistency(
        first as usize,
        second as usize,
        &hash(&early["rootHash"]),
        &hash(&late["rootHash"]),
        &path
    ));

    // The board carries no time of arrival on a cast entry.
    let mut q = s.sel();
    q["from"] = json!(0);
    q["limit"] = json!(100);
    let page = s.bb.board_read(Caller::Anonymous, &q, now).unwrap();
    for item in page["entries"].as_array().unwrap() {
        if item["entry"]["kind"] == "cast" {
            assert!(item["entry"].get("at").is_none());
        }
    }
}

#[test]
fn vot_052_a_private_board_answers_only_its_readers() {
    let mut s = setup("private", "replace", false);
    let now = t("2026-11-04T00:00:00Z");
    let (v, ticket) = s.voter(10);
    let receipt =
        s.bb.cast(
            &s.cast_payload(&v, &ticket, &s.ballot("yes", None), 11),
            now,
        )
        .unwrap();
    let sel = s.sel();
    assert_eq!(
        s.bb.board_head(Caller::Anonymous, &sel, now)
            .unwrap_err()
            .local,
        "electionUnknown"
    );
    assert_eq!(
        s.bb.board_head(Caller::Did("did:example:stranger"), &sel, now)
            .unwrap_err()
            .local,
        "electionUnknown"
    );
    assert!(s.bb.board_head(Caller::Did(AUDITOR), &sel, now).is_ok());
    assert!(s.bb.board_head(Caller::Did(COMMUNITY), &sel, now).is_ok());

    // The receipt's token admits that one leaf's inclusion, anonymously.
    let size =
        s.bb.board_head(Caller::Did(COMMUNITY), &sel, now).unwrap()["head"]["treeSize"].clone();
    let mut q = s.sel();
    q["leafIndex"] = receipt["leafIndex"].clone();
    q["treeSize"] = size;
    q["receiptToken"] = receipt["receiptToken"].clone();
    assert!(s.bb.board_inclusion(Caller::Anonymous, &q, now).is_ok());
    q["leafIndex"] = json!(0);
    assert_eq!(
        s.bb.board_inclusion(Caller::Anonymous, &q, now)
            .unwrap_err()
            .local,
        "electionUnknown"
    );
}

#[test]
fn vot_070_the_board_closes_and_tallies_on_its_own_clock() {
    let mut s = setup("public", "replace", false);
    let open = t("2026-11-04T00:00:00Z");
    for i in 0..11 {
        let (v, ticket) = s.voter(300 + i);
        let choice = if i < 7 { "yes" } else { "no" };
        let p = s.cast_payload(
            &v,
            &ticket,
            &s.ballot(choice, Some("more evenings")),
            400 + i,
        );
        s.bb.cast(&p, open).unwrap();
    }
    assert_eq!(
        s.bb.result(Caller::Anonymous, &s.sel(), open)
            .unwrap_err()
            .local,
        "notTallied"
    );
    let after = t("2026-11-07T18:00:00Z") + Duration::seconds(1);
    let r = s.bb.result(Caller::Anonymous, &s.sel(), after).unwrap();
    assert_eq!(r["state"], "tallied");
    assert_eq!(r["provisional"], false);
    assert_eq!(r["result"]["ballotsCounted"], 11);
    assert_eq!(
        r["result"]["questions"][0]["choice"],
        json!({ "yes": 7, "no": 4 })
    );
    assert_eq!(
        r["result"]["questions"][1]["text"]
            .as_array()
            .unwrap()
            .len(),
        11
    );
    // Voting is over.
    let (v, ticket) = s.voter(999);
    let late = s.cast_payload(&v, &ticket, &s.ballot("yes", None), 1000);
    assert_eq!(s.bb.cast(&late, after).unwrap_err().local, "notOpen");
    // The manifest the board holds is the one registered.
    let shown = s.bb.show(Caller::Anonymous, &s.sel(), after).unwrap();
    assert_eq!(shown["manifest"], s.manifest);
}

#[test]
fn vot_012_013_only_the_community_registers_closes_or_cancels() {
    let mut s = setup("public", "replace", true);
    let now = t("2026-11-04T00:00:00Z");
    let mut sel = s.sel();
    sel["reason"] = json!("quorum reached");
    assert_eq!(
        s.bb.close("did:example:stranger", &sel, now)
            .unwrap_err()
            .local,
        "permissionDenied"
    );
    let closed = s.bb.close(COMMUNITY, &sel, now).unwrap();
    assert_eq!(closed["election"]["state"], "tallied");
    assert_eq!(
        s.bb.cancel(COMMUNITY, &sel, now).unwrap_err().local,
        "notOpen"
    );

    // Another manifest under the same identifier is a conflict.
    let mut other = s.manifest.clone();
    other["title"] = json!("changed");
    let payload = json!({
        "community": COMMUNITY,
        "manifest": other,
        "manifestDigest": digest_multibase(&manifest_digest(&other).unwrap()),
        "parameters": { "suite": "ps-ddh-bls12381", "votingKey": s.reg.public_text().unwrap() },
    });
    assert_eq!(
        s.bb.register(COMMUNITY, &payload, now).unwrap_err().local,
        "alreadyRegistered"
    );
}
