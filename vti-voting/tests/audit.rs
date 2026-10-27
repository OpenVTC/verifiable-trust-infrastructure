//! The auditor over a real board: an election run through the ballot box, then its board
//! re-verified from the published key alone — and every kind of tampering caught.

use chrono::{DateTime, Utc};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::{Value, json};
use vti_voting::{
    audit::{AuditFailure, Evidence, HeadRef, audit},
    election::{Election, ElectionId},
    registrar::Registrar,
    rules::{digest_multibase, manifest_digest},
    service::{BallotBox, Caller},
    voter::Voter,
};

const COMMUNITY: &str = "did:webvh:QmCommunity:vtc.example.org";
const BOX: &str = "did:webvh:QmVote:vote.example.net";

fn t(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

fn manifest(revote: &str) -> Value {
    json!({
        "electionId": "agm-2027",
        "community": COMMUNITY,
        "questions": [{ "key": "budget", "type": "choice",
            "options": [{ "key": "yes" }, { "key": "no" }],
            "minSelections": 1, "maxSelections": 1, "optional": false }],
        "secrecy": "open",
        "roll": { "rule": "members" },
        "registrationOpens": "2026-11-01T00:00:00Z",
        "votingOpens": "2026-11-03T00:00:00Z",
        "votingCloses": "2026-11-07T18:00:00Z",
        "revote": revote,
        "board": { "visibility": "public", "auditors": [] },
        "ballotBox": BOX,
        "binding": false,
        "allowEarlyClose": false,
        "resultsBeforeClose": false,
        "textReleaseThreshold": 10
    })
}

/// A closed election: three voters, one of whom changed their vote. Returns everything a
/// certification reads, and a checkpoint taken while voting was open.
struct Run {
    reg: Registrar,
    manifest: Value,
    entries: Vec<Value>,
    head: HeadRef,
    checkpoint: HeadRef,
    result: Value,
}

fn run(revote: &str) -> Run {
    let reg = Registrar::generate(COMMUNITY, &mut StdRng::seed_from_u64(1)).unwrap();
    let manifest = manifest(revote);
    let digest = manifest_digest(&manifest).unwrap();
    let mut bb = BallotBox::new(BOX);
    let sel = json!({ "community": COMMUNITY, "electionId": "agm-2027" });
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
    let election = Election::new(COMMUNITY, ElectionId::new("agm-2027").unwrap(), digest).unwrap();
    let params = reg.params();
    let ballot = |choice: &str| {
        json!({
            "electionId": "agm-2027",
            "manifestDigest": digest_multibase(&digest),
            "answers": [{ "question": "budget", "choice": [choice] }],
        })
    };
    let now = t("2026-11-04T00:00:00Z");
    let mut checkpoint = None;
    for (seed, choices) in [
        (10u64, vec!["yes", "no"]),
        (20, vec!["yes"]),
        (30, vec!["no"]),
    ] {
        let mut r = StdRng::seed_from_u64(seed);
        let v = Voter::generate(&params, &mut r).unwrap();
        let (req, st) = v.ticket_request(&params, &election, &mut r).unwrap();
        let pre = reg.issue_ticket(&election, v.id(), &req, &mut r).unwrap();
        let ticket = v.accept_ticket(&params, &election, &pre, &st).unwrap();
        for choice in choices {
            if revote == "refuse" && choice == "no" && seed == 10 {
                continue;
            }
            let cast = v
                .cast_wire(&params, &ticket, &ballot(choice), &mut r)
                .unwrap();
            bb.cast(
                &json!({ "community": COMMUNITY, "electionId": "agm-2027", "cast": cast }),
                now,
            )
            .unwrap();
        }
        if checkpoint.is_none() {
            let head = bb.board_head(Caller::Anonymous, &sel, now).unwrap();
            checkpoint = Some(HeadRef::from_wire(&head["head"]).unwrap());
        }
    }
    let after = t("2026-11-08T00:00:00Z");
    let result = bb.result(Caller::Anonymous, &sel, after).unwrap()["result"].clone();
    let head = bb.board_head(Caller::Anonymous, &sel, after).unwrap()["head"].clone();
    let read = bb
        .board_read(
            Caller::Anonymous,
            &json!({ "community": COMMUNITY, "electionId": "agm-2027", "from": 0, "limit": 100 }),
            after,
        )
        .unwrap();
    let entries = read["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["entry"].clone())
        .collect();
    Run {
        reg,
        manifest,
        entries,
        head: HeadRef::from_wire(&head).unwrap(),
        checkpoint: checkpoint.unwrap(),
        result,
    }
}

fn check(r: &Run, entries: &[Value], result: &Value, tickets: u64) -> Result<u64, AuditFailure> {
    let params = r.reg.params();
    audit(Evidence {
        manifest: &r.manifest,
        params: &params,
        entries,
        head: r.head,
        checkpoints: &[r.checkpoint],
        result,
        tickets_issued: tickets,
        proven: &Default::default(),
    })
    .map(|v| v.ballots_counted)
}

#[test]
fn an_honest_board_verifies_from_the_published_key_alone() {
    let r = run("replace");
    assert_eq!(check(&r, &r.entries, &r.result, 3), Ok(3));
    assert_eq!(
        r.result["questions"][0]["choice"],
        json!({ "yes": 1, "no": 2 })
    );
}

#[test]
fn every_kind_of_tampering_is_caught() {
    let r = run("replace");

    // An entry rewritten: the board no longer hashes to its head.
    let mut rewritten = r.entries.clone();
    let i = rewritten.iter().position(|e| e["kind"] == "cast").unwrap();
    rewritten[i]["cast"]["ballot"]["answers"][0]["choice"] = json!(["no"]);
    assert_eq!(
        check(&r, &rewritten, &r.result, 3),
        Err(AuditFailure::RootMismatch)
    );

    // A checkpoint the board does not extend: the ballot box rewrote history after it.
    let params = r.reg.params();
    let forged = HeadRef {
        tree_size: r.checkpoint.tree_size,
        root: [7u8; 32],
    };
    assert_eq!(
        audit(Evidence {
            manifest: &r.manifest,
            params: &params,
            entries: &r.entries,
            head: r.head,
            checkpoints: &[forged],
            result: &r.result,
            tickets_issued: 3,
            proven: &Default::default(),
        })
        .unwrap_err(),
        AuditFailure::CheckpointInconsistent {
            tree_size: r.checkpoint.tree_size
        }
    );

    // A published result other than the board's.
    let mut inflated = r.result.clone();
    inflated["questions"][0]["choice"]["yes"] = json!(2);
    assert!(matches!(
        check(&r, &r.entries, &inflated, 3),
        Err(AuditFailure::ResultMismatch(_))
    ));

    // More ballots than the community issued tickets for.
    assert_eq!(
        check(&r, &r.entries, &r.result, 2),
        Err(AuditFailure::CountExceedsTickets {
            counted: 3,
            issued: 2
        })
    );

    // Another community's key: no cast verifies.
    let other = Registrar::generate(COMMUNITY, &mut StdRng::seed_from_u64(99)).unwrap();
    let other_params = other.params();
    assert!(matches!(
        audit(Evidence {
            manifest: &r.manifest,
            params: &other_params,
            entries: &r.entries,
            head: r.head,
            checkpoints: &[],
            result: &r.result,
            tickets_issued: 3,
            proven: &Default::default(),
        }),
        Err(AuditFailure::CastInvalid { .. })
    ));
}

#[test]
fn a_refuse_board_verifies_too() {
    let r = run("refuse");
    assert_eq!(check(&r, &r.entries, &r.result, 3), Ok(3));
}
