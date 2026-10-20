//! Manifest and ballot rules, and the count, over the generated wire types.

use serde_json::{Value, json};
use trust_tasks_rs::specs::voting::{
    ballot::cast::v0_1::Ballot, election::register::v0_1::Manifest,
};
use vti_voting::{
    rules::{RuleError, check_ballot, check_manifest, digest_multibase, manifest_digest},
    tally::tally,
};

const BOX: &str = "did:webvh:QmVote:vote.example.net";

fn manifest_json() -> Value {
    json!({
        "electionId": "agm-2027",
        "community": "did:webvh:QmCommunity:vtc.example.org",
        "title": "Annual general meeting 2027",
        "questions": [
            { "key": "budget", "type": "choice", "text": "Approve the 2027 budget?",
              "options": [{ "key": "yes" }, { "key": "no" }, { "key": "abstain" }],
              "minSelections": 1, "maxSelections": 1, "optional": false },
            { "key": "workshop", "type": "choice",
              "options": [{ "key": "kiln" }, { "key": "laser" }, { "key": "textile" }],
              "minSelections": 0, "maxSelections": 2, "optional": false },
            { "key": "formats", "type": "ranking",
              "options": [{ "key": "evenings" }, { "key": "weekends" }, { "key": "online" }],
              "partial": false, "optional": true },
            { "key": "venue", "type": "score",
              "options": [{ "key": "hall" }, { "key": "barn" }], "min": 1, "max": 5, "optional": true },
            { "key": "improve", "type": "text", "maxLength": 40, "optional": true }
        ],
        "secrecy": "open",
        "roll": { "rule": "members" },
        "registrationOpens": "2026-11-01T00:00:00Z",
        "votingOpens": "2026-11-03T00:00:00Z",
        "votingCloses": "2026-11-07T18:00:00Z",
        "revote": "replace",
        "board": { "visibility": "private", "auditors": ["did:webvh:QmAudit:audit.example.com"] },
        "ballotBox": BOX,
        "binding": true,
        "allowEarlyClose": false,
        "resultsBeforeClose": false,
        "textReleaseThreshold": 10
    })
}

fn manifest(v: &Value) -> Manifest {
    serde_json::from_value(v.clone()).expect("the example manifest parses")
}

fn ballot(digest: &[u8; 32], answers: Value) -> Ballot {
    serde_json::from_value(json!({
        "electionId": "agm-2027",
        "manifestDigest": digest_multibase(digest),
        "answers": answers,
    }))
    .expect("the ballot parses")
}

fn full_answers() -> Value {
    json!([
        { "question": "budget", "choice": ["yes"] },
        { "question": "workshop", "choice": ["kiln", "textile"] },
        { "question": "formats", "ranking": ["evenings", "weekends", "online"] },
        { "question": "venue", "scores": { "hall": 4, "barn": 2 } },
        { "question": "improve", "text": "Longer weekend hours" }
    ])
}

#[test]
fn vot_010_a_well_formed_manifest_passes() {
    let v = manifest_json();
    assert_eq!(check_manifest(&manifest(&v), Some(BOX)), Ok(()));
}

#[test]
fn vot_010_manifest_rules_are_enforced() {
    let cases: [(&str, Value); 6] = [
        ("votingOpens", json!("2026-11-08T00:00:00Z")),
        ("ballotBox", json!("did:webvh:QmOther:other.example.net")),
        ("textReleaseThreshold", json!(10)), // control: still valid
        ("roll", json!({ "rule": "listed" })),
        ("secrecy", json!("sealed")),
        (
            "board",
            json!({ "visibility": "public", "auditors": [BOX] }),
        ),
    ];
    for (field, value) in cases {
        let mut v = manifest_json();
        v[field] = value;
        let r = check_manifest(&manifest(&v), Some(BOX));
        if field == "textReleaseThreshold" {
            assert_eq!(r, Ok(()));
        } else if field == "secrecy" {
            // Sealed without trustees: served, and refused for its trustee rules.
            assert!(matches!(r, Err(RuleError::InvalidManifest(_))), "{field}");
        } else {
            assert!(
                matches!(r, Err(RuleError::InvalidManifest(_))),
                "{field}: {r:?}"
            );
        }
    }
    let mut v = manifest_json();
    v["questions"][1]["maxSelections"] = json!(4);
    assert!(matches!(
        check_manifest(&manifest(&v), None),
        Err(RuleError::InvalidManifest(_))
    ));
    let mut v = manifest_json();
    v["questions"][4]["key"] = json!("budget");
    assert!(matches!(
        check_manifest(&manifest(&v), None),
        Err(RuleError::InvalidManifest(_))
    ));
}

#[test]
fn vot_062_trustee_rules_are_enforced_for_the_encrypted_levels() {
    use trust_tasks_rs::specs::voting::election::register::v0_1::SecrecyLevel;
    use vti_voting::rules::check_manifest_serving;
    const ALL: &[SecrecyLevel] = &[
        SecrecyLevel::Open,
        SecrecyLevel::Sealed,
        SecrecyLevel::TalliedEncrypted,
    ];
    let trustees = json!({
        "dids": ["did:webvh:QmT1:t1.example", "did:webvh:QmT2:t2.example", "did:webvh:QmT3:t3.example"],
        "threshold": 2
    });
    let sealed = || {
        let mut v = manifest_json();
        v["secrecy"] = json!("sealed");
        v["trustees"] = trustees.clone();
        v
    };
    let check = |v: &Value| check_manifest_serving(&manifest(v), Some(BOX), ALL);
    assert_eq!(check(&sealed()), Ok(()));
    assert_eq!(check_manifest(&manifest(&sealed()), Some(BOX)), Ok(()));
    // A service serving fewer levels refuses the others.
    assert!(matches!(
        check_manifest_serving(&manifest(&sealed()), Some(BOX), &[SecrecyLevel::Open]),
        Err(RuleError::UnsupportedSecrecy(_))
    ));

    let mut broken: Vec<(&str, Value)> = Vec::new();
    let mut v = sealed();
    v.as_object_mut().unwrap().remove("trustees");
    broken.push(("no trustees", v));
    let mut v = sealed();
    v["trustees"]["threshold"] = json!(4);
    broken.push(("threshold above n", v));
    let mut v = sealed();
    v["trustees"]["dids"][1] = json!(BOX);
    broken.push(("the ballot box as a trustee", v));
    let mut v = sealed();
    v["trustees"]["dids"][0] = v["community"].clone();
    broken.push(("the community as a trustee", v));
    let mut v = sealed();
    v["resultsBeforeClose"] = json!(true);
    broken.push(("running totals", v));
    let mut v = sealed();
    v["secrecy"] = json!("talliedEncrypted");
    broken.push(("a tallied-encrypted ranking", v));
    let mut v = manifest_json();
    v["trustees"] = trustees.clone();
    broken.push(("an open election with trustees", v));
    for (why, v) in broken {
        assert!(
            matches!(check(&v), Err(RuleError::InvalidManifest(_))),
            "{why}"
        );
    }

    // Choice questions only: tallied-encrypted passes.
    let mut v = sealed();
    v["secrecy"] = json!("talliedEncrypted");
    let choices: Vec<Value> = v["questions"].as_array().unwrap()[..2].to_vec();
    v["questions"] = json!(choices);
    assert_eq!(check(&v), Ok(()));
}

#[test]
fn vot_011_the_digest_is_over_the_manifest_as_received() {
    let v = manifest_json();
    let d = manifest_digest(&v).unwrap();
    // Key order does not change the JCS digest; content does.
    let reordered: Value = serde_json::from_str(&serde_json::to_string(&v).unwrap()).unwrap();
    assert_eq!(manifest_digest(&reordered).unwrap(), d);
    let mut changed = v.clone();
    changed["title"] = json!("Another meeting");
    assert_ne!(manifest_digest(&changed).unwrap(), d);
    assert!(digest_multibase(&d).starts_with("zQm"));
}

#[test]
fn vot_032_a_complete_ballot_passes() {
    let v = manifest_json();
    let (m, d) = (manifest(&v), manifest_digest(&v).unwrap());
    assert_eq!(check_ballot(&m, &d, &ballot(&d, full_answers())), Ok(()));
}

#[test]
fn vot_011_a_ballot_for_another_manifest_is_a_mismatch() {
    let v = manifest_json();
    let m = manifest(&v);
    let d = manifest_digest(&v).unwrap();
    let other = [9u8; 32];
    assert_eq!(
        check_ballot(&m, &d, &ballot(&other, full_answers())),
        Err(RuleError::ManifestMismatch)
    );
}

#[test]
fn vot_032_ballot_rules_are_enforced() {
    let v = manifest_json();
    let (m, d) = (manifest(&v), manifest_digest(&v).unwrap());
    let mutate = |i: usize, answer: Value| {
        let mut a = full_answers();
        a[i] = answer;
        ballot(&d, a)
    };
    let bad = [
        mutate(0, json!({ "question": "budget", "choice": ["yes", "no"] })),
        mutate(0, json!({ "question": "budget", "abstain": true })),
        mutate(
            1,
            json!({ "question": "workshop", "choice": ["kiln", "kiln"] }),
        ),
        mutate(1, json!({ "question": "workshop", "choice": ["pottery"] })),
        mutate(2, json!({ "question": "formats", "ranking": ["evenings"] })),
        mutate(
            3,
            json!({ "question": "venue", "scores": { "hall": 6, "barn": 2 } }),
        ),
        mutate(3, json!({ "question": "venue", "scores": { "hall": 3 } })),
        mutate(4, json!({ "question": "improve", "text": "x".repeat(41) })),
        mutate(4, json!({ "question": "budget", "choice": ["no"] })),
        mutate(
            0,
            json!({ "question": "budget", "choice": ["yes"], "abstain": true }),
        ),
    ];
    for (i, b) in bad.iter().enumerate() {
        assert!(
            matches!(check_ballot(&m, &d, b), Err(RuleError::BallotInvalid(_))),
            "case {i}"
        );
    }
    // An optional question is answered with abstain, never left out.
    let mut a = full_answers();
    a.as_array_mut().unwrap().pop();
    assert!(matches!(
        check_ballot(&m, &d, &ballot(&d, a)),
        Err(RuleError::BallotInvalid(_))
    ));
    let ok = mutate(4, json!({ "question": "improve", "abstain": true }));
    assert_eq!(check_ballot(&m, &d, &ok), Ok(()));
}

#[test]
fn vot_070_the_count() {
    let v = manifest_json();
    let (m, d) = (manifest(&v), manifest_digest(&v).unwrap());
    let mut ballots = Vec::new();
    for i in 0..12 {
        let mut a = full_answers();
        if i % 3 == 0 {
            a[0] = json!({ "question": "budget", "choice": ["no"] });
            a[2] = json!({ "question": "formats", "abstain": true });
        }
        ballots.push(ballot(&d, a));
    }
    let (n, rows) = tally(&m, &ballots, false).unwrap();
    assert_eq!(n, 12);
    let rows: Vec<Value> = rows
        .iter()
        .map(|r| serde_json::to_value(r).unwrap())
        .collect();
    assert_eq!(
        rows[0]["choice"],
        json!({ "yes": 8, "no": 4, "abstain": 0 })
    );
    assert_eq!(
        rows[1]["choice"],
        json!({ "kiln": 12, "laser": 0, "textile": 12 })
    );
    assert_eq!(rows[2]["ranking"]["evenings"], json!([8, 0, 0]));
    assert_eq!(rows[2]["abstained"], json!(4));
    assert_eq!(rows[3]["score"]["hall"], json!({ "sum": 48, "count": 12 }));
    assert_eq!(rows[4]["text"].as_array().unwrap().len(), 12);

    // VTI-VOT-065: below the threshold, and in any provisional count, text is withheld.
    let (_, few) = tally(&m, &ballots[..9], false).unwrap();
    let few = serde_json::to_value(&few[4]).unwrap();
    assert_eq!(few["withheld"], json!(true));
    assert!(few.get("text").is_none());
    let (_, early) = tally(&m, &ballots, true).unwrap();
    assert_eq!(
        serde_json::to_value(&early[4]).unwrap()["withheld"],
        json!(true)
    );
}
