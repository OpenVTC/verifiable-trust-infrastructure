//! A sealed election on a **private** board, its trustees' whole round run by
//! `pnm elections trustee step` against a real VTA and a real voting service.
//!
//! ## Why this exists
//!
//! The trustee tasks were tested on both sides of the client and never through it: the VTA's
//! handlers against a ballot-box value, the ballot box against documents a test built. Nothing
//! ran the client that carries every document between them — the step that reads the ballot
//! box as the trustee (`vta/pcs/trustee/read`), works out what the ceremony needs, asks the VTA
//! for it and posts it to the ballot box's HTTPS door. On a private board that client can read
//! nothing at all without the trustee's signature, which only the VTA can make.
//!
//! ## What this pins
//!
//! 1. Three trustees, each a `did:key` whose key the VTA holds, enrol, deal and confirm by
//!    running `step` — the ballot box forms the election key, on a board only the community
//!    and the trustees may read.
//! 2. A voter casts a sealed ballot under that key at the HTTPS door.
//! 3. After the community closes, two trustees' `step` decrypts and the result is out; a third
//!    step finds nothing left to do.
//!
//! Hermetic: `MockVta::start` (REST), the voting service's router on a loopback port, and a
//! `did:peer` naming it as `TrustTaskHTTPS` — so the client finds the door the way it would in
//! a deployment, from the ballot box's DID document.

use std::sync::{Arc, Mutex};

use affinidi_tdk::dids::{
    DID, KeyType, OneOrMany, PeerKeyRole, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use vta_cli_common::commands::elections_trustee::{TrusteeTarget, cmd_step};
use vta_sdk::client::{CreateContextRequest, CreateKeyRequest};
use vta_sdk::keys::KeyType as VtaKeyType;
use vta_service::test_support::MockVta;
use vti_voting::{
    election::{Election, ElectionId},
    rand::{SeedableRng, rngs::StdRng},
    registrar::Registrar,
    rules::{digest_multibase, manifest_digest},
    service::{BallotBox, Caller},
    trustees::Threshold,
    voter::{Voter, encrypted_form},
    wire,
};
use vti_voting_service::{AppState, identity::Identity, router};

const CTX: &str = "trustees";
const ELECTION: &str = "board-2027";

fn stamp(t: chrono::DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A request to the ballot box, signed by `signer`.
async fn signed(task: &str, to: &str, signer: &Identity, payload: Value) -> Value {
    let mut doc: TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": format!("https://trusttasks.org/spec/voting/{task}/0.1"),
        "issuer": signer.did,
        "recipient": to,
        "issuedAt": stamp(Utc::now()),
        "payload": payload,
    }))
    .unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &signer.key)
        .await
        .unwrap();
    serde_json::to_value(&doc).unwrap()
}

/// Post to the ballot box's HTTPS door; the answer's status and document.
async fn post(url: &str, doc: &Value) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("{url}/trust-tasks"))
        .json(doc)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn trustees_run_a_sealed_election_on_a_private_board_from_pnm() {
    // The VTA, holding three trustee keys in one context.
    let vta = MockVta::start_provisionable().await;
    let client = vta.signing_client(0x91, "admin", Vec::new()).await;
    client
        .create_context(CreateContextRequest::new(CTX, "Trustees"))
        .await
        .expect("create the trustees' context");
    let mut trustees = Vec::new();
    for i in 0..3 {
        let key = client
            .create_key(CreateKeyRequest {
                key_type: VtaKeyType::Ed25519,
                derivation_path: None,
                key_id: Some(format!("trustee-{i}")),
                mnemonic: None,
                label: None,
                context_id: Some(CTX.into()),
                internal: None,
            })
            .await
            .expect("a trustee key");
        trustees.push(format!("did:key:{}", key.public_key));
    }

    // The ballot box: the voting service's router on a loopback port, under a did:peer whose
    // document names it as `TrustTaskHTTPS`.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (box_did, box_secrets) = DID::generate_did_peer_with_services(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(vec![PeerService {
            type_: "TrustTaskHTTPS".into(),
            endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
                uri: url.clone(),
                accept: vec![],
                routing_keys: vec![],
            })),
            id: None,
        }]),
    )
    .unwrap();
    let box_state = Arc::new(AppState {
        ballot_box: Mutex::new(BallotBox::new(&box_did)),
        identity: Identity {
            did: box_did.clone(),
            key: vta_sdk::trust_task_sign::HolderKey::new(
                box_secrets[0].id.clone(),
                box_secrets[0].get_private_keymultibase().unwrap(),
            )
            .unwrap(),
        },
        resolver: vti_common::auth::TrustTaskVmResolver::did_key_only(),
    });
    let server = tokio::spawn(axum::serve(listener, router(box_state.clone())).into_future());

    // The community registers a sealed election on a private board, voting a little ahead so
    // the trustees can form the key first.
    let community = Identity::from_seed(&[0x51; 32]).unwrap();
    let mut rng = StdRng::seed_from_u64(0x52);
    let reg = Registrar::generate(&community.did, &mut rng).unwrap();
    let now = Utc::now();
    let manifest = json!({
        "electionId": ELECTION, "community": community.did,
        "questions": [{ "key": "chair", "type": "choice",
            "options": [{ "key": "ana" }, { "key": "ben" }],
            "minSelections": 1, "maxSelections": 1, "optional": false }],
        "secrecy": "sealed",
        "trustees": { "dids": trustees, "threshold": 2 },
        "roll": { "rule": "members" },
        "registrationOpens": stamp(now - Duration::hours(1)),
        "votingOpens": stamp(now + Duration::seconds(25)),
        "votingCloses": stamp(now + Duration::hours(1)),
        "revote": "replace",
        "board": { "visibility": "private", "auditors": [] },
        "ballotBox": box_did,
        "binding": false, "allowEarlyClose": true, "resultsBeforeClose": false,
        "textReleaseThreshold": 10,
    });
    let digest = manifest_digest(&manifest).unwrap();
    let register = signed(
        "election/register",
        &box_did,
        &community,
        json!({ "community": community.did, "manifest": manifest,
                "manifestDigest": digest_multibase(&digest),
                "parameters": { "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() } }),
    )
    .await;
    let (status, answer) = post(&url, &register).await;
    assert_eq!(status, 200, "{answer}");

    let sel = json!({ "community": community.did, "electionId": ELECTION });
    let status_now = |at| {
        box_state
            .ballot_box
            .lock()
            .unwrap()
            .trustees_status(Caller::Did(&community.did), &sel, at)
            .unwrap()
    };
    fn target<'a>(community: &'a str, ballot_box: &'a str, trustee: &'a str) -> TrusteeTarget<'a> {
        TrusteeTarget {
            community,
            ballot_box,
            trustee,
            context: CTX,
        }
    }

    // 1. Each round, every trustee runs `step` once; three rounds form the key.
    for (round, want) in ["dealing", "confirming", "keyed"].iter().enumerate() {
        for did in &trustees {
            cmd_step(
                &client,
                target(&community.did, &box_did, did),
                ELECTION,
                false,
            )
            .await
            .unwrap_or_else(|e| panic!("round {round}, {did}: {e}"));
        }
        assert_eq!(
            status_now(Utc::now())["phase"],
            *want,
            "after round {round}"
        );
    }
    // Every step is on the board as its trustee's own signed request.
    let steps = box_state
        .ballot_box
        .lock()
        .unwrap()
        .board_read(
            Caller::Did(&community.did),
            &json!({ "community": community.did, "electionId": ELECTION, "from": 0, "limit": 100 }),
            Utc::now(),
        )
        .unwrap()["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["entry"]["kind"] == "trusteeStep")
        .count();
    assert_eq!(steps, 9);

    // 2. Once voting opens, a voter casts a sealed ballot under the key the trustees formed.
    let opens = now + Duration::seconds(26);
    tokio::time::sleep((opens - Utc::now()).to_std().unwrap_or_default()).await;
    let election =
        Election::new(&community.did, ElectionId::new(ELECTION).unwrap(), digest).unwrap();
    let params = reg.params();
    let voter = Voter::generate(&params, &mut rng).unwrap();
    let (req, st) = voter.ticket_request(&params, &election, &mut rng).unwrap();
    let pre = reg
        .issue_ticket(&election, voter.id(), &req, &mut rng)
        .unwrap();
    let ticket = voter.accept_ticket(&params, &election, &pre, &st).unwrap();
    let ek = wire::election_key(
        &status_now(Utc::now())["electionKey"],
        Threshold::new(2, 3).unwrap(),
    )
    .unwrap();
    let typed: trust_tasks_rs::specs::voting::election::register::v0_1::Manifest =
        serde_json::from_value(manifest.clone()).unwrap();
    let ballot = json!({ "electionId": ELECTION, "manifestDigest": digest_multibase(&digest),
                         "answers": [{ "question": "chair", "choice": ["ben"] }] });
    let tag = voter.tag_for(&params, &ticket, &mut rng).unwrap();
    let form = encrypted_form(&typed, &election, &ek, &ballot, &tag, &mut rng).unwrap();
    let cast = voter
        .cast_encrypted_wire(&params, &ticket, &form, &mut rng)
        .unwrap();
    let one_time = Identity::from_seed(&[0x53; 32]).unwrap();
    let cast_doc = signed(
        "ballot/cast-encrypted",
        &box_did,
        &one_time,
        json!({ "community": community.did, "electionId": ELECTION, "cast": cast }),
    )
    .await;
    let (status, receipt) = post(&url, &cast_doc).await;
    assert_eq!(status, 200, "{receipt}");
    assert_eq!(receipt["payload"]["outcome"], "counted");

    // 3. The community closes; two trustees' `step` decrypts, and the result is out.
    let close = signed("election/close", &box_did, &community, sel.clone()).await;
    let (status, answer) = post(&url, &close).await;
    assert_eq!(status, 200, "{answer}");
    assert_eq!(status_now(Utc::now())["phase"], "decrypting");
    // Until the community authorizes the decryption, a trustee's step decrypts nothing.
    cmd_step(
        &client,
        target(&community.did, &box_did, &trustees[0]),
        ELECTION,
        false,
    )
    .await
    .unwrap();
    assert_eq!(status_now(Utc::now())["decrypted"], json!([]));
    // The community reads the closed board, computes the targets itself and authorizes them
    // (CONVENTIONS §9.7).
    let entries: Vec<Value> = box_state
        .ballot_box
        .lock()
        .unwrap()
        .board_read(
            Caller::Did(&community.did),
            &json!({ "community": community.did, "electionId": ELECTION, "from": 0, "limit": 1000 }),
            Utc::now(),
        )
        .unwrap()["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["entry"].clone())
        .collect();
    let resolver = vti_common::auth::TrustTaskVmResolver::did_key_only();
    let resolver = &resolver;
    let proven = vti_voting::steps::ProvenRequests::prove(&entries, |r| async move {
        vti_common::auth::verify_trust_task_proof_value(&r, resolver)
            .await
            .ok()
    })
    .await;
    let closing = vti_voting::audit::decryption(&manifest, &reg.params(), &entries, &proven)
        .unwrap()
        .expect("the board has closed");
    let size = closing.index as usize + 1;
    let mut board = vti_voting::board::Board::new();
    for e in &entries[..size] {
        board.append(&serde_json_canonicalizer::to_vec(e).unwrap());
    }
    let values = closing.target_values();
    let authorize = signed(
        "trustees/authorize",
        &box_did,
        &community,
        json!({ "community": community.did, "electionId": ELECTION,
                "manifestDigest": digest_multibase(&digest),
                "head": { "electionId": ELECTION, "treeSize": size,
                          "rootHash": digest_multibase(&board.root(size).unwrap()),
                          "issuedAt": closing.at },
                "closedAt": closing.at,
                "targetCount": values.len(),
                "targetsDigest": vti_voting::audit::targets_digest(&values).unwrap() }),
    )
    .await;
    let (status, answer) = post(&url, &authorize).await;
    assert_eq!(status, 200, "{answer}");
    for did in &trustees[..2] {
        cmd_step(
            &client,
            target(&community.did, &box_did, did),
            ELECTION,
            false,
        )
        .await
        .unwrap_or_else(|e| panic!("decrypt, {did}: {e}"));
    }
    let result = box_state
        .ballot_box
        .lock()
        .unwrap()
        .result(Caller::Did(&community.did), &sel, Utc::now())
        .unwrap();
    assert_eq!(result["result"]["ballotsCounted"], 1);
    assert_eq!(
        result["result"]["questions"][0]["choice"],
        json!({ "ana": 0, "ben": 1 })
    );
    // The third trustee finds nothing left to do.
    cmd_step(
        &client,
        target(&community.did, &box_did, &trustees[2]),
        ELECTION,
        false,
    )
    .await
    .expect("a step after the result is out is nothing to do");

    server.abort();
}
