//! The voter role end to end, through the slice's own handlers: register, the community issues
//! the ticket blind, accept, vote, the ballot box admits the cast, and the VTA checks the signed
//! receipt against a signed head — every key held by the VTA and the cast signed by a key made
//! for it alone. Then every code the voter specifications declare.

use super::*;
use crate::acl::Role;
use crate::test_support::build_signing_test_app_state;
use trust_tasks_rs::TypeUri;
use vta_sdk::trust_task_sign::HolderKey;
use vta_sdk::trust_tasks as uris;
use vti_voting::{
    election::{Election, ElectionId},
    rand::{SeedableRng, rngs::StdRng},
    registrar::Registrar,
    rules::{digest_multibase, manifest_digest},
    service::{BallotBox, Caller as BoxCaller},
};

const COMMUNITY: &str = "did:webvh:QmCommunity:vtc.example.org";
const B58: &str = "z3ZeMb8yW1fRq2Rr5b6tHn7Kx9Lp2Vd";

fn claims(did: &str, role: Role, ctx: &str) -> AuthClaims {
    AuthClaims {
        did: did.to_string(),
        role,
        allowed_contexts: vec![ctx.to_string()],
        session_id: "test-session".into(),
        access_expires_at: 0,
        issued_at: 0,
        amr: Vec::new(),
        acr: String::new(),
    }
}

fn doc(uri: &str, payload: Value) -> TrustTask<Value> {
    let uri: TypeUri = uri.parse().expect("voter uri");
    TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
}

fn body(out: &TrustTaskOutcome) -> Value {
    serde_json::from_slice(&out.body).expect("response is JSON")
}

fn ok(out: &TrustTaskOutcome) -> Value {
    let b = body(out);
    assert!(out.status.is_success(), "expected success, got {b}");
    b["payload"].clone()
}

fn code(out: &TrustTaskOutcome) -> String {
    body(out)
        .pointer("/payload/code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// A did:key the test ballot box signs its answers as.
fn box_key(seed: u8) -> (String, HolderKey) {
    let public = ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes();
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&public)
    );
    let key = HolderKey::from_did_key(
        &did,
        multibase::encode(multibase::Base::Base58Btc, [seed; 32]),
    )
    .unwrap();
    (did, key)
}

/// `payload` as a document `issuer` signed, typed `uri`.
async fn signed(uri: &str, issuer: &str, key: &HolderKey, payload: Value) -> Value {
    let mut d: TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": uri,
        "issuer": issuer,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    }))
    .unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut d, key)
        .await
        .unwrap();
    serde_json::to_value(&d).unwrap()
}

fn manifest(id: &str, ballot_box: &str, open: bool, secrecy: &str) -> Value {
    let now = chrono::Utc::now();
    let (opens, closes) = if open {
        (
            now - chrono::Duration::hours(1),
            now + chrono::Duration::days(1),
        )
    } else {
        (
            now - chrono::Duration::days(3),
            now - chrono::Duration::days(1),
        )
    };
    let t = |d: chrono::DateTime<chrono::Utc>| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    json!({
        "electionId": id, "community": COMMUNITY,
        "questions": [{ "key": "budget", "type": "choice",
            "options": [{ "key": "yes" }, { "key": "no" }],
            "minSelections": 1, "maxSelections": 1, "optional": false }],
        "secrecy": secrecy, "roll": { "rule": "members" },
        "registrationOpensAt": t(opens - chrono::Duration::days(1)), "votingOpensAt": t(opens),
        "votingClosesAt": t(closes), "revote": "replace",
        "board": { "visibility": "public", "auditors": [] }, "ballotBox": ballot_box,
        "binding": false, "allowEarlyClose": false, "resultsBeforeClose": false,
        "textReleaseThreshold": 10,
    })
}

fn ballot(manifest: &Value, choice: &str) -> Value {
    json!({
        "electionId": manifest["electionId"],
        "manifestDigest": digest_multibase(&manifest_digest(manifest).unwrap()),
        "answers": [{ "question": "budget", "choice": [choice] }],
    })
}

fn register_doc(params: &Value, m: &Value) -> TrustTask<Value> {
    doc(
        uris::TASK_VTA_PCS_VOTER_REGISTER_0_5,
        json!({ "contextId": "member", "community": COMMUNITY, "parameters": params, "manifest": m }),
    )
}

fn accept_doc(election: &str, params: &Value, pre: &str) -> TrustTask<Value> {
    doc(
        uris::TASK_VTA_PCS_VOTER_ACCEPT_0_1,
        json!({ "contextId": "member", "community": COMMUNITY, "electionId": election,
                "parameters": params,
                "response": { "electionId": election, "label": format!("voter/{election}"), "preCredential": pre } }),
    )
}

fn vote_doc(params: &Value, m: &Value, b: Value) -> TrustTask<Value> {
    doc(
        uris::TASK_VTA_PCS_VOTE_0_4,
        json!({ "contextId": "member", "community": COMMUNITY, "parameters": params,
                "manifest": m, "ballot": b }),
    )
}

#[tokio::test]
async fn a_member_votes_through_the_vta_and_checks_the_receipt() {
    let (state, _dir) = build_signing_test_app_state().await;
    crate::contexts::create_context(&state.contexts_ks, "member", "member")
        .await
        .unwrap();
    let auth = claims("did:key:z6MkVoter", Role::Admin, "member");
    let mut rng = StdRng::seed_from_u64(0xB0);
    let reg = Registrar::generate(COMMUNITY, &mut rng).unwrap();
    let params = json!({ "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() });
    let (box_did, box_signer) = box_key(5);
    let m = manifest("agm-2027", &box_did, true, "open");
    let digest = manifest_digest(&m).unwrap();

    // Register: a blinded request under a key made for this election; a repeat before the
    // ticket is held answers with the same request.
    let first = ok(&handle_voter_register(&state, &auth, register_doc(&params, &m)).await);
    assert_eq!(
        ok(&handle_voter_register(&state, &auth, register_doc(&params, &m)).await),
        first
    );

    // The community issues the ticket blind.
    let election = Election::new(COMMUNITY, ElectionId::new("agm-2027").unwrap(), digest).unwrap();
    let id =
        vti_vetting_pcs::scheme::point_from_text(first["request"]["id"].as_str().unwrap()).unwrap();
    let request = serde_json::from_value(first["request"]["request"].clone()).unwrap();
    let pre = reg
        .issue_ticket(&election, &id, &request, &mut rng)
        .unwrap();
    let pre = vti_vetting_pcs::scheme::enc(&pre).unwrap();
    assert_eq!(
        ok(&handle_voter_accept(&state, &auth, accept_doc("agm-2027", &params, &pre)).await)["ticketHeld"],
        true
    );
    assert_eq!(
        code(&handle_voter_accept(&state, &auth, accept_doc("agm-2027", &params, &pre)).await),
        "vta/pcs/voter/accept:noRequestInFlight"
    );
    assert_eq!(
        code(&handle_voter_register(&state, &auth, register_doc(&params, &m)).await),
        "vta/pcs/voter/register:ticketHeld"
    );

    // Vote: a signed cast document, issued by a one-time key, never the member's DID.
    let voted = ok(&handle_vote(&state, &auth, vote_doc(&params, &m, ballot(&m, "yes"))).await);
    let cast_doc = voted["castDocument"].clone();
    assert_eq!(cast_doc["recipient"], box_did);
    assert_ne!(cast_doc["issuer"], json!(auth.did), "VTI-VOT-003");
    let signer = vti_common::auth::verify_trust_task_proof_value(
        &cast_doc,
        &vti_common::auth::TrustTaskVmResolver::did_key_only(),
    )
    .await
    .unwrap();
    assert_eq!(json!(signer), cast_doc["issuer"]);
    assert_eq!(voted["tag"], cast_doc["payload"]["cast"]["tag"]);

    // The ballot box admits it; its signed receipt and head come back to the VTA.
    let mut bb = BallotBox::new(&box_did);
    let now = chrono::Utc::now();
    bb.register(
        COMMUNITY,
        &json!({ "community": COMMUNITY, "manifest": m,
                 "manifestDigest": digest_multibase(&digest), "parameters": params }),
        now,
    )
    .unwrap();
    let sel = json!({ "community": COMMUNITY, "electionId": "agm-2027" });
    // The head as it stood before the cast: one that cannot hold it.
    let before = bb.board_head(BoxCaller::Anonymous, &sel, now).unwrap();
    let receipt_payload = bb.cast(&cast_doc["payload"], now).unwrap();
    assert_eq!(receipt_payload["outcome"], "counted");
    let receipt = signed(
        "https://trusttasks.org/spec/voting/ballot/cast/0.1#response",
        &box_did,
        &box_signer,
        receipt_payload.clone(),
    )
    .await;
    let head = bb.board_head(BoxCaller::Anonymous, &sel, now).unwrap();
    let checkpoint = signed(
        "https://trusttasks.org/spec/voting/board/head/0.1#response",
        &box_did,
        &box_signer,
        head.clone(),
    )
    .await;
    let mut q = sel.clone();
    q["leafIndex"] = receipt_payload["leafIndex"].clone();
    q["treeSize"] = head["head"]["treeSize"].clone();
    let inclusion = bb.board_inclusion(BoxCaller::Anonymous, &q, now).unwrap();
    let receipt_doc = |r: &Value, c: Option<&Value>| {
        let mut p = json!({ "contextId": "member", "community": COMMUNITY,
                            "electionId": "agm-2027", "receipt": r });
        if let Some(c) = c {
            p["checkpoint"] = c.clone();
            p["inclusion"] = inclusion.clone();
        }
        doc(uris::TASK_VTA_PCS_VOTER_RECEIPT_0_1, p)
    };
    assert_eq!(
        ok(&handle_voter_receipt(&state, &auth, receipt_doc(&receipt, None)).await)["status"],
        "kept"
    );
    assert_eq!(
        ok(&handle_voter_receipt(&state, &auth, receipt_doc(&receipt, Some(&checkpoint))).await)["status"],
        "included"
    );

    // After close the client asks the VTA for what it kept, and checks again (VTI-VOT-053).
    let list_doc = |election: &str| {
        doc(
            uris::TASK_VTA_PCS_VOTER_RECEIPTS_LIST_0_1,
            json!({ "contextId": "member", "community": COMMUNITY, "electionId": election }),
        )
    };
    let kept = ok(&handle_voter_receipts_list(&state, &auth, list_doc("agm-2027")).await);
    assert_eq!(kept["ballotBox"], box_did);
    assert_eq!(
        kept["receipts"],
        json!([receipt]),
        "kept whole, exactly as received"
    );
    assert_eq!(
        code(&handle_voter_receipts_list(&state, &auth, list_doc("agm-2099")).await),
        "vta/pcs/voter/receipts/list:notFound"
    );
    // A head too small to hold the cast omits it, whatever path comes with it (item 7.2).
    let size = before["head"]["treeSize"].as_u64().unwrap();
    let leaf = receipt_payload["leafIndex"].as_u64().unwrap();
    assert!(leaf >= size);
    if size > 0 {
        let short = signed(
            "https://trusttasks.org/spec/voting/board/head/0.1#response",
            &box_did,
            &box_signer,
            before.clone(),
        )
        .await;
        let mut p = json!({ "contextId": "member", "community": COMMUNITY,
                            "electionId": "agm-2027", "receipt": receipt, "checkpoint": short,
                            "inclusion": { "leafIndex": leaf, "treeSize": size,
                                           "entryHash": receipt_payload["entryHash"], "path": [] } });
        let answer = ok(&handle_voter_receipt(
            &state,
            &auth,
            doc(uris::TASK_VTA_PCS_VOTER_RECEIPT_0_1, p.take()),
        )
        .await);
        assert_eq!(answer["status"], "notIncluded");
    }

    // A receipt somebody else signed, or a checkpoint nobody signed, proves nothing.
    let (other, other_signer) = box_key(6);
    let forged = signed(
        "https://trusttasks.org/spec/voting/ballot/cast/0.1#response",
        &other,
        &other_signer,
        receipt_payload,
    )
    .await;
    assert_eq!(
        code(&handle_voter_receipt(&state, &auth, receipt_doc(&forged, None)).await),
        "vta/pcs/voter/receipt:receiptInvalid"
    );
    let mut unsigned = checkpoint.clone();
    unsigned.as_object_mut().unwrap().remove("proof");
    assert_eq!(
        code(&handle_voter_receipt(&state, &auth, receipt_doc(&receipt, Some(&unsigned))).await),
        "vta/pcs/voter/receipt:evidenceInvalid"
    );

    // The vote's own refusals.
    assert_eq!(
        code(&handle_vote(&state, &auth, vote_doc(&params, &m, ballot(&m, "maybe"))).await),
        "vta/pcs/vote:ballotInvalid"
    );
    let mut changed = m.clone();
    changed["title"] = json!("changed");
    let out = handle_vote(
        &state,
        &auth,
        vote_doc(&params, &changed, ballot(&m, "yes")),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/vote:manifestMismatch");
}

#[tokio::test]
async fn the_voter_tasks_refuse_with_the_codes_their_specifications_declare() {
    let (state, _dir) = build_signing_test_app_state().await;
    crate::contexts::create_context(&state.contexts_ks, "member", "member")
        .await
        .unwrap();
    let auth = claims("did:key:z6MkVoter", Role::Admin, "member");
    let mut rng = StdRng::seed_from_u64(0xB1);
    let reg = Registrar::generate(COMMUNITY, &mut rng).unwrap();
    let params = json!({ "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() });
    let bad_key = json!({ "suite": "ps-ddh-bls12381", "votingKey": B58 });
    let (box_did, _) = box_key(5);

    // Every level is served: a ticket is the same at each, only the cast differs.
    let mut sealed = manifest("sealed-1", &box_did, true, "sealed");
    sealed["trustees"] = json!({ "dids": ["did:key:z6MkT1", "did:key:z6MkT2"], "threshold": 2 });
    ok(&handle_voter_register(&state, &auth, register_doc(&params, &sealed)).await);
    let m = manifest("agm-2027", &box_did, true, "open");
    let other_suite = json!({ "suite": "ps-ddh-bls12381-v9", "votingKey": params["votingKey"] });
    assert_eq!(
        code(&handle_voter_register(&state, &auth, register_doc(&other_suite, &m)).await),
        "vta/pcs/voter/register:unsupportedSuite"
    );
    assert_eq!(
        code(&handle_voter_register(&state, &auth, register_doc(&bad_key, &m)).await),
        "vta/pcs/voter/register:parametersInvalid"
    );
    ok(&handle_voter_register(&state, &auth, register_doc(&params, &m)).await);
    let mut changed = m.clone();
    changed["title"] = json!("another manifest");
    assert_eq!(
        code(&handle_voter_register(&state, &auth, register_doc(&params, &changed)).await),
        "vta/pcs/voter/register:electionChanged"
    );

    assert_eq!(
        code(&handle_voter_accept(&state, &auth, accept_doc("none", &params, B58)).await),
        "vta/pcs/voter/accept:notFound"
    );
    assert_eq!(
        code(&handle_voter_accept(&state, &auth, accept_doc("agm-2027", &params, B58)).await),
        "vta/pcs/voter/accept:credentialInvalid"
    );
    assert_eq!(
        code(&handle_voter_accept(&state, &auth, accept_doc("agm-2027", &bad_key, B58)).await),
        "vta/pcs/voter/accept:parametersInvalid"
    );

    let unknown = manifest("never-registered", &box_did, true, "open");
    let out = handle_vote(
        &state,
        &auth,
        vote_doc(&params, &unknown, ballot(&unknown, "yes")),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/vote:notFound");
    assert_eq!(
        code(&handle_vote(&state, &auth, vote_doc(&bad_key, &m, ballot(&m, "yes"))).await),
        "vta/pcs/vote:parametersInvalid"
    );
    let closed = manifest("closed-1", &box_did, false, "open");
    ok(&handle_voter_register(&state, &auth, register_doc(&params, &closed)).await);
    let out = handle_vote(
        &state,
        &auth,
        vote_doc(&params, &closed, ballot(&closed, "yes")),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/vote:notOpen");

    let receipt = doc(
        uris::TASK_VTA_PCS_VOTER_RECEIPT_0_1,
        json!({ "contextId": "member", "community": COMMUNITY, "electionId": "none",
                "receipt": { "type": "https://trusttasks.org/spec/voting/ballot/cast/0.1#response" } }),
    );
    assert_eq!(
        code(&handle_voter_receipt(&state, &auth, receipt).await),
        "vta/pcs/voter/receipt:notFound"
    );
}

#[tokio::test]
async fn the_voter_tasks_need_the_voter_capability() {
    let (state, _dir) = build_signing_test_app_state().await;
    // `application` derives no PCS capability: an agent votes only where granted by name.
    let auth = claims("did:key:z6MkAgent", Role::Application, "member");
    let out = handle_voter_register(
        &state,
        &auth,
        doc(
            uris::TASK_VTA_PCS_VOTER_REGISTER_0_5,
            json!({ "contextId": "member", "community": COMMUNITY }),
        ),
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
}

/// `member` (register item 9): the VTA signs the request to the community as a persona it holds,
/// keeps that document, and returns it unchanged on a repeat — so the community answers a resend
/// with its first answer. A DID it holds no key of is refused before anything is allocated.
#[tokio::test]
async fn the_ticket_request_is_signed_as_the_member_and_kept() {
    let (state, _dir) = build_signing_test_app_state().await;
    crate::contexts::create_context(&state.contexts_ks, "member", "member")
        .await
        .unwrap();
    let auth = claims("did:key:z6MkVoter", Role::Admin, "member");
    let persona = crate::operations::persona::test_fixture::did_key_persona(
        &state.keys_ks,
        &state.internal_ks,
        &state.contexts_ks,
        &state.acl_ks,
        &state.seed_store,
        &state.audit_sink,
        "member",
        "membership-key",
    )
    .await;
    let mut rng = StdRng::seed_from_u64(0xB7);
    let reg = Registrar::generate(COMMUNITY, &mut rng).unwrap();
    let params = json!({ "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() });
    let (box_did, _) = box_key(9);
    let m = manifest("agm-2028", &box_did, true, "open");
    let with_member = |did: &str| {
        doc(
            uris::TASK_VTA_PCS_VOTER_REGISTER_0_5,
            json!({ "contextId": "member", "community": COMMUNITY, "parameters": params,
                    "manifest": m, "member": did }),
        )
    };

    // A DID this VTA holds no key of: refused, and no election is recorded.
    let out = handle_voter_register(&state, &auth, with_member("did:key:z6MkNotHeldHere")).await;
    assert_eq!(code(&out), "vta/pcs/voter/register:memberNotHeld");

    let first = ok(&handle_voter_register(&state, &auth, with_member(&persona.did)).await);
    let ticket = &first["ticketDocument"];
    assert_eq!(
        ticket["type"],
        "https://trusttasks.org/spec/vtc/elections/tickets/issue/0.3"
    );
    // Under a members roll it carries no presentation.
    assert!(ticket["payload"].get("presentation").is_none());
    assert_eq!(ticket["issuer"], persona.did.as_str());
    assert_eq!(ticket["recipient"], COMMUNITY);
    assert_eq!(ticket["payload"]["request"], first["request"]);
    assert_eq!(ticket["payload"]["manifestDigest"], first["manifestDigest"]);
    // Signed by the member, for authentication: what the community verifies it against.
    let signer = vta_sdk::trust_task_proof::verify_trust_task_proof_value(
        ticket,
        &vta_sdk::trust_task_proof::TrustTaskVmResolver::did_key_only(),
    )
    .await
    .expect("the member's proof verifies");
    assert_eq!(signer, persona.did);
    assert_eq!(ticket["proof"]["proofPurpose"], "authentication");

    // A repeat returns the same document, byte for byte.
    let again = ok(&handle_voter_register(&state, &auth, with_member(&persona.did)).await);
    assert_eq!(again["ticketDocument"], first["ticketDocument"]);

    // register 0.3, still served, builds a tickets/issue/0.1 request of its own, and keeps it
    // apart from 0.5's: each version's resend answers with its own document.
    let old = || {
        doc(
            uris::TASK_VTA_PCS_VOTER_REGISTER_0_3,
            json!({ "contextId": "member", "community": COMMUNITY, "parameters": params,
                    "manifest": m, "member": persona.did }),
        )
    };
    let old_first = ok(&handle_voter_register(&state, &auth, old()).await);
    assert_eq!(
        old_first["ticketDocument"]["type"],
        "https://trusttasks.org/spec/vtc/elections/tickets/issue/0.1"
    );
    assert_eq!(old_first["request"], first["request"]);
    let old_again = ok(&handle_voter_register(&state, &auth, old()).await);
    assert_eq!(old_again["ticketDocument"], old_first["ticketDocument"]);
}

/// Every row of the engine's keyspace the seed does not wrap, as text.
async fn unwrapped_rows(state: &AppState) -> Vec<String> {
    state
        .pcs_engine_ks
        .prefix_iter_raw("")
        .await
        .unwrap()
        .into_iter()
        .filter(|(k, _)| !k.starts_with(b"secret:"))
        .map(|(k, v)| {
            format!(
                "{} {}",
                String::from_utf8_lossy(&k),
                String::from_utf8_lossy(&v)
            )
        })
        .collect()
}

/// CONVENTIONS §5 item 3, §6 item 4: once the ticket is held nothing in the clear names the
/// member beside the cast, the ticket goes when voting closes, and the casts and receipts the
/// retention later.
#[tokio::test]
async fn the_vta_keeps_no_clear_pairing_and_discards_after_the_election() {
    let (state, _dir) = build_signing_test_app_state().await;
    crate::contexts::create_context(&state.contexts_ks, "member", "member")
        .await
        .unwrap();
    let auth = claims("did:key:z6MkVoter", Role::Admin, "member");
    let persona = crate::operations::persona::test_fixture::did_key_persona(
        &state.keys_ks,
        &state.internal_ks,
        &state.contexts_ks,
        &state.acl_ks,
        &state.seed_store,
        &state.audit_sink,
        "member",
        "membership-key",
    )
    .await;
    let mut rng = StdRng::seed_from_u64(0xB8);
    let reg = Registrar::generate(COMMUNITY, &mut rng).unwrap();
    let params = json!({ "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() });
    let (box_did, box_signer) = box_key(10);
    let m = manifest("agm-2029", &box_did, true, "open");
    let digest = manifest_digest(&m).unwrap();
    let registered = ok(&handle_voter_register(
        &state,
        &auth,
        doc(
            uris::TASK_VTA_PCS_VOTER_REGISTER_0_5,
            json!({ "contextId": "member", "community": COMMUNITY, "parameters": params,
                    "manifest": m, "member": persona.did }),
        ),
    )
    .await);
    assert!(
        unwrapped_rows(&state)
            .await
            .iter()
            .any(|r| r.contains(&persona.did)),
        "kept for a resend until the ticket is held"
    );

    let election = Election::new(COMMUNITY, ElectionId::new("agm-2029").unwrap(), digest).unwrap();
    let id =
        vti_vetting_pcs::scheme::point_from_text(registered["request"]["id"].as_str().unwrap())
            .unwrap();
    let request = serde_json::from_value(registered["request"]["request"].clone()).unwrap();
    let pre = vti_vetting_pcs::scheme::enc(
        &reg.issue_ticket(&election, &id, &request, &mut rng)
            .unwrap(),
    )
    .unwrap();
    ok(&handle_voter_accept(&state, &auth, accept_doc("agm-2029", &params, &pre)).await);
    let voted = ok(&handle_vote(&state, &auth, vote_doc(&params, &m, ballot(&m, "no"))).await);

    let mut bb = BallotBox::new(&box_did);
    let now = chrono::Utc::now();
    bb.register(
        COMMUNITY,
        &json!({ "community": COMMUNITY, "manifest": m,
                 "manifestDigest": digest_multibase(&digest), "parameters": params }),
        now,
    )
    .unwrap();
    let receipt_payload = bb.cast(&voted["castDocument"]["payload"], now).unwrap();
    let receipt = signed(
        "https://trusttasks.org/spec/voting/ballot/cast/0.1#response",
        &box_did,
        &box_signer,
        receipt_payload.clone(),
    )
    .await;
    let keep = || {
        doc(
            uris::TASK_VTA_PCS_VOTER_RECEIPT_0_1,
            json!({ "contextId": "member", "community": COMMUNITY,
                    "electionId": "agm-2029", "receipt": receipt }),
        )
    };
    assert_eq!(
        ok(&handle_voter_receipt(&state, &auth, keep()).await)["status"],
        "kept"
    );

    // Neither the member nor anything naming the cast is readable without the seed.
    let entry_hash = receipt_payload["entryHash"].as_str().unwrap();
    let tag = voted["tag"].as_str().unwrap();
    for row in unwrapped_rows(&state).await {
        assert!(
            !row.contains(&persona.did),
            "the member, in the clear: {row}"
        );
        assert!(
            !row.contains(entry_hash),
            "the cast's leaf, in the clear: {row}"
        );
        assert!(!row.contains(tag), "the cast's tag, in the clear: {row}");
    }

    let wrapped = |prefix: &'static str| {
        let ks = state.pcs_engine_ks.clone();
        async move { ks.prefix_iter_raw(prefix).await.unwrap().len() }
    };
    let closes: chrono::DateTime<chrono::Utc> =
        m["votingClosesAt"].as_str().unwrap().parse().unwrap();
    let sweep = |at| crate::operations::pcs_voter::sweep(&state.pcs_engine_ks, at);

    // Before voting closes nothing goes.
    assert_eq!(sweep(now).await.unwrap(), 0);
    assert_eq!(wrapped("secret:voter:").await, 1);

    // Once it closes the ticket goes; the receipt is still recognised.
    assert_eq!(sweep(closes).await.unwrap(), 0);
    assert_eq!(wrapped("secret:voter:").await, 0);
    assert_eq!(wrapped("secret:voter-casts:").await, 1);
    assert_eq!(
        ok(&handle_voter_receipt(&state, &auth, keep()).await)["status"],
        "kept"
    );

    // The retention later, everything.
    let gone = closes + crate::operations::pcs_voter::RECEIPT_RETENTION;
    assert_eq!(sweep(gone).await.unwrap(), 1);
    assert_eq!(wrapped("secret:voter-casts:").await, 0);
    assert_eq!(wrapped("voter:").await, 0);
    assert!(
        !handle_voter_receipt(&state, &auth, keep())
            .await
            .status
            .is_success()
    );
}

/// `vta/pcs/voter/read`: one of the election reads, signed as the member — and nothing else.
#[tokio::test]
async fn an_election_read_is_signed_as_the_member() {
    let (state, _dir) = build_signing_test_app_state().await;
    crate::contexts::create_context(&state.contexts_ks, "member", "member")
        .await
        .unwrap();
    let auth = claims("did:key:z6MkVoter", Role::Admin, "member");
    let persona = crate::operations::persona::test_fixture::did_key_persona(
        &state.keys_ks,
        &state.internal_ks,
        &state.contexts_ks,
        &state.acl_ks,
        &state.seed_store,
        &state.audit_sink,
        "member",
        "membership-key",
    )
    .await;
    let read = |member: &str, which: &str, payload: Value| {
        doc(
            uris::TASK_VTA_PCS_VOTER_READ_0_7,
            json!({ "contextId": "member", "community": COMMUNITY, "member": member,
                    "read": which, "payload": payload }),
        )
    };

    // 0.7 also signs the tombstone read (VTI-BRD-009), with no presentation in it.
    let tomb = ok(&handle_voter_read(
        &state,
        &auth,
        read(
            &persona.did,
            "tombstone",
            json!({ "electionId": "agm-2028" }),
        ),
    )
    .await);
    assert_eq!(
        tomb["document"]["type"],
        "https://trusttasks.org/spec/vtc/elections/tombstones/show/0.1"
    );
    assert_eq!(tomb["document"]["issuer"], persona.did.as_str());
    let out = handle_voter_read(&state, &auth, read(&persona.did, "tombstone", json!({}))).await;
    assert_eq!(code(&out), "malformedRequest");
    // 0.6, still served, signs no tombstone read.
    let out = handle_voter_read(
        &state,
        &auth,
        doc(
            uris::TASK_VTA_PCS_VOTER_READ_0_6,
            json!({ "contextId": "member", "community": COMMUNITY, "member": persona.did,
                    "read": "show", "payload": { "electionId": "agm-2028" } }),
        ),
    )
    .await;
    assert_eq!(
        ok(&out)["document"]["type"],
        "https://trusttasks.org/spec/vtc/elections/show/0.6"
    );

    let shown = ok(&handle_voter_read(
        &state,
        &auth,
        read(&persona.did, "show", json!({ "electionId": "agm-2028" })),
    )
    .await);
    let d = &shown["document"];
    assert_eq!(
        d["type"],
        "https://trusttasks.org/spec/vtc/elections/show/0.6"
    );
    // voter/read 0.3, still served, signs show/0.3 and list/0.3.
    for (which, payload, signed) in [
        (
            "show",
            json!({ "electionId": "agm-2028" }),
            "https://trusttasks.org/spec/vtc/elections/show/0.3",
        ),
        (
            "list",
            json!({}),
            "https://trusttasks.org/spec/vtc/elections/list/0.3",
        ),
    ] {
        let mid = doc(
            uris::TASK_VTA_PCS_VOTER_READ_0_3,
            json!({ "contextId": "member", "community": COMMUNITY, "member": persona.did,
                    "read": which, "payload": payload }),
        );
        let mid = ok(&handle_voter_read(&state, &auth, mid).await);
        assert_eq!(mid["document"]["type"], signed);
    }
    // voter/read 0.2, still served, signs the show its version names: 0.2.
    let old = doc(
        uris::TASK_VTA_PCS_VOTER_READ_0_2,
        json!({ "contextId": "member", "community": COMMUNITY, "member": persona.did,
                "read": "show", "payload": { "electionId": "agm-2028" } }),
    );
    let old = ok(&handle_voter_read(&state, &auth, old).await);
    assert_eq!(
        old["document"]["type"],
        "https://trusttasks.org/spec/vtc/elections/show/0.2"
    );
    assert_eq!(d["issuer"], persona.did.as_str());
    assert_eq!(d["recipient"], COMMUNITY);
    assert_eq!(d["payload"], json!({ "electionId": "agm-2028" }));
    let signer = vta_sdk::trust_task_proof::verify_trust_task_proof_value(
        d,
        &vta_sdk::trust_task_proof::TrustTaskVmResolver::did_key_only(),
    )
    .await
    .expect("the member's proof verifies");
    assert_eq!(signer, persona.did);

    let listed = ok(&handle_voter_read(&state, &auth, read(&persona.did, "list", json!({}))).await);
    assert_eq!(
        listed["document"]["type"],
        "https://trusttasks.org/spec/vtc/elections/list/0.5"
    );
    // Item 3: only the engine builds a presentation.
    let out = handle_voter_read(
        &state,
        &auth,
        read(
            &persona.did,
            "show",
            json!({ "electionId": "agm-2028", "presentation": "x~y~z" }),
        ),
    )
    .await;
    assert_eq!(code(&out), "malformedRequest");

    // A payload the read's own schema refuses is not signed.
    let out = handle_voter_read(&state, &auth, read(&persona.did, "show", json!({}))).await;
    assert_eq!(code(&out), "malformedRequest");
    let out = handle_voter_read(
        &state,
        &auth,
        read("did:key:z6MkNotHeldHere", "list", json!({})),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/voter/read:memberNotHeld");
}

// ─── Credential rolls (VTI-VOT-015, VTI-VOT-016, VTI-VOT-025) ───────────────

const GROUP: &str = "did:webvh:QmGroup:vtc.example.org:groups:g7";

/// A Data Integrity membership credential `issuer` issued `subject`, held in the vault.
async fn held_membership(state: &AppState, id: &str, issuer: &str, subject: &str) {
    use crate::vault::model::{CredentialFormat, CredentialStatus, StoredCredential};
    let vc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "MembershipCredential"],
        "issuer": issuer,
        "credentialSubject": { "id": subject },
        "proof": { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
                   "proofValue": "z5vExampleCredentialProof" },
    });
    let cred = StoredCredential {
        id: id.into(),
        format: CredentialFormat::EddsaJcs2022,
        types: vec!["MembershipCredential".into()],
        schema_id: None,
        community_did: None,
        context_id: None,
        subject_did: Some(subject.to_string()),
        issuer_did: Some(issuer.to_string()),
        purpose: None,
        status: CredentialStatus::Valid,
        valid_from: None,
        valid_until: None,
        received_at: "2026-01-01T00:00:00Z".into(),
        source: None,
        tags: Default::default(),
        body: serde_json::to_vec(&vc).unwrap(),
        lifecycle: vti_common::vault::VaultStatus::Active,
        archived_at: None,
        deleted_at: None,
        grace_until: None,
    };
    crate::vault::storage::put(&state.vault_ks, &cred)
        .await
        .unwrap();
}

/// The member's DID: a holder key this VTA derives in the `member` context, which it both signs
/// the ticket request with and presents the membership credential as.
async fn member_persona(state: &AppState) -> MemberDid {
    let ctx = crate::contexts::create_context(&state.contexts_ks, "member", "member")
        .await
        .unwrap();
    let path = format!("{}/7'", ctx.base_path);
    MemberDid {
        did: crate::test_support::seed_holder_key(state, &path, Some("member")).await,
    }
}

struct MemberDid {
    did: String,
}

/// VTI-VOT-025, register item 9: under a credential roll the ticket request carries a
/// presentation of the member's one membership credential for `roll.memberOf`, made as the
/// member, bound to that document's `id` and to the community.
#[tokio::test]
async fn vti_vot_025_the_ticket_request_presents_the_membership_bound_to_it() {
    let (state, _dir) = build_signing_test_app_state().await;
    let auth = claims("did:key:z6MkVoter", Role::Admin, "member");
    let persona = member_persona(&state).await;
    held_membership(&state, "vmc-eng", GROUP, &persona.did).await;
    let mut rng = StdRng::seed_from_u64(0xC1);
    let reg = Registrar::generate(COMMUNITY, &mut rng).unwrap();
    let params = json!({ "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() });
    let (box_did, _) = box_key(21);
    let mut m = manifest("eng-2027", &box_did, true, "open");
    m["roll"] = json!({ "rule": "credential", "memberOf": GROUP });

    let answer = ok(&handle_voter_register(
        &state,
        &auth,
        doc(
            uris::TASK_VTA_PCS_VOTER_REGISTER_0_5,
            json!({ "contextId": "member", "community": COMMUNITY, "parameters": params,
                    "manifest": m, "member": persona.did, "membershipCredential": "vmc-eng" }),
        ),
    )
    .await);
    let ticket = &answer["ticketDocument"];
    assert_eq!(
        ticket["type"],
        "https://trusttasks.org/spec/vtc/elections/tickets/issue/0.3"
    );
    let vp = &ticket["payload"]["presentation"];
    assert_eq!(vp["nonce"], ticket["id"], "bound to this document");
    assert_eq!(vp["domain"], COMMUNITY, "and to the community");
    assert_eq!(vp["holder"], persona.did.as_str());
    assert_eq!(vp["verifiableCredential"][0]["issuer"], GROUP);
    assert_eq!(vp["proof"]["proofPurpose"], "authentication");
    // The whole document, presentation included, is signed as the member.
    let signer = vta_sdk::trust_task_proof::verify_trust_task_proof_value(
        ticket,
        &vta_sdk::trust_task_proof::TrustTaskVmResolver::did_key_only(),
    )
    .await
    .expect("the member's proof verifies");
    assert_eq!(signer, persona.did);
}

/// VTI-VOT-025, register item 9: no credential under a credential roll, a credential under any
/// other rule, one issued by another party, or one the vault does not hold are refused before
/// anything is allocated.
#[tokio::test]
async fn vti_vot_025_a_credential_roll_refuses_a_missing_or_unusable_credential() {
    let (state, _dir) = build_signing_test_app_state().await;
    let auth = claims("did:key:z6MkVoter", Role::Admin, "member");
    let persona = member_persona(&state).await;
    held_membership(
        &state,
        "vmc-other",
        "did:webvh:QmOther:other.example",
        &persona.did,
    )
    .await;
    let mut rng = StdRng::seed_from_u64(0xC2);
    let reg = Registrar::generate(COMMUNITY, &mut rng).unwrap();
    let params = json!({ "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() });
    let (box_did, _) = box_key(22);
    let mut credential_roll = manifest("eng-2028", &box_did, true, "open");
    credential_roll["roll"] = json!({ "rule": "credential", "memberOf": GROUP });
    let members = manifest("all-2028", &box_did, true, "open");
    let ask = |m: &Value, extra: Value| {
        let mut p = json!({ "contextId": "member", "community": COMMUNITY,
                            "parameters": params, "manifest": m, "member": persona.did });
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        doc(uris::TASK_VTA_PCS_VOTER_REGISTER_0_5, p)
    };
    // Under a credential roll, no credential.
    let out = handle_voter_register(&state, &auth, ask(&credential_roll, json!({}))).await;
    assert_eq!(
        code(&out),
        "vta/pcs/voter/register:membershipCredentialRequired"
    );
    // A credential under any other rule.
    let other = json!({ "membershipCredential": "vmc-other" });
    let out = handle_voter_register(&state, &auth, ask(&members, other.clone())).await;
    assert_eq!(
        code(&out),
        "vta/pcs/voter/register:membershipCredentialRequired"
    );
    // One issued by a party other than `roll.memberOf`.
    let out = handle_voter_register(&state, &auth, ask(&credential_roll, other)).await;
    assert_eq!(
        code(&out),
        "vta/pcs/voter/register:membershipCredentialUnusable"
    );
    // One the vault does not hold.
    let absent = json!({ "membershipCredential": "vmc-absent" });
    let out = handle_voter_register(&state, &auth, ask(&credential_roll, absent)).await;
    assert_eq!(
        code(&out),
        "vta/pcs/voter/register:membershipCredentialUnusable"
    );
    // Nothing was allocated for the refused requests.
    assert!(
        !unwrapped_rows(&state)
            .await
            .iter()
            .any(|r| r.starts_with("voter:")),
        "a refused membershipCredential allocates nothing"
    );
}

/// VTI-VOT-016, read items 5 – 6: a `show` naming `memberOf` presents the credential only where
/// that exact DID issued it; any other issuer — even a group of `memberOf` — is a mismatch.
#[tokio::test]
async fn vti_vot_016_a_read_presents_only_a_credential_memberof_issued() {
    let (state, _dir) = build_signing_test_app_state().await;
    let auth = claims("did:key:z6MkVoter", Role::Admin, "member");
    let persona = member_persona(&state).await;
    let party = "did:webvh:QmParty:b.example";
    held_membership(&state, "vmc-party", party, &persona.did).await;
    held_membership(
        &state,
        "vmc-party-group",
        &format!("{party}:groups:g1"),
        &persona.did,
    )
    .await;
    let read = |credential: &str, member_of: &str| {
        doc(
            uris::TASK_VTA_PCS_VOTER_READ_0_6,
            json!({ "contextId": "member", "community": COMMUNITY, "member": persona.did,
                    "read": "show", "payload": { "electionId": "party-2027" },
                    "membershipCredential": credential, "memberOf": member_of }),
        )
    };

    let out = handle_voter_read(&state, &auth, read("vmc-party-group", party)).await;
    assert_eq!(
        code(&out),
        "vta/pcs/voter/read:membershipCredentialMismatch"
    );
    let out = handle_voter_read(&state, &auth, read("vmc-absent", party)).await;
    assert_eq!(
        code(&out),
        "vta/pcs/voter/read:membershipCredentialUnusable"
    );

    let shown = ok(&handle_voter_read(&state, &auth, read("vmc-party", party)).await);
    let d = &shown["document"];
    assert_eq!(
        d["type"],
        "https://trusttasks.org/spec/vtc/elections/show/0.6"
    );
    let vp = &d["payload"]["presentation"];
    assert_eq!(vp["nonce"], d["id"]);
    assert_eq!(vp["domain"], COMMUNITY);
    assert_eq!(vp["verifiableCredential"][0]["issuer"], party);
    assert_eq!(d["payload"]["electionId"], "party-2027");
}
