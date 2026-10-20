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
        "registrationOpens": t(opens - chrono::Duration::days(1)), "votingOpens": t(opens),
        "votingCloses": t(closes), "revote": "replace",
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
        uris::TASK_VTA_PCS_VOTER_REGISTER_0_1,
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
        uris::TASK_VTA_PCS_VOTE_0_1,
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
    let receipt_payload = bb.cast(&cast_doc["payload"], now).unwrap();
    assert_eq!(receipt_payload["outcome"], "counted");
    let receipt = signed(
        "https://trusttasks.org/spec/voting/ballot/cast/0.1#response",
        &box_did,
        &box_signer,
        receipt_payload.clone(),
    )
    .await;
    let sel = json!({ "community": COMMUNITY, "electionId": "agm-2027" });
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
            uris::TASK_VTA_PCS_VOTER_REGISTER_0_1,
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
            uris::TASK_VTA_PCS_VOTER_REGISTER_0_1,
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
        "https://trusttasks.org/spec/vtc/elections/tickets/issue/0.1"
    );
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
}

/// `vta/pcs/voter/read`: one of the two election reads, signed as the member — and nothing else.
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
            uris::TASK_VTA_PCS_VOTER_READ_0_1,
            json!({ "contextId": "member", "community": COMMUNITY, "member": member,
                    "read": which, "payload": payload }),
        )
    };

    let shown = ok(&handle_voter_read(
        &state,
        &auth,
        read(&persona.did, "show", json!({ "electionId": "agm-2028" })),
    )
    .await);
    let d = &shown["document"];
    assert_eq!(
        d["type"],
        "https://trusttasks.org/spec/vtc/elections/show/0.1"
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
        "https://trusttasks.org/spec/vtc/elections/list/0.1"
    );

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
