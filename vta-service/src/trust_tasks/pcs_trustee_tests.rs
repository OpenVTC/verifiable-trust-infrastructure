//! The encrypted levels end to end through the VTA's own handlers, against a real ballot box:
//! three trustee personas held here generate the election key with the box, a member votes a
//! sealed ballot with `vta/pcs/vote-encrypted`, the community closes, two trustees decrypt, and
//! the box publishes the result. Every trustee document is signed as its trustee persona and
//! verified as such before the box sees it. Then every code the new specifications declare.

use super::*;
use crate::acl::Role;
use crate::operations::persona::test_fixture::did_key_persona;
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
const CTX: &str = "member";

fn claims(did: &str) -> AuthClaims {
    AuthClaims {
        did: did.to_string(),
        role: Role::Admin,
        allowed_contexts: vec![CTX.to_string()],
        session_id: "test-session".into(),
        access_expires_at: 0,
        issued_at: 0,
        amr: Vec::new(),
        acr: String::new(),
    }
}

fn doc(uri: &str, payload: Value) -> TrustTask<Value> {
    let uri: TypeUri = uri.parse().expect("uri");
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

fn box_key() -> (String, HolderKey) {
    let public = ed25519_dalek::SigningKey::from_bytes(&[41; 32])
        .verifying_key()
        .to_bytes();
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&public)
    );
    let key = HolderKey::from_did_key(
        &did,
        multibase::encode(multibase::Base::Base58Btc, [41; 32]),
    )
    .unwrap();
    (did, key)
}

fn manifest(trustees: &[String], ballot_box: &str) -> Value {
    let now = chrono::Utc::now();
    let t = |d: chrono::DateTime<chrono::Utc>| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    json!({
        "electionId": "sealed-2027", "community": COMMUNITY,
        "questions": [{ "key": "chair", "type": "choice",
            "options": [{ "key": "ana" }, { "key": "ben" }],
            "minSelections": 1, "maxSelections": 1, "optional": false }],
        "secrecy": "sealed",
        "trustees": { "dids": trustees, "threshold": 2 },
        "roll": { "rule": "members" },
        "registrationOpens": t(now - chrono::Duration::days(2)),
        "votingOpens": t(now - chrono::Duration::hours(1)),
        "votingCloses": t(now + chrono::Duration::days(1)),
        "revote": "replace",
        "board": { "visibility": "public", "auditors": [] }, "ballotBox": ballot_box,
        "binding": false, "allowEarlyClose": true, "resultsBeforeClose": false,
        "textReleaseThreshold": 10,
    })
}

/// The signer a trustee document proves, required to be its issuer — what the voting service
/// checks before the box sees the payload.
async fn proven(document: &Value) -> String {
    let signer = vti_common::auth::verify_trust_task_proof_value(
        document,
        &vti_common::auth::TrustTaskVmResolver::did_key_only(),
    )
    .await
    .expect("signed as the trustee");
    assert_eq!(document["issuer"], signer.as_str());
    signer
}

fn trustee_doc(uri: &str, trustee: &str, extra: Value) -> TrustTask<Value> {
    let mut p = json!({ "contextId": CTX, "community": COMMUNITY, "electionId": "sealed-2027",
                        "trustee": trustee });
    p.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    doc(uri, p)
}

#[tokio::test]
async fn trustees_and_a_voter_run_a_sealed_election_through_the_vta() {
    let (state, _dir) = build_signing_test_app_state().await;
    crate::contexts::create_context(&state.contexts_ks, CTX, CTX)
        .await
        .unwrap();
    let auth = claims("did:key:z6MkOperator");
    let mut personas = Vec::new();
    for label in ["trustee-1", "trustee-2", "trustee-3"] {
        personas.push(
            did_key_persona(
                &state.keys_ks,
                &state.internal_ks,
                &state.contexts_ks,
                &state.acl_ks,
                &state.seed_store,
                &state.audit_sink,
                CTX,
                label,
            )
            .await
            .did,
        );
    }
    let (box_did, box_signer) = box_key();
    let m = manifest(&personas, &box_did);
    let digest = manifest_digest(&m).unwrap();
    let mut rng = StdRng::seed_from_u64(0xC0);
    let reg = Registrar::generate(COMMUNITY, &mut rng).unwrap();
    let params = json!({ "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() });
    let mut bb = BallotBox::new(&box_did);
    let now = chrono::Utc::now;
    bb.register(
        COMMUNITY,
        &json!({ "community": COMMUNITY, "manifest": m,
                 "manifestDigest": digest_multibase(&digest), "parameters": params }),
        now() - chrono::Duration::hours(2),
    )
    .unwrap();
    let sel = json!({ "community": COMMUNITY, "electionId": "sealed-2027" });

    // The key ceremony. Voting opened an hour ago, so register the box's clock before then.
    for p in &personas {
        let d = ok(&handle_trustee_enrol(
            &state,
            &auth,
            trustee_doc(
                uris::TASK_VTA_PCS_TRUSTEE_ENROL_0_1,
                p,
                json!({ "manifest": m }),
            ),
        )
        .await)["document"]
            .clone();
        let signer = proven(&d).await;
        assert_eq!(d["recipient"], box_did.as_str());
        let before = now() - chrono::Duration::hours(2);
        bb.trustees_enrol(&signer, &d, before).unwrap();
        // A repeat is the same transport key, which the box answers as the first.
        let again = ok(&handle_trustee_enrol(
            &state,
            &auth,
            trustee_doc(
                uris::TASK_VTA_PCS_TRUSTEE_ENROL_0_1,
                p,
                json!({ "manifest": m }),
            ),
        )
        .await)["document"]
            .clone();
        assert_eq!(
            again["payload"]["transportKey"],
            d["payload"]["transportKey"]
        );
    }
    let before = || now() - chrono::Duration::hours(2);
    let status = bb
        .trustees_status(BoxCaller::Anonymous, &sel, before())
        .unwrap();
    assert_eq!(status["phase"], "dealing");
    for p in &personas {
        let d = ok(&handle_trustee_deal(
            &state,
            &auth,
            trustee_doc(
                uris::TASK_VTA_PCS_TRUSTEE_DEAL_0_1,
                p,
                json!({ "manifest": m, "transportKeys": status["transportKeys"] }),
            ),
        )
        .await)["document"]
            .clone();
        bb.trustees_deal(&proven(&d).await, &d, before()).unwrap();
    }
    let status = bb
        .trustees_status(BoxCaller::Anonymous, &sel, before())
        .unwrap();
    for p in &personas {
        let out = ok(&handle_trustee_keys(
            &state,
            &auth,
            trustee_doc(
                uris::TASK_VTA_PCS_TRUSTEE_KEYS_0_1,
                p,
                json!({ "manifest": m, "dealings": status["dealings"] }),
            ),
        )
        .await);
        assert_eq!(out["complaints"], json!([]));
        let d = out["document"].clone();
        bb.trustees_confirm(&proven(&d).await, &d, before())
            .unwrap();
    }
    let status = bb
        .trustees_status(BoxCaller::Anonymous, &sel, before())
        .unwrap();
    assert_eq!(status["phase"], "keyed");
    for p in &personas {
        let out = ok(&handle_trustee_keys(
            &state,
            &auth,
            trustee_doc(
                uris::TASK_VTA_PCS_TRUSTEE_KEYS_0_1,
                p,
                json!({ "manifest": m, "dealings": status["dealings"],
                        "electionKey": status["electionKey"] }),
            ),
        )
        .await);
        assert_eq!(out["keyHeld"], true);
    }

    // A member registers, takes the ticket, and casts a sealed ballot.
    let register = doc(
        uris::TASK_VTA_PCS_VOTER_REGISTER_0_1,
        json!({ "contextId": CTX, "community": COMMUNITY, "parameters": params, "manifest": m }),
    );
    let first = ok(&handle_voter_register(&state, &auth, register).await);
    let election =
        Election::new(COMMUNITY, ElectionId::new("sealed-2027").unwrap(), digest).unwrap();
    let id =
        vti_vetting_pcs::scheme::point_from_text(first["request"]["id"].as_str().unwrap()).unwrap();
    let request = serde_json::from_value(first["request"]["request"].clone()).unwrap();
    let pre = vti_vetting_pcs::scheme::enc(
        &reg.issue_ticket(&election, &id, &request, &mut rng)
            .unwrap(),
    )
    .unwrap();
    ok(&handle_voter_accept(
        &state,
        &auth,
        doc(
            uris::TASK_VTA_PCS_VOTER_ACCEPT_0_1,
            json!({ "contextId": CTX, "community": COMMUNITY, "electionId": "sealed-2027",
                    "parameters": params,
                    "response": { "electionId": "sealed-2027", "label": "voter/sealed-2027", "preCredential": pre } }),
        ),
    )
    .await);
    let ballot = json!({
        "electionId": "sealed-2027", "manifestDigest": digest_multibase(&digest),
        "answers": [{ "question": "chair", "choice": ["ben"] }],
    });
    let vote = |b: Value| {
        doc(
            uris::TASK_VTA_PCS_VOTE_ENCRYPTED_0_1,
            json!({ "contextId": CTX, "community": COMMUNITY, "parameters": params, "manifest": m,
                    "electionKey": status["electionKey"], "ballot": b }),
        )
    };
    let voted = ok(&handle_vote_encrypted(&state, &auth, vote(ballot.clone())).await);
    let cast_doc = voted["castDocument"].clone();
    assert_eq!(
        cast_doc["type"],
        "https://trusttasks.org/spec/voting/ballot/cast-encrypted/0.1#request"
    );
    assert!(cast_doc["payload"]["cast"].get("sealed").is_some());
    assert!(
        !cast_doc.to_string().contains("\"ben\""),
        "the plaintext ballot never leaves"
    );
    let receipt_payload = bb.cast_encrypted(&cast_doc["payload"], now()).unwrap();
    // The cleartext task refuses a sealed election's ballot.
    assert_eq!(
        code(
            &handle_vote(
                &state,
                &auth,
                doc(
                    uris::TASK_VTA_PCS_VOTE_0_1,
                    json!({ "contextId": CTX, "community": COMMUNITY, "parameters": params,
                        "manifest": m, "ballot": ballot }),
                )
            )
            .await
        ),
        "malformedRequest"
    );
    // The receipt is recognised as this voter's.
    let mut receipt: TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/voting/ballot/cast-encrypted/0.1#response",
        "issuer": box_did,
        "issuedAt": now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": receipt_payload,
    }))
    .unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut receipt, &box_signer)
        .await
        .unwrap();
    let kept = ok(&handle_voter_receipt(
        &state,
        &auth,
        doc(
            uris::TASK_VTA_PCS_VOTER_RECEIPT_0_1,
            json!({ "contextId": CTX, "community": COMMUNITY, "electionId": "sealed-2027",
                    "receipt": serde_json::to_value(&receipt).unwrap() }),
        ),
    )
    .await);
    assert_eq!(kept["status"], "kept");

    // Before close, no trustee decrypts.
    let early = now() + chrono::Duration::hours(1);
    let p = &status["transportKeys"][0]["key"];
    let targets = json!([{ "leafIndex": 0, "ciphertext": { "a": p, "b": p } }]);
    let out = handle_trustee_decrypt(
        &state,
        &auth,
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_DECRYPT_0_1,
            &personas[0],
            json!({ "targets": targets, "closedAt": early.to_rfc3339() }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/decrypt:notClosed");

    // The community closes; two trustees decrypt; the box publishes the result.
    let closed = now();
    bb.close(COMMUNITY, &sel, closed).unwrap();
    let status = bb
        .trustees_status(BoxCaller::Anonymous, &sel, now())
        .unwrap();
    assert_eq!(status["phase"], "decrypting");
    for p in &personas[1..] {
        let d = ok(&handle_trustee_decrypt(
            &state,
            &auth,
            trustee_doc(
                uris::TASK_VTA_PCS_TRUSTEE_DECRYPT_0_1,
                p,
                json!({ "targets": status["targets"], "closedAt": closed.to_rfc3339() }),
            ),
        )
        .await)["document"]
            .clone();
        bb.trustees_decrypt(&proven(&d).await, &d, now()).unwrap();
    }
    let result = bb.result(BoxCaller::Anonymous, &sel, now()).unwrap();
    assert_eq!(
        result["result"]["questions"][0]["choice"],
        json!({ "ana": 0, "ben": 1 })
    );
}

#[tokio::test]
async fn the_trustee_tasks_refuse_with_the_codes_their_specifications_declare() {
    let (state, _dir) = build_signing_test_app_state().await;
    crate::contexts::create_context(&state.contexts_ks, CTX, CTX)
        .await
        .unwrap();
    let auth = claims("did:key:z6MkOperator");
    let held = did_key_persona(
        &state.keys_ks,
        &state.internal_ks,
        &state.contexts_ks,
        &state.acl_ks,
        &state.seed_store,
        &state.audit_sink,
        CTX,
        "trustee-key",
    )
    .await
    .did;
    let (box_did, _) = box_key();
    let others = vec![
        held.clone(),
        "did:key:z6MkOtherTrustee2".to_string(),
        "did:key:z6MkOtherTrustee3".to_string(),
    ];
    let m = manifest(&others, &box_did);
    let not_held = "did:key:z6MkNotHeldHere";
    // Well-formed values that prove nothing: each refusal below is the task's own, never the
    // schema's.
    let mut grng = StdRng::seed_from_u64(9);
    let tk = vti_voting::trustees::TransportSecret::generate(1, &mut grng).publish(b"x", &mut grng);
    let point = vti_voting::trustees::point_text(&tk.key);
    let scalar = vti_voting::trustees::scalar_text(&tk.pok.c);
    let sigma = json!({ "c": scalar, "z": scalar });
    let fake_tks = json!([{ "trustee": 1, "key": point, "pok": sigma }, { "trustee": 2, "key": point, "pok": sigma }]);
    let ct = json!({ "a": point, "b": point });
    let fake_dealings = json!([{ "dealer": 2, "commitments": [point, point], "pok": sigma,
        "shares": [{ "recipient": 1, "share": { "kem": ct, "body": "z3ZeMb8yW1fRq2Rr5b6tHn7Kx9Lp2Vd" } }] }]);
    let fake_targets = json!([{ "leafIndex": 0, "ciphertext": ct }]);

    // trusteeNotHeld, at every trustee task.
    let cases = [
        (
            uris::TASK_VTA_PCS_TRUSTEE_ENROL_0_1,
            json!({ "manifest": m }),
        ),
        (
            uris::TASK_VTA_PCS_TRUSTEE_DEAL_0_1,
            json!({ "manifest": m, "transportKeys": fake_tks }),
        ),
        (
            uris::TASK_VTA_PCS_TRUSTEE_KEYS_0_1,
            json!({ "manifest": m, "dealings": fake_dealings }),
        ),
        (
            uris::TASK_VTA_PCS_TRUSTEE_JUSTIFY_0_1,
            json!({ "recipient": 2 }),
        ),
        (
            uris::TASK_VTA_PCS_TRUSTEE_DECRYPT_0_1,
            json!({ "targets": fake_targets, "closedAt": "2026-01-01T00:00:00Z" }),
        ),
    ];
    let mut seen = Vec::new();
    for (uri, extra) in &cases {
        let d = trustee_doc(uri, not_held, extra.clone());
        let out = match *uri {
            u if u == uris::TASK_VTA_PCS_TRUSTEE_ENROL_0_1 => {
                handle_trustee_enrol(&state, &auth, d).await
            }
            u if u == uris::TASK_VTA_PCS_TRUSTEE_DEAL_0_1 => {
                handle_trustee_deal(&state, &auth, d).await
            }
            u if u == uris::TASK_VTA_PCS_TRUSTEE_KEYS_0_1 => {
                handle_trustee_keys(&state, &auth, d).await
            }
            u if u == uris::TASK_VTA_PCS_TRUSTEE_JUSTIFY_0_1 => {
                handle_trustee_justify(&state, &auth, d).await
            }
            _ => handle_trustee_decrypt(&state, &auth, d).await,
        };
        seen.push(code(&out));
    }
    assert_eq!(seen[0], "vta/pcs/trustee/enrol:trusteeNotHeld");
    assert_eq!(seen[1], "vta/pcs/trustee/deal:trusteeNotHeld");
    assert_eq!(seen[2], "vta/pcs/trustee/keys:trusteeNotHeld");
    assert_eq!(seen[3], "vta/pcs/trustee/justify:trusteeNotHeld");
    assert_eq!(seen[4], "vta/pcs/trustee/decrypt:trusteeNotHeld");

    // notTrustee: a persona held here that the manifest does not name.
    let elsewhere = manifest(
        &[
            "did:key:z6MkOtherTrustee2".to_string(),
            "did:key:z6MkOtherTrustee3".to_string(),
            "did:key:z6MkOtherTrustee4".to_string(),
        ],
        &box_did,
    );
    let out = handle_trustee_enrol(
        &state,
        &auth,
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_ENROL_0_1,
            &held,
            json!({ "manifest": elsewhere }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/enrol:notTrustee");

    // Before enrolling: notEnrolled at deal and keys, noDealing at justify, keyNotHeld at decrypt.
    let out = handle_trustee_deal(
        &state,
        &auth,
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_DEAL_0_1,
            &held,
            json!({ "manifest": m, "transportKeys": fake_tks }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/deal:notEnrolled");
    let out = handle_trustee_keys(
        &state,
        &auth,
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_KEYS_0_1,
            &held,
            json!({ "manifest": m, "dealings": fake_dealings }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/keys:notEnrolled");
    let out = handle_trustee_justify(
        &state,
        &auth,
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_JUSTIFY_0_1,
            &held,
            json!({ "recipient": 2 }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/justify:noDealing");
    let out = handle_trustee_decrypt(
        &state,
        &auth,
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_DECRYPT_0_1,
            &held,
            json!({ "targets": fake_targets, "closedAt": "2026-01-01T00:00:00Z" }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/decrypt:keyNotHeld");

    // Enrolled: transport keys that do not verify, and an election key that is not this one's.
    ok(&handle_trustee_enrol(
        &state,
        &auth,
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_ENROL_0_1,
            &held,
            json!({ "manifest": m }),
        ),
    )
    .await);
    let out = handle_trustee_deal(
        &state,
        &auth,
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_DEAL_0_1,
            &held,
            json!({ "manifest": m, "transportKeys": fake_tks }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/deal:transportKeysInvalid");
    let wrong_key = json!({ "key": point, "qualified": [1, 2, 3],
        "verification": [{ "trustee": 1, "key": point }, { "trustee": 2, "key": point }, { "trustee": 3, "key": point }] });
    let out = handle_trustee_keys(
        &state,
        &auth,
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_KEYS_0_1,
            &held,
            json!({ "manifest": m, "dealings": fake_dealings, "electionKey": wrong_key }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/keys:keyMismatch");

    // vote-encrypted: no ticket, the wrong level, a key with other trustees, a bad ballot, and
    // outside the window.
    let mut rng = StdRng::seed_from_u64(0xC1);
    let reg = Registrar::generate(COMMUNITY, &mut rng).unwrap();
    let params = json!({ "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() });
    let ve = |manifest: &Value, key: &Value, ballot: Value| {
        doc(
            uris::TASK_VTA_PCS_VOTE_ENCRYPTED_0_1,
            json!({ "contextId": CTX, "community": COMMUNITY, "parameters": params,
                    "manifest": manifest, "electionKey": key, "ballot": ballot }),
        )
    };
    let digest = manifest_digest(&m).unwrap();
    let ballot = |choice: &str| {
        json!({ "electionId": "sealed-2027", "manifestDigest": digest_multibase(&digest),
                "answers": [{ "question": "chair", "choice": [choice] }] })
    };
    assert_eq!(
        code(&handle_vote_encrypted(&state, &auth, ve(&m, &wrong_key, ballot("ana"))).await),
        "vta/pcs/vote-encrypted:notFound"
    );
    ok(&handle_voter_register(
        &state,
        &auth,
        doc(
            uris::TASK_VTA_PCS_VOTER_REGISTER_0_1,
            json!({ "contextId": CTX, "community": COMMUNITY, "parameters": params, "manifest": m }),
        ),
    )
    .await);
    let mut open_m = m.clone();
    open_m["secrecy"] = json!("open");
    open_m["electionId"] = json!("open-2027");
    open_m.as_object_mut().unwrap().remove("trustees");
    let open_digest = manifest_digest(&open_m).unwrap();
    ok(&handle_voter_register(
        &state,
        &auth,
        doc(
            uris::TASK_VTA_PCS_VOTER_REGISTER_0_1,
            json!({ "contextId": CTX, "community": COMMUNITY, "parameters": params, "manifest": open_m }),
        ),
    )
    .await);
    let _ = open_digest;
    assert_eq!(
        code(&handle_vote_encrypted(&state, &auth, ve(&open_m, &wrong_key, ballot("ana"))).await),
        "vta/pcs/vote-encrypted:wrongLevel"
    );
    let mut two = wrong_key.clone();
    two["verification"].as_array_mut().unwrap().pop();
    assert_eq!(
        code(&handle_vote_encrypted(&state, &auth, ve(&m, &two, ballot("ana"))).await),
        "vta/pcs/vote-encrypted:electionKeyInvalid"
    );
    assert_eq!(
        code(&handle_vote_encrypted(&state, &auth, ve(&m, &wrong_key, ballot("cai"))).await),
        "vta/pcs/vote-encrypted:ballotInvalid"
    );
    let mut later = m.clone();
    later["electionId"] = json!("later-2027");
    let soon = chrono::Utc::now() + chrono::Duration::days(1);
    later["votingOpens"] = json!(soon.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    later["votingCloses"] = json!(
        (soon + chrono::Duration::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    ok(&handle_voter_register(
        &state,
        &auth,
        doc(
            uris::TASK_VTA_PCS_VOTER_REGISTER_0_1,
            json!({ "contextId": CTX, "community": COMMUNITY, "parameters": params, "manifest": later }),
        ),
    )
    .await);
    let later_digest = manifest_digest(&later).unwrap();
    let later_ballot = json!({ "electionId": "later-2027", "manifestDigest": digest_multibase(&later_digest),
        "answers": [{ "question": "chair", "choice": ["ana"] }] });
    assert_eq!(
        code(&handle_vote_encrypted(&state, &auth, ve(&later, &wrong_key, later_ballot)).await),
        "vta/pcs/vote-encrypted:notOpen"
    );
}
