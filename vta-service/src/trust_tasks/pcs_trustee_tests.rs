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

/// The community, as a `did:key` that signs: its decryption authorization must verify as it.
static COMMUNITY_KEY: std::sync::LazyLock<(String, HolderKey)> =
    std::sync::LazyLock::new(|| key_from_seed(43));

fn community() -> &'static str {
    &COMMUNITY_KEY.0
}
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
    key_from_seed(41)
}

/// A `did:key` and its signing key, from one byte of seed.
fn key_from_seed(seed: u8) -> (String, HolderKey) {
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

fn manifest(trustees: &[String], ballot_box: &str) -> Value {
    let now = chrono::Utc::now();
    let t = |d: chrono::DateTime<chrono::Utc>| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    json!({
        "electionId": "sealed-2027", "community": community(),
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

/// `task` (`voting/<task>`) to the ballot box, signed by `key` as `issuer`.
async fn signed_by(key: &HolderKey, issuer: &str, task: &str, to: &str, payload: Value) -> Value {
    let mut d: TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": format!("https://trusttasks.org/spec/voting/{task}/0.1"),
        "issuer": issuer,
        "recipient": to,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    }))
    .unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut d, key)
        .await
        .unwrap();
    serde_json::to_value(&d).unwrap()
}

/// The community authorizes the decryption the closed board calls for (CONVENTIONS §9.7): it
/// reads the board, computes the targets itself, and signs their digest under the closing head.
async fn authorize(
    bb: &mut BallotBox,
    reg: &Registrar,
    m: &Value,
    box_did: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Value {
    let sel = json!({ "community": community(), "electionId": m["electionId"] });
    let mut read = sel.clone();
    read["from"] = json!(0);
    read["limit"] = json!(1000);
    let entries: Vec<Value> = bb
        .board_read(BoxCaller::Did(community()), &read, at)
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
    let closing = vti_voting::audit::decryption(m, &reg.params(), &entries, &proven)
        .unwrap()
        .expect("the board has closed");
    let size = closing.index as usize + 1;
    let mut board = vti_voting::board::Board::new();
    for e in &entries[..size] {
        board.append(&serde_json_canonicalizer::to_vec(e).unwrap());
    }
    let values = closing.target_values();
    let mut payload = sel;
    payload["manifestDigest"] = json!(digest_multibase(&manifest_digest(m).unwrap()));
    payload["head"] = json!({ "electionId": m["electionId"], "treeSize": size,
        "rootHash": digest_multibase(&board.root(size).unwrap()), "issuedAt": closing.at });
    payload["closedAt"] = json!(closing.at);
    payload["targetCount"] = json!(values.len());
    payload["targetsDigest"] = json!(vti_voting::audit::targets_digest(&values).unwrap());
    let doc = signed_by(
        &COMMUNITY_KEY.1,
        community(),
        "trustees/authorize",
        box_did,
        payload,
    )
    .await;
    bb.trustees_authorize(community(), &doc, at).unwrap();
    doc
}

fn trustee_doc(uri: &str, trustee: &str, extra: Value) -> TrustTask<Value> {
    let mut p = json!({ "contextId": CTX, "community": community(), "electionId": "sealed-2027",
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
    let reg = Registrar::generate(community(), &mut rng).unwrap();
    let params = json!({ "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() });
    let mut bb = BallotBox::new(&box_did);
    let now = chrono::Utc::now;
    bb.register(
        community(),
        &json!({ "community": community(), "manifest": m,
                 "manifestDigest": digest_multibase(&digest), "parameters": params }),
        now() - chrono::Duration::hours(2),
    )
    .unwrap();
    let sel = json!({ "community": community(), "electionId": "sealed-2027" });

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
                uris::TASK_VTA_PCS_TRUSTEE_DEAL_0_2,
                p,
                json!({ "manifest": m, "ceremony": status["steps"] }),
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
                uris::TASK_VTA_PCS_TRUSTEE_KEYS_0_2,
                p,
                json!({ "manifest": m, "ceremony": status["steps"] }),
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
                uris::TASK_VTA_PCS_TRUSTEE_KEYS_0_2,
                p,
                json!({ "manifest": m, "ceremony": status["steps"] }),
            ),
        )
        .await);
        assert_eq!(out["keyHeld"], true);
    }

    // A member registers, takes the ticket, and casts a sealed ballot.
    let register = doc(
        uris::TASK_VTA_PCS_VOTER_REGISTER_0_1,
        json!({ "contextId": CTX, "community": community(), "parameters": params, "manifest": m }),
    );
    let first = ok(&handle_voter_register(&state, &auth, register).await);
    let election =
        Election::new(community(), ElectionId::new("sealed-2027").unwrap(), digest).unwrap();
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
            json!({ "contextId": CTX, "community": community(), "electionId": "sealed-2027",
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
            uris::TASK_VTA_PCS_VOTE_ENCRYPTED_0_2,
            json!({ "contextId": CTX, "community": community(), "parameters": params, "manifest": m,
                    "ceremony": status["steps"], "ballot": b }),
        )
    };
    // A ceremony some step of which no trustee signed forms no key the VTA will encrypt under:
    // the box's unsigned dealing in place of a trustee's.
    let mut forged = status["steps"].clone();
    forged.as_array_mut().unwrap()[3]
        .as_object_mut()
        .unwrap()
        .remove("proof");
    let forged_vote = doc(
        uris::TASK_VTA_PCS_VOTE_ENCRYPTED_0_2,
        json!({ "contextId": CTX, "community": community(), "parameters": params, "manifest": m,
                "ceremony": forged, "ballot": ballot }),
    );
    assert_eq!(
        code(&handle_vote_encrypted(&state, &auth, forged_vote).await),
        "vta/pcs/vote-encrypted:electionKeyInvalid"
    );
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
                    json!({ "contextId": CTX, "community": community(), "parameters": params,
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
            json!({ "contextId": CTX, "community": community(), "electionId": "sealed-2027",
                    "receipt": serde_json::to_value(&receipt).unwrap() }),
        ),
    )
    .await);
    assert_eq!(kept["status"], "kept");

    // The community closes and authorizes exactly the decryption the board calls for; two
    // trustees decrypt that, and the box publishes the result.
    let closed = now();
    bb.close(community(), &sel, closed).unwrap();
    let status = bb
        .trustees_status(BoxCaller::Anonymous, &sel, now())
        .unwrap();
    assert_eq!(status["phase"], "decrypting");
    assert!(status.get("authorization").is_none());
    authorize(&mut bb, &reg, &m, &box_did, now()).await;
    let status = bb
        .trustees_status(BoxCaller::Anonymous, &sel, now())
        .unwrap();
    for p in &personas[1..] {
        let d = ok(&handle_trustee_decrypt(
            &state,
            &auth,
            trustee_doc(
                uris::TASK_VTA_PCS_TRUSTEE_DECRYPT_0_2,
                p,
                json!({ "targets": status["targets"], "authorization": status["authorization"] }),
            ),
        )
        .await)["document"]
            .clone();
        bb.trustees_decrypt(&proven(&d).await, &d, now()).unwrap();
    }
    // A trustee's VTA decrypts nothing the community did not authorize, and one set only
    // (CONVENTIONS §9.7): not an authorization the ballot box signed, not targets other than the
    // ones it pins, and not a second set even if the community signed it.
    let decrypt_with = |targets: Value, authorization: Value| {
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_DECRYPT_0_2,
            &personas[1],
            json!({ "targets": targets, "authorization": authorization }),
        )
    };
    let mut boxed = status["authorization"].clone();
    boxed["issuer"] = json!(box_did);
    let boxed: Value = {
        let mut d: TrustTask<Value> = serde_json::from_value(boxed).unwrap();
        d.proof = None;
        vta_sdk::trust_task_sign::sign_in_place_with(&mut d, &box_signer)
            .await
            .unwrap();
        serde_json::to_value(&d).unwrap()
    };
    let out = handle_trustee_decrypt(
        &state,
        &auth,
        decrypt_with(status["targets"].clone(), boxed),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/decrypt:authorizationInvalid");
    // Another ciphertext in the target's place — one voter's, say — under the same authorization.
    let k = &status["electionKey"]["key"];
    let one = json!([{ "leafIndex": status["targets"][0]["leafIndex"], "ciphertext": { "a": k, "b": k } }]);
    let out = handle_trustee_decrypt(
        &state,
        &auth,
        decrypt_with(one.clone(), status["authorization"].clone()),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/decrypt:authorizationInvalid");
    let mut other = status["authorization"]["payload"].clone();
    other["targetCount"] = json!(1);
    other["targetsDigest"] =
        json!(vti_voting::audit::targets_digest(one.as_array().unwrap()).unwrap());
    let second = signed_by(
        &COMMUNITY_KEY.1,
        community(),
        "trustees/authorize",
        &box_did,
        other,
    )
    .await;
    let out = handle_trustee_decrypt(&state, &auth, decrypt_with(one, second)).await;
    assert_eq!(code(&out), "vta/pcs/trustee/decrypt:alreadyDecrypted");

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
    // A step no trustee signed: the shape of an enrolment, with no proof.
    let fake_steps = json!([{ "id": "urn:uuid:3f6b9d2e-81c4-4a7f-9e05-6d1c2b8a4f71",
        "type": "https://trusttasks.org/spec/voting/trustees/enrol/0.1", "issuer": held,
        "payload": { "community": community(), "electionId": "sealed-2027",
            "transportKey": { "trustee": 1, "key": point, "pok": sigma } } }]);
    let ct = json!({ "a": point, "b": point });
    let fake_targets = json!([{ "leafIndex": 0, "ciphertext": ct }]);
    let fake_auth = json!({ "id": "urn:uuid:3f6b9d2e-81c4-4a7f-9e05-6d1c2b8a4f72",
        "type": "https://trusttasks.org/spec/voting/trustees/authorize/0.1", "issuer": community(),
        "payload": {} });

    // trusteeNotHeld, at every trustee task.
    let cases = [
        (
            uris::TASK_VTA_PCS_TRUSTEE_ENROL_0_1,
            json!({ "manifest": m }),
        ),
        (
            uris::TASK_VTA_PCS_TRUSTEE_DEAL_0_2,
            json!({ "manifest": m, "ceremony": fake_steps }),
        ),
        (
            uris::TASK_VTA_PCS_TRUSTEE_KEYS_0_2,
            json!({ "manifest": m, "ceremony": fake_steps }),
        ),
        (
            uris::TASK_VTA_PCS_TRUSTEE_JUSTIFY_0_2,
            json!({ "manifest": m, "ceremony": fake_steps, "recipient": 2 }),
        ),
        (
            uris::TASK_VTA_PCS_TRUSTEE_DECRYPT_0_2,
            json!({ "targets": fake_targets, "authorization": fake_auth }),
        ),
    ];
    let mut seen = Vec::new();
    for (uri, extra) in &cases {
        let d = trustee_doc(uri, not_held, extra.clone());
        let out = match *uri {
            u if u == uris::TASK_VTA_PCS_TRUSTEE_ENROL_0_1 => {
                handle_trustee_enrol(&state, &auth, d).await
            }
            u if u == uris::TASK_VTA_PCS_TRUSTEE_DEAL_0_2 => {
                handle_trustee_deal(&state, &auth, d).await
            }
            u if u == uris::TASK_VTA_PCS_TRUSTEE_KEYS_0_2 => {
                handle_trustee_keys(&state, &auth, d).await
            }
            u if u == uris::TASK_VTA_PCS_TRUSTEE_JUSTIFY_0_2 => {
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
            uris::TASK_VTA_PCS_TRUSTEE_DEAL_0_2,
            &held,
            json!({ "manifest": m, "ceremony": fake_steps }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/deal:notEnrolled");
    let out = handle_trustee_keys(
        &state,
        &auth,
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_KEYS_0_2,
            &held,
            json!({ "manifest": m, "ceremony": fake_steps }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/keys:notEnrolled");
    let out = handle_trustee_justify(
        &state,
        &auth,
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_JUSTIFY_0_2,
            &held,
            json!({ "manifest": m, "ceremony": fake_steps, "recipient": 2 }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/justify:noDealing");
    let out = handle_trustee_decrypt(
        &state,
        &auth,
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_DECRYPT_0_2,
            &held,
            json!({ "targets": fake_targets, "authorization": fake_auth }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/decrypt:keyNotHeld");

    // Enrolled: a ceremony whose steps no trustee signed is refused at deal and keys.
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
            uris::TASK_VTA_PCS_TRUSTEE_DEAL_0_2,
            &held,
            json!({ "manifest": m, "ceremony": fake_steps }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/deal:ceremonyInvalid");
    let out = handle_trustee_keys(
        &state,
        &auth,
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_KEYS_0_2,
            &held,
            json!({ "manifest": m, "ceremony": fake_steps }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/trustee/keys:ceremonyInvalid");

    // vote-encrypted: no ticket, the wrong level, a key with other trustees, a bad ballot, and
    // outside the window.
    let mut rng = StdRng::seed_from_u64(0xC1);
    let reg = Registrar::generate(community(), &mut rng).unwrap();
    let params = json!({ "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() });
    let ve = |manifest: &Value, steps: &Value, ballot: Value| {
        doc(
            uris::TASK_VTA_PCS_VOTE_ENCRYPTED_0_2,
            json!({ "contextId": CTX, "community": community(), "parameters": params,
                    "manifest": manifest, "ceremony": steps, "ballot": ballot }),
        )
    };
    let digest = manifest_digest(&m).unwrap();
    let ballot = |choice: &str| {
        json!({ "electionId": "sealed-2027", "manifestDigest": digest_multibase(&digest),
                "answers": [{ "question": "chair", "choice": [choice] }] })
    };
    assert_eq!(
        code(&handle_vote_encrypted(&state, &auth, ve(&m, &fake_steps, ballot("ana"))).await),
        "vta/pcs/vote-encrypted:notFound"
    );
    ok(&handle_voter_register(
        &state,
        &auth,
        doc(
            uris::TASK_VTA_PCS_VOTER_REGISTER_0_1,
            json!({ "contextId": CTX, "community": community(), "parameters": params, "manifest": m }),
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
            json!({ "contextId": CTX, "community": community(), "parameters": params, "manifest": open_m }),
        ),
    )
    .await);
    let _ = open_digest;
    assert_eq!(
        code(&handle_vote_encrypted(&state, &auth, ve(&open_m, &fake_steps, ballot("ana"))).await),
        "vta/pcs/vote-encrypted:wrongLevel"
    );
    assert_eq!(
        code(&handle_vote_encrypted(&state, &auth, ve(&m, &fake_steps, ballot("cai"))).await),
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
            json!({ "contextId": CTX, "community": community(), "parameters": params, "manifest": later }),
        ),
    )
    .await);
    let later_digest = manifest_digest(&later).unwrap();
    let later_ballot = json!({ "electionId": "later-2027", "manifestDigest": digest_multibase(&later_digest),
        "answers": [{ "question": "chair", "choice": ["ana"] }] });
    assert_eq!(
        code(&handle_vote_encrypted(&state, &auth, ve(&later, &fake_steps, later_ballot)).await),
        "vta/pcs/vote-encrypted:notOpen"
    );
}

/// `vta/pcs/trustee/read`: the trustee's client, holding no trustee key, has the VTA sign the
/// two reads a private board answers only to a trustee (CONVENTIONS §4, §9.6) — and the ballot
/// box answers them. A trustee the VTA does not hold is `trusteeNotHeld`; no other read is
/// signed.
#[tokio::test]
async fn a_trustee_reads_its_election_on_a_private_board_through_the_vta() {
    let (state, _dir) = build_signing_test_app_state().await;
    crate::contexts::create_context(&state.contexts_ks, CTX, CTX)
        .await
        .unwrap();
    let auth = claims("did:key:z6MkOperator");
    let mut personas = Vec::new();
    for label in ["trustee-1", "trustee-2"] {
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
    let (box_did, _) = box_key();
    let mut m = manifest(&personas, &box_did);
    m["board"]["visibility"] = json!("private");
    let digest = manifest_digest(&m).unwrap();
    let mut rng = StdRng::seed_from_u64(0xC1);
    let reg = Registrar::generate(community(), &mut rng).unwrap();
    let mut bb = BallotBox::new(&box_did);
    bb.register(
        community(),
        &json!({ "community": community(), "manifest": m,
                 "manifestDigest": digest_multibase(&digest),
                 "parameters": { "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() } }),
        chrono::Utc::now() - chrono::Duration::hours(2),
    )
    .unwrap();
    let now = chrono::Utc::now() - chrono::Duration::hours(2);
    let sel = json!({ "community": community(), "electionId": "sealed-2027" });
    assert!(bb.show(BoxCaller::Anonymous, &sel, now).is_err());

    let read = |which: &str, trustee: &str| {
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_READ_0_1,
            trustee,
            json!({ "ballotBox": box_did, "read": which }),
        )
    };
    let shown = ok(&handle_trustee_read(&state, &auth, read("election", &personas[1])).await);
    let d = &shown["document"];
    assert_eq!(
        d["type"],
        "https://trusttasks.org/spec/voting/election/show/0.1"
    );
    assert_eq!(d["recipient"], box_did.as_str());
    assert_eq!(d["payload"], sel);
    let signer = proven(d).await;
    assert_eq!(
        bb.show(BoxCaller::Did(&signer), &d["payload"], now)
            .unwrap()["manifest"],
        m
    );
    let status = ok(&handle_trustee_read(&state, &auth, read("status", &personas[0])).await);
    let d = &status["document"];
    assert_eq!(
        d["type"],
        "https://trusttasks.org/spec/voting/trustees/status/0.1"
    );
    let signer = proven(d).await;
    assert_eq!(
        bb.trustees_status(BoxCaller::Did(&signer), &d["payload"], now)
            .unwrap()["phase"],
        "enrolling"
    );

    // A trustee this VTA holds no key of, and a read the task does not sign.
    let out = handle_trustee_read(&state, &auth, read("status", "did:key:z6MkNotHeldHere")).await;
    assert_eq!(code(&out), "vta/pcs/trustee/read:trusteeNotHeld");
    let out = handle_trustee_read(&state, &auth, read("board", &personas[0])).await;
    assert_eq!(code(&out), "malformedRequest");
}

/// A trustee's VTA acts on the ceremony's signed steps only (CONVENTIONS §9.6): it reveals a share
/// only to a complaint its complainant signed, and deals to one set of transport keys only — so a
/// ballot box that invents complaints, or swaps in transport keys of its own, learns nothing.
#[tokio::test]
async fn a_trustee_vta_acts_on_signed_steps_only() {
    use vti_voting::trustees::{Threshold, TransportSecret, deal, seal_share};
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
        "trustee-one",
    )
    .await
    .did;
    // Trustees 2 and 3 sign their own steps here, as their own VTAs would.
    let (t2, k2) = key_from_seed(52);
    let (t3, k3) = key_from_seed(53);
    let (box_did, _) = box_key();
    let m = manifest(&[held.clone(), t2.clone(), t3.clone()], &box_did);
    let digest = manifest_digest(&m).unwrap();
    let mut rng = StdRng::seed_from_u64(0xC5);
    let reg = Registrar::generate(community(), &mut rng).unwrap();
    let mut bb = BallotBox::new(&box_did);
    let before = chrono::Utc::now() - chrono::Duration::hours(2);
    bb.register(
        community(),
        &json!({ "community": community(), "manifest": m,
                 "manifestDigest": digest_multibase(&digest),
                 "parameters": { "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() } }),
        before,
    )
    .unwrap();
    let sel = json!({ "community": community(), "electionId": "sealed-2027" });
    let ctx = Election::new(community(), ElectionId::new("sealed-2027").unwrap(), digest)
        .unwrap()
        .trustee_context();
    let with = |extra: Value| {
        let mut v = sel.clone();
        v.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        v
    };

    // Enrol: the VTA's trustee 1, and trustees 2 and 3 signing for themselves.
    let d = ok(&handle_trustee_enrol(
        &state,
        &auth,
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_ENROL_0_1,
            &held,
            json!({ "manifest": m }),
        ),
    )
    .await)["document"]
        .clone();
    bb.trustees_enrol(&held, &d, before).unwrap();
    let secrets: Vec<TransportSecret> = (2..=3)
        .map(|j| TransportSecret::generate(j, &mut rng))
        .collect();
    let mut enrolments = Vec::new();
    for (s, (did, key)) in secrets.iter().zip([(&t2, &k2), (&t3, &k3)]) {
        let tk = s.publish(&ctx, &mut rng);
        let doc = signed_by(
            key,
            did,
            "trustees/enrol",
            &box_did,
            with(json!({ "transportKey": vti_voting::wire::transport_key_value(&tk) })),
        )
        .await;
        bb.trustees_enrol(did, &doc, before).unwrap();
        enrolments.push(doc);
    }
    let steps = |bb: &mut BallotBox| {
        bb.trustees_status(BoxCaller::Did(community()), &sel, before)
            .unwrap()["steps"]
            .clone()
    };
    let enrolled = steps(&mut bb);

    // Deal once, to these transport keys.
    let deal_doc = |ceremony: Value| {
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_DEAL_0_2,
            &held,
            json!({ "manifest": m, "ceremony": ceremony }),
        )
    };
    let d = ok(&handle_trustee_deal(&state, &auth, deal_doc(enrolled.clone())).await)["document"]
        .clone();
    bb.trustees_deal(&held, &d, before).unwrap();
    // A ceremony with another transport key for trustee 2 — one its holder could open — gets
    // no dealing: the VTA deals to the keys it first dealt to, and no others.
    let other = TransportSecret::generate(2, &mut rng).publish(&ctx, &mut rng);
    let swapped_enrol = signed_by(
        &k2,
        &t2,
        "trustees/enrol",
        &box_did,
        with(json!({ "transportKey": vti_voting::wire::transport_key_value(&other) })),
    )
    .await;
    let mut swapped = enrolled.clone();
    swapped.as_array_mut().unwrap()[1] = swapped_enrol;
    let out = handle_trustee_deal(&state, &auth, deal_doc(swapped)).await;
    assert_eq!(code(&out), "vta/pcs/trustee/deal:ceremonyChanged");

    // Trustees 2 and 3 deal.
    let th = Threshold::new(2, 3).unwrap();
    let tks: Vec<_> = enrolled
        .as_array()
        .unwrap()
        .iter()
        .map(|r| vti_voting::wire::transport_key(&r["payload"]["transportKey"]).unwrap())
        .collect();
    for (i, (did, key)) in [(2u32, (&t2, &k2)), (3u32, (&t3, &k3))] {
        let (dealing, shares) = deal(i, th, &ctx, &mut rng).unwrap();
        let sealed = shares
            .iter()
            .map(|s| {
                let to = tks.iter().find(|k| k.trustee == s.recipient).unwrap();
                (s.recipient, seal_share(s, to, &ctx, &mut rng).unwrap())
            })
            .collect();
        let sd = vti_voting::ceremony::SealedDealing {
            dealing,
            shares: sealed,
        };
        let doc = signed_by(
            key,
            did,
            "trustees/deal",
            &box_did,
            with(json!({ "dealing": vti_voting::wire::dealing_value(&sd) })),
        )
        .await;
        bb.trustees_deal(did, &doc, before).unwrap();
    }

    // No share is revealed to a complaint nobody signed — the ballot box saying so is nothing.
    let justify = |ceremony: Value| {
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_JUSTIFY_0_2,
            &held,
            json!({ "manifest": m, "ceremony": ceremony, "recipient": 2 }),
        )
    };
    // A step whose proof is gone is no step.
    let mut unproven = steps(&mut bb);
    unproven.as_array_mut().unwrap()[1]
        .as_object_mut()
        .unwrap()
        .remove("proof");
    let out = handle_trustee_justify(&state, &auth, justify(unproven)).await;
    assert_eq!(code(&out), "vta/pcs/trustee/justify:ceremonyInvalid");
    let out = handle_trustee_justify(&state, &auth, justify(steps(&mut bb))).await;
    assert_eq!(code(&out), "vta/pcs/trustee/justify:noComplaint");
    // Trustee 2's own signed complaint of dealer 1 is answered with the share.
    let complaint = signed_by(
        &k2,
        &t2,
        "trustees/confirm",
        &box_did,
        with(json!({ "trustee": 2, "complaints": [1] })),
    )
    .await;
    bb.trustees_confirm(&t2, &complaint, before).unwrap();
    let answered = ok(&handle_trustee_justify(&state, &auth, justify(steps(&mut bb))).await);
    assert_eq!(answered["document"]["payload"]["recipient"], 2);
    assert!(
        bb.trustees_justify(&held, &answered["document"], before)
            .is_ok()
    );

    // The key forms: trustee 1 (this VTA) and trustee 3 confirm, and the VTA keeps its share.
    let keys = |ceremony: Value| {
        trustee_doc(
            uris::TASK_VTA_PCS_TRUSTEE_KEYS_0_2,
            &held,
            json!({ "manifest": m, "ceremony": ceremony }),
        )
    };
    let out = ok(&handle_trustee_keys(&state, &auth, keys(steps(&mut bb))).await);
    assert_eq!(out["complaints"], json!([]));
    bb.trustees_confirm(&held, &out["document"], before)
        .unwrap();
    let confirm3 = signed_by(
        &k3,
        &t3,
        "trustees/confirm",
        &box_did,
        with(json!({ "trustee": 3, "complaints": [] })),
    )
    .await;
    bb.trustees_confirm(&t3, &confirm3, before).unwrap();
    let formed = steps(&mut bb);
    let out = ok(&handle_trustee_keys(&state, &auth, keys(formed.clone())).await);
    assert_eq!(out["keyHeld"], true);

    // A ceremony in which trustee 3 dealt otherwise — every step still signed — forms another
    // share for this trustee. The share it holds is never replaced.
    let (dealing, shares) = deal(3, th, &ctx, &mut rng).unwrap();
    let sealed = shares
        .iter()
        .map(|s| {
            let to = tks.iter().find(|k| k.trustee == s.recipient).unwrap();
            (s.recipient, seal_share(s, to, &ctx, &mut rng).unwrap())
        })
        .collect();
    let redealt = signed_by(
        &k3,
        &t3,
        "trustees/deal",
        &box_did,
        with(json!({ "dealing": vti_voting::wire::dealing_value(
            &vti_voting::ceremony::SealedDealing { dealing, shares: sealed }) })),
    )
    .await;
    let mut other = formed;
    let at = other
        .as_array()
        .unwrap()
        .iter()
        .position(|r| {
            r["issuer"] == t3.as_str()
                && r["type"]
                    .as_str()
                    .is_some_and(|t| t.contains("/trustees/deal/"))
        })
        .unwrap();
    other.as_array_mut().unwrap()[at] = redealt;
    let out = handle_trustee_keys(&state, &auth, keys(other)).await;
    assert_eq!(code(&out), "vta/pcs/trustee/keys:keyMismatch");
}
