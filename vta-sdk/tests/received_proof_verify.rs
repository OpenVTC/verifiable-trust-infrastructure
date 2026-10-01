//! VTI-45: a proof is verified over the document **as received**.
//!
//! `trust-tasks-rs` parses `issuedAt`, `expiresAt` and the proof's `created`
//! as `DateTime<Utc>` and writes them back without a zero fraction, drops a
//! `null` optional member and every proof member its `Proof` type does not
//! model. A verifier that re-serialises the typed document therefore refuses a
//! correctly signed one — JavaScript's `toISOString()` writes `.000Z` on every
//! whole second, so roughly one document in a thousand per timestamp.
//!
//! Every test here signs the JSON a non-Rust producer would send, byte for
//! byte, and checks the received-JSON entry points accept it — and still
//! refuse what they refused before.
#![cfg(feature = "proof-verify")]

use affinidi_data_integrity::crypto_suites::CryptoSuite;
use affinidi_data_integrity::{DataIntegrityProof, prepare_sign_input};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use vta_sdk::trust_task_proof::{
    DiProofError, TrustTaskVmResolver, verify_approval_proof_value, verify_trust_task_proof_value,
    verify_trust_task_proof_with,
};

const SEED: u8 = 0x45;

/// The `did:key` for [`SEED`] and its verification method.
fn holder() -> (String, String) {
    let sk = SigningKey::from_bytes(&[SEED; 32]);
    let mb = vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes());
    let did = format!("did:key:{mb}");
    (did.clone(), format!("{did}#{mb}"))
}

/// A `did:peer:2` whose one key is published under `purpose_code` only
/// (`A` = assertionMethod), for the purpose-binding checks.
fn peer(purpose_code: char, seed: u8) -> (String, String) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let mb = vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes());
    let did = format!("did:peer:2.{purpose_code}{mb}");
    (did.clone(), format!("{did}#key-1"))
}

/// Sign `doc` exactly as it stands — the JSON a producer sends — with an
/// `eddsa-jcs-2022` proof whose `created` is the string given, verbatim.
fn sign_received(
    doc: &mut Value,
    seed: u8,
    vm: &str,
    purpose: &str,
    created: &str,
    nonce: Option<&str>,
) {
    let mut di = DataIntegrityProof::new(
        CryptoSuite::EddsaJcs2022,
        vm.to_string(),
        purpose.to_string(),
        None,
        Some(created.to_string()),
        None,
    );
    di.nonce = nonce.map(str::to_string);
    doc.as_object_mut().expect("an object").remove("proof");
    let input = prepare_sign_input(&*doc, &di, CryptoSuite::EddsaJcs2022).expect("sign input");
    let sk = SigningKey::from_bytes(&[seed; 32]);
    di.proof_value = Some(multibase::encode(
        multibase::Base::Base58Btc,
        sk.sign(&input).to_bytes(),
    ));
    doc["proof"] = serde_json::to_value(&di).expect("proof serialises");
}

/// The document a JavaScript producer sends on a whole second.
fn javascript_document(issuer: &str) -> Value {
    json!({
        "id": "urn:uuid:45454545-4545-4545-8545-454545454545",
        "type": "https://trusttasks.org/spec/rooms/create/0.1",
        "issuer": issuer,
        "recipient": "did:key:z6MkVta",
        "issuedAt": "2026-09-25T12:37:33.000Z",
        "threadId": null,
        "payload": { "roomId": "room-1" },
    })
}

fn resolver() -> TrustTaskVmResolver {
    TrustTaskVmResolver::did_key_only()
}

/// The finding itself: `.000Z` in `issuedAt` and in the proof's `created`,
/// and a `null` `threadId`, verify as received — and do not verify through
/// the typed re-serialisation, which is what made this a bug.
#[tokio::test]
async fn vti_45_a_javascript_whole_second_document_verifies_as_received() {
    let (did, vm) = holder();
    let mut doc = javascript_document(&did);
    sign_received(
        &mut doc,
        SEED,
        &vm,
        "assertionMethod",
        "2026-09-25T12:37:33.000Z",
        None,
    );

    assert_eq!(
        verify_trust_task_proof_value(&doc, &resolver())
            .await
            .expect("verifies as received"),
        did
    );

    let typed: TrustTask<Value> = serde_json::from_value(doc).expect("parses");
    assert!(
        verify_trust_task_proof_with(&typed, &resolver())
            .await
            .is_err(),
        "the typed form rewrites `.000Z`; if this now verifies, trust-tasks-rs \
         preserves the spelling and the typed path is no longer lossy"
    );
}

/// The other spellings the re-serialisation rewrote, and the other members it
/// dropped. Each is a correctly signed document.
#[tokio::test]
async fn vti_45_every_measured_rewrite_verifies_as_received() {
    let (did, vm) = holder();
    let variants: Vec<(&str, Value)> = vec![
        (
            "+00:00 offset",
            json!({ "issuedAt": "2026-09-25T12:37:33+00:00" }),
        ),
        (
            "one-digit fraction",
            json!({ "issuedAt": "2026-09-25T12:37:33.5Z" }),
        ),
        ("lowercase z", json!({ "issuedAt": "2026-09-25T12:37:33z" })),
        (
            "expiresAt .000Z",
            json!({ "expiresAt": "2026-09-25T13:37:33.000Z" }),
        ),
        (
            "null optional members",
            json!({
                "threadId": null,
                "parentThreadId": null,
                "expiresAt": null,
                "@context": null,
                "ceremony": null,
            }),
        ),
    ];
    for (name, members) in variants {
        let mut doc = javascript_document(&did);
        for (k, v) in members.as_object().unwrap() {
            doc[k] = v.clone();
        }
        sign_received(
            &mut doc,
            SEED,
            &vm,
            "assertionMethod",
            "2026-09-25T12:37:33.000Z",
            None,
        );
        assert_eq!(
            verify_trust_task_proof_value(&doc, &resolver()).await.ok(),
            Some(did.clone()),
            "{name}"
        );
    }
}

/// A `nonce` on the proof is part of the configuration the producer signed and
/// is carried into the one the verifier hashes.
#[tokio::test]
async fn vti_45_a_signed_proof_nonce_verifies_as_received() {
    let (did, vm) = holder();
    let mut doc = javascript_document(&did);
    sign_received(
        &mut doc,
        SEED,
        &vm,
        "assertionMethod",
        "2026-09-25T12:37:33.000Z",
        Some("n-0451"),
    );
    assert_eq!(
        verify_trust_task_proof_value(&doc, &resolver())
            .await
            .unwrap(),
        did
    );
}

/// Verifying as received is not verifying less: an edit to the payload, or to
/// the very spelling the typed path used to rewrite, is refused.
#[tokio::test]
async fn vti_45_tampering_is_still_refused() {
    let (did, vm) = holder();
    let mut signed = javascript_document(&did);
    sign_received(
        &mut signed,
        SEED,
        &vm,
        "assertionMethod",
        "2026-09-25T12:37:33.000Z",
        None,
    );

    let mut payload = signed.clone();
    payload["payload"]["roomId"] = json!("room-2");
    let mut spelling = signed.clone();
    spelling["issuedAt"] = json!("2026-09-25T12:37:33Z");
    let mut null_dropped = signed.clone();
    null_dropped.as_object_mut().unwrap().remove("threadId");
    let mut created = signed.clone();
    created["proof"]["created"] = json!("2026-09-25T12:37:33Z");

    for (name, doc) in [
        ("payload", payload),
        ("issuedAt spelling", spelling),
        ("null member removed", null_dropped),
        ("proof created spelling", created),
    ] {
        let err = verify_trust_task_proof_value(&doc, &resolver())
            .await
            .expect_err(name);
        assert!(
            matches!(err, DiProofError::VerifyFailed(_)),
            "{name}: {err:?}"
        );
        assert_eq!(err.to_string(), "proof verification failed", "{name}");
    }
}

/// A proof member the verifier cannot carry into the configuration it hashes
/// is refused, and the operator's cause names it.
#[tokio::test]
async fn vti_45_an_uncarried_proof_member_is_refused_by_name() {
    let (did, vm) = holder();
    let mut doc = javascript_document(&did);
    sign_received(
        &mut doc,
        SEED,
        &vm,
        "assertionMethod",
        "2026-09-25T12:37:33.000Z",
        None,
    );
    doc["proof"]["challenge"] = json!("c-1");
    let err = verify_trust_task_proof_value(&doc, &resolver())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, DiProofError::VerifyFailed(c) if c.contains("challenge")),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "proof verification failed");
}

/// The received form keeps the purpose rules: an approval must be an
/// `assertionMethod` proof, and every proof's key must be listed under the
/// purpose it declares (VTI-KEY-022).
#[tokio::test]
async fn vti_45_purpose_binding_holds_on_the_received_form() {
    let (asserting, vm) = peer('A', 0x46);

    let mut approval = javascript_document(&asserting);
    sign_received(
        &mut approval,
        0x46,
        &vm,
        "assertionMethod",
        "2026-09-25T12:37:33.000Z",
        None,
    );
    assert_eq!(
        verify_approval_proof_value(&approval, &resolver())
            .await
            .unwrap(),
        asserting
    );

    let mut operational = javascript_document(&asserting);
    sign_received(
        &mut operational,
        0x46,
        &vm,
        "authentication",
        "2026-09-25T12:37:33.000Z",
        None,
    );
    assert!(matches!(
        verify_approval_proof_value(&operational, &resolver()).await,
        Err(DiProofError::WrongPurpose {
            expected: "assertionMethod"
        })
    ));
    // An assertion-only key does not make an `authentication` proof.
    let err = verify_trust_task_proof_value(&operational, &resolver())
        .await
        .unwrap_err();
    assert!(
        err.cause().is_some_and(|c| c.contains("authentication")),
        "{err:?}"
    );
}

/// No `proof`, or `proof: null`, is `NoProof` — the same answer the typed
/// form gives for a document without one.
#[tokio::test]
async fn vti_45_a_missing_proof_is_no_proof() {
    let (did, _) = holder();
    let mut doc = javascript_document(&did);
    assert!(matches!(
        verify_trust_task_proof_value(&doc, &resolver()).await,
        Err(DiProofError::NoProof)
    ));
    doc["proof"] = Value::Null;
    assert!(matches!(
        verify_trust_task_proof_value(&doc, &resolver()).await,
        Err(DiProofError::NoProof)
    ));
}
