//! A proof verifies against the **typed** document, with no trip back through
//! `Value`.
//!
//! ## Why this matters
//!
//! `verify_trust_task_proof_with` used to take `&TrustTask<Value>` only. That
//! constrained nothing cryptographically — `eddsa-jcs-2022` canonicalises
//! whatever serialises, and the payload's Rust shape is not part of the proof —
//! but it forced every typed caller to convert first.
//!
//! The conversion is the hazard. Re-serialising a document *before* checking its
//! signature is the one step in the path that can change what was signed, which
//! is why `vta_sdk::tsp_binding::wrap_envelope` hand-rolls its JSON rather than
//! reparse-and-reserialise on the carriage side. Registering handlers by type
//! (what `trust_tasks_rs::AsyncDispatcher` does) hands them `TrustTask<P>`, so
//! that round trip would otherwise become mandatory on every proof-checking
//! handler in the workspace.
//!
//! So the claim under test is narrow and load-bearing: **a document signed as
//! `Value` still verifies once parsed into its typed form.** If that ever stops
//! holding, typed dispatch silently starts rejecting valid proofs.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use vta_sdk::trust_task_proof::{TrustTaskVmResolver, verify_trust_task_proof_with};
use vta_sdk::trust_task_sign::sign_in_place;

/// A payload with a real shape — not a `Value` under another name, or the test
/// would prove nothing about the typed path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct RoomCreate {
    room_id: String,
    owner_did: String,
    epoch: u32,
}

/// A deterministic `did:key` and its private key, as the signing helper wants
/// them.
fn holder() -> (String, String) {
    let seed = [7u8; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
    );
    let mut buf = vec![0x80, 0x26];
    buf.extend_from_slice(&seed);
    let private = multibase::encode(multibase::Base::Base58Btc, &buf);
    (did, private)
}

#[tokio::test]
async fn a_proof_signed_as_value_verifies_against_the_typed_document() {
    let (did, private_key) = holder();

    // Sign the document the way a client does: over the whole thing, as `Value`.
    let mut signed: TrustTask<Value> = TrustTask::new(
        "urn:uuid:11111111-1111-4111-8111-111111111111".to_string(),
        "https://trusttasks.org/spec/rooms/create/0.1"
            .parse()
            .expect("a valid type URI"),
        json!({ "roomId": "room-1", "ownerDid": did, "epoch": 1 }),
    );
    signed.issuer = Some(did.clone());
    signed.recipient = Some("did:key:zVtc".to_string());
    signed.issued_at = Some(chrono::Utc::now());
    sign_in_place(&mut signed, &did, &private_key)
        .await
        .expect("the holder signs its own document");

    // Parse it the way a type-keyed dispatcher does: straight into the typed
    // form, once. This is the step that used to be followed by a conversion
    // back to `Value` purely to satisfy the verifier.
    let wire = serde_json::to_vec(&signed).expect("serialise");
    let typed: TrustTask<RoomCreate> = serde_json::from_slice(&wire).expect("downcast to the type");
    assert_eq!(
        typed.payload.room_id, "room-1",
        "the payload really is typed"
    );

    let signer = verify_trust_task_proof_with(&typed, &TrustTaskVmResolver::did_key_only())
        .await
        .expect("a proof over the document verifies against its typed form");

    assert_eq!(
        signer, did,
        "the verified signer is the holder that signed it"
    );
}

/// The negative half: a tampered payload must still be caught through the typed
/// path. Without this, the test above could pass against a verifier that had
/// quietly stopped checking anything.
#[tokio::test]
async fn a_tampered_typed_document_is_refused() {
    let (did, private_key) = holder();

    let mut signed: TrustTask<Value> = TrustTask::new(
        "urn:uuid:22222222-2222-4222-8222-222222222222".to_string(),
        "https://trusttasks.org/spec/rooms/create/0.1"
            .parse()
            .expect("a valid type URI"),
        json!({ "roomId": "room-1", "ownerDid": did, "epoch": 1 }),
    );
    signed.issuer = Some(did.clone());
    signed.recipient = Some("did:key:zVtc".to_string());
    signed.issued_at = Some(chrono::Utc::now());
    sign_in_place(&mut signed, &did, &private_key)
        .await
        .expect("sign");

    let wire = serde_json::to_vec(&signed).expect("serialise");
    let mut typed: TrustTask<RoomCreate> = serde_json::from_slice(&wire).expect("downcast");
    // One field, changed after signing — the room someone else owns.
    typed.payload.owner_did = "did:key:zAttacker".to_string();

    let result = verify_trust_task_proof_with(&typed, &TrustTaskVmResolver::did_key_only()).await;

    assert!(
        result.is_err(),
        "a payload edited after signing must not verify — it did, which means \
         the typed path is not covered by the proof"
    );
}
