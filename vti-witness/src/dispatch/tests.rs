//! The dispatch core without a socket: what each inbound document is
//! answered with, and that every answer is this identity's own.

use serde_json::{Value, json};
use vta_sdk::provision_client::EphemeralSetupKey;
use vta_sdk::trust_task_proof::{TrustTaskVmResolver, verify_trust_task_proof_value};
use vta_sdk::trust_task_sign::{HolderKey, build_signed};

use super::*;

/// Witnessing state over a throwaway store, witnessing anyone.
fn witnessing() -> crate::witness::Witnessing {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = vti_common::store::test_fixture::open_with_keyspaces(dir.path(), crate::store::ALL)
        .expect("store");
    // The store outlives the test; the directory is reclaimed with $TMPDIR.
    std::mem::forget(dir);
    crate::witness::Witnessing::new(
        crate::witness::WitnessPolicy::new(
            vec![crate::config::ANY_COMMUNITY.to_string()],
            None,
            Vec::new(),
            crate::config::SessionLimits::default(),
        ),
        crate::store::WitnessStore::from_store(&store).expect("keyspaces"),
    )
}

/// A witness identity on a `did:key`, so its replies verify with no network.
fn witness() -> IdentityContext {
    let key = EphemeralSetupKey::generate().expect("key");
    let holder = HolderKey::from_did_key(&key.did, key.private_key_multibase()).expect("holder");
    IdentityContext::new("w1", key.did.clone(), holder, witnessing()).expect("identity")
}

/// A party writing to the witness: its DID and private key.
fn party() -> EphemeralSetupKey {
    EphemeralSetupKey::generate().expect("key")
}

fn resolver() -> TrustTaskVmResolver {
    TrustTaskVmResolver::did_key_only()
}

/// An unsigned request from `issuer` to `recipient`.
fn request(type_uri: &str, issuer: &str, recipient: &str, payload: Value) -> Value {
    json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuer": issuer,
        "recipient": recipient,
        "issuedAt": Utc::now().to_rfc3339(),
        "payload": payload,
    })
}

async fn send(identity: &IdentityContext, sender: &str, doc: &Value) -> Outcome {
    answer(
        identity,
        sender,
        &serde_json::to_vec(doc).unwrap(),
        &resolver(),
        Utc::now(),
    )
    .await
}

/// The reply, which must exist, be addressed back to `sender`, come from
/// `identity`, and carry a proof that verifies as `identity`'s.
async fn signed_reply(identity: &IdentityContext, sender: &str, doc: &Value) -> Value {
    let reply = match send(identity, sender, doc).await {
        Outcome::Reply(reply) => reply,
        Outcome::Drop(reason) => panic!("expected a reply, dropped: {reason:?}"),
    };
    assert_eq!(reply["issuer"], identity.did(), "{reply:#}");
    assert_eq!(reply["recipient"], sender, "{reply:#}");
    assert_eq!(reply["threadId"], doc["id"], "{reply:#}");
    let signer = verify_trust_task_proof_value(&reply, &resolver())
        .await
        .unwrap_or_else(|e| panic!("the reply's proof must verify: {e}\n{reply:#}"));
    assert_eq!(
        signer,
        identity.did(),
        "signed by the identity's own key, nobody else's"
    );
    reply
}

fn error_code(reply: &Value) -> &str {
    assert!(
        reply["type"]
            .as_str()
            .is_some_and(|t| t.starts_with(vta_sdk::inbound::TRUST_TASK_ERROR_PREFIX)),
        "expected a trust-task-error: {reply:#}"
    );
    reply["payload"]["code"].as_str().expect("an error code")
}

#[tokio::test]
async fn discovery_is_answered_with_this_identitys_task_list_and_signed_by_it() {
    let identity = witness();
    let party = party();
    let doc = request(DISCOVERY_V0_3, &party.did, identity.did(), json!({}));
    let reply = signed_reply(&identity, &party.did, &doc).await;

    assert_eq!(reply["type"], format!("{DISCOVERY_V0_3}#response"));
    v0_3::Response::validate_value(&reply["payload"]).expect("a schema-valid 0.3 response");
    let listed: Vec<&str> = reply["payload"]["supportedTypes"]
        .as_array()
        .expect("supportedTypes")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let mut expected: Vec<&str> = SERVED.to_vec();
    expected.sort_unstable();
    assert_eq!(listed, expected, "exactly what this identity routes");
    for witness_task in [WITNESS_SESSION_V0_1, WITNESS_SESSION_SUBMIT_V0_1] {
        assert!(
            listed.contains(&witness_task),
            "{witness_task} is served, so discovery lists it"
        );
    }
    assert!(
        reply["payload"]["acceptanceWindow"].is_object(),
        "the window this identity applies is advertised (VTI-TRN-047): {reply:#}"
    );
}

#[tokio::test]
async fn discovery_0_1_is_answered_too() {
    let identity = witness();
    let party = party();
    let doc = request(DISCOVERY_V0_1, &party.did, identity.did(), json!({}));
    let reply = signed_reply(&identity, &party.did, &doc).await;
    assert_eq!(reply["type"], format!("{DISCOVERY_V0_1}#response"));
    v0_1::Response::validate_value(&reply["payload"]).expect("a schema-valid 0.1 response");
}

/// A request signed by its issuer is verified and answered.
#[tokio::test]
async fn a_signed_request_is_verified_and_answered() {
    let identity = witness();
    let party = party();
    let body = build_signed(
        DISCOVERY_V0_3,
        json!({}),
        &party.did,
        party.private_key_multibase(),
        identity.did(),
    )
    .await
    .unwrap();
    let doc: Value = serde_json::from_str(&body).unwrap();
    let reply = signed_reply(&identity, &party.did, &doc).await;
    assert_eq!(reply["type"], format!("{DISCOVERY_V0_3}#response"));
}

/// A proof by someone other than the document's issuer is not the issuer's.
#[tokio::test]
async fn a_proof_by_another_key_than_the_issuers_is_refused() {
    let identity = witness();
    let party = party();
    let other = EphemeralSetupKey::generate().unwrap();
    let body = build_signed(
        DISCOVERY_V0_3,
        json!({}),
        &other.did,
        other.private_key_multibase(),
        identity.did(),
    )
    .await
    .unwrap();
    let mut doc: Value = serde_json::from_str(&body).unwrap();
    // Claim to be `party` while carrying `other`'s proof. The signature no
    // longer covers the rewritten issuer, so it fails either way — as it must.
    doc["issuer"] = json!(party.did);
    let reply = signed_reply(&identity, &party.did, &doc).await;
    assert_eq!(error_code(&reply), "proofInvalid", "{reply:#}");
}

#[tokio::test]
async fn an_unknown_type_is_refused_as_unsupported() {
    let identity = witness();
    let party = party();
    let doc = request(
        "https://trusttasks.org/spec/keys/create/0.1",
        &party.did,
        identity.did(),
        json!({}),
    );
    let reply = signed_reply(&identity, &party.did, &doc).await;
    assert_eq!(error_code(&reply), "unsupportedType", "{reply:#}");
}

/// Another version of a served family is a version mismatch.
#[tokio::test]
async fn another_discovery_version_is_refused_as_unsupported_version() {
    let identity = witness();
    let party = party();
    let doc = request(
        "https://trusttasks.org/spec/trust-task-discovery/0.2",
        &party.did,
        identity.did(),
        json!({}),
    );
    let reply = signed_reply(&identity, &party.did, &doc).await;
    assert_eq!(error_code(&reply), "unsupportedVersion", "{reply:#}");
}

/// A document addressed to another DID — another witness of this service,
/// the operator's VTA — is refused, and the refusal is still this identity's:
/// a framework builder would copy the request's `recipient` into the reply's
/// `issuer`, which would sign a document claiming to be someone else.
#[tokio::test]
async fn a_document_addressed_to_another_did_is_refused_as_this_identity() {
    let identity = witness();
    let party = party();
    let elsewhere = "did:webvh:QmVTA:vta.operator.example";
    let doc = request(DISCOVERY_V0_3, &party.did, elsewhere, json!({}));
    let reply = signed_reply(&identity, &party.did, &doc).await;
    assert_eq!(error_code(&reply), "wrongRecipient", "{reply:#}");
    assert_ne!(reply["issuer"], elsewhere);
}

/// A document missing its `recipient` is refused: discovery 0.3 requires one.
#[tokio::test]
async fn a_document_with_no_recipient_is_refused() {
    let identity = witness();
    let party = party();
    let mut doc = request(DISCOVERY_V0_3, &party.did, identity.did(), json!({}));
    doc.as_object_mut().unwrap().remove("recipient");
    let reply = signed_reply(&identity, &party.did, &doc).await;
    assert_eq!(error_code(&reply), "malformedRequest", "{reply:#}");
}

/// An in-band issuer that is not the transport-proven sender.
#[tokio::test]
async fn an_issuer_other_than_the_proven_sender_is_an_identity_mismatch() {
    let identity = witness();
    let party = party();
    let doc = request(
        DISCOVERY_V0_3,
        "did:example:someone-else",
        identity.did(),
        json!({}),
    );
    let reply = signed_reply(&identity, &party.did, &doc).await;
    assert_eq!(error_code(&reply), "identityMismatch", "{reply:#}");
}

#[tokio::test]
async fn a_stale_document_is_refused() {
    let identity = witness();
    let party = party();
    let mut doc = request(DISCOVERY_V0_3, &party.did, identity.did(), json!({}));
    doc["issuedAt"] = json!((Utc::now() - chrono::TimeDelta::hours(2)).to_rfc3339());
    let reply = signed_reply(&identity, &party.did, &doc).await;
    assert_eq!(error_code(&reply), "expired", "{reply:#}");
}

/// An error is never answered, and a `#response` nobody awaits is dropped:
/// answering either is how two peers end up exchanging errors until a rate
/// limiter stops them.
#[tokio::test]
async fn errors_and_responses_are_dropped_rather_than_answered() {
    let identity = witness();
    let party = party();

    let error = json!({
        "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
        "threadId": "urn:uuid:00000000-0000-4000-8000-000000000000",
        "type": trust_tasks_rs::trust_task_error_type_uri().to_string(),
        "issuer": party.did,
        "recipient": identity.did(),
        "issuedAt": Utc::now().to_rfc3339(),
        "payload": { "code": "unsupportedType", "retryable": false },
    });
    assert!(matches!(
        send(&identity, &party.did, &error).await,
        Outcome::Drop(DropReason::Error)
    ));

    let response = json!({
        "id": "urn:uuid:00000000-0000-4000-8000-000000000002",
        "threadId": "urn:uuid:00000000-0000-4000-8000-000000000000",
        "type": format!("{DISCOVERY_V0_3}#response"),
        "issuer": party.did,
        "recipient": identity.did(),
        "issuedAt": Utc::now().to_rfc3339(),
        "payload": { "supportedTypes": [] },
    });
    assert!(matches!(
        send(&identity, &party.did, &response).await,
        Outcome::Drop(DropReason::UnclaimedReply)
    ));
}

#[tokio::test]
async fn bytes_that_are_not_a_trust_task_are_dropped() {
    let identity = witness();
    let outcome = answer(
        &identity,
        "did:example:x",
        b"not json",
        &resolver(),
        Utc::now(),
    )
    .await;
    assert!(matches!(outcome, Outcome::Drop(DropReason::NotJson)));

    let outcome = answer(
        &identity,
        "did:example:x",
        br#"{"hello":"world"}"#,
        &resolver(),
        Utc::now(),
    )
    .await;
    assert!(matches!(outcome, Outcome::Drop(DropReason::NotATrustTask)));
}

/// An identity signs only with a key of its own DID.
#[test]
fn an_identity_refuses_a_signing_key_of_another_did() {
    let key = EphemeralSetupKey::generate().unwrap();
    let holder = HolderKey::from_did_key(&key.did, key.private_key_multibase()).unwrap();
    let err = IdentityContext::new(
        "w1",
        "did:webvh:QmOther:example.com:w1",
        holder,
        witnessing(),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("not a verification method"),
        "{err}"
    );
}

/// The witness tasks are the generated types' own URIs, and served.
#[test]
fn the_witness_tasks_are_the_generated_uris_and_are_served() {
    for uri in [WITNESS_SESSION_V0_1, WITNESS_SESSION_SUBMIT_V0_1] {
        assert!(SERVED.contains(&uri), "{uri}");
        assert!(uri.starts_with("https://trusttasks.org/spec/witness/session/"));
    }
}
