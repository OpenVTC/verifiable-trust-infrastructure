//! `keys/sign-document/0.1` through its handler: proofs made as the DID a
//! document names — a `did:key` and a `did:peer` persona this VTA holds — that a
//! Data Integrity verifier accepts, and every refusal the specification
//! declares, asserted by its wire code.

use super::*;
use crate::acl::Role;
use crate::operations::persona::test_fixture::{did_key_persona, mint_key};
use crate::test_support::build_signing_test_app_state;
use trust_tasks_rs::TypeUri;
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::trust_task_proof::proof_set::{proof_set, verify_one};
use vti_common::auth::ProofPurpose;

const CTX: &str = "personal";
const TASK: &str = "https://trusttasks.org/spec/keys/sign-document/0.1";

fn claims(role: Role) -> AuthClaims {
    AuthClaims {
        did: "did:key:z6MkClientWalletExample".to_string(),
        role,
        allowed_contexts: vec![CTX.to_string()],
        session_id: "test-session".into(),
        access_expires_at: 0,
        issued_at: 0,
        amr: Vec::new(),
        acr: String::new(),
    }
}

fn body(out: &TrustTaskOutcome) -> Value {
    serde_json::from_slice(&out.body).expect("response is JSON")
}

fn code(out: &TrustTaskOutcome) -> String {
    body(out)
        .pointer("/payload/code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn details(out: &TrustTaskOutcome) -> Value {
    body(out)
        .pointer("/payload/details")
        .cloned()
        .unwrap_or_default()
}

struct Fixture {
    state: AppState,
    _dir: tempfile::TempDir,
    auth: AuthClaims,
    /// A `did:key` persona in `CTX`.
    did: String,
    key_id: String,
}

impl Fixture {
    async fn new() -> Self {
        let (state, dir) = build_signing_test_app_state().await;
        crate::contexts::create_context(&state.contexts_ks, CTX, CTX)
            .await
            .expect("create context");
        let persona = did_key_persona(
            &state.keys_ks,
            &state.internal_ks,
            &state.contexts_ks,
            &state.acl_ks,
            &state.seed_store,
            &state.audit_sink,
            CTX,
            "member-key",
        )
        .await;
        Self {
            state,
            _dir: dir,
            auth: claims(Role::Admin),
            did: persona.did,
            key_id: persona.key_id,
        }
    }

    async fn sign_as(&self, auth: &AuthClaims, payload: Value) -> TrustTaskOutcome {
        let uri: TypeUri = TASK.parse().expect("task uri");
        let doc = TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload);
        handle_sign_document(&self.state, auth, doc).await
    }

    async fn sign(&self, payload: Value) -> TrustTaskOutcome {
        self.sign_as(&self.auth, payload).await
    }

    /// `document`, with this persona's key.
    async fn sign_document(&self, document: Value) -> TrustTaskOutcome {
        self.sign(serde_json::json!({ "keyId": self.key_id, "document": document }))
            .await
    }

    fn credential(&self) -> Value {
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "urn:uuid:7c0e9a44-2b1d-4f6e-9a35-1d2c3b4a5e60",
            "type": ["VerifiableCredential"],
            "issuer": self.did,
            "validFrom": "2026-10-18T09:00:00Z",
            "credentialSubject": { "id": "did:example:subject" },
        })
    }
}

/// The proof on `secured` verifies over the document without it, for `purpose`.
async fn verifies(secured: &Value, purpose: ProofPurpose) {
    let proofs = proof_set(&secured["proof"]).expect("one proof");
    let mut unsecured = secured.clone();
    unsecured.as_object_mut().unwrap().remove("proof");
    verify_one(
        &proofs[0],
        &unsecured,
        &TrustTaskVmResolver::did_key_only(),
        purpose,
    )
    .await
    .expect("the proof verifies");
}

#[tokio::test]
async fn a_credential_is_signed_as_the_did_it_names_and_verifies() {
    let f = Fixture::new().await;
    let out = f
        .sign(serde_json::json!({ "keyId": f.key_id, "document": f.credential() }))
        .await;
    let b = body(&out);
    assert!(out.status.is_success(), "{b:#}");
    let p = &b["payload"];
    assert_eq!(p["signerDid"], f.did);
    assert_eq!(p["keyId"], f.key_id);
    assert_eq!(p["document"]["proof"], p["proof"]);
    assert_eq!(p["proof"]["cryptosuite"], "eddsa-jcs-2022");
    assert_eq!(p["proof"]["proofPurpose"], "assertionMethod");
    // The document's `@context` is the proof configuration's, as the cryptosuite says.
    assert_eq!(p["proof"]["@context"], f.credential()["@context"]);
    let id = f.did.trim_start_matches("did:key:");
    assert_eq!(p["proof"]["verificationMethod"], format!("{}#{id}", f.did));
    verifies(&p["document"], ProofPurpose::AssertionMethod).await;
}

/// A member's external directory card (`vtc/directory/card/publish`): it names
/// the membership DID as `issuer` so that a custodian holding the key can sign
/// it, and every other member is carried exactly as sent.
#[tokio::test]
async fn a_members_external_card_is_signed_as_its_issuer() {
    let f = Fixture::new().await;
    let card = serde_json::json!({
        "@type": "Card",
        "version": "1.0",
        "uid": "urn:vtc-directory:dir_Q2xhcmFRMmxoY21GUk1t",
        "issuer": f.did,
        "name": { "full": "Carol Example" },
        "notes": { "n1": { "note": "Rust, decentralised identity, and long walks." } },
    });
    let out = f
        .sign(serde_json::json!({ "keyId": f.key_id, "document": card }))
        .await;
    let b = body(&out);
    assert!(out.status.is_success(), "{b:#}");
    let secured = &b["payload"]["document"];
    let mut without = secured.clone();
    without.as_object_mut().unwrap().remove("proof");
    assert_eq!(without, card, "nothing added or changed");
    assert!(secured["proof"].get("@context").is_none());
    verifies(secured, ProofPurpose::AssertionMethod).await;
}

/// A `did:peer:2` relationship DID is read from its identifier: its `V` key
/// signs for `authentication` (and `assertionMethod`); the same key published
/// as an `A` key is listed under `assertionMethod` only, so a proof for
/// `authentication` is refused.
#[tokio::test]
async fn a_relationship_did_signs_only_for_what_its_document_grants() {
    let f = Fixture::new().await;
    let raw = mint_key(
        &f.state.keys_ks,
        &f.state.internal_ks,
        &f.state.contexts_ks,
        &f.state.acl_ks,
        &f.state.seed_store,
        &f.state.audit_sink,
        CTX,
        "relationship-key",
    )
    .await;
    let peer = format!(
        "did:peer:2.V{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&raw)
    );
    let document = serde_json::json!({ "controller": peer, "id": "urn:uuid:1" });

    let ok = f
        .sign(serde_json::json!({
            "keyId": "relationship-key",
            "document": document,
            "proofPurpose": "authentication",
            "challenge": "c-1",
            "domain": "example.org",
        }))
        .await;
    let b = body(&ok);
    assert!(ok.status.is_success(), "{b:#}");
    assert_eq!(b["payload"]["proof"]["challenge"], "c-1");
    assert_eq!(b["payload"]["proof"]["domain"], "example.org");
    assert!(
        b["payload"]["proof"]["verificationMethod"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{peer}#"))
    );

    let asserting = format!(
        "did:peer:2.A{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&raw)
    );
    let refused = f
        .sign(serde_json::json!({
            "keyId": "relationship-key",
            "document": { "controller": asserting },
            "proofPurpose": "authentication",
        }))
        .await;
    assert_eq!(code(&refused), "keys/sign-document:purposeNotAuthorized");
    assert_eq!(details(&refused)["proofPurpose"], "authentication");
}

#[tokio::test]
async fn sign_document_refuses_what_its_specification_declares() {
    let f = Fixture::new().await;

    // The document's own checks, before any key is looked up.
    let mut proved = f.credential();
    proved["proof"] = serde_json::json!({});
    assert_eq!(
        code(&f.sign_document(proved).await),
        "keys/sign-document:proofPresent"
    );
    let mut anonymous = f.credential();
    anonymous.as_object_mut().unwrap().remove("issuer");
    let out = f.sign_document(anonymous).await;
    assert_eq!(code(&out), "keys/sign-document:documentInvalid");
    assert_eq!(details(&out)["reason"], "noSigner");
    let mut url = f.credential();
    url["issuer"] = format!("{}#key-1", f.did).into();
    let out = f.sign_document(url).await;
    assert_eq!(code(&out), "keys/sign-document:documentInvalid");
    assert_eq!(details(&out)["reason"], "signerMalformed");
    let mut big = f.credential();
    big["credentialSubject"]["n"] = serde_json::json!(9_007_199_254_740_993u64);
    let out = f.sign_document(big).await;
    assert_eq!(code(&out), "keys/sign-document:documentInvalid");
    assert_eq!(details(&out)["reason"], "notCanonicalizable");

    // Somebody else's DID, with this key.
    let mut theirs = f.credential();
    theirs["issuer"] = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into();
    let out = f.sign_document(theirs).await;
    assert_eq!(code(&out), "keys/sign-document:issuerMismatch");
    assert_eq!(details(&out)["member"], "issuer");

    // The key. Said to a super-admin: for anyone else a missing key and one
    // outside their scope are one refusal.
    let unknown = f
        .sign_as(
            &crate::test_support::super_admin_claims(),
            serde_json::json!({ "keyId": "no-such-key", "document": f.credential() }),
        )
        .await;
    assert_eq!(code(&unknown), "keys:notFound");
    let created = f
        .sign(serde_json::json!({
            "keyId": f.key_id,
            "document": f.credential(),
            "created": "2020-01-01T00:00:00Z",
        }))
        .await;
    assert_eq!(code(&created), "keys:invalidArgument");

    crate::operations::keys::create_key(
        &f.state.keys_ks,
        &f.state.internal_ks,
        &f.state.contexts_ks,
        &f.state.seed_store,
        &f.state.audit_sink,
        &f.state.acl_ks,
        &crate::test_support::super_admin_claims(),
        crate::operations::keys::CreateKeyParams {
            key_type: vta_keys::KeyType::P256,
            internal: true,
            derivation_path: None,
            key_id: Some("p256-key".into()),
            mnemonic: None,
            label: None,
            context_id: Some(CTX.into()),
        },
        "test",
    )
    .await
    .expect("mint a P-256 key");
    let p256 = f
        .sign(serde_json::json!({ "keyId": "p256-key", "document": f.credential() }))
        .await;
    assert_eq!(code(&p256), "keys/sign-document:keyTypeUnsupported");
    assert_eq!(details(&p256)["keyType"], "p256");

    let mut record: vta_sdk::keys::KeyRecord = f
        .state
        .keys_ks
        .get(crate::keys::store_key(&f.key_id))
        .await
        .unwrap()
        .unwrap();
    record.status = vta_sdk::keys::KeyStatus::Revoked;
    f.state
        .keys_ks
        .insert(crate::keys::store_key(&f.key_id), &record)
        .await
        .unwrap();
    assert_eq!(
        code(&f.sign_document(f.credential()).await),
        "keys/sign-document:failedPrecondition"
    );
}

/// `sign` is not `sign-document`: a holder narrowed to the general oracle is
/// refused, and one narrowed to `sign-document` alone signs.
#[tokio::test]
async fn sign_document_needs_its_own_capability() {
    let f = Fixture::new().await;
    for (caps, allowed) in [
        (vec![crate::acl::Capability::Sign], false),
        (vec![crate::acl::Capability::SignDocument], true),
    ] {
        let auth = AuthClaims {
            did: format!("did:key:z6MkNarrowed{}", caps.len() + usize::from(allowed)),
            ..claims(Role::Application)
        };
        let mut entry = crate::acl::AclEntry::new(&auth.did, Role::Application, "did:key:zRoot");
        entry.allowed_contexts = vec![CTX.into()];
        entry.capabilities = caps;
        crate::acl::store_acl_entry(&f.state.acl_ks, &entry)
            .await
            .unwrap();
        let out = f
            .sign_as(
                &auth,
                serde_json::json!({ "keyId": f.key_id, "document": f.credential() }),
            )
            .await;
        if allowed {
            assert!(out.status.is_success(), "{:#}", body(&out));
        } else {
            assert_eq!(code(&out), "permissionDenied", "{:#}", body(&out));
        }
    }
}
