//! The witnessed-party tasks end to end, through the slice's own handlers, against a real witness
//! (`vti_witness::dispatch::answer`, the same dispatch core `vti-witness run` puts behind its
//! sockets). The test is the client: it carries each document the VTA builds to the witness,
//! from the relationship DID, and hands each answer back — exactly the carriage of
//! `vta/_shared/0.5/CONVENTIONS.md`.
//!
//! The relationship DID is a `did:peer:2` whose signing key the VTA holds (the shape openvtc
//! mints), the member DID a `did:key` the VTA holds, and the witness and the community are
//! `did:key`s held by the test. Every proof verifies with no network.

use super::*;
use crate::acl::Role;
use crate::operations::persona::{PersonaStores, Relationship, persona_key_for};
use crate::operations::room_issuance::{SigningContext, VtaKeySigner};
use crate::test_support::build_signing_test_app_state;
use chrono::{TimeDelta, Utc};
use dtg_credentials::{DTGCredential, IssuerScope};
use trust_tasks_rs::TypeUri;
use vta_sdk::provision_client::EphemeralSetupKey;
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::trust_task_sign::{HolderKey, sign_in_place_with, sign_object_for_assertion};
use vta_sdk::trust_tasks as uris;
use vti_witness::config::SessionLimits;
use vti_witness::dispatch::{IdentityContext, Outcome, answer};
use vti_witness::store::{self as wstore, WitnessStore};
use vti_witness::witness::{WitnessPolicy, Witnessing};

const CTX: &str = "personal";
const OTHER: &str = "other";

// ── Plumbing ────────────────────────────────────────────────────────────

fn claims(role: Role, ctx: &str) -> AuthClaims {
    AuthClaims {
        did: "did:key:z6MkClientWalletExample".to_string(),
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
    let uri: TypeUri = uri.parse().expect("witness uri");
    TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
}

fn body(out: &TrustTaskOutcome) -> Value {
    serde_json::from_slice(&out.body).expect("response is JSON")
}

fn ok(out: &TrustTaskOutcome) -> Value {
    let b = body(out);
    assert!(out.status.is_success(), "expected success, got {b:#}");
    b["payload"].clone()
}

fn code(out: &TrustTaskOutcome) -> String {
    body(out)
        .pointer("/payload/code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn urn() -> String {
    format!("urn:uuid:{}", uuid::Uuid::new_v4())
}

/// A `did:key` the test holds the private key of.
struct Key {
    did: String,
    multibase: String,
}

impl Key {
    fn new() -> Self {
        let k = EphemeralSetupKey::generate().expect("key");
        Self {
            did: k.did.clone(),
            multibase: k.private_key_multibase().to_string(),
        }
    }

    fn holder(&self) -> HolderKey {
        HolderKey::from_did_key(&self.did, &self.multibase).expect("holder")
    }
}

/// The witness: one `vti-witness` identity, dispatched in process.
struct Witness {
    key: Key,
    identity: IdentityContext,
    _dir: tempfile::TempDir,
}

impl Witness {
    fn new(communities: Vec<String>) -> Self {
        let key = Key::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vti_common::store::test_fixture::open_with_keyspaces(dir.path(), wstore::ALL)
            .expect("witness store");
        let witnessing = Witnessing::new(
            WitnessPolicy::new(
                communities,
                None,
                vec![key.did.clone()],
                SessionLimits::default(),
            ),
            WitnessStore::from_store(&store).expect("witness keyspaces"),
        );
        let identity =
            IdentityContext::new("w", key.did.clone(), key.holder(), witnessing).expect("identity");
        Self {
            key,
            identity,
            _dir: dir,
        }
    }

    fn did(&self) -> &str {
        &self.key.did
    }

    /// Carry `document` to the witness from `sender`, as the client does, and return its answer.
    async fn carry(&self, sender: &str, document: &Value) -> Value {
        match answer(
            &self.identity,
            sender,
            &serde_json::to_vec(document).unwrap(),
            &TrustTaskVmResolver::did_key_only(),
            Utc::now(),
        )
        .await
        {
            Outcome::Reply(reply) => reply,
            Outcome::Drop(reason) => panic!("the witness dropped the document: {reason:?}"),
        }
    }
}

/// A principal whose relationship and member keys this VTA holds in [`CTX`], with a
/// relationship credential for one counterparty and a community membership credential in its
/// vault.
struct World {
    state: AppState,
    _dir: tempfile::TempDir,
    auth: AuthClaims,
    witness: Witness,
    community: Key,
    relationship: String,
    counterparty: String,
    member: String,
}

impl World {
    /// `member_link`: whether the VMC names a separate member DID (the member link) or the
    /// relationship DID itself.
    async fn new(member_link: bool) -> Self {
        let (state, dir) = build_signing_test_app_state().await;
        for ctx in [CTX, OTHER] {
            crate::contexts::create_context(&state.contexts_ks, ctx, ctx)
                .await
                .expect("create context");
        }
        let community = Key::new();
        let witness = Witness::new(vec![community.did.clone()]);
        state.config.write().await.witness.member_link_witnesses = vec![witness.did().to_string()];

        // The relationship DID: a did:peer:2 over a key minted in CTX.
        let raw = crate::operations::persona::test_fixture::mint_key(
            &state.keys_ks,
            &state.internal_ks,
            &state.contexts_ks,
            &state.acl_ks,
            &state.seed_store,
            &state.audit_sink,
            CTX,
            "relationship-key",
        )
        .await;
        let relationship = format!(
            "did:peer:2.V{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&raw)
        );
        // The member DID: a did:key minted in CTX.
        let member = crate::operations::persona::test_fixture::did_key_persona(
            &state.keys_ks,
            &state.internal_ks,
            &state.contexts_ks,
            &state.acl_ks,
            &state.seed_store,
            &state.audit_sink,
            CTX,
            "member-key",
        )
        .await
        .did;
        let counterparty = Key::new().did;
        let auth = claims(Role::Admin, CTX);

        let w = Self {
            state,
            _dir: dir,
            auth,
            witness,
            community,
            relationship,
            counterparty,
            member,
        };
        let vrc = w.vrc(&w.counterparty.clone()).await;
        w.store("vrc-1", vrc).await;
        let member_of = if member_link {
            w.member.clone()
        } else {
            w.relationship.clone()
        };
        let vmc = w.vmc(&member_of).await;
        w.store("vmc-1", vmc).await;
        w
    }

    fn signing(&self) -> SigningContext<'_> {
        SigningContext {
            keys_ks: &self.state.keys_ks,
            imported_ks: &self.state.imported_ks,
            internal_ks: &self.state.internal_ks,
            contexts_ks: &self.state.contexts_ks,
            acl_ks: &self.state.acl_ks,
            seed_store: &self.state.seed_store,
            audit: &self.state.audit_sink,
            auth: &self.auth,
        }
    }

    /// The relationship DID's relationship credential naming `subject`, signed through the
    /// VTA's oracle as the relationship DID.
    async fn vrc(&self, subject: &str) -> Value {
        let key = persona_key_for(
            PersonaStores::from_state(&self.state),
            &self.auth,
            &self.relationship,
            Relationship::AssertionMethod,
        )
        .await
        .unwrap()
        .expect("the VTA holds the relationship key");
        let vc = DTGCredential::new_vrc(
            self.relationship.clone(),
            IssuerScope::Pairwise,
            subject.to_string(),
            Utc::now() - TimeDelta::minutes(5),
            None,
        )
        .with_id(urn());
        let mut vc = serde_json::to_value(vc).unwrap();
        let signer = VtaKeySigner::new(self.signing(), &key.key_id, &key.verification_method);
        let proof = affinidi_data_integrity::DataIntegrityProof::sign(
            &vc,
            &signer,
            affinidi_data_integrity::SignOptions::new().with_proof_purpose("assertionMethod"),
        )
        .await
        .expect("sign the VRC");
        vc["proof"] = serde_json::to_value(proof).unwrap();
        vc
    }

    /// The community's membership credential for `member`.
    async fn vmc(&self, member: &str) -> Value {
        let vc = DTGCredential::new_vmc(
            self.community.did.clone(),
            member.to_string(),
            Utc::now() - TimeDelta::days(1),
            None,
            false,
        )
        .with_id(urn());
        let mut v = serde_json::to_value(vc).unwrap();
        sign_object_for_assertion(&mut v, &self.community.holder())
            .await
            .unwrap();
        v
    }

    async fn store(&self, id: &str, vc: Value) {
        use crate::vault::model::{CredentialFormat, CredentialStatus, StoredCredential};
        crate::vault::storage::put(
            &self.state.vault_ks,
            &StoredCredential {
                id: id.into(),
                format: CredentialFormat::EddsaJcs2022,
                types: Vec::new(),
                schema_id: None,
                community_did: None,
                context_id: Some(CTX.into()),
                subject_did: None,
                issuer_did: None,
                purpose: None,
                status: CredentialStatus::Valid,
                valid_from: None,
                valid_until: None,
                received_at: Utc::now().to_rfc3339(),
                source: None,
                tags: Default::default(),
                body: serde_json::to_vec(&vc).unwrap(),
                lifecycle: vti_common::vault::VaultStatus::Active,
                archived_at: None,
                deleted_at: None,
                grace_until: None,
            },
        )
        .await
        .expect("store the credential");
    }

    fn open_payload(&self, member_link: bool) -> Value {
        let mut p = json!({
            "witness": self.witness.did(),
            "relationshipDid": self.relationship,
            "counterpartyDid": self.counterparty,
            "relationshipThreadId": "urn:uuid:9e8d7c6b-0000-4000-8000-000000000a01",
            "relationshipCredentialId": "vrc-1",
            "membership": { "credentialId": "vmc-1" },
        });
        if member_link {
            p["membership"]["memberDid"] = json!(self.member);
        }
        p
    }

    async fn open_as(&self, auth: &AuthClaims, payload: Value) -> TrustTaskOutcome {
        handle_open(
            &self.state,
            auth,
            doc(uris::TASK_VTA_WITNESS_OPEN_0_1, payload),
        )
        .await
    }

    async fn present_as(
        &self,
        auth: &AuthClaims,
        session: &str,
        response: &Value,
    ) -> TrustTaskOutcome {
        handle_present(
            &self.state,
            auth,
            doc(
                uris::TASK_VTA_WITNESS_PRESENT_0_1,
                json!({ "sessionId": session, "response": response }),
            ),
        )
        .await
    }

    async fn accept_as(
        &self,
        auth: &AuthClaims,
        session: &str,
        response: &Value,
    ) -> TrustTaskOutcome {
        handle_accept(
            &self.state,
            auth,
            doc(
                uris::TASK_VTA_WITNESS_ACCEPT_0_1,
                json!({ "sessionId": session, "response": response }),
            ),
        )
        .await
    }

    /// open → witness → present → witness, returning the session id, the session document, the
    /// witness's session answer, and its submit answer (the outcome).
    async fn run_to_outcome(&self, member_link: bool) -> (String, Value, Value, Value) {
        let opened = ok(&self
            .open_as(&self.auth, self.open_payload(member_link))
            .await);
        let session = opened["sessionId"].as_str().unwrap().to_string();
        let session_doc = opened["document"].clone();
        let session_answer = self.witness.carry(&self.relationship, &session_doc).await;
        let presented = ok(&self.present_as(&self.auth, &session, &session_answer).await);
        let outcome = self
            .witness
            .carry(&self.relationship, &presented["document"])
            .await;
        assert!(
            outcome["type"]
                .as_str()
                .is_some_and(|t| t.ends_with("submit/0.1#response")),
            "the witness accepted the submission: {outcome:#}"
        );
        (session, session_doc, session_answer, outcome)
    }
}

// ── The happy paths ─────────────────────────────────────────────────────

/// The whole family under the member link: the VTA signs the session and the submission as the
/// relationship DID (never as itself), the member presentation rides in the OpenVTC carriage,
/// the real witness mints a VWC, and the VTA verifies and stores it with its evidence.
#[tokio::test]
async fn witnessed_end_to_end_through_the_member_link() {
    let w = World::new(true).await;

    let opened = ok(&w
        .open_as(&w.auth, {
            let mut p = w.open_payload(true);
            p["storeAs"] = json!("vwc-alice-to-bob");
            p
        })
        .await);
    let session = opened["sessionId"].as_str().unwrap().to_string();
    let session_doc = opened["document"].clone();
    assert_eq!(session_doc["id"], session);
    assert_eq!(session_doc["threadId"], session);
    assert_eq!(session_doc["issuer"], w.relationship);
    assert_eq!(session_doc["recipient"], w.witness.did());
    assert_eq!(
        session_doc["payload"]["parties"],
        json!([w.relationship, w.counterparty])
    );
    assert!(
        session_doc["proof"]["verificationMethod"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{}#", w.relationship)),
        "signed as the relationship DID, never as the VTA"
    );

    let session_answer = w.witness.carry(&w.relationship, &session_doc).await;
    let presented = ok(&w.present_as(&w.auth, &session, &session_answer).await);
    let submit = &presented["document"];
    assert_eq!(submit["issuer"], w.relationship);
    assert_eq!(submit["threadId"], session);
    let member_vp = &submit["payload"]["ext"]["org.openvtc.witness"]["memberPresentation"];
    assert_eq!(
        member_vp["holder"], w.member,
        "the member presentation is the member DID's"
    );
    assert_eq!(
        submit["payload"]["vp"]["verifiableCredential"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "under the member link the VMC rides in the member presentation, not beside the VRC"
    );

    let outcome = w.witness.carry(&w.relationship, submit).await;
    let accepted = ok(&w.accept_as(&w.auth, &session, &outcome).await);
    assert_eq!(accepted["credentialId"], "vwc-alice-to-bob");
    assert_eq!(accepted["witness"], w.witness.did());
    assert_eq!(accepted["evidence"]["session"], session_doc);
    assert_eq!(accepted["evidence"]["outcome"], outcome);
    assert_eq!(
        accepted["vwcDigestMultibase"],
        outcome["payload"]["vwcDigestMultibase"]
    );

    // Stored in the relationship key's context, with both evidence documents.
    let stored = crate::vault::storage::get(&w.state.vault_ks, "vwc-alice-to-bob")
        .await
        .unwrap()
        .expect("the VWC is in the vault");
    assert_eq!(stored.context_id.as_deref(), Some(CTX));
    assert_eq!(stored.issuer_did.as_deref(), Some(w.witness.did()));
    assert_eq!(
        serde_json::from_slice::<Value>(&stored.body).unwrap(),
        outcome["payload"]["vwc"]
    );
    let tag = |k: &str| serde_json::from_str::<Value>(stored.tags.get(k).unwrap()).unwrap();
    assert_eq!(
        tag(crate::operations::witness::EVIDENCE_SESSION_TAG),
        session_doc
    );
    assert_eq!(
        tag(crate::operations::witness::EVIDENCE_OUTCOME_TAG),
        outcome
    );

    // The same outcome again is answered again, storing nothing (conventions §5).
    let again = ok(&w.accept_as(&w.auth, &session, &outcome).await);
    assert_eq!(again["credentialId"], accepted["credentialId"]);
    assert_eq!(again["evidence"], accepted["evidence"]);

    // An accepted session admits no further presentation.
    let out = w.present_as(&w.auth, &session, &session_answer).await;
    assert_eq!(code(&out), "vta/witness/present:sessionUnknown");
}

/// A membership credential naming the relationship DID rides in the relationship presentation,
/// with no member DID anywhere — and the derived handle is the VWC's own id.
#[tokio::test]
async fn witnessed_with_membership_naming_the_relationship_did() {
    let w = World::new(false).await;
    let (session, _, _, outcome) = w.run_to_outcome(false).await;
    let accepted = ok(&w.accept_as(&w.auth, &session, &outcome).await);
    assert_eq!(
        accepted["credentialId"], outcome["payload"]["vwc"]["id"],
        "without storeAs the handle is the VWC's id"
    );
}

/// A repeated present builds a fresh submission; the witness spends its challenge on the first
/// it accepts, so at most one VWC results (conventions §5).
#[tokio::test]
async fn a_repeated_present_is_safe() {
    let w = World::new(true).await;
    let opened = ok(&w.open_as(&w.auth, w.open_payload(true)).await);
    let session = opened["sessionId"].as_str().unwrap().to_string();
    let answer = w.witness.carry(&w.relationship, &opened["document"]).await;
    let first = ok(&w.present_as(&w.auth, &session, &answer).await);
    let second = ok(&w.present_as(&w.auth, &session, &answer).await);
    assert_ne!(first["document"]["id"], second["document"]["id"]);
    let outcome = w.witness.carry(&w.relationship, &second["document"]).await;
    ok(&w.accept_as(&w.auth, &session, &outcome).await);
    let refused = w.witness.carry(&w.relationship, &first["document"]).await;
    assert!(
        refused["payload"]["code"]
            .as_str()
            .is_some_and(|c| c.ends_with("challengeMismatch")),
        "{refused:#}"
    );
}

// ── Splices and forgeries ───────────────────────────────────────────────

/// No answer from another session, another witness, or a tampered one is read.
#[tokio::test]
async fn an_answer_from_anywhere_else_is_refused() {
    let w = World::new(true).await;
    let a = ok(&w.open_as(&w.auth, w.open_payload(true)).await);
    let b = ok(&w.open_as(&w.auth, w.open_payload(true)).await);
    let session_a = a["sessionId"].as_str().unwrap();
    let answer_b = w.witness.carry(&w.relationship, &b["document"]).await;

    // Session B's answer spliced into session A.
    let out = w.present_as(&w.auth, session_a, &answer_b).await;
    assert_eq!(code(&out), "vta/witness/present:responseInvalid");

    // A genuine answer with its challenge changed.
    let answer_a = w.witness.carry(&w.relationship, &a["document"]).await;
    let mut tampered = answer_a.clone();
    tampered["payload"]["challenge"] = json!("00".repeat(32));
    let out = w.present_as(&w.auth, session_a, &tampered).await;
    assert_eq!(code(&out), "vta/witness/present:responseInvalid");

    // Another witness answering the same thread.
    let impostor = Key::new();
    let mut forged: TrustTask<Value> = serde_json::from_value(answer_a.clone()).unwrap();
    forged.issuer = Some(impostor.did.clone());
    forged.proof = None;
    sign_in_place_with(&mut forged, &impostor.holder())
        .await
        .unwrap();
    let out = w
        .present_as(&w.auth, session_a, &serde_json::to_value(forged).unwrap())
        .await;
    assert_eq!(code(&out), "vta/witness/present:responseInvalid");

    // The genuine answer still works after all that.
    ok(&w.present_as(&w.auth, session_a, &answer_a).await);

    // A refusal is not an outcome.
    let refusal = json!({
        "id": urn(), "type": "https://trusttasks.org/spec/trust-task-error/0.5",
        "issuer": w.witness.did(), "recipient": w.relationship, "threadId": session_a,
        "payload": { "code": "witness/session/submit:presentationInvalid" },
    });
    let out = w.accept_as(&w.auth, session_a, &refusal).await;
    assert_eq!(code(&out), "vta/witness/accept:responseInvalid");
}

/// A genuinely signed answer whose VWC is not this session's is `vwcInvalid`, and nothing is
/// stored.
#[tokio::test]
async fn a_vwc_from_another_session_is_refused() {
    let w = World::new(true).await;
    let (_, _, _, other_outcome) = w.run_to_outcome(true).await;

    let opened = ok(&w.open_as(&w.auth, w.open_payload(true)).await);
    let session = opened["sessionId"].as_str().unwrap().to_string();
    let answer = w.witness.carry(&w.relationship, &opened["document"]).await;
    ok(&w.present_as(&w.auth, &session, &answer).await);

    // The witness's own key, answering this session with the other session's VWC.
    let mut forged: TrustTask<Value> = serde_json::from_value(json!({
        "id": urn(),
        "type": <trust_tasks_rs::specs::witness::session::submit::v0_1::Response
            as trust_tasks_rs::Payload>::TYPE_URI,
        "issuer": w.witness.did(),
        "recipient": w.relationship,
        "issuedAt": Utc::now().to_rfc3339(),
        "threadId": session,
        "payload": other_outcome["payload"].clone(),
    }))
    .unwrap();
    sign_in_place_with(&mut forged, &w.witness.key.holder())
        .await
        .unwrap();
    let out = w
        .accept_as(&w.auth, &session, &serde_json::to_value(forged).unwrap())
        .await;
    assert_eq!(code(&out), "vta/witness/accept:vwcInvalid");
    assert!(
        body(&out).to_string().contains("taskContext"),
        "{:#}",
        body(&out)
    );

    // Nothing stored under the other VWC's id beyond the session that produced it.
    let other_id = other_outcome["payload"]["vwc"]["id"].as_str().unwrap();
    assert!(
        crate::vault::storage::get(&w.state.vault_ks, other_id)
            .await
            .unwrap()
            .is_none(),
        "the earlier session was never accepted, and this one stored nothing"
    );
}

/// `sessionUnknown` is one answer: unknown, out of the caller's contexts, wrong state.
#[tokio::test]
async fn session_unknown_says_nothing_about_why() {
    let w = World::new(true).await;
    let opened = ok(&w.open_as(&w.auth, w.open_payload(true)).await);
    let session = opened["sessionId"].as_str().unwrap();
    let answer = w.witness.carry(&w.relationship, &opened["document"]).await;

    let unknown = w.present_as(&w.auth, "urn:uuid:nobody", &answer).await;
    let elsewhere = w
        .present_as(&claims(Role::Admin, OTHER), session, &answer)
        .await;
    let wrong_state = w.accept_as(&w.auth, session, &answer).await;
    assert_eq!(code(&unknown), "vta/witness/present:sessionUnknown");
    assert_eq!(code(&elsewhere), "vta/witness/present:sessionUnknown");
    assert_eq!(code(&wrong_state), "vta/witness/accept:sessionUnknown");
    assert_eq!(
        body(&unknown)["payload"]["message"],
        body(&elsewhere)["payload"]["message"]
    );
}

// ── Custody and authorization ───────────────────────────────────────────

/// A caller who may not act where the relationship DID's key is held cannot act as it, and the
/// refusal reads the same as for a DID this VTA does not hold at all.
#[tokio::test]
async fn key_custody_refuses_another_contexts_relationship_did() {
    let w = World::new(true).await;
    let other = claims(Role::Admin, OTHER);
    let out = w.open_as(&other, w.open_payload(true)).await;
    assert_eq!(code(&out), "permissionDenied", "{:#}", body(&out));

    let mut p = w.open_payload(false);
    p["relationshipDid"] = json!(Key::new().did);
    let out = w.open_as(&w.auth, p).await;
    assert_eq!(code(&out), "permissionDenied");

    // A member DID this VTA does not hold.
    let mut p = w.open_payload(true);
    p["membership"]["memberDid"] = json!(Key::new().did);
    let out = w.open_as(&w.auth, p).await;
    assert_eq!(code(&out), "permissionDenied");
}

/// `witness-request` is required, and `sign` is not it: an `application` caller holds `sign`
/// and is refused.
#[tokio::test]
async fn sign_alone_does_not_satisfy_witness_request() {
    let w = World::new(true).await;
    assert!(vti_common::acl::role_has_capability(
        &Role::Application,
        Capability::Sign
    ));
    let out = w
        .open_as(&claims(Role::Application, CTX), w.open_payload(true))
        .await;
    assert_eq!(code(&out), "permissionDenied");
    assert!(body(&out).to_string().contains("WitnessRequest"));
}

// ── open's other refusals ───────────────────────────────────────────────

#[tokio::test]
async fn open_refuses_what_cannot_succeed_before_anything_is_disclosed() {
    let w = World::new(true).await;

    let mut p = w.open_payload(true);
    p["relationshipCredentialId"] = json!("no-such-credential");
    assert_eq!(
        code(&w.open_as(&w.auth, p).await),
        "vta/witness/open:notFound"
    );

    // A VRC naming somebody else.
    let wrong = w.vrc(&Key::new().did).await;
    w.store("vrc-wrong", wrong).await;
    let mut p = w.open_payload(true);
    p["relationshipCredentialId"] = json!("vrc-wrong");
    assert_eq!(
        code(&w.open_as(&w.auth, p).await),
        "vta/witness/open:credentialMismatch"
    );

    // The VMC names the member DID, not the relationship DID.
    assert_eq!(
        code(&w.open_as(&w.auth, w.open_payload(false)).await),
        "vta/witness/open:credentialMismatch"
    );

    // The witness is one of the parties.
    let mut p = w.open_payload(true);
    p["witness"] = json!(w.counterparty);
    assert_eq!(code(&w.open_as(&w.auth, p).await), "malformedRequest");

    // The member link, for a witness whose carriage this VTA does not know.
    w.state
        .config
        .write()
        .await
        .witness
        .member_link_witnesses
        .clear();
    assert_eq!(
        code(&w.open_as(&w.auth, w.open_payload(true)).await),
        "vta/witness/open:memberLinkUnsupported"
    );

    // Nothing above left a session behind.
    assert!(
        w.state
            .witness_sessions_ks
            .prefix_iter_raw("session:")
            .await
            .unwrap()
            .is_empty()
    );
}

/// A credential changed after open is not presented.
#[tokio::test]
async fn present_refuses_a_credential_changed_since_open() {
    let w = World::new(true).await;
    let opened = ok(&w.open_as(&w.auth, w.open_payload(true)).await);
    let session = opened["sessionId"].as_str().unwrap();
    let answer = w.witness.carry(&w.relationship, &opened["document"]).await;
    let reissued = w.vrc(&w.counterparty.clone()).await;
    w.store("vrc-1", reissued).await;
    let out = w.present_as(&w.auth, session, &answer).await;
    assert_eq!(code(&out), "vta/witness/present:credentialMismatch");
}
