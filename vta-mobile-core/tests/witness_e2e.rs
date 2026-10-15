//! A witnessed session driven entirely through `vta_mobile_core::witness`, as a wallet runs it
//! (issue #1068): every request to the VTA is built and signed by the engine and POSTed over
//! HTTPS to a real VTA (`MockVta`, the `vta/witness/*` tasks behind the production spine), every
//! VTA answer is verified as the VTA's and parsed by the engine, and every document the VTA
//! hands back is checked by the engine and carried to a real witness
//! (`vti_witness::dispatch::answer`, the dispatch core `vti-witness run` puts behind its
//! sockets) from the relationship DID, whose answer the engine verifies and classifies.
//!
//! The relationship DID is a `did:peer:2` over a key the VTA holds (the shape openvtc mints);
//! the witness, the community and the wallet are `did:key`s held by the test. No network.

use chrono::{TimeDelta, Utc};
use dtg_credentials::{DTGCredential, IssuerScope};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use vta_mobile_core::FfiError;
use vta_mobile_core::keys::Signer;
use vta_mobile_core::reply::verify_trust_task_reply;
use vta_mobile_core::session::AuthEnvelope;
use vta_mobile_core::witness::{
    WitnessDocument, WitnessRefusal, WitnessReply, WitnessTask, build_witness_task,
    check_witness_document, classify_witness_reply, parse_witness_response,
};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::trust_task_sign::{HolderKey, sign_object_for_assertion};
use vta_service::operations::persona::{PersonaStores, Relationship, persona_key_for};
use vta_service::operations::room_issuance::{SigningContext, VtaKeySigner};
use vta_service::test_support::{MockVta, admin_claims_for_context, super_admin_claims};
use vta_service::vault::model::{CredentialFormat, CredentialStatus, StoredCredential};
use vti_witness::config::SessionLimits;
use vti_witness::dispatch::{IdentityContext, Outcome, answer};
use vti_witness::store::{self as wstore, WitnessStore};
use vti_witness::witness::{WitnessPolicy, Witnessing};

const CTX: &str = "personal";

fn urn() -> String {
    format!("urn:uuid:{}", uuid::Uuid::new_v4())
}

/// A `did:key` the test holds the private key of.
struct Key {
    sk: SigningKey,
    did: String,
}

impl Key {
    fn new(seed: u8) -> Self {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&sk.verifying_key().to_bytes());
        Self { sk, did }
    }

    fn holder(&self) -> HolderKey {
        let mb = multibase::encode(multibase::Base::Base58Btc, self.sk.to_bytes());
        HolderKey::from_did_key(&self.did, &mb).expect("holder key")
    }
}

/// The wallet's native signer, as the enclave-backed one the app hands the engine.
struct WalletSigner(SigningKey, String);

impl Signer for WalletSigner {
    fn did(&self) -> String {
        self.1.clone()
    }
    fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        Ok(self.0.sign(&payload).to_bytes().to_vec())
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
        let key = Key::new(0x57);
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

    /// What arrives back on the relationship DID's connection when `document` is sent from it.
    async fn carry(&self, sender: &str, document: &str) -> String {
        match answer(
            &self.identity,
            sender,
            document.as_bytes(),
            &TrustTaskVmResolver::did_key_only(),
            Utc::now(),
        )
        .await
        {
            Outcome::Reply(reply) => reply.to_string(),
            Outcome::Drop(reason) => panic!("the witness dropped the document: {reason:?}"),
        }
    }
}

/// A VTA holding a principal's relationship key and credentials, the principal's wallet, and
/// a witness serving the principal's community.
struct World {
    vta: MockVta,
    http: reqwest::Client,
    wallet: Key,
    token: String,
    witness: Witness,
    relationship: String,
    counterparty: String,
}

impl World {
    async fn new() -> Self {
        let vta = MockVta::start_provisionable().await;
        let state = &vta.ctx.state;
        vta_service::contexts::create_context(&state.contexts_ks, CTX, CTX)
            .await
            .expect("create context");

        // The relationship DID: a did:peer:2 over a key minted in CTX.
        let created = vta_service::operations::keys::create_key(
            &state.keys_ks,
            &state.internal_ks,
            &state.contexts_ks,
            &state.seed_store,
            &state.audit_sink,
            &state.acl_ks,
            &super_admin_claims(),
            vta_service::operations::keys::CreateKeyParams {
                key_type: vta_service::keys::KeyType::Ed25519,
                internal: true,
                derivation_path: None,
                key_id: Some("relationship-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some(CTX.into()),
            },
            "test",
        )
        .await
        .expect("mint the relationship key");
        let raw = vta_sdk::did_key::decode_ed25519_public_key_multibase(&created.public_key)
            .expect("the minted key");
        let relationship = format!(
            "did:peer:2.V{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&raw)
        );

        let community = Key::new(0xC0);
        let witness = Witness::new(vec![community.did.clone()]);
        let counterparty = Key::new(0xB0).did;

        // The wallet: an admin of CTX, as a principal's own device is.
        let wallet = Key::new(0xA1);
        let token = vta
            .ctx
            .mint_token(&wallet.did, "admin", vec![CTX.into()])
            .await;

        let w = Self {
            vta,
            http: reqwest::Client::builder().build().expect("http client"),
            wallet,
            token,
            witness,
            relationship,
            counterparty,
        };
        let vrc = w.vrc().await;
        w.store("vrc-1", vrc).await;
        let vmc = w.vmc(&community).await;
        w.store("vmc-1", vmc).await;
        w
    }

    /// The relationship credential, signed through the VTA's oracle as the relationship DID.
    async fn vrc(&self) -> Value {
        let state = &self.vta.ctx.state;
        let auth = admin_claims_for_context(CTX);
        let key = persona_key_for(
            PersonaStores::from_state(state),
            &auth,
            &self.relationship,
            Relationship::AssertionMethod,
        )
        .await
        .unwrap()
        .expect("the VTA holds the relationship key");
        let vc = DTGCredential::new_vrc(
            self.relationship.clone(),
            IssuerScope::Pairwise,
            self.counterparty.clone(),
            Utc::now() - TimeDelta::minutes(5),
            None,
        )
        .with_id(urn());
        let mut vc = serde_json::to_value(vc).unwrap();
        let signer = VtaKeySigner::new(
            SigningContext {
                keys_ks: &state.keys_ks,
                imported_ks: &state.imported_ks,
                internal_ks: &state.internal_ks,
                contexts_ks: &state.contexts_ks,
                acl_ks: &state.acl_ks,
                seed_store: &state.seed_store,
                audit: &state.audit_sink,
                auth: &auth,
            },
            &key.key_id,
            &key.verification_method,
        );
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

    /// The community's membership credential, naming the relationship DID.
    async fn vmc(&self, community: &Key) -> Value {
        let vc = DTGCredential::new_vmc(
            community.did.clone(),
            self.relationship.clone(),
            Utc::now() - TimeDelta::days(1),
            None,
            false,
        )
        .with_id(urn());
        let mut v = serde_json::to_value(vc).unwrap();
        sign_object_for_assertion(&mut v, &community.holder())
            .await
            .unwrap();
        v
    }

    async fn store(&self, id: &str, vc: Value) {
        vta_service::vault::storage::put(
            &self.vta.ctx.state.vault_ks,
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

    fn witness_did(&self) -> String {
        self.witness.key.did.clone()
    }

    /// Build, sign and send one `vta/witness/*` request as the wallet does, verify the answer
    /// as the VTA's, and parse it: `Ok(payload)` or `Err(the VTA's error code)`.
    async fn vta(&self, task: WitnessTask, payload: Value) -> Result<Value, String> {
        let env = AuthEnvelope {
            id: urn(),
            holder_did: self.wallet.did.clone(),
            vta_did: self.vta.vta_did().to_string(),
            // Whole seconds, `Z`: the proof's `created` is this string, and a verifier
            // re-serialises it; a fractional `+00:00` form signs bytes the VTA never sees.
            issued_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        };
        let request = build_witness_task(
            env,
            task,
            payload.to_string(),
            Box::new(WalletSigner(
                self.wallet.sk.clone(),
                self.wallet.did.clone(),
            )),
        )
        .expect("build the request");
        let reply = self
            .http
            .post(format!("{}/trust-tasks", self.vta.base_url()))
            .bearer_auth(&self.token)
            .header("content-type", "application/json")
            .body(request.clone())
            .send()
            .await
            .expect("POST /trust-tasks")
            .text()
            .await
            .expect("the VTA's answer");
        verify_trust_task_reply(request, reply.clone(), self.vta.vta_did().to_string())
            .await
            .expect("the VTA's answer is the VTA's");
        match parse_witness_response(task, reply.clone()) {
            Ok(payload) => Ok(serde_json::from_str(&payload).unwrap()),
            Err(FfiError::Decode { .. }) => {
                let v: Value = serde_json::from_str(&reply).unwrap();
                Err(v["payload"]["code"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string())
            }
            Err(e) => panic!("{e:?}"),
        }
    }

    /// Check `document` as the wallet does, carry it to the witness from the relationship DID,
    /// and classify what comes back.
    async fn carry(&self, kind: WitnessDocument, session: &str, document: &Value) -> WitnessReply {
        let document = document.to_string();
        check_witness_document(
            document.clone(),
            kind,
            session.into(),
            self.relationship.clone(),
            self.witness_did(),
        )
        .expect("the document is the session's, to the witness, from the relationship DID");
        let reply = self.witness.carry(&self.relationship, &document).await;
        classify_witness_reply(document, reply, self.witness_did())
            .await
            .expect("the answer is the witness's")
    }
}

fn answered(reply: WitnessReply) -> Value {
    match reply {
        WitnessReply::Answered { response_json } => serde_json::from_str(&response_json).unwrap(),
        other => panic!("expected the witness to answer, got {other:?}"),
    }
}

/// open → carry → present → carry → accept, all through the engine: the VWC is stored, and its
/// evidence is the two documents the wallet carried and received.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wallet_runs_a_witnessed_session_through_its_vta() {
    let w = World::new().await;

    let opened = w
        .vta(
            WitnessTask::Open,
            json!({
                "witness": w.witness_did(),
                "relationshipDid": w.relationship,
                "counterpartyDid": w.counterparty,
                "relationshipThreadId": "urn:uuid:9e8d7c6b-0000-4000-8000-000000000a01",
                "relationshipCredentialId": "vrc-1",
                "membership": { "credentialId": "vmc-1" },
                "storeAs": "vwc-wallet",
            }),
        )
        .await
        .expect("open");
    let session = opened["sessionId"].as_str().unwrap().to_string();
    let session_doc = opened["document"].clone();

    let session_answer = answered(
        w.carry(WitnessDocument::Session, &session, &session_doc)
            .await,
    );

    let presented = w
        .vta(
            WitnessTask::Present,
            json!({ "sessionId": session, "response": session_answer }),
        )
        .await
        .expect("present");
    let submit = presented["document"].clone();
    let outcome = answered(w.carry(WitnessDocument::Submit, &session, &submit).await);
    // The wallet discards `submit` here (CONVENTIONS §6); nothing below reads it.
    drop(submit);

    let accepted = w
        .vta(
            WitnessTask::Accept,
            json!({ "sessionId": session, "response": outcome }),
        )
        .await
        .expect("accept");
    assert_eq!(accepted["credentialId"], "vwc-wallet");
    assert_eq!(accepted["witness"], w.witness_did());
    assert_eq!(accepted["evidence"]["session"], session_doc);
    assert_eq!(accepted["evidence"]["outcome"], outcome);

    let stored = vta_service::vault::storage::get(&w.vta.ctx.state.vault_ks, "vwc-wallet")
        .await
        .unwrap()
        .expect("the VWC is in the vault");
    assert_eq!(
        serde_json::from_slice::<Value>(&stored.body).unwrap(),
        outcome["payload"]["vwc"]
    );
}

/// A witness refusal reaches the wallet classified, and is not handed back: a submission whose
/// challenge the witness already spent is `challengeMismatch`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_witness_refusal_is_classified_for_the_wallet() {
    let w = World::new().await;
    let opened = w
        .vta(
            WitnessTask::Open,
            json!({
                "witness": w.witness_did(),
                "relationshipDid": w.relationship,
                "counterpartyDid": w.counterparty,
                "relationshipThreadId": "urn:uuid:9e8d7c6b-0000-4000-8000-000000000a02",
                "relationshipCredentialId": "vrc-1",
                "membership": { "credentialId": "vmc-1" },
            }),
        )
        .await
        .expect("open");
    let session = opened["sessionId"].as_str().unwrap().to_string();
    let session_answer = answered(
        w.carry(WitnessDocument::Session, &session, &opened["document"])
            .await,
    );
    let present = || {
        w.vta(
            WitnessTask::Present,
            json!({ "sessionId": session, "response": session_answer }),
        )
    };
    let first = present().await.expect("present");
    let second = present().await.expect("a repeated present is safe");

    answered(
        w.carry(WitnessDocument::Submit, &session, &second["document"])
            .await,
    );
    match w
        .carry(WitnessDocument::Submit, &session, &first["document"])
        .await
    {
        WitnessReply::Refused {
            refusal, retryable, ..
        } => {
            assert_eq!(refusal, WitnessRefusal::ChallengeMismatch);
            assert!(!retryable);
        }
        other => panic!("expected challengeMismatch, got {other:?}"),
    }

    // A session id the VTA does not know is its own refusal, not the witness's.
    let code = w
        .vta(
            WitnessTask::Accept,
            json!({ "sessionId": "urn:uuid:00000000-0000-4000-8000-00000000dead",
                    "response": session_answer }),
        )
        .await
        .expect_err("an unknown session");
    assert_eq!(code, "vta/witness/accept:sessionUnknown");
}
