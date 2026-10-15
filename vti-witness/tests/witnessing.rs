//! Witnessing end to end through the dispatch core, without a socket:
//! `witness/session/0.1` and `witness/session/submit/0.1`, every refusal path,
//! and the VWC checked the way the VTC checks one.
//!
//! Every party is a `did:key`, so every proof verifies with no network.

use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, TimeDelta, Utc};
use dtg_credentials::{DTGCredential, IssuerScope, WITNESSED_V1};
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::validate::ValidatedPayload;
use vta_sdk::provision_client::EphemeralSetupKey;
use vta_sdk::trust_task_proof::{
    ProofPurpose, TrustTaskVmResolver, verify_proof_set, verify_trust_task_proof_value,
};
use vta_sdk::trust_task_sign::{
    HolderKey, did_key_to_vm, sign_in_place_with, sign_object_for_assertion,
};
use vti_common::store::Store;
use vti_witness::config::{ANY_COMMUNITY, SessionLimits};
use vti_witness::dispatch::{
    IdentityContext, Outcome, WITNESS_SESSION_SUBMIT_V0_1, WITNESS_SESSION_V0_1, answer,
};
use vti_witness::store::{self as wstore, WitnessStore};
use vti_witness::witness::{WitnessPolicy, Witnessing, vwc_digest_multibase};

// ── Parties ─────────────────────────────────────────────────────────────

/// A `did:key` and its private key.
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

    fn secret(&self) -> Secret {
        let kid = did_key_to_vm(&self.did).expect("vm");
        Secret::from_multibase(&self.multibase, Some(&kid)).expect("secret")
    }
}

/// The witness under test: one identity, its store, and the store's handle
/// (for looking at what was kept).
struct Harness {
    identity: IdentityContext,
    witness: Key,
    store: Store,
    _dir: tempfile::TempDir,
}

struct Policy {
    communities: Vec<String>,
    allowed: Option<Vec<String>>,
    excluded: Vec<String>,
    limits: SessionLimits,
}

impl Policy {
    fn communities(communities: &[&str]) -> Self {
        Self {
            communities: communities.iter().map(|c| c.to_string()).collect(),
            allowed: None,
            excluded: Vec::new(),
            limits: SessionLimits::default(),
        }
    }
}

impl Harness {
    fn new(policy: Policy) -> Self {
        let witness = Key::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vti_common::store::test_fixture::open_with_keyspaces(dir.path(), wstore::ALL)
            .expect("store");
        let mut excluded = policy.excluded;
        excluded.push(witness.did.clone());
        let witnessing = Witnessing::new(
            WitnessPolicy::new(policy.communities, policy.allowed, excluded, policy.limits),
            WitnessStore::from_store(&store).expect("keyspaces"),
        );
        let identity = IdentityContext::new("w", witness.did.clone(), witness.holder(), witnessing)
            .expect("identity");
        Self {
            identity,
            witness,
            store,
            _dir: dir,
        }
    }

    fn store(&self) -> &WitnessStore {
        self.identity.witnessing().store()
    }

    async fn send_at(&self, sender: &str, doc: &Value, now: DateTime<Utc>) -> Value {
        match answer(
            &self.identity,
            sender,
            &serde_json::to_vec(doc).unwrap(),
            &TrustTaskVmResolver::did_key_only(),
            now,
        )
        .await
        {
            Outcome::Reply(reply) => {
                let signer =
                    verify_trust_task_proof_value(&reply, &TrustTaskVmResolver::did_key_only())
                        .await
                        .unwrap_or_else(|e| panic!("every reply is signed: {e}\n{reply:#}"));
                assert_eq!(signer, self.witness.did, "signed by the witness identity");
                assert_eq!(reply["issuer"], self.witness.did);
                assert_eq!(reply["recipient"], sender);
                reply
            }
            Outcome::Drop(reason) => panic!("expected a reply, dropped: {reason:?}"),
        }
    }

    async fn send(&self, sender: &str, doc: &Value) -> Value {
        self.send_at(sender, doc, Utc::now()).await
    }

    /// Every raw value in every keyspace of the store, as text.
    async fn everything_stored(&self) -> String {
        let mut all = String::new();
        for ks in wstore::ALL {
            let handle = self.store.keyspace(ks).unwrap();
            for (_, v) in handle.prefix_iter_raw(Vec::new()).await.unwrap() {
                all.push_str(&String::from_utf8_lossy(&v));
            }
        }
        all
    }
}

fn error_code(reply: &Value) -> &str {
    assert!(
        reply["type"]
            .as_str()
            .is_some_and(|t| t.starts_with(vta_sdk::inbound::TRUST_TASK_ERROR_PREFIX)),
        "expected a trust-task-error: {reply:#}"
    );
    reply["payload"]["code"].as_str().expect("code")
}

fn urn() -> String {
    format!("urn:uuid:{}", uuid::Uuid::new_v4())
}

// ── Documents ───────────────────────────────────────────────────────────

/// A `witness/session/0.1` opening its own thread.
fn session_doc(opener: &str, witness: &str, parties: [&str; 2]) -> Value {
    let id = urn();
    json!({
        "id": id,
        "threadId": id,
        "parentThreadId": "urn:uuid:00000000-0000-4000-8000-00000000beef",
        "type": WITNESS_SESSION_V0_1,
        "issuer": opener,
        "recipient": witness,
        "issuedAt": Utc::now().to_rfc3339(),
        "payload": { "parties": parties },
    })
}

/// A signed `witness/session/submit/0.1` on `thread`.
async fn submit_doc(by: &Key, witness: &str, thread: &str, vp: Value) -> Value {
    let mut doc: TrustTask<Value> = serde_json::from_value(json!({
        "id": urn(),
        "threadId": thread,
        "type": WITNESS_SESSION_SUBMIT_V0_1,
        "issuer": by.did,
        "recipient": witness,
        "issuedAt": Utc::now().to_rfc3339(),
        "payload": { "vp": vp },
    }))
    .unwrap();
    sign_in_place_with(&mut doc, &by.holder()).await.unwrap();
    serde_json::to_value(doc).unwrap()
}

async fn signed_credential(vc: DTGCredential, issuer: &Key) -> Value {
    let mut v = serde_json::to_value(vc).unwrap();
    sign_object_for_assertion(&mut v, &issuer.holder())
        .await
        .unwrap();
    v
}

/// `issuer`'s relationship credential naming `subject`.
async fn vrc(issuer: &Key, subject: &str) -> Value {
    let vc = DTGCredential::new_vrc(
        issuer.did.clone(),
        IssuerScope::Pairwise,
        subject.to_string(),
        Utc::now() - TimeDelta::minutes(5),
        None,
    )
    .with_id(urn());
    signed_credential(vc, issuer).await
}

/// `community`'s membership credential for `member`.
async fn vmc(community: &Key, member: &str, valid_until: Option<DateTime<Utc>>) -> Value {
    let vc = DTGCredential::new_vmc(
        community.did.clone(),
        member.to_string(),
        Utc::now() - TimeDelta::days(1),
        valid_until,
        false,
    )
    .with_id(urn());
    signed_credential(vc, community).await
}

/// A presentation by `holder` of `credentials`, bound to `challenge`/`domain`
/// in the members the workspace's VP builder uses, under an `authentication`
/// proof.
async fn vp(holder: &Key, credentials: Vec<Value>, challenge: &str, domain: &str) -> Value {
    let mut vp = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": holder.did,
        "verifiableCredential": credentials,
        "nonce": challenge,
        "domain": domain,
    });
    let proof = DataIntegrityProof::sign(
        &vp,
        &holder.secret(),
        SignOptions::new()
            .with_proof_purpose("authentication")
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .unwrap();
    vp["proof"] = serde_json::to_value(proof).unwrap();
    vp
}

/// Two relationship parties, a community they belong to, and a witness
/// serving that community.
struct World {
    h: Harness,
    alice: Key,
    bob: Key,
    community: Key,
}

impl World {
    fn new() -> Self {
        let community = Key::new();
        let h = Harness::new(Policy::communities(&[&community.did]));
        Self {
            h,
            alice: Key::new(),
            bob: Key::new(),
            community,
        }
    }

    fn with_policy(f: impl FnOnce(&Key, &mut Policy)) -> Self {
        let community = Key::new();
        let mut policy = Policy::communities(&[&community.did]);
        f(&community, &mut policy);
        Self {
            h: Harness::new(policy),
            alice: Key::new(),
            bob: Key::new(),
            community,
        }
    }

    fn witness_did(&self) -> &str {
        &self.h.witness.did
    }

    /// Alice opens a session naming Alice and Bob; the session document and
    /// the response.
    async fn open(&self) -> (Value, Value) {
        let doc = session_doc(
            &self.alice.did,
            self.witness_did(),
            [&self.alice.did, &self.bob.did],
        );
        let reply = self.h.send(&self.alice.did, &doc).await;
        (doc, reply)
    }

    /// Alice's honest presentation for a session answered with `reply`.
    async fn alice_vp(&self, reply: &Value) -> Value {
        let creds = vec![
            vrc(&self.alice, &self.bob.did).await,
            vmc(&self.community, &self.alice.did, None).await,
        ];
        vp(&self.alice, creds, challenge(reply), domain(reply)).await
    }
}

fn challenge(reply: &Value) -> &str {
    reply["payload"]["challenge"].as_str().expect("challenge")
}

fn domain(reply: &Value) -> &str {
    reply["payload"]["domain"].as_str().expect("domain")
}

fn id(doc: &Value) -> &str {
    doc["id"].as_str().unwrap()
}

// ── witness/session/0.1 ────────────────────────────────────────────────

#[tokio::test]
async fn a_session_opens_with_a_fresh_challenge_and_is_stored_as_received() {
    let w = World::new();
    let (doc, reply) = w.open().await;
    assert_eq!(
        reply["type"],
        format!("{WITNESS_SESSION_V0_1}#response"),
        "{reply:#}"
    );
    assert_eq!(reply["threadId"], doc["id"], "the session's own thread");
    assert_eq!(
        reply["parentThreadId"], doc["parentThreadId"],
        "§4.9.2 carried onto the reply"
    );
    let c = challenge(&reply);
    assert_eq!(c.len(), 64, "32 bytes, hex");
    assert_eq!(domain(&reply), w.witness_did());

    let stored =
        w.h.store()
            .session(w.witness_did(), id(&doc))
            .await
            .unwrap()
            .expect("stored");
    assert_eq!(stored.opener_did, w.alice.did);
    assert_eq!(stored.challenge, c);
    assert_eq!(stored.parties, vec![w.alice.did.clone(), w.bob.did.clone()]);
    let kept: Value = serde_json::from_str(&stored.document).unwrap();
    assert_eq!(kept, doc, "the session document as received");
    assert_eq!(
        stored.document.as_bytes(),
        serde_json::to_vec(&doc).unwrap(),
        "byte for byte"
    );
    assert!(stored.expires_at > Utc::now() + TimeDelta::minutes(9));

    // Bob's own session for the same exchange gets a different challenge.
    let doc2 = session_doc(&w.bob.did, w.witness_did(), [&w.alice.did, &w.bob.did]);
    let reply2 = w.h.send(&w.bob.did, &doc2).await;
    assert_ne!(
        challenge(&reply2),
        c,
        "a challenge is never reused across sessions"
    );
}

#[tokio::test]
async fn a_session_opened_by_a_party_not_in_the_exchange_is_refused() {
    let w = World::new();
    let carol = Key::new();
    let doc = session_doc(&carol.did, w.witness_did(), [&w.alice.did, &w.bob.did]);
    let reply = w.h.send(&carol.did, &doc).await;
    assert_eq!(error_code(&reply), "witness/session:refused", "{reply:#}");
}

#[tokio::test]
async fn a_session_naming_one_party_twice_is_refused() {
    let w = World::new();
    let doc = session_doc(&w.alice.did, w.witness_did(), [&w.alice.did, &w.alice.did]);
    let reply = w.h.send(&w.alice.did, &doc).await;
    assert_eq!(error_code(&reply), "witness/session:refused", "{reply:#}");
}

/// §3.2: a witness never witnesses itself or an excluded DID — and the
/// refusal does not say which rule, or a probe could learn the exclusions.
#[tokio::test]
async fn independence_refuses_the_witness_itself_and_excluded_dids_with_one_message() {
    let excluded = Key::new();
    let w = World::with_policy(|_, p| p.excluded.push(excluded.did.clone()));

    let own = session_doc(
        &w.alice.did,
        w.witness_did(),
        [&w.alice.did, w.witness_did()],
    );
    let r1 = w.h.send(&w.alice.did, &own).await;
    assert_eq!(error_code(&r1), "witness/session:refused");

    let ex = session_doc(&w.alice.did, w.witness_did(), [&w.alice.did, &excluded.did]);
    let r2 = w.h.send(&w.alice.did, &ex).await;
    assert_eq!(error_code(&r2), "witness/session:refused");

    let carol = Key::new();
    let stranger = session_doc(&carol.did, w.witness_did(), [&w.alice.did, &w.bob.did]);
    let r3 = w.h.send(&carol.did, &stranger).await;
    assert_eq!(r1["payload"]["message"], r2["payload"]["message"]);
    assert_eq!(
        r2["payload"]["message"], r3["payload"]["message"],
        "no rule is named"
    );
}

#[tokio::test]
async fn an_identity_with_no_communities_witnesses_nobody() {
    let w = World::with_policy(|_, p| p.communities.clear());
    let (_, reply) = w.open().await;
    assert_eq!(error_code(&reply), "witness/session:refused", "{reply:#}");
}

#[tokio::test]
async fn the_wildcard_witnesses_anyone_without_membership_evidence() {
    let w = World::with_policy(|_, p| p.communities = vec![ANY_COMMUNITY.to_string()]);
    let (doc, reply) = w.open().await;
    assert_eq!(reply["type"], format!("{WITNESS_SESSION_V0_1}#response"));
    // No VMC at all.
    let creds = vec![vrc(&w.alice, &w.bob.did).await];
    let p = vp(&w.alice, creds, challenge(&reply), domain(&reply)).await;
    let sub = submit_doc(&w.alice, w.witness_did(), id(&doc), p).await;
    let out = w.h.send(&w.alice.did, &sub).await;
    assert_eq!(
        out["type"],
        format!("{WITNESS_SESSION_SUBMIT_V0_1}#response"),
        "{out:#}"
    );
}

#[tokio::test]
async fn the_allow_list_admits_only_the_openers_it_names() {
    let alice = Key::new();
    let w = World::with_policy(|_, p| p.allowed = Some(vec![alice.did.clone()]));
    // `w.alice` is not on the list.
    let (_, refused) = w.open().await;
    assert_eq!(error_code(&refused), "witness/session:refused");
    let doc = session_doc(&alice.did, w.witness_did(), [&alice.did, &w.bob.did]);
    let ok = w.h.send(&alice.did, &doc).await;
    assert_eq!(
        ok["type"],
        format!("{WITNESS_SESSION_V0_1}#response"),
        "{ok:#}"
    );
}

#[tokio::test]
async fn the_caps_bound_open_sessions_in_total_and_per_party() {
    let w = World::with_policy(|_, p| {
        p.limits = SessionLimits {
            ttl_secs: 600,
            max_open: 2,
            max_open_per_party: 1,
        }
    });
    let (_, first) = w.open().await;
    assert!(first["payload"]["challenge"].is_string());
    let (_, second) = w.open().await;
    assert_eq!(
        error_code(&second),
        "witness/session:refused",
        "one per party"
    );

    let bob = session_doc(&w.bob.did, w.witness_did(), [&w.alice.did, &w.bob.did]);
    let ok = w.h.send(&w.bob.did, &bob).await;
    assert!(
        ok["payload"]["challenge"].is_string(),
        "another party has its own allowance"
    );

    let carol = Key::new();
    let third = session_doc(&carol.did, w.witness_did(), [&carol.did, &w.bob.did]);
    let full = w.h.send(&carol.did, &third).await;
    assert_eq!(error_code(&full), "witness/session:refused", "two in total");
}

#[tokio::test]
async fn expired_sessions_do_not_count_and_are_swept() {
    let w = World::with_policy(|_, p| {
        p.limits = SessionLimits {
            ttl_secs: 1,
            max_open: 1,
            max_open_per_party: 1,
        }
    });
    let (doc, _) = w.open().await;
    let later = Utc::now() + TimeDelta::seconds(5);
    let again = session_doc(&w.alice.did, w.witness_did(), [&w.alice.did, &w.bob.did]);
    let reply = w.h.send_at(&w.alice.did, &again, later).await;
    assert!(
        reply["payload"]["challenge"].is_string(),
        "the expired one no longer counts"
    );

    let removed = w.h.store().sweep(later).await.unwrap();
    assert!(removed >= 1);
    assert!(
        w.h.store()
            .session(w.witness_did(), id(&doc))
            .await
            .unwrap()
            .is_none()
    );
}

/// Party conformance item 1: the session document names its own thread, or
/// no VWC could ever cite it.
#[tokio::test]
async fn a_session_document_on_another_thread_is_malformed() {
    let w = World::new();
    let mut doc = session_doc(&w.alice.did, w.witness_did(), [&w.alice.did, &w.bob.did]);
    doc["threadId"] = json!(urn());
    let reply = w.h.send(&w.alice.did, &doc).await;
    assert_eq!(error_code(&reply), "malformedRequest", "{reply:#}");
}

/// §7.2 item 11: the same document again is answered with the first reply
/// and opens nothing; a different document under its `id` is `idConflict`.
#[tokio::test]
async fn a_replayed_session_is_answered_once_and_a_reused_id_conflicts() {
    let w = World::new();
    let (doc, first) = w.open().await;
    let again = w.h.send(&w.alice.did, &doc).await;
    assert_eq!(again, first, "the first reply, verbatim");
    assert_eq!(
        w.h.store()
            .open_sessions(w.witness_did(), Utc::now())
            .await
            .unwrap()
            .len(),
        1
    );

    let mut other = doc.clone();
    other["payload"]["parties"] = json!([w.alice.did, Key::new().did]);
    let conflict = w.h.send(&w.alice.did, &other).await;
    assert_eq!(error_code(&conflict), "idConflict", "{conflict:#}");
}

// ── witness/session/submit/0.1 ─────────────────────────────────────────

#[tokio::test]
async fn binding_comes_first_a_wrong_challenge_with_a_bad_vp_is_a_challenge_mismatch() {
    let w = World::new();
    let (doc, reply) = w.open().await;
    let mut p = vp(
        &w.alice,
        vec![vrc(&w.alice, &w.bob.did).await],
        "0000000000000000000000000000000000000000000000000000000000000000",
        domain(&reply),
    )
    .await;
    // Also break the presentation's proof: binding is checked before it.
    p["proof"]["proofValue"] = json!("z3FXQx2Wm7qKn1u8");
    let sub = submit_doc(&w.alice, w.witness_did(), id(&doc), p).await;
    let out = w.h.send(&w.alice.did, &sub).await;
    assert_eq!(
        error_code(&out),
        "witness/session/submit:challengeMismatch",
        "{out:#}"
    );
}

#[tokio::test]
async fn a_wrong_domain_is_a_challenge_mismatch() {
    let w = World::new();
    let (doc, reply) = w.open().await;
    let p = vp(
        &w.alice,
        vec![vrc(&w.alice, &w.bob.did).await],
        challenge(&reply),
        "did:example:another-witness",
    )
    .await;
    let sub = submit_doc(&w.alice, w.witness_did(), id(&doc), p).await;
    let out = w.h.send(&w.alice.did, &sub).await;
    assert_eq!(
        error_code(&out),
        "witness/session/submit:challengeMismatch",
        "{out:#}"
    );
}

/// Submit conformance item 3: only the opener submits on a session.
#[tokio::test]
async fn a_submit_from_a_party_that_did_not_open_the_session_is_a_challenge_mismatch() {
    let w = World::new();
    let (doc, reply) = w.open().await;
    // Bob, with a perfectly good presentation of his own, on Alice's session.
    let creds = vec![
        vrc(&w.bob, &w.alice.did).await,
        vmc(&w.community, &w.bob.did, None).await,
    ];
    let p = vp(&w.bob, creds, challenge(&reply), domain(&reply)).await;
    let sub = submit_doc(&w.bob, w.witness_did(), id(&doc), p).await;
    let out = w.h.send(&w.bob.did, &sub).await;
    assert_eq!(
        error_code(&out),
        "witness/session/submit:challengeMismatch",
        "{out:#}"
    );
}

#[tokio::test]
async fn a_submit_on_an_expired_or_unknown_session_is_a_challenge_mismatch() {
    let w = World::with_policy(|_, p| p.limits.ttl_secs = 1);
    let (doc, reply) = w.open().await;
    let p = w.alice_vp(&reply).await;

    let sub = submit_doc(&w.alice, w.witness_did(), id(&doc), p.clone()).await;
    let out =
        w.h.send_at(&w.alice.did, &sub, Utc::now() + TimeDelta::seconds(5))
            .await;
    assert_eq!(
        error_code(&out),
        "witness/session/submit:challengeMismatch",
        "{out:#}"
    );

    let unknown = submit_doc(&w.alice, w.witness_did(), &urn(), p).await;
    let out = w.h.send(&w.alice.did, &unknown).await;
    assert_eq!(
        error_code(&out),
        "witness/session/submit:challengeMismatch",
        "{out:#}"
    );
}

/// A session is single use: two different submissions racing on one session
/// mint exactly one VWC.
#[tokio::test]
async fn two_submissions_on_one_session_mint_exactly_one_vwc() {
    let w = Arc::new(World::new());
    let (doc, reply) = w.open().await;
    let s1 = submit_doc(
        &w.alice,
        w.witness_did(),
        id(&doc),
        w.alice_vp(&reply).await,
    )
    .await;
    let s2 = submit_doc(
        &w.alice,
        w.witness_did(),
        id(&doc),
        w.alice_vp(&reply).await,
    )
    .await;
    assert_ne!(s1["id"], s2["id"]);

    let (a, b) = tokio::join!(w.h.send(&w.alice.did, &s1), w.h.send(&w.alice.did, &s2));
    let minted = [&a, &b]
        .iter()
        .filter(|r| r["type"] == format!("{WITNESS_SESSION_SUBMIT_V0_1}#response"))
        .count();
    assert_eq!(minted, 1, "exactly one VWC\n{a:#}\n{b:#}");
    let loser = if a["payload"]["vwc"].is_object() {
        &b
    } else {
        &a
    };
    assert_eq!(
        error_code(loser),
        "witness/session/submit:challengeMismatch"
    );
    assert_eq!(
        w.h.store()
            .attestations(w.witness_did())
            .await
            .unwrap()
            .len(),
        1
    );
}

/// §7.2 item 11 on submit: a redelivered submission gets the same VWC back,
/// and nothing is minted twice.
#[tokio::test]
async fn a_replayed_submission_is_answered_with_the_same_vwc() {
    let w = World::new();
    let (doc, reply) = w.open().await;
    let sub = submit_doc(
        &w.alice,
        w.witness_did(),
        id(&doc),
        w.alice_vp(&reply).await,
    )
    .await;
    let first = w.h.send(&w.alice.did, &sub).await;
    let again = w.h.send(&w.alice.did, &sub).await;
    assert_eq!(first, again);
    assert_eq!(
        w.h.store()
            .attestations(w.witness_did())
            .await
            .unwrap()
            .len(),
        1
    );
}

/// Each way a presentation fails after the binding holds.
#[tokio::test]
async fn presentation_failures_are_presentation_invalid() {
    let other_community = Key::new();
    let mallory = Key::new();

    type Build = for<'a> fn(
        &'a World,
        &'a Value,
        &'a Key,
        &'a Key,
    )
        -> std::pin::Pin<Box<dyn std::future::Future<Output = Value> + 'a>>;
    let cases: Vec<(&str, Build)> = vec![
        ("signed by someone else", |w, r, _, m| {
            Box::pin(async move {
                let creds = vec![
                    vrc(&w.alice, &w.bob.did).await,
                    vmc(&w.community, &w.alice.did, None).await,
                ];
                let mut p = vp(m, creds, challenge(r), domain(r)).await;
                p["holder"] = json!(w.alice.did);
                p
            })
        }),
        ("holder is not the submitter", |w, r, _, m| {
            Box::pin(async move {
                let creds = vec![vrc(&w.alice, &w.bob.did).await];
                vp(m, creds, challenge(r), domain(r)).await
            })
        }),
        ("a tampered relationship credential", |w, r, _, _| {
            Box::pin(async move {
                let mut cred = vrc(&w.alice, &w.bob.did).await;
                cred["validFrom"] = json!("2020-01-01T00:00:00Z");
                let creds = vec![cred, vmc(&w.community, &w.alice.did, None).await];
                vp(&w.alice, creds, challenge(r), domain(r)).await
            })
        }),
        (
            "no relationship credential from the submitter",
            |w, r, _, _| {
                Box::pin(async move {
                    let creds = vec![
                        vrc(&w.bob, &w.alice.did).await,
                        vmc(&w.community, &w.alice.did, None).await,
                    ];
                    vp(&w.alice, creds, challenge(r), domain(r)).await
                })
            },
        ),
        (
            "a relationship credential for another edge",
            |w, r, _, m| {
                Box::pin(async move {
                    let creds = vec![
                        vrc(&w.alice, &m.did).await,
                        vmc(&w.community, &w.alice.did, None).await,
                    ];
                    vp(&w.alice, creds, challenge(r), domain(r)).await
                })
            },
        ),
        ("no membership credential", |w, r, _, _| {
            Box::pin(async move {
                let creds = vec![vrc(&w.alice, &w.bob.did).await];
                vp(&w.alice, creds, challenge(r), domain(r)).await
            })
        }),
        ("membership in another community", |w, r, oc, _| {
            Box::pin(async move {
                let creds = vec![
                    vrc(&w.alice, &w.bob.did).await,
                    vmc(oc, &w.alice.did, None).await,
                ];
                vp(&w.alice, creds, challenge(r), domain(r)).await
            })
        }),
        ("membership naming another subject", |w, r, _, _| {
            Box::pin(async move {
                let creds = vec![
                    vrc(&w.alice, &w.bob.did).await,
                    vmc(&w.community, &w.bob.did, None).await,
                ];
                vp(&w.alice, creds, challenge(r), domain(r)).await
            })
        }),
        ("an expired membership", |w, r, _, _| {
            Box::pin(async move {
                let creds = vec![
                    vrc(&w.alice, &w.bob.did).await,
                    vmc(
                        &w.community,
                        &w.alice.did,
                        Some(Utc::now() - TimeDelta::hours(1)),
                    )
                    .await,
                ];
                vp(&w.alice, creds, challenge(r), domain(r)).await
            })
        }),
    ];

    for (what, build) in cases {
        let w = World::new();
        let (doc, reply) = w.open().await;
        let p = build(&w, &reply, &other_community, &mallory).await;
        let sub = submit_doc(&w.alice, w.witness_did(), id(&doc), p).await;
        let out = w.h.send(&w.alice.did, &sub).await;
        assert_eq!(
            error_code(&out),
            "witness/session/submit:presentationInvalid",
            "{what}: {out:#}"
        );
        // A failed presentation does not spend the session.
        assert!(
            w.h.store()
                .session(w.witness_did(), id(&doc))
                .await
                .unwrap()
                .is_some(),
            "{what}"
        );
    }
}

/// §3.2 at submit: membership evidence issued by an excluded DID does not
/// count, even from a community the identity names.
#[tokio::test]
async fn independence_at_submit_refuses_evidence_from_an_excluded_issuer() {
    let w = World::with_policy(|community, p| p.excluded.push(community.did.clone()));
    let (doc, reply) = w.open().await;
    let sub = submit_doc(
        &w.alice,
        w.witness_did(),
        id(&doc),
        w.alice_vp(&reply).await,
    )
    .await;
    let out = w.h.send(&w.alice.did, &sub).await;
    assert_eq!(
        error_code(&out),
        "witness/session/submit:presentationInvalid",
        "{out:#}"
    );
}

// ── End to end, checked as the VTC checks a VWC ─────────────────────────

/// Open, submit, receive the VWC — then verify it with the checks
/// `vtc-service/src/credentials/witness.rs` applies (the digest binding to
/// the VRC and the subject–object rule, `dtg_credentials::witnesses_issuance_of`;
/// `cites_task` against the session document; the issuer is the witness), plus
/// the VWC's own proof and the `vwcDigestMultibase` pairing. Replicated with
/// `dtg-credentials` rather than called, because that verifier lives in
/// `vtc-service`, which this crate does not depend on.
#[tokio::test]
async fn end_to_end_the_vwc_verifies_as_the_vtc_verifies_it() {
    let w = World::new();
    let (session, reply) = w.open().await;
    let edge = vrc(&w.alice, &w.bob.did).await;
    let creds = vec![edge.clone(), vmc(&w.community, &w.alice.did, None).await];
    let p = vp(&w.alice, creds, challenge(&reply), domain(&reply)).await;
    let vp_proof = p["proof"]["proofValue"].as_str().unwrap().to_string();
    let sub = submit_doc(&w.alice, w.witness_did(), id(&session), p).await;
    let out = w.h.send(&w.alice.did, &sub).await;

    assert_eq!(
        out["type"],
        format!("{WITNESS_SESSION_SUBMIT_V0_1}#response"),
        "{out:#}"
    );
    assert_eq!(out["threadId"], session["id"], "on the session's thread");
    trust_tasks_rs::specs::witness::session::submit::v0_1::Response::validate_value(
        &out["payload"],
    )
    .expect("a schema-valid submit response");
    let vwc_json = out["payload"]["vwc"].clone();

    // The VWC's own proof: the witness's assertionMethod key.
    let signed = verify_proof_set(
        &vwc_json,
        ProofPurpose::AssertionMethod,
        &TrustTaskVmResolver::did_key_only(),
    )
    .await
    .expect("the VWC's proof verifies");
    assert_eq!(signed.signer(), w.witness_did());

    // vwcDigestMultibase: the delivered credential whole, proof included.
    let carried = out["payload"]["vwcDigestMultibase"].as_str().unwrap();
    assert_eq!(carried, vwc_digest_multibase(&vwc_json).unwrap());
    assert!(carried.starts_with('z'));
    let proofless = dtg_credentials::digest_multibase_json(&vwc_json).unwrap();
    assert_ne!(carried, proofless, "not the proof-less credential digest");

    let vwc = DTGCredential::try_from(vwc_json.clone()).expect("a DTG credential");
    vwc.validate().expect("validates");
    // The issuer is the witness: the session's recipient and the reply's issuer.
    assert_eq!(vwc.issuer(), w.witness_did());
    assert_eq!(vwc.issuer(), session["recipient"]);
    assert_eq!(vwc.issuer_scope(), IssuerScope::Public);
    assert_eq!(vwc.predicate(), Some(WITNESSED_V1));
    assert!(
        vwc_json["type"]
            .as_array()
            .unwrap()
            .contains(&json!("StatementCredential"))
    );
    // The digest binding to the VRC and the subject–object rule.
    assert!(
        vwc.witnesses_issuance_of(&edge).unwrap(),
        "binds this edge, this direction"
    );
    assert_eq!(vwc.subject(), w.alice.did);
    let reverse = vrc(&w.bob, &w.alice.did).await;
    assert!(
        !vwc.witnesses_issuance_of(&reverse).unwrap(),
        "not the other direction"
    );
    // taskContext / taskDigestMultibase name this session document.
    assert_eq!(vwc.task_context(), Some(id(&session)));
    assert!(
        vwc.cites_task(&session).unwrap(),
        "cites the session document"
    );
    let mut counterfeit = session.clone();
    counterfeit["payload"]["parties"] = json!([w.alice.did, Key::new().did]);
    assert!(
        !vwc.cites_task(&counterfeit).unwrap(),
        "an id alone is not the document"
    );

    // Kept: one attestation record. Not kept: the session, or the VP.
    let records = w.h.store().attestations(w.witness_did()).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].vwc_id, vwc.id().unwrap());
    assert_eq!(records[0].vwc_digest_multibase, carried);
    assert_eq!(records[0].submitter_did, w.alice.did);
    assert_eq!(records[0].session_id, id(&session));
    assert!(
        w.h.store()
            .session(w.witness_did(), id(&session))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !w.h.everything_stored().await.contains(&vp_proof),
        "the presentation is never stored"
    );
}
