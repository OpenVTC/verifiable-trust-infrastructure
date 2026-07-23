//! Delegated trust-task execution, end to end, over the wire.
//!
//! # Why this exists
//!
//! Every integration bug in this feature survived because nobody ran the flow.
//! The unit tests all passed — they were written against seams their authors
//! chose, and they encoded what those authors *believed*, so they could only ever
//! confirm it. A test that mocks the transport cannot discover that the transport
//! throws. A test that uses the type URI from a constant cannot discover that the
//! caller sends a different string.
//!
//! So this test mocks nothing. It drives the real HTTP router, posts real Trust
//! Task documents, verifies real Data-Integrity proofs, and reads the resulting
//! `did:webvh` log off the real keyspace. If any two components disagree about
//! anything — a field's casing, a type URI, the shape of a rejection — this fails.
//!
//! # What it proves
//!
//! The claim the whole design rests on, checked rather than asserted:
//!
//! > **The keys a human was shown are the keys that execute.**
//!
//! The consent request the approver signs carries an executor-authored
//! `keyRotation` effect naming the key that will be installed. The test approves
//! it, re-submits, and then reads the DID log to check that *that* key is the one
//! now in force. Nothing in between is trusted.

#![cfg(feature = "webvh")]

use affinidi_data_integrity::crypto_suites::CryptoSuite;
use affinidi_data_integrity::{DataIntegrityProof, prepare_sign_input};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use multibase::Base;
use serde_json::{Value, json};
use tower::ServiceExt;
use trust_tasks_rs::{Proof, TrustTask};

use vta_service::test_support::{TestAppContext, TestAppOptions, build_test_app_with};

/// The URI a caller actually sends. Taken from the SDK, which is what every real
/// client resolves — a literal here would only re-encode one author's belief, and
/// that belief was wrong once already.
const WEBVH_UPDATE: &str = vta_sdk::trust_tasks::TASK_WEBVH_DIDS_UPDATE_1_0;
const TASK_CONSENT_DECISION: &str = vta_sdk::trust_tasks::TASK_TASK_CONSENT_DECISION_0_1;

/// Policy: this task needs a human, and it must not be the requester.
const REQUIRE_CONSENT: &str = r#"package vta.policy
import rego.v1
decision := {"decision": "requireConsent", "requireConsent": {"approverSet": "operators", "excludeRequester": true}}
"#;

// ─── wire helpers ────────────────────────────────────────────────────────────

async fn post(router: &axum::Router, token: &str, doc: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(doc).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A `did:key` identity that can sign a Data-Integrity proof.
struct Approver {
    did: String,
    vm: String,
    sk: SigningKey,
}

fn approver(seed: u8) -> Approver {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = sk.verifying_key();
    let mut mc = vec![0xed, 0x01];
    mc.extend_from_slice(pk.as_bytes());
    let did = format!("did:key:{}", multibase::encode(Base::Base58Btc, &mc));
    let vm = format!("{did}#{}", did.strip_prefix("did:key:").unwrap());
    Approver { did, vm, sk }
}

/// Sign a Trust Task document as `who`. The proof IS the authorization — the VTA
/// takes the approver's identity from it, never from the bearer session.
fn sign_as(who: &Approver, doc_json: Value) -> Value {
    let mut doc: TrustTask<Value> = serde_json::from_value(doc_json).unwrap();
    let mut di = DataIntegrityProof::new(
        CryptoSuite::EddsaJcs2022,
        who.vm.clone(),
        "assertionMethod".to_string(),
        None,
        Some("2026-07-14T00:00:00Z".to_string()),
        None,
    );
    let input = prepare_sign_input(&doc, &di, CryptoSuite::EddsaJcs2022).unwrap();
    di.proof_value = Some(multibase::encode(
        Base::Base58Btc,
        who.sk.sign(&input).to_bytes(),
    ));
    doc.proof = Some(serde_json::from_value::<Proof>(serde_json::to_value(&di).unwrap()).unwrap());
    serde_json::to_value(&doc).unwrap()
}

fn envelope(type_uri: &str, issuer: &str, recipient: &str, payload: Value) -> Value {
    json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuer": issuer,
        "recipient": recipient,
        "issuedAt": "2026-07-14T00:00:00Z",
        "payload": payload,
    })
}

/// The update keys actually in force on `did`, read from the committed log.
///
/// webvh parameters are a delta — an entry that does not restate `update_keys`
/// leaves the previous entry's standing — so "in force" means the last entry that
/// restated them, not whatever the final entry happens to carry.
async fn update_keys_in_force(ctx: &TestAppContext, did: &str) -> Vec<String> {
    use didwebvh_rs::log_entry::LogEntryMethods;
    let log = vta_service::webvh_store::get_did_log(&ctx.webvh_ks, did)
        .await
        .expect("get_did_log")
        .expect("the DID has a log");
    let state =
        vta_service::operations::did_webvh::state_from_jsonl_pub(&log).expect("valid chain");

    let mut keys: Vec<String> = vec![];
    for entry in state.log_entries() {
        if let Some(arc) = entry.log_entry.get_parameters().update_keys.as_ref() {
            keys = arc.iter().map(|k| k.as_ref().to_string()).collect();
        }
    }
    keys
}

// ─── the flow ────────────────────────────────────────────────────────────────

/// A caller asks the VTA to update a DID document. Policy demands a human. The
/// approver is shown what it will do, approves, and the update executes — and the
/// keys the approver was shown are the keys that end up in the log.
#[tokio::test]
async fn a_did_update_is_approved_by_a_human_and_the_keys_they_saw_are_the_keys_installed() {
    let (router, ctx) = build_test_app_with(TestAppOptions {
        // A real VTA signing identity (active seed + `{vta_did}#key-0`), because
        // the update handler's dry-run signs the planned entry — a sentinel DID
        // with no key cannot execute the flow this test exists to exercise.
        provisionable_vta: true,
        ..Default::default()
    })
    .await;
    let requester = "did:key:z6MkTestRequester";
    let token = ctx.mint_token(requester, "admin", vec![]).await;
    let ops = approver(7);

    // A real DID, minted over the wire by the VTA that holds its key.
    let (did, _scid) = create_did(&router, &ctx, &token).await;
    let keys_before = update_keys_in_force(&ctx, &did).await;
    assert_eq!(keys_before.len(), 1, "a fresh DID has one update key");

    // The deployment's policy: a human approves this, and not the requester.
    {
        let mut cfg = ctx.config.write().await;
        cfg.policy.enforcement = true;
        cfg.policy
            .approver_sets
            .insert("operators".into(), vec![ops.did.clone()]);
    }
    install_policy(&ctx, REQUIRE_CONSENT).await;

    // ── 1. The caller proposes an edit. Note the camelCase — this is the wire
    //       form a real client sends, and a mismatch here once silently disabled
    //       the concurrency precondition entirely.
    let new_doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "service": [{
            "id": "#files",
            "type": "FileStore",
            "serviceEndpoint": "https://files.example.com/acme"
        }]
    });
    let update = envelope(
        WEBVH_UPDATE,
        requester,
        &ctx.vta_did,
        json!({ "did": did, "document": new_doc }),
    );

    let (status, rejected) = post(&router, &token, &update).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a task needing consent must be refused, not executed: {rejected}"
    );
    assert!(
        rejected["payload"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("auth:consent_required"),
        "the refusal must name the consent requirement: {rejected}"
    );

    // ── 2. The refusal carries what an approver needs, and what the requesting
    //       surface must display.
    let details = &rejected["payload"]["details"];
    let payload_digest = details["payloadDigest"]
        .as_str()
        .expect("a digest to match");
    let challenge = details["challenge"].as_str().expect("a challenge");
    let requests = details["consentRequests"]
        .as_array()
        .expect("the signed requests to relay");
    assert_eq!(requests.len(), 1, "one request per eligible approver");

    let consent_request = &requests[0];
    assert!(
        consent_request["proof"].is_object(),
        "the request must be VTA-signed — an unsigned one lets anyone author what \
         the human reads"
    );
    assert_eq!(consent_request["issuer"], json!(ctx.vta_did));
    assert_eq!(consent_request["recipient"], json!(ops.did));

    // ── 3. The effects. This is the point of the whole design: the payload above
    //       says "add a service endpoint" and says nothing about keys, but the
    //       executor dry-ran its own handler and knows better.
    let cp = &consent_request["payload"];
    assert_eq!(
        cp["payloadDigest"],
        json!(payload_digest),
        "both screens show one value"
    );
    assert_eq!(cp["challenge"], json!(challenge));
    assert_eq!(
        cp["sideEffects"], "destructive",
        "rotating a sole controlling key is authority-shifting (SPEC §7.3 item 13)"
    );

    let effects = cp["effects"].as_array().expect("executor-authored effects");
    let rotation = effects
        .iter()
        .find(|e| e["kind"] == "keyRotation")
        .expect("the payload never mentions a key rotation — the dry-run must");

    let promised_keys: Vec<String> = rotation["after"]
        .as_array()
        .expect("the rotation names the keys it will install")
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        rotation["before"],
        json!(keys_before),
        "the rotation must show the key actually in force, not a guess"
    );
    assert_ne!(
        promised_keys, keys_before,
        "a rotation that changes nothing is not one"
    );

    // ── 4. The human approves. The proof is the authorization; the bearer token
    //       belongs to the *requester* and says nothing about who agreed.
    let decision = sign_as(
        &ops,
        envelope(
            TASK_CONSENT_DECISION,
            &ops.did,
            &ctx.vta_did,
            json!({
                "challenge": challenge,
                "payloadDigest": payload_digest,
                "decision": "approve"
            }),
        ),
    );
    let (status, granted) = post(&router, &token, &decision).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the decision must be accepted: {granted}"
    );
    assert_eq!(granted["payload"]["status"], "granted", "{granted}");

    // ── 5. The caller re-submits the SAME PAYLOAD as a fresh envelope. The grant
    //       binds the payload digest, not the envelope id — and the replay guard
    //       would reject a reused id as a duplicate. So a real requester
    //       re-proposes the approved task in a new envelope, exactly as here.
    let resubmit = envelope(
        WEBVH_UPDATE,
        requester,
        &ctx.vta_did,
        update["payload"].clone(),
    );
    let (status, executed) = post(&router, &token, &resubmit).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the approved task must now execute: {executed}"
    );

    // ── 6. THE CLAIM. The keys the human was shown are the keys in the log.
    let keys_after = update_keys_in_force(&ctx, &did).await;
    assert_eq!(
        keys_after, promised_keys,
        "the approver authorized a rotation to {promised_keys:?}, and the DID now \
         has {keys_after:?}. If these differ, a human approved a key that never \
         existed — and every signature over that approval still verifies."
    );
}

/// The grant is single-use: an approved task executes once, and a replay of the
/// same document is refused rather than silently run again.
#[tokio::test]
async fn an_approval_authorizes_exactly_one_execution() {
    let (router, ctx) = build_test_app_with(TestAppOptions {
        // A real VTA signing identity (active seed + `{vta_did}#key-0`), because
        // the update handler's dry-run signs the planned entry — a sentinel DID
        // with no key cannot execute the flow this test exists to exercise.
        provisionable_vta: true,
        ..Default::default()
    })
    .await;
    let requester = "did:key:z6MkTestRequester";
    let token = ctx.mint_token(requester, "admin", vec![]).await;
    let ops = approver(9);

    let (did, _scid) = create_did(&router, &ctx, &token).await;
    {
        let mut cfg = ctx.config.write().await;
        cfg.policy.enforcement = true;
        cfg.policy
            .approver_sets
            .insert("operators".into(), vec![ops.did.clone()]);
    }
    install_policy(&ctx, REQUIRE_CONSENT).await;

    let payload = json!({
        "did": did,
        "document": { "@context": ["https://www.w3.org/ns/did/v1"], "id": did, "alsoKnownAs": ["did:example:x"] }
    });
    let update = envelope(WEBVH_UPDATE, requester, &ctx.vta_did, payload);

    let (_, rejected) = post(&router, &token, &update).await;
    let d = &rejected["payload"]["details"];
    let decision = sign_as(
        &ops,
        envelope(
            TASK_CONSENT_DECISION,
            &ops.did,
            &ctx.vta_did,
            json!({
                "challenge": d["challenge"],
                "payloadDigest": d["payloadDigest"],
                "decision": "approve"
            }),
        ),
    );
    let (status, _) = post(&router, &token, &decision).await;
    assert_eq!(status, StatusCode::OK);

    // First re-submit (fresh envelope, same payload) executes.
    let first = envelope(
        WEBVH_UPDATE,
        requester,
        &ctx.vta_did,
        update["payload"].clone(),
    );
    let (status, _) = post(&router, &token, &first).await;
    assert_eq!(status, StatusCode::OK, "the approved task executes");

    // A second submit of the same payload must NOT quietly execute again. The
    // grant was consumed; what comes back is a fresh demand for consent.
    let second = envelope(
        WEBVH_UPDATE,
        requester,
        &ctx.vta_did,
        update["payload"].clone(),
    );
    let (status, again) = post(&router, &token, &second).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "an approval authorizes ONE execution — a replay must be refused: {again}"
    );
    assert!(
        again["payload"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("auth:consent_required"),
        "a replay must re-require consent: {again}"
    );
}

/// A device that proposes a task cannot approve it when policy excludes the
/// requester — the whole point being that one compromised device is not enough.
#[tokio::test]
async fn the_requester_cannot_approve_its_own_task() {
    let (router, ctx) = build_test_app_with(TestAppOptions {
        // A real VTA signing identity (active seed + `{vta_did}#key-0`), because
        // the update handler's dry-run signs the planned entry — a sentinel DID
        // with no key cannot execute the flow this test exists to exercise.
        provisionable_vta: true,
        ..Default::default()
    })
    .await;
    let requester = approver(11);
    let token = ctx.mint_token(&requester.did, "admin", vec![]).await;

    let (did, _scid) = create_did(&router, &ctx, &token).await;
    {
        let mut cfg = ctx.config.write().await;
        cfg.policy.enforcement = true;
        // The requester is IN the approver set — and the policy excludes them anyway.
        cfg.policy
            .approver_sets
            .insert("operators".into(), vec![requester.did.clone()]);
    }
    install_policy(&ctx, REQUIRE_CONSENT).await;

    let update = envelope(
        WEBVH_UPDATE,
        &requester.did,
        &ctx.vta_did,
        json!({ "did": did, "document": { "@context": ["https://www.w3.org/ns/did/v1"], "id": did } }),
    );
    let (_, rejected) = post(&router, &token, &update).await;
    let d = &rejected["payload"]["details"];

    // Nobody was even asked: the only member of the set is the requester.
    assert_eq!(
        d["consentRequests"].as_array().map(Vec::len),
        Some(0),
        "there is nobody eligible to ask, and we must not pretend otherwise"
    );

    // And if they sign one anyway, the executor refuses it.
    let decision = sign_as(
        &requester,
        envelope(
            TASK_CONSENT_DECISION,
            &requester.did,
            &ctx.vta_did,
            json!({
                "challenge": d["challenge"],
                "payloadDigest": d["payloadDigest"],
                "decision": "approve"
            }),
        ),
    );
    let (status, refused) = post(&router, &token, &decision).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "the requester must not be able to self-approve: {refused}"
    );
}

/// Per-task delegated capability, end to end: a requester with **no authority
/// over the DID's context** proposes an update, an admin **of that context**
/// approves, and the update executes — under authority the approval conferred
/// for that one task, never standing on the requester's token.
///
/// This is the flow the whole redesign exists for: the agent holds nothing, and
/// authority arrives per-task from someone who actually has it.
#[tokio::test]
async fn a_context_admin_approval_lets_a_cross_context_requester_execute() {
    let (router, ctx) = build_test_app_with(TestAppOptions {
        provisionable_vta: true,
        ..Default::default()
    })
    .await;

    // Setup: mint the DID in context `default` using a super-admin (the
    // provisioning identity a deployment already trusts).
    let admin_token = ctx
        .mint_token("did:key:z6MkTestRequester", "admin", vec![])
        .await;
    let (did, _scid) = create_did(&router, &ctx, &admin_token).await;
    let keys_before = update_keys_in_force(&ctx, &did).await;

    // The requester is an admin — but of `other-ctx`, NOT `default`. On its own
    // token it cannot touch this DID.
    let requester = "did:key:z6MkCrossCtxAgent";
    let deleg_token = ctx
        .mint_token(requester, "admin", vec!["other-ctx".into()])
        .await;

    // The approver is an admin of `default` in the ACL — the authority a
    // delegation can draw on.
    let ops = approver(21);
    vta_service::test_support::seed_acl_entry(
        &ctx.acl_ks,
        &ops.did,
        vta_service::acl::Role::Admin,
        vec!["default".into()],
    )
    .await;

    {
        let mut cfg = ctx.config.write().await;
        cfg.policy.enforcement = true;
        cfg.policy
            .approver_sets
            .insert("operators".into(), vec![ops.did.clone()]);
    }
    install_policy(&ctx, REQUIRE_CONSENT).await;

    // 1. The cross-context requester proposes the edit. The dry-run must succeed
    //    *despite* the requester lacking the context (plan tolerance) so an
    //    approver can be shown the effects.
    let update = envelope(
        WEBVH_UPDATE,
        requester,
        &ctx.vta_did,
        json!({
            "did": did,
            "document": { "@context": ["https://www.w3.org/ns/did/v1"], "id": did, "alsoKnownAs": ["did:example:delegated"] }
        }),
    );
    let (status, rejected) = post(&router, &deleg_token, &update).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a cross-context proposal must require consent, not fail or execute: {rejected}"
    );
    let d = &rejected["payload"]["details"];
    let payload_digest = d["payloadDigest"].as_str().expect("digest");
    let challenge = d["challenge"].as_str().expect("challenge");
    assert_eq!(
        d["consentRequests"].as_array().map(Vec::len),
        Some(1),
        "the context admin must be asked: {rejected}"
    );

    // 2. The context admin approves.
    let decision = sign_as(
        &ops,
        envelope(
            TASK_CONSENT_DECISION,
            &ops.did,
            &ctx.vta_did,
            json!({ "challenge": challenge, "payloadDigest": payload_digest, "decision": "approve" }),
        ),
    );
    let (status, granted) = post(&router, &deleg_token, &decision).await;
    assert_eq!(status, StatusCode::OK, "decision accepted: {granted}");
    assert_eq!(granted["payload"]["status"], "granted", "{granted}");

    // 3. The cross-context requester re-submits — and it now executes, under the
    //    context authority the approval conferred for this one task.
    let resubmit = envelope(
        WEBVH_UPDATE,
        requester,
        &ctx.vta_did,
        update["payload"].clone(),
    );
    let (status, executed) = post(&router, &deleg_token, &resubmit).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the delegated task must execute for a requester who never held the context: {executed}"
    );

    // 4. It really ran: a webvh update rotates the update key, so the log moved.
    let keys_after = update_keys_in_force(&ctx, &did).await;
    assert_ne!(
        keys_after, keys_before,
        "the delegated update must have committed to the log"
    );
}

/// The dual: when the only set member is **not** an admin of the DID's context,
/// there is no approval anyone could give that would let the task execute —
/// authority can only be delegated by someone who holds it.
///
/// The task is therefore refused **at submission**, before any consent ceremony
/// is minted (#748). It used to mint a pending, accept the approval, hand back a
/// grant carrying an empty delegation, and only then forbid the re-submit — a
/// ceremony whose outcome was decided before it began, and which in production
/// looped: approved, still forbidden, no actionable error.
///
/// So the guarantee under test is unchanged and strictly stronger: a
/// non-context-admin's approval confers no execution. What moved is *when* we
/// say so, and that the refusal now names the context and the gap.
#[tokio::test]
async fn an_unsatisfiable_elevation_is_refused_before_any_consent_ceremony() {
    let (router, ctx) = build_test_app_with(TestAppOptions {
        provisionable_vta: true,
        ..Default::default()
    })
    .await;

    let admin_token = ctx
        .mint_token("did:key:z6MkTestRequester", "admin", vec![])
        .await;
    let (did, _scid) = create_did(&router, &ctx, &admin_token).await;
    let keys_before = update_keys_in_force(&ctx, &did).await;

    let requester = "did:key:z6MkCrossCtxAgent";
    let deleg_token = ctx
        .mint_token(requester, "admin", vec!["other-ctx".into()])
        .await;

    // The approver administers a DIFFERENT context, not `default`.
    let ops = approver(23);
    vta_service::test_support::seed_acl_entry(
        &ctx.acl_ks,
        &ops.did,
        vta_service::acl::Role::Admin,
        vec!["some-other-ctx".into()],
    )
    .await;

    {
        let mut cfg = ctx.config.write().await;
        cfg.policy.enforcement = true;
        cfg.policy
            .approver_sets
            .insert("operators".into(), vec![ops.did.clone()]);
    }
    install_policy(&ctx, REQUIRE_CONSENT).await;

    let update = envelope(
        WEBVH_UPDATE,
        requester,
        &ctx.vta_did,
        json!({
            "did": did,
            "document": { "@context": ["https://www.w3.org/ns/did/v1"], "id": did, "alsoKnownAs": ["did:example:nope"] }
        }),
    );
    let (status, refused) = post(&router, &deleg_token, &update).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "an elevation no approver can confer must be refused, not executed: {refused}"
    );

    // The refusal has to be actionable: an operator reading it must learn which
    // context is missing and who would have to hold it. A bare "forbidden" is
    // what sent this into a loop in production.
    let payload = refused["payload"].to_string();
    assert!(
        payload.contains("consent cannot confer"),
        "the refusal must say the elevation is unsatisfiable, not merely forbidden: {refused}"
    );
    assert!(
        payload.contains("`default`"),
        "the refusal must name the context the requester lacks: {refused}"
    );
    assert!(
        payload.contains("`operators`"),
        "the refusal must name the approver set that cannot confer it: {refused}"
    );

    // Nothing to approve: no ceremony was minted, so there is no challenge for
    // an approver to sign. This is the part that used to happen and shouldn't.
    let details = &refused["payload"]["details"];
    assert!(
        details["challenge"].is_null() && details["consentRequests"].is_null(),
        "no consent ceremony may be minted for a task that could never execute: {refused}"
    );

    // And of course nothing ran.
    assert_eq!(
        update_keys_in_force(&ctx, &did).await,
        keys_before,
        "nothing may have committed to the log"
    );
}

// ─── setup ───────────────────────────────────────────────────────────────────

async fn install_policy(ctx: &TestAppContext, rego: &str) {
    use vta_service::policy::PolicyModule;
    let module = PolicyModule {
        id: "e2e".into(),
        name: "e2e".into(),
        description: None,
        module: rego.to_string(),
        applies_to: vec![],
        priority: 0,
        enabled: true,
        version: 1,
        created_at: "2026-07-14T00:00:00Z".to_string(),
        updated_at: "2026-07-14T00:00:00Z".to_string(),
    };
    vta_service::policy::storage::store_policy(&ctx.policy_ks, &module)
        .await
        .expect("install policy");
}

/// Mint a `did:webvh` over the wire, as a caller would.
///
/// A DID mint needs a trust context to derive keys under, so we seed one — the
/// equivalent of the provisioning step a real deployment runs before any DID
/// exists. The `url` (with no `server_id`) selects the serverless path, so no
/// hosting server has to be reachable.
async fn create_did(router: &axum::Router, ctx: &TestAppContext, token: &str) -> (String, String) {
    vta_service::contexts::create_context(&ctx.contexts_ks, "default", "Default")
        .await
        .expect("seed the default context");

    let doc = envelope(
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0,
        "did:key:z6MkTestRequester",
        &ctx.vta_did,
        json!({ "contextId": "default", "url": "https://example.com/acme" }),
    );
    let (status, v) = post(router, token, &doc).await;
    assert_eq!(status, StatusCode::OK, "create a DID to update: {v}");
    let did = v["payload"]["did"].as_str().expect("did").to_string();
    let scid = v["payload"]["scid"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    (did, scid)
}
