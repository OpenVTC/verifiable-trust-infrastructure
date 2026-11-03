//! The engine end to end, through the slice's own handlers, against an in-process community
//! (`vti_vetting_pcs::vtc::Vtc`): two vetters enrol and draw tokens, each attests for an
//! applicant, the applicant takes both in and proves, and the community admits — with every PCS
//! key held by the VTA and none crossing the wire.

use super::*;
use crate::acl::Role;
use crate::test_support::build_signing_test_app_state;
use trust_tasks_rs::TypeUri;
use vta_sdk::trust_tasks as uris;
use vti_vetting_pcs::{
    issuer::{RootRequestWire, TokenBatchRequestWire},
    rand::{SeedableRng, rngs::StdRng},
    scheme::{enc, key_text, point_from_text},
    vtc::Vtc,
    wire::{SUITE, SubmissionWire},
};

const COMMUNITY: &str = "did:webvh:QmCommunity:vtc.example.org";

fn claims(did: &str, role: Role, ctx: &str) -> AuthClaims {
    AuthClaims {
        did: did.to_string(),
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
    let uri: TypeUri = uri.parse().expect("pcs uri");
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

fn requirements() -> Value {
    json!({
        "version": "0.1",
        "statementType": vta_sdk::protocols::vetting::VETTED_PREDICATE,
        "minStatements": 2,
        "acceptedMethods": ["inPerson", "video"],
        "requiredClaims": ["name.legal"],
        "eligibleVetters": { "role": "vetter" }
    })
}

/// The parameters exactly as the community's manifest publishes them.
fn published(vtc: &Vtc) -> Value {
    json!({
        "suite": SUITE,
        "helperKey": key_text(vtc.hvk()).unwrap(),
        "tokenKey": key_text(vtc.tvk()).unwrap(),
        "vetterLabels": vtc.live_periods().iter().map(|p| format!("vetter/{p}")).collect::<Vec<_>>(),
        "tokenLabels": [vtc.current_token_label()],
        "dripPerTick": vtc.drip_rate(),
        "tickLength": "P3D",
        "events": [],
    })
}

fn meta(vtc: &Vtc, card: &str) -> Value {
    let today = chrono::Utc::now().date_naive();
    json!({
        "community": COMMUNITY,
        "requirementsDigest": vtc.requirements_digest(),
        "method": "inPerson",
        "claimsVerified": ["name.legal"],
        "livenessConfirmed": true,
        "declaredRelationship": "none",
        "identityCommitment": "zCommitment",
        "cardDigestMultibase": card,
        "validFrom": today.to_string(),
        "validUntil": (today + chrono::Duration::days(90)).to_string(),
    })
}

/// A vetter in its own context: enrolled with the community, holding one tick of tokens.
async fn enrolled_vetter(
    state: &AppState,
    vtc: &mut Vtc,
    rng: &mut StdRng,
    ctx: &str,
    member: &str,
) -> AuthClaims {
    crate::contexts::create_context(&state.contexts_ks, ctx, ctx)
        .await
        .expect("create the vetter's context");
    vtc.grant(member);
    let auth = claims(member, Role::Admin, ctx);
    let params = published(vtc);

    let label = format!("vetter/{}", vtc.current_period());
    let out = handle_root_request(
        state,
        &auth,
        doc(
            uris::TASK_VTA_PCS_ROOT_REQUEST_0_1,
            json!({ "contextId": ctx, "community": COMMUNITY, "memberDid": member,
                    "parameters": params, "label": label }),
        ),
    )
    .await;
    let wire: RootRequestWire = serde_json::from_value(ok(&out)["request"].clone()).unwrap();
    let request = serde_json::from_value(wire.request.clone()).unwrap();
    let pre = vtc
        .issue_vetter_root(member, &point_from_text(&wire.id).unwrap(), &request, rng)
        .expect("the community signs the blinded request");
    let out = handle_root_accept(
        state,
        &auth,
        doc(
            uris::TASK_VTA_PCS_ROOT_ACCEPT_0_1,
            json!({ "contextId": ctx, "community": COMMUNITY, "parameters": params,
                    "response": { "label": label, "preCredential": enc(&pre).unwrap() } }),
        ),
    )
    .await;
    assert_eq!(ok(&out)["vetter"]["enrolledLabels"], json!([label]));

    let token_label = vtc.current_token_label().to_string();
    let out = handle_tokens_request(
        state,
        &auth,
        doc(
            uris::TASK_VTA_PCS_TOKENS_REQUEST_0_1,
            json!({ "contextId": ctx, "community": COMMUNITY, "parameters": params,
                    "label": token_label, "tick": 1, "count": vtc.drip_rate() }),
        ),
    )
    .await;
    let batch: TokenBatchRequestWire = serde_json::from_value(ok(&out)["request"].clone()).unwrap();
    let requests: Vec<_> = batch
        .requests
        .iter()
        .map(|r| r.to_request().unwrap())
        .collect();
    let pres = vtc
        .drip(member, 1, &token_label, &requests, rng)
        .expect("the community serves the draw");
    let pre_credentials: Vec<String> = pres.iter().map(|p| enc(p).unwrap()).collect();
    let out = handle_tokens_accept(
        state,
        &auth,
        doc(
            uris::TASK_VTA_PCS_TOKENS_ACCEPT_0_1,
            json!({ "contextId": ctx, "community": COMMUNITY, "parameters": params,
                    "response": { "label": token_label, "tick": 1, "preCredentials": pre_credentials } }),
        ),
    )
    .await;
    let accepted = ok(&out);
    assert_eq!(accepted["received"], json!(vtc.drip_rate()));
    assert_eq!(accepted["vetter"]["drawsInFlight"], json!([]));
    auth
}

async fn application_for(state: &AppState, carol: &AuthClaims, params: &Value) -> Value {
    crate::contexts::create_context(&state.contexts_ks, "applicant", "applicant")
        .await
        .unwrap();
    let out = handle_applications_create(
        state,
        carol,
        doc(
            uris::TASK_VTA_PCS_APPLICATIONS_CREATE_0_1,
            json!({ "contextId": "applicant", "community": COMMUNITY,
                    "joinDid": "did:key:z6MkCarolJoin", "parameters": params }),
        ),
    )
    .await;
    ok(&out)["application"].clone()
}

#[tokio::test]
async fn two_hidden_vetters_and_an_applicant_get_admitted_with_every_key_in_the_vta() {
    let (state, _dir) = build_signing_test_app_state().await;
    let mut rng = StdRng::seed_from_u64(0xC7);
    let mut vtc = Vtc::new(COMMUNITY, "2026-10", requirements(), &mut rng).unwrap();
    let params = published(&vtc);

    let alice = enrolled_vetter(&state, &mut vtc, &mut rng, "vetter-a", "did:key:z6MkAlice").await;
    let bob = enrolled_vetter(&state, &mut vtc, &mut rng, "vetter-b", "did:key:z6MkBob").await;

    let carol = claims("did:key:z6MkCarol", Role::Initiator, "applicant");
    let application = application_for(&state, &carol, &params).await;
    let app_id = application["applicationId"].as_str().unwrap().to_string();
    let applicant_id = application["id"].as_str().unwrap().to_string();

    for (vetter, ctx, card) in [(&alice, "vetter-a", "zCardA"), (&bob, "vetter-b", "zCardB")] {
        let out = handle_attest(
            &state,
            vetter,
            doc(
                uris::TASK_VTA_PCS_ATTEST_0_1,
                json!({ "contextId": ctx, "community": COMMUNITY, "parameters": params,
                        "applicantId": applicant_id, "meta": meta(&vtc, card) }),
            ),
        )
        .await;
        let attestation = ok(&out)["attestation"].clone();
        let out = handle_verify_attestation(
            &state,
            &carol,
            doc(
                uris::TASK_VTA_PCS_VERIFY_ATTESTATION_0_1,
                json!({ "applicationId": app_id, "parameters": params, "attestation": attestation }),
            ),
        )
        .await;
        ok(&out);
    }

    let challenge = vtc.challenge(&mut rng);
    let out = handle_prove(
        &state,
        &carol,
        doc(
            uris::TASK_VTA_PCS_PROVE_0_1,
            json!({ "applicationId": app_id, "parameters": params,
                    "requirementsDigest": vtc.requirements_digest(), "challenge": challenge }),
        ),
    )
    .await;
    let proof = ok(&out)["hiddenVetting"].clone();
    let wire: SubmissionWire = serde_json::from_value(proof).unwrap();
    let decision = vtc
        .submit(&wire.to_submission().unwrap(), chrono::Utc::now())
        .expect("the community verifies the proof");
    assert!(
        decision.evaluation.satisfied(),
        "two distinct hidden vetters satisfy the criterion: {:?}",
        decision.evaluation.needs
    );

    // The vetter's own view after attesting: one token spent, the attestation logged.
    let out = handle_vetter_show(
        &state,
        &alice,
        doc(
            uris::TASK_VTA_PCS_VETTER_SHOW_0_1,
            json!({ "contextId": "vetter-a", "community": COMMUNITY }),
        ),
    )
    .await;
    let vetter = ok(&out)["vetter"].clone();
    assert_eq!(vetter["attested"], json!(1));
    assert_eq!(vetter["tokensHeld"], json!(vtc.drip_rate() - 1));
}

#[tokio::test]
async fn a_caller_without_the_capability_is_refused_before_anything_is_read() {
    let (state, _dir) = build_signing_test_app_state().await;
    let reader = claims("did:key:z6MkReader", Role::Reader, "acme");
    let agent = claims("did:key:z6MkAgent", Role::Application, "acme");
    for auth in [&reader, &agent] {
        let out = handle_vetter_show(
            &state,
            auth,
            doc(
                uris::TASK_VTA_PCS_VETTER_SHOW_0_1,
                json!({ "contextId": "acme", "community": COMMUNITY }),
            ),
        )
        .await;
        assert_eq!(code(&out), "permissionDenied", "{}", body(&out));
        let out = handle_applications_show(
            &state,
            auth,
            doc(
                uris::TASK_VTA_PCS_APPLICATIONS_SHOW_0_1,
                json!({ "applicationId": "anything" }),
            ),
        )
        .await;
        assert_eq!(code(&out), "permissionDenied", "{}", body(&out));
    }
}

#[tokio::test]
async fn the_engine_refuses_with_the_codes_its_specifications_declare() {
    let (state, _dir) = build_signing_test_app_state().await;
    let mut rng = StdRng::seed_from_u64(0xC8);
    let mut vtc = Vtc::new(COMMUNITY, "2026-10", requirements(), &mut rng).unwrap();
    let params = published(&vtc);
    let alice = enrolled_vetter(&state, &mut vtc, &mut rng, "vetter-a", "did:key:z6MkAlice").await;

    // One key per (context, community): a second member DID is refused.
    let out = handle_root_request(
        &state,
        &alice,
        doc(
            uris::TASK_VTA_PCS_ROOT_REQUEST_0_1,
            json!({ "contextId": "vetter-a", "community": COMMUNITY,
                    "memberDid": "did:key:z6MkMallory", "parameters": params,
                    "label": format!("vetter/{}", vtc.current_period()) }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/root-request:memberMismatch");

    // A second draw of the same tick while one is in flight; abandoning clears it.
    let draw = json!({ "contextId": "vetter-a", "community": COMMUNITY, "parameters": params,
                       "label": vtc.current_token_label(), "tick": 2, "count": 1 });
    ok(&handle_tokens_request(
        &state,
        &alice,
        doc(uris::TASK_VTA_PCS_TOKENS_REQUEST_0_1, draw.clone()),
    )
    .await);
    let out = handle_tokens_request(
        &state,
        &alice,
        doc(uris::TASK_VTA_PCS_TOKENS_REQUEST_0_1, draw),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/tokens/request:alreadyInFlight");
    let abandon = json!({ "contextId": "vetter-a", "community": COMMUNITY,
                          "draw": { "label": vtc.current_token_label(), "tick": 2 } });
    ok(&handle_tokens_abandon(
        &state,
        &alice,
        doc(uris::TASK_VTA_PCS_TOKENS_ABANDON_0_1, abandon.clone()),
    )
    .await);
    let out = handle_tokens_abandon(
        &state,
        &alice,
        doc(uris::TASK_VTA_PCS_TOKENS_ABANDON_0_1, abandon),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/tokens/abandon:noDrawInFlight");

    // More than the community's drip.
    let greedy = json!({ "contextId": "vetter-a", "community": COMMUNITY, "parameters": params,
                         "label": vtc.current_token_label(), "tick": 3, "count": vtc.drip_rate() + 1 });
    let out = handle_tokens_request(
        &state,
        &alice,
        doc(uris::TASK_VTA_PCS_TOKENS_REQUEST_0_1, greedy),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/tokens/request:countExceedsDrip");

    // An application with nothing to prove.
    let carol = claims("did:key:z6MkCarol", Role::Initiator, "applicant");
    let application = application_for(&state, &carol, &params).await;
    let app_id = application["applicationId"].as_str().unwrap().to_string();
    let out = handle_prove(
        &state,
        &carol,
        doc(
            uris::TASK_VTA_PCS_PROVE_0_1,
            json!({ "applicationId": app_id, "parameters": params,
                    "requirementsDigest": vtc.requirements_digest(), "challenge": "zChallenge" }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/prove:noUsableAttestation");

    // An application in a context the caller cannot act in reads as absent.
    let out = handle_applications_show(
        &state,
        &alice,
        doc(
            uris::TASK_VTA_PCS_APPLICATIONS_SHOW_0_1,
            json!({ "applicationId": app_id }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/applications/show:notFound");

    // No vetter engine for a community never enrolled with.
    let out = handle_vetter_show(
        &state,
        &alice,
        doc(
            uris::TASK_VTA_PCS_VETTER_SHOW_0_1,
            json!({ "contextId": "vetter-a", "community": "did:example:elsewhere" }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/vetter/show:notFound");

    // A suite this build does not implement.
    let mut other = params.clone();
    other["suite"] = json!("bbs-2027");
    let out = handle_attest(
        &state,
        &alice,
        doc(
            uris::TASK_VTA_PCS_ATTEST_0_1,
            json!({ "contextId": "vetter-a", "community": COMMUNITY, "parameters": other,
                    "applicantId": application["id"], "meta": meta(&vtc, "zCardA") }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/attest:unsupportedSuite");

    // Deleting the application ends it.
    let del = json!({ "applicationId": app_id });
    ok(&handle_applications_delete(
        &state,
        &carol,
        doc(uris::TASK_VTA_PCS_APPLICATIONS_DELETE_0_1, del.clone()),
    )
    .await);
    let out = handle_applications_delete(
        &state,
        &carol,
        doc(uris::TASK_VTA_PCS_APPLICATIONS_DELETE_0_1, del),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/applications/delete:notFound");
}

// ─── vta/pcs/vetter/recover ──────────────────────────────────────────────────

fn recover(ctx: &str, member: &str, bound_id: &str) -> TrustTask<Value> {
    doc(
        uris::TASK_VTA_PCS_VETTER_RECOVER_0_1,
        json!({ "contextId": ctx, "community": COMMUNITY, "memberDid": member, "boundId": bound_id }),
    )
}

/// Lose the engine record and its state, as a re-created engine or a restore without them
/// would: the seed, and the path counter, survive.
async fn lose_vetter_record(state: &AppState, ctx: &str) {
    let key = crate::operations::pcs::vetter_key(ctx, COMMUNITY);
    vta_keys::imported::delete_secret(&state.pcs_engine_ks, &key)
        .await
        .unwrap();
    state.pcs_engine_ks.remove(key).await.unwrap();
}

/// A blinded root request for the vetter's current key, and the identifier it carries.
async fn root_request_id(
    state: &AppState,
    auth: &AuthClaims,
    ctx: &str,
    params: &Value,
    label: &str,
) -> (RootRequestWire, String) {
    let out = handle_root_request(
        state,
        auth,
        doc(
            uris::TASK_VTA_PCS_ROOT_REQUEST_0_1,
            json!({ "contextId": ctx, "community": COMMUNITY, "memberDid": auth.did,
                    "parameters": params, "label": label }),
        ),
    )
    .await;
    let wire: RootRequestWire = serde_json::from_value(ok(&out)["request"].clone()).unwrap();
    let id = wire.id.clone();
    (wire, id)
}

/// Hand out `n` more paths from the context's counter, as key creation would.
async fn burn_paths(state: &AppState, ctx: &str, n: usize) {
    let base = crate::contexts::get_context(&state.contexts_ks, ctx)
        .await
        .unwrap()
        .unwrap()
        .base_path;
    for _ in 0..n {
        vta_keys::paths::allocate_path(&state.keys_ks, &base)
            .await
            .unwrap();
    }
}

/// A valid PCS identifier no key of this VTA has.
fn stranger_id() -> String {
    let (id, _) = vti_vetting_pcs::scheme::member_key_from_seed(COMMUNITY, &[0x5A; 32]).unwrap();
    vti_vetting_pcs::scheme::point_text(&id).unwrap()
}

/// The whole recovery: the vetter enrols, its engine record is lost and the seed rotated, a new
/// root request makes a key the community refuses as a rebind, and recovering with the bound
/// identifier restores the original key — found under the retired seed generation — so the
/// next enrolment carries it and the community accepts it.
#[tokio::test]
async fn recover_restores_the_bound_key_after_the_engine_record_was_lost() {
    let (state, _dir) = build_signing_test_app_state().await;
    let mut rng = StdRng::seed_from_u64(0xC9);
    let mut vtc = Vtc::new(COMMUNITY, "2026-10", requirements(), &mut rng).unwrap();
    let member = "did:key:z6MkAlice";
    let alice = enrolled_vetter(&state, &mut vtc, &mut rng, "vetter-a", member).await;
    let bound = handle_vetter_show(
        &state,
        &alice,
        doc(
            uris::TASK_VTA_PCS_VETTER_SHOW_0_1,
            json!({ "contextId": "vetter-a", "community": COMMUNITY }),
        ),
    )
    .await;
    let bound_id = ok(&bound)["vetter"]["id"].as_str().unwrap().to_string();

    // Keys created after the vetter's, in the same context: more candidates for the search.
    burn_paths(&state, "vetter-a", 3).await;

    lose_vetter_record(&state, "vetter-a").await;
    vta_keys::seeds::rotate_seed(&state.keys_ks, &*state.seed_store, None)
        .await
        .expect("rotate the seed");

    // The next root request makes a fresh key, which the community refuses as a rebind.
    vtc.rotate("2026-11").unwrap();
    let params = published(&vtc);
    let label = "vetter/2026-11";
    let (wire, fresh_id) = root_request_id(&state, &alice, "vetter-a", &params, label).await;
    assert_ne!(fresh_id, bound_id, "a lost record means a fresh key");
    let request = serde_json::from_value(wire.request.clone()).unwrap();
    let refused = vtc.issue_vetter_root(
        member,
        &point_from_text(&fresh_id).unwrap(),
        &request,
        &mut rng,
    );
    assert!(
        matches!(
            refused,
            Err(vti_vetting_pcs::ProtoError::IdentifierRebound(_))
        ),
        "the community refuses the fresh key"
    );

    // Recover: the engine holds only an enrolment in flight, so its key can be replaced.
    let out = handle_vetter_recover(&state, &alice, recover("vetter-a", member, &bound_id)).await;
    let recovered = ok(&out);
    assert_eq!(recovered["recovered"], json!(true));
    assert_eq!(recovered["vetter"]["id"], json!(bound_id));
    assert_eq!(recovered["vetter"]["pendingLabels"], json!([]));
    assert_eq!(recovered["vetter"]["enrolledLabels"], json!([]));

    // The recovery is audited without the identifier.
    let rows = state.audit_ks.prefix_iter_raw("").await.unwrap();
    let text: String = rows
        .iter()
        .map(|(_, v)| String::from_utf8_lossy(v).to_string())
        .collect();
    assert!(text.contains("pcs.vetter.recover"));
    assert!(text.contains("key.pcs_search"));
    assert!(
        !text.contains(&bound_id),
        "no audit row names the identifier"
    );

    // A second recovery changes nothing.
    let out = handle_vetter_recover(&state, &alice, recover("vetter-a", member, &bound_id)).await;
    assert_eq!(ok(&out)["recovered"], json!(false));

    // The next enrolment carries the bound key, and the community takes it.
    let (wire, id) = root_request_id(&state, &alice, "vetter-a", &params, label).await;
    assert_eq!(id, bound_id);
    let request = serde_json::from_value(wire.request.clone()).unwrap();
    let pre = vtc
        .issue_vetter_root(member, &point_from_text(&id).unwrap(), &request, &mut rng)
        .expect("the community accepts the bound key");
    let out = handle_root_accept(
        &state,
        &alice,
        doc(
            uris::TASK_VTA_PCS_ROOT_ACCEPT_0_1,
            json!({ "contextId": "vetter-a", "community": COMMUNITY, "parameters": params,
                    "response": { "label": label, "preCredential": enc(&pre).unwrap() } }),
        ),
    )
    .await;
    assert_eq!(ok(&out)["vetter"]["enrolledLabels"], json!([label]));
}

#[tokio::test]
async fn recover_refuses_with_the_codes_its_specification_declares() {
    let (state, _dir) = build_signing_test_app_state().await;
    let mut rng = StdRng::seed_from_u64(0xCA);
    let mut vtc = Vtc::new(COMMUNITY, "2026-10", requirements(), &mut rng).unwrap();
    let alice_did = "did:key:z6MkAlice";
    let bob_did = "did:key:z6MkBob";
    let alice = enrolled_vetter(&state, &mut vtc, &mut rng, "vetter-a", alice_did).await;
    let _bob = enrolled_vetter(&state, &mut vtc, &mut rng, "vetter-b", bob_did).await;
    let show = |ctx: &str| {
        doc(
            uris::TASK_VTA_PCS_VETTER_SHOW_0_1,
            json!({ "contextId": ctx, "community": COMMUNITY }),
        )
    };
    let bob_id = {
        let bob = claims(bob_did, Role::Admin, "vetter-b");
        ok(&handle_vetter_show(&state, &bob, show("vetter-b")).await)["vetter"]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };

    // Another member DID for an existing engine.
    let out = handle_vetter_recover(
        &state,
        &alice,
        recover("vetter-a", "did:key:z6MkMallory", &bob_id),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/vetter/recover:memberMismatch");

    // Alice's key holds a class credential and tokens: it is never replaced.
    let out = handle_vetter_recover(
        &state,
        &alice,
        recover("vetter-a", alice_did, &stranger_id()),
    )
    .await;
    assert_eq!(code(&out), "vta/pcs/vetter/recover:engineEnrolled");

    // A fresh context with no engine, keys of its own, and a caller who stands only there.
    crate::contexts::create_context(&state.contexts_ks, "vetter-c", "vetter-c")
        .await
        .unwrap();
    burn_paths(&state, "vetter-c", 3).await;
    let only_c = claims(bob_did, Role::Admin, "vetter-c");

    // An identifier no key of the context has.
    let out = handle_vetter_recover(
        &state,
        &only_c,
        recover("vetter-c", bob_did, &stranger_id()),
    )
    .await;
    assert_eq!(
        code(&out),
        "vta/pcs/vetter/recover:notFound",
        "{}",
        body(&out)
    );
    // A string the schema admits that is no identifier at all.
    let out = handle_vetter_recover(&state, &only_c, recover("vetter-c", bob_did, "z1111")).await;
    assert_eq!(
        code(&out),
        "vta/pcs/vetter/recover:notFound",
        "{}",
        body(&out)
    );

    // Bob's key is derivable by this VTA, but from vetter-b's base: a search in vetter-c never
    // reaches it, and a caller with no standing over vetter-b is not told where it is.
    let out = handle_vetter_recover(&state, &only_c, recover("vetter-c", bob_did, &bob_id)).await;
    assert_eq!(
        code(&out),
        "vta/pcs/vetter/recover:notFound",
        "{}",
        body(&out)
    );
    assert!(!body(&out).to_string().contains("vetter-b"));

    // A caller who stands over both is sent to the context that holds it.
    let mut both = claims(bob_did, Role::Admin, "vetter-c");
    both.allowed_contexts.push("vetter-b".into());
    let out = handle_vetter_recover(&state, &both, recover("vetter-c", bob_did, &bob_id)).await;
    assert_eq!(
        code(&out),
        "vta/pcs/vetter/recover:heldInAnotherContext",
        "{}",
        body(&out)
    );
    assert!(body(&out).to_string().contains("vetter-b"));

    // Nothing was created by the refusals.
    let out = handle_vetter_show(&state, &only_c, show("vetter-c")).await;
    assert_eq!(code(&out), "vta/pcs/vetter/show:notFound");
}

/// A key another engine holds is set aside, even when it is the one named: an applicant's key
/// never becomes a vetter's.
#[tokio::test]
async fn recover_never_hands_another_engines_key_to_the_vetter() {
    let (state, _dir) = build_signing_test_app_state().await;
    let mut rng = StdRng::seed_from_u64(0xCB);
    let vtc = Vtc::new(COMMUNITY, "2026-10", requirements(), &mut rng).unwrap();
    let carol = claims("did:key:z6MkCarol", Role::Admin, "applicant");
    let application = application_for(&state, &carol, &published(&vtc)).await;
    let applicant_id = application["id"].as_str().unwrap().to_string();
    let out = handle_vetter_recover(
        &state,
        &carol,
        recover("applicant", "did:key:z6MkCarol", &applicant_id),
    )
    .await;
    assert_eq!(
        code(&out),
        "vta/pcs/vetter/recover:notFound",
        "{}",
        body(&out)
    );
}
