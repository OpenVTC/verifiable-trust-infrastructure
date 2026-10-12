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
