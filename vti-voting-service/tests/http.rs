//! The service over HTTP: signed requests in, signed answers out, a restart from the journal.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use trust_tasks_rs::TrustTask;
use uuid::Uuid;
use vti_voting::{
    election::{Election, ElectionId},
    rand::{SeedableRng, rngs::StdRng},
    registrar::Registrar,
    rules::{digest_multibase, manifest_digest},
    service::BallotBox,
    voter::Voter,
};
use vti_voting_service::{
    AppState, config::CommunitiesConfig, identity::Identity, journal::FileJournal, router,
};

fn state(dir: &std::path::Path) -> Arc<AppState> {
    state_serving(dir, CommunitiesConfig::any())
}

fn state_serving(dir: &std::path::Path, communities: CommunitiesConfig) -> Arc<AppState> {
    let identity = Identity::load_or_mint(dir).unwrap();
    let journal = Arc::new(FileJournal::open(&dir.join("journal")).unwrap());
    let restored = journal.load().unwrap();
    let bb = BallotBox::restore(&identity.did, journal, restored).unwrap();
    Arc::new(AppState::new(
        bb,
        identity,
        vti_common::auth::TrustTaskVmResolver::did_key_only(),
        communities,
    ))
}

/// A registration of `community`'s election `id` on the box `service_did`.
fn registration(community: &Identity, service_did: &str, id: &str) -> Value {
    let reg = Registrar::generate(&community.did, &mut StdRng::seed_from_u64(1)).unwrap();
    let now = Utc::now();
    let t = |d: chrono::DateTime<Utc>| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let manifest = json!({
        "electionId": id,
        "community": community.did,
        "questions": [{ "key": "chair", "type": "choice",
            "options": [{ "key": "ana" }, { "key": "bo" }],
            "minSelections": 1, "maxSelections": 1, "optional": false }],
        "secrecy": "open",
        "roll": { "rule": "members" },
        "registrationOpens": t(now - Duration::days(2)),
        "votingOpens": t(now - Duration::hours(1)),
        "votingCloses": t(now + Duration::days(1)),
        "revote": "replace",
        "board": { "visibility": "public", "auditors": [] },
        "ballotBox": service_did,
        "binding": false,
        "allowEarlyClose": false,
        "resultsBeforeClose": false,
        "textReleaseThreshold": 10
    });
    let digest = manifest_digest(&manifest).unwrap();
    json!({
        "community": community.did,
        "manifest": manifest,
        "manifestDigest": digest_multibase(&digest),
        "parameters": { "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() },
    })
}

/// A box registers the elections of the communities it serves, and no more of each at once
/// than its quota: a box anyone can register with is a store anyone can fill.
#[tokio::test]
async fn only_a_served_community_registers_and_within_its_quota() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let community = Identity::from_seed(&[0x31; 32]).unwrap();
    let svc = state_serving(
        &dir,
        CommunitiesConfig {
            allowed: vec![community.did.clone()],
            max_unfinished: 1,
            ..Default::default()
        },
    );
    let box_did = svc.identity.did.clone();

    // A community the box does not serve, registering its own election.
    let stranger = Identity::from_seed(&[0x32; 32]).unwrap();
    let (status, answer) = send(
        &svc,
        doc(
            "election/register",
            &box_did,
            Some(&stranger),
            registration(&stranger, &box_did, "agm"),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(answer["payload"]["code"], "permissionDenied");

    // The community it serves: one election, and a repeat of it, but not a second.
    let first = registration(&community, &box_did, "agm");
    for _ in 0..2 {
        let (status, answer) = send(
            &svc,
            doc(
                "election/register",
                &box_did,
                Some(&community),
                first.clone(),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
    }
    let (status, answer) = send(
        &svc,
        doc(
            "election/register",
            &box_did,
            Some(&community),
            registration(&community, &box_did, "egm"),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    assert_eq!(answer["payload"]["code"], "unavailable");
}

async fn send(state: &Arc<AppState>, doc: Value) -> (StatusCode, Value) {
    let res = router(state.clone())
        .oneshot(
            Request::post("/trust-tasks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&doc).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// A request document, signed by `signer` when given.
async fn doc(task: &str, to: &str, signer: Option<&Identity>, payload: Value) -> Value {
    let mut d = json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": format!("https://trusttasks.org/spec/voting/{task}/0.1#request"),
        "recipient": to,
        "issuedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    });
    if let Some(s) = signer {
        d["issuer"] = json!(s.did);
        let mut typed: TrustTask<Value> = serde_json::from_value(d).unwrap();
        vta_sdk::trust_task_sign::sign_in_place_with(&mut typed, &s.key)
            .await
            .unwrap();
        return serde_json::to_value(&typed).unwrap();
    }
    d
}

async fn signed_by(answer: &Value) -> String {
    vti_common::auth::verify_trust_task_proof_value(
        answer,
        &vti_common::auth::TrustTaskVmResolver::did_key_only(),
    )
    .await
    .expect("every answer is signed")
}

#[tokio::test]
async fn an_election_over_http_with_a_restart() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let svc = state(&dir);
    let service_did = svc.identity.did.clone();

    let community = Identity::from_seed(&[7; 32]).unwrap();
    let reg = Registrar::generate(&community.did, &mut StdRng::seed_from_u64(1)).unwrap();
    let now = Utc::now();
    let manifest = json!({
        "electionId": "board-2027",
        "community": community.did,
        "questions": [{ "key": "chair", "type": "choice",
            "options": [{ "key": "ana" }, { "key": "bo" }],
            "minSelections": 1, "maxSelections": 1, "optional": false }],
        "secrecy": "open",
        "roll": { "rule": "members" },
        "registrationOpens": (now - Duration::days(2)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "votingOpens": (now - Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "votingCloses": (now + Duration::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "revote": "replace",
        "board": { "visibility": "public", "auditors": [] },
        "ballotBox": service_did,
        "binding": false,
        "allowEarlyClose": false,
        "resultsBeforeClose": false,
        "textReleaseThreshold": 10
    });
    let digest = manifest_digest(&manifest).unwrap();
    let register = json!({
        "community": community.did,
        "manifest": manifest,
        "manifestDigest": digest_multibase(&digest),
        "parameters": { "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() },
    });

    // Unsigned registration: refused, and the refusal is signed too.
    let (status, answer) = send(
        &svc,
        doc("election/register", &service_did, None, register.clone()).await,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer["payload"]["code"], "proofRequired");
    assert_eq!(signed_by(&answer).await, service_did);

    // Signed by somebody else: permission denied.
    let stranger = Identity::from_seed(&[8; 32]).unwrap();
    let (status, answer) = send(
        &svc,
        doc(
            "election/register",
            &service_did,
            Some(&stranger),
            register.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(answer["payload"]["code"], "permissionDenied");

    let (status, answer) = send(
        &svc,
        doc(
            "election/register",
            &service_did,
            Some(&community),
            register,
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["payload"]["election"]["state"], "voting");
    assert_eq!(signed_by(&answer).await, service_did);

    // A voter: ticket from the registrar, cast from a one-time key.
    let params = reg.params();
    let election = Election::new(
        &community.did,
        ElectionId::new("board-2027").unwrap(),
        digest,
    )
    .unwrap();
    let mut r = StdRng::seed_from_u64(3);
    let voter = Voter::generate(&params, &mut r).unwrap();
    let (req, st) = voter.ticket_request(&params, &election, &mut r).unwrap();
    let pre = reg
        .issue_ticket(&election, voter.id(), &req, &mut r)
        .unwrap();
    let ticket = voter.accept_ticket(&params, &election, &pre, &st).unwrap();
    let ballot = json!({
        "electionId": "board-2027",
        "manifestDigest": digest_multibase(&digest),
        "answers": [{ "question": "chair", "choice": ["ana"] }],
    });
    let cast = voter.cast_wire(&params, &ticket, &ballot, &mut r).unwrap();
    let one_time = Identity::from_seed(&[9; 32]).unwrap();
    let cast_doc = doc(
        "ballot/cast",
        &service_did,
        Some(&one_time),
        json!({ "community": community.did, "electionId": "board-2027", "cast": cast }),
    )
    .await;
    let (status, receipt) = send(&svc, cast_doc.clone()).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["payload"]["outcome"], "counted");
    assert_eq!(receipt["recipient"], one_time.did);
    assert_eq!(
        signed_by(&receipt).await,
        service_did,
        "the receipt is signed"
    );

    // A task-specific refusal carries its slug.
    let mut bad = cast.clone();
    bad["ballot"]["answers"][0]["choice"] = json!(["bo"]);
    let (status, answer) = send(
        &svc,
        doc(
            "ballot/cast",
            &service_did,
            Some(&one_time),
            json!({ "community": community.did, "electionId": "board-2027", "cast": bad }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(answer["payload"]["code"], "voting/ballot/cast:castInvalid");

    // An anonymous head read of a public board.
    let sel = json!({ "community": community.did, "electionId": "board-2027" });
    let (_, head) = send(
        &svc,
        doc("board/head", &service_did, None, sel.clone()).await,
    )
    .await;
    assert_eq!(head["payload"]["head"]["treeSize"], 2);

    // Restart: a new service over the same data directory has the same board and the same
    // identity, and answers a resend with the first receipt.
    drop(svc);
    let restarted = state(&dir);
    assert_eq!(restarted.identity.did, service_did);
    let (_, head2) = send(&restarted, doc("board/head", &service_did, None, sel).await).await;
    assert_eq!(
        head2["payload"]["head"]["rootHash"],
        head["payload"]["head"]["rootHash"]
    );
    let (_, again) = send(&restarted, cast_doc).await;
    assert_eq!(again["payload"]["outcome"], "alreadyCounted");
    assert_eq!(
        again["payload"]["receiptToken"],
        receipt["payload"]["receiptToken"]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Over TSP or DIDComm the transport proves the sender, and the document's issuer must be it: a
/// party cannot relay another's request as its own (framework §7.2 item 6).
#[tokio::test]
async fn over_messaging_the_issuer_must_be_the_proven_sender() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let st = state(&dir);
    let community = Identity::from_seed(&[7u8; 32]).unwrap();
    let request = doc(
        "board/head",
        &st.identity.did,
        Some(&community),
        json!({ "community": community.did, "electionId": "e1" }),
    )
    .await;
    let bytes = serde_json::to_vec(&request).unwrap();

    let relayed =
        vti_voting_service::dispatch::answer(&st, &bytes, Some("did:key:z6MkOther")).await;
    let refused = relayed.doc.expect("a refusal is answered");
    assert_eq!(refused["payload"]["code"], "permissionDenied", "{refused}");
    signed_by(&refused).await;

    let direct = vti_voting_service::dispatch::answer(&st, &bytes, Some(&community.did)).await;
    let answered = direct.doc.expect("answered");
    assert_ne!(
        answered["payload"]["code"], "permissionDenied",
        "{answered}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A reply or an error is never answered: over messaging, an error answering an error is a loop.
#[tokio::test]
async fn a_reply_is_never_answered() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let st = state(&dir);
    for type_uri in [
        "https://trusttasks.org/spec/voting/board/head/0.1#response",
        "https://trusttasks.org/spec/trust-task-error/0.1",
    ] {
        let reply = json!({
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "type": type_uri,
            "issuer": "did:key:z6MkOther",
            "recipient": st.identity.did,
            "issuedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": {},
        });
        let bytes = serde_json::to_vec(&reply).unwrap();
        let out =
            vti_voting_service::dispatch::answer(&st, &bytes, Some("did:key:z6MkOther")).await;
        assert!(out.doc.is_none(), "{type_uri} was answered");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A sealed election's trustees enrol over the service: only the trustee the manifest names at
/// an index enrols as it, and only signed.
#[tokio::test]
async fn trustees_enrol_over_http() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let svc = state(&dir);
    let service_did = svc.identity.did.clone();
    let community = Identity::from_seed(&[5; 32]).unwrap();
    let trustees: Vec<Identity> = (1..=3u8)
        .map(|i| Identity::from_seed(&[20 + i; 32]).unwrap())
        .collect();
    let reg = Registrar::generate(&community.did, &mut StdRng::seed_from_u64(2)).unwrap();
    let now = Utc::now();
    let manifest = json!({
        "electionId": "sealed-2027",
        "community": community.did,
        "questions": [{ "key": "chair", "type": "choice",
            "options": [{ "key": "ana" }, { "key": "bo" }],
            "minSelections": 1, "maxSelections": 1, "optional": false }],
        "secrecy": "sealed",
        "trustees": { "dids": trustees.iter().map(|t| t.did.clone()).collect::<Vec<_>>(), "threshold": 2 },
        "roll": { "rule": "members" },
        "registrationOpens": (now - Duration::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "votingOpens": (now + Duration::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "votingCloses": (now + Duration::days(2)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "revote": "replace",
        "board": { "visibility": "public", "auditors": [] },
        "ballotBox": service_did,
        "binding": false,
        "allowEarlyClose": false,
        "resultsBeforeClose": false,
        "textReleaseThreshold": 10
    });
    let digest = manifest_digest(&manifest).unwrap();
    let register = json!({
        "community": community.did,
        "manifest": manifest,
        "manifestDigest": digest_multibase(&digest),
        "parameters": { "suite": "ps-ddh-bls12381", "votingKey": reg.public_text().unwrap() },
    });
    let (status, _) = send(
        &svc,
        doc(
            "election/register",
            &service_did,
            Some(&community),
            register,
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let ctx = Election::new(
        &community.did,
        ElectionId::new("sealed-2027").unwrap(),
        digest,
    )
    .unwrap()
    .trustee_context();
    let tk = vti_voting::trustees::TransportSecret::generate(1, &mut StdRng::seed_from_u64(3))
        .publish(&ctx, &mut StdRng::seed_from_u64(4));
    let enrol = json!({
        "community": community.did,
        "electionId": "sealed-2027",
        "transportKey": vti_voting::wire::transport_key_value(&tk),
    });
    let (status, answer) = send(
        &svc,
        doc("trustees/enrol", &service_did, None, enrol.clone()).await,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");
    let (status, answer) = send(
        &svc,
        doc(
            "trustees/enrol",
            &service_did,
            Some(&trustees[1]),
            enrol.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    let (status, answer) = send(
        &svc,
        doc("trustees/enrol", &service_did, Some(&trustees[0]), enrol).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["payload"]["phase"], "enrolling");
    assert_eq!(signed_by(&answer).await, service_did);

    let (status, answer) = send(
        &svc,
        doc(
            "trustees/status",
            &service_did,
            None,
            json!({ "community": community.did, "electionId": "sealed-2027" }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["payload"]["transportKeys"][0]["trustee"], 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The `#request` fragment is optional: a peer sending through the generated payload types uses
/// the bare type URI, and is served the same.
#[tokio::test]
async fn a_bare_request_type_is_served() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let st = state(&dir);
    let community = Identity::from_seed(&[9u8; 32]).unwrap();
    let mut request = doc(
        "board/head",
        &st.identity.did,
        None,
        json!({ "community": community.did, "electionId": "e1" }),
    )
    .await;
    request["type"] = json!("https://trusttasks.org/spec/voting/board/head/0.1");
    let out =
        vti_voting_service::dispatch::answer(&st, &serde_json::to_vec(&request).unwrap(), None)
            .await;
    let answer = out.doc.expect("answered");
    assert_ne!(answer["payload"]["code"], "unsupportedType", "{answer}");
    let _ = std::fs::remove_dir_all(&dir);
}

async fn sign(d: Value, s: &Identity) -> Value {
    let mut typed: TrustTask<Value> = serde_json::from_value(d).unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut typed, &s.key)
        .await
        .unwrap();
    serde_json::to_value(&typed).unwrap()
}

/// What a signed request carries before its proof is checked: a recipient (a captured document
/// is no bearer token for another ballot box), `issuedAt` on a consequential task, and on a cast
/// a `did:key` signer, so an anonymous sender cannot have the service fetch a DID of its choosing
/// (VTI-VOT-003).
#[tokio::test]
async fn a_request_names_its_recipient_and_a_cast_its_did_key() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let st = state(&dir);
    let community = Identity::from_seed(&[11u8; 32]).unwrap();
    let payload = json!({ "community": community.did, "electionId": "e1" });

    let mut unaddressed = doc("election/close", &st.identity.did, None, payload.clone()).await;
    unaddressed.as_object_mut().unwrap().remove("recipient");
    unaddressed["issuer"] = json!(community.did);
    let (status, answer) = send(&st, sign(unaddressed, &community).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["payload"]["code"], "malformedRequest", "{answer}");

    let mut undated = doc("election/close", &st.identity.did, None, payload.clone()).await;
    undated.as_object_mut().unwrap().remove("issuedAt");
    undated["issuer"] = json!(community.did);
    let (status, answer) = send(&st, sign(undated, &community).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["payload"]["code"], "malformedRequest", "{answer}");

    let mut cast = doc("ballot/cast", &st.identity.did, Some(&community), payload).await;
    cast["issuer"] = json!("did:webvh:QmSomewhere:attacker.example");
    let (status, answer) = send(&st, cast).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");
    assert_eq!(answer["payload"]["code"], "proofInvalid", "{answer}");
    let _ = std::fs::remove_dir_all(&dir);
}
