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
        "registrationOpensAt": t(now - Duration::days(2)),
        "votingOpensAt": t(now - Duration::hours(1)),
        "votingClosesAt": t(now + Duration::days(1)),
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

/// The box serves `voting/election/{register,show}` at 0.3 and 0.2 and `voting/board/read` at
/// 0.2 — the manifest and the lifecycle entries name their instants `…At` (voting/_shared/0.2
/// and later) — and says so to a 0.1 request rather than reading one it cannot.
#[tokio::test]
async fn a_0_1_registration_show_or_board_read_is_unsupported_version() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let community = Identity::from_seed(&[0x33; 32]).unwrap();
    let svc = state_serving(
        &dir,
        CommunitiesConfig {
            allowed: vec![community.did.clone()],
            ..Default::default()
        },
    );
    let box_did = svc.identity.did.clone();
    for (task, payload) in [
        (
            "election/register",
            registration(&community, &box_did, "agm"),
        ),
        (
            "election/show",
            json!({ "community": community.did, "electionId": "agm" }),
        ),
        (
            "board/read",
            json!({ "community": community.did, "electionId": "agm", "from": 0, "limit": 1 }),
        ),
    ] {
        let mut d = doc(task, &box_did, None, payload).await;
        d["type"] = json!(format!(
            "https://trusttasks.org/spec/voting/{task}/0.1#request"
        ));
        d["issuer"] = json!(community.did);
        let mut typed: TrustTask<Value> = serde_json::from_value(d).unwrap();
        vta_sdk::trust_task_sign::sign_in_place_with(&mut typed, &community.key)
            .await
            .unwrap();
        let (status, answer) = send(&svc, serde_json::to_value(&typed).unwrap()).await;
        assert_ne!(status, StatusCode::OK, "{answer}");
        assert_eq!(
            answer["payload"]["code"], "unsupportedVersion",
            "{task}: {answer}"
        );
    }
}

/// VTI-VOT-065: the box registers and shows a `textReleaseThreshold` of 1 – 9 at
/// `voting/election/{register,show}/0.3`, and never refuses one there. Under 0.2, whose schema
/// says 10, such a registration is malformed and such an election is not shown — 0.2 is
/// refused `unsupportedVersion` for it — while one of 10 or more is served at both versions.
#[tokio::test]
async fn vti_vot_065_a_threshold_below_ten_is_registered_and_shown_at_0_3_only() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let community = Identity::from_seed(&[0x34; 32]).unwrap();
    let svc = state(&dir);
    let box_did = svc.identity.did.clone();

    let low = |id: &str| {
        let mut r = registration(&community, &box_did, id);
        r["manifest"]["textReleaseThreshold"] = json!(3);
        let digest = manifest_digest(&r["manifest"]).unwrap();
        r["manifestDigest"] = json!(digest_multibase(&digest));
        r
    };
    let register_at = |version: &'static str, payload: Value| {
        let box_did = box_did.clone();
        let community = &community;
        async move {
            doc_at(
                "election/register",
                version,
                &box_did,
                Some(community),
                payload,
            )
            .await
        }
    };

    let (status, answer) = send(&svc, register_at("0.2", low("small")).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["payload"]["code"], "malformedRequest");

    let (status, answer) = send(&svc, register_at("0.3", low("small")).await).await;
    assert_eq!(status, StatusCode::OK, "{answer}");

    let show = |version: &'static str, id: &str| {
        let payload = json!({ "community": community.did, "electionId": id });
        let box_did = box_did.clone();
        async move { doc_at("election/show", version, &box_did, None, payload).await }
    };
    let (status, answer) = send(&svc, show("0.3", "small").await).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["payload"]["manifest"]["textReleaseThreshold"], 3);
    let (status, answer) = send(&svc, show("0.2", "small").await).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer["payload"]["code"], "unsupportedVersion");

    // Ten or more: registered under 0.2, as a community from before 0.3 sends it, and shown
    // at either version.
    let usual = registration(&community, &box_did, "usual");
    let (status, answer) = send(&svc, register_at("0.2", usual).await).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    for version in ["0.2", "0.3"] {
        let (status, answer) = send(&svc, show(version, "usual").await).await;
        assert_eq!(status, StatusCode::OK, "{version}: {answer}");
        assert_eq!(answer["payload"]["manifest"]["textReleaseThreshold"], 10);
    }
}

/// VTI-VOT-025: the box registers and shows an election under a credential roll at
/// `voting/election/{register,show}/0.4` only. Under 0.3 and 0.2, whose manifest has no
/// `credential` rule, such a registration is malformed and such an election is not shown —
/// those versions are refused `unsupportedVersion` for it — while a members roll registered at
/// 0.4 is still shown at every version.
#[tokio::test]
async fn vti_vot_025_a_credential_roll_is_registered_and_shown_at_0_4_only() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let community = Identity::from_seed(&[0x35; 32]).unwrap();
    let svc = state(&dir);
    let box_did = svc.identity.did.clone();

    let credential = |id: &str| {
        let mut r = registration(&community, &box_did, id);
        r["manifest"]["roll"] = json!({
            "rule": "credential",
            "memberOf": format!("{}:groups:g7", community.did),
        });
        let digest = manifest_digest(&r["manifest"]).unwrap();
        r["manifestDigest"] = json!(digest_multibase(&digest));
        r
    };
    let register_at = |version: &'static str, payload: Value| {
        let box_did = box_did.clone();
        let community = &community;
        async move {
            doc_at(
                "election/register",
                version,
                &box_did,
                Some(community),
                payload,
            )
            .await
        }
    };
    for version in ["0.2", "0.3"] {
        let (status, answer) = send(&svc, register_at(version, credential("roll")).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{version}: {answer}");
        assert_eq!(answer["payload"]["code"], "malformedRequest");
    }
    let (status, answer) = send(&svc, register_at("0.4", credential("roll")).await).await;
    assert_eq!(status, StatusCode::OK, "{answer}");

    let show = |version: &'static str, id: &str| {
        let payload = json!({ "community": community.did, "electionId": id });
        let box_did = box_did.clone();
        async move { doc_at("election/show", version, &box_did, None, payload).await }
    };
    let (status, answer) = send(&svc, show("0.4", "roll").await).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["payload"]["manifest"]["roll"]["rule"], "credential");
    for version in ["0.2", "0.3"] {
        let (status, answer) = send(&svc, show(version, "roll").await).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{version}: {answer}");
        assert_eq!(answer["payload"]["code"], "unsupportedVersion");
    }

    let usual = registration(&community, &box_did, "usual");
    let (status, answer) = send(&svc, register_at("0.4", usual).await).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    for version in ["0.2", "0.3", "0.4"] {
        let (status, answer) = send(&svc, show(version, "usual").await).await;
        assert_eq!(status, StatusCode::OK, "{version}: {answer}");
    }
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
    let version = match task {
        "election/register" | "election/show" => "0.3",
        "board/read" => "0.2",
        _ => "0.1",
    };
    doc_at(task, version, to, signer, payload).await
}

/// [`doc`], at `version`.
async fn doc_at(
    task: &str,
    version: &str,
    to: &str,
    signer: Option<&Identity>,
    payload: Value,
) -> Value {
    let mut d = json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": format!("https://trusttasks.org/spec/voting/{task}/{version}#request"),
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
        "registrationOpensAt": (now - Duration::days(2)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "votingOpensAt": (now - Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "votingClosesAt": (now + Duration::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
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
        "registrationOpensAt": (now - Duration::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "votingOpensAt": (now + Duration::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "votingClosesAt": (now + Duration::days(2)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
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

async fn get(state: &Arc<AppState>, path: &str) -> (StatusCode, Value) {
    let res = router(state.clone())
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// Without a provisioned identity no community can reach the box: alive, never ready.
#[tokio::test]
async fn health_without_messaging_is_alive_but_never_ready() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let svc = state(&dir);

    let (status, body) = get(&svc, "/health").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["messaging"], "disabled");
    assert_eq!(body["did"], svc.identity.did);

    let (status, body) = get(&svc, "/health/ready").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["status"], "notReady");
    assert_eq!(body["messaging"], "disabled");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Readiness follows the mediator session's live state both ways — never latched at the first
/// connect (R6.2) — while liveness stays `200` throughout, so the cast door is never pulled.
#[tokio::test]
async fn readiness_follows_the_mediator_session_both_ways() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let (connected, rx) = tokio::sync::watch::channel(false);
    let svc = Arc::new(
        Arc::into_inner(state(&dir))
            .expect("sole owner")
            .with_messaging(rx),
    );

    for (up, code, messaging) in [
        (false, StatusCode::SERVICE_UNAVAILABLE, "notConnected"),
        (true, StatusCode::OK, "connected"),
        (false, StatusCode::SERVICE_UNAVAILABLE, "notConnected"),
    ] {
        connected.send_replace(up);
        let (status, body) = get(&svc, "/health/ready").await;
        assert_eq!(status, code, "{body}");
        assert_eq!(body["messaging"], messaging);
        let (status, body) = get(&svc, "/health").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["messaging"], messaging);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A copy of [`sign`]'s output with its proof's verification method moved to `did`: what a
/// document naming a DID of its sender's choosing looks like. Its signature no longer verifies,
/// which does not matter: nothing that names such a DID may get as far as resolving it.
fn naming_method(mut d: Value, did: &str) -> Value {
    d["issuer"] = json!(did);
    d["proof"]["verificationMethod"] = json!(format!("{did}#key-0"));
    d
}

/// On the HTTPS door, which proves nobody, the service resolves a signer only where it has a
/// reason to know it: a `did:key` (or `did:peer`), a community `[communities] allowed` names, or a
/// party an election held here names. Anyone else is refused before anything is fetched
/// (`permissionDenied`), and a proof whose verification method is not the issuer's is refused
/// before it is resolved (`proofInvalid`).
#[tokio::test]
async fn the_https_door_resolves_only_a_signer_it_has_a_reason_to_know() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let community = Identity::from_seed(&[31; 32]).unwrap();
    // A community this box serves by name: the parties its elections list are vouched for.
    let svc = state_serving(
        &dir,
        CommunitiesConfig {
            allowed: vec![community.did.clone()],
            ..CommunitiesConfig::default()
        },
    );
    let service_did = svc.identity.did.clone();
    let auditor = "did:webvh:QmAuditor:audit.example";
    let stranger = "did:webvh:QmStranger:stranger.example";

    let mut register = registration(&community, &service_did, "e-door");
    register["manifest"]["board"]["auditors"] = json!([auditor]);
    let digest = manifest_digest(&register["manifest"]).unwrap();
    register["manifestDigest"] = json!(digest_multibase(&digest));
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

    let sel = json!({ "community": community.did, "electionId": "e-door" });
    let signed_read = doc("board/head", &service_did, Some(&community), sel.clone()).await;

    // A stranger's DID is never resolved: refused as no party, not as a failed resolution.
    let (status, answer) = send(&svc, naming_method(signed_read.clone(), stranger)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(answer["payload"]["code"], "permissionDenied", "{answer}");

    // Nor one naming an election not held here.
    let mut elsewhere = signed_read.clone();
    elsewhere["payload"]["electionId"] = json!("not-here");
    let (status, answer) = send(&svc, naming_method(elsewhere, auditor)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(answer["payload"]["code"], "permissionDenied", "{answer}");

    // A party the election names is resolved: here the test resolver cannot, so the proof
    // fails — after the door let it through.
    let (status, answer) = send(&svc, naming_method(signed_read.clone(), auditor)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");
    assert_eq!(answer["payload"]["code"], "proofInvalid", "{answer}");

    // A verification method that is not the issuer's is refused before it is resolved.
    let mut mismatched = signed_read.clone();
    mismatched["proof"]["verificationMethod"] = json!(format!("{stranger}#key-0"));
    let (status, answer) = send(&svc, mismatched).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");
    assert_eq!(answer["payload"]["code"], "proofInvalid", "{answer}");

    // A did:key signer still reads.
    let (status, answer) = send(&svc, signed_read).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// On an open box (`allow_any`), anyone can mint a `did:key`, register over HTTPS as that
/// community and name any DID as an auditor or a trustee. Those parties are not vouched for, so
/// a request signed as one of them is refused before its DID is fetched.
#[tokio::test]
async fn an_open_box_never_resolves_the_parties_a_did_key_community_names() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let svc = state(&dir);
    let service_did = svc.identity.did.clone();
    let community = Identity::from_seed(&[34; 32]).unwrap();
    let named = "did:webvh:QmNamed:someone.example";

    let mut register = registration(&community, &service_did, "e-open");
    register["manifest"]["board"]["auditors"] = json!([named]);
    let digest = manifest_digest(&register["manifest"]).unwrap();
    register["manifestDigest"] = json!(digest_multibase(&digest));
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

    let read = doc(
        "board/head",
        &service_did,
        Some(&community),
        json!({ "community": community.did, "electionId": "e-open" }),
    )
    .await;
    let (status, answer) = send(&svc, naming_method(read, named)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(answer["payload"]["code"], "permissionDenied", "{answer}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A proof's verification method is a DID URL under the issuer, with a fragment: a bare DID
/// names no method, and is refused before anything is resolved.
#[tokio::test]
async fn a_verification_method_without_a_fragment_is_refused() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let svc = state(&dir);
    let community = Identity::from_seed(&[35; 32]).unwrap();
    let mut read = doc(
        "board/head",
        &svc.identity.did,
        Some(&community),
        json!({ "community": community.did, "electionId": "e1" }),
    )
    .await;
    read["proof"]["verificationMethod"] = json!(community.did);
    let (status, answer) = send(&svc, read).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");
    assert_eq!(answer["payload"]["code"], "proofInvalid", "{answer}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A community named in `[communities] allowed` is resolved on the HTTPS door; an open box
/// (`allow_any`) names nobody, so a stranger registering there over HTTPS is never resolved.
#[tokio::test]
async fn an_allowed_community_is_resolved_on_the_https_door_and_an_open_box_names_nobody() {
    let listed = "did:webvh:QmListed:community.example";
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let svc = state_serving(
        &dir,
        CommunitiesConfig {
            allowed: vec![listed.to_string()],
            ..CommunitiesConfig::default()
        },
    );
    let service_did = svc.identity.did.clone();
    let community = Identity::from_seed(&[32; 32]).unwrap();
    let register = registration(&community, &service_did, "e-listed");
    let signed = doc(
        "election/register",
        &service_did,
        Some(&community),
        register,
    )
    .await;
    let (status, answer) = send(&svc, naming_method(signed, listed)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");
    assert_eq!(answer["payload"]["code"], "proofInvalid", "{answer}");
    let _ = std::fs::remove_dir_all(&dir);

    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let open = state(&dir);
    let open_did = open.identity.did.clone();
    let signed = doc(
        "election/register",
        &open_did,
        Some(&community),
        registration(&community, &open_did, "e-listed"),
    )
    .await;
    let (status, answer) = send(&open, naming_method(signed, listed)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(answer["payload"]["code"], "permissionDenied", "{answer}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A community's or a trustee's request is refused once older than the acceptance window every
/// VTI node applies (VTI-OPS-024): a copy of one is not a standing instruction. A cast is not
/// held to it: its key is made for it, and its sender may resend it until voting closes.
#[tokio::test]
async fn a_communitys_request_older_than_the_acceptance_window_is_refused() {
    let dir = std::env::temp_dir().join(format!("vti-voting-service-{}", Uuid::new_v4()));
    let svc = state(&dir);
    let service_did = svc.identity.did.clone();
    let community = Identity::from_seed(&[33; 32]).unwrap();
    let register = registration(&community, &service_did, "e-window");

    let mut old = doc("election/register", &service_did, None, register.clone()).await;
    old["issuer"] = json!(community.did);
    old["issuedAt"] = json!(
        (Utc::now() - Duration::minutes(20)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    let (status, answer) = send(&svc, sign(old, &community).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["payload"]["code"], "expired", "{answer}");

    let mut recent = doc("election/register", &service_did, None, register).await;
    recent["issuer"] = json!(community.did);
    recent["issuedAt"] = json!(
        (Utc::now() - Duration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    let (status, answer) = send(&svc, sign(recent, &community).await).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let _ = std::fs::remove_dir_all(&dir);
}
