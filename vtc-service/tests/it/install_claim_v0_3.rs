//! `vtc/install/claim/{start,finish}/0.3` — a wallet founder claims a fresh
//! community under a DID they already control, with a step-up approver as
//! their step-up factor (approver design note §6b, R1; VTI-APV-016: the
//! binding rests on the install token and its claim code, never on the
//! founder's signing key).
//!
//! The start is the token and code; the finish is signed by the DID the token
//! names, verified against its live document, and carries the approver's
//! enrolment statement; the approver is bound only when `vtc/admin/bootstrap`
//! writes the administrator.

use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{Duration as ChronoDuration, Utc};
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::VtcRole;
use vtc_service::install::{InstallTokenSigner, mint_install_token};
use vtc_service::test_support::TestVtc;

use crate::common::signed::{call, party_with_role, payload, post, signed_to, unsigned};

use trust_tasks_rs::specs::vtc::install::claim as claim_spec;

const START_V0_3_ERR_INVALID_TOKEN: &str = claim_spec::start::v0_3::error_codes::INVALID_TOKEN.code;
const START_V0_3_ERR_TOKEN_NAMES_NO_DID: &str =
    claim_spec::start::v0_3::error_codes::TOKEN_NAMES_NO_DID.code;
const FINISH_V0_3_ERR_INVALID_TOKEN: &str =
    claim_spec::finish::v0_3::error_codes::INVALID_TOKEN.code;
const FINISH_V0_3_ERR_REGISTRATION_MISMATCH: &str =
    claim_spec::finish::v0_3::error_codes::REGISTRATION_MISMATCH.code;
const FINISH_V0_3_ERR_SUBJECT_MISMATCH: &str =
    claim_spec::finish::v0_3::error_codes::SUBJECT_MISMATCH.code;
const FINISH_V0_3_ERR_DID_UNRESOLVABLE: &str =
    claim_spec::finish::v0_3::error_codes::DID_UNRESOLVABLE.code;
const FINISH_V0_3_ERR_STATEMENT_INVALID: &str =
    claim_spec::finish::v0_3::error_codes::STATEMENT_INVALID.code;
const FINISH_V0_3_ERR_APPROVER_NOT_DISTINCT: &str =
    claim_spec::finish::v0_3::error_codes::APPROVER_NOT_DISTINCT.code;

const RP_ORIGIN: &str = "https://vtc.example.com";
const START: &str = "https://trusttasks.org/spec/vtc/install/claim/start/0.3";
const FINISH: &str = "https://trusttasks.org/spec/vtc/install/claim/finish/0.3";
const BOOTSTRAP: &str = "https://trusttasks.org/spec/vtc/admin/bootstrap/0.1";
const ATTEST: &str = "https://trusttasks.org/spec/auth/step-up/approver/attest/0.1";
const INVITE: &str = "https://trusttasks.org/spec/auth/step-up/approver/invite/0.1";
const APPROVE_V06: &str = "https://trusttasks.org/spec/auth/step-up/approve-response/0.6";

struct Fixture {
    vtc: TestVtc,
    signer: Arc<InstallTokenSigner>,
    audience: String,
}

async fn fixture() -> Fixture {
    let signer = Arc::new(InstallTokenSigner::from_master_seed(&[0xAB; 64]).unwrap());
    let vtc = TestVtc::builder()
        .with_public_url(RP_ORIGIN)
        .with_install_signer(signer.clone())
        .with_audit(true)
        .with_signers(true)
        .build()
        .await;
    let audience = vtc.state.config.read().await.vtc_did.clone().unwrap();
    Fixture {
        vtc,
        signer,
        audience,
    }
}

/// An install token naming `admin_did`, with its claim code.
async fn token_for(fix: &Fixture, admin_did: &str) -> (String, String) {
    let minted = mint_install_token(&fix.signer, &fix.audience, admin_did, 600).unwrap();
    let code = vtc_service::install::claim_secret::generate();
    let hash = vtc_service::install::claim_secret::hash(&code).unwrap();
    fix.vtc
        .state
        .install_store
        .record_issued(
            &minted.jti,
            minted.cnonce_bytes,
            *minted.ephemeral_signing_key,
            Utc::now() + ChronoDuration::seconds(600),
            Some(hash),
            Some(admin_did.into()),
        )
        .await
        .unwrap();
    (minted.jwt, code)
}

fn tt_error_code(doc: &Value) -> Option<&str> {
    if doc["type"].as_str()?.contains("trust-task-error") {
        doc["payload"]["code"].as_str()
    } else {
        None
    }
}

/// `start`, sent unsigned (its proof is optional: the token and code are the
/// gate).
async fn start(fix: &Fixture, token: &str, code: &str) -> (StatusCode, Value) {
    let caller = Party::new();
    post(
        &fix.vtc,
        &unsigned(&caller, START, json!({ "token": token, "claimCode": code })),
    )
    .await
}

async fn enrol_statement(fix: &Fixture, approver: &Party, subject: &str, opened: &Value) -> Value {
    signed_to(
        approver,
        &fix.audience,
        ATTEST,
        json!({
            "purpose": "enrol",
            "subject": subject,
            "audience": fix.audience,
            "challenge": opened["challenge"],
            "boundTo": opened["claimId"],
        }),
    )
    .await
}

async fn finish(
    fix: &Fixture,
    founder: &Party,
    opened: &Value,
    approver_did: &str,
    statement: Value,
) -> (StatusCode, Value) {
    call(
        &fix.vtc,
        founder,
        FINISH,
        json!({
            "claimId": opened["claimId"],
            "approverDid": approver_did,
            "label": "Browser plugin",
            "statement": statement,
        }),
    )
    .await
}

/// R1 end to end: the founder claims under their own DID, the bootstrap writes
/// them as administrator **and** binds their approver (`enrolledVia:
/// install`), and the approver then answers their step-ups.
#[tokio::test]
async fn vti_apv_016_a_wallet_founder_claims_with_an_approver_and_steps_up_with_it() {
    let fix = fixture().await;
    let founder = Party::new();
    let approver = Party::new();
    let (token, code) = token_for(&fix, &founder.did).await;

    let (status, opened) = start(&fix, &token, &code.to_lowercase()).await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    let opened = payload(&opened).clone();
    assert_eq!(opened["adminDid"], founder.did);
    assert_eq!(opened["audience"], fix.audience);

    let st = enrol_statement(&fix, &approver, &founder.did, &opened).await;
    let (status, done) = finish(&fix, &founder, &opened, &approver.did, st).await;
    assert_eq!(status, StatusCode::OK, "{done}");
    let session_token = payload(&done)["setupSessionToken"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(payload(&done)["adminDid"], founder.did);

    // Nothing is bound until the bootstrap writes the administrator.
    assert!(
        vtc_service::acl::approver::stored_live(&fix.vtc.state.step_up_approvers_ks, &founder.did)
            .await
            .unwrap()
            .is_empty()
    );
    let (status, booted) = post(
        &fix.vtc,
        &unsigned(
            &Party::new(),
            BOOTSTRAP,
            json!({ "setupSessionToken": session_token }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{booted}");
    let entry = vtc_service::acl::get_acl_entry(&fix.vtc.state.acl_ks, &founder.did)
        .await
        .unwrap()
        .expect("the founder is an administrator");
    assert_eq!(entry.role, VtcRole::Admin);
    let bound =
        vtc_service::acl::approver::stored_live(&fix.vtc.state.step_up_approvers_ks, &founder.did)
            .await
            .unwrap();
    assert_eq!(bound.len(), 1);
    assert_eq!(bound[0].approver_did, approver.did);
    assert_eq!(
        bound[0].enrolled_via,
        vtc_service::acl::approver::EnrolledVia::Install
    );

    // The founder steps up with it: an invite for a member asks for, and
    // accepts, the approver's statement.
    let member = party_with_role(&fix.vtc, VtcRole::Member, &[]).await;
    let doc = signed_to(
        &founder,
        &fix.audience,
        INVITE,
        json!({ "subject": member.did }),
    )
    .await;
    let (_, refusal) = post(&fix.vtc, &doc).await;
    let request = refusal["payload"]["details"]["stepUpRequest"].clone();
    assert_eq!(request["accepts"], json!(["approverSigned"]), "{refusal}");
    let st = signed_to(
        &approver,
        &fix.audience,
        ATTEST,
        json!({
            "purpose": "stepUp",
            "subject": founder.did,
            "audience": fix.audience,
            "challenge": request["challenge"],
            "boundTo": request["boundTo"],
        }),
    )
    .await;
    let (_, ack) = call(
        &fix.vtc,
        &founder,
        APPROVE_V06,
        json!({
            "subject": founder.did,
            "challenge": request["challenge"],
            "decision": "approved",
            "evidence": { "kind": "approverSigned", "statement": st },
        }),
    )
    .await;
    assert_eq!(payload(&ack)["status"], "recorded", "{ack}");
    let (_, issued) = post(&fix.vtc, &doc).await;
    assert!(tt_error_code(&issued).is_none(), "{issued}");
}

#[tokio::test]
async fn claim_start_v0_3_answers_the_codes_its_spec_declares() {
    let fix = fixture().await;
    let founder = Party::new();
    let (token, _code) = token_for(&fix, &founder.did).await;
    let (_, out) = start(&fix, &token, "WRONGCODE9").await;
    assert_eq!(
        tt_error_code(&out),
        Some(START_V0_3_ERR_INVALID_TOKEN),
        "{out}"
    );
    let (_, out) = start(
        &fix,
        "eyJhbGciOiJFZERTQSJ9.e30.not-a-real-signature",
        "WRONGCODE9",
    )
    .await;
    assert_eq!(
        tt_error_code(&out),
        Some(START_V0_3_ERR_INVALID_TOKEN),
        "{out}"
    );

    let (token, code) = token_for(&fix, "nobody-in-particular").await;
    let (_, out) = start(&fix, &token, &code).await;
    assert_eq!(
        tt_error_code(&out),
        Some(START_V0_3_ERR_TOKEN_NAMES_NO_DID),
        "{out}"
    );
}

/// The fifth wrong claim code voids the install token: the right code after it
/// opens nothing, and the token's state is gone. Every attempt answers alike,
/// so the count is no oracle (claim/start 0.3, as the approver invite's).
#[tokio::test]
async fn claim_start_v0_3_five_wrong_codes_void_the_install_token() {
    let fix = fixture().await;
    let founder = Party::new();
    let (token, code) = token_for(&fix, &founder.did).await;
    let jti = vtc_service::install::parse_install_token(&fix.signer, &token)
        .unwrap()
        .jti
        .parse::<uuid::Uuid>()
        .unwrap();
    for _ in 0..4 {
        let wrong = vtc_service::install::claim_secret::generate();
        let (_, out) = start(&fix, &token, &wrong).await;
        assert_eq!(tt_error_code(&out), Some(START_V0_3_ERR_INVALID_TOKEN));
    }
    // Four wrong codes: the right one still opens the claim.
    let (status, opened) = start(&fix, &token, &code).await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    let (_, out) = start(
        &fix,
        &token,
        &vtc_service::install::claim_secret::generate(),
    )
    .await;
    assert_eq!(tt_error_code(&out), Some(START_V0_3_ERR_INVALID_TOKEN));
    assert!(
        fix.vtc
            .state
            .install_store
            .get_token(&jti)
            .await
            .unwrap()
            .is_none(),
        "voided"
    );
    let (_, out) = start(&fix, &token, &code).await;
    assert_eq!(
        tt_error_code(&out),
        Some(START_V0_3_ERR_INVALID_TOKEN),
        "the right code opens nothing once the token is void: {out}"
    );
}

#[tokio::test]
async fn claim_finish_v0_3_answers_the_codes_its_spec_declares() {
    let fix = fixture().await;
    let founder = Party::new();
    let approver = Party::new();
    let (token, code) = token_for(&fix, &founder.did).await;
    let (_, a) = start(&fix, &token, &code).await;
    let a = payload(&a).clone();
    let (_, b) = start(&fix, &token, &code).await;
    let b = payload(&b).clone();

    // No such claim.
    let bogus = json!({ "claimId": "clm_nope", "challenge": a["challenge"] });
    let st = enrol_statement(&fix, &approver, &founder.did, &bogus).await;
    let (_, out) = finish(&fix, &founder, &bogus, &approver.did, st).await;
    assert_eq!(
        tt_error_code(&out),
        Some(FINISH_V0_3_ERR_REGISTRATION_MISMATCH),
        "{out}"
    );

    // Signed by a DID other than the one the token names.
    let other = Party::new();
    let st = enrol_statement(&fix, &approver, &founder.did, &a).await;
    let (_, out) = finish(&fix, &other, &a, &approver.did, st).await;
    assert_eq!(
        tt_error_code(&out),
        Some(FINISH_V0_3_ERR_SUBJECT_MISMATCH),
        "{out}"
    );

    // A statement bound to another claim.
    let st = enrol_statement(&fix, &approver, &founder.did, &b).await;
    let (_, out) = finish(&fix, &founder, &a, &approver.did, st).await;
    assert_eq!(
        tt_error_code(&out),
        Some(FINISH_V0_3_ERR_STATEMENT_INVALID),
        "{out}"
    );

    // An approver that is no distinct factor (it holds standing of its own).
    let standing = party_with_role(&fix.vtc, VtcRole::Member, &[]).await;
    let st = enrol_statement(&fix, &standing, &founder.did, &a).await;
    let (_, out) = finish(&fix, &founder, &a, &standing.did, st).await;
    assert_eq!(
        tt_error_code(&out),
        Some(FINISH_V0_3_ERR_APPROVER_NOT_DISTINCT),
        "{out}"
    );

    // Claim `a` completes and consumes the token; claim `b`, opened on the
    // same token, then finds it gone.
    let st = enrol_statement(&fix, &approver, &founder.did, &a).await;
    let (status, out) = finish(&fix, &founder, &a, &approver.did, st).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    let st = enrol_statement(&fix, &Party::new(), &founder.did, &b).await;
    let (_, out) = finish(&fix, &founder, &b, &Party::new().did, st).await;
    assert_eq!(
        tt_error_code(&out),
        Some(FINISH_V0_3_ERR_INVALID_TOKEN),
        "{out}"
    );
}

/// The founder's DID is resolved afresh for the finish; one that does not
/// resolve is `didUnresolvable`, and nothing is consumed.
#[tokio::test]
async fn claim_finish_v0_3_refuses_a_founder_did_that_does_not_resolve() {
    let fix = fixture().await;
    let founder = "did:web:unresolvable.example";
    let (token, code) = token_for(&fix, founder).await;
    let (_, opened) = start(&fix, &token, &code).await;
    let opened = payload(&opened).clone();
    let doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": FINISH,
        "issuer": founder,
        "recipient": fix.audience,
        "issuedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": {
            "claimId": opened["claimId"],
            "approverDid": Party::new().did,
            "statement": { "id": "urn:uuid:x" },
        },
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": format!("{founder}#key-1"),
            "created": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "proofPurpose": "authentication",
            "proofValue": "z3kg",
        },
    });
    let (_, out) = post(&fix.vtc, &doc).await;
    assert_eq!(
        tt_error_code(&out),
        Some(FINISH_V0_3_ERR_DID_UNRESOLVABLE),
        "{out}"
    );
    // Nothing consumed: the claim still opens and the token is still issued.
    assert!(matches!(
        fix.vtc
            .state
            .install_store
            .list_tokens()
            .await
            .unwrap()
            .first()
            .map(|(_, s)| s.clone()),
        Some(vtc_service::install::InstallTokenState::Issued { .. })
    ));
}
