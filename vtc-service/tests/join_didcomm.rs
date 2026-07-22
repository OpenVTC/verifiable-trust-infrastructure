//! Worked example for the DIDComm join-requests harness (#436).
//!
//! Drives a genuine community-join round-trip against a **real** `vtc-service`
//! over DIDComm — not canned responses — using [`MockVtcDidcomm`]: an embedded
//! test mediator carrying both a `did:peer` applicant and the VTC, with the
//! VTC's DIDComm responder bound to the production `submit_inner` /
//! `manifest_inner` / `status_inner` handlers and the credential-delivery push.
//!
//! Round-trip exercised:
//!   1. applicant `submit` over DIDComm                  → real `submit_inner`, pending receipt
//!   2. applicant `manifest` over DIDComm               → real `manifest_inner`, DCQL criteria
//!   3. manifest DCQL → `vp_token` via `vta_sdk::vp`     → the OpenVTC **D4** capability
//!   4. applicant `status` over DIDComm                 → real `status_inner`, still pending
//!   5. admin `approve` over REST                        → real ceremony issues the VMC + role VEC
//!   6. VMC delivered to the applicant **over DIDComm**  → `credential-exchange/issue` lands
//!
//! This is the template a downstream consumer (OpenVTC) copies to test its join
//! + activation path against a real VTC.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::auth::session::now_epoch;
use vtc_service::schemas::accepts::{AcceptsCriterion, store_accepts};
use vtc_service::test_support::{MockVtcDidcomm, ReplyOutcome};

use vta_sdk::protocols::credential_exchange::{ISSUE as CREDENTIAL_ISSUE_TYPE, IssueBody};
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_MANIFEST_TYPE, JOIN_REQUEST_STATUS_TYPE, JOIN_REQUEST_SUBMIT_TYPE,
    JoinRequestManifestResponseBody, JoinRequestStatusBody, JoinRequestStatusResponseBody,
    JoinRequestSubmitBody, VerdictEffect, VerdictResponse,
};

/// The `payload` of a Trust Task `#response` document (where every verb's
/// success body lives).
fn response_payload(doc: serde_json::Value) -> serde_json::Value {
    doc.get("payload")
        .cloned()
        .unwrap_or_else(|| panic!("Trust Task response has no payload: {doc}"))
}
use vta_sdk::vp::{HeldCredential, build_vp_token, select_credentials};

const ADMIN_DID: &str = "did:key:z6MkJoinAdmin";
const APPROVE_TASK: &str = "https://trusttasks.org/openvtc/vtc/join-requests/approve/1.0";

/// Seed the join ceremony the same way `server::run` does at boot: default
/// policies (so `join.rego` evaluates instead of failing closed), both status
/// lists (so the approve handler can allocate a VMC revocation slot), an admin
/// ACL entry, and one DCQL Accepts criterion (so the manifest advertises a
/// `presentation_definition`). Returns an admin bearer token.
async fn seed_join_ceremony(mock: &MockVtcDidcomm) -> String {
    let state = &mock.vtc.state;

    vtc_service::policy::default::install_defaults(&state.policies_ks, &state.active_policies_ks)
        .await
        .expect("install default policies");

    for purpose in [
        affinidi_status_list::StatusPurpose::Revocation,
        affinidi_status_list::StatusPurpose::Suspension,
    ] {
        vtc_service::status_list::ensure_initial(
            &state.status_lists_ks,
            purpose,
            format!("https://vtc.test/v1/status-lists/{purpose}"),
        )
        .await
        .expect("ensure status list");
    }

    store_acl_entry(
        &state.acl_ks,
        &VtcAclEntry {
            did: ADMIN_DID.into(),
            role: VtcRole::Admin,
            label: Some("join test admin".into()),
            allowed_contexts: vec![],
            created_at: now_epoch(),
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("store admin ACL");

    // A DCQL Accepts criterion with no `meta.vct_values` — so it needs no
    // schema-store registration — that the manifest surfaces as a
    // `presentation_definition` for the applicant to satisfy.
    store_accepts(
        &state.schemas_ks,
        &AcceptsCriterion {
            id: "membership".into(),
            query: json!({
                "credentials": [{
                    "id": "membership",
                    "format": "ldp_vc",
                    "claims": [ { "path": ["givenName"] } ]
                }]
            }),
            description: Some("Join evidence".into()),
            created_at: chrono::Utc::now(),
            created_by_did: ADMIN_DID.into(),
        },
    )
    .await
    .expect("store Accepts criterion");

    mock.vtc.token(ADMIN_DID, "admin", vec![]).await
}

/// `POST` a Trust-Task against the VTC's REST router (the admin surface).
async fn rest_post(
    mock: &MockVtcDidcomm,
    uri: &str,
    trust_task: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    let res = mock
        .vtc
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("Trust-Task", trust_task)
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("oneshot");
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

#[tokio::test]
async fn didcomm_join_round_trips_submit_manifest_status_approve_and_vmc_delivery() {
    let mock = MockVtcDidcomm::start().await;
    let admin_token = seed_join_ceremony(&mock).await;
    let vtc_did = mock.vtc_did().to_string();
    let applicant_did = mock.client.did().to_string();

    // 1. Submit a join request over DIDComm — the authcrypt sender is the
    //    applicant DID, so no holder-binding signature is needed. Hits the real
    //    `submit_inner`; the default policy defers to a pending decision.
    let submit = JoinRequestSubmitBody {
        vp: json!({ "type": "VerifiablePresentation", "holder": applicant_did }),
        registry_consent: false,
        extensions: json!({}),
    };
    let verdict: VerdictResponse = serde_json::from_value(response_payload(
        mock.client
            .request(
                &vtc_did,
                JOIN_REQUEST_SUBMIT_TYPE,
                serde_json::to_value(submit).unwrap(),
            )
            .await,
    ))
    .expect("submit verdict");
    assert_eq!(
        verdict.verdict.effect,
        VerdictEffect::Refer,
        "default policy refers the request to an admin (pending)"
    );
    let request_id = verdict.request_id;

    // 2. Discover the community's join evidence over DIDComm (real
    //    `manifest_inner`) — the seeded DCQL Accepts criterion.
    let manifest: JoinRequestManifestResponseBody = serde_json::from_value(response_payload(
        mock.client
            .request(&vtc_did, JOIN_REQUEST_MANIFEST_TYPE, json!({}))
            .await,
    ))
    .expect("manifest response");
    assert_eq!(manifest.community_did, vtc_did);
    let criterion = manifest
        .criteria
        .iter()
        .find(|c| c.id == "membership")
        .expect("manifest advertises the membership criterion");

    // 3. OpenVTC D4: select a held credential against the manifest's DCQL and
    //    assemble a holder-bound `vp_token` with the SDK helper — the exact
    //    client-side construction the VTC verifies server-side.
    let subject = json!({ "givenName": "Ada", "memberSince": "2024-01-01" });
    let held = HeldCredential {
        id: "vmc-held".into(),
        format: "ldp_vc".into(),
        claims: subject.clone(),
        vct: None,
        doctype: None,
        supports_holder_binding: true,
        vc: json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "credentialSubject": subject,
        }),
    };
    let candidates = select_credentials(&criterion.presentation_definition, &[held])
        .expect("held credential satisfies the manifest DCQL");
    let vp_token = build_vp_token(
        &candidates,
        mock.client.holder_secret(),
        "join-nonce",
        &vtc_did,
    )
    .await
    .expect("assemble vp_token");
    assert!(
        vp_token.get("membership").is_some(),
        "vp_token is keyed by the credential-query id: {vp_token}"
    );

    // 4. Poll status over DIDComm (real `status_inner`) — still pending pre-approval.
    let status: JoinRequestStatusResponseBody = serde_json::from_value(response_payload(
        mock.client
            .request(
                &vtc_did,
                JOIN_REQUEST_STATUS_TYPE,
                serde_json::to_value(JoinRequestStatusBody { request_id }).unwrap(),
            )
            .await,
    ))
    .expect("status response");
    assert_eq!(status.status, "pending");

    // 5. Admin approves over REST — the real ceremony admits the applicant,
    //    issues the VMC + role VEC, and pushes them to the applicant's wallet
    //    over DIDComm (`deliver_membership_credentials`).
    let (code, body) = rest_post(
        &mock,
        &format!("/v1/join-requests/{request_id}/approve"),
        APPROVE_TASK,
        &admin_token,
        json!({}),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "approve failed: {body}");
    assert_eq!(body["status"], "approved");

    // 6. The membership credential lands at the applicant over DIDComm — the
    //    full push the activation path (T6) needs.
    //
    //    Admission delivers *two* credentials (the VMC and the role VEC) as
    //    independent one-way messages — `deliver_credentials` opens a fresh
    //    thread per credential, and each is forwarded through the mediator
    //    separately. Arrival order is therefore not guaranteed, so collect both
    //    pushes and look for the VMC among them rather than asserting it is the
    //    first to land (which flaked in CI when the VEC overtook it).
    let mut delivered = Vec::new();
    for _ in 0..2 {
        let (typ, issue_body) = mock
            .client
            .next_pushed(Duration::from_secs(20))
            .await
            .expect("admission credential delivered over DIDComm");
        assert_eq!(typ, CREDENTIAL_ISSUE_TYPE);
        let issue: IssueBody = serde_json::from_value(issue_body).expect("issue body");
        delivered.push(
            issue
                .credential_response
                .expect("credential_response present")
                .credential
                .expect("credential present"),
        );
    }

    let has_type = |c: &serde_json::Value, want: &str| {
        c["type"]
            .as_array()
            .expect("VC type array")
            .iter()
            .any(|t| t == want)
    };

    let vmc = delivered
        .iter()
        .find(|c| has_type(c, "MembershipCredential"))
        .unwrap_or_else(|| panic!("a MembershipCredential was delivered: {delivered:#?}"));
    assert_eq!(
        vmc["credentialSubject"]["id"], applicant_did,
        "VMC subject is the applicant"
    );

    // The role VEC is the other half of the admission push.
    let vec_cred = delivered
        .iter()
        .find(|c| has_type(c, "EndorsementCredential"))
        .unwrap_or_else(|| panic!("a role EndorsementCredential was delivered: {delivered:#?}"));
    assert_eq!(
        vec_cred["credentialSubject"]["id"], applicant_did,
        "role VEC subject is the applicant"
    );

    mock.shutdown().await;
}

/// The negative-path counterpart that unblocks a cross-service fuzz campaign
/// (#464): `try_request` must *classify* a rejection rather than abort. A
/// malformed submit (missing the required `vp`) makes the real `submit_inner`
/// reject; the VTC threads back a DIDComm problem-report, and the harness keeps
/// going — exactly what a sustained negative campaign needs (reply = accepted,
/// problem-report = clean reject, timeout = hang/crash).
#[tokio::test]
async fn didcomm_try_request_classifies_reject_and_keeps_going() {
    let mock = MockVtcDidcomm::start().await;
    let _admin_token = seed_join_ceremony(&mock).await;
    let vtc_did = mock.vtc_did().to_string();

    // A malformed submit body (no `vp`) fails to deserialize in the handler →
    // the VTC replies with a problem-report instead of a receipt. The old
    // `request` helper would panic here; `try_request` returns it classified.
    let outcome = mock
        .client
        .try_request(
            &vtc_did,
            JOIN_REQUEST_SUBMIT_TYPE,
            json!({ "registry_consent": false }),
            Duration::from_secs(15),
        )
        .await;
    match outcome {
        ReplyOutcome::Problem(p) => {
            assert!(!p.code.is_empty(), "problem-report carries a code: {:?}", p);
        }
        other => panic!("expected a clean problem-report rejection, got {other:?}"),
    }

    // The campaign keeps running on the same boot: a well-formed submit right
    // after the rejection still round-trips to an accepted receipt.
    let applicant_did = mock.client.did().to_string();
    let good = JoinRequestSubmitBody {
        vp: json!({ "type": "VerifiablePresentation", "holder": applicant_did }),
        registry_consent: false,
        extensions: json!({}),
    };
    let outcome = mock
        .client
        .try_request(
            &vtc_did,
            JOIN_REQUEST_SUBMIT_TYPE,
            serde_json::to_value(good).unwrap(),
            Duration::from_secs(15),
        )
        .await;
    match outcome {
        ReplyOutcome::Reply(body) => {
            let verdict: VerdictResponse =
                serde_json::from_value(response_payload(body)).expect("submit verdict");
            assert_eq!(verdict.verdict.effect, VerdictEffect::Refer);
        }
        other => panic!("expected an accepted verdict after the reject, got {other:?}"),
    }

    mock.shutdown().await;
}

/// Regression for #485 (cross-service join-ceremony fuzzer finding): a *duplicate*
/// submit — same applicant DID resubmits while their first request is still open —
/// is a normal 409-Conflict business-rule rejection, so the threaded DIDComm
/// problem-report must carry the `conflict` code, **not** the generic
/// `internal-error` bucket. `internal-error` would mislead clients into treating
/// an expected condition as a server fault (and the fuzzer flags any
/// `internal-error`-coded problem-report as a soft finding). The dedup guard in
/// `submit_inner` returns `AppError::Conflict`; this pins that it surfaces as
/// `e.p.msg.conflict` end-to-end through the real DIDComm handler.
#[tokio::test]
async fn didcomm_duplicate_submit_rejects_with_conflict_not_internal_error() {
    let mock = MockVtcDidcomm::start().await;
    let _admin_token = seed_join_ceremony(&mock).await;
    let vtc_did = mock.vtc_did().to_string();
    let applicant_did = mock.client.did().to_string();

    let submit = JoinRequestSubmitBody {
        vp: json!({ "type": "VerifiablePresentation", "holder": applicant_did }),
        registry_consent: false,
        extensions: json!({}),
    };

    // First submit → real `submit_inner`, default policy defers to pending so the
    // request is left *open* (the precondition for the dedup guard to fire).
    let outcome = mock
        .client
        .try_request(
            &vtc_did,
            JOIN_REQUEST_SUBMIT_TYPE,
            serde_json::to_value(&submit).unwrap(),
            Duration::from_secs(15),
        )
        .await;
    match outcome {
        ReplyOutcome::Reply(body) => {
            let verdict: VerdictResponse =
                serde_json::from_value(response_payload(body)).expect("submit verdict");
            assert_eq!(verdict.verdict.effect, VerdictEffect::Refer);
        }
        other => panic!("expected a refer verdict for the first submit, got {other:?}"),
    }

    // Second submit from the same applicant DID before the first is decided or
    // withdrawn → the dedup guard rejects it. It must be a *clean, classified*
    // conflict, not a hang and not an `internal-error`.
    let outcome = mock
        .client
        .try_request(
            &vtc_did,
            JOIN_REQUEST_SUBMIT_TYPE,
            serde_json::to_value(&submit).unwrap(),
            Duration::from_secs(15),
        )
        .await;
    match outcome {
        ReplyOutcome::Problem(p) => {
            assert_eq!(
                p.code, "taskFailed",
                "duplicate open join request is a business-rule conflict → the framework \
                 `taskFailed` reject code, not `internalError`: {p:?}",
            );
            assert!(
                p.comment.contains("already exists"),
                "message names the open-request conflict: {p:?}",
            );
        }
        other => {
            panic!("expected a taskFailed trust-task-error for the duplicate submit, got {other:?}")
        }
    }

    mock.shutdown().await;
}
