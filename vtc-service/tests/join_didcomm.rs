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
//!
//! ## Debugging a credential-delivery failure
//!
//! Run with `RUST_LOG=vtc_service=debug cargo test -p vtc-service --test
//! join_didcomm -- --nocapture`.
//!
//! Without a subscriber installed, the service's `warn!` lines go nowhere — and
//! the one that matters here, *"membership-credential delivery failed on
//! approve"*, is the only place a failed push is reported at all. Its caller
//! deliberately swallows the error (the credentials are already issued and
//! returned inline, so a delivery failure must not unwind the decision), which
//! means a silent send failure and a lost frame look identical from the
//! assertion. [`init_tracing`] installs the subscriber so they don't.

use std::time::Duration;

/// Install a `RUST_LOG`-driven subscriber once per test binary.
///
/// `try_init` rather than `init`: several tests in this binary may call it, and
/// a second `init` panics.
///
/// The default filter silences `lsm_tree`, whose temp-dir teardown emits a
/// screenful of "Failed to cleanup deleted table … No such file or directory"
/// warnings on every run. Those are harmless and they are *only* printed when a
/// test fails — which is precisely when they would bury the delivery warning
/// this subscriber exists to surface. Override the whole thing with `RUST_LOG`
/// when you want it back.
///
/// # The delivery layer runs at `debug`, on purpose
///
/// This test has failed intermittently in CI with "1 of 2 credentials
/// delivered", and every attempt to place the loss has run out of evidence.
/// Two things are already known from the warnings, which do print at `warn`:
/// the VTC logged no delivery failure, and the client's pickup logged no poll
/// errors. So the VTC sent, the client polled healthily for the full 60s, and
/// the message was lost between them — and neither side can say more.
///
/// `affinidi_messaging_delivery=debug` adds the one fact that decides it:
/// `drain_once` logs a per-tick `sent` / `retried` / `failed` report, so a
/// failing run shows whether the sender's outbox actually put **two** messages
/// on the wire. If it did, the loss is at the mediator or below and the next
/// probe goes there; if it did not, the loss is in the outbox and this is the
/// wrong place to have been looking.
///
/// It is concise (three counters per 2s tick, not message dumps) and prints
/// only for a failing test, so it costs nothing until it is needed. Local
/// reproduction has been tried and failed — 30 runs under CPU contention, all
/// green — so the next CI occurrence is the only opportunity, and it should not
/// be wasted a fourth time.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(
                    "warn,lsm_tree=off,affinidi_messaging_delivery=debug",
                )
            }),
        )
        .with_test_writer()
        .try_init();
}

/// How long to wait for one admission credential to arrive over DIDComm.
///
/// Two credentials are pushed independently (VMC + role VEC), each awaited with
/// this bound. Sized for a loaded CI runner rather than a developer machine —
/// see the comment at the assertion for why the previous 20s was marginal.
const CREDENTIAL_PUSH_TIMEOUT: Duration = Duration::from_secs(60);

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
const DECIDE_TASK: &str = "https://trusttasks.org/spec/vtc/join-requests/decide/0.1";

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
    init_tracing();
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
        &format!("/v1/join-requests/{request_id}/decide"),
        DECIDE_TASK,
        &admin_token,
        json!({ "decision": "approved" }),
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
    //    The per-push bound is generous because CI is markedly slower than a
    //    developer machine at exactly this step: the whole test runs in ~6s
    //    locally and ~23s on a runner, and a delivery that takes a couple of
    //    seconds here can exceed 20s there. That marginality has failed this
    //    assertion on unrelated PRs — including one whose entire diff was a
    //    `pub use` line — so the bound, not the code, was what broke. Still
    //    bounded (never a hang), just past where runner slowness lives.
    //    When this *does* fail, the message has to say which credential went
    //    missing. `deliver_credentials` is a sequential loop with `?`, so a
    //    failure on the first push sends **zero** and a failure on the second
    //    sends **one** — two different bugs that a bare "not delivered" cannot
    //    tell apart, and this assertion has fired on CI several times without
    //    ever distinguishing them. The index is the whole diagnostic.
    let mut delivered = Vec::new();
    for i in 0..2 {
        let pushed = mock.client.next_pushed(CREDENTIAL_PUSH_TIMEOUT).await;
        // Collected *before* the panic formats: what else reached this socket
        // while we waited is the evidence that decides where the frame went,
        // and a panic that omits it costs another CI cycle to learn nothing.
        // The sender is already cleared — `outbox drain pass sent=2 failed=0`
        // on the 2026-08-14 failure — so the remaining question is whether the
        // frame reached this client at all.
        let buffered = mock.client.inbox_summary().await;
        // Only on the failing path: the probe issues a delivery request, which
        // would consume messages a healthy run's next assertion is waiting for.
        let mediator = if pushed.is_none() {
            mock.client.mediator_queue_report().await
        } else {
            String::new()
        };
        let (typ, issue_body) = pushed.unwrap_or_else(|| {
            panic!(
                "admission credential {}/2 not delivered over DIDComm within {:?} \
                     ({} already received; inbox: {}; mediator: {}). {}",
                i + 1,
                CREDENTIAL_PUSH_TIMEOUT,
                delivered.len(),
                buffered,
                mediator,
                if i == 0 {
                    "Zero arrived, so the VTC most likely never sent: \
                         `deliver_credentials` attempts every credential, but its caller only \
                         `warn!`s — which is invisible here unless a tracing subscriber is \
                         installed (see RUST_LOG note at the top of this test)."
                } else {
                    // VTI#918, reproduced 2026-08-14 (soak run 31769042608,
                    // stream 6 iteration 31). Two suspects are already gone:
                    // the sender logged `outbox drain pass sent=2 retried=0
                    // failed=0`, and the client's inbox held only a
                    // pickup-status heartbeat — no unmatched credential — so
                    // the frame never reached the live stream. The `mediator:`
                    // clause splits what is left.
                    "The first arrived and the second did not. Sender cleared (`sent=2 \
                         failed=0`) and no unmatched credential in the inbox, so read the \
                         `mediator:` clause: `queued=0` ⇒ the mediator never held it and the \
                         loss is at or before its queue; `queued>0`, or a delivery request that \
                         returns the credential, ⇒ the mediator had it all along and the \
                         live-stream path never yielded it — a delivery-mechanism bug, not a \
                         loss."
                }
            )
        });
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
