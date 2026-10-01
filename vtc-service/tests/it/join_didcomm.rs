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
//!   5. admin `approve` as a signed document              → real ceremony issues the VMC + role VAC
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
/// Two credentials are pushed independently (VMC + role VAC), each awaited with
/// this bound. Sized for a loaded CI runner rather than a developer machine —
/// see the comment at the assertion for why the previous 20s was marginal.
const CREDENTIAL_PUSH_TIMEOUT: Duration = Duration::from_secs(60);

use axum::http::StatusCode;
use serde_json::json;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::auth::session::now_epoch;
use vtc_service::schemas::accepts::{AcceptsCriterion, store_accepts};
use vtc_service::test_support::{MockVtcDidcomm, ReplyOutcome};

use vta_sdk::protocols::credential_exchange::{ISSUE as CREDENTIAL_ISSUE_TYPE, IssueBody};
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_MANIFEST_TYPE, JOIN_REQUEST_STATUS_TYPE, JOIN_REQUEST_SUBMIT_TYPE,
    JoinRequestStatusBody, JoinRequestStatusResponseBody, JoinRequestSubmitBody, VerdictEffect,
    VerdictResponse, manifest,
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
            vetting: None,
            hidden_vetting: None,
            created_at: chrono::Utc::now(),
            created_by_did: ADMIN_DID.into(),
        },
    )
    .await
    .expect("store Accepts criterion");

    mock.vtc.token(ADMIN_DID, "admin", vec![]).await
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
        attributes: Vec::new(),
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
    //    manifest read) — the seeded DCQL Accepts criterion.
    let manifest: manifest::v0_1::Response = serde_json::from_value(response_payload(
        mock.client
            .request(&vtc_did, JOIN_REQUEST_MANIFEST_TYPE, json!({}))
            .await,
    ))
    .expect("manifest response");
    assert_eq!(manifest.community_did.as_str(), vtc_did);
    let criterion = manifest
        .criteria
        .iter()
        .find(|c| c.id.as_str() == "membership")
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
    let presentation_definition =
        serde_json::Value::Object(criterion.presentation_definition.clone());
    let candidates = select_credentials(&presentation_definition, &[held])
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
                serde_json::to_value(JoinRequestStatusBody {
                    request_id: Some(request_id),
                })
                .unwrap(),
            )
            .await,
    ))
    .expect("status response");
    assert_eq!(status.status, "pending");

    // 4b. The same poll with **no** request id — "what is my open request?".
    //
    // This is the only form available to an applicant whose first correlated
    // reply was lost: the id it would otherwise quote is the community's, learned
    // from that reply, so it holds nothing this VTC recognises. Requiring the id
    // made the poll unusable in precisely the case it exists for.
    //
    // The response must name the id, because that is what repairs the
    // applicant's record and makes every later poll possible.
    let recovered: JoinRequestStatusResponseBody = serde_json::from_value(response_payload(
        mock.client
            .request(
                &vtc_did,
                JOIN_REQUEST_STATUS_TYPE,
                serde_json::to_value(JoinRequestStatusBody { request_id: None }).unwrap(),
            )
            .await,
    ))
    .expect("id-less status response");
    assert_eq!(
        recovered.request_id, request_id,
        "the community must name the request id it minted — an applicant that \
         cannot learn it stays unable to poll forever"
    );
    assert_eq!(recovered.status, "pending");

    // 5. An administrator approves with a signed decision — the real ceremony
    //    admits the applicant, issues the VMC + role VAC, and pushes them to
    //    the applicant's wallet over DIDComm (`deliver_membership_credentials`).
    let _ = admin_token;
    let admin = crate::common::signed::admin(&mock.vtc).await;
    let (code, doc) = crate::common::signed::call(
        &mock.vtc,
        &admin,
        DECIDE_TASK,
        json!({ "id": request_id, "decision": "approved" }),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "approve failed: {doc}");
    assert_eq!(doc["payload"]["status"], "approved", "{doc}");

    // 6. The membership credential lands at the applicant over DIDComm — the
    //    full push the activation path (T6) needs.
    //
    //    Admission delivers *two* credentials (the VMC and the role VAC) as
    //    independent one-way messages — `deliver_credentials` opens a fresh
    //    thread per credential, and each is forwarded through the mediator
    //    separately. Arrival order is therefore not guaranteed, so collect both
    //    pushes and look for the VMC among them rather than asserting it is the
    //    first to land (which flaked in CI when the VAC overtook it).
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

    // The role VAC is the other half of the admission push.
    let vec_cred = delivered
        .iter()
        .find(|c| has_type(c, "AuthorityCredential"))
        .unwrap_or_else(|| panic!("a role AuthorityCredential was delivered: {delivered:#?}"));
    assert_eq!(
        vec_cred["credentialSubject"]["id"], applicant_did,
        "role VAC subject is the applicant"
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
        attributes: Vec::new(),
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
        attributes: Vec::new(),
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
            // #485's original point, unchanged: this is a business-rule
            // refusal, so it must never arrive in the `internalError` bucket
            // that the fuzzer flags and that tells a client to blame the server.
            assert_ne!(
                p.code, "internalError",
                "a duplicate open join request is an expected condition, not a server fault: {p:?}",
            );
            // And it is now *named*, rather than merely not-a-fault. The code
            // is consumer-minted under the submit slug (SPEC.md §8.5); a client
            // that does not know it still reads `taskFailed` by that section's
            // fallback rule, which is what keeps this additive.
            assert_eq!(
                p.code,
                vta_sdk::protocols::join_requests::JOIN_REQUEST_SUBMIT_ERR_REQUEST_ALREADY_OPEN,
                "the duplicate-submit refusal carries its own code: {p:?}",
            );
            // The annex is the half a client can act on without parsing prose:
            // `requestId` is what it passes to withdraw, and `status` is what
            // says whether the open request is waiting on the community
            // (`pending`) or on the applicant (`deferred`).
            let details = p
                .body
                .pointer("/payload/details")
                .unwrap_or_else(|| panic!("no payload.details in {p:?}"));
            assert!(
                details["requestId"]
                    .as_str()
                    .is_some_and(|id| !id.is_empty()),
                "details names the request in the way: {p:?}",
            );
            assert_eq!(details["status"], "pending", "{p:?}");
            assert!(
                p.comment.contains("already exists"),
                "message names the open-request conflict: {p:?}",
            );
        }
        other => panic!("expected a trust-task-error for the duplicate submit, got {other:?}"),
    }

    mock.shutdown().await;
}

/// Keyring VTI-21: `vtc/invitations/deliver` on the `message` channel pushes a
/// `credential-exchange/offer` to the invited DID over the community's
/// mediator. The offer names the community and carries a pre-authorized code;
/// the invitation itself travels only on redemption, which is covered over
/// HTTPS in `tests/invitations.rs`.
#[tokio::test]
async fn a_delivered_invitation_arrives_as_an_offer() {
    let mock = MockVtcDidcomm::start().await;
    let admin_token = seed_join_ceremony(&mock).await;
    let vtc_did = mock.vtc_did().to_string();
    let invitee = mock.client.did().to_string();

    let _ = admin_token;
    // The invitation verbs are signed documents; an administrator of the
    // community signs them.
    let admin = crate::common::signed::admin(&mock.vtc).await;
    let (status, issued) = crate::common::signed::call(
        &mock.vtc,
        &admin,
        "https://trusttasks.org/spec/vtc/invitations/issue/0.1",
        json!({ "subjectDid": invitee }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let id = issued["payload"]["vic"]["id"]
        .as_str()
        .expect("vic id")
        .to_string();

    let (status, delivered) = crate::common::signed::call(
        &mock.vtc,
        &admin,
        "https://trusttasks.org/spec/vtc/invitations/deliver/0.1",
        json!({ "id": id, "channel": "message" }),
    )
    .await;
    let delivered = delivered["payload"].clone();
    assert_eq!(status, StatusCode::OK, "{delivered}");
    assert!(
        delivered.get("offer").is_none(),
        "the offer went to the invitee: {delivered}"
    );

    let offer_doc = mock
        .client
        .next_pushed_document(Duration::from_secs(15))
        .await
        .expect("the offer reaches the invited DID");
    assert_eq!(
        offer_doc["type"],
        vta_sdk::protocols::credential_exchange::OFFER
    );
    assert_eq!(offer_doc["issuer"], vtc_did);
    assert_eq!(offer_doc["recipient"], invitee);
    assert!(
        offer_doc["proof"].is_object(),
        "a pushed offer is a signed Trust Task: {offer_doc}"
    );
    let body = &offer_doc["payload"];
    let offer = &body["credential_offer"];
    assert_eq!(offer["credential_issuer"], vtc_did);
    let code = offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        ["pre-authorized_code"]
        .as_str()
        .unwrap_or_else(|| panic!("the offer carries a pre-authorized code: {offer}"))
        .to_string();
    assert!(body.get("credential").is_none() && offer.get("credential").is_none());

    // The invitee answers on the offer's thread with a `request` whose
    // key-binding proof is by its own DID key. The transport carries back only
    // the empty `#response` courtesy acknowledgement (SPEC §4.4.2)...
    let offer_id = offer_doc["id"].as_str().expect("offer id").to_string();
    let request = mock.client.credential_request(
        &vtc_did,
        &code,
        "https://openvtc.org/credentials/InvitationCredential",
    );
    match mock
        .client
        .try_request_in_thread(
            &vtc_did,
            vta_sdk::protocols::credential_exchange::REQUEST,
            request,
            &offer_id,
            Duration::from_secs(15),
        )
        .await
    {
        ReplyOutcome::Reply(ack) => {
            assert_eq!(
                ack["type"],
                format!(
                    "{}#response",
                    vta_sdk::protocols::credential_exchange::REQUEST
                ),
                "{ack}"
            );
            assert_eq!(
                ack["payload"],
                json!({}),
                "an acknowledgement carries nothing"
            );
        }
        other => panic!("the request was not accepted: {other:?}"),
    }

    // ...and the credential arrives as the next task on the thread: a signed
    // `credential-exchange/issue` to the invitee.
    let issue_doc = mock
        .client
        .next_trust_task(Duration::from_secs(15))
        .await
        .expect("the invitation is issued to the invitee");
    assert_eq!(
        issue_doc["type"],
        vta_sdk::protocols::credential_exchange::ISSUE
    );
    assert_eq!(
        issue_doc["threadId"], offer_id,
        "issue answers on the offer's thread"
    );
    assert_eq!(issue_doc["recipient"], invitee);
    assert!(issue_doc["proof"].is_object(), "{issue_doc}");
    let issue: IssueBody =
        serde_json::from_value(issue_doc["payload"].clone()).expect("issue payload");
    assert!(
        issue
            .credential_response
            .and_then(|r| r.credential)
            .is_some(),
        "the issue carries the invitation credential"
    );
}

/// A join query goes out as a signed `credential-exchange/query` whose `id` is
/// the thread its single-use challenge is keyed by, and the holder's `present`
/// on that thread is answered on the transport with the empty acknowledgement
/// and with a signed `join-requests/submit-receipt` pushed on the same thread.
///
/// Before, the query was a bare DIDComm message and the `present` a bare reply,
/// which the binding requires a consumer to refuse and TSP could not carry.
#[tokio::test]
async fn a_join_query_is_answered_by_a_present_on_its_thread() {
    init_tracing();
    let mock = MockVtcDidcomm::start().await;
    seed_join_ceremony(&mock).await;
    let vtc_did = mock.vtc_did().to_string();
    let holder = mock.client.did().to_string();

    let admin = crate::common::signed::admin(&mock.vtc).await;
    let (status, sent) = crate::common::signed::call(
        &mock.vtc,
        &admin,
        "https://trusttasks.org/spec/vtc/join-requests/query/0.1",
        json!({ "holderDid": holder, "criterionId": "membership" }),
    )
    .await;
    let sent = sent["payload"].clone();
    assert_eq!(status, StatusCode::OK, "{sent}");
    assert_eq!(
        sent["delivered"], true,
        "the query was queued to the holder: {sent}"
    );
    let thread_id = sent["threadId"].as_str().expect("threadId").to_string();

    let query_doc = mock
        .client
        .next_pushed_document(Duration::from_secs(15))
        .await
        .expect("the query reaches the holder");
    assert_eq!(
        query_doc["type"],
        vta_sdk::protocols::credential_exchange::QUERY
    );
    assert_eq!(
        query_doc["id"], thread_id,
        "the query opens the challenge's thread"
    );
    assert!(query_doc["proof"].is_object(), "{query_doc}");
    let nonce = query_doc["payload"]["nonce"]
        .as_str()
        .expect("the query carries its nonce")
        .to_string();

    // A held credential that verifies: self-issued by the holder's key, which is
    // all this test needs — whether the issuer is trusted is the join policy's
    // question, and a referral still produces a receipt.
    let holder_key = mock.client.holder_secret();
    let issuer_did = holder_key.id.split('#').next().unwrap().to_string();
    let subject = json!({ "id": issuer_did, "givenName": "Ada", "memberSince": "2024-01-01" });
    let mut vc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "MembershipCredential"],
        "issuer": issuer_did,
        "validFrom": "2024-01-01T00:00:00Z",
        "credentialSubject": subject,
    });
    let vc_proof = affinidi_data_integrity::DataIntegrityProof::sign(
        &vc,
        holder_key,
        affinidi_data_integrity::SignOptions::new().with_proof_purpose("assertionMethod"),
    )
    .await
    .expect("sign the held credential");
    vc["proof"] = serde_json::to_value(&vc_proof).expect("a proof serialises");
    let held = HeldCredential {
        id: "vmc-held".into(),
        format: "ldp_vc".into(),
        claims: subject.clone(),
        vct: None,
        doctype: None,
        supports_holder_binding: true,
        vc,
    };
    let dcql = query_doc["payload"]["dcql_query"].clone();
    let candidates =
        select_credentials(&dcql, &[held]).expect("the held credential satisfies the query");
    let vp_token = build_vp_token(&candidates, mock.client.holder_secret(), &nonce, &vtc_did)
        .await
        .expect("assemble vp_token");

    match mock
        .client
        .try_request_in_thread(
            &vtc_did,
            vta_sdk::protocols::credential_exchange::PRESENT,
            json!({ "vp_token": vp_token }),
            &thread_id,
            Duration::from_secs(20),
        )
        .await
    {
        ReplyOutcome::Reply(ack) => {
            assert_eq!(
                ack["type"],
                format!(
                    "{}#response",
                    vta_sdk::protocols::credential_exchange::PRESENT
                ),
                "{ack}"
            );
            assert_eq!(ack["payload"], json!({}));
        }
        other => panic!("the present was not accepted: {other:?}"),
    }

    let receipt = mock
        .client
        .next_trust_task(Duration::from_secs(15))
        .await
        .expect("the submit receipt reaches the presenter");
    assert_eq!(
        receipt["type"],
        vta_sdk::protocols::join_requests::JOIN_REQUEST_SUBMIT_RECEIPT_TYPE
    );
    assert_eq!(receipt["threadId"], thread_id);
    assert_eq!(receipt["recipient"], holder);
    assert!(receipt["proof"].is_object(), "{receipt}");
    assert!(
        receipt["payload"]["requestId"].is_string(),
        "the receipt names the join request: {receipt}"
    );
    mock.shutdown().await;
}

/// `credential-exchange/request` and `present` are served on the spine, and
/// only there: typed as themselves — the bare DIDComm shape the VTC used to
/// answer — they are refused at the DIDComm layer naming the binding envelope
/// (`bindings/didcomm/0.2` §2). The general census in
/// `didcomm_envelope_binding.rs` covers every dispatched URI; this pins the two
/// that were the last bare arms, so reintroducing one fails by name.
#[tokio::test]
async fn a_bare_credential_exchange_step_is_refused_naming_the_envelope() {
    let mock = MockVtcDidcomm::start().await;
    let vtc_did = mock.vtc_did().to_string();
    for uri in [
        vta_sdk::protocols::credential_exchange::REQUEST,
        vta_sdk::protocols::credential_exchange::PRESENT,
    ] {
        match mock
            .client
            .try_request_task_typed(&vtc_did, uri, json!({}), Duration::from_secs(15))
            .await
        {
            ReplyOutcome::Problem(p) => assert!(
                p.comment
                    .contains(vti_common::capability_client::TRUST_TASK_ENVELOPE_TYPE),
                "{uri}: the refusal names the envelope: {p:?}"
            ),
            other => panic!("{uri} typed as itself must be refused, got {other:?}"),
        }
    }
    mock.shutdown().await;
}
