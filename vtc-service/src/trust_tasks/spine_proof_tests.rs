//! The spine's document-level gate: VTI-OPS-020 (a proof by the issuer),
//! VTI-OPS-021 / -093 (the same requirements on every transport), VTI-OPS-024
//! (the acceptance window) and VTI-OPS-025…027 (the replay record).
//!
//! # What this module used to say, and why it no longer does
//!
//! It held one test, `a_transport_authenticated_task_declares_a_proof_it_does_
//! not_carry`, whose assertion was deliberately inverted: it recorded that
//! `join-requests/submit` declares a proof REQUIRED *while this service accepts
//! it without one*, so that "the next person to reach for `spec_policy_for` as
//! an enforcement gate meets it as a failing test rather than as a total
//! outage."
//!
//! The warning was right about the consequence and wrong about the conclusion.
//! Three documents refuse the leniency outright — VTI-OPS-021, VTI-OPS-093, and
//! the DIDComm binding's own §5 ("a *Trust Task specification* that declares
//! `proof` as REQUIRED overrides this binding-level allowance"). So the gate is
//! now the specification's, and the outage it predicted was real for exactly
//! one client: `openvtc-core`, which sent five of these documents unsigned.
//!
//! #1641 met that by gating the refusal behind `[trust_tasks]
//! require_declared_proof`, default `false`, whose rustdoc carried an exact
//! removal condition — "when `openvtc-core` signs the five documents above, the
//! default flips and this field goes with it". openvtc#371 signs them, so the
//! gate is gone and every test here now asserts against the requirement
//! directly, on all three transports.
//!
//! See `docs/05-design-notes/vtc-trust-task-proof-enforcement.md`.
//!
//! Moved out of `trust_tasks/mod.rs` (#2579).

use super::*;
use crate::test_support::{TEST_VTC_DID, build_test_vtc};
use serde_json::json;

// One holder: a `did:key` and the private key behind it, minted the same
// way the rooms fixtures mint theirs.
use vti_rooms_dtg::test_support::Party as Holder;

fn holder() -> Holder {
    Holder::new()
}

/// The unsigned document, exactly as it goes on the wire minus the proof.
/// `build_unsigned` is the SDK's own builder, so `issuer`, `recipient` and
/// `issuedAt` are set the way every real producer sets them and the tests
/// vary only what they mean to.
fn unsigned(h: &Holder, uri: &str, payload: Value) -> TrustTask<Value> {
    vta_sdk::trust_task_sign::build_unsigned(uri, payload, &h.did, TEST_VTC_DID)
        .expect("build the document")
}

async fn signed(h: &Holder, doc: TrustTask<Value>) -> TrustTask<Value> {
    let mut doc = doc;
    let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(&h.did, &h.secret_multibase)
        .expect("a did:key names its own verification method");
    vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
        .await
        .expect("sign the document");
    doc
}

/// The `code` of the `trust-task-error` an outcome carries, or `None` when
/// the outcome is not an error document.
fn error_code(out: &TrustTaskOutcome) -> Option<String> {
    let doc: Value = serde_json::from_slice(&out.body).ok()?;
    doc.pointer("/payload/code")?.as_str().map(str::to_string)
}

async fn dispatch(state: &AppState, doc: &TrustTask<Value>) -> TrustTaskOutcome {
    let body = serde_json::to_vec(doc).expect("a document serialises");
    dispatch_trust_task_core(state, &JoinAuthCtx::rest(), &body).await
}

/// The URI these tests drive. `vtc/join-requests/status/0.1` declares
/// `proof` REQUIRED and needs no seeded community state to reach its
/// handler, so what the spine does is the only thing that varies.
const UNDER_TEST: &str = jr::JOIN_REQUEST_STATUS_TYPE;

/// The premise the rest of this module rests on. If the registry ever
/// relaxes the declaration, these tests are asserting nothing and this one
/// says so first.
#[test]
fn the_task_under_test_declares_a_proof_required() {
    let policy = vti_specs::schema_index::spec_policy_for(UNDER_TEST)
        .expect("the task under test has a published spec policy");
    assert!(
        policy.is_proof_required,
        "{UNDER_TEST} no longer declares proof REQUIRED — these tests now \
         assert nothing, and the design note should be re-read"
    );
}

/// **VTI-OPS-020 / VTI-OPS-021.** A task whose specification declares
/// `proof` REQUIRED is refused when it carries none, with the framework's
/// own code for exactly that.
#[tokio::test]
async fn vti_ops_020_a_proof_required_task_is_refused_without_a_proof() {
    let tv = build_test_vtc().await;
    let h = holder();
    let out = dispatch(&tv.state, &unsigned(&h, UNDER_TEST, json!({}))).await;

    assert_eq!(
        error_code(&out).as_deref(),
        Some("proofRequired"),
        "SPEC §7.2 item 7 names the code: {}",
        String::from_utf8_lossy(&out.body)
    );
}

/// …and accepted with one. "Accepted" here means the spine let it through
/// to the handler, which is the whole of what the spine decides — the
/// handler then answers for a status poll on a request that does not
/// exist, and that answer is not this module's business.
#[tokio::test]
async fn vti_ops_020_the_same_document_is_accepted_once_it_is_signed() {
    let tv = build_test_vtc().await;
    let h = holder();
    let doc = signed(&h, unsigned(&h, UNDER_TEST, json!({}))).await;
    let out = dispatch(&tv.state, &doc).await;

    assert_ne!(
        error_code(&out).as_deref(),
        Some("proofRequired"),
        "a signed document must reach its handler: {}",
        String::from_utf8_lossy(&out.body)
    );
    assert_ne!(
        error_code(&out).as_deref(),
        Some("proofInvalid"),
        "the spine must accept a proof it can verify: {}",
        String::from_utf8_lossy(&out.body)
    );
}

/// **VTI-OPS-020.** SPEC §4.7: the proof's `verificationMethod` "MUST
/// resolve to verification material controlled by the *party* identified by
/// the document's `issuer`". A valid signature by some *other* holder is
/// not a proof by the issuer, and before #1641 it satisfied the
/// requirement — establishing only that somebody signed something, which is
/// not what `verified_signer` is read as downstream.
#[tokio::test]
async fn vti_ops_020_a_proof_by_a_key_the_issuer_does_not_control_is_refused() {
    let tv = build_test_vtc().await;
    let issuer = holder();
    let impostor = holder();

    // Addressed from `issuer`, signed by `impostor`.
    let doc = signed(&impostor, unsigned(&issuer, UNDER_TEST, json!({}))).await;
    let out = dispatch(&tv.state, &doc).await;

    assert_eq!(
        error_code(&out).as_deref(),
        Some("proofInvalid"),
        "{}",
        String::from_utf8_lossy(&out.body)
    );
}

/// **VTI-OPS-024.** A document issued longer ago than the acceptance
/// window is outside it, and `expired` is the code for a document that was
/// once acceptable and no longer is.
#[tokio::test]
async fn vti_ops_024_an_issued_at_older_than_the_window_is_refused() {
    let tv = build_test_vtc().await;
    let h = holder();
    let mut doc = unsigned(&h, UNDER_TEST, json!({}));
    doc.issued_at = Some(chrono::Utc::now() - chrono::TimeDelta::hours(2));
    let doc = signed(&h, doc).await;

    assert_eq!(
        error_code(&dispatch(&tv.state, &doc).await).as_deref(),
        Some("expired"),
    );
}

/// **VTI-OPS-024**, the other end of the window, and the skew tolerance
/// that bounds it. SPEC §7.2 item 13 makes a future-dated document
/// `malformedRequest` rather than `expired`: it was never acceptable, so
/// telling the producer to wait would be wrong — it must reissue.
#[tokio::test]
async fn vti_ops_024_a_future_dated_issued_at_is_malformed_not_expired() {
    let tv = build_test_vtc().await;
    let h = holder();
    let mut doc = unsigned(&h, UNDER_TEST, json!({}));
    doc.issued_at = Some(chrono::Utc::now() + chrono::TimeDelta::minutes(30));
    let doc = signed(&h, doc).await;

    assert_eq!(
        error_code(&dispatch(&tv.state, &doc).await).as_deref(),
        Some("malformedRequest"),
    );
}

/// …and a document inside the skew tolerance is not. 30 seconds ahead of
/// this consumer's clock is an ordinary clock disagreement, and refusing it
/// would make the window depend on whose NTP is better.
#[tokio::test]
async fn vti_ops_024_a_document_inside_the_skew_tolerance_is_accepted() {
    let tv = build_test_vtc().await;
    let h = holder();
    let mut doc = unsigned(&h, UNDER_TEST, json!({}));
    doc.issued_at = Some(chrono::Utc::now() + chrono::TimeDelta::seconds(30));
    let doc = signed(&h, doc).await;
    let out = dispatch(&tv.state, &doc).await;

    assert_ne!(
        error_code(&out).as_deref(),
        Some("malformedRequest"),
        "60s of skew is SPEC §4.2's own tolerance: {}",
        String::from_utf8_lossy(&out.body)
    );
}

/// Give `h` an open join request, so a status poll from them **succeeds**.
///
/// The replay tests below need that: the spine releases a claim whose
/// dispatch failed — deliberately, so a corrected resend under the same
/// `id` is not refused as a conflict for the rest of the retention window
/// — and a test driving a failing task would therefore assert against a
/// record that was never kept.
async fn seed_open_request(state: &AppState, h: &Holder) {
    let request = crate::join::JoinRequest::new(h.did.clone(), serde_json::json!({ "vp": "x" }));
    crate::join::storage::store_join_request(&state.join_requests_ks, &request)
        .await
        .expect("seed an open join request");
}

/// **VTI-OPS-020's replay half (VTI-OPS-025…027), SPEC §7.2 item 11.** The
/// same document delivered twice executes once. A duplicate is answered
/// with the original result rather than an error — "in no case is a
/// duplicate reported as `taskFailed`; the task did not fail, it already
/// happened" — so the assertion is that the second answer is the first.
///
/// Compared as parsed JSON rather than as bytes: the duplicate path
/// re-serialises the recorded `Value`, and `serde_json` without
/// `preserve_order` alphabetises a `Map`'s keys, so the two are the same
/// document and not the same bytes.
#[tokio::test]
async fn vti_ops_025_a_replayed_document_is_answered_not_executed_again() {
    let tv = build_test_vtc().await;
    let h = holder();
    seed_open_request(&tv.state, &h).await;
    let doc = signed(&h, unsigned(&h, UNDER_TEST, json!({}))).await;

    let first = dispatch(&tv.state, &doc).await;
    assert!(
        first.status.is_success(),
        "the fixture must reach a succeeding handler, or the claim is \
         released and the second dispatch runs fresh: {}",
        String::from_utf8_lossy(&first.body)
    );

    let second = dispatch(&tv.state, &doc).await;
    assert_eq!(first.status, second.status);

    let as_json = |out: &TrustTaskOutcome| -> Value {
        serde_json::from_slice(&out.body).expect("the answer is a document")
    };
    assert_eq!(
        as_json(&first),
        as_json(&second),
        "a redelivery is the same document, so it gets the same answer"
    );
}

/// **SPEC §7.2 item 11's conflict half.** A *different* document under an
/// already-spent `id` is `idConflict`, never absorbed as a retry — which is
/// why the record is keyed by digest rather than by `id` alone.
#[tokio::test]
async fn vti_ops_025_a_different_document_reusing_an_id_is_a_conflict() {
    let tv = build_test_vtc().await;
    let h = holder();
    seed_open_request(&tv.state, &h).await;

    let first = signed(&h, unsigned(&h, UNDER_TEST, json!({}))).await;
    let out = dispatch(&tv.state, &first).await;
    assert!(
        out.status.is_success(),
        "{}",
        String::from_utf8_lossy(&out.body)
    );

    // Same `id`, different content: a different document, not a retry.
    let mut second = unsigned(&h, UNDER_TEST, json!({}));
    second.id = first.id.clone();
    second.issued_at = Some(chrono::Utc::now() - chrono::TimeDelta::seconds(1));
    let second = signed(&h, second).await;

    assert_eq!(
        error_code(&dispatch(&tv.state, &second).await).as_deref(),
        Some("idConflict"),
    );
}

/// **VTI-OPS-028 + VTI-OPS-029.** Acceptance and retention are one bound.
/// A document stamped ten years out is acceptable only to the thirty-day
/// horizon, so its record is kept to the horizon (plus the skew), not for
/// ten years.
#[test]
fn vti_ops_029_a_far_expiry_is_retained_to_the_horizon() {
    let h = holder();
    let now = chrono::Utc::now();
    let mut doc = unsigned(&h, UNDER_TEST, json!({}));
    doc.issued_at = Some(now);
    doc.expires_at = Some(now + chrono::TimeDelta::days(3650));

    let policy = freshness_policy();
    let until = retain_until(&doc, now).expect("a document with an issuedAt is boundable");
    assert_eq!(
        until,
        now + vti_common::trust_task::acceptance::EXPIRY_HORIZON + policy.skew,
    );
}

/// **VTI-OPS-029.** A stated expiry inside the horizon is the acceptance
/// end, whatever the maximum age: the record is kept to it, plus the skew.
/// A record kept for the ten-minute window would let a replay of a
/// day-long document an hour later execute twice.
#[test]
fn vti_ops_029_a_stated_expiry_is_retained_past_the_maximum_age() {
    let h = holder();
    let now = chrono::Utc::now();
    let mut doc = unsigned(&h, UNDER_TEST, json!({}));
    doc.issued_at = Some(now);
    doc.expires_at = Some(now + chrono::TimeDelta::days(1));

    assert!(
        doc.validate_freshness(now + chrono::TimeDelta::hours(1), &freshness_policy())
            .is_ok(),
        "precondition: an hour on, the document is still acceptable"
    );
    let until = retain_until(&doc, now).expect("boundable");
    assert_eq!(
        until,
        now + chrono::TimeDelta::days(1) + freshness_policy().skew
    );
}

/// **VTI-OPS-021 / VTI-OPS-093.** One unsigned document, offered on every
/// transport this service accepts, refused on every one of them.
///
/// # Why this replaced three tests, and why the conclusion moved
///
/// #1641 shipped this ground as three: a REST document was refused; the
/// same document over DIDComm, carrying an authcrypt sender, was
/// **accepted** under the shipped default; and it was refused once the
/// operator set `[trust_tasks] require_declared_proof = true`. The middle
/// one existed to pin a transitional allowance, so that flipping the
/// default would be "a visible change to a test rather than a silent
/// change in behaviour". This is that change, made visible.
///
/// The allowance had exactly one reason: `openvtc-core` built
/// `join-requests/{submit,status}`, `members/{self-remove,vmc}` and
/// `members/personhood/assert` with no proof attached. openvtc#371 signs
/// all five, which is the removal condition #1659 wrote down. So the
/// assertion is not relaxed to match the code — it is inverted to match a
/// requirement that never had a transport term in it: "a node MUST apply
/// the same document requirements on every transport", and a transport that
/// authenticates its sender "MUST NOT be treated as relieving a producer of
/// addressing or signing the document it sends".
///
/// Driving all three transports from one body is the point rather than
/// thoroughness: the old tests each asserted about a single transport, so
/// between them they could have agreed with VTI-OPS-021 on two and
/// disagreed on the third without anything noticing.
#[tokio::test]
async fn vti_ops_021_a_missing_proof_is_refused_on_every_transport() {
    let tv = build_test_vtc().await;
    let h = holder();
    let body =
        serde_json::to_vec(&unsigned(&h, UNDER_TEST, json!({}))).expect("serialise document");

    for ctx in [
        JoinAuthCtx::rest(),
        JoinAuthCtx::didcomm(h.did.clone()),
        // TSP, whose sender VID is authenticated the way authcrypt's sender
        // is. It has no constructor — the messaging bridge builds one
        // inline — so this is that shape, written out.
        JoinAuthCtx {
            transport: JoinTransport::Tsp,
            sender_did: Some(h.did.clone()),
            verified_signer: None,
        },
    ] {
        let transport = ctx.transport.as_str();
        let out = dispatch_trust_task_core(&tv.state, &ctx, &body).await;

        assert_eq!(
            error_code(&out).as_deref(),
            Some("proofRequired"),
            "{transport}: an authenticated sender is not a proof by the issuer: {}",
            String::from_utf8_lossy(&out.body),
        );
    }
}

/// …and the refusal is about the missing proof, not about the transport.
///
/// Without this, the test above would pass equally on a spine that refused
/// every DIDComm and TSP document outright — which is a way of satisfying
/// "the same requirements on every transport" that takes the community
/// offline. Each iteration signs a fresh document: the same one dispatched
/// three times is a replay, and the second answer would be a replay of the
/// first rather than a new decision.
#[tokio::test]
async fn vti_ops_021_the_same_document_signed_is_accepted_on_every_transport() {
    let tv = build_test_vtc().await;
    let h = holder();

    for ctx in [
        JoinAuthCtx::rest(),
        JoinAuthCtx::didcomm(h.did.clone()),
        JoinAuthCtx {
            transport: JoinTransport::Tsp,
            sender_did: Some(h.did.clone()),
            verified_signer: None,
        },
    ] {
        let transport = ctx.transport.as_str();
        let doc = signed(&h, unsigned(&h, UNDER_TEST, json!({}))).await;
        let body = serde_json::to_vec(&doc).expect("serialise document");
        let out = dispatch_trust_task_core(&tv.state, &ctx, &body).await;

        assert_ne!(
            error_code(&out).as_deref(),
            Some("proofRequired"),
            "{transport}: a signed document must reach its handler: {}",
            String::from_utf8_lossy(&out.body),
        );
        assert_ne!(
            error_code(&out).as_deref(),
            Some("proofInvalid"),
            "{transport}: the spine must accept a proof it can verify: {}",
            String::from_utf8_lossy(&out.body),
        );
    }
}

/// Keyring VTI-09: a bare payload — no document around it — is refused as
/// `malformedRequest`, naming the missing `id`, on every transport. This is
/// the answer the VTA gives too (`vta-service`'s `keyring_vti_09_27`
/// tests); the finding was that the two disagreed.
#[tokio::test]
async fn vti_09_a_bare_payload_is_refused_as_malformed_on_every_transport() {
    let tv = build_test_vtc().await;
    let h = holder();
    let body = serde_json::to_vec(&json!({ "requestId": "urn:uuid:bare" })).unwrap();

    for ctx in [
        JoinAuthCtx::rest(),
        JoinAuthCtx::didcomm(h.did.clone()),
        JoinAuthCtx {
            transport: JoinTransport::Tsp,
            sender_did: Some(h.did.clone()),
            verified_signer: None,
        },
    ] {
        let transport = ctx.transport.as_str();
        let out = dispatch_trust_task_core(&tv.state, &ctx, &body).await;
        let doc: Value = serde_json::from_slice(&out.body).expect("an error document");
        assert_eq!(
            error_code(&out).as_deref(),
            Some("malformedRequest"),
            "{transport}: {doc}"
        );
        assert!(
            doc.pointer("/payload/message")
                .and_then(Value::as_str)
                .is_some_and(|m| m.contains("missing field `id`")),
            "{transport}: {doc}"
        );
    }
}

/// The rooms family, where the requirement was already enforced by the
/// arms in `dispatch_typed` before the spine took it on. Kept because the
/// arms' guard is now belt to the spine's brace, and a specification that
/// relaxed the declaration would leave that guard standing alone.
#[test]
fn every_rooms_task_declares_the_proof_its_arm_requires() {
    for uri in vti_rooms::wire::ROOMS_DISPATCHED_URIS {
        let policy = vti_specs::schema_index::spec_policy_for(uri)
            .unwrap_or_else(|| panic!("{uri} has no published spec policy"));
        assert!(
            policy.is_proof_required,
            "{uri}: its arm refuses without a verified signer, so the \
             specification had better agree that one is required"
        );
    }
}

/// Every dispatched URI whose specification declares no proof — named here
/// with the reason an unsigned caller is still refused, so that adding (or
/// removing) a task from this list is a decision somebody took rather than
/// a side effect of editing a specification.
///
/// A URI belongs here only because its *handler* enforces identity some
/// other way — an ACL row, a WebAuthn assertion, a bearer refresh token —
/// not because nobody got round to it. [`the_dispatched_set_declares_the_proofs_the_design_note_records`]
/// fails the build the moment a listed URI starts declaring a proof (a
/// stale entry) or an unlisted one stops (an unreasoned one).
const DISPATCHED_WITHOUT_PROOF: &[(&str, &str)] = &[
    (
        jr::JOIN_REQUEST_MANIFEST_TYPE,
        "a public read of the community's join criteria; names no identity to authorize",
    ),
    (
        directory_tasks::DISCLOSURE_TYPE,
        "a public read of what the directory discloses, answered to whoever the join manifest is",
    ),
    (
        directory_tasks::CARD_PUBLIC_TYPE,
        "a public read of a card its member published so that anyone may read it",
    ),
    (
        directory_tasks::IMAGES_GET_TYPE,
        "a picture read through the projection; an unsigned caller is the public, answered only a picture on a published external card",
    ),
    (
        vetting_wire::VETTING_VETTER_LIST_TYPE,
        "a public read of the vetter registry",
    ),
    (
        role_tasks::LIST_TYPE,
        "reads the role vocabulary; the handler authorizes from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        role_tasks::SHOW_TYPE,
        "reads one role; the handler authorizes from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        storage_tasks::LIST_TYPE,
        "reads the storage configs; the handler authorizes vtc.rooms.admin from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        storage_tasks::GET_TYPE,
        "reads one storage config; the handler authorizes vtc.rooms.admin from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        storage_tasks::PROBE_TYPE,
        "probes one storage config; the handler authorizes vtc.rooms.admin from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        room_admin_tasks::GET_TYPE,
        "reads one room's storage, limits, usage and migration; the handler authorizes vtc.rooms.admin from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        community_room_tasks::LIST_TYPE,
        "lists the rooms the community owns, with their details; the handler authorizes vtc.rooms.manage from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        community_room_tasks::GET_TYPE,
        "reads one room the community owns, with its details; the handler authorizes vtc.rooms.manage from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        community_room_tasks::LIST_V4_TYPE,
        "lists the rooms the community owns, with their details and states; the handler authorizes vtc.rooms.manage from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        community_room_tasks::GET_V4_TYPE,
        "reads one room the community owns, with its details and state; the handler authorizes vtc.rooms.manage from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    #[cfg(feature = "voting")]
    (
        election_tasks::BALLOT_BOXES_LIST_TYPE,
        "lists the trusted ballot boxes; the handler authorizes vtc.elections.manage from the signer's own entry (VTI-VOT-080), so an unsigned caller is refused regardless",
    ),
    (
        room_admin_tasks::USAGE_TYPE,
        "reads rooms' usage; the handler authorizes vtc.rooms.admin from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        vetting_wire::VETTING_VETTER_SHOW_TYPE,
        "a public read of the vetter registry",
    ),
    (
        admin_tasks::AUDIT_VERIFY_TYPE,
        "a read; the handler's admin bearer/ACL check refuses an unsigned caller regardless",
    ),
    (
        install_tasks::CLAIM_START_TYPE,
        "passkey install: no key exists to sign with until the passkey does; the one-time install token (and its claim code) the handler requires is the credential",
    ),
    (
        install_tasks::CLAIM_FINISH_TYPE,
        "passkey install: WebAuthn never exposes the passkey's key to sign a document with; the install token, the registration and an assertion by the registered key are the evidence",
    ),
    (
        install_tasks::CLAIM_START_V0_3_TYPE,
        "opens a claim and changes nothing; the install token and its claim code are the gate, and control of the founder's DID is proven by the finish, whose proof the specification requires",
    ),
    (
        install_tasks::BOOTSTRAP_TYPE,
        "first-admin onboarding, before any ACL entry exists to sign with; the one-time install token the handler requires is the credential",
    ),
    (
        recognise_tasks::CHALLENGE_TYPE,
        "names no identity to authorize — it is the first message of the cross-community handshake",
    ),
    (
        recognise_tasks::RECOGNISE_TYPE,
        "the peer VTC's answer is authenticated via the Trust Registry lookup the handler performs, not a request-level proof",
    ),
    (
        discovery::DISCOVERY_V0_4_TYPE,
        "a public discovery read; names no identity to authorize",
    ),
    (
        discovery::DISCOVERY_V0_3_TYPE,
        "a public discovery read; names no identity to authorize",
    ),
    (
        ACL_SHOW_TYPE,
        "reads the caller's own ACL row; the handler authorizes from the signer's entry, so an unsigned caller is refused regardless",
    ),
    (
        ACL_LIST_TYPE,
        "reads ACL rows; the handler authorizes from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        ACL_SHOW_TYPE,
        "reads an ACL row; the handler authorizes from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        ACL_LIST_TYPE,
        "reads ACL rows; the handler authorizes from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        member_tasks::RELATIONSHIPS_LIST_TYPE,
        "a read; the handler refuses an unsigned caller regardless",
    ),
    (
        member_tasks::ENDORSEMENTS_LIST_TYPE,
        "a read; the handler refuses an unsigned caller regardless",
    ),
    (
        member_tasks::ENDORSEMENTS_SHOW_TYPE,
        "a read; the handler refuses an unsigned caller regardless",
    ),
    (
        STEP_UP_APPROVE_RESPONSE_TYPE,
        "approve-response 0.7 makes a user-verified WebAuthn assertion by the approver's own registered passkey evidence on its own; the handler requires a proof for every other answer (didSigned, approverSigned, any denial) and hears an unsigned one only as an approval carrying such an assertion",
    ),
    (
        step_up_passkey_tasks::REDEEM_START_TYPE,
        "redeems a single-use invite token; the handler requires a proof regardless (VTI-APV passkey redemption), the token itself being the thing that makes an unsigned attempt refusable",
    ),
    (
        step_up_passkey_tasks::REDEEM_FINISH_TYPE,
        "redeems a single-use invite token; the handler requires a proof regardless (VTI-APV passkey redemption), the token itself being the thing that makes an unsigned attempt refusable",
    ),
    (
        admin_tasks::DIAGNOSTICS_TYPE,
        "a read; the handler's admin bearer/ACL check refuses an unsigned caller regardless",
    ),
    (
        admin_tasks::SYNC_JOBS_LIST_TYPE,
        "a read; the handler's admin bearer/ACL check refuses an unsigned caller regardless",
    ),
    (
        admin_tasks::RECORDS_LIST_TYPE,
        "a read; the handler's admin bearer/ACL check refuses an unsigned caller regardless",
    ),
    (
        admin_tasks::CONFIG_SHOW_TYPE,
        "a read; the handler's admin bearer/ACL check refuses an unsigned caller regardless",
    ),
    (
        admin_tasks::INVITES_LIST_TYPE,
        "a read; the handler's admin bearer/ACL check refuses an unsigned caller regardless",
    ),
    (
        community_tasks::PROFILE_SHOW_TYPE,
        "a public/community read; the handler refuses an unsigned caller where that read is gated at all",
    ),
    (
        community_tasks::CEREMONIES_LIST_TYPE,
        "a community read; the handler refuses an unsigned caller where that read is gated at all",
    ),
    (
        community_tasks::DIRECTORY_QUERY_TYPE,
        "a community read; the handler refuses an unsigned caller where that read is gated at all",
    ),
    (
        directory_tasks::FIELDS_LIST_TYPE,
        "reads the directory schema; the handler authorizes from the signer's own standing, so an unsigned caller is refused regardless",
    ),
    (
        directory_tasks::CARD_SHOW_TYPE,
        "reads the signer's own card; the handler matches the signer to their membership, so an unsigned caller is refused regardless",
    ),
    (
        directory_tasks::ENTRIES_LIST_TYPE,
        "reads the directory projected for the signer; the handler authorizes from the signer's own standing, so an unsigned caller is refused regardless",
    ),
    (
        directory_tasks::ENTRIES_SHOW_TYPE,
        "reads one entry projected for the signer; the handler authorizes from the signer's own standing, so an unsigned caller is refused regardless",
    ),
    (
        group_tasks::LIST_TYPE,
        "reads the groups the signer may see; the handler authorizes from the signer's own standing, so an unsigned caller is refused regardless",
    ),
    (
        group_tasks::SHOW_TYPE,
        "reads one group the signer may see; the handler authorizes from the signer's own standing, so an unsigned caller is refused regardless",
    ),
    (
        group_tasks::MEMBERS_LIST_TYPE,
        "reads a group's members as the signer may see them; the handler authorizes from the signer's own standing, so an unsigned caller is refused regardless",
    ),
    (
        group_tasks::REQUESTS_LIST_TYPE,
        "reads the join requests to groups the signer manages; the handler authorizes from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        group_tasks::BINDINGS_LIST_TYPE,
        "reads the bindings of a group the signer manages; the handler authorizes from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        board_tasks::LIST_TYPE,
        "reads the boards the signer may see; the handler authorizes from the signer's own standing, so an unsigned caller is refused regardless",
    ),
    (
        board_tasks::SHOW_TYPE,
        "reads one board the signer may see; the handler authorizes from the signer's own standing, so an unsigned caller is refused regardless",
    ),
    (
        board_tasks::NOTES_LIST_TYPE,
        "reads a board's notes as the signer may see them; the handler authorizes from the signer's own standing, so an unsigned caller is refused regardless",
    ),
    (
        board_tasks::FACILITATORS_LIST_TYPE,
        "reads the facilitators of a board the signer facilitates; the handler authorizes from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        community_tasks::ENDORSEMENT_TYPES_LIST_TYPE,
        "a community read; the handler refuses an unsigned caller where that read is gated at all",
    ),
    (
        community_tasks::RECOGNITION_CHECK_TYPE,
        "a community read; the handler refuses an unsigned caller where that read is gated at all",
    ),
    (
        community_tasks::MEMBERS_LIST_TYPE,
        "an admin read; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        community_tasks::MEMBERS_REMOVED_TYPE,
        "an admin read; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        community_tasks::MEMBERS_SHOW_TYPE,
        "an admin read; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        community_tasks::MEMBERS_SOLICIT_VMC_TYPE,
        "an admin action; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        community_tasks::JOIN_REQUESTS_LIST_TYPE,
        "an admin read; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        community_tasks::JOIN_REQUESTS_SHOW_TYPE,
        "an admin read; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        community_tasks::RELATIONSHIPS_GRAPH_TYPE,
        "an admin read; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        community_tasks::INVITATIONS_LIST_TYPE,
        "an admin read; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        policy_tasks::POLICY_LIST_TYPE,
        "a read; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        policy_tasks::POLICY_GET_TYPE,
        "a read; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        policy_tasks::POLICY_ACTIVE_TYPE,
        "a read; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        policy_tasks::POLICY_TEST_TYPE,
        "a dry-run read; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        policy_tasks::DID_REGISTER_TYPE,
        "declares no request-level proof as a specification matter; the handler's own authorization refuses an unsigned caller regardless",
    ),
    (surface_tasks::BRANDING_SHOW_TYPE, "a public read"),
    (
        surface_tasks::THEME_SHOW_TYPE,
        "a public read, answered to an unidentified caller too: the sign-in pages draw the theme before the visitor has an identity",
    ),
    (surface_tasks::REQUESTED_SHOW_TYPE, "a public read"),
    (surface_tasks::JOIN_DISCOVERY_SHOW_TYPE, "a public read"),
    (surface_tasks::SCHEMAS_LIST_TYPE, "a public read"),
    (surface_tasks::SCHEMAS_SHOW_TYPE, "a public read"),
    (surface_tasks::ACCEPTS_LIST_TYPE, "a public read"),
    (surface_tasks::ACCEPTS_SHOW_TYPE, "a public read"),
    (
        surface_tasks::VETTER_GRANTS_LIST_TYPE,
        "an admin read; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        surface_tasks::AUTO_GRANT_SHOW_TYPE,
        "an admin read; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        surface_tasks::REVOCATIONS_LIST_TYPE,
        "an admin read; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        surface_tasks::JOIN_VETTING_SHOW_TYPE,
        "an admin read; the handler's admin ACL check refuses an unsigned caller regardless",
    ),
    (
        surface_tasks::ROOMS_LIST_TYPE,
        "lists the hosted rooms; the handler authorizes vtc.rooms.admin from the signer's own entry, so an unsigned caller is refused regardless",
    ),
    (
        capability_module_tasks::LIST_TYPE,
        "a member read; `acting_party` refuses an unsigned caller as `proofRequired`",
    ),
    #[cfg(feature = "voting")]
    (
        election_tasks::LIST_TYPE,
        "a roll-scoped read; `election_tasks::caller` takes the caller from the proof and refuses an unsigned one as `proofRequired`",
    ),
    #[cfg(feature = "voting")]
    (
        election_tasks::SHOW_TYPE,
        "a roll-scoped read; `election_tasks::caller` takes the caller from the proof and refuses an unsigned one as `proofRequired`",
    ),
    #[cfg(feature = "voting")]
    (
        election_tasks::TOMBSTONE_SHOW_TYPE,
        "a member read; `election_tasks::caller` takes the caller from the proof and refuses an unsigned one as `proofRequired`",
    ),
    #[cfg(feature = "voting")]
    (
        election_tasks::SHOW_0_2_TYPE,
        "a roll-scoped read; `election_tasks::caller` takes the caller from the proof and refuses an unsigned one as `proofRequired`",
    ),
    #[cfg(feature = "voting")]
    (
        election_tasks::SHOW_0_3_TYPE,
        "a roll-scoped read; `election_tasks::caller` takes the caller from the proof and refuses an unsigned one as `proofRequired`",
    ),
    #[cfg(feature = "voting")]
    (
        election_tasks::LIST_0_3_TYPE,
        "a roll-scoped read; `election_tasks::caller` takes the caller from the proof and refuses an unsigned one as `proofRequired`",
    ),
    (
        auth_tasks::CHALLENGE_TYPE,
        "names no identity to authorize — it is the first message of the handshake",
    ),
    (
        auth_tasks::REFRESH_V0_2_TYPE,
        "the refresh token itself is the credential, not a request-level proof",
    ),
    #[cfg(feature = "website")]
    (website_tasks::FILES_SHOW_TYPE, "a public read"),
    #[cfg(feature = "website")]
    (
        website_tasks::FILES_LIST_TYPE,
        "an admin read; `admin_signer` refuses an unsigned caller regardless",
    ),
    #[cfg(feature = "website")]
    (
        website_tasks::GENERATIONS_LIST_TYPE,
        "an admin read; `admin_signer` refuses an unsigned caller regardless",
    ),
];

/// Every dispatched URI either has its spec's `is_proof_required` enforced
/// by the universal check `dispatch_trust_task_core` runs — once, before
/// any handler, for every type with a published policy (see the long
/// comment above `spec_policy_for` in this module) — or is named in
/// [`DISPATCHED_WITHOUT_PROOF`] with the reason it is refused some other
/// way when unsigned.
///
/// This replaces a hand-counted total that broke on every addition or
/// removal whether or not the change was reasoned about. The property it
/// keeps is the one that mattered: nothing is dispatched unsigned by
/// accident.
#[test]
fn the_dispatched_set_declares_the_proofs_the_design_note_records() {
    let dispatched: Vec<&str> = DISPATCHED_URIS
        .iter()
        .copied()
        .chain(crate::rooms::handlers::served_uris())
        .collect();

    let mut unexplained = Vec::new();
    let mut stale = Vec::new();
    for &uri in &dispatched {
        let required = spec_policy_for(uri).is_some_and(|p| p.is_proof_required);
        let allow_listed = DISPATCHED_WITHOUT_PROOF.iter().any(|&(u, _)| u == uri);
        match (required, allow_listed) {
            (false, false) => unexplained.push(uri),
            (true, true) => stale.push(uri),
            _ => {}
        }
    }
    assert!(
        unexplained.is_empty(),
        "dispatched, no proof required by spec, and not reasoned about in \
         DISPATCHED_WITHOUT_PROOF — either its specification should require a proof, or \
         add an entry there with the reason an unsigned caller is refused some other way: \
         {unexplained:#?}"
    );
    assert!(
        stale.is_empty(),
        "DISPATCHED_WITHOUT_PROOF entries whose specification now requires a proof — \
         remove the stale entries: {stale:#?}"
    );

    for &(uri, reason) in DISPATCHED_WITHOUT_PROOF {
        assert!(
            dispatched.contains(&uri),
            "`{uri}` is in DISPATCHED_WITHOUT_PROOF ({reason}) but is not dispatched any \
             more — remove the stale entry"
        );
    }
}

// ── An approver's decision is an attestation ────────────────────────────
//
// A `task-consent/decision` and a step-up `approve-response` are held to
// `verify_approval_proof`: a proof made for `assertionMethod`, by a key the
// signer lists under `assertionMethod`, from a DID that resolves.

/// A `did:peer:2` whose one Ed25519 key is published under
/// `purpose_code` (`A` = assertionMethod only, `D` = capabilityDelegation
/// only), and its signing secret. Resolved locally, no network.
fn peer(purpose_code: char, seed: u8) -> (String, affinidi_secrets_resolver::secrets::Secret) {
    use affinidi_secrets_resolver::secrets::Secret;
    let probe = Secret::generate_ed25519(None, Some(&[seed; 32]));
    let mb = probe.get_public_keymultibase().expect("public key");
    let did = format!("did:peer:2.{purpose_code}{mb}");
    let secret = Secret::generate_ed25519(Some(&format!("{did}#key-1")), Some(&[seed; 32]));
    (did, secret)
}

/// A `did:key` signer and its secret, the verification method named the
/// way a `did:key` names its own.
fn key_signer(seed: u8) -> (String, affinidi_secrets_resolver::secrets::Secret) {
    use affinidi_secrets_resolver::secrets::Secret;
    let mut secret = Secret::generate_ed25519(None, Some(&[seed; 32]));
    let mb = secret.get_public_keymultibase().expect("public key");
    let did = format!("did:key:{mb}");
    secret.id = format!("{did}#{mb}");
    (did, secret)
}

/// `uri` issued by `issuer`, signed by `secret` with `purpose`.
async fn approval(
    uri: &str,
    payload: Value,
    issuer: &str,
    secret: &affinidi_secrets_resolver::secrets::Secret,
    purpose: &str,
) -> TrustTask<Value> {
    use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
    let doc = vta_sdk::trust_task_sign::build_unsigned(uri, payload, issuer, TEST_VTC_DID)
        .expect("build the document");
    let mut doc = serde_json::to_value(doc).unwrap();
    doc.as_object_mut().unwrap().remove("proof");
    let proof =
        DataIntegrityProof::sign(&doc, secret, SignOptions::new().with_proof_purpose(purpose))
            .await
            .expect("sign the approval");
    doc["proof"] = serde_json::to_value(proof).unwrap();
    serde_json::from_value(doc).unwrap()
}

fn decision_payload() -> Value {
    json!({
        "challenge": "9c1f4b7a2e6d80f35a4c9b1e7d2f6083",
        "payloadDigest": "zQmSK9pGKFnmc77pqyNAPJyPKt8rMqctngfg3vwuMArwGYZ",
        "decision": "approve",
    })
}

fn approve_response_payload(subject: &str) -> Value {
    json!({
        "subject": subject,
        "challenge": "c2VjcmV0LWNoYWxsZW5nZS12YWx1ZQ",
        "decision": "approved",
    })
}

/// The refusal came from the proof check.
fn refused_at_the_proof(out: &TrustTaskOutcome) -> bool {
    let body = String::from_utf8_lossy(&out.body);
    error_code(out).as_deref() == Some("permissionDenied") && body.contains("proof")
}

// ── VTI-45: the proof is verified over the document as received ─────────

/// Sign `doc` **exactly as it stands** — the JSON a JavaScript producer sends —
/// with seed `seed`'s Ed25519 key under `vm`, for `purpose`, the proof's
/// `created` set to the string given, verbatim (VTI-45).
fn sign_received(doc: &mut Value, seed: u8, vm: &str, purpose: &str, created: &str) {
    use affinidi_data_integrity::crypto_suites::CryptoSuite;
    use affinidi_data_integrity::{DataIntegrityProof, prepare_sign_input};
    use ed25519_dalek::Signer as _;
    let mut di = DataIntegrityProof::new(
        CryptoSuite::EddsaJcs2022,
        vm.to_string(),
        purpose.to_string(),
        None,
        Some(created.to_string()),
        None,
    );
    doc.as_object_mut().expect("an object").remove("proof");
    let input = prepare_sign_input(&*doc, &di, CryptoSuite::EddsaJcs2022).expect("sign input");
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    di.proof_value = Some(multibase::encode(
        multibase::Base::Base58Btc,
        sk.sign(&input).to_bytes(),
    ));
    doc["proof"] = serde_json::to_value(&di).expect("proof serialises");
}

/// Now, on a whole second, as JavaScript's `toISOString()` writes it.
fn javascript_whole_second_now() -> String {
    format!("{}.000Z", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S"))
}

/// `uri` from `issuer` as a JavaScript producer sends it on a whole second
/// — `.000Z` timestamps, a `null` `threadId` — signed as received.
fn vti_45_document(
    uri: &str,
    payload: Value,
    issuer: &str,
    seed: u8,
    vm: &str,
    purpose: &str,
) -> Value {
    let now = javascript_whole_second_now();
    let mut doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": uri,
        "issuer": issuer,
        "recipient": TEST_VTC_DID,
        "issuedAt": now,
        "threadId": null,
        "payload": payload,
    });
    sign_received(&mut doc, seed, vm, purpose, &now);
    doc
}

async fn dispatch_received(state: &AppState, doc: &Value) -> TrustTaskOutcome {
    let body = serde_json::to_vec(doc).expect("a document serialises");
    dispatch_trust_task_core(state, &JoinAuthCtx::rest(), &body).await
}

/// VTI-45 at the spine: a correctly signed `.000Z` / `threadId: null`
/// document reaches its handler — and the typed re-serialisation the spine
/// used to verify would have refused it.
#[tokio::test]
async fn vti_45_a_javascript_whole_second_document_passes_the_spine() {
    let tv = build_test_vtc().await;
    let (did, secret) = key_signer(0x45);
    let doc = vti_45_document(
        UNDER_TEST,
        json!({}),
        &did,
        0x45,
        &secret.id,
        "assertionMethod",
    );

    let typed: TrustTask<Value> = serde_json::from_value(doc.clone()).unwrap();
    assert!(
        vti_common::auth::verify_trust_task_proof(&typed)
            .await
            .is_err(),
        "the typed form must be what this document breaks"
    );

    let out = dispatch_received(&tv.state, &doc).await;
    for code in ["proofRequired", "proofInvalid"] {
        assert_ne!(
            error_code(&out).as_deref(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
    }

    let mut tampered = doc;
    tampered["payload"] = json!({ "requestId": "someone-elses" });
    let out = dispatch_received(&tv.state, &tampered).await;
    assert!(
        refused_at_the_proof(&out),
        "{}",
        String::from_utf8_lossy(&out.body)
    );
}

/// VTI-45 on the approval path, which holds a proof to `assertionMethod`:
/// a `.000Z` decision gets past the proof, and an `authentication` one is
/// still refused there.
#[tokio::test]
async fn vti_45_a_javascript_whole_second_approval_is_held_to_its_purpose() {
    let tv = build_test_vtc().await;
    let (did, secret) = peer('A', 0x46);
    for uri in [
        crate::acl::admin_consent::DECISION_TYPE,
        STEP_UP_APPROVE_RESPONSE_TYPE,
    ] {
        let payload = if uri == STEP_UP_APPROVE_RESPONSE_TYPE {
            approve_response_payload(&did)
        } else {
            decision_payload()
        };
        let ok = vti_45_document(
            uri,
            payload.clone(),
            &did,
            0x46,
            &secret.id,
            "assertionMethod",
        );
        let out = dispatch_received(&tv.state, &ok).await;
        assert!(
            !refused_at_the_proof(&out),
            "{uri}: {}",
            String::from_utf8_lossy(&out.body)
        );

        let operational = vti_45_document(uri, payload, &did, 0x46, &secret.id, "authentication");
        let out = dispatch_received(&tv.state, &operational).await;
        assert!(
            refused_at_the_proof(&out),
            "{uri}: {}",
            String::from_utf8_lossy(&out.body)
        );
    }
}

#[tokio::test]
async fn an_approval_signed_for_authentication_is_refused() {
    let tv = build_test_vtc().await;
    let (did, secret) = key_signer(0x51);
    for (uri, payload) in [
        (crate::acl::admin_consent::DECISION_TYPE, decision_payload()),
        (
            STEP_UP_APPROVE_RESPONSE_TYPE,
            approve_response_payload(&did),
        ),
    ] {
        let doc = approval(uri, payload, &did, &secret, "authentication").await;
        let out = dispatch(&tv.state, &doc).await;
        let body = String::from_utf8_lossy(&out.body);
        assert!(refused_at_the_proof(&out), "{uri}: {body}");
        assert!(body.contains("assertionMethod"), "{uri}: {body}");
    }
}

/// Declared `assertionMethod`, by a key the signer lists only under
/// `capabilityDelegation`: the signature is valid, but the key is not
/// authorised for the purpose the proof declares (VTI-KEY-022), so neither
/// the general verifier nor the approval path accepts it.
#[tokio::test]
async fn an_approval_by_a_key_not_listed_under_assertion_method_is_refused() {
    let tv = build_test_vtc().await;
    let (did, secret) = peer('D', 0x52);
    for (uri, payload) in [
        (crate::acl::admin_consent::DECISION_TYPE, decision_payload()),
        (
            STEP_UP_APPROVE_RESPONSE_TYPE,
            approve_response_payload(&did),
        ),
    ] {
        let doc = approval(uri, payload, &did, &secret, "assertionMethod").await;
        let err = vti_common::auth::verify_trust_task_proof(&doc)
            .await
            .unwrap_err();
        assert!(
            err.cause().is_some_and(|c| c.contains("assertionMethod")),
            "{uri}: {err:?}"
        );
        let out = dispatch(&tv.state, &doc).await;
        assert!(
            refused_at_the_proof(&out),
            "{uri}: {}",
            String::from_utf8_lossy(&out.body)
        );
    }
}

/// A signer DID this service cannot resolve is refused, never passed
/// through to the handler.
#[tokio::test]
async fn an_approval_whose_signer_does_not_resolve_is_refused() {
    use affinidi_secrets_resolver::secrets::Secret;
    let tv = build_test_vtc().await;
    let did = "did:web:approver.invalid";
    let secret = Secret::generate_ed25519(Some(&format!("{did}#key-1")), Some(&[0x53; 32]));
    for (uri, payload) in [
        (crate::acl::admin_consent::DECISION_TYPE, decision_payload()),
        (STEP_UP_APPROVE_RESPONSE_TYPE, approve_response_payload(did)),
    ] {
        let doc = approval(uri, payload, did, &secret, "assertionMethod").await;
        let out = dispatch(&tv.state, &doc).await;
        assert!(
            refused_at_the_proof(&out),
            "{uri}: {}",
            String::from_utf8_lossy(&out.body)
        );
    }
}

/// The same approvals made for `assertionMethod` by an assertion key get
/// past the proof, to be refused only by the handler (here the signer is
/// no admin of this community).
#[tokio::test]
async fn an_assertion_method_approval_passes_the_proof() {
    let tv = build_test_vtc().await;
    let signers = [key_signer(0x54), peer('A', 0x55)];
    for (did, secret) in &signers {
        for (uri, payload) in [
            (crate::acl::admin_consent::DECISION_TYPE, decision_payload()),
            (STEP_UP_APPROVE_RESPONSE_TYPE, approve_response_payload(did)),
        ] {
            let doc = approval(uri, payload, did, secret, "assertionMethod").await;
            let out = dispatch(&tv.state, &doc).await;
            let body = String::from_utf8_lossy(&out.body);
            assert!(
                !body.contains("proof"),
                "{uri} by {did} passes the proof check: {body}"
            );
        }
    }
}

/// An unsigned approve-response is heard only as an approval carrying a
/// passkey assertion: a `didSigned` one (here, by omission) and any denial
/// are `proofRequired` before any pending step-up is consulted
/// (approve-response 0.7 consumer item 1a).
#[tokio::test]
async fn approve_response_0_7_item_1a_an_unsigned_answer_without_a_passkey_is_refused() {
    let tv = build_test_vtc().await;
    let h = holder();
    let mut denied = approve_response_payload(&h.did);
    denied["decision"] = json!("denied");
    denied["deniedReason"] = json!("no");
    denied["evidence"] = json!({ "kind": "didSigned" });
    for payload in [approve_response_payload(&h.did), denied] {
        let doc = unsigned(&h, STEP_UP_APPROVE_RESPONSE_TYPE, payload);
        let out = dispatch(&tv.state, &doc).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some("proofRequired"),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
    }
}
