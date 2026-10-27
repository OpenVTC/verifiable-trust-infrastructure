//! End-to-end test for VIC-driven auto-join (the demo's VTC behaviour).
//!
//! Drives the production [`submit_inner`] spine (the shared REST + DIDComm join
//! path) with a self-issued Invitation Credential presented inside a VP:
//!
//!   issue VIC → present in VP over the DIDComm path → auto-admit (VMC + role
//!   VAC issued) → invitation burned in the single-use ledger.
//!
//! Plus the holder-binding guard: a VIC minted for one DID cannot be redeemed by
//! another. Crypto edges (expired / revoked / tampered / untrusted issuer) are
//! covered by the unit tests in `credentials::invitation_verify`.

use std::sync::Arc;

use affinidi_status_list::StatusPurpose;
use chrono::Duration;
use ed25519_dalek::SigningKey;
use serde_json::json;

use crate::acl::get_acl_entry;
use crate::credentials::dtg;
use crate::credentials::invitation_verify::is_consumed;
use crate::credentials::signer::LocalSigner;
use crate::join::{JoinStatus, JoinTransport, submit_inner};
use crate::status_list::ensure_initial;
use crate::test_support::TestVtc;

const ISSUER_SEED: [u8; 32] = [0xA1; 32];
const APPLICANT_SEED: [u8; 32] = [0xB2; 32];
const OUTSIDER_SEED: [u8; 32] = [0xC3; 32];

/// A `did:key` for a seed — resolves locally (no network), so the VIC's issuer
/// proof verifies offline.
fn did_key(seed: &[u8; 32]) -> String {
    let sk = SigningKey::from_bytes(seed);
    affinidi_crypto::did_key::ed25519_pub_to_did_key(&sk.verifying_key().to_bytes())
}

/// A signer whose issuer DID is the `did:key` of its own public key.
fn signer(seed: &[u8; 32]) -> LocalSigner {
    LocalSigner::did_key_for_seed(seed)
}

/// Build a TestVtc whose `vtc_did` + credential signer are the same `did:key`,
/// with audit + both status lists + the default join policy installed — the
/// boot state the join ceremony needs to auto-admit.
async fn vtc_with_signer(signer: &LocalSigner) -> TestVtc {
    let tv = TestVtc::builder()
        .vtc_did(signer.issuer_did().to_string())
        .with_audit(true)
        .with_credential_signer(Arc::new(signer.clone()))
        .build()
        .await;

    crate::policy::default::install_defaults(&tv.state.policies_ks, &tv.state.active_policies_ks)
        .await
        .expect("install default policies");
    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        ensure_initial(
            &tv.state.status_lists_ks,
            purpose,
            format!("https://vtc.test/v1/status-lists/{purpose}"),
        )
        .await
        .expect("ensure status list");
    }
    tv
}

/// Issue a self-signed VIC (no `credentialStatus`, so the offline revocation
/// check is a no-op) bound to `subject`, returning `(vp, vic_id)`.
async fn issue_vic_vp(signer: &LocalSigner, subject: &str) -> (serde_json::Value, String) {
    let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let vic = dtg::issue_invitation(signer, subject, Some(&id), None, Duration::days(7), &[])
        .await
        .expect("issue VIC");
    let vp = json!({
        "type": "VerifiablePresentation",
        "holder": subject,
        "verifiableCredential": [vic],
    });
    (vp, id)
}

#[tokio::test]
async fn vic_presented_in_vp_auto_admits_and_is_consumed() {
    let issuer = signer(&ISSUER_SEED);
    let tv = vtc_with_signer(&issuer).await;
    let applicant = did_key(&APPLICANT_SEED);
    let (vp, vic_id) = issue_vic_vp(&issuer, &applicant).await;

    // The DIDComm path: the authcrypt envelope authenticates the sender, so no
    // holder-binding signature (binding = None).
    let outcome = submit_inner(
        &tv.state,
        applicant.clone(),
        vp,
        false,
        json!({}),
        Vec::new(),
        None,
        None,
        JoinTransport::DIDComm,
    )
    .await
    .expect("submit succeeds");

    // Auto-admitted: credentials issued inline, request Approved.
    assert!(
        outcome.admit.is_some(),
        "a valid self-issued VIC must auto-admit (issue the VMC inline)"
    );
    assert_eq!(outcome.request.status, JoinStatus::Approved);

    // The applicant is now a member in the ACL.
    let entry = get_acl_entry(&tv.state.acl_ks, &applicant)
        .await
        .expect("acl read")
        .expect("applicant has an ACL entry after admit");
    assert_eq!(entry.role.to_string(), "member");

    // The member row is flagged invitation-joined (drives the admin-UI badge).
    let member = crate::members::get_member(&tv.state.members_ks, &applicant)
        .await
        .expect("member read")
        .expect("member row exists after admit");
    assert!(
        member.joined_via_invitation,
        "an invitation-driven admit flags the member"
    );

    // The single-use VIC is burned in the ledger.
    assert!(
        is_consumed(&tv.state.consumed_invitations_ks, &vic_id)
            .await
            .expect("consumed lookup"),
        "the redeemed VIC must be recorded consumed"
    );
}

#[tokio::test]
async fn vic_bound_to_another_did_cannot_be_redeemed() {
    let issuer = signer(&ISSUER_SEED);
    let tv = vtc_with_signer(&issuer).await;

    // VIC minted for the applicant…
    let applicant = did_key(&APPLICANT_SEED);
    let (vp, vic_id) = issue_vic_vp(&issuer, &applicant).await;

    // …but presented by an outsider. Holder-binding fails → Forbidden, before
    // any policy runs.
    let outsider = did_key(&OUTSIDER_SEED);
    let result = submit_inner(
        &tv.state,
        outsider.clone(),
        vp,
        false,
        json!({}),
        Vec::new(),
        None,
        None,
        JoinTransport::DIDComm,
    )
    .await;
    // The VP names the applicant as its holder, so it is refused as
    // `submit:presentationInvalid` before the invitation is even examined —
    // a presentation that is not the submitter's own is decided on by nothing
    // (#1600). A VP that names no holder still reaches the invitation's own
    // holder binding, which refuses it `Forbidden`.
    match result {
        Err(crate::join::SubmitRefusal::PresentationInvalid(_)) => {}
        Err(other) => panic!("expected PresentationInvalid, got {other:?}"),
        Ok(_) => panic!("a VIC bound to someone else must be refused"),
    }

    // Without the tell-tale holder, the invitation's own binding refuses it.
    let (mut vp, _) = issue_vic_vp(&issuer, &applicant).await;
    vp.as_object_mut().expect("VP object").remove("holder");
    let result = submit_inner(
        &tv.state,
        outsider.clone(),
        vp,
        false,
        json!({}),
        Vec::new(),
        None,
        None,
        JoinTransport::DIDComm,
    )
    .await;
    match result.map_err(vti_common::error::AppError::from) {
        Err(vti_common::error::AppError::Forbidden(_)) => {}
        Err(other) => panic!("expected Forbidden, got {other:?}"),
        Ok(_) => panic!("a VIC bound to someone else must be refused"),
    }

    // The outsider was not admitted and the VIC was not burned.
    assert!(
        get_acl_entry(&tv.state.acl_ks, &outsider)
            .await
            .expect("acl read")
            .is_none(),
        "outsider must not become a member"
    );
    assert!(
        !is_consumed(&tv.state.consumed_invitations_ks, &vic_id)
            .await
            .expect("consumed lookup"),
        "a refused redeem must not consume the VIC"
    );
}

/// Realize an auto-admit verdict for `applicant` that redeems `vic_id`, the
/// way the submit spine does once the policy has decided over an
/// unconsumed invitation.
async fn realize_invited_admit(
    state: &crate::server::AppState,
    applicant: &str,
    vic_id: &str,
) -> Result<crate::join::JoinSubmitOutcome, vti_common::error::AppError> {
    crate::join::realize_join_verdict(
        state,
        applicant,
        json!({ "type": "VerifiablePresentation", "holder": applicant }),
        json!({}),
        false,
        json!({}),
        Vec::new(),
        crate::ceremony::verdict::Verdict::Allow(crate::ceremony::verdict::Allow::default()),
        JoinTransport::DIDComm,
        Some(vic_id.to_string()),
    )
    .await
}

/// The race's loser: its verdict was decided over an invitation that another
/// redeem consumed before this one was admitted. It must be admitted on
/// nothing — burning the invitation only after admission admitted both.
#[tokio::test]
async fn an_invitation_consumed_since_the_decision_admits_nobody() {
    let issuer = signer(&ISSUER_SEED);
    let tv = vtc_with_signer(&issuer).await;
    let applicant = did_key(&APPLICANT_SEED);
    let vic_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let record = crate::credentials::invitation_verify::ConsumedInvitation {
        applicant: "did:key:zSomeoneElse".into(),
        consumed_at: chrono::Utc::now(),
        via_join_request_id: "earlier".into(),
    };
    assert!(
        crate::credentials::invitation_verify::mark_consumed(
            &tv.state.consumed_invitations_ks,
            &vic_id,
            &record,
        )
        .await
        .unwrap()
    );

    let err = realize_invited_admit(&tv.state, &applicant, &vic_id)
        .await
        .err()
        .expect("a consumed invitation must not admit");
    assert!(
        matches!(err, vti_common::error::AppError::Conflict(_)),
        "{err:?}"
    );
    assert!(
        get_acl_entry(&tv.state.acl_ks, &applicant)
            .await
            .unwrap()
            .is_none(),
        "admitted on an invitation somebody else had already redeemed"
    );
}

/// Redeems of one single-use invitation racing past the decision: exactly
/// one is admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn racing_redeems_of_one_invitation_admit_exactly_one() {
    let issuer = signer(&ISSUER_SEED);
    let tv = vtc_with_signer(&issuer).await;
    let vic_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut tasks = Vec::new();
    for i in 0..8u8 {
        let (state, barrier, vic_id) = (tv.state.clone(), barrier.clone(), vic_id.clone());
        tasks.push(tokio::spawn(async move {
            let applicant = did_key(&[0x40 + i; 32]);
            barrier.wait().await;
            realize_invited_admit(&state, &applicant, &vic_id)
                .await
                .is_ok_and(|o| o.admit.is_some())
        }));
    }
    let mut admitted = 0;
    for t in tasks {
        admitted += t.await.unwrap() as usize;
    }
    assert_eq!(admitted, 1, "one invitation admitted {admitted} members");
}

/// An admission that fails after claiming the invitation gives it back, so
/// the invitee can redeem it again.
#[tokio::test]
async fn a_failed_admission_releases_the_invitation() {
    let issuer = signer(&ISSUER_SEED);
    let tv = vtc_with_signer(&issuer).await;
    let applicant = did_key(&APPLICANT_SEED);
    let vic_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    // Already a member: the admit effect refuses the duplicate.
    realize_invited_admit(&tv.state, &applicant, &format!("{vic_id}-first"))
        .await
        .expect("first admission");

    assert!(
        realize_invited_admit(&tv.state, &applicant, &vic_id)
            .await
            .is_err(),
        "a duplicate admission is refused"
    );
    assert!(
        !is_consumed(&tv.state.consumed_invitations_ks, &vic_id)
            .await
            .unwrap(),
        "a failed admission must not burn the invitation"
    );
}
