//! Integration coverage for the ceremony effect executor
//! (`vtc_service::ceremony::execute::apply`).
//!
//! The manual approve + removal routes already exercise the `Admit`
//! and `Depart` arms over HTTP (`tests/join_requests.rs`,
//! `tests/removal.rs` — both now go through the executor). This file
//! covers the arms directly, including cases the routes don't:
//! - admit at a **non-`member` role** (approve hardcodes `member`);
//! - the duplicate-ACL guard on admit;
//! - depart removing + revoking a member, and the no-last-admin
//!   invariant living in the executor;
//! - the `NoStateChange` no-op.
//!
//! It calls `apply` directly against a built `AppState` rather than
//! over HTTP — the executor is below the route layer.

use affinidi_status_list::StatusPurpose;

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::ceremony::EffectPlan;
use vtc_service::ceremony::execute::{self, EffectOutcome};
use vtc_service::members::{Disposition, get_member, list_members};
use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

const RP_ORIGIN: &str = "https://vtc.example.com";
const ACTOR_DID: &str = "did:key:zActor";

/// Build an `AppState` with a credential signer + provisioned status
/// lists — the minimum the `Admit` arm needs. JWT / webauthn / audit
/// are left `None`; the executor doesn't touch them.
async fn build_state() -> (AppState, TestVtc) {
    let vtc = TestVtc::builder()
        .with_signers(true)
        .with_public_url(RP_ORIGIN)
        .build()
        .await;

    // The admit path allocates a revocation slot when issuing the VMC.
    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        let url = format!("{RP_ORIGIN}/v1/status-lists/{purpose}");
        vtc_service::status_list::ensure_initial(&vtc.state.status_lists_ks, purpose, url)
            .await
            .expect("ensure_initial status list");
    }

    let state = vtc.state.clone();
    (state, vtc)
}

/// `Admit` at a non-`member` role writes the ACL row at that role,
/// writes the Member record, and issues the credentials — proving the
/// plan's role is honoured (approve only ever admits `member`).
#[tokio::test]
async fn admit_honours_the_plan_role() {
    let (state, _dir) = build_state().await;
    let subject = "did:key:zModerator";

    let plan = EffectPlan::Admit {
        subject: subject.into(),
        role: "moderator".into(),
        obligations: vec![],
    };
    let outcome = execute::apply(&state, plan, ACTOR_DID)
        .await
        .expect("apply");

    let EffectOutcome::Admitted(creds) = outcome else {
        panic!("expected Admitted, got {outcome:?}");
    };

    // ACL row written at the granted role, created_by the actor.
    let acl = get_acl_entry(&state.acl_ks, subject)
        .await
        .unwrap()
        .expect("acl row");
    assert_eq!(acl.role, VtcRole::Moderator);
    assert_eq!(acl.created_by, ACTOR_DID);

    // Member row written with the credential pointers stamped.
    let member = get_member(&state.members_ks, subject)
        .await
        .unwrap()
        .expect("member row");
    assert_eq!(member.status_list_index, Some(creds.status_list_index));
    assert!(member.current_vmc_id.is_some(), "VMC id stamped");
    assert!(member.current_role_vec_id.is_some(), "role VEC id stamped");
}

/// Admitting a DID that already holds an ACL row is a conflict — the
/// executor refuses a duplicate membership.
#[tokio::test]
async fn admit_duplicate_acl_is_conflict() {
    let (state, _dir) = build_state().await;
    let subject = "did:key:zExisting";

    store_acl_entry(
        &state.acl_ks,
        &VtcAclEntry {
            did: subject.into(),
            role: VtcRole::Member,
            label: None,
            allowed_contexts: vec![],
            created_at: vtc_service::auth::session::now_epoch(),
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .unwrap();

    let plan = EffectPlan::Admit {
        subject: subject.into(),
        role: "member".into(),
        obligations: vec![],
    };
    let err = execute::apply(&state, plan, ACTOR_DID)
        .await
        .expect_err("duplicate admit must conflict");
    assert!(
        matches!(err, vti_common::error::AppError::Conflict(_)),
        "got {err:?}"
    );
}

/// P0.15: two concurrent admits for the same DID must resolve to exactly
/// one membership — one wins (Admitted), the other loses (Conflict). Before
/// the serializing lock, both could pass the bare `get_acl_entry().is_some()`
/// guard and proceed, minting two VMCs and burning two status-list slots.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_admits_for_one_did_yield_one_membership() {
    let (state, _dir) = build_state().await;
    let subject = "did:key:zRacer";

    let make_plan = || EffectPlan::Admit {
        subject: subject.into(),
        role: "member".into(),
        obligations: vec![],
    };

    let (s1, s2) = (state.clone(), state.clone());
    let h1 = tokio::spawn(async move { execute::apply(&s1, make_plan(), ACTOR_DID).await });
    // Re-declare the plan builder for the second task (closure isn't `Copy`).
    let make_plan2 = || EffectPlan::Admit {
        subject: subject.into(),
        role: "member".into(),
        obligations: vec![],
    };
    let h2 = tokio::spawn(async move { execute::apply(&s2, make_plan2(), ACTOR_DID).await });

    let r1 = h1.await.expect("task 1 panicked");
    let r2 = h2.await.expect("task 2 panicked");

    let wins = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    let conflicts = [&r1, &r2]
        .iter()
        .filter(|r| matches!(r, Err(vti_common::error::AppError::Conflict(_))))
        .count();
    assert_eq!(
        wins, 1,
        "exactly one admit must win; got r1={r1:?} r2={r2:?}"
    );
    assert_eq!(
        conflicts, 1,
        "the loser must get Conflict; got r1={r1:?} r2={r2:?}"
    );

    // The winner's slot is the one recorded on the single member row — proving
    // exactly one slot was burned (not two).
    let winner = [r1, r2].into_iter().find_map(Result::ok).expect("a winner");
    let EffectOutcome::Admitted(creds) = winner else {
        panic!("winner must be Admitted");
    };
    let member = get_member(&state.members_ks, subject)
        .await
        .unwrap()
        .expect("one member row");
    assert_eq!(member.status_list_index, Some(creds.status_list_index));
}

/// A `NoStateChange` plan (deny / refer / request_more) writes nothing.
#[tokio::test]
async fn no_state_change_is_a_noop() {
    let (state, _dir) = build_state().await;

    let outcome = execute::apply(&state, EffectPlan::NoStateChange, ACTOR_DID)
        .await
        .expect("apply");
    assert!(matches!(outcome, EffectOutcome::None), "got {outcome:?}");

    // Nothing was admitted.
    assert!(
        get_acl_entry(&state.acl_ks, "did:key:zAnyone")
            .await
            .unwrap()
            .is_none()
    );
}

/// Depart removes a member: deletes the ACL row, applies the
/// disposition (tombstone keeps the row but clears credentials), and
/// revokes by flipping the member's revocation slot.
#[tokio::test]
async fn depart_removes_member_and_revokes() {
    let (state, _dir) = build_state().await;
    let subject = "did:key:zLeaver";

    // Admit first so there's an ACL + Member + revocation slot to remove.
    let admit = EffectPlan::Admit {
        subject: subject.into(),
        role: "member".into(),
        obligations: vec![],
    };
    let EffectOutcome::Admitted(creds) = execute::apply(&state, admit, ACTOR_DID)
        .await
        .expect("admit")
    else {
        panic!("expected Admitted");
    };
    let slot = creds.status_list_index;

    // Depart with tombstone.
    let plan = EffectPlan::Depart {
        subject: subject.into(),
        disposition: Some("tombstone".into()),
    };
    let EffectOutcome::Departed(outcome) = execute::apply(&state, plan, ACTOR_DID)
        .await
        .expect("depart")
    else {
        panic!("expected Departed");
    };
    assert_eq!(outcome.disposition, Disposition::Tombstone);
    assert_eq!(
        outcome.revoked_slot,
        Some(slot),
        "the member's slot was flipped"
    );

    // ACL gone; Member row tombstoned (kept, removed_at set, VMC cleared).
    assert!(
        get_acl_entry(&state.acl_ks, subject)
            .await
            .unwrap()
            .is_none()
    );
    let m = get_member(&state.members_ks, subject)
        .await
        .unwrap()
        .expect("tombstoned member row is kept");
    assert!(m.removed_at.is_some());
    assert!(
        m.current_vmc_id.is_none(),
        "tombstone clears the VMC pointer"
    );
}

/// Depart enforces the no-last-admin invariant: removing the sole
/// admin is a conflict and leaves the ACL untouched.
#[tokio::test]
async fn depart_refuses_the_last_admin() {
    let (state, _dir) = build_state().await;
    let admin = "did:key:zSoleAdmin";

    store_acl_entry(
        &state.acl_ks,
        &VtcAclEntry {
            did: admin.into(),
            role: VtcRole::Admin,
            label: None,
            allowed_contexts: vec![],
            created_at: vtc_service::auth::session::now_epoch(),
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .unwrap();

    let plan = EffectPlan::Depart {
        subject: admin.into(),
        disposition: Some("tombstone".into()),
    };
    let err = execute::apply(&state, plan, ACTOR_DID)
        .await
        .expect_err("last admin must be protected");
    assert!(
        matches!(err, vti_common::error::AppError::Conflict(_)),
        "got {err:?}"
    );
    // The refusal left the ACL row in place.
    assert!(get_acl_entry(&state.acl_ks, admin).await.unwrap().is_some());
}

/// Remint changes a member's role in place and re-mints the role VEC —
/// the ACL role updates and the member's role-VEC pointer moves.
#[tokio::test]
async fn remint_changes_role_and_reissues_vec() {
    let (state, _dir) = build_state().await;
    let subject = "did:key:zPromote";

    // Admit as a member first.
    let admit = EffectPlan::Admit {
        subject: subject.into(),
        role: "member".into(),
        obligations: vec![],
    };
    execute::apply(&state, admit, ACTOR_DID)
        .await
        .expect("admit");
    // The role-VEC pointer stamped at admit time.
    let original_vec_id = get_member(&state.members_ks, subject)
        .await
        .unwrap()
        .expect("member")
        .current_role_vec_id;
    assert!(original_vec_id.is_some(), "admit stamped a role VEC");

    // Re-mint at moderator.
    let plan = EffectPlan::Remint {
        subject: subject.into(),
        role: "moderator".into(),
    };
    let EffectOutcome::Reminted(outcome) = execute::apply(&state, plan, ACTOR_DID)
        .await
        .expect("remint")
    else {
        panic!("expected Reminted");
    };
    assert_eq!(outcome.previous_role, VtcRole::Member);

    // ACL role updated; the member's role-VEC pointer moved to the new VEC.
    let acl = get_acl_entry(&state.acl_ks, subject)
        .await
        .unwrap()
        .expect("acl");
    assert_eq!(acl.role, VtcRole::Moderator);
    let m = get_member(&state.members_ks, subject)
        .await
        .unwrap()
        .expect("member");
    assert!(m.current_role_vec_id.is_some());
    assert_ne!(
        m.current_role_vec_id, original_vec_id,
        "the role VEC was re-minted"
    );
}

/// Remint enforces no-last-admin on demotion: changing the sole admin
/// to a non-admin role is a conflict, leaving the ACL untouched.
#[tokio::test]
async fn remint_refuses_demoting_the_last_admin() {
    let (state, _dir) = build_state().await;
    let admin = "did:key:zSoleAdmin2";

    store_acl_entry(
        &state.acl_ks,
        &VtcAclEntry {
            did: admin.into(),
            role: VtcRole::Admin,
            label: None,
            allowed_contexts: vec![],
            created_at: vtc_service::auth::session::now_epoch(),
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .unwrap();

    let plan = EffectPlan::Remint {
        subject: admin.into(),
        role: "member".into(),
    };
    let err = execute::apply(&state, plan, ACTOR_DID)
        .await
        .expect_err("demoting the last admin must conflict");
    assert!(
        matches!(err, vti_common::error::AppError::Conflict(_)),
        "got {err:?}"
    );
    // Still admin.
    assert_eq!(
        get_acl_entry(&state.acl_ks, admin)
            .await
            .unwrap()
            .unwrap()
            .role,
        VtcRole::Admin
    );
}

/// The cached `member_count` must equal `list_members().len()` after every
/// mutation the executor performs: +1 on admit, unchanged on a role-change
/// re-mint and on a tombstone departure (the row is kept), −1 only on a purge.
/// A drift here silently corrupts every size-gated policy decision, so assert
/// the invariant after each step.
#[tokio::test]
async fn member_count_cache_tracks_list_members_len() {
    let (state, _dir) = build_state().await;

    async fn assert_consistent(state: &AppState) -> u64 {
        let listed = list_members(&state.members_ks).await.unwrap().len() as u64;
        assert_eq!(
            state.member_count(),
            listed,
            "cached member_count drifted from list_members().len()"
        );
        listed
    }

    let admit = |did: &str, role: &str| EffectPlan::Admit {
        subject: did.into(),
        role: role.into(),
        obligations: vec![],
    };

    assert_eq!(assert_consistent(&state).await, 0, "fresh community");

    execute::apply(&state, admit("did:key:zA", "member"), ACTOR_DID)
        .await
        .expect("admit A");
    assert_eq!(assert_consistent(&state).await, 1, "admit increments");

    execute::apply(&state, admit("did:key:zB", "member"), ACTOR_DID)
        .await
        .expect("admit B");
    assert_eq!(
        assert_consistent(&state).await,
        2,
        "second admit increments"
    );

    // Role-change re-mint updates the existing row in place — no count change.
    execute::apply(
        &state,
        EffectPlan::Remint {
            subject: "did:key:zB".into(),
            role: "moderator".into(),
        },
        ACTOR_DID,
    )
    .await
    .expect("remint B");
    assert_eq!(
        assert_consistent(&state).await,
        2,
        "remint is count-neutral"
    );

    // Tombstone departure keeps the (now-removed-state) row, so the count holds.
    execute::apply(
        &state,
        EffectPlan::Depart {
            subject: "did:key:zA".into(),
            disposition: Some("tombstone".into()),
        },
        ACTOR_DID,
    )
    .await
    .expect("tombstone A");
    assert_eq!(
        assert_consistent(&state).await,
        2,
        "tombstone keeps the row, count unchanged"
    );

    // Purge removes the row — the one departure that decrements.
    execute::apply(
        &state,
        EffectPlan::Depart {
            subject: "did:key:zB".into(),
            disposition: Some("purge".into()),
        },
        ACTOR_DID,
    )
    .await
    .expect("purge B");
    assert_eq!(assert_consistent(&state).await, 1, "purge decrements");
}
