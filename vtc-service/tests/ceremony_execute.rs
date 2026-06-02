//! Integration coverage for the ceremony effect executor
//! (`vtc_service::ceremony::execute::apply`).
//!
//! The manual join-approve route already exercises the `Admit` arm via
//! `tests/join_requests.rs` (approve now goes through the executor).
//! This file covers what approve can't:
//! - admit at a **non-`member` role** (approve hardcodes `member`),
//!   proving the plan's role is honoured;
//! - the duplicate-ACL guard living in the executor;
//! - the trivial dispatch arms (`NoStateChange` no-op, `Depart` not
//!   yet wired).
//!
//! It calls `apply` directly against a built `AppState` rather than
//! over HTTP — the executor is below the route layer.

use std::sync::Arc;

use affinidi_status_list::StatusPurpose;
use tokio::sync::RwLock;
use vti_common::config::StoreConfig;
use vti_common::store::Store;

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::ceremony::EffectPlan;
use vtc_service::ceremony::execute::{self, EffectOutcome};
use vtc_service::config::AppConfig;
use vtc_service::install::InstallTokenStore;
use vtc_service::members::get_member;
use vtc_service::server::AppState;

const RP_ORIGIN: &str = "https://vtc.example.com";
const ACTOR_DID: &str = "did:key:zActor";

/// Build an `AppState` with a credential signer + provisioned status
/// lists — the minimum the `Admit` arm needs. JWT / webauthn / audit
/// are left `None`; the executor doesn't touch them.
async fn build_state() -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .expect("open store");

    let sessions_ks = store.keyspace("sessions").unwrap();
    let acl_ks = store.keyspace("acl").unwrap();
    let community_ks = store.keyspace("community").unwrap();
    let config_ks = store.keyspace("config").unwrap();
    let passkey_ks = store.keyspace("passkey").unwrap();
    let install_ks = store.keyspace("install").unwrap();
    let members_ks = store.keyspace("members").unwrap();
    let join_requests_ks = store.keyspace("join_requests").unwrap();
    let policies_ks = store.keyspace("policies").unwrap();
    let active_policies_ks = store.keyspace("active_policies").unwrap();
    let status_lists_ks = store.keyspace("status_lists").unwrap();
    let registry_records_ks = store.keyspace("registry_records").unwrap();
    let sync_queue_ks = store.keyspace("sync_queue").unwrap();
    let sync_cursor_ks = store.keyspace("sync_cursor").unwrap();
    let relationships_ks = store.keyspace("relationships").unwrap();
    let relationships_by_did_ks = store.keyspace("relationships_by_did").unwrap();
    let endorsement_types_ks = store.keyspace("endorsement_types").unwrap();
    let endorsements_ks = store.keyspace("endorsements").unwrap();
    let audit_ks = store.keyspace("audit").unwrap();
    let audit_key_ks = store.keyspace("audit_key").unwrap();

    // The admit path allocates a revocation slot when issuing the VMC.
    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        let url = format!("{RP_ORIGIN}/v1/status-lists/{purpose}");
        vtc_service::status_list::ensure_initial(&status_lists_ks, purpose, url)
            .await
            .expect("ensure_initial status list");
    }

    let credential_signer = Some(Arc::new(
        vtc_service::credentials::LocalSigner::from_ed25519_seed(
            "did:webvh:vtc.example.com:abc".into(),
            &[0xCC; 32],
        ),
    ));

    let install_store = InstallTokenStore::new(install_ks.clone());

    let config: AppConfig = toml::from_str(&format!(
        r#"
        vtc_did = "did:webvh:vtc.example.com:abc"
        public_url = "{RP_ORIGIN}"
        [store]
        data_dir = "{}"
        "#,
        dir.path().display(),
    ))
    .expect("parse config");

    let state = AppState {
        sessions_ks,
        acl_ks,
        community_ks,
        config_ks,
        passkey_ks,
        install_ks,
        members_ks,
        join_requests_ks,
        policies_ks,
        active_policies_ks,
        status_lists_ks,
        registry_records_ks,
        sync_queue_ks,
        sync_cursor_ks,
        relationships_ks,
        relationships_by_did_ks,
        endorsement_types_ks,
        endorsements_ks,
        registry_client: None,
        registry_health: vtc_service::registry::RegistryHealth::new(),
        credential_signer,
        audit_ks,
        audit_key_ks,
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: None,
        atm: None,
        webauthn: None,
        public_url: Some(RP_ORIGIN.to_string()),
        install_signer: None,
        install_store,
        audit_writer: None,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
    };

    (state, dir)
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

/// The leave (`Depart`) executor arm is not yet wired and errors
/// rather than silently no-op'ing.
#[tokio::test]
async fn depart_is_not_yet_wired() {
    let (state, _dir) = build_state().await;

    let plan = EffectPlan::Depart {
        subject: "did:key:zLeaver".into(),
        disposition: Some("revoke-vmc".into()),
    };
    let err = execute::apply(&state, plan, ACTOR_DID)
        .await
        .expect_err("depart is not wired yet");
    assert!(
        matches!(err, vti_common::error::AppError::Internal(_)),
        "got {err:?}"
    );
}
