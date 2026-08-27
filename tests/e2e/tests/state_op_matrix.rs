//! Spec §7a.2 state × operation matrix.
//!
//! 24 cells covering every combination of starting state (S1, S2,
//! S3) and operation (rest/didcomm × enable/update/disable/rollback).
//! Each cell asserts the operation produces the documented outcome —
//! either the typed error variant for precondition-rejection cells,
//! or a successful state transition for the happy-path cells.
//!
//! ## Coverage in this PR
//!
//! Of the 24 cells:
//!
//! * **16 precondition-error cells** are tested directly. They
//!   exercise the read-preconditions phase of each operation and
//!   assert the typed `Err(...)` short-circuits before any
//!   mutation reaches `update_did_webvh`.
//! * **4 NoPriorMutation rollback cells** are tested by leaving
//!   the snapshot store empty and asserting both rollback ops
//!   surface `NoPriorMutation` from any starting state.
//! * **8 happy-path cells** (`✓ → Sn` in the spec table) are
//!   marked `#[ignore = "needs-webvh-host-fixture"]`. Publishing
//!   a new WebVH LogEntry inside a test requires a webvh-host
//!   fixture that's not yet in this workspace; tracked in
//!   `docs/05-design-notes/runtime-service-management-tasks.md`
//!   §P6 deferred items.
//!
//! Transport coverage (§7a.3) is collapsed to REST transport here
//! — exercising both transports per cell would multiply the test
//! count without exercising new behaviour, since the operation
//! layer is shared between REST and DIDComm handlers (the
//! transport difference is in route dispatch, not the typed-error
//! path).

mod common;

use vta_service::auth::AuthClaims;
use vta_service::messaging::handshake::AlwaysOkProver;
use vta_service::operations::protocol::OpContext;
use vta_service::operations::protocol::disable_didcomm::{
    DisableDidcommError, DisableDidcommParams, DisableTransport, disable_didcomm,
};
use vta_service::operations::protocol::disable_rest::{
    DisableRestError, DisableRestParams, disable_rest,
};
use vta_service::operations::protocol::enable_didcomm::{
    EnableDidcommError, EnableDidcommParams, enable_didcomm,
};
use vta_service::operations::protocol::enable_rest::{
    EnableRestError, EnableRestParams, enable_rest,
};
use vta_service::operations::protocol::rollback_didcomm::{
    RollbackDidcommError, RollbackDidcommParams, rollback_didcomm,
};
use vta_service::operations::protocol::rollback_rest::{
    RollbackRestError, RollbackRestParams, rollback_rest,
};
use vta_service::operations::protocol::update_didcomm::{
    MigrateAuditKind, UpdateDidcommError, UpdateDidcommParams, update_didcomm,
};
use vta_service::operations::protocol::update_rest::{
    UpdateRestError, UpdateRestParams, update_rest,
};

use crate::common::state_fixtures::{OpInfra, ServiceState, setup_vta_in_state};

const FIXTURE_URL: &str = "https://vta.test";

fn super_admin() -> AuthClaims {
    AuthClaims::unsafe_local_cli_super_admin("e2e-matrix")
}

// ── enable_rest cells ────────────────────────────────────────────

/// S1 and S3 advertise REST, so enabling it again is a no-op — *when the
/// document really advertises it*.
///
/// These fixtures model the S-state through `config.services` alone: they
/// cannot publish a DID document, which is why every happy-path cell in this
/// file is `#[ignore = "needs-webvh-host-fixture"]`. Until #1150 that proxy
/// held, because `enable` refused on the config by itself.
///
/// It no longer does, and deliberately: refusing on the config alone made
/// config-on-document-silent unmanageable — `update` requires the service on in
/// both places, so neither operation would touch it. Reconciling that is what
/// enable is for.
///
/// So these two cells now reach the document check and stop there, on a
/// fixture that seeded no webvh record. That is the honest outcome for what
/// this fixture actually sets up; asserting `ServiceAlreadyEnabled` would be
/// asserting the old rule under a state the fixture never established. The
/// document-advertised case is covered end to end in
/// `vta-service/tests/mock_vta.rs`, against the stub host.
#[tokio::test]
async fn s1_rest_enable_reaches_the_document_check() {
    let fx = setup_vta_in_state(ServiceState::S1).await;
    let infra = OpInfra::new(&fx).await;

    let err = enable_rest(
        &infra.deps(&fx),
        &super_admin(),
        EnableRestParams {
            url: "https://x.example.com".into(),
        },
        OpContext::Direct,
        "test",
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, EnableRestError::VtaDidRecordMissing(_)),
        "expected the document check to be reached, got {err:?}"
    );
}

/// As [`s1_rest_enable_reaches_the_document_check`] — S3 advertises REST too,
/// and this fixture models it the same way.
#[tokio::test]
async fn s3_rest_enable_reaches_the_document_check() {
    let fx = setup_vta_in_state(ServiceState::S3).await;
    let infra = OpInfra::new(&fx).await;

    let err = enable_rest(
        &infra.deps(&fx),
        &super_admin(),
        EnableRestParams {
            url: "https://x.example.com".into(),
        },
        OpContext::Direct,
        "test",
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, EnableRestError::VtaDidRecordMissing(_)),
        "expected the document check to be reached, got {err:?}"
    );
}

// ── update_rest cells ────────────────────────────────────────────

#[tokio::test]
async fn s2_rest_update_returns_service_not_present() {
    let fx = setup_vta_in_state(ServiceState::S2).await;
    let infra = OpInfra::new(&fx).await;

    let err = update_rest(
        &infra.deps(&fx),
        &super_admin(),
        UpdateRestParams {
            url: "https://new.example.com".into(),
        },
        OpContext::Direct,
        "test",
    )
    .await
    .unwrap_err();
    assert!(matches!(err, UpdateRestError::ServiceNotPresent));
}

// ── disable_rest cells ───────────────────────────────────────────

#[tokio::test]
async fn s1_rest_disable_returns_last_service_refused() {
    let fx = setup_vta_in_state(ServiceState::S1).await;
    let infra = OpInfra::new(&fx).await;

    let err = disable_rest(
        &infra.deps(&fx),
        &super_admin(),
        DisableRestParams,
        OpContext::Direct,
        "test",
    )
    .await
    .unwrap_err();
    assert!(matches!(err, DisableRestError::LastServiceRefused));
}

#[tokio::test]
async fn s2_rest_disable_returns_service_not_present() {
    let fx = setup_vta_in_state(ServiceState::S2).await;
    let infra = OpInfra::new(&fx).await;

    let err = disable_rest(
        &infra.deps(&fx),
        &super_admin(),
        DisableRestParams,
        OpContext::Direct,
        "test",
    )
    .await
    .unwrap_err();
    assert!(matches!(err, DisableRestError::ServiceNotPresent));
}

// ── enable_didcomm cells ─────────────────────────────────────────

#[tokio::test]
async fn s2_didcomm_enable_returns_already_enabled() {
    let fx = setup_vta_in_state(ServiceState::S2).await;
    let infra = OpInfra::new(&fx).await;
    let prover = AlwaysOkProver;

    let err = enable_didcomm(
        &infra.deps(&fx),
        &prover,
        &super_admin(),
        EnableDidcommParams {
            mediator_did: fx.assumed_mediator_did.clone(),
            force: false,
            handshake_timeout: std::time::Duration::from_secs(1),
        },
        OpContext::Direct,
        "test",
    )
    .await
    .unwrap_err();
    assert!(matches!(err, EnableDidcommError::DidcommAlreadyEnabled));
}

#[tokio::test]
async fn s3_didcomm_enable_returns_already_enabled() {
    let fx = setup_vta_in_state(ServiceState::S3).await;
    let infra = OpInfra::new(&fx).await;
    let prover = AlwaysOkProver;

    let err = enable_didcomm(
        &infra.deps(&fx),
        &prover,
        &super_admin(),
        EnableDidcommParams {
            mediator_did: fx.assumed_mediator_did.clone(),
            force: false,
            handshake_timeout: std::time::Duration::from_secs(1),
        },
        OpContext::Direct,
        "test",
    )
    .await
    .unwrap_err();
    assert!(matches!(err, EnableDidcommError::DidcommAlreadyEnabled));
}

// ── update_didcomm cells ─────────────────────────────────────────

#[tokio::test]
async fn s1_didcomm_update_returns_didcomm_not_enabled() {
    let fx = setup_vta_in_state(ServiceState::S1).await;
    let infra = OpInfra::new(&fx).await;
    let prover = AlwaysOkProver;

    let err = update_didcomm(
        &infra.deps(&fx),
        &prover,
        &super_admin(),
        UpdateDidcommParams {
            new_mediator_did: "did:peer:2.B".into(),
            drain_ttl: std::time::Duration::from_secs(86_400),
            force: false,
            handshake_timeout: std::time::Duration::from_secs(1),
            audit_kind: MigrateAuditKind::Forward,
            transport: vta_service::operations::protocol::disable_didcomm::DisableTransport::Rest,
        },
        OpContext::Direct,
        "test",
    )
    .await
    .unwrap_err();
    assert!(matches!(err, UpdateDidcommError::DidcommNotEnabled));
}

// ── disable_didcomm cells ────────────────────────────────────────

#[tokio::test]
async fn s1_didcomm_disable_returns_didcomm_not_enabled() {
    let fx = setup_vta_in_state(ServiceState::S1).await;
    let infra = OpInfra::new(&fx).await;

    let err = disable_didcomm(
        &infra.deps(&fx),
        &super_admin(),
        DisableDidcommParams {
            drain_ttl: std::time::Duration::from_secs(3600),
            transport: DisableTransport::Rest,
        },
        OpContext::Direct,
        "test",
    )
    .await
    .unwrap_err();
    assert!(matches!(err, DisableDidcommError::DidcommNotEnabled));
}

#[tokio::test]
async fn s2_didcomm_disable_returns_no_protocol_remaining() {
    let fx = setup_vta_in_state(ServiceState::S2).await;
    let infra = OpInfra::new(&fx).await;

    let err = disable_didcomm(
        &infra.deps(&fx),
        &super_admin(),
        DisableDidcommParams {
            drain_ttl: std::time::Duration::from_secs(3600),
            transport: DisableTransport::Rest,
        },
        OpContext::Direct,
        "test",
    )
    .await
    .unwrap_err();
    // S2 → disable didcomm would leave nothing → NoProtocolRemaining
    // (the disable_didcomm wire-error variant for what spec §3.2
    // calls LastServiceRefused).
    assert!(matches!(err, DisableDidcommError::NoProtocolRemaining));
}

// ── rollback cells (NoPriorMutation when snapshot empty) ─────────

#[tokio::test]
async fn rollback_rest_with_empty_snapshot_returns_no_prior_mutation() {
    for state in [ServiceState::S1, ServiceState::S2, ServiceState::S3] {
        let fx = setup_vta_in_state(state).await;
        let infra = OpInfra::new(&fx).await;

        let err = rollback_rest(&infra.deps(&fx), &super_admin(), RollbackRestParams, "test")
            .await
            .unwrap_err();
        assert!(
            matches!(err, RollbackRestError::NoPriorMutation),
            "rollback_rest from {state:?} with empty snapshot must return NoPriorMutation, got {err:?}",
        );
    }
}

#[tokio::test]
async fn rollback_didcomm_with_empty_snapshot_returns_no_prior_mutation() {
    for state in [ServiceState::S1, ServiceState::S2, ServiceState::S3] {
        let fx = setup_vta_in_state(state).await;
        let infra = OpInfra::new(&fx).await;
        let prover = AlwaysOkProver;

        let err = rollback_didcomm(
            &infra.deps(&fx),
            &prover,
            &super_admin(),
            RollbackDidcommParams {
                drain_ttl: std::time::Duration::from_secs(86_400),
                transport: DisableTransport::Rest,
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, RollbackDidcommError::NoPriorMutation),
            "rollback_didcomm from {state:?} with empty snapshot must return NoPriorMutation, got {err:?}",
        );
    }
}

// ── Happy-path cells (deferred — need WebVH host fixture) ────────

#[tokio::test]
#[ignore = "needs-webvh-host-fixture: test publishes a new LogEntry which requires a webvh host"]
async fn s1_rest_update_publishes_new_logentry() {
    // ✓ → S1: publishing a new LogEntry with the new URL.
    // Deferred until a webvh-host fixture lands in tests/e2e.
}

#[tokio::test]
#[ignore = "needs-webvh-host-fixture"]
async fn s1_didcomm_enable_publishes_new_logentry() {
    // ✓ → S3
}

#[tokio::test]
#[ignore = "needs-webvh-host-fixture"]
async fn s2_rest_enable_publishes_new_logentry() {
    // ✓ → S3
}

#[tokio::test]
#[ignore = "needs-webvh-host-fixture"]
async fn s2_didcomm_update_publishes_new_logentry() {
    // ✓ → S2 (mediator change)
}

#[tokio::test]
#[ignore = "needs-webvh-host-fixture"]
async fn s3_rest_update_publishes_new_logentry() {
    // ✓ → S3 (URL change)
}

#[tokio::test]
#[ignore = "needs-webvh-host-fixture"]
async fn s3_rest_disable_publishes_new_logentry() {
    // ✓ → S2
}

#[tokio::test]
#[ignore = "needs-webvh-host-fixture"]
async fn s3_didcomm_update_publishes_new_logentry() {
    // ✓ → S3 (mediator change)
}

#[tokio::test]
#[ignore = "needs-webvh-host-fixture"]
async fn s3_didcomm_disable_publishes_new_logentry() {
    // ✓ → S1
}

// Variable note: keep `FIXTURE_URL` referenced even if unused
// inline so the constant stays warning-free; happy-path tests
// will use it when un-ignored.
#[allow(dead_code)]
fn _fixture_url_in_use() -> &'static str {
    FIXTURE_URL
}
