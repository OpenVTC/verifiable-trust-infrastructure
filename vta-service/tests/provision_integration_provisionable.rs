//! Worked example + regression for the provisionable-VTA test helper (#468).
//!
//! [`bootstrap_test_vta`] wires the VTA's signing identity but registers no
//! target context, so a `provision_integration` call errors at the
//! context-existence precondition — leaving the highest-value surface (template
//! render → seal → VC issuance) unexercised by a fuzz campaign.
//!
//! [`bootstrap_provisionable_test_vta`] additionally registers
//! [`PROVISIONABLE_CONTEXT`], so a well-formed request reaches `Ok`. This is the
//! scaffold a fuzzer copies: stand up the provisionable VTA once, then drive
//! arbitrary template variables (mutating [`provisionable_mediator_vars`])
//! through the real renderer/sealer/issuer.

use vta_service::operations::provision_integration::{
    AssertionMode, ProvisionIntegrationParams, provision_integration,
};
use vta_service::test_support::{
    PROVISIONABLE_CONTEXT, bootstrap_provisionable_test_vta, bootstrap_test_vta, open_test_store,
    provisionable_mediator_vars, signed_request_with_vars, super_admin_claims,
};

/// A well-formed request against the provisionable VTA renders, seals, and
/// issues — `Ok` with a non-empty armored bundle + digest — for both
/// non-attested assertion modes the helper supports.
#[tokio::test]
async fn provisionable_vta_reaches_render_seal_issue_for_both_assertion_modes() {
    for mode in [AssertionMode::PinnedOnly, AssertionMode::DidSigned] {
        let ts = open_test_store().await;
        let (_vta_did, deps) = bootstrap_provisionable_test_vta(&ts).await;

        let request = signed_request_with_vars(
            "didcomm-mediator",
            PROVISIONABLE_CONTEXT,
            provisionable_mediator_vars(),
        )
        .await;

        let output = provision_integration(
            &deps,
            &super_admin_claims(),
            ProvisionIntegrationParams {
                request,
                context: PROVISIONABLE_CONTEXT.into(),
                assertion_mode: mode,
                vc_validity: None,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("provision should succeed in {mode:?} mode: {e:?}"));

        assert!(
            !output.armored.is_empty(),
            "{mode:?}: armored bundle is non-empty"
        );
        assert!(!output.digest.is_empty(), "{mode:?}: digest is non-empty");
    }
}

/// The gap this helper closes: without a registered context, the very same
/// well-formed request errors at the precondition stage — never reaching the
/// render/seal/issue path. Guards against a regression that would make the
/// provisionable helper redundant (e.g. `bootstrap_test_vta` silently seeding a
/// context).
#[tokio::test]
async fn plain_bootstrap_test_vta_errors_before_render_without_a_context() {
    let ts = open_test_store().await;
    let (_vta_did, deps) = bootstrap_test_vta(&ts).await;

    let request = signed_request_with_vars(
        "didcomm-mediator",
        PROVISIONABLE_CONTEXT,
        provisionable_mediator_vars(),
    )
    .await;

    let result = provision_integration(
        &deps,
        &super_admin_claims(),
        ProvisionIntegrationParams {
            request,
            context: PROVISIONABLE_CONTEXT.into(),
            assertion_mode: AssertionMode::PinnedOnly,
            vc_validity: None,
        },
    )
    .await;

    // `ProvisionIntegrationOutput` isn't `Debug`, so map the Ok arm before
    // unwrapping the error.
    let err = result
        .map(|_| ())
        .expect_err("no context registered → precondition error, not a render");
    assert!(
        err.to_string().contains(PROVISIONABLE_CONTEXT),
        "error names the missing context: {err:?}"
    );
}
