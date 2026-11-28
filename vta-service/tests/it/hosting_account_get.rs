//! `vta/hosting-account/get/0.1`'s declared refusal: with `refresh`, a host the
//! VTA cannot read answers `hostUnreachable`, never a bare failure.
#![cfg(feature = "webvh")]

use vta_service::hosting_account::{self, HostingAccountRecord};
use vta_test_support::MockVta;

const GET: &str = "https://trusttasks.org/spec/vta/hosting-account/get/0.1";

#[tokio::test(flavor = "multi_thread")]
async fn refresh_against_an_unreachable_host_is_host_unreachable() {
    let mock = MockVta::start_with_webvh_host().await;
    // A record naming a server this VTA no longer has registered: the host
    // cannot be reached.
    hosting_account::store(
        &mock.ctx.state.service_state_ks,
        &HostingAccountRecord::registered(
            "gone-host",
            "did:webvh:QmGone:gone.example",
            "gone.example",
            None,
        ),
    )
    .await
    .unwrap();
    let client = mock.signing_client(0x32, "admin", vec![]).await;

    // Without `refresh`, the record answers.
    let recorded = client
        .dispatch_trust_task(GET, serde_json::json!({}), 10)
        .await
        .expect("get from the record");
    assert_eq!(recorded["registered"], true);

    let err = client
        .dispatch_trust_task(GET, serde_json::json!({ "refresh": true }), 10)
        .await
        .expect_err("refresh cannot reach the host");
    match err {
        vta_sdk::error::VtaError::Rejected { code, .. } => {
            assert_eq!(code, "vta/hosting-account/get:hostUnreachable")
        }
        other => panic!("expected a declared refusal, got {other:?}"),
    }

    mock.shutdown().await;
}
