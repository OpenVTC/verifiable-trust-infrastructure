//! A VTA set up by the library's setup engine and run in this process
//! ([`vta_service::embedded::EmbeddedVta`]), driven by the real `VtaClient`
//! over its loopback REST listener — the path an application that gives its
//! user a personal VTA (openvtc's quick start) takes.
#![cfg(all(feature = "setup", feature = "rest"))]

use vta_sdk::client::{AutoConnect, VtaClient};
use vta_service::config::AppConfig;
use vta_service::embedded::EmbeddedVta;
use vta_service::setup::{SilentUi, WizardInputs, apply_inputs};

/// Set up a personal VTA with `admin` as its owner: a REST-only, `did:key` VTA
/// whose seed sits in a plaintext file under the data directory (the test
/// stand-in for the host application's own protected storage).
async fn set_up(root: &std::path::Path, admin: &str) -> AppConfig {
    let config_path = root.join("config.toml");
    let inputs: WizardInputs = toml::from_str(&format!(
        r#"
        config_path = {config:?}
        data_dir    = {data:?}
        vta_name    = "embedded"
        # An embedded VTA's REST is a loopback port picked at each start, which
        # nothing advertises.
        rest_local_only = true
        admin_did   = {admin:?}

        [services]
        rest    = true
        didcomm = false

        [secrets]
        backend = "plaintext"

        [messaging]
        kind = "skip"

        [vta_did]
        kind = "create_did_key"
        "#,
        config = config_path.display().to_string(),
        data = root.join("data").display().to_string(),
    ))
    .expect("setup inputs");
    apply_inputs(inputs, &SilentUi).await.expect("setup");
    AppConfig::load(Some(config_path)).expect("load the config setup wrote")
}

async fn connect(vta: &EmbeddedVta, vta_did: &str, admin: &str, admin_key: &str) -> VtaClient {
    VtaClient::connect_auto(AutoConnect {
        vta_url: &vta.rest_url(),
        vta_did,
        credential_did: admin,
        private_key_multibase: admin_key,
        mediator_did: None,
    })
    .await
    .expect("authenticate to the embedded VTA")
    .client
}

/// Set up, start, use, stop — then start the same VTA again in the same
/// process, which is what an application does every time its user reopens it.
/// The second start is the one that used to fail: the service assumed it owned
/// the process (a global metrics recorder installed twice panics).
#[tokio::test(flavor = "multi_thread")]
async fn an_embedded_vta_serves_its_owner_and_restarts_in_process() {
    let root = tempfile::tempdir().expect("tempdir");
    let (admin, admin_key, _) = vta_sdk::did_key::generate_did_key().expect("admin did:key");
    let config = set_up(root.path(), &admin).await;
    let vta_did = config.vta_did.clone().expect("setup minted a VTA DID");

    // The second start binds the port the first one picked, as a host
    // application does so the VTA's URL survives a restart.
    let mut port = 0;
    for generation in 0..2 {
        let vta = EmbeddedVta::start_on(config.clone(), None, port)
            .await
            .expect("start the embedded VTA");
        if generation == 0 {
            port = vta.rest_port();
        } else {
            assert_eq!(vta.rest_port(), port, "the restart keeps the port");
        }
        assert!(
            vta.rest_url().starts_with("http://127.0.0.1:"),
            "an embedded VTA listens on loopback only: {}",
            vta.rest_url()
        );

        let client = connect(&vta, &vta_did, &admin, &admin_key).await;
        let contexts = client
            .list_contexts()
            .await
            .unwrap_or_else(|e| panic!("generation {generation}: list contexts: {e}"));
        assert!(
            !contexts.contexts.is_empty(),
            "generation {generation}: setup's seed context is served"
        );

        vta.shutdown().await.expect("clean shutdown");
    }
}
