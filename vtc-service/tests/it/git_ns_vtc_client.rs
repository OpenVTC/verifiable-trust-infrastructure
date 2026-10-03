//! `vtc-client`'s `git-ns/*` calls, driven against the VTC over every
//! transport it serves: a TSP session and a DIDComm session through a real
//! mediator to the production listener, and a signed document posted to
//! `POST /v1/trust-tasks` over HTTPS.
//!
//! The same calls, on the same client methods, must answer alike whichever
//! transport the client was built for: a bind, a view that shows it, the
//! administrator's listings (`namespace/list`, `repo/list`, `view` 0.5), a refusal
//! whose specification code survives the trip, and an unbind sent as a
//! pre-signed document (the path a step-up retry takes). Over a session the
//! document is bound to its sender, so a call whose key names another DID is
//! refused before anything is sent.
//!
//! Requires `--features transport-harness` (and `tsp` for the TSP case); CI runs
//! it.

#![cfg(feature = "transport-harness")]

use serde_json::Value;

use vtc_client::git_ns::{GIT_NS_VIEW_TYPE, specs, task_error};
use vtc_client::{HolderKey, VtcClient, VtcError};
use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::server::AppState;

/// A deterministic `did:key` and its multibase private key.
fn did_key_from_seed(seed_byte: u8) -> (String, String) {
    let seed = [seed_byte; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
    );
    let mut buf = vec![0x80, 0x26];
    buf.extend_from_slice(&seed);
    (did, multibase::encode(multibase::Base::Base58Btc, &buf))
}

/// Make `did` a community administrator (the capability a bind needs) and
/// install the shipped policies, `gitNamespace` among them.
async fn seed(state: &AppState, did: &str) {
    store_acl_entry(
        &state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role: VtcRole::Admin,
            label: None,
            admin: VtcRole::Admin.implied_authority(),
            delegated_by: None,
            created_at: 0,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("seed the community administrator");
    vtc_service::policy::default::install_defaults(&state.policies_ks, &state.active_policies_ks)
        .await
        .expect("install default policies");
}

/// The namespaces a `git-ns/view/0.4` answer lists, as `forge/owner`.
fn listed(view: &specs::view::v0_4::Response) -> Vec<String> {
    let v = serde_json::to_value(view).unwrap();
    v["namespaces"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|ns| {
            format!(
                "{}/{}",
                ns["forge"].as_str().unwrap_or_default(),
                ns["owner"].as_str().unwrap_or_default()
            )
        })
        .collect()
}

/// Bind, view, a refused second bind, and an unbind sent as a pre-signed
/// document — over whatever transport `client` was built for.
async fn bind_view_refuse_unbind(client: &VtcClient, key: &HolderKey, over: &str) {
    let bound = client
        .git_ns_bind("github.com", "acme", "manual", key)
        .await
        .unwrap_or_else(|e| panic!("bind over {over}: {e}"));
    let bound = serde_json::to_value(&bound).unwrap();
    assert_eq!(bound["namespace"]["forge"], "github.com", "over {over}");
    assert_eq!(bound["namespace"]["owner"], "acme", "over {over}");
    let namespace = bound["namespace"]["id"]
        .as_str()
        .expect("the bind names the namespace")
        .to_string();

    let view = client
        .git_ns_view_v4(None, key)
        .await
        .unwrap_or_else(|e| panic!("view over {over}: {e}"));
    assert_eq!(listed(&view), ["github.com/acme"], "over {over}");

    // The administrator's reads, signed and sent the same way.
    let namespaces = client
        .git_ns_namespace_list(None, key)
        .await
        .unwrap_or_else(|e| panic!("namespace/list over {over}: {e}"));
    assert_eq!(
        namespaces["namespaces"][0]["resource"], "github.com/acme",
        "over {over}"
    );
    assert_eq!(
        namespaces["namespaces"][0]["id"],
        namespace.as_str(),
        "over {over}"
    );
    let repos = client
        .git_ns_repo_list(Some(&namespace), key)
        .await
        .unwrap_or_else(|e| panic!("repo/list over {over}: {e}"));
    assert_eq!(repos["repos"], serde_json::json!([]), "over {over}");
    let admin_view = client
        .git_ns_view_v5(None, true, false, key)
        .await
        .unwrap_or_else(|e| panic!("view 0.5 (administrator) over {over}: {e}"));
    assert_eq!(listed(&admin_view), ["github.com/acme"], "over {over}");
    let break_glass = client
        .git_ns_view_v5(None, true, true, key)
        .await
        .unwrap_or_else(|e| panic!("view 0.5 (break-glass) over {over}: {e}"));
    assert!(
        listed(&break_glass).is_empty(),
        "over {over}: no break-glass, no namespace"
    );

    // A refusal carries the specification's code on every transport.
    let again = client
        .git_ns_bind("github.com", "acme", "manual", key)
        .await
        .expect_err("a second bind of the same owner is refused");
    let (code, _) = task_error(&again).unwrap_or_else(|| {
        panic!("over {over}, the refusal is not a trust-task-error document: {again}")
    });
    assert_eq!(code, vtc_service::git_ns::ops::ALREADY_BOUND, "over {over}");

    // The step-up path: sign once, send the signed document.
    let unbind_type =
        <specs::namespace::unbind::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
    let doc = client
        .git_ns_sign(
            unbind_type,
            &serde_json::json!({ "namespace": namespace }),
            key,
        )
        .await
        .expect("sign the unbind");
    let _: Value = client
        .git_ns_send_signed(unbind_type, &doc)
        .await
        .unwrap_or_else(|e| panic!("unbind over {over}: {e}"));
    let view = client.git_ns_view_v4(None, key).await.unwrap();
    assert!(listed(&view).is_empty(), "over {over}: {:?}", listed(&view));
}

/// Over a session the VTC accepts a document only from the DID that signed
/// it, so a key for any other DID is refused by the client, unsent.
async fn another_signer_is_refused_on_a_session(client: &VtcClient, over: &str) {
    let (other_did, other_key) = did_key_from_seed(0x77);
    let other = HolderKey::from_did_key(&other_did, &other_key).unwrap();
    let err = client
        .git_ns_view_v4(None, &other)
        .await
        .expect_err("a document signed as another DID does not ride this session");
    assert!(matches!(err, VtcError::Signing(_)), "over {over}: {err}");
    let err = client
        .git_ns_task::<_, Value>(GIT_NS_VIEW_TYPE, &serde_json::json!({}), &other)
        .await
        .expect_err("nor through the generic call");
    assert!(matches!(err, VtcError::Signing(_)), "over {over}: {err}");
}

#[cfg(feature = "tsp")]
#[tokio::test]
async fn git_ns_tasks_answer_over_tsp() {
    use vtc_service::test_support::MockVtcTransport;

    let mock = MockVtcTransport::start_with_tsp().await;
    let (did, key) = did_key_from_seed(0x61);
    seed(&mock.vtc.state, &did).await;
    mock.register_local_did(&did).await;
    let client = VtcClient::connect_tsp(&did, &key, mock.vtc_did(), mock.mediator_did(), None)
        .await
        .expect("connect over TSP");
    let holder = HolderKey::from_did_key(&did, &key).unwrap();

    bind_view_refuse_unbind(&client, &holder, "TSP").await;
    another_signer_is_refused_on_a_session(&client, "TSP").await;

    client.shutdown().await;
    mock.shutdown().await;
}

#[tokio::test]
async fn git_ns_tasks_answer_over_didcomm() {
    use vtc_service::test_support::MockVtcTransport;

    let mock = MockVtcTransport::start().await;
    let (did, key) = did_key_from_seed(0x62);
    seed(&mock.vtc.state, &did).await;
    mock.register_local_did(&did).await;
    let client = VtcClient::connect_didcomm(&did, &key, mock.vtc_did(), mock.mediator_did(), None)
        .await
        .expect("connect over DIDComm");
    let holder = HolderKey::from_did_key(&did, &key).unwrap();

    bind_view_refuse_unbind(&client, &holder, "DIDComm").await;
    another_signer_is_refused_on_a_session(&client, "DIDComm").await;

    client.shutdown().await;
    mock.shutdown().await;
}

#[tokio::test]
async fn git_ns_tasks_answer_over_https() {
    use vtc_service::test_support::{MockVtc, TEST_VTC_DID};

    let mock = MockVtc::start().await;
    let (did, key) = did_key_from_seed(0x63);
    seed(&mock.vtc.state, &did).await;
    // No session and no token: each task is signed with the key and posted.
    let client = VtcClient::anonymous(&format!("{}/v1", mock.base_url()), TEST_VTC_DID);
    let holder = HolderKey::from_did_key(&did, &key).unwrap();

    bind_view_refuse_unbind(&client, &holder, "HTTPS").await;

    client.shutdown().await;
    mock.shutdown().await;
}
