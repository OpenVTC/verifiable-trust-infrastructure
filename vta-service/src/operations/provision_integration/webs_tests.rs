//! Provisioning a host service whose DID is a `did:webs` (design note
//! did-webs-in-the-vta §4, S7), end to end: the VTA mints and publishes it
//! from the node template, the sealed bundle carries its keys and its
//! `keri.cesr`, and the integration-side loader the host services use signs a
//! Trust Task that verifies against the document the stream derives.

use std::collections::BTreeMap;
use std::sync::Mutex;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_did_webs::{DidWebs, resolve_from_artifacts};
use serde_json::{Value, json};
use vta_sdk::provision_integration::http::AdminScope;
use vta_sdk::sealed_transfer::SealedPayloadV1;
use vta_sdk::sealed_transfer::template_bootstrap::{DidKeyMaterialV2, TemplateOutput};

use super::sealed_transfer_open::open_raw_for_test;
use super::webs::WebsHostSource;
use super::*;
use crate::operations::did_webs::WebsHost;
use crate::test_support::{
    bootstrap_test_vta, open_test_store, seed_webvh_server, signed_request_with_vars,
    super_admin_claims,
};
use crate::webvh_host::RequestUriResponse;

const MEDIATOR: &str = "did:peer:2.Vz6MkMediator.Ez6LSMediator";

/// A did-hosting service that records what it is given and answers as one
/// does: the DID built from the domain and the slot.
#[derive(Default)]
struct RecordingHost {
    published: Mutex<Vec<(String, String)>>,
}

impl WebsHost for RecordingHost {
    async fn resolve_domain(&self, requested: Option<&str>) -> Result<String, AppError> {
        Ok(requested.unwrap_or("hosting.example").to_string())
    }

    async fn publish(
        &self,
        mnemonic: &str,
        keri_cesr: &str,
        domain: Option<&str>,
    ) -> Result<RequestUriResponse, AppError> {
        self.published
            .lock()
            .unwrap()
            .push((mnemonic.to_string(), keri_cesr.to_string()));
        let label = domain.unwrap_or("hosting.example").replace(':', "%3A");
        Ok(RequestUriResponse {
            did_url: format!("did:webs:{label}:{}", mnemonic.replace('/', ":")),
            mnemonic: mnemonic.to_string(),
        })
    }

    async fn delete(&self, _mnemonic: &str, _domain: Option<&str>) -> Result<(), AppError> {
        Ok(())
    }
}

struct Hosts(RecordingHost);

impl WebsHostSource for Hosts {
    type Host<'a> = &'a RecordingHost;

    async fn host<'a>(
        &'a self,
        _state: &'a ProvisionIntegrationDeps,
        _server_id: &str,
    ) -> Result<&'a RecordingHost, AppError> {
        Ok(&self.0)
    }
}

/// A VTA that may make did:webs service DIDs, with one registered host.
async fn webs_vta(
    service_dids: bool,
) -> (crate::test_support::TestStore, ProvisionIntegrationDeps) {
    let ts = open_test_store().await;
    let (_vta_did, deps) = bootstrap_test_vta(&ts).await;
    {
        let mut config = deps.config.write().await;
        config.dids.webs_enabled = true;
        config.dids.webs_service_dids = service_dids;
    }
    crate::contexts::create_context(&ts.contexts_ks, "nodes", "Host services")
        .await
        .expect("context");
    seed_webvh_server(&ts.webvh_ks, "host-1", "did:web:hosting.example").await;
    (ts, deps)
}

fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), json!(v)))
        .collect()
}

async fn provision(
    deps: &ProvisionIntegrationDeps,
    hosts: &Hosts,
    template: &str,
    vars: BTreeMap<String, Value>,
) -> Result<ProvisionIntegrationOutput, AppError> {
    let request = signed_request_with_vars(template, "nodes", vars).await;
    provision_integration_with(
        deps,
        &super_admin_claims(),
        ProvisionIntegrationParams {
            request,
            context: "nodes".into(),
            admin_scope: AdminScope::Context,
            assertion_mode: AssertionMode::PinnedOnly,
            vc_validity: None,
        },
        hosts,
    )
    .await
}

/// Provision `template` as a did:webs and check everything the integration
/// receives, as the host services read it.
async fn a_node_template_provisions_as_did_webs(template: &str, extra: &[(&str, &str)]) {
    let mut v = vars(&[("MEDIATOR_DID", MEDIATOR)]);
    v.extend(vars(extra));
    a_template_provisions_as_did_webs(template, v).await;
}

/// As [`a_node_template_provisions_as_did_webs`], with the template's own
/// variables given whole; returns the document the stream derives.
async fn a_template_provisions_as_did_webs(
    template: &str,
    extra: BTreeMap<String, Value>,
) -> Value {
    let (ts, deps) = webs_vta(true).await;
    let hosts = Hosts(RecordingHost::default());
    let mut v = vars(&[
        ("WEBVH_SERVER", "host-1"),
        ("WEBVH_PATH", "nodes"),
        ("DID_METHOD", "webs"),
    ]);
    v.extend(extra);
    let output = provision(&deps, &hosts, template, v)
        .await
        .expect("provision_integration");

    let did = output
        .summary
        .integration_did
        .clone()
        .expect("an integration DID");
    assert!(
        did.starts_with("did:webs:hosting.example:nodes:"),
        "a did:webs at the slot asked for: {did}"
    );
    assert_eq!(output.summary.webvh_server_id.as_deref(), Some("host-1"));

    // The sealed shape is the one every opener already reads: V1, with the
    // key event stream as an output and no did.jsonl.
    let SealedPayloadV1::TemplateBootstrap(payload) =
        open_raw_for_test(&output.armored, &output.digest, &[7u8; 32])
    else {
        panic!("a level-1 did:webs seals TemplateBootstrap");
    };
    let outputs = &payload.config.outputs;
    assert_eq!(outputs.len(), 1, "{outputs:?}");
    let TemplateOutput::WebsKeriCesr {
        did: stream_did,
        keri_cesr,
    } = &outputs[0]
    else {
        panic!("the only output is the key event stream: {outputs:?}");
    };
    assert_eq!(stream_did, &did);
    let published = hosts.0.published.lock().unwrap().clone();
    let [(mnemonic, stream)] = published.as_slice() else {
        panic!("published once: {published:?}");
    };
    assert_eq!(keri_cesr, stream, "the stream the host serves");
    assert!(mnemonic.starts_with("nodes/"), "{mnemonic}");

    // The bundled document is what a resolver derives from that stream.
    let derived = serde_json::to_value(
        resolve_from_artifacts(&DidWebs::parse(&did).unwrap(), keri_cesr.as_bytes(), None)
            .expect("the stream resolves"),
    )
    .unwrap();
    assert_eq!(payload.config.did_document, derived);
    assert_eq!(payload.config.template_name, template);

    // The keys, under the ids the document gives them.
    let material = DidKeyMaterialV2::from_v1(payload.secrets.get(&did).expect("secrets"));
    let in_relationship = |relationship: &str, id: &str| {
        derived[relationship]
            .as_array()
            .into_iter()
            .flatten()
            .any(|e| e.as_str().or_else(|| e["id"].as_str()) == Some(id))
    };
    assert!(
        in_relationship("authentication", &material.signing_key.key_id)
            && in_relationship("assertionMethod", &material.signing_key.key_id),
        "the key-state key is the level-1 signing key: {derived}"
    );
    assert!(
        in_relationship("keyAgreement", &material.ka_key.key_id),
        "the designated key agreement key: {derived}"
    );
    assert_eq!(material.ka_key.key_type, vta_sdk::keys::KeyType::X25519);

    // The integration side: the bundle a host service stores, its signing key
    // by role, and a Trust Task signed with it.
    let bundle = material.secrets_bundle(&payload.config.did_document);
    let signing = bundle.trust_task_signing_key().expect("a signing key");
    assert_eq!(
        Some(signing.key_id.as_str()),
        bundle
            .trust_task_signing_key_for(&derived)
            .map(|e| e.key_id.as_str()),
        "the stored bundle leads with the key the document lists for authentication"
    );
    let key =
        vta_sdk::trust_task_sign::HolderKey::new(&signing.key_id, &signing.private_key_multibase)
            .expect("a holder key");
    assert_eq!(key.holder_did(), did);
    let body = vta_sdk::trust_task_sign::build_signed_with(
        "https://trusttasks.org/spec/vtc/join-requests/submit/0.3",
        json!({}),
        &key,
        "did:key:z6MkVtc",
    )
    .await
    .expect("signed");
    let received: Value = serde_json::from_str(&body).unwrap();
    let mut resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .unwrap();
    resolver
        .add_did_document(&did, serde_json::from_value(derived.clone()).unwrap())
        .await;
    let signer = vta_sdk::trust_task_proof::verify_trust_task_proof_value(
        &received,
        &vta_sdk::trust_task_proof::TrustTaskVmResolver::new(resolver),
    )
    .await
    .expect("the proof verifies against the did:webs document");
    assert_eq!(signer, did);

    // The first integration in the context becomes its primary DID, as on
    // every other path; and the DID is recorded as the service DID it is.
    let ctx = crate::contexts::get_context(&ts.contexts_ks, "nodes")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ctx.did.as_deref(), Some(did.as_str()));
    let record = crate::webs_store::get(&ts.webs_ks, &did)
        .await
        .unwrap()
        .expect("recorded");
    assert_eq!(
        record.did_class,
        Some(crate::webs_store::WebsDidClass::Service)
    );
    assert_eq!(record.template.map(|t| t.name).as_deref(), Some(template));
    derived
}

/// S7: a VTC's own identity as a did:webs (VTI-KEY-001, level 1 per
/// VTI-KEY-146), from `vtc-host-classical` — `vtc-host` without the
/// post-quantum key a level-1 did:webs cannot hold — with the messaging
/// transports the VTC setup supplies whole (`SERVICE_TSP`, `SERVICE_DIDCOMM`).
#[tokio::test]
async fn vti_key_001_a_vtc_host_provisions_as_a_did_webs() {
    let mut v = vars(&[("URL", "https://vtc.example")]);
    v.insert(
        vta_sdk::did_templates::TSP_SERVICE_VAR.into(),
        vta_sdk::did_templates::tsp_service(MEDIATOR).unwrap(),
    );
    v.insert(
        vta_sdk::did_templates::DIDCOMM_SERVICE_VAR.into(),
        vta_sdk::did_templates::didcomm_service(MEDIATOR).unwrap(),
    );
    let doc = a_template_provisions_as_did_webs("vtc-host-classical", v).await;
    let did = doc["id"].as_str().unwrap();
    let types: Vec<&str> = doc["service"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|s| match &s["type"] {
            Value::String(t) => vec![t.as_str()],
            Value::Array(ts) => ts.iter().filter_map(Value::as_str).collect(),
            _ => vec![],
        })
        .collect();
    for want in [
        "TSPTransport",
        "DIDCommMessaging",
        "VTCRest",
        "VTCStatusList",
        "TrustTaskHTTPS",
        "SignInPortal",
    ] {
        assert!(types.contains(&want), "{want} designated: {doc}");
    }
    assert_eq!(
        doc["assertionMethod"].as_array().map(Vec::len),
        Some(1),
        "one signing key: {doc}"
    );
    assert!(
        doc["service"].as_array().unwrap().iter().any(|s| s["id"]
            .as_str()
            .is_some_and(|i| i.ends_with("#vtc-status-list"))
            && s["serviceEndpoint"] == "https://vtc.example/v1/status-lists"),
        "{doc}"
    );
    assert!(did.starts_with("did:webs:"), "{did}");
}

/// S7: a `dtg-witness` integration as a did:webs.
#[tokio::test]
async fn a_dtg_witness_provisions_as_a_did_webs() {
    a_node_template_provisions_as_did_webs("dtg-witness", &[]).await;
}

/// S7: a `ballot-box` integration as a did:webs, its `TrustTaskHTTPS` cast
/// door designated with it.
#[tokio::test]
async fn a_ballot_box_provisions_as_a_did_webs() {
    a_node_template_provisions_as_did_webs("ballot-box", &[("HTTPS_URL", "https://votes.example")])
        .await;
}

/// `[dids] webs_service_dids` gates a provisioned integration as it gates
/// `create/0.2`'s service class, and the refusal comes before anything is
/// minted or published.
#[tokio::test]
async fn a_did_webs_integration_waits_for_webs_service_dids() {
    let (ts, deps) = webs_vta(false).await;
    let hosts = Hosts(RecordingHost::default());
    let err = provision(
        &deps,
        &hosts,
        "dtg-witness",
        vars(&[
            ("MEDIATOR_DID", MEDIATOR),
            ("WEBVH_SERVER", "host-1"),
            ("DID_METHOD", "webs"),
        ]),
    )
    .await
    .err()
    .expect("refused");
    assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
    assert!(err.to_string().contains("webs_service_dids"), "{err}");
    assert!(hosts.0.published.lock().unwrap().is_empty());
    assert!(
        crate::webs_store::list(&ts.webs_ks)
            .await
            .unwrap()
            .is_empty(),
        "nothing recorded"
    );
}

/// A did:webs has no serverless mode: without a hosting server the request is
/// refused, naming the var to pass.
#[tokio::test]
async fn a_did_webs_integration_needs_a_hosting_server() {
    let (_ts, deps) = webs_vta(true).await;
    let hosts = Hosts(RecordingHost::default());
    let err = provision(
        &deps,
        &hosts,
        "dtg-witness",
        vars(&[
            ("MEDIATOR_DID", MEDIATOR),
            ("URL", "https://witness.example"),
            ("DID_METHOD", "webs"),
        ]),
    )
    .await
    .err()
    .expect("refused");
    assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    assert!(err.to_string().contains("WEBVH_SERVER"), "{err}");
    assert!(hosts.0.published.lock().unwrap().is_empty());
}

/// A template did:webs cannot represent (`vtc-host`: a post-quantum key) is
/// refused by the §9.2 check, before a key is derived. A did:webs VTC names
/// `vtc-host-classical` instead (above).
#[tokio::test]
async fn a_template_did_webs_cannot_represent_is_refused() {
    let (ts, deps) = webs_vta(true).await;
    let hosts = Hosts(RecordingHost::default());
    let err = provision(
        &deps,
        &hosts,
        "vtc-host",
        vars(&[
            ("URL", "https://vtc.example"),
            ("WEBVH_SERVER", "host-1"),
            ("DID_METHOD", "webs"),
        ]),
    )
    .await
    .err()
    .expect("refused");
    assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    assert!(hosts.0.published.lock().unwrap().is_empty());
    assert!(
        crate::webs_store::list(&ts.webs_ks)
            .await
            .unwrap()
            .is_empty()
    );
}
