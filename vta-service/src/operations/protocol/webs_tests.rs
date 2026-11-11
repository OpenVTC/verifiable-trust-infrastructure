//! Runtime service management on a `did:webs` VTA (S6 of
//! `docs/05-design-notes/did-webs-in-the-vta.md`): every op publishes a key
//! event stream whose derived document advertises exactly the patched
//! services, in transport-preference order.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_did_webs::{DidWebs, resolve_from_artifacts};
use serde_json::{Value, json};
use tokio::sync::RwLock;
use vti_common::telemetry::{RingBufferTelemetry, SharedTelemetrySink};

use super::ServiceOpDeps;
use super::{OpContext, list::list_services};
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::keys::seed_store::PlaintextSeedStore;
use crate::operations::did_webs::{CreateDidWebsParams, WebsDeps, WebsHost, create_did_webs};
use crate::test_support::{
    TestStore, bootstrap_test_vta, open_test_store, seed_webvh_server, super_admin_claims,
};
use crate::webvh_host::RequestUriResponse;

const MEDIATOR: &str = "did:web:mediator.example";
const OTHER_MEDIATOR: &str = "did:web:other-mediator.example";
const REST_URL: &str = "https://vta.example/";

/// A host that records each stream it is given.
#[derive(Default)]
struct RecordingHost {
    published: Mutex<Vec<String>>,
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
        self.published.lock().unwrap().push(keri_cesr.to_string());
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

impl RecordingHost {
    fn publications(&self) -> usize {
        self.published.lock().unwrap().len()
    }
}

struct Env {
    ts: TestStore,
    did: String,
    config: Arc<RwLock<AppConfig>>,
    seed: PlaintextSeedStore,
    resolver: DIDCacheClient,
    bridge: Arc<DIDCommBridge>,
    telemetry: SharedTelemetrySink,
    #[cfg(feature = "didcomm")]
    registry: Arc<crate::messaging::registry::MediatorListenerRegistry>,
    #[cfg(feature = "didcomm")]
    sweeper: Arc<crate::messaging::drain_sweeper::DrainSweeper>,
    host: RecordingHost,
}

/// A mediator's document, cached so a DIDComm handshake resolves it offline.
async fn cache_mediator(resolver: &DIDCacheClient, did: &str) {
    let doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": format!("{did}#ka"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
        }],
        "keyAgreement": [format!("{did}#ka")],
        "service": [{
            "id": format!("{did}#didcomm"),
            "type": "DIDCommMessaging",
            "serviceEndpoint": { "uri": "https://mediator.example", "accept": ["didcomm/v2"] }
        }]
    });
    resolver
        .clone()
        .add_did_document(did, serde_json::from_value(doc).unwrap())
        .await;
}

impl Env {
    /// A VTA whose own DID is a key-role did:webs designating `didcomm` and
    /// `rest` as setup designates them, published to [`RecordingHost`].
    async fn new(didcomm: bool, rest: bool) -> Self {
        let ts = open_test_store().await;
        let (_vta_did, pdeps) = bootstrap_test_vta(&ts).await;
        let mut cfg = pdeps.config.read().await.clone();
        cfg.dids.webs_enabled = true;
        cfg.messaging = Some(
            serde_json::from_value(json!({ "mediator_did": MEDIATOR })).expect("messaging config"),
        );
        crate::contexts::create_context(&ts.contexts_ks, "acme", "Acme")
            .await
            .expect("context");
        seed_webvh_server(&ts.webvh_ks, "host-1", "did:web:hosting.example").await;
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("resolver");
        let seed = PlaintextSeedStore::new(&ts.data_dir);
        let host = RecordingHost::default();

        let mut params = CreateDidWebsParams::new("acme", "host-1");
        params.path = Some("vta".into());
        params.key_roles = true;
        params.add_mediator_service = didcomm;
        params.add_tsp_service = Some(false);
        if rest {
            params.additional_services = vec![
                crate::operations::did_webs::designated_service_from_json(&json!({
                    "id": "{DID}#vta-rest", "type": "VTARest", "serviceEndpoint": REST_URL
                }))
                .unwrap(),
            ];
        }
        let created = create_did_webs(
            &WebsDeps {
                keys_ks: &ts.keys_ks,
                contexts_ks: &ts.contexts_ks,
                webvh_ks: &ts.webvh_ks,
                webs_ks: &ts.webs_ks,
                acl_ks: Some(&ts.acl_ks),
                audit: &ts.audit,
                seed_store: &seed,
                config: &cfg,
                did_resolver: &resolver,
            },
            &super_admin_claims(),
            params,
            &host,
            "test",
        )
        .await
        .expect("created");

        cfg.vta_did = Some(created.did.clone());
        cfg.services.didcomm = didcomm;
        cfg.services.rest = rest;
        cfg.services.tsp = false;
        cfg.services.webauthn = false;
        cfg.config_path = ts.data_dir.join("vta.toml");
        std::fs::write(&cfg.config_path, toml::to_string_pretty(&cfg).unwrap()).unwrap();
        cache_mediator(&resolver, MEDIATOR).await;
        cache_mediator(&resolver, OTHER_MEDIATOR).await;

        let telemetry: SharedTelemetrySink = Arc::new(RingBufferTelemetry::new());
        #[cfg(feature = "didcomm")]
        let registry = Arc::new(crate::messaging::registry::MediatorListenerRegistry::new(
            Arc::clone(&telemetry),
        ));
        #[cfg(feature = "didcomm")]
        let sweeper = {
            let (tx, _rx) = crate::messaging::drain_sweeper::teardown_channel(8);
            Arc::new(crate::messaging::drain_sweeper::DrainSweeper::new(
                Arc::clone(&registry),
                ts.drains_ks.clone(),
                tx,
            ))
        };
        Self {
            did: created.did,
            config: Arc::new(RwLock::new(cfg)),
            seed,
            resolver,
            bridge: Arc::new(DIDCommBridge::placeholder()),
            telemetry,
            #[cfg(feature = "didcomm")]
            registry,
            #[cfg(feature = "didcomm")]
            sweeper,
            host,
            ts,
        }
    }

    fn deps(&self) -> ServiceOpDeps<'_> {
        ServiceOpDeps {
            config: &self.config,
            keys_ks: &self.ts.keys_ks,
            imported_ks: &self.ts.imported_ks,
            contexts_ks: &self.ts.contexts_ks,
            webvh_ks: &self.ts.webvh_ks,
            webs_ks: &self.ts.webs_ks,
            webs_host: Some(&self.host),
            audit: &self.ts.audit,
            snapshot_ks: &self.ts.snapshot_ks,
            service_state_ks: &self.ts.service_state_ks,
            drains_ks: &self.ts.drains_ks,
            seed_store: &self.seed,
            did_resolver: &self.resolver,
            didcomm_bridge: &self.bridge,
            telemetry: &self.telemetry,
            #[cfg(feature = "didcomm")]
            registry: &self.registry,
            #[cfg(feature = "didcomm")]
            sweeper: &self.sweeper,
        }
    }

    /// The document a resolver derives from the stream last published.
    fn published_document(&self) -> Value {
        let stream = self
            .host
            .published
            .lock()
            .unwrap()
            .last()
            .expect("published")
            .clone();
        let did = DidWebs::parse(&self.did).unwrap();
        serde_json::to_value(resolve_from_artifacts(&did, stream.as_bytes(), None).unwrap())
            .unwrap()
    }

    /// `(fragment, type)` of each service the last published document
    /// carries, in its order.
    fn published_services(&self) -> Vec<(String, String)> {
        services_of(&self.published_document(), &self.did)
    }
}

fn services_of(doc: &Value, did: &str) -> Vec<(String, String)> {
    doc["service"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|s| {
            let id = s["id"].as_str().unwrap();
            (
                id.strip_prefix(did).unwrap_or(id).to_string(),
                match &s["type"] {
                    Value::Array(a) => a[0].as_str().unwrap_or_default().to_string(),
                    t => t.as_str().unwrap_or_default().to_string(),
                },
            )
        })
        .collect()
}

fn endpoint<'a>(doc: &'a Value, did: &str, fragment: &str) -> &'a Value {
    let id = format!("{did}{fragment}");
    &doc["service"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == id)
        .unwrap_or_else(|| panic!("{fragment} in {doc}"))["serviceEndpoint"]
}

fn didcomm_rest() -> Vec<(String, String)> {
    vec![
        ("#didcomm".into(), "DIDCommMessaging".into()),
        ("#vta-rest".into(), "VTARest".into()),
    ]
}

#[tokio::test]
async fn a_rest_update_designates_the_new_url_and_keeps_didcomm_first() {
    use super::update_rest::{UpdateRestParams, update_rest};
    let env = Env::new(true, true).await;
    assert_eq!(env.published_services(), didcomm_rest(), "as setup made it");
    let before = env.host.publications();

    let r = update_rest(
        &env.deps(),
        &super_admin_claims(),
        UpdateRestParams {
            url: "https://new.example/".into(),
        },
        OpContext::Direct,
        "test",
    )
    .await
    .expect("updated");

    assert_eq!(env.host.publications(), before + 1, "one stream published");
    let doc = env.published_document();
    assert_eq!(services_of(&doc, &env.did), didcomm_rest());
    assert_eq!(
        endpoint(&doc, &env.did, "#vta-rest"),
        &json!("https://new.example/")
    );
    // The version is the KEL's latest event, as `vta/webs/dids/*` report it.
    let record = crate::webs_store::get(&env.ts.webs_ks, &env.did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        r.new_version_id,
        crate::operations::did_webs::version_id(&record.state)
    );
    assert!(!r.serverless);
    // The VTA's own cached document is the new one.
    let cached = env.resolver.resolve(&env.did).await.expect("cached");
    let cached = serde_json::to_value(&cached.doc).unwrap();
    assert_eq!(
        endpoint(&cached, &env.did, "#vta-rest"),
        &json!("https://new.example/")
    );
}

#[tokio::test]
async fn a_rest_disable_and_its_rollback_republish_the_service_set() {
    use super::disable_rest::{DisableRestParams, disable_rest};
    use super::rollback_rest::{RollbackRestParams, rollback_rest};
    let env = Env::new(true, true).await;

    disable_rest(
        &env.deps(),
        &super_admin_claims(),
        DisableRestParams,
        OpContext::Direct,
        "test",
    )
    .await
    .expect("disabled");
    assert_eq!(
        env.published_services(),
        vec![("#didcomm".to_string(), "DIDCommMessaging".to_string())]
    );

    rollback_rest(
        &env.deps(),
        &super_admin_claims(),
        RollbackRestParams,
        "test",
    )
    .await
    .expect("rolled back");
    let doc = env.published_document();
    assert_eq!(services_of(&doc, &env.did), didcomm_rest());
    assert_eq!(endpoint(&doc, &env.did, "#vta-rest"), &json!(REST_URL));
}

// A build without TSP refuses `services tsp enable` before publishing.
#[cfg(feature = "tsp")]
#[tokio::test]
async fn a_tsp_enable_is_designated_first() {
    use super::enable_tsp::{EnableTspParams, enable_tsp};
    let env = Env::new(true, true).await;
    enable_tsp(
        &env.deps(),
        &super_admin_claims(),
        EnableTspParams {
            mediator_did: MEDIATOR.into(),
        },
        OpContext::Direct,
        "test",
    )
    .await
    .expect("enabled");
    assert_eq!(
        env.published_services(),
        vec![
            ("#tsp".to_string(), "TSPTransport".to_string()),
            ("#didcomm".to_string(), "DIDCommMessaging".to_string()),
            ("#vta-rest".to_string(), "VTARest".to_string()),
        ],
        "TSP > DIDComm > REST, in the designation and so in the document"
    );
}

#[cfg(feature = "didcomm")]
#[tokio::test]
async fn didcomm_enable_update_disable_and_rollback_keep_the_didcomm_id() {
    use super::disable_didcomm::{DisableDidcommParams, DisableTransport, disable_didcomm};
    use super::enable_didcomm::{EnableDidcommParams, enable_didcomm};
    use super::rollback_didcomm::{RollbackDidcommParams, rollback_didcomm};
    use super::update_didcomm::{MigrateAuditKind, UpdateDidcommParams, update_didcomm};
    use crate::messaging::handshake::AlwaysOkProver;

    // REST only, as a VTA set up without a mediator service.
    let env = Env::new(false, true).await;
    assert_eq!(
        env.published_services(),
        vec![("#vta-rest".to_string(), "VTARest".to_string())]
    );

    enable_didcomm(
        &env.deps(),
        &AlwaysOkProver,
        &super_admin_claims(),
        EnableDidcommParams {
            mediator_did: MEDIATOR.into(),
            setup_acl: false,
            force: false,
            handshake_timeout: Duration::from_secs(1),
        },
        OpContext::Direct,
        "test",
    )
    .await
    .expect("enabled");
    let doc = env.published_document();
    assert_eq!(
        services_of(&doc, &env.did),
        didcomm_rest(),
        "DIDComm before REST, designated as #didcomm"
    );
    assert_eq!(
        endpoint(&doc, &env.did, "#didcomm"),
        &json!([{ "accept": ["didcomm/v2"], "uri": MEDIATOR }])
    );

    update_didcomm(
        &env.deps(),
        &AlwaysOkProver,
        &super_admin_claims(),
        UpdateDidcommParams {
            new_mediator_did: OTHER_MEDIATOR.into(),
            drain_ttl: Duration::from_secs(3600),
            setup_acl: false,
            force: false,
            handshake_timeout: Duration::from_secs(1),
            audit_kind: MigrateAuditKind::Forward,
            transport: DisableTransport::Rest,
        },
        OpContext::Direct,
        "test",
    )
    .await
    .expect("updated");
    let doc = env.published_document();
    assert_eq!(services_of(&doc, &env.did), didcomm_rest());
    assert_eq!(
        endpoint(&doc, &env.did, "#didcomm")[0]["uri"],
        json!(OTHER_MEDIATOR)
    );

    disable_didcomm(
        &env.deps(),
        &super_admin_claims(),
        DisableDidcommParams {
            drain_ttl: Duration::from_secs(3600),
            transport: DisableTransport::Rest,
        },
        OpContext::Direct,
        "test",
    )
    .await
    .expect("disabled");
    assert_eq!(
        env.published_services(),
        vec![("#vta-rest".to_string(), "VTARest".to_string())]
    );

    rollback_didcomm(
        &env.deps(),
        &AlwaysOkProver,
        &super_admin_claims(),
        RollbackDidcommParams {
            drain_ttl: Duration::from_secs(3600),
            transport: DisableTransport::Rest,
        },
        "test",
    )
    .await
    .expect("rolled back");
    let doc = env.published_document();
    assert_eq!(services_of(&doc, &env.did), didcomm_rest());
    assert_eq!(
        endpoint(&doc, &env.did, "#didcomm")[0]["uri"],
        json!(OTHER_MEDIATOR)
    );
}

/// WebAuthn is a service like the others: its passkeys are verification
/// methods of the DIDs the VTA manages as did:webvh, never of its own
/// document, so a did:webs VTA designates `#vta-webauthn` (last).
#[tokio::test]
async fn a_webauthn_enable_designates_the_relying_party_last() {
    use super::enable_webauthn::{EnableWebauthnParams, enable_webauthn};
    let env = Env::new(true, true).await;
    enable_webauthn(
        &env.deps(),
        &super_admin_claims(),
        EnableWebauthnParams {
            url: "https://vta.example/auth/portal".into(),
        },
        OpContext::Direct,
        "test",
    )
    .await
    .expect("enabled");
    let mut want = didcomm_rest();
    want.push(("#vta-webauthn".into(), "WebAuthnRP".into()));
    assert_eq!(env.published_services(), want);
}

#[tokio::test]
async fn an_enable_of_what_is_already_designated_publishes_nothing() {
    use super::enable_rest::{EnableRestParams, enable_rest};
    let env = Env::new(true, true).await;
    // The document advertises REST, the config says it is off: enable
    // reconciles the config, and the designation already is what it asks.
    env.config.write().await.services.rest = false;
    let before = env.host.publications();
    let r = enable_rest(
        &env.deps(),
        &super_admin_claims(),
        EnableRestParams {
            url: REST_URL.into(),
        },
        OpContext::Direct,
        "test",
    )
    .await
    .expect("enabled");
    assert_eq!(env.host.publications(), before);
    assert!(env.config.read().await.services.rest);
    let record = crate::webs_store::get(&env.ts.webs_ks, &env.did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        r.new_version_id,
        crate::operations::did_webs::version_id(&record.state)
    );
}

#[tokio::test]
async fn an_unpublished_vta_identity_is_refused_before_anything_is_written() {
    use super::update_rest::{UpdateRestError, UpdateRestParams, update_rest};
    let env = Env::new(true, true).await;
    let mut record = crate::webs_store::get(&env.ts.webs_ks, &env.did)
        .await
        .unwrap()
        .unwrap();
    record.published = false;
    crate::webs_store::put(&env.ts.webs_ks, &record)
        .await
        .unwrap();
    let before = env.host.publications();
    let err = update_rest(
        &env.deps(),
        &super_admin_claims(),
        UpdateRestParams {
            url: "https://new.example/".into(),
        },
        OpContext::Direct,
        "test",
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, UpdateRestError::VtaDidLogMissing(ref d) if *d == env.did),
        "{err:?}"
    );
    assert_eq!(env.host.publications(), before);
}

#[tokio::test]
async fn services_list_reports_the_designated_services() {
    let env = Env::new(true, true).await;
    let listed = list_services(
        &env.config,
        &env.ts.webvh_ks,
        &env.ts.webs_ks,
        &super_admin_claims(),
    )
    .await
    .expect("listed");
    let v = serde_json::to_value(&listed).unwrap();
    let by_kind = |kind: &str| {
        v["services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["kind"] == kind)
            .cloned()
            .unwrap_or_else(|| panic!("{kind} in {v}"))
    };
    assert_eq!(by_kind("didcomm")["enabled"], json!(true));
    assert_eq!(by_kind("didcomm")["mediator_did"], json!(MEDIATOR));
    assert_eq!(by_kind("rest")["enabled"], json!(true));
    assert_eq!(by_kind("rest")["url"], json!(REST_URL));
    assert_eq!(by_kind("tsp")["enabled"], json!(false));
}
