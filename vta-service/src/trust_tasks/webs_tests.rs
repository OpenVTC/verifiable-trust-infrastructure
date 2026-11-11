//! `vta/webs/dids/*/0.1` end to end through the slice: create → get → list →
//! update → rotate-keys → delete, against a recording host, and every declared
//! refusal by its wire code.

use std::sync::Mutex;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use trust_tasks_rs::TypeUri;
use vta_sdk::trust_tasks as uris;

use super::*;
use crate::test_support::{
    admin_claims_for_context, build_signing_test_app_state, seed_webvh_server,
};
use crate::webvh_host::{RequestUriResponse, host_refusal};

const MEDIATOR: &str = "did:peer:2.Vz6MkMediator.Ez6LSMediator";
const CTX: &str = "acme";

/// A did-hosting server that records what it is sent, and refuses with
/// `refuse` (a host error code) when set.
#[derive(Default)]
struct RecordingHost {
    published: Mutex<Vec<(String, String)>>,
    deleted: Mutex<Vec<String>>,
    refuse: Mutex<Option<&'static str>>,
}

impl RecordingHost {
    fn refuse_with(&self, code: Option<&'static str>) {
        *self.refuse.lock().unwrap() = code;
    }
}

impl engine::WebsHost for RecordingHost {
    async fn resolve_domain(&self, requested: Option<&str>) -> Result<String, AppError> {
        match requested {
            Some("elsewhere.example") => Err(AppError::Validation(
                "the hosting server does not serve the domain elsewhere.example".into(),
            )),
            Some(d) => Ok(d.to_string()),
            None => Ok("hosting.example".into()),
        }
    }

    async fn publish(
        &self,
        mnemonic: &str,
        keri_cesr: &str,
        domain: Option<&str>,
    ) -> Result<RequestUriResponse, AppError> {
        if let Some(code) = *self.refuse.lock().unwrap() {
            return Err(if code == "method-webs" {
                AppError::Validation(
                    "the DID hosting service refused the request: this host does not host \
                     did:webs: it was built without the `method-webs` feature [validationError]"
                        .into(),
                )
            } else {
                host_refusal(code, "refused")
            });
        }
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

    async fn delete(&self, mnemonic: &str, _domain: Option<&str>) -> Result<(), AppError> {
        self.deleted.lock().unwrap().push(mnemonic.to_string());
        Ok(())
    }
}

struct Fake<'f>(&'f RecordingHost);

impl<'f> HostSource for Fake<'f> {
    type Host = &'f RecordingHost;

    fn host(
        &self,
        _server_id: &str,
    ) -> impl std::future::Future<Output = Result<&'f RecordingHost, WebsError>> + Send {
        let host = self.0;
        async move { Ok(host) }
    }
}

struct Rig {
    state: AppState,
    _dir: tempfile::TempDir,
    host: RecordingHost,
    resolver: DIDCacheClient,
    auth: AuthClaims,
}

impl Rig {
    async fn new() -> Self {
        let (state, dir) = build_signing_test_app_state().await;
        {
            let mut config = state.config.write().await;
            config.dids.webs_enabled = true;
            config.messaging = Some(vti_common::config::MessagingConfig {
                mediator_url: String::new(),
                mediator_did: MEDIATOR.into(),
                mediator_host: None,
                setup_acl: false,
                drain_inbox_on_start: false,
            });
        }
        crate::contexts::create_context(&state.contexts_ks, CTX, "Acme")
            .await
            .expect("context");
        seed_webvh_server(&state.webvh_ks, "host-1", "did:web:hosting.example").await;
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("resolver");
        Self {
            state,
            _dir: dir,
            host: RecordingHost::default(),
            resolver,
            auth: admin_claims_for_context(CTX),
        }
    }

    async fn run(&self, uri: &str, payload: Value) -> TrustTaskOutcome {
        let type_uri: TypeUri = uri.parse().expect("uri");
        let doc = TrustTask::new(
            format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            type_uri,
            payload,
        );
        let hosts = Fake(&self.host);
        let (s, a, r) = (&self.state, &self.auth, &self.resolver);
        if uri == uris::TASK_VTA_WEBS_DIDS_CREATE_0_1 {
            use spec::create::v0_1 as t;
            if let Err(out) = parse_payload::<t::Payload>(&doc) {
                return out;
            }
            let codes = Codes {
                method_disabled: Some(t::error_codes::METHOD_DISABLED),
                server_not_found: Some(t::error_codes::SERVER_NOT_FOUND),
                host_does_not_host_webs: Some(t::error_codes::HOST_DOES_NOT_HOST_WEBS),
                domain_not_served: Some(t::error_codes::DOMAIN_NOT_SERVED),
                path_refused: Some(t::error_codes::PATH_REFUSED),
                service_did_not_permitted: Some(t::error_codes::SERVICE_DID_NOT_PERMITTED),
                service_id_conflict: Some(t::error_codes::SERVICE_ID_CONFLICT),
                publish_refused: Some(t::error_codes::PUBLISH_REFUSED),
                ..Codes::default()
            };
            return match create(s, a, &doc.payload, r, &hosts).await {
                Ok(v) => respond::<t::Response>(&doc, v),
                Err(e) => refuse(&doc, e, &codes),
            };
        }
        if uri == uris::TASK_VTA_WEBS_DIDS_UPDATE_0_1 {
            use spec::update::v0_1 as t;
            if let Err(out) = parse_payload::<t::Payload>(&doc) {
                return out;
            }
            let codes = Codes {
                not_found: Some(t::error_codes::NOT_FOUND),
                version_conflict: Some(t::error_codes::VERSION_CONFLICT),
                no_change: Some(t::error_codes::NO_CHANGE),
                service_id_conflict: Some(t::error_codes::SERVICE_ID_CONFLICT),
                deactivated: Some(t::error_codes::DEACTIVATED),
                publish_refused: Some(t::error_codes::PUBLISH_REFUSED),
                ..Codes::default()
            };
            return match update(s, a, &doc.payload, r, &hosts).await {
                Ok(v) => respond::<t::Response>(&doc, v),
                Err(e) => refuse(&doc, e, &codes),
            };
        }
        if uri == uris::TASK_VTA_WEBS_DIDS_ROTATE_KEYS_0_1 {
            return rotate_keys(s, a, &doc, r, &hosts).await;
        }
        if uri == uris::TASK_VTA_WEBS_DIDS_DELETE_0_1 {
            return delete(s, a, &doc, r, &hosts).await;
        }
        if uri == uris::TASK_VTA_WEBS_DIDS_GET_0_1 {
            return handle_get(s, a, doc).await;
        }
        handle_list(s, a, doc).await
    }
}

fn body(out: &TrustTaskOutcome) -> Value {
    serde_json::from_slice(&out.body).expect("response is JSON")
}

fn ok(out: &TrustTaskOutcome) -> Value {
    let b = body(out);
    assert!(out.status.is_success(), "expected success, got {b:#}");
    b["payload"].clone()
}

fn code(out: &TrustTaskOutcome) -> String {
    body(out)
        .pointer("/payload/code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn create_payload() -> Value {
    json!({ "contextId": CTX, "serverId": "host-1", "path": "people", "addMediatorService": true,
            "addTspService": false })
}

#[tokio::test]
async fn a_did_webs_lives_its_whole_life_through_the_slice() {
    let rig = Rig::new().await;

    // create
    let created = ok(&rig
        .run(uris::TASK_VTA_WEBS_DIDS_CREATE_0_1, create_payload())
        .await);
    let did = created["did"].as_str().unwrap().to_string();
    assert!(did.starts_with("did:webs:hosting.example:people:"), "{did}");
    assert_eq!(created["serviceIds"], json!(["#didcomm"]));
    assert_eq!(
        created["alsoKnownAs"][0], did,
        "the DID designates itself first"
    );
    assert!(
        created["signingKeyId"]
            .as_str()
            .unwrap()
            .ends_with(created["signingKey"].as_str().unwrap())
    );
    assert_eq!(rig.host.published.lock().unwrap().len(), 1);

    // get, with its stream
    let got = ok(&rig
        .run(
            uris::TASK_VTA_WEBS_DIDS_GET_0_1,
            json!({ "did": did, "includeKeriCesr": true }),
        )
        .await);
    assert_eq!(got["record"]["did"], did);
    assert_eq!(got["record"]["services"][0]["id"], "#didcomm");
    assert!(
        got["keriCesr"].as_str().unwrap().starts_with("-_AAACAA"),
        "a 2.0 stream"
    );
    let version = got["record"]["versionId"].as_str().unwrap().to_string();

    // list
    let listed = ok(&rig
        .run(
            uris::TASK_VTA_WEBS_DIDS_LIST_0_1,
            json!({ "contextId": CTX }),
        )
        .await);
    assert_eq!(listed["dids"].as_array().unwrap().len(), 1);

    // update: swap #didcomm for #tsp, and add a service
    let updated = ok(&rig
        .run(
            uris::TASK_VTA_WEBS_DIDS_UPDATE_0_1,
            json!({ "did": did, "expectedVersionId": version,
                    "services": { "mediator": false, "tsp": true,
                      "additional": [{ "id": "#files", "type": "LinkedDomains",
                                       "serviceEndpoint": "https://files.example" }] } }),
        )
        .await);
    assert_eq!(updated["replaced"], json!(["services"]));
    let mut ids: Vec<&str> = updated["serviceIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    ids.sort();
    assert_eq!(ids, ["#files", "#tsp"]);

    // the same update again changes nothing
    let out = rig
        .run(
            uris::TASK_VTA_WEBS_DIDS_UPDATE_0_1,
            json!({ "did": did, "services": { "mediator": false, "tsp": true,
                      "additional": [{ "id": "#files", "type": "LinkedDomains",
                                       "serviceEndpoint": "https://files.example" }] } }),
        )
        .await;
    assert_eq!(code(&out), "vta/webs/dids/update:noChange");

    // an update based on the old version is refused
    let out = rig
        .run(
            uris::TASK_VTA_WEBS_DIDS_UPDATE_0_1,
            json!({ "did": did, "expectedVersionId": version, "rotateKeyAgreementKey": true }),
        )
        .await;
    assert_eq!(code(&out), "vta/webs/dids/update:versionConflict");

    // two services may not share an id
    let out = rig
        .run(
            uris::TASK_VTA_WEBS_DIDS_UPDATE_0_1,
            json!({ "did": did, "services": { "mediator": false, "tsp": false, "additional": [
                { "id": "#files", "type": "LinkedDomains", "serviceEndpoint": "https://a.example" },
                { "id": "#files", "type": "LinkedDomains", "serviceEndpoint": "https://b.example" }
            ] } }),
        )
        .await;
    assert_eq!(code(&out), "vta/webs/dids:serviceIdConflict");

    // rotate-keys: the committed successor is installed
    let before = got["record"]["signingKey"].as_str().unwrap().to_string();
    let rotated = ok(&rig
        .run(
            uris::TASK_VTA_WEBS_DIDS_ROTATE_KEYS_0_1,
            json!({ "did": did }),
        )
        .await);
    assert_ne!(rotated["signingKey"], before);
    assert_eq!(rotated["resumed"], false);
    let out = rig
        .run(
            uris::TASK_VTA_WEBS_DIDS_ROTATE_KEYS_0_1,
            json!({ "did": did, "expectedVersionId": version }),
        )
        .await;
    assert_eq!(code(&out), "vta/webs/dids/rotate-keys:versionConflict");

    // a refused publication of a rotation
    rig.host.refuse_with(Some("did/register:invalidLog"));
    let out = rig
        .run(
            uris::TASK_VTA_WEBS_DIDS_ROTATE_KEYS_0_1,
            json!({ "did": did }),
        )
        .await;
    assert_eq!(code(&out), "vta/webs/dids:publishRefused");
    rig.host.refuse_with(None);
    let resumed = ok(&rig
        .run(
            uris::TASK_VTA_WEBS_DIDS_ROTATE_KEYS_0_1,
            json!({ "did": did }),
        )
        .await);
    assert_eq!(
        resumed["resumed"], true,
        "the staged rotation is completed, not repeated"
    );

    // delete: a stale version is refused, then it deactivates for good
    let out = rig
        .run(
            uris::TASK_VTA_WEBS_DIDS_DELETE_0_1,
            json!({ "did": did, "expectedVersionId": version }),
        )
        .await;
    assert_eq!(code(&out), "vta/webs/dids/delete:versionConflict");
    let deleted = ok(&rig
        .run(uris::TASK_VTA_WEBS_DIDS_DELETE_0_1, json!({ "did": did }))
        .await);
    assert_eq!(deleted["newlyDeactivated"], true);
    assert_eq!(deleted["slotRemoved"], true);
    let again = ok(&rig
        .run(uris::TASK_VTA_WEBS_DIDS_DELETE_0_1, json!({ "did": did }))
        .await);
    assert_eq!(again["newlyDeactivated"], false);

    // nothing more changes it
    let out = rig
        .run(
            uris::TASK_VTA_WEBS_DIDS_UPDATE_0_1,
            json!({ "did": did, "rotateKeyAgreementKey": true }),
        )
        .await;
    assert_eq!(code(&out), "vta/webs/dids:deactivated");

    // it leaves the default listing
    let listed = ok(&rig
        .run(
            uris::TASK_VTA_WEBS_DIDS_LIST_0_1,
            json!({ "contextId": CTX }),
        )
        .await);
    assert!(listed["dids"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn an_unknown_did_is_not_found_on_every_task() {
    let rig = Rig::new().await;
    let did = "did:webs:hosting.example:EUnknown0000000000000000000000000000000000";
    let out = rig
        .run(uris::TASK_VTA_WEBS_DIDS_GET_0_1, json!({ "did": did }))
        .await;
    assert_eq!(code(&out), "vta/webs/dids/get:notFound");
    let out = rig
        .run(
            uris::TASK_VTA_WEBS_DIDS_UPDATE_0_1,
            json!({ "did": did, "rotateKeyAgreementKey": true }),
        )
        .await;
    assert_eq!(code(&out), "vta/webs/dids/update:notFound");
    let out = rig
        .run(
            uris::TASK_VTA_WEBS_DIDS_ROTATE_KEYS_0_1,
            json!({ "did": did }),
        )
        .await;
    assert_eq!(code(&out), "vta/webs/dids/rotate-keys:notFound");
    let out = rig
        .run(uris::TASK_VTA_WEBS_DIDS_DELETE_0_1, json!({ "did": did }))
        .await;
    assert_eq!(code(&out), "vta/webs/dids/delete:notFound");
}

#[tokio::test]
async fn create_refuses_as_the_specification_declares() {
    let rig = Rig::new().await;

    // the host's refusals, sorted by its code
    rig.host.refuse_with(Some("method-webs"));
    let out = rig
        .run(uris::TASK_VTA_WEBS_DIDS_CREATE_0_1, create_payload())
        .await;
    assert_eq!(code(&out), "vta/webs/dids/create:hostDoesNotHostWebs");
    rig.host.refuse_with(Some("did/register:invalidPath"));
    let out = rig
        .run(uris::TASK_VTA_WEBS_DIDS_CREATE_0_1, create_payload())
        .await;
    assert_eq!(code(&out), "vta/webs/dids/create:pathRefused");
    rig.host.refuse_with(Some("did/register:invalidLog"));
    let out = rig
        .run(uris::TASK_VTA_WEBS_DIDS_CREATE_0_1, create_payload())
        .await;
    assert_eq!(code(&out), "vta/webs/dids:publishRefused");
    rig.host.refuse_with(None);
    assert!(
        crate::webs_store::list(&rig.state.webs_ks)
            .await
            .unwrap()
            .is_empty(),
        "a refused publication leaves no DID"
    );

    // a domain the host does not serve, before anything is derived
    let mut p = create_payload();
    p["domain"] = json!("elsewhere.example");
    let out = rig.run(uris::TASK_VTA_WEBS_DIDS_CREATE_0_1, p).await;
    assert_eq!(code(&out), "vta/webs/dids/create:domainNotServed");

    // an unregistered server
    let mut p = create_payload();
    p["serverId"] = json!("no-such-host");
    let out = rig.run(uris::TASK_VTA_WEBS_DIDS_CREATE_0_1, p).await;
    assert_eq!(code(&out), "vta/webs/dids/create:serverNotFound");

    // two services with one id
    let mut p = create_payload();
    p["additionalServices"] = json!([
        { "id": "#files", "type": "LinkedDomains", "serviceEndpoint": "https://a.example" },
        { "id": "#files", "type": "LinkedDomains", "serviceEndpoint": "https://b.example" }
    ]);
    let out = rig.run(uris::TASK_VTA_WEBS_DIDS_CREATE_0_1, p).await;
    assert_eq!(code(&out), "vta/webs/dids:serviceIdConflict");

    // the context holding this VTA's own DID cannot take a did:webs as primary
    let vta_did = rig.state.config.read().await.vta_did.clone().unwrap();
    let mut ctx = crate::contexts::get_context(&rig.state.contexts_ks, CTX)
        .await
        .unwrap()
        .unwrap();
    ctx.did = Some(vta_did);
    crate::contexts::store_context(&rig.state.contexts_ks, &ctx)
        .await
        .unwrap();
    let mut p = create_payload();
    p["setPrimary"] = json!(true);
    let out = rig.run(uris::TASK_VTA_WEBS_DIDS_CREATE_0_1, p).await;
    assert_eq!(code(&out), "vta/webs/dids/create:serviceDidNotPermitted");

    // and with creation off, nothing else is looked at
    rig.state.config.write().await.dids.webs_enabled = false;
    let out = rig
        .run(uris::TASK_VTA_WEBS_DIDS_CREATE_0_1, create_payload())
        .await;
    assert_eq!(code(&out), "vta/webs/dids/create:methodDisabled");
}
