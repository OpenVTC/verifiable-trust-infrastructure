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
        if uri == uris::TASK_VTA_WEBS_DIDS_CREATE_0_1 || uri == uris::TASK_VTA_WEBS_DIDS_CREATE_0_2
        {
            #[allow(deprecated)] // 0.1 is superseded by 0.2, still served
            let (parsed, version) = if uri == uris::TASK_VTA_WEBS_DIDS_CREATE_0_1 {
                (
                    parse_payload::<spec::create::v0_1::Payload>(&doc).map(|_| ()),
                    CreateVersion::V0_1,
                )
            } else {
                (
                    parse_payload::<spec::create::v0_2::Payload>(&doc).map(|_| ()),
                    CreateVersion::V0_2,
                )
            };
            if let Err(out) = parsed {
                return out;
            }
            return create_outcome(s, a, &doc, version, r, &hosts).await;
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

// ─── create/0.2 ────────────────────────────────────────────────────────

const C02: &str = uris::TASK_VTA_WEBS_DIDS_CREATE_0_2;

fn create_02(class: &str) -> Value {
    json!({ "contextId": CTX, "serverId": "host-1", "didClass": class, "path": "people",
            "addMediatorService": true })
}

/// The aliases every did:webs designates before the caller's: the DID, its
/// did:web twin and its did:keri form.
fn equivalents(did: &str) -> Vec<String> {
    let rest = did.strip_prefix("did:webs:").expect("a did:webs");
    let aid = rest.rsplit(':').next().unwrap();
    vec![
        did.to_string(),
        format!("did:web:{rest}"),
        format!("did:keri:{aid}"),
    ]
}

fn details(out: &TrustTaskOutcome) -> Value {
    body(out)
        .pointer("/payload/details")
        .cloned()
        .unwrap_or(Value::Null)
}

impl Rig {
    async fn record(&self, did: &str) -> WebsDidRecord {
        crate::webs_store::get(&self.state.webs_ks, did)
            .await
            .unwrap()
            .expect("recorded")
    }

    async fn nothing_created(&self) {
        assert!(
            crate::webs_store::list(&self.state.webs_ks)
                .await
                .unwrap()
                .is_empty(),
            "no record"
        );
        assert!(
            self.host.published.lock().unwrap().is_empty(),
            "nothing published"
        );
    }

    async fn set_primary_did(&self, did: Option<&str>) {
        let mut ctx = crate::contexts::get_context(&self.state.contexts_ks, CTX)
            .await
            .unwrap()
            .unwrap();
        ctx.did = did.map(str::to_string);
        crate::contexts::store_context(&self.state.contexts_ks, &ctx)
            .await
            .unwrap();
    }

    /// Every row of the keys keyspace: key records and derivation counters.
    async fn key_rows(&self) -> usize {
        self.state.keys_ks.prefix_iter_raw("").await.unwrap().len()
    }
}

/// VTI-KEY-190, VTI-KEY-191: a relationship and a persona DID are created in
/// their class, which the record keeps and the response returns.
#[tokio::test]
async fn create_0_2_makes_a_relationship_and_a_persona_did_in_their_class() {
    let rig = Rig::new().await;
    for class in ["relationship", "persona"] {
        let created = ok(&rig.run(C02, create_02(class)).await);
        assert_eq!(created["didClass"], class);
        assert_eq!(created["serviceIds"], json!(["#didcomm"]));
        assert!(created.get("template").is_none(), "no template was named");
        assert!(created.get("templateScope").is_none());
        let did = created["did"].as_str().unwrap();
        assert_eq!(
            rig.record(did).await.did_class.map(WebsDidClass::as_str),
            Some(class)
        );
    }
}

/// create/0.2 Changes from 0.1: a 0.1 request records no class, and none is
/// inferred.
#[tokio::test]
async fn create_0_1_records_no_class() {
    let rig = Rig::new().await;
    let created = ok(&rig
        .run(uris::TASK_VTA_WEBS_DIDS_CREATE_0_1, create_payload())
        .await);
    assert!(created.get("didClass").is_none());
    let record = rig.record(created["did"].as_str().unwrap()).await;
    assert_eq!(record.did_class, None);
    assert_eq!(record.template, None);
}

/// CONVENTIONS.md 0.2 §1.1 item 1: a service DID is refused unless
/// `[dids] webs_service_dids` enables it, separately from `webs_enabled`.
#[tokio::test]
async fn a_service_did_needs_its_own_switch() {
    let rig = Rig::new().await;
    let out = rig.run(C02, create_02("service")).await;
    assert_eq!(code(&out), "vta/webs/dids/create:serviceDidNotPermitted");
    assert!(
        body(&out)["payload"]["message"]
            .as_str()
            .unwrap()
            .contains("webs_service_dids"),
        "the message names the switch"
    );
    rig.nothing_created().await;

    rig.state.config.write().await.dids.webs_service_dids = true;
    let created = ok(&rig.run(C02, create_02("service")).await);
    assert_eq!(created["didClass"], "service");
    assert_eq!(
        rig.record(created["did"].as_str().unwrap()).await.did_class,
        Some(WebsDidClass::Service)
    );

    // Creation off still answers first.
    rig.state.config.write().await.dids.webs_enabled = false;
    let out = rig.run(C02, create_02("service")).await;
    assert_eq!(code(&out), "vta/webs/dids/create:methodDisabled");
}

/// CONVENTIONS.md 0.2 §1.2 items 1 and 2 (VTI-KEY-193).
#[tokio::test]
async fn a_class_that_disagrees_with_the_primary_it_would_replace_is_a_did_class_conflict() {
    let rig = Rig::new().await;
    rig.state.config.write().await.dids.webs_service_dids = true;

    // Item 1: a persona or relationship DID cannot become the primary of a
    // context whose primary is a service DID — here this VTA's own.
    let vta_did = rig.state.config.read().await.vta_did.clone().unwrap();
    rig.set_primary_did(Some(&vta_did)).await;
    for class in ["persona", "relationship"] {
        let mut p = create_02(class);
        p["setPrimary"] = json!(true);
        let out = rig.run(C02, p).await;
        assert_eq!(
            code(&out),
            "vta/webs/dids/create:didClassConflict",
            "{class}"
        );
        assert_eq!(details(&out), json!({ "requiredClass": "service" }));
    }
    // A service DID agrees with the class, but a create still never
    // re-identifies this VTA: 0.2 has no code of its own for that.
    let mut p = create_02("service");
    p["setPrimary"] = json!(true);
    let out = rig.run(C02, p).await;
    assert_eq!(code(&out), "permissionDenied");
    // 0.1 answers the same as it always has.
    let mut p = create_payload();
    p["setPrimary"] = json!(true);
    let out = rig.run(uris::TASK_VTA_WEBS_DIDS_CREATE_0_1, p).await;
    assert_eq!(code(&out), "vta/webs/dids/create:serviceDidNotPermitted");
    rig.nothing_created().await;

    // Item 1 again, where the primary is a service did:webs this VTA made.
    rig.set_primary_did(None).await;
    let mut p = create_02("service");
    p["setPrimary"] = json!(true);
    let service = ok(&rig.run(C02, p).await);
    assert_eq!(service["primary"], true);
    let mut p = create_02("persona");
    p["setPrimary"] = json!(true);
    let out = rig.run(C02, p).await;
    assert_eq!(code(&out), "vta/webs/dids/create:didClassConflict");

    // Item 2: a service DID does not replace a persona primary.
    rig.set_primary_did(None).await;
    let mut p = create_02("persona");
    p["setPrimary"] = json!(true);
    let persona = ok(&rig.run(C02, p).await);
    let mut p = create_02("service");
    p["setPrimary"] = json!(true);
    let out = rig.run(C02, p).await;
    assert_eq!(code(&out), "vta/webs/dids/create:didClassConflict");
    assert_eq!(
        details(&out),
        Value::Null,
        "persona and relationship would both be accepted"
    );
    // ... and a persona replacing a persona is no conflict.
    let mut p = create_02("persona");
    p["setPrimary"] = json!(true);
    ok(&rig.run(C02, p).await);
    assert!(persona["did"].is_string());
}

/// CONVENTIONS.md 0.2 §9: a built-in whose every member the derivation
/// expresses (`ai-agent`) shapes the DID whole, and the response names it.
#[tokio::test]
async fn a_representable_builtin_template_shapes_the_did() {
    let rig = Rig::new().await;
    rig.state.config.write().await.dids.webs_service_dids = true;
    let created = ok(&rig
        .run(
            C02,
            json!({ "contextId": CTX, "serverId": "host-1", "didClass": "service",
                    "path": "agents", "template": "ai-agent",
                    "templateVars": { "MEDIATOR_DID": "did:web:mediator.example" } }),
        )
        .await);
    assert_eq!(created["template"], "ai-agent");
    assert_eq!(created["templateScope"], "builtin");
    assert_eq!(created["templateKind"], "ai-agent");
    let did = created["did"].as_str().unwrap().to_string();
    // The template lists no alias; the DID designates itself first, then the
    // did:web twin and the did:keri form the did:webs derivation always
    // designates (affinidi-did-webs `attestation::designation`, as for 0.1).
    assert_eq!(created["alsoKnownAs"], json!(equivalents(&did)));

    // The designations are the template's, ids reduced to fragments.
    let got = ok(&rig
        .run(uris::TASK_VTA_WEBS_DIDS_GET_0_1, json!({ "did": did }))
        .await);
    let services = got["record"]["services"].as_array().unwrap();
    let by_id = |id: &str| {
        services
            .iter()
            .find(|s| s["id"] == id)
            .unwrap_or_else(|| panic!("{id} in {services:?}"))
            .clone()
    };
    assert_eq!(by_id("#tsp")["type"], "TSPTransport");
    assert_eq!(by_id("#tsp")["serviceEndpoint"], "did:web:mediator.example");
    assert_eq!(by_id("#vta-didcomm")["type"], "DIDCommMessaging");
    assert_eq!(
        by_id("#vta-didcomm")["serviceEndpoint"][0]["uri"],
        "did:web:mediator.example"
    );
    assert_eq!(services.len(), 2);
    let record = rig.record(&did).await;
    assert_eq!(
        record.template,
        Some(crate::webs_store::WebsTemplateUse {
            name: "ai-agent".into(),
            scope: "builtin".into(),
            kind: "ai-agent".into(),
        })
    );
}

/// A context's own template resolves before the global scope and the
/// built-ins, and the response names the context as its scope.
#[tokio::test]
async fn a_context_template_resolves_in_its_scope() {
    let rig = Rig::new().await;
    let template = vta_sdk::did_templates::DidTemplate::from_json(json!({
        "schemaVersion": 1, "name": "webs-persona", "kind": "custom",
        "document": {
            "id": "{DID}",
            "verificationMethod": [
                { "id": "{DID}#key-0", "type": "Multikey", "controller": "{DID}",
                  "publicKeyMultibase": "{SIGNING_KEY_MB}" },
                { "id": "{DID}#key-1", "type": "Multikey", "controller": "{DID}",
                  "publicKeyMultibase": "{KA_KEY_MB}" }
            ],
            "authentication": ["{DID}#key-0"],
            "assertionMethod": ["{DID}#key-0"],
            "keyAgreement": ["{DID}#key-1"],
            "service": [{ "id": "{DID}#files", "type": "LinkedDomains",
                          "serviceEndpoint": "https://files.example" }],
            "alsoKnownAs": ["did:web:alice.example"]
        }
    }))
    .unwrap();
    crate::did_templates::store_context_template(
        &rig.state.did_templates_ks,
        CTX,
        &vta_sdk::did_templates::DidTemplateRecord {
            template,
            scope: vta_sdk::did_templates::Scope::Context {
                context_id: CTX.into(),
            },
            created_at: 0,
            updated_at: 0,
            created_by: "did:key:test".into(),
        },
    )
    .await
    .unwrap();
    let created = ok(&rig
        .run(
            C02,
            json!({ "contextId": CTX, "serverId": "host-1", "didClass": "persona",
                    "template": "webs-persona", "templateContext": CTX }),
        )
        .await);
    let did = created["did"].as_str().unwrap();
    assert_eq!(created["templateScope"], CTX);
    assert_eq!(created["templateKind"], "custom");
    assert_eq!(created["serviceIds"], json!(["#files"]));
    let mut aliases = equivalents(did);
    aliases.push("did:web:alice.example".into());
    assert_eq!(created["alsoKnownAs"], json!(aliases));
}

/// CONVENTIONS.md 0.2 §9.2, as written: `resolvedMethods` is a member the
/// derivation does not render, so the node built-ins that carry it are
/// refused (trustoverip/dtgwg-trust-tasks-tf#1164 asks whether it should be
/// honoured; if so, `vta_sdk::did_templates::webs::DOCUMENT_MEMBERS` gains it
/// and this test turns into a happy path). Nothing is derived or published.
#[tokio::test]
async fn a_template_the_derivation_cannot_reproduce_is_refused_before_any_key() {
    let rig = Rig::new().await;
    rig.state.config.write().await.dids.webs_service_dids = true;
    let keys_before = rig.key_rows().await;
    let out = rig
        .run(
            C02,
            json!({ "contextId": CTX, "serverId": "host-1", "didClass": "service",
                    "path": "witnesses", "template": "dtg-witness",
                    "templateVars": { "MEDIATOR_DID": "did:web:mediator.example" } }),
        )
        .await;
    assert_eq!(code(&out), "vta/webs/dids/create:templateNotRepresentable");
    assert_eq!(
        details(&out),
        json!({ "reason": "documentMember", "members": ["/document/resolvedMethods"] })
    );

    // The specification's own example: swiyu-verifier's keys.
    let out = rig
        .run(
            C02,
            json!({ "contextId": CTX, "serverId": "host-1", "didClass": "service",
                    "template": "swiyu-verifier" }),
        )
        .await;
    assert_eq!(code(&out), "vta/webs/dids/create:templateNotRepresentable");
    assert_eq!(
        details(&out),
        json!({ "reason": "keyAlgorithm", "members": ["/keys/signing", "/keys/verifier"] })
    );
    rig.nothing_created().await;
    assert_eq!(
        keys_before,
        rig.key_rows().await,
        "no key record, and no derivation path allocated"
    );
}

#[tokio::test]
async fn template_names_and_variables_are_checked() {
    let rig = Rig::new().await;
    rig.state.config.write().await.dids.webs_service_dids = true;
    let out = rig
        .run(
            C02,
            json!({ "contextId": CTX, "serverId": "host-1", "didClass": "service",
                    "template": "no-such-template" }),
        )
        .await;
    assert_eq!(code(&out), "vta/webs/dids/create:templateNotFound");
    assert_eq!(details(&out), json!({ "template": "no-such-template" }));

    let out = rig
        .run(
            C02,
            json!({ "contextId": CTX, "serverId": "host-1", "didClass": "service",
                    "template": "ai-agent" }),
        )
        .await;
    assert_eq!(code(&out), "vta/webs/dids/create:templateVarsInvalid");
    assert_eq!(details(&out), json!({ "missing": ["MEDIATOR_DID"] }));

    let out = rig
        .run(
            C02,
            json!({ "contextId": CTX, "serverId": "host-1", "didClass": "service",
                    "template": "ai-agent",
                    "templateVars": { "MEDIATOR_DID": "did:web:m.example", "BOGUS": "x",
                                      "DID": "did:web:mine" } }),
        )
        .await;
    assert_eq!(code(&out), "vta/webs/dids/create:templateVarsInvalid");
    assert_eq!(details(&out), json!({ "unknown": ["BOGUS", "DID"] }));
    rig.nothing_created().await;
}

/// CONVENTIONS.md 0.2 §9.2 MAY: a node's template under a class other than
/// `service` is a class conflict.
#[tokio::test]
async fn a_node_template_under_a_persona_class_is_a_did_class_conflict() {
    let rig = Rig::new().await;
    let out = rig
        .run(
            C02,
            json!({ "contextId": CTX, "serverId": "host-1", "didClass": "persona",
                    "template": "dtg-witness",
                    "templateVars": { "MEDIATOR_DID": "did:web:mediator.example" } }),
        )
        .await;
    assert_eq!(code(&out), "vta/webs/dids/create:didClassConflict");
    assert_eq!(details(&out), json!({ "requiredClass": "service" }));
    rig.nothing_created().await;
}

/// The bundle's `payload.invalid-examples.json`, each refused by the payload
/// schema the dispatch spine validates against; the response example by the
/// generated response type.
#[test]
fn create_0_2_invalid_examples_are_refused() {
    use trust_tasks_rs::validate::ValidatedPayload;
    let payloads = [
        json!({ "contextId": "alice", "serverId": "prod", "path": "people/alice" }),
        json!({ "contextId": "bridge", "serverId": "prod", "didClass": "integration" }),
        json!({ "contextId": "alice", "didClass": "persona", "path": "people/alice" }),
        json!({ "contextId": "alice", "serverId": "prod", "didClass": "persona",
                "path": "people/ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe" }),
        json!({ "contextId": "alice", "serverId": "prod", "didClass": "persona",
                "signingKeyId": "my-key" }),
        json!({ "contextId": "witness-1", "serverId": "prod", "didClass": "service",
                "template": "dtg-witness",
                "templateVars": { "MEDIATOR_DID": "did:webvh:QmMediatorScid:mediator.example" },
                "addTspService": true }),
        json!({ "contextId": "witness-1", "serverId": "prod", "didClass": "service",
                "template": "dtg-witness",
                "alsoKnownAs": ["did:webvh:QmWitnessScid:example.com:w1"] }),
        json!({ "contextId": "witness-1", "serverId": "prod", "didClass": "service",
                "templateVars": { "MEDIATOR_DID": "did:webvh:QmMediatorScid:mediator.example" } }),
        json!({ "contextId": "witness-1", "serverId": "prod", "didClass": "service",
                "templateContext": "witness-1" }),
        json!({ "contextId": "witness-1", "serverId": "prod", "didClass": "service",
                "template": "DTG Witness" }),
        json!({ "contextId": "alice", "serverId": "prod", "didClass": "persona",
                "additionalServices": [{ "id": "did:webs:other.example:EAbc#files",
                  "type": "FileStore", "serviceEndpoint": "https://files.example.com" }] }),
    ];
    for p in &payloads {
        assert!(
            spec::create::v0_2::Payload::validate_value(p).is_err(),
            "the schema accepts {p}"
        );
    }
    let response = json!({
        "did": "did:webs:example.com:people:alice:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
        "aid": "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
        "contextId": "alice", "serverId": "prod", "domain": "example.com",
        "slot": "people/alice/ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
        "keriCesrUrl": "https://example.com/people/alice/E/keri.cesr",
        "didJsonUrl": "https://example.com/people/alice/E/did.json",
        "signingKeyId": "webs-alice-sign-0", "signingKey": "DKxy",
        "nextKeyId": "webs-alice-sign-1", "keyAgreementKeyId": "webs-alice-ka-0",
        "keyAgreementKey": "CBwO", "sequenceNumber": 1, "versionId": "1:EHmL",
        "alsoKnownAs": ["did:webs:example.com:people:alice:E"],
        "createdAt": "2026-11-11T10:00:02Z"
    });
    assert!(serde_json::from_value::<spec::create::v0_2::Response>(response).is_err());
    // And a valid one is accepted, so the refusals above are the examples'.
    assert!(
        spec::create::v0_2::Payload::validate_value(&json!({
            "contextId": "witness-1", "serverId": "prod", "didClass": "service",
            "template": "dtg-witness",
            "templateVars": { "MEDIATOR_DID": "did:webvh:QmMediatorScid:mediator.example" }
        }))
        .is_ok()
    );
}
