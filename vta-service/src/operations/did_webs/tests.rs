use std::sync::Mutex;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_did_webs::{DidWebs, Kels, resolve_from_artifacts};

use super::*;
use crate::acl::Role;
use crate::keys::seed_store::PlaintextSeedStore;
use crate::test_support::{
    TestStore, admin_claims_for_context, bootstrap_test_vta, open_test_store, seed_acl_entry,
    seed_webvh_server, test_admin_did,
};

const MEDIATOR: &str = "did:peer:2.Vz6MkMediator.Ez6LSMediator";

/// A host that records what it was given and answers as a did-hosting
/// service does: the DID built from the domain and the slot.
#[derive(Default)]
struct RecordingHost {
    published: Mutex<Vec<(String, String, Option<String>)>>,
    /// Answer with this DID instead of the one the slot names.
    lie: Option<String>,
}

impl WebsHost for RecordingHost {
    async fn default_domain(&self) -> Result<String, AppError> {
        Ok("hosting.example".into())
    }

    async fn publish(
        &self,
        mnemonic: &str,
        keri_cesr: &str,
        domain: Option<&str>,
    ) -> Result<RequestUriResponse, AppError> {
        self.published.lock().unwrap().push((
            mnemonic.to_string(),
            keri_cesr.to_string(),
            domain.map(str::to_string),
        ));
        let label = domain.unwrap_or("hosting.example").replace(':', "%3A");
        let did = format!("did:webs:{label}:{}", mnemonic.replace('/', ":"));
        Ok(RequestUriResponse {
            did_url: self.lie.clone().unwrap_or(did),
            mnemonic: mnemonic.to_string(),
        })
    }
}

struct Fixture {
    ts: TestStore,
    config: AppConfig,
    audit: vta_audit::SharedAuditSink,
    seed_store: PlaintextSeedStore,
    resolver: DIDCacheClient,
}

impl Fixture {
    async fn new() -> Self {
        let ts = open_test_store().await;
        let (_vta_did, deps) = bootstrap_test_vta(&ts).await;
        let mut config = deps.config.read().await.clone();
        config.dids.webs_enabled = true;
        config.messaging = Some(
            serde_json::from_value(json!({ "mediator_did": MEDIATOR })).expect("messaging config"),
        );
        crate::contexts::create_context(&ts.contexts_ks, "acme", "Acme")
            .await
            .expect("context");
        seed_webvh_server(&ts.webvh_ks, "host-1", "did:web:hosting.example").await;
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("resolver");
        Self {
            audit: vta_audit::shared_keyspace_sink(ts.audit_ks.clone()),
            seed_store: PlaintextSeedStore::new(&ts.data_dir),
            ts,
            config,
            resolver,
        }
    }

    fn deps(&self) -> WebsDeps<'_> {
        WebsDeps {
            keys_ks: &self.ts.keys_ks,
            contexts_ks: &self.ts.contexts_ks,
            webvh_ks: &self.ts.webvh_ks,
            webs_ks: &self.ts.webs_ks,
            acl_ks: Some(&self.ts.acl_ks),
            audit: &self.audit,
            seed_store: &self.seed_store,
            config: &self.config,
            did_resolver: &self.resolver,
        }
    }

    fn params(&self) -> CreateDidWebsParams {
        let mut p = CreateDidWebsParams::new("acme", "host-1");
        p.path = Some("people/alice".into());
        p.add_mediator_service = true;
        p.add_tsp_service = Some(false);
        p
    }
}

#[test]
fn the_did_label_percent_encodes_the_port_and_joins_the_path() {
    assert_eq!(did_host_label("example.com", None), "example.com");
    assert_eq!(
        did_host_label("localhost:8534", Some("people/alice")),
        "localhost%3A8534:people:alice"
    );
}

#[test]
fn a_path_that_would_make_the_did_and_the_slot_disagree_is_refused() {
    for bad in ["", "/a", "a/", "a//b", "a:b", "a%3Ab"] {
        assert!(check_path(bad).is_err(), "{bad:?}");
    }
    check_path("people/alice").unwrap();
}

#[test]
fn a_signer_signs_as_the_key_its_public_half_names() {
    let signer = ed25519_signer(&[7u8; 32]).unwrap();
    let message = b"an event";
    let signature = KeySigner::sign(&signer, message).unwrap();
    let verfer = Verfer::from_qb64(&KeySigner::public_key(&signer).unwrap()).unwrap();
    assert!(verfer.verify(message, &signature).unwrap());
    assert!(ed25519_signer(&[7u8; 31]).is_err());
}

#[tokio::test]
async fn a_created_did_webs_is_published_resolves_and_is_recorded() {
    let f = Fixture::new().await;
    let host = RecordingHost::default();
    let created = create_did_webs(
        &f.deps(),
        &crate::test_support::super_admin_claims(),
        f.params(),
        &host,
        "test",
    )
    .await
    .expect("created");

    assert_eq!(
        created.did,
        format!("did:webs:hosting.example:people:alice:{}", created.aid)
    );
    assert_eq!(created.mnemonic, format!("people/alice/{}", created.aid));

    // Exactly what was published: the slot, the stream and the domain.
    let published = host.published.lock().unwrap().clone();
    let [(mnemonic, stream, domain)] = published.as_slice() else {
        panic!("one publish: {published:?}");
    };
    assert_eq!(mnemonic, &created.mnemonic);
    assert_eq!(domain.as_deref(), Some("hosting.example"));

    // The stream verifies, and the document a resolver derives from it has
    // the signing key, the key agreement key and the designated #didcomm.
    let kels = Kels::parse(stream.as_bytes()).expect("parses");
    let state = kels.key_state(&created.aid).expect("the KEL verifies");
    assert_eq!(state.next_keys.len(), 1, "one committed successor");
    let did = DidWebs::parse(&created.did).expect("a did:webs");
    let doc = serde_json::to_value(
        resolve_from_artifacts(&did, stream.as_bytes(), None).expect("resolves"),
    )
    .unwrap();
    let signing_fragment = created.signing_key_id.split_once('#').unwrap().1;
    let ka_fragment = created.key_agreement_key_id.split_once('#').unwrap().1;
    let text = doc.to_string();
    assert!(text.contains(signing_fragment), "{doc}");
    assert!(
        doc["keyAgreement"].to_string().contains(ka_fragment),
        "{doc}"
    );
    // A designated service's `type` is rendered as an array; peers match a
    // string or an array of them.
    let typed = |s: &serde_json::Value, t: &str| {
        s["type"] == t
            || s["type"]
                .as_array()
                .is_some_and(|a| a.iter().any(|x| x == t))
    };
    let services = doc["service"].as_array().cloned().unwrap_or_default();
    assert!(
        services
            .iter()
            .any(|s| typed(s, "DIDCommMessaging")
                && s["serviceEndpoint"].to_string().contains(MEDIATOR)),
        "{doc}"
    );
    assert!(
        !services.iter().any(|s| typed(s, "TSPTransport")),
        "TSP was not asked for: {doc}"
    );

    // The row continues the log, and the key records are in the context.
    let record = webs_store::get(&f.ts.webs_ks, &created.did)
        .await
        .unwrap()
        .expect("recorded");
    assert_eq!(record.keri_cesr, stream.as_bytes());
    assert_eq!(record.state.prefix, created.aid);
    assert_eq!(record.state.sn, created.sn);
    assert_eq!(record.context_id, "acme");
    for key_id in [
        &created.signing_key_id,
        &created.next_key_id,
        &created.key_agreement_key_id,
    ] {
        let key: crate::keys::KeyRecord =
            f.ts.keys_ks
                .get(crate::keys::store_key(key_id))
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("no key record {key_id}"));
        assert_eq!(key.context_id.as_deref(), Some("acme"));
    }

    // get and list answer within the context, and not outside it.
    let admin = admin_claims_for_context("acme");
    assert_eq!(
        get_did_webs(&f.ts.webs_ks, &admin, &created.did)
            .await
            .unwrap()
            .did,
        created.did
    );
    assert_eq!(
        list_did_webs(&f.ts.webs_ks, &admin, "acme")
            .await
            .unwrap()
            .len(),
        1
    );
    let other = admin_claims_for_context("other");
    assert!(matches!(
        get_did_webs(&f.ts.webs_ks, &other, &created.did).await,
        Err(AppError::NotFound(_))
    ));
}

#[tokio::test]
async fn creation_is_refused_while_did_webs_is_off() {
    let mut f = Fixture::new().await;
    f.config.dids.webs_enabled = false;
    let host = RecordingHost::default();
    let err = create_did_webs(
        &f.deps(),
        &crate::test_support::super_admin_claims(),
        f.params(),
        &host,
        "test",
    )
    .await
    .expect_err("off");
    assert!(
        matches!(&err, AppError::Forbidden(m) if m.contains("webs_enabled")),
        "{err:?}"
    );
    assert!(host.published.lock().unwrap().is_empty());
}

#[tokio::test]
async fn creation_needs_key_mint() {
    let f = Fixture::new().await;
    // An entry with a role that does not carry KeyMint.
    let (did, _) = test_admin_did();
    let reader = "did:key:z6MkReaderWithoutKeyMint";
    seed_acl_entry(&f.ts.acl_ks, reader, Role::Reader, vec!["acme".into()]).await;
    let mut auth = admin_claims_for_context("acme");
    auth.did = reader.into();
    auth.role = Role::Reader;
    let host = RecordingHost::default();
    let err = create_did_webs(&f.deps(), &auth, f.params(), &host, "test")
        .await
        .expect_err("no KeyMint");
    assert!(matches!(err, AppError::Forbidden(_)), "{err:?} ({did})");
    assert!(host.published.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_host_that_serves_another_did_leaves_nothing_recorded() {
    let f = Fixture::new().await;
    let host = RecordingHost {
        lie: Some("did:webs:elsewhere.example:EOther".into()),
        ..RecordingHost::default()
    };
    let err = create_did_webs(
        &f.deps(),
        &crate::test_support::super_admin_claims(),
        f.params(),
        &host,
        "test",
    )
    .await
    .expect_err("mismatch");
    assert!(matches!(err, AppError::Internal(_)), "{err:?}");
    assert!(webs_store::list(&f.ts.webs_ks).await.unwrap().is_empty());
}

#[tokio::test]
async fn tsp_asked_for_is_designated_through_the_mediator() {
    let f = Fixture::new().await;
    let mut params = f.params();
    params.path = None;
    params.add_mediator_service = false;
    params.add_tsp_service = Some(true);
    let host = RecordingHost::default();
    let created = create_did_webs(
        &f.deps(),
        &crate::test_support::super_admin_claims(),
        params,
        &host,
        "test",
    )
    .await
    .expect("created");
    assert_eq!(
        created.mnemonic, created.aid,
        "no path: the slot is the AID"
    );
    let stream = host.published.lock().unwrap()[0].1.clone();
    let did = DidWebs::parse(&created.did).unwrap();
    let doc = serde_json::to_value(resolve_from_artifacts(&did, stream.as_bytes(), None).unwrap())
        .unwrap();
    let services = doc["service"].as_array().cloned().unwrap_or_default();
    assert_eq!(services.len(), 1, "{doc}");
    assert!(
        services[0]["id"].as_str().unwrap().ends_with("#tsp"),
        "{doc}"
    );
    assert_eq!(services[0]["serviceEndpoint"], MEDIATOR, "{doc}");
}
