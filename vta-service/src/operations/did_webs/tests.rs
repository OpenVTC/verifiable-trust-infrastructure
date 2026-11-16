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
    /// Refuse every publication while set, as an unreachable host would.
    down: std::sync::atomic::AtomicBool,
    deleted: Mutex<Vec<(String, Option<String>)>>,
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
        if self.down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(AppError::Internal("hosting server unreachable".into()));
        }
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

    async fn delete(&self, mnemonic: &str, domain: Option<&str>) -> Result<(), AppError> {
        self.deleted
            .lock()
            .unwrap()
            .push((mnemonic.to_string(), domain.map(str::to_string)));
        Ok(())
    }
}

impl RecordingHost {
    fn last_stream(&self) -> String {
        self.published
            .lock()
            .unwrap()
            .last()
            .expect("published")
            .1
            .clone()
    }

    fn publications(&self) -> usize {
        self.published.lock().unwrap().len()
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
            did_templates_ks: Some(&self.ts.did_templates_ks),
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
        err.refusal() == Some(WebsRefusal::MethodDisabled)
            && err.to_string().contains("webs_enabled"),
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
    assert!(
        matches!(err, WebsError::App(AppError::Forbidden(_))),
        "{err:?} ({did})"
    );
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
    assert!(
        matches!(err, WebsError::App(AppError::Internal(_))),
        "{err:?}"
    );
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

/// S6, decision 2: a key-role did:webs — what a node's durable identity is —
/// has distinct attestation, operational and messaging keys, each on its own
/// path and recorded under the id its document gives it, and the key event
/// log's key in no relationship (VTI-KEY-071, VTI-KEY-072, VTI-KEY-173).
#[tokio::test]
async fn a_key_role_did_webs_has_distinct_role_keys_found_by_role() {
    let f = Fixture::new().await;
    let host = RecordingHost::default();
    let mut params = f.params();
    params.key_roles = true;
    let created = create_did_webs(
        &f.deps(),
        &crate::test_support::super_admin_claims(),
        params,
        &host,
        "test",
    )
    .await
    .expect("created");
    let attestation = created.attestation_key_id.clone().expect("attestation key");
    let operational = created.operational_key_id.clone().expect("operational key");

    let published = host.published.lock().unwrap().clone();
    let [(_, stream, _)] = published.as_slice() else {
        panic!("one publish: {published:?}");
    };
    let doc = document(&created.did, stream);
    assert!(doc.get("keyRoles").is_some(), "{doc}");

    // By role, the ids the creation recorded.
    let ids = vta_sdk::node_keys::NodeKeyIds::from_document(&created.did, &doc).unwrap();
    assert_eq!(ids.signing, attestation);
    assert_eq!(ids.authentication, operational);
    assert_eq!(
        ids.key_agreement.as_deref(),
        Some(created.key_agreement_key_id.as_str())
    );
    // The key event log's key signs no relationship.
    assert!(
        !doc["authentication"]
            .to_string()
            .contains(created.signing_key_id.split_once('#').unwrap().1)
            && !doc["assertionMethod"]
                .to_string()
                .contains(created.signing_key_id.split_once('#').unwrap().1),
        "{doc}"
    );

    // Every key is recorded, in the context, each on its own path.
    let mut paths = std::collections::BTreeSet::new();
    for key_id in [
        &created.signing_key_id,
        &created.next_key_id,
        &created.key_agreement_key_id,
        &attestation,
        &operational,
    ] {
        let record = key(&f, key_id).await;
        assert_eq!(record.context_id.as_deref(), Some("acme"));
        assert!(
            paths.insert(record.derivation_path.clone()),
            "{key_id} reuses a path"
        );
    }

    // And the VTA would read the same keys off its own record.
    let stored = record(&f, &created.did).await;
    assert_eq!(
        stored.attestation_key_id.as_deref(),
        Some(attestation.as_str())
    );
    assert_eq!(
        stored.operational_key_id.as_deref(),
        Some(operational.as_str())
    );
    let keys = crate::self_keys::self_keys(&created.did, None, Some(&f.ts.webs_ks)).await;
    assert_eq!(keys.signing.record_id, attestation);
    assert_eq!(keys.authentication.record_id, operational);
}

/// S6 decision 3: setup mints a VTA's did:webs without its host, and the
/// first boot publishes it once — the stream setup minted, at its slot and
/// domain — after which nothing more is sent.
#[tokio::test]
async fn setup_mints_offline_and_the_first_boot_publishes_once() {
    let f = Fixture::new().await;
    let mut params = f.params();
    params.key_roles = true;
    params.defer_publish = true;
    params.domain = Some("hosting.example".into());
    let created = create_did_webs(
        &f.deps(),
        &crate::test_support::super_admin_claims(),
        params,
        &NoHost,
        "setup",
    )
    .await
    .expect("minted offline");
    let stored = record(&f, &created.did).await;
    assert!(!stored.published);
    assert_eq!(stored.domain.as_deref(), Some("hosting.example"));

    let host = RecordingHost::default();
    assert!(
        publish_own_identity(&f.ts.webs_ks, &created.did, &host)
            .await
            .expect("published")
    );
    let published = host.published.lock().unwrap().clone();
    let [(mnemonic, stream, domain)] = published.as_slice() else {
        panic!("one publish: {published:?}");
    };
    assert_eq!(mnemonic, &created.mnemonic);
    assert_eq!(stream.as_bytes(), stored.keri_cesr.as_slice());
    assert_eq!(domain.as_deref(), Some("hosting.example"));
    assert!(record(&f, &created.did).await.published);

    // Published: the next boot sends nothing.
    assert!(
        !publish_own_identity(&f.ts.webs_ks, &created.did, &host)
            .await
            .unwrap()
    );
    assert_eq!(host.published.lock().unwrap().len(), 1);
}

/// A deferred create must be told its domain: setup cannot ask the host.
#[tokio::test]
async fn a_deferred_create_names_its_domain() {
    let f = Fixture::new().await;
    let mut params = f.params();
    params.defer_publish = true;
    params.domain = None;
    let err = create_did_webs(
        &f.deps(),
        &crate::test_support::super_admin_claims(),
        params,
        &NoHost,
        "setup",
    )
    .await
    .expect_err("refused");
    assert!(
        matches!(err, WebsError::App(AppError::Validation(_))),
        "{err:?}"
    );
}

/// A key-role did:webs, as a node's identity is made.
async fn key_role(f: &Fixture, host: &RecordingHost) -> CreateDidWebsResult {
    let mut params = f.params();
    params.key_roles = true;
    create_did_webs(
        &f.deps(),
        &crate::test_support::super_admin_claims(),
        params,
        host,
        "test",
    )
    .await
    .expect("created")
}

/// S6: planned rotation of a role key replaces that key and no other; the
/// retired key signs nothing more, while a replaced messaging key stays held
/// to decrypt what was sent to it (VTI-KEY-072).
#[tokio::test]
async fn rotating_a_role_key_replaces_it_alone() {
    use affinidi_did_webs::key_roles::KeyRole;
    let f = Fixture::new().await;
    let host = RecordingHost::default();
    let created = key_role(&f, &host).await;
    let before = record(&f, &created.did).await;

    let rotated = rotate_did_webs_role_keys(
        &f.deps(),
        &crate::test_support::super_admin_claims(),
        &created.did,
        &[KeyRole::Operational, KeyRole::Messaging],
        None,
        &host,
        "test",
    )
    .await
    .expect("rotated");
    assert_eq!(rotated.rotated, ["operational", "messaging"]);
    assert!(!rotated.own_identity);
    assert_eq!(
        Some(rotated.attestation_key_id.clone()),
        before.attestation_key_id
    );
    assert_ne!(
        Some(rotated.operational_key_id.clone()),
        before.operational_key_id
    );
    assert_ne!(rotated.key_agreement_key_id, before.key_agreement_key_id);

    // What the host now serves gives the new keys by role.
    let published = host.published.lock().unwrap().clone();
    let doc = document(&created.did, &published.last().unwrap().1);
    let ids = vta_sdk::node_keys::NodeKeyIds::from_document(&created.did, &doc).unwrap();
    assert_eq!(ids.signing, rotated.attestation_key_id);
    assert_eq!(ids.authentication, rotated.operational_key_id);
    assert_eq!(
        ids.key_agreement.as_deref(),
        Some(rotated.key_agreement_key_id.as_str())
    );

    // The retired operational key is revoked; the old messaging key is held.
    let old_operational = key(&f, before.operational_key_id.as_deref().unwrap()).await;
    assert_eq!(old_operational.status, vta_sdk::keys::KeyStatus::Revoked);
    let old_messaging = key(&f, &before.key_agreement_key_id).await;
    assert_eq!(old_messaging.status, vta_sdk::keys::KeyStatus::Active);
    let new_operational = key(&f, &rotated.operational_key_id).await;
    assert_eq!(new_operational.context_id.as_deref(), Some("acme"));
    assert_ne!(
        new_operational.derivation_path,
        old_operational.derivation_path
    );

    // The record agrees, and the VTA would read the same keys off it.
    let after = record(&f, &created.did).await;
    assert_eq!(
        after.operational_key_id.as_deref(),
        Some(rotated.operational_key_id.as_str())
    );
    assert_eq!(after.state.sn, rotated.sequence_number);
}

/// Rotating this VTA's own role keys tells the caller to restart it, so every
/// component loads the keys under their new ids.
#[tokio::test]
async fn rotating_this_vtas_own_role_keys_asks_for_a_restart() {
    use affinidi_did_webs::key_roles::KeyRole;
    let mut f = Fixture::new().await;
    let host = RecordingHost::default();
    let created = key_role(&f, &host).await;
    f.config.vta_did = Some(created.did.clone());
    let rotated = rotate_did_webs_role_keys(
        &f.deps(),
        &crate::test_support::super_admin_claims(),
        &created.did,
        &[KeyRole::Attestation],
        None,
        &host,
        "test",
    )
    .await
    .expect("rotated");
    assert!(rotated.own_identity);
}

/// A did:webs without key roles has no role keys to rotate.
#[tokio::test]
async fn a_did_webs_without_key_roles_has_no_role_keys_to_rotate() {
    use affinidi_did_webs::key_roles::KeyRole;
    let f = Fixture::new().await;
    let host = RecordingHost::default();
    let created = created(&f, &host).await;
    let err = rotate_did_webs_role_keys(
        &f.deps(),
        &crate::test_support::super_admin_claims(),
        &created.did,
        &[KeyRole::Operational],
        None,
        &host,
        "test",
    )
    .await
    .expect_err("refused");
    assert!(
        matches!(err, WebsError::App(AppError::Validation(_))),
        "{err:?}"
    );
}

/// The VTA's own DID cannot be deleted through the DID operations.
#[tokio::test]
async fn this_vtas_own_did_is_not_deleted() {
    let mut f = Fixture::new().await;
    let host = RecordingHost::default();
    let created = created(&f, &host).await;
    f.config.vta_did = Some(created.did.clone());
    let err = delete_did_webs(
        &f.deps(),
        &crate::test_support::super_admin_claims(),
        &created.did,
        None,
        &host,
        "test",
    )
    .await
    .expect_err("refused");
    assert!(
        matches!(err, WebsError::App(AppError::Forbidden(_))),
        "{err:?}"
    );
    assert!(!record(&f, &created.did).await.deactivated);
}

/// Without key roles a did:webs is as it was: no `keyRoles`, no role keys.
#[tokio::test]
async fn a_did_webs_without_key_roles_has_no_role_keys() {
    let f = Fixture::new().await;
    let host = RecordingHost::default();
    let created = created(&f, &host).await;
    assert!(created.attestation_key_id.is_none() && created.operational_key_id.is_none());
    let published = host.published.lock().unwrap().clone();
    let doc = document(&created.did, &published[0].1);
    assert!(doc.get("keyRoles").is_none(), "{doc}");
}

// ── Update, rotate, delete ────────────────────────────────────────────────

async fn created(f: &Fixture, host: &RecordingHost) -> CreateDidWebsResult {
    create_did_webs(
        &f.deps(),
        &crate::test_support::super_admin_claims(),
        f.params(),
        host,
        "test",
    )
    .await
    .expect("created")
}

fn document(did: &str, stream: &str) -> serde_json::Value {
    let did = DidWebs::parse(did).unwrap();
    serde_json::to_value(resolve_from_artifacts(&did, stream.as_bytes(), None).expect("resolves"))
        .unwrap()
}

async fn record(f: &Fixture, did: &str) -> WebsDidRecord {
    webs_store::get(&f.ts.webs_ks, did)
        .await
        .unwrap()
        .expect("record")
}

async fn key(f: &Fixture, key_id: &str) -> crate::keys::KeyRecord {
    f.ts.keys_ks
        .get(crate::keys::store_key(key_id))
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("no key record {key_id}"))
}

#[tokio::test]
async fn an_update_replaces_designations_and_keeps_the_keys() {
    let f = Fixture::new().await;
    let host = RecordingHost::default();
    let c = created(&f, &host).await;
    let before = record(&f, &c.did).await;

    let mut params = UpdateDidWebsParams::new(&c.did);
    params.services = Some(WebsServices::new(false, true, Vec::new()));
    params.rotate_key_agreement_key = true;
    params.expected_version_id = Some(lifecycle::version_id(&before.state));
    let updated = update_did_webs(
        &f.deps(),
        &admin_claims_for_context("acme"),
        params,
        &host,
        "test",
    )
    .await
    .expect("updated");
    assert_eq!(updated.replaced, vec!["keyAgreement", "services"]);
    assert_ne!(updated.key_agreement_key_id, c.key_agreement_key_id);

    let doc = document(&c.did, &host.last_stream());
    let services = doc["service"].as_array().cloned().unwrap_or_default();
    assert_eq!(services.len(), 1, "{doc}");
    assert!(
        services[0]["id"].as_str().unwrap().ends_with("#tsp"),
        "{doc}"
    );
    let ka = doc["keyAgreement"].to_string();
    let new_ka = updated.key_agreement_key_id.split_once('#').unwrap().1;
    let old_ka = c.key_agreement_key_id.split_once('#').unwrap().1;
    assert!(ka.contains(new_ka) && !ka.contains(old_ka), "{doc}");

    let after = record(&f, &c.did).await;
    assert_eq!(after.state.keys, before.state.keys, "no key changed");
    assert_eq!(after.state.next_digests, before.state.next_digests);
    assert!(after.state.sn > before.state.sn);
    assert_eq!(after.key_agreement_key_id, updated.key_agreement_key_id);
    assert_eq!(
        key(&f, &updated.key_agreement_key_id)
            .await
            .context_id
            .as_deref(),
        Some("acme")
    );

    // The same services again change nothing, and nothing is published.
    let published = host.publications();
    let mut again = UpdateDidWebsParams::new(&c.did);
    again.services = Some(WebsServices::new(false, true, Vec::new()));
    let err = update_did_webs(
        &f.deps(),
        &admin_claims_for_context("acme"),
        again,
        &host,
        "test",
    )
    .await
    .expect_err("noChange");
    assert!(err.refusal() == Some(WebsRefusal::NoChange), "{err:?}");
    assert_eq!(host.publications(), published);
}

#[tokio::test]
async fn a_write_based_on_another_version_is_refused() {
    let f = Fixture::new().await;
    let host = RecordingHost::default();
    let c = created(&f, &host).await;
    let mut params = UpdateDidWebsParams::new(&c.did);
    params.services = Some(WebsServices::new(false, true, Vec::new()));
    params.expected_version_id = Some("0:Ewrong".into());
    let err = update_did_webs(
        &f.deps(),
        &admin_claims_for_context("acme"),
        params,
        &host,
        "test",
    )
    .await
    .expect_err("conflict");
    assert!(
        err.refusal() == Some(WebsRefusal::VersionConflict),
        "{err:?}"
    );
    let err = rotate_did_webs_keys(
        &f.deps(),
        &admin_claims_for_context("acme"),
        &c.did,
        Some("0:Ewrong"),
        &host,
        "test",
    )
    .await
    .expect_err("conflict");
    assert!(
        err.refusal() == Some(WebsRefusal::VersionConflict),
        "{err:?}"
    );
    assert_eq!(host.publications(), 1, "only the creation");

    // A caller outside the context does not find it.
    let err = rotate_did_webs_keys(
        &f.deps(),
        &admin_claims_for_context("other"),
        &c.did,
        None,
        &host,
        "test",
    )
    .await
    .expect_err("not found");
    assert_eq!(err.refusal(), Some(WebsRefusal::NotFound), "{err:?}");
}

#[tokio::test]
async fn a_rotation_installs_the_committed_successor() {
    let f = Fixture::new().await;
    let host = RecordingHost::default();
    let c = created(&f, &host).await;
    let successor_public = key(&f, &c.next_key_id).await.public_key;
    let successor_qb64 = ed25519_qb64(&successor_public).unwrap();

    let rotated = rotate_did_webs_keys(
        &f.deps(),
        &admin_claims_for_context("acme"),
        &c.did,
        None,
        &host,
        "test",
    )
    .await
    .expect("rotated");
    assert!(!rotated.resumed);
    assert_eq!(rotated.signing_public_key, successor_qb64);
    assert_eq!(
        rotated.signing_key_id,
        format!("{}#{successor_qb64}", c.did)
    );
    assert_eq!(rotated.retired_key_id, c.signing_key_id);

    // keripy's rule, as our reader applies it: the stream verifies, and the
    // key state names the successor and a fresh commitment.
    let stream = host.last_stream();
    let kels = Kels::parse(stream.as_bytes()).unwrap();
    let state = kels.key_state(&c.aid).expect("the rotation verifies");
    assert_eq!(state.keys, vec![successor_qb64.clone()]);
    assert_eq!(state.next_keys.len(), 1);
    let doc = document(&c.did, &stream);
    let old = c.signing_key_id.split_once('#').unwrap().1;
    assert!(doc.to_string().contains(&successor_qb64), "{doc}");
    assert!(
        !doc["verificationMethod"].to_string().contains(old),
        "{doc}"
    );

    // Key records: the successor is the signing key, the old one revoked,
    // and the new successor recorded in the context.
    assert_eq!(
        key(&f, &rotated.signing_key_id).await.status,
        vta_sdk::keys::KeyStatus::Active
    );
    assert_eq!(
        key(&f, &c.signing_key_id).await.status,
        vta_sdk::keys::KeyStatus::Revoked
    );
    assert_eq!(
        key(&f, &rotated.next_key_id).await.context_id.as_deref(),
        Some("acme")
    );
    let r = record(&f, &c.did).await;
    assert!(r.staged.is_none());
    assert_eq!(r.signing_key_id, rotated.signing_key_id);

    // A second rotation signs with the new successor.
    let again = rotate_did_webs_keys(
        &f.deps(),
        &admin_claims_for_context("acme"),
        &c.did,
        Some(&rotated.version_id),
        &host,
        "test",
    )
    .await
    .expect("rotated again");
    let kels = Kels::parse(host.last_stream().as_bytes()).unwrap();
    assert_eq!(
        kels.key_state(&c.aid).unwrap().keys,
        vec![again.signing_public_key.clone()]
    );
}

#[tokio::test]
async fn a_rotation_the_host_did_not_take_is_resumed_not_repeated() {
    let f = Fixture::new().await;
    let host = RecordingHost::default();
    let c = created(&f, &host).await;
    let before = record(&f, &c.did).await;

    host.down.store(true, std::sync::atomic::Ordering::SeqCst);
    rotate_did_webs_keys(
        &f.deps(),
        &admin_claims_for_context("acme"),
        &c.did,
        None,
        &host,
        "test",
    )
    .await
    .expect_err("the host is down");
    let staged = record(&f, &c.did).await;
    let pending = staged.staged.clone().expect("staged");
    assert_eq!(staged.state, before.state, "nothing committed");
    assert_eq!(staged.signing_key_id, before.signing_key_id);

    // Every other write completes it first; while the host is down, none can.
    let mut params = UpdateDidWebsParams::new(&c.did);
    params.services = Some(WebsServices::new(false, true, Vec::new()));
    update_did_webs(
        &f.deps(),
        &admin_claims_for_context("acme"),
        params,
        &host,
        "test",
    )
    .await
    .expect_err("the staged rotation is not yet published");

    host.down.store(false, std::sync::atomic::Ordering::SeqCst);
    let resumed = rotate_did_webs_keys(
        &f.deps(),
        &admin_claims_for_context("acme"),
        &c.did,
        None,
        &host,
        "test",
    )
    .await
    .expect("resumed");
    assert!(resumed.resumed);
    assert_eq!(
        resumed.sequence_number, pending.state.sn,
        "the same rotation, once"
    );
    assert_eq!(host.last_stream().as_bytes(), pending.keri_cesr.as_slice());
    let after = record(&f, &c.did).await;
    assert!(after.staged.is_none());
    assert_eq!(after.state, pending.state);
}

#[tokio::test]
async fn a_deletion_deactivates_removes_the_slot_and_keeps_the_record() {
    let f = Fixture::new().await;
    let host = RecordingHost::default();
    let c = created(&f, &host).await;

    let deleted = delete_did_webs(
        &f.deps(),
        &admin_claims_for_context("acme"),
        &c.did,
        None,
        &host,
        "test",
    )
    .await
    .expect("deleted");
    assert!(deleted.deactivated && deleted.newly_deactivated && deleted.slot_removed);
    assert!(deleted.host_cleanup_error.is_none());
    assert_eq!(
        host.deleted.lock().unwrap().as_slice(),
        &[(c.mnemonic.clone(), Some("hosting.example".to_string()))]
    );

    let did = DidWebs::parse(&c.did).unwrap();
    let stream = host.last_stream();
    let resolution = affinidi_did_webs::resolve_with_metadata(&did, stream.as_bytes(), None)
        .expect("a deactivated identifier still resolves");
    assert!(resolution.metadata.deactivated);

    let r = record(&f, &c.did).await;
    assert!(r.deactivated && r.slot_removed);
    assert_eq!(r.keri_cesr, stream.as_bytes(), "the final stream is kept");

    // Again: nothing published, nothing removed twice.
    let published = host.publications();
    let again = delete_did_webs(
        &f.deps(),
        &admin_claims_for_context("acme"),
        &c.did,
        None,
        &host,
        "test",
    )
    .await
    .expect("idempotent");
    assert!(!again.newly_deactivated);
    assert_eq!(host.publications(), published);
    assert_eq!(host.deleted.lock().unwrap().len(), 1);

    // And nothing more is signed as it.
    let err = rotate_did_webs_keys(
        &f.deps(),
        &admin_claims_for_context("acme"),
        &c.did,
        None,
        &host,
        "test",
    )
    .await
    .expect_err("deactivated");
    assert!(err.refusal() == Some(WebsRefusal::Deactivated), "{err:?}");
}

// ── Personas ──────────────────────────────────────────────────────────────

fn persona_stores(f: &Fixture) -> crate::operations::persona::PersonaStores<'_> {
    crate::operations::persona::PersonaStores {
        keys_ks: &f.ts.keys_ks,
        webvh_ks: &f.ts.webvh_ks,
        webs_ks: &f.ts.webs_ks,
    }
}

#[tokio::test]
async fn a_did_webs_is_a_persona_signing_as_its_key_state_key() {
    use crate::operations::persona::{Relationship, own_document, persona_key_for};
    let f = Fixture::new().await;
    let host = RecordingHost::default();
    let c = created(&f, &host).await;
    let acme = admin_claims_for_context("acme");

    let doc = own_document(persona_stores(&f), &c.did)
        .await
        .unwrap()
        .expect("its own document, from its own stream");
    assert_eq!(doc["id"], c.did);

    for relationship in [Relationship::AssertionMethod, Relationship::Authentication] {
        let key = persona_key_for(persona_stores(&f), &acme, &c.did, relationship)
            .await
            .unwrap()
            .expect("a persona the caller may act as");
        assert_eq!(key.key_id, c.signing_key_id);
        assert_eq!(key.verification_method, c.signing_key_id);
        // The method a proof names is the one the document lists for it.
        let fragment = format!("#{}", c.signing_key_id.split_once('#').unwrap().1);
        let listed = doc[relationship.as_str()].to_string();
        assert!(
            listed.contains(&fragment) || listed.contains(&c.signing_key_id),
            "{relationship:?}: {doc}"
        );
    }

    // Outside its context it is no one's persona, and a DID URL is not a DID.
    let other = admin_claims_for_context("other");
    assert!(
        persona_key_for(
            persona_stores(&f),
            &other,
            &c.did,
            Relationship::AssertionMethod
        )
        .await
        .unwrap()
        .is_none()
    );
    assert!(
        persona_key_for(
            persona_stores(&f),
            &acme,
            &c.signing_key_id,
            Relationship::AssertionMethod
        )
        .await
        .unwrap()
        .is_none()
    );

    // After a rotation it signs with the installed key.
    let rotated = rotate_did_webs_keys(&f.deps(), &acme, &c.did, None, &host, "test")
        .await
        .expect("rotated");
    let key = persona_key_for(
        persona_stores(&f),
        &acme,
        &c.did,
        Relationship::AssertionMethod,
    )
    .await
    .unwrap()
    .expect("still a persona");
    assert_eq!(key.key_id, rotated.signing_key_id);

    // Deactivated, it signs nothing.
    delete_did_webs(&f.deps(), &acme, &c.did, None, &host, "test")
        .await
        .expect("deleted");
    assert!(
        persona_key_for(
            persona_stores(&f),
            &acme,
            &c.did,
            Relationship::AssertionMethod
        )
        .await
        .unwrap()
        .is_none()
    );
}

/// A signature a did:webs persona makes, through the same gated signer every
/// persona path uses, verifies at an independent verifier that knows nothing but
/// the document the host would serve: the VTA names its key by the method the
/// did:webs document renders for it, under the relationship the proof claims.
/// Checked again after a rotation, against the rotated document.
#[tokio::test]
async fn a_did_webs_persona_signs_a_trust_task_a_verifier_accepts() {
    use crate::operations::persona::{Relationship, persona_key_for};
    use crate::operations::room_issuance::{SigningContext, VtaKeySigner};
    use serde_json::Value;
    use trust_tasks_rs::TrustTask;
    use vta_sdk::trust_task_proof::{TrustTaskVmResolver, verify_trust_task_proof_with};

    let f = Fixture::new().await;
    let host = RecordingHost::default();
    let c = created(&f, &host).await;
    let acme = admin_claims_for_context("acme");
    let seed_store: std::sync::Arc<dyn crate::keys::seed_store::SeedStore> =
        std::sync::Arc::new(PlaintextSeedStore::new(&f.ts.data_dir));

    // What a verifier sees: the document derived from the stream the host holds.
    async fn verifier_for(did: &str, stream: &str) -> TrustTaskVmResolver {
        let mut cache = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("resolver");
        cache
            .add_did_document(did, serde_json::from_value(document(did, stream)).unwrap())
            .await;
        TrustTaskVmResolver::new(cache)
    }

    async fn sign_and_verify(
        f: &Fixture,
        seed_store: &std::sync::Arc<dyn crate::keys::seed_store::SeedStore>,
        acme: &AuthClaims,
        did: &str,
        verifier: &TrustTaskVmResolver,
        id: &str,
    ) -> Result<String, String> {
        let key = persona_key_for(persona_stores(f), acme, did, Relationship::Authentication)
            .await
            .unwrap()
            .expect("a persona the caller may act as");
        let mut task: TrustTask<Value> = TrustTask::new(
            id.to_string(),
            "https://trusttasks.org/spec/rooms/create/0.2"
                .parse()
                .expect("a type URI"),
            json!({ "roomId": "room-1", "ownerDid": did, "epoch": 1 }),
        );
        task.issuer = Some(did.to_string());
        task.recipient = Some("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into());
        task.issued_at = Some(chrono::Utc::now());
        let mut doc = serde_json::to_value(&task).unwrap();
        let signer = VtaKeySigner::new(
            SigningContext {
                keys_ks: &f.ts.keys_ks,
                imported_ks: &f.ts.imported_ks,
                internal_ks: &f.ts.internal_ks,
                contexts_ks: &f.ts.contexts_ks,
                acl_ks: &f.ts.acl_ks,
                seed_store,
                audit: &f.audit,
                auth: acme,
            },
            key.key_id,
            key.verification_method,
        );
        let proof = affinidi_data_integrity::DataIntegrityProof::sign(
            &doc,
            &signer,
            affinidi_data_integrity::SignOptions::new()
                .with_proof_purpose(Relationship::Authentication.as_str()),
        )
        .await
        .expect("the persona signs");
        doc["proof"] = serde_json::to_value(proof).unwrap();
        let typed: TrustTask<Value> = serde_json::from_value(doc).unwrap();
        verify_trust_task_proof_with(&typed, verifier)
            .await
            .map_err(|e| e.to_string())
    }

    let verifier = verifier_for(&c.did, &host.last_stream()).await;
    let signer = sign_and_verify(
        &f,
        &seed_store,
        &acme,
        &c.did,
        &verifier,
        "urn:uuid:aaaaaaaa-0000-4000-8000-000000000001",
    )
    .await
    .expect("a verifier accepts the persona's proof");
    assert_eq!(signer, c.did);

    // After a rotation the persona signs with the installed key, and the
    // rotated document is what a verifier holds it to.
    rotate_did_webs_keys(&f.deps(), &acme, &c.did, None, &host, "test")
        .await
        .expect("rotated");
    let rotated = verifier_for(&c.did, &host.last_stream()).await;
    assert_eq!(
        sign_and_verify(
            &f,
            &seed_store,
            &acme,
            &c.did,
            &rotated,
            "urn:uuid:aaaaaaaa-0000-4000-8000-000000000002",
        )
        .await
        .expect("a verifier accepts the proof after rotation"),
        c.did
    );
    // A verifier still holding the pre-rotation document refuses the new key:
    // the signature really is under the rotated key, not the old one.
    assert!(
        sign_and_verify(
            &f,
            &seed_store,
            &acme,
            &c.did,
            &verifier,
            "urn:uuid:aaaaaaaa-0000-4000-8000-000000000003",
        )
        .await
        .is_err()
    );
}

/// A secrets bundle exported for a did:webs (an integration running its own
/// messaging) names each key by the id its published document gives it: a
/// mediator matches a JWE recipient kid against these, and a kid the document
/// does not list is a secret no message can reach (`select_secret_kid`).
#[tokio::test]
async fn the_kids_a_did_webs_exports_are_the_ids_its_document_lists() {
    let f = Fixture::new().await;
    let host = RecordingHost::default();
    let c = created(&f, &host).await;
    let doc = document(&c.did, &host.last_stream());

    // Every id a relationship lists, absolute.
    let listed = |relationship: &str| -> Vec<String> {
        doc[relationship]
            .as_array()
            .unwrap_or_else(|| panic!("{relationship}: {doc}"))
            .iter()
            .map(|e| {
                let id = e.as_str().or_else(|| e["id"].as_str()).expect("an id");
                if id.starts_with('#') {
                    format!("{}{id}", c.did)
                } else {
                    id.to_string()
                }
            })
            .collect()
    };

    for (key_id, relationship) in [
        (&c.signing_key_id, "authentication"),
        (&c.signing_key_id, "assertionMethod"),
        (&c.key_agreement_key_id, "keyAgreement"),
    ] {
        let record = key(&f, key_id).await;
        let kid = vta_sdk::did_secrets::select_secret_kid(
            &c.did,
            &record.key_id,
            record.label.as_deref(),
        )
        .unwrap_or_else(|| panic!("{key_id} is exported under no kid"));
        assert!(
            listed(relationship).contains(&kid),
            "{kid} is not listed under {relationship}: {doc}"
        );
    }
}

/// A TSP peer can reach a did:webs persona: TSP's own VID resolver reads its
/// document for an Ed25519 `authentication` key, an X25519 `keyAgreement` key
/// and the `#tsp` route, and finds the keys the VTA holds and the mediator it
/// designated.
#[cfg(feature = "tsp")]
#[tokio::test]
async fn a_tsp_peer_resolves_a_did_webs_persona_to_its_keys_and_mediator() {
    let f = Fixture::new().await;
    let host = RecordingHost::default();
    let mut params = f.params();
    params.add_tsp_service = Some(true);
    let c = create_did_webs(
        &f.deps(),
        &crate::test_support::super_admin_claims(),
        params,
        &host,
        "test",
    )
    .await
    .expect("created");

    let mut cache = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("resolver");
    cache
        .add_did_document(
            &c.did,
            serde_json::from_value(document(&c.did, &host.last_stream())).unwrap(),
        )
        .await;
    let vid = affinidi_tdk::tsp::DidVidResolver::new(cache)
        .resolve_did(&c.did)
        .await
        .expect("a TSP VID");

    // A multikey: the two-byte multicodec prefix, then the key.
    let public = |record: &crate::keys::KeyRecord| {
        let (_, bytes) = multibase::decode(&record.public_key).expect("multibase");
        bytes[2..].to_vec()
    };
    let signing = key(&f, &c.signing_key_id).await;
    let agreement = key(&f, &c.key_agreement_key_id).await;
    assert_eq!(vid.signing_key.to_vec(), public(&signing));
    assert_eq!(vid.encryption_key.to_vec(), public(&agreement));
    assert_eq!(vid.mediators, vec![MEDIATOR.to_string()]);
}

/// DIDComm both ways with a did:webs persona, through its mediator.
///
/// A peer reads only the published document: it authcrypts to the persona's
/// key agreement key, wraps the message in a forward to the mediator its
/// `#didcomm` service names, and the mediator finds the persona as `next`. The
/// VTA unpacks the inner message with the persona's secrets as it exports them
/// (`build_did_secrets_bundle`, the kids a mediator matches recipients on), and
/// authcrypts back from the persona to a peer that authenticates the sender.
#[cfg(feature = "didcomm")]
#[tokio::test]
async fn a_did_webs_persona_sends_and_receives_didcomm_through_its_mediator() {
    use affinidi_secrets_resolver::SecretsResolver as _;
    use affinidi_secrets_resolver::secrets::Secret;
    use affinidi_tdk::common::TDKSharedState;
    use affinidi_tdk::common::config::TDKConfig;
    use affinidi_tdk::didcomm::Message;
    use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
    use affinidi_tdk::messaging::ATM;
    use affinidi_tdk::messaging::config::ATMConfig;
    use affinidi_tdk::messaging::profiles::ATMProfile;
    use base64::Engine as _;
    use std::sync::Arc;

    fn peer_identity() -> (String, Vec<Secret>) {
        DID::generate_did_peer(
            vec![
                (PeerKeyRole::Verification, KeyType::Ed25519),
                (PeerKeyRole::Encryption, KeyType::X25519),
            ],
            None,
        )
        .expect("a did:peer")
    }

    /// An ATM that holds `secrets` and knows `documents` (everything else, a
    /// did:peer, resolves from the identifier).
    async fn agent(
        secrets: &[Secret],
        documents: &[(&str, &serde_json::Value)],
        unpack_forwards: bool,
    ) -> ATM {
        let mut resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        for (did, doc) in documents {
            resolver
                .add_did_document(did, serde_json::from_value((*doc).clone()).unwrap())
                .await;
        }
        let tdk = TDKSharedState::new(
            TDKConfig::builder()
                .with_did_resolver(resolver)
                .build()
                .unwrap(),
        )
        .await
        .unwrap();
        for s in secrets {
            tdk.secrets_resolver().insert(s.clone()).await;
        }
        ATM::new(
            ATMConfig::builder()
                .with_unpack_forwards(unpack_forwards)
                .build()
                .unwrap(),
            Arc::new(tdk),
        )
        .await
        .unwrap()
    }

    // The persona, routed through a mediator that exists.
    let (mediator, mediator_secrets) = peer_identity();
    let mut f = Fixture::new().await;
    f.config.messaging =
        Some(serde_json::from_value(json!({ "mediator_did": mediator })).expect("messaging"));
    let host = RecordingHost::default();
    let mut params = f.params();
    params.set_primary = true;
    let c = create_did_webs(
        &f.deps(),
        &crate::test_support::super_admin_claims(),
        params,
        &host,
        "test",
    )
    .await
    .expect("created");
    let doc = document(&c.did, &host.last_stream());

    // The persona's secrets, as the VTA exports them for the DID's context.
    let seed_store: Arc<dyn crate::keys::seed_store::SeedStore> =
        Arc::new(PlaintextSeedStore::new(&f.ts.data_dir));
    let bundle = crate::operations::export::build_did_secrets_bundle(
        &crate::operations::export::ExportDeps {
            keys_ks: &f.ts.keys_ks,
            contexts_ks: &f.ts.contexts_ks,
            imported_ks: &f.ts.imported_ks,
            audit: &f.audit,
            acl_ks: &f.ts.acl_ks,
            #[cfg(feature = "webvh")]
            webvh_ks: &f.ts.webvh_ks,
            webs_ks: &f.ts.webs_ks,
            seed_store: &seed_store,
        },
        &crate::test_support::super_admin_claims(),
        "acme",
        crate::operations::keys::ExportChannel::Local("test"),
    )
    .await
    .expect("the persona's secrets");
    assert_eq!(bundle.did, c.did, "the context's DID is the persona");
    // Exactly the keys the document lists, led by its authentication key: the
    // pre-rotated successor stays with the VTA (it controls the next rotation),
    // and is never what a reader of the first Ed25519 key signs with.
    let ids: Vec<&str> = bundle.secrets.iter().map(|e| e.key_id.as_str()).collect();
    assert_eq!(
        ids,
        vec![c.signing_key_id.as_str(), c.key_agreement_key_id.as_str()],
        "{ids:?}"
    );
    assert!(!ids.contains(&c.next_key_id.as_str()));
    assert_eq!(
        bundle.trust_task_signing_key().map(|e| e.key_id.as_str()),
        Some(c.signing_key_id.as_str())
    );
    let persona_secrets: Vec<Secret> = bundle
        .secrets
        .iter()
        .map(|e| Secret::from_multibase(&e.private_key_multibase, Some(&e.key_id)).unwrap())
        .collect();

    let (peer, peer_secrets) = peer_identity();
    let persona_atm = agent(&persona_secrets, &[(&c.did, &doc)], true).await;
    let peer_atm = agent(&peer_secrets, &[(&c.did, &doc)], true).await;
    let mediator_atm = agent(&mediator_secrets, &[(&c.did, &doc)], false).await;

    // (a) Peer → persona, through the mediator its document names.
    let route = doc["service"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"].as_str().is_some_and(|id| id.ends_with("#didcomm")))
        .unwrap_or_else(|| panic!("a #didcomm service: {doc}"))["serviceEndpoint"][0]["uri"]
        .as_str()
        .expect("a mediator uri")
        .to_string();
    assert_eq!(route, mediator);

    let to_persona = Message::build(
        "urn:uuid:7e1b1e1a-0000-4000-8000-000000000001".to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "hello, did:webs" }),
    )
    .from(peer.clone())
    .to(c.did.clone())
    .finalize();
    let (packed, _) = peer_atm
        .pack_encrypted(&to_persona, &c.did, Some(&peer), None)
        .await
        .expect("authcrypt to the persona");
    let peer_profile = Arc::new(
        ATMProfile::new(&peer_atm, None, peer.clone(), Some(mediator.clone()))
            .await
            .unwrap(),
    );
    let (_, envelope) = peer_atm
        .routing()
        // Authcrypted, as room-host and the VTA send their forwards.
        .forward_message(&peer_profile, false, &packed, &route, &c.did, None, None)
        .await
        .expect("a forward to the mediator");

    let (forward, _) = mediator_atm
        .unpack(&envelope)
        .await
        .expect("the mediator opens the forward");
    assert_eq!(forward.typ, "https://didcomm.org/routing/2.0/forward");
    assert_eq!(
        forward.body["next"], c.did,
        "the mediator delivers to the persona"
    );
    let attachment = &forward.attachments.as_ref().unwrap()[0];
    let inner = String::from_utf8(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(
                attachment
                    .data
                    .base64
                    .as_ref()
                    .expect("a base64 attachment"),
            )
            .unwrap(),
    )
    .unwrap();
    // The mediator cannot read what it carries.
    assert!(mediator_atm.unpack(&inner).await.is_err());

    let (received, meta) = persona_atm
        .unpack(&inner)
        .await
        .expect("the persona's exported secrets open it");
    assert_eq!(received.body["content"], "hello, did:webs");
    assert!(meta.encrypted && meta.authenticated, "{meta:?}");
    assert!(
        meta.encrypted_from_kid
            .as_deref()
            .is_some_and(|kid| kid.starts_with(&format!("{peer}#"))),
        "{meta:?}"
    );
    assert!(
        meta.encrypted_to_kids
            .iter()
            .all(|kid| kid.starts_with(&format!("{}#", c.did))),
        "{meta:?}"
    );

    // (b) Persona → peer: the peer authenticates the persona from its document.
    let reply = Message::build(
        "urn:uuid:7e1b1e1a-0000-4000-8000-000000000002".to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "hello back" }),
    )
    .from(c.did.clone())
    .to(peer.clone())
    .finalize();
    let (packed, _) = persona_atm
        .pack_encrypted(&reply, &peer, Some(&c.did), None)
        .await
        .expect("authcrypt from the persona");
    let (received, meta) = peer_atm.unpack(&packed).await.expect("the peer opens it");
    assert_eq!(received.body["content"], "hello back");
    assert!(meta.authenticated, "{meta:?}");
    assert!(
        meta.encrypted_from_kid
            .as_deref()
            .is_some_and(|kid| kid.starts_with(&format!("{}#", c.did))),
        "{meta:?}"
    );
}
