//! A TEE VTA whose own identity is a `did:webs` (`[tee.kms] vta_did_webs`;
//! design note did-webs-in-the-vta §4, S8).
//!
//! [`vta_tee::did_autogen::maybe_generate_vta_did`] runs first and settles
//! everything but the mint: an identity already in the store wins, a baked
//! `vta_did` is persisted, a `did:webvh` template is generated, and asking for
//! both a template and a `did:webs` is refused. What is left for here is a
//! first boot that asked for a `did:webs`: mint it inside the enclave from the
//! KMS-bootstrapped seed with the create `vta setup` runs
//! ([`crate::operations::did_webs::create_own_identity`]), and persist it as
//! the enclave's identity (`tee:vta_did`), so every later boot restores it
//! through the store-wins path.
//!
//! It is not published here. [`crate::server`] publishes an unpublished own
//! `did:webs` at every boot until the host has it
//! (`publish_own_webs_identity`), before messaging starts, as it does for a
//! VTA set up by `vta setup` — over the host's Trust-Task HTTPS endpoint,
//! which the enclave reaches through its egress proxy (the proxy allowlists
//! the host and the domain from the same `vta_did_webs`).
//!
//! The `webs` keyspace row is the record; `tee:vta_did` names it. No sibling
//! of `tee:did_log` is written: a `did:webs` has no `did.jsonl` for the
//! parent to serve, and its key event log is published to its host instead.

#[cfg(feature = "webs")]
use tracing::info;

use vti_common::error::AppError;

use crate::config::AppConfig;
use crate::keys::seed_store::SeedStore;
use crate::store::Store;

/// The store key the enclave's identity is persisted under, from its writer.
#[cfg(feature = "webs")]
use crate::tee::did_autogen::VTA_DID_STORE_KEY;

/// Mint this enclave's `did:webs` identity on first boot, when
/// `[tee.kms] vta_did_webs` asks for one and no identity is established yet.
/// Sets `config.vta_did` on success.
///
/// A no-op when the config asks for no `did:webs` or the VTA already has an
/// identity. Resumable: a boot that died after the create but before the DID
/// was persisted adopts the identity it minted rather than minting another.
///
/// # Errors
/// `Config` when `did:webs` is off (`[dids] webs_enabled`) or this build has
/// no `webs` feature — never a fallback to another identifier (VTI-KEY-009);
/// the create's refusal otherwise.
pub async fn maybe_generate_webs_vta_did(
    config: &mut AppConfig,
    seed_store: &dyn SeedStore,
    store: &Store,
    storage_encryption_key: Option<[u8; 32]>,
) -> Result<(), AppError> {
    if config.vta_did.is_some() {
        return Ok(());
    }
    let Some(spec) = config
        .tee
        .kms
        .as_ref()
        .and_then(|kms| kms.vta_did_webs.clone())
    else {
        return Ok(());
    };
    if !config.dids.webs_enabled {
        return Err(AppError::Config(
            "[tee.kms] vta_did_webs asks for a did:webs identity, and did:webs is off: set \
             `webs_enabled = true` under `[dids]` (did:webs is alpha)"
                .into(),
        ));
    }
    let did = mint(config, &spec, seed_store, store, storage_encryption_key).await?;
    config.vta_did = Some(did);
    Ok(())
}

#[cfg(feature = "webs")]
async fn mint(
    config: &AppConfig,
    spec: &vta_config::TeeWebsIdentityConfig,
    seed_store: &dyn SeedStore,
    store: &Store,
    storage_encryption_key: Option<[u8; 32]>,
) -> Result<String, AppError> {
    use crate::operations::did_webs::{
        OwnWebsIdentity, WebsDeps, create_own_identity, own_identity_in_progress,
    };
    use crate::store::KeyspaceHandle;

    let with_enc = |ks: KeyspaceHandle| match storage_encryption_key {
        Some(key) => ks.with_encryption(key),
        None => ks,
    };
    let keys_ks = with_enc(store.keyspace(crate::keyspaces::KEYS)?);
    let webs_ks = with_enc(store.keyspace(crate::keyspaces::WEBS)?);

    let did = match own_identity_in_progress(&webs_ks).await? {
        Some(did) => {
            info!(did = %did, "adopting the did:webs identity an earlier first boot minted");
            did
        }
        None => {
            let contexts_ks = with_enc(store.keyspace(crate::keyspaces::CONTEXTS)?);
            let webvh_ks = with_enc(store.keyspace(crate::keyspaces::WEBVH)?);
            let audit =
                vta_audit::shared_keyspace_sink(with_enc(store.keyspace(crate::keyspaces::AUDIT)?));
            // Local mode, never asked: the create is told whether to designate
            // `#tsp` (`add_tsp_service`), so it resolves nothing.
            let did_resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
                vta_sdk::resolver::build_did_cache_config(None),
            )
            .await
            .map_err(|e| AppError::Internal(format!("build a DID resolver: {e}")))?;
            let mediator = config.messaging.as_ref().map(|m| m.mediator_did.as_str());
            let mut own = OwnWebsIdentity::new(&spec.server_did, &spec.domain, "tee:first-boot");
            if let Some(id) = &spec.server_id {
                own.server_id = id.clone();
            }
            own.path = spec.path.clone();
            // The same services `vta setup` designates for its own DID.
            own.additional_services =
                crate::operations::protocol::document::vta_additional_services(
                    &config.services,
                    config.public_url.as_deref(),
                    mediator,
                )
                .unwrap_or_default();
            own.add_mediator_service = config.messaging.is_some() && config.services.didcomm;
            let deps = WebsDeps {
                keys_ks: &keys_ks,
                contexts_ks: &contexts_ks,
                webvh_ks: &webvh_ks,
                webs_ks: &webs_ks,
                did_templates_ks: None,
                acl_ks: None,
                audit: &audit,
                seed_store,
                config,
                did_resolver: &did_resolver,
            };
            let created = create_own_identity(&deps, own, "tee")
                .await
                .map_err(|e| match e {
                    crate::operations::did_webs::WebsError::App(e) => e,
                    e => AppError::Config(format!(
                        "could not mint this VTA's did:webs from [tee.kms] vta_did_webs: {e}"
                    )),
                })?;
            info!(
                did = %created.did,
                server = %spec.server_did,
                "minted this VTA's did:webs identity; it is registered at its host at startup"
            );
            created.did
        }
    };

    // The enclave's identity: every later boot restores it from here.
    keys_ks
        .insert_raw_if_absent(VTA_DID_STORE_KEY, did.as_bytes().to_vec())
        .await?;
    store.persist().await?;
    Ok(did)
}

#[cfg(not(feature = "webs"))]
async fn mint(
    _config: &AppConfig,
    _spec: &vta_config::TeeWebsIdentityConfig,
    _seed_store: &dyn SeedStore,
    _store: &Store,
    _storage_encryption_key: Option<[u8; 32]>,
) -> Result<String, AppError> {
    Err(AppError::Config(
        "[tee.kms] vta_did_webs asks for a did:webs identity, and this enclave image was built \
         without the `webs` feature (`cargo build -p vta-enclave --features webs`)"
            .into(),
    ))
}

#[cfg(all(test, feature = "webs"))]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::operations::did_webs::{WebsHost, publish_own_identity};
    use crate::store::KeyspaceHandle;
    use crate::test_support::{TestSeedStore, test_app_config};
    use crate::webvh_host::RequestUriResponse;
    use vta_tee::did_autogen::maybe_generate_vta_did;

    const STORAGE_KEY: [u8; 32] = [42; 32];
    const HOST_DID: &str = "did:webvh:QmHostScid:hosting.example.com";
    const MEDIATOR: &str = "did:peer:2.Vz6MkMediator.Ez6LSMediator";

    /// A host that records what it is given and answers as a did-hosting
    /// service does: the DID the domain and the slot name.
    #[derive(Default)]
    struct FakeHost {
        published: Mutex<Vec<(String, String, Option<String>)>>,
    }

    impl WebsHost for FakeHost {
        async fn resolve_domain(&self, requested: Option<&str>) -> Result<String, AppError> {
            Ok(requested.unwrap_or_default().to_string())
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
            let label = domain.unwrap_or_default().replace(':', "%3A");
            Ok(RequestUriResponse {
                did_url: format!("did:webs:{label}:{}", mnemonic.replace('/', ":")),
                mnemonic: mnemonic.to_string(),
            })
        }

        async fn delete(&self, _mnemonic: &str, _domain: Option<&str>) -> Result<(), AppError> {
            Ok(())
        }
    }

    struct Enclave {
        _dir: tempfile::TempDir,
        store: Store,
        seed: TestSeedStore,
        config: AppConfig,
    }

    impl Enclave {
        /// A fresh enclave store and the config a TEE operator asking for a
        /// did:webs boots with.
        fn new(kms: serde_json::Value, webs_enabled: bool) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let mut config = test_app_config(dir.path().into());
            config.dids.webs_enabled = webs_enabled;
            config.messaging = Some(
                serde_json::from_value(serde_json::json!({ "mediator_did": MEDIATOR })).unwrap(),
            );
            config.tee.kms = Some(serde_json::from_value(kms).unwrap());
            let store = Store::open(&config.store).unwrap();
            Self {
                _dir: dir,
                store,
                seed: TestSeedStore(vec![7; 64]),
                config,
            }
        }

        fn webs() -> serde_json::Value {
            serde_json::json!({
                "region": "eu-west-1",
                "key_arn": "unused-in-did-generation",
                "vta_did_webs": {
                    "server_did": HOST_DID,
                    "domain": "did.example.com:8443",
                    "path": "nodes",
                }
            })
        }

        fn keyspace(&self, name: &str) -> KeyspaceHandle {
            self.store
                .keyspace(name)
                .unwrap()
                .with_encryption(STORAGE_KEY)
        }

        /// One boot's identity steps, in `vta-enclave`'s order, from the
        /// config as delivered (no `vta_did`).
        async fn boot(&self) -> Result<AppConfig, AppError> {
            let mut config = self.config.clone();
            maybe_generate_vta_did(&mut config, &self.seed, &self.store, Some(STORAGE_KEY)).await?;
            maybe_generate_webs_vta_did(&mut config, &self.seed, &self.store, Some(STORAGE_KEY))
                .await?;
            Ok(config)
        }

        async fn stored_did(&self) -> Option<String> {
            self.keyspace(crate::keyspaces::KEYS)
                .get_raw(VTA_DID_STORE_KEY)
                .await
                .unwrap()
                .map(|b| String::from_utf8(b).unwrap())
        }
    }

    /// S8: first boot mints a key-role did:webs inside the enclave, records it
    /// unpublished and persists it as the enclave's identity; the startup
    /// publish registers it at its host once; a later boot restores the same
    /// DID and mints nothing.
    #[tokio::test]
    async fn first_boot_mints_a_key_role_did_webs_and_publishes_it_once() {
        let enclave = Enclave::new(Enclave::webs(), true);
        let config = enclave.boot().await.expect("first boot");
        let did = config.vta_did.clone().expect("an identity");
        assert!(
            did.starts_with("did:webs:did.example.com%3A8443:nodes:"),
            "{did}"
        );
        assert_eq!(enclave.stored_did().await.as_deref(), Some(did.as_str()));

        let webs_ks = enclave.keyspace(crate::keyspaces::WEBS);
        let record = crate::webs_store::get(&webs_ks, &did)
            .await
            .unwrap()
            .expect("the identity's record");
        assert!(!record.published, "first boot's mint is offline");
        assert_eq!(record.context_id, "vta");
        assert_eq!(
            record.did_class,
            Some(crate::webs_store::WebsDidClass::Service)
        );
        assert!(record.attestation_key_id.is_some() && record.operational_key_id.is_some());
        let server = crate::webvh_store::get_server(
            &enclave.keyspace(crate::keyspaces::WEBVH),
            &record.server_id,
        )
        .await
        .unwrap()
        .expect("the host is registered");
        assert_eq!(server.did, HOST_DID);
        let ctx =
            crate::contexts::get_context(&enclave.keyspace(crate::keyspaces::CONTEXTS), "vta")
                .await
                .unwrap()
                .unwrap();
        assert_eq!(ctx.did.as_deref(), Some(did.as_str()));
        // The VTA finds its keys by role in its own document.
        let keys = crate::self_keys::self_keys(&did, None, Some(&webs_ks)).await;
        assert_eq!(
            Some(&keys.authentication.record_id),
            record.operational_key_id.as_ref()
        );

        // Startup publishes it, once.
        let host = FakeHost::default();
        assert!(publish_own_identity(&webs_ks, &did, &host).await.unwrap());
        {
            let published = host.published.lock().unwrap();
            let [(mnemonic, stream, domain)] = published.as_slice() else {
                panic!("one publish: {published:?}");
            };
            assert_eq!(mnemonic, &record.mnemonic);
            assert_eq!(stream.as_bytes(), record.keri_cesr.as_slice());
            assert_eq!(domain.as_deref(), Some("did.example.com:8443"));
        }

        // The next boot restores the identity and mints nothing.
        let again = enclave.boot().await.expect("second boot");
        assert_eq!(again.vta_did.as_deref(), Some(did.as_str()));
        assert_eq!(
            crate::webs_store::list(&webs_ks).await.unwrap().len(),
            1,
            "one identity"
        );
        assert!(!publish_own_identity(&webs_ks, &did, &host).await.unwrap());
        assert_eq!(host.published.lock().unwrap().len(), 1);
    }

    /// A boot that died after the create but before the DID was persisted
    /// adopts what it minted (R2.1): one identity per enclave.
    #[tokio::test]
    async fn an_interrupted_first_boot_adopts_the_identity_it_minted() {
        let enclave = Enclave::new(Enclave::webs(), true);
        let did = enclave.boot().await.unwrap().vta_did.unwrap();
        enclave
            .keyspace(crate::keyspaces::KEYS)
            .remove(VTA_DID_STORE_KEY)
            .await
            .unwrap();

        let config = enclave.boot().await.expect("resumed boot");
        assert_eq!(config.vta_did.as_deref(), Some(did.as_str()));
        assert_eq!(enclave.stored_did().await.as_deref(), Some(did.as_str()));
        let webs_ks = enclave.keyspace(crate::keyspaces::WEBS);
        assert_eq!(crate::webs_store::list(&webs_ks).await.unwrap().len(), 1);
    }

    /// Never another identifier in place of the one asked for (VTI-KEY-009).
    #[tokio::test]
    async fn a_did_webs_that_cannot_be_minted_is_refused() {
        // did:webs off.
        let enclave = Enclave::new(Enclave::webs(), false);
        let err = enclave.boot().await.expect_err("refused");
        assert!(format!("{err}").contains("webs_enabled"), "{err}");
        assert_eq!(enclave.stored_did().await, None);

        // Both a did:webvh template and a did:webs.
        let mut kms = Enclave::webs();
        kms["vta_did_template"] = "did:webvh:{SCID}:identity.example.com:vta".into();
        let enclave = Enclave::new(kms, true);
        let err = enclave.boot().await.expect_err("refused");
        assert!(format!("{err}").contains("choose one"), "{err}");
        assert_eq!(enclave.stored_did().await, None);
    }

    /// Without `vta_did_webs` a boot is what it was: the template's did:webvh.
    #[tokio::test]
    async fn without_vta_did_webs_first_boot_is_unchanged() {
        let enclave = Enclave::new(
            serde_json::json!({
                "region": "eu-west-1",
                "key_arn": "unused-in-did-generation",
                "vta_did_template": "did:webvh:{SCID}:identity.example.com:vta",
            }),
            true,
        );
        let did = enclave.boot().await.unwrap().vta_did.unwrap();
        assert!(did.starts_with("did:webvh:"), "{did}");
        let webs_ks = enclave.keyspace(crate::keyspaces::WEBS);
        assert!(crate::webs_store::list(&webs_ks).await.unwrap().is_empty());
    }
}
