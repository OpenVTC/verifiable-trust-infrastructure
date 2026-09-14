//! Persist the auto-generated serverless VTA did:webvh identity into the
//! `webvh` keyspace.
//!
//! In TEE mode [`vta_tee::did_autogen::maybe_generate_vta_did`] mints the VTA's
//! own did:webvh from the KMS-bootstrapped seed and stores the DID + did.jsonl
//! log under the `KEYS` / `BOOTSTRAP` keyspaces (`tee:vta_did`, `tee:did_log`).
//! It does *not* go through [`crate::operations::did_webvh`]'s create flow, so
//! the `webvh` keyspace — which `list_services`, the self-DID resolver preload
//! ([`crate::server`]'s `preload_self_did_document`) and
//! `/.well-known/did.jsonl` all read via [`crate::webvh_store`] — is left
//! empty. `GET /services` then 500s with `VtaDidRecordMissing` and the VTA's
//! own DID is unresolvable, so no client can authcrypt to it.
//!
//! This module bridges that gap: after auto-generation it idempotently
//! backfills the `webvh` keyspace with the DID *record* (`did:{did}`) and *log*
//! (`log:{did}`) so those read paths work on both fresh generation and restore,
//! without going through the full create flow (which would try to publish to a
//! hosting server the serverless VTA doesn't have).

use tracing::info;

use vta_sdk::webvh::WebvhDidRecord;
use vti_common::error::AppError;

use crate::store::{KeyspaceHandle, Store};
use crate::webvh_store;

/// The `KEYS`-keyspace key that `vta_tee::did_autogen` writes the encrypted
/// did.jsonl log under.
///
/// Taken from the writer rather than re-typed: this module is `cfg(tee)` and
/// `crate::tee` is already `pub use vta_tee`, so there is no dependency to
/// avoid — only a literal to keep in sync, which is the failure mode.
use crate::tee::did_autogen::DID_LOG_STORE_KEY as TEE_DID_LOG_STORE_KEY;

/// Idempotently persist the serverless VTA did:webvh record + log into the
/// `webvh` keyspace.
///
/// No-op for non-`did:webvh` identities and whenever the records are already
/// present, so it is safe to call unconditionally on every boot after DID
/// auto-generation — a rebuild + reboot repairs an already-generated DID
/// without wiping state (which would rotate the DID).
pub async fn backfill_serverless_webvh_identity(
    store: &Store,
    storage_encryption_key: Option<[u8; 32]>,
    vta_did: &str,
) -> Result<(), AppError> {
    // Only serverless did:webvh identities live in the webvh keyspace.
    if !vta_did.starts_with("did:webvh:") {
        return Ok(());
    }

    let with_enc = |ks: KeyspaceHandle| match storage_encryption_key {
        Some(key) => ks.with_encryption(key),
        None => ks,
    };
    let webvh_ks = with_enc(store.keyspace(crate::keyspaces::WEBVH)?);

    let mut persisted = false;

    // Log (`log:{did}`): copy the did.jsonl the autogen wrote under the `KEYS`
    // keyspace. Read by the resolver preload, `list_services`, and well-known.
    if webvh_store::get_did_log(&webvh_ks, vta_did)
        .await?
        .is_none()
    {
        let keys_ks = with_enc(store.keyspace(crate::keyspaces::KEYS)?);
        if let Some(bytes) = keys_ks.get_raw(TEE_DID_LOG_STORE_KEY).await? {
            let log_content = String::from_utf8(bytes).map_err(|e| {
                AppError::Internal(format!("corrupt stored VTA did.jsonl log: {e}"))
            })?;
            webvh_store::store_did_log(&webvh_ks, vta_did, &log_content).await?;
            persisted = true;
        }
    }

    // Record (`did:{did}`): required by `list_services` and the did
    // update/rotate ops via `webvh_store::get_did`.
    if webvh_store::get_did(&webvh_ks, vta_did).await?.is_none() {
        let record = build_serverless_webvh_record(vta_did);
        webvh_store::store_did(&webvh_ks, &record).await?;
        persisted = true;
    }

    if persisted {
        store.persist().await?;
        info!(
            did = %vta_did,
            "backfilled serverless webvh DID record + log into the webvh keyspace"
        );
    }

    Ok(())
}

/// Build the [`WebvhDidRecord`] for the auto-generated serverless VTA DID.
///
/// Mirrors the production serverless builder in
/// `operations::did_webvh::create_did_webvh`: `create` mints `#key-0`
/// (signing) and `#key-1` (key-agreement) so the next `#key-{n}` fragment is
/// `2`, and TEE autogen commits exactly one pre-rotation key. Any drift is
/// self-healing — the next did update/rotate re-scans the log and persists the
/// corrected `log_entry_count` / `pre_rotation_count` / `next_fragment_id`.
fn build_serverless_webvh_record(did: &str) -> WebvhDidRecord {
    // did:webvh:{SCID}:{host}… — the SCID is the third colon-segment.
    let scid = did.split(':').nth(2).unwrap_or_default().to_string();
    let now = chrono::Utc::now();
    WebvhDidRecord {
        did: did.to_string(),
        server_id: "serverless".to_string(),
        mnemonic: String::new(),
        scid,
        context_id: "vta".to_string(),
        portable: true,
        log_entry_count: 1,
        pre_rotation_count: 1,
        next_fragment_id: 2,
        created_at: now,
        updated_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use didwebvh_rs::log_entry::LogEntryMethods;
    use vta_sdk::protocol::matching::ServiceCapabilities;
    use vta_tee::did_autogen::maybe_generate_vta_did;

    use crate::operations::did_webvh::state_from_jsonl_pub;
    use crate::test_support::{TestSeedStore, test_app_config};

    const STORAGE_KEY: [u8; 32] = [42; 32];
    const PUBLIC_URL: &str = "https://api.example.com:8443/tenant/vta/";

    struct AutogenFixture {
        _dir: tempfile::TempDir,
        store: Store,
        config: vta_config::AppConfig,
        seed: TestSeedStore,
    }

    impl AutogenFixture {
        async fn new(rest: bool, public_url: Option<&str>, embed: bool) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let mut config = test_app_config(dir.path().into());
            config.services.rest = rest;
            config.public_url = public_url.map(str::to_owned);
            config.tee.embed_in_did = embed;
            config.tee.kms = Some(
                serde_json::from_value(serde_json::json!({
                    "region": "ap-southeast-1",
                    "key_arn": "unused-in-did-generation",
                    "vta_did_template": "did:webvh:{SCID}:identity.example.com:logs:vta"
                }))
                .unwrap(),
            );
            let store = Store::open(&config.store).unwrap();
            let seed = TestSeedStore(vec![7; 64]);
            maybe_generate_vta_did(&mut config, &seed, &store, Some(STORAGE_KEY))
                .await
                .unwrap();
            backfill_serverless_webvh_identity(
                &store,
                Some(STORAGE_KEY),
                config.vta_did.as_deref().unwrap(),
            )
            .await
            .unwrap();
            Self {
                _dir: dir,
                store,
                config,
                seed,
            }
        }

        fn keyspace(&self, name: &str) -> KeyspaceHandle {
            self.store
                .keyspace(name)
                .unwrap()
                .with_encryption(STORAGE_KEY)
        }

        async fn log(&self) -> String {
            webvh_store::get_did_log(
                &self.keyspace(crate::keyspaces::WEBVH),
                self.config.vta_did.as_deref().unwrap(),
            )
            .await
            .unwrap()
            .unwrap()
        }
    }

    fn verified_document(log: &str) -> serde_json::Value {
        let state = state_from_jsonl_pub(log).expect("SCID and signed chain must validate");
        state
            .log_entries()
            .last()
            .unwrap()
            .log_entry
            .get_state()
            .clone()
    }

    #[tokio::test]
    async fn tee_generated_log_supports_bootstrap_rest_discovery() {
        for (rest, url, embed, expected) in [
            (true, Some(PUBLIC_URL), true, Some(PUBLIC_URL)),
            (true, Some(PUBLIC_URL), false, Some(PUBLIC_URL)),
            (
                true,
                Some("  https://api.example.com:8443/vta/  "),
                false,
                Some("https://api.example.com:8443/vta/"),
            ),
            // Same padded value with the attestation service on: both
            // endpoints must read the trimmed URL, not one each way.
            (
                true,
                Some("  https://api.example.com:8443/vta/  "),
                true,
                Some("https://api.example.com:8443/vta/"),
            ),
            (false, Some(PUBLIC_URL), true, None),
            (true, None, false, None),
            (true, Some("  "), false, None),
        ] {
            let fx = AutogenFixture::new(rest, url, embed).await;
            let log = fx.log().await;
            let doc = verified_document(&log);
            assert_eq!(doc["id"].as_str(), fx.config.vta_did.as_deref());
            // This is the exact service-by-type discovery used by PNM connect,
            // not a synthetic document with a hand-injected REST endpoint.
            let endpoint = ServiceCapabilities::from_did_document(&doc).rest;
            assert_eq!(endpoint.as_deref(), expected);
            if let Some(endpoint) = endpoint {
                vta_sdk::http::guard_vta_endpoint(
                    &endpoint,
                    vta_sdk::http::EndpointPolicy::public_only(),
                )
                .unwrap();
            }
            // Whatever else it advertises must be callable too — a service
            // built from an untrimmed `public_url` is not.
            for svc in doc["service"].as_array().into_iter().flatten() {
                let advertised = svc["serviceEndpoint"].as_str().unwrap_or_default();
                assert_eq!(advertised.trim(), advertised, "{svc}");
            }
            for ks in [
                fx.keyspace(crate::keyspaces::KEYS),
                fx.store.keyspace(crate::keyspaces::BOOTSTRAP).unwrap(),
            ] {
                assert_eq!(
                    ks.get_raw(TEE_DID_LOG_STORE_KEY).await.unwrap().unwrap(),
                    log.as_bytes()
                );
            }
        }
    }

    #[tokio::test]
    async fn tee_existing_identity_rest_repair_appends_signed_update() {
        use crate::operations::did_webvh::{
            UpdateDidWebvhOptions, WebvhAuthLocks, WebvhDeps, update_did_webvh,
        };
        use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
        use std::sync::Arc;

        // Generate the legacy no-REST shape by leaving public_url unset.
        // Never edit a signed genesis to construct (or repair) this fixture.
        let mut fx = AutogenFixture::new(true, None, false).await;
        let genesis = fx.log().await;
        let original = verified_document(&genesis);
        assert!(
            ServiceCapabilities::from_did_document(&original)
                .rest
                .is_none()
        );
        let did = fx.config.vta_did.clone().unwrap();
        fx.config.public_url = Some(PUBLIC_URL.into());
        maybe_generate_vta_did(&mut fx.config, &fx.seed, &fx.store, Some(STORAGE_KEY))
            .await
            .unwrap();
        assert_eq!(fx.log().await, genesis, "reboot must not rewrite genesis");
        assert_eq!(
            fx.keyspace(crate::keyspaces::KEYS)
                .get_raw(TEE_DID_LOG_STORE_KEY)
                .await
                .unwrap()
                .unwrap(),
            genesis.as_bytes(),
        );

        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let bridge = Arc::new(crate::didcomm_bridge::DIDCommBridge::placeholder());
        let locks = WebvhAuthLocks::new();
        let audit = vta_audit::shared_keyspace_sink(fx.keyspace(crate::keyspaces::AUDIT));
        let deps = WebvhDeps {
            keys_ks: &fx.keyspace(crate::keyspaces::KEYS),
            imported_ks: &fx.keyspace(crate::keyspaces::IMPORTED_SECRETS),
            contexts_ks: &fx.keyspace(crate::keyspaces::CONTEXTS),
            webvh_ks: &fx.keyspace(crate::keyspaces::WEBVH),
            delete_cascade: None,
            audit: &audit,
            seed_store: &fx.seed,
            did_resolver: &resolver,
            didcomm_bridge: &bridge,
            auth_locks: &locks,
        };
        // The same document patch + signed update engine as services rest enable.
        let patched =
            crate::operations::protocol::document::with_rest_service(original.clone(), PUBLIC_URL)
                .unwrap();
        // No sleep: even a repair immediately after TEE genesis must validate.
        let result = update_did_webvh(
            &deps,
            &crate::test_support::super_admin_claims(),
            &did,
            UpdateDidWebvhOptions {
                document: Some(patched),
                ..Default::default()
            },
            Some(&did),
            "test",
        )
        .await
        .unwrap();
        assert!(result.new_version_id.starts_with("2-"));
        let updated_log = fx.log().await;
        assert_eq!(updated_log.lines().count(), 2);
        assert_eq!(updated_log.lines().next(), genesis.lines().next());
        let updated = verified_document(&updated_log);
        assert_eq!(updated["id"], original["id"]);
        assert_eq!(
            updated["verificationMethod"],
            original["verificationMethod"]
        );
        assert_eq!(
            ServiceCapabilities::from_did_document(&updated)
                .rest
                .as_deref(),
            Some(PUBLIC_URL)
        );

        backfill_serverless_webvh_identity(&fx.store, Some(STORAGE_KEY), &did)
            .await
            .unwrap();
        assert_eq!(
            fx.log().await,
            updated_log,
            "backfill must not restore the older genesis"
        );
    }

    #[test]
    fn record_scid_is_third_colon_segment() {
        let record = build_serverless_webvh_record("did:webvh:QmScidValue:example.com:vta");
        assert_eq!(record.scid, "QmScidValue");
        assert_eq!(record.did, "did:webvh:QmScidValue:example.com:vta");
        assert_eq!(record.server_id, "serverless");
        assert_eq!(record.next_fragment_id, 2);
        assert_eq!(record.pre_rotation_count, 1);
        assert_eq!(record.log_entry_count, 1);
        assert!(record.portable);
    }
}
