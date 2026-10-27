//! Where each did:scid identity this community has verified was found, and the
//! latest version it verified (VTI-KEY-162).
//!
//! A did:scid identity is the bare `did:scid:vh:1:<scid>`; its `?src=` is only
//! a locator (VTI-KEY-160). Members, administrators and peers are recorded by
//! the bare DID, so after a restart the resolver could not resolve one again
//! until it next presented its `src` — and could not refuse a former host
//! serving its log as it stood before a move. The rows here are
//! [`vti_common::scid_floors`] records (sources and version floor) in the
//! `members` keyspace, so they are backed up with the members they locate.
//! Every proof this community verifies under a did:scid DID URL with `src`
//! records that source; the resolver's own records are persisted for members
//! and administrators as they change ([`spawn`]); boot seeds the resolver from
//! them ([`seed`]).
//!
//! Rows written before floors existed (`scid_source:` holding only a DID URL)
//! are migrated at boot.

use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde::Deserialize;
use tokio::sync::watch;
use tracing::{info, warn};
use vti_common::error::AppError;
use vti_common::scid_floors::{self, ScidSourceRecord};
use vti_common::store::KeyspaceHandle;

/// The rows written before floors existed.
const LEGACY_PREFIX: &str = "scid_source:";

/// How often the resolver's records are swept into the store, beside the
/// writes made as they change.
const SWEEP_EVERY: Duration = Duration::from_secs(300);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacySource {
    did_url: String,
}

/// Record the source of a did:scid DID URL just verified. Returns whether a row
/// was written: `false` for anything but a did:scid with `src`, and for a
/// source already recorded as the most recent.
pub async fn record(ks: &KeyspaceHandle, did_url: &str) -> Result<bool, AppError> {
    let did_url = did_url.split('#').next().unwrap_or(did_url);
    let Some(src) = vta_sdk::did_scid::src(did_url).filter(|_| vta_sdk::did_scid::is_scid(did_url))
    else {
        return Ok(false);
    };
    let bare = vta_sdk::did_scid::identity(did_url);
    if scid_floors::get(ks, &bare)
        .await?
        .is_some_and(|held| held.sources.first().map(String::as_str) == Some(src))
    {
        return Ok(false);
    }
    scid_floors::store(
        ks,
        &ScidSourceRecord {
            did: bare,
            sources: vec![src.to_string()],
            version: None,
        },
    )
    .await
}

/// [`record`], logging rather than failing: a source not recorded costs a
/// re-presentation after a restart, never the request in hand.
pub async fn record_best_effort(ks: &KeyspaceHandle, did_url: &str) {
    if let Err(e) = record(ks, did_url).await {
        warn!(did = %did_url, error = %e, "did:scid source not recorded");
    }
}

/// The DID URL of the most recent source recorded for a did:scid identity, by
/// its bare DID or any DID URL of it.
pub async fn source_of(ks: &KeyspaceHandle, did: &str) -> Result<Option<String>, AppError> {
    let bare = vta_sdk::did_scid::identity(did);
    Ok(scid_floors::get(ks, &bare)
        .await?
        .and_then(|record| record.sources.into_iter().next())
        .map(|src| format!("{bare}?src={src}")))
}

/// Move rows written before floors existed into floor records. Idempotent: a
/// migrated row is removed only after its record is written. Returns how many
/// were migrated.
async fn migrate_legacy(ks: &KeyspaceHandle) -> Result<usize, AppError> {
    let mut migrated = 0;
    for (key, raw) in ks
        .prefix_iter_raw(LEGACY_PREFIX.as_bytes().to_vec())
        .await?
    {
        match serde_json::from_slice::<LegacySource>(&raw) {
            Ok(row) => {
                record(ks, &row.did_url).await?;
                ks.remove(key).await?;
                migrated += 1;
            }
            Err(e) => warn!(error = %e, "unreadable legacy did:scid source row left in place"),
        }
    }
    Ok(migrated)
}

/// Seed `resolver`'s did:scid source book from every recorded row — sources and
/// version floor — so a did:scid this community verified before resolves by
/// its bare DID after a restart, and an older log of it is refused. Migrates
/// legacy rows first. Returns how many were seeded.
pub async fn seed(ks: &KeyspaceHandle, resolver: &DIDCacheClient) -> Result<usize, AppError> {
    let migrated = migrate_legacy(ks).await?;
    if migrated > 0 {
        info!(
            migrated,
            "legacy did:scid source rows migrated to version floors"
        );
    }
    scid_floors::seed(ks, resolver).await
}

/// Persist the resolver's did:scid records for every identity this community
/// grants standing to — a member, or an ACL entry's subject — as they change
/// and on a sweep, until `shutdown`.
pub fn spawn(
    members_ks: KeyspaceHandle,
    acl_ks: KeyspaceHandle,
    resolver: DIDCacheClient,
    shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let ks = members_ks.clone();
    let authorised: scid_floors::Authorised = Arc::new(move |did: String| {
        let members_ks = members_ks.clone();
        let acl_ks = acl_ks.clone();
        Box::pin(async move {
            matches!(
                crate::members::storage::get_member(&members_ks, &did).await,
                Ok(Some(_))
            ) || matches!(
                crate::acl::storage::get_acl_entry(&acl_ks, &did).await,
                Ok(Some(_))
            )
        })
    });
    scid_floors::spawn(ks, resolver, authorised, shutdown, SWEEP_EVERY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_did_resolver_cache_sdk::{
        config::DIDCacheConfigBuilder, network_resolvers::HostPolicy,
    };
    use didwebvh_rs::prelude::*;
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn open_ks() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace(crate::store::keyspaces::MEMBERS).unwrap();
        (dir, ks)
    }

    async fn resolver() -> DIDCacheClient {
        DIDCacheClient::new(
            DIDCacheConfigBuilder::default()
                .with_host_policy(HostPolicy::AllowPrivate)
                .build(),
        )
        .await
        .unwrap()
    }

    /// A signed did:webvh log, listing its did:scid alias, served at the mock
    /// server's root; returns its did:scid DID URL.
    async fn serve_member(server: &MockServer) -> String {
        let port = server.address().port();
        let (_, key) = didwebvh_rs::did_key::generate_did_key(KeyType::Ed25519).unwrap();
        let pk = key.get_public_keymultibase().unwrap();
        let config = CreateDIDConfig::builder()
            .address(format!("http://localhost:{port}/"))
            .authorization_key(key)
            .did_document(json!({
                "id": "{DID}",
                "@context": ["https://www.w3.org/ns/did/v1"],
                "verificationMethod": [{ "id": "{DID}#key-0", "type": "Multikey",
                    "controller": "{DID}", "publicKeyMultibase": pk }],
                "authentication": ["{DID}#key-0"],
            }))
            .parameters(Parameters {
                update_keys: Some(Arc::new(vec![Multibase::new(pk)])),
                ..Default::default()
            })
            .also_known_as_scid(true)
            .build()
            .unwrap();
        let created = create_did(config).await.unwrap();
        Mock::given(method("GET"))
            .and(path("/.well-known/did.jsonl"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(serde_json::to_string(created.log_entry()).unwrap()),
            )
            .mount(server)
            .await;
        vta_sdk::did_scid::scid_forms(created.did()).unwrap().1
    }

    /// VTI-KEY-162: a member verified through its `src` before a restart
    /// resolves by its bare DID after one, from the seeded source — and does not
    /// without it.
    #[tokio::test]
    async fn a_bare_member_did_resolves_after_a_restart() {
        let server = MockServer::start().await;
        let url = serve_member(&server).await;
        let bare = vta_sdk::did_scid::identity(&url);
        let (_dir, ks) = open_ks();

        // Before the restart: verified through its src, and recorded.
        resolver()
            .await
            .resolve(&url)
            .await
            .expect("resolves with src");
        assert!(record(&ks, &format!("{url}#key-0")).await.unwrap());

        // After: a fresh resolver knows no source until seeded.
        let cold = resolver().await;
        assert!(cold.resolve(&bare).await.is_err());

        let warm = resolver().await;
        assert_eq!(seed(&ks, &warm).await.unwrap(), 1);
        let doc = warm
            .resolve(&bare)
            .await
            .expect("bare DID resolves from the seed");
        assert_eq!(doc.doc.id.as_str(), bare);
    }

    #[tokio::test]
    async fn legacy_rows_are_migrated_and_seeded() {
        let (_dir, ks) = open_ks();
        ks.insert(
            format!("{LEGACY_PREFIX}did:scid:vh:1:QmOld"),
            &serde_json::json!({ "didUrl": "did:scid:vh:1:QmOld?src=old.example/m" }),
        )
        .await
        .unwrap();
        let booted = resolver().await;
        assert_eq!(seed(&ks, &booted).await.unwrap(), 1);
        assert!(
            ks.prefix_iter_raw(LEGACY_PREFIX.as_bytes().to_vec())
                .await
                .unwrap()
                .is_empty(),
            "the legacy row is gone"
        );
        assert_eq!(
            source_of(&ks, "did:scid:vh:1:QmOld")
                .await
                .unwrap()
                .as_deref(),
            Some("did:scid:vh:1:QmOld?src=old.example/m")
        );
        assert_eq!(
            booted
                .scid_sources()
                .source("did:scid:vh:1:QmOld")
                .as_deref(),
            Some("old.example/m")
        );
        // A second boot finds nothing left to migrate.
        assert_eq!(seed(&ks, &resolver().await).await.unwrap(), 1);
    }

    /// VTI-KEY-162: a portable member log that moved hosts. After a restart,
    /// the former host serving the log as it stood before the move is refused
    /// from the persisted floor alone — the new host being unreachable then.
    #[tokio::test]
    async fn a_pre_move_log_is_refused_after_a_restart() {
        use didwebvh_rs::update::{UpdateDIDConfig, update_did};

        let old = MockServer::start().await;
        let new = MockServer::start().await;
        let (_, key) = didwebvh_rs::did_key::generate_did_key(KeyType::Ed25519).unwrap();
        let pk = key.get_public_keymultibase().unwrap();
        let template = format!("did:webvh:{{SCID}}:localhost%3A{}", old.address().port());
        let doc = json!({
            "id": template,
            "@context": ["https://www.w3.org/ns/did/v1"],
            "verificationMethod": [{ "id": format!("{template}#key-0"), "type": "Multikey",
                "controller": template, "publicKeyMultibase": pk }],
            "authentication": [format!("{template}#key-0")],
        });
        let params = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(pk)])),
            portable: Some(true),
            ..Default::default()
        };
        let start = (chrono::Utc::now() - chrono::Duration::seconds(100)).fixed_offset();
        let mut state = DIDWebVHState::default();
        state
            .create_log_entry(Some(start), &doc, &params, &key)
            .await
            .unwrap();
        let jsonl = |state: &DIDWebVHState| {
            state
                .log_entries()
                .iter()
                .map(|e| serde_json::to_string(&e.log_entry).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        };
        Mock::given(method("GET"))
            .and(path("/.well-known/did.jsonl"))
            .respond_with(ResponseTemplate::new(200).set_body_string(jsonl(&state)))
            .mount(&old)
            .await;
        let webvh = state.log_entries()[0].log_entry.get_did_document().unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let bare = vta_sdk::did_scid::identity(&vta_sdk::did_scid::scid_forms(&webvh).unwrap().1);

        let moved = update_did(
            UpdateDIDConfig::builder()
                .state(state)
                .signing_key(key)
                .migrate_to(format!("http://localhost:{}/", new.address().port()))
                .build()
                .unwrap(),
        )
        .await
        .unwrap();
        Mock::given(method("GET"))
            .and(path("/.well-known/did.jsonl"))
            .respond_with(ResponseTemplate::new(200).set_body_string(jsonl(moved.state())))
            .mount(&new)
            .await;

        // Before the restart: the member resolved at its new host, and the
        // resolver's record persisted.
        let (_dir, ks) = open_ks();
        let before = resolver().await;
        before
            .resolve(&format!("{bare}?src=localhost:{}", new.address().port()))
            .await
            .expect("the current log resolves");
        let record = before.scid_sources().record(&bare).unwrap();
        assert_eq!(record.version.as_ref().unwrap().number, 2);
        vti_common::scid_floors::store(&ks, &record).await.unwrap();

        // After it, with the new host gone.
        drop(new);
        let after = resolver().await;
        assert_eq!(seed(&ks, &after).await.unwrap(), 1);
        let error = after
            .resolve(&format!("{bare}?src=localhost:{}", old.address().port()))
            .await
            .expect_err("the pre-move log is behind the persisted floor");
        assert!(error.to_string().contains("behind"), "{error}");
    }

    #[tokio::test]
    async fn a_newer_source_replaces_the_recorded_one() {
        let (_dir, ks) = open_ks();
        let first = "did:scid:vh:1:QmScid?src=a.example/m";
        let moved = "did:scid:vh:1:QmScid?src=b.example/m";
        assert!(record(&ks, first).await.unwrap());
        assert!(
            !record(&ks, first).await.unwrap(),
            "unchanged: nothing written"
        );
        assert!(record(&ks, moved).await.unwrap());
        assert_eq!(
            source_of(&ks, "did:scid:vh:1:QmScid")
                .await
                .unwrap()
                .as_deref(),
            Some(moved)
        );
        for not_a_source in [
            "did:scid:vh:1:QmScid",
            "did:webvh:QmScid:a.example",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        ] {
            assert!(!record(&ks, not_a_source).await.unwrap(), "{not_a_source}");
        }
        // Not a member row: a member listing never sees it.
        assert!(
            crate::members::storage::list_members(&ks)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
