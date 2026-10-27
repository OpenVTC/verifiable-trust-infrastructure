//! Durable did:scid version floors for the identities this VTA authorises
//! (VTI-KEY-162).
//!
//! A did:scid ACL subject is recorded by its bare DID. The resolver's source
//! book knows where its log was found and the latest version verified; this
//! keeps that across a restart, as [`vti_common::scid_floors`] rows in the
//! `acl` keyspace (beside the `acl:` entries, which [`list_acl_entries`] reads
//! by prefix), so a former host serving a moved log as it stood before the move
//! is refused from the first request after one. The VTA's own did:scid
//! identities need none of this: their logs are held locally and preloaded.
//!
//! [`list_acl_entries`]: vti_common::acl::list_acl_entries

use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use tokio::sync::watch;
use vti_common::scid_floors::{self, Authorised};
use vti_common::store::KeyspaceHandle;

/// How often the resolver's records are swept into the store, beside the
/// writes made as they change.
const SWEEP_EVERY: Duration = Duration::from_secs(300);

/// An identity this VTA authorises: the subject of an ACL entry.
pub fn authorised_by_acl(acl_ks: KeyspaceHandle) -> Authorised {
    Arc::new(move |did: String| {
        let acl_ks = acl_ks.clone();
        Box::pin(async move {
            matches!(
                vti_common::acl::get_acl_entry(&acl_ks, &did).await,
                Ok(Some(_))
            )
        })
    })
}

/// Persist the resolver's did:scid records for every ACL subject, as they
/// change and on a sweep, until `shutdown`.
pub fn spawn(
    acl_ks: KeyspaceHandle,
    resolver: DIDCacheClient,
    shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    scid_floors::spawn(
        acl_ks.clone(),
        resolver,
        authorised_by_acl(acl_ks),
        shutdown,
        SWEEP_EVERY,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    use vti_common::acl::{AclEntry, Role, store_acl_entry};

    fn open_acl() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::ACL).unwrap();
        (dir, ks)
    }

    async fn resolver() -> DIDCacheClient {
        DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap()
    }

    /// VTI-KEY-162: an ACL subject's did:scid source is persisted; a stranger's
    /// is not; the next boot seeds it back; the row is not an ACL entry.
    #[tokio::test]
    async fn an_acl_subjects_did_scid_floor_survives_a_restart() {
        let (_dir, acl) = open_acl();
        let admin = "did:scid:vh:1:QmAdmin";
        store_acl_entry(&acl, &AclEntry::new(admin, Role::Admin, "test"))
            .await
            .unwrap();

        let before = resolver().await;
        let (stop, shutdown) = watch::channel(false);
        let task = spawn(acl.clone(), before.clone(), shutdown);
        let book = before.scid_sources();
        assert!(book.add_source(&format!("{admin}?src=admin.example/vta")));
        assert!(book.add_source("did:scid:vh:1:QmStranger?src=elsewhere.example"));
        stop.send(true).unwrap();
        task.await.unwrap();

        assert!(
            vti_common::scid_floors::get(&acl, admin)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            vti_common::scid_floors::get(&acl, "did:scid:vh:1:QmStranger")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            vti_common::acl::list_acl_entries(&acl).await.unwrap().len(),
            1,
            "a floor row is not an ACL entry"
        );

        let after = resolver().await;
        assert_eq!(
            vti_common::scid_floors::seed(&acl, &after).await.unwrap(),
            1
        );
        assert_eq!(
            after.scid_sources().source(admin).as_deref(),
            Some("admin.example/vta")
        );
    }
}
