//! Durable did:scid version floors (VTI-KEY-162).
//!
//! A did:scid identity is the bare `did:scid:vh:1:<scid>`; the `?src=` a peer
//! presents is its own choice (VTI-KEY-160). did:webvh verification binds each
//! log entry to the host its own DID names, so a host the log never named
//! cannot serve it — but a portable log that has moved still names its former
//! host in its early entries, and whoever holds that host can serve the log as
//! it stood before the move, with keys its controller has since rotated away.
//! The resolver's [`ScidSourceBook`](affinidi_did_resolver_cache_sdk::network_resolvers::ScidSourceBook)
//! refuses a log older than one it has verified, and checks an unknown source
//! against the known ones; this module makes what it knows survive a restart
//! for every did:scid identity a node grants authority to.
//!
//! Records are rows `scid_floor:<bare did>` in a keyspace the caller chooses,
//! holding a [`ScidSourceRecord`]. A write merges with the row already there
//! and never lowers its version. [`seed`] loads them into a resolver at boot;
//! [`spawn`] persists the resolver's records as they change — through its
//! listener, and by a periodic sweep that also catches an identity resolved
//! before it was authorised — for the identities `authorised` accepts.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
pub use affinidi_did_resolver_cache_sdk::network_resolvers::{ScidSourceRecord, ScidVersion};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Row prefix, clear of any other prefix a keyspace holding these uses.
pub const PREFIX: &str = "scid_floor:";

/// How many sources a row keeps, matching the resolver's book.
const MAX_SOURCES: usize = 4;

/// How many records the listener may queue for the writer before it drops one
/// (and says so). The listener runs on resolving tasks and must not block.
const QUEUE: usize = 1024;

/// Whether a node grants authority to the did:scid identity with this bare DID,
/// and so must keep its floor across a restart.
pub type Authorised =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>;

fn key(bare: &str) -> String {
    format!("{PREFIX}{bare}")
}

/// The bare DID of a record's `did`, whatever form it was given in.
fn bare(did: &str) -> String {
    let did = vta_sdk::did_scid::identity(did);
    did.split('#').next().unwrap_or(&did).to_string()
}

/// Merge `incoming` into `current`: incoming sources first, the version that is
/// further along. Returns `None` when nothing would change.
fn merge(
    current: Option<ScidSourceRecord>,
    incoming: &ScidSourceRecord,
) -> Option<ScidSourceRecord> {
    let did = bare(&incoming.did);
    let mut merged = ScidSourceRecord {
        did: did.clone(),
        sources: incoming.sources.clone(),
        version: incoming.version.clone(),
    };
    if let Some(current) = &current {
        for src in &current.sources {
            if !merged.sources.contains(src) {
                merged.sources.push(src.clone());
            }
        }
        merged.version = match (&current.version, &incoming.version) {
            (Some(c), Some(i)) if c.number >= i.number => Some(c.clone()),
            (Some(c), None) => Some(c.clone()),
            (_, i) => i.clone(),
        };
    }
    merged.sources.truncate(MAX_SOURCES);
    (current.as_ref() != Some(&merged)).then_some(merged)
}

/// Persist `record`, merged with the row already held for its identity, so a
/// floor is never lowered. Returns whether a row was written.
pub async fn store(ks: &KeyspaceHandle, record: &ScidSourceRecord) -> Result<bool, AppError> {
    if !record.did.starts_with("did:scid:") {
        return Ok(false);
    }
    let did = bare(&record.did);
    let current: Option<ScidSourceRecord> = ks.get(key(&did)).await?;
    match merge(current, record) {
        Some(merged) => {
            ks.insert(key(&did), &merged).await?;
            debug!(did = %did, version = ?merged.version.as_ref().map(|v| v.number), "did:scid floor persisted");
            Ok(true)
        }
        None => Ok(false),
    }
}

/// The record held for the identity of `did`.
pub async fn get(ks: &KeyspaceHandle, did: &str) -> Result<Option<ScidSourceRecord>, AppError> {
    ks.get(key(&bare(did))).await
}

/// Every record held. An unreadable row is skipped with a warning.
pub async fn load(ks: &KeyspaceHandle) -> Result<Vec<ScidSourceRecord>, AppError> {
    let mut records = Vec::new();
    for (_key, raw) in ks.prefix_iter_raw(PREFIX.as_bytes().to_vec()).await? {
        match serde_json::from_slice::<ScidSourceRecord>(&raw) {
            Ok(record) => records.push(record),
            Err(e) => warn!(error = %e, "unreadable did:scid floor row skipped"),
        }
    }
    Ok(records)
}

/// Seed `resolver`'s did:scid source book with every persisted record, so the
/// identities this node authorises resolve by their bare DID, and refuse an
/// older log, from the first request after a restart. Returns how many were
/// seeded.
pub async fn seed(ks: &KeyspaceHandle, resolver: &DIDCacheClient) -> Result<usize, AppError> {
    let book = resolver.scid_sources();
    Ok(load(ks).await?.iter().filter(|r| book.seed(r)).count())
}

/// Persist every record in `resolver`'s book whose identity `authorised`
/// accepts. Returns how many rows were written.
pub async fn sweep(
    ks: &KeyspaceHandle,
    resolver: &DIDCacheClient,
    authorised: &Authorised,
) -> usize {
    let mut written = 0;
    for record in resolver.scid_sources().records() {
        if authorised(record.did.clone()).await {
            match store(ks, &record).await {
                Ok(true) => written += 1,
                Ok(false) => {}
                Err(e) => warn!(did = %record.did, error = %e, "did:scid floor not persisted"),
            }
        }
    }
    written
}

/// Keep `ks` in step with `resolver`'s did:scid book for the identities
/// `authorised` accepts: each record the book changes is persisted as it
/// changes, and every `sweep_every` (and at shutdown) the whole book is swept,
/// which picks up an identity that was resolved before it was authorised.
///
/// Replaces any listener already set on the resolver's book. Ends when
/// `shutdown` turns `true`.
pub fn spawn(
    ks: KeyspaceHandle,
    resolver: DIDCacheClient,
    authorised: Authorised,
    mut shutdown: watch::Receiver<bool>,
    sweep_every: Duration,
) -> JoinHandle<()> {
    let (tx, mut rx) = mpsc::channel::<ScidSourceRecord>(QUEUE);
    resolver
        .scid_sources()
        .set_listener(Arc::new(move |record: &ScidSourceRecord| {
            if tx.try_send(record.clone()).is_err() {
                // The sweep persists it later; nothing is lost but timeliness.
                warn!(did = %record.did, "did:scid floor queue full; left to the next sweep");
            }
        }));
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(sweep_every);
        tick.tick().await;
        loop {
            tokio::select! {
                Some(record) = rx.recv() => {
                    if authorised(record.did.clone()).await
                        && let Err(e) = store(&ks, &record).await
                    {
                        warn!(did = %record.did, error = %e, "did:scid floor not persisted");
                    }
                }
                _ = tick.tick() => {
                    sweep(&ks, &resolver, &authorised).await;
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        sweep(&ks, &resolver, &authorised).await;
                        break;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_ks() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(&crate::config::StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace("acl").unwrap();
        (dir, ks)
    }

    fn at(number: u32, sources: &[&str]) -> ScidSourceRecord {
        ScidSourceRecord {
            did: "did:scid:vh:1:QmScid".into(),
            sources: sources.iter().map(|s| s.to_string()).collect(),
            version: Some(ScidVersion {
                number,
                id: format!("{number}-Qm"),
            }),
        }
    }

    #[tokio::test]
    async fn a_stored_floor_is_never_lowered() {
        let (_dir, ks) = open_ks();
        assert!(store(&ks, &at(5, &["b.example"])).await.unwrap());
        assert!(
            store(&ks, &at(3, &["a.example"])).await.unwrap(),
            "a new source is added"
        );
        let held = get(&ks, "did:scid:vh:1:QmScid?src=c.example")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(held.version.unwrap().number, 5);
        assert_eq!(held.sources, vec!["a.example", "b.example"]);
        assert!(
            !store(&ks, &at(5, &["a.example"])).await.unwrap(),
            "unchanged: nothing written"
        );
        assert!(store(&ks, &at(7, &["a.example"])).await.unwrap());
        assert_eq!(
            get(&ks, "did:scid:vh:1:QmScid")
                .await
                .unwrap()
                .unwrap()
                .version
                .unwrap()
                .number,
            7
        );
    }

    #[tokio::test]
    async fn only_did_scid_records_are_stored() {
        let (_dir, ks) = open_ks();
        let mut record = at(1, &["a.example"]);
        record.did = "did:webvh:QmScid:a.example".into();
        assert!(!store(&ks, &record).await.unwrap());
        assert!(load(&ks).await.unwrap().is_empty());
    }

    async fn resolver() -> DIDCacheClient {
        DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap()
    }

    async fn eventually(ks: &KeyspaceHandle, did: &str) -> Option<ScidSourceRecord> {
        for _ in 0..50 {
            if let Some(record) = get(ks, did).await.unwrap() {
                return Some(record);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    }

    /// The writer persists what the book learns, for authorised identities
    /// only; the sweep picks up one authorised after it was resolved; a seed
    /// at the next boot restores it.
    #[tokio::test]
    async fn the_writer_persists_authorised_identities_and_a_restart_reseeds_them() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let (_dir, ks) = open_ks();
        let live = resolver().await;
        let late = Arc::new(AtomicBool::new(false));
        let gate = late.clone();
        let authorised: Authorised = Arc::new(move |did: String| {
            let late = gate.load(Ordering::SeqCst);
            Box::pin(async move {
                did == "did:scid:vh:1:QmMember" || (late && did == "did:scid:vh:1:QmLater")
            })
        });
        let (stop, shutdown) = watch::channel(false);
        let task = spawn(
            ks.clone(),
            live.clone(),
            authorised,
            shutdown,
            Duration::from_secs(3600),
        );

        let book = live.scid_sources();
        assert!(book.add_source("did:scid:vh:1:QmMember?src=a.example/m"));
        assert!(book.add_source("did:scid:vh:1:QmStranger?src=b.example"));
        assert!(book.add_source("did:scid:vh:1:QmLater?src=c.example"));

        let held = eventually(&ks, "did:scid:vh:1:QmMember")
            .await
            .expect("persisted");
        assert_eq!(held.sources, vec!["a.example/m"]);
        assert!(
            get(&ks, "did:scid:vh:1:QmStranger")
                .await
                .unwrap()
                .is_none()
        );
        assert!(get(&ks, "did:scid:vh:1:QmLater").await.unwrap().is_none());

        // Authorised after it was resolved: the shutdown sweep keeps it.
        late.store(true, Ordering::SeqCst);
        stop.send(true).unwrap();
        task.await.unwrap();
        assert!(get(&ks, "did:scid:vh:1:QmLater").await.unwrap().is_some());
        assert!(
            get(&ks, "did:scid:vh:1:QmStranger")
                .await
                .unwrap()
                .is_none()
        );

        // The next boot.
        let restarted = resolver().await;
        assert_eq!(seed(&ks, &restarted).await.unwrap(), 2);
        assert_eq!(
            restarted
                .scid_sources()
                .source("did:scid:vh:1:QmMember")
                .as_deref(),
            Some("a.example/m")
        );
    }

    #[tokio::test]
    async fn rows_do_not_appear_as_acl_entries() {
        let (_dir, ks) = open_ks();
        store(&ks, &at(1, &["a.example"])).await.unwrap();
        assert!(crate::acl::list_acl_entries(&ks).await.unwrap().is_empty());
    }
}
