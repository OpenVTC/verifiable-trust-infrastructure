//! Room files on this community's host (`docs/05-design-notes/data-rooms-files.md` §5–§7):
//! the storage configs, the room-file host over them, its sweeper, and the limits
//! `rooms/info/0.5` advertises.
//!
//! The `rooms/blobs/*` tasks themselves are [`vti_rooms_host`], shared with `room-host` so
//! the two hosts cannot answer one task two ways.
//!
//! The VTC holds ciphertext only. A file's key is derived in the member's VTA and never
//! reaches a host, and nothing here could use one.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use vti_common::error::AppError;
use vti_common::store::Store;
use vti_rooms::blobs::BlobHost;

use super::storage_configs::RoomStorage;
use crate::config::RoomFilesConfig;
use crate::store::keyspaces;

/// Open this community's storage configs (`[rooms.files]`, §7): the `local` config is
/// seeded from `blob_dir` (default `<data_dir>/room-blobs`) on first start, and a
/// `local` root may be placed only beneath `local_storage_bases` (default
/// `<data_dir>/room-storage`).
///
/// With no `[rooms.files]` section (`None`) nothing is created or seeded: the registry
/// is opened over whatever configs are already stored, and room files stay off. That is
/// every configuration written before room files existed, and it must keep starting.
pub async fn open_room_storage(
    store: &Store,
    data_dir: &Path,
    config: Option<&RoomFilesConfig>,
    community_did: Option<&str>,
) -> Result<Arc<RoomStorage>, AppError> {
    let Some(config) = config else {
        return RoomStorage::open(
            store.keyspace(keyspaces::STORAGE_CONFIGS)?,
            &store.keyspace(keyspaces::ROOMS)?,
            None,
            Vec::new(),
            community_did,
        )
        .await;
    };
    // A storage config's `root` is absolute (`vtc/_shared/0.1/room-storage`), and a
    // relative `[store] data_dir` is ordinary, so a root derived from it, or a
    // `blob_dir` given relative, is resolved against the directory the store itself
    // was opened from. Left relative, the seeded config fails its own schema check
    // and the community does not start.
    let cwd = std::env::current_dir().map_err(AppError::Io)?;
    let seed_root = absolute_dir(
        config
            .blob_dir
            .clone()
            .unwrap_or_else(|| data_dir.join("room-blobs")),
        &cwd,
    )
    .await?;
    // Explicit bases stay as given: they must be absolute, and are refused otherwise.
    let bases = if config.local_storage_bases.is_empty() {
        vec![absolute_dir(data_dir.join("room-storage"), &cwd).await?]
    } else {
        config.local_storage_bases.clone()
    };
    let storage = RoomStorage::open(
        store.keyspace(keyspaces::STORAGE_CONFIGS)?,
        &store.keyspace(keyspaces::ROOMS)?,
        Some(seed_root),
        bases,
        community_did,
    )
    .await?;
    // Which modes beyond `vta-account` this host permits (`[rooms.files.auth]`; absent,
    // neither `ambient` nor `sealed`).
    storage.set_host_auth((&config.auth).into()).await?;
    Ok(storage)
}

/// `path` as an absolute directory: unchanged when it already is one, and otherwise
/// created beneath `cwd` and resolved, so it carries no `.` or `..`.
async fn absolute_dir(path: PathBuf, cwd: &Path) -> Result<PathBuf, AppError> {
    if path.is_absolute() {
        return Ok(path);
    }
    let joined = cwd.join(path);
    tokio::fs::create_dir_all(&joined)
        .await
        .map_err(AppError::Io)?;
    std::fs::canonicalize(&joined).map_err(AppError::Io)
}

/// Open the room-file host over this service's store, from `[rooms.files]`, storing
/// committed blobs in the configs `storage` holds. Staging sits under the data directory.
/// With no section, uploads are refused; files already stored are still served.
pub fn open_blob_host(
    store: &Store,
    data_dir: &Path,
    config: Option<&RoomFilesConfig>,
    storage: Arc<RoomStorage>,
) -> Result<BlobHost, AppError> {
    // Room registrations, renewals and holdings are written inside `vti_rooms`;
    // its hook feeds the console's live `rooms` topic (`crate::admin_events`).
    vti_rooms::observe::set_hook(crate::admin_events::notify_rooms);
    let limits = match config {
        Some(c) => c.limits(),
        None => vti_rooms::blobs::HostLimits {
            files_enabled: false,
            ..RoomFilesConfig::default().limits()
        },
    };
    Ok(BlobHost::new(
        store.keyspace(keyspaces::ROOM_BLOBS)?,
        store.keyspace(keyspaces::ROOM_BLOB_TRANSFERS)?,
        data_dir.join("room-blob-staging"),
        storage,
        limits,
    )
    .with_direct_transfer(config.map(|c| c.direct_transfer).unwrap_or_default()))
}

/// Collect deleted, orphaned-past-grace and abandoned files every `interval_secs`, and
/// retire each `draining` storage config once its last blob is gone.
pub(crate) fn spawn_sweeper(
    files: Arc<BlobHost>,
    storage: Arc<RoomStorage>,
    interval_secs: u64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let interval = std::time::Duration::from_secs(interval_secs.max(1));
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(interval) => {}
            }
            match files.sweep().await {
                Ok(stats) if stats.collected + stats.released + stats.forgotten > 0 => {
                    tracing::info!(
                        collected = stats.collected,
                        released = stats.released,
                        forgotten = stats.forgotten,
                        "room files swept"
                    );
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "room file sweep failed"),
            }
            let settled = match files.config_holdings().await {
                Ok(holdings) => storage.settle_draining(&holdings).await,
                Err(e) => Err(e),
            };
            if let Err(e) = settled {
                tracing::warn!(error = %e, "draining storage configs not settled");
            }
        }
    });
}

/// The limits this community advertises in `rooms/info/0.5` (trust-tasks-tf #1289).
///
/// - **`maxRecordDocumentBytes`**: the size gate's limit for the newest `rooms/records/put`
///   served ([`crate::trust_tasks::size::max_document_bytes`]). No served put version
///   declares `maxDocumentBytes`, so it is the spine's default, 65,536 bytes — below the
///   2,097,152 that put 0.6 declares, which is why it MUST be stated.
/// - **`maxChunkSize`**: an upload chunk is admitted at its own size, charged to the room's
///   transfer budget on every transport (#2515), so the transfer ceiling.
pub(crate) fn host_limits() -> vti_rooms::signal_delay::HostLimits {
    vti_rooms::signal_delay::HostLimits {
        max_record_document_bytes: Some(crate::trust_tasks::size::max_document_bytes(
            vti_rooms::wire::ROOMS_RECORDS_PUT_V5_TYPE,
        ) as u64),
        max_chunk_size: Some(vti_rooms::signal_delay::MAX_CHUNK_SIZE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No `[rooms.files]` section — every configuration written before room files
    /// existed — opens without touching the disk: no directory, no seeded config, and
    /// uploads refused. Such a VTC must keep starting after an upgrade.
    #[tokio::test]
    async fn without_the_section_nothing_is_created_and_files_are_off() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().join("store"),
        })
        .unwrap();
        // A data directory that does not exist and cannot be created: anything that
        // tried to make a directory beneath it would fail the open.
        let unwritable = Path::new("/nonexistent/vtc-data");
        let storage = open_room_storage(&store, unwritable, None, Some("did:key:zCommunity"))
            .await
            .expect("opens with room files off");
        assert!(
            storage.configs().await.unwrap().is_empty(),
            "nothing seeded"
        );
        let host = open_blob_host(&store, unwritable, None, storage).unwrap();
        assert!(!host.files_enabled());
    }

    /// A relative `[store] data_dir` is ordinary; the `local` config seeded from it
    /// must still carry the absolute `root` the specification requires.
    #[tokio::test]
    async fn a_relative_blob_dir_is_resolved_against_the_working_directory() {
        let cwd = tempfile::tempdir().unwrap();
        let resolved = absolute_dir(PathBuf::from("data/vtc/room-blobs"), cwd.path())
            .await
            .unwrap();
        assert!(resolved.is_absolute(), "{}", resolved.display());
        assert_eq!(
            resolved,
            std::fs::canonicalize(cwd.path())
                .unwrap()
                .join("data/vtc/room-blobs")
        );
        assert!(resolved.is_dir());

        let with_dots = absolute_dir(PathBuf::from("data/../data/./x"), cwd.path())
            .await
            .unwrap();
        assert!(
            !with_dots.components().any(|c| matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )),
            "{}",
            with_dots.display()
        );
    }

    #[tokio::test]
    async fn an_absolute_blob_dir_is_kept_as_given() {
        let p = PathBuf::from("/srv/vtc/room-blobs");
        assert_eq!(
            absolute_dir(p.clone(), Path::new("/elsewhere"))
                .await
                .unwrap(),
            p
        );
    }

    /// End to end: storage opened over a relative data directory seeds a config
    /// that conforms, rather than refusing to start.
    #[tokio::test]
    async fn storage_opens_over_a_relative_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().join("store"),
        })
        .unwrap();
        // Relative to the test process's working directory, as an operator's
        // `data_dir = "data"` is relative to theirs. Unique, and removed after.
        let rel = PathBuf::from(format!("target/relative-data-{}", uuid::Uuid::new_v4()));
        let storage = open_room_storage(
            &store,
            &rel,
            Some(&RoomFilesConfig::default()),
            Some("did:key:zCommunity"),
        )
        .await;
        let _ = std::fs::remove_dir_all(&rel);
        let storage = storage.expect("a relative data directory opens");
        let local = storage
            .config(super::super::storage_configs::SEED_CONFIG_ID)
            .await
            .unwrap()
            .unwrap();
        assert!(
            local["settings"]["root"].as_str().unwrap().starts_with('/'),
            "{local}"
        );
    }
}
