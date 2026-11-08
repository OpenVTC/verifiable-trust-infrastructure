//! Test fixtures that open a store with its keyspaces already created,
//! without paying for creating them.
//!
//! Compiled only under `cfg(test)` or the `test-support` feature. Production
//! code opens its store with [`Store::open`] / [`Store::open_with`], which
//! this module does not touch: production durability is unchanged.
//!
//! # Why
//!
//! Creating a fjall keyspace is crash-durable by construction, and no
//! configuration turns that off: `lsm_tree::Tree::create_new` fsyncs the
//! tree's two directories (`lsm_tree::file::fsync_directory`), then writes
//! and fsyncs its version file and directory (`lsm_tree::version::persist`),
//! and fjall then records the keyspace in its meta keyspace through an
//! ingestion, which writes, fsyncs and directory-fsyncs a table and a second
//! version. fjall 3.1's `Builder` knobs (`manual_journal_persist`,
//! `temporary`, journal sizing) govern the write journal, not these. On
//! macOS Rust's `File::sync_all` is `fcntl(F_FULLFSYNC)`, which flushes the
//! drive's cache and costs tens of milliseconds each.
//!
//! Measured on a Mac, fjall 3.1.10: creating 45 keyspaces took 2.68 s;
//! copying the resulting database and reopening it took 47 ms. A sampled
//! vtc-service unit test spent 2.9 s wall / 0.5 s CPU in `F_FULLFSYNC` under
//! `fsync_directory` while its fixture created the VTC's ~45 keyspaces —
//! the reason the VTC's lib tests ran ~141 s on Linux CI and ~1100 s on a
//! Mac.
//!
//! So each distinct keyspace set is created **once** in a template
//! database, and every fixture writes the template's files — and its
//! directories, empty ones included (see [`Snapshot`]) — into its own
//! directory and opens them — ordinary buffered writes, no fsync. Opening
//! recovers the copy as fjall would any database (one journal fsync), and
//! each fixture's store is fully independent.
//!
//! "Once" has to span processes: nextest runs every test in a process of
//! its own, so a per-process template would be built by every test and save
//! nothing. The template is therefore published under the system temp
//! directory (`vti-store-templates/`, keyed by this crate's version and the
//! keyspace set), by atomic rename so a reader never sees a partial one, and
//! also cached in memory for `cargo test`'s many fixtures per process. A
//! published template that no longer opens (a fjall format change under the
//! same crate version) is discarded and rebuilt.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use crate::config::StoreConfig;
use crate::error::AppError;

use super::{LocalStore, Store};

/// A template database as its entries: (path relative to the root, bytes for a file or
/// `None` for a directory).
///
/// Directories are entries too, **empty ones included**. An empty tree has an empty
/// `tables/` folder, and lsm-tree's recovery creates and fsyncs one it finds missing
/// (`recover_levels`), so a copy that dropped them paid one `F_FULLFSYNC` per keyspace on
/// every open — ~5 ms each on a Mac, ~0.3 s for the VTA's set, which is what this module
/// exists to avoid (#2383).
type Snapshot = Arc<Vec<Entry>>;
type Entry = (PathBuf, Option<Vec<u8>>);

/// Templates already loaded by this process, by keyspace set.
fn templates() -> &'static Mutex<HashMap<Vec<String>, Snapshot>> {
    static TEMPLATES: OnceLock<Mutex<HashMap<Vec<String>, Snapshot>>> = OnceLock::new();
    TEMPLATES.get_or_init(Default::default)
}

/// Open a local store at `data_dir` in which every keyspace in `keyspaces`
/// already exists, without creating any of them there.
///
/// `data_dir` must be empty or absent. A keyspace not in `keyspaces` can
/// still be opened on the result; it is created the ordinary (fsyncing)
/// way. Test fixtures only — see the module docs.
pub fn open_with_keyspaces(data_dir: &Path, keyspaces: &[&str]) -> Result<Store, AppError> {
    let mut key: Vec<String> = keyspaces.iter().map(|s| s.to_string()).collect();
    key.sort();
    key.dedup();

    match copy_and_open(&snapshot_for(&key)?, data_dir) {
        Ok(store) => Ok(store),
        Err(_) => {
            // A published template this build's fjall cannot open: replace
            // it, and open a fresh copy.
            forget(&key);
            std::fs::remove_dir_all(data_dir)?;
            copy_and_open(&snapshot_for(&key)?, data_dir)
        }
    }
}

fn copy_and_open(snapshot: &Snapshot, data_dir: &Path) -> Result<Store, AppError> {
    for (rel, bytes) in snapshot.iter() {
        let path = data_dir.join(rel);
        match bytes {
            None => std::fs::create_dir_all(&path)?,
            Some(bytes) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, bytes)?;
            }
        }
    }
    std::fs::create_dir_all(data_dir)?;
    Store::open(&StoreConfig {
        data_dir: data_dir.to_path_buf(),
    })
}

/// Where the template for `key` is published.
fn published_dir(key: &[String]) -> PathBuf {
    // FNV-1a: stable across processes and toolchains, unlike `DefaultHasher`.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in key.join("\n").bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    std::env::temp_dir()
        .join("vti-store-templates")
        .join(format!("{}-{hash:016x}", env!("CARGO_PKG_VERSION")))
}

fn forget(key: &[String]) {
    templates()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(key);
    let _ = std::fs::remove_dir_all(published_dir(key));
}

fn snapshot_for(key: &[String]) -> Result<Snapshot, AppError> {
    // Held across the load so this process loads or builds a set once.
    let mut templates = templates()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(snapshot) = templates.get(key) {
        return Ok(snapshot.clone());
    }

    let published = published_dir(key);
    let snapshot = Arc::new(match load(&published) {
        Some(files) => files,
        None => {
            // Every test process starts at once on a cold run; without this
            // lock each would build the template itself and the first run
            // would gain nothing. One builds; the rest wait, then load it.
            let parent = published
                .parent()
                .expect("published template dir has a parent");
            std::fs::create_dir_all(parent)?;
            let mut lock_path = published.clone().into_os_string();
            lock_path.push(".lock");
            let lock = std::fs::File::create(lock_path)?;
            lock.lock()?;
            match load(&published) {
                Some(files) => files,
                None => build_and_publish(key, &published)?,
            }
        }
    });
    templates.insert(key.to_vec(), snapshot.clone());
    Ok(snapshot)
}

fn load(published: &Path) -> Option<Vec<Entry>> {
    let mut files = Vec::new();
    match read_tree(published, Path::new(""), &mut files) {
        Ok(()) if files.iter().any(|(_, bytes)| bytes.is_some()) => Some(files),
        _ => None,
    }
}

/// Build the template in a private staging directory, read it, then
/// publish it by renaming the staging directory into place. A process that
/// loses the race to publish discards its own copy; the two are equivalent.
fn build_and_publish(key: &[String], published: &Path) -> Result<Vec<Entry>, AppError> {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let parent = published
        .parent()
        .expect("published template dir has a parent");
    let staging = parent.join(format!(
        ".staging-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let built = (|| {
        {
            let store = LocalStore::open(&StoreConfig {
                data_dir: staging.clone(),
            })?;
            for name in key {
                store.keyspace(name)?;
            }
            // Dropping the last handle stops fjall's workers synchronously
            // (`DatabaseInner::drop`), so the directory is quiescent below.
        }
        let mut files = Vec::new();
        read_tree(&staging, Path::new(""), &mut files)?;
        Ok(files)
    })();
    if built.is_err() || std::fs::rename(&staging, published).is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    built
}

fn read_tree(root: &Path, rel: &Path, out: &mut Vec<Entry>) -> Result<(), AppError> {
    for entry in std::fs::read_dir(root.join(rel))? {
        let entry = entry?;
        let rel = rel.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            // Before its contents, so a copy creates it first.
            out.push((rel.clone(), None));
            read_tree(root, &rel, out)?;
        } else {
            out.push((rel.clone(), Some(std::fs::read(root.join(&rel))?)));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SET: &[&str] = &["alpha", "beta", "gamma"];

    /// Fixtures opened from one template are independent stores: a write
    /// to one is invisible to another, and each survives its own reopen.
    #[tokio::test]
    async fn templated_stores_are_independent_and_reopenable() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();

        {
            let store_a = open_with_keyspaces(a.path(), SET).unwrap();
            let store_b = open_with_keyspaces(b.path(), SET).unwrap();
            store_a
                .keyspace("beta")
                .unwrap()
                .insert("k", &"in a")
                .await
                .unwrap();
            let in_b: Option<String> = store_b.keyspace("beta").unwrap().get("k").await.unwrap();
            assert_eq!(in_b, None, "a write to one fixture leaked into another");
            store_a.persist().await.unwrap();
        }

        let reopened = Store::open(&StoreConfig {
            data_dir: a.path().to_path_buf(),
        })
        .unwrap();
        let got: Option<String> = reopened.keyspace("beta").unwrap().get("k").await.unwrap();
        assert_eq!(got.as_deref(), Some("in a"));
    }

    /// Every directory of the template is in its snapshot, empty ones included: an empty
    /// tree's `tables/` folder that a copy leaves out is one lsm-tree's recovery creates
    /// and fsyncs, per keyspace, on every open (#2383).
    #[test]
    fn the_snapshot_carries_every_directory_of_the_template() {
        let mut key: Vec<String> = SET.iter().map(|s| s.to_string()).collect();
        key.sort();
        let snapshot = snapshot_for(&key).unwrap();

        fn dirs(root: &Path, rel: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(root.join(rel)).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    let rel = rel.join(entry.file_name());
                    out.push(rel.clone());
                    dirs(root, &rel, out);
                }
            }
        }
        let mut published = Vec::new();
        dirs(&published_dir(&key), Path::new(""), &mut published);

        let empty = published
            .iter()
            .filter(|d| {
                std::fs::read_dir(published_dir(&key).join(d))
                    .unwrap()
                    .next()
                    .is_none()
            })
            .count();
        assert!(empty > 0, "the template has no empty directory to check");
        for dir in &published {
            assert!(
                snapshot
                    .iter()
                    .any(|(rel, bytes)| rel == dir && bytes.is_none()),
                "`{}` is not in the snapshot",
                dir.display()
            );
        }
    }

    /// A keyspace outside the template's set still opens (created normally).
    #[tokio::test]
    async fn keyspaces_outside_the_template_still_open() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_with_keyspaces(dir.path(), SET).unwrap();
        let ks = store.keyspace("delta").unwrap();
        ks.insert("k", &1u32).await.unwrap();
        assert_eq!(ks.get::<u32>("k").await.unwrap(), Some(1));
    }

    /// A published template that does not open is replaced, not trusted.
    #[tokio::test]
    async fn an_unopenable_published_template_is_rebuilt() {
        let set = [format!("unopenable-{}", std::process::id())];
        let published = published_dir(&set);
        std::fs::create_dir_all(&published).unwrap();
        std::fs::write(published.join("version"), b"not a fjall marker").unwrap();

        let dir = tempfile::tempdir().unwrap();
        let store = open_with_keyspaces(dir.path(), &[set[0].as_str()]).unwrap();
        let ks = store.keyspace(&set[0]).unwrap();
        ks.insert("k", &1u32).await.unwrap();
        assert_eq!(ks.get::<u32>("k").await.unwrap(), Some(1));

        let _ = std::fs::remove_dir_all(&published);
    }
}
