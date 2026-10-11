//! Blobs as plain files under a directory.
//!
//! The default store, and the one a standalone host on one machine wants. A blob
//! is `<root>/<key>`, written to a temporary file in the same directory, synced
//! and renamed into place, so a crash leaves either the whole blob or none of it
//! — never a truncated file under a content address. Directories are created
//! owner-only (0700) and files owner-only (0600).
//!
//! Not in a node's backup: the bytes would make every backup grow with every
//! upload. Back the directory up beside the node (design note §5.6).

use std::io::SeekFrom;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::{BackendRef, BlobKey, BlobStore, Deletion, Health, check_kind};
use crate::error::AppError;

/// The store's kind, as recorded in its [`BackendRef`]s.
pub const KIND: &str = "local";

/// Blobs under one directory.
#[derive(Debug, Clone)]
pub struct LocalDirStore {
    root: PathBuf,
}

impl LocalDirStore {
    /// A store rooted at `root`, created (owner-only) if it does not exist.
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self, AppError> {
        let root = root.into();
        create_dir_private(&root).await?;
        Ok(Self { root })
    }

    /// A store rooted at `root`, which is created (owner-only) on the first
    /// write. For a caller that cannot await at construction.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory blobs are written under.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_of(&self, key: &BlobKey) -> PathBuf {
        // `BlobKey` is built only from a validated digest under a fixed prefix,
        // so joining it cannot leave `root`.
        self.root.join(key.as_str())
    }
}

async fn create_dir_private(dir: &Path) -> Result<(), AppError> {
    tokio::fs::create_dir_all(dir).await.map_err(AppError::Io)?;
    #[cfg(unix)]
    crate::backup_transfer::set_dir_mode_700(dir).await?;
    Ok(())
}

#[async_trait]
impl BlobStore for LocalDirStore {
    fn kind(&self) -> &'static str {
        KIND
    }

    async fn put(&self, key: &BlobKey, staged: &Path, size: u64) -> Result<BackendRef, AppError> {
        let dest = self.path_of(key);
        let at = BackendRef {
            kind: KIND.into(),
            key: key.clone(),
        };
        // Idempotent on the key: a content address that is already there holds
        // these bytes, so a repeated commit stores nothing new.
        if let Ok(meta) = tokio::fs::metadata(&dest).await
            && meta.len() == size
        {
            return Ok(at);
        }
        let parent = dest.parent().ok_or_else(|| {
            AppError::Internal(format!("blob key `{}` has no parent", key.as_str()))
        })?;
        // Each level owner-only, not only the last: `create_dir_all` would leave
        // the intermediate `rooms/<prefix>` at the umask's mode.
        create_dir_private(&self.root).await?;
        let mut dir = self.root.clone();
        for part in parent
            .strip_prefix(&self.root)
            .map_err(|_| AppError::Internal("blob path escaped the store root".into()))?
            .components()
        {
            dir.push(part);
            create_dir_private(&dir).await?;
        }

        let staged_len = tokio::fs::metadata(staged)
            .await
            .map_err(AppError::Io)?
            .len();
        if staged_len != size {
            return Err(AppError::Internal(format!(
                "staged blob is {staged_len} bytes, expected {size}"
            )));
        }
        let tmp = parent.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
        let result = async {
            tokio::fs::copy(staged, &tmp).await.map_err(AppError::Io)?;
            #[cfg(unix)]
            crate::backup_transfer::set_file_mode_600(&tmp).await?;
            let file = tokio::fs::File::open(&tmp).await.map_err(AppError::Io)?;
            file.sync_all().await.map_err(AppError::Io)?;
            tokio::fs::rename(&tmp, &dest).await.map_err(AppError::Io)
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&tmp).await;
        }
        result?;
        Ok(at)
    }

    async fn get_range(&self, at: &BackendRef, start: u64, end: u64) -> Result<Vec<u8>, AppError> {
        check_kind(self, at)?;
        if end < start {
            return Err(AppError::Validation(format!(
                "range {start}..{end} is reversed"
            )));
        }
        let mut file = match tokio::fs::File::open(self.path_of(&at.key)).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(AppError::NotFound(format!("blob `{}`", at.key.as_str())));
            }
            Err(e) => return Err(AppError::Io(e)),
        };
        file.seek(SeekFrom::Start(start))
            .await
            .map_err(AppError::Io)?;
        let mut buf = vec![0u8; (end - start) as usize];
        file.read_exact(&mut buf).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                AppError::Internal(format!(
                    "blob `{}` is shorter than {end} bytes",
                    at.key.as_str()
                ))
            } else {
                AppError::Io(e)
            }
        })?;
        Ok(buf)
    }

    async fn delete(&self, at: &BackendRef) -> Result<Deletion, AppError> {
        check_kind(self, at)?;
        match tokio::fs::remove_file(self.path_of(&at.key)).await {
            Ok(()) => Ok(Deletion::Deleted),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Deletion::Deleted),
            Err(e) => Err(AppError::Io(e)),
        }
    }

    async fn health(&self) -> Health {
        if let Err(e) = create_dir_private(&self.root).await {
            return Health {
                ok: false,
                detail: Some(e.to_string()),
            };
        }
        let probe = self.root.join(format!(".health-{}", uuid::Uuid::new_v4()));
        match tokio::fs::write(&probe, b"ok").await {
            Ok(()) => {
                let _ = tokio::fs::remove_file(&probe).await;
                Health {
                    ok: true,
                    detail: None,
                }
            }
            Err(e) => Health {
                ok: false,
                detail: Some(e.to_string()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn passes_the_conformance_suite() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalDirStore::open(dir.path().join("blobs")).await.unwrap();
        super::super::conformance::run(&store, dir.path()).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn files_and_directories_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = LocalDirStore::open(dir.path().join("blobs")).await.unwrap();
        let staged = dir.path().join("staged");
        tokio::fs::write(&staged, b"ciphertext").await.unwrap();
        let key = BlobKey::for_room(
            "did:key:zRoom",
            &super::super::sha256_digest_multibase(&[1u8; 32]),
        )
        .unwrap();
        store.put(&key, &staged, 10).await.unwrap();
        let path = store.root().join(key.as_str());
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(path.parent().unwrap().parent().unwrap()), 0o700);
    }
}
