use std::fs::OpenOptions;
use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::pin::Pin;

use tracing::warn;

use vti_common::error::AppError;

/// Plaintext file-based seed store (NOT secure — use only for development).
///
/// The seed is stored as a hex-encoded string in a plaintext file.
/// A warning is emitted on every access. Even though this backend is
/// dev-only, the file is still written with owner-only permissions
/// (`0600` on Unix; user-only DACL on Windows) so a misconfigured dev
/// VM can't trivially leak the BIP-32 master seed to other local users.
pub struct PlaintextSeedStore {
    path: PathBuf,
}

impl PlaintextSeedStore {
    /// Store at `<data_dir>/seed.plaintext` (the VTA default).
    pub fn new(data_dir: &std::path::Path) -> Self {
        Self::with_filename(data_dir, "seed.plaintext")
    }

    /// Store at `<data_dir>/<filename>`. Lets a consumer pin a
    /// backend-specific filename (e.g. the VTC uses `secret.plaintext`)
    /// while sharing this implementation.
    pub fn with_filename(data_dir: &std::path::Path, filename: &str) -> Self {
        Self {
            path: data_dir.join(filename),
        }
    }
}

impl super::SeedStore for PlaintextSeedStore {
    fn get(&self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>> {
        Box::pin(async {
            warn!(
                path = %self.path.display(),
                "reading seed from PLAINTEXT file — this is NOT secure for production use"
            );
            match std::fs::read_to_string(&self.path) {
                Ok(hex_seed) => {
                    let bytes = hex::decode(hex_seed.trim()).map_err(|e| {
                        AppError::SecretStore(format!(
                            "failed to decode hex seed from plaintext file: {e}"
                        ))
                    })?;
                    Ok(Some(bytes))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(AppError::SecretStore(format!(
                    "failed to read plaintext seed file: {e}"
                ))),
            }
        })
    }

    fn set(&self, seed: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let hex_seed = hex::encode(seed);
        Box::pin(async move {
            warn!(
                path = %self.path.display(),
                "writing seed to PLAINTEXT file — this is NOT secure for production use"
            );
            if let Some(parent) = self.path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    AppError::SecretStore(format!(
                        "failed to create directory for plaintext seed: {e}"
                    ))
                })?;
            }

            // Open with restrictive permissions BEFORE writing so the seed
            // never lands at the default umask (0644 on most distros) even
            // for the brief window between create and chmod. On Unix,
            // `mode(0o600)` on `OpenOptions` is honoured at file-creation
            // time; on Windows we apply the user-only DACL after write.
            let mut opts = OpenOptions::new();
            opts.create(true).write(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&self.path).map_err(|e| {
                AppError::SecretStore(format!("failed to open plaintext seed file: {e}"))
            })?;
            file.write_all(hex_seed.as_bytes()).map_err(|e| {
                AppError::SecretStore(format!("failed to write plaintext seed file: {e}"))
            })?;

            // Belt-and-braces: re-assert the owner-only restriction in
            // case the file already existed before this open() — a
            // pre-existing file at 0644 would have kept its mode through
            // a plain `OpenOptions::open` even with `mode(0o600)` set
            // (the mode hint only applies on creation). On Windows, this
            // is the primary mechanism (no `OpenOptions::mode` analogue).
            vti_common::secure_file::restrict_file_to_owner(&self.path).map_err(|e| {
                AppError::SecretStore(format!(
                    "failed to restrict plaintext seed file to owner: {e}"
                ))
            })?;

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::SeedStore;
    use super::*;

    /// Pin the owner-only file-mode invariant on Unix. A misconfigured
    /// dev VM with the plaintext backend (banner notwithstanding) is
    /// one operator-typo away from leaking the BIP-32 master seed to
    /// every local user — `0600` is the cheapest defence.
    #[cfg(unix)]
    #[tokio::test]
    async fn set_writes_file_at_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = PlaintextSeedStore::new(dir.path());
        store.set(b"\x42".repeat(32).as_slice()).await.unwrap();
        let mode = std::fs::metadata(&store.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "plaintext seed file must be owner-only");
    }

    /// Re-writing an existing file must keep the restrictive mode even
    /// if the existing file had a permissive mode (the
    /// belt-and-braces post-write `restrict_file_to_owner` is what
    /// guarantees this — `OpenOptions::mode` only applies at creation).
    #[cfg(unix)]
    #[tokio::test]
    async fn set_overwrite_re_restricts_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = PlaintextSeedStore::new(dir.path());

        // Pre-create the file at 0644 to simulate a plaintext seed
        // file that was originally written by an older buggy version.
        std::fs::write(&store.path, "stale").unwrap();
        let mut perm = std::fs::metadata(&store.path).unwrap().permissions();
        perm.set_mode(0o644);
        std::fs::set_permissions(&store.path, perm).unwrap();

        store.set(b"\x42".repeat(32).as_slice()).await.unwrap();
        let mode = std::fs::metadata(&store.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "overwriting an existing seed file must re-apply 0600"
        );
    }

    /// Round-trip sanity — the security fix didn't break get/set.
    #[tokio::test]
    async fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = PlaintextSeedStore::new(dir.path());
        let seed: Vec<u8> = (0..32).collect();
        store.set(&seed).await.unwrap();
        let got = store.get().await.unwrap().expect("seed present");
        assert_eq!(got, seed);
    }
}
