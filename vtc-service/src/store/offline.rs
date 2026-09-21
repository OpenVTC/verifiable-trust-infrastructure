//! Opening the store from an offline CLI command, and saying so plainly when
//! the daemon already holds it.
//!
//! fjall permits one process per data directory. Every offline `vtc` command
//! opens the store directly, so each one, run while the daemon is up, used to
//! fail with the storage engine's own words: `store error: FjallError:
//! Locked`. That names the mechanism and not the situation — and it is
//! precisely the situation an operator can act on, because the fix is either
//! "stop the daemon" or "do this through the daemon instead".
//!
//! Keyring's VTI-16 met it on `vtc admin invite`, concluding that admitting a
//! new administrator meant taking the community offline. It does not:
//! `POST /v1/admin/invites` mints the same invite through the running daemon,
//! and the admin console's access page calls it. The CLI simply never said so.

use std::fmt;
use std::path::PathBuf;

use vti_common::config::StoreConfig;
use vti_common::error::AppError;

use super::Store;

/// Why an offline command could not open the store.
#[derive(Debug)]
pub enum OfflineStoreError {
    /// Another process — in practice the running daemon — holds the store.
    DaemonRunning { data_dir: PathBuf },
    /// Anything else, unchanged.
    Other(AppError),
}

impl fmt::Display for OfflineStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DaemonRunning { data_dir } => write!(
                f,
                "the VTC daemon is running and holds the store at {} — this command \
                 opens the store directly, and only one process can. Stop the daemon \
                 and re-run it",
                data_dir.display()
            ),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for OfflineStoreError {}

/// Open the store for an offline command, distinguishing "the daemon holds it"
/// from every other failure.
///
/// Matches fjall's `Locked` exactly rather than treating any open failure as a
/// running daemon, which is what `vtc status` has to guess at: a permissions
/// error or a corrupt directory is not solved by stopping anything.
pub fn open_offline(config: &StoreConfig) -> Result<Store, OfflineStoreError> {
    match Store::open(config) {
        Ok(store) => Ok(store),
        Err(AppError::Store(fjall::Error::Locked)) => Err(OfflineStoreError::DaemonRunning {
            data_dir: config.data_dir.clone(),
        }),
        Err(e) => Err(OfflineStoreError::Other(e)),
    }
}

/// Whether `data_dir` is currently held by another process. Only for tests
/// that need to assert against a real lock rather than a constructed error.
#[cfg(test)]
fn held_by_another(data_dir: &std::path::Path) -> bool {
    matches!(
        open_offline(&StoreConfig {
            data_dir: data_dir.to_path_buf()
        }),
        Err(OfflineStoreError::DaemonRunning { .. })
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real thing, not a constructed error: hold the store open as the
    /// daemon would, then open it again as an offline command does.
    #[test]
    fn a_held_store_is_reported_as_the_daemon_running() {
        let dir = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let _daemon = Store::open(&config).expect("the first open succeeds");

        match open_offline(&config) {
            Err(OfflineStoreError::DaemonRunning { data_dir }) => {
                assert_eq!(data_dir, dir.path());
            }
            Err(OfflineStoreError::Other(e)) => {
                panic!("a held store must read as the daemon running, got: {e}")
            }
            Ok(_) => panic!("fjall allowed a second process on one data dir"),
        }
    }

    #[test]
    fn the_message_names_the_situation_not_the_storage_engine() {
        let msg = OfflineStoreError::DaemonRunning {
            data_dir: PathBuf::from("/var/lib/vtc"),
        }
        .to_string();
        assert!(msg.contains("daemon is running"), "{msg}");
        assert!(msg.contains("/var/lib/vtc"), "{msg}");
        assert!(!msg.contains("Fjall"), "{msg}");
    }

    #[test]
    fn a_free_store_opens() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!held_by_another(dir.path()));
    }
}
