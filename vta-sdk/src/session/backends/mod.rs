//! Built-in [`SessionBackend`](super::SessionBackend) implementations.
//!
//! Each backend is feature-gated to its respective dependency:
//! - [`KeyringBackend`] (`keyring` feature) — OS-native keyring via
//!   `keyring-core` (Apple Keychain / Windows Credential Manager /
//!   DBus Secret Service).
//! - [`AzureBackend`] (`azure-secrets` without `keyring`) — Azure
//!   Key Vault, isolated through a side thread to avoid nesting tokio
//!   runtimes.
//! - [`FileBackend`] — plaintext on-disk JSON at mode `0600`. Reachable only
//!   by explicit choice: the `config-session` feature, or `VTI_SECURE_STORE=file`
//!   at runtime.
//! - [`RefusingBackend`] — what a build with no session store at all gets. It
//!   refuses to save rather than inventing somewhere to put a private key.
//!
//! # There is no silent fallback
//!
//! [`default_backend`] used to end in an `#[allow(unreachable_code)]`
//! `FileBackend`, reached whenever no backend feature was enabled. That wrote
//! the admin private key to `sessions.json` as plaintext JSON at whatever the
//! umask allowed, announced by a `WARNING:` line on every access — which is to
//! say, invisible. A store that holds a private key is a decision, so it is now
//! always made explicitly and never arrived at by omission.
//!
//! The runtime override exists because the alternative is worse: an operator on
//! a headless host with no Secret Service would otherwise have to rebuild the
//! binary with `--features config-session` to run it at all, and the pressure
//! that creates is to disable the check rather than to make a choice.

use std::path::PathBuf;

use super::SessionBackend;
use crate::secure_store::{self, SecureStore};

#[cfg(all(feature = "azure-secrets", not(feature = "keyring")))]
mod azure;
mod file;
#[cfg(feature = "keyring")]
mod keyring;
mod refusing;

#[cfg(all(feature = "azure-secrets", not(feature = "keyring")))]
pub(super) use azure::AzureBackend;
pub(super) use file::FileBackend;
#[cfg(feature = "keyring")]
pub(super) use keyring::KeyringBackend;
pub(super) use refusing::RefusingBackend;

/// Create the default session backend based on compiled features.
///
/// Priority: explicit `VTI_SECURE_STORE=file` → keyring → azure-secrets →
/// config-session → refuse.
///
/// The runtime override is checked *first* on purpose. It is the operator
/// saying "this host has no credential store"; consulting it after the
/// compiled default would mean a binary built with `keyring` could never honour
/// it, which is exactly the case it exists for.
pub(super) fn default_backend(
    service_name: &str,
    sessions_dir: PathBuf,
) -> Box<dyn SessionBackend> {
    let _ = service_name;

    match secure_store::override_from_env() {
        Ok(Some(SecureStore::File)) => {
            return Box::new(FileBackend {
                sessions_dir,
                reason: "VTI_SECURE_STORE=file",
            });
        }
        Ok(Some(SecureStore::Os)) => {
            // Asking for the OS store on a build that has none must not quietly
            // resolve to a file — that is the substitution this whole change
            // exists to remove, and an explicit request makes it worse, not
            // better.
            #[cfg(not(feature = "keyring"))]
            return Box::new(RefusingBackend {
                reason: format!(
                    "{}=os asks for the OS credential store, but this build has no \
                     `keyring` feature compiled in. Rebuild with it, or choose \
                     `file` deliberately.",
                    secure_store::OVERRIDE_ENV
                ),
            });
        }
        Ok(None) => {}
        Err(msg) => {
            // Selection is the gate between a keychain entry and a file on
            // disk. An unparseable value resolves to neither.
            return Box::new(RefusingBackend {
                reason: format!("{msg} Until it is fixed, no session store is selected."),
            });
        }
    }

    compiled_default(service_name, sessions_dir)
}

/// The compile-time half of [`default_backend`], after the runtime override has
/// declined to answer.
fn compiled_default(service_name: &str, sessions_dir: PathBuf) -> Box<dyn SessionBackend> {
    let _ = service_name;
    let _ = &sessions_dir;

    #[cfg(feature = "keyring")]
    {
        return Box::new(KeyringBackend {
            service_name: service_name.to_string(),
        });
    }

    #[cfg(all(feature = "azure-secrets", not(feature = "keyring")))]
    {
        return Box::new(AzureBackend {
            vault_url: std::env::var("AZURE_KEYVAULT_URL").unwrap_or_default(),
            secret_prefix: service_name.to_string(),
        });
    }

    #[cfg(all(
        feature = "config-session",
        not(feature = "keyring"),
        not(feature = "azure-secrets")
    ))]
    {
        return Box::new(FileBackend {
            sessions_dir,
            reason: "the `config-session` feature",
        });
    }

    #[allow(unreachable_code)]
    Box::new(RefusingBackend {
        reason: format!(
            "this build has no session store compiled in. Rebuild with one of the \
             `keyring`, `azure-secrets` or `config-session` features, or set \
             {}=file to accept a plaintext file at mode 0600.",
            secure_store::OVERRIDE_ENV
        ),
    })
}
