//! Register the platform-native credential store as keyring-core's
//! global default.
//!
//! `keyring-core` 1.0 split the Entry API from the backend stores. Every
//! binary that uses the OS keyring must register a store at startup before
//! constructing any `keyring_core::Entry`. Call [`install_default_store`]
//! once from `main()` before opening a session store, seed store, or
//! anything else that touches `Entry::new`.

/// Register the OS-native credential store as the keyring-core default.
///
/// - macOS → Keychain
/// - Linux → DBus Secret Service (GNOME Keyring / KWallet / KeePassXC)
/// - Windows → Windows Credential Manager
///
/// The keyring feature is unsupported on other platforms; enabling it
/// there is a build error.
#[cfg(target_os = "macos")]
pub fn install_default_store() -> keyring_core::Result<()> {
    let store = apple_native_keyring_store::keychain::Store::new()?;
    keyring_core::set_default_store(store);
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn install_default_store() -> keyring_core::Result<()> {
    let store = dbus_secret_service_keyring_store::Store::new()?;
    keyring_core::set_default_store(store);
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn install_default_store() -> keyring_core::Result<()> {
    let store = windows_native_keyring_store::Store::new()?;
    keyring_core::set_default_store(store);
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
compile_error!(
    "vta-sdk `keyring` feature requires target_os in (macos, linux, windows). \
     Disable the feature or build for a supported OS."
);

/// Install the platform store, or terminate the process explaining why not.
///
/// For a binary whose **sessions live in the credential store** — `pnm`, `cnm`,
/// and external consumers with the same shape. Those tools cannot do anything
/// useful once the store is unreachable: [`crate::session::SessionStore`] reads
/// through `SessionBackend::load`, which returns `Option`, so a store error is
/// indistinguishable from "no session" and the tool behaves as though the user
/// had never logged in. It does not fall back — it *forgets*. Stopping here,
/// with [`crate::secure_store::unavailable_message`], is the difference between
/// a diagnosable failure and a user reinstalling their account.
///
/// A binary for which the credential store is only *one* of several configured
/// secret backends must not call this — see [`warn_store_unavailable`]
/// below. Hard-failing
/// there would break every deployment using AWS, GCP, Vault or Kubernetes on a
/// host that has no credential store at all, which is the normal server shape.
///
/// Honours `VTI_SECURE_STORE` ([`crate::secure_store::OVERRIDE_ENV`]): an
/// operator who has explicitly selected `file` has already accepted that the
/// platform store is not in play, so its absence is not an error.
pub fn install_default_store_or_exit(tool: &str) {
    use crate::secure_store::{self, SecureStore};

    let selected = match secure_store::override_from_env() {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("error: {msg}");
            std::process::exit(1);
        }
    };

    if selected == Some(SecureStore::File) {
        // Deliberate opt-out. `default_backend` will pick the file store; there
        // is no platform store to install and nothing to warn about.
        return;
    }

    if let Err(e) = install_default_store() {
        eprintln!("{}", secure_store::unavailable_message(tool, &e));
        std::process::exit(1);
    }
}

/// Install the platform store, or report that secrets held *in it* will fail.
///
/// For a binary where the credential store is one backend among several
/// (`vta`, `vtc`: `[secrets] backend = ...` also offers AWS, GCP, Azure, Vault,
/// Kubernetes and TEE-KMS). Which one is in play is not known until config is
/// loaded, well after this runs, so this cannot decide to be fatal.
///
/// It does not need to. The keyring-backed seed store already fails closed —
/// `vti_secrets::seed_store::KeyringSeedStore` propagates the entry error as
/// `AppError::SecretStore` rather than reporting an absent seed. The only thing
/// missing was an operator being told which subsystem broke, which is what this
/// prints.
pub fn warn_store_unavailable(tool: &str) {
    if let Err(e) = install_default_store() {
        eprintln!(
            "warning: the OS credential store is unavailable: {e}\n\
             \n\
             {tool} will still start. This is fatal only if `[secrets] backend` \
             resolves to the keyring — that path fails closed and will refuse to \
             read or write the master seed rather than report it missing. Any \
             other backend (aws, gcp, azure, vault, k8s, tee-kms) is unaffected."
        );
    }
}
