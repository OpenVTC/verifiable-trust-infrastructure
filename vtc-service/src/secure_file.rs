//! Owner-only permission hardening for secret-bearing files written by the
//! VTC service (`config.toml` — carries `auth.jwt_signing_key` and, under the
//! config-secret backend, the hex `VtcKeyBundle`; `secret.plaintext` — the
//! dev secret store).
//!
//! This mirrors the workspace discipline used for PNM bootstrap secrets
//! (`vta-cli-common::secure_file::restrict_file_to_owner`,
//! `vta-sdk::provision_client::setup_key`). `vtc-service` can't depend on
//! `vta-cli-common` (wrong direction in the crate graph — the CLIs depend on
//! the services, not the reverse), so the small helper is reproduced here.
//!
//! # Unix
//! `chmod 0600` — owner read/write only.
//!
//! # Windows
//! `icacls <path> /inheritance:r /grant:r <user>:(F)` — strip inherited ACEs
//! and replace the DACL with a single full-control grant to the current user.
//!
//! Defence-in-depth: the file content is the secret, but file-mode hardening
//! keeps it off a co-tenant's `cat`.

use std::path::Path;

/// Restrict `path` (a file) so only the owner can read / write.
///
/// Unix → `0600`. Windows → user-only DACL via `icacls`. Other platforms are
/// a no-op. Best-effort: callers should treat an error as a hardening failure,
/// not a write failure (the bytes are already on disk by the time this runs).
pub fn restrict_file_to_owner(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(path)?.permissions();
        perm.set_mode(0o600);
        std::fs::set_permissions(path, perm)?;
    }
    #[cfg(windows)]
    {
        apply_windows_user_only_dacl(path)?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(windows)]
fn apply_windows_user_only_dacl(path: &Path) -> std::io::Result<()> {
    use std::process::Command;

    // `USERNAME` is present on every modern Windows shell. A missing value
    // means an unusual execution context (service / scheduled task without a
    // user) — surface it rather than silently leaving the file wide open.
    let user = std::env::var("USERNAME").map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "USERNAME env var not set — cannot apply Windows user-only DACL",
        )
    })?;
    let user_trimmed = user.trim();
    if user_trimmed.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "USERNAME is empty — cannot apply Windows user-only DACL",
        ));
    }

    let path_str = path.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path is not valid UTF-8 — cannot pass to icacls",
        )
    })?;

    let output = Command::new("icacls")
        .arg(path_str)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{user_trimmed}:(F)"))
        .output()?;

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "icacls failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn restrict_file_sets_0600_on_unix() {
        let tmp = std::env::temp_dir().join(format!("vtc-secure-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmp).unwrap();
        let f = tmp.join("secret.bin");
        std::fs::write(&f, b"sensitive").unwrap();

        // Start permissive so the change is observable.
        let mut perm = std::fs::metadata(&f).unwrap().permissions();
        perm.set_mode(0o644);
        std::fs::set_permissions(&f, perm).unwrap();

        restrict_file_to_owner(&f).expect("restrict_file_to_owner succeeds");

        let mode = std::fs::metadata(&f).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
