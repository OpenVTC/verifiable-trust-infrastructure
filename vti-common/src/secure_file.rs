//! Cross-platform file / directory permission tightening for
//! secret-bearing paths (bootstrap seeds, keystores, export bundles).
//!
//! # Unix
//!
//! `restrict_file_to_owner` → `chmod 0600`, `restrict_dir_to_owner` →
//! `chmod 0700`. Mirrors the discipline already applied inline at
//! existing call sites.
//!
//! # Windows
//!
//! `icacls <path> /inheritance:r /grant:r <user>:(F)` — removes any
//! inherited ACEs and replaces the DACL with a single full-control
//! grant to the current user. This is defence-in-depth on top of the
//! user-profile defaults (which already keep other local users out,
//! but inherited admin / Users group grants can slip through on
//! misconfigured boxes or when the data lives outside the profile).
//!
//! Shell-out to `icacls` rather than native `SetNamedSecurityInfoW`
//! because `icacls` is universally available on every supported Windows
//! version, gets the quirks right (inheritance flags, SID lookup), and
//! doesn't force the crate to carry a pile of unsafe Windows API code
//! on a platform we don't exercise in CI. A future iteration can swap
//! to the native API if `icacls` becomes insufficient.
//!
//! Errors are non-fatal at call sites: callers log a warning and
//! continue, matching how the existing Unix `PermissionsExt` calls are
//! already wired (best-effort hardening, not a correctness gate).

use std::path::Path;

/// Restrict `path` (a file) so only the owner can read / write.
///
/// Returns `Ok(())` on platforms where the operation either succeeded
/// or is a no-op (everything non-Unix / non-Windows falls through —
/// Unix gets 0600, Windows gets an icacls-applied user-only DACL).
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

/// Restrict `path` (a directory) so only the owner can traverse / read /
/// write. On Unix: `0700`. On Windows: inheritance removed and DACL
/// replaced with full control to the current user only.
pub fn restrict_dir_to_owner(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(path)?.permissions();
        perm.set_mode(0o700);
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

    // Resolve the current user. `USERNAME` is present on every modern
    // Windows shell environment; fall back to `USERDOMAIN\USERNAME`
    // only if the plain name is missing. A missing `USERNAME` means
    // the process is running in an unusual execution context
    // (service, scheduled task without user context, etc.) — surface
    // that via an error rather than silently leaving the file
    // wide-open.
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

    // `icacls <path> /inheritance:r /grant:r "user:(F)"`
    //   /inheritance:r → remove inherited ACEs
    //   /grant:r       → replace any existing grant for <user>
    //   user:(F)       → full control
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

    #[test]
    fn restrict_file_sets_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join(format!("vta-test-secure-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmp).unwrap();
        let f = tmp.join("secret.bin");
        std::fs::write(&f, b"sensitive").unwrap();

        // Start with permissive mode so we can see the change.
        let mut perm = std::fs::metadata(&f).unwrap().permissions();
        perm.set_mode(0o644);
        std::fs::set_permissions(&f, perm).unwrap();

        restrict_file_to_owner(&f).expect("restrict_file_to_owner succeeds");

        let mode = std::fs::metadata(&f).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn restrict_dir_sets_0700_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join(format!("vta-test-secure-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmp).unwrap();

        let mut perm = std::fs::metadata(&tmp).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&tmp, perm).unwrap();

        restrict_dir_to_owner(&tmp).expect("restrict_dir_to_owner succeeds");

        let mode = std::fs::metadata(&tmp).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
