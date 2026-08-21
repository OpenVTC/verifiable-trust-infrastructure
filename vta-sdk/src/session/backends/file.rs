//! Plaintext on-disk JSON [`SessionBackend`] for hosts with no OS credential
//! store — an encrypted volume, a locked-down container, CI.
//!
//! Sessions live at `<sessions_dir>/sessions.json`, written at mode `0600`
//! inside a `0700` directory. Reachable only by explicit choice: the
//! `config-session` feature, or `VTI_SECURE_STORE=file`. See
//! [`super`] for why there is no longer a silent fallback into this backend.
//!
//! # Mode is set before content
//!
//! The file holds an admin private key. Writing it and then hardening it leaves
//! a window — however short — in which it is readable at the process umask, and
//! on a shared host that window is the whole vulnerability. So the file is
//! created empty with its mode already restrictive, and only then written.
//! `pnm`'s bootstrap-secrets path has always done this; the session store did
//! not, which is the inconsistency #1027 names.

use std::path::PathBuf;

use crate::session::SessionBackend;

pub(crate) struct FileBackend {
    pub(crate) sessions_dir: PathBuf,
    /// How this backend came to be selected, for the one-time notice. Always an
    /// explicit choice — there is no fallback path into here.
    pub(crate) reason: &'static str,
}

impl FileBackend {
    fn sessions_path(&self) -> PathBuf {
        self.sessions_dir.join("sessions.json")
    }

    /// Announce plaintext storage once per process, not once per access.
    ///
    /// The previous implementation printed on every `load` and `save`, which
    /// trained everyone to ignore it.
    fn notice_once(&self) {
        use std::sync::Once;
        static NOTICE: Once = Once::new();
        let reason = self.reason;
        let path = self.sessions_path();
        NOTICE.call_once(|| {
            eprintln!(
                "note: sessions are stored as plaintext at mode 0600 in {} \
                 (selected by {reason}).",
                path.display()
            );
        });
    }

    fn load_map(&self) -> std::collections::HashMap<String, serde_json::Value> {
        let path = self.sessions_path();
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return std::collections::HashMap::new();
            }
            Err(e) => {
                tracing::warn!("failed to read sessions file {}: {e}", path.display());
                return std::collections::HashMap::new();
            }
        };
        match serde_json::from_str(&data) {
            Ok(map) => map,
            Err(e) => {
                tracing::warn!("failed to parse sessions file {}: {e}", path.display());
                std::collections::HashMap::new()
            }
        }
    }

    fn save_map(
        &self,
        map: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = self.sessions_path();
        let json = serde_json::to_string_pretty(map)?;
        create_owner_only(&path)?;
        std::fs::write(&path, json)?;
        Ok(())
    }
}

/// Create the sessions directory owner-only (`0700`).
///
/// A `0600` file inside a world-traversable directory is fine on its own, but
/// the directory listing leaks which VTAs an operator holds sessions for, and a
/// group-writable directory lets someone swap the file underneath us.
fn create_dir_owner_only(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(dir)?.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(dir, perms)?;
    }
    Ok(())
}

/// Ensure the sessions file exists at mode `0600` *before* anything is written
/// into it.
///
/// `std::fs::write` on a fresh path creates at `0666 & !umask`, which on a
/// default umask is world-readable. Pre-creating with an explicit mode closes
/// that, and re-asserting the mode on an existing file repairs one written by
/// an older build.
fn create_owner_only(path: &std::path::Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_owner_only(parent)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        // `.mode()` applies only on creation, so an existing file keeps
        // whatever it had — including a world-readable mode from a build
        // before this hardening. Re-assert it.
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    #[cfg(not(unix))]
    {
        // Windows: the file inherits the parent directory's ACL, and the
        // per-user config dir is already user-scoped. `vti_common::secure_file`
        // holds the explicit-ACL treatment for the paths that need it; the SDK
        // is a leaf crate and cannot reach it.
        if !path.exists() {
            std::fs::File::create(path)?;
        }
    }

    Ok(())
}

impl SessionBackend for FileBackend {
    fn load(&self, key: &str) -> Option<String> {
        self.notice_once();
        let map = self.load_map();
        map.get(key).map(|v| v.to_string())
    }

    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.notice_once();
        let mut map = self.load_map();
        let parsed: serde_json::Value = serde_json::from_str(value)?;
        map.insert(key.to_string(), parsed);
        self.save_map(&map)
    }

    fn clear(&self, key: &str) {
        let mut map = self.load_map();
        map.remove(key);
        let _ = self.save_map(&map);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(p: &std::path::Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// The point of the whole change: an admin private key must never land in a
    /// world-readable file, not even for the instant between write and chmod.
    #[test]
    fn a_saved_session_is_owner_only() {
        let dir = std::env::temp_dir().join(format!("vta-sdk-file-backend-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let backend = FileBackend {
            sessions_dir: dir.clone(),
            reason: "a test",
        };

        backend.save("k", r#"{"private_key":"secret"}"#).unwrap();

        assert_eq!(
            mode_of(&backend.sessions_path()),
            0o600,
            "file must be 0600"
        );
        assert_eq!(mode_of(&dir), 0o700, "directory must be 0700");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A sessions file written by a build from before this hardening is
    /// repaired on the next write rather than left permanently exposed.
    #[test]
    fn an_existing_world_readable_file_is_repaired() {
        let dir = std::env::temp_dir().join(format!(
            "vta-sdk-file-backend-legacy-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sessions.json");
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(mode_of(&path), 0o644, "precondition: starts world-readable");

        let backend = FileBackend {
            sessions_dir: dir.clone(),
            reason: "a test",
        };
        backend.save("k", r#"{"private_key":"secret"}"#).unwrap();

        assert_eq!(
            mode_of(&path),
            0o600,
            "an existing file must be re-hardened"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
