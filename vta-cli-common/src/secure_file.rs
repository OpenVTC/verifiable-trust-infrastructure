//! Cross-platform file / directory permission tightening for secret-bearing
//! paths (bootstrap seeds, keystores, export bundles).
//!
//! The implementation is homed in [`vti_common::secure_file`] so it can be
//! shared by every consumer (CLIs, services, and the `vti-secrets` crate's
//! plaintext backend) without duplication. This module re-exports it for
//! backwards-compatible `vta_cli_common::secure_file::*` call sites, and adds
//! the CLI-facing helpers the export commands share.

use std::io::ErrorKind;
use std::path::Path;

pub use vti_common::secure_file::{
    restrict_dir_to_owner, restrict_file_to_owner, write_secret_file,
};

/// Longest slug [`did_filename_slug`] returns, so a long DID cannot push a
/// default file name past file-system name limits.
const MAX_SLUG_LEN: usize = 64;

/// Fail early when an explicit export path already exists and `force` is not
/// set.
///
/// Call this before asking the server for the export, so the operator does not
/// enter a password and wait for an export only for the write to be refused.
/// [`write_secret_export`] still makes the authoritative check when it creates
/// the file.
pub fn check_export_path(path: &Path, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    // `symlink_metadata` so a dangling symlink counts as existing, matching
    // what `create_new` will do.
    if !force && std::fs::symlink_metadata(path).is_ok() {
        return Err(already_exists(path));
    }
    Ok(())
}

/// Write a secret-bearing export (such as a backup envelope) to `path`, owner
/// read/write only.
///
/// Wraps [`write_secret_file`], so an existing file is never silently
/// truncated. With `force`, an existing file at `path` is removed first and a
/// new one created in its place; without it, an existing file is an error
/// that names `--force`.
pub fn write_secret_export(
    path: &Path,
    bytes: &[u8],
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if force {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => {
                return Err(
                    format!("could not remove existing file {}: {e}", path.display()).into(),
                );
            }
        }
    }
    write_secret_file(path, bytes).map_err(|e| {
        if e.kind() == ErrorKind::AlreadyExists {
            already_exists(path)
        } else {
            format!("could not write {}: {e}", path.display()).into()
        }
    })
}

fn already_exists(path: &Path) -> Box<dyn std::error::Error> {
    format!(
        "{} already exists. Choose another path with --output, or pass --force to replace it.",
        path.display()
    )
    .into()
}

/// A file-name-safe slug from the last `:`-separated segment of `did`.
///
/// Used for default export file names. The DID comes from a server response,
/// so it is not trusted to be a safe path component: only `[A-Za-z0-9._-]` is
/// kept, the result is capped at 64 characters, and `fallback` is returned when
/// nothing usable is left (no DID, an empty segment, or only dots).
pub fn did_filename_slug(did: Option<&str>, fallback: &str) -> String {
    let slug: String = did
        .and_then(|d| d.rsplit(':').next())
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(MAX_SLUG_LEN)
        .collect();
    if slug.chars().all(|c| c == '.') {
        fallback.to_string()
    } else {
        slug
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vta-test-export-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn slug_keeps_an_ordinary_did_segment() {
        assert_eq!(
            did_filename_slug(Some("did:webvh:QmScid:example.com"), "vtc"),
            "example.com"
        );
        assert_eq!(
            did_filename_slug(Some("did:key:z6MkAbc_1-2"), "vta"),
            "z6MkAbc_1-2"
        );
    }

    #[test]
    fn slug_strips_path_separators_and_other_characters() {
        for did in [
            "did:web:../../x",
            "did:web:..\\..\\x",
            "did:web:a/b c\0d%2Fe",
            "did:web:caf\u{e9}\n",
        ] {
            let slug = did_filename_slug(Some(did), "vtc");
            assert!(
                slug.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')),
                "{did:?} -> {slug:?}"
            );
            let name = format!("vtc-backup-{slug}-20260101.vtcbak");
            assert_eq!(
                Path::new(&name).components().count(),
                1,
                "{did:?} must yield a single path component, got {name:?}"
            );
        }
        assert_eq!(did_filename_slug(Some("did:web:../../x"), "vtc"), "....x");
    }

    #[test]
    fn slug_falls_back_when_nothing_usable_is_left() {
        assert_eq!(did_filename_slug(None, "vta"), "vta");
        assert_eq!(did_filename_slug(Some("did:web:"), "vtc"), "vtc");
        assert_eq!(did_filename_slug(Some("did:web:.."), "vtc"), "vtc");
        assert_eq!(did_filename_slug(Some("did:web:/\\"), "vtc"), "vtc");
    }

    #[test]
    fn slug_is_capped() {
        let did = format!("did:web:{}", "a".repeat(500));
        assert_eq!(did_filename_slug(Some(&did), "vtc").len(), MAX_SLUG_LEN);
    }

    #[test]
    fn export_refuses_an_existing_file_without_force() {
        let dir = tmp_dir();
        let f = dir.join("backup.vtabak");
        std::fs::write(&f, b"original").unwrap();

        assert!(check_export_path(&f, false).is_err());
        let err = write_secret_export(&f, b"new", false).unwrap_err();
        assert!(err.to_string().contains("--force"), "{err}");
        assert_eq!(std::fs::read(&f).unwrap(), b"original");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_replaces_an_existing_file_with_force() {
        let dir = tmp_dir();
        let f = dir.join("backup.vtabak");
        std::fs::write(&f, b"original").unwrap();

        check_export_path(&f, true).unwrap();
        write_secret_export(&f, b"new", true).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&f).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_creates_a_new_file() {
        let dir = tmp_dir();
        let f = dir.join("backup.vtabak");
        check_export_path(&f, false).unwrap();
        write_secret_export(&f, b"data", false).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"data");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
