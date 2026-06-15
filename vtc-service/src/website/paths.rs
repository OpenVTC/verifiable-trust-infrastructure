//! Filesystem path-safety helpers (§12.1, Phase 5 M5.4.1).
//!
//! Every request to the static handler walks through
//! [`canonical_within_root`]:
//!
//! 1. Decode the request path; reject NUL / control characters.
//! 2. NFC-normalise; reject non-NFC originals.
//! 3. Reject any segment starting with `.` (hidden files).
//! 4. Reject blocklisted extensions (`.cgi` / `.php` / `.exe` by
//!    default).
//! 5. Canonicalise (resolve `.`, `..`, symlinks) against
//!    `root_dir`; reject any result that escapes `root_dir`.
//! 6. Reject regular files with the executable bit set on Unix.
//!
//! The function returns the canonical filesystem path on success
//! so the caller can pass it to the FD cache directly. Path-safety
//! failures surface as typed [`PathError`] values; callers map
//! these into HTTP responses.

use std::path::{Path, PathBuf};

use unicode_normalization::{IsNormalized, UnicodeNormalization, is_nfc_quick};

/// Reasons a request path can fail the safety checks. Mapped to
/// HTTP responses by [`crate::website::serve::serve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// Path contained NUL / control characters.
    ControlChars,
    /// Path bytes were not NFC-normalised.
    NonNfc,
    /// Path component starts with `.` (hidden file).
    Hidden,
    /// Extension matches the configured blocklist.
    BlockedExtension(String),
    /// Canonicalised path escaped `root_dir`.
    Escape,
    /// `std::fs::canonicalize` failed (file not found, broken
    /// symlink, permission denied, etc.).
    NotFound,
    /// File on disk has the executable bit set (Unix).
    ExecBit,
}

/// Validate + canonicalise `request_path` against `root_dir`,
/// applying the full §12.1 safety chain.
///
/// Returns the canonical filesystem path on success; one of the
/// [`PathError`] variants on rejection. **Does not** open the
/// file — that's the FD cache's job.
pub fn canonical_within_root(
    root_dir: &Path,
    request_path: &str,
    executable_blocklist: &[String],
) -> Result<PathBuf, PathError> {
    // Steps 1–4 are the pure-string component checks (control chars,
    // NFC, hidden, blocklist) shared with the create path.
    let trimmed = validate_path_components(request_path, executable_blocklist)?;

    // 5 — canonicalise against root_dir.
    let candidate = root_dir.join(&trimmed);
    let canonical = std::fs::canonicalize(&candidate).map_err(|_| PathError::NotFound)?;
    let root_canonical = std::fs::canonicalize(root_dir).map_err(|_| PathError::NotFound)?;

    if !canonical.starts_with(&root_canonical) {
        return Err(PathError::Escape);
    }

    // 6 — exec bit on regular files (Unix only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = canonical.metadata()
            && meta.is_file()
            && meta.permissions().mode() & 0o111 != 0
        {
            return Err(PathError::ExecBit);
        }
    }

    Ok(canonical)
}

/// Steps 1–4 of the safety chain: the pure-string checks that don't
/// touch the filesystem and so apply equally to a path whose target
/// doesn't exist yet (a `PUT` creating a file). Returns the trimmed,
/// NFC-normalised relative path (no leading `/`) on success.
fn validate_path_components(
    request_path: &str,
    executable_blocklist: &[String],
) -> Result<String, PathError> {
    // 1 — NUL / control char check. Decoded URL paths shouldn't
    //     carry control bytes; surface explicitly so the audit
    //     log records the rejection reason.
    if request_path
        .as_bytes()
        .iter()
        .any(|&b| b < 0x20 || b == 0x7f)
    {
        return Err(PathError::ControlChars);
    }

    // 2 — NFC normalisation. Requests must arrive NFC-normalised;
    //     non-NFC paths can map to different files on
    //     case-insensitive filesystems and on platforms that
    //     normalise differently (macOS HFS+ used NFD historically).
    if is_nfc_quick(request_path.chars()) != IsNormalized::Yes {
        return Err(PathError::NonNfc);
    }

    let nfc: String = request_path.chars().nfc().collect();

    // 3 — hidden-file check. Any component starting with `.` is
    //     refused. `.` and `..` are path-traversal markers, not
    //     hidden files; canonicalisation surfaces a traversal as
    //     `Escape` / `NotFound` instead (the create path rejects
    //     `..` outright — see [`canonical_within_root_for_create`]).
    let trimmed = nfc.trim_start_matches('/');
    for segment in trimmed.split('/') {
        if segment == "." || segment == ".." || segment.is_empty() {
            continue;
        }
        if segment.starts_with('.') {
            return Err(PathError::Hidden);
        }
    }

    // 4 — blocklisted extension check.
    if let Some(dot_idx) = trimmed.rfind('.') {
        let ext = &trimmed[dot_idx..];
        let ext_lower = ext.to_ascii_lowercase();
        if executable_blocklist
            .iter()
            .any(|b| b.eq_ignore_ascii_case(&ext_lower))
        {
            return Err(PathError::BlockedExtension(ext_lower));
        }
    }

    Ok(trimmed.to_string())
}

/// Validate a `PUT` target path against the **full** safety chain
/// *before* any filesystem mutation, returning the (non-canonical,
/// possibly not-yet-existing) target path inside `root_dir`.
///
/// [`canonical_within_root`] requires the target to exist (it
/// `canonicalize`s it), so it can't gate a create. This applies the
/// same component checks (control / NFC / hidden / blocklist), then
/// proves containment without the target existing:
///
/// - `.` / `..` segments are rejected outright (`Escape`) — a create
///   never legitimately traverses.
/// - the **nearest existing ancestor** of the target is canonicalised
///   and must stay within the canonical root, so a symlinked ancestor
///   pointing outside the root is caught before we write or `mkdir`.
///
/// The caller creates the parent and writes only after this returns
/// `Ok`.
pub fn canonical_within_root_for_create(
    root_dir: &Path,
    request_path: &str,
    executable_blocklist: &[String],
) -> Result<PathBuf, PathError> {
    let trimmed = validate_path_components(request_path, executable_blocklist)?;

    // Reject traversal + a directory-valued target (empty final
    // segment). The create path must name a concrete file.
    if trimmed.is_empty() || trimmed.ends_with('/') {
        return Err(PathError::NotFound);
    }
    for segment in trimmed.split('/') {
        if segment == "." || segment == ".." {
            return Err(PathError::Escape);
        }
    }

    let target = root_dir.join(&trimmed);
    let root_canonical = std::fs::canonicalize(root_dir).map_err(|_| PathError::NotFound)?;

    // Walk up from the target to the first ancestor that exists on
    // disk and canonicalise it — that resolves any symlinks in the
    // existing prefix. With no `..` in the path, an ancestor that
    // canonicalises within root guarantees the target does too.
    let mut existing = target.as_path();
    let canonical_ancestor = loop {
        match std::fs::canonicalize(existing) {
            Ok(c) => break c,
            Err(_) => match existing.parent() {
                Some(p) => existing = p,
                // Should be unreachable — root_dir always exists and
                // is an ancestor — but fail closed.
                None => return Err(PathError::Escape),
            },
        }
    };

    if !canonical_ancestor.starts_with(&root_canonical) {
        return Err(PathError::Escape);
    }

    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, write};
    use std::io::Write;

    fn block() -> Vec<String> {
        vec![".cgi".into(), ".php".into(), ".exe".into()]
    }

    fn setup_root() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_path_buf();
        write(root.join("index.html"), "<html></html>").unwrap();
        std::fs::create_dir(root.join("assets")).unwrap();
        write(root.join("assets/logo.png"), [0x89u8, b'P', b'N', b'G']).unwrap();
        write(root.join(".hidden"), "secret").unwrap();
        write(root.join("evil.cgi"), "#!/bin/sh\n").unwrap();
        (dir, root)
    }

    #[test]
    fn happy_path_resolves_within_root() {
        let (_d, root) = setup_root();
        let result = canonical_within_root(&root, "/index.html", &block()).unwrap();
        assert!(result.ends_with("index.html"));
    }

    #[test]
    fn rejects_dotdot_escape() {
        let (_d, root) = setup_root();
        let err =
            canonical_within_root(&root, "/../../etc/passwd", &block()).expect_err("must reject");
        assert!(
            matches!(err, PathError::NotFound | PathError::Escape),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_hidden_file() {
        let (_d, root) = setup_root();
        let err = canonical_within_root(&root, "/.hidden", &block()).expect_err("must reject");
        assert_eq!(err, PathError::Hidden);
    }

    #[test]
    fn rejects_blocklisted_extension() {
        let (_d, root) = setup_root();
        let err = canonical_within_root(&root, "/evil.cgi", &block()).expect_err("must reject");
        assert_eq!(err, PathError::BlockedExtension(".cgi".into()));
    }

    #[test]
    fn rejects_non_nfc() {
        let (_d, root) = setup_root();
        // U+00E9 (NFC `é`) vs U+0065 + U+0301 (NFD `é`). The NFD
        // form is not NFC-normalised; must reject.
        let non_nfc = "/cafe\u{0301}.html";
        let err = canonical_within_root(&root, non_nfc, &block()).expect_err("must reject");
        assert_eq!(err, PathError::NonNfc);
    }

    #[test]
    fn rejects_nul_byte() {
        let (_d, root) = setup_root();
        let err = canonical_within_root(&root, "/index\0.html", &block()).expect_err("must reject");
        assert_eq!(err, PathError::ControlChars);
    }

    #[test]
    fn rejects_nested_hidden_segment() {
        let (_d, root) = setup_root();
        let err =
            canonical_within_root(&root, "/assets/.cache", &block()).expect_err("must reject");
        assert_eq!(err, PathError::Hidden);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_exec_bit_file() {
        use std::os::unix::fs::PermissionsExt;

        let (_d, root) = setup_root();
        let exec_path = root.join("script.bin");
        let mut f = File::create(&exec_path).unwrap();
        f.write_all(b"#!/bin/sh\n").unwrap();
        let mut perms = std::fs::metadata(&exec_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&exec_path, perms).unwrap();

        let err = canonical_within_root(&root, "/script.bin", &block()).expect_err("must reject");
        assert_eq!(err, PathError::ExecBit);
    }

    // ── canonical_within_root_for_create (PUT path) ──────────────

    #[test]
    fn create_allows_new_file_in_existing_dir() {
        let (_d, root) = setup_root();
        let target = canonical_within_root_for_create(&root, "/assets/new.css", &block()).unwrap();
        assert!(target.ends_with("assets/new.css"));
        // Validation must not create anything.
        assert!(!target.exists());
    }

    #[test]
    fn create_allows_new_nested_dir() {
        let (_d, root) = setup_root();
        // The parent dir doesn't exist yet — the create validator must
        // still accept it (the caller mkdirs after).
        let target =
            canonical_within_root_for_create(&root, "/blog/2026/post.html", &block()).unwrap();
        assert!(target.ends_with("blog/2026/post.html"));
        assert!(!root.join("blog").exists(), "validation must not mkdir");
    }

    #[test]
    fn create_rejects_blocklisted_extension() {
        let (_d, root) = setup_root();
        let err = canonical_within_root_for_create(&root, "/evil.php", &block())
            .expect_err("must reject");
        assert_eq!(err, PathError::BlockedExtension(".php".into()));
    }

    #[test]
    fn create_rejects_hidden_target() {
        let (_d, root) = setup_root();
        // `.htaccess`, `.git/config`, etc. — caught by the hidden check.
        for p in ["/.htaccess", "/.git/config", "/assets/.secret"] {
            let err = canonical_within_root_for_create(&root, p, &block()).unwrap_err();
            assert_eq!(err, PathError::Hidden, "path {p}");
        }
    }

    #[test]
    fn create_rejects_control_and_non_nfc() {
        let (_d, root) = setup_root();
        assert_eq!(
            canonical_within_root_for_create(&root, "/x\0.html", &block()).unwrap_err(),
            PathError::ControlChars,
        );
        assert_eq!(
            canonical_within_root_for_create(&root, "/cafe\u{0301}.html", &block()).unwrap_err(),
            PathError::NonNfc,
        );
    }

    #[test]
    fn create_rejects_dotdot_and_creates_nothing() {
        let (_d, root) = setup_root();
        let err = canonical_within_root_for_create(&root, "/../escape/x.html", &block())
            .expect_err("must reject");
        assert_eq!(err, PathError::Escape);
        // The pre-validation `create_dir_all` bug created directories
        // outside the root before rejecting; the validator must touch
        // nothing.
        assert!(!root.parent().unwrap().join("escape").exists());
    }

    #[test]
    fn create_rejects_empty_and_dir_target() {
        let (_d, root) = setup_root();
        assert_eq!(
            canonical_within_root_for_create(&root, "/", &block()).unwrap_err(),
            PathError::NotFound,
        );
        assert_eq!(
            canonical_within_root_for_create(&root, "/assets/", &block()).unwrap_err(),
            PathError::NotFound,
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_rejects_symlinked_ancestor_escape() {
        use std::os::unix::fs::symlink;

        let (_d, root) = setup_root();
        // An attacker-controlled symlink inside root pointing outside
        // it: PUT through it must be rejected by the nearest-existing-
        // ancestor canonicalisation, even though the target file
        // doesn't exist yet.
        let outside = _d.path().parent().unwrap().join("vtc-escape-target");
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.join("link")).unwrap();

        let err = canonical_within_root_for_create(&root, "/link/pwned.html", &block())
            .expect_err("symlinked ancestor must be rejected");
        assert_eq!(err, PathError::Escape);
        assert!(!outside.join("pwned.html").exists());
        let _ = std::fs::remove_dir_all(&outside);
    }
}
