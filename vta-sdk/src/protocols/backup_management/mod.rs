pub mod descriptors;
pub mod types;

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/backup-management/1.0";

pub const EXPORT_BACKUP: &str =
    "https://firstperson.network/protocols/backup-management/1.0/export";
pub const EXPORT_BACKUP_RESULT: &str =
    "https://firstperson.network/protocols/backup-management/1.0/export-result";

pub const IMPORT_BACKUP: &str =
    "https://firstperson.network/protocols/backup-management/1.0/import";
pub const IMPORT_BACKUP_RESULT: &str =
    "https://firstperson.network/protocols/backup-management/1.0/import-result";

// ── Password policy ─────────────────────────────────────────────────────

/// Minimum length of a backup-encryption password, in characters.
///
/// **Single source of truth** for every export-side guard in the workspace:
/// `vta_backup::ops::export_backup`, `vtc_service::backup::export_backup`, and
/// the `pnm` / `cnm` interactive prompts all read this constant rather than
/// repeating the literal. A backup envelope carries the master seed, the
/// BIP-32 key hierarchy, and the ACL, so this password is the only thing
/// between an exfiltrated `.vtabak` and full control of the deployment.
///
/// Enforced **on export only**. Import / decrypt paths deliberately carry no
/// length check, so envelopes written under an older, shorter minimum stay
/// decryptable.
pub const MIN_BACKUP_PASSWORD_LEN: usize = 15;

/// Reject a backup-encryption password shorter than
/// [`MIN_BACKUP_PASSWORD_LEN`], with the message every surface renders.
///
/// Counts **characters** (Unicode scalar values), not bytes. `str::len()`
/// would let a six-character non-ASCII password clear a "15 characters"
/// check, since every non-ASCII scalar occupies 2–4 UTF-8 bytes — the guard
/// would then contradict the error text beside it.
///
/// The `String` error converts into `Box<dyn Error>` for CLI call sites and
/// into `AppError::Validation` for service call sites.
pub fn validate_backup_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_BACKUP_PASSWORD_LEN {
        return Err(format!(
            "backup password must be at least {MIN_BACKUP_PASSWORD_LEN} characters"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod password_tests {
    use super::*;

    #[test]
    fn rejects_below_minimum_and_accepts_the_boundary() {
        // 14 chars — one short.
        let err = validate_backup_password("14-char-passwo").expect_err("14 chars must be short");
        assert!(
            err.contains("15 characters"),
            "error must name the minimum, got: {err}"
        );

        // Exactly 15 — the boundary is inclusive.
        validate_backup_password("15-char-passwor").expect("15 chars is the minimum");
    }

    #[test]
    fn counts_characters_not_bytes() {
        // 10 Cyrillic characters — 20 UTF-8 bytes, so a `len()`-based guard
        // would wave this through as "15 characters".
        let ten_chars = "паролькмоя";
        assert_eq!(ten_chars.chars().count(), 10);
        assert!(ten_chars.len() >= MIN_BACKUP_PASSWORD_LEN);
        assert!(validate_backup_password(ten_chars).is_err());
    }
}
