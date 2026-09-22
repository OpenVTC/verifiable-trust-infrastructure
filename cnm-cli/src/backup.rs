//! `cnm backup …` — encrypted full-state backup / restore of the VTC
//! community (the P3.9 REST surface).
//!
//! Mirrors `pnm backup` but targets the VTC's `/v1/backup/{export,
//! import}` endpoints, which return a `vtc-backup-v1` envelope. The CLI
//! treats the envelope as **opaque JSON** — it never needs the typed
//! struct, just save/load/forward — so this stays decoupled from the
//! vtc-service crate.
//!
//! Backup is REST-only and super-admin, so it authenticates to the VTC itself —
//! with the VTC's DID as the audience, as [`crate::vtc`] explains — rather than
//! riding the profile's VTA session.

use std::io::Write;
use std::path::PathBuf;

use serde_json::Value;
use vta_cli_common::render::{DIM, GREEN, RED, RESET, bin_name};
use vta_cli_common::secure_file;
use vta_sdk::protocols::backup_management::{MIN_BACKUP_PASSWORD_LEN, validate_backup_password};

use crate::vtc::{self, Connected, VtcTarget};

/// An operator error for a failed backup call.
fn backup_error(vtc: &Connected, err: vtc_client::VtcError) -> Box<dyn std::error::Error> {
    vtc::super_admin_call_error("VTC backup request", err, &vtc.client_did, bin_name()).into()
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("(none)")
}

pub(crate) async fn cmd_export(
    keyring_key: &str,
    target: &VtcTarget,
    include_audit: bool,
    output: Option<PathBuf>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(path) = &output {
        secure_file::check_export_path(path, force)?;
    }
    let password = dialoguer::Password::new()
        .with_prompt(format!(
            "Backup password (min {MIN_BACKUP_PASSWORD_LEN} chars)"
        ))
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()?;
    validate_backup_password(&password)?;

    let vtc = vtc::connect(keyring_key, target).await?;
    println!("Exporting community backup...");
    let envelope = vtc
        .client
        .export_backup(&password, include_audit)
        .await
        .map_err(|e| backup_error(&vtc, e))?;

    let source_did = envelope.get("sourceDid").and_then(Value::as_str);
    let path = output.unwrap_or_else(|| {
        let slug = secure_file::did_filename_slug(source_did, "vtc");
        PathBuf::from(format!(
            "vtc-backup-{slug}-{}.vtcbak",
            file_stamp(&envelope)
        ))
    });

    let json_str = serde_json::to_string_pretty(&envelope)?;
    // Owner-only (0600), and never silently over an existing file.
    secure_file::write_secret_export(&path, json_str.as_bytes(), force)?;

    println!("{GREEN}✓{RESET} Backup saved to {}", path.display());
    println!("  Source DID:     {}", source_did.unwrap_or("(none)"));
    println!(
        "  Includes audit: {}",
        envelope
            .get("includesAudit")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    );
    println!("  File size:      {} bytes", json_str.len());
    println!(
        "{DIM}  The backup contains the community's signing key — store it like a \
         secret.{RESET}"
    );
    Ok(())
}

pub(crate) async fn cmd_import(
    keyring_key: &str,
    target: &VtcTarget,
    file: PathBuf,
    preview_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let json_str = std::fs::read_to_string(&file)?;
    let envelope: Value = serde_json::from_str(&json_str)
        .map_err(|e| format!("{} is not a valid backup file: {e}", file.display()))?;

    println!("Backup file: {}", file.display());
    println!("  Source DID:  {}", str_field(&envelope, "sourceDid"));
    println!("  Created:     {}", str_field(&envelope, "createdAt"));
    println!("  Format:      {}", str_field(&envelope, "format"));
    println!(
        "  Audit:       {}",
        envelope
            .get("includesAudit")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    );

    // The floor binds on the way in too, so check it here rather than let the
    // refusal arrive as a schema-conformance error naming a task URI.
    let password = dialoguer::Password::new()
        .with_prompt(format!(
            "Backup password (min {MIN_BACKUP_PASSWORD_LEN} chars)"
        ))
        .interact()?;
    validate_backup_password(&password)?;

    // Preview first (confirm=false) — no mutation, just row counts.
    let vtc = vtc::connect(keyring_key, target).await?;
    println!("Validating backup...");
    let preview = vtc
        .client
        .import_backup(&envelope, &password, false)
        .await
        .map_err(|e| backup_error(&vtc, e))?;
    print_counts(&preview);

    if preview_only {
        println!("\n{DIM}Preview only — no changes applied.{RESET}");
        return Ok(());
    }

    println!();
    println!("{RED}WARNING: This will REPLACE ALL community state in the VTC.{RESET}");
    print!("Type 'yes' to confirm: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != "yes" {
        println!("Import cancelled.");
        return Ok(());
    }

    println!("Importing...");
    let result = vtc
        .client
        .import_backup(&envelope, &password, true)
        .await
        .map_err(|e| backup_error(&vtc, e))?;
    println!(
        "{GREEN}✓{RESET} {}",
        result
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Import complete")
    );
    if result.get("status").and_then(Value::as_str) == Some("imported") {
        println!("  Restart the VTC daemon to serve the restored identity.");
        println!("  Browser passkeys are not restored — re-enrol via your admin DID.");
    }
    Ok(())
}

/// Print the per-keyspace row counts from an import preview/result.
fn print_counts(result: &Value) {
    let Some(counts) = result.get("counts").and_then(Value::as_object) else {
        return;
    };
    if counts.is_empty() {
        return;
    }
    println!();
    println!("  Rows by keyspace:");
    for (ks, n) in counts {
        println!("    {ks}: {}", n.as_u64().unwrap_or(0));
    }
}

/// A filename-safe stamp derived from the envelope's `created_at` (the
/// digits of its ISO-8601 timestamp), avoiding a `chrono` dependency.
fn file_stamp(envelope: &Value) -> String {
    let created = envelope
        .get("createdAt")
        .and_then(Value::as_str)
        .unwrap_or("");
    let digits: String = created
        .chars()
        .filter(char::is_ascii_digit)
        .take(14)
        .collect();
    if digits.is_empty() {
        "backup".to_string()
    } else {
        digits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn file_stamp_uses_created_at_digits() {
        let env = json!({ "createdAt": "2026-06-15T14:30:05Z" });
        assert_eq!(file_stamp(&env), "20260615143005");
    }

    #[test]
    fn file_stamp_falls_back_without_timestamp() {
        assert_eq!(file_stamp(&json!({})), "backup");
    }

    #[test]
    fn print_counts_tolerates_missing_or_empty() {
        // Must not panic on a result without counts or with an empty map.
        print_counts(&json!({ "status": "imported" }));
        print_counts(&json!({ "counts": {} }));
    }
}
