//! `cnm backup …` — encrypted full-state backup / restore of the VTC
//! community (the P3.9 REST surface).
//!
//! Mirrors `pnm backup` but targets the VTC's `/v1/backup/{export,
//! import}` endpoints, which return a `vtc-backup-v1` envelope. The CLI
//! treats the envelope as **opaque JSON** — it never needs the typed
//! struct, just save/load/forward — so this stays decoupled from the
//! vtc-service crate.
//!
//! Backup is REST-only + super-admin, so we make a direct authenticated
//! POST (forcing REST regardless of the session's preferred transport)
//! and attach the `Trust-Task` header the routes require.

use std::io::Write;
use std::path::PathBuf;

use serde_json::{Value, json};
use vta_cli_common::render::{DIM, GREEN, RED, RESET};
use vta_sdk::client::VtaClient;

use crate::auth;

/// Canonical HTTP header carrying the Trust-Task URL (mirrors
/// `vti_common::trust_task::HEADER_NAME`).
const TRUST_TASK_HEADER: &str = "Trust-Task";
const EXPORT_TASK: &str = "https://trusttasks.org/openvtc/vtc/backup/export/1.0";
const IMPORT_TASK: &str = "https://trusttasks.org/openvtc/vtc/backup/import/1.0";

/// Authenticated REST POST to a VTC `/v1/backup/*` route. `client.rest_url()`
/// already carries the `/v1` mount, so the path here is relative to it.
async fn authed_post(
    client: &VtaClient,
    keyring_key: &str,
    path: &str,
    task: &str,
    body: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let base = client
        .rest_url()
        .ok_or("VTC backup requires a REST connection to the VTC")?;
    // Refresh / mint a REST bearer token for the VTC (aud = "VTC").
    let token = auth::ensure_authenticated(base, keyring_key).await?;
    let resp = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .bearer_auth(&token)
        .header(TRUST_TASK_HEADER, task)
        .json(&body)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        // Surface the server's error body verbatim — it carries the
        // actionable message (short password, vtc_did mismatch, …).
        return Err(format!("VTC backup request failed ({status}): {text}").into());
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("could not parse VTC response: {e} (body: {text})").into())
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("(none)")
}

pub(crate) async fn cmd_export(
    client: &VtaClient,
    keyring_key: &str,
    include_audit: bool,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let password = dialoguer::Password::new()
        .with_prompt("Backup password (min 12 chars)")
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()?;
    if password.len() < 12 {
        return Err("password must be at least 12 characters".into());
    }

    println!("Exporting community backup...");
    let envelope = authed_post(
        client,
        keyring_key,
        "/backup/export",
        EXPORT_TASK,
        json!({ "password": password, "include_audit": include_audit }),
    )
    .await?;

    let source_did = envelope.get("source_did").and_then(Value::as_str);
    let path = output.unwrap_or_else(|| {
        let slug = source_did
            .and_then(|d| d.rsplit(':').next())
            .filter(|s| !s.is_empty())
            .unwrap_or("vtc");
        PathBuf::from(format!(
            "vtc-backup-{slug}-{}.vtcbak",
            file_stamp(&envelope)
        ))
    });

    let json_str = serde_json::to_string_pretty(&envelope)?;
    std::fs::write(&path, &json_str)?;

    println!("{GREEN}✓{RESET} Backup saved to {}", path.display());
    println!("  Source DID:     {}", source_did.unwrap_or("(none)"));
    println!(
        "  Includes audit: {}",
        envelope
            .get("includes_audit")
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
    client: &VtaClient,
    keyring_key: &str,
    file: PathBuf,
    preview_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let json_str = std::fs::read_to_string(&file)?;
    let envelope: Value = serde_json::from_str(&json_str)
        .map_err(|e| format!("{} is not a valid backup file: {e}", file.display()))?;

    println!("Backup file: {}", file.display());
    println!("  Source DID:  {}", str_field(&envelope, "source_did"));
    println!("  Created:     {}", str_field(&envelope, "created_at"));
    println!("  Format:      {}", str_field(&envelope, "format"));
    println!(
        "  Audit:       {}",
        envelope
            .get("includes_audit")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    );

    let password = dialoguer::Password::new()
        .with_prompt("Backup password")
        .interact()?;

    // Preview first (confirm=false) — no mutation, just row counts.
    println!("Validating backup...");
    let preview = authed_post(
        client,
        keyring_key,
        "/backup/import",
        IMPORT_TASK,
        json!({ "backup": envelope, "password": password, "confirm": false }),
    )
    .await?;
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
    let result = authed_post(
        client,
        keyring_key,
        "/backup/import",
        IMPORT_TASK,
        json!({ "backup": envelope, "password": password, "confirm": true }),
    )
    .await?;
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
        .get("created_at")
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

    #[test]
    fn file_stamp_uses_created_at_digits() {
        let env = json!({ "created_at": "2026-06-15T14:30:05Z" });
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
