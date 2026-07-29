//! Dispatch for `pnm backup …`.
//!
//! Both export and import prompt interactively for the encryption
//! password (Argon2id KDF, ≥15 chars). `--preview` on import skips the
//! destructive write so an operator can inspect a backup before
//! committing.

use vta_cli_common::render::{DIM, GREEN, RED, RESET};
use vta_sdk::client::VtaClient;
use vta_sdk::protocols::backup_management::{MIN_BACKUP_PASSWORD_LEN, validate_backup_password};

use crate::cli::BackupCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: BackupCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        BackupCommands::Export {
            include_audit,
            output,
            use_trust_task,
        } => {
            if use_trust_task {
                cmd_backup_export_descriptor(client, include_audit, output).await
            } else {
                cmd_backup_export(client, include_audit, output).await
            }
        }
        BackupCommands::Import {
            file,
            preview,
            use_trust_task,
        } => {
            if use_trust_task {
                cmd_backup_import_descriptor(client, file, preview).await
            } else {
                cmd_backup_import(client, file, preview).await
            }
        }
    }
}

async fn cmd_backup_export(
    client: &VtaClient,
    include_audit: bool,
    output: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prompt for password
    let password = dialoguer::Password::new()
        .with_prompt(format!(
            "Backup password (min {MIN_BACKUP_PASSWORD_LEN} chars)"
        ))
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()?;
    validate_backup_password(&password)?;

    println!("Exporting backup...");
    let envelope = client.backup_export(&password, include_audit).await?;

    // Determine output path
    let path = output.unwrap_or_else(|| {
        let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let slug = envelope
            .source_did
            .as_deref()
            .and_then(|d| d.rsplit(':').next())
            .unwrap_or("vta");
        std::path::PathBuf::from(format!("vta-backup-{slug}-{ts}.vtabak"))
    });

    let json = serde_json::to_string_pretty(&envelope)?;
    std::fs::write(&path, &json)?;

    println!("{GREEN}✓{RESET} Backup saved to {}", path.display());
    println!(
        "  Source DID: {}",
        envelope.source_did.as_deref().unwrap_or("(none)")
    );
    println!("  Includes audit: {}", envelope.includes_audit);
    println!("  File size: {} bytes", json.len());
    Ok(())
}

async fn cmd_backup_import(
    client: &VtaClient,
    file: std::path::PathBuf,
    preview_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = std::fs::read_to_string(&file)?;
    let envelope: vta_sdk::protocols::backup_management::types::BackupEnvelope =
        serde_json::from_str(&json)?;

    println!("Backup file: {}", file.display());
    println!(
        "  Source DID:  {}",
        envelope.source_did.as_deref().unwrap_or("(none)")
    );
    println!("  Created:     {}", envelope.created_at);
    println!("  Version:     {}", envelope.source_version);
    println!("  Audit:       {}", envelope.includes_audit);

    let password = dialoguer::Password::new()
        .with_prompt("Backup password")
        .interact()?;

    // Preview first
    let preview = client.backup_import(&envelope, &password, false).await?;
    println!();
    println!("  Keys:        {}", preview.key_count);
    println!("  ACL entries: {}", preview.acl_count);
    println!("  Contexts:    {}", preview.context_count);
    println!("  Audit logs:  {}", preview.audit_count);

    if preview_only {
        println!("\n{DIM}Preview only — no changes applied.{RESET}");
        return Ok(());
    }

    // Confirm
    println!();
    println!("{RED}WARNING: This will REPLACE ALL DATA in the VTA.{RESET}");
    print!("Type 'yes' to confirm: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != "yes" {
        println!("Import cancelled.");
        return Ok(());
    }

    println!("Importing...");
    let result = client.backup_import(&envelope, &password, true).await?;
    println!(
        "{GREEN}✓{RESET} {}",
        result.message.as_deref().unwrap_or("Import complete")
    );

    if result.status == "imported" {
        println!("  VTA is restarting with the new identity.");
        println!("  You may need to re-authenticate if the VTA DID changed.");
    }
    Ok(())
}

// ─── Descriptor-pattern variants ──────────────────────────────────────────
//
// Drive the 3-phase ceremony via the trust-task envelope + the
// out-of-band blob endpoint. See
// `docs/05-design-notes/backup-descriptor-pattern.md`. The user-visible
// flow is identical to the legacy paths above; the wire is different.

async fn cmd_backup_export_descriptor(
    client: &VtaClient,
    include_audit: bool,
    output: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let password = dialoguer::Password::new()
        .with_prompt(format!(
            "Backup password (min {MIN_BACKUP_PASSWORD_LEN} chars)"
        ))
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()?;
    validate_backup_password(&password)?;

    println!("Exporting backup (trust-task descriptor flow)...");
    let bytes = client
        .backup_export_via_descriptor(&password, include_audit)
        .await?;

    // Bytes are the JSON-serialised `BackupEnvelope`; inflate just
    // enough to surface the source DID + audit flag for the user.
    let envelope: vta_sdk::protocols::backup_management::types::BackupEnvelope =
        serde_json::from_slice(&bytes)?;

    let path = output.unwrap_or_else(|| {
        let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let slug = envelope
            .source_did
            .as_deref()
            .and_then(|d| d.rsplit(':').next())
            .unwrap_or("vta");
        std::path::PathBuf::from(format!("vta-backup-{slug}-{ts}.vtabak"))
    });

    std::fs::write(&path, &bytes)?;

    println!("{GREEN}✓{RESET} Backup saved to {}", path.display());
    println!(
        "  Source DID: {}",
        envelope.source_did.as_deref().unwrap_or("(none)")
    );
    println!("  Includes audit: {}", envelope.includes_audit);
    println!("  File size: {} bytes", bytes.len());
    println!(
        "{DIM}  Flow: trust-task descriptor (one-shot bearer token, bytes deleted server-side){RESET}"
    );
    Ok(())
}

async fn cmd_backup_import_descriptor(
    client: &VtaClient,
    file: std::path::PathBuf,
    preview_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(&file)?;

    // Surface the envelope's metadata to the operator before
    // prompting for password — same UX as the legacy path.
    let envelope: vta_sdk::protocols::backup_management::types::BackupEnvelope =
        serde_json::from_slice(&bytes)?;

    println!("Backup file: {}", file.display());
    println!(
        "  Source DID:  {}",
        envelope.source_did.as_deref().unwrap_or("(none)")
    );
    println!("  Created:     {}", envelope.created_at);
    println!("  Version:     {}", envelope.source_version);
    println!("  Audit:       {}", envelope.includes_audit);

    let password = dialoguer::Password::new()
        .with_prompt("Backup password")
        .interact()?;

    // Preview run: confirm=false. The descriptor-pattern import
    // ceremony uploads the bytes once and then re-runs finalize
    // with confirm=true for the commit. Each finalize call reads
    // the staged bytes server-side; the state machine allows the
    // preview → commit sequence.
    println!("Validating backup (trust-task descriptor flow)...");
    let preview = client
        .backup_import_via_descriptor(&bytes, &password, false)
        .await?;
    println!();
    println!("  Keys:        {}", preview.key_count);
    println!("  ACL entries: {}", preview.acl_count);
    println!("  Contexts:    {}", preview.context_count);
    println!("  Audit logs:  {}", preview.audit_count);

    if preview_only {
        println!("\n{DIM}Preview only — no changes applied.{RESET}");
        // Best-effort: abort the bundle so it doesn't tie up the
        // per-DID open-bundle cap. Errors are non-fatal.
        let _ = client.backup_abort_bundle(&preview.bundle_id).await;
        return Ok(());
    }

    println!();
    println!("{RED}WARNING: This will REPLACE ALL DATA in the VTA.{RESET}");
    print!("Type 'yes' to confirm: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != "yes" {
        println!("Import cancelled.");
        let _ = client.backup_abort_bundle(&preview.bundle_id).await;
        return Ok(());
    }

    // Commit run: confirm=true. The descriptor-pattern import
    // ceremony re-runs the full initiate → upload → finalize
    // sequence because the SDK helper is one-shot per call. This
    // mirrors the legacy path's "preview then import" idiom; bytes
    // are uploaded twice but the VTA-side cost is just buffer +
    // re-decrypt.
    println!("Importing...");
    let result = client
        .backup_import_via_descriptor(&bytes, &password, true)
        .await?;
    println!(
        "{GREEN}✓{RESET} {}",
        result.message.as_deref().unwrap_or("Import complete")
    );

    if result.status == "committed" {
        println!("  VTA is restarting with the new identity.");
        println!("  You may need to re-authenticate if the VTA DID changed.");
    }
    Ok(())
}
