//! Dispatch for `pnm backup …`.
//!
//! Both export and import prompt interactively for the encryption
//! password (Argon2id KDF, ≥15 chars). `--preview` on import skips the
//! destructive write so an operator can inspect a backup before
//! committing.

use vta_cli_common::render::{DIM, GREEN, RED, RESET};
use vta_cli_common::secure_file;
use vta_sdk::client::{SurfaceTransport, TransferProgress, VtaClient};
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
            force,
            use_rest_legacy,
        } => {
            if let Some(path) = &output {
                secure_file::check_export_path(path, force)?;
            }
            if use_rest_legacy {
                warn_legacy_over_mediator(client);
                cmd_backup_export(client, include_audit, output, force).await
            } else {
                cmd_backup_export_descriptor(client, include_audit, output, force).await
            }
        }
        BackupCommands::Import {
            file,
            preview,
            use_rest_legacy,
        } => {
            if use_rest_legacy {
                warn_legacy_over_mediator(client);
                cmd_backup_import(client, file, preview).await
            } else {
                cmd_backup_import_descriptor(client, file, preview).await
            }
        }
    }
}

/// `--use-rest-legacy` is only REST when the client is.
///
/// The legacy calls ride the protocol-message surface, so on a DIDComm client
/// the flag silently sent the whole backup envelope as one DIDComm message.
/// A mediator refuses anything over its `message_size` limit (1 MiB by
/// default, and DIDComm's base64 layers leave roughly half of that for the
/// envelope), so for any real VTA the reply never arrives and the CLI waits out
/// its timeout with no explanation. The flag is kept, and a small VTA may still
/// fit, so this warns rather than refuses — but it says what is actually
/// happening and how to get what the flag name promises.
fn warn_legacy_over_mediator(client: &VtaClient) {
    let surface = client.protocol_message_transport();
    if let Some(warning) = legacy_over_mediator_warning(surface) {
        eprintln!("{RED}warning:{RESET} {warning}");
    }
}

fn legacy_over_mediator_warning(surface: SurfaceTransport) -> Option<String> {
    match surface {
        SurfaceTransport::Rest => None,
        other => Some(format!(
            "`--use-rest-legacy` is not using REST: this client reaches the VTA over \
             {other}, so the whole backup travels as a single mediator message. A \
             mediator refuses messages over its size limit (1 MiB by default, roughly \
             half of that usable after DIDComm encoding), so this fails — usually as a \
             timeout — for all but very small VTAs. Drop the flag: the default flow \
             moves the backup in verified chunks over {other}. Or re-run with \
             `--transport rest` for an actual REST transfer."
        )),
    }
}

#[allow(deprecated)] // the `--use-rest-legacy` escape hatch; removed at rollout step 6
async fn cmd_backup_export(
    client: &VtaClient,
    include_audit: bool,
    output: Option<std::path::PathBuf>,
    force: bool,
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
        let slug = secure_file::did_filename_slug(envelope.source_did.as_deref(), "vta");
        std::path::PathBuf::from(format!("vta-backup-{slug}-{ts}.vtabak"))
    });

    let json = serde_json::to_string_pretty(&envelope)?;
    // Owner-only (0600), and never silently over an existing file.
    secure_file::write_secret_export(&path, json.as_bytes(), force)?;

    println!("{GREEN}✓{RESET} Backup saved to {}", path.display());
    println!(
        "  Source DID: {}",
        envelope.source_did.as_deref().unwrap_or("(none)")
    );
    println!("  Includes audit: {}", envelope.includes_audit);
    println!("  File size: {} bytes", json.len());
    Ok(())
}

#[allow(deprecated)] // the `--use-rest-legacy` escape hatch; removed at rollout step 6
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

    // The floor binds on the way in too, so check it here rather than let the
    // refusal arrive as a schema-conformance error naming a task URI.
    let password = dialoguer::Password::new()
        .with_prompt(format!(
            "Backup password (min {MIN_BACKUP_PASSWORD_LEN} chars)"
        ))
        .interact()?;
    validate_backup_password(&password)?;

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
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let password = dialoguer::Password::new()
        .with_prompt(format!(
            "Backup password (min {MIN_BACKUP_PASSWORD_LEN} chars)"
        ))
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()?;
    validate_backup_password(&password)?;

    let surface = client.trust_task_transport();
    println!("Exporting backup ({})...", flow_label(surface));
    let bytes = client
        .backup_export_with_progress(&password, include_audit, &mut progress_line("received"))
        .await;
    finish_progress_line(surface);
    let bytes = bytes?;

    // Bytes are the JSON-serialised `BackupEnvelope`; inflate just
    // enough to surface the source DID + audit flag for the user.
    let envelope: vta_sdk::protocols::backup_management::types::BackupEnvelope =
        serde_json::from_slice(&bytes)?;

    let path = output.unwrap_or_else(|| {
        let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let slug = secure_file::did_filename_slug(envelope.source_did.as_deref(), "vta");
        std::path::PathBuf::from(format!("vta-backup-{slug}-{ts}.vtabak"))
    });

    // Owner-only (0600), and never silently over an existing file.
    secure_file::write_secret_export(&path, &bytes, force)?;

    println!("{GREEN}✓{RESET} Backup saved to {}", path.display());
    println!(
        "  Source DID: {}",
        envelope.source_did.as_deref().unwrap_or("(none)")
    );
    println!("  Includes audit: {}", envelope.includes_audit);
    println!("  File size: {} bytes", bytes.len());
    println!("{DIM}  Flow: {}{RESET}", flow_detail(surface));
    Ok(())
}

/// What the operator is told the transfer is using. The algorithm follows the
/// client's Trust-Task transport, which follows what the VTA advertises.
fn flow_label(surface: SurfaceTransport) -> String {
    match surface {
        SurfaceTransport::Rest => "trust-task descriptor flow, HTTPS stream".into(),
        other => format!("trust-task descriptor flow, chunked over {other}"),
    }
}

fn flow_detail(surface: SurfaceTransport) -> &'static str {
    match surface {
        SurfaceTransport::Rest => {
            "trust-task descriptor, `stream` (one-shot bearer token, bytes deleted server-side)"
        }
        _ => {
            "trust-task descriptor, `chunkedTrustTask` (each chunk verified, bundle released on completion)"
        }
    }
}

/// A progress reporter for a chunked transfer: one line on stderr, rewritten
/// in place. Called only by the chunked path, so a `stream` transfer prints
/// nothing extra.
fn progress_line(verb: &'static str) -> impl FnMut(TransferProgress) + Send {
    move |p: TransferProgress| {
        eprint!(
            "\r  {verb} chunk {}/{} ({} / {})",
            p.chunks_done,
            p.chunks_total,
            human_bytes(p.bytes_done),
            human_bytes(p.bytes_total)
        );
        let _ = std::io::Write::flush(&mut std::io::stderr());
    }
}

/// End the in-place progress line, if one was drawn.
fn finish_progress_line(surface: SurfaceTransport) {
    if surface != SurfaceTransport::Rest {
        eprintln!();
    }
}

fn human_bytes(n: u64) -> String {
    const KIB: f64 = 1024.0;
    let n = n as f64;
    if n < KIB {
        format!("{n} B")
    } else if n < KIB * KIB {
        format!("{:.1} KiB", n / KIB)
    } else {
        format!("{:.1} MiB", n / (KIB * KIB))
    }
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

    // The floor binds on the way in too, so check it here rather than let the
    // refusal arrive as a schema-conformance error naming a task URI.
    let password = dialoguer::Password::new()
        .with_prompt(format!(
            "Backup password (min {MIN_BACKUP_PASSWORD_LEN} chars)"
        ))
        .interact()?;
    validate_backup_password(&password)?;

    // Preview run: confirm=false. This uploads the bytes; the commit below
    // re-runs finalize against the same bundle. Each finalize call reads the
    // staged bytes server-side; the state machine allows preview → commit.
    let surface = client.trust_task_transport();
    println!("Validating backup ({})...", flow_label(surface));
    let preview = client
        .backup_import_with_progress(&bytes, &password, false, &mut progress_line("sent"))
        .await;
    finish_progress_line(surface);
    let preview = preview?;
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

    // Commit run: confirm=true, against the bundle the preview already
    // uploaded — a previewed bundle accepts the commit, so the bytes do not
    // cross the wire twice. The slot is short-lived (5 minutes), though, and
    // the confirmation prompt above waits on a human. A slot the sweeper has
    // already collected answers not-found, and only then is the full
    // initiate → upload → finalize sequence re-run.
    //
    // A conflict is deliberately NOT retried that way. It covers both an
    // expired-but-not-yet-collected slot and "already committed", and the two
    // cannot be told apart without parsing prose. Re-uploading and committing
    // after the second would apply the backup twice — commit is not idempotent
    // (`vta/backup/finalize-import` §"Why commit is not idempotent") — so the
    // operator is told to re-run instead.
    println!("Importing...");
    let result = match client
        .backup_finalize_import(&preview.bundle_id, &password, true)
        .await
    {
        Ok(result) => result,
        Err(vta_sdk::error::VtaError::NotFound(_)) => {
            println!("{DIM}  Upload slot expired during confirmation; uploading again...{RESET}");
            let result = client
                .backup_import_with_progress(&bytes, &password, true, &mut progress_line("sent"))
                .await;
            finish_progress_line(surface);
            result?
        }
        Err(e @ vta_sdk::error::VtaError::Conflict(_)) => {
            eprintln!(
                "{RED}error:{RESET} the previewed bundle can no longer be committed ({e}). \
                 If the confirmation took longer than the 5-minute upload slot, re-run \
                 `pnm backup import {}`; nothing was applied by this attempt unless the \
                 message says the bundle was already committed.",
                file.display()
            );
            return Err(e.into());
        }
        Err(e) => return Err(e.into()),
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flow_names_the_algorithm_the_transport_selects() {
        assert!(flow_label(SurfaceTransport::Rest).contains("stream"));
        assert!(flow_label(SurfaceTransport::Didcomm).contains("chunked over DIDComm"));
        assert!(flow_label(SurfaceTransport::Tsp).contains("chunked over TSP"));
    }

    #[test]
    fn progress_sizes_are_human_readable() {
        assert_eq!(human_bytes(12), "12 B");
        assert_eq!(human_bytes(262_144), "256.0 KiB");
        assert_eq!(human_bytes(3 * 1024 * 1024), "3.0 MiB");
    }

    #[test]
    fn legacy_flag_is_silent_on_a_rest_client() {
        assert!(legacy_over_mediator_warning(SurfaceTransport::Rest).is_none());
    }

    #[test]
    fn legacy_flag_warns_with_the_size_caveat_on_a_mediator_client() {
        for surface in [SurfaceTransport::Didcomm, SurfaceTransport::Tsp] {
            let w = legacy_over_mediator_warning(surface).expect("a warning");
            assert!(w.contains("1 MiB"), "{w}");
            assert!(w.contains("--transport rest"), "{w}");
            assert!(w.contains("Drop the flag"), "{w}");
        }
    }
}
