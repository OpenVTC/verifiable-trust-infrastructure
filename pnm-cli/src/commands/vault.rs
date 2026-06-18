//! `pnm vault …` dispatch — thin shim over the shared vault commands.
//!
//! File-based inputs keep intricate wire shapes (entry fields, secrets,
//! site targets, proxy-login / sign-trust-task requests) out of the flag
//! surface: each `--*-file` is read here into a `serde_json::Value` and handed
//! to the shared command. Pass `-` to read from stdin.

use std::io::Read;

use vta_cli_common::commands::vault as v;
use vta_sdk::prelude::*;

use crate::cli::VaultCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: VaultCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        VaultCommands::List {
            filters_file,
            status,
        } => {
            let filters = filters_file.as_deref().map(read_json).transpose()?;
            v::cmd_vault_list(client, filters, status).await
        }
        VaultCommands::Get { id } => v::cmd_vault_get(client, id).await,
        VaultCommands::Delete {
            id,
            expected_version,
            force,
            reason,
        } => v::cmd_vault_delete(client, id, expected_version, force, reason).await,
        VaultCommands::Archive {
            id,
            expected_version,
            reason,
        } => v::cmd_vault_archive(client, id, expected_version, reason).await,
        VaultCommands::Unarchive {
            id,
            expected_version,
            reason,
        } => v::cmd_vault_unarchive(client, id, expected_version, reason).await,
        VaultCommands::Restore {
            id,
            expected_version,
            reason,
        } => v::cmd_vault_restore(client, id, expected_version, reason).await,
        VaultCommands::Purge {
            id,
            expected_version,
            reason,
        } => v::cmd_vault_purge(client, id, expected_version, reason).await,
        VaultCommands::Upsert {
            entry_file,
            secret_file,
        } => {
            let entry = read_json(&entry_file)?;
            let secret = secret_file.as_deref().map(read_json).transpose()?;
            v::cmd_vault_upsert(client, entry, secret).await
        }
        VaultCommands::Release { id, target_file } => {
            let target = target_file.as_deref().map(read_json).transpose()?;
            v::cmd_vault_release(client, id, target).await
        }
        VaultCommands::ProxyLogin { file } => {
            let payload = read_json(&file)?;
            v::cmd_vault_proxy_login(client, payload).await
        }
        VaultCommands::SignTrustTask { file } => {
            let payload = read_json(&file)?;
            v::cmd_vault_sign_trust_task(client, payload).await
        }
    }
}

/// Read a JSON document from a file path, or stdin when `path` is `-`.
fn read_json(path: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let contents = if path == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?
    };
    serde_json::from_str(&contents).map_err(|e| format!("{path}: invalid JSON: {e}").into())
}
