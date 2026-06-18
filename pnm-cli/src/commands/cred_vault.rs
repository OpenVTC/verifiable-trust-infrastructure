//! `pnm cred-vault …` dispatch — thin shim over the shared credential-store
//! commands. `receive`/`query` take a `--*-file` JSON input (`-` for stdin);
//! the lifecycle verbs operate on a credential id.

use std::io::Read;

use vta_cli_common::commands::cred_vault as cv;
use vta_sdk::prelude::*;

use crate::cli::CredVaultCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: CredVaultCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        CredVaultCommands::Receive {
            credential_file,
            id,
        } => {
            let credential = read_json(&credential_file)?;
            cv::cmd_cred_receive(client, credential, id).await
        }
        CredVaultCommands::Query { filter_file } => {
            let filter = read_json(&filter_file)?;
            cv::cmd_cred_query(client, filter).await
        }
        CredVaultCommands::Get { id } => cv::cmd_cred_get(client, id).await,
        CredVaultCommands::Archive { id, reason } => cv::cmd_cred_archive(client, id, reason).await,
        CredVaultCommands::Unarchive { id, reason } => {
            cv::cmd_cred_unarchive(client, id, reason).await
        }
        CredVaultCommands::Delete { id, force, reason } => {
            cv::cmd_cred_delete(client, id, force, reason).await
        }
        CredVaultCommands::Restore { id, reason } => cv::cmd_cred_restore(client, id, reason).await,
        CredVaultCommands::Purge { id, reason } => cv::cmd_cred_purge(client, id, reason).await,
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
