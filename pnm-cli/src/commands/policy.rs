//! `pnm policy …` dispatch — thin shim over the shared policy commands.

use std::io::Read;

use vta_cli_common::commands::policy as pol;
use vta_sdk::prelude::*;

use crate::cli::PolicyModuleCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: PolicyModuleCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        PolicyModuleCommands::List {
            context,
            enabled_only,
        } => pol::cmd_list(client, context, enabled_only).await,
        PolicyModuleCommands::Show { id } => pol::cmd_show(client, &id).await,
        PolicyModuleCommands::Upsert {
            id,
            name,
            module,
            description,
            context,
            priority,
            disabled,
            expected_version,
        } => {
            let source = read_module(&module)?;
            pol::cmd_upsert(
                client,
                id,
                name,
                source,
                description,
                context,
                priority,
                disabled,
                expected_version,
            )
            .await
        }
        PolicyModuleCommands::Delete {
            id,
            expected_version,
            reason,
        } => pol::cmd_delete(client, &id, expected_version, reason).await,
    }
}

/// Read Rego source from a file path, or stdin when `from` is `-`.
fn read_module(from: &str) -> Result<String, Box<dyn std::error::Error>> {
    if from == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        return Ok(buf);
    }
    std::fs::read_to_string(from).map_err(|e| format!("--module {from}: {e}").into())
}
