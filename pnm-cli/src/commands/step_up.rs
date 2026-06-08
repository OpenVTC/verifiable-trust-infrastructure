//! `pnm step-up …` dispatch — thin shim over the shared step-up commands.

use std::io::Read;

use vta_cli_common::commands::step_up as su;
use vta_sdk::prelude::*;

use crate::cli::{PolicyCommands, StepUpCommands};

pub(crate) async fn run(
    client: &VtaClient,
    command: StepUpCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        StepUpCommands::Policy { command } => match command {
            PolicyCommands::Show => su::cmd_policy_show(client).await,
            PolicyCommands::Set { from } => {
                let policy = read_policy(&from)?;
                su::cmd_policy_set(client, policy).await
            }
            PolicyCommands::Disable => su::cmd_policy_disable(client).await,
        },
    }
}

/// Read a policy JSON document from a file path, or stdin when `from` is `-`.
fn read_policy(from: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let contents = if from == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(from).map_err(|e| format!("--from {from}: {e}"))?
    };
    serde_json::from_str(&contents).map_err(|e| format!("--from {from}: invalid JSON: {e}").into())
}
