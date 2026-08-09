//! `pnm approvals …` dispatch — thin shim over the shared approvals commands.

use vta_cli_common::commands::approvals as ap;
use vta_sdk::approvals::Requires;
use vta_sdk::prelude::*;

use crate::cli::{ApprovalsCommands, ApproversCommands};

pub(crate) async fn run(
    client: &VtaClient,
    command: ApprovalsCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        ApprovalsCommands::List => ap::cmd_list(client).await,
        ApprovalsCommands::Require {
            task_type,
            reauth,
            consent,
            set,
            min,
            exclude_requester,
            context,
        } => {
            // clap enforces that the two are mutually exclusive and that
            // --consent brings --set; it cannot enforce that *one* was given,
            // and defaulting silently would pick a security posture for the
            // operator.
            let requires = match (reauth, consent) {
                (true, false) => Requires::Reauth,
                (false, true) => Requires::Consent,
                _ => {
                    return Err("pass exactly one of --reauth or --consent".into());
                }
            };
            ap::cmd_require(
                client,
                task_type,
                requires,
                set,
                min,
                exclude_requester,
                context,
            )
            .await
        }
        ApprovalsCommands::Remove { task_type, context } => {
            ap::cmd_remove(client, task_type, context).await
        }
        ApprovalsCommands::Approvers { command } => match command {
            ApproversCommands::Add { set, did } => ap::cmd_approver_add(client, set, did).await,
            ApproversCommands::Remove { set, did } => {
                ap::cmd_approver_remove(client, set, did).await
            }
        },
        ApprovalsCommands::Explain { task_type, context } => {
            ap::cmd_explain(client, task_type, context).await
        }
    }
}
