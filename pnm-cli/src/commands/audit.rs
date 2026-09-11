//! Dispatch for `pnm audit …`.

use vta_cli_common::commands::audit;
use vta_sdk::client::VtaClient;

use crate::cli::{AuditCommands, RetentionCommands};

pub(crate) async fn run(
    client: &VtaClient,
    command: AuditCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        AuditCommands::List {
            from,
            to,
            action,
            actor,
            outcome,
            context_id,
            cursor,
            page_size,
        } => {
            let params = vta_sdk::protocols::audit_management::list::ListAuditLogsBody {
                from,
                to,
                action,
                actor,
                outcome,
                context_id,
                cursor,
                page_size,
            };
            audit::cmd_list_audit_logs(client, &params).await
        }
        AuditCommands::Retention { command } => match command {
            RetentionCommands::Get => audit::cmd_get_retention(client).await,
            RetentionCommands::Set { days } => audit::cmd_update_retention(client, days).await,
        },
    }
}
