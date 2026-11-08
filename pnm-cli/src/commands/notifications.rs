//! `pnm notifications …` dispatch — thin shim over the shared notification commands
//! (`vta_cli_common::commands::notifications`).

use vta_cli_common::commands::notifications::{self, ListOptions};
use vta_sdk::client::VtaClient;

use crate::cli::NotificationsCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: NotificationsCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        NotificationsCommands::List {
            context,
            kind,
            held_by,
            include_dismissed,
            include_lapsed,
            limit,
            cursor,
        } => {
            let opts = ListOptions {
                kind,
                held_by,
                include_dismissed,
                include_lapsed,
                limit,
                cursor,
            };
            notifications::cmd_notifications_list(client, &context, &opts).await
        }
        NotificationsCommands::Show { record_id, context } => {
            notifications::cmd_notifications_show(client, &context, &record_id).await
        }
        NotificationsCommands::Dismiss { record_id, context } => {
            notifications::cmd_notifications_dismiss(client, &context, &record_id).await
        }
        NotificationsCommands::Deposit { file, context } => {
            notifications::cmd_notifications_deposit(client, &context, &file).await
        }
    }
}
