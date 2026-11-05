//! `pnm collection …` dispatch — thin shim over the shared collection commands
//! (`vta_cli_common::commands::collection`).

use vta_cli_common::commands::collection::{self, ListOptions};
use vta_sdk::client::VtaClient;

use crate::cli::CollectionCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: CollectionCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        CollectionCommands::Status { context } => {
            collection::cmd_collection_status(client, &context).await
        }
        CollectionCommands::Enable { context } => {
            collection::cmd_collection_set(client, &context, true).await
        }
        CollectionCommands::Disable { context } => {
            collection::cmd_collection_set(client, &context, false).await
        }
        CollectionCommands::Claim {
            context,
            identifier,
            duration,
        } => collection::cmd_collection_claim(client, &context, &identifier, duration).await,
        CollectionCommands::Release {
            context,
            identifier,
        } => collection::cmd_collection_release(client, &context, &identifier).await,
        CollectionCommands::List {
            context,
            identifier,
            collector,
            limit,
            cursor,
        } => {
            let opts = ListOptions {
                identifier,
                collector,
                limit,
                cursor,
            };
            collection::cmd_collection_list(client, &context, &opts).await
        }
    }
}
