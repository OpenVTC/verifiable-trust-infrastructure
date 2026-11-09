//! `pnm memory …` dispatch — thin shim over the shared memory commands.
//!
//! The implementations (rendering included) live in
//! `vta_cli_common::commands::memory` so any CLI can adopt the same surface;
//! this module only maps the parsed subcommand onto them.

use vta_cli_common::commands::{memory, memory_history};
use vta_sdk::client::VtaClient;

use crate::cli::MemoryCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: MemoryCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        MemoryCommands::Plant {
            key,
            value,
            context,
        } => memory::cmd_memory_plant(client, &context, &key, &value).await,
        MemoryCommands::Recall { key, context } => {
            memory::cmd_memory_recall(client, &context, key.as_deref()).await
        }
        MemoryCommands::Delete { key, context } => {
            memory::cmd_memory_forget(client, &context, &key).await
        }
        MemoryCommands::Wipe { context, yes } => {
            memory::cmd_memory_wipe(client, &context, yes).await
        }
        MemoryCommands::History {
            context,
            actor,
            from,
            to,
            limit,
        } => {
            let filter = memory_history::HistoryFilter {
                actor,
                from,
                to,
                limit,
            };
            memory_history::cmd_memory_history(client, &context, &filter).await
        }
    }
}
