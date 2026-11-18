//! `pnm did-mgmt agent-names …` dispatch.
//!
//! The implementations live in `vta_cli_common::commands::agent_names` so
//! `cnm` can adopt the same surface without duplication.

use vta_sdk::prelude::*;

/// Dispatch `pnm did-mgmt agent-names …`.
pub async fn run(
    client: &VtaClient,
    command: crate::cli::DidMgmtAgentNameCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::cli::DidMgmtAgentNameCommands as C;
    match command {
        C::Set { did, name } => {
            vta_cli_common::commands::agent_names::cmd_agent_name_set(client, &did, &name).await
        }
        C::Remove { did, name, yes } => {
            if !vta_cli_common::confirm::confirm_or_cancel(
                &format!("release the name `{name}` so any DID may claim it"),
                yes,
            )? {
                return Ok(());
            }
            vta_cli_common::commands::agent_names::cmd_agent_name_remove(client, &did, &name).await
        }
        C::Disable { did, name } => {
            vta_cli_common::commands::agent_names::cmd_agent_name_disable(client, &did, &name).await
        }
        C::Enable { did, name } => {
            vta_cli_common::commands::agent_names::cmd_agent_name_enable(client, &did, &name).await
        }
        C::List { did } => {
            vta_cli_common::commands::agent_names::cmd_agent_name_list(client, &did).await
        }
        C::Check { did, name } => {
            vta_cli_common::commands::agent_names::cmd_agent_name_check(client, &did, &name).await
        }
    }
}
