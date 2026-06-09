//! Dispatch for `pnm acl …`.

use vta_cli_common::commands::acl;
use vta_sdk::client::VtaClient;

use crate::cli::AclCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: AclCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        AclCommands::List { context } => acl::cmd_acl_list(client, context.as_deref()).await,
        AclCommands::Get { did } => acl::cmd_acl_get(client, &did).await,
        AclCommands::Create {
            did,
            role,
            label,
            contexts,
            expires,
            step_up_approver,
            step_up_require,
        } => match resolve_expires_at(expires.as_deref()) {
            Ok(expires_at) => {
                acl::cmd_acl_create(
                    client,
                    did,
                    role,
                    label,
                    contexts,
                    expires_at,
                    step_up_approver,
                    step_up_require,
                )
                .await
            }
            Err(e) => Err(e),
        },
        AclCommands::Update {
            did,
            role,
            label,
            contexts,
            step_up_approver,
            step_up_require,
        } => {
            acl::cmd_acl_update(
                client,
                &did,
                role,
                label,
                contexts,
                step_up_approver,
                step_up_require,
            )
            .await
        }
        AclCommands::Delete { did } => acl::cmd_acl_delete(client, &did).await,
    }
}

/// Resolve an optional `--expires` duration string (e.g. `24h`, `7d`)
/// to an absolute unix-epoch `expires_at`. Matches the error-prefix
/// style used by `contexts::resolve_admin_acl_options` so CLI messages
/// read consistently.
fn resolve_expires_at(expires: Option<&str>) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    match expires {
        Some(s) => Ok(Some(
            vta_cli_common::duration::duration_to_expires_at(s)
                .map_err(|e| format!("--expires: {e}"))?,
        )),
        None => Ok(None),
    }
}
