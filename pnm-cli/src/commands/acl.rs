//! Dispatch for `pnm acl …`.

use vta_cli_common::commands::acl;
use vta_sdk::client::VtaClient;

use crate::cli::AclCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: AclCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        AclCommands::List { context, direction } => {
            acl::cmd_acl_list(client, context.as_deref(), direction.as_deref()).await
        }
        AclCommands::Get { did } => acl::cmd_acl_get(client, &did).await,
        AclCommands::Create {
            did,
            did_flag,
            role,
            label,
            contexts,
            expires,
            handoff,
            step_up_approver,
            step_up_require,
            approve_all,
            approve_contexts,
            allowed_keys,
            capabilities,
            purposes,
        } => match resolve_expires_at(expires.as_deref()) {
            Ok(expires_at) => {
                let purposes = match acl::purposes_from_flags(purposes, false) {
                    Ok(p) => p,
                    Err(e) => return Err(e),
                };
                acl::cmd_acl_create(
                    client,
                    did.or(did_flag).ok_or("a DID is required")?,
                    role,
                    label,
                    contexts,
                    expires_at,
                    step_up_approver,
                    step_up_require,
                    approve_all,
                    approve_contexts,
                    allowed_keys,
                    capabilities,
                    handoff,
                    purposes,
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
            approve_all,
            approve_contexts,
            approve_none,
            allowed_keys,
            allowed_keys_unrestricted,
            capabilities,
            capabilities_all,
            purposes,
            purposes_any,
            reason,
        } => {
            let purposes = acl::purposes_from_flags(purposes, purposes_any)?;
            let approve_scope =
                acl::approve_scope_from_flags(approve_all, approve_contexts, approve_none);
            let allowed_keys =
                acl::allowed_keys_from_flags(allowed_keys, allowed_keys_unrestricted);
            let capabilities = acl::capabilities_from_flags(capabilities, capabilities_all);
            acl::cmd_acl_update(
                client,
                &did,
                role,
                label,
                contexts,
                step_up_approver,
                step_up_require,
                approve_scope,
                allowed_keys,
                capabilities,
                purposes,
                reason.as_deref(),
            )
            .await
        }
        AclCommands::ChangeRole {
            did,
            did_flag,
            from_role,
            to_role,
            reason,
        } => {
            let did = did.or(did_flag).ok_or("a DID is required")?;
            acl::cmd_acl_change_role(client, &did, &from_role, &to_role, reason).await
        }
        AclCommands::Delete { did, reason, yes } => {
            acl::cmd_acl_delete(client, &did, reason.as_deref(), yes).await
        }
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
