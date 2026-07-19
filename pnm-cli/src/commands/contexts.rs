//! Dispatch for `pnm contexts …`.

use vta_cli_common::commands::contexts;
use vta_cli_common::sealed_producer::resolve_recipient;
use vta_sdk::client::VtaClient;

use crate::cli::ContextCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: ContextCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        ContextCommands::List => contexts::cmd_context_list(client).await,
        ContextCommands::Get { id } => contexts::cmd_context_get(client, &id).await,
        ContextCommands::Create {
            id,
            name,
            description,
            parent,
            admin_did,
            admin_label,
            admin_expires,
        } => match resolve_admin_acl_options(admin_did, admin_label, admin_expires.as_deref()) {
            Ok(admin) => {
                contexts::cmd_context_create(client, &id, &name, description, parent, admin).await
            }
            Err(e) => Err(e),
        },
        ContextCommands::Update {
            id,
            name,
            did,
            description,
        } => contexts::cmd_context_update(client, &id, name, did, description).await,
        ContextCommands::UpdateDid { id, did } => {
            contexts::cmd_context_update_did(client, &id, &did).await
        }
        ContextCommands::Delete { id, force } => {
            contexts::cmd_context_delete(client, &id, force).await
        }
        ContextCommands::Bootstrap {
            id,
            name,
            description,
            admin_label,
            recipient,
            recipient_did,
            recipient_nonce,
        } => match resolve_recipient(
            recipient.as_deref(),
            recipient_did.as_deref(),
            recipient_nonce.as_deref(),
        ) {
            Ok(recipient) => {
                contexts::cmd_context_bootstrap(
                    client,
                    &id,
                    &name,
                    description,
                    admin_label,
                    recipient,
                )
                .await
            }
            Err(e) => Err(e),
        },
        ContextCommands::Provision {
            id,
            name,
            description,
            admin_label,
            server,
            did_url,
            did_path,
            portable,
            mediator_service,
            pre_rotation,
            recipient,
            recipient_did,
            recipient_nonce,
        } => {
            if server.is_some() && did_url.is_some() {
                Err("--server and --did-url are mutually exclusive".into())
            } else if did_path.is_some() && server.is_none() && did_url.is_none() {
                // No DID is minted without --server/--did-url, so a path
                // label would be silently discarded. Say so rather than
                // provisioning a context the operator thinks is hosted
                // at their chosen path.
                Err("--did-path requires --server or --did-url".into())
            } else {
                let recipient_spec = resolve_recipient(
                    recipient.as_deref(),
                    recipient_did.as_deref(),
                    recipient_nonce.as_deref(),
                );
                match recipient_spec {
                    Ok(recipient) => {
                        let did_opts = match (&server, &did_url) {
                            (None, None) => None,
                            _ => Some(contexts::ProvisionDidOptions {
                                server_id: server,
                                did_url,
                                did_path,
                                portable,
                                add_mediator_service: mediator_service,
                                pre_rotation_count: pre_rotation,
                            }),
                        };
                        contexts::cmd_context_provision(
                            client,
                            &id,
                            &name,
                            description,
                            admin_label,
                            did_opts,
                            recipient,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                }
            }
        }
        ContextCommands::Reprovision {
            id,
            admin_key,
            admin_label,
            recipient,
            recipient_did,
            recipient_nonce,
        } => match resolve_recipient(
            recipient.as_deref(),
            recipient_did.as_deref(),
            recipient_nonce.as_deref(),
        ) {
            Ok(recipient) => {
                contexts::cmd_context_reprovision(client, &id, admin_key, admin_label, recipient)
                    .await
            }
            Err(e) => Err(e),
        },
    }
}

/// Parse `pnm contexts create`'s `--admin-did` / `--admin-label` /
/// `--admin-expires` flags into [`contexts::AdminAclOptions`]. Resolves
/// the duration string to an absolute unix-epoch `expires_at` on the
/// client side so the server just stores the value verbatim.
fn resolve_admin_acl_options(
    admin_did: Option<String>,
    admin_label: Option<String>,
    admin_expires: Option<&str>,
) -> Result<contexts::AdminAclOptions, Box<dyn std::error::Error>> {
    let expires_at = match admin_expires {
        Some(s) => Some(
            vta_cli_common::duration::duration_to_expires_at(s)
                .map_err(|e| format!("--admin-expires: {e}"))?,
        ),
        None => None,
    };
    Ok(contexts::AdminAclOptions {
        did: admin_did,
        label: admin_label,
        expires_at,
        expires_duration: admin_expires.map(str::to_string),
    })
}
