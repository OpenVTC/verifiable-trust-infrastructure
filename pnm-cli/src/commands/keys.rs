//! Dispatch for `pnm keys …`.

use vta_cli_common::commands::keys;
use vta_cli_common::sealed_producer::resolve_recipient;
use vta_sdk::client::VtaClient;

use crate::cli::KeyCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: KeyCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        KeyCommands::Create {
            key_type,
            derivation_path,
            mnemonic,
            label,
            context_id,
            internal,
            yes,
        } => {
            keys::cmd_key_create(
                client,
                &key_type,
                derivation_path,
                mnemonic,
                label,
                context_id,
                internal,
                yes,
            )
            .await
        }
        KeyCommands::Import {
            key_type,
            private_key,
            private_key_file,
            label,
            context_id,
        } => {
            keys::cmd_key_import(
                client,
                &key_type,
                private_key,
                private_key_file,
                label,
                context_id,
            )
            .await
        }
        KeyCommands::Get { key_id, secret } => keys::cmd_key_get(client, &key_id, secret).await,
        KeyCommands::Revoke { key_id } => keys::cmd_key_revoke(client, &key_id).await,
        KeyCommands::Rename { key_id, new_key_id } => {
            keys::cmd_key_rename(client, &key_id, &new_key_id).await
        }
        KeyCommands::List {
            limit,
            offset,
            status,
            context,
        } => keys::cmd_key_list(client, offset, limit, status, context).await,
        KeyCommands::Secrets { key_ids, context } => {
            keys::cmd_key_secrets(client, key_ids, context).await
        }
        KeyCommands::Bundle {
            context,
            recipient,
            recipient_did,
            recipient_nonce,
        } => match resolve_recipient(
            recipient.as_deref(),
            recipient_did.as_deref(),
            recipient_nonce.as_deref(),
        ) {
            Ok(recipient) => keys::cmd_key_bundle(client, &context, recipient).await,
            Err(e) => Err(e),
        },
        KeyCommands::Seeds => keys::cmd_seeds_list(client).await,
        KeyCommands::RotateSeed { mnemonic } => keys::cmd_seeds_rotate(client, mnemonic).await,
    }
}
