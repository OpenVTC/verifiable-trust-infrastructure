//! `pnm external …` dispatch — thin shim over the shared external-account
//! commands in `vta_cli_common::commands::external`.

use vta_cli_common::commands::external::{self as ext, Lifecycle};
use vta_sdk::client::VtaClient;

use crate::cli::ExternalCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: ExternalCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    use ExternalCommands as C;
    match command {
        C::List {
            context,
            state,
            model,
        } => ext::cmd_list(client, &context, state.as_deref(), model.as_deref()).await,
        C::Get { id, context } => ext::cmd_get(client, &context, &id).await,
        C::Create {
            id,
            context,
            label,
            settings,
        } => ext::cmd_create(client, &context, &id, &label, &settings).await,
        C::Update {
            id,
            context,
            label,
            settings,
        } => ext::cmd_update(client, &context, &id, label.as_deref(), settings.as_deref()).await,
        C::SecretSet { id, context } => ext::cmd_secret_set(client, &context, &id).await,
        C::Bind {
            id,
            context,
            consumer,
            prefixes,
            actions,
            max_ttl,
            rate,
        } => {
            ext::cmd_bind(
                client, &context, &id, &consumer, &prefixes, &actions, max_ttl, rate,
            )
            .await
        }
        C::Unbind {
            id,
            context,
            consumer,
        } => ext::cmd_unbind(client, &context, &id, &consumer).await,
        C::Setup { id, context } => ext::cmd_setup(client, &context, &id).await,
        C::Probe { id, context } => ext::cmd_probe(client, &context, &id).await,
        C::Suspend {
            id,
            context,
            reason,
        } => ext::cmd_lifecycle(client, Lifecycle::Suspend, &context, &id, reason.as_deref()).await,
        C::Resume {
            id,
            context,
            reason,
        } => ext::cmd_lifecycle(client, Lifecycle::Resume, &context, &id, reason.as_deref()).await,
        C::Archive {
            id,
            context,
            reason,
        } => ext::cmd_lifecycle(client, Lifecycle::Archive, &context, &id, reason.as_deref()).await,
        C::Restore {
            id,
            context,
            reason,
        } => ext::cmd_lifecycle(client, Lifecycle::Restore, &context, &id, reason.as_deref()).await,
        C::Delete {
            id,
            context,
            reason,
        } => ext::cmd_lifecycle(client, Lifecycle::Delete, &context, &id, reason.as_deref()).await,
        C::Issue {
            account,
            context,
            prefix,
            actions,
            object_key,
            ttl,
        } => {
            ext::cmd_issue(
                client,
                &context,
                &account,
                prefix.as_deref(),
                &actions,
                object_key.as_deref(),
                ttl,
            )
            .await
        }
    }
}
