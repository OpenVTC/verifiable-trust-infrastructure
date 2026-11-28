//! `pnm calendar …` dispatch — thin shim over the shared calendar commands
//! (`vta_cli_common::commands::calendar`).

use vta_cli_common::commands::calendar::{self as cal, FeedCreate, ListOptions, SettingsUpdate};
use vta_sdk::client::VtaClient;

use crate::cli::{
    CalendarAlertsCommands, CalendarCommands, CalendarFeedsCommands, CalendarSettingsCommands,
};

pub(crate) async fn run(
    client: &VtaClient,
    command: CalendarCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        CalendarCommands::List {
            contexts,
            from,
            to,
            tiers,
            limit,
            cursor,
        } => {
            let opts = ListOptions {
                contexts,
                from,
                to,
                tiers,
                limit,
                cursor,
            };
            cal::cmd_calendar_list(client, &opts).await
        }
        CalendarCommands::Sync { context } => {
            cal::cmd_calendar_sync(client, context.as_deref()).await
        }
        CalendarCommands::Settings { command } => match command {
            CalendarSettingsCommands::Show { context } => {
                cal::cmd_calendar_settings_show(client, &context).await
            }
            CalendarSettingsCommands::Update {
                context,
                sync,
                default_reminders,
                quiet,
                time_zone,
            } => {
                let upd = SettingsUpdate {
                    sync,
                    default_reminders,
                    quiet,
                    time_zone,
                };
                cal::cmd_calendar_settings_update(client, &context, &upd).await
            }
        },
        CalendarCommands::Alerts { command } => match command {
            CalendarAlertsCommands::Set {
                event_id,
                community,
                context,
                minutes,
            } => {
                cal::cmd_calendar_alerts_set(client, &context, &community, &event_id, &minutes)
                    .await
            }
            CalendarAlertsCommands::Clear {
                event_id,
                community,
                context,
            } => cal::cmd_calendar_alerts_clear(client, &context, &community, &event_id).await,
        },
        CalendarCommands::Feeds { command } => match command {
            CalendarFeedsCommands::Create {
                contexts,
                label,
                detail,
                tiers,
                expires,
            } => {
                let opts = FeedCreate {
                    contexts,
                    label,
                    detail,
                    tiers,
                    expires,
                };
                cal::cmd_calendar_feeds_create(client, &opts).await
            }
            CalendarFeedsCommands::List { include_revoked } => {
                cal::cmd_calendar_feeds_list(client, include_revoked).await
            }
            CalendarFeedsCommands::Revoke { feed_id } => {
                cal::cmd_calendar_feeds_revoke(client, &feed_id).await
            }
        },
        CalendarCommands::Export {
            contexts,
            out,
            receipts,
        } => cal::cmd_calendar_export(client, &contexts, &out, receipts.as_deref()).await,
    }
}
