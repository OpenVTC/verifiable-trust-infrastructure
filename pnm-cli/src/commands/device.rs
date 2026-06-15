//! `pnm device …` dispatch — thin shim over the shared device commands.

use vta_cli_common::commands::device as dev;
use vta_sdk::prelude::*;

use crate::cli::DeviceCommands;

pub(crate) async fn run(
    client: &VtaClient,
    command: DeviceCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        DeviceCommands::List { service_kind } => dev::cmd_device_list(client, service_kind).await,
        DeviceCommands::Register {
            service_kind,
            display_name,
            platform,
            hpke_public_key,
        } => {
            dev::cmd_device_register(
                client,
                service_kind,
                display_name,
                platform,
                hpke_public_key,
            )
            .await
        }
        DeviceCommands::Disable { device_id } => dev::cmd_device_disable(client, device_id).await,
        DeviceCommands::Wipe {
            device_id,
            reason,
            scope,
        } => dev::cmd_device_wipe(client, device_id, reason, scope).await,
        DeviceCommands::SetWake {
            gateway,
            handle,
            suggested_triggers,
        } => dev::cmd_device_set_wake(client, gateway, handle, suggested_triggers).await,
        DeviceCommands::Heartbeat { platform } => dev::cmd_device_heartbeat(client, platform).await,
    }
}
