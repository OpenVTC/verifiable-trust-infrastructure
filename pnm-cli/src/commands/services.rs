//! Dispatch for `pnm services …` (REST + DIDComm transport advertisement).

use vta_cli_common::commands::services;
use vta_sdk::client::VtaClient;

use crate::cli::{
    DidcommCommands, DrainCommands, RestCommands, ServicesCommands, TspCommands, WebauthnCommands,
};

pub(crate) async fn run(
    client: &VtaClient,
    command: ServicesCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        ServicesCommands::List => services::cmd_services_list(client).await,
        ServicesCommands::Tsp { command } => run_tsp(client, command).await,
        ServicesCommands::Rest { command } => run_rest(client, command).await,
        ServicesCommands::Didcomm { command } => run_didcomm(client, command).await,
        ServicesCommands::Webauthn { command } => run_webauthn(client, command).await,
        ServicesCommands::Report {
            since,
            until,
            format,
        } => match format.parse::<services::ReportFormat>() {
            Ok(format) => services::cmd_services_report(client, since, until, format).await,
            Err(msg) => Err(msg.into()),
        },
    }
}

async fn run_webauthn(
    client: &VtaClient,
    command: WebauthnCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        WebauthnCommands::Enable { url } => {
            services::cmd_services_webauthn_enable(client, url).await
        }
        WebauthnCommands::Update { url } => {
            services::cmd_services_webauthn_update(client, url).await
        }
        WebauthnCommands::Disable => services::cmd_services_webauthn_disable(client).await,
        WebauthnCommands::Rollback => services::cmd_services_webauthn_rollback(client).await,
    }
}

async fn run_tsp(
    client: &VtaClient,
    command: TspCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        TspCommands::Enable { mediator_did } => {
            services::cmd_services_tsp_enable(client, mediator_did).await
        }
        TspCommands::Update { mediator_did } => {
            services::cmd_services_tsp_update(client, mediator_did).await
        }
        TspCommands::Disable => services::cmd_services_tsp_disable(client).await,
        TspCommands::Rollback => services::cmd_services_tsp_rollback(client).await,
    }
}

async fn run_rest(
    client: &VtaClient,
    command: RestCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        RestCommands::Enable { url } => services::cmd_services_rest_enable(client, url).await,
        RestCommands::Update { url } => services::cmd_services_rest_update(client, url).await,
        RestCommands::Disable => services::cmd_services_rest_disable(client).await,
        RestCommands::Rollback => services::cmd_services_rest_rollback(client).await,
    }
}

async fn run_didcomm(
    client: &VtaClient,
    command: DidcommCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        DidcommCommands::Enable {
            mediator_did,
            force,
            handshake_timeout,
        } => {
            services::cmd_services_didcomm_enable(client, mediator_did, force, handshake_timeout)
                .await
        }
        DidcommCommands::Update {
            new_mediator_did,
            drain_ttl,
            force,
            handshake_timeout,
        } => {
            services::cmd_services_didcomm_update(
                client,
                new_mediator_did,
                drain_ttl,
                force,
                handshake_timeout,
            )
            .await
        }
        DidcommCommands::Disable { drain_ttl } => {
            services::cmd_services_didcomm_disable(client, drain_ttl).await
        }
        DidcommCommands::Rollback { drain_ttl } => {
            services::cmd_services_didcomm_rollback(client, drain_ttl).await
        }
        DidcommCommands::Drain { command } => match command {
            DrainCommands::List => services::cmd_services_didcomm_drain_list(client).await,
            DrainCommands::Cancel { mediator_did } => {
                services::cmd_services_didcomm_drain_cancel(client, mediator_did).await
            }
        },
    }
}
