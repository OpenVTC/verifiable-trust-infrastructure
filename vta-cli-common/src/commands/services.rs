//! `pnm services …` command implementations — unified CLI surface.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §5.1.
//!
//! Twelve commands across two transport kinds plus a top-level
//! list/report. Each function calls the matching `vta-sdk` client
//! method; the typed `VtaError` variants are surfaced via the
//! existing CLI error renderer (`render::print_cli_error`) which
//! attaches operator-actionable suggested-fix strings per
//! CLAUDE.md.
//!
//! The retired `pnm mediator …` subcommand surface is replaced by
//! `pnm services didcomm {update,rollback,drain {list,cancel}}` —
//! see the migration cue in pnm-cli/cnm-cli for the
//! retired-command UX.

use vta_sdk::client::VtaClient;
use vta_sdk::error::VtaError;
use vta_sdk::protocol::services::{
    DisableRestRequest, EnableRestRequest, RollbackDidcommRequest, RollbackRestRequest,
    UpdateRestRequest,
};
use vta_sdk::protocol::{
    DisableDidcommRequest, EnableDidcommConflictBody, EnableDidcommRequest, UpdateDidcommRequest,
};

// ── services list ──────────────────────────────────────────────────

/// `pnm services list` — show current REST + DIDComm advertisements.
pub async fn cmd_services_list(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let response = client.list_services().await?;

    println!("Services advertised on this VTA's DID document:");
    println!();
    for state in &response.services {
        match state {
            vta_sdk::protocol::services::ServiceState::Tsp {
                enabled,
                mediator_did,
            } => {
                let on = if *enabled { "on" } else { "off" };
                println!("  TSP:      {on}");
                if let Some(m) = mediator_did {
                    println!("    Mediator:     {m}");
                }
            }
            vta_sdk::protocol::services::ServiceState::Didcomm {
                enabled,
                mediator_did,
                routing_keys,
            } => {
                let on = if *enabled { "on" } else { "off" };
                println!("  DIDComm:  {on}");
                if let Some(m) = mediator_did {
                    println!("    Mediator:     {m}");
                }
                if !routing_keys.is_empty() {
                    println!("    Routing keys: {}", routing_keys.join(", "));
                }
            }
            vta_sdk::protocol::services::ServiceState::Rest { enabled, url } => {
                let on = if *enabled { "on" } else { "off" };
                println!("  REST:     {on}");
                if let Some(u) = url {
                    println!("    URL:          {u}");
                }
            }
            vta_sdk::protocol::services::ServiceState::Webauthn { enabled, url } => {
                let on = if *enabled { "on" } else { "off" };
                println!("  WebAuthn: {on}");
                if let Some(u) = url {
                    println!("    URL:          {u}");
                }
            }
        }
    }
    Ok(())
}

// ── services rest {enable, update, disable, rollback} ─────────────

pub async fn cmd_services_rest_enable(
    client: &VtaClient,
    url: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = EnableRestRequest::new(url);
    let resp = client.enable_rest(req).await?;
    println!("REST enabled.");
    println!("  New version ID: {}", resp.log_entry_version_id);
    println!("  Effective at:   {}", resp.effective_at);
    print_serverless_hint(resp.serverless, &resp.vta_did);
    Ok(())
}

pub async fn cmd_services_rest_update(
    client: &VtaClient,
    url: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = UpdateRestRequest::new(url);
    let resp = client.update_rest(req).await?;
    println!("REST URL updated.");
    println!("  New version ID: {}", resp.log_entry_version_id);
    println!("  Effective at:   {}", resp.effective_at);
    print_serverless_hint(resp.serverless, &resp.vta_did);
    Ok(())
}

pub async fn cmd_services_rest_disable(
    client: &VtaClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.disable_rest(DisableRestRequest::default()).await?;
    println!("REST disabled.");
    println!("  New version ID: {}", resp.log_entry_version_id);
    println!("  Effective at:   {}", resp.effective_at);
    print_serverless_hint(resp.serverless, &resp.vta_did);
    Ok(())
}

pub async fn cmd_services_rest_rollback(
    client: &VtaClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.rollback_rest(RollbackRestRequest::default()).await?;
    print_rollback_result("REST", &resp);
    Ok(())
}

// ── services webauthn {enable, update, disable, rollback} ─────────

pub async fn cmd_services_webauthn_enable(
    client: &VtaClient,
    url: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = vta_sdk::protocol::services::EnableWebauthnRequest::new(url);
    let resp = client.enable_webauthn(req).await?;
    println!("WebAuthn enabled.");
    println!("  New version ID: {}", resp.log_entry_version_id);
    println!("  Effective at:   {}", resp.effective_at);
    print_serverless_hint(resp.serverless, &resp.vta_did);
    Ok(())
}

pub async fn cmd_services_webauthn_update(
    client: &VtaClient,
    url: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = vta_sdk::protocol::services::UpdateWebauthnRequest::new(url);
    let resp = client.update_webauthn(req).await?;
    println!("WebAuthn URL updated.");
    println!("  New version ID: {}", resp.log_entry_version_id);
    println!("  Effective at:   {}", resp.effective_at);
    print_serverless_hint(resp.serverless, &resp.vta_did);
    Ok(())
}

pub async fn cmd_services_webauthn_disable(
    client: &VtaClient,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!(
        "WARNING: disabling WebAuthn will also REMOVE passkey verificationMethods from every DID \
         this VTA controls. Any operator currently using passkey login will need to re-enrol \
         after the next `services webauthn enable`."
    );
    let resp = client
        .disable_webauthn(vta_sdk::protocol::services::DisableWebauthnRequest::default())
        .await?;
    println!("WebAuthn disabled.");
    println!("  New version ID: {}", resp.log_entry_version_id);
    println!("  Effective at:   {}", resp.effective_at);
    print_serverless_hint(resp.serverless, &resp.vta_did);
    Ok(())
}

pub async fn cmd_services_webauthn_rollback(
    client: &VtaClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .rollback_webauthn(vta_sdk::protocol::services::RollbackWebauthnRequest::default())
        .await?;
    print_rollback_result("WebAuthn", &resp);
    Ok(())
}

// ── services didcomm {enable, update, disable, rollback} ──────────

pub async fn cmd_services_didcomm_enable(
    client: &VtaClient,
    mediator_did: String,
    force: bool,
    handshake_timeout_secs: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut req = EnableDidcommRequest::new(&mediator_did);
    req.force = force;
    req.handshake_timeout_secs = handshake_timeout_secs;
    let resp = match client.enable_didcomm(req).await {
        Ok(resp) => resp,
        Err(VtaError::Conflict(body)) => {
            if let Ok(conflict) = serde_json::from_str::<EnableDidcommConflictBody>(&body)
                && conflict.error == "didcomm_already_enabled"
            {
                println!("DIDComm already enabled.");
                if let Some(mediator_did) = conflict.mediator_did {
                    println!("  Mediator DID:   {mediator_did}");
                }
                return Ok(());
            }
            return Err(VtaError::Conflict(body).into());
        }
        Err(e) => return Err(e.into()),
    };
    println!("DIDComm enabled.");
    println!("  Mediator DID:   {}", resp.mediator_did);
    if !resp.mediator_endpoint.is_empty() {
        println!("  Mediator URL:   {}", resp.mediator_endpoint);
    }
    println!("  New version ID: {}", resp.new_version_id);
    if force {
        println!();
        println!("  Note: --force was set; mediator handshake steps 2-5 were bypassed.");
    }
    print_serverless_hint(resp.serverless, &resp.vta_did);
    Ok(())
}

pub async fn cmd_services_didcomm_update(
    client: &VtaClient,
    new_mediator_did: String,
    drain_ttl_secs: u64,
    force: bool,
    handshake_timeout_secs: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut req = UpdateDidcommRequest::new(&new_mediator_did, drain_ttl_secs);
    req.force = force;
    req.handshake_timeout_secs = handshake_timeout_secs;
    let resp = client.update_didcomm(req).await?;
    println!("DIDComm mediator updated.");
    println!("  Prior mediator:  {}", resp.prior_mediator_did);
    println!("  Active mediator: {}", resp.active_mediator_did);
    if !resp.active_mediator_endpoint.is_empty() {
        println!("  Active endpoint: {}", resp.active_mediator_endpoint);
    }
    println!("  New version ID:  {}", resp.new_version_id);
    println!(
        "  Drain deadline:  {} (prior listener stays up until then)",
        resp.drains_until
    );
    print_serverless_hint(resp.serverless, &resp.vta_did);
    Ok(())
}

pub async fn cmd_services_didcomm_disable(
    client: &VtaClient,
    drain_ttl_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = DisableDidcommRequest::new(drain_ttl_secs);
    let resp = client.disable_didcomm(req).await?;
    println!("DIDComm disabled.");
    println!("  Prior mediator: {}", resp.prior_mediator_did);
    println!("  New version ID: {}", resp.new_version_id);
    match resp.drains_until {
        Some(deadline) => {
            println!("  Drain deadline: {deadline}");
            println!();
            println!("  The listener stays up until the deadline so in-flight messages can drain.");
            println!(
                "  Cancel early with `pnm services didcomm drain cancel --mediator-did <did>`."
            );
        }
        None => println!("  Listener torn down immediately (drain TTL was 0)."),
    }
    print_serverless_hint(resp.serverless, &resp.vta_did);
    Ok(())
}

pub async fn cmd_services_didcomm_rollback(
    client: &VtaClient,
    drain_ttl_secs: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = RollbackDidcommRequest { drain_ttl_secs };
    let resp = client.rollback_didcomm(req).await?;
    print_rollback_result("DIDComm", &resp);
    Ok(())
}

// ── services didcomm drain {list, cancel} ─────────────────────────

pub async fn cmd_services_didcomm_drain_list(
    client: &VtaClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.list_drain().await?;
    if resp.entries.is_empty() {
        println!("No mediators currently in drain.");
        return Ok(());
    }
    println!("Drain set ({} mediator(s)):", resp.entries.len());
    println!();
    let header_did = "MEDIATOR DID";
    let header_until = "DRAIN UNTIL";
    println!("  {header_did:<60}  {header_until}");
    for e in &resp.entries {
        println!(
            "  {:<60}  {}",
            truncate(&e.mediator_did, 60),
            e.drains_until
        );
    }
    Ok(())
}

pub async fn cmd_services_didcomm_drain_cancel(
    client: &VtaClient,
    mediator_did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = vta_sdk::protocol::DrainCancelRequest { mediator_did };
    let resp = client.drain_cancel(req).await?;
    println!("Drain cancelled for {}.", resp.mediator_did);
    println!("  Listener was torn down immediately.");
    Ok(())
}

// ── services report ───────────────────────────────────────────────

pub async fn cmd_services_report(
    client: &VtaClient,
    since: Option<String>,
    until: Option<String>,
    format: ReportFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let report = client
        .mediator_report(since.as_deref(), until.as_deref())
        .await?;

    match format {
        ReportFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        ReportFormat::Table => {
            println!("Service-management report");
            if let Some(ref s) = report.since {
                println!("  Window: {s} → {}", report.until);
            } else {
                println!("  Window: (all time) → {}", report.until);
            }
            println!();
            if report.mediators.is_empty() {
                println!("  No inbound DIDComm messages recorded.");
            } else {
                println!("  Per-mediator inbound counts (most recent first):");
                let header_did = "MEDIATOR DID";
                let header_count = "INBOUND";
                println!("    {header_did:<60}  {header_count:>10}  LAST SEEN");
                for m in &report.mediators {
                    println!(
                        "    {:<60}  {:>10}  {}",
                        truncate(&m.mediator_did, 60),
                        m.inbound_count,
                        m.last_seen
                    );
                }
            }
            if !report.senders.is_empty() {
                println!();
                println!("  Senders by last-seen mediator:");
                for s in &report.senders {
                    println!(
                        "    {} → {} (at {})",
                        truncate(&s.sender_did, 50),
                        truncate(&s.last_seen_mediator, 50),
                        s.last_seen_at
                    );
                }
            }
        }
    }
    Ok(())
}

// ── shared helpers ────────────────────────────────────────────────

fn print_rollback_result(kind: &str, resp: &vta_sdk::protocol::services::RollbackResponse) {
    if resp.kind == "no_op" {
        println!("{kind} rollback: no change required.");
        println!("  Snapshot matches current state — nothing to do.");
        return;
    }
    println!("{kind} rolled back.");
    println!("  Action:         {}", resp.kind);
    if !resp.log_entry_version_id.is_empty() {
        println!("  New version ID: {}", resp.log_entry_version_id);
    }
    println!("  Effective at:   {}", resp.effective_at);
    if let Some(ref drain_until) = resp.drain_until {
        println!("  Drain deadline: {drain_until}");
    }
    if let Some(ref draining) = resp.draining_mediator {
        println!("  Draining:       {draining}");
    }
    print_serverless_hint(resp.serverless, &resp.vta_did);
}

/// Print the "fetch did.jsonl + redeploy" hint when the mutation
/// just wrote a LogEntry to a self-hosted VTA DID.
///
/// Silent when `serverless` is false (the VTA published to a host
/// as part of the call — no follow-up needed) and when `vta_did`
/// is empty (no LogEntry was written, e.g. no-op rollback).
///
/// Suffix is two operator-actionable lines: the command and the
/// reason. Operators running scripted updates will see the line
/// every time on serverless deployments — that's intentional,
/// since the alternative is stale resolvers without an obvious
/// cause.
pub fn print_serverless_hint(serverless: bool, vta_did: &str) {
    if !serverless || vta_did.is_empty() {
        return;
    }
    println!();
    println!("  This VTA's DID is self-hosted. Fetch the updated log:");
    println!("    pnm did-mgmt dids get-log {vta_did} --out did.jsonl");
    println!("  then redeploy did.jsonl to your host. Until you do,");
    println!("  resolvers will keep returning the prior version.");
}

#[derive(Debug, Clone, Copy)]
pub enum ReportFormat {
    Json,
    Table,
}

impl std::str::FromStr for ReportFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Self::Json),
            "table" => Ok(Self::Table),
            other => Err(format!("unknown format `{other}` — use `json` or `table`")),
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}
