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
    DisableRestRequest, DisableTspRequest, EnableRestRequest, EnableTspRequest,
    RollbackDidcommRequest, RollbackRestRequest, RollbackTspRequest, UpdateRestRequest,
    UpdateTspRequest,
};
use vta_sdk::protocol::{
    DisableDidcommRequest, EnableDidcommConflictBody, EnableDidcommRequest, UpdateDidcommRequest,
};

use crate::display::{NAME_HEADER, NameBook, UNNAMED, book_from_acl, inline, shorten_did};

// ── Trust-Task path (DIDComm / TSP) ────────────────────────────────
//
// Over DIDComm and TSP the VTA serves only signed Trust Tasks, so the
// `vta/services/*` tasks carry these commands there. REST keeps its routes.

/// Whether this client reaches the VTA's Trust-Task surface by messaging rather
/// than REST — in which case the services commands go as Trust Tasks.
fn over_messaging(client: &VtaClient) -> bool {
    !matches!(
        client.trust_task_transport(),
        vta_sdk::client::SurfaceTransport::Rest
    )
}

async fn services_task(
    client: &VtaClient,
    type_uri: &str,
    payload: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(client.dispatch_trust_task(type_uri, payload, 120).await?)
}

fn str_of<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(serde_json::Value::as_str)
}

/// Print a `ServiceMutationResult` from `vta/services/{enable,update,disable}`.
fn print_mutation(headline: &str, response: &serde_json::Value) {
    let result = response.get("result").unwrap_or(response);
    println!("{headline}");
    if let Some(v) = str_of(result, "logEntryVersionId") {
        println!("  New version ID: {v}");
    }
    if let Some(v) = str_of(result, "effectiveAt") {
        println!("  Effective at:   {v}");
    }
    if let Some(v) = str_of(result, "drainingMediator") {
        println!("  Draining:       {v}");
    }
    if let Some(v) = str_of(result, "drainUntil") {
        println!("  Drain deadline: {v}");
    }
    let serverless = result
        .get("serverless")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if let Some(vta_did) = str_of(result, "vtaDid") {
        print_serverless_hint(serverless, vta_did);
    }
}

/// Print a `RollbackResult` from `vta/services/rollback`.
fn print_rollback_task(kind: &str, response: &serde_json::Value) {
    let result = response.get("result").unwrap_or(response);
    let outcome = str_of(result, "kind").unwrap_or("unknown");
    if outcome == "noOp" {
        println!("{kind} rollback: nothing to do — the previous state already holds.");
        return;
    }
    println!("{kind} rolled back ({outcome}).");
    if let Some(v) = str_of(result, "logEntryVersionId") {
        println!("  New version ID: {v}");
    }
    if let Some(v) = str_of(result, "effectiveAt") {
        println!("  Effective at:   {v}");
    }
    if let Some(v) = str_of(result, "drainingMediator") {
        println!("  Draining:       {v}");
    }
    if let Some(v) = str_of(result, "drainUntil") {
        println!("  Drain deadline: {v}");
    }
}

async fn mutate(
    client: &VtaClient,
    type_uri: &str,
    service: &str,
    config: Option<serde_json::Value>,
    headline: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut payload = serde_json::json!({ "service": service });
    if let Some(c) = config {
        payload["config"] = c;
    }
    let response = services_task(client, type_uri, payload).await?;
    print_mutation(headline, &response);
    Ok(())
}

async fn rollback(
    client: &VtaClient,
    service: &str,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = services_task(
        client,
        vta_sdk::trust_tasks::TASK_SERVICES_ROLLBACK_1_0,
        serde_json::json!({ "service": service }),
    )
    .await?;
    print_rollback_task(label, &response);
    Ok(())
}

// ── services list ──────────────────────────────────────────────────

/// `pnm services list` — show current REST + DIDComm advertisements.
pub async fn cmd_services_list(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    if over_messaging(client) {
        let response = services_task(
            client,
            vta_sdk::trust_tasks::TASK_SERVICES_LIST_1_0,
            serde_json::json!({}),
        )
        .await?;
        println!("Services advertised on this VTA's DID document:");
        println!();
        for state in response
            .get("services")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let kind = str_of(state, "kind").unwrap_or("?");
            let on = if state.get("enabled").and_then(serde_json::Value::as_bool) == Some(true) {
                "on"
            } else {
                "off"
            };
            println!("  {kind:<9} {on}");
            if let Some(m) = str_of(state, "mediatorDid") {
                println!("    Mediator:     {m}");
            }
            if let Some(u) = str_of(state, "url") {
                println!("    URL:          {u}");
            }
            if let Some(d) = str_of(state, "drainsUntil") {
                println!("    Drains until: {d}");
            }
        }
        return Ok(());
    }
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
    if over_messaging(client) {
        return mutate(
            client,
            vta_sdk::trust_tasks::TASK_SERVICES_ENABLE_1_0,
            "rest",
            Some(serde_json::json!({ "url": url })),
            "REST enabled.",
        )
        .await;
    }
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
    if over_messaging(client) {
        return mutate(
            client,
            vta_sdk::trust_tasks::TASK_SERVICES_UPDATE_1_0,
            "rest",
            Some(serde_json::json!({ "url": url })),
            "REST URL updated.",
        )
        .await;
    }
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
    if over_messaging(client) {
        return mutate(
            client,
            vta_sdk::trust_tasks::TASK_SERVICES_DISABLE_1_0,
            "rest",
            None,
            "REST disabled.",
        )
        .await;
    }
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
    if over_messaging(client) {
        return rollback(client, "rest", "REST").await;
    }
    let resp = client.rollback_rest(RollbackRestRequest::default()).await?;
    print_rollback_result("REST", &resp);
    Ok(())
}

// ── services tsp {enable, update, disable, rollback} ──────────────
//
// TSP advertises a **mediator DID** (the VTA's TSP VID), not a URL —
// so these mirror the REST commands with `mediator_did` in place of
// `url`. Responses reuse the same `ServiceMutationResponse` /
// `RollbackResponse` shapes, so the rendering is identical.

pub async fn cmd_services_tsp_enable(
    client: &VtaClient,
    mediator_did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    if over_messaging(client) {
        return mutate(
            client,
            vta_sdk::trust_tasks::TASK_SERVICES_ENABLE_1_0,
            "tsp",
            Some(serde_json::json!({ "mediatorDid": mediator_did })),
            "TSP enabled.",
        )
        .await;
    }
    let req = EnableTspRequest::new(mediator_did);
    let resp = client.enable_tsp(req).await?;
    println!("TSP enabled.");
    println!("  New version ID: {}", resp.log_entry_version_id);
    println!("  Effective at:   {}", resp.effective_at);
    print_serverless_hint(resp.serverless, &resp.vta_did);
    Ok(())
}

pub async fn cmd_services_tsp_update(
    client: &VtaClient,
    mediator_did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    if over_messaging(client) {
        return mutate(
            client,
            vta_sdk::trust_tasks::TASK_SERVICES_UPDATE_1_0,
            "tsp",
            Some(serde_json::json!({ "mediatorDid": mediator_did })),
            "TSP mediator DID updated.",
        )
        .await;
    }
    let req = UpdateTspRequest::new(mediator_did);
    let resp = client.update_tsp(req).await?;
    println!("TSP mediator DID updated.");
    println!("  New version ID: {}", resp.log_entry_version_id);
    println!("  Effective at:   {}", resp.effective_at);
    print_serverless_hint(resp.serverless, &resp.vta_did);
    Ok(())
}

pub async fn cmd_services_tsp_disable(
    client: &VtaClient,
) -> Result<(), Box<dyn std::error::Error>> {
    if over_messaging(client) {
        return mutate(
            client,
            vta_sdk::trust_tasks::TASK_SERVICES_DISABLE_1_0,
            "tsp",
            None,
            "TSP disabled.",
        )
        .await;
    }
    let resp = client.disable_tsp(DisableTspRequest::default()).await?;
    println!("TSP disabled.");
    println!("  New version ID: {}", resp.log_entry_version_id);
    println!("  Effective at:   {}", resp.effective_at);
    print_serverless_hint(resp.serverless, &resp.vta_did);
    Ok(())
}

pub async fn cmd_services_tsp_rollback(
    client: &VtaClient,
) -> Result<(), Box<dyn std::error::Error>> {
    if over_messaging(client) {
        return rollback(client, "tsp", "TSP").await;
    }
    let resp = client.rollback_tsp(RollbackTspRequest::default()).await?;
    print_rollback_result("TSP", &resp);
    Ok(())
}

// ── services webauthn {enable, update, disable, rollback} ─────────

pub async fn cmd_services_webauthn_enable(
    client: &VtaClient,
    url: String,
) -> Result<(), Box<dyn std::error::Error>> {
    if over_messaging(client) {
        return mutate(
            client,
            vta_sdk::trust_tasks::TASK_SERVICES_ENABLE_1_0,
            "webauthn",
            Some(serde_json::json!({ "url": url })),
            "WebAuthn enabled.",
        )
        .await;
    }
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
    if over_messaging(client) {
        return mutate(
            client,
            vta_sdk::trust_tasks::TASK_SERVICES_UPDATE_1_0,
            "webauthn",
            Some(serde_json::json!({ "url": url })),
            "WebAuthn URL updated.",
        )
        .await;
    }
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
    if over_messaging(client) {
        return mutate(
            client,
            vta_sdk::trust_tasks::TASK_SERVICES_DISABLE_1_0,
            "webauthn",
            None,
            "WebAuthn disabled.",
        )
        .await;
    }
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
    if over_messaging(client) {
        return rollback(client, "webauthn", "WebAuthn").await;
    }
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
    if over_messaging(client) {
        let mut config = serde_json::json!({ "mediatorDid": mediator_did, "force": force });
        if let Some(t) = handshake_timeout_secs {
            config["handshakeTimeoutSecs"] = t.into();
        }
        return mutate(
            client,
            vta_sdk::trust_tasks::TASK_SERVICES_ENABLE_1_0,
            "didcomm",
            Some(config),
            "DIDComm enabled.",
        )
        .await;
    }
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
    if over_messaging(client) {
        // `update` carries no drain TTL: the agent applies its own floor to a
        // mediator change requested over messaging.
        let _ = drain_ttl_secs;
        let mut config = serde_json::json!({ "mediatorDid": new_mediator_did, "force": force });
        if let Some(t) = handshake_timeout_secs {
            config["handshakeTimeoutSecs"] = t.into();
        }
        return mutate(
            client,
            vta_sdk::trust_tasks::TASK_SERVICES_UPDATE_1_0,
            "didcomm",
            Some(config),
            "DIDComm mediator updated.",
        )
        .await;
    }
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
    if over_messaging(client) {
        let response = services_task(
            client,
            vta_sdk::trust_tasks::TASK_SERVICES_DISABLE_1_0,
            serde_json::json!({ "service": "didcomm", "drainTtlSecs": drain_ttl_secs }),
        )
        .await?;
        print_mutation("DIDComm disabled.", &response);
        return Ok(());
    }
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
    if over_messaging(client) {
        return rollback(client, "didcomm", "DIDComm").await;
    }
    let req = RollbackDidcommRequest { drain_ttl_secs };
    let resp = client.rollback_didcomm(req).await?;
    print_rollback_result("DIDComm", &resp);
    Ok(())
}

/// Best-effort names for mediator / peer DIDs.
///
/// Neither the drain set nor the telemetry report carries a label, so the only
/// local source is the ACL — which does cover mediators an operator has
/// granted an entry to. Peer *senders* are not in our ACL and stay bare until
/// agent names exist; they are the clearest case for that feature.
///
/// Failure is ignored on purpose. Naming is decoration, and an operator who
/// can read the drain set but not the ACL must still get their table.
async fn mediator_name_book(client: &VtaClient) -> NameBook {
    let mut book = NameBook::new();
    if let Ok(acl) = client.list_acl(None).await {
        book_from_acl(&mut book, &acl.entries);
    }
    book
}

// ── services didcomm drain {list, cancel} ─────────────────────────

pub async fn cmd_services_didcomm_drain_list(
    client: &VtaClient,
) -> Result<(), Box<dyn std::error::Error>> {
    if over_messaging(client) {
        let response = services_task(
            client,
            vta_sdk::trust_tasks::TASK_SERVICES_DRAIN_LIST_1_0,
            serde_json::json!({}),
        )
        .await?;
        let entries: Vec<&serde_json::Value> = response
            .get("entries")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .collect();
        if entries.is_empty() {
            println!("No mediators currently in drain.");
            return Ok(());
        }
        println!("Drain set ({} mediator(s)):", entries.len());
        println!();
        println!("  {:<46}  DRAIN UNTIL", "MEDIATOR DID");
        for e in entries {
            println!(
                "  {:<46}  {}",
                shorten_did(str_of(e, "mediatorDid").unwrap_or("?")),
                str_of(e, "drainsUntil").unwrap_or("?")
            );
        }
        return Ok(());
    }
    let resp = client.list_drain().await?;
    if resp.entries.is_empty() {
        println!("No mediators currently in drain.");
        return Ok(());
    }
    println!("Drain set ({} mediator(s)):", resp.entries.len());
    println!();

    let book = mediator_name_book(client).await;
    let show_names = book.names_any(resp.entries.iter().map(|e| e.mediator_did.as_str()));

    let header_did = "MEDIATOR DID";
    let header_until = "DRAIN UNTIL";
    if show_names {
        println!("  {:<24}  {header_did:<46}  {header_until}", NAME_HEADER);
    } else {
        println!("  {header_did:<46}  {header_until}");
    }
    for e in &resp.entries {
        let did = shorten_did(&e.mediator_did);
        if show_names {
            let name = book
                .name_of(&e.mediator_did)
                .unwrap_or_else(|| UNNAMED.into());
            println!("  {:<24}  {:<46}  {}", name, did, e.drains_until);
        } else {
            println!("  {:<46}  {}", did, e.drains_until);
        }
    }
    Ok(())
}

pub async fn cmd_services_didcomm_drain_cancel(
    client: &VtaClient,
    mediator_did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    if over_messaging(client) {
        let response = services_task(
            client,
            vta_sdk::trust_tasks::TASK_SERVICES_DRAIN_CANCEL_1_0,
            serde_json::json!({ "mediatorDid": mediator_did }),
        )
        .await?;
        println!(
            "Drain cancelled for {}.",
            str_of(&response, "mediatorDid").unwrap_or(&mediator_did)
        );
        println!("  Listener was torn down immediately.");
        return Ok(());
    }
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
    if over_messaging(client) {
        return Err(
            "`services report` is REST-only: the mediator telemetry report has no Trust Task. \
             Reach it over REST:\n  <cli> --transport rest services report"
                .into(),
        );
    }
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
            // Peer sender DIDs have no label anywhere in our store, so most
            // will stay bare until agent names land — which is exactly the
            // surface they are for.
            let book = mediator_name_book(client).await;

            if report.mediators.is_empty() {
                println!("  No inbound DIDComm messages recorded.");
            } else {
                println!("  Per-mediator inbound counts (most recent first):");
                let show_names =
                    book.names_any(report.mediators.iter().map(|m| m.mediator_did.as_str()));
                let header_did = "MEDIATOR DID";
                let header_count = "INBOUND";
                if show_names {
                    println!(
                        "    {:<24}  {header_did:<46}  {header_count:>10}  LAST SEEN",
                        NAME_HEADER
                    );
                } else {
                    println!("    {header_did:<46}  {header_count:>10}  LAST SEEN");
                }
                for m in &report.mediators {
                    let did = shorten_did(&m.mediator_did);
                    if show_names {
                        let name = book
                            .name_of(&m.mediator_did)
                            .unwrap_or_else(|| UNNAMED.into());
                        println!(
                            "    {:<24}  {:<46}  {:>10}  {}",
                            name, did, m.inbound_count, m.last_seen
                        );
                    } else {
                        println!("    {:<46}  {:>10}  {}", did, m.inbound_count, m.last_seen);
                    }
                }
            }
            if !report.senders.is_empty() {
                println!();
                println!("  Senders by last-seen mediator:");
                for s in &report.senders {
                    // Prose, not a fixed-width column, so both sides carry
                    // their DID alongside the name.
                    println!(
                        "    {} → {} (at {})",
                        inline(&book, &s.sender_did),
                        inline(&book, &s.last_seen_mediator),
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

/// Tell the operator where the new log entry went, after a mutation of the
/// VTA's **own** DID on a running VTA.
///
/// Silent when `serverless` is false (the VTA published to a did-hosting
/// server as part of the call) and when `vta_did` is empty (no LogEntry was
/// written, e.g. a no-op rollback).
///
/// A self-hosted ("serverless") VTA serves its own `did.jsonl` from its store
/// at the DID's canonical path, read per request — so the entry just written is
/// already being served, and there is nothing to redeploy. Advising a redeploy
/// here sent operators to copy a log to the host that was already serving it
/// (Keyring VTI-36). The one case that still needs a copy is a log the operator
/// *also* publishes somewhere else, which is said last.
pub fn print_serverless_hint(serverless: bool, vta_did: &str) {
    if !serverless || vta_did.is_empty() {
        return;
    }
    print_self_hosted_notice(vta_did, "now serves");
}

/// [`print_serverless_hint`] for the offline `vta services …` surface, which
/// runs with the daemon stopped: the entry is served once the VTA starts.
pub fn print_serverless_hint_offline(serverless: bool, vta_did: &str) {
    if !serverless || vta_did.is_empty() {
        return;
    }
    print_self_hosted_notice(vta_did, "will serve, once it is running again,");
}

fn print_self_hosted_notice(vta_did: &str, serves: &str) {
    println!();
    match webvh_log_url(vta_did) {
        Some(url) => {
            println!("  This VTA hosts its own DID, and {serves} the updated log at");
            println!("    {url}");
        }
        None => println!("  This VTA hosts its own DID, and {serves} the updated log itself."),
    }
    println!("  Nothing to redeploy. Resolvers pick up the new version as their cache");
    println!("  expires (60 s for this VTA's own responses, up to 5 min in a caching resolver).");
    println!("  Only a copy you also publish elsewhere needs replacing:");
    println!("    pnm did-mgmt dids get-log {vta_did} --out did.jsonl");
}

/// After a mutation of a DID this VTA does **not** serve itself — a
/// self-hosted DID it manages for someone else, such as a community's. The
/// new entry exists only in the VTA's store until it is delivered to wherever
/// that DID's log is served.
pub fn print_redeploy_hint(serverless: bool, did: &str) {
    if !serverless || did.is_empty() {
        return;
    }
    println!();
    println!("  This DID is self-hosted, and not by this VTA. Fetch the updated log:");
    println!("    pnm did-mgmt dids get-log {did} --out did.jsonl");
    match webvh_log_url(did) {
        Some(url) => println!("  then install it where {url} is served from."),
        None => println!("  then install it where the DID's log is served from."),
    }
    println!("  For a community that self-hosts its DID, that is:");
    println!("    cnm did-log install --file did.jsonl");
    println!("  Until you do, resolvers will keep returning the prior version.");
}

/// The HTTPS URL a `did:webvh` DID's log is resolved from (did:webvh v1.0,
/// DID-to-HTTPS transformation): `did:webvh:<scid>:<host>[:<path>…]` becomes
/// `https://<host>/<path…>/did.jsonl`, or `/.well-known/did.jsonl` with no
/// path. `%3A` in the host is a port separator. `None` for anything else.
fn webvh_log_url(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:webvh:")?;
    let mut parts = rest.split(':');
    let _scid = parts.next().filter(|s| !s.is_empty())?;
    let host = parts.next().filter(|s| !s.is_empty())?;
    let host = host.replace("%3A", ":").replace("%3a", ":");
    let path: Vec<&str> = parts.collect();
    if path.iter().any(|p| p.is_empty()) {
        return None;
    }
    Some(if path.is_empty() {
        format!("https://{host}/.well-known/did.jsonl")
    } else {
        format!("https://{host}/{}/did.jsonl", path.join("/"))
    })
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

#[cfg(test)]
mod tests {
    /// A REST client keeps the REST routes; the Trust-Task path is for the
    /// messaging transports, where the VTA serves nothing else.
    #[test]
    fn a_rest_client_keeps_the_rest_routes() {
        let client = vta_sdk::client::VtaClient::new("http://localhost:9999");
        assert!(!super::over_messaging(&client));
    }

    /// The mutation result the `vta/services/*` tasks answer with renders
    /// without panicking whatever members are present.
    #[test]
    fn a_trust_task_result_renders() {
        super::print_mutation(
            "REST enabled.",
            &serde_json::json!({ "result": {
                "logEntryVersionId": "2-abc",
                "effectiveAt": "2026-01-01T00:00:00Z",
            }}),
        );
        super::print_rollback_task("REST", &serde_json::json!({ "result": { "kind": "noOp" } }));
    }
    /// Keyring VTI-36: the hint names the URL the log is resolved from.
    #[test]
    fn webvh_log_url_follows_the_did_to_https_transform() {
        use super::webvh_log_url;
        assert_eq!(
            webvh_log_url("did:webvh:QmScid:vta.example.com").as_deref(),
            Some("https://vta.example.com/.well-known/did.jsonl")
        );
        assert_eq!(
            webvh_log_url("did:webvh:QmScid:example.com%3A8100:dids:vta").as_deref(),
            Some("https://example.com:8100/dids/vta/did.jsonl")
        );
        assert_eq!(webvh_log_url("did:key:z6Mk"), None);
        assert_eq!(webvh_log_url("did:webvh:QmScid"), None);
    }
}
