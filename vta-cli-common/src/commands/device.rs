//! `device …` operator commands (online, via the trust-task dispatcher).
//!
//! Thin wrappers over the `VtaClient::device_*` methods. A personal AI agent
//! (open-claw / nano-claw / hermes) is a Service consumer
//! (`consumerKind.serviceKind = "ai-agent"`); these commands enroll, list, and
//! retire its `DeviceBinding`. See `docs/02-vta/personal-ai-agents.md`.

use serde_json::{Value, json};
use vta_sdk::client::VtaClient;

use crate::render::{DIM, RESET, is_json_output, print_json};

/// Print a trust-task result either as raw JSON (`--json`) or as a labelled,
/// pretty-printed document for humans.
fn print_result(label: &str, value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    if is_json_output() {
        print_json(value)?;
    } else {
        println!("{label}");
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

/// `device list` — list the caller's registered devices. `service_kind` filters
/// to a single Service consumer kind (e.g. `ai-agent`) when supplied.
pub async fn cmd_device_list(
    client: &VtaClient,
    service_kind: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut filters = json!({});
    if let Some(sk) = service_kind {
        filters["consumerKindFilter"] = json!("service");
        filters["serviceKindFilter"] = json!(sk);
    }
    let result = client.device_list(filters).await?;
    print_result("Registered devices:", &result)
}

/// `device register` — claim a `DeviceBinding` for the authenticated DID. The
/// DID must already be in the ACL (provision the `ai-agent` template first).
pub async fn cmd_device_register(
    client: &VtaClient,
    service_kind: String,
    display_name: String,
    platform: Option<String>,
    hpke_public_key: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let consumer_kind = json!({ "kind": "service", "serviceKind": service_kind });
    let result = client
        .device_register(
            consumer_kind,
            &display_name,
            platform.as_deref(),
            hpke_public_key.as_deref(),
        )
        .await?;
    println!("{DIM}Device registered.{RESET}");
    print_result("Binding:", &result)
}

/// `device disable` — disable a device by id (kept on record, can no longer
/// authenticate). The operator kill switch.
pub async fn cmd_device_disable(
    client: &VtaClient,
    device_id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.device_disable(&device_id).await?;
    println!("{DIM}Device {device_id} disabled.{RESET}");
    print_result("Result:", &result)
}

/// `device wipe` — remotely wipe a lost/compromised device. Marks it wiped +
/// disabled and records the reason. `scope` is `cache`, `cache-and-keys`, or
/// `full`.
pub async fn cmd_device_wipe(
    client: &VtaClient,
    device_id: String,
    reason: String,
    scope: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.device_wipe(&device_id, &reason, &scope).await?;
    println!("{DIM}Device {device_id} wiped (scope: {scope}).{RESET}");
    print_result("Result:", &result)
}

/// `device set-wake` — record the device's push `WakeHandle` (gateway DID/URL +
/// opaque handle) and return the trigger allowlist.
pub async fn cmd_device_set_wake(
    client: &VtaClient,
    gateway: String,
    handle: String,
    suggested_triggers: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client
        .device_set_wake(&gateway, &handle, suggested_triggers)
        .await?;
    print_result("Wake handle recorded:", &result)
}

/// `device heartbeat` — refresh `lastSeenAt`; returns server time + any queued
/// operations for the device.
pub async fn cmd_device_heartbeat(
    client: &VtaClient,
    platform: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.device_heartbeat(platform.as_deref()).await?;
    print_result("Heartbeat:", &result)
}
