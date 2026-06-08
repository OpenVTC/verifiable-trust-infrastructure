//! `… step-up policy` operator commands (online, via the VTA REST surface).
//!
//! Thin wrappers over [`VtaClient::get_step_up_policy`] /
//! [`VtaClient::set_step_up_policy`]. The policy JSON is the `0.2` shape
//! (`{ enabled, floors: [{ operation, mode, allowAal1IfNonEscalating }] }`).

use serde_json::Value;
use vta_sdk::prelude::*;

/// `step-up policy show` — print the maintainer's current effective policy.
pub async fn cmd_policy_show(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let policy = client.get_step_up_policy().await?;
    print_policy(&policy);
    Ok(())
}

/// `step-up policy set` — apply `policy` (the `0.2` payload) and print the
/// effective (canonicalized) result the maintainer now holds.
pub async fn cmd_policy_set(
    client: &VtaClient,
    policy: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let effective = client.set_step_up_policy(policy).await?;
    println!("Step-up policy updated:");
    print_policy(&effective);
    Ok(())
}

/// `step-up policy disable` — revert to AAL1 everywhere (the shipping default).
pub async fn cmd_policy_disable(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let effective = client
        .set_step_up_policy(serde_json::json!({ "enabled": false, "floors": [] }))
        .await?;
    println!("Step-up policy disabled (AAL1 everywhere):");
    print_policy(&effective);
    Ok(())
}

/// Pretty-print a `0.2` policy value.
pub fn print_policy(p: &Value) {
    let enabled = p.get("enabled").and_then(Value::as_bool).unwrap_or(false);
    println!(
        "  Enforcement: {}",
        if enabled {
            "ENABLED"
        } else {
            "disabled (AAL1 everywhere)"
        }
    );
    let floors = p.get("floors").and_then(Value::as_array);
    match floors {
        Some(floors) if !floors.is_empty() => {
            println!("  Floors:");
            for f in floors {
                let op = f.get("operation").and_then(Value::as_str).unwrap_or("?");
                let mode = f.get("mode").and_then(Value::as_str).unwrap_or("?");
                let carve = f
                    .get("allowAal1IfNonEscalating")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let suffix = if carve {
                    "  (AAL1 carve-out for non-escalating self-service)"
                } else {
                    ""
                };
                println!("    {op:<18} → {mode}{suffix}");
            }
        }
        _ => println!("  Floors: (none)"),
    }
}
