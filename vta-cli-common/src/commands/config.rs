use std::collections::HashMap;

use vta_sdk::prelude::*;
use vta_sdk::protocols::vta_management::update_config::UpdateConfigBody;

/// Print the configuration registry as canonical `config/show/0.1` returns it.
///
/// Boot-stable keys are marked, so an operator can see before patching that a
/// change will not take effect until a restart.
pub async fn cmd_config_get(
    client: &VtaClient,
    label_prefix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.get_config().await?;
    for field in &resp.config.fields {
        let value = match &field.value {
            serde_json::Value::Null => "(not set)".to_string(),
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let restart = if field.requires_restart {
            "  (requires restart)"
        } else {
            ""
        };
        println!(
            "{label_prefix}{:<12} {value}  [{}]{restart}",
            format!("{}:", field.key),
            field.source
        );
    }
    Ok(())
}

/// Patch configuration keys.
///
/// `vta_did` is deliberately **not** a parameter: the VTA's own identity is
/// set at setup and is immutable at runtime, so there is no flag to attempt
/// it with. A caller that names it anyway (over the wire) is answered with a
/// rejection, which this command prints — the operator learns the rule rather
/// than silently re-pointing the agent's identity, which is what the
/// pre-canonical surface did.
pub async fn cmd_config_update(
    client: &VtaClient,
    label_prefix: &str,
    vta_name: Option<String>,
    public_url: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut overrides = HashMap::new();
    if let Some(v) = vta_name {
        overrides.insert("vta_name".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = public_url {
        overrides.insert("public_url".to_string(), serde_json::Value::String(v));
    }
    if overrides.is_empty() {
        println!("Nothing to update — pass at least one of --vta-name or --public-url.");
        return Ok(());
    }

    let resp = client
        .update_config(UpdateConfigRequest {
            patch: UpdateConfigBody::new(overrides),
        })
        .await?;

    if !resp.applied.is_empty() {
        println!(
            "{label_prefix}Applied:          {}",
            resp.applied.join(", ")
        );
    }
    if !resp.pending_restart.is_empty() {
        println!(
            "{label_prefix}Pending restart:  {}",
            resp.pending_restart.join(", ")
        );
        println!("{label_prefix}  Stored, but not in effect until the VTA restarts.");
    }
    for rejected in &resp.rejected {
        println!(
            "{label_prefix}Rejected {}: {}",
            rejected.key, rejected.reason
        );
    }
    Ok(())
}
