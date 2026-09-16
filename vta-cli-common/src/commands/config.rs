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
    // Pad to the longest key so the rate-limit keys line up with the short ones.
    let width = resp
        .config
        .fields
        .iter()
        .map(|f| f.key.len() + 1)
        .max()
        .unwrap_or(0)
        .max(12);
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
            "{label_prefix}{:<width$} {value}  [{}]{restart}",
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
    cmd_config_patch(
        client,
        label_prefix,
        vta_name,
        public_url,
        RateLimitOverrides::default(),
    )
    .await
}

/// The VTA's runtime rate-limit keys, each optional. Intervals are **seconds
/// per token** (lower is looser), not rates. The VTA bounds them (intervals
/// 1-3600, bursts 1-10000) and applies them without a restart.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct RateLimitOverrides {
    /// `rate_limit_interval_secs` — the auth limiter's seconds per token.
    pub rate_limit_interval_secs: Option<u64>,
    /// `rate_limit_burst` — the auth limiter's burst.
    pub rate_limit_burst: Option<u32>,
    /// `did_log_rate_limit_interval_secs` — the DID-log limiter's seconds per
    /// token.
    pub did_log_rate_limit_interval_secs: Option<u64>,
    /// `did_log_rate_limit_burst` — the DID-log limiter's burst.
    pub did_log_rate_limit_burst: Option<u32>,
}

impl RateLimitOverrides {
    /// `(registry key, value)` for every field that is set.
    fn entries(&self) -> Vec<(&'static str, serde_json::Value)> {
        [
            (
                vta_sdk::rate_limit::VTA_INTERVAL_KEY,
                self.rate_limit_interval_secs.map(serde_json::Value::from),
            ),
            (
                vta_sdk::rate_limit::VTA_BURST_KEY,
                self.rate_limit_burst.map(serde_json::Value::from),
            ),
            (
                vta_sdk::rate_limit::VTA_DID_LOG_INTERVAL_KEY,
                self.did_log_rate_limit_interval_secs
                    .map(serde_json::Value::from),
            ),
            (
                vta_sdk::rate_limit::VTA_DID_LOG_BURST_KEY,
                self.did_log_rate_limit_burst.map(serde_json::Value::from),
            ),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect()
    }
}

/// [`cmd_config_update`] plus the runtime rate-limit keys. Rate-limit values
/// travel as JSON integers.
pub async fn cmd_config_patch(
    client: &VtaClient,
    label_prefix: &str,
    vta_name: Option<String>,
    public_url: Option<String>,
    rate_limits: RateLimitOverrides,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut overrides = HashMap::new();
    if let Some(v) = vta_name {
        overrides.insert("vta_name".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = public_url {
        overrides.insert("public_url".to_string(), serde_json::Value::String(v));
    }
    for (key, value) in rate_limits.entries() {
        overrides.insert(key.to_string(), value);
    }
    if overrides.is_empty() {
        println!(
            "Nothing to update — pass at least one of --vta-name, --public-url, \
             --rate-limit-interval-secs, --rate-limit-burst, \
             --did-log-rate-limit-interval-secs or --did-log-rate-limit-burst."
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_overrides_emit_only_set_keys_as_integers() {
        assert!(RateLimitOverrides::default().entries().is_empty());

        let mut o = RateLimitOverrides::default();
        o.rate_limit_burst = Some(30);
        o.did_log_rate_limit_interval_secs = Some(2);
        let entries = o.entries();
        assert_eq!(
            entries,
            vec![
                ("rate_limit_burst", serde_json::json!(30)),
                ("did_log_rate_limit_interval_secs", serde_json::json!(2)),
            ]
        );
    }
}
